"""S-AES 作业的 Tkinter 图形界面。

窗口用 ``ttk.Notebook`` 分成五个标签页，与作业的五个关卡一一对应：

1. 基本测试 —— 16 bit 明文 + 16 bit 密钥，展示完整加解密中间过程；
2. 交叉测试 —— 生成/导入 ``(K, P, C)`` 向量，与同组同学核对算法标准；
3. 扩展功能 —— 把字符串按 2 字节分组加解密；
4. 多重加密 —— 双重/三重加密，以及中间相遇攻击；
5. CBC 模式 —— 分组链接加密与密文篡改演示。

启动::

    python -m gui.app
"""

from __future__ import annotations

import ctypes
import queue
import random
import re
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from saes.core import (
    SaesError,
    decrypt_block,
    encrypt_block,
    expand_key,
    format_bits,
    format_hex,
    key_expansion_rows,
    parse_data,
    trace_operation_steps,
)
from saes.modes import cbc_decrypt, cbc_encrypt, cbc_encrypt_details, flip_bit
from saes.multi import (
    AttackCancelled,
    double_decrypt,
    double_encrypt,
    meet_in_the_middle,
    split_key32,
    split_key48,
    triple_decrypt_ede2,
    triple_decrypt_ede3,
    triple_encrypt_ede2,
    triple_encrypt_ede3,
)
from saes.text import (
    decrypt_bytes,
    decrypt_text,
    encrypt_text,
    pad,
    split_blocks,
    to_display,
    to_hex,
)
from saes.vectors import check_vectors, generate_vectors, parse_vectors, vectors_to_csv

from .theme import (
    COLORS,
    FONT,
    SPACE,
    apply_theme,
    make_card,
    make_hint_label,
    make_page_title,
    make_scrollable_page,
    make_section_label,
    make_text_area,
)

SAMPLE_KEY = "1010 0111 0011 1011"
SAMPLE_PLAINTEXT = "0110 1111 0110 1011"

_APPEARANCE = (
    "状态矩阵按列优先填充：\n"
    "    [ n0  n2 ]\n"
    "    [ n1  n3 ]\n\n"
    "S 盒（行 = b0b3，列 = b1b2）        逆 S 盒\n"
    "    9  4  A  B                          A  5  9  B\n"
    "    D  1  8  5                          1  7  8  F\n"
    "    6  2  0  3                          6  0  2  3\n"
    "    C  E  F  7                          C  4  D  E\n\n"
    "列混淆矩阵 [[1, 4], [4, 1]]（解密用 [[9, 2], [2, 9]]）\n"
    "GF(2^4) 模多项式 x^4 + x + 1，轮常量 RCON = 0x80, 0x30\n"
    "密钥扩展：K0 = 主密钥，K1 = w2 || w3，K2 = w4 || w5\n\n"
    "标准测试向量：\n"
    "    K = 1010 0111 0011 1011\n"
    "    P = 0110 1111 0110 1011\n"
    "    C = 0000 0111 0011 1000"
)


_APPENDIX_D_STRUCTURE = (
    "附录 D.1 复合函数（从右向左执行）\n"
    "  加密 = AK2 ∘ SR ∘ NS ∘ AK1 ∘ MC ∘ SR ∘ NS ∘ AK0\n"
    "  解密 = AK0 ∘ INS ∘ ISR ∘ IMC ∘ AK1 ∘ INS ∘ ISR ∘ AK2\n\n"
    "D.2.1 AK   密钥加：状态与轮密钥逐位异或\n"
    "D.2.2 NS   半字节代替：按（行 = b0b3，列 = b1b2）查 S 盒\n"
    "D.2.3 SR   行移位：第二行循环左移一个半字节（2 列时即交换）\n"
    "D.2.4 MC   列混淆：每列左乘 [[1,4],[4,1]]，GF(2^4) 模 x^4+x+1\n\n"
    "D.3    密钥扩展：w2 = w0 ⊕ RCON(1) ⊕ SubNib(RotNib(w1))\n"
    "                 w3 = w2 ⊕ w1\n"
    "                 w4 = w2 ⊕ RCON(2) ⊕ SubNib(RotNib(w3))\n"
    "                 w5 = w4 ⊕ w3，K1 = w2‖w3，K2 = w4‖w5\n"
    "附件 D.1  GF(2^4) 加法即异或；乘法对 x^4+x+1 取模\n"
)


class SaesApp:
    """主窗口。所有耗时操作（目前只有中间相遇攻击）都放到后台线程。"""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("S-AES 加解密实验 · 信息安全导论作业 2")
        root.geometry("1180x840")
        root.minsize(1000, 700)
        apply_theme(root)

        header = ttk.Frame(root, padding=(SPACE["xl"], SPACE["lg"], SPACE["xl"], SPACE["sm"]))
        header.pack(fill="x")
        ttk.Label(header, text="S-AES 简化 AES 算法实现", style="PageTitle.TLabel").pack(anchor="w")
        ttk.Label(
            header,
            text="分组 16 bit · 密钥 16 bit · 2 轮 SPN 结构 · 五个关卡全部实现",
            style="Hint.TLabel",
        ).pack(anchor="w", pady=(SPACE["xs"], 0))

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True, padx=SPACE["xl"], pady=(0, SPACE["lg"]))

        self.notebook.add(self._build_basic(self.notebook), text="第 1 关 · 基本测试")
        self.notebook.add(self._build_cross(self.notebook), text="第 2 关 · 交叉测试")
        self.notebook.add(self._build_text(self.notebook), text="第 3 关 · 扩展功能")
        self.notebook.add(self._build_multi(self.notebook), text="第 4 关 · 多重加密")
        self.notebook.add(self._build_cbc(self.notebook), text="第 5 关 · CBC 模式")

        # 中间相遇攻击的线程间通信
        self._mitm_queue: queue.Queue = queue.Queue()
        self._mitm_cancel = threading.Event()
        self._mitm_running = False
        self._mitm_demo_key: int | None = None
        self._mitm_started_at = 0.0

        self._cbc_last_cipher: bytes | None = None

    # ------------------------------------------------------------------
    # 通用小工具
    # ------------------------------------------------------------------

    def _make_field(
        self,
        parent: tk.Widget,
        label: str,
        variable: tk.StringVar,
        hint: str | None = None,
    ) -> ttk.Entry:
        """一行「标签 + 等宽输入框」。"""
        row = ttk.Frame(parent, style="CardInner.TFrame")
        row.pack(fill="x", pady=(0, SPACE["sm"]))
        ttk.Label(row, text=label, width=26, style="Field.TLabel").pack(side="left")
        entry = ttk.Entry(row, textvariable=variable, font=FONT["mono"])
        entry.pack(side="left", fill="x", expand=True)
        if hint:
            make_hint_label(parent, hint, on_surface=True)
        return entry

    def _make_buttons(self, parent: tk.Widget) -> ttk.Frame:
        row = ttk.Frame(parent, style="CardInner.TFrame")
        row.pack(anchor="w", pady=(SPACE["sm"], 0))
        return row

    def _button(
        self, parent: tk.Widget, text: str, command, *, primary: bool = False
    ) -> ttk.Button:
        button = ttk.Button(
            parent,
            text=text,
            command=command,
            style="Primary.TButton" if primary else "Secondary.TButton",
        )
        button.pack(side="left", padx=(0, SPACE["sm"]))
        return button

    def _make_result_label(self, parent: tk.Widget, variable: tk.StringVar) -> ttk.Label:
        label = ttk.Label(
            parent,
            textvariable=variable,
            font=FONT["result"],
            foreground=COLORS["accent"],
            background=COLORS["surface"],
        )
        label.pack(anchor="w")
        return label

    def _make_tree(
        self,
        parent: tk.Widget,
        columns: tuple[str, ...],
        widths: tuple[int, ...],
        height: int = 8,
    ) -> ttk.Treeview:
        container = ttk.Frame(parent, style="CardInner.TFrame")
        container.pack(fill="x", pady=(SPACE["sm"], 0))
        tree = ttk.Treeview(container, columns=columns, show="headings", height=height)
        for column, width in zip(columns, widths):
            tree.heading(column, text=column)
            tree.column(column, width=width, anchor="w")
        tree.pack(side="left", fill="both", expand=True)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=tree.yview)
        scrollbar.pack(side="right", fill="y")
        tree.configure(yscrollcommand=scrollbar.set)
        return tree

    @staticmethod
    def _read_text(widget: tk.Text) -> str:
        return widget.get("1.0", "end-1c")

    @staticmethod
    def _write_text(widget: tk.Text, text: str) -> None:
        """向可能只读的 Text 写入内容。"""
        previous = str(widget.cget("state"))
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        if previous == "disabled":
            widget.configure(state="disabled")

    def _error(self, error: Exception) -> None:
        messagebox.showwarning("输入有误", str(error), parent=self.root)

    @staticmethod
    def _copy_to_clipboard(root: tk.Misc, text: str) -> None:
        root.clipboard_clear()
        root.clipboard_append(text)

    @staticmethod
    def _parse_hex_bytes(text: str, name: str = "密文") -> bytes:
        cleaned = re.sub(r"[\s,:_\-]+", "", text.strip())
        if not cleaned:
            raise SaesError(f"{name}不能为空")
        if len(cleaned) % 2:
            raise SaesError(f"{name}的十六进制长度必须是偶数")
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise SaesError(f"{name}不是合法的十六进制：{text!r}") from exc

    # ------------------------------------------------------------------
    # 第 1 关：基本测试
    # ------------------------------------------------------------------

    def _build_basic(self, notebook: ttk.Notebook) -> ttk.Frame:
        page, body = make_scrollable_page(notebook)
        make_page_title(body, "第 1 关 · 基本测试")
        make_hint_label(
            body,
            "输入 16 bit 数据和 16 bit 密钥，输出 16 bit 密文。"
            "支持二进制（可带空格）或十六进制（如 1A2B / 0x1A2B）。",
        )

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["md"], 0))
        make_section_label(inner, "输入")
        self.basic_key = tk.StringVar()
        self.basic_data = tk.StringVar()
        self._make_field(inner, "密钥 K（16 bit）", self.basic_key)
        self._make_field(inner, "明文 / 密文（16 bit）", self.basic_data)
        buttons = self._make_buttons(inner)
        self._button(buttons, "加密", self._basic_encrypt, primary=True)
        self._button(buttons, "解密", self._basic_decrypt)
        self._button(buttons, "填入标准示例", self._basic_sample)
        self._button(buttons, "随机示例", self._basic_random)
        self._button(buttons, "清空", self._basic_clear)

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "结果")
        self.basic_result = tk.StringVar(value="（等待操作）")
        self.basic_result_label = self._make_result_label(inner, self.basic_result)
        self.basic_meta = tk.StringVar(value="")
        ttk.Label(
            inner, textvariable=self.basic_meta, style="MonoOnSurface.TLabel"
        ).pack(anchor="w", pady=(SPACE["xs"], 0))
        self.basic_check = tk.StringVar(value="")
        self.basic_check_label = ttk.Label(
            inner, textvariable=self.basic_check, style="HintOnSurface.TLabel"
        )
        self.basic_check_label.pack(anchor="w", pady=(SPACE["xs"], 0))

        # --- 运算步骤 + 状态矩阵（与附录 D 图 D.3 对应）---
        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "附录 D 运算步骤与状态矩阵")
        make_hint_label(
            inner,
            "左侧列出 AK / NS / SR / MC 及其逆运算；选中任一步骤，"
            "右侧按图 D.2(a) 的列优先布局显示 2×2 状态矩阵。",
            on_surface=True,
        )
        content = ttk.Frame(inner, style="CardInner.TFrame")
        content.pack(fill="x", pady=(SPACE["sm"], 0))

        left = ttk.Frame(content, style="CardInner.TFrame")
        left.pack(side="left", fill="both", expand=True)
        self.basic_steps: list = []
        self.basic_steps_tree = self._make_tree(
            left,
            ("轮次", "操作", "说明", "16 bit"),
            (66, 72, 250, 90),
            height=9,
        )
        self.basic_steps_tree.bind("<<TreeviewSelect>>", self._on_basic_step_selected)

        right = ttk.Frame(content, style="CardInner.TFrame")
        right.pack(side="left", padx=(SPACE["lg"], 0))
        self.state_title = tk.StringVar(value="选择一个步骤查看状态矩阵")
        ttk.Label(
            right,
            textvariable=self.state_title,
            style="MonoOnSurface.TLabel",
            wraplength=250,
            justify="left",
        ).pack(anchor="w")
        self.state_canvas = tk.Canvas(
            right,
            width=196,
            height=182,
            background=COLORS["surface"],
            highlightthickness=0,
        )
        self.state_canvas.pack(anchor="w", pady=(SPACE["sm"], 0))
        self.state_meta = tk.StringVar(value="s(i,j)：i = 行，j = 列")
        ttk.Label(
            right, textvariable=self.state_meta, style="HintOnSurface.TLabel"
        ).pack(anchor="w", pady=(SPACE["xs"], 0))

        # --- 密钥扩展明细（D.3）---
        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "密钥扩展（D.3）：w0 → w5")
        self.basic_key_tree = self._make_tree(
            inner,
            ("名称", "二进制", "十六进制", "说明"),
            (80, 190, 90, 400),
            height=11,
        )

        # --- 结构对照 ---
        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "附录 D 结构对照")
        structure = make_text_area(inner, height=10, mono=True, readonly=True)
        structure.pack(fill="x")
        self._write_text(structure, _APPENDIX_D_STRUCTURE)
        return page

    def _fill_basic_analysis(self, data: int, key: int, *, decrypt: bool = False) -> None:
        """填充运算步骤表、状态矩阵和密钥扩展表。"""
        steps = trace_operation_steps(data, key, decrypt=decrypt)
        self.basic_steps = steps

        tree = self.basic_steps_tree
        tree.delete(*tree.get_children())
        for index, step in enumerate(steps):
            round_text = "输入" if step.operation == "输入" else str(step.round_index)
            tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    round_text,
                    step.operation,
                    step.title,
                    format_hex(step.block),
                ),
            )
        if steps:
            last = str(len(steps) - 1)
            tree.selection_set(last)
            tree.see(last)
            self._show_state_step(steps[-1])

        key_tree = self.basic_key_tree
        key_tree.delete(*key_tree.get_children())
        for name, value, note in key_expansion_rows(key):
            key_tree.insert(
                "",
                "end",
                values=(name, format_bits(value, 8), format_hex(value, 8), note),
            )
        schedule = expand_key(key)
        for name, value, note in (
            ("K0", schedule.k0, "w0 ‖ w1（主密钥）"),
            ("K1", schedule.k1, "w2 ‖ w3"),
            ("K2", schedule.k2, "w4 ‖ w5"),
        ):
            key_tree.insert(
                "",
                "end",
                values=(name, format_bits(value), format_hex(value), note),
            )

    def _on_basic_step_selected(self, _event: object = None) -> None:
        selection = self.basic_steps_tree.selection()
        if not selection:
            return
        index = int(selection[0])
        if 0 <= index < len(self.basic_steps):
            self._show_state_step(self.basic_steps[index])

    def _show_state_step(self, step) -> None:
        """把某一步的状态画到右侧矩阵面板。"""
        if step.operation == "输入":
            title = "输入分组"
        else:
            title = f"{step.title}（{step.operation}）"
        self.state_title.set(title)
        self.state_meta.set(f"16 bit 分组 = 0x{format_hex(step.block)}")
        self._draw_state(step.state)

    def _draw_state(self, state) -> None:
        """按图 D.2(a) 画出 2×2 半字节矩阵。"""
        canvas = self.state_canvas
        canvas.delete("all")
        cell, gap, x0, y0 = 60, 6, 24, 22
        for row in range(2):
            for column in range(2):
                x = x0 + column * cell
                y = y0 + row * cell
                canvas.create_rectangle(
                    x,
                    y,
                    x + cell - gap,
                    y + cell - gap,
                    fill=COLORS["surface_sunken"],
                    outline=COLORS["border_strong"],
                    width=1,
                )
                canvas.create_text(
                    x + 4,
                    y + 3,
                    text=f"s{row}{column}",
                    anchor="nw",
                    font=FONT["small"],
                    fill=COLORS["text_muted"],
                )
                canvas.create_text(
                    x + (cell - gap) / 2,
                    y + (cell - gap) / 2 + 2,
                    text=f"{state[row][column]:X}",
                    font=(FONT["mono"][0], 20, "bold"),
                    fill=COLORS["text"],
                )

    def _basic_inputs(self) -> tuple[int, int]:
        data = parse_data(self.basic_data.get(), 16, "数据")
        key = parse_data(self.basic_key.get(), 16, "密钥")
        return data, key

    def _basic_encrypt(self) -> None:
        try:
            plaintext, key = self._basic_inputs()
        except SaesError as error:
            self._error(error)
            return

        ciphertext = encrypt_block(plaintext, key)
        self.basic_result.set(f"密文 C = {format_bits(ciphertext)}")
        self.basic_meta.set(
            f"十六进制 0x{format_hex(ciphertext)}    十进制 {ciphertext}"
        )
        recovered = decrypt_block(ciphertext, key)
        self._basic_check(recovered == plaintext, "解密(C) = P")
        self._fill_basic_analysis(plaintext, key)

    def _basic_decrypt(self) -> None:
        try:
            ciphertext, key = self._basic_inputs()
        except SaesError as error:
            self._error(error)
            return

        plaintext = decrypt_block(ciphertext, key)
        self.basic_result.set(f"明文 P = {format_bits(plaintext)}")
        self.basic_meta.set(f"十六进制 0x{format_hex(plaintext)}    十进制 {plaintext}")
        self._basic_check(encrypt_block(plaintext, key) == ciphertext, "加密(P) = C")
        self._fill_basic_analysis(ciphertext, key, decrypt=True)

    def _basic_check(self, passed: bool, expression: str) -> None:
        if passed:
            self.basic_check.set(f"往返校验通过：{expression} ✓")
            self.basic_check_label.configure(foreground=COLORS["success"])
        else:
            self.basic_check.set(f"往返校验失败：{expression} ✗")
            self.basic_check_label.configure(foreground=COLORS["danger"])

    def _basic_sample(self) -> None:
        self.basic_key.set(SAMPLE_KEY)
        self.basic_data.set(SAMPLE_PLAINTEXT)
        self._basic_encrypt()

    def _basic_random(self) -> None:
        self.basic_key.set(f"{random.getrandbits(16):016b}")
        self.basic_data.set(f"{random.getrandbits(16):016b}")
        self._basic_encrypt()

    def _basic_clear(self) -> None:
        self.basic_key.set("")
        self.basic_data.set("")
        self.basic_result.set("（等待操作）")
        self.basic_meta.set("")
        self.basic_check.set("")
        self.basic_steps = []
        self.basic_steps_tree.delete(*self.basic_steps_tree.get_children())
        self.basic_key_tree.delete(*self.basic_key_tree.get_children())
        self.state_canvas.delete("all")
        self.state_title.set("选择一个步骤查看状态矩阵")
        self.state_meta.set("s(i,j)：i = 行，j = 列")

    # ------------------------------------------------------------------
    # 第 2 关：交叉测试
    # ------------------------------------------------------------------

    def _build_cross(self, notebook: ttk.Notebook) -> ttk.Frame:
        page, body = make_scrollable_page(notebook)
        make_page_title(body, "第 2 关 · 交叉测试")
        make_hint_label(
            body,
            "与同组同学交换 (密钥 K, 明文 P, 密文 C) 向量。"
            "双方使用相同的 S 盒、列混淆矩阵和状态布局时，同一 (K, P) 必须得到同一 C。",
        )

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["md"], 0))
        make_section_label(inner, "生成测试向量（发给同组同学）")
        self.cross_count = tk.StringVar(value="20")
        self.cross_seed = tk.StringVar(value="")
        self.cross_fixed_key = tk.StringVar(value="")
        self._make_field(inner, "生成数量（1 ~ 1000）", self.cross_count)
        self._make_field(inner, "随机种子（可空，用于复现）", self.cross_seed)
        self._make_field(inner, "固定密钥（可空，默认每题随机）", self.cross_fixed_key)
        buttons = self._make_buttons(inner)
        self._button(buttons, "生成 CSV", self._cross_generate, primary=True)
        self._button(buttons, "复制", self._cross_copy)
        self._button(buttons, "保存为文件", self._cross_save)
        self.cross_output = make_text_area(inner, height=9, mono=True)
        self.cross_output.pack(fill="x", pady=(SPACE["sm"], 0))

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "校验同组同学的向量")
        make_hint_label(
            inner,
            "每行三列：密钥, 明文, 密文（逗号、制表符或空格分隔；可含表头）。",
            on_surface=True,
        )
        self.cross_input = make_text_area(inner, height=8, mono=True)
        self.cross_input.pack(fill="x", pady=(SPACE["sm"], 0))
        buttons = self._make_buttons(inner)
        self._button(buttons, "开始校验", self._cross_check, primary=True)
        self._button(buttons, "从文件加载", self._cross_load)
        self._button(buttons, "清空", self._cross_clear)
        self.cross_summary = tk.StringVar(value="（尚未校验）")
        self.cross_summary_label = ttk.Label(
            inner, textvariable=self.cross_summary, style="HintOnSurface.TLabel"
        )
        self.cross_summary_label.pack(anchor="w", pady=(SPACE["sm"], 0))
        self.cross_failures = self._make_tree(
            inner,
            ("序号", "密钥 K", "明文 P", "期望密文", "实际密文"),
            (60, 120, 120, 140, 140),
            height=6,
        )

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "算法标准（与同学核对用）")
        standard = make_text_area(inner, height=18, mono=True, readonly=True)
        standard.pack(fill="x")
        self._write_text(standard, _APPEARANCE)
        return page

    def _cross_generate(self) -> None:
        try:
            count_text = self.cross_count.get().strip() or "20"
            count = int(count_text, 10)
            seed_text = self.cross_seed.get().strip()
            seed = int(seed_text, 0) if seed_text else None
            key_text = self.cross_fixed_key.get().strip()
            key = parse_data(key_text, 16, "固定密钥") if key_text else None
            vectors = generate_vectors(count, seed=seed, key=key)
        except (SaesError, ValueError) as error:
            self._error(SaesError(str(error)) if not isinstance(error, SaesError) else error)
            return

        text = vectors_to_csv(vectors)
        self._write_text(self.cross_output, text)
        self.cross_summary.set(
            f"已生成 {len(vectors)} 组向量"
            + (f"（随机种子 {seed}）" if seed is not None else "")
        )
        self.cross_summary_label.configure(foreground=COLORS["success"])

    def _cross_copy(self) -> None:
        self._copy_to_clipboard(self.root, self._read_text(self.cross_output))
        self.cross_summary.set("已复制到剪贴板")
        self.cross_summary_label.configure(foreground=COLORS["text_muted"])

    def _cross_save(self) -> None:
        text = self._read_text(self.cross_output)
        if not text.strip():
            self._error(SaesError("没有可保存的向量，请先生成"))
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="保存测试向量",
            defaultextension=".csv",
            filetypes=(("CSV 文件", "*.csv"), ("文本文件", "*.txt"), ("所有文件", "*.*")),
        )
        if not path:
            return
        Path(path).write_text(text, encoding="utf-8")
        self.cross_summary.set(f"已保存到 {path}")
        self.cross_summary_label.configure(foreground=COLORS["success"])

    def _cross_load(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="加载测试向量",
            filetypes=(("CSV 文件", "*.csv"), ("文本文件", "*.txt"), ("所有文件", "*.*")),
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8-sig")
        except UnicodeDecodeError:
            text = Path(path).read_text(encoding="gbk", errors="replace")
        self._write_text(self.cross_input, text)
        self.cross_summary.set(f"已加载 {path}")
        self.cross_summary_label.configure(foreground=COLORS["text_muted"])

    def _cross_check(self) -> None:
        try:
            vectors = parse_vectors(self._read_text(self.cross_input))
            results = check_vectors(vectors)
        except SaesError as error:
            self._error(error)
            return

        failures = [result for result in results if not result.passed]
        self.cross_failures.delete(*self.cross_failures.get_children())
        for index, result in enumerate(failures, start=1):
            vector = result.vector
            self.cross_failures.insert(
                "",
                "end",
                values=(
                    index,
                    format_hex(vector.key),
                    format_hex(vector.plaintext),
                    format_hex(vector.ciphertext),
                    format_hex(result.actual),
                ),
            )

        if not failures:
            self.cross_summary.set(f"全部 {len(results)} 组向量通过，算法标准一致 ✓")
            self.cross_summary_label.configure(foreground=COLORS["success"])
        else:
            self.cross_summary.set(
                f"共 {len(results)} 组，通过 {len(results) - len(failures)} 组，"
                f"失败 {len(failures)} 组。请重点核对 S 盒、逆 S 盒、列混淆矩阵与状态布局。"
            )
            self.cross_summary_label.configure(foreground=COLORS["danger"])

    def _cross_clear(self) -> None:
        self._write_text(self.cross_input, "")
        self.cross_failures.delete(*self.cross_failures.get_children())
        self.cross_summary.set("（尚未校验）")
        self.cross_summary_label.configure(foreground=COLORS["text_muted"])

    # ------------------------------------------------------------------
    # 第 3 关：扩展功能（字符串）
    # ------------------------------------------------------------------

    def _build_text(self, notebook: ttk.Notebook) -> ttk.Frame:
        page, body = make_scrollable_page(notebook)
        make_page_title(body, "第 3 关 · 扩展功能")
        make_hint_label(
            body,
            "把字符串按 2 字节（16 bit）一组加密。不足一组时用 PKCS#7 填充，"
            "解密后自动去除。字符串默认按 UTF-8 编码；纯 ASCII 文本与作业要求一致。",
        )

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["md"], 0))
        make_section_label(inner, "输入")
        self.text_key = tk.StringVar()
        self._make_field(inner, "密钥 K（16 bit）", self.text_key)
        ttk.Label(inner, text="明文（UTF-8 / ASCII 字符串）", style="Field.TLabel").pack(anchor="w")
        self.text_plain = make_text_area(inner, height=5)
        self.text_plain.pack(fill="x", pady=(SPACE["xs"], 0))
        buttons = self._make_buttons(inner)
        self._button(buttons, "加密", self._text_encrypt, primary=True)
        self._button(buttons, "解密", self._text_decrypt)
        self._button(buttons, "随机示例", self._text_sample)
        self._button(buttons, "清空", self._text_clear)

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "密文（每 2 字节一个分组，十六进制）")
        self.text_cipher_hex = make_text_area(inner, height=4, mono=True)
        self.text_cipher_hex.pack(fill="x")
        ttk.Label(inner, text="可读形式", style="Field.TLabel").pack(
            anchor="w", pady=(SPACE["sm"], 0)
        )
        self.text_cipher_display = make_text_area(inner, height=3, mono=True, readonly=True)
        self.text_cipher_display.pack(fill="x")
        self.text_info = tk.StringVar(value="")
        ttk.Label(inner, textvariable=self.text_info, style="HintOnSurface.TLabel").pack(
            anchor="w", pady=(SPACE["sm"], 0)
        )

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "解密结果")
        self.text_plain_out = make_text_area(inner, height=4, readonly=True)
        self.text_plain_out.pack(fill="x")
        self.text_plain_info = tk.StringVar(value="")
        ttk.Label(
            inner, textvariable=self.text_plain_info, style="HintOnSurface.TLabel"
        ).pack(anchor="w", pady=(SPACE["sm"], 0))

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "分组明细（含填充）")
        self.text_blocks = self._make_tree(
            inner, ("序号", "明文字节", "密文字节"), (80, 200, 200), height=7
        )
        return page

    def _text_encrypt(self) -> None:
        try:
            key = parse_data(self.text_key.get(), 16, "密钥")
        except SaesError as error:
            self._error(error)
            return

        plaintext = self._read_text(self.text_plain)
        data = plaintext.encode("utf-8")
        ciphertext = encrypt_text(plaintext, key)
        self._write_text(self.text_cipher_hex, to_hex(ciphertext))
        self._write_text(self.text_cipher_display, to_display(ciphertext))
        self.text_info.set(
            f"{len(data)} 字节明文 → {len(ciphertext)} 字节密文，共 {len(ciphertext) // 2} 组"
        )

        self.text_blocks.delete(*self.text_blocks.get_children())
        padded = pad(data)
        plain_blocks = split_blocks(padded)
        cipher_blocks = split_blocks(ciphertext)
        for index, (plain_block, cipher_block) in enumerate(
            zip(plain_blocks, cipher_blocks), start=1
        ):
            self.text_blocks.insert(
                "",
                "end",
                values=(
                    index,
                    f"{plain_block >> 8:02X} {plain_block & 0xFF:02X}",
                    f"{cipher_block >> 8:02X} {cipher_block & 0xFF:02X}",
                ),
            )
        self._write_text(self.text_plain_out, "")

    def _text_decrypt(self) -> None:
        try:
            key = parse_data(self.text_key.get(), 16, "密钥")
            ciphertext = self._parse_hex_bytes(self._read_text(self.text_cipher_hex))
            plaintext = decrypt_text(ciphertext, key)
        except SaesError as error:
            # 密钥错误时填充校验通常失败；仍展示未去填充的原始字节，便于分析
            raw = ""
            try:
                key = parse_data(self.text_key.get(), 16, "密钥")
                ciphertext = self._parse_hex_bytes(self._read_text(self.text_cipher_hex))
                raw = to_display(decrypt_bytes(ciphertext, key, unpad_data=False))
            except SaesError:
                raw = ""
            self._write_text(self.text_plain_out, f"解密失败：{error}")
            self.text_plain_info.set(f"原始字节（未去填充）：{raw}" if raw else "")
            self._error(error)
            return

        self._write_text(self.text_plain_out, plaintext)
        self.text_plain_info.set(f"解密成功，共 {len(plaintext.encode('utf-8'))} 字节")

    def _text_sample(self) -> None:
        self.text_key.set(SAMPLE_KEY)
        self._write_text(self.text_plain, "ok")
        self._text_encrypt()

    def _text_clear(self) -> None:
        self.text_key.set("")
        self._write_text(self.text_plain, "")
        self._write_text(self.text_cipher_hex, "")
        self._write_text(self.text_cipher_display, "")
        self._write_text(self.text_plain_out, "")
        self.text_info.set("")
        self.text_plain_info.set("")
        self.text_blocks.delete(*self.text_blocks.get_children())

    # ------------------------------------------------------------------
    # 第 4 关：多重加密与中间相遇攻击
    # ------------------------------------------------------------------

    def _build_multi(self, notebook: ttk.Notebook) -> ttk.Frame:
        page, body = make_scrollable_page(notebook)
        make_page_title(body, "第 4 关 · 多重加密")
        make_hint_label(
            body,
            "双重加密使用 32 bit 密钥；三重加密可选两密钥 EDE（32 bit）"
            "或三密钥 EDE（48 bit）。中间相遇攻击可在约 2×2^16 次运算内恢复 32 bit 密钥。",
        )

        # --- 双重加密 ---
        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["md"], 0))
        make_section_label(inner, "双重加密（32 bit 密钥）")
        self.double_key = tk.StringVar()
        self.double_input = tk.StringVar()
        self._make_field(inner, "密钥 K = K1 || K2（32 bit）", self.double_key)
        self._make_field(inner, "明文 / 密文（16 bit）", self.double_input)
        buttons = self._make_buttons(inner)
        self._button(buttons, "加密", self._double_encrypt, primary=True)
        self._button(buttons, "解密", self._double_decrypt)
        self._button(buttons, "随机示例", self._double_sample)
        self.double_result = tk.StringVar(value="（等待操作）")
        self._make_result_label(inner, self.double_result)
        self.double_meta = tk.StringVar(value="")
        ttk.Label(inner, textvariable=self.double_meta, style="MonoOnSurface.TLabel").pack(
            anchor="w", pady=(SPACE["xs"], 0)
        )

        # --- 三重加密 ---
        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "三重加密")
        self.triple_mode = tk.StringVar(value="ede2")
        mode_row = ttk.Frame(inner, style="CardInner.TFrame")
        mode_row.pack(anchor="w", pady=(0, SPACE["sm"]))
        ttk.Radiobutton(
            mode_row,
            text="两密钥 EDE（32 bit）：E_K1(D_K2(E_K1(P)))",
            variable=self.triple_mode,
            value="ede2",
            command=self._triple_mode_changed,
        ).pack(side="left", padx=(0, SPACE["lg"]))
        ttk.Radiobutton(
            mode_row,
            text="三密钥 EDE（48 bit）：E_K3(D_K2(E_K1(P)))",
            variable=self.triple_mode,
            value="ede3",
            command=self._triple_mode_changed,
        ).pack(side="left")
        self.triple_key = tk.StringVar()
        self.triple_input = tk.StringVar()
        self._make_field(inner, "密钥（32 / 48 bit）", self.triple_key)
        self._make_field(inner, "明文 / 密文（16 bit）", self.triple_input)
        self.triple_key_hint = make_hint_label(
            inner, "当前模式：32 bit 密钥（8 位十六进制，如 1A2B3C4D）", on_surface=True
        )
        buttons = self._make_buttons(inner)
        self._button(buttons, "加密", self._triple_encrypt, primary=True)
        self._button(buttons, "解密", self._triple_decrypt)
        self._button(buttons, "随机示例", self._triple_sample)
        self.triple_result = tk.StringVar(value="（等待操作）")
        self._make_result_label(inner, self.triple_result)
        self.triple_meta = tk.StringVar(value="")
        ttk.Label(inner, textvariable=self.triple_meta, style="MonoOnSurface.TLabel").pack(
            anchor="w", pady=(SPACE["xs"], 0)
        )

        # --- 中间相遇攻击 ---
        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "中间相遇攻击（恢复 32 bit 密钥）")
        make_hint_label(
            inner,
            "每行一组「明文 密文」（十六进制或二进制）。"
            "一组向量平均会留下约 2^16 个候选，建议用 2~3 组排除碰撞。",
            on_surface=True,
        )
        self.mitm_pairs = make_text_area(inner, height=5, mono=True)
        self.mitm_pairs.pack(fill="x", pady=(SPACE["sm"], 0))
        buttons = self._make_buttons(inner)
        self._button(buttons, "生成演示数据", self._mitm_generate)
        self.mitm_start_button = self._button(
            buttons, "开始攻击", self._mitm_start, primary=True
        )
        self.mitm_cancel_button = self._button(buttons, "取消", self._mitm_cancel_click)
        self.mitm_cancel_button.configure(state="disabled")
        self._button(buttons, "清空", self._mitm_clear)

        self.mitm_progress = ttk.Progressbar(inner, mode="determinate", maximum=1 << 17)
        self.mitm_progress.pack(fill="x", pady=(SPACE["sm"], 0))
        self.mitm_status = tk.StringVar(value="（等待操作）")
        ttk.Label(inner, textvariable=self.mitm_status, style="HintOnSurface.TLabel").pack(
            anchor="w", pady=(SPACE["xs"], 0)
        )
        self.mitm_result = make_text_area(inner, height=7, mono=True, readonly=True)
        self.mitm_result.pack(fill="x", pady=(SPACE["sm"], 0))
        return page

    # --- 双重加密 ---

    def _double_encrypt(self) -> None:
        try:
            key = parse_data(self.double_key.get(), 32, "32 bit 密钥")
            plaintext = parse_data(self.double_input.get(), 16, "明文")
        except SaesError as error:
            self._error(error)
            return

        ciphertext = double_encrypt(plaintext, key)
        key1, key2 = split_key32(key)
        self.double_result.set(f"密文 C = {format_bits(ciphertext)}")
        self.double_meta.set(
            f"K1 = {format_hex(key1)}    K2 = {format_hex(key2)}    "
            f"中间值 E_K1(P) = {format_hex(encrypt_block(plaintext, key1))}"
        )

    def _double_decrypt(self) -> None:
        try:
            key = parse_data(self.double_key.get(), 32, "32 bit 密钥")
            ciphertext = parse_data(self.double_input.get(), 16, "密文")
        except SaesError as error:
            self._error(error)
            return

        plaintext = double_decrypt(ciphertext, key)
        key1, key2 = split_key32(key)
        self.double_result.set(f"明文 P = {format_bits(plaintext)}")
        self.double_meta.set(f"K1 = {format_hex(key1)}    K2 = {format_hex(key2)}")

    def _double_sample(self) -> None:
        key = random.getrandbits(32)
        self.double_key.set(f"{key:08X}")
        self.double_input.set(f"{random.getrandbits(16):04X}")
        self._double_encrypt()

    # --- 三重加密 ---

    def _triple_mode_changed(self) -> None:
        if self.triple_mode.get() == "ede2":
            self.triple_key_hint.configure(
                text="当前模式：32 bit 密钥（8 位十六进制，如 1A2B3C4D）"
            )
        else:
            self.triple_key_hint.configure(
                text="当前模式：48 bit 密钥（12 位十六进制，如 1A2B3C4D5E6F）"
            )

    def _triple_encrypt(self) -> None:
        try:
            mode = self.triple_mode.get()
            bits = 32 if mode == "ede2" else 48
            key = parse_data(self.triple_key.get(), bits, f"{bits} bit 密钥")
            plaintext = parse_data(self.triple_input.get(), 16, "明文")
        except SaesError as error:
            self._error(error)
            return

        if mode == "ede2":
            ciphertext = triple_encrypt_ede2(plaintext, key)
            key1, key2 = split_key32(key)
            detail = f"K1 = {format_hex(key1)}    K2 = {format_hex(key2)}"
        else:
            ciphertext = triple_encrypt_ede3(plaintext, key)
            key1, key2, key3 = split_key48(key)
            detail = (
                f"K1 = {format_hex(key1)}    K2 = {format_hex(key2)}    "
                f"K3 = {format_hex(key3)}"
            )
        self.triple_result.set(f"密文 C = {format_bits(ciphertext)}")
        self.triple_meta.set(detail)

    def _triple_decrypt(self) -> None:
        try:
            mode = self.triple_mode.get()
            bits = 32 if mode == "ede2" else 48
            key = parse_data(self.triple_key.get(), bits, f"{bits} bit 密钥")
            ciphertext = parse_data(self.triple_input.get(), 16, "密文")
        except SaesError as error:
            self._error(error)
            return

        if mode == "ede2":
            plaintext = triple_decrypt_ede2(ciphertext, key)
            key1, key2 = split_key32(key)
            detail = f"K1 = {format_hex(key1)}    K2 = {format_hex(key2)}"
        else:
            plaintext = triple_decrypt_ede3(ciphertext, key)
            key1, key2, key3 = split_key48(key)
            detail = (
                f"K1 = {format_hex(key1)}    K2 = {format_hex(key2)}    "
                f"K3 = {format_hex(key3)}"
            )
        self.triple_result.set(f"明文 P = {format_bits(plaintext)}")
        self.triple_meta.set(detail)

    def _triple_sample(self) -> None:
        if self.triple_mode.get() == "ede2":
            self.triple_key.set(f"{random.getrandbits(32):08X}")
        else:
            self.triple_key.set(f"{random.getrandbits(48):012X}")
        self.triple_input.set(f"{random.getrandbits(16):04X}")
        self._triple_encrypt()

    # --- 中间相遇攻击 ---

    @staticmethod
    def _parse_mitm_pairs(text: str) -> list[tuple[int, int]]:
        pairs = []
        for line_number, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            cells = re.split(r"[\s,;]+", stripped)
            if len(cells) != 2:
                raise SaesError(f"第 {line_number} 行应为「明文 密文」两列")
            pairs.append(
                (
                    parse_data(cells[0], 16, f"第 {line_number} 行明文"),
                    parse_data(cells[1], 16, f"第 {line_number} 行密文"),
                )
            )
        if not pairs:
            raise SaesError("请先输入至少一组明密文对")
        return pairs

    def _mitm_generate(self) -> None:
        key = random.getrandbits(32)
        # 3 组向量可以把假阳性概率压到 2^-32 量级，结果通常唯一
        plaintexts = random.sample(range(1 << 16), 3)
        lines = []
        for plaintext in plaintexts:
            ciphertext = double_encrypt(plaintext, key)
            lines.append(f"{plaintext:04X} {ciphertext:04X}")
        self._write_text(self.mitm_pairs, "\n".join(lines))
        self._mitm_demo_key = key
        self._write_text(self.mitm_result, "")
        self.mitm_progress.configure(value=0)
        self.mitm_status.set(
            "已生成 3 组演示向量，真实密钥暂不显示。点击「开始攻击」恢复它。"
        )

    def _mitm_start(self) -> None:
        if self._mitm_running:
            return
        try:
            pairs = self._parse_mitm_pairs(self._read_text(self.mitm_pairs))
        except SaesError as error:
            self._error(error)
            return

        if len(pairs) < 2:
            proceed = messagebox.askyesno(
                "只有一组明密文对",
                "一组 16 bit 分组平均会留下约 2^16 个候选密钥。\n"
                "建议用 2~3 组向量；仍要继续吗？",
                parent=self.root,
            )
            if not proceed:
                return

        self._mitm_running = True
        self._mitm_started_at = time.perf_counter()
        self._mitm_cancel.clear()
        while True:  # 清掉上一次残留的消息
            try:
                self._mitm_queue.get_nowait()
            except queue.Empty:
                break

        self.mitm_start_button.configure(state="disabled")
        self.mitm_cancel_button.configure(state="normal")
        self.mitm_progress.configure(maximum=1 << 17, value=0)
        self.mitm_status.set("正在攻击……")
        self._write_text(self.mitm_result, "")

        def report(done: int, total: int, phase: str) -> None:
            self._mitm_queue.put(("progress", done, total, phase))

        def worker() -> None:
            try:
                keys = meet_in_the_middle(
                    pairs, progress=report, cancel_event=self._mitm_cancel
                )
                self._mitm_queue.put(("done", keys))
            except AttackCancelled:
                self._mitm_queue.put(("cancelled",))
            except Exception as error:  # noqa: BLE001 - 反馈给界面而不是静默崩溃
                self._mitm_queue.put(("error", str(error)))

        threading.Thread(target=worker, daemon=True).start()
        self.root.after(80, self._mitm_poll)

    def _mitm_cancel_click(self) -> None:
        if self._mitm_running:
            self._mitm_cancel.set()
            self.mitm_status.set("正在取消……")

    def _mitm_poll(self) -> None:
        try:
            while True:
                message = self._mitm_queue.get_nowait()
                kind = message[0]
                if kind == "progress":
                    _, done, total, phase = message
                    self.mitm_progress.configure(maximum=total, value=done)
                    self.mitm_status.set(f"{phase} …… {done}/{total}")
                elif kind == "done":
                    self._mitm_finish(message[1])
                    return
                elif kind == "cancelled":
                    self._mitm_stop()
                    self.mitm_status.set("攻击已取消")
                    return
                elif kind == "error":
                    self._mitm_stop()
                    self.mitm_status.set(f"攻击失败：{message[1]}")
                    self._error(SaesError(message[1]))
                    return
        except queue.Empty:
            pass

        if self._mitm_running:
            self.root.after(80, self._mitm_poll)

    def _mitm_stop(self) -> None:
        self._mitm_running = False
        self.mitm_start_button.configure(state="normal")
        self.mitm_cancel_button.configure(state="disabled")

    def _mitm_finish(self, keys: list[int]) -> None:
        self._mitm_stop()
        elapsed = time.perf_counter() - self._mitm_started_at
        self.mitm_progress.configure(value=self.mitm_progress.cget("maximum"))
        self.mitm_status.set(f"攻击完成，用时 {elapsed:.2f} 秒，候选密钥 {len(keys)} 个")

        lines = [
            f"攻击完成，用时 {elapsed:.2f} 秒",
            f"通过全部明密文对验证的候选密钥：{len(keys)} 个",
            "",
        ]
        for key in keys:
            key1, key2 = split_key32(key)
            lines.append(
                f"K = {key:08X}    K1 = {format_hex(key1)}    K2 = {format_hex(key2)}"
            )
        if not keys:
            lines.append("未找到候选密钥：请检查明密文对是否真的由双重加密产生。")
        if self._mitm_demo_key is not None:
            key1, key2 = split_key32(self._mitm_demo_key)
            lines.append("")
            lines.append(
                f"演示数据真实密钥：K = {self._mitm_demo_key:08X}    "
                f"K1 = {format_hex(key1)}    K2 = {format_hex(key2)}"
            )
            lines.append(
                "恢复结果与真实密钥一致 ✓"
                if self._mitm_demo_key in keys
                else "恢复结果与真实密钥不一致 ✗"
            )
        self._write_text(self.mitm_result, "\n".join(lines))

    def _mitm_clear(self) -> None:
        self._write_text(self.mitm_pairs, "")
        self._write_text(self.mitm_result, "")
        self._mitm_demo_key = None
        self.mitm_progress.configure(value=0)
        self.mitm_status.set("（等待操作）")

    # ------------------------------------------------------------------
    # 第 5 关：CBC 模式
    # ------------------------------------------------------------------

    def _build_cbc(self, notebook: ttk.Notebook) -> ttk.Frame:
        page, body = make_scrollable_page(notebook)
        make_page_title(body, "第 5 关 · CBC 工作模式")
        make_hint_label(
            body,
            "C_i = E(P_i ⊕ C_{i-1})，初始向量 IV 为 16 bit，由通信双方共享。"
            "下方还可以翻转密文中的一位，观察 CBC 的差错传播。",
        )

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["md"], 0))
        make_section_label(inner, "加密 / 解密")
        self.cbc_key = tk.StringVar()
        self.cbc_iv = tk.StringVar()
        self._make_field(inner, "密钥 K（16 bit）", self.cbc_key)
        self._make_field(inner, "初始向量 IV（16 bit）", self.cbc_iv)
        ttk.Label(inner, text="明文（UTF-8 / ASCII 字符串）", style="Field.TLabel").pack(anchor="w")
        self.cbc_plain = make_text_area(inner, height=4)
        self.cbc_plain.pack(fill="x", pady=(SPACE["xs"], 0))
        buttons = self._make_buttons(inner)
        self._button(buttons, "加密", self._cbc_encrypt, primary=True)
        self._button(buttons, "解密", self._cbc_decrypt)
        self._button(buttons, "随机示例", self._cbc_sample)
        self._button(buttons, "随机 IV", self._cbc_random_iv)
        self._button(buttons, "清空", self._cbc_clear)

        ttk.Label(inner, text="密文（十六进制，可直接编辑）", style="Field.TLabel").pack(
            anchor="w", pady=(SPACE["sm"], 0)
        )
        self.cbc_cipher = make_text_area(inner, height=4, mono=True)
        self.cbc_cipher.pack(fill="x", pady=(SPACE["xs"], 0))
        ttk.Label(inner, text="解密结果", style="Field.TLabel").pack(
            anchor="w", pady=(SPACE["sm"], 0)
        )
        self.cbc_plain_out = make_text_area(inner, height=4, readonly=True)
        self.cbc_plain_out.pack(fill="x")
        self.cbc_info = tk.StringVar(value="")
        ttk.Label(inner, textvariable=self.cbc_info, style="HintOnSurface.TLabel").pack(
            anchor="w", pady=(SPACE["sm"], 0)
        )

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "加密分组明细（含填充）")
        self.cbc_blocks = self._make_tree(
            inner,
            ("序号", "明文分组", "异或 IV / 前一组密文", "密文分组"),
            (70, 160, 220, 160),
            height=8,
        )

        card, inner = make_card(body)
        card.pack(fill="x", pady=(SPACE["lg"], 0))
        make_section_label(inner, "密文篡改演示")
        make_hint_label(
            inner,
            "翻转某个密文分组中的一位后再解密，对比篡改前后的明文。"
            "该分组会解密成随机噪声，下一分组的对应位会翻转。",
            on_surface=True,
        )
        control = ttk.Frame(inner, style="CardInner.TFrame")
        control.pack(anchor="w", pady=(SPACE["sm"], 0))
        ttk.Label(control, text="篡改分组（从 1 开始）", style="Field.TLabel").pack(side="left")
        self.tamper_block = tk.StringVar(value="1")
        self.tamper_block_spin = ttk.Spinbox(
            control, from_=1, to=1, width=6, textvariable=self.tamper_block, font=FONT["mono"]
        )
        self.tamper_block_spin.pack(side="left", padx=(SPACE["xs"], SPACE["lg"]))
        ttk.Label(control, text="比特位置（0 = 最低位）", style="Field.TLabel").pack(side="left")
        self.tamper_bit = tk.StringVar(value="7")
        ttk.Spinbox(
            control, from_=0, to=15, width=6, textvariable=self.tamper_bit, font=FONT["mono"]
        ).pack(side="left", padx=(SPACE["xs"], 0))

        buttons = self._make_buttons(inner)
        self._button(buttons, "翻转一位并解密", self._cbc_tamper, primary=True)
        self._button(buttons, "恢复密文", self._cbc_restore)

        result_row = ttk.Frame(inner, style="CardInner.TFrame")
        result_row.pack(fill="x", pady=(SPACE["sm"], 0))
        left = ttk.Frame(result_row, style="CardInner.TFrame")
        left.pack(side="left", fill="both", expand=True, padx=(0, SPACE["sm"]))
        ttk.Label(left, text="原始解密结果", style="Field.TLabel").pack(anchor="w")
        self.tamper_original = make_text_area(left, height=4, mono=True, readonly=True)
        # Text 的默认宽度是 80 个字符，两栏并排会把窗口撑破，这里改为跟随父容器
        self.tamper_original.configure(width=1)
        self.tamper_original.pack(fill="x")
        right = ttk.Frame(result_row, style="CardInner.TFrame")
        right.pack(side="left", fill="both", expand=True)
        ttk.Label(right, text="篡改后解密结果", style="Field.TLabel").pack(anchor="w")
        self.tamper_modified = make_text_area(right, height=4, mono=True, readonly=True)
        self.tamper_modified.configure(width=1)
        self.tamper_modified.pack(fill="x")

        self.tamper_diff = tk.StringVar(value="")
        ttk.Label(
            inner, textvariable=self.tamper_diff, style="HintOnSurface.TLabel"
        ).pack(anchor="w", pady=(SPACE["sm"], 0))
        self.tamper_explain = make_text_area(inner, height=4, readonly=True)
        self.tamper_explain.pack(fill="x", pady=(SPACE["xs"], 0))
        return page

    def _cbc_key_iv(self) -> tuple[int, int]:
        key = parse_data(self.cbc_key.get(), 16, "密钥")
        iv = parse_data(self.cbc_iv.get(), 16, "初始向量")
        return key, iv

    def _cbc_encrypt(self) -> None:
        try:
            key, iv = self._cbc_key_iv()
        except SaesError as error:
            self._error(error)
            return

        plaintext = self._read_text(self.cbc_plain)
        if not plaintext:
            self._error(SaesError("明文不能为空"))
            return

        try:
            ciphertext = cbc_encrypt(plaintext.encode("utf-8"), key, iv)
            details = cbc_encrypt_details(plaintext.encode("utf-8"), key, iv)
        except SaesError as error:
            self._error(error)
            return

        self._cbc_last_cipher = ciphertext
        self._write_text(self.cbc_cipher, to_hex(ciphertext))
        self._write_text(self.cbc_plain_out, "")
        self.cbc_info.set(
            f"明文 {len(plaintext.encode('utf-8'))} 字节 → 密文 {len(ciphertext)} 字节，"
            f"共 {len(ciphertext) // 2} 组"
        )
        self.tamper_block_spin.configure(to=max(1, len(ciphertext) // 2))
        self.tamper_block.set("1")

        self.cbc_blocks.delete(*self.cbc_blocks.get_children())
        for index, plain_block, mixed, cipher_block in details:
            self.cbc_blocks.insert(
                "",
                "end",
                values=(
                    index,
                    format_hex(plain_block),
                    format_hex(mixed),
                    format_hex(cipher_block),
                ),
            )

    def _cbc_decrypt(self) -> None:
        try:
            key, iv = self._cbc_key_iv()
            ciphertext = self._parse_hex_bytes(self._read_text(self.cbc_cipher))
            plaintext = cbc_decrypt(ciphertext, key, iv)
        except SaesError as error:
            self._error(error)
            return

        self._write_text(self.cbc_plain_out, to_display(plaintext))
        self.cbc_info.set(f"解密成功，明文 {len(plaintext)} 字节")

    def _cbc_sample(self) -> None:
        self.cbc_key.set(SAMPLE_KEY)
        self.cbc_iv.set("0000 0000 0000 0000")
        self._write_text(self.cbc_plain, "Information Security")
        self._cbc_encrypt()

    def _cbc_random_iv(self) -> None:
        """生成一个 16 bit 随机 IV；IV 本身不需要保密，但双方必须一致。"""
        self.cbc_iv.set(f"{random.getrandbits(16):04X}")

    def _cbc_clear(self) -> None:
        self.cbc_key.set("")
        self.cbc_iv.set("")
        self._write_text(self.cbc_plain, "")
        self._write_text(self.cbc_cipher, "")
        self._write_text(self.cbc_plain_out, "")
        self._write_text(self.tamper_original, "")
        self._write_text(self.tamper_modified, "")
        self.tamper_diff.set("")
        self._write_text(self.tamper_explain, "")
        self.cbc_info.set("")
        self.cbc_blocks.delete(*self.cbc_blocks.get_children())
        self._cbc_last_cipher = None

    def _cbc_tamper(self) -> None:
        try:
            key, iv = self._cbc_key_iv()
            ciphertext = self._parse_hex_bytes(self._read_text(self.cbc_cipher))
            if len(ciphertext) % 2:
                raise SaesError("密文长度必须是 2 字节的整数倍")
            block_count = len(ciphertext) // 2
            if block_count == 0:
                raise SaesError("密文不能为空")
            block_index = int(self.tamper_block.get(), 10) - 1
            bit_index = int(self.tamper_bit.get(), 10)
            tampered = flip_bit(ciphertext, block_index, bit_index)
            original_plain = cbc_decrypt(ciphertext, key, iv, unpad_data=False)
            tampered_plain = cbc_decrypt(tampered, key, iv, unpad_data=False)
        except (SaesError, ValueError) as error:
            self._error(SaesError(str(error)))
            return

        self._write_text(
            self.tamper_original,
            f"HEX: {to_hex(original_plain)}\nTXT: {to_display(original_plain)}",
        )
        self._write_text(
            self.tamper_modified,
            f"HEX: {to_hex(tampered_plain)}\nTXT: {to_display(tampered_plain)}",
        )

        differences = [
            f"字节 {index}（第 {index // 2 + 1} 组）：{left:02X} → {right:02X}"
            for index, (left, right) in enumerate(zip(original_plain, tampered_plain))
            if left != right
        ]
        self.tamper_diff.set(
            "明文共 " + str(len(original_plain)) + " 字节，变化 " + str(len(differences)) + " 字节"
        )
        bit_in_block = bit_index
        byte_in_block = 0 if bit_in_block >= 8 else 1
        affected_byte = block_index * 2 + byte_in_block
        explain = [
            f"翻转了第 {block_index + 1} 个密文分组的第 {bit_index} 位"
            f"（该分组内第 {affected_byte - block_index * 2 + 1} 字节）。",
            f"CBC 解密时 P_i = D(C_i) ⊕ C_(i-1)：",
            f"• 被篡改的分组（第 {block_index + 1} 组）解密成随机噪声，"
            f"对应明文字节 {block_index * 2} ~ {block_index * 2 + 1} 全部改变；",
        ]
        if block_index + 1 < block_count:
            # 16 bit 分组中 bit 15~8 属于第一个字节，bit 7~0 属于第二个字节
            next_byte_offset = 0 if bit_index >= 8 else 1
            explain.append(
                f"• 下一分组（第 {block_index + 2} 组）的同一比特位被翻转，"
                f"对应明文字节 {block_index * 2 + 2 + next_byte_offset} 发生一位变化；"
            )
        else:
            explain.append("• 这是最后一个分组，没有后续分组受影响。")
        explain.append("• 更靠后的分组不受影响。")
        if differences:
            explain.append("实际变化的字节：" + "；".join(differences))
        explain.append("注：此处展示的是未去填充的原始解密字节；正常解密还会校验填充。")
        self._write_text(self.tamper_explain, "\n".join(explain))

    def _cbc_restore(self) -> None:
        if self._cbc_last_cipher is None:
            self._error(SaesError("还没有可恢复的密文，请先加密一次"))
            return
        self._write_text(self.cbc_cipher, to_hex(self._cbc_last_cipher))
        self._write_text(self.tamper_original, "")
        self._write_text(self.tamper_modified, "")
        self.tamper_diff.set("")
        self._write_text(self.tamper_explain, "")


def main() -> None:
    """启动图形界面。"""
    # 高 DPI 屏幕上避免 Tkinter 界面被系统拉伸导致模糊
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass

    root = tk.Tk()
    SaesApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
