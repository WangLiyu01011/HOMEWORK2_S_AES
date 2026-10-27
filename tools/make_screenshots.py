"""自动截取五个关卡的操作界面，保存到 ``results/screenshots/``。

需要 Pillow（仅截图工具使用，程序本身不依赖它）::

    python -m pip install pillow
    python -m tools.make_screenshots
"""

from __future__ import annotations

import ctypes
import time
import tkinter as tk
from pathlib import Path

from PIL import ImageGrab

from gui.app import SaesApp

OUTPUT = Path(__file__).resolve().parent.parent / "results" / "screenshots"


def pump(root: tk.Tk, seconds: float = 0.35) -> None:
    """处理 Tk 事件并等待界面完成重绘。"""
    deadline = time.perf_counter() + seconds
    while time.perf_counter() < deadline:
        root.update()
        time.sleep(0.02)


def find_canvas(widget: tk.Misc) -> tk.Canvas | None:
    """在可滚动页面里找到承载内容的 Canvas。"""
    for child in widget.winfo_children():
        if isinstance(child, tk.Canvas):
            return child
        found = find_canvas(child)
        if found is not None:
            return found
    return None


def scroll_to_bottom(root: tk.Tk, page: tk.Misc) -> None:
    canvas = find_canvas(page)
    if canvas is not None:
        canvas.yview_moveto(1.0)
    pump(root, 0.4)


def scroll_to(root: tk.Tk, page: tk.Misc, fraction: float) -> None:
    canvas = find_canvas(page)
    if canvas is not None:
        canvas.yview_moveto(fraction)
    pump(root, 0.4)


def capture(root: tk.Tk, name: str) -> None:
    pump(root)
    x = root.winfo_rootx()
    y = root.winfo_rooty()
    width = root.winfo_width()
    height = root.winfo_height()
    image = ImageGrab.grab(bbox=(x, y, x + width, y + height))
    path = OUTPUT / name
    image.save(path)
    print(f"已保存 {path}")


def main() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass

    OUTPUT.mkdir(parents=True, exist_ok=True)

    root = tk.Tk()
    root.geometry("1180x840+40+30")
    app = SaesApp(root)
    root.update()
    root.attributes("-topmost", True)
    root.lift()
    root.focus_force()
    pump(root)

    tabs = app.notebook.tabs()

    def page(index: int) -> tk.Misc:
        return root.nametowidget(tabs[index])

    # 第 1 关：填入标准向量并加密
    app.notebook.select(tabs[0])
    app._basic_sample()
    capture(root, "01a_basic.png")
    scroll_to(root, page(0), 0.30)
    capture(root, "01b_basic_detail.png")
    scroll_to(root, page(0), 0.62)
    capture(root, "01c_basic_key.png")
    scroll_to_bottom(root, page(0))
    capture(root, "01d_basic_structure.png")

    # 第 2 关：生成并校验 10 组向量
    app.notebook.select(tabs[1])
    app.cross_count.set("30")
    app.cross_seed.set("20261019")
    app._cross_generate()
    capture(root, "02a_cross_generate.png")
    app._write_text(app.cross_input, app._read_text(app.cross_output))
    app._cross_check()
    scroll_to(root, page(1), 0.35)
    capture(root, "02b_cross_check.png")
    scroll_to_bottom(root, page(1))
    capture(root, "02c_cross_standard.png")

    # 第 3 关：字符串加解密
    app.notebook.select(tabs[2])
    app._text_sample()
    app._text_decrypt()
    capture(root, "03a_text.png")
    scroll_to_bottom(root, page(2))
    capture(root, "03b_text_result.png")

    # 第 4 关：使用报告中的固定向量，保证截图与文字表格一致
    app.notebook.select(tabs[3])
    app.double_key.set("1A2B3C4D")
    app.double_input.set("6F6B")
    app._double_encrypt()
    app.triple_mode.set("ede2")
    app._triple_mode_changed()
    app.triple_key.set("1A2B3C4D")
    app.triple_input.set("6F6B")
    app._triple_encrypt()
    capture(root, "04a_multi_top.png")

    # MITM 也使用报告表中的固定 3 组向量
    app._write_text(app.mitm_pairs, "1234 F04D\nABCD F571\n5555 06A0")
    app._mitm_demo_key = 0x1A2B3C4D
    app._mitm_start()
    deadline = time.perf_counter() + 15
    while app._mitm_running and time.perf_counter() < deadline:
        pump(root, 0.1)
    pump(root)
    scroll_to_bottom(root, page(3))
    capture(root, "04b_multi_mitm.png")

    # 第 5 关：使用报告中的固定 K / IV / 明文
    app.notebook.select(tabs[4])
    app.cbc_key.set("A73B")
    app.cbc_iv.set("1234")
    app._write_text(app.cbc_plain, "Information Security")
    app._cbc_encrypt()
    app._cbc_decrypt()
    capture(root, "05a_cbc_top.png")
    app.tamper_block.set("1")
    app.tamper_bit.set("3")
    app._cbc_tamper()
    scroll_to_bottom(root, page(4))
    capture(root, "05b_cbc_tamper.png")

    root.destroy()


if __name__ == "__main__":
    main()
