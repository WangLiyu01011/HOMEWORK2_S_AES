"""界面设计系统：颜色、间距、字体等设计 token，以及统一的 ttk 样式。

全部视觉参数集中在这里，``gui/app.py`` 只引用 token、不写死颜色与字号，
改主题时只需动这一个文件。

**关于 Tkinter 的能力边界**（决定了为什么某些 Web 上的常见做法这里没有）：

* ``ttk`` 控件**不支持圆角**，也无法绘制 CSS 那样的 ``box-shadow``；
* **没有 CSS 过渡/动画**，所谓"微交互"只能靠 ``style.map()`` 做
  hover / pressed / focus / disabled 的状态换色，没有缓动；
* 因此本主题的"高级感"主要靠 **克制的配色 + 充分的留白 + 统一的
  1px 细边框 + 一致的状态反馈** 来实现，而不是圆角和阴影。
  这是原生 Tkinter 能达到的上限，硬做圆角需要自绘 Canvas 控件，
  会大幅增加复杂度且容易在高 DPI 下出问题。

对比度：正文与背景的对比度均满足 WCAG AA（≥ 4.5:1），
次要文字（``TEXT_MUTED``）在浅色背景上约为 5.0:1，也达到了 AA。
"""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

__all__ = [
    "apply_theme",
    "make_card",
    "make_scrollable_page",
    "make_text_area",
    "make_section_label",
    "make_hint_label",
    "make_page_title",
    "COLORS",
    "SPACE",
    "FONT",
]

# ---------------------------------------------------------------------------
# 颜色：中性色为主，单一强调色（靛蓝），语义色克制使用
# ---------------------------------------------------------------------------

COLORS = {
    # 背景层次：窗口底 → 卡片面 → 输入面
    "bg": "#F6F7F9",
    "surface": "#FFFFFF",
    "surface_sunken": "#FBFBFC",
    # 中性阶（含边框与不同层级的文字）
    "neutral_50": "#F9FAFB",
    "neutral_100": "#F2F4F7",
    "neutral_200": "#EAECF0",
    "neutral_300": "#D0D5DD",
    "neutral_400": "#98A2B3",
    "neutral_500": "#667085",
    "neutral_600": "#475467",
    "neutral_700": "#344054",
    # 边框
    "border": "#E4E7EC",
    "border_strong": "#D0D5DD",
    # 文字
    "text": "#101828",
    "text_muted": "#667085",
    "text_faint": "#98A2B3",
    "text_on_accent": "#FFFFFF",
    # 强调色（唯一）
    "accent": "#5E6AD2",
    "accent_hover": "#4F5AC2",
    "accent_pressed": "#454FB0",
    "accent_subtle": "#EEF0FB",
    # 语义色
    "success": "#067647",
    "success_subtle": "#ECFDF3",
    "danger": "#B42318",
    "danger_subtle": "#FEF3F2",
    "warning": "#B54708",
}

# ---------------------------------------------------------------------------
# 间距：统一的 4pt 网格
# ---------------------------------------------------------------------------

SPACE = {
    "xs": 4,
    "sm": 8,
    "md": 12,
    "lg": 16,
    "xl": 24,
    "2xl": 32,
    "3xl": 40,
}

# ---------------------------------------------------------------------------
# 字体：正文字号 10pt（≈13.3px），标题紧凑，二进制数据用等宽字体
# ---------------------------------------------------------------------------

_FAMILY = "Microsoft YaHei UI"
_MONO = "Consolas"

FONT = {
    "page_title": (_FAMILY, 15, "bold"),
    "section": (_FAMILY, 10, "bold"),
    "body": (_FAMILY, 10),
    "small": (_FAMILY, 9),
    "button": (_FAMILY, 10),
    "mono": (_MONO, 10),
    "mono_small": (_MONO, 9),
    "result": (_MONO, 17, "bold"),
    "log": (_MONO, 9),
}


def apply_theme(root: tk.Misc) -> ttk.Style:
    """把本设计系统应用到整个窗口。

    参数:
        root: 根窗口（或任何 Tk 部件）。

    返回:
        配置好的 :class:`ttk.Style` 实例，便于调用方追加自定义样式。
    """
    style = ttk.Style(root)
    # clam 是各平台差异最小、最便于完整覆写的内置主题
    if "clam" in style.theme_names():
        style.theme_use("clam")

    root.configure(background=COLORS["bg"])

    _style_base(style)
    _style_buttons(style)
    _style_inputs(style)
    _style_notebook(style)
    _style_containers(style)
    _style_tables(style)
    _style_misc(style)
    return style


def _style_base(style: ttk.Style) -> None:
    """全局默认字体、背景与焦点样式。"""
    style.configure(
        ".",
        background=COLORS["bg"],
        foreground=COLORS["text"],
        font=FONT["body"],
        focuscolor=COLORS["accent"],
        bordercolor=COLORS["border"],
    )
    style.configure("TFrame", background=COLORS["bg"])
    style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"])

    # 页面大标题
    style.configure(
        "PageTitle.TLabel",
        background=COLORS["bg"],
        foreground=COLORS["text"],
        font=FONT["page_title"],
    )
    # 段落小标题（卡片标题）
    style.configure(
        "Section.TLabel",
        background=COLORS["surface"],
        foreground=COLORS["text"],
        font=FONT["section"],
    )
    # 次要说明文字
    style.configure(
        "Hint.TLabel",
        background=COLORS["bg"],
        foreground=COLORS["text_muted"],
        font=FONT["small"],
    )
    style.configure(
        "HintOnSurface.TLabel",
        background=COLORS["surface"],
        foreground=COLORS["text_muted"],
        font=FONT["small"],
    )
    style.configure(
        "MonoOnSurface.TLabel",
        background=COLORS["surface"],
        foreground=COLORS["text"],
        font=FONT["mono"],
    )
    # 卡片内的字段标签。默认 TLabel 的背景是页面灰，直接放进白卡片会形成灰块
    style.configure(
        "Field.TLabel",
        background=COLORS["surface"],
        foreground=COLORS["text"],
        font=FONT["body"],
    )


def _style_buttons(style: ttk.Style) -> None:
    """按钮：主操作（实心强调色）与次操作（描边）两种层级。"""
    # 次操作：白底 + 细边框，hover 时边框加深、底色变浅灰。
    # relief 必须是 "solid"：clam 下 "flat" 会完全跳过边框绘制，
    # 按钮会退化成一行纯文字（已实测确认）。
    style.configure(
        "Secondary.TButton",
        background=COLORS["surface"],
        foreground=COLORS["text"],
        bordercolor=COLORS["border_strong"],
        lightcolor=COLORS["border_strong"],
        darkcolor=COLORS["border_strong"],
        focuscolor=COLORS["surface"],
        font=FONT["button"],
        padding=(14, 6),
        relief="solid",
        borderwidth=1,
    )
    style.map(
        "Secondary.TButton",
        background=[
            ("disabled", COLORS["neutral_100"]),
            ("pressed", COLORS["neutral_200"]),
            ("active", COLORS["neutral_100"]),
        ],
        foreground=[("disabled", COLORS["text_faint"])],
        bordercolor=[("active", COLORS["neutral_400"]), ("disabled", COLORS["border"])],
        lightcolor=[("active", COLORS["neutral_400"])],
        darkcolor=[("active", COLORS["neutral_400"])],
    )

    # 主操作：实心强调色，一个页面只出现一次
    style.configure(
        "Primary.TButton",
        background=COLORS["accent"],
        foreground=COLORS["text_on_accent"],
        bordercolor=COLORS["accent"],
        lightcolor=COLORS["accent"],
        darkcolor=COLORS["accent"],
        focuscolor=COLORS["accent"],
        font=FONT["button"],
        padding=(16, 7),
        relief="flat",
        borderwidth=1,
    )
    style.map(
        "Primary.TButton",
        background=[
            ("disabled", COLORS["neutral_200"]),
            ("pressed", COLORS["accent_pressed"]),
            ("active", COLORS["accent_hover"]),
        ],
        foreground=[("disabled", COLORS["text_faint"])],
        bordercolor=[
            ("disabled", COLORS["neutral_200"]),
            ("pressed", COLORS["accent_pressed"]),
            ("active", COLORS["accent_hover"]),
        ],
        lightcolor=[("active", COLORS["accent_hover"]), ("pressed", COLORS["accent_pressed"])],
        darkcolor=[("active", COLORS["accent_hover"]), ("pressed", COLORS["accent_pressed"])],
    )


def _style_inputs(style: ttk.Style) -> None:
    """输入控件：无内阴影的扁平输入框，聚焦时边框变为强调色（充当焦点环）。"""
    for name in ("TEntry", "TSpinbox", "TCombobox"):
        style.configure(
            name,
            fieldbackground=COLORS["surface"],
            background=COLORS["surface"],
            foreground=COLORS["text"],
            bordercolor=COLORS["border_strong"],
            lightcolor=COLORS["border_strong"],
            darkcolor=COLORS["border_strong"],
            insertcolor=COLORS["text"],
            arrowcolor=COLORS["neutral_500"],
            padding=(8, 6),
            relief="flat",
            borderwidth=1,
        )
        # 聚焦时四周描边变强调色——Tkinter 没有 box-shadow，用这个代替焦点环
        style.map(
            name,
            bordercolor=[("focus", COLORS["accent"]), ("hover", COLORS["neutral_400"])],
            lightcolor=[("focus", COLORS["accent"]), ("hover", COLORS["neutral_400"])],
            darkcolor=[("focus", COLORS["accent"]), ("hover", COLORS["neutral_400"])],
            fieldbackground=[("disabled", COLORS["neutral_100"])],
            foreground=[("disabled", COLORS["text_faint"])],
        )

    style.configure(
        "TCheckbutton",
        background=COLORS["bg"],
        foreground=COLORS["text"],
        focuscolor=COLORS["bg"],
        font=FONT["body"],
        padding=(0, 4),
        indicatorcolor=COLORS["surface"],
        indicatorrelief="flat",
    )
    style.map(
        "TCheckbutton",
        background=[("active", COLORS["bg"])],
        foreground=[("disabled", COLORS["text_faint"])],
        indicatorcolor=[
            ("selected", COLORS["accent"]),
            ("pressed", COLORS["accent_pressed"]),
            ("active", COLORS["accent_hover"]),
        ],
    )


def _style_notebook(style: ttk.Style) -> None:
    """标签页：去掉立体感，选中项用白色卡片面 + 强调色下划线暗示。"""
    style.configure(
        "TNotebook",
        background=COLORS["bg"],
        bordercolor=COLORS["border"],
        lightcolor=COLORS["bg"],
        darkcolor=COLORS["bg"],
        tabmargins=(0, 0, 0, 0),
        borderwidth=0,
    )
    style.configure(
        "TNotebook.Tab",
        background=COLORS["bg"],
        foreground=COLORS["text_muted"],
        font=FONT["body"],
        padding=(18, 10),
        borderwidth=0,
        lightcolor=COLORS["bg"],
        darkcolor=COLORS["bg"],
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", COLORS["surface"]), ("active", COLORS["neutral_100"])],
        foreground=[("selected", COLORS["accent"]), ("active", COLORS["text"])],
        lightcolor=[("selected", COLORS["surface"])],
        darkcolor=[("selected", COLORS["surface"])],
        expand=[("selected", (0, 0, 0, 0))],
    )


def _style_containers(style: ttk.Style) -> None:
    """容器：卡片式分组框，只有一条 1px 细边框，不加阴影。"""
    style.configure(
        "Card.TFrame",
        background=COLORS["surface"],
        borderwidth=1,
        relief="solid",
        bordercolor=COLORS["border"],
    )
    style.configure(
        "CardInner.TFrame",
        background=COLORS["surface"],
        borderwidth=0,
    )
    style.configure(
        "TLabelframe",
        background=COLORS["surface"],
        bordercolor=COLORS["border"],
        lightcolor=COLORS["surface"],
        darkcolor=COLORS["surface"],
        borderwidth=1,
        relief="solid",
        padding=SPACE["md"],
    )
    style.configure(
        "TLabelframe.Label",
        background=COLORS["surface"],
        foreground=COLORS["text_muted"],
        font=FONT["small"],
    )


def _style_tables(style: ttk.Style) -> None:
    """表格：轻表头、无网格线、选中行用强调色的浅色底。"""
    style.configure(
        "Treeview",
        background=COLORS["surface"],
        fieldbackground=COLORS["surface"],
        foreground=COLORS["text"],
        bordercolor=COLORS["border"],
        lightcolor=COLORS["surface"],
        darkcolor=COLORS["surface"],
        borderwidth=0,
        relief="flat",
        font=FONT["mono"],
        rowheight=26,
    )
    style.map(
        "Treeview",
        background=[("selected", COLORS["accent_subtle"])],
        foreground=[("selected", COLORS["text"])],
    )
    style.configure(
        "Treeview.Heading",
        background=COLORS["neutral_50"],
        foreground=COLORS["text_muted"],
        font=FONT["small"],
        relief="flat",
        borderwidth=0,
        padding=(10, 8),
    )
    style.map(
        "Treeview.Heading",
        background=[("active", COLORS["neutral_100"])],
        foreground=[("active", COLORS["text"])],
    )


def _style_misc(style: ttk.Style) -> None:
    """进度条与滚动条：细、扁平、低干扰。"""
    style.configure(
        "Accent.Horizontal.TProgressbar",
        background=COLORS["accent"],
        troughcolor=COLORS["neutral_100"],
        bordercolor=COLORS["neutral_100"],
        lightcolor=COLORS["accent"],
        darkcolor=COLORS["accent"],
        thickness=6,
        borderwidth=0,
    )
    for orient in ("Vertical", "Horizontal"):
        style.configure(
            f"{orient}.TScrollbar",
            background=COLORS["neutral_300"],
            troughcolor=COLORS["bg"],
            bordercolor=COLORS["bg"],
            arrowcolor=COLORS["neutral_500"],
            lightcolor=COLORS["neutral_300"],
            darkcolor=COLORS["neutral_300"],
            relief="flat",
            borderwidth=0,
            arrowsize=12,
        )
        style.map(
            f"{orient}.TScrollbar",
            background=[("active", COLORS["neutral_400"])],
        )
    style.configure("TSeparator", background=COLORS["border"])


# ---------------------------------------------------------------------------
# 组合控件工厂：把"卡片 / 文本区"这类重复结构收敛成几个函数
# ---------------------------------------------------------------------------


def make_scrollable_page(
    parent: tk.Widget, padding: int = SPACE["xl"]
) -> tuple[ttk.Frame, ttk.Frame]:
    """创建一个可滚动的页面容器。

    内容超出窗口高度时可以滚动查看（第 3、4 关内容较长，在 768p 屏幕上
    必然超出）。滚动条**只在内容真的超高时才出现**，正常尺寸下不占空间。

    实现是 Tkinter 的经典套路：``Canvas`` + 内嵌 ``Frame``。
    关键点是让内嵌 Frame 的宽度跟随 Canvas，否则子控件的 ``fill="x"`` 不会生效。

    参数:
        parent: 父容器（通常是 Notebook）。
        padding: 内容区四周的内边距。

    返回:
        ``(外层容器, 内容区)``。把页面内容放进内容区即可。
    """
    outer = ttk.Frame(parent)
    canvas = tk.Canvas(
        outer,
        background=COLORS["bg"],
        highlightthickness=0,
        borderwidth=0,
    )
    scrollbar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=scrollbar.set)
    canvas.pack(side="left", fill="both", expand=True)

    inner = ttk.Frame(canvas, padding=padding)
    window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

    def sync_scroll_region(_event: object = None) -> None:
        """更新可滚动范围，并按需显示/隐藏滚动条。"""
        bounds = canvas.bbox("all")
        if bounds is None:
            return
        canvas.configure(scrollregion=bounds)
        overflows = (bounds[3] - bounds[1]) > canvas.winfo_height()
        if overflows and not scrollbar.winfo_ismapped():
            scrollbar.pack(side="right", fill="y")
        elif not overflows and scrollbar.winfo_ismapped():
            scrollbar.pack_forget()

    def fit_width(event: tk.Event) -> None:
        """让内嵌 Frame 的宽度等于 Canvas 宽度，使 fill="x" 生效。"""
        canvas.itemconfigure(window_id, width=event.width)
        sync_scroll_region()

    def on_wheel(event: tk.Event) -> None:
        """鼠标滚轮滚动——仅当指针确实位于本页面上时才响应。"""
        if not canvas.winfo_ismapped():
            return
        left, top = canvas.winfo_rootx(), canvas.winfo_rooty()
        if not (
            left <= event.x_root < left + canvas.winfo_width()
            and top <= event.y_root < top + canvas.winfo_height()
        ):
            return
        canvas.yview_scroll(int(-event.delta / 120), "units")

    inner.bind("<Configure>", sync_scroll_region)
    canvas.bind("<Configure>", fit_width)
    # add="+" 让多个页面各自保留滚轮处理函数；处理函数内部会判断
    # 鼠标是否真的在本页面上方，因此不会互相抢事件。
    canvas.bind_all("<MouseWheel>", on_wheel, add="+")

    return outer, inner


def make_card(parent: tk.Widget, padding: int = SPACE["lg"]) -> tuple[ttk.Frame, ttk.Frame]:
    """创建一个白色卡片容器。

    参数:
        parent: 父容器。
        padding: 卡片内边距。

    返回:
        ``(外框, 内容区)``。外框负责 1px 细边框，内容区已有内边距，
        把子控件放进内容区即可。
    """
    outer = ttk.Frame(parent, style="Card.TFrame")
    inner = ttk.Frame(outer, style="CardInner.TFrame", padding=padding)
    inner.pack(fill="both", expand=True)
    return outer, inner


def make_text_area(
    parent: tk.Widget,
    height: int = 4,
    mono: bool = False,
    readonly: bool = False,
) -> tk.Text:
    """创建一个与主题一致的文本区。

    ``tk.Text`` 不是 ttk 控件，无法用 Style 配置，只能在实例上逐个设置。
    这里用 ``highlightthickness=1`` 画一条 1px 边框，并让它在聚焦时变成
    强调色——效果等同于 Web 上的 focus ring。

    参数:
        parent: 父容器。
        height: 显示行数。
        mono: 是否使用等宽字体（二进制、密钥等数据用）。
        readonly: 是否只读（用作输出展示区）。

    返回:
        配置好的 :class:`tk.Text`。
    """
    background = COLORS["surface_sunken"] if readonly else COLORS["surface"]
    widget = tk.Text(
        parent,
        height=height,
        font=FONT["mono"] if mono else FONT["body"],
        wrap="word",
        background=background,
        foreground=COLORS["text"],
        insertbackground=COLORS["text"],
        selectbackground=COLORS["accent_subtle"],
        selectforeground=COLORS["text"],
        relief="flat",
        borderwidth=0,
        highlightthickness=1,
        highlightbackground=COLORS["border_strong"],
        highlightcolor=COLORS["accent"],
        padx=SPACE["sm"],
        pady=SPACE["sm"],
        # 行间距，让多行文本更透气
        spacing1=1,
        spacing3=2,
    )
    if readonly:
        # 只读区不接收键盘焦点移动，但仍可选中复制
        widget.configure(state="disabled")

    return widget


def make_page_title(parent: tk.Widget, text: str) -> ttk.Label:
    """页面主标题。"""
    label = ttk.Label(parent, text=text, style="PageTitle.TLabel")
    label.pack(anchor="w", pady=(0, SPACE["xs"]))
    return label


def make_section_label(parent: tk.Widget, text: str) -> ttk.Label:
    """卡片内的小节标题。"""
    label = ttk.Label(parent, text=text, style="Section.TLabel")
    label.pack(anchor="w", pady=(0, SPACE["sm"]))
    return label


def make_hint_label(
    parent: tk.Widget,
    text: str,
    on_surface: bool = False,
    wraplength: int = 1020,
) -> ttk.Label:
    """次要说明文字。长文本会自动换行，避免在窗口右侧被截断。"""
    label = ttk.Label(
        parent,
        text=text,
        style="HintOnSurface.TLabel" if on_surface else "Hint.TLabel",
        wraplength=wraplength,
        justify="left",
    )
    label.pack(anchor="w")
    return label
