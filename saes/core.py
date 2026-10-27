"""S-AES（简化 AES）核心实现。

本模块严格按《密码编码学与网络安全——原理与实践（第 8 版）》
**附录 D：简化 AES** 的记号与运算序列组织：

* D.1  总体结构：16 bit 分组、16 bit 密钥、2 轮；
* D.2.1 密钥加 ``AK``；
* D.2.2 半字节代替 ``NS``；
* D.2.3 行移位 ``SR``；
* D.2.4 列混淆 ``MC``；
* D.3  密钥扩展（``w0 ~ w5``、``RCON(1)=0x80``、``RCON(2)=0x30``）；
* 附件 D.1  GF(2^4) 加法与乘法；
* 附件 D.2  列混淆的多项式解释。

教材把加密写成复合函数（从右向左执行）::

    加密 = AK2 ∘ SR ∘ NS ∘ AK1 ∘ MC ∘ SR ∘ NS ∘ AK0
    解密 = AK0 ∘ INS ∘ ISR ∘ IMC ∘ AK1 ∘ INS ∘ ISR ∘ AK2

数据表示
--------
状态是 2×2 的半字节矩阵，行、列下标与教材一致::

        s00  s01
        s10  s11

16 bit 分组 ``b0 b1 ... b15`` 按列优先填入（图 D.2(a)）::

        b0..b3    b8..b11
        b4..b7    b12..b15

因此 ``state_from_block(0xABCD)`` 得到 ``((0xA, 0xC), (0xB, 0xD))``。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

__all__ = [
    "BLOCK_BITS",
    "KEY_BITS",
    "SBOX",
    "INV_SBOX",
    "RCON",
    "MUL2",
    "MUL4",
    "MUL9",
    "State",
    "SaesError",
    "KeySchedule",
    "OperationStep",
    "expand_key",
    "key_expansion_rows",
    "state_from_block",
    "state_to_block",
    "add_round_key",
    "nibble_substitution",
    "inverse_nibble_substitution",
    "shift_rows",
    "inverse_shift_rows",
    "mix_columns",
    "inverse_mix_columns",
    "encrypt_state",
    "decrypt_state",
    "make_schedule",
    "encrypt_with_schedule",
    "decrypt_with_schedule",
    "encrypt_block",
    "decrypt_block",
    "trace_operation_steps",
    "trace_encryption",
    "trace_decryption",
    "parse_data",
    "format_bits",
    "format_hex",
    "gf_mul",
]

BLOCK_BITS = 16
KEY_BITS = 16

#: S 盒（表 D.1(a)）：行 = 最左侧 2 位，列 = 最右侧 2 位
SBOX: tuple[int, ...] = (
    0x9, 0x4, 0xA, 0xB,
    0xD, 0x1, 0x8, 0x5,
    0x6, 0x2, 0x0, 0x3,
    0xC, 0xE, 0xF, 0x7,
)

#: 逆 S 盒（表 D.1(b)），由 SBOX 反查得到
INV_SBOX: tuple[int, ...] = tuple(SBOX.index(value) for value in range(16))

#: 轮常量 RCON(1)、RCON(2)（D.3）
RCON: tuple[int, ...] = (0x80, 0x30)

#: 2×2 状态矩阵。外层为行，内层为列：state[row][column]
State = tuple[tuple[int, int], tuple[int, int]]


def _build_mul_table(factor: int) -> tuple[int, ...]:
    """构造附录 D.1 表 D.2(b) 的一行：``factor`` 与 0~F 的乘积。"""
    table = []
    for value in range(16):
        product = 0
        a, b = value, factor
        for _ in range(4):
            if b & 1:
                product ^= a
            b >>= 1
            a <<= 1
            if a & 0x10:  # 超过 4 次，对 x^4 + x + 1 取模
                a ^= 0x13
        table.append(product & 0xF)
    return tuple(table)


MUL2: tuple[int, ...] = _build_mul_table(2)
MUL4: tuple[int, ...] = _build_mul_table(4)
MUL9: tuple[int, ...] = _build_mul_table(9)


class SaesError(ValueError):
    """输入数据不合法（位数、长度、格式等）时抛出。"""


@dataclass(frozen=True)
class KeySchedule:
    """密钥扩展结果（D.3）。

    ``k0`` 是主密钥，``k1``、``k2`` 是第 1、2 轮密钥；
    6 个字节 ``w0 ~ w5`` 可由 :attr:`words` 取得。
    """

    k0: int
    k1: int
    k2: int

    @property
    def round_keys(self) -> tuple[int, int, int]:
        return (self.k0, self.k1, self.k2)

    @property
    def words(self) -> tuple[int, int, int, int, int, int]:
        """按教材记号返回 ``(w0, w1, w2, w3, w4, w5)``。"""
        return (
            (self.k0 >> 8) & 0xFF,
            self.k0 & 0xFF,
            (self.k1 >> 8) & 0xFF,
            self.k1 & 0xFF,
            (self.k2 >> 8) & 0xFF,
            self.k2 & 0xFF,
        )

    def states(self) -> tuple[State, State, State]:
        """把 3 个轮密钥转成 2×2 状态矩阵。"""
        return tuple(state_from_block(key) for key in self.round_keys)  # type: ignore[return-value]


@dataclass(frozen=True)
class OperationStep:
    """一次 S-AES 运算后的状态，用于界面逐步展示。"""

    round_index: int
    operation: str
    title: str
    state: State

    @property
    def block(self) -> int:
        return state_to_block(self.state)


def _require_bits(value: int, bits: int, name: str) -> int:
    if not isinstance(value, int):
        raise SaesError(f"{name}必须是整数，当前类型为 {type(value).__name__}")
    if not 0 <= value < (1 << bits):
        raise SaesError(f"{name}必须是 {bits} bit（0 ~ 0x{1 << bits:X}），当前值为 {value}")
    return value


# ---------------------------------------------------------------------------
# 状态与 16 bit 分组的相互转换（图 D.2）
# ---------------------------------------------------------------------------


def state_from_block(block: int) -> State:
    """把 16 bit 分组按列优先填入 2×2 状态矩阵。

    例：``0xABCD`` → ``((0xA, 0xC), (0xB, 0xD))``。
    """
    _require_bits(block, BLOCK_BITS, "分组")
    n0 = (block >> 12) & 0xF
    n1 = (block >> 8) & 0xF
    n2 = (block >> 4) & 0xF
    n3 = block & 0xF
    return ((n0, n2), (n1, n3))


def state_to_block(state: State) -> int:
    """把 2×2 状态矩阵按列优先拼回 16 bit 分组。"""
    (s00, s01), (s10, s11) = state
    return (s00 << 12) | (s10 << 8) | (s01 << 4) | s11


# ---------------------------------------------------------------------------
# D.2 四个基本变换及其逆
# ---------------------------------------------------------------------------


def add_round_key(state: State, round_key: State) -> State:
    """D.2.1 密钥加 ``AK``：状态与轮密钥逐位异或。"""
    (s00, s01), (s10, s11) = state
    (k00, k01), (k10, k11) = round_key
    return (
        (s00 ^ k00, s01 ^ k01),
        (s10 ^ k10, s11 ^ k11),
    )


def nibble_substitution(state: State) -> State:
    """D.2.2 半字节代替 ``NS``：对 4 个半字节分别查 S 盒。"""
    (s00, s01), (s10, s11) = state
    return (
        (SBOX[s00], SBOX[s01]),
        (SBOX[s10], SBOX[s11]),
    )


def inverse_nibble_substitution(state: State) -> State:
    """``INS``：查逆 S 盒。"""
    (s00, s01), (s10, s11) = state
    return (
        (INV_SBOX[s00], INV_SBOX[s01]),
        (INV_SBOX[s10], INV_SBOX[s11]),
    )


def shift_rows(state: State) -> State:
    """D.2.3 行移位 ``SR``：第二行循环左移一个半字节，第一行不变。"""
    (s00, s01), (s10, s11) = state
    return ((s00, s01), (s11, s10))


def inverse_shift_rows(state: State) -> State:
    """``ISR``：第二行循环右移一个半字节。

    对 2 个半字节的行而言，左移与右移等价，因此与 ``SR`` 相同；
    单独保留函数名是为了与教材的复合函数记号一一对应。
    """
    return shift_rows(state)


def mix_columns(state: State) -> State:
    """D.2.4 列混淆 ``MC``：每列左乘矩阵 ``[[1,4],[4,1]]``。"""
    (s00, s01), (s10, s11) = state
    return (
        (s00 ^ MUL4[s10], s01 ^ MUL4[s11]),
        (MUL4[s00] ^ s10, MUL4[s01] ^ s11),
    )


def inverse_mix_columns(state: State) -> State:
    """``IMC``：每列左乘逆矩阵 ``[[9,2],[2,9]]``。"""
    (s00, s01), (s10, s11) = state
    return (
        (MUL9[s00] ^ MUL2[s10], MUL9[s01] ^ MUL2[s11]),
        (MUL2[s00] ^ MUL9[s10], MUL2[s01] ^ MUL9[s11]),
    )


# ---------------------------------------------------------------------------
# D.3 密钥扩展
# ---------------------------------------------------------------------------


def _g(word: int, rcon: int) -> int:
    """函数 g：RotNib → SubNib → 异或轮常量（图 D.5(b)）。"""
    rotated = ((word & 0x0F) << 4) | (word >> 4)
    substituted = (SBOX[rotated >> 4] << 4) | SBOX[rotated & 0x0F]
    return substituted ^ rcon


def expand_key(key: int) -> KeySchedule:
    """D.3 密钥扩展：把 16 bit 主密钥扩展为 48 bit（3 个轮密钥）。

    教材示例 ``K = 2D55`` 的结果为 ``w2=BC, w3=E9, w4=A3, w5=4A``，
    即 ``K1=BCE9``、``K2=A34A``。
    """
    _require_bits(key, KEY_BITS, "密钥")
    w0, w1 = (key >> 8) & 0xFF, key & 0xFF
    w2 = w0 ^ _g(w1, RCON[0])
    w3 = w2 ^ w1
    w4 = w2 ^ _g(w3, RCON[1])
    w5 = w4 ^ w3
    return KeySchedule(key, (w2 << 8) | w3, (w4 << 8) | w5)


def key_expansion_rows(key: int) -> list[tuple[str, int, str]]:
    """返回密钥扩展的逐步明细 ``(名称, 字节值, 说明)``，供界面表格展示。"""
    _require_bits(key, KEY_BITS, "密钥")
    w0, w1 = (key >> 8) & 0xFF, key & 0xFF
    g1 = _g(w1, RCON[0])
    w2 = w0 ^ g1
    w3 = w2 ^ w1
    g3 = _g(w3, RCON[1])
    w4 = w2 ^ g3
    w5 = w4 ^ w3
    return [
        ("w0", w0, "主密钥高字节"),
        ("w1", w1, "主密钥低字节"),
        ("g(w1)", g1, "RotNib → SubNib → ⊕ RCON(1)=0x80"),
        ("w2", w2, "w2 = w0 ⊕ g(w1)"),
        ("w3", w3, "w3 = w2 ⊕ w1"),
        ("g(w3)", g3, "RotNib → SubNib → ⊕ RCON(2)=0x30"),
        ("w4", w4, "w4 = w2 ⊕ g(w3)"),
        ("w5", w5, "w5 = w4 ⊕ w3"),
    ]


# ---------------------------------------------------------------------------
# 加密 / 解密
# ---------------------------------------------------------------------------


def encrypt_state(plaintext: State, schedule: Sequence[State]) -> State:
    """对一个状态执行附录 D.1 的加密复合函数。"""
    state = add_round_key(plaintext, schedule[0])
    state = nibble_substitution(state)      # 第 1 轮 NS
    state = shift_rows(state)               # 第 1 轮 SR
    state = mix_columns(state)              # 第 1 轮 MC
    state = add_round_key(state, schedule[1])
    state = nibble_substitution(state)      # 第 2 轮 NS
    state = shift_rows(state)               # 第 2 轮 SR
    state = add_round_key(state, schedule[2])
    return state


def decrypt_state(ciphertext: State, schedule: Sequence[State]) -> State:
    """执行附录 D 的解密复合函数（加密的逆序）。"""
    state = add_round_key(ciphertext, schedule[2])
    state = inverse_shift_rows(state)
    state = inverse_nibble_substitution(state)
    state = add_round_key(state, schedule[1])
    state = inverse_mix_columns(state)
    state = inverse_shift_rows(state)
    state = inverse_nibble_substitution(state)
    state = add_round_key(state, schedule[0])
    return state


def make_schedule(key: int) -> tuple[State, State, State]:
    """返回以 2×2 状态表示的 3 个轮密钥。"""
    return expand_key(key).states()


def encrypt_with_schedule(block: int, schedule: Sequence[State]) -> int:
    """使用预扩展的轮密钥加密一个分组（供多重加密、MITM 复用）。"""
    return state_to_block(encrypt_state(state_from_block(block), schedule))


def decrypt_with_schedule(block: int, schedule: Sequence[State]) -> int:
    """使用预扩展的轮密钥解密一个分组。"""
    return state_to_block(decrypt_state(state_from_block(block), schedule))


def encrypt_block(plaintext: int, key: int) -> int:
    """加密一个 16 bit 分组。"""
    _require_bits(plaintext, BLOCK_BITS, "明文")
    return encrypt_with_schedule(plaintext, make_schedule(key))


def decrypt_block(ciphertext: int, key: int) -> int:
    """解密一个 16 bit 分组。"""
    _require_bits(ciphertext, BLOCK_BITS, "密文")
    return decrypt_with_schedule(ciphertext, make_schedule(key))


# ---------------------------------------------------------------------------
# 过程记录
# ---------------------------------------------------------------------------


def trace_operation_steps(data: int, key: int, *, decrypt: bool = False) -> list[OperationStep]:
    """返回加/解密每一步的完整状态矩阵（含输入），供界面逐步展示。"""
    _require_bits(data, BLOCK_BITS, "数据")
    schedule = make_schedule(key)
    state = state_from_block(data)
    steps: list[OperationStep] = [
        OperationStep(0, "输入", "16 bit 输入分组", state)
    ]

    if not decrypt:
        state = add_round_key(state, schedule[0])
        steps.append(OperationStep(0, "AK0", "密钥加 K0", state))
        state = nibble_substitution(state)
        steps.append(OperationStep(1, "NS", "第 1 轮 · 半字节代替", state))
        state = shift_rows(state)
        steps.append(OperationStep(1, "SR", "第 1 轮 · 行移位", state))
        state = mix_columns(state)
        steps.append(OperationStep(1, "MC", "第 1 轮 · 列混淆", state))
        state = add_round_key(state, schedule[1])
        steps.append(OperationStep(1, "AK1", "第 1 轮 · 密钥加 K1", state))
        state = nibble_substitution(state)
        steps.append(OperationStep(2, "NS", "第 2 轮 · 半字节代替", state))
        state = shift_rows(state)
        steps.append(OperationStep(2, "SR", "第 2 轮 · 行移位", state))
        state = add_round_key(state, schedule[2])
        steps.append(OperationStep(2, "AK2", "第 2 轮 · 密钥加 K2（输出）", state))
    else:
        state = add_round_key(state, schedule[2])
        steps.append(OperationStep(0, "AK2", "密钥加 K2", state))
        state = inverse_shift_rows(state)
        steps.append(OperationStep(2, "ISR", "第 2 轮 · 逆行移位", state))
        state = inverse_nibble_substitution(state)
        steps.append(OperationStep(2, "INS", "第 2 轮 · 逆半字节代替", state))
        state = add_round_key(state, schedule[1])
        steps.append(OperationStep(1, "AK1", "第 1 轮 · 密钥加 K1", state))
        state = inverse_mix_columns(state)
        steps.append(OperationStep(1, "IMC", "第 1 轮 · 逆列混淆", state))
        state = inverse_shift_rows(state)
        steps.append(OperationStep(1, "ISR", "第 1 轮 · 逆行移位", state))
        state = inverse_nibble_substitution(state)
        steps.append(OperationStep(1, "INS", "第 1 轮 · 逆半字节代替", state))
        state = add_round_key(state, schedule[0])
        steps.append(OperationStep(0, "AK0", "密钥加 K0（输出）", state))

    return steps


def trace_encryption(plaintext: int, key: int) -> list[tuple[str, int]]:
    """兼容旧接口：返回 ``(步骤说明, 16 bit 中间值)``。"""
    return [
        (f"{step.title}（{step.operation}）", step.block)
        for step in trace_operation_steps(plaintext, key)[1:]
    ]


def trace_decryption(ciphertext: int, key: int) -> list[tuple[str, int]]:
    """兼容旧接口：返回解密过程的 ``(步骤说明, 16 bit 中间值)``。"""
    return [
        (f"{step.title}（{step.operation}）", step.block)
        for step in trace_operation_steps(ciphertext, key, decrypt=True)[1:]
    ]


# ---------------------------------------------------------------------------
# 输入/输出格式
# ---------------------------------------------------------------------------

_SEPARATORS = re.compile(r"[\s_:,\-]+")
_HEX_DIGITS = set("0123456789abcdefABCDEF")


def parse_data(text: str, bits: int, name: str = "数值") -> int:
    """把用户输入解析成 ``bits`` 位整数。

    支持 ``0x`` 十六进制、``0b`` 二进制和裸字符串。裸字符串恰好
    ``bits`` 位且只含 0/1 时按二进制处理，否则按十六进制处理。
    """
    if not isinstance(text, str):
        raise SaesError(f"{name}必须是字符串")
    cleaned = _SEPARATORS.sub("", text.strip())
    if not cleaned:
        raise SaesError(f"{name}不能为空")

    lowered = cleaned.lower()
    try:
        if lowered.startswith("0x"):
            digits, base = cleaned[2:], 16
        elif lowered.startswith("0b"):
            digits, base = cleaned[2:], 2
        elif len(cleaned) == bits and set(cleaned) <= {"0", "1"}:
            digits, base = cleaned, 2
        else:
            digits, base = cleaned, 16

        allowed = _HEX_DIGITS if base == 16 else {"0", "1"}
        if not digits or not set(digits) <= allowed:
            kind = "十六进制" if base == 16 else "二进制"
            raise SaesError(f"{name}包含非法字符（按{kind}解析）：{text!r}")

        value = int(digits, base)
    except ValueError as exc:
        raise SaesError(f"{name}格式不正确：{text!r}") from exc

    if value >= (1 << bits):
        raise SaesError(f"{name}超出 {bits} bit 范围：0x{value:X}")
    return value


def format_bits(value: int, bits: int = BLOCK_BITS, group: int = 4) -> str:
    """格式化为二进制字符串，默认每 4 位空一格。"""
    raw = f"{value:0{bits}b}"
    if group <= 0:
        return raw
    return " ".join(raw[i : i + group] for i in range(0, len(raw), group))


def format_hex(value: int, bits: int = BLOCK_BITS) -> str:
    """格式化为固定宽度的大写十六进制字符串（无前缀）。"""
    return f"{value:0{bits // 4}X}"


def gf_mul(a: int, b: int) -> int:
    """GF(2^4) 乘法，模多项式 ``x^4 + x + 1``（附件 D.1）。"""
    _require_bits(a, 4, "乘数 a")
    _require_bits(b, 4, "乘数 b")
    table = {2: MUL2, 4: MUL4, 9: MUL9}
    if b in table:
        return table[b][a]
    if a in table:
        return table[a][b]
    product = 0
    while b:
        if b & 1:
            product ^= a
        a <<= 1
        if a & 0x10:
            a ^= 0x13
        b >>= 1
    return product & 0xF
