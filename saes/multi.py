"""第 4 关：S-AES 的多重加密与中间相遇攻击。

本模块提供三种组合方式：

* **双重加密**：``C = E_K2(E_K1(P))``，密钥 32 bit；
* **两密钥三重加密（EDE）**：``C = E_K1(D_K2(E_K1(P)))``，密钥 32 bit，
  与 ANSI X9.52 的两密钥 3DES 结构相同；
* **三密钥三重加密（EDE）**：``C = E_K3(D_K2(E_K1(P)))``，密钥 48 bit。

中间相遇攻击针对双重加密：先枚举 K1，把 ``E_K1(P)`` 存入哈希表；
再枚举 K2，计算 ``D_K2(C)`` 并查表。两次各 2^16 次运算即可恢复
32 bit 密钥，远少于直接枚举的 2^32 次。
"""

from __future__ import annotations

import threading
from typing import Callable, Iterable, Sequence

from .core import SaesError, decrypt_block, encrypt_block

__all__ = [
    "AttackCancelled",
    "split_key32",
    "split_key48",
    "double_encrypt",
    "double_decrypt",
    "triple_encrypt_ede2",
    "triple_decrypt_ede2",
    "triple_encrypt_ede3",
    "triple_decrypt_ede3",
    "meet_in_the_middle",
    "verify_key32",
    "ProgressCallback",
]

ProgressCallback = Callable[[int, int, str], None]

_KEY32_MAX = 1 << 32
_KEY48_MAX = 1 << 48


class AttackCancelled(Exception):
    """中间相遇攻击被用户取消。"""


def _require_int(value: int, bits: int, name: str) -> int:
    if not isinstance(value, int):
        raise SaesError(f"{name}必须是整数")
    if not 0 <= value < (1 << bits):
        raise SaesError(f"{name}必须是 {bits} bit，当前值为 {value}")
    return value


def split_key32(key: int) -> tuple[int, int]:
    """把 32 bit 密钥拆成 ``(K1, K2)``，各 16 bit。"""
    _require_int(key, 32, "32 bit 密钥")
    return (key >> 16) & 0xFFFF, key & 0xFFFF


def split_key48(key: int) -> tuple[int, int, int]:
    """把 48 bit 密钥拆成 ``(K1, K2, K3)``，各 16 bit。"""
    _require_int(key, 48, "48 bit 密钥")
    return (key >> 32) & 0xFFFF, (key >> 16) & 0xFFFF, key & 0xFFFF


def double_encrypt(plaintext: int, key: int) -> int:
    """双重加密：先用 K1 加密，再用 K2 加密。"""
    key1, key2 = split_key32(key)
    return encrypt_block(encrypt_block(plaintext, key1), key2)


def double_decrypt(ciphertext: int, key: int) -> int:
    """双重解密：先用 K2 解密，再用 K1 解密。"""
    key1, key2 = split_key32(key)
    return decrypt_block(decrypt_block(ciphertext, key2), key1)


def triple_encrypt_ede2(plaintext: int, key: int) -> int:
    """两密钥三重加密（EDE）：``E_K1(D_K2(E_K1(P)))``。"""
    key1, key2 = split_key32(key)
    return encrypt_block(decrypt_block(encrypt_block(plaintext, key1), key2), key1)


def triple_decrypt_ede2(ciphertext: int, key: int) -> int:
    """两密钥三重解密的逆过程：``D_K1(E_K2(D_K1(C)))``。"""
    key1, key2 = split_key32(key)
    return decrypt_block(encrypt_block(decrypt_block(ciphertext, key1), key2), key1)


def triple_encrypt_ede3(plaintext: int, key: int) -> int:
    """三密钥三重加密（EDE）：``E_K3(D_K2(E_K1(P)))``。"""
    key1, key2, key3 = split_key48(key)
    return encrypt_block(decrypt_block(encrypt_block(plaintext, key1), key2), key3)


def triple_decrypt_ede3(ciphertext: int, key: int) -> int:
    """三密钥三重解密的逆过程：``D_K1(E_K2(D_K3(C)))``。"""
    key1, key2, key3 = split_key48(key)
    return decrypt_block(encrypt_block(decrypt_block(ciphertext, key3), key2), key1)


def verify_key32(key: int, pairs: Sequence[tuple[int, int]]) -> bool:
    """检查 32 bit 候选密钥能否把每组明文都加密成对应密文。"""
    return all(double_encrypt(plaintext, key) == ciphertext for plaintext, ciphertext in pairs)


def meet_in_the_middle(
    pairs: Sequence[tuple[int, int]],
    progress: ProgressCallback | None = None,
    cancel_event: threading.Event | None = None,
) -> list[int]:
    """用中间相遇攻击恢复双重加密的 32 bit 密钥。

    参数:
        pairs: 至少一组 ``(明文, 密文)``。第一组用于建表，其余用于排除
            偶然碰撞（一组 16 bit 分组通常会产生若干候选）。
        progress: 可选回调 ``(已完成, 总数, 阶段名)``，用于更新进度条。
        cancel_event: 设置后尽快抛出 :class:`AttackCancelled`。

    返回:
        全部通过所有明密文对验证的 32 bit 密钥，按数值升序排列。
        理论上应恰好包含真实密钥。

    异常:
        SaesError: 明密文对为空或含非法数值。
        AttackCancelled: 调用方通过 ``cancel_event`` 取消。
    """
    if not pairs:
        raise SaesError("至少需要一组明密文对")

    checked: list[tuple[int, int]] = []
    for plaintext, ciphertext in pairs:
        _require_int(plaintext, 16, "明文")
        _require_int(ciphertext, 16, "密文")
        checked.append((plaintext, ciphertext))

    first_plaintext, first_ciphertext = checked[0]
    total = 2 * (1 << 16)

    # 正向：枚举 K1，建立 中间值 -> 候选 K1 列表 的哈希表
    forward: dict[int, list[int]] = {}
    for key1 in range(1 << 16):
        if cancel_event is not None and (key1 & 0x3FF) == 0 and cancel_event.is_set():
            raise AttackCancelled("中间相遇攻击已取消")
        if progress is not None and (key1 & 0xFF) == 0:
            progress(key1, total, "正向：枚举 K1 并建表")
        forward.setdefault(encrypt_block(first_plaintext, key1), []).append(key1)

    # 反向：枚举 K2，解密 C，与表中的中间值比对
    candidates: set[int] = set()
    for key2 in range(1 << 16):
        if cancel_event is not None and (key2 & 0x3FF) == 0 and cancel_event.is_set():
            raise AttackCancelled("中间相遇攻击已取消")
        if progress is not None and (key2 & 0xFF) == 0:
            progress((1 << 16) + key2, total, "反向：枚举 K2 并查表")

        for key1 in forward.get(decrypt_block(first_ciphertext, key2), ()):
            key32 = (key1 << 16) | key2
            if verify_key32(key32, checked):
                candidates.add(key32)

    if progress is not None:
        progress(total, total, "完成")
    return sorted(candidates)


def double_encrypt_details(plaintext: int, key: int) -> Iterable[tuple[str, int]]:
    """返回双重加密的中间结果，供界面展示。"""
    key1, key2 = split_key32(key)
    intermediate = encrypt_block(plaintext, key1)
    yield ("K1 加密结果", intermediate)
    yield ("K2 加密结果（最终密文）", encrypt_block(intermediate, key2))
