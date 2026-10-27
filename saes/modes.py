"""第 5 关：S-AES 的密码分组链接（CBC）工作模式。

CBC 用前一个密文分组与当前明文分组异或后再加密::

    C_0 = E(P_0 ⊕ IV)
    C_i = E(P_i ⊕ C_{i-1})

解密时::

    P_i = D(C_i) ⊕ C_{i-1},  C_{-1} = IV

分组长度和初始向量都是 16 bit。本模块还提供密文篡改演示：
翻转某个密文分组中的一位后，该分组解密成随机噪声，而**下一个**
明文分组中对应的一位也会翻转——这正是 CBC 的差错传播特性。
"""

from __future__ import annotations

from .core import BLOCK_BITS, SaesError, decrypt_block, encrypt_block
from .text import BLOCK_SIZE, pad, split_blocks, unpad

__all__ = [
    "cbc_encrypt",
    "cbc_decrypt",
    "cbc_encrypt_details",
    "flip_bit",
    "xor_block",
]

_MASK = (1 << BLOCK_BITS) - 1


def _require_iv(iv: int) -> int:
    if not isinstance(iv, int):
        raise SaesError("初始向量必须是整数")
    if not 0 <= iv <= _MASK:
        raise SaesError("初始向量必须是 16 bit（0x0000 ~ 0xFFFF）")
    return iv


def xor_block(left: int, right: int) -> int:
    """两个 16 bit 分组按位异或。"""
    return (left ^ right) & _MASK


def cbc_encrypt(data: bytes, key: int, iv: int) -> bytes:
    """用 CBC 模式加密任意长度数据（自动补齐并添加 PKCS#7 填充）。"""
    _require_iv(iv)
    previous = iv
    output = bytearray()
    for block in split_blocks(pad(data)):
        previous = encrypt_block(xor_block(block, previous), key)
        output.append((previous >> 8) & 0xFF)
        output.append(previous & 0xFF)
    return bytes(output)


def cbc_decrypt(ciphertext: bytes, key: int, iv: int, *, unpad_data: bool = True) -> bytes:
    """用 CBC 模式解密。

    参数:
        ciphertext: 密文，长度必须是 2 字节的整数倍。
        key: 16 bit 密钥。
        iv: 16 bit 初始向量，必须与加密端一致。
        unpad_data: 为 ``False`` 时保留填充，用于篡改演示。

    异常:
        SaesError: 长度不合法或填充不合法。
    """
    _require_iv(iv)
    if len(ciphertext) % BLOCK_SIZE:
        raise SaesError("密文长度必须是 2 字节的整数倍")
    previous = iv
    output = bytearray()
    for block in split_blocks(ciphertext):
        plaintext = xor_block(decrypt_block(block, key), previous)
        previous = block
        output.append((plaintext >> 8) & 0xFF)
        output.append(plaintext & 0xFF)
    return unpad(bytes(output)) if unpad_data else bytes(output)


def cbc_encrypt_details(
    data: bytes, key: int, iv: int
) -> list[tuple[int, int, int, int]]:
    """返回 CBC 加密的逐分组明细，便于 GUI 展示。

    每行是 ``(分组序号, 明文分组, 送入加密器的值, 密文分组)``；
    分组序号从 1 开始，方便与界面上的表格对应。
    """
    _require_iv(iv)
    previous = iv
    rows: list[tuple[int, int, int, int]] = []
    for index, block in enumerate(split_blocks(pad(data)), start=1):
        mixed = xor_block(block, previous)
        previous = encrypt_block(mixed, key)
        rows.append((index, block, mixed, previous))
    return rows


def flip_bit(ciphertext: bytes, block_index: int, bit_index: int = 7) -> bytes:
    """翻转指定密文分组中的某一位，返回新的字节串。

    参数:
        ciphertext: 原密文，长度为 2 的整数倍。
        block_index: 分组下标，从 0 开始。
        bit_index: 分组内比特下标，0 表示最低位，15 表示最高位。

    异常:
        SaesError: 下标越界。
    """
    if len(ciphertext) % BLOCK_SIZE:
        raise SaesError("密文长度必须是 2 字节的整数倍")
    blocks = split_blocks(ciphertext)
    if not 0 <= block_index < len(blocks):
        raise SaesError(f"分组下标必须在 0 ~ {len(blocks) - 1} 之间")
    if not 0 <= bit_index < BLOCK_BITS:
        raise SaesError("比特下标必须在 0 ~ 15 之间")

    tampered = list(blocks)
    tampered[block_index] ^= 1 << bit_index
    return bytes(
        byte
        for block in tampered
        for byte in ((block >> 8) & 0xFF, block & 0xFF)
    )
