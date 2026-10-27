"""第 3 关：把 S-AES 从 16 bit 分组扩展到字符串。

S-AES 的分组固定为 16 bit（2 字节），因此字符串按 **2 字节一组**切分后
逐组加密。最后不足 2 字节时用 PKCS#7 填充：缺少 1 字节就补 ``01``，
缺少 2 字节（即长度为偶数）就补 ``02 02``，解密后自动去除。

字符串默认按 UTF-8 编码成字节。纯 ASCII 文本与作业要求完全一致；
UTF-8 只是额外的便利，不会影响 ASCII 的结果。
"""

from __future__ import annotations

import string

from .core import BLOCK_BITS, SaesError, decrypt_block, encrypt_block

__all__ = [
    "BLOCK_SIZE",
    "MODULUS",
    "pad",
    "unpad",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_text",
    "decrypt_text",
    "to_display",
    "to_hex",
    "split_blocks",
    "join_blocks",
]

BLOCK_SIZE = BLOCK_BITS // 8  # 2 字节
MODULUS = 1 << BLOCK_SIZE  # 256，用于 PKCS#7 填充长度

_PRINTABLE = set(bytes(string.printable, "ascii")) - {ord("\n"), ord("\r"), ord("\t")}


def pad(data: bytes) -> bytes:
    """按 PKCS#7 把字节串补齐到 2 字节的整数倍。

    即使长度已经是 2 的倍数也会补满一整组 ``02 02``，
    这样解密端总能可靠地判定并去除填充。
    """
    if not isinstance(data, (bytes, bytearray)):
        raise SaesError("待填充的数据必须是 bytes")
    missing = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return bytes(data) + bytes([missing]) * missing


def unpad(data: bytes) -> bytes:
    """校验并去除 :func:`pad` 添加的 PKCS#7 填充。"""
    if not isinstance(data, (bytes, bytearray)):
        raise SaesError("待去填充的数据必须是 bytes")
    if not data or len(data) % BLOCK_SIZE != 0:
        raise SaesError(f"密文长度必须是 {BLOCK_SIZE} 字节的整数倍")

    padding_length = data[-1]
    if not 1 <= padding_length <= BLOCK_SIZE:
        raise SaesError("填充不合法：密文可能被篡改或用错了密钥")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise SaesError("填充不合法：密文可能被篡改或用错了密钥")
    return bytes(data[:-padding_length])


def split_blocks(data: bytes) -> list[int]:
    """把字节串按 2 字节大端切成 16 bit 分组列表。"""
    if len(data) % BLOCK_SIZE:
        raise SaesError(f"数据长度必须是 {BLOCK_SIZE} 字节的整数倍")
    return [(data[i] << 8) | data[i + 1] for i in range(0, len(data), BLOCK_SIZE)]


def join_blocks(blocks: list[int]) -> bytes:
    """把 16 bit 分组列表按大端拼回字节串。"""
    result = bytearray()
    for block in blocks:
        result.append((block >> 8) & 0xFF)
        result.append(block & 0xFF)
    return bytes(result)


def encrypt_bytes(data: bytes, key: int) -> bytes:
    """加密任意长度的字节串，返回等长的密文字节串（含填充）。"""
    return join_blocks([encrypt_block(block, key) for block in split_blocks(pad(data))])


def decrypt_bytes(ciphertext: bytes, key: int, *, unpad_data: bool = True) -> bytes:
    """解密字节串。

    参数:
        ciphertext: 密文字节串，长度必须是 2 的整数倍。
        key: 16 bit 密钥。
        unpad_data: 为 ``False`` 时保留 PKCS#7 填充，
            用于 CBC 篡改演示中展示"解密失败"的原始结果。

    异常:
        SaesError: 长度不合法、填充不合法。
    """
    blocks = [decrypt_block(block, key) for block in split_blocks(ciphertext)]
    plaintext = join_blocks(blocks)
    return unpad(plaintext) if unpad_data else plaintext


def encrypt_text(text: str, key: int, encoding: str = "utf-8") -> bytes:
    """把字符串编码为字节后加密。"""
    return encrypt_bytes(text.encode(encoding), key)


def decrypt_text(ciphertext: bytes, key: int, encoding: str = "utf-8") -> str:
    """解密字节串并按 ``encoding`` 解码。

    解密结果通常只在密钥正确、密文完整时才是合法文本；
    否则会抛出 :class:`SaesError`，由调用方决定如何展示。
    """
    plaintext = decrypt_bytes(ciphertext, key)
    try:
        return plaintext.decode(encoding)
    except UnicodeDecodeError as exc:
        raise SaesError(
            f"解密成功，但结果不是合法的 {encoding} 文本（密钥错误或密文被篡改）"
        ) from exc


def to_hex(data: bytes, group: int = 2) -> str:
    """字节串转大写十六进制；默认每 2 字节（一个分组）空一格。"""
    raw = data.hex().upper()
    if group <= 0:
        return raw
    step = group * 2
    return " ".join(raw[i : i + step] for i in range(0, len(raw), step))


def to_display(data: bytes, encoding: str = "utf-8") -> str:
    """把字节串转换成可读文本。

    可打印字符原样显示，其余显示为 ``\\xNN``，以 ``\\` 开头避免歧义。
    这样密文即使"是乱码"也不会破坏界面或终端。
    """
    try:
        text = data.decode(encoding)
    except UnicodeDecodeError:
        text = None

    # 能完整解码且全部可打印时直接展示（包括中文）；否则退回逐字节转义
    if text is not None and all(ch.isprintable() for ch in text):
        return text

    parts = []
    for byte in data:
        if byte in _PRINTABLE:
            char = chr(byte)
            parts.append("\\\\" if char == "\\" else char)
        else:
            parts.append(f"\\x{byte:02X}")
    return "".join(parts)
