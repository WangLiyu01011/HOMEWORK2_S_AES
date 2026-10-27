"""第 2 关：交叉测试用的测试向量生成、导入导出与校验。

交叉测试的关键是双方使用**同一套算法标准**。本模块生成的向量采用
CSV 文本格式，便于复制到聊天窗口或保存成文件与同组同学交换::

    key,plaintext,ciphertext
    1A2B,3C4D,7E8F

字段可以用十六进制（``1A2B`` / ``0x1A2B``）或二进制
（``1010011100111011`` / ``0b1010...``）书写。
"""

from __future__ import annotations

import csv
import io
import random
from dataclasses import dataclass

from .core import SaesError, encrypt_block, parse_data

__all__ = [
    "TestVector",
    "VectorResult",
    "generate_vectors",
    "vectors_to_csv",
    "parse_vectors",
    "check_vectors",
]

EXPORT_HEADER = ("key", "plaintext", "ciphertext")


@dataclass(frozen=True)
class TestVector:
    """一组交叉测试向量（均为 16 bit 整数）。"""

    key: int
    plaintext: int
    ciphertext: int


@dataclass(frozen=True)
class VectorResult:
    """单条向量的校验结果。"""

    vector: TestVector
    actual: int
    passed: bool

    @property
    def expected(self) -> int:
        return self.vector.ciphertext


def generate_vectors(
    count: int,
    *,
    seed: int | None = None,
    key: int | None = None,
) -> list[TestVector]:
    """随机生成 ``count`` 组 ``(K, P, C)`` 向量。

    参数:
        count: 生成数量，必须在 1 ~ 1000 之间。
        seed: 随机数种子；相同种子 + 相同密钥可复现同一批向量，
            便于在报告中记录复现实验的参数。
        key: 固定密钥；省略时每组使用不同随机密钥。

    异常:
        SaesError: 数量越界或密钥不是 16 bit。
    """
    if not 1 <= count <= 1000:
        raise SaesError("向量数量必须在 1 ~ 1000 之间")
    if key is not None and not 0 <= key <= 0xFFFF:
        raise SaesError("密钥必须是 16 bit")

    rng = random.Random(seed)
    vectors = []
    for _ in range(count):
        current_key = key if key is not None else rng.getrandbits(16)
        plaintext = rng.getrandbits(16)
        vectors.append(TestVector(current_key, plaintext, encrypt_block(plaintext, current_key)))
    return vectors


def vectors_to_csv(vectors: list[TestVector]) -> str:
    """把向量列表序列化成 CSV，字段用 4 位大写十六进制。"""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(EXPORT_HEADER)
    for vector in vectors:
        writer.writerow(
            (f"{vector.key:04X}", f"{vector.plaintext:04X}", f"{vector.ciphertext:04X}")
        )
    return buffer.getvalue()


_HEX_CHARS = set("0123456789abcdefABCDEFxXbB")


def _looks_like_header(cells: list[str]) -> bool:
    """判断一行是否更像表头而不是数据。

    只检查字符是否都在「十六进制/二进制数字」范围内。这样 ``FEEC``
    这样的全字母十六进制数据不会被误判成表头，而 ``key``、``密钥``
    之类的文字会被识别出来。
    """
    return any(any(char not in _HEX_CHARS for char in cell) for cell in cells)


def parse_vectors(text: str) -> list[TestVector]:
    """解析 CSV / 制表符 / 空格分隔的测试向量。

    自动跳过表头、空行和以 ``#`` 开头的注释。每行必须有 3 个字段。
    支持中文表头（``密钥``、``明文``、``密文``），方便直接粘贴同学发来的表。

    异常:
        SaesError: 没有有效数据，或某行字段数量、数值不合法。
    """
    if not isinstance(text, str) or not text.strip():
        raise SaesError("测试向量不能为空")

    vectors: list[TestVector] = []
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # 同一行既支持逗号/制表符分隔，也支持纯空格分隔
        if "," in line or "\t" in line:
            cells = next(csv.reader([line]))
        else:
            cells = line.split()
        cells = [cell.strip() for cell in cells if cell.strip()]
        if len(cells) != 3:
            if not vectors and _looks_like_header(cells):
                continue
            raise SaesError(f"第 {line_number} 行应有 3 列（密钥, 明文, 密文），实际 {len(cells)} 列")

        try:
            key = parse_data(cells[0], 16, "密钥")
            plaintext = parse_data(cells[1], 16, "明文")
            ciphertext = parse_data(cells[2], 16, "密文")
        except SaesError as exc:
            # 允许首行是表头，例如 key,plaintext,ciphertext 或 密钥,明文,密文。
            # 注意不能用 isalpha() 判断：FEEC 这类全字母的十六进制值也是合法数据。
            if not vectors and _looks_like_header(cells):
                continue
            raise SaesError(f"第 {line_number} 行：{exc}") from exc
        vectors.append(TestVector(key, plaintext, ciphertext))

    if not vectors:
        raise SaesError("没有解析到任何有效向量")
    return vectors


def check_vectors(vectors: list[TestVector]) -> list[VectorResult]:
    """逐条重新计算密文并与给定值比对。"""
    if not vectors:
        raise SaesError("没有可校验的向量")
    results = []
    for vector in vectors:
        actual = encrypt_block(vector.plaintext, vector.key)
        results.append(VectorResult(vector, actual, actual == vector.ciphertext))
    return results
