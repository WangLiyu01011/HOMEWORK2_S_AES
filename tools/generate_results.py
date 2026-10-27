"""重新生成 ``results/`` 下的测试结果文件。

所有输出都是确定性的（随机部分使用固定种子），便于在报告中复现::

    python -m tools.generate_results
"""

from __future__ import annotations

import time
from pathlib import Path

from saes.core import decrypt_block, encrypt_block, expand_key, format_bits, format_hex
from saes.modes import cbc_decrypt, cbc_encrypt, flip_bit
from saes.multi import double_encrypt, meet_in_the_middle, split_key32
from saes.text import decrypt_text, encrypt_text, to_display, to_hex
from saes.vectors import generate_vectors, vectors_to_csv

RESULTS = Path(__file__).resolve().parent.parent / "results"


def write(name: str, content: str) -> None:
    path = RESULTS / name
    path.write_text(content, encoding="utf-8")
    print(f"已写入 {path}")


def known_vectors() -> None:
    cases = ((0xA73B, 0x6F6B, 0x0738), (0x4AF5, 0x873B, 0xEC1A))
    lines = ["来源,密钥K,明文P,密文C,解密校验"]
    for index, (key, plaintext, expected) in enumerate(cases, start=1):
        actual = encrypt_block(plaintext, key)
        recovered = decrypt_block(actual, key)
        assert actual == expected and recovered == plaintext
        lines.append(
            f"公开测试向量 {index},{format_hex(key)},{format_hex(plaintext)},"
            f"{format_hex(actual)},通过"
        )
    schedule = expand_key(0xA73B)
    lines.extend(
        [
            "",
            "密钥扩展（K = A73B）：",
            f"K0 = {format_bits(schedule.k0)}",
            f"K1 = {format_bits(schedule.k1)}",
            f"K2 = {format_bits(schedule.k2)}",
        ]
    )
    write("known_vectors.csv", "\n".join(lines) + "\n")


def cross_vectors() -> None:
    vectors = generate_vectors(30, seed=20261019)
    write("cross_vectors.csv", vectors_to_csv(vectors))


def mitm_demo() -> None:
    key = 0x1A2B3C4D
    plaintexts = (0x1234, 0xABCD, 0x5555)
    pairs = [(plaintext, double_encrypt(plaintext, key)) for plaintext in plaintexts]
    start = time.perf_counter()
    recovered = meet_in_the_middle(pairs)
    elapsed = time.perf_counter() - start
    key1, key2 = split_key32(key)
    lines = [
        "中间相遇攻击演示",
        f"真实密钥 K = {format_hex(key, 32)}  (K1 = {format_hex(key1)}, K2 = {format_hex(key2)})",
        "",
        "明密文对：",
    ]
    lines += [f"P = {format_hex(p)}, C = {format_hex(c)}" for p, c in pairs]
    lines += [
        "",
        f"耗时：{elapsed:.3f} 秒",
        f"候选密钥数量：{len(recovered)}",
    ]
    lines += [f"K = {format_hex(item, 32)}" for item in recovered]
    lines.append("恢复成功：" + ("是" if recovered == [key] else "否"))
    write("mitm_demo.txt", "\n".join(lines) + "\n")


def text_demo() -> None:
    key = 0xA73B
    plaintext = "Information Security"
    ciphertext = encrypt_text(plaintext, key)
    recovered = decrypt_text(ciphertext, key)
    lines = [
        "第 3 关 字符串加解密",
        f"密钥 K = {format_hex(key)}",
        f"明文 = {plaintext}",
        f"明文十六进制 = {to_hex(plaintext.encode('utf-8'))}",
        f"密文十六进制 = {to_hex(ciphertext)}",
        f"密文可读形式 = {to_display(ciphertext)}",
        f"解密结果 = {recovered}",
    ]
    write("text_demo.txt", "\n".join(lines) + "\n")


def cbc_demo() -> None:
    key, iv = 0xA73B, 0x1234
    plaintext = "Information Security"
    data = plaintext.encode("utf-8")
    ciphertext = cbc_encrypt(data, key, iv)
    recovered = cbc_decrypt(ciphertext, key, iv).decode("utf-8")

    tampered = flip_bit(ciphertext, 0, 3)
    original_raw = cbc_decrypt(ciphertext, key, iv, unpad_data=False)
    tampered_raw = cbc_decrypt(tampered, key, iv, unpad_data=False)
    differences = [
        f"字节 {index}: {left:02X} -> {right:02X}"
        for index, (left, right) in enumerate(zip(original_raw, tampered_raw))
        if left != right
    ]
    lines = [
        "第 5 关 CBC 模式",
        f"密钥 K = {format_hex(key)}，IV = {format_hex(iv)}",
        f"明文 = {plaintext}（{len(data)} 字节）",
        f"密文 = {to_hex(ciphertext)}",
        f"正常解密 = {recovered}",
        "",
        "篡改：翻转第 1 个密文分组的第 3 位",
        f"篡改后密文 = {to_hex(tampered)}",
        f"原始解密字节 = {to_hex(original_raw)}",
        f"篡改后解密字节 = {to_hex(tampered_raw)}",
        f"变化的字节数 = {len(differences)}",
    ] + differences
    write("cbc_demo.txt", "\n".join(lines) + "\n")


def main() -> None:
    RESULTS.mkdir(exist_ok=True)
    known_vectors()
    cross_vectors()
    mitm_demo()
    text_demo()
    cbc_demo()


if __name__ == "__main__":
    main()
