"""S-AES 五个关卡的单元测试。

运行::

    python -m unittest discover -s tests -t .
"""

from __future__ import annotations

import random
import unittest

from saes.core import (
    INV_SBOX,
    MUL4,
    SBOX,
    SaesError,
    add_round_key,
    decrypt_block,
    encrypt_block,
    expand_key,
    format_bits,
    format_hex,
    gf_mul,
    inverse_mix_columns,
    inverse_shift_rows,
    key_expansion_rows,
    mix_columns,
    nibble_substitution,
    parse_data,
    shift_rows,
    state_from_block,
    state_to_block,
    trace_decryption,
    trace_encryption,
    trace_operation_steps,
)
from saes.modes import cbc_decrypt, cbc_encrypt, flip_bit
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
    encrypt_bytes,
    encrypt_text,
    pad,
    split_blocks,
    to_display,
    to_hex,
    unpad,
)
from saes.vectors import (
    check_vectors,
    generate_vectors,
    parse_vectors,
    vectors_to_csv,
)


class SBoxTests(unittest.TestCase):
    def test_sbox_is_a_permutation(self):
        self.assertEqual(len(SBOX), 16)
        self.assertEqual(sorted(SBOX), list(range(16)))

    def test_inverse_sbox(self):
        for value in range(16):
            self.assertEqual(INV_SBOX[SBOX[value]], value)

    def test_known_values(self):
        # 教材附录 D 中反复用到的几个值
        self.assertEqual(SBOX[0x0], 0x9)
        self.assertEqual(SBOX[0x5], 0x1)
        self.assertEqual(SBOX[0xA], 0x0)
        self.assertEqual(SBOX[0xF], 0x7)


class GaloisFieldTests(unittest.TestCase):
    def test_multiplication(self):
        self.assertEqual(gf_mul(4, 4), 0x3)
        self.assertEqual(gf_mul(2, 9), 0x1)
        self.assertEqual(gf_mul(9, 4), 0x2)

    def test_commutative_and_identity(self):
        for left in range(16):
            self.assertEqual(gf_mul(left, 1), left)
            for right in range(16):
                self.assertEqual(gf_mul(left, right), gf_mul(right, left))

    def test_rejects_out_of_range(self):
        with self.assertRaises(SaesError):
            gf_mul(16, 1)


class KeyExpansionTests(unittest.TestCase):
    def test_standard_example(self):
        # K = 1010 0111 0011 1011
        schedule = expand_key(0xA73B)
        self.assertEqual(schedule.k0, 0xA73B)
        self.assertEqual(schedule.k1, 0x1C27)
        self.assertEqual(schedule.k2, 0x7651)

    def test_second_example(self):
        schedule = expand_key(0x4AF5)
        self.assertEqual(schedule.k1, 0xDD28)
        self.assertEqual(schedule.k2, 0x87AF)

    def test_rejects_wrong_size(self):
        for bad in (-1, 1 << 16):
            with self.assertRaises(SaesError):
                expand_key(bad)


class BlockCipherTests(unittest.TestCase):
    def test_published_vector_ok(self):
        # 明文 "ok"，经典 S-AES 示例
        self.assertEqual(encrypt_block(0x6F6B, 0xA73B), 0x0738)
        self.assertEqual(decrypt_block(0x0738, 0xA73B), 0x6F6B)

    def test_published_vector_second(self):
        self.assertEqual(encrypt_block(0x873B, 0x4AF5), 0xEC1A)
        self.assertEqual(decrypt_block(0xEC1A, 0x4AF5), 0x873B)

    def test_round_trip_random(self):
        rng = random.Random(20261019)
        for _ in range(2000):
            key = rng.getrandbits(16)
            plaintext = rng.getrandbits(16)
            self.assertEqual(decrypt_block(encrypt_block(plaintext, key), key), plaintext)

    def test_trace_matches_encryption(self):
        plaintext, key = 0x6F6B, 0xA73B
        trace = trace_encryption(plaintext, key)
        self.assertEqual(trace[-1][1], encrypt_block(plaintext, key))
        self.assertIn("密钥加 K0（AK0）", [label for label, _ in trace])
        decrypt_trace = trace_decryption(0x0738, key)
        self.assertEqual(decrypt_trace[-1][1], 0x6F6B)
        steps = trace_operation_steps(plaintext, key)
        self.assertEqual(steps[0].operation, "输入")
        self.assertEqual(steps[-1].operation, "AK2")
        self.assertEqual(steps[-1].block, encrypt_block(plaintext, key))

    def test_rejects_oversized_block(self):
        with self.assertRaises(SaesError):
            encrypt_block(0x10000, 0xA73B)


class AppendixDTests(unittest.TestCase):
    """附录 D 中逐一给出的算例，用于证明实现与教材一致。"""

    def test_state_layout_matches_figure_d2(self):
        # 图 D.2(a)：前 8 bit 填第一列，后 8 bit 填第二列
        self.assertEqual(state_from_block(0xABCD), ((0xA, 0xC), (0xB, 0xD)))
        self.assertEqual(state_to_block(state_from_block(0xABCD)), 0xABCD)

    def test_sbox_table_matches_table_d1(self):
        rows = (SBOX[0:4], SBOX[4:8], SBOX[8:12], SBOX[12:16])
        self.assertEqual(rows, ((0x9, 0x4, 0xA, 0xB),
                                (0xD, 0x1, 0x8, 0x5),
                                (0x6, 0x2, 0x0, 0x3),
                                (0xC, 0xE, 0xF, 0x7)))
        inverse_rows = (
            INV_SBOX[0:4], INV_SBOX[4:8], INV_SBOX[8:12], INV_SBOX[12:16]
        )
        self.assertEqual(inverse_rows, ((0xA, 0x5, 0x9, 0xB),
                                        (0x1, 0x7, 0x8, 0xF),
                                        (0x6, 0x0, 0x2, 0x3),
                                        (0xC, 0x4, 0xD, 0xE)))

    def test_key_expansion_example_d3(self):
        # 教材 D.3：K = 2D55 → w2=BC, w3=E9, w4=A3, w5=4A
        schedule = expand_key(0x2D55)
        self.assertEqual(schedule.words, (0x2D, 0x55, 0xBC, 0xE9, 0xA3, 0x4A))
        self.assertEqual(schedule.k1, 0xBCE9)
        self.assertEqual(schedule.k2, 0xA34A)

    def test_key_expansion_rows(self):
        rows = key_expansion_rows(0x2D55)
        values = {name: value for name, value, _ in rows}
        self.assertEqual(values["w2"], 0xBC)
        self.assertEqual(values["w4"], 0xA3)
        self.assertEqual(values["w5"], 0x4A)

    def test_add_round_key_example_d21(self):
        state = ((0xA, 0x4), (0x7, 0x9))
        key = ((0x2, 0x5), (0xD, 0x5))
        self.assertEqual(add_round_key(state, key), ((0x8, 0x1), (0xA, 0xC)))

    def test_nibble_substitution_example_d22(self):
        self.assertEqual(
            nibble_substitution(((0x8, 0x1), (0xA, 0xC))),
            ((0x6, 0x4), (0x0, 0xC)),
        )

    def test_shift_rows_example_d23(self):
        self.assertEqual(
            shift_rows(((0x6, 0x4), (0x0, 0xC))),
            ((0x6, 0x4), (0xC, 0x0)),
        )
        self.assertEqual(inverse_shift_rows(((6, 4), (0xC, 0))), ((6, 4), (0, 0xC)))

    def test_mix_columns_example_d24(self):
        self.assertEqual(
            mix_columns(((0x6, 0x4), (0xC, 0x0))),
            ((0x3, 0x4), (0x7, 0x3)),
        )
        self.assertEqual(
            inverse_mix_columns(((0x3, 0x4), (0x7, 0x3))),
            ((0x6, 0x4), (0xC, 0x0)),
        )

    def test_gf_multiplication_table_d2(self):
        self.assertEqual(
            MUL4, (0, 4, 8, 0xC, 3, 7, 0xB, 0xF, 6, 2, 0xE, 0xA, 5, 1, 0xD, 9)
        )
        self.assertEqual(gf_mul(4, 0xC), 5)  # 教材附件 D.1 的例子

    def test_encryption_composition_from_appendix(self):
        # AK2 ∘ SR ∘ NS ∘ AK1 ∘ MC ∘ SR ∘ NS ∘ AK0
        schedule = expand_key(0xA73B).states()
        state = state_from_block(0x6F6B)
        state = add_round_key(state, schedule[0])
        state = nibble_substitution(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, schedule[1])
        state = nibble_substitution(state)
        state = shift_rows(state)
        state = add_round_key(state, schedule[2])
        self.assertEqual(state_to_block(state), 0x0738)


class InputFormatTests(unittest.TestCase):
    def test_binary_and_hex(self):
        self.assertEqual(parse_data("1010011100111011", 16), 0xA73B)
        self.assertEqual(parse_data("0b1010 0111 0011 1011", 16), 0xA73B)
        self.assertEqual(parse_data("A73B", 16), 0xA73B)
        self.assertEqual(parse_data("0xA73B", 16), 0xA73B)
        self.assertEqual(parse_data("1010:0111:0011:1011", 16), 0xA73B)

    def test_32_bit(self):
        self.assertEqual(parse_data("1A2B3C4D", 32), 0x1A2B3C4D)
        self.assertEqual(parse_data("0001 1010 0010 1011", 16), 0x1A2B)

    def test_invalid(self):
        for text in ("", "XYZ", "0b102", "0xGG", "1 0000"):
            with self.assertRaises(SaesError):
                parse_data(text, 16)

    def test_out_of_range(self):
        with self.assertRaises(SaesError):
            parse_data("10000", 16)
        with self.assertRaises(SaesError):
            parse_data("12345", 16)

    def test_formatting(self):
        self.assertEqual(format_bits(0x0738), "0000 0111 0011 1000")
        self.assertEqual(format_hex(0x0738), "0738")


class TextModeTests(unittest.TestCase):
    def test_padding(self):
        self.assertEqual(pad(b"ok"), b"ok\x02\x02")
        self.assertEqual(pad(b"a"), b"a\x01")
        self.assertEqual(unpad(pad(b"Information")), b"Information")
        self.assertEqual(unpad(pad(b"")), b"")

    def test_bad_padding(self):
        with self.assertRaises(SaesError):
            unpad(b"\x00\x03")
        with self.assertRaises(SaesError):
            unpad(b"\x01")

    def test_ascii_round_trip(self):
        key = 0xA73B
        for text in ("ok", "Information Security", "", "A", "信息安全"):
            ciphertext = encrypt_text(text, key)
            self.assertEqual(len(ciphertext) % 2, 0)
            self.assertEqual(decrypt_text(ciphertext, key), text)

    def test_block_count(self):
        # "ok" 2 字节 + 2 字节填充 = 2 组
        self.assertEqual(len(encrypt_text("ok", 0xA73B)), 4)
        self.assertEqual(len(encrypt_text("abc", 0xA73B)), 4)

    def test_wrong_key_generally_fails(self):
        ciphertext = encrypt_text("Information Security", 0xA73B)
        failures = 0
        for key in range(0, 100):
            try:
                decrypt_text(ciphertext, key)
            except SaesError:
                failures += 1
        self.assertGreater(failures, 90)

    def test_raw_decrypt_keeps_padding(self):
        ciphertext = encrypt_text("ok", 0xA73B)
        raw = decrypt_bytes(ciphertext, 0xA73B, unpad_data=False)
        self.assertEqual(raw, b"ok\x02\x02")

    def test_display(self):
        self.assertEqual(to_display(b"ok"), "ok")
        self.assertEqual(to_display(b"\x00\xff"), "\\x00\\xFF")
        self.assertEqual(to_hex(b"ok"), "6F6B")
        self.assertEqual(split_blocks(b"\x6f\x6b"), [0x6F6B])


class MultipleEncryptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.key32 = 0x1A2B3C4D
        self.key48 = 0x1A2B3C4D5E6F

    def test_split_keys(self):
        self.assertEqual(split_key32(self.key32), (0x1A2B, 0x3C4D))
        self.assertEqual(split_key48(self.key48), (0x1A2B, 0x3C4D, 0x5E6F))

    def test_double_round_trip(self):
        rng = random.Random(7)
        for _ in range(200):
            plaintext = rng.getrandbits(16)
            ciphertext = double_encrypt(plaintext, self.key32)
            self.assertEqual(double_decrypt(ciphertext, self.key32), plaintext)

    def test_double_is_two_single_encryptions(self):
        key1, key2 = split_key32(self.key32)
        expected = encrypt_block(encrypt_block(0x1234, key1), key2)
        self.assertEqual(double_encrypt(0x1234, self.key32), expected)

    def test_triple_ede2_round_trip(self):
        key1, key2 = split_key32(self.key32)
        ciphertext = triple_encrypt_ede2(0xABCD, self.key32)
        expected = encrypt_block(
            decrypt_block(encrypt_block(0xABCD, key1), key2), key1
        )
        self.assertEqual(ciphertext, expected)
        self.assertEqual(triple_decrypt_ede2(ciphertext, self.key32), 0xABCD)

    def test_triple_ede3_round_trip(self):
        rng = random.Random(9)
        for _ in range(100):
            plaintext = rng.getrandbits(16)
            ciphertext = triple_encrypt_ede3(plaintext, self.key48)
            self.assertEqual(triple_decrypt_ede3(ciphertext, self.key48), plaintext)

    def test_meet_in_the_middle_recovers_key(self):
        key = 0x1A2B3C4D
        pairs = [(plaintext, double_encrypt(plaintext, key)) for plaintext in (0x1234, 0xABCD, 0x5555)]
        self.assertEqual(meet_in_the_middle(pairs), [key])

    def test_meet_in_the_middle_cancel(self):
        import threading

        event = threading.Event()
        event.set()
        with self.assertRaises(AttackCancelled):
            meet_in_the_middle([(0x1234, 0x5678)], cancel_event=event)

    def test_meet_in_the_middle_rejects_empty(self):
        with self.assertRaises(SaesError):
            meet_in_the_middle([])


class CbcTests(unittest.TestCase):
    def test_round_trip(self):
        key, iv = 0xA73B, 0x1234
        for text in ("Information Security", "ok", "信息安全"):
            ciphertext = cbc_encrypt(text.encode("utf-8"), key, iv)
            self.assertEqual(cbc_decrypt(ciphertext, key, iv), text.encode("utf-8"))

    def test_first_block_formula(self):
        key, iv = 0xA73B, 0x1234
        data = b"ok"
        ciphertext = cbc_encrypt(data, key, iv)
        padded = pad(data)
        first_plain, second_plain = split_blocks(padded)
        first_cipher = encrypt_block(first_plain ^ iv, key)
        second_cipher = encrypt_block(second_plain ^ first_cipher, key)
        self.assertEqual(split_blocks(ciphertext), [first_cipher, second_cipher])

    def test_iv_changes_ciphertext(self):
        data, key = b"Information Security", 0xA73B
        self.assertNotEqual(cbc_encrypt(data, key, 0), cbc_encrypt(data, key, 1))

    def test_invalid_iv(self):
        with self.assertRaises(SaesError):
            cbc_encrypt(b"ok", 0xA73B, 0x10000)

    def test_tamper_propagation(self):
        key, iv = 0xA73B, 0x1234
        data = b"Information Security"
        ciphertext = cbc_encrypt(data, key, iv)
        tampered = flip_bit(ciphertext, 0, 3)
        original = cbc_decrypt(ciphertext, key, iv, unpad_data=False)
        modified = cbc_decrypt(tampered, key, iv, unpad_data=False)

        self.assertNotEqual(original[0:2], modified[0:2])  # 被篡改分组变成噪声
        # 下一分组中只有 bit 3 所在的第 2 个字节发生 0x08 变化
        self.assertEqual(original[2], modified[2])
        self.assertEqual(original[3] ^ modified[3], 0x08)
        # 再往后的分组完全不受影响
        self.assertEqual(original[4:], modified[4:])

    def test_flip_bit_bounds(self):
        with self.assertRaises(SaesError):
            flip_bit(b"ok", 1, 0)
        with self.assertRaises(SaesError):
            flip_bit(b"ok", 0, 16)


class VectorTests(unittest.TestCase):
    def test_generate_is_deterministic(self):
        first = generate_vectors(10, seed=123)
        second = generate_vectors(10, seed=123)
        self.assertEqual(first, second)
        self.assertNotEqual(first, generate_vectors(10, seed=124))

    def test_csv_round_trip(self):
        vectors = generate_vectors(20, seed=42)
        text = vectors_to_csv(vectors)
        self.assertEqual(parse_vectors(text), vectors)
        results = check_vectors(vectors)
        self.assertTrue(all(result.passed for result in results))

    def test_chinese_header(self):
        text = "密钥,明文,密文\nA73B,6F6B,0738\n"
        vectors = parse_vectors(text)
        self.assertEqual(len(vectors), 1)
        self.assertTrue(check_vectors(vectors)[0].passed)

    def test_binary_fields(self):
        text = "1010011100111011 0110111101101011 0000011100111000"
        self.assertTrue(check_vectors(parse_vectors(text))[0].passed)

    def test_detect_mismatch(self):
        text = "A73B,6F6B,0000\n"
        result = check_vectors(parse_vectors(text))[0]
        self.assertFalse(result.passed)
        self.assertEqual(result.actual, 0x0738)

    def test_invalid_rows(self):
        for text in ("", "# only comments\n", "A73B,6F6B\n", "GGGG,0000,0000\n"):
            with self.assertRaises(SaesError):
                parse_vectors(text)


if __name__ == "__main__":
    unittest.main()
