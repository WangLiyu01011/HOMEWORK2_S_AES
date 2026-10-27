"""S-AES 算法实现包（严格对应教材附录 D 的运算体系）。

子模块划分::

* :mod:`saes.core`    —— AK/NS/SR/MC 及其逆运算、密钥扩展、加解密、输入解析；
* :mod:`saes.text`    —— 第 3 关，字符串（2 字节分组）加解密；
* :mod:`saes.multi`   —— 第 4 关，双重/三重加密与中间相遇攻击；
* :mod:`saes.modes`   —— 第 5 关，CBC 工作模式与篡改演示；
* :mod:`saes.vectors` —— 第 2 关，交叉测试向量的生成与校验。
"""

from .core import (
    BLOCK_BITS,
    KEY_BITS,
    OperationStep,
    KeySchedule,
    SaesError,
    State,
    add_round_key,
    decrypt_block,
    decrypt_state,
    encrypt_block,
    encrypt_state,
    expand_key,
    format_bits,
    format_hex,
    inverse_mix_columns,
    inverse_nibble_substitution,
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

__version__ = "2.0.0"

__all__ = [
    "BLOCK_BITS",
    "KEY_BITS",
    "KeySchedule",
    "OperationStep",
    "SaesError",
    "State",
    "add_round_key",
    "decrypt_block",
    "decrypt_state",
    "encrypt_block",
    "encrypt_state",
    "expand_key",
    "format_bits",
    "format_hex",
    "inverse_mix_columns",
    "inverse_nibble_substitution",
    "inverse_shift_rows",
    "key_expansion_rows",
    "mix_columns",
    "nibble_substitution",
    "parse_data",
    "shift_rows",
    "state_from_block",
    "state_to_block",
    "trace_decryption",
    "trace_encryption",
    "trace_operation_steps",
    "__version__",
]
