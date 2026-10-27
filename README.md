# S-AES 简化 AES 算法实现

> 「信息安全导论」作业 2 —— 三人一组，用 **Python 3 + Tkinter** 实现 S-AES
> 加解密程序，完成作业文档要求的五个关卡。

S-AES 分组长度 **16 bit**，密钥长度 **16 bit**，共 **2 轮**，
状态矩阵为 2×2 个半字节。程序使用纯标准库实现，无第三方运行时依赖。

---

## 快速开始

```bash
python -m gui.app                             # 启动图形界面（五个标签页对应五个关卡）
python -m unittest discover -s tests -t .     # 运行全部单元测试（56 项）
python -m tools.generate_results              # 重新生成 results/ 下的测试结果
```

环境要求：Python 3.10 或更高版本（使用了 `X | None` 类型写法）。
截图脚本额外需要 Pillow：`python -m pip install pillow`。

---

## 按附录 D 的重构说明

本版（v2.0）按教材附录 D 重新组织了核心实现，而不是只保留一个黑盒加解密接口：

* 状态从扁平半字节元组改为教材的 **2×2 矩阵**，直接使用 `s00 ~ s11` 下标；
* `AK / NS / SR / MC / INS / ISR / IMC` 全部拆成独立函数，加密和解密按
  D.1 的复合函数顺序书写，便于逐行对照教材；
* 新增附录 D 的全部算例测试：D.2.1 ~ D.2.4 的变换示例、D.3 的
  `K = 2D55` 密钥扩展，以及表 D.1、表 D.2 的查表结果；
* 第 1 关新增 2×2 状态矩阵画布、`w0 ~ w5` 密钥扩展表和附录 D 结构对照，
  点击任意运算步骤即可查看该步状态；
* 第 2 ~ 5 关的功能和对外接口保持不变。

当前共 **56 项单元测试**，全部通过。

## 五个关卡的完成情况

| 关卡 | 要求 | 实现位置 | 结果截图 |
|---|---|---|---|
| 第 1 关 | 16 bit 数据 + 16 bit 密钥，GUI 加解密 | 界面「第 1 关」；核心 `saes/core.py` | [01a](results/screenshots/01a_basic.png) · [01b](results/screenshots/01b_basic_detail.png) · [01c](results/screenshots/01c_basic_key.png) · [01d](results/screenshots/01d_basic_structure.png) |
| 第 2 关 | 交叉测试，与同组程序结果一致 | 界面「第 2 关」；`saes/vectors.py` | [02a](results/screenshots/02a_cross_generate.png) · [02b](results/screenshots/02b_cross_check.png) · [02c](results/screenshots/02c_cross_standard.png) |
| 第 3 关 | ASCII 字符串按 2 字节分组加解密 | 界面「第 3 关」；`saes/text.py` | [03a](results/screenshots/03a_text.png) · [03b](results/screenshots/03b_text_result.png) |
| 第 4 关 | 双重/三重加密 + 中间相遇攻击 | 界面「第 4 关」；`saes/multi.py` | [04a](results/screenshots/04a_multi_top.png) · [04b](results/screenshots/04b_multi_mitm.png) |
| 第 5 关 | CBC 模式 + 密文篡改对比 | 界面「第 5 关」；`saes/modes.py` | [05a](results/screenshots/05a_cbc_top.png) · [05b](results/screenshots/05b_cbc_tamper.png) |

所有关卡的输入都在界面上完成，不依赖命令行参数；耗时操作（中间相遇攻击）
放在后台线程，界面不会卡死。

---

## 算法标准

状态按列优先填充：明文半字节 `n0 n1 n2 n3` 对应

```
[ n0  n2 ]
[ n1  n3 ]
```

| 装置 | 取值 |
|---|---|
| S 盒 | `9 4 A B / D 1 8 5 / 6 2 0 3 / C E F 7` |
| 逆 S 盒 | `A 5 9 B / 1 7 8 F / 6 0 2 3 / C 4 D E` |
| 列混淆矩阵 | `[[1, 4], [4, 1]]`，逆矩阵 `[[9, 2], [2, 9]]` |
| GF(2⁴) 模多项式 | `x⁴ + x + 1`（0b10011） |
| 轮常量 RCON | `0x80`（第 1 轮）、`0x30`（第 2 轮） |
| 密钥扩展 | `w2 = w0 ⊕ RCON(1) ⊕ SubNib(RotNib(w1))`，`w3 = w2 ⊕ w1`；`w4`、`w5` 同理 |

按附录 D.1 的复合函数记号（从右向左执行）：

```
加密 = AK2 ∘ SR ∘ NS ∘ AK1 ∘ MC ∘ SR ∘ NS ∘ AK0
解密 = AK0 ∘ INS ∘ ISR ∘ IMC ∘ AK1 ∘ INS ∘ ISR ∘ AK2
```

**教材示例（附录 D.3）**：`K = 2D55` 时，
`w2=BC, w3=E9, w4=A3, w5=4A`，即 `K1=BCE9`、`K2=A34A`。
该组数据与 D.2 中 `AK/NS/SR/MC/IMC` 的每一步算例都已写入单元测试。

**公开测试向量（已通过）**

| 密钥 K | 明文 P | 密文 C | 来源 |
|---|---|---|---|
| `1010 0111 0011 1011` | `0110 1111 0110 1011` | `0000 0111 0011 1000` | Rose–Holman, *A Simplified AES Algorithm* |
| `0100 1010 1111 0101` | `1000 0111 0011 1011` | `1110 1100 0001 1010` | Towson MATH 314 课堂讲义 |

第一条向量在界面第 1 关点击「填入标准示例」即可复现；密钥扩展的
`K1 = 0001 1100 0010 0111`、`K2 = 0111 0110 0101 0001` 也在运算步骤表和密钥扩展表中展示。

---

## 各关卡的设计要点

### 第 1 关：基本测试

输入支持二进制（可带空格，恰好 16 位时自动识别）和十六进制
（`1A2B` 或 `0x1A2B`）。加密后自动反解一次，直接显示往返校验结果。

中间过程严格按附录 D 的运算序列展示：

* 运算步骤表列出 `输入 → AK0 → NS → SR → MC → AK1 → NS → SR → AK2`
  （解密为 `AK2 → ISR → INS → AK1 → IMC → ISR → INS → AK0`）；
* 选中任一步骤，右侧按图 D.2(a) 的列优先布局画出 2×2 状态矩阵；
* 密钥扩展表逐行列出 `w0 ~ w5`、`g(w1)`、`g(w3)` 以及 `K0/K1/K2` 的
  二进制、十六进制和计算公式；
* 界面底部附有附录 D.1 ~ D.3 的结构对照，便于答辩时直接讲解。

### 第 2 关：交叉测试

支持一键生成随机 `(K, P, C)` 向量并导出 CSV，也支持粘贴/导入同学的
向量逐条校验。界面内附「算法标准」卡片，把 S 盒、逆 S 盒、矩阵、RCON、
状态布局和标准向量全部摊开，方便双方逐项核对。

已与 A 组的《算法标准》和 16 组加密 + 16 组解密向量完成实际交叉测试：
算法标准逐项一致，**加密 16/16、解密 16/16 全部通过**。A 组向量已转换为
[groupA_cross_vectors.csv](results/groupA_cross_vectors.csv)，可直接在
第 2 关导入；逐行结果见
[groupA_cross_test_report.txt](results/groupA_cross_test_report.txt)。

> 交叉测试失败时，最常见的原因是 S 盒或列混淆矩阵取值不同，
> 其次是状态矩阵的行列填充顺序、密钥扩展的 `w` 顺序。

### 第 3 关：扩展功能

字符串按 UTF-8 编码后以 2 字节为一组加密，不足一组时用 PKCS#7 填充
（缺 1 字节补 `01`，缺 2 字节补 `02 02`），解密后自动去除。
纯 ASCII 文本的行为与作业要求完全一致。密文同时以十六进制和可读转义
形式展示；分组明细表列出每组明文字节与密文字节。

### 第 4 关：多重加密

| 模式 | 公式 | 密钥 |
|---|---|---|
| 双重加密 | `C = E_K2(E_K1(P))` | 32 bit（K1 ‖ K2） |
| 两密钥三重加密 | `C = E_K1(D_K2(E_K1(P)))` | 32 bit（K1 ‖ K2） |
| 三密钥三重加密 | `C = E_K3(D_K2(E_K1(P)))` | 48 bit（K1 ‖ K2 ‖ K3） |

**中间相遇攻击**：先枚举 65536 个 K1，建立 `E_K1(P) → K1` 哈希表；
再枚举 65536 个 K2，计算 `D_K2(C)` 查表。总运算量约 `2×2^16`，
实测 1~2 秒恢复 32 bit 密钥。界面可一键生成 3 组演示向量并显示
真实密钥与恢复结果的比对。

### 第 5 关：CBC 模式

`C_i = E(P_i ⊕ C_{i-1})`，IV 为 16 bit。界面提供加密、解密、随机 IV 生成
和逐分组明细（明文分组、异或结果、密文分组）。篡改演示可翻转任意密文分组的
任意一位，并排显示篡改前后的解密字节，自动列出发生变化的字节并解释
差错传播规律：被篡改分组变为随机噪声，下一分组对应位翻转，更后面的
分组不受影响。

---

## 目录结构

```
作业二/
├── gui/
│   ├── app.py            # 五个标签页的 Tkinter 界面
│   └── theme.py          # 颜色、字体、间距与 ttk 样式
├── saes/
│   ├── core.py           # S 盒、密钥扩展、加解密、输入解析
│   ├── text.py           # 第 3 关：按 2 字节分组 + PKCS#7
│   ├── vectors.py        # 第 2 关：测试向量生成/导入/校验
│   ├── multi.py          # 第 4 关：双重/三重加密、中间相遇攻击
│   ├── modes.py          # 第 5 关：CBC 模式与篡改
│   └── __init__.py
├── tests/
│   └── test_saes.py      # 56 项单元测试
├── tools/
│   ├── generate_results.py   # 生成 results/ 下的结果文件
│   └── make_screenshots.py   # 自动截取五个关卡界面
├── results/
│   ├── known_vectors.csv
│   ├── cross_vectors.csv
│   ├── groupA_cross_vectors.csv
│   ├── groupA_cross_test_report.txt
│   ├── mitm_demo.txt
│   ├── text_demo.txt
│   ├── cbc_demo.txt
│   ├── test_output.txt
│   └── screenshots/
├── docs/
│   ├── 用户指南.md
│   ├── 开发手册.md
│   └── S-AES_五关测试报告.docx
└── README.md
```

---

## 文档

* [用户指南](docs/用户指南.md)：安装、启动、每个界面的操作步骤与常见问题；
* [开发手册](docs/开发手册.md)：模块划分、算法约定、公开接口与扩展方式；
* [测试结果](docs/测试结果.md)：56 项单元测试、五关的实测数据与截图索引；
* [五关测试报告（Word）](results/S-AES_五关测试报告.docx)：含本组截图、
  对方截图预留区和提供给对方的测试向量（同目录另有 PDF 预览版）。

---

## 提交要求对照

* 源代码：本目录全部 `.py` 文件；
* 测试结果：`results/` 与 [测试结果](docs/测试结果.md)；
* 相关文档：`docs/用户指南.md`、`docs/开发手册.md`。

作业要求在石墨文档表格中提交 GitHub / Gitee 链接。把本目录作为仓库根目录
推送到远端后，将链接填入《信息安全导论-作业2提交》即可。
