[English](sm4-fdex-adapter.md) | 中文

# 可选适配器：已证实的 SM4-ECB / fdex 前缀

**仅在当前 APK 的 Native 路径或独立输入输出向量已确认标准 SM4、ECB 逐块解密、加密范围和段边界时使用。** `fdex` 标记、梆梆壳家族、旧样本的成功记录，都不能单独证明这些条件。此适配器只生成解密前缀；方法对应和 DEX 回填仍由当前样本的布局证据决定。条件不成立时，回到[通用流程](extracted-dex.zh-CN.md)定位 Native 函数并用 Unidbg 或真机采集其输出。

## 当前样本的最小验证实验

1. **只建立候选，不作结论。** 从原容器取确切密文位置，并独立确定明文字节、候选密钥及其来源。`dex\n` magic 只有部分分组长度；解出前 8 字节只能筛候选，不能排除异或、流密码或其他变换。不能把“用候选 SM4 解出的字节”再当作独立已知明文。
2. **分清实现验证与算法验证。** 先用[公开 SM4 单分组向量](https://datatracker.ietf.org/doc/draft-ribose-cfrg-sm4/07/)检查本地实现；这只证明工具实现。再用当前样本中**独立得知的完整 16 字节明文块**与相应密文，对照 `SM4_encrypt(K, P_i) == C_i`。优先取不同位置的两块；或结合 Native 中可确认的 SM4 轮函数/密钥扩展与独立块对照。已知明文可来自可信的 Native 输出，或从容器结构独立推导出的完整块。只有 magic、没有独立完整块或 Native 算法证据时，仍标为“SM4 候选”。
3. **验证逐块模式和适用范围。** 若不同位置确有相同的独立已知明文块，检查其密文是否相同；这支持 ECB，但单独不足以排除重复密钥流等模型。结合多个位置的完整分组对照，以及 Native 中没有 IV、反馈或计数状态的证据，或与独立输出的完整前缀逐字节一致，才把该**已观察范围**判为 SM4-ECB。没有重复明文块并不否定 ECB。随后核验每段 DEX 头、`file_size`、段尾和方法映射；这些结构检查不能代替算法/模式证据。[NIST 的 ECB 定义](https://csrc.nist.gov/pubs/sp/800/38/a/final)是同一密钥下每个明文块独立映射到固定密文块。

这些检查可通过离线容器、已验证密钥及静态 Native 分析完成，**但容器只有 8 字节可确定明文时无法单靠 magic 证明算法或模式**。把每个完整分组的位置、明文来源、密文、密钥哈希、Native 证据及结论写入样本证据文件；证据不够时回到通用 Native 边界分析。

## 选择并验证密钥来源

| 来源 | 适用情况与验证 |
|---|---|
| Hook 密钥扩展函数入参 | 已定位 Native 函数且能抓到初始化时机；记录 16 字节输入的函数、时间和内存来源，并以 DEX 首块及完整前缀验证。 |
| [sm4_key_scan.py](../sm4_key_scan.py) 扫描完整捕获集 | 已知当前样本的加密 DEX 首块和至少 8 字节明文。默认递归扫描样本工作区的捕获目录，避免只选 SO 映射而漏掉堆中的密钥；需要 NumPy，并用完整 DEX 头及 `fdex` 尾标复核。无命中可能是只存轮密钥、动态派生密钥、漏抓映射，或算法/模式假设错误。 |
| 静态推导 | 能证明密钥来自常量、签名或确定性状态；记录输入和转换过程，再用独立前缀或真机向量验证。 |

### 捕获范围与扫描顺序

先记录密钥初始化前后的映射、可写页变化和 Native 调用。捕获清单至少检查模块 RX/RW/BSS、独立的 `[anon:.bss]`、实际使用的堆（含可能的 `[anon:scudo:*]`）、相关 stack/TLS；依据**本样本的读写与分配证据**决定哪些页需抓取，并记录地址、时间及哈希。不要把某个 `lib*.so` 或 scudo 当成固定密钥位置。

把全部捕获文件放在样本工作区的 `capture/`、`captures/`、`maps/`、`memory/`、`memregions/` 等专用目录；从样本工作区运行扫描器时会自动发现这些目录并递归扫描其中的二进制文件。其他目录名用 `--capture-dir` 指明**整个捕获根目录**。同名 `.bin.json` 采集清单与 `maps-<pid>.txt` 可补足虚拟基址和映射名，`maps` 文本支持 UTF-8/UTF-16 BOM，清单哈希不符即停止；脚本将标记为 scudo 的区域排在前面，仍扫描其余文件。没有地址元数据时报告文件偏移，虚拟地址留空。`--memory`/`--range` 只用于已定位问题后的有界诊断，不作为首次默认搜索。

默认 `--stride 1` 覆盖每个 16 字节候选起点，并用最多 4 个进程并行；可调 `--workers`。**实测参考**：单进程扫描 185 MiB 曾约需 90 分钟；并行加速受 CPU、内存带宽和文件系统影响，不能按进程数线性估计。可以先对完整捕获集用 `--stride 4` 快筛，但无命中时必须对**完整捕获集**再用 `--stride 1`，不能仅复查先前选中的 SO 区域。原始密钥若未留在任何已捕获映射中，改为观察密钥扩展入参或静态推导。

扫描器只把唯一命中的密钥写入新二进制文件，报告仅记录哈希和来源地址。**密钥文件放在 Git 忽略目录，不能把密钥十六进制放进命令行或提交到仓库。** 以下只是命令形状；所有偏移、对齐、长度和段数必须从当前 APK 推导：

```text
cd <样本工作区，内含完整 captures/ 目录>
python <Skill目录>/sm4_key_scan.py --stride 1 --workers 4 \
  --container original-classes.dex --cipher-offset <确认的第一段起点> \
  --known-plaintext-hex <当前DEX版本的前8字节> \
  --key-output <忽略目录>/key.bin --report key-scan.json

python decrypt_prefixes.py --container original-classes.dex --key-file <key.bin> \
  --encrypted-cap <Native验证的每段上限> --discover \
  --payload-offset <Native验证的payload偏移> --alignment <Native验证的段对齐> \
  --expected-segments <确认段数> --evidence-file <样本证据报告> \
  --output-dir offline-prefixes
```

已逐段确定起点时，用可重复的 `--segment-offset` 代替 `--discover`、`--payload-offset`、`--alignment`。解密器检查每段 DEX 头、`file_size` 和 `fdex` 尾标，短 DEX 按完整 16 字节块截断；输出 `prefix-N.bin` 和 manifest。manifest 的 `caller_claim` 仅记录调用方采用的模型，`evidence_file` 与 `evidence_sha256` 只追溯证据文件，**脚本不会替调用方审定其内容**；无证据文件时对应字段为 `null`。

`--truth-prefix` 可传设备前缀或完整设备 DEX，仅比较相同长度的前缀。若差异**全部**位于可解析 `class_data` 的 `code_off` ULEB 字段、字段起止位置与编码宽度相同，manifest 记为 `class_data_code_off_rewrite` 并继续保留离线明文；这提示设备可能已回填方法偏移，**不代表前缀逐字节一致**。任一差异不能归类就报错。设备真值从不进入解密或重建输入；以离线前缀运行 `$rev-dex-rebuild --prefix-source offline`，再用完整最终 DEX 与设备真值逐字节比较并做方法数对账。`--prefix-source device` 仅供 `--diagnostic-only` 冒烟，不可交付。
