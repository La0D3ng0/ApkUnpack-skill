[English](extracted-dex.md) | 中文

# 二代动态抽取型 DEX：Native 重放与可视化验收

适用于壳在磁盘 DEX 中保留方法骨架，在加载或调用时恢复指令、CodeItem 或 `code_off` 的场景。先确定真实发生的内存变化，再决定是否需要伪造 `ArtMethod`；不能仅凭“抽取型壳”的名称预设恢复机制。

## 1. 确定输入、输出和抽取层次

1. 先运行 `rev-apk-shell-detect`，读取 `container_layout` 与 `routing`；仅凭静态 `fdex` 容器证据即可进入本 Skill。计算 APK 哈希；若使用真机输入/输出向量，再校验设备安装副本哈希并记录 ABI、Android 版本、进程、SO 映射和采集时间。两个 APK 哈希不同则不能混用向量。
2. 先解析磁盘 DEX 或 `fdex` 等容器；需要内存对照时，再按已确认的映射范围定向采集并逐页比较。采集必须保留头部 `file_size` 指示的完整长度，包括 `data_off + data_size` 之后的尾部。追踪 Native 密钥或指针时，检查模块 RX/RW/BSS、独立 `[anon:.bss]`、实际使用的堆（可能含 scudo）、相关 stack/TLS；只采本样本有证据的范围，并保留地址和哈希清单。不要把 panda 的整机 dump 当作本路线的默认入口。
3. 解析源 DEX 的类数据，对每个方法记录 `method_idx`、`code_off`、CodeItem 头和指令。稀疏占位指令与追加尾部真实 CodeItem 的匹配，比单纯寻找 `nop` 或短方法更可靠。独立记录全部边界、长度与哈希。
4. 另行统计 JNI 桥接调用。DEX 方法恢复后若仍只转发到 Native，必须将“恢复了桥接 CodeItem”和“恢复了桥接背后的业务语义”分别报告。

报告中的 `valid_data_end` 是 DEX 头部的 `data_off + data_size`，并非解析 `map_list` 时最后一个条目的末尾。`dexdata0` 后的 payload 偏移默认按已测 Bangcle 变体的 `+12` 给出**候选值**；可在 `container_triage.py --payload-after-marker` 修改，实际值仍以本样本 Native 解析器为准。内存切出的 DEX 若 `signature_ok` / `checksum_ok=false`，可能只是壳改了 `code_off` 却未重算头部；需继续做结构和独立字节对照，不能单凭该字段判切分失败。

## 2. 找到可独立执行的 Native 边界

- 以原始容器字节作输入，以真机内存映射作输出向量。结合字符串、尾标记、调用链和发生变化的页，确认函数 RVA、ABI、参数顺序、密钥来源、循环长度、读写内存区域。只模拟已观察到的契约。
- 如果磁盘 SO 的代码本身被加密，可以分析真机捕获的可执行映射。该映射是进程快照，**不自动等同可重定位 SO**。在 Unidbg 中按虚拟地址偏移放置 RX、RW、BSS 和表数据；仅重定位已有真机证据的 GOT/函数指针。节表被擦时，依赖节名的静态 GOT 定位不可用；若 `PT_DYNAMIC`/重定位仍在，可改从程序头解析，不能一概认定静态解析无路。运行时槽值也可能指向没有导出符号的 IFUNC 实现，优先追调用行为和指针来源，不以追出符号名为前提（[ELF ABI](https://refspecs.linuxfoundation.org/elf/gabi4+/ch5.dynamic.html)、[glibc IFUNC](https://sourceware.org/glibc/manual/2.44/html_node/Indirect-Functions.html)）。少量依赖可以用行为精确的小型 SVC 实现。
- 外层函数若严重依赖 ART 内部结构，优先继续定位已核实的内层算法函数。只有确认目标函数确实读取 `ArtMethod` 或 `CodeItem` 时，才依据目标 Android 构建伪造该结构，不能使用通用猜测偏移。
- 固定 Unidbg 提交、JDK 和后端；至少运行两个全新基线。比较**完整输出范围**。解析器返回容器位置，仅证明定位成功，不能代替解密验证。

将当前 APK 推导出的 RVA、映射范围、表指针、密钥来源、容器偏移、加密范围和 DEX 数量记录在样本配置及证据清单中，不把这些值复制到通用流程。Harness 按已验证的虚拟地址关系装载捕获映射、修复指针、调用 Native 函数并输出解密片段；入口、参数和片段长度均需在新样本中重新识别。先验证 Native 解析器给出的容器边界，再验证解密结果。独立真机 DEX 只用于比对，不能作为离线恢复的输入。

若当前样本已独立证实标准 SM4-ECB、加密范围和 `fdex` 段边界，可使用[可选 SM4/fdex 适配器](sm4-fdex-adapter.zh-CN.md)生成前缀。未证实时继续定位当前 Native 变换；适配器的失败也不改变抽取型壳的判断。

## 3. 回填、结构校验与交付

对于已经验证为同一 `fdex` 变体的样本，**先离线生成前缀，再回填交付**。[回填脚本](../../rev-dex-rebuild/rebuild_bangcle_fdex.py) 接收**未改动的源容器**、每个 DEX 的离线解密前缀、解析器返回的 payload 偏移，以及从当前样本确认的加密上限。设备前缀只用于 `--diagnostic-only` 冒烟或独立比对，不作为交付重建输入。短 DEX 的前缀按实际文件边界截断。脚本检查页面对齐、容器尾标和该变体的稀疏占位指令；完整解析尾部 CodeItem 和异常处理列表，要求唯一且连续的对应关系，再以原预留宽度重写 ULEB128 `code_off`。布局或映射有歧义就停止，不将这一特征推广到未知壳版本。

保留未修复头部的原始重建文件。另用 [头部修复脚本](../../rev-dex-rebuild/repair_dex_header.py) 复制并重算 SHA-1/Adler-32，然后运行 `verify_dex.py`；**必须使用 Baksmali 对全部最终 DEX 成功反汇编并保存日志与 Smali 结果**。检查每个类/方法、引用、CodeItem 尾界、异常范围和原始未修改区；若有真机参照，要求整个 DEX 逐字节一致。

交付目录统一放在独立分析工作区内，命名为 `<源 APK 文件名去掉 .apk>-unpacked/`。将可供工具直接打开的 `classes.dex`、`classes2.dex` 等放在目录顶层，**不产生 `classes1.dex`**；回填 manifest 的 `output_file` 和 `dex_file_naming` 给出精确对应关系。附上每个文件的哈希、原始真机对比和结构校验结果。此命名规则见仓库根目录 `README.md`。

## 4. 用 JADX/IDEA 直观验收

使用固定版本的 JADX 同时打开所有恢复后的 DEX，生成 Java 源码；保留原始壳 DEX 的单独反编译结果作基线。将 JADX 源码目录放入交付目录，并可在 IDEA 中作为普通源码浏览。90 MiB 级 DEX 集在 16 GiB 内存或页面文件受限的 Windows 主机上，可先给 JADX JVM `-Xmx3g` 并降低并发；G1 预留失败时先调堆/并发，不要判 DEX 损坏。记录原始/恢复后的 DEX 类定义数、JADX 输出文件数、报错和 `Method not decompiled` **方法**数；这些指标不能互相替代。

JADX 可读性验收以“有 CodeItem 的 DEX 方法数”为分母，统计 `Method not decompiled` 的方法比例；**目标核心业务包 0 个含失败方法的类、全局失败方法低于 1%**可作为反编译质量的通过线，超出则逐类排查。该线只评价 JADX 输出；即使低于 1%，核心方法若仍是 JNI 桥接、Smali 不完整或行为未验证，仍不能判业务恢复完成。JADX 失败的方法优先用 Baksmali 核实实际指令。

以用户关心的核心业务为优先验收对象：从入口顺着实际调用链检查账户、预约、网络请求、校验、持久化等路径，选择样本确实包含的模块；不能只挑容易读的工具类。对每条路径记录关键分支、输入、输出、字段或网络副作用，以及源码是否仍跳向 Native。至少抽查两类**可定位到方法索引和 `code_off` 的方法**：

- 恢复出可读 Java 逻辑的方法：展示原占位 `code_off`、新 CodeItem 偏移和 JADX 源码片段。
- 恢复后仍为 `JniLib` 等 JNI 桥接的方法：展示分发入口与参数/编号，并明确背后的 Native 语义尚未还原。

不要用“JADX 能列出类”推断所有方法都已还原，也不要把一次成功调用 Unidbg 当成原始 Dalvik 方法体已生成。Unidbg 可以执行 `.so`，适合记录 JNI 分发、返回值、字段写入、异常及副作用；若目标是等价 Java/DEX，还需对指定桥接方法解析分发编号、覆盖可行分支、重建控制流并与真机重复比较。一个 Native 运行结果通常不足以唯一确定完整方法语义。

Windows 采集时，PowerShell 5.1 的 `>` 可能写出 UTF-16/BOM，不能用于原始二进制流；不同 PowerShell 版本也不要依赖默认文本编码。优先用 `adb exec-out` 将字节流交给 Python 以二进制方式保存，再在 Python 中根据 BOM/UTF-8/目标编码解析文本。`su -c` 跨 PowerShell、ADB 和设备 shell 时引号可能被剥；先用无害命令验证实际参数，复杂命令可放到设备脚本执行，并记录原始调用。

## 5. 交接到 Java2C / Native 化方法

重建 DEX 通过结构校验及可获得的真机逐字节比对后，该范围的二代抽取还原即可结项。后续没有固定的壳类型：若用户关心的业务已恢复且无相关 Native 桥接，就在此结束。若仍有 JNI 桥接，把精确类名、方法原型、原始及恢复后的 `code_off`、桥接签名、分发编号、APK/SO 哈希与 smali/JADX 证据交给 `$rev-java2c`，逐方法判别是延迟回填 Dalvik、普通 Native/JNI 实现、私有字节码 VM，还是尚未确定。单凭 `JniLib` 调用不能断言存在 VMP；只有观察到连续的私有取指、解码与 handler 分派，才交给 `$rev-opcodes`。

样本的具体偏移、加密范围、恢复数量和业务验收结果放在各自工作区的实测报告中；不要把一个 APK 的参数或恢复比例当成下一个 APK 的前提。
