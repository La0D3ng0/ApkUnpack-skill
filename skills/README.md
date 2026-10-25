# Skill 工具索引与脱壳路由

先运行 `rev-apk-shell-detect`，读取报告中的 `shell.variant`、`shell.generation`、`container_layout` 和 `routing.next_skill`。**壳家族（例如 Bangcle）不是代际；不能仅凭家族名选择脱壳工具。**

| 当前证据 | 下一步 | 验证重点 |
|---|---|---|
| 主 DEX 的有效数据区之后存在大段 overlay，附近有 `dexdata0`，内部有候选 `fdex` 段尾且文件以 `fdex` 结束；或已证实方法体被抽取、运行时逐方法回填 | `rev-gen2-extracted-dex-unpack` | 先解析容器和占位方法，再确定需要哪些定向内存采集、Native 解密与 `rev-dex-rebuild`；无需先完成整机 DEX dump 才能进入此 Skill |
| 小型启动 DEX + 运行时加载器，尚无可辨识的抽取容器证据；尾部可有不透明高熵数据 | `rev-dex-dumper` 作为一代整 DEX 释放的首个采集尝试 | dump 后核对目标包类描述符、DEX 数量与核心业务方法；只有 framework/boot DEX 视为采集失败，并重新判别代际 |
| 只有 `known_shell` 家族命中、`variant=unknown`，或静态扫描不完整 | 继续分析 DEX/容器/加载路径 | 不把“没有检测到 `fdex`”直接当作一代壳，也不把 `known_shell` 直接当作二代壳 |
| DEX 中有稀疏占位 `CodeItem`，已获得可映射的真实方法体 | `rev-dex-rebuild` | 对账方法映射和全部 `code_off`，Baksmali 反汇编全部最终 DEX，核验核心业务链 |
| 还原后的方法仍调用 `JniLib.cV/cI/cL` 等桥接 | `rev-java2c` | 逐方法判别延迟 Dalvik 回填、普通 Native 实现或私有指令流；桥接本身不证明 VMP |
| 观察到私有字节码取指、解码及 handler 分派 | `rev-opcodes` | 只对有证据的 VM 范围开展去虚拟化 |

`rev-apk-shell-detect` 的 `first-generation-candidate` 和 `second-generation-candidate` 是路线判断，不是已经完成脱壳的结论。`fdex_trailer_count` 是静态候选段数；实际段数须与解密后的 DEX 长度及容器边界核对。运行时采集可以作为二代流程的定向证据来源，但不能以采集工具的输出代替抽取方法重建和业务验收。

二代流程先确定**当前样本**的还原边界和变换方式；算法未知时分析 Native 输入输出并按需用 Unidbg 重放。只有证实标准 SM4-ECB 且匹配所述容器结构，才进入[可选 SM4/fdex 适配器](rev-gen2-extracted-dex-unpack/references/sm4-fdex-adapter.zh-CN.md)。密钥、加密范围、段数和对齐均不是壳家族参数。该 `fdex` 变体先对完整捕获集寻找密钥、离线生成前缀再交付；设备前缀仅供诊断和独立比对。

已遇到壳的容器、密钥查找与解密思路集中在[抽取型壳加解密档案](rev-gen2-extracted-dex-unpack/shell-profiles/README.md)，按壳家族命名文档；先判当前 APK 的结构，再将档案当作待验证的线索。

最终结果放在样本工作区的 `<APK 文件名去掉 .apk>-unpacked/`，顶层提供还原后的 `classes*.dex`，并保留 Baksmali、JADX、方法映射、结构校验和核心业务链证据。
