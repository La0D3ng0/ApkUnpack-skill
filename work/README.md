# APK 分析工作区

分析任何 APK 都在 `work/` 下使用独立目录，避免不同样本的日志、dump、中间产物和结论混用。

```text
work/
├── README.md
├── <apk名>-<SHA256前12位>.apk_work/
└── <另一个apk名>-<SHA256前12位>.apk_work/
```

每个 `.apk_work` 只绑定一个 APK SHA-256。同名 APK 的哈希不同必须分目录。不要默认复制源 APK；需要确认样本身份时计算完整 SHA-256。

## 普通脱壳

普通壳识别、DEX dump、修复、重打包和签名只要求在对应 `.apk_work` 内工作。目录结构、文件名和记录方式由 Agent 根据任务决定，不要求创建检查点或固定子目录。

完成脱壳并交付时，在对应 `.apk_work` 内创建 `<源 APK 文件名去掉 .apk>-unpacked/`。交付目录顶层放 `classes.dex`、`classes2.dex` 等最终 DEX；校验清单、反编译源码及原壳对照可放子目录。临时 dump、进程快照和调试日志继续留在工作区其他位置。若只完成部分方法或仍有 Native 桥接，在交付目录中说明范围，不把可解析 DEX 等同于完整源代码。

## VMP 与长任务

VMP、长时间动态分析、多轮回放或数据库增量处理必须在对应 `.apk_work` 中创建 `checkpoint.md`。聊天记录不能代替检查点。

检查点至少记录以下三部分：

1. 一句话任务目标，初始化后不得漂移。
2. 最小单元清单，明确已完成、唯一正在处理和剩余项目。
3. 可独立验证的工作区状态，包括变更文件、数据库持久位置和中间产物。

推荐使用以下精简模板：

```markdown
# Checkpoint

Updated: YYYY-MM-DD HH:MM:SS +08:00
Status: active | blocked | complete

## Goal

<一句话目标；初始化后不得修改>

## Checklist

| ID | State | Minimal unit | Evidence |
|---|---|---|---|
| CP-001 | done | `<completed unit>` | `<relative path, hash, or validation>` |
| CP-002 | doing | `<current unit>` | `<last durable result or not_started>` |
| CP-003 | todo | `<remaining unit>` | `-` |

## Workspace State

### Source

| APK path | Size | SHA-256 | Package/version |
|---|---:|---|---|
| `<absolute path>` | `<bytes>` | `<64 hex>` | `<known value or unknown>` |

### Files And Artifacts

| Path | State/kind | Size | SHA-256 | Independent check |
|---|---|---:|---|---|
| `<relative path>` | `<new/modified/trace/dump/report/...>` | `<bytes>` | `<hash>` | `<diff, parser, or validation>` |

### Databases

| Path | Table/index | Durable position | Verification |
|---|---|---|---|
| `<relative path>` | `<table or index>` | `<last committed row/key/offset>` | `<query and result>` |

## Resume

- Current unit: `CP-002`
- Last verified fact: `<fact plus evidence path>`
- Next action: `<one exact, executable action>`
- Blocker: `<none or concrete blocker>`
```

状态只允许 `todo`、`doing`、`done`、`blocked`，并且最多只有一个 `doing`。

## 更新与续跑

1. 长命令开始前先把对应单元设为 `doing`，写明预期产物。
2. 命令结束后先验证文件、数据库提交位置和产物，再将单元设为 `done`。
3. 数据库只记录已提交的行、键或偏移；终端最后一行和进程缓存不算持久进度。
4. 续跑时先校验 APK SHA-256，再复核文件大小、哈希和数据库 durable position。
5. 磁盘与记录不一致时标记 `blocked` 并记录 drift，不从模型记忆补齐，也不静默覆盖。
