---
name: frida-hook-tool
description: Use the bundled rt-gum-sdk KernelPatch + Frida Gum runtime for authorized Android ARM64 native/ART hooks, JNI lifecycle observation, trace, and .ghm modules on its validated Pixel 8 profile. For dynamic hooking on that device, do not fall back to frida-server when this tool lacks prerequisites; report the missing prerequisite.
---

# frida-hook-tool

这里封装了从 `rt-gum-sdk` 当前工作树编译的 Android ARM64 工具链。`bin/` 包含 Stage 1 KPM/控制端、Stage 2 Daemon、Gum/Lua、Mako、功能模块和已签名 Manager APK；`manifest.json` 记录源码、构建环境、设备基线及每个文件的 SHA-256。用 `scripts/rtgum_bundle.py` 校验、推送和调用控制端。路径均相对于本文件解析。

## 何时使用

- 需要在已适配设备上运行内核辅助的 Native/ART Hook、JNI 生命周期观察、Gum/Lua、Shadow Page、内核 Trace 或 `.ghm` 模块时使用。
- 对这台 Android 设备做 Frida 动态 Hook/采集时，必须先使用本工具。**禁止以 frida-server 作为本工具不可用时的回退。** 若缺 SuperKey、会话、适配内核或模块文件，明确报告缺项和下一步需要的文件/路径，再继续其他不依赖该工具的分析。
- 这是一套运行时采集工具，不能仅凭一次 Hook 命中宣称完成 DEX、Java2C 或 VMP 还原。抽取型 DEX 继续按 `rev-gen2-extracted-dex-unpack` 验收；Native 桥接按 `rev-java2c` 判别。
- “无痕”只指已有测试中的特定暴露面；不要把它描述为对任意应用不可检测。

## 构建与设备边界

当前包使用 KernelPatch `0.13.9`、Frida Gum devkit `17.22.2`，针对 `shiba` / Android 16 / arm64-v8a / `6.1.145-android14-11-gfa1d6308d1fe-ab14691759` 构建。目标设备的内核或系统不同，应回到 `rt-gum-sdk` 重新适配、编译和验证；不要直接加载这里的 KPM。签名密钥和会话密钥不属于工具包；SuperKey 也必须由设备所有者单独保管。当前工作区的 `stage1-superkey-v3.txt` 是测试设备的本地私有文件，分发 Skill 时排除。完整来源见 [manifest.json](manifest.json)，重新构建见 [references/rebuild.md](references/rebuild.md)。

## 生成自己的 SuperKey

SuperKey 是修补 KernelPatch 引导镜像时设定的控制凭据，`rtgum_bundle.py` 不会生成或更换它。**使用已修补的设备时，必须取得该设备当前引导镜像对应的原密钥；仅新建一个密钥文件无法连接该设备。** 会话密钥由加载 KPM 后的 `pair` 另行生成。

给自己的新设备准备引导镜像时，在 Skill 目录之外生成一份随机密钥文件。下面的命令产生 48 个 ASCII 十六进制字符，符合此工具链要求的 32–63 个字母数字字符格式；`x` 模式会拒绝覆盖已有密钥：

```powershell
$keyFile = Join-Path $env:USERPROFILE 'rtgum-private\superkey.txt'
python -c 'import pathlib,secrets,sys; p=pathlib.Path(sys.argv[1]); p.parent.mkdir(parents=True,exist_ok=True); p.open("x",encoding="ascii").write(secrets.token_hex(24))' $keyFile
```

取得与设备当前固件完全匹配的原始 `boot.img`，用**同一份**密钥修补 KernelPatch 镜像，再从该镜像启动设备；之后把 `$keyFile` 传给下文的 `ctl`/`pair`。`rt-gum-sdk/tools/prepare-pixel8-boot-kali.py` 的 `--key-file` 可用于本 Skill 已验证的 Pixel 8 固件基线，并会校验输入镜像及补丁结果；它有固定的镜像哈希，不能拿来修补其他固件。其他设备须按对应 KernelPatch/设备流程重新适配镜像和 KPM。换密钥或遗失旧密钥时，需要用新密钥重新修补并启动引导镜像；修改文本文件或重新 `pair` 都不会更改内核中的 SuperKey。

## 调用

先从本 `SKILL.md` 定位 Skill 目录，再在 PowerShell 中运行：

```powershell
$tool = '<本 Skill 的绝对路径>'
$serial = '<adb 设备序列号>'
python -X utf8 "$tool/scripts/rtgum_bundle.py" verify
python -X utf8 "$tool/scripts/rtgum_bundle.py" --serial $serial device
python -X utf8 "$tool/scripts/rtgum_bundle.py" --serial $serial stage
```

`verify` 检查哈希、ARM64 ELF 类型和 Manager 内容；`device` 只读检查目标设备；`stage` 将运行组件推到控制端硬编码的 `/data/local/tmp/rtgum-stage1-pixel8/` 并逐个核对设备哈希，**不会加载 KPM**。若该目录已有不同版本，先停止活跃 Hook/卸载旧 KPM，再明确执行 `stage --replace`。不要在活跃会话中混用不同版本的 Daemon、Gum、Lua 或 Mako。

控制端在解析任何子命令前都要求 SuperKey，`ready` 和 `dmesg` 也无法免密调用。无密钥时仍可运行 `verify`、`device`，但必须明确报告缺 SuperKey，并向设备所有者索取路径。脚本也接受 `RTGUM_SUPERKEY_FILE` 环境变量指定路径；它不会把密钥值写入命令行。当前测试设备的本地密钥文件若存在，可用 `Join-Path $tool 'stage1-superkey-v3.txt'` 定位；其他用户使用自己生成且用于修补引导镜像的文件。

```powershell
$keyFile = '<本机私有的 SuperKey 文件路径>'
if (-not (Test-Path -LiteralPath $keyFile)) { throw '缺少 SuperKey 文件，请向设备所有者索取路径' }
python -X utf8 "$tool/scripts/rtgum_bundle.py" --serial $serial ctl --superkey-file $keyFile ready
python -X utf8 "$tool/scripts/rtgum_bundle.py" --serial $serial ctl --superkey-file $keyFile load /data/local/tmp/rtgum-stage1-pixel8/rtgum-stage1.kpm
python -X utf8 "$tool/scripts/rtgum_bundle.py" --serial $serial ctl --superkey-file $keyFile dmesg
```

首次加载后，从 `dmesg` 的 `debug-pair-code` 取得一次性六位码，将会话文件放在 Skill 目录之外：

```powershell
$sessionFile = '<私有工作目录>/rtgum-session.txt'
python -X utf8 "$tool/scripts/rtgum_bundle.py" --serial $serial pair --superkey-file $keyFile --code <六位码> --session-out $sessionFile
python -X utf8 "$tool/scripts/rtgum_bundle.py" --serial $serial ctl --superkey-file $keyFile --session-key-file $sessionFile capabilities
```

其余 `ctl` 子命令按 `rtgum-stage1-ctl` 的用法传入。配置目标包、加载模块和采集时要记录 APK/SO 哈希、目标 PID、模块哈希、命中证据与清理结果。结束时清除该会话的 trace/hook；确认 `capabilities` 显示 `active=0 busy=0 images=0` 后再 `unload`。

若保有 `rt-gum-sdk` 源码，可用其 `tools/smoke-stage1-pixel8.ps1` 并传 `-OutputDirectory "$tool/bin"` 执行已实现的设备验收；某些模式仍需源码仓库中的 Lab APK/测试夹具。Manager 位于 `bin/rtgum-manager-debug.apk`，安装升级前核对已有 Manager 的签名，避免覆盖失败后误删应用数据。
