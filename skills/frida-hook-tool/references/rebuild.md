# 重新构建此工具包

在 `rt-gum-sdk` 源码目录使用隔离输出目录，按顺序执行其现有构建脚本：

```powershell
$out = '<rt-gum-sdk>/out/<新的构建目录>'
pwsh -NoProfile -File tools/build-stage1-kpm-windows.ps1 -OutputDirectory $out
pwsh -NoProfile -File tools/build-stage1-client.ps1 -OutputDirectory $out
pwsh -NoProfile -File tools/build-stage2-daemon.ps1 -OutputDirectory $out
pwsh -NoProfile -File tools/build-mako-ghost.ps1 -OutputDirectory $out
pwsh -NoProfile -File tools/build-stage1-payload.ps1 -OutputDirectory $out
pwsh -NoProfile -File tools/verify-stage1-artifacts.ps1 -OutputDirectory $out
pwsh -NoProfile -File tools/build-manager.ps1 -MakoPath "$out/libmako-ghost.so" -OutputDirectory "$out/manager"
```

Windows 需准备源码所要求的 NDK r29/r25c、Android SDK 35、JDK 和 Frida Gum devkit。Manager 构建脚本的 `-MakoPath` 确保 APK 内嵌的 Mako 来自本轮构建；指定同一签名密钥以保留升级能力。不要将密钥文件复制进 Skill。

只复制 `manifest.json` 当前列出的文件名到 `bin/`；排除 `stage1.o`、静态 `.a`、debug SO 和测试程序。重新计算全部哈希/长度，更新源码 commit、改动源码的哈希、设备基线和构建时间，然后运行 `scripts/rtgum_bundle.py verify`。目标系统/内核变化时，还要在该设备上重新完成 KPM 加载、功能命中和卸载验收，不能沿用这次 Pixel 8 的结论。

`librtgum-gum-ghost.so` 静态包含 Frida Gum 17.22.2。对外发布二进制前核对该第三方组件的许可及对应源码/重链接要求；本 Skill 不打包 Frida devkit 静态库。
