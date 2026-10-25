---
name: rev-dex-dumper
description: Dump whole DEX files released into memory by an Android loader, especially a first-generation stub-loader shell, and verify that captured files contain target app classes. When fdex overlays or per-method extraction are identified, enter rev-gen2-extracted-dex-unpack first and use this Skill only for a specific acquisition or comparison requested by that workflow.
---

# rev-dex-dumper - Android DEX Dumper

Dump whole DEX files from a running Android application's memory using `panda-dex-dumper` via ADB.

## Route Check Before Dumping

Read the `rev-apk-shell-detect` report and examine the DEX layout. If `shell.variant=fdex-overlay` or method-by-method extraction is established, **do not start with panda as the unpacking route**. Enter `rev-gen2-extracted-dex-unpack`; use a bounded map capture only if its triage calls for runtime evidence. If the detector reports `stub-loader` with a first-generation candidate, a whole-DEX memory dump is a reasonable first step. If the variant is unknown, inspect the loader and DEX structure before choosing. A shell family name alone is insufficient.

---

## Tool Location

The `panda-dex-dumper` binary is bundled in this skill's directory. Resolve its absolute path relative to this SKILL.md file:

```
skills/rev-dex-dumper/panda-dex-dumper
```

For a second-generation workflow that needs one mapping as evidence, derive the PID, start/end addresses, and target descriptor from the current app, then use the available bounded acquisition tool (for example the authorized device's kernel collector or `adb exec-out` with Python binary output). Save the raw bytes plus base, length, acquisition time, and SHA-256 in a manifest. This Skill currently bundles panda, not a map-capture or carve script; do not invoke unbundled helper names. A candidate DEX without target classes is a failed target capture even if its header is valid.

---

## Workflow

### 1. Push the tool to device

```bash
adb push <path-to>/panda-dex-dumper /data/local/tmp/
adb shell chmod +x /data/local/tmp/panda-dex-dumper
```

### 2. Determine target package name

If the user provides a package name, use it directly. Otherwise, get the foreground app:

```bash
adb shell dumpsys activity top | grep 'ACTIVITY' | tail -1 | awk '{print $2}' | cut -d/ -f1
```

### 3. Run the dumper

```bash
adb shell "cd /data/local/tmp && ./panda-dex-dumper -p $(adb shell pidof <package_name>)"
```

The dumped DEX files are saved to `/data/local/tmp/panda/` on the device.

### 4. Pull DEX files to host and validate them

```bash
adb pull /data/local/tmp/panda/ ./
```

Pull into the sample's isolated workspace. Parse every candidate DEX, record its hash, class descriptors and method counts, and confirm that at least one contains the target package's own classes. If output contains only framework/boot DEX or no relevant business methods, **mark the dump unsuccessful** and return to the shell/layout diagnosis; do not present it as a completed unpack.

In an extracted-method shell, runtime `code_off` edits may leave stored SHA-1/Adler-32 stale; failed header checks alone do not invalidate a candidate carve. Validate DEX structure, provenance, target classes, and the intended runtime byte comparison separately.

### 5. Clean up device cache

```bash
adb shell rm -rf /data/local/tmp/panda/
adb shell rm /data/local/tmp/panda-dex-dumper
```

---

## Guidelines

1. **Always verify ADB connection first** — run `adb devices` and confirm a device is listed before proceeding.
2. **Root may be required** — `panda-dex-dumper` uses `ptrace` to attach to the target process. If the device is not rooted, the dump will fail. Suggest `adb root` or running via `su` if needed.
3. **Observe the loader state** — capture after the target DEX is actually loaded. A privacy or login screen does not by itself prove that loading has or has not occurred; inspect memory maps or loader events rather than assuming UI navigation is sufficient.
4. **Handle pidof failure** — if `pidof` returns empty, the app may not be running. Launch it first with `adb shell monkey -p <package_name> -c android.intent.category.LAUNCHER 1`.
5. **Multiple DEX files are normal** — packed apps often produce several DEX files. All files in `/data/local/tmp/panda/` should be pulled.
6. **Retain evidence before cleanup** — hash and copy the output into the sample workspace before removing temporary device files.
