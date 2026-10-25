---
name: rev-signer
description: Zipalign, sign, and verify authorized rebuilt Android APKs with pinned Android Build Tools and an explicitly selected keystore. Use when Codex must prepare a repacked unsigned APK for installation, preserve 16 KiB native-library page alignment, apply APK Signature Scheme-compatible signatures, inspect signer certificates, compare signing identity with deployment requirements, handle an evidenced native signing-identity guard in an authorized lab build, or produce a final signed-artifact manifest. Do not generate or replace production keys implicitly, expose passwords, overwrite inputs, or claim success without apksigner verification.
---

# Android APK Alignment And Signing

Turn a validated unsigned APK copy into a separately named, aligned, signed, and verified artifact.

## Inputs

Require the unsigned APK and repack report, pinned `zipalign` and `apksigner` paths/versions, output path, keystore path, key alias, password environment-variable names, minimum SDK, and deployment identity requirements.

Follow the integrated signing contract and tool records below before selecting a key or invoking tools.

## Workflow

### 1. Select The Signing Identity Explicitly

Determine whether the target is a disposable lab build, an organization-controlled test build, or an update that must match an existing signing certificate. Never create a production key automatically. A differently signed APK cannot update an installed package with the same application ID.

Record expected certificate SHA-256 before signing when continuity matters.

### 2. Pin And Inspect Build Tools

Record `zipalign -h` and `apksigner version`. Use both tools from the same Android Build Tools installation. Check the pinned tool help for supported page-alignment and signature-scheme options.

For the repository-pinned Windows toolchain, review the integrated Build Tools record below, then install with explicit SDK license acceptance:

```powershell
./install_android_build_tools.ps1 `
  -SdkRoot C:\android-sdk-reverse-skills -AcceptSdkLicense
```

The installer verifies the fixed command-line tools archive and the installed
Build Tools 36.0.0 files. Do not substitute a GUI wrapper for final
`apksigner verify` evidence.

### 3. Keep Secrets Out Of Commands And Logs

Store keystore and key passwords in named environment variables. Pass `env:VARIABLE` references to `apksigner`; never put secret values in command history, reports, source files, or process-debug output.

### 4. Align, Sign, And Verify

Run:

```bash
python sign_apk.py --input rebuilt-unsigned.apk \
  --output rebuilt-signed.apk --keystore lab.jks --alias lab \
  --ks-pass-env APK_KS_PASS --key-pass-env APK_KEY_PASS \
  --zipalign /path/to/zipalign --apksigner /path/to/apksigner \
  --identity-policy release-update --expected-cert-sha256 <digest> \
  --report signing-report.json
```

The script aligns before signing, writes to a new output, invokes `apksigner verify --verbose --print-certs`, checks alignment again, and records hashes/tool output without recording password values.

Use `--dry-run` to validate paths and inspect the redacted plan without executing external tools.

### 5. Check Certificate And Deployment Compatibility

Compare the verified signer certificate digest with the expected identity. If it differs, label the artifact as a separately installable lab build or stop when update compatibility is required.

### 6. Handle Evidenced Native Signing Guards

Prefer signing with the required certificate. When that certificate is unavailable and an authorized disposable lab build aborts because a native signing-identity whitelist rejects the selected lab key, preserve the original crash evidence and identify the exact guard instruction before patching.

Apply only an explicit, preimage-checked patch to a new ELF copy:

```bash
python patch_aarch64_guard.py --input libguard.so \
  --output libguard-lab.so --vaddr 0x1234 \
  --expect-hex 17260036 --replace-hex 1f2003d5 \
  --report native-guard-patch.json
```

The caller must establish the instruction semantics independently. Record the original and replacement instruction, virtual address, file offset, both hashes, native crash backtrace, signer mismatch, and same-device original-build control result. Never use a wildcard byte search, overwrite the source ELF, or describe a lab-key guard patch as certificate continuity.

### 7. Smoke Test On An Authorized Device

After verification, install only on a disposable authorized device/profile. Record install result, launch result, protected-method smoke vectors, crashes, and logcat. Do not uninstall or replace an existing user installation without explicit authorization and a recovery plan.

## Deliverables

Produce the signed APK, signing report, input/output hashes, build-tool versions, alignment verification, signature-scheme and certificate output, identity comparison, and optional device smoke-test report.

## Completion Criteria

- Alignment occurs before signing and final alignment verification passes.
- `apksigner verify --verbose --print-certs` succeeds.
- Certificate digest matches the declared deployment policy or the mismatch is an explicit lab-build limitation.
- No password value appears in commands, logs, reports, or repository files.
- Source and unsigned APK inputs remain unchanged.
- Any native signing-guard patch is exact, preimage-checked, separately reported, and limited to an authorized lab artifact.
- Device smoke testing, when requested, uses an authorized disposable target.

---

## Integrated Reference: APK Signing Contract

## Identity Classes

- `lab`: disposable local key; cannot update a build signed by another certificate.
- `organization-test`: controlled shared test key with documented custody.
- `release-update`: must match the installed/released certificate and organizational signing process.

Stop before signing when the required identity is unknown. Never create, rotate, or export a production key implicitly.

Use `--identity-policy release-update --expected-cert-sha256 <digest>` when the artifact must update an existing installation. The signing helper stops before execution if a release-update digest is missing and stops before publishing the output if the verified digest differs.

## Required Order

1. Validate the unsigned APK and repack report.
2. Run `zipalign` to a temporary artifact. Preserve 16 KiB page alignment for uncompressed native libraries when supported by the pinned Build Tools.
3. Sign the aligned artifact with `apksigner`.
4. Run `apksigner verify --verbose --print-certs`.
5. Run final `zipalign -c` verification.
6. Compare signer certificate digest with the declared policy.

Signing before alignment invalidates the signature. `jarsigner` alone is not an adequate replacement for modern APK signature-scheme verification.

## Secret Handling

Pass password references as `env:VARIABLE`. Reports may record the environment-variable names, keystore hash, alias, certificate digests, and tool output, but never the secret values.

## Final Report

Record input/output hashes, exact tool paths and versions, alignment command/result, redacted signing command, verification output, certificate DN and digests, identity class, expected digest comparison, and smoke-test status.

## Native Signing-Identity Guards

A valid APK signature does not guarantee that application-native code accepts a different signer. Prefer the original or organization-controlled certificate. For an authorized lab build only, an exact guard patch is acceptable after all of the following are recorded:

- the rebuilt APK passes `apksigner verify` and alignment checks;
- a device tombstone or trace identifies the native abort path;
- instruction-level analysis establishes the guard predicate and failure edge;
- the untouched original APK survives the same-device control launch;
- the changed ELF address and original bytes are supplied as a mandatory preimage;
- the patched ELF and final APK are separately named and hashed.

Do not infer a signing guard from a generic startup crash. Do not patch by wildcard search, suppress unrelated native failures, or claim that a lab certificate is update-compatible with the release certificate.

---

## Integrated Reference: Android Build Tools 36.0.0 Lock

This module records the official Android SDK packages used by `rev-signer`.
The SDK binaries are not redistributed by this repository. The installer
downloads the fixed official command-line tools package, installs
`build-tools;36.0.0`, and verifies the exact `zipalign` and `apksigner` files
against `build-tools.lock.json`.

The SDK license must be accepted explicitly:

```powershell
./install_android_build_tools.ps1 `
  -SdkRoot C:\android-sdk-reverse-skills -AcceptSdkLicense
```

Review the current Android SDK terms before using or redistributing any SDK
component.

---

## Integrated Reference: Android Platform Tools 35.0.2 Test Record

This module records the ADB executable used for the authorized device smoke
test. Android SDK binaries are not redistributed by this repository.

- Tested ADB version: `35.0.2-12147458`
- Official release notes: <https://developer.android.com/tools/releases/platform-tools>
- Official Windows download alias: <https://dl.google.com/android/repository/platform-tools-latest-windows.zip>
- Tested host path: `D:\Pixel2_root\platform-tools-latest-windows\platform-tools\adb.exe`

The `latest` download alias is mutable and is not a version pin. Verify the
installed executable against `platform-tools.lock.json` or establish a new reviewed
lock before reproducing the smoke test.

For the tested root device, APK installation must use this exact sequence:

```powershell
adb push rebuilt.apk /data/local/tmp/rebuilt.apk
adb shell su -c "pm install -t /data/local/tmp/rebuilt.apk"
```

Do not substitute `adb install` or another package-installer path for this device.
After a successful install, verify the installed base APK hash and remove the
exact `/data/local/tmp/` staging file.
