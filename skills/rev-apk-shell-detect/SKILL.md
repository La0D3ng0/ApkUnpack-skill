---
name: rev-apk-shell-detect
description: Quickly inspect an authorized Android APK and classify common commercial packer signatures, custom loader-shell evidence, no detected APK loader shell, or an inconclusive result. Use when the APK loader-shell family is unknown and the user wants a fast static classification report.
---

# APK Shell Detection

Classify an APK without installing or executing it, and report the detection evidence.

## Quick Use

Run from this Skill directory:

```bash
python detect_apk_shell.py target.apk -o shell-report.json
```

The detector uses Python's standard library to inspect ZIP paths, Application and SO markers, bounded DEX strings, stub relationships, and suspicious opaque payloads. If `apkid` is on `PATH`, the default `--apkid auto` also merges its JSON packer matches.

Use `--apkid off` for the built-in scan only. Use `--apkid required` when the external APKiD result is required; an unavailable or failed APKiD run then remains inconclusive.

## Interpret The Result

The report has one of four family/classification states:

- `known_shell`: a strong signature identifies a likely commercial/common family.
- `custom_shell`: several independent structural signals indicate a loader shell, but no known family wins.
- `no_shell`: this bounded scan found no APK loader shell. It says nothing about VMP, OLLVM, encrypted algorithms, or other protection inside native `.so` files.
- `inconclusive`: evidence is incomplete, weak, or conflicting.

## Choose The Unpacking Route

Read `shell.variant`, `shell.generation`, `container_layout`, and `routing.next_skill` after the family result. The commercial shell family does **not** determine its generation.

| Structural evidence | Report and next Skill |
|---|---|
| Large primary-DEX overlay, nearby `dexdata0`, interior `fdex` markers, EOF `fdex` trailer | `fdex-overlay`, `second-generation-candidate` → `rev-gen2-extracted-dex-unpack`. Enter its container triage immediately; runtime dump is a conditional evidence source inside that workflow. |
| Small bootstrap DEX with loader relationship and no recognizable extracted-container evidence (an opaque high-entropy overlay may still be present) | `stub-loader`, `first-generation-candidate` → try `rev-dex-dumper` first. Confirm that output contains the app's own classes and business methods; otherwise re-evaluate the generation. |
| Only family evidence, or a truncated/ambiguous container scan | `unknown` → inspect DEX layout and loader behavior before selecting either route. Absence of a detected `fdex` marker does not prove first generation. |

`fdex_trailer_count` counts **candidate** interior markers. Confirm segments using decrypted DEX lengths and boundaries. A `known_shell` result can still have `variant=unknown`; do not treat `gate.continue_unpacking=true` as a tool choice. A second-generation extraction result is complete only after rebuilding and validating its method bodies and core business logic.

`valid_data_end` is calculated from the DEX header's `data_off + data_size`. It is a declared section boundary and can differ from the last parsed `map_list` item. The detector searches the first 4 KiB after this boundary for `dexdata0`; missing that marker is inconclusive for other container layouts.

## Detection Boundaries

Do not classify an APK as packed from only one generic signal such as multidex, ProGuard/R8 names, JNI use, `DexClassLoader`, a small DEX, a plugin/hot-fix framework, or a generic SO filename.

A known family requires one unique strong marker, two compatible independent markers, or an unambiguous APKiD packer match. Close strong conflicts remain `inconclusive`.

A custom shell requires all of these categories:

- a small primary or stub DEX;
- an opaque high-entropy payload;
- a runtime DEX loader or native bootstrap relationship;
- no winning known family.

`no_shell` means only that this bounded static scan found no APK loader shell. It does not prove that there is no method encryption, native protection, dynamic feature, or remotely delivered code.

## Updating Signatures

Edit `shell-signatures.json` beside this file. Prefer exact vendor-specific paths, class descriptors, or library basenames. Keep generic markers low-weight and non-unique. For every change, test both a positive sample and a collision sample so a common library cannot identify a vendor by itself.

## Deliverables

Preserve the original APK and report:

- APK SHA-256;
- `shell-report.json`;
- status, likely family, confidence, and exact evidence;
- APKiD availability and matches;
- scan gaps and limits.

Completion means the static family/variant result and route are evidence-backed and the source APK is unchanged. It does not mean that the APK has been unpacked.
