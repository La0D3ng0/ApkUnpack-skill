---
name: rev-apk-repack
description: Rebuild an unsigned APK copy from an authorized source APK and validated replacement entries such as classes.dex files. Use when Codex must replace rebuilt DEX files, preserve ZIP entry metadata and compression, remove invalidated legacy signatures, detect duplicate or unsafe archive paths, produce a reproducible repack manifest, or prepare an unsigned artifact for zipalign and signing. Do not sign APKs or modify the source archive in this skill.
---

# APK Repacking

Create a new unsigned APK container while preserving the source archive and recording every changed entry.

## Inputs

Require the source APK hash, replacement entry map, rebuilt DEX validation reports, output path, and signing plan. Follow the integrated repack manifest contract below before creating the replacement manifest.

## Workflow

### 1. Validate Inputs

Confirm that the source is a parseable ZIP/APK with no duplicate entry names. Reject absolute paths, traversal components, backslashes in archive names, missing replacement files, mismatched source hashes, and attempts to overwrite the source.

Require independent DEX validation for every `classes*.dex` replacement.

### 2. Build An Unsigned Copy

try apktool first,if it failed,then:

Run:

```bash
python repack_apk.py --manifest repack-manifest.json \
  --output rebuilt-unsigned.apk --report repack-report.json
```

The script copies entries in source order, preserves relevant ZIP metadata and compression, substitutes only named entries, and removes invalidated `META-INF` JAR signature files. Rebuilding the ZIP also discards any old APK Signing Block.

Do not add arbitrary files unless the manifest explicitly allows new entries and the security impact is reviewed.

### 3. Verify The Container

Check ZIP CRCs, entry count, replacement hashes, compression methods, manifest/resources presence, ABI entries, and absence of old signature artifacts. Confirm the source hash did not change.

If reproducibility matters, run twice with the same source and replacement files and compare output hashes. Any timestamp or extra-field normalization must be intentional and documented.

### 4. Record The Delta

Produce an entry-level manifest containing source/output hashes, removed signature files, replaced entries with before/after hashes, added entries, compression, sizes, and tool version.

### 5. Hand Off Unsigned Output

Pass the unsigned APK and repack report to `$rev-signer`. Do not install or distribute the unsigned artifact as a completed result.

## Deliverables

Produce the unchanged source hash, unsigned APK copy, replacement manifest, repack report, ZIP validation result, and exact changed-entry list.

## Completion Criteria

- Only manifest-approved entries changed or were removed.
- Every replacement hash matches its validated input artifact.
- ZIP CRC validation passes and required APK entries remain present.
- Old signatures are absent and output is explicitly marked unsigned.
- The source APK remains byte-for-byte unchanged.

---

## Integrated Reference: APK Repack Manifest Contract

Use `schema: rev-apk-repack/v1`:

```json
{
  "schema": "rev-apk-repack/v1",
  "source_apk": "artifacts/base.apk",
  "source_apk_sha256": "...",
  "allow_new_entries": false,
  "remove_legacy_signatures": true,
  "replacements": [
    {
      "entry": "classes12.dex",
      "file": "artifacts/classes12-rebuilt.dex",
      "sha256": "...",
      "validation_report": "reports/classes12-validation.json"
    }
  ]
}
```

Archive entry names must be relative POSIX paths with no empty, `.` or `..` component and no backslash. Reject duplicate source or replacement names.

Legacy signature removal covers `META-INF/MANIFEST.MF`, `META-INF/*.SF`, `META-INF/*.RSA`, `META-INF/*.DSA`, and `META-INF/*.EC`. Rebuilding the ZIP removes the old APK Signing Block. The output is unsigned even when no visible `META-INF` signature existed.

Only direct children of `META-INF/` match this rule. Preserve nested resources
such as `META-INF/versions/9/OSGI-INF/MANIFEST.MF`; they are not APK signature
metadata.

The repack report must record source/output hashes, entry count, removals, replacements, additions, before/after hashes, compression methods, sizes, and CRC validation.
