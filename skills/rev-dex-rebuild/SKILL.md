---
name: rev-dex-rebuild
description: Restore verified class data or method code extracted from a first- or second-generation Android shell into a copy of its DEX and validate structural integrity. Use when runtime dumping produced partial DEX files, displaced code_item data, no-header regions, JDex2/FART/kernel acquisition output, or exact smali bodies that must be mapped to class/method descriptors, assembled, header-repaired, and compared with raw evidence. Do not patch the original DEX or insert unproven bytes.
---

# DEX Rebuilding

Rebuild only ranges or methods with exact source identity, location, descriptor mapping, and structural evidence.

## Inputs

Require source DEX/APK hashes, raw acquisition manifest, exact class/name/descriptor mapping, captured address/original DEX offset and length where available, recovered code/class data, reference-resolution evidence, and validation expectations.

Follow the integrated rebuild contract below before selecting a rebuild strategy or writing a patch manifest.

## Workflow

### 1. Gate Every Patch

Require:

- Exact class descriptor, method name, and method descriptor.
- Raw artifact hash plus acquisition run, environment, address/size, and reason.
- Complete instruction decoding and valid branch/payload/try boundaries for a code item.
- Resolved string/type/field/method references.
- Register, parameter, exception, annotation, and debug-info decisions.
- No conflicting capture for the same original DEX range.

Leave failed or ambiguous patches pending. Do not infer a missing method body from a similar class or another app version.

### 2. Choose A Rebuild Strategy

- Prefer baksmali/smali symbolic rebuilding when code size, indexes, branches, try ranges, or payloads can change.
- Use byte-level replacement only when an exact original DEX offset/layout is proven and a DEX-aware parser validates the result.
- For a no-header capture, preserve the raw region and create a separate repaired candidate; never overwrite the evidence.
- Do not append raw code items and hand-edit `code_off` unless a DEX-aware writer updates class data, map items, offsets, signature, and checksum. When complete CodeItems already exist inside `file_size` and fixed-width `code_off` fields can point to them without moving any section, use a variant-specific parser to prove every mapping and repair the header in a separate copy.

### 3. Apply To A Copy

For a Bangcle `fdex` container whose observed layout matches the ordered decoy-CodeItem variant, run `rebuild_bangcle_fdex.py` with the original container, a verified native prefix for each DEX, the parser-derived payload offset, and the independently established encrypted-prefix cap (`--encrypted-cap`). Derive these inputs anew for every APK; a short DEX may have a shorter block-aligned prefix. The script refuses ambiguous segment or tail mappings, reconciles the extracted placeholder count with **all** final methods whose `code_off` lies beyond `data_end`, and writes fixed-width `code_off` updates to new files. **For deliverables, generate offline prefixes first and use `--prefix-source offline`.** `--prefix-source device` requires `--diagnostic-only`: device class data may already contain patched offsets, masking placeholders. Use `--truth` only to compare against independent device captures; it never supplies restoration bytes. For other layouts, choose the general strategy below.

After rebuilding, `repair_dex_header.py` can create a separate analysis copy with recalculated SHA-1 and Adler-32; it requires physical length to match declared `file_size` and leaves all other bytes intact.

Install the pinned smali toolchain when required:

```powershell
./install_smali_toolchain.ps1 -MavenCommand mvn
```

Apply a `rev-dex-rebuild/v1` manifest to a new tree:

```bash
python apply_smali_patches.py \
  --smali-root original-smali --manifest patch-manifest.json \
  --output-root rebuilt-smali --report smali-patch-report.json
```

The script requires one exact method match and refuses to overwrite the source or an existing output tree.

### 4. Assemble And Validate

```bash
python verify_dex.py rebuilt.dex -o dex-validation.json
```

Disassemble every final DEX with the pinned Baksmali toolchain and retain its log and Smali output. Compare class/method counts, descriptors, code presence, annotations, try/catch ranges, and untouched hashes. If method IDs approach 65,535, move only a proven closed class cluster to the next unused `classesN.dex`; verify no duplicate or omitted class.

On Windows, if a Java tool fails when its working directory or input path contains Chinese characters, rerun through an ASCII-only junction/path and record that alias. Keep PowerShell 5.1 output and JSON explicitly UTF-8; its `>` can write UTF-16/BOM, so use `adb exec-out` plus Python binary I/O for captures and detect text encoding in Python. Check `su -c` quoting with a harmless probe or stage a device script. For a roughly 90 MiB DEX set on a 16 GiB host or restricted page file, start JADX with `-Xmx3g` and reduced parallelism; a G1 reserve failure is a heap/environment issue until shown otherwise.

For extracted-method shells, decompile the final DEX set with JADX and compare it with the original shell DEX. Follow the app's main and core business paths through the actual calls. Show which methods changed from placeholders to readable Dalvik, and inspect their decisions, inputs, outputs, and effects in JADX and Smali. Quantify relevant JNI bridges and Java decompiler failures. Count `Method not decompiled` **methods** over DEX methods with CodeItems: zero classes containing failed methods in the target core business packages and below 1% failed methods globally is a useful JADX-quality gate; above it, investigate. This ratio cannot pass a core method that is still a native bridge. If core logic is hidden there, report that scope as unrecovered. Class count or valid DEX headers alone cannot establish business-logic recovery. Deliver final DEX files at the root of the `<source-apk-stem>-unpacked/` folder inside the sample workspace, as specified by the repository README. The adapter's manifest maps output DEX 1 to `classes.dex`, then DEX 2 to `classes2.dex`; never name a file `classes1.dex`.

### 5. Replay Relevant Behavior

Where a recovered method has an executable test vector, compare return values, exceptions, field writes, and calls with the protected original run. Structural validity alone does not prove the extracted body belongs to that method.

### 6. Hand Off

Pass only the validated DEX copy to `$rev-apk-repack`. Keep raw dumps, repaired candidates, rejected conflicts, and final rebuilt DEX as separate artifacts.

If validated methods still delegate to JNI, hand their descriptors, bridge call sites, dispatch IDs, and source hashes to `$rev-java2c`. Treat the extracted DEX as complete for its validated scope; recovery of native method behavior is a separate task. Accept a later Java/smali replacement only with the same per-method evidence and validation gates above.

## Deliverables

Produce the patch manifest, evidence mapping, body/range files, untouched source hash, rebuilt DEX, structural/independent validation reports, applied/pending/conflict list, and optional behavior comparison.

## Completion Criteria

- Every patch maps to one exact descriptor and one source DEX identity.
- Captured bytes have run/address/offset/length/hash provenance.
- DEX checksum, signature, bounds, code items, and independent parsing pass.
- For an extracted-method shell, every final DEX disassembles with Baksmali and the main/core business paths have readable, method-mapped evidence; otherwise report partial recovery.
- Untouched classes and methods remain equivalent.
- Conflicting or incomplete extracted data remains pending.
- Source APK/DEX remains unchanged.

---

## Integrated Reference: DEX Rebuild Contract

## Strategy Selection

Use symbolic baksmali/smali rebuilding when any method size, branch layout, reference index, try range, payload, or debug program can change. Use raw replacement only when an acquisition manifest proves the original DEX offset and a DEX-aware parser proves layout compatibility.

## Smali Patch Manifest

Use `schema: rev-dex-rebuild/v1`:

```json
{
  "schema": "rev-dex-rebuild/v1",
  "source_dex_sha256": "...",
  "acquisition_manifest": "reports/kernel-or-art-dump.json",
  "patches": [
    {
      "patch_id": "extracted-method-16",
      "class_descriptor": "Lcom/example/Result;",
      "method_name": "load",
      "method_descriptor": "()V",
      "body_file": "bodies/extracted-method-16.smali",
      "evidence_ids": ["run-early-2", "dex-range-0x41a20"],
      "original_dex_offset": "0x41a20",
      "raw_sha256": "..."
    }
  ]
}
```

Body files contain the complete content between `.method ...` and `.end method`, including one `.locals` or `.registers` directive. They must not contain `.method`, `.end method`, or class-level directives.

## Required Validation

1. Verify source DEX and raw-capture hashes.
2. Require exactly one target method match.
3. Prove offset/descriptor/reference mapping and reject conflicting captures.
4. Assemble with pinned smali.
5. Validate magic, size, endian tag, SHA-1 signature, Adler-32 checksum, map bounds, class data, and code items.
6. Parse/disassemble with a second tool.
7. Compare untouched class/method surface and replay relevant behavior when available.

If the rebuilt DEX approaches the 65,535 method-ID limit, perform an explicit multidex split using only classes with a verified closed ownership/reference boundary. Use the next unused `classesN.dex` and validate every DEX independently.

Never treat checksum repair, class count, or one successful parse as proof of complete second-generation shell recovery.

---

## Integrated Reference: Smali 3.0.9 Tool Lock

This module pins the Google smali/baksmali 3.0.9 Maven release used by the
DEX rebuild workflow. Binary jars are fetched from Google Maven and Maven
Central, then checked against `smali-toolchain.lock.json`; they are not committed.

Install with:

```powershell
./install_smali_toolchain.ps1 -MavenCommand mvn
```

Use `run_baksmali.ps1` and `run_smali.ps1` so the exact locked classpath is
selected. The upstream project and artifacts use Apache License 2.0.
