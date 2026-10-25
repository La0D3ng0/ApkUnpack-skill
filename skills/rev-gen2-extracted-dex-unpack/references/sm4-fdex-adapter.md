English | [中文](sm4-fdex-adapter.zh-CN.md)

# Optional adapter: verified SM4-ECB / fdex prefixes

**Use only when this APK's native path or independent input/output vectors establish standard SM4, blockwise ECB decryption, the encrypted extent, and segment boundaries.** An `fdex` marker, shell-family label, or previous sample does not establish these conditions. This adapter produces decrypted prefixes; method mapping and DEX reconstruction still require evidence from this sample's layout. Otherwise return to the [general workflow](extracted-dex.md), identify the native transform, and replay it with Unidbg or capture its output on device.

## Minimum experiment for this sample

1. **Form a candidate, not a conclusion.** Locate ciphertext in the original container and establish plaintext clues, a candidate key, and its provenance independently. The `dex\n` magic covers only part of one block: obtaining the first eight bytes does not rule out XOR, a stream cipher, or another transform. Plaintext produced by the proposed SM4 decryptor cannot be reused as independent known plaintext.
2. **Separate implementation checks from target evidence.** Check the local implementation against a [published SM4 single-block vector](https://datatracker.ietf.org/doc/draft-ribose-cfrg-sm4/07/); that validates the tool only. For this APK, compare **independently known full 16-byte plaintext blocks** with their ciphertext using `SM4_encrypt(K, P_i) == C_i`. Prefer two blocks at distinct positions, or combine a block comparison with recognizable SM4 rounds/key expansion in the native routine. Independent plaintext may come from trusted native output or complete blocks inferred without using the proposed decryptor. With only magic and no independent full block or native algorithm evidence, retain “SM4 candidate” status.
3. **Check the block mode and its scope.** If independent plaintext contains identical blocks at different positions, check that their ciphertext matches. This supports ECB but does not alone exclude a repeated keystream. Combine full-block comparisons at several positions with native evidence of no IV, feedback, or counter state, or byte equality against an independent full-prefix output, before calling the **observed range** SM4-ECB. The absence of repeated plaintext does not disprove ECB. Then validate DEX headers, `file_size`, segment trailers, and method mappings; those structural checks do not replace cipher evidence. [NIST defines ECB](https://csrc.nist.gov/pubs/sp/800/38/a/final) as an independent fixed mapping of plaintext blocks under a given key.

This can be done offline with the container, a verified key, and static native analysis, but a container offering only eight known plaintext bytes cannot by itself prove the algorithm or mode. Record every full block's offset, independent plaintext source, ciphertext, key hash, native evidence, and conclusion in a sample evidence file. If evidence is insufficient, return to native-boundary analysis.

## Select and verify a key source

| Source | When and how to verify |
|---|---|
| Hook the native key-schedule input | The function and initialization time are known. Record the 16-byte input's function, timing, and memory provenance; validate the first DEX block and full prefixes. |
| [sm4_key_scan.py](../sm4_key_scan.py) over the complete capture | The current sample supplies an encrypted first DEX block and at least 8 known plaintext bytes. By default it recursively scans the sample's capture directory so a key in a heap mapping is not missed by selecting only the SO. NumPy checks candidate windows against the full DEX header and `fdex` trailer. A miss can mean a missing mapping, a stored round schedule, a derived key, or a wrong cipher model. |
| Static derivation | Constants, signature data, or deterministic state provably yield the key. Record inputs and transformations, then check independent prefix or device vectors. |

### Capture coverage and scan order

Record the process mappings, writable-page changes, and native calls around key initialization. Check module RX/RW/BSS, separate `[anon:.bss]`, the heap actually used (possibly `[anon:scudo:*]`), and relevant stack/TLS. Choose captured pages from this sample's reads, writes, and allocations; retain address, time, and hash provenance. No particular SO or allocator is a universal key source.

Put the full captured set in a dedicated `capture/`, `captures/`, `maps/`, `memory/`, or `memregions/` directory beneath the sample workspace. Running the scanner from that workspace discovers these directories and scans their binary files recursively; for another directory name, pass `--capture-dir` for the **whole capture root**. A matching `.bin.json` acquisition sidecar and `maps-<pid>.txt` can supply the virtual base and map label; maps text supports UTF-8/UTF-16 BOM, and a sidecar hash mismatch stops the scan. Scudo-labeled regions are processed first, without excluding any other region. Without base metadata, the report keeps the file offset and leaves the virtual address null. `--memory`/`--range` is for a later bounded diagnostic, not the default first search.

The default `--stride 1` covers every 16-byte window, using up to four worker processes; tune `--workers` if needed. **Observed reference, not an ETA:** one 185 MiB capture took roughly 90 minutes with one worker; parallel speedup depends on CPU, memory bandwidth, and storage. A full-capture `--stride 4` pass can be used for early triage, but a miss requires `--stride 1` over the **entire capture**, including regions outside the SO. If the raw key never appears in captured memory, observe the native key-schedule input or derive it statically. A scan miss alone does not disprove the cipher model.

The scanner writes a uniquely matched key to a new binary file; its report contains hashes and source addresses only. Keep the file in an ignored directory. **Do not pass raw key bytes on a command line or commit them.** These are command shapes, with every offset, alignment, length, and count derived from the current APK:

```text
cd <sample-workdir-containing-complete-captures-directory>
python <skill-dir>/sm4_key_scan.py --stride 1 --workers 4 \
  --container original-classes.dex --cipher-offset <verified-first-segment> \
  --known-plaintext-hex <current-DEX-first-8-bytes> \
  --key-output <ignored-directory>/key.bin --report key-scan.json

python decrypt_prefixes.py --container original-classes.dex --key-file <key.bin> \
  --encrypted-cap <native-verified-cap> --discover \
  --payload-offset <native-verified-payload> --alignment <native-verified-alignment> \
  --expected-segments <confirmed-count> --evidence-file <sample-evidence-report> \
  --output-dir offline-prefixes
```

When segment starts are already established, repeat `--segment-offset` instead of using discovery. The decryptor checks each DEX header, `file_size`, and `fdex` trailer; a short DEX stops at its block-aligned file boundary. The manifest's `caller_claim` records the caller's model. `evidence_file` and `evidence_sha256` identify an external report; **the script does not adjudicate that report** and stores `null` when none is supplied.

`--truth-prefix` accepts an independent device prefix or full DEX, comparing only the prefix length. If **every** difference falls inside a parsed `class_data` `code_off` ULEB field at the same offset and encoded width, the manifest reports `class_data_code_off_rewrite` and keeps the offline plaintext. This diagnoses a possible device-side method-offset refill; it is **not** a byte-equal prefix result. Any unclassified difference fails. Device bytes never feed decryption or reconstruction. Rebuild with `$rev-dex-rebuild --prefix-source offline`, then compare the whole final DEX to the device reference and reconcile method counts. `--prefix-source device` requires `--diagnostic-only` and cannot be delivered.
