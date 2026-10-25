---
name: rev-java2c
description: Analyze JNI dispatch bridges such as JniLib.cV/cI/cL after Android DEX extraction. Distinguish Dalvik refill, JNI native behavior, and a private bytecode VM; inventory dispatch IDs, harvest private programs without UI triggers when possible, and recover verified semantics or DEX code.
---

# Java2C and Native Bridge Recovery

Use this skill after the extracted DEX and its `CodeItem` mappings pass `$rev-dex-rebuild` validation. DEX extraction can be complete even when some recovered methods still call a native dispatcher. A JNI bridge proves delegation to native code; it does not alone prove that original Java code was converted to C/C++, that original Dalvik instructions can be recovered, or that the SO contains a VMP.

## Scope and intake

Start with one exact Java method unless the user requests an inventory or whole-sample recovery. Record the source APK and SO hashes, ABI, restored DEX hash, class/name/prototype, DEX method index and `code_off` where known, bridge call and argument order, dispatch ID if present, and the observed return type and side effects. Keep a list of bridge methods separate from methods with readable restored Dalvik bodies. A dispatch ID is not a DEX method index, and its maximum does not establish the number of protected methods.

The extracted-DEX workflow in `$rev-gen2-extracted-dex-unpack` and the validated DEX from `$rev-dex-rebuild` provide the intake. Do not reopen DEX restoration merely because JADX displays a bridge. For the observed Bangcle sample, `LoadingActivity.onCreate(Bundle)` calls `JniLib.cV(..., 286)` after its `code_off` is restored; this is an example of the handoff, not a universal dispatch format.

For an inventory, use [scripts/inventory_bridges.py](scripts/inventory_bridges.py) to bind each literal ID to a class, method descriptor, and DEX method index. Cross-check the call count against baksmali or another independent parser. A parser may silently skip a valid nonzero `code_off` outside the DEX header's declared `data_size`: on the Bangcle sample, direct Androguard traversal saw 5,224 of 17,468 bridge calls. The script warns about skipped code items; give it the matching baksmali directory with `--smali-root` to collect all 17,468. Reject duplicate or unresolved IDs before using an ID-indexed table as a whole-sample map.

| Observed mechanism | Next work |
| --- | --- |
| The bridge decrypts and writes valid Dalvik `CodeItem` bytes into a DEX or ART-visible method location. | Treat it as a trigger for delayed refill; capture the complete bytes and return them to `$rev-dex-rebuild`. |
| The bridge executes Native operations and JNI callbacks, without evidence of private instruction fetch. | Route A: trace selected methods with valid inputs and reconstruct evidence-backed behavior. |
| A changing private instruction cursor feeds an opcode decoder and handler dispatch. | Route B: harvest programs if possible, then use `$rev-opcodes` to decode and validate them before Smali/DEX reconstruction. |

## Find the native body

1. Confirm the bridge declaration and its loaded library. Resolve `RegisterNatives` or exported JNI bindings and trace the native dispatch from the exact Java signature and ID to the target branch/function. Normalize addresses as `SO hash + RVA`.
2. Determine what is being recovered: a native implementation, a wrapper around further JNI/ART calls, runtime restoration of a Dalvik body, or an actual bytecode interpreter. Compare a selected method's mapped `CodeItem` before and after its real bridge call; also look for writes to other DEX copies and `ArtMethod` fields before excluding refill. If valid Dalvik instructions reappear, pass those bytes and their provenance back to `$rev-dex-rebuild`.
3. Use static analysis and a narrow real-device trace to establish inputs, state reads, calls, writes, returns, and exceptions. Replay a verified narrow native entry with an evidence-backed unidbg harness when useful; use `$rev-jni-env` for nontrivial environment dependencies and `$rev-frida` when real process state is needed. Use `$rev-symbol` to recover bounded native function semantics. Emulation outputs are observations for specified inputs, not a recovered method body by themselves.
4. If a changing VM PC reads private words, decode selects handlers, and handler execution advances the VM state, hand the verified fetch/dispatch evidence to `$rev-opcodes`. OLLVM flattening, a jump table, or a JNI dispatch ID alone is insufficient for a VMP claim.

## UI-independent intake and private VM handoff

Privacy prompts and login screens limit **executed-path** coverage, but may leave an already initialized private program pool available. After the app's own initialization, first inspect the native resolver that takes a dispatch ID. If it indexes an in-memory record table, read the table and bounded records from the process or replay a pure lookup/decryption helper in Unidbg. Check every pointer against current mappings, every record ID against its slot, every length against readable memory, and hashes across fresh runs. Link records to the static bridge inventory; this can harvest cold methods without clicking through the UI. Do not assume all packs initialize their pool before consent or login; verify table population at the observed startup state.

Calling every `JniLib.c*` entry with synthetic objects is a different experiment. Its JNI method body can read real receivers, mutate app state, start network/payment operations, throw, or crash, and one fake input reveals only one path. For a controlled active replay, choose a small method with a verified argument contract, construct valid receiver/parameter objects, record side effects and exceptions, and compare with an ordinary invocation. Prefer the read-only table or a verified pure decoder for **bulk data extraction**; use the selected-method semantic workflow below for **behavioral recovery**.

For private records shaped like `CodeItem`, verify the header and full byte extent, then decode sample instruction bodies with a standard DEX parser and check register and reference bounds. A DEX-shaped header does not make the body Dalvik. If the bytes are private opcodes, keep the raw programs as evidence and follow the native fetch, opcode table, handlers, operand lengths, reference translation, branches, and exception behavior before emitting smali. In the Bangcle sample, 17,468 records were captured without UI actions; a 65,536-slot private dispatch table had 383 valid native handler entries, and all 17,468 first opcodes hit it. `JniLib.cV(..., 248)` has a valid `CodeItem` header but nonsensical standard Dalvik register/type references. These observations warrant route B for that sample and show that direct `insns` replacement would be invalid.

### When `RegisterNatives` observation is silent

An empty registration trace does not establish how the method was bound. On a version-matched device, resolve the exact bridge class and signature through its app class loader, obtain its `jmethodID`, and decode it to an `ArtMethod*` when ART uses managed IDs. Validate the method's native flag and DEX index, then read its native `data_` pointer using the **device's verified ART layout** and map that pointer to a loaded SO or executable region. Keep the quick entry point distinct from `data_`; neither a fixed offset nor a raw `jmethodID` cast is portable. Record the SO hash and RVA. A bound native pointer gives a narrow function to observe, but does not reveal whether binding used `RegisterNatives`, static JNI lookup, or a direct write.

Hook only that verified entry for the chosen dispatch ID, call the original, and compare the selected method's mapped `CodeItem` bytes around the actual invocation. If no Dalvik refill is observed, trace bounded field changes, JNI callbacks, return and exception behavior for route A. Inspect a private instruction stream and invest in `$rev-opcodes` only if a changing fetch/dispatch mechanism is actually observed. A single unchanged `CodeItem` rules out only an in-place refill of that observed region and invocation; it does not classify every bridge in the app.

## Recover and check selected-method behavior

For a selected nativeized method, reconstruct an equivalent Java/smali implementation only where control flow and effects are supported by evidence. Preserve return values, field and buffer changes, JNI callbacks, and exceptions. For a `void` bridge such as `cV`, side effects and callback order are part of the result. Compare the candidate with the protected app on inputs that distinguish feasible branches, including relevant null, boundary, and error cases. State the tested paths and unresolved paths; do not label an untested method complete.

If only the dispatch map or a subset of behavior is established, deliver that partial result without synthesizing missing branches. Keep reconstructed candidates separate from the validated extracted DEX. Apply a proven smali/DEX replacement through `$rev-dex-rebuild`; repack only when requested and after the replacement is validated.

## Deliverables

Provide a bridge inventory or one-method record with descriptor, bridge signature, dispatch ID, SO binding and RVA, hashes, input/state contract, scoped traces, native behavior summary, and evidence for any Java/smali candidate. Record comparison inputs, expected and observed returns, exceptions, writes, callbacks, and remaining gaps. Place user-facing results under the sample's `<apk-stem>-unpacked/` directory without changing its already validated `classes*.dex` unless a separate replacement passes validation.
