---
name: rev-gen2-extracted-dex-unpack
description: Unpack second-generation Android dynamically extracted-method DEX shells (二代动态抽取型壳). Enter as soon as a DEX overlay/container such as fdex or extracted-method placeholders indicate this variant; runtime confirmation and native parameters are findings of this workflow, not prerequisites. Triage the container, replay a bounded native decrypt routine with unidbg when useful, rebuild verified DEX files, and check core business logic. Classify remaining JNI bridges separately; do not assume VMP.
---

# 二代动态抽取型 DEX 脱壳 / Second-Generation Extracted DEX Unpacking

Use this Skill once static container evidence or per-method runtime refill makes extraction likely. **Do not wait for a whole-process DEX dump, recovered key, exact JNI RVA, or confirmed generation before entering.** Those are possible findings, not entrance conditions. Unidbg is one way to replay a bounded native loader/decrypt routine; its output becomes an unpacked DEX only after method mapping, reconstruction, and independent validation. Follow [the extracted DEX replay guide](references/extracted-dex.md) ([中文](references/extracted-dex.zh-CN.md)) for the full workflow.

## Inputs

To start, require only the original APK and its hash plus the evidence that suggests method extraction (for example `fdex` overlay or sparse occupied method bodies). Record ABI/API, process name, load order, native entry, argument contract, process evidence, and environmental dependencies as they are established. Derive the loader boundary and every decrypt parameter anew for each APK; keep values in its sample workspace. Follow the integrated harness workflow below **when** using unidbg.

## Workflow

### 0. Triage The Container And Method Layout

Read the detector's `container_layout` and inspect the original APK/DEX. Run `python container_triage.py target.apk --report triage.json --extract-container original-classes.dex` to save the focused evidence and unmodified container. Determine where ordinary DEX data ends, whether the remaining bytes form a structured container, which methods are placeholders, and whether the intended output is whole DEX release or per-method restoration. For `fdex`, the static interior marker count and suggested payload offset are only candidates: the native parser and decrypted DEX lengths must prove segment boundaries. Prefer an offline reconstruction path when verified container bytes, native output, and method mapping suffice. Use `rev-dex-dumper` only for a named, bounded memory range or independent comparison when this analysis requires it; a generic full-process dump is not the completion criterion.

For the matched Bangcle `fdex` ordered-decoy variant, establish **offline prefixes first**, then rebuild from the original container. A device prefix is a diagnostic smoke test or independent comparison only; it cannot be the input to the deliverable reconstruction. Capture every mapping needed to establish the native data flow, including module RX/RW/BSS, `[anon:.bss]`, allocator mappings such as scudo, and relevant stack/TLS, instead of assuming a key resides beside the SO. The optional SM4 scanner searches the complete captured set by default and may prioritize scudo without excluding other regions.

`valid_data_end` means the DEX header's `data_off + data_size`; it is not the last parsed `map_list` byte. `container_triage.py --payload-after-marker` exposes the observed `dexdata0` record delta (default 12) as a hypothesis, not a format guarantee; confirm it with the current native parser.

### Choose The Recovery Boundary

Establish this APK's container layout, transform inputs/outputs, algorithm or native routine, and segment boundaries; establish a key/state source and encrypted extent when encryption is present. Prefer direct offline restoration when the transform and independent vector are verified; otherwise replay the narrow native routine with Unidbg or capture its output on device. **Neither Bangcle nor `fdex` proves SM4, ECB, a fixed key, a fixed prefix length, or a fixed segment count.**

| Evidence from this APK | Next step |
|---|---|
| Extracted method layout is plausible, but the transform is unknown | Locate the loader's input/output boundary and obtain a bounded native or device vector. Do not select a cipher adapter yet. |
| Algorithm, mode, state, and extent are independently verified | Implement or select a matching offline transform, then validate its complete output and method mapping. |
| Native transform is usable but its internals are impractical to reproduce | Replay the narrow function in Unidbg, or collect the exact output range on device, then rebuild. |
| New APK differs in container or placeholder structure | Derive new segment and method mappings; do not force the tested `fdex` rebuilder's assumptions. |

Before choosing **any** cipher adapter, distinguish three claims: a DEX magic hit is only a candidate; a published test vector validates the local cipher implementation, not the target APK; the APK's algorithm and mode require independent full-block input/output comparisons or identifiable native operations, followed by multi-position output validation. Repeated plaintext yielding repeated ciphertext supports ECB but cannot establish it alone; no repeated blocks means that particular check is unavailable. Record the evidence and its limits in the sample workspace.

When the shell family is known, consult the [extracted-shell profiles](shell-profiles/README.md) for previously observed container, key-search, and decrypt workflows. A profile supplies hypotheses to test against this APK; it never fixes the algorithm or parameters for a family.

Only for a sample proven to use standard SM4-ECB on an `fdex` prefix, the optional [SM4/fdex adapter](references/sm4-fdex-adapter.md) ([中文](references/sm4-fdex-adapter.zh-CN.md)) supplies `sm4_key_scan.py` and `decrypt_prefixes.py`. Its failure does not change the shell generation classification; investigate the actual native transform instead. Keep key material outside tracked Skill files and pass verified plaintext to `$rev-dex-rebuild` with `--prefix-source offline`. A `--truth-prefix` mismatch may be diagnosed as equal-width `class_data` `code_off` edits, but the final rebuilt DEX still needs independent whole-file validation.

The remaining Unidbg steps apply only when replay is needed to establish or execute the current sample's native transform.

### 1. Pin The Replay Environment (If Using Unidbg)

Record unidbg commit/release, JDK, backend, host OS, resolver API, target hashes, and harness commit. Confirm APIs against the selected upstream source and tests.

### 2. Build The Minimal Harness

Create the matching emulator, process name, resolver and Dalvik VM. Install target-specific JNI behavior, load only required libraries, and call `JNI_OnLoad` only when the real app does. Prefer APK-backed loading when resources, signatures, classes, or package metadata matter.

### 3. Fill Dependencies From Evidence

Use `$rev-jni-env` when more than trivial dependencies are missing. For every failure, record the missing contract, obtain its value from app code/device evidence/documentation, add the smallest deterministic implementation, and rerun the same input. Never use catch-all success stubs.

### 4. Invoke And Observe Narrowly

Call one exact JNI descriptor, export, or verified RVA. Allocate emulated buffers correctly and capture output before closing. Start with function/block hooks and targeted loader buffers. Instruction traces must be restricted to a small module/RVA range.

At the native boundary, answer a narrow question such as:

- which native routine decrypts/copies the DEX region;
- which buffer pointer and length reach the loader;
- which environment value selects an alternate anti-instrumentation path;
- whether the candidate plaintext is transient or persistent in the emulated path.

The extracted DEX replay guide separates container parsing, native decryption, method restoration, and native bridge methods. Derive the payload location, native entry points, key source, encrypted extent, segment count, and layout from the current APK and process; keep these values in its work directory, never in the reusable workflow. Pass verified plaintext and exact method mappings to `$rev-dex-rebuild` for DEX reconstruction and business-logic acceptance.

The next step depends on evidence. If the requested core business logic is present in the validated DEX and no relevant native bridge remains, finish the extracted-DEX task. For remaining JNI dispatch bridges, use `$rev-java2c` to distinguish delayed Dalvik refill, ordinary native/JNI implementation, a private bytecode VM, or unresolved behavior for each method. A second-generation extraction shell does not imply VMP. Use `$rev-opcodes` only after observing a changing private instruction cursor, decode, and handler dispatch. Do not claim that emulation alone restored a JNI bridge's original Java semantics.

### 5. Make Replay Deterministic

Control or record time, random APIs, properties, files, network data, and thread inputs. Run two fresh baselines and investigate any changed output before differential probes.

### 6. Use MCP Only When Helpful

If a compatible local unidbg MCP is connected, use it for bounded register/memory inspection and repeatable tools. Keep a version-pinned Java harness as the reproducible artifact.

## Deliverables

Produce the original APK hash, container/segment evidence, any pinned harness/build command, environment inventory and provenance, invocation contract, scoped trace/dump manifest, baseline comparison, extracted loader facts, unresolved dependencies, reconstructed DEX files, method mapping, structural checks, and core-business review. Keep the raw native output and the final DEX in separate artifacts.

For the user-facing `<apk-name>-unpacked/` result, include a separate JNI-bridge method list (descriptor, dispatch ID when known, and recovery status). Follow at least two sample-relevant core business chains when available; for each, show method descriptors, original placeholder and restored `code_off`, a readable decision/effect in Smali or JADX, and any bridge that still hides behavior. If only one chain is accessible or a core method remains native, state the gap explicitly. Where executable test vectors exist, compare returns, exceptions, field changes, and calls against the protected run. Whole-file equality with a device snapshot proves equivalence to that observed state, not that no later runtime mutation occurs.

## Completion Criteria

- The actual transform or native replay contract, segment and method boundaries, and any applicable cipher mode, key/state source, and encrypted extent are established for this sample; output matches independent vectors where available.
- Two fresh baselines produce identical relevant output when using a stateful Unidbg harness; offline output hashes are reproducible.
- Every simulated dependency, when simulation is used, has evidence or remains explicitly pending.
- Traces and memory captures are bounded and hashed.
- Every final DEX disassembles with Baksmali; method mappings and the app's main/core business paths are checked in JADX and Smali before claiming extracted-method unpacking complete.
- Original APK/SO files remain unchanged.

---

## Integrated Reference: unidbg Harness Workflow

## Contents

1. Version and project discovery
2. Harness construction
3. JNI and environment completion
4. Invocation and observation
5. Debugger and MCP options
6. Failure classification

The official project is [zhkl0228/unidbg](https://github.com/zhkl0228/unidbg). Its current README documents Android native-library emulation, JNI/JavaVM, ARM32/ARM64, syscall emulation, multiple backends, hooks, debugger traces, and optional MCP. Verify every concrete API against the pinned source revision.

## 1. Version And Project Discovery

Before generating code:

- Inspect `pom.xml` and module layout.
- Search `unidbg-android/src/test` for the nearest maintained example.
- Record the exact Git commit or release.
- Select a backend supported by the host and the observation features required.
- Do not mix code snippets from different unidbg versions.

Use Maven Wrapper from the pinned checkout when possible. Keep target artifacts outside the unidbg source tree or under a clearly isolated test-resource directory.

## 2. Harness Construction

A typical Android harness has these responsibilities, in this order:

1. Build a 32-bit or 64-bit `AndroidEmulator` with the intended process name.
2. Configure a backend explicitly when backend-specific trace/debug behavior matters.
3. Set an `AndroidResolver` matching the target's expected API level.
4. Create a Dalvik VM from an APK when package/class/resource fidelity matters, or without an APK for a deliberate standalone-SO model.
5. Extend/install `AbstractJni` for only the Java behavior the target calls.
6. Load the library with its dependency policy.
7. Invoke `JNI_OnLoad` if it is part of the real load path.
8. Resolve the JNI class/object or native symbol.
9. Invoke with exact descriptors and emulated-memory arguments.
10. Close the emulator in all paths.

Treat this as a structure, not copy-paste code. Constructor and method names may change between versions.

## 3. JNI And Environment Completion

Use `vm.setVerbose(true)` temporarily to discover missing JNI behavior, then turn it down once the contract is known. Implement methods by exact class, name, descriptor, static/instance context, and return type.

For every stub, record one provenance category:

- Captured from an authorized real execution.
- Derived from the app's Java/Kotlin code or resources.
- Defined by Android/JNI documentation.
- Synthetic test value used only for a named experiment.

Reject unknown methods by default. A permissive fallback such as “return zero for everything” can make the library appear to work while selecting a path the real app never takes.

Model files and properties with the same discipline. Map only required paths, preserve expected byte content and metadata, and record any substitution.

## 4. Invocation And Observation

For JNI calls, preserve the exact descriptor, including array and object types. Confirm whether the method is static or instance-bound. For exports/RVAs, confirm calling convention, pointer width, module base, and relocation.

Allocate byte arrays, strings, structures, and output buffers in the emulated domain. Read results before releasing objects or closing the emulator.

Observation order:

1. Entry/exit and return value.
2. Calls and basic blocks in the target module.
3. Targeted memory reads/writes.
4. Narrow instruction trace when earlier levels are insufficient to establish the loader's input/output boundary.

## 5. Debugger And MCP Options

The official project supports a console debugger and, in recent revisions, a local MCP mode. MCP can expose module/symbol discovery, registers, memory, breakpoints, stepping, trace, and function calls. Custom MCP tools can make repeated target invocations available without reloading the library.

Use MCP for interactive evidence gathering when the pinned build supports it. Keep the Java harness and recorded test vectors as the durable, reviewable reproduction path. Do not assume an MCP URL, port, or tool schema without checking the running server.

## 6. Failure Classification

| Failure | Likely cause | Next action |
|---|---|---|
| Library not found | Wrong ABI/path or unresolved dependency | Inspect APK ABI and loader dependency list |
| `JNI_OnLoad` fails | Missing class/method, wrong VM state, anti-emulation | Enable narrow JNI logs and implement the first missing contract |
| JNI call returns wrong type | Descriptor/static-instance mismatch | Compare exact Java declaration and JNI signature |
| Invalid memory access | Wrong RVA/base, bad pointer lifetime, missing mapping | Normalize addresses and inspect the last valid call/memory event |
| Infinite loop | Environment check, persistent breakpoint, unsupported thread behavior | Add bounded block trace and stop threshold; do not blindly skip |
| Output changes each run | Uncontrolled time/random/file/thread input | Inventory entropy and rebuild fresh deterministic runs |
| Trace is too large | Scope includes loader/system libraries or whole process | Restrict module/RVA and aggregate before analysis |
