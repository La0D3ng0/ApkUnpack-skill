---
name: rev-jni-env
description: Inventory, model, and validate evidence-based Android/JNI runtime dependencies for authorized native targets. Use when a unidbg harness stops on missing Java methods, fields, objects, files, properties, syscalls, services, entropy, or app state; when Codex must decide whether to stub, capture, proxy, or move a path to a real device; or when simulated and device behavior must be compared. Do not use catch-all JNI stubs or invent values without provenance.
---

# Android/JNI Environment Modeling

Build the smallest deterministic environment that preserves the target's observed behavior. Treat each modeled dependency as a testable contract, not a convenience stub.

## Inputs

Require the APK/SO hashes, ABI, package/process name, Android API level, load order, exact invocation, current harness, failure log, and at least one controlled input. Record whether a device trace is available.

Follow the integrated environment manifest contract below before creating the environment manifest.

## Workflow

### 1. Freeze The Baseline

Pin unidbg, JDK, backend, Android resolver, host OS, APK/SO, harness, and input hashes. Run in a fresh emulator instance and retain the first unsupported dependency with its native call site or VM PC.

### 2. Inventory One Dependency At A Time

For every missing JNI call, object, field, file, property, syscall, service, or entropy source:

1. Record the exact signature or resource name.
2. Record the caller RVA and tested method/input.
3. Obtain the real behavior from static code, a controlled device trace, captured app data, or authoritative platform behavior.
4. Classify it as `captured`, `modeled`, `proxied`, `pending`, or `unsupported`.
5. Add only the narrow implementation needed for that contract.

Never implement wildcard success, default every object to `null`, or swallow all field writes. Those shortcuts can make an invalid path appear complete.

### 3. Choose The Execution Source

- Keep deterministic value objects, pure Java helpers, stable properties, and fixed test files in unidbg.
- Capture hardware identifiers, keystore results, Binder/service behavior, anti-emulation probes, and app-session state from an authorized device.
- Proxy only when the transport, serialization, timeout, and failure behavior are recorded.
- Mark a path unsupported when faithful modeling would require unknown secrets or uncontrolled production services.

For an extracted-method DEX shell, use `$rev-gen2-extracted-dex-unpack` to implement the unidbg harness; use `$rev-frida` to collect real-device evidence. This skill owns the dependency contract and parity decision, not the low-level hook implementation.

### 4. Write The Environment Manifest

Create `environment-manifest.json` with target identity, dependency inventory, provenance, deterministic controls, baseline runs, and unresolved items. Validate it with:

```bash
python validate_env_manifest.py environment-manifest.json -o environment-validation.json
```

Use `--strict` only for a completion gate. Strict mode must fail while required dependencies are pending, unsupported, assumption-only, non-deterministic, or missing provenance.

### 5. Check Device/Emulator Parity

For the same input, compare return values, exceptions, field writes, JNI call sequence, relevant memory writes, and VM dispatch trace. Explain every accepted difference, such as normalized addresses or intentionally fixed entropy.

Do not accept "both returned successfully" as parity when side effects differ.

### 6. Prove Determinism

Run the simulated baseline twice in fresh instances. Hash normalized traces and outputs. Fix or record time, randomness, filesystem order, properties, network fixtures, and thread inputs until the hashes match.

### 7. Continue With The Relevant Experiment

Pass the validated environment manifest and invocation catalog to `$rev-gen2-extracted-dex-unpack` for extracted-method DEX work, or to another experiment chosen from the current evidence. Keep unresolved dependencies attached to the affected observation so an environment failure is not misclassified as shell behavior.

## Deliverables

Produce the version-pinned harness, environment manifest, validation report, provenance artifacts, parity matrix, deterministic replay hashes, and unresolved dependency ledger.

## Completion Criteria

- Every required dependency has exact scope, provenance, and deterministic behavior.
- No catch-all JNI/syscall/file stub is present.
- Two fresh simulated baselines match after normalization.
- Device parity passes for paths that depend on real state, or the limitation is explicit.
- Required manifest items pass `validate_env_manifest.py --strict`.
- Original APK/SO and device data remain unchanged.

---

## Integrated Reference: Environment Manifest Contract

Use JSON with `schema` set to `rev-jni-env/v1`.

## Required Shape

```json
{
  "schema": "rev-jni-env/v1",
  "target": {
    "apk_sha256": "...",
    "module": "libtarget.so",
    "module_sha256": "...",
    "abi": "arm64-v8a",
    "android_api": 23,
    "process_name": "com.example.app",
    "entrypoint": "Lcom/example/Bridge;->run([Ljava/lang/Object;)V"
  },
  "toolchain": {
    "unidbg": "commit-or-version",
    "jdk": "21",
    "backend": "unicorn2",
    "host_os": "windows"
  },
  "dependencies": [
    {
      "id": "jni-001",
      "kind": "jni_method",
      "name": "android/os/Build$VERSION->SDK_INT:I",
      "status": "modeled",
      "required": true,
      "deterministic": true,
      "provenance": {
        "type": "device_trace",
        "artifact": "trace/device-01.jsonl",
        "sha256": "..."
      },
      "behavior": {"returns": 23},
      "affected_methods": [10, 11]
    }
  ],
  "controls": {
    "time": "fixed",
    "random": "fixed",
    "filesystem": "fixture",
    "network": "disabled"
  },
  "baseline_runs": [
    {
      "run_id": "baseline-a",
      "input_sha256": "...",
      "output_sha256": "...",
      "normalized_trace_sha256": "...",
      "status": "returned"
    }
  ],
  "unresolved": []
}
```

## Allowed Values

- Dependency `kind`: `jni_method`, `jni_field`, `jni_object`, `file`, `property`, `syscall`, `service`, `entropy`, `network`, `library`, or `other`.
- Dependency `status`: `captured`, `modeled`, `proxied`, `pending`, or `unsupported`.
- Provenance `type`: `static`, `device_trace`, `captured_fixture`, `platform_contract`, or `assumption`.

Strict completion rejects required dependencies that are pending, unsupported, non-deterministic, missing provenance/hashes, or supported only by an assumption. At least two returned baseline runs must share identical input, output, and normalized-trace hashes.
