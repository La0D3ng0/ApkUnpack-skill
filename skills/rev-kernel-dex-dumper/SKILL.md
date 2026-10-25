---
name: rev-kernel-dex-dumper
description: Plan and validate authorized kernel-assisted Android DEX acquisition using a source-built Akane injector and a target-specific JDex2-derived class-loading payload. Use when first- or second-generation extraction shells detect Frida, LSPosed, or ptrace; when a rooted GKI 2.0 Android 12+ lab device can inject a native payload; or when Codex must design a scoped ClassLoader/ART hook, active class invocation, concealment profile, evidence manifest, and exact cleanup. Do not use on unsupported kernels, production devices, unpinned binaries, or for covert persistence.
---

# Kernel-Assisted DEX Dumper

Use Akane as the injection transport and adapt JDex2's class filtering/active-invocation model into an injectable payload. Akane injects native `.so` files; JDex2 is an Xposed/LSPosed application, so direct injection is not possible without an adapter.

## Required References

Use the integrated upstream, adapter, and kernel-plan contracts below before fetching or changing either source. Use the pinned upstream identities in [tool-lock.json](tool-lock.json).

## Workflow

### 1. Prove Device Compatibility

Require an explicitly authorized disposable/rooted device, Android 12+, GKI 2.0, kernel 5.10+, and a supported ABI. Record `uname -r`, Android version/API, ABI, boot image/build fingerprint, SELinux state, root mechanism, and whether module loading is permitted.

Create `kernel-plan.json` from the integrated contract and validate it before building or touching the device:

```bash
python validate_kernel_plan.py kernel-plan.json -o kernel-plan-validation.json --strict
```

An unsupported kernel must fail closed. Do not attempt a same-kernel "best guess" module.

### 2. Fetch And Build From Pinned Source

Fetch the exact commits in `tool-lock.json` into a case-local source directory. Record Git object IDs and source-tree hashes. Build Akane with its documented Docker/DDK and Android NDK requirements; do not download or commit an opaque prebuilt kernel module.

Both upstream repositories lacked detected license metadata at the recorded commits. Keep modifications case-local and non-redistributed until licensing or maintainer permission is resolved.

### 3. Build The JDex2 Adapter

Do not copy the Xposed entrypoint into a native payload. Separate these concerns:

- class-prefix filtering, blacklist, inner-class policy, and active invocation;
- ClassLoader/DexFile observation for the exact Android/libart version;
- native Akane payload bootstrap and JavaVM/JNI attachment;
- companion DEX loading or a versioned native ART adapter;
- raw DEX/code-item output and structured event logging.

Scope hooks to the target package and chosen ClassLoader. Never hook all processes or invoke all classes without filters.

### 4. Select A Concealment Profile

Akane already exposes VMA naming, memory-access masking, and path/module/port hiding. Do not add a second unknown "hidden kernel module." Keep concealment off for the first control run. If the shell blocks acquisition and the user authorized a comparison, enable only the minimum named features in the validated plan.

Concealment must not create persistence, survive reboot, alter unrelated processes, or hide artifacts after the case. Record the clean-versus-concealed behavior difference; hidden instrumentation is still instrumentation.

### 5. Inject And Observe

Deploy only validated case artifacts under `/data/local/tmp/`. Start the target from a fresh process, obtain the exact PID, and use the source-built Akane command form documented upstream to inject the adapter `.so`. The payload must:

1. attach safely to the target JavaVM;
2. observe ClassLoader/DexFile events for the configured package/classes;
3. dump each independently identified DEX region with address/size/provenance;
4. actively invoke only allowed classes when extraction requires it;
5. write bounded JSONL events and raw artifacts to the exact case output path.

Do not claim "hook ClassLoader and done": custom loaders, in-memory DEX, method-granularity extraction, re-encryption, and libart drift require explicit adapters and validation.

### 6. Validate And Clean Up

Pull and hash all output before cleanup. Pass candidates to `$rev-dex-rebuild` for structural/content validation and verified partial repair; do not re-enter a user-space memory-dump loop. Compare a clean run, user-space attempt, and kernel-assisted attempt where feasible.

Unload Akane, stop the target, remove exact case paths, and verify `/dev/akane`, injected mappings, hidden-path rules, module state, and output paths are gone. Reboot the disposable device if unload or restoration cannot be proven.

## Deliverables

Produce the validated kernel plan, tool/source/build hashes, adapter source diff, compatibility report, concealment/control matrix, injection/event manifests, raw DEX inventory, validation reports, and exact unload/cleanup evidence.

## Completion Criteria

- Device/kernel/ABI compatibility passes the strict validator.
- Akane and JDex2 source identities match the lock; no opaque binary is trusted.
- The native-versus-Xposed adapter boundary is implemented explicitly.
- Hooks and active invocation are scoped by package/ClassLoader/class prefix.
- Any concealment is minimal, explicitly authorized, compared with a control, and fully removed.
- Accepted DEX files pass independent structural and content validation.
- No persistence or unrelated process instrumentation is introduced.

---

## Integrated Reference: Upstream Tool Notes

Information was verified against the upstream repositories on 2026-08-14. Re-check before every fetch because interfaces and kernel support can change.

## Akane Injector

Upstream: https://github.com/aimardcr/akane-injector  
Pinned commit: `8a80056e7ec80932d8896ac20bb0c7ab19408ffc`

Upstream describes a kernel-assisted shared-library injector that avoids ptrace and maps a native payload into a target. Its components include `akane.ko`, a controller, `libakane-runtime.so`, bootstrap code, and an ELF loader. The module exposes target-memory operations, VMA naming/masking, path/module/port hiding, and task-work redirection.

Recorded requirements:

- Android 12-16;
- GKI 2.0;
- kernel 5.10, 5.15, 6.1, 6.6, or 6.12 branches documented upstream;
- `arm64-v8a` by default and optional `armeabi-v7a`;
- rooted device/emulator with module loading;
- Docker/DDK for modules and Android NDK r26 for injector components.

The upstream quickstart uses `make`, `scripts/deploy.sh`, and `scripts/run.sh -p <pid> -s <payload.so>`. Verify these commands at the pinned commit instead of copying them from memory.

Android 11/kernel 5.4 and pre-GKI kernels are not generic-module targets; they require exact per-device kernel builds and are rejected by this Skill's generic route.

## JDex2

Upstream: https://github.com/J5now/JDex2  
Pinned commit: `4d869c8f9d47780d73dcddeb8c5da4ac84452e52`

JDex2 is an Xposed/LSPosed active-invocation unpacker for class-level extraction shells. It provides target class filters, blacklists, inner-class control, constructor invocation, lazy dumping, and debugger logging. Upstream writes results under the target app's external-files `dumpDex` directory.

Recorded limitations:

- class-granularity extraction only;
- cannot fully handle method-granularity extraction, post-execution re-extraction, or bytecode decrypted only at execution;
- targets Android 9+; Android 7 and below are unsupported and Android 8 is uncertain;
- active invocation can crash on unavailable platform superclass/API combinations;
- JNI global references can exceed the documented 51,200 limit;
- behavior depends heavily on LSPosed concealment.

## Licensing Boundary

GitHub metadata and repository roots showed no `LICENSE`/`COPYING` file for either pinned source. `NOASSERTION` does not mean public-domain or unrestricted. Do not vendor, publish, or distribute modified code/binaries without confirmed permission or a later explicit license. Record any subsequent license discovery in a new lock revision.

---

## Integrated Reference: JDex2-To-Akane Adapter Contract

## Why An Adapter Is Required

Akane injects native ELF shared libraries. JDex2 expects Xposed/LSPosed Java hooks and configuration. A working combined tool needs a new native bootstrap plus either a companion DEX/JNI bridge or a versioned native ART adapter.

## Required Layers

### Native Bootstrap

- Build `libjdex2-akane.so` for the target ABI.
- Receive package, class filter, blacklist, output path, and adapter version through a bounded configuration blob.
- Locate/attach to the existing JavaVM without starting another runtime.
- Avoid constructors or background work before target identity is verified.

### ClassLoader Adapter

Implement one explicit adapter per Android/libart family. Record symbol/build fingerprints and reject unknown layouts. Observe the target's actual ClassLoader/DexFile relationship, including in-memory loaders; do not assume only `PathClassLoader`.

### Active Invocation Engine

Port or reimplement the JDex2 behavior behind a stable interface:

```text
enumerate(class_loader, class_prefix) -> class descriptors
filter(descriptor, blacklist, inner_class_policy) -> allow/deny
invoke(descriptor, constructor_policy) -> result/exception
dump(dex_identity, address, size, reason) -> raw artifact
```

Bound class count, invocation rate, JNI global references, exceptions, and wall time. Persist a completed-class checkpoint so a crash does not require repeating proven classes.

### Output Contract

Emit JSONL events with `run_id`, monotonic timestamp, package, pid, adapter ID, ClassLoader identity, class descriptor, action, result, dex address/size/hash, and error. Raw artifacts must be immutable after hashing. Repaired DEX files go to a separate directory.

## Concealment Contract

Default to no concealment. If enabled, list exact Akane capabilities such as VMA rename, `HIDE_FROM_MEMORY`, path hide, or module hide. Each feature needs target-specific evidence, an explicit authorization flag, a control run, and a restoration check. Do not add boot scripts, auto-load services, network listeners, or persistence.

## Success Boundary

ClassLoader observation proves loading, not full code recovery. Active invocation can materialize class-level extraction but does not solve bytecode decrypted only during execution. Mark missing method code as partial and hand it to normal DEX validation/rebuild reporting. Stop when no supported acquisition surface can be proven.

---

## Integrated Reference: Kernel Plan Contract

`rev-kernel-dex-dumper/plan-v1` requires:

```json
{
  "schema": "rev-kernel-dex-dumper/plan-v1",
  "authorization": {"authorized": true, "scope": "lab package/build"},
  "device": {
    "android_version": 14,
    "kernel_release": "6.1.75-android14-11",
    "gki_generation": "2.0",
    "abi": "arm64-v8a",
    "root": true,
    "disposable": true
  },
  "tools": {
    "akane-injector": {"commit": "..."},
    "jdex2": {"commit": "..."}
  },
  "adapter": {
    "mode": "companion_dex_jni_bridge",
    "source_fork_commit": "40-hex local commit",
    "package": "com.example",
    "class_prefix": "com.example.business",
    "output_dir": "/data/local/tmp/rev-kernel-dex/case-id"
  },
  "license_review": {"redistribute": false, "basis": "case-local research only"},
  "concealment": {
    "enabled": false,
    "explicitly_authorized": false,
    "features": []
  },
  "cleanup": {
    "unload_module": true,
    "remove_exact_output": true,
    "verify_no_device_node": true,
    "reboot_on_unproven_restore": true
  }
}
```

Use `native_art_adapter` only when the exact libart build/symbol contract is recorded. Concealment features accepted by the validator are `vma_name`, `hide_from_memory`, `hide_path`, and `hide_module`; validity does not prove a feature is necessary.
