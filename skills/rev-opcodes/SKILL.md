---
name: rev-opcodes
description: Recover and fully devirtualize custom native VMP code in authorized Android SO files. Use IDA-NO-MCP exports exclusively for IDA data because VMP/CFF functions are too large for IDA MCP, capture bounded raw instruction-level traces, distinguish an inner bytecode VM from outer OLLVM/CFF, recover opcode and operand semantics, extract bytecode, build an independent emulator, prove path coverage, or lift one protected JNI wrapper or bytecode method into equivalent native, Python, C, smali, or DEX logic.
---

# Native VMP Devirtualization

Recover a virtual program and an independently testable implementation, not merely a native dispatcher trace. Keep facts, hypotheses, and disproved hypotheses separate. Normalize native addresses to `module + RVA`.

## 1. Fix The Scope

Default to one JNI wrapper or one protected bytecode method. Record its inputs, outputs, Java field writes, buffers, exceptions, JNI calls, and terminal behavior before tracing internals.

Claim whole-SO devirtualization only after inventorying every protected entry and proving the opcode, bytecode, path, and environment universes for all of them. One recovered wrapper never proves a whole library complete.

## 2. Build The Static Corpus With IDA-NO-MCP

For VMP or large flattened functions, use an IDA-NO-MCP batch export as the only IDA evidence interface. Do not call IDA MCP at any stage of this scope: interactive decompilation, xref, disassembly, or bounded follow-up queries still risk filling the model context with huge functions.

Record the input SO hash and export root, then search `decompile/`, `decompile_failed.txt`, `decompile_skipped.txt`, `strings.txt`, `imports.txt`, `exports.txt`, and relevant `memory/` chunks. Read only the files needed for the current subproblem. If the export is absent, create or request it with [IDA-NO-MCP](https://github.com/P4nda0s/IDA-NO-MCP) before static VMP recovery; do not fall back to IDA MCP.

## 3. Prove The Inner VM

For a method arriving from `$rev-java2c`, a JNI bridge or numeric dispatch ID only identifies the native entry. Establish the interpreter below before using VMP recovery steps.

Require this dataflow:

1. A changing VM PC reads instruction bytes or words.
2. Decode logic derives an opcode and operands.
3. The decoded value selects a stable handler or semantic path.
4. The handler updates VM state and eventually reaches the next fetch or a terminal.

Treat a state variable and jump table without a bytecode fetch as native CFF. An inner handler may set an outer CFF state and execute many flattened blocks before returning to the VM fetch; do not mistake that outer state for an opcode.

Discover RVAs, stack slots, and register roles for each build. Do not copy sample addresses or register names into a reusable capture script.

## 4. Establish Deterministic Replay

Record APK/SO hashes, ABI, wrapper, arguments, module base, and environment. Fix or record time, randomness, files, properties, network responses, thread inputs, and JNI return values. Require two fresh runs with the same relevant VM-PC/opcode sequence and externally visible result before comparing cases.

Use unidbg when JNI or Android state is needed, Unicorn for an isolated CPU-only interpreter, and Frida or a debugger when real-device state or anti-emulation behavior matters.

## 5. Locate The Capture Boundary And Preserve The Raw Trace

Find four behavioral landmarks rather than fixed instructions:

- bytecode base or initial cursor assignment;
- pre-fetch VM PC;
- post-fetch VM PC and raw opcode;
- indirect handler transfer.

Block/call traces and hotspot counts only locate the interpreter range. Before assigning opcode semantics, persist a bounded raw trace containing one event for every executed native instruction in the fetch/handler range. Each event must include `run_id`, monotonically increasing sequence, thread ID, module hash/base, PC/RVA, instruction bytes, mnemonic/operands, and a taken branch target when present. At the four landmarks also snapshot the selected registers, stack, VM-PC bytes, and relevant memory.

Preserve the raw trace file, its SHA-256, exact RVA filter, input case, and environment. Derive dispatch rows from that trace: `run_id`, wrapper/case, VM PC before/after, raw bytes, raw opcode, handler RVA, selected state changes, memory reads/writes, and next fetch, return, throw, or abort. A hotspot report, basic-block list, console excerpt, or opcode summary never replaces the ordered instruction log.

If the log is too large, narrow the module/RVA range or input case and process the saved file with search and statistics. Do not omit the instruction sequence or load a million-line trace into model context.

Define one virtual instruction as the complete execution slice from the post-fetch state through every outer CFF block to the next pre-fetch state or terminal. A short handler entry that only assigns a CFF state is not the instruction semantics.

## 6. Run A Discriminating Case Matrix

Vary one factor at a time across normal, null, empty, zero, one, sign boundary, length boundary, invalid type/index, branch-flipping, and exception cases relevant to the wrapper. Preserve failures as evidence.

Compare at least two cases before assigning a VM role. Verify candidates such as VM context, virtual stack/register bank, current object/value, output cursor, and VM PC through correlated changes and memory aliases; never name a role from one snapshot.

## 7. Recover Operands And Semantics

Dump bytes around the pre-fetch cursor and follow every subsequent bytecode read inside the full instruction slice. Infer instruction length, immediate width, signedness, endianness, register indexes, and relative or absolute branch targets. Confirm that decoding one instruction lands exactly on the next observed VM PC.

Separate raw opcode slots, unique handler entries, aliases, and invalid/default slots. For each valid opcode record:

```text
raw opcode | operand format | instruction length | handler RVA | VM-PC delta
stack/register effect | memory/JNI side effect | branch behavior
validation cases | confidence
```

Use discriminating values to separate ADD from XOR, operand order, widths, comparisons, shifts, and sign extension. Keep unresolved alternatives explicit.

## 8. Remove Outer CFF Per Instruction

Send only one instruction slice or a small shared handler region to `$rev-symbol`. Seed bounded angr exploration from a concrete pre-state and use concrete traces as observed edges. Explore unresolved predicates within the slice; cap addresses, states, steps, and time.

Merge observed, symbolically feasible, statically inferred, infeasible, and unresolved edges. Validate live-out registers, flags, memory, next VM PC, and terminal effects. Do not run unconstrained symbolic execution over the whole flattened wrapper.

## 9. Recover Bytecode And Build Independent Tools

Dump each wrapper's bytecode and VM data before mutation. Record base, logical length, hash, relocation/decryption state, and source run. Build a target-specific disassembler that handles variable-length operands and stops visibly on unknown or truncated data without losing synchronization.

Implement an independent emulator outside the protected process:

```python
while state.running:
    opcode = bytecode[state.pc]
    state.pc += 1
    state.pc = handlers[opcode](state, bytecode, state.pc)
```

Compare the emulator with unidbg or the device after every virtual instruction: VM PC, virtual registers/stack, relevant memory, JNI calls, exceptions, and final outputs. Keep target-specific disassemblers and emulators with the analysis artifacts; do not add them to this generic Skill unless they generalize across samples.

## 10. Prove Coverage And Equivalence

Derive the opcode universe from the handler table, the instruction-site and edge universe from complete bytecode decoding, and the method universe from wrapper metadata. Use `$rev-vm-coverage` to expose missing sites, branch outcomes, terminals, raw slots, handlers, inputs, and environment blockers.

Call the scoped method fully devirtualized only when:

1. every claimed virtual instruction can be reconstructed from a hashed raw native instruction trace;
2. every valid bytecode site decodes without desynchronization;
3. every feasible virtual edge, branch outcome, and terminal is replayed or has a defensible infeasibility proof;
4. every reachable opcode has evidence-backed operands and state effects;
5. the independent emulator matches intermediate state and final side effects across normal, boundary, null, and exceptional cases;
6. no unresolved environment dependency can alter the claimed paths.

## 11. Choose The Final Representation

If VMP replaced a Java method with a JNI wrapper, lift verified logic to smali/DEX and then use `$rev-dex-rebuild`. If it protects a native algorithm, produce a readable native/Python/C implementation or replace a copy of the SO. Repack and sign only after equivalence validation.

## Stop And Pivot

- Narrow unbounded traces to the fetch/handler region and aggregate hot blocks.
- Return to `$rev-symbol` when no changing bytecode fetch exists.
- Use `$rev-jni-env` when a concrete environment dependency blocks execution; do not invent catch-all stubs.
- Switch from random probes to predicate-directed inputs or static table/bytecode analysis after a stable coverage plateau.
- Preserve unknown or polymorphic handlers instead of forcing a mnemonic.

## Deliverables

Produce the scope contract, IDA-NO-MCP corpus identity, deterministic replay record, raw per-instruction trace files and hashes, VM role map, raw-slot and handler table, bytecode/data hashes, instruction table, disassembly, virtual CFG, bounded CFF recovery evidence, coverage gaps, independent emulator, equivalence results, and chosen lifted output. State exactly which wrapper, inputs, paths, and opcodes are complete.
