---
name: rev-vm-coverage
description: Measure and close coverage gaps in authorized native VMP analysis. Use when Codex must merge Frida, unidbg, Unicorn, or debugger dispatch traces; determine which protected methods, VM instruction sites, virtual edges, branch outcomes, terminal paths, handlers, opcodes, and input classes were exercised; prioritize new probes; or decide whether a claimed opcode table or recovered method is complete for a stated scope.
---

# VMP Coverage

Use coverage to answer "what remains unobserved?" It is optional analysis support, not a prerequisite for starting VMP work or calling another Skill.

## Define The Expected Universe

Coverage needs a denominator. Derive targets from whichever structural evidence is reliable:

- protected method metadata or JNI wrapper inventory;
- fully decoded bytecode instruction boundaries and branch operands;
- raw handler-table slots, including aliases and invalid/default slots;
- unique semantic handlers and recovered opcodes;
- virtual fallthrough/branch edges and terminal sites.

Keep unknown fields unknown. If only current traces are available, report observational coverage; do not call it complete.

## Normalize And Merge

Use one record per complete virtual instruction slice, from post-fetch through any outer CFF blocks to the next pre-fetch or terminal. Preserve run/input ID, method, VM PC before/after, raw opcode slot, semantic handler RVA, branch outcome, terminal status, and environment failure. Normalize native addresses to module RVAs and VM PCs to bytecode-relative offsets.

Do not merge native CFF states into VM opcode coverage until `$rev-opcodes` has proven the bytecode fetch/decode relationship.

Measure separately:

- planned versus reached protected methods;
- expected versus observed VM sites and edges;
- both outcomes of conditional branches;
- normal return, throw, abort, and other terminal paths;
- expected versus observed raw opcode slots, unique handlers, aliases, and default slots;
- input classes and environment-dependent paths.

## Classify Every Gap

- `not_probed`: no input has targeted the path.
- `environment_blocked`: an unresolved JNI, file, service, anti-emulation, or device dependency stopped execution.
- `structurally_missing`: structural evidence expects the item, but valid probes have not reached it.
- `infeasible`: a symbolic/static argument and concrete probes support that the edge cannot occur within the stated scope.

Do not silently drop crashes, exceptions, or non-returning handlers. They are coverage evidence.

## Choose The Next Probe

Prioritize information gain:

1. protected methods never entered;
2. branches with only one observed outcome;
3. exception, early-return, and terminal paths;
4. opcodes seen in only one input or method;
5. loop zero/one/max boundaries and switch targets;
6. environment blockers that affect several paths.

Vary one factor at a time: nullability, booleans, zero/one/boundary integers, lengths, valid/invalid indexes, object subtype, API level, property/file presence, or captured service response. Stop random probing after a stable plateau and use predicate-directed, symbolic, static, or real-device evidence.

## Completion Rule

Claim completion only for an explicit scope such as one protected wrapper or one bytecode method. Every valid bytecode site must decode without desynchronization; every expected feasible edge, branch outcome, terminal, raw slot, and handler must be observed or carry a defensible infeasibility proof. Account for invalid/default table slots separately. Keep unknown universes and environment blockers visible.

Coverage does not prove semantic correctness. Pair it with the opcode/handler evidence and independent replay required by `$rev-opcodes`.

## Deliverables

Produce the target universe and provenance, per-run normalized trace summary, per-method coverage and gaps, coverage delta by input, prioritized probe list, environment blockers, and the exact scope that is complete or still observational.
