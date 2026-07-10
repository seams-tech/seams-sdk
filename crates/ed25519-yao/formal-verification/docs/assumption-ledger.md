# FV1 Assumption Ledger

This ledger names trusted boundaries used by current evidence. Cryptographic
protocol assumptions enter after the active suite and security games are
frozen.

| ID             | Boundary                                                                                | Affected obligations                                      | Evidence                                                                | Invalidation trigger                                  |
| -------------- | --------------------------------------------------------------------------------------- | --------------------------------------------------------- | ----------------------------------------------------------------------- | ----------------------------------------------------- |
| TCB-RUST-001   | Rust compiler and host execution preserve tested semantics                              | all executable checks                                     | locked Cargo dependency graphs and counted local gate                   | compiler/toolchain change                             |
| TCB-VERUS-001  | Verus `0.2026.04.03.21dfcd2` and pinned `vstd` check their stated logic faithfully      | `YAO-ID-001`, `YAO-MAN-001`, `YAO-MAN-002`, `YAO-MET-001` | task-runner version rejection and `verus/Cargo.lock`                    | Verus or `vstd` change                                |
| TCB-AENEAS-001 | Pinned Charon/Aeneas translate the selected Rust helper surface faithfully              | `YAO-REF-001`, `YAO-REF-002`                              | exact Git pins, transient LLBC, committed Lean, regeneration comparison | pin, flags, Rust surface, or generated output change  |
| TCB-AENEAS-002 | The pinned external Aeneas Lean library contains admitted slice and string declarations | current generated Lean build                              | Lake warnings name the affected external support modules                | Aeneas pin or dependency use changes                  |
| TCB-AENEAS-003 | Ambient opam resolution builds the pinned Aeneas sources consistently                   | current local extraction evidence                         | local green gate; empty-cache reproduction remains open                 | opam repository, OCaml, package, or build-host change |
| TCB-LEAN-001   | Lean `v4.28.0-rc1` checks the named targets faithfully                                  | current Lean theorems                                     | `lean-toolchain`, explicit targets, required `.olean` outputs           | Lean or dependency change                             |
| TCB-SHA256-001 | `sha2` implements SHA-256 for draft manifest identity                                   | `YAO-MAN-003`                                             | production golden digest test                                           | dependency, encoder, or algorithm change              |
| TCB-SHA256-002 | `sha2` implements SHA-256 for the stable-context binding                                | `YAO-CTX-001`                                             | frozen golden context binding                                           | dependency, encoding, or algorithm change             |
| TCB-CURVE-001  | `sha2`, `curve25519-dalek`, and `ed25519-dalek` implement oracle primitives correctly   | `YAO-REF-003`                                             | RFC 8032 and independent algebra tests                                  | dependency or primitive boundary change               |

The current project-owned Lean and Verus files contain no axioms or admitted
proofs. Generated Aeneas code imports the pinned external support library;
`TCB-AENEAS-001` and `TCB-AENEAS-002` keep that dependency explicit.

Operational, malicious-OT, garbling, active-compiler, output-authentication,
transport, erasure, and non-collusion assumptions are absent from current
theorems. They must be added before those surfaces or claims are introduced.
