# FV1 Compliance Baseline

This baseline maps only implemented FV1 surfaces. It is not a protocol audit.

| Source requirement                                                           | Rust owner                                   | Verification owner                                                       | Alignment                                              |
| ---------------------------------------------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------ |
| Fixed activation/export identifiers and distinct family encodings            | `src/ids.rs`, `src/manifest.rs`              | Verus constants, family proof, anti-drift                                | full for implemented constants                         |
| Six typed artifact digests plus a family-specific output digest              | `src/digest.rs`, `src/manifest.rs`           | manifest shape proof, constructor anti-drift, tests                      | full for role/count shape                              |
| Twelve manifest metrics with validated gate totals                           | `src/metrics.rs`                             | metric/count proofs, accessor anti-drift, rejection tests                | full for current validation relation                   |
| Stable-context validation, canonical ordering, encoding, and SHA-256 binding | generator `src/context.rs`                   | golden, mutation-sensitive, and formal anti-drift tests                  | executable match; formal mirror pending                |
| Role/source/output-separated contribution KDF bound to stable context        | generator `src/kdf.rs`                       | committed KDF corpus, Rust continuity tests, independent Python verifier | executable cross-language match; formal mirror pending |
| Clear and deterministic differential vector arithmetic                       | generator `src/fixtures.rs`                  | independent stdlib Python verifier and mutation suite                    | executable cross-language match                        |
| Five disjoint lifecycle and output-custody boundary contracts                | generator `docs/ideal-functionalities-v1.md` | specification/code evidence matrix only                                  | partial; blocked transitions have no executable owner  |
| Clear wrapping addition modulo `2^256`                                       | generator `src/lib.rs`                       | executable mirror and Aeneas output                                      | partial; exhaustive equivalence proof pending          |
| RFC 8032 clamp helper                                                        | generator `src/lib.rs`                       | executable mirror and Aeneas output                                      | partial; general correspondence proof pending          |
| Deterministic canonical manifest preimage                                    | `src/manifest.rs`                            | golden Rust test                                                         | partial; proof-facing encoder pending                  |
| Fixed circuit functionality                                                  | absent                                       | absent                                                                   | missing by phase gate                                  |
| Streaming Yao and active security                                            | absent                                       | absent                                                                   | missing by phase gate                                  |

No formal file claims a match for an absent production surface. New code or
specification changes update this table, the proof-obligation list, and the
assumption ledger together.
