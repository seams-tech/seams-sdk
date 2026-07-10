# FV1 Proof Obligations

Status values are `checked`, `executable-evidence`, and `pending`.

| ID           | Obligation                                                                                 | Owner            | Current evidence                                                                      | Status              |
| ------------ | ------------------------------------------------------------------------------------------ | ---------------- | ------------------------------------------------------------------------------------- | ------------------- |
| YAO-ID-001   | Activation and export family bytes differ                                                  | `ed25519-yao`    | Verus `family_bytes_are_distinct`; anti-drift constants                               | checked             |
| YAO-MAN-001  | A family manifest has six artifact digest roles plus one output-schema role                | `ed25519-yao`    | Verus `manifest_binds_seven_digest_slots`; constructor anti-drift                     | checked             |
| YAO-MAN-002  | A family manifest carries twelve scalar metrics                                            | `ed25519-yao`    | Verus `manifest_binds_twelve_metrics`; accessor anti-drift                            | checked             |
| YAO-MET-001  | A valid declared gate total equals AND + XOR + inversion counts                            | `ed25519-yao`    | Verus `valid_gate_total_matches_sum`; runtime and rejection parity                    | checked             |
| YAO-REF-001  | The mirror RFC 8032 clamp agrees with the generator boundary                               | generator        | Four-case executable anti-drift plus Aeneas extraction                                | executable-evidence |
| YAO-REF-002  | The mirror wrapping addition agrees with the generator boundary                            | generator        | Four-case executable anti-drift plus Aeneas extraction                                | executable-evidence |
| YAO-CTX-001  | Stable-context validation, ordering, encoding, and binding match the frozen vectors        | generator        | Three context tests, corpus check, and formal anti-drift                              | executable-evidence |
| YAO-KDF-001  | Eight role/source/output-separated KDF values match the frozen context and joined identity | generator        | Committed KDF corpus, continuity tests, independent Python HKDF/oracle reproduction   | executable-evidence |
| YAO-LIFE-001 | Five lifecycle branches have disjoint pre-state/success/output-custody boundary contracts  | specification    | Evidence matrix and export-only Rust fixture shape; blocked transitions remain absent | pending             |
| YAO-MAN-003  | Canonical manifest field order and length match production byte for byte                   | `ed25519-yao`    | Golden Rust digest exists; proof-facing encoder absent                                | pending             |
| YAO-REF-003  | Independent implementations reproduce the complete clear-arithmetic vector corpus          | generator        | Five committed and 128 deterministic differential cases pass Rust and stdlib Python   | executable-evidence |
| YAO-SEC-001  | Activation and export refine their ideal functionalities                                   | circuit/compiler | No circuit or frozen functionality exists                                             | pending             |

`checked` applies only to the exact local statement. It does not imply circuit
correctness, privacy, active security, or a production release claim.
