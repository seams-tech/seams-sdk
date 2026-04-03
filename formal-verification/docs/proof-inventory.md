# Proof Inventory

Last updated: 2026-04-03

## Legend

- Status:
  - `planned`: target identified, proof not implemented
  - `in-progress`: theorem/proof is being implemented
  - `proven`: theorem is fully proven and checked in CI
- Source Class:
  - `Tier0-pinned-impl`: pinned `threshold-signatures` docs/code semantics
  - `Tier1-rfc`: RFC-level constraints
  - `Local-rust-spec`: local implementation semantics for signer-core or `ed25519-hss`

## Coverage Table

| Theorem ID        | Rust Function / Module                                                                                  | Property                                                              | Source Class      | Primary Source(s)                                                            | Status      |
| ----------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------- | ----------- |
| FV-BOOT-001       | `formal-verification/coq/Theories/Starter.v::z_add_sub_cancel`                                          | CI bootstrap theorem to validate proof toolchain path                 | Local-rust-spec   | Internal bootstrap theorem                                                   | in-progress |
| FV-SECP-2P-001    | `crates/signer-core/src/secp256k1.rs::map_additive_share_to_threshold_signatures_share_2p`              | Inverse-Lagrange mapping preserves additive share relation in 2P flow | Tier0-pinned-impl | `near/threshold-signatures` ot_based_ecdsa signing/triples docs (pinned rev) | planned     |
| FV-TX-ENC-001     | `crates/signer-core/src/eip1559.rs`                                                                     | EIP-1559 hash preimage and signed encoding determinism                | Local-rust-spec   | signer-core implementation + Ethereum typed tx encoding rules                | planned     |
| FV-TX-ENC-002     | `crates/signer-core/src/tempo_tx.rs`                                                                    | Tempo sender-hash and signed payload encoding determinism             | Local-rust-spec   | signer-core implementation semantics                                         | planned     |
| FV-ED25519-2P-001 | `crates/signer-core/src/near_threshold_frost.rs` and `crates/signer-core/src/near_threshold_ed25519.rs` | Group key reconstruction and participant-id invariants                | Tier1-rfc         | RFC 9591, RFC 8032                                                           | planned     |
| FV-HSS-FEXP-001   | `crates/ed25519-hss/src/reference.rs::eval_f_expand`                                                    | Clear `F_expand` output relation is correct and deterministic         | Local-rust-spec   | `ed25519-hss` `reference.rs` implementation semantics                        | planned     |
| FV-HSS-FEXP-002   | `crates/ed25519-hss/src/reference.rs::derive_output_shares` and `recover_a_from_base_shares`            | Base-share projection and recovery satisfy the stated algebra         | Local-rust-spec   | `ed25519-hss` `reference.rs` implementation semantics                        | planned     |
| FV-HSS-CAND-001   | `crates/ed25519-hss/src/candidate.rs::build_fixed_hidden_core_candidate`                                | Candidate digest and context binding are deterministic and normalized | Local-rust-spec   | `ed25519-hss` `candidate.rs` implementation semantics                        | planned     |
| FV-HSS-ART-001    | `crates/ed25519-hss/src/artifact/prime_order_encoder.rs`                                                | Artifact materialization is deterministic and section-layout stable   | Local-rust-spec   | `ed25519-hss` artifact encoder semantics                                     | planned     |
| FV-HSS-IR-001     | `crates/ed25519-hss/src/ddh/hidden_eval.rs::compile_prime_order_hidden_eval_program`                    | Hidden-eval IR deterministically covers the intended fixed-function stages | Local-rust-spec   | `ed25519-hss` hidden-eval compiler semantics                             | planned     |
| FV-HSS-CIR-001    | `crates/ed25519-hss/src/ddh/hidden_eval_executor.rs`                                                    | Compiled hidden evaluator is equivalent to `eval_f_expand` at the `FExpandOutput` boundary | Local-rust-spec   | `ed25519-hss` reference + executor semantics                  | planned     |

## Change Policy

- Any change to a function listed above requires updating this file in the same PR.
- `proven` status is only valid when CI runs `coqc`, `coqchk`, and corresponding vector parity checks.
