# Proof Inventory

Last updated: 2026-02-26

## Legend

- Status:
  - `planned`: target identified, proof not implemented
  - `in-progress`: theorem/proof is being implemented
  - `proven`: theorem is fully proven and checked in CI
- Source Class:
  - `Tier0-pinned-impl`: pinned `threshold-signatures` docs/code semantics
  - `Tier1-rfc`: RFC-level constraints
  - `Local-rust-spec`: local signer-core implementation semantics

## Coverage Table

| Theorem ID        | Rust Function / Module                                                                                  | Property                                                              | Source Class      | Primary Source(s)                                                            | Status      |
| ----------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------- | ----------------- | ---------------------------------------------------------------------------- | ----------- |
| FV-BOOT-001       | `formal-verification/coq/Theories/Starter.v::z_add_sub_cancel`                                          | CI bootstrap theorem to validate proof toolchain path                 | Local-rust-spec   | Internal bootstrap theorem                                                   | in-progress |
| FV-SECP-2P-001    | `crates/signer-core/src/secp256k1.rs::map_additive_share_to_threshold_signatures_share_2p`              | Inverse-Lagrange mapping preserves additive share relation in 2P flow | Tier0-pinned-impl | `near/threshold-signatures` ot_based_ecdsa signing/triples docs (pinned rev) | planned     |
| FV-TX-ENC-001     | `crates/signer-core/src/eip1559.rs`                                                                     | EIP-1559 hash preimage and signed encoding determinism                | Local-rust-spec   | signer-core implementation + Ethereum typed tx encoding rules                | planned     |
| FV-TX-ENC-002     | `crates/signer-core/src/tempo_tx.rs`                                                                    | Tempo sender-hash and signed payload encoding determinism             | Local-rust-spec   | signer-core implementation semantics                                         | planned     |
| FV-ED25519-2P-001 | `crates/signer-core/src/near_threshold_frost.rs` and `crates/signer-core/src/near_threshold_ed25519.rs` | Group key reconstruction and participant-id invariants                | Tier1-rfc         | RFC 9591, RFC 8032                                                           | planned     |

## Change Policy

- Any change to a function listed above requires updating this file in the same PR.
- `proven` status is only valid when CI runs `coqc`, `coqchk`, and corresponding vector parity checks.
