# `ed25519-hss` Spec-To-Code Compliance Review

Date: 2026-04-05

## Spec Corpus Reviewed

- [`../specs/protocol.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/protocol.md)
- [`../specs/derivation.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/derivation.md)
- [`../security.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md)
- [`../README.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- [`../docs/plans/refactor-hss-1.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/docs/plans/refactor-hss-1.md)

## Alignment Summary

- The clear fixed-function math in `shared/reference.rs` matches the documented
  `F_expand` and reconstruction formulas.
- The refactored module tree matches the intended `shared` / `wire` / `client`
  / `server` split.
- The strongest remaining compliance issues are in documentation drift around
  the active security boundary and in stale file references.

## Findings

### 1. Security-boundary text in the older protocol spec was stricter than the shipped sealed packet flow

Severity: Medium

Spec evidence:

- older protocol spec text, now tracked in
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/specs/protocol.md)
  says the evaluator must not receive enough material to decode server input.
- the same older spec text also said “no interparty wire type may carry both
  halves of a hidden server-owned value”.

Code evidence:

- [`server/api.rs:387`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs#L387)
  seals a `ServerInputsPacket`.
- [`server/api.rs:397`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/server/api.rs#L397)
  serializes server inputs via `serialize_server_inputs_payload`.
- [`wire/mod.rs:446`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/wire/mod.rs#L446)
  encodes `y_server_left`, `y_server_right`, `tau_server_left`, and
  `tau_server_right` into one payload.
- [`client/api.rs:103`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/client/api.rs#L103)
  opens that packet and returns both left/right server bundles.

Reasoning:

- The shipped packet format carries both server halves together inside one
  sealed server-input message.
- [`security.md:64`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md#L64)
  also describes this active behavior, so this is not just a code bug. It is a
  contradiction inside the spec corpus.

Classification:

- older protocol spec boundary clause: `mismatch`
- `security.md` active-runtime description: `full_match`

Confidence: 0.96

Recommended remediation:

- Rewrite the boundary claim so it matches the current sealed-packet design, or
  change the packet design before freezing boundary proofs.

### 2. The older protocol spec current-status section still pointed at pre-refactor file paths

Severity: Low

Spec evidence:

- the older protocol spec referenced pre-refactor paths such as
  `src/reference.rs`, `src/hidden_eval.rs`, `src/ddh_hss.rs`,
  `src/prime_order_encoder.rs`, and `src/succinct_hss.rs`

Code evidence:

- [`lib.rs:1`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/lib.rs#L1)
  shows the refactored module tree with `shared`, `client`, `server`, `wire`,
  and nested `ddh` / `artifact` modules.
- The live files are now:
  - [`shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs)
  - [`ddh/hidden_eval.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/hidden_eval.rs)
  - [`ddh/ddh_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/ddh/ddh_hss.rs)
  - [`artifact/prime_order_encoder.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/artifact/prime_order_encoder.rs)
  - [`protocol/prepared.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/prepared.rs)

Reasoning:

- The current-status section no longer maps 1:1 to the live code tree after the
  boundary refactor.
- This is documentation drift, not functional divergence, but it weakens the
  traceability required for formal verification.

Classification:

- `mismatch`

Confidence: 0.99

Recommended remediation:

- Update the protocol spec to the post-refactor file paths before
  using it as a frozen proof reference.
