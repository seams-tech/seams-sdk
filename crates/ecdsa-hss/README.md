# ECDSA HSS

`ecdsa-hss` is the secp256k1 / ECDSA sibling to
[ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

The goal is not to add another EVM recovery key. The goal is to replace the
current two-key EVM model with one canonical secp256k1 key that is:

- threshold-signable
- exportable
- deterministic
- server-blind

The intended contribution is:

- one canonical secp256k1 private key `x`
- one corresponding secp256k1 public key and Ethereum address
- threshold ECDSA signing uses shares of that same `x`
- export returns that same `x`
- the server can participate in setup and signing flows without seeing `x`

This crate now has a crate-local reference implementation for the one-key
bootstrap, sign, and explicit export lifecycle. The SDK/server staged
`ecdsa-hss` seam is now live and test-backed; remaining work is rollout/QA and
broader product cleanup, not the old bootstrap cutover itself.

## Why This Exists

Today the repo's EVM threshold path effectively has two key lanes:

- a threshold ECDSA signing key
- a separate deterministic exportable secp256k1 key

`ecdsa-hss` exists to remove that split.

The working v1 design target is:

- derive a canonical hidden secp256k1 scalar `x`
- derive additive 2-party shares of `x`
- keep v1 scope fixed to the current 2-of-2 signer set `{client=1, relayer=2}`
- reuse the current `threshold-signatures`-based EVM threshold ECDSA backend through the
  existing additive-share mapping layer
- keep resharing as a fallback only if direct additive-share integration fails

## Current Status

Current status:

- specs and core design memos are now written
- a reference staged derivation path now exists in the crate
- a crate-local EVM-threshold bootstrap entrypoint now exists
- a crate-local EVM-threshold sign bridge now exists
- a crate-local explicit export entrypoint now exists
- the preferred share-derivation design is direct additive shares from
  canonical `x`
- public-key-preserving resharing remains the fallback path
- the current threshold ECDSA backend seam is now frozen as:
  - shared threshold identity
  - client presign input
  - relayer presign input
- crate-local bootstrap -> sign -> export regressions now prove the one-key
  identity across:
  - generic non-export bootstrap
  - registration bootstrap
  - session bootstrap
- the agreed formal-verification scope is now complete:
  - Verus stable slice is complete for the frozen implementation-facing scope
  - the Lean boundary bridge is complete for the server-visible staged boundary
  - the Lean privacy pass is complete for the frozen server-visible staged
    boundary scope
- crate-local benchmark work is now in a good stopping place for the crate
  phase:
  - derivation/bootstrap/export are all sub-millisecond
  - the only remaining hotspot is the upstream threshold-signatures triples
    phase at roughly `~40 ms` full sign latency
- a first wasm baseline now also exists through
  [wasm/eth_signer](/Users/pta/Dev/rust/simple-threshold-signer/wasm/eth_signer):
  - bootstrap/export remain sub-millisecond
  - full non-export sign is about `~120 ms` in the current Node-hosted wasm
    runtime
  - profiled wasm sign runs show almost all of that cost is still the
    presign/triples roundtrip, not input parsing or final signature assembly

This crate should not be treated as production-ready yet.

For the crate itself, the agreed formal-verification reconciliation is now
done. The remaining unchecked items are optional parity/performance follow-up
or product cutover work, not core crate implementation gaps.

Current crate stop point:

- implementation-complete enough for crate review
- native and wasm baselines are established
- optimization is paused at an acceptable crate-phase stopping point
- the agreed formal-verification scope is complete and green
- remaining proof caveats are explicit trusted assumptions inside the current
  Verus slice, plus intentionally deferred broader privacy/runtime scope

Product integration and rollout state are tracked separately in
[docs/plans/sdk-server-integration-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/sdk-server-integration-plan.md).
This README stays crate-scoped.

## Docs

- Security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
- Optimization ledger:
  [optimizations.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/optimizations.md)
- Formal verification plan:
  [formal-verification/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/README.md)
- Protocol shape:
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md)
- Export semantics:
  [specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
- Integration with the current threshold ECDSA backend:
  [specs/integration-near-threshold.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-near-threshold.md)
- Implementation plan:
  [docs/plans/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/implementation-plan.md)
- Share-derivation design memo:
  [docs/plans/share-derivation-design-memo.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/share-derivation-design-memo.md)
- Canonical-secret design memo:
  [docs/plans/canonical-secret-design-memo.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/canonical-secret-design-memo.md)
- Integration-seam design memo:
  [docs/plans/integration-seam-design-memo.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/integration-seam-design-memo.md)
- Boundary note:
  [docs/plans/boundary.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/boundary.md)
- Refactor 1:
  [docs/plans/refactor-1.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/refactor-1.md)
- Optimization V1 summary:
  [docs/plans/optimization-v1.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/optimization-v1.md)

## Intended v1 Architecture

The intended v1 shape is:

1. Client and server hold root-share material.
2. `ecdsa-hss` deterministically derives one canonical hidden secp256k1 secret
   `x`.
3. `ecdsa-hss` derives additive 2-party shares of `x`.
4. Those additive shares are adapted into the current threshold ECDSA backend.
5. Threshold signing and export both refer to the same logical key.

The crate does not aim to be:

- a generic ECDSA MPC framework
- a generic garbling framework
- a sidecar export layer for a separate threshold key

## Working v1 Decision

The current working decision is:

- canonical export object: scalar-first
- primary share-derivation path: direct additive-share derivation from
  canonical `x`
- fallback path: public-key-preserving resharing into the current backend only
  if direct additive shares prove incompatible

## Non-Goals

`ecdsa-hss` should not:

- preserve the current "threshold key plus sidecar export key" model
- add legacy compatibility branches for the old two-key EVM flow
- weaken the export/signing boundary to save implementation time
- replace the current threshold ECDSA backend before reuse has been ruled out
