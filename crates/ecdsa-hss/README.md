# ECDSA HSS

`ecdsa-hss` is the secp256k1 / ECDSA sibling to
[ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

The crate derives one canonical hidden secp256k1 private scalar `x` for each
stable EVM-family key identity. That key is:

- threshold-signable
- explicitly exportable through the `ExplicitKeyExport` operation
- deterministic from client/server root-share material and stable key context
- server-blind

The crate provides:

- one canonical secp256k1 private scalar `x`
- one corresponding compressed secp256k1 public key `X = x * G`
- one Ethereum address derived from `X`
- additive 2-party signing shares `x_client` and `x_relayer`
- mapped private-share inputs for the `threshold-signatures` ECDSA backend
- explicit export output that returns the same canonical `x`

## V1 Scope

The v1 implementation is fixed to:

- signer set `{client=1, relayer=2}`
- 2-of-2 threshold ECDSA
- secp256k1 / Ethereum address derivation
- stable key scope `evm-family`
- direct additive-share derivation from canonical `x`
- the existing `threshold-signatures` sign-time backend through the
  additive-share mapping layer

The core invariant is:

```text
x = x_client + x_relayer mod n
pub(x) = pub(x_client) + pub(x_relayer)
threshold_ethereum_address = addr(pub(x))
exported_private_key = x
```

## Architecture

The v1 lifecycle is:

1. Client and relayer provide root-share inputs.
2. `ecdsa-hss` encodes the stable key context.
3. `ecdsa-hss` derives canonical scalar `x`.
4. `ecdsa-hss` derives additive shares `x_client` and `x_relayer`.
5. The additive shares are mapped into `threshold-signatures` participant-share
   encoding.
6. Threshold ECDSA presign/sign runs with the mapped shares and public key
   `X = x * G`.
7. Explicit export returns canonical `x` and verifies that `pub(x)` matches the
   threshold signing identity.

The sign-time backend seam is:

- shared threshold identity:
  - `group_public_key33`
  - `ethereum_address20`
  - fixed participant IDs `{1, 2}`
- client presign input:
  - additive share `x_client`
  - mapped threshold private share for participant `1`
  - client verifying share public key
- relayer presign input:
  - additive share `x_relayer`
  - mapped threshold private share for participant `2`
  - relayer verifying share public key

## Output Policy

The operation type controls what leaves the HSS boundary:

- `RegistrationBootstrap`, `SessionBootstrap`, and `NonExportSign` return
  threshold material only.
- `ExplicitKeyExport` returns threshold material and canonical `x`.

Server-retained state contains:

- relayer threshold share
- relayer public key
- threshold public key
- threshold Ethereum address
- retry counter

Server-retained state excludes canonical `x`.

## Status

The crate-local reference implementation includes:

- staged derivation
- EVM-threshold bootstrap
- EVM-threshold sign bridge
- explicit export
- bootstrap -> sign -> export regression coverage
- Verus coverage for the frozen implementation-facing scope
- Lean boundary and privacy checks for the frozen server-visible staged boundary
- native and wasm performance baselines

The crate is ready for crate-level review. Product rollout, QA, and integration
tracking live in
[docs/plans/sdk-server-integration-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/sdk-server-integration-plan.md).

Current performance notes:

- derivation, bootstrap, and export are sub-millisecond in native benchmarks
- full native sign latency is dominated by upstream `threshold-signatures`
  triples/presign work, roughly `~40 ms`
- Node-hosted wasm non-export sign is about `~120 ms`
- wasm profiling shows most sign cost lives in presign/triples roundtrip

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
- Integration with the threshold ECDSA backend:
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
