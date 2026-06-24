# ECDSA HSS

`ecdsa-hss` is the secp256k1 / ECDSA sibling to
[ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

The crate derives one logical secp256k1 private scalar `x` for each stable
EVM-family key identity. The live protocol represents that key as role-local
additive shares:

```text
x = x_client + x_relayer mod n
X = x_clientG + x_relayerG
```

That key is:

- threshold-signable
- explicitly exportable through the `ExplicitKeyExport` operation
- deterministic from role-local client/server root-share material and an opaque
  SDK-owned application binding digest
- server-blind

The crate provides:

- one canonical secp256k1 private scalar `x`
- one corresponding compressed secp256k1 public key `X = x * G`
- one Ethereum address derived from `X`
- additive 2-party signing shares `x_client` and `x_relayer`
- mapped private-share inputs for the `threshold-signatures` ECDSA backend
- explicit client-side export reconstruction of the same logical `x`

## Active Scope

The active implementation is fixed to:

- signer set `{client=1, relayer=2}`
- 2-of-2 threshold ECDSA
- secp256k1 / Ethereum address derivation
- stable key scope `evm-family`
- role-local additive-share derivation
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

The active lifecycle is:

1. The client derives `x_client` locally from client-owned root-share material
   and the HSS context.
2. The relayer derives `x_relayer` locally from relayer-owned root-share
   material and the HSS context.
3. The roles exchange public share commitments.
4. The shared public identity is computed as `X = x_clientG + x_relayerG`.
5. The additive shares are mapped into `threshold-signatures` participant-share
   encoding.
6. Threshold ECDSA presign/sign runs with mapped role-local shares and public key
   `X`.
7. Explicit export releases an authorized relayer export share to the client,
   and the client reconstructs and verifies `x` locally.

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
- `ExplicitKeyExport` returns threshold material and an export-authorized relayer
  share envelope. The client reconstructs canonical `x`.

Server-retained state contains:

- relayer additive share
- relayer public key
- threshold public key
- threshold Ethereum address
- retry counter

Server-retained state excludes canonical `x`.
Client-wire non-export responses exclude `x_relayer`. Server-retained state is
returned only through server-owned result types for persistence.

## Status

The old ECDSA HSS context and server/client crate APIs were removed after the
v3 stable-key context invalidation. The active context carries only
`application_binding_digest`, fixed scheme/curve values, and participant IDs.
No crate module retains the old
`wallet_session_user_id`/`subject_id` context, wire, server, integration,
fixture, or benchmark path.

The crate-local implementation includes:

- staged derivation
- explicit export
- bootstrap -> export regression coverage
- Lean boundary and privacy checks for the active server-visible staged boundary
- native performance baselines

The crate is ready for crate-level review. Product rollout, QA, and integration
tracking live in
[docs/plans/sdk-server-integration-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/sdk-server-integration-plan.md).

Current performance notes:

- derivation, bootstrap, and export are sub-millisecond in native benchmarks
- full native sign latency is dominated by upstream `threshold-signatures`
  triples/presign work, roughly `~40 ms`
- current role-local WASM numbers are pending until the bindings and benchmark
  runner are updated

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
  [specs/integration-cait-sith-backend.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-cait-sith-backend.md)
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
- True server-blindness plan:
  [docs/plans/true-server-blindness.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/true-server-blindness.md)
- Refactor 1:
  [docs/plans/refactor-1.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/refactor-1.md)
