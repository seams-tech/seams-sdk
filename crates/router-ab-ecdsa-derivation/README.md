# Router A/B ECDSA derivation

`router-ab-ecdsa-derivation` owns the secp256k1 / ECDSA strict Router A/B derivation and
additive-share construction. Ed25519 is owned separately by Streaming Yao.

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
- direct role-local inputs for the purpose-built fixed 2-of-2 ECDSA backend
- explicit client-side export reconstruction of the same logical `x`

## Active Scope

The active implementation is fixed to:

- signer set `{client=1, relayer=2}`
- 2-of-2 threshold ECDSA
- secp256k1 / Ethereum address derivation
- stable key scope `evm-family`
- role-local additive-share derivation
- the purpose-built `router-ab-ecdsa-presign` and
  `router-ab-ecdsa-online` sign-time backends

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
   and the Router A/B ECDSA derivation context.
2. The relayer derives `x_relayer` locally from relayer-owned root-share
   material and the Router A/B ECDSA derivation context.
3. The roles exchange public share commitments.
4. The shared public identity is computed as `X = x_clientG + x_relayerG`.
5. Purpose-built fixed-role presigning consumes each role's additive share
   directly and stores one-use material in the role-local pools.
6. Purpose-built online signing consumes paired Client and SigningWorker
   presignatures for public key `X`.
7. Explicit export releases an authorized relayer export share to the client,
   and the client reconstructs and verifies `x` locally.

The sign-time backend seam is:

- shared threshold identity:
  - `group_public_key33`
  - `ethereum_address20`
  - fixed participant IDs `{1, 2}`
- client presign input:
  - additive share `x_client`
  - client verifying share public key
- relayer presign input:
  - additive share `x_relayer`
  - relayer verifying share public key

## Output Policy

The operation type controls what leaves the Router A/B ECDSA derivation boundary:

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

The old Router A/B ECDSA derivation context and server/client crate APIs were removed after the
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
[docs/plans/sdk-server-integration-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/docs/plans/sdk-server-integration-plan.md).

Current performance notes:

- derivation, bootstrap, and export are sub-millisecond in native benchmarks
- presigning is the expensive background phase and is owned by
  `router-ab-ecdsa-presign`
- a pool hit loads the small `router-ab-ecdsa-online` Client artifact and does
  not load the presign protocol

## Docs

- Security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/security.md)
- Optimization ledger:
  [optimizations.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/optimizations.md)
- Formal verification plan:
  [formal-verification/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/README.md)
- Protocol shape:
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/protocol.md)
- Export semantics:
  [specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/export.md)
- Integration with the purpose-built fixed ECDSA backend:
  [specs/integration-purpose-built-ecdsa.md](specs/integration-purpose-built-ecdsa.md)
- Historical design and optimization notes remain under `docs/plans/` and
  `optimizations.md`; they are superseded by the active specs above and
  [refactor-89](../../docs/refactor-89-slimmer-near-ecdsa.md).
