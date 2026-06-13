# Threshold PRF Integration Design

Date created: April 17, 2026
Last updated: June 13, 2026

## Status

This memo defines how new integrations should use `threshold-prf` for the
server-input derivation layer in future HSS wallet creation. The crate remains
responsible only for deriving server-side HSS input bytes from threshold signing
root shares.

The crate gates that are already complete:

- committed protocol specs and JSON vectors
- Option A and Option B output parity
- configurable `t-of-N` split, reconstruct, partial-combine, and
  verified-combine APIs
- context-bound partial-wire decode
- DLEQ proof generation and verification
- native benchmarks and native guardrail checks
- local Node/V8 WASM proxy benchmarks
- WASM HSS and distributed-combine exports
- crate-local FV parity, Verus abstract proofs, and Lean privacy model
- dependency review and root/share zeroization

Open deployment gate:

- real Cloudflare Worker runtime benchmarks are still required if Cloudflare
  Worker is the first integration target

First integration target:

- server SDK only
- Cloudflare Worker integration remains gated on real Worker runtime benchmark
  results and Worker-specific sealed-share tests
- do not integrate server SDK and Cloudflare Worker in the same refactor

## Integration Boundary

`threshold-prf` owns only this layer:

```text
sealed signing-root shares
  -> threshold partial evaluation
  -> threshold partial combine
  -> y_relayer bytes
```

It must not absorb HSS protocol code, passkey/client-share logic, policy
evaluation, gas sponsorship, console project management, or SaaS-only features.

The HSS crates keep their current behavior after `y_relayer` or
`tau_relayer` bytes are produced.

## Canonical Production Path

Production signing must use threshold partial evaluation and combine.

Option A:

```text
one runtime:
  load ThresholdPolicy(threshold, share_count)
  decrypt threshold signing-root share wires
  validate the share set against the policy
  partials = evaluate_partial(each share, context)
  y_relayer = combine_partials(validated partial set, context)
```

Option B:

```text
workers:
  load ThresholdPolicy(threshold, share_count)
  decrypt assigned signing-root share wires
  partial_i = evaluate_partial(assigned share_i, context)

combiner:
  validate a threshold partial set against the policy
  y_relayer = combine_partials(validated partial set, context)
```

`evaluate_direct_reference(k_org, context)` is reference-only for tests,
vectors, audits, and recovery checks. It must not become the canonical signing
path.

## HSS Contexts

The HSS integration must construct `PrfContext` using the frozen context
encodings in [protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/threshold-prf/docs/protocol.md).

ECDSA:

- purpose: `ecdsa-hss/y_relayer`
- context bytes: existing `ecdsa-hss` canonical context v1
- output handling: downstream `ecdsa-hss` treats `y_relayer[32]` as its
  existing little-endian integer input; `threshold-prf` does not parse or reduce
  it

Ed25519:

- purpose: `ed25519-hss/y_relayer` for the server root input
- purpose: `ed25519-hss/tau_relayer` for the server rerandomization input
- context bytes: existing `Ed25519HssCanonicalContextV1` SHA-256 binding digest
- output handling: downstream `ed25519-hss` treats `y_relayer[32]` as opaque
  input to seed expansion and `tau_relayer[32]` as canonical Ed25519 scalar
  bytes; `threshold-prf` reduces only the `tau_relayer` purpose output

No integration may use ad hoc project or wallet strings as production context
bytes.

## Storage And Runtime Inputs

New integrations should consume sealed signing-root shares plus an explicit
`ThresholdPolicy`. The threshold-prf crate does not define database, Durable
Object, KMS, KEK, or TEE storage behavior.

The first Option A integration may decrypt one threshold subset in one runtime.
That runtime observes enough plaintext material to reconstruct `k_org`, so this
is an availability-first model.

Option B may later move partial evaluation across multiple runtimes without
changing wallet addresses because both modes use the same partial-combine
algorithm and policy.

## DLEQ And Partial Authenticity

DLEQ is implemented, vector-pinned, and benchmarked in the crate.

First Option A integration does not require DLEQ on the hot path because one
runtime computes the threshold subset locally.

Option B should require DLEQ, TEE attestation, or an equivalent
deployment-level authenticity mechanism before claiming malicious-worker
partial correctness. DLEQ verification proves a partial matches the supplied
share commitment; deployment code must still authenticate the commitment
registry or attestation source.

If DLEQ is selected for Option B, the combiner should call
`threshold_prf::combine_verified_partials` so proof verification and
threshold combine remain one boundary operation.

## Refactor Shape

When integration starts, add a narrow derivation interface:

```text
derive_hss_server_input(
  threshold_policy,
  sealed_signing_root_shares,
  hss_context,
  purpose,
) -> y_relayer_or_tau_relayer
```

The implementation should:

- select exactly `threshold` signing-root shares from the selected policy
- decrypt the selected signing-root shares in memory
- decode each decrypted share as `threshold_prf::SigningRootShareWire`
- validate the decoded share set against `threshold_prf::ThresholdPolicy`
- build the frozen `PrfContext`
- call `threshold_prf::evaluate_partial` for each share
- call `threshold_prf::combine_partials` on the validated partial set
- pass the resulting 32 bytes into the existing HSS flow
- zeroize root-share material after use

Existing fixed 2-of-3 callers should use an explicit `ThresholdPolicy` with
threshold `2` and share count `3`. New Router/A/B and HSS integration code
should enter through the boundary above.

## Integrated Entry Points

The server-input derivation path is now split across the TypeScript
signing-root resolver boundary and narrow threshold-prf WASM wrappers. Router/A/B
and HSS work should keep the resolver boundary and route through exports that
accept a threshold policy and signing-root share wires.

ECDSA active path:

- [ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
  should resolve the signing root and threshold policy from runtime policy scope
  and derive ECDSA `y_relayer` through the sealed-share resolver boundary
  during first bootstrap and HSS prepare.
- [signingRootShareResolver.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/signingRootShareResolver.ts)
  should list sealed signing-root shares, decrypt a threshold subset, call
  the threshold-prf WASM boundary, and zeroize plaintext share wires after use.
- [thresholdPrfWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/thresholdPrfWasm.ts)
  should wrap `threshold_prf_derive_ecdsa_hss_y_relayer` for derivation.
- [ethSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ethSignerWasm.ts)
  keeps handling ECDSA HSS/bootstrap operations after the 32-byte `y_relayer`
  input is produced.

Ed25519 active path:

- [ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
  should derive Ed25519 HSS server inputs from signing-root share sets during
  session and registration prepare.
- [signingRootShareResolver.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/signingRootShareResolver.ts)
  should derive both `y_relayer` and `tau_relayer` through the same
  policy-aware sealed-share resolver boundary.
- [thresholdPrfWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/thresholdPrfWasm.ts)
  should wrap `threshold_prf_derive_ed25519_hss_server_inputs` for derivation.
- [ed25519HssWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ed25519HssWasm.ts)
  keeps handling Ed25519 HSS ceremony operations after provider-derived server
  inputs are staged in the short-lived ceremony record.

Configuration active path:

- `ThresholdStoreConfigInput` accepts either a complete
  `signingRootShareResolver` or a sealed-share store plus KEK resolver.
- New configuration must include a `ThresholdPolicy` or a policy resolver
  that normalizes persisted policy data before core derivation code runs.
- The server SDK includes in-memory and Postgres sealed-share stores plus an
  AES-GCM sealed-share decrypt adapter.
- Production KMS/HSM KEK resolution remains the open deployment boundary.

## Refactor Sequence

The integration refactor should be narrow and should remove replaced derivation
in the same change.

1. Add a server-side derivation boundary that accepts a `ThresholdPolicy` and
   sealed signing-root shares, decrypts a threshold subset into
   `SigningRootShareWire` values, builds the HSS `PrfContext`, and returns the
   required 32-byte `threshold-prf` outputs.
2. Route ECDSA first-bootstrap and ECDSA prepare through
   `threshold-prf` Option A partial evaluation and combine.
3. Route Ed25519 session prepare and registration prepare through two
   `threshold-prf` purposes: `ed25519-hss/y_relayer` and
   `ed25519-hss/tau_relayer`.
4. Keep HSS WASM calls unchanged after the server input bytes are produced.
5. Replace process-level server-root validation with threshold policy,
   sealed-share storage, and decrypt configuration in the integration layer.
6. Remove the old process-level server-input derivation wrappers once callers
   are migrated.
7. Add parity tests that compare the server derivation boundary against
   `crates/threshold-prf/fixtures/protocol-t-of-n.json`.

## Tests Required Before Merge

Minimum integration tests:

- ECDSA HSS receives the same `y_relayer` bytes as the crate vector for the
  matching context
- Ed25519 HSS receives the same `y_relayer` and `tau_relayer` bytes as the crate
  vectors for the matching context
- Option A one-runtime partial combine equals the crate threshold-subset
  vector output
- transported partials reject wrong-context `threshold_prf::PrfPartialWire`
  bytes
- the direct reference path is not used by production derivation code
- existing HSS signing behavior is unchanged after `y_relayer` bytes are
  produced

If Cloudflare Worker is the first target, also require:

- sealed-share read and decrypt-in-memory coverage
- Worker runtime benchmark numbers for Option A full derivation
- Worker runtime benchmark numbers for DLEQ prove/verify, even if DLEQ remains
  Option B-only

## Remaining Decisions

- define the storage abstraction that supplies `ThresholdPolicy` and sealed
  signing-root shares
- decide whether Option A should compute DLEQ proofs for audit telemetry or keep
  DLEQ entirely out of the first hot path
- update [korg-secrets.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/korg-secrets.md)
  once threshold-PRF becomes canonical
- update
  [cloudflare-signing-worker-self-host.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/cloudflare-signing-worker-self-host.md)
  once threshold-PRF becomes canonical
