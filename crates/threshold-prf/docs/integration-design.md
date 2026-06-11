# Threshold PRF Integration Design

Date created: April 17, 2026

## Status

This memo defines how `threshold-prf` should replace only the server-input
derivation layer for future HSS wallet creation. It does not start HSS,
Cloudflare Worker, server SDK, storage, or migration implementation.

The crate gates that are already complete:

- committed protocol specs and JSON vectors
- Option A and Option B output parity
- context-bound `PrfPartialWireV1` decode
- DLEQ proof generation and verification
- native benchmarks and native guardrail checks
- local Node/V8 WASM proxy benchmarks
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
  decrypt share_i
  decrypt share_j
  partial_i = evaluate_partial(share_i, context)
  partial_j = evaluate_partial(share_j, context)
  y_relayer = combine_partials([partial_i, partial_j], context)
```

Option B:

```text
worker A:
  decrypt share_i
  partial_i = evaluate_partial(share_i, context)

worker B:
  decrypt share_j
  partial_j = evaluate_partial(share_j, context)

combiner:
  y_relayer = combine_partials([partial_i, partial_j], context)
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

The integration should consume sealed 2-of-3 signing-root shares. The
threshold-prf crate does not define database, Durable Object, KMS, KEK, or TEE
storage behavior.

The first Option A integration may decrypt two root shares in one runtime. That
runtime observes enough plaintext material to reconstruct `k_org`, so this is
an availability-first model, not a malicious-runtime privacy boundary.

Option B may later move partial evaluation across two runtimes without changing
wallet addresses because both modes use the same partial-combine algorithm.

## DLEQ And Partial Authenticity

DLEQ is implemented, vector-pinned, and benchmarked in the crate.

First Option A integration does not require DLEQ on the hot path because one
runtime computes both partials locally.

Option B should require DLEQ, TEE attestation, or an equivalent
deployment-level authenticity mechanism before claiming malicious-worker
partial correctness. DLEQ verification proves a partial matches the supplied
share commitment; deployment code must still authenticate the commitment
registry or attestation source.

If DLEQ is selected for Option B, the combiner should call
`combine_verified_partials` rather than manually sequencing
`verify_partial_dleq_proof` and `combine_partials`.

## Refactor Shape

When integration starts, add a narrow derivation interface:

```text
derive_hss_server_input(
  sealed_signing_root_share_i,
  sealed_signing_root_share_j,
  hss_context,
  purpose,
) -> y_relayer_or_tau_relayer
```

The implementation should:

- decrypt two signing-root shares in memory
- decode each decrypted share as `SigningRootShareWireV1`
- build the frozen `PrfContext`
- call `derive_output_from_signing_root_share_wires`
- pass the resulting 32 bytes into the existing HSS flow
- zeroize root-share material after use

The integration should not preserve a parallel legacy derivation path. Breaking
changes are acceptable before real customer wallets exist; remove replaced
master-secret/HKDF derivation code in the same refactor.

## Integrated Entry Points

The server-input derivation path is now split across the TypeScript
signing-root resolver boundary and narrow threshold-prf WASM wrappers.

ECDSA active path:

- [ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
  resolves the signing root from runtime policy scope and derives ECDSA
  `y_relayer` through `deriveEcdsaHssYRelayerFromSigningRootShareResolver`
  during first bootstrap and HSS prepare.
- [signingRootShareResolver.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/signingRootShareResolver.ts)
  lists sealed signing-root shares, decrypts exactly two share wires, calls the
  threshold-prf WASM boundary, and zeroizes plaintext share wires after use.
- [thresholdPrfWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/thresholdPrfWasm.ts)
  wraps `threshold_prf_derive_ecdsa_hss_y_relayer`.
- [ethSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ethSignerWasm.ts)
  keeps handling ECDSA HSS/bootstrap operations after the 32-byte `y_relayer`
  input is produced.

Ed25519 active path:

- [ThresholdSigningService.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ThresholdSigningService.ts)
  derives Ed25519 HSS server inputs from signing-root shares during session and
  registration prepare.
- [signingRootShareResolver.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/signingRootShareResolver.ts)
  derives both `y_relayer` and `tau_relayer` through the same sealed-share
  resolver boundary.
- [thresholdPrfWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/thresholdPrfWasm.ts)
  wraps `threshold_prf_derive_ed25519_hss_server_inputs`.
- [ed25519HssWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ed25519HssWasm.ts)
  keeps handling Ed25519 HSS ceremony operations after provider-derived server
  inputs are staged in the short-lived ceremony record.

Configuration active path:

- `ThresholdStoreConfigInput` accepts either a complete
  `signingRootShareResolver` or a sealed-share store plus KEK resolver.
- The server SDK includes in-memory and Postgres sealed-share stores plus an
  AES-GCM sealed-share decrypt adapter.
- Production KMS/HSM KEK resolution remains the open deployment boundary.

## Refactor Sequence

The integration refactor should be narrow and should remove old derivation in
the same change.

1. Add a server-side derivation boundary that accepts sealed signing-root shares,
   decrypts them into `SigningRootShareWireV1` values, builds the HSS
   `PrfContext`, and returns the required 32-byte `threshold-prf` outputs.
2. Route ECDSA first-bootstrap and ECDSA prepare through
   `threshold-prf` Option A partial evaluation and combine.
3. Route Ed25519 session prepare and registration prepare through two
   `threshold-prf` purposes: `ed25519-hss/y_relayer` and
   `ed25519-hss/tau_relayer`.
4. Keep HSS WASM calls unchanged after the server input bytes are produced.
5. Replace process-level server-root validation with sealed signing-root share
   storage/decrypt configuration in the integration layer.
6. Remove the old process-level server-input derivation wrappers once callers
   are migrated.
7. Add parity tests that compare the server derivation boundary against
   `crates/threshold-prf/fixtures/protocol-v1.json`.

## Tests Required Before Merge

Minimum integration tests:

- ECDSA HSS receives the same `y_relayer` bytes as the crate vector for the
  matching context
- Ed25519 HSS receives the same `y_relayer` and `tau_relayer` bytes as the crate
  vectors for the matching context
- Option A one-runtime partial combine equals the crate pairwise vector output
- transported partials reject wrong-context `PrfPartialWireV1` bytes
- the direct reference path is not used by production derivation code
- existing HSS signing behavior is unchanged after `y_relayer` bytes are
  produced

If Cloudflare Worker is the first target, also require:

- sealed-share read and decrypt-in-memory coverage
- Worker runtime benchmark numbers for Option A full derivation
- Worker runtime benchmark numbers for DLEQ prove/verify, even if DLEQ remains
  Option B-only

## Remaining Decisions

- define the storage abstraction that supplies sealed signing-root shares
- decide whether Option A should compute DLEQ proofs for audit telemetry or keep
  DLEQ entirely out of the first hot path
- update [korg-secrets.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/korg-secrets.md)
  once threshold-PRF becomes canonical
- update
  [cloudflare-signing-worker-self-host.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/cloudflare-signing-worker-self-host.md)
  once threshold-PRF becomes canonical
