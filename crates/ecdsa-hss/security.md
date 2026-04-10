# Security Model

This file is the security-focused entrypoint for
[crates/ecdsa-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss).
Protocol shape and lifecycle live in
[specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md).

This is the security-focused design and review document for the current
`ecdsa-hss` crate. It records the intended security model for the implemented
reference lifecycle and the remaining properties that still need verification.

## Threat Model

Two parties participate in the lifecycle:

- client
- server / relayer

The intended system derives one canonical hidden secp256k1 secret `x` and then
uses threshold signing shares derived from that same key.

The main product requirement is stronger than "threshold signing works":

- export and threshold signing must refer to the same logical key
- the server must not learn the canonical exportable secret

## Core Security Goals

### 1. Single-Key Invariant

There must be exactly one canonical EVM private key per account under this
protocol.

That means:

- exported key = canonical secret `x`
- threshold signing public key = `x * G`
- threshold signing address = Ethereum address derived from `x * G`

If export and threshold signing use different keys, the protocol has failed.

### 2. Server-Blindness

The server must not learn canonical `x`, even when it:

- participates in key setup
- participates in threshold signing
- participates in export preparation

The server may hold:

- its own root-share material
- its own threshold-share material
- staged server-owned continuation state

The server must not hold:

- plaintext canonical `x`
- an export-capable reconstruction of `x`

### 3. Standard EVM Compatibility

The signing output must remain standard secp256k1 ECDSA compatible for:

- Ethereum transaction signing
- public-key recovery
- standard RPC and wallet tooling

### 4. Explicit Export Policy

Export must be:

- explicit
- policy-bound
- auditable

Signing flows must not accidentally produce export-capable output.

## Working v1 Boundary

The working v1 boundary is:

- non-export flows must never deliver canonical `x` to the client
- non-export flows may deliver only the minimum signing/share material needed
  for threshold ECDSA operation
- export flows may intentionally deliver `x` to the client
- the server must still never see `x`

This is the ECDSA analog of the `ExplicitKeyExport` exception in
[ed25519-hss/security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/security.md).

## Retained-State Rule

The intended retained-state rule is:

- after the server-owned staged boundary begins, raw root-share material should
  be dropped as early as possible
- later stages should advance from server-owned continuation state rather than
  stored plaintext root material

The exact retained-state exceptions will be frozen in the implementation/specs
once the staged ECDSA-HSS flow is implemented.

Current product-boundary note:

- deferred first-time ECDSA bootstrap is intentionally supported
- that means registration and an authenticated first `session_bootstrap` may
  both act as first-bootstrap entrypoints before an `ecdsaThresholdKeyId`
  exists
- after that point, resume/export flows are expected to use persisted
  server-owned key material rather than first-bootstrap derivation
- the staged `prepare/respond/finalize` SDK/server wire now uses hidden-eval
  envelopes only; raw client root material is no longer allowed on that staged
  transport
- this narrower transport proof does not claim every product boundary is root-share-free:
  registration and recovery payloads may still carry client root material at
  their own separate boundary outside the staged `ecdsa-hss` transport

## Current Working Assumptions

The design currently assumes:

- the canonical export object is a scalar `x`, not a seed
- direct additive-share derivation from `x` is the preferred path
- the first implementation pass is fixed 2-of-2 with participant IDs
  `{client=1, relayer=2}`
- the existing `near/threshold-signatures` ECDSA backend is reused if direct
  additive-share integration works cleanly

If that backend cannot consume the derived additive shares without violating
the single-key invariant, public-key-preserving resharing is the fallback.

## Main Security Risks

### Risk 1: Recreating The Two-Key Model

If threshold signing and export end up on separate derivation lanes, the crate
has recreated the current EVM problem.

Mitigation:

- define the single-key invariant in the specs
- test public-key and address equivalence everywhere

### Risk 2: Server-Blindness Drift

It is easy to accidentally retain too much root material on the server for
convenience or performance.

Mitigation:

- define retained-state rules early
- add boundary tests before optimization work

### Risk 3: Backend-Mismatch Drift

If the current threshold ECDSA backend cannot represent the same logical key as
the exported secret, forcing integration will break the design.

Mitigation:

- treat direct additive-share integration as the preferred path
- treat resharing as the fallback
- reject any design that preserves separate signing and export keys

## Current Implementation Review Findings

The current crate has been reviewed against its runtime boundary and core
cryptographic helpers.

### Finding 1: Secret-dependent big-integer arithmetic

The original reference implementation used `BigUint` in the canonical-scalar
reduction, additive-share derivation, and 2P backend-share mapping.

Why it mattered:

- `BigUint` arithmetic is not intended to be constant-time
- secret-derived comparisons and modular operations widened the timing/cache
  exposure surface
- the current backend-share mapper used variable-time exponentiation to compute
  the inverse Lagrange coefficient

Implemented mitigation:

- reduced secret scalar arithmetic now uses fixed-width `k256` secp256k1 scalar
  types instead of `BigUint`
- the 2P backend-share mapper now uses constant-time scalar inversion and
  multiplication on `k256` scalars
- canonical-scalar reduction now uses `k256` wide reduction instead of
  hand-rolled big-integer modulo arithmetic

Residual note:

- additive-share derivation still uses the frozen deterministic retry rule when
  the candidate client share equals `x`
- that branch is acceptable for the current fixed-function slice because the
  retry counter is itself an explicit protocol output, not hidden server-only
  state

### Finding 2: Boundary helpers trusted response tuples too much

The original integration helpers accepted `RespondResponseV1` values after only
finalize-envelope validation, then reused the supplied key/share fields without
recomputing the cryptographic relationships between them.

Why it mattered:

- a malformed or malicious response could carry inconsistent secret/public
  tuples across the client/server seam
- explicit export checked public-key/address equality, but did not prove
  `canonical_x32 -> canonical_public_key33 -> canonical_ethereum_address20`

Implemented mitigation:

- the integration boundary now recomputes and verifies:
  - `pub(x_client32) == client_public_key33`
  - `pub(x_relayer32) == relayer_public_key33`
  - `pub(x_client32) + pub(x_relayer32) == threshold_public_key33`
  - `addr(threshold_public_key33) == threshold_ethereum_address20`
  - `pub(canonical_x32) == canonical_public_key33`
  - `addr(canonical_public_key33) == canonical_ethereum_address20`
- the client-output threshold identity is now checked against the retained
  server identity instead of being trusted directly

### Finding 3: Secret-bearing structs were not zeroized

The original reference flow kept canonical secrets, additive shares, export
objects, bootstrap material, and retained relayer shares in ordinary arrays and
vectors without drop-time zeroization.

Why it mattered:

- secret material remained in heap/stack allocations longer than necessary
- intermediate staging objects widened the memory exposure window for root and
  threshold key material

Implemented mitigation:

- secret-bearing structs in the wire, client, server, shared derivation, and
  integration layers now zeroize on drop
- `signer-core` now zeroizes sensitive HKDF output buffers used during
  secp256k1 key/share derivation

## Intended Verification Targets

The highest-priority future proof/audit targets are:

- exported private key public key == threshold signing public key
- exported private key address == threshold signing address
- server never learns canonical `x`
- non-export signing flows never expose export-capable output
- retained state does not preserve forbidden root material past the accepted
  boundary

## Current FV Status

The agreed current formal-verification scope is now complete.

Completed:

- Verus stable slice for:
  - `encode_context_v1`
  - canonical `x` derivation shape and scalar-domain theorems
  - additive-share reconstruction and non-zero-share theorems
  - fixed `{1, 2}` backend share-mapping seam
  - output-policy boundary
  - finalized retained-state exclusion shape
- Aeneas + Lean boundary bridge for the frozen server-visible staged boundary
- Lean privacy theorems for the same frozen server-visible staged boundary
- widened Lean privacy theorems over paired full execution states and explicit
  secret-reconstruction-style client/server view models

Important caveat:

- the current Verus slice still uses explicit trusted axioms at a few
  production-boundary seams:
  - scalar reduction
  - retry/share selection and relayer-share construction
  - the production 2P mapper
  - the tie from backend group public key derivation to the effective group
    secret

That means the current FV pass is strong and useful for the agreed stable
slice, but it is not a claim that every cryptographic primitive boundary is
fully reduced to proof without trusted assumptions.

Still intentionally out of scope:

- hidden-eval compiler semantics
- richer runtime orchestration or transport privacy claims
- backend-general proofs beyond the fixed `{1, 2}` seam

## Related Docs

- Protocol shape:
  [specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md)
- Export semantics:
  [specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
- Integration with the current backend:
  [specs/integration-near-threshold.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/integration-near-threshold.md)
- Implementation plan:
  [docs/plans/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/implementation-plan.md)
- Share-derivation design memo:
  [docs/plans/share-derivation-design-memo.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/share-derivation-design-memo.md)
