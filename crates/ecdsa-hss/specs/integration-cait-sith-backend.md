# Integration Spec: Current Threshold ECDSA Backend

This document defines how `ecdsa-hss` is intended to integrate with the
repo's current threshold ECDSA backend.

## Integration Target

The integration target is the current threshold ECDSA stack built around:

- `near/threshold-signatures`
- signer-core threshold ECDSA helpers
- the existing additive-share mapping layer

Relevant local references:

- [server/src/core/ThresholdService/ethSignerWasm.ts](/Users/pta/Dev/rust/simple-threshold-signer/server/src/core/ThresholdService/ethSignerWasm.ts)
- [crates/signer-core/src/secp256k1.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/secp256k1.rs)
- [crates/signer-core/src/threshold_ecdsa.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/threshold_ecdsa.rs)
- [docs/ecdsa_threshold_signing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/ecdsa_threshold_signing.md)

## Integration Goal

The goal is:

- reuse the current threshold ECDSA signing backend
- replace the current two-key EVM model with one canonical key model

That means:

- threshold signing key should come from `ecdsa-hss`
- export should return that same threshold signing key
- the current separate `prfSecond` export lane should go away after cutover

## Fixed Backend Scope

The preferred reuse path is only defined for the current fixed 2-party
integration seam.

Active integration scope is:

- fixed 2-of-2 signer set only
- fixed participant IDs:
  - client = `1`
  - relayer = `2`
- the existing 2-party additive-share mapper is the only accepted mapping path

This matters because the current mapper is not generic. A broader signer set or
different participant-ID layout would require a new mapping spec, new proofs,
and likely new runtime assumptions.

## Preferred Path

The preferred integration path is:

1. the client derives `x_client` locally from client-owned material and stable
   key context
2. the relayer derives `x_relayer` locally from relayer-owned material and stable
   key context
3. the public identity is computed as `X = x_clientG + x_relayerG`
4. those additive shares are mapped into the current
   `near/threshold-signatures` share encoding using the existing 2-party
   mapping layer
5. the current presign/sign backend operates unchanged on the mapped shares
6. explicit export releases an authorized relayer export share, and the client
   reconstructs canonical `x`

This is the intended design because it:

- preserves the single-key invariant most directly
- keeps the current sign-time backend and performance profile
- avoids writing a new threshold ECDSA library

## Exact Bootstrap Seam

The current backend seam we are targeting is now explicit.

`ecdsa-hss` must be able to supply:

- shared threshold identity:
  - `group_public_key33`
  - `ethereum_address20`
  - fixed participant IDs `{1, 2}`
- client-side presign input:
  - additive share `x_client`
  - mapped threshold private share for participant `1`
  - client verifying share public key
- relayer-side presign input:
  - additive share `x_relayer`
  - mapped threshold private share for participant `2`
  - relayer verifying share public key

That matches the real current backend seam:

- the runtime persists identity as `thresholdEcdsaPublicKeyB64u`
- the client runtime derives or retains `clientVerifyingShareB64u`
- the presign backend ultimately consumes:
  - `private_share32`
  - `public_key_sec1`

So the first adapter target is not the full product bootstrap payload. It is:

- one shared threshold identity
- one client presign input
- one relayer presign input

That is the minimum shape needed to replace the current `PRF.first +
relayer master secret` bootstrap lane without changing the sign-time backend.

The crate-side bootstrap entrypoint for that shape is:

- client and relayer role-local bootstrap builders

Its job is to:

- derive role-local additive shares without reconstructing canonical `x` in the
  server path
- produce the shared threshold identity
- produce client and relayer presign inputs in the current backend format

The old crate-side sign bridge helpers were removed with the old context
version. Active product signing consumes v2 role-local output through the
runtime threshold ECDSA integration instead of retaining crate-level old-version
server/client APIs.

## Fallback Path

If the current backend cannot safely consume directly derived additive shares,
the fallback path is:

1. `ecdsa-hss` derives role-local additive shares.
2. A public-key-preserving resharing step adapts that sharing into the exact
   format expected by the current backend.
3. The current backend signs using the reshared material.
4. Explicit export still reconstructs canonical `x` client-side.

This fallback is acceptable only if it preserves:

- the same public key
- the same Ethereum address
- server-blindness of canonical `x`

## What Should Not Be Reused

The old EVM split-key assumption should not survive the integration.

That means the integrated `ecdsa-hss` path should not preserve:

- threshold signing key derived from `PRF.first`
- separate export key derived from `PRF.second`

Once `ecdsa-hss` is live, export and threshold signing should use the same
logical key.

## Required Backend Properties

The current backend is only an acceptable integration target if all of these
hold:

1. It can consume externally derived share material.
2. It can be given the public key corresponding to logical canonical `x`.
3. Its additive-share mapping layer preserves the same group secret and public
   key.
4. It does not require a second independent keygen lane that would recreate the
   two-key problem.

## Canonical Identity Persistence

The integration layer must persist the threshold identity produced by
`ecdsa-hss`; it cannot rely on ephemeral presign state.

Minimum required persisted identity:

- `thresholdEcdsaPublicKeyB64u`
- enough account/key-version context to bind that key to the correct account
- the derived Ethereum address, or enough information to recompute it
  deterministically from `thresholdEcdsaPublicKeyB64u`

The current session/runtime layer may also retain:

- `relayerVerifyingShareB64u`

but only as supporting material for bootstrap or compatibility fallback.
Steady-state identity checks should prefer the persisted group public key.

Export verification must compare returned `x` against that persisted threshold
identity before delivery.

The active explicit export artifact kind exposed to product and UI boundaries is:

```text
ecdsa-hss-secp256k1-export
```

The retired `ecdsa-hss-secp256k1-key-v1` artifact kind is invalid for active
`ecdsa-hss` export paths.

## Performance Expectations

### Direct Additive-Share Integration

Expected performance profile:

- bootstrap/registration slower than today because HSS is added
- sign path stays close to current presign/sign performance
- export becomes explicit and separate

This is the preferred path because it adds the least steady-state latency.

### Resharing Fallback

Expected performance profile:

- bootstrap/registration slower than direct additive-share integration
- sign path may stay similar after resharing completes
- more setup state and protocol machinery to maintain

This should be used only if the direct path fails compatibility review.

## Migration Implications

The current product has:

- threshold ECDSA signing key
- separate deterministic exportable secp256k1 key

The intended integrated state is:

- one threshold-signable exportable secp256k1 key

The working cutover decision is:

- there is no in-place cryptographic migration from the current two-key model
  to `ecdsa-hss`
- existing users must re-register to enter the `ecdsa-hss` one-key model
- the current `prfSecond` export lane is retired when `ecdsa-hss` becomes the
  active EVM scheme
- legacy `prfSecond` export artifacts remain legacy-only and are never accepted
  as `ecdsa-hss` export output

Why:

- the current threshold signing key and the current export key are different
  keys
- there is no clean way to reinterpret them as one canonical key without
  violating the single-key invariant

So the migration rule is explicit:

- old accounts remain old accounts
- new `ecdsa-hss` accounts are created through re-registration
- we do not attempt an automatic key merge or silent key reinterpretation
- the product must not present legacy `prfSecond` export as if it were the
  threshold ECDSA key for `ecdsa-hss` accounts

## Working Recommendation

The working recommendation for implementation is:

- use direct role-local additive-share derivation first
- keep resharing as the fallback
- do not write a new threshold ECDSA signing backend unless backend reuse
  fails

## Related Docs

- Protocol shape:
  [protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/protocol.md)
- Export semantics:
  [export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/specs/export.md)
- Security model:
  [security.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/security.md)
- Share-derivation design memo:
  [docs/plans/share-derivation-design-memo.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/share-derivation-design-memo.md)
