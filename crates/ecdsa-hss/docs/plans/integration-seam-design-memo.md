# Design Memo: Current EVM Threshold Backend Seam

Date created: April 9, 2026

## Scope

This memo freezes the integration seam between `ecdsa-hss` and the repo's
current EVM threshold ECDSA backend.

The backend is an implementation target, not the source of truth for the
protocol.

## Decision

`ecdsa-hss` v1 reuses the current threshold-signatures-based ECDSA backend
through the existing 2-party additive-share mapping seam.

It does not:

- introduce a second signing backend
- rewrite threshold ECDSA from scratch
- preserve a separate export-key lane

## Exact Adapter Shape

The crate-side adapter must provide:

1. shared threshold identity
   - `group_public_key33`
   - `ethereum_address20`
   - fixed participant IDs `{1, 2}`
2. client presign input
   - additive share `x_client`
   - mapped threshold private share for participant `1`
   - client verifying-share public key
3. relayer presign input
   - additive share `x_relayer`
   - mapped threshold private share for participant `2`
   - relayer verifying-share public key

This is the exact seam already exercised by the crate-local bootstrap and sign
bridge.

## Preferred Path

Preferred v1 path:

1. derive role-local additive shares `x_client` and `x_relayer`
2. compute the shared public identity as `X = x_clientG + x_relayerG`
3. map each role's share into the current backend share encoding
4. reuse the current presign/sign backend unchanged
5. reconstruct canonical `x` only in the explicit client export runtime

## Fallback Path

If direct additive-share integration proves incompatible with the backend, the
only acceptable fallback is:

- public-key-preserving resharing into the backend's expected share form

That fallback is acceptable only if:

- the public key is unchanged
- the Ethereum address is unchanged
- export still reconstructs canonical `x` client-side
- the server remains blind to `x`

## Explicit Rejection

This memo explicitly rejects any integration that preserves separate threshold
and export key lanes.

Rejected shape:

- signing uses one secp256k1 key lane
- export uses a different deterministic secp256k1 key lane

If the backend cannot consume `ecdsa-hss` material without preserving that
split, the integration must be treated as failed.
