# Design Memo: Canonical Secret Representation

Date created: April 9, 2026

Removal note: this memo is historical where it describes the old Router A/B ECDSA derivation
context version. The active crate removed that path after v2 invalidation.

## Decision

The canonical export object for `router-ab-ecdsa-derivation` v1 is a scalar-first object:

- canonical secp256k1 private scalar `x`

Not:

- a seed-first export object
- a second recovery-only private key
- a threshold-share bundle

## Why Scalar-First

Scalar-first keeps the one-key invariant direct and testable:

- export returns `x`
- threshold public key must equal `x * G`
- Ethereum address must be derived from that same public key

That gives the cleanest audit statement for v1:

- threshold signing key and exported key are the same logical key

## Why Not Seed-First In v1

A seed-first export object is still a possible future design, but not for v1.

Reasons:

- it adds an extra derivation layer between export and the actual signing key
- it increases proof surface
- it makes the single-key invariant less direct
- it creates more room for runtime drift across Rust, wasm, and client code

## Normalization Rule

The scalar is normalized exactly once inside the crate reference derivation
path.

The resulting v1 scalar must be:

- 32 bytes
- valid in the secp256k1 scalar field
- non-zero

Invalid or out-of-range scalar material is rejected, not silently repaired by a
second unrelated rule later in the flow.

## Export Rule

Only explicit export operations may return canonical `x`.

Non-export operations may return:

- client signing-share material
- public identity material
- server-owned continuation artifacts

They must not return canonical `x`.

## Rejected Alternative

The following design is explicitly rejected:

- threshold signing uses one secp256k1 key
- export returns a different deterministic secp256k1 key

That is the current two-key EVM problem under a different name, and it is not
an acceptable `router-ab-ecdsa-derivation` design.

