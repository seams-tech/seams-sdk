# Homomorphic Key Export Historical Note (Ed25519, Option B)

Date updated: March 31, 2026

## Status

Option B is now historical background for older NEAR-specific dual-key work,
not the active default.

The active strategic direction is Option A:

- [homomorphic-key-export-ED25519-OPTION-A.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/homomorphic-key-export-ED25519-OPTION-A.md)

Keep this note only as a record of the dual-key alternative and migration
history. Do not treat it as the live product specs for Ed25519 signing or
export.

## Objective

Option B defines a simpler NEAR-specific model with:

- one threshold operational key `pk_a`
- one independent recovery/export key `pk_d`
- standard seed-compatible export only for `pk_d`

This avoids the hidden single-key `d -> a` conversion for the hot threshold
signing path, at the cost of abandoning the single canonical key invariant.

## When Option B Makes Sense

Choose Option B only if:

- NEAR-specific product simplicity matters more than one-key architecture
- operational signing and export are allowed to be different key lifecycles
- a dual-key account story is acceptable in product and API design

Do not choose Option B if:

- one canonical public key is a hard requirement
- the same Ed25519 model should extend cleanly to Solana or Sui
- export and signing must obviously refer to the same underlying key

## Core Model

Option B uses two sibling derivation domains:

- operational threshold domain:
  - derives threshold signing material for `a`
  - yields public key `pk_a`
- recovery/export domain:
  - derives seed material `d`
  - yields public key `pk_d`

Both can still be rooted in:

- WebAuthn `prf.output`
- server secret `K_org`
- shared canonical context

But they are intentionally separate domains with separate public keys.

## Why It Existed

Option B existed because the single-key hidden conversion looked too expensive:

- `d -> SHA-512(d) -> clamp -> a`

If that conversion were too slow, Option B would avoid forcing standard seed
export and threshold signing onto the same hidden path.

That tradeoff is now less compelling because the succinct-HSS path has become
materially faster.

## Current Recommendation

Treat Option B as:

- a NEAR-only alternative
- a possible migration bridge
- a fallback if Option A proves unacceptable on target hardware

Do not treat Option B as the shared default Ed25519 model across chains.

## Export Guidance

If Option B is ever used:

- export verifies against `pk_d`, never `pk_a`
- operational signing uses only `pk_a`
- recovery/export metadata must stay separate from operational signing metadata

Do not blur these domains in route types, storage, or user-facing language.
