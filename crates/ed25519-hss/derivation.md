# Ed25519 HSS Derivation

Date updated: March 31, 2026

This note defines how the current Ed25519 HSS design derives:

- the hidden root secret inputs
- the canonical Ed25519 seed `d`
- the canonical Ed25519 signing scalar `a`
- the rerandomization value `tau`
- the final 2-of-2 base signing shares

It is the short reference for the fixed-function path implemented in this
crate.

## Variables

Client-side roots:

- `prf.output`

Server-side roots:

- `K_org`

Context binding:

- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`
- participant ids
- derivation version

We refer to the full bound tuple as `ctx`.

## Step 1: Root Shares

The client and server first derive root-share inputs from their own roots plus
the same canonical context.

Define:

- `y_client = HKDF_u256(prf.output, "ed25519/root-share/client:v1", ctx)`
- `y_relayer = HKDF_u256(K_org, "ed25519/root-share/relayer:v1", ctx)`

Interpret both values in `Z_(2^256)`.

Meaning:

- `y_client` is the client root-share input
- `y_relayer` is the server root-share input

These are not signing shares yet.

## Step 2: Canonical Seed

Combine the root shares in the 256-bit seed domain:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`

Meaning:

- `m` is the canonical seed integer
- `d` is the canonical 32-byte Ed25519 seed

This is the standard export-compatible seed.

## Step 3: Canonical Signing Scalar

Derive the standard Ed25519 signing state from the seed:

- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `prefix = h[32..63]`
- `A = [a]B`

Meaning:

- `a` is the canonical Ed25519 signing scalar
- `A` is the canonical public key
- `prefix` is the standard Ed25519 nonce-prefix material derived from `d`

Important distinction:

- `d` is the canonical seed
- `a` is the canonical signing scalar derived from `d`

The hidden nonlinear conversion this crate exists to implement is:

- `y_client + y_relayer -> d -> SHA-512(d) -> clamp -> a`

## Step 4: Rerandomization Shares

Independently of the seed path, derive rerandomization inputs in the scalar
field:

- `tau_client = HKDF_mod_l(prf.output, "ed25519/tau/client:v1", ctx)`
- `tau_relayer = HKDF_mod_l(K_org, "ed25519/tau/relayer:v1", ctx)`
- `tau = tau_client + tau_relayer mod l`

Meaning:

- `tau_client` is the client rerandomization share
- `tau_relayer` is the server rerandomization share
- `tau` is the combined rerandomization value

`tau` is not the seed share and not the Lagrange coefficient.

Its job is to turn the canonical scalar `a` into one concrete valid pair of
2-of-2 base signing shares.

## Step 5: Base Signing Shares

Project `a` and `tau` into the final 2-of-2 base shares:

- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`

Meaning:

- `x_client_base` is the client's base signing share
- `x_relayer_base` is the server's base signing share

These are the actual signing shares used to start a signing session.

## Reconstruction Invariant

For participant ids `(1, 2)`, the Lagrange coefficients at zero are:

- `lambda_client = 2`
- `lambda_relayer = -1 mod l`

Therefore the base shares satisfy:

- `a = 2 * x_client_base - x_relayer_base mod l`

This is why the output projection is chosen that way.

Important distinction:

- `tau` changes the share values
- the Lagrange coefficients tell you how to reconstruct `a` from those values

So:

- `tau` is secret rerandomization material
- the Lagrange coefficients are public interpolation constants

## Mental Model

The protocol has two hidden paths that meet at the output-share projector.

Seed path:

- `y_client + y_relayer -> d -> SHA-512(d) -> clamp -> a`

Share path:

- `tau_client + tau_relayer -> tau`

Output projection:

- `x_client_base = a + tau`
- `x_relayer_base = a + 2 * tau`

So:

- `y` defines the canonical secret
- `tau` defines how that secret is projected into signing shares

## Summary

The derivation roles are:

- `y_client`, `y_relayer`
  - root-share inputs
  - define the canonical seed `d`
- `d`
  - canonical Ed25519 seed
  - standard export-compatible private-key seed
- `a`
  - canonical Ed25519 signing scalar derived from `d`
- `tau_client`, `tau_relayer`
  - rerandomization shares
  - define `tau`
- `x_client_base`, `x_relayer_base`
  - final base signing shares used by threshold signing

The two critical invariants are:

- `d = LE32(y_client + y_relayer mod 2^256)`
- `a = 2 * x_client_base - x_relayer_base mod l`
