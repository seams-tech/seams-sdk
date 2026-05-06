# Threshold Ed25519 Stateless Shared-Root Architecture

Date updated: May 6, 2026

Status: active architecture for threshold Ed25519 key identity, HSS
reconstruction, signing-session material, and seed export.

## Objective

Define the primary Ed25519 account model for NEAR and future Ed25519 chains:

- one canonical Ed25519 key per concrete auth signer and HSS context
- deterministic client/server root derivation for each signer
- standard seed-compatible export
- threshold signing over the same canonical key lifecycle
- no durable client-side wrapped signing share

Older KEK-unwrapped client-share designs are obsolete.

## Core Idea

Use a deterministic shared root as the canonical Ed25519 source of truth:

- client root contribution is derived from the selected auth signer:
  - passkey uses WebAuthn PRF output
  - Email OTP uses worker-owned Email OTP secret material to derive the
    Ed25519 HSS client root input
- server root contribution is derived from tenant secret `K_org`
- hidden evaluation combines those contributions into the canonical seed `d`
- hidden evaluation derives the canonical signing scalar `a`
- hidden evaluation projects the result into base FROST shares
- those base shares are reconstructed on demand for registration, unlock,
  signing-session creation, export, and recovery

This means:

- the selected client root input is part of the MPC signing-share model
- the server never relies on a per-account relayer signing share as the source
  of truth
- the client does not store wrapped `x_client_base`
- ordinary per-signature signing still uses an already-created signing session,
  not a fresh HSS run per signature

## Current Implementation Status

The active Ed25519 product path now follows this model for session creation and
signing:

- passkey clients re-derive passkey-rooted inputs and reconstruct
  `x_client_base` through the single-key HSS ceremony when canonical runtime
  scope is available
- Email OTP clients derive the Ed25519 HSS client root input inside the
  dedicated Email OTP worker, then run the same single-key HSS ceremony
- the server re-derives its root inputs and participates only through the
  role-separated HSS server routes
- the live signer worker accepts `x_client_base` as the Ed25519 signing-share
  basis
- warm-session-bearing bootstrap flows now reuse that same HSS seam:
  registration, sync-account, link-device, Email OTP provisioning, and
  email-recovery hydrate a threshold-ed25519 session and reconstruct
  `x_client_base` immediately for follow-on signing
- local threshold-ed25519 key metadata is now canonical single-key metadata:
  one public key, one relayer key id, one key version, and signer-set
  participant metadata; it no longer stores a second recovery public key as
  active local state
- the default threshold-ed25519 registration/bootstrap response is now
  single-key as well: registration creates and verifies one canonical
  operational NEAR access key instead of returning a second active recovery key

The active product surface is the single-key HSS lifecycle only.

## Strict Architectural Rule

There is exactly one Ed25519 lifecycle:

- stateless shared-root Ed25519
- one canonical public key per selected auth signer and HSS context
- one canonical seed `d`
- one canonical signing scalar `a = clamp(SHA-512(d)[0..31])`
- one threshold signing model over shares of `a`
- one export model over the same canonical seed `d`
- no alternate default lifecycle
- no local-only Ed25519 lifecycle

Implementation consequence:

- cached session material is an availability/performance optimization only
- it must never become a second source of truth

## Product Model

The active product flow is:

1. Registration
   HSS derives the canonical hidden `d -> a` path and returns
   `x_client_base`, `x_relayer_base`, and `A`.
2. Login / unlock
   The client re-derives its hidden inputs from the selected auth signer. The
   server re-derives its hidden inputs from `K_org`. HSS reconstructs the
   current session base shares.
3. Signing-session creation
   The same deterministic derivation/HSS path may be used to create fresh base
   shares for a new session boundary.
4. Per-signature signing
   Uses the already-created signing session. It does not rerun the full hidden
   `d -> a` conversion for every signature.
5. Export / recovery
   Uses the same canonical key lifecycle so NEAR-compatible seed export stays
   aligned with threshold signing.

## Mathematical Model

Let `ctx` bind:

- `signingRootId`
- `nearAccountId`
- `keyPurpose`
- `keyVersion`
- participant ids
- derivation version

Define:

- `client_root_input` as the normalized 32-byte input for the selected auth
  signer
- `y_client = HKDF_u256(client_root_input, "ed25519/root-share/client:v1", ctx)`
- `y_relayer = HKDF_u256(K_org, "ed25519/root-share/relayer:v1", ctx)`

Interpret both in `Z_(2^256)`.

Define the canonical seed:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`

Derive the canonical signing state:

- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `prefix = h[32..63]`
- `A = [a]B`

Define rerandomization:

- `tau_client = HKDF_mod_l(client_root_input, "ed25519/tau/client:v1", ctx)`
- `tau_relayer = HKDF_mod_l(K_org, "ed25519/tau/relayer:v1", ctx)`
- `tau = tau_client + tau_relayer mod l`

Project into 2-of-2 base shares:

- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`

Invariant:

- `a = 2 * x_client_base - x_relayer_base mod l`

## Why HSS Exists

The hidden nonlinear step is:

- `y_client + y_relayer -> d -> SHA-512(d) -> clamp -> a`

That is the reason this design needs HSS at all.

Additive shares of `d` cannot be transformed locally into threshold signing
shares of `a`.

## Performance Model

The old assumption was:

- store wrapped `x_client_base`
- derive a `KEK`
- unwrap on unlock

That is no longer the target model.

The current assumption is:

- HSS is cheap enough to sit on registration, unlock, provisioning, and
  signing-session creation
- current kept secure benchmark checkpoint is about `0.305 s` native and about
  `0.415 s` browser total hidden eval for the fixed function
- this is acceptable for unlock/session creation if it buys a cleaner
  single-key lifecycle
- the removed threshold-ed25519 microbenchmark harness is obsolete and should
  not be used as a live performance reference for the active path
- the active performance and verification reference now lives in
  [threshold-ed25519-single-key-hss.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/benchmarks/threshold-ed25519-single-key-hss.md)

The performance bar is therefore:

- fast enough for registration, unlock, provisioning, and signing-session
  creation
- not required for every single signature once a session exists

## Security Model

The security goals are:

- neither client nor server sees plaintext `d`
- neither client nor server sees plaintext `a`
- the client learns only `x_client_base` and public verification data
- the server learns only `x_relayer_base` and public verification data

The active implementation work is tracked in:

- [succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)
- [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- [optimization-v3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization-v3.md)
- [hss-threshold-ed25519.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/hss-threshold-ed25519.md)

## Export Model

Export must remain compatible with standard NEAR seed export:

- reconstruct canonical seed `d`
- derive the public key from `d`
- fail closed if the derived public key does not match the bound account key

This is why the system is designed around one canonical seed/key lifecycle
rather than separate operational and export keys by default.

## Design Consequences

- Do not introduce a second NEAR-only default key lifecycle.
- Do not reintroduce wrapped client signing-share storage as the main unlock
  path.
- Do not describe HSS as a rebuild-only backend experiment anymore.
- Keep per-signature signing and unlock/session creation as separate concerns.

## Current Recommendation

Treat this as the canonical Ed25519 direction for:

- NEAR
- Solana
- Sui
- any other Ed25519 chain where one canonical key identity matters more than a
  chain-specific optimization
