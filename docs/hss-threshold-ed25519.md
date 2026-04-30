# HSS Threshold Ed25519

Date updated: April 3, 2026

## Summary

This document explains the active single-key Ed25519 HSS threshold signer, including
the implemented server-side relayer-share self-heal path used when durable
relayer share storage is missing.

The active design is:

- one canonical Ed25519 seed `d`
- one canonical signing scalar `a`
- one canonical public key `A`
- threshold signing and verified export both bound to that same lifecycle
- client hidden input re-derived from passkey `prf.output`
- server hidden input re-derived from server root material

This keeps the product independent of NEAR-specific recovery semantics. The
same hidden Ed25519 lifecycle can support any chain whose wallet model is based
on normal Ed25519 keypairs, with chain-specific account and message adapters
layered on top.

## Current Status

Current single-key HSS state:

- registration uses the HSS prepare/finalize seam
- warm-session reconstruction uses the HSS prepare/finalize seam
- signing uses the canonical single-key Ed25519 key
- export uses verified seed export only
- sync-account, link-device, and email recovery all use the single-key HSS path
- relayer-share cache loss is now recoverable through authenticated
  client-assisted HSS self-heal

What is still cached for performance:

- the client may cache `xClientBaseB64u` in warm-session state
- the server persists `relayerSigningShareB64u` and
  `relayerVerifyingShareB64u` in the Ed25519 key store

Those caches improve latency, but they are not equally fundamental today:

- client cache: already optional in practice because the client can lazily
  reconstruct `xClientBaseB64u` on demand
- server cache: still used by the live sign path for the hot path, but cache
  loss is now recoverable because session HSS finalize can reinsert the missing
  relayer share material

## How The Single-Key HSS Design Works

### Canonical Hidden Lifecycle

Let:

- `y_client` be the client hidden root derived from passkey PRF output
- `y_relayer` be the server hidden root derived from server root material
- `tau_client` and `tau_relayer` be hidden rerandomization inputs

The fixed hidden lifecycle is:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `tau = tau_client + tau_relayer mod l`
- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`
- `A = [a]B`

Important distinctions:

- `d` is the canonical hidden seed
- `a` is the canonical hidden signing scalar
- `x_client_base` and `x_relayer_base` are the operational base shares used for
  threshold signing

This means signing and export are two views over one key lifecycle, not two
different keys.

### Registration

Registration currently does this:

1. complete WebAuthn registration
2. derive client HSS inputs from passkey PRF material
3. call relay HSS `prepare`
4. evaluate locally
5. call relay HSS `finalize`
6. persist server-side Ed25519 registration material
7. create the NEAR account and bind the canonical public key

The server-side registration HSS finalize path derives:

- canonical public key
- `relayerSigningShareB64u`
- `relayerVerifyingShareB64u`
- `relayerKeyId`

That material is then stored for later signing.

### Warm Session And Unlock

Unlock and first-use signing rely on:

- session/auth state that tells the client which relayer key and threshold
  session to use
- optional warm cache of `xClientBaseB64u`

If the client cache is absent, the client already knows how to:

1. re-derive client HSS inputs from `prf.output`
2. prepare an HSS request
3. run a session-bound HSS ceremony
4. recover `xClientBaseB64u`
5. re-cache it

### Signing

The live server sign path currently does:

1. load relayer key material by `relayerKeyId`
2. use stored `relayerSigningShareB64u`
3. produce Ed25519 threshold commitments and signature shares

That means the hot sign path still prefers persisted relayer share cache
material, but it is no longer a permanent outage if that cache entry is lost.

### Export

Ed25519 export means canonical seed export only.

Supported artifact:

- `near-ed25519-seed-v1`

Export reconstructs canonical seed `d`, derives the public key from that seed,
and fails closed on mismatch before emitting any export artifact.

## Why The Current Server Cache Is Not Ideal

The clean architectural story is:

- the client secret root is re-derived from passkey PRF
- the server secret root is re-derived from server root material
- the system does not fundamentally depend on durable storage of operational
  shares

Today, the client is already close to that model.

The server is not yet fully there because it still treats
`relayerSigningShareB64u` as required account-lifetime key material.

That has two drawbacks:

1. a relayer key-store loss currently becomes a hard Ed25519 outage until
   operator intervention
2. the implementation does not fully realize the intended safety property that
   operational shares are recoverable from the two real roots plus authenticated
   client participation

## Important Constraint

The relayer share cannot be recovered by the server alone from server root
material.

That is because `x_relayer_base` depends on both parties' hidden inputs:

- `y_client`
- `y_relayer`
- `tau_client`
- `tau_relayer`

So the correct recovery model is:

- not server-only recovery
- but client-assisted self-heal on the next authenticated HSS ceremony

That is still enough to remove the relayer share as a correctness dependency on
durable storage.

## Implemented Self-Heal Design

### Goal

If the Ed25519 relayer share cache is missing, the next authenticated
client-assisted HSS session should:

- reconstruct the relayer share
- reinsert it into the Ed25519 key store
- continue the active flow

This should work for:

- session-bound lazy reconstruction before signing
- explicit warm-session repair flows
- future registration or account-sync repair paths

### Desired Behavior

When a sign path resolves `relayerKeyId`:

- if the key store entry exists, use it as today
- if the key store entry is missing, do not fail permanently
- instead require a valid single-key HSS threshold session and run a repair ceremony
- derive and persist:
  - `relayerSigningShareB64u`
  - `relayerVerifyingShareB64u`
- continue signing

This makes durable relayer share persistence a performance cache, not a hard
correctness dependency.

### Current Self-Heal Flow

The live repair flow now works like this:

1. the sign path resolves `relayerKeyId`
2. if the key exists, signing continues on the normal hot path
3. if the key is missing, the client forces one fresh session-bound HSS
   ceremony
4. session HSS finalize validates the authenticated scope and opens fresh
   `xRelayerBase`
5. the server derives and stores:
   - `relayerSigningShareB64u`
   - `relayerVerifyingShareB64u`
6. the client retries the sign once
7. if the repair attempt still fails, the flow returns a precise error instead
   of silently continuing

This is intentionally client-assisted. The server does not claim to recover the
share from server root material alone.

### What Is Verified

The current implementation now has explicit coverage for:

- successful self-heal after Ed25519 relayer key-store loss
- rejection of repair when account scope does not match the authenticated
  threshold session
- rejection of repair when HSS binding does not match the prepared session
- structured logs for:
  - relayer share cache hit
  - relayer share cache miss
  - self-heal success
  - self-heal failure
  - repair latency in HSS finalize timing logs

## Proposed Implementation Plan

### Phase 1: Define Repair Inputs

Create a narrow internal repair surface that can rebuild server Ed25519 key
material from:

- authenticated threshold session context
- canonical HSS context binding
- relayer server root material
- client-provided HSS request/evaluation participation

Status: landed.

This surface does not accept arbitrary unauthenticated "rebuild my key"
requests.

### Phase 2: Build A Server Self-Heal Path

Add a dedicated internal helper that:

1. validates the threshold session belongs to the expected account and key
   purpose
2. runs the server side of the HSS ceremony
3. opens server output
4. derives `relayerVerifyingShareB64u`
5. stores repaired key material
6. emits structured audit logs

Status: landed.

This helper is explicit and testable rather than hidden inside one large sign
handler.

### Phase 3: Add Missing-Key Fallback To Signing

Update the live Ed25519 sign path so that:

- `missing_key` becomes a repair trigger when valid authenticated session
  context is available
- repair is attempted once
- repaired key material is stored
- the sign flow resumes
- if repair still fails, the caller gets a precise error

Status: landed.

This does not silently invent new relayer key IDs or bypass context binding.

### Phase 4: Tighten Cache Semantics

Status: landed for observability and recoverability; cache policy remains open.

After the repair path exists:

- document the relayer key store as a warm cache of operational share material
- make cache loss a recoverable condition
- keep metrics on cache hit, cache miss, repair success, and repair latency

### Phase 5: Reevaluate Whether Durable Relayer Shares Should Remain Default

Status: still open.

Once self-heal is proven stable, decide whether to keep persistent relayer
shares as:

- default warm cache for latency, or
- optional cache that can be disabled in stricter environments

Do not make that decision before repair reliability is proven.

## Security Rules For Self-Heal

The repair path must preserve the same security rules as normal single-key HSS flows:

- no server-only reconstruction claim
- no raw client-root disclosure to the server
- no raw server-root disclosure to the client
- no repair without authenticated threshold session context
- no repair without strict binding to the expected account, RP ID, key purpose,
  key version, and relayer key ID
- repaired material must be verified against the expected bound public key
- repair events must be auditable

## Operational Guidance

The intended operational model after this work lands is:

- warm caches make signing fast
- cache loss does not destroy the ability to sign
- the next client-assisted HSS session repairs the relayer share cache
- disaster recovery is rooted in:
  - server root material
  - client passkey PRF material
  - authenticated HSS participation

That is much cleaner than treating the persisted relayer share as irreplaceable
account state.

## Cache Policy

The cache policy is now explicit:

- persistent relayer shares remain the default warm cache
- the normal hot sign path should continue to use stored
  `relayerSigningShareB64u` and `relayerVerifyingShareB64u`
- relayer-share self-heal exists as the recovery path when that cache is lost
- self-heal is not the intended steady-state signing path

This means the product keeps the lower-latency operational profile of a warm
server cache while removing cache loss as a permanent outage condition.

## Plan Checklist

- [x] Single-key HSS registration uses HSS prepare/finalize
- [x] Single-key HSS signing uses canonical Ed25519 key lifecycle
- [x] Single-key HSS export uses verified seed export only
- [x] Client-side `xClientBaseB64u` can be lazily reconstructed when missing
- [x] Add a dedicated internal Ed25519 relayer-share repair helper
- [x] Define the authenticated session/context requirements for repair
- [x] Implement server-side relayer-share self-heal from client-assisted HSS
- [x] Persist repaired `relayerSigningShareB64u`
- [x] Persist repaired `relayerVerifyingShareB64u`
- [x] Add missing-key fallback to the live Ed25519 sign path
- [x] Add structured audit logs for repair attempts and outcomes
- [x] Add metrics for cache hit, cache miss, repair success, repair failure,
      and repair latency
- [x] Add unit tests for missing-key repair success
- [x] Add unit tests for missing-key repair rejection on wrong account or
      wrong binding
- [x] Add integration coverage for sign-after-relayer-cache-loss
- [x] Decide whether persistent relayer shares remain default warm cache or
      become optional

## References

- [docs/hss-export-key.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/hss-export-key.md)
- [docs/stateless-shared-root-ed25519.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/stateless-shared-root-ed25519.md)
- [crates/ed25519-hss/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
