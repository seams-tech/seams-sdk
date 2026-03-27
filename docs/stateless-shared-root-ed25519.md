# Stateless Shared-Root Ed25519 Plan

Date updated: March 24, 2026

## Objective

Define an Ed25519 lifecycle that is:

- stateless for long-lived server-side source-of-truth key material,
- recoverable after accidental primary database loss,
- compatible with standard NEAR `ed25519:` private-key export,
- fast on the normal signing path by using a durable server-side relayer base
  share plus a durable wrapped client base share,
- portable to tenant-specific self-hosting where appropriate.

This is an alternative to the persisted-relayer-share model in
[`homomorphic-key-export-ED25519.md`](/Users/pta/Dev/rust/simple-threshold-signer/docs/homomorphic-key-export-ED25519.md).

## Core Idea

Use a deterministic shared root as the canonical Ed25519 secret source of truth:

- client root share is derived from WebAuthn `prf.output`,
- server root share is derived from a tenant-specific master secret,
- the canonical Ed25519 seed is defined jointly from those two shares,
- export reconstructs that canonical seed,
- signing uses:
  - a durable server-side cached relayer base share derived from that root,
  - a durable wrapped client base share stored in IndexedDB,
  - worker-memory unwrapping of that client base share during unlock.

This means:

- no long-lived per-account Ed25519 relayer signing share is the source of truth,
- durable server base shares and wrapped client base shares are only performance cache,
- cache loss hurts availability and latency, not recoverability,
- accidental primary DB loss should not permanently destroy Ed25519 accounts.

## Strict Architectural Rule

There is exactly one Ed25519 lifecycle:

- stateless shared-root Ed25519,
- one canonical public key per `(orgId, accountId, keyPurpose, keyVersion)`,
- one deterministic client/server root-share derivation model,
- one server-durable / client-wrapped-base-share model for hot-path signing,
- no alternate derived-share fallback,
- no persisted-relayer-share model as the source of truth,
- no local-only Ed25519 lifecycle.

Implementation consequence:

- persisted Ed25519 signing material may exist only as a disposable performance cache,
- it must never be treated as the only recoverable copy of server-side Ed25519 key state.

## Why This Model Exists

The persisted-relayer-share model has a serious operational weakness:

- if the server loses the primary Ed25519 key store and backups, signing and export may be permanently broken for affected accounts.

The stateless shared-root model changes the source of truth:

- the durable secret source is the tenant master secret on the server plus WebAuthn-derived client material,
- not a per-account persisted relayer share record.

That makes the system more resilient to catastrophic DB loss at the cost of a
more complex one-time share-construction/rebuild flow.

## Properties

### Source of truth

- client share is deterministic from WebAuthn `prf.output`,
- server share is deterministic from a tenant-specific master secret,
- canonical Ed25519 seed is jointly defined from those two shares,
- long-lived per-account server key material is derivable, not primary persisted state.

### Performance model

- normal unlock/signing can be roughly as fast as the persisted-share model
  because:
  - the server caches an account-scoped relayer base share durably,
  - the client caches a wrapped client base share durably in IndexedDB,
  - unlock only derives a KEK from a separate PRF output and unwraps the base share into worker memory,
- the heavy root-to-share construction runs only during registration,
  rotation, link-device, or full cache-rebuild/recovery flows,
- reusable garbled tables are only a rebuild-path optimization, not part of normal unlock,
- database loss should degrade to "rebuild derived-share cache on a recovery-capable flow"
  rather than permanent key loss.

### Export model

- standard NEAR-wallet-compatible seed export remains possible,
- export reconstructs the canonical seed rather than a scalar-only secret,
- homomorphic export works over the root-share domain, not over a long-lived persisted relayer export share record.

### Tenant portability

- tenant-specific master secrets fit this model well,
- handover to tenant self-hosting is cleaner because the tenant can receive a tenant-scoped root secret rather than a database dump of relayer shares,
- RP-ID continuity still matters for passkey portability.

## Mathematical Model

### Root-share domain

Let:

- `K_org` be a tenant-specific server master secret,
- `ctx` be a deterministic context binding:
  - `orgId`
  - `accountId`
  - `keyPurpose`
  - `keyVersion`
  - participant ids
  - derivation version

Define:

- `y_client = HKDF_u256(prf.output, "ed25519/root-share/client:v1", ctx)`
- `y_relayer = HKDF_u256(K_org, "ed25519/root-share/relayer:v1", ctx)`

Interpret both in `Z_(2^256)`.

Define the canonical seed integer:

- `m = y_client + y_relayer mod 2^256`

Then:

- `d = LE32(m)`

Where:

- `d` is the canonical 32-byte Ed25519 seed,
- `LE32` means 32-byte little-endian encoding.

### Canonical Ed25519 key

From `d` derive:

- `h = SHA-512(d)`
- `a = clamp(h[0..31])`
- `prefix = h[32..63]`
- `A = [a]B`

Where:

- `a` is the Ed25519 signing scalar,
- `A` is the canonical public key,
- exported NEAR private key is `ed25519:` + base58(`d || A`).

### Important consequence

This model makes the canonical seed `d` the root of truth.

That means:

- export is straightforward,
- signing must not treat a long-lived persisted relayer share as canonical state,
- signing must derive:
  - a durable server-side relayer base share,
  - a durable wrapped client base share,
  from the shared root.

## Server-Durable / Client-Wrapped Base-Share Model

### High-level flow

During registration, rotation, link-device, or explicit cache rebuild:

1. client derives `y_client` from WebAuthn `prf.output`,
2. server derives `y_relayer` from `K_org`,
3. client and server run a conversion protocol,
4. that protocol yields:
   - a durable server-side relayer base share,
   - a client base share,
   - public verification metadata,
   - optional reusable GC / base OT artifacts for future rebuilds,
5. server persists only the relayer base share plus binding metadata,
6. client wraps `x_client_base` under a KEK derived from a separate PRF output
   and persists the wrapped share in IndexedDB inside the cross-origin iframe,
7. client may also persist reusable per-account garbled tables / base OT setup
   for rebuild-only fallback,
8. on unlock, the client derives the KEK, unwraps `x_client_base` into worker
   memory only, and registers it in the signing-session system,
8. normal transaction signing uses:
   - in-memory `x_client_base`
   - durable server `x_relayer_base`
   until the signing session ends.

This means:

- the heavy conversion step is not on the normal unlock path,
- normal signing should not feel materially slower than the persisted-share model after unlock completes,
- database loss forces a cache-rebuild flow, not account loss.

### Derived-share output spec

The conversion protocol should derive and persist only the minimum state needed
to support:

- durable server-side relayer base-share storage,
- durable wrapped client base-share storage,
- canonical public-key verification.

For v1, the conversion protocol should output an account-scoped FROST package:

- `(orgId, accountId, keyPurpose, keyVersion, participantIds, derivationVersion)` binding,
- canonical public key `A`,
- one private durable relayer signing share for the server,
- one private client base share that must be wrapped before durable storage,
- one public verifying share per participant,
- optional client-consumable rebuild artifact metadata,
- cache generation / replacement metadata.

For the default 2-of-2 participant set `(1, 2)`, the durable signing shares
must realize the same canonical signing scalar `a`:

- `a = 2 * x_client_base - x_relayer_base mod l`

Design rule:

- the canonical public key is deterministic from the root shares and canonical account context,
- the exact base-share values may change across rebuilds because the
  conversion protocol may rerandomize the cached FROST base-share representation,
- rebuild may use hidden randomness internally, but the resulting durable share
  package must remain bound to the same canonical public key `A`.

### V1 design decision

For v1, the conversion flow should:

- derive a durable account-scoped server relayer base share,
- store the relayer base share durably on the server,
- derive a durable account-scoped client base share,
- require the client to wrap `x_client_base` under a KEK derived from a
  separate PRF output before storing it durably,
- allow reusable per-account garbled tables and reusable base OT setup as a
  rebuild-only fallback on the client,
- not precompute nonce commitments as part of the conversion flow.

Rationale:

- the source-of-truth problem is solved by the root-share model,
- the hot-path latency problem is solved by:
  - server-side durable `x_relayer_base`,
  - client-side durable wrapped `x_client_base`,
  - unlock-time KEK derivation and unwrapping into worker memory only,
- the full cache-build protocol becomes a rare lifecycle operation rather than a
  routine unlock step,
- reusable GC only matters for rebuild/bootstrap flows,
- nonce precomputation can be added later as a bounded optimization if needed,
- keeping nonce generation out of the conversion flow reduces statefulness and
  replay risk.

### Cache model

The cache may be persisted durably, but it is not the source of truth.

The persisted state should hold only:

- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`
- canonical public key
- participant ids
- server durable relayer base-share material
- client durable wrapped base-share metadata
- optional reusable rebuild-artifact metadata
- cache generation metadata
- derivation version

Cache rules:

- server durable-base-share hit + wrapped client-share hit:
  - unlock unwraps `x_client_base` quickly and proceeds to signing,
- missing reusable garbled tables or base OT setup:
  - fetch or refresh them only when a rebuild-capable flow needs them,
- missing server durable base share:
  - trigger explicit cache rebuild or recovery flow,
- missing or unwrap-failed wrapped client base share:
  - trigger explicit cache rebuild, link-device, or recovery flow,
- cache contents must be disposable and re-creatable from the shared root model.

## Signing Model

### Desired behavior

For normal transaction signing:

- signing uses:
  - worker-memory `x_client_base`
  - durable server `x_relayer_base`,
- per-sign latency should be roughly comparable to the persisted-share model on cache hit,
- the heavy conversion is not part of the normal unlock/sign path.

### Normal unlock behavior

Normal unlock should:

- derive a KEK from a separate WebAuthn PRF output such as `prf.second`,
- validate that the wrapped-share metadata matches the canonical account context,
- load the wrapped `x_client_base` envelope from IndexedDB in the cross-origin iframe,
- unwrap `x_client_base` into worker memory only,
- store `x_client_base` only in the existing signing-session warm-state model,
- proceed directly into ordinary FROST signing if:
  - server durable `x_relayer_base` exists,
  - unwrap succeeds.

Normal unlock should not:

- rerun the full cache-build protocol by default,
- require a GC or TEE round trip,
- hide missing server durable state behind an ordinary sign request.

If unlock cannot proceed, the client should surface:

- `cache_rebuild_required` when:
  - the server durable relayer base share is missing,
  - the wrapped client base share is missing,
  - the wrapped client base share cannot be unwrapped,
  - the canonical cache generation is missing or invalid.

The client should route into the appropriate refill/rebuild flow instead of
silently turning an ordinary sign into a heavy lifecycle operation.

## Export Model

### Canonical export

Export reconstructs `d` from the root-share domain:

- client reconstructs or HE-encrypts its root share contribution,
- server contributes its root share contribution,
- worker reconstructs `m`,
- worker decodes `d = LE32(m)`,
- worker derives `A`,
- worker verifies `A` equals the expected public key,
- worker emits `ed25519:` + base58(`d || A`) only on match.

### HE compatibility

The same shared-root model works naturally with homomorphic export:

- the additive domain is `Z_(2^256)`,
- the export target is the canonical seed,
- no scalar-only export artifact is needed.

## Root-To-Derived-Share Conversion Protocol

This section outlines the recommended v1 protocol for converting:

- additive root shares over the canonical seed domain

into:

- a durable server-side FROST relayer base share plus client wrapped-base-share state over the Ed25519 scalar field

without revealing `d` or `a` to either party.

### Protocol choice

For v1, the cleanest correctness reference is:

- malicious-secure 2-party computation for the `d -> a` conversion,
- outputs only:
  - durable server-side relayer base-share state,
  - client base-share state,
  - optional reusable client rebuild-time artifacts,
  - canonical public-key binding data,
- keeps local curve math outside the secure computation for verifying-share publication and validation.

Important implementation note:

- this is the clearest security-model reference design,
- it is not yet the frozen production backend choice,
- because this conversion is rare, v1 should optimize for correctness and simplicity first rather than for sub-second unlock latency.

### Inputs

Client private inputs:

- `y_client in Z_(2^256)`
- fresh hidden base-share coefficient contribution `tau_client in Z_l`
- canonical context `(orgId, accountId, keyPurpose, keyVersion, participantIds, derivationVersion)`
- fresh `cacheBuildId`

Server private inputs:

- `y_relayer in Z_(2^256)`
- fresh hidden base-share coefficient contribution `tau_relayer in Z_l`
- the same canonical context
- the same `cacheBuildId`

Shared public inputs:

- participant ids for v1, currently `(1, 2)`
- protocol version / ciphersuite identifiers

### MPC computation

Inside the 2-party secure computation, compute:

1. canonical seed integer
   - `m = y_client + y_relayer mod 2^256`
   - `d = LE32(m)`

2. canonical Ed25519 signing scalar
   - `h = SHA-512(d)`
   - `a_bytes = clamp(h[0..31])`
   - `a = LE256(a_bytes) mod l`

3. hidden base-share coefficient
   - `tau = tau_client + tau_relayer mod l`
   - if `tau == 0`, abort and retry cache build with fresh `tau_*`

4. 2-of-2 FROST base-share polynomial
   - `g(z) = a + tau * z mod l`

5. base-share outputs
   - `x_client_base = g(1) = a + tau mod l`
   - `x_relayer_base = g(2) = a + 2 * tau mod l`

6. canonical public key
   - `A = [a]B`

The secure computation outputs:

- to client only:
  - `x_client_base`
- to server only:
  - `x_relayer_base`
- to both:
  - `A`
  - canonical context binding
  - `cacheBuildId`
  - cache-build success / retry bit
  - wrapped-share binding metadata

Important:

- `tau` itself is never output,
- `d` is never output,
- `a` is never output.

### Public verifying-share publication

After secure computation completes:

1. client computes:
   - `X_client_base = [x_client_base]B`
2. server computes:
   - `X_relayer_base = [x_relayer_base]B`
3. both sides exchange their public verifying shares over the authenticated
   cache-build channel
4. both sides verify:
   - `2 * X_client_base - X_relayer_base = A`

If the equality fails, cache build fails and the derived share cache must not be committed.

This keeps expensive point multiplication outside the secure computation while
still binding the cached shares to the canonical public key.

### Why this works

For participant ids `(1, 2)`, a Shamir polynomial:

- `g(z) = a + tau * z`

has:

- `g(1) = a + tau`
- `g(2) = a + 2 * tau`

and recombines with the standard Lagrange coefficients:

- `a = 2 * g(1) - g(2) mod l`

So the server durable base share and the client base share are valid
FROST shares of the same canonical signing scalar `a`, while each single share
still hides `a`.

### Client wrapping after cache build

After cache build succeeds, the client must wrap `x_client_base` before any
durable storage:

1. derive a KEK from a separate WebAuthn PRF output such as `prf.second`,
2. domain-separate that KEK derivation from root-share derivation labels,
3. bind the KEK derivation to the canonical account context and backend
   version,
4. encrypt `x_client_base` into a durable envelope,
5. persist only the wrapped envelope and its metadata in IndexedDB inside the
   cross-origin iframe.

The client may keep plaintext `x_client_base` in worker memory for immediate
post-registration signing, but plaintext `x_client_base` must not be stored
durably outside the encrypted envelope.

### Security properties

This protocol satisfies the required lifecycle properties:

- neither party learns `d`,
- neither party learns `a`,
- neither party learns the hidden base-share coefficient `tau`,
- both parties learn the same canonical public key `A`,
- the server receives one durable relayer base share,
- the client receives one base share for immediate use and for durable wrapped storage,
- reusable GC artifacts are only a rebuild-path optimization,
- cache loss destroys only performance state, not the root of truth.

The key privacy point is that `tau` is hidden from both parties because it is
formed from private random contributions inside the secure computation. If
either party knew the full `tau`, that party could recover `a` from its base
share.

### Failure semantics

If cache build fails:

- because `tau == 0`,
- because verifying-share validation fails,
- because the durable server base-share cache or client wrapped-share write fails,
- or because either party loses state before finalize,

then the entire cache-build attempt is discarded and must be retried from the
start with:

- a fresh `cacheBuildId`,
- fresh `tau_client`,
- fresh `tau_relayer`.

No partially created relayer base shares, wrapped client-share envelopes, or in-flight data
should be reused.

## Cache-Build API Spec

For v1, freeze cache construction as a dedicated route family:

- `POST /threshold-ed25519/cache-build/init`
- `POST /threshold-ed25519/cache-build/step`
- `POST /threshold-ed25519/cache-build/finalize`

This route family exists to hide the internal secure-computation rounds behind
one logical cache-construction or cache-rebuild flow.

### Flow triggers

This API is for:

- registration,
- rotation,
- link-device,
- explicit cache rebuild after client/server cache loss.

This API is not for:

- routine wallet unlock,
- ordinary transaction signing,
- every warm-session refresh.

### Auth and binding rules

All cache-build routes must require an authenticated lifecycle context for the
same:

- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`

Freeze this generic wrapper field for v1:

- `lifecycleAuthId`

The outer caller may back `lifecycleAuthId` with registration auth, threshold
auth, device-link auth, or recovery auth, but the inner cache-build API should
not multiply distinct route families for each flow.

The server must reject any cache-build request whose authenticated subject does
not match the requested canonical context.

### Identifiers

Freeze these identifiers for v1:

- `cacheBuildId`: client-generated random 128-bit identifier for one cache-build attempt
- `cacheGenerationId`: server-generated identifier for the committed server durable-cache generation

Rules:

- `cacheBuildId` is one-time-use,
- `cacheGenerationId` is only allocated after successful finalize,
- any restart uses a fresh `cacheBuildId`.

### Request and response spec

#### `POST /threshold-ed25519/cache-build/init`

Purpose:

- start a new cache-build attempt,
- validate canonical context,
- create server-side temporary build state,
- process the first secure-computation message.

Request body:

- `lifecycleAuthId`
- `operationKind`:
  - `"registration" | "rotation" | "link-device" | "cache-rebuild"`
- `cacheBuildId`
- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`
- `participantIds`:
  - must equal `[1, 2]` for v1
- `derivationVersion`
- `clientMpcMessageB64u`

Response body:

- `cacheBuildId`
- `status`:
  - `"continue"` or `"await_client_base_verifying_share"`
- `serverMpcMessageB64u`
- `cacheBuildExpiresAtMs`
- `nextStepIndex`
- `publicKey`:
  - present only when secure computation is complete and verifying-share exchange is next

#### `POST /threshold-ed25519/cache-build/step`

Purpose:

- continue the in-flight secure-computation transcript.

Request body:

- `lifecycleAuthId`
- `cacheBuildId`
- `stepIndex`
- `clientMpcMessageB64u`

Response body:

- `cacheBuildId`
- `status`:
  - `"continue"` or `"await_client_base_verifying_share"`
- `serverMpcMessageB64u`
- `cacheBuildExpiresAtMs`
- `nextStepIndex`
- `publicKey`:
  - present only when secure computation is complete and verifying-share exchange is next

#### `POST /threshold-ed25519/cache-build/finalize`

Purpose:

- exchange public verifying shares,
- verify share/public-key consistency,
- commit:
  - the durable server relayer base-share cache,
  - the client wrapped-base-share metadata.

Request body:

- `lifecycleAuthId`
- `cacheBuildId`
- `clientBaseVerifyingShareB64u`
- `clientCacheBuildTranscriptHashB64u`

Response body:

- `cacheGenerationId`
- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`
- `participantIds`
- `derivationVersion`
- `publicKey`
- `serverBaseVerifyingShareB64u`
- `cacheBuiltAtMs`

### Transcript hash

For v1, finalize must bind a cache-build transcript hash.

Both sides must compute:

- `cacheBuildTranscriptHash = H(protocolVersion || cacheBuildId || canonicalContext || publicKey || mpcTranscriptSummary)`

Rules:

- client sends `clientCacheBuildTranscriptHashB64u` in finalize,
- server compares it to its own computed transcript hash,
- mismatch is a hard failure and the cache-build attempt is discarded.

This prevents committing state when the two sides disagree about the effective
secure-computation transcript or output.

## Cache-Build Retry Semantics

Freeze these retry rules for v1:

- cache-build attempts are rare and safe to restart from scratch,
- cache-build routes are not required to support arbitrary replay/resume after
  ambiguous network failure,
- the safe retry path is always "start a new cache-build attempt".

Specific rules:

1. duplicate `cache-build/init` with the same `cacheBuildId` and identical request may return the same in-flight build state while the attempt is still pending,
2. duplicate `cache-build/init` with the same `cacheBuildId` but different payload is a hard error,
3. if the client loses track of `cache-build/step` progress, it should discard the attempt and restart with a new `cacheBuildId`,
4. if `cacheBuildExpiresAtMs` is exceeded, the attempt is invalid and must be restarted,
5. if finalize fails after secure computation completes, the server must discard the attempt and require a full restart with fresh `tau_*`,
6. if the server loses temporary build state before finalize, it must return `restart_required`,
7. if durable server base-share cache write or client wrapped-share write fails, the cache-build attempt is treated as failed and the client must restart from init.

No route may silently reuse partial cache-build state after failure.

## Server Durable Cache And Client Wrapped-Share Spec

### Cache authority

Freeze the server-durable / client-wrapped-share model for v1 as:

- server: durable account-scoped base-share cache,
- client: IndexedDB-backed wrapped-base-share cache under wallet origin inside the cross-origin iframe,
- client: optional IndexedDB-backed reusable GC / base-OT cache for rebuild-only flows,
- client signing-session state: worker-memory only,
- temporary server in-flight build state during `cache-build/*`.

Rationale:

- normal signing must not depend on rerunning the heavy conversion flow,
- the server needs reusable durable base-share material,
- the client needs a durable wrapped base share for the normal hot path,
- reusable garbled tables and base OT setup are only rebuild-path accelerators,
- all cached material remains disposable because it can be rebuilt from the shared root.

### Server durable cache entry

On successful finalize, the server must persist:

- `cacheGenerationId`
- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`
- `participantIds`
- `derivationVersion`
- `publicKey`
- `relayerBaseSigningShareB64u`
- `relayerBaseVerifyingShareB64u`
- `clientBaseVerifyingShareB64u`
- `cacheBuildTranscriptHashB64u`
- `builtAtMs`
- `lastUsedAtMs`
- ciphersuite / protocol version

The server must not persist:

- `d`
- `a`
- `y_client`
- `y_relayer`
- `tau`

### Client durable wrapped-share entry

On successful finalize, the client must persist in IndexedDB:

- `cacheGenerationId`
- `orgId`
- `accountId`
- `keyPurpose`
- `keyVersion`
- `participantIds`
- `derivationVersion`
- `publicKey`
- `relayerBaseVerifyingShareB64u`
- `wrappedClientBaseShareB64u`
- wrap algorithm / KEK derivation metadata
- optional reusable rebuild-artifact metadata
- optional reusable per-account garbled tables
- optional reusable base OT setup handles or references
- `cacheBuildTranscriptHashB64u`
- `builtAtMs`

The client must not persist:

- `x_client_base`
- `d`
- `a`
- `y_relayer`
- full `tau`

Access rule:

- wrapped-share records are worker-managed and must not be exposed as plaintext
  application-level API outputs.

### Client signing-session state

After unlock unwrap succeeds, the client may cache:

- plaintext `x_client_base`
- matching verifying-share metadata
- `cacheGenerationId`

only inside the existing in-memory signing-session system described in
[signing-sessions.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/signing-sessions.md).

Rules:

- this state is worker-memory only,
- it is zeroized when the signing session ends,
- it is not stored in IndexedDB,
- it is not promoted to canonical or durable key material.

### Temporary server build state

While cache-build is in progress, the server may hold a temporary entry keyed by
`cacheBuildId` containing:

- canonical context,
- authenticated lifecycle binding,
- secure-computation backend state,
- `x_relayer_base` if already available,
- `X_relayer_base` if already available,
- `publicKey` if already available,
- `cacheBuildTranscriptHashB64u` if already available,
- `cacheBuildExpiresAtMs`

This entry is temporary:

- it must be deleted on successful finalize,
- it must be deleted on failure or expiry,
- it must never be promoted to canonical long-lived key state.

### Cache invalidation rules

Durable cached derived shares must be invalidated when:

- `keyVersion` changes,
- participant ids or derivation version mismatch,
- public-key binding validation fails,
- explicit cache rebuild is requested,
- client and server cache generations diverge and cannot be reconciled safely.

## Normal Signing State

The hot-path signing inputs are:

- worker-memory `x_client_base`,
- durable server `x_relayer_base`,
- verifying-share metadata,
- fresh per-sign nonces.

Ordinary Ed25519 signing should use:

- client worker-memory `x_client_base`,
- server durable base share,
- stored base verifying shares,
- fresh RFC 9591-style nonce generation for each sign attempt,
- temporary in-flight sign state only until finalize.

The system should not introduce a second durable client runtime-share cache
layer for v1.

## In-Flight Signing Semantics

Nonce material is per-sign-attempt, one-time-use, and ephemeral.

This means:

- no global monotonic nonce counter is required,
- no long-term nonce history is required,
- but each active sign attempt must retain its own in-flight nonce state until
  that sign attempt either completes or is aborted.

Rules:

- loss of in-flight nonce state invalidates that sign attempt,
- the system must restart the sign attempt with fresh nonces rather than resume,
- durable cache loss and in-flight sign loss are separate failure domains.

## Backend Direction For The Root-To-Derived-Share Step

The protocol above freezes the required output shape. It does not yet freeze the
exact backend implementation used to realize the `d -> a` conversion.

This plan now freezes:

- one SSR lifecycle,
- two allowed conversion backends,
- backend selection scoped per tenant and per environment,
- identical canonical inputs/outputs regardless of backend.

### Option A — Generic malicious-secure 2PC over `SHA-512 + clamp`

Pros:

- simplest end-to-end security story,
- directly matches the current SSR math,
- easiest option to reason about formally.

Cons:

- likely the highest runtime cost,
- significant implementation complexity,
- likely worse than necessary for a fixed one-block RFC 8032 seed expansion.

Status:

- treat as the correctness reference and benchmark baseline,
- do not treat as the preferred production backend.

### Option B — Custom fixed-function 2PC specialized to one-block `SHA-512 + clamp`

Pros:

- potentially much faster than generic 2PC,
- preserves the current SSR trust model,
- can exploit the fact that Ed25519 seed expansion uses a fixed 32-byte input and therefore a fixed single-block SHA-512 evaluation with fixed padding,
- can reuse the same deterministic garbled subcircuit across rebuild-capable flows for the same credential and canonical context,
- keeps ordinary unlock free of GC traffic when a wrapped client base share already exists.

Cons:

- this is cryptography-protocol design work, not routine engineering,
- higher audit and correctness burden than using a generic framework,
- easy to get wrong if the protocol is ad hoc.

Status:

- preferred pure-cryptographic direction for this project,
- should be designed as a fixed-function protocol, not as a generic MPC engine.

### Preferred shape of Option B

If we pursue a custom protocol, it should be a fixed-function 2-party protocol
for exactly:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- one-block RFC 8032 `SHA-512(d)` with fixed padding
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`

Key design constraints:

- optimize for the fixed 32-byte Ed25519 seed input, not arbitrary SHA-512,
- keep the deterministic nonlinear subcircuit reusable for the same credential and canonical context,
- keep point multiplication outside the secure computation when possible,
- reveal only cached shares and public binding data,
- never reveal `d`, `a`, or full `tau`.

Preferred implementation shape:

- mixed-mode circuit or other fixed-function realization specialized to one-block `SHA-512 + clamp`,
- reusable per-account garbled tables cached in IndexedDB,
- reusable base OT setup cached client-side,
- fresh small online OT / label-delivery phase only for cache-build and rebuild-capable flows,
- correctness and simplicity first,
- garbled-circuit prefetch as a required architectural property of the registration flow,
- aggressive preprocessing beyond prefetch only if later benchmarks justify it.

GC reuse rule:

- only the deterministic nonlinear subcircuit is reused,
- the reusable artifact is pinned to the same credential and canonical context,
- the online OT / input-label delivery is fresh on every cache-build or rebuild attempt,
- no implementation may replay a stale unlock transcript as if it were a fresh evaluation.

### Garbled-circuit prefetch requirement

Freeze these registration requirements for v1:

- the reusable garbled tables must be fetched and pinned before the WebAuthn ceremony begins,
- reusable base OT setup required for evaluator input delivery must also complete before the
  WebAuthn ceremony begins,
- the registration UI must not enable the final "Register" / WebAuthn button
  until garbling prefetch and OT setup are both ready,
- the large garbling transfer must not sit on the post-WebAuthn critical path,
- the same garbled tables may be reused on later unlocks for the same
  credential and canonical context during rebuild-capable flows.

This requirement exists because:

- registration already has unavoidable waiting points,
- the custom 2PC payload is large enough that it should be overlapped with
  user-driven registration steps,
- the online phase should be kept close to an ordinary threshold-signing round.

### Online-phase budget

Freeze the post-prefetch online target budget as:

- `< 15 KB` total online bytes,
- `2` network round trips,
- `< 500 ms` end-to-end online conversion time on target devices.

This budget applies to the input-dependent phase after:

- garbling prefetch completes,
- OT setup completes,
- WebAuthn produces `prf.output`.

This budget applies to cache-build and rebuild-capable flows, not to ordinary
unlock.

If implementation measurements miss this budget materially, the backend design
must be revised before rollout.

### Experimental Conversion Directions

This section captures the most plausible pure-cryptographic research directions
for the hidden `d -> a` conversion.

All three directions assume the same SSR lifecycle:

- shared root shares over canonical seed `d`,
- hidden conversion to Ed25519 signing scalar `a`,
- output as durable base FROST shares,
- neither client nor server sees plaintext `d` or plaintext `a`.

#### GC-heavy

Shape:

- keep most or all of the fixed one-block RFC 8032 seed expansion in a
  garbled-circuit style backend,
- optimize active security and arithmetic handling around that core,
- treat generic malicious-secure 2PC as the baseline reference.

Strengths:

- easiest direction to reason about from the current SSR math,
- strongest continuity with the current fixed-function 2PC plan,
- clearest benchmark baseline for bandwidth and latency.

Weaknesses:

- likely the highest communication/storage cost,
- easiest direction to end up with multi-hundred-KB or MB-scale artifacts,
- less likely to hit aggressive product budgets without substantial
  optimization.

Assessment:

- useful as the reference implementation shape and benchmark floor,
- not the most promising long-term pure-crypto optimization path.

#### Mixed-circuit `edaBits` / `mv-edabits`

Shape:

- keep the one-block `SHA-512(d)` evaluation in the Boolean world,
- convert the relevant outputs into arithmetic-domain shares using
  `edaBits` / `mv-edabits`-style machinery,
- perform scalar-domain postprocessing and base-share derivation in the
  arithmetic domain.

Strengths:

- most directly targets the real structure of the problem:
  - SHA-512 compression is bit-oriented,
  - Ed25519 scalar and share derivation are arithmetic-oriented,
- avoids forcing the full pipeline into one circuit style,
- best recent literature signal for reducing communication while preserving the
  "neither side sees `d`" invariant.

Weaknesses:

- still real protocol-design work,
- requires careful Boolean-to-arithmetic conversion design and auditing,
- more specialized than a straightforward GC-heavy implementation.

Assessment:

- most promising experimental pure-crypto direction,
- best candidate if we want to push beyond GC-heavy without changing the trust
  model.

#### Succinct-garbling research track

Shape:

- investigate newer succinct-garbling or HSS-inspired approaches that may
  reduce circuit communication/storage substantially below traditional garbling.

Strengths:

- potentially strongest communication reduction if it works well in practice,
- directly attacks the largest known product risk for pure-crypto conversion.

Weaknesses:

- most research-heavy and least mature option,
- highest implementation and audit risk,
- weakest near-term confidence for production rollout.

Assessment:

- keep as a research track, not the initial implementation plan.

#### Recommendation order

If we revisit experimental hidden `d -> a` work, investigate in this order:

1. mixed-circuit `edaBits` / `mv-edabits`,
2. GC-heavy active-secure backend improvements for the nonlinear/hash-heavy
   core,
3. succinct-garbling research only if communication remains the dominant
   blocker after the first two tracks are explored.

### Option C — TEE / enclave-assisted conversion

Pros:

- much simpler than custom 2PC,
- likely much lower registration/recovery bandwidth,
- avoids shipping the large garbled payload to the client,
- keeps the same SSR canonical seed and export model.

Cons:

- changes the trust model from pure client/server secure computation to enclave trust,
- requires attestation verification, measurement pinning, and enclave ops,
- weaker portability and audit story than pure 2PC.

Status:

- allowed backend for tenants that explicitly opt into enclave trust,
- not the preferred pure-cryptographic direction,
- still part of the same SSR lifecycle.

TEE rule:

- `d` may exist transiently inside the enclave during conversion,
- outside the enclave, neither the client nor the application server may see plaintext `d`,
- this is acceptable only because the tenant explicitly accepts the enclave trust boundary.

### Concrete fixed-function 2PC sketch

This is the concrete shape the production protocol should follow.

#### Private inputs

Client private inputs:

- `y_client in Z_(2^256)`
- `tau_client in Z_l`

Server private inputs:

- `y_relayer in Z_(2^256)`
- `tau_relayer in Z_l`

Public inputs:

- `cacheBuildId`
- canonical context `(orgId, accountId, keyPurpose, keyVersion, participantIds, derivationVersion)`
- protocol version
- ciphersuite identifier

#### Outputs

Client-only output:

- `x_client_base`

Server-only output:

- `x_relayer_base`

Public outputs:

- canonical public key `A`
- transcript / circuit binding digest inputs

#### What stays outside secure computation

These steps should remain outside the secure computation:

- authentication and canonical-context reservation,
- derivation of `y_client` from WebAuthn `prf.output`,
- derivation of `y_relayer` from `K_org`,
- derivation of the client KEK from a separate PRF output such as `prf.second`,
- client-side wrapping of `x_client_base`,
- point multiplication:
  - `X_client_base = [x_client_base]B`
  - `X_relayer_base = [x_relayer_base]B`
- public verifying-share exchange for cache-build base shares,
- the equality checks:
  - `2 * X_client_base - X_relayer_base = A`
- transcript hashing,
- durable cache writes,
- ordinary FROST signing and nonce generation after cache construction.

The secure computation should contain only the hidden nonlinear conversion and
base-share construction:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- one-block `SHA-512(d)`
- `clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `tau = tau_client + tau_relayer mod l`
- `x_client_base = a + tau mod l`
- `x_relayer_base = a + 2 * tau mod l`

#### Circuit/backend components required from an OT-based implementation

The backend should provide:

- malicious-secure garbling or equivalent authenticated circuit evaluation,
- fixed-function circuit support for exactly one-block RFC 8032 seed expansion,
- evaluator input delivery using fresh online OT / OT extension,
- designated-output support so:
  - the client decodes `x_client_base`,
  - the server decodes `x_relayer_base`,
  - both learn public output `A`,
- transcript binding to:
  - `cacheBuildId`
  - canonical context
  - circuit hash / protocol version
- reusable per-account garbled tables pinned to the canonical context and
  backend version,
- reusable base OT setup or OT-extension seeds pinned to the same context.

The fixed-function circuit itself should include:

- 256-bit addition modulo `2^256`,
- fixed-padding one-block SHA-512 schedule and compression,
- clamp bit-masking,
- scalar reduction / canonical scalar conversion into `Z_l`,
- addition of hidden `tau` contributions,
- production of:
  - the base client FROST share,
  - the durable server base FROST share.

#### Registration-flow split

For registration, the intended split is:

1. reserve canonical context and allocate `cacheBuildId`,
2. prefetch reusable per-account garbled tables,
3. complete reusable base OT setup,
4. enable the Register / WebAuthn button,
5. run WebAuthn and derive `y_client`,
6. execute the small online phase,
7. exchange verifying shares and commit:
   - the durable server relayer base share
   - the client wrapped-share metadata
8. wrap `x_client_base` and persist it in IndexedDB inside the cross-origin
   iframe,
9. optionally keep plaintext `x_client_base` in worker memory for immediate
   post-registration signing.

The online phase should not be responsible for:

- downloading or regenerating the reusable per-account garbled tables,
- establishing reusable base OT setup from scratch,
- any other large one-time backend artifact transfer.

### Unlock unwrap model

For v1, freeze normal unlock as:

1. derive a KEK from a separate WebAuthn PRF output such as `prf.second`,
2. load the wrapped local `x_client_base` envelope from IndexedDB in the
   cross-origin iframe,
3. unwrap `x_client_base` into worker memory only,
4. sign normally until lock, tab close, or worker teardown,
5. zeroize plaintext `x_client_base` when the unlocked signing window ends.

Unlock should not:

- persist plaintext `x_client_base`,
- rerun the full cache-build protocol by default,
- require a 2PC or TEE round trip,
- silently fabricate a new cache generation.

### Tenant/environment backend selection

Freeze backend selection as:

- explicit,
- tenant-scoped,
- environment-scoped,
- configured from the console dashboard.

Allowed backend values for v1:

- `2pc-gc-v1`
- `tee-v1`

Rules:

- no silent fallback or downgrade between backends,
- the selected backend must be surfaced to the client during cache-build init,
- the selected backend must be bound into the transcript, cache metadata, and audit logs,
- developer environments may choose differently from production environments,
- backend choice is operational policy, not a separate key lifecycle.

### Backend switching and compatibility

Wallets created under one backend must remain valid under the same SSR lifecycle.

That means:

- a wallet first built with `2pc-gc-v1` may later rebuild its durable cache under `tee-v1`,
- a wallet first built with `tee-v1` may later rebuild its durable cache under `2pc-gc-v1`,
- no key rotation is required solely because the backend changes,
- the canonical seed/public key identity must remain unchanged.

Why this is possible:

- the backend is only a conversion mechanism,
- the source of truth remains the same root-share model,
- both backends must produce the same canonical `d`, `A`, and compatible durable cached FROST shares.

Migration rules:

- backend switching must be an explicit tenant action from the dashboard,
- switching must invalidate old durable cache generations and force a rebuild-capable flow,
- switching must never happen silently during a sign or export request,
- backend provenance must be recorded per cache generation for audit/debug purposes.

### Why HE is not the preferred tool here

Homomorphic encryption is not the natural fit for the `d -> a` conversion.

Additive HE is insufficient because:

- `SHA-512 + clamp` is nonlinear and bit-oriented,
- additions with carries, rotations, and boolean operations are the hard part.

Fully homomorphic encryption could evaluate the function in principle, but:

- that is closer to generic circuit evaluation than to a lightweight HE helper,
- it still leaves the problem of how to output split cached shares rather than a plaintext `a`,
- in practice it is unlikely to be simpler or faster than a specialized 2-party protocol for this interactive setting.

So for this plan:

- use HE for export over the additive root-share domain when appropriate,
- do not assume HE is the right primitive for shielded `d -> a` conversion.

## Tenant-Specific Master Secrets

This model should use tenant-specific server master secrets.

Recommended structure:

- one root secret per tenant: `K_org`,
- wrapped by KMS/HSM or equivalent server-side secret management,
- derived values always bind:
  - `orgId`
  - `accountId`
  - `keyPurpose`
  - `keyVersion`
  - derivation label/version

Benefits:

- smaller blast radius,
- cleaner self-hosting handover,
- explicit tenant isolation,
- simpler tenant-scoped rotation stories.

### Self-hosting handover

If a tenant wants to self-host:

- they should be able to receive `K_org`,
- plus the derivation/version spec,
- plus account/key metadata needed to derive server-side root shares.

Important caveat:

- passkeys are RP-ID scoped,
- if self-hosting changes the effective RP-ID, handing over `K_org` alone is not enough,
- either RP-ID continuity must be preserved, or users must re-enroll / rotate passkeys.

## Strengths

- stateless source of truth for Ed25519 server-side key material,
- avoids catastrophic DB-loss scenarios where per-account relayer shares are lost permanently,
- standard NEAR `ed25519:` seed export stays natural,
- tenant-specific master secrets enable cleaner tenant isolation and handover,
- normal signing can be fast after unlock unwrap succeeds,
- database loss becomes a rebuild event, not necessarily a key-loss event.

## Risks

- the root-to-derived-share conversion protocol is materially more complex than the persisted-share model,
- cache loss now requires an explicit rebuild-capable lifecycle flow,
- client-local durable cache handling becomes security-critical,
- nonce handling remains a critical safety boundary,
- self-host portability still depends on RP-ID/passkey realities,
- the exact conversion backend must be specified and reviewed carefully before implementation.

## Nonce Reuse Caveats

Nonce handling is the biggest cryptographic risk in the signing path.

### What must be true

- durable cache loss must not cause nonce reuse,
- reboot or DB loss must not cause a previously used in-flight nonce state to be replayed,
- multiple servers must not accidentally reuse one-time nonce commitments for the same sign attempt.

### Timestamps are not enough

Do not use timestamps alone as signing nonces.

Why not:

- clocks can drift,
- timestamps can collide under concurrency,
- restarts can repeat timestamp windows,
- low-entropy timestamps are not sufficient secret nonce material,
- "timestamp + message" is not a substitute for a properly generated secret nonce.

Timestamps may be included as metadata or as part of a larger domain-separation context, but they must not be the nonce primitive by themselves.

### Safer direction

For v1, the nonce strategy should follow standard FROST nonce generation with
fresh randomness per signing attempt.

For this plan, the preferred direction is:

1. standard FROST round-one nonce generation with fresh randomness,
2. explicit tracking that a nonce commitment is one-time-use,
3. loss of in-flight sign state invalidates that sign attempt and forces a restart.

Rejected designs:

1. timestamp-only nonces,
2. deterministic per-signature nonces derived only from cached state and message digest,
3. reuse of nonce commitments after restart, replay, or partial failure.

### Future optimization: nonce precomputation

Nonce precomputation means generating fresh FROST round-one nonce material
before a concrete signing request arrives, then storing a bounded pool of
unused nonce commitments for later consumption.

Potential benefit:

- lower hot-path signing latency, especially for the first sign in a burst.

Potential costs and risks:

- more ephemeral state to manage correctly,
- stricter one-time-use guarantees,
- replay/reuse risk after restart or partial failure,
- extra invalidation logic when cached signing material is rebuilt.

Design rule for this plan:

- nonce precomputation is out of scope for v1,
- if added later, it must remain a bounded optimization on top of the server-durable / client-wrapped-base-share model, not a new source of truth,
- precomputed nonce commitments must be one-time-use and must be discarded on ambiguous failure.

## Comparison Against Hybrid Persisted Shares

### SSR with server-durable relayer base share and client-wrapped durable base share

- long-lived Ed25519 source of truth is derivable,
- better disaster recovery story,
- better tenant handover story,
- normal signing can still be fast,
- cache rebuild is more complex than the persisted-share model.

### Hybrid persisted shares

- long-lived Ed25519 relayer shares are persisted,
- simpler overall signing architecture,
- lower implementation risk,
- but DB-loss risk remains unless backups are perfect,
- less elegant as a long-term source-of-truth architecture.

### Summary

- more elegant source-of-truth architecture: stateless shared-root,
- easier near-term implementation: hybrid persisted shares,
- if disaster recovery and tenant portability are hard requirements, stateless shared-root is the stronger long-term model.

## Frozen Specs For This Plan

These should be treated as design inputs unless explicitly revised.

### Root-share derivation

- `y_client` is derived from WebAuthn `prf.output`,
- `y_relayer` is derived from tenant master secret `K_org`,
- both use domain-separated HKDF labels,
- both bind the same context including `orgId`, `accountId`, `keyPurpose`, `keyVersion`, participant ids, and derivation version.

### Canonical seed

- `d = LE32(y_client + y_relayer mod 2^256)`,
- `d` is the only canonical Ed25519 private-key seed,
- `A = [clamp(SHA-512(d)[0..31])]B` is the only canonical Ed25519 public key.

### Server-durable / client-wrapped-base-share signing model

- the durable server relayer base share is the only persisted server-side hot-path base share,
- the client persists a wrapped `x_client_base` envelope durably,
- the client may also persist reusable garbled tables and reusable base OT setup for rebuild-only flows,
- plaintext `x_client_base` exists in worker memory only after unlock unwrap,
- full cache rebuild happens only during registration, rotation, link-device, or explicit recovery/cache-rebuild flows,
- normal unlock runs only KEK derivation plus unwrap, not the full cache-build protocol.

### Cache-build API

- cache construction uses the dedicated route family:
  - `POST /threshold-ed25519/cache-build/init`
  - `POST /threshold-ed25519/cache-build/step`
  - `POST /threshold-ed25519/cache-build/finalize`
- `cacheBuildId` is client-generated and one-time-use,
- `cacheGenerationId` is server-generated after successful finalize,
- transcript-hash binding is mandatory in finalize.

### Unlock unwrap

- unlock derives a KEK from a separate WebAuthn PRF output such as `prf.second`,
- unlock loads the wrapped `x_client_base` envelope from IndexedDB in the cross-origin iframe,
- unlock unwraps `x_client_base` in worker memory only,
- unlock may then register plaintext `x_client_base` into the existing in-memory signing-session state,
- unlock requires a matching server durable relayer-base cache generation,
- unlock never persists plaintext `x_client_base`.

### Signing path

- ordinary signing uses:
  - worker-memory `x_client_base`
  - durable server `x_relayer_base`,
- in-flight sign state is ephemeral and per-attempt only,
- missing wrapped client base-share envelope or unwrap failure requires explicit recovery/capable rebuild flow,
- missing server durable relayer base share requires explicit recovery/capable rebuild flow rather than silent hot-path conversion.

### Nonces

- signing uses fresh FROST nonce generation per signing attempt,
- nonce generation must follow RFC 9591-style fresh-randomness requirements,
- deterministic per-signature nonce derivation is out of scope and rejected for v1,
- timestamp-only nonce schemes are forbidden.

### Export

- export target is only standard `near-ed25519-seed-v1`,
- export reconstructs `d`, not a scalar-only artifact,
- worker must verify derived public key before emitting `ed25519:`.

### Tenant isolation

- use tenant-specific master secrets,
- do not use one global master secret for all tenants,
- all derivations must be versioned and context-bound.

### Backend direction

- there is one SSR lifecycle with two allowed conversion backends:
  - `2pc-gc-v1`
  - `tee-v1`
- backend selection is tenant-scoped and environment-scoped,
- backend selection is configured explicitly from the dashboard,
- backend selection must be surfaced to the client and bound into transcript and cache metadata,
- no silent fallback or downgrade between backends is allowed,
- `2pc-gc-v1` remains the preferred pure-cryptographic backend,
- generic malicious-secure 2PC remains the correctness reference only,
- for `2pc-gc-v1`:
  - registration must prefetch reusable garbled tables and complete reusable base OT setup before WebAuthn begins,
  - the Register / WebAuthn button must remain disabled until prefetch and OT setup are ready,
  - the post-prefetch online phase budget is:
    - `< 15 KB`
    - `2` round trips
    - `< 500 ms`
- for `tee-v1`:
  - `d` may exist only transiently inside the enclave,
  - outside the enclave, neither client nor server may see plaintext `d`.

## Must Resolve Before Implementation

These are the remaining design blockers after freezing the durable-cache lifecycle.

### 1. Registration and rotation context timing

We still need to freeze exactly when:

- `accountId`
- `keyVersion`
- `keyPurpose`

become available during registration and rotation.

If account creation allocates identifiers late, the flow may need:

- a server-issued reserved context before PRF derivation, or
- a revised registration order that makes the canonical context available first.

### 2. Minimum durable metadata after DB loss

SSR removes long-lived per-account relayer key material as the source of truth,
but it does not remove the need for durable account metadata.

We still need to freeze the minimum metadata that must survive or be recoverable:

- org/account/key identifiers,
- credential bindings,
- public-key metadata,
- tenant secret version,
- derivation version,
- durable cache generation metadata.

### 3. Client durable storage boundary

Storage location is resolved for v1:

- the wrapped `x_client_base` envelope lives in IndexedDB under wallet origin inside the cross-origin iframe,
- optional reusable garbled tables and reusable base OT setup also live there for rebuild-only flows,
- plaintext `x_client_base` lives only in the in-memory signing-session system.

Remaining detail to freeze:

- exact KEK derivation and envelope format for the wrapped client base share,
- whether reusable garbled tables / base OT setup need additional wrapping beyond worker-managed IndexedDB storage,
- how wrapped-share refill behaves after local storage wipe,
- how device-link provisions the local reusable garbled-table / base-OT cache on the new device.

### 4. Concurrency and in-flight signing semantics

Before implementation we should freeze:

- whether multiple sign attempts may be open per account after one unlock unwrap,
- whether parallel signs are allowed per device/account pair,
- how in-flight nonce commitments are stored until finalize,
- what exact error is returned when:
  - in-flight sign state is lost,
  - the wrapped client base share is missing or cannot be unwrapped,
  - `x_client_base` is no longer present in worker memory.

### 5. Export binding to the same lifecycle

Export should not be implemented as a side protocol with different context semantics.

Before implementation we should freeze:

- that export uses the same canonical `(orgId, accountId, keyPurpose, keyVersion, participantIds, derivationVersion)` binding,
- that export/init returns the same public-key identity used by signing,
- that stale `keyVersion` or mismatched context is a hard failure.

### 6. Backend attestation and policy surface

We still need to freeze the exact backend-policy details for `tee-v1`:

- attestation format and verification chain,
- enclave measurement / code identity pinning,
- how the selected backend is exposed in the dashboard and SDK config,
- whether some environments may forbid one backend entirely,
- what audit log fields record backend selection and switching.

## Detailed Phased Implementation Plan

### Phase 0 — Scope Freeze And Replacement Decision

- [ ] Freeze stateless shared-root with:
  - durable server `x_relayer_base`
  - client durable wrapped `x_client_base`
  - client durable reusable garbled-table / base-OT fallback cache
  as the single Ed25519 architecture target.
- [ ] Explicitly retire the persisted-relayer-share model as the Ed25519 source of truth.
- [ ] Freeze tenant-specific master secrets as required for Ed25519.
- [ ] Freeze the rule that durable server signing material is performance-only, not canonical state.
- [ ] Freeze the rule that normal unlock/signing does not rerun the full root-to-share conversion.
- [ ] Freeze the rule that the client may persist only a wrapped `x_client_base` envelope durably, never plaintext share material.
- [ ] Freeze one SSR lifecycle with two allowed conversion backends:
  - `2pc-gc-v1`
  - `tee-v1`
- [ ] Freeze that generic malicious-secure 2PC is the correctness reference, not a tenant-facing production backend.
- [ ] Freeze that backend choice is tenant-scoped and environment-scoped.
- [ ] Freeze that backend switching is explicit and rebuild-driven, not silent.

### Phase 1 — Crypto Spec Freeze

- [ ] Freeze exact HKDF labels and info layout for:
  - client root-share derivation
  - relayer root-share derivation
- [ ] Freeze the canonical seed reconstruction rule:
  - `m = y_client + y_relayer mod 2^256`
  - `d = LE32(m)`
- [ ] Freeze the canonical public-key rule:
  - `a = clamp(SHA-512(d)[0..31])`
  - `A = [a]B`
- [ ] Freeze participant-id assumptions for v1.
- [ ] Freeze the output shapes for:
  - durable server `x_relayer_base`
  - wrapped durable client `x_client_base` envelope
  - worker-memory `x_client_base`
  - optional reusable rebuild-artifact metadata
- [ ] Freeze the nonce strategy as fresh-random FROST nonce generation; explicitly reject deterministic per-signature and timestamp-only nonce designs.
- [ ] Publish cross-runtime test vectors for:
  - `y_client`
  - `y_relayer`
  - `d`
  - `a`
  - `A`
  - `x_client_base`
  - `x_relayer_base`
  - wrapped client-share envelope metadata
  - exported `ed25519:` string

### Phase 1.5 — Backend Feasibility Gate

- [ ] Design and benchmark the simplest viable fixed-function Option B candidate for one-block `SHA-512 + clamp`.
- [ ] Keep Option A only as a correctness/reference comparison, not as the preferred rollout path.
- [ ] Measure:
  - prefetched bytes
  - post-prefetch online bytes
  - online round trips
  - post-prefetch online latency
  - client CPU time
  - server CPU time
  - registration/recovery latency
  - desktop vs mobile feasibility
- [ ] Confirm that the chosen backend meets the frozen online budget:
  - `< 15 KB`
  - `2` round trips
  - `< 500 ms`
- [ ] Confirm that registration UX can overlap the prefetched transfer and OT setup before WebAuthn begins.
- [ ] If future measurements justify it, evaluate additional preprocessing beyond required prefetch as a phase-after-v1 performance improvement.
- [ ] Specify the `tee-v1` attestation verification contract and expected latency budget.

### Phase 2 — Root-Share Core Helpers

- [ ] Add Rust core helpers for client root-share derivation.
- [ ] Add Rust core helpers for relayer root-share derivation.
- [ ] Add canonical seed/public-key derivation helpers.
- [ ] Add helper to verify that derived `A` matches expected account public key.
- [ ] Add explicit root-share and canonical-seed types; avoid overloading old share names.
- [ ] Publish fixture JSON consumed by Rust, wasm, and TypeScript.

### Phase 3 — Server Master-Secret Architecture

- [ ] Introduce tenant-specific Ed25519 master-secret management.
- [ ] Add KMS/HSM wrapping or equivalent secure-secret handling for `K_org`.
- [ ] Bind tenant secret lookup to org-scoped config, not global config.
- [ ] Add tenant/environment backend configuration:
  - `2pc-gc-v1`
  - `tee-v1`
- [ ] Expose backend policy in dashboard and server config APIs.
- [ ] Add versioning for server root-share derivation labels.
- [ ] Ensure relayer root-share derivation requires only:
  - tenant secret
  - account context
  - key version
- [ ] Remove assumptions that Ed25519 server-side recoverability depends on per-account key rows.

### Phase 4 — Enrollment / Rotation Context Freeze

- [ ] Refactor registration so the canonical Ed25519 context is allocated before client PRF derivation.
- [ ] Refactor rotation so a new `keyVersion` is available before root-share derivation.
- [ ] Freeze the exact outer auth wrapper for `lifecycleAuthId` across:
  - registration
  - rotation
  - link-device
  - cache rebuild / recovery
- [ ] Persist only metadata needed to rebuild and validate the shared-root model.
- [ ] Seed the initial client reusable garbled-table / base-OT cache during registration/link-device.
- [ ] Define the wrapped client base-share envelope format and KEK derivation spec.

### Phase 5 — Cache-Build Protocol And Routes

- [ ] Implement:
  - `POST /threshold-ed25519/cache-build/init`
  - `POST /threshold-ed25519/cache-build/step`
  - `POST /threshold-ed25519/cache-build/finalize`
- [ ] Make `cache-build/init` the registration-time prefetch entrypoint for:
  - canonical-context reservation
  - reusable per-account garbled-table fetch
  - reusable base OT bootstrap
- [ ] Return explicit backend metadata from `cache-build/init` so the client knows whether this flow is:
  - `2pc-gc-v1`
  - `tee-v1`
- [ ] Ensure the registration UI does not enable the Register / WebAuthn button until:
  - garbling prefetch is complete
  - OT setup is complete
- [ ] Ensure cache build outputs durable cached FROST base shares and public verification metadata only.
- [ ] Ensure cache build commits:
  - durable server `x_relayer_base`
  - public verifying metadata
  - client wrapped-base-share metadata
- [ ] Bind cache-build results to:
  - `orgId`
  - `accountId`
  - `keyPurpose`
  - `keyVersion`
  - `cacheBuildId`
  - `cacheGenerationId`
  - participant ids
- [ ] Cache a verified canonical public key alongside durable signing material.
- [ ] Implement transcript-hash verification in finalize.
- [ ] Implement cache-build expiry / invalidation semantics.
- [ ] Keep the large garbling transfer off the post-WebAuthn critical path.
- [ ] Implement `tee-v1` cache-build flow with attestation verification and enclave-bound conversion.

### Phase 5.5 — Unlock Unwrap Flow

- [ ] Add the normal unlock flow that derives the KEK from a separate PRF output and unwraps `x_client_base`.
- [ ] Ensure unlock requires a matching server `cacheGenerationId`.
- [ ] Ensure plaintext `x_client_base` is retained only in the existing in-memory signing-session state.
- [ ] Zeroize plaintext `x_client_base` on signing-session end, lock, tab close, session teardown, or worker restart.

### Phase 6 — Durable Cache Storage

- [ ] Introduce explicit durable cache types for Ed25519 signing material.
- [ ] Separate durable cache storage from canonical account metadata storage.
- [ ] Implement the v1 cache authority model:
  - server durable relayer base-share cache
  - IndexedDB-backed client wrapped-share cache
  - optional IndexedDB-backed client reusable garbled-table / base-OT cache
  - in-memory signing-session cache for plaintext `x_client_base`
  - temporary server build state keyed by `cacheBuildId`
- [ ] Add cache generation and divergence checks.
- [ ] Record backend provenance per cache generation.
- [ ] Define behavior after:
  - process restart
  - server DB loss
  - local client storage loss
  - key rotation
  - backend switch

### Phase 7 — Signing Path Refactor

- [ ] Refactor Ed25519 transaction signing to require:
  - worker-memory `x_client_base`
  - durable server `x_relayer_base`
- [ ] Ensure normal signing latency remains roughly comparable to the current hot path after unlock unwrap succeeds.
- [ ] Ensure sign-init/finalize paths no longer imply the old persisted-share lifecycle.
- [ ] Return explicit:
  - `cache_rebuild_required`
  when the corresponding prerequisite is missing.
- [ ] Keep in-flight sign state ephemeral and isolated from the durable server base-share cache.

### Phase 8 — Nonce Safety

- [ ] Implement RFC 9591-compatible fresh-random nonce generation for Ed25519 FROST signing.
- [ ] Prove that reboot/cache loss cannot cause nonce reuse.
- [ ] Add tests for:
  - repeated signing after one unlock unwrap
  - parallel signing
  - process restart
  - local reusable garbled-table / base-OT loss
  - server durable base-share loss
- [ ] Track one-time-use nonce commitments and reject replayed commitments.
- [ ] Explicitly reject deterministic per-signature and timestamp-only nonce implementations in code review and tests.

### Phase 9 — Recovery / Link-Device / Cache Rebuild

- [ ] Implement cache rebuild using `cache-build/*` for:
  - local wrapped client-share loss or unwrap failure
  - server durable base-share cache loss
  - link-device
  - explicit recovery flow
- [ ] Allow reusable garbled tables / base OT to accelerate rebuild on the same device, but do not require them for ordinary unlock.
- [ ] Ensure rebuild produces the same canonical public key and export identity.
- [ ] Ensure rebuild safely replaces prior durable cache generations.
- [ ] Allow explicit backend switching during rebuild-capable flows without changing canonical key identity.
- [ ] Add user-facing recovery errors and recovery-capable routing when cache is missing.

### Phase 10 — Export Integration

- [ ] Adapt Ed25519 export to operate on the shared-root domain.
- [ ] Ensure export can reconstruct canonical seed `d` without requiring long-lived persisted relayer shares.
- [ ] Keep export finalize inside worker memory only.
- [ ] Verify exported `ed25519:` string against:
  - repo-native parser/import
  - `near-api-js`
- [ ] Add failure tests for wrong public-key reconstruction and stale key version.

### Phase 11 — Verification And Disaster Recovery

- [ ] Add end-to-end tests for:
  - enroll account
  - normal unlock/sign using:
    - local wrapped client-share hit
    - server durable relayer base-share hit
  - wrapped client-share missing or unwrap failure producing `cache_rebuild_required`
  - missing server durable base share producing `cache_rebuild_required`
  - cache rebuild
  - export canonical seed
- [ ] Add disaster-recovery tests for:
  - primary DB loss
  - client local wrapped-share loss
  - process restart
  - multi-instance server durable cache miss
- [ ] Add metrics/observability for:
  - cache-build duration
  - durable cache hit ratio
  - rebuild frequency
  - export success/failure

### Phase 12 — Comprehensive Cleanup And Cutover

- [ ] Delete persisted-relayer-share Ed25519 source-of-truth code paths.
- [ ] Delete any Ed25519 config, docs, or comments that describe:
  - persisted relayer shares as canonical state
  - derived-share fallbacks
  - alternate Ed25519 lifecycles
  - routine unlock-time 2PC/TEE conversion
- [ ] Delete any ad hoc backend-specific branching that changes the canonical Ed25519 lifecycle instead of just the conversion mechanism.
- [ ] Delete any remaining server/session/store abstractions that exist only for the old Ed25519 model.
- [ ] Remove dead client worker fields and IndexedDB shapes that imply plaintext durable client signing-share cache instead of wrapped-share storage.
- [ ] Remove dead client worker fields and IndexedDB shapes that imply a consumable pre-garbled-artifact pool instead of reusable per-account garbled tables.
- [ ] Remove dead client worker fields and IndexedDB shapes that imply per-unlock rerandomized runtime-share persistence.
- [ ] Remove old export assumptions that depended on persisted relayer export shares as canonical state.
- [ ] Remove obsolete docs once this model is the only supported Ed25519 architecture.
- [ ] Record the final compatibility matrix and operational runbook.

## Cleanup Checklist

When this model is chosen, all of the following must be removed or revised:

- persisted-share-only Ed25519 assumptions in:
  - server key resolution
  - signing handlers
  - export handlers
  - cache rebuild handlers
- any type names that imply long-lived relayer signing-share persistence is canonical,
- any comments that describe DB-backed relayer-share records as the only recovery path,
- any docs that present hybrid persisted shares as the final Ed25519 architecture,
- any old "session bootstrap at unlock" abstractions or route names,
- any docs that imply GC or TEE sits on the ordinary unlock path,
- any nonce logic that depends on best-effort timestamps instead of safe per-attempt randomness.

## Open Questions

These are the remaining questions after the durable-cache lifecycle is frozen:

- exact wrapped-share KEK derivation and envelope algorithm,
- whether reusable garbled tables / base OT setup need additional client-side wrapping beyond worker-managed IndexedDB storage,
- whether a bounded nonce-commitment pool is worth adding after the core model is stable,
- whether self-hosting with stable RP-ID continuity is realistic for target tenants.

## Recommendation

Choose this model if the primary goals are:

- avoiding catastrophic DB-loss scenarios,
- supporting tenant-specific deterministic recovery,
- preserving a clean path to tenant handover/self-hosting,
- keeping standard NEAR seed export,
- keeping hot-path signing fast by using durable cached FROST shares.

Do not choose this model if the primary goal is to minimize implementation complexity in the short term.
