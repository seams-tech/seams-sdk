# Homomorphic Key Export Support Plan (Ed25519, Option A)

Date updated: April 2, 2026

## Objective

Define the primary single-key Ed25519 export architecture:

- one canonical Ed25519 seed `d`
- one canonical signing scalar `a`
- one canonical public key `A`
- threshold signing and export both bound to that same lifecycle

This is the preferred long-term Ed25519 architecture.

## Why Option A

Option A is the right model when the product wants:

- one canonical key per account
- one consistent mental model across NEAR, Solana, and Sui
- standard seed-compatible export
- threshold signing over the same underlying key

The cost is the hidden nonlinear conversion:

- `d -> SHA-512(d) -> clamp -> a`

That used to look too expensive. The current succinct-HSS work makes it
feasible enough to treat this as the active direction again.

## Core Model

Let:

- `y_client` be the client root share derived from WebAuthn `prf.output`
- `y_relayer` be the server root share derived from `K_org`

Define:

- `m = y_client + y_relayer mod 2^256`
- `d = LE32(m)`
- `h = SHA-512(d)`
- `a_bytes = clamp(h[0..31])`
- `a = LE256(a_bytes) mod l`
- `A = [a]B`

Threshold signing uses shares of `a`.

Standard export reconstructs `d`.

Those are two views over one canonical key lifecycle, not two separate keys.

## Current Product Interpretation

Under the revised HSS architecture:

- the client re-derives its hidden inputs from `prf.output` on demand
- the server re-derives its hidden inputs from `K_org` on demand
- HSS performs the hidden `d -> a` conversion whenever the product needs fresh
  signing-share reconstruction
- there is no durable wrapped `x_client_base` in the target design

So the client-side share story is:

- `prf.output` is part of the client signing share
- export compatibility comes from the same canonical seed lifecycle

## Export Rule

Ed25519 export means seed export.

Supported artifact:

- `near-ed25519-seed-v1`

That means:

- reconstruct canonical seed `d`
- derive `A` from `d`
- fail closed if the derived public key does not match the bound account key
- emit standard NEAR `ed25519:` encoding only after that check

Do not treat scalar export as equivalent to seed export.

## Security Boundary

The goals are:

- the server must not learn plaintext client contribution
- the client must not learn plaintext server contribution
- neither side should learn plaintext `a` during normal threshold setup
- plaintext `d` is reconstructed only inside the controlled export path

Correctness rule:

- export must verify the derived public key before releasing any seed artifact

## Why This Is Better Than Option B

Option A is better when:

- one canonical public key identity matters
- multi-chain consistency matters
- product simplicity matters more than avoiding the hidden `d -> a` step

Option B remains simpler for a NEAR-only dual-key recovery design, but it gives
up the single-key invariant.

## Active Dependencies

This plan depends on the HSS track documented in:

- [succinct-garbling-spec.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/succinct-garbling-spec.md)
- [README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/README.md)
- [optimization-v3.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/optimization-v3.md)

## Refactor Goal

Switch the threshold Ed25519 signer from the currently implemented Option B
model to the Option A model, using
[`crates/ed25519-hss`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss)
as the hidden-conversion engine.

That means:

- one canonical Ed25519 lifecycle only
- one canonical public key `A`
- one canonical seed `d`
- one canonical signing scalar `a`
- threshold signing shares reconstructed from hidden `a`
- export compatibility derived from the same canonical seed lifecycle

This migration should leave no primary-path Option B assumptions behind.
Option B may remain only as an explicitly marked migration or compatibility
track until the cutover is complete.

## Phased Roadmap

- [x] Phase 0: inventory the current Option B signer/export surfaces and
      freeze the migration boundary
- [x] Phase 1: define one shared Option A product interface around
      `ed25519-hss`
- [x] Phase 2: switch signing-share reconstruction onto the Option A HSS path
- [x] Phase 3: add the controlled canonical-seed export flow
- [x] Phase 4: replace product-side derivation and session wiring with Option A
      inputs and ceremony
- [x] Phase 5: remove Option B from the active product path
- [x] Phase 6: verify segregation, security boundaries, and one-key invariants
- [x] Phase 7: delete migration leftovers and cut docs fully over to Option A

## Current State

Today:

- the crate
  [`crates/ed25519-hss`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss)
  implements the hidden conversion and signing-share projection path
- the active Ed25519 session/signing path now reconstructs `x_client_base`
  through the Option A HSS ceremony and feeds the signer only Option A
  base-share material
- the active signer worker no longer derives operational shares locally from
  PRF or wrap-key material, and no longer accepts Option B operational-signing
  inputs
- Option B remains only as explicitly historical background in migration docs;
  it is no longer part of the active code path or active product specs

The migration task is therefore not to invent new cryptography. It is to
replace the current product integration with the already chosen Option A specs
and the already implemented `ed25519-hss` hidden-conversion engine.

## Target Integration Shape

The target product shape is:

- client derives:
  - `y_client` from passkey `prf.output`
  - `tau_client` from the same passkey root and canonical context
- server derives:
  - `y_relayer` from `K_org`
  - `tau_relayer` from the same server root and canonical context
- the product invokes
  [`prepare_prime_order_succinct_hss(...)`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/succinct_hss.rs#L478)
  and the role-separated session flow in
  [`src/protocol/succinct_hss.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/protocol/succinct_hss.rs)
- the hidden conversion produces:
  - `x_client_base`
  - `x_relayer_base`
  - public key verification data
- threshold signing uses reconstructed shares of hidden `a`
- export reconstructs canonical seed `d` only inside an explicitly controlled
  export path

## Non-Negotiable Migration Rules

- Do not preserve dual-key Option B behavior as the default path.
- Do not reintroduce wrapped local `x_client_base` storage as the primary
  model.
- Do not add new parallel Ed25519 signing/export lifecycles.
- Do not widen client visibility to server root material or server signing
  shares.
- Do not widen server visibility to client root material or client signing
  shares.
- Do not keep legacy Option B flags, alternate structs, or route names once
  the Option A replacement is live.

## Phased Todo List

### Phase 0: Freeze Current Boundaries

- [x] Inventory every current Option B product entrypoint, route, worker, and
      storage shape that assumes a dual-key Ed25519 model.
- [x] Identify the exact integration points where Option B currently supplies:
  - operational signing material
  - export material
  - public-key verification data
- [x] Write down the current API and persistence surfaces that must change in
      the signer layer, worker layer, and server layer.
- [x] Mark all Option B-only docs and code paths as legacy migration context,
      not target architecture.

### Phase 1: Define the Shared Option A Product Interface

- [x] Add the first Option A client-input derivation interface across
      `signer-core`, the signer worker, and the client lifecycle helper for:
  - canonical context normalization and binding
  - client-derived `y_client`
  - client-derived `tau_client`
- [x] Add the matching server-side Option A derivation interface across
      `signer-core`, signer wasm exports, and the server helper layer for:
  - server-derived `y_relayer`
  - server-derived `tau_relayer`
  - shared canonical context binding
- [x] Define one crate-facing integration interface for:
  - canonical context
  - client-derived `y_client`, `tau_client`
  - server-derived `y_relayer`, `tau_relayer`
  - role-separated wire messages
  - output share opening
- [x] Define the product-level data model for:
  - one canonical public key
  - one signing-share reconstruction path
  - one controlled seed-export path
- [x] Remove any new interface proposals that keep separate `pk_a` / `pk_d`
      assumptions in the default path.

Landed Phase 1 interface slices:

- `signer-core` now derives canonical Option A client/server inputs
  (`y_client`, `tau_client`, `y_relayer`, `tau_relayer`) from shared canonical
  context binding rules.
- `wasm/near_signer` now exposes the `ed25519-hss` prepared-session and
  role-separated ceremony boundary as opaque state/message blobs:
  - prepare session
  - prepare client request
  - prepare server message
  - evaluate result
  - finalize report
- `wasm/near_signer` now also exposes role-gated output handling for the same
  ceremony boundary:
  - open client output
  - open server output
  - derive public key from opened base shares
- `server/src/core/ThresholdService/ed25519HssWasm.ts` now provides the first
  normalized product-facing adapter over that ceremony boundary and its output
  types.

### Phase 2: Wire Signing-Share Reconstruction Through `ed25519-hss`

- [x] Add the product adapter that calls the `ed25519-hss` prepared-session and
      role-separated evaluation flow.
- [x] Remove stale Option B Ed25519 session-mint assumptions from the active
      login/session path (`clientVerifyingShareB64u` is no longer derived or
      sent for `/threshold-ed25519/session`).
- [x] Remove stale Option B Ed25519 session/authorize wire fields from the
      active wasm signer transport path (`clientVerifyingShareB64u` is no
      longer sent to `/threshold-ed25519/session` or `/threshold-ed25519/authorize`).
- [x] Replace the current Option B operational-signing reconstruction path with
      Option A share reconstruction from hidden `a`.
- [x] Ensure the signer can consume `x_client_base` / `x_relayer_base` as the
      signing-share basis instead of Option B operational-share material.
- [x] Verify that the same canonical public key can be recovered from the Option A
      signing-share outputs.

Keep gate:

- [x] end-to-end signing works using only Option A share reconstruction
- [x] no Option B operational-key assumptions remain in the active signing path

Landed Phase 2 adapter slice:

- the client now has a real Option A ceremony adapter over the
  `ed25519-hss` prepared-session flow:
  - prepare HSS session
  - prepare client request
  - evaluate result
  - open client output
  - derive public key from base shares
- the server now has matching composed helpers for the server half of the same
  ceremony:
  - derive server inputs
  - prepare server message
  - finalize report
  - open server output
- the lifecycle layer now also exposes one product-facing helper that takes a
  credential plus canonical context and returns:
  - derived client inputs
  - prepared session envelope
  - client request envelope
- the lifecycle layer also exposes the matching client-side completion helper
  for:
  - evaluation result
  - client output opening
  - optional canonical public-key derivation from opened base shares
- the live Ed25519 session-connect path no longer derives or sends the legacy
  Option B `clientVerifyingShareB64u` field just to mint a threshold auth
  session; session minting is now bound only to WebAuthn plus the canonical
  session policy
- the wasm signer transport no longer sends the legacy Option B
  `clientVerifyingShareB64u` field on Ed25519 session/authorize requests; the
  remaining Option B dependency is now deeper in the active signing backend
  itself
- `signer-core` and the wasm signer now have a shared FROST key-package
  constructor from base-share scalars plus canonical public key, which is the
  prerequisite for replacing Option B client-share derivation with Option A
  `x_client_base` reconstruction in the active signer backend
- the active wasm Ed25519 signer backend can now consume `x_client_base`
  directly when the product provides it, instead of being structurally limited
  to Option B PRF-derived client-share material
- completed Option A client output can now be persisted onto the live Ed25519
  threshold session record, and the active NEAR signing flows will pass that
  stored `x_client_base` through to the signer worker whenever it is present
- Ed25519 threshold auth sessions, auth-session cache entries, and stored
  threshold session records now preserve `runtimeSnapshotScope` when the
  relayer provides it, so the active path can carry canonical Option A scope
  without introducing a second side channel for `orgId`
- the server now exposes authenticated Ed25519 HSS session routes under the
  existing threshold session JWT:
  - `POST /threshold-ed25519/hss/prepare`
  - `POST /threshold-ed25519/hss/finalize`
- those HSS session routes are claim-bound to the active threshold session
  scope and return only client-safe ceremony artifacts:
  - server prepare returns `serverMessage`
  - server finalize returns `finalizedReport`
  - the relayer base share is not returned to the client
- the active NEAR signing flows now opportunistically run the Option A HSS
  ceremony before signing whenever the live threshold session already carries
  canonical runtime scope and no cached `x_client_base` is present:
  - transaction signing
  - NEP-413 signing
  - delegate signing
- that live Option A reconstruction is keyed to the canonical relayer-issued
  threshold session id, not a transient operation-local session id, so the
  reconstructed `x_client_base` persists correctly across the active session
- login warm-up now forwards canonical `runtimeSnapshotScope` from the existing
  threshold ECDSA session context into Ed25519 session mint, so threshold
  accounts that already have canonical session scope default onto the Option A
  HSS reconstruction path instead of only using it opportunistically later
- managed-mode Ed25519 session mint can now derive canonical
  `runtimeSnapshotScope` on first session creation from authenticated
  `environmentId + publishableKey`, so the first threshold login does not need
  a preexisting ECDSA session record before defaulting onto the Option A HSS
  path
- once the active path has reconstructed `x_client_base`, the client worker
  request no longer carries the stale Option B `clientVerifyingShareB64u`
  field into the signer; the default worker envelope now prefers the Option A
  base-share path instead of shipping both representations together
- once an active Ed25519 threshold session carries canonical Option A runtime
  scope, the live signing path now treats missing HSS reconstruction material
  as an error instead of silently drifting back to Option B assumptions for
  that session
- the active wasm Ed25519 signer backend now accepts only `x_client_base` for
  threshold signing; the old Option B operational-share reconstruction path and
  its `clientVerifyingShareB64u` worker input have been deleted from the live
  signing path
- the live threshold signer worker envelope also no longer carries the dead
  Option B `keyVersion` input into signing, because the active signer path no
  longer derives operational shares inside the worker
- the live Ed25519 sign worker requests no longer carry dead `prfFirstB64u` or
  `wrapKeySalt` fields into signing; PRF is still used before signing for the
  HSS reconstruction step, but the active signer itself no longer consumes
  local wrap-key material
- the active NEAR signing material resolver no longer blocks Ed25519 signing on
  a local `wrapKeySalt` check, because the default signing path now reconstructs
  `x_client_base` through HSS before signing instead of deriving operational
  shares locally inside the worker
- Ed25519 auth-session cache refresh now preserves an already reconstructed
  `x_client_base` for the same threshold session record instead of silently
  dropping it on session-cache rebuild
- the active product signing path now uses the role-separated HSS ceremony as
  its canonical Ed25519 signing-share reconstruction path

### Phase 3: Add the Controlled Seed-Export Path

- [x] Add a crate-level controlled canonical-seed output/opening seam in
      `ed25519-hss`.
- [x] Carry the new `seed_output` message through the product-facing wasm,
      client, and server HSS adapters.
- [x] Thread opened canonical seed into one verified
      `near-ed25519-seed-v1` artifact builder in the client lifecycle layer.
- [x] Add an Option A `near-ed25519-seed-v1` lane to the export UI/worker
      boundary.
- [x] Add a high-level client export helper that goes from finalized Option A
      HSS report to the export UI.
- [x] Expose a product-facing client API entrypoint that can route finalized
      Option A HSS export inputs through the direct client path or wallet-iframe
      boundary without falling back to Option B export payloads.
- [x] Make the existing user-facing NEAR export action prefer an export-scoped
      Option A HSS ceremony when the active Ed25519 threshold session already
      has canonical runtime scope plus warm client PRF material.
- [x] Define the explicit export flow that reconstructs canonical seed `d`
      inside a controlled export ceremony.
- [x] Bind export requests to the same canonical public key identity used by
      signing.
- [x] Verify `A` derived from reconstructed `d` before releasing any export
      artifact.
- [x] Emit only the intended export artifact format, such as
      `near-ed25519-seed-v1`, after verification succeeds.
- [x] Fail closed on any mismatch between reconstructed seed-derived public key
      and the bound account key.

Keep gate:

- [x] export and signing are both visibly tied to one canonical public key
- [x] export reconstructs seed, not scalar-only material

Landed Phase 3 groundwork:

- `signer-core` now has one explicit `near-ed25519-seed-v1` artifact builder
  plus a fail-closed helper that verifies a reconstructed canonical seed
  against the expected canonical public key before any artifact is emitted
- `wasm/near_signer` now exposes the same verified seed-artifact builder so the
  future worker-owned export path has one mandatory verification seam instead
  of ad hoc seed handling
- `ed25519-hss` now emits canonical seed `d` as a dedicated role-gated
  `seed_output` message alongside the existing base-share outputs, and the
  crate test flow now verifies that opening that message reproduces the same
  canonical seed bytes implied by the fixture input
- the product-facing HSS envelopes now carry `seed_output_message_b64u`, and
  both the client and server HSS wasm adapters can open canonical seed bytes
  from a finalized Option A report without touching the legacy Option B export
  flow
- the client lifecycle layer now has one Option A helper that:
  - opens canonical seed from the finalized HSS report
  - verifies the expected canonical public key
  - emits one `near-ed25519-seed-v1` artifact shape
    That gives the future export route one canonical artifact builder path
    instead of ad hoc seed handling
- the secure-confirm worker and export recovery layer now accept a dedicated
  `near-ed25519-seed-v1` payload, so the export UI boundary is no longer
  structurally locked to the legacy Option B Paillier flow
- the client signing engine now has one high-level Option A helper that:
  - opens canonical seed from finalized HSS report
  - builds the verified `near-ed25519-seed-v1` artifact
  - sends that artifact through the export UI worker lane
    so the product has one direct Option A export entrypoint available
- the public `TatchiPasskey` / wallet-iframe key-export surface now exposes a
  dedicated Option A entrypoint that accepts finalized HSS export inputs and
  routes them through the same verified `near-ed25519-seed-v1` export lane,
  instead of forcing callers back through the legacy generic Option B export
  shape
- the existing user-facing NEAR export action now prefers an export-scoped
  Option A HSS ceremony whenever the active Ed25519 threshold session already
  has canonical runtime scope, a matching warm threshold session, and cached
  client PRF material; only sessions that still lack those canonical Option A
  prerequisites fall back to the legacy export path
- the export path now uses the same canonical signing-purpose HSS context as
  threshold signing, instead of a separate export-only key purpose, so both
  flows stay bound to one canonical seed/signing lifecycle
- the active Option A export lane now returns the finalized HSS report from the
  client-completion seam, so the export flow can open canonical seed from the
  same completed ceremony instead of reconstructing ad hoc follow-up state
- the product-level script test now exercises the real Option A export path
  end to end with export-scoped HSS context, derives the real canonical public
  key for that path, and verifies that the export worker receives only a
  verified `near-ed25519-seed-v1` payload
- when an active Ed25519 threshold session already has canonical Option A
  runtime scope, the export entrypoint now fails closed on missing warm-session
  HSS prerequisites instead of silently drifting back to the legacy Option B
  export path

Phase 3 blockers removed:

- the export path is no longer blocked on `ed25519-hss` lacking a controlled
  canonical-seed output/opening seam
- the export path is no longer blocked on product-facing HSS adapters lacking
  the new `seed_output` message

Next steps:

- add a higher-level product e2e that proves signing and export stay bound to
  the same canonical public key over the real route/session flow
- remove the remaining Option B Ed25519 registration/bootstrap baggage from
  product-local models and stored metadata that no longer belongs on the
  default path
- add e2e verification that signing and export are both bound to the same
  canonical public key and that only `near-ed25519-seed-v1` leaves the worker

### Phase 4: Replace Product Derivation and Session Wiring

- [x] Move the client integration onto passkey-derived `y_client` /
      `tau_client` inputs for the active path.
- [x] Add authenticated server session helpers that derive server-root-based
      `y_relayer` / `tau_relayer` and run the server half of the HSS ceremony.
- [x] Move the server integration onto server-root-derived `y_relayer` /
      `tau_relayer` inputs for the active path.
- [x] Replace any Option B session bootstrap or local-share bootstrap code with
      the role-separated OT/HSS ceremony.
- [x] Update session/auth flow documentation to say:
  - stateless client share reconstruction
  - stateless server share reconstruction
  - one canonical hidden seed/signing lifecycle

### Phase 5: Remove Option B From The Active Product Path

- [x] Delete Option B-only active code paths from the default signer/export
      flow.
- [x] Remove dual-key assumptions from API models, worker messages, and server
      handlers.
- [x] Rename product-layer types and route descriptions so the default path is
      clearly the Option A single-key lifecycle.
- [x] Keep Option B only if it is explicitly isolated as migration-only or
      fallback-only behavior.

Reject gate:

- [x] reject any migration that leaves the product default ambiguous between
      Option A and Option B

Landed Phase 5 cleanup:

- the client-side secure-confirm export worker and its payload types no longer
  support the legacy Option B `near-ed25519-option-b-v1` recovery-export lane
- the old client relayer RPC helpers for `/threshold-ed25519/export/init` and
  `/threshold-ed25519/export/combine` are removed from the active client code
- the generic private-key export recovery helper now rejects NEAR export and
  leaves that chain exclusively on the canonical Option A seed-export path
- the dead server-side `/threshold-ed25519/export/init` and
  `/threshold-ed25519/export/combine` route handlers and route definitions are
  removed from the active product surface
- the unreachable server-side Option B export request/response types, scheme
  hooks, dedicated export-session store, and export init/combine service methods
  are removed instead of being left behind as dead plumbing
- local NEAR threshold-key metadata no longer stores a legacy Option B export
  artifact kind, and registration/sync/bootstrap callers no longer write that
  field into the default product path
- local NEAR threshold-key metadata no longer stores top-level recovery/export
  derivation flags that the active product path does not read; only relayer
  metadata plus the participant list remain on that record
- the dead client-side Option B Ed25519 enrollment helper
  `threshold/workflows/enrollEd25519Key.ts` is deleted instead of being kept as
  unreachable migration baggage
- the dead client-side Option B Ed25519 keygen workflow
  `threshold/workflows/keygenEd25519.ts`, its public re-export from
  `client/src/threshold.ts`, and its dedicated relay RPC helper
  `thresholdEd25519Keygen(...)` are deleted instead of being left behind as
  unused dual-key bootstrap API surface
- the remaining warm-session bootstrap helper now keeps its
  `ThresholdWarmSessionPolicyDraft`, `ThresholdWarmSessionBootstrapPayload`, and
  `ThresholdWarmSessionRelayResult` types internal instead of exporting extra
  Option B migration-only API surface, and registration now imports the shared
  `DUAL_KEY_ED25519_KEY_VERSION_V1` constant instead of carrying another local
  copy
- the still-live Option B migration flows in sync-account, link-device, and
  email recovery now route bootstrap-payload construction and returned recovery
  metadata checks through shared migration-only helpers in
  `thresholdEd25519LegacyBootstrap.ts` instead of repeating the same dual-key
  assumptions and error handling in each product flow
- those same still-live migration flows now also route the repeated
  `createThresholdWarmSessionPolicyDraft + deriveThresholdEd25519BootstrapPackageFromCredential +
build payload` sequence through one shared
  `prepareThresholdWarmSessionBootstrapFromCredential(...)` helper, so the
  remaining Option B bootstrap logic is isolated in one migration-only seam
  instead of being open-coded in three product flows
- the remaining live registration bootstrap path no longer open-codes relay
  recovery-share preflight plus Option B package validation; it now routes
  that sequence through one shared
  `prepareThresholdEd25519RegistrationBootstrapPackageFromCredential(...)`
  helper in `thresholdEd25519LegacyBootstrap.ts`, keeping the last live Option B
  bootstrap derivation behind the same migration-only seam
- that registration path no longer splits the migration-only Ed25519 bootstrap
  package back into a separate local `thresholdClientVerifyingShareB64u`
  shadow variable; registration now reads the client share directly from the
  shared package object, which removes another duplicate Option B assumption
  from the last live bootstrap flow
- the relay registration transport in `createAccountRelayServer.ts` now routes
  the remaining Option B Ed25519 request/response mapping through dedicated
  helpers (`buildThresholdEd25519RegistrationRequest(...)` and
  `normalizeThresholdEd25519RegistrationResult(...)`) instead of hand-assembling
  and hand-validating that field list inline, which keeps the last live
  bootstrap package shape localized to one migration-only seam
- the post-registration Ed25519 bootstrap response/session checks in
  `registration.ts` are now collapsed into one local
  `requireRegisteredThresholdEd25519Bootstrap(...)` helper, so the main
  registration flow no longer re-validates key version, recovery capability,
  recovery key, relayer metadata, and bootstrap session shape inline
- the remaining migration-only Ed25519 IndexedDB write in `registration.ts`
  is now localized to one `storeRegisteredThresholdEd25519KeyMaterial(...)`
  helper instead of hand-assembling participant metadata and storage payload
  fields in the middle of the main registration flow
- the Ed25519 warm-session hydrate/auth-session cache block in `registration.ts`
  is now localized to one `hydrateRegisteredThresholdEd25519BootstrapSession(...)`
  helper instead of unpacking bootstrap-session JWT fields and auth-session
  cache inputs inline in the main registration flow
- the main registration flow no longer carries nullable local
  `thresholdEd25519RegistrationPackage`, `thresholdEd25519SessionPolicyForRegistration`,
  or `thresholdEd25519SessionIdForRegistration` state; after the migration-only
  bootstrap derivation succeeds, registration now treats the remaining
  Option B Ed25519 bootstrap package and session policy as required inputs
  instead of optional baggage
- the remaining registration-time Option B Ed25519 bootstrap state is now
  bundled behind one `prepareThresholdEd25519RegistrationBootstrap(...)`
  helper that returns `{ package, sessionPolicy }`, so the main registration
  flow no longer threads those migration-only pieces around as separate values
- the main registration flow no longer explodes the validated
  `registeredThresholdEd25519` result back into separate `thresholdPublicKey`,
  `thresholdRecoveryPublicKey`, `relayerKeyId`, `relayerVerifyingShareB64u`,
  and `thresholdKeyVersion` locals; it now carries the validated bootstrap
  object through directly
- the prepared registration bootstrap helper now owns the relay-facing
  Ed25519 bootstrap request shape too, so `registration.ts` no longer
  hand-assembles the migration-only `thresholdEd25519` relay input field list
  inline and instead passes `thresholdEd25519Bootstrap.registrationInput`
- the remaining migration-only Ed25519 threshold-key persistence shape is now
  centralized in one shared
  `storeThresholdEd25519BootstrapKeyMaterial(...)` helper in
  `thresholdEd25519LegacyBootstrap.ts`; registration, sync-account, link-device,
  and email recovery no longer each hand-assemble the same
  `storeNearThresholdKeyMaterial(...) + buildThresholdEd25519Participants2pV1(...)`
  payload separately
- the remaining post-registration threshold-ed25519 bootstrap completion path in
  `registration.ts` is now routed through dedicated local helpers:
  `completeRegisteredThresholdEd25519Bootstrap(...)` for validating the
  returned registration result and `persistRegisteredThresholdEd25519Bootstrap(...)`
  for storage plus session hydration, so the main registration flow no longer
  open-codes that migration-only completion sequence
- the remaining threshold-ed25519 registration bootstrap semantics are now
  hosted by `thresholdEd25519LegacyBootstrap.ts` instead of `registration.ts`;
  the default registration flow calls shared migration-only helpers for
  prepare/validate/persist work rather than deriving and persisting the Option B
  bootstrap artifact directly inside the main registration body
- relay-backed registration now injects canonical `runtimeSnapshotScope`
  (`orgId`, `environmentId`) from the authenticated relay principal into the
  threshold session policies it mints, and the client-side
  registration-persistence path now preserves that scope on the cached
  threshold-ed25519 auth session record instead of dropping it during
  registration bootstrap
- managed registration bootstrap grants now return canonical runtime scope
  (`orgId`, `environmentId`, optional `projectId`) to the client, so the
  future sessionless Option A HSS registration/bootstrap flow has a real
  canonical scope source before account creation instead of having to invent
  an ad hoc `orgId`
- the relay now exposes a real sessionless registration-side Option A HSS seam
  at `/registration/threshold-ed25519/hss/prepare` and
  `/registration/threshold-ed25519/hss/finalize`, backed by the same
  registration bootstrap auth plane instead of threshold-session JWTs
- managed bootstrap grants can now bind to those registration HSS route paths,
  so the browser can mint per-request bootstrap tokens for prepare/finalize
  instead of being limited to `/registration/bootstrap` only
- the client registration transport now has dedicated helpers for the new
  registration HSS prepare/finalize flow in
  `createAccountRelayServer.ts`, which removes the biggest missing relay seam
  for replacing the legacy `threshold_ed25519` dual-key package on the default
  path
- the default registration flow now uses that registration HSS seam
  immediately after bootstrap to reconstruct and persist `xClientBaseB64u` onto
  the cached threshold-ed25519 auth session, so live post-registration signing
  state no longer depends on the legacy bootstrap package after account
  creation completes
- `thresholdWarmSessionBootstrap.ts` is now the Option A warm-session module
  rather than a mixed migration file: it owns warm-session policy drafts,
  relay-session hydration, and registration-time HSS reconstruction of
  `xClientBaseB64u`, while the remaining Option B migration helpers live in the
  dedicated `thresholdEd25519LegacyBootstrap.ts` seam
- sync-account, link-device, and email-recovery now reuse that same Option A
  warm-session seam after the relay returns a threshold-ed25519 session:
  they hydrate the relay session, immediately run the session-backed HSS
  ceremony, and persist `xClientBaseB64u` instead of waiting for a later
  opportunistic reconstruction pass
- WebAuthn credential bindings now persist canonical `runtimeSnapshotScope`,
  and the sync-account / link-device / email-recovery Ed25519 session-mint
  path reuses that scope when the incoming session policy does not already
  carry it
- client IndexedDB threshold-ed25519 metadata is now a canonical
  single-key `threshold_ed25519_v1` record: it no longer stores
  `recoveryPublicKey` as a second active Ed25519 key, and it no longer stores
  a threshold-specific wrap-key salt
- the shared threshold-ed25519 participant metadata stored with that record no
  longer persists verifying-share blobs that the active signer path does not
  read
- the relay threshold-ed25519 key store no longer persists
  `recoveryPublicKey` as a second active Ed25519 key; the stored record now
  contains only the canonical public key plus relayer signing metadata
- the default relay registration/bootstrap request and response shape is now
  single-key too: account registration no longer adds a second Ed25519 recovery
  access key on chain, the live `threshold_ed25519` registration response no
  longer returns `recoveryPublicKey`, and the client registration verification
  path now verifies only the canonical operational access key
- sync-account, link-device, and email-recovery no longer send the legacy
  `threshold_ed25519` bootstrap share package on the default path; they now
  mint threshold-ed25519 warm sessions from relay-held credential binding
  metadata, hydrate the returned JWT session, and reconstruct `xClientBaseB64u`
  through the Option A HSS ceremony before touchless signing
- the registration HSS finalize route can now derive canonical Ed25519
  registration material directly from the finalized Option A report: it opens
  the canonical seed and relayer base share on the relay, derives the canonical
  public key plus relayer verifying share there, and returns the derived
  `publicKey` / `relayerKeyId` pair without exposing raw relayer base-share
  material back to the client
- the default `/registration/bootstrap` path now consumes that derived
  single-key registration material instead of the old bootstrap share package:
  the client sends only `key_version`, `public_key`, `relayer_key_id`, and
  warm-session policy metadata for threshold-ed25519, while the relay loads the
  relayer signing/verifying share pair from its stored HSS finalize state
  instead of trusting client-supplied share blobs
- the active registration path now prepares its threshold-ed25519 warm session
  input through `prepareThresholdEd25519RegistrationWithHss(...)` in
  `thresholdWarmSessionBootstrap.ts`, so the main registration flow no longer
  derives or sends Option B bootstrap-share material on the default path

Phase 5 completion notes:

- the registration-side Option A HSS seam is now live across:
  - sessionless registration HSS prepare/finalize
  - `/registration/bootstrap`
  - sync-account
  - link-device
  - email-recovery
- the remaining registration/session validation and persistence helpers were
  moved into `thresholdWarmSessionBootstrap.ts`, so the dedicated
  `thresholdEd25519LegacyBootstrap.ts` seam has been deleted instead of being
  kept as migration baggage
- the client-side registration response normalization no longer requires or
  models `relayerVerifyingShareB64u` for threshold-ed25519, because the active
  warm-session and signing path no longer depends on relay verifying-share
  blobs
- the server-side public threshold-ed25519 response shapes now match that:
  atomic registration, sync-account verification, link-device preparation,
  email-recovery bootstrap, and credential-binding hydration no longer emit or
  require `relayerVerifyingShareB64u` on the active Option A path

### Phase 6: Security and Segregation Verification

- [x] Add or extend e2e tests that verify:
  - client never receives enough material to recover server roots/shares
  - server never receives enough material to recover client roots/shares
  - role-separated wire packets remain input-segregated
  - signing and export stay bound to the same canonical public key
- [x] Reuse the separated-role e2e pattern from
      [`examples/prime_order_separated_roles_e2e.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/examples/prime_order_separated_roles_e2e.rs)
      wherever possible.
- [x] Add product-level tests for controlled export verification and fail-closed
      behavior.

Landed Phase 6 verification slice:

- added a real script-level regression test at
  [`tests/unit/thresholdEd25519.optionAActivePath.script.unit.test.ts`](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.optionAActivePath.script.unit.test.ts)
  that verifies:
  - the active client path can run the real Option A HSS ceremony and persist
    `xClientBaseB64u` onto the threshold session record
  - the canonical public key can be re-derived from the opened client/server
    base shares produced by that ceremony
  - the live NEAR signing orchestration forwards only `xClientBaseB64u` into
    the signer worker payload, without the old Option B
    `clientVerifyingShareB64u`, `prfFirstB64u`, or `wrapKeySalt` live-signing
    baggage
  - the existing NEAR export entrypoint prefers the Option A HSS export lane
    when canonical warm-session prerequisites are present, and the export
    worker receives only a verified `near-ed25519-seed-v1` payload instead of
    legacy Option B recovery-export fields
  - the existing NEAR export entrypoint now fails closed when canonical Option
    A export prerequisites are missing, instead of falling back to the legacy
    default Option B export path
  - the export lane now uses the same signing-purpose HSS context as the live
    signing path, so the canonical public key checked during export is the same
    key derived from the active signing-share reconstruction path
- a higher-level route/session-flow case now proves live signing reconstructs
  `xClientBaseB64u` through the HSS relayer routes, derives the canonical
  public key from that same ceremony, and then exports through the verified
  `near-ed25519-seed-v1` lane against that exact key
- the same script-level suite now includes an explicit route/session
  segregation case that verifies:
  - `/threshold-ed25519/hss/prepare` and `/threshold-ed25519/hss/finalize`
    requests do not carry raw `prfFirstB64u`, raw `xClientBaseB64u`, raw
    `seedB64u`, or server master-secret material
  - those relayer responses do not return raw `xRelayerBaseB64u`, raw server
    input material, or server master-secret material to the client
  - the active product route/session flow therefore keeps raw client and server
    secret inputs segregated while signing and export remain bound to the same
    canonical public key
- that same script suite now also covers the new sessionless registration HSS
  seam, verifying that managed registration bootstrap grants can bind to
  `/registration/threshold-ed25519/hss/prepare` and `/registration/threshold-ed25519/hss/finalize`
  and that those route bodies still stay free of raw `prfFirstB64u` and server
  master-secret material
- added
  [`tests/unit/thresholdEd25519.separatedRoles.script.unit.test.ts`](/Users/pta/Dev/rust/simple-threshold-signer/tests/unit/thresholdEd25519.separatedRoles.script.unit.test.ts),
  which runs the real
  [`prime_order_separated_roles_e2e.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/examples/prime_order_separated_roles_e2e.rs)
  example as a keep-gate and asserts the published segregation checklist still
  passes end to end:
  - `separation_of_shares`
  - `wire_messages_do_not_embed_raw_secret_inputs`
  - `client_never_gets_server_recovery_material`
  - `server_never_gets_client_recovery_material`
  - `split_role_e2e_matches_reference_output`
- persisting `xClientBaseB64u` onto the threshold session record now preserves
  `runtimeSnapshotScope`, so the later export path stays bound to the same
  canonical Option A session context instead of dropping that scope during
  session updates

### Phase 7: Cleanup and Documentation Cutover

- [x] Update all product docs to describe Option A as the implemented default.
- [x] Remove stale Option B references from the active Ed25519 signer/export
      docs.
- [x] Keep one active single-key Option A spec set only.
- [x] Delete obsolete Option B code, flags, and compatibility shims that are no
      longer needed.
- [x] Refresh performance and e2e benchmark docs after the product cutover.

Landed Phase 7 docs cleanup:

- `docs/homomorphic-key-export.md` now presents Option A as the active
  threshold-ed25519 path and moves Option B into a historical-background
  section instead of the active plan list
- `docs/stateless-shared-root-ed25519.md` now describes the active runtime path
  only and no longer frames Option B as code-adjacent active scaffolding
- `docs/homomorphic-key-export-ED25519-OPTION-B.md` is now explicitly a
  historical note, not live product specs
- the dead threshold-ed25519 bootstrap-package worker request/response path is
  deleted from the client/wasm worker surface instead of being left behind as a
  removed-but-still-exported shim
- the dead threshold-ed25519 registration recovery-share client helper,
  relay route definitions, router handlers, public types, and server service
  methods are deleted instead of being kept as dormant Option B baggage
- the dead shared Option B recovery-export challenge helper
  `shared/src/threshold/ed25519Recovery.ts` is deleted instead of being kept
  as an unreferenced helper for the removed Paillier export lane
- the pure Option B threshold-ed25519 unit suites
  `tests/unit/thresholdEd25519.export.unit.test.ts` and
  `tests/unit/thresholdEd25519.optionB.registration.integration.test.ts`
  are deleted instead of being preserved as active-path coverage
- the remaining recovery export API unit coverage now targets the active
  Option A `near-ed25519-seed-v1` worker lane instead of the deleted
  `near-ed25519-option-b-v1` payloads
- the passkey-confirm export worker suite now targets the active
  `near-ed25519-seed-v1` seed-export payload and no longer asserts the deleted
  Paillier `/threshold-ed25519/export/init` + `/combine` flow
- the near signing session-selection unit fixture now uses the canonical
  `threshold_ed25519_v1` IndexedDB record shape instead of the removed
  `threshold_ed25519_2p_v1` dual-key fixture fields
- the threshold-ed25519 e2e persistence helper no longer calls the deleted
  `keygenFromBootstrapPackage(...)` API and now persists relay registration
  material through the live `keygenFromRegistrationMaterial(...)` path instead
- the shared threshold-ed25519 e2e helpers and callers no longer use `OptionB`
  helper names for the active registration/bootstrap seam; the helper surface
  now refers to generic threshold-ed25519 registration material instead of
  broadcasting deleted Option B terminology
- the active-path threshold-ed25519 unit fixtures no longer use the removed
  `threshold_ed25519_2p_v1` record kind or carry stale wrap-key / recovery-key
  fixture baggage when the current `threshold_ed25519_v1` shape is sufficient
- the main threshold-ed25519 signing e2e suites no longer model
  `recoveryPublicKey` as an active second key; they now verify signatures
  against the canonical operational public key and a stable unrelated-key
  negative control instead
- the threshold-ed25519 IndexedDB persistence regression now targets the
  canonical `threshold_ed25519_v1` record shape instead of asserting deleted
  recovery/export/wrap-key payload fields on threshold key writes
- the local email-recovery regression no longer mocks or asserts removed
  threshold-ed25519 `recoveryPublicKey` / `relayerVerifyingShareB64u`
  response baggage, and the dead bootstrap-integrity check for tampered
  `recoveryPublicKey` is deleted instead of being preserved as fake coverage
- the shared threshold-ed25519 unit-test service helper no longer models an
  optional `recoveryPublicKey`, and it now derives
  `relayerVerifyingShareB64u` from the actual relayer signing share via the
  live Option A verifying-share helper instead of relying on arbitrary base64
  fixture bytes
- the relayer scheme-dispatch and relayer-cosigner stub suites now use that
  derived verifying-share path and no longer pin their threshold-ed25519 test
  fixtures to fabricated verifying-share blobs or the stale `option-b-v1`
  key-version literal
- the link-device and email-recovery prepare-route suites now model the current
  threshold-ed25519 public request/response shape: they no longer send or mock
  removed threshold-ed25519 verifying-share fields, and instead use the active
  single-key registration/session material (`key_version`, `public_key`,
  `relayer_key_id`, `recovery_export_capable`, and `session_policy`)
- the dead client-facing threshold-ed25519 keygen intent-digest helper is
  deleted from the public client threshold surface instead of being kept as an
  unreferenced leftover from the removed default keygen/bootstrap path
- the threshold signing concept docs now describe the active Option A
  registration/session/HSS lifecycle instead of any separate keygen bootstrap
  story
- the dead server-side `/threshold-ed25519/keygen` route, public types, scheme
  wiring, relay harness endpoint, and route-definition entry are deleted
  instead of being preserved as non-default migration baggage
- the threshold-ed25519 relay scope suite, shared e2e registration helper, and
  route-driven e2e tests no longer provision via `/threshold-ed25519/keygen`
  or no-op route fallbacks; they now seed registration/session material
  directly through the active single-key path
- the auth-gating docs now reflect the real threshold-ed25519 route split:
  `/registration/threshold-ed25519/hss/*` is api-credential bootstrap,
  `/threshold-ed25519/session` is public proof bootstrap, and
  `/threshold-ed25519/hss/*` is threshold-session gated
- the remaining mixed threshold-ed25519 unit fixtures now use the live
  `threshold-ed25519-hss-v1` key-version literal instead of stale
  `option-b-v1` values while still asserting the canonical
  `threshold_ed25519_v1` record shape and the absence of deleted recovery-key
  fields
- the obsolete `benchmarks/threshold-ed25519-dual-key` harness, its synced
  benchmark doc, and the matching `package.json` scripts are deleted instead
  of being left behind as a benchmark surface for a removed dual-key path
- `docs/stateless-shared-root-ed25519.md` now explicitly treats the current HSS
  checkpoint as the live threshold-ed25519 performance reference and no longer
  points readers at the removed dual-key benchmark harness
- the remaining signer-core Option B recovery/bootstrap helpers, tests, and
  fixture file are deleted instead of being kept as dead crypto background:
  `crates/signer-core/src/near_ed25519_recovery.rs` no longer exports that
  dual-key path, `wasm/near_signer/src/threshold/threshold_frost.rs` no longer
  exports the dead recovery-client-share wasm entrypoint, and
  `crates/signer-core/fixtures/ed25519-option-b-v1/` is deleted
- the active benchmark/docs surface now points at
  `docs/benchmarks/threshold-ed25519-option-a.md` and the refreshed
  `docs/load-testing.md` instead of the deleted dual-key harness

## Verification Checklist

- [x] threshold signing works through the Option A path
- [x] export works through the controlled seed-reconstruction path
- [x] both paths verify against the same canonical public key
- [x] client reconstruction is stateless from passkey PRF plus context
- [x] server reconstruction is stateless from server root material plus context
- [x] no active product path depends on Option B dual-key assumptions
- [x] no default stored key metadata still requires a second Ed25519 recovery key
- [x] no duplicate legacy Option B code remains in the default implementation

## Post-Plan Follow-On Work

These are not part of the migration close criteria anymore. They are the next
operational follow-ons after the Option A cutover:

- [x] Build the actor-based multi-wallet active-path threshold-ed25519 load
      harness described in
      [load-testing.md](/Users/pta/Dev/rust/simple-threshold-signer/docs/load-testing.md).
- [x] Broaden CI coverage from the current keep-gate slice to a larger active
      threshold-ed25519 relayer/e2e matrix.
- [ ] Reduce the remaining historical Option B background docs into one short
      archival note if keeping separate historical documents stops adding
      value.
