# Refactor 68: Wallet Session V2 Router A/B Normal Signing

Date created: June 15, 2026

Status: implemented locally. Deployed Cloudflare release evidence remains open.

Primary source of truth:

- [router-a-b-single-session.md](./router-a-b-single-session.md)
- [router-A-B-signer.md](./router-A-B-signer.md)
- [router-A-B-signer-SPEC.md](./router-A-B-signer-SPEC.md)
- [router-a-b-local-dev.md](./router-a-b-local-dev.md)

This file preserves the historical refactor plan for agents working on the SDK.
The implementation plan was written in `docs/router-a-b-single-session.md` while
the cutover was in progress. This refactor note records the finished shape,
major decisions, completed phases, validation evidence, and the remaining
release-tail work.

## Goal

Make Router A/B normal signing expose one client-facing authorization concept:

```text
Wallet Session
```

The SDK sends a Wallet Session credential and typed signing request to the
public Router. Router verifies the Wallet Session, validates the typed request,
recomputes the intent and signing-payload digests, applies policy/quota/abuse
and replay gates, then forwards only Router-admitted material to the
SigningWorker.

The public client boundary no longer exposes a Router normal-signing grant.

Follow-up cleanup for making Router A/B the only Ed25519 and ECDSA signing
architecture is tracked in
[router-a-b-cleanup.md](./router-a-b-cleanup.md). That follow-up deletes the
separate non-Router threshold-session signing stack after Router A/B replacement
coverage is complete.

## Starting Point

Before this refactor, Router A/B normal signing had the cryptographic pieces in
place, while the public authorization surface still carried transitional grant
and threshold-session naming.

- SDK normal-signing helpers accepted `thresholdSessionAuthToken`.
- Strict Cloudflare normal-signing routes verified a Router JWT carrying
  per-request `intentDigest`.
- Public v1 request bodies carried digest-only authority plus signing protocol
  material.
- Router already had admission-store machinery for request id, policy, quota,
  abuse, and replay handling.

The design problem was user-visible authority fragmentation. A caller had a
Wallet Session and then had to handle a second Router normal-signing grant. This
refactor moved per-signature authority into Router-side typed request
validation.

## Final Model

Public route shape:

```text
POST /v2/router-ab/ed25519/sign/prepare
POST /v2/router-ab/ed25519/sign
```

Public credential:

```ts
type WalletSessionCredential = {
  kind: 'bearer_wallet_session';
  walletSessionJwt: string;
};
```

Target flow:

```text
Client
  -> Router: bearer Wallet Session + typed v2 request
Router
  -> verifies Wallet Session
  -> parses raw request bytes through v2 boundary parsers
  -> validates account, session, policy, quota, replay, and SigningWorker scope
  -> recomputes canonical intent digest
  -> recomputes canonical signing-payload digest
  -> derives admitted Ed25519 signing digest
  -> creates an internal admission candidate
  -> forwards admitted private prepare/finalize material to SigningWorker
SigningWorker
  -> stores one-use round-1 material on prepare
  -> consumes the round-1 record on finalize
  -> signs the Router-admitted 32-byte digest
Router
  -> validates response binding
  -> returns the result to the client
```

Router admission is internal state. It is never returned to the SDK as a token.

## Client Material Boundary

TypeScript SDK code orchestrates Router A/B signing with worker handles and
public facts. It may persist and route material handles, binding digests,
Wallet Session JWTs, session ids, runtime-policy scope, SigningWorker scope,
client verifying-share public facts, ECDSA public identity, and activation
metadata.

`crates/signer-core` and the browser WASM workers own crypto-secret client
material and crypto-adjacent validation. Ed25519 HSS client-base material,
ECDSA-HSS client signing shares, presignature/client-share material, nonce
state, PRF-derived secret material, binding checks, and signing-share
generation stay behind that boundary. Active SDK signing paths consume strict
Router A/B Wallet Session state plus worker-owned handles.

## Core Decisions

- Bearer Wallet Session JWT is the only MVP public credential for Router A/B
  normal signing.
- Cookie Wallet Session auth is deferred until CSRF, SameSite, exact-origin
  CORS, credentialed request, and preflight-cache requirements are specified and
  covered.
- The SDK uses `credentials: 'omit'` for public Router A/B normal-signing
  requests.
- Strict Cloudflare normal-signing CORS requires an exact configured origin.
  Missing, empty, or wildcard CORS config fails closed.
- Strict Cloudflare normal-signing responses omit
  `Access-Control-Allow-Credentials`.
- Public v2 request types stay branch-specific:
  NEAR transaction, NEP-413, and NEP-461 delegate action.
- Rust `router-ab-core` is the canonicalization authority for intent,
  signing-payload, admitted-signing digest, and boundary parsing.
- SigningWorker private routes never parse Wallet Session credentials.
- Deriver A and Deriver B stay off the normal-signing hot path.
- `V2` remains part of the active public prepare/finalize wire contract.
  Existing `V1` suffixes stay only where they name current durable wire schemas,
  route versions, persistence records, metric versions, or cryptographic
  protocol primitives.

## Completed Phases

### Phase 1: Typed V2 Public Requests

- [x] Added `RouterAbEd25519NormalSigningIntentV2` with branch-specific fields
      for NEAR transactions, NEP-413, and delegate actions.
- [x] Added `RouterAbEd25519SigningPayloadV2` with one authoritative preimage
      per branch and an explicit expected 32-byte Ed25519 signing digest.
- [x] Added raw request-body boundary parsers that normalize untrusted JSON once
      into precise v2 types.
- [x] Added Rust canonical digest helpers for intent, signing payload, and
      admitted signing digest.
- [x] Added real Borsh parsing for NEAR unsigned transactions and NEP-461
      delegate-action preimages.
- [x] Added vector fixtures for accepted digests, malformed payload rejection,
      expected digest drift, and typed intent/preimage mismatch.
- [x] Replaced digest-only v1 public request tests that encoded old public
      authority.

### Phase 2: Wallet Session Router Admission

- [x] Added strict Router Wallet Session boundary types and verifier plumbing.
- [x] Replaced public normal-signing JWT claim verification with Wallet Session
      verification on prepare and finalize.
- [x] Built prepare/finalize admission candidates only after Wallet Session
      verification, typed request parsing, digest recomputation, preimage
      consistency checks, and expiry checks.
- [x] Fed policy, quota, abuse, and replay stores from internal admission
      metadata.
- [x] Bound prepare/finalize to request id, account id, session id,
      SigningWorker id, intent digest, signing-payload digest, admitted signing
      digest, round-1 binding digest, and expiry.
- [x] Added strict Worker CORS and preflight behavior for the v2 public
      normal-signing endpoints.

### Phase 3: SigningWorker Private Boundary

- [x] Removed Wallet Session parsing from SigningWorker private routes.
- [x] Forwarded only Router-admitted prepare/finalize material to SigningWorker.
- [x] Persisted v2 round-1 binding digest and Router-admitted signing digest in
      the round-1 record.
- [x] Finalize now signs only the persisted Router-admitted 32-byte digest.
- [x] Preserved single-use round-1 `take` semantics.
- [x] Added binding-drift rejection coverage before nonce consumption.

### Phase 4: SDK Public Client Boundary

- [x] Replaced `ThresholdEd25519PresignPoolRouteAuth` at the Router A/B
      normal-signing boundary with Wallet Session credentials.
- [x] Mapped persisted threshold-session transport records into Wallet Session
      credentials once at the SDK boundary.
- [x] Replaced `prepareRouterAbNormalSigningV1` and
      `finalizeRouterAbNormalSigningV1` with v2 request builders.
- [x] Built branch-specific SDK request builders for NEAR transaction signing,
      NEP-413, and delegate actions.
- [x] Matched SDK diagnostic digests against Rust v2 vector fixtures.
- [x] Added TypeScript type fixtures and source guards for invalid branch
      combinations and deleted public legacy names.

### Phase 5: Local And Self-Hosted Paths

- [x] Updated local Router workers and bundled local profile to the Wallet
      Session plus typed v2 request shape.
- [x] Updated local smoke fixtures so NEAR transactions, NEP-413, and delegate
      actions use Wallet Session auth.
- [x] Verified Express/local relay route definitions do not mirror Router A/B
      normal signing.
- [x] Removed mocks, fixtures, and guards that existed only for the
      client-visible Router normal-signing grant.

### Phase 6: Guards, Tests, And Release Gates

- [x] Added Rust negative coverage for account mismatch, session mismatch,
      replayed request ids, intent digest drift, signing-payload digest drift,
      admitted signing digest drift, and typed intent/preimage mismatch.
- [x] Added expiry clamping and exact-expiry rejection coverage for prepare and
      finalize.
- [x] Added accepted-path coverage for NEAR transaction, NEP-413, and delegate
      action normal signing through Wallet Session auth.
- [x] Added source guards proving public normal-signing routes do not read JWT
      `intentDigest`.
- [x] Added source guards proving SigningWorker private routes cannot parse
      Wallet Session credentials.
- [x] Added SDK guards proving deleted grant names cannot return at the public
      client boundary.
- [x] Restored `rtk pnpm -C packages/sdk-web type-check`.
- [x] Ran local Router smoke gates through split-worker and bundled topologies.

### Phase 7: Delete Legacy Normal-Signing Surface

- [x] Deleted grant-oriented public auth types and verifier APIs.
- [x] Deleted v1 public Router normal-signing handlers.
- [x] Deleted old Router-to-SigningWorker v1 service-call helpers.
- [x] Deleted private SigningWorker v1 request wrappers and old handler traits.
- [x] Deleted digest-only `router-ab-core` public normal-signing request
      structs.
- [x] Deleted SDK v1 helper names and `routerAbNormalSigningGrant` branches.
- [x] Re-scanned SDK, server, tests, and Rust Router A/B source for the deleted
      symbols. Active source matches are gone outside docs and guard deny-lists.

### Phase 8: Cleanup And Naming Normalization

- [x] Removed the old credentialed CORS header from bearer-only strict
      normal-signing responses.
- [x] Normalized pre-gate admission naming to explicit prepare/finalize
      admission candidates.
- [x] Renamed the private SigningWorker prepare field to `admission_candidate`.
- [x] Defined expiry, quota, replay, and abandoned-prepare cleanup semantics.
- [x] Added cleanup operations for expired replay, quota, and SigningWorker
      round-1 records.
- [x] Added deployed-browser evidence harness:
      `rtk pnpm router:deploy:browser-evidence`.
- [x] Completed the broader non-Router-A/B cleanup follow-up:
      app CSS token rename, sealed-session parser naming cleanup, synthetic
      legacy ECDSA key-id branch deletion, demo seed cleanup, PostgreSQL startup
      migration cleanup, and cron rotation flag deletion.

## Follow-Up Progress Log

This section records Wallet Session V2 cleanup progress after the original
local cutover. Keep updating it as cleanup slices land so future agents can see
which historical names are already gone and which boundaries still intentionally
retain protocol or persistence fields.

### June 17, 2026

- [x] Renamed current persisted and sealed signing-session auth fields to
      `walletSessionJwt`.
      Current Ed25519/ECDSA stored records, sealed restore metadata,
      warm-capability read models, UI-confirm restore helpers, shared
      `signingSessionSeal` types, and matching typed fixtures now use
      `walletSessionJwt`. The old stored-field parser was deleted from the SDK
      persistence/sealed-record path.
- [x] Removed the old auth field from current SDK state types and redaction
      lists.
      ECDSA key refs and NEAR resolved signing-session state no longer carry a
      `thresholdSessionAuthToken?: never` compatibility field; excess-property
      fixtures still reject the old key. Email OTP escrow redaction deny-lists
      now reject `walletSessionJwt`.
- [x] Renamed shared SDK/server session-token helpers to Wallet Session JWT
      terminology.
      `sessionTokens.ts` now exposes `WalletSessionJwtKind`,
      `WalletSessionJwtAuth`, `AppOrWalletSessionAuth`,
      `isWalletSessionJwt`, `requireWalletSessionJwt`,
      `walletSessionJwtAuth`, and `appOrWalletSessionJwtAuth`. The server
      boundary signer is now `signWalletSessionJwt`. The JWT payload `kind`
      strings and the retained `threshold_session` route-auth discriminant are
      stable protocol values.
- [x] Renamed remaining test-harness auth fixtures to `walletSessionJwt`.
      E2E debug snapshots, Ed25519 bootstrap helpers, Email OTP tempo helpers,
      and relayer integration fixtures no longer construct or assert
      `thresholdSessionAuthToken`. Remaining matches are negative type fixtures
      and source-guard token lists.
- [x] Renamed the active NEAR Ed25519 Wallet Session state helper.
      `thresholdSessionAuth.ts` is now
      `routerAbEd25519WalletSessionState.ts`, with exported resolver/require
      helpers using `ResolvedRouterAbEd25519WalletSessionState` naming. The
      focused browser unit test is now
      `routerAbEd25519.walletSessionState.unit.test.ts`.
- [x] Renamed ECDSA active route-auth plumbing away from
      `thresholdSessionAuth`.
      ECDSA activation/bootstrap request branches now carry
      `walletSessionRouteAuth`. The lifecycle guard enforces that this field is
      branch-specific.
- [x] Tightened ECDSA reconnect readiness identity handling.
      `ecdsaReadiness.ts` now compares exact ECDSA session identities through
      `buildEcdsaSessionIdentity` instead of paired local raw string parsing.
- [x] Restated the signing-root boundary invariant in the active cleanup plan.
      `signingRootId` and `signingRootVersion` are not Wallet Session V2 client
      fields. They should be isolated to server-side code, protocol helpers,
      and persistence/request normalization boundaries while SDK domain objects,
      registration/link-device payloads, active ECDSA key refs,
      warm-capability records, and Email OTP worker payloads move behind
      `EvmFamilyEcdsaKeyHandle` / Router A/B key-handle state.
- [x] Removed signing-root identity fields from active ECDSA key refs.
      `ThresholdEcdsaSecp256k1KeyRef` now rejects `signingRootId` and
      `signingRootVersion`. Activation, wallet-registration bootstrap,
      warm-session fixtures, ready-signer tests, and Email OTP worker bootstrap
      returns keep key refs on `keyHandle`, public key facts, and Wallet
      Session state. Persistence and signer activation derive signing-root
      binding from `runtimePolicyScope` or role-local public facts at boundary
      normalization time.
- [x] Extended public-surface guards for signing-root isolation.
      Guard coverage now rejects `signingRootId`, `signingRootVersion`, and
      `runtimePolicyScope` on public ECDSA SDK args and iframe payloads, and
      requires active SDK `KeyRef` to keep signing-root fields as `never`
      tripwires.
- [x] Classified remaining SDK-side signing-root occurrences.
      The cleanup plan now separates allowed persistence/request boundaries,
      allowed protocol/HSS helpers, current internal HSS identity contexts, and
      remaining removal targets in registration/link-device/recovery payloads,
      Email OTP worker payloads, older use-case route helpers, and non-boundary
      type fixtures.
- [x] Removed direct signing-root reads from link-device and email-recovery
      ECDSA prepare payload parsers.
      These parsers now require `runtimePolicyScope`, derive signing-root
      binding with `signingRootScopeFromRuntimePolicyScope`, and pass the
      normalized scope through the ECDSA prepare context. Wallet-key inventory
      responses still carry signing-root identity as server key facts.
- [x] Removed signing-root identity from the Email OTP ECDSA explicit-export
      worker request payload.
      The SDK sends `keyHandle`, route/session auth, and the role-local
      `readyRecord`; the worker derives signing-root binding from parsed
      `readyRecord.publicFacts` before constructing the HSS export digest.
      Type fixtures and the coordinator unit test now guard against
      reintroducing `signingRootId` or `signingRootVersion` on this worker
      request.
- [x] Removed signing-root identity from the Email OTP Ed25519 seed-export
      worker request payload.
      The export API now relies on the stored session record's
      `runtimePolicyScope`; the worker derives the HSS signing-root id with
      `signingRootScopeFromRuntimePolicyScope` before invoking the low-level
      Ed25519 export helper. Type fixtures and the coordinator unit test guard
      against reintroducing root fields on this request.
- [x] Removed signing-root identity from ECDSA provisioning and bootstrap route
      inputs.
      `ProvisionEcdsaInput` and `BootstrapEcdsaSessionRouteInput` now require
      `runtimePolicyScope` and derive `signingRootId` / `signingRootVersion`
      only at protocol, persistence, and HSS-helper boundaries. The relayer
      bootstrap output type no longer returns signing-root fields, and focused
      fixtures/tests reject reintroducing them into the SDK use-case input.
- [x] Removed signing-root identity from registration precompute and ECDSA
      warm-provision context shapes.
      Wallet-registration precompute readiness now carries
      `thresholdRuntimePolicyScope` and derives the root only when building
      Ed25519 HSS client material. `EcdsaSigningKeyContext` now carries only
      threshold key id and participant ids; activation, EVM reconnect digest
      construction, and prepared-signing metadata derive signing-root binding
      from authoritative key identity or persisted session records.
- [x] Removed signing-root identity from warm auth plans and prepared EVM
      signing operation metadata.
      `SigningAuthPlan` / `WalletAuthPlan` warm-session branches now carry
      only curve, threshold session id, expiry, and remaining-use data.
      Prepared EVM signing metadata now carries operation id, optional
      operation fingerprint, exact lane identity key, and selected material;
      signing-root binding stays inside protocol/persistence material and HSS
      boundaries.
- [x] Removed signing-root identity from additional Email OTP host-facing
      material and worker request shapes.
      `EmailOtpRecoveryCodeRotationMaterial` no longer exposes
      `signingRootId` / `signingRootVersion`. The ECDSA warm-session
      rehydrate request now sends companion Ed25519 `runtimePolicyScope`; the
      Email OTP worker derives its exact internal root binding at the worker
      boundary before deriving the Ed25519 restore seed.
- [x] Removed loose signing-root identity from SeamsWeb Ed25519 registration
      HSS preparation helpers.
      Registration and add-signer flows now pass the threshold runtime policy
      scope to the helper, and the helper derives `signingRootId` only at the
      low-level Ed25519 HSS client-material boundary.
- [x] Removed stale signing-root fields from the ECDSA provisioning lifecycle
      type.
      `EcdsaProvisioningState.needs_secret_source` now carries `keyHandle` and
      `runtimePolicyScope`, and type fixtures reject reintroducing
      `signingRootId` on that SDK lifecycle branch.
- [x] Removed a non-boundary signing-root argument from the NEAR Ed25519
      explicit-export wrapper.
      The export orchestration helper now receives `runtimePolicyScope` and
      derives `signingRootId` only when it calls the low-level HSS export
      ceremony helper. Focused private-key export fixtures were updated to the
      current `keyMaterialStore` dependency shape.
- [x] Made the Email OTP wallet-unlock worker boundary require
      `runtimePolicyScope`.
      The login flow already resolves the scope before calling the worker
      payload builder, so this removes an optional core identity field from the
      active SDK path.
- [x] Tightened the `loginWithEmailOtpWallet` worker operation contract.
      The shared worker payload type now requires `runtimePolicyScope`, the
      raw worker parser rejects missing scope, and the worker no longer falls
      back to route-JWT scope parsing for wallet unlock.
- [x] Removed signing-root identity from Email OTP enrollment-restore and
      recovery-code rotation worker results.
      The worker still keeps signing-root binding inside encrypted escrow and
      recovery-key AAD handling, while `restoreEmailOtpDeviceEnrollmentEscrow`
      and `rotateEmailOtpRecoveryCodes` now return root-free result shapes to
      host SDK code. Type fixtures reject adding `signingRootId` /
      `signingRootVersion` back to those results.
- [x] Removed the host-supplied Email OTP ECDSA role-local key identity handoff.
      `bootstrapEmailOtpEcdsaSessionsFromWorkerHandle` now receives `keyHandle`
      and `runtimePolicyScope`; the worker derives role-local threshold key id,
      signing-root binding, and relayer key id inside the HSS bootstrap
      boundary. Existing-key bootstrap checks the supplied key handle against
      that derived identity, and the obsolete resolver/test were deleted.
- [x] Removed redundant signing-root fields from ready EVM signing material.
      `ReadyEvmFamilyEcdsaMaterial.signingKeyContext` now carries only the
      threshold key id and participant ids; signing-root binding stays on the
      protocol key identity or persisted record boundary. Type fixtures reject
      reintroducing `signingRootId` on that context.
- [x] Removed signing-root identity from ECDSA availability diagnostics.
      ECDSA lane debug summaries now report key handle, shared key
      fingerprint, threshold key id, public facts, and session ids, and sealed
      ECDSA record debug summaries report restore target identity without
      exposing `signingRootId` / `signingRootVersion`. Conflict grouping and
      protocol identity checks still use root binding internally.
- [x] Removed duplicated full ECDSA key identity from wallet signing budget
      spend plans.
      `EcdsaWalletSigningSpendPlan` now derives ECDSA key identity from its
      selected lane and rejects an `ecdsaKey` field. The internal budget status
      check builder still uses `spend.lane.key` for exact ECDSA status reads,
      and the spend-plan builder no longer accepts a duplicate identity bag.
- [x] Reclassified `ecdsaUseCaseClient.ts` as an active protocol boundary.
      Its public/use-case input remains root-free; it derives signing-root
      binding from `runtimePolicyScope` only when building the low-level
      ECDSA-HSS route request and role-local storage facts.
- [x] Collapsed a login ECDSA bootstrap helper that returned loose
      signing-root fields.
      The helper now returns `keyHandle` plus normalized
      `EvmFamilyEcdsaKeyIdentity`, keeping signing-root binding at the
      key-identity boundary instead of exposing another intermediate SDK object.
- [x] Renamed Wallet Session activation dependency plumbing.
      `ThresholdSessionActivationDeps`,
      `createThresholdSessionActivationDeps`, and
      `thresholdSessionActivationDeps` are now
      `WalletSessionActivationDeps`,
      `createWalletSessionActivationDeps`, and
      `walletSessionActivationDeps`, keeping active Router A/B bootstrap and
      warm-session assembly aligned with the Wallet Session V2 public model.
- [x] Renamed the Email OTP active coordinator wrapper.
      `EmailOtpThresholdSessionCoordinator`,
      `EmailOtpThresholdSessionCoordinatorDeps`, and
      `EmailOtpThresholdSessionRuntime` are now
      `EmailOtpWalletSessionCoordinator`,
      `EmailOtpWalletSessionCoordinatorDeps`, and
      `EmailOtpWalletSessionRuntime`. Durable `thresholdSessionId` fields stay
      as persisted session identifiers.
- [x] Renamed active NEAR Ed25519 Router A/B Wallet Session state locals.
      The transaction, NEP-413, delegate, Router A/B presign/finalize, NEAR
      Ed25519 export, and passkey sealed-refresh helpers now use
      `walletSessionState` naming for
      `ResolvedRouterAbEd25519WalletSessionState`, while the persisted
      threshold session id remains the durable worker-session identifier.
- [x] Renamed sealed recovery and UI-confirm Wallet Session JWT boundary locals.
      Sealed recovery runtime-scope parsing and UI-confirm persisted auth
      helpers now use Wallet Session JWT/session-auth naming instead of
      threshold-session auth-token helper names. Durable stored fields such as
      `thresholdSessionKind` remain persistence schema names.
- [x] Renamed active auth-unavailable helpers away from threshold-session
      auth-token wording.
      `SIGNING_SESSION_AUTH_UNAVAILABLE_ERROR` and
      `isSigningSessionAuthUnavailableError` now describe the active
      signing-session auth failure path. ECDSA ready material reports Wallet
      Session auth unavailability, and iframe error mapping recognizes the new
      canonical message.
- [x] Renamed warm-session test fixture auth inputs to Wallet Session JWT
      terminology.
      `createThresholdEcdsaBootstrapFixture` and warm-session unit tests now
      pass `walletSessionJwt` instead of `sessionAuthToken`; negative fixtures
      still mention `thresholdSessionAuthToken` only to reject it.
- [x] Renamed live threshold warm-session bootstrap auth locals.
      Ed25519 registration and passkey warm-session bootstrap now use
      `walletSessionJwt` local names when handling session JWT material.
- [x] Renamed the active NEAR signing-session auth planner.
      `signingSessionAuthMode.ts`, `NearSigningSessionAuthPlan`,
      `NearSigningSessionAuthContext`,
      `resolveNearSigningSessionAuthContext`, and
      `buildNearSigningSessionAuthPlan` now describe the active planner
      boundary without old threshold-auth-mode naming.
- [x] Restricted the public threshold subpath away from low-level session
      bootstrap helpers.
      `@seams/sdk/threshold` no longer re-exports
      `connectEd25519Session` or `connectEcdsaSession`; those helpers remain
      internal provisioning implementation details behind SeamsWeb and the
      passkey/session surfaces.
- [x] Renamed the Ed25519 Wallet Session mint helper surface.
      `Ed25519WalletSessionMintAuthorization`,
      `localPrfFirstForEd25519WalletSessionMintAuthorization`, and
      `mintEd25519WalletSession` now describe the active Wallet Session JWT
      mint boundary. The SDK helper module is now `walletSession.ts` with a
      matching `walletSession.typecheck.ts` fixture. Current route
      discriminants remain versioned boundary values.
- [x] Renamed the server Wallet Session record-store surface.
      `AuthSessionStore.ts` became `WalletSessionStore.ts`, and server exports,
      store factories, record/parser types, signing-session seal policy helpers,
      Durable Object bindings, tests, and README examples now use Wallet
      Session names. The follow-up schema/config bump moved the remaining
      `AUTH_PREFIX` and `auth:` storage vocabulary to Wallet Session prefix,
      row-kind, and consumption-table names.
      Validation: `rtk pnpm -C packages/sdk-server-ts run type-check`, the
      focused signing-session seal / wallet-budget / rehydrate / malformed-row
      unit bundle, the ECDSA durable-store relayer test, the Router A/B SDK
      guard, and `rtk git diff --check`.
- [x] Renamed the app server's signing-session-seal store construction to the
      Wallet Session store surface.
      `apps/web-server/src/index.ts` now imports
      `createEd25519WalletSessionStore`, `createEcdsaWalletSessionStore`, and
      `createSigningSessionSealPolicyFromWalletSessionStores`. Validation:
      `rtk pnpm -C apps/web-server exec tsc --noEmit`.
- [x] Applied the Wallet Session store schema/config prefix bump.
      `THRESHOLD_ED25519_AUTH_PREFIX`,
      `THRESHOLD_ECDSA_AUTH_PREFIX`, the `auth:` derived keyspace, the
      Postgres `kind = 'auth'` store row, and
      `threshold_ed25519_auth_consumptions` are now Wallet Session-named
      as `THRESHOLD_ED25519_WALLET_SESSION_PREFIX`,
      `THRESHOLD_ECDSA_WALLET_SESSION_PREFIX`, `wallet-session:`,
      `kind = 'wallet_session'`, and
      `threshold_wallet_session_consumptions`.
      Validation: `rtk pnpm -C packages/sdk-server-ts run type-check`, the
      focused malformed-row / wallet-budget / signing-session seal unit bundle,
      and the ECDSA durable-store relayer test.
- [x] Renamed active ECDSA-HSS pool-fill auth and SDK diagnostics.
      The active ECDSA session-token route boundary now returns Wallet Session
      wording, the server pool-fill handlers report Router A/B ECDSA-HSS
      pool-fill scope errors, and the SDK pool-fill helper types/fallback
      messages no longer describe the deleted public
      `/threshold-ecdsa/presign/*` route surface.
      Validation: `rtk pnpm -C packages/sdk-server-ts run type-check`, `rtk
      pnpm -C packages/sdk-web run type-check`, the focused ECDSA-HSS
      presign-distributed / presign-bridge / presign-refill / normal-signing
      unit bundle, and the ECDSA relayer signature harness.
- [x] Renamed the SDK public-auth domain helper away from stale auth-session
      vocabulary.
      `authSessions.ts`, `AuthSessionDomainDeps`, `AuthSessionSigningSurface`,
      `AuthSessionWebContext`, and `getAuthSessionDeps` are now
      `walletAuth.ts`, `WalletAuthDomainDeps`, `WalletAuthSigningSurface`,
      `WalletAuthWebContext`, and `getWalletAuthDeps`.
      Validation: `rtk pnpm -C packages/sdk-web run type-check` and the focused
      public-auth / SeamsWeb login / wallet-iframe guard bundle.
- [x] Cleaned active/public documentation after the Router A/B-only signing
      cleanup.
      Obsolete old-route docs for Ed25519 session auth, ECDSA presign-pool
      lifecycle, Cloudflare self-host route shape, and the old Ed25519 benchmark
      reference were deleted. The route-auth, load-testing, ECDSA signing, and
      docs-app threshold-signing pages now describe Router A/B plus Wallet
      Session V2 as the current product signing architecture.
      Validation: active docs/apps/packages stale-reference scans found no
      deleted standalone doc paths, deleted benchmark harness paths, broken
      walletAuth-gating link, or exact deleted public signing route literals
      outside cleanup/audit/refactor/future notes; the auth-secret terminology
      guard passed under `playwright.config.ts`.
- [x] Closed the Router A/B cleanup suffix audit for the current code state.
      Durable wire/schema/route/persistence/crypto/worker names stay versioned.
      Stale suffixes were removed from the internal
      `routerAbEcdsaHssActiveStateSessionId` helper and from the
      await-confirmation test alias. Validation: SDK type-check, focused
      await-confirmation and Router A/B ECDSA-HSS normal-signing unit tests, and
      source scans passed.

### June 18, 2026

- [x] Patched the Wallet Session V2 lifecycle JWT tail that was still assuming
      legacy threshold-session token kinds.
      Wallet-registration, link-device, sync-account, and email-recovery
      lifecycle issuers now mint Router A/B Wallet Session JWT kinds for current
      Ed25519 and ECDSA-HSS signing-capable sessions. Budget-status parsing,
      ECDSA durable-lane recovery, and current server route/service boundaries
      now require Router A/B Wallet Session JWT kinds for signable state.
- [x] Updated server HSS/session claim boundaries to enforce Router A/B Wallet
      Session claims only for active signing-capable state.
      `ThresholdSigningService` now parses Router A/B Ed25519 claims for HSS
      prepare/respond/finalize and Router A/B ECDSA-HSS claims when an existing
      ECDSA Wallet Session authorizes Ed25519 session minting. Legacy
      threshold-session claim parsers remain only in the validation boundary
      file with deletion-condition comments and source-guard coverage.
- [x] Added strict server Wallet Session JWT wrapper coverage.
      Active signable issuers now call
      `signRouterAbEd25519WalletSessionJwt` or
      `signRouterAbEcdsaHssWalletSessionJwt`, which hard-code Router A/B claim
      kinds, reject cookie-mode signing auth, and require curve-specific Router
      A/B binding inputs before minting a JWT. Those bindings are now part of
      the signed JWT payload, and Router A/B claim parsers reject under-bound
      tokens. ECDSA-HSS JWTs carry exactly one binding branch:
      `routerAbEcdsaHssNormalSigning` or `routerAbEcdsaHssIssuerBinding`. The
      generic signer implementation is private and Router A/B-only.
      SDK signing-capable state no longer normalizes browser-cookie auth into
      Ed25519/ECDSA signer state. Validation covered
      `rtk pnpm -C packages/sdk-server-ts type-check`, focused claim/budget
      parser unit tests, the server claim-boundary source guard, and the
      relayer seal plus Ed25519/ECDSA route subset.
- [x] Finish the remaining cookie-mode lower-level provisioning audit.
      Current login/warm-session paths require bearer Wallet Session auth for
      Router A/B signing. Lower-level Email OTP/passkey provisioning helpers were
      audited and narrowed so app-session cookies remain route authorization
      only, while signing-capable Wallet Session records cannot be minted or
      advertised without Router A/B state and bearer JWT material.
      Completed in the strict internal signing Wallet Session pass: SDK
      signing-capable provision/bootstrap/worker payloads are JWT-only, active
      Ed25519 and ECDSA ready-state builders consume strict Router A/B signing
      Wallet Session types, and server route wrappers parse Router A/B session
      info before issuing Wallet Session JWTs.

Recent validation for this cleanup pass:

- `rtk pnpm -C packages/sdk-web run type-check`
- `rtk pnpm -C packages/sdk-server-ts run type-check`
- `rtk pnpm -C tests exec playwright test unit/signingBudgetStatus.parser.unit.test.ts unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts --reporter=line`
- `rtk pnpm -C packages/sdk-web run build`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/sessionTokens.unit.test.ts ./unit/thresholdSessionClaims.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbEd25519.walletSessionState.unit.test.ts ./unit/warmSessionStore.bootstrapResolution.unit.test.ts ./unit/warmSessionStore.capabilityResolution.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.relayer.config.ts ./relayer/email-otp.bootstrap-integration.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/addWalletSigner.orchestration.unit.test.ts ./unit/seamsWeb.loginThresholdWarm.unit.test.ts ./unit/warmSessionEcdsaProvisioning.unit.test.ts ./unit/warmSessionStore.reconnect.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/provisionEcdsaUseCase.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/emailOtpWalletSessionCoordinator.unit.test.ts ./unit/emailOtpOperationSplit.guard.unit.test.ts ./unit/signingEngineArchitecture.flows.guard.unit.test.ts ./unit/thresholdEd25519.nearSigningQueue.guard.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts ./unit/routerAbEd25519.walletSessionState.unit.test.ts ./unit/thresholdEd25519.presignPool.unit.test.ts ./unit/nearSigning.sessionSelection.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/exportKeysUseCase.unit.test.ts ./unit/exportLaneSelection.unit.test.ts ./unit/crossPlatformBoundaries.guard.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/sealedRecovery.methodAdapters.unit.test.ts ./unit/signingSessionRestoreCoordinator.unit.test.ts ./unit/sealedSessionStore.unit.test.ts ./unit/touchConfirm.workerRouter.integration.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdSigningSessionReadiness.unit.test.ts ./unit/warmSessionStore.errorNormalization.unit.test.ts ./unit/walletIframeHost.signTempoCancel.unit.test.ts ./unit/signingFlow.readySigner.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/warmSessionStore.prfClaim.unit.test.ts ./unit/warmSessionStore.reconnect.unit.test.ts ./unit/warmSessionStore.transitions.unit.test.ts ./unit/warmSessionStore.invariants.unit.test.ts ./unit/warmSessionStore.concurrency.unit.test.ts ./unit/warmSessionStore.errorNormalization.unit.test.ts ./unit/warmSessionStore.capabilityResolution.unit.test.ts ./unit/warmSessionStore.bootstrapResolution.unit.test.ts ./unit/warmSessionRuntime.unit.test.ts ./unit/warmSessionEcdsaProvisioning.unit.test.ts ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts ./unit/evmFamily.requestBoundary.unit.test.ts ./unit/evmFamilyStepUpProvisionPlan.unit.test.ts ./unit/emailOtpWalletSessionCoordinator.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEd25519.registrationWarmSession.unit.test.ts ./unit/seamsWeb.loginThresholdWarm.unit.test.ts ./unit/warmSessionStore.bootstrapResolution.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/nearSigning.sessionSelection.unit.test.ts ./unit/warmSessionStore.errorNormalization.unit.test.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts ./unit/routerAbEd25519.walletSessionState.unit.test.ts ./unit/thresholdEd25519.presignPool.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.config.ts unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/warmSessionEcdsaProvisioning.unit.test.ts ./unit/warmSessionStore.reconnect.unit.test.ts ./unit/evmSigning.thresholdReconnectEvents.unit.test.ts ./unit/addWalletSigner.orchestration.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/seamsWeb.loginThresholdWarm.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.config.ts ./unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts ./unit/signingEngineEcdsaIdentity.publicSurfaces.guard.unit.test.ts ./unit/signingEngineEcdsaIdentity.lifecycle.guard.unit.test.ts --reporter=line`
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEcdsa.bootstrapPersistence.unit.test.ts ./unit/warmSessionStore.concurrency.unit.test.ts ./unit/evmFamilyEcdsaIdentity.unit.test.ts ./unit/signingFlow.readySigner.unit.test.ts --reporter=line`
- `rtk git diff --check`

## Validation Evidence

Representative validation from June 15, 2026:

- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml normal_signing`
  passed.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
  passed.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- normal_signing_v2`
  passed.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --benches`
  passed.
- `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http`
  passed.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningVectors.unit.test.ts ./unit/routerAbNormalSigningValidation.unit.test.ts --reporter=line`
  passed.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`
  passed.
- `rtk pnpm router:smoke` passed.
- `rtk pnpm router:smoke:bundled` passed.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 279 tests after adding pool-backed ECDSA-HSS strict private
  prepare dispatch and strict private presignature pool-fill dispatch.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after adding pool-backed ECDSA-HSS strict private prepare dispatch.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after adding pool-backed ECDSA-HSS strict private prepare dispatch.
- `rtk pnpm router:deploy:check` passed before ECDSA-HSS was promoted to a
  pre-deploy release blocker; the current release tail remains blocked on the
  ECDSA-HSS items below.
- `rtk pnpm -C packages/sdk-web type-check` passed.
- `rtk pnpm -C apps/web-client typecheck` passed after the broader cleanup.
- `rtk pnpm -C packages/sdk-server-ts type-check` passed after the broader
  cleanup.
- `rtk pnpm -C packages/sdk-server-ts type-check` passed after adding the
  Router A/B ECDSA-HSS presignature bridge and sender.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbEcdsaHssPresignBridge.unit.test.ts --reporter=line`
  passed with 6 tests after adding the Router A/B ECDSA-HSS presignature
  bridge and sender.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEcdsa.presignDistributed.unit.test.ts ./unit/thresholdEcdsa.postgresRecords.unit.test.ts --reporter=line`
  passed with 20 tests after wiring Router A/B ECDSA-HSS pool-fill through
  threshold-ECDSA presign-session state and completion.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 58 tests after adding strict ECDSA-HSS recovery and activation
  refresh request boundaries plus generic Router proof-bundle conversion.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 283 tests after adding strict Cloudflare ECDSA-HSS recovery and
  activation-refresh private Deriver wrappers and route dispatch.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`
  and `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed after wiring strict Signer A/B ECDSA-HSS recovery and refresh private
  routes.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 284 tests after wiring the strict public Router ECDSA-HSS
  recovery route and public recovery admission response validation.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after wiring the strict public Router ECDSA-HSS recovery route.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`
  and `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed after adding the public recovery route to the shared strict worker.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 287 tests after wiring the strict public Router ECDSA-HSS
  activation-refresh route, distinct private SigningWorker refresh route, and
  refresh public-identity parity validation.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 288 tests after adding Cloudflare source guards that reject
  canonical ECDSA-HSS export/private-key material in Router, Deriver,
  SigningWorker, public response, and receipt boundaries.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts unit/thresholdEcdsa.behavior.guard.unit.test.ts --reporter=line`
  passed with 5 source-guard tests after adding the Router A/B ECDSA-HSS
  production bridge guard for export/root material.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 58 tests after adding the canonical ECDSA-HSS active-state
  session id and binding lifecycle validation to key id, signing root
  id/version, and activation epoch.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 289 tests after keying ECDSA-HSS active SigningWorker state and
  Wallet Session/admission validation by the canonical active-state session id.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after wiring the public ECDSA-HSS activation-refresh route.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after wiring the private ECDSA-HSS SigningWorker refresh route.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-a-entrypoint`
  and `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signer-b-entrypoint`
  passed after adding refresh to the shared strict worker.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 67 tests after adding branch-specific ECDSA-HSS Deriver A/B
  encrypted envelope plaintext types, canonical plaintext digests, envelope
  role/AAD binding, exact output-kind/work-kind validation, and source guards
  against private scalar/root material.
- `rtk cargo test --manifest-path crates/ecdsa-hss/Cargo.toml --test role_local_mvp`
  passed with 9 tests after making the committed role-local fixture executable
  for scalar validity, public-key sum, Ethereum address parity, retry counters,
  export reconstruction, zero-sum identity rejection, and transcript operation
  drift.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test ecdsa_hss_protocol --test source_guards`
  passed with 69 tests after adding wrong Deriver recipient and wrong
  SigningWorker identity rejection coverage to the ECDSA-HSS Deriver envelope
  plaintext boundary.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 291 tests after adding explicit Signer A/B SigningWorker peer
  bindings and negative binding-role coverage.
- `rtk pnpm router:deploy:check` passed with
  `Router A/B release blockers clear.` after updating the release-ready guard
  to the current ECDSA-HSS strict-route symbols and Signer A/B SigningWorker
  service-binding config.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 296 tests after adding the direct single-bundle
  Deriver-to-SigningWorker activation delivery request type and rejection
  coverage for client-recipient, wrong-role, and wrong-context bundles.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 299 tests after adding deterministic direct-delivery aggregation
  coverage for reversed delivery order, duplicate Deriver role, and activation
  context conflict.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings --test source_guards`
  passed with 300 tests after adding direct-delivery source guards for
  server-only bundle validation and client/export surface exclusion.
- `rtk pnpm -C apps/web-server build` passed after the broader cleanup.
- `rtk pnpm -C packages/sdk-web run type-check` and
  `rtk pnpm -C packages/sdk-server-ts run type-check` passed after hardening the
  Router A/B-only unlock-to-sign readiness boundary.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningPolicy.unit.test.ts ./unit/availableSigningLanes.ed25519Duplicates.unit.test.ts ./unit/availableSigningLanes.ecdsaDuplicates.unit.test.ts ./unit/seamsWeb.loginThresholdWarm.unit.test.ts ./unit/thresholdEd25519.registrationWarmSession.unit.test.ts --reporter=line`
  passed with 76 tests for the same hardening.

Focused stale-name scans found no active source matches for the deleted
normal-signing v1/grant symbols outside docs and guard deny-lists.

## Remaining Release Tail

These are release-readiness tasks. They do not reopen the local Wallet Session
V2 implementation.

Cloudflare Router A/B deployment is now also blocked on release-complete
ECDSA-HSS Router A/B support. See `docs/router-a-b-ecdsa.md`; that plan is an
active pre-deploy requirement rather than a post-MVP feature.

- [x] Add initial release-blocking ECDSA-HSS Router A/B protocol/wire shapes,
      Router registration/bootstrap/export boundaries, and Router-mediated
      SigningWorker activation with public identity receipt derivation.
- [x] Add protocol-specific ECDSA-HSS Deriver A/B private registration requests,
      strict private registration routes, and Router service-call wiring before
      SigningWorker activation.
- [x] Add client-only ECDSA-HSS Deriver export handlers and response types so
      explicit export does not produce unused SigningWorker-targeted bundles.
- [x] Add active ECDSA-HSS normal-signing scope/material binding so persisted
      SigningWorker material is checked against the expected public identity
      before ECDSA signing.
- [x] Add ECDSA-HSS EVM digest signing request boundary and Cloudflare
      materialization against active SigningWorker state.
- [x] Add ECDSA-HSS recoverable-signature response boundary and SigningWorker
      handler interface.
- [x] Add Cloudflare-compatible one-use ECDSA-HSS presignature Durable Object
      state with request/digest/active-state binding and scalar-share receipt
      redaction.
- [x] Add ECDSA-HSS finalize request boundary with server presignature id,
      32-byte client signature share, and prepare request-digest binding.
- [x] Add ECDSA-HSS prepare response boundary and SigningWorker private prepare
      fetch helper that persists one-use presignature state before returning the
      redacted public prepare response.
- [x] Add Router public ECDSA-HSS prepare admission and service-call helper with
      Wallet Session verification, Router-owned store admission, replay
      reservation, and trusted-admission-bearing SigningWorker forwarding.
- [x] Add ECDSA-HSS Router finalize admission, SigningWorker private finalize
      fetch, one-use presignature take, and service-call helper.
- [x] Add rerandomization entropy to ECDSA-HSS prepare response, one-use
      presignature state, and Durable Object put receipt, with exact
      response/record/receipt binding and scalar-share redaction.
- [x] Wire strict public Router ECDSA-HSS prepare/finalize routes to the Wallet
      Session authenticated boundary and SigningWorker service calls.
- [x] Wire strict private SigningWorker ECDSA-HSS finalize dispatch to one-use
      presignature take and production finalize handling.
- [x] Implement production ECDSA-HSS finalize handling with `signer-core` over
      Cloudflare-compatible presign state.
- [x] Require ECDSA-HSS prepare requests to carry the client-held presignature
      id, bind it into the canonical prepare digest, carry it through Router
      prepare admission, and require the public prepare response to echo it as
      the server presignature id.
- [x] Add pool-backed production SigningWorker ECDSA-HSS prepare dispatch:
      strict private prepare now reserves the selected unbound pool entry,
      binds it to the request, persists the request-bound one-use record, and
      returns the redacted public prepare response.
- [x] Add strict private SigningWorker ECDSA-HSS pool-fill dispatch:
      trusted presign producers can write validated unbound pool records after
      active-state derivation from the ECDSA-HSS scope.
- [x] Add SDK/server bridge for public/client-facing ECDSA-HSS presignature
      production: completed TypeScript threshold-ECDSA presign output plus
      validated Router A/B ECDSA-HSS scope now builds the exact strict private
      SigningWorker pool-fill request.
- [x] Add SDK/server sender for the strict private SigningWorker pool-fill
      route with exact-path POST, receipt validation, duplicate classification,
      and request/receipt drift rejection.
- [x] Wire the SDK/server threshold-ECDSA presign-session lifecycle to carry
      validated Router A/B ECDSA-HSS scope and invoke the strict private
      SigningWorker pool-fill sender when presign completes.
- [x] Define strict ECDSA-HSS recovery and activation-refresh request
      boundaries in `router-ab-core`: recovery uses client-recipient export
      material, refresh uses SigningWorker activation material, and refresh
      rejects non-advancing activation epochs at the boundary.
- [x] Add Cloudflare Deriver A/B private ECDSA-HSS recovery and
      activation-refresh wrappers plus strict Signer A/B route dispatch, with
      recovery restricted to client-recipient output and refresh restricted to
      SigningWorker activation output.
- [x] Wire public Router ECDSA-HSS recovery endpoint to the private Deriver
      recovery handlers and client-recipient response aggregation.
- [x] Wire public Router ECDSA-HSS activation-refresh endpoint to a typed
      SigningWorker refresh activation path with a distinct private refresh
      route and public-identity parity validation.
- [x] Add ECDSA-HSS source guards proving public Router, Deriver,
      SigningWorker, log, audit, and receipt paths do not materialize canonical
      `x`, `privateKeyHex`, or raw root material.
- [x] Key active ECDSA-HSS SigningWorker state by wallet id, ECDSA threshold
      key id, signing root id/version, SigningWorker identity, and activation
      epoch through the canonical active-state session id.
- [x] Add branch-specific ECDSA-HSS Deriver A/B encrypted envelope plaintext
      types for registration, export, recovery, and refresh with canonical
      plaintext digests, envelope role/AAD binding, exact output-kind/work-kind
      validation, and source guards against private scalar/root material.
- [x] Add deterministic ECDSA-HSS derivation vector coverage for scalar
      validity, public-key sum, Ethereum address parity, retry counters, export
      reconstruction, zero-sum identity rejection, transcript operation drift,
      wrong Deriver recipient, and wrong SigningWorker identity.
- [x] Add explicit Signer A/B SigningWorker service bindings and config guards
      for the direct ECDSA-HSS activation delivery prerequisite.
- [x] Add the direct ECDSA-HSS activation delivery request type that carries
      only activation context, Deriver role, and one SigningWorker-recipient
      bundle.
- [x] Add pure direct ECDSA-HSS activation delivery reconciliation so one
      Signer A delivery and one Signer B delivery for the same activation
      context produce the existing aggregate SigningWorker activation request.
- [x] Add direct ECDSA-HSS activation delivery source guards proving the
      boundary cannot carry client/export bundles.
- [x] Complete local ECDSA-HSS Router A/B support for the Wallet Session V2
      cutover. Registration, activation, export, recovery, refresh, SDK request
      building, local validation, and local benchmarks are covered by the Router
      A/B ECDSA-HSS and cleanup plans; deployed Cloudflare evidence remains
      below.
- [x] Run the final local Router A/B legacy and naming cleanup after Wallet
      Session V2 and ECDSA-HSS support. The canonical cleanup record is
      [router-a-b-cleanup.md](./router-a-b-cleanup.md); local Router A/B-only
      cleanup is review-ready there, while deployed Cloudflare release evidence
      remains below.
- [x] Harden the unlock-to-sign readiness boundary for Router A/B-only signing.
      Wallet unlock now requests and persists Ed25519 Router A/B
      normal-signing state, ECDSA runtime availability requires persisted
      ECDSA-HSS Router A/B normal-signing state, stale runtime lanes without
      that state are not advertised as sign-ready, and the server fails startup
      without `ROUTER_AB_NORMAL_SIGNING_WORKER_ID`.
- [ ] Capture deployed strict Cloudflare browser evidence with
      `rtk pnpm router:deploy:browser-evidence` for:
      configured-origin success, rejected-origin behavior, preflight behavior,
      and timing with preflight included.
- [ ] Run real Cloudflare upload or deploy validation for Router, Deriver A,
      Deriver B, and SigningWorker.
- [ ] Record Wrangler `startup_time_ms` for each role. Dry-run reports bundle
      size only and currently has `startupTimeMs: null`.
- [ ] Record cold-ish and hot-isolate normal-signing latency against deployed
      strict Cloudflare Workers.
- [ ] Confirm deployed normal signing does not invoke Deriver A or Deriver B.
- [ ] Pull Cloudflare metrics/logs for CPU time, wall time, invocation status,
      and startup failure events.
- [ ] Add the measured startup table to the Router A/B signer budget section.

Current blockers:

- `rtk pnpm router:deploy:browser-evidence` reaches the Playwright test and
  fails before issuing deployed requests because `ROUTER_AB_DEPLOYED_BASE_URL`
  is missing from the local shell.
- `ROUTER_AB_DEPLOYED_ALLOWED_ORIGIN`,
  `ROUTER_AB_DEPLOYED_REJECTED_ORIGIN`, a request-scoped Wallet Session flow
  fixture, and deployed request body inputs are still needed.
- GitHub repo-level Actions secrets and variables are empty.
- `staging` and `production` environments contain generated Router A/B identity
  key material, public variables, and private identity secrets.
- Real upload/deploy still needs `ROUTER_AB_JWT_ISSUER`,
  `ROUTER_AB_JWT_JWKS_URL`, optional `ROUTER_AB_JWT_AUDIENCE`, Cloudflare
  credentials, and Deriver A/B root-share wire secrets.

## Manual Testing Readiness

Local/manual pre-deploy testing is ready. Use the current public route shape and
bearer Wallet Session credential:

```text
POST /v2/router-ab/ed25519/sign/prepare
POST /v2/router-ab/ed25519/sign
Authorization: Bearer <wallet-session-jwt>
```

Preferred local gates before manual testing:

```sh
rtk pnpm -C packages/sdk-web type-check
rtk pnpm router:smoke
rtk pnpm router:smoke:bundled
rtk pnpm router:deploy:check
```

Deployed manual testing should wait until the release-tail inputs above are
available.

## Guardrails For Future Agents

- Do not add a client-visible Router normal-signing grant.
- Do not reintroduce `thresholdSessionAuthToken` at the Router A/B public client
  boundary.
- Do not add `signingRootId` or `signingRootVersion` back to Wallet Session V2
  client-side SDK domain structs. Keep them behind server/protocol or
  persistence/request normalization boundaries until they are fully hidden
  behind `EvmFamilyEcdsaKeyHandle` / Router A/B key-handle state.
- Do not reintroduce `routerAbNormalSigningGrant`,
  `prepareRouterAbNormalSigningV1`, or `finalizeRouterAbNormalSigningV1`.
- Keep Wallet Session parsing out of SigningWorker private routes.
- Keep the Rust v2 boundary parsers as the raw request normalization boundary.
- Keep TypeScript request builders branch-specific.
- Keep cookie Wallet Session auth deferred until the browser security
  requirements have tests.
- Keep public wire-schema suffixes only where they describe current serialized
  contracts.
- Treat `docs/router-a-b-single-session.md` as the detailed implementation log
  and this file as the refactor handoff.
