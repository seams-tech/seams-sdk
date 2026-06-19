# Router A/B Single Wallet Session Plan

Date created: June 15, 2026

Status: local/core review-ready. Wallet Session V2 normal signing is
implemented locally for Router A/B Ed25519 and ECDSA-HSS; deployed Cloudflare
browser/runtime evidence remains open.

Related docs:

- [Router A/B signer plan](router-A-B-signer.md)
- [Router A/B signer spec](router-A-B-signer-SPEC.md)
- [Router A/B local development](router-a-b-local-dev.md)

## Goal

Make the client see exactly one authorization concept:

```text
Wallet Session
```

The public worker is the Router. Historical relay language maps to the same
public worker in this architecture:

```text
Client -> Router/Relay -> SigningWorker -> Router/Relay -> Client
```

The SDK should send only the Wallet Session credential to public Router A/B
normal-signing endpoints. The SDK should not request, store, pass, or expose a
second Router normal-signing grant.

Cloudflare Router A/B deployment is blocked until Ed25519 and ECDSA signing use
Router A/B as the only SDK/server signing architecture. The old public
`/threshold-ed25519/*` and `/threshold-ecdsa/*` signing surfaces are tracked for
deletion in [router-a-b-cleanup.md](./router-a-b-cleanup.md).

## Target Model

The public normal-signing flow should be:

```text
Client
  -> Router: Wallet Session credential + typed normal-signing request
Router
  -> verifies Wallet Session
  -> validates account, session, policy, quota, replay, and SigningWorker scope
  -> recomputes intent digest and signing payload digest from typed request data
  -> creates internal NormalSigningAdmission
  -> calls SigningWorker
SigningWorker
  -> signs only the admitted prepare/finalize material
Router
  -> validates response binding and returns signature to Client
```

`NormalSigningAdmission` is internal Router state. It is not a public token and
is never returned to the SDK.

## Starting Point

At the start of this plan, the implementation had the core cryptographic pieces
in the right place, while the public authorization boundary still carried
transitional normal-signing language.

- SDK normal-signing helpers send the current threshold-session auth transport
  as `thresholdSessionAuthToken`.
- Strict Cloudflare normal-signing routes verify a Router JWT whose claims
  include per-request `intentDigest`.
- Public v1 normal-signing requests carry `intent_digest`, `signing_payload`,
  and prepare/finalize protocol material.
- Router already has normal-signing admission-store machinery for request id,
  policy, quota, and abuse evaluation.

This plan reclassifies the user-visible auth object as Wallet Session and moves
per-signature intent authority into Router-side typed request validation. See
Current Implementation Status for the implementation snapshot after the cutover.

## Why The Request Shape Must Change

The old strict Cloudflare normal-signing route expected a bearer JWT with an
`intentDigest`. That makes sense when the public request contains only a digest
and signing bytes: the JWT is the object proving that a policy authority already
authorized this exact digest.

The single-session design removes that second client-visible object. Therefore
the Router request must contain enough typed intent data for Router to validate
the request itself.

Old v1 public request shape:

```text
Threshold/Wallet Session credential
NormalSigningRequestV1 {
  intent_digest,
  signing_payload,
  prepare or finalize protocol material
}
```

Target v2 prepare shape:

```text
Wallet Session credential
NormalSigningPrepareRequestV2 {
  scope: NormalSigningScopeV1,
  expires_at_ms,
  intent,
  signing_payload
}
```

Target v2 finalize shape:

```text
Wallet Session credential
NormalSigningFinalizeRequestV2 {
  scope: NormalSigningScopeV1,
  expires_at_ms,
  prepare_binding,
  protocol finalize material
}
```

Router computes:

```text
intent_digest = hash(canonical_intent(intent))
signing_payload_digest = hash(canonical_signing_payload(signing_payload))
admitted_signing_digest = derive_signing_digest(signing_payload)
```

Router then validates that the typed intent, payload, account, session,
prepare/finalize binding, and SigningWorker scope all agree. The client can
still include expected digest fields for diagnostics, but core admission must
derive its authority from the Wallet Session plus typed request data.

## Wallet Session Credential

Use one client-facing credential branch:

```ts
type WalletSessionCredential = { kind: 'bearer_wallet_session'; token: string };
```

The bearer form may still be a JWT internally. Its public meaning is Wallet
Session rather than Router grant. Cookie Wallet Session auth is deferred until
CSRF, SameSite, origin allowlist, credentialed request requirements, and
preflight-cache behavior are specified and covered.

Required verified Wallet Session claims:

- `subject_id`
- `account_id`
- `session_id`
- `org_id`
- `project_id`
- `environment`
- session expiry
- session authorization level
- Ed25519 signing session metadata
- `routerAbNormalSigning.signingWorkerId`

The Wallet Session credential should not carry a per-signature `intentDigest`.
Intent binding lives in Router request validation.

## Normal Signing Intent Types

Add a discriminated intent union for Router A/B Ed25519 normal signing:

```ts
type RouterAbEd25519NormalSigningIntentV2 =
  | {
      kind: 'near_transaction_v1';
      operationId: string;
      operationFingerprint: string;
      nearAccountId: string;
      nearNetworkId: 'testnet' | 'mainnet';
      transactions: readonly RouterAbNearTransactionIntentV1[];
      unsignedTransactionBorshB64u: string;
    }
  | {
      kind: 'nep413_v1';
      operationId: string;
      operationFingerprint: string;
      nearAccountId: string;
      nearNetworkId: 'testnet' | 'mainnet';
      recipient: string;
      message: string;
      nonceB64u?: string;
      callbackUrl?: string;
    }
  | {
      kind: 'near_delegate_action_v1';
      operationId: string;
      operationFingerprint: string;
      nearAccountId: string;
      nearNetworkId: 'testnet' | 'mainnet';
      delegate: RouterAbNearDelegateActionIntentV1;
    };
```

Use required fields for identity, session, signing, and lifecycle data. Optional
fields are allowed only where the underlying protocol makes them optional, such
as NEP-413 callback URL.

## Signing Payload Types

Replace opaque digest-only normal-signing payloads with typed payload branches:

```ts
type RouterAbEd25519SigningPayloadV2 =
  | {
      kind: 'near_unsigned_transaction_borsh_v1';
      unsignedTransactionBorshB64u: string;
      expectedSigningDigestB64u: string;
    }
  | {
      kind: 'nep413_message_v1';
      canonicalMessageB64u: string;
      expectedSigningDigestB64u: string;
    }
  | {
      kind: 'near_delegate_action_v1';
      canonicalDelegateBorshB64u: string;
      expectedSigningDigestB64u: string;
    };
```

Router must recompute the signing digest from the payload preimage and compare
it to `expectedSigningDigestB64u`. SigningWorker receives only the digest and
finalize material after Router admission succeeds.

Each branch has one authoritative signing preimage:

- NEAR transaction signing: `unsignedTransactionBorshB64u`.
- NEP-413 signing: `canonicalMessageB64u`.
- Delegate action signing: `canonicalDelegateBorshB64u`.

The typed intent provides policy and display data. Router parses the signing
preimage and rejects the request when parsed fields disagree with the typed
intent. `expectedSigningDigestB64u` is a diagnostic cross-check; Router derives
the signing authority from the preimage and Wallet Session.

## Prepare And Finalize Binding

The public API has two different request types because prepare and finalize
protect different invariants.

Prepare:

```ts
type RouterAbEd25519NormalSigningPrepareRequestV2 = {
  scope: NormalSigningScopeV1;
  expiresAtMs: number;
  intent: RouterAbEd25519NormalSigningIntentV2;
  signingPayload: RouterAbEd25519SigningPayloadV2;
};
```

Finalize:

```ts
type RouterAbEd25519NormalSigningFinalizeRequestV2 = {
  scope: NormalSigningScopeV1;
  expiresAtMs: number;
  prepareBinding: {
    serverRound1Handle: string;
    round1BindingDigest: string;
    intentDigest: string;
    signingPayloadDigest: string;
  };
  protocol: {
    kind: 'ed25519_two_party_frost_finalize_v1';
    groupPublicKey: string;
    clientCommitments: RouterAbNormalSigningCommitmentsV2;
    serverCommitments: RouterAbNormalSigningCommitmentsV2;
    clientVerifyingShareB64u: string;
    serverVerifyingShareB64u: string;
    clientSignatureShareB64u: string;
  };
};
```

Router prepare creates one internal admission record and one SigningWorker
round-1 nonce record. Router finalize must consume the server round-1 handle
exactly once. If scope, expiry, intent digest, signing-payload digest,
round-1 binding, commitments, or SigningWorker id mismatch, finalize rejects
without consuming nonce material.

## Canonicalization Authority

Router canonicalization is authoritative. Implement Rust `router-ab-core`
boundary parsers and digest helpers first, then expose test vectors that SDK
builders must satisfy.

TypeScript builders may construct typed request branches and compute expected
digests for diagnostics. They must not define an independent canonicalization
algorithm for Router admission. Every branch needs cross-language vectors for:

- canonical intent digest
- signing-payload digest
- mismatched intent versus payload rejection
- malformed payload rejection
- expected digest drift rejection

## Implementation Guardrails

- Rust `router-ab-core` remains the sole canonicalization authority for Router
  admission. TypeScript can build typed request branches, compute diagnostic
  expected digests, and check vector parity. Admission rejects any path that
  relies on TS canonicalization as the source of truth.
- V2 prepare and finalize requests stay narrow and branch-specific. Keep NEAR
  transaction, NEP-413, and delegate-action branches explicit; avoid a generic
  sign-anything envelope that lets opaque bytes bypass typed intent and payload
  validation.

## Public Router API

Keep public endpoints simple:

```text
POST /v2/router-ab/ed25519/sign/prepare
POST /v2/router-ab/ed25519/sign
```

Both MVP endpoints accept:

```http
Authorization: Bearer <wallet-session-token>
```

Cookie Wallet Session auth is deferred.

Both endpoints reject:

- missing Wallet Session
- invalid Wallet Session
- Wallet Session account/session mismatch
- missing `routerAbNormalSigning.signingWorkerId`
- request SigningWorker mismatch
- typed intent mismatch
- signing payload digest mismatch
- prepare/finalize binding mismatch
- expired request
- replayed request id

No public endpoint should mint `routerAbNormalSigningGrant`.

Strict Cloudflare Router deployment must expose browser-safe CORS for these
public endpoints:

- `OPTIONS /v2/router-ab/ed25519/sign/prepare`
- `OPTIONS /v2/router-ab/ed25519/sign`
- configured allowlist for app and wallet origins
- deployed Worker evidence that browser prepare/finalize requests succeed

## Internal Router Admission

Evolve the existing normal-signing admission-store path into an internal type
that replaces the client-visible Router grant:

```rust
pub struct CloudflareRouterNormalSigningPrepareAdmissionCandidateV2 {
    pub org_id: String,
    pub project_id: String,
    pub environment: String,
    pub account_id: String,
    pub subject_id: String,
    pub session_id: String,
    pub signing_worker_id: String,
    pub request_id: String,
    pub intent_digest: PublicDigest32,
    pub signing_payload_digest: PublicDigest32,
    pub admitted_signing_digest: PublicDigest32,
    pub round1_binding_digest: Option<PublicDigest32>,
    pub trusted_source_digest: PublicDigest32,
    pub expires_at_ms: u64,
}
```

The prepare/finalize candidate types are constructed only after:

1. Wallet Session verification succeeds.
2. Normal-signing request parsing succeeds.
3. Typed intent digest recomputation succeeds.
4. Signing payload digest recomputation succeeds.
5. Admitted signing digest derivation succeeds.
6. Prepare/finalize binding validation succeeds when finalizing.

Router policy, quota, abuse, and prepare replay gates produce a
`CloudflareRouterNormalSigningTrustedAdmissionV1`. Only the
`CloudflareSigningWorkerAdmittedNormalSigningPrepareRequestV2` or
`CloudflareSigningWorkerAdmittedNormalSigningFinalizeRequestV2` service-call
body crosses into SigningWorker, and those bodies carry both the pre-gate
candidate and the accepted trusted admission decision. They are never serialized
to the client.

## Review Notes

The model fits the current Router, Deriver A/B, and SigningWorker split. The
cryptographic hot path already routes through the SigningWorker and
role-separated Ed25519-HSS finalizer; the implementation work is mostly a
public-boundary refactor plus typed Router validation.

The main missing implementation detail is the exact digest carried to the
SigningWorker finalize path. Current SigningWorker finalize needs the 32-byte
message digest, while the target public finalize shape carries only
`prepareBinding` and protocol material. The implementation must add an
admitted signing digest to Router-internal state and either persist it with the
round-1 record or carry it in the Router-to-SigningWorker private finalize
request after prepare lookup. The client-facing finalize request must not be
the authority for that digest.

The active public normal-signing endpoints use explicit `/v2/router-ab/ed25519/sign/prepare`
and `/v2/router-ab/ed25519/sign` paths because the body contract is a clean replacement for
the old digest-only public shape.

## Phased TODO List

### Phase 0: Freeze The Contract And Inventory The Cutover

- [x] Confirm whether the public paths stay `/v1/hss/sign/prepare` and
      `/v1/hss/sign` with v2 bodies, or move to explicit `/v2` paths.
- [x] Inventory current public normal-signing request surfaces in
      `crates/router-ab-core/src/protocol/normal_signing.rs`,
      `crates/router-ab-cloudflare/src/strict_worker.rs`,
      `packages/sdk-web/src/core/rpcClients/relayer/routerAbNormalSigning.ts`,
      `packages/sdk-web/src/core/signingEngine/flows/signNear/shared/ed25519PresignFinalize.ts`,
      and the local router/dev smoke harness.
- [x] Decide the Router-internal signing-digest carry model:
      `NormalSigningAdmission` plus private finalize request, or
      SigningWorker round-1 record persistence.
- [x] Decide the strict Router packaging path for NEAR transaction preimage
      parsing and digest recomputation. The MVP strict Router uses the
      `router-ab-core` Rust NEAR transaction parser and action-fingerprint
      helpers directly; bundle-size tuning remains a deferred deployment
      question.
- [x] List deletion targets for grant-oriented public auth:
      `CloudflareRouterVerifiedNormalSigningJwtClaimsV1`,
      `CloudflareRouterNormalSigningJwtVerifierV1`, v1 SDK normal-signing
      helper names, and public tests that require JWT `intentDigest`.

### Phase 1: Build Rust V2 Domain Types And Vectors First

- [x] Add `RouterAbEd25519NormalSigningIntentV2` in `router-ab-core` with
      branch-specific required fields for NEAR transactions, NEP-413, and
      delegate actions.
- [x] Add `RouterAbEd25519SigningPayloadV2` with one authoritative preimage per
      branch and an explicit expected 32-byte Ed25519 signing digest.
- [x] Add boundary parsers that normalize raw request bodies once and return
      precise internal types.
- [x] Add Router-side Borsh parsers for NEAR unsigned transaction and NEP-461
      delegate-action signing preimages, then compare parsed fields to typed
      intent metadata before deriving admission material.
- [x] Add canonical intent digest, canonical signing-payload digest, and
      admitted signing digest helpers in Rust.
- [x] Add branch consistency checks between typed intent and parsed signing
      preimage.
- [x] Add vector fixtures for intent digest, signing-payload digest, admitted
      signing digest, malformed payload rejection, expected digest drift, and
      intent/preimage mismatch.
- [x] Delete or replace v1 public request tests that encode digest-only public
      authority.

### Phase 2: Replace Public Router Auth With Wallet Session Admission

- [x] Add `WalletSessionCredential` and `VerifiedWalletSession` boundary types
      for strict Router normal signing.
- [x] Add `CloudflareRouterWalletSessionVerifierV1` for bearer Wallet Session
      verification, with cookie verification left behind the same interface.
- [x] Replace public normal-signing JWT claim verification with Wallet Session
      verification on prepare and finalize.
- [x] Replace public normal-signing JWT claim verification with Wallet Session
      verification on strict Router prepare.
- [x] Replace public normal-signing JWT claim verification with Wallet Session
      verification on strict Router finalize.
- [x] Build prepare/finalize admission candidates only after Wallet Session
      verification, typed request parsing, digest recomputation, branch
      consistency checks, and expiry checks; require trusted admission plus
      prepare replay reservation before creating the SigningWorker-admitted
      private request body.
- [x] Feed the existing normal-signing admission-store checks from internal
      admission metadata.
- [x] Bind prepare and finalize to request id, account id, session id,
      SigningWorker id, intent digest, signing-payload digest, admitted signing
      digest, round-1 binding digest, and expiry.
- [x] Add browser-safe CORS and preflight handling for both public
      normal-signing endpoints in the strict Cloudflare Router.

### Phase 3: Narrow The SigningWorker Private Contract

- [x] Keep Wallet Session parsing out of all SigningWorker private routes.
- [x] Forward only Router-admitted prepare/finalize material from Router to
      SigningWorker.
- [x] Ensure the SigningWorker finalize path receives the admitted 32-byte
      signing digest from Router-controlled state.
- [x] Store round-1 nonce material with binding data sufficient to reject drift
      before nonce consumption.
- [x] Preserve single-use round-1 handle consumption and add coverage that
      binding drift rejects without consuming the handle.
- [x] Keep `CloudflareRoleSeparatedEd25519NormalSigningHandlerV1` finalizing
      through `ed25519_hss::role_signing`.

### Phase 4: Refactor The SDK Normal-Signing Surface

- [x] Replace `ThresholdEd25519PresignPoolRouteAuth` at the Router A/B
      normal-signing client boundary with `WalletSessionCredential`.
- [x] Map persisted threshold-session transport records into Wallet Session
      credentials once at the SDK boundary.
- [x] Replace `prepareRouterAbNormalSigningV1` and
      `finalizeRouterAbNormalSigningV1` with v2 helpers and delete the old
      helper names.
- [x] Build branch-specific SDK request builders for NEAR transaction signing,
      NEP-413, and delegate actions.
- [x] Split the current generic signature-only Router A/B intent path into the
      explicit public intent branches.
- [x] Use Rust vector fixtures for SDK diagnostic digest parity. Keep Router
      admission authority in Rust.
- [x] Add `@ts-expect-error` fixtures for invalid branch combinations, broad
      object spreads, missing identity/session/signing fields, and unsafe
      finalize-without-prepare shapes.

### Phase 5: Update Local, Express, And Self-Hosted Paths

- [x] Update local router workers used by `pnpm router` and
      `pnpm router:multiplex` to the Wallet Session plus typed request shape.
- [x] Update the bundled one-process profile used by `pnpm router:bundled` to
      the same public API.
- [x] Verify Express/local relayer route definitions do not currently mirror
      Router A/B normal signing.
- [x] Update local smoke fixtures so NEAR transactions, NEP-413, and delegate
      actions all use Wallet Session auth only.
- [x] Remove local mocks, fixtures, and route guards that exist only for the
      client-visible Router normal-signing grant.

### Phase 6: Add Guards, Tests, And Release Gates

- [x] Complete remaining Rust negative tests for account mismatch, session
      mismatch, replayed request ids, intent digest drift, signing-payload
      digest drift, admitted signing digest drift, and typed intent/preimage
      mismatch. Missing local Wallet Session auth is now covered at the local
      public Router HTTP boundary.
- [x] Add Rust tests for Wallet Session normal-signing expiry clamping and
      exact-expiry rejection for prepare and finalize.
- [x] Add Rust tests for accepted NEAR transaction, NEP-413, and delegate-action
      normal signing through Wallet Session auth.
- [x] Add Cloudflare tests/source guards for strict Router normal-signing CORS
      exact-origin allowlist behavior and fail-closed wildcard/missing-config
      behavior.
- [x] Add source guards proving public normal-signing routes do not read JWT
      `intentDigest` and do construct internal admission candidates before
      creating SigningWorker-admitted private requests.
- [x] Add source guards proving SDK Router A/B normal-signing helpers do not
      expose `thresholdSessionAuthToken` naming or
      `routerAbNormalSigningGrant`.
- [x] Add source guards proving SigningWorker private routes cannot parse
      Wallet Session credentials.
- [x] Run focused Rust validation:
      `cargo test --manifest-path crates/router-ab-core/Cargo.toml normal_signing`,
      `cargo test --manifest-path crates/router-ab-core/Cargo.toml --test generated_vectors`,
      `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`,
      and
      `cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`.
- [x] Run focused Router A/B TypeScript validation:
      `pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningVectors.unit.test.ts ./unit/routerAbNormalSigningValidation.unit.test.ts --reporter=line`
      and
      `pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`.
- [x] Restore the package-wide SDK type-check gate:
      `rtk pnpm -C packages/sdk-web type-check` now passes after fixing the
      non-Router-A/B workspace/test and VoiceID diagnostics.
- [x] Run local Router validation:
      `pnpm router:smoke`, `pnpm router:smoke:bundled`, and
      `pnpm router:deploy:check`.
- [x] Run local Worker HTTP validation for Wallet Session bearer enforcement and
      v2 normal-signing prepare/finalize through split-worker and bundled local
      topologies.
- [ ] Capture deployed strict Cloudflare browser prepare/finalize evidence from
      a configured app or wallet origin.

### Phase 7: Delete Legacy V1 Normal-Signing Surface And Normalize Names

Legacy means the old client-visible normal-signing grant and digest-only public
request flow. Do not delete unrelated `V1` names that are still the current
durable wire schema, Durable Object record schema, route version, response
schema, or shared cryptographic protocol primitive.

Naming rule decided on June 15, 2026: keep explicit version suffixes for the
current route version, durable wire and persistence schemas, response schemas,
and shared cryptographic protocol primitives. Keep `V2` on the active Wallet
Session prepare/finalize request and admission body contracts until a deliberate
public API cutover replaces that wire contract. Delete or rename suffixes only
where the name describes a retired branch.

- [x] Classify remaining normal-signing `V1`/`V2` symbols into three lists:
      delete now, keep as current durable/wire schema, and rename after cutover.
- [x] Delete grant-oriented public auth types and verifier APIs:
      `CloudflareRouterVerifiedNormalSigningJwtClaimsV1`,
      `CloudflareRouterNormalSigningJwtVerifierV1`,
      `verify_normal_signing_jwt`,
      `verify_normal_signing_round1_prepare_jwt`, and their mock/test
      implementations.
- [x] Delete v1 public Router handlers once no strict, local, Express, or SDK
      caller remains:
      `handle_cloudflare_router_normal_signing_authenticated_public_request_v1`
      and
      `handle_cloudflare_router_normal_signing_round1_prepare_authenticated_public_request_v1`.
- [x] Delete v1 Router-to-SigningWorker service-call helpers once all callers
      use v2 admitted prepare/finalize requests:
      `execute_cloudflare_signing_worker_normal_signing_service_call_v1` and
      `execute_cloudflare_signing_worker_normal_signing_round1_prepare_service_call_v1`.
- [x] Delete private SigningWorker v1 normal-signing request wrappers and
      materialized state after the v2 private contract is the only caller:
      `CloudflareSigningWorkerAdmittedNormalSigningRequestV1`,
      `CloudflareSigningWorkerAdmittedNormalSigningRound1PrepareRequestV1`,
      `CloudflareSigningWorkerMaterializedNormalSigningRequestV1`, and
      `CloudflareSigningWorkerMaterializedNormalSigningRound1PrepareRequestV1`.
- [x] Delete old SigningWorker v1 handler traits after v2 prepare/finalize
      handlers cover the active path:
      `CloudflareSigningWorkerNormalSigningHandlerV1` and
      `CloudflareSigningWorkerNormalSigningRound1PrepareHandlerV1`.
- [x] Delete `router-ab-core` v1 public normal-signing request structs after
      internal callers are gone: `NormalSigningRequestV1` and
      `NormalSigningRound1PrepareRequestV1`.
- [x] Keep or rename shared non-legacy normal-signing primitives only after
      deciding the repo naming rule. Keep explicit versions for durable
      wire/persistence schemas, route versions, response shapes, and shared
      cryptographic protocol primitives; delete or rename suffixes that only
      describe retired branches.
- [x] Rename the accepted Wallet Session request/admission types after the old
      public surface is gone, or document why the `V2` suffix remains part of
      the public wire contract:
      `RouterAbEd25519NormalSigningPrepareRequestV2`,
      `RouterAbEd25519NormalSigningFinalizeRequestV2`,
      `CloudflareRouterNormalSigningPrepareAdmissionCandidateV2`, and
      `CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2`.
- [x] Delete SDK Router A/B normal-signing v1 helpers and names:
      `prepareRouterAbNormalSigningV1`, `finalizeRouterAbNormalSigningV1`,
      `ThresholdEd25519PresignPoolRouteAuth`, Router A/B
      `thresholdSessionAuthToken` usage, and any
      `routerAbNormalSigningGrant` branch.
- [x] Keep threshold-session naming outside Router A/B normal signing only when
      it still describes non-Router-A/B persisted auth, ECDSA flows, recovery
      flows, or other current product behavior.
- [x] Delete local, Express, bundled, and smoke-test fixtures that build old
      digest-only normal-signing requests or old grant-bound JWT claims.
- [x] Delete Rust v1 grant tests and fixtures whose only purpose is
      `intentDigest` JWT admission after Wallet Session tests cover the active
      path.
- [x] Add Rust source guards that fail if public normal-signing routes,
      SigningWorker private routes, or Router admission code reference the old
      grant verifier, old JWT claims, old v1 request structs, or old v1 private
      service-call helpers.
- [x] Add TypeScript source guards that fail if Router A/B normal-signing SDK
      code exposes `thresholdSessionAuthToken`,
      `routerAbNormalSigningGrant`, `prepareRouterAbNormalSigningV1`, or
      `finalizeRouterAbNormalSigningV1`.
- [x] Re-scan SDK, server, test, and Router A/B Rust source for deleted
      Router A/B normal-signing v1/grant symbols outside docs and guard
      deny-lists. No active matches remain.
- [x] Run focused cleanup validation that is currently unblocked:
      `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml normal_signing`,
      `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`,
      `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`,
      `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`,
      `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`,
      Router A/B unit/source-guard tests, and Rust local smoke coverage.
- [ ] Restore the remaining release validation gates in the order listed below:
      deployed browser evidence, deploy/runtime validation, and real
      staging/production keygen application.

### Phase 8: Architecture Critiques And Hardening Improvements

- [x] Update or delete the normal-signing benchmark in
      `crates/router-ab-cloudflare/benches/router_latency.rs`. The v1
      Router-to-SigningWorker helper and old SigningWorker handler symbols have
      been removed from the library, so `cargo check --benches` currently catches
      stale benchmark code that the release gate does not exercise.
- [x] Add `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --benches`
      to cleanup validation after the benchmark is moved to the Wallet Session v2
      prepare/finalize path or intentionally removed.
- [x] Rewrite the top-level "Current State" section as either "Starting Point"
      or a current implementation snapshot. It still describes the old
      per-request `intentDigest` Router JWT boundary, while the later status
      section describes Wallet Session prepare/finalize as implemented.
- [x] Resolve the public route/body versioning decision. Keep `/v1/hss/sign/*`
      only if v2 request bodies are the single breaking replacement; otherwise
      create explicit `/v2` routes and delete the old public route body shape.
- [x] Make bearer Wallet Session JWT the only MVP public credential in the API
      section. Keep cookie Wallet Session auth deferred until CSRF, SameSite,
      origin allowlist, credentialed request requirements, and preflight-cache
      behavior are specified and covered.
- [x] Align request-shape examples with the implemented scope type. The current
      Rust v2 prepare/finalize requests use `NormalSigningScopeV1`, and the
      plan examples now use that current wire type explicitly.
- [x] Define expiry semantics precisely: maximum prepare TTL, maximum finalize
      TTL, clock-skew allowance, Wallet Session expiry clamping, replay
      reservation lifetime, and cleanup behavior for expired round-1 handles.
- [x] Define quota and abuse accounting semantics for prepare/finalize. Specify
      whether quota is charged on prepare, finalize, or both, and how abandoned
      prepares, failed finalizes, repeated finalize attempts, and binding-drift
      rejections affect counters.
- [x] Add an operational cleanup requirement for abandoned prepare records and
      persisted one-use nonce material. The security invariant is single-use
      consumption; the availability invariant is bounded Durable Object growth.
- [x] Add deployed-browser evidence requirements for strict Cloudflare
      prepare/finalize beyond source guards: configured origin success, rejected
      origin behavior, preflight behavior, and timing with preflight included.
- [x] Add an explicit deployed-browser evidence harness:
      `rtk pnpm router:deploy:browser-evidence` runs a Playwright browser from
      configured allowed and rejected origins, checks bearer-only preflight
      headers, captures browser timing with preflight included, and writes a
      JSON evidence artifact.

### Phase 9: Restore Ed25519 Presign-Pool Latency

Router A/B Ed25519 normal signing must preserve the previous user-facing
latency model: background presign refill creates one-use nonce pairs before the
user signs, a pool hit finalizes in one public Router request, and a pool miss
falls back to the current just-in-time prepare/finalize path.

- [x] Add Router A/B Ed25519 presign-pool wire types:
      `RouterAbEd25519PresignPoolPrepareRequestV2`,
      `RouterAbEd25519PresignPoolPrepareResponseV2`,
      `RouterAbEd25519PresignPoolHitBindingV2`, and
      `RouterAbEd25519PresignPoolHitFinalizeRequestV2`. The refill request is
      message-agnostic, the response validates accepted entries against the
      originating offers, and the pool-hit request carries the selected pool
      handle plus the full typed intent/signing-payload data needed for Router
      admission.
- [x] Add a public Wallet Session authenticated pool-refill route at
      `/v2/router-ab/ed25519/sign/presign-pool/prepare` that accepts client-generated
      commitment offers, verifies account/session/SigningWorker scope, enforces
      refill size/TTL bounds, and forwards only Router-authenticated pool
      material to SigningWorker.
- [x] Add SigningWorker unbound Ed25519 round-1 pool records and the refill-time
      Durable Object put path. Records are scoped by account id, session id,
      SigningWorker id, pool generation, client presign id, server round-1
      handle, and expiry, and store the offered client commitments/client
      verifying share plus generated server nonce state/server commitments/server
      verifying share.
- [x] Add the claim-time lookup/burn path for unbound Ed25519 round-1 pool
      records. The lookup must validate account id, session id, signing
      root/key id once exposed in the active state model, SigningWorker id,
      client presign id, server round-1 handle, generation, pool binding digest,
      and expiry before binding a claimed record to an admitted signing digest.
- [x] Keep unbound pool records message-agnostic until finalization. Pool refill
      must not carry an intent digest, signing-payload digest, or admitted
      signing digest.
- [x] Add pool-hit finalization admission: Router verifies Wallet Session,
      typed intent, signing payload, expiry, policy/quota/abuse, and replay,
      recomputes the admitted 32-byte signing digest, and forwards a
      trusted-admission-bearing pool-hit finalize request to SigningWorker.
- [x] Add SigningWorker pool-hit materialization that atomically claims the exact
      unbound pool record, validates scope, client commitments, client verifying
      share, server handle, server commitments, expiry, and SigningWorker id,
      then binds the claimed nonce record to the admitted signing digest for
      one finalization attempt.
- [x] Define burn semantics precisely:
      scope/handle/commitment drift rejects before claim and does not consume
      the pool record; once a record is claimed for an admitted signing digest,
      cryptographic failure, invalid client signature share, or response-send
      uncertainty burns the record so nonce material cannot be reused.
- [x] Reuse the existing SDK Ed25519 client presign-pool state where possible,
      but replace the old threshold-session transport with Router A/B Wallet
      Session auth, Router A/B SigningWorker scope, and the new pool-refill
      route. Keep invalid states unrepresentable: a ready Router A/B presign
      entry must include the server round-1 handle, server commitments, server
      verifying share, client nonce handle, client commitments, scope, expiry,
      and generation.
- [x] Update Router A/B SDK signing selection:
      pool hit -> one public finalize request;
      pool miss -> current `/v2/router-ab/ed25519/sign/prepare` plus `/v2/router-ab/ed25519/sign` fallback;
      background refill -> keep target depth above the low-water mark after a
      miss or successful use.
- [x] Add local and Cloudflare Durable Object cleanup for expired unbound pool
      records. Cleanup must be idempotent, must preserve live records, and must
      not create signing side effects.
- [x] Add tests and source guards for one-use pool consumption, duplicate
      handle rejection, cross-session rejection, SigningWorker mismatch,
      commitment drift, expired pool records, invalid client signature-share
      burn, pool-hit Deriver A/B non-invocation, and fallback-to-prepare on
      pool miss.
- [ ] Add deployed browser evidence that a Router A/B Ed25519 pool hit performs
      one public signing request from user confirmation to signature, while a
      pool miss performs the two-request prepare/finalize fallback. Record
      timing for both cases with CORS preflight behavior included.

## Expiry, Quota, Replay, And Cleanup Semantics

These are the current Wallet Session v2 normal-signing test targets for strict
Cloudflare and local parity.

### Expiry

- Prepare and finalize request bodies require positive `expires_at_ms`.
- Worker/server time is authoritative. A Wallet Session, prepare request,
  finalize request, replay reservation, quota reservation, and SigningWorker
  round-1 record are live only while `now_unix_ms < expires_at_ms`; exact
  equality is expired. Clock-skew allowance is `0 ms`.
- The MVP has no separate Router-side hard TTL constant. The effective maximum
  prepare and finalize lifetime is the request `expires_at_ms` bounded by the
  verified Wallet Session `expires_at_ms`. The strict Router rejects a request
  whose Wallet Session expires before the request expiry.
- SDK-built normal-signing requests should continue using the SDK's short
  request TTL by default. A caller-supplied expiry is valid only when it is
  positive, still live at Router time, and covered by the Wallet Session.
- Replay reservation expiry, quota reservation expiry, and SigningWorker
  round-1 record expiry all use the admitted request `expires_at_ms`.

### Replay

- Replay reservation exists only on prepare. The strict Router derives it after
  Wallet Session verification and policy/quota/abuse acceptance, then before
  forwarding to SigningWorker.
- Replay material is the v2 round-1 binding digest. The reservation key is the
  request id plus replay material digest, with a request-id index that rejects a
  reused request id bound to different material.
- The Durable Object returns `reserved = true` for the first reservation and
  `reserved = false` for the same request id/material tuple. The strict Router
  treats `reserved = false` as `ReplayedLocalRequest`, so a public prepare is
  single-admission.
- Finalize has no public replay reservation. Finalize is single-use through the
  SigningWorker round-1 `take` path.

### Quota And Abuse

- Prepare and finalize both evaluate policy, quota, and abuse stores before
  SigningWorker forwarding. Both calls carry the same request id and request
  expiry.
- Quota is reserved per normal-signing quota scope. An active reservation for
  the same request id is accepted again; a different active request id in the
  same scope returns `ShortWindowSaturated`.
- Because prepare and finalize share a request id, finalize reuses the active
  prepare reservation while it is live. It does not double-charge.
- An abandoned prepare holds the quota slot until `expires_at_ms`. After expiry,
  a later call can create a fresh reservation only if its own request body is
  still live.
- Binding-drift and failed finalize attempts happen after quota/abuse
  evaluation in the current route order. They do not increment a separate
  normal-signing counter in the current Durable Object model.
- Abuse evaluation is read-only in the current Durable Object model. Missing
  abuse state allows the request; stored rejection state rejects prepare and
  finalize under the same principal/source scope.

### Abandoned Prepare Cleanup

- A prepare is abandoned when no finalize consumes its SigningWorker round-1
  record before `expires_at_ms`.
- Successful finalize deletes the round-1 record exactly once. Missing,
  expired, or binding-mismatched round-1 lookup rejects; expired and
  binding-mismatched lookup must leave the stored record intact for audit and
  to avoid attacker-triggered deletion.
- Operational cleanup deletes expired round-1 records, replay reservations,
  replay request-id index entries, and quota reservations when
  `now_unix_ms >= expires_at_ms`. Cleanup must be idempotent, must leave live
  records untouched, and must not create signing side effects.
- Bounded Durable Object growth is handled by explicit Durable Object cleanup
  operations for replay, quota, and SigningWorker round-1 state.

### Deployed Browser Evidence

Capture these with `rtk pnpm router:deploy:browser-evidence` against a strict
Cloudflare Router deployment with real normal-signing Worker bindings and a
configured app or wallet origin.

Required inputs:

- `ROUTER_AB_DEPLOYED_BASE_URL`
- `ROUTER_AB_DEPLOYED_ALLOWED_ORIGIN`
- `ROUTER_AB_DEPLOYED_REJECTED_ORIGIN`
- `ROUTER_AB_DEPLOYED_WALLET_SESSION_JWT`, unless the flow module returns
  request-scoped Wallet Session JWTs
- either `ROUTER_AB_DEPLOYED_FLOW_MODULE`, exporting `buildPrepareRequest` and
  `buildFinalizeRequest`, or both `ROUTER_AB_DEPLOYED_PREPARE_BODY_FILE` and
  `ROUTER_AB_DEPLOYED_FINALIZE_BODY_FILE`
- optional `ROUTER_AB_DEPLOYED_EVIDENCE_OUT`

Flow-module builders return `{ body, walletSessionJwt? }`. `buildFinalizeRequest`
receives the prepare request and the deployed prepare response so it can create
the matching client signature share for the one-use round-1 handle.

- `OPTIONS /v2/router-ab/ed25519/sign/prepare` returns the configured origin, omits
  `Access-Control-Allow-Credentials`, and returns the expected method/header
  allowlist.
- `OPTIONS /v2/router-ab/ed25519/sign` returns the same bearer-only CORS policy.
- Browser `POST /v2/router-ab/ed25519/sign/prepare` with a bearer Wallet Session succeeds
  from an allowed origin and rejects a missing or wrong origin.
- Browser `POST /v2/router-ab/ed25519/sign` succeeds only after the matching prepare binding
  and round-1 handle are returned by prepare.
- Deployed timing captures include the preflight round trip when the browser
  cannot use a cached preflight.

## Current Implementation Status

Completed on June 15, 2026:

- Rust v2 intent and payload types landed in `router-ab-core`.
- Router-derived admission material now includes `intent_digest`,
  `signing_payload_digest`, and `admitted_signing_digest`.
- Branch consistency checks reject mismatched intent and payload branches.
- Focused Rust coverage passes for accepted NEAR transaction, NEP-413, and
  delegate-action admission plus expected digest drift and preimage mismatch.
- Rust normal-signing v2 now parses NEAR unsigned transaction Borsh and
  NEP-461 delegate-action Borsh from the admitted signing preimage. The Router
  rejects typed intent drift for NEAR signer/receiver/action fingerprint and
  delegate sender/receiver/public key/nonce/max block height/action fingerprint
  before deriving admission material.
- Cloudflare now has `CloudflareRouterWalletSessionCredentialV1`,
  `CloudflareRouterVerifiedWalletSessionV1`,
  `CloudflareRouterWalletSessionVerifierV1`, and prepare/finalize admission
  candidate foundation types.
- `CloudflareRouterNormalSigningPrepareAdmissionCandidateV2` validates request
  scope, v2 digest material, and round-1 binding against typed prepare
  requests, then converts to the current v1 admission-store metadata shape.
- `CloudflareRouterNormalSigningFinalizeAdmissionCandidateV2` validates finalize
  scope, intent/signing-payload digest, and round-1 binding against the typed
  finalize request before store checks run.
- `CloudflareRouterWorkerRuntimeV1` can now build existing normal-signing
  policy, quota, and abuse Durable Object calls from v2 typed prepare admission
  metadata.
- Focused Cloudflare coverage passes for accepted Wallet Session admission,
  SigningWorker mismatch rejection, signing-payload digest drift rejection, and
  v1 admission-store metadata conversion.
- Focused Cloudflare coverage passes for v2 prepare admission-store call
  derivation and round-1 binding drift rejection.
- The strict Cloudflare Router prepare route now parses
  `RouterAbEd25519NormalSigningPrepareRequestV2`, verifies Wallet Session
  credentials, derives a v2 prepare admission candidate, runs
  policy/quota/abuse stores, reserves replay, and forwards a v2 admitted private
  prepare request to SigningWorker.
- SigningWorker v2 prepare now stores both the v2 round-1 binding digest and
  Router-admitted signing digest in the round-1 record.
- Focused Cloudflare coverage passes for concrete Wallet Session JWT
  verification, v2 prepare replay reservation, and v2 SigningWorker prepare
  record binding.
- Rust v2 finalize domain types landed in `router-ab-core` with explicit
  prepare-binding and FROST finalize protocol branches.
- The strict Cloudflare Router finalize route now parses
  `RouterAbEd25519NormalSigningFinalizeRequestV2`, verifies Wallet Session
  credentials, derives a v2 finalize admission candidate from the prepare
  binding, runs policy/quota/abuse stores, and forwards a v2 admitted private
  finalize request to SigningWorker.
- SigningWorker v2 finalize consumes the stored round-1 record and signs the
  Router-admitted 32-byte signing digest persisted during v2 prepare.
- Focused Cloudflare coverage passes for v2 finalize Wallet Session scope
  validation, finalize admission-store derivation, round-1 binding drift
  rejection, and production Ed25519 signature verification over the admitted
  digest.
- Strict Cloudflare Router normal-signing prepare/finalize routes now handle
  CORS preflight and attach configured-origin CORS headers to public
  normal-signing responses.
- Source guard coverage proves strict normal-signing routes keep the CORS
  boundary and route through the v2 prepare/finalize handlers.
- Phase 7 Rust cleanup deleted the grant-oriented normal-signing JWT verifier,
  v1 public Router handlers, v1 Router-to-SigningWorker service-call helpers,
  private SigningWorker v1 request wrappers, old SigningWorker v1 handler
  traits, and Rust tests that existed only for `intentDigest` JWT admission.
- Source guard coverage now fails if those deleted v1 normal-signing flow
  symbols reappear in `crates/router-ab-cloudflare/src/lib.rs`.
- SDK Router A/B normal-signing helpers now expose Wallet Session credentials
  and v2 prepare/finalize request builders. The old v1 helper names and grant
  auth type are gone from the SDK Router A/B client boundary.
- SDK NEAR transaction, NEP-413, and delegate-action normal-signing flows now
  build branch-specific v2 prepare requests before calling Router prepare and
  finalize. Persisted threshold-session transport state is mapped into a
  Wallet Session credential once at that boundary.
- SDK Router A/B normal signing now accepts bearer Wallet Session JWT
  credentials only. Cookie Wallet Session state fails at the Router A/B
  boundary until the deferred browser-cookie requirements are specified.
- Public Router normal-signing endpoints now use explicit
  `/v2/router-ab/ed25519/sign/prepare` and `/v2/router-ab/ed25519/sign` paths in the SDK, strict
  Cloudflare Router, and local dev harness.
- The near-signer WASM boundary now exposes a delegate signing-payload builder
  so the SDK can supply canonical NEP-461 delegate preimages to the Router v2
  request builder without duplicating Borsh encoding in TypeScript.
- Rust normal-signing v2 vectors now live at
  `crates/router-ab-core/fixtures/protocol/normal-signing/normal-signing-vectors-v2.json`,
  and SDK unit coverage verifies the v2 request builders match Rust admission
  digests for all three public branches.
- Local Router and SigningWorker HTTP handlers now parse
  `RouterAbEd25519NormalSigningPrepareRequestV2` and
  `RouterAbEd25519NormalSigningFinalizeRequestV2`. The local round-1 store
  persists v2 intent, signing-payload, and admitted signing digests, and
  finalize signs only the stored admitted digest.
- Local smoke fixtures now build typed v2 prepare requests for NEAR
  transaction, NEP-413, and delegate-action branches. Split-worker and bundled
  local topologies exercise all three branches through Router prepare/finalize.
- Phase 7 cleanup deleted the remaining `router-ab-core` digest-only public
  normal-signing request structs and the old `RouterToSigningWorkerSigningRequestV1`
  wrapper. Cloudflare tests and the latency bench now use v2 prepare/finalize
  admission and handler fixtures.
- Spec-to-code review cleanup renamed pre-gate Cloudflare normal-signing
  admission objects to explicit prepare/finalize admission candidates and
  renamed the private SigningWorker prepare field to `admission_candidate`.
  Source guard coverage now prevents the old pre-gate `AdmissionV2` names from
  returning.
- Expiry, quota, replay, and abandoned-prepare cleanup semantics are now
  specified as testable Wallet Session v2 rules. Strict Router time has zero
  skew allowance, request expiry is bounded by Wallet Session expiry, prepare
  replay is single-admission, finalize is single-use through round-1 `take`,
  and expired record cleanup is constrained to expired replay/quota/round-1
  storage.
- Cloudflare coverage now rejects prepare/finalize when the request expiry is
  beyond the Wallet Session expiry and when Router time is exactly
  `expires_at_ms`.
- Router A/B TypeScript fixture parsers now normalize unknown JSON record and
  number fields before returning typed test values, clearing the Router A/B
  errors from package-wide `tsc`.
- SDK/server naming cleanup now has a scoped source scan proving deleted Router
  A/B normal-signing v1/grant symbols are absent outside docs and guard
  deny-lists. Existing threshold-session names outside Router A/B remain current
  auth, recovery, ECDSA, or signing-session terminology.
- Strict Cloudflare normal-signing CORS now requires an exact configured Origin.
  Missing config, empty config, and wildcard config fail closed for browser
  access to bearer-auth signing routes.
- Strict Cloudflare normal-signing CORS now omits
  `Access-Control-Allow-Credentials`; the public SDK uses bearer auth with
  `credentials: 'omit'`, and cookie Wallet Session auth remains deferred.
- Strict Cloudflare normal-signing routes parse raw request bytes through
  `router-ab-core` v2 boundary parsers. The v2 request graph rejects unknown
  legacy fields at top-level, scope, prepare-binding, and protocol boundaries.
- Durable Object cleanup now has explicit replay, quota, and SigningWorker
  round-1 cleanup operations. Cleanup removes only expired records and preserves
  live replay/quota/round-1 state.
- Local split-worker and bundled Router HTTP normal-signing paths now require
  the local Wallet Session bearer fixture. Local smoke/test fixtures use valid
  NEAR transaction and NEP-461 delegate-action Borsh preimages.
- Cloudflare coverage now explicitly rejects Wallet Session account/session
  mismatches, prepare/finalize admission account/session/request-id drift,
  prepare intent/signing-payload/admitted-signing digest drift, finalize
  intent/signing-payload drift, and replayed v2 prepare request ids.

Validation run on June 15, 2026:

- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed 13 tests after adding Router-side NEAR transaction and NEP-461
  delegate-action Borsh preimage parsing plus typed metadata drift rejection.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_vectors`
  passed 3 tests after regenerating normal-signing vectors with real Borsh
  NEAR transaction and delegate-action preimages.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- normal_signing`
  passed 17 focused normal-signing tests after replacing Cloudflare placeholder
  preimages with real Borsh fixtures.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
  passed 198 tests after the Borsh preimage parser and admission-candidate
  lifecycle cleanup.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 17 tests after adding the admission-candidate lifecycle guard and the
  SigningWorker Wallet Session exclusion guard.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after the admission-candidate rename and Borsh parser changes.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after the private SigningWorker field rename to `admission_candidate`.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --benches`
  passed after converting the normal-signing latency bench to admission
  candidate names and real Borsh preimage fixtures.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningVectors.unit.test.ts --reporter=line`
  passed 1 SDK/Rust vector parity test against the regenerated Borsh-backed
  vectors.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningValidation.unit.test.ts --reporter=line`
  passed 2 validation tests.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`
  passed 1 SDK source-guard test.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
  passed 201 tests after deleting v1-only grant/private-handler coverage.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed 9 tests.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml normal_signing`
  passed 4 matching tests.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 15 tests.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed 15 tests after adding v2 JSON boundary parsers and unknown-field
  rejection.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
  passed 206 tests after adding exact-origin CORS checks and expired-state
  cleanup operations.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 18 tests after adding strict Worker boundary-parser and CORS guards.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after strict Worker switched normal-signing public routes to raw-body
  v2 boundary parsers.
- `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http`
  passed 4 tests after local Router normal-signing HTTP paths started requiring
  the local Wallet Session bearer fixture.
- `rtk cargo check --manifest-path crates/router-ab-dev/Cargo.toml` passed after
  local split-worker and bundled HTTP auth updates.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml normal_signing`
  passed 5 matching tests.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test generated_vectors`
  passed 4 tests.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_vectors`
  passed 3 tests.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed 9 tests after adding the vector fixture.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml normal_signing`
  passed 7 matching tests after the SDK vector fixture work.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningVectors.unit.test.ts --reporter=line`
  passed 1 test.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningValidation.unit.test.ts --reporter=line`
  passed 2 tests.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`
  passed 1 test.
- `rtk wasm-pack build --target web --out-dir pkg --out-name wasm_signer_worker --release`
  and
  `rtk wasm-pack build --target web --out-dir pkg-server --out-name wasm_signer_worker --release --no-opt --features hss-server-exports`
  passed for `wasm/near_signer`.
- `rtk cargo test --manifest-path wasm/near_signer/Cargo.toml` passed 45
  tests.
- `rtk pnpm -C packages/sdk-web type-check` passed after fixing the
  package-wide workspace/test and VoiceID diagnostics.
- `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml`
  passed 50 tests after switching local route handlers and smoke fixtures to
  v2 request shapes.
- `rtk cargo run --manifest-path crates/router-ab-dev/Cargo.toml --bin router_ab_local_smoke -- --ephemeral --topology bundled`
  passed with `normal_signing_status: ed25519_v1` after exercising NEAR
  transaction, NEP-413, and delegate-action v2 prepare/finalize requests.
- `rtk cargo run --manifest-path crates/router-ab-dev/Cargo.toml --bin router_ab_local_smoke -- --ephemeral --topology four-worker`
  passed with `normal_signing_status: ed25519_v1` after exercising the same
  three branch requests through split local workers.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test protocol_boundaries`
  passed 59 tests after deleting the old public request structs and v1-only
  boundary tests.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
  passed 198 tests after converting Cloudflare fixtures away from v1 public
  normal-signing request structs.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 15 tests after extending the guard to the deleted v1 admission helper
  surface.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --benches`
  passed after converting the normal-signing latency bench to v2
  prepare/finalize admission.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after moving public normal-signing paths to `/v2/router-ab/ed25519/sign/*`.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 15 tests after adding guards for the `/v2/router-ab/ed25519/sign/*` public routes.
- `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml`
  passed 50 tests after moving the local Router normal-signing public paths to
  `/v2/router-ab/ed25519/sign/*`.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`
  passed 1 test after enforcing v2 SDK paths and bearer-only Router A/B
  credentials.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningVectors.unit.test.ts ./unit/routerAbNormalSigningValidation.unit.test.ts --reporter=line`
  passed 3 tests after the bearer-only Router A/B credential type change.
- `rtk pnpm -C packages/sdk-web type-check` passed after fixing the non-Router
  A/B workspace/test and VoiceID diagnostics.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- normal_signing_v2`
  passed 12 focused tests after adding Wallet Session expiry-clamp and
  exact-expiry rejection coverage.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 17 source-guard tests.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningVectors.unit.test.ts ./unit/routerAbNormalSigningValidation.unit.test.ts --reporter=line`
  passed 3 focused Router A/B normal-signing tests after the fixture parser
  fix.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`
  passed 1 SDK naming/source-guard test.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbWireVectors.unit.test.ts --reporter=line`
  passed 1 Router A/B wire-vector test after the fixture parser fix.
- `rtk pnpm -C packages/sdk-web type-check` passed after the broad workspace
  diagnostics were fixed.
- `rtk rg -n --glob '!target/**' --glob '!docs/router-a-b-single-session.md' --glob '!crates/router-ab-cloudflare/tests/source_guards.rs' --glob '!tests/unit/routerAbNormalSigningSdk.guard.unit.test.ts' "routerAbNormalSigningGrant|prepareRouterAbNormalSigningV1|finalizeRouterAbNormalSigningV1|NormalSigningRequestV1|NormalSigningRound1PrepareRequestV1|CloudflareSigningWorkerAdmittedNormalSigningRequestV1|CloudflareSigningWorkerMaterializedNormalSigningRequestV1" packages/sdk-web packages/sdk-server-ts tests/unit crates/router-ab-cloudflare crates/router-ab-core`
  returned no active source matches.
- `rtk rg -n "NormalSigningRound1PrepareRequestV1|NormalSigningRequestV1|RouterToSigningWorkerSigningRequestV1|derive_cloudflare_router_normal_signing_trusted_admission_v1|derive_cloudflare_router_normal_signing_round1_prepare_trusted_admission_v1|CloudflareSigningWorkerAdmittedNormalSigningRequestV1|CloudflareSigningWorkerMaterializedNormalSigningRequestV1|CloudflareSigningWorkerNormalSigningHandlerV1|normal_signing_admission_store_calls_at\\(|normal_signing_round1_prepare_admission_store_calls_at\\(|normal_signing_replay_reserve_call\\(" crates -S`
  now finds only the source guard's forbidden-string list.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- normal_signing_v2`
  passed 15 focused tests after adding Wallet Session account/session mismatch,
  admission drift, and replayed v2 prepare request-id coverage.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings`
  passed 211 tests after the negative-coverage additions.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 18 tests.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed 15 tests.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml normal_signing`
  passed 5 matching tests.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --benches`
  passed.
- `rtk cargo test --manifest-path crates/router-ab-dev/Cargo.toml --test local_worker_http`
  passed 4 tests.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningVectors.unit.test.ts ./unit/routerAbNormalSigningValidation.unit.test.ts --reporter=line`
  passed 3 tests.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`
  passed 1 test.
- `rtk pnpm router:smoke` passed through the four-worker topology with
  `normal_signing_status: ed25519_v1`.
- `rtk pnpm router:smoke:bundled` passed through the bundled topology with
  `normal_signing_status: ed25519_v1`.
- `rtk pnpm router:deploy:check` passed with
  `Router A/B release blockers clear.`
- `rtk pnpm -C packages/sdk-web type-check` passed after fixing the package-wide
  SDK type-check diagnostics outside Router A/B.
- `rtk pnpm -C packages/sdk-web type-check` passed after adding the deployed
  browser evidence harness.
- `rtk pnpm -C packages/sdk-web type-check` passed again after fixing the
  threshold-PRF and single-key HSS script fixtures for the current
  `ecdsa-hss/y_server` corpus.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 18 tests after removing the credentialed browser-request header from
  bearer-only normal-signing routes.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- normal_signing_v2`
  passed 15 focused tests after the bearer-only CORS header cleanup.
- `rtk pnpm router:deploy:browser-evidence --list` listed the single
  deployed-browser evidence test without starting local dev servers.
- `rtk pnpm -C tests exec playwright test -c playwright.router.config.ts ./unit/router.relayRouteSurface.unit.test.ts --reporter=line`
  passed 9 tests.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/registrationIntentAllocation.unit.test.ts --reporter=line`
  passed 29 tests.
- `rtk pnpm -C tests exec playwright test -c playwright.scripts.config.ts ./unit/signingRootShareResolver.script.unit.test.ts ./unit/thresholdPrfWasm.script.unit.test.ts --reporter=line`
  passed 7 tests.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/thresholdEd25519.registrationWarmSession.unit.test.ts --reporter=line`
  passed 3 tests.
- `rtk pnpm -C tests exec playwright test -c playwright.scripts.config.ts ./unit/thresholdEd25519.singleKeyHssActivePath.script.unit.test.ts --reporter=line`
  passed 14 tests.
- `rtk pnpm -C packages/sdk-web type-check` passed during the release-tail
  recheck.
- `rtk pnpm router:deploy:check` passed with
  `Router A/B release blockers clear.` during the release-tail recheck.
- `rtk pnpm router:deploy:browser-evidence --list` listed the deployed-browser
  evidence test without requiring deployed credentials.
- `rtk pnpm router:deploy:browser-evidence` reached the deployed-browser
  Playwright test and failed before issuing deployed requests because
  `ROUTER_AB_DEPLOYED_BASE_URL` is not set in the local shell. No
  `ROUTER_AB_DEPLOYED_*` or Cloudflare deployment variables were visible to
  this run.
- GitHub release-input audit after keygen:
  `seams-tech/seams-sdk` has no repo-level Actions secrets or variables.
  `staging` and `production` environment variables contain only the generated
  Router A/B identity public keys and peer verifying keys. Environment secrets
  contain only the generated identity private keys. The deploy workflow still
  needs `ROUTER_AB_JWT_ISSUER`, `ROUTER_AB_JWT_JWKS_URL`, optional
  `ROUTER_AB_JWT_AUDIENCE`, Cloudflare credentials, and Deriver A/B
  root-share wire secrets before a real upload/deploy can run.
- `rtk pnpm router:deploy:keygen -- --env staging --apply --repo seams-tech/seams-sdk`
  applied real staging Router A/B deployment identity variables and secrets to
  the `staging` GitHub Environment.
- Created the missing `production` GitHub Environment for
  `seams-tech/seams-sdk`, then
  `rtk pnpm router:deploy:keygen -- --env production --apply --repo seams-tech/seams-sdk`
  applied real production Router A/B deployment identity variables and secrets.
- `rtk pnpm router:deploy:dry-run -- --env staging` passed and wrote a
  timestamped ignored report under
  `crates/router-ab-cloudflare/reports/startup-latencies/`.
  Dry-run upload totals were Router 2887.88 KiB / gzip 879.45 KiB,
  Deriver A 2336.55 KiB / gzip 737.40 KiB, Deriver B 2336.49 KiB / gzip
  738.38 KiB, and SigningWorker 2784.06 KiB / gzip 896.44 KiB after
  ECDSA-HSS strict-route integration. The report has `startupTimeMs: null` for
  each role because Wrangler dry-run does not emit deployed startup timings.
- `rtk cargo test --manifest-path crates/router-ab-core/Cargo.toml --test normal_signing_v2`
  passed 20 tests after adding Router A/B Ed25519 presign-pool core wire
  types, strict pool-refill/pool-hit parsers, response/request binding
  validation, duplicate-handle rejection, cross-session response rejection, and
  pool-hit finalization lowering.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- normal_signing`
  passed 33 focused tests after adding the Wallet Session authenticated
  `/v2/router-ab/ed25519/sign/presign-pool/prepare` route model, SigningWorker private
  presign-pool refill materialization, unbound Ed25519 Durable Object put
  storage, and duplicate client-presign conflict coverage.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- normal_signing`
  passed 35 focused tests after adding Router pool-hit finalization admission,
  the private SigningWorker pool-hit claim route, Durable Object
  Ed25519-presign-pool take semantics, expiry enforcement, one-use missing
  handling, and pool-record drift rejection before final signing.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 36 source-guard tests after adding the Ed25519 presign-pool route and
  storage surface.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after wiring the strict public presign-pool refill route.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after wiring the strict private SigningWorker presign-pool refill
  route.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  passed after wiring `/v2/router-ab/ed25519/sign` to accept both the just-in-time finalize
  request shape and the presign-pool-hit finalize request shape.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after wiring the private
  `/router-ab/v1/signing-worker/sign/presign-pool` claim-and-finalize route.
- `rtk pnpm -C packages/sdk-web type-check` passed after adding the Router A/B
  Ed25519 presign-pool SDK ready-entry branch, Wallet Session pool-refill
  request builders, pool-hit selection, pool-miss fallback, and background
  refill wiring.
- `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/routerAbNormalSigningSdk.guard.unit.test.ts --reporter=line`
  passed 1 SDK source-guard test after the Router A/B pool-hit/refill SDK
  helper wiring.
- `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/routerAbNormalSigningVectors.unit.test.ts ./unit/routerAbNormalSigningValidation.unit.test.ts --reporter=line`
  passed 3 focused SDK normal-signing vector/validation tests.
- The old `thresholdEd25519.presignFinalizeClient.unit.test.ts` suite was
  deleted during Router A/B-only cleanup because it protected the removed
  `/threshold-ed25519/*` client fallback. Current SDK coverage is the Router A/B
  normal-signing guard plus focused Router A/B vector/validation tests.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- ed25519_presign_pool`
  passed 4 focused Durable Object Ed25519 presign-pool storage tests after
  adding expired-record cleanup and cross-session keyed-isolation coverage.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- signing_worker_production_presign_pool_hit_signs_router_admitted_digest`
  passed 1 production-handler test proving a valid pool hit signs the
  Router-admitted digest and an invalid client signature share burns the
  claimed pool record.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test bindings -- normal_signing`
  passed 35 focused normal-signing tests after the Ed25519 presign-pool cleanup
  and production pool-hit coverage.
- `rtk cargo test --manifest-path crates/router-ab-cloudflare/Cargo.toml --test source_guards`
  passed 36 source-guard tests after extending normal-signing Deriver A/B
  non-invocation guards to the pool-refill and pool-hit handlers.
- `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-router-entrypoint`
  and
  `rtk cargo check --manifest-path crates/router-ab-cloudflare/Cargo.toml --features strict-worker-signing-worker-entrypoint`
  passed after adding the Ed25519 presign-pool expired-record cleanup operation
  to the local and workers-rs Durable Object handlers.
- `rtk pnpm router:deploy:check` passed with
  `Router A/B release blockers clear.` after the Phase 9 local implementation
  and cleanup updates.

Next implementation order:

1. Finish release-blocking Router A/B ECDSA-HSS support.

   Product requirement: Cloudflare Router A/B must support ECDSA-HSS before any
   staging or production deploy. Treat `docs/router-a-b-ecdsa.md` as an active
   release plan, not a post-MVP feature.

   - [x] Complete initial `router_ab_ecdsa_hss_secp256k1_v1` protocol ids, request
         kinds, transcript domains, wire shapes, and boundary parsers.
   - [x] Implement Router public ECDSA-HSS registration/bootstrap and export
         boundaries.
   - [x] Implement Router-mediated ECDSA-HSS SigningWorker activation and
         public identity receipt derivation.
   - [x] Implement Deriver A/B private ECDSA-HSS registration/bootstrap handlers
         and strict private registration routes.
   - [x] Implement Deriver A/B private ECDSA-HSS recovery and refresh handlers.
   - [x] Implement client-only Deriver A/B export bundles so export does not
         produce unused SigningWorker-targeted bundles.
   - [x] Add active ECDSA-HSS normal-signing scope/material binding so
         SigningWorker material is re-derived and compared to the expected
         public identity before ECDSA signing.
   - [x] Add the ECDSA-HSS EVM digest signing request boundary and materialize
         it against active SigningWorker state before signature handling.
   - [x] Add the ECDSA-HSS recoverable-signature response boundary and
         SigningWorker handler interface.
   - [x] Add Cloudflare-compatible one-use ECDSA-HSS presignature state with
         typed Durable Object put/take/cleanup, active SigningWorker binding,
         request-digest binding, signing-digest binding, and scalar-share
         receipt redaction.
   - [x] Add the ECDSA-HSS finalize request boundary carrying server
         presignature id, 32-byte client signature share, and prepare
         request-digest binding.
   - [x] Add the ECDSA-HSS prepare response boundary and SigningWorker private
         prepare fetch helper that persists a one-use presignature record before
         returning the redacted public prepare response.
   - [x] Add Router public ECDSA-HSS prepare admission and service-call helper
         with Wallet Session verification, Router-owned store admission, replay
         reservation, and trusted-admission-bearing SigningWorker forwarding.
   - [x] Add Router public ECDSA-HSS finalize admission, SigningWorker private
         finalize fetch, one-use presignature take, and service-call helper.
   - [x] Add rerandomization entropy to the ECDSA-HSS prepare response,
         one-use presignature record, and Durable Object put receipt, with
         response/record/receipt binding and scalar-share redaction.
   - [x] Wire strict public Router ECDSA-HSS prepare/finalize routes to the
         materialized Wallet Session boundary and SigningWorker service calls.
   - [x] Wire strict private SigningWorker ECDSA-HSS finalize dispatch to
         one-use presignature take and production finalize handling.
   - [x] Implement the production ECDSA-HSS finalize handler using
         `signer-core` over Cloudflare-compatible presign state.
   - [x] Require ECDSA-HSS prepare requests to carry the client-held
         presignature id, bind it into the canonical prepare digest, carry it
         through Router prepare admission, and require the prepare response to
         echo it as the server presignature id.
   - [x] Add pool-backed production SigningWorker ECDSA-HSS prepare dispatch:
         strict private prepare reserves the selected unbound pool entry, binds
         it to the exact request, persists the request-bound one-use
         presignature record, and returns the redacted public response.
   - [x] Add strict private SigningWorker ECDSA-HSS pool-fill dispatch:
         trusted presign producers can write validated unbound pool records
         after active-state derivation from the ECDSA-HSS scope.
   - [x] Add SDK/server bridge for public/client-facing ECDSA-HSS
         presignature production: completed TypeScript threshold-ECDSA presign
         output plus validated Router A/B ECDSA-HSS scope now builds the exact
         strict private SigningWorker pool-fill request.
   - [x] Add SDK/server sender for the strict private SigningWorker pool-fill
         route with exact-path POST, receipt validation, duplicate
         classification, and request/receipt drift rejection.
   - [x] Wire the client-facing SDK/server ECDSA-HSS presignature producer path
         to carry validated Router A/B scope through presign-session state and
         invoke the sender when presign completes.
   - [x] Define strict ECDSA-HSS recovery and activation-refresh request
         boundaries: recovery maps to client-recipient export material, refresh
         maps to SigningWorker activation material, refresh carries previous and
         next activation epochs, and non-advancing epochs reject at the
         boundary.
   - [x] Implement Cloudflare Deriver A/B private recovery and activation
         refresh handlers.
   - [x] Wire public Router ECDSA-HSS recovery endpoint to the private Deriver
         recovery handlers and client-recipient response aggregation.
   - [x] Wire public Router ECDSA-HSS activation-refresh endpoint to a typed
         SigningWorker refresh activation path.
         Refresh now uses a distinct request/receipt model and a separate
         private SigningWorker refresh route.
   - [x] Keep Deriver A/B unreachable from the ECDSA-HSS materialized
         normal-signing boundary and prove this with source guards.
   - [x] Add native core and Cloudflare adapter validation for ECDSA-HSS
         boundary parsing, activation, export non-activation, and identity
         derivation.
   - [x] Add TypeScript bridge validation for mapping existing public
         threshold-ECDSA presign output into the strict private ECDSA-HSS
         pool-fill wire shape.
         The Router A/B bridge uses `serverKeyId` for new boundary input and
         isolates existing store `relayerKeyId` conversion at the adapter.
   - [x] Add TypeScript sender validation for the strict private ECDSA-HSS
         pool-fill route call and receipt handling.
         The sender uses the strict internal service-auth header expected by
         private Deriver/SigningWorker dispatchers.
   - [x] Add TypeScript lifecycle validation that a Router A/B ECDSA-HSS
         presign session persists the validated pool-fill branch, completes the
         real WASM presign exchange, calls the strict private pool-fill route,
         and leaves the local presign pool empty.
   - [x] Add native core validation for ECDSA-HSS recovery and activation
         refresh request parsing, lifecycle-kind rejection, envelope-role
         rejection, strict unknown-field rejection, recovery/export digest
         separation, non-advancing activation epoch rejection, and conversion
         into the generic Router proof-bundle transport.
   - [x] Add Cloudflare adapter validation for ECDSA-HSS recovery and
         activation-refresh private request wrappers, payload drift rejection,
         strict private route dispatch, and recipient-class separation.
   - [x] Add ECDSA-HSS source guards proving public Router, Deriver,
         SigningWorker, log, audit, and receipt paths do not materialize
         canonical `x`, `privateKeyHex`, or raw root material; private
         presignature scalar shares stay confined to SigningWorker request and
         storage records.
   - [x] Key active ECDSA-HSS SigningWorker state by wallet id, ECDSA
         threshold key id, signing root id/version, SigningWorker identity, and
         activation epoch through the canonical active-state session id used by
         Wallet Session and Router admission validation.
   - [x] Add branch-specific ECDSA-HSS Deriver A/B encrypted envelope plaintext
         types for registration, export, recovery, and refresh with canonical
         plaintext digests, envelope role/AAD binding, exact
         output-kind/work-kind validation, and source guards against private
         scalar/root material.
   - [x] Add deterministic ECDSA-HSS derivation vector coverage for scalar
         validity, public-key sum, Ethereum address parity, retry counters,
         export reconstruction, zero-sum identity rejection, transcript
         operation drift, wrong Deriver recipient, and wrong SigningWorker
         identity.
   - [x] Add explicit Signer A/B SigningWorker service bindings plus config
         guards for the direct ECDSA-HSS activation delivery prerequisite.
   - [x] Disable public `workers_dev` exposure for non-Router strict workers,
         require internal service-auth before private runtime construction or
         body parsing, and add release guards for those config and source
         invariants.
   - [x] Add the direct ECDSA-HSS activation delivery request type carrying only
         activation context, Deriver role, and one SigningWorker-recipient
         bundle.
   - [x] Add pure direct ECDSA-HSS activation delivery reconciliation so one
         Signer A delivery and one Signer B delivery for the same activation
         context produce the existing aggregate SigningWorker activation
         request.
   - [x] Add direct ECDSA-HSS activation delivery source guards proving the
         boundary cannot carry client/export bundles.
   - [x] Add remaining local Wasm adapter, SDK/server, local browser/WASM
         benchmark, recovery, refresh, and Cloudflare boundary-parser
         validation for ECDSA-HSS.
   - [x] Add expanded vector-matrix coverage for ECDSA-HSS.
   - [x] Add local normal-signing latency evidence for ECDSA-HSS.
   - [ ] Add remaining deployed Cloudflare evidence for ECDSA-HSS.

2. Restore Router A/B Ed25519 presign-pool UX.

   Product requirement: Ed25519 Router A/B normal signing must remain
   UX/latency optimized like the previous threshold Ed25519 presign path.
   Background refill should create one-use client/server round-1 pairs before
   confirmation, pool-hit signing should require one public Router finalize
   request, and pool misses should fall back to the current prepare/finalize
   path.

   - [x] Implement the Phase 9 Router A/B Ed25519 presign-pool core wire
         types, strict request/response parsers, pool-hit finalization request,
         and protocol tests.
   - [x] Implement the public Wallet Session pool-refill route, SigningWorker
         unbound round-1 pool storage, pool-hit finalize branch, and
         route/source tests.
   - [x] Implement SDK pool-hit selection, miss fallback, background refill,
         expired unbound-pool cleanup, and local source/test coverage.
   - [x] Prove pool-hit normal signing does not invoke Deriver A or Deriver B.
   - [ ] Record pool-hit and pool-miss latency separately, including CORS
         preflight behavior.

3. Close Router A/B release evidence.

   Finish deploy/runtime evidence only after the ECDSA-HSS release blocker
   above is complete and the Ed25519 presign-pool UX path is restored.

   - [ ] Capture deployed strict Cloudflare browser evidence with
         `rtk pnpm router:deploy:browser-evidence` for
         `/v2/router-ab/ed25519/sign/prepare` and `/v2/router-ab/ed25519/sign`: configured-origin success,
         rejected-origin behavior, preflight behavior, and timing with
         preflight included. Blocked until `ROUTER_AB_DEPLOYED_BASE_URL`, the
         remaining `ROUTER_AB_DEPLOYED_*` inputs, and a request-scoped Wallet
         Session flow fixture are available.
   - [x] Restore the package-wide SDK type-check gate:
         `rtk pnpm -C packages/sdk-web type-check`.
   - [ ] Run and record the remaining deploy/runtime validation from
         `docs/router-A-B-signer.md` Phase 9B: cold-ish and hot-isolate
         normal-signing latency, cold-ish and hot-isolate
         registration/export/refresh latency, Deriver A/B non-invocation on
         normal signing, Cloudflare metrics/logs, startup-budget comparison,
         and the measured startup table. Local dry-run upload shape passed, but
         real upload/runtime evidence remains blocked on Router JWT variables,
         Cloudflare deployment credentials, deployed Worker URL/log access, and
         Deriver A/B root-share wire-secret provisioning.
   - [x] Apply real staging Router A/B deployment identity keys:
         `rtk pnpm router:deploy:keygen -- --env staging --apply`.
   - [x] Apply real production Router A/B deployment identity keys:
         `rtk pnpm router:deploy:keygen -- --env production --apply`.

4. Finish non-Router-A/B cleanup.

   Do this cleanup audit next because it reduces background drag and stale
   naming before deeper domain work.

   - [x] Complete the broader `V1`/`V2`, `_v1`/`_v2`, legacy,
         compatibility, and deprecated suffix audit outside the Router A/B
         normal-signing public boundary.
   - [x] Rename app `--fe-*` CSS tokens to `--site-*` or domain-specific
         tokens, then delete the alias block from `apps/web-client/src/app.css`.
   - [x] Audit sealed-session persistence and `sealedRecovery` legacy parser
         branches; keep only request/persistence boundary parsers with explicit
         persisted-shape coverage and deletion criteria.
   - [x] Audit synthetic legacy ECDSA key-id rejection in
         `ecdsaKeyFactsInventory` and warm-unlock planner tests; delete the
         branch and tests if persisted profile inventory can no longer contain
         those ids.
   - [x] Audit demo/console seed cleanup and PostgreSQL startup migrations that
         mention deprecated or legacy rows/columns, then delete one-time
         migration branches whose source schema is no longer supported in
         development.
   - [x] Re-run focused source scans after each cleanup phase and keep public
         wire-schema suffixes out of deletion lists.

5. Final Router A/B legacy and naming cleanup.

   This is the end-of-plan cleanup phase. Start it after the Wallet Session V2
   and ECDSA-HSS Router A/B functional work is complete and the release evidence
   tail above is closed. Delete retired compatibility surfaces first, then
   normalize internal names after one active model remains.

   The comprehensive cleanup plan for making Router A/B the only Ed25519 and
   ECDSA signing architecture lives in
   [router-a-b-cleanup.md](./router-a-b-cleanup.md). That plan owns the deletion
   of old non-Router `/threshold-ed25519/*` and `/threshold-ecdsa/*` public
   signing routes, SDK callers, handlers, fixtures, and threshold-session auth
   fields.

   - [ ] Audit all Router A/B Rust, TypeScript, test, fixture, doc, route, and
         script symbols containing `_v1`, `_v2`, `V1`, `V2`, `legacy`,
         `compat`, `deprecated`, old grant naming, old threshold-session naming,
         and obsolete one-shot normal-signing naming.
   - [ ] Delete all retired legacy V1 structs, enums, type aliases, traits,
         builders, functions, route handlers, route constants, endpoints,
         fixture builders, mocks, source guards, docs snippets, and tests that
         exist only for retired Router A/B flows.
   - [ ] Keep compatibility code only at persistence or request parsing
         boundaries where a current persisted/deployed shape still requires it;
         each remaining boundary must have deletion criteria and targeted
         coverage.
   - [ ] Re-run source scans proving no retired Router A/B legacy V1 flow names,
         structs, endpoints, helpers, tests, or fixtures remain outside explicitly
         documented current wire/persistence boundaries.
   - [ ] Keep `RouterAb` prefixes where they identify the active protocol
         boundary, wire schema, public API, cross-role contract, or
         multi-protocol call site. Rename only redundant internal `RouterAb`
         prefixes after the legacy surface is gone and local module context
         already makes the protocol obvious.
   - [ ] Remove excessive `V1`/`V2` suffixes from internal non-wire structs,
         helpers, tests, and functions after the legacy surface is gone.
   - [ ] Keep explicit version suffixes only for current serialized wire schemas,
         public API contracts, persistence records, metrics, and cross-language
         worker/signer contracts where the version is part of the durable
         protocol.
   - [ ] Update source guards to reject reintroduction of deleted legacy V1
         symbols and to enforce the new internal naming rules.
   - [ ] Run focused Rust and TypeScript validation after each deletion/rename
         slice, then run the release-ready gate after the final cleanup.

## Broader Non-Router-A/B V1/V2 Suffix Audit

Scope: SDK, server, app, and test names outside the Router A/B normal-signing
public boundary. This audit excludes `V1`/`V2` symbols that are part of current
Router A/B normal-signing wire contracts already classified in Phase 7.

Policy:

- Keep explicit suffixes for current public wire contracts, database schemas,
  migration/export artifacts, durable persistence records, cryptographic wire
  primitives, route versions, and metric versions.
- Delete or rename suffixes when the suffix describes a retired branch,
  compatibility shim, stale test fixture, or active helper whose current role is
  no longer legacy.
- Keep compatibility and migration logic only at request and persistence
  boundaries. Give each kept boundary a deletion condition.

Completed cleanup on June 15, 2026:

- [x] Confirmed the Wallet Session V2 plan and Phase 7 legacy Router A/B
      normal-signing cleanup are implementation-complete, with release evidence
      and deploy/runtime tail work tracked in the ordered queue above.
- [x] Scanned SDK, server, app, and test source for `V1`, `V2`, `_v1`, `_v2`,
      `legacy`, `compatibility`, and `deprecated` outside generated/build
      output.
- [x] Replaced the `PasskeyAuthMenu/passkeyAuthMenuCompat` source entrypoint
      with `PasskeyAuthMenu/public`, updated the package export, build entry,
      React index export, and direct test imports, then deleted the compat-named
      module.
- [x] Renamed the invalid Router A/B normal-signing type fixture from
      `router_ab_ed25519_normal_signing_legacy_v1` to a neutral invalid variant.
- [x] Renamed active Wallet Session budget glue from
      `buildLegacyStatusQueryFromBudgetStatusCheck` to
      `buildStatusQueryFromBudgetStatusCheck`.
- [x] Validated the first cleanup slice:
      `rtk pnpm -C packages/sdk-web build:rolldown`,
      `rtk pnpm -C tests exec playwright test -c playwright.unit.config.ts ./unit/passkeyAuthMenu.ssr.unit.test.ts --reporter=line`,
      and
      `rtk pnpm -C tests exec playwright test -c playwright.source.config.ts ./unit/passkeyAuthMenuPublicEntry.guard.unit.test.ts --reporter=line`
      passed.
- [x] Removed pre-refactor inline style-node cleanup from
      `SeamsWebProvider` and the wallet iframe host, and deleted the unused
      PasskeyAuthMenu input-message keyframe kept only for old class names.
- [x] Re-ran `rtk pnpm -C packages/sdk-web build:rolldown` and the
      `passkeyAuthMenuPublicEntry` source guard after the style/provider
      cleanup. A focused source scan now finds no old inline-style cleanup ids,
      unused PasskeyAuthMenu input-message animation names, old compat module
      imports, old Wallet Session budget helper names, or old Router A/B
      invalid-fixture names outside the guard's forbidden string.
- [x] Renamed app CSS design tokens from `--fe-*` to `--site-*` or
      domain-specific tokens across `apps/web-client/src`, then deleted the
      transitional app-wide alias block from `apps/web-client/src/app.css`.
- [x] Deleted the synthetic legacy ECDSA key-id branch from
      `ecdsaKeyFactsInventory`, normalized the warm-unlock blocked reason to
      `invalid_key_handle`, and updated the targeted inventory, warm-unlock,
      and login fixtures.
- [x] Normalized sealed-session persistence and recovery parser names to
      `RawSealedSessionRecord`, `asRawSealedSessionRecord`, and
      `unsupported_record`, leaving versioned values only in persisted wire
      `kind` fields.
- [x] Removed demo seed cleanup for deprecated users, deleted obsolete
      one-time PostgreSQL cleanup scripts and package scripts, removed startup
      migration branches for retired console sponsorship/observability schema
      shapes, and deleted the no-op Cloudflare cron rotation flag.
- [x] Validated the completed cleanup slice with
      `rtk pnpm -C apps/web-client typecheck`,
      `rtk pnpm -C packages/sdk-web type-check`,
      `rtk pnpm -C apps/web-server build`,
      `rtk pnpm -C packages/sdk-server-ts type-check`,
      targeted ECDSA inventory/warm-unlock unit tests, targeted relayer cron
      tests, and focused source scans for the deleted legacy names.

Current suffixes classified as keep-current:

- [x] Registration and signer intent schemas:
      `RegistrationIntentV1`, `AddSignerIntentV1`,
      `AddAuthMethodIntentV1`, and `NearAccountOwnershipProofV1`.
- [x] Threshold Ed25519 participant and signing-root wire primitives:
      `ThresholdEd25519ParticipantV1`, `SigningRootSecretShareWireV1`,
      and `SigningRootMigrationBundleV1`.
- [x] Current server/app protocol and metric literals such as
      `registration_v1`, `sealed_refresh_v1`, `app_session_v1`,
      `free_registrations_v1`, and `maw_v1`.
- [x] Current UI/security worker API version names such as
      `awaitUserConfirmationV2`.
- [x] Current cryptographic and persistence wire `kind` values stay versioned
      where they identify serialized artifacts, route payloads, metrics,
      database rows, or cross-language signer/worker contracts.

Remaining cleanup tasks:

- [x] Add a focused source guard that rejects reintroducing the deleted
      `passkeyAuthMenuCompat` module/path in source, package exports, and tests.
- [x] Audit `packages/sdk-web/src/react/context/SeamsWebProvider.tsx` and
      PasskeyAuthMenu CSS for older inline-style/class cleanup paths; delete
      them if current styles no longer produce those nodes/classes.
- [x] Rename app `--fe-*` CSS tokens to `--site-*`/domain-specific tokens in a
      coordinated app style cleanup, then delete the alias block from
      `apps/web-client/src/app.css`.
- [x] Audit `packages/sdk-web/src/core/signingEngine/session/persistence` and
      `sealedRecovery` legacy record parsing; keep only boundary parsers with
      explicit persisted-shape coverage and add deletion criteria.
- [x] Audit `ecdsaKeyFactsInventory` synthetic legacy key-id rejection and
      warm-unlock planner tests; keep it only if persisted profile inventory can
      still contain those ids, otherwise delete the branch and tests.
- [x] Audit demo/console seed cleanup and PostgreSQL startup migrations that
      mention deprecated or legacy rows/columns, then delete one-time migration
      branches whose source schema is no longer supported in development.
- [x] Re-run focused source scans after each cleanup phase and keep public
      wire-schema suffixes out of deletion lists.

No local non-Router-A/B cleanup task remains open. The final Router A/B
legacy/naming cleanup is tracked in the ordered queue above and starts after the
functional Wallet Session V2/ECDSA-HSS plan and release evidence tail are
closed.

## Migration Policy

This repo is still in development. Make this a clean breaking change.

- Remove client-visible Router grant helpers.
- Remove grant-specific SDK auth branches.
- Remove grant-specific public API docs.
- Keep compatibility parsing only where an existing persisted Wallet Session
  shape must still be read.
- Delete obsolete compatibility code after the new Wallet Session boundary is
  validated locally.

## Deployment Impact

The Cloudflare Router still needs JWT verification config if Wallet Session uses
JWT bearer auth:

- issuer
- audience
- JWKS URL

Those settings now describe Wallet Session verification for the public Router
worker. They do not define a second Router normal-signing grant.

MVP deployment decisions:

- Strict Cloudflare Router uses bearer Wallet Session auth first.
- Cookie Wallet Session auth is deferred until CSRF, SameSite, origin, and CORS
  credential requirements are specified for the strict Worker.
- Wallet Session contains `routerAbNormalSigning.signingWorkerId`, and Router
  validates it against request scope and SigningWorker response scope.
- Runtime SigningWorker lookup by session id is deferred to key/identity
  rotation work.

## Performance Impact

Expected latency impact:

- Removes the extra client-visible grant exchange.
- Adds Router-side intent and signing-payload digest recomputation.
- Preserves the previous Ed25519 presign-pool UX: pool hits require one public
  finalize request after user confirmation, while pool misses use the current
  prepare/finalize fallback.
- Moves pool refill to background Wallet Session authenticated Router calls.
- Keeps Deriver A and Deriver B off the normal-signing hot path.

Expected CPU impact:

- Ed25519/JWT verification remains cheap relative to network and Worker startup.
- Digest recomputation is cheap for NEP-413 and delegate actions.
- NEAR transaction payload verification may require signer-core/Wasm helpers in
  Router. Measure this in the focused normal-signing smoke path.
- Browser CORS preflight adds one network round trip when the request is not
  preflight-cacheable; capture deployed prepare/finalize timing with preflight
  included.

## Security Tradeoff

The per-intent Router grant minimized bearer-token blast radius by encoding one
authorized `intentDigest`. The single-session design preserves exact request
binding after Router admission by validating typed request data, canonical
payload preimages, request id, round-1 binding, and SigningWorker scope.

The Wallet Session credential remains session-scoped. Its blast radius is the
authorized session window and policy. Mitigations:

- short Wallet Session TTL
- request replay reservation
- one-use round-1 nonce consumption
- one-use presign-pool record claim/burn semantics
- per-account normal-signing quota
- policy and abuse gates
- typed intent validation
- signing-payload digest recomputation
- client-side confirmation before constructing the request

If a deployment needs per-intent bearer blast-radius reduction, add it as an
internal Router implementation detail or a stricter Wallet Session renewal mode.
Do not expose a second Router grant to SDK users.

## Acceptance Criteria

- The SDK exposes only Wallet Session auth for Router A/B normal signing.
- Public Router/Relay normal-signing endpoints accept Wallet Session auth only.
- Router recomputes intent and signing payload digests from typed request data.
- Router creates prepare/finalize admission candidates after Wallet Session,
  request, digest, preimage, and binding checks; SigningWorker forwarding uses
  only admitted private request bodies after policy/quota/abuse and replay gates.
- Prepare and finalize use distinct v2 request types.
- Router A/B Ed25519 preserves presign-pool latency: pool hits finalize through
  one public Router request, pool misses fall back to prepare/finalize, and
  background refill restores the target pool depth.
- Finalize consumes the server round-1 handle exactly once.
- Finalize rejects binding drift without consuming nonce material.
- Pool-hit finalize burns a claimed nonce record after any admitted
  cryptographic finalization attempt.
- SigningWorker receives only admitted prepare/finalize material.
- NEAR transaction signing passes through the new path.
- NEP-413 signing passes through the new path.
- Delegate-action signing passes through the new path.
- Source guards prove no client-visible Router normal-signing grant remains.
- Source guards prove public normal-signing JWT validation no longer reads
  `intentDigest`.
- Strict Cloudflare CORS/browser prepare/finalize evidence is captured.
- Vector/source guards prove Rust `router-ab-core` is the canonicalization
  authority for admission.
- Public v2 request types remain branch-specific and do not expose a generic
  sign-anything payload.
- `pnpm router:smoke` and `pnpm router:smoke:bundled` pass.
- `pnpm router:deploy:check` passes.

## Deferred Questions

- Should Wallet Session bearer JWT audience be a general public Router audience
  or a wallet-session-specific audience?
- Which Rust/Wasm packaging path should strict Router use for NEAR transaction
  digest recomputation if pure Rust validation increases Worker bundle size too
  much?
- What rotation policy should replace static
  `routerAbNormalSigning.signingWorkerId` after MVP key and identity rotation
  work begins?
