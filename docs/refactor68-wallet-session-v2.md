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
POST /v2/hss/sign/prepare
POST /v2/hss/sign
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
- `rtk pnpm router:deploy:check` passed with
  `Router A/B release blockers clear.`
- `rtk pnpm -C packages/sdk-web type-check` passed.
- `rtk pnpm -C apps/web-client typecheck` passed after the broader cleanup.
- `rtk pnpm -C packages/sdk-server-ts type-check` passed after the broader
  cleanup.
- `rtk pnpm -C apps/web-server build` passed after the broader cleanup.

Focused stale-name scans found no active source matches for the deleted
normal-signing v1/grant symbols outside docs and guard deny-lists.

## Remaining Release Tail

These are release-readiness tasks. They do not reopen the local Wallet Session
V2 implementation.

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
POST /v2/hss/sign/prepare
POST /v2/hss/sign
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
