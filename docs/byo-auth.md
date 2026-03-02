# BYO Auth Integration Plan (Post-Refactor Update)

Date updated: March 1, 2026

## Objective

Let customer-developers keep their existing auth stack while using our embedded wallet and threshold signing stack, without legacy route/symbol duplication.

Core outcomes:

1. App auth remains customer-owned.
2. Wallet state is modeled as `locked`/`unlocked` (not app-auth state).
3. Wallet server exposes HTTP + webhook controls for warm session lifecycle.
4. One canonical auth/session API surface after cutover (no compatibility aliases).

## Breaking Changes Landed (March 1, 2026)

1. React wallet-menu callback is `onLock` (legacy `onLogout` removed, no alias).
2. Passive stale-session cookie matching is strict by cookie name via `sessionCookieName` (typically wired from `SESSION_COOKIE_NAME`), defaulting to `tatchi-jwt`.
3. Wallet-state terminology is fully lock/unlock-first across active SDK and docs surfaces.

## Current Implementation Snapshot

### 1) App Session Model (Implemented)

1. App session claims are explicitly separated from threshold claims using `kind=app_session_v1`.
2. Session-bearing routes validate `appSessionVersion` using identity store state.
3. Session invalidation primitive already exists at user scope via app-session-version rotation.
4. Session transport supports both JWT and HttpOnly cookie via `sessionKind` normalization.

### 2) Server Route Surface (Current)

App/provider auth routes:

- `POST /auth/passkey/options`
- `POST /auth/passkey/verify`
- `POST /auth/google/options`
- `POST /auth/google/verify`
- `GET /auth/identities`
- `POST /auth/link`
- `POST /auth/unlink`

Session routes:

- `GET /session/state` (configurable via `sessionRoutes.state`)
- `POST /session/exchange`
- `POST /session/refresh`
- `POST /session/revoke`

### 3) Threshold Session Model (Implemented)

1. Threshold claim kinds remain explicit and separate:
- `threshold_ed25519_session_v1`
- `threshold_ecdsa_session_v1`
2. Threshold route guards validate threshold-scoped claims independently from app-session claims.
3. Direct threshold session minting paths can issue JWT or cookie depending on `sessionKind`.
4. Some registration/bootstrap flows still enforce JWT-only threshold session signing when assembling response payloads (`threshold_*.session_kind must be jwt`).

### 4) SDK/Auth Surface (Current)

1. SDK session minting in unlock flow defaults to exchange-first app-session issuance (`POST /session/exchange`).
2. Public wallet-state naming is lock/unlock-first (`auth.unlock`, `auth.lock`, `auth.getWalletSession`).
3. Wallet lock/unlock-specific HTTP routes are present in both Express and Cloudflare routers.
4. `AccountMenuButton` lock-state callback is `onLock`; legacy `onLogout` no longer exists.
5. Named-cookie matching for passive stale-session expiry uses `sessionCookieName` (env `SESSION_COOKIE_NAME` in examples), default `tatchi-jwt`.

### 5) Relay Lifecycle Webhooks (Partially Implemented)

1. Relay routes can emit lifecycle events through `relayWebhooks` integration.
2. Implemented event emissions:
- `session.warm.created`
- `session.warm.refreshed`
- `session.warm.expired` (refresh unauthorized outcomes, invalid-session-version failures, stale bearer/cookie parse failures)
- `session.exchange.failed`
- `session.revoked`
- `wallet.unlocked`
- `wallet.locked`
3. Passive stale-session expiry coverage now includes stale bearer and named-cookie parse failures.

### 6) Relay Webhook Payload Contract (Current)

Delivery headers (Console webhook transport):

- `X-Console-Webhook-Id`
- `X-Console-Webhook-Event-Id`
- `X-Console-Webhook-Event-Type`
- `X-Console-Webhook-Timestamp`
- `X-Console-Webhook-Signature`

Common payload fields:

1. `orgId` (resolved from relay webhook config/claims).
2. `userId` (present when route has user identity context).
3. Event-specific fields:
- `session.warm.created`: `kind`, `provider`, `sessionKind`, `appSessionVersion`.
- `session.warm.refreshed`: `refreshed`, `sessionKind`.
- `session.warm.expired`: `expired`, `source`, `reason`, `sessionKind`, `code` (when available).
- `session.exchange.failed`: `code`, `message`, `status`, `exchangeType`, `sessionKind`.
- `session.revoked`: `revoked`, `appSessionVersion`.
- `wallet.unlocked`: `unlocked`, `method`, `challengeId`.
- `wallet.locked`: `locked`, `appSessionVersion`.

Consumer idempotency and replay guidance:

1. Use `X-Console-Webhook-Event-Id` as the dedupe key.
2. Reject deliveries with stale `X-Console-Webhook-Timestamp` outside your accepted skew window.
3. Verify `X-Console-Webhook-Signature` before processing payload.
4. Persist terminal processing result by `eventId` so retries and manual replay calls are no-ops.
5. Log both `eventId` and `eventType` for incident correlation.

Retry/backoff and dead-letter operational guidance:

1. Return 2xx only after durable processing (or durable enqueue in your worker pipeline).
2. Return 4xx only for permanently invalid payload/signature/authorization outcomes.
3. Return 5xx (or timeout) for transient failures to allow retry scheduling.
4. Monitor delivery attempts and dead-letter queues from `/console/webhooks/*` endpoints.
5. Configure retry cadence and max attempts from deployment env (`WEBHOOK_RETRY_*` settings) where retry dispatch is enabled.

## Gaps To Reach BYO Auth End State

1. Remaining legacy `/auth/*` routes still exist, but app-session issuance is now exchange-first.
2. Warm-session lifecycle webhook coverage is complete for current guarded app-session routes.
3. Provider guides are published; final polish/alignment across all docs is still incomplete.
4. Remaining legacy references are now limited to historical/planning notes (not runtime or API docs).

## Locked Decisions For Next Cutover

1. App auth and wallet unlock remain separate planes.
2. `OIDC/JWT` is the primary external-auth exchange contract.
3. Breaking changes are allowed; no legacy alias routes/symbols after cutover.
4. Threshold session claim schemas and signing invariants remain unchanged.
5. Canonical route vocabulary post-cutover:
- app-session lifecycle in `session/*`
- wallet state lifecycle in `wallet/*`

## Target API Surface (Post-Cutover)

### Session Plane

- `POST /session/exchange`
- `POST /session/refresh`
- `POST /session/revoke`
- `GET /session/state`

### Wallet Plane

- `POST /wallet/unlock/challenge`
- `POST /wallet/unlock/verify`
- `POST /wallet/lock`
- `GET /wallet/state`

### Legacy Removal In Same Release

1. Remove `/auth/passkey/*` and `/auth/google/*` as primary app-session issuance routes.
2. Remove `/session/auth` and `/session/logout` in favor of canonical `session/state` and `session/revoke` semantics.
3. Remove legacy wallet auth naming in SDK/server/docs where wallet lock state is intended.
4. Remove migration-only compatibility branches/flags.

## `POST /session/exchange` Contract (Spec Candidate)

Request (`exchange.type=oidc_jwt`):

```json
{
  "sessionKind": "jwt",
  "exchange": {
    "type": "oidc_jwt",
    "token": "eyJ..."
  }
}
```

Request (`exchange.type=passkey_assertion`):

```json
{
  "sessionKind": "jwt",
  "exchange": {
    "type": "passkey_assertion",
    "challengeId": "webauthn-challenge-id",
    "webauthn_authentication": {
      "id": "...",
      "rawId": "...",
      "type": "public-key",
      "response": {
        "clientDataJSON": "...",
        "authenticatorData": "...",
        "signature": "...",
        "userHandle": null
      },
      "clientExtensionResults": null
    }
  }
}
```

Passkey-first one-step login + session mint sequence:

1. `POST /wallet/unlock/challenge` with `user_id` and `rp_id`.
2. Collect WebAuthn assertion in the client.
3. `POST /session/exchange` with `exchange.type=passkey_assertion`.
4. Read app-session claims via `GET /session/state`.

Response (`sessionKind=jwt`):

```json
{
  "ok": true,
  "session": {
    "kind": "app_session_v1",
    "userId": "user_123"
  },
  "jwt": "eyJ..."
}
```

Response metadata contract (frozen):

- `session.expiresAt` is optional.
- Include `session.expiresAt` only when the minted app-session token carries a parseable numeric JWT `exp` claim; omit for opaque/non-JWT token formats.

Response (`sessionKind=cookie`):

- `Set-Cookie: <HttpOnly app session cookie>`
- body omits `jwt`

Validation requirements:

1. `iss` + `aud` allowlist checks.
2. JWKS signature verification.
3. Stable subject mapping (`sub -> userId`).
4. Clock claim checks (`iat`, `nbf`, `exp`) with bounded skew.
5. Optional replay protection (`jti`) for short-lived exchange tokens.
6. `POST /auth/passkey/verify` remains verification-only (no app-session minting).

## Implementation Plan (Aligned To Current Code)

### Phase 0: Spec Lock

1. Freeze `session/exchange` schema and exchange types.
2. Freeze subject/claims mapping contract (`sub`, optional org/role claims).
3. Freeze route vocabulary and remove dual naming from docs/specs.
4. Decide threshold transport policy and lock it:
- Option A: keep mixed behavior where already present and do not expand.
- Option B: full threshold cookie parity in all threshold session minting paths.

### Phase 1: Generic Exchange Service

1. Add generic OIDC/JWT verifier abstraction in server core config/types.
2. Implement exchange flow in `AuthService`:
- verify token (issuer/audience/JWKS/time claims)
- map subject to `userId`
- ensure app-session version
- mint `app_session_v1` via existing session adapter
3. Keep existing passkey/google flows functional only until full route cutover lands.

### Phase 2: Session Routes Cutover (Express + Cloudflare)

1. Add `POST /session/exchange`.
2. Add `GET /session/state` (successor to `/session/auth`).
3. Add `POST /session/revoke`:
- initial implementation may use app-session-version rotation for user-scope revoke
- add explicit per-session revoke only if a session-id store is introduced
4. Keep `POST /session/refresh`.
5. Remove `/session/auth` and `/session/logout` once SDK/tests are cut over.

### Phase 3: Wallet Plane + SDK Naming Cutover

1. Introduce wallet unlock/lock endpoints under `wallet/*`.
2. Move passkey unlock step-up semantics from provider-auth framing to wallet-unlock framing.
3. Rename SDK/client symbols to `unlock/lock` where wallet state is intended.
4. Remove old `/auth/*` primary-session paths and old wallet auth symbols in the same release.

### Phase 4: Warm Session Controls + Webhooks

1. Implement signed webhooks:
- `session.warm.created`
- `session.warm.refreshed`
- `session.warm.expired`
- `session.revoked`
- `wallet.unlocked`
- `wallet.locked`
- `session.exchange.failed`
2. Delivery requirements:
- HMAC signature + timestamp
- idempotent event ids
- retry/backoff + dead-letter visibility
- tenant/org scoping in payload

### Phase 5: Provider Guides

1. Better Auth (OIDC/JWT exchange).
2. Auth0.
3. Okta.
4. Google OIDC.
5. Optional quickstarts for Clerk/Supabase/Firebase using the same exchange contract.

## Execution Order (Recommended)

1. Spec PR: lock route names, exchange contract, claim mapping, threshold transport policy.
2. Server core PR: generic OIDC verifier + session exchange service.
3. Router PR: add `session/exchange`, `session/state`, `session/revoke` (both Express and Cloudflare).
4. SDK PR: switch default session creation path from `/auth/passkey/*` to `/session/exchange`.
5. Wallet naming PR: legacy wallet auth naming -> `unlock/lock` where wallet state is intended.
6. Cleanup PR: remove legacy routes/symbols/tests in same release train.
7. Webhook PR: signed delivery + retries + lifecycle events.
8. Docs/examples PR: provider integration guides and final API references.

## Immediate Next Steps

- [x] Make `GET /session/state` the canonical session-read path in router defaults.
- [x] Add `AuthService.verifyOidcJwtExchange` unit coverage for issuer/audience/signature/time-claim failure modes.
- [x] Add integration coverage for `session/exchange -> threshold bootstrap/session -> authorize/sign`.
- [x] Add SDK unit coverage for `exchangeSession` success/error/cookie-path behavior.
- [x] Add SDK guardrail: reject `session.route=/session/exchange` when `session.exchange` payload is missing.
- [x] Begin SDK cutover so app-session issuance defaults to `POST /session/exchange` instead of `/auth/passkey/*`.
- [x] Start wallet-plane route implementation (`wallet/unlock/*`, `wallet/lock`, `wallet/state`) and remove legacy wallet auth wording where lock state is intended.
- [x] Rename `auth` capability methods to lock-state semantics (`auth.unlock`, `auth.lock`, `auth.getWalletSession`) and update direct callsites.
- [x] Remove remaining legacy wallet-state symbols from SDK public surface.
- [x] Require named cookie matching for passive stale-session expiry signaling (`sessionCookieName`, env-backed, default `tatchi-jwt`).

## Next Execution Slice (Phased)

1. SDK session issuance cutover:
- [x] make exchange-first app-session issuance explicit in SDK unlock/session options and docs
- [x] add SDK tests for exchange path (`jwt` + `cookie`) and expected error propagation
- [x] remove remaining default assumptions that app-session issuance must use `/auth/passkey/*`
2. Wallet-plane route scaffolding:
- [x] add `POST /wallet/unlock/challenge`, `POST /wallet/unlock/verify`, `POST /wallet/lock`, `GET /wallet/state` in Express + Cloudflare
- [x] map existing passkey challenge/verify primitives into wallet unlock semantics
- [x] keep app-session (`session/*`) and wallet-state (`wallet/*`) responsibilities fully separated
3. Legacy surface removal prep:
- [x] identify and delete migration-only route aliases/symbols once SDK/tests are switched
- [x] remove `/session/auth` and `/session/logout` compatibility endpoints in the same release train
- [x] drop remaining legacy wallet auth wording where lock-state semantics are intended
4. Auth-route retirement (next):
- [x] stop minting app sessions from `/auth/passkey/verify` and require `session/exchange` for app-session issuance
- [x] remove `/auth/google/verify` session-issuance path in favor of exchange-only issuance
- [x] delete remaining test/helpers that treat `/auth/*` as the canonical app-session flow

## Phased TODO Checklist

### Phase 0: Spec Lock

- [x] Freeze `POST /session/exchange` request/response schema.
- [x] Freeze claim mapping contract (`sub`, optional org/role claims, provider metadata).
- [x] Freeze canonical route vocabulary (`session/*` and `wallet/*`).
- [x] Choose and lock threshold transport policy (mixed vs full cookie parity).
- [x] Remove conflicting route naming from docs (`/session/auth` vs `/session/state` target).

Locked decision (March 1, 2026):
- Threshold transport policy is **Option A** for this cut: keep mixed behavior where it already exists, do not expand threshold cookie parity in this release.

### Phase 1: Generic Exchange Service

- [x] Add pluggable OIDC/JWT verifier config in server core types/config.
- [x] Implement generic token verification (issuer, audience, JWKS signature, time claims).
- [x] Implement stable subject mapping (`sub -> userId`) in `AuthService`.
- [x] Mint `app_session_v1` with `appSessionVersion` via existing session adapter.
- [x] Add unit tests for verifier failure modes and claim mapping behavior.

### Phase 2: Session Routes Cutover

- [x] Add `POST /session/exchange` for `exchange.type=oidc_jwt`.
- [x] Add `GET /session/state` as canonical app-session read endpoint.
- [x] Add `POST /session/revoke` (initially user-scope via app-session-version rotation).
- [x] Keep `POST /session/refresh` unchanged.
- [x] Cut over Express and Cloudflare adapters in the same rollout.
- [x] Remove `/session/auth` and `/session/logout` after SDK/test cutover.

### Phase 3: Wallet Plane + SDK Naming

- [x] Add wallet routes: `POST /wallet/unlock/challenge`, `POST /wallet/unlock/verify`, `POST /wallet/lock`, `GET /wallet/state`.
- [x] Move passkey step-up semantics into wallet unlock flows.
- [x] Switch SDK default session issuance to `POST /session/exchange`.
- [x] Rename remaining wallet-state symbols to `unlock/lock`.
- [x] Remove `/auth/passkey/*` and `/auth/google/*` as primary session issuance paths.
- [x] Remove migration-only aliases and compat branches in same release.

### Phase 4: Warm Session Controls + Webhooks

- [x] Emit warm-session lifecycle events: `session.warm.created`, `session.warm.refreshed`.
- [x] Emit `session.warm.expired` for refresh unauthorized outcomes, invalid-session-version validation failures, and stale bearer/cookie parse failures.
- [x] Expand `session.warm.expired` passive coverage to stale bearer/cookie parse failures on guarded session routes.
- [x] Require stale-cookie passive expiry signals to match configured cookie name (`sessionCookieName`; default `tatchi-jwt`).
- [x] Optional future expansion assessed: no additional guarded app-session routes in this release; add emit points only when new guarded routes are introduced.
- [x] Emit relay lifecycle events: `session.revoked`, `wallet.unlocked`, `wallet.locked`, `session.exchange.failed`.
- [x] Add HMAC signature + timestamp headers for webhook delivery.
- [x] Add idempotent event IDs and replay-safe consumer guidance.
- [x] Add retry/backoff and dead-letter visibility guidance.
- [x] Add tenant/org scoping fields in webhook payload contract.

### Phase 5: Provider Guides

- [x] Publish Better Auth exchange guide.
- [x] Publish Auth0 exchange guide.
- [x] Publish Okta exchange guide.
- [x] Publish Google OIDC exchange guide.
- [x] Publish optional Clerk/Supabase/Firebase quickstarts on same contract.

### Phase 6: Follow-up Hardening (Post-Cutover)

- [x] Remove unsigned webhook signature fallback (`v1=fallback`) and fail closed when WebCrypto signing support is unavailable.
- [x] Ensure webhook delivery paths persist failed attempts/DLQ entries when signing cannot be performed.
- [x] Map OIDC exchange capability failures (`verifyOidcJwtExchange -> code=unsupported`) to `501`.
- [x] Return `invalid_session_version` (not generic `unauthorized`) from app-session-version validation mismatches so guarded-route expiry/webhook handling is deterministic.
- [x] Expand passive `session.warm.expired` emissions across all guarded app-session routes (`session/*`, `auth/*`, `/webauthn/authenticators`, `/near/public-keys`).
- [x] Freeze `session/exchange` response metadata contract (`session.expiresAt`: optional; only emitted when JWT `exp` is parseable) and align examples/tests.

### Validation and Cleanup Gate (Release Exit)

- [x] Integration: `session/exchange -> threshold bootstrap/session -> authorize/sign`.
- [x] Integration: revoke/lock invalidates future protected calls.
- [x] Integration: JWT + cookie transport for app sessions works in both adapters.
- [x] Regression: threshold Ed25519/ECDSA sign flows unchanged.
- [x] Regression: no fallback to removed legacy route names/symbols.
- [x] Webhook signatures are always HMAC (`v1=<hex>`); no unsigned fallback signature variants.
- [x] Final sweep: use unlock/lock vocabulary for wallet-state semantics in active docs and SDK surface.

### Phase 7: Session Exchange Dual-Mode (OIDC + Passkey Assertion)

- [x] Extend `POST /session/exchange` contract to accept `exchange.type=passkey_assertion` in addition to `oidc_jwt`.
- [x] Define request schema for passkey assertion exchange:
  - `exchange.challengeId` (required)
  - `exchange.webauthn_authentication` (required WebAuthn authentication payload)
  - optional `expected_origin` handling (header-derived default, explicit override policy documented)
- [x] Reuse existing challenge issuance route (`POST /wallet/unlock/challenge`) for passkey assertion exchange; do not add legacy alias routes.
- [x] Implement relay exchange handler branch for `passkey_assertion`:
  - verify assertion via existing `verifyWebAuthnLogin`
  - derive `userId`
  - mint `app_session_v1` (JWT/cookie by `sessionKind`)
  - preserve current `session.expiresAt` metadata contract behavior
- [x] Keep app-session minting canonical at `/session/exchange`; do not reintroduce app-session minting in `/auth/passkey/verify`.
- [x] Decide and lock webhook coupling policy for this flow:
  - always emit `session.warm.created`
  - emit `wallet.unlocked` from exchange path for `passkey_assertion` (with `challengeId` event id)
- [x] Add SDK support:
  - [x] extend `session.exchange` input union with `passkey_assertion`
  - [x] keep existing `oidc_jwt` behavior unchanged
  - [x] support one-step SDK flow: `wallet/unlock/challenge -> WebAuthn assertion -> session/exchange(passkey_assertion)`
  - [x] reject incomplete passkey assertion payloads with deterministic client errors
- [x] Add server unit tests:
  - passkey assertion success (`jwt` + `cookie`)
  - invalid/missing `challengeId`
  - invalid/missing `webauthn_authentication`
  - user-mismatch/verification-failure paths
  - webhook emission expectations
- [x] Add integration tests:
  - `wallet/unlock/challenge -> session/exchange(passkey_assertion) -> session/state -> threshold bootstrap/sign`
  - revoke/lock invalidation after passkey-assertion exchange
  - cookie-name matching (`SESSION_COOKIE_NAME`, default `tatchi-jwt`) remains enforced
- [x] Update docs and provider guides:
  - document dual exchange types under one canonical endpoint
  - include passkey-first quickstart sequence and payload examples
  - mark `auth/passkey/verify` as verification-only (no app-session minting)

## Testing Plan

### Unit

1. OIDC verifier failure modes (`iss`, `aud`, signature/JWKS, time claims).
2. Session exchange claim mapping and token minting.
3. Route guards for `app_session_v1` and threshold session claim kinds.
4. Revoke semantics (user-scope rotation and any per-session behavior).

### Integration

1. Exchange JWT -> app session -> threshold bootstrap/session -> authorize/sign happy path.
2. Revoke/lock behavior invalidates future protected calls.
3. Cookie and JWT transport behavior for app sessions.
4. Wallet unlock/lock route behavior and step-up checks.
5. Webhook signature verification and retry/dead-letter behavior.

### Regression

1. Existing threshold Ed25519/ECDSA sign flows remain unchanged under valid threshold session tokens.
2. Presign pool behavior remains unchanged.
3. No fallback to removed legacy route names/symbols.

## Acceptance Criteria

1. Customer backend can exchange external auth assertions via one `POST /session/exchange` contract.
2. Wallet state is represented as `locked/unlocked`.
3. Threshold signing claims and security invariants remain intact.
4. Warm session lifecycle can be controlled via HTTP and observed through signed webhooks.
5. No legacy auth-named wallet route/symbol aliases remain after cutover.
