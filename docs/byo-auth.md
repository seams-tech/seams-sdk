# BYO Auth Integration Plan

Date updated: February 26, 2026

## Objective

Let customer-developers keep their existing auth stack while using our embedded wallet and threshold signing stack.

Core outcomes:

1. App auth remains customer-owned.
2. Wallet state is modeled as `locked`/`unlocked` (not logged in/out).
3. Wallet server exposes HTTP + webhook controls for warm session lifecycle.
4. No legacy aliasing or duplicate auth/login codepaths after refactor.

## Locked Product Decisions

1. `Auth` and `wallet unlock` are separate planes.
2. `OIDC/JWT` is the primary integration contract for external auth.
3. Breaking changes are allowed; legacy route/symbol compatibility is not retained.
4. Threshold signing session model (`threshold_*_session_v1`) remains explicit and separate from app session model (`app_session_v1`).

## Current Architecture Fit (Why This Works)

The current architecture already separates app sessions and threshold signing sessions:

- App session validation is strict to `kind=app_session_v1` in `session/*`.
- Threshold routes validate `threshold_ed25519_session_v1` / `threshold_ecdsa_session_v1` claims separately.
- Threshold bootstrap/session endpoints mint dedicated threshold session tokens with TTL + participant binding.

This means BYO auth can slot in primarily at app session issuance time (`session/exchange`) without redesigning threshold signing internals.

## Current Gaps

1. SDK login flow defaults to passkey auth endpoints (`/auth/passkey/options|verify`) instead of a generic BYO exchange contract.
2. Naming mixes app auth and wallet behavior in places (`login`, `logout` language).
3. Registration/bootstrap paths currently enforce `threshold_*.session_kind=jwt`; cookie-mode support for threshold sessions is not symmetric.
4. Warm session lifecycle control (revoke/force-lock/webhooks) is not yet exposed as a cohesive API surface.

## Target Architecture

Two explicit planes:

1. **App Auth Plane (customer-owned)**

- Customer authenticates via Auth0/Okta/Better Auth/Google/etc.
- Customer backend verifies provider token.
- Customer backend calls wallet server `POST /session/exchange` with a verified assertion/token.
- Wallet server returns app session as JWT or HttpOnly cookie.

2. **Wallet Unlock + Signing Plane (wallet-owned)**

- Wallet unlock uses dedicated unlock endpoints and passkey step-up.
- Threshold signing routes continue using threshold-scoped session tokens and policies.
- Wallet server emits lifecycle webhooks for audit and orchestration.

## API Plan (Breaking, No Legacy)

### Session Plane

- `POST /session/exchange`
- `POST /session/refresh`
- `POST /session/revoke`
- `GET /session/state`

### Wallet Plane

- `POST /wallet/unlock/options`
- `POST /wallet/unlock/verify`
- `POST /wallet/lock`
- `GET /wallet/state`

### Legacy Removal in Same Release

1. Remove old provider-auth route names from default runtime path (`/auth/passkey/*`, `/auth/google/*` as primary login path).
2. Remove SDK/API wording and symbols that equate wallet unlock with app login.
3. Remove fallback/compat flags added only for naming migration.
4. Keep one canonical route/symbol set post-cutover.

## `POST /session/exchange` Contract (Proposed)

Request:

```json
{
  "sessionKind": "jwt",
  "exchange": {
    "type": "oidc_jwt",
    "token": "eyJ..."
  }
}
```

Response (`sessionKind=jwt`):

```json
{
  "ok": true,
  "session": {
    "kind": "app_session_v1",
    "userId": "user_123",
    "expiresAt": "2026-02-26T19:30:00.000Z"
  },
  "jwt": "eyJ..."
}
```

Response (`sessionKind=cookie`):

- `Set-Cookie: <HttpOnly app session cookie>`
- body omits `jwt`.

Validation requirements:

1. `iss` + `aud` allowlist checks.
2. JWKS signature verification.
3. Stable subject mapping (`sub` -> internal user id).
4. Clock skew checks (`iat`, `nbf`, `exp`).
5. Optional replay protection (`jti`) for short-lived exchange tokens.

## Threshold Session Compatibility Plan

1. Keep `threshold-ed25519` and `threshold-ecdsa` session claim schema unchanged.
2. Keep current threshold policy constraints (TTL, remainingUses, participantIds, relayerKeyId scope).
3. Ensure app session from `session/exchange` can call threshold bootstrap/session endpoints exactly as current app sessions do.
4. Decide and lock threshold transport policy:

- Option A: keep threshold sessions JWT-only for now (current behavior in registration/bootstrap paths).
- Option B: add complete cookie parity for threshold sessions.

## Warm Session Control and Webhooks

### HTTP Controls

1. Revoke active warm sessions by user/session id (`/session/revoke`).
2. Force wallet lock (`/wallet/lock`).
3. Query session + wallet state (`/session/state`, `/wallet/state`).

### Webhook Events

- `session.warm.created`
- `session.warm.refreshed`
- `session.warm.expired`
- `session.revoked`
- `wallet.unlocked`
- `wallet.locked`
- `session.exchange.failed`

Delivery requirements:

1. HMAC signature + timestamp.
2. Idempotent event ids.
3. Retry/backoff + dead-letter visibility.
4. Tenant/org scoping in payload.

## Implementation Phases

### Phase 0: Spec Lock

1. Freeze `session/exchange` request/response schema.
2. Freeze claim mapping contract (`sub`, org/project/env roles, optional provider fields).
3. Freeze wallet lock/unlock terminology and route names.

### Phase 1: Server Exchange Path

1. Add `session/exchange` handler (Express + Cloudflare adapters).
2. Add pluggable OIDC/JWT verifier adapter (JWKS-based).
3. Mint `app_session_v1` from exchange result via existing SessionAdapter.
4. Add `session/revoke` + `session/state`.

### Phase 2: SDK and Router Refactor

1. Update client login/session API to use `session/exchange` default path.
2. Split wallet unlock methods from app login APIs.
3. Rename user-facing and SDK internal symbols from login/logout to lock/unlock where wallet state is intended.
4. Remove legacy `/auth/*`-as-primary-login codepaths.

### Phase 3: Warm Session Controls

1. Implement force-lock + revoke orchestration.
2. Emit webhook events with signature and retry semantics.
3. Add audit logs for exchange/refresh/revoke/unlock/lock flows.

### Phase 4: Provider Guides

1. Better Auth guide (OIDC/JWT exchange).
2. Auth0 guide.
3. Okta guide.
4. Google OIDC guide.
5. Optional quickstarts for Clerk/Supabase/Firebase on same exchange contract.

## First Steps (Execution Order)

1. Lock contracts and naming in one short spec PR.

- Freeze `POST /session/exchange` schema (request, JWT response, cookie response).
- Freeze claim mapping (`iss`, `aud`, `sub`, optional org/role claims).
- Freeze route vocabulary: app auth in `session/*`, wallet state in `wallet/*`, no `login/logout` naming for wallet state.

2. Ship a minimal vertical slice for BYO auth exchange.

- Implement `POST /session/exchange` for `exchange.type=oidc_jwt`.
- Verify JWKS signature, issuer/audience, time claims, and map `sub -> userId`.
- Mint `app_session_v1` through existing SessionAdapter.
- Add unit tests for verifier failure modes and mapping behavior.

3. Prove compatibility with current signing-session architecture.

- Add integration test: `session/exchange -> threshold bootstrap/session -> authorize/sign`.
- Confirm threshold claim kinds and policy (`ttlMs`, `remainingUses`, participant binding) are unchanged.
- Fail closed on invalid app session or invalid threshold session.

4. Cut over SDK/API naming and routes in the same sequence.

- Switch default client session creation path to `session/exchange`.
- Rename wallet state methods/symbols to `unlock/lock`.
- Remove old `/auth/*` as primary login paths and remove old wallet login/logout symbols in the same rollout (no compatibility aliases).

5. Add baseline lifecycle controls.

- Implement `POST /session/revoke` and `GET /session/state`.
- Implement `POST /wallet/lock` and `GET /wallet/state`.
- Emit initial signed webhooks for `session.warm.created`, `session.revoked`, `wallet.unlocked`, `wallet.locked`.

## Testing Plan

### Unit

1. OIDC token verifier: issuer/audience/JWKS/expiry failure modes.
2. Session exchange claim mapping and token minting.
3. Route guards for `app_session_v1` and threshold session claim kinds.

### Integration

1. Exchange JWT -> app session -> threshold bootstrap/session -> authorize/sign happy path.
2. Revoke/lock behavior invalidates future protected calls.
3. Cookie and JWT session transport paths for app session.
4. Webhook signature and retry/dead-letter behavior.

### Regression

1. Existing threshold ECDSA/Ed25519 sign flows unchanged under valid threshold session tokens.
2. Presign pool flow remains unchanged.
3. No fallback to removed legacy route names.

## Acceptance Criteria

1. Customer can keep existing auth provider and create wallet app sessions through one `session/exchange` contract.
2. Wallet signing/unlock behavior is semantically separate from app login.
3. Threshold signing claims and security invariants remain intact.
4. Warm session lifecycle can be controlled via HTTP and observed via signed webhooks.
5. No legacy login-named route/symbol aliases remain after cutover.
