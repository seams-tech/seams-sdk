# Auth Provider Integrations Plan

Date updated: March 1, 2026

## Objective

Make wallet embedding fit existing app-auth stacks by:

1. Separating app authentication from wallet state transitions.
2. Using wallet `unlock/lock` naming across APIs and docs.
3. Exposing wallet-server HTTP + webhook controls for JWT/HttpOnly warm sessions.
4. Shipping first-class integration guides for mainstream auth systems.

## Product Contract (Locked)

1. App auth is owned by the customer-developer's auth system (not by wallet runtime).
2. Wallet state is `locked`/`unlocked` (never app-auth semantics).
3. Core server auth integration is protocol-first (`OIDC/JWT`, optional `SAML`) instead of vendor-first.
4. Breaking changes are allowed. No legacy aliases, no dual naming, no deprecated symbols left behind.

## Current Baseline

Current relay/server already supports JWT + HttpOnly cookie session handling:

- `POST /auth/passkey/options`
- `POST /auth/passkey/verify`
- `POST /auth/google/options`
- `POST /auth/google/verify`
- `POST /session/exchange`
- `GET /session/state`
- `POST /session/refresh`
- `POST /session/revoke`
- `POST /wallet/unlock/challenge`
- `POST /wallet/unlock/verify`
- `POST /wallet/lock`
- `GET /wallet/state`

Current issue: `/auth/*` mixes app-auth provider workflows with wallet runtime concerns.
`POST /auth/passkey/verify` is verification-only and must not be used for app-session minting.

## Published Guides

1. Better Auth: [better-auth.md](./better-auth.md)
2. Auth0: [auth0.md](./walletAuth0.md)
3. Okta: [okta.md](./okta.md)
4. Google OIDC: [google-oidc.md](./google-oidc.md)
5. Clerk/Supabase/Firebase quickstarts: [quickstarts-clerk-supabase-firebase.md](./quickstarts-clerk-supabase-firebase.md)

## Target Architecture

Two explicit planes:

1. **App Auth Plane (customer-owned)**

- Customer app authenticates users via Auth0/Okta/Better Auth/Google/etc.
- Customer backend sends verified auth assertions to wallet server.

2. **Wallet Session + Unlock Plane (wallet-owned)**

- Wallet server mints/refreshes/revokes warm sessions (JWT or HttpOnly cookie).
- Wallet server manages wallet `lock/unlock` state and unlock step-up checks.
- Wallet server emits webhooks so customer backend can observe/control session lifecycle.

## API Refactor Plan (Breaking, No Legacy)

### A) Route and Naming Split

1. Remove provider-specific auth semantics from core route naming.
2. Replace legacy wallet-auth wording with unlock/lock terminology in:

- SDK public APIs
- server route names
- webhook event names
- docs and examples

3. Keep `session/*` as app-session transport, keep `wallet/*` as signing-state transport.

### B) Proposed Route Surface

App session exchange/control:

- `POST /session/exchange`
- `POST /session/refresh`
- `POST /session/revoke`
- `GET /session/state`

Wallet state control:

- `POST /wallet/unlock/challenge`
- `POST /wallet/unlock/verify`
- `POST /wallet/lock`
- `GET /wallet/state`

`POST /session/exchange` accepts verified auth assertions (ID token/JWT or backend-signed assertion), then returns:

- HttpOnly cookie session (`Set-Cookie`) or
- JWT body payload (`{ jwt: ... }`)
- Optional session metadata (`session.expiresAt`) only when JWT `exp` is parseable

based on `sessionKind`.

Supported exchange types:

1. `exchange.type=oidc_jwt` for BYO provider tokens/JWT assertions.
2. `exchange.type=passkey_assertion` for one-step passkey unlock + app-session mint
   (`/wallet/unlock/challenge -> WebAuthn assertion -> /session/exchange`).

### C) Legacy Cleanup Required in Same Release

1. Delete old route handlers and symbols that express legacy wallet auth semantics.
2. Delete old client API names that refer to legacy wallet auth naming.
3. Remove compatibility branches and feature flags created only for rename migration.
4. Update tests to new route + symbol names only.

## Warm Session Control (HTTP + Webhooks)

### HTTP Control Capabilities

1. Create warm session from customer-auth assertion (`/session/exchange`).
2. Refresh sliding session (`/session/refresh`).
3. Revoke specific session or all user sessions (`/session/revoke`).
4. Query session and wallet lock state (`/session/state`, `/wallet/state`).
5. Force wallet lock on risk events (`/wallet/lock`).

### Webhook Events

Emit signed events for customer backend orchestration:

- `session.warm.created`
- `session.warm.refreshed`
- `session.warm.expired`
- `session.revoked`
- `wallet.unlocked`
- `wallet.locked`
- `session.exchange.failed`

Webhook delivery requirements:

1. HMAC signature header + timestamp.
2. Idempotency/event IDs.
3. Retry with backoff + dead-letter visibility.
4. Strict tenant scoping in payload claims.

## Auth Provider Research and Integration Strategy

Protocol-first adapter priority:

1. OIDC/JWT verifier adapter (JWKS discovery, issuer/audience checks, clock skew controls).
2. Provider-specific glue only where needed (claims mapping, lock/revocation hooks).
3. SAML support as enterprise phase after OIDC/JWT baseline is complete.

### Priority Integration Matrix

| Provider                                  | Why it matters                                                                   | Integration mode                                                                            | Priority |
| ----------------------------------------- | -------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | -------- |
| Better Auth                               | Growing TS-first auth framework, supports OAuth/OIDC and passkey plugin model    | Exchange Better Auth-issued session/JWT into wallet warm session; ship reference middleware | P0       |
| Auth0                                     | Common B2B/B2C managed auth platform with OIDC + SAML support                    | OIDC ID token/JWT exchange + optional lock/revocation webhook bridge                        | P0       |
| Okta                                      | Enterprise SSO standard with strong OIDC posture and inbound federation patterns | OIDC token exchange + enterprise claim mapping (`groups`, org, domain)                      | P0       |
| Google (GIS / OIDC)                       | Frequent direct social/Workspace SSO source                                      | Google ID token exchange in customer backend, then wallet session exchange                  | P1       |
| Clerk / Supabase / Firebase Auth (guides) | Common dev-platform auth stacks in modern web apps                               | Reuse OIDC/JWT adapter path, provider-specific quickstart docs                              | P2       |

## Delivery Plan

### Phase 0: Spec Lock (1 week)

1. Finalize terminology and API contracts (`auth` vs `session` vs `wallet unlock`).
2. Freeze webhook event schema for warm session lifecycle.
3. Freeze claims contract for `session/exchange` input.

### Phase 1: Core Refactor (1-2 weeks)

1. Introduce `wallet/*` unlock/lock endpoints.
2. Introduce `session/exchange` and `session/revoke`.
3. Remove legacy route/symbol names in same PR sequence.
4. Update SDK naming and UI copy to lock/unlock vocabulary.

### Phase 2: Warm Session Controls + Observability (1 week)

1. Implement webhook events and delivery guarantees.
2. Add audit log events for session create/refresh/revoke/lock.
3. Add admin APIs for forced lock and session revocation.

### Phase 3: Provider Guides + Adapters (1-2 weeks)

1. Publish Better Auth integration guide and sample middleware. (done)
2. Publish Auth0 guide (OIDC + optional SAML enterprise notes). (done)
3. Publish Okta guide (OIDC + inbound federation mapping notes). (done)
4. Publish Google SSO guide (GIS -> backend token verify -> session exchange). (done)
5. Publish optional quickstarts for Clerk/Supabase/Firebase using same OIDC/JWT adapter. (done)

## Acceptance Criteria

1. Wallet actions in SDK/server/docs use `lock/unlock` terminology only.
2. Customer app can fully own login while still creating wallet warm sessions via HTTP APIs.
3. Session issuance works for both JWT and HttpOnly cookie transport through one exchange contract.
4. Customer backend can observe and control warm-session lifecycle through signed webhooks + revoke APIs.
5. Reference integrations are documented for Better Auth, Auth0, Okta, and Google SSO.
6. No legacy auth-named wallet routes/symbols remain after refactor lands.

## Source References (Provider Research)

- Better Auth OAuth concepts: https://www.better-auth.com/docs/concepts/oauth
- Better Auth other social/OIDC providers: https://www.better-auth.com/docs/authentication/other-social-providers
- Better Auth passkey plugin: https://www.better-auth.com/docs/plugins/passkey
- Auth0 OIDC protocol docs: https://auth0.com/docs/authenticate/protocols/openid-connect-protocol
- Auth0 SAML protocol docs: https://auth0.com/docs/authenticate/protocols/saml
- Okta OAuth/OIDC overview: https://developer.okta.com/docs/concepts/oauth-openid/
- Okta social login/inbound federation: https://developer.okta.com/docs/guides/social-login/-/main/
- Google OpenID Connect docs: https://developers.google.com/identity/openid-connect/openid-connect
- Clerk OAuth SSO guide: https://clerk.com/docs/advanced-usage/clerk-idp
- Supabase Auth overview: https://supabase.com/docs/guides/auth
- Firebase Auth overview: https://firebase.google.com/docs/auth/
