# Dashboard Google SSO Login Plan

Date updated: March 5, 2026

## Objective

Use Google SSO as the dashboard login path:

1. Google sign-in -> ID token
2. `POST /session/exchange` with `exchange.type=oidc_jwt`
3. relay issues `app_session_v1` cookie
4. dashboard bootstraps auth via `GET /console/session`

## Constraints

- `POST /session/exchange` is the only app-session minting path.
- `POST /auth/google/verify` remains verification-only.
- Express and Cloudflare behavior must stay in parity.
- Legacy dashboard header-auth paths are removed.

## Implemented

- `/dashboard/login` Google sign-in flow is wired with `VITE_GOOGLE_OIDC_CLIENT_ID`.
- Dashboard unauthenticated guard redirects to `/dashboard/login`.
- Dashboard sign-out calls `POST /session/revoke` and clears local dashboard state.
- Shared app-session console auth helper (`createAppSessionConsoleAuthAdapter`) is exported from both adaptors.
- Example relay server uses shared app-session console auth.
- First-login SSO provisioning is implemented (org ensure, membership bootstrap, audit event).
- Session-state UX distinguishes `401 unauthorized` vs `403 forbidden`.
- Shared auth output uses optional `projectId` / `environmentId` claims.

## Verification Coverage

- Relay OIDC exchange/session lifecycle parity (`/session/exchange`, `/session/revoke`, `/session/state`) in Express + Cloudflare.
- `/console/session` parity for success, revoke->401, no-membership->403, and first-login provisioning paths.
- OIDC failure mappings (`invalid_issuer`, `invalid_audience`, `expired`) to 401 in both adapters.
- Dashboard login wiring coverage for Google credential exchange and onboarding redirect.

## Configuration

Frontend:

- `VITE_GOOGLE_OIDC_CLIENT_ID`

Server:

- `GOOGLE_OIDC_CLIENT_ID` or `GOOGLE_OIDC_CLIENT_IDS`
- optional `GOOGLE_OIDC_HOSTED_DOMAINS`

## Definition of Done

- Google SSO is the default dashboard login path.
- Dashboard runtime does not depend on header-injected console identity.
- `/console/session` is app-session backed in Express + Cloudflare.
- New Google users can authenticate and reach onboarding without manual DB seeding.

## Status

- Requested Google SSO dashboard integration scope is complete.

## Next Steps

1. Merge the SSO changeset.
2. Keep this document as the canonical auth flow reference for dashboard work.
