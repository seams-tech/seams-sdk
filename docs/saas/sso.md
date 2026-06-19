# Dashboard Google SSO Auth Reference

Date updated: March 6, 2026

## Canonical Reference

Use Google SSO as the dashboard login path:

1. Google sign-in -> ID token
2. `POST /session/exchange` with `exchange.type=oidc_jwt` and `exchange.provider=google`
3. relay issues `app_session_v1` cookie
4. dashboard bootstraps auth via `GET /console/session`

Dashboard Google SSO does not send `exchange.account_mode`. That field is reserved for the Google Email OTP wallet lane, where `register` and `login` select wallet registration/unlock behavior. Plain Google SSO is the console lane and must not resolve or create Email OTP wallet state.

This document is the canonical dashboard auth reference. Any dashboard auth behavior change must update this file in the same changeset.

## Constraints

- `POST /session/exchange` is the only app-session minting path.
- `POST /auth/google/verify` remains verification-only.
- Express and Cloudflare behavior must stay in parity.
- Legacy dashboard header-auth paths are removed.

## Implemented

- `/dashboard/login` Google sign-in flow reads the public Google client ID from relay `/auth/google/options`.
- Dashboard unauthenticated guard redirects to `/dashboard/login`.
- Dashboard sign-out calls `POST /session/revoke` and clears local dashboard state.
- Shared app-session console auth helper (`createAppSessionConsoleAuthAdapter`) is exported from both adaptors.
- Example Router API server uses shared app-session console auth.
- First-login SSO provisioning is implemented (org ensure, membership bootstrap, audit event).
- First-login SSO without a configured/default org creates a stable org context for the OIDC user, then bootstraps owner/admin membership so a fresh database can reach onboarding.
- Session-state UX distinguishes `401 unauthorized` vs `403 forbidden`.
- Shared auth output uses optional `projectId` / `environmentId` claims.

## Verification Coverage

- Relay OIDC exchange/session lifecycle parity (`/session/exchange`, `/session/revoke`, `/session/state`) in Express + Cloudflare.
- `/console/session` parity for success, revoke->401, no-membership->403, and first-login provisioning paths.
- OIDC failure mappings (`invalid_issuer`, `invalid_audience`, `expired`) to 401 in both adapters.
- Dashboard login wiring coverage for Google credential exchange and onboarding redirect.

## Configuration

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
- Canonical reference policy is active for dashboard auth changes.
