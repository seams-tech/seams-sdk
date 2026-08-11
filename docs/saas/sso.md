# Dashboard SSO Auth Reference

Date updated: August 11, 2026

## Canonical Reference

The dashboard offers Google OIDC and GitHub OAuth:

1. Google sign-in returns an ID token. GitHub OAuth returns a short-lived authorization code to `/dashboard/login`.
2. The dashboard posts the credential to `/session/exchange` using `exchange.type=oidc_jwt` with `exchange.provider=google`, or `exchange.type=github_oauth_code`.
3. The relay verifies the Google token or exchanges the GitHub code using the server-side OAuth App secret.
4. The relay issues the `app_session_v1` cookie and the dashboard bootstraps auth through `GET /console/session`.

Dashboard Google SSO does not send `exchange.account_mode`. That field is reserved for the Google Email OTP wallet lane, where `register` and `login` select wallet registration/unlock behavior. Plain Google SSO is the console lane and must not resolve or create Email OTP wallet state.

This document is the canonical dashboard auth reference. Any dashboard auth behavior change must update this file in the same changeset.

## Constraints

- `POST /session/exchange` is the only app-session minting path.
- `POST /auth/google/verify` remains verification-only.
- GitHub access tokens remain inside the relay and are never returned to the dashboard or persisted.
- Express and Cloudflare behavior must stay in parity.
- Legacy dashboard header-auth paths are removed.

## Implemented

- `/dashboard/login` Google sign-in flow reads the public Google client ID from relay `/auth/google/options`.
- `/dashboard/login` GitHub sign-in flow reads the public OAuth App client ID and callback URL from relay `/auth/github/options`.
- GitHub OAuth callback state is generated and verified in the browser before its authorization code is exchanged.
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
- Dashboard login wiring coverage for Google and GitHub credential exchange and onboarding redirect.

## Configuration

Server:

- `GOOGLE_OIDC_CLIENT_ID` or `GOOGLE_OIDC_CLIENT_IDS`
- optional `GOOGLE_OIDC_HOSTED_DOMAINS`
- `GITHUB_OAUTH_CLIENT_ID`, `GITHUB_OAUTH_CLIENT_SECRET`, and `GITHUB_OAUTH_CALLBACK_URL`
- Cross-site deployments must issue the app-session cookie with `HttpOnly`,
  `Secure`, and `SameSite=None`. The Cloudflare gateway adapter applies this
  policy because the dashboard and gateway use different sites in production.

## Definition of Done

- Google and GitHub are the dashboard login providers.
- Dashboard runtime does not depend on header-injected console identity.
- `/console/session` is app-session backed in Express + Cloudflare.
- New Google users can authenticate and reach onboarding without manual DB seeding.

## Status

- Requested Google and GitHub dashboard SSO integration scope is complete.
- Canonical reference policy is active for dashboard auth changes.
