# Dashboard Onboarding + API Keys Plan

Date updated: March 3, 2026

## Objective

Build a first-run console flow that is demoable and production-oriented:

1. User creates a console account.
2. User completes onboarding steps: organization profile -> billing payment method -> first project (+ default Production environment).
3. User creates an API key from the API keys page.
4. User uses that API key to call gas-costing relay endpoints (starting with account creation/registration).

After that is stable, integrate Stripe checkout and billing management.

## Direct Answers To Current Questions

### 1) How does a user create an account?

Target flow:

- User signs up via dashboard auth (email/passkey and/or OIDC, depending on selected provider).
- Backend creates or loads a console user identity.
- Backend issues console session.
- User is redirected to onboarding wizard if they have no org membership.

### 2) How do they create an organization?

Target flow:

- In onboarding wizard, user enters org name (and optional slug/id) for their authenticated org context.
- Backend idempotently upserts org profile and ensures owner membership bootstrap.

### 3) How do they create a project?

Target flow:

- In onboarding wizard, project step runs only after billing is ready.
- Backend creates first project and default `prod`/`Production` environment together (idempotent).
- User can only create projects if they are `owner` or `admin`.

### 4) How do they create an API key?

Target flow:

- After onboarding completes, user is auto-handoffed to API keys page (with org/project/environment context) when no API key exists yet, then creates an environment-scoped API key.
- Secret is shown once and never returned again.
- Key is immediately usable against relay routes that require API key auth.

## Scope

In scope now:

- Explicit onboarding flow (account/session -> organization -> billing -> project + default environment).
- First API key creation immediately post-onboarding from API keys page (auto-handoff).
- API key lifecycle and enforcement on gas-costing relay routes.
- Dashboard UX for onboarding and API key management.
- Auditability and usage telemetry for API keys.

Out of scope for this slice:

- Advanced SSO enterprise provisioning.
- Full billing UX redesign.
- Stablecoin billing expansion details.

Follow-up phase in this doc:

- Stripe pricing -> checkout -> dashboard billing management integration.

## Current State And Gaps

Current implemented pieces:

- `GET /console/session` exists.
- `GET /console/org`, `GET/POST/PATCH /console/projects`, `GET/POST/PATCH /console/environments` exist.
- `GET/POST/DELETE /console/api-keys`, `POST /console/api-keys/:id/rotate` exist.
- Dashboard pages already call these APIs.

Gaps to close:

- Keep onboarding and API-key contracts aligned with implementation docs (step-based onboarding + post-onboarding API key creation).
- Complete remaining onboarding billing recovery UX for Stripe action-required/declined outcomes.

## Target Architecture

### A) Identity + Session Boundary

- Keep auth provider pluggable.
- Add explicit post-login onboarding state evaluation:
  - has user identity?
  - has org membership?
  - billing ready?
  - has at least one active project/environment?
- Route users to onboarding wizard until organization + billing + project/environment are complete.

### B) Explicit Tenancy Creation

- Replace implicit auto-bootstrap for org/project/environment with explicit create flows.
- Keep deterministic defaults only in local demo seeding scripts, not in core service read paths.

### C) API Key As Relay Access Control

- API key is a first-class credential for server-to-server and client-mediated gas-costing operations.
- Add relay middleware to:
  - authenticate key,
  - authorize by scope,
  - validate environment binding,
  - enforce optional IP allowlist,
  - record usage/anomaly signals,
  - emit audit and metering events.

### D) Separation Of Concerns

- Console module remains control-plane (onboarding, key management, billing controls).
- Relay module remains runtime execution-plane (registration/signing/session routes).
- Integration point is API key validation + usage recording.

## Proposed API Contract Changes

### Console Auth + Onboarding

- `GET /console/onboarding/state`
  - Returns current step status for authenticated user.
- `POST /console/onboarding/organization`
  - Idempotently upserts org profile and owner membership in current org context.
- `POST /console/onboarding/project`
  - Idempotently creates first project and default `prod` environment (billing required).

Request example:

```json
{
  "org": { "name": "Acme Wallets", "slug": "acme-wallets" },
  "project": { "name": "Consumer App", "id": "proj_consumer" },
  "environment": { "name": "Production", "id": "proj_consumer-prod" }
}
```

Response example:

```json
{
  "ok": true,
  "result": {
    "project": { "id": "proj_consumer" },
    "environment": { "id": "proj_consumer-prod" },
    "state": { "onboardingComplete": true }
  }
}
```

### API Key Management

Existing endpoints stay:

- `GET /console/api-keys`
- `POST /console/api-keys`
- `POST /console/api-keys/:id/rotate`
- `DELETE /console/api-keys/:id`

Additions:

- enforce mutation RBAC checks on create/rotate/revoke.
- enforce environment existence and org ownership on create.
- add optional expiry metadata in request/response (if needed).

### Relay Runtime Enforcement

Protect gas-costing endpoints first:

- `POST /registration/bootstrap` (first required target).

Header support:

- `Authorization: Bearer <api_key_secret>` primary.
- `X-API-Key: <api_key_secret>` optional compatibility.

Middleware behavior:

- Lookup by key prefix/id -> verify hash.
- Check `status === ACTIVE`.
- Validate environment scope against request target.
- Validate scope includes required action (`accounts.create` for `/registration/bootstrap`).
- Validate IP allowlist when configured.
- Record usage stats and update `lastUsedAt`.
- Emit structured reject reasons (`api_key_missing`, `api_key_invalid`, `api_key_forbidden_scope`, `api_key_ip_blocked`, `api_key_revoked`).

## Data Model / Persistence Plan

### Keep

- Existing `console_api_keys` table and core columns.

### Extend

- Add/standardize columns:
  - `created_by_user_id`
  - `revoked_by_user_id`
  - `revoked_reason`
  - `expires_at_ms` (nullable)
  - `secret_hash_algo` (explicit hash metadata)
  - `key_prefix` (indexable non-secret prefix for fast lookup)

- Add append-only table for auth attempts if needed:
  - `console_api_key_auth_events`
  - fields: `api_key_id`, `org_id`, `environment_id`, `route`, `outcome`, `reason_code`, `ip`, `created_at_ms`.

- Add onboarding operation table:
  - `console_onboarding_runs`
  - supports idempotency and resumable onboarding.

### Data Rules

- Secret is never persisted in plaintext.
- Key secret generated from cryptographically secure RNG only.
- Hashing uses strong one-way hash with server-side pepper.
- All key lookups and writes are tenant-scoped with RLS.

## RBAC Plan

Org/project/environment creation:

- create/update/archive project/environment: `owner` or `admin` (already aligned).

API key operations:

- create/rotate/revoke API keys:
  - `owner`, `admin` at org scope,
  - optionally `developer`/`ops` at project scope only for environments in that project.
- read/list API keys:
  - `owner`, `admin`, `security_admin`, and project-scoped roles within allowed project scope.

Audit requirements:

- emit audit events for key create/rotate/revoke with actor, scope, and reason.

## Phased Execution Queue (Dependency Order)

## Phase 0: Contract Lock + Legacy Cleanup

- [ ] Lock scope taxonomy for relay-protected actions:
  - `accounts.create`
  - `accounts.sync`
  - `webauthn.link`
  - `sessions.refresh`
- [ ] Lock onboarding API contracts and response payloads.
- [x] Remove implicit org/project/environment auto-bootstrap from core read paths.
- [ ] Keep demo data seeding only in explicit local seed code.
- [x] Add migration notes for existing local data.

Exit criteria:

- Contracts are stable and documented.
- Core services no longer auto-create tenancy on read.

Migration notes:

- Existing Postgres rows are preserved; no destructive migration is required for this slice.
- Fresh orgs no longer materialize on read (`GET /console/org`, `/console/projects`, `/console/environments`, `/console/wallets`).
- Local/dev upgrade path:
  - Run onboarding organization + project steps to create org/project/environment state.
  - Create first API key using `POST /console/api-keys` for the target environment.
  - Seed demo wallets explicitly (test fixtures or local seed scripts) instead of relying on read-time bootstrap side effects.

## Phase 1: Backend Onboarding Foundation

- [x] Add onboarding state service and endpoint (`GET /console/onboarding/state`).
- [x] Add idempotent onboarding organization endpoint (`POST /console/onboarding/organization`).
- [x] Add idempotent onboarding project endpoint (`POST /console/onboarding/project`).
- [x] Add ownership bootstrap (first user becomes org `owner`).
- [x] Add audit emission for each created resource.
- [x] Add Express + Cloudflare route parity tests.
- [x] Add Postgres persistence tests with tenant isolation checks.

Exit criteria:

- First-run setup can be completed via step-based onboarding.
- Duplicate retries do not create duplicate org/project/env rows.

## Phase 2: API Key Hardening And RBAC

- [x] Enforce RBAC on API key create/rotate/revoke routes.
- [x] Validate environment belongs to caller org before key create.
- [x] Move secret generation to CSPRNG-only implementation.
- [x] Add `key_prefix` fast lookup path and supporting indexes.
- [x] Add optional expiry support and revoke reason support.
- [x] Add audit events for API key lifecycle mutations.
- [x] Add route tests for RBAC forbidden cases and validation errors.

Exit criteria:

- API key mutations are permission-gated and auditable.
- Key material lifecycle is secure and deterministic.

## Phase 3: Relay API Key Enforcement (Gas-Costing Paths)

- [x] Implement relay API key auth middleware module.
- [x] Protect `POST /registration/bootstrap` with required scope `accounts.create`.
- [x] Bind API key environment scope to request context.
- [x] Enforce IP allowlist checks.
- [x] Record usage stats (`lastUsedAt`, per-endpoint counts).
- [x] Emit anomaly flags from middleware signals (high reject rates, unknown IP churn).
- [x] Emit usage/meter events suitable for billing linkage later.
- [x] Add Express + Cloudflare tests:
  - missing key,
  - invalid key,
  - revoked key,
  - scope denied,
  - allowlist denied,
  - success path.

Exit criteria:

- Registration endpoint cannot be called without valid scoped API key.
- Usage telemetry is populated from real traffic.

## Phase 4: Dashboard UX (Onboarding + API Keys)

- [x] Add `/dashboard/onboarding` wizard route and state machine.
- [x] Implement wizard steps:
  - account/session confirmation,
  - organization creation,
  - billing setup,
  - project creation (+ default environment).
- [x] Auto-redirect to onboarding when state is incomplete.
- [x] Upgrade API keys page with scope presets and safer copy UX.
- [x] Show post-create integration snippet for `/registration/bootstrap`.
- [x] Add frontend tests for wizard completion and failure recovery.

Exit criteria:

- New user can complete onboarding in one guided flow.
- User can create first API key immediately after onboarding using API keys page.

## Phase 5: Client/SDK Integration For Registration

- [x] Add SDK/client config support for relay API key.
- [x] Ensure registration bootstrap requests attach API key header.
- [x] Add typed errors for key auth failures and missing scope.
- [x] Add integration docs and curl examples.
- [x] Add e2e test: key created in dashboard -> used successfully by client registration call.

Exit criteria:

- Client registration path works end-to-end with API key auth.

SDK and curl integration examples:

SDK config:

```ts
const tatchi = new TatchiPasskey({
  relayer: {
    url: 'https://relay.example.com',
    apiKey: 'tsk_live_...',
  },
});
```

Relay request behavior:

- SDK sends `Authorization: Bearer <apiKey>` on `POST /registration/bootstrap` when `relayer.apiKey` is set.
- SDK registration failures now include `RegistrationResult.errorCode` for relay API key auth failures:
  - `api_key_missing`
  - `api_key_invalid`
  - `api_key_revoked`
  - `api_key_forbidden_scope`
  - `api_key_ip_blocked`
  - `api_key_environment_mismatch`

Direct curl:

```bash
curl -X POST "https://relay.example.com/registration/bootstrap" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer tsk_live_..." \
  -d '{
    "new_account_id": "alice.w3a-relayer.testnet",
    "device_number": 1,
    "rp_id": "wallet.example.com",
    "webauthn_registration": {
      "id": "cred_1",
      "rawId": "raw_1",
      "type": "public-key",
      "response": {
        "clientDataJSON": "base64url...",
        "attestationObject": "base64url...",
        "transports": ["internal"]
      },
      "clientExtensionResults": { "prf": { "results": {} } }
    }
  }'
```

## Phase 6: Stripe Integration (After Onboarding/API Keys)

- [x] Add pricing page CTA wiring to `POST /console/billing/stripe/checkout-session`.
- [x] Implement success/cancel dashboard return handling.
- [x] Add subscription status panel in dashboard billing.
- [x] Wire customer portal entry to `POST /console/billing/stripe/customer-portal-session`.
- [x] Ensure Stripe webhook idempotency and reconciliation paths are covered.
- [x] Add e2e flow: pricing -> checkout -> return -> billing status reflected.

Exit criteria:

- Self-serve billing entry flow is live after onboarding/API key foundation.

## Testing Matrix

- Unit tests:
  - scope matching,
  - key hash verify,
  - allowlist checks,
  - onboarding idempotency logic.
- Service tests:
  - org/project/environment creation invariants,
  - API key lifecycle and RBAC.
- Router tests:
  - Express + Cloudflare parity for onboarding and key routes.
- Postgres tests:
  - tenant isolation,
  - migration compatibility,
  - index-backed key lookup behavior.
- E2E tests:
  - dashboard onboarding happy path,
  - dashboard onboarding retry/resume,
  - created key usable on registration endpoint.

## Acceptance Criteria

- New user can sign in and complete onboarding without manual DB seeding.
- Organization creation is explicit and auditable.
- Project/environment hierarchy is explicit and validated.
- API key secret is shown once, then never retrievable.
- Relay registration endpoint requires valid API key with correct scope.
- API key usage telemetry is populated from real auth middleware.
- Dashboard provides a copy-paste integration example that works.
- Stripe integration is layered in only after onboarding + API key flow is stable.

## Implementation Notes

- Keep runtime and console domains separated by module boundaries.
- Keep schema/user isolation between signer DB domain and console DB domain.
- Do not introduce legacy fallback behavior for implicit tenancy creation; cut over cleanly.
- Prefer additive migrations with deterministic backfill, then remove old code paths immediately after cutover.
