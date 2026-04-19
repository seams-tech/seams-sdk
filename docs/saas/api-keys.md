# Dashboard Onboarding + API Keys Plan

Date updated: March 7, 2026

## Objective

Build a first-run console flow that is demoable and production-oriented:

1. User creates a console account.
2. User completes onboarding steps: organization profile -> fund prepaid balance -> first project (+ default Production environment).
3. User provisions an integration credential from the API keys page.
4. User uses either:
   - a `secret_key` from their backend for server-mediated registration, or
   - a `publishable_key` from the frontend for managed registration bootstrap.

Stripe billing is an independent account-eligibility track:

- it determines whether an org/environment is allowed to provision or keep active credentials
- it does not change the registration auth mode:
  - `secret_key`
  - `publishable_key`
  - x402-paid managed grant acquisition

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

### 4) How do they create a credential?

Target flow:

- After onboarding completes, user is auto-handoffed to API keys page (with org/project/environment context) when no credential exists yet.
- User chooses one of two integration modes:
  - `secret_key` for server-based registration.
  - `publishable_key` for frontend-only managed registration.
- `secret_key` is shown once and never returned again.
- `publishable_key` is browser-safe and paired with origin restrictions plus managed rate limiting.

### 5) Do we allow x402-based one-time scoped calls?

Target answer:

- Yes, but only as an optional paid grant-acquisition lane on top of `publishable_key` mode.
- x402 is not a third long-lived credential type.
- The paid flow should mint a single-use, short-TTL `bootstrap_token` after payment succeeds.
- Relay continues to accept only:
  - `secret_key`, or
  - `bootstrap_token`.
- Relay must never accept `publishable_key` directly as a privileged credential.

## Canonical Credential Terminology

- `secret_key`
  - server-only credential
  - used by developer backend services to call privileged relay/bootstrap routes
  - must never be stored in frontend config or shipped in browser bundles
- `publishable_key`
  - browser-safe credential
  - identifies project/environment to a Tatchi-managed bootstrap broker
  - cannot directly authorize privileged relay calls on its own
- This doc uses explicit key types instead of the generic phrase "API key".
- There is no supported long-lived browser-held secret for registration.

## Non-Negotiable Constraints

- There are exactly two long-lived credential kinds in product and code:
  - `secret_key`
  - `publishable_key`
- `bootstrap_token` is not a key. It is a short-lived, single-use bearer grant minted by the managed broker.
- Browser SDKs must never accept `secret_key`.
- Public docs, dashboard copy, SDK config, and runtime errors must stop using the generic browser-facing term `apiKey`.
- `Authorization: Bearer <credential>` is the only supported auth transport for new work.
- Do not support alternate auth headers.
- Breaking changes are acceptable. Replace ambiguous symbols immediately rather than preserving them.

## Supported Integration Modes

### Mode A: `secret_key` (Developer Backend)

Request path:

1. Browser collects registration material.
2. Browser sends registration payload to the developer backend.
3. Developer backend adds `Authorization: Bearer <secret_key>`.
4. Developer backend calls relay `POST /registration/bootstrap`.

Properties:

- Requires developer-hosted backend.
- Supports self-hosted relay.
- Supports custom signup policy, tenant gating, invite flows, and private abuse controls.
- `secret_key` may carry scopes, expiry, and IP allowlist.

### Mode B: `publishable_key` (Managed Browser Flow)

Request path:

1. Browser collects registration material and computes a request hash for the exact relay payload.
2. Browser calls managed broker with `Authorization: Bearer <publishable_key>`.
3. Broker validates origin, project/environment status, quotas, and risk policy.
4. Broker returns a single-use short-lived `bootstrap_token`.
5. Browser calls relay `POST /registration/bootstrap` with `Authorization: Bearer <bootstrap_token>`.

Properties:

- No developer backend required.
- Requires Tatchi-managed broker infrastructure.
- `publishable_key` never authorizes direct relay access.
- Origin restrictions and quotas are enforced before relay bootstrap is reachable.

### Optional Lane: x402-Paid Grant Acquisition

Request path:

1. Browser calls the same managed broker endpoint with `publishable_key`.
2. If free quota is exhausted or the project requires payment, broker returns HTTP `402 Payment Required`.
3. Broker sends payment requirements in the `PAYMENT-REQUIRED` header.
4. Client retries with `PAYMENT-SIGNATURE` after settlement preparation.
5. Broker validates payment and returns the same `bootstrap_token` shape used in free managed mode.

Properties:

- Not a third credential kind.
- Best for anonymous usage, overage handling, or agentic pay-per-call access.
- Payment buys a one-time grant, not direct privileged relay access.

## Credential And Token Model

### `secret_key`

- Holder: developer backend only.
- Current prefix in code: `sk_`.
- Credential format: opaque random token body; org and key ids are not embedded.
- Direct relay authorization: yes.
- Metadata:
  - `kind = secret_key`
  - `environment_id`
  - `scopes[]`
  - `ip_allowlist[]`
  - `expires_at`
  - `secret_version`
  - `status`
- Storage:
  - store only hash + preview + lookup prefix
  - never return full value after create/rotate response

### `publishable_key`

- Holder: browser-safe frontend config.
- Target prefix: `pk_`.
- Credential format: opaque random token body; org and key ids are not embedded.
- Direct relay authorization: no.
- Metadata:
  - `kind = publishable_key`
  - `environment_id`
  - `allowed_origins[]`
  - `rate_limit_bucket`
  - `quota_bucket`
  - `risk_policy`
  - `payment_policy`
  - `status`
- Storage:
  - treat as a credential that still needs hashing and rotation
  - allow full value to be displayed at creation/rotation time only, same as `secret_key`

### `bootstrap_token`

- Holder: browser, short-lived.
- Target prefix: `tbt_v1_`.
- Direct relay authorization: yes, but only for a single bound request.
- Not managed from the API keys UI directly.
- Target persisted fields:
  - `id`
  - `publishable_key_id`
  - `project_id`
  - `environment_id`
  - `origin`
  - `method = POST`
  - `path = /registration/bootstrap`
  - `request_hash_sha256`
  - `status = issued | redeemed | expired | canceled`
  - `issued_at`
  - `expires_at`
  - `redeemed_at`
  - `max_uses = 1`
  - `payment_reference` (nullable)
  - `risk_decision` (nullable)
- Default TTL target:
  - issue at `60s`
  - hard maximum `5m`

## Normalization Rules

- Origin matching is exact on normalized `scheme://host[:port]`.
- `https://localhost` and `https://localhost:3600` are distinct origins.
- `localhost` and `example.localhost` are distinct origins.
- Allowed origin matching must not use wildcard suffix rules in v1.
- Request-hash binding must be computed from a canonical JSON serialization of the exact relay request body.
- Environment binding must be explicit on the credential record; do not infer from org-only scope.

## Scope

In scope now:

- Explicit onboarding flow (account/session -> organization -> billing -> project + default environment).
- First credential creation immediately post-onboarding from API keys page (auto-handoff).
- Credential lifecycle and enforcement on gas-costing relay routes.
- Dashboard UX for onboarding and credential management.
- Auditability and usage telemetry for credentials.

Out of scope for this slice:

- Advanced SSO enterprise provisioning.
- Full billing UX redesign.
- Stablecoin billing expansion details.

Parallel billing phase in this doc:

- Stripe pricing -> checkout -> dashboard billing management integration.

## Current State And Gaps

Current implemented pieces:

- `GET /console/session` exists.
- `GET /console/org`, `GET/POST/PATCH /console/projects`, `GET/POST/PATCH /console/environments` exist.
- `GET/POST/DELETE /console/api-keys`, `POST /console/api-keys/:id/rotate` exist.
- Dashboard pages already call these APIs.

Gaps to close:

- Keep onboarding and credential contracts aligned with implementation docs (step-based onboarding + post-onboarding credential creation).
- Complete remaining onboarding billing recovery UX for Stripe action-required/declined outcomes.
- Replace generic `apiKey` terminology in SDK/runtime/browser docs with `secret_key` or `publishable_key`.
- Delete browser-side `configs.network.relayer.apiKey`.
- Support only `Authorization: Bearer`.
- Add managed broker + bootstrap token path; today relay auth is only `secret_key`-based.

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

### C) Credential And Billing Eligibility

- Billing state determines whether an org/environment may create or keep active credentials.
- Billing state does not determine which auth mode the integration uses.
- Auth mode remains one of:
  - `secret_key`
  - `publishable_key` -> `bootstrap_token`
  - optional x402-paid broker issuance of `bootstrap_token`

- `secret_key` is the first-class credential for direct privileged relay access.
- `publishable_key` is the browser-safe identifier used to obtain a short-lived managed bootstrap token.
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
- Integration point is credential validation + usage recording.

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

### Credential Management (`/console/api-keys`)

Existing endpoints stay:

- `GET /console/api-keys`
- `POST /console/api-keys`
- `POST /console/api-keys/:id/rotate`
- `DELETE /console/api-keys/:id`

Additions:

- enforce mutation RBAC checks on create/rotate/revoke.
- enforce environment existence and org ownership on create.
- enforce billing eligibility before create/rotate/reactivate when billing is required for the target environment.
- make `kind` required on create/list/rotate responses.
- split request shapes by `kind`:
  - `secret_key`
    - `name`
    - `environmentId`
    - `scopes[]`
    - `ipAllowlist[]`
    - `expiresAt?`
  - `publishable_key`
    - `name`
    - `environmentId`
    - `allowedOrigins[]`
    - `rateLimitBucket`
    - `quotaBucket`
    - `riskPolicy`
    - `paymentPolicy`
    - `expiresAt?`
- stop returning fields that do not apply to the selected kind:
  - `publishable_key` should not expose `scopes` or `ipAllowlist`
  - `secret_key` should not expose `allowedOrigins` or broker-only policy fields

Create request examples:

```json
{
  "kind": "secret_key",
  "name": "Next.js backend",
  "environmentId": "env_prod",
  "scopes": ["accounts.create", "wallets.read"],
  "ipAllowlist": ["203.0.113.10/32"],
  "expiresAt": null
}
```

```json
{
  "kind": "publishable_key",
  "name": "Consumer web app",
  "environmentId": "env_prod",
  "allowedOrigins": ["https://app.example.com"],
  "rateLimitBucket": "default_web_v1",
  "quotaBucket": "free_registrations_v1",
  "riskPolicy": { "captcha": "adaptive" },
  "paymentPolicy": { "mode": "quota_then_x402", "productId": "wallet_registration_v1" },
  "expiresAt": null
}
```

Create response example:

```json
{
  "ok": true,
  "key": {
    "id": "key_abc123",
    "kind": "publishable_key",
    "environmentId": "env_prod",
    "name": "Consumer web app",
    "status": "ACTIVE",
    "allowedOrigins": ["https://app.example.com"],
    "rateLimitBucket": "default_web_v1",
    "quotaBucket": "free_registrations_v1",
    "riskPolicy": { "captcha": "adaptive" },
    "paymentPolicy": { "mode": "quota_then_x402", "productId": "wallet_registration_v1" },
    "createdAt": "2026-03-07T00:00:00.000Z",
    "updatedAt": "2026-03-07T00:00:00.000Z",
    "lastUsedAt": null,
    "expiresAt": null
  },
  "credential": "pk_..."
}
```

### Managed Broker Endpoints

Add new public broker surface:

- `POST /v1/registration/bootstrap-grants`

Auth:

- `Authorization: Bearer <publishable_key>`

Request body:

```json
{
  "environmentId": "env_prod",
  "newAccountId": "alice.w3a-relayer.testnet",
  "rpId": "app.example.com",
  "requestHashSha256": "base64url(sha256(canonicalRelayJson))",
  "clientContext": {
    "sdk": "web",
    "sdkVersion": "0.0.0-dev",
    "userAgentHint": "optional"
  }
}
```

Response on free success:

```json
{
  "ok": true,
  "grant": {
    "token": "tbt_v1_...",
    "expiresAt": "2026-03-07T00:01:00.000Z",
    "environmentId": "env_prod",
    "origin": "https://app.example.com",
    "mode": "free"
  }
}
```

Response when payment is required:

- HTTP `402 Payment Required`
- `PAYMENT-REQUIRED` header populated per x402 flow
- JSON body still includes machine-readable denial reason:

```json
{
  "ok": false,
  "code": "payment_required",
  "message": "Project quota exceeded; payment required for bootstrap grant",
  "payment": {
    "mode": "x402",
    "productId": "wallet_registration_v1"
  }
}
```

Retry after payment:

- same endpoint
- same request body
- `PAYMENT-SIGNATURE` header added
- broker settles payment and returns the same success shape with `mode: "paid"`

### Relay Runtime Enforcement

Protect gas-costing endpoints first:

- `POST /registration/bootstrap` (first required target).

Auth transport:

- `Authorization: Bearer <secret_key | bootstrap_token>`

Middleware behavior:

- Detect credential kind from prefix.
- `secret_key` path:
  - lookup by key prefix/id -> verify hash
  - check `status === ACTIVE`
  - validate scope includes required action (`accounts.create` for `/registration/bootstrap`)
  - validate scope includes required action (`wallets.read` for `GET /v1/wallets*`)
  - validate environment binding
  - validate IP allowlist when configured
- `bootstrap_token` path:
  - lookup by token prefix/id -> verify hash
  - check `status === issued`
  - validate `expires_at > now`
  - validate method/path match exactly
  - validate environment binding
  - validate exact normalized origin
  - validate exact `request_hash_sha256` against canonical request body
  - atomically mark token `redeemed` before invoking expensive write path
- Record usage stats and update `lastUsedAt`.
- Emit structured reject reasons with credential-specific codes:
  - `secret_key_missing`
  - `secret_key_invalid`
  - `secret_key_revoked`
  - `secret_key_forbidden_scope`
  - `secret_key_ip_blocked`
  - `secret_key_environment_mismatch`
  - `bootstrap_token_missing`
  - `bootstrap_token_invalid`
  - `bootstrap_token_expired`
  - `bootstrap_token_already_used`
  - `bootstrap_token_request_mismatch`
  - `bootstrap_token_origin_mismatch`

Broker-only deny codes for `POST /v1/registration/bootstrap-grants`:

- `publishable_key_missing`
- `publishable_key_invalid`
- `publishable_key_revoked`
- `publishable_key_origin_blocked`
- `publishable_key_rate_limited`
- `publishable_key_quota_exhausted`
- `payment_required`
- `payment_invalid`

### SDK Configuration Target

Target browser/server configuration split:

```ts
type RegistrationAuthMode =
  | {
      mode: 'backend_proxy';
      registrationBootstrapUrl: string;
    }
  | {
      mode: 'managed';
      environmentId: string;
      publishableKey: string;
      paymentMode?: 'disabled' | 'quota_then_x402' | 'always_x402';
    };
```

Rules:

- Browser SDK accepts only `backend_proxy` or `managed`.
- Browser SDK rejects `secretKey`, `apiKey`, and `relayer.apiKey`.
- Server examples use:
  - `TATCHI_SECRET_KEY`
- Browser examples use:
  - `VITE_TATCHI_PUBLISHABLE_KEY`
- Relay runtime can still be called directly from a trusted backend with `secret_key`.

## Data Model / Persistence Plan

### Keep

- Existing `console_api_keys` table and core columns.

### Extend

- Add/standardize columns:
  - `kind`
  - `created_by_user_id`
  - `revoked_by_user_id`
  - `revoked_reason`
  - `expires_at_ms` (nullable)
  - `secret_hash_algo` (explicit hash metadata)
  - `key_prefix` (indexable non-secret prefix for fast lookup)
  - `allowed_origins_json` (for `publishable_key`)
  - `broker_policy_json` (for `publishable_key`)
  - `scope_policy_json` or equivalent normalized scope storage (for `secret_key`)

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

Credential operations:

- create/rotate/revoke credentials:
  - `owner`, `admin` at org scope,
  - optionally `developer`/`ops` at project scope only for environments in that project.
- read/list credentials:
  - `owner`, `admin`, `security_admin`, and project-scoped roles within allowed project scope.

Audit requirements:

- emit audit events for key create/rotate/revoke with actor, scope, and reason.

## Managed Broker And Bootstrap Token Spec

### Grant Issuance Flow

Browser-managed registration target flow:

1. Browser creates the WebAuthn credential and the final relay request body.
2. Browser canonicalizes the intended relay JSON body and computes `requestHashSha256`.
3. Browser calls `POST /v1/registration/bootstrap-grants` with:
   - `Authorization: Bearer <publishable_key>`
   - `Origin`
   - `environmentId`
   - `requestHashSha256`
   - registration metadata needed for quota/risk policy
4. Broker performs cheap checks first:
   - key lookup and status
   - allowed origin exact match
   - project/environment enabled state
   - quota and rate-limit evaluation
   - optional captcha/risk gates
   - account ID / RP ID validation
5. Broker returns either:
   - `200` with `bootstrap_token`, or
   - `402` with x402 payment requirements, or
   - terminal 4xx denial
6. Browser calls relay `POST /registration/bootstrap` with:
   - `Authorization: Bearer <bootstrap_token>`
   - the exact body used to compute `requestHashSha256`
7. Relay redeems the token exactly once and executes registration.

### Canonical Request Hash

Requirements:

- Use a deterministic JSON serialization for the exact relay body.
- Hash input includes:
  - `new_account_id`
  - `signer_slot`
  - `threshold_ed25519`
  - `threshold_ecdsa`
  - `rp_id`
  - `webauthn_registration`
  - `authenticator_options`
- Hash excludes:
  - transport headers
  - bearer credential
  - browser-only metadata
- Hash algorithm:
  - `SHA-256`
  - encoded as base64url

### Token Redemption Semantics

- Token is single-use and must be atomically transitioned from `issued` to `redeemed`.
- Token is consumed before the expensive registration write path starts.
- Replay of the same token must fail even if the first request later returns a 4xx or 5xx.
- If a paid token is consumed and the relay fails with an internal retryable error, broker may mint one replacement token:
  - same `requestHashSha256`
  - same `origin`
  - same `environmentId`
  - maximum one replacement
  - only for retryable internal errors, not validation failures

### Broker Persistence

Add storage for managed grants:

- `console_bootstrap_tokens`
  - `id`
  - `token_hash`
  - `token_prefix`
  - `publishable_key_id`
  - `org_id`
  - `project_id`
  - `environment_id`
  - `origin`
  - `method`
  - `path`
  - `request_hash_sha256`
  - `status`
  - `risk_decision`
  - `payment_reference`
  - `replacement_for_token_id`
  - `issued_at`
  - `expires_at`
  - `redeemed_at`
  - `created_at`
  - `updated_at`

### Broker Telemetry

Emit structured events for:

- `publishable_key.auth.success`
- `publishable_key.auth.denied`
- `bootstrap_token.issued`
- `bootstrap_token.redeemed`
- `bootstrap_token.rejected`
- `bootstrap_token.expired`
- `bootstrap_token.replacement_issued`
- `x402.challenge_issued`
- `x402.payment_settled`
- `x402.payment_rejected`

## x402 Optional Paid Lane Spec

### Positioning

- x402 is an acquisition path for `bootstrap_token`.
- x402 does not replace `publishable_key`.
- x402 does not replace `secret_key`.
- x402 is only relevant to managed browser mode.

### Payment Decision Rules

Broker should return `402 Payment Required` only after all non-payment checks pass:

- `publishable_key` is valid and active
- origin is allowed
- environment is active
- request shape is valid
- project policy allows paid overage

Do not request payment for:

- malformed relay request body
- blocked origin
- disabled project/environment
- revoked credential

### Payment Policy Shape

Target `paymentPolicy` fields on `publishable_key`:

```json
{
  "mode": "disabled | quota_then_x402 | always_x402",
  "productId": "wallet_registration_v1",
  "network": "base",
  "asset": "USDC",
  "amount": "0.10",
  "replacementWindowSeconds": 600
}
```

### Payment Outcome Behavior

- Successful payment returns a normal `bootstrap_token` response with `mode: "paid"`.
- Failed payment returns:
  - `402` again when the challenge can be retried, or
  - `403` / `422` when payment proof is invalid or unusable
- Settlement metadata is recorded on the token row and in audit/metering events.

## Phased Execution Queue (Dependency Order)

## Phase 0: Contract Lock + Cleanup

- [x] Lock scope taxonomy for relay-protected actions:
  - `accounts.create`
  - `wallets.read`
- [ ] Lock onboarding API contracts and response payloads.
- [ ] Lock credential vocabulary in all public surfaces:
  - `secret_key`
  - `publishable_key`
  - `bootstrap_token`
- [ ] Ban generic browser-facing `apiKey` naming in public docs and SDK config.
- [ ] Support only `Authorization: Bearer`.
- [x] Remove implicit org/project/environment auto-bootstrap from core read paths.
- [ ] Keep demo data seeding only in explicit local seed code.

Exit criteria:

- Contracts are stable and documented.
- Current `secret_key` scope catalog is explicitly limited to `accounts.create` and `wallets.read`.
- Core services no longer auto-create tenancy on read.
- Terminology no longer leaves room for a browser-held secret interpretation.

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

## Phase 2: `secret_key` Persistence Hardening And RBAC

- [x] Enforce RBAC on credential create/rotate/revoke routes.
- [x] Validate environment belongs to caller org before key create.
- [x] Move secret generation to CSPRNG-only implementation.
- [x] Add `key_prefix` fast lookup path and supporting indexes.
- [x] Add optional expiry support and revoke reason support.
- [x] Add audit events for credential lifecycle mutations.
- [x] Add route tests for RBAC forbidden cases and validation errors.
- [x] Add `kind` discriminator to persistence and API contracts.
- [x] Split stored metadata by kind so `publishable_key` does not carry secret-only fields such as scopes/IP allowlist.

Exit criteria:

- Credential mutations are permission-gated and auditable.
- `secret_key` lifecycle is secure and deterministic.
- Persistence model is ready to store `publishable_key` without ambiguous nullable columns.

## Phase 3: Relay `secret_key` Enforcement (Gas-Costing Paths)

- [x] Implement relay `secret_key` auth middleware module.
- [x] Protect `POST /registration/bootstrap` with required scope `accounts.create`.
- [x] Bind `secret_key` environment scope to request context.
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
- [x] Rename relay auth error codes from generic `api_key_*` to `secret_key_*`.
- [x] Use `Authorization: Bearer` only.

Exit criteria:

- Registration endpoint cannot be called without valid scoped `secret_key`.
- Usage telemetry is populated from real traffic.
- Auth transport and error naming are unambiguous.

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
- [x] Split API keys page into explicit create flows:
  - create `secret_key`
  - create `publishable_key`
- [x] Use each `publishable_key` as the canonical allowed-origin editor and source of truth for browser access.
- [x] Stop showing browser-side direct relay snippets that imply frontend secret storage.

Exit criteria:

- New user can complete onboarding in one guided flow.
- User can create first credential immediately after onboarding using API keys page.
- Dashboard copy is aligned with the two-mode model.

## Phase 5: Secret-Key Registration Mode (Server-Based)

- [x] Keep relay `secret_key` auth on `POST /registration/bootstrap`.
- [x] Rename typed SDK registration errors for this path:
  - `secret_key_missing`
  - `secret_key_invalid`
  - `secret_key_revoked`
  - `secret_key_forbidden_scope`
  - `secret_key_ip_blocked`
  - `secret_key_environment_mismatch`
- [ ] Add first-class backend proxy integration docs and examples for Node/Next/Express.
- [x] Add explicit SDK/browser proxy config surface:
  - `mode: 'backend_proxy'`
  - `registrationBootstrapUrl`
- [x] Delete `relayer.apiKey` from SDK config and docs.
- [x] Add SDK runtime guard that throws when browser config includes `secretKey` or `apiKey`.
- [ ] Add e2e test: browser -> developer backend proxy -> relay bootstrap -> successful registration.
- [ ] Add e2e test: backend proxy forwards relay auth failures with typed `secret_key_*` codes.

Exit criteria:

- `secret_key` mode works end-to-end without storing secrets in the frontend.
- Browser-facing SDK docs no longer teach direct secret usage.

Server-only relay request example:

Direct curl:

```bash
curl -X POST "https://relay.example.com/registration/bootstrap" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk_..." \
  -d '{
    "new_account_id": "alice.w3a-relayer.testnet",
    "signer_slot": 1,
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

## Phase 6: Stripe Billing Eligibility Track

- [x] Add pricing page CTA wiring to `POST /console/billing/stripe/checkout-session`.
- [x] Implement success/cancel dashboard return handling.
- [x] Add prepaid balance / usage visibility in dashboard billing.
- [x] Keep Stripe billing surface checkout-only.
- [x] Ensure Stripe webhook idempotency and reconciliation paths are covered.
- [x] Add e2e flow: pricing -> checkout -> return -> prepaid balance state reflected.

Exit criteria:

- Self-serve billing entry flow is live as the eligibility layer for credential provisioning and retention.

## Phase 7: `publishable_key` Data Model And Console API

- [x] Add `publishable_key` as a first-class key kind in API contracts and persistence.
- [x] Add explicit key-kind metadata (`publishable_key` vs `secret_key`) to `/console/api-keys` responses.
- [x] Add allowed-origin storage and create/list/rotate support for `publishable_key`.
- [x] Add broker-policy storage for `publishable_key`:
  - `rateLimitBucket`
  - `quotaBucket`
  - `riskPolicy`
  - `paymentPolicy`
- [x] Keep scopes and direct relay authorization limited to `secret_key`; do not overload `publishable_key`.
- [x] Add create/list/rotate/revoke audit events that include key kind.
- [x] Add relayer coverage for `publishable_key` create/list flows and direct relay rejection.
- [x] Add dashboard create/list UI for `publishable_key`.
- [x] Add dashboard copy and snippets that present the two integration modes clearly.

Exit criteria:

- The product surface has explicit `publishable_key` and `secret_key` terminology.
- `publishable_key` records can be created, rotated, revoked, and listed cleanly.
- There is no ambiguous browser-facing credential path left in docs or UI.

## Phase 8: Managed Broker Grant Issuance

- [x] Add managed broker endpoint that accepts `publishable_key` from the browser:
  - `POST /v1/registration/bootstrap-grants`
- [x] Require `Authorization: Bearer <publishable_key>`.
- [x] Validate allowed origin against the key/project/environment.
- [x] Validate project/environment status before issuing bootstrap grants.
- [x] Enforce quotas and rate limits at the managed broker.
- [ ] Add optional abuse hooks (captcha/challenge/risk scoring) without changing relay contract.
- [x] Define canonical request-hash helper shared across browser SDK, broker, and relay tests.
- [x] Issue single-use, short-TTL, origin-bound `bootstrap_token`.
- [x] Persist issued-token rows with exact request hash and lifecycle state.
- [x] Add structured broker issue/deny logs at the relay router boundary.
- [ ] Add durable broker audit + telemetry events for issue/deny decisions.

Exit criteria:

- Browser can start registration with `publishable_key` only.
- Managed broker enforces origin and quota checks before relay bootstrap is reachable.
- The issued grant is request-bound and replay-resistant.

## Phase 9: Relay `bootstrap_token` Redemption

- [x] Add relay auth strategy for managed `bootstrap_token` on `POST /registration/bootstrap`.
- [x] Detect credential type by bearer prefix and route to the correct validator.
- [x] Bind `bootstrap_token` to:
  - project/environment
  - origin
  - request hash
  - single use
  - short expiration
  - exact method/path
- [x] Keep existing `secret_key` auth path for server-based integrations.
- [x] Atomically redeem token before expensive write path begins.
- [ ] Add telemetry for token issuance, redemption, expiry, replay rejects, and request-hash mismatches.
- [x] Add replay-prevention, request-mismatch, and token-consumption tests.
- [x] Add explicit expired-token regression tests.
- [x] Add parity coverage for Express + Cloudflare runtime paths.

Exit criteria:

- Relay accepts either:
  - `secret_key` from a trusted backend, or
  - managed bootstrap token minted from a `publishable_key`.
- Relay never accepts `publishable_key` directly as a privileged credential.
- Replay of a consumed token fails deterministically.

## Phase 10: Browser SDK Managed Mode And Public Surface Cleanup

- [x] Add SDK config for `managed` mode:
  - `environmentId`
  - `publishableKey`
  - `paymentMode?`
- [x] Add SDK config for backend proxy mode without exposing `secret_key`.
- [x] Implement browser-side grant acquisition:
  - compute canonical request hash
  - request `bootstrap_token`
  - redeem token against relay
- [x] Update dashboard snippets to show:
  - backend/server integration using `secret_key`
  - frontend-only managed integration using `publishable_key`
- [x] Reject `secret_key` usage from browser-targeted SDK config at runtime.
- [ ] Remove generic `apiKey` naming from examples, snippets, public docs, and environment variable examples.

Exit criteria:

- Developers have two clear supported paths.
- Frontend config surfaces are browser-safe by default.
- Browser-managed registration works without a developer backend.

## Phase 11: x402 Optional Paid Grant Lane

- [ ] Add broker support for HTTP `402 Payment Required` on grant issuance.
- [ ] Encode product-level payment policy on `publishable_key` / environment.
- [ ] Return x402 challenge data only after non-payment validation passes.
- [ ] Accept payment settlement proof and mint normal `bootstrap_token` on success.
- [ ] Persist settlement reference on token and audit events.
- [ ] Add optional replacement-token path for retryable internal relay failures after a paid redemption.
- [ ] Add tests for:
  - quota exceeded -> 402
  - invalid payment proof
  - successful paid grant issuance
  - replacement-token issuance rules

Exit criteria:

- x402 is an optional paid lane layered on the managed broker.
- Payment never becomes a direct relay auth mechanism.

## Phase 12: Security Hardening And Rollout

- [x] Add schema updates for key-kind discriminator, allowed-origin storage, and broker-policy fields.
- [x] Add bootstrap-token storage schema and lifecycle tables.
- [ ] Add audit events for `publishable_key` create/rotate/revoke and origin changes.
- [ ] Add rate-limit dashboards and operational alerts for broker abuse patterns.
- [ ] Add end-to-end tests for:
  - `secret_key` backend proxy mode
  - `publishable_key` managed mode
  - browser rejection when `secret_key` is misconfigured client-side
  - x402 paid grant mode
- [ ] Add docs/playbooks for self-hosted relay users:
  - `secret_key` mode supported
  - managed `publishable_key` mode unsupported unless they also host a compatible broker
- [ ] Delete generic `apiKey` names from runtime types, docs, examples, and UI copy.
- [x] Rename `api_key_*` errors to final `secret_key_*` and broker-specific codes.

Exit criteria:

- Explicit key kinds and token types are complete.
- Security boundaries are enforced in code, tests, docs, and dashboard UX.
- Ambiguous credential paths have been deleted.

## Testing Matrix

- Unit tests:
  - scope matching,
  - key hash verify,
  - allowlist checks,
  - onboarding idempotency logic,
  - canonical request-hash serializer,
  - bootstrap-token lifecycle state transitions.
- Service tests:
  - org/project/environment creation invariants,
  - `secret_key` lifecycle and RBAC,
  - `publishable_key` lifecycle and allowed-origin validation,
  - broker quota / rate-limit decisions.
- Router tests:
  - Express + Cloudflare parity for onboarding and key routes,
  - relay auth parity for `secret_key` and `bootstrap_token`.
- Postgres tests:
  - tenant isolation,
  - schema evolution,
  - index-backed key lookup behavior,
  - bootstrap-token redemption atomicity.
- E2E tests:
  - dashboard onboarding happy path,
  - dashboard onboarding retry/resume,
  - `secret_key` backend proxy registration flow,
  - `publishable_key` managed registration flow,
  - x402 paid grant flow,
  - browser runtime rejection of invalid frontend credential config.

## Acceptance Criteria

- New user can sign in and complete onboarding without manual DB seeding.
- Organization creation is explicit and auditable.
- Project/environment hierarchy is explicit and validated.
- Credential value is shown once, then never retrievable.
- Browser never requires a long-lived secret for registration.
- Billing eligibility gates whether credentials may be provisioned or remain active, independent of auth mode.
- There are only two long-lived credential kinds in product and code:
  - `secret_key`
  - `publishable_key`
- Relay registration endpoint requires either:
  - valid `secret_key` with correct scope, or
  - valid managed bootstrap token minted from `publishable_key`.
- `publishable_key` never authorizes relay runtime directly.
- x402, when enabled, only buys a one-time `bootstrap_token`.
- Credential usage telemetry is populated from real auth middleware and managed broker paths.
- Dashboard provides copy-paste integration examples for both supported modes.
- Stripe billing works as the credential-eligibility layer alongside auth-mode support.

## Implementation Notes

- Keep runtime and console domains separated by module boundaries.
- Keep schema/user isolation between signer DB domain and console DB domain.
- Do not introduce fallback behavior for implicit tenancy creation.
- Apply schema changes and delete superseded code paths in the same workstream.
- Delete ambiguous generic `apiKey` symbols instead of aliasing them.
- Support only one auth transport: `Authorization: Bearer`.
