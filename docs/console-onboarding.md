# Console Onboarding Implementation Plan

Date updated: March 4, 2026

## Objective

Implement a production onboarding flow for the dashboard console in this order:

1. User signs in / creates account (SSO-capable).
2. User configures organization context.
3. User adds a billing option.
4. User creates the first project.
5. User lands in wallet management for that project.

Related context:

- `docs/saas/dashboard-backend-implementation-plan.md`
- `docs/saas/api-keys.md`

## Current State Snapshot (Reality Check)

### Implemented

- [x] `GET /console/session` auth/session endpoint exists.
- [x] Dashboard redirects to `/dashboard/onboarding` when onboarding state is incomplete.
- [x] `GET /console/onboarding/state` exists.
- [x] Billing payment-method endpoints exist:
  - [x] `GET/POST/DELETE /console/billing/payment-methods`
  - [x] `POST /console/billing/payment-methods/:id/default`
  - [x] `POST /console/billing/stripe/setup-intent`
- [x] Card mutation RBAC is enforced (`admin` for add/remove/default).
- [x] Read-path auto-bootstrap has been removed from core org/project/environment read routes.

### Misalignments To Fix

- [x] Onboarding frontend is now step-based (organization -> billing -> project).
- [x] Onboarding state now exposes canonical step fields (`currentStep`, `billingReady`, `onboardingComplete`).
- [x] Billing-ready precondition is enforced on `POST /console/projects` when billing service is configured.
- [x] `POST /console/onboarding/project` now exists (project + default Production environment, idempotent).
- [x] `POST /console/onboarding/organization` now exists (org profile upsert + owner bootstrap, idempotent).
- [x] Frontend onboarding UI is now a resumable step wizard (organization + billing + project).
- [x] Enforce organization-first precondition on `POST /console/onboarding/project`.
- [x] Remove implicit org auto-create from project creation write paths.
- [x] Set active project/environment context immediately after onboarding project success.
- [x] Auto-redirect to wallet list when onboarding completes (instead of manual continue action).

## Product Decisions (Locked)

- Onboarding is step-based and resumable; legacy bootstrap route has been removed.
- Billing comes before first project creation.
- First project creation auto-creates one default environment (`prod`/`Production`).
- No implicit org/project/environment auto-bootstrap in read paths.
- Breaking changes are allowed; old onboarding paths are removed as part of cutover.

Auth/tenant constraint (important):

- Current console auth claims require `orgId`.
- Therefore, onboarding "organization step" means configuring/upserting the org profile in that org context, not selecting arbitrary org tenancy from within this flow.

## Target UX Flow

1. `GET /console/session` confirms authenticated user.
2. `GET /console/onboarding/state` returns deterministic step.
3. If onboarding incomplete, frontend redirects to `/dashboard/onboarding`.
4. Step 1: Organization details.
5. Step 2: Billing payment method.
6. Step 3: First project creation (auto-create default Production environment).
7. Redirect with active org/project/environment context:
   - to `/dashboard/api-keys` when no API key exists yet (first-run handoff),
   - to `/dashboard/wallets-list` when API keys already exist.

## Target Backend Contracts

Existing endpoints retained:

- `GET /console/session`
- `GET /console/org`
- `POST /console/projects` (with billing-ready enforcement)
- `GET/POST/DELETE /console/billing/payment-methods`
- `POST /console/billing/payment-methods/:id/default`
- `POST /console/billing/stripe/setup-intent`

Onboarding endpoints:

- `GET /console/onboarding/state`
  - includes:
    - `currentStep` (`organization` | `billing` | `project` | `complete`)
    - `accountReady`
    - `organizationReady`
    - `billingReady`
    - `projectReady`
    - `onboardingComplete`
- `POST /console/onboarding/organization`
  - upserts organization profile in caller org context; ensures owner membership.
- `POST /console/onboarding/project`
  - creates first project and default `prod` environment idempotently.
- `GET /console/onboarding/telemetry`
  - returns per-operation onboarding request metrics, active SLO alerts, and threshold metadata.
- `POST /console/onboarding/bootstrap` has been removed; onboarding is step-only.

## Security And Data Requirements

- Persist onboarding progress server-side (derived from canonical data; no client-only state).
- Tenant isolation and RLS remain enforced.
- Audit events required for:
  - organization profile set,
  - billing method add/remove/default,
  - project create,
  - default environment create.
- Idempotency behavior must be deterministic for onboarding mutations.

## Phased Execution Queue (Dependency Ordered)

### Phase 1: State Contract Alignment

- [x] Keep `GET /console/onboarding/state` endpoint live.
- [x] Extend onboarding state schema with:
  - [x] `currentStep`
  - [x] `accountReady`
  - [x] `organizationReady`
  - [x] `billingReady`
  - [x] `projectReady`
  - [x] `onboardingComplete`
- [x] Compute billing readiness from billing payment methods.
- [x] Add route tests (Express + Cloudflare parity) for new state fields.

Exit criteria:

- Every authenticated user maps to a deterministic onboarding step.

### Phase 2: Organization Step

- [x] Implement `POST /console/onboarding/organization` (idempotent).
- [x] Ensure org profile exists/updated in caller org context.
- [x] Ensure owner bootstrap is deterministic for first user.
- [x] Emit audit event for org profile setup.
- [x] Add request validation + route parity tests (Express + Cloudflare).

Exit criteria:

- Organization step can be completed independently and resumed.

### Phase 3: Billing Step

- [x] Implement onboarding billing UI on top of existing billing endpoints.
- [x] Require at least one active payment method before allowing project step.
- [x] Add server-side billing-ready helper reused by onboarding/project routes.
- [x] Add error recovery for Stripe action-required / declined states.

Exit criteria:

- Project onboarding step cannot proceed without valid billing.

### Phase 4: Project Step + Wallet Entry

- [x] Implement `POST /console/onboarding/project` (idempotent).
- [x] Create first project + default Production environment in one operation path.
- [x] Enforce billing-ready precondition in:
  - [x] `POST /console/onboarding/project`
  - [x] `POST /console/projects`
- [x] Set active org/project/environment client context after success.
- [x] Redirect to wallet list first-run state.

Exit criteria:

- Newly onboarded org lands in wallet-manageable context immediately.

### Phase 5: Frontend Wizard Cutover

- [x] Replace bootstrap form with step wizard:
  - [x] organization
  - [x] billing
  - [x] project
- [x] Resume by `currentStep`.
- [x] Keep route-gating driven by `onboardingComplete`.
- [x] Add e2e tests for happy path and resume/retry paths.
- [x] Add e2e coverage for partial progress + browser reload resume (organization complete -> billing step).

Exit criteria:

- Wizard is step-based and resumable end-to-end.

### Phase 6: Legacy Removal + Hardening

- [x] Remove `POST /console/onboarding/bootstrap` backend route/service.
- [x] Remove bootstrap frontend API calls/types/UI.
- [x] Reconcile `docs/saas/api-keys.md` with step-based onboarding model.
- [x] Add onboarding metrics, alerting, and SLO checks.

Exit criteria:

- One onboarding model remains (step-based only), no legacy bootstrap code.

### Phase 7: Organization-First Enforcement (Backend)

- [x] Add explicit organization readiness guard in onboarding project mutation:
  - [x] In `createOnboardingProject`, resolve onboarding state first.
  - [x] If `organizationReady !== true`, return deterministic `organization_required` (409).
- [x] Keep billing guard after organization guard (organization -> billing -> project order).
- [x] Add Express + Cloudflare parity tests:
  - [x] project step is blocked before organization step,
  - [x] project step proceeds after organization + billing are ready.

Exit criteria:

- Project step cannot run unless organization step is complete.

### Phase 8: Remove Implicit Org Auto-Create (Write Paths)

- [x] Postgres service:
  - [x] Remove `ensureOrganizationExists` usage from `createProject`.
  - [x] Require existing org row and return `organization_not_found` when absent.
- [x] In-memory service:
  - [x] Remove org auto-materialization for `createProject`.
  - [x] Require explicit org creation via `upsertOrganization` first.
- [x] Update router/service tests that currently rely on implicit org creation side effects.
- [x] Keep onboarding organization endpoint as the canonical org bootstrap path.

Exit criteria:

- Organization records are never auto-created by project write routes.

### Phase 9: Active Context Handoff On Onboarding Completion (Frontend)

- [x] On onboarding project success, persist `selectedProjectId` + `selectedEnvironmentId` into dashboard context preferences (query/localStorage keys).
- [x] Ensure dashboard topbar context resolves to newly-created project/environment immediately.
- [x] Add e2e assertion that post-onboarding context matches created IDs.

Exit criteria:

- Newly-created project/environment become active context without manual selection.

### Phase 10: Automatic Wallet Redirect (Frontend)

- [x] Replace manual-only completion path with automatic completion redirect after onboarding state is observed.
- [x] Route onboarding completion to API keys first when no key exists; otherwise route to wallets.
- [x] Keep explicit secondary action to open API keys.
- [x] Add e2e coverage for automatic redirect and no redirect loop.

Exit criteria:

- User lands on API key setup first for first-run orgs, and lands on wallets when API keys already exist.

### Phase 11: Ops Cockpit Integration

- [x] Add an Ops Cockpit dashboard route (`/dashboard/overview`) that surfaces onboarding SLO alerts from `GET /console/onboarding/telemetry`.
- [x] Aggregate operator queues in one place for daily workflow:
  - [x] pending approvals,
  - [x] failed or overdue billing invoices,
  - [x] webhook dead letters,
  - [x] queued/processing audit exports,
  - [x] active enterprise isolation requests.
- [x] Add e2e API-wiring coverage for Ops Cockpit queue aggregation and quick-link navigation.

Exit criteria:

- Operators can inspect onboarding health and adjacent failure queues from a single dashboard page.

### Phase 12: Ops Cockpit Backend Aggregation

- [x] Add server-side summary endpoint `GET /console/ops-cockpit/summary` (Express + Cloudflare parity) to aggregate operator queues.
- [x] Keep endpoint resilient by returning per-module statuses (`ok`, `not_configured`, `forbidden`, `error`) instead of failing whole responses when optional modules are disabled.
- [x] Enforce role-aware onboarding telemetry behavior in summary payload:
  - [x] `admin`/`ops`: include telemetry snapshot + alerts.
  - [x] non-`admin`/`ops`: return telemetry section as `forbidden` while preserving other sections.
- [x] Switch dashboard Ops Cockpit page to consume summary endpoint directly (single request model).
- [x] Add route + e2e wiring coverage for summary endpoint integration.
- [x] Add Ops Cockpit dead-letter row quick action to replay deliveries via `POST /console/webhooks/:id/replay`.
- [x] Add e2e wiring coverage for Ops Cockpit replay action request payload and success notice.
- [x] Add Ops Cockpit pending-approval row quick actions (`approve` / `reject`) via `/console/approvals/:id/*` endpoints.
- [x] Add e2e wiring coverage for Ops Cockpit approval quick-action payloads and success notices.
- [x] Add Ops Cockpit queued-audit-export row quick action to requeue exports via existing audit export APIs.
- [x] Add e2e wiring coverage for Ops Cockpit audit-export requeue payload and success notice.

Exit criteria:

- Ops Cockpit works as a single-call operator surface and degrades gracefully when specific backend modules are unavailable.

## Acceptance Criteria

- New SSO user can complete onboarding without manual DB seeding.
- Organization context is explicitly configured and auditable.
- Billing option is captured before first project.
- First project creation yields wallet-manageable context immediately.
- User lands on wallet management with valid org/project/environment selection.
