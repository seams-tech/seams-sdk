# Dashboard + Backend Implementation Plan

Date updated: February 19, 2026

## Objective

Turn dashboard requirements into a shippable SaaS console backend with a clear execution sequence across:

- Dashboard frontend (UI + UX + state handling).
- SaaS backend (authz, APIs, business logic).
- Data layer (tenant-safe schemas, migrations, jobs).

This plan assumes:

- Runtime signing stays in SDK/relay paths.
- Dashboard features are implemented in a separate SaaS backend.

## Inputs

- Requirements: `docs/saas/dashboard-requirements.md`
- Data model: `docs/saas/db-schema.md`
- Related migration and custody planning:
  - `docs/saas/self-hosted-migration.md`
  - `docs/saas/import-threshold-keys.md`
  - `docs/saas/multichain-account-recovery.md`

## Current State (as of February 19, 2026)

Frontend:

- `/dashboard` shell exists with:
  - expandable sidebar,
  - topbar context dropdowns,
  - route per requirement item,
  - requirement-driven placeholder content.
- UI preferences are persisted in URL + local storage.

Backend:

- No dedicated SaaS console backend is finalized yet.
- API surfaces are defined at requirements level, but not yet contract-locked.

## Route Namespace Convention

- `/console/*`: SaaS/admin APIs used by dashboard and org-management surfaces.
- `/relay/*`: runtime/transaction APIs used by signing and relay execution flows.
- Implementation target: keep routers and auth contexts separate so `console` and `relay` can be co-deployed in one Cloudflare worker when needed.

## Delivery Principles

1. Contract-first: lock API and event schemas before deep UI wiring.
2. Tenant safety first: enforce org/project scoping and RLS early.
3. Vertical slices: deliver end-to-end feature slices, not isolated layers.
4. Auditability by default: every mutating admin action writes immutable logs.
5. Progressive hardening: MVP first, then approvals/anomaly/governance depth.

## Workstreams

### A) Dashboard Frontend

Scope:

- Data-fetching layer and typed API client.
- Feature pages for wallets, policy, settings, api keys, webhooks, exports.
- Reusable state patterns for loading/empty/error/success.

Key outputs:

- Production route map under `/dashboard/*`.
- Accessible controls with keyboard support and semantic labels.
- URL-synced filters for list/search pages.

### B) SaaS Backend

Scope:

- Authn/authz, org/project/environment scoping.
- CRUD APIs + validation + business rules.
- Eventing/outbox + audit log + approval workflows (phased).

Key outputs:

- Versioned REST/JSON APIs.
- Tenant-aware authorization and policy enforcement.
- Operational jobs for rollups, retries, and metering.

### C) Data and Platform

Scope:

- Migration sets for control/runtime/audit schemas.
- RLS policies + tenant-context middleware.
- Operational infra: queues, scheduled jobs, observability.

Key outputs:

- Stable schema baseline.
- Repeatable migration pipeline.
- SLO-backed service telemetry.

## Dashboard Route to Backend Mapping

### `/dashboard/wallets-list`

- APIs:
  - `GET /console/wallets`
  - `GET /console/wallets/:id`
- Data:
  - `wallets`
  - `wallet_balances_snapshot`
  - `wallet_activity_events`
- Jobs:
  - daily KPI rollup for assets/funded/activity cards

### `/dashboard/wallets-search`

- APIs:
  - `GET /console/wallets/search`
- Data:
  - `wallets`
  - optional search index/materialized view
- Jobs:
  - index refresh and search latency monitoring

### `/dashboard/policy-engine`

- APIs:
  - `GET/POST/PATCH /console/policies`
  - `POST /console/policies/:id/simulate`
  - `POST /console/policies/:id/publish`
- Data:
  - `policies`
  - `policy_versions`
  - `policy_assignments`
  - `policy_decision_logs`
- Jobs:
  - policy publish propagation and snapshot generation

### `/dashboard/gas-smart-wallets`

- APIs:
  - `GET/POST/PATCH /console/gas-sponsorship`
  - `GET/POST/PATCH /console/smart-wallets`
- Data:
  - sponsorship budget and telemetry tables
  - smart-wallet configuration tables
- Jobs:
  - spend rollup and threshold alerting

### `/dashboard/app-settings`

- APIs:
  - `GET/PATCH /console/settings/app`
  - `GET/PATCH /console/settings/security`
- Data:
  - `project_settings`
  - `environment_settings`
- Jobs:
  - settings snapshot publish to runtime consumers

### `/dashboard/export-keys`

- APIs:
  - `GET/POST /console/key-exports`
  - `POST /console/key-exports/:id/approve`
- Data:
  - export request and approval tables
  - immutable export audit log
- Jobs:
  - approval timeout/escalation and audit artifact writer

### `/dashboard/api-keys`

- APIs:
  - `GET/POST/DELETE /console/api-keys`
  - `POST /console/api-keys/:id/rotate`
- Data:
  - `api_keys`
  - `api_key_scopes`
  - `api_key_usage_stats`
- Jobs:
  - key-usage anomaly detector

### `/dashboard/webhooks`

- APIs:
  - `GET/POST/PATCH/DELETE /console/webhooks`
  - `GET /console/webhooks/:id/deliveries`
  - `POST /console/webhooks/:id/replay`
- Data:
  - `webhook_endpoints`
  - `webhook_secrets`
  - `webhook_deliveries`
  - `webhook_attempts`
  - `webhook_dead_letters`
- Jobs:
  - delivery worker with retry/backoff and DLQ processor

## Milestone Plan

### Milestone 0: Foundation (1-2 weeks)

Frontend:

- Introduce API client abstraction (typed request/response layer).
- Add shared UI primitives: `AsyncState`, `TableShell`, `FormSection`, `ConfirmDialog`.

Backend:

- Scaffold new SaaS service boundaries:
  - `identity-access`
  - `org-project-env`
  - `wallet-index`
  - `policy`
  - `integrations`
  - `billing`
- Add auth middleware + tenant context propagation.

Data:

- Land Phase 0 schema from `db-schema.md`:
  - organizations/projects/environments/memberships
  - audit_log
  - event_outbox
- Add baseline RLS policies and policy tests.

Exit criteria:

- Authenticated org-scoped request can list org/project metadata.
- CI has migration + RLS test gates.

### Milestone 1: Wallets List + Search (2 weeks)

Frontend:

- Replace placeholder KPI and table content with live API data.
- Implement pagination, sorting, and URL-synced search/filter controls.
- Add row action menu with guarded actions.

Backend:

- Implement:
  - `GET /console/wallets`
  - `GET /console/wallets/:id`
  - `GET /console/wallets/search`
- Add filter/sort constraints and input validation.

Data:

- Add wallet index tables and query-friendly indexes.
- Add daily activity rollup job for KPI cards.

Exit criteria:

- Admin can list/search wallets under a project without cross-tenant leakage.
- p95 list/search latency target is measured and tracked.

### Milestone 2: Policy Engine + App Settings Core (2-3 weeks)

Frontend:

- Policy authoring UI (draft/publish flow).
- Policy assignment UI (org/project/segment/wallet scope).
- App settings forms with validation and risky-change warnings.

Backend:

- Implement:
  - `GET/POST/PATCH /console/policies`
  - `POST /console/policies/:id/publish`
  - `POST /console/policies/:id/simulate`
  - `GET/PATCH /console/settings/app`
- Add policy precedence resolution and simulation evaluator.

Data:

- Land policy tables (`policies`, `policy_versions`, `policy_assignments`, `policy_decision_logs`).
- Add settings tables for origins/cookies/JWT and environment scoping.

Exit criteria:

- Policies can be drafted, simulated, published, and audited.
- App settings are environment-specific and validated.

### Milestone 3: API Keys + Webhooks (2 weeks)

Frontend:

- API key lifecycle flows: create, reveal-once, revoke, rotate.
- Webhook endpoint management + delivery log views + replay actions.

Backend:

- Implement:
  - `GET/POST/DELETE /console/api-keys`
  - `POST /console/api-keys/:id/rotate`
  - `GET/POST/PATCH/DELETE /console/webhooks`
  - `GET /console/webhooks/:id/deliveries`
  - `POST /console/webhooks/:id/replay`
- Add webhook signer and retry worker.

Data:

- Add key and webhook tables including delivery attempts/dead-letter records.
- Add usage timestamps and basic anomaly flags.

Exit criteria:

- API key secrets are never retrievable after creation.
- Failed webhooks retry with backoff and support replay.

### Milestone 4: Export Keys + Gas Sponsorship + Smart Wallet Controls (2-3 weeks)

Frontend:

- Export settings modes and approval workflow UX.
- Gas sponsorship controls with budget dashboards.
- Smart wallet mode controls and fallback settings.

Backend:

- Implement:
  - `GET/POST /console/key-exports`
  - `POST /console/key-exports/:id/approve`
  - `GET/POST/PATCH /console/gas-sponsorship`
  - `GET/POST/PATCH /console/smart-wallets`
- Add step-up and approval guardrails for export actions.

Data:

- Add export request/approval tables and immutable export logs.
- Add sponsorship budget and spend telemetry tables.

Exit criteria:

- Sensitive export changes require policy-defined approvals.
- Sponsorship and smart wallet controls affect runtime config snapshots.

### Milestone 5: Billing + Governance Hardening (2-4 weeks)

Frontend:

- Billing overview pages: plan, usage, credits, invoices.
- Team/role management and audit investigation views.

Backend:

- Implement billing accounts, usage ingestion, invoicing workflows.
- Add advanced RBAC, support-access controls, and approval workflows.

Data:

- Add subscriptions, usage rollups, credit ledger, invoice tables.
- Add retention policies and compliance export jobs.

Exit criteria:

- Org billing supports monthly + active-wallet + credits model.
- Governance actions are fully auditable.

## API Contract Plan

### Contract package

- Create a versioned API contract package (OpenAPI + JSON schemas).
- Include:
  - request/response schemas,
  - error taxonomy,
  - idempotency behavior for mutating endpoints.

### Versioning rules

- Path versioning: `/v1/...`
- Additive-first changes in minor versions.
- Breaking changes require new major contract version.

### Event contracts

Define event envelopes for:

- policy changes,
- api key lifecycle events,
- webhook delivery status,
- key export approvals,
- billing usage and invoice generation.

## Dashboard Integration Plan

1. Replace static `dashboardContent` usage per page with query-driven view models.
2. Add feature flags per page to safely roll out backend-connected pages.
3. Keep mock adapters for local development and visual regression.
4. Add end-to-end tests per route for:
   - list/search,
   - create/update actions,
   - error/retry behavior.

## Security and Reliability Plan

Security:

- RLS enforcement tests for every tenant table.
- Short-lived session tokens and scoped service tokens.
- Secret management via KMS/HSM references only.

Reliability:

- Queue-backed webhook delivery with dead-letter handling.
- Outbox pattern for reliable event publication.
- SLO dashboards for p95 latency, error rate, and job lag.

Compliance:

- Immutable audit logs for admin actions.
- Evidence export endpoint for policy and billing history.
- Retention and legal-hold controls.

## Testing Strategy

1. Contract tests:
   - API schema conformance,
   - stable error codes.
2. Authorization tests:
   - cross-org and cross-project access denial.
3. Integration tests:
   - happy/edge paths for each milestone endpoint.
4. Frontend E2E tests:
   - critical dashboard workflows.
5. Performance tests:
   - wallets list/search at target scale.

## Immediate Next Steps (Execution Checklist)

1. Lock API contract skeleton for Milestones 0-2.
2. Create backend service scaffold and migration pipeline.
3. Implement org/project/environment read APIs first.
4. Wire dashboard wallets list route to live API behind feature flag.
5. Land RLS test harness and cross-tenant denial tests in CI.

## Open Decisions

1. Final runtime-config snapshot format consumed by relay/runtime services.
2. Canonical active-wallet billing definition.
3. Enterprise isolation trigger policy (when shared DB is not sufficient).
4. Approval policy defaults by operation type (policy publish, key export, settings).
