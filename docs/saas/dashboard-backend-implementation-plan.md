# Dashboard + Backend Implementation Plan

Date updated: March 10, 2026

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

## Database Topology Decision (Resolved)

- Use the same Postgres cluster/instance for local and early-stage deployments.
- Split runtime signer data and console/billing data into separate logical databases (or at minimum separate schemas with separate app roles).
- Maintain separate DB users/permissions/migration streams per domain:
  - signer domain: threshold signing + relay runtime tables.
  - console domain: org/project/environment, dashboard settings, billing, webhooks, API keys.
- Local cluster anchor:
  - `postgresql://seams:seams@127.0.0.1/seams?statusColor=686B6F&env=local&name=seams&tLSMode=0&usePrivateKey=false&safeModeLevel=0&advancedSafeModeLevel=0&driverVersion=0&lazyload=false`
  - target logical DBs: `seams_signer` and `seams_console` on the same `127.0.0.1` cluster.
- Integration between signer and console domains stays API/event-based; no direct cross-database joins.

## Current State (as of February 27, 2026)

Frontend:

- `/dashboard` shell exists with:
  - expandable sidebar,
  - topbar context dropdowns,
  - route per requirement item,
  - requirement-driven placeholder content.
- UI preferences are persisted in URL + local storage.

Backend:

- Dedicated SaaS console backend modules are implemented for billing, webhooks, API keys, and account settings.
- Org/project/environment metadata APIs are implemented.
- Wallet-index console APIs are implemented.

## Status Snapshot (as of February 27, 2026)

Completed:

- `/console` route namespace and separate console router paths are implemented for Express and Cloudflare adapters.
- Webhooks backend slice is implemented:
  - `GET/POST/PATCH/DELETE /console/webhooks`
  - `GET /console/webhooks/:id/deliveries`
  - `GET /console/webhooks/:id/attempts`
  - `GET /console/webhooks/:id/dead-letters`
  - `POST /console/webhooks/:id/replay`
  - cursor pagination contract (`limit`, `cursor`, `nextCursor`) and malformed-cursor validation are implemented and tested.
- Billing backend slice is implemented:
  - `GET /console/billing/overview`
  - `GET /console/billing/account/activity`
  - `GET /console/billing/usage/monthly-active-wallets`
  - `POST /console/billing/usage/events`
  - `GET /console/billing/invoices`
  - `GET /console/billing/invoices/:id`
  - `GET /console/billing/invoices/:id/line-items`
  - `GET /console/billing/invoices/:id/activity`
  - `GET /console/billing/invoices/:id/pdf`
  - `POST /console/billing/invoices/generate`
  - `POST /console/billing/adjustments/support-credit`
  - `POST /console/billing/adjustments/admin-debit`
  - `POST /console/billing/stripe/checkout-session`
  - `POST /console/billing/stripe/webhook`
- Billing semantics implemented:
  - ledger-first prepaid balance projection,
  - append-only journal entries and postings,
  - receipt and usage-statement projection rebuild,
  - shared balance readiness states (`HEALTHY`, `LOW_BALANCE`, `BLOCKED`),
  - internal-only manual adjustment visibility for staff timelines.
- Billing provider boundaries are implemented via explicit Stripe checkout + webhook adapters.
- API key backend slice is implemented:
  - `GET/POST/DELETE /console/api-keys`
  - `POST /console/api-keys/:id/rotate`
  - create/rotate reveal-once secret semantics are implemented.
- API key Postgres persistence is implemented with Postgres-backed org-isolation route tests for Express and Cloudflare adapters.
- Org/project/environment metadata backend slice is implemented:
  - `GET /console/org`
  - `GET /console/projects` (`status=ACTIVE|ARCHIVED` filter supported)
  - `GET /console/environments` (`projectId` and `status=ACTIVE|ARCHIVED` filters supported)
  - `POST /console/projects`
  - `PATCH /console/projects/:id`
  - `POST /console/projects/:id/archive`
  - `POST /console/environments`
  - `PATCH /console/environments/:id`
  - `POST /console/environments/:id/archive`
  - relationship model enforced: one org has many projects; each project has many environments.
  - `GET /console/projects` now includes per-project `environmentCount` aggregate.
  - Postgres constraints now enforce org-consistent project->environment linkage.
  - mutation RBAC enforced (`admin` or `owner` for project/environment mutations).
  - focused parser/service tests cover status-filter normalization/validation and in-memory filter semantics.
  - Postgres-backed org-isolation route tests are implemented for Express and Cloudflare adapters.
- Team/RBAC backend slice is implemented (in-memory service + router contracts):
  - `GET /console/members`
  - `POST /console/members/invite`
  - `PATCH /console/members/:id/roles`
  - `DELETE /console/members/:id`
  - role-scope validation is enforced for org-scoped (`owner`, `admin`, `security_admin`, `billing_admin`) and project-scoped (`developer`, `support`, `ops`) assignments.
  - mutation RBAC is enforced (`admin` or `owner` for invite/role-update/remove).
  - relayer route coverage is implemented for Express and Cloudflare adapters (success paths, validation errors, and mutation-forbidden checks).
  - Postgres-backed Team/RBAC persistence is implemented (`console_team_members` with tenant RLS) and covered by Express + Cloudflare org-isolation route tests.
- Approval queue backend slice is implemented (in-memory + Postgres service + router contracts):
  - `GET /console/approvals`
  - `GET /console/approvals/:id`
  - `POST /console/approvals`
  - `POST /console/approvals/:id/approve`
  - `POST /console/approvals/:id/reject`
  - mutation RBAC is enforced (`owner`, `admin`, or `security_admin` for create/approve/reject).
  - operation defaults are implemented (`POLICY_PUBLISH`, `KEY_EXPORT`) with per-operation approval/MFA defaults.
  - Postgres-backed approval persistence is implemented (`console_approvals` with tenant RLS).
  - relayer route coverage is implemented for Express and Cloudflare adapters (`*_not_configured`, mutation-forbidden checks, MFA-required checks, and state-transition behavior), including Postgres org-isolation route tests.
  - approval queue create/approve/reject mutations emit lifecycle webhook events (`policy.approval.created`, `policy.approval.approved`, `policy.approval.rejected`) when a webhook service is configured.
  - approval enforcement is integrated for sensitive operation routes when approvals service is configured:
    - `POST /console/policies/:id/publish` requires approved `POLICY_PUBLISH` queue entry (`approvalId`).
    - `POST /console/key-exports/:id/approve` requires approved `KEY_EXPORT` queue entry (`approvalId`).
- Audit/evidence backend slice is implemented (in-memory + Postgres services + router contracts):
  - `GET /console/audit/events`
  - `GET /console/audit/evidence`
  - query filters are wired for project/environment scope, category/outcome/domain, actor, time windows, and limit bounds.
  - Postgres-backed audit persistence is implemented (`console_audit_events`, `console_audit_evidence`) with tenant RLS and service-level org-isolation tests.
  - relayer route coverage now includes Express + Cloudflare Postgres org-isolation checks for `/console/audit/events` and `/console/audit/evidence`.
  - relay-server demo now seeds deterministic audit and evidence rows for local console testing.
  - audit event emission is now wired for key governance mutations:
    - approval request create/approve/reject,
    - policy publish,
    - key export approval.
  - relayer route coverage now includes service-not-wired behavior, filtered list success paths, and approval-create -> audit-event projection for Express + Cloudflare adapters.
- Dashboard Team members and roles page now consumes live Team/RBAC APIs:
  - `GET /console/members`
  - `POST /console/members/invite`
  - `PATCH /console/members/:id/roles`
  - `DELETE /console/members/:id`
  - role-spec driven invite/update/remove actions are wired with owner/admin mutation gating.
  - browser-level API wiring coverage validates invite -> role update -> remove and status-filter refresh behavior.
- Account settings backend slice is implemented (in-memory + Postgres service + router contracts):
  - `GET /console/account/profile`
  - `PATCH /console/account/profile`
  - `GET /console/account/organizations`
  - `POST /console/account/organizations`
  - `PATCH /console/account/organizations/:orgId`
  - `DELETE /console/account/organizations/:orgId`
  - `POST /console/account/organizations/:orgId/transfer-owner`
  - `POST /console/account/organizations/:orgId/switch-context`
  - account org creation reuses the onboarding org bootstrap path instead of duplicating owner/bootstrap logic.
  - empty-org deletion is implemented with owner-only, non-current-org, no-other-members, and no-wallets guardrails.
  - Postgres-backed account persistence is implemented with `console_user_profiles`, `console_user_backup_emails`, and `console_organizations.created_by_user_id`.
  - focused relayer route coverage is implemented for Express and Cloudflare adapters, including owner transfer and context-switch session re-signing.
- Wallet backend slice is implemented:
  - `GET /console/wallets`
  - `GET /console/wallets/search`
  - `GET /console/wallets/:id`
  - wallet rows are now constrained to valid org/project/environment lineage via Postgres FK enforcement.
  - Postgres-backed org-isolation route tests are implemented for Express and Cloudflare adapters.
- Policy backend lifecycle slice is implemented:
  - `GET /console/policies`
  - `POST /console/policies`
  - `PATCH /console/policies/:id`
  - `POST /console/policies/:id/simulate`
  - `POST /console/policies/:id/publish`
  - `GET /console/policies/assignments`
  - `PUT /console/policies/assignments`
  - `DELETE /console/policies/assignments/:id`
  - mutation RBAC is enforced for policy create/update/publish (`owner`, `admin`, `security_admin`).
  - route coverage now includes policy lifecycle and org-isolation tests for Express and Cloudflare adapters.
  - Postgres policy persistence is implemented (`console_policies`, `console_policy_versions`), including default-policy bootstrap and publish-version snapshots.
  - policy assignment persistence is implemented (`console_policy_assignments`) with precedence resolver (`WALLET` > `ENVIRONMENT` > `PROJECT` > `ORG`).
  - policy coverage now resolves canonical assignments from policy service (with wallet `policyId` fallback when policy service is absent).
  - Postgres-backed org-isolation route tests are implemented for Express and Cloudflare policy endpoints.
- Dashboard wallet list/search routes are now wired behind a frontend feature flag:
  - `VITE_DASHBOARD_WALLETS_ROUTES_ENABLED` (default `true`).
- Dashboard wallet list/search pages now consume live console APIs:
  - `GET /console/wallets`
  - `GET /console/wallets/search`
  - row-level wallet detail fetch via `GET /console/wallets/:id`.
  - cursor pagination controls are wired (`Load more` via `nextCursor`).
- Dashboard wallet list/search queries now inherit selected topbar context and send `projectId` / `environmentId` filters to `/console/wallets*`.
- Dashboard API keys page now consumes live console APIs:
  - `GET /console/api-keys`
  - `POST /console/api-keys`
  - `POST /console/api-keys/:id/rotate`
  - `DELETE /console/api-keys/:id`
  - create/rotate secret reveal-once handling is surfaced in UI.
  - selected topbar environment is used as the API key environment scope default/filter.
- Dashboard webhooks page now consumes live console APIs:
  - `GET/POST/PATCH/DELETE /console/webhooks`
  - `GET /console/webhooks/:id/deliveries`
  - `POST /console/webhooks/:id/replay`
  - endpoint status toggles, delivery history pagination, and replay actions are wired in UI.
- Dashboard billing routes now consume live console APIs:
  - `/dashboard/billing/account` uses `GET /console/billing/overview`, `GET /console/billing/account/activity`, and `POST /console/billing/stripe/checkout-session`
  - `/dashboard/invoices` uses `GET /console/billing/invoices`
  - `/dashboard/invoices/:id` uses `GET /console/billing/invoices/:id`, `/line-items`, `/activity`, and `/pdf`
  - admin-only billing adjustments use `POST /console/billing/adjustments/support-credit` and `POST /console/billing/adjustments/admin-debit`
  - billing account/invoices split, PDF export, low-balance warnings, and internal adjustment visibility are wired in UI.
- Dashboard account settings page now consumes live console APIs:
  - `GET/PATCH /console/account/profile`
  - `GET/POST /console/account/organizations`
  - `PATCH /console/account/organizations/:orgId`
  - `DELETE /console/account/organizations/:orgId`
  - `POST /console/account/organizations/:orgId/transfer-owner`
  - `POST /console/account/organizations/:orgId/switch-context`
  - topbar account-menu cutover now routes directly to `/dashboard/account-settings`.
  - `/dashboard/account-settings` remains reachable while onboarding is incomplete.
  - opening an org from account settings refreshes `orgId`, `projectId`, and `environmentId` together, then routes to onboarding or the default dashboard entry based on target-org readiness.
- Dashboard console frontend clients now share a common HTTP helper for base URL resolution, headers, JSON parsing, and API error normalization (session/context/wallet/api-keys/webhooks/billing).
- Dashboard now bootstraps console auth state via `GET /console/session` and gates wallet page API calls on active session claims.
- Dashboard topbar org/project/environment selectors are now wired to live console APIs:
  - `GET /console/org`
  - `GET /console/projects?status=ACTIVE`
  - `GET /console/environments?projectId=...&status=ACTIVE`
  - project selection now drives environment option loading and keeps selected context aligned to the org->project->environment hierarchy.
- Dashboard org/project/environment management pages now consume live context APIs:
  - `POST/PATCH /console/projects`
  - `POST /console/projects/:id/archive`
  - `POST/PATCH /console/environments`
  - `POST /console/environments/:id/archive`
  - project/environment create/update/archive flows are wired in UI with `owner`/`admin` mutation gating.
  - environment rename/archive controls are project-scoped in UI to mirror org -> project -> environment hierarchy.
  - project list defaults to active rows and supports archived visibility toggle via `status` filtering.
  - environment management now loads server-filtered rows via `GET /console/environments?projectId=...` for selected project scope, with an explicit all-projects scope option.
  - environment list defaults to active rows and supports archived visibility toggle via `status` filtering.
  - project environment counts are sourced from `/console/projects` aggregate fields (`environmentCount`), avoiding extra all-environments scans for count-only rendering.
  - app-settings hierarchy decision logic (project/environment scope resolution + active-project-only environment creation guard) is covered by dedicated unit tests.
  - browser-level app-settings flow coverage validates archived toggles and active-project-only environment creation selection/guard behavior.
  - settings mutation controls are gated in UI to `owner`/`admin`/`security_admin` roles to match backend RBAC.
- Dedicated console insight APIs are implemented for policy/gas/export workflows:
  - `GET /console/policy/coverage`
  - `GET /console/gas/readiness`
  - `GET /console/export/governance`
  - responses are org-scoped and support context filtering (`projectId` / `environmentId` where applicable).
- Console router coverage now includes the new config modules (`gas-sponsorship`, `settings`, `key-exports`, `runtime-snapshots`) across:
  - service-not-wired (`*_not_configured`) behavior,
  - scaffold CRUD success paths,
  - mutation RBAC denies (`forbidden`) by role,
  - validation and domain error paths (`invalid_query`, `invalid_body`, `invalid_scope`, `mfa_required`),
  - cross-org isolation behavior for list/read/mutate/approve paths
    for both Express and Cloudflare adapters.
- Runtime snapshot contract backend slice is now scaffolded and versioned:
  - `GET /console/runtime-snapshots`
  - `GET /console/runtime-snapshots/latest`
  - `POST /console/runtime-snapshots/publish`
  - `POST /console/runtime-snapshots/publish-current`
  - snapshots include `snapshotId`, monotonically increasing `version` per environment scope, `effectiveAt`, `checksum`, and resolved payload envelope.
  - `publish-current` generates payload server-side from currently configured policy/settings/gas modules (with explicit `not_configured` module markers when optional services are absent).
- Dashboard policy engine page now consumes `GET /console/policy/coverage` for policy assignment coverage and unassigned wallet sampling.
- Dashboard policy engine page now consumes policy lifecycle APIs:
  - `GET /console/policies`
  - `POST /console/policies`
  - `PATCH /console/policies/:id`
  - `POST /console/policies/:id/simulate`
  - `POST /console/policies/:id/publish`
  - `GET /console/policies/assignments`
  - `PUT /console/policies/assignments`
  - `DELETE /console/policies/assignments/:id`
  - draft creation, rule updates, simulation, publish, assignment upsert, and assignment delete actions are wired while keeping coverage insights.
  - policy publish controls now integrate with the approval queue and forward the selected approved request id (`approvalId`) to publish when approvals are configured.
- Dashboard gas sponsorship page now consumes live policy-backed APIs:
  - gas sponsorship flows use `GET/POST/PATCH /console/policies` with `kind=GAS_SPONSORSHIP`, plus `POST /console/policies/:id/publish`
  - the dedicated gas page remains a thin adapter over policy APIs, with role-gated actions plus scope-aware payloads.
- Dashboard export keys page now consumes live key export workflow APIs:
  - `GET /console/key-exports`
  - `POST /console/key-exports`
  - `POST /console/key-exports/:id/approve`
  - create request and admin approval controls are wired with status/environment filtering.
  - approve controls now support forwarding an optional approval request ID (`approvalId`) for approval-enforced environments.
- Dashboard approvals queue page now consumes live approval queue APIs:
  - `GET /console/approvals`
  - `POST /console/approvals`
  - `POST /console/approvals/:id/approve`
  - `POST /console/approvals/:id/reject`
  - list filters, create request controls, and approve/reject actions are wired with owner/admin/security-admin role gating.
- Dashboard audit logs and evidence page now consumes live audit APIs:
  - `GET /console/audit/events`
  - `GET /console/audit/evidence`
  - timeline/evidence filters and context-scoped investigation tables are wired in UI.
- Browser-level dashboard API wiring coverage now validates the new page flows:
  - `/dashboard/gas-sponsorship`: gas policy create + mutation flow against mocked `/console/policies` endpoints using `kind=GAS_SPONSORSHIP`.
  - `/dashboard/policy-engine`: approval-backed policy publish flow forwards the selected `approvalId` to `/console/policies/:id/publish`.
  - `/dashboard/export-keys`: key export create + MFA-gated approval flow against mocked `/console/key-exports` endpoints.
  - `/dashboard/approvals`: approval request create + MFA-gated approve + reject + filter flows against mocked `/console/approvals` endpoints.
  - `/dashboard/audit`: audit timeline and evidence filter flows against mocked `/console/audit/*` endpoints.
  - e2e wiring assertions validate `approvalId` forwarding on key-export approve requests.
- Cross-org isolation coverage is implemented for webhook and billing routes (including invoice, payment-intent, overview, and MAW usage paths) with Postgres-backed integration tests.
- CI now executes Postgres-backed console isolation coverage (`console-router`) in `threshold-signing-core`.
- Dedicated Postgres tenant-isolation harness tests are implemented at the console service layer (org/project/environment, wallets, API keys, webhooks, billing, policy-backed gas sponsorship, settings, key exports, runtime snapshots) and wired into the CI-gated console Postgres suite.
- Cross-org mutation denial coverage is implemented for org/project/environment services and routes.
- Direct Postgres FK denial coverage is implemented for invalid cross-org wallet lineage inserts.

Recently completed hardening:

- DB-level tenant context primitives are now introduced (`app.console_namespace`, `app.console_org_id`) with transaction-scoped Postgres client wiring across runtime snapshots, org/project/environment, wallets, API keys, policies, webhooks, config modules, and billing operations.
- RLS policy enforcement is now active for `console_runtime_snapshots`, `console_organizations`, `console_projects`, `console_environments`, `console_wallet_index`, `console_api_keys`, `console_environment_settings`, `console_key_exports`, `console_policies`, `console_policy_versions`, `console_policy_assignments`, `console_webhook_endpoints`, `console_webhook_deliveries`, `console_webhook_attempts`, `console_webhook_dead_letters`, `console_billing_accounts`, `console_billing_credit_purchases`, `console_billing_ledger_accounts`, `console_billing_ledger_entries`, `console_billing_ledger_postings`, `console_usage_meter_events`, `console_usage_rollups_monthly`, `console_invoices`, `console_invoice_line_items`, and `console_stripe_webhook_events`, with dedicated DB-level policy tests for each completed slice.
- Monthly billing finalization now runs with explicit org targets (`orgIds`) to remain compatible with FORCE-RLS billing tables.
- Stripe webhook reconciliation now resolves prepaid purchase settlement without the removed payment-intent/provider-ref tables.
- Runtime snapshot publish now writes tenant-scoped outbox events (`console_runtime_snapshot_outbox`) and a cron-dispatch runner exists with org-targeted advisory-lock execution (default runner requires an explicit dispatch callback).
- Webhook delivery retries now have a dedicated Postgres retry-dispatch runner (`runPostgresConsoleWebhookRetryDispatch`) with configurable attempt caps/backoff windows and Cloudflare cron advisory-lock wiring.
- Cloudflare relay worker cron enablement is now resolved from a unified feature-flag snapshot, so billing/outbox/webhook cron jobs can run without requiring legacy `ENABLE_ROTATION`.
- Worker cron-flag semantics are covered by focused unit tests (`cloudflare-worker-cron-flags.test.ts`) to prevent regressions in cron activation behavior.
- Cloudflare cron jobs now support per-job cron-expression allowlists (`cronExpressions`) so billing finalization, runtime snapshot outbox dispatch, and webhook retry dispatch can run on independent schedules from the same worker.
- Worker cron config assembly is now extracted into a dedicated helper (`cronConfig.ts`) and covered by focused mapping tests (`cloudflare-worker-cron-config.test.ts`) for env parsing, fallback semantics, and runtime snapshot outbox dispatch wiring.
- Worker scheduled orchestration is now extracted into `scheduledHandler.ts` and covered by integration tests (`cloudflare-worker-scheduled.test.ts`) validating env flag resolution, cron option handoff, and scheduled event forwarding.
- Worker deployment config now includes explicit staging/production console cron scaffolding (`BILLING_*`, `RUNTIME_SNAPSHOT_OUTBOX_*`, `WEBHOOK_RETRY_*`) with jobs disabled by default and per-job cron expressions declared for controlled enablement.
- Worker scheduled path now performs pre-flight cron config validation and emits structured warnings for missing required job config (`postgresUrl` / `orgIds`) with test coverage on warning emission.
- Worker cron env surface now has explicit defaults for all related vars in staging/production (`ENABLE_ROTATION`, `*_POSTGRES_URL`, `*_ORG_IDS`, `*_CRONS`, limits/backoff, and period override), with safe disabled/no-op defaults.
- Stripe webhook projection coverage now includes prepaid checkout settlement (`checkout.session.completed`) with idempotent event processing across in-memory and Postgres billing services and router suites.
- Browser-level e2e wiring coverage now includes:
  - `/pricing` -> checkout-session API handoff and redirect behavior.
  - `/dashboard/billing/account` top-up and internal adjustment controls.
  - `/dashboard/invoices` list/detail/PDF flows.

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

## Governance Defaults (Locked)

1. Runtime snapshot contract: full versioned per-environment document (`snapshot_id`, `version`, `effective_at`, resolved settings/policy/sponsorship payloads, integrity hash).
2. Enterprise isolation trigger: manual enterprise/compliance trigger.
3. Enterprise isolation SLA targets: `99.95%` availability, `RPO 15m`, `RTO 4h`.
4. Approval defaults:
   - policy publish: `1 admin`
   - key export: `2 admin + MFA + reason`
5. Role scope model: hybrid
   - org-scoped roles: `owner`, `admin`, `security_admin`, `billing_admin`
   - project-scoped roles: `developer`, `support`, `ops`
6. Retention defaults:
   - runtime + webhook: `180d` hot + `2y` archive
   - billing + payments + audit: `7y`

## Workstreams

### A) Dashboard Frontend

Scope:

- Data-fetching layer and typed API client.
- Feature pages for wallets, policy, settings, api keys, webhooks, exports, and billing.
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
- Billing orchestration for prepaid Stripe Checkout, ledger projections, and internal adjustments.

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
  - `GET /console/policy/coverage` (implemented)
  - `GET/POST/PATCH /console/policies` (implemented)
  - `POST /console/policies/:id/simulate` (implemented)
  - `POST /console/policies/:id/publish` (implemented)
  - `GET/PUT /console/policies/assignments` (implemented)
  - `DELETE /console/policies/assignments/:id` (implemented)
- Data:
  - `policies`
  - `policy_versions`
  - `policy_assignments`
  - `policy_decision_logs`
- Jobs:
  - policy publish propagation and snapshot generation

### `/dashboard/gas-sponsorship`

- APIs:
  - `GET /console/gas/readiness` (implemented)
  - gas sponsorship flows use `GET/POST/PATCH /console/policies` with `kind=GAS_SPONSORSHIP` and `POST /console/policies/:id/publish`
- Data:
  - sponsorship budget and telemetry tables
- Jobs:
  - spend rollup and threshold alerting

### `/dashboard/export-keys`

- APIs:
  - `GET /console/export/governance` (implemented)
  - `GET/POST /console/key-exports` (scaffolded; in-memory + postgres service + router wiring)
  - `POST /console/key-exports/:id/approve` (scaffolded; in-memory + postgres service + router wiring)
- Data:
  - export request and approval tables
  - immutable export audit log
- Jobs:
  - approval timeout/escalation and audit artifact writer

### `/dashboard/audit`

- APIs:
  - `GET /console/audit/events` (scaffolded; in-memory service + router wiring)
  - `GET /console/audit/evidence` (scaffolded; in-memory service + router wiring)
- Data:
  - `audit_log` timeline rows (category/action/outcome/actor/scope metadata)
  - evidence bundle rows linking audit event IDs to export/payment/approval references
- Jobs:
  - deferred: immutable audit projection and evidence export materialization jobs

### `/dashboard/api-keys`

- APIs:
  - `GET/POST/DELETE /console/api-keys`
  - `POST /console/api-keys/:id/rotate`
- Data:
  - `api_keys`
  - `api_key_scopes`
  - `api_key_usage_stats`
- Current product scope surface:
  - `accounts.create`
  - `wallets.read`
- Not in the current product surface:
  - `wallets.sign`
  - `accounts.sync`
  - `billing.read`
- Jobs:
  - key-usage anomaly detector

### `/dashboard/webhooks`

- APIs:
  - `GET/POST/PATCH/DELETE /console/webhooks`
  - `GET /console/webhooks/:id/deliveries` (`limit`, `cursor`)
  - `GET /console/webhooks/:id/attempts` (`deliveryId`, `limit`, `cursor`)
  - `GET /console/webhooks/:id/dead-letters` (`deliveryId`, `includeResolved`, `limit`, `cursor`)
  - `POST /console/webhooks/:id/replay`
- Pagination contract:
  - Responses return `items` and optional `nextCursor`.
  - Invalid cursor returns `400` with code `invalid_query`.
- Data:
  - `webhook_endpoints`
  - `webhook_secrets`
  - `webhook_deliveries`
  - `webhook_attempts`
  - `webhook_dead_letters`
- Jobs:
  - delivery worker with retry/backoff and DLQ processor

### `/dashboard/billing`

- APIs:
  - `GET /console/billing/overview`
  - `GET /console/billing/account/activity`
  - `GET /console/billing/usage/monthly-active-wallets`
  - `POST /console/billing/usage/events`
  - `GET /console/billing/invoices`
  - `GET /console/billing/invoices/:id`
  - `GET /console/billing/invoices/:id/line-items`
  - `GET /console/billing/invoices/:id/activity`
  - `GET /console/billing/invoices/:id/pdf`
  - `POST /console/billing/invoices/generate`
  - `POST /console/billing/adjustments/support-credit`
  - `POST /console/billing/adjustments/admin-debit`
  - `POST /console/billing/stripe/checkout-session`
  - `POST /console/billing/stripe/webhook` (provider callback endpoint)
- Data:
  - `billing_accounts`
  - `billing_credit_purchases`
  - `billing_ledger_accounts`
  - `billing_ledger_entries`
  - `billing_ledger_postings`
  - `invoices`
  - `invoice_line_items`
  - `stripe_webhook_events`
- Jobs:
  - invoice generation + usage rollup jobs
  - Stripe webhook reconciler

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

### Milestone 2: Policy Engine (2-3 weeks)

Frontend:

- Policy authoring UI (draft/publish flow).
- Policy assignment UI (org/project/segment/wallet scope).

Backend:

- Implement:
  - `GET/POST/PATCH /console/policies`
  - `POST /console/policies/:id/publish`
  - `POST /console/policies/:id/simulate`
- Add policy precedence resolution and simulation evaluator.
- Enforce default approvals:
  - policy publish: `1 admin`

Data:

- Land policy tables (`policies`, `policy_versions`, `policy_assignments`, `policy_decision_logs`).

Exit criteria:

- Policies can be drafted, simulated, published, and audited.

### Milestone 3: API Keys + Webhooks + Prepaid Billing (2-3 weeks)

Frontend:

- API key lifecycle flows: create, reveal-once, revoke, rotate.
- Webhook endpoint management + delivery log views + replay actions.
- Billing pages for prepaid balance, invoices, receipts/statements, and internal adjustment controls.

Backend:

Status (backend):

- [x] API key routes (`/console/api-keys`) are implemented.
- [x] API key Postgres persistence and cross-org isolation tests are implemented.
- [x] Webhook CRUD + delivery/replay flows are implemented.
- [x] Webhook attempts/dead-letter list endpoints with cursor pagination are implemented.
- [x] Billing overview/invoice/usage/prepaid route set is implemented.
- [x] Stripe checkout + webhook settlement flow is implemented.
- [x] Ledger-first projection rebuild is implemented.
- [x] Admin-only manual adjustment controls are implemented.
- [x] Postgres-backed cross-org isolation route tests are implemented for webhook and billing surfaces.

- Implement:
  - `GET/POST/DELETE /console/api-keys`
  - `POST /console/api-keys/:id/rotate`
  - `GET/POST/PATCH/DELETE /console/webhooks`
  - `GET /console/webhooks/:id/deliveries`
  - `POST /console/webhooks/:id/replay`
  - `GET /console/billing/overview`
  - `GET /console/billing/account/activity`
  - `GET /console/billing/invoices`
  - `GET /console/billing/invoices/:id/activity`
  - `GET /console/billing/invoices/:id/pdf`
  - `POST /console/billing/adjustments/support-credit`
  - `POST /console/billing/adjustments/admin-debit`
  - `POST /console/billing/stripe/checkout-session`
  - `POST /console/billing/stripe/webhook`
- Add webhook signer and retry worker.
- Add Stripe integration for checkout-session creation and webhook verification.
- Add dashboard return handling (`success`/`cancel`) and prepaid balance refresh.
- Keep provider boundaries explicit via billing provider adapters (Stripe checkout + webhook settlement only).
- Enforce billing RBAC for internal adjustments and owner escalation for large admin debits.

Data:

- Add key and webhook tables including delivery attempts/dead-letter records.
- Add usage timestamps and basic anomaly flags.
- Add billing ledger, purchase, invoice, and Stripe webhook tables.

Exit criteria:

- API key secrets are never retrievable after creation.
- Failed webhooks retry with backoff and support replay.
- Billing accepts prepaid Stripe Checkout top-ups and projects receipts/statements from ledger state.
- Internal manual adjustments are append-only and audited.
- Non-admin users cannot access internal adjustment routes.

### Milestone 4: Export Keys + Gas Sponsorship Controls (2-3 weeks)

Frontend:

- Export settings modes and approval workflow UX.
- Gas sponsorship controls with budget dashboards.
Backend:

- Implement:
  - `GET/POST /console/key-exports`
  - `POST /console/key-exports/:id/approve`
  - gas sponsorship policy CRUD through `GET/POST/PATCH /console/policies` with `kind=GAS_SPONSORSHIP`
  - `POST /console/policies/:id/publish` for gas publish
- Add step-up and approval guardrails for export actions.
- Enforce default key-export approval: `2 admin + MFA + reason`.

Data:

- Add export request/approval tables and immutable export logs.
- Add sponsorship budget and spend telemetry tables.

Exit criteria:

- Sensitive export changes require policy-defined approvals.
- Sponsorship controls affect runtime config snapshots.

### Milestone 5: Governance Hardening (2-4 weeks)

Frontend:

- Team/role management and audit investigation views.

Backend:

- Add advanced RBAC, support-access controls, and approval workflows.

Data:

- Add retention policies and compliance export jobs.

Exit criteria:

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
- billing usage and invoice generation,
- Stripe checkout settlement and invoice export changes,
- internal billing adjustment actions.

### Runtime snapshot contract

Runtime consumers read full versioned environment snapshots:

- Envelope fields:
  - `snapshot_id`
  - `version`
  - `effective_at`
  - `org_id`, `project_id`, `environment_id`
  - `checksum`
- Payload includes resolved runtime config:
  - effective policy assignment + limits
  - gas sponsorship controls

### Billing journal contract

Define one append-only billing journal model:

- Canonical write objects:
  - `ledger_account`
  - `ledger_entry`
  - `ledger_posting`
- Contract rule:
  - financial writes append balanced journal postings,
  - balances are projections, not edited fields,
  - receipts/statements are regenerated from ledger + purchase state,
  - manual corrections are compensating entries, not row mutation,
  - internal-only adjustment details never leak into customer-facing PDF exports.

### MAW billing metric contract

Use `Monthly Active Wallets (MAW)` as canonical wallet usage metric:

- Window: calendar month in `UTC`.
- Unit: distinct `wallet_id` per organization per month.
- Billable actions: successful `transfer`, `swap`, `approve`, `contract_call`.
- Exclusions: wallet creation-only activity, simulations, failed transactions, internal retries.
- Output:
  - `billable_active_wallet_count`
  - deterministic evidence rows linking each counted wallet to at least one qualifying action event.

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
- Retention defaults:
  - runtime + webhook: `180d` hot + `2y` archive
  - billing + payments + audit: `7y`

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
6. Billing tests:
   - Stripe checkout settlement + webhook reconciliation,
   - receipt/statement projection rebuild,
   - internal adjustment visibility and PDF export policy.
7. Billing journal tests:
   - balanced postings accepted,
   - malformed or duplicate journal writes rejected,
   - compensating-entry behavior remains append-only.
8. Billing RBAC tests:
   - internal adjustments are restricted to authorized roles,
   - large admin debits require stronger authorization.
9. MAW billing tests:

- distinct-wallet counting per org/month is correct,
- only successful billable actions contribute,
- excluded action categories never affect MAW totals.

## Immediate Next Steps (Execution Checklist)

- [x] Lock API contract skeleton for Milestones 0-3 (including billing + payments).
- [x] Create backend service scaffold and migration pipeline.
- [x] Implement org/project/environment read APIs first.
- [x] Implement org/project/environment mutation APIs with RBAC + cross-org denial tests.
- [x] Implement Postgres-backed API key persistence + org-isolation route tests.
- [x] Implement `/console/wallets` list/detail/search APIs.
- [x] Wire dashboard route behind a feature flag for wallet list/search/detail pages.
- [x] Land RLS test harness and cross-tenant denial tests in CI (include console Postgres suites).
- [x] Define billing provider adapter boundaries (Stripe checkout + webhook settlement) before endpoint implementation.
- [x] Implement dedicated console insight contracts for policy/gas/export (`/console/policy/coverage`, `/console/gas/readiness`, `/console/export/governance`).
- [x] Wire policy/gas/export dashboard pages to dedicated insight contracts.
- [x] Extend console router tests to cover insight contracts (express/cloudflare + Postgres org isolation).

## Post-Refactor Next Steps (Open Checklist)

- [x] Add dashboard runtime snapshot UI wiring (`latest`, history list, and `publish-current` action) with role-gated controls.
- [x] Add relay/runtime consumer integration for versioned environment snapshots (read latest by org/project/environment and validate checksum/version semantics).
- [x] Implement DB-level tenant context variables + table-by-table RLS policies for console tables, with policy tests.
- [x] Introduce outbox-backed runtime snapshot publish events so runtime consumers can subscribe to config changes deterministically.
- [x] Add API contract tests for runtime snapshot endpoints (`/console/runtime-snapshots*`) including publish-current payload-resolver semantics and `not_configured` module markers.
- [x] Add pricing page -> Stripe Checkout session wiring (CTA calls backend checkout-session endpoint and redirects to hosted checkout).
- [x] Add Stripe Checkout return route handling in dashboard billing (`success`/`cancel`, status banners, idempotent refresh).
- [x] Add dashboard billing split routes (`/dashboard/billing/account`, `/dashboard/invoices`, `/dashboard/invoices/:invoiceId`).
- [x] Add internal manual adjustment routes and UI controls with projected-balance preview.
- [x] Add webhook handling coverage for prepaid checkout settlement (`checkout.session.completed`) with idempotent projection.
- [x] Add e2e/route tests for pricing -> checkout handoff and dashboard post-checkout state.
- [x] Add Ops Cockpit dashboard route to aggregate pending approvals, failed payments, webhook dead letters, queued audit exports, enterprise isolation requests, and onboarding telemetry alerts.
- [x] Add backend Ops Cockpit summary endpoint (`GET /console/ops-cockpit/summary`) with Express/Cloudflare parity and per-module degradation states.
- [x] Switch dashboard Ops Cockpit page from client fan-out to single summary endpoint consumption.
- [x] Add Ops Cockpit row-level dead-letter replay quick action wired to `POST /console/webhooks/:id/replay`, with e2e API-wiring coverage.
- [x] Add Ops Cockpit row-level pending-approval approve/reject quick actions wired to `/console/approvals/:id/approve|reject`, with e2e API-wiring coverage.
- [x] Add Ops Cockpit row-level queued-audit-export requeue quick action using existing `/console/audit/exports` list/create contracts, with e2e API-wiring coverage.
- [x] Split Postgres config into signer and console logical DB targets with separate migration runners and least-privilege DB users.
  - Progress: relay-server example now requires explicit `CONSOLE_POSTGRES_URL` for console-domain Postgres backends so console billing/webhooks/observability can stay separate from threshold runtime stores.
  - Progress: relay-server now includes explicit domain migration commands:
    - `postgres:migrate:signer` (`POSTGRES_MIGRATION_URL` -> `POSTGRES_URL`)
    - `postgres:migrate:console` (`CONSOLE_POSTGRES_MIGRATION_URL` -> `CONSOLE_POSTGRES_URL`)
    - `postgres:migrate:all`
  - Progress: relay-server now includes local split-domain DB/bootstrap automation (`postgres:bootstrap:split`) for signer/console runtime+migrator roles, databases, and grants.
  - Progress: relay-server supports strict migration mode with `CONSOLE_BILLING_ENSURE_SCHEMA=0` and `CONSOLE_WEBHOOKS_ENSURE_SCHEMA=0` to disable startup schema auto-creation.
  - Progress: relay-server now includes explicit least-privilege verification (`postgres:verify:split`) and validated local flow (`postgres:up` -> `postgres:bootstrap:split` -> `postgres:migrate:all` -> `postgres:verify:split`).
  - Progress: relay-server now exposes a one-shot bootstrap+migrate+verify command (`postgres:setup:split`) for repeatable local bring-up.
  - Progress: relay-server now exposes a one-shot monolith-to-split data migration command (`postgres:migrate:split-from-monolith`) with explicit source/target envs.
  - Progress: local migration from monolith `seams` into `seams_signer` + `seams_console` has been executed and verified for table-count parity across signer tables and most console tables.
  - Progress: migration runner now logs/skips legacy-incompatible rows missing required target fields (notably historical `console_payment_state_transitions` rows with `NULL org_id`) and tracks these for explicit follow-up policy.
  - Progress: CI now includes a dedicated `relay-server-postgres-split-smoke` job that executes split bootstrap+migrate+verify and always tears down compose resources.
  - Progress: verifier failure-path coverage now includes invalid-identifier fast-fail assertions (`tests/unit/postgresVerifySplitDomains.script.unit.test.ts`).
  - Progress: threshold-core CI now runs `test:unit:relay-server-scripts`, gating verifier-script unit checks on every run.

## Open Decisions

- None currently blocking implementation sequencing.
