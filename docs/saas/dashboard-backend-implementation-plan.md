# Dashboard + Backend Implementation Plan

Date updated: February 25, 2026

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

## Governance Defaults (Locked)

1. Runtime snapshot contract: full versioned per-environment document (`snapshot_id`, `version`, `effective_at`, resolved settings/policy/sponsorship payloads, integrity hash).
2. Enterprise isolation trigger: manual enterprise/compliance trigger.
3. Enterprise isolation SLA targets: `99.95%` availability, `RPO 15m`, `RTO 4h`.
4. Approval defaults:
   - policy publish: `1 admin`
   - key export: `2 admin + MFA + reason`
   - risky security settings: `1 admin + MFA`
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
- Billing orchestration for Stripe card payments and stablecoin settlement rails.

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
  - runtime snapshot publisher writes full versioned per-environment snapshot documents

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

### `/dashboard/billing`

- APIs:
  - `GET /console/billing/overview`
  - `GET /console/billing/invoices`
  - `GET /console/billing/invoices/:id`
  - `GET/POST/DELETE /console/billing/payment-methods`
  - `POST /console/billing/payment-methods/:id/default`
  - `POST /console/billing/stripe/setup-intent`
  - `POST /console/billing/stripe/payment-intent`
  - `GET /console/billing/stablecoins/assets`
  - `POST /console/billing/stablecoins/quotes`
  - `POST /console/billing/stablecoins/payment-intents`
  - `GET /console/billing/stablecoins/payment-intents/:id`
- Data:
  - `billing_accounts`
  - `subscriptions`
  - `invoices`
  - `invoice_line_items`
  - `payments`
  - `invoice_payment_rail_locks`
  - `billing_payment_methods`
  - `stablecoin_payment_quotes`
  - `stablecoin_payment_intents`
  - `stablecoin_settlement_events`
- Jobs:
  - invoice generation + usage rollup jobs
  - Stripe webhook reconciler
  - stablecoin settlement watcher + confirmation reconciler

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
- Enforce default approvals:
  - policy publish: `1 admin`
  - risky security settings changes: `1 admin + MFA`

Data:

- Land policy tables (`policies`, `policy_versions`, `policy_assignments`, `policy_decision_logs`).
- Add settings tables for origins/cookies/JWT and environment scoping.

Exit criteria:

- Policies can be drafted, simulated, published, and audited.
- App settings are environment-specific and validated.

### Milestone 3: API Keys + Webhooks + Billing Payments (2-3 weeks)

Frontend:

- API key lifecycle flows: create, reveal-once, revoke, rotate.
- Webhook endpoint management + delivery log views + replay actions.
- Billing pages for overview, invoices, card payment methods, and stablecoin payment intents.

Backend:

- Implement:
  - `GET/POST/DELETE /console/api-keys`
  - `POST /console/api-keys/:id/rotate`
  - `GET/POST/PATCH/DELETE /console/webhooks`
  - `GET /console/webhooks/:id/deliveries`
  - `POST /console/webhooks/:id/replay`
  - `GET /console/billing/overview`
  - `GET /console/billing/invoices`
  - `GET/POST/DELETE /console/billing/payment-methods`
  - `POST /console/billing/payment-methods/:id/default`
  - `POST /console/billing/stripe/setup-intent`
  - `POST /console/billing/stripe/payment-intent`
  - `GET /console/billing/stablecoins/assets`
  - `POST /console/billing/stablecoins/quotes`
  - `POST /console/billing/stablecoins/payment-intents`
- Add webhook signer and retry worker.
- Add Stripe integration (setup intents, payment intents, webhook verification).
- Add stablecoin quote/payment-intent lifecycle and on-chain settlement reconciliation for `USDC` and `USDT`.
- Enforce `USDC`/`USDT` funding support across all currently supported chains: `Ethereum`, `Base`, `Tempo`, `Arc Circle`, and `NEAR`.
- Enforce chain finality defaults for stablecoin settlement:
  - `Ethereum`: `12` confirmations, `360` minute confirmation timeout, `24` hour reorg-risk window.
  - `Base`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
  - `Tempo`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
  - `Arc Circle`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
  - `NEAR`: `10` confirmations, `60` minute confirmation timeout, `6` hour reorg-risk window.
- Enforce single-rail invoice settlement: `Stripe/card` or `stablecoin`; mixed-rail payment application is rejected.
- Enforce billing RBAC: only `admin` can call `POST/DELETE /console/billing/payment-methods`.
- Enforce billing RBAC: only `admin` can call `POST /console/billing/payment-methods/:id/default`.

Data:

- Add key and webhook tables including delivery attempts/dead-letter records.
- Add usage timestamps and basic anomaly flags.
- Add billing/payment tables for Stripe payment methods and stablecoin settlement tracking.

Exit criteria:

- API key secrets are never retrievable after creation.
- Failed webhooks retry with backoff and support replay.
- Billing accepts card payments via Stripe and stablecoin settlement via `USDC` and `USDT`.
- Invoice settlement is single-rail only (no card + stablecoin mixing on the same invoice).
- Non-admin attempts to add/remove card payment methods are denied.
- Non-admin attempts to set default card payment method are denied.

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
- Enforce default key-export approval: `2 admin + MFA + reason`.

Data:

- Add export request/approval tables and immutable export logs.
- Add sponsorship budget and spend telemetry tables.

Exit criteria:

- Sensitive export changes require policy-defined approvals.
- Sponsorship and smart wallet controls affect runtime config snapshots.

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
- Stripe payment and invoice status changes,
- stablecoin payment intent and settlement status changes.

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
  - app security settings
  - gas sponsorship + smart-wallet controls

### Payment lifecycle contract

Define one shared payment attempt lifecycle across Stripe and stablecoin rails:

- States:
  - `CREATED`
  - `ACTION_REQUIRED`
  - `PENDING`
  - `CONFIRMING`
  - `SETTLED`
  - `PARTIALLY_SETTLED`
  - `OVERPAID`
  - `FAILED`
  - `CANCELED`
  - `EXPIRED`
  - `REFUNDED`
  - `DISPUTED`
- Allowed transitions:
  - `CREATED` -> `ACTION_REQUIRED` | `PENDING` | `FAILED` | `CANCELED`
  - `ACTION_REQUIRED` -> `PENDING` | `FAILED` | `CANCELED` | `EXPIRED`
  - `PENDING` -> `CONFIRMING` | `SETTLED` | `PARTIALLY_SETTLED` | `OVERPAID` | `FAILED` | `CANCELED` | `EXPIRED`
  - `CONFIRMING` -> `SETTLED` | `PARTIALLY_SETTLED` | `OVERPAID` | `FAILED`
  - `SETTLED` -> `REFUNDED` | `DISPUTED`
  - `DISPUTED` -> `SETTLED` | `REFUNDED`
- Contract rule:
  - illegal transitions are rejected at API and persistence layers, and emitted as auditable validation failures.
  - each invoice has one locked settlement rail (`CARD` or `STABLECOIN`) and payment events from other rails are rejected.
  - `CONFIRMING` -> `SETTLED` requires chain-specific confirmation threshold; timeout breaches transition to `FAILED` with reason `CONFIRMATION_TIMEOUT`.
- Chain finality defaults (stablecoin payments):
  - `Ethereum`: `12` confirmations, `360` minute confirmation timeout, `24` hour reorg-risk window.
  - `Base`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
  - `Tempo`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
  - `Arc Circle`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
  - `NEAR`: `10` confirmations, `60` minute confirmation timeout, `6` hour reorg-risk window.

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
   - Stripe card lifecycle + webhook reconciliation,
   - stablecoin quote expiry + settlement confirmation paths.
7. Payment-state tests:
   - valid transitions accepted,
   - invalid transitions rejected,
   - terminal state immutability enforced except listed post-settlement transitions.
8. Split-payment policy tests:
   - mixed card + stablecoin settlement attempts are rejected,
   - invoice rail lock remains immutable while invoice is open.
9. Billing RBAC tests:
   - only `admin` can add/remove card payment methods,
   - non-admin receives authorization denial for `POST/DELETE /console/billing/payment-methods`.
   - only `admin` can set default card payment method (`POST /console/billing/payment-methods/:id/default`).
10. Chain-finality tests:
   - settlement blocked before threshold and allowed once threshold is met,
   - confirmation timeout transitions to `FAILED` with `CONFIRMATION_TIMEOUT`,
   - post-settlement risk-window flags are emitted per chain policy.
11. MAW billing tests:
   - distinct-wallet counting per org/month is correct,
   - only successful billable actions contribute,
   - excluded action categories never affect MAW totals.

## Immediate Next Steps (Execution Checklist)

1. Lock API contract skeleton for Milestones 0-3 (including billing + payments).
2. Create backend service scaffold and migration pipeline.
3. Implement org/project/environment read APIs first.
4. Wire dashboard wallets list route to live API behind feature flag.
5. Land RLS test harness and cross-tenant denial tests in CI.
6. Define payment provider adapter boundaries (Stripe + stablecoin watcher) before endpoint implementation.

## Open Decisions

- None currently blocking implementation sequencing.
