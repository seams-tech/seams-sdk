# SaaS DB Schema Plan

Date updated: February 19, 2026

## Objective

Define a production-ready database model for SaaS dashboard features, while keeping runtime SDK concerns separate from control-plane concerns.

This plan covers:

- Organization and team account modeling.
- Project and environment modeling.
- Wallet/user data isolation strategy.
- Policy engine configuration and versioning.
- Billing for monthly plans, active-wallet usage, and credits.
- Additional platform concerns needed for secure multi-tenant operation.

## Scope Boundary

- `SDK + relay`: signing/runtime execution path only.
- `SaaS backend (new app)`: org/project/admin/policy/billing/control-plane features.
- Shared contracts only via versioned API schemas and minimal shared types package.

## Tenancy and Isolation Plan

### Recommended default

Use one shared Postgres database with tenant-aware tables and strict RLS:

- Every tenant row includes `org_id`.
- Project-scoped rows include `project_id`.
- Session context sets tenant vars per request.
- RLS is default-deny; policies only allow current tenant scope.

### Enterprise isolation tier

Support dedicated database (or dedicated schema) per organization for high-compliance enterprise customers.

### Decision on schema-per-project

Do not use schema-per-project by default.

Reason:

- High operational overhead (migrations, monitoring, backups).
- Harder cross-project reporting.
- More complexity without proportional security benefit if RLS + key design are correct.

## High-Level Domain Model

1. `Organization` has many `Memberships`, `Projects`, `BillingAccounts`, and `AuditEvents`.
2. `Project` belongs to `Organization`; has many `Environments`, `Policies`, `Wallets`, and `APIKeys`.
3. `Environment` belongs to `Project`; scopes runtime settings and secrets.
4. `Wallet/User runtime data` is project-scoped and tenant-enforced.
5. `Policy engine` is versioned and assigned at org/project/wallet-segment levels.
6. `Billing` rolls up usage events into invoices and applies credits from an immutable ledger.

## Schema Plan by Domain

### 1) Identity and Access

Tables:

- `users`
- `organizations`
- `organization_memberships`
- `organization_invites`
- `roles`
- `role_permissions`
- `service_accounts`
- `sessions` (optional; if needed for dashboard auth)

Notes:

- Membership is the source of truth for org-level access.
- Roles can be org-level and project-level.
- Support account states: invited, active, suspended, removed.

### 2) Projects and Environments

Tables:

- `projects`
- `environments` (for example: dev, staging, prod)
- `project_settings`
- `environment_settings`
- `project_key_rings`
- `key_versions`

Notes:

- Key material should stay in KMS/HSM; DB stores references and metadata only.
- Environment settings include allowed origins, cookie/JWT config, optional IP allowlist.

### 3) Wallet and User Runtime Data

Tables:

- `wallets`
- `wallet_owners`
- `wallet_balances_snapshot`
- `wallet_activity_events`
- `wallet_status_history`
- `wallet_segments`

Notes:

- Keep runtime-heavy tables partitioned by time where needed.
- All runtime tables include `org_id`, `project_id`, and optionally `environment_id`.

### 4) Policy Engine

Tables:

- `policies`
- `policy_versions` (immutable rule documents)
- `policy_assignments`
- `policy_publish_events`
- `policy_simulation_runs`
- `policy_decision_logs`

Notes:

- Policy publication must create immutable version records.
- Policy rules should be JSON with schema validation version attached.
- Assignments should support precedence rules (wallet > segment > project > org).

### 5) Billing and Metering

Tables:

- `billing_accounts`
- `subscriptions`
- `usage_meter_events` (append-only)
- `usage_rollups_daily`
- `usage_rollups_monthly`
- `credit_ledger` (append-only, immutable adjustments)
- `invoices`
- `invoice_line_items`
- `payments`

Billing support:

- Monthly org subscription: from `subscriptions`.
- Active-wallet usage: meter event definition + monthly rollup.
- Credits billing: consume credits through ledger debits before final charge.

Critical rule:

- Define one canonical "active wallet" metric (for example: at least one successful signed action in billing month) and version it.

### 6) Integrations and Automation

Tables:

- `api_keys`
- `api_key_scopes`
- `api_key_usage_stats`
- `webhook_endpoints`
- `webhook_secrets`
- `webhook_deliveries`
- `webhook_attempts`
- `webhook_dead_letters`

Notes:

- API key secret is shown once, then only stored as hash.
- Webhook secrets are encrypted at rest and rotate with versioning.

### 7) Governance, Audit, and Approvals

Tables:

- `audit_log` (append-only)
- `approval_requests`
- `approval_steps`
- `change_requests` (optional)
- `support_access_grants`

Notes:

- Capture actor, action, resource type/id, diff summary, timestamp, request id.
- Protect audit table against updates/deletes by app role.

## Cross-Cutting Data Rules

1. Use UUID primary keys for externally referenced resources.
2. Every tenant table has `created_at`, `updated_at`, and `deleted_at` (soft delete only where needed).
3. Composite uniqueness includes tenant scope.
4. Foreign keys for scoped entities include tenant columns.
5. Idempotency keys for mutation endpoints (`idempotency_keys` table).
6. Outbox table for reliable event publication (`event_outbox`).

## Security and Compliance Requirements

- RLS on all tenant tables.
- Encryption at rest and TLS in transit.
- Secrets never stored plaintext.
- Immutable log strategy for policy, key export, billing, and admin actions.
- Data retention windows and deletion workflows (including legal hold support).

## Suggested Physical Layout

Schemas:

- `control`: org, projects, settings, memberships, policy configs, billing metadata.
- `runtime`: wallets, wallet events, search indexes, policy decisions.
- `audit`: immutable logs and compliance records.

Optional at scale:

- Read replicas for search/list APIs.
- Separate OLAP sink for analytics-heavy queries.

## Rollout Plan

### Phase 0: Foundation

- Create core tenancy tables: `organizations`, `projects`, `environments`, `organization_memberships`.
- Implement RLS and tenant context middleware.
- Add `audit_log` and `event_outbox`.

### Phase 1: MVP Control Plane

- Add policy tables with versioning and assignments.
- Add API key and webhook tables.
- Add app/environment settings tables.
- Add basic billing account + subscription records.

### Phase 2: Usage and Billing

- Add `usage_meter_events` ingestion.
- Build daily/monthly rollup jobs.
- Add invoice generation and credit ledger consumption.
- Add active-wallet billing metric computation.

### Phase 3: Hardening and Enterprise

- Add approval workflows for risky changes.
- Add enterprise isolation mode (dedicated DB or schema).
- Add backup/restore automation and tenant export.
- Add support-access controls and compliance reporting pack.

## Open Decisions to Finalize Before Migration

1. Canonical definition of "active wallet" for billing.
2. Whether environment is mandatory for every runtime wallet row.
3. Which roles are global vs project-scoped.
4. Enterprise tenant isolation SLA and trigger threshold.
5. Retention periods by table class (runtime, billing, audit, webhook logs).

## Deliverables from This Plan

1. ERD v1 (control + runtime + audit).
2. Migration set `0001` through `000N` for Phase 0 and Phase 1.
3. RLS policy test suite.
4. Metering and invoicing job specs.
5. Operational runbook for tenant isolation and incident response.
