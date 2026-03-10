# SaaS DB Schema Plan

Date updated: March 10, 2026

Related implementation plan:

- `docs/saas/dashboard-backend-implementation-plan.md`

## Objective

Define a production-ready database model for SaaS dashboard features, while keeping runtime SDK concerns separate from console/admin concerns.

This plan covers:

- Organization and team account modeling.
- Project and environment modeling.
- Wallet/user data isolation strategy.
- Policy engine configuration and versioning.
- Billing for monthly plans, active-wallet usage, credits, and payment rails.
- Additional platform concerns needed for secure multi-tenant operation.

## Scope Boundary

- `SDK + relay`: signing/runtime execution path only.
- `SaaS console backend (new app)`: org/project/admin/policy/billing features.
- Shared contracts only via versioned API schemas and minimal shared types package.

## API Namespace Boundary

- `/console/*` routes map to SaaS/admin APIs backed by this schema.
- `/relay/*` routes map to runtime/transaction APIs and should stay isolated at auth + routing layers.

## Tenancy and Isolation Plan

### Recommended default

Use one shared Postgres cluster/instance with separate logical databases per major domain:

- `tatchi_signer` logical DB for threshold signing + relay runtime paths.
- `tatchi_console` logical DB for `/console` control-plane features (org/project/environment, settings, billing, subscriptions, webhooks, API keys).
- Within each logical DB, enforce tenant-aware tables and strict RLS where multi-tenant data exists:
  - every tenant row includes `org_id`,
  - project-scoped rows include `project_id`,
  - session context sets tenant vars per request,
  - RLS remains default-deny and only allows current tenant scope.
- If local tooling temporarily uses a single logical DB, preserve equivalent isolation by strict schema + role separation until DB split is completed.

### Enterprise isolation tier

Support dedicated database (or dedicated schema) per organization for high-compliance enterprise customers.

Trigger and SLO defaults:

- Trigger: manual enterprise/compliance request.
- Isolation SLO targets: `99.95%` availability, `RPO 15m`, `RTO 4h`.

### Decision on schema-per-project

Do not use schema-per-project by default.

Reason:

- High operational overhead (migrations, monitoring, backups).
- Harder cross-project reporting.
- More complexity without proportional security benefit if RLS + key design are correct.

### Local development connection anchor

- Current local cluster connection provided by team:
  - `postgresql://tatchi:tatchi@127.0.0.1/tatchi?statusColor=686B6F&env=local&name=tatchi&tLSMode=0&usePrivateKey=false&safeModeLevel=0&advancedSafeModeLevel=0&driverVersion=0&lazyload=false`
- Planned logical DB targets on the same cluster:
  - `tatchi_signer`
  - `tatchi_console`
- Plan keeps separate DB users and migration runners per logical DB to reduce blast radius and keep least privilege boundaries explicit.

## High-Level Domain Model

1. `Organization` has many `Memberships`, `Projects`, `BillingAccounts`, and `AuditEvents`.
2. `Project` belongs to `Organization`; has many `Environments`, `Policies`, `Wallets`, and `APIKeys`.
3. `Environment` belongs to `Project`; scopes runtime settings and secrets.
4. `Wallet/User runtime data` is project-scoped and tenant-enforced.
5. `Policy engine` is versioned and assigned at org/project/wallet-segment levels.
6. `Billing` rolls up usage events into invoices, applies credits from an immutable ledger, and settles through Stripe cards or supported stablecoin assets.

## Schema Plan by Domain

### 1) Identity and Access

Tables:

- `users`
- `user_profiles`
- `user_backup_emails`
- `organizations`
- `organization_memberships`
- `organization_invites`
- `roles`
- `role_permissions`
- `service_accounts`
- `sessions` (optional; if needed for dashboard auth)

Notes:

- Membership is the source of truth for org-level access.
- Account settings needs user-owned profile/contact state that is separate from org membership:
  - `user_profiles` stores display name and primary email.
  - `user_backup_emails` stores additional recovery addresses plus verification status.
  - `organizations.created_by_user_id` supports “organizations created by me” without inferring authorship from current membership.
- Hybrid role scope model:
  - org-scoped roles: `owner`, `admin`, `security_admin`, `billing_admin`
  - project-scoped roles: `developer`, `support`, `ops`
- Support account states: invited, active, suspended, removed.
- Billing permissions include explicit actions such as `billing.payment_methods.write` and map `add/remove card` to `admin` only.
- Current console implementation materializes these as `console_user_profiles`, `console_user_backup_emails`, and `created_by_user_id` on `console_organizations`.

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
- All runtime tables include `org_id`, `project_id`, and mandatory `environment_id`.

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
- `invoice_payment_rail_locks`
- `payments`
- `billing_payment_methods`
- `stripe_customers`
- `stripe_events`
- `stablecoin_payment_quotes`
- `stablecoin_payment_intents`
- `stablecoin_settlement_events`
- `stablecoin_deposit_addresses`
- `chain_finality_policies`

Billing support:

- Monthly org subscription: from `subscriptions`.
- Active-wallet usage: `Monthly Active Wallets (MAW)` definition + monthly rollup.
  - `MAW` is the count of distinct `wallet_id` per organization per calendar month (`UTC`) with at least one successful billable action.
  - Billable actions: `transfer`, `swap`, `approve`, `contract_call`.
  - Exclusions: wallet creation-only activity, simulations, failed transactions, internal retries.
- Credits billing: consume credits through ledger debits before final charge.
- Card payments via Stripe:
  - map organization billing account to Stripe customer,
  - store external payment method references and default method per billing account,
  - persist external Stripe payment intent reference per payment attempt for webhook correlation,
  - persist processed Stripe webhook callback events (event id + provider ref + linked payment intent) for idempotency and auditability,
  - reconcile invoice/payment status from verified Stripe webhook events.
  - authorization rule: only `admin` role can create/delete card payment method records and set the default card payment method.
- Stablecoin settlement for `USDC` and `USDT`:
  - `USDC` and `USDT` accept funding from any currently supported chain: `Ethereum`, `Base`, `Tempo`, `Arc Circle`, `NEAR`.
  - lock quote terms (asset, amount, network, expiry) per invoice payment intent,
  - allocate destination details per payment intent,
  - track on-chain confirmations and settlement outcomes.
  - persist settlement risk metadata (`settled_at_ms`, `reorg_risk_window_ends_at_ms`) and expose `withinReorgRiskWindow` for post-settlement monitoring.
  - v1 finality policy defaults:
    - `Ethereum`: `12` confirmations, `360` minute confirmation timeout, `24` hour reorg-risk window.
    - `Base`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
    - `Tempo`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
    - `Arc Circle`: `20` confirmations, `120` minute confirmation timeout, `12` hour reorg-risk window.
    - `NEAR`: `10` confirmations, `60` minute confirmation timeout, `6` hour reorg-risk window.
- Split-payment policy:
  - invoices must settle fully on one rail: `CARD` or `STABLECOIN`.
  - no mixed card + stablecoin settlement for a single invoice.
  - rail is locked on first payment intent and remains immutable while invoice is open.
- Payment lifecycle model:
  - `payments.state` enum values:
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
  - append-only `payment_state_transitions` audit table:
    - `payment_id`, `from_state`, `to_state`, `changed_at`, `actor_type`, `source_event_id`, `reason`
  - enforce allowed transitions with DB trigger + application guardrails:
    - `CREATED` -> `ACTION_REQUIRED` | `PENDING` | `FAILED` | `CANCELED`
    - `ACTION_REQUIRED` -> `PENDING` | `FAILED` | `CANCELED` | `EXPIRED`
    - `PENDING` -> `CONFIRMING` | `SETTLED` | `PARTIALLY_SETTLED` | `OVERPAID` | `FAILED` | `CANCELED` | `EXPIRED`
    - `CONFIRMING` -> `SETTLED` | `PARTIALLY_SETTLED` | `OVERPAID` | `FAILED`
    - `SETTLED` -> `REFUNDED` | `DISPUTED`
    - `DISPUTED` -> `SETTLED` | `REFUNDED`
  - `CONFIRMING` -> `SETTLED` requires `observed_confirmations >= chain_finality_policies.required_confirmations`.
  - if `chain_finality_policies.confirmation_timeout_minutes` is exceeded before threshold, transition to `FAILED` with `failure_reason = CONFIRMATION_TIMEOUT`.

Critical rule:

- Canonical active-wallet metric is `MAW` (Monthly Active Wallets) and must be versioned (`maw_v1`) in metering logic.
- Stablecoin over/underpayment handling must be deterministic and auditable (credit, remaining balance due, or manual review).
- Payment transition history must be immutable and complete for dispute/compliance evidence.
- Invoice settlement remains open until full amount is covered by the locked rail; cross-rail top-ups are disallowed.

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
- Retention defaults:
  - runtime + webhook: `180d` hot + `2y` archive
  - billing + payments + audit: `7y`
- Payment-provider webhook payloads are stored with signature-verification metadata for audit and dispute support.

## Suggested Physical Layout

Logical databases + schemas:

- `tatchi_signer`:
  - `runtime`: signer/relay execution state.
  - `audit`: signer-domain immutable logs.
- `tatchi_console`:
  - `control`: org, projects, environments, memberships, settings, policy configs.
  - `billing`: metering, invoices, payments, Stripe/stablecoin integration records.
  - `integrations`: api keys, webhook endpoints/deliveries/retries.
  - `audit`: console-domain immutable logs and compliance records.
- If only one logical DB is available temporarily, keep these schema boundaries unchanged and map separate DB users to schema-scoped privileges.

Optional at scale:

- Read replicas for search/list APIs.
- Separate OLAP sink for analytics-heavy queries.

## Rollout Plan

### Phase 0: Foundation

- Create core tenancy tables: `organizations`, `projects`, `environments`, `organization_memberships`.
- Add account-settings identity tables: `user_profiles`, `user_backup_emails`, and `organizations.created_by_user_id`.
- Implement RLS and tenant context middleware.
- Add `audit_log` and `event_outbox`.

### Phase 1: MVP Control Plane

- Add policy tables with versioning and assignments.
- Add API key and webhook tables.
- Add app/environment settings tables.
- Add billing account + subscription records.
- Add Stripe customer linkage + card payment method references.

### Phase 2: Usage and Billing

- Add `usage_meter_events` ingestion.
- Build daily/monthly rollup jobs.
- Add invoice generation and credit ledger consumption.
- Add `MAW` billing metric computation (`maw_v1`) and evidence exports.
- Add Stripe webhook reconciliation and payment status projection.
- Add stablecoin quote/intents and on-chain settlement tracking for `USDC` and `USDT`, with funding accepted from `Ethereum`, `Base`, `Tempo`, `Arc Circle`, and `NEAR`.
- Seed `chain_finality_policies` with v1 defaults for `Ethereum`, `Base`, `Tempo`, `Arc Circle`, and `NEAR`.
- Add invoice rail-lock persistence and mixed-rail rejection constraints.

### Phase 3: Hardening and Enterprise

- Add approval workflows for risky changes.
- Add enterprise isolation mode (dedicated DB or schema).
- Add backup/restore automation and tenant export.
- Add support-access controls and compliance reporting pack.

## Open Decisions to Finalize Before Migration

- None currently blocking migration design.

## Deliverables from This Plan

1. ERD v1 (control + runtime + audit).
2. Migration set `0001` through `000N` for Phase 0 and Phase 1.
3. RLS policy test suite.
4. Metering and invoicing job specs.
5. Operational runbook for tenant isolation and incident response.
