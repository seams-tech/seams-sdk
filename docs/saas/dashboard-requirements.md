# Dashboard Requirements Plan (Wallet-as-a-Service)

Related implementation plan:

- `docs/saas/dashboard-backend-implementation-plan.md`

## Objective

Build a console dashboard at `/dashboard` for teams running embedded threshold wallets, with operational controls for wallet lifecycle, authorization policy, app security, integrations, and billing/payments.

## API Namespace Convention

- `/console/*` for SaaS/admin APIs used by dashboard features.
- `/relay/*` for runtime/transaction APIs used by signing and relay execution flows.

## Personas

- Product admin: configures wallet behavior and app-level settings.
- Security admin: owns policy, key export controls, and approvals.
- Developer/platform engineer: manages API keys, webhooks, and environments.
- Billing admin: manages invoices, prepaid balance operations, and internal billing adjustments.
- Support/ops: inspects wallet state, transactions, and delivery failures.

## Information architecture

- Overview
  - Overview (Ops Cockpit)
  - Observability
- Administration
  - Team members and roles
  - API keys
- Wallet Operations
  - User wallets list
  - Gas sponsorship
  - Policy engine
  - Enterprise isolation
  - Audit logs
- Integrations
  - API key management
  - Webhooks
- Billing
  - Billing

## Functional requirements

### 1) User wallets list

- Paginated wallets table with columns: wallet ID, address, chain type, environment, owner/user, policy, balance, status, created/updated timestamps.
- Summary KPI cards: total assets, total wallets, funded wallets, activity in last 24h/7d.
- Row actions: view details, view activity, assign policy, freeze/unfreeze (if supported).
- Empty/loading/error states with retry.

### 2) Search for user wallets

- Search by wallet address, wallet ID, user ID, and external reference ID.
- Filter by chain, environment, policy, key quorum, wallet type, status, and date range.
- Sort by balance, last activity, and creation time.
- URL-synced filter state for shareable views.

### 3) Policy engine (threshold wallet actions + chains)

- Policy model supports:
  - Allowed actions: transfer, swap, approve, contract call, key export.
  - Allowed chains/networks by environment.
  - Limits: per tx, per day, per policy segment.
  - Contract/method allowlists and deny-lists.
  - Approval rules: MFA, admin approval, or signer quorum requirements.
- Policy simulation mode to evaluate a proposed action without execution.
- Policy versioning, staged rollout, and rollback.
- Full audit trail for policy create/update/publish/assign events.
- Default approval for policy publish: `1 admin` approval.

### 4) Gas sponsorship

- Toggle gas sponsorship at org, environment, policy, and wallet segment levels.
- Budget and quota controls by chain and period.
- Telemetry: sponsored tx count, spend, failures, and budget threshold alerts.

### 5) Allowed origins

- `publishable_key` editor:
  - Allowed browser origins with strict validation.

### 6) Export keys settings

- Export policy modes:
  - Disabled
  - Approval required
  - Allowed with scoped constraints
- Constraints by role, chain, wallet type, and environment.
- Step-up requirements (MFA + reason) for export actions.
- Default approval for export actions: `2 admin` approvals + `MFA` + reason.
- Immutable export log: who, what, when, why, approval chain.

### 7) API key management

- Create/revoke/rotate API keys with scoped permissions.
- Keys scoped by environment and optional IP restrictions.
- Secret visible once at creation only; never retrievable in plaintext.
- Usage analytics: last used, endpoint distribution, anomaly flags.

### 8) Webhooks

- Webhook endpoints with event categories (wallet, policy, auth, tx lifecycle, session).
- Signed payloads with rotating secrets.
- Retry strategy with backoff and dead-letter queue handling.
- Delivery logs with request/response metadata and replay action.
- Webhook list pagination semantics:
  - Cursor pagination uses `limit` + opaque `cursor` token and returns `nextCursor` when more rows exist.
  - Stable sort order is descending by timestamp then id:
    - deliveries: (`createdAt`, `id`)
    - attempts: (`attemptedAt`, `id`)
    - dead-letters: (`movedToDlqAt`, `id`)
  - Invalid cursor format returns `400` with code `invalid_query`.

### 9) Billing

- Billing is org-scoped and split into:
  - `/dashboard/billing/account`
  - `/dashboard/invoices`
  - `/dashboard/invoices/:invoiceId`
- Billing is prepaid and ledger-first:
  - append-only journal entries are the source of truth,
  - projected balance is derived from ledger postings,
  - receipts and usage statements are projection views, not mutable source records.
- Billing overview shows:
  - projected prepaid balance,
  - `Monthly Active Wallets (MAW)` usage,
  - recent usage debits and top-ups,
  - receipt/statement document counts,
  - live-environment readiness state (`HEALTHY`, `LOW_BALANCE`, `BLOCKED`).
- Canonical usage metric is `Monthly Active Wallets (MAW)`:
  - count distinct wallet IDs per organization per calendar month (`UTC`) with at least one successful billable action.
  - billable actions: `transfer`, `swap`, `approve`, `contract_call`.
  - exclusions: wallet creation-only activity, simulations, failed transactions, and internal retries.
- Stripe billing surface is checkout-only:
  - pricing funnel creates Stripe Checkout session and redirects to hosted checkout,
  - success/cancel returns route back to dashboard billing surfaces with status context,
  - verified webhook settlement creates prepaid credit purchase entries and purchase receipts.
- Internal billing operations:
  - support credits and admin debits append audited manual adjustment entries,
  - linked manual adjustments may appear on staff invoice timelines,
  - customer-facing PDF exports exclude internal adjustment detail.
- Live-environment readiness is derived from projected prepaid balance.

### 10) Dashboard UX flow and navigation

- Sidebar grouping requirement:
  - `Observability` must live under `Overview` (not under `Wallet Operations`).
- Onboarding requirement:
  - Onboarding must explicitly prompt for `Organization name` before project setup.
  - Organization step is not complete until a non-empty organization name is saved.
  - If organization profile exists but is still effectively default/unconfigured, onboarding remains on the organization step.
- Navigation lock requirement before setup:
  - Before both organization and first project are configured, all sidebar menu items are disabled.
  - Disabled sidebar items must not navigate on click and must expose accessible disabled semantics.
  - After organization and project are configured, sidebar navigation is enabled.

## Non-functional requirements

- Security: least-privilege RBAC, immutable audit logs, encryption at rest/in transit.
- Reliability: p95 list/search latency < 500ms at target org scale.
- Compliance readiness: evidence-friendly logs and deterministic change history.
- Accessibility: keyboard navigation and semantic labels for key controls.
- Responsive behavior: desktop-first with functional mobile fallback.
- Financial correctness: invoice balances, credits, and payment settlement states remain consistent and auditable.
- Runtime snapshot contract for relay/runtime consumers uses full versioned per-environment snapshots.
- Enterprise isolation is supported via manual enterprise/compliance trigger with target SLO `99.95%`, `RPO 15m`, `RTO 4h`.
- Role scope model is hybrid:
  - org-scoped roles: `owner`, `admin`, `security_admin`, `billing_admin`
  - project-scoped roles: `developer`, `support`, `ops`
- Data retention defaults:
  - Runtime + webhook data: `180` days hot retention + `2` years archive.
  - Billing + payments + audit data: `7` years retention.

## Suggested API surfaces

- `GET /console/wallets`, `GET /console/wallets/:id`
- `GET /console/wallets/search`
- `GET/POST/PATCH /console/policies`, `POST /console/policies/:id/simulate`, `POST /console/policies/:id/publish`
- `GET /console/runtime-snapshots`, `GET /console/runtime-snapshots/latest`, `POST /console/runtime-snapshots/publish`, `POST /console/runtime-snapshots/publish-current`
- gas sponsorship uses `GET/POST/PATCH /console/policies` with `kind=GAS_SPONSORSHIP`, and `POST /console/policies/:id/publish`
- `GET/POST/PATCH /console/smart-wallets`
- `GET/POST /console/key-exports`, `POST /console/key-exports/:id/approve`
- `GET/POST/DELETE /console/api-keys`, `POST /console/api-keys/:id/rotate`
- `GET/POST/PATCH/DELETE /console/webhooks`, `GET /console/webhooks/:id/deliveries`, `POST /console/webhooks/:id/replay`
- `GET /console/webhooks/:id/attempts`, `GET /console/webhooks/:id/dead-letters` (support `limit`/`cursor` pagination)
- `GET /console/billing/overview`, `GET /console/billing/invoices`, `GET /console/billing/invoices/:id`
- `GET /console/billing/invoices/:id/line-items`, `GET /console/billing/invoices/:id/activity`
- `GET /console/billing/invoices/:id/pdf`, `POST /console/billing/invoices/generate`
- `GET /console/billing/usage/monthly-active-wallets`, `POST /console/billing/usage/events`
- `GET /console/billing/account/activity`
- `POST /console/billing/adjustments/support-credit`, `POST /console/billing/adjustments/admin-debit`
- `POST /console/billing/stripe/checkout-session`
- `POST /console/billing/stripe/webhook` (provider callback endpoint; shared-secret protected)

## Delivery plan

- Phase 1 (MVP): wallets list/search, baseline policy controls, API keys, webhooks basics, billing overview + invoices read APIs.
- Phase 2: policy simulation/versioning, gas sponsorship budgets through `GAS_SPONSORSHIP` policies, smart wallet controls, key export approvals, prepaid Stripe Checkout top-ups, pricing -> Stripe Checkout -> dashboard return flow.
- Phase 3: advanced governance (RBAC refinements, staged rollouts, SSO, anomaly detection, deeper observability), operator billing adjustments, and ledger/reporting hardening.

## Acceptance criteria

- Pricing CTA starts Stripe Checkout and success path lands user back in `/dashboard/billing`.
- Admin can list/search wallets and filter by chain/policy/status.
- Policy engine can enforce action+chain constraints for threshold wallets.
- Gas sponsorship toggles affect runtime behavior and telemetry.
- Security settings (origins/cookies/JWT) are environment-specific and validated.
- Key export, API key, and webhook features include audit-friendly logs.
- Billing supports prepaid Stripe Checkout top-ups, receipts/statements, customer-facing PDF exports, and audited internal adjustments.
- Dashboard billing exposes prepaid balance state, receipt/statement history, and invoice activity under the split account/invoices routes.
- Billing writes are append-only and auditable through the ledger-first model.
- Live-environment readiness is enforced from projected prepaid balance state.
- Billing usage is computed from `Monthly Active Wallets (MAW)` as the canonical wallet activity metric.
- Policy publish requires `1 admin` approval by default.
- Key export requires `2 admin` approvals + `MFA` + reason by default.
- Runtime consumers receive full versioned per-environment snapshots of effective config.
- Sidebar navigation places `Observability` under `Overview`.
- Onboarding requires an explicit organization name step before project creation.
- Sidebar menu items are disabled until both organization and project are configured.
