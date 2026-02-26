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
- Billing admin: manages invoices and card payment method administration.
- Support/ops: inspects wallet state, transactions, and delivery failures.

## Information architecture

- Wallet infrastructure
- User management
- Security and policy
- Integrations and automation
- Billing and payments
- Environment settings (Dev, Staging, Prod)

## Functional requirements

### 1) User wallets list

- Paginated wallets table with columns: wallet ID, address, chain type, environment, owner/user, policy, balance, status, created/updated timestamps.
- Summary KPI cards: total assets, total wallets, funded wallets, activity in last 24h/7d.
- Row actions: view details, view activity, assign policy, freeze/unfreeze (if supported).
- Empty/loading/error states with retry.

### 2) Search for user wallets

- Search by wallet address, wallet ID, user ID, and external reference ID.
- Filter by chain, environment, policy, key quorum, wallet type (EOA/smart), status, and date range.
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

### 4) Gas sponsorship and smart wallets

- Toggle gas sponsorship at org, environment, policy, and wallet segment levels.
- Budget and quota controls by chain and period.
- Smart wallet/AA controls (when enabled): account type, paymaster mode, fallback behavior.
- Telemetry: sponsored tx count, spend, failures, and budget threshold alerts.

### 5) App settings (origins/domains, cookies, JWT)

- Environment-scoped app settings panel:
  - Allowed origins/domains with strict validation.
  - Cookie mode (including `HttpOnly`, `Secure`, `SameSite`).
  - JWT settings: issuer, audience, key IDs, token TTL/refresh TTL.
- Change guardrails for risky settings (warnings, confirmation, and approval workflow).
- Optional IP allowlist and SSO metadata fields.
- Default approval for risky security settings changes: `1 admin + MFA`.

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

- Webhook endpoints with event subscriptions (wallet, policy, auth, tx lifecycle).
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

### 9) Billing and payments

- Billing overview with current plan, active-wallet usage, credit balance, invoice status, and upcoming charge estimate.
- Canonical usage metric is `Monthly Active Wallets (MAW)`:
  - Count distinct wallet IDs per organization per calendar month (`UTC`) with at least one successful billable action.
  - Billable actions: `transfer`, `swap`, `approve`, `contract_call`.
  - Exclusions: wallet creation-only activity, simulations, failed transactions, and internal retries.
- Card billing via Stripe:
  - Attach/update/remove card payment method.
  - RBAC: only `admin` can add/remove card payment methods.
  - Mark default payment method per organization billing account.
  - RBAC: only `admin` can set default card payment method.
  - Handle SCA-required flows and failed-payment recovery states.
- Stablecoin payment support for `USDC` and `USDT`:
  - `USDC` and `USDT` can be funded from any supported chain. Current supported chains: `Ethereum`, `Base`, `Tempo`, `Arc Circle`, `NEAR`.
  - Create payment quote and payment intent for an invoice.
  - Issue asset/network-specific destination details and quote expiry.
  - Quote semantics:
    - quote amount is a snapshot of invoice outstanding at quote creation time.
    - quote is single-use and cannot back multiple payment intents.
    - quote consumption requires amount to still match current invoice outstanding; stale quotes are rejected.
  - Track confirmations and settlement status through completion.
  - Surface post-settlement risk metadata on payment intents:
    - `settledAt`
    - `reorgRiskWindowEndsAt`
    - `withinReorgRiskWindow`
  - Finality thresholds and risk windows (v1 defaults):
    - `Ethereum`: `12` confirmations, `360` minute confirmation timeout, `24` hour post-settlement reorg-risk window.
    - `Base`: `20` confirmations, `120` minute confirmation timeout, `12` hour post-settlement reorg-risk window.
    - `Tempo`: `20` confirmations, `120` minute confirmation timeout, `12` hour post-settlement reorg-risk window.
    - `Arc Circle`: `20` confirmations, `120` minute confirmation timeout, `12` hour post-settlement reorg-risk window.
    - `NEAR`: `10` confirmations, `60` minute confirmation timeout, `6` hour post-settlement reorg-risk window.
- Reconciliation and controls:
  - Invoices are single-rail: fully paid by `Stripe/card` or `stablecoin` rail; mixed-rail settlement is rejected.
  - Payment rail lock is set on first payment intent for an invoice and cannot change while invoice is open.
  - At most one active payment intent is allowed per invoice per rail (`CREATED`/`ACTION_REQUIRED`/`PENDING`/`CONFIRMING`).
  - Detect underpayment/overpayment and apply rules (credit, partial balance due, or manual review).
  - Immutable payment ledger tying invoices, payment attempts, and settlement evidence.
  - Webhook events for invoice status changes and payment settlement.
- Payment state machine (SaaS billing payment attempts):
  - `CREATED`: payment attempt created with immutable expected amount snapshot.
  - `ACTION_REQUIRED`: customer interaction required (for example Stripe SCA).
  - `PENDING`: payment submitted, waiting provider callback or on-chain detection.
  - `CONFIRMING`: on-chain transaction detected, waiting chain finality threshold.
  - `SETTLED`: expected amount fully satisfied.
  - `PARTIALLY_SETTLED`: payment received but below expected amount; shortfall remains on invoice.
  - `OVERPAID`: payment received above expected amount; excess becomes credit.
  - `FAILED`: terminal provider or validation failure.
  - `CANCELED`: terminal user/system cancellation before settlement.
  - `EXPIRED`: terminal timeout of quote/intent/action window.
  - `REFUNDED`: settled payment fully or partially refunded.
  - `DISPUTED`: settled payment under dispute/chargeback.
- Allowed transitions:
  - `CREATED` -> `ACTION_REQUIRED` | `PENDING` | `FAILED` | `CANCELED`
  - `ACTION_REQUIRED` -> `PENDING` | `FAILED` | `CANCELED` | `EXPIRED`
  - `PENDING` -> `CONFIRMING` | `SETTLED` | `PARTIALLY_SETTLED` | `OVERPAID` | `FAILED` | `CANCELED` | `EXPIRED`
  - `CONFIRMING` -> `SETTLED` | `PARTIALLY_SETTLED` | `OVERPAID` | `FAILED`
  - `SETTLED` -> `REFUNDED` | `DISPUTED`
  - `DISPUTED` -> `SETTLED` | `REFUNDED`
- Finality transition rules:
  - `CONFIRMING` -> `SETTLED` is allowed only when per-chain confirmation threshold is met.
  - If confirmation timeout elapses before threshold is met, transition to `FAILED` with reason `CONFIRMATION_TIMEOUT`.

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
- `GET/PATCH /console/settings/app`, `GET/PATCH /console/settings/security`
- `GET/POST/PATCH /console/gas-sponsorship`, `GET/POST/PATCH /console/smart-wallets`
- `GET/POST /console/key-exports`, `POST /console/key-exports/:id/approve`
- `GET/POST/DELETE /console/api-keys`, `POST /console/api-keys/:id/rotate`
- `GET/POST/PATCH/DELETE /console/webhooks`, `GET /console/webhooks/:id/deliveries`, `POST /console/webhooks/:id/replay`
- `GET /console/webhooks/:id/attempts`, `GET /console/webhooks/:id/dead-letters` (support `limit`/`cursor` pagination)
- `GET /console/billing/overview`, `GET /console/billing/invoices`, `GET /console/billing/invoices/:id`
- `GET /console/billing/invoices/:id/line-items`, `POST /console/billing/invoices/generate`
- `GET /console/billing/usage/monthly-active-wallets`, `POST /console/billing/usage/events`
- `GET/POST/DELETE /console/billing/payment-methods`, `POST /console/billing/payment-methods/:id/default`
- `POST /console/billing/stripe/setup-intent`, `POST /console/billing/stripe/payment-intent`
- `POST /console/billing/stripe/webhook` (provider callback endpoint; shared-secret protected)
- `GET /console/billing/stablecoins/assets`, `POST /console/billing/stablecoins/quotes`, `POST /console/billing/stablecoins/payment-intents`
- `GET /console/billing/stablecoins/payment-intents/:id`, `POST /console/billing/stablecoins/payment-intents/:id/cancel`

## Delivery plan

- Phase 1 (MVP): wallets list/search, baseline policy controls, app settings core, API keys, webhooks basics, billing overview + invoices read APIs.
- Phase 2: policy simulation/versioning, gas sponsorship budgets, smart wallet controls, key export approvals, Stripe card payment flows.
- Phase 3: advanced governance (RBAC refinements, staged rollouts, SSO, anomaly detection, deeper observability) and stablecoin payment flows (`USDC`, `USDT`).

## Acceptance criteria

- Pricing CTAs route users into `/dashboard`.
- Admin can list/search wallets and filter by chain/policy/status.
- Policy engine can enforce action+chain constraints for threshold wallets.
- Gas sponsorship and smart wallet toggles affect runtime behavior and telemetry.
- Security settings (origins/cookies/JWT) are environment-specific and validated.
- Key export, API key, and webhook features include audit-friendly logs.
- Billing supports card payments through Stripe and stablecoin invoice settlement via `USDC` and `USDT`.
- `USDC`/`USDT` settlement accepts payments from all currently supported chains: `Ethereum`, `Base`, `Tempo`, `Arc Circle`, and `NEAR`.
- Billing payment attempts enforce the defined payment state machine and allow only listed transitions.
- Invoice settlement never mixes rails: each invoice is fully settled by card rail or stablecoin rail.
- Only `admin` can add/remove card payment methods.
- Only `admin` can set default card payment method.
- Settlement enforces chain-specific finality thresholds and risk windows for `Ethereum`, `Base`, `Tempo`, `Arc Circle`, and `NEAR`.
- Billing usage is computed from `Monthly Active Wallets (MAW)` as the canonical wallet activity metric.
- Policy publish requires `1 admin` approval by default.
- Key export requires `2 admin` approvals + `MFA` + reason by default.
- Risky security settings changes require `1 admin + MFA` by default.
- Runtime consumers receive full versioned per-environment snapshots of effective config.
