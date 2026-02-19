# Dashboard Requirements Plan (Wallet-as-a-Service)

## Objective
Build a control-plane dashboard at `/dashboard` for teams running embedded threshold wallets, with operational controls for wallet lifecycle, authorization policy, app security, and integrations.

## Personas
- Product admin: configures wallet behavior and app-level settings.
- Security admin: owns policy, key export controls, and approvals.
- Developer/platform engineer: manages API keys, webhooks, and environments.
- Support/ops: inspects wallet state, transactions, and delivery failures.

## Information architecture
- Wallet infrastructure
- User management
- Security and policy
- Integrations and automation
- Environment settings (Dev, Staging, Prod)

## Functional requirements

### 1) User wallets list
- Paginated wallets table with columns: wallet ID, address, chain type, owner/user, policy, balance, status, created/updated timestamps.
- Summary KPI cards: total assets, total wallets, funded wallets, activity in last 24h/7d.
- Row actions: view details, view activity, assign policy, freeze/unfreeze (if supported).
- Empty/loading/error states with retry.

### 2) Search for user wallets
- Search by wallet address, wallet ID, user ID, and external reference ID.
- Filter by chain, policy, key quorum, wallet type (EOA/smart), status, and date range.
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
- Change guardrails for risky settings (warnings, confirmation, optional approval).
- Optional IP allowlist and SSO metadata fields.

### 6) Export keys settings
- Export policy modes:
  - Disabled
  - Approval required
  - Allowed with scoped constraints
- Constraints by role, chain, wallet type, and environment.
- Step-up requirements (MFA + reason) for export actions.
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

## Non-functional requirements
- Security: least-privilege RBAC, immutable audit logs, encryption at rest/in transit.
- Reliability: p95 list/search latency < 500ms at target org scale.
- Compliance readiness: evidence-friendly logs and deterministic change history.
- Accessibility: keyboard navigation and semantic labels for key controls.
- Responsive behavior: desktop-first with functional mobile fallback.

## Suggested API surfaces
- `GET /wallets`, `GET /wallets/:id`
- `GET /wallets/search`
- `GET/POST/PATCH /policies`, `POST /policies/:id/simulate`, `POST /policies/:id/publish`
- `GET/PATCH /settings/app`, `GET/PATCH /settings/security`
- `GET/POST/PATCH /gas-sponsorship`, `GET/POST/PATCH /smart-wallets`
- `GET/POST /key-exports`, `POST /key-exports/:id/approve`
- `GET/POST/DELETE /api-keys`, `POST /api-keys/:id/rotate`
- `GET/POST/PATCH/DELETE /webhooks`, `GET /webhooks/:id/deliveries`, `POST /webhooks/:id/replay`

## Delivery plan
- Phase 1 (MVP): wallets list/search, baseline policy controls, app settings core, API keys, webhooks basics.
- Phase 2: policy simulation/versioning, gas sponsorship budgets, smart wallet controls, key export approvals.
- Phase 3: advanced governance (RBAC refinements, staged rollouts, SSO, anomaly detection, deeper observability).

## Acceptance criteria
- Pricing CTAs route users into `/dashboard`.
- Admin can list/search wallets and filter by chain/policy/status.
- Policy engine can enforce action+chain constraints for threshold wallets.
- Gas sponsorship and smart wallet toggles affect runtime behavior and telemetry.
- Security settings (origins/cookies/JWT) are environment-specific and validated.
- Key export, API key, and webhook features include audit-friendly logs.
