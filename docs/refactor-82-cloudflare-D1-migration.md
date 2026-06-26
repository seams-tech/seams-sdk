# Cloudflare D1 Migration Plan

Date created: June 26, 2026
Updated: June 27, 2026

Status: simplified execution plan. This plan moves the default Seams console and
signer persistence path to Cloudflare D1 plus Durable Objects, while keeping a
clean full-family Postgres escape hatch for future scale or relational needs.

## Decision

Use Cloudflare D1 and Durable Objects as the first production backend family:

- D1 owns console tables, signer metadata, sealed signer ciphertext, billing
  records, sponsored gas records, reconciliation tables, and snapshot outbox
  tables.
- Durable Objects own hot signer coordination that needs per-entity serialized
  mutation: session use counts, budget consumption, replay guards,
  presignature pools, and signing-root coordination.
- Cloudflare Secrets Store is the hosted KEK source for signer share
  encryption. Wrangler secrets are allowed for local development. External KMS
  or HSM support is exposed through a narrow signer-only KEK provider adapter.
- Local development uses Wrangler/Miniflare D1 and local Durable Object storage
  by default.
- Postgres remains an adapter family behind the same domain-store ports. It is
  activated only as a complete backend family.

Key rule: no half-Postgres runtime. A tenant or deployment uses D1/DO for all
route-owned persistence, or Postgres for all route-owned persistence.

Authoritative Cloudflare references:

- [D1 local development](https://developers.cloudflare.com/d1/best-practices/local-development/)
- [D1 Worker binding API](https://developers.cloudflare.com/d1/worker-api/d1-database/)
- [D1 migrations](https://developers.cloudflare.com/d1/reference/migrations/)
- [D1 limits](https://developers.cloudflare.com/d1/platform/limits/)
- [D1 Time Travel](https://developers.cloudflare.com/d1/reference/time-travel/)
- [D1 data security](https://developers.cloudflare.com/d1/reference/data-security/)
- [Durable Object storage](https://developers.cloudflare.com/durable-objects/best-practices/access-durable-objects-storage/)
- [Durable Object rules](https://developers.cloudflare.com/durable-objects/best-practices/rules-of-durable-objects/)
- [Workers testing](https://developers.cloudflare.com/workers/testing/)
- [Hyperdrive Postgres connectivity](https://developers.cloudflare.com/hyperdrive/)

## Simplified Rule Set

- Build domain-store adapters, not a generic SQL compatibility layer.
- Implement D1/DO first.
- Keep Postgres as a documented full-family backend contract until a real
  trigger requires implementation.
- Resolve storage once per request from tenant identity.
- Pass domain stores into core logic. Core code never receives raw D1 bindings,
  Postgres clients, transaction handles, Durable Object stubs, or raw rows.
- Store JSON as `TEXT` in D1 and parse it at adapter boundaries.
- Validate request bodies, DB rows, Worker responses, and route records once at
  the boundary.
- Make invalid backend combinations unrepresentable with discriminated unions.
- Use atomic D1/SQLite writes for prepaid reservations and sponsored gas
  settlement.
- Stage on D1/DO from the start. There is no mixed staging mode.

## Simplification Decisions

- First staging uses one shared `CONSOLE_DB`, one shared `SIGNER_DB`, one
  `THRESHOLD_STORE` Durable Object namespace, and one hosted signer KEK
  provider.
- Tenant route resolution is static for the first release. A persistent tenant
  route registry is deferred until the first dedicated D1 route or Postgres
  route is required.
- Dedicated tenant D1 databases are deferred. Shared D1 remains acceptable while
  storage, latency, and customer isolation triggers stay below the thresholds in
  this plan.
- The first staging environment starts empty on D1/DO or imports fixture data
  through D1/DO import tools. It does not run a live mixed Postgres/D1 request
  path.
- The Postgres adapter family is defined through ports, schema contracts,
  transaction semantics, and shared contract tests. A live implementation waits
  until a concrete scale or enterprise trigger appears.
- High-volume observability, cold archives, and bulky long-retention data go to
  R2, Analytics Engine, logs, or later warehouse storage. D1 keeps compact
  dashboard state and reconciliation records.
- Durable Objects are used only where serialized mutation is the core property:
  signer budgets, replay guards, presignature pools, signing-session admission,
  and signing-root coordination.
- Cloudflare Secrets Store is the hosted signer KEK source. External KMS/HSM
  support stays behind the signer KEK provider interface.

## Current Implementation Status

Completed so far:

- Added tenant storage route types that make D1/DO and Postgres full-family
  choices.
- Added D1 adapters for org/project/environment records, account profiles,
  team RBAC, policies, wallet index, API keys, approvals, audit, bootstrap
  tokens, billing account/ledger settlement, prepaid billing reservations,
  sponsored call records, runtime snapshot storage/outbox, and sealed
  signing-root secret shares.
- Added signer KEK provider routing for Cloudflare Secrets Store, Wrangler
  secrets, and external KMS/HSM clients.
- Wired D1 org/project/env, Team RBAC, account/profile, policies, API keys,
  wallet index, approvals, audit, bootstrap tokens, billing, prepaid
  reservations, sponsored calls, runtime snapshots, and signer secret storage
  into the Cloudflare service bundle.
- Added local Wrangler/Miniflare D1 configuration, append-only migrations,
  smoke Worker, and package scripts.
- Verified local D1 migrations and `/readyz` smoke against Wrangler.
- Added targeted SQLite-backed D1 adapter contract tests for
  org/project/environment tenant scoping, account profile and organization
  resolution, team RBAC owner/member lifecycle invariants, policy default
  bootstrap/versioning/assignment resolution, API key auth and tenant scoping,
  wallet index filters/search/pagination and tenant scoping, approval MFA and
  conditional-decision transitions, audit event/evidence tenant scoping,
  bootstrap token redemption atomicity, prepaid reservation atomicity,
  sponsored-call idempotency, atomic sponsored gas settlement, and signer
  secret tenant scoping.
- Completed the first Postgres-coupling inventory and ownership matrix.
- Added D1 runtime snapshot outbox lease-race coverage.
- Added Durable Object ECDSA presignature reservation and pool-fill CAS
  coverage.
- Added D1 sponsored gas settlement finalization for prepaid EVM calls. The
  D1 path batches reservation settlement, billing ledger debit, and
  sponsored-call record insertion, and requires the sponsored-call idempotency
  key to prevent retry debits.
- Added D1 Stripe credit purchase persistence, purchase receipt documents,
  receipt line items, and webhook event idempotency.
- Added persisted D1 monthly usage statements, MAW debit reconciliation, and
  the D1 monthly billing finalization runner.

Remaining before D1 staging:

- Finish only the console and signer D1 adapters required by the first staging
  dashboard, signer, sponsored gas, billing, and reconciliation flows.
- Add the Durable Object coordination tests required for signer admission,
  budget, replay, presignature, and signing-root coordination.
- Add local Wrangler/Miniflare smoke coverage for every required D1 table.
- Add staging import, restore, and R2 export drills.
- Keep the Postgres escape hatch as a typed full-family contract until a tenant
  or deployment actually needs Postgres.

## Scope

### In Scope

- Console org, project, environment, RBAC, policy, approval, API key, wallet,
  settings, and audit storage.
- Production sponsored EVM gas payments with prepaid billing and dashboard
  reconciliation.
- Billing summaries, append-only ledger entries, reservations, settlement, and
  release flows.
- Runtime snapshot persistence and snapshot outbox dispatch.
- Signer metadata, wallet auth, WebAuthn, email OTP, threshold key metadata,
  sealed signer ciphertext, recovery records, and identity indexes.
- Signer coordination in Durable Objects.
- Local D1/DO development and D1 adapter tests.
- Future Postgres adapter contract, readiness bar, and D1-to-Postgres migration
  path.

### Out Of Scope For The First Cut

- A live Postgres adapter implementation.
- A tenant route registry database.
- Dedicated tenant D1 databases.
- Postgres RLS, advisory locks, partitions, JSONB operators, or row locks in
  core domain code.
- High-volume raw observability in D1.
- Storing plaintext signer shares, root shares, private keys, KEKs, or API
  secrets in D1, Durable Objects, R2 exports, or Postgres.

## Target Runtime Topology

First release topology:

- One shared `CONSOLE_DB` D1 database.
- One shared `SIGNER_DB` D1 database.
- One shared `THRESHOLD_STORE` Durable Object namespace.
- One signer KEK provider configured for hosted production.
- Local Wrangler/Miniflare bindings for the same D1/DO shape.

Wrangler shape:

```toml
[[d1_databases]]
binding = "CONSOLE_DB"
database_name = "seams-console"
database_id = "<remote-console-d1-database-id>"
preview_database_id = "seams-console-local"
migrations_dir = "migrations/d1-console"

[[d1_databases]]
binding = "SIGNER_DB"
database_name = "seams-signer"
database_id = "<remote-signer-d1-database-id>"
preview_database_id = "seams-signer-local"
migrations_dir = "migrations/d1-signer"

[[durable_objects.bindings]]
name = "THRESHOLD_STORE"
class_name = "ThresholdStoreDurableObject"

[[migrations]]
tag = "signer-do-v1"
new_sqlite_classes = ["ThresholdStoreDurableObject"]
```

Local commands:

```bash
pnpm wrangler d1 migrations apply seams-console --local
pnpm wrangler d1 migrations apply seams-signer --local
pnpm wrangler d1 execute seams-console --local --command "SELECT 1"
pnpm wrangler d1 execute seams-signer --local --command "SELECT 1"
pnpm wrangler dev --persist-to .wrangler/state/seams-d1
```

Inspection:

- Open local SQLite files under `.wrangler/state/seams-d1` in TablePlus with
  the SQLite driver.
- Treat TablePlus as read-only.
- Remote D1 has no TablePlus TCP endpoint. Use `wrangler d1 execute`,
  `wrangler d1 export`, Cloudflare dashboard tools, or a purpose-built admin
  route.

## Storage Route Type

The route type allows only two backend families:

```ts
type CloudflareD1DoTenantRoute = {
  kind: 'cloudflare_d1_do';
  namespace: NamespaceId;
  orgId: OrgId;
  routeVersion: RouteVersion;
  topology: 'shared' | 'dedicated_tenant';
  jurisdiction: TenantDataJurisdiction;
  console: ConsoleD1Target;
  signer: SignerD1DoTarget;
  postgres?: never;
};

type PostgresTenantRoute = {
  kind: 'postgres';
  namespace: NamespaceId;
  orgId: OrgId;
  routeVersion: RouteVersion;
  migrationReason: 'd1_size_limit' | 'd1_throughput_limit' | 'logical_database_required';
  console: ConsolePostgresTarget;
  signer: SignerPostgresTarget;
  cloudflare?: never;
};

type TenantStorageRoute = CloudflareD1DoTenantRoute | PostgresTenantRoute;
```

Rules:

- First release uses a static resolver that always returns
  `kind: 'cloudflare_d1_do'` with `topology: 'shared'`.
- The canonical route registry is deferred. Add a dedicated `TENANT_ROUTE_DB`
  only when the first dedicated D1 route or Postgres route is needed.
- Route registry rows, once introduced, are parsed at the request boundary into
  `TenantStorageRoute`.
- Route target combinations are checked at the type level and again when parsing
  untrusted registry rows.
- Route changes are versioned. Writes include the expected `routeVersion` and
  fail with `tenant_route_changed` when stale.

## Domain Store Ports

Core logic depends on these ports:

- `ConsoleTenantRecordStore`: org, project, environment, RBAC, policies,
  approvals, API keys, account settings, wallets, and audit events.
- `ConsoleBillingStore`: prepaid summaries, reservations, ledger entries,
  sponsored execution settlement, and reconciliation reads.
- `ConsoleRuntimeSnapshotStore`: snapshot writes, outbox enqueue, lease claim,
  dispatch acknowledgement, retry visibility, and dead-letter state.
- `SignerMetadataStore`: wallet auth, WebAuthn, email OTP, threshold key
  metadata, sealed share ciphertext, recovery records, and identity indexes.
- `SignerCoordinationStore`: signing-session counts, signing budgets, replay
  guards, presignature pools, pool-fill compare-and-swap, and signing-root
  coordination.
- `SigningRootKekResolver`: resolves KEK material from Cloudflare Secrets Store,
  Wrangler secrets, or external KMS/HSM clients.

Every port result is a narrow `Result`-style union. Idempotency conflicts,
insufficient balance, expired reservations, duplicate identity, exhausted
signing budget, corrupt persisted rows, missing custody authority, and stale
route versions are recoverable domain failures. Driver errors stay inside
adapters.

## Postgres Coupling Inventory

Current Postgres coupling is concentrated in:

- `packages/sdk-server-ts/src/console/**/postgres.ts`
- `packages/sdk-server-ts/src/console/shared/postgresTenantContext.ts`
- `packages/sdk-server-ts/src/storage/postgres.ts`
- `packages/sdk-server-ts/src/core/**/*Store.ts`
- `packages/sdk-server-ts/src/core/ThresholdService/stores/*Store.ts`
- `packages/sdk-server-ts/src/router/routerAbNormalSigningAdmissionStore.ts`
- `packages/sdk-server-ts/src/threshold/session/signingSessionSeal/idempotencyBackends.ts`

### Console Table Ownership

| Area | Current Postgres tables | Target owner | Notes |
| --- | --- | --- | --- |
| Org/project/env | `console_organizations`, `console_projects`, `console_environments` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, and tenant-scoping contract test are in place. |
| Account/profile | `console_user_profiles`, `console_user_backup_emails` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, and profile/organization contract test are in place. |
| Team RBAC | `console_team_members` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, and owner/member lifecycle contract test are in place. Add `console_team_member_roles` only if indexed role lookup becomes necessary. |
| Approvals | `console_approvals` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, tenant-scoping checks, MFA enforcement, duplicate-decision checks, and state-specific conditional transition tests are in place. Approval JSON is stored as `TEXT` and parsed at the adapter boundary. |
| Audit | `console_audit_events`, `console_audit_evidence` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, event/evidence filters, search, duplicate-id handling, and tenant-scoping contract test are in place. JSON is stored as `TEXT` and parsed at the adapter boundary. |
| Bootstrap tokens | `console_bootstrap_tokens` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, tenant-scoped count/peek, and atomic conditional redemption contract test are in place. |
| Policies | `console_policies`, `console_policy_versions`, `console_policy_assignments` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, system-default uniqueness, publish-version history, and assignment-resolution contract test are in place. Policy JSON is stored as `TEXT`. |
| API keys | `console_api_keys` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, hashed lookup, secret-key auth, publishable-key auth, revoke/rotate/delete, anomaly flag, usage count, and tenant-scoping contract test are in place. |
| Wallet index | `console_wallet_index` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, tenant-scoped upsert/get/list/search, filter indexes, cursor pagination, and contract tests are in place. This is a queryable dashboard index only; signer ownership stays in `SIGNER_DB`/DO. |
| Billing | `console_billing_accounts`, `console_billing_ledger_entries`, `console_billing_ledger_postings`, `console_billing_monthly_active_wallets`, `console_billing_credit_purchases`, `console_invoices`, `console_invoice_line_items`, `console_stripe_webhook_events`; later `console_usage_meter_events`, `console_usage_rollups_monthly` if per-event usage audit or rollup replay becomes necessary | `CONSOLE_DB` D1 | D1 billing account/ledger tables, Stripe credit purchases, receipt invoices, monthly usage statements, receipt/statement line items, webhook idempotency, monthly finalization runner, append-only migrations, local smoke coverage, Cloudflare bundle wiring, manual credit/debit support, and sponsored execution debit statements are in place. |
| Prepaid reservations | `console_billing_prepaid_reservation_summaries`, `console_billing_prepaid_reservations` | `CONSOLE_DB` D1 | Trigger-backed D1 adapter, append-only migration, local smoke coverage, and contract tests are in place. Summary mutation and reservation lifecycle transitions remain SQLite-atomic. |
| Sponsored calls | `console_sponsored_call_records` | `CONSOLE_DB` D1 | D1 adapter, append-only migration, local smoke coverage, Cloudflare bundle wiring, idempotency test, and atomic sponsored gas settlement contract test are in place. |
| Sponsorship spend caps | `console_sponsorship_spend_cap_windows`, `console_sponsorship_spend_cap_reservations` | `CONSOLE_DB` D1 | Replace row locks with atomic conditional upserts against the window row. Keep source-event uniqueness. |
| Key exports | `console_key_exports` | `CONSOLE_DB` D1 | Replace approval `FOR UPDATE` with conditional approval insert plus derived status update. Store approvals/constraints as `TEXT` or normalize approvals into child rows. |
| Runtime snapshots | `console_runtime_snapshots`, `console_runtime_snapshot_outbox` | `CONSOLE_DB` D1 | Already has D1 schema. Replace `SKIP LOCKED` with claim lease columns and conditional updates. |
| Webhooks | `console_webhook_endpoints`, `console_webhook_deliveries`, `console_webhook_attempts`, `console_webhook_dead_letters` | `CONSOLE_DB` D1 | Replace GIN category index with `console_webhook_endpoint_categories(namespace, org_id, endpoint_id, category)`. Payload JSON is `TEXT`. |
| Key export and webhook secrets | `console_key_exports`, `console_webhook_endpoints.signing_secret` | `CONSOLE_DB` D1 plus secrets adapter | Store only encrypted/derived values in D1 when values can authorize actions. |
| Observability | `console_observability_events`, `console_observability_event_dedup`, `console_observability_ingest_windows`, `console_observability_request_rollups_minute` | R2/Analytics Engine plus limited D1 rollups | Keep high-volume raw events outside shared D1. D1 may store compact dashboard rollups and dedup markers only. |

### Signer Table Ownership

| Area | Current Postgres tables | Target owner | Notes |
| --- | --- | --- | --- |
| WebAuthn | `webauthn_authenticators`, `webauthn_credential_bindings`, `webauthn_challenges` | `SIGNER_DB` D1 | Tenant/project/env scope must be explicit where custody state is environment-specific. |
| Registration | `wallet_registration_intents`, `wallet_registration_ceremonies` | `SIGNER_DB` D1 | Expiring records with tenant-first indexes and cleanup job. |
| Wallet metadata | `wallets`, `wallet_auth_methods`, `wallet_signers` | `SIGNER_DB` D1 | Queryable durable signer metadata. Keep wallet ID, org, project, env, RP ID, and chain identity required. |
| Email OTP | `email_otp_challenges`, `email_otp_grants`, `email_otp_wallet_enrollments`, `email_otp_recovery_wrapped_enrollment_escrows`, `email_otp_auth_states`, `email_otp_unlock_challenges`, `email_otp_registration_attempts` | `SIGNER_DB` D1 | Challenge/grant expiry stays adapter-owned. Store JSON as `TEXT` and normalize lookup columns. |
| Threshold key metadata | `threshold_ed25519_keys`, `threshold_ecdsa_keys` | `SIGNER_DB` D1 | Durable metadata and public identifiers only. Secret shares stay application-encrypted. |
| Sealed signing-root shares | `signing_root_secret_shares`, `signer_signing_root_secret_shares` | `SIGNER_DB` D1 | D1 stores ciphertext, KEK ID, envelope version, AAD digest, ciphertext digest, and audit marker. |
| Device/recovery/identity | `device_linking_sessions`, `email_recovery_preparations`, `near_public_keys`, `identity_links`, `app_session_versions`, `recovery_sessions`, `recovery_executions` | `SIGNER_DB` D1 | Queryable records with explicit tenant and lifecycle columns. |
| Signing sessions | `threshold_ed25519_sessions` | Durable Object | Session use counts and replay-sensitive mutation need per-session serialization. Persist durable DO state before cache updates. |
| Budget and replay guards | `threshold_wallet_session_consumptions`, `threshold_wallet_session_budget_reservations`, `threshold_signing_session_seal_idempotency` | Durable Object | Replace row locks and unique idempotency rows with DO methods that return the same result unions. |
| ECDSA presign | `threshold_ecdsa_presign_sessions`, `threshold_ecdsa_presignatures` | Durable Object | Replace `FOR UPDATE SKIP LOCKED` with one object per relayer key or signing root. |
| Normal signing admission | `router_ab_normal_signing_quota_reservations`, `router_ab_normal_signing_project_policies`, `router_ab_normal_signing_abuse_records` | Durable Object | Quota reservation and abuse counters are hot coordination state. |

### Postgres Primitive Replacement Map

| Postgres primitive | Current use | D1/DO replacement |
| --- | --- | --- |
| Advisory migration locks | Schema setup in console and signer Postgres modules | Wrangler D1 migrations plus serialized CI/deploy migration command. Runtime adapters do not take migration locks. |
| Row-level security | Console tenant protection through Postgres policies | Tenant route resolution plus required tenant columns in every primary key and query. Tests must prove cross-org reads and writes fail. |
| `JSONB` columns | Policy payloads, webhook categories, audit evidence, signer records, session records | Store JSON as `TEXT` and parse once at adapter boundaries. Add normalized side tables for indexed membership queries. |
| GIN indexes | Webhook endpoint category lookup | `console_webhook_endpoint_categories` join table with `(namespace, org_id, category, endpoint_id)` index. |
| `FOR UPDATE` | Billing, approvals, key exports, bootstrap tokens, spend caps, signer sessions, signer budgets | D1 conditional updates or Durable Object serialized methods. The target owner decides the primitive. |
| `FOR UPDATE SKIP LOCKED` | Runtime snapshot outbox and ECDSA presignature reservation | D1 claim leases for snapshot outbox; Durable Object reservation method for presignatures. |
| Bigserial IDs | Webhook attempts and similar append-only rows | Application-generated IDs or monotonic per-owner counters inside the owning Durable Object. |
| Postgres partial indexes | Pending/unresolved and idempotency lookups | SQLite partial indexes where supported; otherwise explicit status columns in tenant-first indexes. |

### Adapter Checklist

Before D1 staging, these adapters must exist behind domain-store ports:

- Console D1 remaining: spend caps, key exports, webhooks, and compact
  observability rollups.
- Console D1 in place: org/project/env, account/profile, team RBAC, policies,
  wallet index, API keys, approvals, audit, bootstrap tokens, billing ledger
  sponsored settlement, prepaid reservations, sponsored calls, and runtime
  snapshots.
- Signer D1: WebAuthn, registration ceremonies, wallet metadata, auth methods,
  email OTP, recovery, identity links, app sessions, threshold key metadata,
  and sealed signing-root secret shares.
- Durable Objects: signing-session use counts, wallet signing budgets,
  idempotency/replay guards, ECDSA presignature pools, ECDSA pool-fill
  sessions, normal-signing admission quotas, and signing-root coordination.
- Postgres escape hatch: matching full-family ports, schemas, migrations, and
  shared contract tests before any production tenant can select Postgres.

## D1 Schema Rules

Every D1 table has explicit tenant columns. Console tables use
`(namespace, org_id, ...)`. Signer tables use the narrowest required identity,
usually `(namespace, org_id, project_id, env_id, ...)` for custody records and
wallet-specific keys for wallet auth records.

Baseline table shape:

```sql
CREATE TABLE console_projects (
  namespace TEXT NOT NULL,
  org_id TEXT NOT NULL,
  project_id TEXT NOT NULL,
  name TEXT NOT NULL,
  status TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER NOT NULL,
  PRIMARY KEY (namespace, org_id, project_id)
);
```

D1 adapter rules:

- Bind `namespace` and `org_id` in every console query.
- Bind signer identity fields in every signer query.
- Keep indexes page-first and tenant-first.
- Keep row values under D1 row/blob/string limits.
- Keep raw observability and large archive data outside D1 from the start.
- Use `D1Database.batch()` or trigger-backed single statements for invariants
  that must roll back together.
- Cover every trigger-backed invariant with local SQLite and D1 integration
  tests.

## Atomic Billing Reservations

Billing reservations must be atomic in D1/SQLite. Double debit risk is
unacceptable.

Recommended D1 implementation:

- `console_billing_prepaid_reservation_summaries`
  - Primary key: `(namespace, org_id)`.
  - Tracks active reserved amount, active reservation count, and updated time.
- `console_billing_prepaid_reservations`
  - Primary key: `(namespace, org_id, reservation_id)`.
  - Unique idempotency/source key: `(namespace, org_id, source_event_id)`.
  - Stores amount, state, created time, expiry, settlement reference, and
    posted balance evidence.
- `console_billing_ledger_entries`
  - Append-only evidence for credits, reservations, settlement, release,
    expiry, and corrections.

Reserve operation:

1. Read the current billing account balance from `console_billing_accounts`.
2. Insert the reservation row with a unique source or idempotency key and the
   posted balance evidence.
3. In the same SQLite atomic unit, verify
   `reserved_minor + reserve_amount <= posted_balance_minor`.
4. Abort the insert with a domain error such as `prepaid_balance_insufficient`
   when funds are unavailable.
5. On duplicate source key, return the existing reservation result after parsing
   the stored row.

Implementation options:

- Preferred first cut: one `INSERT` guarded by SQLite triggers that create the
  summary row if needed, check balance, and mutate the summary atomically.
- Acceptable alternative: one `D1Database.batch()` with a conditional summary
  update and a reservation insert, with tests proving rollback and duplicate
  idempotency behavior.

Settle, release, and expire operations use state-specific conditional writes:

- `RESERVED -> SETTLED`
- `RESERVED -> RELEASED`
- `RESERVED -> EXPIRED`

Each transition updates the summary and writes ledger evidence in the same D1
atomic unit.

## Sponsored EVM Gas Payments

Simplified product scope:

- Production sponsored gas payments for EVM calls.
- Prepaid billing only.
- Dashboard reconciliation for sponsored executions, fee estimates, final fees,
  reservation IDs, ledger IDs, and settlement status.

Flow:

1. Authorize the API key and resolve tenant route.
2. Estimate sponsor cost and create a prepaid reservation.
3. Execute the EVM call.
4. Record the sponsored call result with an idempotency key.
5. Finalize settlement by atomically updating the sponsored call, reservation,
   billing summary, and ledger entry.
6. Reconcile dashboard views from sponsored call records plus billing ledger
   evidence.

D1 settlement invariant:

- A sponsored execution can settle only once.
- A reservation can settle only once.
- Sponsored-call records require an idempotency key.
- The ledger entry for settlement is unique by `(namespace, org_id, entry_type,
  source_event_id)`, where `source_event_id` is derived from the reservation
  source event.
- Finalization runs as one D1 `D1Database.batch()` unit over the shared
  `CONSOLE_DB`: reservation lifecycle update, sponsored execution debit ledger
  insert, and sponsored-call record insert.

Recoverable states:

- `reserved`
- `executed_pending_settlement`
- `settled`
- `released`
- `failed_released`
- `reconciliation_required`

## Runtime Snapshot Outbox

Replace `FOR UPDATE SKIP LOCKED` with a D1 lease model.

Outbox columns:

- `namespace`
- `org_id`
- `event_id`
- `snapshot_id`
- `event_kind`
- `payload_json`
- `status`
- `attempt_count`
- `available_at_ms`
- `claimed_by`
- `claim_expires_at_ms`
- `last_error`
- `created_at_ms`
- `updated_at_ms`

Claiming approach:

1. Select a bounded page of visible rows where `status = 'pending'`,
   `available_at_ms <= now`, and the existing claim is empty or expired.
2. For each candidate, run conditional `UPDATE ... WHERE event_id = ? AND
   (claimed_by IS NULL OR claim_expires_at_ms < ?)`.
3. Read back rows claimed by this worker and lease token.
4. Mark dispatched, retry, or dead-letter with state-specific conditional
   updates.

Cloudflare Queues or Workflows remain a later dispatch option. The first cut
keeps outbox semantics in D1 because it is the closest replacement for the
current snapshot outbox contract.

## Signer Persistence

D1 owns durable queryable signer state:

- wallets and wallet auth methods
- WebAuthn authenticators, bindings, and challenges
- email OTP challenges, grants, enrollments, recovery escrows, and auth state
- wallet signers and threshold key metadata
- sealed signing-root secret shares
- device linking, identity links, app sessions, recovery sessions, and recovery
  executions

Durable Objects own hot coordination state:

- signing-session use-count consumption
- idempotency consumption guards
- wallet signing budget reserve, commit, release, and validation
- ECDSA presignature put, reserve, take, and discard
- ECDSA pool-fill compare-and-swap advancement
- Ed25519 presign capacity and rate limiting
- signing-root status and replay guards

Durable Object names:

```text
threshold-store:namespace:{namespace}:wallet:{walletId}
threshold-store:namespace:{namespace}:signing-root:{signingRootId}:{signingRootVersion}
threshold-store:namespace:{namespace}:relayer-key:{relayerKeyId}
threshold-store:namespace:{namespace}:session:{sessionId}
```

DO rules:

- Use one object per coordination atom.
- Persist before updating in-memory cache.
- Keep `blockConcurrencyWhile()` limited to constructor schema setup.
- Avoid external network I/O inside critical mutations.
- Use typed RPC methods for new callers.
- Keep import-only fetch surfaces behind migration admin boundaries and delete
  them before production cutover.

## Encrypted Signer Secrets

D1 may store encrypted signer ciphertext. D1 must never store plaintext signer
shares, root shares, private keys, KEKs, or API secrets.

Sealed share rows include:

- tenant identity fields
- signing root ID and version
- share ID
- sealed ciphertext
- optional external storage ID
- KEK ID
- envelope version
- AAD digest
- ciphertext digest
- rotation state
- last audit event ID
- created and updated timestamps

KEK provider shape:

```ts
type SignerKekProvider =
  | {
      kind: 'cloudflare_secrets_store';
      secretsByKekId: Readonly<Record<KekId, CloudflareSecretsStoreSecretBinding>>;
      encoding: SigningRootEncodedKekMaterialEncoding;
      workerSecretsByKekId?: never;
      externalKmsClient?: never;
    }
  | {
      kind: 'worker_secret';
      workerSecretsByKekId: Readonly<Record<KekId, string>>;
      encoding: SigningRootEncodedKekMaterialEncoding;
      secretsByKekId?: never;
      externalKmsClient?: never;
    }
  | {
      kind: 'external_kms';
      externalKmsClient: SigningRootExternalKmsKekClient;
      secretsByKekId?: never;
      workerSecretsByKekId?: never;
      encoding?: never;
    };
```

Rules:

- Core sealing code depends on `SigningRootKekResolver`.
- Hosted production uses Cloudflare Secrets Store.
- Local development may use Wrangler secrets.
- Enterprise custody can use an external KMS/HSM through a signer-only adapter.
- Console routes cannot access signer KEKs.
- Import tooling may handle plaintext only in process memory during a controlled
  migration. Plaintext cannot be logged, written to disk, returned in responses,
  or stored in D1/DO/R2/Postgres.

## Multi-Tenancy Decisions

First-release recommendation:

- Use shared D1 databases for all tenants.
- Add tenant route resolution now, backed by a static resolver.
- Defer the route registry until a tenant needs a dedicated D1 route or
  full-family Postgres route.
- Keep every table tenant-scoped.
- Keep raw observability, bulky snapshots, and long-retention archives out of
  shared D1.

D1 scaling thresholds:

- Alert at 7 GB.
- Prepare cold-data offload, dedicated tenant D1, or Postgres migration at 8 GB.
- Freeze new high-volume writes and execute the move before 9 GB.
- Treat 10 GB as a hard cap, since paid D1 databases are capped at 10 GB per
  database.

Scaling order:

1. Move raw and cold data out of D1.
2. Move a large enterprise tenant to dedicated `CONSOLE_DB` and `SIGNER_DB`
   bindings.
3. Move the tenant or deployment to the full-family Postgres adapter when the
   product needs one logical relational database above D1 limits.

Dedicated tenant D1 triggers:

- Contractual database-level isolation.
- Database-level restore/export/delete requirements.
- Tenant signer or console rows exceed 2 GB.
- One tenant consumes more than 30 percent of shared D1 storage.
- Shared D1 reaches 7 GB and one tenant is the largest contributor.
- Repeated hot-tenant latency or overload incidents.
- Customer-managed KMS/HSM or dedicated KEK lifecycle.

## Backup And Recovery

D1 reliability plan:

- Use D1 Time Travel as the primary short-term recovery layer for production D1
  databases on the production storage subsystem.
- Verify production storage support with `wrangler d1 info DB_NAME` before
  cutover.
- Capture `wrangler d1 time-travel info DB_NAME` bookmarks before migrations,
  imports, tenant moves, route switches, and destructive maintenance.
- Keep weekly exports of `CONSOLE_DB` and `SIGNER_DB` in R2.
- Add weekly exports for `TENANT_ROUTE_DB` after the registry exists.
- Add weekly exports for every dedicated tenant D1.
- Retain weekly R2 exports for at least 12 weeks unless customer or compliance
  policy requires more.
- Run monthly staging restore drills from Time Travel and R2 exports.

Security notes:

- D1 encrypts data at rest and in transit.
- Signer shares remain application-encrypted before storage.
- R2 exports contain sensitive encrypted data and require restricted access.
- KEKs are never exported to D1, R2, or local SQLite files.
- Tenant deletion reports must account for Time Travel, export, and backup
  retention windows.

## Postgres Escape Hatch

Postgres is a future full-family backend adapter selected by
`TenantStorageRoute`. Partial backend splits are invalid.

Postgres adapter readiness bar:

- Every required domain-store port has a Postgres implementation.
- Postgres migrations exist for console, billing, sponsored gas, runtime
  snapshots, signer metadata, signer coordination, and reconciliation data.
- Schemas mirror the D1 logical model: tenant keys, lifecycle columns,
  idempotency keys, uniqueness constraints, ciphertext fields, AAD fields,
  digest fields, and parse boundaries.
- Billing reserve, settle, release, and expiry operations run in one Postgres
  transaction and lock the summary and reservation rows they mutate.
- Sponsored settlement finalization runs in one transaction that updates the
  sponsored execution, reservation lifecycle, billing summary, and ledger entry.
- Snapshot outbox claiming may use `FOR UPDATE SKIP LOCKED` inside the adapter.
  It returns the same lease, retry, and dead-letter result unions as the D1
  adapter.
- Signer coordination uses transactions, row locks, and unique idempotency
  indexes to match Durable Object result contracts.
- Worker runtime access uses Hyperdrive. Node migration tooling may use a direct
  Postgres pool.
- Shared contract tests pass against D1/DO and Postgres.
- Export/import tooling has passed a tenant smoke test.

D1-to-Postgres migration path:

1. Provision Postgres and Hyperdrive.
2. Apply Postgres adapter migrations.
3. Capture D1 Time Travel bookmarks and write a migration manifest to R2.
4. Freeze tenant writes through the route layer.
5. Export all tenant-scoped D1 state and Durable Object durable coordination
   state.
6. Parse exports into internal domain types.
7. Import through Postgres adapters.
8. Run count, key-identity, signer sealed-share, billing-balance, sponsored gas,
   snapshot outbox, and dashboard smoke checks.
9. Switch the route to the `postgres` branch with a route version compare-and-set.
10. Reopen writes.
11. Keep source D1 read-only through the archive window, then delete rows in
    small batches.

## Simplified Execution Track

Goal: ship staging on D1/DO with the smallest backend surface that preserves
sponsored gas billing, dashboard reconciliation, signer custody, tenant
isolation, local development, recovery, and a full-family Postgres escape
hatch.

### Step 1: Inventory Postgres Coupling

Status: first pass complete. Keep the ownership matrix current as adapters
land.

Work:

- Inventory `seams-console` Postgres services, SQL files, migrations, and tests.
- Inventory `seams-signer` Postgres tables and runtime call sites.
- Categorize each table as console D1, signer D1, signer Durable Object, raw
  archive, or deferred Postgres escape-hatch concern.
- Record every `FOR UPDATE`, `SKIP LOCKED`, advisory lock, transaction, JSONB,
  partial-index, and RLS dependency.

Exit criteria:

- Every current Postgres table and SQL primitive has a target owner in this
  document.
- Remaining unknowns are tracked as explicit open items before adapter work
  starts.

### Step 2: Define D1 Schemas And Durable Object Ownership

Status: complete for the first implemented adapter slices; continue only for
remaining staging-required flows.

Work:

- Add D1 migrations for the console and signer tables required by staging.
- Add Durable Object storage schemas for signer coordination atoms.
- Define lifecycle states, idempotency keys, tenant-first indexes, lease
  columns, and atomic D1/SQLite invariants.
- Store JSON as `TEXT` and add side tables only for indexed membership queries.

Exit criteria:

- Local Wrangler/Miniflare migrations apply cleanly for `CONSOLE_DB` and
  `SIGNER_DB`.
- Every staging-required table appears in the D1 smoke Worker.
- Atomic billing, sponsored settlement, snapshot leases, and signer secret rows
  have focused schema tests.

### Step 3: Add D1/DO Adapters Behind Domain Stores

Status: in progress.

Work:

- Finish remaining console D1 adapters for spend caps, key exports, webhooks,
  and compact observability rollups.
- Finish remaining signer D1 adapters for wallet metadata, wallet auth,
  WebAuthn, email OTP, recovery, identity links, app sessions, and threshold key
  metadata.
- Finish Durable Object adapters for signer admission, budgets, replay guards,
  presignature pools, and signing-root coordination.
- Keep the KEK provider boundary narrow: Cloudflare Secrets Store for hosted
  production, Wrangler secrets for local development, external KMS/HSM for
  enterprise custody.

Exit criteria:

- Core logic receives domain-store ports only.
- Adapter tests prove tenant scoping, idempotency, lifecycle transitions, and
  corrupt-row parsing for each high-risk store.
- Route-owned staging persistence no longer depends on local Postgres.

### Step 4: Make Local Development D1/DO By Default

Status: partly complete.

Work:

- Keep local Postgres available only for current unfinished areas while the
  refactor is underway.
- Make the default local console/signer path use Wrangler/Miniflare D1 and local
  Durable Object storage once required adapters exist.
- Add reset, seed, migrate, and smoke commands for local D1/DO.
- Document read-only TablePlus inspection of local SQLite files under
  `.wrangler/state`.

Exit criteria:

- A developer can run the dashboard, signer flows, sponsored gas billing, and
  reconciliation locally without Docker Postgres.
- The local command path mirrors Cloudflare bindings and D1 API behavior.

### Step 5: Port Tests To D1/DO

Status: in progress.

Work:

- Move persistence tests for staging-required flows onto D1/DO adapters.
- Add Workers/Vitest or Playwright coverage where real bindings matter.
- Keep pure unit fakes for core logic that does not depend on SQL behavior.
- Cover duplicate idempotency, insufficient balance, settlement replay, lease
  races, tenant isolation, sealed-share parsing, budget exhaustion, and
  signing-root coordination.

Exit criteria:

- `pnpm --dir packages/sdk-server-ts type-check` passes.
- Local D1 adapter contract tests pass.
- Local Wrangler/Miniflare smoke proves all required D1 tables exist.
- Durable Object coordination tests pass for hot signer state.

### Step 6: Deploy D1/DO Staging

Status: pending.

Work:

- Apply D1 migrations to staging.
- Configure hosted signer KEK provider and verify console routes cannot access
  signer KEKs.
- Import staging fixture data through D1/DO import tooling.
- Capture D1 Time Travel bookmarks before imports and route changes.
- Run local smoke, staging smoke, dashboard reconciliation checks, signer
  custody checks, and R2 export/restore drills.

Exit criteria:

- Staging starts on D1/DO.
- No request path mixes D1/DO and Postgres.
- Dashboard reconciliation, sponsored gas settlement, signer custody, and
  restore drills pass before production planning begins.

## Validation

Minimum checks before first D1 staging deploy:

- `pnpm --dir packages/sdk-server-ts type-check`
- D1 schema smoke tests for every migration.
- Billing reservation atomic duplicate and insufficient-balance tests.
- Sponsored settlement idempotency and replay tests.
- Snapshot outbox lease claim tests.
- Tenant scoping tests that prove cross-org reads and writes fail.
- Signer sealed-share parser tests.
- Durable Object coordination tests for budgets, replay guards, presignature
  pools, and session consumption.
- Local Wrangler D1 smoke:

```bash
pnpm wrangler d1 migrations apply seams-console --local
pnpm wrangler d1 migrations apply seams-signer --local
pnpm wrangler d1 execute seams-console --local --command "SELECT 1"
pnpm wrangler d1 execute seams-signer --local --command "SELECT 1"
```

## Immediate Next Steps

Completed:

1. Inventory current Postgres coupling in `seams-signer` and `seams-console`.
2. Define the first D1 schemas and Durable Object ownership boundaries.
3. Add D1 adapters for org/project/env, account/profile, team RBAC, policies,
   wallet index, API keys, approvals, audit, bootstrap tokens, billing ledger
   settlement, prepaid reservations, sponsored calls, runtime snapshots, and
   sealed signing-root secret shares.
4. Make local development run on Wrangler/Miniflare D1 for the implemented D1
   adapters.
5. Port focused adapter tests to D1 for the implemented D1 adapters.
6. Add D1 billing ledger settlement finalization for sponsored EVM gas payments.
7. Add D1 Stripe credit purchase persistence, purchase receipts, and webhook
   idempotency.
8. Add persisted D1 monthly usage statements and the D1 monthly billing
   finalization runner.

Next:

1. Continue Step 3 by adding the remaining console D1 adapters: spend caps, key
   exports, webhooks, and compact observability rollups.
2. Continue Step 3 by adding the remaining signer D1 metadata adapters: wallet
   metadata, wallet auth, WebAuthn, email OTP, recovery, identity links, app
   sessions, and threshold key metadata.
3. Finish the Durable Object adapter and test slice for normal-signing
   admission, budget, replay, presignature, and signing-root coordination.
4. Finish Step 4 by making Wrangler/Miniflare D1 and local Durable Object
   storage the default development path after required adapters exist.
5. Finish Step 5 with D1/DO contract tests and local smoke coverage for every
   staging-required table.
6. Deploy staging only after local D1 smoke and all D1/DO adapter contract tests
   pass.

Key rule for execution: no half-Postgres staging. If D1 is the target, staging
starts life on D1.
