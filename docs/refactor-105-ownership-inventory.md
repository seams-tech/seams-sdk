# Refactor 105 Phase 0: Historical Ownership Inventory

Date frozen: August 18, 2026

Status: historical snapshot. It records the pre-closeout classification and is
not an extraction manifest or evidence that the current tree satisfies the
Refactor 105 boundary. Refactor 105B Phase 0 must regenerate and reconcile the
current route, service, schema, test, workflow, and path inventory before it
freezes an extraction reference. The repository destination addendum below is
the current ownership decision.

This is the checked-in ownership matrix required by
[refactor-105-split-console.md](./refactor-105-split-console.md) Phase 0. Every
current route, service, table, migration, scheduled job, environment binding,
UI route, event category, and relevant test is assigned to exactly one owner:

- `console-core` — product-neutral customer control plane;
- `wallet-console` — hosted wallet administration (future
  `wallet-console-shared-ts` / `wallet-console-server-ts`);
- `mpc-admin` — Refactor 99B operator plane (no package or `/admin` Worker
  exists yet; these assignments are forward-looking);
- `composition` — deployed/local wiring that may import both sides.

Items marked `MIXED` carry both core and Wallet vocabulary today; their split
is named inline and executes in Phases 1-2 (contracts/services) or Phase 6
(schema).

## Baseline

- Console D1 baseline: `packages/console-server-ts/migrations/d1-console/0001_console_d1_initial.sql`
  — 49 tables (clean-slate consolidation, August 17).
- Signer D1 baseline: `packages/wallet-server/migrations/d1-signer/0001_signer_d1_initial.sql`
  — 52 tables.
- Refactor 130A's legacy inbound-email recovery paths are absent from this
  tree; they are not inventoried. No Refactor 113/114 implementation has
  landed.
- `apps/seams-admin` and `platform-admin-server-ts` (Refactor 99B) do not
  exist yet; the Gateway still serves the routes destined for them.
- Concurrent R103 zero-prompt work is in flight in
  `packages/wallet/src/SeamsWeb/operations/devices/`, `registration.ts`, and
  the linked-device tests. Those files are Wallet-runtime owned and outside
  every boundary this inventory freezes; Phase 0-3 does not touch them.

## Workspace Packages And Applications

| Path                         | Owner        | Notes                                                                                                                                          |
| ---------------------------- | ------------ | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/console-shared-ts` | console-core | MIXED: wallet vocabulary moves to `wallet-console-shared-ts` in Phase 1 (see vocabulary inventory)                                             |
| `packages/console-server-ts` | console-core | MIXED: wallet services move to `wallet-console-server-ts` in Phase 2 (see service inventory)                                                   |
| `packages/wallet`            | wallet       | public `@seams/wallet`; renamed `packages/wallet` in Phase 7                                                                                   |
| `packages/wallet-server`     | wallet       | public `@seams/wallet-server`; renamed `packages/wallet-server` in Phase 7                                                                     |
| `packages/shared-ts`         | wallet       | shared browser/server contracts consumed by the Wallet packages (see shared-ts note)                                                           |
| `apps/seams-site`            | MIXED        | marketing + demos stay; `/dashboard/*` extracts to `apps/seams-console` in Phase 5                                                             |
| `apps/web-server`            | composition  | Express in-memory console-only dev server (NOT the gateway; the hosted gateway entrypoints live in `console-server-ts/src/router/cloudflare/`) |
| `apps/docs`                  | composition  | hosted docs application stays private; Wallet API/protocol/example documents receive one canonical public copy under `seams-wallet/docs`      |
| `crates/*`, `wasm/*`         | wallet       | signer runtime and protocol crates                                                                                                             |

## Console D1 Tables (49)

Owner `wallet-console` tables move with Phase 2 services and get their own
schema section in Phase 6. `MIXED` core tables stay core with their Wallet
vocabulary (CHECK catalogs, enum values) relocated to Wallet Console
validation.

| #   | Table                                   | Owner          | Notes                                                                        |
| --- | --------------------------------------- | -------------- | ---------------------------------------------------------------------------- |
| 1   | `api_keys`                              | console-core   | MIXED: wallet/signing scope CHECK catalog moves to Wallet Console validation |
| 2   | `approvals`                             | wallet-console | wallet approval payloads                                                     |
| 3   | `audit_events`                          | console-core   | MIXED: wallet event vocabulary in payloads/categories                        |
| 4   | `audit_evidence`                        | console-core   | MIXED: wallet evidence details                                               |
| 5   | `billing_accounts`                      | console-core   |                                                                              |
| 6   | `billing_credit_purchases`              | console-core   |                                                                              |
| 7   | `billing_disputes`                      | console-core   |                                                                              |
| 8   | `billing_ledger_entries`                | console-core   | MIXED: wallet usage enums in posting vocabulary                              |
| 9   | `billing_ledger_postings`               | console-core   | MIXED: wallet usage enums                                                    |
| 10  | `billing_monthly_active_resources`      | console-core   | product-neutral active-resource meter                                        |
| 11  | `billing_prepaid_reservation_summaries` | wallet-console | decided in Phase 2: no non-wallet caller; moved with sponsorship             |
| 12  | `billing_prepaid_reservations`          | wallet-console | decided in Phase 2: moved with sponsorship                                   |
| 13  | `billing_refunds`                       | console-core   |                                                                              |
| 14  | `billing_stripe_post_processing_outbox` | console-core   |                                                                              |
| 15  | `console_email_deliveries`              | console-core   |                                                                              |
| 16  | `console_email_outbox`                  | console-core   |                                                                              |
| 17  | `environments`                          | console-core   |                                                                              |
| 18  | `invoice_line_items`                    | console-core   |                                                                              |
| 19  | `invoices`                              | console-core   |                                                                              |
| 20  | `key_exports`                           | wallet-console |                                                                              |
| 21  | `observability_event_dedup`             | console-core   | MIXED: fleet/platform slices move to mpc-admin under R99B                    |
| 22  | `observability_events`                  | console-core   | MIXED: same                                                                  |
| 23  | `observability_ingest_windows`          | console-core   | MIXED: same                                                                  |
| 24  | `observability_request_rollups_minute`  | console-core   | MIXED: same                                                                  |
| 25  | `organization_admin_permissions`        | console-core   |                                                                              |
| 26  | `organization_invitations`              | console-core   |                                                                              |
| 27  | `organization_memberships`              | console-core   |                                                                              |
| 28  | `organization_owner_events`             | console-core   |                                                                              |
| 29  | `organizations`                         | console-core   |                                                                              |
| 30  | `policies`                              | wallet-console |                                                                              |
| 31  | `policy_assignments`                    | wallet-console |                                                                              |
| 32  | `policy_versions`                       | wallet-console |                                                                              |
| 33  | `project_member_access`                 | console-core   |                                                                              |
| 34  | `projects`                              | console-core   |                                                                              |
| 35  | `runtime_snapshot_outbox`               | wallet-console |                                                                              |
| 36  | `runtime_snapshots`                     | wallet-console |                                                                              |
| 37  | `sponsored_call_records`                | wallet-console |                                                                              |
| 38  | `sponsorship_pricing_rules`             | wallet-console |                                                                              |
| 39  | `sponsorship_spend_cap_reservations`    | wallet-console |                                                                              |
| 40  | `sponsorship_spend_cap_windows`         | wallet-console |                                                                              |
| 41  | `stripe_webhook_events`                 | console-core   |                                                                              |
| 42  | `user_backup_emails`                    | console-core   |                                                                              |
| 43  | `user_profiles`                         | console-core   |                                                                              |
| 44  | `wallet_index`                          | wallet-console |                                                                              |
| 45  | `webhook_attempts`                      | console-core   | delivery transport                                                           |
| 46  | `webhook_dead_letters`                  | console-core   | delivery transport                                                           |
| 47  | `webhook_deliveries`                    | console-core   | delivery transport                                                           |
| 48  | `webhook_endpoint_categories`           | console-core   | MIXED: wallet event category catalog moves to Wallet Console validation      |
| 49  | `webhook_endpoints`                     | console-core   |                                                                              |

Wallet Console total: 14 tables (`wallet_index`, `key_exports`, `policies`,
`policy_versions`, `policy_assignments`, `approvals`, `runtime_snapshots`,
`runtime_snapshot_outbox`, four sponsorship tables, `sponsored_call_records`,
and both prepaid-reservation tables per the Phase 2 caller decision). Console
core total: 35, including the generic active-resource billing meter.

Phase 6 cutover (landed): the composed baseline is now
`packages/wallet-console-server-ts/migrations/d1-console/0001_wallet_console_initial.sql`
(core section + wallet section, one owner per section); the fresh Console-core
schema is
`packages/console-server-ts/migrations/d1-console-core/0001_console_core_initial.sql`.
`tests/unit/consoleSchemaOwnership.unit.test.ts` holds both fresh schemas to
exactly these ownership sets. The old `0001_console_d1_initial.sql` is
deleted; both files apply the identical 49-table schema for the single
`seams-console` D1 retained during R105.

## Signer D1 Tables (52)

All 52 tables in the canonical signer baseline are Wallet runtime ownership
and stay packaged with the Wallet server (`@seams/wallet-server` after Phase
7). Verified against the retired-surface list: the baseline contains no
`app_session`, `authorization_session`, or legacy inbound-email recovery
table. `authorization_wallet_session_quotas`, `opaque_wallet_session_tokens`,
and `verified_owner_proof_consumptions` are current R107 opaque-session state,
not retired surfaces. The `email_otp_*` tables are the current OTP auth
factor, not R130A's deleted inbound-email recovery.

`authorization_wallet_session_quotas`, `authorized_operation_audit_events`,
`authorized_operations`, `email_otp_auth_states`, `email_otp_challenges`,
`email_otp_grants`, `email_otp_rate_limits`,
`email_otp_registration_attempts`, `email_otp_unlock_challenges`,
`email_otp_wallet_enrollments`, `hosted_wallet_session_exchange_codes`,
`identity_links`, `lane_cas_guard`, `lane_effect_journal`, `lane_enrollments`,
`lane_locks`, `lane_product_epochs`, `lane_protocol_operations`,
`lane_receipts`, `linked_device_custody_transfers`,
`linked_device_owner_auth_bindings`,
`linked_device_owner_planning_snapshots`,
`linked_device_provisioning_records`, `linked_device_request_proof_nonces`,
`linked_device_session_cas_guard`, `linked_device_session_transcripts`,
`linked_device_sessions`, `linked_device_source_handoffs`,
`linked_device_target_commit_reservations`,
`linked_device_target_credentials`,
`linked_device_target_deployment_descriptors`,
`linked_device_wallet_session_authorizations`,
`linked_device_wallet_session_quotas`, `near_public_keys`,
`opaque_wallet_session_tokens`, `registration_ceremony_cas_guard`,
`registration_ceremony_records`, `reusable_wallet_sessions`,
`router_ab_normal_signing_admission_records`,
`router_ab_yao_capability_replacements`,
`router_ab_yao_versioned_json_cas_guard`,
`router_ab_yao_versioned_json_records`, `vault_proxy_secrets`,
`verified_owner_proof_consumptions`,
`verified_wallet_operation_evidence_sets`, `wallet_auth_methods`,
`wallet_ecdsa_pending_session_activations`, `wallet_signers`, `wallets`,
`webauthn_authenticators`, `webauthn_challenges`,
`webauthn_credential_bindings`.

The private role-storage migrations under
`crates/router-ab-cloudflare/migrations/` (deriver-a, deriver-b,
signing-worker) are Wallet runtime ownership.

## Boundary Guard

`tests/scripts/check-console-core-wallet-import-boundaries.mjs`
(`pnpm -C tests run check:console-core-wallet-import-boundaries`, part of
`test:source-guards`) forbids every `@seams/wallet`, `@seams/wallet-server`,
`@seams/wallet`, `@seams/wallet-server`, or relative Wallet-source import in
`packages/console-server-ts/src` and `packages/console-shared-ts/src`, beyond
a temporary allowlist of the 80 inventoried pre-split imports (79 files x
`@seams/wallet-server/cloud-host` plus `router/cloudflare/d1SignerWasm.ts` x
`@seams/wallet-server/wasm/signer`). Allowlist entries may only be deleted;
stale entries fail the guard. `console-shared-ts` has zero entries and must
stay clean.

## Console Routes And Services

The authoritative route table is
`packages/console-server-ts/src/router/consoleRouteDefinitions.ts` (113
declared routes with RBAC requirements), mirrored 1:1 by the Express router
(`src/router/express/createConsoleRouter.ts`) and the Cloudflare router
(`src/router/cloudflare/createCloudflareConsoleRouter.ts`). Three routes are
undeclared: `/console/healthz`, `/console/readyz`, and the signature-verified
`POST /console/billing/stripe/webhook`.

Route-group ownership:

| Route group                                                                                                                       | Owner                  | Notes                                                                                                                                                      |
| --------------------------------------------------------------------------------------------------------------------------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| session, account, org/project/env, memberships, invitations, onboarding, isolation                                                | console-core           |                                                                                                                                                            |
| api-keys lifecycle                                                                                                                | console-core           | scope catalog values are wallet vocabulary (Phase 1)                                                                                                       |
| audit, audit exports                                                                                                              | console-core           |                                                                                                                                                            |
| webhooks CRUD/deliveries/replay                                                                                                   | console-core           | category catalog is mixed                                                                                                                                  |
| billing overview/invoices/refunds/checkout                                                                                        | console-core           | `GET /console/billing/usage/monthly-active-wallets` is a wallet-console meter                                                                              |
| observability summary/events/timeseries/services                                                                                  | console-core           | tenant-scoped reads                                                                                                                                        |
| wallets, wallets/search, wallets/:id                                                                                              | wallet-console         |                                                                                                                                                            |
| policies (CRUD/versions/assignments/simulate/publish)                                                                             | wallet-console         |                                                                                                                                                            |
| key-exports                                                                                                                       | wallet-console         |                                                                                                                                                            |
| approvals                                                                                                                         | console-core mechanism | current operation types (`POLICY_PUBLISH`, `KEY_EXPORT`) are both wallet-console; payload vocabulary moves, queue mechanism stays                          |
| runtime-snapshots                                                                                                                 | wallet-console         |                                                                                                                                                            |
| insights (`/console/policy/coverage`, `/console/gas/readiness`, `/console/export/governance`)                                     | wallet-console         |                                                                                                                                                            |
| `platform.support` routes (ops-cockpit summary, `/console/platform/billing/*`, usage-event/invoice-generate/adjustment admin ops) | mpc-admin              | leaves customer Console under R99B                                                                                                                         |
| `/console/auth/google`, `/console/auth/github`, `/console/auth/revoke`                                                            | console-core           | currently implemented in the composed worker entrypoint (`d1RouterApiStagingWorker.ts` `HostedConsoleAuthHandler`); moves to the Console Worker in Phase 4 |

Router-API relay routes owned by this package (registered as
`RouterApiRouteExtension`s in `src/router/routeExtensions.ts`, mounted by the
Wallet Gateway): `GET /v1/wallets`, `GET /v1/wallets/search`,
`GET /v1/wallets/:id`, `POST /signed-delegate`,
`POST /sponsorships/evm/call` — all wallet-console.

### Service bag

`ConsoleRouterOptions` (`src/router/console.ts:46`) is the broad optional bag
the plan retires: ~25 service fields, every one optional/nullable, plus a
discriminated tenant-storage pair. Phase 1 replaces it with exact
`createConsoleCoreRouter` / `createWalletConsoleRouter` required-input
compositions.

### Service modules

| Modules (under `packages/console-server-ts/src/`)                                                                                                                                                                                                                                                                                                                              | Owner                                                                                                                                     |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `orgProjectEnv/`, `teamRbac/`, `account/`, `apiKeys/`, `audit/`, `auditExports/`, `email/` (+`otp/`), `webhooks/`, `billing/` (ledger, Stripe, PDF, readiness, adjustments, credit packs), `enterpriseIsolation/`, `onboarding/`, `observability/`, `shared/requestParse.ts`                                                                                                   | console-core                                                                                                                              |
| `wallets/`, `policies/`, `gasSponsorship/`, `sponsorship/`, `sponsorshipSpendCaps/`, `sponsorshipPricing/`, `sponsoredCalls/`, `billingPrepaidReservations/`, `runtimeSnapshots/`, `keyExports/`                                                                                                                                                                               | wallet-console                                                                                                                            |
| `router/routerApiWallets.ts`, `routerApiSignedDelegate.ts`, `routerApiSponsoredEvmCall.ts`, `sponsorshipRuntime.ts`, `sponsorshipExecution.ts`, `sponsorshipBillingEvents.ts`, `sponsorshipSpendCapObservability.ts`, `runtimeSnapshotPayload.ts`, `policyPresentation.ts`, `consoleInsights.ts`, `routerApiKeyAuth.ts`                                                        | wallet-console (routerApiKeyAuth is the CC/WC auth boundary)                                                                              |
| `router/opsCockpitSummary.ts`, `router/platformBilling.ts`                                                                                                                                                                                                                                                                                                                     | mpc-admin                                                                                                                                 |
| `router/console.ts`, `consoleAuth.ts`, `consoleAppSessionAuth.ts`, `consoleSessionContext.ts`, `consoleRouteDefinitions.ts`, `consoleRouteSurface.ts`, `consoleRoutePolicy.ts`, `consoleAuditMetadata.ts`, `consoleObservabilityHooks.ts`, `routeExtensions.ts`, `stripePostProcessing.ts`, both `createC*Router.ts` assemblies, `express-adaptor.ts`, `cloudflare-adaptor.ts` | composition (route/auth mechanism is console-core; wallet route mounting separates in Phase 2)                                            |
| `router/cloudflare/` workers (`d1LocalDevWorker.ts`, `d1RouterApiStagingWorker.ts`, `d1ConsoleStagingWorker.ts`, `d1RouterApiWorker.ts`, `d1ConsoleServices.ts`, `d1StagingSession.ts`, `tenantStorageRoute.ts`, `cloudflareConsole.types.ts`, `cron.ts`, `d1SignerWasm.ts`, `routerAbServiceBindings.ts`)                                                                     | composition (the composed-worker files carry the bulk wallet imports; the console-only staging worker is the Phase 4 Console Worker seed) |

### Scheduled jobs

Factory `createCloudflareCron` (`src/router/cloudflare/cron.ts:430`), wired
into both staging workers' `scheduled` handlers (none locally):

| Job                                                | Owner          |
| -------------------------------------------------- | -------------- |
| `billingMonthlyFinalization` (`billing/d1.ts`)     | console-core   |
| `webhookRetryDispatch` (`webhooks/d1.ts`)          | console-core   |
| `consoleEmailDispatch` (`email/d1.ts`)             | console-core   |
| `runtimeSnapshotOutbox` (`runtimeSnapshots/d1.ts`) | wallet-console |

Inline (non-cron) outbox drain: Stripe post-processing dispatch from the
webhook route in both routers — console-core.

### console_session_v1

Issued in `src/router/cloudflare/d1RouterApiStagingWorker.ts:519`
(`issueConsoleSession`, claims kind `console_session_v1`); parsed in
`src/router/cloudflare/d1StagingSession.ts:399` (adapter rejects any other
kind, then RBAC lookup via `organizationAccess.lookupAuthorization`). Context
switch re-issuance in `src/router/consoleSessionContext.ts`. All sites lean
on the Wallet server's `SessionAdapter`/`SessionService` — the Phase 1/4
internalization target. Owner: console-core.

### Signer concerns in console package scripts (Phase 6 removals)

`packages/console-server-ts/package.json`: `d1:local:migrate:signer`,
`d1:local:prepare`, `d1:local:ensure-wasm` (signer Wasm), `d1:staging:migrate`
(profile `signer`), `d1:staging:smoke` (signer custody healthz),
`d1:staging:signer-custody`. Signer migrations are consumed from
`@seams/wallet-server/migrations/d1-signer` — none are checked into the console
package (correct ownership already; the orchestration moves to the
composition root in Phase 6).

## Gateway Route Surface And Worker Bindings

### Worker entrypoints

| Entrypoint                                            | File (`packages/console-server-ts/src/router/cloudflare/`) | Owner        |
| ----------------------------------------------------- | ---------------------------------------------------------- | ------------ |
| deployed combined gateway                             | `d1RouterApiWorker.ts` (re-export of the staging worker)   | composition  |
| combined gateway impl (`fetch` + `scheduled`)         | `d1RouterApiStagingWorker.ts`                              | composition  |
| local dev combined worker (`fetch` only, no cron)     | `d1LocalDevWorker.ts`                                      | composition  |
| console-only worker (the Phase 4 Console Worker seed) | `d1ConsoleStagingWorker.ts`                                | console-core |

Console dispatch: `dispatchHostedGatewayRequest`
(`d1RouterApiStagingWorker.ts:856`) sends `/console/*` to the console handler
and everything else to the Router API handler. The generic
`/session/exchange` route no longer exists anywhere in source — customer
Console auth is already the exact `POST /console/auth/google`,
`POST /console/auth/github`, `POST /console/auth/revoke` set
(`HostedConsoleAuthHandler`, `d1RouterApiStagingWorker.ts:394-431`),
instantiated in both combined workers. Phase 4 moves those routes to the
Console Worker rather than creating them. Stale `/session/exchange`
references survive only in docs/READMEs/env examples and one dead test
(`tests/unit/cloudflareD1ConsoleServices.unit.test.ts:875-919` expects
routing behavior the local worker no longer has).

### Route namespaces served by the combined gateway

| Namespace                                                                                                                                                                                                                                        | Owner                                                    |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| `/healthz`, `/readyz`, `/.well-known/*`, `/auth/*`, `/near/public-keys`, `/sync-account/*`, `/wallet/*`, `/wallets/*`, `/webauthn/*`, `/wallet-session/seal/*`, `/router-ab/*`, `/internal/gateway/device-linking/v1/*`, `/relay/*` (local only) | wallet (defined in `packages/wallet-server/src/router/`) |
| `/signed-delegate`, `/v1/wallets*`, `/sponsorships/evm/call` (route extensions mounted into the Router API handler)                                                                                                                              | wallet-console                                           |
| `/console/*` (~75 routes + `/console/auth/*`)                                                                                                                                                                                                    | console (Phase 4: leaves the Gateway)                    |

No `/admin/*` surface exists yet (R99B).

### Combined gateway bindings

Declared in `wrangler.d1-local.toml`, `wrangler.d1-staging-gateway.toml`, and
`scripts/render-d1-gateway-config.mjs`:

| Binding                        | Type                                               | Owner                                      |
| ------------------------------ | -------------------------------------------------- | ------------------------------------------ |
| `CONSOLE_DB`                   | D1 `seams-console`                                 | console (Phase 4 removes from the Gateway) |
| `SIGNER_DB`                    | D1 `seams-signer`                                  | wallet                                     |
| `MPC_ROUTER`, `SIGNING_WORKER` | service bindings to the private Router A/B Workers | wallet                                     |

No KV. No live Durable Objects on the gateway — `wrangler.d1-staging-gateway.toml`
carries create-then-delete migration tags for `ThresholdStoreDurableObject`
and `RouterApiRuntimeDurableObject` whose source classes still exist in
`sdk-server-ts` (dead-binding freeze candidates). Signer Wasm is not a
wrangler binding; it is an ESM import (`d1SignerWasm.ts` →
`@seams/wallet-server/wasm/signer`). The only live DO in the system is
`RouterAbSigningWorkerPresignSessionDurableObject` on the wallet-owned
`router-ab-signing-worker`.

Secrets: `CONSOLE_SESSION_HMAC_SECRET`, `STRIPE_API_SK`,
`CONSOLE_INITIAL_OWNER_EMAIL`, `GITHUB_OAUTH_*`, `STRIPE_WEBHOOK_SECRET` are
console-owned; `ACCOUNT_ID_DERIVATION_SECRET`,
`ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET`, `ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK`,
`LINKED_DEVICE_*`, `RELAYER_PRIVATE_KEY`, `SPONSORED_EVM_EXECUTORS_JSON` are
wallet/wallet-console-owned (`scripts/deployment-targets.mjs`).

The gateway `scheduled()` handler runs the console email cron
(console-owned; Phase 4 moves it) in parallel with the wallet-owned
Router A/B prewarm poster. The private Router A/B Workers
(`crates/router-ab-cloudflare/`: mpc-router, deriver-a, deriver-b,
signing-worker with their role-private D1s) are wholly wallet-owned.

Stale artifact: the gitignored on-disk
`packages/console-server-ts/.wrangler/generated/gateway.jsonc` declares live
DO bindings and a `SIGNING_ROOT_KEK_PRODUCTION_R1` secrets-store entry that
the current generator no longer emits — untracked, ignore.

## cloud-host Import Inventory

`packages/console-server-ts` imports `@seams/wallet-server` from 81 source files
(235 imports + 9 re-exports). Every specifier is
`@seams/wallet-server/cloud-host` except one dynamic
`@seams/wallet-server/wasm/signer` import in
`src/router/cloudflare/d1SignerWasm.ts`. `console-shared-ts` has zero.

By domain (Phase 1 target from the plan's ownership table):

| Domain                       | Files      | Symbols (representative)                                                                                                                                                                                                                                                                                                                                                                                                                                         | Phase 1 disposition                                                                                                                                                                                 |
| ---------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| random-ID / base64url / hash | ~40        | `secureRandomBase36`, `secureRandomBase64Url`, `base64UrlEncode/Decode`, `sha256Bytes`, `keccak256Bytes`                                                                                                                                                                                                                                                                                                                                                         | pass-through re-exports of `@seams-internal/shared-ts` (`packages/wallet-server/src/cloud-host.ts:133-178`); repoint to shared-ts or a Console-owned Web Crypto module                              |
| D1 types / SQL parsing       | 20         | `D1DatabaseLike`, `D1Row`, `queryD1All/One`, `formatD1ExecStatement`, `d1Integer/Number/ChangedRows`, `parseD1Json*Column`                                                                                                                                                                                                                                                                                                                                       | Console-owned D1 boundary module                                                                                                                                                                    |
| logger                       | 14         | `Logger`, `NormalizedLogger`, `RouterLogger`, `NormalizedRouterLogger`, `normalizeLogger`, `coerceRouterLogger`                                                                                                                                                                                                                                                                                                                                                  | Console-owned minimal logger contract                                                                                                                                                               |
| normalization                | 9          | `normalizeCorsOrigin`, `normalizeSourceIp`, `normalizeBoundedPositiveInteger`, `resolveSourceIp*`                                                                                                                                                                                                                                                                                                                                                                | mostly shared-ts pass-throughs; source-IP helpers live in wallet router auth and need a Console-owned copy                                                                                          |
| session adapter              | 7          | `SessionAdapter`, `SessionClaims`, `SessionService`                                                                                                                                                                                                                                                                                                                                                                                                              | Console-owned session contract (`consoleSessionContext.ts`, `consoleAppSessionAuth.ts`, `console.ts`, `express/createConsoleRouter.ts`, `cloudflare/d1StagingSession.ts`, both dev/staging workers) |
| HTTP helpers                 | ~14        | `routeJson`, `readJson`, `toFetchRouteResponse`, `RouteDefinition`, `CfEnv`, `FetchHandler`, `ScheduledHandler`                                                                                                                                                                                                                                                                                                                                                  | Console router transport module                                                                                                                                                                     |
| host composition             | ~14        | `RouterApiKeyAuthAdapter`, `RouterApiUsageMeterAdapter`, `CloudflareD1RouterApiAuthService`, tenant-storage routing, `CloudflareD1EmailOtpDeliveryProvider*`, route policy/metering                                                                                                                                                                                                                                                                              | Wallet Console package or composition root                                                                                                                                                          |
| wallet domain                | 9 + barrel | signer Wasm secp256k1/EIP-1559 ops (`sponsorship/evmWorkerSignerWasm.ts`, `evmRelay.ts`), NEAR delegate actions (`sponsorship/near.ts`, `nearExecutionAdapter.ts`), bulk RouterAb/Yao/linked-device/signing composition (`router/cloudflare/d1LocalDevWorker.ts`, `d1RouterApiStagingWorker.ts`), signer storage targets (`tenantStorageRoute.ts`, `cloudflareConsole.types.ts`, `d1ConsoleServices.ts`), signer worker env re-exports (`cloudflare-adaptor.ts`) | Wallet Console package or Wallet Gateway                                                                                                                                                            |

Concentration: `d1LocalDevWorker.ts` and `d1RouterApiStagingWorker.ts` carry
roughly 85% of the wallet symbol imports; those two plus the four
`sponsorship/*` files isolate nearly the entire wallet coupling.

The exact per-file allowlist is the temporary list inside
`tests/scripts/check-console-core-wallet-import-boundaries.mjs`.

## console-shared-ts Wallet Vocabulary

Five source files; all real consumers use per-module subpath exports, so the
subpaths (not the barrel) are the breaking surface.

| File                                   | Verdict     | Phase 1 disposition                                                                                                                                                                                        |
| -------------------------------------- | ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `src/gasSponsorshipSpendCapTargets.ts` | pure wallet | moves wholesale to `wallet-console-shared-ts` (NEAR spend-cap chain-id sentinels)                                                                                                                          |
| `src/gasSponsorshipChains.ts`          | pure wallet | moves wholesale (chain matrix: NEAR/Ethereum/Arc Circle/Tempo)                                                                                                                                             |
| `src/organizationIdentity.ts`          | pure core   | stays                                                                                                                                                                                                      |
| `src/apiKeyScopes.ts`                  | MIXED       | catalog contents are 100% wallet scopes (`accounts.create`, `wallets.read`, `wallets.auth_methods.create`, `wallets.signers.create`) and move; core keeps the generic `ApiCredentialScopeOption` machinery |
| `src/webhookEventCategories.ts`        | MIXED       | categories `wallet`, `policy`, `tx`, `session` move; `auth`, `billing` and the normalizer machinery stay, re-parameterized over a composed catalog                                                         |

Wallet billing inputs are normalized into the generic active-resource and
product-execution vocabulary in `src/billing/*`. Policy payloads, approval
vocabulary, key-export contracts, and sponsorship contracts live in the
Wallet Console packages.

The reconciled role-based `repository-split.json` assigns Console core, Wallet
Console integration, and the hosted docs application to the private
`seams-monorepo`; it assigns the two Wallet packages and required Rust/Wasm to
the public `seams-wallet` output.

## UI Routes

`apps/seams-site` has no react-router; the route table is a `switch` in
`src/app/App.tsx` with dashboard sub-routes declared in
`src/pages/dashboard/dashboardConfig.tsx`.

| Route                                                                                                                                                                                              | Owner                                         | Notes                                                                                                                                    |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `/`, `/home2`, `/wallet`, `/ecommerce`, `/pricing`, `/company`, `/contact`, not-found                                                                                                              | seams-site (marketing)                        | `/pricing` CTA links to `/dashboard/login` — cross-app URL after Phase 5                                                                 |
| `/near-login`, `/__intended-e2e`, `src/flows/demo/**` (mounted in marketing sections)                                                                                                              | seams-site (wallet demos / intended examples) |                                                                                                                                          |
| `/dashboard/login`                                                                                                                                                                                 | console-core                                  | with `src/shared/auth/` OAuth helpers                                                                                                    |
| `/dashboard/account-settings`, `/dashboard/team-members`, `/dashboard/api-keys`, `/dashboard/webhooks`, `/dashboard/audit`, `/dashboard/billing/*`, `/dashboard/invoices`, `/dashboard/onboarding` | console-core                                  | move to `apps/seams-console` `core/`                                                                                                     |
| `/dashboard/overview`                                                                                                                                                                              | console-core                                  | MIXED: renders `OpsCockpitPage` + `consoleOpsCockpitApi`; the tenant overview stays, the ops-cockpit slices move to mpc-admin under R99B |
| `/dashboard/observability`                                                                                                                                                                         | console-core                                  | tenant-scoped; fleet/platform slices → mpc-admin                                                                                         |
| `/dashboard/wallets-list`, `/dashboard/gas-sponsorship`, `/dashboard/policy-engine` (+ page-less `routes/approvals/consoleApprovalsApi.ts`, `routes/wallets/consoleWalletApi.ts`)                  | wallet-console                                | move to `apps/seams-console` `products/wallet/`                                                                                          |
| `/platform/billing`, `/platform/*` (gated on `platformSupport`)                                                                                                                                    | mpc-admin                                     |                                                                                                                                          |
| Dashboard shell (`page.tsx`, `consoleSession.tsx`, `consoleHttp.ts`, layout, components, icons, drafts, utils)                                                                                     | console-core                                  | moves wholesale                                                                                                                          |

Cross-boundary UI leaks to fix in Phase 5:

- core pages importing wallet APIs: `routes/audit/page.tsx` and
  `routes/ops-cockpit/page.tsx` import `consoleApprovalsApi`;
  `consoleBillingApi.ts` embeds the `active_resource_v1` monthly-active-wallets metric
  and endpoint.
- SDK/theme coupling: `SeamsWebProvider` wraps every route including
  `/dashboard/*` (`src/context/frontendRuntime.tsx`, `src/app/App.tsx`;
  only `/near-login` escapes); `App.tsx` bridges `--w3a-*` theme tokens from
  `@seams/wallet/react` onto the document; direct dashboard imports are
  `layout/DashboardTopbar.tsx` (`MoonIcon`/`SunIcon`) and
  `routes/gas-sponsorship/consoleGasSponsorshipApi.ts` (`keccak256Bytes` from
  `@seams/wallet/advanced`); global hooks `useBodyLoginStateBridge` /
  `useExportKeyCancelToast` mount on dashboard routes too.
- no key-export dashboard page exists (key export appears only in the wallet
  demo profile settings).

## Tests

All console tests run under the shared `tests/playwright.config.ts` /
`playwright.unit.config.ts`; no console-specific config exists. The shared
`webServer` block boots the seams-site dev server with `VITE_CONSOLE_BASE_URL`

- `VITE_WALLET_ORIGIN` together — a Phase 5 coupling point.

| Group                                                                                                                           | Files                                                                                                                                                                                                                                                                                                                                                                                                                          | Owner          |
| ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | -------------- |
| dashboard UI                                                                                                                    | `tests/e2e/dashboard.billing.console.apiWiring.test.ts`, `dashboard.consoleConfigPages.apiWiring.test.ts`, `dashboard.webhooks.apiWiring.test.ts`; `tests/unit/dashboard.*` (4 files)                                                                                                                                                                                                                                          | console-core   |
| console server/router                                                                                                           | `tests/unit/router.consoleRouteSurface.unit.test.ts`, `cloudflareD1ConsoleServices.unit.test.ts`, `consoleApiKeys.secretFormat.unit.test.ts`, `consoleServer.stripeBillingProvider.unit.test.ts`, `webServer.consoleConfig.unit.test.ts`, `githubOAuth.unit.test.ts`                                                                                                                                                           | console-core   |
| sponsorship (wallet feature implemented in console package)                                                                     | `tests/unit/sponsorship.*.unit.test.ts`, `sponsorshipPricing.d1.unit.test.ts`, `router.sponsoredEvmCallCloudflare.unit.test.ts`                                                                                                                                                                                                                                                                                                | wallet-console |
| mixed — split later                                                                                                             | `tests/e2e/pricing.checkout.apiWiring.test.ts`, `tests/unit/packageExports.contract.unit.test.ts`, `frontendRuntimeState.unit.test.ts`, the `d1Staging*`/`d1LocalDev*`/`d1HostedGatewayRouting`/`migrationFingerprint`/`signingRootScope`/`intendedYaoFault` script tests (import console-server-ts while testing wallet/signer behavior), OTP provider tests, shared fixtures (`tests/helpers/sqliteD1.ts`, staging fixtures) | composition    |
| everything else (~460 files: `wallet-iframe/`, `lit-components/`, `e2e/intended-behaviours/`, `relayer/`, wallet unit families) |                                                                                                                                                                                                                                                                                                                                                                                                                                | wallet         |

Boundary guards needing updates at each split: `tests/scripts/check-signer-console-module-boundaries.mjs`, `check-workspace-package-boundaries.mjs`, and the new `check-console-core-wallet-import-boundaries.mjs`.

## Local Runtime Classification

`pnpm router` (`crates/router-ab-dev/scripts/dev-local-workers.mjs`) is the
composed private development runtime: it prepares env/config, applies private
Router A/B D1 migrations, starts the four Router A/B workers (:9100-:9103),
spawns `pnpm gateway:server` (which applies console + signer D1 migrations
via `d1:local:prepare`, then serves the combined local worker on :9090), and
fronts it with Caddy on :9444. Ownership split for the public/private
repositories:

| Piece                                                                                                                                                                                | Owner                                                                                                                          |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Router A/B Worker and `router_ab_local_*` source, role-private D1 schema, and generic runtime behavior                                                                              | wallet (public local reference runtime)                                                                                        |
| Combined local worker (`d1LocalDevWorker.ts`), console+signer migration chaining (`d1:local:prepare`), Caddy topology, `gateway:server`, seeding (`seed-intended-local-console.mjs`) | composition (private composed development)                                                                                     |
| `apps/web-server` Express in-memory console server (`gateway:server:threshold-3nodes`, `gateway:server:iphone`)                                                                      | composition (console-in-the-loop dev path)                                                                                     |
| State-preserving startup (canonical-schema SHA check renames drifted state; `router:reset` renames, never deletes; `d1:local:reset` is the explicit destructive command)             | split: the Wallet-only local runtime keeps the preserve/reset semantics per the plan; the console halves move with composition |

`packages/shared-ts` (`@seams-internal/shared-ts`) is consumed exclusively by
the Wallet packages and tests via the `@shared/*` alias (446 files in
`sdk-web`, 280 in `sdk-server-ts`, ~140 in `tests/`; zero console
importers) — it is Wallet-owned and goes to the public repository. The
console analogue is `console-shared-ts`.

## Deployment Secret And Environment Generation

The current private deployment tooling still couples the two authorities:

- `deployment/targets.json` contains site, Console D1, Wallet Gateway, Wallet
  origin, signer, Router A/B, and frontend targets in one structure;
- `generate-github-env-values.mjs` prepares one generation containing both
  `wallet-core` and `product` manifests. Its generated secret set includes
  Router/signing material together with Console invitation and webhook secrets;
- the root commands `wallet-core:deploy:env-*`, `product:deploy:env-*`, and the
  combined rotation/verification commands share generation metadata;
- `deploy-backend.mjs` deploys Wallet Runtime, Console, and Gateway in one
  sequence and can receive the GitHub environment's full
  `DEPLOYMENT_SECRETS_JSON` inventory;
- `deploy-frontend.mjs` currently composes the site, docs, Wallet Pages, and the
  mounted Console build.

These remain private, but the coupled generation and write authority is
retired by Refactors 105B/105C. The destination is two explicit private
pipelines:

| Pipeline | Owns | Must never write |
| --- | --- | --- |
| Console | Console Pages/Worker/D1, Console session and OAuth secrets, Console email/webhook/billing inputs, Console routes and origins | Wallet Gateway/Runtime, hosted Wallet, signer, Router A/B, root-share, ceremony, signing-session, or relayer values |
| Wallet system | Wallet Gateway/Runtime, hosted Wallet Pages, signer D1, Router A/B workers and role D1s, protocol keys, root shares, ceremony/signing-session material, relayer and Wallet-network values | Console D1, Console session/OAuth/email/webhook/billing values, Console Pages/Worker, or Console routes |

Each pipeline receives its own target file, generator, protected GitHub
environments, update/rotation command, backup output, and deploy workflow. A
shared read-only handoff may contain public origins, network names, service
binding names, and deployed artifact versions. It contains no secret and grants
neither pipeline write access to the other's environments.

## Current Repository Destination Addendum

- The existing private repository is renamed in place to
  `seams-tech/seams-monorepo`. It keeps Console, Admin, future products,
  `apps/docs`, deployment topology, environment and provider configuration,
  secrets, operational runbooks, every staging/production workflow, and the
  private composed test/runtime harness.
- One fresh-history public `seams-tech/seams-wallet` repository owns
  `@seams/wallet`, `@seams/wallet-server`, required shared code, Rust/Wasm,
  signer migrations, public Wallet tests, `docs/`,
  `examples/seams-auth-menu`, and the generic self-host/runtime example.
- Current deployment/local scripts are not moved by directory assumption.
  Generic Wallet behavior is re-expressed in the public runtime; Console,
  environment, provider, and deployment orchestration remains private.
- Private deployment is split into Console and Wallet-system pipelines. Each
  pipeline owns disjoint GitHub environments and secret/variable names, and no
  command generates or applies both ownership sets.
- Rust crates remain co-located implementation inputs with `publish = false`.
  Refactor 105 publishes no crate and creates no Rust repository.
- The private monorepo deploys exact-pinned npm artifacts and has no Cargo,
  `wasm-pack`, Git, sibling-checkout, or source-path fallback for Wallet builds.
