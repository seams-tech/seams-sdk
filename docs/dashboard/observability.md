# Dashboard Observability Plan

## Current status

Observability is **partially** built.

Implemented today:
- Ops Cockpit summary endpoint and page (`/console/ops-cockpit/summary`, `/dashboard/overview`) for queue-style operational issues (approvals, failed billing, webhook dead letters, queued audit exports, isolation requests, onboarding SLO alerts).
- Audit logs page (`/dashboard/audit`) for immutable admin/event trail.
- Webhook dead-letter replay from Ops Cockpit.
- Observability route and page scaffold (`/dashboard/observability`) with summary/events/services wiring and degraded/not-configured/forbidden states.
- Observability Postgres storage schema + ingestion scaffold (`console_observability_events`) with org RLS, idempotent event keying, and metadata redaction on ingest.
- Observability Postgres read-path aggregation implementation for `summary`, `events`, `timeseries`, and `services` with strict bounded query windows.
- Observability ingestion wiring in Express + Cloudflare console routers for:
  - billing finalization/reconcile failures,
  - policy publish failures,
  - request metric observation into rollups (no durable router completion events).
- Monolith-to-split Postgres migration script and command for local/dev data moves:
  - `pnpm -C examples/relay-server run postgres:migrate:split-from-monolith`
  - envs: `MONOLITH_POSTGRES_URL`, `POSTGRES_MIGRATION_URL`, `CONSOLE_POSTGRES_MIGRATION_URL`.
- Local migration execution completed from `tatchi` -> `tatchi_signer` + `tatchi_console` with signer/console table-count verification and idempotent re-run behavior.
- Local split cutover validation completed:
  - `pnpm -C examples/relay-server run postgres:migrate:all`
  - `pnpm -C examples/relay-server run postgres:verify:split`

Not implemented yet:
- Unified log explorer for console/service logs.
- Time-series metrics explorer (latency/error rate/throughput trends).
- Service health matrix with drill-down diagnostics.
- Alert policy management for observability signals.
- Legacy billing transition backfill policy for historical rows with `NULL org_id` in monolith sources (incompatible with current console constraints).

## Goal

Give developers one place to monitor:
- logs,
- service health,
- failures,
- latency and error trends,
- webhook delivery quality.

## Execution rules

- No throwaway "temporary" implementations. Every phase must land reusable contracts/services.
- Express and Cloudflare console routers stay in parity for every observability endpoint.
- Observability data is not audit data: retention is shorter and PII redaction is enforced at ingestion.
- Console observability Postgres is isolated from signer state Postgres: use `CONSOLE_POSTGRES_URL` for console domains and `POSTGRES_URL` for signer/runtime state.
- Keep observability on Postgres for now with guardrails (partitioning, TTL cleanup, strict bounded queries, ingest backpressure). Re-evaluate a log/analytics store only when sustained ingest, retention horizon, or ad-hoc/full-text analytics needs exceed Postgres fit.

## Phased TODO list

### Phase 0 TODO (contract lock)
- [ ] Finalize API response contracts and request query shapes for `summary`, `events`, `timeseries`, `services`, and `alerts`.
- [x] Finalize service-state/error behavior (`ok`, `forbidden`, `not_configured`, `error`; `observability_not_configured`).
- [x] Finalize RBAC read matrix baseline in routers (`owner`, `admin`, `security_admin`, `ops`, `support`); keep redaction constraints pending.
- [x] Finalize query limits (max page size, cursor sort key).
- [x] Finalize max time-window guardrail (7-day maximum for observability read queries).
- [x] Finalize metadata redaction rules (denylist/allowlist + secret stripping policy).

### Phase 1 TODO (scaffold + parity wiring)
- [x] Create `server/src/console/observability/{types,requests,errors,service,postgres,index}.ts`.
- [x] Add observability service option/context wiring to console router types and adaptors.
- [x] Add `GET /console/observability/{summary,events,timeseries,services}` in Express router.
- [x] Add `GET /console/observability/{summary,events,timeseries,services}` in Cloudflare router.
- [x] Add dashboard route/nav + route type updates for `/dashboard/observability`.
- [x] Add `examples/tatchi-site/src/pages/dashboard/routes/observability/consoleObservabilityApi.ts`.
- [x] Add route wiring tests for parity and `observability_not_configured`.
- [x] Add route wiring tests for `forbidden`.

### Phase 2 TODO (ingestion + storage)
- [x] Finalize event envelope fields (`eventId`, `schemaVersion`, `source`, timestamps, scope, trace/request IDs).
- [x] Add append-only `console_observability_events` schema and indexes.
- [x] Partition observability events storage by month (with automatic adjacent partition creation).
- [x] Add idempotent ingestion key (`org_id`, `event_id`).
- [x] Add ingestion adapters from webhooks, billing, and approvals/policy publish.
- [x] Add request metric observation from console routers into request rollups.
- [x] Enforce metadata redaction before persistence.
- [x] Add retention policy and cleanup workflow for observability data.
- [x] Add ingest backpressure controls (max batch + per-org per-minute budget).

### Phase 3 TODO (queries + aggregation)
- [x] Implement filtered/paginated events API with deterministic cursor ordering.
- [x] Implement timeseries API (error count, request count, p50/p95 latency) with bounded buckets.
- [x] Implement services API (health state, failure counts, latest incident timestamp).
- [x] Implement summary API cards and module status mapping.
- [ ] Add contract tests for bounds enforcement and pagination behavior.

### Phase 4 TODO (dashboard UX)
- [ ] Build `/dashboard/observability` page shell and data loaders.
- [ ] Add KPI cards, log explorer, service health table, and timeseries charts.
- [ ] Add quick links from Ops Cockpit and audit views into filtered observability views.
- [ ] Add explicit empty-state, partial-data, and degraded-data UX states.
- [ ] Add e2e coverage for load/filter/paginate/degraded states.

### Phase 5 TODO (alerts)
- [ ] Implement alert rule model (error-rate, latency, dead-letter growth thresholds).
- [ ] Implement `/console/observability/alerts` list/create/update/acknowledge APIs.
- [ ] Add alert panel and acknowledge workflow in dashboard UI.
- [ ] Add optional alert sinks (webhook/email) with delivery status visibility.
- [ ] Add tests for alert rule validation and ack state transitions.

### Phase 6 TODO (hardening + readiness)
- [ ] Add org-isolation and authorization coverage for all observability APIs (Express + Cloudflare).
- [ ] Add high-cardinality query performance/load tests.
- [x] Add ingest backpressure controls (max batch + per-org per-minute budget).
- [ ] Add operator runbooks and incident workflow docs.
- [ ] Add release-readiness checklist and rollback plan.

### Phase 7 TODO (console/dashboard modularization)
- [x] Extract observability route registration into dedicated modules for both adapters:
  - `server/src/router/express/consoleObservabilityRoutes.ts`
  - `server/src/router/cloudflare/consoleObservabilityRoutes.ts`
- [ ] Split console router domain registration into per-module route registrars (Express + Cloudflare) and keep top-level router files as pure composition.
- [ ] Add explicit module boundary contracts per console domain (`types`, `requests`, `errors`, `service`, `postgres`, `index`, `routes` where applicable).
- [ ] Refactor dashboard observability route into feature-module layout (`api`, `model`, `hooks`, `components`, `page`) and document it as the pattern for other dashboard domains.
- [ ] Eliminate cross-domain coupling in module internals (no module reaching into another module's storage details directly).
- [ ] Add module-boundary tests/checks for console/dashboard imports to prevent regression into monolithic route files.

### Phase 8 TODO (split DB cutover + monolith retirement)
- [x] Add a one-shot monolith -> split migration script for existing single-DB setups.
- [x] Validate local migration run from monolith `tatchi` to split `tatchi_signer` + `tatchi_console`.
- [ ] Resolve legacy-incompatible rows (`console_payment_state_transitions` rows with `NULL org_id`): explicit backfill or intentional archive policy.
  - Current local gap snapshot: source `121` rows vs target `25` rows; `96` rows skipped due to `NULL org_id` in source (top reason: `payment_intent_created` = `72` rows).
- [ ] Complete runtime cutover in all environments (`POSTGRES_URL` -> signer DB, `CONSOLE_POSTGRES_URL` -> console DB) and freeze monolith writes.
- [ ] Run 24-48h soak monitoring with rollback gates and error-budget checks.
- [ ] Take final monolith backup snapshot, then decommission monolith DB path.

## Next execution steps (immediate)

1. Complete split cutover gate:
   - [ ] update runtime envs to split DB URLs in all deploy targets.
   - [ ] run `postgres:migrate:all` and `postgres:verify:split` in each environment (local done).
   - [ ] freeze monolith writes after split cutover validation.
2. Close known migration compatibility gap:
   - [ ] decide policy for `console_payment_state_transitions` legacy rows with `NULL org_id` (backfill vs archive).
   - [ ] implement chosen policy and capture in runbook.
3. Finish observability contract and hardening tests:
   - [ ] add bounds + pagination contract tests for events/timeseries/services/summary.
   - [ ] add degraded-state assertions across Express + Cloudflare parity suites.
4. Start Phase 7 modularization execution:
   - [x] extract observability route registration into module-local registrars.
   - [ ] refactor dashboard observability route into `api/model/hooks/components/page`.
   - [ ] enforce module-boundary import checks in CI.

## Phase plan (execution queue)

### Phase 0 - Contract hardening (required before scaffolding)
- [ ] Lock endpoint contracts and error surface:
  - [ ] `GET /console/observability/summary`
  - [ ] `GET /console/observability/events`
  - [ ] `GET /console/observability/timeseries`
  - [ ] `GET /console/observability/services`
  - [ ] `GET /console/observability/alerts` (future-write APIs can follow)
- [x] Lock service-state mapping and error codes:
  - [x] module status states: `ok`, `forbidden`, `not_configured`, `error`
  - [x] service-not-wired code: `observability_not_configured`
- [x] Lock RBAC read policy:
  - [x] default read roles: `owner`, `admin`, `security_admin`, `ops`
  - [ ] `support` only with strict metadata redaction profile enabled
- [ ] Lock query guardrails:
  - [ ] max events page size
  - [x] max query window (7 days)
  - [x] stable sort keys for cursor pagination
- [ ] Lock ingestion redaction contract:
  - [x] denylist/allowlist for metadata keys
  - [x] secret/token/key material stripping before persistence

### Phase 1 - Core routes and service scaffolding
- [x] Add new route and nav item: `/dashboard/observability` (`Observability`).
- [ ] Add typed client API module:
  - [x] `examples/tatchi-site/src/pages/dashboard/routes/observability/consoleObservabilityApi.ts`
- [x] Add backend module scaffold:
  - [x] `server/src/console/observability/{types,requests,errors,service,postgres,index}.ts`
- [x] Add backend read endpoints (contract-complete, minimal data implementation + `observability_not_configured` fallback):
  - [x] `GET /console/observability/summary`
  - [x] `GET /console/observability/events`
  - [x] `GET /console/observability/timeseries`
  - [x] `GET /console/observability/services`
- [x] Wire endpoint parity:
  - [x] Express: `server/src/router/express/createConsoleRouter.ts`
  - [x] Cloudflare: `server/src/router/cloudflare/createCloudflareConsoleRouter.ts`
  - [x] shared options/types exports in console adaptor surfaces
- [ ] Add route wiring tests:
  - [x] relayer router tests (Express + Cloudflare parity, not-configured)
  - [x] relayer router tests (`forbidden`)
  - [x] dashboard e2e API wiring (page load, empty state, not-configured state, forbidden state)

### Phase 2 - Log ingestion and storage foundation
- [x] Define normalized observability event envelope:
  - [x] `eventId`, `schemaVersion`, `source`, `ingestedAtMs`
  - [x] `timestamp`, `orgId`, `projectId`, `environmentId`
  - [x] `service`, `component`, `level`, `eventType`
  - [x] `message`, `requestId`, `traceId`, `metadata`
  - [x] `redactionVersion`, `redactionApplied`
- [ ] Add Postgres schema for observability events (append-only):
  - [x] `console_observability_events`
  - [x] unique key on `(org_id, event_id)` for idempotent ingestion
  - [x] indexes on `(org_id, created_at_ms)`, `(org_id, service, created_at_ms)`, `(org_id, level, created_at_ms)`
- [ ] Add write adapters from existing server telemetry points:
  - [x] webhook delivery failures and retries (adapter builders)
  - [x] billing finalization/job failures (adapter builders)
  - [x] approval/policy publish failures (adapter builders)
  - [x] request metric observation hooks
  - [x] wire billing failure adapter emits in Express + Cloudflare billing routes.
  - [x] wire approval failure adapter emits in Express + Cloudflare policy publish routes.
  - [x] wire request metric observation in Express + Cloudflare console request pipelines.
- [x] Apply redaction before writes for all ingestion adapters (no raw sensitive metadata at rest).
- [x] Add retention controls for observability events (default shorter than audit retention).

### Phase 3 - Query APIs and aggregation
- [ ] Implement `GET /console/observability/events` with filters:
  - [x] time window (`from`, `to`)
  - [x] `level`, `service`, `eventType`
  - [x] optional `projectId`, `environmentId`
  - [x] cursor pagination
  - [ ] enforce max page size
  - [x] enforce max query window
  - [x] deterministic ordering for pagination (`created_at_ms desc`, tie-breaker id)
- [ ] Implement `GET /console/observability/timeseries`:
  - [x] error count per bucket
  - [x] request count per bucket
  - [x] p50/p95 latency per bucket
  - [x] explicit bucketing strategy (auto bucket count + min/max bucket duration)
- [ ] Implement `GET /console/observability/services`:
  - [x] per-service health status
  - [x] recent failure counts
  - [x] latest incident timestamp
- [ ] Implement `GET /console/observability/summary`:
  - [x] top-line cards (error rate, p95 latency, failing services, dead-letter count)
  - [ ] warning state mapping (`ok`, `forbidden`, `not_configured`, `error`)

### Phase 4 - Dashboard Observability UX
- [ ] Build `/dashboard/observability` page with:
  - [ ] KPI cards (error rate, p95, failing services, webhook failure rate)
  - [ ] log explorer table (filter + search + pagination)
  - [ ] service health table (status, last error, incident count)
  - [ ] latency/error trend charts (time-series)
- [ ] Add quick links:
  - [ ] from Ops Cockpit cards to filtered observability views
  - [ ] from audit rows to related observability context (by request/trace id when present)
- [ ] Add graceful no-data and degraded-data states.

### Phase 5 - Alerting and operator workflows
- [ ] Add alert rule model (threshold and window based):
  - [ ] error-rate breach
  - [ ] latency breach
  - [ ] dead-letter growth breach
- [ ] Add `/console/observability/alerts` APIs (list/create/update/acknowledge).
- [ ] Add Observability alert panel and ack actions in UI.
- [ ] Add optional webhook/email sinks for alert notifications.

### Phase 6 - Hardening and production readiness
- [ ] Add org-isolation and authorization tests for all observability APIs (Express + Cloudflare parity).
- [ ] Add load/perf tests for high-cardinality event queries.
- [x] Add backpressure controls for ingestion.
- [ ] Add runbooks and operational docs for on-call usage.

### Phase 7 - Console/Dashboard modularization
- [ ] Backend router decomposition:
  - [ ] Extract observability route registration from:
    - [x] `server/src/router/express/createConsoleRouter.ts`
    - [x] `server/src/router/cloudflare/createCloudflareConsoleRouter.ts`
  - [ ] Keep top-level router builders as orchestration/composition only.
- [ ] Backend module boundary hardening:
  - [ ] Standardize per-domain public surface via `index.ts` exports only.
  - [ ] Move any domain-specific parsing/normalization out of monolithic router files into module-local files.
  - [ ] Add import-boundary tests/checks preventing cross-domain storage coupling.
- [ ] Dashboard feature module decomposition:
  - [ ] Refactor `examples/tatchi-site/src/pages/dashboard/routes/observability/page.tsx` into feature submodules (`api`, `model`, `hooks`, `components`, `page`).
  - [ ] Keep route pages as view orchestration, not API/state/business logic containers.
  - [ ] Add a short dashboard module template doc so other routes follow the same structure.

### Phase 8 - Split DB cutover and monolith retirement
- [x] Add migration command for existing monolith DB users:
  - [x] `postgres:migrate:split-from-monolith` in relay-server scripts.
  - [x] migration docs for env setup and command invocation.
- [x] Execute and verify local migration from monolith -> split DBs.
- [ ] Finalize policy for legacy-incompatible rows (`console_payment_state_transitions` with `NULL org_id`).
- [ ] Complete env cutover and monolith write freeze.
- [ ] Complete soak monitoring + rollback checkpoint.
- [ ] Archive/backup then remove monolith DB dependency.

## Definition of done

- [ ] Developer can open `/dashboard/observability` and inspect logs by org/project/environment.
- [ ] Developer can identify failing services and top error classes within a selected time window.
- [ ] Developer can inspect latency/error trends and correlate with webhook/billing/approval failures.
- [ ] Alert thresholds are configurable and actionable.
- [ ] Redaction policy is enforced on ingestion and validated in automated tests.
- [ ] Query limits and pagination behavior are deterministic and covered by tests.
- [ ] API + UI behavior is covered by automated tests.
