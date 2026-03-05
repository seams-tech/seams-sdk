# Dashboard Observability Plan

## Current status

Observability is **partially** built.

Implemented today:
- Ops Cockpit summary endpoint and page (`/console/ops-cockpit/summary`, `/dashboard/ops-cockpit`) for queue-style operational issues (approvals, failed billing, webhook dead letters, queued audit exports, isolation requests, onboarding SLO alerts).
- Audit logs page (`/dashboard/audit`) for immutable admin/event trail.
- Webhook dead-letter replay from Ops Cockpit.

Not implemented yet:
- Dedicated `/dashboard/observability` page.
- Unified log explorer for console/service logs.
- Time-series metrics explorer (latency/error rate/throughput trends).
- Service health matrix with drill-down diagnostics.
- Alert policy management for observability signals.

## Goal

Give developers one place to monitor:
- logs,
- service health,
- failures,
- latency and error trends,
- webhook delivery quality.

## Phase plan (execution queue)

### Phase 1 - Core contracts and scaffolding
- [ ] Add new route and nav item: `/dashboard/observability` (`Observability`).
- [ ] Add typed client API module: `routes/observability/consoleObservabilityApi.ts`.
- [ ] Add backend read endpoints (scaffold + `not_configured` status fallback):
  - [ ] `GET /console/observability/summary`
  - [ ] `GET /console/observability/events`
  - [ ] `GET /console/observability/timeseries`
  - [ ] `GET /console/observability/services`
- [ ] Add RBAC gates for read access (default: `owner`, `admin`, `security_admin`, `ops`, `support`).
- [ ] Add e2e route wiring tests (page loads, API wiring, empty and not-configured states).

### Phase 2 - Log ingestion and storage foundation
- [ ] Define normalized observability event envelope:
  - [ ] `timestamp`, `orgId`, `projectId`, `environmentId`
  - [ ] `service`, `component`, `level`, `eventType`
  - [ ] `message`, `requestId`, `traceId`, `metadata`
- [ ] Add Postgres schema for observability events (append-only):
  - [ ] `console_observability_events`
  - [ ] indexes on `(org_id, created_at_ms)`, `(org_id, service, created_at_ms)`, `(org_id, level, created_at_ms)`
- [ ] Add write adapters from existing server telemetry points:
  - [ ] webhook delivery failures and retries
  - [ ] billing finalization/job failures
  - [ ] approval/policy publish failures
  - [ ] router request timing/error hooks (sampled)
- [ ] Add retention controls for observability events (default shorter than audit retention).

### Phase 3 - Query APIs and aggregation
- [ ] Implement `GET /console/observability/events` with filters:
  - [ ] time window (`from`, `to`)
  - [ ] `level`, `service`, `eventType`
  - [ ] optional `projectId`, `environmentId`
  - [ ] cursor pagination
- [ ] Implement `GET /console/observability/timeseries`:
  - [ ] error count per bucket
  - [ ] request count per bucket
  - [ ] p50/p95 latency per bucket
- [ ] Implement `GET /console/observability/services`:
  - [ ] per-service health status
  - [ ] recent failure counts
  - [ ] latest incident timestamp
- [ ] Implement `GET /console/observability/summary`:
  - [ ] top-line cards (error rate, p95 latency, failing services, dead-letter count)
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
- [ ] Add PII redaction guardrails for event metadata.
- [ ] Add sampling/rate-limit controls for ingestion.
- [ ] Add runbooks and operational docs for on-call usage.

## Definition of done

- [ ] Developer can open `/dashboard/observability` and inspect logs by org/project/environment.
- [ ] Developer can identify failing services and top error classes within a selected time window.
- [ ] Developer can inspect latency/error trends and correlate with webhook/billing/approval failures.
- [ ] Alert thresholds are configurable and actionable.
- [ ] API + UI behavior is covered by automated tests.
