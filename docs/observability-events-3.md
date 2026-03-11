# Observability Event Noise Reduction Plan

## Problem statement

The current observability pipeline is too chatty because it stores routine console request completions as durable events. That creates three problems:

- low-signal `GET` traffic pollutes the event log
- the observability dashboard reads its own APIs and generates more observability events while doing so
- summary and timeseries metrics are derived from the event table, so routine reads dilute incident-focused signals

The historical offender was `router.request.completed`, which previously appended authenticated console traffic across Express and Cloudflare, including successful read paths.

## Decision

We will narrow durable observability events to operator-actionable incidents and state transitions.

We will stop persisting routine request completions as append-only events. Request throughput and latency will move to a dedicated rollup path. This is a clean break. We will not keep compatibility flags, shadow legacy paths, or a dual-write mode longer than the migration window required to land the new implementation.

## Goals

- keep the event stream useful for humans investigating failures
- preserve request-level summary and timeseries metrics without storing every request as an event
- prevent self-observing dashboard reads from polluting the event list
- keep Express and Cloudflare behavior in parity
- remove obsolete router-event code once the new path lands

## Non-goals

- building a full external log analytics platform
- preserving historical compatibility for `router.request.completed`
- keeping old event semantics alive through feature flags

## Target event policy

### Keep as durable events

Persist only events that an operator would investigate later:

- webhook dead-letter moves
- billing failures
- approval publish failures
- policy/security denies and rejects when they indicate a meaningful runtime issue
- async job failures, retry exhaustion, and stuck-state transitions
- alert state transitions
- explicit system degradation or recovery transitions

### Do not persist as durable events

These should not enter `console_observability_events`:

- successful `GET`, `HEAD`, and `OPTIONS` requests
- successful dashboard bootstrap reads
- successful observability read endpoints
- routine successful `POST` requests that do not represent an incident or state transition
- per-request latency/timing records for healthy traffic

### Track as metrics instead

These remain important, but they belong in rollups rather than the event log:

- request count
- error count (`5xx` only)
- latency distribution
- status-class trends
- route-family throughput

## Target architecture

### 1. Durable event stream

`console_observability_events` becomes an incident log, not a request log.

Required properties:

- append-only
- strongly redacted
- low-cardinality service and event type dimensions
- optimized for filtered investigation, not throughput analytics

### 2. Request metrics rollups

Add a dedicated request metrics table, for example:

- `console_observability_request_rollups_minute`

Suggested dimensions:

- `namespace`
- `org_id`
- `project_id`
- `environment_id`
- `service`
- `route_family`
- `method`
- `status_class`
- `window_start_ms`

Suggested aggregates:

- `request_count`
- `error_count`
- `latency_sum_ms`
- `latency_max_ms`
- fixed latency histogram buckets for approximate `p50` and `p95`

The histogram buckets matter because the current dashboard wants percentile views. We should not reintroduce raw per-request event storage just to compute `p95`.

### 3. Query split

- `events` reads only from the durable event table
- `summary` reads request volume, latency, and error-rate from rollups, plus incident counts from the durable event table where appropriate
- `timeseries` reads request/error/latency from rollups
- `services` combines rollup-derived degradation signals with recent incident counts

## Implementation plan

### Phase 1. Reset the contract

- remove `router.request.completed` from the durable event taxonomy
- reject incoming `router.request.completed` ingest payloads instead of translating/shimming them
- redefine observability event docs around incidents and state transitions only
- document that request metrics are a separate data class from durable events
- keep existing endpoint shapes where practical, but change their backing storage and semantics

Deliverables:

- updated event taxonomy in `server/src/console/observability/types.ts`
- updated adapter surface in `server/src/console/observability/adapters.ts`
- updated docs in `docs/dashboard/observability.md`

### Phase 2. Add request rollup storage

- create a rollup table for per-minute request metrics
- implement upsert-style aggregation keyed by org/project/environment/service/route family/method/status class/window
- store histogram bucket counts for latency percentile approximation
- keep retention shorter than or equal to the current observability retention unless a stronger need emerges

Deliverables:

- schema and indexes in `server/src/console/observability/postgres.ts`
- retention and cleanup coverage for rollup rows
- ingestion tests for aggregation correctness and bounded cardinality

### Phase 3. Replace router event writes with metric observation

- remove durable router timing event writes from:
  - `server/src/router/express/createConsoleRouter.ts`
  - `server/src/router/cloudflare/createCloudflareConsoleRouter.ts`
- replace them with request metric observation into the rollup store
- keep incident-specific event builders for billing, approvals, webhooks, and future failure classes

Important rule:

- healthy request traffic updates rollups only
- incident-specific code paths emit durable events only when they represent a real failure or transition

### Phase 4. Tighten route capture scope

Even after the rollup split, avoid collecting unnecessary request metrics for obviously irrelevant paths.

Do not record request metrics for:

- `/console/observability/*`
- `/console/session`
- `/console/org`
- `/console/projects`
- `/console/environments`
- health and readiness routes

Record request metrics only for routes that represent product behavior we actually want to trend, such as approvals, billing actions, webhook delivery handling, policy publish flows, onboarding APIs, and other operator-relevant domains.

If we later need broader coverage, we should add explicit allowlist entries, not revert to blanket capture.

### Phase 5. Update summary and timeseries queries

- rework `summary` to compute request volume, latency, and error rate from rollups
- keep dead-letter and similar incident counts from the durable event table
- rework `timeseries` to use rollups exclusively for traffic and latency
- update `services` to classify health from recent rollup error behavior plus incident activity

Deliverables:

- rewritten query paths in `server/src/console/observability/postgres.ts`
- query tests proving the dashboard still gets meaningful numbers without router event rows

### Phase 6. Simplify the dashboard read pattern

The dashboard should stop amplifying noise and load by draining every event page on mount.

- fetch only the first events page initially
- add explicit pagination or load-more behavior
- set a narrower default UI window such as last hour or last 24 hours instead of implicit last 7 days
- keep explicit filters for service, event type, and severity

Deliverables:

- update `examples/tatchi-site/src/pages/dashboard/routes/observability/page.tsx`
- keep `consoleObservabilityApi.ts` simple and paginated

### Phase 7. Delete legacy noisy data and code

Because we are in development, we should clean this up as if the old approach never existed.

- remove router event builders that are no longer used
- delete tests that assert durable `router.request.completed` writes
- replace them with rollup aggregation tests
- delete existing `router.request.completed` rows from local and dev datasets:
  - `DELETE FROM console_observability_events WHERE event_type = 'router.request.completed' OR source = 'ROUTER';`
- do not add compatibility shims or dormant code paths

## Progress snapshot (2026-03-11)

- [x] Phase 1 complete: durable event contract reset to incidents/transitions only; legacy `router.request.completed` ingest is rejected with `invalid_body`.
- [x] Phase 2 complete: per-minute request rollup storage and upsert aggregation are live, including latency histogram buckets.
- [x] Phase 3 complete: durable router timing writes removed from Express and Cloudflare; routers emit request metrics plus incident-specific durable events only.
- [x] Phase 4 complete: request metric capture is now explicit allowlist-based (approvals, billing, webhooks, policy, onboarding, and other operator-relevant domains) and still skips successful `GET`/`HEAD` plus `OPTIONS`.
- [x] Phase 5 complete: `summary`, `timeseries`, and `services` read traffic/error/latency from rollups and incident counts from durable events.
- [x] Phase 6 complete: dashboard now defaults to last 24 hours, fetches first events page only, and loads more via explicit cursor pagination.
- [x] Phase 7 complete in code and schema migration: legacy router builders/tests were removed/replaced, legacy rows are deleted during schema ensure, and source constraint is enforced as (`WEBHOOK`, `BILLING`, `APPROVAL`, `SYSTEM`).

## File-level execution map

- `server/src/router/express/createConsoleRouter.ts`
- `server/src/router/cloudflare/createCloudflareConsoleRouter.ts`
- `server/src/console/observability/adapters.ts`
- `server/src/console/observability/types.ts`
- `server/src/console/observability/postgres.ts`
- `server/src/console/observability/requests.ts`
- `examples/tatchi-site/src/pages/dashboard/routes/observability/page.tsx`
- `examples/tatchi-site/src/pages/dashboard/routes/observability/consoleObservabilityApi.ts`
- `tests/relayer/console-router.test.ts`
- `tests/relayer/console-observability.ingestion.test.ts`
- `docs/dashboard/observability.md`

## Acceptance criteria

- refreshing `/dashboard/observability` does not create new durable observability events
- successful `GET /console/observability/*` requests do not appear in the event list
- successful dashboard bootstrap reads do not appear in the event list
- summary and timeseries still show request count, error rate, and latency trends
- event list contains substantially fewer, higher-signal rows
- Express and Cloudflare stay behaviorally aligned
- no legacy router-event compatibility code remains after the change

## Rollout notes

- land storage and query changes before deleting router event ingestion
- keep the cutover short and direct
- do not backfill historical router events into the new model unless a specific debugging need appears
- once rollups are live and validated, remove router event writes and clean old noisy rows
- enforce the strict durable-event source constraint (`WEBHOOK`, `BILLING`, `APPROVAL`, `SYSTEM`) for pre-existing schemas during migration

## Next steps

1. [x] Local schema ensure executed on 2026-03-11 via `examples/relay-server/scripts/postgres-migrate-console.mjs`.
2. [x] Local cleanup verification executed on 2026-03-11:
   - `SELECT COUNT(*) FROM console_observability_events WHERE event_type = 'router.request.completed' OR source = 'ROUTER';`
   - result: `0`.
3. [x] Validation rerun completed on 2026-03-11:
   - `pnpm -s type-check:relay-server` passed.
   - relayer observability suites passed (`console-observability.ingestion`, `console-router`) after test isolation fixes.
   - dashboard observability API wiring e2e subset passed.
4. [ ] Run schema ensure + legacy-row verification in shared dev/staging databases (not just local).
   - requires shared DB credentials/environment access not present in this workspace.
   - run: `pnpm -C examples/relay-server exec node scripts/postgres-migrate-console.mjs`
   - verify: `SELECT COUNT(*) FROM console_observability_events WHERE event_type = 'router.request.completed' OR source = 'ROUTER';` (expect `0`)
5. [x] Route-family allowlist capture landed on 2026-03-11 (skip-list removed from capture path).

## Success metric

After the change, the observability event list should read like an incident queue, not an access log.
