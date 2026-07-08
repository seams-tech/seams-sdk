# Observability Event Noise Reduction Plan

This document is the current source of truth for the implemented observability architecture, rollout state, and maintainability follow-up work.

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

These should not enter `observability_events`:

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

`observability_events` becomes an incident log, not a request log.

Required properties:

- append-only
- strongly redacted
- low-cardinality service and event type dimensions
- optimized for filtered investigation, not throughput analytics

### 2. Request metrics rollups

Add a dedicated request metrics table, for example:

- `observability_request_rollups_minute`

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

- updated event taxonomy in `packages/console-server-ts/src/observability/types.ts`
- updated adapter surface in `packages/console-server-ts/src/observability/adapters.ts`
- updated docs in `docs/saas/observability-events-3.md`

### Phase 2. Add request rollup storage

- create a rollup table for per-minute request metrics
- implement upsert-style aggregation keyed by org/project/environment/service/route family/method/status class/window
- store histogram bucket counts for latency percentile approximation
- keep retention shorter than or equal to the current observability retention unless a stronger need emerges

Deliverables:

- schema and indexes in `packages/console-server-ts/migrations/d1-console/0016_console_observability.sql`
  and `packages/console-server-ts/src/observability/d1.ts`
- retention and cleanup coverage for rollup rows
- ingestion tests for aggregation correctness and bounded cardinality

### Phase 3. Replace router event writes with metric observation

- remove durable router timing event writes from:
  - `packages/sdk-server-ts/src/router/express/createConsoleRouter.ts`
  - `packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts`
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

- rewritten query paths in `packages/console-server-ts/src/observability/d1.ts`
- query tests proving the dashboard still gets meaningful numbers without router event rows

### Phase 6. Simplify the dashboard read pattern

The dashboard should stop amplifying noise and load by draining every event page on mount.

- fetch only the first events page initially
- add explicit pagination or load-more behavior
- set a narrower default UI window such as last hour or last 24 hours instead of implicit last 7 days
- keep explicit filters for service, event type, and severity

Deliverables:

- update `apps/seams-site/src/pages/dashboard/routes/observability/page.tsx`
- keep `consoleObservabilityApi.ts` simple and paginated

### Phase 7. Delete legacy noisy data and code

Because we are in development, we should clean this up as if the old approach never existed.

- remove router event builders that are no longer used
- delete tests that assert durable `router.request.completed` writes
- replace them with rollup aggregation tests
- delete existing `router.request.completed` rows from local and dev datasets:
  - `DELETE FROM observability_events WHERE event_type = 'router.request.completed' OR source = 'ROUTER';`
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

- `packages/sdk-server-ts/src/router/express/createConsoleRouter.ts`
- `packages/sdk-server-ts/src/router/cloudflare/createCloudflareConsoleRouter.ts`
- `packages/sdk-server-ts/src/router/consoleObservabilityHooks.ts`
- `packages/console-server-ts/src/observability/adapters.ts`
- `packages/console-server-ts/src/observability/types.ts`
- `packages/console-server-ts/src/observability/policy.ts`
- `packages/console-server-ts/src/observability/requestRollups.ts`
- `packages/console-server-ts/src/observability/d1.ts`
- `packages/console-server-ts/src/observability/requests.ts`
- `apps/seams-site/src/pages/dashboard/routes/observability/page.tsx`
- `apps/seams-site/src/pages/dashboard/routes/observability/consoleObservabilityApi.ts`
- `tests/relayer/console-router.test.ts`
- `tests/relayer/console-observability.ingestion.test.ts`
- `docs/observability-events-3.md`

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

## Local D1 Rollout Checkpoint

1. [x] The active schema is the D1 migration
   `packages/console-server-ts/migrations/d1-console/0016_console_observability.sql`.
2. [x] The active storage path is
   `packages/console-server-ts/src/observability/d1.ts`, with policy in
   `policy.ts`, request rollup helpers in `requestRollups.ts`, and redaction in
   `redaction.ts`.
3. [x] The local and staging Cloudflare runtimes use D1 console services; deleted
   Postgres migration scripts are not part of local observability development.
4. [x] Current validation is the relayer observability/router coverage plus the
   Refactor 82 runtime guard, which prevents stale Postgres paths from returning
   to this active doc set.

Shared staging verification belongs to the Refactor 82 Phase 6 runbook and
staging evidence manifests.

## Maintainability follow-up

The incident-log and rollup split is the right steady-state design, but the implementation still carries avoidable maintenance cost in a few places. The next cleanup pass should reduce code duplication, sharpen module boundaries, and move product policy out of storage internals.

### TODO list

- [x] Extract a declarative observability policy registry module.
- [x] Move request-metric route-family allowlist definitions into the registry.
- [x] Move route-family to service mapping into the registry.
- [x] Move durable event taxonomy and source ownership declarations into the registry.
- [x] Refactor observability storage code to consume the registry instead of embedded policy constants.
- [x] Keep request-metric normalization, histogram bucket definitions, and percentile
      estimation in `requestRollups.ts`.
- [x] Keep the D1 persistence adapter in `d1.ts`.
- [x] Keep metadata redaction in `redaction.ts`.
- [x] Replaced the deleted Postgres observability adapter with
      `packages/console-server-ts/src/observability/d1.ts`, backed by
      `policy.ts`, `requestRollups.ts`, and `redaction.ts`.
- [x] Keep `packages/console-server-ts/src/observability/index.ts` as the stable export surface.
- [x] Preserve existing behavior and test coverage while replacing the old Postgres storage path.
- [x] Extract shared observability hook helpers used by both Express and Cloudflare routers.
- [x] Unify request metric recording across Express and Cloudflare through the shared helper path.
- [x] Unify billing failure event emission across Express and Cloudflare through the shared helper path.
- [x] Unify approval failure event emission across Express and Cloudflare through the shared helper path.
- [x] Unify request/trace ID extraction and observability warning logs across both router adapters.
- [x] Consolidate observability docs into the newer rollout/architecture docs and remove legacy planning docs that no longer reflect the implemented system.
- [x] Re-run observability ingestion tests after the D1 storage replacement.
- [x] Re-run router parity and dashboard wiring tests after the router-hook unification work.

Maintainability follow-up is complete for the current local-development scope.

### 1. Keep D1 Observability Storage Focused

Current issue:

- `d1.ts` owns D1 schema bootstrap, event ingestion, request-rollup writes, and
  read queries.
- policy and request-rollup normalization live in separate modules so product
  rules can be reviewed without tracing every SQL query.

Target shape:

- `d1.ts` remains the D1 persistence adapter.
- `requestRollups.ts` owns request metric normalization, histogram buckets, and
  percentile estimation.
- `policy.ts` owns durable event source ownership and event taxonomy.
- `redaction.ts` owns metadata redaction.
- `index.ts` remains the stable export surface.

Acceptance criteria:

- product policy does not live inside ad hoc query branches
- feature behavior and tests remain unchanged after the split
- future changes to rollup policy or event taxonomy do not require touching D1
  query code by default

### 2. Unify Express/Cloudflare observability hooks

Current issue:

- request metric capture and failure-event emission are duplicated across Express and Cloudflare router implementations
- parity currently depends on keeping two large router files in sync

Target shape:

- extract shared observability hook helpers for:
  - request metric recording
  - billing failure event emission
  - approval failure event emission
  - request/trace ID extraction and common logging
- keep transport-specific adapters thin so Express and Cloudflare only provide request/response primitives

Acceptance criteria:

- common observability hook behavior lives in shared code rather than duplicated router logic
- Express and Cloudflare parity tests continue to pass against the shared helper path
- adding a new observability hook requires one implementation, not parallel edits in both routers

Completion note:

- shared router observability plumbing now lives in
  `packages/sdk-server-ts/src/router/consoleObservabilityHooks.ts`
- verified with relayer router parity subset and dashboard observability API wiring subset on 2026-03-12

### 3. Create a declarative observability policy registry

Current issue:

- route-family allowlist capture and related observability policy decisions currently live inside storage-oriented code
- product policy is therefore harder to inspect and update independently from persistence details

Target shape:

- add a single registry module that defines:
  - allowed request-metric route families
  - route-family to service mapping
  - durable event taxonomy and source ownership
  - any shared defaults for severity and component naming where applicable
- storage code should consume this registry rather than hardcoding policy locally

Acceptance criteria:

- observability capture policy is declared in one module
- storage and router code read policy from the registry instead of embedding their own route/service rules
- reviewers can inspect observability policy changes without tracing through D1
  query code

### 4. Consolidate observability docs

Current issue:

- observability documentation is currently split between this completed rollout doc and older planning docs that still describe the system as partially built
- that split will drift and makes it harder to tell which document is authoritative

Target shape:

- keep the newer rollout/architecture docs as the source of truth for the implemented system
- fold any still-relevant material from older planning docs into the maintained docs
- remove or replace outdated observability planning docs once their remaining useful content is captured

Acceptance criteria:

- there is one clear, current observability design document for implemented behavior
- stale observability planning docs are removed or explicitly superseded
- future observability changes update one current doc set instead of parallel narratives

Completion note:

- `docs/dashboard/observability.md` has been removed and this document now carries the active architecture, rollout, and refactor tracking.

## Suggested execution order

1. Extract the declarative policy registry first so subsequent refactors share one source of truth.
2. Keep D1 storage behind the `ConsoleObservabilityService` and
   `ConsoleObservabilityIngestionService` ports.
3. Unify Express/Cloudflare observability hooks last, once the storage and policy surfaces are smaller and clearer.

## Success metric

After the change, the observability event list should read like an incident queue, not an access log.
