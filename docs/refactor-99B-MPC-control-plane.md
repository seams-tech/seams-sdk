# Refactor 99B: MPC Control Plane

Date created: July 30, 2026

Status: Planned

## Goal

Create a Seams-internal control plane for MPC fleet observability and carefully
governed MPC runtime configuration. Keep it separate from the customer console
where organizations manage wallets, policies, team access, webhooks, usage, and
billing.

The target product surfaces are:

- `seams.sh/dashboard` for the customer console, backed by `/console/*` APIs;
- `admin.seams.sh` for Seams operators, backed by `/admin/*` APIs.

Refactor 95 remains responsible only for producing authenticated prewarm
heartbeat telemetry. This plan owns the operator UI, telemetry queries, alerts,
configuration publishing, authorization boundary, and deployment split.

## Current State

The intended product boundary exists only in fragments today:

- `ConsoleAuthClaims` includes a `platformSupport` boolean and selected platform
  support routes require it.
- Platform billing is hidden from non-support users in the customer dashboard.
- A console-only Cloudflare Worker entrypoint already exists in
  `d1ConsoleStagingWorker.ts`.

MPC and platform operations are still mixed into the customer console:

- `/dashboard/observability` is an unconditional customer-dashboard route.
- `/console/observability/*` uses `project.view`, so customer project viewers can
  access the current observability API.
- the observability backend lives under `packages/console-server-ts` and is
  scoped by customer organization, project, and environment;
- `/dashboard/overview` renders the platform-support ops cockpit inside the
  customer dashboard;
- all route definitions identify themselves as the `console` surface and use
  the console authentication plane;
- the deployed Gateway currently dispatches `/console/*` requests and Router API
  traffic from the same Worker.

The current observability implementation is useful and should be split by
audience rather than discarded. Its incident-only event policy, per-minute
latency rollups, service-health model, redaction, and pagination are appropriate
patterns for the MPC control plane.

## Product Boundary

### Customer console

The customer console owns tenant-scoped product administration:

- organizations, projects, environments, and team access;
- wallets and wallet lifecycle history;
- policies, approvals, and gas sponsorship;
- API keys and webhooks;
- tenant usage, invoices, billing, and receipts;
- customer audit history;
- customer-visible webhook delivery and product failure details.

It must not expose MPC topology, Worker names, deployment revisions, internal
service health, cold-start telemetry, fleet alerts, platform-wide customer
search, or MPC configuration.

### MPC control plane

The MPC control plane owns Seams-operated infrastructure:

- Gateway, MPC Router, Deriver A, Deriver B, and SigningWorker fleet health;
- synthetic heartbeat and real-user request telemetry;
- signing-path latency, availability, and failure classification;
- deployment and configuration revision consistency;
- MPC-specific incidents and alerts;
- safe MPC runtime parameters and their publication history;
- platform operator audit history.

The control plane may aggregate tenant-independent service metrics. A support
workflow may accept a customer request or trace identifier for investigation,
but the primary metrics model must remain low-cardinality and must not expose
wallet addresses, public keys, transcript material, request bodies, or
secret-derived identifiers.

## Target Architecture

```text
seams.sh/dashboard
  -> customer console application
  -> customer console Worker /console/*
  -> tenant console services and console D1

admin.seams.sh
  -> MPC admin application
  -> MPC admin Worker /admin/*
  -> Cloudflare telemetry query adapter
  -> MPC configuration and operator-audit store

public Gateway
  -> wallet and signing APIs
  -> one-minute authenticated prewarm chain
  -> MPC Router -> Deriver A, Deriver B, SigningWorker
```

The three entrypoints are independently deployable. The public Gateway must not
serve customer-console or admin APIs. The customer console must not receive MPC
telemetry or configuration bindings. The admin Worker receives only the
bindings required to query telemetry and publish approved MPC configuration.

## Source Layout

Use direct ownership boundaries in the current repository:

```text
apps/
  seams-site/                    # marketing and customer dashboard
  seams-admin/                   # Seams-internal MPC control plane UI

packages/
  console-server-ts/             # customer console services and /console routes
  platform-admin-server-ts/      # operator auth, MPC telemetry, config, audit
```

`platform-admin-server-ts` should begin with concrete modules rather than a
generic administration framework:

```text
src/
  auth/
  mpcObservability/
  mpcConfiguration/
  audit/
  router/
  cloudflare/
```

Do not create a shared UI or server package until repeated code demonstrates a
real shared abstraction. Small value types that genuinely cross the customer
and admin boundary may remain in an existing neutral package.

## Authentication And Authorization

The admin surface must use its own authentication plane. Customer organization
membership, customer `OWNER` or `ADMIN` roles, and `platformSupport` embedded in
customer console claims must not grant admin access.

Initial admin authorization has two explicit roles:

- `VIEWER`: read fleet health, metrics, incidents, configuration, and audit;
- `ADMIN`: all viewer access plus publish and rollback MPC configuration.

Use a host-only secure session for `admin.seams.sh` with a distinct issuer,
audience, cookie name, and signing secret. Put Cloudflare Access or an equivalent
identity-aware perimeter in front of the Worker as an additional boundary. The
application still validates its own admin session and authorization.

Every configuration publication and rollback requires recent authentication
and appends an operator audit record. Do not reuse tenant audit contexts or
derive admin authorization from an active customer organization.

## Observability Model

### Metrics

Routine healthy measurements belong in bounded-cardinality metric rollups:

- heartbeat count and success rate;
- last successful heartbeat and consecutive failure count;
- cold-start rate per Worker;
- p50, p95, and p99 wall latency per Worker and for the complete chain;
- CPU-time distribution per Worker;
- real-user request count, success rate, and p50/p95/p99 latency;
- admission rejects, throttling, timeouts, and in-flight work;
- service-binding, Durable Object, D1, queue, and RPC latency and failures;
- deployment version and applied configuration revision;
- configuration or participant-set skew.

Keep synthetic and product traffic separate:

- **synthetic warmth** reports whether scheduled heartbeat invocations are cold;
- **user-experienced warmth** reports whether real wallet operations encounter
  cold Workers.

The heartbeat series measures the prewarm mechanism. The real-user series owns
the product SLI.

Use Cloudflare invocation telemetry and automatic traces as the primary source
for Worker identity, version, colo, CPU time, wall time, outcome, cold-start
state, handler spans, and service-binding spans. Store/query metric rollups for
the dashboard. Do not copy every healthy invocation into D1 as a durable event.

### MPC-specific signals

Add low-cardinality signals for:

- signing success, abort, and timeout rates;
- Deriver A and Deriver B failure rates;
- stuck or orphaned ceremonies;
- replay and idempotency rejections;
- participant-set, key-epoch, or protocol mismatch transitions;
- presignature availability and replenishment failure, where applicable;
- circuit-breaker state and degraded routing decisions.

### Durable incidents

Persist only operator-actionable state transitions:

- heartbeat degradation and recovery;
- sustained latency or error-budget threshold crossings and recovery;
- participant unavailable or recovered;
- deployment/configuration skew detected or resolved;
- signing subsystem degradation and recovery;
- configuration publication or rollout failure;
- telemetry ingestion or export failure.

Alerting is driven by these transitions. A first release needs alerts for three
missed heartbeat intervals, repeated child failure, sustained cold-start rate,
p95 signing latency, signing error rate, participant/configuration skew, and
presignature low-watermark conditions that already exist in the runtime.

## Admin Dashboard

Start with three pages:

### Fleet

- topology from Gateway through all MPC roles;
- current health and last successful heartbeat;
- synthetic and user-experienced cold-start rates;
- heartbeat and real-user latency distributions;
- Worker version, region distribution, and configuration revision;
- active incidents and configuration skew.

### Signing operations

- request volume, success rate, and latency over time;
- failures grouped by stable stage and code;
- participant and dependency health;
- trace/request lookup for incident investigation;
- MPC-specific abort, timeout, mismatch, and pool signals.

### Configuration

- desired and observed configuration revisions;
- validated draft and current configuration diff;
- publish history, actor, timestamp, and rollout status;
- rollback to a previously valid revision;
- links from a revision to correlated metrics and incidents.

The operator audit log is available from the configuration page initially. Add
a standalone audit page only when its volume justifies one.

## MPC Configuration Model

MPC configuration is platform-scoped desired state. It must not reuse the
tenant runtime snapshot payload, which is scoped to organization policy and gas
sponsorship.

Define a strict, versioned MPC configuration schema. Parse and normalize raw
storage and request shapes at the admin API boundary. Internal code accepts only
validated configuration variants with required fields.

Separate parameters by how they take effect:

### Runtime parameters

Examples include prewarm enabled state, request timeouts, admission and
concurrency limits, routing and circuit-breaker thresholds, existing
presignature watermarks, and telemetry sampling.

### Deployment parameters

Cron expressions, Worker routes, service bindings, compatibility dates, and
deployed code versions remain deployment configuration. The one-minute prewarm
cron stays fixed; the admin runtime control only enables or disables its work.

### Secrets and cryptographic configuration

The dashboard displays only secret references, public fingerprints, key epochs,
participant identities, and rotation status. It never reads or writes raw
secrets, private shares, seed material, or transcript material.

Publishing follows one path:

```text
Draft -> validate -> show diff -> publish -> observe rollout -> rollback
```

Each published revision is immutable and checksummed. Every MPC Worker reports
its applied revision in telemetry so the control plane can compare desired and
observed state. Do not add compatibility readers for superseded internal config
shapes; migrate the boundary and remove the old shape.

## Implementation Plan

### Phase 1: Establish the two product surfaces

- [ ] Create `apps/seams-admin` with only the MPC control-plane shell.
- [ ] Remove Observability, Ops Cockpit, and platform billing from the customer
      dashboard route table and sidebar.
- [ ] Keep customer wallet, policy, webhook, audit, usage, and billing views in
      `apps/seams-site`.
- [ ] Route `admin.seams.sh` to the admin application and keep the customer
      console at `seams.sh/dashboard`.

### Phase 2: Split backend ownership and authorization

- [ ] Create `packages/platform-admin-server-ts` with admin auth, route policy,
      router, audit, MPC observability, and MPC configuration modules.
- [ ] Define `/admin/*` route definitions with an `admin` surface and admin auth
      plane.
- [ ] Move platform-support APIs out of `/console/*`; delete the old routes
      after their callers move.
- [ ] Remove `platformSupport` from customer console claims after the platform
      routes no longer depend on it.
- [ ] Keep customer console authorization scoped only to organization and
      project roles.

### Phase 3: Split Worker deployments

- [ ] Deploy the existing console-only entrypoint as the customer Console
      Worker.
- [ ] Stop dispatching `/console/*` from the public Gateway Worker.
- [ ] Add a dedicated admin Worker with a distinct session configuration and
      the minimal telemetry/configuration bindings.
- [ ] Verify the Gateway cannot resolve `/console/*` or `/admin/*`, the customer
      Console Worker cannot resolve `/admin/*`, and the admin Worker cannot
      resolve `/console/*`.

### Phase 4: Ship read-only MPC observability

- [ ] Add a Cloudflare telemetry query adapter and MPC metric vocabulary.
- [ ] Ingest or query Refactor 95 heartbeat telemetry without durable
      per-heartbeat event writes.
- [ ] Add real-user cold-start, latency, success, and failure rollups.
- [ ] Build Fleet and Signing Operations pages.
- [ ] Add incident transitions and the first alert thresholds.

### Phase 5: Ship governed MPC configuration

- [ ] Define and validate the versioned MPC configuration schema.
- [ ] Implement immutable publication, checksum, current revision, observed
      revision, rollout status, and rollback.
- [ ] Add the Configuration page with validation and diffs.
- [ ] Emit applied revision telemetry from each MPC Worker.
- [ ] Require recent authentication and append an operator audit record for
      publication and rollback.

### Phase 6: Delete mixed-surface paths

- [ ] Delete the customer `/dashboard/observability` route after its useful
      platform functionality has moved.
- [ ] Delete `/console/observability/*`, `/console/ops-cockpit/*`, and other
      platform-support routes after admin callers use `/admin/*`.
- [ ] Move platform-only observability storage, types, tests, and migrations out
      of `console-server-ts`.
- [ ] Delete stale fixtures and guards that assert the combined Gateway/Console
      or customer/Admin surface.
- [ ] Confirm no customer bundle imports admin modules and no admin bundle
      imports customer dashboard modules.

## Minimal Validation

- A customer session cannot authenticate to or call any `/admin/*` route.
- An admin session does not require an active customer organization.
- Customer navigation contains no platform observability or MPC configuration.
- `admin.seams.sh` shows all five MPC roles and the latest Refactor 95 heartbeat.
- Synthetic and real-user cold-start series remain distinct.
- Healthy heartbeat traffic updates metrics without appending durable incident
  events.
- A simulated missed-heartbeat threshold creates one degradation incident and
  one recovery incident.
- A configuration publication is validated, checksummed, audited, observed by
  every MPC role, and reversible to the prior revision.
- Gateway, customer Console, and admin Workers reject one another's route
  namespaces.

## Non-goals

- building a general-purpose log analytics product;
- exposing MPC internals or platform-wide telemetry to customers;
- editing raw environment variables, Wrangler configuration, bindings, routes,
  or secrets from the dashboard;
- running synthetic signing ceremonies from the heartbeat;
- replacing Cloudflare deployment versions, traces, logs, or metrics;
- changing signing protocol, custody, persistence, or cryptographic behavior.

## Acceptance

Refactor 99B is complete when:

1. the customer and admin applications, APIs, authentication planes, modules,
   and Worker deployments are separate;
2. only Seams operators can access MPC telemetry, incidents, alerts, and
   configuration;
3. customer console functionality remains available without platform-support
   claims or admin code;
4. the admin Fleet and Signing Operations pages report synthetic and real-user
   health for all five MPC roles;
5. MPC configuration uses immutable validated revisions with audit, observed
   rollout state, and rollback;
6. raw secrets and sensitive MPC material never cross the admin API boundary;
7. the public Gateway serves neither customer-console nor admin routes.
