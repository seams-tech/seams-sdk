# Refactor 93 Production Evidence

Phase 0 remains externally gated. Existing production logs cannot reconstruct
twenty complete historical traces because the Gateway and frontend spans,
per-role preparation subspans, and isolate-reuse facts were not emitted. The
current account can run live `wrangler tail`, while Workers Observability
history is unavailable to it.

The evidence analyzer prevents local or partial measurements from being
reported as the Phase 0 baseline:

```sh
node ./crates/router-ab-cloudflare/scripts/refactor93-production-evidence.mjs \
  analyze \
  --manifest /absolute/path/refactor93-cohort.json \
  --logs /absolute/path/gateway.jsonl \
  --logs /absolute/path/router.jsonl \
  --logs /absolute/path/deriver-a.jsonl \
  --logs /absolute/path/deriver-b.jsonl \
  --logs /absolute/path/signing-worker.jsonl \
  --out /absolute/path/refactor93-report.json
```

Use `wrangler tail <worker> --format json` for live span and correlation
checks. A tail record does not expose invocation CPU or wall time. Export JSON
from Workers Logs when access is available to acquire those resource fields.
Preserve each raw file. The report records its SHA-256 digest and rejects
incomplete evidence with a non-zero exit status.

## Read-only staging audit (2026-07-25)

The current Wrangler credential can read live Worker tails, but it cannot read
the historical Workers Observability export needed to reconstruct a cohort.
The tail session for `router-ab-mpc-router-staging` connected successfully and
produced no events during the bounded observation window; this is a live-tail
capability check, not production evidence.

The active staging versions are not one coherent Refactor 93 deployment. The
latest active version timestamps are:

| Worker                             | Version                                | Created (UTC)                 |
| ---------------------------------- | -------------------------------------- | ----------------------------- |
| `router-ab-mpc-router-staging`     | `c908c692-d254-4ca5-ac98-433d57829913` | `2026-07-25T05:34:46.844011Z` |
| `router-ab-deriver-a-staging`      | `10959b1b-1aae-436f-b01f-32ea89add211` | `2026-07-25T05:31:00.806662Z` |
| `router-ab-deriver-b-staging`      | `2d5f7ab4-b245-4c5f-8b20-174a6d0738ab` | `2026-07-25T05:31:03.068707Z` |
| `router-ab-signing-worker-staging` | `49c5d928-48ca-4fd8-8320-f2a202dcf46f` | `2026-07-25T05:31:18.085944Z` |
| `seams-sdk-d1-gateway-staging`     | `3764caf6-d8fb-43c7-a647-a16103368022` | `2026-07-24T12:03:37.161982Z` |

The 2026-07-25 stack run selected source `a13f8e56526e15fd4ad8bbfdd14225a89f24328f`.
That revision does not contain `router_coordinator.rs` or the private Refactor
93 execute route, so it overwrote the earlier historical route deployment.
Generic method/authentication responses cannot prove that the currently active
Router dispatches the new route.

The active Gateway version still exposes `ROUTER_API_RUNTIME` and direct
`DERIVER_A`, `DERIVER_B`, and `SIGNING_WORKER` bindings. It does not expose
any `ROUTER_AB_YAO_GATEWAY_<FAMILY>_ADMISSION_CUTOFF_MS` and
`ROUTER_AB_YAO_GATEWAY_<FAMILY>_DRAIN_UNTIL_MS` pair, so no drain-gated family
cutover is enabled. Read-only endpoint checks confirmed Router POST-only responses (405),
the staging ceremony JWKS (200), and Gateway health (200); these checks do not
exercise registration, recovery, export, replay, or conflict behavior.

This audit records no Phase 0 or Phase 6 completion. No deployment, cutover,
route deletion, or production trace claim is authorized by these observations.

## Historical staging workflow failure audit (2026-07-25)

The last run of the retired staging stack workflow (`30145784893`, Gateway job
`89647436415`) deployed Router, Deriver A, Deriver B, and SigningWorker, then
failed before the Gateway Worker upload. The Gateway secrets-file builder
reported `STRIPE_API_SK is required`. The selected source revision required
that secret, while the workflow graph used for the run did not pass it into
the Gateway job environment or its preflight validation loop. The
`staging-gateway` environment has the secret configured; this was a workflow
schema mismatch rather than evidence of an absent runtime secret.

The current deployment model replaces that stack workflow with
`deploy-staging-backend.yml` and derives Gateway secret requirements from
`deployment/targets.json`. Billing is enabled in both hosted environments, so
both Gateway jobs require `STRIPE_API_SK`; the staging workflow now projects
the configured secret into the same capability-derived preflight and deploy
path. The deployment-target unit test owns that capability-to-secret invariant.
A coherent staging run of the current backend workflow is still required before
the Refactor 93 deployment can be claimed.

The analyzer also validates event ownership for every required span. Gateway
spans must arrive as `router_ab_yao_gateway_span_v1`, Router spans as
`router_ab_yao_coordinator_span_v1`, role spans as
`router_ab_yao_role_span_v1` with the matching `deriver_a` or `deriver_b`
role, and frontend spans as `seams_registration_timing_span_v1`. Role events
carry low-level command or protocol labels rather than the Gateway's
`registration` operation label, so those labels are accepted after ownership
validation. A required span under the wrong event owner blocks the Phase 0
baseline instead of silently contributing to its latency budget.

Each role-session Durable Object emits a sanitized
`deriver_a.session_do.instance` or `deriver_b.session_do.instance` span. Its
in-memory request sequence is `1` for a newly instantiated object and greater
than `1` for reuse of that same live object. The analyzer reports whether later
ceremony transitions reused the live role object. Eviction creates a new object
and resets the sequence. This is Durable Object instance evidence; it does not
prove Worker isolate reuse, which remains a separate platform evidence field.

## Workers Logs resource join

The parser accepts direct structured events, Wrangler tail records, individual
Workers Logs events, and Workers Observability query responses containing
event arrays. The current Workers Observability API represents the structured
application log under `source` while invocation facts are carried by the
`$workers` resource record. The relevant
[Workers API schema](https://developers.cloudflare.com/api/resources/workers/)
defines `requestId`, `scriptName`, optional `executionModel` and
`durableObjectId`, and the invocation-only `cpuTimeMs` and `wallTimeMs`
fields.

Custom-log and invocation records are joined by the exact
`$workers.requestId` and `$workers.scriptName` pair. Optional execution-model
Durable Object, trace, span, and script-version identifiers must agree when
both records provide them. The parser also rejects disagreement between
`$metadata` and `$workers` request, service, trace, or span identifiers.
Ambiguous resource records fail the input instead of choosing one.

CPU and wall time are admitted only from the `cloudflare-workers` dataset's
invocation variant. That record must carry `$metadata.type =
"cf-worker-event"`, an outcome, and `$workers.scriptVersion.id`. The version
must equal the cohort manifest's `gatewayVersionId`; a record from another
Gateway deployment cannot certify the cohort.

The join adds only these platform-proven values:

```text
$workers.cpuTimeMs   -> cpu_ms
$workers.wallTimeMs  -> wall_time_ms
```

It retains request ID, script name, script version, trace ID, span ID,
execution model, and Durable Object ID in the `workers_resource` attribution
object. Those identifiers prove the invocation associated with the resource
values. They do not prove isolate reuse, memory usage, database work, replay
behavior, or downstream call counts. `wallTimeMs` remains wall time; the
parser does not relabel it as active duration.

An official invocation record may carry the span in the same Workers Logs
event, or it may be a separate event with the same join identity. CPU and wall
time on an unwrapped custom event, a Wrangler tail event, a custom-log record,
or an unmatched Workers Logs record remain untrusted for production
readiness.

## Execution telemetry contract

The successful `gateway.yao_execute` event is the per-trace execution record.
A production trace is ineligible for the Phase 0 baseline until its CPU and
wall time have the Workers Logs attribution above and it carries all of these
non-negative fields:

```text
cpu_ms                       number
wall_time_ms                 number
memory_mb                    number
durable_object_call_count    integer
worker_invocation_count      integer
d1_query_count               integer
exact_replay_count           integer
conflict_count               integer
```

The analyzer reports nearest-rank p50/p95/min/max values for each field by
cold and warm cohort. Missing values remain explicit blockers; the analyzer
never treats an omitted platform metric as zero. `d1_query_count` is the
platform-attributed count for the connected Router execution. A value greater
than zero blocks the trace, which prevents a successful Phase 0 report from
claiming that product D1 work stayed outside the MPC execution span. D1 work
belongs on the separate `gateway.d1_commit` event.

Replay and conflict counts are retained as observed per-execution counts. They
are not inferred from HTTP status, error text, or duplicate log lines. The
custom event fields are optional at the parser boundary so local and
historical logs remain readable; production readiness requires all fields on
the execution event. No ciphertext, identity, token, or package data is
accepted as telemetry.

The remaining acquisition sources are deliberately separate:

- `memory_mb` needs a retained platform artifact that exposes per-invocation
  memory for the exact execution. The current Workers Logs resource schema
  does not expose it, and
  [OpenTelemetry export does not currently export Worker metrics](https://developers.cloudflare.com/workers/observability/exporting-opentelemetry-data/).
  Until such an artifact exists, this field remains a blocker.
- Durable Object calls, Worker invocations, and D1 queries require correlated
  automatic trace spans. Cloudflare tracing instruments handler invocations
  and binding operations; the evidence pipeline still needs the trace export
  and a strict count join before those three values are admissible.
- Exact replay and conflict counts require sanitized Router coordinator
  counters for the execution. Cloudflare resource metadata has no knowledge
  of these protocol outcomes.

No missing field is defaulted to zero. Workers Logs alone can satisfy CPU and
wall time, while the six remaining values keep the production cohort open.

The cohort manifest is a strict declaration of provenance:

```json
{
  "schemaVersion": 1,
  "environment": "production",
  "capturedAt": "2026-07-24T00:00:00.000Z",
  "captureMethod": "cloudflare_workers_logs_export",
  "release": {
    "sourceSha": "0000000000000000000000000000000000000000",
    "gatewayVersionId": "cloudflare-version-id",
    "routerVersionId": "cloudflare-version-id",
    "deriverAVersionId": "cloudflare-version-id",
    "deriverBVersionId": "cloudflare-version-id",
    "signingWorkerVersionId": "cloudflare-version-id"
  },
  "traces": [
    {
      "traceId": "00000000000000000000000000000000",
      "cohort": "cold_after_deploy",
      "isolateReuse": {
        "gateway": "unknown",
        "router": "unknown",
        "deriverA": "unknown",
        "deriverB": "unknown",
        "signingWorker": "unknown"
      }
    }
  ]
}
```

Replace every placeholder with deployment or trace facts. `unknown` is a valid
capture state and a readiness blocker. This records the absence of telemetry
without inventing a cold or warm isolate classification. The release component
IDs must describe one coherent deployment.

The gate requires at least twenty successful correlated registration traces,
both deployment cohorts, the complete span tree from
[`refactor-93.md`](./refactor-93.md), separate
`router.prepare_pair.deriver_a` and `router.prepare_pair.deriver_b` spans, and
known isolate-reuse status. It calculates p50 and p95 with the nearest-rank
method. Only complete production traces contribute to those values.

Current readiness blockers are:

1. Deploy the Gateway `gateway.pre_yao` and `gateway.yao_execute` span
   instrumentation together with the Router and role workers, then verify the
   `registration.post_touch_id`, `gateway.d1_commit`, and
   `frontend.wallet_ready` events on the same canonical `x-seams-trace-id`
   correlation path. The frontend and Gateway route emitters are implemented;
   deployment collection and D1-write attribution remain to be verified.
2. Verify deployed collection preserves the existing separate A and B
   preparation durations beneath `router.prepare_pair`.
3. Record a platform-supported isolate-instantiation or reuse fact. Deployment
   cohort labels alone do not prove isolate reuse.
4. Roll out Gateway, Router, Deriver A, Deriver B, and SigningWorker
   coherently, then capture a fresh cold-after-deploy cohort and a warm cohort.
5. Run the analyzer and review the critical path before freezing the
   Router-owned `gateway.yao_execute` budget.

Local traces remain useful for schema and correlation checks. Set the manifest
environment and capture method to `synthetic_test`; the analyzer will calculate
diagnostic values and keep `phase0BaselineReady` false.
