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

Use `wrangler tail <worker> --format json` for a future live capture, or export
JSON from Workers Logs when access is available. Preserve each raw file. The
report records its SHA-256 digest and rejects incomplete evidence with a
non-zero exit status.

The cohort manifest is a strict declaration of provenance:

```json
{
  "schemaVersion": 1,
  "environment": "production",
  "capturedAt": "2026-07-24T00:00:00.000Z",
  "captureMethod": "wrangler_tail_json",
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
   instrumentation together with the Router and role workers, then add the
   remaining `registration.post_touch_id`, `gateway.d1_commit`, and
   `frontend.wallet_ready` events on the same canonical
   `x-seams-trace-id` correlation path.
2. Emit separate A and B preparation durations beneath
   `router.prepare_pair`.
3. Record a platform-supported isolate-instantiation or reuse fact. Deployment
   cohort labels alone do not prove isolate reuse.
4. Roll out Gateway, Router, Deriver A, Deriver B, and SigningWorker
   coherently, then capture a fresh cold-after-deploy cohort and a warm cohort.
5. Run the analyzer and review the critical path before freezing the
   Router-owned `gateway.yao_execute` budget.

Local traces remain useful for schema and correlation checks. Set the manifest
environment and capture method to `synthetic_test`; the analyzer will calculate
diagnostic values and keep `phase0BaselineReady` false.
