# Threshold Signing Load Testing Plan

Date updated: March 16, 2026

## Goal

Build a repeatable load-testing program for threshold signing that can answer, with measured data rather than anecdotes:

1. How threshold Ed25519 behaves under medium load.
2. How threshold ECDSA behaves under medium load, including presign pool contention.
3. What one coordinator node can sustain.
4. How many coordinator nodes are required for realistic `500 wallet` traffic profiles.
5. Which operational limits and failure modes must drive autoscaling, alerting, and topology choices.

## Why This Work Is Needed

Current evidence is useful but incomplete:

- Single-user concurrency is healthy, but that mostly validates per-session client behavior, not cross-wallet server pressure.
- Threshold ECDSA already has a benchmark harness and recent numbers, but it is not a true multi-wallet load test.
- Threshold Ed25519 has no equivalent benchmark harness yet.
- Threshold ECDSA live presign sessions are process-local, so multi-instance behavior depends on routing and peer-forwarding correctness, not just shared storage.

Current threshold ECDSA benchmark data from the March 15, 2026 run shows:

- cold first sign p95: `2128ms`
- warm pool-hit sign p95: `21ms`
- background refill contention p95: `4011ms`
- duplicate runtime contention p95: `5990ms`

Interpretation:

- warm-path latency is excellent
- sustained throughput is still bounded by presign generation
- multi-runtime and refill contention are already visible at small scale
- the next step must be actor-based multi-wallet load, not more single-flow microbenchmarks

## Questions This Plan Must Answer

1. What happens at `50`, `100`, `250`, and `500` active wallets?
2. What is the difference between low steady-state load and synchronized bursts?
3. How much ECDSA warm-pool masking do we get before refill debt dominates?
4. How much better does Ed25519 scale than ECDSA in this implementation?
5. How much capacity is lost when multi-instance routing is not sticky?
6. Which backend is acceptable for the hot path: Redis/Upstash vs Postgres?
7. What alert thresholds should block rollout or trigger autoscaling?

## Scope

### In Scope

- Node relay server coordinator deployments
- Threshold Ed25519 local 2-party flow
- Threshold Ed25519 relayer-cosigner topology as a later phase
- Threshold ECDSA warm pool-hit, cold miss, refill contention, and duplicate-runtime scenarios
- Single-node and multi-node coordinator topologies
- Shared persistent backend comparison for hot-path state
- Metrics, reports, and operator guidance derived from measured runs

### Out of Scope for Initial Implementation

- Browser rendering performance and UI paint timing
- Chain finalization latency after a signature is produced
- Cloudflare-first worker-only benchmark parity
- Full production traffic replay
- Monthly-scale durability soak tests

## Implementation Principles

1. Reuse the existing benchmark style in `benchmarks/threshold-ecdsa-presign` instead of creating unrelated one-off scripts.
2. Prefer a stateful Node actor harness over a thin HTTP-only load tool for the first version, because both threshold flows are multi-step and sessionful.
3. Measure steady-state load and burst load separately.
4. Treat `registered wallets` and `active wallets` as different capacity concepts.
5. Emit machine-readable output and a markdown summary for every run.
6. Keep foreground sign latency, background refill load, and internal fanout traffic as separate dimensions in reports.

## Deliverables

1. `benchmarks/threshold-load/README.md`
2. `benchmarks/threshold-load/src/runner.mjs`
3. `benchmarks/threshold-load/src/scenarios.mjs`
4. `benchmarks/threshold-load/src/report.mjs`
5. `benchmarks/threshold-load/src/system-stats.mjs`
6. `benchmarks/threshold-load/src/actors/ecdsaWallet.mjs`
7. `benchmarks/threshold-load/src/actors/ed25519Wallet.mjs`
8. `benchmarks/threshold-load/out/<run-id>/raw-summary.json`
9. `benchmarks/threshold-load/out/<run-id>/summary.md`
10. A reduced smoke profile that can run in CI or nightly without attempting full `500 wallet` load
11. Updated operator guidance in this document after the first real multi-wallet run

## Metrics To Capture

### User-Visible Flow Metrics

- end-to-end sign latency p50, p95, p99
- success rate
- timeout rate
- cancellation rate
- error code distribution

### Route-Level Metrics

- `/threshold-ed25519/authorize`
- `/threshold-ed25519/sign/init`
- `/threshold-ed25519/sign/finalize`
- `/threshold-ed25519/internal/cosign/init`
- `/threshold-ed25519/internal/cosign/finalize`
- `/threshold-ecdsa/authorize`
- `/threshold-ecdsa/presign/init`
- `/threshold-ecdsa/presign/step`
- `/threshold-ecdsa/sign/init`
- `/threshold-ecdsa/sign/finalize`

### ECDSA-Specific Load Metrics

- presign live cache hit ratio
- stale session ratio
- pool empty responses
- background vs foreground presign ratio
- presign gate wait
- average presignatures generated per second
- pool-hit ratio at sign time

### System Metrics

- CPU utilization
- RSS and heap usage
- event loop lag
- GC pauses if available
- backend latency
- Postgres pool saturation if Postgres is used
- Redis or Upstash request latency if Redis is used
- internal east-west request failure rate for multi-node and cosigner scenarios

## Test Profiles

The harness should support named traffic profiles instead of only raw wallet counts.

### Profile A: Low Steady State

- `500 wallets`
- each wallet signs roughly `1 tx / 5 min`
- purpose: approximate a moderate installed base with low overlap

### Profile B: Medium Steady State

- `500 wallets`
- each wallet signs roughly `1 tx / min`
- purpose: establish whether ECDSA becomes a fleet problem immediately

### Profile C: Burst Sign Wave

- `10%`, `25%`, `50%`, and `100%` of wallets sign within `5s`
- purpose: quantify p95 and failure-rate collapse under synchronized activity

### Profile D: Login or Refresh Storm

- wallets begin from cold runtime state
- ECDSA pool starts empty
- purpose: capture the worst realistic case after reload or fleet restart

### Profile E: Duplicate Runtime Pressure

- one logical wallet is represented by more than one active runtime
- purpose: quantify extra background refill and self-inflicted contention

## Scenario Matrix

| Scenario ID | Curve | Topology | Wallets | Traffic Profile | Purpose |
| --- | --- | --- | ---: | --- | --- |
| `ed25519_local_steady` | Ed25519 | 1 coordinator | 50/100/250/500 | A, B | establish Ed25519 baseline |
| `ed25519_local_burst` | Ed25519 | 1 coordinator | 50/100/250/500 | C | burst collapse point |
| `ed25519_cosigner_steady` | Ed25519 | 1 coordinator + cosigners | 50/100/250/500 | A, B | internal fanout cost |
| `ecdsa_warm_pool_steady` | ECDSA | 1 coordinator | 50/100/250/500 | A, B | best-case warm-path capacity |
| `ecdsa_cold_start_burst` | ECDSA | 1 coordinator | 50/100/250/500 | C, D | worst-case first-sign behavior |
| `ecdsa_refill_contention` | ECDSA | 1 coordinator | 50/100/250/500 | B, C | refill debt and tail amplification |
| `ecdsa_multi_runtime` | ECDSA | 1 coordinator | 50/100/250/500 | E | duplicate-runtime overhead |
| `ecdsa_multinode_sticky` | ECDSA | 2/4/8 coordinators | 100/250/500 | A, B, C | horizontal scale with correct routing |
| `ecdsa_multinode_forwarded` | ECDSA | 2/4/8 coordinators | 100/250/500 | A, B, C | peer-forward behavior under load |
| `ecdsa_backend_compare` | ECDSA | 1/2 coordinators | 100/250 | B | Redis/Upstash vs Postgres |

## Execution Backlog

### Phase 1: Harness Foundation

1. Create `benchmarks/threshold-load/` using the existing ECDSA benchmark module as the structural template.
2. Add an actor abstraction that owns wallet-local state:
   - session state
   - key references
   - ECDSA presign pool state
   - request counters
   - recent failures
3. Add a scheduler that can drive both steady-state and burst profiles.
4. Add a standard summary schema so all scenarios emit the same machine-readable result shape.
5. Add a system-stats collector sampled during the run.

### Phase 2: Ed25519 Baseline

1. Implement an Ed25519 actor that can:
   - authorize
   - sign init
   - sign finalize
2. Start with local 2-party mode only.
3. Run `50`, `100`, `250`, `500` wallet tests on one coordinator.
4. Record:
   - signs per second
   - latency distribution
   - CPU saturation point
   - error onset
5. Add relayer-cosigner mode only after the local baseline is stable.

### Phase 3: ECDSA Actor and Warm vs Cold Separation

1. Implement an ECDSA actor with explicit warm-pool and cold-start modes.
2. Record pool-hit ratio separately from end-to-end sign latency.
3. Add scenarios for:
   - warm steady-state
   - cold burst
   - refill contention
   - duplicate runtime contention
4. Preserve the current pool defaults during first measurement:
   - `targetDepth=3`
   - `lowWatermark=1`
   - `maxRefillInFlight=1`
5. Only tune pool policy after baseline data exists.

### Phase 4: Horizontal Scale and Routing

1. Run the ECDSA scenarios on `1`, `2`, `4`, and `8` coordinators.
2. Compare:
   - sticky routing by session or instance ownership
   - owner-forward behavior with coordinator peers configured
3. Measure:
   - extra hop cost
   - stale session rate
   - owner-forward failure rate
4. Document the minimum routing guarantees required for production.

### Phase 5: Backend Comparison

1. Use Redis or Upstash as the primary hot-path baseline.
2. Run Postgres as a comparison, not the presumed target.
3. Measure:
   - p95 and p99 route latency
   - saturation onset
   - storage-specific failure behavior
4. Confirm whether Postgres remains acceptable only for lower-throughput or non-hot-path cases.

### Phase 6: Resilience and Failure Injection

1. Inject backend latency or temporary unavailability.
2. Inject cosigner unavailability for Ed25519 relayer-cosigner mode.
3. Inject coordinator peer misconfiguration for ECDSA owner-forward.
4. Run login-storm and refresh-storm scenarios after server restarts.
5. Capture how errors surface:
   - `pool_empty`
   - `stale_session_state`
   - timeouts
   - internal fanout failures

### Phase 7: Reporting and Capacity Guidance

1. Produce a summary table for each topology:
   - safe sustained signs/sec
   - burst tolerance window
   - p95 sign latency
   - error rate at saturation
2. Convert the benchmark output into operator guidance:
   - minimum recommended coordinator count by traffic model
   - backend recommendation
   - autoscaling triggers
   - rollout guardrails
3. Keep this document updated with the latest measured envelope.

## Environment Matrix

Every serious run should pin the environment so results are comparable.

### Required Controls

- fixed Node version
- fixed instance size or CPU count
- fixed backend deployment mode
- known region or machine locality for coordinator and storage
- explicit coordinator count
- explicit routing mode
- explicit ECDSA pool policy

### Backend Order of Operations

1. Redis or Upstash hot-path baseline
2. Postgres comparison run
3. Optional Cloudflare worker parity later

### Topology Order of Operations

1. single coordinator
2. multi-coordinator with sticky routing
3. multi-coordinator with owner-forward enabled
4. Ed25519 relayer-cosigner topology

## CI and Runtime Strategy

The full `500 wallet` suite should not be part of the normal PR path.

### CI Smoke

- one reduced Ed25519 scenario
- one reduced ECDSA warm-path scenario
- one reduced ECDSA cold-path scenario
- small wallet counts only
- objective: catch regressions in behavior and result shape

### Nightly or Manual Full Load

- `100`, `250`, `500` wallet suites
- multi-node ECDSA runs
- backend comparison runs
- artifact upload and summary publication

## Initial Recommendations This Plan Intends To Validate

1. Threshold ECDSA should be treated as a separate capacity domain from Ed25519.
2. Redis or Upstash should be the default ECDSA hot-path backend for serious load.
3. One-node ECDSA should not be assumed sufficient for `500 wallet` medium load without measured sustained signs/sec data.
4. Sticky routing or correct owner-forward configuration is mandatory for horizontally scaled ECDSA.
5. Duplicate runtime activity must be treated as a real traffic multiplier, not a corner case.

## Success Criteria

This work is complete when all of the following are true:

1. We can run a reproducible command that simulates `50`, `100`, `250`, and `500` wallet load.
2. We have measured Ed25519 and ECDSA separately.
3. We can state a safe sustained signs/sec envelope for `1`, `2`, `4`, and `8` coordinator nodes.
4. We can answer whether a single coordinator is acceptable for the target `500 wallet` profile, with numbers.
5. We have a documented recommendation for:
   - coordinator count
   - storage backend
   - routing mode
   - autoscaling triggers
6. We have a reduced smoke profile suitable for CI or nightly regression detection.

## Follow-On Work

After the first implementation pass:

1. Add Cloudflare worker parity scenarios if that deployment mode matters.
2. Add long-duration soak tests for memory growth and presign pool churn.
3. Add automated trend comparison so each new benchmark run can detect capacity regressions, not just correctness regressions.
