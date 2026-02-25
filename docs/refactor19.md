# Refactor 19: Remove Per-Step Presign Replay (When Runtime Scope Allows)

Status: In Progress (live-session-only shipped; replay deleted)  
Severity: High (ECDSA presign latency and CPU overhead)  
Last updated: 2026-02-25

## 1. Why Replay Exists Today

Current server presign sessions store a replay log (`appliedSteps`) and reconstruct a fresh `ThresholdEcdsaPresignSession` for every `/threshold-ecdsa/presign/step`.

This exists because:

1. The WASM `ThresholdEcdsaPresignSession` object is not persisted as a native snapshot today.
2. Presign session state is stored in external stores (Postgres/Redis/DO) and must be resumable across process boundaries.
3. Deterministic RNG seeding + replay preserves protocol continuity when restoring session state.
4. CAS-based progression supports distributed/multi-instance safety.

Relevant code:

1. Replay state model: `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
2. Reconstruction on each step: `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
3. Distributed-store test validating cross-instance progression: `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts`

## 2. Problem Statement

Per-step replay is expensive and grows with session progress:

1. Every step replays prior messages before doing new work.
2. This adds avoidable CPU and serialization overhead.
3. Under concurrent refill + foreground sign traffic, p95/p99 step latency spikes.

Observed impact in production logs: `/presign/step` dominates end-to-end cold-sign latency.

## 2.1 Eight Bottlenecks and Solutions

1. Bottleneck: Per-step replay on server (largest hotspot).  
Evidence: `server/src/core/ThresholdService/ecdsaSigningHandlers.ts:344` and `server/src/core/ThresholdService/ecdsaSigningHandlers.ts:705` reconstruct/replay prior state every step.  
Solution: Replace replay-first execution with live session-first execution (in-memory/worker object), keeping replay only as transitional fallback.

2. Bottleneck: No long-lived live presign object between step calls.  
Evidence: each `/presign/step` rehydrates protocol state from serialized JSON replay state.  
Solution: Keep live `ThresholdEcdsaPresignSession` objects in memory with minimal checkpoints; use persistent state only for fallback/recovery paths.

3. Bottleneck: Foreground sign competes with background refill.  
Evidence: refill traffic is already tagged as `background_presign_pool_refill`, and tagging logic exists at `server/src/router/express/routes/thresholdEcdsa.ts:31`.  
Solution: Add server-side priority scheduling so foreground sign work preempts/yields ahead of refill workloads.

4. Bottleneck: Refill defaults are too aggressive for interactive UX.  
Evidence: pre-refactor defaults were `targetDepth: 20`, `lowWatermark: 5`, `maxRefillInFlight: 2`; current interactive defaults are now reduced in `client/src/core/config/defaultConfigs.ts`.  
Solution: default interactive policy to `targetDepth=2..3`, `lowWatermark=1`, `maxRefillInFlight=1` (and keep override support for high-throughput environments).

5. Bottleneck: Duplicate runtimes can do duplicate refill/sign preparation.  
Evidence: host + iframe + multiple tabs may each schedule refill, increasing contention and duplicate presign work.  
Solution: enforce a single authority runtime per account for refill/sign orchestration, with cross-runtime lock/leadership semantics.

6. Bottleneck: High-churn presign/session state on slower backing store causes tail spikes.  
Evidence: code explicitly recommends Redis/Upstash for high churn at `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts:1354`.  
Solution: move presign/session stores to Redis/Upstash (or equivalent low-latency churn store) instead of Postgres for hot-path CAS/get-del workloads.

7. Bottleneck: Client cold-start after relogin due to non-persistent client presign shares.  
Evidence: loss of client-side presign material forces fresh cold presign handshake after login/runtime reset.  
Solution: persist encrypted client presign cache across login sessions with strict controls: encrypt-at-rest, single-use atomic consume, TTL, pool-key binding, and mismatch purge.

8. Bottleneck: Route-level `durationMs` lacks phase-level attribution.  
Evidence: current logs provide endpoint totals but not per-phase timings (replay vs wasm step vs store CAS).  
Solution: add micro-timing spans for replay restore, wasm compute, and store CAS/write to make optimization impact measurable and regression-proof.

## 2.2 Task Assessment Matrix

| # | Task | Perf likelihood + impact | Security-critical to remove/change? | Better secure alternative |
|---|---|---|---|---|
| 1 | Remove per-step replay on server | High likelihood, large impact (p95/p99 presign step) | Not cryptographic-critical; yes for distributed resumability/availability semantics | Live-session-first path with replay fallback; long-term WASM snapshot/restore |
| 2 | Keep live presign session objects in memory and checkpoint minimally | High likelihood, large impact on cold path | Not cryptographic-critical; availability-sensitive under restart/failover | In-memory live cache + bounded TTL + fallback replay/retry |
| 3 | Prioritize foreground sign over background refill | Medium-high likelihood under load, medium-high impact on UX latency | Not security-critical | Priority queue/token bucket with strict fairness and starvation guard |
| 4 | Reduce refill aggressiveness | High likelihood, medium-high impact (contention reduction) | Not security-critical | Lower interactive defaults (`targetDepth=2..3`, `lowWatermark=1`, `maxRefillInFlight=1`) + adaptive policy |
| 5 | Ensure one authority runtime per account for refill/sign prep | Medium-high likelihood in host+iframe+tab scenarios, medium impact | Not security-critical | Cross-runtime leadership lock (`navigator.locks`/BroadcastChannel) |
| 6 | Use fast churn stores for presign/session state | Medium likelihood (deployment-dependent), medium impact on tail latency | Not crypto-critical; operationally sensitive | Redis/Upstash for hot churn paths; keep durable semantics where needed |
| 7 | Persist encrypted client presign cache across login sessions | High likelihood for relogin cold-start reduction, medium-high impact | Security-sensitive if mishandled (nonce-share secrecy / single-use) | Encrypted-at-rest cache with atomic single-use consume, TTL, pool-key binding, mismatch purge |
| 8 | Add micro-timing around replay vs wasm vs CAS | Certain observability gap; indirect but high leverage | Not security-critical (if secrets excluded from logs) | Phase timers + redaction rules + sampled tracing for high-cardinality safety |

Notes:

1. Task #1 has the highest expected direct latency win but must preserve distributed correctness guarantees.
2. Task #7 offers major UX gains after relogin but has the highest security handling bar on the client side.
3. Task #8 should be landed first to validate assumptions and quantify win per task.

## 3. Scope and Decision Gate

This refactor is only valid when we explicitly accept a non-distributed presign-step runtime model (or provide equivalent fast local session affinity).

Gate must be satisfied before removing replay:

1. Presign-step handling is guaranteed on the same live coordinator runtime for the session lifetime.
2. Losing a process may drop in-flight presign sessions (acceptable; client retries).
3. Multi-instance step migration is not required for correctness in this deployment mode.

If any gate fails, keep replay path (or implement true WASM snapshot/restore first).

## 4. Target Architecture (No Replay Path)

## 4.1 Live Session Registry

Maintain an in-memory registry:

1. `presignSessionId -> live ThresholdEcdsaPresignSession`
2. Session metadata (stage, expiry, claims scope) kept with entry
3. TTL-driven eviction + explicit cleanup on terminal states

## 4.2 Store Contract Simplification

For no-replay mode:

1. Persist only minimal session metadata (or skip persistent presign session store entirely)
2. Remove `wasmSessionStateB64u` replay payload writes
3. Preserve presignature pool persistence and sign session persistence

## 4.3 Safety and Correctness

1. Keep existing validation and scope checks (`userId`, `rpId`, `participantIds`, `relayerKeyId`).
2. Keep stage transition rules (`triples -> presign -> done`).
3. Keep atomic reserve/consume behavior for presignature pool and sign sessions unchanged.

## 5. Implementation Plan

## Phase 0: Measure + Guardrails

- [x] Add detailed timers around current presign step phases:
  - restore/replay
  - protocol step compute
  - store CAS/write
- [x] Record representative baseline timing profile for `/presign/step` in docs (`docs/presigning-pool.md`).
- [x] Record baseline p50/p95/p99 for `/presign/step` via benchmark report (`docs/benchmarks/threshold-ecdsa-presign.md`, run `20260224-162718Z`).
- [x] Added runtime flag for controlled rollout (`THRESHOLD_ECDSA_PRESIGN_STRICT_NO_REPLAY`), then removed it after replay deletion.

Suggested files:

- `server/src/router/express/routes/thresholdEcdsa.ts`
- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`

## Phase 1: Introduce Live Session Cache

- [x] Add internal live presign session cache keyed by `presignSessionId`.
- [x] On `/presign/init`, create live session and cache it.
- [x] On `/presign/step`, use cached live session first.
- [x] Add TTL eviction + cleanup on `done`/error.

Suggested files:

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`

## Phase 2: Hybrid Fallback (Safe Rollout, Temporary)

- [x] Keep replay path as fallback while no-replay is being validated.
- [x] If cache miss occurs in hybrid mode, fallback to existing replay path.
- [x] In strict no-replay mode, return explicit retriable session error.
- [x] Emit structured metrics:
  - [x] Structured `/presign/step` perf fields exposed live/fallback behavior during hybrid rollout (`liveCacheStatus`, `liveResolveSource`, `replayFallbackUsed`, `replayFallbackReason`).
  - [x] Dedicated metric names/counters:
    - `presign_live_cache_hit`
    - `presign_live_cache_miss`
    - `presign_replay_fallback_used`

Note: This phase was completed as a rollout bridge and superseded by Phase 4 replay deletion; fallback-specific fields/counters were removed from the live path.

Suggested files:

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`

## Phase 3: Remove Replay State Writes

- [x] Stop appending `appliedSteps` when no-replay mode is enabled.
- [x] Stop serializing `wasmSessionStateB64u` for no-replay sessions.
- [x] Keep schema backward compatibility during rollout window.

Suggested files:

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
- `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts`

## Phase 4: Delete Replay Logic (When Proven Unneeded)

- [x] Remove:
  - deterministic replay state types/parsers
  - deterministic RNG replay shim for presign reconstruction
  - reconstruct-from-state flow
- [x] Simplify presign session record schema to minimal metadata.

Suggested files:

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
- `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts`
- `server/src/core/ThresholdService/validation.ts`

## Phase 5: Tests

- [x] Unit: init->step->done with live cache only.
- [x] Unit: cache eviction causes retriable miss behavior (or hybrid fallback).
- [x] Unit: stage regression and scope mismatch still rejected.
- [x] Integration: full sign flow unchanged correctness.
- [x] Integration: multi-instance HTTP forwarding validates `/threshold-ecdsa/presign/step` owner routing + session auth propagation.
- [x] Integration: owner-restart continuity test returns retriable `stale_session_state` and validates recovery via fresh `/threshold-ecdsa/presign/init`.
- [x] Integration: owner-peer-missing path returns retriable `stale_session_state` without deleting owner-owned session.
- [x] Integration: untrusted client `x-threshold-ecdsa-presign-forward-hop` header is ignored (trusted only with known forwarded-by peer).
- [x] Update/remove distributed replay-specific tests once architecture decision is final.

Suggested tests:

- `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts` (split into replay-mode and no-replay-mode coverage)
- Add: `tests/unit/thresholdEcdsa.presignLiveCache.unit.test.ts`
- `tests/relayer/threshold-ecdsa.signature-harness.test.ts` (HTTP multi-instance forwarding + auth propagation + trust hardening)

## 6. Risks and Mitigations

1. In-flight presign sessions lost on process restart.  
Mitigation: client retry path; short presign session TTL; clear error code.

2. Multi-instance load balancing breaks session continuity.  
Mitigation: require sticky routing for presign session id or handle retriable `stale_session_state` by re-running `/presign/init`.

3. Hidden dependency on replay semantics in tests/ops tooling.  
Mitigation: staged rollout with dual-mode metrics and explicit kill switch.

4. Premature replay deletion in distributed deployments.  
Mitigation: decision gate + rollout checklist must be signed off before Phase 4.

## 7. Done Criteria

- [x] `/presign/step` cold-path latency reduced materially by eliminating duplicate foreground/background presign contention and replay overhead.
- [x] Foreground sign latency improvement is measurable and stable in current testing (first sign ~3s, subsequent sign ~0.5-1s with warm pool).
- [x] No correctness regressions in signature outputs for current live-session-only path.
- [x] Replay path removed after runtime constraints were explicitly accepted.
- [x] Documentation updated to reflect current live-session behavior and presign pool lifecycle/timings.

## 8. Phased TODO List (Active Tasks)

## Immediate (Measure + Low-Risk Contention Wins)

- [x] Task 8: Add micro-timing spans for live cache resolve, wasm compute, and store CAS/write.
- [x] Task 3: Add server-side foreground-priority scheduling over background refill.
- [x] Task 4: Lower interactive refill defaults to `targetDepth=2..3`, `lowWatermark=1`, `maxRefillInFlight=1`.
- [x] Task 5: Introduce single authority runtime election/locking for refill orchestration per account.
- [x] Client contention guard: when a foreground sign is in-flight for a pool key, skip scheduling new refill work for that key; foreground path first waits for any existing refill before starting a new handshake.
- [x] Regression coverage: add unit test proving foreground sign reuses in-flight refill and avoids duplicate presign handshake for the same pool key.

## Next (State/Storage Throughput Improvements)

- [x] Sequence gate: do live-session-first with replay fallback before any full replay removal.
- [x] Observability gate (temporary): add explicit replay-fallback logs during hybrid rollout.
- [x] Observability gate: expose `liveCacheStatus` (`hit`/`miss`) in `/presign/step` perf logs for measurable cache/miss ratios.
- [ ] Task 6: Migrate high-churn presign/session hot path to Redis/Upstash and benchmark p95/p99 delta.
- [x] Task 2: Add live presign session object cache with TTL/cleanup (cache-first execution).
- [x] Task 1: Keep replay only as fallback; validate hit ratio and latency gains in hybrid mode, then delete replay.

## Finalize (Security-Sensitive and Architectural Completion)

- [x] Task 1: Remove replay path after decision gate was satisfied and hybrid fallback metrics stabilized.
- [x] Security hardening: ignore client-supplied forwarded-hop values unless accompanied by a known peer `forwarded-by` instance id.
- [x] Integration coverage: HTTP owner-forward success, owner-peer-missing fallback, and untrusted-hop behavior.
- [x] Convert matrix assumptions into verified results (before/after timing table + security review signoff).

### Verified Results (2026-02-25)

| Area | Before (field logs) | After (field logs + benchmark) | Verification |
|---|---|---|---|
| First sign latency | ~10-15s | ~3s (field), 2108ms p95 (`cold_first_sign_no_pool`) | User field traces + benchmark run `20260225-124743Z` |
| Subsequent sign latency | ~3-4s | ~0.5-1s (field), 26ms p95 (`warm_sign_pool_hit`) | User field traces + benchmark run `20260225-124743Z` |
| Presign step tail | 700-2200ms observed under duplicate/contended flow | 764ms p95 / 764ms p99 in benchmark gate | `docs/benchmarks/threshold-ecdsa-presign.md` |
| Session continuity failure behavior | replay-dependent and expensive | explicit retriable `stale_session_state` on cache miss/owner-unavailable paths | unit + relayer integration coverage |

Security review summary (current architecture):

1. Presign/session scope checks remain strict (`userId`, `rpId`, `participantIds`, `relayerKeyId`, expiry) and are enforced before step execution.
2. Client-supplied forwarded-hop is ignored unless accompanied by trusted peer provenance (`forwarded-by` in configured peer set).
3. One-time presignature reserve/consume semantics are unchanged (no reuse shortcut introduced).
4. No persistent client presign cache was introduced; sensitive client presign shares remain out of persistent client storage in this plan.
5. Replay removal changed availability semantics (retriable init on continuity loss) but did not reduce cryptographic validation coverage.

## 9. Benchmarking Program and Config-Tuning Loop

Goal: make presign performance tuning reproducible and data-driven, not anecdotal.

### 9.1 Dedicated benchmark module/folder

- [x] Add a standalone benchmark package under `benchmarks/threshold-ecdsa-presign/`.
- [x] Keep benchmark code isolated from production runtime logic.
- [x] Add a single entrypoint command (for local + CI):
  - `pnpm benchmark:threshold-ecdsa`

Proposed files:

- `benchmarks/threshold-ecdsa-presign/README.md`
- `benchmarks/threshold-ecdsa-presign/src/runner.mjs`
- `benchmarks/threshold-ecdsa-presign/src/scenarios.mjs`
- `benchmarks/threshold-ecdsa-presign/src/collectors.mjs`
- `benchmarks/threshold-ecdsa-presign/src/report.mjs`
- `benchmarks/threshold-ecdsa-presign/fixtures/`

### 9.2 Required benchmark scenarios

- [x] `cold_first_sign_no_pool`: empty pool, no warm entries.
- [x] `warm_sign_pool_hit`: pooled presignature available.
- [x] `background_refill_contention`: foreground sign under refill traffic.
- [x] `multi_runtime_contention`: host + iframe/tab-like duplicate runtime pressure.
- [x] `store_backend_compare`: Postgres vs Redis/Upstash (harness implemented; backend mode is env-driven).
- [x] `live_cache_miss_path`: force live-cache miss and verify retriable stale-session behavior/cost.

### 9.3 Metrics to capture

- [x] Route timings:
  - `/threshold-ecdsa/presign/init`
  - `/threshold-ecdsa/presign/step`
  - `/threshold-ecdsa/sign/init`
  - `/threshold-ecdsa/sign/finalize`
- [x] Percentiles:
  - p50, p95, p99
- [x] Ratios/counters:
  - `presign_live_cache_hit`
  - `presign_live_cache_miss`
  - `presign_stale_session_state`
  - foreground-vs-background queue wait
- [x] End-to-end UX metrics:
  - first-sign latency
  - warm-sign latency
  - error/retry rate

### 9.4 Benchmark outputs and documentation

- [x] Write raw run artifacts to `benchmarks/threshold-ecdsa-presign/out/*.json`.
- [x] Generate human-readable report at `docs/benchmarks/threshold-ecdsa-presign.md`.
- [x] Add a summarized tuning table to `docs/presigning-pool.md`:
  - recommended `targetDepth`
  - recommended `lowWatermark`
  - recommended `maxRefillInFlight`
  - when to switch from Postgres to Redis/Upstash

### 9.5 Config decision policy driven by benchmarks

- [x] Define explicit SLO gates for interactive signing:
  - first-sign p95 target
  - warm-sign p95 target
  - `/presign/step` p95 and p99 guardrails
- [x] Enforce benchmark SLO gates in CI (`.github/workflows/ci.yml`, threshold-signing-core job) using `pnpm benchmark:threshold-ecdsa`.
- [x] Keep defaults (`targetDepth=3`, `lowWatermark=1`, `maxRefillInFlight=1`) unless benchmark evidence supports a change.
- [x] Require benchmark evidence before changing presign pool defaults in `client/src/core/config/defaultConfigs.ts`.
- [x] Record each default change decision in `docs/refactor19.md` with before/after data.

### 9.6 Latest benchmark snapshot

- Latest run id: `20260225-124743Z`
- Report: `docs/benchmarks/threshold-ecdsa-presign.md`
- Current recommendation: keep `targetDepth=3`, `lowWatermark=1`, `maxRefillInFlight=1`

### 9.7 Next Execution Steps (Ordered)

- [ ] Run full GitHub CI for commit `c08f2f2` and confirm benchmark SLO gate stability on hosted runners.
- [x] Run `store_backend_compare` with real Postgres and Redis/Upstash backends; append backend comparison table (p50/p95/p99 + error rate) to `docs/benchmarks/threshold-ecdsa-presign.md`.
- [ ] Run multi-coordinator staging validation with real shared backend and rolling restarts; record first-sign/warm-sign latency and stale-session retry rate.
- [ ] Configure alerting for owner-forward outcomes (`ownerForwardReason`) and untrusted forward-header attempts (`forwardedByTrustedPeer=0`).
- [x] Add a runtime flag for strict no-replay mode and wire rollout control in server config.
- [x] Implement strict no-replay cache-miss behavior returning explicit retriable session error (no replay fallback in strict mode).
- [x] Add/adjust tests for strict mode:
  - [x] cache miss retriable behavior
  - [x] stage/scope validation parity
  - [x] full sign correctness unchanged
- [x] Record decision-gate evidence for replay removal (availability/distributed-correctness + security review) before any Phase 4 deletion.

### 9.8 Presign Pool Default Change Record

| Date | Run ID | Decision | Before | After | Reason |
|---|---|---|---|---|---|
| 2026-02-25 | `20260225-124743Z` | Keep defaults | `targetDepth=3`, `lowWatermark=1`, `maxRefillInFlight=1` | unchanged | SLO gates passed; no benchmark evidence to increase refill pressure |

Policy: any future change to `client/src/core/config/defaultConfigs.ts` presign defaults must include a benchmark run ID and before/after p50/p95/p99 deltas in this table.

### 9.8.1 Real Store Backend Compare Evidence

1. Harness logs: `benchmarks/threshold-ecdsa-presign/out/backend-compare-20260225-124327Z`
2. Parsed run summary: `benchmarks/threshold-ecdsa-presign/out/20260225-124611Z/raw-summary.json`
3. Doc table: `docs/benchmarks/threshold-ecdsa-presign.md` (`Real Store Backend Compare` section)
4. Result: Postgres and Redis were effectively tied in local runs for `store_backend_compare`; no default pool-policy change recommended.

### 9.8.2 Local Multi-Coordinator Restart Validation (Pre-Staging)

1. Test: `tests/relayer/threshold-ecdsa.signature-harness.test.ts` (`returns stale_session_state after owner restart and recovers via new presign init`)
2. Coverage: real HTTP owner-forward path, simulated owner live-session loss, retriable stale-session response, and fresh-session recovery flow.
3. Status: local integration validation complete; full staging with rolling restarts remains pending.

### 9.9 Replay Removal Decision-Gate Evidence

Availability/distributed-correctness evidence:

1. Owner-forward continuity implemented and validated over real HTTP routes (success path + owner-peer-missing retriable fallback).
2. Missing auth on forward path is explicitly rejected (`stale_session_state`) without deleting owner-owned session.
3. Untrusted forwarded-hop header is ignored unless trusted peer provenance is present.
4. Cache miss behavior is explicit/retriable (`stale_session_state`), allowing deterministic client recovery via `/threshold-ecdsa/presign/init`.

Security evidence:

1. Scope checks and expiry checks run before step processing.
2. Forwarding does not trust client-controlled hop metadata without peer attestation.
3. Sign flow correctness remains covered by relayer integration harness (known-digest verify + end-to-end sign).

## 10. Potential (Risky) Improvements (Out of Scope)

The following items are intentionally excluded from the active implementation plan due to security and operational risk:

1. Task 7 (deferred): Persistent encrypted client presign cache across login sessions.  
Potential upside: lower relogin cold-start latency.  
Why risky: introduces sensitive at-rest handling for client presign share material (`kShare`/`sigmaShare`) and strict single-use guarantees become harder to enforce correctly.

2. If reconsidered in the future, minimum required controls:
   - strong encrypt-at-rest with non-persisted key material
   - atomic single-use consume/delete semantics
   - strict TTL and pool-key binding
   - mismatch/decrypt-failure hard purge
   - explicit security review + red-team validation before rollout
