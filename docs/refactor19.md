# Refactor 19: Remove Per-Step Presign Replay (When Runtime Scope Allows)

Status: Planned  
Severity: High (ECDSA presign latency and CPU overhead)  
Last updated: 2026-02-24

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
Evidence: current defaults are `targetDepth: 20`, `lowWatermark: 5`, `maxRefillInFlight: 2` at `client/src/core/config/defaultConfigs.ts:35`.  
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
- [ ] Record baseline p50/p95/p99 for `/presign/step`.
- [ ] Add runtime flag to enable no-replay mode in controlled rollout.

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

## Phase 2: Hybrid Fallback (Safe Rollout)

- [x] Keep replay path as fallback while no-replay is being validated.
- [x] If cache miss occurs in hybrid mode, fallback to existing replay path.
- [ ] In strict no-replay mode, return explicit retriable session error.
- [ ] Emit structured metrics:
  - [x] Structured `/presign/step` perf fields now expose live/fallback behavior (`liveCacheStatus`, `liveResolveSource`, `replayFallbackUsed`, `replayFallbackReason`).
  - [ ] Dedicated metric names/counters:
    - `presign_live_cache_hit`
    - `presign_live_cache_miss`
    - `presign_replay_fallback_used`

Suggested files:

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`

## Phase 3: Remove Replay State Writes

- [ ] Stop appending `appliedSteps` when no-replay mode is enabled.
- [ ] Stop serializing `wasmSessionStateB64u` for no-replay sessions.
- [ ] Keep schema backward compatibility during rollout window.

Suggested files:

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
- `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts`

## Phase 4: Delete Replay Logic (When Proven Unneeded)

- [ ] Remove:
  - deterministic replay state types/parsers
  - deterministic RNG replay shim for presign reconstruction
  - reconstruct-from-state flow
- [ ] Simplify presign session record schema to minimal metadata.

Suggested files:

- `server/src/core/ThresholdService/ecdsaSigningHandlers.ts`
- `server/src/core/ThresholdService/stores/EcdsaSigningStore.ts`
- `server/src/core/ThresholdService/validation.ts`

## Phase 5: Tests

- [ ] Unit: init->step->done with live cache only.
- [ ] Unit: cache eviction causes retriable miss behavior (or hybrid fallback).
- [ ] Unit: stage regression and scope mismatch still rejected.
- [ ] Integration: full sign flow unchanged correctness.
- [ ] Update/remove distributed replay-specific tests once architecture decision is final.

Suggested tests:

- `tests/unit/thresholdEcdsa.presignDistributed.unit.test.ts` (split into replay-mode and no-replay-mode coverage)
- Add: `tests/unit/thresholdEcdsa.presignLiveCache.unit.test.ts`

## 6. Risks and Mitigations

1. In-flight presign sessions lost on process restart.  
Mitigation: client retry path; short presign session TTL; clear error code.

2. Multi-instance load balancing breaks session continuity.  
Mitigation: require sticky routing for presign session id or keep hybrid fallback.

3. Hidden dependency on replay semantics in tests/ops tooling.  
Mitigation: staged rollout with dual-mode metrics and explicit kill switch.

4. Premature replay deletion in distributed deployments.  
Mitigation: decision gate + rollout checklist must be signed off before Phase 4.

## 7. Done Criteria

- [ ] `/presign/step` p95 reduced materially versus baseline.
- [ ] Foreground sign latency improvement is measurable and stable.
- [ ] No correctness regressions in signature outputs.
- [ ] Replay path removed only after runtime constraints are explicitly accepted.
- [ ] Documentation updated to reflect non-distributed or sticky-session presign assumptions.

## 8. Phased TODO List (Active Tasks)

## Immediate (Measure + Low-Risk Contention Wins)

- [x] Task 8: Add micro-timing spans for replay restore, wasm compute, and store CAS/write.
- [x] Task 3: Add server-side foreground-priority scheduling over background refill.
- [x] Task 4: Lower interactive refill defaults to `targetDepth=2..3`, `lowWatermark=1`, `maxRefillInFlight=1`.
- [x] Task 5: Introduce single authority runtime election/locking for refill orchestration per account.
- [x] Client contention guard: when a foreground sign is in-flight for a pool key, skip scheduling new refill work for that key; foreground path first waits for any existing refill before starting a new handshake.
- [x] Regression coverage: add unit test proving foreground sign reuses in-flight refill and avoids duplicate presign handshake for the same pool key.

## Next (State/Storage Throughput Improvements)

- [x] Sequence gate: do live-session-first with replay fallback before any full replay removal.
- [x] Observability gate: add explicit replay-fallback logs so it is obvious when live-session restore failed and the system had to fallback (or fallback itself failed).
- [x] Observability gate: expose `liveCacheStatus` (`hit`/`miss`) and `replayFallbackUsed` in `/presign/step` perf logs for measurable cache/fallback ratios.
- [ ] Task 6: Migrate high-churn presign/session hot path to Redis/Upstash and benchmark p95/p99 delta.
- [x] Task 2: Add live presign session object cache with TTL/cleanup (cache-first execution).
- [x] Task 1: Keep replay only as fallback; validate hit ratio and latency gains in hybrid mode.

## Finalize (Security-Sensitive and Architectural Completion)

- [ ] Task 1: Remove replay path only after decision gate is satisfied and hybrid fallback metrics are stable.
- [ ] Convert matrix assumptions into verified results (before/after timing table + security review signoff).

## 9. Potential (Risky) Improvements (Out of Scope)

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
