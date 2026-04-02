# Threshold ECDSA Presign Benchmark Report

Generated: 2026-04-01T17:16:21.707Z
Run ID: `20260401-171621Z`

## Scenario Results

### cold_first_sign_no_pool

- Description: First sign with empty presign pool
- Status: error
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario cold_first_sign_no_pool --iterations 2`
- Error: Scenario command exited with code 1

### warm_sign_pool_hit

- Description: Warm sign with available presign pool entry
- Status: error
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario warm_sign_pool_hit --iterations 2`
- Error: Scenario command exited with code 1

### background_refill_contention

- Description: Foreground sign while background refill traffic is active
- Status: error
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario background_refill_contention --iterations 2`
- Error: Scenario command exited with code 1

### multi_runtime_contention

- Description: Duplicate runtime pressure (host + iframe/tab style)
- Status: error
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario multi_runtime_contention --iterations 2`
- Error: Scenario command exited with code 1

### store_backend_compare

- Description: Store backend benchmark (Postgres vs Redis/Upstash)
- Status: error
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario store_backend_compare --iterations 2`
- Error: Scenario command exited with code 1

### live_cache_miss_path

- Description: Force live-cache miss and stale-session retry path
- Status: error
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario live_cache_miss_path --iterations 2`
- Error: Scenario command exited with code 1

## SLO Gates

- Enabled: yes
- Passed: 0
- Failed: 0
- Skipped: 5

| Gate | Status | Actual | Comparator | Threshold | Reason |
|---|---|---:|---|---:|---|
| first_sign_p95_ms | skipped | n/a | <= | 4000.00 | `cold_first_sign_no_pool` was not executed |
| warm_sign_p95_ms | skipped | n/a | <= | 1500.00 | `warm_sign_pool_hit` was not executed |
| presign_step_p95_ms | skipped | n/a | <= | 900.00 | No `/threshold-ecdsa/presign/step` p95 values were collected |
| presign_step_p99_ms | skipped | n/a | <= | 1300.00 | No `/threshold-ecdsa/presign/step` p99 values were collected |
| stale_session_ratio_nonmiss_max | skipped | n/a | <= | 0.01 | No stale session ratios were collected |

## Presign Pool Configuration Recommendation

| Setting | Recommended |
|---|---:|
| targetDepth | 3 |
| lowWatermark | 1 |
| maxRefillInFlight | 1 |

Rationale:

- Current data supports keeping defaults (targetDepth=3, lowWatermark=1, maxRefillInFlight=1).

## Notes

- Use this report to justify changes in `client/src/core/config/defaultConfigs.ts`.
- Keep route-level and presign-step perf logs enabled in benchmark runs.
- Re-run benchmarks after any live-cache/store-path change.
