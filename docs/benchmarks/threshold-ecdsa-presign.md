# Threshold ECDSA Presign Benchmark Report

Generated: 2026-03-15T15:32:17.690Z
Run ID: `20260315-153144Z`

## Scenario Results

### cold_first_sign_no_pool

- Description: First sign with empty presign pool
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario cold_first_sign_no_pool --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `cold_first_sign_no_pool` | 2 | 1951 | 2128 | 2128 | 2039.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 1 | 1 | 0.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 66 | 66 | 66 | 66.0 |
| `/threshold-ecdsa/presign/init` | 2 | 16 | 39 | 39 | 27.5 |
| `/threshold-ecdsa/presign/step` | 12 | 17 | 736 | 736 | 183.4 |
| `/threshold-ecdsa/sign/finalize` | 2 | 15 | 18 | 18 | 16.5 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 1 | 1 | 0.5 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 12 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | 100.0% |
| staleSessionRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | n/a |
| backgroundPresignRequestRatio | 0.0% |
| poolEmptyResponses | 0 |

### warm_sign_pool_hit

- Description: Warm sign with available presign pool entry
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario warm_sign_pool_hit --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `warm_sign_pool_hit` | 2 | 21 | 21 | 21 | 21.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 1 | 1 | 1.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 56 | 56 | 56 | 56.0 |
| `/threshold-ecdsa/presign/init` | 2 | 16 | 38 | 38 | 27.0 |
| `/threshold-ecdsa/presign/step` | 12 | 19 | 723 | 723 | 182.5 |
| `/threshold-ecdsa/sign/finalize` | 2 | 12 | 15 | 15 | 13.5 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 12 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | 100.0% |
| staleSessionRatio | 0.0% |
| gateWaitP95ForegroundMs | n/a |
| gateWaitP95BackgroundMs | 0 |
| backgroundPresignRequestRatio | 100.0% |
| poolEmptyResponses | 0 |

### background_refill_contention

- Description: Foreground sign while background refill traffic is active
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario background_refill_contention --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `background_refill_contention` | 2 | 3876 | 4011 | 4011 | 3943.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 689 | 689 | 345.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 61 | 61 | 61 | 61.0 |
| `/threshold-ecdsa/presign/init` | 4 | 16 | 192 | 192 | 66.3 |
| `/threshold-ecdsa/presign/step` | 24 | 18 | 696 | 740 | 180.8 |
| `/threshold-ecdsa/sign/finalize` | 2 | 14 | 15 | 15 | 14.5 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 24 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | 100.0% |
| staleSessionRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | 0 |
| backgroundPresignRequestRatio | 50.0% |
| poolEmptyResponses | 0 |

### multi_runtime_contention

- Description: Duplicate runtime pressure (host + iframe/tab style)
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario multi_runtime_contention --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `multi_runtime_contention` | 2 | 5768 | 5990 | 5990 | 5879.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 770 | 1978 | 1978 | 1374.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 59 | 59 | 59 | 59.0 |
| `/threshold-ecdsa/presign/init` | 6 | 20 | 207 | 207 | 82.5 |
| `/threshold-ecdsa/presign/step` | 36 | 17 | 703 | 730 | 180.4 |
| `/threshold-ecdsa/sign/finalize` | 2 | 16 | 18 | 18 | 17.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 1 | 1 | 0.5 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 36 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | 100.0% |
| staleSessionRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | 16 |
| backgroundPresignRequestRatio | 66.7% |
| poolEmptyResponses | 0 |

### store_backend_compare

- Description: Store backend benchmark (Postgres vs Redis/Upstash)
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario store_backend_compare --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `store_backend_compare` | 2 | 1960 | 2102 | 2102 | 2031.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 1 | 1 | 0.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 57 | 57 | 57 | 57.0 |
| `/threshold-ecdsa/presign/init` | 2 | 15 | 41 | 41 | 28.0 |
| `/threshold-ecdsa/presign/step` | 12 | 19 | 724 | 724 | 182.7 |
| `/threshold-ecdsa/sign/finalize` | 2 | 14 | 15 | 15 | 14.5 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 12 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | 100.0% |
| staleSessionRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | n/a |
| backgroundPresignRequestRatio | 0.0% |
| poolEmptyResponses | 0 |

### live_cache_miss_path

- Description: Force live-cache miss and stale-session retry path
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario live_cache_miss_path --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `live_cache_miss_path` | 2 | 20 | 41 | 41 | 30.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/bootstrap` | 1 | 60 | 60 | 60 | 60.0 |
| `/threshold-ecdsa/presign/init` | 2 | 19 | 40 | 40 | 29.5 |
| `/threshold-ecdsa/presign/step` | 2 | 1 | 1 | 1 | 1.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 0 |
| presign_live_cache_miss | 2 |
| presign_stale_session_state | 2 |
| liveCacheHitRatio | 0.0% |
| staleSessionRatio | 100.0% |
| gateWaitP95ForegroundMs | n/a |
| gateWaitP95BackgroundMs | n/a |
| backgroundPresignRequestRatio | 0.0% |
| poolEmptyResponses | 0 |

## SLO Gates

- Enabled: yes
- Passed: 5
- Failed: 0
- Skipped: 0

| Gate | Status | Actual | Comparator | Threshold | Reason |
|---|---|---:|---|---:|---|
| first_sign_p95_ms | pass | 2128.00 | <= | 4000.00 |  |
| warm_sign_p95_ms | pass | 21.00 | <= | 1500.00 |  |
| presign_step_p95_ms | pass | 736.00 | <= | 900.00 |  |
| presign_step_p99_ms | pass | 740.00 | <= | 1300.00 |  |
| stale_session_ratio_nonmiss_max | pass | 0.00 | <= | 0.01 |  |

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
