# Threshold ECDSA Presign Benchmark Report

Generated: 2026-02-24T16:47:15.785Z
Run ID: `20260224-164630Z`

## Scenario Results

### cold_first_sign_no_pool

- Description: First sign with empty presign pool
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario cold_first_sign_no_pool --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `cold_first_sign_no_pool` | 2 | 1926 | 2053 | 2053 | 1989.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 1 | 1 | 0.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 56 | 56 | 56 | 56.0 |
| `/threshold-ecdsa/presign/init` | 2 | 15 | 37 | 37 | 26.0 |
| `/threshold-ecdsa/presign/step` | 12 | 16 | 719 | 719 | 179.3 |
| `/threshold-ecdsa/sign/finalize` | 2 | 11 | 12 | 12 | 11.5 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 12 |
| presign_live_cache_miss | 0 |
| presign_replay_fallback_used | 0 |
| liveCacheHitRatio | 100.0% |
| replayFallbackRatio | 0.0% |
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
| `warm_sign_pool_hit` | 2 | 20 | 21 | 21 | 20.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 0 | 0 | 0.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 51 | 51 | 51 | 51.0 |
| `/threshold-ecdsa/presign/init` | 2 | 15 | 36 | 36 | 25.5 |
| `/threshold-ecdsa/presign/step` | 12 | 19 | 730 | 730 | 180.0 |
| `/threshold-ecdsa/sign/finalize` | 2 | 12 | 16 | 16 | 14.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 12 |
| presign_live_cache_miss | 0 |
| presign_replay_fallback_used | 0 |
| liveCacheHitRatio | 100.0% |
| replayFallbackRatio | 0.0% |
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
| `background_refill_contention` | 2 | 3821 | 3957 | 3957 | 3889.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 1252 | 1252 | 626.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 59 | 59 | 59 | 59.0 |
| `/threshold-ecdsa/presign/init` | 4 | 16 | 44 | 44 | 23.3 |
| `/threshold-ecdsa/presign/step` | 24 | 17 | 705 | 741 | 179.6 |
| `/threshold-ecdsa/sign/finalize` | 2 | 15 | 19 | 19 | 17.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 1 | 1 | 0.5 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 24 |
| presign_live_cache_miss | 0 |
| presign_replay_fallback_used | 0 |
| liveCacheHitRatio | 100.0% |
| replayFallbackRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | 16 |
| backgroundPresignRequestRatio | 50.0% |
| poolEmptyResponses | 0 |

### multi_runtime_contention

- Description: Duplicate runtime pressure (host + iframe/tab style)
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario multi_runtime_contention --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `multi_runtime_contention` | 2 | 5663 | 5862 | 5862 | 5762.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 782 | 1408 | 1408 | 1095.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 58 | 58 | 58 | 58.0 |
| `/threshold-ecdsa/presign/init` | 6 | 20 | 200 | 200 | 79.5 |
| `/threshold-ecdsa/presign/step` | 36 | 18 | 698 | 743 | 177.8 |
| `/threshold-ecdsa/sign/finalize` | 2 | 11 | 12 | 12 | 11.5 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 1 | 1 | 0.5 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 36 |
| presign_live_cache_miss | 0 |
| presign_replay_fallback_used | 0 |
| liveCacheHitRatio | 100.0% |
| replayFallbackRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | 15 |
| backgroundPresignRequestRatio | 66.7% |
| poolEmptyResponses | 0 |

### store_backend_compare

- Description: Store backend benchmark (Postgres vs Redis/Upstash)
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario store_backend_compare --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `store_backend_compare` | 2 | 1948 | 2096 | 2096 | 2022.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 1 | 1 | 0.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 58 | 58 | 58 | 58.0 |
| `/threshold-ecdsa/presign/init` | 2 | 16 | 40 | 40 | 28.0 |
| `/threshold-ecdsa/presign/step` | 12 | 18 | 738 | 738 | 183.1 |
| `/threshold-ecdsa/sign/finalize` | 2 | 11 | 17 | 17 | 14.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 12 |
| presign_live_cache_miss | 0 |
| presign_replay_fallback_used | 0 |
| liveCacheHitRatio | 100.0% |
| replayFallbackRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | n/a |
| backgroundPresignRequestRatio | 0.0% |
| poolEmptyResponses | 0 |

### replay_fallback_path

- Description: Force live-cache miss and replay fallback
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario replay_fallback_path --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `replay_fallback_path` | 2 | 6562 | 6633 | 6633 | 6597.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/bootstrap` | 1 | 50 | 50 | 50 | 50.0 |
| `/threshold-ecdsa/presign/init` | 2 | 17 | 35 | 35 | 26.0 |
| `/threshold-ecdsa/presign/step` | 12 | 1030 | 1094 | 1094 | 951.5 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 0 |
| presign_live_cache_miss | 12 |
| presign_replay_fallback_used | 12 |
| liveCacheHitRatio | 0.0% |
| replayFallbackRatio | 100.0% |
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
| first_sign_p95_ms | pass | 2053.00 | <= | 4000.00 |  |
| warm_sign_p95_ms | pass | 21.00 | <= | 1500.00 |  |
| presign_step_p95_ms | pass | 738.00 | <= | 900.00 |  |
| presign_step_p99_ms | pass | 743.00 | <= | 1300.00 |  |
| replay_fallback_ratio_nonfallback_max | pass | 0.00 | <= | 0.01 |  |

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
- Re-run benchmarks after any replay/fallback/store-path change.
