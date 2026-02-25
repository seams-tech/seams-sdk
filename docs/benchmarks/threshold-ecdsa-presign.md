# Threshold ECDSA Presign Benchmark Report

Generated: 2026-02-25T09:11:05.582Z
Run ID: `20260225-091017Z`

## Scenario Results

### cold_first_sign_no_pool

- Description: First sign with empty presign pool
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario cold_first_sign_no_pool --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `cold_first_sign_no_pool` | 2 | 2036 | 2226 | 2226 | 2131.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 1 | 1 | 0.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 65 | 65 | 65 | 65.0 |
| `/threshold-ecdsa/presign/init` | 2 | 16 | 41 | 41 | 28.5 |
| `/threshold-ecdsa/presign/step` | 12 | 20 | 783 | 783 | 193.3 |
| `/threshold-ecdsa/sign/finalize` | 2 | 17 | 18 | 18 | 17.5 |
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
| `warm_sign_pool_hit` | 2 | 22 | 24 | 24 | 23.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 1 | 1 | 0.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 61 | 61 | 61 | 61.0 |
| `/threshold-ecdsa/presign/init` | 2 | 17 | 40 | 40 | 28.5 |
| `/threshold-ecdsa/presign/step` | 12 | 18 | 770 | 770 | 193.2 |
| `/threshold-ecdsa/sign/finalize` | 2 | 13 | 17 | 17 | 15.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 1 | 1 | 0.5 |

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
| `background_refill_contention` | 2 | 4017 | 4205 | 4205 | 4111.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 1298 | 1298 | 649.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 60 | 60 | 60 | 60.0 |
| `/threshold-ecdsa/presign/init` | 4 | 17 | 41 | 41 | 23.0 |
| `/threshold-ecdsa/presign/step` | 24 | 20 | 741 | 769 | 189.0 |
| `/threshold-ecdsa/sign/finalize` | 2 | 12 | 18 | 18 | 15.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 24 |
| presign_live_cache_miss | 0 |
| presign_replay_fallback_used | 0 |
| liveCacheHitRatio | 100.0% |
| replayFallbackRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | 18 |
| backgroundPresignRequestRatio | 50.0% |
| poolEmptyResponses | 0 |

### multi_runtime_contention

- Description: Duplicate runtime pressure (host + iframe/tab style)
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario multi_runtime_contention --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `multi_runtime_contention` | 2 | 6026 | 6267 | 6267 | 6146.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 761 | 815 | 815 | 788.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 60 | 60 | 60 | 60.0 |
| `/threshold-ecdsa/presign/init` | 6 | 23 | 213 | 213 | 86.2 |
| `/threshold-ecdsa/presign/step` | 36 | 19 | 747 | 774 | 188.7 |
| `/threshold-ecdsa/sign/finalize` | 2 | 16 | 18 | 18 | 17.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 36 |
| presign_live_cache_miss | 0 |
| presign_replay_fallback_used | 0 |
| liveCacheHitRatio | 100.0% |
| replayFallbackRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | 41 |
| backgroundPresignRequestRatio | 66.7% |
| poolEmptyResponses | 0 |

### store_backend_compare

- Description: Store backend benchmark (Postgres vs Redis/Upstash)
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario store_backend_compare --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `store_backend_compare` | 2 | 2049 | 2196 | 2196 | 2122.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 1 | 1 | 0.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 62 | 62 | 62 | 62.0 |
| `/threshold-ecdsa/presign/init` | 2 | 16 | 42 | 42 | 29.0 |
| `/threshold-ecdsa/presign/step` | 12 | 20 | 764 | 764 | 192.6 |
| `/threshold-ecdsa/sign/finalize` | 2 | 12 | 18 | 18 | 15.0 |
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
| `replay_fallback_path` | 2 | 6811 | 7018 | 7018 | 6914.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/bootstrap` | 1 | 62 | 62 | 62 | 62.0 |
| `/threshold-ecdsa/presign/init` | 2 | 19 | 39 | 39 | 29.0 |
| `/threshold-ecdsa/presign/step` | 12 | 1075 | 1138 | 1138 | 995.0 |

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
| first_sign_p95_ms | pass | 2226.00 | <= | 4000.00 |  |
| warm_sign_p95_ms | pass | 24.00 | <= | 1500.00 |  |
| presign_step_p95_ms | pass | 783.00 | <= | 1400.00 |  |
| presign_step_p99_ms | pass | 783.00 | <= | 2000.00 |  |
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
