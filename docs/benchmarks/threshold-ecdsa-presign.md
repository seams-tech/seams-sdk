# Threshold ECDSA Presign Benchmark Report

Generated: 2026-05-20T13:29:08.989Z
Run ID: `20260520-132907Z`

## Scenario Results

### cold_first_sign_no_pool

- Description: First sign with empty presign pool
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario cold_first_sign_no_pool --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `cold_first_sign_no_pool` | 2 | 144 | 186 | 186 | 165.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 5 | 5 | 3.0 |
| `/threshold-ecdsa/hss/bootstrap` | 1 | 72 | 72 | 72 | 72.0 |
| `/threshold-ecdsa/presign/init` | 2 | 1 | 7 | 7 | 4.0 |
| `/threshold-ecdsa/presign/step` | 12 | 2 | 60 | 60 | 13.4 |
| `/threshold-ecdsa/sign/finalize` | 2 | 1 | 1 | 1 | 1.0 |
| `/threshold-ecdsa/sign/init` | 2 | 1 | 1 | 1 | 1.0 |

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
| `warm_sign_pool_hit` | 2 | 7 | 10 | 10 | 8.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 2 | 2 | 1.5 |
| `/threshold-ecdsa/hss/bootstrap` | 1 | 71 | 71 | 71 | 71.0 |
| `/threshold-ecdsa/presign/init` | 2 | 2 | 9 | 9 | 5.5 |
| `/threshold-ecdsa/presign/step` | 12 | 2 | 62 | 62 | 15.0 |
| `/threshold-ecdsa/sign/finalize` | 2 | 1 | 2 | 2 | 1.5 |
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

### pool_empty_retry

- Description: Sign init against an empty presignature pool and measure retry signal
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario pool_empty_retry --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `pool_empty_retry` | 2 | 2 | 3 | 3 | 2.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 4 | 4 | 2.0 |
| `/threshold-ecdsa/hss/bootstrap` | 1 | 67 | 67 | 67 | 67.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 1 | 1 | 0.5 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 0 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | n/a |
| staleSessionRatio | n/a |
| gateWaitP95ForegroundMs | n/a |
| gateWaitP95BackgroundMs | n/a |
| backgroundPresignRequestRatio | n/a |
| poolEmptyResponses | 2 |

### explicit_export_product

- Description: Explicit role-local ECDSA HSS export-share route plus client artifact creation
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario explicit_export_product --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `explicit_export_product` | 2 | 3 | 6 | 6 | 4.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/hss/bootstrap` | 1 | 63 | 63 | 63 | 63.0 |
| `/threshold-ecdsa/hss/export/share` | 2 | 0 | 1 | 1 | 0.5 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 0 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | n/a |
| staleSessionRatio | n/a |
| gateWaitP95ForegroundMs | n/a |
| gateWaitP95BackgroundMs | n/a |
| backgroundPresignRequestRatio | n/a |
| poolEmptyResponses | 0 |

## SLO Gates

- Enabled: yes
- Passed: 5
- Failed: 0
- Skipped: 0

| Gate | Status | Actual | Comparator | Threshold | Reason |
|---|---|---:|---|---:|---|
| first_sign_p95_ms | pass | 186.00 | <= | 4000.00 |  |
| warm_sign_p95_ms | pass | 10.00 | <= | 1500.00 |  |
| presign_step_p95_ms | pass | 62.00 | <= | 900.00 |  |
| presign_step_p99_ms | pass | 62.00 | <= | 1300.00 |  |
| stale_session_ratio_nonmiss_max | pass | 0.00 | <= | 0.01 |  |

## Presign Pool Configuration Recommendation

| Setting | Recommended |
|---|---:|
| targetDepth | 4 |
| lowWatermark | 2 |
| maxRefillInFlight | 1 |

Rationale:

- Observed 2 pool_empty responses; raise depth to reduce cold misses.

## Notes

- Use this report to justify changes in `client/src/core/config/defaultConfigs.ts`.
- Keep route-level and presign-step perf logs enabled in benchmark runs.
- Re-run benchmarks after any live-cache/store-path change.
