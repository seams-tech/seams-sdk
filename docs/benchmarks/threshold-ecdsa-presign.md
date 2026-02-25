# Threshold ECDSA Presign Benchmark Report

Generated: 2026-02-25T12:48:17.515Z
Run ID: `20260225-124743Z`

## Scenario Results

### cold_first_sign_no_pool

- Description: First sign with empty presign pool
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario cold_first_sign_no_pool --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `cold_first_sign_no_pool` | 2 | 1962 | 2108 | 2108 | 2035.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 1 | 1 | 1.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 78 | 78 | 78 | 78.0 |
| `/threshold-ecdsa/presign/init` | 2 | 20 | 38 | 38 | 29.0 |
| `/threshold-ecdsa/presign/step` | 12 | 18 | 728 | 728 | 183.6 |
| `/threshold-ecdsa/sign/finalize` | 2 | 11 | 14 | 14 | 12.5 |
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
| `warm_sign_pool_hit` | 2 | 16 | 26 | 26 | 21.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 0 | 0 | 0 | 0.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 61 | 61 | 61 | 61.0 |
| `/threshold-ecdsa/presign/init` | 2 | 16 | 44 | 44 | 30.0 |
| `/threshold-ecdsa/presign/step` | 12 | 19 | 735 | 735 | 186.2 |
| `/threshold-ecdsa/sign/finalize` | 2 | 12 | 18 | 18 | 15.0 |
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
| `background_refill_contention` | 2 | 3994 | 4129 | 4129 | 4061.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 1282 | 1282 | 641.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 62 | 62 | 62 | 62.0 |
| `/threshold-ecdsa/presign/init` | 4 | 17 | 41 | 41 | 23.0 |
| `/threshold-ecdsa/presign/step` | 24 | 19 | 718 | 757 | 185.6 |
| `/threshold-ecdsa/sign/finalize` | 2 | 15 | 17 | 17 | 16.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 24 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | 100.0% |
| staleSessionRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | 17 |
| backgroundPresignRequestRatio | 50.0% |
| poolEmptyResponses | 0 |

### multi_runtime_contention

- Description: Duplicate runtime pressure (host + iframe/tab style)
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario multi_runtime_contention --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `multi_runtime_contention` | 2 | 5923 | 6053 | 6053 | 5988.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 738 | 1493 | 1493 | 1115.5 |
| `/threshold-ecdsa/bootstrap` | 1 | 63 | 63 | 63 | 63.0 |
| `/threshold-ecdsa/presign/init` | 6 | 20 | 212 | 212 | 82.7 |
| `/threshold-ecdsa/presign/step` | 36 | 18 | 711 | 736 | 182.7 |
| `/threshold-ecdsa/sign/finalize` | 2 | 11 | 17 | 17 | 14.0 |
| `/threshold-ecdsa/sign/init` | 2 | 0 | 0 | 0 | 0.0 |

| Presign Perf | Value |
|---|---:|
| presign_live_cache_hit | 36 |
| presign_live_cache_miss | 0 |
| presign_stale_session_state | 0 |
| liveCacheHitRatio | 100.0% |
| staleSessionRatio | 0.0% |
| gateWaitP95ForegroundMs | 0 |
| gateWaitP95BackgroundMs | 37 |
| backgroundPresignRequestRatio | 66.7% |
| poolEmptyResponses | 0 |

### store_backend_compare

- Description: Store backend benchmark (Postgres vs Redis/Upstash)
- Status: ok
- Command: `node ./benchmarks/threshold-ecdsa-presign/src/scenario-harness.mjs --scenario store_backend_compare --iterations 2`

| End-to-End Scenario Total | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `store_backend_compare` | 2 | 1964 | 2137 | 2137 | 2050.5 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/authorize` | 2 | 1 | 1 | 1 | 1.0 |
| `/threshold-ecdsa/bootstrap` | 1 | 59 | 59 | 59 | 59.0 |
| `/threshold-ecdsa/presign/init` | 2 | 16 | 40 | 40 | 28.0 |
| `/threshold-ecdsa/presign/step` | 12 | 17 | 764 | 764 | 186.3 |
| `/threshold-ecdsa/sign/finalize` | 2 | 13 | 16 | 16 | 14.5 |
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
| `live_cache_miss_path` | 2 | 20 | 42 | 42 | 31.0 |

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) |
|---|---:|---:|---:|---:|---:|
| `/threshold-ecdsa/bootstrap` | 1 | 61 | 61 | 61 | 61.0 |
| `/threshold-ecdsa/presign/init` | 2 | 20 | 40 | 40 | 30.0 |
| `/threshold-ecdsa/presign/step` | 2 | 0 | 0 | 0 | 0.0 |

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
| first_sign_p95_ms | pass | 2108.00 | <= | 4000.00 |  |
| warm_sign_p95_ms | pass | 26.00 | <= | 1500.00 |  |
| presign_step_p95_ms | pass | 764.00 | <= | 900.00 |  |
| presign_step_p99_ms | pass | 764.00 | <= | 1300.00 |  |
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

## Real Store Backend Compare (Postgres vs Redis)

Run metadata:

1. Harness run directory: `benchmarks/threshold-ecdsa-presign/out/backend-compare-20260225-124327Z`
2. Parsed summary: `benchmarks/threshold-ecdsa-presign/out/20260225-124611Z/raw-summary.json`
3. Mode/env:
   - Postgres: `BENCH_THRESHOLD_STORE_MODE=postgres`, `BENCH_PG_URL=postgres://tatchi:tatchi@127.0.0.1:5432/tatchi`
   - Redis: `BENCH_THRESHOLD_STORE_MODE=redis`, `BENCH_REDIS_URL=redis://127.0.0.1:6379`
4. Scenario: `store_backend_compare`, `iterations=6` for each backend

| Backend | E2E p50 (ms) | E2E p95 (ms) | E2E p99 (ms) | `/presign/step` p95 (ms) | `/presign/step` p99 (ms) | `/presign/init` p95 (ms) | `/sign/init` p95 (ms) | `/sign/finalize` p95 (ms) | Stale-session ratio |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| Postgres | 1964 | 2106 | 2106 | 687 | 717 | 41 | 6 | 20 | 0.0% |
| Redis (tcp) | 1953 | 2136 | 2136 | 691 | 735 | 43 | 5 | 19 | 0.0% |

Interpretation:

1. On this local run, Postgres and Redis are effectively tied for this scenario.
2. Redis is slightly better on `sign/init` p95, while Postgres is slightly better on end-to-end p95 and presign-step tail.
3. No stale-session behavior was observed on either backend.
4. Keep current pool defaults unchanged (`targetDepth=3`, `lowWatermark=1`, `maxRefillInFlight=1`); no backend-driven tuning change is warranted from this run alone.
