# Threshold Load Report

Generated: 2026-06-03T05:06:38.283Z
Run ID: `20260603-050635Z`

## Scenario Summary

| Scenario | Description | Status | Success Rate | Signs/sec | Sign p95 (ms) |
|---|---|---|---:|---:|---:|
| `ed25519_local_steady_smoke` | Threshold Ed25519 local warm-session steady-state smoke profile | ok | 100.0% | 235.76 | 17.82 |
| `ed25519_local_burst_smoke` | Threshold Ed25519 local warm-session synchronized burst smoke profile | ok | 100.0% | 201.31 | 36.27 |
| `ed25519_local_presign_pool_hit_smoke` | Threshold Ed25519 local presign pool-hit finalize-and-dispatch smoke profile | ok | 100.0% | 260.19 | 14.91 |
| `ed25519_local_presign_pool_miss_smoke` | Threshold Ed25519 local depleted-pool two-RTT fallback smoke profile | ok | 100.0% | 230.72 | 18.70 |
| `ed25519_local_presign_refill_smoke` | Threshold Ed25519 local presign refill smoke profile | ok | 100.0% | 361.45 | 12.23 |
| `ed25519_local_presign_double_consume_smoke` | Threshold Ed25519 local presign serverless double-consume pressure smoke profile | ok | 100.0% | 109.95 | 34.41 |

## ed25519_local_steady_smoke

- Description: Threshold Ed25519 local warm-session steady-state smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 45.02
- Signing duration (ms): 50.90
- Total attempts: 12
- Total success: 12
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 235.76
- Presign mode: two_rtt
- Presign accepted during measured run: 0
- Presign rejected during measured run: 0
- Presign pool hits: 0

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 7.03 | 19.71 | 19.71 | 12.32 | 19.71 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 12 | 10.56 | 17.82 | 17.82 | 12.04 | 17.82 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 7.03 | 19.71 | 19.71 | 12.32 | 19.71 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 12 | 3.60 | 7.36 | 7.36 | 3.80 | 7.36 |
| `/threshold-ed25519/sign/finalize` | 12 | 3.99 | 4.96 | 4.96 | 3.69 | 4.96 |
| `/threshold-ed25519/sign/init` | 12 | 3.24 | 5.66 | 5.66 | 3.20 | 5.66 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 74.93 |
| cpuSystemMsTotal | 2.93 |
| rssMb p95 | 177.94 |
| rssMb max | 177.94 |
| heapUsedMb p95 | 35.67 |
| heapUsedMb max | 35.67 |
| eventLoopDelayMs p95 | 20.28 |
| eventLoopDelayMs max | 20.28 |

## ed25519_local_burst_smoke

- Description: Threshold Ed25519 local warm-session synchronized burst smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 8 --signs-per-wallet 1 --max-concurrency 8 --profile burst`
- Profile: burst
- Wallets: 8
- Signs per wallet: 1
- Max concurrency: 8
- Bootstrap duration (ms): 47.37
- Signing duration (ms): 39.74
- Total attempts: 8
- Total success: 8
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 201.31
- Presign mode: two_rtt
- Presign accepted during measured run: 0
- Presign rejected during measured run: 0
- Presign pool hits: 0

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 8 | 22.29 | 27.41 | 27.41 | 23.12 | 27.41 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 8 | 30.23 | 36.27 | 36.27 | 31.23 | 36.27 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 8 | 22.29 | 27.41 | 27.41 | 23.12 | 27.41 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 8 | 9.24 | 13.36 | 13.36 | 9.75 | 13.36 |
| `/threshold-ed25519/sign/finalize` | 8 | 4.66 | 9.44 | 9.44 | 5.44 | 9.44 |
| `/threshold-ed25519/sign/init` | 8 | 11.97 | 24.23 | 24.23 | 14.53 | 24.23 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 64.80 |
| cpuSystemMsTotal | 4.06 |
| rssMb p95 | 187.44 |
| rssMb max | 187.44 |
| heapUsedMb p95 | 35.02 |
| heapUsedMb max | 35.02 |
| eventLoopDelayMs p95 | 19.30 |
| eventLoopDelayMs max | 19.30 |

## ed25519_local_presign_pool_hit_smoke

- Description: Threshold Ed25519 local presign pool-hit finalize-and-dispatch smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_pool_hit --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 43.12
- Signing duration (ms): 46.12
- Total attempts: 12
- Total success: 12
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 260.19
- Presign mode: presign_pool_hit
- Presign accepted during measured run: 0
- Presign rejected during measured run: 0
- Presign pool hits: 12
- Presign setup accepted: 12
- Presign setup rejected: 0

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 4.44 | 19.84 | 19.84 | 11.15 | 19.84 |

#### Presign Setup

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Presign Setup | 6 | 6.40 | 12.72 | 12.72 | 7.28 | 12.72 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 12 | 10.27 | 14.91 | 14.91 | 10.93 | 14.91 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 4.44 | 19.84 | 19.84 | 11.15 | 19.84 |

### Presign Setup Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/presign/refill` | 6 | 4.89 | 11.92 | 11.92 | 6.33 | 11.92 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/sign/finalize-and-dispatch` | 12 | 7.91 | 12.11 | 12.11 | 8.58 | 12.11 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 57.44 |
| cpuSystemMsTotal | 2.73 |
| rssMb p95 | 190.30 |
| rssMb max | 190.30 |
| heapUsedMb p95 | 35.37 |
| heapUsedMb max | 35.37 |
| eventLoopDelayMs p95 | 20.76 |
| eventLoopDelayMs max | 20.76 |

## ed25519_local_presign_pool_miss_smoke

- Description: Threshold Ed25519 local depleted-pool two-RTT fallback smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_pool_miss --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 46.85
- Signing duration (ms): 52.01
- Total attempts: 12
- Total success: 12
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 230.72
- Presign mode: presign_pool_miss_fallback
- Presign accepted during measured run: 0
- Presign rejected during measured run: 0
- Presign pool hits: 0

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 6.31 | 21.42 | 21.42 | 12.68 | 21.42 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 12 | 10.73 | 18.70 | 18.70 | 12.39 | 18.70 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 6.31 | 21.42 | 21.42 | 12.68 | 21.42 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 12 | 3.73 | 10.05 | 10.05 | 4.42 | 10.05 |
| `/threshold-ed25519/sign/finalize` | 12 | 3.30 | 4.96 | 4.96 | 3.41 | 4.96 |
| `/threshold-ed25519/sign/init` | 12 | 3.21 | 6.50 | 6.50 | 3.21 | 6.50 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 76.78 |
| cpuSystemMsTotal | 3.84 |
| rssMb p95 | 180.06 |
| rssMb max | 180.06 |
| heapUsedMb p95 | 36.15 |
| heapUsedMb max | 36.15 |
| eventLoopDelayMs p95 | 21.48 |
| eventLoopDelayMs max | 21.48 |

## ed25519_local_presign_refill_smoke

- Description: Threshold Ed25519 local presign refill smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_refill --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 45.25
- Signing duration (ms): 16.60
- Total attempts: 6
- Total success: 6
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 361.45
- Presign mode: presign_refill
- Presign accepted during measured run: 12
- Presign rejected during measured run: 0
- Presign pool hits: 0

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 5.88 | 21.27 | 21.27 | 12.33 | 21.27 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 6 | 6.05 | 12.23 | 12.23 | 7.12 | 12.23 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 5.88 | 21.27 | 21.27 | 12.33 | 21.27 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/presign/refill` | 6 | 5.20 | 11.40 | 11.40 | 6.11 | 11.40 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 32.54 |
| cpuSystemMsTotal | 1.46 |
| rssMb p95 | 174.50 |
| rssMb max | 174.50 |
| heapUsedMb p95 | 31.41 |
| heapUsedMb max | 31.41 |
| eventLoopDelayMs p95 | 0.00 |
| eventLoopDelayMs max | 0.00 |

## ed25519_local_presign_double_consume_smoke

- Description: Threshold Ed25519 local presign serverless double-consume pressure smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_presign_double_consume --wallets 4 --signs-per-wallet 1 --max-concurrency 4 --profile steady`
- Profile: steady
- Wallets: 4
- Signs per wallet: 1
- Max concurrency: 4
- Bootstrap duration (ms): 39.87
- Signing duration (ms): 36.38
- Total attempts: 4
- Total success: 4
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 109.95
- Presign mode: presign_double_consume
- Presign accepted during measured run: 0
- Presign rejected during measured run: 0
- Presign pool hits: 4

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 4 | 18.35 | 22.19 | 22.19 | 19.18 | 22.19 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 4 | 30.35 | 34.41 | 34.41 | 31.16 | 34.41 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 4 | 18.35 | 22.19 | 22.19 | 19.18 | 22.19 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/presign/refill` | 4 | 8.69 | 14.51 | 14.51 | 9.55 | 14.51 |
| `/threshold-ed25519/sign/finalize-and-dispatch` | 8 | 14.50 | 21.44 | 21.44 | 16.32 | 21.44 |

#### Presign Double-Consume Rejection Codes

| Value | Count |
|---|---:|
| `budget_operation_conflict` | 4 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 71.36 |
| cpuSystemMsTotal | 5.08 |
| rssMb p95 | 184.38 |
| rssMb max | 184.38 |
| heapUsedMb p95 | 29.41 |
| heapUsedMb max | 29.41 |
| eventLoopDelayMs p95 | 0.00 |
| eventLoopDelayMs max | 0.00 |

## Notes

- Current coverage is threshold-ed25519 warm-session local 2-party only.
- The actor provisions canonical single-key material directly, then measures the kept warm signing and presign paths.
- ECDSA, multi-node routing, backend comparison, and relayer-cosigner topologies remain follow-on work.
