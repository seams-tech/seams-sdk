# Threshold Load Report

Generated: 2026-04-02T00:53:35.615Z
Run ID: `20260402-005332Z`

## Scenario Summary

| Scenario | Description | Status | Success Rate | Signs/sec | Sign p95 (ms) |
|---|---|---|---:|---:|---:|
| `ed25519_local_steady_smoke` | Threshold Ed25519 local warm-session steady-state smoke profile | ok | 100.0% | 252.84 | 17.62 |
| `ed25519_local_burst_smoke` | Threshold Ed25519 local warm-session synchronized burst smoke profile | ok | 100.0% | 231.55 | 31.86 |
| `ed25519_local_steady_50` | Threshold Ed25519 local warm-session medium steady-state profile (50 wallets) | ok | 100.0% | 348.02 | 37.61 |
| `ed25519_local_burst_50` | Threshold Ed25519 local warm-session medium burst profile (50 wallets) | ok | 100.0% | 328.77 | 147.80 |

## ed25519_local_steady_smoke

- Description: Threshold Ed25519 local warm-session steady-state smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 39.84
- Signing duration (ms): 47.46
- Total attempts: 12
- Total success: 12
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 252.84

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 3.30 | 18.12 | 18.12 | 9.45 | 18.12 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 12 | 9.42 | 17.62 | 17.62 | 11.18 | 17.62 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 3.30 | 18.12 | 18.12 | 9.45 | 18.12 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 12 | 3.50 | 9.04 | 9.04 | 4.34 | 9.04 |
| `/threshold-ed25519/sign/finalize` | 12 | 2.80 | 4.64 | 4.64 | 2.91 | 4.64 |
| `/threshold-ed25519/sign/init` | 12 | 2.15 | 5.14 | 5.14 | 2.61 | 5.14 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 71.17 |
| cpuSystemMsTotal | 3.23 |
| rssMb p95 | 196.33 |
| rssMb max | 196.33 |
| heapUsedMb p95 | 36.11 |
| heapUsedMb max | 36.11 |
| eventLoopDelayMs p95 | 20.15 |
| eventLoopDelayMs max | 20.15 |

## ed25519_local_burst_smoke

- Description: Threshold Ed25519 local warm-session synchronized burst smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 8 --signs-per-wallet 1 --max-concurrency 8 --profile burst`
- Profile: burst
- Wallets: 8
- Signs per wallet: 1
- Max concurrency: 8
- Bootstrap duration (ms): 50.73
- Signing duration (ms): 34.55
- Total attempts: 8
- Total success: 8
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 231.55

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 8 | 21.70 | 24.74 | 24.74 | 22.28 | 24.74 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 8 | 25.29 | 31.86 | 31.86 | 26.19 | 31.86 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 8 | 21.70 | 24.74 | 24.74 | 22.28 | 24.74 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 8 | 8.23 | 10.82 | 10.82 | 8.53 | 10.82 |
| `/threshold-ed25519/sign/finalize` | 8 | 4.04 | 6.22 | 6.22 | 3.95 | 6.22 |
| `/threshold-ed25519/sign/init` | 8 | 11.44 | 20.50 | 20.50 | 12.26 | 20.50 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 56.95 |
| cpuSystemMsTotal | 2.05 |
| rssMb p95 | 209.08 |
| rssMb max | 209.08 |
| heapUsedMb p95 | 35.18 |
| heapUsedMb max | 35.18 |
| eventLoopDelayMs p95 | 0.00 |
| eventLoopDelayMs max | 0.00 |

## ed25519_local_steady_50

- Description: Threshold Ed25519 local warm-session medium steady-state profile (50 wallets)
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 50 --signs-per-wallet 2 --max-concurrency 12 --profile steady`
- Profile: steady
- Wallets: 50
- Signs per wallet: 2
- Max concurrency: 12
- Bootstrap duration (ms): 89.93
- Signing duration (ms): 287.34
- Total attempts: 100
- Total success: 100
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 348.02

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 50 | 7.35 | 38.93 | 40.60 | 13.13 | 40.60 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 100 | 33.62 | 37.61 | 50.89 | 33.41 | 57.23 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 50 | 7.35 | 38.93 | 40.60 | 13.13 | 40.60 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 100 | 9.64 | 13.09 | 13.68 | 9.73 | 14.42 |
| `/threshold-ed25519/sign/finalize` | 100 | 11.66 | 14.35 | 14.71 | 11.29 | 15.44 |
| `/threshold-ed25519/sign/init` | 100 | 10.58 | 16.66 | 31.02 | 11.34 | 37.52 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 326.47 |
| cpuSystemMsTotal | 10.20 |
| rssMb p95 | 227.53 |
| rssMb max | 227.53 |
| heapUsedMb p95 | 49.20 |
| heapUsedMb max | 49.20 |
| eventLoopDelayMs p95 | 24.92 |
| eventLoopDelayMs max | 24.92 |

## ed25519_local_burst_50

- Description: Threshold Ed25519 local warm-session medium burst profile (50 wallets)
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 50 --signs-per-wallet 1 --max-concurrency 25 --profile burst`
- Profile: burst
- Wallets: 50
- Signs per wallet: 1
- Max concurrency: 25
- Bootstrap duration (ms): 95.57
- Signing duration (ms): 152.08
- Total attempts: 50
- Total success: 50
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 328.77

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 50 | 16.87 | 57.59 | 60.50 | 28.04 | 60.50 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 50 | 95.34 | 147.80 | 148.78 | 93.84 | 148.78 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 50 | 16.87 | 57.59 | 60.50 | 28.04 | 60.50 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 50 | 20.05 | 87.02 | 92.65 | 36.76 | 92.65 |
| `/threshold-ed25519/sign/finalize` | 50 | 6.53 | 8.24 | 8.59 | 6.19 | 8.59 |
| `/threshold-ed25519/sign/init` | 50 | 7.52 | 125.01 | 128.55 | 49.81 | 128.55 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 180.47 |
| cpuSystemMsTotal | 6.01 |
| rssMb p95 | 226.19 |
| rssMb max | 226.19 |
| heapUsedMb p95 | 44.00 |
| heapUsedMb max | 44.00 |
| eventLoopDelayMs p95 | 22.20 |
| eventLoopDelayMs max | 22.20 |

## Notes

- Current coverage is threshold-ed25519 warm-session local 2-party only.
- The actor provisions canonical single-key material directly, then measures the kept warm signing path.
- ECDSA, multi-node routing, backend comparison, and relayer-cosigner topologies remain follow-on work.
