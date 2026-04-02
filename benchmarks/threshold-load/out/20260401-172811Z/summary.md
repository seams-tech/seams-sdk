# Threshold Load Report

Generated: 2026-04-01T17:28:12.332Z
Run ID: `20260401-172811Z`

## Scenario Summary

| Scenario | Description | Status | Success Rate | Signs/sec | Sign p95 (ms) |
|---|---|---|---:|---:|---:|
| `ed25519_local_steady_smoke` | Threshold Ed25519 local warm-session steady-state smoke profile | ok | 100.0% | 260.70 | 17.93 |
| `ed25519_local_burst_smoke` | Threshold Ed25519 local warm-session synchronized burst smoke profile | ok | 100.0% | 236.48 | 30.93 |

## ed25519_local_steady_smoke

- Description: Threshold Ed25519 local warm-session steady-state smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 39.43
- Signing duration (ms): 46.03
- Total attempts: 12
- Total success: 12
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 260.70

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 3.23 | 17.96 | 17.96 | 9.35 | 17.96 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 12 | 9.41 | 17.93 | 17.93 | 10.74 | 17.93 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 3.23 | 17.96 | 17.96 | 9.35 | 17.96 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 12 | 3.36 | 8.98 | 8.98 | 3.97 | 8.98 |
| `/threshold-ed25519/sign/finalize` | 12 | 2.71 | 4.62 | 4.62 | 2.85 | 4.62 |
| `/threshold-ed25519/sign/init` | 12 | 2.30 | 5.36 | 5.36 | 2.62 | 5.36 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 67.98 |
| cpuSystemMsTotal | 2.11 |
| rssMb p95 | 193.94 |
| rssMb max | 193.94 |
| heapUsedMb p95 | 43.65 |
| heapUsedMb max | 43.65 |
| eventLoopDelayMs p95 | 20.73 |
| eventLoopDelayMs max | 20.73 |

## ed25519_local_burst_smoke

- Description: Threshold Ed25519 local warm-session synchronized burst smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 8 --signs-per-wallet 1 --max-concurrency 8 --profile burst`
- Profile: burst
- Wallets: 8
- Signs per wallet: 1
- Max concurrency: 8
- Bootstrap duration (ms): 48.72
- Signing duration (ms): 33.83
- Total attempts: 8
- Total success: 8
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 236.48

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 8 | 21.73 | 23.20 | 23.20 | 21.76 | 23.20 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 8 | 25.41 | 30.93 | 30.93 | 26.32 | 30.93 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 8 | 21.73 | 23.20 | 23.20 | 21.76 | 23.20 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 8 | 7.48 | 10.07 | 10.07 | 7.87 | 10.07 |
| `/threshold-ed25519/sign/finalize` | 8 | 4.02 | 8.64 | 8.64 | 5.15 | 8.64 |
| `/threshold-ed25519/sign/init` | 8 | 9.22 | 19.77 | 19.77 | 11.84 | 19.77 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 60.36 |
| cpuSystemMsTotal | 1.93 |
| rssMb p95 | 213.17 |
| rssMb max | 213.17 |
| heapUsedMb p95 | 35.19 |
| heapUsedMb max | 35.19 |
| eventLoopDelayMs p95 | 0.00 |
| eventLoopDelayMs max | 0.00 |

## Notes

- Current coverage is threshold-ed25519 warm-session local 2-party only.
- The actor provisions canonical single-key material directly, then measures the kept warm signing path.
- ECDSA, multi-node routing, backend comparison, and relayer-cosigner topologies remain follow-on work.
