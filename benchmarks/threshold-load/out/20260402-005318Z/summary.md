# Threshold Load Report

Generated: 2026-04-02T00:53:19.641Z
Run ID: `20260402-005318Z`

## Scenario Summary

| Scenario | Description | Status | Success Rate | Signs/sec | Sign p95 (ms) |
|---|---|---|---:|---:|---:|
| `ed25519_local_steady_smoke` | Threshold Ed25519 local warm-session steady-state smoke profile | ok | 100.0% | 257.35 | 17.98 |
| `ed25519_local_burst_smoke` | Threshold Ed25519 local warm-session synchronized burst smoke profile | ok | 100.0% | 217.98 | 33.73 |

## ed25519_local_steady_smoke

- Description: Threshold Ed25519 local warm-session steady-state smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 40.28
- Signing duration (ms): 46.63
- Total attempts: 12
- Total success: 12
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 257.35

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 3.30 | 17.91 | 17.91 | 9.37 | 17.91 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 12 | 9.62 | 17.98 | 17.98 | 10.89 | 17.98 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 3.30 | 17.91 | 17.91 | 9.37 | 17.91 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 12 | 3.42 | 8.98 | 8.98 | 4.03 | 8.98 |
| `/threshold-ed25519/sign/finalize` | 12 | 2.79 | 4.63 | 4.63 | 2.89 | 4.63 |
| `/threshold-ed25519/sign/init` | 12 | 2.34 | 5.38 | 5.38 | 2.64 | 5.38 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 68.42 |
| cpuSystemMsTotal | 2.17 |
| rssMb p95 | 193.20 |
| rssMb max | 193.20 |
| heapUsedMb p95 | 43.32 |
| heapUsedMb max | 43.32 |
| eventLoopDelayMs p95 | 20.63 |
| eventLoopDelayMs max | 20.63 |

## ed25519_local_burst_smoke

- Description: Threshold Ed25519 local warm-session synchronized burst smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 8 --signs-per-wallet 1 --max-concurrency 8 --profile burst`
- Profile: burst
- Wallets: 8
- Signs per wallet: 1
- Max concurrency: 8
- Bootstrap duration (ms): 45.15
- Signing duration (ms): 36.70
- Total attempts: 8
- Total success: 8
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 217.98

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 8 | 21.14 | 23.10 | 23.10 | 21.79 | 23.10 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 8 | 28.49 | 33.73 | 33.73 | 28.14 | 33.73 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 8 | 21.14 | 23.10 | 23.10 | 21.79 | 23.10 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 8 | 9.92 | 14.40 | 14.40 | 10.46 | 14.40 |
| `/threshold-ed25519/sign/finalize` | 8 | 4.04 | 6.25 | 6.25 | 4.05 | 6.25 |
| `/threshold-ed25519/sign/init` | 8 | 11.67 | 20.74 | 20.74 | 12.16 | 20.74 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 67.23 |
| cpuSystemMsTotal | 2.63 |
| rssMb p95 | 213.94 |
| rssMb max | 213.94 |
| heapUsedMb p95 | 34.93 |
| heapUsedMb max | 34.93 |
| eventLoopDelayMs p95 | 0.00 |
| eventLoopDelayMs max | 0.00 |

## Notes

- Current coverage is threshold-ed25519 warm-session local 2-party only.
- The actor provisions canonical single-key material directly, then measures the kept warm signing path.
- ECDSA, multi-node routing, backend comparison, and relayer-cosigner topologies remain follow-on work.
