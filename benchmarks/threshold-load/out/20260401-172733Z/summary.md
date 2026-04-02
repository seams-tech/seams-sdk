# Threshold Load Report

Generated: 2026-04-01T17:27:34.738Z
Run ID: `20260401-172733Z`

## Scenario Summary

| Scenario | Description | Status | Success Rate | Signs/sec | Sign p95 (ms) |
|---|---|---|---:|---:|---:|
| `ed25519_local_steady_smoke` | Threshold Ed25519 local warm-session steady-state smoke profile | ok | 100.0% | 259.52 | 18.04 |
| `ed25519_local_burst_smoke` | Threshold Ed25519 local warm-session synchronized burst smoke profile | ok | 100.0% | 221.73 | 33.14 |

## ed25519_local_steady_smoke

- Description: Threshold Ed25519 local warm-session steady-state smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 39.94
- Signing duration (ms): 46.24
- Total attempts: 12
- Total success: 12
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 259.52

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 3.30 | 18.37 | 18.37 | 9.57 | 18.37 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 12 | 9.44 | 18.04 | 18.04 | 10.77 | 18.04 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 3.30 | 18.37 | 18.37 | 9.57 | 18.37 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 12 | 2.54 | 9.05 | 9.05 | 3.38 | 9.05 |
| `/threshold-ed25519/sign/finalize` | 12 | 3.15 | 5.08 | 5.08 | 3.23 | 5.08 |
| `/threshold-ed25519/sign/init` | 12 | 2.62 | 5.38 | 5.38 | 2.85 | 5.38 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 68.25 |
| cpuSystemMsTotal | 2.40 |
| rssMb p95 | n/a |
| rssMb max | n/a |
| heapUsedMb p95 | n/a |
| heapUsedMb max | n/a |
| eventLoopDelayMs p95 | n/a |
| eventLoopDelayMs max | n/a |

## ed25519_local_burst_smoke

- Description: Threshold Ed25519 local warm-session synchronized burst smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_burst --wallets 8 --signs-per-wallet 1 --max-concurrency 8 --profile burst`
- Profile: burst
- Wallets: 8
- Signs per wallet: 1
- Max concurrency: 8
- Bootstrap duration (ms): 50.06
- Signing duration (ms): 36.08
- Total attempts: 8
- Total success: 8
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 221.73

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 8 | 22.95 | 28.54 | 28.54 | 23.83 | 28.54 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 8 | 25.84 | 33.14 | 33.14 | 27.39 | 33.14 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 8 | 22.95 | 28.54 | 28.54 | 23.83 | 28.54 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 8 | 9.51 | 13.97 | 13.97 | 10.06 | 13.97 |
| `/threshold-ed25519/sign/finalize` | 8 | 3.03 | 6.29 | 6.29 | 3.66 | 6.29 |
| `/threshold-ed25519/sign/init` | 8 | 11.23 | 20.63 | 20.63 | 12.20 | 20.63 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 65.66 |
| cpuSystemMsTotal | 2.79 |
| rssMb p95 | n/a |
| rssMb max | n/a |
| heapUsedMb p95 | n/a |
| heapUsedMb max | n/a |
| eventLoopDelayMs p95 | n/a |
| eventLoopDelayMs max | n/a |

## Notes

- Current coverage is threshold-ed25519 warm-session local 2-party only.
- The actor provisions canonical single-key material directly, then measures the kept warm signing path.
- ECDSA, multi-node routing, backend comparison, and relayer-cosigner topologies remain follow-on work.
