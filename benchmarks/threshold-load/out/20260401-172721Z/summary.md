# Threshold Load Report

Generated: 2026-04-01T17:27:22.623Z
Run ID: `20260401-172721Z`

## Scenario Summary

| Scenario | Description | Status | Success Rate | Signs/sec | Sign p95 (ms) |
|---|---|---|---:|---:|---:|
| `ed25519_local_steady_smoke` | Threshold Ed25519 local warm-session steady-state smoke profile | ok | 100.0% | 249.95 | 18.31 |

## ed25519_local_steady_smoke

- Description: Threshold Ed25519 local warm-session steady-state smoke profile
- Status: ok
- Command: `pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Profile: steady
- Wallets: 6
- Signs per wallet: 2
- Max concurrency: 3
- Bootstrap duration (ms): 42.75
- Signing duration (ms): 48.01
- Total attempts: 12
- Total success: 12
- Total failure: 0
- Success rate: 100.0%
- Throughput (signs/sec): 249.95

#### Bootstrap Session Mint

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| Bootstrap Session Mint | 6 | 3.55 | 20.26 | 20.26 | 10.59 | 20.26 |

#### End-to-End Sign

| Metric | Count | p50 | p95 | p99 | Mean | Max |
|---|---:|---:|---:|---:|---:|---:|
| End-to-End Sign | 12 | 9.44 | 18.31 | 18.31 | 10.99 | 18.31 |

### Bootstrap Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/session` | 6 | 3.55 | 20.26 | 20.26 | 10.59 | 20.26 |

### Signing Routes

| Route | Count | p50 (ms) | p95 (ms) | p99 (ms) | Mean (ms) | Max (ms) |
|---|---:|---:|---:|---:|---:|---:|
| `/threshold-ed25519/authorize` | 12 | 2.61 | 9.35 | 9.35 | 3.44 | 9.35 |
| `/threshold-ed25519/sign/finalize` | 12 | 3.18 | 5.10 | 5.10 | 3.32 | 5.10 |
| `/threshold-ed25519/sign/init` | 12 | 2.60 | 5.42 | 5.42 | 2.90 | 5.42 |

### System

| Metric | Value |
|---|---:|
| cpuUserMsTotal | 71.28 |
| cpuSystemMsTotal | 3.12 |
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
