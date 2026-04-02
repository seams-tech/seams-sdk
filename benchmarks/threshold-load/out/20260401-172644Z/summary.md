# Threshold Load Report

Generated: 2026-04-01T17:26:44.618Z
Run ID: `20260401-172644Z`

## Scenario Summary

| Scenario | Description | Status | Success Rate | Signs/sec | Sign p95 (ms) |
|---|---|---|---:|---:|---:|
| `ed25519_local_steady_smoke` | Threshold Ed25519 local warm-session steady-state smoke profile | error | n/a | n/a | n/a |

## ed25519_local_steady_smoke

- Description: Threshold Ed25519 local warm-session steady-state smoke profile
- Status: error
- Command: `pnpm exec tsx ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 6 --signs-per-wallet 2 --max-concurrency 3 --profile steady`
- Error: Scenario command exited with code 1

## Notes

- Current coverage is threshold-ed25519 warm-session local 2-party only.
- The actor provisions canonical single-key material directly, then measures the kept warm signing path.
- ECDSA, multi-node routing, backend comparison, and relayer-cosigner topologies remain follow-on work.
