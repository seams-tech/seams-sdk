# Threshold Load Harness

This module runs actor-based threshold load scenarios against the active path.

Current scope:

- threshold-ed25519 warm-session local 2-party signing
- threshold-ed25519 presign pool hit, depleted-pool fallback, refill,
  refill-pressure, concurrent-finalize, and duplicate-consume pressure smoke paths
- named smoke, medium, and scale scenario groups for the active local path
- real relay routes:
  - `/threshold-ed25519/session`
  - `/threshold-ed25519/authorize`
  - `/threshold-ed25519/sign/init`
  - `/threshold-ed25519/sign/finalize`
  - `/threshold-ed25519/presign/refill`
  - `/threshold-ed25519/sign/finalize-and-dispatch`
- machine-readable and markdown summaries per run

Current non-goals:

- ECDSA actor coverage
- multi-node routing scenarios
- relayer-cosigner Ed25519 topologies
- registration HSS bootstrap benchmarking

The current actor provisions canonical single-key threshold-ed25519 material directly, then
measures the warm touchless signing path with cached `xClientBaseB64u`.

## Quick Start

Run the default smoke scenarios:

```bash
pnpm benchmark:threshold-load
```

Run the CI smoke subset without syncing docs:

```bash
pnpm benchmark:threshold-load:ci
```

Run the first multi-wallet medium profiles:

```bash
pnpm benchmark:threshold-load:medium
```

Run one specific scenario:

```bash
pnpm benchmark:threshold-load --scenario ed25519_local_steady_smoke
```

## Scenario Command Variables

Each scenario supports an override environment variable.

- `BENCH_CMD_ED25519_LOCAL_STEADY_SMOKE`
- `BENCH_CMD_ED25519_LOCAL_BURST_SMOKE`
- `BENCH_CMD_ED25519_LOCAL_PRESIGN_POOL_HIT_SMOKE`
- `BENCH_CMD_ED25519_LOCAL_PRESIGN_POOL_MISS_SMOKE`
- `BENCH_CMD_ED25519_LOCAL_PRESIGN_REFILL_SMOKE`
- `BENCH_CMD_ED25519_LOCAL_PRESIGN_REFILL_PRESSURE_SMOKE`
- `BENCH_CMD_ED25519_LOCAL_PRESIGN_CONCURRENT_FINALIZE_SMOKE`
- `BENCH_CMD_ED25519_LOCAL_PRESIGN_DOUBLE_CONSUME_SMOKE`
- `BENCH_CMD_ED25519_LOCAL_STEADY_50`
- `BENCH_CMD_ED25519_LOCAL_BURST_50`
- `BENCH_CMD_ED25519_LOCAL_STEADY_100`
- `BENCH_CMD_ED25519_LOCAL_BURST_100`
- `BENCH_CMD_ED25519_LOCAL_STEADY_250`
- `BENCH_CMD_ED25519_LOCAL_BURST_250`
- `BENCH_CMD_ED25519_LOCAL_STEADY_500`
- `BENCH_CMD_ED25519_LOCAL_BURST_500`

Example:

```bash
export BENCH_CMD_ED25519_LOCAL_STEADY_SMOKE="pnpm exec tsx --tsconfig ./client/tsconfig.json ./benchmarks/threshold-load/src/scenario-harness.ts --scenario ed25519_local_steady --wallets 12 --signs-per-wallet 3 --max-concurrency 6 --profile steady"
pnpm benchmark:threshold-load --scenario ed25519_local_steady_smoke
```

## Output

Per run, the runner writes:

- `benchmarks/threshold-load/out/<timestamp>/raw-summary.json`
- `benchmarks/threshold-load/out/<timestamp>/summary.md`
- `benchmarks/threshold-load/out/<timestamp>/<scenario>.log`

When the run succeeds, it also syncs the latest summary to:

- `docs/benchmarks/threshold-load.md`

## Notes

- The scenario harness runs with `pnpm exec tsx` so it can import the current server source
  directly instead of depending on a generated `sdk/dist` build.
- The current Ed25519 actor is intentionally honest: it measures warm active-path signing, not the
  registration bootstrap path.
- Scenario groups are selected with `--group smoke`, `--group medium`, or `--group scale`.
