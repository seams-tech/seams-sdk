# Threshold ECDSA Presign Benchmarks

This module runs and analyzes threshold ECDSA presign/sign benchmarks for refactor tracking.

## Quick Start

1. Run defaults (built-in scenario harness) or override scenario commands through environment variables.
2. Run:

```bash
pnpm benchmark:threshold-ecdsa
```

## Scenario Command Variables

Each scenario supports an override environment variable so teams can swap local/CI commands without code edits.
If unset, the benchmark runner uses the built-in scenario harness command.

- `BENCH_CMD_COLD_FIRST_SIGN_NO_POOL`
- `BENCH_CMD_WARM_SIGN_POOL_HIT`
- `BENCH_CMD_BACKGROUND_REFILL_CONTENTION`
- `BENCH_CMD_MULTI_RUNTIME_CONTENTION`
- `BENCH_CMD_STORE_BACKEND_COMPARE`
- `BENCH_CMD_REPLAY_FALLBACK_PATH`

Example:

```bash
export BENCH_CMD_COLD_FIRST_SIGN_NO_POOL="pnpm -C tests playwright test ./relayer/threshold-ecdsa.signature-harness.test.ts --reporter=line"
pnpm benchmark:threshold-ecdsa --scenario cold_first_sign_no_pool
```

## SLO Gates

The runner enforces interactive-latency gates by default and returns non-zero exit when a gate fails.

Default gates:

- `first_sign_p95_ms <= 4000` (`cold_first_sign_no_pool`)
- `warm_sign_p95_ms <= 1500` (`warm_sign_pool_hit`)
- `presign_step_p95_ms <= 900` (max across non-fallback scenarios)
- `presign_step_p99_ms <= 1300` (max across non-fallback scenarios)
- `replay_fallback_ratio_nonfallback_max <= 0.01`

Optional overrides:

- `BENCH_SLO_DISABLE=1` (disable all SLO gates)
- `BENCH_SLO_FIRST_SIGN_P95_MS`
- `BENCH_SLO_WARM_SIGN_P95_MS`
- `BENCH_SLO_PRESIGN_STEP_P95_MS`
- `BENCH_SLO_PRESIGN_STEP_P99_MS`
- `BENCH_SLO_REPLAY_FALLBACK_RATIO_MAX`

CI profile (current):

- workflow: `.github/workflows/ci.yml` (`threshold-signing-core` job)
- command: `pnpm benchmark:threshold-ecdsa`
- CI overrides:
  - `BENCH_SLO_PRESIGN_STEP_P95_MS=1400`
  - `BENCH_SLO_PRESIGN_STEP_P99_MS=2000`

## Output

Per run, the runner writes:

- `benchmarks/threshold-ecdsa-presign/out/<timestamp>/raw-summary.json`
- `benchmarks/threshold-ecdsa-presign/out/<timestamp>/summary.md`
- `benchmarks/threshold-ecdsa-presign/out/<timestamp>/<scenario>.log`

When a run succeeds, it also syncs the latest summary to:

- `docs/benchmarks/threshold-ecdsa-presign.md`

## Notes

- Commands are intentionally injected via env vars to keep this module runtime-agnostic.
- The parser is optimized for current server log patterns:
  - `[threshold-ecdsa] request { ... }`
  - `[threshold-ecdsa] response { ... }`
  - `[threshold-ecdsa] presign/step perf { ... }`
