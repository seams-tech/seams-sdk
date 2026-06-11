# Registration Flow Benchmark

Runs browser-backed wallet registration scenarios and extracts the SDK timing
summary emitted by `client/src/SeamsWeb/operations/registration/registration.ts`.

The benchmark uses Playwright, WebAuthn mocks, IndexedDB, workers, and the local
managed-registration relay harness. It is intended for registration latency
work, while `benchmarks/threshold-load` remains the warm signing benchmark.

`/sdk/esm/*` is served from the SDK build output in the Playwright environment.
The full and smoke scripts run `pnpm -C sdk run build:prepare` before launching
the browser so timing instrumentation matches the current source tree.

## Commands

```bash
pnpm benchmark:registration-flow:smoke
pnpm benchmark:registration-flow -- --scenario passkey_ed25519_only_wallet_iframe
pnpm benchmark:registration-flow -- --scenario passkey_ed25519_only_wallet_iframe_activation
pnpm benchmark:registration-flow:report-only -- --scenario passkey_ed25519_only_wallet_iframe
```

For a quick local probe, override a scenario command with fewer runs:

```bash
BENCH_CMD_REGISTRATION_PASSKEY_ED25519_ONLY_WALLET_IFRAME='BENCH_REGISTRATION_SCENARIO=passkey_ed25519_only_wallet_iframe BENCH_REGISTRATION_RUNS=1 pnpm -C tests exec playwright test -c ../benchmarks/registration-flow/playwright.config.ts --project=chromium --reporter=line' pnpm benchmark:registration-flow -- --scenario passkey_ed25519_only_wallet_iframe --skip-doc-sync
```

Use `benchmark:registration-flow:report-only` only when the SDK build has
already been prepared.

## Output

Each run writes:

```text
benchmarks/registration-flow/out/<timestamp>/
  raw-summary.json
  summary.md
  <scenario>.log
```

The markdown summary is also synced to
`docs/benchmarks/registration-flow.md` unless `--skip-doc-sync` is passed.
