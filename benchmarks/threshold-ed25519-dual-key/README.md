# Threshold Ed25519 Dual-Key Benchmarks

This module records the current performance profile for the NEAR dual-key Ed25519 bootstrap and recovery-export flow.

## Quick Start

```bash
pnpm benchmark:threshold-ed25519
pnpm benchmark:threshold-ed25519:browser
```

The runner writes:

- `benchmarks/threshold-ed25519-dual-key/out/<timestamp>/raw-summary.json`
- `benchmarks/threshold-ed25519-dual-key/out/<timestamp>/summary.md`
- `benchmarks/threshold-ed25519-dual-key/out/<timestamp>/browser-summary.json`
- `benchmarks/threshold-ed25519-dual-key/out/<timestamp>/browser-summary.md`

It also syncs the latest summary to:

- `docs/benchmarks/threshold-ed25519-dual-key.md`

## What It Measures

- operational threshold enrollment baseline
  - client verifying-share derivation
  - relay deterministic keygen from `master_secret + clientVerifyingShare`
- dual-key registration bootstrap
  - recovery-share preflight
  - client dual-key bootstrap package derivation
- recovery export
  - Paillier keygen
  - Paillier encrypt / add-constant / decrypt
  - request / response payload sizes
- desktop browser runtime deltas in Chromium and WebKit using a static `/sdk/dist` host

## Real Device Runs

The current runner executes:

- node on the local machine
- desktop Chromium
- desktop WebKit

It does not drive physical mobile hardware from this workspace.

Real release-target measurements must be collected on actual target devices and then appended to:

- `docs/benchmarks/threshold-ed25519-dual-key.md`

Do not label desktop Playwright or device-profile emulation runs as real-device data.

## Options

- `--registration-iterations <n>`
- `--paillier-iterations <n>`
- `--out-dir <path>`
- `--docs-output <path>`
- `--skip-doc-sync`
