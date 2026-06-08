# Ed25519 HSS WASM Benchmarks

This benchmark measures the Ed25519 HSS registration artifact path through the
WASM exports used by the SDK.

Scope:

- deterministic client and server HSS input setup
- role-separated server input delivery
- client-owned staged evaluator artifact construction
- internal hidden-eval timing buckets exposed by `hss_client_signer`

Runtime:

- Node-hosted WASM for repeatable local comparisons
- optional Chromium-hosted WASM for browser-adjacent measurements

Run:

```bash
pnpm benchmark:ed25519-hss:wasm
```

Useful options:

```bash
node ./benchmarks/ed25519-hss-wasm/src/runner.mjs --iterations 12 --browser-iterations 8
node ./benchmarks/ed25519-hss-wasm/src/runner.mjs --skip-browser
```

Outputs:

- `benchmarks/ed25519-hss-wasm/out/<timestamp>/raw-summary.json`
- `benchmarks/ed25519-hss-wasm/out/<timestamp>/summary.md`
