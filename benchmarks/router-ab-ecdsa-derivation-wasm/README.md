# Router A/B ECDSA derivation WASM benchmarks

This module benchmarks the Router A/B ECDSA derivation lifecycle through the
client-only derivation WASM and the server signing-worker WASM boundaries.

Scope:

- canonical derivation
- additive-share derivation
- bootstrap
- non-export sign
- explicit export

Runtime:

- Node-hosted wasm using the web-target
  `wasm/router_ab_ecdsa_signing_worker/pkg`
- intended as a Cloudflare-worker-adjacent benchmark, not a full worker
  deployment benchmark

Run:

```bash
pnpm benchmark:router-ab-ecdsa-derivation:wasm
```

Outputs:

- `benchmarks/router-ab-ecdsa-derivation-wasm/out/<timestamp>/raw-summary.json`
- `benchmarks/router-ab-ecdsa-derivation-wasm/out/<timestamp>/summary.md`
