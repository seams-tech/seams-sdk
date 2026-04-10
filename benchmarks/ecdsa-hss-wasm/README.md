# `ecdsa-hss` WASM Benchmarks

This module benchmarks the `ecdsa-hss` reference lifecycle through the
`wasm/eth_signer` wasm boundary.

Scope:

- canonical derivation
- additive-share derivation
- bootstrap
- non-export sign
- explicit export

Runtime:

- Node-hosted wasm using the web-target `wasm/eth_signer/pkg`
- intended as a Cloudflare-worker-adjacent benchmark, not a full worker
  deployment benchmark

Run:

```bash
pnpm benchmark:ecdsa-hss:wasm
```

Outputs:

- `benchmarks/ecdsa-hss-wasm/out/<timestamp>/raw-summary.json`
- `benchmarks/ecdsa-hss-wasm/out/<timestamp>/summary.md`
