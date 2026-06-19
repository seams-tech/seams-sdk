# Router A/B Threshold-PRF WASM Benchmarks

This benchmark measures the selected Router A/B derivation candidate's
threshold-PRF proof-bundle boundary through the `wasm/threshold_prf` package.

```sh
pnpm benchmark:router-ab-threshold-prf:wasm
```

Outputs are written under:

- `benchmarks/router-ab-threshold-prf-wasm/out/<timestamp>/raw-summary.json`
- `benchmarks/router-ab-threshold-prf-wasm/out/<timestamp>/summary.md`
