# Router A/B Threshold-PRF WASM Benchmark Summary

- Run ID: `2026-06-17T08-47-53-975Z`
- Runtime: Node-hosted `wasm/threshold_prf`
- Scope: selected `mpc_threshold_prf_v1` proof-bundle generation and verified combine
- Warmup / iterations: 3 / 12

| Path | Median | p95 | Mean | Min | Max | Output bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `router_ab_mpc_threshold_prf_two_proofs_wasm` | `0.672 ms` | `0.807 ms` | `0.695 ms` | `0.661 ms` | `0.807 ms` | `328` |
| `router_ab_mpc_threshold_prf_verified_combine_wasm` | `0.854 ms` | `0.926 ms` | `0.862 ms` | `0.825 ms` | `0.926 ms` | `32` |
| `router_ab_mpc_threshold_prf_two_proofs_plus_combine_wasm` | `1.454 ms` | `1.799 ms` | `1.48 ms` | `1.394 ms` | `1.799 ms` | `32` |

Notes:
- Proof generation uses secure randomness from the WASM `getrandom` path.
- The benchmark excludes HPKE, JSON, HTTP, Service Binding, and Cloudflare runtime latency.
