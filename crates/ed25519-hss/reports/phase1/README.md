# Phase 1 Reports

Saved native/browser CPU baseline reports for the fixed-function prime-order
executor prototype.

Files:

- `native-desktop-release.json`
  - release-mode native CPU benchmark from
    `benchmark_prime_order_cpu_executor`
- `browser-desktop-chrome-146.json`
  - headless Chrome benchmark page report collected through the browser CDP
    collector script
  - includes cache, structured decode/trace, browser wasm CPU executor, and the
    first browser WebGPU backend-shaped probe
  - the WebGPU section now includes per-subkernel timing for
    `digit_recode_v0`, `window_bucket_accumulate_v0`, `bucket_reduce_v0`, and
    `dependency_merge_normalize_v0`, plus the combined bucket-pipeline share
    and dominant subkernel label

Regenerate:

```bash
cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_prime_order_cpu_executor -- --json --output crates/ed25519-hss/reports/phase1/native-desktop-release.json
node crates/ed25519-hss/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/ed25519-hss/reports/phase1/browser-desktop-chrome-146.json
```
