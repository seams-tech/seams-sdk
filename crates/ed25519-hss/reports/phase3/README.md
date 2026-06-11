# Phase 3 DDH Hidden-Eval Reports

Saved release-mode DDH hidden-eval benchmark reports for the current prime-order
prototype live here.

Current report:

- [`ddh-hidden-eval-native-release.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/reports/phase3/ddh-hidden-eval-native-release.json)
  - native release benchmark collected from
    [`benchmark_ddh_hidden_eval.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/bin/benchmark_ddh_hidden_eval.rs)
  - fixture: `wraparound-seed`
  - artifact: `138,256` bytes
  - prepare duration: `~112.9 ms`
  - direct hidden-eval executor mean: `~224.2 ms`
  - same-process delivery path mean: `~264.2 ms`
  - dominant stage: round core at `~134.9 ms`
  - message schedule mean: `~40.4 ms`
  - output projector mean: `~42.9 ms`
  - substage split: schedule accumulation `~28.9 ms`, `new_a_bits`
    `~32.6 ms`, `new_e_bits` `~32.8 ms`, `maj` `~26.6 ms`, `ch`
    `~21.9 ms`
- [`browser-ddh-hidden-eval-chrome.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/reports/phase3/browser-ddh-hidden-eval-chrome.json)
  - browser benchmark report collected through
    [`collect_browser_cache_benchmark.mjs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/scripts/collect_browser_cache_benchmark.mjs)
  - current headless Chrome direct hidden-eval snapshot:
    - prepare duration: `~220.1 ms`
    - total hidden eval mean: `~203.6 ms`
    - total hidden eval median: `~203.5 ms`
    - total hidden eval p95: `~205.4 ms`
    - input sharing mean: `~11.3 ms`
    - add stage mean: `~2.3 ms`
    - message schedule mean: `~30.7 ms`
    - round core mean: `~123.7 ms`
    - output projector mean: `~35.4 ms`
    - substage split: schedule accumulation `~25.7 ms`, `sigma1` `~5.9 ms`,
      `ch` `~21.8 ms`, `temp1` `~7.1 ms`, `temp2` `~2.7 ms`
    - pressure counters: message schedule local/core materializations
      `26,624` / `16,384`, round-core local materializations `103,424`,
      output-projector local materializations `2,048`, `Ch`/`Maj`
      multiplication paths `5,120` each, sigma0/sigma1 local materializations
      `10,240` each, `state3`/`temp1`/`temp2` B2A paths
      `5,120` / `25,600` / `10,240`, `new_a_bits`/`new_e_bits` A2B paths
      `5,120` each
  - reference match: `true`
  - note: this report uses the crate-local `browser-benchmark` wasm shim and
    measures the direct hidden-eval executor path. Product registration smoke
    is a separate cross-crate check.

Ignored DDH conformance lane:

- all `4` ignored Phase 3b DDH tests now pass
- full five-fixture hidden-eval milestone run currently takes about `334.90 s`
  in the debug lane

Reproduce:

```bash
cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --output crates/ed25519-hss/reports/phase3/ddh-hidden-eval-native-release.json
wasm-pack build crates/ed25519-hss --target web --out-dir web/generated/pkg --release --no-typescript --features browser-benchmark
cargo run --manifest-path crates/ed25519-hss/Cargo.toml --bin emit_browser_cache_benchmark_bundle -- --output-dir crates/ed25519-hss/web/generated
python3 -m http.server 8765 -d crates/ed25519-hss/web
node crates/ed25519-hss/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/ed25519-hss/reports/phase3/browser-ddh-hidden-eval-chrome.json
```
