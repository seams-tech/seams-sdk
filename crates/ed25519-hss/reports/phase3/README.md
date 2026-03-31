# Phase 3 DDH Hidden-Eval Reports

Saved release-mode DDH hidden-eval benchmark reports for the current prime-order
prototype live here.

Current report:

- [`ddh-hidden-eval-native-release.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/reports/phase3/ddh-hidden-eval-native-release.json)
  - native release benchmark collected from
    [`benchmark_ddh_hidden_eval.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/bin/benchmark_ddh_hidden_eval.rs)
  - fixture: `wraparound-seed`
  - artifact: `138,256` bytes
  - prepare duration: `~86.4 ms`
  - total hidden eval mean: `~0.551 s`
  - dominant stage: round core at `~307.1 ms`
  - message schedule mean: `~91.9 ms`
  - output projector mean: `~87.7 ms`
  - substage split: schedule accumulation `~79.4 ms`, `temp1` `~132.2 ms`,
    `temp2` `~32.8 ms`
- [`browser-ddh-hidden-eval-chrome.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/reports/phase3/browser-ddh-hidden-eval-chrome.json)
  - first browser benchmark report collected through
    [`collect_browser_cache_benchmark.mjs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/scripts/collect_browser_cache_benchmark.mjs)
  - current desktop Chrome baseline:
    - prepare duration: `~148.5 ms`
    - total hidden eval mean: `~0.774 s`
    - input sharing mean: `~10.7 ms`
    - add stage mean: `~3.7 ms`
    - message schedule mean: `~122.0 ms`
    - round core mean: `~406.5 ms`
    - output projector mean: `~118.4 ms`
    - substage split: schedule accumulation `~106.1 ms`, `temp1` `~175.8 ms`,
      `temp2` `~43.5 ms`
  - reference match: `true`
  - browser/native total ratio on this host: `~1.40x`
  - note: browser total now reflects the packetized delivery-path wall clock,
    while stage timings remain hidden-evaluator stage probes

Ignored DDH conformance lane:

- all `4` ignored Phase 3b DDH tests now pass
- full five-fixture hidden-eval milestone run currently takes about `334.90 s`
  in the debug lane

Reproduce:

```bash
cargo run --release --manifest-path crates/ed25519-hss/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-iterations 5000 --samples 3 --stage-iterations 1 --json --output crates/ed25519-hss/reports/phase3/ddh-hidden-eval-native-release.json
wasm-pack build crates/ed25519-hss --target web --out-dir web/generated/pkg --release --no-typescript
cargo run --manifest-path crates/ed25519-hss/Cargo.toml --bin emit_browser_cache_benchmark_bundle -- --output-dir crates/ed25519-hss/web/generated
python3 -m http.server 8765 -d crates/ed25519-hss/web
node crates/ed25519-hss/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/ed25519-hss/reports/phase3/browser-ddh-hidden-eval-chrome.json
```
