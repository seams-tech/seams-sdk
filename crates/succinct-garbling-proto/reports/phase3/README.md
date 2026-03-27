# Phase 3 DDH Hidden-Eval Reports

Saved release-mode DDH hidden-eval benchmark reports for the current prime-order
prototype live here.

Current report:

- [`ddh-hidden-eval-native-release.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3/ddh-hidden-eval-native-release.json)
  - native release benchmark collected from
    [`benchmark_ddh_hidden_eval.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/src/bin/benchmark_ddh_hidden_eval.rs)
  - fixture: `wraparound-seed`
  - artifact: `138,256` bytes
  - prepare duration: `~111.2 ms`
  - total hidden eval mean: `~1.28 s`
  - dominant stage: round core at `~528.3 ms`
  - message schedule mean: `~169.7 ms`
  - output projector mean: `~120.3 ms`
  - substage split: schedule accumulation `~138.8 ms`, `temp1` `~228.1 ms`,
    `temp2` `~56.8 ms`
- [`browser-ddh-hidden-eval-chrome.json`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/reports/phase3/browser-ddh-hidden-eval-chrome.json)
  - first browser benchmark report collected through
    [`collect_browser_cache_benchmark.mjs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/succinct-garbling-proto/scripts/collect_browser_cache_benchmark.mjs)
  - current desktop Chrome baseline:
    - prepare duration: `~222.0 ms`
    - total hidden eval mean: `~1.70 s`
    - input sharing mean: `~150.6 ms`
    - add stage mean: `~31.7 ms`
    - message schedule mean: `~183.6 ms`
    - round core mean: `~590.2 ms`
    - output projector mean: `~139.9 ms`
    - substage split: schedule accumulation `~153.2 ms`, `temp1` `~256.1 ms`,
      `temp2` `~62.9 ms`
  - reference match: `true`
  - browser/native total ratio on this host: `~1.33x`
  - note: browser total now reflects the packetized delivery-path wall clock,
    while stage timings remain hidden-evaluator stage probes

Ignored DDH conformance lane:

- all `4` ignored Phase 3b DDH tests now pass
- full five-fixture hidden-eval milestone run currently takes about `334.90 s`
  in the debug lane

Reproduce:

```bash
cargo run --release --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin benchmark_ddh_hidden_eval -- --primitive-iterations 5000 --samples 3 --stage-iterations 1 --json --output crates/succinct-garbling-proto/reports/phase3/ddh-hidden-eval-native-release.json
wasm-pack build crates/succinct-garbling-proto --target web --out-dir web/generated/pkg --release --no-typescript
cargo run --manifest-path crates/succinct-garbling-proto/Cargo.toml --bin emit_browser_cache_benchmark_bundle -- --output-dir crates/succinct-garbling-proto/web/generated
python3 -m http.server 8765 -d crates/succinct-garbling-proto/web
node crates/succinct-garbling-proto/scripts/collect_browser_cache_benchmark.mjs --debug-port 57514 --server-origin http://127.0.0.1:8765 --bundle-path generated/bundle.json --output crates/succinct-garbling-proto/reports/phase3/browser-ddh-hidden-eval-chrome.json
```
