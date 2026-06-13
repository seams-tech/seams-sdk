default:
  @just --list

# Run the full formal-verification path for all crate-local FV tracks.
fv:
  just ed25519-hss-fv
  just ecdsa-hss-fv
  just signer-core-fv
  just threshold-prf-fv
  just router-ab-core-fv

# Run the full gated formal-verification path for `ed25519-hss`, including the Aeneas boundary check.
ed25519-hss-fv:
  cargo hss-fv all

# Run the fixture regeneration diff and `fv_hss_` Rust parity tests for `ed25519-hss`.
ed25519-hss-fv-check:
  cargo hss-fv check

# Run only the committed fixture regeneration diff for `ed25519-hss`.
ed25519-hss-fv-vectors:
  cargo hss-fv vectors-check

# Run only the `fv_hss_` Rust parity tests for `ed25519-hss`.
ed25519-hss-fv-parity:
  cargo hss-fv parity

# Run only the Lean/Lake privacy proof workspace build for `ed25519-hss`.
ed25519-hss-fv-lean:
  cargo hss-fv lean-check

# Run only the Aeneas/Lean boundary extraction and workspace check for `ed25519-hss`.
ed25519-hss-fv-aeneas:
  cargo hss-fv aeneas-check

# Run the committed fixture parity bridge and Verus verification path for `ed25519-hss`.
ed25519-hss-fv-verus:
  cargo hss-fv parity
  cargo hss-fv verus-check

# Run the active crate parity tests for `ecdsa-hss`.
ecdsa-hss-fv-parity:
  cargo test -q --manifest-path crates/ecdsa-hss/Cargo.toml --test role_local_mvp

# Run the current Verus verifier for `ecdsa-hss`.
ecdsa-hss-fv-verus:
  cargo verus verify --manifest-path crates/ecdsa-hss/formal-verification/verus/Cargo.toml

# Run the current full formal-verification path for `ecdsa-hss`.
ecdsa-hss-fv:
  just ecdsa-hss-fv-parity
  just ecdsa-hss-fv-verus
  just ecdsa-hss-fv-boundary
  just ecdsa-hss-fv-privacy

# Run the Aeneas/Lean boundary extraction and workspace check for `ecdsa-hss`.
ecdsa-hss-fv-boundary:
  cd crates/ecdsa-hss/formal-verification/lean-boundary && ./scripts/extract-visible-boundary.sh
  cd crates/ecdsa-hss/formal-verification/lean-boundary && $HOME/.elan/bin/lake build

# Run the Lean privacy workspace for `ecdsa-hss`.
ecdsa-hss-fv-privacy:
  cd crates/ecdsa-hss/formal-verification/lean-privacy && $HOME/.elan/bin/lake build

# Run the committed anti-drift tests for `signer-core`.
signer-core-fv-parity:
  cargo test -q --manifest-path crates/signer-core/formal-verification/verus/Cargo.toml --tests

# Run the current Verus verifier for `signer-core`.
signer-core-fv-verus:
  cargo verus verify --manifest-path crates/signer-core/formal-verification/verus/Cargo.toml

# Run the current full formal-verification path for `signer-core`.
signer-core-fv:
  just signer-core-fv-parity
  just signer-core-fv-verus

# Run the committed anti-drift tests for `threshold-prf`.
threshold-prf-fv-parity:
  cargo test -q --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml --tests

# Run the abstract threshold-prf Verus model.
threshold-prf-fv-verus:
  cargo verus verify --manifest-path crates/threshold-prf/formal-verification/verus/Cargo.toml

# Run the current full formal-verification path for `threshold-prf`.
threshold-prf-fv:
  cargo test -q --manifest-path crates/threshold-prf/Cargo.toml --tests
  just threshold-prf-fv-parity
  just threshold-prf-fv-verus
  just threshold-prf-fv-privacy

# Run the Lean privacy execution-state model for `threshold-prf`.
threshold-prf-fv-privacy:
  cd crates/threshold-prf/formal-verification/lean-privacy && $HOME/.elan/bin/lake build

# Run the Router A/B committed Rust boundary checks and formal-verification tracks.
router-ab-core-fv-parity:
  cargo test -q --manifest-path crates/router-ab-core/Cargo.toml --test source_guards
  cargo test -q --manifest-path crates/router-ab-core/Cargo.toml --test evidence
  cargo test -q --manifest-path crates/router-ab-core/Cargo.toml --test protocol_boundaries
  cargo test -q --manifest-path crates/router-ab-core/formal-verification/verus/Cargo.toml --tests

# Run the abstract Router A/B Verus model.
router-ab-core-fv-verus:
  cargo verus verify --manifest-path crates/router-ab-core/formal-verification/verus/Cargo.toml

# Run the Router A/B Lean boundary workspace.
router-ab-core-fv-boundary:
  cd crates/router-ab-core/formal-verification/lean-boundary && $HOME/.elan/bin/lake build

# Run the Router A/B Lean privacy workspace.
router-ab-core-fv-privacy:
  cd crates/router-ab-core/formal-verification/lean-privacy && $HOME/.elan/bin/lake build

# Run the current full formal-verification path for `router-ab-core`.
router-ab-core-fv:
  just router-ab-core-fv-parity
  just router-ab-core-fv-verus
  just router-ab-core-fv-boundary
  just router-ab-core-fv-privacy

# Build the threshold-prf benchmark harness without running it.
threshold-prf-bench-build:
  cargo bench --manifest-path crates/threshold-prf/Cargo.toml --bench threshold_prf_baseline --no-run

# Run the threshold-prf native benchmark suite.
threshold-prf-bench:
  cargo bench --manifest-path crates/threshold-prf/Cargo.toml --bench threshold_prf_baseline

# Check the latest threshold-prf native Criterion results against guardrail thresholds.
threshold-prf-bench-check:
  cargo run --quiet --manifest-path crates/threshold-prf/Cargo.toml --example check_benchmark_thresholds

# Run the threshold-prf native benchmark suite and enforce guardrail thresholds.
threshold-prf-bench-gate:
  just threshold-prf-bench
  just threshold-prf-bench-check

# Build and run the threshold-prf WASM benchmark harness under Node/V8.
threshold-prf-wasm-bench:
  node crates/threshold-prf/scripts/wasm-bench.mjs

# Run threshold-prf wasm-bindgen tests under Node.
threshold-prf-wasm-test:
  wasm-pack test --node wasm/threshold_prf

# Build the production threshold-prf WASM package and record bundle sizes.
threshold-prf-wasm-size:
  node crates/threshold-prf/scripts/wasm-size.mjs

# Build the production threshold-prf WASM package and smoke-test generated JS exports.
threshold-prf-wasm-smoke:
  node crates/threshold-prf/scripts/wasm-production-smoke.mjs

# Run the API-neutral private t-of-N interpolation smoke timing harness.
threshold-prf-t-of-n-prep-bench:
  cargo test --manifest-path crates/threshold-prf/Cargo.toml benchmark_private -- --ignored --nocapture --test-threads=1

# Build the threshold-prf Cloudflare Worker benchmark fixture.
threshold-prf-worker-bench-build:
  node crates/threshold-prf/scripts/worker-bench-build.mjs

# Run the threshold-prf Worker benchmark fixture locally with Wrangler.
threshold-prf-worker-bench-dev:
  just threshold-prf-worker-bench-build
  cd crates/threshold-prf/worker-bench && pnpm exec wrangler dev

# Check that warm local Worker requests reuse initialized threshold-prf WASM state.
threshold-prf-worker-bench-init-check:
  just threshold-prf-worker-bench-build
  node crates/threshold-prf/scripts/worker-bench-init-check.mjs

# Deploy the threshold-prf Worker benchmark fixture with Wrangler.
threshold-prf-worker-bench-deploy:
  just threshold-prf-worker-bench-build
  cd crates/threshold-prf/worker-bench && pnpm exec wrangler deploy

# Collect samples from a deployed threshold-prf Worker benchmark URL.
threshold-prf-worker-bench-run url:
  node crates/threshold-prf/scripts/worker-bench-run.mjs {{url}}
