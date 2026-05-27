default:
  @just --list

# Run the full formal-verification path for all crate-local FV tracks.
fv:
  just ed25519-hss-fv
  just ecdsa-hss-fv
  just signer-core-fv
  just threshold-prf-fv

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

# Run the active V2 crate parity tests for `ecdsa-hss`.
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
  just threshold-prf-fv-parity
  just threshold-prf-fv-verus
  just threshold-prf-fv-privacy

# Run the Lean privacy execution-state model for `threshold-prf`.
threshold-prf-fv-privacy:
  cd crates/threshold-prf/formal-verification/lean-privacy && $HOME/.elan/bin/lake build

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
