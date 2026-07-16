default:
  @just --list

# Run the full formal-verification path for all crate-local FV tracks.
fv:
  just ed25519-yao-fv
  just router-ab-ecdsa-derivation-fv
  just signer-core-fv
  just threshold-prf-fv
  just router-ab-core-fv

# Run every currently gated Ed25519 Yao formal-verification track.
ed25519-yao-fv:
  cargo yao-fv all

# Check the versioned fixed-reference generated region against its Rust owner.
ed25519-yao-fv-reference-spec:
  cargo yao-fv reference-spec-check

# Check the committed Ed25519 Yao vector corpus through the clear oracle.
ed25519-yao-fv-vectors:
  cargo yao-fv vectors-check

# Reproduce canonical and deterministic differential vectors in independent Python.
ed25519-yao-fv-cross-language:
  cargo yao-fv cross-language-check

# Run the Rust manifest and clear-oracle parity suites.
ed25519-yao-fv-parity:
  cargo yao-fv parity

# Run production-to-mirror anti-drift without requiring Verus.
ed25519-yao-fv-anti-drift:
  cargo yao-fv anti-drift

# Build the named Ed25519 Yao Lean model target.
ed25519-yao-fv-lean:
  cargo yao-fv lean-check

# Run the pinned Aeneas extraction and named Lean boundary targets.
ed25519-yao-fv-aeneas:
  cargo yao-fv aeneas-check

# Verify the current Ed25519 Yao Verus mirror with the pinned release.
ed25519-yao-fv-verus:
  cargo yao-fv verus-check

# Qualify the pinned native constant-time analyzer with safe and vulnerable fixtures.
ed25519-yao-fv-constant-time-qualification:
  cargo yao-fv constant-time-qualification

# Deterministic mutation smoke for untrusted Yao stream and recipient-package parsers.
ed25519-yao-parser-fuzz-smoke:
  cargo test -q --manifest-path crates/ed25519-yao/Cargo.toml deterministic_untrusted_stream_parser_fuzz_smoke
  cargo test -q --manifest-path crates/router-ab-ed25519-yao-protocol/Cargo.toml deterministic_recipient_package_parser_fuzz_smoke

ed25519-yao-fv-benchmark-manifest-reproducibility:
  cargo yao-fv benchmark-manifest-reproducibility

# Reconcile the Phase 2B candidate against all closed Phase 1 corpora.
ed25519-yao-fv-phase2b-reconciliation:
  cargo yao-fv phase2b-reconciliation-check

# Check the signed external-evidence parsers without claiming reproduction or approval.
ed25519-yao-fv-phase2b-exit-evidence-readiness:
  cargo yao-fv phase2b-exit-evidence-readiness-check

# Check the dormant Phase 2B CI staging state machine and workflow.
ed25519-yao-fv-phase2b-change-control-readiness:
  cargo yao-fv phase2b-change-control-readiness-check

# Regenerate the fixed Phase 2B review subject from a clean checkout.
ed25519-yao-fv-phase2b-review-subject:
  cargo yao-fv phase2b-review-subject-check

# Validate externally protected Phase 2B policy and challenge capabilities.
ed25519-yao-fv-phase2b-protected-inputs:
  cargo yao-fv phase2b-protected-inputs-check

# Prepare the unsigned Phase 2B independent-host reproduction envelope.
ed25519-yao-fv-phase2b-independent-host-prepare:
  cargo yao-fv phase2b-independent-host-prepare

# Finalize a bounded canonical Phase 2B request from stdin.
ed25519-yao-fv-phase2b-independent-host-finalize:
  cargo yao-fv phase2b-independent-host-finalize

# Verify the fixed Phase 2B evidence commit and signed reproduction record.
ed25519-yao-fv-phase2b-independent-host-record-check:
  cargo yao-fv phase2b-independent-host-record-check

# Verify the fixed Phase 2B cryptographic-review approval.
ed25519-yao-fv-phase2b-review-approval-check:
  cargo yao-fv phase2b-review-approval-check

# Run the active crate parity tests for Router A/B ECDSA derivation.
router-ab-ecdsa-derivation-fv-parity:
  cargo test -q --manifest-path crates/router-ab-ecdsa-derivation/Cargo.toml --test role_local_mvp

# Run the current Verus verifier for Router A/B ECDSA derivation.
router-ab-ecdsa-derivation-fv-verus:
  cargo verus verify --manifest-path crates/router-ab-ecdsa-derivation/formal-verification/verus/Cargo.toml -- --rlimit 100

# Run the current full formal-verification path for Router A/B ECDSA derivation.
router-ab-ecdsa-derivation-fv:
  just router-ab-ecdsa-derivation-fv-parity
  just router-ab-ecdsa-derivation-fv-verus
  just router-ab-ecdsa-derivation-fv-boundary
  just router-ab-ecdsa-derivation-fv-privacy

# Run the Aeneas/Lean boundary extraction and workspace check for Router A/B ECDSA derivation.
router-ab-ecdsa-derivation-fv-boundary:
  cd crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary && ./scripts/extract-visible-boundary.sh
  git diff --exit-code -- crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary/generated/visible-boundary-input/router_ab_ecdsa_derivation.llbc || (echo "Router A/B ECDSA derivation visible-boundary extraction drifted; commit the regenerated LLBC artifact or fix extraction." >&2; exit 1)
  cd crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary && $HOME/.elan/bin/lake build RouterAbEcdsaDerivation RouterAbEcdsaDerivationBoundary

# Run the Lean privacy workspace for Router A/B ECDSA derivation.
router-ab-ecdsa-derivation-fv-privacy:
  cd crates/router-ab-ecdsa-derivation/formal-verification/lean-privacy && $HOME/.elan/bin/lake build RouterAbEcdsaDerivationPrivacy

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
