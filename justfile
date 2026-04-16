default:
  @just --list

# Run the full formal-verification path for all crate-local FV tracks.
fv:
  just ed25519-hss-fv
  just ecdsa-hss-fv
  just signer-core-fv

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

# Run the committed fixture parity test for `ecdsa-hss`.
ecdsa-hss-fv-parity:
  cargo test -q --manifest-path crates/ecdsa-hss/formal-verification/verus/Cargo.toml --tests

# Run the current Verus verifier for `ecdsa-hss`.
ecdsa-hss-fv-verus:
  cargo verus verify --manifest-path crates/ecdsa-hss/formal-verification/verus/Cargo.toml

# Run the current full formal-verification path for `ecdsa-hss`.
ecdsa-hss-fv:
  just ecdsa-hss-fv-parity
  just ecdsa-hss-fv-verus
  just ecdsa-hss-fv-boundary
  just ecdsa-hss-fv-privacy

# Run the Lean boundary extraction and workspace build for `ecdsa-hss`.
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
