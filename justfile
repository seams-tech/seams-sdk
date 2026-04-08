# Run the full `ed25519-hss` formal-verification task set: vectors, parity,
# Lean privacy, and Verus.
default:
  @just --list

# Run the full gated formal-verification path for `ed25519-hss`.
fv:
  cargo hss-fv all

# Run only the fixture regeneration diff and `fv_hss_` Rust parity tests.
fv-check:
  cargo hss-fv check

# Run only the committed fixture regeneration diff.
fv-vectors:
  cargo hss-fv vectors-check

# Run only the `fv_hss_` Rust parity tests.
fv-parity:
  cargo hss-fv parity

# Run only the Lean/Lake privacy proof workspace build for `ed25519-hss`.
fv-lean:
  cargo hss-fv lean-check

# Run the Aeneas/Lean boundary bootstrap check for `ed25519-hss`.
fv-aeneas:
  cargo hss-fv aeneas-check

# Run the committed fixture parity bridge and Verus verification path for `ed25519-hss`.
fv-verus:
  cargo hss-fv parity
  cargo hss-fv verus-check
