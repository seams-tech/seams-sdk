# `ed25519-hss` Verus Track

This directory is the new default path for proving the `ed25519-hss` Rust
implementation directly with Verus.

Recommended layout:

- `Cargo.toml`
- `src/lib.rs`
- `src/shared/reference.rs`
- `src/candidate.rs`
- `src/artifact/prime_order_encoder.rs`
- `src/ddh/hidden_eval.rs`
- `src/ddh/hidden_eval_executor.rs`
- `docs/`

The verification crate should mirror the production crate module layout as
closely as possible, but stay isolated from production runtime code while the
proof effort is still incubating.

Current bootstrap status:

- `Cargo.toml` exists,
- `src/lib.rs` exists,
- the crate mirrors the production module layout under:
  - `src/shared/reference.rs`
  - `src/candidate.rs`
  - `src/artifact/prime_order_encoder.rs`
  - `src/ddh/hidden_eval.rs`
  - `src/ddh/hidden_eval_executor.rs`

Current command path:

- `cargo hss-fv verus-check`
- `just fv-verus`

`cargo hss-fv verus-check` runs only the verifier. `just fv-verus` runs the
committed fixture parity bridge first and then runs the verifier.

These commands prefer `cargo verus` when the Verus toolchain is installed and
otherwise fall back to a direct `verus` invocation.

## Current Proof Boundary

The current Verus boundary is intentionally frozen at:

- reference helper correctness in `src/shared/reference.rs`
- deterministic shape invariants in `src/candidate.rs`,
  `src/artifact/prime_order_encoder.rs`, and `src/ddh/hidden_eval.rs`
- executor visible-boundary equivalence in
  `src/ddh/hidden_eval_executor.rs`
- narrow runtime/export-boundary invariants in `src/server/api.rs`
- production-vs-Verus anti-drift checks in `tests/anti_drift.rs`

In practice, this Verus pass is the implementation-proof layer for four kinds
of guarantees:

- anti-drift protection
  so the proof mirror and the production crate do not silently diverge
- input/output boundary guarantees
  so the Rust-shaped implementation exposes only the intended visible boundary
- runtime/export-boundary discipline
  so non-export and explicit-export behavior stay separated correctly
- deterministic shape guarantees
  so fixed counts, ordering, and layout assumptions remain checked

This pass does not try to prove:

- full hidden-eval internal executor equivalence beyond the visible boundary
- full runtime/transport protocol correctness
- full client/server integration behavior

If production shape changes for an accepted optimization and there is no
security regression, update the Verus mirror and anti-drift checks to match
production rather than freezing old internals.

See:

- [`docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/verus/docs/implementation-plan.md)
