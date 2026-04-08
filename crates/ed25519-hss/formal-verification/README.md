# `ed25519-hss` Formal Verification

This directory keeps shared formal-verification inputs, crate-local conformance
tooling, the Lean privacy track, and the Verus track next to the low-level
cryptographic code they target.

The first proof target for both tracks remains the clear fixed-function
expansion spec in
[`../src/shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs).

## Layout

- `docs/`
  shared inputs such as the spec corpus and spec-to-code review
- `lean-privacy/`
  the Lean 4 privacy proof track for higher-level secrecy, hiding, simulator,
  and indistinguishability claims over the already-stabilized visible boundary
- `verus/`
  the default implementation-proof track for the Rust-shaped `ed25519-hss`
  logic, boundary discipline, and anti-drift checks against production

## Shared Scope

- freeze the post-refactor spec corpus for `shared/`, `wire/`, `client/`, and
  `server/`,
- record compliance findings that affect proof scope,
- keep the committed fixture corpus in `../fixtures/f_expand_v1.json` as the
  initial executable parity bridge.

## Commands

Run from this directory:

```sh
make check
```

Useful subcommands:

```sh
make vectors-check
make parity
make proof-check
```

`make proof-check` now delegates to the Lean privacy workspace in
`lean-privacy/`.

## Track Status

`verus/` and `lean-privacy/` do different jobs and are intended to fit
together rather than duplicate each other.

- `verus/`
  proves the implementation-facing layer:
  reference helper correctness, deterministic shape invariants, executor
  visible-boundary equivalence, narrow runtime/export-boundary rules, and
  anti-drift checks against the production crate.
- `lean-privacy/`
  proves the privacy-facing layer above that implementation boundary:
  export-exception isolation, non-export hiding, client/server
  non-derivability claims, simulator-based privacy structure, and the current
  observable-profile indistinguishability model.

Use `verus/` to answer "does the Rust-shaped implementation enforce the
intended boundary?" Use `lean-privacy/` to answer "what privacy claim are we
making over that boundary?"

See also:

- [`docs/spec-corpus.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/docs/spec-corpus.md)
- [`docs/spec-compliance-review-2026-04-05.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/docs/spec-compliance-review-2026-04-05.md)
- [`lean-privacy/README.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-privacy/README.md)
- [`lean-privacy/docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-privacy/docs/implementation-plan.md)
- [`verus/README.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/verus/README.md)
- [`verus/docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/verus/docs/implementation-plan.md)
