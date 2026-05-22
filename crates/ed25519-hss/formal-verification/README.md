# `ed25519-hss` Formal Verification

This directory keeps shared formal-verification inputs, crate-local conformance
tooling, the Lean privacy track, the Aeneas Lean boundary track, and the Verus
track next to the low-level cryptographic code they target.

The first proof target for both tracks remains the clear fixed-function
expansion spec in
[`../src/shared/reference.rs`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/src/shared/reference.rs).

## Layout

- `docs/`
  shared inputs such as the spec corpus and spec-to-code review
- `lean-privacy/`
  the handwritten Lean 4 privacy proof track for higher-level secrecy, hiding,
  simulator, and indistinguishability claims over the visible boundary
- `lean-boundary/`
  the Aeneas-backed Rust-to-Lean boundary track for mechanically linking the
  Rust boundary slice into Lean
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

The default full gated command from the repo root is:

```sh
pnpm check:formal-verification
```

Useful subcommands:

```sh
make vectors-check
make parity
make lean-check
make verus-check
make aeneas-check
```

`make check` and `pnpm check:formal-verification` now run the same default
gated path:

- fixture regeneration check
- Rust parity tests
- Aeneas boundary extraction drift check
- Lean privacy build
- Verus verification

`make aeneas-check`, `cargo hss-fv aeneas-check`, and `just ed25519-hss-fv-aeneas` are
still available as focused boundary-only commands, but they are now part of
the default gated path as well.

## Track Status

`verus/`, `lean-privacy/`, and `lean-boundary/` do different jobs and are
intended to fit together rather than duplicate each other.

- `lean-privacy/` purpose:
  define the privacy model and prove the high-level non-export secrecy claims.
  This is the handwritten Lean layer where we state and prove things like
  hidden-seed hiding and client/server non-derivability.
- `lean-boundary/` purpose:
  generate a narrow Lean boundary artifact mechanically from Rust with Aeneas,
  then prove bridge lemmas from that generated Rust boundary into the
  handwritten Lean privacy model.
- `verus/`
  proves the implementation-facing layer:
  reference helper correctness, deterministic shape invariants, executor
  visible-boundary equivalence, narrow runtime/export-boundary rules, and
  anti-drift checks against the production crate.
- `lean-privacy/`
  proves the privacy-facing layer above the Rust boundary:
  export-exception isolation, non-export hiding, client/server
  non-derivability claims, simulator-based privacy structure, and the current
  observable-profile indistinguishability model.
- `lean-boundary/`
  is the mechanically linked bridge:
  Aeneas-generated Lean artifacts from the Rust boundary slice plus bridge
  lemmas into `lean-privacy/`.

## How They Relate

The Lean tracks are layered, not duplicated.

- `lean-privacy/`
  is the reference privacy model and theorem layer.
- `lean-boundary/`
  is the implementation-to-Lean bridge layer.

The intended flow is:

1. Rust exposes the visible hidden-seed boundary.
2. `lean-boundary/` generates that Rust boundary into Lean mechanically.
3. `lean-privacy/` proves the privacy theorems over the corresponding Lean
   boundary model.
4. The bridge lemmas connect the generated Rust boundary to the handwritten
   privacy model, so the non-export privacy claims apply to the Rust boundary
   slice rather than to a purely handwritten model.

Use `verus/` to answer "does the Rust-shaped implementation enforce the
intended boundary?" Use `lean-privacy/` to answer "what privacy claim are we
making over that boundary?" Use `lean-boundary/` to answer "how do we connect
the Rust boundary mechanically to Lean?"

The current Verus anti-drift track also models the Level A
`ClientMaskedProjection` boundary: client-owned WASM/SDK artifact construction
and client-output opening must carry a fixed 32-byte `clientOutputMaskB64u`,
and server finalize state must not retain client-output bundles or mask
material. This supports the trusted-server/code-as-deployed claim that the
server-side protocol path does not receive or materialize the client's
sensitive key-derivation secret during Ed25519 HSS key derivation. It does not
upgrade the protocol to a full malicious-server security proof.

See also:

- [`docs/spec-corpus.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/docs/spec-corpus.md)
- [`docs/spec-compliance-review-2026-04-05.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/docs/spec-compliance-review-2026-04-05.md)
- [`lean-privacy/README.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-privacy/README.md)
- [`lean-privacy/docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-privacy/docs/implementation-plan.md)
- [`lean-boundary/README.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/README.md)
- [`lean-boundary/docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-boundary/docs/implementation-plan.md)
- [`verus/README.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/verus/README.md)
- [`verus/docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/verus/docs/implementation-plan.md)
