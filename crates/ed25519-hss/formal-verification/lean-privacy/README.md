# `ed25519-hss` Lean Privacy Track

This directory is the Lean 4 track for privacy-specific proofs that are out of
scope for the implementation-oriented Verus pass:
- non-export hidden-seed expansion is hidden from the client and the server
- the client cannot derive `y_relayer` or `tau_relayer` from allowed outputs
- the server cannot derive client-secret material from allowed outputs
- explicit key export is the only allowed exception to stronger disclosure

This track is not intended to re-prove the full crate implementation. Verus
remains the implementation proof path. Lean privacy work should prove the
privacy and hiding layer over the already-stabilized visible boundary.
The Aeneas-backed `lean-boundary/` track now provides the mechanically linked
Rust-to-Lean boundary bridge for the non-export slice, while `lean-privacy/`
remains the handwritten theorem layer above that boundary.

## Layout

- `lakefile.lean`
- `lean-toolchain`
- `Ed25519HssPrivacy.lean`
- `Ed25519HssPrivacy/`
- `docs/`

## Commands

Run from this directory:

```sh
lake build
```

Or from the crate root through the shared wrapper:

```sh
cargo hss-fv lean-check
just ed25519-hss-fv-lean
```

The default full repo gate is:

```sh
pnpm check:formal-verification
```

## Scope

Lean privacy work should focus on:

- adversary models for non-export client/server views
- simulator definitions for allowed outputs
- secrecy / non-derivability theorem statements
- export-path exception isolation

Lean privacy work should not duplicate the Verus implementation mirror.

See:

- [`docs/implementation-plan.md`](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss/formal-verification/lean-privacy/docs/implementation-plan.md)
