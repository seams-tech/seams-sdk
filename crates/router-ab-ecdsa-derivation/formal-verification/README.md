# `router-ab-ecdsa-derivation` Formal Verification

This directory contains the completed formal-verification tracks for the agreed
current `router-ab-ecdsa-derivation` scope in
[crates/router-ab-ecdsa-derivation](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation).

## Recommended Verification Split

The recommended split is:

- **Verus as the primary implementation-proof track**
- **Aeneas + Lean as the secondary boundary/privacy track**

That means:

- use Verus first for Rust-shaped algebraic and implementation invariants
- add Aeneas + Lean later once there is a stable Rust boundary slice worth
  extracting mechanically

## Why Verus First

The first proof targets for `router-ab-ecdsa-derivation` are implementation-facing:

- canonical `x` derivation is deterministic and valid
- additive share derivation produces valid non-zero scalars
- additive-share mapping preserves the same effective group secret
- exported key, threshold public key, and Ethereum address are the same
  logical key
- non-export operations do not expose export-capable output

Those are best handled first with Verus because they are:

- Rust-shaped
- algebraic
- local to the implementation
- valuable before the full protocol boundary is stable

## Why Aeneas + Lean Later

Aeneas + Lean is still useful, but its best role here is narrower:

- mechanically extract a stable Rust boundary slice into Lean
- connect that generated boundary to higher-level secrecy/privacy statements
- prove that the Rust boundary matches the handwritten privacy model

That is most useful after:

- the Rust boundary exists
- the staged boundary is frozen
- the non-export/export boundary is stable enough to extract

So Aeneas + Lean should be treated as:

- **follow-on boundary work**
- not the first implementation-proof tool

## Current Decision

For `router-ab-ecdsa-derivation`, the working decision is:

- **Primary path:** Verus
- **Secondary path:** Aeneas + Lean
- **Long-term posture:** both, but not at the same time and not for the same
  job

## Current Status

Current state:

- root scope docs exist
- proof inventory exists at:
  [docs/proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/docs/proof-inventory.md)
- Verus bootstrap crate exists at:
  [verus/](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/verus)
- Lean boundary extraction track now exists at:
  [lean-boundary/](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-boundary)
- the pinned Aeneas/Charon toolchain is installed locally for that track
- the first Rust-derived Lean boundary artifact now exists for the narrow
  staged server boundary
- a separate Lean privacy track now exists at:
  [lean-privacy/](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-privacy)
  for the completed privacy slice over the frozen staged boundary
- the Lean privacy track now includes:
  - server non-derivability of client secrets over full states that share the
    same server-visible boundary
  - client non-derivability of server secrets over full states that share the
    same client-visible boundary
  - explicit export isolated as the only canonical-secret disclosure exception
  - generated-boundary lifts for those privacy theorems
- the hidden-eval/compiler-facing reference seam is now frozen and extracted
  as a second narrow Aeneas boundary
- the Lean boundary track now proves the generated hidden-eval/compiler seam
  matches the handwritten hidden-eval boundary model
- the Lean privacy track now includes transport/persisted-state exclusion
  theorems for forbidden secret material at that same frozen seam
- the current wrapper commands are green:
  - `just router-ab-ecdsa-derivation-fv`
  - `just router-ab-ecdsa-derivation-fv-boundary`
  - `just router-ab-ecdsa-derivation-fv-privacy`

The current repo-level command path is:

```sh
just router-ab-ecdsa-derivation-fv
```

That command now runs:

- committed fixture parity and executable anti-drift tests for the Verus slice
- Verus verification
- Lean boundary extraction plus Lean build
- Lean privacy build

## Completed Scope

The first useful proof targets are:

1. canonical `x` derivation from `(y_client, y_relayer, context)`
2. additive share derivation `(x_client, x_relayer)`
3. non-zero-share and retry-counter invariants
4. mapping into the current `threshold-signatures` 2P share encoding
5. public-key and address equivalence:
   - exported `x`
   - threshold public key
   - threshold signing address

These are the targets that are now complete for the agreed frozen scope.

The completed privacy targets for that same frozen scope are:

1. server-visible staged-boundary non-observability for threshold-derived
   private material
2. widened client/server observable-view models over full handwritten
   execution states
3. server non-derivability of client secrets in the handwritten model for
   state pairs sharing the same server-visible boundary
4. client non-derivability of server secrets in the handwritten model for
   state pairs sharing the same client-visible boundary
5. explicit export isolated as the only canonical-secret disclosure exception
6. generated-boundary lifts of those privacy theorems

The current privacy scope is intentionally capped at the frozen boundary/seam
models. Full runtime orchestration, side-channel claims, and
implementation-facing algebra remain out of this Lean track.

The important caveat is that some Verus theorems still rely on explicit
trusted axioms at production-boundary seams. See
[docs/proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/docs/proof-inventory.md)
for the exact list.

The two former broad trusted seams for:

- additive-share relayer-share construction
- the `{1,2}` backend share-mapping formula

are no longer axiom-only. Those slices are now proved in the Verus model,
leaving narrower trust only at the scalar-reduction and scalar-int-to-bytes
encoding bridges, plus the public-key primitive boundary.

The scalar-byte injectivity axiom is no longer part of the `router-ab-ecdsa-derivation` Verus
slice. The remaining reduction/encoding seam is now also pinned by executable
anti-drift checks over fixture scalars, boundary-domain scalars, and a
generated digest corpus.

## Docs

- implementation plan:
  [docs/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/docs/implementation-plan.md)
- proof inventory:
  [docs/proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/docs/proof-inventory.md)
- Verus bootstrap:
  [verus/README.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/verus/README.md)
- crate implementation plan:
  [../docs/plans/implementation-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/docs/plans/implementation-plan.md)
- share-derivation design memo:
  [../docs/plans/share-derivation-design-memo.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/docs/plans/share-derivation-design-memo.md)
- protocol spec:
  [../specs/protocol.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/protocol.md)
- export spec:
  [../specs/export.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/export.md)
- integration spec:
  [../specs/integration-cait-sith-backend.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/specs/integration-cait-sith-backend.md)

