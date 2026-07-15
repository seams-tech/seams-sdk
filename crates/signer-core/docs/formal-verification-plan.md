# `signer-core` Formal Verification Plan

Last updated: 2026-04-16

## Decision

The recommended verification strategy for
[crates/signer-core](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core)
is:

- **Verus first**
- **no standalone Lean track initially**

This is the right starting point because the highest-value proof targets in
`signer-core` are implementation-facing algebraic and encoding invariants over
shared Rust helpers. They are not privacy/boundary theorems of the kind that
justify an Aeneas + Lean stack by themselves.

## Why This Is Worth Doing

`signer-core` is the shared cryptographic helper layer beneath:

- [crates/ecdsa-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss)
- [crates/ed25519-yao](/Users/pta/Dev/rust/seams-sdk/crates/ed25519-yao)
- [crates/router-ab-ed25519-yao](/Users/pta/Dev/rust/seams-sdk/crates/router-ab-ed25519-yao)
- wasm consumers
- platform bindings that re-export these helpers

That means a narrow proof over `signer-core` has unusually high leverage.
Verifying a shared derivation or mapping helper here is more valuable than
re-proving the same helper behavior piecemeal at higher layers.

The best targets are the local formulas and invariants that:

1. directly affect key derivation or share derivation,
2. are reused by multiple higher-level crates, and
3. are currently still treated as trusted seams by higher-level proofs.

## Why Not Start With A Full Lean Stack

`signer-core` is mostly shared primitive/helper code. Its crate-local targets
are algebraic and encoding invariants; protocol privacy is owned by the
higher-level ECDSA and Ed25519 Yao verification tracks.

So the recommended sequence is:

1. prove the shared Rust helpers in Verus,
2. add executable anti-drift checks against committed vectors,
3. only consider Aeneas + Lean later if a specific Rust-facing boundary in
   `signer-core` becomes proof-relevant on its own.

## Primary Scope

### Priority 1: `secp256k1`

The first `signer-core` FV pass should focus on
[src/secp256k1.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/secp256k1.rs):

1. reduction of 64-byte HKDF output into a valid non-zero secp256k1 scalar
2. derivation of the threshold relayer signing share from `(master_secret, relayer_key_id)`
3. derivation of the canonical secp256k1 keypair from `(prf_second, near_account_id)`
4. additive-share mapping into the fixed `{1, 2}` backend share encoding
5. compressed/uncompressed public-key and address consistency

This is the highest-impact slice because it sits directly under:

- `ecdsa-hss` key derivation
- threshold share mapping
- public-key / Ethereum-address equivalence

### Priority 2: `near_threshold_ed25519`

The second `signer-core` FV pass should focus on
[src/near_threshold_ed25519.rs](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/src/near_threshold_ed25519.rs):

1. deterministic threshold client-share derivation from `(wrap_key_seed, near_account_id)`
2. non-zero share guarantees for the derived client signing share
3. verifying-share derivation consistency from the derived signing share
4. key-package construction shape and participant-ID normalization
5. NEP-413 digest construction shape and nonce-length validation

This is useful, but it is lower urgency than the `secp256k1` slice because the
largest currently-open shared trust seams are on the ECDSA path.

## Explicit Non-Goals

The initial `signer-core` FV plan should **not** try to prove:

1. full secp256k1 primitive correctness
2. full Keccak or SHA-256 correctness
3. side-channel resistance
4. the behavior of the external `threshold-signatures` crate from first principles
5. a separate formal-verification track for
   [crates/signer-embedded-linux](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-embedded-linux)

`signer-embedded-linux` is currently a feature-gated re-export layer, so a
standalone FV track there would be much lower impact than proving the shared
helpers in `signer-core`.

## Recommended Layout

To stay consistent with the `ecdsa-hss` setup, the recommended future
structure for `signer-core` is:

- `formal-verification/README.md`
- `formal-verification/docs/implementation-plan.md`
- `formal-verification/docs/proof-inventory.md`
- `formal-verification/verus/`
- `formal-verification/lean-boundary/`
- `formal-verification/lean-privacy/`

The key point is sequencing, not symmetry for its own sake:

- `verus/` should be created and used first
- `lean-boundary/` and `lean-privacy/` should exist only if a specific
  `signer-core` Rust boundary becomes important enough to justify extraction

So the folder structure should mirror `ecdsa-hss`, while the initial active
scope remains Verus-first and possibly Verus-only.

Current implementation status:

- `formal-verification/` exists
- `formal-verification/verus/` exists
- the first `secp256k1` Verus model exists
- a committed secp256k1 fixture corpus exists
- executable anti-drift tests cover the first `secp256k1` slice
- the first `near_threshold_ed25519` derivation Verus model exists
- committed Ed25519 derivation and NEP-413 fixtures with anti-drift tests exist
- `near_threshold_ed25519` participant, key-package, and NEP-413 shape models exist
- the current Phase 5 decision is to keep Aeneas + Lean inactive for signer-core
- full repository `just fv` passes with signer-core included
- `just signer-core-fv` runs the current signer-core FV path

## Initial Proof Inventory

See
[formal-verification-proof-inventory.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/signer-core/docs/formal-verification-proof-inventory.md)
for the first concrete theorem targets.

## Phased Todo List

Current status:

- [x] current Verus-first signer-core scope complete
- [x] `just signer-core-fv` passes
- [x] full repository `just fv` passes

### Phase 0: Bootstrap

- [x] create `crates/signer-core/formal-verification/`
- [x] add `formal-verification/README.md`
- [x] add `formal-verification/docs/implementation-plan.md`
- [x] add `formal-verification/docs/proof-inventory.md`
- [x] add `formal-verification/verus/`
- [x] add `formal-verification/verus/Cargo.toml`
- [x] add `formal-verification/verus/README.md`
- [x] add `formal-verification/verus/docs/implementation-plan.md`
- [x] add `formal-verification/verus/src/lib.rs`
- [x] mirror the future production module layout minimally under `verus/src/`
- [x] wire repo-local wrapper commands for `signer-core` verification

### Phase 1: `secp256k1` Scalar Reduction And Key Derivation

- [x] add a Verus module for HKDF-output reduction in `src/secp256k1.rs`
- [x] prove deterministic reduction from 64-byte HKDF output
- [x] prove the reduction output is always a valid non-zero secp256k1 scalar
- [x] add a Verus module for relayer-share derivation from `(master_secret, relayer_key_id)`
- [x] prove relayer-share derivation is deterministic
- [x] prove the returned relayer signing share bytes encode a valid non-zero scalar
- [x] model the returned relayer verifying share as the compressed public key of the returned signing share
- [x] add a Verus module for canonical keypair derivation from `(prf_second, near_account_id)`
- [x] prove canonical keypair derivation is deterministic
- [x] model the compressed public key and Ethereum address as derived from the same private key
- [x] connect this layer to executable anti-drift vectors

### Phase 2: `secp256k1` Mapping And Public-Key Consistency

- [x] mirror the fixed `{1, 2}` additive-share mapping logic in the Verus track
- [x] prove participant-ID rejection for unsupported IDs
- [x] prove the mapping uses the intended fixed lambdas
- [x] prove mapped shares remain valid non-zero scalars
- [x] prove mapped-share semantics preserve the same local additive-share meaning
- [x] prove the public-key helper functions preserve compressed SEC1 shape
- [x] add executable anti-drift checks for scalar-byte encoding and mapping behavior

### Phase 3: `near_threshold_ed25519` Shared Derivation

- [x] add a Verus module for threshold client-share derivation from `(wrap_key_seed, near_account_id)`
- [x] prove deterministic share derivation
- [x] prove non-zero client-share output
- [x] prove verifying-share derivation matches the derived signing share
- [x] prove participant-ID normalization and validation invariants
- [x] prove key-package construction preserves the intended signing-share / verifying-share / group-key relationship
- [x] prove NEP-413 digest construction shape and exact nonce-length validation
- [x] add executable anti-drift checks for the committed Ed25519 derivation slice
- [x] add executable anti-drift checks for committed NEP-413 digest vectors

### Phase 4: Shared-Helper Boundary And Anti-Drift Expansion

This phase should stay narrower than "prove all of `signer-core`."

It should focus on the highest-value remaining shared-helper seams:

- vector parity
- anti-drift checks
- exact byte-layout guarantees for helper outputs

- [x] add a committed vector corpus for the `secp256k1` slice
- [x] add a committed vector corpus for the `near_threshold_ed25519` derivation slice
- [x] add a committed vector corpus for the `near_threshold_ed25519` NEP-413 digest slice
- [x] add anti-drift checks between production code and the Verus mirror for the first `secp256k1` slice
- [x] add anti-drift checks for helper output layout and rejected-input shape for the first `secp256k1` slice

### Phase 5: Decide Whether Aeneas + Lean Expansion Is Justified

This phase should explicitly mirror the `ecdsa-hss` decision point, but it may
end with "do nothing."

- [x] decide whether any `signer-core` Rust-facing boundary is stable and important enough to justify extraction

Decision:

No current `signer-core` helper boundary warrants Aeneas + Lean extraction.
The active track should remain Verus plus executable anti-drift checks until a
stable shared Rust-facing boundary becomes proof-relevant on its own.

## Deferred Future Work

Only if a future stable shared Rust-facing boundary justifies extraction:

- define the handwritten Lean model for that boundary
- prove the generated boundary matches the handwritten model
- add any crate-local boundary theorem only if it is genuinely shared across downstream consumers
- create `formal-verification/lean-boundary/`
- install the pinned Aeneas/Charon toolchain locally
- generate the first Rust-derived Lean boundary artifact
- keep generated modules separate from handwritten Lean bridge lemmas
- create `formal-verification/lean-privacy/` if a real privacy boundary exists
- freeze the extraction target to one narrow helper boundary only
- keep broader privacy/boundary expansion out of scope until the first bridge works

## Practical Recommendation

If only one `signer-core` FV phase is funded now, do:

1. `src/secp256k1.rs`
2. vector parity and anti-drift for that slice

That is the highest-impact improvement because it shrinks a shared trust seam
used by `ecdsa-hss`, wasm exports, and other downstream code.
