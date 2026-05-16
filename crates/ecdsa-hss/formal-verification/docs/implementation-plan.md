# `ecdsa-hss` Formal Verification Implementation Plan

Last updated: 2026-04-09

## Decision

The recommended verification strategy is:

- **Verus first**
- **Aeneas + Lean later**

This is not because Aeneas + Lean is weaker. It is because the first
high-value proof targets for `ecdsa-hss` are implementation-facing algebraic
invariants over Rust-shaped code and data.

## Why Verus Is The Better First Tool

The first `ecdsa-hss` proof targets are:

- canonical `x` derivation correctness
- additive-share derivation correctness
- non-zero-share and retry-counter invariants
- additive-share mapping correctness into the current backend
- public-key/address equivalence for:
  - exported key
  - threshold signing public key
  - threshold signing address

These are all good Verus targets because they are:

- local
- algebraic
- Rust-shaped
- useful before the full runtime boundary is frozen

## Why Aeneas + Lean Is Still Worth Doing

Aeneas + Lean becomes valuable after there is a stable boundary slice to
extract.

For `ecdsa-hss`, that likely means:

- non-export visible boundary
- explicit export boundary
- retained-state boundary
- policy-bound output kinds

So the right sequencing is:

1. prove the Rust implementation invariants in Verus
2. freeze the boundary
3. extract a narrow Rust boundary slice with Aeneas
4. connect that extracted boundary to higher-level Lean privacy/boundary claims

## Working Scope

### Primary Verus Scope

The first Verus pass should cover:

1. fixed-function canonical `x` derivation
2. additive share derivation
3. additive-share mapping to current backend share encoding
4. public-key equivalence
5. Ethereum address equivalence
6. non-export/export output-policy invariants

### Deferred Aeneas + Lean Scope

The Aeneas + Lean follow-on should cover:

1. extracted Rust boundary for non-export visible outputs
2. extracted Rust boundary for explicit export outputs
3. bridge lemmas from Rust boundary to Lean privacy/boundary model
4. Lean theorems for:
   - non-export no-key-disclosure
   - explicit-export-only disclosure
   - retained-state boundary claims

## Recommended Layout

Recommended future structure:

- `formal-verification/README.md`
- `formal-verification/docs/implementation-plan.md`
- `formal-verification/docs/proof-inventory.md`
- `formal-verification/verus/`
- `formal-verification/lean-boundary/`
- `formal-verification/lean-privacy/`

The practical rule is:

- do not create the Aeneas/Lean workspaces until the Rust boundary slice is
  stable enough to justify them

## Initial Proof Inventory

The first useful theorem/proof targets are:

### FV-ECDSA-HSS-001

Target:

- canonical `x` derivation

Property:

- for fixed `(y_client, y_relayer, context)`, canonical `x` derivation is
  deterministic and always yields a valid non-zero secp256k1 scalar

### FV-ECDSA-HSS-002

Target:

- additive-share derivation

Property:

- `x = x_client + x_relayer mod n`
- `x_client != 0`
- `x_relayer != 0`
- retry-counter logic is deterministic and sufficient for the fixed v1 rule

### FV-ECDSA-HSS-003

Target:

- current 2P additive-share mapping layer

Property:

- mapping additive shares into the `threshold-signatures` share encoding
  preserves the same effective group secret for participant IDs `{1, 2}`

### FV-ECDSA-HSS-004

Target:

- exported-key and threshold-public-key equivalence

Property:

- the public key derived from exported `x` equals the threshold signing public
  key

### FV-ECDSA-HSS-005

Target:

- exported-key and threshold-address equivalence

Property:

- the Ethereum address derived from exported `x` equals the threshold signing
  address

### FV-ECDSA-HSS-006

Target:

- output-policy boundary

Property:

- non-export operations cannot return canonical `x`
- only explicit export can return canonical `x`

### FV-ECDSA-HSS-007

Target:

- retained-state boundary

Property:

- forbidden root material is not retained past the accepted staged boundary

## Phased Todo List

### Phase 0: Bootstrap

- [x] create `crates/ecdsa-hss/formal-verification/docs/proof-inventory.md`
- [x] create `crates/ecdsa-hss/formal-verification/verus/`
- [x] add `verus/README.md`
- [x] add `verus/docs/implementation-plan.md`
- [x] add `verus/Cargo.toml`
- [x] add `verus/src/lib.rs`
- [x] mirror the future production module layout minimally under `verus/src/`
- [x] wire repo-local wrapper commands for `ecdsa-hss` verification

### Phase 1: Fixed-Function And Share Derivation

- [x] add a Verus module for canonical `x` derivation
- [x] prove deterministic canonical `x` derivation
- [x] prove canonical `x` is always in the valid non-zero scalar domain
- [x] add a Verus module for additive-share derivation
- [x] prove `x = x_client + x_relayer mod n`
- [x] prove both shares are non-zero
- [x] prove retry-counter determinism for the frozen v1 rule
- [x] connect the proof layer to a fixture corpus once vectors exist

### Phase 2: Mapping And Backend Equivalence

- [x] mirror the current additive-share mapping logic in the Verus track
- [x] prove that mapping preserves the effective group secret for `{1, 2}`
- [x] prove the mapped shares are accepted by the current backend domain rules
- [x] prove that the threshold public key equals `x * G`
- [x] prove that the threshold signing address equals `addr(x * G)`

### Phase 3: Output-Policy And Boundary Invariants

- [x] define the narrow runtime/output boundary model in Verus
- [x] prove non-export operations cannot return canonical `x`
- [x] prove explicit export is the only operation that can return canonical `x`
- [x] prove retained-state exclusions for forbidden root material
- [x] add anti-drift checks between production code and the Verus mirror

### Phase 4: Decide Aeneas + Lean Expansion

- [x] decide whether the Rust boundary is stable enough to justify extraction
- [x] if yes, create `formal-verification/lean-boundary/`
- [x] install the pinned Aeneas/Charon toolchain locally
- [x] generate the first Rust-derived Lean boundary artifact
- [x] keep generated modules separate from handwritten Lean bridge lemmas
- [x] if yes, create `formal-verification/lean-privacy/`
- [x] freeze the extraction target to the narrow non-export/export boundary
- [x] keep broader protocol/privacy expansion out of scope until the first
      boundary bridge works

### Phase 5: Hidden-Eval And Runtime-Boundary Expansion

This phase is intentionally narrower than "prove the full runtime."

It should focus on the next proof boundary that materially strengthens the
current privacy story:

- hidden-eval/compiler-boundary correctness
- transport/state exclusion guarantees at the message and persisted-state seam

It should explicitly not try to prove:

- end-to-end runtime orchestration correctness
- side-channel resistance
- full system behavior outside the frozen boundary slice

- [x] freeze the hidden-eval-facing Rust boundary spec that the privacy story
      depends on
- [x] define the exact extracted Rust facade for the hidden-eval/compiler seam
- [x] add a separate Aeneas + Lean bridge for that hidden-eval/compiler seam
- [x] prove the generated hidden-eval/compiler boundary matches the handwritten
      privacy model
- [x] add an explicit transport-visible message model for non-export vs
      explicit-export flows
- [x] add an explicit persisted-runtime-state model for the staged server path
- [x] prove forbidden secret material is absent from transport-visible
      non-export messages
- [x] prove forbidden secret material is absent from persisted staged runtime
      state after the accepted boundary
- [x] prove explicit export remains the only allowed disclosure exception at
      the transport/state layer
- [ ] keep side-channel resistance in a separate security-engineering plan
      rather than this formal-verification phase

### Phase 6: True-Blind ECDSA HSS V2

This phase is the Lean-first track for replacing joined-root ECDSA HSS
derivation with role-local additive share derivation.

- [x] add the initial Lean scaffold in
      [lean-privacy/EcdsaHssPrivacy/TrueBlindV2.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/formal-verification/lean-privacy/EcdsaHssPrivacy/TrueBlindV2.lean)
- [x] model role-local client and server private inputs
- [x] model role-local `x_client` and `x_relayer` derived shares
- [x] model non-export client and server views
- [x] model explicit-export client and server views
- [x] add first exclusion theorems for forbidden fields in non-export views
- [x] add named algebraic obligations for public-key agreement and export
      verification
- [ ] replace named algebraic obligations with concrete Lean relations over
      scalar addition and public-key addition
- [ ] define `F_ecdsa_hss_true_blind_v2` as the ideal functionality
- [ ] add simulator definitions from own share plus public identity
- [ ] add non-derivability theorems for client-secret and server-secret variation
- [ ] update the Verus mirror only after the Lean v2 boundary settles
- [ ] extract the v2 Rust boundary with Aeneas after implementation lands

## Current Recommendation

If we want verification work that helps implementation soonest, do this:

1. start with Verus
2. prove canonical `x`, additive-share derivation, and mapping correctness
3. generate the fixture corpus in parallel
4. add Aeneas + Lean only after the Rust boundary is stable enough to extract
5. after the current frozen boundary work is complete, expand next into
   hidden-eval/compiler-boundary correctness and transport/state exclusion

## Short Answer

Which is better for `ecdsa-hss` right now?

- **Verus** for the first implementation-proof pass
- **both** eventually, but only after the boundary is stable
