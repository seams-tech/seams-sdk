# `router-ab-ecdsa-derivation` Formal Verification Implementation Plan

Last updated: 2026-05-17

## Decision

The recommended verification strategy is:

- **Verus first**
- **Aeneas + Lean later**

The first high-value proof targets for the existing `router-ab-ecdsa-derivation` implementation
are implementation-facing algebraic invariants over Rust-shaped code and data.
Aeneas + Lean remains valuable once a stable boundary slice exists.

## Why Verus Is The Better First Tool

The first `router-ab-ecdsa-derivation` proof targets are:

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

For `router-ab-ecdsa-derivation`, that likely means:

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

### FV-Router A/B ECDSA derivation-001

Target:

- canonical `x` derivation

Property:

- for fixed `(y_client, y_relayer, context)`, canonical `x` derivation is
  deterministic and always yields a valid non-zero secp256k1 scalar

### FV-Router A/B ECDSA derivation-002

Target:

- additive-share derivation

Property:

- `x = x_client + x_relayer mod n`
- `x_client != 0`
- `x_relayer != 0`
- retry-counter logic is deterministic and sufficient for the fixed v1 rule

### FV-Router A/B ECDSA derivation-003

Target:

- current 2P additive-share mapping layer

Property:

- mapping additive shares into the `threshold-signatures` share encoding
  preserves the same effective group secret for participant IDs `{1, 2}`

### FV-Router A/B ECDSA derivation-004

Target:

- exported-key and threshold-public-key equivalence

Property:

- the public key derived from exported `x` equals the threshold signing public
  key

### FV-Router A/B ECDSA derivation-005

Target:

- exported-key and threshold-address equivalence

Property:

- the Ethereum address derived from exported `x` equals the threshold signing
  address

### FV-Router A/B ECDSA derivation-006

Target:

- output-policy boundary

Property:

- non-export operations cannot return canonical `x`
- only explicit export can return canonical `x`

### FV-Router A/B ECDSA derivation-007

Target:

- retained-state boundary

Property:

- forbidden root material is not retained past the accepted staged boundary

## Phased Todo List

### Phase 0: Bootstrap

- [x] create `crates/router-ab-ecdsa-derivation/formal-verification/docs/proof-inventory.md`
- [x] create `crates/router-ab-ecdsa-derivation/formal-verification/verus/`
- [x] add `verus/README.md`
- [x] add `verus/docs/implementation-plan.md`
- [x] add `verus/Cargo.toml`
- [x] add `verus/src/lib.rs`
- [x] mirror the future production module layout minimally under `verus/src/`
- [x] wire repo-local wrapper commands for `router-ab-ecdsa-derivation` verification

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

### Phase 6: True-Blind Router A/B ECDSA derivation

This phase is the Lean-first track for replacing joined-root Router A/B ECDSA derivation
derivation with role-local additive share derivation.

- [x] add the initial Lean scaffold in
      [lean-privacy/RouterAbEcdsaDerivationPrivacy/TrueBlind.lean](/Users/pta/Dev/rust/simple-threshold-signer/crates/router-ab-ecdsa-derivation/formal-verification/lean-privacy/RouterAbEcdsaDerivationPrivacy/TrueBlind.lean)
- [x] model role-local client and server private inputs
- [x] model role-local `x_client` and `x_relayer` derived shares
- [x] model non-export client and server views
- [x] model explicit-export client and server views
- [x] add first exclusion theorems for forbidden fields in non-export views
- [x] add named algebraic obligations for public-key agreement and export
      verification
- [x] replace named algebraic obligations with concrete Lean relations over
      scalar addition and public-key addition
- [x] define `F_router_ab_ecdsa_derivation_true_blind` as the ideal functionality
- [x] add simulator definitions from own share plus public identity
- [x] add first non-derivability theorems for client-secret and server-secret
      variation over non-export views
- [x] add explicit derivation assumptions for the Rust/Verus proof boundary
- [x] prove ideal-functionality well-formedness under those assumptions
- [x] prove export reconstruction and shared-public-identity properties for the
      ideal functionality
- [x] add typed operation views and prove the disclosure policy for non-export
      and explicit-export flows
- [x] model allowed public transcript fields and prove transcripts exclude
      root/share/canonical-secret payloads
- [x] add the Lean role-local boundary contract for client bootstrap wire, server
      bootstrap wire, retained client/server state, explicit export wire, and
      client export reconstruction
- [x] prove the role-local boundary contract excludes forbidden
      root/share/canonical-secret payloads
- [x] prove client export reconstruction from the explicit export wire matches
      the ideal explicit-export client view and verifies against public key `X`
- [x] add an authorized explicit-export envelope with transcript-bound
      authorization
- [x] prove only explicit-export wire can carry the relayer export share
- [x] prove all active wire-envelope variants exclude client root/share material
      and canonical `x`
- [x] add a bound explicit-export session tying client retained state, export
      authorization, and export wire to the same public identity/context
- [x] prove bound-session reconstruction preserves the authorized public identity
      and matches the ideal explicit-export client view
- [x] add a bound role-local signing-session model tying retained client/server
      state to the same public identity/context
- [x] prove mismatched public identity or context prevents constructing a bound
      role-local signing session
- [x] prove state-derived role-local signing sessions reconstruct the same scalar
      and verify against public key `X`
- [x] add a digest-valid export authorization predicate for explicit-export
      envelopes
- [x] prove state-created export envelopes carry valid authorization digests
- [x] prove malformed authorization digests prevent valid explicit-export
      envelopes
- [x] prove a valid role-local envelope carrying the relayer export share must be
      an authorized explicit-export wire
- [x] update the Verus mirror now that the Lean boundary has settled
- [x] align the Verus context mirror with the fixed `evm-family` key scope
- [ ] extract the Rust boundary with Aeneas after implementation lands

## Current Recommendation

For the true-blind replacement, continue in this order:

1. implement the role-local Rust protocol
2. extend Verus to cover role-local derivation, public-key addition, export
   isolation, and production anti-drift checks
3. extract the Rust boundary with Aeneas
4. bridge the generated boundary back to the Lean model

## Short Answer

Which is better for `router-ab-ecdsa-derivation` right now?

- **Lean first** for the true-blind replacement boundary
- **Verus next** for implementation-facing Rust invariants
- **Aeneas + Lean bridge** after the Rust boundary exists

