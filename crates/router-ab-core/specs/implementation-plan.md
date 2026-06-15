# Split Derivation Primitive Implementation Plan

This plan scopes the Rust crate that will decide and implement the
Router/A/B split-derivation primitive.

## Implementation Rule

Candidate comparison has selected `mpc_threshold_prf_v1` for the production
path. New production work should implement the thin `threshold-prf` adapter,
freeze Candidate A vectors, and keep `split_root_derivation_v1` as
comparison/prototype material until a later decision record re-opens its
root-generation, anti-bias, refresh, and address-verification gates.

## Spec Documents

- [derivation-goals.md](derivation-goals.md): crate scope and target invariant
- [spec-review.md](spec-review.md): review findings and missing details that
  block candidate implementation
- [threat-model.md](threat-model.md): corruption matrix and security claims
- [encoding-and-transcript.md](encoding-and-transcript.md): canonical encoding,
  transcript digest, identity format, and domain labels
- [envelopes-and-delivery.md](envelopes-and-delivery.md): encrypted envelope
  headers, AAD, delivery packages, and retry rules
- [minimum-level-c.md](minimum-level-c.md): first correctness-level verifier,
  evidence, residual risk, and error mapping
- [public-share-binding.md](public-share-binding.md): stronger correctness path
  and candidate-specific hardening hooks
- [candidate-mpc-threshold-prf.md](candidate-mpc-threshold-prf.md):
  threshold-PRF candidate state, flow, partials, and open items
- [candidate-split-root.md](candidate-split-root.md): split-root candidate
  state, flow, candidate formula, refresh risk, and open items
- [state-machine.md](state-machine.md): ceremony states, transition ownership,
  replay cache, retries, and activation rules
- [refresh-context.md](refresh-context.md): request-scope enum, refresh epochs,
  activation, and address verification evidence
- [errors-and-diagnostics.md](errors-and-diagnostics.md): stable error codes,
  redacted diagnostics, and source guards
- [secret-classification.md](secret-classification.md): public, metadata,
  encrypted, role-local, recipient, and forbidden secret classes
- [vector-matrix.md](vector-matrix.md): committed vector corpus layout and cases
- [api-shape.md](api-shape.md): intended public Rust API boundaries
- [protocol-spec.md](protocol-spec.md): role behavior, ceremonies, transcript
  binding, errors, persistence, and constant-time requirements
- [invariants-and-behaviors.md](invariants-and-behaviors.md): state,
  context, transcript, replay, diagnostics, candidate, and FV requirements
- [candidate-comparison.md](candidate-comparison.md): candidate decision
  questions
- [phase-0a-decision-record.md](phase-0a-decision-record.md): side-by-side
  evidence snapshot and decision guidance
- [measurement-gates.md](measurement-gates.md): typed Phase 6 measurement
  gates and current evidence snapshot
- [vector-format.md](vector-format.md): JSON vector format
- [leakage-analysis.md](leakage-analysis.md): leakage table requirements
- [refresh-rotation.md](refresh-rotation.md): refresh and root rotation rules
- [benchmarking.md](benchmarking.md): benchmark gates

## Phase TODO List

### Phase 0: Scaffold

- [x] Create `crates/router-ab-core`
- [x] Add typed derivation context
- [x] Add transcript-binding digest helper
- [x] Add candidate identifiers
- [x] Add vector parser
- [x] Add leakage checklist scaffold
- [x] Add benchmark scaffold
- [x] Add Verus and Lean folder scaffolding

### Phase 1: Full Specs, Invariants, And Behaviors

- [x] Add candidate-neutral protocol spec
- [x] Add invariant and behavior checklist
- [x] Review specs for implementation readiness
- [x] Add threat model and claim matrix
- [x] Add field-level encoding and transcript tables
- [x] Add envelope and delivery boundary spec
- [x] Add Minimum Level C verification spec
- [x] Add candidate-specific spec files
- [x] Add state-machine ownership spec
- [x] Add refresh context-extension spec
- [x] Add error and diagnostics contract
- [x] Add secret/public classification contract
- [x] Add vector matrix
- [x] Add public Rust API shape
- [x] Model Router A/B v1 transcript internals around a deriver-set and indexed
      role-envelope shape while enforcing `all(2)`
- [ ] Fill exact registration flow for `mpc_threshold_prf_v1`
- [ ] Fill exact export flow for `mpc_threshold_prf_v1`
- [ ] Fill exact refresh flow for `mpc_threshold_prf_v1`
- [ ] Fill exact registration flow for `split_root_derivation_v1`
- [ ] Fill exact export flow for `split_root_derivation_v1`
- [ ] Fill exact refresh flow for `split_root_derivation_v1`
- [ ] Write A/B state visibility tables for each candidate flow
- [ ] Write Router, client, and server visibility tables for each candidate
      flow
- [x] Decide candidate A preferred combine location: recipient-side combine
- [x] Specify Minimum Level C transcript checks in field-level detail
- [x] Specify public-share-binding hardening checks in field-level detail
- [x] Specify replay, idempotency, and retry behavior
- [x] Specify refresh-specific context extension for old and new epochs
- [x] Specify all typed error codes required by adapters
- [x] Specify diagnostic redaction rules as source-guard patterns
- [ ] Resolve whether `split_root_derivation_v1` can preserve existing account
      output relations through refresh
- [ ] Resolve whether `mpc_threshold_prf_v1` proof verification is included in
      Minimum Level C or deferred to stronger hardening
- [ ] Choose envelope authentication mode
- [ ] Choose candidate-specific proof formats
- [x] Choose provisional Candidate B `HashToScalar` and scalar-share encoding
      for measurement: SHA-512 transcript to Curve25519 scalar, fixed 32-byte
      canonical scalar-share wires
- [ ] Confirm product acceptance of the threat-claim matrix

### Phase 2: Formal Verification Spec Gate

- [ ] Translate state invariants into Verus model obligations
- [ ] Translate role-view privacy into Lean model obligations
- [ ] Define state-machine transition predicates
- [ ] Define context encoding field-order proof target
- [ ] Define transcript binding field-inclusion proof target
- [ ] Define recipient separation proof target
- [ ] Define epoch separation proof target
- [ ] Define secret-classification proof assumptions
- [ ] Define Minimum Level C evidence binding proof target
- [ ] Define replay-cache proof target
- [ ] Define vector anti-drift test format for proof crates
- [ ] Mark cryptographic assumptions that proofs will not cover
- [ ] Add proof inventory entries for every required invariant

### Phase 2A: Contract Scaffold Implementation

- [x] Expand stable error codes and redacted diagnostics
- [x] Add public digest wrappers
- [x] Add context digest helper
- [x] Add deriver-set-based transcript digest helper with v1 `all(2)` enforcement
- [x] Add request-scope types for registration, export, and refresh
- [x] Add refresh old/new epoch validation
- [x] Add envelope public-header type
- [x] Add envelope AAD helper
- [x] Add delivery package commitment helper
- [x] Add envelope idempotency helper
- [x] Add Minimum Level C evidence structs and verifier
- [x] Add branch-specific ceremony state builders
- [x] Add vector generation for context, transcript, envelopes, diagnostics, and
      Minimum Level C
- [x] Add source guards for redaction and forbidden joined-state exposure

### Phase 3: Vector Corpus

- [x] Commit generated contract vector fixture for context, transcript,
      envelope, diagnostics, and Minimum Level C
- [x] Add anti-drift test comparing committed contract fixture to generator
- [x] Add transcript digest vectors
- [x] Add registration success vectors
- [x] Add Minimum Level C rejection vectors
- [x] Add deriver identity mismatch vectors
- [x] Add root epoch mismatch vectors
- [x] Add transcript replay vectors
- [x] Add malformed envelope vectors
- [x] Add error-code vectors
- [x] Add redacted-diagnostics vectors
- [x] Add refresh old/new epoch vectors
- [x] Replace placeholder fixture digests with committed context digests
- [x] Add export success vectors
- [x] Add refresh success vectors
- [x] Add candidate-specific output gate vectors

### Phase 4: Candidate A Spec And Prototype, MPC Threshold PRF

- [x] Decide whether to reuse `threshold-prf` or mirror a narrow primitive here
- [x] Define deriver partial input and output types
- [x] Define verified partial format
- [x] Define combiner behavior
- [x] Define all A/B coordination messages
- [x] Define recipient encryption boundary
- [x] Define constant-time handling requirements for secret partials
- [x] Add Router/A/B purpose-binding plan
- [x] Add partial verification tests
- [x] Add round-trip and latency benchmarks
- [x] Complete leakage table
- [x] Add Verus abstract model entries
- [x] Add Lean privacy state entries
- [x] Add `threshold-prf` compatibility for Router/A/B purpose labels and
      canonical scalar output

### Phase 5: Candidate B Spec And Prototype, Split Root Derivation

- [x] Define A/B root material
- [x] Define role-separated derivation labels
- [x] Define output-share derivation formula
- [x] Define refresh formula
- [x] Define recipient encryption boundary
- [x] Define all A/B coordination messages
- [x] Define constant-time handling requirements for root-share operations
- [x] Add real `HashToScalarSha512V1` output-share derivation
- [x] Add real scalar-share combine path
- [x] Add canonical and non-canonical scalar-share tests
- [x] Add success and rejection tests
- [x] Add round-trip and latency benchmarks
- [x] Add native cryptographic-path benchmarks
- [x] Complete leakage table
- [x] Add Verus abstract model entries
- [x] Add Lean privacy state entries

### Phase 6: Candidate Selection

- [x] Compare selection-critical latency and round trips
  - [x] Capture native adapter latency baseline
  - [x] Compare adapter round-trip shape
  - [x] Check wasm32 library build compatibility
  - [x] Add typed measurement gate report
  - [x] Add Candidate A purpose-binding adapter plan
  - [x] Capture Candidate A cryptographic-path native latency
  - [x] Capture Candidate B cryptographic-path native latency
  - [x] Complete cryptographic-path native latency comparison
  - [x] Record final side-by-side decision evidence
  - [ ] Capture deployable wasm or Worker bundle size
  - [ ] Capture Cloudflare Worker runtime latency if Workers are first target
- [x] Compare implementation complexity
- [x] Compare leakage tables
- [x] Compare proof effort
- [x] Select production candidate: `mpc_threshold_prf_v1`
- [x] Keep losing candidate code paths only as comparison/prototype material
- [ ] Freeze vector format for the selected candidate

### Phase 7: Production Primitive

- [x] Add initial production `threshold-prf` backend adapter for
      `mpc_threshold_prf_v1`
- [x] Add Router/A/B-owned signing-root-share wire wrapper
- [x] Add deriver proof-bundle evaluation through `threshold-prf`
- [x] Add proof verification and recipient-side verified combine through
      `threshold-prf`
- [x] Freeze Candidate A vectors around backend partials, commitments, proofs,
      verified-combine outputs, and rejection cases
- [x] Update Router/A/B threshold-prf adapter plan to target
      `threshold_prf` with an explicit threshold policy.
- [x] Add Router/A/B threshold-prf protocol-selection type that normalizes to
      `ThresholdPolicy`.
- [x] Migrate Candidate A signer and combiner backend imports from the
      fixed-pair backend to `threshold_prf` with initial policy `2-of-3`.
- [x] Update Candidate A backend wire wrappers and source guards for signing-root, partial, and commitment widths.
- [x] Add Router/A/B parity tests against the committed threshold-prf `2-of-3` fixture.
- [ ] Replace candidate placeholder entry point with selected implementation
- [ ] Add constant-time review for secret-dependent control flow
- [ ] Add source guards for joined-state construction
- [ ] Add fuzz or property tests for context and transcript parsing
- [x] Add wasm build check
- [ ] Add Workers adapter integration tests outside this crate
- [ ] Add release-gate checklist to Router/A/B deployment plan

### Phase 8: Formal Verification Implementation

- [ ] Mirror the selected Rust formulas in Verus
- [ ] Prove context field inclusion and order
- [ ] Prove transcript field inclusion and order
- [ ] Prove role output separation in the abstract model
- [ ] Prove no single modeled role view contains joined forbidden state
- [ ] Add anti-drift tests from committed vectors
- [ ] Add Lean privacy model for execution-state visibility
- [ ] Consider Aeneas extraction after Rust APIs stabilize

### Phase 9: Release Readiness

- [ ] Run native tests
- [ ] Run wasm build check
- [ ] Run benchmark suite
- [ ] Run source guards
- [ ] Run vector anti-drift checks
- [ ] Run available Verus checks
- [ ] Run available Lean checks
- [ ] Confirm address verification gate for root rotation
- [ ] Update Router/A/B deployment plan with selected primitive details

## Open Decisions

- Deployable Worker size and runtime budget for the selected candidate
- Canonical encoding family for selected production vectors
- Whether Candidate A DLEQ verification ships in the first production path or
  remains stronger hardening after Minimum Level C

## Release Gates

Before this crate can be used by production Router/A/B ceremonies:

- vectors cover registration, export, and refresh
- leakage table passes the target invariant
- benchmarks cover native and wasm builds
- source guards reject forbidden joined-state construction
- address verification passes before root rotation
- formal proof inventory names all deferred claims explicitly
