# ecdsa-hss Implementation Plan

Date created: April 8, 2026

Removal note: this implementation plan predates the v3 invalidation. The active
crate removed the old ECDSA HSS context version and now receives only an opaque
SDK-owned application binding digest for role-local derivation.

## Summary

`ecdsa-hss` is a proposed sibling crate to
[ed25519-hss](/Users/pta/Dev/rust/simple-threshold-signer/crates/ed25519-hss).

Its purpose is to give the existing EVM-compatible threshold ECDSA signer a
single canonical private-key lane that is:

- threshold-signable
- exportable
- deterministic
- server-blind

The end state is not "threshold ECDSA plus a second export key." The end state
is:

- one canonical secp256k1 private key
- one corresponding Ethereum address
- threshold signing uses shares derived from that key
- export returns that same key
- the server can assist without ever learning the canonical private key

This is a new crate and a new protocol effort. It is not a small extension of
the current threshold ECDSA bootstrap flow.

## Why A Separate Crate

The current threshold ECDSA path and `ed25519-hss` solve different problems.

Today:

- threshold ECDSA signing uses a threshold secp256k1 key built from:
  - a client share derived from `PRF.first`
  - a relayer share derived from the relayer master secret
- EVM private-key export uses a separate deterministic secp256k1 key derived
  from `PRF.second`

That means the current EVM model effectively has two key lanes:

- threshold signing key
- exportable recovery key

`ecdsa-hss` exists to replace that two-key model with a one-key model.

It should be developed separately because:

- the cryptographic design is materially different from the current threshold
  ECDSA flow
- the failure mode for a half-migrated implementation is severe confusion
- we do not want legacy ECDSA-share bootstrap assumptions mixed into the new
  design

## Primary Goal

Build a server-blind threshold ECDSA protocol for EVM chains where:

- the canonical exportable secp256k1 secret is never visible to the server
- threshold signing and export refer to the same logical key
- the resulting signatures remain standard ECDSA / secp256k1 / Ethereum
  compatible

## Non-Goals

This effort should not:

- add a second ECDSA export lane
- preserve the current "threshold key plus sidecar export key" model
- claim Schnorr-like simplicity where ECDSA imposes different constraints
- weaken the signing or export boundary to chase performance
- merge partial `ecdsa-hss` logic directly into the existing threshold ECDSA
  runtime before the protocol is stable

## Hard Requirements

The crate is only successful if all of these are true.

### 1. Single-Key Invariant

The exported private key must correspond to the exact same public key and
Ethereum address used by threshold signing.

In concrete terms:

- `ecdsa_hss_export_secret -> secp256k1 public key -> Ethereum address`
- threshold group public key and threshold signing address must match that same
  result

If this invariant does not hold, then `ecdsa-hss` has recreated the current
two-key problem in a more complicated form.

### 2. Server-Blindness

The server must not learn the canonical secp256k1 private key, even when it:

- assists with key setup
- assists with signing
- assists with export preparation

### 3. Standard EVM Compatibility

The signing output must remain standard ECDSA/secp256k1-compatible for:

- Ethereum transaction signing
- `ecrecover`-style public-key recovery
- standard wallet and RPC tooling

### 4. Explicit Export Policy

Export must be:

- explicit
- policy-bound
- auditable

It must not fall out accidentally from a signing flow or a cached ceremony.

## High-Level Architecture

The target shape should mirror the good parts of `ed25519-hss`, but not assume
the same math.

### Canonical Secret Root

`ecdsa-hss` should define one canonical exportable secp256k1 secret root.

There are two plausible representations:

- a canonical private scalar `x`
- a canonical seed that deterministically expands into `x`

The default design target should be the simpler one:

- a canonical secp256k1 private scalar `x`

That keeps the equivalence condition straightforward:

- threshold public key must equal `x * G`
- export returns `x`

If later implementation constraints make a seed-first design better, the seed
must still deterministically map to one canonical scalar and one canonical
Ethereum address.

### Threshold Share Derivation

The threshold signer should be derived from that canonical secret, not operate
as an unrelated threshold keygen lane.

The clean target is:

- hidden joint derivation of a canonical secret root
- deterministic derivation of threshold signing shares from that root
- threshold signing protocol consumes those derived shares

### Separate Integration Layer

The repo's current threshold-signatures-based EVM threshold ECDSA backend
should remain the integration target, not the design source of truth.

That means:

- `ecdsa-hss` defines the canonical-key and export semantics
- the existing threshold ECDSA runtime is adapted to consume `ecdsa-hss`
  material
- not the other way around

## Core Research Question

The main research question is:

How do we derive threshold ECDSA signing shares from a canonical hidden
secp256k1 secret such that:

- the group public key equals the public key of the canonical secret
- threshold signing remains secure
- the server stays blind to the canonical secret

This is the main reason `ecdsa-hss` is harder than `ed25519-hss`.

With `ed25519-hss`, the hidden deterministic secret and the signing lane fit
cleanly into a Schnorr-style model. For ECDSA, nonce handling and the signing
equation are more fragile.

## Candidate Design Directions

### Direction A: Hidden Canonical Secret, Deterministic Threshold Shares

This is the preferred design direction.

Shape:

1. Client and server hold root shares.
2. `ecdsa-hss` computes a canonical hidden secp256k1 secret root.
3. The crate derives threshold signing shares deterministically from that root.
4. Threshold ECDSA signing operates on those shares.
5. Export returns the canonical secret root.

Pros:

- clean one-key model
- export is obviously the threshold key
- easiest model to specify and audit

Cons:

- requires a threshold ECDSA share-derivation model that is compatible with
  the current signing backend or a replacement backend

### Direction B: Hidden Canonical Seed, Deterministic Threshold Keygen

Alternative shape:

1. `ecdsa-hss` computes a canonical hidden seed.
2. The seed deterministically expands into a canonical secp256k1 scalar and
   threshold signing-share inputs.
3. Export returns the seed or the derived canonical scalar.

Pros:

- flexible if we later need more than one deterministic EVM artifact

Cons:

- introduces an extra layer between the exported object and the actual private
  scalar
- increases proof and audit surface

### Direction C: Adapt The Current Threshold ECDSA Backend As-Is

This is not the preferred plan.

Trying to directly bolt HSS export onto the current:

- `PRF.first` client-share lane
- relayer master-secret lane

is likely to preserve the current two-key mismatch under a different name.

This direction should be rejected unless it can prove the single-key invariant
cleanly.

## Recommended Implementation Strategy

Build `ecdsa-hss` as a separate crate with phases similar to `ed25519-hss`,
but adapted for ECDSA.

## Phase 0: Specs First

Write the specs before writing production code.

Deliverables:

- `README.md`
- `security.md`
- `specs/protocol.md`
- `specs/export.md`
- `specs/integration-cait-sith-backend.md`

The specs must define:

- the canonical export object
- the threshold/public-key equivalence invariant
- the server-blindness boundary
- explicit export policy
- retained-state rules
- what the integration layer is allowed to cache or persist
- the fixed v1 signer set and participant-ID scope

Exit criteria:

- the crate can state exactly what it exports
- the crate can state exactly why threshold signing and export refer to the
  same key

Todo:

- [x] define the canonical export object: scalar-first or seed-first
- [x] write the single-key invariant precisely
- [x] define the signing/export policy boundary
- [x] define the retained-state boundary
- [x] freeze the fixed v1 scope: 2-of-2 only, participant IDs `{1, 2}`
- [x] freeze the exact `encode_context_v1` byte contract
- [x] define how the integration layer proves that the threshold public key
      matches the export key

## Phase 1: Fixed-Function Prototype

Build the hidden deterministic derivation layer first, before threshold signing
integration.

Deliverables:

- deterministic client/server root-share input model
- fixed-function derivation for the canonical secp256k1 secret root
- test vectors for:
  - canonical secret root
  - corresponding compressed public key
  - corresponding Ethereum address

This phase should mirror the discipline of `ed25519-hss`:

- small fixed function
- deterministic fixture corpus
- zero ambiguity about what the canonical secret is

Exit criteria:

- a fixed-function corpus exists and is stable
- the canonical secret maps deterministically to one public key and one
  Ethereum address

Todo:

- [x] define the root-share input domain
- [x] define the fixed function for canonical secret derivation
- [x] publish vectors for `encode_context_v1` byte encoding
- [x] publish fixtures for secret/public key/address equivalence
- [x] publish fixtures for additive share derivation and retry-counter
- [x] publish fixtures for mapped backend shares for participant IDs `{1, 2}`
- [ ] build cross-language test vectors if the client runtime will participate

## Phase 2: Server-Blind Hidden Evaluation

Implement the HSS-like hidden evaluation layer for the canonical ECDSA secret
derivation.

Deliverables:

- client/server hidden derivation protocol
- server-owned staged boundary
- no direct exposure of the canonical secret to the server

This phase should borrow the good architecture from `ed25519-hss`:

- explicit staged boundary
- clear retained-state rules
- no joined-input legacy seam

Exit criteria:

- the server can assist in deriving threshold-signing material without seeing
  the canonical secret

Todo:

- [x] define the staged server-owned execution model
- [x] define retained-state exceptions precisely
- [x] implement fixtures and determinism tests for the hidden derivation path
- [x] add boundary tests for "server cannot derive the canonical secret"

## Phase 3: Threshold ECDSA Share Derivation

This is the most important phase.

Translate the canonical secret root into threshold signing shares in a way that
preserves:

- standard ECDSA compatibility
- threshold signing security
- the single-key invariant

Deliverables:

- derived threshold share representation
- deterministic mapping from canonical secret root to threshold share state
- proof-oriented statement of why the threshold public key equals the exported
  key's public key

Exit criteria:

- the same canonical key is used for both export and threshold signing

Todo:

- [x] define the share-derivation algorithm
- [x] guarantee derived additive shares are valid non-zero scalars accepted by
      the current mapping layer
- [x] define how relayer/client roles map onto those derived shares
- [x] prove or mechanically check public-key equivalence
- [x] add negative tests for accidental two-key divergence

## Phase 4: Current EVM Threshold Backend Integration

Only after Phases 0-3 are stable should the current threshold ECDSA signer be
adapted.

The integration goal is:

- replace the current `PRF.first + relayer master secret` bootstrap model
- keep standard signing endpoints and EVM outputs
- make export return the threshold key, not a sidecar key

Deliverables:

- adapter from `ecdsa-hss` canonical-key/share outputs into the current
  threshold ECDSA runtime
- migration strategy for registration/login/export/signing flows
- removal plan for the separate `prfSecond`-derived export lane

Exit criteria:

- EVM signing uses the `ecdsa-hss` key
- EVM export returns that same key
- the server still never sees the canonical private key

Todo:

- [x] identify the exact integration seam in the current threshold ECDSA
      bootstrap flow
- [x] define how session bootstrapping consumes `ecdsa-hss` material
- [x] define migration from the current two-key model
- [ ] remove the sidecar export lane once the new path is complete

## Phase 5: Export Policy And UX

Once the protocol is stable, bind export behavior at the product boundary.

Deliverables:

- explicit export operation type
- export UI and policy checks
- audit logs or telemetry that distinguishes signing from export

Exit criteria:

- export cannot be triggered accidentally from a signing session
- export always returns the canonical threshold private key

Todo:

- [x] define export-only operation type
- [x] define export policy checks
- [x] ensure signing sessions cannot request export material
- [x] ensure export path returns the exact same public key/address as signing

## Phase 6: Verification And Audit Track

As with `ed25519-hss`, this needs a verification track, not just unit tests.

Deliverables:

- formal verification scope document
- implementation plan for proof-oriented invariants
- proof inventory

The highest-priority invariants are:

- exported private key public key == threshold signing public key
- server never learns the canonical private key
- non-export signing flows never expose export-capable output
- retained state does not preserve forbidden root material past the accepted
  boundary

Exit criteria:

- there is a clear proof/audit plan for the single-key and server-blindness
  invariants

Todo:

- [x] define formal verification scope
- [x] define proof inventory for single-key equivalence
- [x] define proof inventory for export-policy binding
- [x] define retained-state boundary proofs or proof obligations

## Suggested Crate Layout

When implementation begins, the crate should look structurally familiar:

```text
crates/ecdsa-hss/
  README.md
  security.md
  optimizations.md
  quantum.md
  specs/
    protocol.md
    export.md
    integration-cait-sith-backend.md
  docs/plans/
    implementation-plan.md
    refactor-1.md
    boundary.md
    optimization-v1.md
  src/
    client/
    server/
    wire/
    fixtures.rs
    lib.rs
```

The point is not to clone `ed25519-hss` mechanically. The point is to keep the
same level of clarity:

- specs first
- fixed-function fixtures
- explicit boundary
- explicit optimization log

## Integration Risks

### Risk 1: Recreating The Two-Key Model

If threshold signing shares are derived from one lane and export from another,
the crate has failed its main goal.

Mitigation:

- enforce the single-key invariant everywhere
- test public-key equivalence on every integration path

### Risk 2: Server-Blindness Drift

It is easy to accidentally persist too much server-side material in the name of
performance or convenience.

Mitigation:

- write retained-state rules early
- add boundary tests before optimization work

### Risk 3: Product-Level Confusion During Migration

The current product already has an exportable `secp256k1` lane.

Mitigation:

- keep `ecdsa-hss` isolated until it can replace the current model cleanly
- do not mix partial `ecdsa-hss` semantics into the old flow

### Risk 4: Threshold ECDSA Backend Mismatch

The current signer may not be a clean fit for deterministic share derivation
from a canonical hidden secret.

Mitigation:

- treat the current backend as an integration target, not a constraint
  that forces the wrong protocol
- if necessary, revise the threshold ECDSA backend instead of bending
  `ecdsa-hss` into a two-key design

## Success Criteria

`ecdsa-hss` is successful only if all of these are true:

- there is exactly one canonical EVM private key per account
- threshold signing and export use that same key
- the Ethereum address is the same across signing and export
- the server never learns the canonical private key
- export is explicit and policy-bound
- the current threshold ECDSA product path can migrate without preserving the
  old sidecar export lane

## Boundary-First Code Organization

Because `ecdsa-hss` will carry both implementation-facing proofs and
security/privacy audits, the crate should be organized so client-visible code
and server-owned code are cleanly separated.

The intended direction is:

- `src/client/`
  client-visible requests, responses, and client-side derivation helpers
- `src/server/`
  server-owned staged state, retained-state rules, and server-only ceremony
  logic
- `src/wire/`
  shared wire types and operation enums that legitimately cross the boundary
- shared root modules only for narrow fixed-function helpers that are truly
  boundary-neutral

Current state is now aligned with that goal:

- `src/client/`, `src/server/`, and `src/wire/` exist
- fixed-function shared helpers live under `src/shared/`
- the earlier mixed boundary layout has already been removed

## Uncertainties To Resolve Before Protocol Code

We can start Phase 0 immediately, but there are still real design questions to
settle before protocol implementation begins.

### 1. What exactly is the canonical export object?

Current recommendation:

- default to a canonical private scalar `x`

Still unresolved:

- whether a seed-first design would make share derivation or migration easier
- whether the product/export UX needs a seed artifact instead of a scalar

Why it matters:

- this choice affects the fixed function
- this choice affects the export format
- this choice affects how cleanly we can state the single-key invariant

Current stance:

- resolved for v1:
  - canonical export object is scalar `x`

### 2. How do threshold signing shares derive from the canonical key?

This is the biggest unresolved protocol question.

We need an answer for:

- how client and relayer shares are derived from the canonical hidden secret
- why the resulting threshold public key equals the public key of the exported
  key
- why the share derivation remains secure for ECDSA signing

Why it matters:

- this is the difference between a real one-key design and another disguised
  two-key design

Current stance:

- answered for the current crate direction in:
  - [share-derivation-design-memo.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/share-derivation-design-memo.md)

### 3. Can the current threshold-signatures-based EVM threshold ECDSA backend
consume deterministic share derivation cleanly?

We do not yet know whether the current backend:

- can accept externally derived share state directly
- can be adapted with a narrow integration seam
- or would need a deeper redesign

Why it matters:

- this determines whether `ecdsa-hss` can integrate with the current backend
  or whether the backend itself must change

Current stance:

- not blocked for early crate work
- blocked before Phase 4 integration begins

### 4. Can we safely reuse the current HSS substrate pattern?

We want to follow `ed25519-hss` structurally, but ECDSA changes the fixed
function and the signing backend.

Still unresolved:

- which parts of the staged boundary and fixture model carry over unchanged
- whether the current hidden-eval substrate can represent the needed fixed
  function without awkward workarounds

Why it matters:

- we want to reuse architecture, not force-fit the wrong math

Current stance:

- not blocked for Phase 0 docs
- should be reviewed before Phase 2 implementation

### 5. What migration story do we want for existing users?

The current product already has:

- a threshold ECDSA signing key
- a separate deterministic exportable secp256k1 key

Why it matters:

- this affects integration and rollout, not the core cryptography

Current stance:

- resolved for v1:
  - no in-place cryptographic migration
  - existing users must re-register into the new one-key model
  - the old `prfSecond` export lane is retired at cutover

### 6. What is the exact export policy surface?

We know export must be explicit and policy-bound, but the exact product/API
shape still needs to be fixed.

Still unresolved:

- whether export uses a distinct session operation type
- whether export requires stronger confirmation than signing
- what telemetry/audit requirements are mandatory

Current stance:

- not blocked for early protocol work
- should be defined before Phase 5 integration

## Questions That Should Be Answered Early

These are the specific questions worth answering in writing before protocol
code starts:

1. What deterministic function maps the hidden canonical secret into threshold
   ECDSA share state?
2. Can the current threshold ECDSA backend consume that share state directly?
3. What exact invariant proves that exported key, threshold public key, and
   Ethereum address are the same logical key?
4. What exact integration seam replaces the current threshold ECDSA bootstrap?

## Immediate Next Steps

1. Create the crate skeleton without production integration.
2. Write the Phase 0 specs first.
3. Decide the canonical export object:
   - scalar-first is the default recommendation
   - seed-first only if there is a strong implementation reason
4. Write a short design memo that answers one question explicitly:
   - how do threshold signing shares derive from the canonical secret while
     preserving ECDSA compatibility?
5. Only after that, start code.

## Detailed Todo List

### Phase 0: Crate Skeleton And Specs

- [x] create `crates/ecdsa-hss/Cargo.toml`
- [x] create `crates/ecdsa-hss/src/lib.rs`
- [x] create `crates/ecdsa-hss/README.md`
- [x] create `crates/ecdsa-hss/security.md`
- [x] create `crates/ecdsa-hss/optimizations.md`
- [x] create `crates/ecdsa-hss/specs/protocol.md`
- [x] create `crates/ecdsa-hss/specs/export.md`
- [x] create `crates/ecdsa-hss/specs/integration-cait-sith-backend.md`
- [x] create `crates/ecdsa-hss/docs/plans/refactor-1.md`
- [x] create `crates/ecdsa-hss/docs/plans/boundary.md`
- [x] create `crates/ecdsa-hss/docs/plans/optimization-v1.md`
- [x] write the canonical export object section
- [x] write the single-key invariant section
- [x] write the server-blindness boundary section
- [x] write the retained-state boundary section
- [x] write the explicit export-policy section
- [x] write the integration assumptions for the current threshold ECDSA signer

### Phase 0.5: Design Memo Before Protocol Code

- [x] write a short design memo for canonical secret representation
- [x] write a short design memo for threshold share derivation
- [x] write a short design memo for integration seam into the current ECDSA
      backend
- [x] reject explicitly any design that preserves separate threshold and export
      key lanes

### Phase 1: Fixed-Function Prototype

- [x] create `crates/ecdsa-hss/src/fixtures.rs`
- [x] define the root-share input types
- [x] define canonical secret normalization rules
- [x] define secp256k1 public-key derivation from the canonical secret
- [x] define Ethereum address derivation from the public key
- [x] generate initial deterministic fixture corpus
- [x] add tests for secret -> public key -> address equivalence
- [x] add negative tests for malformed secret normalization
- [ ] add client-runtime parity vectors if browser/worker code will consume the
      same fixtures

### Phase 1.5: Boundary-First Reorganization

- [x] move boundary-neutral fixed-function helpers into clearly named shared or
      wire-adjacent modules
- [x] move client-visible derivation/request logic under `src/client/`
- [x] move server-owned staged/finalize logic under `src/server/`
- [x] keep shared root modules only where both sides genuinely need the same
      representation
- [x] remove transitional module shapes once the split is complete
- [x] add a short crate-layout note explaining what belongs in:
  - `client/`
  - `server/`
  - `wire/`
  - shared root modules
- [x] treat this reorganization as a prerequisite for further protocol
      implementation and audit work

### Phase 2: Hidden Deterministic Derivation

- [x] create `crates/ecdsa-hss/src/client/`
- [x] create `crates/ecdsa-hss/src/server/`
- [x] create `crates/ecdsa-hss/src/wire/`
- [x] define prepare/respond/finalize wire types
- [x] define staged server-owned ceremony state
- [x] define allowed retained-state exceptions
- [x] implement deterministic hidden derivation for the canonical secret
- [x] add fixture-backed protocol tests
- [x] add boundary tests for "server never sees canonical secret"
- [x] add tests for forbidden retained-state material

Phase 2 should not proceed past the current reference/staged model until Phase
1.5 finishes. The goal is to avoid growing protocol logic in a layout that
blurs the client/server boundary.

### Phase 3: Deterministic Threshold Share Derivation

- [x] define threshold share representation derived from the canonical secret
- [x] define client role material derived from the canonical secret
- [x] define relayer role material derived from the canonical secret
- [x] define resulting threshold public key derivation
- [x] add equivalence tests: exported key public key == threshold public key
- [x] add equivalence tests: exported key address == threshold signing address
- [x] add negative tests for accidental two-key divergence
- [x] document exactly which share material is export-capable and which is not

### Phase 4: Integrate With Current Threshold ECDSA Signer

- [x] identify the exact bootstrap seam in the current threshold ECDSA flow
- [x] define adapter types from `ecdsa-hss` outputs to current signer inputs
- [x] implement bootstrap path backed by `ecdsa-hss`
- [x] implement sign path backed by `ecdsa-hss` key material
- [x] implement export path backed by `ecdsa-hss`
- [x] verify threshold signing address is unchanged across sign/export flows
- [x] add integration tests for registration -> sign -> export
- [x] add integration tests for login -> sign -> export
- [ ] remove the separate `prfSecond`-derived export lane once replacement is
      complete

### Phase 5: Export Policy And Product Boundary

- [x] define export-only operation type
- [x] define export confirmation requirements
- [x] define export audit/telemetry requirements
- [x] ensure signing sessions cannot request export-capable output
- [x] ensure export requests cannot reuse signing-only ceremony state
- [x] add regression tests for policy binding
- [x] fail closed at the legacy product export boundary for one-key accounts
- [x] wire a canonical one-key secp256k1 export artifact lane through the worker/export UI
- [x] source canonical one-key export artifacts from active EVM session state without
      persisting private key material to storage
- [x] thread canonical one-key export artifacts through bootstrap/session activation
      APIs without persisting them to browser storage
- [x] infer `ecdsa-hss-one-key-v1` automatically at bootstrap when canonical
      one-key export artifacts are present
- [x] define an explicit product-side canonical artifact producer seam for
      registration and login warm-up flows
- [x] make missing canonical artifact producers explicit in registration/login
      runtime logs instead of silently implying one-key cutover is already live
- [x] add an explicit new-account key-mode rollout knob for threshold ECDSA
- [x] fail closed during new-account registration when one-key mode is required
      but no canonical `ecdsa-hss` artifact is available

### Phase 6: Verification And Audit Track

- [x] create formal verification scope note
- [x] create implementation-plan note for proof obligations
- [x] create proof inventory note
- [x] define proof obligations for single-key equivalence
- [x] define proof obligations for export-policy binding
- [x] define proof obligations for retained-state boundary
- [x] define proof obligations for server-blindness
- [x] reconcile the completed Verus and Lean findings back into the crate docs
      and status notes

### Phase 6.5: Benchmarking And Optimization Prep

- [x] add a dedicated crate-local benchmark suite
- [x] benchmark:
  - canonical derivation
  - share derivation
  - bootstrap adapter path
  - sign bridge path
  - explicit export path
- [x] establish an initial benchmark baseline
- [x] identify the dominant cost center before optimization work
- [x] create an explicit optimization ledger with acceptance results
- [x] split the sign-path benchmark into setup vs full-execution measurements
- [x] split the full sign path into presign roundtrip vs final arithmetic
      measurements
- [x] split the presign protocol into pre-start, start-transition, and
      post-start measurements
- [x] inspect the underlying threshold ECDSA presign flow and identify the
      dominant internal presign stage
- [x] land the first accepted wrapper-level optimization against the pre-start
      presign path
- [x] inspect the upstream triples implementation and identify the first
      backend-level optimization target
- [ ] attempt the first backend-level optimization inside the triples stage
- [x] decide whether the current benchmark profile is already acceptable for
      the crate phase
- [x] freeze the optimization stop point before resuming SDK/product work
- [x] add a dedicated wasm benchmark suite for the crate lifecycle
- [x] establish an initial wasm baseline for bootstrap, sign, and export

### Rollout And Cleanup

- [x] define migration policy for existing two-key EVM users
- [x] define whether re-registration is required
- [x] define whether old export artifacts are retired or supported
- [x] block one-key accounts from entering the legacy `prfSecond` export lane
- [ ] remove legacy product assumptions after cutover
- [x] update top-level docs once the one-key model is live

## Remaining Work Split

At the current stop point, the remaining unchecked items fall into three
separate buckets.

### Crate blockers before SDK/product resumption

- none for the agreed current crate scope

### Optional crate follow-up, not a blocker

- build cross-language/client-runtime parity vectors if a browser or worker
  runtime needs to consume the same frozen fixture corpus
- attempt a deeper backend-level triples optimization only if the current
  native/wasm sign latency is judged insufficient

### Product cutover work, not part of crate completion

- SDK/server refactor work is tracked in
  [sdk-server-integration-plan.md](/Users/pta/Dev/rust/simple-threshold-signer/crates/ecdsa-hss/docs/plans/sdk-server-integration-plan.md)
- remove the separate `prfSecond`-derived export lane once replacement is
  actually live
- remove legacy product assumptions after cutover
- update top-level docs once the one-key model is live
