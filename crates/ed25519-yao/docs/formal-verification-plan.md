# Ed25519 Yao Formal Verification Scaffold Plan

Status: **FV1 mechanical scaffold in progress; protocol-security proofs have not started**

This document defines the formal-verification workstream for the fixed
Router A/B Ed25519 Streaming Yao protocol. It adapts the useful structure from
`crates/ed25519-hss/formal-verification` and tightens the places where that
structure currently provides only model or build scaffolding.

The workstream covers Ed25519 Yao only. ECDSA remains on the strict Router A/B
threshold-PRF and additive-share design.

## Current Decision

The repository retains this approved plan and FV1 mechanical toolchain work has
begun. The implementation is **not yet complete enough for protocol-security
proofs**.

Meaningful proof work begins in stages:

1. Yao Phase 1 closes before the reference-functionality and party-view model
   starts.
2. Yao Phase 2 closes before the circuit/compiler proof starts.
3. Yao Phase 6 selects and freezes the active-security suite before any
   malicious-security composition theorem starts.
4. Yao Phase 13 closes before deployment-profile evidence is accepted, Yao
   Phase 14 closes before verification gates replace HSS gates, and Yao Phase 15
   closes before final release evidence is complete.

The maintainer should receive an explicit readiness notice at each gate. A
directory that builds, a reflexive view theorem, or a handwritten model alone
does not satisfy a readiness gate.

## Scope

The formal workstream will establish, with clearly separated proof and
assumption boundaries:

- the exact four-`y`, four-`tau` Ed25519 derivation functionality;
- activation and export output separation;
- deterministic manifest, circuit, compiler, schema, and schedule identity;
- circuit equivalence to the clear reference oracle;
- functional correctness of the garbler/evaluator execution;
- private randomized output sharing and absence of a joined Deriver output;
- bounded, ordered streaming and transcript binding;
- consuming, at-most-once ticket state transitions;
- correctness with abort under the selected active-security construction;
- privacy against Router plus at most one corrupt Deriver, relative to the
  recorded cryptographic and operational assumptions;
- the exact weaker claim available to same-account development deployments;
- mechanically checked correspondence between narrow Rust boundaries and the
  Lean model.

The following remain outside the mechanized claim unless later phases add a
reviewed proof track for them:

- A+B collusion;
- Cloudflare platform compromise;
- simultaneous compromise of both independent deployment authorities;
- side channels outside the reviewed Rust/WASM constant-time boundary;
- entropy-source, compiler, hardware, TLS, and platform correctness;
- availability against a malicious participant;
- foundational security reductions for the selected hash, block-cipher or
  fixed-key primitive, malicious OT, HPKE, signatures, and active Yao compiler.

Those items must appear in an assumption ledger. The final theorem and release
claim must reference that ledger directly.

## Source Precedence and Conflict Policy

Create a new Yao corpus. HSS specifications, proof files, theorem names, and
generated artifacts are historical inputs only.

The Yao corpus uses this precedence:

1. the approved security claim, ideal functionalities, corruption model, and
   topology in `docs/yaos-ab.md`;
2. the frozen bit- and byte-level functionality plus party views produced by
   Yao Phase 1;
3. the independently reproducible golden and randomized vector corpus;
4. reviewed Rust source and deterministic circuit artifacts;
5. formal mirrors, generated Lean, handwritten models, and explanatory prose.

Any disagreement between two levels becomes a recorded compliance finding.
Proof work stops at the affected boundary until the authoritative source and
implementation agree. A formal model must never silently redefine behavior to
match a convenient implementation.

## Lessons Retained from `ed25519-hss`

Retain these structural choices:

- a crate-local `formal-verification/` tree;
- a standalone unpublished Verus mirror with an exact `vstd` pin;
- executable anti-drift tests that import the production and mirror crates
  side by side;
- handwritten Lean models separated from Aeneas-generated code;
- a narrow Aeneas/Charon extraction facade around pure Rust boundaries;
- committed generated artifacts plus deterministic regeneration checks;
- an explicit spec corpus and compliance review before proof claims;
- one command that runs vectors, parity, extraction drift, Lean, and Verus.

Strengthen these areas in the Yao track:

- require Verus in the gated CI job and fail when it is unavailable;
- run Rust anti-drift tests independently of Verus tool discovery;
- declare every Lean library and Aeneas dependency explicitly;
- build named Lean targets from a clean checkout and reject a zero-job build;
- use repository-relative links in verification documentation;
- enumerate every generated or handwritten axiom;
- model distinct A and B transcripts, randomness, leakage, and aborts;
- require non-reflexive real/ideal statements before using privacy language;
- reserve Aeneas claims for Rust-to-Lean correspondence;
- reserve cryptographic security claims for the reviewed theorem layer and its
  stated assumptions.

The HSS privacy-model files prove useful structural properties such as export
branch separation and boundary-field correspondence. Their privacy-named
lemmas do not provide a real/ideal Yao precedent. The new model starts in a new
namespace and carries no inherited privacy theorem.

## Planned Layout

```text
crates/ed25519-yao/formal-verification
  .gitignore
  README.md
  Makefile
  toolchain.toml
  docs
    assumption-ledger.md
    compliance-baseline.md
    proof-obligations.md
    spec-corpus.md
  tasks
    Cargo.toml
    Cargo.lock
    src/main.rs
  verus
    Cargo.toml
    Cargo.lock
    README.md
    docs/implementation-plan.md
    src
      lib.rs
      reference.rs
      digest.rs
      ids.rs
      metrics.rs
      manifest.rs
      circuit_ir.rs
      schedule.rs
      garbling.rs
      output.rs
      stream.rs
      ticket.rs
      protocol.rs
    tests/anti_drift.rs
  lean-boundary
    README.md
    lean-toolchain
    lakefile.lean
    lake-manifest.json
    scripts
      setup-aeneas.sh
      extract-reference-boundary.sh
      extract-protocol-boundary.sh
    generated
    Ed25519Yao.lean
    Ed25519Yao
      Types.lean
      Funs.lean
      FunsExternal.lean
    Ed25519YaoBoundary.lean
    Ed25519YaoBoundary
      Reference.lean
      Protocol.lean
      Scope.lean
  lean-model
    README.md
    lean-toolchain
    lakefile.lean
    lake-manifest.json
    Ed25519YaoModel.lean
    Ed25519YaoModel
      Functionality.lean
      Execution.lean
      Views.lean
      Leakage.lean
      Assumptions.lean
      Simulators.lean
      Correctness.lean
      Security.lean
      Topology.lean
      AeneasBridge.lean
```

Later modules land only when their production owner exists. Empty proof files,
placeholder privacy theorems, `sorry`, and `admit` are excluded from the
scaffold.

The host-only task runner lives under `formal-verification/tasks`. The
production `ed25519-yao` crate will not gain a verification command binary or a
reverse dependency on the generator, Lean, Aeneas, or Verus mirrors.

## Toolchain Baseline

The first scaffold should reuse the known repository pins so all formal tracks
share one installed CI toolchain:

- Verus release `0.2026.04.03.21dfcd2`;
- `vstd = "=0.0.0-2026-03-29-0113"`;
- Aeneas commit `42c0e90dacf486f7d3ed5b6cde3a9a81f04915a4`;
- Charon commit `419f53b6eed3fe487a8427fd290a734c49634366`;
- Lean `leanprover/lean4:v4.28.0-rc1`.

Validate the pins from a clean checkout before adopting them. A later toolchain
upgrade updates all affected formal tracks together in one reviewed change.

The Lean boundary package must declare both `Ed25519Yao` and
`Ed25519YaoBoundary`, declare the pinned Aeneas library, and build explicit
targets. The gate must verify that expected `.olean` outputs were produced.

## Proof Layers

### Executable oracle and vectors

`tools/ed25519-yao-generator` remains the exact clear reference and vector
owner. Its proof-facing scope will include:

- four little-endian `y` contributions and wrapping addition modulo `2^256`;
- four canonical `tau` contributions and addition modulo `l`;
- `d -> SHA-512(d) -> clamp -> a`;
- `x_client_base = a + tau mod l`;
- `x_server_base = a + 2*tau mod l`;
- `2*X_client - X_server = A_pub`;
- separate seed-free activation and required-seed export outputs;
- the frozen `StableKeyDerivationContext` once Yao Phase 1 defines it;
- lifecycle-specific registration, activation, recovery, refresh, and export
  vectors.

The clear oracle stays host-only and synthetic. Production crates retain no
reverse dependency on it.

### Verus implementation proofs

The Verus crate mirrors stable security boundaries rather than allocation and
performance internals. Initial targets are:

- digest role types and nonzero validation;
- activation/export bundle and output-schema separation;
- metric nonzero, sum, and overflow invariants;
- the exact canonical manifest preimage order and length;
- domain, family, schema, seven artifact digests, and twelve metrics binding;
- deterministic manifest identity around a trusted SHA-256 boundary;
- pure wrapping-addition, clamp, and scalar-byte helper properties;
- deterministic circuit IR semantics and bit ordering;
- schedule equivalence, gate uniqueness, liveness, and storage bounds;
- garbler/evaluator functional state transitions;
- output-recipient separation;
- frame order, transcript binding, and consuming ticket transitions.

Anti-drift tests connect each mirror to production constants, layouts, vector
results, generated artifacts, and typed public boundaries.

### Aeneas/Charon Rust-to-Lean boundary

Extraction starts from small, reviewed facades. Crypto dependency internals are
opaque at first because Charon cannot extract the current `sha2` and curve
stack end to end.

The first reference facade exposes two distinct projections:

- activation correctness fields with no seed or joined secret;
- explicitly authorized export fields with the required export result.

It must not project `OracleMaterial` wholesale. That synthetic trace contains
the digest, signing scalar, joined `tau`, and scalar bases and is not a
production-visible party view.

The protocol facade lands after the active role state machines exist. It
contains only pure state transitions and visible transcript/output fields.
Every opaque external body is listed in `assumption-ledger.md` and in generated
scope metadata.

Generated code and handwritten bridge lemmas remain in separate directories.
Regeneration drift is a gated failure.

### Lean functionality and security model

The Lean model defines distinct records for Client, Router, Deriver A,
Deriver B, SigningWorker, recipients, and public observers. Each view contains
that party's input, randomness, received frames, sent frames, outputs, leakage,
and abort reason.

The security layer requires two different corruption games:

- Router plus corrupt Deriver A against honest Deriver B;
- Router plus corrupt Deriver B against honest Deriver A.

Real and ideal executions must vary honest inputs while preserving declared
public leakage. Simulators receive only the corrupt party's input, authorized
output, public values, leakage, and abort information. A theorem that compares
one view expression with itself does not satisfy this requirement.

The expected theorem families are:

- `activation_refines_fixed_functionality`;
- `export_refines_authorized_export_functionality`;
- `activation_has_no_seed_output`;
- `correctness_with_abort_corrupt_a`;
- `correctness_with_abort_corrupt_b`;
- `privacy_under_one_corrupt_deriver_a`;
- `privacy_under_one_corrupt_deriver_b`;
- `selective_failure_independent_of_honest_input`;
- `input_provenance_sound`;
- `output_share_unbiased`;
- `no_deriver_obtains_joined_output`;
- `ticket_consumes_at_most_once`;
- `export_authorization_sound`.

Names may change after the active suite is selected. Their statements must
encode the assumption record and supported corruption set.

## Claim and Evidence Matrix

| Claim                                    | Primary owner                | Mechanized evidence                                    | External premise                                                     |
| ---------------------------------------- | ---------------------------- | ------------------------------------------------------ | -------------------------------------------------------------------- |
| Exact Ed25519 functionality              | generator + Phase 1 corpus   | vectors, Verus helpers, Lean functionality             | SHA-512 and curve implementation correctness                         |
| Manifest binds every artifact field      | `ed25519-yao`                | Verus encoder proof + anti-drift                       | SHA-256 collision resistance                                         |
| Circuit matches the oracle               | generator + circuit compiler | clear evaluator parity + Verus/Lean circuit semantics  | compiler/toolchain execution integrity                               |
| Passive garbling evaluates correctly     | `ed25519-yao`                | gate KATs + Verus execution refinement                 | chosen primitive correctness                                         |
| Activation cannot emit a seed            | output schema + role APIs    | Rust type checks + Verus + Lean branch theorem         | reviewed boundary inventory                                          |
| Neither Deriver receives a joined output | output protocol              | Verus state/output proof + Lean views                  | erasure and side-channel assumptions                                 |
| Streaming preserves circuit execution    | stream state machine         | Verus transition proof + parity                        | authenticated transport delivery semantics                           |
| Ticket use is at most once               | ticket state machine         | Verus state-machine invariant + extracted bridge       | crash-safe storage atomicity                                         |
| One-malicious-Deriver privacy            | selected active suite        | Lean conditional real/ideal composition                | malicious OT, active compiler, input consistency, primitive security |
| Same-account development isolation       | deployment profile           | typed profile and conditional topology lemma           | honest shared administrator/control plane                            |
| Separate-account production independence | deployment profile           | production type exclusion + conditional topology lemma | operational attestation of independent accounts/deployers            |

No row is considered proved until its production link, generated-artifact
link, assumption set, and verification command are all present.

## Trusted Computing Base and Assumption Ledger

At minimum, record:

- `sha2` SHA-256 and SHA-512 behavior;
- `curve25519-dalek` scalar reduction and basepoint operations used by the
  oracle and boundary checks;
- the chosen garbling primitive and domain-separated gate tweaks;
- malicious OT extension and base-OT security;
- the selected active compiler, input consistency mechanism, and output
  authentication mechanism;
- OS, Worker, and Web Crypto randomness;
- HPKE, signatures, TLS, peer authentication, and key custody;
- constant-time and secret-erasure boundaries;
- Rust, LLVM/WASM, Verus, Aeneas, Charon, Lean, and circuit-generator
  correctness;
- Durable Object atomicity and persistence behavior used by the ticket proof;
- no A+B collusion;
- the administrative-independence premise for production;
- the honest shared-control-plane premise for same-account development.

Each assumption has an owner, evidence link, affected theorem IDs, review date,
and invalidation trigger.

## Deployment Profile Semantics

Both deployment profiles use the same reviewed protocol and circuit artifacts.
They instantiate different operational premises.

### Same-account development

The formal claim may cover one runtime-confined corrupt Worker while the shared
account administrator, CI, deployment control plane, bindings, and platform
remain honest. A shared administrator can replace or inspect both Derivers,
which is equivalent to A+B compromise and lies outside the protocol theorem.

This profile supports local development, staging, and optimistic latency
measurement. It does not instantiate the strict server-blind production claim.

### Separate-account production

The formal protocol claim assumes Router plus at most one corrupt Deriver and
no A+B collusion. Independent account and deployer control is an operational
premise checked by configuration, release evidence, and human review. Lean
cannot derive administrative independence from a deployment identifier.

The production configuration type must remain unable to represent the
same-account profile.

## Phased TODO

### Cross-plan phase crosswalk and status rules

`docs/yaos-ab.md` owns Ed25519 implementation gates.
`docs/router-a-b-sol-refactor.md` owns the wider product migration and cleanup
gates. This document owns formal-evidence gates. A formal phase may prepare
mechanical scaffolding in parallel, but it cannot prove or open an implementation
phase whose production owner is absent or blocked.

| Yao implementation phases | Wider Router A/B phases | Formal-verification phases    |
| ------------------------- | ----------------------- | ----------------------------- |
| 0                         | 0                       | plan approval                 |
| 1                         | 1                       | FV0-FV1                       |
| 2-3                       | 2                       | FV2-FV4                       |
| 4-6                       | 3                       | FV5-FV6                       |
| 7-8                       | 4-5                     | FV7                           |
| 9-10                      | 6                       | FV8 deployment assumptions    |
| 11                        | 7                       | FV7-FV8 integration evidence  |
| 12                        | 8                       | outside Ed25519 Yao proofs    |
| 13                        | 9                       | FV8 pre-cutover evidence gate |
| 14                        | 10                      | FV9 verification hard cutover |
| 15                        | 11                      | FV10 final release evidence   |

Phase 0 is closed, Yao Phase 1 is in progress, and Yao Phase 2 remains blocked.
The current oracle and manifest code is partial foundation evidence. It does not
open FV2 circuit proofs or any later security theorem. A checked formal TODO
means only that exact artifact or proof obligation is complete.

### FV0: Freeze claims, sources, and proof obligations

Depends on: Yao Phase 1

- [ ] Create `docs/spec-corpus.md` with source precedence and exact immutable
      source revisions.
- [ ] Define the five lifecycle ideal functionalities separately.
- [x] Freeze the exact `StableKeyDerivationContext` encoding, validation, and
      binding-digest bytes.
- [ ] Freeze role-local KDF integration and public-key continuity rules for the
      stable context.
- [ ] Freeze role-specific inputs, outputs, leakage, randomness, and aborts.
- [ ] Define the two supported corruption games and excluded corruption sets.
- [x] Create stable proof-obligation identifiers for the implemented FV1
      surface.
- [x] Create the trusted-computing-base and assumption ledger.
- [ ] Audit the Yao plan, oracle, manifests, and vectors for contradictions.
- [ ] Resolve every critical or high compliance finding.
- [ ] Obtain independent cryptographic review of the claim boundary.

Exit gate:

- [ ] Yao Phase 1 is complete.
- [ ] Two independent implementations reproduce the full vector corpus.
- [ ] Each theorem target has one exact source statement and owner.
- [ ] No lifecycle, party-view, topology, or export ambiguity remains.

### FV1: Build the mechanical scaffold

Depends on: plan approval; may run alongside the end of FV0

- [x] Create the directory layout in this document.
- [x] Add a host-only task-runner crate under `formal-verification/tasks`.
- [x] Add `cargo yao-fv` and `just ed25519-yao-fv` commands.
- [x] Pin the Verus release, `vstd`, Aeneas/Charon source revisions, and Lean
      exactly.
- [x] Add exact source-pinned Aeneas bootstrap and actionable missing-tool
      diagnostics.
- [ ] Lock the Aeneas bootstrap package environment and verify it from empty
      caches.
- [x] Declare explicit `Ed25519Yao`, `Ed25519YaoBoundary`, and Aeneas Lean
      dependencies.
- [x] Make Lean checks build named targets and assert expected output files.
- [x] Make a missing Verus toolchain a gated failure.
- [x] Run anti-drift tests even when Verus tool discovery fails.
- [x] Add README status language that makes zero security claims.
- [x] Add repository-relative documentation links only.
- [ ] Verify the scaffold from a clean checkout with empty tool caches.

Exit gate:

- [x] Every focused command executes real work and reports a nonzero check
      count or an explicit artifact list.
- [ ] The full scaffold command succeeds from a clean checkout.
- [x] There are no `sorry`, `admit`, placeholder privacy theorems, or unlisted
      axioms.

### FV2: Prove oracle and manifest foundations

Depends on: FV0-FV1

- [ ] Mirror `ids`, `digest`, `metrics`, and `manifest` in Verus.
- [ ] Prove digest-role separation and nonzero validation.
- [ ] Prove metric validation, sums, bounds, and overflow rejection.
- [ ] Expose a narrow proof-facing canonical manifest-preimage encoder.
- [ ] Prove the exact domain/family/schema/digest/metric byte order.
- [ ] Treat SHA-256 compression as an explicit trusted boundary.
- [ ] Prove pure little-endian wrapping-add and clamp helpers.
- [ ] Model scalar and point operations through reviewed external contracts.
- [ ] Add separate activation and export Aeneas reference facades.
- [ ] Prove activation result types contain no seed field.
- [ ] Prove export result types require the authorized seed result.
- [ ] Add production/mirror/vector anti-drift tests.
- [ ] List every opaque extracted function in the assumption ledger.

Exit gate:

- [ ] Manifest identity and family separation are verified and parity-tested.
- [ ] Oracle helpers reproduce the Phase 1 vectors.
- [ ] Generated Lean is reproducible and builds through explicit targets.
- [ ] The reference bridge exposes no wholesale joined trace.

### FV3: Prove deterministic circuit and schedule equivalence

Depends on: Yao Phase 2 and FV2

- [ ] Formalize the minimal gate IR and Boolean semantics.
- [ ] Prove bit order and fixed SHA-512 padding specialization.
- [ ] Prove 256-bit addition, clamp, reduction, `tau`, and output equations.
- [ ] Prove activation and export circuits refine their ideal functions.
- [ ] Prove the activation circuit has no seed-output wire.
- [ ] Prove the export circuit has the required export-output schema.
- [ ] Prove deterministic gate numbering and unique gate tweaks.
- [ ] Prove schedule execution is equivalent to unscheduled IR execution.
- [ ] Prove liveness slot reuse cannot read an overwritten wire.
- [ ] Check gate, wire, depth, liveness, schedule, and table-byte metrics against
      generated artifacts.
- [ ] Regenerate, hash, and diff all circuit artifacts in the full gate.

Exit gate:

- [ ] Reviewed artifacts reproduce every Phase 1 vector.
- [ ] Circuit, schedule, and manifest digests are tied to proved semantics.
- [ ] Activation/export artifact substitution is rejected mechanically.

### FV4: Prove passive Yao functional correctness

Depends on: Yao Phase 3 and FV3

- [ ] Prove truth-table correctness for XOR, inversion, and AND garbling.
- [ ] Prove fixed garbler/evaluator role transitions.
- [ ] Prove evaluation over the scheduled circuit refines clear evaluation.
- [ ] Prove one role-local API cannot accept the opposite role's state.
- [ ] Prove unique gate tweaks and session domains prevent internal reuse.
- [ ] Connect gate KATs and randomized differential tests to proof fixtures.
- [ ] Extract the narrow passive visible boundary with Aeneas.
- [ ] Label all results as passive/semi-honest functional evidence.

Exit gate:

- [ ] Two separate role processes reproduce the reference outputs.
- [ ] The passive execution-refinement theorem is linked to production Rust.
- [ ] No malicious-security claim depends on FV4 alone.

### FV5: Prove private outputs and streaming invariants

Depends on: Yao Phases 4-5 and FV4

- [ ] Formalize protocol-generated randomized output sharing.
- [ ] Prove neither role can choose a linear mask that reveals the joined
      output.
- [ ] Prove recipient packages are disjoint and correctly bound.
- [ ] Prove activation output packages cannot carry export seed material.
- [ ] Prove frame-size, count, order, and sequence-number bounds.
- [ ] Prove incremental evaluation equals non-streaming evaluation.
- [ ] Prove transcript commitments bind all headers and payload frames.
- [ ] Prove role state never requires a whole-stream `Vec`.
- [ ] Model early EOF, duplicate, reordering, overflow, timeout, and abort.

Exit gate:

- [ ] The private-output and streaming invariants are linked to Rust.
- [ ] Peak live state is bounded by manifest and protocol constants.
- [ ] No Deriver-visible state contains a joined scalar or seed.

### FV6: Model and prove the selected active-security composition

Depends on: Yao Phase 6 and FV3-FV5

- [ ] Freeze one reviewed active compiler and malicious-OT construction.
- [ ] Freeze input provenance, input consistency, selective-failure,
      randomized-output, and output-authentication mechanisms.
- [ ] Define probabilistic or relational real/ideal execution semantics.
- [ ] Define distinct simulators for corrupt A and corrupt B.
- [ ] State primitive and compiler assumptions at their exact call boundaries.
- [ ] Prove correctness with abort for corrupt A and corrupt B.
- [ ] Prove input provenance and consistency composition.
- [ ] Prove abort behavior does not leak undeclared honest-input information.
- [ ] Prove active output shares are authentic and correctly recipient-bound.
- [ ] Prove the conditional one-malicious-Deriver privacy theorem.
- [ ] Record the explicit absence of an A+B theorem.
- [ ] Obtain independent cryptographic review of assumptions and composition.

Exit gate:

- [ ] Production circuit and protocol IDs identify the reviewed active suite.
- [ ] Every theorem premise maps to code, artifact metadata, or an external
      assumption with evidence.
- [ ] No theorem relies on reflexive view equality as privacy evidence.
- [ ] The reviewer approves the exact wording of the supported security claim.

### FV7: Prove tickets, lifecycle, and Router adapter boundaries

Depends on: Yao Phases 7-8 and FV6

- [ ] Model `Prepositioning`, `Available`, `Reserved`, `Activated`,
      `OutputPrepared`, `OutputCommitted`, `Consumed`, and `Destroyed` as
      consuming states.
- [ ] Prove a ticket reaches `Consumed` at most once.
- [ ] Prove retries cannot repeat OT, labels, masks, or output release.
- [ ] Prove crash recovery preserves terminal-state monotonicity.
- [ ] Bind ticket, request, account, epoch, circuit, protocol, peer, transcript,
      and recipient identities.
- [ ] Prove the Router adapter maps each lifecycle request to exact role-local
      inputs.
- [ ] Prove recovery remains seed-preserving and non-export.
- [ ] Prove export requires the explicit authorization branch.
- [ ] Extract stable pure protocol transitions with Aeneas.
- [ ] Bridge generated transitions into the Lean execution model.
- [ ] Add cross-crate anti-drift tests for `router-ab-ed25519-yao` and
      `router-ab-core` boundaries.

Exit gate:

- [ ] One-use, lifecycle, and export-authorization claims are linked to Rust.
- [ ] Every extracted axiom and opaque function remains in the ledger.
- [ ] Router admission policy stays owned by Router A/B formal verification.

### FV8: Instantiate deployment profiles and validate pre-cutover evidence

Depends on: Yao Phases 9-10 and 13 plus FV7

- [ ] Define `SameAccountDevelopmentAssumptions`.
- [ ] Define `SeparateAccountProductionAssumptions`.
- [ ] Prove the production configuration excludes same-account deployment.
- [ ] Map administrative-independence premises to deployment evidence.
- [ ] Map role-isolation premises to Worker bindings, secrets, and storage
      evidence.
- [ ] Run the full proof and anti-drift suite on native and WASM artifacts where
      applicable.
- [ ] Obtain pre-cutover independent formal-methods and deployment review.

Exit gate:

- [ ] The proposed release claim matches the proved conditional theorem exactly.
- [ ] Same-account evidence carries development-only wording.
- [ ] Separate-account evidence demonstrates independent operational control.
- [ ] Every Phase 13 security and deployment premise maps to a checked theorem,
      explicit assumption, or reviewed external evidence item.

### FV9: Replace verification gates at hard cutover

Depends on: Yao Phase 14 and FV8

- [ ] Replace the HSS formal-verification default gate with the Yao gate in the
      same hard-cutover change.
- [ ] Delete HSS-only verification aliases, compatibility paths, generated
      artifacts, and proof jobs after their current owners move or are deleted.
- [ ] Require clean-checkout reproducibility in CI.
- [ ] Run the full proof, extraction, anti-drift, source-guard, native, and WASM
      artifact suite against the cutover tree.
- [ ] Prove repository verification commands cannot silently skip a Yao track or
      fall back to the deleted HSS track.

Exit gate:

- [ ] All default repository verification commands exercise the Yao tracks.
- [ ] No default command, artifact path, or release check depends on the deleted
      HSS verification tree.
- [ ] The hard-cutover commit records the exact proof, artifact, and toolchain
      digests it exercised.

### FV10: Publish final release evidence

Depends on: Yao Phase 15 and FV9

- [ ] Publish theorem, assumption, artifact, toolchain, and review hashes in the
      release evidence.
- [ ] Obtain final independent formal-methods and deployment approval for the
      cutover artifacts and exact release wording.
- [ ] Reproduce every formal track from a clean checkout under the independent
      operator workflow.
- [ ] Bind the signed production deployment manifests to the verified protocol,
      circuit, schema, and proof-artifact digests.
- [ ] Record every accepted external premise and residual exclusion in the
      published security capability.

Exit gate:

- [ ] The published release claim matches the proved conditional theorem and
      assumption ledger exactly.
- [ ] Both independent Deriver operators attest to the verified artifact set.
- [ ] Production burn-in introduces no proof, artifact, deployment, or
      assumption drift.

## Command Contract

The scaffold should eventually provide:

```sh
cargo yao-fv vectors-check
cargo yao-fv parity
cargo yao-fv anti-drift
cargo yao-fv verus-check
cargo yao-fv aeneas-check
cargo yao-fv lean-check
cargo yao-fv all

make -C crates/ed25519-yao/formal-verification check
just ed25519-yao-fv
```

`all` runs six nonempty tracks, in order:

1. vector regeneration and byte comparison;
2. Rust oracle/manifest parity, including compile-fail doctests;
3. production/mirror anti-drift tests;
4. Aeneas extraction, stable generated-Lean comparison, and explicit boundary
   builds;
5. the explicit Lean model build;
6. Verus verification through a driver in the same pinned release bundle.

Every track checks an exact nonzero evidence count or explicit artifact list
from `formal-verification/toolchain.toml`.

After the FV1 empty-cache bootstrap gate closes, the aggregate repository
formal-verification command adds Yao while the implementation remains isolated.
At the Ed25519 hard cutover it removes the obsolete HSS gate in the same change.

## Anti-Drift Policy

Proofs freeze security invariants, semantics, artifact identities, and visible
boundaries. They do not freeze internal allocation strategies or harmless
performance refactors.

Any accepted change to functionality, input/output schema, active suite,
stream transcript, ticket lifecycle, or artifact encoding requires:

1. a new or updated proof obligation;
2. regenerated vectors and artifacts;
3. updated anti-drift fixtures;
4. proof and bridge updates;
5. a protocol/circuit/schema version change whenever wire compatibility or the
   security claim changes;
6. renewed review for every invalidated assumption.

## Readiness Dashboard

| Prerequisite                                                   | Current state                                   |
| -------------------------------------------------------------- | ----------------------------------------------- |
| Frozen protocol, circuit-family, and output-schema identifiers | complete                                        |
| Typed draft manifest and canonical digest binding              | complete                                        |
| Isolated four-`y`, four-`tau` clear oracle                     | partial Phase 1 foundation                      |
| RFC 8032 reference vectors                                     | partial Phase 1 foundation                      |
| Five exact lifecycle ideal functionalities                     | missing                                         |
| Frozen `StableKeyDerivationContext` encoding and binding       | complete                                        |
| Stable-context KDF integration and continuity vectors          | missing                                         |
| Complete party views, leakage, and aborts                      | missing                                         |
| Deterministic circuit IR, compiler, schedule, and artifacts    | missing                                         |
| Passive garbler/evaluator implementation                       | missing                                         |
| Private randomized outputs and streaming state machine         | missing                                         |
| Selected reviewed active suite                                 | missing                                         |
| One-use ticket and adapter state machines                      | missing                                         |
| Formal-verification directory and clean build gate             | local gate green; empty-cache FV1 check pending |

Current verdict: continue Yao Phase 1 and the FV1 mechanical scaffold. Notify
the maintainer to begin FV0 and FV2 when Phase 1 and the FV1 exit gate are
satisfied. Notify again before FV3 and FV6 when their implementation gates
close.

## Definition of Done

Formal verification is comprehensive enough for production review when:

- every claim in the matrix has mechanized evidence or an explicit external
  premise;
- all mirrors and generated files have executable anti-drift links;
- every production artifact digest is tied to reviewed semantics;
- all Lean builds execute named nonempty targets from a clean checkout;
- the checked tree contains no `sorry`, `admit`, placeholder security theorem,
  stale generated artifact, or unlisted axiom;
- corrupt-A and corrupt-B executions use distinct real/ideal views and
  simulators;
- activation, recovery, and refresh cannot contain a seed-export result;
- ticket and output state is consuming and at most once;
- same-account and separate-account claims remain explicitly different;
- CI fails on missing tools, skipped tracks, drift, or proof failure;
- independent reviewers approve the formal model, implementation bridge,
  assumption ledger, and release wording.
