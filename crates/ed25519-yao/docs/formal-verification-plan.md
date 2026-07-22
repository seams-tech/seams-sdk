# Ed25519 Yao Formal Verification Scaffold Plan

Status: **Phase 1/FV1 and the Phase 2B mechanical reconciliation gate pass;
the local P0 construction and complete Phase 9C lifecycle pass; the public SDK
cutover is active; deep proof and external review are deferred until the Phase
13A go/no-go decision**

This document defines the formal-verification workstream for the fixed
Router A/B Ed25519 Streaming Yao protocol. It uses executable safeguards,
mechanical anti-drift checks, and proof tracks scoped to the selected protocol.

The workstream covers Ed25519 Yao only. ECDSA remains on the strict Router A/B
threshold-PRF and additive-share design.

## Current Decision

The repository retains this approved plan. Phase 1 and its FV1 mechanical
baseline are complete, and Phase 2B reconciliation passes. The fixed Half-Gates
circuits, passive OT path, bounded duplex stream, recipient-specific encrypted
outputs, separate-process Router/A/B/SigningWorker graph, and the registration,
activation, recovery, refresh, export, and ordinary-signing lifecycle now pass
locally. These artifacts are the non-promotable P0 viability implementation
owned by `router-ab/ed25519-yao/implementation-plan.md` Phase 9C.

Independent reproduction, reviewer approval, public SDK cutover, profile
selection, deployed evidence, and production-promotion evidence remain open.
The implementation is **not yet complete enough for protocol-security proofs
or a production security claim**.

Until Yao Phase 13A records a `go`, formal work is limited to executable
safeguards on the active implementation: exact KATs, committed vectors,
differential correctness, bounded-parser properties, basic constant-time
qualification, and anti-drift checks. Deep compiler proofs, profile-security
experiments, external review ceremonies, and production-release proofs stay
paused. After `go`, those obligations target only the selected surviving
implementation.

Meaningful proof work begins in stages:

1. FV0 froze the reference-functionality and party-view boundary alongside Yao
   Phase 1. The construction-independent lifecycle and view models are attached.
2. Yao Phases 3-5 implement and measure the actual passive protocol before deep
   circuit/compiler proof starts. Their local viability scope is complete.
3. Yao Phase 6A selects and freezes one P0-P3 security profile, its exact claim,
   composition, provenance/output scope, lifecycle, garbling hash,
   implementation strategy, platform, and assumptions before selected-profile
   proof work starts.
4. Yao Phase 6B closes before FV6 claims implementation-linked evidence for
   the selected profile.
5. Yao Phase 13B closes before deployment-profile evidence is accepted, Yao
   Phase 14 closes before verification gates replace HSS gates, and Yao Phase 15
   closes before final release evidence is complete.

The maintainer should receive an explicit readiness notice at each gate. A
directory that builds, a reflexive view theorem, or a handwritten model alone
does not satisfy a readiness gate.

### Phase 6A Proof-Scope Gate

Before Phase 6A closes, formal work is limited to construction-independent
evidence:

- canonical encoders, KDF continuity, golden vectors, and anti-drift;
- lifecycle and value-custody ideal boundaries;
- oracle arithmetic and manifest identity;
- deterministic circuit and schedule equivalence;
- passive garbling functional correctness as benchmark-only evidence.

Construction-specific randomized outputs, stream retention/disposal, selected
provenance and output binding, selected session or preprocessing-ticket state,
and profile-specific real/ideal work begin only after the signed Phase 6A
decision record freezes their targets. Malicious OT and an active compiler are
P1-P3 targets only when required by the selected claim. FV6 links the frozen
targets to the Phase 6B production implementation. Proof artifacts for losing
candidates are deleted before product integration.

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
- consuming, at-most-once selected session or preprocessing-ticket transitions;
- the exact correctness, privacy, corruption, and abort properties claimed by
  the Phase 6A-selected profile: P0 honest execution and passive one-Deriver
  privacy, P1 only its reviewed subset, and P2/P3 one-malicious-Deriver
  correctness with abort;
- the exact weaker claim available to same-account development deployments;
- mechanically checked correspondence between narrow Rust boundaries and the
  Lean model.

The following remain outside the mechanized claim unless later phases add a
reviewed proof track for them:

- A+B collusion;
- platform compromise spanning both independent administrative domains;
- simultaneous compromise of both independent deployment authorities;
- side channels outside the reviewed Rust/WASM/native compiled constant-time
  boundary;
- entropy-source, compiler, hardware, TLS, and platform correctness;
- availability against a malicious participant;
- foundational security reductions for the selected hash, block-cipher or
  fixed-key primitive, HPKE, and signatures, plus malicious OT and an active
  Yao compiler when required by the selected P1-P3 claim.

Those items must appear in an assumption ledger. The final theorem and release
claim must reference that ledger directly.

## Source Precedence and Conflict Policy

Create a new Yao corpus. HSS specifications, proof files, theorem names, and
generated artifacts are historical inputs only.

The Yao corpus uses this precedence:

1. the approved security claim, corruption model, and topology in
   `docs/router-ab/ed25519-yao/implementation-plan.md`;
2. the lifecycle and value-custody boundary in
   `tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`, together with
   the frozen bit- and byte-level functionality produced by Yao Phase 1;
3. the proof-system-neutral provenance statement and epoch contract in
   `tools/ed25519-yao-generator/docs/input-provenance-v1.md`;
4. the host-only output-sharing arithmetic and corpus contract in
   `tools/ed25519-yao-generator/docs/output-sharing-v1.md`;
5. the construction-independent host output-custody composition and corpus in
   `tools/ed25519-yao-generator/docs/output-party-views-v1.md`;
6. the construction-independent accepted-evaluation input and ideal-coin
   custody composition and corpus in
   `tools/ed25519-yao-generator/docs/evaluation-input-party-views-v1.md`;
7. the signed Phase 6A selected-profile construction decision record and its
   versioned stream, session or ticket, deployment-profile, and release-SLO
   specifications;
8. the independently reproducible golden, KDF-continuity, and randomized vector
   corpora;
9. reviewed Rust source and deterministic circuit artifacts;
10. formal mirrors, generated Lean, handwritten models, and explanatory prose.

Any disagreement between two levels becomes a recorded compliance finding.
Proof work stops at the affected boundary until the authoritative source and
implementation agree. A formal model must never silently redefine behavior to
match a convenient implementation.

The explicit formal-verification gate regenerates prose golden bytes and digests from
`tools/ed25519-yao-generator` and diffs them against every versioned normative
specification. Formal anti-drift evidence consumes those exact generated
artifacts rather than manually copied constants.

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

- require Verus in the gated release-verification command and fail when it is unavailable;
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
share one installed verification toolchain:

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
owner. Its current proof-facing scope includes:

- four little-endian `y` contributions and wrapping addition modulo `2^256`;
- four canonical `tau` contributions and addition modulo `l`;
- `d -> SHA-512(d) -> clamp -> a`;
- `x_client_base = a + tau mod l`;
- `x_server_base = a + 2*tau mod l`;
- `2*X_client - X_server = A_pub`;
- separate seed-free activation and required-seed export outputs;
- the frozen visible-ASCII four-fact application binding with positive
  immutable `keyCreationSignerSlot` and no `nearAccountId`, mutable slot,
  version, or epoch;
- the frozen `StableKeyDerivationContext` and contribution KDF;
- synthetic same-logical-root client-KDF continuity and opposite-delta refresh
  arithmetic;
- nonserializable five-branch host-semantic lifecycle types and a synthetic
  activation-metadata continuation;
- the committed six-case synthetic registration-metadata/activation/recovery/
  activation/refresh/activation continuity corpus and its independent Python
  reproduction.
- typed host-only client/SigningWorker scalar sharing and export-only seed
  sharing, with a strict six-case corpus independently reproduced by Python.
- a narrow host-only registration preparation that derives four role/source-
  separated contribution pairs from three purpose-typed public synthetic roots
  and one stable context, evaluates seed-free activation arithmetic, and
  composes the result with typed scalar sharing.
- a narrow host-only export preparation that accepts a caller-supplied validated
  registered key, requires equality with the host export oracle's derived public
  key before sharing, and move-consumes the prepared output into typed seed
  shares without exposing joined seed or oracle material.
- a narrow host-only same-root recovery preparation that validates current
  role-separated client KDF contributions, preserves both Derivers' server
  contributions, witnesses exact joined-seed and activation-output continuity,
  and composes the recovered activation output with typed scalar sharing.
- a narrow host-only refresh preparation that consumes move-owned A/B ideal
  delta contributions, derives their nonzero modular sum, preserves both Derivers' client
  contributions, applies exact Deriver A `+delta` and Deriver B `-delta` server
  fields, witnesses joined-seed and activation-output continuity, and composes the refreshed
  activation output with typed scalar sharing.
- construction-independent host-only output views for registration, recovery,
  and refresh package preparation, activation metadata consumption, and export
  release. Five core relation tests, two compile/static boundary tests, a strict
  five-case corpus with six Rust and nine independent Python tests, and nine Lean
  policy-shape theorems cover seven closed role extensions and consuming static
  A/B observation.
- construction-independent accepted-evaluation input views for registration,
  activation, recovery, refresh, and export. Five core tests, two compile/static
  boundary tests with 16 rejection fixtures, a strict five-case corpus with
  seven Rust and nine independent Python tests, and 22 Lean policy-shape
  theorems cover branch-typed A/B inputs, y-only export, zero-work activation,
  ideal-function coin custody, output reproduction, and static A/B observation.
- host-only activation delivery with monotonic authorization, exact
  same-evaluation share retention, atomic Client/SigningWorker capability
  release, uncertainty/redelivery self-loops, four Rust corpus tests, five
  independent Python tests, and ten Lean theorems.
- host-only activation recipient views across release and verified worker
  activation, with seven closed roles, narrow recipient custody, a strict
  three-origin corpus, four core tests, two compile/static guards, six Rust
  corpus tests, seven independent Python tests, and twelve Lean theorems.
- a complete host-reference export evaluator that requires two independently
  verified role-pinned A/B authorization acceptances over one exact ceremony,
  provenance pair, authenticated store resolution, identity, state version, and
  one-use execution. Seven core tests, five strict corpus tests, seven
  independent Python tests, and twelve Lean theorems cover the ordered
  acceptance pair, one evaluation, output commitment, and release-time
  authorization consumption.
- a complete construction-independent host-reference registration evaluator
  that consumes one sealed admission over the exact ceremony, intent,
  provenance pair, two opaque input-selection evidence identities, checked-at
  time, activation epoch, and execution identity. Eight core tests, five strict
  corpus tests, seven independent Python tests, and twelve Lean theorems cover
  one evaluation, candidate/receipt identity, stable-scope enforcement, and
  terminal selection retention through success and abort.
- a complete construction-independent host-reference recovery evaluator that
  consumes one sealed admission over the exact ceremony, ordered provenance,
  strictly verified old state, checked-at time, distinct replacement credential,
  same-root artifact identity, selected-mechanism acceptance identity, advancing
  activation epoch, and one-use execution. Eight core tests, five strict corpus
  tests, seven independent Python tests, and twelve Lean theorems cover old-
  credential suspension, one evaluation, exact output binding, and terminal
  authority retention through abort, worker activation, and promotion.
- a complete construction-independent host-reference refresh evaluator that
  consumes one sealed admission over the exact ceremony, ordered provenance,
  strictly verified current state, checked-at time, exact current and proposed
  A/B role-state bindings, continuity-artifact identity, selected-mechanism
  acceptance identity, advancing activation and role epochs, and one-use
  execution. Eight core tests, five strict corpus tests, seven independent
  Python tests, and twelve Lean theorems cover one evaluation, exact output
  binding, registered-state abort retention, worker-activation gating, and
  terminal authority retention through promotion.

Full party views covering frames and remaining delivery behavior, durable
persistence transitions, corruption interfaces, and value-learning statements
remain Phase 1 work. The registration case above is
a public candidate-metadata snapshot retained as an older continuity
attachment. The complete host registration evaluator remains variable-time,
construction-independent evidence. Its unregistered claim is public-scope-only
and it establishes no authenticated absence, durable uniqueness, production
input-opening/anti-bias verification, persistence promotion, role-private
constant-time execution, or profile-security claim. The
host-only export reference is variable-time public-synthetic evidence. It checks
one structurally validated caller-supplied expected key before sharing, then
returns only typed seed shares from its consuming output step. It does not
authenticate expected registered state, consume authorization, enforce replay,
prove provenance or original-seed continuity, establish unbiased randomness,
create private recipient outputs, packages, receipts, or persistence, establish
constant-time or P0-P3 security evidence, or implement the complete
`evaluate_export_v1` functionality by itself. The separate export evaluator-
authorization composition supplies that host functionality with signed A/B
acceptances. Its authorization record remains opaque, and production key
distribution, clock integrity, replay persistence, transport, recipient
encryption, constant-time execution, and P0-P3 security remain excluded. The
narrow recovery reference is
variable-time public-synthetic evidence; it is not the
complete `evaluate_recovery_v1` functionality and has no production root,
proof, authorization/state, package, receipt, persistence, or cutover claim.
The separate recovery evaluator-admission composition supplies the complete
construction-independent host functionality with authenticated old state, a
distinct replacement credential, typed suspension, one evaluation, output
binding, and terminal retention. Its same-root artifact and selected-mechanism
acceptance digest are distinct opaque identities. Production same-root proof
validity, private-input opening, root custody, durable replay/atomicity,
transport, constant-time execution, and every P0-P3 security claim remain
excluded.
The narrow refresh reference is also variable-time public-synthetic evidence.
It does not by itself implement the complete `evaluate_refresh_v1` functionality
and establishes no
client-root/KDF provenance; deployed unbiased delta generation, custody, or
proof; authorization, state, or epoch transition; package; receipt;
persistence; distributed cutover; role-private execution; or active-security
claim.
The separate refresh evaluator-admission composition supplies the complete
construction-independent host functionality with authenticated current state,
exact proposed A/B next-state authority, one evaluation, output binding,
registered-state abort retention, verified-activation gating, and terminal
retention through promotion. Its continuity artifact and selected-mechanism
acceptance digest are distinct opaque identities. Production transition-proof
validity, private-input opening, delta entropy/independence/anti-bias, selective-
abort and retry-grinding resistance, forward security, mobile-adversary healing,
secure erasure, durable replay/atomicity/retirement, transport, constant-time
execution, and every P0-P3 security claim remain excluded.

The output-party-view evidence freezes host-reference output custody only. Its
portable corpus intentionally exposes synthetic role-private values to the
independent verifier and supplies no production encoding or public-leakage
classification. It does not prove delivery, memory erasure, noninterference,
simulator equivalence, protocol privacy, adaptive-corruption security, or any
selected P0-P3 claim.

The clear oracle stays host-only and synthetic. Production crates retain no
reverse dependency on it.

### Verus implementation proofs

The Verus crate mirrors stable security boundaries rather than allocation and
performance internals. Initial targets are:

- digest role types and nonzero validation;
- activation/export bundle and output-schema separation;
- metric nonzero, sum, and overflow invariants;
- the exact canonical manifest preimage order and length;
- domain, family, schema, seven artifact digests, and thirteen metrics binding;
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

### Lean functionality and selected-profile security model

The pinned post-attachment 158-theorem Lean slice contains three manifest rehearsals, nine
structural output-view theorems, 22 accepted-evaluation input/coin-custody
theorems, four uniform-abort theorems, seven evaluator-abort theorems, seven
export-delivery theorems, ten activation-delivery theorems, twelve
activation-recipient party-view theorems, twelve recovery credential-transition
theorems, twelve export evaluator-authorization theorems, and twelve
registration evaluator-admission theorems, twelve recovery evaluator-admission
theorems, twelve refresh evaluator-admission theorems, and twenty-four semantic-
frame party-view theorems. The counted Lean gate
passes at this total. These theorems cover
A/B role exclusion, public-only Router/Observer/diagnostics views, export-client-
only seed visibility, a public-only SigningWorker across all five frozen stages,
zero new output during activation metadata consumption, static one-Deriver
observation, branch/family input separation, infrastructure exclusion, y-only
export, zero-input activation, and ideal-function coin exclusion from party
views, plus the exact finite stage/request/plan/count, pre-state-class, seven-
role, and static-observation tables, plus host-only authorization/capability
ordering and narrow post-release recipient custody. These are policy-shape
results. The pre-
state table does not authenticate a companion or store. The model establishes
no noninterference or protocol privacy.

The eventual Lean model defines distinct records for Client, Router, Deriver A,
Deriver B, SigningWorker, recipients, and public observers. Each complete view
contains that party's input, randomness, received frames, sent frames, outputs,
leakage, and abort reason.

Every profile proves the exact functionality, output custody, transcript
binding, and public failure contract it implements. Security games are indexed
by the Phase 6A-selected claim:

- P0 proves honest execution and passive privacy for each one-Deriver view;
- P1 proves only the independently reviewed one-sided or attack-specific games
  named by its complete composition;
- P2/P3 prove separate Router-plus-corrupt-A and Router-plus-corrupt-B
  real/ideal games, correctness with abort, and the selected active composition.

Where a game uses simulation, real and ideal executions vary honest inputs while
preserving declared public leakage. Simulators receive only the corrupt party's
input, authorized output, public values, leakage, and abort information. A
theorem that compares one view expression with itself does not satisfy any
profile's privacy requirement.

The expected theorem families are:

- `activation_refines_fixed_functionality`;
- `export_refines_authorized_export_functionality`;
- `activation_has_no_seed_output`;
- `p0_honest_execution_correct` and passive A/B view theorems when P0 is
  selected;
- the exact approved targeted games when P1 is selected;
- `correctness_with_abort_corrupt_a` and
  `correctness_with_abort_corrupt_b` when P2/P3 are selected;
- `privacy_under_one_corrupt_deriver_a` and
  `privacy_under_one_corrupt_deriver_b` when P2/P3 are selected;
- selected-profile abort, provenance, and input-consistency obligations;
- `output_share_unbiased`;
- `no_deriver_obtains_joined_output`;
- `selected_session_or_ticket_consumes_at_most_once`;
- `export_authorization_sound`.

Names may change after the security profile and exact claim are selected. Their
statements must encode the assumption record, supported corruption set, and
explicit residual exclusions.

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
| Selected session/ticket use is at most once | selected lifecycle        | Verus state-machine invariant + extracted bridge       | selected replay/storage premise                                      |
| Selected-profile privacy/correctness claim | selected P0-P3 suite      | profile-indexed Lean/refinement evidence                | exact Phase 6A cryptographic and operational assumptions              |
| Same-account development isolation       | deployment profile           | typed profile and conditional topology lemma           | honest shared administrator/control plane                            |
| Independent-domain production separation | deployment profile           | production type exclusion + conditional topology lemma | operational attestation of independent administrators                |

No row is considered proved until its production link, generated-artifact
link, assumption set, and verification command are all present.

## Trusted Computing Base and Assumption Ledger

At minimum, record:

- `sha2` SHA-256 and SHA-512 behavior;
- `curve25519-dalek` scalar reduction and basepoint operations used by the
  oracle and boundary checks;
- the chosen garbling primitive and domain-separated gate tweaks;
- the selected OT and garbling security assumptions; malicious OT, an active
  compiler, input consistency, and active-output authentication enter only when
  required by the selected P1-P3 claim;
- OS, Worker, Container/native, and Web Crypto randomness where selected;
- HPKE, signatures, TLS, peer authentication, and key custody;
- constant-time and secret-erasure boundaries;
- Rust, LLVM/WASM, Verus, Aeneas, Charon, Lean, and circuit-generator
  correctness;
- selected persistence atomicity and durability used by the session or ticket
  proof; Durable Objects and preprocessing assumptions enter only when selected;
- no A+B collusion;
- the administrative-independence premise for production;
- the honest shared-control-plane premise for same-account development.

Each assumption has an owner, evidence link, affected theorem IDs, review date,
and invalidation trigger.

## Deployment Profile Semantics

All approved deployment profiles instantiate the Phase 6A-selected security
profile and its reviewed protocol and circuit artifacts. They supply different
operational premises.

### Same-account development

The formal claim may cover one runtime-confined corrupt Worker while the shared
account administrator, CI, deployment control plane, bindings, and platform
remain honest. A shared administrator can replace or inspect both Derivers,
which is equivalent to A+B compromise and lies outside the protocol theorem.

This profile supports local development, staging, and optimistic latency
measurement. It does not instantiate the strict server-blind production claim.

### Independent-domain production

The formal protocol claim is the Phase 6A-selected P0-P3 claim. P0/P1 do not
inherit the P2/P3 Router-plus-one-malicious-Deriver theorem. Independent
administrator and deployer control plus no A+B collusion remain operational
premises checked by configuration, release evidence, and human review. Lean
cannot derive administrative independence from a deployment identifier.

Phase 6A selects exactly one security profile and one production platform:
separate-account Cloudflare Workers, separate-account Cloudflare Containers, or
independently administered native services. Each pairing supplies distinct
premises for constant-time execution, randomness, selected persistence,
erasure, placement, transport, CPU features, and supply-chain integrity. A
proof for one pairing does not establish another profile or platform.

The production configuration type must remain unable to represent the
same-account profile.

## Phased TODO

### Cross-plan phase crosswalk and status rules

`docs/router-ab/ed25519-yao/implementation-plan.md` owns Ed25519 implementation gates.
`docs/router-a-b-sol-refactor.md` owns the wider product migration and cleanup
gates. This document owns formal-evidence gates. A formal phase may prepare
mechanical scaffolding in parallel, but it cannot prove or open an implementation
phase whose production owner is absent or blocked.

| Yao implementation phases | Wider Router A/B phases | Formal-verification phases    |
| ------------------------- | ----------------------- | ----------------------------- |
| 0                         | 0                       | plan approval                 |
| 1                         | 1                       | FV0-FV1                       |
| 2-3                       | 2                       | FV2-FV4                       |
| 6A                        | 3A                      | gate before FV5/FV6           |
| 4-5                       | 3B                      | FV5                           |
| 6B                        | 3B                      | FV6                           |
| 7-8                       | 4-5                     | FV7                           |
| 9-10                      | 6                       | FV8 deployment assumptions    |
| 11                        | 7                       | FV7-FV8 integration evidence  |
| 12                        | 8                       | outside Ed25519 Yao proofs    |
| 13                        | 9                       | FV8 pre-cutover evidence gate |
| 14                        | 10                      | FV9 verification hard cutover |
| 15                        | 11                      | FV10 final release evidence   |

Phase 0 and Yao Phase 1 are closed. Yao Phase 2A is complete as provisional
benchmark evidence. The Phase 2B mechanical cross-corpus reconciliation is
attached; the counted named gate passes six focused Rust tests, four focused
Python tests, and direct five-case verification. Independent-host
reproduction, reviewer approval of circuit semantics and bit ordering, and the
Phase 2 exit remain open. The current oracle,
compiler, manifest, and reconciliation code do not open later security theorems.
A checked formal TODO means only that exact artifact or proof obligation is
complete.

### FV0: Freeze claims, sources, and proof obligations

Depends on: Yao Phase 0; runs alongside Yao Phase 1

- [ ] Create `docs/spec-corpus.md` with source precedence and exact immutable
      source revisions.
- [x] Define five disjoint lifecycle boundary contracts separately, including
      pre-state/success types, activation continuation, and export-only seed
      output.
- [x] Implement the nonserializable five-branch host-semantic type layer and a
      narrow synthetic activation-metadata continuation with typed origin-package
      context, an origin-distinct activation-control context, and
      retry-preserving proposal rejection.
- [x] Commit and independently reproduce the six-case synthetic registration
      metadata, all-origin activation, same-root recovery, and opposite-delta
      refresh lifecycle-continuity corpus.
- [ ] Close blocked private-input and transition semantics and freeze five
      executable ideal functionalities.
- [x] Freeze the exact `StableKeyDerivationContext` encoding, validation, and
      binding-digest bytes.
- [x] Freeze the Yao-only application-binding visible-ASCII grammar, digest
      preimage, validation, positive immutable `keyCreationSignerSlot`
      semantics, and golden vectors.
      Exclude circular `nearAccountId`, mutable/current signer slots, versions,
      and every root/deployment epoch.
- [x] Freeze role-local KDF integration and public-key continuity rules for the
      stable context.
- [x] Freeze same-logical-root recovery and opposite-delta refresh reference
      semantics with a static-corruption-only claim boundary.
- [x] Implement `YAO-REG-001` as the narrow host-only registration preparation
      and activation output-sharing composition: derive four exact role/source-
      separated contribution pairs from three purpose-typed public synthetic roots
      and one stable context, evaluate the seed-free activation projection, and
      reconstruct typed client and SigningWorker scalar shares in six focused
      Rust tests. Keep complete `evaluate_registration_v1`, production root
      custody/provenance/authentication, anti-bias, admission, authorization,
      package/receipt/persistence, private/constant-time execution, and every
      profile-security claim open.
- [x] Implement `YAO-EXP-001` as the narrow host-only export preparation and seed
      output-sharing composition: require a caller-supplied validated registered
      key to equal the host export oracle's derived public key before sharing,
      move-consume the prepared value without exposing joined seed or oracle
      material, reconstruct typed seed shares, and verify RFC 8032 public-key and
      signature parity in six focused Rust tests. Keep expected-key/state
      authentication, authorization consumption, replay, provenance or
      original-seed continuity, unbiased randomness, private/recipient outputs,
      packages/receipts/persistence, constant-time/profile security, and complete
      `evaluate_export_v1` open for this narrow component alone.
      The six named tests are
      `matching_registered_key_prepares_public_key_equality_witness`,
      `different_valid_registered_key_is_rejected_and_borrowed_inputs_retry`,
      `split_y_carry_and_wrap_reconstruct_exact_export_seed`,
      `seed_shares_match_independent_zero_one_and_max_arithmetic`,
      `reconstructed_rfc8032_seed_signs_and_verifies_with_registered_key`, and
      `source_and_ui_guards_keep_export_synthetic_seed_scoped_and_nonproduction`.
- [x] Implement `YAO-EXP-002` and freeze
      `export-evaluator-authorization-v1.md`: require distinct trusted A/B
      Ed25519 authorities, independently verify both exact 24-field role
      acceptances, bind their ordered pair to one authenticated store resolution,
      ceremony/provenance graph, state/version, identity, and execution ID, then
      perform exactly one export evaluation and retain the pair through output
      commitment and Client release. Count seven core tests, five strict corpus
      tests, seven independent Python tests, and twelve Lean theorems. Keep
      authorization-record policy validation, production authority discovery,
      clock integrity, global replay, transport, recipient encryption, durable
      receipt storage, constant-time execution, and P0-P3 security outside this
      host-only claim.
- [x] Implement the narrow host-only recovery preparation and activation
      output-sharing composition with equal-root/current-KDF validation,
      preserved server contributions, exact activation continuity, and six
      counted Rust tests. Keep complete `evaluate_recovery_v1` and every
      production custody/proof/state/deployment claim open.
- [x] Implement `YAO-REC-002` as the construction-independent complete host-
      reference recovery evaluator: consume one sealed admission binding the
      exact ceremony, ordered provenance, strictly verified old state, checked-
      at time, distinct replacement credential, two separate opaque recovery-
      evidence identities, advancing activation epoch, and one-use execution;
      suspend the old credential before one evaluation; bind output commitment;
      and retain the terminal authority through abort, verified recovery-origin
      worker activation, and promotion. Count eight core Rust tests, five strict
      corpus tests, seven independent Python tests, and twelve Lean structural
      theorems. Keep proof validity, production private-input opening, root
      custody, durable suspension/replay/atomicity, transport, constant-time
      execution, and P0-P3 security open.
- [x] Implement `YAO-RFR-001` as the narrow host-only refresh preparation and
      activation output-sharing composition: consume move-owned role-local
      ideal delta contributions, derive their nonzero modular sum, preserve client fields,
      apply exact Deriver A `+delta` and Deriver B `-delta` server fields,
      witness joined and activation continuity, and reconstruct typed scalar
      shares in six focused refresh tests plus six joint-delta tests. Keep
      complete `evaluate_refresh_v1`, root/KDF provenance, deployed delta
      generation/custody/proof, lifecycle state,
      deployment, role-private execution, and profile-selected security claims
      open.
- [x] Implement `YAO-RFR-002` as the construction-independent complete host-
      reference refresh evaluator: consume one sealed admission binding the
      exact ceremony, ordered provenance, strictly verified current state,
      current/proposed A/B role-state bindings, two separate opaque transition-
      evidence identities, advancing activation and role epochs, and one-use
      execution; perform one evaluation; bind output commitment; preserve the
      registered state on abort; and retain terminal authority through verified
      refresh-origin worker activation and promotion. Count eight core Rust
      tests, five strict corpus tests, seven independent Python tests, and twelve
      Lean structural theorems. Keep transition-proof validity, production
      private opening, delta entropy/anti-bias, selective-abort/grinding,
      erasure/healing, durable replay/atomicity/retirement, transport, constant-
      time execution, and P0-P3 security open.
- [x] Freeze the proof-system-neutral provenance statement slots, outer
      encoding, role pairing, and root/input-state epoch meanings.
- [x] Implement the construction-independent provenance outer layer with sealed
      A/B types, strict structural parsers, fixed request/family dispatch,
      role-typed epochs, canonical vectors, and independent Python
      reproduction.
- [ ] Close production root custody, the selected registration input-selection
      contract, refresh-delta generation, and distributed-realization
      contracts. Leave each mechanism as either a Phase 6A-selected proof
      obligation or an explicit residual exclusion, with implementation linkage
      in FV6.
- [ ] State the anti-bias, selective-abort, and retry guarantees actually
      selected. P0 records honest-derivation/output assumptions and active
      exclusions; stronger profiles prove only their reviewed composition.
      Record client vanity-key grinding as a separate product/admission premise.
- [x] Freeze output custody, ideal sharing randomness, common public leakage,
      forbidden values, and the uniform abort-envelope shape.
- [x] Implement the exact four-field `UniformLifecycleAbortV1` for all five
      validated ceremony kinds, remove request-context and blame-bearing
      fields, commit a strict five-case ceremony-linked corpus, reproduce it in
      five independent Python mutation tests, and add four Lean shape theorems.
      Keep evaluator/protocol failure integration, frame/ticket handling,
      timing equivalence, selective-failure resistance, and P0-P3 correctness-
      with-abort open.
- [x] Freeze and implement the deterministic host-only output-sharing
      reference, typed role/recipient shares, strict six-case corpus, and
      independent Python reproduction. Keep active sampling, private output
      translation, authentication, and encryption outside this claim.
- [x] Freeze and implement construction-independent host output views for five
      lifecycle stages and seven roles, with equal common-public leakage,
      closed role extensions, static consuming A/B observation, and strict
      output-family separation. Keep runtime delivery and selected-protocol
      claims outside this boundary.
- [x] Bind activation package artifacts and exact typed A/B shares from one
      evaluation into a single move-only output commitment, retain it through
      all three pending origins and metadata consumption, and make the
      package-prepared view builder consume only that typed lifecycle state.
      Delete independent-share fixture helpers and the obsolete substitution
      test.
- [x] Start `YAO-DELIVERY-002` with the activation authorization timeline and
      atomic two-recipient release. Metadata-consumed exact output now moves
      through uncertainty into disjoint Client and SigningWorker capabilities;
      raw metadata can no longer activate the SigningWorker; rejection retains
      the exact authority; and authenticated opened worker shares are compared
      in constant time with the retained same-evaluation shares. Two focused
      Rust tests cover all origins, retry, redelivery, and zero reevaluation.
      The package-prepared Client projection is now empty; its scalar exists
      only in the released Client capability. The strict three-origin delivery
      corpus, four Rust corpus tests, five independent Python tests, and ten
      Lean delivery theorems now cross-link and freeze the same host-only
      authorization, identity, custody, and capability relations. Production
      opening, transport, durable replay, complete runtime views, and
      selected-profile security remain open.
- [x] Freeze the narrow post-release activation recipient-party-view boundary.
      The two-stage, seven-role host-only model retains the exact Client scalar
      capability, exposes only opaque SigningWorker authority before strict
      receipt verification, seals activated worker custody, preserves identity
      through redelivery, and keeps Deriver/infrastructure extensions empty.
      Four core tests, two compile/static guards, a six-test three-origin Rust
      corpus, seven independent Python tests, and twelve Lean theorems cover the
      structural claim. Runtime frames, durable delivery, erasure,
      noninterference, and selected-profile security remain open.
- [x] Commit the strict five-case output-party-view corpus and nine Lean
      structural policy theorems. Nine independent Python tests reproduce its
      companion-linked relations and mutation boundary. Treat its synthetic
      role-private values as verifier evidence only; make no noninterference,
      erasure, corruption-game, simulator, or protocol-privacy claim.
- [x] Implement `YAO-DELIVERY-001` for export: split output commitment from
      Client release, retain the exact evaluation package/share identity through
      delivery uncertainty, consume authorization only at release, construct the
      Client view solely from the released transition, and model exact-identity
      redelivery with zero private reevaluation. Commit the normative companion,
      strict one-case corpus, four Rust tests, five independent Python tests,
      compile/static API guards, and seven Lean structural theorems. Keep the
      production opener, transport, durable replay, acknowledgement, and P0-P3
      claims open.
- [x] Freeze accepted-evaluation role-private input custody and ideal-function
      coin custody in `evaluation-input-party-views-v1.md`; implement branch-
      typed nonserializable Rust views and coins, a strict five-case companion-
      linked corpus, seven Rust corpus tests, nine independent Python mutation
      tests, and 22 Lean structural theorems. Keep runtime frames, delivery,
      authoritative pre-state, noninterference,
      randomness security, and P0-P3 claims outside this evidence.
- [ ] Freeze the remaining complete randomness/frames, selected
      persistence views, and the exact profile-specific abort equivalence.
- [ ] Define the adversary games required by each eligible P0-P3 claim and every
      excluded corruption set.
- [x] Create stable proof-obligation identifiers for the implemented FV1
      surface.
- [x] Create the trusted-computing-base and assumption ledger.
- [ ] Audit the Yao plan, oracle, manifests, and vectors for contradictions.
- [x] Add the generator-owned `fixed-reference-v1.md` normative specification
      and its counted `reference-spec-check` regeneration gate.
- [x] Add `output-sharing-v1.md` as a counted normative companion and commit
      its complete bytes through the generated fixed-reference block.
- [x] Add `circuit-ir-v1.md` as a counted provisional Phase 2A companion and
      commit its complete bytes through the generated fixed-reference block.
- [x] Add `ceremony-context-v1.md` and `input-provenance-v1.md` as counted
      normative companions and commit their complete bytes through the generated
      fixed-reference block.
- [x] Add `semantic-artifact-lifecycle-v1.md` and `output-party-views-v1.md` as
      counted normative companions, commit their complete bytes through the
      generated fixed-reference block, and attach their strict five-case
      corpora.
- [x] Add `evaluation-input-party-views-v1.md` as the eighth counted reference
      document, commit its complete bytes through the generated fixed-reference
      block, and attach its strict five-case corpus.
- [x] Add `uniform-abort-envelope-v1.md` as the ninth counted reference
      document, commit its complete bytes through the generated fixed-reference
      block, and attach its strict five-case corpus.
- [x] Add `evaluator-abort-state-party-views-v1.md` as the tenth counted
      reference document, commit its complete bytes through the generated
      fixed-reference block, and attach its strict four-case corpus.
- [x] Add `export-delivery-lifecycle-v1.md` as a counted normative companion,
      commit its complete bytes and strict one-case corpus through the generated
      fixed-reference block, and include it in Rust/Python/formal gates.
- [x] Add `recovery-credential-transition-v1.md` as a counted normative
      companion, commit its strict one-case corpus, independently reconstruct
      its pinned-authority receipt in Python, and include its twelve suspension/
      promotion theorems in the counted Lean gate.
- [x] Add `export-evaluator-authorization-v1.md` as `YAO-SPEC-021`, commit its
      strict one-case corpus, independently verify both pinned A/B signatures and
      lifecycle cross-links in Python, and include its twelve acceptance/lifecycle
      theorems in the counted Lean gate.
- [x] Add `registration-evaluator-admission-v1.md` as `YAO-SPEC-022`, commit its
      strict one-case corpus, independently reconstruct admission, candidate,
      receipt, retry, and nonclaim boundaries in Python, and include its twelve
      structural lifecycle theorems in the counted Lean gate.
- [x] Add `recovery-evaluator-admission-v1.md` as `YAO-SPEC-023`, commit its
      strict one-case corpus, independently reconstruct store/admission/output/
      retry bindings in Python, and attach its twelve suspension/retention
      theorems to the Lean model. The counted Rust, Python, Lean, reference-spec,
      and vector gates pass at the pinned post-attachment totals.
- [x] Add `refresh-evaluator-admission-v1.md` as `YAO-SPEC-024`, commit its
      strict one-case corpus, independently reconstruct store/admission/current-
      and-next-state/output/retry bindings in Python, and attach its twelve
      retention/promotion-gating theorems to the Lean model.
- [x] Add `semantic-frame-party-views-v1.md` as `YAO-SPEC-025`, commit its
      strict eight-case corpus, independently reconstruct the eleven frame
      classes, eleven states, seven cumulative role views, exact observations,
      retry/redelivery policies, ten corruption markers, and four interface
      shapes, and attach twenty-four structural Lean theorems. Runtime frame
      bytes, durable state, simulators, experiments, noninterference,
      indistinguishability, profile satisfaction, and protocol security remain
      later gates.
- [x] Attach `phase2b-core-reconciliation-v1.md` as `YAO-SPEC-026`, commit its
      strict five-case certificate, bind all twenty Phase 1 corpus commitments
      and the exact `EYAOBM01` candidate, and register `YAO-CIR-003` for closed
      field/wire/output mappings, separate IR/schedule evaluation, party-output
      reconstruction, authorized export Client reconstruction, and activation's
      zero-evaluation continuation. Six focused Rust and four independent Python
      tests form the attachment slice. Reconciliation derives output relations
      from coherent output-party-view projections, while output-sharing remains
      independently committed. The counted named gate passes six Rust tests,
      four Python tests, and direct five-case verification.
      Independent-host reproduction, reviewer approval, and the Phase 2 exit
      remain open.
      The certificate's exact ordered nonclaims are
      `production_artifact_authority_absent`,
      `selected_security_profile_absent`, `garbling_and_ot_unimplemented`,
      `randomized_output_protection_unimplemented`,
      `simulator_and_security_experiment_unimplemented`,
      `runtime_frame_and_transport_encoding_absent`,
      `durable_lifecycle_and_replay_semantics_absent`,
      `production_constant_time_and_erasure_unclaimed`,
      `independent_operator_reproducibility_unclaimed`, and
      `reviewer_approval_absent`.
- [x] Attach the host-only `phase2b-exit-evidence-v1.md` contract as
      `YAO-SPEC-027`, pin its complete SHA-256 outside the generator-owned
      fixed-reference block, and add twenty readiness tests for canonical
      records, distinct non-weak authorities, strict signatures, exact policy,
      subject/source/observation/challenge/report binding, sequence floors,
      fixed review scope, and nonclaims. Acceptance consumes private trusted
      capabilities. The fixed-path subject and independently decoded fresh-
      observation builders add eleven passing tests and join the clean-checkout
      local gate.
      The isolated captured-commit rebuild passes a disposable clean-checkout
      integration run, producing one canonical 15757-byte subject and six exact
      observations. Protected policy/challenge loading adds eight passing tests
      over fixed environment names and private capabilities. The zero-argument
      prepare command now executes reconciliation and subject construction in
      one private captured-commit checkout. The zero-argument bounded finalize
      command strictly verifies the external raw-digest signature and exact
      rebuilt subject. Their clean-repository integration passes end to end.
      The fixed Git-object record checker accepts only the exact four-blob
      `C → E` evidence shape and passed a disposable clean integration. The
      approval checker consumes that verified-reproduction capability and
      validates the fixed report and approval blobs before issuing a stronger
      private capability. A disposable complete command-boundary integration
      passes with synthetic test-only authorities and an exact clean `C → E`
      evidence commit. Genuine externally governed evidence and the Phase 2
      exit remain open.
- [ ] Add later normative specifications and the Phase 6A decision-record schema
      to the spec corpus as they freeze; regenerate their golden bytes in the
      anti-drift gate.
- [ ] Resolve every critical or high compliance finding.
- [ ] Obtain independent cryptographic review of the claim boundary.

Exit gate:

- [x] Yao Phase 1 construction-independent functionality freeze is complete.
- [x] Two independent implementations reproduce the full Phase 1 vector corpus.
- [x] Each Phase 1 theorem target has one exact source statement and owner.
- [x] No construction-independent lifecycle, party-view, topology, or export
      ambiguity remains; runtime/profile realization stays in later phases.

### FV1: Build the mechanical scaffold

Depends on: plan approval; may run alongside the end of FV0

- [x] Create the directory layout in this document.
- [x] Add a host-only task-runner crate under `formal-verification/tasks`.
- [x] Add `cargo yao-fv` and `just ed25519-yao-fv` commands.
- [x] Pin the installed constant-time analyzer and Python lockfile digests, then
      add `cargo yao-fv constant-time-qualification` with safe and intentionally
      vulnerable native assembly fixtures at `O0` and `O3`. This qualifies the
      tool path without making a production-kernel claim.
- [x] Add a lightweight benchmark-kernel codegen gate over optimized host and
      exact Deriver A/B Worker WASM, plus a dedicated Linux CI job with the
      WASM target and `llvm-objdump`. It caught and prevents the secret IKNP
      branch introduced by optimizing hand-written masking.
- [x] Bind that Worker-WASM inspection to the exact prebuilt benchmark modules
      accepted by the v2 deployment receipt and uploaded with Wrangler
      `--no-bundle`; stale or mismatched digests fail before either role deploys.
- [ ] Confirm the clean Linux x86-64 CI qualification and connect native plus
      generated-WASM inspection to the Phase 6B-selected production kernels.
- [x] Add a counted `cargo yao-fv reference-spec-check` command for the
      generator-owned fixed-reference normative specification.
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
- [x] Add construction-independent Verus obligations and Rust anti-drift for
      provenance request tags, activation exclusion, request-to-family mapping,
      and fixed A/B role order.
- [x] Count the Phase 2A circuit target plus the six-test registration-, export-,
      recovery-, and refresh-reference Rust targets, 11 output-party-view tests,
      14 evaluation-input party-view tests, four uniform-abort corpus tests, and
      four evaluator-abort state/party-view tests, four export-delivery core
      tests, four export-delivery corpus tests, two activation-delivery core
      tests, four activation-delivery corpus tests, four activation-recipient
      party-view core tests, two activation-recipient compile/static guards,
      and six activation-recipient corpus tests,
      seven recovery credential-transition core tests and five strict recovery
      credential-transition corpus tests,
      seven export evaluator-authorization core tests and five strict export
      evaluator-authorization corpus tests,
      eight registration evaluator-admission core tests and five strict
      registration evaluator-admission corpus tests,
      eight recovery evaluator-admission core tests and five strict recovery
      evaluator-admission corpus tests,
      eight refresh evaluator-admission core tests and five strict refresh
      evaluator-admission corpus tests,
      ten semantic-frame core tests, three semantic-trace boundary tests, and
      six strict semantic-frame corpus tests,
      ten profile-neutral
      SigningWorker-activation tests, six refresh-promotion tests, and six
      benchmark-manifest tests plus six joint-refresh-delta tests independently.
      Pin the post-reconciliation generator evidence total at 418 tests,
      including 19 circuit, six reconciliation, 11 artifact-bundle, and
      compile-fail tests. Count
      the isolated artifact-filesystem-policy crate's three platform-stable
      local-filesystem and ACL tests in the same parity gate. The counted named
      reconciliation gate passes all six focused Rust tests.
- [x] Pin the post-readiness aggregate evidence baseline at 27 reference
      documents, 21 corpora, 186 independent Python verifier tests, 418 generator Rust
      tests, and 158 Lean model theorems. Count changes are gated through
      `toolchain.toml`. The counted named reconciliation gate passes six focused
      Rust and four focused Python tests; the separate host-only readiness gate
      passes twelve Rust tests.
- [x] Commit `authenticated-store-resolution-v1.md`, require strictly verified
      request-bound store authority before registered issuance, bind the active
      credential and recovery replacement/same-root artifact, and count seven
      signature/key/state/replay tests independently plus three lifecycle recovery
      continuity tests.
- [x] Commit `signing-worker-activation-v1.md`, implement sealed post-opener
      share validation and zeroizing origin-preserving activated state, require
      a strictly verified deterministic worker-bound receipt before release,
      and count ten focused tests independently. The selected-profile opener
      and durable activation-receipt storage remain later-phase work.
- [x] Commit `refresh-promotion-v1.md`, require a verified refresh activation,
      bind complete old/next state and A/B retirement edges into a strict store-
      authority receipt, retain the activated secret across retry, and count six
      focused tests independently. Production atomic storage remains Phase 7.
- [x] Commit `benchmark-manifest-v1.md` and derive a benchmark-only manifest
      internally from the three fixed compiler outputs. Freeze its 1973-byte
      encoding and digest, bind compiler/order/schema/bundle/artifact/metric
      identities, reject every noncanonical input, and count six focused tests.
      Four independent Python decode/mutation tests cross-check the complete
      format and wrapped index. Independent-host reproduction and reviewer
      approval remain Phase 2B gates.
- [x] Commit `artifact-filesystem-policy-v1.md`; require descriptor-only local-
      filesystem and ACL inspection for every opened artifact directory/file;
      reject macOS extended ACLs and remote/unrecognized Linux filesystem
      semantics; keep the narrow macOS FFI outside the unsafe-forbidden
      generator; and count all three policy-crate tests in parity.
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

- [x] Register separate executable obligations for canonical Boolean IR,
      fixed-input SHA-512, scalar reduction/addition, and typed activation/export
      benchmark cores without widening `YAO-SEC-001`.
- [x] Add exact gate/digest goldens and circuit comparisons over the five
      committed plus 128 deterministic public arithmetic cases.
- [x] Register deterministic liveness-schedule evidence for last-use slot
      reuse, read-before-overwrite safety, pinned outputs, metrics, and digests.
- [x] Add a fixed six-file provisional artifact emitter/checker with a canonical
      bundle index and counted missing/extra/mutation rejection evidence.
- [x] Add an independently implemented strict canonical-IR and schedule
      parser/evaluator, byte-for-byte schedule rederivation, frozen artifact
      digest checks, and dual evaluation over all five committed cases.
- [x] Attach the strict Phase 2B core-reconciliation certificate across all
      twenty Phase 1 corpora, exact input/output mappings, separate IR/schedule
      evaluation, party-output reconstruction, export Client reconstruction,
      and activation zero evaluation. This closes only the mechanical
      reconciliation deliverable under `YAO-CIR-003`. The counted named gate,
      six Rust tests, four Python tests, and direct verification pass.
      Independent reproduction, reviewer approval, and the remaining FV2 proof
      work stay open.
- [ ] Replace the provisional path-based artifact emitter/checkers with
      descriptor-relative no-follow I/O and atomic publication, or prove that
      every invocation uses a newly created process-private directory. Static
      symlink and bounded-read evidence does not cover hardlinks or concurrent
      path replacement.
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

Depends on: Yao Phase 6A, Yao Phases 4-5, and FV4

- [ ] Import the Phase 6A construction, randomized-output, stream request-graph,
      retention, challenge, and disposal decisions as fixed proof targets.
- [ ] Formalize the selected protocol-generated randomized output sharing.
- [ ] Prove honest P0 output sampling preserves role privacy. Prove only the
      anti-bias or malicious mask-selection resistance required by a selected
      P1-P3 composition.
- [ ] Prove recipient packages are disjoint and correctly bound.
- [ ] Prove activation output packages cannot carry export seed material.
- [ ] Prove frame-size, count, order, and sequence-number bounds.
- [ ] Prove incremental evaluation equals non-streaming evaluation.
- [ ] Prove transcript commitments bind all headers and payload frames.
- [ ] Prove role state never requires a whole-stream `Vec`.
- [ ] Model early EOF, duplicate, reordering, overflow, timeout, and abort.
- [ ] Prove that evaluation and disposal never precede the selected
      construction's commitment, challenge, checking, or retention obligations.

Exit gate:

- [ ] The private-output and streaming invariants are linked to Rust.
- [ ] Peak live state is bounded by manifest and protocol constants.
- [ ] No Deriver-visible state contains a joined scalar or seed.

### FV6: Model and prove the selected security-profile composition

Depends on: Yao Phases 6A and 6B plus FV3-FV5

- [ ] Import the reviewed Phase 6A P0-P3 profile, exact claim, assumptions,
      residual exclusions, OT/garbling choices, provenance/output scope,
      randomized-output construction, and garbling hash without widening them.
- [ ] Link every selected component to the exact Phase 6B implementation,
      parameter, artifact digest, and compiled target.
- [ ] State primitive and compiler assumptions at their exact call boundaries.
- [ ] For P0, prove honest execution against the fixed functionality and passive
      privacy for the separate A/B views; encode every active deviation as an
      explicit exclusion.
- [ ] For P1, prove only the independently approved targeted games and compose
      only the mechanisms included in the signed decision record.
- [ ] For P2/P3, define distinct corrupt-A/corrupt-B simulators and prove the
      reviewed malicious-OT/compiler, provenance/input-consistency,
      correctness-with-abort, selective-failure, anti-bias, and authenticated
      private-output composition.
- [ ] Prove the common output-custody, transcript-binding, and public failure
      properties required by the selected profile.
- [ ] Record the explicit absence of an A+B theorem.
- [ ] Obtain independent cryptographic review of assumptions and composition.

Exit gate:

- [ ] Production circuit and protocol IDs identify the reviewed selected suite
      and exact claim.
- [ ] The theorem assumptions and state machine match the signed Phase 6A
      decision record and Phase 6B production artifacts.
- [ ] Every theorem premise maps to code, artifact metadata, or an external
      assumption with evidence.
- [ ] No theorem relies on reflexive view equality as privacy evidence.
- [ ] The reviewer approves the exact wording of the supported security claim.

### FV7: Prove tickets, lifecycle, and Router adapter boundaries

Depends on: Yao Phases 7-8 and FV6

- [ ] Import the minimal lifecycle selected by Phase 6A/7. Model common fresh
      per-ceremony session, replay, output-preparation/commitment, release, and
      terminal states as consuming states.
- [ ] Add `Generated`, `Paired`, `Prepositioning`, `Available`, `Reserved`,
      reusable base-OT state, and preprocessing-ticket transitions only when the
      selected profile uses them.
- [ ] Prove the selected session or ticket reaches output release/`Consumed` at
      most once and cannot repeat OT state, labels, masks, or release contrary
      to the selected construction.
- [ ] Prove crash recovery preserves terminal-state monotonicity.
- [ ] Prove the replay/output-commit and circuit-version floor required by the
      selected lifecycle. Model `EpochFloorAuthorityV1`, base-OT revival
      prevention, bounded drains, and pre-activation ticket destruction only
      when Phase 6A/7 selects those mechanisms.
- [ ] Prove local busy rejection and durable budget rejection occur before
      selected session/ticket allocation; model durable burn attribution only
      for profiles with durable preprocessing budgets.
- [ ] Bind the selected session or ticket to request, account, epoch, circuit,
      protocol, peer, transcript, and recipient identities.
- [ ] Prove the Router adapter maps each lifecycle request to exact role-local
      inputs.
- [ ] Prove recovery remains seed-preserving and non-export.
- [ ] Prove export requires the explicit authorization branch.
- [ ] Extract stable pure protocol transitions with Aeneas.
- [ ] Bridge generated transitions into the Lean execution model.
- [ ] Add cross-crate anti-drift tests for `router-ab-ed25519-yao` and
      `router-ab-core` boundaries.

Exit gate:

- [ ] Selected session/ticket, lifecycle, and export-authorization claims are
      linked to Rust.
- [ ] Every selected epoch/circuit-floor safety claim is linked to its authority
      and production persistence boundary; unselected mechanisms are absent.
- [ ] Every extracted axiom and opaque function remains in the ledger.
- [ ] Router admission policy stays owned by Router A/B formal verification.

### FV8: Instantiate deployment profiles and validate pre-cutover evidence

Depends on: Yao Phases 9-10 and 13 plus FV7

- [ ] Define `SameAccountDevelopmentAssumptions`.
- [ ] Define `IndependentDomainProductionAssumptions` and the concrete Worker,
      Container, or native-service premises selected by Phase 6A.
- [ ] Prove the production configuration excludes same-account deployment.
- [ ] Map administrative-independence premises to deployment evidence.
- [ ] Map role-isolation premises to the selected runtime bindings, secrets,
      persistence, backups, logs, and erasure evidence.
- [ ] Map local admission, durable budget, persistence critical-path, epoch-floor,
      circuit-rollout, and burn-control premises to Phase 13 evidence.
- [ ] Run the full proof and anti-drift suite on native and WASM artifacts where
      applicable.
- [ ] Obtain pre-cutover independent formal-methods and deployment review.

Exit gate:

- [ ] The proposed release claim matches the proved conditional theorem exactly.
- [ ] Same-account evidence carries development-only wording.
- [ ] Selected strict-profile evidence demonstrates independent operational
      control.
- [ ] Every Phase 13 security and deployment premise maps to a checked theorem,
      explicit assumption, or reviewed external evidence item.

### FV9: Replace verification gates at hard cutover

Depends on: Yao Phase 14 and FV8

- [ ] Replace the HSS formal-verification default gate with the Yao gate in the
      same hard-cutover change.
- [ ] Delete HSS-only verification aliases, compatibility paths, generated
      artifacts, and proof jobs after their current owners move or are deleted.
- [ ] Require clean-checkout reproducibility in release verification.
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

The scaffold provides:

```sh
cargo yao-fv reference-spec-check
cargo yao-fv vectors-check
cargo yao-fv phase2b-reconciliation-check
cargo yao-fv phase2b-exit-evidence-readiness-check
cargo yao-fv phase2b-review-subject-check
cargo yao-fv phase2b-protected-inputs-check
cargo yao-fv phase2b-independent-host-prepare
cargo yao-fv phase2b-independent-host-finalize
cargo yao-fv phase2b-independent-host-record-check
cargo yao-fv phase2b-review-approval-check
cargo yao-fv cross-language-check
cargo yao-fv parity
cargo yao-fv anti-drift
cargo yao-fv verus-check
cargo yao-fv aeneas-check
cargo yao-fv lean-check
cargo yao-fv all

make -C crates/ed25519-yao/formal-verification check
just ed25519-yao-fv
```

The post-subject-builder `all` target runs twelve nonempty tracks, in order:

1. fixed-reference normative-spec regeneration and generated-region comparison;
2. vector regeneration and byte comparison;
3. independent Python reproduction of committed and deterministic differential
   vector corpora;
4. strict Phase 2B cross-corpus reconciliation against a fresh provisional
   artifact bundle;
5. host-only Phase 2B exit-evidence contract and rejection-suite readiness;
6. clean-checkout fixed review-subject and fresh-artifact-observation
   construction with eleven counted builder tests;
7. two isolated clean-build reproductions of the benchmark-only manifest;
8. Rust oracle/manifest parity, including compile-fail doctests;
9. production/mirror anti-drift tests;
10. Aeneas extraction, stable generated-Lean comparison, and explicit boundary
   builds;
11. the explicit Lean model build;
12. Verus verification through a driver in the same pinned release bundle.

Track 4's counted six-test Rust, four-test Python, and direct-verification slices
pass.

Every track checks an exact nonzero evidence count or explicit artifact list
from `formal-verification/toolchain.toml`.

After the FV1 empty-cache bootstrap gate closes, the aggregate repository
formal-verification command adds Yao while the implementation remains isolated.
At the Ed25519 hard cutover it removes the obsolete HSS gate in the same change.
The construction-independent `reference-spec-check`, `vectors-check`, and
benchmark-manifest reproducibility tracks remain available through explicit
local and release verification.

## Anti-Drift Policy

Proofs freeze security invariants, semantics, artifact identities, and visible
boundaries. They do not freeze internal allocation strategies or harmless
performance refactors.

Any accepted change to functionality, input/output schema, selected protocol
suite or security profile, stream transcript, selected session or ticket
lifecycle, or artifact encoding requires:

1. a new or updated proof obligation;
2. regenerated vectors and artifacts;
3. updated anti-drift fixtures;
4. proof and bridge updates;
5. a protocol/circuit/schema version change whenever wire compatibility or the
   security claim changes;
6. renewed review for every invalidated assumption.

## Readiness Dashboard

| Prerequisite                                                   | Current state                                                                                                                                                                        |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Frozen protocol, circuit-family, and output-schema identifiers | complete                                                                                                                                                                             |
| Typed draft manifest and canonical digest binding              | complete                                                                                                                                                                             |
| Isolated four-`y`, four-`tau` clear oracle                     | Phase 1 clear-reference and cross-language corpus complete; circuit-refinement proof remains later work                                                                              |
| RFC 8032 reference vectors                                     | Phase 1 oracle/vector attachment complete; production circuit and protocol review remain later work                                                                                  |
| Five lifecycle structural boundary families                    | construction-independent host evaluators and nonserializable semantic types are complete; all five families execute through the local P0 runtime; selected production-profile realization remains missing |
| Synthetic activation-metadata continuation                     | registration/recovery/refresh origins, semantic public-binding checks, move consumption, and zero reference work are executable                                                      |
| Six-case lifecycle-continuity corpus                           | committed Rust corpus and independent Python reproduction cover synthetic registration metadata/activation/recovery/activation/refresh/activation                                   |
| Narrow host-only registration reference                       | three purpose-typed public synthetic roots and one stable context derive four role/source-separated contribution pairs; seed-free activation and typed scalar sharing have six counted Rust tests; complete production registration remains missing |
| Narrow host-only export reference                             | a caller-supplied validated registered key must match the host export oracle before consuming prepared state yields typed seed shares; six counted Rust tests cover mismatch retry, custody, reconstruction, RFC 8032 parity, and exclusions; complete production export remains missing |
| Complete host-reference export evaluator                      | distinct pinned A/B authorities independently sign one request/provenance/store/state/execution binding; one evaluation retains the acceptance pair through commitment and consumes authorization at Client release; seven core, five corpus, seven Python, and twelve Lean checks pass, while policy-record validation, key distribution, clock/global replay, production transport/encryption/storage, constant-time execution, and P0-P3 security remain missing |
| Narrow host-only recovery reference                           | equal synthetic roots/current KDF inputs, server preservation, exact activation continuity, and activation scalar sharing have six counted Rust tests; complete production recovery remains missing |
| Complete host-reference recovery evaluator                    | one sealed ceremony/provenance/authenticated-state admission suspends the old credential, permits one evaluation, binds output, and retains terminal authority through abort, verified worker activation, and promotion; eight core, five corpus, seven Python, and twelve Lean checks form the post-attachment gate, while same-root proof validity, private openings, durable replay/atomicity, root custody, transport, constant-time execution, and P0-P3 security remain missing |
| Narrow host-only refresh reference                            | move-owned A/B ideal delta contributions derive one nonzero modular sum; unchanged clients, exact opposite server updates, joined/activation continuity, and typed scalar sharing have twelve counted Rust tests plus independent Python corpus checks; complete production refresh remains missing |
| Complete host-reference refresh evaluator                     | one sealed ceremony/provenance/authenticated-current-state admission fixes exact proposed A/B next-state authority, permits one evaluation, binds output, preserves registered state on abort, and retains terminal authority through verified worker activation and promotion; eight core, five corpus, seven Python, and twelve Lean checks pass, while transition-proof validity, private openings, delta entropy/anti-bias, selective-abort/grinding, erasure/healing, durable replay/atomicity/retirement, transport, constant-time execution, and P0-P3 security remain missing |
| Complete lifecycle evaluators and party views                  | complete host-reference evaluators, output/input/abort/recipient views, eleven semantic frame classes, seven cumulative role views, and profile-neutral corruption interfaces exist; runtime frame bytes, durable realization, simulators/experiments, and selected-profile views remain missing |
| Frozen Yao application binding                                 | visible-ASCII four-field encoder with positive immutable `keyCreationSignerSlot`, golden KDF vector, and independent Python reproduction complete                                    |
| Frozen `StableKeyDerivationContext` encoding and binding       | application binding through stable-context binding implemented in the host reference                                                                                                 |
| Stable-context KDF integration and continuity vectors          | implemented in isolated host-only reference                                                                                                                                          |
| Role-input provenance statement and epochs                     | host-only outer types, structural parser, four-case cross-language corpus linked to independently reconstructed ceremony DAGs, and tag/dispatch Verus obligations complete; authenticated artifact suite and production verifier missing |
| Authenticated registered-store resolution                      | exact signed encoding, non-weak epoch-bound Ed25519 authority key, active version/epoch/credential plus immutable identity and ceremony/provenance/state binding, move-only lifecycle retention, seven focused store tests, and three recovery credential-continuity tests complete; production parser, rollback floor, key distribution, custody/proof verification, and durable transactions remain missing |
| Host-only randomized-output reference                          | typed activation scalar and export-only seed shares plus a six-case cross-language corpus are complete; selected-profile sampling, private translation, authentication, and encryption are missing |
| Construction-independent output party views                    | five output stages, seven closed role extensions, static consuming A/B observation, a strict five-case Rust/Python corpus, and nine Lean policy-shape theorems complete; no runtime delivery or noninterference claim |
| Construction-independent evaluation-input party views         | five accepted-evaluation stages, branch-typed A/B inputs, y-only export, zero-work activation, host-only ideal coins, a strict five-case Rust/Python corpus, and 22 Lean policy-shape theorems including exact finite plan/count, pre-state-class, role, and static-observation tables complete; no authoritative pre-state, runtime delivery, randomness-security, or noninterference claim |
| Construction-independent activation recipient party views     | two post-release stages, seven closed roles, exact Client capability retention, opaque pre-activation worker authority, sealed activated worker custody, a strict three-origin Rust/Python corpus, and twelve Lean policy-shape theorems complete; runtime frames, durable delivery, erasure, noninterference, and selected-profile security remain missing |
| Construction-independent uniform abort envelope                | exact four-field public shape, five ceremony-linked Rust/Python cases, and four Lean shape theorems complete; actual evaluator/protocol failure integration, timing equivalence, and selective-failure claims remain missing |
| Complete party views, leakage, and aborts                      | output, accepted-evaluation input/coin, uniform-abort, and evaluator-abort state/role shapes are executable; complete frame/delivery views, durable encoding, abort timing/equivalence, and selected-profile corruption games remain missing |
| Deterministic circuit IR, compiler, schedule, and artifacts    | provisional Phase 2A benchmark bundle and Phase 2B mechanical reconciliation gate pass; independent reproduction, review, production digest, and promotable artifacts remain open |
| Phase 2B core-reconciliation and exit-evidence readiness gates | reconciliation passes at the 27-spec/21-corpus/410-generator-Rust/185-Python/158-Lean baseline; twenty host-only readiness and eleven fixed-subject builder tests pass; a complete prepare/sign/finalize/four-blob-commit/record/approval command integration passes with synthetic test-only authorities; genuine independent-host evidence and reviewer approval remain open |
| Passive garbler/evaluator implementation                       | complete for local viability with fixed Half-Gates circuits, passive OT, deterministic KATs, and separate-process execution; independent review and production promotion remain open |
| Selected-profile private outputs and streaming state machine   | local P0 recipient-encrypted outputs and bounded duplex streaming pass; the signed production profile and its reviewed output mechanism remain missing |
| Signed Phase 6A construction and platform decision             | missing; FV5 and construction-specific proof work remain gate-closed                                                                                                                 |
| Selected reviewed P0-P3 suite                                  | missing                                                                                                                                                                              |
| Versioned stream, selected session/ticket, deployment, and SLO specifications | local Phase 9C stream framing, profiles, and measurements are frozen; selected production session/ticket, deployment, and SLO specifications remain missing |
| Selected session/ticket and adapter state machines             | local one-use Router admission, Rust/WASM Client activation, role processes, and lifecycle adapters pass; durable selected-profile state machines remain missing |
| Formal-verification directory and clean build gate             | local gate green; empty-cache FV1 check pending                                                                                                                                      |

Current verdict: the construction-independent scaffold, Phase 2B mechanical
reconciliation, local P0 construction, and complete local lifecycle pass. Phase
9C remains open until the public SDK uses those Yao contracts exclusively and
all Ed25519-HSS runtime surfaces are deleted. Independent-host reproduction,
reviewer approval, signed profile selection, deployed evidence, and
profile-specific proofs remain required before production promotion. Notify
again before FV5 when Phase 6A closes and before FV6 when the Phase 6B
implementation gate closes.

## Definition of Done

Formal verification is comprehensive enough for production review when:

- every claim in the matrix has mechanized evidence or an explicit external
  premise;
- all mirrors and generated files have executable anti-drift links;
- every production artifact digest is tied to reviewed semantics;
- all Lean builds execute named nonempty targets from a clean checkout;
- the checked tree contains no `sorry`, `admit`, placeholder security theorem,
  stale generated artifact, or unlisted axiom;
- every adversary game and simulator required by the Phase 6A-selected claim is
  distinct and non-reflexive; P0/P1 do not inherit P2/P3 games;
- activation, recovery, and refresh cannot contain a seed-export result;
- selected session or ticket/output state is consuming and at most once;
- same-account and selected independent-domain claims remain explicitly
  different;
- release verification fails on missing tools, skipped tracks, drift, or proof failure;
- independent reviewers approve the formal model, implementation bridge,
  assumption ledger, and release wording.
