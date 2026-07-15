# Ed25519 Yao Formal Verification

Status: **FV1 plus a passing benchmark-only Phase 2B reconciliation gate;
clean-checkout, independent reproduction, reviewer
approval, and Phase 2 exit remain open; no protocol-security claim**

This directory contains isolated verification infrastructure for the parts of
Ed25519 Yao that exist today. The checked surface is deliberately narrow:

- frozen protocol, circuit, output-schema, and manifest identifiers;
- draft-manifest digest roles and metric shape;
- the versioned fixed-reference specification's generator-owned golden blocks
  and its exact commitments to the output-sharing, circuit-IR, canonical
  ceremony-context, input-provenance, semantic-artifact lifecycle, and output-
  party-view companion specifications, checked byte for byte against the
  canonical Rust renderer;
- the visible-ASCII four-field application-binding encoder, including positive
  immutable `keyCreationSignerSlot`, stable-context encoding, role-local
  contribution KDF, five-case arithmetic corpus, and one-case KDF-continuity
  corpus;
- host-only synthetic same-root client-KDF continuity and opposite-delta refresh
  arithmetic evidence;
- a narrow host-only registration reference that derives four role/source-
  separated contribution pairs from three purpose-typed public synthetic roots and
  one stable context, evaluates the seed-free activation projection, and
  composes it with typed client and SigningWorker scalar sharing;
- a host-only export composition that resolves authenticated registered state,
  checks ceremony/provenance bindings and registered-key equality, requires
  independently verified role-pinned A/B authorization acceptances, retains the
  exact acceptance-pair digest and separated seed shares through output
  commitment, and consumes export authorization only at Client release;
- a strict six-case host lifecycle-continuity corpus covering synthetic
  registration-candidate metadata, all three activation origins, recovery, and
  refresh;
- a strict five-case public ceremony-context corpus whose request,
  branch-authorization, and transcript encodings form a validated digest DAG;
- a narrow host-only same-root recovery reference that validates current
  role-separated client KDF contributions, rederives recovered client
  contributions, preserves both Derivers' server contributions, checks exact
  joined-seed and activation-output continuity, and composes the recovered
  activation output with typed scalar sharing;
- a narrow host-only refresh reference that consumes move-owned role-local A/B
  ideal delta contributions, derives their nonzero modular sum, preserves both
  Derivers' client contributions,
  applies exact `+delta` Deriver A and `-delta` Deriver B server fields, checks
  joined-seed and activation-output continuity, and composes the refreshed
  activation output with typed scalar sharing;
- canonical ceremony-owning lifecycle requests, a non-`Clone` registered-state
  projection, crate-private provenance/state bridges and move-owned
  issuance/sessions, evaluation-burn failures, origin-typed output-committed
  artifacts, retry-preserving activation control, metadata-consumed states, and
  three nonserializable persistence projections; the complete host-reference
  registration, recovery, refresh, and export evaluators are frozen, while
  production durable storage and selected-profile opening remain absent; host
  worker activation and refresh-promotion transitions are separately scoped;
- a complete construction-independent host refresh evaluator that binds one
  sealed ceremony/provenance/authenticated-current-state admission, exact
  proposed A/B next-state authority, one evaluation, output commitment,
  registered-state abort retention, verified worker activation, and promotion;
  continuity proofs, production private openings, delta entropy/anti-bias,
  selective-abort/grinding resistance, erasure/healing, durable realization,
  constant-time execution, and P0-P3 security remain absent;
- the proof-system-neutral provenance outer statement implementation, strict
  parser, four-case corpus, and independent verifier; production proof
  artifacts remain absent;
- typed host-only scalar and seed output-sharing arithmetic, with a strict
  six-case corpus and independent verifier; protocol randomness, private
  translation, authentication, and encryption remain absent;
- construction-independent host-only output views for five lifecycle stages
  and seven roles, including consuming static A/B observation, a strict five-
  case corpus, and nine Lean policy-shape theorems; complete runtime party views,
  delivery, noninterference, and protocol privacy remain absent;
- construction-independent accepted-evaluation input custody for five stages
  and seven roles, branch-specific ideal-function coins outside every party
  view, a strict five-case corpus, and 22 Lean policy-shape theorems; runtime
  frames, delivery, pre-state authority, noninterference, and randomness
  security remain absent;
- a construction-independent semantic trace layer with exactly eleven directed
  frame classes, eleven delivery states, seven ordered cumulative value-
  learning views, exact frame ownership, success/abort/redelivery composition,
  ten closed corruption markers, four typed interface shapes, a strict eight-
  case corpus, and 24 Lean structural theorems; runtime frame bytes/payloads,
  durable state, simulators, experiments, noninterference,
  indistinguishability, selected-profile satisfaction, and protocol security
  remain absent;
- a benchmark-only five-case Phase 2B certificate that reconciles the exact
  `EYAOBM01` candidate and separate IR/schedule clear evaluation with all twenty
  Phase 1 corpus commitments, closed field/wire/output mappings, party-output
  reconstruction, authorized export Client reconstruction, and activation's
  zero-evaluation continuation; independent reproduction, reviewer approval,
  production authority, profile selection, and protocol security remain absent;
- one exact public-only uniform abort shape across all five request kinds, a
  strict ceremony-linked five-case corpus, and four Lean shape theorems;
  failure timing, selective-failure resistance, and selected-profile
  correctness-with-abort remain absent;
- 128 deterministic differential cases regenerated and checked by an
  independent standard-library Python implementation;
- the clear generator's `wrapping_add_le_256` and `clamp_rfc8032` boundaries;
- executable production-to-mirror anti-drift checks.

There is no garbled-circuit engine, streaming protocol, active-security suite,
ticket state machine, or privacy theorem in this scaffold. A passing command
does not establish Yao security.

The post-attachment baseline contains 27 reference specifications, 21 committed
corpora, 418 generator Rust tests, 186 independent Python tests, and 158 Lean
theorems. Six attached Rust and four passing Python tests belong to
reconciliation; three concurrent Rust tests freeze circuit field order and LSB0
bit layout. Twelve host-only Rust tests exercise the external-evidence readiness
boundary and eleven more exercise fixed-subject/fresh-observation construction;
both are tracked separately from the generator total. The counted named
reconciliation, readiness, and subject-builder gates pass. These counts
do not close independent-host reproduction, reviewer approval, or the Phase 2
exit.

The certificate freezes this exact ordered nonclaim list:
`production_artifact_authority_absent`, `selected_security_profile_absent`,
`garbling_and_ot_unimplemented`,
`randomized_output_protection_unimplemented`,
`simulator_and_security_experiment_unimplemented`,
`runtime_frame_and_transport_encoding_absent`,
`durable_lifecycle_and_replay_semantics_absent`,
`production_constant_time_and_erasure_unclaimed`,
`independent_operator_reproducibility_unclaimed`, and
`reviewer_approval_absent`.

## Tracks

- [`verus/`](verus/README.md) contains the standalone unpublished Verus mirror.
- [`lean-boundary/`](lean-boundary/README.md) contains the pinned Aeneas/Charon
  extraction of two implemented pure generator helpers.
- [`lean-model/`](lean-model/README.md) contains model-only manifest-shape,
  output-view, accepted-evaluation input/coin custody, lifecycle, and role-
  pinned export-authorization, registration-admission, recovery-admission, and
  refresh-admission and semantic-frame party-view policy theorems. Its exact
  FV1 count is 158 and it has no production anti-
  drift bridge.
- [`tasks/`](tasks/Cargo.toml) owns host-only command orchestration. Production
  crates have no dependency on this task runner or on the clear oracle.
- `tools/ed25519-yao-generator/src/authenticated_store.rs` owns the move-only
  strictly verified registered-store resolution. Its companion specification
  is committed by the fixed-reference golden block; production parsing,
  rollback floors, key distribution, and durable transactions remain open.
- `tools/ed25519-yao-verifier` is a standard-library Python implementation that
  independently reproduces the application binding, stable-context binding,
  contribution KDF, clear arithmetic, Edwards25519 point encodings, and
  canonical ceremony-context DAG, proof-system-neutral provenance outer bytes,
  deterministic output-sharing reference equations, public semantic-artifact
  lifecycle encodings and projections, and host-only output-party-view
  and evaluation-input party-view relations, recovery credential transitions,
  role-pinned export evaluator-authorization composition, and construction-
  independent registration evaluator-admission/candidate, recovery evaluator-
  admission, refresh evaluator-admission, and semantic-frame trace/value-
  learning compositions.
- [`docs/`](docs/) records sources, obligations, assumptions, and the current
  compliance baseline.

The tracks are complementary. Verus checks an executable Rust-shaped mirror
whose proved constants are compared with production, Aeneas checks a narrow
Rust-to-Lean translation boundary, and Lean checks explicit model-only
statements. No track upgrades the others into a cryptographic security proof.

## Commands

Run focused checks from the repository root:

```sh
cargo yao-fv reference-spec-check
cargo yao-fv vectors-check
cargo yao-fv phase2b-reconciliation-check
cargo yao-fv phase2b-exit-evidence-readiness-check
cargo yao-fv phase2b-change-control-readiness-check
cargo yao-fv phase2b-review-subject-check
cargo yao-fv phase2b-protected-inputs-check
cargo yao-fv phase2b-independent-host-prepare
cargo yao-fv phase2b-independent-host-finalize
cargo yao-fv phase2b-independent-host-record-check
cargo yao-fv phase2b-review-approval-check
cargo yao-fv cross-language-check
cargo yao-fv parity
cargo yao-fv anti-drift
cargo yao-fv lean-check
cargo yao-fv aeneas-check
cargo yao-fv verus-check
cargo yao-fv constant-time-qualification
node ../scripts/check_constant_time_codegen.mjs
```

`constant-time-qualification` verifies the pinned analyzer and `uv.lock`, emits
native assembly from a host-only Rust fixture crate, and requires the analyzer
to accept branchless selection and reject secret-dependent division at `O0` and
`O3`. On macOS it removes LLVM's `L...` local labels before analysis because the
analyzer otherwise classifies them as function boundaries. The command requires
at least one scanned instruction, preventing that adaptation from producing an
empty false green. This qualification command covers tooling only. The adjacent
codegen script clean-builds the active benchmark kernel for optimized host code
and exact Deriver A/B Worker WASM, qualifies its matcher with safe/vulnerable
fixtures, and rejects the former secret IKNP branch. The variable-time
generator remains outside constant-time evidence. The Phase 9B deployment
path records the inspection against the exact prebuilt A/B WASM digests and
uploads those modules with bundling disabled. Production native/WASM
inspection remains open until Phase 6B selects its exact kernel and runtime.

`reference-spec-check` requires an exact twenty-seven-document gate: the fixed
reference, twenty-five generator companions, and the separately pinned host-only
Phase 2B exit-evidence contract. It checks
`tools/ed25519-yao-generator/docs/fixed-reference-v1.md` and the output-sharing,
circuit-IR, ceremony-context, input-provenance, semantic-artifact lifecycle,
output-party-view, evaluation-input party-view, uniform-abort,
evaluator-abort state/party-view, authenticated-store resolution,
SigningWorker activation, refresh-promotion, benchmark-manifest, and artifact-
filesystem policy, ideal joint refresh-delta, and export-delivery lifecycle
companion specifications, plus activation-delivery lifecycle, activation
recipient-party-view, recovery credential-transition, export evaluator-
authorization, registration evaluator-admission, recovery evaluator-admission,
refresh evaluator-admission, and semantic-frame party-view companions.
The Phase 2B core-reconciliation companion is the twenty-fifth companion. The
target runs the generator's dedicated golden checker over the fixed-reference
document, whose generated region commits all twenty-five generator companion
documents, then checks the exact SHA-256 of `phase2b-exit-evidence-v1.md` from
the formal toolchain baseline. This is
executable specification/code anti-drift. It does not independently validate
the cryptographic algorithms or extend the frozen scope of the specification.

`vectors-check` regenerates and compares the committed five-case arithmetic,
one-case KDF-continuity, five-case ceremony-context, six-case
lifecycle-continuity, four-case provenance outer-contract, and six-case
output-sharing, five-case semantic-lifecycle, five-case output-party-view, and
five-case evaluation-input party-view, five-case uniform-abort, four-case
evaluator-abort state/party-view, one-case export-delivery, three-case
activation-delivery, three-case activation-recipient party-view, one-case
recovery credential-transition, one-case export evaluator-authorization, and
one-case registration, recovery, and refresh evaluator-admission corpora, plus
the eight-case semantic-frame party-view and five-case Phase 2B reconciliation
corpora, through their Rust owners.

`phase2b-reconciliation-check` is the mechanical attachment gate. It checks the
strict committed certificate, six focused Rust reconciliation tests, four
focused independent Python tests against a fresh provisional artifact bundle,
the complete candidate-manifest decoder, and exact evidence counts. A passing
gate does not supply independent-operator reproduction or reviewer approval and
does not close Phase 2. Reconciliation derives its output relations from
coherent output-party-view projections; output-sharing remains independently
committed. Final Rust-gate validation remains open.

`phase2b-exit-evidence-readiness-check` pins the host-only exit-evidence
contract and runs twenty fail-closed parser, authority, signature, subject,
source, observation, policy, challenge, report, scope, and nonclaim tests. The
acceptance API consumes private subject/observation/policy/challenge/report
capabilities, so raw caller digests cannot authorize an exit. The fixed-path
subject builder now binds the clean Git archive, toolchain, eleven specifications,
complete manifest metrics, certificate, twenty corpora, and fresh decoded bundle
observations through eleven focused tests. The outer checker rebuilds an internal
material command compiled inside a private clone of the single captured commit;
the clean committed-checkout integration run produces one canonical 15757-byte
subject and six observations. The protected-input command is implemented with
eight focused tests. The zero-argument prepare command now runs reconciliation
and subject construction inside one private captured-commit checkout and emits
one canonical unsigned envelope. The bounded zero-argument finalize command
strictly verifies an external raw-digest signature, rebuilds the exact subject,
and emits one canonical signed record. The fixed record checker consumes only
the exact bounded four-blob `C → E` Git-object shape and returns a private
verified-reproduction capability. The zero-argument approval checker consumes
that capability and validates the fixed report and approval blobs before
issuing the stronger private approval capability. A disposable complete
prepare/sign/finalize/four-blob-commit/record/approval integration passes with
synthetic test-only authorities and a clean unchanged evidence checkout.
Genuine externally governed evidence and reviewer approval remain open.

`anti-drift` is intentionally independent of Verus discovery. It remains
usable with an ordinary Rust toolchain.

`cross-language-check` runs the Python mutation suite, verifies the committed
five-case arithmetic, one-case KDF-continuity, six-case host
lifecycle-continuity, five-case ceremony-context, four-case provenance
outer-contract, six-case output-sharing, five-case semantic-lifecycle, five-
case output-party-view, five-case evaluation-input party-view, and one-case
export-delivery, three-case activation-delivery, three-case activation-
recipient party-view, one-case recovery credential-transition, and one-case
export evaluator-authorization, registration evaluator-admission, recovery
evaluator-admission, refresh evaluator-admission, and semantic-frame party-view
corpora, then verifies the Phase 2B core-reconciliation certificate against all
twenty source corpora and a fresh provisional artifact bundle. The
evaluation-input CLI additionally requires the output-party-view companion;
both party-view corpora require semantic-lifecycle, ceremony-context, and
provenance companions. Recovery-transition verification additionally requires
the activation-delivery and activation-recipient companions. The check also emits the
provisional seven-file Phase 2A bundle, runs 24 independently counted strict
artifact tests, rederives
each schedule from decoded IR, and evaluates both encodings over the five
committed cases. This remains benchmark-only FV2 evidence; independent-host
reproduction, human review of circuit semantics and bit ordering, and the
overall Phase 2 exit remain open.

The vector track then
generates 128 deterministic public-test cases, independently regenerates every
input from the fixed seed, and verifies every output. The provenance checks
cover LP32 nesting, stable-context recomputation, registered-point validity,
refresh epochs, fixed A/B ordering, and statement/pair digests; opaque artifact
slots remain public synthetic values. The application-binding checks cover `walletId`,
`nearEd25519SigningKeyId`, `signingRootId`, and positive immutable
`keyCreationSignerSlot`. `nearAccountId`, mutable/current signer slots,
versions, and epochs are absent from that binding.
The six ceremony-context tests independently rebuild all three canonical
layers, enforce exact version and field grammar, check activation-origin
eligibility and distinctness, and reject digest or provenance branch splicing.
The provenance check cross-links all four evaluation branches to those rebuilt
request, authorization, and transcript digests before reporting success.
The output-sharing checks independently recompute the joined activation/export
values from copied source inputs, enforce request-family shapes, and verify
scalar and seed reconstruction across zero, small, and wraparound coins.
The ten semantic-lifecycle tests independently parse descriptor, package-set,
receipt, and activation-control LP32 encodings; cross-link ceremony and
provenance identities; verify A/B point addition, per-share subgroup membership,
and `2*X_client-X_server=A_pub`; and reject persistence, abort, and secret-field
mutations.
The output-party-view checks compose those public artifacts with five closed
stage variants and seven role-specific extensions. They validate A/B scalar-
share points and reconstruction, all three activation origins with zero new
outputs, export seed reconstruction and registered-key continuity, common-
public equality, static one-Deriver observation, and recursive forbidden-value
exclusion. The synthetic role-private corpus values are verifier evidence. They
are not public runtime leakage or a production serialization format.
The evaluation-input party-view checks derive the exact registration/recovery/
refresh and y-only export inputs, enforce activation's zero-work shape, keep
ideal-function coins outside every role view, reproduce the companion output
shares, and reject peer-role, family, scalar-domain, lifecycle-relation, and
static-copy mutations. Its synthetic inputs and coins are verifier evidence.
The five export-delivery tests independently parse both export receipts, enforce
authorization ordering, preserve exact package and state identity through
uncertainty, validate Client release and registered-key derivation, and require
zero-work redelivery.
The five activation-delivery tests independently cross-link all three origins,
enforce monotonic authorization and exact identity through uncertainty,
validate the disjoint Client/SigningWorker capability split and released Client
scalar, require zero-work redelivery, and reject forbidden secret-bearing
fields.
The seven activation-recipient party-view tests independently enforce the exact
two-stage and seven-role shapes, pre-release emptiness, release/activation
identity continuity, narrow Client and SigningWorker custody, strict worker
receipt verification, and exclusion of frames, durable state, retained Deriver
shares, scalar openers, and profile claims.
The seven recovery credential-transition tests independently recompute the
complete old/next registered-state digests, old-version tombstone, exact
20-field promotion receipt, receipt digest, and strict signature under a
verifier-pinned store authority. They reject coherent attacker-key re-signing
and cross-corpus identity drift.
The seven export evaluator-authorization tests independently parse and verify
the exact A/B role statements and ordered pair, enforce distinct pinned
authorities, cross-link ceremony/provenance/store/evaluation/output identities,
require one evaluation and release-time authorization consumption, and reject
expiry, execution-ID splice, role-key reuse, signature drift, and coherent
attacker-key re-signing.
The seven registration evaluator-admission tests independently reconstruct the
exact admission and candidate encodings/digests, checked-at expiry, both opaque
selection-evidence identities, one-evaluation receipt/public-key relation,
terminal retry rule, and explicit nonclaims. They reject scope, intent,
provenance, epoch, execution, receipt, candidate, retry, and schema/order drift.
The seven recovery evaluator-admission tests independently verify the pinned
store-authority signature and reconstruct the exact store, admission, output,
retry, and nonclaim boundaries. They reject ceremony/scope/freshness,
store/state/authority, continuity/provenance/evidence, epoch/execution/output,
receipt, retry, forbidden-field, and schema/order drift.
The seven refresh evaluator-admission tests independently verify the pinned
store-authority signature and reconstruct the exact 37-field admission,
flattened proposed A/B next-state bindings, output receipt, registered-state
abort retention, retry, forbidden-field, and nonclaim boundaries. They reject
ceremony/scope/freshness, store/state/authority, current/next role-state,
continuity/provenance/evidence, epoch/execution/output, receipt, retry, and
schema/order drift.
The eight semantic-frame party-view tests independently reconstruct all eight
success/abort traces, exact state and frame order, seven cumulative role views,
frame ownership, identity-label crosslinks, retry/redelivery policy, ten
corruption markers, four interface shapes, and explicit nonclaims.
The task runner separately counts the seven output-sharing, six ceremony-
context, ten semantic-lifecycle, nine output-party-view, nine evaluation-input
party-view, five uniform-abort, five evaluator-abort-view, five export-delivery,
five activation-delivery, seven activation-recipient party-view, seven recovery
credential-transition, seven export evaluator-authorization, seven registration
evaluator-admission, seven recovery evaluator-admission, seven refresh evaluator-
admission, eight semantic-frame party-view, four Phase 2B reconciliation, and 24
artifact Python tests inside the 186-test aggregate verifier suite. One
additional Phase 5 stream-KAT regeneration test accounts for the remaining
test. `parity`
likewise requires the named 25-test Phase 2A/Phase 4 circuit target, 11-test artifact-bundle
target, six-test benchmark-manifest target, six-test joint-refresh-delta target,
five-test output-sharing core, eight-test output-sharing vector, seven-test
semantic-lifecycle vector, three-test output-party-view core, two-test output-
party-view compile/static boundary, six-test output-party-view corpus, five-test
evaluation-input core, two-test evaluation-input compile/static boundary,
seven-test evaluation-input corpus, six-test registration-, export-, recovery-,
and refresh-reference targets, four uniform-abort, four evaluator-abort-view,
four export-delivery core, four export-delivery corpus, two activation-delivery
core, four activation-delivery corpus, four activation-recipient party-view
core, two activation-recipient compile/static boundary, and six activation-
recipient party-view corpus tests, seven
authenticated-store tests, ten SigningWorker-activation
tests, six refresh-promotion tests, seven recovery credential-transition core
tests, five recovery credential-transition corpus tests, seven export evaluator-
authorization core tests, five export evaluator-authorization corpus tests,
eight registration evaluator-admission core tests, and five registration
evaluator-admission corpus tests, eight recovery evaluator-admission core tests,
five recovery evaluator-admission corpus tests, eight refresh evaluator-admission
core tests, five refresh evaluator-admission corpus tests, ten semantic-frame
core tests, three semantic-trace boundary tests, six semantic-frame corpus
tests, and six Phase 2B reconciliation tests.
The separate artifact-filesystem-policy crate contributes three tests. The
pinned generator total is 418 Rust tests,
including compile-fail doctests and the transitive production-dependency guard.

The host lifecycle evidence now includes more than the continuity corpus.
`lifecycle_domain` owns canonical ceremony-bearing requests and crate-private
bridges from recovery, refresh, and export provenance into store-comparable
state. Registered issuance accepts only the move-only authenticated resolution
from `authenticated_store`; raw projections cannot enter a semantic session.
Its issuance and semantic sessions are move-owned and crate-private.
Pre-evaluation binding failures return the request and issuance. A failed
admitted evaluation returns only a non-callable burned-attempt identity;
refresh/export retain registered state and recovery retains credential
suspension. Success seals the origin request inside origin-typed output-
committed artifacts.

Activation control retains that exact output-committed value on rejection and
moves accepted metadata into an origin-preserving metadata-consumed state with
zero reevaluation. `lifecycle_persistence` projects this into nonserializable
digest-only `OutputCommitted`, exact rejected-attempt self-loop, and
`MetadataConsumed` views. These are construction-independent persistence states,
not durable records. The five-case semantic-lifecycle attachment commits their
public descriptor, receipt, and projection relations without promoting them to
wire or storage formats. Export output commitment and release retain one exact
evaluation's package/share identity, consume authorization at Client release,
and model uncertainty/redelivery with zero private reevaluation. Authenticated
store reads, durable transactions, replay storage, recipient-package verification, SigningWorker
activation, identity/state-version promotion, recovery custody, refresh next-
state promotion, the remaining complete lifecycle evaluators, and selected-
profile security remain absent.

`output_party_views` composes the construction-independent output-custody
boundary after package preparation, activation metadata consumption, or export
release. Its validated aggregate is nonserializable and exposes separate
consuming A and B observation methods, with no runtime role selector. Client,
SigningWorker, Router, Observer, and diagnostics extensions are structurally
distinct. This establishes host-reference output shape and relation evidence
only. Export Client release has a separate construction-independent lifecycle;
The separate activation-recipient views cover atomic release and receipt-
verified SigningWorker activation while retaining the Client capability and
sealing the worker scalar. Complete runtime frames, durable delivery, and
selected-profile security remain open. The model does not cover complete
party inputs, protocol randomness, frames, recipient encryption or opening,
abort timing, memory erasure, adaptive
corruption, noninterference, real/ideal security, or any P0-P3 claim.

The registration-reference target uses public synthetic fixture bytes and
permits variable-time host arithmetic. Its six focused Rust tests cover exact
role/source-separated KDF derivation from three purpose-typed roots and one stable
context, root/context domain separation, deterministic borrowed inputs,
independent seed-free activation arithmetic, typed scalar-share reconstruction,
and source/type exclusions. It does not implement
`evaluate_registration_v1`; establish production root generation or custody,
provenance or authentication, the registration input-selection contract or
active anti-bias, unregistered admission, authorization, packages, receipts,
durable persistence, role-private execution,
constant-time behavior, or any P0-P3 protocol-security claim.

The export-reference target uses public synthetic fixture bytes and permits
variable-time host arithmetic. Its six focused Rust tests cover validated
registered-key equality before sharing, mismatch rejection with borrowed inputs
retained for retry, consuming prepared-state custody, zero/small/wraparound seed
share reconstruction, RFC 8032 public-key and signature parity, and source/type
exclusions. It does not authenticate the expected key or registered state,
consume export authorization, enforce replay, establish input provenance or
original-seed continuity, sample unbiased distributed randomness, create
role-private or recipient outputs, create packages or receipts, write durable state,
provide constant-time or selected-profile evidence, or implement the complete
`evaluate_export_v1` functionality by itself. It supplies no P0-P3 protocol-security
claim.

The separate export evaluator-authorization target completes the host-reference
composition with authenticated registered state, exact ceremony/provenance
authority, distinct pinned A/B Ed25519 authorities, two strictly verified role
acceptances, one export evaluation, output commitment, and Client release with
consumed authorization. Its authorization record remains an opaque boundary
digest. The host evidence does not validate its policy grant, actor, step-up
claims, scope, or revocation state, and it does not establish production key
distribution or rotation, admission-clock integrity, global replay, recipient
encryption, transport, durable receipt storage, constant-time execution, or any
P0-P3 protocol-security property.

The six named tests are
`matching_registered_key_prepares_public_key_equality_witness`,
`different_valid_registered_key_is_rejected_and_borrowed_inputs_retry`,
`split_y_carry_and_wrap_reconstruct_exact_export_seed`,
`seed_shares_match_independent_zero_one_and_max_arithmetic`,
`reconstructed_rfc8032_seed_signs_and_verifies_with_registered_key`, and
`source_and_ui_guards_keep_export_synthetic_seed_scoped_and_nonproduction`.

The recovery-reference target uses public synthetic fixture bytes and permits
variable-time host arithmetic. The separate recovery-admission lifecycle
composes it into the complete construction-independent host evaluator. Neither
target establishes production client-root custody, recovery-proof validity,
durable persistence, distributed cutover, or a selected-protocol security
claim.

The refresh-reference target also uses public synthetic fixture bytes and
permits variable-time host arithmetic. Six joint-delta tests and six focused
refresh tests cover role-local contributions, nonzero modular summation,
unchanged client fields, exact
Deriver A `+delta` and Deriver B `-delta` server fields, joined and activation
continuity, and typed activation scalar-share reconstruction. It does not
implement `evaluate_refresh_v1`; establish client-root or KDF provenance; or
establish deployed unbiased delta generation, contribution custody or proof,
authorization, state or epoch transitions, packages, receipts, durable persistence,
distributed cutover, role-private execution, or selected-protocol security.

The full local gate is:

```sh
cargo yao-fv all
make -C crates/ed25519-yao/formal-verification check
just ed25519-yao-fv
```

The full command runs thirteen nonempty tracks, including Phase 2B
reconciliation, external-evidence readiness, change-control staging readiness,
clean-checkout review-subject construction, isolated clean-build benchmark-
manifest reproduction, and Rust parity.

The full gate requires the exact source and verifier pins recorded in
[`toolchain.toml`](toolchain.toml). Missing or mismatched tools are failures.
Bootstrap Aeneas and Charon with:

```sh
crates/ed25519-yao/formal-verification/lean-boundary/scripts/setup-aeneas.sh
```

The bootstrap currently resolves its OCaml packages through the ambient opam
repository. Locking that package environment and reproducing the entire gate
from empty caches remain the final FV1 reproducibility tasks.

The repository-wide `check:formal-verification` command still owns the HSS
gate. Yao joins that CI aggregate after the clean-checkout Aeneas installation
path is added; HSS remains until hard cutover.
CI separately runs the construction-independent `reference-spec-check`,
`vectors-check`, `cross-language-check`, `phase2b-reconciliation-check`,
`phase2b-exit-evidence-readiness-check`,
`phase2b-change-control-readiness-check`,
`phase2b-review-subject-check`,
`benchmark-manifest-reproducibility`, and `parity` Yao tracks now. The separate
`ed25519-yao-constant-time-codegen` job installs the WASM target and LLVM tools,
then inspects the optimized benchmark kernel and exact cross-account Deriver
A/B Worker-WASM artifacts. Remote job success remains required evidence before
the clean Linux qualification item closes.

`phase2b-protected-inputs-check` is available outside `all`; it requires the
three externally administered values and an out-of-repository policy pin.

The dedicated `phase2b-change-control.yml` workflow checks only public evidence
staging shape. Before genuine evidence it accepts the zero-file development
state. The first four-file checkpoint and every later covered change require an
exact PR-head `C → E` shape. Unrelated descendants retain the historical
checkpoint for unchanged covered bytes. GitHub runs no release verification and
holds no policy, challenge, key, or release-authority state. The independent
verifier must run the protected-input, record, and approval checks against exact
`E` with the externally pinned policy before Phase 2 can close.

## Evidence and scope

- [Spec corpus](docs/spec-corpus.md)
- [Proof obligations](docs/proof-obligations.md)
- [Assumption ledger](docs/assumption-ledger.md)
- [Compliance baseline](docs/compliance-baseline.md)
- [Full phased plan](../docs/formal-verification-plan.md)
- [Protocol implementation plan](../../../docs/yaos-ab.md)

Generated Lean files are committed. Charon LLBC remains a transient intermediate
because its internal identifier ordering is nondeterministic even when the
resulting Lean is stable. `aeneas-check` regenerates the Lean files, compares
them byte for byte, builds both named targets, and requires their `.olean`
outputs. Focused source guards reject `sorry`, `admit`, and `axiom` in
project-owned Lean plus unchecked Verus declaration attributes in the mirror.
