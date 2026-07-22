# Ed25519 Yao Verification Spec Corpus

Status: **FV1 plus a passing benchmark-only Phase 2B reconciliation gate;
independent reproduction, review approval, and
runtime/profile realization remain open**

## Source precedence

1. [`docs/router-ab/ed25519-yao/implementation-plan.md`](../../../../docs/router-ab/ed25519-yao/implementation-plan.md) owns the approved
   architecture, corruption model, and phased protocol plan.
2. [`tools/ed25519-yao-generator/docs/fixed-reference-v1.md`](../../../../tools/ed25519-yao-generator/docs/fixed-reference-v1.md)
   owns the extracted fixed reference encodings, domains, identifiers,
   arithmetic relations, KDF definition, and generator-owned golden blocks
   within its explicit scope and exclusions.
3. [`tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`](../../../../tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md)
   owns the frozen partial lifecycle and value-custody boundary. Its blocker
   sections identify the semantics it does not yet own.
4. [`tools/ed25519-yao-generator/docs/ceremony-context-v1.md`](../../../../tools/ed25519-yao-generator/docs/ceremony-context-v1.md)
   owns the canonical public request, branch-authorization, transcript DAG,
   activation-origin witness, and explicit host-only evidence boundary.
5. [`tools/ed25519-yao-generator/docs/input-provenance-v1.md`](../../../../tools/ed25519-yao-generator/docs/input-provenance-v1.md)
   owns the proof-system-neutral provenance statement, paired-role invariants,
   epoch meanings, and profile-indexed registration input-integrity and
   anti-bias requirement slots. Its explicit blockers retain commitment, proof,
   custody, and selected-profile composition work; P0 keeps active anti-bias as
   an exclusion under its honest-derivation assumption.
6. [`tools/ed25519-yao-generator/docs/lifecycle-continuity-v1.md`](../../../../tools/ed25519-yao-generator/docs/lifecycle-continuity-v1.md)
   owns only the strict six-case host continuity schema and its synthetic
   registration-metadata, same-root, opposite-delta, ideal epoch-promotion, and
   zero-reference-work relations.
7. [`tools/ed25519-yao-generator/docs/output-sharing-v1.md`](../../../../tools/ed25519-yao-generator/docs/output-sharing-v1.md)
   owns the typed host-only scalar and seed sharing equations, disjoint family
   shapes, strict six-case corpus, and its explicit selected-protocol exclusions.
8. [`tools/ed25519-yao-generator/docs/semantic-artifact-lifecycle-v1.md`](../../../../tools/ed25519-yao-generator/docs/semantic-artifact-lifecycle-v1.md)
   owns the strict five-branch public descriptor, package-set, receipt-body,
   activation-control, and persistence-projection attachment and its explicit
   host-only exclusions.
9. [`tools/ed25519-yao-generator/docs/output-party-views-v1.md`](../../../../tools/ed25519-yao-generator/docs/output-party-views-v1.md)
   owns the five-stage, seven-role construction-independent host output views,
   common-public equality, static consuming A/B observation, strict five-case
   corpus, and explicit runtime, delivery, and security exclusions.
10. [`tools/ed25519-yao-generator/docs/evaluation-input-party-views-v1.md`](../../../../tools/ed25519-yao-generator/docs/evaluation-input-party-views-v1.md)
   owns the five accepted-evaluation stages, seven-role private-input custody,
   branch-specific ideal-function coins, static consuming A/B observations,
   companion links, strict five-case corpus, and explicit runtime and security
   exclusions.
11. [`tools/ed25519-yao-generator/docs/uniform-abort-envelope-v1.md`](../../../../tools/ed25519-yao-generator/docs/uniform-abort-envelope-v1.md)
   owns the exact four-field public host abort shape, five-branch ceremony
   linkage, forbidden failure leakage, and explicit timing/profile exclusions.
12. [`tools/ed25519-yao-generator/docs/evaluator-abort-state-party-views-v1.md`](../../../../tools/ed25519-yao-generator/docs/evaluator-abort-state-party-views-v1.md)
   owns the four admitted evaluator-abort state self-loops, burned-attempt
   identity, seven common-only role views, and strict four-case corpus.
13. [`tools/ed25519-yao-generator/docs/circuit-ir-v1.md`](../../../../tools/ed25519-yao-generator/docs/circuit-ir-v1.md)
   owns the provisional deterministic Boolean IR, fixed SHA-512 specialization,
   scalar arithmetic, activation/export benchmark cores, encodings, metrics,
   and explicit non-production authority boundary.
14. [`tools/ed25519-yao-generator/docs/benchmark-manifest-v1.md`](../../../../tools/ed25519-yao-generator/docs/benchmark-manifest-v1.md)
   owns the provisional benchmark-only compiler/order/schema/bundle/artifact/
   metric aggregation, frozen candidate identity, exact-regeneration acceptance
   rule, independent Python decoding boundary, and explicit independent-host,
   reviewer-approval, and production exclusions.
15. [`tools/ed25519-yao-generator/docs/artifact-filesystem-policy-v1.md`](../../../../tools/ed25519-yao-generator/docs/artifact-filesystem-policy-v1.md)
   owns the descriptor-only Linux/macOS local-filesystem allowlist, additional-
   authority ACL rejection rules, deny-only macOS acceptance, fail-closed
   inspection behavior, and explicit benchmark-tooling authority boundary.
16. [`tools/ed25519-yao-generator/docs/joint-refresh-delta-v1.md`](../../../../tools/ed25519-yao-generator/docs/joint-refresh-delta-v1.md)
   owns the construction-independent role-local A/B ideal refresh-delta
   contributions, nonzero modular joint result, fixture commitment, and
   selected-mechanism exclusions.
17. [`tools/ed25519-yao-generator/docs/signing-worker-activation-v1.md`](../../../../tools/ed25519-yao-generator/docs/signing-worker-activation-v1.md)
   owns the profile-neutral post-opener validation contract, origin-preserving
   receipt-pending state, secret-scalar custody and erasure requirements, and
   deterministic worker-bound activation receipt encoding. Its explicit
   exclusions retain the selected-profile opener and production persistence.
18. [`tools/ed25519-yao-generator/docs/refresh-promotion-v1.md`](../../../../tools/ed25519-yao-generator/docs/refresh-promotion-v1.md)
   owns the verified-activation-only host promotion state machine, complete
   old/next registered-state and A/B retirement binding, deterministic store-
   authority receipt, and explicit production-atomicity exclusion.
19. [`tools/ed25519-yao-generator/docs/export-delivery-lifecycle-v1.md`](../../../../tools/ed25519-yao-generator/docs/export-delivery-lifecycle-v1.md)
   owns the construction-independent output-commitment, delivery-uncertainty,
   Client-release, authorization-consumption, exact-share provenance, and
   redelivery state machine. Its explicit exclusions retain production opening,
   transport, durable replay, acknowledgement, and selected-profile security.
20. [`tools/ed25519-yao-generator/docs/activation-delivery-lifecycle-v1.md`](../../../../tools/ed25519-yao-generator/docs/activation-delivery-lifecycle-v1.md)
   owns the construction-independent activation authorization ordering,
   exact-output retention, atomic Client/SigningWorker capability split,
   uncertainty, retry, redelivery, and SigningWorker release-authority gate.
   Its strict three-origin corpus, independent verifier, and Lean model cover
   the host authorization/capability claim. Its exclusions retain production
   opening, transport, durable replay, complete runtime views, and profile
   security.
21. [`tools/ed25519-yao-generator/docs/activation-recipient-party-views-v1.md`](../../../../tools/ed25519-yao-generator/docs/activation-recipient-party-views-v1.md)
   owns the two-stage, seven-role host-only activation recipient views after
   atomic release and verified SigningWorker activation. Its strict
   three-origin corpus, independent verifier, and Lean model cover exact Client
   scalar custody, opaque pre-activation worker authority, sealed activated
   worker custody, identity continuity, and infrastructure-role emptiness. Its
   exclusions retain production frames, durable delivery, erasure,
   noninterference, and selected-profile security.
22. [`tools/ed25519-yao-generator/docs/recovery-credential-transition-v1.md`](../../../../tools/ed25519-yao-generator/docs/recovery-credential-transition-v1.md)
   owns the construction-independent recovery suspension, verified-activation-
   only replacement promotion, exact registered-identity preservation, old-
   credential tombstone, and pinned store-authority receipt. Its strict one-case
   corpus, independent verifier, and Lean model retain durable atomicity,
   rollback/replay floors, crash recovery, and selected-profile security as
   explicit exclusions.
23. [`tools/ed25519-yao-generator/docs/export-evaluator-authorization-v1.md`](../../../../tools/ed25519-yao-generator/docs/export-evaluator-authorization-v1.md)
   owns the host-reference requirement that role-pinned Deriver A and B
   independently sign the same request-, authorization-, transcript-,
   provenance-, authenticated-store-, identity-, and one-use-execution binding
   before one export evaluation. Its strict one-case corpus, independent
   verifier, and Lean model cover host authority and lifecycle composition only;
   production key distribution, authorization-record policy validation,
   admission-clock trust, durable replay, transport, constant-time execution,
   and P0-P3 protocol security remain excluded.
24. [`tools/ed25519-yao-generator/docs/registration-evaluator-admission-v1.md`](../../../../tools/ed25519-yao-generator/docs/registration-evaluator-admission-v1.md)
   owns construction-independent registration admission, checked-at expiry,
   terminal selection, one-evaluation, candidate-state, success-retention, and
   evaluator-abort-retention relations. Its strict one-case corpus, independent
   verifier, and Lean model explicitly exclude authenticated absence, durable
   uniqueness, input-opening consistency, selected-profile security, and
   production constant-time evidence.
25. [`tools/ed25519-yao-generator/docs/recovery-evaluator-admission-v1.md`](../../../../tools/ed25519-yao-generator/docs/recovery-evaluator-admission-v1.md)
   owns construction-independent recovery admission, checked-at expiry,
   authenticated old-state binding, distinct replacement authority, old-
   credential suspension, one evaluation, exact output binding, terminal
   retention through abort and promotion, and its two distinct opaque recovery-
   evidence identities. Its strict one-case corpus, independent verifier, and
   Lean model explicitly exclude same-root proof validity, production private-
   input opening, durable replay/atomicity, root custody, transport, constant-
   time execution, and P0-P3 security.
26. [`tools/ed25519-yao-generator/docs/refresh-evaluator-admission-v1.md`](../../../../tools/ed25519-yao-generator/docs/refresh-evaluator-admission-v1.md)
   owns construction-independent refresh admission, checked-at expiry,
   authenticated current-state binding, exact proposed A/B next-state authority,
   one evaluation, output binding, registered-state abort retention, promotion
   gating, and its two distinct opaque transition-evidence identities. Its strict
   one-case corpus, independent verifier, and Lean model explicitly exclude
   continuity-proof validity, production private-input opening, delta entropy,
   independence and anti-bias, selective-abort and retry-grinding resistance,
   forward security, mobile-adversary healing, secure erasure, durable replay/
   atomicity/retirement, transport, constant-time execution, and P0-P3 security.
27. [`tools/ed25519-yao-generator/docs/semantic-frame-party-views-v1.md`](../../../../tools/ed25519-yao-generator/docs/semantic-frame-party-views-v1.md)
   owns exactly eleven construction-independent directed frame classes, eleven
   delivery states, seven ordered cumulative value-learning views, exact
   frame ownership, success/abort/redelivery trace composition, ten closed
   corruption markers, and four profile-neutral interface shapes. Its strict
   eight-case corpus, independent verifier, and Lean mirror explicitly exclude
   runtime frame bytes and payloads, transport/authentication, durable state,
   secret values, simulators, experiments, noninterference,
   indistinguishability, profile satisfaction, and protocol security.
28. [`tools/ed25519-yao-generator/docs/phase2b-core-reconciliation-v1.md`](../../../../tools/ed25519-yao-generator/docs/phase2b-core-reconciliation-v1.md)
   owns the benchmark-only five-case certificate that binds the provisional
   compiler, separate IR/schedule clear evaluators, exact `EYAOBM01` candidate,
   all twenty Phase 1 corpus commitments, closed field/wire/output mappings,
   party-output reconstruction, authorized export Client reconstruction, and
   activation's zero-evaluation continuation. Its ten explicit nonclaims retain
   production authority, profile selection, garbling/OT, randomized output
   protection, security experiments, runtime transport, durable lifecycle and
   replay, production constant-time and erasure, independent reproduction, and
   reviewer approval as exclusions.
29. [`phase2b-exit-evidence-v1.md`](phase2b-exit-evidence-v1.md) owns the
   host-only external reproduction/review record schemas, canonical encodings,
   authority separation, signature domains, private acceptance-capability
   boundary, and exact nonclaims. Its twenty readiness tests include the
   unsigned clean-host prepare and bounded signature-only finalize boundaries
   plus the fixed Git-object `C → E` record and reviewer-approval acceptance
   boundaries. It also freezes the exact covered change-control surface,
   historical-checkpoint rule, and non-authoritative public staging workflow
   through thirteen stdlib-Python staging/workflow tests. These artifacts do not provide genuine
   externally governed evidence, reviewer approval, or Phase 2 exit. Eleven
   additional tests cover
   its fixed-path subject, internally closed tracked symlinks, environment
   sanitization, and independently decoded fresh-observation builders, while
   eight cover the protected policy/challenge capabilities.
30. [`tools/ed25519-yao-generator`](../../../../tools/ed25519-yao-generator/README.md)
   owns the clear reference oracle, role-local KDF, host-only provenance outer
   implementation, narrow host-only registration, registered-key-checked export,
   same-root recovery, and opposite-delta refresh references, typed host-only
   output-sharing reference, the host-only lifecycle ownership and
   persistence-projection scaffold, and committed arithmetic, KDF-,
   ceremony-context, lifecycle-continuity, provenance, and output-sharing
   corpora plus the public semantic-artifact lifecycle and host output-party-
   view attachments.
31. [`crates/ed25519-yao`](../../README.md) owns implemented public identifiers,
   draft manifests, digest roles, and metric validation.
32. This formal tree contains derived mirrors, generated translations, models,
   and explanatory evidence.

The HSS formal tree is historical tooling guidance. Its statements, generated
artifacts, and theorem names have no authority over this protocol.

The reconciliation certificate's exact ordered nonclaim vocabulary is
`production_artifact_authority_absent`, `selected_security_profile_absent`,
`garbling_and_ot_unimplemented`,
`randomized_output_protection_unimplemented`,
`simulator_and_security_experiment_unimplemented`,
`runtime_frame_and_transport_encoding_absent`,
`durable_lifecycle_and_replay_semantics_absent`,
`production_constant_time_and_erasure_unclaimed`,
`independent_operator_reproducibility_unclaimed`, and
`reviewer_approval_absent`. These labels are part of the corpus contract.

## Frozen post-attachment baseline

The post-attachment baseline contains 27 documents, 21 corpora, 418 generator
Rust tests, 186 Python tests, and 158 Lean theorems. The counted reconciliation
gate passes six focused Rust tests, four focused Python tests, and direct
five-case verification. A separate host-only readiness gate passes twenty Rust
tests, the fixed-subject builder passes eleven Rust tests, and the change-
control readiness gate passes thirteen stdlib-Python tests.

- protocol and activation/export circuit identifiers;
- activation/export output-schema identifiers;
- canonical draft-manifest domain and family bytes;
- six typed artifact digest roles plus one family-specific output digest;
- thirteen scalar manifest metrics, including distinct circuit and AND depths;
- the versioned fixed-reference specification and byte-for-byte regeneration of
  its generator-owned golden blocks;
- one benchmark-only `EYAOBM01` candidate derived without caller artifacts that
  binds the compiler contract, bit/wire order, exact schemas, `EYAOBA01` index,
  all IR/schedule identities and metrics, and passive `32*AND` table counts;
- a twenty-seven-document anti-drift gate comprising the fixed reference,
  complete-document byte commitments for twenty-five generator companion
  specifications, and the separately pinned host-only exit-evidence contract:
  output sharing, circuit IR, ceremony context, input
  provenance, semantic-artifact lifecycle, output party views, evaluation-input
  party views, uniform abort, evaluator-abort state/party views,
  authenticated-store resolution, SigningWorker activation, refresh promotion,
  benchmark manifest, artifact-filesystem policy, ideal joint refresh delta,
  export delivery, activation delivery, activation recipient party views,
  recovery credential transition, export evaluator authorization, registration
  evaluator admission, recovery evaluator admission, refresh evaluator
  admission, semantic-frame party views, and the Phase 2B core reconciliation;
- a twenty-one-corpus gate including the strict five-case Phase 2B core-
  reconciliation certificate, strict eight-case semantic-frame party-
  view corpus, the one-case recovery and refresh evaluator-admission corpora,
  and their exact cross-links to the existing
  ceremony, provenance, input/output/lifecycle, delivery, recipient, transition,
  promotion, and abort attachments;
- the post-reconciliation aggregate evidence counts of 186 independent
  Python verifier tests, 418 generator Rust tests, and 158 Lean model theorems;
  the reconciliation slice contributes six Rust and four Python tests, while
  three concurrent Rust tests freeze circuit field order and LSB0 bit layout
  and one additional Python test freezes Phase 5 stream-KAT regeneration;
- exact stable-context encoding, validation, normalization, and binding digest;
- exact visible-ASCII Yao-only application-binding facts (`walletId`,
  `nearEd25519SigningKeyId`, `signingRootId`, and positive immutable
  `keyCreationSignerSlot`), validation, LP32 encoding, and SHA-256 digest;
- exclusion of circular `nearAccountId`, mutable/current signer slots, versions,
  and epochs from that application binding;
- exact role/source/output-separated HKDF-SHA256 contribution derivation;
- the exact public request-context, branch-authorization, and transcript LP32
  encodings, their two digest edges, and the five-case ceremony corpus;
- coherent activation origins restricted to registration, recovery, or refresh,
  with activation/export origin and current-context reuse rejection;
- a disjoint five-lifecycle boundary, activation continuation, output custody,
  common public leakage, ideal sharing distributions, and uniform abort shape;
- the closed construction-independent semantic trace layer: exactly eleven
  directed frame classes, eleven delivery states, seven ordered cumulative
  value-learning views, static frame ownership, terminal evaluator abort,
  exact activation/export redelivery identity, ten corruption markers, and
  four typed interface shapes, with runtime bytes and security claims excluded;
- the attached benchmark-only Phase 2B mechanical reconciliation surface: exact binding
  to the `EYAOBM01` candidate and all twenty Phase 1 corpus commitments, closed
  activation/export field-to-wire and wire-to-output maps, separate IR and
  schedule evaluation, exact party-output reconstruction, authorized export
  Client reconstruction, and activation with zero evaluation; reconciliation
  uses coherent output-party-view projections while output-sharing stays an
  independently committed corpus;
- canonical ceremony-owning request types, a non-`Clone` registered-state
  projection, crate-private registered-state provenance bridges, move-owned
  issuance and semantic sessions, pre-evaluation input return, and
  evaluation-burn audit identity;
- origin-typed output-committed activation artifacts, exact retry-preserving
  activation-control self-loops, metadata-consumed states with zero
  reevaluation, and nonserializable digest-only `OutputCommitted`,
  `AttemptRejected`, and `MetadataConsumed` persistence projections;
- same-logical-root recovery semantics, opposite-delta refresh arithmetic, and
  the monotonic reference cutover boundary;
- public-synthetic registration preparation that derives four role/source-
  separated contribution pairs from three purpose-typed roots and one stable
  context, evaluates the seed-free activation projection, and composes it with
  typed client and SigningWorker scalar output sharing;
- public-synthetic export preparation that requires a caller-supplied validated
  registered key to equal the host export oracle's derived public key before
  typed seed sharing, then move-consumes the prepared output without exposing
  joined seed or oracle material;
- public-synthetic same-root recovery preparation that validates current
  role-separated client KDF contributions, preserves server contributions,
  checks exact joined-seed and activation-output continuity, and composes the
  recovered activation result with typed scalar output sharing;
- public-synthetic refresh preparation that consumes move-owned role-local A/B
  ideal delta contributions, derives their nonzero modular sum, leaves every
  client contribution unchanged, applies
  exact `+delta_y`/`+delta_tau` Deriver A and `-delta_y`/`-delta_tau` Deriver B
  server fields, checks joined-seed and activation-output continuity, and
  composes the refreshed activation result with typed scalar output sharing;
- proof-system-neutral provenance statement slots, encodings, role pairing,
  root/input-state epoch meanings, and profile-indexed registration
  input-integrity/anti-bias requirements and exclusions;
- cross-language linkage from every provenance ceremony digest tuple to the
  matching independently reconstructed canonical ceremony case;
- committed clear-arithmetic, KDF-continuity, five-case ceremony-context,
  six-case lifecycle-continuity, four-case proof-system-neutral provenance
  outer, six-case deterministic output-sharing, five-case public semantic-
  artifact lifecycle, five-case output-party-view, and five-case evaluation-
  input party-view, five-case uniform-abort, and four-case evaluator-abort
  state/party-view corpora plus deterministic differential generation and
  independent Python reproduction;
- host-only typed client/SigningWorker scalar shares and export-only seed
  shares with deterministic zero, small, and wraparound coin coverage;
- host-only construction-independent output views for registration, recovery,
  and refresh package preparation, activation metadata consumption, and export
  release, each with one equal common-public value and seven closed role
  extensions; static consuming A/B observation; and a strict five-case corpus;
- host-only export delivery from output commitment through uncertainty to
  Client release, with authorization consumed only at release, exact evaluation
  shares retained into the Client view, exact-identity redelivery, and a strict
  one-case corpus;
- host-only export evaluator authorization requiring distinct pinned A/B
  Ed25519 authorities and two independently verified role capabilities over one
  request, replay nonce, expiry, recipient key, authorization, transcript,
  provenance pair, signed store resolution, active state version, registered
  key, and one-use execution identity; its exact acceptance-pair digest is
  retained through output commitment and Client release in a strict one-case
  corpus;
- host-only recovery evaluator admission requiring one sealed recovery ceremony,
  ordered A/B provenance pair, strictly verified store resolution, checked-at
  time, distinct replacement credential, nonzero selected-mechanism acceptance
  identity, advancing activation epoch, and one-use execution identity; admission
  suspends the old credential before one evaluation and retains the exact terminal
  authority through abort, output commitment, worker activation, and promotion in
  a strict one-case corpus;
- host-only refresh evaluator admission requiring one sealed refresh ceremony,
  ordered A/B provenance pair, strictly verified current store resolution,
  checked-at time, exact current and proposed role-state bindings, nonzero
  selected-mechanism acceptance identity, advancing activation and role epochs,
  and one-use execution identity; admission preserves current registered state,
  permits one evaluation, and retains the exact terminal authority through abort,
  output commitment, worker activation, and promotion in a strict one-case corpus;
- host-only activation delivery with not-issued, unconsumed, and consumed
  authorization states; exact same-evaluation share retention; atomic Client
  and SigningWorker capability release; exact-identity redelivery; and a strict
  three-origin corpus;
- host-only activation recipient views at release and verified worker
  activation, with exact Client capability retention, opaque pre-activation
  worker authority, sealed activated worker custody, seven closed roles, and a
  strict three-origin corpus;
- host-only construction-independent accepted-evaluation input views: four
  typed activation-family inputs per Deriver for registration/recovery/refresh,
  two `y` inputs per Deriver for export, zero activation inputs, empty
  infrastructure extensions, branch-specific ideal-function coins outside all
  party views, static consuming A/B observations, and a strict five-case corpus;
- one exact public uniform-abort envelope for all five request kinds, with a
  ceremony-linked transcript digest, one redacted code, one terminal state, no
  request-context or blame field, and a strict five-case corpus;
- branch-typed admitted evaluator-abort retention, unregistered/credential-
  suspended/registered self-loops, one burned attempt identity, seven common-
  only role views, and a strict four-case corpus;
- authenticated registered-store resolution with a non-weak epoch-bound
  Ed25519 authority key, exact request/DAG/provenance/state and durable-identity
  binding, active state version plus activation epoch and active credential,
  move-only retention, and a sealed recovery transition binding the distinct
  authorized replacement to the common A/B same-root evidence artifact;
- a profile-neutral SigningWorker activation engine over sealed role-specific
  opened shares, with exact worker/recipient/epoch/context/package/share/public-
  identity checks, origin-preserving activated state, zeroizing secret scalar
  custody, and a strictly verified deterministic worker-bound Ed25519 receipt;
- authenticated host refresh promotion from only a verified refresh activation,
  with strictly advancing state/activation versions, exact identity and proposed
  A/B next-state preservation, complete retirement binding, retry retention, and
  a strict store-authority receipt;
- two pure clear-reference helpers: little-endian addition modulo `2^256` and
  RFC 8032 clamping.

## Unfrozen and excluded

- production registration root generation/custody, provenance/authentication,
  anti-bias and unregistered admission, production export delivery evidence,
  replay, original-seed proof,
  production recovery custody/proof, deployed unbiased refresh-delta generation,
  refresh-contribution custody/proof, distributed cutover, production store parsing,
  rollback floors, authority-key distribution, durable lifecycle records/
  transactions, selected-profile package opening, production state-version
  promotion and refresh transaction atomicity, and authenticated
  provenance records/artifacts and their verifier;
- complete role-private runtime views covering frames, delivery, durable
  selected-profile persistence, private output translation, abort timing and
  equivalence, and corruption-game state; accepted-evaluation input and ideal-
  coin custody is frozen only as host evidence;
- canonical role-private runtime lifecycle/party-view fixtures, runtime frame
  payloads and delivery, durable corruption-game state, and selected-profile
  simulator/experiment instantiation; the complete construction-independent
  host-reference evaluators, semantic trace, cumulative value-learning labels,
  and corruption-interface shapes are frozen, while their production
  realizations remain excluded;
- production package opening and wire encodings, authenticated transport
  bindings, replay persistence, durable receipt storage, and verification of
  opaque authorization and artifact digest preimages;
- production-selected/final circuit IR, compiler, schedules, and promotable
  artifacts; the deterministic provisional Phase 2A IR, schedules, bundle, and
  Phase 2B reconciliation certificate remain frozen benchmark evidence only;
- independent-operator or independent-host reproduction and human reviewer
  approval of the provisional circuit semantics, schemas, bit order, wire order,
  and candidate manifest; the Phase 2 exit remains open;
- garbling, OT, streaming, outputs, tickets, and runtime adapters;
- Phase 6A-selected P0-P3 assumptions, adversary games, and real/ideal or
  honest-execution/passive-security statements.

These exclusions prevent the scaffold from presenting architecture prose as a
mechanized protocol claim. Exact immutable source revisions are recorded after
the Phase 1 freeze checkpoint.

The executable registration preparation is variable-time host reference code
over public synthetic inputs. Its six focused Rust tests establish exact
role/source-separated KDF derivation from three purpose-typed roots and one stable
context, seed-free activation arithmetic, and typed scalar-share
reconstruction. They do not implement the complete
`evaluate_registration_v1` functionality or establish production root
generation or custody, provenance or authentication, the registration
input-selection contract or active anti-bias,
unregistered admission, authorization, packages, receipts, durable persistence,
role-private execution, constant-time behavior, or any P0-P3 protocol-security
claim.

The executable export preparation is variable-time host reference code over
public synthetic contributions and a caller-supplied structurally validated
registered key. Its six focused Rust tests establish pre-sharing key equality,
precise mismatch rejection with borrowed inputs retained for retry, move-only
prepared-state custody, exact seed-share reconstruction, and RFC 8032 public-key
and signature parity. They do not authenticate the expected key or registered
state, consume authorization, enforce replay, establish provenance or
original-seed continuity, establish unbiased distributed randomness, implement
role-private or recipient outputs, create packages or receipts, write durable state,
establish constant-time behavior or any P0-P3 protocol-security property, or
implement the complete `evaluate_export_v1` functionality by itself.

The separate export evaluator-authorization composition closes the Phase 1
host-reference export evaluator around authenticated registered state, exact
ceremony/provenance bindings, two role-pinned signed acceptances, one export
evaluation, output commitment, and Client release with consumed authorization.
Its seven core tests, five strict corpus tests, seven independent Python tests,
and twelve Lean policy theorems establish only that host relation. The
authorization record remains an opaque boundary digest whose policy grant,
actor, step-up claims, scope, and revocation state require boundary validation.
Trusted A/B key distribution, admission-clock integrity, global nonce
reservation, production transport and recipient encryption, durable replay and
receipt storage, constant-time production execution, selected-profile input/
output security, and every P0-P3 protocol-security claim remain excluded.

The registration evaluator-admission composition closes the Phase 1 host
registration evaluator from one sealed ideal admission through output
commitment. Eight core tests, five strict corpus tests, seven independent Python
tests, and twelve Lean theorems cover exact ceremony/intent/provenance binding,
checked-at expiry, two distinct opaque input-selection evidence identities,
stable-scope enforcement, one evaluation, candidate/receipt identity, and
terminal selection retention across success and abort. Its unregistered claim
is public-scope-only. Authenticated absence, durable uniqueness and retry
coordination, raw input-opening consistency, selected-profile security,
production storage, and production constant-time execution remain excluded.

The executable recovery preparation is variable-time host reference code over
public synthetic inputs. It excludes production root custody, recovery proofs,
authorization and persisted-state binding, packages, receipts, durable persistence,
distributed cutover, and the complete `evaluate_recovery_v1` functionality.

The recovery evaluator-admission composition closes the Phase 1 host recovery
evaluator around that arithmetic component. One sealed admission binds the exact
ceremony, ordered provenance, strictly verified old state, checked-at time,
distinct replacement credential, same-root artifact identity, selected-
mechanism acceptance identity, advancing activation epoch, and one-use execution.
Eight core tests, five strict corpus tests, seven independent Python tests, and
twelve Lean theorems are the counted target for one evaluation, output binding,
old-credential suspension, and terminal retention through abort, activation,
and promotion. The same-root artifact and selected-mechanism digest remain
distinct opaque values. Their cryptographic relation, production input opening,
durable suspension/replay/atomicity, root custody, transport, constant-time
execution, and every P0-P3 security property remain excluded.

The executable refresh preparation is likewise variable-time host reference
code over public synthetic inputs. Its six joint-delta and six focused refresh
Rust tests do not by themselves implement the complete `evaluate_refresh_v1`
functionality or establish client-root/KDF
provenance, deployed unbiased delta generation, contribution custody or proof,
authorization, state or epoch transitions, packages, receipts, durable persistence,
distributed cutover, role-private execution, or selected-protocol security.

The refresh evaluator-admission composition closes the Phase 1 host refresh
evaluator around that arithmetic component. One sealed admission binds the exact
ceremony, ordered provenance, strictly verified current state, checked-at time,
current and proposed A/B role-state bindings, continuity-artifact identity,
selected-mechanism acceptance identity, advancing activation and role epochs,
and one-use execution. Eight core tests, five strict corpus tests, seven
independent Python tests, and twelve Lean theorems cover one evaluation, output
binding, registered-state abort retention, worker-activation gating, and terminal
retention through promotion. The continuity artifact and selected-mechanism
digest remain distinct opaque values. Their cryptographic relation, production
input opening, delta entropy or independence, anti-bias, selective-abort and
retry-grinding resistance, forward security, mobile-adversary healing, secure
erasure, durable replay/atomicity/retirement, transport, constant-time execution,
and every P0-P3 security property remain excluded.
