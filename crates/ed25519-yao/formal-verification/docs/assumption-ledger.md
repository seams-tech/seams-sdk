# FV1 Assumption Ledger

This ledger names trusted boundaries used by current evidence. Cryptographic
protocol assumptions enter after Phase 6A freezes the selected P0-P3 profile,
exact claim, composition, and required security games.

| ID             | Boundary                                                                                    | Affected obligations                                                                       | Evidence                                                                            | Invalidation trigger                                                                             |
| -------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| TCB-RUST-001   | Rust compiler and host execution preserve tested semantics                                  | all executable checks                                                                      | locked Cargo dependency graphs and counted local gate                               | compiler/toolchain change                                                                        |
| TCB-VERUS-001  | Verus `0.2026.04.03.21dfcd2` and pinned `vstd` check their stated logic faithfully          | `YAO-ID-001`, `YAO-MAN-001`, `YAO-MAN-002`, `YAO-MET-001`, `YAO-PROV-001`                  | task-runner version rejection and `verus/Cargo.lock`                                | Verus or `vstd` change                                                                           |
| TCB-AENEAS-001 | Pinned Charon/Aeneas translate the selected Rust helper surface faithfully                  | `YAO-REF-001`, `YAO-REF-002`                                                               | exact Git pins, transient LLBC, committed Lean, regeneration comparison             | pin, flags, Rust surface, or generated output change                                             |
| TCB-AENEAS-002 | The pinned external Aeneas Lean library contains admitted slice and string declarations     | current generated Lean build                                                               | Lake warnings name the affected external support modules                            | Aeneas pin or dependency use changes                                                             |
| TCB-AENEAS-003 | Ambient opam resolution builds the pinned Aeneas sources consistently                       | current local extraction evidence                                                          | local green gate; empty-cache reproduction remains open                             | opam repository, OCaml, package, or build-host change                                            |
| TCB-LEAN-001   | Lean `v4.28.0-rc1` checks the named targets faithfully                                      | current Lean theorems                                                                      | `lean-toolchain`, explicit targets, required `.olean` outputs                       | Lean or dependency change                                                                        |
| TCB-SHA256-001 | `sha2` implements SHA-256 for draft manifest identity                                       | `YAO-MAN-003`                                                                              | production golden digest test                                                       | dependency, encoder, or algorithm change                                                         |
| TCB-SHA256-002 | `sha2` implements SHA-256 for the stable-context binding                                    | `YAO-CTX-001`, `YAO-KDF-001`, `YAO-LIFE-002`, `YAO-REG-001`, `YAO-REC-001`, `YAO-REC-002`, `YAO-RFR-002`, `YAO-PROV-001` | frozen golden context binding                                                       | dependency, encoding, or algorithm change                                                        |
| TCB-SHA256-003 | `sha2` implements SHA-256 for the immutable four-fact application binding                   | `YAO-APP-001`, `YAO-KDF-001`, `YAO-LIFE-002`                                               | independent Python grammar/encoding/digest reproduction and mutation tests          | dependency, identifier grammar, encoding, `keyCreationSignerSlot`, fact set, or algorithm change |
| TCB-SHA256-004 | `sha2` implements SHA-256 for provenance wrapper, envelope-set, statement, pair, semantic package, delivery, recovery-transition state, tombstone, export-acceptance authority/statement/pair, registration admission/candidate, recovery admission, refresh admission, and receipt digests | `YAO-PROV-001`, `YAO-SEM-001`, `YAO-VIEW-001`, `YAO-VIEW-002`, `YAO-VIEW-003`, `YAO-DELIVERY-001`, `YAO-DELIVERY-002`, `YAO-RECOVERY-002`, `YAO-EXP-002`, `YAO-REG-002`, `YAO-REC-002`, `YAO-RFR-002` | independent Python LP32/digest reproduction, ceremony/provenance cross-links, and mutation tests | dependency, provenance, semantic, delivery, recovery-transition, export-acceptance, registration-admission, recovery-admission, refresh-admission, or party-view encoding, domain, tag, field order, or algorithm change |
| TCB-SHA256-005 | Rust `sha2` and Python `hashlib` implement SHA-256 for Phase 1 corpus commitments, benchmark/artifact bindings, and LP32-domain-separated Phase 2B reconciliation digests | `YAO-CIR-003`, `YAO-SPEC-026` | exact Rust/Python certificate reconstruction plus passing counted commitment, selector, mapping, digest, and mutation checks | dependency, domain, LP32 encoding, canonical-byte encoding, field order, or algorithm change |
| TCB-SHA256-006 | Rust `sha2` implements SHA-256 for the pinned authority policy, subject, source/archive, reproduced artifacts, signed records, and review report | `YAO-SPEC-027`, `YAO-REVIEW-001` | full-document pin, twenty host-only policy/source/observation/report/Git-shape tests, and eleven isolated fixed-subject/fresh-observation tests | dependency, domain, canonical JSON, source/archive rule, fixed path, or algorithm change |
| TCB-SHA512-001 | `sha2` implements the standard SHA-512 comparison oracle for the fixed circuit component  | `YAO-SHA-001`, `YAO-CIR-002`, `YAO-CIR-003`                                                               | fixed padding/bit-order tests plus committed and deterministic circuit comparisons   | dependency, fixed-block mapping, circuit topology, or algorithm change                            |
| TCB-HKDF-001   | Rust `hkdf`/`sha2` implement the frozen contribution KDF                                    | `YAO-KDF-001`, `YAO-LIFE-002`, `YAO-REG-001`, `YAO-REC-001`, `YAO-REC-002`                                | independent Python `hmac`/`hashlib` reproduction of committed outputs               | dependency, KDF encoding, or algorithm change                                                    |
| TCB-PYTHON-001 | Python 3.11+ integer arithmetic, `hashlib`, and `hmac` implement verifier semantics         | `YAO-APP-001`, `YAO-CTX-001`, `YAO-KDF-001`, `YAO-LIFE-002`, `YAO-LIFE-004`, `YAO-PROV-001`, `YAO-REF-003`, `YAO-OUT-001`, `YAO-RFR-001`, `YAO-RFR-002`, `YAO-SEM-001`, `YAO-VIEW-001`, `YAO-VIEW-002`, `YAO-VIEW-003`, `YAO-VIEW-004`, `YAO-RAND-001`, `YAO-ABORT-001`, `YAO-DELIVERY-001`, `YAO-DELIVERY-002`, `YAO-RECOVERY-002`, `YAO-EXP-002`, `YAO-REG-002`, `YAO-REC-002`, `YAO-CIR-003` | pinned minimum version, mutation suite, counted cross-language gate                 | Python/runtime/hash backend or verifier change                                                   |
| TCB-FS-001     | Kernel descriptor metadata, `fstatfs`, Linux xattr reporting, and macOS extended-ACL APIs faithfully expose the authority and filesystem semantics used by the benchmark artifact policy | `YAO-ART-001`, `YAO-FS-001`, `YAO-CIR-003` | descriptor-only no-follow traversal, local-filesystem allowlist, authority-expanding ACL rejection, metadata snapshots, bounded reads, atomic no-replace publication, 11 bundle tests, and three policy tests | OS/filesystem, allowlist, ACL ABI, ownership model, or publication model change |
| TCB-CURVE-001  | `sha2`, `curve25519-dalek`, and `ed25519-dalek` implement oracle primitives correctly       | `YAO-LIFE-002`, `YAO-REG-001`, `YAO-REG-002`, `YAO-EXP-001`, `YAO-EXP-002`, `YAO-REC-001`, `YAO-REC-002`, `YAO-RFR-001`, `YAO-RFR-002`, `YAO-PROV-001`, `YAO-REF-003`, `YAO-OUT-001`, `YAO-SEM-001`, `YAO-VIEW-001`, `YAO-VIEW-002`, `YAO-VIEW-003`, `YAO-RAND-001`, `YAO-DELIVERY-001`, `YAO-DELIVERY-002` | RFC 8032 tests plus independent Python Edwards25519 arithmetic and point validation | dependency or primitive boundary change                                                          |
| TCB-CURVE-002  | `curve25519-dalek` implements canonical scalar decoding and modulo-`l` comparison arithmetic | `YAO-SCA-001`, `YAO-CIR-002`, `YAO-CIR-003`                                                               | boundary rejection and circuit parity across order, clamp, modular-add, tau, and reconciliation cases | dependency, scalar-order constant, reduction range, or arithmetic change                          |
| TCB-STORE-SIG-001 | `ed25519-dalek` strict verification authenticates public registered-store resolutions plus refresh- and recovery-promotion receipts under the non-weak authority retained by the authenticated old state | `YAO-STORE-001`, `YAO-RECOVERY-001`, `YAO-RECOVERY-002`, `YAO-PROMOTE-001`, `YAO-REC-002`, `YAO-RFR-002` | signature mutation, key/epoch substitution, state splice, credential substitution, request-family replay, coherent authority re-signing, and promotion authority-substitution tests | dependency, authority-key rule, signed encoding, verification API, or key-distribution change |
| TCB-WORKER-SIG-001 | `ed25519-dalek` strict verification authenticates the activation receipt under the non-weak key bound to the exact SigningWorker and recipient-key epoch | `YAO-ACTIVATE-001`, `YAO-VIEW-003`, `YAO-RFR-002` | signature, key-epoch, key-digest, and worker-authority substitution tests plus deterministic receipt-byte tests | dependency, authority-key rule, receipt encoding, verification API, or key-distribution change |
| TCB-WORKER-SCALAR-001 | `curve25519-dalek`, `subtle`, and `zeroize` implement canonical scalar decoding, constant-time point equality, scalar arithmetic, and drop-time erasure for the profile-neutral activation engine | `YAO-ACTIVATE-001`, `YAO-VIEW-003`, `YAO-RFR-002` | canonical-scalar, role-share splice, joined-point, registered-key, and secret-redaction tests plus source review; the analyzer qualification gate validates the tool on isolated O0/O3 fixtures only | dependency, compiler/codegen, comparison/arithmetic path, memory ownership, or erasure implementation change |
| TCB-DERIVER-SIG-001 | `ed25519-dalek` strict verification authenticates export-authorization acceptances under two non-weak, role-distinct A/B authority keys supplied by trusted configuration; the host admission clock reports an accurate nonzero time | `YAO-EXP-002` | seven core tests, five strict corpus tests, seven independent Python tests, signature/expiry/role-key-reuse/splice rejection, and coherent A/B attacker-key re-signing rejection | dependency, authority-key rule or distribution, role/epoch binding, statement encoding, verification API, or admission-clock trust change |
| TCB-PHASE2B-REVIEW-001 | Governance outside the repository and GitHub account protects and distributes the exact authority-policy digest, canonical policy JSON, project challenge, key epochs, and approval-sequence floor, and establishes independent operator/reviewer identity and competence | `YAO-REVIEW-001` | fixed external-input loader, private policy/challenge capabilities, distinct authority keys, and eight focused tests; operational evidence remains absent | external trust-anchor distribution, challenge process, authority ownership/rotation, reviewer assignment, or sequence-floor change |
| TCB-PHASE2B-SIG-001 | `ed25519-dalek` strict verification authenticates the domain-separated independent-host record and reviewer approval under distinct non-weak externally pinned keys | `YAO-REVIEW-001` | twenty host-only prepare/finalize/record/approval, signature, key, policy, source, artifact, report, scope, and replay-floor tests | dependency, authority-key rule, canonical payload, signature domain, or verification API change |
| TCB-PHASE2B-STAGING-001 | The local state checker classifies the inspected immutable Git objects and exact `C → E` shape as implemented; GitHub execution is advisory and supplies no release authority | `YAO-REVIEW-001` | hardened Git-object checker, non-authoritative public workflow, and thirteen local staging/workflow tests | checker semantics, covered paths, evidence paths, Git object interpretation, or staging workflow change |
| TCB-PHASE2B-RELEASE-001 | A relying party obtains the trusted policy digest and accepted `E` identity from an independently authenticated channel and runs the pinned verifier against exact `E`; repository and GitHub state are untrusted inputs | `YAO-REVIEW-001` | strict reproducer/reviewer signatures, fixed four-blob acceptance, private verified capabilities, and explicit revised claim; genuine policy publication and signed release remain absent | trust-anchor channel, verifier distribution, accepted-commit publication, authority compromise, or relying-party verification change |

The current project-owned Lean and Verus files contain no axioms or admitted
proofs. Generated Aeneas code imports the pinned external support library;
`TCB-AENEAS-001` and `TCB-AENEAS-002` keep that dependency explicit.

`YAO-SPEC-001` through `YAO-SPEC-027` add no protocol-security premise. Their
byte-comparison and commitment checks are executable host checks
under `TCB-RUST-001`; independent primitive correctness, specification
completeness, and protocol-security obligations remain separate.

`YAO-CIR-001`, `YAO-SHA-001`, `YAO-SCA-001`, `YAO-CIR-002`, `YAO-CIR-003`,
`YAO-SCH-001`, and `YAO-ART-001` depend on
deterministic host compilation, public synthetic clear evaluation,
`TCB-SHA512-001`, `TCB-CURVE-002`, and `TCB-FS-001`. The evaluator allocates `Vec<bool>`
storage and branches while reconstructing public synthetic bytes. It has no
constant-time or production-secret claim. The production dependency guard,
host-only `wasm32` rejection, distinct provisional component tags, and
purpose-specific digest types are part of this evidence boundary. Any reuse in
a label, garbling, Worker, Router, SDK, or production artifact path invalidates
this assumption and requires a compiled constant-time and protocol review.

`YAO-BENCH-001` adds an exact benchmark-only aggregation of those same compiler
outputs. Its Rust parser regenerates the compiler output and performs byte
equality. The separate stdlib-Python parser independently decodes the complete
format and wrapped index. Treating two isolated local builds as independent-host
reproducibility, or the frozen candidate digest as reviewer approval, a
production manifest, or a security-suite identity invalidates the evidence
boundary.

`YAO-CIR-003` depends on deterministic public synthetic fixture construction,
all twenty canonical Phase 1 corpus builders, the provisional compiler and
clear IR/schedule evaluators, the candidate `EYAOBM01` manifest, the independent
Python verifier, `TCB-SHA256-005`, `TCB-SHA512-001`, `TCB-CURVE-002`, and
`TCB-FS-001`. Its five cases establish only exact cross-corpus equality and the
activation zero-evaluation relation. The certificate explicitly records
`production_artifact_authority_absent`, `selected_security_profile_absent`,
`garbling_and_ot_unimplemented`,
`randomized_output_protection_unimplemented`,
`simulator_and_security_experiment_unimplemented`,
`runtime_frame_and_transport_encoding_absent`,
`durable_lifecycle_and_replay_semantics_absent`,
`production_constant_time_and_erasure_unclaimed`,
`independent_operator_reproducibility_unclaimed`, and
`reviewer_approval_absent`. Treating the attachment as an independently
reproduced or reviewer-approved compiler, a production artifact authority, a
selected-profile implementation, or a protocol-security result invalidates the
evidence boundary. Reconciliation derives outputs from coherent output-party-view
projections while retaining output-sharing as an independently committed
corpus. The counted named reconciliation gate passes. Phase 2 closure
remains a separate reviewed gate.

`YAO-FS-001` excludes remote, stacked, and unrecognized filesystems and every
recognized additional ACL authority from the v1 benchmark artifact boundary.
Treating a rejected filesystem as local through an override, adding an ACL
representation without inspection, or using the wrapper as production storage
authority invalidates this evidence.

Operational, malicious-OT, garbling, active-compiler, output-authentication,
transport, erasure, and non-collusion assumptions are absent from current
theorems. They must be added before those surfaces or claims are introduced.

`YAO-LIFE-001`, `YAO-LIFE-003`, and `YAO-STORE-001` depend on Rust move
ownership, exact host-only state comparison, and `TCB-STORE-SIG-001`.
Recovery, refresh, and export issuance require the move-only authenticated
resolution and retain it through abort and metadata consumption. The
registered-state constructor, provenance bridges, issuance, semantic sessions,
activation construction, and metadata consumption remain crate-private.
`ActivationPersistenceProjectionV1` values are nonserializable digest/epoch
projections and assume no production storage system. Treating the host
resolution as evidence for production parsing, rollback floors, authority-key
distribution, atomic durable records, global replay/redelivery state,
worker-activation evidence, recovery custody or same-root proof verification, or refresh promotion invalidates
the current evidence boundary.

`YAO-ACTIVATE-001` depends on Rust move ownership,
`TCB-WORKER-SIG-001`, and `TCB-WORKER-SCALAR-001`. The selected profile is the
sole authority allowed to construct sealed opened-share inputs. The engine then
checks every public descriptor and share relation independently and releases
activated state only after strict receipt verification. Treating this host
engine as an authenticated ciphertext opener, transport binding, replay store,
durable transaction, refresh promotion, deployed erasure proof, or any P0-P3
protocol-security claim invalidates the evidence boundary.

`YAO-PROMOTE-001` depends on Rust move ownership, the already verified worker
activation, and `TCB-STORE-SIG-001`. It authenticates a complete host transition
and retains the activated secret on retry. Treating the caller-supplied durable
transaction-receipt digest as proof of an atomic database commit, rollback-floor
enforcement, replay admission, or crash recovery invalidates the evidence
boundary until the production adapter owns and tests those effects.

`YAO-SEM-001` depends on deterministic public synthetic fixture construction,
the canonical ceremony/provenance companions, and the independent Python
LP32/hash/Edwards implementation. Opaque evidence slots are accepted as public
nonzero bytes. Treating them as verified cryptographic artifacts, signed
receipts, consumed production authorization, durable state, or worker activation
invalidates the claim.

`YAO-VIEW-001` depends on deterministic host-only fixture construction, the
semantic-artifact attachment, supplied output-sharing coins, Rust move
ownership, the curve/hash boundaries above, and the Lean model as a policy-
shape check. The portable corpus intentionally exposes synthetic role-private
values to the independent verifier. Treating those corpus values as public
runtime leakage, a production serialization, delivery evidence, a
noninterference theorem, a real/ideal proof, memory-erasure evidence, or a
selected-profile security claim invalidates the evidence boundary.

The structural portion of `YAO-ABORT-001` depends on a validated public
ceremony DAG, deterministic host projection, and the independent ceremony-
linked verifier. It establishes an exact public field set only. Treating it as
evidence for timing equivalence, protected-input independence, selective-
failure resistance, authenticated frame failure handling, ticket destruction,
or selected-profile correctness-with-abort invalidates the boundary.

`YAO-VIEW-002` and `YAO-RAND-001` depend on deterministic host-only fixture
construction, canonical ceremony/provenance/semantic/output companions, Rust
move ownership, branch-specific ideal-coin wrappers, and the Lean model as a
policy-shape check. The portable corpus intentionally exposes synthetic private
inputs and coins to the verifier. Treating it as production serialization,
runtime leakage, an entropy source, delivery evidence, a pre-state authority,
a noninterference theorem, or selected-profile security evidence invalidates
the boundary. The reference code is variable-time and has no production-secret
or constant-time claim.

`YAO-LIFE-004` and `YAO-VIEW-004` depend on deterministic host construction of
enum labels and ordered cross-references to the existing ceremony, provenance,
evaluation, output, delivery, activation, and abort corpora. The independent
Python verifier trusts filesystem access to those committed sibling corpora and
checks selectors, request-family applicability, state/frame order, cumulative
label learning, frame ownership, retry/redelivery policy, and forbidden fields.
The Lean mirror is a structural policy-shape model. Treating these labels as
runtime payloads, authenticated identity equality, durable replay state,
private values, a simulator or experiment implementation, noninterference,
indistinguishability, selected-profile satisfaction, or protocol-security
evidence invalidates this boundary.

`YAO-REG-001` depends only on three purpose-typed public synthetic roots, one
public synthetic stable context, deterministic supplied sharing coins, the KDF
and oracle primitives named above, and variable-time host execution. It derives
four role/source-separated contribution pairs and a seed-free activation
projection. Production root generation or custody, provenance or
authentication, the registration input-selection contract or active anti-bias,
unregistered admission, authorization,
packages, receipts, durable persistence, role-private execution, constant-time
behavior, and every P0-P3 protocol-security claim remain outside its assumption
set and claim. The complete `evaluate_registration_v1` functionality remains
unimplemented.

`YAO-EXP-001` depends only on public synthetic current contributions, a
caller-supplied structurally validated expected key, deterministic supplied seed
sharing coins, the oracle primitives named by `TCB-CURVE-001`, and variable-time
host execution. Expected-key and registered-state authentication, authorization
consumption, replay, provenance and original-seed continuity, unbiased
distributed randomness, role-private or recipient output translation, packages,
receipts, durable persistence, constant-time behavior, and every P0-P3 protocol-security
claim remain outside its assumption set and claim. The complete
`evaluate_export_v1` functionality is supplied separately by `YAO-EXP-002`.

`YAO-EXP-002` depends on Rust move ownership, authenticated registered-store
resolution, sealed ceremony/provenance composition, `TCB-SHA256-004`,
`TCB-CURVE-001`, `TCB-DERIVER-SIG-001`, and the independent Python verifier.
It establishes a host-reference export evaluator only: distinct pinned A/B
authorities strictly verify two role-specific acceptances over the same request,
replay/expiry/recipient binding, authorization, transcript, provenance pair,
signed store resolution, registered state/version, identity, and one-use
execution. The acceptance-pair digest is retained through output commitment and
release-time authorization consumption. The authorization record remains an
opaque digest; actor, policy grant, step-up claims, scope, and revocation are
boundary responsibilities. Treating this evidence as production authority
discovery, key rotation, clock-hardening, global nonce reservation,
authenticated transport, recipient encryption, durable replay/receipt storage,
constant-time execution, selected-profile input/output protection, or any P0-P3
security claim invalidates the boundary.

`YAO-REG-002` depends on Rust move ownership, sealed ceremony/provenance
composition, `TCB-SHA256-004`, `TCB-CURVE-001`, and the independent Python
verifier. It establishes one construction-independent ideal host admission,
one evaluation, and one candidate identity with terminal selection retained
through success or abort. The selected-mechanism acceptance digest is opaque
and assumes acceptance of the provenance input-selection artifact. Treating the
public identity scope as authenticated absence, the call-local terminal state
as durable uniqueness, the opaque evidence as an input-opening proof, or the
variable-time fixture evaluator as production constant-time or P0-P3 security
evidence invalidates the boundary.

`YAO-DELIVERY-001` depends on the authenticated host store resolution, sealed
ceremony/provenance composition, exact move-owned output shares, Rust ownership,
`TCB-SHA256-004`, `TCB-CURVE-001`, and the independent Python verifier. The
Client-delivery and consumed-authorization digests remain opaque nonzero host
slots. Treating them as proof of production ciphertext opening, authenticated
transport, durable replay admission, recipient acknowledgement, erasure, or a
P0-P3 security claim invalidates the evidence boundary.

`YAO-DELIVERY-002` depends on the exact move-owned activation output, sealed
ceremony/provenance and semantic companion corpora, Rust ownership,
`TCB-SHA256-004`, `TCB-CURVE-001`, and the independent Python verifier. The
Client and SigningWorker evidence digests remain opaque nonzero host slots.
Treating the host capability split as proof of ciphertext opening,
authenticated transport, durable replay admission, recipient acknowledgement,
noninterference, or a P0-P3 security claim invalidates the evidence boundary.

`YAO-VIEW-003` depends on that same host-only release state, strict
SigningWorker receipt verification, Rust move ownership, the hash/curve/worker
signature boundaries above, and the Lean model as a policy-shape check. Its
portable corpus exposes synthetic verification material to the independent
verifier. Treating it as a runtime frame, durable delivery record, scalar
opening API, erasure proof, noninterference theorem, or selected-profile
security evidence invalidates the boundary.

`YAO-REC-001` depends only on public synthetic fixture inputs, deterministic
supplied sharing coins, and variable-time host execution. Production
client-root custody, recovery proof verification, authorization/state binding,
packages, receipts, durable persistence, and distributed cutover remain outside its
assumption set because they remain outside its claim.

`YAO-REC-002` depends on Rust move ownership, the strictly verified registered-
store resolution, sealed ceremony/provenance composition, `TCB-SHA256-004`,
`TCB-CURVE-001`, `TCB-STORE-SIG-001`, and the independent Python verifier. It
establishes one construction-independent host admission, suspends the old
credential, performs one recovery activation-family evaluation, and retains
the terminal admission through abort, output commitment, worker activation,
and promotion. The same-root artifact and selected-mechanism acceptance digest
are opaque and their cryptographic relation is assumed at this boundary.
Treating this evidence as proof of same-root validity, production private-input
opening, root custody, durable suspension or global replay, atomic storage,
transport, constant-time execution, or any P0-P3 security property invalidates
the boundary.

`YAO-RFR-001` depends only on public synthetic fixture inputs, two move-owned
role-local ideal delta contributions, deterministic supplied sharing coins,
the oracle primitives named by `TCB-CURVE-001`, and variable-time host
execution. Client-root/KDF provenance, deployed unbiased delta generation,
contribution custody or proof, authorization, state or epoch transitions, packages,
receipts, durable persistence, distributed cutover, role-private execution, and
selected-protocol security remain outside its assumption set because they remain
outside its claim. The complete construction-independent `evaluate_refresh_v1`
host composition is owned separately by `YAO-RFR-002`.

`YAO-RFR-002` depends on Rust move ownership, the strictly verified registered-
store resolution, sealed ceremony/provenance composition, `TCB-SHA256-002`,
`TCB-SHA256-004`, `TCB-CURVE-001`, `TCB-STORE-SIG-001`, `TCB-WORKER-SIG-001`,
`TCB-WORKER-SCALAR-001`, and the independent Python verifier. It establishes
one construction-independent host admission over the exact current and proposed
A/B role-state bindings, performs one refresh activation-family evaluation,
preserves the current registered state on abort, and retains the terminal
admission through output commitment, worker activation, and promotion. The
continuity artifact and selected-mechanism acceptance digest are opaque and
their cryptographic relation is assumed at this boundary. Treating this evidence
as proof of production private-input opening, delta entropy or independence,
anti-bias, selective-abort or retry-grinding resistance, forward security,
mobile-adversary healing, secure erasure, durable replay or atomic retirement,
transport, constant-time execution, or any P0-P3 security property invalidates
the boundary.
