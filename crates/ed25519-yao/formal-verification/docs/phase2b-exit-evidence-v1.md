# Ed25519 Yao Phase 2B Exit Evidence V1

Status: **normative host-only verification contract; no trusted authority
policy, independent reproduction record, reviewer approval, or Phase 2 exit is
present**

This contract defines the only version-one evidence that may close the two
external Phase 2B gates:

1. exact reproduction by a trusted operator on an independently administered
   clean host; and
2. separate human approval of circuit semantics and bit ordering by a trusted
   cryptographic reviewer.

The records live under `crates/ed25519-yao/formal-verification`. They are never
generator, circuit, manifest, Router, Worker, SDK, or production artifacts.
Neither record changes `EYAOBM01`, the Phase 2B reconciliation certificate, or
their benchmark-only claims.

## 1. Authority boundary

The formal tooling verifies signatures. It contains no signing key, signing
command, synthetic accepted authority, fallback key, self-approval path, or
approval-emission API.

The authority policy is supplied at the independent verification boundary. Its
complete canonical-byte SHA-256 digest is pinned outside the repository and
passed through `ED25519_YAO_PHASE2B_REVIEW_POLICY_SHA256`. A command-line value,
repository file, GitHub variable, workflow, branch rule, or repository
administrator cannot replace that external trust anchor.

The canonical policy bytes are supplied through the separate multiline
environment value `ED25519_YAO_PHASE2B_REVIEW_POLICY_JSON`. It must
contain the exact UTF-8 canonical JSON including its final LF. The loader hashes
those bytes before parsing and requires equality with the independently
administered digest variable. No policy path, fallback bytes, or command-line
policy is accepted.

The project-issued challenge is supplied only through the external environment
value `ED25519_YAO_PHASE2B_REPRODUCTION_CHALLENGE_HEX`. Acceptance code converts
it into a private challenge capability; record verification accepts no raw
challenge string.

The independent reproducer and reviewer MUST have distinct:

- role tags;
- authority identifiers;
- Ed25519 verifying keys; and
- domain-separated authority-key digests.

The cryptographic reviewer is the external signed Phase 2 release authority.
Its approval is valid only together with the separately signed independent-host
reproduction record, the exact four-blob `C → E` evidence shape, and an
out-of-repository policy digest pinned by the relying party. Key ownership,
operator independence, reviewer competence, challenge issuance, policy
publication, key rotation, approval-sequence floors, and relying-party trust-
anchor distribution are external governance assumptions. Machine verification
cannot infer them.

GitHub Free is a non-authoritative source and CI transport. Its checks may catch
malformed staging transitions, but GitHub approval state, branch settings,
workflow results, repository history, release tags, and administrator actions
cannot create or revoke the signed Phase 2 claim.

## 2. Canonical JSON and primitive encodings

Every JSON file MUST use:

- UTF-8;
- two-space indentation;
- the exact field order in this contract;
- lowercase fixed-width hexadecimal;
- no `null`, optional, unknown, duplicate, or reordered fields; and
- exactly one trailing LF.

Parsing MUST deserialize into `deny_unknown_fields` structures, serialize the
value canonically, and require byte equality with the input. This rejects
duplicate fields, alternative whitespace, CRLF, reordered fields, and trailing
data.

Primitive encodings are:

- `BE64(x)`: eight-byte unsigned big-endian integer;
- `LP32(x)`: four-byte unsigned big-endian length followed by `x`;
- SHA-256: 32 bytes, rendered as 64 lowercase hex characters;
- Ed25519 verifying key: 32 bytes, rendered as 64 lowercase hex characters;
- Ed25519 signature: 64 bytes, rendered as 128 lowercase hex characters; and
- Git commit/tree identity: 20 bytes, rendered as 40 lowercase hex characters.

Identifiers and environment labels MUST be nonempty visible ASCII without
leading/trailing whitespace. Timestamps, key epochs, policy versions, and
approval sequences MUST be nonzero.

## 3. Deterministic review subject

The formal task tooling builds one unsigned subject from fixed internal paths.
The builder accepts no paths, manifests, corpora, digests, schemas, component
lists, nonclaims, or field overrides.

The exact top-level order is:

```text
schema
protocol_id
evidence_scope
source
toolchain_commitments
authoritative_specifications
benchmark_manifest_binding
reconciliation_certificate_binding
phase1_corpus_commitments
explicit_nonclaims
subject_digest_hex
```

Fixed identifiers are:

```text
schema = seams:router-ab:ed25519-yao:phase2b-review-subject:v1
protocol_id = router_ab_ed25519_yao_v1
evidence_scope = benchmark_only_phase2b_deterministic_core_review_subject_v1
```

`source` contains, in order:

```text
repository_commit_hex
repository_tree_hex
source_archive_sha256_hex
checkout_state
```

`checkout_state` MUST equal `clean_exact_commit`. The source archive is the
exact byte output of `git archive --format=tar <commit>`.

`toolchain_commitments` contains, in order:

```text
generator_cargo_lock_sha256_hex
task_runner_cargo_lock_sha256_hex
formal_toolchain_sha256_hex
rustc_version_verbose_sha256_hex
cargo_version_sha256_hex
python_version_sha256_hex
git_version_sha256_hex
```

The final four fields hash the exact stdout bytes, including the final LF and
excluding stderr, from `rustc --version --verbose`, `cargo --version`,
`python3 --version`, and `git --version`, respectively. Empty output, CR bytes,
a missing final LF, or nonempty stderr fail closed. The Git version is bound
because Git produces the canonical source archive bytes.

`authoritative_specifications` contains exactly these eleven fixed paths, in
this order. Each entry has `path`, `canonical_bytes`, and `sha256_hex`:

1. `tools/ed25519-yao-generator/docs/fixed-reference-v1.md`;
2. `tools/ed25519-yao-generator/docs/circuit-ir-v1.md`;
3. `tools/ed25519-yao-generator/docs/benchmark-manifest-v1.md`;
4. `tools/ed25519-yao-generator/docs/evaluation-input-party-views-v1.md`;
5. `tools/ed25519-yao-generator/docs/output-party-views-v1.md`;
6. `tools/ed25519-yao-generator/docs/semantic-frame-party-views-v1.md`;
7. `tools/ed25519-yao-generator/docs/registration-evaluator-admission-v1.md`;
8. `tools/ed25519-yao-generator/docs/recovery-evaluator-admission-v1.md`;
9. `tools/ed25519-yao-generator/docs/refresh-evaluator-admission-v1.md`;
10. `tools/ed25519-yao-generator/docs/export-evaluator-authorization-v1.md`;
11. `tools/ed25519-yao-generator/docs/phase2b-core-reconciliation-v1.md`.

`benchmark_manifest_binding` copies the exact accepted `EYAOBM01` manifest
magic, canonical byte length, manifest digest, compiler contract, bit order,
wire order, `EYAOBA01` length/digest, and the three ordered component bindings.
Each component binds its kind, tag, IR file/digest, schedule file/digest, input
schema, output schema, complete metrics, and passive table bytes.

The exact manifest-binding order is:

```text
manifest_magic
manifest_canonical_bytes
manifest_digest_hex
compiler_contract
bit_order
wire_order
bundle_index_file
bundle_index_canonical_bytes
bundle_index_digest_hex
components
```

`manifest_digest_hex` is the domain-separated manifest digest
`c9c969fd23998509ae07f04fdc9982e2f3b5b21aa92aac9cf62db5ed2f0cce81`,
not raw SHA-256 over the 1973 manifest bytes. Each component contains, in order:

```text
component_kind
component_tag
ir_file
schedule_file
input_schema
output_schema
ir_digest_hex
schedule_digest_hex
circuit_metrics
schedule_metrics
passive_half_gates_table_bytes
```

`circuit_metrics` contains `input_wire_count`, `output_wire_count`,
`wire_count`, `and_gate_count`, `xor_gate_count`, `inversion_gate_count`,
`total_gate_count`, `circuit_depth`, `and_depth`, and `canonical_ir_bytes`, in
that order. `schedule_metrics` contains `input_wire_count`,
`output_wire_count`, `scheduled_gate_count`, `reusable_slot_count`,
`slot_width_bytes`, `gate_record_width_bytes`, and
`canonical_schedule_bytes`, in that order.

`reconciliation_certificate_binding` contains, in order:

```text
path
canonical_bytes
sha256_hex
case_count
```

It names the committed five-case Phase 2B certificate. The subject copies all
twenty ordered `phase1_corpus_commitments` from that certificate and re-reads
every fixed path to require exact byte length and SHA-256 equality.

`explicit_nonclaims` is the certificate's exact ordered ten-element nonclaim
list. Approval never removes or weakens a nonclaim.

`ReviewSubjectPayloadV1` is the complete ordered object from `schema` through
`explicit_nonclaims`; it omits `subject_digest_hex`. The final subject object
copies those fields unchanged and appends `subject_digest_hex`. The digest is:

```text
SHA-256(
  LP32("seams/router-ab/ed25519-yao/phase2b-review-subject-digest/v1")
  || LP32(complete canonical LF-terminated ReviewSubjectPayloadV1 JSON)
)
```

## 4. Trusted authority policy

The exact policy order is:

```text
schema
protocol_id
policy_scope
policy_version
minimum_approval_sequence
independent_reproducer
cryptographic_reviewer
required_distinct_authorities
```

Fixed values are:

```text
schema = seams:router-ab:ed25519-yao:phase2b-review-authorities:v1
protocol_id = router_ab_ed25519_yao_v1
policy_scope = phase2b_external_reproduction_and_review_authorities_v1
required_distinct_authorities = true
```

Each authority has, in order:

```text
role
authority_id
key_epoch
verifying_key_hex
authority_key_digest_hex
```

The fixed roles are `independent_reproducer` and `cryptographic_reviewer`.
Invalid compressed Edwards keys and weak/small-order keys fail closed.

The authority-key digest is:

```text
SHA-256(
  LP32("seams/router-ab/ed25519-yao/phase2b-review-authority-key-digest/v1")
  || LP32(role)
  || LP32(authority_id)
  || LP32(BE64(key_epoch))
  || LP32(verifying_key)
)
```

## 5. Independent-host reproduction record

The signed envelope order is:

```text
payload
signature_algorithm
signature_hex
```

`signature_algorithm` is exactly `ed25519`. The payload order is:

```text
schema
protocol_id
evidence_scope
authority_policy_sha256_hex
subject_digest_hex
source_commit_hex
source_tree_hex
operator_assertion
host_environment
execution
observations
explicit_nonclaims
```

Fixed identifiers are:

```text
schema = seams:router-ab:ed25519-yao:phase2b-independent-host-reproduction:v1
protocol_id = router_ab_ed25519_yao_v1
evidence_scope = benchmark_only_phase2b_independent_host_reproduction_v1
```

`authority_policy_sha256_hex` is the SHA-256 digest of the exact canonical
trusted-authority policy bytes selected by the external policy pin. Any policy
change invalidates the signed record even when authority IDs, keys, epochs, and
approval floors remain unchanged.

`operator_assertion` contains, in order:

```text
operator_id
operator_key_epoch
operator_authority_key_digest_hex
challenge_hex
independence_claim
started_at_unix_seconds
completed_at_unix_seconds
```

The independence claim is exactly
`operator_and_execution_host_are_independent_of_primary_implementation_environment`.
The completion time MUST be greater than or equal to the start time.

`host_environment` contains, in order:

```text
operating_system
architecture
kernel_release
artifact_filesystem_policy
checkout_state
cargo_target_state
```

The last three values are exactly `accepted_local_filesystem`,
`clean_exact_commit`, and `fresh_process_owned_directory`.

`execution` contains, in order:

```text
runner_contract
locked_dependencies
committed_certificate_check
phase2b_reconciliation_cases
phase2b_reconciliation_rust_tests
phase2b_reconciliation_python_tests
artifact_python_tests
```

Fixed values are the runner contract
`cargo_yao_fv_phase2b_independent_host_reproduce_v1`, `true`, `passed`, and the
counts `5`, `6`, `4`, and `24`.

`observations` contains the exact manifest length/digest, bundle-index
length/digest, and six ordered artifact entries. Each entry has `tag`,
`filename`, `canonical_bytes`, and `sha256_hex`. The fixed-path subject builder
and clean-host runner produce a private expected-observations capability from
fresh emitted bytes and decoded `EYAOBA01` entries. Record verification requires
exact equality with that capability; valid-looking digests or merely nonzero
lengths are insufficient.

The exact reproduction nonclaims are:

```text
operator_independence_policy_is_external
reviewer_approval_not_conveyed_by_this_record
production_artifact_authority_absent
selected_security_profile_absent
protocol_security_unclaimed
runtime_and_deployment_authority_absent
```

The operator signs:

```text
SHA-256(
  LP32("seams/router-ab/ed25519-yao/phase2b-independent-host-reproduction-attestation/v1")
  || LP32(canonical payload JSON)
)
```

The record omits the verifying key. Verification uses the independently pinned
policy and an expected project-issued 32-byte challenge.

### 5.1 Unsigned prepare envelope

`phase2b-independent-host-prepare` accepts no positional arguments, caller
paths, field overrides, or signing material. It does not read stdin. Its only
governance inputs are the three fixed external environment values in Section
4. On success, stdout is exactly one canonical LF-terminated JSON object with
this field order:

```text
schema
review_subject
unsigned_reproduction_payload
signing_digest_hex
```

The fixed prepare schema is:

```text
seams:router-ab:ed25519-yao:phase2b-independent-host-prepare:v1
```

`review_subject` is the exact Section 3 object constructed during this run.
`unsigned_reproduction_payload` is the exact ordered payload from this section.
`signing_digest_hex` is the lowercase hexadecimal encoding of the 32-byte
operator signing digest defined above. The external signer hex-decodes this
field and signs those 32 raw bytes. It does not sign the 64 ASCII hex bytes.
The prepare envelope contains no signature, private key, signing-key handle, or
accepted-evidence authority.

Preparation captures one clean candidate commit `C`, validates its tree, and
creates one private isolated checkout of `C`. The task runner is compiled from
that checkout with locked offline dependencies and a fresh process-owned Cargo
target. The isolated runner executes the complete counted Phase 2B
reconciliation gate, then constructs and measures the review subject from that
same checkout and target. The policy JSON, policy digest, challenge, compiler
wrappers, Rust flags, and ambient Cargo/Rust tool overrides are removed from the
candidate subprocess environment. The reconciliation result must end with the
exact `5` case, `6` Rust-test, `4` focused-Python-test, and `24`
artifact-verifier-test summary before subject material is accepted.

The subject's separately emitted artifact bundle must be byte-for-byte equal to
the manifest and six ordered artifact commitments checked by reconciliation.
Preparation checks the invoking checkout is still clean at `C`, measures the
completion time only after reconciliation, artifact measurement, subject
construction, and the unchanged-checkout check succeed, and then emits the
unsigned envelope. Diagnostics use stderr. The command writes no review or
accepted-evidence file.

### 5.2 Signature-only finalize request

`phase2b-independent-host-finalize` accepts zero positional arguments and reads
exactly one canonical LF-terminated JSON request from stdin through EOF. The
complete stdin request, including the final LF, MUST be at most 65536 bytes.
The bounded reader reads at most 65537 bytes and rejects the input when the
extra byte exists. Empty, truncated, concatenated, noncanonical, or trailing
input fails before any stdout write.

The finalize-request field order is:

```text
schema
prepare_envelope
signature_hex
```

The fixed request schema is:

```text
seams:router-ab:ed25519-yao:phase2b-independent-host-finalize-request:v1
```

`prepare_envelope` is the complete exact Section 5.1 object. `signature_hex` is
exactly 128 lowercase hexadecimal characters encoding the trusted reproducer's
64-byte Ed25519 signature over the 32 raw signing-digest bytes. The request
schema fixes Ed25519, so it contains no caller-selected algorithm. It also
contains no digest copy, payload copy, key handle, private key, field override,
or file path.

Finalize strictly parses and canonically reserializes the complete request,
requires both fixed schemas, recomputes the signing digest from the embedded
payload, and requires exact equality with `signing_digest_hex`. It loads the
three protected inputs, verifies the signature with `verify_strict` under the
pinned independent-reproducer key, and only then performs the expensive subject
check. It regenerates the deterministic subject and fresh observations inside a
private isolated checkout of the captured candidate commit, requires byte
equality with the embedded subject, and validates every policy, challenge,
source, authority, timestamp, host-assertion, execution, observation, and
nonclaim field.

Finalize does not rerun the independent reconciliation ceremony. The trusted
reproducer signature attests to the run recorded by prepare; a second ceremony
on the finalizer host would not prove that earlier execution. Deterministic
subject regeneration still recompiles and checks the exact manifest, bundle,
and six artifact observations. Because the subject commits toolchain-version
outputs, the finalize environment must reproduce those commitments. A different
host is accepted only when it regenerates the exact same subject bytes.

On success, finalize constructs the Section 5 signed reproduction record from
the already validated payload and signature, internally sets
`signature_algorithm` to `ed25519`, rechecks that the invoking checkout remains
clean at the captured commit, and writes exactly that canonical record to
stdout. It writes no evidence file. Repeating the same valid request for the
same protected challenge deterministically emits the same record; challenge
issuance and one-use governance remain external responsibilities.

## 6. Cryptographic-reviewer approval record

The signed envelope again contains `payload`, `signature_algorithm`, and
`signature_hex`. The approval payload order is:

```text
schema
protocol_id
approval_scope
decision
approval_sequence
authority_policy_sha256_hex
subject_digest_hex
independent_reproduction_record_sha256_hex
review_report_path
review_report_sha256_hex
reviewed_at_unix_seconds
reviewer_authority_id
reviewer_key_epoch
reviewer_authority_key_digest_hex
reviewed_surfaces
explicit_nonclaims
```

Fixed identifiers are:

```text
schema = seams:router-ab:ed25519-yao:phase2b-review-approval:v1
protocol_id = router_ab_ed25519_yao_v1
approval_scope = benchmark_only_phase2b_deterministic_core_exit_v1
decision = approve_exact_subject
```

`approval_sequence` MUST be at least the policy floor. The approval binds the
complete signed reproduction envelope and the exact review-report bytes.
`authority_policy_sha256_hex` has the same exact-policy meaning as in the
reproduction record.

`review_report_path` is fixed to
`crates/ed25519-yao/formal-verification/review/phase2b-cryptographic-review-v1.md`.
Acceptance selects the bounded immutable blob at that exact path from the raw
`C..E` diff and hashes its object bytes. Accepted report bytes never come from
the worktree, and callers cannot pair another path with supplied bytes.

`reviewed_surfaces` is exactly this ordered list:

```text
compiler_contract
boolean_core_semantics
input_and_output_schemas
field_byte_bit_and_wire_order
clear_ir_and_schedule_evaluator_equivalence
component_bundle_and_manifest_digests
schedule_gate_metric_and_passive_table_counts
phase1_input_and_party_output_reconciliation
```

`explicit_nonclaims` is the subject's exact ten-element list.

The reviewer signs:

```text
SHA-256(
  LP32("seams/router-ab/ed25519-yao/phase2b-review-approval-attestation/v1")
  || LP32(canonical approval payload JSON)
)
```

## 7. Verification commands

The completed formal tooling MUST expose:

```text
cargo yao-fv phase2b-review-subject-check
cargo yao-fv phase2b-exit-evidence-readiness-check
cargo yao-fv phase2b-change-control-readiness-check
cargo yao-fv phase2b-protected-inputs-check
cargo yao-fv phase2b-independent-host-prepare
cargo yao-fv phase2b-independent-host-finalize
cargo yao-fv phase2b-independent-host-record-check
cargo yao-fv phase2b-review-approval-check
```

The current scaffold exposes all eight commands above. Subject construction refuses a dirty checkout,
uses no caller paths or field overrides, builds a fresh process-owned artifact
directory, checks it byte for byte, decodes the exact `EYAOBA01` entries,
re-reads every specification and corpus commitment, and checks the checkout
again. It prints only canonical subject length, digest, commit, tree, and
artifact count; it writes no accepted evidence. Before exit authority is
possible, the command MUST build all subject material inside a private isolated
checkout of the single captured candidate commit and require the invoking HEAD
remains unchanged. The outer/inner causal snapshot implementation and eleven
focused tests are present. A disposable clean committed-checkout integration
run produced one canonical 15757-byte subject and six exact observations.
The protected-input command loads only the three fixed externally administered
environment values and returns private policy/challenge capabilities; eight
focused tests cover its fail-closed boundary. Prepare emits only the exact unsigned envelope
defined in Section 5.1 after the single-snapshot isolated reproduction flow.
Finalize consumes only the bounded canonical Section 5.2 request and emits the
verified signed record. Record-check accepts only the fixed Section 9 Git-object
staging shape and returns a private verified-reproduction capability.
Approval-check consumes that capability and returns a stronger private review-
approval capability only after the fixed approval blob passes every Section 6
check. These fail-closed commands cannot satisfy the independent-host,
reviewer-approval, or Phase 2 exit gates without genuine externally governed
evidence.

`prepare` refuses a dirty checkout, hashes `git archive --format=tar C`, uses
one private isolated checkout and fresh process-owned target directory, runs
locked offline builds and the complete Phase 2B reconciliation gate, measures
the six emitted artifacts, checks the invoking worktree remains clean at `C`,
and emits the Section 5.1 envelope.

`finalize` accepts the canonical stdin request containing the exact prepare
envelope and externally generated signature, verifies it against the pinned
policy and regenerated subject, and emits the signed envelope. It accepts no
private key.

`record-check` accepts no arguments or stdin. It reads the four fixed evidence
blobs from the captured Git object database, regenerates the subject for `C`,
requires exact committed-subject equality, verifies the protected context and
strict reproduction signature, rechecks clean unchanged `E`, and prints only a
non-authoritative digest summary after issuing its private capability.

`approval-check` accepts no arguments or stdin and first performs the complete
`record-check` verification. It hashes the immutable fixed review-report blob,
canonically parses the immutable fixed approval blob, and verifies its exact
policy, subject, reproduction-record, report, authority, scope, reviewed-
surface, nonclaim, timestamp, sequence-floor, and strict Ed25519 signature
bindings. It rechecks the clean unchanged `E` checkout and prints only a
non-authoritative digest summary after issuing the stronger private capability.
It accepts no caller paths, digests, report bytes, policy values, challenges,
or signing keys.

The record and approval checks regenerate the subject from fixed Git objects,
verify the externally pinned policy digest, convert the externally issued project challenge into a
private capability, require strict Ed25519 signatures with
`verify_strict`, require distinct authorities, and reject stale policy epochs or
approval sequences. They require source commit/tree and every reproduced
artifact observation to equal the regenerated subject capability. A private,
nonserializable verified capability is returned only after every check passes.

Before genuine external evidence exists, the readiness and fixed-subject checks
join normal CI. The protected-input check stays outside `all` because its trust
anchors must be supplied by the independent release verifier. Record and
approval checks stay outside `all` and fail closed when their external files or
externally pinned policy digest are absent. A normal GitHub CI success has no
release-authority meaning.

## 8. Required rejection evidence

Tests MUST reject:

1. unknown, missing, duplicate, reordered, `null`, CRLF, noncanonical
   whitespace, and trailing fields;
2. uppercase, short, long, or nonhex digests, keys, challenges, and signatures;
3. zero epochs, timestamps, policy versions, or approval sequences;
4. invalid or weak Ed25519 keys;
5. shared authority IDs, roles, key bytes, or key digests;
6. wrong-role, wrong-key, altered, truncated, and malleated signatures;
7. absent or mismatched externally pinned policy digest;
8. policy/key substitution at one epoch and stale approval after rotation;
9. any subject compiler, schema, order, component, artifact, schedule, metric,
   count, corpus, specification, certificate, or nonclaim mutation;
10. a changed challenge, host assertion, execution count, or artifact entry;
11. approval bound to another subject, reproduction record, or review report;
12. partial/reordered review surfaces or broadened approval scope;
13. caller-selected subject paths or arbitrary generator artifacts;
14. any private key or signing surface outside test fixtures; and
15. approval/reviewer/signature/promotion surfaces in generator or production
    crates.

## 9. Change control and staging

Any covered compiler, schema, ordering, artifact, metric, count, corpus,
certificate, authoritative-specification, report, authority, or policy change
changes a signed digest and invalidates the old evidence.

Version one has one accepted current parser. A future version replaces it;
there is no compatibility parser or multi-version acceptance path.

The implementation phase commits this specification, strict parsers,
verification logic, subject generation, tests, and CI readiness gate. It MUST
NOT commit a synthetic authority policy, trusted key, successful reproduction
record, review report, or reviewer approval.

The candidate commit `C` contains all generator, verifier, acceptance-command,
CI, and normative-specification code. It contains none of these four fixed
external-evidence files:

```text
crates/ed25519-yao/formal-verification/review/phase2b-review-subject-v1.json
crates/ed25519-yao/formal-verification/review/phase2b-independent-host-reproduction-v1.json
crates/ed25519-yao/formal-verification/review/phase2b-cryptographic-review-v1.md
crates/ed25519-yao/formal-verification/review/phase2b-review-approval-v1.json
```

The independent run and review bind `C`. Genuine evidence is attached in one
subsequent evidence commit `E`. `E` MUST have exactly one parent equal to `C`,
and a replacement-disabled NUL-delimited raw `C..E` tree diff MUST contain
exactly the four paths above. Every entry MUST be an addition from mode `000000`
and the all-zero object ID to a mode-`100644` blob with status exactly `A`.
Executable blobs, symlinks, submodules, modifications, deletions, renames,
copies, type changes, duplicate/case-changed paths, and every fifth path fail.
The evidence commit may not change its own verifier, CI, task lock, toolchain,
specifications, corpora, compiler, artifacts, or claims.

Acceptance captures `E = HEAD` from a clean checkout, reads the raw commit
object with replace objects and ambient Git redirection/configuration disabled,
and requires its one raw `parent` header to equal `C`. It obtains the four new
blob object IDs from the raw diff and reads their immutable object bytes through
bounded `git cat-file`; checked-out paths never supply accepted bytes. Fixed
bounds are 32768 bytes for the subject JSON, 16384 bytes each for the
reproduction and approval JSON, and 262144 bytes for the raw Markdown report.
The raw commit and diff streams are each bounded at 1048576 bytes. Declared
object size, returned byte count, object type, mode, status, and path must all
match before parsing.

At `E`, acceptance derives `C` from the sole raw parent, parses the committed
subject only to require its candidate identity equals that parent, regenerates
the complete subject for `C`, and requires byte equality with the committed
subject. It hashes the
raw `git archive --format=tar C` output and obtains all non-review files from a
tree proven unchanged between `C` and `E`. This prevents the review files from
changing the subject they attest and avoids a source/evidence commit cycle.
The external release verifier treats this accepted pair as a historical
checkpoint for the exact reviewed surface. An unrelated descendant cannot claim
that its whole-repository subject equals `C`, but it may retain the checkpoint
for unchanged reviewed components. Any later covered change requires a new
candidate and a new evidence commit.

### 9.1 Covered change-control surface

The exact covered paths are:

```text
.cargo/**
.github/workflows/phase2b-change-control.yml
crates/ed25519-yao/**
docs/yaos-ab.md
justfile
tools/ed25519-yao-generator/**
tools/ed25519-yao-verifier/**
```

This set contains the compiler contract, schemas and ordering, artifacts,
schedules, metrics and counts, corpora, certificate, formal acceptance code,
normative specifications, task locks, command aliases, and the public staging
checker. A change outside this set does not acquire a Phase 2 claim and does not
require re-review while every covered byte remains unchanged.

The state checker compares an inspected commit with a supplied base and
implements these exact states:

1. zero fixed evidence paths at both base and head is the pre-evidence
   development state; covered changes may continue without an approval claim;
2. one, two, or three fixed evidence paths at either base or head fail;
3. the first complete four-file head requires external verification;
4. a complete base plus an unrelated descendant retains the historical
   checkpoint without rerunning the external verifier;
5. a complete base plus any covered change requires a fresh complete head;
6. a complete base followed by an absent or partial head fails.

Whenever external verification is required, `HEAD` MUST be exact `E`, its sole
parent MUST be the new candidate `C`, the event base MUST be an ancestor of
`C`, and the raw `C..E` diff MUST satisfy the four-addition rule above. A future
covered pull request may therefore contain a candidate commit that removes old
evidence and changes covered bytes followed by the new four-file evidence
commit. The public checker accepts no merge, squash, fifth file, modification,
or partial staging substitute.

The GitHub workflow `.github/workflows/phase2b-change-control.yml` runs only this
public evidence-shape checker. It carries no policy, challenge, signing key,
independent identity, release decision, or protected verification job. Its
result is advisory staging evidence and MUST NOT be treated as a required
release-authority status.

The independent release verifier obtains these exact values through a channel
administered outside the repository and outside the GitHub account:

```text
ED25519_YAO_PHASE2B_REVIEW_POLICY_JSON
ED25519_YAO_PHASE2B_REVIEW_POLICY_SHA256
ED25519_YAO_PHASE2B_REPRODUCTION_CHALLENGE_HEX
```

The verifier runs `phase2b-protected-inputs-check`,
`phase2b-independent-host-record-check`, and `phase2b-review-approval-check`
against exact `E`. It obtains `E` by immutable commit identity, requires the raw
sole-parent `C → E` shape, and independently pins the authority-policy digest.
The reviewer approval signature is the release decision. The reproduction
signature supplies the required separate execution witness.

The revised claim is cryptographic authenticity of the exact Phase 2 subject
and evidence under the externally pinned authority policy. It does not claim
that GitHub prevented repository administrators from rewriting branches,
changing tags, editing workflows, merging unreviewed commits, or publishing
lookalike artifacts. A relying party MUST reject any purported Phase 2 release
unless its own external trust anchor and verifier accept the exact evidence
commit. Repository or GitHub availability remains an operational dependency
only when the relying party chooses GitHub as its artifact source.

After an actual independent run and review:

1. externally govern and distribute the authority-policy digest, canonical
   policy, challenge process, key epochs, and approval-sequence floor;
2. attach the genuine subject, signed reproduction, review report, and approval
   in the single restricted evidence commit;
3. publish the immutable `E` identity and evidence bundle through the external
   release-authority channel;
4. independently run all three acceptance commands against exact `E`; and
5. close only the Phase 2B external-evidence and Phase 2 exits after that
   external verification succeeds.

Garbling, OT, streaming, randomized private output protection, production
constant-time execution, deployment, P0-P3 selection, and protocol security
remain later gates.
