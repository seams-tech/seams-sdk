# Ed25519 Yao Host-Only Lifecycle Continuity Corpus V1

Status: **Phase 1 executable host-only six-case contract; no production
lifecycle or security claim**

This document freezes one narrow, separately versioned JSON corpus for the
isolated generator. It covers:

- a synthetic public registration-candidate metadata snapshot;
- first activation from registration-origin pending metadata;
- recovery with the exact same logical client derivation root;
- refresh with explicit opposite nonzero server-contribution deltas;
- activation continuations for all three valid pending-state origins;
- activation records with zero Deriver/KDF/Yao/export counts and exactly one
  pending-metadata consumption.

The corpus is synthetic reference evidence. Every secret-looking byte in the
file is public test data, while the `host_only_reference` boundary records how
the value is classified in the ideal functionality. Production code must never
consume this corpus or its fixture material.

The keywords **MUST**, **MUST NOT**, **REQUIRED**, and **BLOCKED** are normative.

## 1. Source Boundary

The controlling requirements are:

- Activation consumes committed activation-family packages and performs no
  second Yao evaluation (`docs/router-ab/ed25519-yao/implementation-plan.md`, **Fixed Circuit Families**, and
  `docs/router-ab/protocol.md:902-925`).
- Recovery rewraps the exact same logical 32-byte client root and preserves every
  KDF contribution and identity value (`docs/router-ab/ed25519-yao/implementation-plan.md`, **Fixed Circuit
  Families**, and `tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`,
  **F_ed25519_recovery_v1**).
- Refresh applies `+delta` to A and `-delta` to B, preserves the joined seed and
  scalar, advances role-input-state epochs, and uses forward-only cutover
  (`docs/router-ab/ed25519-yao/implementation-plan.md`, **Fixed Circuit Families**, and
  `tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`,
  **F_ed25519_refresh_v1**).
- Host-only recovery and refresh vectors may land before the production custody,
  proof, active-output, and distributed-cutover mechanisms
  (`tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`, **Add a
  separate lifecycle corpus**, **Recovery preservation proof and custody**, and
  **Refresh delta generation, proof, and distributed cutover**).
- The complete lifecycle corpus eventually requires requests, party views,
  packages, receipts, aborts, and persisted transitions
  (`tools/ed25519-yao-generator/docs/ideal-functionalities-v1.md`, **Add a
  separate lifecycle corpus**).

`recovery_reference.rs` now owns the same-root recovery arithmetic used by the
corpus builder. It checks exact synthetic-root equality, stable-context client
KDF re-derivation, all four current client-contribution fields, unchanged server
fields, joined `d`, and every downstream activation field. A separate stage
composes the validated result with typed scalar output sharing, while those coins
and shares remain outside this corpus. Six focused Rust tests cover precise
rejections, retry-safe borrowed inputs, continuity, preserved server state,
output reconstruction, and source-boundary guards.

`refresh_reference.rs` takes move ownership of typed A/B ideal delta
contributions, derives their nonzero modular sum, verifies
all four client fields unchanged, checks the exact positive A and inverse B
server updates, and checks
joined/downstream activation continuity. Its separate output-sharing stage
remains outside this corpus. Six focused Rust tests cover ordinary and boundary
transforms, the private witness, scalar-share reconstruction, and source guards.

`joint_refresh_delta.rs` owns role contribution validation and joint derivation;
`lifecycle_reference.rs` owns only the opposite-delta arithmetic primitive used
by that preparation. All four modules expressly
exclude credentials, packages, persistence, transport, production custody,
production delta generation, and any P0-P3 protocol-security claim.

The existing `VectorCaseV1` corpus cannot be extended for this purpose. Its
builder evaluates the activation-family arithmetic before branching on every
request label, including `activation` (`src/fixtures.rs:423-455`). Those records
are clear-arithmetic cases, not lifecycle-transition evidence
(`docs/ideal-functionalities-v1.md`, **Source authority and evidence baseline**).

## 2. Claim Boundary

The artifact name and schema use **lifecycle continuity** deliberately:

```text
file = vectors/ed25519-yao-lifecycle-continuity-v1.json
schema = seams:router-ab:ed25519-yao:lifecycle-continuity-vectors:v1
protocol_id = router_ab_ed25519_yao_v1
evidence_scope = host_only_synthetic_continuity_v1
```

This corpus provides executable evidence only for deterministic host-reference
relations over synthetic values. It does not prove:

- credential authorization, suspension, promotion, or tombstone persistence;
- root custody or a production same-root proof;
- unbiased joint refresh-delta generation or delta erasure;
- output-sharing coins, private shares, ciphertexts, package digest sets, or
  recipient opening;
- signed prepare, output-commit, activation, or cutover receipts;
- exact transcript, authorization, ticket, or failure-envelope bytes;
- exact redelivery, crash recovery, atomic distributed persistence, or stale
  epoch rejection in deployed services;
- complete Client, Router, A, B, SigningWorker, observer, or log views;
- active security, selective-failure resistance, or proactive/mobile-adversary
  healing.

Registration evaluation and export are outside this corpus. The registration
case is an already-created synthetic public candidate-metadata snapshot with
zero represented evaluation work. The full five-branch lifecycle JSON corpus
remains BLOCKED.

## 3. Primitive JSON Rules

- Every object has a closed field set. Rust DTOs use
  `#[serde(deny_unknown_fields)]` at every level.
- Tagged unions use `request_kind` and `vector`. Activation uses a second tagged
  union with `origin_kind` and `transition`.
- Every field is required. There are no `Option`, `null`, flattened maps,
  untagged unions, generic metadata bags, or compatibility fields.
- Hex is lowercase and has the exact byte length named by its type.
- A scalar is exactly 32 little-endian bytes and must be strictly less than the
  Ed25519 scalar order `l`.
- A root, `y` value, compressed point, or digest is exactly 32 bytes.
- A SHA-512 trace value is exactly 64 bytes.
- Epochs are JSON integers in `1..=2^64-1`. Booleans, floats, strings, zero, and
  negative values are rejected.
- Participant identifiers are two distinct nonzero `u16` values in ascending
  order.
- Case identifiers are nonempty visible ASCII and unique.
- Duplicate JSON keys and non-standard values such as `NaN` are rejected before
  DTO decoding, matching `_strict_object` and `_reject_json_constant` in
  `tools/ed25519-yao-verifier/verify_vectors.py`.

The canonical committed file is pretty-printed by `serde_json`, ends with one
newline, and must equal the canonical Rust builder byte-for-byte.

This repository is pre-release. The six-case contract replaces the earlier
four-case draft in place; no four-case compatibility schema or decoder remains.

## 4. Exact Corpus Shape

The following pseudocode freezes JSON field presence, nesting, and tags. Every
named struct also has `deny_unknown_fields`.

```rust
struct LifecycleContinuityCorpusV1 {
    schema: String,
    protocol_id: String,
    evidence_scope: String,
    cases: Vec<LifecycleContinuityCaseV1>,
}

#[serde(
    tag = "request_kind",
    content = "vector",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum LifecycleContinuityCaseV1 {
    Registration(RegistrationCandidateMetadataVectorV1),
    Recovery(RecoveryContinuityVectorV1),
    Activation(ActivationContinuityVectorV1),
    Refresh(RefreshContinuityVectorV1),
}

#[serde(
    tag = "origin_kind",
    content = "transition",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum ActivationContinuityVectorV1 {
    Registration(RegistrationActivationContinuationV1),
    Recovery(RecoveryActivationContinuationV1),
    Refresh(RefreshActivationContinuationV1),
}
```

The top-level `cases` array MUST contain exactly the six cases and order frozen
in Section 7.

### 4.1 Fixture Identity

```rust
struct FixtureIdentityV1 {
    application_binding: ApplicationBindingFixtureV1,
    context: StableContextFixtureV1,
    registered_public_key_hex: String,
    x_client_point_hex: String,
    x_server_point_hex: String,
}

struct ApplicationBindingFixtureV1 {
    wallet_id: String,
    near_ed25519_signing_key_id: String,
    signing_root_id: String,
    key_creation_signer_slot: u32,
    encoded_hex: String,
    digest_sha256_hex: String,
}

struct StableContextFixtureV1 {
    application_binding_digest_hex: String,
    participant_ids: [u16; 2],
    encoded_hex: String,
    binding_sha256_hex: String,
}
```

These are the existing strict KDF fixture field sets. The implementation MUST
reuse their Rust types and independent verification logic rather than create a
second encoder.

### 4.2 Epoch And Public-State Shapes

```rust
struct NonZeroEpochV1(NonZeroU64);

struct RoleEpochV1 {
    role_root_epoch: NonZeroEpochV1,
    role_input_state_epoch: NonZeroEpochV1,
}

struct RoleEpochPairV1 {
    deriver_a: RoleEpochV1,
    deriver_b: RoleEpochV1,
}

struct ActiveContinuityPublicStateV1 {
    identity: FixtureIdentityV1,
    active_role_epochs: RoleEpochPairV1,
    active_activation_epoch: NonZeroEpochV1,
}

struct RegistrationPendingPublicStateV1 {
    identity: FixtureIdentityV1,
    candidate_role_epochs: RoleEpochPairV1,
    pending_activation_epoch: NonZeroEpochV1,
}

struct RecoveryPendingPublicStateV1 {
    identity: FixtureIdentityV1,
    current_role_epochs: RoleEpochPairV1,
    active_activation_epoch: NonZeroEpochV1,
    pending_activation_epoch: NonZeroEpochV1,
}

struct RefreshPendingPublicStateV1 {
    identity: FixtureIdentityV1,
    current_role_epochs: RoleEpochPairV1,
    next_role_epochs: RoleEpochPairV1,
    active_activation_epoch: NonZeroEpochV1,
    pending_activation_epoch: NonZeroEpochV1,
    derivation_admission: FrozenAdmissionV1,
}

#[serde(rename_all = "snake_case")]
enum FrozenAdmissionV1 {
    Frozen,
}

struct RefreshActivatedPublicStateV1 {
    identity: FixtureIdentityV1,
    active_role_epochs: RoleEpochPairV1,
    retired_role_input_state_epochs: RetiredRoleInputEpochPairV1,
    active_activation_epoch: NonZeroEpochV1,
    derivation_admission: OpenAdmissionV1,
}

struct RetiredRoleInputEpochPairV1 {
    deriver_a: NonZeroEpochV1,
    deriver_b: NonZeroEpochV1,
}

#[serde(rename_all = "snake_case")]
enum OpenAdmissionV1 {
    Open,
}
```

`FrozenAdmissionV1` and `OpenAdmissionV1` are branch-specific types. A broad
boolean or caller-selected status string is forbidden.

`NonZeroEpochV1` serializes as a JSON integer and rejects zero during
deserialization. Top-level corpus validation additionally requires the exact
canonical six-case relation, including each same-role `next > current`
transition.

### 4.3 Reference Operation Counts

```rust
struct ReferenceOperationCountsV1 {
    deriver_a_invocations: u8,
    deriver_b_invocations: u8,
    client_kdf_derivations_a: u8,
    client_kdf_derivations_b: u8,
    server_kdf_derivations_a: u8,
    server_kdf_derivations_b: u8,
    activation_family_evaluations: u8,
    export_family_evaluations: u8,
    pending_activation_consumptions: u8,
}
```

The corpus omits output-share-sampling counts because output sharing is outside
its claim. The activation variants structurally contain no output randomness or
share field.

### 4.4 Host-Only Arithmetic Shapes

```rust
struct SyntheticRootsV1 {
    client_root_hex: String,
    deriver_a_root_hex: String,
    deriver_b_root_hex: String,
}

struct ContributionTupleV1 {
    y_client_a_hex: String,
    tau_client_a_hex: String,
    y_client_b_hex: String,
    tau_client_b_hex: String,
    y_server_a_hex: String,
    tau_server_a_hex: String,
    y_server_b_hex: String,
    tau_server_b_hex: String,
}

struct ClientContributionPairV1 {
    y_client_a_hex: String,
    tau_client_a_hex: String,
    y_client_b_hex: String,
    tau_client_b_hex: String,
}

struct ClearReferenceTraceV1 {
    y_a_hex: String,
    y_b_hex: String,
    joined_seed_hex: String,
    sha512_digest_hex: String,
    clamped_scalar_bytes_hex: String,
    signing_scalar_hex: String,
    tau_a_hex: String,
    tau_b_hex: String,
    tau_hex: String,
    x_client_base_hex: String,
    x_server_base_hex: String,
    x_client_point_hex: String,
    x_server_point_hex: String,
    public_key_hex: String,
}

struct RecoveryHostOnlyReferenceV1 {
    synthetic_roots: SyntheticRootsV1,
    current_contributions: ContributionTupleV1,
    recovered_client_root_hex: String,
    rederived_client_contributions: ClientContributionPairV1,
    after_contributions: ContributionTupleV1,
    before_clear_reference_trace: ClearReferenceTraceV1,
    after_clear_reference_trace: ClearReferenceTraceV1,
}

struct CorrelatedRefreshDeltaV1 {
    delta_y_hex: String,
    delta_tau_hex: String,
}

struct RefreshHostOnlyReferenceV1 {
    synthetic_roots: SyntheticRootsV1,
    before_contributions: ContributionTupleV1,
    delta: CorrelatedRefreshDeltaV1,
    after_contributions: ContributionTupleV1,
    before_clear_reference_trace: ClearReferenceTraceV1,
    after_clear_reference_trace: ClearReferenceTraceV1,
}
```

The implementation MUST reuse the existing KDF fixture types for roots,
contributions, and clear traces where their exact field sets match.

### 4.5 Case Payloads

```rust
struct RegistrationCandidateMetadataVectorV1 {
    case_id: String,
    pending_public: RegistrationPendingPublicStateV1,
    reference_operation_counts: ReferenceOperationCountsV1,
}

struct RecoveryContinuityVectorV1 {
    case_id: String,
    before_public: ActiveContinuityPublicStateV1,
    pending_public: RecoveryPendingPublicStateV1,
    reference_operation_counts: ReferenceOperationCountsV1,
    host_only_reference: RecoveryHostOnlyReferenceV1,
}

struct RegistrationActivationContinuationV1 {
    case_id: String,
    origin_case_id: String,
    pending_public: RegistrationPendingPublicStateV1,
    activated_public: ActiveContinuityPublicStateV1,
    reference_operation_counts: ReferenceOperationCountsV1,
}

struct RefreshContinuityVectorV1 {
    case_id: String,
    before_public: ActiveContinuityPublicStateV1,
    pending_public: RefreshPendingPublicStateV1,
    reference_operation_counts: ReferenceOperationCountsV1,
    host_only_reference: RefreshHostOnlyReferenceV1,
}

struct RecoveryActivationContinuationV1 {
    case_id: String,
    origin_case_id: String,
    pending_public: RecoveryPendingPublicStateV1,
    activated_public: ActiveContinuityPublicStateV1,
    reference_operation_counts: ReferenceOperationCountsV1,
}

struct RefreshActivationContinuationV1 {
    case_id: String,
    origin_case_id: String,
    pending_public: RefreshPendingPublicStateV1,
    activated_public: RefreshActivatedPublicStateV1,
    reference_operation_counts: ReferenceOperationCountsV1,
}
```

The registration candidate and every activation case have no
`host_only_reference`, root, contribution, delta, clear trace, output
randomness, or export result field. Registration-candidate operation counts are
all zero because the case represents an already-created metadata snapshot; the
corpus makes no claim about registration computation.

## 5. Public Versus Host-Only Classification

JSON placement is normative:

| Location                     | Semantic visibility  | Allowed values                                                                                 |
| ---------------------------- | -------------------- | ---------------------------------------------------------------------------------------------- |
| `before_public`              | public reference     | immutable binding/context evidence, public points, current epochs                              |
| registration `pending_public` | public reference   | candidate identity, candidate role epochs, first pending epoch, and no active predecessor       |
| recovery `pending_public`     | public reference    | unchanged identity/current epochs, active epoch, and next pending activation epoch              |
| refresh `pending_public`      | public reference    | unchanged identity, current/next epochs, active/pending epochs, and frozen-admission tag         |
| `activated_public`           | public reference     | unchanged public identity, active/retired epochs, active activation epoch                      |
| `reference_operation_counts` | public test metadata | only the counters frozen by Section 7                                                          |
| `origin_case_id`             | public test linkage  | exact earlier registration, recovery, or refresh case identifier                                |
| `host_only_reference`        | host-only reference  | synthetic roots, contributions, delta, joined traces                                           |

Public objects MUST NOT contain a root, contribution, delta, joined seed,
SHA-512 digest, clamped scalar, signing scalar, scalar base, or seed/export
result. The compressed `X_client`, `X_server`, and registered public key are
public points and remain allowed.

No field in this corpus represents a production party view.

## 6. Frozen Arithmetic And Continuity Relations

The independent implementations recompute:

```text
y_A = y_client_A + y_server_A mod 2^256
y_B = y_client_B + y_server_B mod 2^256
d   = LE32(y_A + y_B mod 2^256)
a   = LE256(clamp(SHA-512(d)[0..32])) mod l

tau_A = tau_client_A + tau_server_A mod l
tau_B = tau_client_B + tau_server_B mod l
tau   = tau_A + tau_B mod l

x_client_base = a + tau mod l
x_server_base = a + 2*tau mod l
```

The registration candidate requires:

```text
candidate identity = canonical synthetic fixture identity
candidate role epochs = A(root=3,input=11), B(root=9,input=41)
pending activation epoch = 7
all reference-operation counts = 0
```

Recovery requires:

```text
recovered_client_root = synthetic_roots.client_root
rederived_client_contributions = current client contributions
after_contributions = current_contributions
after_clear_reference_trace = before_clear_reference_trace
pending_public.identity = before_public.identity
pending_public.current_role_epochs = before_public.active_role_epochs
pending_activation_epoch > active_activation_epoch
```

Refresh requires:

```text
delta_y != 0 in Z_(2^256)
delta_tau != 0 and delta_tau < l

y_server_A_after   = y_server_A_before + delta_y mod 2^256
y_server_B_after   = y_server_B_before - delta_y mod 2^256
tau_server_A_after = tau_server_A_before + delta_tau mod l
tau_server_B_after = tau_server_B_before - delta_tau mod l

all client contributions after = all client contributions before
y_A_after = y_A_before + delta_y mod 2^256
y_B_after = y_B_before - delta_y mod 2^256
tau_A_after = tau_A_before + delta_tau mod l
tau_B_after = tau_B_before - delta_tau mod l

joined_seed_after = joined_seed_before
SHA512_after = SHA512_before
clamped_scalar_after = clamped_scalar_before
signing_scalar_after = signing_scalar_before
tau_after = tau_before
x_client_base_after = x_client_base_before
x_server_base_after = x_server_base_before
X_client_after = X_client_before
X_server_after = X_server_before
A_pub_after = A_pub_before
next role-root epochs = current role-root epochs
each next role-input-state epoch > its current same-role epoch
pending_public.identity = before_public.identity
pending_activation_epoch > active_activation_epoch
```

Activation requires exact equality with its earlier origin case's pending state.
It changes no public identity value or role epoch beyond the origin's already
staged transition. Registration-origin activation promotes the candidate role
epochs and first pending activation epoch into the initial active state.
Recovery-origin activation promotes the pending activation epoch.
Refresh-origin activation promotes the staged role epochs and activation epoch,
records the two former input-state epochs as retired, and changes derivation
admission from the branch-specific `frozen` type to `open`.

## 7. Canonical Six-Case Corpus

The corpus uses the committed KDF fixture:

```text
wallet_id                   = wallet-fixture
near_ed25519_signing_key_id = ed25519ks_fixture
signing_root_id             = project-fixture:env-fixture
key_creation_signer_slot    = 1
participant_ids             = [1, 2]
client_root                 = 0x11 * 32
deriver_a_root              = 0x22 * 32
deriver_b_root              = 0x33 * 32
application_binding_digest  = b1dbafce5fd696ae4bd5611e3684a778febfdf7f716e2dfe3211ce0cff708121
stable_context_binding      = b5601ad156882b545a2e4a4a694e87c7982842d37a4c666645302604b2720655
registered_public_key       = ccd255d0b88721771947038f1a7c29b49eee3902d6aa732e5e448251537bf077
x_client_point              = 51b3df90f4b138f15cce318f39b790972440dc6a22122e52839dc83513006b72
x_server_point              = 4809448a1ab1912ec0f4664194d9a6ad23b93ac4c348c4028c760a3c641f0e02
```

The cases and order are:

1. `registration_candidate_metadata_v1`
   - request kind `registration`;
   - records the canonical synthetic candidate identity and role epochs A
     `(root=3,input=11)`, B `(root=9,input=41)`;
   - stages the first activation epoch `7` without an active pre-state;
   - represents no registration evaluator, contribution derivation, package
     construction, or proof;
   - every reference-operation count is `0`.
2. `activation_after_registration_zero_evaluation_v1`
   - request kind `activation`, origin kind `registration`;
   - origin case is `registration_candidate_metadata_v1`;
   - pending state is byte-for-byte equal to the origin's pending public state;
   - candidate role epochs become active and activation epoch `7` becomes the
     first active epoch;
   - counts: every Deriver, KDF, activation-family, and export-family count is
     `0`; pending consumptions is `1`.
3. `recovery_same_root_continuity_v1`
   - request kind `recovery`;
   - before state equals the preceding registration-origin activation output;
   - recovered client root `0x11 * 32`;
   - role epochs A `(root=3,input=11)`, B `(root=9,input=41)` remain unchanged;
   - activation epoch stages `7 -> 8`;
   - counts: A/B invocations `1/1`, client KDF derivations `1/1`, server KDF
     derivations `0/0`, activation-family evaluations `1`, export-family
     evaluations `0`, pending consumptions `0`.
4. `activation_after_recovery_zero_evaluation_v1`
   - request kind `activation`, origin kind `recovery`;
   - origin case is `recovery_same_root_continuity_v1`;
   - pending state is byte-for-byte equal to the origin's pending public state;
   - activation epoch `8` becomes active; role epochs and identity stay fixed;
   - counts: every Deriver, KDF, activation-family, and export-family count is
     `0`; pending consumptions is `1`.
5. `refresh_opposite_delta_continuity_v1`
   - request kind `refresh`;
   - starts from activation epoch `8` and the same role epochs;
   - `delta_y_hex = a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5`;
   - `delta_tau_hex = 1100000000000000000000000000000000000000000000000000000000000000`
     (`LE32(17)`);
   - next role epochs are A `(root=3,input=12)`, B `(root=9,input=43)`;
   - activation epoch stages `8 -> 9`; derivation admission is `frozen`;
   - counts: A/B invocations `1/1`, all KDF derivations `0`, activation-family
     evaluations `1`, export-family evaluations `0`, pending consumptions `0`.
6. `activation_after_refresh_zero_evaluation_v1`
   - request kind `activation`, origin kind `refresh`;
   - origin case is `refresh_opposite_delta_continuity_v1`;
   - pending state is byte-for-byte equal to the origin's pending public state;
   - next role epochs become active, input epochs `11` and `41` become retired,
     activation epoch `9` becomes active, and derivation admission becomes
     `open`;
   - counts: every Deriver, KDF, activation-family, and export-family count is
     `0`; pending consumptions is `1`.

The different A/B epoch values and B's `41 -> 43` transition prove that epochs
are per-role and need only advance strictly; lockstep equality or `+1` is not an
invariant (`docs/input-provenance-v1.md`, **Epoch semantics**).

## 8. Required Rejection Tests

Invalid JSON is generated by mutation tests. It is not committed as a second
generic or raw-value corpus.

### 8.1 Parser And Shape Rejections

Reject:

1. duplicate keys, unknown keys, missing required keys, `null`, or an empty
   object;
2. wrong schema, protocol id, evidence scope, case count, case order, or case id;
3. duplicate case ids or an activation origin that is missing, later in the
   array, or of the wrong request kind;
4. unsupported request kinds or activation origin kinds;
5. recovery/refresh fields placed in activation, including
   `host_only_reference`, roots, contributions, deltas, clear traces, or output
   randomness;
6. registration-evaluator inputs/results, export fields, export seed results,
   optional secret bags, or a generic lifecycle payload;
7. malformed, uppercase, short, or long hex; a noncanonical scalar; a zero or
   invalid epoch; invalid participant ids; invalid application-binding facts.

### 8.2 Registration Metadata Rejections

Reject a mutation that:

1. adds an active predecessor epoch or active registered pre-state;
2. changes the candidate identity, either role epoch, or the first pending
   activation epoch;
3. makes the first pending activation epoch zero, boolean, or noncanonical;
4. makes any reference-operation count nonzero;
5. adds roots, contributions, registration-evaluator inputs/results, package
   bytes, proof material, or a host-only reference object.

### 8.3 Recovery Rejections

Reject a mutation that:

1. changes `recovered_client_root_hex` by any byte;
2. changes any rederived client contribution;
3. changes any client or server field in `after_contributions`;
4. changes any after-trace field, including joined `d`, `a`, `tau`, either scalar
   base, either public point, or the registered public key;
5. changes the application binding, stable-context binding, key-creation signer
   slot, public identity, role-root epoch, or role-input-state epoch across the
   transition;
6. repeats, regresses, or zeroes the pending activation epoch;
7. sets a nonzero export-family count or a zero/multiple activation-family count.

Unavailable/compromised-root classification and credential suspension are not
fields in this narrow corpus. Their rejection behavior remains part of the full
lifecycle boundary.

### 8.4 Refresh Rejections

Reject a mutation that:

1. makes `delta_y` zero;
2. makes `delta_tau` zero or noncanonical;
3. applies the delta with the same sign to both roles, swaps arithmetic domains,
   or changes only one side;
4. changes a client contribution;
5. fails to change `y_A`, `y_B`, `tau_A`, or `tau_B` by the exact signed delta,
   or changes any joined/downstream identity field or public identity value;
6. changes either role-root epoch;
7. repeats, regresses, or zeroes either next role-input-state epoch;
8. repeats, regresses, or zeroes the pending activation epoch;
9. uses an `open` admission tag in the pending refresh state;
10. sets a nonzero KDF/export count or a zero/multiple activation-family count.

### 8.5 Activation Rejections

Reject a mutation that:

1. names activation or export as the origin kind, or uses registration outside
   the frozen registration-origin activation case;
2. changes any byte of the copied origin pending state;
3. changes the registered public key, stable binding, public points, or role-root
   epoch;
4. activates the wrong activation epoch;
5. changes a registration- or recovery-origin role-input-state epoch;
6. fails to promote both refresh next epochs, records the wrong retired input
   epoch, or leaves derivation admission frozen;
7. makes any Deriver, KDF, activation-family, or export-family count nonzero;
8. makes pending activation consumptions anything other than `1`;
9. adds a root, contribution, delta, joined trace, output coin/share, ciphertext,
   receipt, export result, or new client-secret field.

### 8.6 Public/Host Boundary Rejections

For every public object, inject each forbidden host-only field name and require
strict decoding failure. Also recursively assert that public objects contain no
field ending in:

```text
_root_hex
_contribution_hex
_delta_hex
joined_seed_hex
sha512_digest_hex
clamped_scalar_bytes_hex
signing_scalar_hex
x_client_base_hex
x_server_base_hex
authorized_seed_hex
```

The explicit exact-key checks remain authoritative; the suffix scan is a defense
against future DTO expansion.

## 9. Independent Python Verification Scope

Extend the standard-library verifier with schema auto-detection for
`lifecycle-continuity-vectors:v1`. The Python implementation MUST:

1. enforce every exact key set, tag, primitive encoding, range, case id, case
   order, and cross-case origin relation;
2. reuse its independent application-binding, stable-context, HKDF-SHA256,
   Ed25519 arithmetic, and point-compression routines;
3. derive the eight current contributions from the three synthetic roots and
   stable context;
4. recompute both recovery traces and require exact root, contribution, trace,
   and public-identity equality;
5. validate both nonzero refresh deltas, apply `+delta` to A and `-delta` to B in
   the correct domains, require the four role-local trace fields to move by those
   exact deltas, and require equality only for the joined/downstream identity
   fields;
6. enforce recovery and refresh epoch invariants;
7. resolve all three activation origins, require exact pending-state equality,
   enforce the origin-specific promotion, and require the frozen zero-evaluation
   counts;
8. enforce the public/host boundary and structural absence of activation secret
   inputs;
9. run one mutation test for every rejection class in Section 8.

Python verification does not establish that deployed code made zero network or
Yao calls. The Rust host-fixture construction shows only that these three
synthetic activation-continuation builders have no contribution, KDF, oracle,
or Deriver input. Python verifies the resulting closed shape and counters.

The Python verifier MUST NOT import Rust artifacts, generated code, third-party
cryptography, or workspace JavaScript. Variable-time arithmetic remains
host-test-only, matching `tools/ed25519-yao-verifier/README.md`.

## 10. Rust Generator And Test Contract

The corpus is implemented in `lifecycle_fixtures.rs` and reuses the strict
application-binding, context, KDF fixture, contribution, and trace types. Its
public construction surface is:

```text
canonical_lifecycle_continuity_corpus_v1()
LIFECYCLE_CONTINUITY_CORPUS_SCHEMA_V1
```

The builder MUST:

- construct the baseline through the canonical KDF fixture path;
- construct a public-only synthetic registration-candidate metadata snapshot;
- construct recovery only through
  `prepare_host_only_recovery_reference_v1` with the same typed synthetic client
  root;
- construct refresh only through `prepare_host_only_refresh_reference_v1`;
- recompute before and after oracle traces independently;
- construct each activation solely from the earlier pending public state;
- avoid calling `evaluate_activation`, KDF functions, or either Deriver path in
  any activation branch;
- contain no production adapter, persistence, transport, or feature flag.

Add focused Rust tests for:

- byte-for-byte committed corpus equality and one trailing newline;
- exact six-case order and activation origin links;
- every relation in Section 6;
- all strict Serde shape rejections in Section 8;
- compile-time structural absence of activation host-only inputs and export seed
  outputs;
- a source guard preventing the lifecycle fixture module from depending on
  Router, SDK, Worker, WASM, Cloudflare, HSS, or production protocol crates.

The separate `recovery_reference` test target MUST remain nonzero and counted by
the formal parity gate. It MUST reject a changed root and independent A/B client
`y` or `tau` drift, prove all before/after activation fields equal, preserve
arbitrary validated server inputs, reconstruct both typed scalar outputs, and
exclude serialization and production surfaces.

The separate `refresh_reference` test target MUST likewise remain nonzero and
counted. It MUST check unchanged clients, exact A-positive/B-inverse server
updates, carry/borrow and scalar wrap boundaries, every joined/downstream field,
typed scalar-output reconstruction, call-local delta move ownership, and exclusion of
serialization and production surfaces.

Extend the existing vector CLI with distinct
`emit-lifecycle-continuity` and `check-lifecycle-continuity` commands. Do not add
a second duplicate binary or reinterpret the existing arithmetic corpus.

## 11. Exit Criteria

This narrow artifact is complete when:

- Rust regenerates the committed six-case JSON byte-for-byte;
- independent Python accepts it and rejects every required mutation;
- recovery preserves every frozen root/contribution/identity byte;
- refresh satisfies the exact opposite-delta and epoch relations;
- all three activation variants contain no host-only input and record zero Deriver,
  KDF, and Yao evaluation counts;
- the corpus and tests label all aggregate secret data as host-only;
- documentation and TODOs continue to leave the full lifecycle corpus,
  production custody/proof, active output, receipts, party views, and distributed
  integration open.
