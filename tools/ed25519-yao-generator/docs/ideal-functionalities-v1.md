# Ed25519 Yao Lifecycle Ideal-Functionality Boundary V1

Status: **Phase 1 partial freeze for the isolated host-only reference generator**

This document freezes the lifecycle and party-boundary facts that already have
normative support. It also records the decisions that still block executable
lifecycle functions. The five functions below are reference contracts for
`tools/ed25519-yao-generator`. They do not describe a deployed protocol, prove an
active Yao construction, or authorize Router, Cloudflare, SigningWorker, SDK, or
persistence integration.

Phase 1 remains open. In particular, recovery preservation, refresh cutover,
production root custody, role-input provenance, registration anti-bias, and the
exact active protocol require separate reviewed decisions.

## 1. Source authority and evidence baseline

The source precedence for this boundary is:

1. `docs/router-a-b-SPEC.md` owns product lifecycle, routing, transcript, and
   recipient behavior. See lines 5-11 and 902-925.
2. `docs/yaos-ab.md` owns the Ed25519 secure-computation backend, arithmetic,
   output custody, and active-security target. See lines 79-103 and 105-161.
3. `docs/router-a-b-sol-refactor.md` owns the wider cutover constraints and
   deletion plan. See lines 27-102 and 117-170.
4. Current generator code supplies executable clear-arithmetic evidence only.
   Its README explicitly leaves lifecycle transitions, provenance, and
   active-protocol semantics open at
   `tools/ed25519-yao-generator/README.md:109-125`.

Current implementation facts:

- `LifecycleRequestKindV1` and `VectorCaseV1` already encode five disjoint tags
  at `tools/ed25519-yao-generator/src/fixtures.rs:61-112`.
- The existing vector union prevents an export result in a non-export branch at
  `tools/ed25519-yao-generator/src/fixtures.rs:89-112,152-160`.
- `ActivationOracleOutput` has no seed field while `ExportOracleOutput` requires
  one at `tools/ed25519-yao-generator/src/lib.rs:435-470`.
- The only executable functions are the shared clear-arithmetic activation and
  export projections at `tools/ed25519-yao-generator/src/lib.rs:483-504`.
- Every current non-export vector is a lifecycle-labelled arithmetic case. The
  builder calls `evaluate_activation` before branching on the lifecycle tag at
  `tools/ed25519-yao-generator/src/fixtures.rs:423-455`. Those cases are not
  lifecycle-transition evidence.
- The current Router primitive enum has only registration, export, and refresh
  at `crates/router-ab-core/src/derivation/context.rs:29-49`. Its admission
  mapping sends recovery to export at
  `crates/router-ab-core/src/protocol/gate.rs:33-40`, with a locking test at
  `crates/router-ab-core/tests/gate.rs:13-30`. That path is superseded target
  behavior and remains outside this isolated generator slice.

## 2. Normative vocabulary

The keywords **MUST**, **MUST NOT**, **REQUIRED**, and **BLOCKED** are normative.

- **Reference functionality** means deterministic or explicitly coin-driven
  host-only semantics used to create synthetic vectors.
- **Activation-family evaluation** means the Ed25519 arithmetic plus private
  randomized sharing needed by registration, recovery, and refresh.
- **Activation continuation** means consumption of already committed
  activation-family packages. It performs no second Yao evaluation.
- **Party-visible output** means a value a named party may receive in the ideal
  execution. A host-only clear reference trace is never a party-visible output.
- **Public leakage** means transcript-bound public information and observable
  metadata that the ideal model deliberately exposes.
- **Uniform abort** means one redacted terminal envelope whose contents are
  independent of protected honest-party values. Exact active-protocol timing and
  selective-failure proofs remain blocked.

## 3. Frozen arithmetic relation

The reference functionality uses the already frozen arithmetic:

```text
y_A = y_client_A + y_server_A mod 2^256
y_B = y_client_B + y_server_B mod 2^256
d   = LE32(y_A + y_B mod 2^256)
h   = SHA-512(d)
a   = LE256(clamp(h[0..32])) mod l

tau_A = tau_client_A + tau_server_A mod l
tau_B = tau_client_B + tau_server_B mod l
tau   = tau_A + tau_B mod l

x_client_base = a + tau mod l
x_server_base = a + 2 * tau mod l
```

The canonical byte and scalar rules appear in `docs/yaos-ab.md:163-181`. The
four-`y` and four-`tau` decomposition and output projection appear at lines
272-295. The public relation is:

```text
X_client = x_client_base * B
X_server = x_server_base * B
A_pub    = a * B
2 * X_client - X_server = A_pub
```

Evidence: `docs/yaos-ab.md:426-451`. Export recomputes the registered identity
from `d` as required by `docs/yaos-ab.md:456-458`.

## 4. Frozen lifecycle dispatch

Exactly five lifecycle request kinds exist:

| Request kind   | Ideal-function name         | Evaluation behavior                              |
| -------------- | --------------------------- | ------------------------------------------------ |
| `registration` | `F_ed25519_registration_v1` | one activation-family evaluation                 |
| `activation`   | `F_ed25519_activation_v1`   | consume committed packages; zero Yao evaluations |
| `recovery`     | `F_ed25519_recovery_v1`     | one activation-family evaluation                 |
| `refresh`      | `F_ed25519_refresh_v1`      | one activation-family evaluation                 |
| `export`       | `F_ed25519_export_v1`       | one export-family evaluation                     |

This mapping is fixed by `docs/router-a-b-SPEC.md:902-920` and
`docs/yaos-ab.md:297-333`. A caller never supplies a circuit or ideal-function
identifier. Router derives both from the admitted request kind.

Activation is an internal continuation. It consumes and verifies packages
created by registration, recovery, or refresh and never triggers another Yao
evaluation (`docs/router-a-b-SPEC.md:916-920`; `docs/yaos-ab.md:329-333`).

## 5. Common public context and leakage

### 5.1 Public transcript scope

Every lifecycle request MUST bind the following public semantic fields:

- protocol version and canonical request kind;
- request id and replay nonce;
- account or wallet identity and session id;
- organization, project, and environment identity;
- signing-root id and version;
- root-share epoch;
- Deriver A identity and key epoch;
- Deriver B identity and key epoch;
- SigningWorker identity and key epoch;
- client ephemeral public key;
- recipient kind and output-package kind;
- request expiry;
- public request-context digest.

Evidence: `docs/router-a-b-SPEC.md:377-395,409-433`. The exact canonical encoding
of `CeremonyTranscriptContext` remains Phase 1 work. Implementations may define
the semantic type now; serialization and digest constructors MUST stay private
until that encoding is frozen.

The stable key context stays separate. Lifecycle, authorization, transport,
deployment, ticket, epoch, and circuit metadata MUST NOT enter
`StableKeyDerivationContextV1` (`docs/yaos-ab.md:183-270`).

### 5.2 Common public leakage

The ideal model may expose:

- every common public transcript field above;
- the request kind and its derived circuit family;
- public transcript and request digests;
- recipient ciphertext digests and the complete package-digest set;
- public output receipt, ticket id, and terminal status;
- `A_pub` and, for activation-family output, `X_client` and `X_server`;
- role ids, key epochs, state-transition labels, response sizes, and timing;
- a redacted public failure code through the uniform abort envelope.

Evidence: public receipt fields at `docs/yaos-ab.md:419-443`, payload boundaries
at `docs/yaos-ab.md:498-510`, Router-held values at
`docs/router-a-b-SPEC.md:72-92`, and observability rules at
`docs/router-a-b-SPEC.md:2849-2857`.

The public receipt schema MUST be lifecycle-discriminated. Activation-family
receipts may carry `X_client`, `X_server`, and `A_pub`. Export public leakage may
include the already-public registered `A_pub`, package digests, ticket id, and
transcript root. The exact export receipt field set and signed byte encoding
remain blocked with the active output protocol.

### 5.3 Forbidden leakage

Public leakage, diagnostics, persistence-visible metadata, and aborts MUST NOT
contain:

- role-envelope plaintext;
- either role's root material;
- `y` or `tau` contributions;
- joined `d`, `a`, `y_server`, `tau_server`, `x_client_base`, or
  `x_server_base`;
- scalar output shares or seed shares;
- labels, masks, OT state, garbling seeds, or recipient-encryption keys;
- protocol payload plaintext or secret-bearing material handles.

Evidence: `docs/router-a-b-SPEC.md:150-184,230-247,2849-2857` and
`docs/yaos-ab.md:498-510`.

## 6. Value-custody matrix

The following matrix is frozen for the ideal party views.

| Party            | Allowed private input/output                                                                                     | Forbidden values                                                                                               |
| ---------------- | ---------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Client           | its role-scoped inputs; eventual `x_client_base`; joined `d` and derived `a` only after an authorized export     | `y_server`, `tau_server`, `x_server_base`; joined `d` or `a` in registration, activation, recovery, or refresh |
| Router           | opaque role envelopes, opaque recipient ciphertexts, public scope, digests, receipts, lifecycle and replay state | all role plaintext, output shares, joined secrets, client or SigningWorker plaintext                           |
| Deriver A        | A role-local inputs, A protocol randomness and frames, A-only randomized output shares, public transcript        | B private inputs, either joined signing output, joined `d` or `a`, recipient joined plaintext                  |
| Deriver B        | B role-local inputs, B protocol randomness and frames, B-only randomized output shares, public transcript        | A private inputs, either joined signing output, joined `d` or `a`, recipient joined plaintext                  |
| SigningWorker    | eventual `x_server_base`, active server signing state, server-recipient package verification, public receipt     | client output, `d`, `a`, Deriver roots, export packages                                                        |
| Public observer  | common public leakage                                                                                            | every private input, random share, plaintext output, label, mask, OT state, seed, scalar, or decryption key    |
| Logs/diagnostics | public ids, digests, safe state transitions, sizes, timings, redacted failure code                               | protocol payload plaintext and every secret listed for the public observer                                     |

The custody rule is stated directly at `docs/yaos-ab.md:105-124` and
`docs/router-a-b-SPEC.md:150-184`. Recipient opening is fixed at
`docs/router-a-b-SPEC.md:463-488,702-715`. Source-boundary prohibitions also
appear at `docs/router-a-b-sol-refactor.md:1084-1102`.

Client plus SigningWorker may reconstruct `a = 2*x_client_base -
x_server_base mod l`. That collusion is an explicit security exclusion
(`docs/yaos-ab.md:960-979`).

## 7. Frozen state families

Five disjoint request, pre-state, and success types are REQUIRED. Activation may
consume pending output from registration, recovery, or refresh. Export carries a
separate consumed-authorization result. No lifecycle struct uses optional secret
fields.

The normative pre-state and identity table is:

| Function     | Required pre-state                                       | Success state/update                                                                  | Identity invariant                                        |
| ------------ | -------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Registration | no registered Ed25519 key                                | registered identity plus committed client and SigningWorker activation packages       | establish exactly one new `A_pub`                         |
| Activation   | registered identity plus inactive committed packages     | consume the pending packages and activate the selected SigningWorker epoch            | preserve registered `A_pub`                               |
| Recovery     | registered identity plus approved recovery authorization | replace approved client credential/root binding and prepare fresh activation packages | `d_after = d_before`; `A_pub_after = A_pub_before`        |
| Refresh      | registered identity plus current role epochs             | replace role-local shares/epochs and prepare next-epoch activation packages           | joined `y`, joined `tau`, `d`, and `A_pub` stay unchanged |
| Export       | registered identity plus explicit export authorization   | consume/audit export authorization after output release; retain registered identity   | exported `d` derives the registered `A_pub`               |

The source table is `docs/yaos-ab.md:345-353`. Fresh recovery and refresh
recipient ciphertext requirements come from `docs/router-a-b-SPEC.md:908-925`.
Export authorization consumption after release is fixed by
`docs/router-a-b-sol-refactor.md:160-170`.

### 7.1 Rust type-shape pseudocode

The following pseudocode is normative for disjointness and ownership. Names may
change during implementation. Field presence and branch separation may not.

```rust
pub enum ReferenceLifecycleRequestV1 {
    Registration(RegistrationRequestV1),
    Activation(ActivationRequestV1),
    Recovery(RecoveryRequestV1),
    Refresh(RefreshRequestV1),
    Export(ExportRequestV1),
}

pub struct RegistrationRequestV1 {
    pub public: CommonLifecyclePublicInputV1,
    pub recipients: ActivationRecipientsV1,
}

pub struct ActivationRequestV1 {
    pub public: CommonLifecyclePublicInputV1,
    pub pending: PendingActivationPreStateV1,
}

pub struct RecoveryRequestV1 {
    pub public: CommonLifecyclePublicInputV1,
    pub authorization: ApprovedRecoveryAuthorizationV1,
    pub replacement_client: ClientRecipientV1,
}

pub struct RefreshRequestV1 {
    pub public: CommonLifecyclePublicInputV1,
    pub authorization: ApprovedRefreshAuthorizationV1,
    pub next_role_epochs: NextRoleEpochsV1,
}

pub struct ExportRequestV1 {
    pub public: CommonLifecyclePublicInputV1,
    pub authorization: ApprovedExportAuthorizationV1,
    pub recipient: ClientRecipientV1,
}

pub struct UnregisteredPreStateV1 {
    pub scope: PublicIdentityScopeV1,
}

pub struct RegisteredPreStateV1 {
    pub identity: RegisteredEd25519IdentityV1,
    pub current_role_epochs: CurrentRoleEpochsV1,
}

pub enum PendingActivationPreStateV1 {
    Registration(RegistrationPendingActivationV1),
    Recovery(RecoveryPendingActivationV1),
    Refresh(RefreshPendingActivationV1),
}

pub struct RegistrationSuccessV1 {
    pub post_state: RegistrationPendingActivationV1,
    pub outputs: ReferenceActivationFamilyOutputsV1,
    pub leakage: ActivationFamilyPublicLeakageV1,
}

pub struct ActivationSuccessV1 {
    pub post_state: ActivatedRegisteredStateV1,
    pub signing_worker: SigningWorkerActivatedOutputV1,
    pub router: RouterActivationReceiptV1,
    pub client: NoNewClientSecretOutputV1,
    pub deriver_a: NoDeriverInvocationV1,
    pub deriver_b: NoDeriverInvocationV1,
    pub leakage: ActivationPublicLeakageV1,
}

pub struct RecoverySuccessV1 {
    pub post_state: RecoveryPendingActivationV1,
    pub outputs: ReferenceActivationFamilyOutputsV1,
    pub leakage: ActivationFamilyPublicLeakageV1,
}

pub struct RefreshSuccessV1 {
    pub post_state: RefreshPendingActivationV1,
    pub outputs: ReferenceActivationFamilyOutputsV1,
    pub leakage: ActivationFamilyPublicLeakageV1,
}

pub struct ExportSuccessV1 {
    pub retained_state: RegisteredPreStateV1,
    pub consumed_authorization: ConsumedExportAuthorizationV1,
    pub outputs: ReferenceExportOutputsV1,
    pub leakage: ExportPublicLeakageV1,
}

pub enum ReferenceLifecycleSuccessV1 {
    Registration(RegistrationSuccessV1),
    Activation(ActivationSuccessV1),
    Recovery(RecoverySuccessV1),
    Refresh(RefreshSuccessV1),
    Export(ExportSuccessV1),
}
```

`ActivationRequestV1` has no Deriver contribution, output-randomness, export
authorization, or seed field. `ExportSuccessV1` has no activation-family output,
SigningWorker output, or client scalar output. The output types below enforce
those rules.

```rust
pub struct ReferenceActivationFamilyOutputsV1 {
    pub deriver_a: DeriverAActivationSharesV1,
    pub deriver_b: DeriverBActivationSharesV1,
    pub client_deliverable: ClientScalarDeliverableV1,
    pub signing_worker_deliverable: SigningWorkerScalarDeliverableV1,
    pub public_receipt: ActivationFamilyPublicReceiptV1,
}

pub struct ReferenceExportOutputsV1 {
    pub deriver_a: DeriverASeedExportShareV1,
    pub deriver_b: DeriverBSeedExportShareV1,
    pub client: AuthorizedClientSeedOutputV1,
    pub router: RouterExportRelayViewV1,
    pub signing_worker: NoSigningWorkerExportOutputV1,
    pub public_receipt: ExportPublicReceiptV1,
}
```

These aggregate `Reference*` types belong only in the host generator and formal
model. A production role API MUST expose one role-specific view and MUST NOT
construct an aggregate containing all parties' inputs or outputs.

### 7.2 Function signatures

Separate function signatures keep each pre-state narrow:

```rust
pub fn evaluate_registration_v1(
    pre: UnregisteredPreStateV1,
    request: RegistrationRequestV1,
    inputs: RegistrationReferenceInputsV1,
) -> ReferenceLifecycleResultV1<RegistrationSuccessV1>;

pub fn evaluate_activation_v1(
    request: ActivationRequestV1,
) -> ReferenceLifecycleResultV1<ActivationSuccessV1>;

pub fn evaluate_recovery_v1(
    pre: RegisteredPreStateV1,
    request: RecoveryRequestV1,
    inputs: RecoveryReferenceInputsV1,
) -> ReferenceLifecycleResultV1<RecoverySuccessV1>;

pub fn evaluate_refresh_v1(
    pre: RegisteredPreStateV1,
    request: RefreshRequestV1,
    inputs: RefreshReferenceInputsV1,
) -> ReferenceLifecycleResultV1<RefreshSuccessV1>;

pub fn evaluate_export_v1(
    pre: RegisteredPreStateV1,
    request: ExportRequestV1,
    inputs: ExportReferenceInputsV1,
) -> ReferenceLifecycleResultV1<ExportSuccessV1>;
```

`RecoveryReferenceInputsV1` and `RefreshReferenceInputsV1` MUST remain
undefined until Sections 12.1 and 12.2 close. `RegistrationReferenceInputsV1`
may wrap the current synthetic A/B contributions for arithmetic fixtures. Its
production-provenance member remains undefined until Section 12.3 closes.

## 8. Common output sharing

Registration, recovery, and refresh conceptually sample independent output
sharing randomness for each scalar output:

```text
R_client <- Z_l
client_A = R_client
client_B = x_client_base - R_client mod l

R_server <- Z_l
server_A = R_server
server_B = x_server_base - R_server mod l
```

Export samples:

```text
U <- Z_(2^256)
d_A = U
d_B = d - U mod 2^256
```

Evidence: `docs/yaos-ab.md:361-403`. The coins belong to the ideal
functionality. Neither Deriver supplies them as a freely chosen linear mask.
Synthetic fixtures may record deterministic reference coins under an explicit
`host_only_reference_randomness` field. Party views contain only the coins or
shares visible to that party.

The active realization of these samples, private output translation,
authentication, encryption, and anti-equivocation remains blocked by Section
12.4.

## 9. Five lifecycle functionality contracts

### 9.1 `F_ed25519_registration_v1`

Precondition:

- the public identity scope has no registered Ed25519 key;
- the request kind is `registration`;
- activation recipients identify one client and one SigningWorker;
- role inputs are fresh and bound to the frozen stable context;
- the admission and registration authorization boundary has accepted the
  request.

Reference computation:

1. Evaluate the frozen four-`y`, four-`tau` arithmetic.
2. Establish one new `A_pub`.
3. Sample independent client and SigningWorker output shares.
4. Produce role-private shares, recipient deliverables, and an
   activation-family public receipt.
5. Commit a `RegistrationPendingActivationV1` state.

Success outputs:

- Deriver A sees only A inputs and A randomized scalar shares;
- Deriver B sees only B inputs and B randomized scalar shares;
- Router sees opaque client and SigningWorker ciphertext metadata plus public
  receipt data;
- the client deliverable opens only to `x_client_base`;
- the SigningWorker deliverable opens only to `x_server_base`;
- public observers see only common public leakage.

Identity invariant: success establishes exactly one new `A_pub`. Registration
has no pre-existing public-key equality precondition. Evidence:
`docs/yaos-ab.md:345-359` and `docs/router-a-b-SPEC.md:908-920`.

Production root custody, the provenance proof, and the anti-bias rule are
blockers. A complete registration evaluator and lifecycle fixture cannot ship
before Section 12.3 closes.

### 9.2 `F_ed25519_activation_v1`

Precondition:

- the request kind is `activation`;
- the pending state originated from registration, recovery, or refresh;
- the package set is committed, unconsumed, recipient-bound, transcript-bound,
  and identity/epoch-consistent;
- the selected SigningWorker matches the pending state's fixed recipient.

Reference computation:

1. Verify the pending public receipt and package references.
2. Let SigningWorker verify and combine only its two server-recipient shares.
3. Require the resulting point and registered identity relation.
4. Consume the pending activation state.
5. Record `ActivatedRegisteredStateV1` and a public activation receipt.

The function performs zero Deriver invocations, zero contribution derivations,
zero output-share sampling, and zero Yao evaluations. It emits no new client
secret. Evidence: `docs/router-a-b-SPEC.md:916-920` and
`docs/yaos-ab.md:329-333`.

Identity invariant: the registered `A_pub` is unchanged. SigningWorker accepts
only its current recipient identity and activation epoch
(`docs/router-a-b-SPEC.md:116-127`).

### 9.3 `F_ed25519_recovery_v1`

Precondition:

- a registered identity exists;
- the request kind is `recovery`;
- approved recovery authorization names the registered identity and replacement
  client recipient;
- the continuity mechanism proves preservation of the registered seed-derived
  identity without seed export.

Frozen success boundary:

- produce fresh client and SigningWorker activation-family deliverables;
- commit `RecoveryPendingActivationV1` for a fresh activation epoch;
- reveal no seed share, joined seed, or scalar `a`;
- preserve `d` and `A_pub` byte-for-byte.

Evidence: `docs/router-a-b-SPEC.md:908-925`,
`docs/router-a-b-sol-refactor.md:1068-1074`, and
`docs/yaos-ab.md:345-359`.

The actual recovery transition is BLOCKED. The current documents do not define
how a replacement credential or client root preserves `d` without
reconstruction. No recovery evaluator, success corpus entry, or continuity proof
may claim completion before Section 12.1 closes.

### 9.4 `F_ed25519_refresh_v1`

Precondition:

- a registered identity exists;
- the request kind is `refresh`;
- both current role epochs match the registered state;
- an approved refresh transition names the next role epochs;
- the resharing mechanism proves preservation of joined `y` and joined `tau`.

Frozen success boundary:

- replace role-local shares and epochs;
- prepare next-epoch activation-family deliverables;
- preserve joined `y`, joined `tau`, `d`, `a`, `x_client_base`,
  `x_server_base`, and `A_pub`;
- reject the old epoch after successful cutover;
- reveal no seed share, joined seed, or scalar `a`.

Preservation of `x_client_base` and `x_server_base` follows algebraically from
the frozen preservation of `d` and `tau`. The normative identity requirements
are at `docs/yaos-ab.md:340-353` and
`docs/router-a-b-sol-refactor.md:119-128,313-340`. Old-epoch rejection appears in
`docs/router-a-b-sol-refactor.md:1068-1075`.

The refresh transition is BLOCKED on the exact resharing protocol, recipient
set, SigningWorker acknowledgement boundary, failure rollback behavior, and
atomic old/new epoch cutover. See Section 12.2.

### 9.5 `F_ed25519_export_v1`

Precondition:

- a registered identity exists;
- the request kind is `export`;
- explicit step-up authorization binds wallet/key identity, operation, client
  recipient key, transcript, expiry, and one-use nonce;
- each Deriver independently accepts that authorization.

Reference computation:

1. Evaluate only the seed-export projection for the registered role inputs.
2. Sample `U` and form `d_A`, `d_B` modulo `2^256`.
3. Address both authenticated seed-share deliverables to the authorized client.
4. Let the client reconstruct `d`, derive `a` and `A_pub`, and compare `A_pub`
   with the registered identity.
5. Consume the export authorization after output release, including delivery or
   client-import failure after release.

Success reveals `d` only to the authorized client. The client may derive `a`
from that seed. Router receives opaque export ciphertexts and public receipt
metadata. SigningWorker receives no export output. Each Deriver receives only
its randomized seed share and never the joined seed.

Evidence: `docs/router-a-b-sol-refactor.md:160-170`,
`docs/router-a-b-SPEC.md:638-658,681-715`, and
`docs/yaos-ab.md:297-333,390-403,456-458`.

Export MUST NOT contain activation-family client shares, SigningWorker shares,
or a SigningWorker recipient. Registration, activation, recovery, and refresh
MUST NOT contain seed wires, seed-share outputs, or export authorization.

## 10. Uniform abort envelope

All five functions use one result shape:

```rust
pub type ReferenceLifecycleResultV1<S> = Result<S, UniformLifecycleAbortV1>;

pub struct UniformLifecycleAbortV1 {
    pub request_kind: LifecycleRequestKindV1,
    pub public_transcript_digest: TranscriptDigest32,
    pub public_failure_code: RedactedFailureCodeV1,
    pub terminal: AbortedTerminalStateV1,
}
```

The abort envelope MUST contain public metadata only. It has no role id naming a
suspected corrupt party, private validation detail, peer frame, package
plaintext, contribution, share, seed, scalar, label, mask, OT value, or secret
digest. A redacted failure-code registry may distinguish public boundary classes
such as expiry or replay only after review. Its encoding is not frozen here.

Router faults such as denial, stale routing, replay, or incomplete delivery must
be detectable (`docs/router-a-b-SPEC.md:746-759`). Malicious A or B behavior must
produce a valid authenticated output or a uniform detectable abort
(`docs/router-a-b-SPEC.md:761-772`). Timeout, crash, cancellation, peer
uncertainty, malformed input, partial send, and rollback destroy one-use material
(`docs/yaos-ab.md:789-854`).

The ideal model freezes the envelope and its forbidden contents. Exact timing,
active-protocol abort points, selective-failure independence, and failure-code
equivalence remain Section 12.4 blockers.

## 11. Fixture and test strategy

### 11.1 Preserve the arithmetic corpus

Keep `vectors/ed25519-yao-v1.json` as a host-only clear-arithmetic corpus. Its
`clear_reference_trace` continues to contain joined synthetic values for
differential implementations. No party-view test may treat that trace as a
protocol output.

### 11.2 Add a separate lifecycle corpus

Create a separately versioned lifecycle corpus after the applicable blockers
close. Use a tagged union with five distinct DTOs:

```rust
pub enum LifecycleFixtureCaseV1 {
    Registration(RegistrationFixtureV1),
    Activation(ActivationFixtureV1),
    Recovery(RecoveryFixtureV1),
    Refresh(RefreshFixtureV1),
    Export(ExportFixtureV1),
}
```

Every fixture contains:

- exact pre-state;
- branch-specific request;
- host-only reference inputs and coins when the function evaluates arithmetic;
- branch-specific success or the common uniform abort;
- post-state;
- separate Client, Router, Deriver A, Deriver B, SigningWorker, observer, and log
  views;
- common public leakage;
- a host-only clear trace stored outside all party views;
- explicit evaluation counters.

Activation fixtures MUST set Deriver invocations and Yao evaluations to zero.
They reference committed output digests from a registration, recovery, or refresh
fixture. They contain no `VectorInputsV1` and no output-sharing randomness.

Recovery success fixtures remain absent until recovery preservation is defined.
Refresh success fixtures remain absent until refresh cutover is defined. Record
the blockers in documentation rather than serializing placeholder or
`unsupported` success variants.

### 11.3 Required positive fixtures

Once unblocked, add:

- registration from an unregistered state through pending activation;
- activation of a registration-origin pending package set;
- activation of recovery-origin and refresh-origin pending package sets;
- recovery before/after continuity with identical `d` and `A_pub`;
- refresh before/after continuity with identical joined `y`, joined `tau`, `d`,
  `a`, scalar bases, points, and `A_pub`;
- export whose reconstructed `d` reproduces the registered public key and RFC
  8032 signature behavior;
- exact encrypted-package redelivery with zero cryptographic reevaluation.

### 11.4 Required rejection and static fixtures

Add serde rejection tests and compile-fail examples for:

- export seed fields in registration, activation, recovery, or refresh;
- client or SigningWorker scalar outputs in export;
- Deriver contributions or output randomness in activation;
- activation of an export result;
- wrong origin, request kind, recipient, registered identity, root epoch, role
  epoch, transcript digest, package digest set, or activation epoch;
- recovery mapped to export;
- registration requiring a pre-existing public key;
- refresh that changes joined `y`, joined `tau`, `d`, or `A_pub`;
- export that reconstructs a public key different from the registered identity;
- unknown JSON fields, optional secret fields, and broad generic lifecycle
  constructors.

The fixture decoder validates raw JSON once and returns the precise tagged type.
Core evaluators never accept a raw string, partial record, or untagged property
bag.

### 11.5 Party-view assertions

For each complete fixture, assert:

- the Router and observer views equal declared public leakage plus opaque bytes;
- A's view contains no B input or joined output;
- B's view contains no A input or joined output;
- the client view contains `x_client_base` only for activation-family delivery
  and `d` only for export;
- the SigningWorker view contains `x_server_base` only after activation;
- every non-export view is structurally incapable of carrying a seed;
- every log and abort view excludes host-only trace values;
- changing an honest role's private input while holding public leakage fixed does
  not change the other role's declared ideal view, subject to the selected
  active-security model.

The final assertion becomes executable only after the active construction and
corruption games are defined.

## 12. Explicit blockers

### 12.1 Recovery preservation

`docs/yaos-ab.md:355-359` explicitly blocks recovery until the design explains
how a replacement credential or client root preserves `d` without
reconstruction. Required decisions:

- which role-local client and server contributions persist or change;
- how a new credential binds to existing seed-preserving state;
- how both Derivers prove continuity to the registered identity;
- which old credential and material state becomes invalid, and when;
- failure and rollback behavior around the later activation continuation.

No executable `RecoveryReferenceInputsV1` or successful recovery vector is
valid before these decisions are reviewed.

### 12.2 Refresh resharing and cutover

The invariant is frozen. The transition mechanics remain incomplete. Required
decisions:

- whether this request refreshes root shares, account contributions,
  SigningWorker shares, or one exact combined operation;
- exact preservation proof for joined `y` and joined `tau`;
- whether the client always receives a next-epoch package;
- the SigningWorker acknowledgement required before completion;
- atomic activation of the new epoch and rejection of the old epoch;
- retry, rollback, partial failure, and crash semantics.

Evidence for the current ambiguity spans the root-share flow at
`docs/router-a-b-SPEC.md:533-553`, activation-family refresh at
`docs/yaos-ab.md:340-353`, and recipient wording at
`docs/router-a-b-sol-refactor.md:1068-1075`.

### 12.3 Role-input provenance, root custody, and registration anti-bias

The stable-context and contribution-KDF bytes are frozen in the host reference
under `docs/yaos-ab.md` **Stable Key Context and Ceremony Context**. Production
root custody and input provenance remain open. Active 2PC alone proves a
computation over supplied inputs; it does not prove that those inputs match the
provisioned roots described under **Input Provenance**. Required decisions:

- the upstream Yao-only application-binding digest preimage and normalization;
- protected production root representations and role-local invocation APIs;
- proof statements connecting each frozen KDF output to its provisioned root;
- root, wallet/key, path, epoch, request, envelope, and authorization bindings;
- registration anti-bias mechanism and acceptance rule;
- recovery and refresh continuity proof statements.

Synthetic raw contributions remain valid clear-arithmetic test inputs. They are
not production provenance evidence.

### 12.4 Exact active protocol and private outputs

The ideal random-sharing distribution is frozen in Section 8. Its realization
remains blocked on selection and review of:

- malicious-secure OT and consistency checks;
- garbling correctness and input consistency;
- protocol-generated unbiased output randomness;
- two-sided private output translation;
- active-output authentication and anti-equivocation;
- recipient encryption and exact signed receipt bytes;
- selective-failure-resistant uniform abort behavior;
- one-use preprocessing, stream, persistence, and crash state machines.

These are production capabilities at `docs/yaos-ab.md:909-959`. This reference
boundary supplies no evidence for them.

## 13. Alignment and readiness

| Requirement                               | Current code status                                                                    | Classification       | Confidence |
| ----------------------------------------- | -------------------------------------------------------------------------------------- | -------------------- | ---------- |
| Five disjoint request tags                | `fixtures.rs:61-75,89-112`                                                             | full for tags        | 1.00       |
| Export-only seed result                   | `fixtures.rs:152-160`; `lib.rs:435-470`                                                | full for oracle DTOs | 1.00       |
| Five disjoint prestates and transitions   | lifecycle semantics expressly excluded by `fixtures.rs:89-93` and README lines 109-115 | missing in code      | 1.00       |
| Activation consumes committed packages    | current fixture builder evaluates arithmetic at `fixtures.rs:423-455`                  | missing in code      | 1.00       |
| Recovery remains distinct from export     | generator tag is distinct; legacy gate maps it to export at `protocol/gate.rs:33-40`   | integration mismatch | 1.00       |
| Recovery seed-preserving transition       | no executable input or transition type                                                 | blocked by spec      | 1.00       |
| Refresh identity-preserving transition    | arithmetic tag exists; no paired before/after state                                    | blocked/partial      | 0.98       |
| Complete party views and declared leakage | clear trace is explicitly host-only at `fixtures.rs:198-204`                           | missing in code      | 1.00       |
| Uniform lifecycle abort envelope          | oracle exposes only noncanonical tau input errors at `src/lib.rs:92-102`               | missing in code      | 0.99       |
| Active private randomized outputs         | no protocol implementation exists                                                      | intentionally absent | 1.00       |

The safe next implementation slice is limited to the common public/context
types, five disjoint request/pre-state/success DTO families, the zero-evaluation
activation continuation model, export/non-export structural rejection tests,
the public leakage DTOs, and the uniform abort envelope. Recovery and refresh
evaluators stop at their undefined reference-input types. Registration remains
an arithmetic reference until provenance and anti-bias close.

This document does not close Yao Phase 1 or FV0.
