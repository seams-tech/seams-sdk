# Ed25519 Yao Lifecycle Ideal-Functionality Boundary V1

Status: **Phase 1 partial freeze for the isolated host-only reference generator**

This document freezes the lifecycle and party-boundary facts that already have
normative support. It also records the decisions that still block executable
lifecycle functions. The five functions below are reference contracts for
`tools/ed25519-yao-generator`. They do not describe a deployed protocol, prove an
active Yao construction, or authorize Router, Cloudflare, SigningWorker, SDK, or
persistence integration.

Phase 1 remains open. The same-logical-root recovery transition and correlated
refresh algebra are frozen below. Production root custody, production refresh
delta generation, provenance artifacts and proofs, the registration anti-bias
mechanism, active-output integration, and the exact active protocol require
separate reviewed decisions.

## 1. Source authority and evidence baseline

The source precedence for this boundary is:

1. `docs/router-a-b-SPEC.md` owns product lifecycle, routing, transcript, and
   recipient behavior. See lines 5-11 and 902-925.
2. `docs/yaos-ab.md` owns the Ed25519 secure-computation backend, arithmetic,
   output custody, and active-security target. See **Document Authority and
   Resolved Conflicts**, **Goal**, and **Scope**.
3. `docs/router-a-b-sol-refactor.md` owns the wider cutover constraints and
   deletion plan. See **Goal**, **Executive Decisions**, and **Non-Negotiable
   Invariants**.
4. Current generator code supplies executable clear-arithmetic evidence only.
   Its README explicitly leaves lifecycle transitions, provenance, and
   active-protocol semantics open in the `lifecycle_reference` and lifecycle
   boundary paragraphs.

Current implementation facts:

- `LifecycleRequestKindV1` and `VectorCaseV1` already encode five disjoint tags
  at `tools/ed25519-yao-generator/src/fixtures.rs:64-112`.
- The existing vector union prevents an export result in a non-export branch at
  `tools/ed25519-yao-generator/src/fixtures.rs:101-112,152-160`.
- `ActivationOracleOutput` has no seed field while `ExportOracleOutput` requires
  one at `tools/ed25519-yao-generator/src/lib.rs:453-489`.
- The only executable functions are the shared clear-arithmetic activation and
  export projections at `tools/ed25519-yao-generator/src/lib.rs:501-522`.
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
- **Same-logical-root rewrap** means recovering the exact existing 32-byte client
  derivation root inside an authorized secret boundary and encrypting those same
  bytes under a replacement credential binding. It never changes the stable
  context or any KDF contribution.
- **Output committed** means both roles have signed the complete recipient-package
  digest set. From that point, the lifecycle advances forward or exactly
  redelivers those ciphertexts; it never re-evaluates the circuit or restores the
  preceding credential/share epoch.
- **Correlated refresh delta** means one nonzero `delta_y` in `Z_(2^256)` and one
  nonzero `delta_tau` in `Z_l`, added to A's effective role-local account
  contribution and subtracted from B's contribution.

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

The canonical byte and scalar rules and the four-`y` and four-`tau`
decomposition appear in the **Field and Byte Conventions** and **Stable Key
Context and Ceremony Context** sections of `docs/yaos-ab.md`. The public
relation is:

```text
X_client = x_client_base * B
X_server = x_server_base * B
A_pub    = a * B
2 * X_client - X_server = A_pub
```

Evidence: the **Protocol-Generated Output Sharing** section of
`docs/yaos-ab.md`. Export recomputes the registered identity from `d` as
required by that section.

## 4. Frozen lifecycle dispatch

Exactly five lifecycle request kinds exist:

| Request kind   | Ideal-function name         | Evaluation behavior                              |
| -------------- | --------------------------- | ------------------------------------------------ |
| `registration` | `F_ed25519_registration_v1` | one activation-family evaluation                 |
| `activation`   | `F_ed25519_activation_v1`   | consume committed packages; zero Yao evaluations |
| `recovery`     | `F_ed25519_recovery_v1`     | one activation-family evaluation                 |
| `refresh`      | `F_ed25519_refresh_v1`      | one activation-family evaluation                 |
| `export`       | `F_ed25519_export_v1`       | one export-family evaluation                     |

This mapping is fixed by `docs/router-a-b-SPEC.md:902-920` and the **Fixed
Circuit Families** section of `docs/yaos-ab.md`. A caller never supplies a
circuit or ideal-function identifier. Router derives both from the admitted
request kind.

Activation is an internal continuation. It consumes and verifies packages
created by registration, recovery, or refresh and never triggers another Yao
evaluation (`docs/router-a-b-SPEC.md:916-920`; `docs/yaos-ab.md`, **Fixed
Circuit Families**).

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
`StableKeyDerivationContextV1` (`docs/yaos-ab.md`, **Stable Key Context and
Ceremony Context**).

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

Evidence: the **Protocol-Generated Output Sharing** and **Payload Boundaries**
sections of `docs/yaos-ab.md`, Router-held values at
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

Evidence: `docs/router-a-b-SPEC.md:150-184,230-247,2849-2857` and the **Payload
Boundaries** section of `docs/yaos-ab.md`.

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

The custody rule is stated directly in the **Goal** section of `docs/yaos-ab.md`
and at `docs/router-a-b-SPEC.md:150-184`. Recipient opening is fixed at
`docs/router-a-b-SPEC.md:463-488,702-715`. Source-boundary prohibitions also
appear in the **Source And Bundle Guards** section of
`docs/router-a-b-sol-refactor.md`.

Client plus SigningWorker may reconstruct `a = 2*x_client_base -
x_server_base mod l`. That collusion is an explicit security exclusion
(`docs/yaos-ab.md`, **Explicit Exclusions**).

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

The source table appears in the **Fixed Circuit Families** section of
`docs/yaos-ab.md`. Fresh recovery and refresh recipient ciphertext requirements
come from `docs/router-a-b-SPEC.md:908-925`. Export authorization consumption
after release is fixed by the **Ed25519 Export** section of
`docs/router-a-b-sol-refactor.md`.

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
    pub replacement_credential: ReplacementCredentialBindingV1,
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
    pub active_client_root_binding: ActiveClientRootBindingV1,
    pub current_role_commitments: CurrentRoleContributionCommitmentsV1,
    pub active_activation_epoch: ActiveActivationEpochV1,
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

The recovery and refresh input shapes are frozen for the host-only reference:

```rust
pub struct RecoveryReferenceInputsV1 {
    pub current_client_root: HostOnlyClientDerivationRootV1,
    pub recovered_client_root: HostOnlyClientDerivationRootV1,
    pub current_deriver_a: DeriverAContribution,
    pub current_deriver_b: DeriverBContribution,
    pub output_sharing_coins: HostOnlyActivationOutputCoinsV1,
}

pub struct CorrelatedRefreshDeltaV1 {
    pub delta_y: NonzeroLe256V1,
    pub delta_tau: NonzeroCanonicalScalarV1,
}

pub struct RefreshReferenceInputsV1 {
    pub current_deriver_a: DeriverAContribution,
    pub current_deriver_b: DeriverBContribution,
    pub delta: CorrelatedRefreshDeltaV1,
    pub output_sharing_coins: HostOnlyActivationOutputCoinsV1,
}
```

The aggregate inputs and explicit coins exist only in the reference generator
and formal model. Production APIs expose one role-local view. The production
same-root witness, refresh-delta generation, contribution-state commitments, and
input-provenance proofs remain undefined until Sections 12.1 through 12.4 close
their remaining gates. `RegistrationReferenceInputsV1` may wrap the current
synthetic A/B contributions for arithmetic fixtures. Its production-provenance
member remains undefined until Section 12.3 closes.

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

Evidence: the **Protocol-Generated Output Sharing** section of
`docs/yaos-ab.md`. The coins belong to the ideal functionality. Neither Deriver
supplies them as a freely chosen linear mask.
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
has no pre-existing public-key equality precondition. Evidence: the **Fixed
Circuit Families** section of `docs/yaos-ab.md` and
`docs/router-a-b-SPEC.md:908-920`.

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
secret. Evidence: `docs/router-a-b-SPEC.md:916-920` and the **Fixed Circuit
Families** section of `docs/yaos-ab.md`.

Identity invariant: the registered `A_pub` is unchanged. SigningWorker accepts
only its current recipient identity and activation epoch
(`docs/router-a-b-SPEC.md:116-127`).

### 9.3 `F_ed25519_recovery_v1`

Precondition:

- a registered identity exists;
- the request kind is `recovery`;
- approved recovery authorization names the registered identity and replacement
  client recipient;
- the authorized recovery boundary can recover the exact existing logical client
  derivation root;
- the existing client derivation root is not classified as unavailable or
  compromised;
- both current role epochs, the active credential/root binding, and the active
  activation epoch match registered state.

An unavailable or suspected-compromised client derivation root fails this
functionality. The caller must enter an explicit wallet-rekey operation that
establishes a new Ed25519 identity. Version-one recovery has no compensating
root-replacement branch.

Reference computation:

1. Consume the one-use recovery authorization and suspend the old credential
   binding from new signing admission.
2. Require `recovered_client_root == current_client_root` inside the host-only
   reference boundary, then construct a replacement credential envelope around
   those exact root bytes.
3. Re-derive both role-separated client contributions under the unchanged stable
   context and require byte-for-byte equality with the current client
   contributions. Keep both Deriver roots and all effective server/account
   contributions unchanged.
4. Evaluate the activation-family function with fresh output-sharing coins and a
   fresh one-use ticket. Require byte-for-byte equality of `d`, `a`, `tau`, both
   scalar bases, both public points, and `A_pub` with registered state.
5. Persist the replacement credential binding, recipient packages, package
   digest set, and next activation epoch as `RecoveryPendingActivationV1`.
6. Let `F_ed25519_activation_v1` consume the committed SigningWorker packages.
   After its idempotent activation receipt, promote the replacement binding and
   next activation epoch and retain only a tombstone for the old credential
   binding.

Frozen success boundary:

- produce fresh client and SigningWorker activation-family deliverables;
- commit `RecoveryPendingActivationV1` for a fresh activation epoch;
- reveal no seed share, joined seed, or scalar `a`;
- preserve the logical client root, every KDF contribution, `d`, `a`, `tau`, both
  scalar bases, both public points, and `A_pub` byte-for-byte;
- reject the old credential and activation epoch after successful cutover.

Crash and retry semantics:

- Before the complete output-package digest set is committed by both roles, an
  abort destroys the pending ticket and staged packages. The old credential
  remains suspended, and retry requires fresh recovery authorization and a fresh
  ticket.
- `OutputCommitted` is the forward-only boundary. Delivery uncertainty permits
  exact ciphertext redelivery from the committed package set and no
  cryptographic re-evaluation.
- A crash after SigningWorker activation resumes from its idempotent signed
  receipt and completes the credential/epoch promotion. It never restores the
  old credential or activation epoch.

Evidence: `docs/router-a-b-SPEC.md:908-925`; the **Root And Key-Continuity
Policy** and **Flow Completion Matrix** sections of
`docs/router-a-b-sol-refactor.md`; and the **Stable Key Context and Ceremony
Context**, **Fixed Circuit Families**, **Frame Format**, and **Incremental
Evaluation** sections of `docs/yaos-ab.md`. The host-only arithmetic equality
witness is frozen. Its production proof and custody realization remain Section
12.1 and 12.3 gates.

### 9.4 `F_ed25519_refresh_v1`

Precondition:

- a registered identity exists;
- the request kind is `refresh`;
- both current role epochs match the registered state;
- an approved refresh transition names the next role epochs;
- both next role epochs strictly advance their corresponding current epochs;
- the stable derivation roots, stable context, and both client contributions stay
  unchanged;
- the host-only reference receives one nonzero canonical correlated refresh
  delta for each arithmetic domain.

At initial provisioning, each effective server/account contribution equals its
frozen role-local KDF output. A refresh updates that persisted effective
contribution while retaining its KDF provenance chain:

```text
effective_y_server_A_next = effective_y_server_A + delta_y mod 2^256
effective_y_server_B_next = effective_y_server_B - delta_y mod 2^256

effective_tau_server_A_next = effective_tau_server_A + delta_tau mod l
effective_tau_server_B_next = effective_tau_server_B - delta_tau mod l
```

The client contributions remain fixed. Therefore:

```text
y_A_next + y_B_next = y_A_current + y_B_current mod 2^256
tau_A_next + tau_B_next = tau_A_current + tau_B_current mod l
```

Reference computation:

1. Freeze new derivation ceremonies for the registered key and reserve one fresh
   one-use ticket at each role.
2. Apply the explicit correlated delta above and stage both next-epoch role-local
   contribution states. Neither next state is active yet.
3. Recompute the old and next joined reference traces and require equality of
   joined `y`, joined `tau`, `d`, `a`, `x_client_base`, `x_server_base`,
   `X_client`, `X_server`, and `A_pub`.
4. Evaluate the activation-family function over the next-epoch inputs with fresh
   output-sharing coins. Both roles prepare their recipient packages and sign the
   complete package-digest set.
5. Advance from `Prepared` to `OutputCommitted` only after both role prepare
   receipts agree on the wallet/key identity, current and next role epochs,
   circuit/transcript identity, recipient set, and complete package-digest set.
6. Let `F_ed25519_activation_v1` consume the committed SigningWorker packages.
   Its idempotent acknowledgement advances the cutover to `WorkerActivated`.
7. Commit both next role epochs, retire both old role epochs, retain old-epoch
   tombstones, and unfreeze derivation admission. Admission rejects either old
   role epoch after this commit.

Frozen success boundary:

- replace role-local shares and epochs;
- prepare next-epoch activation-family deliverables;
- preserve joined `y`, joined `tau`, `d`, `a`, `x_client_base`,
  `x_server_base`, and `A_pub`;
- reject the old epoch after successful cutover;
- reveal no seed share, joined seed, or scalar `a`.

Crash and retry semantics:

- Before `OutputCommitted`, an abort destroys the pending one-use ticket and
  staged next-epoch state; the current role epochs remain active.
- At and after `OutputCommitted`, the transition is forward-only. Ciphertext
  delivery uncertainty permits exact redelivery of the committed package set.
  Circuit re-evaluation, delta replacement, and rollback to the old role epochs
  are forbidden.
- A partial role cutover keeps derivation admission frozen. Recovery resumes from
  the signed prepare, output-commitment, and SigningWorker activation receipts
  until both roles record the same active next epoch.
- An uncertain pre-commit ticket is destroyed. A retry uses a fresh authorization,
  delta, transcript, and ticket.

Preservation of `x_client_base` and `x_server_base` follows algebraically from
the frozen preservation of `d` and `tau`. The normative identity requirements
are in the **Fixed Circuit Families** section of `docs/yaos-ab.md` and the
**Canonical Ed25519 Identity** and **Root And Key-Continuity Policy** sections of
`docs/router-a-b-sol-refactor.md`. The latter also fixes old-epoch rejection.

These semantics target the approved static-corruption model. They make no
proactive or mobile-adversary healing claim. Both roles can derive the correlated
delta from their own signed update, so any sequential-compromise claim requires a
separately reviewed corruption schedule and verified-erasure model. The current
security target explicitly excludes that stronger claim in the **Security
Target** section of `docs/router-a-b-sol-refactor.md` and the **Explicit
Exclusions** section of `docs/yaos-ab.md`.

Production delta generation, active proof of old/new input provenance, private
output integration, and distributed persistence realization remain Section 12.2
through 12.4 gates.

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

Evidence: the **Ed25519 Export** section of
`docs/router-a-b-sol-refactor.md`, `docs/router-a-b-SPEC.md:638-658,681-715`,
and the **Fixed Circuit Families** and **Protocol-Generated Output Sharing**
sections of `docs/yaos-ab.md`.

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
uncertainty, malformed input, partial send, and rollback destroy one-use
material (`docs/yaos-ab.md`, **Frame Format** and **Incremental Evaluation**).

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

Recovery and refresh success fixtures may now implement the frozen host-only
semantics. They use exact root equality and explicit synthetic refresh deltas;
they carry no placeholder or `unsupported` success variant. These fixtures are
reference evidence only. They do not satisfy the production provenance,
delta-generation, active-output, or distributed-cutover gates.

### 11.3 Required positive fixtures

Once unblocked, add:

- registration from an unregistered state through pending activation;
- activation of a registration-origin pending package set;
- activation of recovery-origin and refresh-origin pending package sets;
- recovery rewrapping the same logical root under a different credential binding,
  with identical KDF contributions, `d`, `a`, `tau`, scalar bases, points, and
  `A_pub`;
- recovery cutover suspending and then tombstoning the old credential binding;
- refresh before/after continuity with identical joined `y`, joined `tau`, `d`,
  `a`, scalar bases, points, and `A_pub`;
- refresh applying opposite nonzero deltas, advancing both role epochs, and
  rejecting both old epochs after cutover;
- export whose reconstructed `d` reproduces the registered public key and RFC
  8032 signature behavior;
- exact encrypted-package redelivery with zero cryptographic reevaluation after
  recovery and refresh output commitment;
- pre-commit recovery and refresh aborts that destroy pending one-use material;
- post-commit recovery and refresh crashes that resume forward from signed
  receipts.

### 11.4 Required rejection and static fixtures

Add serde rejection tests and compile-fail examples for:

- export seed fields in registration, activation, recovery, or refresh;
- client or SigningWorker scalar outputs in export;
- Deriver contributions or output randomness in activation;
- activation of an export result;
- wrong origin, request kind, recipient, registered identity, root epoch, role
  epoch, transcript digest, package digest set, or activation epoch;
- recovery mapped to export;
- recovery with a changed, unavailable, or suspected-compromised client root;
- recovery that leaves the old credential binding sign-capable after admission;
- recovery rollback or circuit re-evaluation after output commitment;
- registration requiring a pre-existing public key;
- refresh that changes joined `y`, joined `tau`, `d`, or `A_pub`;
- refresh with a zero, noncanonical, same-sign, or mismatched-domain delta;
- refresh that changes the stable context, a derivation root, or a client
  contribution;
- refresh rollback, delta replacement, or circuit re-evaluation after output
  commitment;
- refresh admission using either retired old role epoch;
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

## 12. Frozen recovery and refresh decisions with remaining blockers

### 12.1 Recovery preservation proof and custody

The version-one semantic choice is frozen: recovery rewraps the exact same
logical client derivation root. It changes the credential binding and activation
epoch while preserving the stable context, client KDF contributions, effective
server/account contributions, joined values, signing bases, and public identity.
An unavailable or suspected-compromised client root requires explicit wallet
rekey. Compensating client-root replacement is outside version one.

The host-only reference proves continuity through exact root and contribution
equality. Production remains BLOCKED until review selects:

- the protected boundary that opens the old recovery envelope and creates the new
  credential envelope around the same root bytes;
- the proof binding the replacement credential envelope to the same logical root
  and both frozen role-separated client KDF contributions;
- role-local commitments proving the Deriver inputs and effective account
  contributions match current registered state and epochs;
- exact signed receipt bytes and persistence transactions for credential
  suspension, output commitment, activation, promotion, and old-binding
  tombstones.

Successful host-only recovery vectors and a deterministic reference evaluator
may land before that production proof. They MUST label exact root comparison and
all aggregate inputs as host-only evidence.

### 12.2 Refresh delta generation, proof, and distributed cutover

The version-one reference transform and cutover semantics are frozen in Section
9.4. The reference takes explicit nonzero `delta_y` and `delta_tau`, applies them
with opposite signs to the effective A/B server/account contributions, advances
both role epochs, and models the following monotonic transition:

```text
Active(current)
  -> Prepared(current, next)
  -> OutputCommitted(current, next, package_digest_set)
  -> WorkerActivated(current, next, activation_receipt)
  -> Active(next) + RetiredTombstone(current)
```

`OutputCommitted` is the point of no return. Earlier aborts discard the pending
next epoch and retain the current epoch. Later crashes resume forward through
exact ciphertext redelivery and idempotent signed receipts. Derivation admission
stays frozen during a partial cutover, and the committed transition rejects both
old role epochs.

Production remains BLOCKED until review selects and verifies:

- protocol-generated joint delta generation with correctness-with-abort and no
  client or Router control over either delta;
- input commitments proving each old contribution belongs to the current epoch
  and each new contribution is the exact signed-delta update;
- active-circuit or equivalent proof that old and next joined `y` and `tau` are
  equal without opening either joined value;
- authenticated binding between next contribution state, recipient packages,
  active outputs, and the complete package-digest set;
- concrete role-local durable transactions, cutover certificates, erasure, and
  crash recovery across independent deployments.

Evidence for the current ambiguity spans the root-share flow at
`docs/router-a-b-SPEC.md:533-553`, activation-family refresh in the **Fixed
Circuit Families** section of `docs/yaos-ab.md`, and the **Root And
Key-Continuity Policy** of `docs/router-a-b-sol-refactor.md`.

The security claim remains static corruption. This transition invalidates stale
role-share epochs and shortens retained-state cryptoperiods. It supplies no
mobile-adversary or sequential-compromise healing claim. Such a claim requires a
reviewed erasure model, corruption schedule, and refresh proof beyond this
reference functionality.

### 12.3 Role-input provenance, root custody, and registration anti-bias

The application binding, stable context, and contribution-KDF bytes are frozen
in the host reference under `docs/yaos-ab.md` **Stable Key Context and Ceremony
Context**. `docs/input-provenance-v1.md` freezes a proof-system-neutral outer
statement, A/B pair invariants, root/input-state epoch meanings, lifecycle
evidence slots, and registration anti-bias acceptance requirements. Production
root custody and proof realization remain open. Active 2PC proves a computation
over supplied inputs; it does not establish that those inputs match the
provisioned roots described under **Input Provenance**. Required decisions are:

- protected production root representations and role-local invocation APIs;
- hiding and binding artifact suites plus proof statements connecting each
  frozen KDF output to its provisioned root;
- canonical ceremony, authorization, root-record, and role-input-state bytes;
- registration anti-bias mechanism and retry/acceptance state machine;
- protected same-root recovery proof and joint refresh-delta proof;
- active-protocol composition binding accepted provenance to exact input wires.

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

These are production capabilities in the **Production Capabilities** section of
`docs/yaos-ab.md`. This reference boundary supplies no evidence for them.

## 13. Alignment and readiness

| Requirement                               | Current code status                                                                  | Classification        | Confidence |
| ----------------------------------------- | ------------------------------------------------------------------------------------ | --------------------- | ---------- |
| Five disjoint request tags                | `fixtures.rs:64-75,101-112`                                                          | full for tags         | 1.00       |
| Export-only seed result                   | `fixtures.rs:152-160`; `lib.rs:453-489`                                              | full for oracle DTOs  | 1.00       |
| Five disjoint prestates and transitions   | lifecycle semantics expressly excluded by the README lifecycle-boundary paragraph    | missing in code       | 1.00       |
| Activation consumes committed packages    | current fixture builder evaluates arithmetic at `fixtures.rs:423-455`                | missing in code       | 1.00       |
| Recovery remains distinct from export     | generator tag is distinct; legacy gate maps it to export at `protocol/gate.rs:33-40` | integration mismatch  | 1.00       |
| Recovery seed-preserving transition       | same-root KDF/identity continuity test in `lifecycle_reference.rs`                   | partial host evidence | 1.00       |
| Refresh identity-preserving transition    | explicit opposite-delta continuity test in `lifecycle_reference.rs`                  | partial host evidence | 1.00       |
| Complete party views and declared leakage | clear trace is explicitly host-only at `fixtures.rs:198-204`                         | missing in code       | 1.00       |
| Uniform lifecycle abort envelope          | oracle exposes only noncanonical tau input errors at `src/lib.rs:112-135`            | missing in code       | 0.99       |
| Active private randomized outputs         | no protocol implementation exists                                                    | intentionally absent  | 1.00       |

The safe next implementation slice includes the common public/context types,
five disjoint request/pre-state/success DTO families, the zero-evaluation
activation continuation model, export/non-export structural rejection tests,
the public leakage DTOs, the uniform abort envelope, and committed recovery and
refresh lifecycle vectors. Recovery and refresh inputs remain host-only
synthetic evidence. Registration remains an arithmetic reference until its
provenance and anti-bias mechanism close. No production adapter, persistence
path, or security capability claim may land before Sections 12.1 through 12.4
close their production gates.

This document does not close Yao Phase 1 or FV0.
