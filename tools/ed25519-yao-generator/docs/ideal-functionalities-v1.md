# Ed25519 Yao Lifecycle Ideal-Functionality Boundary V1

Status: **Phase 1 partial freeze with executable host-only structural and
continuity evidence**

This document freezes the lifecycle and party-boundary facts that already have
normative support. It also records the decisions that still block executable
lifecycle functions. The five functions below are reference contracts for
`tools/ed25519-yao-generator`. They do not describe a deployed protocol, prove an
active Yao construction, or authorize Router, Cloudflare, SigningWorker, SDK, or
persistence integration.

Phase 1 remains open. The same-logical-root recovery transition and correlated
refresh algebra are frozen below. Production root custody, production refresh
delta generation, profile-required provenance artifacts or proofs, the selected
registration input-selection contract, private-output integration, and the
exact P0-P3 protocol require separate reviewed decisions.

## 1. Source authority and evidence baseline

The source precedence for this boundary is:

1. `docs/router-a-b-SPEC.md` owns product lifecycle, routing, transcript, and
   recipient behavior. See lines 5-11 and 902-925.
2. `docs/yaos-ab.md` owns the Ed25519 secure-computation backend, arithmetic,
   output custody, and P0-P3 security target. See **Document Authority and
   Resolved Conflicts**, **Goal**, and **Scope**.
3. `docs/router-a-b-sol-refactor.md` owns the wider cutover constraints and
   deletion plan. See **Goal**, **Executive Decisions**, and **Non-Negotiable
   Invariants**.
4. Current generator code supplies executable clear arithmetic, a
   nonserializable lifecycle ownership and persistence-projection layer, narrow
   host lifecycle-continuity evidence, and profile-neutral semantic
   package/receipt bodies. Its README explicitly leaves production lifecycle
   evaluators, durable persistence, authenticated provenance, package opening,
   worker activation, and selected-protocol semantics open.

Current implementation facts:

- The serde-enabled `CeremonyRequestKindV1` is the single canonical five-branch
  request discriminant; `VectorCaseV1` uses it directly in
  `tools/ed25519-yao-generator/src/fixtures.rs:74-120`.
- The existing vector union prevents an export result in a non-export branch at
  `tools/ed25519-yao-generator/src/fixtures.rs:74-120`.
- `ActivationOracleOutput` has no seed field while `ExportOracleOutput` requires
  one at `tools/ed25519-yao-generator/src/lib.rs:590-626`.
- `lifecycle_domain.rs` owns canonical branch requests, a non-`Clone`
  `RegisteredLifecyclePreStateV1`, crate-private registered-state provenance
  bridges, move-owned issuance and semantic sessions, evaluation-burn audit
  identities, origin-typed output-committed activation states, retry-preserving
  activation control, and metadata-consumed state projections. Registered
  state is compared with recovery, refresh, or export provenance before host
  evaluation; refresh also checks current and proposed role-input-state epochs.
- `lifecycle_persistence.rs` implements nonserializable digest-only
  `OutputCommitted`, rejected-attempt self-loop, and `MetadataConsumed`
  projections. These values define construction-independent persistence states;
  they are not durable records or transactions.
- `lifecycle_fixtures.rs` owns a separate strict six-case continuity corpus:
  synthetic registration-candidate metadata, first activation, recovery,
  recovery-origin activation, refresh, and refresh-origin activation. Rust and
  an independent standard-library Python verifier reproduce its complete
  relation. The registration snapshot represents no registration evaluator.
- Narrow registration, recovery, refresh, and export arithmetic/output-sharing
  references now exist outside the complete lifecycle contracts. Their semantic
  package descriptors and receipt bodies bind the exact ceremony/provenance DAG
  through move-only branch contexts that run host-reference preparation,
  output-sharing, and package construction in one call. No package API accepts a
  separately precomputed success. This closes call-local type-level
  ceremony/evaluation mixing; opaque provenance and evidence do not authenticate
  the supplied synthetic inputs. Complete registration, recovery, refresh,
  activation, and export evaluators, party views, selected cryptographic
  package/receipt bytes, durable persistence, selected-profile opening,
  production state promotion, recovery custody, atomic refresh cutover, and
  production custody remain blocked below. Separate profile-neutral host
  contracts now cover worker activation and authenticated refresh promotion.
- Every current non-export vector is a lifecycle-labelled arithmetic case. The
  builder calls `evaluate_activation` before branching on the lifecycle tag at
  `tools/ed25519-yao-generator/src/fixtures.rs:410-436`. Those cases are not
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
  independent of protected honest-party values. Exact selected-profile timing
  and any selective-failure proof required by the frozen claim remain blocked.
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

Activation has two public semantic contexts. The origin context remains bound to
the registration, recovery, or refresh package set. An origin-distinct
activation-control context carries a request id, replay nonce, request-context
digest, and transcript digest that each differ from the selected origin. It also
carries a derived selection of the origin transition, origin transcript,
package-set digest, and activation epoch. This is a pairwise comparison with the
selected origin. Global uniqueness and replay admission remain responsibilities
of the production request boundary. Package validation MUST compare package
metadata with the origin context.

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

The following pseudocode is normative for disjointness and ownership. The
nonserializable host-semantic implementation follows this separation while
using branch-specific public-input wrappers and origin-specific pending-state
internals. Boxing or internal wrapper choices do not change the required branch
boundaries. These are host model types, with no Serde or wire-encoding surface.

```rust
pub enum ReferenceLifecycleRequestV1 {
    Registration(RegistrationRequestV1),
    Activation(ActivationRequestV1),
    Recovery(RecoveryRequestV1),
    Refresh(RefreshRequestV1),
    Export(ExportRequestV1),
}

pub struct RegistrationRequestV1 {
    pub public: RegistrationPublicInputV1,
}

pub enum ActivationPackageOriginPublicInputV1 {
    Registration(RegistrationPublicInputV1),
    Recovery(RecoveryPublicInputV1),
    Refresh(RefreshPublicInputV1),
}

pub struct ActivationControlProposalFieldsV1 {
    request_id: PublicRequestIdV1,
    replay_nonce: PublicReplayNonceV1,
    request_expiry: PublicRequestExpiryV1,
    request_context_digest: PublicRequestContextDigestV1,
    transcript_digest: PublicTranscriptDigestV1,
}

pub struct PendingActivationSelectionV1 {
    origin_transition: ActivationTransitionRefV1,
    origin_transcript_digest: PublicTranscriptDigestV1,
    package_set_digest: PublicActivationPackageSetDigestV1,
    activation_epoch: ActivationEpochV1,
}

pub struct ActivationPublicInputV1 {
    common: CommonLifecyclePublicInputV1,
    selection: PendingActivationSelectionV1,
}

pub struct ActivationRequestV1 {
    public: ActivationPublicInputV1,
    pending: PendingActivationPreStateV1,
}

pub struct RejectedActivationControlProposalV1 {
    public_abort: UniformLifecycleAbortV1,
    pending: Box<PendingActivationPreStateV1>,
}

pub struct RecoveryRequestV1 {
    pub public: RecoveryPublicInputV1,
    pub authorization: ApprovedRecoveryAuthorizationV1,
    pub replacement_credential: ReplacementCredentialBindingV1,
}

pub struct RefreshRequestV1 {
    pub public: RefreshPublicInputV1,
    pub authorization: ApprovedRefreshAuthorizationV1,
    pub next_role_epochs: NextRoleEpochsV1,
}

pub struct ExportRequestV1 {
    pub public: ExportPublicInputV1,
    pub authorization: ApprovedExportAuthorizationV1,
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

pub struct RegistrationPendingActivationV1 {
    origin_public: RegistrationPublicInputV1,
    // candidate, recipients, transition, activation epoch, packages
}

pub struct RecoveryPendingActivationV1 {
    origin_public: RecoveryPublicInputV1,
    // current/staged state, recipients, transition, activation epoch, packages
}

pub struct RefreshPendingActivationV1 {
    origin_public: RefreshPublicInputV1,
    // current/staged state, recipients, transition, activation epoch, packages
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

The executable host scaffold exposes less authority than this ideal schema.
`RegisteredLifecyclePreStateV1::from_host_reference_store_projection`, the
registered-state extraction methods on `RoleInputProvenancePairV1`, every
`*ArtifactIssuanceV1`, and every `*ArtifactSessionV1` are crate-private.
Issuance consumes its state and one-use execution identity; recovery and refresh
also require strictly advancing epochs. Binding failure returns the owned request
and issuance before evaluation. If an admitted evaluation fails, it returns a
non-callable `BurnedArtifactAttemptV1` and any unchanged registered projection,
without returning the request. Success seals the origin request into
output-committed pending activation artifacts or a committed export value. None
of these host-only values establishes globally unique issuance or durable
storage.

The crate-private `ActivationRequestV1::new` consumes
`ActivationControlFreshFieldsV1` and an owned `PendingActivationPreStateV1`.
It derives the canonical activation request, authorization, transcript, and
validated DAG from the typed origin and committed artifact binding. Request id,
replay nonce, request-context digest, transcript nonce, and transcript digest
must each differ from the origin. Rejection returns a move-only
`RejectedActivationControlProposalV1` containing the exact pending state for
retry and one copyable public abort. Acceptance permits only crate-private
`consume_activation_metadata_v1`, which moves the artifacts into an
origin-preserving `MetadataConsumedActivationStateV1` with an exact
`ZeroReevaluationWitnessV1`. It does not open or verify recipient packages,
activate a SigningWorker, or promote registered identity, credential state,
role-input-state epochs, or any state version. Canonical ceremony bytes and
digests exist; expiry ordering, global replay admission, authenticated transport,
and production wire handling remain outside this host scaffold.

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

These are the complete ideal-function contracts. The current Rust slice keeps
`consume_activation_metadata_v1(ActivationRequestV1)` crate-private. It
validates and consumes synthetic metadata/control authority while retaining
origin-specific host-reference state; it does not open packages, combine
SigningWorker shares, promote state, or establish activation. The crate also
exposes
`prepare_host_only_registration_reference_v1` and
`evaluate_host_only_registration_output_sharing_v1`,
`prepare_host_only_recovery_reference_v1` and
`evaluate_host_only_recovery_output_sharing_v1`, plus
`prepare_host_only_refresh_reference_v1` and
`evaluate_host_only_refresh_output_sharing_v1`, plus
`prepare_host_only_export_reference_v1` and
`evaluate_host_only_export_output_sharing_v1`. Registration derives four
role/source-separated contribution pairs from three purpose-typed public
synthetic roots and the stable context, evaluates the seed-free activation
family, and applies typed scalar sharing. The recovery stages check exact
synthetic-root equality, stable-context client KDF re-derivation, current
client-contribution equality, and unchanged server contribution bytes. The
refresh stages consume move-owned role-local A/B ideal delta contributions,
derive their nonzero modular sum internally, keep all client bytes unchanged,
and check the exact positive A and inverse B server updates. Both operations check complete before/after
activation-oracle equality and typed scalar-share reconstruction from explicit
public fixture coins. Export checks the projection's public key against one
caller-supplied canonical expected key before typed seed sharing; its prepared
and success accessors expose neither the joined seed nor the oracle material.

The public host-reference arithmetic functions do not consume authorization,
bind an activation output to authenticated state or epochs, establish
unregistered admission, root/KDF provenance, or a registration input-selection
claim, realize a deployed joint refresh-delta protocol, or open and replace a credential
envelope. Crate-private lifecycle sessions construct profile-neutral semantic
package and receipt bodies plus digest-only persistence projections from
synthetic opaque evidence. They do not authenticate those evidence slots, write
durable state, perform cutover, consume a production export authorization, or
establish replay uniqueness. These functions are deliberately named outside
the complete `evaluate_registration_v1`, `evaluate_activation_v1`,
`evaluate_recovery_v1`, `evaluate_refresh_v1`, and `evaluate_export_v1`
contracts. Full activation and every complete lifecycle evaluator remain absent
until their respective blockers close.

The implemented preparation input shapes are frozen for the host-only
reference. Output-sharing coins enter only the separate consuming evaluation
functions:

```rust
pub struct HostOnlyRegistrationReferenceInputsV1<'a> {
    client_root: &'a SyntheticClientDerivationRootV1,
    deriver_a_root: &'a SyntheticDeriverADerivationRootV1,
    deriver_b_root: &'a SyntheticDeriverBDerivationRootV1,
    stable_context: &'a StableKeyDerivationContext,
}

pub struct HostOnlyRecoveryReferenceInputsV1<'a> {
    current_client_root: &'a SyntheticClientDerivationRootV1,
    recovered_client_root: &'a SyntheticClientDerivationRootV1,
    stable_context: &'a StableKeyDerivationContext,
    current_deriver_a: &'a DeriverAContribution,
    current_deriver_b: &'a DeriverBContribution,
}

pub struct HostOnlyRefreshReferenceInputsV1<'a> {
    current_deriver_a: &'a DeriverAContribution,
    current_deriver_b: &'a DeriverBContribution,
    delta_coins: HostOnlyJointRefreshDeltaCoinsV1,
}
```

The borrowed aggregate inputs, moved role-local refresh contributions, and
explicit output-sharing fixture coins
exist only in the reference generator and formal model. Production APIs expose
one role-local view. Production registration admission and root custody,
same-root recovery proof, refresh-delta generation, contribution-state
commitments, and profile-required input-provenance evidence remain undefined
until Sections 12.1 through 12.4 close their remaining gates.

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

The generator implements this deterministic reference in typed,
nonserializable activation and export APIs. The strict six-case corpus in
`docs/output-sharing-v1.md` covers zero, small, and wraparound coins and is
independently reproduced by Python. This evidence establishes the equations
and export-only seed-share boundary for public synthetic inputs.

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

The complete Phase 1 construction-independent host evaluator uses the sealed
admission and terminal-selection relation in
`registration-evaluator-admission-v1.md`. It binds the public identity scope,
ceremony DAG, intent, ordered provenance pair, both opaque input-selection
evidence identities, checked-at time, activation epoch, execution identity,
candidate key, and output commitment. This is an ideal host relation with an
explicit public-scope-only unregistered claim.

Production root custody, authenticated input provenance, durable absence and
uniqueness, and the selected input-selection mechanism remain Phase 6B-7
blockers. P0 records signed/public bindings plus the honest-input-derivation
assumption. P1-P3 add only the reviewed anti-bias mechanism and proof covered by
their selected composition. The deployable evaluator cannot ship before those
Section 12.3 requirements close.

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
- the host-only reference receives distinct canonical A/B ideal contributions
  for each arithmetic domain and internally derives a nonzero joint result.

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
2. Derive the nonzero joint delta from the role-local contributions, apply the
   correlated update above, and stage both next-epoch role-local
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
  A/B contribution pair, transcript, and ticket.

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

The host-only export composition now starts from authenticated registered state,
binds the canonical ceremony and role provenance, evaluates and packages one
exact typed A/B share pair, and commits that output while authorization remains
unconsumed. A construction-independent release transition retains those exact
shares through delivery uncertainty, consumes authorization at Client release,
binds the preceding output-commitment receipt, and models exact-identity
redelivery with zero private reevaluation. Independent Rust and Python checks
reconstruct the seed and reproduce the registered RFC 8032 public key. The
model supplies no production opener, authenticated transport, durable replay
transaction, constant-time construction evidence, or profile-security claim.

Export MUST NOT contain activation-family client shares, SigningWorker shares,
or a SigningWorker recipient. Registration, activation, recovery, and refresh
MUST NOT contain seed wires, seed-share outputs, or export authorization.

## 10. Uniform abort envelope

All five ideal-function contracts specify one result shape:

```rust
pub type ReferenceLifecycleResultV1<S> = Result<S, UniformLifecycleAbortV1>;

pub struct UniformLifecycleAbortV1 {
    pub request_kind: CeremonyRequestKindV1,
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
be detectable (`docs/router-a-b-SPEC.md:746-759`). The Phase 6A-selected profile
defines the Deriver-deviation claim. P0 covers approved honest execution and
records active Deriver behavior as an exclusion; P1 covers only its coherent
reviewed subset; P2/P3 require a valid authenticated output or a uniform
detectable abort for the selected malicious-Deriver model
(`docs/router-a-b-SPEC.md:761-772`). Timeout, crash, cancellation, peer
uncertainty, malformed input, partial send, and rollback destroy the selected
per-ceremony session or preprocessing-ticket material (`docs/yaos-ab.md`,
**Frame Format** and **Incremental Evaluation**).

The ideal model freezes the envelope and its forbidden contents. Exact timing,
selected-profile protocol failure points, failure-code equivalence, and any
selective-failure independence required by the selected P1-P3 claim remain
Section 12.4 blockers.

The host-semantic implementation now constructs this exact four-field shape
from a validated ceremony DAG for all five request kinds and uses one redacted
host-reference code plus one terminal state. A strict five-case corpus links
each transcript digest to the canonical ceremony companion. Rejected activation
metadata and every admitted registration, recovery, refresh, or export host-
reference evaluation failure expose this envelope. Evaluator failures retain
their detailed semantic cause only for crate-owned audit handling; the public
accessor and `Debug` projection omit it. Production encoding, selected-profile
protocol failures, timing equivalence, and every selective-failure guarantee
remain unimplemented.

The admitted evaluator-abort persistence and party-view layer now uses distinct
registration, recovery, refresh, and export retention types. Registration is an
unregistered self-loop; recovery retains its exact credential-suspended state;
refresh and export return their exact registered state through `before()` and
`after()`. All seven role observations contain only the uniform abort. Its strict
four-case host corpus and complete contract are in
`evaluator-abort-state-party-views-v1.md`. Production storage, actual ticket
destruction, frames, delivery, timing, and selected-profile failure semantics
remain unimplemented.

## 11. Fixture and test strategy

### 11.1 Preserve the arithmetic corpus

Keep `vectors/ed25519-yao-v1.json` as a host-only clear-arithmetic corpus. Its
`clear_reference_trace` continues to contain joined synthetic values for
differential implementations. No party-view test may treat that trace as a
protocol output.

### 11.2 Narrow lifecycle and output-party-view corpora

A separately versioned six-case host continuity corpus is implemented. It
contains:

- a synthetic public registration-candidate metadata snapshot with all-zero
  represented-work counters;
- a registration-origin ideal first-activation snapshot with zero reference
  work;
- same-root recovery continuity;
- a recovery-origin ideal activation snapshot with zero reference work;
- opposite-delta refresh continuity;
- a refresh-origin ideal activation snapshot with zero reference work.

The same-root case is generated through
`prepare_host_only_recovery_reference_v1`, which is the sole recovery arithmetic
path used by the corpus builder. The opposite-delta case is generated through
`prepare_host_only_refresh_reference_v1`, which is likewise its sole arithmetic
path. The narrow corpus retains its existing public continuity schema and
contains no output-sharing coins or shares.

Its operation counters are ideal reference metadata. They do not instrument a
deployed network, Deriver call path, Yao engine, or fixture-construction work.
The activated snapshots are continuity fixtures. They do not represent the
implemented `MetadataConsumedActivationStateV1`, prove SigningWorker activation,
or promote identity, credential, role-input-state, or versioned durable state.
Registration evaluation, export, ciphertext/package receipts, crash and durable
persistence behavior, and separate party views remain outside this narrow
schema.

The separate five-case semantic-artifact lifecycle corpus closes the public
encoding and projection portion of this boundary. It contains registration,
activation, recovery, refresh, and export tagged cases; exact semantic
descriptor, package-set, and receipt-body encodings; the three digest-only
persistence projections; all three activation origins with zero-reevaluation
counters; and four reconstructed freshness-reuse rejection self-loops. Seven
Rust tests and ten independent Python tests cover canonical bytes, typed
digest domains, ceremony/provenance links, descriptor ordering, prime-subgroup
share points, `2*X_client-X_server=A_pub`, uniform aborts, and recursive secret
exclusion. The exact contract is `semantic-artifact-lifecycle-v1.md`.

That corpus renders public evidence projections. It does not add party-private
views, authenticated ciphertexts or receipts, durable records, recovery custody,
refresh promotion, or worker activation.

The separate strict five-case output-party-view corpus composes those public
artifacts with construction-independent host output custody. It covers
registration, recovery, and refresh package preparation; activation metadata
consumption; and export release. Each case has one equal common-public value and
seven closed role extensions. The core exposes separate consuming Deriver A and
Deriver B observation methods, with no runtime role selector. Five core relation
tests, two compile/static boundary tests, six corpus tests, nine independent
Python tests, and nine Lean policy-shape theorems cover scalar/seed
reconstruction, all three activation
origins, export registered-key continuity, empty infrastructure extensions,
static A/B separation, and forbidden-value exclusions. The exact contract is
`output-party-views-v1.md`.

The separate export-delivery lifecycle closes the host authorization-ordering
and exact-output-provenance gap for export. Its one-case corpus covers output
commitment, delivery uncertainty, Client release, and exact-identity redelivery.
It does not model a production opener, network frames, durable delivery state,
or selected-profile security. Separate activation-delivery and activation-
recipient companions now cover atomic release and verified SigningWorker
activation as host-only structural evidence.

The corpora intentionally contain synthetic role-private values for independent
verification. They are not public runtime leakage or a production format. This
evidence does not model complete party inputs, protocol randomness, production
frames, abort timing, durable transition state, memory erasure, adaptive
corruption, noninterference, simulator equivalence, or selected-profile
security.

After the applicable blockers close, add a complete lifecycle corpus using a
tagged union with five distinct DTOs:

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
semantics. They use exact root equality and explicit synthetic A/B refresh
contributions plus their checked joint result;
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

The host-only reference checks continuity through exact root and contribution
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

The successful host-only recovery vector and deterministic preparation/output-
sharing reference are implemented. They label exact root comparison, aggregate
inputs, and explicit coins as host-only public synthetic evidence. They do not
bind the before/after values to authenticated registered state. Production proof
and custody remain blocked by the requirements above.

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

The deterministic host-only refresh preparation and scalar-output-sharing
composition are implemented over public synthetic current inputs, move-owned
role-local A/B ideal delta contributions, and explicit output-sharing fixture coins. They
check unchanged
client inputs, exact `+delta`/`-delta` server updates, joined and downstream
activation continuity, and scalar-share reconstruction. The implementation is
variable-time and does not authenticate roots, KDF provenance, registered state,
or epochs.

Production remains BLOCKED until Phase 6A selects a coherent P0-P3 profile and
review verifies the corresponding realization:

- deployed role-separated A/B contribution origination with no client or Router
  control, reviewed entropy and anti-bias, and the frozen ideal nonzero-sum
  distribution; correctness-with-abort is required when the selected profile
  claims active protection;
- profile-appropriate binding of each old contribution to the current epoch and
  each new contribution to the exact signed-delta update; P0 records its
  honest-execution assumption and signed/public checks explicitly;
- an active-circuit or equivalent proof that old and next joined `y` and `tau`
  are equal without opening either joined value for every profile whose claim
  covers a deviating Deriver;
- profile-appropriate authenticated binding between next contribution state,
  recipient packages, outputs, and the complete package-digest set, using the
  selected P0 signed/public checks or the reviewed P1-P3 mechanism;
- the minimal role-local persistence, cutover evidence, erasure, and crash
  recovery required by the Phase 6A-selected lifecycle across independent
  deployments.

Evidence for the current ambiguity spans the root-share flow at
`docs/router-a-b-SPEC.md:533-553`, activation-family refresh in the **Fixed
Circuit Families** section of `docs/yaos-ab.md`, and the **Root And
Key-Continuity Policy** of `docs/router-a-b-sol-refactor.md`.

The production corruption claim follows the Phase 6A-selected P0-P3 profile;
this host reference carries no corruption claim. The transition invalidates
stale role-share epochs and shortens retained-state cryptoperiods. It supplies
no mobile-adversary or sequential-compromise healing claim. Such a claim
requires a reviewed erasure model, corruption schedule, and refresh proof beyond
this reference functionality.

### 12.3 Role-input provenance, root custody, and registration input selection

The application binding, stable context, and contribution-KDF bytes are frozen
in the host reference under `docs/yaos-ab.md` **Stable Key Context and Ceremony
Context**. `docs/input-provenance-v1.md` freezes a proof-system-neutral outer
statement, A/B pair invariants, root/input-state epoch meanings, lifecycle
evidence slots, and profile-indexed registration input-selection requirements.
Production root custody and artifact realization remain open. Yao proves only
the computation guaranteed by the selected profile over supplied inputs; it
does not by itself establish that those inputs match the provisioned roots
described under **Input Provenance**. Required decisions are:

- protected production root representations and role-local invocation APIs;
- hiding and binding artifact suites plus proof statements connecting each
  frozen KDF output to its provisioned root;
- authenticated authorization-record, root-record, and role-input-state bytes
  plus their production verification and lookup rules;
- the Phase 6A-selected registration input-selection contract and
  retry/acceptance state: P0 signed/public bindings and explicit honest-input
  assumption, or the reviewed P1-P3 anti-bias mechanism;
- protected same-root recovery proof and joint refresh-delta proof;
- selected-protocol composition binding accepted provenance to exact input
  wires at the strength required by the frozen claim.

Synthetic raw contributions remain valid clear-arithmetic test inputs. They are
not production provenance evidence.

### 12.4 Selected protocol and private outputs

The ideal random-sharing distribution is frozen in Section 8. Its realization
remains blocked on the Phase 6A P0-P3 selection and review. Every eligible
profile requires:

- protocol-generated unbiased output randomness;
- reviewed garbling and OT matching the exact selected claim;
- two-sided private output translation and recipient encryption;
- transcript/package binding, public output checks, and exact signed receipt
  bytes;
- the minimal replay, stream, persistence, and crash lifecycle selected for
  that profile.

P1-P3 additionally require the complete reviewed combination selected for their
claim, which may include malicious-secure OT, input consistency, active garbling
correctness, active-output authentication, selective-failure-resistant aborts,
and one-use preprocessing. P0 records honest execution of the approved OT,
garbling, input derivation, and output-sharing algorithms as an explicit
assumption. It retains the mandatory independent administration, artifact
pinning, authenticated transport, replay controls, recipient encryption,
constant-time review, and signed/public output checks defined in
`docs/yaos-ab.md`. Partial active mechanisms do not widen its claim.

These are production capabilities in the **Production Capabilities** section of
`docs/yaos-ab.md`. This reference boundary supplies no evidence for them.

## 13. Alignment and readiness

| Requirement                               | Current code status                                                                                                                  | Classification              | Confidence |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ---------- |
| Five disjoint request tags                | `fixtures.rs` and branch-specific wrappers in `lifecycle_domain.rs`                                                                  | executable structural match | 1.00       |
| Export-only seed result                   | arithmetic oracle union and structural export output family                                                                          | executable structural match | 1.00       |
| Five disjoint prestates and transitions   | nonserializable request, pre-state, success, and output-custody families in `lifecycle_domain.rs`                                    | host-semantic match         | 0.99       |
| Lifecycle artifact ownership              | crate-private registered-state bridges and move-owned issuance/sessions return inputs before evaluation, then burn admitted request identities | executable host evidence    | 1.00       |
| Activation package-reference consumption  | crate-private activation control retains output-committed artifacts on rejection and move-consumes accepted metadata with zero reevaluation | metadata-only evidence      | 1.00       |
| Activation persistence projections        | digest-only `OutputCommitted`, exact rejected-attempt self-loop, and `MetadataConsumed` values; no durable record or worker-activation claim | executable host evidence    | 1.00       |
| Public semantic artifact lifecycle corpus | strict five-branch descriptor/package/receipt/projection bytes, three activation origins, four uniform rejection self-loops, seven Rust tests, and ten independent Python tests | executable host evidence | 1.00 |
| Recovery remains distinct from export     | generator types are distinct; the superseded Router gate remains an integration cleanup item                                         | integration mismatch        | 1.00       |
| Registration arithmetic establishment     | typed host-only root-to-contribution preparation, seed-free activation, and scalar sharing with six focused independent-arithmetic tests | executable host evidence    | 1.00       |
| Recovery seed-preserving transition       | typed host-only preparation/output-sharing reference plus committed six-case corpus and Rust/Python checks                           | executable host evidence    | 1.00       |
| Refresh identity-preserving transition    | typed host-only preparation/output-sharing reference, exact role-local signed deltas, six focused Rust tests, and unchanged Rust/Python corpus evidence | executable host evidence    | 1.00       |
| Export registered-key equality and sharing | typed host-only caller-supplied key check plus consuming seed-share composition and six focused independent-arithmetic/RFC 8032 tests | executable host evidence    | 1.00       |
| Host-only output-sharing arithmetic       | typed activation scalar and export-only seed shares plus a six-case Rust/Python corpus                                              | executable host evidence    | 1.00       |
| Construction-independent output party views | five stage/seven-role host views, static consuming A/B observation, strict five-case corpus, 11 Rust tests, nine Python tests, and nine Lean policy theorems | executable host evidence | 1.00 |
| Export release and redelivery lifecycle | output commitment keeps authorization live; exact retained shares flow through uncertainty to Client release; release consumes authorization; redelivery is an identity self-loop | executable host evidence | 1.00 |
| Complete party views and declared leakage | output custody is executable; private input/randomness/frame, delivery, abort, durable-transition, and selected-profile views remain absent | missing in code | 1.00 |
| Uniform lifecycle abort envelope          | exact public-only four-field shape and five-branch ceremony-linked corpus; activation-metadata mismatch is the only integrated lifecycle failure | partial executable evidence | 1.00       |
| Active private randomized outputs         | no protocol implementation exists                                                                                                    | intentionally absent        | 1.00       |

The completed slice provides branch-specific public semantics, canonical
ceremony-owning requests, crate-private registered-state bridges, move-owned
issuance and sessions, evaluation-burn behavior, origin-typed output-committed
artifacts, retry-preserving activation control, metadata-consumed states, and
three digest-only persistence projections. It also provides typed host-only
recovery and refresh preparation/output-sharing references, a cross-language
six-case continuity corpus, and a cross-language six-case host-only
output-sharing corpus. The strict five-branch semantic-artifact lifecycle corpus
adds public package/receipt encodings and persistence cross-links without
creating production authority. The five-case output-party-view corpus adds
closed construction-independent output-custody projections and static A/B
observation without claiming runtime privacy. Recovery and refresh inputs remain
public synthetic host evidence. The companion authenticated-store contract now
requires a strictly verified request-bound authority wrapper before registered
issuance. Package opening, production store parsing and rollback floors, global
one-use issuance, complete lifecycle evaluators, durable persistence and
transactions, selected-profile opening, production identity/state-version
promotion, recovery custody, atomic refresh cutover, complete runtime party
views, production provenance and custody, deployed role-separated delta
origination and anti-bias, profile-selected private outputs, and authenticated
receipt artifacts remain blocked by Sections 12.1 through 12.4 and Phase 6A.

This document does not close Yao Phase 1 or FV0.
