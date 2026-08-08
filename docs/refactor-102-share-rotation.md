# Signing Lane Provisioning, Refresh, And Revocation

Date created: June 15, 2026

Last reconciled: August 5, 2026

Status: active cryptographic plan. Shared rotation types and server store
interfaces exist. Current owner flows now preserve local Ed25519 material and
durable ECDSA material identity, while no lane-provisioning protocol is
registered. The previous plan's universal additive-reshare design has been
removed because Ed25519 lane provisioning belongs to the Streaming Yao
lifecycle.

## Dependencies And Authority

This plan consumes:

- [refactor-90-modular-auth-capabilities-plan.md](./refactor-90-modular-auth-capabilities-plan.md)
  for canonical capability hydration, the landed ECDSA capability manifest and
  activation journal, exact `MpcMaterialActivationRef` identities, and
  operation authorization/admission;
- [router-ab/ed25519-yao/implementation-plan.md](./router-ab/ed25519-yao/implementation-plan.md) for Ed25519 stable context, registered `A_pub`,
  Client and SigningWorker recipients, recovery, correlated refresh,
  forward-only output commitment, and production security gates;
- `crates/router-ab-ecdsa-derivation` for secp256k1 role-local additive shares,
  public identity, threshold sessions, and explicit export;
- [refactor-100-passkey-account-refactor.md](./refactor-100-passkey-account-refactor.md)
  for sealed roots and holder material;
- [refactor-101-wallet-execution-lanes.md](./refactor-101-wallet-execution-lanes.md)
  for wallet keys, share-bearing lanes, lifecycle, and execution identity;
- [refactor-104-agent-id-spending.md](./refactor-104-agent-id-spending.md) for
  agent identity, owner authorization, custody binding, and delegated execution
  admission.

Refactor 103 consumes linked-device protocols and lifecycle defined here.
Refactor 104 may consume an authorization-bound delegated-execution lane when
the selected wallet adapter requires agent-held MPC participation.

## Goal

Create, refresh, and revoke independently controlled signing lanes while
preserving every wallet public identity.

The critical invariant is curve-specific:

```text
Ed25519: registered A_pub remains byte-for-byte identical
ECDSA:    threshold public key and EVM address remain byte-for-byte identical
```

## Protocol Taxonomy

### Envelope Rewrap

Rewrap changes encryption around the same client root or holder share.

```text
same wallet key
same lane
same lane share epoch
same custody secret
new credential, KEK, custody key, or envelope version
```

Refactor 100 owns passkey and recovery rewrap. Refactor 104 owns agent
identity-key and custody replacement. When an optional delegated-execution
holder share changes custody, this plan supplies the admitted lane refresh.

### Credential Recovery

Recovery replaces a credential while preserving the wallet key and lane.

- Ed25519 uses the same-root Yao recovery lifecycle.
- ECDSA reopens the same client root share and rebinds the replacement
  credential to the existing EVM-family key and exact threshold sessions.
- The prior credential binding is tombstoned only after replacement activation.

Recovery does not create a linked-device or delegated-execution lane.

### Lane Creation

Lane creation adds an independently revocable participant pair for an existing
wallet key.

```text
same wallet key
source owner lane remains active
new target lane ID
new target lane share epoch
new holder material
new matching server/SigningWorker material
```

ECDSA client finalization now verifies proof-contained root-share commitments
and DLEQ proofs. The removed signed ECDSA commitment-policy registry is outside
this lane protocol. Target-lane resharing uses operation-scoped transcript
commitments bound to the exact source lane, target lane, epochs, public
identity, and activation receipt; it must not recreate a long-lived commitment
authority or registry.

Each target lane is activated as its own material instance. The curve adapter
creates a fresh `MpcMaterialActivationId` and exact
`MpcMaterialActivationRef`, binds it to the target lane and first share epoch,
and records the curve-specific activation receipt. For ECDSA this reference is
the active manifest's activation plus its server activation commit; for
Ed25519 it is the Yao recipient-package activation and its verified receipt.
The aggregate enrollment manifest is a product receipt and never substitutes
for either curve-specific capability record.

Ed25519 and ECDSA use different protocols described below.

### Lane Share Refresh

Refresh replaces holder and server material for one existing lane.

```text
same wallet key
same lane ID
next lane share epoch
replacement holder material
replacement server/SigningWorker material
old target epoch retired at activation
```

Other lanes stay active.

Refresh follows the same mapping as creation: a fresh activation ID and
activation reference bind the replacement material to the same lane ID and the
next share epoch. The prior activation remains the canonical source until the
replacement receipt is committed, then its material is retired or revoked by
the owning protocol. Refresh cannot reuse an activation ID, move an activation
between lanes, or replace the wallet-key public identity.

### Wallet-Key Root Refresh

An Ed25519 Yao root/provenance refresh or Router A/B ECDSA root-custody refresh
can affect every lane derived from that wallet key. These are wallet-key-scoped
operations. Their root custody, operator separation, and production protocol
remain owned by the authoritative protocol documents.

If such a refresh changes active recipient packages, it must enumerate the
exact active lane references and reactivate every affected lane under one
wallet-key refresh operation. The enrollment manifest is an aggregate product
receipt; each curve-specific capability hydration still resolves its own
manifest and `MpcMaterialActivationRef`. A pending activation journal is
reconciled before lookup and deleted during atomic local finalization. A root
refresh cannot silently mutate one lane's server material while leaving its
holder binding stale.

### Revocation

Revocation makes one lane or one aggregate enrollment unavailable to signing.
It increments the revocation epoch, rejects new admission immediately, stops
queued work, disables the exact server/SigningWorker capability, and invalidates
warm handles.

### Wallet Rekey

Wallet rekey creates a new wallet key and normally changes the public identity.
Use it after confirmed compromise of both sides of a lane, loss of an
unrecoverable root, or an explicit wallet migration. Rekey is outside ordinary
lane rotation.

## Ed25519 Protocol: Yao Lane Provisioning

Ed25519 lane creation runs a Streaming Yao lifecycle ceremony. It does not use
the secp256k1 additive-delta protocol.

The authoritative Yao request mapping currently defines registration,
activation, recovery, refresh, and export. Linked-device and optional
delegated-execution provisioning need a new disjoint operation before
implementation:

```text
product operation:  lane_provisioning
request kind:       lane_provisioning
ideal functionality: F_ed25519_lane_provisioning_v1
circuit family:     selected and frozen in router-ab/ed25519-yao/implementation-plan.md
```

The Yao plan must accept this operation and freeze its circuit/output semantics
before routes are registered. Reusing `registration`, `recovery`, or
`server_share_refresh` would apply the wrong pre-state and promotion rules.

### Ed25519 Inputs

- authenticated wallet and active Ed25519 `WalletKey`;
- exact registered `A_pub`;
- immutable `nearEd25519SigningKeyId` and `keyCreationSignerSlot`;
- stable Yao application context and role-root provenance;
- source owner lane authorization;
- target lane ID and first target share epoch;
- target holder principal and target SigningWorker participant;
- enrollment, policy, operation, and idempotency digests;
- target holder HPKE public key;
- target SigningWorker recipient key;
- selected Yao suite and protocol version.

### Ed25519 Outputs

- recipient-isolated target Client/holder package;
- recipient-isolated target SigningWorker package;
- target holder and SigningWorker public commitments;
- proof or checked relation to the registered `A_pub`;
- complete transcript and terminal receipt;
- no seed-output branch and no export-capable package.

### Ed25519 Invariants

1. Stable Client and server roots preserve the existing key-creation identity.
2. `keyCreationSignerSlot`, stable context, and registered `A_pub` are unchanged.
3. The target lane and enrollment identity bind the new recipient packages
   outside the stable key KDF.
4. Existing active recipient lanes remain active during target creation.
5. The Router sees ciphertext, public commitments, and receipts only.
6. The target holder package is encrypted directly to Device 2 or, for an
   already-authorized Refactor 104 execution adapter, its named custody binding.
7. The target SigningWorker package activates under the exact target lane and
   epoch.
8. Ordinary signing uses the activated Client and SigningWorker and performs
   zero Deriver calls.
9. Export fields are unrepresentable in lane-provisioning requests and outputs.

### Ed25519 Commitment Boundary

Before Yao `OutputCommitted`, abort discards the pending target and leaves every
existing lane active.

At and after `OutputCommitted`, the exact committed packages are forward-only.
The system redelivers and completes activation with the same transcript. It
cannot reevaluate with new randomness or roll back the protocol epoch. If the
product enrollment is cancelled after commitment, the system completes durable
receipt accounting and revokes the target before signing admission can use it.

### Ed25519 Lane Refresh

Lane-scoped refresh requires a second disjoint Yao operation or a reviewed
lane-recipient branch of the provisioning functionality. It keeps the lane ID,
creates the next share epoch, preserves `A_pub`, activates replacement Client
and SigningWorker packages, and retires the prior lane epoch.

The existing wallet-key-level correlated refresh in `router-ab/ed25519-yao/implementation-plan.md` has different
scope. It remains valid for Yao role-root and registered-key lifecycle. It
cannot be treated as a lane-scoped refresh until the Yao specification defines
parallel recipient behavior explicitly.

## ECDSA Protocol: Additive Lane Resharing

For the EVM-family secp256k1 wallet key:

```text
n = secp256k1 scalar field order
x_client_source + x_relayer_source = x mod n
X_client_source + X_relayer_source = X
```

Target-lane creation:

```text
holder samples x_client_target uniformly from [1, n - 1]
delta = x_client_source - x_client_target mod n
relayer derives x_relayer_target = x_relayer_source + delta mod n

X_client_target = x_client_target * G
X_relayer_target = x_relayer_target * G
X_client_target + X_relayer_target = X
```

The source lane shares remain unchanged. A lane refresh applies the same
construction to the next epoch of the same lane and retires the prior epoch at
activation.

### ECDSA Security Requirements

- the holder samples the target client share inside browser Rust/WASM;
- the holder sends `delta` over an authenticated encrypted channel;
- `delta` is bound to the transcript and never persisted;
- the relayer never receives either client share;
- the holder never receives either relayer share outside explicit export;
- the target client share is encrypted directly to the target custody key;
- the target relayer share is sealed under the exact lane and epoch;
- both sides verify the threshold public key and EVM address;
- target threshold sessions bind the same EVM-family wallet key;
- non-export lane creation cannot produce a relayer export-share envelope.

### ECDSA Transcript Binding

The transcript includes:

- wallet and wallet-key IDs;
- EVM-family key-slot ID;
- threshold public key and EVM address;
- source lane ID, epoch, holder principal, and relayer key ID;
- target lane ID, epoch, holder principal, and relayer key ID;
- `X_client_target` and `X_relayer_target`;
- target threshold-session identities;
- enrollment identity and exactly one authorization binding digest;
- target custody public key;
- operation ID, idempotency key, protocol version, and expiry.

## Protocol Job Types

Use curve-specific job branches.

```ts
type LaneProvisioningJob =
  | Ed25519YaoLaneProvisioningJob
  | EcdsaAdditiveLaneProvisioningJob;

type LaneAuthorizationBinding =
  | {
      kind: 'linked_device';
      linkedDevicePermissionDigestB64u: string;
      authorizationBindingDigestB64u?: never;
    }
  | {
      kind: 'delegated_execution';
      authorizationBindingDigestB64u: string;
      linkedDevicePermissionDigestB64u?: never;
    };

type Ed25519YaoLaneProvisioningJob = {
  kind: 'ed25519_yao_lane_provisioning_v1';
  operationId: LaneOperationId;
  enrollmentId: EnrollmentId;
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  sourceLaneId: SigningLaneId;
  sourceLaneShareEpoch: LaneShareEpoch;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivationId: MpcMaterialActivationId;
  registeredPublicKeyB64u: string;
  keyCreationSignerSlot: KeyCreationSignerSlot;
  authorization: LaneAuthorizationBinding;
  lifecycle: LaneProtocolLifecycle;
};

type EcdsaAdditiveLaneProvisioningJob = {
  kind: 'ecdsa_additive_lane_provisioning_v1';
  operationId: LaneOperationId;
  enrollmentId: EnrollmentId;
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  sourceLaneId: SigningLaneId;
  sourceLaneShareEpoch: LaneShareEpoch;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivationId: MpcMaterialActivationId;
  thresholdPublicKey33B64u: string;
  evmAddress: string;
  authorization: LaneAuthorizationBinding;
  lifecycle: LaneProtocolLifecycle;
};
```

The target activation ID is allocated once for the exact lane/epoch job. On
commit, the curve adapter returns the full `MpcMaterialActivationRef` and
persists it with the lane record. Delegated-execution and linked-device jobs
use the disjoint `LaneAuthorizationBinding` branches above, so a linked-device
permission digest cannot be presented as delegated authorization or vice versa.

## Protocol Lifecycle

```ts
type LaneProtocolLifecycle =
  | {
      state: 'preparing';
      startedAtMs: number;
      committedAtMs?: never;
      holderReceiptAtMs?: never;
      activatedAtMs?: never;
      abortedAtMs?: never;
    }
  | {
      state: 'awaiting_protocol_commitment';
      startedAtMs: number;
      committedAtMs?: never;
      holderReceiptAtMs?: never;
      activatedAtMs?: never;
      abortedAtMs?: never;
    }
  | {
      state: 'committed_awaiting_holder_delivery';
      startedAtMs: number;
      committedAtMs: number;
      transcriptHashB64u: string;
      holderReceiptAtMs?: never;
      activatedAtMs?: never;
      abortedAtMs?: never;
    }
  | {
      state: 'ready_to_activate';
      startedAtMs: number;
      committedAtMs: number;
      transcriptHashB64u: string;
      holderReceiptAtMs: number;
      activatedAtMs?: never;
      abortedAtMs?: never;
    }
  | {
      state: 'activated';
      startedAtMs: number;
      committedAtMs: number;
      transcriptHashB64u: string;
      holderReceiptAtMs: number;
      activatedAtMs: number;
      abortedAtMs?: never;
    }
  | {
      state: 'aborted_precommit';
      startedAtMs: number;
      abortedAtMs: number;
      abortReason: LaneProtocolAbortReason;
      committedAtMs?: never;
      holderReceiptAtMs?: never;
      activatedAtMs?: never;
    }
  | {
      state: 'committed_completion_required';
      startedAtMs: number;
      committedAtMs: number;
      transcriptHashB64u: string;
      recoveryReason: LaneProtocolCompletionReason;
      holderReceiptAtMs?: never;
      activatedAtMs?: never;
      abortedAtMs?: never;
    };
```

Only pre-commit states can abort. Committed states either reach
`ready_to_activate`, activate, or remain fenced in
`committed_completion_required` for exact redelivery and recovery.

## Multi-Key Enrollment Activation

A linked-device or optional delegated-execution enrollment has one aggregate
product manifest digest and one child job per target wallet key. This aggregate
manifest coordinates the enrollment only; it is distinct from the landed
curve-specific ECDSA capability manifest and from every child
`MpcMaterialActivationRef`.

```text
Enrollment(preparing)
  -> every child protocol committed
  -> every holder package delivered and sealed
  -> every server/SigningWorker target ready
  -> aggregate receipt verifies exact manifest
  -> Enrollment(active) and child lanes active
```

Atomic visibility is enforced through the parent enrollment:

- child lane records and server material remain `provisioning` while work runs;
- a child can become `ready_to_activate` without becoming signable;
- the parent activation commit stores the manifest receipt and marks all child
  lanes active;
- signing admission requires the active parent and active child;
- a crash after some child commits leaves the parent inactive;
- recovery resumes exact committed children and starts only missing pre-commit
  work;
- cancellation after committed Yao output completes accounting and revokes all
  child targets before the parent can become active.

Gateway D1 owns the parent enrollment, child lane product records, aggregate
manifest receipt, activation result, Wallet Session authorization, quotas,
authorized operations, and authorization audit. SigningWorker private D1 owns
target server material, delivery state, active material, cryptographic effect
deduplication, presignature or Yao material consumption, and terminal response
replay; Deriver A/B private D1 owns role-local custody and one-use state. Device
storage owns the holder package after local finalization.
Router carries authenticated typed commands, ciphertext, and receipts and owns
no mutable enrollment, lane, manifest, or activation state. Cross-store
convergence uses exact correlation and idempotent effects; it does not claim a
single database transaction.

## Concurrency And Fencing

- acquire a wallet-key lock for each child protocol;
- acquire an enrollment lock for aggregate activation and revocation;
- pin source lane share epoch and revocation epoch at admission;
- reject target lane or operation ID reuse with a different transcript;
- burn failed ECDSA deltas and presign state;
- follow Yao one-use ticket and forward-only output rules;
- give revocation priority over creation or refresh;
- reject stale epochs before any holder or server participation;
- keep pending and retired material unavailable to ordinary signing;
- keep Wallet Session expiry, quota exhaustion, and delegated-authorization
  expiry as admission outcomes that preserve lane material and activation;
- make every activation and receipt idempotent for the exact transcript.

## Owner Lane Refresh

Owner passkey or Email OTP lane refresh uses the protocol for its wallet-key
family:

- Ed25519: lane-scoped Yao refresh after the operation is frozen in the Yao
  specification;
- ECDSA: additive resharing through the active client capability and relayer
  share;
- mixed wallet: one refresh enrollment coordinates every selected key;
- credential-only replacement: Refactor 100 rewrap/recovery path, with no lane
  epoch change.

The UI must distinguish credential replacement, lane refresh, and wallet rekey.

## Linked-Device Lane Creation

1. Device 2 registers a QR link session with a target holder encryption key.
2. Device 1 authenticates an active owner lane and approves the exact key
   manifest and permission policy.
3. Create one curve-specific child protocol per wallet key.
4. Encrypt Ed25519 recipient packages or ECDSA target holder shares directly to
   Device 2.
5. Seal target SigningWorker/relayer material under each lane and epoch.
6. Device 2 verifies identity continuity, seals every holder entry under its
   passkey KEK, and returns per-key receipts plus one manifest receipt.
7. Activate the parent enrollment and all child lanes.

The source owner lanes remain active throughout.

## Authorization-Bound Delegated Execution Lane

This optional flow exists only for the Refactor 104 direct threshold-wallet
adapter. Agent identity registration and owner authorization complete first.
Lane creation then uses these substitutions:

- target custody is the exact authorization-bound agent custody binding;
- the key manifest is equal to or an explicitly authorized subset of the signed
  wallet-key manifest;
- an authorization-binding digest replaces the linked-device permission
  digest;
- activation requires custody and participant receipts;
- every signing operation still requires a verified agent request, active
  delegated authorization, an atomic delegated budget claim, and Refactor 104
  admission. It does not consume or rename Refactor 90's Wallet Session quota.

The lane share never acts as the agent identity or delegated authorization.

## Revocation

Lane revocation:

1. Increment the lane revocation epoch and mark the lane revoked.
2. Reject new requests and stop queued operations.
3. Disable the exact target SigningWorker or relayer capability.
4. Retire target holder-delivery records and invalidate warm handles.
5. Emit a revocation receipt and audit event.

ECDSA uses an exact server retirement effect for this path. Refactor 90's
canonical ECDSA manifest currently has one terminal retirement shape,
`replaced`, proven by a replacement server activation commit. Lane revocation
cannot be encoded as `replaced` or inferred from an authorization state. This
plan adds a disjoint receipt and lane-aware hydration adapter:

```ts
type EcdsaServerRetirementReceipt = {
  kind: 'ecdsa_server_retirement_receipt_v1';
  manifest: EcdsaManifestIdentity;
  materialActivation: MpcMaterialActivationRef;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  revocationEpoch: number;
  retirementReason:
    | 'lane_revoked'
    | 'device_compromise'
    | 'agent_compromise'
    | 'rotation';
  retirementCorrelationId: CorrelationId;
  retirementRequestDigestB64u: string;
  serverGeneration: EcdsaServerGeneration;
  lifecycleId: EcdsaLifecycleId;
  receiptDigestB64u: string;
  retiredAt: IsoTimestamp;
};
```

The receipt is produced by the ECDSA server-material owner, persisted with the
Gateway's lane product record, and delivered to the SigningWorker owner for
exact capability disablement. Hydration verifies manifest identity,
activation reference, lane/epoch, retirement correlation and request digest,
server generation, and receipt digest before returning a lane-specific
`blocked.revoked` result. It never retires another
lane or changes the wallet-key public identity. Router transports the command
and receipt and keeps no retirement record.

Enrollment revocation applies these steps to every child lane under one parent
revocation operation. Owner lanes and unrelated enrollments remain active.

If both holder and server material may be compromised, revoke immediately and
evaluate wallet rekey. A replacement lane always requires fresh owner approval.

## Current Implementation Gaps

- `ShareRotationJob` treats Ed25519 and ECDSA as one protocol family.
- the dormant `AdditiveDeltaReshareCommitment` type lacks a key-family,
  operation, lane, and epoch binding;
- job lifecycle omits committed delivery and forward-only recovery states;
- source-lane creation and same-lane refresh share overly broad types;
- parent enrollment activation and aggregate receipts do not exist;
- no Yao `lane_provisioning` request kind exists;
- no lane-scoped Yao refresh exists;
- ECDSA additive target-lane resharing is unimplemented;
- Refactor 90's canonical ECDSA manifest, activation journal, hydration, and
  exact `MpcMaterialActivationRef` are landed; the lane-aware source-material
  adapter remains open;
- the exact ECDSA lane-retirement receipt and lane-specific hydration mapping
  remain open;
- Gateway, SigningWorker, and Deriver owner adapters for lane delivery and
  activation remain open;
- signing admission does not resolve active enrollment and lane records.

Replace these scaffolds directly. Do not retain a universal rotation job or
protocol fallback.

## Implementation Phases

### Phase 0: Freeze Protocol Ownership

- [x] Adopt Refactor 90's landed curve-specific canonical hydration and ECDSA
      manifest as the source of truth; do not introduce a cross-curve manifest.
- [ ] Add `lane_provisioning` and lane-scoped refresh to the Yao specification,
      ideal functionality map, request union, and lifecycle proofs.
- [ ] Freeze ECDSA additive target-lane resharing and transcript encoding using
      operation-scoped proof commitments, without a signed commitment-policy
      registry.
- [ ] Freeze aggregate enrollment activation and recovery semantics.

### Phase 1: Correct Domain Types

- [ ] Replace universal rotation jobs with curve-specific creation and refresh
      unions.
- [ ] Add committed forward-only lifecycle states.
- [ ] Add enrollment manifests, aggregate receipts, and activation decisions.
- [ ] Add type fixtures for creation-versus-refresh and curve separation.
- [ ] Require a fresh target `MpcMaterialActivationId` for every lane create or
      refresh and bind the resulting reference to the lane and share epoch.

### Phase 2: ECDSA Lane Protocol

- [x] Resolve the exact active source material through Refactor 90's landed
      `ActiveEcdsaCapabilityManifest` and hydration contract after reconciling
      any pending activation journal.
- [ ] Add the lane-aware source-material adapter that binds the manifest,
      lane/epoch, participants, and exact `MpcMaterialActivationRef`.
- [ ] Implement holder-sampled target share and transient delta handling.
- [ ] Verify public-key and address continuity.
- [ ] Seal target relayer shares and bind target threshold sessions.
- [ ] Emit and hydrate the exact `EcdsaServerRetirementReceipt` for lane
      revocation; do not encode revocation as `replaced`.
- [ ] Add replay, parity, tamper, and zeroization tests.

### Phase 3: Ed25519 Yao Lane Protocol

- [ ] Implement admitted recipient provisioning through the selected Yao suite.
- [ ] Deliver separate target Client and SigningWorker packages.
- [ ] Verify registered `A_pub` and immutable key-creation identity.
- [ ] Preserve zero-Deriver ordinary signing.
- [ ] Add output-commit redelivery and recovery tests.

### Phase 4: Aggregate Activation

- [ ] Implement enrollment locks and manifest receipts.
- [ ] Activate child lanes through one parent visibility commit.
- [ ] Resume partial committed work after crashes.
- [ ] Keep every partial enrollment unavailable to signing.

### Phase 5: Refresh And Revocation

- [ ] Add owner, linked-device, and delegated-execution lane refresh.
- [ ] Add immediate lane and aggregate enrollment revocation.
- [ ] Invalidate warm capabilities and reject stale epochs.
- [ ] Ensure Wallet Session and delegated-authorization expiry preserve active
      lane material and activation references.
- [ ] Add wallet-key root refresh integration after authoritative protocol
      support exists.

## Validation

Static checks:

- Ed25519 job with ECDSA fields fails;
- ECDSA job with Yao circuit fields fails;
- lane creation cannot carry a prior target epoch to retire;
- lane refresh requires the same lane ID and strictly advancing epoch;
- every create or refresh allocates a fresh activation ID and persists the
  exact activation reference with the target lane epoch;
- delegated authorization-binding and linked-device permission digests cannot
  be interchanged;
- committed lifecycle cannot transition to pre-commit abort;
- active enrollment requires a nonempty exact child manifest;
- persisted records cannot contain ECDSA delta, plaintext holder material, Yao
  private outputs, or export shares;
- ECDSA lane revocation fails closed without an exact server retirement receipt
  bound to the manifest, activation, lane, epoch, generation, and digest;

Focused cryptographic tests:

- Yao lane provisioning preserves registered `A_pub` and existing lanes;
- Yao linked-device package substitution and recipient swap fail;
- Yao output commitment is forward-only and redelivery is idempotent;
- ECDSA additive resharing preserves threshold public key and EVM address;
- ECDSA delta replay, persistence, transcript substitution, and parity mismatch
  fail;
- both protocols produce ordinary valid signatures from the target lane;
- ordinary Ed25519 target-lane signing performs zero Deriver calls;
- non-export provisioning never creates export-capable output.

Aggregate tests:

- Ed25519 ready plus ECDSA pending keeps the device inactive;
- all child receipts activate the device exactly once;
- crash recovery resumes the exact committed manifest;
- cancellation after Yao commit never exposes a signable partial lane;
- revoking a device disables all child lanes and preserves owner lanes;
- stale lane, revocation, Wallet Session, participant, and threshold-session
  identities fail before share work.

Broad gate:

- extend and run the Yao local lifecycle and source-isolation gate;
- run ECDSA derivation, threshold-signing, and export-continuity suites;
- run mixed-wallet registration, recovery, signing, budget, and device-link
  behavior suites;
- repeat selected production-profile and deployment gates before release.

## Non-Goals

- using secp256k1 additive-delta resharing as the Ed25519 Yao protocol;
- calling Yao registration to create a parallel lane;
- rotating a wallet public identity during normal lane operations;
- letting Router, Derivers, or SigningWorker reconstruct a wallet key;
- using an ordinary signing route for export or lane provisioning;
- claiming production security from the local passive Yao implementation;
- retaining old server-custody rotation terminology or compatibility paths.

## Decisions Required Before Implementation

- Freeze `F_ed25519_lane_provisioning_v1`, its circuit family, recipient model,
  and relation to existing Yao roots.
- Freeze the lane-scoped Ed25519 refresh operation and its effect on parallel
  recipients.
- Decide how committed target packages are durably redelivered after a link
  session expires.
- Freeze the aggregate enrollment visibility and lane-aware hydration read
  model across Gateway D1 and private material owners; Router remains
  stateless.
- Define compromise cases that require lane refresh, enrollment revocation, or
  wallet rekey.
