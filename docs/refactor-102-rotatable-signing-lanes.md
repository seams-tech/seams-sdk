# Rotatable Signing Lanes

Date created: June 15, 2026

Last reconciled: August 10, 2026

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
  for wallet keys, share-bearing lanes, lifecycle, and execution identity.

Refactor 103 consumes linked-device protocols and lifecycle defined here.
Refactor 104 is not a prerequisite. It may later consume an
authorization-bound delegated-execution adapter after its identity,
authorization, budget, and custody records exist. The first implementation in
this plan supports linked-device creation plus owner-authorized lane refresh and
revocation.

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

The authoritative Yao plan now defines two disjoint lane operations:

```text
create:  lane_provisioning -> F_ed25519_lane_provisioning_v1
refresh: lane_refresh      -> F_ed25519_lane_refresh_v1
circuit: ed25519_yao_lane_materialization_v1
```

Both functionalities recompute the registered mathematical bases from the
stable role roots and apply one fresh protocol-generated scalar `lambda`:

```text
x_client_lane = x_client_base + lambda mod l
x_server_lane = x_server_base + 2 * lambda mod l

2 * X_client_lane - X_server_lane = A_pub
```

`lambda` is sampled inside the selected randomized-output functionality. It is
never supplied, decoded, persisted, or retried based on its value. Deriver A and
Deriver B privately share and encrypt the target holder scalar to the holder
recipient and the target server scalar to the SigningWorker recipient. Neither
recipient receives a base scalar, root, seed, or export-capable package.

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
6. The target holder package is encrypted directly to Device 2's admitted
   recipient key.
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

`F_ed25519_lane_refresh_v1` requires the exact active lane, current share and
revocation epochs, and current material activation. It retains the lane ID,
creates the strictly next share epoch with a fresh activation ID and fresh
`lambda`, activates replacement Client and SigningWorker packages through the
parent visibility protocol, and retires the prior epoch only afterward.

This operation does not run the wallet-key-level `server_share_refresh`. Stable
roots and role contributions remain unchanged, and every unrelated lane remains
active. Combining holder material from one lane with server material from
another fails the public relation and participant-binding checks.

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

The immutable transcript preamble is the exhaustive projection of the parsed
`EcdsaAdditiveLaneJobV1`. It includes:

- wallet and wallet-key IDs;
- EVM-family key-slot ID;
- threshold public key and EVM address;
- exact source capability manifest identity, server generation, material
  activation, lane ID, epoch, revocation epoch, holder participant, SigningWorker
  participant, relayer key ID, and both source verifying shares;
- exact target capability manifest identity, lane ID, epoch, holder participant,
  SigningWorker participant, recipient keys, custody binding, and ordered
  threshold-session identities with their chain memberships;
- enrollment identity and exactly one authorization binding digest;
- operation kind, operation ID, idempotency key, fresh activation ID, protocol
  version, resharing-channel binding, and expiry.

The target points and encrypted delta are protocol-round outputs. They cannot
appear in the admitted job. The complete transcript therefore has three
digest-linked records:

```ts
type EcdsaAdditiveLaneTranscriptPreambleV1 = {
  kind: 'ecdsa_additive_lane_transcript_preamble_v1';
  job: EcdsaAdditiveLaneJobV1;
};

type EcdsaAdditiveLaneHolderRoundV1 = {
  kind: 'ecdsa_additive_lane_holder_round_v1';
  preambleHashB64u: string;
  targetHolderPublicCommitment33B64u: string;
  encryptedDeltaCiphertextDigestB64u: string;
  sealedTargetHolderMaterialDigestB64u: string;
  holderAttestationB64u: string;
  holderCommittedAtMs: number;
};

type EcdsaAdditiveLaneServerRoundV1 = {
  kind: 'ecdsa_additive_lane_server_round_v1';
  preambleHashB64u: string;
  holderRoundHashB64u: string;
  targetServerPublicCommitment33B64u: string;
  sealedTargetServerMaterialDigestB64u: string;
  targetThresholdSessionSetDigestB64u: string;
  publicIdentityRelationDigestB64u: string;
  serverAttestationB64u: string;
  serverCommittedAtMs: number;
};

type EcdsaAdditiveLaneTranscriptV1 = {
  kind: 'ecdsa_additive_lane_transcript_v1';
  preambleHashB64u: string;
  holderRoundHashB64u: string;
  serverRoundHashB64u: string;
};
```

Each record uses the canonical length-prefixed encoder defined in this plan:
the domain string first, followed by fields in declaration order; nested job
fields use `LaneProtocolJobCommonV1`, the selected operation branch, and then
`EcdsaAdditiveLaneJobV1` field order; unions encode their discriminator followed
only by that branch's required fields; arrays encode a nonempty `u32` count
followed by each item in order; numeric epochs and timestamps are nonnegative
big-endian `u64`; digests decode to their 32 raw bytes before `LP32` encoding.
The domains are:

```text
seams/rotatable-signing-lanes/ecdsa-preamble/v1
seams/rotatable-signing-lanes/ecdsa-holder-round/v1
seams/rotatable-signing-lanes/ecdsa-server-round/v1
seams/rotatable-signing-lanes/ecdsa-transcript/v1
```

The encrypted-delta AEAD associated data is `preambleHashB64u`. The server
checks `X_client_target = X_client_source - delta * G`, derives
`X_relayer_target = X_relayer_source + delta * G`, and checks
`X_client_target + X_relayer_target = X` before attesting its round. Plaintext
`delta` is transient protocol memory and never enters a durable record. The
holder and server round hashes bind its ciphertext and checked effect without
publishing it. Reordering threshold sessions, substituting either recipient,
changing an authorization branch, or changing any source or target activation
produces a different preamble and fails before material activation.
`preambleHashB64u`, each round hash, and the final `transcriptHashB64u` are the
SHA-256 digest of their domain-separated canonical record. A record never
includes its own digest while computing it.

## Protocol Job Types

Jobs carry every value needed to reproduce their transcript. Persistence and
worker boundaries parse these records once; core protocol code never reloads a
mutable lane, participant, authorization, or recipient-key field while a job is
running.

```ts
type LinkedDeviceLaneAuthorizationBindingV1 = {
  kind: 'linked_device_enrollment';
  authorizedOperationId: AuthorizedOperationId;
  linkedDeviceEnrollmentId: LinkedDeviceEnrollmentId;
  linkedDevicePermissionDigestB64u: string;
  ownerLaneRefreshDigestB64u?: never;
};

type OwnerLaneRefreshAuthorizationBindingV1 = {
  kind: 'owner_lane_refresh';
  authorizedOperationId: AuthorizedOperationId;
  ownerLaneRefreshDigestB64u: string;
  linkedDevicePermissionDigestB64u?: never;
};

type LaneOperationAuthorizationBindingV1 =
  | LinkedDeviceLaneAuthorizationBindingV1
  | OwnerLaneRefreshAuthorizationBindingV1;

type ActiveLaneProtocolSourceV1 = {
  laneId: SigningLaneId;
  laneKind: SigningLaneKind;
  laneShareEpoch: LaneShareEpoch;
  revocationEpoch: number;
  holderParticipantId: LaneHolderParticipantId;
  signingWorkerParticipantId: SigningWorkerParticipantId;
  signingWorkerRecipientKeyId: SigningWorkerRecipientKeyId;
  participantBindingDigestB64u: string;
  materialActivation: MpcMaterialActivationRef;
};

type LaneTargetHolderV1 = {
  participantId: LaneHolderParticipantId;
  participantBindingDigestB64u: string;
  custodyBindingDigestB64u: string;
  hpkePublicKeyB64u: string;
  hpkePublicKeyDigestB64u: string;
};

type LaneTargetSigningWorkerV1 = {
  participantId: SigningWorkerParticipantId;
  participantBindingDigestB64u: string;
  recipientKeyId: SigningWorkerRecipientKeyId;
  hpkePublicKeyB64u: string;
  hpkePublicKeyDigestB64u: string;
};

type LaneCreationTargetV1 = {
  operation: 'create_lane';
  laneId: SigningLaneId;
  laneKind: 'linked_device';
  laneShareEpoch: LaneShareEpoch;
  expectedTargetState: 'absent';
  priorMaterialActivation?: never;
};

type LaneRefreshTargetV1 = {
  operation: 'refresh_lane';
  laneId: SigningLaneId;
  laneKind: 'owner_passkey' | 'owner_email_otp' | 'linked_device' | 'recovery' | 'break_glass';
  laneShareEpoch: LaneShareEpoch;
  expectedTargetState: 'active_previous_epoch';
  priorMaterialActivation: MpcMaterialActivationRef;
};

type EcdsaTargetThresholdSessionBindingV1 = {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  participantBindingDigestB64u: string;
};

type EcdsaSourceCapabilityBindingV1 = {
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
  serverGeneration: EcdsaServerGeneration;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: EcdsaRelayerKeyId;
};

type EcdsaTargetCapabilityBindingV1 = {
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  orderedThresholdSessions: readonly [
    EcdsaTargetThresholdSessionBindingV1,
    ...EcdsaTargetThresholdSessionBindingV1[],
  ];
};

type LaneProtocolJobCommonV1 = {
  operationId: LaneOperationId;
  enrollmentId: LaneEnrollmentId;
  idempotencyKey: LaneOperationIdempotencyKey;
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  source: ActiveLaneProtocolSourceV1;
  targetHolder: LaneTargetHolderV1;
  targetSigningWorker: LaneTargetSigningWorkerV1;
  targetMaterialActivationId: MpcMaterialActivationId;
  protocolVersion: 'rotatable_signing_lane_protocol_v1';
  expiresAtMs: number;
};

type LaneCreationOperationV1 = {
  target: LaneCreationTargetV1;
  authorization: LinkedDeviceLaneAuthorizationBindingV1;
};

type LaneRefreshOperationV1 = {
  target: LaneRefreshTargetV1;
  authorization: OwnerLaneRefreshAuthorizationBindingV1;
};

type LaneProtocolOperationV1 = LaneCreationOperationV1 | LaneRefreshOperationV1;

type Ed25519YaoLaneJobCurveV1 = {
  kind: 'ed25519_yao_lane_job_v1';
  keyFamily: 'ed25519';
  registeredPublicKeyB64u: string;
  nearEd25519SigningKeyId: NearEd25519SigningKeyId;
  keyCreationSignerSlot: KeyCreationSignerSlot;
  stableContextBindingB64u: string;
  yaoSuiteId: Ed25519YaoSuiteId;
  circuitDigestB64u: string;
  evmFamilySigningKeySlotId?: never;
  thresholdPublicKey33B64u?: never;
  evmAddress?: never;
};

type Ed25519YaoLaneJobV1 = LaneProtocolJobCommonV1 &
  Ed25519YaoLaneJobCurveV1 &
  (
    | (LaneCreationOperationV1 & { yaoRequestKind: 'lane_provisioning' })
    | (LaneRefreshOperationV1 & { yaoRequestKind: 'lane_refresh' })
  );

type EcdsaAdditiveLaneJobV1 = LaneProtocolJobCommonV1 &
  LaneProtocolOperationV1 & {
    kind: 'ecdsa_additive_lane_job_v1';
    keyFamily: 'ecdsa_secp256k1';
    evmFamilySigningKeySlotId: EvmFamilySigningKeySlotId;
    thresholdPublicKey33B64u: string;
    evmAddress: string;
    sourceCapability: EcdsaSourceCapabilityBindingV1;
    targetCapability: EcdsaTargetCapabilityBindingV1;
    sourceHolderVerifyingShare33B64u: string;
    sourceServerVerifyingShare33B64u: string;
    reshareChannelBindingDigestB64u: string;
    transcriptEncoding: 'ecdsa_additive_lane_transcript_v1';
    nearEd25519SigningKeyId?: never;
    registeredPublicKeyB64u?: never;
    keyCreationSignerSlot?: never;
    stableContextBindingB64u?: never;
    yaoRequestKind?: never;
    yaoSuiteId?: never;
    circuitDigestB64u?: never;
  };

type RotatableSigningLaneJobV1 = Ed25519YaoLaneJobV1 | EcdsaAdditiveLaneJobV1;
```

Boundary validation enforces that creation has a distinct source and target
lane, first target epoch, linked-device authority, and absent target. Refresh
requires `source.laneId === target.laneId`, a strictly advancing epoch, matching
prior activation, and owner refresh authority. The source activation and
revocation epoch are pinned before any holder or server work. The target
activation ID is allocated once and cannot be reused by another lane or epoch.
For an Ed25519 job, `create_lane` maps only to `lane_provisioning` and
`refresh_lane` maps only to `lane_refresh`. For ECDSA, the source capability
must resolve the source activation exactly, target chain memberships must equal
the ordered threshold-session bindings, and every participant and recipient ID
must match the parsed lane bindings. Production lifecycle branches carry
`never` exclusions for fields owned by every other branch.

Refactor 104 may later define a disjoint delegated-execution job adapter. It
must construct this plan's validated curve inputs only after R104 admission and
cannot widen `LaneOperationAuthorizationBindingV1` or the first-release target
unions with optional agent fields.

## Protocol Receipts

Every receipt is canonical, signed by its durable owner, and digest-addressed.
Receipt verification recomputes the job transcript from the stored parsed job;
callers cannot supply a replacement transcript summary.

```ts
type LaneProtocolCommitReceiptV1 = {
  kind: 'lane_protocol_commit_receipt_v1';
  operationId: LaneOperationId;
  enrollmentId: LaneEnrollmentId;
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  sourceLaneId: SigningLaneId;
  sourceLaneShareEpoch: LaneShareEpoch;
  sourceRevocationEpoch: number;
  sourceMaterialActivation: MpcMaterialActivationRef;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivationId: MpcMaterialActivationId;
  keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  publicIdentityDigestB64u: string;
  targetHolderPublicCommitmentB64u: string;
  targetServerPublicCommitmentB64u: string;
  targetHolderCiphertextDigestSetB64u: string;
  targetServerCiphertextDigestSetB64u: string;
  holderRecipientKeyDigestB64u: string;
  serverRecipientKeyDigestB64u: string;
  transcriptHashB64u: string;
  committedAtMs: number;
};

type LaneHolderDeliveryReceiptV1 = {
  kind: 'lane_holder_delivery_receipt_v1';
  operationId: LaneOperationId;
  enrollmentId: LaneEnrollmentId;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivationId: MpcMaterialActivationId;
  holderParticipantBindingDigestB64u: string;
  holderRecipientKeyDigestB64u: string;
  holderCiphertextDigestSetB64u: string;
  sealedHolderRecordDigestB64u: string;
  transcriptHashB64u: string;
  acknowledgedAtMs: number;
};

type LaneServerActivationReceiptV1 = {
  kind: 'lane_server_activation_receipt_v1';
  operationId: LaneOperationId;
  enrollmentId: LaneEnrollmentId;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivation: MpcMaterialActivationRef;
  signingWorkerParticipantBindingDigestB64u: string;
  serverCiphertextDigestSetB64u: string;
  transcriptHashB64u: string;
  activatedAtMs: number;
};
```

For Ed25519, the commit receipt additionally verifies
`2 * X_client_lane - X_server_lane = A_pub`. For ECDSA it verifies
`X_client_target + X_server_target = X` and the exact EVM address. These
curve-specific checked facts are included in `publicIdentityDigestB64u` and in
the authoritative curve receipt retained beside this product receipt.

## Protocol Lifecycle

```ts
type LaneProtocolLifecycle =
  | {
      state: 'preparing';
      startedAtMs: number;
    }
  | {
      state: 'awaiting_protocol_commitment';
      startedAtMs: number;
    }
  | {
      state: 'committed_awaiting_holder_delivery';
      startedAtMs: number;
      committedAtMs: number;
      transcriptHashB64u: string;
      protocolCommitReceiptDigestB64u: string;
    }
  | {
      state: 'awaiting_server_activation';
      startedAtMs: number;
      committedAtMs: number;
      transcriptHashB64u: string;
      protocolCommitReceiptDigestB64u: string;
      holderDeliveryReceiptDigestB64u: string;
      holderReceiptAtMs: number;
    }
  | {
      state: 'ready_for_parent_visibility';
      startedAtMs: number;
      committedAtMs: number;
      transcriptHashB64u: string;
      protocolCommitReceiptDigestB64u: string;
      holderDeliveryReceiptDigestB64u: string;
      holderReceiptAtMs: number;
      serverActivationReceiptDigestB64u: string;
      serverActivatedAtMs: number;
    }
  | {
      state: 'active';
      transcriptHashB64u: string;
      protocolCommitReceiptDigestB64u: string;
      holderDeliveryReceiptDigestB64u: string;
      serverActivationReceiptDigestB64u: string;
      aggregateActivationReceiptDigestB64u: string;
      activatedAtMs: number;
    }
  | {
      state: 'aborted_precommit';
      startedAtMs: number;
      abortedAtMs: number;
      abortReason: LaneProtocolAbortReason;
    }
  | {
      state: 'committed_completion_required';
      startedAtMs: number;
      committedAtMs: number;
      transcriptHashB64u: string;
      protocolCommitReceiptDigestB64u: string;
      recoveryReason: LaneProtocolCompletionReason;
    };

type LaneProtocolRecordV1 = {
  job: RotatableSigningLaneJobV1;
  lifecycle: LaneProtocolLifecycle;
};
```

Only pre-commit states can abort. Committed states either reach
`ready_for_parent_visibility`, become active through the exact parent commit,
or remain fenced in
`committed_completion_required` for exact redelivery and recovery.

## Multi-Key Enrollment Activation

A linked-device creation or owner-authorized refresh has one immutable parent
manifest and one child job per target wallet key. The ordered child list is the
exact order approved by the owner authorization. Parsers reject an empty list,
duplicate wallet keys, duplicate target lanes, duplicate activation IDs,
reordering, and any child whose wallet, authorization, operation kind, or
enrollment differs from the parent.

```ts
type LaneEnrollmentManifestChildV1 = {
  operationId: LaneOperationId;
  walletKeyId: WalletKeyId;
  keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  sourceLaneId: SigningLaneId;
  sourceLaneShareEpoch: LaneShareEpoch;
  sourceRevocationEpoch: number;
  sourceMaterialActivation: MpcMaterialActivationRef;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivationId: MpcMaterialActivationId;
  holderParticipantBindingDigestB64u: string;
  signingWorkerParticipantBindingDigestB64u: string;
};

type LaneEnrollmentManifestV1 = {
  kind: 'lane_enrollment_manifest_v1';
  enrollmentId: LaneEnrollmentId;
  walletId: WalletId;
  authorization: LaneOperationAuthorizationBindingV1;
  orderedChildren: readonly [LaneEnrollmentManifestChildV1, ...LaneEnrollmentManifestChildV1[]];
  createdAtMs: number;
  expiresAtMs: number;
};

type AggregateLaneActivationChildReceiptV1 = {
  operationId: LaneOperationId;
  walletKeyId: WalletKeyId;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivation: MpcMaterialActivationRef;
  protocolCommitReceiptDigestB64u: string;
  holderDeliveryReceiptDigestB64u: string;
  serverActivationReceiptDigestB64u: string;
};

type AggregateLaneActivationReceiptV1 = {
  kind: 'aggregate_lane_activation_receipt_v1';
  enrollmentId: LaneEnrollmentId;
  walletId: WalletId;
  manifestDigestB64u: string;
  orderedChildReceipts: readonly [
    AggregateLaneActivationChildReceiptV1,
    ...AggregateLaneActivationChildReceiptV1[],
  ];
  activatedAtMs: number;
};

type CommitLaneEnrollmentActivationV1 = {
  kind: 'commit_lane_enrollment_activation_v1';
  enrollmentId: LaneEnrollmentId;
  walletId: WalletId;
  manifestDigestB64u: string;
  orderedChildReceipts: readonly [
    AggregateLaneActivationChildReceiptV1,
    ...AggregateLaneActivationChildReceiptV1[],
  ];
  activatedAtMs: number;
};
```

The manifest digest uses the domain
`seams/rotatable-signing-lanes/enrollment-manifest/v1` and the repository's
canonical length-prefixed digest encoding. The exact encoding is frozen here:

```text
LP32(x) = BE32(byte_length(x)) || x
TEXT(x) = LP32(UTF8(x))
U64(x)  = unsigned 64-bit big-endian x
DIGEST(x) = LP32(BASE64URL_DECODE_CANONICAL_32(x))

AUTH(linked) =
    TEXT(linked.kind)
 || TEXT(linked.authorizedOperationId)
 || TEXT(linked.linkedDeviceEnrollmentId)
 || DIGEST(linked.linkedDevicePermissionDigestB64u)

AUTH(refresh) =
    TEXT(refresh.kind)
 || TEXT(refresh.authorizedOperationId)
 || DIGEST(refresh.ownerLaneRefreshDigestB64u)

ACTIVATION(ref) =
    TEXT(ref.kind)
 || TEXT(ref.activationId)
 || TEXT(ref.capability)
 || TEXT(ref.materialOwner)
 || TEXT(ref.keyBinding)
 || TEXT(ref.lifecycleBinding)
 || TEXT(ref.signingWorker)

CHILD(child) =
    TEXT(child.operationId)
 || TEXT(child.walletKeyId)
 || TEXT(child.keyFamily)
 || TEXT(child.sourceLaneId)
 || TEXT(child.sourceLaneShareEpoch)
 || U64(child.sourceRevocationEpoch)
 || LP32(ACTIVATION(child.sourceMaterialActivation))
 || TEXT(child.targetLaneId)
 || TEXT(child.targetLaneShareEpoch)
 || TEXT(child.targetMaterialActivationId)
 || TEXT(child.holderParticipantBindingDigestB64u)
 || TEXT(child.signingWorkerParticipantBindingDigestB64u)

MANIFEST(manifest) =
    TEXT("seams/rotatable-signing-lanes/enrollment-manifest/v1")
 || TEXT(manifest.enrollmentId)
 || TEXT(manifest.walletId)
 || LP32(AUTH(manifest.authorization))
 || U64(manifest.createdAtMs)
 || U64(manifest.expiresAtMs)
 || BE32(manifest.orderedChildren.length)
 || LP32(CHILD(manifest.orderedChildren[0]))
 || ...

manifestDigest = SHA-256(MANIFEST(manifest))
```

Every identifier is parsed into its branded domain type before encoding. Digest
strings are canonical unpadded base64url over 32 bytes. The encoder rejects
timestamps outside the safe nonnegative `u64` range and child counts outside
nonempty `u32`. No JSON serialization, object-key ordering, or Unicode
normalization participates in either digest.

The aggregate receipt encoding is also exact:

```text
ACTIVATION_CHILD(child) =
    TEXT(child.operationId)
 || TEXT(child.walletKeyId)
 || TEXT(child.targetLaneId)
 || TEXT(child.targetLaneShareEpoch)
 || LP32(ACTIVATION(child.targetMaterialActivation))
 || DIGEST(child.protocolCommitReceiptDigestB64u)
 || DIGEST(child.holderDeliveryReceiptDigestB64u)
 || DIGEST(child.serverActivationReceiptDigestB64u)

AGGREGATE(receipt) =
    TEXT("seams/rotatable-signing-lanes/aggregate-activation-receipt/v1")
 || TEXT(receipt.enrollmentId)
 || TEXT(receipt.walletId)
 || DIGEST(receipt.manifestDigestB64u)
 || U64(receipt.activatedAtMs)
 || BE32(receipt.orderedChildReceipts.length)
 || LP32(ACTIVATION_CHILD(receipt.orderedChildReceipts[0]))
 || ...

aggregateReceiptDigest = SHA-256(AGGREGATE(receipt))
```

The aggregate manifest coordinates product visibility only. It is distinct
from the landed curve-specific ECDSA capability manifest, the Yao terminal
receipt, and every child `MpcMaterialActivationRef`.

```text
Enrollment(preparing)
  -> every child protocol committed
  -> every holder package delivered and sealed
  -> every server/SigningWorker target ready
  -> aggregate receipt verifies exact manifest
  -> Enrollment(active) and child lanes active
```

The parent lifecycle is exhaustive:

```ts
type LaneEnrollmentLifecycleV1 =
  | { state: 'preparing'; manifestDigestB64u: string; startedAtMs: number }
  | {
      state: 'committed_completion_required';
      manifestDigestB64u: string;
      committedChildOperationIds: readonly [LaneOperationId, ...LaneOperationId[]];
      markedAtMs: number;
    }
  | {
      state: 'ready_for_visibility';
      manifestDigestB64u: string;
      aggregateReceiptDigestB64u: string;
      readyAtMs: number;
    }
  | {
      state: 'active';
      manifestDigestB64u: string;
      aggregateReceiptDigestB64u: string;
      activatedAtMs: number;
    }
  | { state: 'cancelled_precommit'; cancelledAtMs: number }
  | {
      state: 'revoking_committed_targets';
      manifestDigestB64u: string;
      reason: 'cancelled_after_commit' | 'expired_after_commit' | 'revoked_during_activation';
      markedAtMs: number;
    }
  | {
      state: 'revoked';
      manifestDigestB64u: string;
      aggregateRevocationReceiptDigestB64u: string;
      revokedAtMs: number;
    };
```

### Activation Effect Order

1. Gateway D1 atomically admits the owner operation and inserts the immutable
   parent manifest plus every provisioning child. No child is signable.
2. Each curve protocol commits exact target ciphertexts and its protocol
   receipt. SigningWorker private D1 durably stores the holder ciphertext,
   server ciphertext/material, transcript, and delivery state keyed by the
   child operation. Router stores nothing.
3. Device 2 fetches the committed holder ciphertext under an authenticated
   delivery claim bound to the enrollment, target participant, original HPKE
   recipient-key digest, and transcript. It verifies and seals the holder
   material, then returns `LaneHolderDeliveryReceiptV1`.
4. After that exact holder receipt, Gateway sends an idempotent server-activation
   command. SigningWorker activates the target material under the lane, epoch,
   and fresh activation ID and returns `LaneServerActivationReceiptV1`. The
   parent remains inactive, so Gateway cannot issue an execution admission.
5. Once every child has matching protocol, holder, and server receipts, Gateway
   recomputes the manifest and aggregate receipt. One Gateway D1 transaction
   stores the aggregate receipt, marks every child lane active with its exact
   `MpcMaterialActivationRef`, and changes the parent to `active`.
6. Only after that transaction may Refactor 103 mint the linked-device Wallet
   Session authorization. Signing admission requires both the active parent and
   exact active child.

### Atomic Visibility Commit

`CommitLaneEnrollmentActivationV1` is the only command that can make these
lanes product-visible. Gateway parses it, reloads the immutable parent and child
rows inside one D1 transaction, and requires all of the following:

- the parent is `ready_for_visibility` with the exact manifest digest, or is
  already `active` with the exact aggregate receipt digest for idempotent replay;
- the command child count and order equal the manifest exactly;
- every child is `ready_for_parent_visibility` and its operation, wallet key,
  target lane, target epoch, activation reference, and three receipt digests
  equal the command and stored protocol state;
- every target lane is still non-signable at its expected pre-state, every
  activation ID is unique, and no revocation epoch advanced after admission;
- recomputing `MANIFEST` and `AGGREGATE` yields the supplied manifest digest and
  the receipt digest recorded by the parent transition.

The transaction inserts the aggregate receipt, marks every exact child lane and
protocol lifecycle `active`, and marks the parent `active`. It performs no
network call and has no partial-success branch. A mismatched active replay is a
conflict. Any failed precondition leaves every row unchanged. Unique constraints
cover `(wallet_key_id, lane_id, lane_share_epoch)`, material activation ID, child
operation ID, and enrollment ID. Server activation remains private and unusable
until this transaction succeeds.

Private server activation deliberately precedes public product visibility. A
crash in that interval leaves unusable private material because no active parent
can authorize it. Replaying the exact activation command returns the same
receipt, and replaying the Gateway visibility transaction returns the same
active enrollment.

### Crash, Expiry, And Redelivery

- Before any child reaches protocol commitment, cancellation or expiry aborts
  all children and writes `cancelled_precommit`.
- After any child commits, the parent can no longer abort. It enters
  `committed_completion_required`; committed children are redelivered exactly,
  while missing pre-commit children may start once with their allocated IDs.
- SigningWorker private D1 retains committed holder ciphertext and its receipt
  until the enrollment is active or durably revoked. Link-session expiry never
  deletes committed output.
- A fresh authenticated resume claim may retrieve only the same ciphertext for
  the same participant and recipient-key digest. It cannot substitute a new
  recipient key or trigger reevaluation. Loss of the matching private key forces
  revocation of the committed target and a new enrollment.
- A crash after holder delivery replays server activation. A crash after server
  activation replays the Gateway visibility commit. A crash after visibility
  returns the stored aggregate receipt.
- Cancellation, expiry, or revocation after commitment moves the parent to
  `revoking_committed_targets`. The system finishes receipt accounting,
  disables every activated server target, marks all children revoked, and then
  stores one aggregate revocation receipt. The parent never becomes active.

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
- keep Wallet Session expiry and quota exhaustion as admission outcomes that
  preserve lane material and activation; a future delegated adapter must apply
  the same rule to delegated-authorization expiry;
- make every activation and receipt idempotent for the exact transcript.

## Owner Lane Refresh

Owner passkey or Email OTP lane refresh uses the protocol for its wallet-key
family:

- Ed25519: `F_ed25519_lane_refresh_v1` through the lane-materialization circuit;
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
It is outside the first implementation and does not add optional fields or a
third authorization branch to the linked-device and owner-refresh job unions
above. Refactor 104 owns a disjoint adapter request and must normalize it into
the already validated curve protocol only after its own admission commits.
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
  retirementReason: 'lane_revoked' | 'device_compromise' | 'agent_compromise' | 'rotation';
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

The compromise response is fixed:

| Evidence                                                                  | Immediate response                                         | Follow-up                                                           |
| ------------------------------------------------------------------------- | ---------------------------------------------------------- | ------------------------------------------------------------------- |
| holder-only loss or suspected compromise                                  | revoke that lane and disable its server participant        | provision a replacement lane with fresh owner approval              |
| server-only lane-material compromise                                      | revoke that lane and destroy/retire the exact server epoch | refresh or reprovision that lane after server isolation is restored |
| both participants of one lane may be compromised                          | revoke every lane for the wallet key and stop signing      | wallet rekey; lane refresh cannot restore secrecy of the old key    |
| Yao stable root, ECDSA root custody, or complete wallet key compromise    | stop every affected wallet-key operation                   | wallet rekey under the authoritative root-custody protocol          |
| recipient private key lost after output commitment                        | finish receipt accounting and revoke the committed target  | start a new enrollment with a new recipient key                     |
| enrollment authorization or device identity compromised before visibility | fence the parent and revoke all committed targets          | new owner-approved enrollment                                       |

A replacement lane always requires fresh owner approval. Refresh is appropriate
only when the wallet key itself and at least one side of the lane remain trusted.

## Current Implementation Gaps

- `ShareRotationJob` treats Ed25519 and ECDSA as one protocol family.
- the dormant `AdditiveDeltaReshareCommitment` type lacks a key-family,
  operation, lane, and epoch binding;
- job lifecycle omits committed delivery and forward-only recovery states;
- source-lane creation and same-lane refresh share overly broad types;
- parent enrollment activation and aggregate receipts do not exist;
- the frozen Yao `lane_provisioning` and `lane_refresh` request kinds and
  lane-materialization circuit are not implemented;
- ECDSA additive target-lane resharing is unimplemented;
- Refactor 90's canonical ECDSA manifest, activation journal, hydration, and
  exact `MpcMaterialActivationRef` are landed; the lane-aware source-material
  adapter remains open;
- the exact ECDSA lane-retirement receipt and lane-specific hydration mapping
  remain open;
- Gateway, SigningWorker, and Deriver owner adapters for lane delivery and
  activation remain open;
- Refactor 101 owner-lane projection and normal-signing admission are landed;
  independently provisioned lanes must extend that exact lookup without a
  parallel admission path.

Replace these scaffolds directly. Do not retain a universal rotation job or
protocol fallback.

## Parallel Delivery Strategy

R102 uses four implementation subagents after one short contract seed owned by
the integrator. The seed is the only serial step. It freezes:

- curve-specific lane-create and lane-refresh job unions;
- canonical transcript, protocol-receipt, activation-receipt, and retirement-
  receipt encodings;
- forward-only lifecycle states and legal transitions;
- fresh target `MpcMaterialActivationId` rules;
- aggregate child-manifest and enrollment-receipt shapes;
- exact Rust, WASM, TypeScript, Gateway, and worker port names;
- versioned CAS outcomes and exact-replay behavior;
- a persisted lane-epoch product record that represents pending visibility,
  active, retired, and revoked epochs without duplicating projected owner
  lanes.

The integrator owns these seed files:

- `packages/shared-ts/src/signing-lanes/rotation.ts`;
- `packages/shared-ts/src/signing-lanes/rotationParsers.ts`;
- `packages/shared-ts/src/signing-lanes/rotationDigests.ts`;
- `packages/shared-ts/src/signing-lanes/rotationLifecycle.ts`;
- `packages/shared-ts/src/signing-lanes/rotation.typecheck.ts`;
- the signing-lanes barrel export.

The seed contains types, parsers, canonical encoders, builders, transition
functions, interfaces, and static fixtures only. It does not implement crypto,
persistence, route behavior, browser orchestration, or compatibility paths.
Every subagent receives one positive cross-language fixture and one
field-substitution fixture for each wire record it consumes.

### Subagent 1: ECDSA Additive Lane Protocol

Own ECDSA protocol crates, ECDSA Client and SigningWorker WASM, and isolated
ECDSA lane adapter modules. The integrator owns shared contracts and central
Cloudflare dispatch files.

- resolve the exact R101 source lane and R90 capability manifest;
- sample target holder material and keep the additive delta transient;
- bind the source lane, target lane, epochs, participants, activation,
  recipient, server generation, and threshold sessions;
- verify threshold-public-key and EVM-address continuity;
- emit exact server activation and retirement receipts;
- add replay, parity, substitution, tamper, and zeroization vectors.

Primary owned modules:

- `crates/router-ab-ecdsa-client-protocol/src/lane_resharing.rs`;
- ECDSA lane primitives under `crates/router-ab-ecdsa-derivation/`;
- `wasm/router_ab_ecdsa_client/src/lane_resharing.rs`;
- `wasm/router_ab_ecdsa_signing_worker/src/lane_resharing.rs`;
- focused Rust, WASM, and frozen-vector tests.

Expose pure protocol functions and typed ports. JavaScript never receives a
plaintext target share or additive delta. Do not add Gateway routes, aggregate
state, browser APIs, or shared contract variants.

### Subagent 2: Ed25519 Streaming Yao Protocol

Own Ed25519-Yao protocol and circuit code, Yao client WASM, and new isolated
Ed25519 adapter modules. The integrator owns central Cloudflare dispatch files.

- implement `lane_provisioning` and `lane_refresh`;
- create isolated Client and SigningWorker target packages;
- preserve registered `A_pub` byte-for-byte;
- implement output commitment, exact redelivery, and forward-only recovery;
- preserve zero-Deriver ordinary signing;
- add recipient-swap, package-substitution, replay, and commitment-recovery
  vectors.

Primary owned modules:

- the lane family in `crates/router-ab-core/src/protocol/ed25519_yao.rs`;
- new lane modules in `crates/router-ab-ed25519-yao-protocol/`,
  `crates/router-ab-ed25519-yao/`, and
  `crates/router-ab-ed25519-yao-client/`;
- the distinct lane-materialization circuit and fixtures under
  `tools/ed25519-yao-generator/`;
- narrow passive-runtime package/schedule additions under
  `crates/ed25519-yao/`;
- focused Yao, circuit, recipient, and redelivery vectors.

This lane is the critical path and starts immediately after the contract seed.
It must use distinct lane package tags and circuit digests; activation or export
families cannot be reused.

### Subagent 3: Gateway Persistence And Aggregate Lifecycle

Own `packages/sdk-server-ts/src/core/signingLanes/`, new isolated D1 store
modules, and their focused tests.

- replace blind-write scaffolds with versioned CAS stores and exact replay;
- persist curve-specific job lifecycle and product-epoch records;
- implement wallet-key and enrollment locks;
- persist parent enrollment manifests without duplicating curve capability
  state;
- commit child-lane visibility atomically;
- reconcile crashes and exact redelivery;
- fence revocation ahead of creation, refresh, and queued signing;
- revoke aggregate enrollments while preserving unrelated owner lanes.

Primary owned modules:

- lifecycle, effect-journal, aggregate activation, and revocation ports under
  `packages/sdk-server-ts/src/core/signingLanes/`;
- one normalized D1 migration for enrollment, operation, product-epoch,
  receipt, effect-journal, and lock records;
- isolated D1 implementations under
  `packages/sdk-server-ts/src/router/cloudflare/d1/signingLanes/`;
- focused CAS, crash-reconciliation, atomic-visibility, and revocation tests.

Build against typed fake curve receipts from the contract seed. The atomic
visibility transaction performs zero network calls. Do not edit route
definitions, dependency injection, public SDK files, or canonical owner-lane
projection.

### Subagent 4: Browser And Worker Orchestration

Own SDK worker channels, WASM adapters, lane-operation coordinators, and their
focused tests.

- generate holder recipient keys inside the worker boundary;
- invoke the curve-specific WASM operations;
- seal and persist target holder material;
- reconcile activation journals before capability hydration;
- invalidate warm handles after refresh or revocation;
- exercise the workflow through fake Gateway and WASM ports.

Primary owned modules:

- isolated coordinators under
  `packages/sdk-web/src/core/signingEngine/session/lanes/operations/`;
- isolated `laneWorkerChannels.ts` and curve-specific lane WASM adapters;
- lane-scoped sealed holder persistence;
- narrow linked-lane support in `walletExecutionLaneHydration.ts`;
- exact activation invalidation in Ed25519 and ECDSA runtime registries;
- worker-boundary, delivery, hydration, invalidation, and crash tests.

Build against fake Gateway and WASM ports immediately after the seed. Recipient
private keys and plaintext lane material remain worker-bound. Hydration uses the
exact lane `MpcMaterialActivationRef`; chain-only or wallet-only selection is
forbidden. Do not edit public API unions, iframe messages, central worker
registration, dependency injection, or shared domain contracts.

### Integrator Ownership

Only the integrator edits:

- the contract-seed files listed above;
- route definitions and fetch-router registration;
- server dependency injection and central service barrels;
- central Cloudflare route dispatch;
- SDK public APIs and iframe message unions;
- central worker registration;
- shared test helpers, source guards, and this plan;
- cross-curve activation, refresh, and revocation tests.

The integrator also removes the obsolete universal rotation store and transcript
types after all consumers move to the frozen contracts. No subagent restores
another subagent's files, adds compatibility shims, or edits outside its
ownership. Every subagent commits only its owned files.

### Execution Waves

With four child-agent slots, all four subagents start immediately after the
seed:

```text
contract seed — root integrator

parallel implementation
  Subagent 1: ECDSA protocol and vectors
  Subagent 2: Ed25519 Yao protocol, circuit, and vectors
  Subagent 3: Gateway persistence and aggregate lifecycle
  Subagent 4: browser and worker orchestration against fake ports
  root: central wiring, review, and cross-curve integration
```

The current Codex session permits the root plus three child agents. In that
environment, start Subagents 1, 2, and 3 first. The root performs central
integration scaffolding, then Subagent 4 starts as soon as either crypto agent
finishes its first mergeable slice. This is a scheduling limit rather than a
technical dependency: Subagent 4 builds against frozen fake ports, and
Subagent 3 uses fake curve receipts.

Each subagent delivers small mergeable slices instead of one terminal commit:

1. boundary types and positive-path adapter;
2. lifecycle or secret-containment behavior;
3. adversarial and replay tests;
4. cleanup of superseded owned scaffolds.

The integrator merges by contract dependency, not by completion time: seed,
pure curve adapters, stores, browser adapters, central wiring, then broad tests.

### Per-Lane Merge Gates

- shared domain: shared-ts typecheck plus invalid-state fixtures;
- ECDSA: Rust vectors, WASM checks, public-identity continuity, and zeroization;
- Ed25519: Yao vectors, circuit checks, redelivery, and `A_pub` continuity;
- Gateway: D1 CAS, crash reconciliation, fencing, and atomic visibility tests;
- browser: sdk-web typecheck and worker-boundary tests.

The integrator performs one broad validation wave after the narrow gates pass.
Subagents do not independently run the full repository suite.

## Implementation Phases

### Phase 0: Freeze Protocol Ownership

- [x] Adopt Refactor 90's landed curve-specific canonical hydration and ECDSA
      manifest as the source of truth; do not introduce a cross-curve manifest.
- [x] Add `lane_provisioning` and `lane_refresh` to the Yao specification and
      freeze their ideal relations, circuit family, recipient isolation,
      request mapping, and forward-only lifecycle.
- [x] Freeze ECDSA additive target-lane resharing and transcript encoding using
      operation-scoped proof commitments, without a signed commitment-policy
      registry.
- [x] Freeze aggregate manifest and receipt encodings, private activation before
      product visibility, crash recovery, exact redelivery, and post-commit
      revocation semantics.

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

- [ ] Add owner and linked-device lane refresh. Refactor 104 owns any later
      delegated-execution adapter.
- [ ] Add immediate lane and aggregate enrollment revocation.
- [ ] Invalidate warm capabilities and reject stale epochs.
- [ ] Ensure Wallet Session expiry preserves active lane material and activation
      references; require the same property from future authorization adapters.
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
- linked-device enrollment authority and owner-refresh authority cannot be
  interchanged;
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
- ECDSA source-manifest, server-generation, recipient, channel-binding, target
  threshold-session, and chain-membership substitution fail;
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

## Decisions Resolved Before Implementation

- Refactor 101 exact wallet-key, owner-lane, participant-continuity, and active
  admission records are landed.
- Existing owner records use canonical `OwnerLaneParticipantContinuityV1`;
  independently provisioned linked-device and delegated lanes use the full
  holder and SigningWorker participant records.
- R102 job, receipt, and enrollment encodings consume those canonical digests
  directly. They do not introduce another participant identity or digest path.
- Normal signing already fails before private work when owner-lane projection
  or admission is unavailable. R102 extends the same lookup for independently
  provisioned lanes.
