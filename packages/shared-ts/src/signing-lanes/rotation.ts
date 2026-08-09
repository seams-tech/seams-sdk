import type { AuthorizedOperationId } from '../authorization/capabilityKinds';
import type { KeyCreationSignerSlot } from '../passkey-custody/primitives';
import type {
  MpcMaterialActivationId,
  MpcMaterialActivationRef,
  ThresholdEcdsaSessionId,
  WalletId,
} from '../utils/domainIds';
import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
  EcdsaLifecycleId,
  EcdsaServerGeneration,
} from '../utils/ecdsaCapabilityActivation';
import type { CorrelationId, IsoTimestamp } from '../utils/canonicalPrimitives';
import type { NearEd25519SigningKeyId } from '../utils/registrationIntent';
import type { EcdsaThresholdKeyId } from '../threshold/ecdsaDerivationRoleLocalBootstrap';
import type {
  EcdsaManifestIdentity,
  EcdsaRelayerKeyId,
  Ed25519YaoSuiteId,
  LaneEnrollmentId,
  LaneOperationId,
  LaneOperationIdempotencyKey,
  LaneShareEpoch,
  LinkedDeviceEnrollmentId,
  SigningLaneId,
  ThresholdEcdsaChainTarget,
  WalletKeyId,
} from './ids';
import type {
  LaneHolderParticipantId,
  SigningWorkerParticipantId,
  SigningWorkerRecipientKeyId,
} from './participants';
import type { EvmFamilySigningKeySlotId } from './evmFamilySigningKeySlotId';
import type { SigningLaneKind } from './records';

export type LinkedDeviceLaneAuthorizationBindingV1 = {
  kind: 'linked_device_enrollment';
  authorizedOperationId: AuthorizedOperationId;
  linkedDeviceEnrollmentId: LinkedDeviceEnrollmentId;
  linkedDevicePermissionDigestB64u: string;
  ownerLaneRefreshDigestB64u?: never;
};

export type OwnerLaneRefreshAuthorizationBindingV1 = {
  kind: 'owner_lane_refresh';
  authorizedOperationId: AuthorizedOperationId;
  ownerLaneRefreshDigestB64u: string;
  linkedDevicePermissionDigestB64u?: never;
};

export type LaneOperationAuthorizationBindingV1 =
  | LinkedDeviceLaneAuthorizationBindingV1
  | OwnerLaneRefreshAuthorizationBindingV1;

export type ActiveLaneProtocolSourceV1 = {
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

export type LaneTargetHolderV1 = {
  participantId: LaneHolderParticipantId;
  participantBindingDigestB64u: string;
  custodyBindingDigestB64u: string;
  hpkePublicKeyB64u: string;
  hpkePublicKeyDigestB64u: string;
};

export type LaneTargetSigningWorkerV1 = {
  participantId: SigningWorkerParticipantId;
  participantBindingDigestB64u: string;
  recipientKeyId: SigningWorkerRecipientKeyId;
  hpkePublicKeyB64u: string;
  hpkePublicKeyDigestB64u: string;
};

export type LaneCreationTargetV1 = {
  operation: 'create_lane';
  laneId: SigningLaneId;
  laneKind: 'linked_device';
  laneShareEpoch: LaneShareEpoch;
  expectedTargetState: 'absent';
  priorMaterialActivation?: never;
};

export type LaneRefreshTargetV1 = {
  operation: 'refresh_lane';
  laneId: SigningLaneId;
  laneKind:
    | 'owner_passkey'
    | 'owner_email_otp'
    | 'linked_device'
    | 'recovery'
    | 'break_glass';
  laneShareEpoch: LaneShareEpoch;
  expectedTargetState: 'active_previous_epoch';
  priorMaterialActivation: MpcMaterialActivationRef;
};

export type EcdsaTargetThresholdSessionBindingV1 = {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: ThresholdEcdsaSessionId;
  participantBindingDigestB64u: string;
};

export type EcdsaSourceCapabilityBindingV1 = {
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
  serverGeneration: EcdsaServerGeneration;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  relayerKeyId: EcdsaRelayerKeyId;
};

export type EcdsaTargetCapabilityBindingV1 = {
  manifestId: EcdsaCapabilityManifestId;
  manifestRevision: EcdsaCapabilityManifestRevision;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  orderedThresholdSessions: readonly [
    EcdsaTargetThresholdSessionBindingV1,
    ...EcdsaTargetThresholdSessionBindingV1[],
  ];
};

export type LaneProtocolJobCommonV1 = {
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

export type LaneCreationOperationV1 = {
  target: LaneCreationTargetV1;
  authorization: LinkedDeviceLaneAuthorizationBindingV1;
};

export type LaneRefreshOperationV1 = {
  target: LaneRefreshTargetV1;
  authorization: OwnerLaneRefreshAuthorizationBindingV1;
};

export type LaneProtocolOperationV1 = LaneCreationOperationV1 | LaneRefreshOperationV1;

export type Ed25519YaoLaneJobCurveV1 = {
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

export type Ed25519YaoLaneJobV1 = LaneProtocolJobCommonV1 &
  Ed25519YaoLaneJobCurveV1 &
  (
    | (LaneCreationOperationV1 & { yaoRequestKind: 'lane_provisioning' })
    | (LaneRefreshOperationV1 & { yaoRequestKind: 'lane_refresh' })
  );

export type EcdsaAdditiveLaneJobV1 = LaneProtocolJobCommonV1 &
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

export type RotatableSigningLaneJobV1 = Ed25519YaoLaneJobV1 | EcdsaAdditiveLaneJobV1;

export type LaneProtocolCommitReceiptV1 = {
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

export type LaneHolderDeliveryReceiptV1 = {
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

export type LaneServerActivationReceiptV1 = {
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

export type LaneProtocolAbortReason =
  | 'cancelled'
  | 'expired'
  | 'revoked_before_commit';

export type LaneProtocolCompletionReason =
  | 'exact_redelivery_required'
  | 'recovery_required';

export type LaneProtocolLifecycle =
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

export type LaneProtocolRecordV1 = {
  job: RotatableSigningLaneJobV1;
  lifecycle: LaneProtocolLifecycle;
};

export type LaneEnrollmentManifestChildV1 = {
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

export type LaneEnrollmentManifestV1 = {
  kind: 'lane_enrollment_manifest_v1';
  enrollmentId: LaneEnrollmentId;
  walletId: WalletId;
  authorization: LaneOperationAuthorizationBindingV1;
  orderedChildren: readonly [
    LaneEnrollmentManifestChildV1,
    ...LaneEnrollmentManifestChildV1[],
  ];
  createdAtMs: number;
  expiresAtMs: number;
};

export type AggregateLaneActivationChildReceiptV1 = {
  operationId: LaneOperationId;
  walletKeyId: WalletKeyId;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivation: MpcMaterialActivationRef;
  protocolCommitReceiptDigestB64u: string;
  holderDeliveryReceiptDigestB64u: string;
  serverActivationReceiptDigestB64u: string;
};

export type AggregateLaneActivationReceiptV1 = {
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

export type CommitLaneEnrollmentActivationV1 = {
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

export type LaneEnrollmentLifecycleV1 =
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

export type EcdsaServerRetirementReceipt = {
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
