import type { AuthorizedOperationId } from '../authorization/capabilityKinds';
import type { KeyCreationSignerSlot } from '../passkey-custody/primitives';
import type {
  MpcMaterialActivationId,
  MpcMaterialActivationRef,
  ThresholdEcdsaSessionId,
  WalletId,
  LaneHolderRecipientHandleV1,
} from '../utils/domainIds';
import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
  EcdsaLifecycleId,
  EcdsaServerGeneration,
} from '../utils/ecdsaCapabilityActivation';
import type { CorrelationId, DigestB64u, IsoTimestamp } from '../utils/canonicalPrimitives';
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
  HpkePublicKeyB64u,
  HpkePublicKeyDigestB64u,
  LaneCustodyBindingDigestB64u,
  LaneParticipantBindingDigestB64u,
  LaneHolderCustodyBindingId,
  SigningWorkerParticipantId,
  SigningWorkerRecipientKeyId,
  LaneHolderParticipantRecordV1,
  SigningWorkerParticipantRecordV1,
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
  participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
  custodyBindingId: LaneHolderCustodyBindingId;
  custodyBindingDigestB64u: LaneCustodyBindingDigestB64u;
  hpkePublicKeyB64u: HpkePublicKeyB64u;
  hpkePublicKeyDigestB64u: HpkePublicKeyDigestB64u;
};

export type LaneTargetSigningWorkerV1 = {
  participantId: SigningWorkerParticipantId;
  participantBindingDigestB64u: LaneParticipantBindingDigestB64u;
  recipientKeyId: SigningWorkerRecipientKeyId;
  hpkePublicKeyB64u: HpkePublicKeyB64u;
  hpkePublicKeyDigestB64u: HpkePublicKeyDigestB64u;
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
  laneKind: 'owner_passkey' | 'owner_email_otp' | 'linked_device' | 'recovery' | 'break_glass';
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

type EcdsaAdditiveLaneJobCurveV1 = {
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

export type Ed25519YaoLaneCreationJobV1 = LaneProtocolJobCommonV1 &
  Ed25519YaoLaneJobCurveV1 &
  LaneCreationOperationV1 & { yaoRequestKind: 'lane_provisioning' };

export type Ed25519YaoLaneRefreshJobV1 = LaneProtocolJobCommonV1 &
  Ed25519YaoLaneJobCurveV1 &
  LaneRefreshOperationV1 & { yaoRequestKind: 'lane_refresh' };

export type Ed25519YaoLaneJobV1 = Ed25519YaoLaneCreationJobV1 | Ed25519YaoLaneRefreshJobV1;

export type EcdsaAdditiveLaneCreationJobV1 = LaneProtocolJobCommonV1 &
  LaneCreationOperationV1 &
  EcdsaAdditiveLaneJobCurveV1;

export type EcdsaAdditiveLaneRefreshJobV1 = LaneProtocolJobCommonV1 &
  LaneRefreshOperationV1 &
  EcdsaAdditiveLaneJobCurveV1;

export type EcdsaAdditiveLaneJobV1 = EcdsaAdditiveLaneCreationJobV1 | EcdsaAdditiveLaneRefreshJobV1;

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

export type LaneProtocolAbortReason = 'cancelled' | 'expired' | 'revoked_before_commit';

export type LaneProtocolCompletionReason = 'exact_redelivery_required' | 'recovery_required';

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

export type EcdsaAdditiveLaneTranscriptPreambleV1 = {
  kind: 'ecdsa_additive_lane_transcript_preamble_v1';
  job: EcdsaAdditiveLaneJobV1;
};

export type EcdsaAdditiveLaneHolderRoundV1 = {
  kind: 'ecdsa_additive_lane_holder_round_v1';
  preambleHashB64u: string;
  targetHolderPublicCommitment33B64u: string;
  encryptedDeltaCiphertextDigestB64u: string;
  sealedTargetHolderMaterialDigestB64u: string;
  holderAttestationB64u: string;
  holderCommittedAtMs: number;
};

export type EcdsaAdditiveLaneServerRoundV1 = {
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

export type EcdsaAdditiveLaneTranscriptV1 = {
  kind: 'ecdsa_additive_lane_transcript_v1';
  preambleHashB64u: string;
  holderRoundHashB64u: string;
  serverRoundHashB64u: string;
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
  orderedChildren: readonly [LaneEnrollmentManifestChildV1, ...LaneEnrollmentManifestChildV1[]];
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

export type EcdsaServerRetirementReceiptV1 = {
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

export type LaneServerRetirementReceiptV1 = EcdsaServerRetirementReceiptV1;

export type LaneProductEpochRecordCommonV1 = {
  kind: 'lane_product_epoch_record_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneKind: SigningLaneKind;
  laneShareEpoch: LaneShareEpoch;
  keyFamily: 'ed25519' | 'ecdsa_secp256k1';
  enrollmentId: LaneEnrollmentId;
  operationId: LaneOperationId;
  targetMaterialActivationId: MpcMaterialActivationId;
  materialActivation: MpcMaterialActivationRef;
  publicIdentityDigestB64u: string;
  holderParticipant: LaneHolderParticipantRecordV1;
  signingWorkerParticipant: SigningWorkerParticipantRecordV1;
  participantSetBindingDigestB64u: LaneParticipantBindingDigestB64u;
  revocationEpoch: number;
  createdAtMs: number;
};

export type LaneProductEpochPendingVisibilityV1 = LaneProductEpochRecordCommonV1 & {
  state: 'pending_visibility';
  aggregateManifestDigestB64u: string;
  protocolCommitReceiptDigestB64u: string;
  holderDeliveryReceiptDigestB64u: string;
  serverActivationReceiptDigestB64u: string;
  pendingSinceMs: number;
  activatedAtMs?: never;
  retiredAtMs?: never;
  retirementReason?: never;
  retirementReceiptDigestB64u?: never;
  revokedAtMs?: never;
  revocationReason?: never;
  revocationReceiptDigestB64u?: never;
  retirementEffectBindingDigestB64u?: never;
  revocationRequestedAtMs?: never;
};

export type LaneProductEpochActiveV1 = LaneProductEpochRecordCommonV1 & {
  state: 'active';
  aggregateManifestDigestB64u: string;
  aggregateActivationReceiptDigestB64u: string;
  activatedAtMs: number;
  pendingSinceMs?: never;
  protocolCommitReceiptDigestB64u?: never;
  holderDeliveryReceiptDigestB64u?: never;
  serverActivationReceiptDigestB64u?: never;
  retiredAtMs?: never;
  retirementReason?: never;
  retirementReceiptDigestB64u?: never;
  revokedAtMs?: never;
  revocationReason?: never;
  revocationReceiptDigestB64u?: never;
  retirementEffectBindingDigestB64u?: never;
  revocationRequestedAtMs?: never;
};

export type LaneProductEpochRetiredV1 = LaneProductEpochRecordCommonV1 & {
  state: 'retired';
  retirementReason: 'rotation' | 'device_compromise' | 'agent_compromise';
  retirementReceiptDigestB64u: string;
  retiredAtMs: number;
  pendingSinceMs?: never;
  aggregateManifestDigestB64u?: never;
  protocolCommitReceiptDigestB64u?: never;
  holderDeliveryReceiptDigestB64u?: never;
  serverActivationReceiptDigestB64u?: never;
  aggregateActivationReceiptDigestB64u?: never;
  activatedAtMs?: never;
  revokedAtMs?: never;
  revocationReason?: never;
  revocationReceiptDigestB64u?: never;
  retirementEffectBindingDigestB64u?: never;
  revocationRequestedAtMs?: never;
};

export type LaneProductEpochRevocationPendingV1 = LaneProductEpochRecordCommonV1 & {
  state: 'revocation_pending';
  revocationReason:
    | 'user_revoked'
    | 'policy_revoked'
    | 'device_compromise'
    | 'agent_compromise'
    | 'rotation';
  retirementEffectBindingDigestB64u: string;
  revocationRequestedAtMs: number;
  pendingSinceMs?: never;
  aggregateManifestDigestB64u?: never;
  protocolCommitReceiptDigestB64u?: never;
  holderDeliveryReceiptDigestB64u?: never;
  serverActivationReceiptDigestB64u?: never;
  aggregateActivationReceiptDigestB64u?: never;
  activatedAtMs?: never;
  retiredAtMs?: never;
  retirementReason?: never;
  retirementReceiptDigestB64u?: never;
  revokedAtMs?: never;
  revocationReceiptDigestB64u?: never;
};

export type LaneProductEpochRevokedV1 = LaneProductEpochRecordCommonV1 & {
  state: 'revoked';
  revocationReason:
    | 'user_revoked'
    | 'policy_revoked'
    | 'device_compromise'
    | 'agent_compromise'
    | 'rotation';
  retirementEffectBindingDigestB64u: string;
  revocationReceiptDigestB64u: string;
  revokedAtMs: number;
  pendingSinceMs?: never;
  aggregateManifestDigestB64u?: never;
  protocolCommitReceiptDigestB64u?: never;
  holderDeliveryReceiptDigestB64u?: never;
  serverActivationReceiptDigestB64u?: never;
  aggregateActivationReceiptDigestB64u?: never;
  activatedAtMs?: never;
  retiredAtMs?: never;
  retirementReason?: never;
  retirementReceiptDigestB64u?: never;
  revocationRequestedAtMs?: never;
};

export type LaneProductEpochRecordV1 =
  | LaneProductEpochPendingVisibilityV1
  | LaneProductEpochActiveV1
  | LaneProductEpochRetiredV1
  | LaneProductEpochRevocationPendingV1
  | LaneProductEpochRevokedV1;

export type CompleteSigningLaneRevocationV1 = {
  kind: 'complete_signing_lane_revocation_v1';
  command: RevokeSigningLaneV1;
  expectedVersion: number;
  commandDigestB64u: string;
  retirementReceipt: LaneServerRetirementReceiptV1;
  revokedAtMs: number;
};

export type AggregateLaneRevocationChildReceiptV1 = {
  operationId: LaneOperationId;
  walletKeyId: WalletKeyId;
  targetLaneId: SigningLaneId;
  targetLaneShareEpoch: LaneShareEpoch;
  targetMaterialActivation: MpcMaterialActivationRef;
  revocationEpoch: number;
  retirementReceiptDigestB64u: string;
};

export type AggregateLaneRevocationReceiptV1 = {
  kind: 'aggregate_lane_revocation_receipt_v1';
  enrollmentId: LaneEnrollmentId;
  walletId: WalletId;
  manifestDigestB64u: string;
  orderedChildReceipts: readonly [
    AggregateLaneRevocationChildReceiptV1,
    ...AggregateLaneRevocationChildReceiptV1[],
  ];
  revokedAtMs: number;
};

export type RevokeLaneEnrollmentV1 = {
  kind: 'revoke_lane_enrollment_v1';
  enrollmentId: LaneEnrollmentId;
  walletId: WalletId;
  manifestDigestB64u: string;
  reason:
    | 'cancelled_after_commit'
    | 'expired_after_commit'
    | 'revoked_during_activation'
    | 'user_revoked'
    | 'device_compromise'
    | 'agent_compromise';
  requestedAtMs: number;
};

export type RevokeSigningLaneV1 = {
  kind: 'revoke_signing_lane_v1';
  walletId: WalletId;
  walletKeyId: WalletKeyId;
  laneId: SigningLaneId;
  laneShareEpoch: LaneShareEpoch;
  expectedRevocationEpoch: number;
  reason: 'user_revoked' | 'policy_revoked' | 'device_compromise' | 'agent_compromise' | 'rotation';
  retirementCorrelationId: CorrelationId;
  retirementRequestDigestB64u: string;
  retirementEffectBindingDigestB64u: string;
  requestedAtMs: number;
};

export type CommitLaneEnrollmentRevocationV1 = {
  kind: 'commit_lane_enrollment_revocation_v1';
  enrollmentId: LaneEnrollmentId;
  walletId: WalletId;
  manifestDigestB64u: string;
  receipt: AggregateLaneRevocationReceiptV1;
  revokedAtMs: number;
};

export type LaneEnrollmentActivationResultV1 =
  | {
      kind: 'lane_enrollment_activation_result_v1';
      outcome: 'applied';
      enrollmentId: LaneEnrollmentId;
      version: number;
      commandDigestB64u: string;
      receipt: AggregateLaneActivationReceiptV1;
      lifecycle: Extract<LaneEnrollmentLifecycleV1, { state: 'active' }>;
      productEpochs: readonly [LaneProductEpochActiveV1, ...LaneProductEpochActiveV1[]];
    }
  | {
      kind: 'lane_enrollment_activation_result_v1';
      outcome: 'replayed';
      enrollmentId: LaneEnrollmentId;
      version: number;
      commandDigestB64u: string;
      receipt: AggregateLaneActivationReceiptV1;
      lifecycle: Extract<LaneEnrollmentLifecycleV1, { state: 'active' }>;
      productEpochs: readonly [LaneProductEpochActiveV1, ...LaneProductEpochActiveV1[]];
    }
  | {
      kind: 'lane_enrollment_activation_result_v1';
      outcome: 'conflict';
      enrollmentId: LaneEnrollmentId;
      expectedVersion: number;
      actualVersion: number;
      requestedCommandDigestB64u: string;
      storedCommandDigestB64u: string;
    };

export type LaneEnrollmentRevocationResultV1 =
  | {
      kind: 'lane_enrollment_revocation_result_v1';
      outcome: 'applied';
      enrollmentId: LaneEnrollmentId;
      version: number;
      commandDigestB64u: string;
      receipt: AggregateLaneRevocationReceiptV1;
      lifecycle: Extract<LaneEnrollmentLifecycleV1, { state: 'revoked' }>;
      productEpochs: readonly [LaneProductEpochRevokedV1, ...LaneProductEpochRevokedV1[]];
    }
  | {
      kind: 'lane_enrollment_revocation_result_v1';
      outcome: 'replayed';
      enrollmentId: LaneEnrollmentId;
      version: number;
      commandDigestB64u: string;
      receipt: AggregateLaneRevocationReceiptV1;
      lifecycle: Extract<LaneEnrollmentLifecycleV1, { state: 'revoked' }>;
      productEpochs: readonly [LaneProductEpochRevokedV1, ...LaneProductEpochRevokedV1[]];
    }
  | {
      kind: 'lane_enrollment_revocation_result_v1';
      outcome: 'conflict';
      enrollmentId: LaneEnrollmentId;
      expectedVersion: number;
      actualVersion: number;
      requestedCommandDigestB64u: string;
      storedCommandDigestB64u: string;
    };

export type LaneSigningLaneRevocationResultV1 =
  | {
      kind: 'lane_signing_lane_revocation_result_v1';
      outcome: 'applied';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      version: number;
      commandDigestB64u: string;
      productEpoch: LaneProductEpochRevokedV1;
      retirementReceipt: LaneServerRetirementReceiptV1;
    }
  | {
      kind: 'lane_signing_lane_revocation_result_v1';
      outcome: 'replayed';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      version: number;
      commandDigestB64u: string;
      productEpoch: LaneProductEpochRevokedV1;
      retirementReceipt: LaneServerRetirementReceiptV1;
    }
  | {
      kind: 'lane_signing_lane_revocation_result_v1';
      outcome: 'conflict';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      expectedVersion: number;
      actualVersion: number;
      requestedCommandDigestB64u: string;
      storedCommandDigestB64u: string;
    };

export type LaneSigningLaneRevocationFenceResultV1 =
  | {
      kind: 'lane_signing_lane_revocation_fence_result_v1';
      outcome: 'applied' | 'replayed';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      version: number;
      commandDigestB64u: string;
      productEpoch: LaneProductEpochRevocationPendingV1;
    }
  | {
      kind: 'lane_signing_lane_revocation_fence_result_v1';
      outcome: 'already_completed';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      version: number;
      commandDigestB64u: string;
      productEpoch: LaneProductEpochRevokedV1;
      retirementReceipt: LaneServerRetirementReceiptV1;
    }
  | {
      kind: 'lane_signing_lane_revocation_fence_result_v1';
      outcome: 'conflict';
      walletKeyId: WalletKeyId;
      laneId: SigningLaneId;
      laneShareEpoch: LaneShareEpoch;
      expectedVersion: number;
      actualVersion: number;
      requestedCommandDigestB64u: string;
      storedCommandDigestB64u: string;
    };

export type LaneProtocolCasResultV1 =
  | {
      outcome: 'applied';
      version: number;
      record: LaneProtocolRecordV1;
      commandDigestB64u: string;
    }
  | {
      outcome: 'replayed';
      version: number;
      record: LaneProtocolRecordV1;
      commandDigestB64u: string;
    }
  | {
      outcome: 'conflict';
      expectedVersion: number;
      actualVersion: number;
      requestedCommandDigestB64u: string;
      storedCommandDigestB64u: string;
    };

export type PreparedLaneProtocolRecordV1 = {
  version: number;
  commandDigestB64u: DigestB64u;
  record: LaneProtocolRecordV1;
};

export type LaneEnrollmentPreparationResultV1 =
  | {
      kind: 'lane_enrollment_preparation_result_v1';
      outcome: 'applied' | 'replayed';
      enrollmentId: LaneEnrollmentId;
      version: number;
      commandDigestB64u: DigestB64u;
      lifecycle: LaneEnrollmentLifecycleV1;
      orderedProtocols: readonly [PreparedLaneProtocolRecordV1, ...PreparedLaneProtocolRecordV1[]];
    }
  | {
      kind: 'lane_enrollment_preparation_result_v1';
      outcome: 'conflict';
      enrollmentId: LaneEnrollmentId;
      expectedVersion: number | null;
      actualVersion: number;
      requestedCommandDigestB64u: DigestB64u;
      storedCommandDigestB64u: DigestB64u;
    };

export type EcdsaLaneProtocolWasmV1 = {
  prepareEcdsaAdditiveLaneHolderRoundV1(
    input: EcdsaAdditiveLaneJobV1,
  ): Promise<EcdsaAdditiveLaneHolderPreparationV1>;
};

export type { LaneHolderRecipientHandleV1 } from '../utils/domainIds';

export type LaneHolderRecipientDescriptorV1 = {
  recipientHandle: LaneHolderRecipientHandleV1;
  hpkePublicKeyB64u: HpkePublicKeyB64u;
  hpkePublicKeyDigestB64u: HpkePublicKeyDigestB64u;
};

export type LaneHolderPackageWireV1 =
  | {
      kind: 'ed25519_yao_lane_holder_package_set_v1';
      deriverAEncryptedPackageJson: string;
      deriverBEncryptedPackageJson: string;
      ecdsaEncryptedMaterialEnvelopeJson?: never;
    }
  | {
      kind: 'ecdsa_additive_lane_holder_package_v1';
      ecdsaEncryptedMaterialEnvelopeJson: string;
      deriverAEncryptedPackageJson?: never;
      deriverBEncryptedPackageJson?: never;
    };

export type EcdsaAdditiveLaneHolderPreparationV1 = {
  kind: 'ecdsa_additive_lane_holder_preparation_v1';
  holderRound: EcdsaAdditiveLaneHolderRoundV1;
  holderPackage: Extract<
    LaneHolderPackageWireV1,
    { kind: 'ecdsa_additive_lane_holder_package_v1' }
  >;
  encryptedDeltaPackageJson: string;
};

export type Ed25519YaoLaneClientCompletionV1 = {
  protocolCommitReceipt: LaneProtocolCommitReceiptV1;
  holderPackage: Extract<
    LaneHolderPackageWireV1,
    { kind: 'ed25519_yao_lane_holder_package_set_v1' }
  >;
};

export type SealedLaneHolderMaterialV1 = {
  sealedHolderMaterialB64u: string;
  sealedHolderRecordDigestB64u: DigestB64u;
  verifiedHolderCiphertextDigestSetB64u: DigestB64u;
};

export type VerifiedLaneHolderPackageV1 = {
  verifiedHolderCiphertextDigestSetB64u: DigestB64u;
};

export type WasmEd25519YaoLaneClientV1 = {
  prepare(input: Ed25519YaoLaneJobV1): Promise<{ requestJson: string }>;
  complete(input: {
    job: Ed25519YaoLaneJobV1;
    responseJson: string;
  }): Promise<Ed25519YaoLaneClientCompletionV1>;
};

export type PrepareLaneEnrollmentV1 = {
  manifest: LaneEnrollmentManifestV1;
  children: readonly [RotatableSigningLaneJobV1, ...RotatableSigningLaneJobV1[]];
};

export type ResumeLaneProtocolOperationV1 = {
  operationId: LaneOperationId;
  enrollmentId: LaneEnrollmentId;
  idempotencyKey: LaneOperationIdempotencyKey;
  expectedVersion: number;
};

export type RecordLaneHolderDeliveryV1 = {
  receipt: LaneHolderDeliveryReceiptV1;
  expectedVersion: number;
};

export type RecordLaneProtocolCommitV1 = {
  receipt: LaneProtocolCommitReceiptV1;
  expectedVersion: number;
};

export type ActivateLaneServerMaterialV1 = {
  receipt: LaneServerActivationReceiptV1;
  expectedVersion: number;
};

export type LaneHolderRecipientWorkerV1 = {
  createLaneHolderRecipientV1(input: {
    operationId: LaneOperationId;
    enrollmentId: LaneEnrollmentId;
    targetLaneId: SigningLaneId;
    targetLaneShareEpoch: LaneShareEpoch;
    targetHolderParticipantId: LaneHolderParticipantId;
    targetHolderParticipantBindingDigestB64u: LaneParticipantBindingDigestB64u;
    custodyBindingId: LaneHolderCustodyBindingId;
    custodyBindingDigestB64u: LaneCustodyBindingDigestB64u;
  }): Promise<LaneHolderRecipientDescriptorV1>;
  openAndSealLaneHolderPackageV1(input: {
    job: RotatableSigningLaneJobV1;
    protocolCommitReceipt: LaneProtocolCommitReceiptV1;
    holderPackage: LaneHolderPackageWireV1;
    recipientHandle: LaneHolderRecipientHandleV1;
  }): Promise<SealedLaneHolderMaterialV1>;
  verifyLaneHolderPackageCommitmentV1(input: {
    job: RotatableSigningLaneJobV1;
    protocolCommitReceipt: LaneProtocolCommitReceiptV1;
    holderPackage: LaneHolderPackageWireV1;
  }): Promise<VerifiedLaneHolderPackageV1>;
  discardLaneHolderRecipientV1(input: {
    recipientHandle: LaneHolderRecipientHandleV1;
    operationId: LaneOperationId;
  }): Promise<void>;
  invalidateLaneMaterialV1(input: {
    walletKeyId: WalletKeyId;
    laneId: SigningLaneId;
    laneShareEpoch: LaneShareEpoch;
    materialActivation: MpcMaterialActivationRef;
  }): Promise<void>;
};

export type LaneEnrollmentGatewayV1 = {
  prepareLaneEnrollmentV1(
    input: PrepareLaneEnrollmentV1,
  ): Promise<LaneEnrollmentPreparationResultV1>;
  resumeLaneProtocolOperationV1(
    input: ResumeLaneProtocolOperationV1,
  ): Promise<LaneProtocolCasResultV1>;
  recordLaneProtocolCommitV1(input: RecordLaneProtocolCommitV1): Promise<LaneProtocolCasResultV1>;
  recordLaneHolderDeliveryV1(input: RecordLaneHolderDeliveryV1): Promise<LaneProtocolCasResultV1>;
  activateLaneServerMaterialV1(
    input: ActivateLaneServerMaterialV1,
  ): Promise<LaneProtocolCasResultV1>;
  commitLaneEnrollmentActivationV1(
    input: CommitLaneEnrollmentActivationV1,
  ): Promise<LaneEnrollmentActivationResultV1>;
  fenceSigningLaneRevocationV1(
    input: RevokeSigningLaneV1,
  ): Promise<LaneSigningLaneRevocationFenceResultV1>;
  completeSigningLaneRevocationV1(
    input: CompleteSigningLaneRevocationV1,
  ): Promise<LaneSigningLaneRevocationResultV1>;
};
