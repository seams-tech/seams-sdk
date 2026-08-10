import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import {
  assertLaneHolderParticipantBindingDigestV1,
  assertSigningWorkerParticipantBindingDigestV1,
  type ActiveSigningLaneReference,
  type LaneParticipantBindingDigestB64u,
  type SigningLaneRecord,
  type WalletKeyRecord,
} from '@shared/signing-lanes';
import type { DigestB64u } from '@shared/utils/canonicalPrimitives';
import type { MpcMaterialActivationRef, WalletId } from '@shared/utils/domainIds';
import type { AuthorizedOperation } from '../../../authorization/domain';

export type ClaimedAuthorizedOperation = AuthorizedOperation & {
  readonly lifecycle: 'claimed';
  readonly result?: never;
  readonly response?: never;
  readonly resultDigest?: never;
  readonly completedAtMs?: never;
};

type ActiveWalletKeyRecord = WalletKeyRecord & {
  readonly lifecycle: Extract<WalletKeyRecord['lifecycle'], { readonly state: 'active' }>;
};

type OwnerSigningLaneRecord = Extract<
  SigningLaneRecord,
  {
    readonly laneKind: 'owner_passkey' | 'owner_email_otp' | 'recovery' | 'break_glass';
  }
>;

type ActiveOwnerSigningLaneRecord = OwnerSigningLaneRecord & {
  readonly lifecycle: Extract<SigningLaneRecord['lifecycle'], { readonly state: 'active' }>;
};

export type PreparedOwnerWalletExecution = {
  readonly kind: 'prepared_owner_wallet_execution';
  readonly laneKind: ActiveOwnerSigningLaneRecord['laneKind'];
  readonly authorizedOperation: ClaimedAuthorizedOperation;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly lane: ActiveSigningLaneReference;
};

export type WalletExecutionAdmissionRefusalReason =
  | 'operation_not_claimed'
  | 'wallet_key_inactive'
  | 'lane_inactive'
  | 'unsupported_lane'
  | 'wallet_mismatch'
  | 'wallet_key_mismatch'
  | 'curve_mismatch'
  | 'capability_mismatch'
  | 'material_activation_mismatch'
  | 'participant_binding_mismatch'
  | 'activation_receipt_mismatch';

export type WalletExecutionAdmissionResult =
  | {
      readonly kind: 'prepared';
      readonly execution: PreparedOwnerWalletExecution;
    }
  | {
      readonly kind: 'refused';
      readonly reason: WalletExecutionAdmissionRefusalReason;
    };

export type OwnerWalletExecutionEvidence = {
  readonly walletId: WalletId;
  readonly walletKey: WalletKeyRecord;
  readonly lane: SigningLaneRecord;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
  readonly verifiedLaneParticipantBindingDigestB64u: LaneParticipantBindingDigestB64u;
  readonly verifiedActivationReceiptDigestB64u: DigestB64u;
};

export async function prepareOwnerWalletExecution(input: {
  readonly authorizedOperation: AuthorizedOperation;
  readonly evidence: OwnerWalletExecutionEvidence;
}): Promise<WalletExecutionAdmissionResult> {
  if (input.authorizedOperation.lifecycle !== 'claimed') {
    return refused('operation_not_claimed');
  }
  const claimedOperation = input.authorizedOperation;
  if (input.evidence.walletKey.lifecycle.state !== 'active') {
    return refused('wallet_key_inactive');
  }
  if (input.evidence.lane.lifecycle.state !== 'active') {
    return refused('lane_inactive');
  }
  if (!isActiveOwnerLane(input.evidence.lane)) {
    return refused('unsupported_lane');
  }
  const lane = input.evidence.lane;
  if (
    input.evidence.walletKey.walletId !== input.evidence.walletId ||
    lane.walletId !== input.evidence.walletId ||
    String(input.evidence.materialActivation.materialOwner) !== String(input.evidence.walletId)
  ) {
    return refused('wallet_mismatch');
  }
  if (lane.walletKeyId !== input.evidence.walletKey.walletKeyId) {
    return refused('wallet_key_mismatch');
  }
  if (!operationMatchesWalletKey(input.authorizedOperation, input.evidence.walletKey)) {
    return refused('curve_mismatch');
  }
  if (
    String(claimedOperation.operation.capabilityId) !==
    String(input.evidence.materialActivation.capability)
  ) {
    return refused('capability_mismatch');
  }
  if (
    !sameMaterialActivation(
      input.evidence.materialActivation,
      input.evidence.expectedMaterialActivation,
    )
  ) {
    return refused('material_activation_mismatch');
  }
  if (
    lane.participantBindingDigestB64u !== input.evidence.verifiedLaneParticipantBindingDigestB64u ||
    String(lane.serverParticipant.participantId) !==
      String(input.evidence.materialActivation.signingWorker)
  ) {
    return refused('participant_binding_mismatch');
  }
  try {
    await Promise.all([
      assertLaneHolderParticipantBindingDigestV1(lane.holderParticipant),
      assertSigningWorkerParticipantBindingDigestV1(lane.serverParticipant),
    ]);
  } catch {
    return refused('participant_binding_mismatch');
  }
  if (
    lane.lifecycle.activationReceiptDigestB64u !==
    input.evidence.verifiedActivationReceiptDigestB64u
  ) {
    return refused('activation_receipt_mismatch');
  }

  return {
    kind: 'prepared',
    execution: {
      kind: 'prepared_owner_wallet_execution',
      laneKind: lane.laneKind,
      authorizedOperation: claimedOperation,
      materialActivation: input.evidence.materialActivation,
      lane: {
        kind: 'signing_lane_reference_v1',
        walletId: lane.walletId,
        walletKeyId: lane.walletKeyId,
        laneId: lane.laneId,
        laneKind: lane.laneKind,
        laneShareEpoch: lane.laneShareEpoch,
        participantBindingDigestB64u: lane.participantBindingDigestB64u,
        lifecycle: lane.lifecycle,
        materialActivation: input.evidence.materialActivation,
      },
    },
  };
}

export async function admitAndDispatchOwnerWalletExecution<TResult>(input: {
  readonly authorizedOperation: AuthorizedOperation;
  readonly resolveEvidence: () => Promise<OwnerWalletExecutionEvidence>;
  readonly dispatch: (execution: PreparedOwnerWalletExecution) => Promise<TResult>;
}): Promise<
  | { readonly kind: 'dispatched'; readonly result: TResult }
  | Extract<WalletExecutionAdmissionResult, { readonly kind: 'refused' }>
> {
  if (input.authorizedOperation.lifecycle !== 'claimed') {
    return refused('operation_not_claimed');
  }
  const admission = await prepareOwnerWalletExecution({
    authorizedOperation: input.authorizedOperation,
    evidence: await input.resolveEvidence(),
  });
  if (admission.kind === 'refused') return admission;
  return {
    kind: 'dispatched',
    result: await input.dispatch(admission.execution),
  };
}

function isActiveOwnerLane(lane: SigningLaneRecord): lane is ActiveOwnerSigningLaneRecord {
  if (lane.lifecycle.state !== 'active') return false;
  switch (lane.laneKind) {
    case 'owner_passkey':
    case 'owner_email_otp':
    case 'recovery':
    case 'break_glass':
      return true;
    case 'linked_device':
    case 'delegated_execution':
      return false;
  }
}

function operationMatchesWalletKey(
  operation: AuthorizedOperation,
  walletKey: WalletKeyRecord,
): boolean {
  switch (walletKey.keyFamily) {
    case 'ed25519':
      return (
        operation.operation.operation.capabilityKind === CAPABILITY_KINDS.nearEd25519MpcSigning &&
        operation.operation.operation.operationKind !== NEAR_ED25519_MPC_OPERATION_KINDS.exportKey
      );
    case 'ecdsa_secp256k1':
      return (
        operation.operation.operation.capabilityKind === CAPABILITY_KINDS.evmEcdsaMpcSigning &&
        operation.operation.operation.operationKind !== EVM_ECDSA_MPC_OPERATION_KINDS.exportKey
      );
  }
}

function sameMaterialActivation(
  left: MpcMaterialActivationRef,
  right: MpcMaterialActivationRef,
): boolean {
  return (
    left.activationId === right.activationId &&
    left.capability === right.capability &&
    left.materialOwner === right.materialOwner &&
    left.keyBinding === right.keyBinding &&
    left.lifecycleBinding === right.lifecycleBinding &&
    left.signingWorker === right.signingWorker
  );
}

function refused(
  reason: WalletExecutionAdmissionRefusalReason,
): Extract<WalletExecutionAdmissionResult, { readonly kind: 'refused' }> {
  return { kind: 'refused', reason };
}
