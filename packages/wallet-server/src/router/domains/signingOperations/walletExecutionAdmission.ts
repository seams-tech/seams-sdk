import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import {
  computeLaneParticipantSetBindingDigestV1,
  buildPreparedOwnerWalletExecution,
  computeOwnerLaneParticipantBindingDigestV1,
  type ClaimedWalletExecutionAuthorization,
  type Ed25519WalletKeyRecord,
  type EvmFamilyWalletKeyRecord,
  type LaneParticipantBindingDigestB64u,
  type PreparedOwnerWalletExecution,
  type SigningLaneRecord,
  type WalletKeyRecord,
} from '@shared/signing-lanes';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  type MpcMaterialActivationRef,
  type WalletId,
  type WalletKeyId,
} from '@shared/utils/domainIds';
import type {
  ActiveWalletAuthorityV1,
  WalletSignerActivationSetV1,
} from '@shared/authorization/walletAuthority';
import type {
  ExactAdministeredEcdsaSignerV1,
  ExactAdministeredEd25519SignerV1,
} from '@shared/device-linking/delegatedActivationPlan';
import type { WalletAuthMethodRecordV2 } from '@shared/utils/registrationIntent';
import type {
  AuthorizedOperation,
  WalletSessionAuthorizationV2,
  WalletSessionCapabilitySubjectV1,
} from '../../../authorization/domain';
import {
  buildWalletSessionCapabilitySubjectsV1,
  walletSessionCapabilitySubjectsV1Equal,
} from '../../../authorization/domain';
import type { PrincipalId, TenantId } from '@shared/authorization/capabilityKinds';

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
















type WalletSessionAuthorizationV2Ed25519OperationKind =
  | (typeof NEAR_ED25519_MPC_OPERATION_KINDS)['signTransaction']
  | (typeof NEAR_ED25519_MPC_OPERATION_KINDS)['signDelegateAction']
  | (typeof NEAR_ED25519_MPC_OPERATION_KINDS)['signNep413Message']
  | (typeof NEAR_ED25519_MPC_OPERATION_KINDS)['exportKey'];

type WalletSessionAuthorizationV2EcdsaOperationKind =
  | (typeof EVM_ECDSA_MPC_OPERATION_KINDS)['signTransaction']
  | (typeof EVM_ECDSA_MPC_OPERATION_KINDS)['exportKey'];

export type WalletSessionAuthorizationV2RequestedOperation =
  | {
      readonly tenantId: TenantId;
      readonly principalId: PrincipalId;
      readonly walletId: WalletId;
      readonly keyFamily: 'ed25519';
      readonly operationKind: WalletSessionAuthorizationV2Ed25519OperationKind;
    }
  | {
      readonly tenantId: TenantId;
      readonly principalId: PrincipalId;
      readonly walletId: WalletId;
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly operationKind: WalletSessionAuthorizationV2EcdsaOperationKind;
    };

export type WalletSessionAuthorizationV2AdmissionError =
  | 'invalid_time'
  | 'authorization_retired'
  | 'authorization_expired'
  | 'operation_identity_mismatch'
  | 'wallet_mismatch'
  | 'authority_inactive'
  | 'authority_mismatch'
  | 'authority_digest_mismatch'
  | 'authority_revocation_epoch_mismatch'
  | 'auth_method_inactive'
  | 'auth_method_mismatch'
  | 'permission_mismatch'
  | 'capability_subject_mismatch'
  | 'signer_family_mismatch'
  | 'signer_activation_mismatch';

type WalletSessionAuthorizationV2AdmittedSigner =
  | {
      readonly keyFamily: 'ed25519';
      readonly operationKind: WalletSessionAuthorizationV2Ed25519OperationKind;
      readonly walletKeyId: WalletKeyId;
      readonly signer: ExactAdministeredEd25519SignerV1;
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly operationKind: WalletSessionAuthorizationV2EcdsaOperationKind;
      readonly walletKeyId: WalletKeyId;
      readonly signer: ExactAdministeredEcdsaSignerV1;
      readonly materialActivation: MpcMaterialActivationRef;
    };

export type WalletSessionAuthorizationV2AdmissionResult =
  | ({ readonly ok: true } & WalletSessionAuthorizationV2AdmittedSigner)
  | {
      readonly ok: false;
      readonly error: WalletSessionAuthorizationV2AdmissionError;
    };

export function resolveWalletSessionAuthorizationV2Admission(input: {
  readonly authorization: WalletSessionAuthorizationV2;
  readonly authority: ActiveWalletAuthorityV1;
  readonly authMethod: WalletAuthMethodRecordV2;
  readonly operation: WalletSessionAuthorizationV2RequestedOperation;
  readonly retiredAtMs: number | null;
  readonly nowMs: number;
}): WalletSessionAuthorizationV2AdmissionResult {
  if (!isPositiveSafeInteger(input.nowMs)) return admissionRefused('invalid_time');
  if (input.retiredAtMs !== null) return admissionRefused('authorization_retired');
  if (input.authorization.expiresAtMs <= input.nowMs) {
    return admissionRefused('authorization_expired');
  }
  if (
    input.authorization.tenantId !== input.operation.tenantId ||
    input.authorization.principalId !== input.operation.principalId
  ) {
    return admissionRefused('operation_identity_mismatch');
  }
  if (
    input.authorization.walletId !== input.operation.walletId ||
    input.authority.walletId !== input.operation.walletId
  ) {
    return admissionRefused('wallet_mismatch');
  }
  if (input.authority.state !== 'active') return admissionRefused('authority_inactive');
  if (input.authorization.authorityId !== input.authority.authorityId) {
    return admissionRefused('authority_mismatch');
  }
  if (input.authorization.authorityDigestB64u !== input.authority.authorityDigestB64u) {
    return admissionRefused('authority_digest_mismatch');
  }
  if (input.authorization.authorityRevocationEpoch !== input.authority.revocationEpoch) {
    return admissionRefused('authority_revocation_epoch_mismatch');
  }
  if (input.authMethod.status !== 'active') return admissionRefused('auth_method_inactive');
  if (
    input.authorization.walletAuthMethodId !== input.authMethod.walletAuthMethodId ||
    input.authMethod.walletId !== input.authority.walletId ||
    input.authMethod.walletAuthorityId !== input.authority.authorityId
  ) {
    return admissionRefused('auth_method_mismatch');
  }

  const requirement = requiredWalletSessionAuthorizationV2Capability(input.operation);
  if (!input.authority.permissions.includes(requirement.permission)) {
    return admissionRefused('permission_mismatch');
  }
  let expectedSubjects: readonly [
    WalletSessionCapabilitySubjectV1,
    ...WalletSessionCapabilitySubjectV1[],
  ];
  try {
    expectedSubjects = buildWalletSessionCapabilitySubjectsV1(input.authority);
  } catch {
    return admissionRefused('capability_subject_mismatch');
  }
  if (
    !walletSessionCapabilitySubjectsV1Equal(
      input.authorization.capabilitySubjects,
      expectedSubjects,
    )
  ) {
    return admissionRefused('capability_subject_mismatch');
  }
  const signer = resolveWalletSessionAuthorizationV2Signer(
    input.authority,
    input.operation.keyFamily,
  );
  if (!signer) return admissionRefused('signer_family_mismatch');
  if (
    !hasExactWalletSessionAuthorizationV2SignerSubject(
      input.authorization.capabilitySubjects,
      requirement.subjectKind,
      input.operation.keyFamily,
      signer.materialActivation,
    )
  ) {
    return admissionRefused('signer_activation_mismatch');
  }
  switch (input.operation.keyFamily) {
    case 'ed25519':
      if (signer.keyFamily !== 'ed25519') return admissionRefused('signer_family_mismatch');
      return {
        ok: true,
        keyFamily: 'ed25519',
        operationKind: input.operation.operationKind,
        walletKeyId: signer.walletKeyId,
        signer: signer.signer,
        materialActivation: signer.materialActivation,
      };
    case 'ecdsa_secp256k1':
      if (signer.keyFamily !== 'ecdsa_secp256k1') {
        return admissionRefused('signer_family_mismatch');
      }
      return {
        ok: true,
        keyFamily: 'ecdsa_secp256k1',
        operationKind: input.operation.operationKind,
        walletKeyId: signer.walletKeyId,
        signer: signer.signer,
        materialActivation: signer.materialActivation,
      };
    default:
      return assertNeverWalletSessionAuthorizationV2Operation(input.operation);
  }
}

type WalletSessionAuthorizationV2CapabilityRequirement = {
  readonly permission: 'sign' | 'export_keys';
  readonly subjectKind: 'sign' | 'export_keys';
};

type WalletSessionAuthorizationV2ResolvedSigner =
  | {
      readonly keyFamily: 'ed25519';
      readonly walletKeyId: WalletKeyId;
      readonly signer: ExactAdministeredEd25519SignerV1;
      readonly materialActivation: MpcMaterialActivationRef;
    }
  | {
      readonly keyFamily: 'ecdsa_secp256k1';
      readonly walletKeyId: WalletKeyId;
      readonly signer: ExactAdministeredEcdsaSignerV1;
      readonly materialActivation: MpcMaterialActivationRef;
    };

function requiredWalletSessionAuthorizationV2Capability(
  operation: WalletSessionAuthorizationV2RequestedOperation,
): WalletSessionAuthorizationV2CapabilityRequirement {
  switch (operation.keyFamily) {
    case 'ed25519':
      switch (operation.operationKind) {
        case NEAR_ED25519_MPC_OPERATION_KINDS.signTransaction:
        case NEAR_ED25519_MPC_OPERATION_KINDS.signDelegateAction:
        case NEAR_ED25519_MPC_OPERATION_KINDS.signNep413Message:
          return { permission: 'sign', subjectKind: 'sign' };
        case NEAR_ED25519_MPC_OPERATION_KINDS.exportKey:
          return { permission: 'export_keys', subjectKind: 'export_keys' };
        default:
          return assertNeverWalletSessionAuthorizationV2Operation(operation);
      }
    case 'ecdsa_secp256k1':
      switch (operation.operationKind) {
        case EVM_ECDSA_MPC_OPERATION_KINDS.signTransaction:
          return { permission: 'sign', subjectKind: 'sign' };
        case EVM_ECDSA_MPC_OPERATION_KINDS.exportKey:
          return { permission: 'export_keys', subjectKind: 'export_keys' };
        default:
          return assertNeverWalletSessionAuthorizationV2Operation(operation);
      }
  }
}

function resolveWalletSessionAuthorizationV2Signer(
  authority: ActiveWalletAuthorityV1,
  keyFamily: WalletSessionAuthorizationV2RequestedOperation['keyFamily'],
): WalletSessionAuthorizationV2ResolvedSigner | null {
  switch (keyFamily) {
    case 'ed25519': {
      const activation = authority.signerActivations.ed25519;
      if (!activation) return null;
      if (
        activation.signer.keyFamily !== 'ed25519' ||
        activation.signer.walletId !== authority.walletId ||
        String(activation.materialActivation.materialOwner) !== String(authority.walletId)
      ) {
        return null;
      }
      return {
        keyFamily,
        walletKeyId: activation.signer.walletKeyId,
        signer: activation.signer,
        materialActivation: activation.materialActivation,
      };
    }
    case 'ecdsa_secp256k1': {
      const activation = authority.signerActivations.ecdsa;
      if (!activation) return null;
      if (
        activation.signer.keyFamily !== 'ecdsa_secp256k1' ||
        activation.signer.walletId !== authority.walletId ||
        String(activation.materialActivation.materialOwner) !== String(authority.walletId)
      ) {
        return null;
      }
      return {
        keyFamily,
        walletKeyId: activation.signer.walletKeyId,
        signer: activation.signer,
        materialActivation: activation.materialActivation,
      };
    }
  }
}

function hasExactWalletSessionAuthorizationV2SignerSubject(
  subjects: readonly WalletSessionCapabilitySubjectV1[],
  subjectKind: 'sign' | 'export_keys',
  keyFamily: WalletSessionAuthorizationV2RequestedOperation['keyFamily'],
  materialActivation: MpcMaterialActivationRef,
): boolean {
  for (const subject of subjects) {
    if (
      (subject.kind === 'sign' || subject.kind === 'export_keys') &&
      subject.kind === subjectKind &&
      subject.keyFamily === keyFamily
    ) {
      return mpcMaterialActivationRefsEqual(subject.materialActivation, materialActivation);
    }
  }
  return false;
}

function isPositiveSafeInteger(value: number): boolean {
  return Number.isSafeInteger(value) && value > 0;
}

function admissionRefused(
  error: WalletSessionAuthorizationV2AdmissionError,
): Extract<WalletSessionAuthorizationV2AdmissionResult, { readonly ok: false }> {
  return { ok: false, error };
}

function assertNeverWalletSessionAuthorizationV2Operation(value: never): never {
  throw new Error(`Unsupported Wallet Session authorization V2 operation: ${String(value)}`);
}

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
    String(lane.ownerParticipantContinuity.signingWorkerId) !==
      String(input.evidence.materialActivation.signingWorker)
  ) {
    return refused('participant_binding_mismatch');
  }
  const canonicalParticipantBindingDigestB64u = await computeOwnerLaneParticipantBindingDigestV1(
    lane.ownerParticipantContinuity,
  );
  if (canonicalParticipantBindingDigestB64u !== lane.participantBindingDigestB64u) {
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
    execution: buildPreparedOwnerWalletExecution({
      authorization: claimedExecutionAuthorization(claimedOperation),
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
    }),
  };
}

function claimedExecutionAuthorization(
  operation: ClaimedAuthorizedOperation,
): ClaimedWalletExecutionAuthorization {
  return {
    kind: 'claimed_wallet_execution_authorization_v1',
    authorizedOperationId: operation.authorizedOperationId,
    operationFingerprintDigest: operation.operationFingerprintDigest,
    capabilityId: operation.operation.capabilityId,
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
        operation.operation.operation.capabilityKind === CAPABILITY_KINDS.nearEd25519MpcSigning
      );
    case 'ecdsa_secp256k1':
      return operation.operation.operation.capabilityKind === CAPABILITY_KINDS.evmEcdsaMpcSigning;
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
