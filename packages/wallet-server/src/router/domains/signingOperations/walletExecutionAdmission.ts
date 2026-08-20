import {
  CAPABILITY_KINDS,
  EVM_ECDSA_MPC_OPERATION_KINDS,
  NEAR_ED25519_MPC_OPERATION_KINDS,
} from '@shared/authorization/capabilityKinds';
import {
  computeLaneParticipantSetBindingDigestV1,
  buildPreparedOwnerWalletExecution,
  buildPreparedLinkedDeviceWalletExecution,
  computeOwnerLaneParticipantBindingDigestV1,
  type ClaimedWalletExecutionAuthorization,
  type Ed25519WalletKeyRecord,
  type EvmFamilyWalletKeyRecord,
  type LaneParticipantBindingDigestB64u,
  type LaneProductEpochActiveV1,
  type LinkedDeviceEcdsaNormalSigningScopeV1,
  type LinkedDeviceSigningLaneRecord,
  type PreparedOwnerWalletExecution,
  type PreparedLinkedDeviceWalletExecution,
  type SigningLaneRecord,
  type WalletKeyRecord,
} from '@shared/signing-lanes';
import { parseDigestB64u, type DigestB64u } from '@shared/utils/canonicalPrimitives';
import {
  mpcMaterialActivationRefsEqual,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type MpcMaterialActivationRef,
  type WalletId,
  type WalletKeyId,
  type WebAuthnCredentialIdB64u,
} from '@shared/utils/domainIds';
import type {
  AuthorizedOperation,
  LinkedDeviceWalletSessionAuthorizationV1,
} from '../../../authorization/domain';
import type {
  AuthorizedOperationId,
  LinkedDeviceWalletSessionAuthorizationId,
  MpcWalletSigningQuotaId,
  TenantId,
  WalletSessionId,
} from '@shared/authorization/capabilityKinds';
import type { SigningLaneId, LaneShareEpoch } from '@shared/signing-lanes/ids';
import type { RouterAbNormalSigningMaterialSourceV1 } from './routerAbPrivateSigningWorker';
import { hasDelegatedWalletPermissionV1 } from '@shared/authorization/delegatedAuthority';

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

export type LinkedDeviceWalletExecutionAdmissionRefusalReason =
  | WalletExecutionAdmissionRefusalReason
  | 'authorization_grant_mismatch'
  | 'authorization_expired'
  | 'authorization_permission_mismatch'
  | 'linked_device_mismatch'
  | 'linked_enrollment_mismatch'
  | 'linked_product_mismatch'
  | 'linked_participant_mismatch'
  | 'revocation_epoch_mismatch'
  | 'local_presence_missing'
  | 'local_presence_mismatch'
  | 'linked_execution_unavailable';

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

/** Durable linked-device enrollment facts required by signing admission. */
export type ActiveLinkedDeviceEnrollmentExecutionRecordV1 = {
  readonly kind: 'active_linked_device_enrollment_v1';
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly credentialIdB64u: WebAuthnCredentialIdB64u;
  readonly revocationEpoch: number;
  readonly lifecycle: {
    readonly state: 'active';
    readonly activatedAtMs: number;
  };
};

/** The local WebAuthn proof is verified before this kernel is called. */
export type LinkedDeviceLocalPresenceEvidenceV1 =
  | {
      readonly kind: 'linked_device_local_presence_evidence_v1';
      readonly authorizedOperationId: AuthorizedOperationId;
      readonly deviceId: LinkedDeviceId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      readonly intentDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
      readonly assertionDigestB64u: DigestB64u;
      readonly challengeDigestB64u?: never;
    }
  | {
      readonly kind: 'linked_device_local_presence_evidence_v1';
      readonly authorizedOperationId: AuthorizedOperationId;
      readonly deviceId: LinkedDeviceId;
      readonly enrollmentId: LinkedDeviceEnrollmentId;
      readonly credentialIdB64u: WebAuthnCredentialIdB64u;
      readonly intentDigestB64u: DigestB64u;
      readonly verifiedAtMs: number;
      readonly assertionDigestB64u?: never;
      readonly challengeDigestB64u: DigestB64u;
    };

const linkedDeviceLocalPresenceCapabilityBrand = Symbol('linked-device-local-presence-capability');

/**
 * The first operation request carries verified WebAuthn evidence. Once that
 * claim is durable, continuation requests use the claim itself as the local
 * presence capability and never replay the assertion.
 */
export type LinkedDeviceLocalPresenceAuthorizationV1 =
  | { readonly kind: 'verified_assertion'; readonly evidence: LinkedDeviceLocalPresenceEvidenceV1 }
  | {
      readonly kind: 'admitted_operation';
      readonly operation: ClaimedAuthorizedOperation;
      readonly [linkedDeviceLocalPresenceCapabilityBrand]: true;
    };

export function buildLinkedDeviceLocalPresenceCapabilityV1(
  operation: ClaimedAuthorizedOperation,
): LinkedDeviceLocalPresenceAuthorizationV1 {
  if (operation.lifecycle !== 'claimed') {
    throw new Error('linked-device local presence capability requires a claimed operation');
  }
  return {
    kind: 'admitted_operation',
    operation,
    [linkedDeviceLocalPresenceCapabilityBrand]: true,
  };
}

const linkedDeviceWalletSessionRenewalCapabilityBrand = Symbol(
  'linked-device-wallet-session-renewal-capability',
);

export type LinkedDeviceWalletSessionRenewalCapabilityV1 = {
  readonly kind: 'linked_device_wallet_session_renewal_capability_v1';
  readonly tenantId: TenantId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly revocationEpoch: number;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
  readonly verifiedAtMs: number;
  readonly assertionDigestB64u: DigestB64u;
  readonly [linkedDeviceWalletSessionRenewalCapabilityBrand]: true;
};

export function buildLinkedDeviceWalletSessionRenewalCapabilityV1(input: {
  readonly evidence: LinkedDeviceLocalPresenceEvidenceV1;
  readonly tenantId: TenantId;
  readonly deviceId: LinkedDeviceId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
  readonly walletSessionId: WalletSessionId;
  readonly quotaId: MpcWalletSigningQuotaId;
  readonly revocationEpoch: number;
  readonly authorizedOperationId: AuthorizedOperationId;
  readonly intentDigestB64u: DigestB64u;
}): LinkedDeviceWalletSessionRenewalCapabilityV1 {
  const evidence = input.evidence;
  if (
    evidence.kind !== 'linked_device_local_presence_evidence_v1' ||
    evidence.authorizedOperationId !== input.authorizedOperationId ||
    evidence.deviceId !== input.deviceId ||
    evidence.enrollmentId !== input.enrollmentId ||
    evidence.intentDigestB64u !== input.intentDigestB64u ||
    !('assertionDigestB64u' in evidence)
  ) {
    throw new Error('linked-device Wallet Session renewal evidence binding differs');
  }
  const assertionDigestB64u = evidence.assertionDigestB64u;
  if (!assertionDigestB64u) {
    throw new Error('linked-device Wallet Session renewal assertion evidence is missing');
  }
  return {
    kind: 'linked_device_wallet_session_renewal_capability_v1',
    tenantId: input.tenantId,
    deviceId: input.deviceId,
    enrollmentId: input.enrollmentId,
    authorizationId: input.authorizationId,
    walletSessionId: input.walletSessionId,
    quotaId: input.quotaId,
    revocationEpoch: input.revocationEpoch,
    authorizedOperationId: input.authorizedOperationId,
    intentDigestB64u: input.intentDigestB64u,
    verifiedAtMs: evidence.verifiedAtMs,
    assertionDigestB64u,
    [linkedDeviceWalletSessionRenewalCapabilityBrand]: true,
  };
}

export function isLinkedDeviceWalletSessionRenewalCapabilityV1(
  value: unknown,
): value is LinkedDeviceWalletSessionRenewalCapabilityV1 {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  return (
    Reflect.get(value, 'kind') === 'linked_device_wallet_session_renewal_capability_v1' &&
    Reflect.get(value, linkedDeviceWalletSessionRenewalCapabilityBrand) === true
  );
}

type ActiveLinkedDeviceExecutionProjectionCommonV1 = {
  readonly kind: 'active_linked_device_execution_projection_v1';
  readonly authorization: LinkedDeviceWalletSessionAuthorizationV1;
  readonly enrollment: ActiveLinkedDeviceEnrollmentExecutionRecordV1;
  readonly lane: LinkedDeviceSigningLaneRecord;
  readonly product: LaneProductEpochActiveV1;
  readonly materialActivation: MpcMaterialActivationRef;
  readonly verifiedLaneParticipantBindingDigestB64u: LaneParticipantBindingDigestB64u;
  readonly verifiedActivationReceiptDigestB64u: DigestB64u;
  readonly materialSource: Extract<
    RouterAbNormalSigningMaterialSourceV1,
    {
      readonly kind: 'rotatable_lane';
    }
  >;
  readonly trustedScope: {
    readonly orgId: string;
    readonly projectId: string;
    readonly environment: string;
  };
};

export type ActiveLinkedDeviceExecutionProjectionV1 =
  | (ActiveLinkedDeviceExecutionProjectionCommonV1 & {
      readonly walletKey: Ed25519WalletKeyRecord;
      readonly ecdsaNormalSigningScope?: never;
    })
  | (ActiveLinkedDeviceExecutionProjectionCommonV1 & {
      readonly walletKey: EvmFamilyWalletKeyRecord;
      readonly ecdsaNormalSigningScope: LinkedDeviceEcdsaNormalSigningScopeV1;
    });

export type LinkedDeviceExecutionProjectionResult =
  | {
      readonly kind: 'projected';
      readonly projection: ActiveLinkedDeviceExecutionProjectionV1;
    }
  | {
      readonly kind: 'refused';
      readonly reason: LinkedDeviceWalletExecutionAdmissionRefusalReason;
    };

export interface LinkedDeviceExecutionAdmissionResolverV1 {
  resolveActiveLinkedDeviceExecutionV1(input: {
    readonly tenantId: TenantId;
    readonly walletSessionId: WalletSessionId;
    readonly quotaId: MpcWalletSigningQuotaId;
    readonly walletId: WalletId;
    readonly enrollmentId: LinkedDeviceEnrollmentId;
    readonly deviceId: LinkedDeviceId;
    readonly walletKeyId: WalletKeyId;
    readonly laneId: SigningLaneId;
    readonly laneShareEpoch: LaneShareEpoch;
    readonly materialActivation: MpcMaterialActivationRef;
    /** Epoch claimed by the selected lane JWT, distinct from the enrollment fence. */
    readonly laneRevocationEpoch: number;
    readonly authorizationId: LinkedDeviceWalletSessionAuthorizationId;
    readonly authorizedOperationId: AuthorizedOperationId;
  }): Promise<LinkedDeviceExecutionProjectionResult>;
}

export type LinkedDeviceWalletExecutionEvidenceV1 = ActiveLinkedDeviceExecutionProjectionV1 & {
  readonly expectedMaterialActivation: MpcMaterialActivationRef;
};

export type LinkedDeviceWalletExecutionAdmissionResult =
  | {
      readonly kind: 'prepared';
      readonly execution: PreparedLinkedDeviceWalletExecution;
    }
  | {
      readonly kind: 'refused';
      readonly reason: LinkedDeviceWalletExecutionAdmissionRefusalReason;
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

export async function prepareLinkedDeviceWalletExecution(input: {
  readonly authorizedOperation: AuthorizedOperation;
  readonly evidence: LinkedDeviceWalletExecutionEvidenceV1;
  readonly localPresence: LinkedDeviceLocalPresenceAuthorizationV1;
}): Promise<LinkedDeviceWalletExecutionAdmissionResult> {
  const operation = input.authorizedOperation;
  if (operation.lifecycle !== 'claimed') return linkedRefused('operation_not_claimed');

  const grantRef = linkedGrantRef(operation);
  if (!grantRef) return linkedRefused('authorization_grant_mismatch');

  const evidence = input.evidence;
  const grant = evidence.authorization;
  const enrollment = evidence.enrollment;
  const product = evidence.product;
  const lane = evidence.lane;
  const walletKey = evidence.walletKey;

  if (walletKey.lifecycle.state !== 'active') return linkedRefused('wallet_key_inactive');
  if (lane.lifecycle.state !== 'active') return linkedRefused('lane_inactive');
  if (enrollment.lifecycle.state !== 'active') return linkedRefused('linked_enrollment_mismatch');
  if (product.state !== 'active') return linkedRefused('linked_product_mismatch');
  if (lane.laneKind !== 'linked_device') return linkedRefused('unsupported_lane');

  if (
    String(grant.authorizationGrantRef.authorizationId) !== String(grantRef.authorizationId) ||
    grant.authorizationGrantRef.kind !== grantRef.kind
  ) {
    return linkedRefused('authorization_grant_mismatch');
  }
  if (
    operation.tenantId !== grant.tenantId ||
    operation.operation.principalId !== grant.principalId ||
    grant.walletId !== evidence.walletKey.walletId
  ) {
    return linkedRefused('authorization_grant_mismatch');
  }
  if (operation.claimedAtMs < grant.issuedAtMs || operation.claimedAtMs >= grant.expiresAtMs) {
    return linkedRefused('authorization_expired');
  }
  if (!hasDelegatedWalletPermissionV1(grant.permission, 'sign')) {
    return linkedRefused('authorization_permission_mismatch');
  }
  if (
    operation.quota.kind !== 'consume_reusable_wallet_session' ||
    String(operation.quota.quotaId) !== String(grant.quotaId)
  ) {
    return linkedRefused('authorization_grant_mismatch');
  }

  if (
    enrollment.walletId !== grant.walletId ||
    String(enrollment.enrollmentId) !== String(grant.enrollmentId) ||
    enrollment.deviceId !== grant.deviceId ||
    enrollment.keyManifestDigestB64u !== grant.keyManifestDigestB64u
  ) {
    return linkedRefused('linked_enrollment_mismatch');
  }
  if (
    product.walletId !== grant.walletId ||
    product.laneKind !== 'linked_device' ||
    product.aggregateManifestDigestB64u !== grant.keyManifestDigestB64u ||
    product.walletKeyId !== walletKey.walletKeyId ||
    product.laneId !== lane.laneId ||
    String(product.enrollmentId) !== String(grant.enrollmentId) ||
    product.laneShareEpoch !== lane.laneShareEpoch
  ) {
    return linkedRefused('linked_product_mismatch');
  }
  if (
    lane.walletId !== grant.walletId ||
    lane.walletKeyId !== walletKey.walletKeyId ||
    lane.linkedDeviceId !== grant.deviceId ||
    lane.laneId !== product.laneId ||
    lane.laneShareEpoch !== product.laneShareEpoch ||
    lane.lifecycle.revocationEpoch !== product.revocationEpoch
  ) {
    return linkedRefused('linked_device_mismatch');
  }
  if (
    enrollment.revocationEpoch !== grant.revocationEpoch
  ) {
    return linkedRefused('revocation_epoch_mismatch');
  }
  if (
    !mpcMaterialActivationRefsEqual(
      evidence.materialActivation,
      evidence.expectedMaterialActivation,
    ) ||
    !mpcMaterialActivationRefsEqual(product.materialActivation, evidence.materialActivation) ||
    product.targetMaterialActivationId !== evidence.materialActivation.activationId ||
    String(evidence.materialActivation.materialOwner) !== String(grant.walletId) ||
    String(evidence.materialActivation.capability) !== String(operation.operation.capabilityId)
  ) {
    return linkedRefused('material_activation_mismatch');
  }
  if (
    String(evidence.verifiedActivationReceiptDigestB64u) !==
      String(product.aggregateActivationReceiptDigestB64u) ||
    String(lane.lifecycle.activationReceiptDigestB64u) !==
      String(evidence.verifiedActivationReceiptDigestB64u)
  ) {
    return linkedRefused('activation_receipt_mismatch');
  }
  if (
    lane.participantBindingDigestB64u !== evidence.verifiedLaneParticipantBindingDigestB64u ||
    product.participantSetBindingDigestB64u !== evidence.verifiedLaneParticipantBindingDigestB64u ||
    !sameLaneHolderParticipant(lane.holderParticipant, product.holderParticipant) ||
    !sameSigningWorkerParticipant(lane.serverParticipant, product.signingWorkerParticipant)
  ) {
    return linkedRefused('linked_participant_mismatch');
  }
  try {
    const participantBindingDigestB64u = await computeLaneParticipantSetBindingDigestV1({
      holderParticipant: lane.holderParticipant,
      signingWorkerParticipant: lane.serverParticipant,
    });
    if (participantBindingDigestB64u !== evidence.verifiedLaneParticipantBindingDigestB64u) {
      return linkedRefused('linked_participant_mismatch');
    }
  } catch {
    return linkedRefused('linked_participant_mismatch');
  }
  if (!materialSourceMatchesActiveLinkedProduct(evidence)) {
    return linkedRefused('material_activation_mismatch');
  }

  const localPresenceRefusal = validateLinkedDeviceLocalPresence({
    operation,
    enrollment,
    localPresence: input.localPresence,
  });
  if (localPresenceRefusal) return linkedRefused(localPresenceRefusal);
  if (!operationMatchesWalletKey(operation, walletKey)) return linkedRefused('curve_mismatch');

  return {
    kind: 'prepared',
    execution: buildPreparedLinkedDeviceWalletExecution({
      authorization: claimedExecutionAuthorization(operation),
      materialActivation: evidence.materialActivation,
      linkedDeviceEnrollmentId: grant.enrollmentId,
      lane: {
        kind: 'signing_lane_reference_v1',
        walletId: lane.walletId,
        walletKeyId: lane.walletKeyId,
        laneId: lane.laneId,
        laneKind: lane.laneKind,
        laneShareEpoch: lane.laneShareEpoch,
        participantBindingDigestB64u: lane.participantBindingDigestB64u,
        lifecycle: lane.lifecycle,
        materialActivation: evidence.materialActivation,
      },
    }),
  };
}

function linkedGrantRef(operation: ClaimedAuthorizedOperation):
  | (Extract<
      ClaimedAuthorizedOperation['authorization'],
      { readonly kind: 'authorization_grant' }
    >['authorizationGrantRef'] & {
      readonly kind: 'linked_device_wallet_session_authorization_v1';
    })
  | null {
  if (operation.authorization.kind !== 'authorization_grant') return null;
  if (
    operation.authorization.authorizationGrantRef.kind !==
    'linked_device_wallet_session_authorization_v1'
  ) {
    return null;
  }
  return operation.authorization.authorizationGrantRef;
}

function validateLinkedDeviceLocalPresence(input: {
  readonly operation: ClaimedAuthorizedOperation;
  readonly enrollment: ActiveLinkedDeviceEnrollmentExecutionRecordV1;
  readonly localPresence: LinkedDeviceLocalPresenceAuthorizationV1;
}):
  | Extract<LinkedDeviceWalletExecutionAdmissionResult, { readonly kind: 'refused' }>['reason']
  | null {
  if (input.localPresence.kind === 'admitted_operation') {
    if (
      input.localPresence[linkedDeviceLocalPresenceCapabilityBrand] !== true ||
      input.localPresence.operation.authorizedOperationId !== input.operation.authorizedOperationId ||
      input.localPresence.operation.operationFingerprintDigest !==
        input.operation.operationFingerprintDigest ||
      input.localPresence.operation.lifecycle !== 'claimed'
    ) {
      return 'local_presence_mismatch';
    }
    return null;
  }
  const presence = input.localPresence.evidence;
  if (presence.kind !== 'linked_device_local_presence_evidence_v1') {
    return 'local_presence_missing';
  }
  if (
    presence.authorizedOperationId !== input.operation.authorizedOperationId ||
    presence.deviceId !== input.enrollment.deviceId ||
    presence.enrollmentId !== input.enrollment.enrollmentId ||
    presence.credentialIdB64u !== input.enrollment.credentialIdB64u ||
    presence.intentDigestB64u !== input.operation.operation.digests.intentDigest ||
    !Number.isSafeInteger(presence.verifiedAtMs) ||
    presence.verifiedAtMs <= 0
  ) {
    return 'local_presence_mismatch';
  }
  try {
    const proofDigest =
      'assertionDigestB64u' in presence
        ? presence.assertionDigestB64u
        : presence.challengeDigestB64u;
    parseDigestB64u(proofDigest);
  } catch {
    return 'local_presence_mismatch';
  }
  return null;
}

function sameLaneHolderParticipant(
  left: LinkedDeviceSigningLaneRecord['holderParticipant'],
  right: LaneProductEpochActiveV1['holderParticipant'],
): boolean {
  return (
    left.kind === right.kind &&
    left.participantId === right.participantId &&
    left.custodyBindingId === right.custodyBindingId &&
    left.custodyBindingDigestB64u === right.custodyBindingDigestB64u &&
    left.hpkePublicKeyB64u === right.hpkePublicKeyB64u &&
    left.hpkePublicKeyDigestB64u === right.hpkePublicKeyDigestB64u &&
    left.participantBindingDigestB64u === right.participantBindingDigestB64u
  );
}

function sameSigningWorkerParticipant(
  left: LinkedDeviceSigningLaneRecord['serverParticipant'],
  right: LaneProductEpochActiveV1['signingWorkerParticipant'],
): boolean {
  return (
    left.kind === right.kind &&
    left.participantId === right.participantId &&
    left.recipientKeyId === right.recipientKeyId &&
    left.hpkePublicKeyB64u === right.hpkePublicKeyB64u &&
    left.hpkePublicKeyDigestB64u === right.hpkePublicKeyDigestB64u &&
    left.participantBindingDigestB64u === right.participantBindingDigestB64u
  );
}

function materialSourceMatchesActiveLinkedProduct(
  evidence: LinkedDeviceWalletExecutionEvidenceV1,
): boolean {
  const identity = evidence.materialSource.lookup.identity;
  const product = evidence.product;
  if (
    identity.operationId !== product.operationId ||
    identity.enrollmentId !== product.enrollmentId ||
    identity.walletId !== product.walletId ||
    identity.walletKeyId !== product.walletKeyId ||
    identity.targetLaneId !== product.laneId ||
    identity.targetLaneShareEpoch !== product.laneShareEpoch ||
    identity.targetMaterialActivationId !== product.targetMaterialActivationId ||
    identity.keyFamily !== product.keyFamily ||
    identity.holderParticipantBindingDigestB64u !==
      product.holderParticipant.participantBindingDigestB64u ||
    identity.signingWorkerParticipantBindingDigestB64u !==
      product.signingWorkerParticipant.participantBindingDigestB64u ||
    identity.holderRecipientKeyDigestB64u !== product.holderParticipant.hpkePublicKeyDigestB64u ||
    identity.serverRecipientKeyDigestB64u !==
      product.signingWorkerParticipant.hpkePublicKeyDigestB64u ||
    String(identity.targetMaterialActivationId) !== String(evidence.materialActivation.activationId)
  ) {
    return false;
  }
  try {
    parseDigestB64u(evidence.materialSource.lookup.admittedLaneIdentityDigestB64u);
  } catch {
    return false;
  }
  if (evidence.walletKey.keyFamily === 'ecdsa_secp256k1') {
    return evidence.materialSource.group_public_key === evidence.walletKey.thresholdPublicKey33B64u;
  }
  return evidence.materialSource.group_public_key.length > 0;
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

function linkedRefused(
  reason: LinkedDeviceWalletExecutionAdmissionRefusalReason,
): Extract<LinkedDeviceWalletExecutionAdmissionResult, { readonly kind: 'refused' }> {
  return { kind: 'refused', reason };
}
