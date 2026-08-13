import type {
  LinkedDeviceApprovalV1,
  LinkedDeviceEnrollmentChildReceiptV1,
  LinkedDeviceEnrollmentReceiptV1,
  LinkedDeviceReceiptAcknowledgementV1,
  LinkedDeviceRevokeResultV1,
  LinkedDeviceSummaryV1,
  LinkedDeviceOwnerAuthorizationSourceV1,
  LinkedDeviceOwnerSourceLaneV1,
  LinkedDeviceSessionState,
  LinkedDeviceSessionTransportRequestV1,
  LinkedDeviceTargetCredentialRegistrationV1,
  LinkedDeviceTargetPreparationV1,
  QrLinkedDeviceSessionPayloadV4,
} from './contracts';
import type { SigningLaneRecord, WalletKeyRecord } from '../signing-lanes/records';
import type {
  EcdsaCapabilityManifestId,
  EcdsaCapabilityManifestRevision,
} from '../utils/ecdsaCapabilityActivation';
import type {
  WalletSessionAuthorizationId,
  WalletSessionId,
} from '../authorization/capabilityKinds';
import type {
  LaneOperationId,
  LaneOperationIdempotencyKey,
  LaneShareEpoch,
  LinkedDeviceEnrollmentId,
  LinkedDeviceId,
  LinkDeviceSessionId,
  SigningLaneId,
  WalletKeyId,
} from '../signing-lanes/ids';
import type {
  LaneHolderParticipantRecordV1,
  LaneHolderParticipantId,
  SigningWorkerParticipantId,
} from '../signing-lanes/participants';
import type { DigestB64u } from '../utils/canonicalPrimitives';
import type { OwnerLaneParticipantContinuityV1 } from '../signing-lanes/ownerContinuity';
import type {
  MpcMaterialActivationId,
  MpcMaterialActivationRef,
  WalletId,
  WebAuthnCredentialIdB64u,
  WebAuthnRpId,
} from '../utils/domainIds';

declare const linkSessionId: LinkDeviceSessionId;
declare const walletId: WalletId;
declare const enrollmentId: LinkedDeviceEnrollmentId;
declare const deviceId: LinkedDeviceId;
declare const walletKeyId: WalletKeyId;
declare const sourceLaneId: SigningLaneId;
declare const targetLaneId: SigningLaneId;
declare const sourceEpoch: LaneShareEpoch;
declare const targetEpoch: LaneShareEpoch;
declare const holderParticipantId: LaneHolderParticipantId;
declare const workerParticipantId: SigningWorkerParticipantId;
declare const operationId: LaneOperationId;
declare const idempotencyKey: LaneOperationIdempotencyKey;
declare const digest: DigestB64u;
declare const enrollmentReceipt: LinkedDeviceEnrollmentReceiptV1;
declare const enrollmentChildReceipt: LinkedDeviceEnrollmentChildReceiptV1;
declare const walletSessionId: WalletSessionId;
declare const authorizationId: WalletSessionAuthorizationId;
declare const materialActivationId: MpcMaterialActivationId;
declare const holderParticipant: LaneHolderParticipantRecordV1;
declare const rpId: WebAuthnRpId;
declare const credentialIdB64u: WebAuthnCredentialIdB64u;
declare const ed25519WalletKey: Extract<WalletKeyRecord, { readonly keyFamily: 'ed25519' }>;
declare const ecdsaWalletKey: Extract<WalletKeyRecord, { readonly keyFamily: 'ecdsa_secp256k1' }>;
declare const ownerLane: Extract<
  SigningLaneRecord,
  { readonly laneKind: 'owner_passkey' | 'owner_email_otp' }
>;
declare const materialActivation: MpcMaterialActivationRef;
declare const ownerParticipantContinuity: OwnerLaneParticipantContinuityV1;
declare const manifestId: EcdsaCapabilityManifestId;
declare const manifestRevision: EcdsaCapabilityManifestRevision;

declare const payload: QrLinkedDeviceSessionPayloadV4;
declare const ownerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1;

const ed25519OwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  kind: 'linked_device_owner_source_lane_v1',
  keyFamily: 'ed25519',
  walletKey: ed25519WalletKey,
  lane: ownerLane,
  materialActivation,
  verifiedActivationReceiptDigestB64u: digest,
};

const ecdsaOwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  kind: 'linked_device_owner_source_lane_v1',
  keyFamily: 'ecdsa_secp256k1',
  walletKey: ecdsaWalletKey,
  lane: ownerLane,
  materialActivation,
  verifiedActivationReceiptDigestB64u: digest,
  ecdsaSourceManifest: { manifestId, manifestRevision },
};

// @ts-expect-error Ed25519 source projections cannot carry ECDSA manifest identity.
const invalidEd25519OwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  ...ed25519OwnerSource,
  ecdsaSourceManifest: { manifestId, manifestRevision },
};

// @ts-expect-error ECDSA source projections require exact active manifest identity.
const invalidEcdsaOwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  kind: 'linked_device_owner_source_lane_v1',
  keyFamily: 'ecdsa_secp256k1',
  walletKey: ecdsaWalletKey,
  lane: ownerLane,
  materialActivation,
  verifiedActivationReceiptDigestB64u: digest,
};

// @ts-expect-error curve discriminator and wallet-key family must agree.
const invalidCrossCurveOwnerSource: LinkedDeviceOwnerSourceLaneV1 = {
  ...ed25519OwnerSource,
  walletKey: ecdsaWalletKey,
};

const displaying: Extract<LinkedDeviceSessionState, { readonly state: 'displaying_qr' }> = {
  state: 'displaying_qr',
  linkSessionId,
  expiresAtMs: 10,
};

const claimed: Extract<LinkedDeviceSessionState, { readonly state: 'claimed_by_owner' }> = {
  state: 'claimed_by_owner',
  linkSessionId,
  walletId,
  enrollmentId,
  claimExpiresAtMs: 20,
};

// Unclaimed states cannot acquire wallet or enrollment identity.
const invalidUnclaimedIdentity: Extract<
  LinkedDeviceSessionState,
  { readonly state: 'displaying_qr' }
> = {
  ...displaying,
  // @ts-expect-error unclaimed states cannot carry wallet identity
  walletId,
};

// Claimed states require both identities.
// @ts-expect-error a claimed state cannot omit enrollment identity
const invalidClaimedIdentity: Extract<
  LinkedDeviceSessionState,
  { readonly state: 'claimed_by_owner' }
> = {
  state: 'claimed_by_owner',
  linkSessionId,
  walletId,
  claimExpiresAtMs: 20,
};

// Dormant permission branches are deliberately absent from v4.
const invalidPermissionPayload: QrLinkedDeviceSessionPayloadV4 = {
  ...payload,
  requestedPermission: {
    // @ts-expect-error dormant scoped signing permission is not supported
    kind: 'scoped_signing',
    // @ts-expect-error dormant administration scope is not supported
    administrationScope: 'no_account_admin',
    mandatePolicyDigest: digest,
  },
};

const invalidPermissionPresence: QrLinkedDeviceSessionPayloadV4 = {
  ...payload,
  requestedPermission: {
    kind: 'owner_equivalent_signing',
    administrationScope: 'signing_only',
    // @ts-expect-error local presence is required
    localUserPresence: 'optional',
  },
};

const invalidOwnerAuthorization: LinkedDeviceOwnerAuthorizationSourceV1 = {
  kind: 'wallet_session',
  walletSessionId,
  authorizationId,
  // @ts-expect-error wallet-session authorization cannot carry step-up evidence
  stepUpEvidenceSetId: digest,
};

const approval: LinkedDeviceApprovalV1 = {
  kind: 'linked_device_approval_v1',
  linkSessionId,
  walletId,
  enrollmentId,
  deviceId,
  linkPublicKeyB64u: payload.linkPublicKeyB64u,
  devicePublicKeyB64u: payload.devicePublicKeyB64u,
  permission: payload.requestedPermission,
  ownerAuthorization,
  policyDigestB64u: digest,
  operationId,
  idempotencyKey,
  orderedKeyBindings: [
    {
      walletKeyId,
      keyFamily: 'ed25519',
      sourceLaneId,
      sourceLaneKind: 'linked_device',
      sourceKind: 'provisioned_lane',
      sourceLaneShareEpoch: sourceEpoch,
      sourceRevocationEpoch: 0,
      sourceHolderParticipantId: holderParticipantId,
      sourceSigningWorkerParticipantId: workerParticipantId,
      targetLaneId,
      targetLaneShareEpoch: targetEpoch,
    },
  ],
  protocolVersions: [{ keyFamily: 'ed25519', version: 'rotatable_signing_lane_protocol_v1' }],
  approvedAtMs: 1,
  expiresAtMs: 2,
};

const ownerApprovalBinding: LinkedDeviceApprovalV1['orderedKeyBindings'][number] = {
  walletKeyId,
  keyFamily: 'ed25519',
  sourceLaneId,
  sourceLaneKind: 'owner_passkey',
  sourceKind: 'owner_registration',
  sourceLaneShareEpoch: sourceEpoch,
  sourceRevocationEpoch: 0,
  ownerParticipantContinuity,
  targetLaneId,
  targetLaneShareEpoch: targetEpoch,
};

// @ts-expect-error owner bindings cannot carry provisioned holder identity.
const invalidMixedOwnerApprovalBinding: LinkedDeviceApprovalV1['orderedKeyBindings'][number] = {
  ...ownerApprovalBinding,
  sourceHolderParticipantId: holderParticipantId,
};

const summary: LinkedDeviceSummaryV1 = {
  deviceId,
  enrollmentId,
  walletId,
  label: 'Target device',
  platform: 'browser',
  permission: payload.requestedPermission,
  keyManifestDigestB64u: digest,
  coveredWalletKeys: [walletKeyId],
  state: 'provisioning',
  createdAtMs: 1,
  lastActivityAtMs: 2,
  revocationEpoch: 0,
};

const validReceiptAcknowledgement: LinkedDeviceReceiptAcknowledgementV1 = {
  kind: 'linked_device_receipt_acknowledgement_v1',
  linkSessionId,
  enrollmentId,
  deviceId,
  receipt: enrollmentReceipt,
  acknowledgedAtMs: 3,
};

const invalidChildReceiptAcknowledgement: LinkedDeviceReceiptAcknowledgementV1 = {
  kind: 'linked_device_receipt_acknowledgement_v1',
  linkSessionId,
  enrollmentId,
  deviceId,
  // @ts-expect-error acknowledgements cover the full aggregate enrollment receipt
  receipt: enrollmentChildReceipt,
  acknowledgedAtMs: 3,
};

const invalidSummaryState: LinkedDeviceSummaryV1 = {
  ...summary,
  // @ts-expect-error management projections have an exhaustive lifecycle
  state: 'pending',
};

// @ts-expect-error successful revocation results require enrollment receipt identity
const invalidRevokeResult: LinkedDeviceRevokeResultV1 = {
  kind: 'revoked',
};

// Approval always contains a non-empty ordered manifest.
const invalidEmptyApprovalManifest: LinkedDeviceApprovalV1 = {
  ...approval,
  // @ts-expect-error empty manifests cannot activate an enrollment
  orderedKeyBindings: [],
};

const targetPreparation: LinkedDeviceTargetPreparationV1 = {
  kind: 'linked_device_target_preparation_v1',
  linkSessionId,
  walletId,
  enrollmentId,
  deviceId,
  rpId,
  userHandleB64u: 'AQ',
  challengeB64u: digest,
  orderedChildren: [
    {
      kind: 'linked_device_target_preparation_child_v1',
      operationId,
      walletKeyId,
      keyFamily: 'ed25519',
      targetLaneId,
      targetLaneShareEpoch: targetEpoch,
      targetMaterialActivationId: materialActivationId,
      targetHolderParticipantId: holderParticipantId,
    },
  ],
  issuedAtMs: 1,
  expiresAtMs: 2,
};

const invalidEmptyTargetPreparation: LinkedDeviceTargetPreparationV1 = {
  ...targetPreparation,
  // @ts-expect-error a target preparation requires at least one R102 child
  orderedChildren: [],
};

const credentialRegistration: LinkedDeviceTargetCredentialRegistrationV1 = {
  kind: 'linked_device_target_credential_registration_v1',
  linkSessionId,
  walletId,
  enrollmentId,
  deviceId,
  targetPreparationDigestB64u: digest,
  webauthnRegistration: {
    kind: 'linked_device_webauthn_registration_v1',
    credentialIdB64u,
    authenticatorAttachment: 'platform',
    clientDataJsonB64u: 'AQ',
    attestationObjectB64u: 'Ag',
    transports: ['internal'],
  },
  orderedHolderRegistrations: [
    {
      kind: 'linked_device_target_holder_registration_v1',
      operationId,
      walletKeyId,
      keyFamily: 'ed25519',
      targetLaneId,
      targetLaneShareEpoch: targetEpoch,
      targetMaterialActivationId: materialActivationId,
      holderParticipant,
    },
  ],
  registeredAtMs: 3,
};

const invalidIdOnlyCredentialRegistration: LinkedDeviceTargetCredentialRegistrationV1 = {
  kind: 'linked_device_target_credential_registration_v1',
  linkSessionId,
  walletId,
  enrollmentId,
  deviceId,
  // @ts-expect-error an ID cannot replace verified attestation and holder registrations
  credentialIdB64u: 'AQ',
  registeredAtMs: 3,
};

// Unclaimed cancellation cannot carry target identity; claimed cancellation requires it.
const invalidUnclaimedCancel: LinkedDeviceSessionTransportRequestV1 = {
  kind: 'linked_device_session_cancel_unclaimed_request_v1',
  linkSessionId,
  reason: 'user_cancelled',
  requestedAtMs: 1,
  // @ts-expect-error unclaimed cancellation has no device identity
  deviceId,
};

// @ts-expect-error claimed cancellation requires enrollment identity
const invalidClaimedCancel: LinkedDeviceSessionTransportRequestV1 = {
  kind: 'linked_device_session_cancel_claimed_request_v1',
  linkSessionId,
  deviceId,
  reason: 'user_cancelled',
  requestedAtMs: 1,
};

void invalidUnclaimedIdentity;
void claimed;
void invalidClaimedIdentity;
void invalidPermissionPayload;
void invalidPermissionPresence;
void invalidOwnerAuthorization;
void invalidEmptyApprovalManifest;
void invalidEmptyTargetPreparation;
void credentialRegistration;
void invalidIdOnlyCredentialRegistration;
void summary;
void validReceiptAcknowledgement;
void invalidChildReceiptAcknowledgement;
void invalidSummaryState;
void invalidRevokeResult;
void invalidUnclaimedCancel;
void invalidClaimedCancel;
void ed25519OwnerSource;
void ecdsaOwnerSource;
void invalidEd25519OwnerSource;
void invalidEcdsaOwnerSource;
void invalidCrossCurveOwnerSource;
