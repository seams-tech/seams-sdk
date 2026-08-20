import { parseWalletAddAuthMethodRegistrationOptions } from '../utils/addAuthMethodRegistration';
import {
  parseAuthorizationEvidenceSetId,
  parseLinkedDeviceWalletSessionAuthorizationId,
  parseMpcWalletSigningQuotaId,
  parseTenantId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type AuthorizationEvidenceSetId,
  type LinkedDeviceWalletSessionAuthorizationId,
  type MpcWalletSigningQuotaId,
  type TenantId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '../authorization/capabilityKinds';
import {
  parseLaneHolderParticipantRecordV1,
  parseLaneHolderParticipantId,
  parseSigningWorkerParticipantId,
  type LaneHolderParticipantRecordV1,
  type LaneHolderParticipantId,
  type SigningWorkerParticipantId,
} from '../signing-lanes/participants';
import {
  parseLaneOperationId,
  parseLaneOperationIdempotencyKey,
  parseLaneShareEpoch,
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseSigningLaneId,
  parseWalletKeyId,
  type LaneOperationId,
  type LaneOperationIdempotencyKey,
  type LaneShareEpoch,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
  type SigningLaneId,
  type WalletKeyId,
} from '../signing-lanes/ids';
import {
  parseMpcMaterialActivationId,
  parseMpcMaterialActivationRef,
  parseWalletAuthMethodId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type MpcMaterialActivationId,
  type MpcMaterialActivationRef,
  type WalletId,
  type WebAuthnCredentialIdB64u,
  type WebAuthnRpId,
} from '../utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { parsePasskeyCustodyEnvelopeRecord } from '../passkey-custody/custodyEnvelope';
import {
  parseLaneHolderPackageWireV1,
  parseLaneHolderDeliveryReceiptV1,
  parseLaneProtocolCommitReceiptV1,
  parseRotatableSigningLaneJobV1,
  parseLaneEnrollmentManifestV1,
} from '../signing-lanes/rotationParsers';
import { parseSigningLaneRecord, parseWalletKeyRecord } from '../signing-lanes/recordParsers';
import {
  parseEcdsaCapabilityManifestId,
  parseEcdsaCapabilityManifestRevision,
} from '../utils/ecdsaCapabilityActivation';
import type {
  LaneEnrollmentManifestV1,
  LaneProtocolCommitReceiptV1,
  RotatableSigningLaneJobV1,
} from '../signing-lanes/rotation';
import { parseOwnerLaneParticipantContinuityV1 } from '../signing-lanes/ownerContinuity';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { decodeJwtPayloadRecord } from '../utils/sessionTokens';
const ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND =
  'router_ab_ecdsa_derivation_wallet_session_v1';
const ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND = 'router_ab_ed25519_wallet_session_v1';
import { parseUnixMs, requireRecord, rejectUnknownFields } from '../passkey-custody/primitives';
import { parseNearAccountId } from '../utils/near';
import { parseWebAuthnAuthenticatorDeviceInfo } from '../utils/webauthnDeviceInfo';
import {
  assertNeverLinkedDeviceSessionState,
  type LinkedDeviceApprovalV1,
  type LinkedDeviceApprovalDeliveryV1,
  type LinkedDeviceApprovalResultV1,
  type LinkedDeviceProvisioningChildV1,
  type LinkedDeviceProvisioningCommandV1,
  type LinkedDeviceProvisioningDeliveriesV1,
  type LinkedDeviceProvisioningDeliveriesSubmissionV1,
  type LinkedDeviceHolderDeliveryAcknowledgementV1,
  type LinkedDeviceEnrollmentChildReceiptV1,
  type LinkedDeviceEnrollmentKeyBindingV1,
  type LinkedDeviceEnrollmentReceiptV1,
  type LinkedDeviceEnrollmentTranscriptV1,
  type LinkedDeviceListRequestV1,
  type LinkedDeviceListResultV1,
  type OwnerDeviceSummaryV1,
  type LinkedDeviceRevokeRequestV1,
  type LinkedDeviceRevokeResultV1,
  type LinkedDeviceSummaryV1,
  type LinkedOwnerCredentialMetadataV1,
  type LinkedDeviceWalletSessionDeliveryV1,
  type LinkedDeviceWalletSessionTokenV1,
  type LinkedDeviceOwnerAuthorizationSourceV1,
  type LinkedDeviceOwnerAuthorizationRequestV1,
  type LinkedDeviceOwnerSourceLaneV1,
  type LinkedDeviceProtocolVersionV1,
  type LinkedDeviceReceiptAcknowledgementV1,
  type LinkedDeviceSessionClaimRequestV1,
  type LinkedDeviceSessionClaimV1,
  type LinkedDeviceSessionProjectionV1,
  type LinkedDeviceSessionState,
  type LinkedDeviceSessionUnclaimedState,
  type LinkedDeviceSessionTransportEventV1,
  type LinkedDeviceSessionTransportRequestV1,
  type LinkedDeviceTargetCredentialRegistrationV1,
  type LinkedDeviceEmailOtpVerificationGrantV1,
  type LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  type LinkedDeviceEmailOtpChallengeStartRequestV1,
  type LinkedDeviceEmailOtpChallengeResendRequestV1,
  type LinkedDeviceEmailOtpChallengeVerifyRequestV1,
  type LinkedDeviceEmailOtpChallengeResultV1,
  type LinkedDeviceEmailOtpVerificationResultV1,
  type LinkedDeviceTargetHolderRegistrationV1,
  type LinkedDeviceTargetPreparationChildV1,
  type LinkedDeviceOwnerEnrollmentCeremonyV1,
  type LinkedDeviceTargetPreparationV1,
  type LinkedDeviceTargetReadyR102InputV1,
  type LinkedDeviceWebAuthnRegistrationV1,
  type LinkDevicePublicKeyB64u,
  type QrLinkedDevicePermissionRequest,
  type QrLinkedDeviceSessionPayloadV5,
  type LinkedDeviceTargetFactorV1,
  type LinkedDeviceLocalAccountProjectionV1,
  type LinkedDeviceOwnerFinalizeRequestV1,
} from './contracts';

type UnknownRecord = Record<string, unknown>;

const QR_FIELDS = [
  'version',
  'purpose',
  'linkSessionId',
  'linkPublicKeyB64u',
  'devicePublicKeyB64u',
  'requestedPermission',
  'targetFactor',
  'issuedAtMs',
  'expiresAtMs',
] as const;
const COMPACT_QR_FIELDS = ['v', 's', 'l', 'd', 'f', 'i', 'e'] as const;
const OWNER_AUTHORIZATION_REQUEST_FIELDS = [
  'payload',
  'requestedAtMs',
  'orderedOwnerSourceLaneHints',
] as const;
const OWNER_SOURCE_LANE_COMMON_FIELDS = [
  'kind',
  'keyFamily',
  'walletKey',
  'lane',
  'materialActivation',
  'verifiedActivationReceiptDigestB64u',
] as const;
const LINKED_WALLET_SESSION_DELIVERY_FIELDS = [
  'kind',
  'tenantId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'authorizationId',
  'walletSessionId',
  'quotaId',
  'keyManifestDigestB64u',
  'permission',
  'revocationEpoch',
  'remainingUses',
  'issuedAtMs',
  'expiresAtMs',
  'orderedTokens',
] as const;
const LINKED_WALLET_SESSION_DELIVERY_WITH_NEAR_FIELDS = [
  ...LINKED_WALLET_SESSION_DELIVERY_FIELDS,
  'nearAccountId',
] as const;
const LINKED_WALLET_SESSION_TOKEN_FIELDS = [
  'kind',
  'walletKeyId',
  'keyFamily',
  'walletSessionJwt',
  'revocationEpoch',
] as const;
const LINKED_WALLET_SESSION_JWT_FIELDS = [
  'kind',
  'authorizationKind',
  'sub',
  'tenantId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'walletKeyId',
  'authorizationId',
  'walletSessionId',
  'quotaId',
  'keyManifestDigestB64u',
  'permission',
  'revocationEpoch',
  'issuedAtMs',
  'expiresAtMs',
  'iat',
  'exp',
] as const;
const LINKED_WALLET_SESSION_JWT_OPTIONAL_FIELDS = ['iss', 'aud'] as const;
const PERMISSION_FIELDS = ['kind', 'administrationScope', 'localUserPresence'] as const;
const CLAIM_REQUEST_FIELDS = ['kind', 'payload'] as const;
const CLAIM_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'devicePublicKeyB64u',
  'targetFactor',
  'claimedAtMs',
  'claimExpiresAtMs',
] as const;
const OWNER_AUTH_WALLET_SESSION_FIELDS = ['kind', 'walletSessionId', 'authorizationId'] as const;
const OWNER_AUTH_STEP_UP_FIELDS = ['kind', 'evidenceSetId'] as const;
const KEY_BINDING_BASE_FIELDS = [
  'walletKeyId',
  'keyFamily',
  'sourceLaneId',
  'sourceLaneKind',
  'sourceKind',
  'sourceLaneShareEpoch',
  'sourceRevocationEpoch',
  'targetLaneId',
  'targetLaneShareEpoch',
] as const;
const OWNER_KEY_BINDING_FIELDS = [
  ...KEY_BINDING_BASE_FIELDS,
  'ownerParticipantContinuity',
] as const;
const PROVISIONED_KEY_BINDING_FIELDS = [
  ...KEY_BINDING_BASE_FIELDS,
  'sourceHolderParticipantId',
  'sourceSigningWorkerParticipantId',
] as const;
const PROTOCOL_VERSION_FIELDS = ['keyFamily', 'version'] as const;
const ENROLLMENT_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'linkPublicKeyB64u',
  'devicePublicKeyB64u',
  'permission',
  'targetFactor',
  'ownerAuthorization',
  'ownerEnrollment',
  'policyDigestB64u',
  'operationId',
  'idempotencyKey',
  'orderedKeyBindings',
  'protocolVersions',
  'approvedAtMs',
  'expiresAtMs',
] as const;
const PROVISIONING_COMMAND_FIELDS = [
  'kind',
  'linkSessionId',
  'enrollmentId',
  'deviceId',
  'targetFactor',
] as const;
const PROVISIONING_DELIVERIES_FIELDS = [
  'kind',
  'linkSessionId',
  'enrollmentId',
  'deviceId',
  'manifest',
  'orderedChildren',
] as const;
const PROVISIONING_CHILD_FIELDS = [
  'kind',
  'job',
  'protocolCommitReceipt',
  'holderPackage',
  'expectedVersion',
] as const;
const TARGET_READY_R102_INPUT_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'manifest',
  'children',
] as const;
const PROVISIONING_DELIVERIES_SUBMISSION_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'manifestDigestB64u',
  'deliveries',
] as const;
const APPROVAL_DELIVERY_FIELDS = ['kind', 'approval'] as const;
const HOLDER_DELIVERY_ACK_FIELDS = [
  'kind',
  'linkSessionId',
  'enrollmentId',
  'deviceId',
  'orderedHolderDeliveryReceipts',
  'acknowledgedAtMs',
] as const;
const CHILD_RECEIPT_FIELDS = [
  'kind',
  'enrollmentId',
  'walletId',
  'walletKeyId',
  'keyFamily',
  'targetLaneId',
  'targetLaneShareEpoch',
  'materialActivation',
  'receiptDigestB64u',
  'transcriptHashB64u',
  'deliveredAtMs',
] as const;
const ENROLLMENT_RECEIPT_FIELDS = [
  'kind',
  'enrollmentId',
  'walletId',
  'deviceId',
  'targetFactor',
  'manifestDigestB64u',
  'aggregateReceiptDigestB64u',
  'orderedChildReceipts',
  'activatedAtMs',
] as const;
const CREDENTIAL_BASE_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'targetFactor',
  'targetPreparationDigestB64u',
  'orderedHolderRegistrations',
  'registeredAtMs',
] as const;
const PASSKEY_CREDENTIAL_FIELDS = [...CREDENTIAL_BASE_FIELDS, 'webauthnRegistration'] as const;
const EMAIL_OTP_CREDENTIAL_FIELDS = [
  ...CREDENTIAL_BASE_FIELDS,
  'emailOtpVerificationGrant',
] as const;
const TARGET_PREPARATION_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'targetFactor',
  'ownerEnrollment',
  'orderedChildren',
  'issuedAtMs',
  'expiresAtMs',
] as const;
const PASSKEY_OWNER_ENROLLMENT_FIELDS = [
  'kind',
  'targetFactor',
  'addAuthMethodCeremonyId',
  'registration',
  'expiresAtMs',
] as const;
const EMAIL_OTP_OWNER_ENROLLMENT_FIELDS = [
  'kind',
  'targetFactor',
  'baseWalletAuthMethodId',
  'maskedEmailHint',
  'expiresAtMs',
] as const;
const EMAIL_OTP_VERIFICATION_GRANT_FIELDS = [
  'kind',
  'grantId',
  'grantToken',
  'challengeId',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'targetPreparationDigestB64u',
  'baseWalletAuthMethodId',
  'emailHashHex',
  'registrationAuthorityId',
  'providerUserId',
  'linkedOwnerAuthMethodId',
  'authorityDigestB64u',
  'issuedAtMs',
  'expiresAtMs',
] as const;
const EMAIL_OTP_FACTOR_RELEASE_FIELDS = [
  'kind',
  'challengeId',
  'enrollmentId',
  'enrollmentSealKeyVersion',
  'serverEphemeralPublicKey65B64u',
  'nonce12B64u',
  'ciphertextB64u',
] as const;
const TARGET_PREPARATION_CHILD_FIELDS = [
  'kind',
  'operationId',
  'walletKeyId',
  'keyFamily',
  'targetLaneId',
  'targetLaneShareEpoch',
  'targetMaterialActivationId',
  'targetHolderParticipantId',
] as const;
const WEBAUTHN_REGISTRATION_FIELDS = [
  'kind',
  'credentialIdB64u',
  'authenticatorAttachment',
  'clientDataJsonB64u',
  'attestationObjectB64u',
  'transports',
] as const;
const TARGET_HOLDER_REGISTRATION_FIELDS = [
  'kind',
  'operationId',
  'walletKeyId',
  'keyFamily',
  'targetLaneId',
  'targetLaneShareEpoch',
  'targetMaterialActivationId',
  'holderParticipant',
] as const;
const RECEIPT_ACK_FIELDS = [
  'kind',
  'linkSessionId',
  'enrollmentId',
  'deviceId',
  'receipt',
  'acknowledgedAtMs',
] as const;
const SESSION_PROJECTION_BASE_FIELDS = [
  'kind',
  'linkSessionId',
  'qrPayload',
  'revision',
  'createdAtMs',
  'updatedAtMs',
  'state',
] as const;
const SESSION_PROJECTION_CLAIMED_FIELDS = [...SESSION_PROJECTION_BASE_FIELDS, 'deviceId'] as const;
const APPROVAL_PENDING_FIELDS = ['outcome', 'state'] as const;
const APPROVAL_ACTIVE_FIELDS = ['outcome', 'state', 'manifestDigestB64u', 'receipt'] as const;
const APPROVAL_REPLAY_FIELDS = ['outcome', 'replay'] as const;
const APPROVAL_REPLAY_PENDING_FIELDS = ['state', 'session'] as const;
const APPROVAL_REPLAY_ACTIVE_FIELDS = [
  'state',
  'session',
  'manifestDigestB64u',
  'receipt',
] as const;
const LINKED_DEVICE_SUMMARY_FIELDS = [
  'deviceId',
  'enrollmentId',
  'walletId',
  'credential',
  'permission',
  'keyManifestDigestB64u',
  'coveredWalletKeys',
  'state',
  'createdAtMs',
  'lastActivityAtMs',
  'revocationEpoch',
] as const;
const LINKED_OWNER_PASSKEY_CREDENTIAL_FIELDS = [
  'kind',
  'walletAuthMethodId',
  'credentialIdB64u',
  'device',
] as const;
const LINKED_OWNER_EMAIL_OTP_CREDENTIAL_FIELDS = ['kind', 'walletAuthMethodId'] as const;
const LINKED_DEVICE_LIST_REQUEST_FIELDS = ['kind', 'walletId', 'limit', 'cursor'] as const;
const OWNER_DEVICE_SUMMARY_FIELDS = [
  'walletId',
  'credential',
  'createdAtMs',
  'lastActivityAtMs',
] as const;
const LINKED_DEVICE_LIST_RESULT_FIELDS = ['devices', 'ownerDevices', 'nextCursor'] as const;
const LINKED_DEVICE_REVOKE_REQUEST_FIELDS = [
  'kind',
  'walletId',
  'deviceId',
  'requestedAtMs',
] as const;
const LINKED_DEVICE_REVOKE_SUCCESS_FIELDS = [
  'kind',
  'enrollmentId',
  'revocationEpoch',
  'aggregateReceiptDigestB64u',
] as const;
const LINKED_DEVICE_REVOKE_FAILURE_FIELDS = ['kind'] as const;

const SESSION_STATE_FIELDS = {
  displaying_qr: ['state', 'linkSessionId', 'expiresAtMs'],
  claimed_by_owner: ['state', 'linkSessionId', 'walletId', 'enrollmentId', 'claimExpiresAtMs'],
  awaiting_target_factor: [
    'state',
    'linkSessionId',
    'walletId',
    'enrollmentId',
    'targetFactor',
    'credentialDeadlineMs',
  ],
  provisioning: ['state', 'linkSessionId', 'walletId', 'enrollmentId', 'keyManifestDigestB64u'],
  active: ['state', 'linkSessionId', 'walletId', 'enrollmentId', 'activatedAtMs'],
  expired_unclaimed: ['state', 'linkSessionId', 'expiredAtMs'],
  expired_claimed: ['state', 'linkSessionId', 'walletId', 'enrollmentId', 'expiredAtMs'],
  cancelled_unclaimed: ['state', 'linkSessionId', 'cancelledAtMs'],
  cancelled_claimed_precommit: [
    'state',
    'linkSessionId',
    'walletId',
    'enrollmentId',
    'cancelledAtMs',
  ],
  committed_completion_required: [
    'state',
    'linkSessionId',
    'walletId',
    'enrollmentId',
    'keyManifestDigestB64u',
    'transcriptSetDigestB64u',
  ],
} as const;

const AWAITING_PASSKEY_FACTOR_STATE_FIELDS = [
  'state',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'targetFactor',
  'credentialDeadlineMs',
] as const;
const AWAITING_EMAIL_OTP_FACTOR_STATE_FIELDS = [
  'state',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'targetFactor',
  'emailOtpChallenge',
] as const;

function exactRecord(raw: unknown, fields: readonly string[], label: string): UnknownRecord {
  const record = requireRecord(raw, label);
  rejectUnknownFields(record, fields, label);
  for (const field of fields) {
    if (!Object.prototype.hasOwnProperty.call(record, field) || record[field] === undefined) {
      throw new Error(`${label}.${field} is required`);
    }
  }
  return record;
}

function parseId<T>(
  parser: (
    raw: unknown,
  ) =>
    | { readonly ok: true; readonly value: T }
    | { readonly ok: false; readonly error: { readonly message: string } },
  raw: unknown,
  label: string,
): T {
  const result = parser(raw);
  if (result.ok) return result.value;
  throw new Error(`${label} ${result.error.message}`);
}

function parseUnixTime(raw: unknown, label: string): number {
  try {
    return parseUnixMs(raw, label);
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : `${label} is invalid`);
  }
}

function parseNonEmptyToken(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || raw.trim() !== raw) {
    throw new Error(`${label} must be a non-empty canonical string`);
  }
  for (const character of raw) {
    const code = character.charCodeAt(0);
    if (/\s/.test(character) || code <= 31 || code === 127) {
      throw new Error(`${label} must not contain whitespace or control characters`);
    }
  }
  return raw;
}

function parseEmailHashHex(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || !/^[0-9a-f]{64}$/.test(raw)) {
    throw new Error(`${label} must be 32 canonical lowercase hex bytes`);
  }
  return raw;
}

function parseDigest(raw: unknown, label: string): DigestB64u {
  try {
    return parseDigestB64u(raw);
  } catch (error) {
    throw new Error(`${label} ${error instanceof Error ? error.message : 'is invalid'}`);
  }
}

function parsePublicKey(raw: unknown, label: string): LinkDevicePublicKeyB64u {
  if (typeof raw !== 'string' || raw.length === 0 || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error(`${label} must be canonical unpadded base64url`);
  }
  try {
    const decoded = base64UrlDecode(raw);
    if (decoded.length !== 32 || base64UrlEncode(decoded) !== raw) throw new Error('non-canonical');
  } catch {
    throw new Error(`${label} must be a canonical 32-byte unpadded base64url key`);
  }
  return raw as LinkDevicePublicKeyB64u;
}

function parseCanonicalBase64UrlBytes(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || raw.length === 0 || !/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error(`${label} must be canonical unpadded base64url`);
  }
  try {
    const decoded = base64UrlDecode(raw);
    if (decoded.length === 0 || base64UrlEncode(decoded) !== raw) throw new Error('non-canonical');
  } catch {
    throw new Error(`${label} must be canonical unpadded base64url`);
  }
  return raw;
}

function parseCanonicalFixedBase64UrlBytes(raw: unknown, length: number, label: string): string {
  const value = parseCanonicalBase64UrlBytes(raw, label);
  const decoded = base64UrlDecode(value);
  try {
    if (decoded.length !== length) throw new Error(`${label} must encode ${length} bytes`);
    return value;
  } finally {
    decoded.fill(0);
  }
}

// An ECDH recipient or sender key must be a well-formed uncompressed SEC1
// P-256 point (65 bytes, 0x04 prefix) before it is persisted or sealed to —
// a malformed point would otherwise fail only after the OTP code is spent.
function parseUncompressedP256PointB64u(raw: unknown, label: string): string {
  const value = parseCanonicalFixedBase64UrlBytes(raw, 65, label);
  const decoded = base64UrlDecode(value);
  try {
    if (decoded[0] !== 0x04) {
      throw new Error(`${label} must be an uncompressed SEC1 P-256 point`);
    }
    return value;
  } finally {
    decoded.fill(0);
  }
}

export function parseLinkDevicePublicKeyB64u(raw: unknown): LinkDevicePublicKeyB64u {
  return parsePublicKey(raw, 'LinkDevicePublicKeyB64u');
}

function parseCredential(raw: unknown, label: string): WebAuthnCredentialIdB64u {
  const value = parseCanonicalBase64UrlBytes(raw, label);
  return parseId(parseWebAuthnCredentialIdB64u, value, label);
}

function parseKeyFamily(raw: unknown, label: string): 'ed25519' | 'ecdsa_secp256k1' {
  if (raw !== 'ed25519' && raw !== 'ecdsa_secp256k1') {
    throw new Error(`${label} must identify a supported key family`);
  }
  return raw;
}

function parseSigningLaneKind(
  raw: unknown,
  label: string,
):
  | 'owner_passkey'
  | 'owner_email_otp'
  | 'linked_device'
  | 'delegated_execution'
  | 'recovery'
  | 'break_glass' {
  switch (raw) {
    case 'owner_passkey':
    case 'owner_email_otp':
    case 'linked_device':
    case 'delegated_execution':
    case 'recovery':
    case 'break_glass':
      return raw;
    default:
      throw new Error(`${label} must identify a supported signing lane kind`);
  }
}

function parseNonNegativeSafeInteger(raw: unknown, label: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(raw);
}

function parsePositiveSafeInteger(raw: unknown, label: string): number {
  const value = parseNonNegativeSafeInteger(raw, label);
  if (value < 1) throw new Error(`${label} must be a positive safe integer`);
  return value;
}

function parseNullableCursor(raw: unknown, label: string): string | null {
  if (raw === null) return null;
  return parseNonEmptyToken(raw, label);
}

function assertExpiryAfterIssued(issuedAtMs: number, expiresAtMs: number, label: string): void {
  if (expiresAtMs <= issuedAtMs) throw new Error(`${label}.expiresAtMs must be after issuedAtMs`);
}

function nonEmptyTuple<T>(values: readonly T[], label: string): [T, ...T[]] {
  if (values.length === 0) throw new Error(`${label} must be non-empty`);
  const [first, ...rest] = values;
  return [first, ...rest];
}

function parsePermission(
  raw: unknown,
  label = 'requestedPermission',
): QrLinkedDevicePermissionRequest {
  const record = exactRecord(raw, PERMISSION_FIELDS, label);
  if (record.kind !== 'owner_equivalent_signing') throw new Error(`${label}.kind is unsupported`);
  if (record.administrationScope !== 'signing_only') {
    throw new Error(`${label}.administrationScope is unsupported`);
  }
  if (record.localUserPresence !== 'required') {
    throw new Error(`${label}.localUserPresence is unsupported`);
  }
  return {
    kind: 'owner_equivalent_signing',
    administrationScope: 'signing_only',
    localUserPresence: 'required',
  };
}

function parseTargetFactor(raw: unknown, label: string): LinkedDeviceTargetFactorV1 {
  const record = exactRecord(raw, ['kind'], label);
  switch (record.kind) {
    case 'passkey_prf':
      return { kind: 'passkey_prf' };
    case 'email_otp':
      return { kind: 'email_otp' };
    default:
      throw new Error(`${label}.kind is unsupported`);
  }
}

function parseSessionId(raw: unknown, label: string): LinkDeviceSessionId {
  return parseId(parseLinkDeviceSessionId, raw, label);
}
function parseWallet(raw: unknown, label: string): WalletId {
  return parseId(parseWalletId, raw, label);
}
function parseEnrollmentId(raw: unknown, label: string): LinkedDeviceEnrollmentId {
  return parseId(parseLinkedDeviceEnrollmentId, raw, label);
}
function parseDeviceId(raw: unknown, label: string): LinkedDeviceId {
  return parseId(parseLinkedDeviceId, raw, label);
}
function parseWalletKey(raw: unknown, label: string): WalletKeyId {
  return parseId(parseWalletKeyId, raw, label);
}
function parseLaneId(raw: unknown, label: string): SigningLaneId {
  return parseId(parseSigningLaneId, raw, label);
}
function parseLaneEpoch(raw: unknown, label: string): LaneShareEpoch {
  return parseId(parseLaneShareEpoch, raw, label);
}
function parseOperation(raw: unknown, label: string): LaneOperationId {
  return parseId(parseLaneOperationId, raw, label);
}
function parseIdempotencyKey(raw: unknown, label: string): LaneOperationIdempotencyKey {
  return parseId(parseLaneOperationIdempotencyKey, raw, label);
}
function parseHolderParticipant(raw: unknown, label: string): LaneHolderParticipantId {
  return parseId(parseLaneHolderParticipantId, raw, label);
}
function parseSigningWorkerParticipant(raw: unknown, label: string): SigningWorkerParticipantId {
  return parseId(parseSigningWorkerParticipantId, raw, label);
}
function parseActivation(raw: unknown, label: string): MpcMaterialActivationRef {
  return parseId(parseMpcMaterialActivationRef, raw, label);
}
function parseWalletSession(raw: unknown, label: string): WalletSessionId {
  return parseId(parseWalletSessionId, raw, label);
}
function parseWalletAuthorization(raw: unknown, label: string): WalletSessionAuthorizationId {
  return parseId(parseWalletSessionAuthorizationId, raw, label);
}
function parseEvidenceSet(raw: unknown, label: string): AuthorizationEvidenceSetId {
  return parseId(parseAuthorizationEvidenceSetId, raw, label);
}

function parseLinkedOwnerCredentialMetadata(
  raw: unknown,
  label: string,
): LinkedOwnerCredentialMetadataV1 {
  const record = requireRecord(raw, label);
  switch (record.kind) {
    case 'passkey': {
      const exact = exactRecord(record, LINKED_OWNER_PASSKEY_CREDENTIAL_FIELDS, label);
      const device = parseWebAuthnAuthenticatorDeviceInfo(exact.device);
      if (!device) throw new Error(`${label}.device is invalid`);
      return {
        kind: 'passkey',
        walletAuthMethodId: parseId(
          parseWalletAuthMethodId,
          exact.walletAuthMethodId,
          `${label}.walletAuthMethodId`,
        ),
        credentialIdB64u: parseId(
          parseWebAuthnCredentialIdB64u,
          exact.credentialIdB64u,
          `${label}.credentialIdB64u`,
        ),
        device,
      };
    }
    case 'email_otp': {
      const exact = exactRecord(record, LINKED_OWNER_EMAIL_OTP_CREDENTIAL_FIELDS, label);
      return {
        kind: 'email_otp',
        walletAuthMethodId: parseId(
          parseWalletAuthMethodId,
          exact.walletAuthMethodId,
          `${label}.walletAuthMethodId`,
        ),
      };
    }
    default:
      throw new Error(`${label}.kind is invalid`);
  }
}

function parseLinkedDeviceSummaryRecord(record: UnknownRecord): LinkedDeviceSummaryV1 {
  const state = record.state;
  if (
    state !== 'provisioning' &&
    state !== 'active' &&
    state !== 'suspended' &&
    state !== 'expired' &&
    state !== 'revoked'
  ) {
    throw new Error('LinkedDeviceSummaryV1.state is invalid');
  }
  if (!Array.isArray(record.coveredWalletKeys)) {
    throw new Error('LinkedDeviceSummaryV1.coveredWalletKeys is invalid');
  }
  const coveredWalletKeys = record.coveredWalletKeys.map((value, index) =>
    parseWalletKey(value, `LinkedDeviceSummaryV1.coveredWalletKeys[${index}]`),
  );
  return {
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceSummaryV1.deviceId'),
    enrollmentId: parseEnrollmentId(record.enrollmentId, 'LinkedDeviceSummaryV1.enrollmentId'),
    walletId: parseWallet(record.walletId, 'LinkedDeviceSummaryV1.walletId'),
    credential: parseLinkedOwnerCredentialMetadata(
      record.credential,
      'LinkedDeviceSummaryV1.credential',
    ),
    permission: parsePermission(record.permission, 'LinkedDeviceSummaryV1.permission'),
    keyManifestDigestB64u: parseDigest(
      record.keyManifestDigestB64u,
      'LinkedDeviceSummaryV1.keyManifestDigestB64u',
    ),
    coveredWalletKeys,
    state,
    createdAtMs: parseUnixTime(record.createdAtMs, 'LinkedDeviceSummaryV1.createdAtMs'),
    lastActivityAtMs: parseUnixTime(
      record.lastActivityAtMs,
      'LinkedDeviceSummaryV1.lastActivityAtMs',
    ),
    revocationEpoch: parseNonNegativeSafeInteger(
      record.revocationEpoch,
      'LinkedDeviceSummaryV1.revocationEpoch',
    ),
  };
}

export function parseLinkedDeviceSummaryV1(raw: unknown): LinkedDeviceSummaryV1 {
  return parseLinkedDeviceSummaryRecord(
    exactRecord(raw, LINKED_DEVICE_SUMMARY_FIELDS, 'LinkedDeviceSummaryV1'),
  );
}

export function parseLinkedDeviceListRequestV1(raw: unknown): LinkedDeviceListRequestV1 {
  const record = exactRecord(raw, LINKED_DEVICE_LIST_REQUEST_FIELDS, 'LinkedDeviceListRequestV1');
  if (record.kind !== 'linked_device_list_request_v1') {
    throw new Error('LinkedDeviceListRequestV1.kind is invalid');
  }
  return {
    kind: 'linked_device_list_request_v1',
    walletId: parseWallet(record.walletId, 'LinkedDeviceListRequestV1.walletId'),
    limit: parsePositiveSafeInteger(record.limit, 'LinkedDeviceListRequestV1.limit'),
    cursor: parseNullableCursor(record.cursor, 'LinkedDeviceListRequestV1.cursor'),
  };
}

export function buildLinkedDeviceListRequestV1(args: {
  readonly walletId: WalletId;
  readonly limit: number;
  readonly cursor: string | null;
}): LinkedDeviceListRequestV1 {
  return parseLinkedDeviceListRequestV1({
    kind: 'linked_device_list_request_v1',
    walletId: args.walletId,
    limit: args.limit,
    cursor: args.cursor,
  });
}

export function parseOwnerDeviceSummaryV1(raw: unknown): OwnerDeviceSummaryV1 {
  const record = exactRecord(raw, OWNER_DEVICE_SUMMARY_FIELDS, 'OwnerDeviceSummaryV1');
  return {
    walletId: parseWallet(record.walletId, 'OwnerDeviceSummaryV1.walletId'),
    credential: parseLinkedOwnerCredentialMetadata(
      record.credential,
      'OwnerDeviceSummaryV1.credential',
    ),
    createdAtMs: parseUnixTime(record.createdAtMs, 'OwnerDeviceSummaryV1.createdAtMs'),
    lastActivityAtMs: parseUnixTime(
      record.lastActivityAtMs,
      'OwnerDeviceSummaryV1.lastActivityAtMs',
    ),
  };
}

export function parseLinkedDeviceListResultV1(raw: unknown): LinkedDeviceListResultV1 {
  const record = exactRecord(raw, LINKED_DEVICE_LIST_RESULT_FIELDS, 'LinkedDeviceListResultV1');
  if (!Array.isArray(record.devices))
    throw new Error('LinkedDeviceListResultV1.devices is invalid');
  if (!Array.isArray(record.ownerDevices))
    throw new Error('LinkedDeviceListResultV1.ownerDevices is invalid');
  return {
    devices: record.devices.map(parseLinkedDeviceSummaryV1),
    ownerDevices: record.ownerDevices.map(parseOwnerDeviceSummaryV1),
    nextCursor: parseNullableCursor(record.nextCursor, 'LinkedDeviceListResultV1.nextCursor'),
  };
}

export function buildLinkedDeviceListResultV1(args: {
  readonly devices: readonly LinkedDeviceSummaryV1[];
  readonly ownerDevices: readonly OwnerDeviceSummaryV1[];
  readonly nextCursor: string | null;
}): LinkedDeviceListResultV1 {
  return parseLinkedDeviceListResultV1({
    devices: args.devices,
    ownerDevices: args.ownerDevices,
    nextCursor: args.nextCursor,
  });
}

export function parseLinkedDeviceRevokeRequestV1(raw: unknown): LinkedDeviceRevokeRequestV1 {
  const record = exactRecord(
    raw,
    LINKED_DEVICE_REVOKE_REQUEST_FIELDS,
    'LinkedDeviceRevokeRequestV1',
  );
  if (record.kind !== 'linked_device_revoke_request_v1') {
    throw new Error('LinkedDeviceRevokeRequestV1.kind is invalid');
  }
  return {
    kind: 'linked_device_revoke_request_v1',
    walletId: parseWallet(record.walletId, 'LinkedDeviceRevokeRequestV1.walletId'),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceRevokeRequestV1.deviceId'),
    requestedAtMs: parseUnixTime(record.requestedAtMs, 'LinkedDeviceRevokeRequestV1.requestedAtMs'),
  };
}

export function buildLinkedDeviceRevokeRequestV1(args: {
  readonly walletId: WalletId;
  readonly deviceId: LinkedDeviceId;
  readonly requestedAtMs: number;
}): LinkedDeviceRevokeRequestV1 {
  return parseLinkedDeviceRevokeRequestV1({
    kind: 'linked_device_revoke_request_v1',
    ...args,
  });
}

export function parseLinkedDeviceRevokeResultV1(raw: unknown): LinkedDeviceRevokeResultV1 {
  const initial = requireRecord(raw, 'LinkedDeviceRevokeResultV1');
  if (
    initial.kind === 'not_found' ||
    initial.kind === 'conflict' ||
    initial.kind === 'unauthorized'
  ) {
    const record = exactRecord(
      initial,
      LINKED_DEVICE_REVOKE_FAILURE_FIELDS,
      'LinkedDeviceRevokeResultV1',
    );
    switch (record.kind) {
      case 'not_found':
        return { kind: 'not_found' };
      case 'conflict':
        return { kind: 'conflict' };
      case 'unauthorized':
        return { kind: 'unauthorized' };
      default:
        throw new Error('LinkedDeviceRevokeResultV1.kind is invalid');
    }
  }
  const record = exactRecord(
    initial,
    LINKED_DEVICE_REVOKE_SUCCESS_FIELDS,
    'LinkedDeviceRevokeResultV1',
  );
  if (record.kind !== 'revoked' && record.kind !== 'replayed') {
    throw new Error('LinkedDeviceRevokeResultV1.kind is invalid');
  }
  return {
    kind: record.kind,
    enrollmentId: parseEnrollmentId(record.enrollmentId, 'LinkedDeviceRevokeResultV1.enrollmentId'),
    revocationEpoch: parseNonNegativeSafeInteger(
      record.revocationEpoch,
      'LinkedDeviceRevokeResultV1.revocationEpoch',
    ),
    aggregateReceiptDigestB64u: parseDigest(
      record.aggregateReceiptDigestB64u,
      'LinkedDeviceRevokeResultV1.aggregateReceiptDigestB64u',
    ),
  };
}

export function buildLinkedDeviceRevokeResultV1(
  value: LinkedDeviceRevokeResultV1,
): LinkedDeviceRevokeResultV1 {
  return parseLinkedDeviceRevokeResultV1(value);
}

function parseLinkedDeviceEcdsaChainTarget(raw: unknown, label: string) {
  const record = requireRecord(raw, label);
  if (record.kind === 'evm') {
    const exact = exactRecord(record, ['kind', 'namespace', 'chainId', 'networkSlug'], label);
    if (exact.namespace !== 'eip155') throw new Error(`${label}.namespace is invalid`);
    return {
      kind: 'evm' as const,
      namespace: 'eip155' as const,
      chainId: parsePositiveSafeInteger(exact.chainId, `${label}.chainId`),
      networkSlug: parseNonEmptyToken(exact.networkSlug, `${label}.networkSlug`),
    };
  }
  const exact = exactRecord(record, ['kind', 'chainId', 'networkSlug'], label);
  if (exact.kind !== 'tempo') throw new Error(`${label}.kind is invalid`);
  return {
    kind: 'tempo' as const,
    chainId: parsePositiveSafeInteger(exact.chainId, `${label}.chainId`),
    networkSlug: parseNonEmptyToken(exact.networkSlug, `${label}.networkSlug`),
  };
}

export function parseLinkedDeviceWalletSessionDeliveryV1(
  raw: unknown,
): LinkedDeviceWalletSessionDeliveryV1 {
  const initial = requireRecord(raw, 'LinkedDeviceWalletSessionDeliveryV1');
  const hasNearAccountId = Object.prototype.hasOwnProperty.call(initial, 'nearAccountId');
  const record = exactRecord(
    initial,
    hasNearAccountId
      ? LINKED_WALLET_SESSION_DELIVERY_WITH_NEAR_FIELDS
      : LINKED_WALLET_SESSION_DELIVERY_FIELDS,
    'LinkedDeviceWalletSessionDeliveryV1',
  );
  if (record.kind !== 'linked_device_wallet_session_delivery_v1') {
    throw new Error('LinkedDeviceWalletSessionDeliveryV1.kind is invalid');
  }
  const issuedAtMs = parseUnixTime(
    record.issuedAtMs,
    'LinkedDeviceWalletSessionDeliveryV1.issuedAtMs',
  );
  const expiresAtMs = parseUnixTime(
    record.expiresAtMs,
    'LinkedDeviceWalletSessionDeliveryV1.expiresAtMs',
  );
  assertExpiryAfterIssued(issuedAtMs, expiresAtMs, 'LinkedDeviceWalletSessionDeliveryV1');
  const identity = {
    tenantId: parseId(
      parseTenantId,
      record.tenantId,
      'LinkedDeviceWalletSessionDeliveryV1.tenantId',
    ),
    walletId: parseWallet(record.walletId, 'LinkedDeviceWalletSessionDeliveryV1.walletId'),
    enrollmentId: parseEnrollmentId(
      record.enrollmentId,
      'LinkedDeviceWalletSessionDeliveryV1.enrollmentId',
    ),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceWalletSessionDeliveryV1.deviceId'),
    authorizationId: parseId(
      parseLinkedDeviceWalletSessionAuthorizationId,
      record.authorizationId,
      'LinkedDeviceWalletSessionDeliveryV1.authorizationId',
    ),
    walletSessionId: parseId(
      parseWalletSessionId,
      record.walletSessionId,
      'LinkedDeviceWalletSessionDeliveryV1.walletSessionId',
    ),
    quotaId: parseId(
      parseMpcWalletSigningQuotaId,
      record.quotaId,
      'LinkedDeviceWalletSessionDeliveryV1.quotaId',
    ),
    keyManifestDigestB64u: parseDigest(
      record.keyManifestDigestB64u,
      'LinkedDeviceWalletSessionDeliveryV1.keyManifestDigestB64u',
    ),
    permission: parsePermission(
      record.permission,
      'LinkedDeviceWalletSessionDeliveryV1.permission',
    ),
    revocationEpoch: parseNonNegativeSafeInteger(
      record.revocationEpoch,
      'LinkedDeviceWalletSessionDeliveryV1.revocationEpoch',
    ),
    remainingUses: parseNonNegativeSafeInteger(
      record.remainingUses,
      'LinkedDeviceWalletSessionDeliveryV1.remainingUses',
    ),
    issuedAtMs,
    expiresAtMs,
  };
  if (!Array.isArray(record.orderedTokens)) {
    throw new Error('LinkedDeviceWalletSessionDeliveryV1.orderedTokens must be an array');
  }
  const seenWalletKeys = new Set<string>();
  const orderedTokens = record.orderedTokens.map((token, index) => {
    const parsed = parseLinkedDeviceWalletSessionTokenV1(token, identity, index);
    if (seenWalletKeys.has(parsed.walletKeyId)) {
      throw new Error('LinkedDeviceWalletSessionDeliveryV1 contains a duplicate wallet key');
    }
    seenWalletKeys.add(parsed.walletKeyId);
    return parsed;
  });
  const exactTokens = nonEmptyTuple(
    orderedTokens,
    'LinkedDeviceWalletSessionDeliveryV1.orderedTokens',
  );
  const ed25519Tokens = exactTokens.filter((token) => token.keyFamily === 'ed25519');
  const ecdsaTokens = exactTokens.filter((token) => token.keyFamily === 'ecdsa_secp256k1');
  if (ed25519Tokens.length > 1 || ecdsaTokens.length > 1) {
    throw new Error('LinkedDeviceWalletSessionDeliveryV1 contains duplicate key families');
  }
  const base = {
    kind: 'linked_device_wallet_session_delivery_v1' as const,
    ...identity,
  };
  const ed25519 = ed25519Tokens[0];
  const ecdsa = ecdsaTokens[0];
  if (!ed25519) {
    if (hasNearAccountId || !ecdsa || exactTokens.length !== 1) {
      throw new Error('LinkedDeviceWalletSessionDeliveryV1 NEAR identity is invalid');
    }
    return { ...base, orderedTokens: [ecdsa] };
  }
  const nearAccountId = parseNearAccountId(record.nearAccountId);
  if (!nearAccountId.ok) {
    throw new Error('LinkedDeviceWalletSessionDeliveryV1.nearAccountId is invalid');
  }
  if (!ecdsa) return { ...base, nearAccountId: nearAccountId.value, orderedTokens: [ed25519] };
  return exactTokens[0]?.keyFamily === 'ed25519'
    ? { ...base, nearAccountId: nearAccountId.value, orderedTokens: [ed25519, ecdsa] }
    : { ...base, nearAccountId: nearAccountId.value, orderedTokens: [ecdsa, ed25519] };
}

export function buildLinkedDeviceWalletSessionDeliveryV1(
  value: unknown,
): LinkedDeviceWalletSessionDeliveryV1 {
  return parseLinkedDeviceWalletSessionDeliveryV1(value);
}

function parseLinkedDeviceWalletSessionTokenV1(
  raw: unknown,
  expected: {
    readonly tenantId: LinkedDeviceWalletSessionDeliveryV1['tenantId'];
    readonly walletId: LinkedDeviceWalletSessionDeliveryV1['walletId'];
    readonly enrollmentId: LinkedDeviceWalletSessionDeliveryV1['enrollmentId'];
    readonly deviceId: LinkedDeviceWalletSessionDeliveryV1['deviceId'];
    readonly authorizationId: LinkedDeviceWalletSessionDeliveryV1['authorizationId'];
    readonly walletSessionId: LinkedDeviceWalletSessionDeliveryV1['walletSessionId'];
    readonly quotaId: LinkedDeviceWalletSessionDeliveryV1['quotaId'];
    readonly keyManifestDigestB64u: LinkedDeviceWalletSessionDeliveryV1['keyManifestDigestB64u'];
    readonly permission: LinkedDeviceWalletSessionDeliveryV1['permission'];
    readonly issuedAtMs: number;
    readonly expiresAtMs: number;
  },
  index: number,
): LinkedDeviceWalletSessionTokenV1 {
  const label = `LinkedDeviceWalletSessionDeliveryV1.orderedTokens[${index}]`;
  const record = exactRecord(raw, LINKED_WALLET_SESSION_TOKEN_FIELDS, label);
  if (record.kind !== 'linked_device_wallet_session_token_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const walletKeyId = parseWalletKey(record.walletKeyId, `${label}.walletKeyId`);
  if (record.keyFamily !== 'ed25519' && record.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error(`${label}.keyFamily is invalid`);
  }
  const keyFamily = record.keyFamily;
  const revocationEpoch = parseNonNegativeSafeInteger(
    record.revocationEpoch,
    `${label}.revocationEpoch`,
  );
  const walletSessionJwt = parseNonEmptyToken(record.walletSessionJwt, `${label}.walletSessionJwt`);
  const jwtSegments = walletSessionJwt.split('.');
  if (
    jwtSegments.length !== 3 ||
    jwtSegments.some((segment) => !segment || !/^[A-Za-z0-9_-]+$/.test(segment))
  ) {
    throw new Error(`${label}.walletSessionJwt is not a compact JWT`);
  }
  const decodedClaims = decodeJwtPayloadRecord(walletSessionJwt);
  if (!decodedClaims) throw new Error(`${label}.walletSessionJwt payload is invalid`);
  const claims = linkedWalletSessionJwtClaims(decodedClaims, `${label}.walletSessionJwt payload`);
  const expectedKind =
    keyFamily === 'ed25519'
      ? ROUTER_AB_ED25519_WALLET_SESSION_JWT_KIND
      : ROUTER_AB_ECDSA_DERIVATION_WALLET_SESSION_JWT_KIND;
  if (
    claims.kind !== expectedKind ||
    claims.authorizationKind !== 'linked_device_wallet_session' ||
    claims.sub !== `linked-device:${expected.deviceId}` ||
    claims.tenantId !== expected.tenantId ||
    claims.walletId !== expected.walletId ||
    claims.enrollmentId !== expected.enrollmentId ||
    claims.deviceId !== expected.deviceId ||
    claims.walletKeyId !== walletKeyId ||
    claims.authorizationId !== expected.authorizationId ||
    claims.walletSessionId !== expected.walletSessionId ||
    claims.quotaId !== expected.quotaId ||
    claims.keyManifestDigestB64u !== expected.keyManifestDigestB64u ||
    claims.revocationEpoch !== revocationEpoch ||
    claims.issuedAtMs !== expected.issuedAtMs ||
    claims.expiresAtMs !== expected.expiresAtMs ||
    claims.iat !== Math.floor(expected.issuedAtMs / 1_000) ||
    claims.exp !== Math.floor(expected.expiresAtMs / 1_000)
  ) {
    throw new Error(`${label}.walletSessionJwt identity does not match its delivery`);
  }
  const permission = parsePermission(claims.permission, `${label}.walletSessionJwt.permission`);
  if (
    permission.kind !== expected.permission.kind ||
    permission.administrationScope !== expected.permission.administrationScope ||
    permission.localUserPresence !== expected.permission.localUserPresence
  ) {
    throw new Error(`${label}.walletSessionJwt permission does not match its delivery`);
  }
  return {
    kind: 'linked_device_wallet_session_token_v1',
    walletKeyId,
    keyFamily,
    walletSessionJwt,
    revocationEpoch,
  };
}

function linkedWalletSessionJwtClaims(raw: unknown, label: string): UnknownRecord {
  const record = requireRecord(raw, label);
  rejectUnknownFields(
    record,
    [...LINKED_WALLET_SESSION_JWT_FIELDS, ...LINKED_WALLET_SESSION_JWT_OPTIONAL_FIELDS],
    label,
  );
  for (const field of LINKED_WALLET_SESSION_JWT_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(record, field) || record[field] === undefined) {
      throw new Error(`${label}.${field} is required`);
    }
  }
  if (record.iss !== undefined) parseNonEmptyToken(record.iss, `${label}.iss`);
  if (record.aud !== undefined) validateJwtAudience(record.aud, `${label}.aud`);
  return record;
}

function validateJwtAudience(raw: unknown, label: string): void {
  if (typeof raw === 'string') {
    parseNonEmptyToken(raw, label);
    return;
  }
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new Error(`${label} must be a non-empty string or string array`);
  }
  for (let index = 0; index < raw.length; index += 1) {
    parseNonEmptyToken(raw[index], `${label}[${index}]`);
  }
}

function parseQrPayloadRecord(record: UnknownRecord): QrLinkedDeviceSessionPayloadV5 {
  if (record.version !== 'v5') throw new Error('QrLinkedDeviceSessionPayloadV5.version is invalid');
  if (record.purpose !== 'linked_device_lane_creation') {
    throw new Error('QrLinkedDeviceSessionPayloadV5.purpose is invalid');
  }
  const issuedAtMs = parseUnixTime(record.issuedAtMs, 'QrLinkedDeviceSessionPayloadV5.issuedAtMs');
  const expiresAtMs = parseUnixTime(
    record.expiresAtMs,
    'QrLinkedDeviceSessionPayloadV5.expiresAtMs',
  );
  assertExpiryAfterIssued(issuedAtMs, expiresAtMs, 'QrLinkedDeviceSessionPayloadV5');
  return {
    version: 'v5',
    purpose: 'linked_device_lane_creation',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'QrLinkedDeviceSessionPayloadV5.linkSessionId',
    ),
    linkPublicKeyB64u: parsePublicKey(
      record.linkPublicKeyB64u,
      'QrLinkedDeviceSessionPayloadV5.linkPublicKeyB64u',
    ),
    devicePublicKeyB64u: parsePublicKey(
      record.devicePublicKeyB64u,
      'QrLinkedDeviceSessionPayloadV5.devicePublicKeyB64u',
    ),
    requestedPermission: parsePermission(record.requestedPermission),
    targetFactor: parseTargetFactor(
      record.targetFactor,
      'QrLinkedDeviceSessionPayloadV5.targetFactor',
    ),
    issuedAtMs,
    expiresAtMs,
  };
}

export function parseQrLinkedDeviceSessionPayloadV5(raw: unknown): QrLinkedDeviceSessionPayloadV5 {
  return parseQrPayloadRecord(exactRecord(raw, QR_FIELDS, 'QrLinkedDeviceSessionPayloadV5'));
}

export function serializeQrLinkedDeviceSessionPayloadV5(
  payload: QrLinkedDeviceSessionPayloadV5,
): string {
  const parsed = parseQrLinkedDeviceSessionPayloadV5(payload);
  return JSON.stringify({
    v: 5,
    s: parsed.linkSessionId,
    l: parsed.linkPublicKeyB64u,
    d: parsed.devicePublicKeyB64u,
    f: parsed.targetFactor.kind === 'passkey_prf' ? 'p' : 'e',
    i: parsed.issuedAtMs,
    e: parsed.expiresAtMs,
  });
}

export function parseQrLinkedDeviceSessionTextV5(raw: string): QrLinkedDeviceSessionPayloadV5 {
  let decoded: unknown;
  try {
    decoded = JSON.parse(raw);
  } catch {
    throw new Error('Linked-device QR payload is not valid JSON');
  }
  const compact = exactRecord(decoded, COMPACT_QR_FIELDS, 'LinkedDeviceQrV5');
  if (compact.v !== 5) throw new Error('LinkedDeviceQrV5.v is invalid');
  if (compact.f !== 'p' && compact.f !== 'e') {
    throw new Error('LinkedDeviceQrV5.f is invalid');
  }
  return parseQrLinkedDeviceSessionPayloadV5({
    version: 'v5',
    purpose: 'linked_device_lane_creation',
    linkSessionId: compact.s,
    linkPublicKeyB64u: compact.l,
    devicePublicKeyB64u: compact.d,
    requestedPermission: buildQrLinkedDevicePermissionRequest(),
    targetFactor: { kind: compact.f === 'p' ? 'passkey_prf' : 'email_otp' },
    issuedAtMs: compact.i,
    expiresAtMs: compact.e,
  });
}

export function parseLinkedDeviceOwnerAuthorizationRequestV1(
  raw: unknown,
): LinkedDeviceOwnerAuthorizationRequestV1 {
  const record = exactRecord(
    raw,
    OWNER_AUTHORIZATION_REQUEST_FIELDS,
    'LinkedDeviceOwnerAuthorizationRequestV1',
  );
  const requestedAtMs = parseUnixTime(
    record.requestedAtMs,
    'LinkedDeviceOwnerAuthorizationRequestV1.requestedAtMs',
  );
  const payload = parseQrLinkedDeviceSessionPayloadV5(record.payload);
  if (!Array.isArray(record.orderedOwnerSourceLaneHints)) {
    throw new Error(
      'LinkedDeviceOwnerAuthorizationRequestV1.orderedOwnerSourceLaneHints must be an array',
    );
  }
  if (record.orderedOwnerSourceLaneHints.length === 0) {
    throw new Error(
      'LinkedDeviceOwnerAuthorizationRequestV1.orderedOwnerSourceLaneHints must not be empty',
    );
  }
  const hints = record.orderedOwnerSourceLaneHints.map((value, index) =>
    parseLinkedDeviceOwnerSourceLaneV1(
      value,
      `LinkedDeviceOwnerAuthorizationRequestV1.orderedOwnerSourceLaneHints[${index}]`,
    ),
  );
  const walletId = hints[0]?.walletKey.walletId;
  if (!walletId) throw new Error('owner source lane hint wallet identity is missing');
  if (hints.some((hint) => hint.walletKey.walletId !== walletId)) {
    throw new Error('owner source lane hints must use one wallet identity');
  }
  return {
    payload,
    requestedAtMs,
    orderedOwnerSourceLaneHints: [hints[0]!, ...hints.slice(1)],
  };
}

export function parseLinkedDeviceOwnerSourceLaneV1(
  raw: unknown,
  label = 'LinkedDeviceOwnerSourceLaneV1',
): LinkedDeviceOwnerSourceLaneV1 {
  const record = requireRecord(raw, label);
  const keyFamily = record.keyFamily;
  const fields =
    keyFamily === 'ecdsa_secp256k1'
      ? [...OWNER_SOURCE_LANE_COMMON_FIELDS, 'ecdsaSourceManifest']
      : OWNER_SOURCE_LANE_COMMON_FIELDS;
  const exact = exactRecord(record, fields, label);
  if (exact.kind !== 'linked_device_owner_source_lane_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  const walletKey = parseWalletKeyRecord(exact.walletKey);
  const lane = parseSigningLaneRecord(exact.lane);
  const materialActivation = parseMpcMaterialActivationRef(exact.materialActivation);
  if (!materialActivation.ok) throw new Error(`${label}.${materialActivation.error.message}`);
  if (
    lane.walletId !== walletKey.walletId ||
    lane.walletKeyId !== walletKey.walletKeyId ||
    (lane.laneKind !== 'owner_passkey' && lane.laneKind !== 'owner_email_otp') ||
    lane.lifecycle.state !== 'active'
  ) {
    throw new Error(`${label} owner lane identity is inconsistent`);
  }
  const verifiedActivationReceiptDigestB64u = parseDigestB64u(
    exact.verifiedActivationReceiptDigestB64u,
  );
  if (keyFamily === 'ed25519') {
    if (walletKey.keyFamily !== 'ed25519') throw new Error(`${label}.keyFamily is inconsistent`);
    return {
      kind: 'linked_device_owner_source_lane_v1',
      keyFamily,
      walletKey,
      lane,
      materialActivation: materialActivation.value,
      verifiedActivationReceiptDigestB64u,
    };
  }
  if (keyFamily !== 'ecdsa_secp256k1' || walletKey.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error(`${label}.keyFamily is invalid`);
  }
  const manifest = exactRecord(
    exact.ecdsaSourceManifest,
    ['manifestId', 'manifestRevision'],
    `${label}.ecdsaSourceManifest`,
  );
  return {
    kind: 'linked_device_owner_source_lane_v1',
    keyFamily,
    walletKey,
    lane,
    materialActivation: materialActivation.value,
    verifiedActivationReceiptDigestB64u,
    ecdsaSourceManifest: {
      manifestId: parseEcdsaCapabilityManifestId(manifest.manifestId),
      manifestRevision: parseEcdsaCapabilityManifestRevision(manifest.manifestRevision),
    },
  };
}

function parseEmailOtpChallengeState(raw: unknown): Extract<
  LinkedDeviceSessionState,
  {
    readonly state: 'awaiting_target_factor';
    readonly targetFactor: { readonly kind: 'email_otp' };
  }
>['emailOtpChallenge'] {
  const initial = requireRecord(raw, 'awaiting_target_factor.emailOtpChallenge');
  if (initial.state === 'available') {
    const record = exactRecord(
      initial,
      ['state', 'maskedEmailHint'],
      'awaiting_target_factor.emailOtpChallenge.available',
    );
    return {
      state: 'available',
      maskedEmailHint: parseNonEmptyToken(
        record.maskedEmailHint,
        'emailOtpChallenge.maskedEmailHint',
      ),
    };
  }
  if (initial.state === 'sent') {
    const record = exactRecord(
      initial,
      [
        'state',
        'challengeId',
        'workerEphemeralPublicKey65B64u',
        'maskedEmailHint',
        'expiresAtMs',
        'resendAvailableAtMs',
      ],
      'awaiting_target_factor.emailOtpChallenge.sent',
    );
    return {
      state: 'sent',
      challengeId: parseNonEmptyToken(record.challengeId, 'emailOtpChallenge.challengeId'),
      workerEphemeralPublicKey65B64u: parseCanonicalFixedBase64UrlBytes(
        record.workerEphemeralPublicKey65B64u,
        65,
        'emailOtpChallenge.workerEphemeralPublicKey65B64u',
      ),
      maskedEmailHint: parseNonEmptyToken(
        record.maskedEmailHint,
        'emailOtpChallenge.maskedEmailHint',
      ),
      expiresAtMs: parseUnixTime(record.expiresAtMs, 'emailOtpChallenge.expiresAtMs'),
      resendAvailableAtMs: parseUnixTime(
        record.resendAvailableAtMs,
        'emailOtpChallenge.resendAvailableAtMs',
      ),
    };
  }
  throw new Error('awaiting_target_factor.emailOtpChallenge.state is unsupported');
}

function parseAwaitingTargetFactorState(
  record: UnknownRecord,
  linkSessionId: LinkDeviceSessionId,
): Extract<LinkedDeviceSessionState, { readonly state: 'awaiting_target_factor' }> {
  const targetFactor = parseTargetFactor(
    record.targetFactor,
    'awaiting_target_factor.targetFactor',
  );
  const identity = {
    state: 'awaiting_target_factor' as const,
    linkSessionId,
    walletId: parseWallet(record.walletId, 'awaiting_target_factor.walletId'),
    enrollmentId: parseEnrollmentId(record.enrollmentId, 'awaiting_target_factor.enrollmentId'),
  };
  switch (targetFactor.kind) {
    case 'passkey_prf':
      return {
        ...identity,
        targetFactor,
        credentialDeadlineMs: parseUnixTime(
          record.credentialDeadlineMs,
          'awaiting_target_factor.credentialDeadlineMs',
        ),
      };
    case 'email_otp':
      return {
        ...identity,
        targetFactor,
        emailOtpChallenge: parseEmailOtpChallengeState(record.emailOtpChallenge),
      };
  }
  targetFactor satisfies never;
  throw new Error('awaiting_target_factor target factor is unsupported');
}

function parseStateRecord(record: UnknownRecord): LinkedDeviceSessionState {
  if (typeof record.state !== 'string' || !(record.state in SESSION_STATE_FIELDS)) {
    throw new Error('LinkedDeviceSessionState.state is unsupported');
  }
  const state = record.state as keyof typeof SESSION_STATE_FIELDS;
  const stateFields =
    state === 'awaiting_target_factor'
      ? parseTargetFactor(record.targetFactor, 'awaiting_target_factor.targetFactor').kind ===
        'passkey_prf'
        ? AWAITING_PASSKEY_FACTOR_STATE_FIELDS
        : AWAITING_EMAIL_OTP_FACTOR_STATE_FIELDS
      : SESSION_STATE_FIELDS[state];
  const exact = exactRecord(record, stateFields, `LinkedDeviceSessionState.${state}`);
  const linkSessionId = parseSessionId(exact.linkSessionId, `${state}.linkSessionId`);
  switch (state) {
    case 'displaying_qr':
      return {
        state,
        linkSessionId,
        expiresAtMs: parseUnixTime(exact.expiresAtMs, `${state}.expiresAtMs`),
      };
    case 'claimed_by_owner':
      return {
        state,
        linkSessionId,
        walletId: parseWallet(exact.walletId, `${state}.walletId`),
        enrollmentId: parseEnrollmentId(exact.enrollmentId, `${state}.enrollmentId`),
        claimExpiresAtMs: parseUnixTime(exact.claimExpiresAtMs, `${state}.claimExpiresAtMs`),
      };
    case 'awaiting_target_factor':
      return parseAwaitingTargetFactorState(exact, linkSessionId);
    case 'provisioning':
      return {
        state,
        linkSessionId,
        walletId: parseWallet(exact.walletId, `${state}.walletId`),
        enrollmentId: parseEnrollmentId(exact.enrollmentId, `${state}.enrollmentId`),
        keyManifestDigestB64u: parseDigest(
          exact.keyManifestDigestB64u,
          `${state}.keyManifestDigestB64u`,
        ),
      };
    case 'active':
      return {
        state,
        linkSessionId,
        walletId: parseWallet(exact.walletId, `${state}.walletId`),
        enrollmentId: parseEnrollmentId(exact.enrollmentId, `${state}.enrollmentId`),
        activatedAtMs: parseUnixTime(exact.activatedAtMs, `${state}.activatedAtMs`),
      };
    case 'expired_unclaimed':
      return {
        state,
        linkSessionId,
        expiredAtMs: parseUnixTime(exact.expiredAtMs, `${state}.expiredAtMs`),
      };
    case 'expired_claimed':
      return {
        state,
        linkSessionId,
        walletId: parseWallet(exact.walletId, `${state}.walletId`),
        enrollmentId: parseEnrollmentId(exact.enrollmentId, `${state}.enrollmentId`),
        expiredAtMs: parseUnixTime(exact.expiredAtMs, `${state}.expiredAtMs`),
      };
    case 'cancelled_unclaimed':
      return {
        state,
        linkSessionId,
        cancelledAtMs: parseUnixTime(exact.cancelledAtMs, `${state}.cancelledAtMs`),
      };
    case 'cancelled_claimed_precommit':
      return {
        state,
        linkSessionId,
        walletId: parseWallet(exact.walletId, `${state}.walletId`),
        enrollmentId: parseEnrollmentId(exact.enrollmentId, `${state}.enrollmentId`),
        cancelledAtMs: parseUnixTime(exact.cancelledAtMs, `${state}.cancelledAtMs`),
      };
    case 'committed_completion_required':
      return {
        state,
        linkSessionId,
        walletId: parseWallet(exact.walletId, `${state}.walletId`),
        enrollmentId: parseEnrollmentId(exact.enrollmentId, `${state}.enrollmentId`),
        keyManifestDigestB64u: parseDigest(
          exact.keyManifestDigestB64u,
          `${state}.keyManifestDigestB64u`,
        ),
        transcriptSetDigestB64u: parseDigest(
          exact.transcriptSetDigestB64u,
          `${state}.transcriptSetDigestB64u`,
        ),
      };
    default:
      return assertNeverLinkedDeviceSessionState(state);
  }
}

export function parseLinkedDeviceSessionState(raw: unknown): LinkedDeviceSessionState {
  return parseStateRecord(requireRecord(raw, 'LinkedDeviceSessionState'));
}

function isUnclaimedSessionState(
  state: LinkedDeviceSessionState,
): state is Extract<
  LinkedDeviceSessionState,
  { readonly state: LinkedDeviceSessionUnclaimedState['state'] }
> {
  return (
    state.state === 'displaying_qr' ||
    state.state === 'expired_unclaimed' ||
    state.state === 'cancelled_unclaimed'
  );
}

function isPendingApprovalState(state: LinkedDeviceSessionState): state is Extract<
  LinkedDeviceSessionState,
  {
    readonly state: 'awaiting_target_factor' | 'provisioning' | 'committed_completion_required';
  }
> {
  return (
    state.state === 'awaiting_target_factor' ||
    state.state === 'provisioning' ||
    state.state === 'committed_completion_required'
  );
}

export function parseLinkedDeviceSessionProjectionV1(
  raw: unknown,
): LinkedDeviceSessionProjectionV1 {
  const initial = requireRecord(raw, 'LinkedDeviceSessionProjectionV1');
  const state = parseLinkedDeviceSessionState(initial.state);
  const record = exactRecord(
    initial,
    isUnclaimedSessionState(state)
      ? SESSION_PROJECTION_BASE_FIELDS
      : SESSION_PROJECTION_CLAIMED_FIELDS,
    'LinkedDeviceSessionProjectionV1',
  );
  if (record.kind !== 'linked_device_session_projection_v1') {
    throw new Error('LinkedDeviceSessionProjectionV1.kind is invalid');
  }
  const base = {
    kind: 'linked_device_session_projection_v1' as const,
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceSessionProjectionV1.linkSessionId',
    ),
    qrPayload: parseQrLinkedDeviceSessionPayloadV5(record.qrPayload),
    revision: parseNonNegativeSafeInteger(
      record.revision,
      'LinkedDeviceSessionProjectionV1.revision',
    ),
    createdAtMs: parseUnixTime(record.createdAtMs, 'LinkedDeviceSessionProjectionV1.createdAtMs'),
    updatedAtMs: parseUnixTime(record.updatedAtMs, 'LinkedDeviceSessionProjectionV1.updatedAtMs'),
  } as const;
  if (isUnclaimedSessionState(state)) return { ...base, state };
  return {
    ...base,
    state,
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceSessionProjectionV1.deviceId'),
  };
}

export function parseLinkedDeviceApprovalResultV1(raw: unknown): LinkedDeviceApprovalResultV1 {
  const initial = requireRecord(raw, 'LinkedDeviceApprovalResultV1');
  if (initial.outcome === 'pending') {
    const record = exactRecord(initial, APPROVAL_PENDING_FIELDS, 'LinkedDeviceApprovalResultV1');
    if (record.outcome !== 'pending')
      throw new Error('LinkedDeviceApprovalResultV1.outcome is invalid');
    const state = parseLinkedDeviceSessionState(record.state);
    if (!isPendingApprovalState(state)) {
      throw new Error('LinkedDeviceApprovalResultV1.pending state is invalid');
    }
    return { outcome: 'pending', state };
  }
  if (initial.outcome === 'active') {
    const record = exactRecord(initial, APPROVAL_ACTIVE_FIELDS, 'LinkedDeviceApprovalResultV1');
    if (record.outcome !== 'active')
      throw new Error('LinkedDeviceApprovalResultV1.outcome is invalid');
    const state = parseLinkedDeviceSessionState(record.state);
    if (state.state !== 'active')
      throw new Error('LinkedDeviceApprovalResultV1.active state is invalid');
    const receipt = parseLinkedDeviceEnrollmentReceiptV1(record.receipt);
    const manifestDigestB64u = parseDigest(
      record.manifestDigestB64u,
      'LinkedDeviceApprovalResultV1.manifestDigestB64u',
    );
    if (manifestDigestB64u !== receipt.manifestDigestB64u) {
      throw new Error('LinkedDeviceApprovalResultV1 manifest digest does not match receipt');
    }
    return { outcome: 'active', state, manifestDigestB64u, receipt };
  }
  if (initial.outcome !== 'replayed') {
    throw new Error('LinkedDeviceApprovalResultV1.outcome is invalid');
  }
  const outer = exactRecord(initial, APPROVAL_REPLAY_FIELDS, 'LinkedDeviceApprovalResultV1');
  const replay = requireRecord(outer.replay, 'LinkedDeviceApprovalResultV1.replay');
  if (replay.state === 'pending') {
    const record = exactRecord(
      replay,
      APPROVAL_REPLAY_PENDING_FIELDS,
      'LinkedDeviceApprovalResultV1.replay',
    );
    const state = parseLinkedDeviceSessionState(record.session);
    if (!isPendingApprovalState(state)) {
      throw new Error('LinkedDeviceApprovalResultV1.replay pending state is invalid');
    }
    return { outcome: 'replayed', replay: { state: 'pending', session: state } };
  }
  if (replay.state !== 'active')
    throw new Error('LinkedDeviceApprovalResultV1.replay.state is invalid');
  const record = exactRecord(
    replay,
    APPROVAL_REPLAY_ACTIVE_FIELDS,
    'LinkedDeviceApprovalResultV1.replay',
  );
  const state = parseLinkedDeviceSessionState(record.session);
  if (state.state !== 'active') {
    throw new Error('LinkedDeviceApprovalResultV1.replay active state is invalid');
  }
  const receipt = parseLinkedDeviceEnrollmentReceiptV1(record.receipt);
  const manifestDigestB64u = parseDigest(
    record.manifestDigestB64u,
    'LinkedDeviceApprovalResultV1.replay.manifestDigestB64u',
  );
  if (manifestDigestB64u !== receipt.manifestDigestB64u) {
    throw new Error('LinkedDeviceApprovalResultV1.replay manifest digest does not match receipt');
  }
  return {
    outcome: 'replayed',
    replay: { state: 'active', session: state, manifestDigestB64u, receipt },
  };
}

export function parseLinkedDeviceSessionClaimRequestV1(
  raw: unknown,
): LinkedDeviceSessionClaimRequestV1 {
  const record = exactRecord(raw, CLAIM_REQUEST_FIELDS, 'LinkedDeviceSessionClaimRequestV1');
  if (record.kind !== 'linked_device_session_claim_request_v1') {
    throw new Error('LinkedDeviceSessionClaimRequestV1.kind is invalid');
  }
  return {
    kind: 'linked_device_session_claim_request_v1',
    payload: parseQrLinkedDeviceSessionPayloadV5(record.payload),
  };
}

export function parseLinkedDeviceSessionClaimV1(raw: unknown): LinkedDeviceSessionClaimV1 {
  const record = exactRecord(raw, CLAIM_FIELDS, 'LinkedDeviceSessionClaimV1');
  if (record.kind !== 'linked_device_session_claim_v1') {
    throw new Error('LinkedDeviceSessionClaimV1.kind is invalid');
  }
  const claimedAtMs = parseUnixTime(record.claimedAtMs, 'LinkedDeviceSessionClaimV1.claimedAtMs');
  const claimExpiresAtMs = parseUnixTime(
    record.claimExpiresAtMs,
    'LinkedDeviceSessionClaimV1.claimExpiresAtMs',
  );
  assertExpiryAfterIssued(claimedAtMs, claimExpiresAtMs, 'LinkedDeviceSessionClaimV1');
  return {
    kind: 'linked_device_session_claim_v1',
    linkSessionId: parseSessionId(record.linkSessionId, 'LinkedDeviceSessionClaimV1.linkSessionId'),
    walletId: parseWallet(record.walletId, 'LinkedDeviceSessionClaimV1.walletId'),
    enrollmentId: parseEnrollmentId(record.enrollmentId, 'LinkedDeviceSessionClaimV1.enrollmentId'),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceSessionClaimV1.deviceId'),
    devicePublicKeyB64u: parsePublicKey(
      record.devicePublicKeyB64u,
      'LinkedDeviceSessionClaimV1.devicePublicKeyB64u',
    ),
    targetFactor: parseTargetFactor(record.targetFactor, 'LinkedDeviceSessionClaimV1.targetFactor'),
    claimedAtMs,
    claimExpiresAtMs,
  };
}

export function parseLinkedDeviceOwnerAuthorizationSourceV1(
  raw: unknown,
  label = 'ownerAuthorization',
): LinkedDeviceOwnerAuthorizationSourceV1 {
  const record = requireRecord(raw, label);
  if (record.kind === 'wallet_session') {
    const exact = exactRecord(record, OWNER_AUTH_WALLET_SESSION_FIELDS, label);
    return {
      kind: 'wallet_session',
      walletSessionId: parseWalletSession(exact.walletSessionId, `${label}.walletSessionId`),
      authorizationId: parseWalletAuthorization(exact.authorizationId, `${label}.authorizationId`),
    };
  }
  if (record.kind === 'step_up') {
    const exact = exactRecord(record, OWNER_AUTH_STEP_UP_FIELDS, label);
    return {
      kind: 'step_up',
      evidenceSetId: parseEvidenceSet(exact.evidenceSetId, `${label}.evidenceSetId`),
    };
  }
  throw new Error(`${label}.kind is unsupported`);
}

export function parseLinkedDeviceEnrollmentKeyBindingV1(
  raw: unknown,
  label: string,
): LinkedDeviceEnrollmentKeyBindingV1 {
  const baseRecord = requireRecord(raw, label);
  const sourceLaneKind = parseSigningLaneKind(baseRecord.sourceLaneKind, `${label}.sourceLaneKind`);
  const sourceKind = baseRecord.sourceKind;
  if (sourceKind !== 'owner_registration' && sourceKind !== 'provisioned_lane') {
    throw new Error(`${label}.sourceKind must identify a supported source branch`);
  }
  const record = exactRecord(
    baseRecord,
    sourceKind === 'owner_registration' ? OWNER_KEY_BINDING_FIELDS : PROVISIONED_KEY_BINDING_FIELDS,
    label,
  );
  if (sourceKind === 'owner_registration') {
    if (sourceLaneKind !== 'owner_passkey' && sourceLaneKind !== 'owner_email_otp') {
      throw new Error(`${label}.sourceLaneKind must be an owner lane for owner_registration`);
    }
    return {
      walletKeyId: parseWalletKey(record.walletKeyId, `${label}.walletKeyId`),
      keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
      sourceLaneId: parseLaneId(record.sourceLaneId, `${label}.sourceLaneId`),
      sourceLaneKind,
      sourceKind,
      sourceLaneShareEpoch: parseLaneEpoch(
        record.sourceLaneShareEpoch,
        `${label}.sourceLaneShareEpoch`,
      ),
      sourceRevocationEpoch: parseNonNegativeSafeInteger(
        record.sourceRevocationEpoch,
        `${label}.sourceRevocationEpoch`,
      ),
      ownerParticipantContinuity: parseOwnerLaneParticipantContinuityV1(
        record.ownerParticipantContinuity,
        `${label}.ownerParticipantContinuity`,
      ),
      targetLaneId: parseLaneId(record.targetLaneId, `${label}.targetLaneId`),
      targetLaneShareEpoch: parseLaneEpoch(
        record.targetLaneShareEpoch,
        `${label}.targetLaneShareEpoch`,
      ),
    };
  }
  if (sourceLaneKind === 'owner_passkey' || sourceLaneKind === 'owner_email_otp') {
    throw new Error(`${label}.sourceLaneKind must be provisioned for provisioned_lane`);
  }
  return {
    walletKeyId: parseWalletKey(record.walletKeyId, `${label}.walletKeyId`),
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    sourceLaneId: parseLaneId(record.sourceLaneId, `${label}.sourceLaneId`),
    sourceLaneKind,
    sourceKind,
    sourceLaneShareEpoch: parseLaneEpoch(
      record.sourceLaneShareEpoch,
      `${label}.sourceLaneShareEpoch`,
    ),
    sourceRevocationEpoch: parseNonNegativeSafeInteger(
      record.sourceRevocationEpoch,
      `${label}.sourceRevocationEpoch`,
    ),
    sourceHolderParticipantId: parseHolderParticipant(
      record.sourceHolderParticipantId,
      `${label}.sourceHolderParticipantId`,
    ),
    sourceSigningWorkerParticipantId: parseSigningWorkerParticipant(
      record.sourceSigningWorkerParticipantId,
      `${label}.sourceSigningWorkerParticipantId`,
    ),
    targetLaneId: parseLaneId(record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseLaneEpoch(
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
  };
}

function parseKeyBindings(
  raw: unknown,
  label: string,
): readonly [LinkedDeviceEnrollmentKeyBindingV1, ...LinkedDeviceEnrollmentKeyBindingV1[]] {
  if (!Array.isArray(raw)) throw new Error(`${label} must be an array`);
  const values = raw.map((entry, index) =>
    parseLinkedDeviceEnrollmentKeyBindingV1(entry, `${label}[${index}]`),
  );
  const walletKeys = new Set<string>();
  const targetLanes = new Set<string>();
  for (const value of values) {
    if (walletKeys.has(value.walletKeyId))
      throw new Error(`${label} contains duplicate walletKeyId`);
    if (targetLanes.has(value.targetLaneId))
      throw new Error(`${label} contains duplicate targetLaneId`);
    walletKeys.add(value.walletKeyId);
    targetLanes.add(value.targetLaneId);
  }
  return nonEmptyTuple(values, label);
}

export function parseLinkedDeviceProtocolVersionV1(
  raw: unknown,
  label: string,
): LinkedDeviceProtocolVersionV1 {
  const record = exactRecord(raw, PROTOCOL_VERSION_FIELDS, label);
  const version = parseNonEmptyToken(record.version, `${label}.version`);
  return {
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    version,
  };
}

function parseProtocolVersions(
  raw: unknown,
  label: string,
): readonly [LinkedDeviceProtocolVersionV1, ...LinkedDeviceProtocolVersionV1[]] {
  if (!Array.isArray(raw)) throw new Error(`${label} must be an array`);
  const values = raw.map((entry, index) =>
    parseLinkedDeviceProtocolVersionV1(entry, `${label}[${index}]`),
  );
  const families = new Set<string>();
  for (const value of values) {
    if (families.has(value.keyFamily)) throw new Error(`${label} contains duplicate keyFamily`);
    families.add(value.keyFamily);
  }
  return nonEmptyTuple(values, label);
}

type EnrollmentCore = Omit<LinkedDeviceEnrollmentTranscriptV1, 'kind'> & {
  readonly ownerEnrollment: LinkedDeviceOwnerEnrollmentCeremonyV1;
};

function parseEnrollmentCore(record: UnknownRecord, label: string): EnrollmentCore {
  const approvedAtMs = parseUnixTime(record.approvedAtMs, `${label}.approvedAtMs`);
  const expiresAtMs = parseUnixTime(record.expiresAtMs, `${label}.expiresAtMs`);
  assertExpiryAfterIssued(approvedAtMs, expiresAtMs, label);
  const ownerEnrollment = parseLinkedDeviceOwnerEnrollmentCeremonyV1(record.ownerEnrollment);
  if (expiresAtMs > ownerEnrollment.expiresAtMs) {
    throw new Error(`${label}.expiresAtMs must not outlive its owner enrollment ceremony`);
  }
  return {
    linkSessionId: parseSessionId(record.linkSessionId, `${label}.linkSessionId`),
    walletId: parseWallet(record.walletId, `${label}.walletId`),
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    deviceId: parseDeviceId(record.deviceId, `${label}.deviceId`),
    linkPublicKeyB64u: parsePublicKey(record.linkPublicKeyB64u, `${label}.linkPublicKeyB64u`),
    devicePublicKeyB64u: parsePublicKey(record.devicePublicKeyB64u, `${label}.devicePublicKeyB64u`),
    permission: parsePermission(record.permission, `${label}.permission`),
    targetFactor: parseTargetFactor(record.targetFactor, `${label}.targetFactor`),
    ownerAuthorization: parseLinkedDeviceOwnerAuthorizationSourceV1(
      record.ownerAuthorization,
      `${label}.ownerAuthorization`,
    ),
    ownerEnrollment,
    policyDigestB64u: parseDigest(record.policyDigestB64u, `${label}.policyDigestB64u`),
    operationId: parseOperation(record.operationId, `${label}.operationId`),
    idempotencyKey: parseIdempotencyKey(record.idempotencyKey, `${label}.idempotencyKey`),
    orderedKeyBindings: parseKeyBindings(record.orderedKeyBindings, `${label}.orderedKeyBindings`),
    protocolVersions: parseProtocolVersions(record.protocolVersions, `${label}.protocolVersions`),
    approvedAtMs,
    expiresAtMs,
  };
}

export function parseLinkedDeviceApprovalV1(raw: unknown): LinkedDeviceApprovalV1 {
  const record = exactRecord(raw, ENROLLMENT_FIELDS, 'LinkedDeviceApprovalV1');
  if (record.kind !== 'linked_device_approval_v1')
    throw new Error('LinkedDeviceApprovalV1.kind is invalid');
  const core = parseEnrollmentCore(record, 'LinkedDeviceApprovalV1');
  const { targetFactor, ownerEnrollment, ...base } = core;
  if (
    targetFactor.kind === 'passkey_prf' &&
    ownerEnrollment.kind === 'linked_device_passkey_owner_enrollment_v1'
  ) {
    return { kind: 'linked_device_approval_v1', ...base, targetFactor, ownerEnrollment };
  }
  if (
    targetFactor.kind === 'email_otp' &&
    ownerEnrollment.kind === 'linked_device_email_otp_owner_enrollment_v1'
  ) {
    return { kind: 'linked_device_approval_v1', ...base, targetFactor, ownerEnrollment };
  }
  throw new Error('LinkedDeviceApprovalV1 target factor differs from owner enrollment');
}

export function parseLinkedDeviceApprovalDeliveryV1(raw: unknown): LinkedDeviceApprovalDeliveryV1 {
  const record = exactRecord(raw, APPROVAL_DELIVERY_FIELDS, 'LinkedDeviceApprovalDeliveryV1');
  if (record.kind !== 'linked_device_approval_delivery_v1') {
    throw new Error('LinkedDeviceApprovalDeliveryV1.kind is invalid');
  }
  return {
    kind: 'linked_device_approval_delivery_v1',
    approval: parseLinkedDeviceApprovalV1(record.approval),
  };
}

export function parseLinkedDeviceProvisioningCommandV1(
  raw: unknown,
): LinkedDeviceProvisioningCommandV1 {
  const record = exactRecord(raw, PROVISIONING_COMMAND_FIELDS, 'LinkedDeviceProvisioningCommandV1');
  if (record.kind !== 'linked_device_provisioning_command_v1') {
    throw new Error('LinkedDeviceProvisioningCommandV1.kind is invalid');
  }
  return {
    kind: 'linked_device_provisioning_command_v1',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceProvisioningCommandV1.linkSessionId',
    ),
    enrollmentId: parseEnrollmentId(
      record.enrollmentId,
      'LinkedDeviceProvisioningCommandV1.enrollmentId',
    ),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceProvisioningCommandV1.deviceId'),
    targetFactor: parseTargetFactor(
      record.targetFactor,
      'LinkedDeviceProvisioningCommandV1.targetFactor',
    ),
  };
}

export function buildLinkedDeviceProvisioningCommandV1(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
}): LinkedDeviceProvisioningCommandV1 {
  return {
    kind: 'linked_device_provisioning_command_v1',
    linkSessionId: args.linkSessionId,
    enrollmentId: args.enrollmentId,
    deviceId: args.deviceId,
    targetFactor: args.targetFactor,
  };
}

function parseProvisioningChild(raw: unknown, index: number): LinkedDeviceProvisioningChildV1 {
  const label = `LinkedDeviceProvisioningDeliveriesV1.orderedChildren[${index}]`;
  const record = exactRecord(raw, PROVISIONING_CHILD_FIELDS, label);
  if (record.kind !== 'linked_device_provisioning_child_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  if (!Number.isSafeInteger(record.expectedVersion) || Number(record.expectedVersion) < 0) {
    throw new Error(`${label}.expectedVersion must be a non-negative safe integer`);
  }
  const job = parseRotatableSigningLaneJobV1(record.job, `${label}.job`);
  const protocolCommitReceipt = parseLaneProtocolCommitReceiptV1(
    record.protocolCommitReceipt,
    `${label}.protocolCommitReceipt`,
  );
  if (
    String(job.operationId) !== String(protocolCommitReceipt.operationId) ||
    String(job.enrollmentId) !== String(protocolCommitReceipt.enrollmentId) ||
    String(job.walletId) !== String(protocolCommitReceipt.walletId) ||
    String(job.walletKeyId) !== String(protocolCommitReceipt.walletKeyId) ||
    String(job.source.laneId) !== String(protocolCommitReceipt.sourceLaneId) ||
    String(job.source.laneShareEpoch) !== String(protocolCommitReceipt.sourceLaneShareEpoch) ||
    String(job.source.revocationEpoch) !== String(protocolCommitReceipt.sourceRevocationEpoch) ||
    !sameMaterialActivationRef(
      job.source.materialActivation,
      protocolCommitReceipt.sourceMaterialActivation,
    ) ||
    String(job.target.laneId) !== String(protocolCommitReceipt.targetLaneId) ||
    String(job.target.laneShareEpoch) !== String(protocolCommitReceipt.targetLaneShareEpoch) ||
    String(job.targetMaterialActivationId) !==
      String(protocolCommitReceipt.targetMaterialActivationId) ||
    String(job.targetHolder.hpkePublicKeyDigestB64u) !==
      String(protocolCommitReceipt.holderRecipientKeyDigestB64u) ||
    String(job.targetSigningWorker.hpkePublicKeyDigestB64u) !==
      String(protocolCommitReceipt.serverRecipientKeyDigestB64u) ||
    job.keyFamily !== protocolCommitReceipt.keyFamily
  ) {
    throw new Error(`${label} protocol receipt does not match its job`);
  }
  const holderPackage = parseLaneHolderPackageWireV1(
    record.holderPackage,
    `${label}.holderPackage`,
  );
  if (
    (job.keyFamily === 'ed25519' &&
      holderPackage.kind !== 'ed25519_yao_lane_holder_package_set_v1') ||
    (job.keyFamily === 'ecdsa_secp256k1' &&
      holderPackage.kind !== 'ecdsa_additive_lane_holder_package_v1')
  ) {
    throw new Error(`${label} holder package curve does not match its job`);
  }
  return {
    kind: 'linked_device_provisioning_child_v1',
    job,
    protocolCommitReceipt,
    holderPackage,
    expectedVersion: Number(record.expectedVersion),
  };
}

export function parseLinkedDeviceProvisioningChildV1(
  raw: unknown,
): LinkedDeviceProvisioningChildV1 {
  return parseProvisioningChild(raw, 0);
}

function sameMaterialActivationRef(
  left: RotatableSigningLaneJobV1['source']['materialActivation'],
  right: LaneProtocolCommitReceiptV1['sourceMaterialActivation'],
): boolean {
  return (
    String(left.activationId) === String(right.activationId) &&
    String(left.capability) === String(right.capability) &&
    String(left.materialOwner) === String(right.materialOwner) &&
    String(left.keyBinding) === String(right.keyBinding) &&
    String(left.lifecycleBinding) === String(right.lifecycleBinding) &&
    String(left.signingWorker) === String(right.signingWorker)
  );
}

export function parseLinkedDeviceProvisioningDeliveriesV1(
  raw: unknown,
): LinkedDeviceProvisioningDeliveriesV1 {
  const record = exactRecord(
    raw,
    PROVISIONING_DELIVERIES_FIELDS,
    'LinkedDeviceProvisioningDeliveriesV1',
  );
  if (record.kind !== 'linked_device_provisioning_deliveries_v1') {
    throw new Error('LinkedDeviceProvisioningDeliveriesV1.kind is invalid');
  }
  if (!Array.isArray(record.orderedChildren)) {
    throw new Error('LinkedDeviceProvisioningDeliveriesV1.orderedChildren must be an array');
  }
  const orderedChildren = nonEmptyTuple(
    record.orderedChildren.map((entry, index) => parseProvisioningChild(entry, index)),
    'LinkedDeviceProvisioningDeliveriesV1.orderedChildren',
  );
  const linkSessionId = parseSessionId(
    record.linkSessionId,
    'LinkedDeviceProvisioningDeliveriesV1.linkSessionId',
  );
  const enrollmentId = parseEnrollmentId(
    record.enrollmentId,
    'LinkedDeviceProvisioningDeliveriesV1.enrollmentId',
  );
  const deviceId = parseDeviceId(record.deviceId, 'LinkedDeviceProvisioningDeliveriesV1.deviceId');
  const manifest = parseLaneEnrollmentManifestV1(
    record.manifest,
    'LinkedDeviceProvisioningDeliveriesV1.manifest',
  );
  if (
    String(manifest.enrollmentId) !== String(enrollmentId) ||
    manifest.authorization.kind !== 'linked_device_enrollment' ||
    String(manifest.authorization.linkedDeviceEnrollmentId) !== String(enrollmentId) ||
    manifest.orderedChildren.length !== orderedChildren.length
  ) {
    throw new Error('LinkedDeviceProvisioningDeliveriesV1 manifest does not match parent');
  }
  const targetLanes = new Set<string>();
  for (let index = 0; index < orderedChildren.length; index += 1) {
    const child = orderedChildren[index];
    const manifestChild = manifest.orderedChildren[index];
    if (
      !child ||
      !manifestChild ||
      !sameTargetReadyJobManifestChild(child.job, manifest, manifestChild)
    ) {
      throw new Error(
        `LinkedDeviceProvisioningDeliveriesV1 child ${index} differs from its manifest child`,
      );
    }
    if (String(child.job.enrollmentId) !== String(enrollmentId)) {
      throw new Error(
        'LinkedDeviceProvisioningDeliveriesV1 child enrollment does not match parent',
      );
    }
    if (child.job.target.laneKind !== 'linked_device') {
      throw new Error(
        'LinkedDeviceProvisioningDeliveriesV1 child target lane is not linked-device',
      );
    }
    if (
      child.job.authorization.kind !== 'linked_device_enrollment' ||
      String(child.job.authorization.linkedDeviceEnrollmentId) !== String(enrollmentId)
    ) {
      throw new Error(
        'LinkedDeviceProvisioningDeliveriesV1 child authorization does not match parent',
      );
    }
    const targetKey = String(child.job.target.laneId);
    if (targetLanes.has(targetKey)) {
      throw new Error('LinkedDeviceProvisioningDeliveriesV1 contains duplicate target lane');
    }
    targetLanes.add(targetKey);
  }
  return {
    kind: 'linked_device_provisioning_deliveries_v1',
    linkSessionId,
    enrollmentId,
    deviceId,
    manifest,
    orderedChildren,
  };
}

/** Parse the owner source handoff and bind every job to the exact manifest child. */
export function parseLinkedDeviceTargetReadyR102InputV1(
  raw: unknown,
): LinkedDeviceTargetReadyR102InputV1 {
  const record = exactRecord(
    raw,
    TARGET_READY_R102_INPUT_FIELDS,
    'LinkedDeviceTargetReadyR102InputV1',
  );
  if (record.kind !== 'linked_device_target_ready_r102_input_v1') {
    throw new Error('LinkedDeviceTargetReadyR102InputV1.kind is invalid');
  }
  if (!Array.isArray(record.children)) {
    throw new Error('LinkedDeviceTargetReadyR102InputV1.children must be an array');
  }
  const children = nonEmptyTuple(
    record.children.map((entry, index) =>
      parseRotatableSigningLaneJobV1(
        entry,
        `LinkedDeviceTargetReadyR102InputV1.children[${index}]`,
      ),
    ),
    'LinkedDeviceTargetReadyR102InputV1.children',
  );
  const manifest = parseLaneEnrollmentManifestV1(
    record.manifest,
    'LinkedDeviceTargetReadyR102InputV1.manifest',
  );
  const linkSessionId = parseSessionId(
    record.linkSessionId,
    'LinkedDeviceTargetReadyR102InputV1.linkSessionId',
  );
  const walletId = parseWallet(record.walletId, 'LinkedDeviceTargetReadyR102InputV1.walletId');
  const enrollmentId = parseEnrollmentId(
    record.enrollmentId,
    'LinkedDeviceTargetReadyR102InputV1.enrollmentId',
  );
  const deviceId = parseDeviceId(record.deviceId, 'LinkedDeviceTargetReadyR102InputV1.deviceId');
  const authorization = manifest.authorization;
  if (
    manifest.walletId !== walletId ||
    String(manifest.enrollmentId) !== String(enrollmentId) ||
    authorization.kind !== 'linked_device_enrollment'
  ) {
    throw new Error('LinkedDeviceTargetReadyR102InputV1 manifest is not bound to its enrollment');
  }
  if (String(authorization.linkedDeviceEnrollmentId) !== String(enrollmentId)) {
    throw new Error('LinkedDeviceTargetReadyR102InputV1 manifest enrollment differs from parent');
  }
  if (children.length !== manifest.orderedChildren.length) {
    throw new Error('LinkedDeviceTargetReadyR102InputV1 child coverage differs from manifest');
  }
  for (let index = 0; index < children.length; index += 1) {
    const child = children[index];
    const manifestChild = manifest.orderedChildren[index];
    if (
      !child ||
      !manifestChild ||
      !sameTargetReadyJobManifestChild(child, manifest, manifestChild)
    ) {
      throw new Error(
        `LinkedDeviceTargetReadyR102InputV1 child ${index} differs from its manifest child`,
      );
    }
  }
  return {
    kind: 'linked_device_target_ready_r102_input_v1',
    linkSessionId,
    walletId,
    enrollmentId,
    deviceId,
    manifest,
    children,
  };
}

export function parseLinkedDeviceProvisioningDeliveriesSubmissionV1(
  raw: unknown,
): LinkedDeviceProvisioningDeliveriesSubmissionV1 {
  const record = exactRecord(
    raw,
    PROVISIONING_DELIVERIES_SUBMISSION_FIELDS,
    'LinkedDeviceProvisioningDeliveriesSubmissionV1',
  );
  if (record.kind !== 'linked_device_provisioning_deliveries_submission_v1') {
    throw new Error('LinkedDeviceProvisioningDeliveriesSubmissionV1.kind is invalid');
  }
  const linkSessionId = parseSessionId(
    record.linkSessionId,
    'LinkedDeviceProvisioningDeliveriesSubmissionV1.linkSessionId',
  );
  const walletId = parseWallet(
    record.walletId,
    'LinkedDeviceProvisioningDeliveriesSubmissionV1.walletId',
  );
  const enrollmentId = parseEnrollmentId(
    record.enrollmentId,
    'LinkedDeviceProvisioningDeliveriesSubmissionV1.enrollmentId',
  );
  const deviceId = parseDeviceId(
    record.deviceId,
    'LinkedDeviceProvisioningDeliveriesSubmissionV1.deviceId',
  );
  const manifestDigestB64u = parseDigest(
    record.manifestDigestB64u,
    'LinkedDeviceProvisioningDeliveriesSubmissionV1.manifestDigestB64u',
  );
  const deliveries = parseLinkedDeviceProvisioningDeliveriesV1(record.deliveries);
  if (
    deliveries.linkSessionId !== linkSessionId ||
    deliveries.enrollmentId !== enrollmentId ||
    deliveries.deviceId !== deviceId
  ) {
    throw new Error(
      'LinkedDeviceProvisioningDeliveriesSubmissionV1 deliveries identity differs from submission',
    );
  }
  return {
    kind: 'linked_device_provisioning_deliveries_submission_v1',
    linkSessionId,
    walletId,
    enrollmentId,
    deviceId,
    manifestDigestB64u,
    deliveries,
  };
}

function sameTargetReadyJobManifestChild(
  job: RotatableSigningLaneJobV1,
  manifest: LaneEnrollmentManifestV1,
  manifestChild: LaneEnrollmentManifestV1['orderedChildren'][number],
): boolean {
  const authorization = manifest.authorization;
  if (authorization.kind !== 'linked_device_enrollment') return false;
  if (job.authorization.kind !== 'linked_device_enrollment') return false;
  return (
    String(job.operationId) === String(manifestChild.operationId) &&
    String(job.enrollmentId) === String(manifest.enrollmentId) &&
    String(job.walletId) === String(manifest.walletId) &&
    String(job.walletKeyId) === String(manifestChild.walletKeyId) &&
    job.keyFamily === manifestChild.keyFamily &&
    String(job.source.laneId) === String(manifestChild.sourceLaneId) &&
    String(job.source.laneShareEpoch) === String(manifestChild.sourceLaneShareEpoch) &&
    job.source.revocationEpoch === manifestChild.sourceRevocationEpoch &&
    sameMaterialActivationRef(
      job.source.materialActivation,
      manifestChild.sourceMaterialActivation,
    ) &&
    job.target.operation === 'create_lane' &&
    job.target.laneKind === 'linked_device' &&
    String(job.target.laneId) === String(manifestChild.targetLaneId) &&
    String(job.target.laneShareEpoch) === String(manifestChild.targetLaneShareEpoch) &&
    String(job.targetMaterialActivationId) === String(manifestChild.targetMaterialActivationId) &&
    String(job.targetHolder.participantBindingDigestB64u) ===
      String(manifestChild.holderParticipantBindingDigestB64u) &&
    String(job.targetSigningWorker.participantBindingDigestB64u) ===
      String(manifestChild.signingWorkerParticipantBindingDigestB64u) &&
    String(job.authorization.linkedDeviceEnrollmentId) ===
      String(authorization.linkedDeviceEnrollmentId) &&
    String(job.authorization.authorizedOperationId) ===
      String(authorization.authorizedOperationId) &&
    String(job.authorization.linkedDevicePermissionDigestB64u) ===
      String(authorization.linkedDevicePermissionDigestB64u)
  );
}

export function parseLinkedDeviceHolderDeliveryAcknowledgementV1(
  raw: unknown,
): LinkedDeviceHolderDeliveryAcknowledgementV1 {
  const record = exactRecord(
    raw,
    HOLDER_DELIVERY_ACK_FIELDS,
    'LinkedDeviceHolderDeliveryAcknowledgementV1',
  );
  if (record.kind !== 'linked_device_holder_delivery_acknowledgement_v1') {
    throw new Error('LinkedDeviceHolderDeliveryAcknowledgementV1.kind is invalid');
  }
  if (!Array.isArray(record.orderedHolderDeliveryReceipts)) {
    throw new Error(
      'LinkedDeviceHolderDeliveryAcknowledgementV1.orderedHolderDeliveryReceipts must be an array',
    );
  }
  const receipts = nonEmptyTuple(
    record.orderedHolderDeliveryReceipts.map((entry, index) =>
      parseLaneHolderDeliveryReceiptV1(
        entry,
        `LinkedDeviceHolderDeliveryAcknowledgementV1.orderedHolderDeliveryReceipts[${index}]`,
      ),
    ),
    'LinkedDeviceHolderDeliveryAcknowledgementV1.orderedHolderDeliveryReceipts',
  );
  const linkSessionId = parseSessionId(
    record.linkSessionId,
    'LinkedDeviceHolderDeliveryAcknowledgementV1.linkSessionId',
  );
  const enrollmentId = parseEnrollmentId(
    record.enrollmentId,
    'LinkedDeviceHolderDeliveryAcknowledgementV1.enrollmentId',
  );
  const deviceId = parseDeviceId(
    record.deviceId,
    'LinkedDeviceHolderDeliveryAcknowledgementV1.deviceId',
  );
  const acknowledgedAtMs = parseUnixMs(
    record.acknowledgedAtMs,
    'LinkedDeviceHolderDeliveryAcknowledgementV1.acknowledgedAtMs',
  );
  const targetLanes = new Set<string>();
  for (const receipt of receipts) {
    if (String(receipt.enrollmentId) !== String(enrollmentId)) {
      throw new Error(
        'LinkedDeviceHolderDeliveryAcknowledgementV1 receipt enrollment does not match parent',
      );
    }
    const targetKey = String(receipt.targetLaneId);
    if (targetLanes.has(targetKey)) {
      throw new Error('LinkedDeviceHolderDeliveryAcknowledgementV1 contains duplicate target lane');
    }
    targetLanes.add(targetKey);
  }
  return {
    kind: 'linked_device_holder_delivery_acknowledgement_v1',
    linkSessionId,
    enrollmentId,
    deviceId,
    orderedHolderDeliveryReceipts: receipts,
    acknowledgedAtMs,
  };
}

export function parseLinkedDeviceEnrollmentTranscriptV1(
  raw: unknown,
): LinkedDeviceEnrollmentTranscriptV1 {
  const record = exactRecord(raw, ENROLLMENT_FIELDS, 'LinkedDeviceEnrollmentTranscriptV1');
  if (record.kind !== 'linked_device_enrollment_transcript_v1') {
    throw new Error('LinkedDeviceEnrollmentTranscriptV1.kind is invalid');
  }
  return {
    kind: 'linked_device_enrollment_transcript_v1',
    ...parseEnrollmentCore(record, 'LinkedDeviceEnrollmentTranscriptV1'),
  };
}

function parseChildReceiptRecord(
  record: UnknownRecord,
  label: string,
): LinkedDeviceEnrollmentChildReceiptV1 {
  const exact = exactRecord(record, CHILD_RECEIPT_FIELDS, label);
  if (exact.kind !== 'linked_device_enrollment_child_receipt_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  return {
    kind: 'linked_device_enrollment_child_receipt_v1',
    enrollmentId: parseEnrollmentId(exact.enrollmentId, `${label}.enrollmentId`),
    walletId: parseWallet(exact.walletId, `${label}.walletId`),
    walletKeyId: parseWalletKey(exact.walletKeyId, `${label}.walletKeyId`),
    keyFamily: parseKeyFamily(exact.keyFamily, `${label}.keyFamily`),
    targetLaneId: parseLaneId(exact.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseLaneEpoch(
      exact.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    materialActivation: parseActivation(exact.materialActivation, `${label}.materialActivation`),
    receiptDigestB64u: parseDigest(exact.receiptDigestB64u, `${label}.receiptDigestB64u`),
    transcriptHashB64u: parseDigest(exact.transcriptHashB64u, `${label}.transcriptHashB64u`),
    deliveredAtMs: parseUnixTime(exact.deliveredAtMs, `${label}.deliveredAtMs`),
  };
}

export function parseLinkedDeviceEnrollmentChildReceiptV1(
  raw: unknown,
): LinkedDeviceEnrollmentChildReceiptV1 {
  return parseChildReceiptRecord(
    requireRecord(raw, 'LinkedDeviceEnrollmentChildReceiptV1'),
    'LinkedDeviceEnrollmentChildReceiptV1',
  );
}

export function parseLinkedDeviceEnrollmentReceiptV1(
  raw: unknown,
): LinkedDeviceEnrollmentReceiptV1 {
  const record = exactRecord(raw, ENROLLMENT_RECEIPT_FIELDS, 'LinkedDeviceEnrollmentReceiptV1');
  if (record.kind !== 'linked_device_enrollment_receipt_v1') {
    throw new Error('LinkedDeviceEnrollmentReceiptV1.kind is invalid');
  }
  if (!Array.isArray(record.orderedChildReceipts)) {
    throw new Error('LinkedDeviceEnrollmentReceiptV1.orderedChildReceipts must be an array');
  }
  const orderedChildReceipts = nonEmptyTuple(
    record.orderedChildReceipts.map((entry, index) =>
      parseChildReceiptRecord(
        requireRecord(entry, `LinkedDeviceEnrollmentReceiptV1.orderedChildReceipts[${index}]`),
        `LinkedDeviceEnrollmentReceiptV1.orderedChildReceipts[${index}]`,
      ),
    ),
    'LinkedDeviceEnrollmentReceiptV1.orderedChildReceipts',
  );
  const enrollmentId = parseEnrollmentId(
    record.enrollmentId,
    'LinkedDeviceEnrollmentReceiptV1.enrollmentId',
  );
  for (const receipt of orderedChildReceipts) {
    if (receipt.enrollmentId !== enrollmentId) {
      throw new Error('LinkedDeviceEnrollmentReceiptV1 child enrollment does not match parent');
    }
  }
  return {
    kind: 'linked_device_enrollment_receipt_v1',
    enrollmentId,
    walletId: parseWallet(record.walletId, 'LinkedDeviceEnrollmentReceiptV1.walletId'),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceEnrollmentReceiptV1.deviceId'),
    targetFactor: parseTargetFactor(
      record.targetFactor,
      'LinkedDeviceEnrollmentReceiptV1.targetFactor',
    ),
    manifestDigestB64u: parseDigest(
      record.manifestDigestB64u,
      'LinkedDeviceEnrollmentReceiptV1.manifestDigestB64u',
    ),
    aggregateReceiptDigestB64u: parseDigest(
      record.aggregateReceiptDigestB64u,
      'LinkedDeviceEnrollmentReceiptV1.aggregateReceiptDigestB64u',
    ),
    orderedChildReceipts,
    activatedAtMs: parseUnixTime(
      record.activatedAtMs,
      'LinkedDeviceEnrollmentReceiptV1.activatedAtMs',
    ),
  };
}

function parseTargetPreparationChild(
  raw: unknown,
  index: number,
): LinkedDeviceTargetPreparationChildV1 {
  const label = `LinkedDeviceTargetPreparationV1.orderedChildren[${index}]`;
  const record = exactRecord(raw, TARGET_PREPARATION_CHILD_FIELDS, label);
  if (record.kind !== 'linked_device_target_preparation_child_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  return {
    kind: 'linked_device_target_preparation_child_v1',
    operationId: parseId(parseLaneOperationId, record.operationId, `${label}.operationId`),
    walletKeyId: parseId(parseWalletKeyId, record.walletKeyId, `${label}.walletKeyId`),
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    targetLaneId: parseId(parseSigningLaneId, record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseId(
      parseLaneShareEpoch,
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivationId: parseId(
      parseMpcMaterialActivationId,
      record.targetMaterialActivationId,
      `${label}.targetMaterialActivationId`,
    ),
    targetHolderParticipantId: parseId(
      parseLaneHolderParticipantId,
      record.targetHolderParticipantId,
      `${label}.targetHolderParticipantId`,
    ),
  };
}

/**
 * The owner ceremony Device 2 will finalize.
 *
 * `registration` is validated against the canonical add-auth-method options
 * rather than re-declared here, so this boundary cannot drift from the
 * ceremony that mints it. What it owns beyond that is that the ceremony is
 * named and that nothing else rides along with it.
 */
export function parseLinkedDeviceOwnerEnrollmentCeremonyV1(
  raw: unknown,
): LinkedDeviceOwnerEnrollmentCeremonyV1 {
  const initial = requireRecord(raw, 'LinkedDeviceOwnerEnrollmentCeremonyV1');
  if (initial.kind === 'linked_device_passkey_owner_enrollment_v1') {
    const record = exactRecord(
      initial,
      PASSKEY_OWNER_ENROLLMENT_FIELDS,
      'LinkedDeviceOwnerEnrollmentCeremonyV1.passkey',
    );
    const targetFactor = parseTargetFactor(
      record.targetFactor,
      'LinkedDeviceOwnerEnrollmentCeremonyV1.targetFactor',
    );
    if (targetFactor.kind !== 'passkey_prf') {
      throw new Error('Passkey owner enrollment requires passkey_prf target factor');
    }
    return {
      kind: 'linked_device_passkey_owner_enrollment_v1',
      targetFactor,
      addAuthMethodCeremonyId: parseNonEmptyToken(
        record.addAuthMethodCeremonyId,
        'LinkedDeviceOwnerEnrollmentCeremonyV1.addAuthMethodCeremonyId',
      ),
      registration: parseWalletAddAuthMethodRegistrationOptions(record.registration),
      expiresAtMs: parseUnixTime(
        record.expiresAtMs,
        'LinkedDeviceOwnerEnrollmentCeremonyV1.expiresAtMs',
      ),
    };
  }
  if (initial.kind === 'linked_device_email_otp_owner_enrollment_v1') {
    const record = exactRecord(
      initial,
      EMAIL_OTP_OWNER_ENROLLMENT_FIELDS,
      'LinkedDeviceOwnerEnrollmentCeremonyV1.emailOtp',
    );
    const targetFactor = parseTargetFactor(
      record.targetFactor,
      'LinkedDeviceOwnerEnrollmentCeremonyV1.targetFactor',
    );
    if (targetFactor.kind !== 'email_otp') {
      throw new Error('Email OTP owner enrollment requires email_otp target factor');
    }
    return {
      kind: 'linked_device_email_otp_owner_enrollment_v1',
      targetFactor,
      baseWalletAuthMethodId: parseId(
        parseWalletAuthMethodId,
        record.baseWalletAuthMethodId,
        'LinkedDeviceOwnerEnrollmentCeremonyV1.baseWalletAuthMethodId',
      ),
      maskedEmailHint: parseNonEmptyToken(
        record.maskedEmailHint,
        'LinkedDeviceOwnerEnrollmentCeremonyV1.maskedEmailHint',
      ),
      expiresAtMs: parseUnixTime(
        record.expiresAtMs,
        'LinkedDeviceOwnerEnrollmentCeremonyV1.expiresAtMs',
      ),
    };
  }
  throw new Error('LinkedDeviceOwnerEnrollmentCeremonyV1.kind is invalid');
}

export function parseLinkedDeviceTargetPreparationV1(
  raw: unknown,
): LinkedDeviceTargetPreparationV1 {
  const record = exactRecord(raw, TARGET_PREPARATION_FIELDS, 'LinkedDeviceTargetPreparationV1');
  if (record.kind !== 'linked_device_target_preparation_v1') {
    throw new Error('LinkedDeviceTargetPreparationV1.kind is invalid');
  }
  if (!Array.isArray(record.orderedChildren)) {
    throw new Error('LinkedDeviceTargetPreparationV1.orderedChildren must be an array');
  }
  const orderedChildren = nonEmptyTuple(
    record.orderedChildren.map((entry, index) => parseTargetPreparationChild(entry, index)),
    'LinkedDeviceTargetPreparationV1.orderedChildren',
  );
  assertUniqueTargetPreparationChildren(orderedChildren);
  const issuedAtMs = parseUnixTime(record.issuedAtMs, 'LinkedDeviceTargetPreparationV1.issuedAtMs');
  const expiresAtMs = parseUnixTime(
    record.expiresAtMs,
    'LinkedDeviceTargetPreparationV1.expiresAtMs',
  );
  if (expiresAtMs <= issuedAtMs) {
    throw new Error('LinkedDeviceTargetPreparationV1.expiresAtMs must follow issuedAtMs');
  }
  const ownerEnrollment = parseLinkedDeviceOwnerEnrollmentCeremonyV1(record.ownerEnrollment);
  const targetFactor = parseTargetFactor(
    record.targetFactor,
    'LinkedDeviceTargetPreparationV1.targetFactor',
  );
  if (targetFactor.kind !== ownerEnrollment.targetFactor.kind) {
    throw new Error('LinkedDeviceTargetPreparationV1 target factor differs from owner enrollment');
  }
  if (expiresAtMs > ownerEnrollment.expiresAtMs) {
    throw new Error(
      'LinkedDeviceTargetPreparationV1.expiresAtMs must not outlive its owner enrollment ceremony',
    );
  }
  const base = {
    kind: 'linked_device_target_preparation_v1' as const,
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceTargetPreparationV1.linkSessionId',
    ),
    walletId: parseWallet(record.walletId, 'LinkedDeviceTargetPreparationV1.walletId'),
    enrollmentId: parseEnrollmentId(
      record.enrollmentId,
      'LinkedDeviceTargetPreparationV1.enrollmentId',
    ),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceTargetPreparationV1.deviceId'),
    orderedChildren,
    issuedAtMs,
    expiresAtMs,
  };
  if (
    targetFactor.kind === 'passkey_prf' &&
    ownerEnrollment.kind === 'linked_device_passkey_owner_enrollment_v1'
  ) {
    return { ...base, targetFactor, ownerEnrollment };
  }
  if (
    targetFactor.kind === 'email_otp' &&
    ownerEnrollment.kind === 'linked_device_email_otp_owner_enrollment_v1'
  ) {
    return { ...base, targetFactor, ownerEnrollment };
  }
  throw new Error('LinkedDeviceTargetPreparationV1 target factor differs from owner enrollment');
}

function assertUniqueTargetPreparationChildren(
  children: readonly LinkedDeviceTargetPreparationChildV1[],
): void {
  const operations = new Set<string>();
  const targets = new Set<string>();
  for (const child of children) {
    const operationId = String(child.operationId);
    const target = `${String(child.walletKeyId)}\u0000${String(child.targetLaneId)}\u0000${String(child.targetLaneShareEpoch)}`;
    if (operations.has(operationId) || targets.has(target)) {
      throw new Error('LinkedDeviceTargetPreparationV1 contains duplicate child identity');
    }
    operations.add(operationId);
    targets.add(target);
  }
}

function parseWebAuthnTransport(
  raw: unknown,
  label: string,
): LinkedDeviceWebAuthnRegistrationV1['transports'][number] {
  switch (raw) {
    case 'ble':
    case 'cable':
    case 'hybrid':
    case 'internal':
    case 'nfc':
    case 'smart-card':
    case 'usb':
      return raw;
    default:
      throw new Error(`${label} is invalid`);
  }
}

function parseLinkedDeviceWebAuthnRegistrationV1(raw: unknown): LinkedDeviceWebAuthnRegistrationV1 {
  const label = 'LinkedDeviceTargetCredentialRegistrationV1.webauthnRegistration';
  const record = exactRecord(raw, WEBAUTHN_REGISTRATION_FIELDS, label);
  if (record.kind !== 'linked_device_webauthn_registration_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  if (!Array.isArray(record.transports)) throw new Error(`${label}.transports must be an array`);
  if (
    record.authenticatorAttachment !== null &&
    record.authenticatorAttachment !== 'platform' &&
    record.authenticatorAttachment !== 'cross-platform'
  ) {
    throw new Error(`${label}.authenticatorAttachment is invalid`);
  }
  const transports = record.transports.map((entry, index) =>
    parseWebAuthnTransport(entry, `${label}.transports[${index}]`),
  );
  if (new Set(transports).size !== transports.length) {
    throw new Error(`${label}.transports contains duplicates`);
  }
  return {
    kind: 'linked_device_webauthn_registration_v1',
    credentialIdB64u: parseCredential(record.credentialIdB64u, `${label}.credentialIdB64u`),
    authenticatorAttachment: record.authenticatorAttachment,
    clientDataJsonB64u: parseCanonicalBase64UrlBytes(
      record.clientDataJsonB64u,
      `${label}.clientDataJsonB64u`,
    ),
    attestationObjectB64u: parseCanonicalBase64UrlBytes(
      record.attestationObjectB64u,
      `${label}.attestationObjectB64u`,
    ),
    transports,
  };
}

function parseTargetHolderRegistration(
  raw: unknown,
  index: number,
): LinkedDeviceTargetHolderRegistrationV1 {
  const label = `LinkedDeviceTargetCredentialRegistrationV1.orderedHolderRegistrations[${index}]`;
  const record = exactRecord(raw, TARGET_HOLDER_REGISTRATION_FIELDS, label);
  if (record.kind !== 'linked_device_target_holder_registration_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  return {
    kind: 'linked_device_target_holder_registration_v1',
    operationId: parseId(parseLaneOperationId, record.operationId, `${label}.operationId`),
    walletKeyId: parseId(parseWalletKeyId, record.walletKeyId, `${label}.walletKeyId`),
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    targetLaneId: parseId(parseSigningLaneId, record.targetLaneId, `${label}.targetLaneId`),
    targetLaneShareEpoch: parseId(
      parseLaneShareEpoch,
      record.targetLaneShareEpoch,
      `${label}.targetLaneShareEpoch`,
    ),
    targetMaterialActivationId: parseId(
      parseMpcMaterialActivationId,
      record.targetMaterialActivationId,
      `${label}.targetMaterialActivationId`,
    ),
    holderParticipant: parseLaneHolderParticipantRecordV1(
      record.holderParticipant,
      `${label}.holderParticipant`,
    ),
  };
}

export function parseLinkedDeviceTargetCredentialRegistrationV1(
  raw: unknown,
): LinkedDeviceTargetCredentialRegistrationV1 {
  const initial = requireRecord(raw, 'LinkedDeviceTargetCredentialRegistrationV1');
  const targetFactor = parseTargetFactor(
    initial.targetFactor,
    'LinkedDeviceTargetCredentialRegistrationV1.targetFactor',
  );
  const record = exactRecord(
    initial,
    targetFactor.kind === 'passkey_prf' ? PASSKEY_CREDENTIAL_FIELDS : EMAIL_OTP_CREDENTIAL_FIELDS,
    'LinkedDeviceTargetCredentialRegistrationV1',
  );
  if (record.kind !== 'linked_device_target_credential_registration_v1') {
    throw new Error('LinkedDeviceTargetCredentialRegistrationV1.kind is invalid');
  }
  const linkSessionId = parseSessionId(
    record.linkSessionId,
    'LinkedDeviceTargetCredentialRegistrationV1.linkSessionId',
  );
  const walletId = parseWallet(
    record.walletId,
    'LinkedDeviceTargetCredentialRegistrationV1.walletId',
  );
  const enrollmentId = parseEnrollmentId(
    record.enrollmentId,
    'LinkedDeviceTargetCredentialRegistrationV1.enrollmentId',
  );
  const deviceId = parseDeviceId(
    record.deviceId,
    'LinkedDeviceTargetCredentialRegistrationV1.deviceId',
  );
  const targetPreparationDigestB64u = parseDigest(
    record.targetPreparationDigestB64u,
    'LinkedDeviceTargetCredentialRegistrationV1.targetPreparationDigestB64u',
  );
  const orderedHolderRegistrations = parseTargetHolderRegistrations(
    record.orderedHolderRegistrations,
  );
  const registeredAtMs = parseUnixTime(
    record.registeredAtMs,
    'LinkedDeviceTargetCredentialRegistrationV1.registeredAtMs',
  );
  if (targetFactor.kind === 'passkey_prf') {
    return {
      kind: 'linked_device_target_credential_registration_v1',
      linkSessionId,
      walletId,
      enrollmentId,
      deviceId,
      targetFactor,
      targetPreparationDigestB64u,
      webauthnRegistration: parseLinkedDeviceWebAuthnRegistrationV1(record.webauthnRegistration),
      orderedHolderRegistrations,
      registeredAtMs,
    };
  }
  return {
    kind: 'linked_device_target_credential_registration_v1',
    linkSessionId,
    walletId,
    enrollmentId,
    deviceId,
    targetFactor,
    targetPreparationDigestB64u,
    emailOtpVerificationGrant: parseLinkedDeviceEmailOtpVerificationGrantV1(
      record.emailOtpVerificationGrant,
    ),
    orderedHolderRegistrations,
    registeredAtMs,
  };
}

export function parseLinkedDeviceEmailOtpVerificationGrantV1(
  raw: unknown,
): LinkedDeviceEmailOtpVerificationGrantV1 {
  const record = exactRecord(
    raw,
    EMAIL_OTP_VERIFICATION_GRANT_FIELDS,
    'LinkedDeviceEmailOtpVerificationGrantV1',
  );
  if (record.kind !== 'linked_device_email_otp_verification_grant_v1') {
    throw new Error('LinkedDeviceEmailOtpVerificationGrantV1.kind is invalid');
  }
  const issuedAtMs = parseUnixTime(
    record.issuedAtMs,
    'LinkedDeviceEmailOtpVerificationGrantV1.issuedAtMs',
  );
  const expiresAtMs = parseUnixTime(
    record.expiresAtMs,
    'LinkedDeviceEmailOtpVerificationGrantV1.expiresAtMs',
  );
  assertExpiryAfterIssued(issuedAtMs, expiresAtMs, 'LinkedDeviceEmailOtpVerificationGrantV1');
  return {
    kind: 'linked_device_email_otp_verification_grant_v1',
    grantId: parseNonEmptyToken(record.grantId, 'LinkedDeviceEmailOtpVerificationGrantV1.grantId'),
    grantToken: parseNonEmptyToken(
      record.grantToken,
      'LinkedDeviceEmailOtpVerificationGrantV1.grantToken',
    ),
    challengeId: parseNonEmptyToken(
      record.challengeId,
      'LinkedDeviceEmailOtpVerificationGrantV1.challengeId',
    ),
    linkSessionId: parseId(
      parseLinkDeviceSessionId,
      record.linkSessionId,
      'LinkedDeviceEmailOtpVerificationGrantV1.linkSessionId',
    ),
    walletId: parseId(
      parseWalletId,
      record.walletId,
      'LinkedDeviceEmailOtpVerificationGrantV1.walletId',
    ),
    enrollmentId: parseId(
      parseLinkedDeviceEnrollmentId,
      record.enrollmentId,
      'LinkedDeviceEmailOtpVerificationGrantV1.enrollmentId',
    ),
    deviceId: parseId(
      parseLinkedDeviceId,
      record.deviceId,
      'LinkedDeviceEmailOtpVerificationGrantV1.deviceId',
    ),
    targetPreparationDigestB64u: parseDigest(
      record.targetPreparationDigestB64u,
      'LinkedDeviceEmailOtpVerificationGrantV1.targetPreparationDigestB64u',
    ),
    baseWalletAuthMethodId: parseId(
      parseWalletAuthMethodId,
      record.baseWalletAuthMethodId,
      'LinkedDeviceEmailOtpVerificationGrantV1.baseWalletAuthMethodId',
    ),
    emailHashHex: parseEmailHashHex(
      record.emailHashHex,
      'LinkedDeviceEmailOtpVerificationGrantV1.emailHashHex',
    ),
    registrationAuthorityId: parseNonEmptyToken(
      record.registrationAuthorityId,
      'LinkedDeviceEmailOtpVerificationGrantV1.registrationAuthorityId',
    ),
    providerUserId: parseNonEmptyToken(
      record.providerUserId,
      'LinkedDeviceEmailOtpVerificationGrantV1.providerUserId',
    ),
    linkedOwnerAuthMethodId: parseId(
      parseWalletAuthMethodId,
      record.linkedOwnerAuthMethodId,
      'LinkedDeviceEmailOtpVerificationGrantV1.linkedOwnerAuthMethodId',
    ),
    authorityDigestB64u: parseDigest(
      record.authorityDigestB64u,
      'LinkedDeviceEmailOtpVerificationGrantV1.authorityDigestB64u',
    ),
    issuedAtMs,
    expiresAtMs,
  };
}

export function parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1(
  raw: unknown,
): LinkedDeviceEmailOtpFactorReleaseEnvelopeV1 {
  const record = exactRecord(
    raw,
    EMAIL_OTP_FACTOR_RELEASE_FIELDS,
    'LinkedDeviceEmailOtpFactorReleaseEnvelopeV1',
  );
  if (record.kind !== 'email_otp_factor_release_v1') {
    throw new Error('LinkedDeviceEmailOtpFactorReleaseEnvelopeV1.kind is invalid');
  }
  return {
    kind: 'email_otp_factor_release_v1',
    challengeId: parseNonEmptyToken(
      record.challengeId,
      'LinkedDeviceEmailOtpFactorReleaseEnvelopeV1.challengeId',
    ),
    enrollmentId: parseNonEmptyToken(
      record.enrollmentId,
      'LinkedDeviceEmailOtpFactorReleaseEnvelopeV1.enrollmentId',
    ),
    enrollmentSealKeyVersion: parseNonEmptyToken(
      record.enrollmentSealKeyVersion,
      'LinkedDeviceEmailOtpFactorReleaseEnvelopeV1.enrollmentSealKeyVersion',
    ),
    serverEphemeralPublicKey65B64u: parseUncompressedP256PointB64u(
      record.serverEphemeralPublicKey65B64u,
      'LinkedDeviceEmailOtpFactorReleaseEnvelopeV1.serverEphemeralPublicKey65B64u',
    ),
    nonce12B64u: parseCanonicalFixedBase64UrlBytes(
      record.nonce12B64u,
      12,
      'LinkedDeviceEmailOtpFactorReleaseEnvelopeV1.nonce12B64u',
    ),
    ciphertextB64u: parseCanonicalBase64UrlBytes(
      record.ciphertextB64u,
      'LinkedDeviceEmailOtpFactorReleaseEnvelopeV1.ciphertextB64u',
    ),
  };
}

export function parseLinkedDeviceEmailOtpChallengeStartRequestV1(
  raw: unknown,
): LinkedDeviceEmailOtpChallengeStartRequestV1 {
  const record = exactRecord(
    raw,
    ['kind', 'linkSessionId', 'workerEphemeralPublicKey65B64u'],
    'LinkedDeviceEmailOtpChallengeStartRequestV1',
  );
  if (record.kind !== 'linked_device_email_otp_challenge_start_request_v1') {
    throw new Error('LinkedDeviceEmailOtpChallengeStartRequestV1.kind is invalid');
  }
  return {
    kind: 'linked_device_email_otp_challenge_start_request_v1',
    linkSessionId: parseId(
      parseLinkDeviceSessionId,
      record.linkSessionId,
      'LinkedDeviceEmailOtpChallengeStartRequestV1.linkSessionId',
    ),
    workerEphemeralPublicKey65B64u: parseUncompressedP256PointB64u(
      record.workerEphemeralPublicKey65B64u,
      'LinkedDeviceEmailOtpChallengeStartRequestV1.workerEphemeralPublicKey65B64u',
    ),
  };
}

export function parseLinkedDeviceEmailOtpChallengeResendRequestV1(
  raw: unknown,
): LinkedDeviceEmailOtpChallengeResendRequestV1 {
  const record = exactRecord(
    raw,
    ['kind', 'linkSessionId', 'challengeId'],
    'LinkedDeviceEmailOtpChallengeResendRequestV1',
  );
  if (record.kind !== 'linked_device_email_otp_challenge_resend_request_v1') {
    throw new Error('LinkedDeviceEmailOtpChallengeResendRequestV1.kind is invalid');
  }
  return {
    kind: 'linked_device_email_otp_challenge_resend_request_v1',
    linkSessionId: parseId(
      parseLinkDeviceSessionId,
      record.linkSessionId,
      'LinkedDeviceEmailOtpChallengeResendRequestV1.linkSessionId',
    ),
    challengeId: parseNonEmptyToken(
      record.challengeId,
      'LinkedDeviceEmailOtpChallengeResendRequestV1.challengeId',
    ),
  };
}

export function parseLinkedDeviceEmailOtpChallengeVerifyRequestV1(
  raw: unknown,
): LinkedDeviceEmailOtpChallengeVerifyRequestV1 {
  const record = exactRecord(
    raw,
    ['kind', 'linkSessionId', 'challengeId', 'otpCode'],
    'LinkedDeviceEmailOtpChallengeVerifyRequestV1',
  );
  if (record.kind !== 'linked_device_email_otp_challenge_verify_request_v1') {
    throw new Error('LinkedDeviceEmailOtpChallengeVerifyRequestV1.kind is invalid');
  }
  if (typeof record.otpCode !== 'string' || !/^[0-9]{6,10}$/.test(record.otpCode)) {
    throw new Error('LinkedDeviceEmailOtpChallengeVerifyRequestV1.otpCode is invalid');
  }
  return {
    kind: 'linked_device_email_otp_challenge_verify_request_v1',
    linkSessionId: parseId(
      parseLinkDeviceSessionId,
      record.linkSessionId,
      'LinkedDeviceEmailOtpChallengeVerifyRequestV1.linkSessionId',
    ),
    challengeId: parseNonEmptyToken(
      record.challengeId,
      'LinkedDeviceEmailOtpChallengeVerifyRequestV1.challengeId',
    ),
    otpCode: record.otpCode,
  };
}

export function parseLinkedDeviceEmailOtpChallengeResultV1(
  raw: unknown,
): LinkedDeviceEmailOtpChallengeResultV1 {
  const record = exactRecord(
    raw,
    ['kind', 'challengeId', 'maskedEmailHint', 'expiresAtMs', 'resendAvailableAtMs'],
    'LinkedDeviceEmailOtpChallengeResultV1',
  );
  if (record.kind !== 'linked_device_email_otp_challenge_result_v1') {
    throw new Error('LinkedDeviceEmailOtpChallengeResultV1.kind is invalid');
  }
  const expiresAtMs = parseUnixTime(
    record.expiresAtMs,
    'LinkedDeviceEmailOtpChallengeResultV1.expiresAtMs',
  );
  const resendAvailableAtMs = parseUnixTime(
    record.resendAvailableAtMs,
    'LinkedDeviceEmailOtpChallengeResultV1.resendAvailableAtMs',
  );
  return {
    kind: 'linked_device_email_otp_challenge_result_v1',
    challengeId: parseNonEmptyToken(
      record.challengeId,
      'LinkedDeviceEmailOtpChallengeResultV1.challengeId',
    ),
    maskedEmailHint: parseNonEmptyToken(
      record.maskedEmailHint,
      'LinkedDeviceEmailOtpChallengeResultV1.maskedEmailHint',
    ),
    expiresAtMs,
    resendAvailableAtMs,
  };
}

export function parseLinkedDeviceEmailOtpVerificationResultV1(
  raw: unknown,
): LinkedDeviceEmailOtpVerificationResultV1 {
  const record = exactRecord(
    raw,
    ['kind', 'verificationGrant', 'factorRelease'],
    'LinkedDeviceEmailOtpVerificationResultV1',
  );
  if (record.kind !== 'linked_device_email_otp_verification_result_v1') {
    throw new Error('LinkedDeviceEmailOtpVerificationResultV1.kind is invalid');
  }
  const verificationGrant = parseLinkedDeviceEmailOtpVerificationGrantV1(record.verificationGrant);
  const factorRelease = parseLinkedDeviceEmailOtpFactorReleaseEnvelopeV1(record.factorRelease);
  if (factorRelease.challengeId !== verificationGrant.challengeId) {
    throw new Error('LinkedDeviceEmailOtpVerificationResultV1 challenge binding changed');
  }
  return {
    kind: 'linked_device_email_otp_verification_result_v1',
    verificationGrant,
    factorRelease,
  };
}

function parseTargetHolderRegistrations(
  raw: unknown,
): [LinkedDeviceTargetHolderRegistrationV1, ...LinkedDeviceTargetHolderRegistrationV1[]] {
  if (!Array.isArray(raw)) {
    throw new Error(
      'LinkedDeviceTargetCredentialRegistrationV1.orderedHolderRegistrations must be an array',
    );
  }
  const registrations = nonEmptyTuple(
    raw.map((entry, index) => parseTargetHolderRegistration(entry, index)),
    'LinkedDeviceTargetCredentialRegistrationV1.orderedHolderRegistrations',
  );
  const operations = registrations.map((entry) => String(entry.operationId));
  if (new Set(operations).size !== operations.length) {
    throw new Error(
      'LinkedDeviceTargetCredentialRegistrationV1 contains duplicate holder operation',
    );
  }
  return registrations;
}

export function parseLinkedDeviceReceiptAcknowledgementV1(
  raw: unknown,
): LinkedDeviceReceiptAcknowledgementV1 {
  const record = exactRecord(raw, RECEIPT_ACK_FIELDS, 'LinkedDeviceReceiptAcknowledgementV1');
  if (record.kind !== 'linked_device_receipt_acknowledgement_v1') {
    throw new Error('LinkedDeviceReceiptAcknowledgementV1.kind is invalid');
  }
  return {
    kind: 'linked_device_receipt_acknowledgement_v1',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceReceiptAcknowledgementV1.linkSessionId',
    ),
    enrollmentId: parseEnrollmentId(
      record.enrollmentId,
      'LinkedDeviceReceiptAcknowledgementV1.enrollmentId',
    ),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceReceiptAcknowledgementV1.deviceId'),
    receipt: parseLinkedDeviceEnrollmentReceiptV1(record.receipt),
    acknowledgedAtMs: parseUnixTime(
      record.acknowledgedAtMs,
      'LinkedDeviceReceiptAcknowledgementV1.acknowledgedAtMs',
    ),
  };
}

function parseCancelUnclaimedRequest(raw: UnknownRecord): LinkedDeviceSessionTransportRequestV1 {
  const record = exactRecord(
    raw,
    ['kind', 'linkSessionId', 'reason', 'requestedAtMs'],
    'LinkedDeviceSessionCancelUnclaimedRequestV1',
  );
  if (
    record.kind !== 'linked_device_session_cancel_unclaimed_request_v1' ||
    record.reason !== 'user_cancelled'
  ) {
    throw new Error('LinkedDeviceSessionCancelUnclaimedRequestV1 is invalid');
  }
  return {
    kind: 'linked_device_session_cancel_unclaimed_request_v1',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceSessionCancelUnclaimedRequestV1.linkSessionId',
    ),
    reason: 'user_cancelled',
    requestedAtMs: parseUnixTime(
      record.requestedAtMs,
      'LinkedDeviceSessionCancelUnclaimedRequestV1.requestedAtMs',
    ),
  };
}

function parseCancelClaimedRequest(raw: UnknownRecord): LinkedDeviceSessionTransportRequestV1 {
  const record = exactRecord(
    raw,
    ['kind', 'linkSessionId', 'enrollmentId', 'deviceId', 'reason', 'requestedAtMs'],
    'LinkedDeviceSessionCancelClaimedRequestV1',
  );
  if (record.kind !== 'linked_device_session_cancel_claimed_request_v1') {
    throw new Error('LinkedDeviceSessionCancelClaimedRequestV1.kind is invalid');
  }
  if (
    record.reason !== 'user_cancelled' &&
    record.reason !== 'expired' &&
    record.reason !== 'revoked'
  ) {
    throw new Error('LinkedDeviceSessionCancelClaimedRequestV1.reason is unsupported');
  }
  return {
    kind: 'linked_device_session_cancel_claimed_request_v1',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceSessionCancelClaimedRequestV1.linkSessionId',
    ),
    enrollmentId: parseEnrollmentId(
      record.enrollmentId,
      'LinkedDeviceSessionCancelClaimedRequestV1.enrollmentId',
    ),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceSessionCancelClaimedRequestV1.deviceId'),
    reason: record.reason,
    requestedAtMs: parseUnixTime(
      record.requestedAtMs,
      'LinkedDeviceSessionCancelClaimedRequestV1.requestedAtMs',
    ),
  };
}

function parseRetryRequest(raw: UnknownRecord): LinkedDeviceSessionTransportRequestV1 {
  const record = exactRecord(
    raw,
    ['kind', 'linkSessionId', 'enrollmentId', 'deviceId', 'requestedAtMs'],
    'LinkedDeviceSessionRetryCommittedDeliveryRequestV1',
  );
  if (record.kind !== 'linked_device_session_retry_committed_delivery_request_v1') {
    throw new Error('LinkedDeviceSessionRetryCommittedDeliveryRequestV1.kind is invalid');
  }
  return {
    kind: 'linked_device_session_retry_committed_delivery_request_v1',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceSessionRetryCommittedDeliveryRequestV1.linkSessionId',
    ),
    enrollmentId: parseEnrollmentId(
      record.enrollmentId,
      'LinkedDeviceSessionRetryCommittedDeliveryRequestV1.enrollmentId',
    ),
    deviceId: parseDeviceId(
      record.deviceId,
      'LinkedDeviceSessionRetryCommittedDeliveryRequestV1.deviceId',
    ),
    requestedAtMs: parseUnixTime(
      record.requestedAtMs,
      'LinkedDeviceSessionRetryCommittedDeliveryRequestV1.requestedAtMs',
    ),
  };
}

export function parseLinkedDeviceSessionTransportRequestV1(
  raw: unknown,
): LinkedDeviceSessionTransportRequestV1 {
  const record = requireRecord(raw, 'LinkedDeviceSessionTransportRequestV1');
  switch (record.kind) {
    case 'linked_device_session_claim_request_v1':
      return parseLinkedDeviceSessionClaimRequestV1(record);
    case 'linked_device_approval_v1':
      return parseLinkedDeviceApprovalV1(record);
    case 'linked_device_target_credential_registration_v1':
      return parseLinkedDeviceTargetCredentialRegistrationV1(record);
    case 'linked_device_receipt_acknowledgement_v1':
      return parseLinkedDeviceReceiptAcknowledgementV1(record);
    case 'linked_device_session_cancel_unclaimed_request_v1':
      return parseCancelUnclaimedRequest(record);
    case 'linked_device_session_cancel_claimed_request_v1':
      return parseCancelClaimedRequest(record);
    case 'linked_device_session_retry_committed_delivery_request_v1':
      return parseRetryRequest(record);
    default:
      throw new Error('LinkedDeviceSessionTransportRequestV1.kind is unsupported');
  }
}

export function parseLinkedDeviceSessionTransportEventV1(
  raw: unknown,
): LinkedDeviceSessionTransportEventV1 {
  const record = exactRecord(
    raw,
    ['kind', 'linkSessionId', 'state', 'emittedAtMs'],
    'LinkedDeviceSessionTransportEventV1',
  );
  if (record.kind !== 'linked_device_session_event_v1') {
    throw new Error('LinkedDeviceSessionTransportEventV1.kind is invalid');
  }
  return {
    kind: 'linked_device_session_event_v1',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceSessionTransportEventV1.linkSessionId',
    ),
    state: parseLinkedDeviceSessionState(record.state),
    emittedAtMs: parseUnixTime(
      record.emittedAtMs,
      'LinkedDeviceSessionTransportEventV1.emittedAtMs',
    ),
  };
}

export function buildQrLinkedDevicePermissionRequest(): QrLinkedDevicePermissionRequest {
  return {
    kind: 'owner_equivalent_signing',
    administrationScope: 'signing_only',
    localUserPresence: 'required',
  };
}

export function buildQrLinkedDeviceSessionPayloadV5(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly targetFactor: LinkedDeviceTargetFactorV1;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): QrLinkedDeviceSessionPayloadV5 {
  const issuedAtMs = parseUnixTime(args.issuedAtMs, 'QrLinkedDeviceSessionPayloadV5.issuedAtMs');
  const expiresAtMs = parseUnixTime(args.expiresAtMs, 'QrLinkedDeviceSessionPayloadV5.expiresAtMs');
  assertExpiryAfterIssued(issuedAtMs, expiresAtMs, 'QrLinkedDeviceSessionPayloadV5');
  return {
    version: 'v5',
    purpose: 'linked_device_lane_creation',
    linkSessionId: args.linkSessionId,
    linkPublicKeyB64u: args.linkPublicKeyB64u,
    devicePublicKeyB64u: args.devicePublicKeyB64u,
    requestedPermission: buildQrLinkedDevicePermissionRequest(),
    targetFactor: parseTargetFactor(
      args.targetFactor,
      'QrLinkedDeviceSessionPayloadV5.targetFactor',
    ),
    issuedAtMs,
    expiresAtMs,
  };
}

export function buildLinkedDeviceSessionClaimRequestV1(
  payload: QrLinkedDeviceSessionPayloadV5,
): LinkedDeviceSessionClaimRequestV1 {
  return { kind: 'linked_device_session_claim_request_v1', payload };
}

export function buildLinkedDeviceSessionClaimV1(
  args: Omit<LinkedDeviceSessionClaimV1, 'kind'>,
): LinkedDeviceSessionClaimV1 {
  const claimedAtMs = parseUnixTime(args.claimedAtMs, 'LinkedDeviceSessionClaimV1.claimedAtMs');
  const claimExpiresAtMs = parseUnixTime(
    args.claimExpiresAtMs,
    'LinkedDeviceSessionClaimV1.claimExpiresAtMs',
  );
  assertExpiryAfterIssued(claimedAtMs, claimExpiresAtMs, 'LinkedDeviceSessionClaimV1');
  return { kind: 'linked_device_session_claim_v1', ...args, claimedAtMs, claimExpiresAtMs };
}

export function buildWalletSessionLinkedDeviceOwnerAuthorizationV1(args: {
  readonly walletSessionId: WalletSessionId;
  readonly authorizationId: WalletSessionAuthorizationId;
}): LinkedDeviceOwnerAuthorizationSourceV1 {
  return {
    kind: 'wallet_session',
    walletSessionId: args.walletSessionId,
    authorizationId: args.authorizationId,
  };
}

export function buildStepUpLinkedDeviceOwnerAuthorizationV1(args: {
  readonly evidenceSetId: AuthorizationEvidenceSetId;
}): LinkedDeviceOwnerAuthorizationSourceV1 {
  return { kind: 'step_up', evidenceSetId: args.evidenceSetId };
}

function validateEnrollmentTimes(
  approvedAtMs: number,
  expiresAtMs: number,
  label: string,
): {
  readonly approvedAtMs: number;
  readonly expiresAtMs: number;
} {
  const approved = parseUnixTime(approvedAtMs, `${label}.approvedAtMs`);
  const expires = parseUnixTime(expiresAtMs, `${label}.expiresAtMs`);
  assertExpiryAfterIssued(approved, expires, label);
  return { approvedAtMs: approved, expiresAtMs: expires };
}

export function buildLinkedDeviceApprovalV1(
  args: Omit<LinkedDeviceApprovalV1, 'kind'>,
): LinkedDeviceApprovalV1 {
  const times = validateEnrollmentTimes(
    args.approvedAtMs,
    args.expiresAtMs,
    'LinkedDeviceApprovalV1',
  );
  return parseLinkedDeviceApprovalV1({ kind: 'linked_device_approval_v1', ...args, ...times });
}

export function buildLinkedDeviceEnrollmentTranscriptV1(
  args: Omit<LinkedDeviceEnrollmentTranscriptV1, 'kind'>,
): LinkedDeviceEnrollmentTranscriptV1 {
  const times = validateEnrollmentTimes(
    args.approvedAtMs,
    args.expiresAtMs,
    'LinkedDeviceEnrollmentTranscriptV1',
  );
  return { kind: 'linked_device_enrollment_transcript_v1', ...args, ...times };
}

export function buildLinkedDeviceEnrollmentChildReceiptV1(
  args: Omit<LinkedDeviceEnrollmentChildReceiptV1, 'kind'>,
): LinkedDeviceEnrollmentChildReceiptV1 {
  return {
    kind: 'linked_device_enrollment_child_receipt_v1',
    ...args,
    deliveredAtMs: parseUnixTime(
      args.deliveredAtMs,
      'LinkedDeviceEnrollmentChildReceiptV1.deliveredAtMs',
    ),
  };
}

export function buildLinkedDeviceEnrollmentReceiptV1(
  args: Omit<LinkedDeviceEnrollmentReceiptV1, 'kind'>,
): LinkedDeviceEnrollmentReceiptV1 {
  const orderedChildReceipts = nonEmptyTuple(
    args.orderedChildReceipts,
    'LinkedDeviceEnrollmentReceiptV1.orderedChildReceipts',
  );
  for (const receipt of orderedChildReceipts) {
    if (receipt.enrollmentId !== args.enrollmentId) {
      throw new Error('LinkedDeviceEnrollmentReceiptV1 child enrollment does not match parent');
    }
  }
  return {
    kind: 'linked_device_enrollment_receipt_v1',
    ...args,
    orderedChildReceipts,
    activatedAtMs: parseUnixTime(
      args.activatedAtMs,
      'LinkedDeviceEnrollmentReceiptV1.activatedAtMs',
    ),
  };
}

export function buildLinkedDeviceTargetPreparationV1(
  args: Omit<LinkedDeviceTargetPreparationV1, 'kind'>,
): LinkedDeviceTargetPreparationV1 {
  return parseLinkedDeviceTargetPreparationV1({
    kind: 'linked_device_target_preparation_v1',
    ...args,
  });
}

export function buildLinkedDeviceTargetCredentialRegistrationV1(
  args: Omit<LinkedDeviceTargetCredentialRegistrationV1, 'kind'>,
): LinkedDeviceTargetCredentialRegistrationV1 {
  return parseLinkedDeviceTargetCredentialRegistrationV1({
    kind: 'linked_device_target_credential_registration_v1',
    ...args,
  });
}

export function buildLinkedDeviceReceiptAcknowledgementV1(
  args: Omit<LinkedDeviceReceiptAcknowledgementV1, 'kind'>,
): LinkedDeviceReceiptAcknowledgementV1 {
  return {
    kind: 'linked_device_receipt_acknowledgement_v1',
    ...args,
    acknowledgedAtMs: parseUnixTime(
      args.acknowledgedAtMs,
      'LinkedDeviceReceiptAcknowledgementV1.acknowledgedAtMs',
    ),
  };
}

export function buildLinkedDeviceHolderDeliveryAcknowledgementV1(
  args: Omit<LinkedDeviceHolderDeliveryAcknowledgementV1, 'kind'>,
): LinkedDeviceHolderDeliveryAcknowledgementV1 {
  const orderedHolderDeliveryReceipts = nonEmptyTuple(
    args.orderedHolderDeliveryReceipts,
    'LinkedDeviceHolderDeliveryAcknowledgementV1.orderedHolderDeliveryReceipts',
  );
  const targetLanes = new Set<string>();
  for (const receipt of orderedHolderDeliveryReceipts) {
    if (String(receipt.enrollmentId) !== String(args.enrollmentId)) {
      throw new Error(
        'LinkedDeviceHolderDeliveryAcknowledgementV1 receipt enrollment does not match parent',
      );
    }
    const targetKey = String(receipt.targetLaneId);
    if (targetLanes.has(targetKey)) {
      throw new Error('LinkedDeviceHolderDeliveryAcknowledgementV1 contains duplicate target lane');
    }
    targetLanes.add(targetKey);
  }
  return {
    kind: 'linked_device_holder_delivery_acknowledgement_v1',
    ...args,
    orderedHolderDeliveryReceipts,
    acknowledgedAtMs: parseUnixTime(
      args.acknowledgedAtMs,
      'LinkedDeviceHolderDeliveryAcknowledgementV1.acknowledgedAtMs',
    ),
  };
}

export function buildLinkedDeviceSessionCancelUnclaimedRequestV1(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly requestedAtMs: number;
}): Extract<
  LinkedDeviceSessionTransportRequestV1,
  { readonly kind: 'linked_device_session_cancel_unclaimed_request_v1' }
> {
  return {
    kind: 'linked_device_session_cancel_unclaimed_request_v1',
    linkSessionId: args.linkSessionId,
    reason: 'user_cancelled',
    requestedAtMs: parseUnixTime(
      args.requestedAtMs,
      'LinkedDeviceSessionCancelUnclaimedRequestV1.requestedAtMs',
    ),
  };
}

export function buildLinkedDeviceSessionCancelClaimedRequestV1(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly reason: 'user_cancelled' | 'expired' | 'revoked';
  readonly requestedAtMs: number;
}): Extract<
  LinkedDeviceSessionTransportRequestV1,
  { readonly kind: 'linked_device_session_cancel_claimed_request_v1' }
> {
  return {
    kind: 'linked_device_session_cancel_claimed_request_v1',
    ...args,
    requestedAtMs: parseUnixTime(
      args.requestedAtMs,
      'LinkedDeviceSessionCancelClaimedRequestV1.requestedAtMs',
    ),
  };
}

export function buildLinkedDeviceSessionRetryCommittedDeliveryRequestV1(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly deviceId: LinkedDeviceId;
  readonly requestedAtMs: number;
}): Extract<
  LinkedDeviceSessionTransportRequestV1,
  { readonly kind: 'linked_device_session_retry_committed_delivery_request_v1' }
> {
  return {
    kind: 'linked_device_session_retry_committed_delivery_request_v1',
    ...args,
    requestedAtMs: parseUnixTime(
      args.requestedAtMs,
      'LinkedDeviceSessionRetryCommittedDeliveryRequestV1.requestedAtMs',
    ),
  };
}

export function buildLinkedDeviceSessionTransportEventV1(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly state: LinkedDeviceSessionState;
  readonly emittedAtMs: number;
}): LinkedDeviceSessionTransportEventV1 {
  return {
    kind: 'linked_device_session_event_v1',
    linkSessionId: args.linkSessionId,
    state: args.state,
    emittedAtMs: parseUnixTime(args.emittedAtMs, 'LinkedDeviceSessionTransportEventV1.emittedAtMs'),
  };
}

function buildState<T extends LinkedDeviceSessionState>(state: T): T {
  return state;
}

export function buildDisplayingQrLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expiresAtMs: number;
}): Extract<LinkedDeviceSessionState, { readonly state: 'displaying_qr' }> {
  return buildState({
    state: 'displaying_qr',
    linkSessionId: args.linkSessionId,
    expiresAtMs: parseUnixTime(args.expiresAtMs, 'displaying_qr.expiresAtMs'),
  });
}

export function buildClaimedByOwnerLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly claimExpiresAtMs: number;
}): Extract<LinkedDeviceSessionState, { readonly state: 'claimed_by_owner' }> {
  return buildState({
    state: 'claimed_by_owner',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    claimExpiresAtMs: parseUnixTime(args.claimExpiresAtMs, 'claimed_by_owner.claimExpiresAtMs'),
  });
}

export function buildAwaitingTargetFactorLinkedDeviceSessionState(
  args:
    | {
        readonly linkSessionId: LinkDeviceSessionId;
        readonly walletId: WalletId;
        readonly enrollmentId: LinkedDeviceEnrollmentId;
        readonly targetFactor: { readonly kind: 'passkey_prf' };
        readonly credentialDeadlineMs: number;
        readonly emailOtpChallenge?: never;
      }
    | {
        readonly linkSessionId: LinkDeviceSessionId;
        readonly walletId: WalletId;
        readonly enrollmentId: LinkedDeviceEnrollmentId;
        readonly targetFactor: { readonly kind: 'email_otp' };
        readonly emailOtpChallenge: Extract<
          LinkedDeviceSessionState,
          {
            readonly state: 'awaiting_target_factor';
            readonly targetFactor: { readonly kind: 'email_otp' };
          }
        >['emailOtpChallenge'];
        readonly credentialDeadlineMs?: never;
      },
): Extract<LinkedDeviceSessionState, { readonly state: 'awaiting_target_factor' }> {
  if ('credentialDeadlineMs' in args && args.credentialDeadlineMs !== undefined) {
    return buildState({
      state: 'awaiting_target_factor',
      linkSessionId: args.linkSessionId,
      walletId: args.walletId,
      enrollmentId: args.enrollmentId,
      targetFactor: { kind: 'passkey_prf' },
      credentialDeadlineMs: parseUnixTime(
        args.credentialDeadlineMs,
        'awaiting_target_factor.credentialDeadlineMs',
      ),
    });
  }
  return buildState({
    state: 'awaiting_target_factor',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    targetFactor: { kind: 'email_otp' },
    emailOtpChallenge: args.emailOtpChallenge,
  });
}

export function buildProvisioningLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly keyManifestDigestB64u: DigestB64u;
}): Extract<LinkedDeviceSessionState, { readonly state: 'provisioning' }> {
  return buildState({
    state: 'provisioning',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    keyManifestDigestB64u: args.keyManifestDigestB64u,
  });
}

export function buildActiveLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly activatedAtMs: number;
}): Extract<LinkedDeviceSessionState, { readonly state: 'active' }> {
  return buildState({
    state: 'active',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    activatedAtMs: parseUnixTime(args.activatedAtMs, 'active.activatedAtMs'),
  });
}

export function buildExpiredUnclaimedLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly expiredAtMs: number;
}): Extract<LinkedDeviceSessionState, { readonly state: 'expired_unclaimed' }> {
  return buildState({
    state: 'expired_unclaimed',
    linkSessionId: args.linkSessionId,
    expiredAtMs: parseUnixTime(args.expiredAtMs, 'expired_unclaimed.expiredAtMs'),
  });
}

export function buildExpiredClaimedLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly expiredAtMs: number;
}): Extract<LinkedDeviceSessionState, { readonly state: 'expired_claimed' }> {
  return buildState({
    state: 'expired_claimed',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    expiredAtMs: parseUnixTime(args.expiredAtMs, 'expired_claimed.expiredAtMs'),
  });
}

export function buildCancelledUnclaimedLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly cancelledAtMs: number;
}): Extract<LinkedDeviceSessionState, { readonly state: 'cancelled_unclaimed' }> {
  return buildState({
    state: 'cancelled_unclaimed',
    linkSessionId: args.linkSessionId,
    cancelledAtMs: parseUnixTime(args.cancelledAtMs, 'cancelled_unclaimed.cancelledAtMs'),
  });
}

export function buildCancelledClaimedPrecommitLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly cancelledAtMs: number;
}): Extract<LinkedDeviceSessionState, { readonly state: 'cancelled_claimed_precommit' }> {
  return buildState({
    state: 'cancelled_claimed_precommit',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    cancelledAtMs: parseUnixTime(args.cancelledAtMs, 'cancelled_claimed_precommit.cancelledAtMs'),
  });
}

export function buildCommittedCompletionRequiredLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly keyManifestDigestB64u: DigestB64u;
  readonly transcriptSetDigestB64u: DigestB64u;
}): Extract<LinkedDeviceSessionState, { readonly state: 'committed_completion_required' }> {
  return buildState({
    state: 'committed_completion_required',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    keyManifestDigestB64u: args.keyManifestDigestB64u,
    transcriptSetDigestB64u: args.transcriptSetDigestB64u,
  });
}

const OWNER_FINALIZE_REQUEST_FIELDS = [
  'kind',
  'addAuthMethodCeremonyId',
  'webauthnRegistration',
  'custodyEnvelope',
] as const;

export function parseLinkedDeviceOwnerFinalizeRequestV1(
  raw: unknown,
): LinkedDeviceOwnerFinalizeRequestV1 {
  const record = exactRecord(
    raw,
    OWNER_FINALIZE_REQUEST_FIELDS,
    'LinkedDeviceOwnerFinalizeRequestV1',
  );
  if (record.kind !== 'linked_device_owner_finalize_request_v1') {
    throw new Error('LinkedDeviceOwnerFinalizeRequestV1.kind is invalid');
  }
  const addAuthMethodCeremonyId =
    typeof record.addAuthMethodCeremonyId === 'string' ? record.addAuthMethodCeremonyId.trim() : '';
  if (!addAuthMethodCeremonyId) {
    throw new Error('LinkedDeviceOwnerFinalizeRequestV1.addAuthMethodCeremonyId is required');
  }
  if (record.webauthnRegistration === undefined || record.webauthnRegistration === null) {
    throw new Error('LinkedDeviceOwnerFinalizeRequestV1.webauthnRegistration is required');
  }
  return {
    kind: 'linked_device_owner_finalize_request_v1',
    addAuthMethodCeremonyId,
    webauthnRegistration: parseLinkedDeviceWebAuthnRegistrationV1(record.webauthnRegistration),
    custodyEnvelope: parsePasskeyCustodyEnvelopeRecord(record.custodyEnvelope),
  };
}

const LOCAL_ACCOUNT_PROJECTION_FIELDS = [
  'kind',
  'walletId',
  'nearAccountId',
  'signerSlot',
] as const;

export function parseLinkedDeviceLocalAccountProjectionV1(
  raw: unknown,
): LinkedDeviceLocalAccountProjectionV1 {
  const record = exactRecord(
    raw,
    LOCAL_ACCOUNT_PROJECTION_FIELDS,
    'LinkedDeviceLocalAccountProjectionV1',
  );
  if (record.kind !== 'linked_device_local_account_projection_v1') {
    throw new Error('LinkedDeviceLocalAccountProjectionV1.kind is invalid');
  }
  const walletId = parseWalletId(record.walletId);
  if (!walletId.ok) throw new Error(walletId.error.message);
  const nearAccountId = parseNonEmptyToken(
    record.nearAccountId,
    'LinkedDeviceLocalAccountProjectionV1.nearAccountId',
  );
  // Unlock parses this with a minimum of 1 and fails closed, so a slot that is
  // absent or zero has to be refused here rather than defaulted to something
  // that would unlock the wrong signer.
  if (!Number.isSafeInteger(record.signerSlot) || Number(record.signerSlot) < 1) {
    throw new Error('LinkedDeviceLocalAccountProjectionV1.signerSlot must be an integer >= 1');
  }
  return {
    kind: 'linked_device_local_account_projection_v1',
    walletId: walletId.value,
    nearAccountId,
    signerSlot: Number(record.signerSlot),
  };
}
