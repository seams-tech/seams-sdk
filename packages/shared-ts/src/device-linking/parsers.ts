import {
  delegatedWalletPermissionNamesV1,
  parseDelegatedWalletAuthorityV1 as parseDelegatedWalletAuthorityResult,
  type DelegatedWalletAuthorityV1,
  type DelegatedWalletPermissionV1,
} from '../authorization/delegatedAuthority';
import {
  parseDeviceId as parseAuthorizationDeviceId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '../authorization/capabilityKinds';
import {
  parseLinkedDeviceEnrollmentId,
  parseLinkedDeviceId,
  parseLinkDeviceSessionId,
  parseWalletKeyId,
  type LinkedDeviceEnrollmentId,
  type LinkedDeviceId,
  type LinkDeviceSessionId,
  type WalletKeyId,
} from '../signing-lanes/ids';
import {
  parseMpcMaterialActivationRef,
  parseWalletAuthMethodId,
  parseWalletAuthorityId,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
  type WalletAuthMethodId,
  type WalletId,
  type WebAuthnCredentialIdB64u,
} from '../utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { parseWalletAddAuthMethodRegistrationOptions } from '../utils/addAuthMethodRegistration';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import {
  parseEd25519PublicKeyB64u,
  parseUnixMs,
  requireRecord,
  rejectUnknownFields,
} from '../passkey-custody/primitives';
import {
  parseWalletAuthorityV1,
  parseWalletSignerActivationSetV1,
} from '../authorization/walletAuthority';
import { parseWalletAuthMethodRecordV2 } from '../utils/registrationIntent';
import {
  type EmailOtpWalletAuthMethodDraftV1,
  type PasskeyWalletAuthMethodDraftV1,
} from '../utils/registrationIntent';
import { requireRouterAbX25519PublicKey } from '../utils/routerAbPublicKeyset';
import { parseWebAuthnAuthenticatorDeviceInfo } from '../utils/webauthnDeviceInfo';
import {
  type LinkedDeviceApprovalV1,
  type LinkedDeviceApprovalDeliveryV1,
  type LinkedDeviceApprovalResultV1,
  type LinkedDevicePendingSessionStateV1,
  type LinkedDeviceListRequestV1,
  type LinkedDeviceListResultV1,
  type OwnerDeviceSummaryV1,
  type LinkedDeviceRevokeRequestV1,
  type LinkedDeviceRevokeResultV1,
  type LinkedDeviceSummaryV1,
  type LinkedOwnerCredentialMetadataV1,
  type LinkedDeviceOwnerAuthorizationSourceV1,
  type LinkedDeviceOwnerAuthorizationRequestV1,
  type LinkedDeviceSessionClaimRequestV1,
  type LinkedDeviceSessionClaimV1,
  type LinkSessionProjectionV1,
  type LinkPrecommitFailureV1,
  type LinkSessionStateV1,
  type LinkSessionTransportEventV1,
  type LinkedDeviceSessionTransportRequestV1,
  type LinkedDeviceTargetCredentialRegistrationV1,
  type LinkedDeviceTargetCredentialRegistrationResultV1,
  type OrdinarySignerMaterialRecipientRequestV1,
  type OrdinarySignerMaterialRecipientRequirementV1,
  type OrdinarySignerMaterialReservationPreparationV1,
  type VerifiedTargetFactorV1,
  type LinkedDeviceEd25519ExportRootPreparationV1,
  type LinkedDeviceEmailOtpVerificationGrantV1,
  type LinkedDeviceEmailOtpFactorReleaseEnvelopeV1,
  type LinkedDeviceEmailOtpChallengeStartRequestV1,
  type LinkedDeviceEmailOtpChallengeResendRequestV1,
  type LinkedDeviceEmailOtpChallengeVerifyRequestV1,
  type LinkedDeviceEmailOtpChallengeResultV1,
  type LinkedDeviceEmailOtpVerificationResultV1,
  type LinkedDeviceTargetPreparationV1,
  type LinkedDevicePasskeyCreationOptionsV1,
  type LinkedDeviceWebAuthnRegistrationV1,
  type LinkDevicePublicKeyB64u,
  type QrLinkedDeviceSessionPayloadV5,
  type LinkedDeviceTargetFactorV1,
  type LinkedDeviceApprovedTargetFactorV1,
  type LinkedDeviceEmailOtpBaseFactorRequestV1,
  type LinkedDeviceEmailOtpBaseFactorResolutionV1,
  type LinkedDeviceEmailOtpBaseFactorResolutionResultV1,
  type ActiveWalletSessionV1,
  type ActivateInstalledAuthorityResultV1,
  type ActivationRetryReasonV1,
  type LinkIntegrityFailureV1,
  type LocalAuthorityActivationFinalAckV1,
  type LocalAuthorityInstallationReceiptV1,
  type WalletSessionOperationCredentialV1,
  type WalletCapabilitySubjectV1,
} from './contracts';
import {
  parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationV1,
  parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1,
  parseLinkedDeviceOrdinaryMaterialSourceContributionTupleV1,
} from './sourceContribution';

type UnknownRecord = Record<string, unknown>;

export {
  parseCommittedSignerPackageSetDigestB64u,
  parseCommittedSignerPackageSetV1,
} from './committedSignerPackages';

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
const COMPACT_QR_FIELDS = ['v', 's', 'l', 'd', 'a', 'f', 'i', 'e'] as const;
const OWNER_AUTHORIZATION_REQUEST_FIELDS = ['payload', 'requestedAtMs'] as const;
const CLAIM_REQUEST_FIELDS = ['kind', 'payload'] as const;
const CLAIM_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'devicePublicKeyB64u',
  'targetFactor',
  'sessionRevision',
  'claimedAtMs',
  'claimExpiresAtMs',
] as const;
const OWNER_AUTH_WALLET_SESSION_FIELDS = ['kind', 'walletSessionId', 'authorizationId'] as const;
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
  'approvedAtMs',
  'expiresAtMs',
] as const;
const ENROLLMENT_FIELDS_WITH_SOURCE_CONTRIBUTION = [
  ...ENROLLMENT_FIELDS,
  'sourceContribution',
] as const;
const APPROVAL_DELIVERY_FIELDS = ['kind', 'approval'] as const;
const CREDENTIAL_BASE_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'walletAuthMethodId',
  'targetFactor',
  'targetPreparationDigestB64u',
  'ordinarySignerMaterialRecipientRequests',
  'registeredAtMs',
] as const;
const PASSKEY_CREDENTIAL_FIELDS = [...CREDENTIAL_BASE_FIELDS, 'webauthnRegistration'] as const;
const EMAIL_OTP_CREDENTIAL_FIELDS = [
  ...CREDENTIAL_BASE_FIELDS,
  'emailOtpVerificationGrant',
] as const;
const TARGET_PREPARATION_BASE_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'walletAuthMethodId',
  'ed25519ExportRoot',
  'targetFactor',
  'ordinarySignerMaterialRecipientRequirements',
  'issuedAtMs',
  'expiresAtMs',
] as const;
const TARGET_PREPARATION_PASSKEY_FIELDS = [
  ...TARGET_PREPARATION_BASE_FIELDS,
  'passkeyCreationOptions',
] as const;
const TARGET_PREPARATION_EMAIL_FIELDS = [
  ...TARGET_PREPARATION_BASE_FIELDS,
  'baseWalletAuthMethodId',
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
const WEBAUTHN_REGISTRATION_FIELDS = [
  'kind',
  'credentialIdB64u',
  'authenticatorAttachment',
  'clientDataJsonB64u',
  'attestationObjectB64u',
  'transports',
] as const;
const APPROVAL_PENDING_FIELDS = ['outcome', 'state'] as const;
const APPROVAL_REPLAY_FIELDS = ['outcome', 'replay'] as const;
const APPROVAL_REPLAY_PENDING_FIELDS = ['state', 'session'] as const;
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
  'walletAuthorityId',
  'credential',
  'createdAtMs',
  'lastActivityAtMs',
] as const;
const LINKED_DEVICE_LIST_RESULT_FIELDS = ['devices', 'ownerDevices', 'nextCursor'] as const;
const LINKED_DEVICE_REVOKE_REQUEST_FIELDS = [
  'kind',
  'walletId',
  'walletAuthMethodId',
  'requestedAtMs',
] as const;
const LINKED_DEVICE_REVOKE_SUCCESS_FIELDS = [
  'kind',
  'walletAuthMethodId',
  'authorityId',
  'revocationEpoch',
] as const;
const LINKED_DEVICE_REVOKE_FAILURE_FIELDS = ['kind'] as const;

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

function parseLinkedDeviceRevokeWalletAuthMethodId(
  raw: unknown,
  label: string,
): WalletAuthMethodId {
  const value = parseId(parseWalletAuthMethodId, raw, label);
  if (value.startsWith('wallet-authority:') || value.startsWith('authority:')) {
    throw new Error(`${label} must identify a WalletAuthMethodId`);
  }
  return value;
}

function parseUnixTime(raw: unknown, label: string): number {
  try {
    return parseUnixMs(raw, label);
  } catch (error) {
    throw new Error(error instanceof Error ? error.message : `${label} is invalid`);
  }
}

function parseEmailHashHex(raw: unknown, label: string): string {
  if (typeof raw !== 'string' || !/^[0-9a-f]{64}$/.test(raw)) {
    throw new Error(`${label} must be 32 canonical lowercase hex bytes`);
  }
  return raw;
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

function parseDelegatedWalletAuthority(raw: unknown, label: string): DelegatedWalletAuthorityV1 {
  const result = parseDelegatedWalletAuthorityResult(raw);
  if (!result.ok) throw new Error(`${label}: ${result.error.message}`);
  return result.value;
}

function delegatedWalletAuthorityWireValue(value: DelegatedWalletAuthorityV1): {
  readonly kind: DelegatedWalletAuthorityV1['kind'];
  readonly permissions: readonly DelegatedWalletPermissionV1[];
} {
  return {
    kind: value.kind,
    permissions: [...delegatedWalletPermissionNamesV1(value)],
  };
}

function qrPayloadWireValue(payload: QrLinkedDeviceSessionPayloadV5): UnknownRecord {
  return {
    version: payload.version,
    purpose: payload.purpose,
    linkSessionId: payload.linkSessionId,
    linkPublicKeyB64u: payload.linkPublicKeyB64u,
    devicePublicKeyB64u: payload.devicePublicKeyB64u,
    requestedPermission: delegatedWalletAuthorityWireValue(payload.requestedPermission),
    targetFactor: payload.targetFactor,
    issuedAtMs: payload.issuedAtMs,
    expiresAtMs: payload.expiresAtMs,
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

function parseApprovedTargetFactor(
  raw: unknown,
  label: string,
): LinkedDeviceApprovedTargetFactorV1 {
  const record = requireRecord(raw, label);
  if (record.kind === 'passkey_prf') {
    exactRecord(record, ['kind'], label);
    return { kind: 'passkey_prf' };
  }
  if (record.kind === 'email_otp') {
    const exact = exactRecord(record, ['kind', 'baseWalletAuthMethodId'], label);
    return {
      kind: 'email_otp',
      baseWalletAuthMethodId: parseId(
        parseWalletAuthMethodId,
        exact.baseWalletAuthMethodId,
        `${label}.baseWalletAuthMethodId`,
      ),
    };
  }
  throw new Error(`${label}.kind is unsupported`);
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
function parseWalletSession(raw: unknown, label: string): WalletSessionId {
  return parseId(parseWalletSessionId, raw, label);
}
function parseWalletAuthorization(raw: unknown, label: string): WalletSessionAuthorizationId {
  return parseId(parseWalletSessionAuthorizationId, raw, label);
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
    permission: parseDelegatedWalletAuthority(
      record.permission,
      'LinkedDeviceSummaryV1.permission',
    ),
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
    walletAuthorityId: parseId(
      parseWalletAuthorityId,
      record.walletAuthorityId,
      'OwnerDeviceSummaryV1.walletAuthorityId',
    ),
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
    walletAuthMethodId: parseLinkedDeviceRevokeWalletAuthMethodId(
      record.walletAuthMethodId,
      'LinkedDeviceRevokeRequestV1.walletAuthMethodId',
    ),
    requestedAtMs: parseUnixTime(record.requestedAtMs, 'LinkedDeviceRevokeRequestV1.requestedAtMs'),
  };
}

export function buildLinkedDeviceRevokeRequestV1(args: {
  readonly walletId: WalletId;
  readonly walletAuthMethodId: WalletAuthMethodId;
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
  if (record.kind !== 'revoked') {
    throw new Error('LinkedDeviceRevokeResultV1.kind is invalid');
  }
  return {
    kind: record.kind,
    walletAuthMethodId: parseLinkedDeviceRevokeWalletAuthMethodId(
      record.walletAuthMethodId,
      'LinkedDeviceRevokeResultV1.walletAuthMethodId',
    ),
    authorityId: parseId(
      parseWalletAuthorityId,
      record.authorityId,
      'LinkedDeviceRevokeResultV1.authorityId',
    ),
    revocationEpoch: parseNonNegativeSafeInteger(
      record.revocationEpoch,
      'LinkedDeviceRevokeResultV1.revocationEpoch',
    ),
  };
}

export function buildLinkedDeviceRevokeResultV1(
  value: LinkedDeviceRevokeResultV1,
): LinkedDeviceRevokeResultV1 {
  return parseLinkedDeviceRevokeResultV1(value);
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
    requestedPermission: parseDelegatedWalletAuthority(
      record.requestedPermission,
      'QrLinkedDeviceSessionPayloadV5.requestedPermission',
    ),
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
  const parsed = parseQrPayloadRecord(qrPayloadWireValue(payload));
  return JSON.stringify({
    v: 5,
    s: parsed.linkSessionId,
    l: parsed.linkPublicKeyB64u,
    d: parsed.devicePublicKeyB64u,
    a: delegatedWalletAuthorityWireValue(parsed.requestedPermission),
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
    requestedPermission: compact.a,
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
  return {
    payload,
    requestedAtMs,
  };
}

const LINK_SESSION_PROJECTION_FIELDS = [
  'kind',
  'linkSessionId',
  'qrPayload',
  'revision',
  'createdAtMs',
  'updatedAtMs',
  'state',
] as const;

const LINK_SESSION_EVENT_FIELDS = ['kind', 'linkSessionId', 'state', 'emittedAtMs'] as const;

export function parseLinkSessionStateV1(raw: unknown): LinkSessionStateV1 {
  const initial = requireRecord(raw, 'LinkSessionStateV1');
  if (typeof initial.state !== 'string') {
    throw new Error('LinkSessionStateV1.state is invalid');
  }
  switch (initial.state) {
    case 'displaying_qr':
      exactRecord(initial, ['state'], 'LinkSessionStateV1.displaying_qr');
      return { state: 'displaying_qr' };
    case 'claimed':
    case 'awaiting_target_factor':
    case 'awaiting_source_contribution':
    case 'provisioning':
      exactRecord(initial, ['state', 'deviceId'], `LinkSessionStateV1.${initial.state}`);
      return {
        state: initial.state,
        deviceId: parseId(
          parseAuthorizationDeviceId,
          initial.deviceId,
          `LinkSessionStateV1.${initial.state}.deviceId`,
        ),
      };
    case 'authority_pending_local_install':
      exactRecord(
        initial,
        ['state', 'deviceId', 'authorityId', 'packageSetDigestB64u'],
        'LinkSessionStateV1.authority_pending_local_install',
      );
      return {
        state: initial.state,
        deviceId: parseId(
          parseAuthorizationDeviceId,
          initial.deviceId,
          'LinkSessionStateV1.authority_pending_local_install.deviceId',
        ),
        authorityId: parseId(
          parseWalletAuthorityId,
          initial.authorityId,
          'LinkSessionStateV1.authority_pending_local_install.authorityId',
        ),
        packageSetDigestB64u: parseDigest(
          initial.packageSetDigestB64u,
          'LinkSessionStateV1.authority_pending_local_install.packageSetDigestB64u',
        ),
      };
    case 'active':
      exactRecord(
        initial,
        ['state', 'deviceId', 'authorityId', 'activatedAtMs'],
        'LinkSessionStateV1.active',
      );
      return {
        state: initial.state,
        deviceId: parseId(
          parseAuthorizationDeviceId,
          initial.deviceId,
          'LinkSessionStateV1.active.deviceId',
        ),
        authorityId: parseId(
          parseWalletAuthorityId,
          initial.authorityId,
          'LinkSessionStateV1.active.authorityId',
        ),
        activatedAtMs: parseUnixTime(
          initial.activatedAtMs,
          'LinkSessionStateV1.active.activatedAtMs',
        ),
      };
    case 'failed_before_commit':
      exactRecord(initial, ['state', 'error'], 'LinkSessionStateV1.failed_before_commit');
      return { state: initial.state, error: parseLinkPrecommitFailureV1(initial.error) };
    case 'cancelled':
      exactRecord(initial, ['state', 'cancelledAtMs'], 'LinkSessionStateV1.cancelled');
      return {
        state: initial.state,
        cancelledAtMs: parseUnixTime(
          initial.cancelledAtMs,
          'LinkSessionStateV1.cancelled.cancelledAtMs',
        ),
      };
    case 'expired':
      exactRecord(initial, ['state', 'expiredAtMs'], 'LinkSessionStateV1.expired');
      return {
        state: initial.state,
        expiredAtMs: parseUnixTime(initial.expiredAtMs, 'LinkSessionStateV1.expired.expiredAtMs'),
      };
    default:
      throw new Error(`LinkSessionStateV1.state ${initial.state} is unsupported`);
  }
}

function parseLinkPrecommitFailureV1(raw: unknown): LinkPrecommitFailureV1 {
  const record = exactRecord(raw, ['kind', 'reason'], 'LinkPrecommitFailureV1');
  if (
    record.kind !== 'invalid_input' &&
    record.kind !== 'unauthorized_source' &&
    record.kind !== 'revoked_source' &&
    record.kind !== 'permission_attenuation_failed' &&
    record.kind !== 'target_factor_failed' &&
    record.kind !== 'expired_session' &&
    record.kind !== 'cancelled_session' &&
    record.kind !== 'claim_conflict' &&
    record.kind !== 'package_preparation_failed'
  ) {
    throw new Error('LinkPrecommitFailureV1.kind is invalid');
  }
  return {
    kind: record.kind,
    reason: parseNonEmptyToken(record.reason, 'LinkPrecommitFailureV1.reason'),
  };
}

export function parseLinkSessionProjectionV1(raw: unknown): LinkSessionProjectionV1 {
  const record = exactRecord(raw, LINK_SESSION_PROJECTION_FIELDS, 'LinkSessionProjectionV1');
  if (record.kind !== 'linked_device_session_projection_v1') {
    throw new Error('LinkSessionProjectionV1.kind is invalid');
  }
  return {
    kind: 'linked_device_session_projection_v1',
    linkSessionId: parseSessionId(record.linkSessionId, 'LinkSessionProjectionV1.linkSessionId'),
    qrPayload: parseQrLinkedDeviceSessionPayloadV5(record.qrPayload),
    revision: parseNonNegativeSafeInteger(record.revision, 'LinkSessionProjectionV1.revision'),
    createdAtMs: parseUnixTime(record.createdAtMs, 'LinkSessionProjectionV1.createdAtMs'),
    updatedAtMs: parseUnixTime(record.updatedAtMs, 'LinkSessionProjectionV1.updatedAtMs'),
    state: parseLinkSessionStateV1(record.state),
  };
}

export function parseLinkSessionTransportEventV1(raw: unknown): LinkSessionTransportEventV1 {
  const record = exactRecord(raw, LINK_SESSION_EVENT_FIELDS, 'LinkSessionTransportEventV1');
  if (record.kind !== 'linked_device_session_event_v1') {
    throw new Error('LinkSessionTransportEventV1.kind is invalid');
  }
  return {
    kind: 'linked_device_session_event_v1',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkSessionTransportEventV1.linkSessionId',
    ),
    state: parseLinkSessionStateV1(record.state),
    emittedAtMs: parseUnixTime(record.emittedAtMs, 'LinkSessionTransportEventV1.emittedAtMs'),
  };
}

export function parseLinkedDeviceApprovalResultV1(raw: unknown): LinkedDeviceApprovalResultV1 {
  const initial = requireRecord(raw, 'LinkedDeviceApprovalResultV1');
  if (initial.outcome === 'pending') {
    const record = exactRecord(initial, APPROVAL_PENDING_FIELDS, 'LinkedDeviceApprovalResultV1');
    return {
      outcome: 'pending',
      state: parsePendingApprovalState(record.state),
    };
  }
  if (initial.outcome !== 'replayed') {
    throw new Error('LinkedDeviceApprovalResultV1.outcome is invalid');
  }
  const outer = exactRecord(initial, APPROVAL_REPLAY_FIELDS, 'LinkedDeviceApprovalResultV1');
  const replay = exactRecord(
    outer.replay,
    APPROVAL_REPLAY_PENDING_FIELDS,
    'LinkedDeviceApprovalResultV1.replay',
  );
  return {
    outcome: 'replayed',
    replay: {
      state: 'pending',
      session: parsePendingApprovalState(replay.session),
    },
  };
}

function parsePendingApprovalState(raw: unknown): LinkedDevicePendingSessionStateV1 {
  const state = parseLinkSessionStateV1(raw);
  switch (state.state) {
    case 'awaiting_target_factor':
    case 'awaiting_source_contribution':
    case 'provisioning':
    case 'authority_pending_local_install':
      return state;
    default:
      throw new Error('LinkedDeviceApprovalResultV1 state is not pending');
  }
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
    sessionRevision: parseUnixTime(
      record.sessionRevision,
      'LinkedDeviceSessionClaimV1.sessionRevision',
    ),
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
  throw new Error(`${label}.kind is unsupported`);
}

type EnrollmentCore = Omit<LinkedDeviceApprovalV1, 'kind'>;

function parseEnrollmentCore(record: UnknownRecord, label: string): EnrollmentCore {
  const approvedAtMs = parseUnixTime(record.approvedAtMs, `${label}.approvedAtMs`);
  const expiresAtMs = parseUnixTime(record.expiresAtMs, `${label}.expiresAtMs`);
  assertExpiryAfterIssued(approvedAtMs, expiresAtMs, label);
  const core = {
    linkSessionId: parseSessionId(record.linkSessionId, `${label}.linkSessionId`),
    walletId: parseWallet(record.walletId, `${label}.walletId`),
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    deviceId: parseDeviceId(record.deviceId, `${label}.deviceId`),
    linkPublicKeyB64u: parsePublicKey(record.linkPublicKeyB64u, `${label}.linkPublicKeyB64u`),
    devicePublicKeyB64u: parsePublicKey(record.devicePublicKeyB64u, `${label}.devicePublicKeyB64u`),
    permission: parseDelegatedWalletAuthority(record.permission, `${label}.permission`),
    targetFactor: parseApprovedTargetFactor(record.targetFactor, `${label}.targetFactor`),
    ownerAuthorization: parseLinkedDeviceOwnerAuthorizationSourceV1(
      record.ownerAuthorization,
      `${label}.ownerAuthorization`,
    ),
    approvedAtMs,
    expiresAtMs,
  };
  if (record.sourceContribution === undefined) {
    return core;
  }
  return {
    ...core,
    sourceContribution: parseLinkedDeviceOrdinaryMaterialSourceContributionTupleV1(
      record.sourceContribution,
    ),
  };
}

export function parseLinkedDeviceApprovalV1(raw: unknown): LinkedDeviceApprovalV1 {
  const candidate = requireRecord(raw, 'LinkedDeviceApprovalV1');
  const record = exactRecord(
    candidate,
    candidate.sourceContribution === undefined
      ? ENROLLMENT_FIELDS
      : ENROLLMENT_FIELDS_WITH_SOURCE_CONTRIBUTION,
    'LinkedDeviceApprovalV1',
  );
  if (record.kind !== 'linked_device_approval_v1')
    throw new Error('LinkedDeviceApprovalV1.kind is invalid');
  const core = parseEnrollmentCore(record, 'LinkedDeviceApprovalV1');
  return { kind: 'linked_device_approval_v1', ...core };
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

export function parseLinkedDeviceTargetPreparationV1(
  raw: unknown,
): LinkedDeviceTargetPreparationV1 {
  const candidate = requireRecord(raw, 'LinkedDeviceTargetPreparationV1');
  const targetFactor = parseTargetFactor(
    candidate.targetFactor,
    'LinkedDeviceTargetPreparationV1.targetFactor',
  );
  const record = exactRecord(
    candidate,
    targetFactor.kind === 'passkey_prf'
      ? TARGET_PREPARATION_PASSKEY_FIELDS
      : TARGET_PREPARATION_EMAIL_FIELDS,
    'LinkedDeviceTargetPreparationV1',
  );
  if (record.kind !== 'linked_device_target_preparation_v1') {
    throw new Error('LinkedDeviceTargetPreparationV1.kind is invalid');
  }
  const walletAuthMethodId = parseId(
    parseWalletAuthMethodId,
    record.walletAuthMethodId,
    'LinkedDeviceTargetPreparationV1.walletAuthMethodId',
  );
  const ordinarySignerMaterialRecipientRequirements =
    parseOrdinarySignerMaterialRecipientRequirementsV1(
      record.ordinarySignerMaterialRecipientRequirements,
    );
  const issuedAtMs = parseUnixTime(record.issuedAtMs, 'LinkedDeviceTargetPreparationV1.issuedAtMs');
  const expiresAtMs = parseUnixTime(
    record.expiresAtMs,
    'LinkedDeviceTargetPreparationV1.expiresAtMs',
  );
  if (expiresAtMs <= issuedAtMs) {
    throw new Error('LinkedDeviceTargetPreparationV1.expiresAtMs must follow issuedAtMs');
  }
  const ed25519ExportRoot = parseLinkedDeviceEd25519ExportRootPreparationV1(
    record.ed25519ExportRoot,
  );
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
    walletAuthMethodId,
    ed25519ExportRoot,
    ordinarySignerMaterialRecipientRequirements,
    issuedAtMs,
    expiresAtMs,
  };
  if (targetFactor.kind === 'passkey_prf') {
    const passkeyCreationOptions = parseLinkedDevicePasskeyCreationOptionsV1(
      record.passkeyCreationOptions,
      walletAuthMethodId,
    );
    return { ...base, targetFactor, passkeyCreationOptions };
  }
  return {
    ...base,
    targetFactor,
    baseWalletAuthMethodId: parseId(
      parseWalletAuthMethodId,
      record.baseWalletAuthMethodId,
      'LinkedDeviceTargetPreparationV1.baseWalletAuthMethodId',
    ),
  };
}

export function parseLinkedDeviceEmailOtpBaseFactorRequestV1(
  raw: unknown,
): LinkedDeviceEmailOtpBaseFactorRequestV1 {
  const record = requireRecord(raw, 'LinkedDeviceEmailOtpBaseFactorRequestV1');
  const expectedRevision = parseUnixTime(
    record.expectedRevision,
    'LinkedDeviceEmailOtpBaseFactorRequestV1.expectedRevision',
  );
  if (record.kind === 'resolve') {
    exactRecord(record, ['kind', 'expectedRevision'], 'LinkedDeviceEmailOtpBaseFactorRequestV1');
    return { kind: 'resolve', expectedRevision };
  }
  if (record.kind === 'select') {
    const exact = exactRecord(
      record,
      ['kind', 'expectedRevision', 'baseWalletAuthMethodId'],
      'LinkedDeviceEmailOtpBaseFactorRequestV1',
    );
    return {
      kind: 'select',
      expectedRevision,
      baseWalletAuthMethodId: parseId(
        parseWalletAuthMethodId,
        exact.baseWalletAuthMethodId,
        'LinkedDeviceEmailOtpBaseFactorRequestV1.baseWalletAuthMethodId',
      ),
    };
  }
  throw new Error('LinkedDeviceEmailOtpBaseFactorRequestV1.kind is unsupported');
}

function parseLinkedDeviceEmailOtpBaseFactorChoiceV1(raw: unknown) {
  const record = exactRecord(
    raw,
    ['baseWalletAuthMethodId', 'maskedEmailHint'],
    'LinkedDeviceEmailOtpBaseFactorChoiceV1',
  );
  if (typeof record.maskedEmailHint !== 'string' || record.maskedEmailHint.length === 0) {
    throw new Error('LinkedDeviceEmailOtpBaseFactorChoiceV1.maskedEmailHint is invalid');
  }
  return {
    baseWalletAuthMethodId: parseId(
      parseWalletAuthMethodId,
      record.baseWalletAuthMethodId,
      'LinkedDeviceEmailOtpBaseFactorChoiceV1.baseWalletAuthMethodId',
    ),
    maskedEmailHint: record.maskedEmailHint,
  };
}

export function parseLinkedDeviceEmailOtpBaseFactorResolutionV1(
  raw: unknown,
): LinkedDeviceEmailOtpBaseFactorResolutionV1 {
  const record = requireRecord(raw, 'LinkedDeviceEmailOtpBaseFactorResolutionV1');
  switch (record.kind) {
    case 'selected': {
      const exact = exactRecord(
        record,
        ['kind', 'choice'],
        'LinkedDeviceEmailOtpBaseFactorResolutionV1',
      );
      return {
        kind: 'selected',
        choice: parseLinkedDeviceEmailOtpBaseFactorChoiceV1(exact.choice),
      };
    }
    case 'selection_required': {
      const exact = exactRecord(
        record,
        ['kind', 'choices'],
        'LinkedDeviceEmailOtpBaseFactorResolutionV1',
      );
      if (!Array.isArray(exact.choices) || exact.choices.length === 0) {
        throw new Error('LinkedDeviceEmailOtpBaseFactorResolutionV1.choices must not be empty');
      }
      const choices = exact.choices.map(parseLinkedDeviceEmailOtpBaseFactorChoiceV1);
      return { kind: 'selection_required', choices: [choices[0]!, ...choices.slice(1)] };
    }
    case 'unavailable': {
      const exact = exactRecord(
        record,
        ['kind', 'reason'],
        'LinkedDeviceEmailOtpBaseFactorResolutionV1',
      );
      if (exact.reason !== 'no_active_email_otp_base_factor') {
        throw new Error('LinkedDeviceEmailOtpBaseFactorResolutionV1.reason is unsupported');
      }
      return { kind: 'unavailable', reason: exact.reason };
    }
    default:
      throw new Error('LinkedDeviceEmailOtpBaseFactorResolutionV1.kind is unsupported');
  }
}

export function parseLinkedDeviceEmailOtpBaseFactorResolutionResultV1(
  raw: unknown,
): LinkedDeviceEmailOtpBaseFactorResolutionResultV1 {
  const record = exactRecord(
    raw,
    ['revision', 'resolution'],
    'LinkedDeviceEmailOtpBaseFactorResolutionResultV1',
  );
  return {
    revision: parseUnixTime(
      record.revision,
      'LinkedDeviceEmailOtpBaseFactorResolutionResultV1.revision',
    ),
    resolution: parseLinkedDeviceEmailOtpBaseFactorResolutionV1(record.resolution),
  };
}

function parseLinkedDevicePasskeyCreationOptionsV1(
  raw: unknown,
  expectedWalletAuthMethodId: WalletAuthMethodId,
): LinkedDevicePasskeyCreationOptionsV1 {
  const label = 'LinkedDeviceTargetPreparationV1.passkeyCreationOptions';
  const record = exactRecord(
    raw,
    [
      'kind',
      'walletAuthMethodId',
      'challengeId',
      'challengeB64u',
      'rpId',
      'user',
      'pubKeyCredParams',
      'authenticatorSelection',
      'timeoutMs',
      'attestation',
      'extensions',
      'excludeCredentials',
    ],
    label,
  );
  const walletAuthMethodId = parseId(
    parseWalletAuthMethodId,
    record.walletAuthMethodId,
    `${label}.walletAuthMethodId`,
  );
  if (walletAuthMethodId !== expectedWalletAuthMethodId) {
    throw new Error(`${label}.walletAuthMethodId must match the preparation`);
  }
  exactRecord(record.user, ['idB64u', 'name', 'displayName'], `${label}.user`);
  exactRecord(
    record.authenticatorSelection,
    ['residentKey', 'userVerification'],
    `${label}.authenticatorSelection`,
  );
  const extensions = exactRecord(record.extensions, ['prf'], `${label}.extensions`);
  const prf = exactRecord(extensions.prf, ['eval'], `${label}.extensions.prf`);
  exactRecord(prf.eval, ['firstB64u', 'secondB64u'], `${label}.extensions.prf.eval`);
  if (!Array.isArray(record.pubKeyCredParams)) {
    throw new Error(`${label}.pubKeyCredParams must be an array`);
  }
  record.pubKeyCredParams.forEach((entry, index) => {
    exactRecord(entry, ['type', 'alg'], `${label}.pubKeyCredParams[${index}]`);
  });
  if (!Array.isArray(record.excludeCredentials)) {
    throw new Error(`${label}.excludeCredentials must be an array`);
  }
  record.excludeCredentials.forEach((entry, index) => {
    exactRecord(entry, ['type', 'id'], `${label}.excludeCredentials[${index}]`);
  });
  const options = parseWalletAddAuthMethodRegistrationOptions(record);
  return {
    kind: options.kind,
    walletAuthMethodId,
    challengeId: options.challengeId,
    challengeB64u: options.challengeB64u,
    rpId: options.rpId,
    user: options.user,
    pubKeyCredParams: options.pubKeyCredParams,
    authenticatorSelection: options.authenticatorSelection,
    timeoutMs: options.timeoutMs,
    attestation: options.attestation,
    extensions: options.extensions,
    excludeCredentials: options.excludeCredentials,
  };
}

function parseLinkedDeviceEd25519ExportRootPreparationV1(
  raw: unknown,
): LinkedDeviceEd25519ExportRootPreparationV1 | null {
  if (raw === null) return null;
  const record = exactRecord(
    raw,
    [
      'kind',
      'walletKeyId',
      'applicationBindingDigestB64u',
      'registeredPublicKeyB64u',
      'revocationEpoch',
    ],
    'LinkedDeviceTargetPreparationV1.ed25519ExportRoot',
  );
  if (record.kind !== 'linked_device_ed25519_export_root_preparation_v1') {
    throw new Error('LinkedDeviceTargetPreparationV1.ed25519ExportRoot.kind is invalid');
  }
  return {
    kind: 'linked_device_ed25519_export_root_preparation_v1',
    walletKeyId: parseWalletKey(
      record.walletKeyId,
      'LinkedDeviceTargetPreparationV1.ed25519ExportRoot.walletKeyId',
    ),
    applicationBindingDigestB64u: parseDigest(
      record.applicationBindingDigestB64u,
      'LinkedDeviceTargetPreparationV1.ed25519ExportRoot.applicationBindingDigestB64u',
    ),
    registeredPublicKeyB64u: parseEd25519PublicKeyB64u(
      record.registeredPublicKeyB64u,
      'LinkedDeviceTargetPreparationV1.ed25519ExportRoot.registeredPublicKeyB64u',
    ),
    revocationEpoch: parseNonNegativeSafeInteger(
      record.revocationEpoch,
      'LinkedDeviceTargetPreparationV1.ed25519ExportRoot.revocationEpoch',
    ),
  };
}

function parseOrdinarySignerMaterialRecipientRequirementV1(
  raw: unknown,
  index: number,
): OrdinarySignerMaterialRecipientRequirementV1 {
  const label = `LinkedDeviceTargetPreparationV1.ordinarySignerMaterialRecipientRequirements[${index}]`;
  const record = exactRecord(raw, ['kind', 'keyFamily', 'walletKeyId'], label);
  if (record.kind !== 'ordinary_signer_material_recipient_requirement_v1') {
    throw new Error(`${label}.kind is invalid`);
  }
  return {
    kind: 'ordinary_signer_material_recipient_requirement_v1',
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    walletKeyId: parseId(parseWalletKeyId, record.walletKeyId, `${label}.walletKeyId`),
  };
}

function parseOrdinarySignerMaterialRecipientRequirementsV1(
  raw: unknown,
): [
  OrdinarySignerMaterialRecipientRequirementV1,
  ...OrdinarySignerMaterialRecipientRequirementV1[],
] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 2) {
    throw new Error(
      'LinkedDeviceTargetPreparationV1.ordinarySignerMaterialRecipientRequirements must contain one or two entries',
    );
  }
  const requirements = raw.map((entry, index) =>
    parseOrdinarySignerMaterialRecipientRequirementV1(entry, index),
  );
  if (new Set(requirements.map((entry) => entry.keyFamily)).size !== requirements.length) {
    throw new Error(
      'LinkedDeviceTargetPreparationV1.ordinarySignerMaterialRecipientRequirements repeats a key family',
    );
  }
  if (
    new Set(requirements.map((entry) => String(entry.walletKeyId))).size !== requirements.length
  ) {
    throw new Error(
      'LinkedDeviceTargetPreparationV1.ordinarySignerMaterialRecipientRequirements repeats a wallet key',
    );
  }
  if (
    requirements.length === 2 &&
    (requirements[0]?.keyFamily !== 'ed25519' || requirements[1]?.keyFamily !== 'ecdsa_secp256k1')
  ) {
    throw new Error(
      'LinkedDeviceTargetPreparationV1.ordinarySignerMaterialRecipientRequirements must be ordered Ed25519 then ECDSA',
    );
  }
  const first = requirements[0];
  if (!first) throw new Error('ordinary signer material recipient requirements are empty');
  return [first, ...requirements.slice(1)];
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

function parseOrdinarySignerMaterialPreparationsV1(
  raw: unknown,
): readonly [
  OrdinarySignerMaterialReservationPreparationV1,
  ...OrdinarySignerMaterialReservationPreparationV1[],
] {
  return parseLinkedDeviceOrdinaryMaterialSourceContributionPreparationTupleV1(raw);
}

function parseOrdinarySignerMaterialRecipientRequestV1(
  raw: unknown,
  index: number,
): OrdinarySignerMaterialRecipientRequestV1 {
  const label = `LinkedDeviceTargetCredentialRegistrationV1.ordinarySignerMaterialRecipientRequests[${index}]`;
  const record = requireRecord(raw, label);
  if (record.kind === 'ordinary_ed25519_signer_material_recipient_request_v1') {
    exactRecord(record, ['kind', 'keyFamily', 'walletKeyId', 'recipientPublicKeyB64u'], label);
    if (record.keyFamily !== 'ed25519') {
      throw new Error(`${label}.keyFamily does not match its kind`);
    }
    return {
      kind: record.kind,
      keyFamily: 'ed25519',
      walletKeyId: parseId(parseWalletKeyId, record.walletKeyId, `${label}.walletKeyId`),
      recipientPublicKeyB64u: parseCanonicalFixedBase64UrlBytes(
        record.recipientPublicKeyB64u,
        32,
        `${label}.recipientPublicKeyB64u`,
      ),
    };
  }
  if (record.kind === 'ordinary_ecdsa_signer_material_recipient_request_v1') {
    exactRecord(record, ['kind', 'keyFamily', 'walletKeyId', 'clientEphemeralPublicKey'], label);
    if (record.keyFamily !== 'ecdsa_secp256k1') {
      throw new Error(`${label}.keyFamily does not match its kind`);
    }
    return {
      kind: record.kind,
      keyFamily: 'ecdsa_secp256k1',
      walletKeyId: parseId(parseWalletKeyId, record.walletKeyId, `${label}.walletKeyId`),
      clientEphemeralPublicKey: requireRouterAbX25519PublicKey(
        record.clientEphemeralPublicKey,
        `${label}.clientEphemeralPublicKey`,
      ),
    };
  }
  throw new Error(`${label}.kind is invalid`);
}

function parseOrdinarySignerMaterialRecipientRequestsV1(
  raw: unknown,
): [OrdinarySignerMaterialRecipientRequestV1, ...OrdinarySignerMaterialRecipientRequestV1[]] {
  if (!Array.isArray(raw) || raw.length === 0 || raw.length > 2) {
    throw new Error(
      'LinkedDeviceTargetCredentialRegistrationV1.ordinarySignerMaterialRecipientRequests must contain one or two entries',
    );
  }
  const requests = raw.map((entry, index) =>
    parseOrdinarySignerMaterialRecipientRequestV1(entry, index),
  );
  const families = requests.map((entry) => entry.keyFamily);
  if (new Set(families).size !== families.length) {
    throw new Error(
      'LinkedDeviceTargetCredentialRegistrationV1.ordinarySignerMaterialRecipientRequests repeats a key family',
    );
  }
  if (new Set(requests.map((entry) => String(entry.walletKeyId))).size !== requests.length) {
    throw new Error(
      'LinkedDeviceTargetCredentialRegistrationV1.ordinarySignerMaterialRecipientRequests repeats a wallet key',
    );
  }
  if (
    requests.length === 2 &&
    (requests[0]?.keyFamily !== 'ed25519' || requests[1]?.keyFamily !== 'ecdsa_secp256k1')
  ) {
    throw new Error(
      'LinkedDeviceTargetCredentialRegistrationV1.ordinarySignerMaterialRecipientRequests must be ordered Ed25519 then ECDSA',
    );
  }
  const first = requests[0];
  if (!first) throw new Error('ordinary signer material recipient requests are empty');
  return [first, ...requests.slice(1)];
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
  const walletAuthMethodId = parseWalletAuthMethodId(record.walletAuthMethodId);
  if (!walletAuthMethodId.ok) {
    throw new Error(
      `LinkedDeviceTargetCredentialRegistrationV1.walletAuthMethodId ${walletAuthMethodId.error.message}`,
    );
  }
  const targetPreparationDigestB64u = parseDigest(
    record.targetPreparationDigestB64u,
    'LinkedDeviceTargetCredentialRegistrationV1.targetPreparationDigestB64u',
  );
  const ordinarySignerMaterialRecipientRequests = parseOrdinarySignerMaterialRecipientRequestsV1(
    record.ordinarySignerMaterialRecipientRequests,
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
      walletAuthMethodId: walletAuthMethodId.value,
      targetFactor,
      targetPreparationDigestB64u,
      ordinarySignerMaterialRecipientRequests,
      webauthnRegistration: parseLinkedDeviceWebAuthnRegistrationV1(record.webauthnRegistration),
      registeredAtMs,
    };
  }
  return {
    kind: 'linked_device_target_credential_registration_v1',
    linkSessionId,
    walletId,
    enrollmentId,
    deviceId,
    walletAuthMethodId: walletAuthMethodId.value,
    targetFactor,
    targetPreparationDigestB64u,
    ordinarySignerMaterialRecipientRequests,
    emailOtpVerificationGrant: parseLinkedDeviceEmailOtpVerificationGrantV1(
      record.emailOtpVerificationGrant,
    ),
    registeredAtMs,
  };
}

export function parseLinkedDeviceTargetCredentialRegistrationResultV1(
  raw: unknown,
): LinkedDeviceTargetCredentialRegistrationResultV1 {
  const record = exactRecord(
    raw,
    [
      'kind',
      'outcome',
      'linkSessionId',
      'walletId',
      'enrollmentId',
      'deviceId',
      'walletAuthMethodId',
      'targetPreparationDigestB64u',
      'targetFactor',
      'ordinarySignerMaterialPreparations',
      'ordinarySignerMaterialRecipientRequests',
      'keyManifestDigestB64u',
    ],
    'LinkedDeviceTargetCredentialRegistrationResultV1',
  );
  if (record.kind !== 'linked_device_target_credential_registration_result_v1') {
    throw new Error('LinkedDeviceTargetCredentialRegistrationResultV1.kind is invalid');
  }
  if (record.outcome !== 'applied' && record.outcome !== 'replayed') {
    throw new Error('LinkedDeviceTargetCredentialRegistrationResultV1.outcome is invalid');
  }
  const linkSessionId = parseSessionId(
    record.linkSessionId,
    'LinkedDeviceTargetCredentialRegistrationResultV1.linkSessionId',
  );
  const walletId = parseWallet(
    record.walletId,
    'LinkedDeviceTargetCredentialRegistrationResultV1.walletId',
  );
  const enrollmentId = parseEnrollmentId(
    record.enrollmentId,
    'LinkedDeviceTargetCredentialRegistrationResultV1.enrollmentId',
  );
  const deviceId = parseDeviceId(
    record.deviceId,
    'LinkedDeviceTargetCredentialRegistrationResultV1.deviceId',
  );
  const walletAuthMethodId = parseId(
    parseWalletAuthMethodId,
    record.walletAuthMethodId,
    'LinkedDeviceTargetCredentialRegistrationResultV1.walletAuthMethodId',
  );
  const targetPreparationDigestB64u = parseDigest(
    record.targetPreparationDigestB64u,
    'LinkedDeviceTargetCredentialRegistrationResultV1.targetPreparationDigestB64u',
  );
  const targetFactor = parseVerifiedTargetFactorV1(
    record.targetFactor,
    'LinkedDeviceTargetCredentialRegistrationResultV1.targetFactor',
  );
  if (
    targetFactor.authMethod.walletAuthMethodId !== walletAuthMethodId ||
    targetFactor.authMethod.walletId !== walletId
  ) {
    throw new Error('LinkedDeviceTargetCredentialRegistrationResultV1 target identity differs');
  }
  const ordinarySignerMaterialPreparations = parseOrdinarySignerMaterialPreparationsV1(
    record.ordinarySignerMaterialPreparations,
  );
  const ordinarySignerMaterialRecipientRequests = parseOrdinarySignerMaterialRecipientRequestsV1(
    record.ordinarySignerMaterialRecipientRequests,
  );
  return {
    kind: 'linked_device_target_credential_registration_result_v1',
    outcome: record.outcome,
    linkSessionId,
    walletId,
    enrollmentId,
    deviceId,
    walletAuthMethodId,
    targetPreparationDigestB64u,
    targetFactor,
    ordinarySignerMaterialPreparations,
    ordinarySignerMaterialRecipientRequests,
    keyManifestDigestB64u: parseDigest(
      record.keyManifestDigestB64u,
      'LinkedDeviceTargetCredentialRegistrationResultV1.keyManifestDigestB64u',
    ),
  };
}

function parseVerifiedTargetFactorV1(raw: unknown, label: string): VerifiedTargetFactorV1 {
  const record = requireRecord(raw, label);
  if (record.kind === 'verified_passkey_target_v1') {
    exactRecord(record, ['kind', 'authMethod', 'verificationDigestB64u', 'verifiedAtMs'], label);
    const authMethod = parsePasskeyWalletAuthMethodDraftV1(
      record.authMethod,
      `${label}.authMethod`,
    );
    const verifiedAtMs = parseUnixTime(record.verifiedAtMs, `${label}.verifiedAtMs`);
    if (verifiedAtMs < authMethod.createdAtMs) {
      throw new Error(`${label}.verifiedAtMs precedes authMethod.createdAtMs`);
    }
    return {
      kind: 'verified_passkey_target_v1',
      authMethod,
      verificationDigestB64u: parseDigest(
        record.verificationDigestB64u,
        `${label}.verificationDigestB64u`,
      ),
      verifiedAtMs,
    };
  }
  if (record.kind === 'verified_email_otp_target_v1') {
    exactRecord(
      record,
      ['kind', 'authMethod', 'baseWalletAuthMethodId', 'verificationDigestB64u', 'verifiedAtMs'],
      label,
    );
    const authMethod = parseEmailOtpWalletAuthMethodDraftV1(
      record.authMethod,
      `${label}.authMethod`,
    );
    const verifiedAtMs = parseUnixTime(record.verifiedAtMs, `${label}.verifiedAtMs`);
    if (verifiedAtMs < authMethod.createdAtMs) {
      throw new Error(`${label}.verifiedAtMs precedes authMethod.createdAtMs`);
    }
    return {
      kind: 'verified_email_otp_target_v1',
      authMethod,
      baseWalletAuthMethodId: parseId(
        parseWalletAuthMethodId,
        record.baseWalletAuthMethodId,
        `${label}.baseWalletAuthMethodId`,
      ),
      verificationDigestB64u: parseDigest(
        record.verificationDigestB64u,
        `${label}.verificationDigestB64u`,
      ),
      verifiedAtMs,
    };
  }
  throw new Error(`${label}.kind is invalid`);
}

function parsePasskeyWalletAuthMethodDraftV1(
  raw: unknown,
  label: string,
): PasskeyWalletAuthMethodDraftV1 {
  const record = exactRecord(
    raw,
    [
      'walletAuthMethodId',
      'walletId',
      'createdAtMs',
      'kind',
      'rpId',
      'credentialIdB64u',
      'credentialPublicKeyB64u',
      'counter',
    ],
    label,
  );
  if (record.kind !== 'passkey') throw new Error(`${label}.kind is invalid`);
  return {
    walletAuthMethodId: parseId(
      parseWalletAuthMethodId,
      record.walletAuthMethodId,
      `${label}.walletAuthMethodId`,
    ),
    walletId: parseWallet(record.walletId, `${label}.walletId`),
    createdAtMs: parseUnixTime(record.createdAtMs, `${label}.createdAtMs`),
    kind: 'passkey',
    rpId: parseId(parseWebAuthnRpId, record.rpId, `${label}.rpId`),
    credentialIdB64u: parseId(
      parseWebAuthnCredentialIdB64u,
      record.credentialIdB64u,
      `${label}.credentialIdB64u`,
    ),
    credentialPublicKeyB64u: parseCanonicalBase64UrlBytes(
      record.credentialPublicKeyB64u,
      `${label}.credentialPublicKeyB64u`,
    ),
    counter: parseNonNegativeInteger(record.counter, `${label}.counter`),
  };
}

function parseEmailOtpWalletAuthMethodDraftV1(
  raw: unknown,
  label: string,
): EmailOtpWalletAuthMethodDraftV1 {
  const record = exactRecord(
    raw,
    [
      'walletAuthMethodId',
      'walletId',
      'createdAtMs',
      'kind',
      'emailHashHex',
      'registrationAuthorityId',
    ],
    label,
  );
  if (record.kind !== 'email_otp') throw new Error(`${label}.kind is invalid`);
  return {
    walletAuthMethodId: parseId(
      parseWalletAuthMethodId,
      record.walletAuthMethodId,
      `${label}.walletAuthMethodId`,
    ),
    walletId: parseWallet(record.walletId, `${label}.walletId`),
    createdAtMs: parseUnixTime(record.createdAtMs, `${label}.createdAtMs`),
    kind: 'email_otp',
    emailHashHex: parseEmailHashHex(record.emailHashHex, `${label}.emailHashHex`),
    registrationAuthorityId: parseNonEmptyToken(
      record.registrationAuthorityId,
      `${label}.registrationAuthorityId`,
    ),
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

export function buildQrLinkedDeviceSessionPayloadV5(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly requestedPermission: DelegatedWalletAuthorityV1;
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
    requestedPermission: parseDelegatedWalletAuthority(
      delegatedWalletAuthorityWireValue(args.requestedPermission),
      'QrLinkedDeviceSessionPayloadV5.requestedPermission',
    ),
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

const LOCAL_AUTHORITY_INSTALLATION_RECEIPT_FIELDS = [
  'kind',
  'authorityId',
  'walletId',
  'authMethodId',
  'deviceId',
  'packageSetDigestB64u',
  'installedActivationRefs',
  'installedRecordSetDigestB64u',
  'targetFactorVerificationDigestB64u',
  'installedAtMs',
] as const;

export function parseLocalAuthorityInstallationReceiptV1(
  raw: unknown,
): LocalAuthorityInstallationReceiptV1 {
  const record = exactRecord(
    raw,
    LOCAL_AUTHORITY_INSTALLATION_RECEIPT_FIELDS,
    'LocalAuthorityInstallationReceiptV1',
  );
  if (record.kind !== 'local_authority_installation_receipt_v1') {
    throw new Error('LocalAuthorityInstallationReceiptV1.kind is invalid');
  }
  const installedActivationResult = parseWalletSignerActivationSetV1(
    record.installedActivationRefs,
  );
  if (!installedActivationResult.ok) {
    throw new Error(
      `LocalAuthorityInstallationReceiptV1.installedActivationRefs ${installedActivationResult.error}`,
    );
  }
  return {
    kind: 'local_authority_installation_receipt_v1',
    authorityId: parseId(parseWalletAuthorityId, record.authorityId, 'authorityId'),
    walletId: parseId(parseWalletId, record.walletId, 'walletId'),
    authMethodId: parseId(parseWalletAuthMethodId, record.authMethodId, 'authMethodId'),
    deviceId: parseId(parseAuthorizationDeviceId, record.deviceId, 'deviceId'),
    packageSetDigestB64u: parseDigest(record.packageSetDigestB64u, 'packageSetDigestB64u'),
    installedActivationRefs: installedActivationResult.value,
    installedRecordSetDigestB64u: parseDigest(
      record.installedRecordSetDigestB64u,
      'installedRecordSetDigestB64u',
    ),
    targetFactorVerificationDigestB64u: parseDigest(
      record.targetFactorVerificationDigestB64u,
      'targetFactorVerificationDigestB64u',
    ),
    installedAtMs: parseUnixTime(record.installedAtMs, 'installedAtMs'),
  };
}

const ACTIVE_WALLET_SESSION_FIELDS = [
  'kind',
  'walletId',
  'authorityId',
  'authMethodId',
  'authorizationId',
  'authorityDigestB64u',
  'authorityRevocationEpoch',
  'capabilitySubjects',
  'issuedAtMs',
  'expiresAtMs',
] as const;

const WALLET_SESSION_OPERATION_CREDENTIAL_FIELDS = ['kind', 'token', 'walletSessionId'] as const;

export function parseWalletSessionOperationCredentialV1(
  raw: unknown,
): WalletSessionOperationCredentialV1 {
  const record = exactRecord(
    raw,
    WALLET_SESSION_OPERATION_CREDENTIAL_FIELDS,
    'WalletSessionOperationCredentialV1',
  );
  if (typeof record.token !== 'string' || record.token.length > 8192) {
    throw new Error('WalletSessionOperationCredentialV1.token is invalid');
  }
  if (record.kind === 'opaque_wallet_session_operation_credential_v1') {
    if (!/^wst_[A-Za-z0-9_-]{43}$/.test(record.token)) {
      throw new Error('WalletSessionOperationCredentialV1 opaque token is invalid');
    }
    return {
      kind: record.kind,
      token: record.token,
      walletSessionId: parseId(parseWalletSessionId, record.walletSessionId, 'walletSessionId'),
    };
  }
  throw new Error('WalletSessionOperationCredentialV1.kind is invalid');
}

export function parseActiveWalletSessionV1(raw: unknown): ActiveWalletSessionV1 {
  const record = exactRecord(raw, ACTIVE_WALLET_SESSION_FIELDS, 'ActiveWalletSessionV1');
  if (record.kind !== 'active_wallet_session_v1') {
    throw new Error('ActiveWalletSessionV1.kind is invalid');
  }
  if (!Array.isArray(record.capabilitySubjects) || record.capabilitySubjects.length === 0) {
    throw new Error('ActiveWalletSessionV1.capabilitySubjects must be non-empty');
  }
  const capabilitySubjects: WalletCapabilitySubjectV1[] = [];
  const subjectKeys = new Set<string>();
  for (const [index, rawSubject] of record.capabilitySubjects.entries()) {
    const subject = parseWalletCapabilitySubjectV1(rawSubject, `capabilitySubjects[${index}]`);
    const key =
      subject.kind === 'sign' || subject.kind === 'export_keys'
        ? `${subject.kind}:${subject.keyFamily}:${subject.materialActivation.activationId}`
        : subject.kind;
    if (subjectKeys.has(key)) throw new Error('ActiveWalletSessionV1 capability subjects repeat');
    subjectKeys.add(key);
    capabilitySubjects.push(subject);
  }
  const first = capabilitySubjects[0];
  if (!first) throw new Error('ActiveWalletSessionV1.capabilitySubjects must be non-empty');
  return {
    kind: 'active_wallet_session_v1',
    walletId: parseId(parseWalletId, record.walletId, 'walletId'),
    authorityId: parseId(parseWalletAuthorityId, record.authorityId, 'authorityId'),
    authMethodId: parseId(parseWalletAuthMethodId, record.authMethodId, 'authMethodId'),
    authorizationId: parseId(
      parseWalletSessionAuthorizationId,
      record.authorizationId,
      'authorizationId',
    ),
    authorityDigestB64u: parseDigest(record.authorityDigestB64u, 'authorityDigestB64u'),
    authorityRevocationEpoch: parseNonNegativeInteger(
      record.authorityRevocationEpoch,
      'authorityRevocationEpoch',
    ),
    capabilitySubjects: [first, ...capabilitySubjects.slice(1)],
    issuedAtMs: parseUnixTime(record.issuedAtMs, 'issuedAtMs'),
    expiresAtMs: parseUnixTime(record.expiresAtMs, 'expiresAtMs'),
  };
}

function parseWalletCapabilitySubjectV1(raw: unknown, label: string): WalletCapabilitySubjectV1 {
  const record = requireRecord(raw, label);
  if (record.kind === 'link_devices' || record.kind === 'revoke_devices') {
    rejectUnknownFields(record, ['kind'], label);
    return { kind: record.kind };
  }
  if (record.kind !== 'sign' && record.kind !== 'export_keys') {
    throw new Error(`${label}.kind is invalid`);
  }
  rejectUnknownFields(record, ['kind', 'keyFamily', 'materialActivation'], label);
  if (record.keyFamily !== 'ed25519' && record.keyFamily !== 'ecdsa_secp256k1') {
    throw new Error(`${label}.keyFamily is invalid`);
  }
  return {
    kind: record.kind,
    keyFamily: record.keyFamily,
    materialActivation: parseId(
      parseMpcMaterialActivationRef,
      record.materialActivation,
      `${label}.materialActivation`,
    ),
  };
}

function parseNonNegativeInteger(raw: unknown, label: string): number {
  if (!Number.isSafeInteger(raw) || Number(raw) < 0) {
    throw new Error(`${label} must be a non-negative safe integer`);
  }
  return Number(raw);
}

const LOCAL_AUTHORITY_ACTIVATION_FINAL_ACK_FIELDS = [
  'kind',
  'linkSessionId',
  'authorityId',
  'packageSetDigestB64u',
  'authorizationId',
  'acknowledgedAtMs',
] as const;

export function parseLocalAuthorityActivationFinalAckV1(
  raw: unknown,
): LocalAuthorityActivationFinalAckV1 {
  const record = exactRecord(
    raw,
    LOCAL_AUTHORITY_ACTIVATION_FINAL_ACK_FIELDS,
    'LocalAuthorityActivationFinalAckV1',
  );
  if (record.kind !== 'local_authority_activation_final_ack_v1') {
    throw new Error('LocalAuthorityActivationFinalAckV1.kind is invalid');
  }
  return {
    kind: 'local_authority_activation_final_ack_v1',
    linkSessionId: parseId(parseLinkDeviceSessionId, record.linkSessionId, 'linkSessionId'),
    authorityId: parseId(parseWalletAuthorityId, record.authorityId, 'authorityId'),
    packageSetDigestB64u: parseDigest(record.packageSetDigestB64u, 'packageSetDigestB64u'),
    authorizationId: parseId(
      parseWalletSessionAuthorizationId,
      record.authorizationId,
      'authorizationId',
    ),
    acknowledgedAtMs: parseUnixTime(record.acknowledgedAtMs, 'acknowledgedAtMs'),
  };
}

export function parseActivateInstalledAuthorityResultV1(
  raw: unknown,
): ActivateInstalledAuthorityResultV1 {
  const record = requireRecord(raw, 'ActivateInstalledAuthorityResultV1');
  switch (record.kind) {
    case 'active': {
      rejectUnknownFields(
        record,
        ['kind', 'authority', 'authMethod', 'walletSession', 'operationCredential'],
        'ActivateInstalledAuthorityResultV1',
      );
      const authorityResult = parseWalletAuthorityV1(record.authority);
      if (!authorityResult.ok || authorityResult.value.state !== 'active') {
        throw new Error('ActivateInstalledAuthorityResultV1.authority must be active');
      }
      const authMethod = parseWalletAuthMethodRecordV2(record.authMethod);
      if (!authMethod || authMethod.status !== 'active') {
        throw new Error('ActivateInstalledAuthorityResultV1.authMethod must be active');
      }
      const walletSession = parseActiveWalletSessionV1(record.walletSession);
      const operationCredential = parseWalletSessionOperationCredentialV1(
        record.operationCredential,
      );
      if (
        authorityResult.value.walletId !== authMethod.walletId ||
        authorityResult.value.authorityId !== authMethod.walletAuthorityId ||
        walletSession.walletId !== authorityResult.value.walletId ||
        walletSession.authorityId !== authorityResult.value.authorityId ||
        walletSession.authMethodId !== authMethod.walletAuthMethodId ||
        walletSession.authorityDigestB64u !== authorityResult.value.authorityDigestB64u ||
        walletSession.authorityRevocationEpoch !== authorityResult.value.revocationEpoch
      ) {
        throw new Error('ActivateInstalledAuthorityResultV1 identities do not match');
      }
      return {
        kind: 'active',
        authority: authorityResult.value,
        authMethod,
        walletSession,
        operationCredential,
      };
    }
    case 'pending_local_install':
      rejectUnknownFields(
        record,
        ['kind', 'authorityId', 'reason'],
        'ActivateInstalledAuthorityResultV1',
      );
      return {
        kind: 'pending_local_install',
        authorityId: parseId(parseWalletAuthorityId, record.authorityId, 'authorityId'),
        reason: parseActivationRetryReasonV1(record.reason),
      };
    case 'integrity_error':
      rejectUnknownFields(record, ['kind', 'reason'], 'ActivateInstalledAuthorityResultV1');
      return {
        kind: 'integrity_error',
        reason: parseLinkIntegrityFailureV1(record.reason),
      };
    default:
      throw new Error('ActivateInstalledAuthorityResultV1.kind is invalid');
  }
}

function parseActivationRetryReasonV1(raw: unknown): ActivationRetryReasonV1 {
  const record = requireRecord(raw, 'ActivationRetryReasonV1');
  switch (record.kind) {
    case 'installation_receipt_not_found':
    case 'server_worker_activation_pending':
    case 'wallet_session_issuance_pending':
      rejectUnknownFields(record, ['kind'], 'ActivationRetryReasonV1');
      return { kind: record.kind };
    default:
      throw new Error('ActivationRetryReasonV1.kind is invalid');
  }
}

function parseLinkIntegrityFailureV1(raw: unknown): LinkIntegrityFailureV1 {
  const record = requireRecord(raw, 'LinkIntegrityFailureV1');
  switch (record.kind) {
    case 'authority_id_mismatch':
      rejectUnknownFields(
        record,
        ['kind', 'expectedAuthorityId', 'actualAuthorityId'],
        'LinkIntegrityFailureV1',
      );
      return {
        kind: 'authority_id_mismatch',
        expectedAuthorityId: parseId(
          parseWalletAuthorityId,
          record.expectedAuthorityId,
          'expectedAuthorityId',
        ),
        actualAuthorityId: parseId(
          parseWalletAuthorityId,
          record.actualAuthorityId,
          'actualAuthorityId',
        ),
      };
    case 'package_set_digest_mismatch':
      rejectUnknownFields(
        record,
        ['kind', 'expectedPackageSetDigestB64u', 'actualPackageSetDigestB64u'],
        'LinkIntegrityFailureV1',
      );
      return {
        kind: 'package_set_digest_mismatch',
        expectedPackageSetDigestB64u: parseDigest(
          record.expectedPackageSetDigestB64u,
          'expectedPackageSetDigestB64u',
        ),
        actualPackageSetDigestB64u: parseDigest(
          record.actualPackageSetDigestB64u,
          'actualPackageSetDigestB64u',
        ),
      };
    case 'installation_receipt_mismatch':
      rejectUnknownFields(record, ['kind', 'field'], 'LinkIntegrityFailureV1');
      if (
        record.field !== 'walletId' &&
        record.field !== 'authMethodId' &&
        record.field !== 'deviceId' &&
        record.field !== 'targetFactorVerificationDigestB64u' &&
        record.field !== 'installedActivationRefs'
      ) {
        throw new Error('LinkIntegrityFailureV1.field is invalid');
      }
      return { kind: 'installation_receipt_mismatch', field: record.field };
    default:
      throw new Error('LinkIntegrityFailureV1.kind is invalid');
  }
}
