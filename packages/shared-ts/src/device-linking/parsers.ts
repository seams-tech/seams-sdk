import {
  parseAuthorizationEvidenceSetId,
  parseWalletSessionAuthorizationId,
  parseWalletSessionId,
  type AuthorizationEvidenceSetId,
  type WalletSessionAuthorizationId,
  type WalletSessionId,
} from '../authorization/capabilityKinds';
import {
  parseLaneHolderParticipantId,
  parseSigningWorkerParticipantId,
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
  parseMpcMaterialActivationRef,
  parseWalletId,
  parseWebAuthnCredentialIdB64u,
  type MpcMaterialActivationRef,
  type WalletId,
  type WebAuthnCredentialIdB64u,
} from '../utils/domainIds';
import { parseDigestB64u, type DigestB64u } from '../utils/canonicalPrimitives';
import { base64UrlDecode, base64UrlEncode } from '../utils/base64';
import { parseUnixMs, requireRecord, rejectUnknownFields } from '../passkey-custody/primitives';
import {
  assertNeverLinkedDeviceSessionState,
  type LinkedDeviceApprovalV1,
  type LinkedDeviceEnrollmentChildReceiptV1,
  type LinkedDeviceEnrollmentKeyBindingV1,
  type LinkedDeviceEnrollmentReceiptV1,
  type LinkedDeviceEnrollmentTranscriptV1,
  type LinkedDeviceListRequestV1,
  type LinkedDeviceListResultV1,
  type LinkedDeviceRevokeRequestV1,
  type LinkedDeviceRevokeResultV1,
  type LinkedDeviceSummaryV1,
  type LinkedDeviceOwnerAuthorizationSourceV1,
  type LinkedDeviceProtocolVersionV1,
  type LinkedDeviceReceiptAcknowledgementV1,
  type LinkedDeviceSessionClaimRequestV1,
  type LinkedDeviceSessionClaimV1,
  type LinkedDeviceSessionState,
  type LinkedDeviceSessionTransportEventV1,
  type LinkedDeviceSessionTransportRequestV1,
  type LinkedDeviceTargetCredentialRegistrationV1,
  type LinkDevicePublicKeyB64u,
  type QrLinkedDevicePermissionRequest,
  type QrLinkedDeviceSessionPayloadV4,
} from './contracts';

type UnknownRecord = Record<string, unknown>;

const QR_FIELDS = [
  'version',
  'purpose',
  'linkSessionId',
  'linkPublicKeyB64u',
  'devicePublicKeyB64u',
  'requestedPermission',
  'issuedAtMs',
  'expiresAtMs',
] as const;
const PERMISSION_FIELDS = ['kind', 'administrationScope', 'localUserPresence'] as const;
const CLAIM_REQUEST_FIELDS = ['kind', 'payload'] as const;
const CLAIM_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'devicePublicKeyB64u',
  'claimedAtMs',
  'claimExpiresAtMs',
] as const;
const OWNER_AUTH_WALLET_SESSION_FIELDS = ['kind', 'walletSessionId', 'authorizationId'] as const;
const OWNER_AUTH_STEP_UP_FIELDS = ['kind', 'evidenceSetId'] as const;
const KEY_BINDING_FIELDS = [
  'walletKeyId',
  'keyFamily',
  'sourceLaneId',
  'sourceLaneShareEpoch',
  'sourceRevocationEpoch',
  'sourceHolderParticipantId',
  'sourceSigningWorkerParticipantId',
  'targetLaneId',
  'targetLaneShareEpoch',
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
  'ownerAuthorization',
  'policyDigestB64u',
  'operationId',
  'idempotencyKey',
  'orderedKeyBindings',
  'protocolVersions',
  'approvedAtMs',
  'expiresAtMs',
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
  'manifestDigestB64u',
  'aggregateReceiptDigestB64u',
  'orderedChildReceipts',
  'activatedAtMs',
] as const;
const CREDENTIAL_FIELDS = [
  'kind',
  'linkSessionId',
  'walletId',
  'enrollmentId',
  'deviceId',
  'credentialIdB64u',
  'registeredAtMs',
] as const;
const RECEIPT_ACK_FIELDS = [
  'kind',
  'linkSessionId',
  'enrollmentId',
  'deviceId',
  'receipt',
  'acknowledgedAtMs',
] as const;
const LINKED_DEVICE_SUMMARY_FIELDS = [
  'deviceId',
  'enrollmentId',
  'walletId',
  'label',
  'platform',
  'permission',
  'keyManifestDigestB64u',
  'coveredWalletKeys',
  'state',
  'createdAtMs',
  'lastActivityAtMs',
  'revocationEpoch',
] as const;
const LINKED_DEVICE_LIST_REQUEST_FIELDS = ['kind', 'walletId'] as const;
const LINKED_DEVICE_LIST_RESULT_FIELDS = ['devices'] as const;
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
  awaiting_target_passkey: [
    'state',
    'linkSessionId',
    'walletId',
    'enrollmentId',
    'credentialDeadlineMs',
  ],
  provisioning: ['state', 'linkSessionId', 'walletId', 'enrollmentId', 'keyManifestDigestB64u'],
  awaiting_aggregate_receipt: [
    'state',
    'linkSessionId',
    'walletId',
    'enrollmentId',
    'keyManifestDigestB64u',
  ],
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
    'transcriptSetDigestB64u',
  ],
} as const;

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
    if (decoded.length === 0 || base64UrlEncode(decoded) !== raw) throw new Error('non-canonical');
  } catch {
    throw new Error(`${label} must be canonical unpadded base64url`);
  }
  return raw as LinkDevicePublicKeyB64u;
}

function parseCredential(raw: unknown, label: string): WebAuthnCredentialIdB64u {
  const value = parseNonEmptyToken(raw, label);
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be canonical unpadded base64url`);
  }
  try {
    const bytes = base64UrlDecode(value);
    if (bytes.length === 0 || base64UrlEncode(bytes) !== value) throw new Error('non-canonical');
  } catch {
    throw new Error(`${label} must be canonical unpadded base64url`);
  }
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
  if (
    typeof record.label !== 'string' ||
    record.label.length === 0 ||
    record.label.trim() !== record.label
  ) {
    throw new Error('LinkedDeviceSummaryV1.label is invalid');
  }
  if (
    typeof record.platform !== 'string' ||
    record.platform.trim() !== record.platform ||
    record.platform.length === 0
  ) {
    throw new Error('LinkedDeviceSummaryV1.platform is invalid');
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
    label: record.label,
    platform: record.platform,
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
  };
}

export function buildLinkedDeviceListRequestV1(args: {
  readonly walletId: WalletId;
}): LinkedDeviceListRequestV1 {
  return {
    kind: 'linked_device_list_request_v1',
    walletId: parseWallet(args.walletId, 'LinkedDeviceListRequestV1.walletId'),
  };
}

export function parseLinkedDeviceListResultV1(raw: unknown): LinkedDeviceListResultV1 {
  const record = exactRecord(raw, LINKED_DEVICE_LIST_RESULT_FIELDS, 'LinkedDeviceListResultV1');
  if (!Array.isArray(record.devices))
    throw new Error('LinkedDeviceListResultV1.devices is invalid');
  return { devices: record.devices.map(parseLinkedDeviceSummaryV1) };
}

export function buildLinkedDeviceListResultV1(args: {
  readonly devices: readonly LinkedDeviceSummaryV1[];
}): LinkedDeviceListResultV1 {
  return parseLinkedDeviceListResultV1({ devices: args.devices });
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

function parseQrPayloadRecord(record: UnknownRecord): QrLinkedDeviceSessionPayloadV4 {
  if (record.version !== 'v4') throw new Error('QrLinkedDeviceSessionPayloadV4.version is invalid');
  if (record.purpose !== 'linked_device_lane_creation') {
    throw new Error('QrLinkedDeviceSessionPayloadV4.purpose is invalid');
  }
  const issuedAtMs = parseUnixTime(record.issuedAtMs, 'QrLinkedDeviceSessionPayloadV4.issuedAtMs');
  const expiresAtMs = parseUnixTime(
    record.expiresAtMs,
    'QrLinkedDeviceSessionPayloadV4.expiresAtMs',
  );
  assertExpiryAfterIssued(issuedAtMs, expiresAtMs, 'QrLinkedDeviceSessionPayloadV4');
  return {
    version: 'v4',
    purpose: 'linked_device_lane_creation',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'QrLinkedDeviceSessionPayloadV4.linkSessionId',
    ),
    linkPublicKeyB64u: parsePublicKey(
      record.linkPublicKeyB64u,
      'QrLinkedDeviceSessionPayloadV4.linkPublicKeyB64u',
    ),
    devicePublicKeyB64u: parsePublicKey(
      record.devicePublicKeyB64u,
      'QrLinkedDeviceSessionPayloadV4.devicePublicKeyB64u',
    ),
    requestedPermission: parsePermission(record.requestedPermission),
    issuedAtMs,
    expiresAtMs,
  };
}

export function parseQrLinkedDeviceSessionPayloadV4(raw: unknown): QrLinkedDeviceSessionPayloadV4 {
  return parseQrPayloadRecord(exactRecord(raw, QR_FIELDS, 'QrLinkedDeviceSessionPayloadV4'));
}

function parseStateRecord(record: UnknownRecord): LinkedDeviceSessionState {
  if (typeof record.state !== 'string' || !(record.state in SESSION_STATE_FIELDS)) {
    throw new Error('LinkedDeviceSessionState.state is unsupported');
  }
  const state = record.state as keyof typeof SESSION_STATE_FIELDS;
  const exact = exactRecord(
    record,
    SESSION_STATE_FIELDS[state],
    `LinkedDeviceSessionState.${state}`,
  );
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
    case 'awaiting_target_passkey':
      return {
        state,
        linkSessionId,
        walletId: parseWallet(exact.walletId, `${state}.walletId`),
        enrollmentId: parseEnrollmentId(exact.enrollmentId, `${state}.enrollmentId`),
        credentialDeadlineMs: parseUnixTime(
          exact.credentialDeadlineMs,
          `${state}.credentialDeadlineMs`,
        ),
      };
    case 'provisioning':
    case 'awaiting_aggregate_receipt':
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

export function parseLinkedDeviceSessionClaimRequestV1(
  raw: unknown,
): LinkedDeviceSessionClaimRequestV1 {
  const record = exactRecord(raw, CLAIM_REQUEST_FIELDS, 'LinkedDeviceSessionClaimRequestV1');
  if (record.kind !== 'linked_device_session_claim_request_v1') {
    throw new Error('LinkedDeviceSessionClaimRequestV1.kind is invalid');
  }
  return {
    kind: 'linked_device_session_claim_request_v1',
    payload: parseQrLinkedDeviceSessionPayloadV4(record.payload),
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
    claimedAtMs,
    claimExpiresAtMs,
  };
}

function parseOwnerAuthorization(
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

function parseKeyBinding(raw: unknown, label: string): LinkedDeviceEnrollmentKeyBindingV1 {
  const record = exactRecord(raw, KEY_BINDING_FIELDS, label);
  return {
    walletKeyId: parseWalletKey(record.walletKeyId, `${label}.walletKeyId`),
    keyFamily: parseKeyFamily(record.keyFamily, `${label}.keyFamily`),
    sourceLaneId: parseLaneId(record.sourceLaneId, `${label}.sourceLaneId`),
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
  const values = raw.map((entry, index) => parseKeyBinding(entry, `${label}[${index}]`));
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

function parseProtocolVersion(raw: unknown, label: string): LinkedDeviceProtocolVersionV1 {
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
  const values = raw.map((entry, index) => parseProtocolVersion(entry, `${label}[${index}]`));
  const families = new Set<string>();
  for (const value of values) {
    if (families.has(value.keyFamily)) throw new Error(`${label} contains duplicate keyFamily`);
    families.add(value.keyFamily);
  }
  return nonEmptyTuple(values, label);
}

type EnrollmentCore = Omit<LinkedDeviceApprovalV1, 'kind'>;

function parseEnrollmentCore(record: UnknownRecord, label: string): EnrollmentCore {
  const approvedAtMs = parseUnixTime(record.approvedAtMs, `${label}.approvedAtMs`);
  const expiresAtMs = parseUnixTime(record.expiresAtMs, `${label}.expiresAtMs`);
  assertExpiryAfterIssued(approvedAtMs, expiresAtMs, label);
  return {
    linkSessionId: parseSessionId(record.linkSessionId, `${label}.linkSessionId`),
    walletId: parseWallet(record.walletId, `${label}.walletId`),
    enrollmentId: parseEnrollmentId(record.enrollmentId, `${label}.enrollmentId`),
    deviceId: parseDeviceId(record.deviceId, `${label}.deviceId`),
    linkPublicKeyB64u: parsePublicKey(record.linkPublicKeyB64u, `${label}.linkPublicKeyB64u`),
    devicePublicKeyB64u: parsePublicKey(record.devicePublicKeyB64u, `${label}.devicePublicKeyB64u`),
    permission: parsePermission(record.permission, `${label}.permission`),
    ownerAuthorization: parseOwnerAuthorization(
      record.ownerAuthorization,
      `${label}.ownerAuthorization`,
    ),
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
  return {
    kind: 'linked_device_approval_v1',
    ...parseEnrollmentCore(record, 'LinkedDeviceApprovalV1'),
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

export function parseLinkedDeviceTargetCredentialRegistrationV1(
  raw: unknown,
): LinkedDeviceTargetCredentialRegistrationV1 {
  const record = exactRecord(raw, CREDENTIAL_FIELDS, 'LinkedDeviceTargetCredentialRegistrationV1');
  if (record.kind !== 'linked_device_target_credential_registration_v1') {
    throw new Error('LinkedDeviceTargetCredentialRegistrationV1.kind is invalid');
  }
  return {
    kind: 'linked_device_target_credential_registration_v1',
    linkSessionId: parseSessionId(
      record.linkSessionId,
      'LinkedDeviceTargetCredentialRegistrationV1.linkSessionId',
    ),
    walletId: parseWallet(record.walletId, 'LinkedDeviceTargetCredentialRegistrationV1.walletId'),
    enrollmentId: parseEnrollmentId(
      record.enrollmentId,
      'LinkedDeviceTargetCredentialRegistrationV1.enrollmentId',
    ),
    deviceId: parseDeviceId(record.deviceId, 'LinkedDeviceTargetCredentialRegistrationV1.deviceId'),
    credentialIdB64u: parseCredential(
      record.credentialIdB64u,
      'LinkedDeviceTargetCredentialRegistrationV1.credentialIdB64u',
    ),
    registeredAtMs: parseUnixTime(
      record.registeredAtMs,
      'LinkedDeviceTargetCredentialRegistrationV1.registeredAtMs',
    ),
  };
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
    receipt: parseLinkedDeviceEnrollmentChildReceiptV1(record.receipt),
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

export function buildQrLinkedDeviceSessionPayloadV4(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly linkPublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly devicePublicKeyB64u: LinkDevicePublicKeyB64u;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
}): QrLinkedDeviceSessionPayloadV4 {
  const issuedAtMs = parseUnixTime(args.issuedAtMs, 'QrLinkedDeviceSessionPayloadV4.issuedAtMs');
  const expiresAtMs = parseUnixTime(args.expiresAtMs, 'QrLinkedDeviceSessionPayloadV4.expiresAtMs');
  assertExpiryAfterIssued(issuedAtMs, expiresAtMs, 'QrLinkedDeviceSessionPayloadV4');
  return {
    version: 'v4',
    purpose: 'linked_device_lane_creation',
    linkSessionId: args.linkSessionId,
    linkPublicKeyB64u: args.linkPublicKeyB64u,
    devicePublicKeyB64u: args.devicePublicKeyB64u,
    requestedPermission: buildQrLinkedDevicePermissionRequest(),
    issuedAtMs,
    expiresAtMs,
  };
}

export function buildLinkedDeviceSessionClaimRequestV1(
  payload: QrLinkedDeviceSessionPayloadV4,
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
  return { kind: 'linked_device_approval_v1', ...args, ...times };
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

export function buildLinkedDeviceTargetCredentialRegistrationV1(
  args: Omit<LinkedDeviceTargetCredentialRegistrationV1, 'kind'>,
): LinkedDeviceTargetCredentialRegistrationV1 {
  return {
    kind: 'linked_device_target_credential_registration_v1',
    ...args,
    registeredAtMs: parseUnixTime(
      args.registeredAtMs,
      'LinkedDeviceTargetCredentialRegistrationV1.registeredAtMs',
    ),
  };
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

export function buildAwaitingTargetPasskeyLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly credentialDeadlineMs: number;
}): Extract<LinkedDeviceSessionState, { readonly state: 'awaiting_target_passkey' }> {
  return buildState({
    state: 'awaiting_target_passkey',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    credentialDeadlineMs: parseUnixTime(
      args.credentialDeadlineMs,
      'awaiting_target_passkey.credentialDeadlineMs',
    ),
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

export function buildAwaitingAggregateReceiptLinkedDeviceSessionState(args: {
  readonly linkSessionId: LinkDeviceSessionId;
  readonly walletId: WalletId;
  readonly enrollmentId: LinkedDeviceEnrollmentId;
  readonly keyManifestDigestB64u: DigestB64u;
}): Extract<LinkedDeviceSessionState, { readonly state: 'awaiting_aggregate_receipt' }> {
  return buildState({
    state: 'awaiting_aggregate_receipt',
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
  readonly transcriptSetDigestB64u: DigestB64u;
}): Extract<LinkedDeviceSessionState, { readonly state: 'committed_completion_required' }> {
  return buildState({
    state: 'committed_completion_required',
    linkSessionId: args.linkSessionId,
    walletId: args.walletId,
    enrollmentId: args.enrollmentId,
    transcriptSetDigestB64u: args.transcriptSetDigestB64u,
  });
}
