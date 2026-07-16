import { parseWebAuthnRpId, type WebAuthnRpId } from '@shared/utils/domainIds';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  parseWebAuthnAuthenticatorDeviceInfo,
  unknownWebAuthnAuthenticatorDeviceInfo,
  type WebAuthnAuthenticatorDeviceInfo,
} from '@shared/utils/webauthnDeviceInfo';
import {
  nonNegativeSafeInteger,
  optionalNonNegativeInteger,
  positiveInteger,
  toRecordValue,
} from './d1RouterApiAuthBoundary';

export type D1AuthenticatorRow = {
  readonly credential_id_b64u?: unknown;
  readonly credential_public_key_b64u?: unknown;
  readonly counter?: unknown;
  readonly created_at_ms?: unknown;
  readonly updated_at_ms?: unknown;
  readonly device_info_json?: unknown;
};

export type D1RecordJsonRow = {
  readonly record_json?: unknown;
};

export type WebAuthnCredentialBindingRecord = {
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly userId: string;
  readonly nearAccountId?: string;
  readonly nearEd25519SigningKeyId?: string;
  readonly signerSlot: number;
  readonly publicKey?: string;
  readonly relayerKeyId?: string;
  readonly keyVersion?: string;
  readonly recoveryExportCapable?: boolean;
  readonly clientParticipantId?: number;
  readonly relayerParticipantId?: number;
  readonly participantIds?: number[];
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

export type WebAuthnSyncWalletBinding = {
  readonly walletId: string;
  readonly nearAccountId: string;
  readonly nearEd25519SigningKeyId: string;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly signerSlot: number;
};

export type NearPublicKeyAuthBinding = {
  readonly kind: 'passkey';
  readonly rpId: WebAuthnRpId;
  readonly credentialIdB64u: string;
};

export type NearPublicKeyRecord = {
  readonly publicKey: string;
  readonly kind: 'threshold' | 'local' | 'backup' | 'ephemeral';
  readonly signerSlot?: number;
  readonly authBinding?: NearPublicKeyAuthBinding;
  readonly credentialIdB64u?: never;
  readonly rpId?: never;
  readonly createdAtMs?: number;
  readonly updatedAtMs?: number;
};

export type WebAuthnAuthenticatorRecord = {
  readonly credentialIdB64u: string;
  readonly credentialPublicKeyB64u: string;
  readonly counter: number;
  readonly createdAtMs: number;
  readonly updatedAtMs: number;
  readonly deviceInfo: WebAuthnAuthenticatorDeviceInfo;
};

export function parseWebAuthnAuthenticatorRowDeviceInfo(
  raw: unknown,
): WebAuthnAuthenticatorDeviceInfo {
  if (typeof raw !== 'string' || !raw.trim()) return unknownWebAuthnAuthenticatorDeviceInfo();
  try {
    return (
      parseWebAuthnAuthenticatorDeviceInfo(JSON.parse(raw)) ??
      unknownWebAuthnAuthenticatorDeviceInfo()
    );
  } catch {
    return unknownWebAuthnAuthenticatorDeviceInfo();
  }
}

export type WebAuthnLoginChallengeRecord = {
  readonly version: 'webauthn_login_challenge_v1';
  readonly challengeId: string;
  readonly userId: string;
  readonly rpId: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export type WebAuthnSyncChallengeRecord = {
  readonly version: 'webauthn_sync_challenge_v1';
  readonly challengeId: string;
  readonly rpId: string;
  readonly expectedUserId?: string;
  readonly challengeB64u: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
};

export function parseWebAuthnLoginChallengeRecord(
  input: unknown,
): WebAuthnLoginChallengeRecord | null {
  const record = parseJsonRecord(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const userId = toOptionalTrimmedString(record.userId);
  const rpId = toOptionalTrimmedString(record.rpId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveInteger(record.createdAtMs);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (version !== 'webauthn_login_challenge_v1') return null;
  if (!challengeId || !userId || !rpId || !challengeB64u) return null;
  if (createdAtMs === null || expiresAtMs === null) return null;
  return {
    version: 'webauthn_login_challenge_v1',
    challengeId,
    userId,
    rpId,
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

export function parseWebAuthnSyncChallengeRecord(
  input: unknown,
): WebAuthnSyncChallengeRecord | null {
  const record = parseJsonRecord(input);
  if (!record) return null;
  const version = toOptionalTrimmedString(record.version);
  const challengeId = toOptionalTrimmedString(record.challengeId);
  const rpId = toOptionalTrimmedString(record.rpId);
  const expectedUserId = toOptionalTrimmedString(record.expectedUserId);
  const challengeB64u = toOptionalTrimmedString(record.challengeB64u);
  const createdAtMs = positiveInteger(record.createdAtMs);
  const expiresAtMs = positiveInteger(record.expiresAtMs);
  if (version !== 'webauthn_sync_challenge_v1') return null;
  if (!challengeId || !rpId || !challengeB64u) return null;
  if (createdAtMs === null || expiresAtMs === null) return null;
  return {
    version: 'webauthn_sync_challenge_v1',
    challengeId,
    rpId,
    ...(expectedUserId ? { expectedUserId } : {}),
    challengeB64u,
    createdAtMs,
    expiresAtMs,
  };
}

export function parseWebAuthnAuthenticator(
  row: D1AuthenticatorRow | null,
): WebAuthnAuthenticatorRecord | null {
  const credentialIdB64u = toOptionalTrimmedString(row?.credential_id_b64u);
  const credentialPublicKeyB64u = toOptionalTrimmedString(row?.credential_public_key_b64u);
  const counter = nonNegativeSafeInteger(row?.counter);
  const createdAtMs = positiveInteger(row?.created_at_ms);
  const updatedAtMs = positiveInteger(row?.updated_at_ms);
  if (!credentialIdB64u || !credentialPublicKeyB64u) return null;
  if (counter === null || createdAtMs === null || updatedAtMs === null) return null;
  return {
    credentialIdB64u,
    credentialPublicKeyB64u,
    counter,
    createdAtMs,
    updatedAtMs,
    deviceInfo: parseWebAuthnAuthenticatorRowDeviceInfo(row?.device_info_json),
  };
}

export function parseWebAuthnBinding(
  row: D1RecordJsonRow,
): WebAuthnCredentialBindingRecord | null {
  const record = parseJsonRecord(row.record_json);
  if (!record) return null;
  const rpId = toOptionalTrimmedString(record.rpId);
  const credentialIdB64u = toOptionalTrimmedString(record.credentialIdB64u);
  const userId = toOptionalTrimmedString(record.userId);
  const signerSlot = positiveInteger(record.signerSlot);
  if (!rpId || !credentialIdB64u || !userId || signerSlot === null) return null;
  const nearAccountId = toOptionalTrimmedString(record.nearAccountId);
  const nearEd25519SigningKeyId = toOptionalTrimmedString(record.nearEd25519SigningKeyId);
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
  const keyVersion = toOptionalTrimmedString(record.keyVersion);
  const clientParticipantId = optionalNonNegativeInteger(record.clientParticipantId);
  const relayerParticipantId = optionalNonNegativeInteger(record.relayerParticipantId);
  const participantIds = optionalNumberArray(record.participantIds);
  const createdAtMs = optionalNonNegativeInteger(record.createdAtMs);
  const updatedAtMs = optionalNonNegativeInteger(record.updatedAtMs);
  return {
    rpId,
    credentialIdB64u,
    userId,
    signerSlot,
    ...(nearAccountId ? { nearAccountId } : {}),
    ...(nearEd25519SigningKeyId ? { nearEd25519SigningKeyId } : {}),
    ...(publicKey ? { publicKey } : {}),
    ...(relayerKeyId ? { relayerKeyId } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(typeof record.recoveryExportCapable === 'boolean'
      ? { recoveryExportCapable: record.recoveryExportCapable }
      : {}),
    ...(clientParticipantId !== undefined ? { clientParticipantId } : {}),
    ...(relayerParticipantId !== undefined ? { relayerParticipantId } : {}),
    ...(participantIds ? { participantIds } : {}),
    ...(createdAtMs !== undefined ? { createdAtMs } : {}),
    ...(updatedAtMs !== undefined ? { updatedAtMs } : {}),
  };
}

export function webAuthnSyncWalletBindingFromCredentialBinding(
  binding: WebAuthnCredentialBindingRecord,
): WebAuthnSyncWalletBinding | null {
  if (!binding.nearAccountId || !binding.nearEd25519SigningKeyId) return null;
  return {
    walletId: binding.userId,
    nearAccountId: binding.nearAccountId,
    nearEd25519SigningKeyId: binding.nearEd25519SigningKeyId,
    rpId: binding.rpId,
    credentialIdB64u: binding.credentialIdB64u,
    signerSlot: binding.signerSlot,
  };
}

export function parseNearPublicKey(row: D1RecordJsonRow): NearPublicKeyRecord | null {
  const record = parseJsonRecord(row.record_json);
  if (!record) return null;
  const publicKey = toOptionalTrimmedString(record.publicKey);
  const kindRaw = toOptionalTrimmedString(record.kind);
  const kind = parseNearPublicKeyKind(kindRaw);
  const authBinding = parseNearPublicKeyAuthBinding(record);
  if (authBinding === null) return null;
  if (!publicKey || !kind) return null;
  return {
    publicKey,
    kind,
    signerSlot: optionalNonNegativeInteger(record.signerSlot),
    ...(authBinding ? { authBinding } : {}),
    createdAtMs: optionalNonNegativeInteger(record.createdAtMs),
    updatedAtMs: optionalNonNegativeInteger(record.updatedAtMs),
  };
}

function parseJsonRecord(input: unknown): Record<string, unknown> | null {
  if (typeof input === 'string') {
    try {
      return toRecordValue(JSON.parse(input));
    } catch {
      return null;
    }
  }
  return toRecordValue(input);
}

function optionalNumberArray(input: unknown): number[] | undefined {
  if (!Array.isArray(input)) return undefined;
  const values: number[] = [];
  for (const item of input) {
    const value = nonNegativeSafeInteger(item);
    if (value === null) return undefined;
    values.push(value);
  }
  return values;
}

function parseNearPublicKeyKind(input: string | undefined): NearPublicKeyRecord['kind'] | null {
  switch (input) {
    case 'threshold':
    case 'local':
    case 'backup':
    case 'ephemeral':
      return input;
    default:
      return null;
  }
}

function parseNearPublicKeyAuthBinding(
  record: Record<string, unknown>,
): NearPublicKeyAuthBinding | undefined | null {
  if (
    Object.prototype.hasOwnProperty.call(record, 'rpId') ||
    Object.prototype.hasOwnProperty.call(record, 'credentialIdB64u')
  ) {
    return null;
  }
  if (record.authBinding === undefined) return undefined;
  const authBinding = toRecordValue(record.authBinding);
  if (!authBinding) return null;
  const kind = toOptionalTrimmedString(authBinding.kind);
  const rpId = parseWebAuthnRpId(authBinding.rpId);
  const credentialIdB64u = toOptionalTrimmedString(authBinding.credentialIdB64u);
  if (kind !== 'passkey' || !rpId.ok || !credentialIdB64u) return null;
  return { kind: 'passkey', rpId: rpId.value, credentialIdB64u };
}
