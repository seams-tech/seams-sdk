import type {
  KeyMaterialPayloadEnvelope,
  KeyMaterialPayloadEnvelopeAAD,
  KeyMaterialRecord,
} from '../accountKeyMaterialDB.types';
import { toTrimmedString } from '@shared/utils/validation';

export const KEY_PAYLOAD_ENC_VERSION = 1;

function asRecord(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  return value as Record<string, unknown>;
}

export function sanitizePayload(value: unknown): Record<string, unknown> | undefined {
  const record = asRecord(value);
  if (!record) return undefined;
  return { ...record };
}

export function buildEnvelopeAAD(args: {
  profileId: string;
  deviceNumber: number;
  chainIdKey: string;
  keyKind: string;
  schemaVersion: number;
  signerId?: string;
}): KeyMaterialPayloadEnvelopeAAD {
  const signerId = toTrimmedString(args.signerId || '');
  return {
    profileId: toTrimmedString(args.profileId || ''),
    deviceNumber: args.deviceNumber,
    chainIdKey: toTrimmedString(args.chainIdKey || '').toLowerCase(),
    keyKind: toTrimmedString(args.keyKind || ''),
    schemaVersion: args.schemaVersion,
    ...(signerId ? { signerId } : {}),
  };
}

function normalizeEnvelopeAAD(
  raw: unknown,
  expected: KeyMaterialPayloadEnvelopeAAD,
  context: string,
): KeyMaterialPayloadEnvelopeAAD {
  const record = asRecord(raw);
  const profileId = String(record?.profileId ?? expected.profileId).trim();
  const chainIdKey = String(record?.chainIdKey ?? expected.chainIdKey)
    .trim()
    .toLowerCase();
  const keyKind = String(record?.keyKind ?? expected.keyKind).trim();
  const schemaVersionRaw = Number(record?.schemaVersion ?? expected.schemaVersion);
  const schemaVersion =
    Number.isSafeInteger(schemaVersionRaw) && schemaVersionRaw >= 1
      ? schemaVersionRaw
      : expected.schemaVersion;
  const deviceNumberRaw = Number(record?.deviceNumber ?? expected.deviceNumber);
  const deviceNumber =
    Number.isSafeInteger(deviceNumberRaw) && deviceNumberRaw >= 1
      ? deviceNumberRaw
      : expected.deviceNumber;
  const signerId = String(record?.signerId ?? expected.signerId ?? '').trim();
  const accountAddress = toTrimmedString(record?.accountAddress || '').toLowerCase();
  const normalized: KeyMaterialPayloadEnvelopeAAD = {
    profileId,
    deviceNumber,
    chainIdKey,
    keyKind,
    schemaVersion,
    ...(signerId ? { signerId } : {}),
    ...(accountAddress ? { accountAddress } : {}),
  };

  const matchesExpected =
    normalized.profileId === expected.profileId &&
    normalized.deviceNumber === expected.deviceNumber &&
    normalized.chainIdKey === expected.chainIdKey &&
    normalized.keyKind === expected.keyKind &&
    normalized.schemaVersion === expected.schemaVersion &&
    (!expected.signerId || normalized.signerId === expected.signerId);
  if (!matchesExpected) {
    throw new Error(`PasskeyAccountKeyMaterialDB: payloadEnvelope.aad mismatch for ${context}`);
  }

  return normalized;
}

export function normalizePayloadEnvelope(
  raw: unknown,
  expectedAAD: KeyMaterialPayloadEnvelopeAAD,
  context: string,
): KeyMaterialPayloadEnvelope | undefined {
  if (raw == null) return undefined;
  const record = asRecord(raw);
  if (!record) {
    throw new Error(`PasskeyAccountKeyMaterialDB: Invalid payloadEnvelope object for ${context}`);
  }
  const encVersionRaw = Number(record.encVersion);
  const encVersion =
    Number.isSafeInteger(encVersionRaw) && encVersionRaw >= 1 ? encVersionRaw : NaN;
  const alg = toTrimmedString(record.alg || '');
  const nonce = toTrimmedString(record.nonce || '');
  const ciphertext = toTrimmedString(record.ciphertext || '');
  const tag = toTrimmedString(record.tag || '');
  if (!Number.isFinite(encVersion)) {
    throw new Error(`PasskeyAccountKeyMaterialDB: Invalid payloadEnvelope.encVersion for ${context}`);
  }
  if (!alg || !nonce || !ciphertext) {
    throw new Error(
      `PasskeyAccountKeyMaterialDB: Missing payloadEnvelope cryptographic fields for ${context}`,
    );
  }
  return {
    encVersion,
    alg,
    nonce,
    ciphertext,
    ...(tag ? { tag } : {}),
    aad: normalizeEnvelopeAAD(record.aad, expectedAAD, context),
  };
}

export function normalizeStoredPayloadRecord(
  rec: KeyMaterialRecord,
): KeyMaterialRecord | null {
  const profileId = toTrimmedString(rec.profileId || '');
  const chainIdKey = toTrimmedString(rec.chainIdKey || '').toLowerCase();
  const keyKind = toTrimmedString(rec.keyKind || '');
  const algorithm = toTrimmedString(rec.algorithm || '');
  const publicKey = toTrimmedString(rec.publicKey || '');
  const signerId = toTrimmedString(rec.signerId || '');
  const wrapKeySalt = toTrimmedString(rec.wrapKeySalt || '');
  if (!profileId || !chainIdKey || !keyKind || !algorithm || !publicKey) return null;
  if (!Number.isSafeInteger(rec.deviceNumber) || rec.deviceNumber < 1) return null;
  if (typeof rec.timestamp !== 'number') return null;
  if (!Number.isSafeInteger(rec.schemaVersion) || rec.schemaVersion < 1) return null;

  const payload = sanitizePayload(rec.payload);
  const expectedAAD = buildEnvelopeAAD({
    profileId,
    deviceNumber: rec.deviceNumber,
    chainIdKey,
    keyKind,
    schemaVersion: rec.schemaVersion,
    ...(signerId ? { signerId } : {}),
  });
  const payloadEnvelope = normalizePayloadEnvelope(
    rec.payloadEnvelope,
    expectedAAD,
    `${profileId}/${rec.deviceNumber}/${chainIdKey}/${keyKind}`,
  );

  return {
    ...rec,
    profileId,
    chainIdKey,
    keyKind,
    algorithm,
    publicKey,
    ...(signerId ? { signerId } : {}),
    ...(wrapKeySalt ? { wrapKeySalt } : {}),
    ...(payload ? { payload } : {}),
    ...(payloadEnvelope ? { payloadEnvelope } : {}),
  };
}
