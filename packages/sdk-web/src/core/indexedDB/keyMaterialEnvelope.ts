import type {
  KeyMaterialPayloadEnvelope,
  KeyMaterialPayloadEnvelopeAAD,
  KeyMaterialRecord,
} from './keyMaterial.types';
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
  signerSlot: number;
  chainIdKey: string;
  accountAddress: string;
  keyKind: string;
  schemaVersion: number;
  signerId: string;
}): KeyMaterialPayloadEnvelopeAAD {
  const signerId = toTrimmedString(args.signerId || '');
  const accountAddress = toTrimmedString(args.accountAddress || '').toLowerCase();
  return {
    profileId: toTrimmedString(args.profileId || ''),
    signerSlot: args.signerSlot,
    chainIdKey: toTrimmedString(args.chainIdKey || '').toLowerCase(),
    accountAddress,
    keyKind: toTrimmedString(args.keyKind || ''),
    schemaVersion: args.schemaVersion,
    signerId,
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
  const signerSlotRaw = Number(record?.signerSlot ?? expected.signerSlot);
  const signerSlot =
    Number.isSafeInteger(signerSlotRaw) && signerSlotRaw >= 1
      ? signerSlotRaw
      : expected.signerSlot;
  const signerId = String(record?.signerId ?? expected.signerId).trim();
  const accountAddress = toTrimmedString(
    record?.accountAddress ?? expected.accountAddress,
  ).toLowerCase();
  const normalized: KeyMaterialPayloadEnvelopeAAD = {
    profileId,
    signerSlot,
    chainIdKey,
    accountAddress,
    keyKind,
    schemaVersion,
    signerId,
  };

  const matchesExpected =
    normalized.profileId === expected.profileId &&
    normalized.signerSlot === expected.signerSlot &&
    normalized.chainIdKey === expected.chainIdKey &&
    normalized.accountAddress === expected.accountAddress &&
    normalized.keyKind === expected.keyKind &&
    normalized.schemaVersion === expected.schemaVersion &&
    normalized.signerId === expected.signerId;
  if (!matchesExpected) {
    throw new Error(`KeyMaterialStore: payloadEnvelope.aad mismatch for ${context}`);
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
    throw new Error(`KeyMaterialStore: Invalid payloadEnvelope object for ${context}`);
  }
  const encVersionRaw = Number(record.encVersion);
  const encVersion =
    Number.isSafeInteger(encVersionRaw) && encVersionRaw >= 1 ? encVersionRaw : NaN;
  const alg = toTrimmedString(record.alg || '');
  const nonce = toTrimmedString(record.nonce || '');
  const ciphertext = toTrimmedString(record.ciphertext || '');
  const tag = toTrimmedString(record.tag || '');
  if (!Number.isFinite(encVersion)) {
    throw new Error(`KeyMaterialStore: Invalid payloadEnvelope.encVersion for ${context}`);
  }
  if (!alg || !nonce || !ciphertext) {
    throw new Error(
      `KeyMaterialStore: Missing payloadEnvelope cryptographic fields for ${context}`,
    );
  }
  const envelope: KeyMaterialPayloadEnvelope = {
    encVersion,
    alg,
    nonce,
    ciphertext,
    aad: normalizeEnvelopeAAD(record.aad, expectedAAD, context),
  };
  if (tag) {
    envelope.tag = tag;
  }
  return envelope;
}

export function normalizeStoredPayloadRecord(
  rec: KeyMaterialRecord,
): KeyMaterialRecord | null {
  const profileId = toTrimmedString(rec.profileId || '');
  const chainIdKey = toTrimmedString(rec.chainIdKey || '').toLowerCase();
  const accountAddress = toTrimmedString(rec.accountAddress || '').toLowerCase();
  const keyKind = toTrimmedString(rec.keyKind || '');
  const algorithm = toTrimmedString(rec.algorithm || '');
  const publicKey = toTrimmedString(rec.publicKey || '');
  const signerId = toTrimmedString(rec.signerId || '');
  const wrapKeySalt = toTrimmedString(rec.wrapKeySalt || '');
  if (!profileId || !chainIdKey || !accountAddress || !keyKind || !algorithm || !publicKey) return null;
  if (!signerId) return null;
  if (!Number.isSafeInteger(rec.signerSlot) || rec.signerSlot < 1) return null;
  if (typeof rec.timestamp !== 'number') return null;
  if (!Number.isSafeInteger(rec.schemaVersion) || rec.schemaVersion < 1) return null;

  const payload = sanitizePayload(rec.payload);
  const expectedAAD = buildEnvelopeAAD({
    profileId,
    signerSlot: rec.signerSlot,
    chainIdKey,
    accountAddress,
    keyKind,
    schemaVersion: rec.schemaVersion,
    signerId,
  });
  const payloadEnvelope = normalizePayloadEnvelope(
    rec.payloadEnvelope,
    expectedAAD,
    `${profileId}/${rec.signerSlot}/${chainIdKey}/${keyKind}`,
  );

  const normalizedRecord: KeyMaterialRecord = {
    profileId,
    signerSlot: rec.signerSlot,
    chainIdKey,
    accountAddress,
    keyKind,
    algorithm,
    publicKey,
    signerId,
    timestamp: rec.timestamp,
    schemaVersion: rec.schemaVersion,
  };
  if (wrapKeySalt) {
    normalizedRecord.wrapKeySalt = wrapKeySalt;
  }
  if (payload) {
    normalizedRecord.payload = payload;
  }
  if (payloadEnvelope) {
    normalizedRecord.payloadEnvelope = payloadEnvelope;
  }
  return normalizedRecord;
}
