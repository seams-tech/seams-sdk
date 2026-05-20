import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { base64UrlDecode } from '@shared/utils/encoders';
import {
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseEd25519AuthSessionRecord,
  parseThresholdEcdsaPresignSessionRecord,
  parseThresholdEcdsaPresignatureRelayerShareRecord,
  parseThresholdEcdsaSigningSessionRecord,
  parseThresholdEd25519KeyRecord,
  parseThresholdEd25519MpcSessionRecord,
  parseThresholdEd25519SigningSessionRecord,
} from './validation';
import {
  normalizeSigningRootSecretShareId,
  type SealedSigningRootSecretShare,
} from './signingRootSecretShareWires';

export type CurrentThresholdEd25519SessionRecord = NonNullable<
  ReturnType<typeof parseEd25519AuthSessionRecord>
>;

export type CurrentThresholdEd25519SessionStatusRow = {
  record: CurrentThresholdEd25519SessionRecord;
  expiresAtMs: number;
  remainingUses: number;
};

export type CurrentThresholdEd25519KeyRecord = NonNullable<
  ReturnType<typeof parseThresholdEd25519KeyRecord>
>;

export type CurrentThresholdEd25519MpcSessionRecord = NonNullable<
  ReturnType<typeof parseThresholdEd25519MpcSessionRecord>
>;

export type CurrentThresholdEd25519SigningSessionRecord = NonNullable<
  ReturnType<typeof parseThresholdEd25519SigningSessionRecord>
>;

export type CurrentThresholdEd25519CoordinatorSigningSessionRecord = NonNullable<
  ReturnType<typeof parseThresholdEd25519CoordinatorSigningSessionRecord>
>;

export type CurrentThresholdEd25519StoreSessionRow =
  | { kind: 'mpc'; record: CurrentThresholdEd25519MpcSessionRecord; expiresAtMs: number }
  | { kind: 'signing'; record: CurrentThresholdEd25519SigningSessionRecord; expiresAtMs: number }
  | {
      kind: 'coordinator';
      record: CurrentThresholdEd25519CoordinatorSigningSessionRecord;
      expiresAtMs: number;
    };

export type CurrentThresholdEcdsaSigningSessionRecord = NonNullable<
  ReturnType<typeof parseThresholdEcdsaSigningSessionRecord>
>;

export type CurrentThresholdEcdsaSigningSessionRow = {
  record: CurrentThresholdEcdsaSigningSessionRecord;
  expiresAtMs: number;
};

export type CurrentThresholdEcdsaPresignSessionRecord = NonNullable<
  ReturnType<typeof parseThresholdEcdsaPresignSessionRecord>
>;

export type CurrentThresholdEcdsaPresignSessionRow = {
  record: CurrentThresholdEcdsaPresignSessionRecord;
  expiresAtMs: number;
};

export type CurrentThresholdEcdsaPresignatureRecord = NonNullable<
  ReturnType<typeof parseThresholdEcdsaPresignatureRelayerShareRecord>
>;

export type CurrentSigningRootSecretShareRecord = SealedSigningRootSecretShare & {
  createdAtMs: number;
  updatedAtMs: number;
};

function toPositiveSafeInt(value: unknown): number | null {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) return null;
  return parsed;
}

function toNonNegativeSafeInt(value: unknown): number | null {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) return null;
  return parsed;
}

function hasIncreasingTimestamps(createdAtMs: number, updatedAtMs: number): boolean {
  return updatedAtMs >= createdAtMs;
}

export function parseCurrentThresholdEd25519SessionRecord(
  raw: unknown,
): CurrentThresholdEd25519SessionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const parsed = parseEd25519AuthSessionRecord(record);
  if (!parsed) return null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(record.participantIds);
  const expiresAtMs = toPositiveSafeInt(record.expiresAtMs);
  if (!participantIds || !expiresAtMs) return null;
  return {
    ...parsed,
    expiresAtMs,
    participantIds,
  };
}

export function parseCurrentThresholdEd25519KeyRecord(
  raw: unknown,
): CurrentThresholdEd25519KeyRecord | null {
  return parseThresholdEd25519KeyRecord(raw);
}

export function parseCurrentThresholdEd25519MpcSessionRecord(
  raw: unknown,
): CurrentThresholdEd25519MpcSessionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const parsed = parseThresholdEd25519MpcSessionRecord(record);
  if (!parsed) return null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(record.participantIds);
  const expiresAtMs = toPositiveSafeInt(record.expiresAtMs);
  if (!participantIds || !expiresAtMs) return null;
  return {
    ...parsed,
    participantIds,
    expiresAtMs,
  };
}

export function parseCurrentThresholdEd25519SigningSessionRecord(
  raw: unknown,
): CurrentThresholdEd25519SigningSessionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const parsed = parseThresholdEd25519SigningSessionRecord(record);
  if (!parsed) return null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(record.participantIds);
  const expiresAtMs = toPositiveSafeInt(record.expiresAtMs);
  if (!participantIds || !expiresAtMs) return null;
  return {
    ...parsed,
    participantIds,
    expiresAtMs,
  };
}

export function parseCurrentThresholdEd25519CoordinatorSigningSessionRecord(
  raw: unknown,
): CurrentThresholdEd25519CoordinatorSigningSessionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const parsed = parseThresholdEd25519CoordinatorSigningSessionRecord(record);
  if (!parsed) return null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(record.participantIds);
  const expiresAtMs = toPositiveSafeInt(record.expiresAtMs);
  if (!participantIds || !expiresAtMs) return null;
  return {
    ...parsed,
    participantIds,
    expiresAtMs,
  };
}

export function parseCurrentThresholdEd25519StoreSessionRow(input: {
  kind: 'mpc' | 'signing' | 'coordinator';
  recordJson: unknown;
  expiresAtMs: unknown;
}): CurrentThresholdEd25519StoreSessionRow | null {
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  if (!expiresAtMs) return null;
  switch (input.kind) {
    case 'mpc': {
      const record = parseCurrentThresholdEd25519MpcSessionRecord(input.recordJson);
      if (!record || record.expiresAtMs !== expiresAtMs) return null;
      return { kind: 'mpc', record, expiresAtMs };
    }
    case 'signing': {
      const record = parseCurrentThresholdEd25519SigningSessionRecord(input.recordJson);
      if (!record || record.expiresAtMs !== expiresAtMs) return null;
      return { kind: 'signing', record, expiresAtMs };
    }
    case 'coordinator': {
      const record = parseCurrentThresholdEd25519CoordinatorSigningSessionRecord(input.recordJson);
      if (!record || record.expiresAtMs !== expiresAtMs) return null;
      return { kind: 'coordinator', record, expiresAtMs };
    }
  }
}

export function parseCurrentThresholdEcdsaSigningSessionRecord(
  raw: unknown,
): CurrentThresholdEcdsaSigningSessionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const parsed = parseThresholdEcdsaSigningSessionRecord(record);
  if (!parsed) return null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(record.participantIds);
  const expiresAtMs = toPositiveSafeInt(record.expiresAtMs);
  if (!participantIds || !expiresAtMs) return null;
  return {
    ...parsed,
    participantIds,
    expiresAtMs,
  };
}

export function parseCurrentThresholdEcdsaSigningSessionRow(input: {
  recordJson: unknown;
  expiresAtMs: unknown;
}): CurrentThresholdEcdsaSigningSessionRow | null {
  const record = parseCurrentThresholdEcdsaSigningSessionRecord(input.recordJson);
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  if (!record || !expiresAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs) return null;
  return {
    record,
    expiresAtMs,
  };
}

export function parseCurrentThresholdEcdsaPresignSessionRecord(
  raw: unknown,
): CurrentThresholdEcdsaPresignSessionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const parsed = parseThresholdEcdsaPresignSessionRecord(record);
  if (!parsed) return null;
  const participantIds = normalizeThresholdEd25519ParticipantIds(record.participantIds);
  const createdAtMs = toPositiveSafeInt(record.createdAtMs);
  const updatedAtMs = toPositiveSafeInt(record.updatedAtMs);
  const expiresAtMs = toPositiveSafeInt(record.expiresAtMs);
  if (!participantIds || !createdAtMs || !updatedAtMs || !expiresAtMs) return null;
  if (!hasIncreasingTimestamps(createdAtMs, updatedAtMs)) return null;
  return {
    ...parsed,
    participantIds,
    createdAtMs,
    updatedAtMs,
    expiresAtMs,
  };
}

export function parseCurrentThresholdEcdsaPresignSessionRow(input: {
  recordJson: unknown;
  expiresAtMs: unknown;
}): CurrentThresholdEcdsaPresignSessionRow | null {
  const record = parseCurrentThresholdEcdsaPresignSessionRecord(input.recordJson);
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  if (!record || !expiresAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs) return null;
  return {
    record,
    expiresAtMs,
  };
}

export function parseCurrentThresholdEcdsaPresignatureRecord(
  raw: unknown,
): CurrentThresholdEcdsaPresignatureRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const parsed = parseThresholdEcdsaPresignatureRelayerShareRecord(record);
  const createdAtMs = toPositiveSafeInt(record.createdAtMs);
  if (!parsed || !createdAtMs) return null;
  return {
    ...parsed,
    createdAtMs,
  };
}

export function parseCurrentSigningRootSecretShareRecord(raw: {
  signing_root_id?: unknown;
  signing_root_version?: unknown;
  share_id?: unknown;
  sealed_share_b64u?: unknown;
  storage_id?: unknown;
  kek_id?: unknown;
  created_at_ms?: unknown;
  updated_at_ms?: unknown;
}): CurrentSigningRootSecretShareRecord | null {
  const signingRootId =
    typeof raw.signing_root_id === 'string' && raw.signing_root_id.trim()
      ? raw.signing_root_id.trim()
      : null;
  const shareId = normalizeSigningRootSecretShareId(raw.share_id);
  const sealedShareB64u =
    typeof raw.sealed_share_b64u === 'string' && raw.sealed_share_b64u.trim()
      ? raw.sealed_share_b64u.trim()
      : null;
  const createdAtMs = toPositiveSafeInt(raw.created_at_ms);
  const updatedAtMs = toPositiveSafeInt(raw.updated_at_ms);
  if (!signingRootId || !shareId || !sealedShareB64u || !createdAtMs || !updatedAtMs) return null;
  if (!hasIncreasingTimestamps(createdAtMs, updatedAtMs)) return null;
  let sealedShare: Uint8Array;
  try {
    sealedShare = base64UrlDecode(sealedShareB64u);
  } catch {
    return null;
  }
  if (sealedShare.length === 0) return null;
  const signingRootVersion =
    typeof raw.signing_root_version === 'string' ? raw.signing_root_version : null;
  if (signingRootVersion === null) return null;
  const storageId =
    typeof raw.storage_id === 'string' && raw.storage_id.trim() ? raw.storage_id.trim() : null;
  const kekId = typeof raw.kek_id === 'string' && raw.kek_id.trim() ? raw.kek_id.trim() : null;
  return {
    signingRootId,
    shareId,
    sealedShare,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(storageId ? { storageId } : {}),
    ...(kekId ? { kekId } : {}),
    createdAtMs,
    updatedAtMs,
  };
}

export function parseCurrentThresholdEd25519SessionStatusRow(input: {
  recordJson: unknown;
  expiresAtMs: unknown;
  remainingUses: unknown;
}): CurrentThresholdEd25519SessionStatusRow | null {
  const record = parseCurrentThresholdEd25519SessionRecord(input.recordJson);
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  const remainingUses = toNonNegativeSafeInt(input.remainingUses);
  if (!record || !expiresAtMs || remainingUses == null) return null;
  if (record.expiresAtMs !== expiresAtMs) return null;
  return {
    record,
    expiresAtMs,
    remainingUses,
  };
}
