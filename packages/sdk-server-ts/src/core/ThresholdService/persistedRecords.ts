import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseEd25519WalletSessionRecord,
  parseRouterAbEcdsaDerivationPoolFillSessionRecord,
  parseThresholdEd25519KeyRecord,
  parseThresholdEd25519MpcSessionRecord,
  parseThresholdEd25519SigningSessionRecord,
} from './validation';

export type CurrentThresholdEd25519SessionRecord = NonNullable<
  ReturnType<typeof parseEd25519WalletSessionRecord>
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

export type CurrentRouterAbEcdsaDerivationPoolFillSessionRecord = NonNullable<
  ReturnType<typeof parseRouterAbEcdsaDerivationPoolFillSessionRecord>
>;

export type CurrentRouterAbEcdsaDerivationPoolFillSessionRow = {
  record: CurrentRouterAbEcdsaDerivationPoolFillSessionRecord;
  expiresAtMs: number;
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
  const parsed = parseEd25519WalletSessionRecord(record);
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

export function parseCurrentRouterAbEcdsaDerivationPoolFillSessionRecord(
  raw: unknown,
): CurrentRouterAbEcdsaDerivationPoolFillSessionRecord | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const record = raw as Record<string, unknown>;
  const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(record);
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

export function parseCurrentRouterAbEcdsaDerivationPoolFillSessionRow(input: {
  recordJson: unknown;
  expiresAtMs: unknown;
}): CurrentRouterAbEcdsaDerivationPoolFillSessionRow | null {
  const record = parseCurrentRouterAbEcdsaDerivationPoolFillSessionRecord(input.recordJson);
  const expiresAtMs = toPositiveSafeInt(input.expiresAtMs);
  if (!record || !expiresAtMs) return null;
  if (record.expiresAtMs !== expiresAtMs) return null;
  return {
    record,
    expiresAtMs,
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
