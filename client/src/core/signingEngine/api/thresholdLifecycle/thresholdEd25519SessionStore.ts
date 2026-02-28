import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeInteger,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { toAccountId, type AccountId } from '@/core/types/accountIds';

export type ThresholdEd25519SessionStoreSource =
  | 'login'
  | 'registration'
  | 'manual-connect'
  | 'bootstrap';

export type ThresholdEd25519SessionRecord = {
  nearAccountId: AccountId;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  thresholdSessionJwt?: string;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
  source: ThresholdEd25519SessionStoreSource;
};

type ThresholdEd25519SessionStoreValue = {
  v: 1;
  record: ThresholdEd25519SessionRecord;
};

type SessionStoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

const STORAGE_KEY_PREFIX = 'tatchi:threshold-ed25519-session:v1';
const STORAGE_INDEX_KEY = `${STORAGE_KEY_PREFIX}:index`;

function getSessionStorageSafe(): SessionStoragePort | null {
  const globalObj = globalThis as { sessionStorage?: SessionStoragePort };
  if (!globalObj?.sessionStorage) return null;
  try {
    const storage = globalObj.sessionStorage;
    storage.getItem('__tatchi_threshold_ed25519_session_probe__');
    return storage;
  } catch {
    return null;
  }
}

function storageKeyForAccount(nearAccountId: AccountId): string {
  return `${STORAGE_KEY_PREFIX}:${String(nearAccountId)}`;
}

function readStorageIndex(storage: SessionStoragePort): string[] {
  try {
    const raw = storage.getItem(STORAGE_INDEX_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((value) => String(value || '').trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function writeStorageIndex(storage: SessionStoragePort, accounts: string[]): void {
  try {
    storage.setItem(STORAGE_INDEX_KEY, JSON.stringify(accounts));
  } catch {}
}

function addToStorageIndex(storage: SessionStoragePort, nearAccountId: AccountId): void {
  const accountId = String(nearAccountId || '').trim();
  if (!accountId) return;
  const current = readStorageIndex(storage);
  if (current.includes(accountId)) return;
  writeStorageIndex(storage, [...current, accountId]);
}

function removeFromStorageIndex(storage: SessionStoragePort, nearAccountId: AccountId): void {
  const accountId = String(nearAccountId || '').trim();
  if (!accountId) return;
  const current = readStorageIndex(storage);
  const next = current.filter((entry) => entry !== accountId);
  if (next.length === current.length) return;
  writeStorageIndex(storage, next);
}

function normalizeThresholdEd25519SessionRecord(value: unknown): ThresholdEd25519SessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const nearAccountId = toAccountId(String(obj.nearAccountId || '').trim());
  const rpId = String(obj.rpId || '').trim();
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const thresholdSessionKindRaw = String(obj.thresholdSessionKind || 'jwt')
    .trim()
    .toLowerCase();
  const thresholdSessionKind: 'jwt' | 'cookie' =
    thresholdSessionKindRaw === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(obj.thresholdSessionJwt);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizePositiveInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs) || Date.now();
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEd25519SessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
    sourceRaw === 'manual-connect' ||
    sourceRaw === 'bootstrap'
      ? sourceRaw
      : 'manual-connect';

  if (!rpId || !relayerUrl || !relayerKeyId || !participantIds || !thresholdSessionId) {
    throw new Error('Invalid threshold Ed25519 canonical session record');
  }
  if (thresholdSessionKind === 'jwt' && !thresholdSessionJwt) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing JWT');
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing expiresAtMs');
  }
  if (remainingUses == null || remainingUses <= 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing remainingUses');
  }

  return {
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    participantIds,
    thresholdSessionKind,
    thresholdSessionId,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    expiresAtMs,
    remainingUses,
    updatedAtMs,
    source,
  };
}

function writeStoredRecord(storage: SessionStoragePort, record: ThresholdEd25519SessionRecord): void {
  try {
    const payload: ThresholdEd25519SessionStoreValue = {
      v: 1,
      record,
    };
    storage.setItem(storageKeyForAccount(record.nearAccountId), JSON.stringify(payload));
    addToStorageIndex(storage, record.nearAccountId);
  } catch {}
}

function readStoredRecord(
  storage: SessionStoragePort,
  nearAccountId: AccountId,
): ThresholdEd25519SessionRecord | null {
  try {
    const raw = storage.getItem(storageKeyForAccount(nearAccountId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as ThresholdEd25519SessionStoreValue;
    if (!parsed || parsed.v !== 1 || typeof parsed !== 'object') return null;
    return normalizeThresholdEd25519SessionRecord(parsed.record);
  } catch {
    return null;
  }
}

export function upsertStoredThresholdEd25519SessionRecord(args: {
  nearAccountId: AccountId | string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  thresholdSessionKind?: 'jwt' | 'cookie';
  thresholdSessionId: string;
  thresholdSessionJwt?: string;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs?: number;
  source?: ThresholdEd25519SessionStoreSource;
}): ThresholdEd25519SessionRecord | null {
  const storage = getSessionStorageSafe();
  if (!storage) return null;
  const record = normalizeThresholdEd25519SessionRecord({
    nearAccountId: toAccountId(args.nearAccountId),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds: args.participantIds,
    thresholdSessionKind: String(args.thresholdSessionKind || 'jwt').trim().toLowerCase(),
    thresholdSessionId: String(args.thresholdSessionId || '').trim(),
    ...(String(args.thresholdSessionJwt || '').trim()
      ? { thresholdSessionJwt: String(args.thresholdSessionJwt || '').trim() }
      : {}),
    expiresAtMs: Math.floor(Number(args.expiresAtMs) || 0),
    remainingUses: Math.floor(Number(args.remainingUses) || 0),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source: args.source || 'manual-connect',
  });
  writeStoredRecord(storage, record);
  return record;
}

export function getStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  const storage = getSessionStorageSafe();
  if (!storage) return null;
  try {
    const nearAccountId = toAccountId(nearAccountIdRaw);
    return readStoredRecord(storage, nearAccountId);
  } catch {
    return null;
  }
}

export function getStoredThresholdEd25519SessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const storage = getSessionStorageSafe();
  if (!storage) return null;
  const accountIds = readStorageIndex(storage);
  for (const accountIdRaw of accountIds) {
    try {
      const nearAccountId = toAccountId(accountIdRaw);
      const record = readStoredRecord(storage, nearAccountId);
      if (!record) continue;
      if (String(record.thresholdSessionId || '').trim() === thresholdSessionId) {
        return record;
      }
    } catch {}
  }
  return null;
}

export function clearStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): void {
  const storage = getSessionStorageSafe();
  if (!storage) return;
  try {
    const nearAccountId = toAccountId(nearAccountIdRaw);
    storage.removeItem(storageKeyForAccount(nearAccountId));
    removeFromStorageIndex(storage, nearAccountId);
  } catch {}
}

export function clearAllStoredThresholdEd25519SessionRecords(): void {
  const storage = getSessionStorageSafe();
  if (!storage) return;
  const accountIds = readStorageIndex(storage);
  for (const accountIdRaw of accountIds) {
    try {
      const nearAccountId = toAccountId(accountIdRaw);
      storage.removeItem(storageKeyForAccount(nearAccountId));
    } catch {}
  }
  try {
    storage.removeItem(STORAGE_INDEX_KEY);
  } catch {}
}
