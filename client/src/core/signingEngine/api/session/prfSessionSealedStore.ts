import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';

type SessionStoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

export type PrfSessionSealedStoreRecord = {
  v: 1;
  alg: 'shamir3pass-v1';
  thresholdSessionId: string;
  sealedPrfFirstB64u: string;
  keyVersion?: string;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs: number;
};

const STORAGE_KEY_PREFIX = 'tatchi:threshold-prf-sealed:v1';
const STORAGE_INDEX_KEY = `${STORAGE_KEY_PREFIX}:index`;

function storageKeyForThresholdSession(thresholdSessionId: string): string {
  return `${STORAGE_KEY_PREFIX}:${thresholdSessionId}`;
}

function getSessionStorageSafe(): SessionStoragePort | null {
  const globalObj = globalThis as { sessionStorage?: SessionStoragePort };
  if (!globalObj?.sessionStorage) return null;
  try {
    const storage = globalObj.sessionStorage;
    storage.getItem('__tatchi_prf_session_sealed_probe__');
    return storage;
  } catch {
    return null;
  }
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

function writeStorageIndex(storage: SessionStoragePort, thresholdSessionIds: string[]): void {
  try {
    storage.setItem(STORAGE_INDEX_KEY, JSON.stringify(thresholdSessionIds));
  } catch {}
}

function addToStorageIndex(storage: SessionStoragePort, thresholdSessionId: string): void {
  const sessionId = String(thresholdSessionId || '').trim();
  if (!sessionId) return;
  const current = readStorageIndex(storage);
  if (current.includes(sessionId)) return;
  writeStorageIndex(storage, [...current, sessionId]);
}

function removeFromStorageIndex(storage: SessionStoragePort, thresholdSessionId: string): void {
  const sessionId = String(thresholdSessionId || '').trim();
  if (!sessionId) return;
  const current = readStorageIndex(storage);
  const next = current.filter((entry) => entry !== sessionId);
  if (next.length === current.length) return;
  writeStorageIndex(storage, next);
}

function normalizePrfSessionSealedStoreRecord(value: unknown): PrfSessionSealedStoreRecord | null {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  if (Number(obj.v) !== 1) return null;
  if (String(obj.alg || '').trim() !== 'shamir3pass-v1') return null;
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const sealedPrfFirstB64u = String(obj.sealedPrfFirstB64u || '').trim();
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);
  const keyVersion = normalizeOptionalNonEmptyString(obj.keyVersion);
  if (!thresholdSessionId || !sealedPrfFirstB64u) return null;
  if (expiresAtMs == null || expiresAtMs <= 0) return null;
  if (remainingUses == null || remainingUses < 0) return null;
  if (updatedAtMs == null || updatedAtMs <= 0) return null;
  return {
    v: 1,
    alg: 'shamir3pass-v1',
    thresholdSessionId,
    sealedPrfFirstB64u,
    ...(keyVersion ? { keyVersion } : {}),
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  };
}

function writeStoredRecord(storage: SessionStoragePort, record: PrfSessionSealedStoreRecord): void {
  try {
    storage.setItem(storageKeyForThresholdSession(record.thresholdSessionId), JSON.stringify(record));
    addToStorageIndex(storage, record.thresholdSessionId);
  } catch {}
}

export function readPrfSessionSealedRecord(
  thresholdSessionIdRaw: string,
): PrfSessionSealedStoreRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const storage = getSessionStorageSafe();
  if (!storage) return null;
  try {
    const raw = storage.getItem(storageKeyForThresholdSession(thresholdSessionId));
    if (!raw) return null;
    return normalizePrfSessionSealedStoreRecord(JSON.parse(raw));
  } catch {
    return null;
  }
}

export function writePrfSessionSealedRecord(args: {
  thresholdSessionId: string;
  sealedPrfFirstB64u: string;
  keyVersion?: string;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs?: number;
}): void {
  const storage = getSessionStorageSafe();
  if (!storage) return;
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const sealedPrfFirstB64u = String(args.sealedPrfFirstB64u || '').trim();
  const expiresAtMs = normalizeInteger(args.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses);
  const updatedAtMs = normalizeInteger(args.updatedAtMs ?? Date.now());
  const keyVersion = normalizeOptionalNonEmptyString(args.keyVersion);
  if (!thresholdSessionId || !sealedPrfFirstB64u) return;
  if (expiresAtMs == null || expiresAtMs <= 0) return;
  if (remainingUses == null || remainingUses < 0) return;
  if (updatedAtMs == null || updatedAtMs <= 0) return;

  writeStoredRecord(storage, {
    v: 1,
    alg: 'shamir3pass-v1',
    thresholdSessionId,
    sealedPrfFirstB64u,
    ...(keyVersion ? { keyVersion } : {}),
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  });
}

export function updatePrfSessionSealedRecordPolicy(args: {
  thresholdSessionId: string;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
}): void {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const existing = readPrfSessionSealedRecord(thresholdSessionId);
  if (!existing) return;
  const expiresAtMs = normalizeInteger(args.expiresAtMs ?? existing.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses ?? existing.remainingUses);
  const updatedAtMs = normalizeInteger(args.updatedAtMs ?? Date.now());
  if (expiresAtMs == null || expiresAtMs <= 0) return;
  if (remainingUses == null || remainingUses < 0) return;
  if (updatedAtMs == null || updatedAtMs <= 0) return;
  writePrfSessionSealedRecord({
    thresholdSessionId,
    sealedPrfFirstB64u: existing.sealedPrfFirstB64u,
    keyVersion: existing.keyVersion,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  });
}

export function deletePrfSessionSealedRecord(thresholdSessionIdRaw: string): void {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return;
  const storage = getSessionStorageSafe();
  if (!storage) return;
  try {
    storage.removeItem(storageKeyForThresholdSession(thresholdSessionId));
  } catch {}
  removeFromStorageIndex(storage, thresholdSessionId);
}

export function listPrfSessionSealedRecordSessionIds(): string[] {
  const storage = getSessionStorageSafe();
  if (!storage) return [];
  return readStorageIndex(storage);
}

export function clearAllPrfSessionSealedRecords(): void {
  const storage = getSessionStorageSafe();
  if (!storage) return;
  const sessionIds = readStorageIndex(storage);
  for (const sessionId of sessionIds) {
    try {
      storage.removeItem(storageKeyForThresholdSession(sessionId));
    } catch {}
  }
  try {
    storage.removeItem(STORAGE_INDEX_KEY);
  } catch {}
}
