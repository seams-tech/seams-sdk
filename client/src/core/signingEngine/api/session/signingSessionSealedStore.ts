import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import {
  SIGNING_SESSION_RESTORE_LEASE_STORE_NAME,
  SIGNING_SESSION_RUNTIME_SESSION_ID_KEY,
  SIGNING_SESSION_SEALED_RECORD_VERSION,
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_DB_NAME,
  SIGNING_SESSION_SEAL_DB_VERSION,
  SIGNING_SESSION_SEAL_STORAGE_SCOPE,
  SIGNING_SESSION_SEAL_STORE_NAME,
  SIGNING_SESSION_SECRET_KIND,
  type SealedSigningSessionRecord,
} from '@shared/utils/signingSessionSeal';

type SessionStoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

export type SigningSessionRestoreLease = {
  v: 1;
  walletSigningSessionId: string;
  ownerId: string;
  attemptId: string;
  startedAtMs: number;
  expiresAtMs: number;
};

export type SigningSessionRestoreLeaseHandle = SigningSessionRestoreLease & {
  thresholdSessionId: string;
};

export type SigningSessionSealedStoreRecord = SealedSigningSessionRecord;

const DB_NAME = SIGNING_SESSION_SEAL_DB_NAME;
const DB_VERSION = SIGNING_SESSION_SEAL_DB_VERSION;
const STORE_NAME = SIGNING_SESSION_SEAL_STORE_NAME;
const LEASE_STORE_NAME = SIGNING_SESSION_RESTORE_LEASE_STORE_NAME;
const RUNTIME_SESSION_ID_KEY = SIGNING_SESSION_RUNTIME_SESSION_ID_KEY;
const DEFAULT_RESTORE_LEASE_TTL_MS = 15_000;

function getSessionStorageSafe(): SessionStoragePort | null {
  const globalObj = globalThis as {
    sessionStorage?: SessionStoragePort;
  };
  const storage = globalObj?.sessionStorage;
  if (!storage) return null;
  try {
    storage.getItem('__tatchi_signing_session_runtime_probe__');
    return storage;
  } catch {
    return null;
  }
}

function createRuntimeSessionId(): string {
  const cryptoObj = (globalThis as { crypto?: Crypto }).crypto;
  const randomUuid =
    cryptoObj && typeof cryptoObj.randomUUID === 'function' ? cryptoObj.randomUUID() : '';
  if (randomUuid) return randomUuid;
  return `runtime-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function createRandomId(prefix: string): string {
  const cryptoObj = (globalThis as { crypto?: Crypto }).crypto;
  const randomUuid =
    cryptoObj && typeof cryptoObj.randomUUID === 'function' ? cryptoObj.randomUUID() : '';
  if (randomUuid) return `${prefix}-${randomUuid}`;
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

function getRuntimeSessionId(): string | null {
  const storage = getSessionStorageSafe();
  if (!storage) return null;
  const existing = String(storage.getItem(RUNTIME_SESSION_ID_KEY) || '').trim();
  if (existing) return existing;
  const next = createRuntimeSessionId();
  try {
    storage.setItem(RUNTIME_SESSION_ID_KEY, next);
    return next;
  } catch {
    return null;
  }
}

function readRuntimeSessionId(): string | null {
  const storage = getSessionStorageSafe();
  if (!storage) return null;
  return String(storage.getItem(RUNTIME_SESSION_ID_KEY) || '').trim() || null;
}

function getIndexedDbSafe(): IDBFactory | null {
  const indexedDBFactory = (globalThis as { indexedDB?: IDBFactory }).indexedDB;
  return indexedDBFactory || null;
}

function requestToPromise<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error || new Error('IndexedDB request failed'));
  });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
    tx.onerror = () => reject(tx.error || new Error('IndexedDB transaction failed'));
  });
}

function createStoreIndexes(store: IDBObjectStore): void {
  const indexes: Array<[string, string | string[]]> = [
    ['walletId', 'walletId'],
    ['userId', 'userId'],
    ['authMethod', 'authMethod'],
    ['signingRootId', 'signingRootId'],
    ['expiresAtMs', 'expiresAtMs'],
    ['wallet_signingRoot_authMethod', ['walletId', 'signingRootId', 'authMethod']],
    ['ed25519ThresholdSessionId', 'thresholdSessionIds.ed25519'],
    ['ecdsaThresholdSessionId', 'thresholdSessionIds.ecdsa'],
  ];
  for (const [name, keyPath] of indexes) {
    try {
      store.createIndex(name, keyPath, { unique: false });
    } catch {}
  }
}

function ensureSigningSessionSealStores(db: IDBDatabase, tx?: IDBTransaction | null): void {
  const sealStore = !db.objectStoreNames.contains(STORE_NAME)
    ? db.createObjectStore(STORE_NAME, { keyPath: 'walletSigningSessionId' })
    : tx?.objectStore(STORE_NAME);
  if (sealStore) createStoreIndexes(sealStore);
  if (!db.objectStoreNames.contains(LEASE_STORE_NAME)) {
    db.createObjectStore(LEASE_STORE_NAME, { keyPath: 'walletSigningSessionId' });
  }
}

function openSigningSessionSealsDb(): Promise<IDBDatabase | null> {
  const indexedDBFactory = getIndexedDbSafe();
  if (!indexedDBFactory) return Promise.resolve(null);
  return new Promise((resolve) => {
    let request: IDBOpenDBRequest;
    try {
      request = indexedDBFactory.open(DB_NAME, DB_VERSION);
    } catch {
      resolve(null);
      return;
    }
    request.onupgradeneeded = () => {
      ensureSigningSessionSealStores(request.result, request.transaction);
    };
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => resolve(null);
    request.onblocked = () => resolve(null);
  });
}

function normalizeThresholdSessionIds(value: unknown): {
  ed25519?: string;
  ecdsa?: string;
} {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : {};
  const ed25519 = normalizeOptionalNonEmptyString(obj.ed25519);
  const ecdsa = normalizeOptionalNonEmptyString(obj.ecdsa);
  return {
    ...(ed25519 ? { ed25519 } : {}),
    ...(ecdsa ? { ecdsa } : {}),
  };
}

function normalizeCurve(value: unknown): 'ed25519' | 'ecdsa' | undefined {
  const curve = String(value || '').trim();
  return curve === 'ed25519' || curve === 'ecdsa' ? curve : undefined;
}

function normalizeSigningSessionSealedStoreRecord(
  value: unknown,
): SigningSessionSealedStoreRecord | null {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  if (Number(obj.v) !== SIGNING_SESSION_SEALED_RECORD_VERSION) return null;
  if (String(obj.alg || '').trim() !== SIGNING_SESSION_SEAL_ALG) return null;
  if (String(obj.storageScope || '').trim() !== SIGNING_SESSION_SEAL_STORAGE_SCOPE) return null;
  if (String(obj.secretKind || '').trim() !== SIGNING_SESSION_SECRET_KIND) return null;

  const runtimeSessionId = normalizeOptionalNonEmptyString(obj.runtimeSessionId);
  const authMethod = String(obj.authMethod || '').trim();
  const walletSigningSessionId = normalizeOptionalNonEmptyString(obj.walletSigningSessionId);
  const thresholdSessionIds = normalizeThresholdSessionIds(obj.thresholdSessionIds);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(obj.sealedSecretB64u);
  const curve = normalizeCurve(obj.curve);
  const walletId = normalizeOptionalNonEmptyString(obj.walletId);
  const userId = normalizeOptionalNonEmptyString(obj.userId);
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const relayerUrl = normalizeOptionalNonEmptyString(obj.relayerUrl);
  const keyVersion = normalizeOptionalNonEmptyString(obj.keyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(obj.shamirPrimeB64u);
  const issuedAtMs = normalizeInteger(obj.issuedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);

  if (!runtimeSessionId || !walletSigningSessionId || !sealedSecretB64u) return null;
  if (authMethod !== 'passkey' && authMethod !== 'email_otp') return null;
  if (!thresholdSessionIds.ed25519 && !thresholdSessionIds.ecdsa) return null;
  if (issuedAtMs == null || issuedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= 0) return null;
  if (remainingUses == null || remainingUses < 0) return null;
  if (updatedAtMs == null || updatedAtMs <= 0) return null;

  return {
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    runtimeSessionId,
    authMethod,
    secretKind: SIGNING_SESSION_SECRET_KIND,
    walletSigningSessionId,
    thresholdSessionIds,
    sealedSecretB64u,
    ...(curve ? { curve } : {}),
    ...(walletId ? { walletId } : {}),
    ...(userId ? { userId } : {}),
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(relayerUrl ? { relayerUrl } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
    issuedAtMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  };
}

function normalizeSigningSessionRestoreLease(value: unknown): SigningSessionRestoreLease | null {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return null;
  if (Number(obj.v) !== 1) return null;
  const walletSigningSessionId = normalizeOptionalNonEmptyString(obj.walletSigningSessionId);
  const ownerId = normalizeOptionalNonEmptyString(obj.ownerId);
  const attemptId = normalizeOptionalNonEmptyString(obj.attemptId);
  const startedAtMs = normalizeInteger(obj.startedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  if (!walletSigningSessionId || !ownerId || !attemptId) return null;
  if (startedAtMs == null || startedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= startedAtMs) return null;
  return {
    v: 1,
    walletSigningSessionId,
    ownerId,
    attemptId,
    startedAtMs,
    expiresAtMs,
  };
}

function makeSigningSessionRestoreLease(args: {
  walletSigningSessionId: string;
  ownerId: string;
  nowMs: number;
  ttlMs: number;
}): SigningSessionRestoreLease {
  return {
    v: 1,
    walletSigningSessionId: args.walletSigningSessionId,
    ownerId: args.ownerId,
    attemptId: createRandomId('restore-attempt'),
    startedAtMs: args.nowMs,
    expiresAtMs: args.nowMs + args.ttlMs,
  };
}

function thresholdSessionIdsForWrite(args: {
  thresholdSessionId: string;
  curve?: 'ed25519' | 'ecdsa';
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
}): { ed25519?: string; ecdsa?: string } {
  const explicit = normalizeThresholdSessionIds(args.thresholdSessionIds);
  if (explicit.ed25519 || explicit.ecdsa) return explicit;
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return {};
  const curve = normalizeCurve(args.curve) || 'ecdsa';
  return curve === 'ed25519' ? { ed25519: thresholdSessionId } : { ecdsa: thresholdSessionId };
}

async function readRecordByThresholdSessionId(
  db: IDBDatabase,
  thresholdSessionId: string,
): Promise<SigningSessionSealedStoreRecord | null> {
  const indexes = ['ed25519ThresholdSessionId', 'ecdsaThresholdSessionId'];
  for (const indexName of indexes) {
    try {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const value = await requestToPromise(store.index(indexName).get(thresholdSessionId));
      const normalized = normalizeSigningSessionSealedStoreRecord(value);
      if (normalized) return normalized;
    } catch {}
  }
  return null;
}

async function deleteRecordByThresholdSessionId(
  db: IDBDatabase,
  thresholdSessionId: string,
): Promise<void> {
  const indexes = ['ed25519ThresholdSessionId', 'ecdsaThresholdSessionId'];
  for (const indexName of indexes) {
    try {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const key = await requestToPromise(store.index(indexName).getKey(thresholdSessionId));
      if (key != null) {
        store.delete(key);
      }
      await transactionDone(tx).catch(() => undefined);
    } catch {}
  }
}

async function deleteSameScopeRecords(
  store: IDBObjectStore,
  record: SigningSessionSealedStoreRecord,
): Promise<void> {
  if (!record.walletId || !record.signingRootId || !record.authMethod) return;
  try {
    const all = await requestToPromise<unknown[]>(store.getAll());
    for (const entry of all) {
      const existing = normalizeSigningSessionSealedStoreRecord(entry);
      if (!existing) continue;
      if (existing.walletSigningSessionId === record.walletSigningSessionId) continue;
      if (
        existing.walletId === record.walletId &&
        existing.signingRootId === record.signingRootId &&
        existing.authMethod === record.authMethod
      ) {
        store.delete(existing.walletSigningSessionId);
      }
    }
  } catch {}
}

export async function readSigningSessionSealedRecord(
  thresholdSessionIdRaw: string,
): Promise<SigningSessionSealedStoreRecord | null> {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const runtimeSessionId = readRuntimeSessionId();
  const db = await openSigningSessionSealsDb();
  if (!db) return null;
  try {
    const record = await readRecordByThresholdSessionId(db, thresholdSessionId);
    if (!record) return null;
    if (!runtimeSessionId || record.runtimeSessionId !== runtimeSessionId) {
      await deleteRecordByThresholdSessionId(db, thresholdSessionId);
      return null;
    }
    return record;
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function writeSigningSessionSealedRecord(args: {
  thresholdSessionId: string;
  sealedSecretB64u: string;
  curve?: 'ed25519' | 'ecdsa';
  authMethod?: 'passkey' | 'email_otp';
  walletSigningSessionId?: string;
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
  walletId?: string;
  userId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  relayerUrl?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  issuedAtMs?: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs?: number;
}): Promise<void> {
  const runtimeSessionId = getRuntimeSessionId();
  if (!runtimeSessionId) return;
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const thresholdSessionIds = thresholdSessionIdsForWrite({
    thresholdSessionId,
    curve: args.curve,
    thresholdSessionIds: args.thresholdSessionIds,
  });
  const walletSigningSessionId = normalizeOptionalNonEmptyString(args.walletSigningSessionId);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(args.sealedSecretB64u);
  const expiresAtMs = normalizeInteger(args.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses);
  const issuedAtMs = normalizeInteger(args.issuedAtMs ?? Date.now());
  const updatedAtMs = normalizeInteger(args.updatedAtMs ?? Date.now());
  if (!thresholdSessionId || !walletSigningSessionId || !sealedSecretB64u) return;
  if (!thresholdSessionIds.ed25519 && !thresholdSessionIds.ecdsa) return;
  if (issuedAtMs == null || issuedAtMs <= 0) return;
  if (expiresAtMs == null || expiresAtMs <= 0) return;
  if (remainingUses == null || remainingUses < 0) return;
  if (updatedAtMs == null || updatedAtMs <= 0) return;

  const curve = normalizeCurve(args.curve);
  const record = normalizeSigningSessionSealedStoreRecord({
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    runtimeSessionId,
    authMethod: args.authMethod === 'email_otp' ? 'email_otp' : 'passkey',
    secretKind: SIGNING_SESSION_SECRET_KIND,
    walletSigningSessionId,
    thresholdSessionIds,
    sealedSecretB64u,
    ...(curve ? { curve } : {}),
    ...(normalizeOptionalNonEmptyString(args.walletId)
      ? { walletId: normalizeOptionalNonEmptyString(args.walletId) }
      : {}),
    ...(normalizeOptionalNonEmptyString(args.userId)
      ? { userId: normalizeOptionalNonEmptyString(args.userId) }
      : {}),
    ...(normalizeOptionalNonEmptyString(args.signingRootId)
      ? { signingRootId: normalizeOptionalNonEmptyString(args.signingRootId) }
      : {}),
    ...(normalizeOptionalNonEmptyString(args.signingRootVersion)
      ? { signingRootVersion: normalizeOptionalNonEmptyString(args.signingRootVersion) }
      : {}),
    ...(normalizeOptionalNonEmptyString(args.relayerUrl)
      ? { relayerUrl: normalizeOptionalNonEmptyString(args.relayerUrl) }
      : {}),
    ...(normalizeOptionalNonEmptyString(args.keyVersion)
      ? { keyVersion: normalizeOptionalNonEmptyString(args.keyVersion) }
      : {}),
    ...(normalizeOptionalNonEmptyString(args.shamirPrimeB64u)
      ? { shamirPrimeB64u: normalizeOptionalNonEmptyString(args.shamirPrimeB64u) }
      : {}),
    issuedAtMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  });
  if (!record) return;

  const db = await openSigningSessionSealsDb();
  if (!db) return;
  try {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    await deleteSameScopeRecords(store, record);
    store.put(record);
    await transactionDone(tx).catch(() => undefined);
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function updateSigningSessionSealedRecordPolicy(args: {
  thresholdSessionId: string;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
}): Promise<void> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const existing = await readSigningSessionSealedRecord(thresholdSessionId);
  if (!existing) return;
  const expiresAtMs = normalizeInteger(args.expiresAtMs ?? existing.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses ?? existing.remainingUses);
  const updatedAtMs = normalizeInteger(args.updatedAtMs ?? Date.now());
  if (expiresAtMs == null || expiresAtMs <= 0) return;
  if (remainingUses == null || remainingUses < 0) return;
  if (updatedAtMs == null || updatedAtMs <= 0) return;
  await writeSigningSessionSealedRecord({
    thresholdSessionId,
    sealedSecretB64u: existing.sealedSecretB64u,
    curve: existing.curve,
    authMethod: existing.authMethod,
    walletSigningSessionId: existing.walletSigningSessionId,
    thresholdSessionIds: existing.thresholdSessionIds,
    walletId: existing.walletId,
    userId: existing.userId,
    signingRootId: existing.signingRootId,
    signingRootVersion: existing.signingRootVersion,
    relayerUrl: existing.relayerUrl,
    keyVersion: existing.keyVersion,
    shamirPrimeB64u: existing.shamirPrimeB64u,
    issuedAtMs: existing.issuedAtMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  });
}

export async function deleteSigningSessionSealedRecord(
  thresholdSessionIdRaw: string,
): Promise<void> {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return;
  const db = await openSigningSessionSealsDb();
  if (!db) return;
  try {
    const record = await readRecordByThresholdSessionId(db, thresholdSessionId);
    await deleteRecordByThresholdSessionId(db, thresholdSessionId);
    if (record?.walletSigningSessionId) {
      const tx = db.transaction(LEASE_STORE_NAME, 'readwrite');
      tx.objectStore(LEASE_STORE_NAME).delete(record.walletSigningSessionId);
      await transactionDone(tx).catch(() => undefined);
    }
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function acquireSigningSessionRestoreLease(args: {
  thresholdSessionId: string;
  ownerId?: string;
  nowMs?: number;
  ttlMs?: number;
}): Promise<SigningSessionRestoreLeaseHandle | null> {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const nowMs = normalizeInteger(args.nowMs ?? Date.now()) ?? Date.now();
  const ttlMs = Math.max(
    1,
    normalizeInteger(args.ttlMs ?? DEFAULT_RESTORE_LEASE_TTL_MS) ?? DEFAULT_RESTORE_LEASE_TTL_MS,
  );
  const ownerId = normalizeOptionalNonEmptyString(args.ownerId) || createRandomId('restore-owner');
  const runtimeSessionId = readRuntimeSessionId();
  if (!runtimeSessionId) return null;
  const db = await openSigningSessionSealsDb();
  if (!db) return null;
  try {
    const tx = db.transaction([STORE_NAME, LEASE_STORE_NAME], 'readwrite');
    const sealStore = tx.objectStore(STORE_NAME);
    let record: SigningSessionSealedStoreRecord | null = null;
    for (const indexName of ['ed25519ThresholdSessionId', 'ecdsaThresholdSessionId']) {
      if (record) break;
      try {
        const value = await requestToPromise(sealStore.index(indexName).get(thresholdSessionId));
        record = normalizeSigningSessionSealedStoreRecord(value);
      } catch {}
    }
    if (!record || record.runtimeSessionId !== runtimeSessionId) {
      tx.abort();
      return null;
    }

    const leaseStore = tx.objectStore(LEASE_STORE_NAME);
    const existing = normalizeSigningSessionRestoreLease(
      await requestToPromise(leaseStore.get(record.walletSigningSessionId)),
    );
    if (existing && existing.expiresAtMs > nowMs && existing.ownerId !== ownerId) {
      tx.abort();
      return null;
    }

    const lease = makeSigningSessionRestoreLease({
      walletSigningSessionId: record.walletSigningSessionId,
      ownerId,
      nowMs,
      ttlMs,
    });
    leaseStore.put(lease);
    await transactionDone(tx);
    return {
      ...lease,
      thresholdSessionId,
    };
  } catch {
    return null;
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function releaseSigningSessionRestoreLease(
  lease: SigningSessionRestoreLeaseHandle | null | undefined,
): Promise<void> {
  if (!lease?.walletSigningSessionId || !lease.ownerId || !lease.attemptId) return;
  const db = await openSigningSessionSealsDb();
  if (!db) return;
  try {
    const tx = db.transaction(LEASE_STORE_NAME, 'readwrite');
    const store = tx.objectStore(LEASE_STORE_NAME);
    const existing = normalizeSigningSessionRestoreLease(
      await requestToPromise(store.get(lease.walletSigningSessionId)),
    );
    if (existing?.ownerId === lease.ownerId && existing.attemptId === lease.attemptId) {
      store.delete(lease.walletSigningSessionId);
    }
    await transactionDone(tx).catch(() => undefined);
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function clearAllSigningSessionSealedRecords(): Promise<void> {
  const db = await openSigningSessionSealsDb();
  if (!db) return;
  try {
    const tx = db.transaction([STORE_NAME, LEASE_STORE_NAME], 'readwrite');
    tx.objectStore(STORE_NAME).clear();
    tx.objectStore(LEASE_STORE_NAME).clear();
    await transactionDone(tx).catch(() => undefined);
  } finally {
    try {
      db.close();
    } catch {}
  }
}
