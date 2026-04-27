import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { isIndexedDBPersistenceDisabled } from '../../../indexedDB';
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
  type SealedSigningSessionEcdsaRestoreMetadata,
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

export type SigningSessionSealedStoreRecord = SealedSigningSessionRecord & {
  storeKey: string;
  curve: 'ed25519' | 'ecdsa';
};
// Sealed records are indexed by threshold session id, but that id can appear
// on more than one lane. Every read/delete/lease must name the intended lane.
export type SigningSessionSealedRecordFilter = {
  authMethod: 'passkey' | 'email_otp';
  curve: 'ed25519' | 'ecdsa';
};

const DB_NAME = SIGNING_SESSION_SEAL_DB_NAME;
const DB_VERSION = SIGNING_SESSION_SEAL_DB_VERSION;
const STORE_NAME = SIGNING_SESSION_SEAL_STORE_NAME;
const LEASE_STORE_NAME = SIGNING_SESSION_RESTORE_LEASE_STORE_NAME;
const RUNTIME_SESSION_ID_KEY = SIGNING_SESSION_RUNTIME_SESSION_ID_KEY;
const DEFAULT_RESTORE_LEASE_TTL_MS = 15_000;
const SEALED_RECORD_STORE_KEY_PATH = 'storeKey';

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
  if (isIndexedDBPersistenceDisabled()) return null;
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
  let sealStore: IDBObjectStore | undefined;
  if (!db.objectStoreNames.contains(STORE_NAME)) {
    sealStore = db.createObjectStore(STORE_NAME, { keyPath: SEALED_RECORD_STORE_KEY_PATH });
  } else {
    const existing = tx?.objectStore(STORE_NAME);
    if (existing?.keyPath === SEALED_RECORD_STORE_KEY_PATH) {
      sealStore = existing;
    } else {
      // Version 3 changes the primary key from wallet session to purpose. A
      // stale v2 store cannot hold passkey and Email OTP seals side by side.
      db.deleteObjectStore(STORE_NAME);
      sealStore = db.createObjectStore(STORE_NAME, { keyPath: SEALED_RECORD_STORE_KEY_PATH });
    }
  }
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

function resolveSealedRecordCurve(args: {
  curve?: 'ed25519' | 'ecdsa';
  thresholdSessionIds: { ed25519?: string; ecdsa?: string };
}): 'ed25519' | 'ecdsa' | null {
  if (args.curve) return args.curve;
  if (args.thresholdSessionIds.ecdsa) return 'ecdsa';
  if (args.thresholdSessionIds.ed25519) return 'ed25519';
  return null;
}

function normalizeEcdsaRestoreMetadata(
  value: unknown,
): SealedSigningSessionEcdsaRestoreMetadata | undefined {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return undefined;
  const chainRaw = String(obj.chain || '').trim();
  const chain = chainRaw === 'tempo' || chainRaw === 'evm' ? chainRaw : undefined;
  const sessionKindRaw = String(obj.sessionKind || '').trim();
  const sessionKind =
    sessionKindRaw === 'cookie' || sessionKindRaw === 'jwt' ? sessionKindRaw : undefined;
  const ecdsaThresholdKeyId = normalizeOptionalNonEmptyString(obj.ecdsaThresholdKeyId);
  const relayerKeyId = normalizeOptionalNonEmptyString(obj.relayerKeyId);
  const participantIds = Array.isArray(obj.participantIds)
    ? obj.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  if (!chain || !sessionKind || !ecdsaThresholdKeyId || !relayerKeyId || !participantIds.length) {
    return undefined;
  }
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(obj.thresholdSessionJwt);
  return {
    chain,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    sessionKind,
    ecdsaThresholdKeyId,
    relayerKeyId,
    participantIds,
    ...(obj.runtimePolicyScope && typeof obj.runtimePolicyScope === 'object'
      ? { runtimePolicyScope: obj.runtimePolicyScope }
      : {}),
  };
}

function makeSealedRecordStoreKey(args: {
  walletSigningSessionId: string;
  authMethod: 'passkey' | 'email_otp';
  curve: 'ed25519' | 'ecdsa';
}): string {
  return [args.walletSigningSessionId, args.authMethod, args.curve].join(':');
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
  const ecdsaRestore = normalizeEcdsaRestoreMetadata(obj.ecdsaRestore);
  const issuedAtMs = normalizeInteger(obj.issuedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);

  if (!runtimeSessionId || !walletSigningSessionId || !sealedSecretB64u) return null;
  if (authMethod !== 'passkey' && authMethod !== 'email_otp') return null;
  if (!thresholdSessionIds.ed25519 && !thresholdSessionIds.ecdsa) return null;
  const recordCurve = resolveSealedRecordCurve({ curve, thresholdSessionIds });
  if (!recordCurve) return null;
  if (issuedAtMs == null || issuedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= 0) return null;
  if (remainingUses == null || remainingUses < 0) return null;
  if (updatedAtMs == null || updatedAtMs <= 0) return null;
  const storeKey =
    normalizeOptionalNonEmptyString(obj.storeKey) ||
    makeSealedRecordStoreKey({
      walletSigningSessionId,
      authMethod,
      curve: recordCurve,
    });

  return {
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    runtimeSessionId,
    authMethod,
    secretKind: SIGNING_SESSION_SECRET_KIND,
    storeKey,
    walletSigningSessionId,
    thresholdSessionIds,
    sealedSecretB64u,
    curve: recordCurve,
    ...(walletId ? { walletId } : {}),
    ...(userId ? { userId } : {}),
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(relayerUrl ? { relayerUrl } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
    ...(ecdsaRestore ? { ecdsaRestore } : {}),
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

function recordMatchesFilter(
  record: SigningSessionSealedStoreRecord,
  thresholdSessionId: string,
  filter: SigningSessionSealedRecordFilter,
): boolean {
  if (record.authMethod !== filter.authMethod) return false;
  // Some Email OTP seals bind a single secret to both ECDSA and Ed25519 lane ids.
  // The requested curve is enforced by the thresholdSessionIds map below.
  if (record.thresholdSessionIds[filter.curve] !== thresholdSessionId) return false;
  return true;
}

function requireSealedRecordPurpose(
  filter: SigningSessionSealedRecordFilter | undefined,
  operation: string,
): SigningSessionSealedRecordFilter {
  if (filter?.authMethod && filter.curve) return filter;
  console.warn('[SigningSessionSealedStore] rejected ambiguous sealed record access', {
    operation,
  });
  throw new Error(
    `[SigningSessionSealedStore] ${operation} requires an explicit authMethod and curve`,
  );
}

function warnSealedRecordPurposeMiss(args: {
  operation: string;
  thresholdSessionId: string;
  filter: SigningSessionSealedRecordFilter;
  candidates: SigningSessionSealedStoreRecord[];
}): void {
  if (!args.candidates.length) return;
  console.warn('[SigningSessionSealedStore] sealed record purpose mismatch', {
    operation: args.operation,
    thresholdSessionId: args.thresholdSessionId,
    expected: args.filter,
    candidates: args.candidates.map((record) => ({
      storeKey: record.storeKey,
      authMethod: record.authMethod,
      curve: record.curve,
      walletSigningSessionId: record.walletSigningSessionId,
      thresholdSessionIds: record.thresholdSessionIds,
    })),
  });
}

async function readRecordsByThresholdSessionId(
  db: IDBDatabase,
  thresholdSessionId: string,
): Promise<SigningSessionSealedStoreRecord[]> {
  const indexes = ['ed25519ThresholdSessionId', 'ecdsaThresholdSessionId'];
  const recordsByPurpose = new Map<string, SigningSessionSealedStoreRecord>();
  for (const indexName of indexes) {
    try {
      const tx = db.transaction(STORE_NAME, 'readonly');
      const store = tx.objectStore(STORE_NAME);
      const values = await requestToPromise<unknown[]>(
        store.index(indexName).getAll(thresholdSessionId),
      );
      for (const value of values) {
        const normalized = normalizeSigningSessionSealedStoreRecord(value);
        if (normalized?.storeKey) recordsByPurpose.set(normalized.storeKey, normalized);
      }
    } catch {}
  }
  return [...recordsByPurpose.values()];
}

async function readRecordByThresholdSessionId(
  db: IDBDatabase,
  thresholdSessionId: string,
  filter: SigningSessionSealedRecordFilter,
  operation: string,
): Promise<SigningSessionSealedStoreRecord | null> {
  const records = await readRecordsByThresholdSessionId(db, thresholdSessionId);
  const record =
    records.find((candidate) => recordMatchesFilter(candidate, thresholdSessionId, filter)) || null;
  if (!record) {
    warnSealedRecordPurposeMiss({ operation, thresholdSessionId, filter, candidates: records });
  }
  return record;
}

async function deleteRecordByThresholdSessionId(
  db: IDBDatabase,
  thresholdSessionId: string,
  filter: SigningSessionSealedRecordFilter,
): Promise<void> {
  const indexes = ['ed25519ThresholdSessionId', 'ecdsaThresholdSessionId'];
  for (const indexName of indexes) {
    try {
      const tx = db.transaction(STORE_NAME, 'readwrite');
      const store = tx.objectStore(STORE_NAME);
      const values = await requestToPromise<unknown[]>(
        store.index(indexName).getAll(thresholdSessionId),
      );
      for (const value of values) {
        const record = normalizeSigningSessionSealedStoreRecord(value);
        if (record?.storeKey && recordMatchesFilter(record, thresholdSessionId, filter)) {
          store.delete(record.storeKey);
        }
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
      if (existing.storeKey === record.storeKey) continue;
      if (
        existing.walletId === record.walletId &&
        existing.signingRootId === record.signingRootId &&
        existing.authMethod === record.authMethod &&
        existing.curve === record.curve
      ) {
        store.delete(existing.storeKey);
      }
    }
  } catch {}
}

export async function readSigningSessionSealedRecord(
  thresholdSessionIdRaw: string,
  filter: SigningSessionSealedRecordFilter,
): Promise<SigningSessionSealedStoreRecord | null> {
  const purpose = requireSealedRecordPurpose(filter, 'read');
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const runtimeSessionId = readRuntimeSessionId();
  const db = await openSigningSessionSealsDb();
  if (!db) return null;
  try {
    const record = await readRecordByThresholdSessionId(db, thresholdSessionId, purpose, 'read');
    if (!record) return null;
    if (!runtimeSessionId || record.runtimeSessionId !== runtimeSessionId) {
      await deleteRecordByThresholdSessionId(db, thresholdSessionId, purpose);
      return null;
    }
    return record;
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function listSigningSessionSealedRecordsForAccount(args: {
  accountId: string;
  filter?: Partial<SigningSessionSealedRecordFilter>;
}): Promise<SigningSessionSealedStoreRecord[]> {
  const accountId = normalizeOptionalNonEmptyString(args.accountId);
  if (!accountId) return [];
  const runtimeSessionId = readRuntimeSessionId();
  if (!runtimeSessionId) return [];
  const db = await openSigningSessionSealsDb();
  if (!db) return [];
  try {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const values = await requestToPromise<unknown[]>(store.getAll());
    const records: SigningSessionSealedStoreRecord[] = [];
    const seen = new Set<string>();
    for (const value of values) {
      const record = normalizeSigningSessionSealedStoreRecord(value);
      if (!record) continue;
      if (record.runtimeSessionId !== runtimeSessionId) continue;
      if (record.walletId !== accountId && record.userId !== accountId) continue;
      if (args.filter?.authMethod && record.authMethod !== args.filter.authMethod) continue;
      if (args.filter?.curve && record.curve !== args.filter.curve) continue;
      if (seen.has(record.storeKey)) continue;
      seen.add(record.storeKey);
      records.push(record);
    }
    return records;
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function writeSigningSessionSealedRecord(args: {
  thresholdSessionId: string;
  sealedSecretB64u: string;
  curve: 'ed25519' | 'ecdsa';
  authMethod: 'passkey' | 'email_otp';
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
  ecdsaRestore?: SealedSigningSessionEcdsaRestoreMetadata;
  issuedAtMs?: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs?: number;
}): Promise<void> {
  const runtimeSessionId = getRuntimeSessionId();
  if (!runtimeSessionId) return;
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const curve = normalizeCurve(args.curve);
  const authMethod =
    args.authMethod === 'passkey' || args.authMethod === 'email_otp' ? args.authMethod : undefined;
  const thresholdSessionIds = thresholdSessionIdsForWrite({
    thresholdSessionId,
    curve,
    thresholdSessionIds: args.thresholdSessionIds,
  });
  const walletSigningSessionId = normalizeOptionalNonEmptyString(args.walletSigningSessionId);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(args.sealedSecretB64u);
  const expiresAtMs = normalizeInteger(args.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses);
  const issuedAtMs = normalizeInteger(args.issuedAtMs ?? Date.now());
  const updatedAtMs = normalizeInteger(args.updatedAtMs ?? Date.now());
  if (!thresholdSessionId || !walletSigningSessionId || !sealedSecretB64u) return;
  if (!curve) {
    console.warn('[SigningSessionSealedStore] rejected sealed record write without curve', {
      thresholdSessionId,
    });
    return;
  }
  if (!authMethod) {
    console.warn('[SigningSessionSealedStore] rejected sealed record write without auth method', {
      thresholdSessionId,
      curve,
    });
    return;
  }
  if (!thresholdSessionIds.ed25519 && !thresholdSessionIds.ecdsa) return;
  if (issuedAtMs == null || issuedAtMs <= 0) return;
  if (expiresAtMs == null || expiresAtMs <= 0) return;
  if (remainingUses == null || remainingUses < 0) return;
  if (updatedAtMs == null || updatedAtMs <= 0) return;
  const ecdsaRestore = normalizeEcdsaRestoreMetadata(args.ecdsaRestore);

  const record = normalizeSigningSessionSealedStoreRecord({
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
    ...(ecdsaRestore ? { ecdsaRestore } : {}),
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
  filter: SigningSessionSealedRecordFilter;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
}): Promise<void> {
  const purpose = requireSealedRecordPurpose(args.filter, 'update policy');
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const existing = await readSigningSessionSealedRecord(thresholdSessionId, purpose);
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
    curve: existing.curve || purpose.curve,
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
    ecdsaRestore: existing.ecdsaRestore,
    issuedAtMs: existing.issuedAtMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  });
}

export async function deleteSigningSessionSealedRecord(
  thresholdSessionIdRaw: string,
  filter: SigningSessionSealedRecordFilter,
): Promise<void> {
  const purpose = requireSealedRecordPurpose(filter, 'delete');
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return;
  const db = await openSigningSessionSealsDb();
  if (!db) return;
  try {
    const record = await readRecordByThresholdSessionId(db, thresholdSessionId, purpose, 'delete');
    await deleteRecordByThresholdSessionId(db, thresholdSessionId, purpose);
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
  authMethod: 'passkey' | 'email_otp';
  curve: 'ed25519' | 'ecdsa';
  ownerId?: string;
  nowMs?: number;
  ttlMs?: number;
}): Promise<SigningSessionRestoreLeaseHandle | null> {
  const purpose = requireSealedRecordPurpose(args, 'acquire restore lease');
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
    const records: SigningSessionSealedStoreRecord[] = [];
    for (const indexName of ['ed25519ThresholdSessionId', 'ecdsaThresholdSessionId']) {
      try {
        const values = await requestToPromise<unknown[]>(
          sealStore.index(indexName).getAll(thresholdSessionId),
        );
        for (const value of values) {
          const normalized = normalizeSigningSessionSealedStoreRecord(value);
          if (
            normalized?.storeKey &&
            !records.some((record) => record.storeKey === normalized.storeKey)
          ) {
            records.push(normalized);
          }
        }
      } catch {}
    }
    const record =
      records.find((candidate) => recordMatchesFilter(candidate, thresholdSessionId, purpose)) ||
      null;
    if (!record) {
      warnSealedRecordPurposeMiss({
        operation: 'acquire restore lease',
        thresholdSessionId,
        filter: purpose,
        candidates: records,
      });
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
