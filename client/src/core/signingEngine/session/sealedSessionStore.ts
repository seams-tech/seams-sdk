import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { isIndexedDBPersistenceDisabled } from '../../indexedDB';
import {
  SIGNING_SESSION_RESTORE_LEASE_STORE_NAME,
  SIGNING_SESSION_SEALED_RECORD_VERSION,
  SIGNING_SESSION_SEAL_ALG,
  SIGNING_SESSION_SEAL_DB_NAME,
  SIGNING_SESSION_SEAL_DB_VERSION,
  SIGNING_SESSION_SEAL_STORAGE_SCOPE,
  SIGNING_SESSION_SEAL_STORE_NAME,
  SIGNING_SESSION_SECRET_KIND,
  type SealedSigningSessionEcdsaRestoreMetadata,
  type SealedSigningSessionEd25519RestoreMetadata,
  type SealedSigningSessionRecord,
} from '@shared/utils/signingSessionSeal';
import {
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetsEqual,
  type ThresholdEcdsaChainTarget,
} from './signingSession/ecdsaChainTarget';

export type SigningSessionRestoreLease = {
  v: 1;
  leaseKey: string;
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
export type SigningSessionSealedRecordFilter =
  | {
      authMethod: 'passkey' | 'email_otp';
      curve: 'ed25519';
    }
  | {
      authMethod: 'passkey' | 'email_otp';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

export type ListExactSigningSessionSealedRecordsForAccountFilter = SigningSessionSealedRecordFilter;

export type WriteExactSealedSessionBaseInput = {
  thresholdSessionId: string;
  sealedSecretB64u: string;
  authMethod: 'passkey' | 'email_otp';
  walletSigningSessionId: string;
  thresholdSessionIds?: {
    ed25519?: string;
    ecdsa?: string;
  };
  subjectId?: string;
  walletId?: string;
  userId?: string;
  signingRootId?: string;
  signingRootVersion?: string;
  relayerUrl?: string;
  keyVersion?: string;
  shamirPrimeB64u?: string;
  ecdsaRestore?: SealedSigningSessionEcdsaRestoreMetadata;
  ed25519Restore?: SealedSigningSessionEd25519RestoreMetadata;
  issuedAtMs?: number;
  expiresAtMs: number;
  remainingUses: number;
  updatedAtMs?: number;
};

export type WriteExactSealedSessionInput =
  | (WriteExactSealedSessionBaseInput & {
      curve: 'ed25519';
    })
  | (WriteExactSealedSessionBaseInput & {
      curve: 'ecdsa';
      subjectId: string;
    });

export type ResolvedSigningSessionIdentity =
  | {
      walletId: string;
      authMethod: 'passkey' | 'email_otp';
      curve: 'ed25519';
      chain: 'near';
      walletSigningSessionId: string;
      thresholdSessionId: string;
      updatedAtMs: number;
    }
  | {
      walletId: string;
      authMethod: 'passkey' | 'email_otp';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      walletSigningSessionId: string;
      thresholdSessionId: string;
      updatedAtMs: number;
    };

export type PublishResolvedIdentityInput =
  | (Omit<Extract<ResolvedSigningSessionIdentity, { curve: 'ed25519' }>, 'updatedAtMs'> & {
      updatedAtMs?: number;
    })
  | (Omit<Extract<ResolvedSigningSessionIdentity, { curve: 'ecdsa' }>, 'updatedAtMs'> & {
      updatedAtMs?: number;
    });

const DB_NAME = SIGNING_SESSION_SEAL_DB_NAME;
const DB_VERSION = SIGNING_SESSION_SEAL_DB_VERSION;
const STORE_NAME = SIGNING_SESSION_SEAL_STORE_NAME;
const LEASE_STORE_NAME = SIGNING_SESSION_RESTORE_LEASE_STORE_NAME;
const DEFAULT_RESTORE_LEASE_TTL_MS = 15_000;
const SEALED_RECORD_STORE_KEY_PATH = 'storeKey';
const resolvedIdentitiesByPurposeKey = new Map<string, ResolvedSigningSessionIdentity>();
const resolvedIdentityKeysByListKey = new Map<string, Set<string>>();

function createRandomId(prefix: string): string {
  const cryptoObj = (globalThis as { crypto?: Crypto }).crypto;
  const randomUuid =
    cryptoObj && typeof cryptoObj.randomUUID === 'function' ? cryptoObj.randomUUID() : '';
  if (randomUuid) return `${prefix}-${randomUuid}`;
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
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

function ensureSigningSessionSealStores(
  db: IDBDatabase,
  tx?: IDBTransaction | null,
  opts?: { resetStores?: boolean },
): void {
  if (opts?.resetStores) {
    if (db.objectStoreNames.contains(STORE_NAME)) {
      db.deleteObjectStore(STORE_NAME);
    }
    if (db.objectStoreNames.contains(LEASE_STORE_NAME)) {
      db.deleteObjectStore(LEASE_STORE_NAME);
    }
  }
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
    db.createObjectStore(LEASE_STORE_NAME, { keyPath: 'leaseKey' });
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
    request.onupgradeneeded = (event) => {
      // v4 makes ECDSA chain part of durable identity. Old v3 records used
      // chain-less primary keys, so the clean migration is to drop local seals
      // and require a fresh explicit restore/auth path.
      const oldVersion = Math.floor(Number(event.oldVersion) || 0);
      ensureSigningSessionSealStores(request.result, request.transaction, {
        resetStores: oldVersion > 0 && oldVersion < 4,
      });
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
  let chainTarget: ThresholdEcdsaChainTarget | null = null;
  try {
    chainTarget = thresholdEcdsaChainTargetFromRequest(
      obj.chainTarget && typeof obj.chainTarget === 'object' && !Array.isArray(obj.chainTarget)
        ? (obj.chainTarget as Record<string, unknown>)
        : {},
    );
  } catch {
    chainTarget = null;
  }
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
  if (
    !chainTarget ||
    !sessionKind ||
    !ecdsaThresholdKeyId ||
    !relayerKeyId ||
    !participantIds.length
  ) {
    return undefined;
  }
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(obj.thresholdSessionJwt);
  const clientVerifyingShareB64u = normalizeOptionalNonEmptyString(obj.clientVerifyingShareB64u);
  return {
    chainTarget,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    sessionKind,
    ecdsaThresholdKeyId,
    relayerKeyId,
    ...(clientVerifyingShareB64u ? { clientVerifyingShareB64u } : {}),
    participantIds,
    ...(obj.runtimePolicyScope && typeof obj.runtimePolicyScope === 'object'
      ? { runtimePolicyScope: obj.runtimePolicyScope }
      : {}),
  };
}

function normalizeEd25519RestoreMetadata(
  value: unknown,
): SealedSigningSessionEd25519RestoreMetadata | undefined {
  const obj =
    value && typeof value === 'object' && !Array.isArray(value)
      ? (value as Record<string, unknown>)
      : null;
  if (!obj) return undefined;
  const rpId = normalizeOptionalNonEmptyString(obj.rpId);
  const relayerKeyId = normalizeOptionalNonEmptyString(obj.relayerKeyId);
  const sessionKindRaw = String(obj.sessionKind || '').trim();
  const sessionKind =
    sessionKindRaw === 'cookie' || sessionKindRaw === 'jwt' ? sessionKindRaw : undefined;
  const participantIds = Array.isArray(obj.participantIds)
    ? obj.participantIds
        .map((participantId) => Math.floor(Number(participantId)))
        .filter((participantId) => Number.isFinite(participantId) && participantId > 0)
    : [];
  if (!rpId || !relayerKeyId || !sessionKind || !participantIds.length) {
    return undefined;
  }
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(obj.thresholdSessionJwt);
  const xClientBaseB64u = normalizeOptionalNonEmptyString(obj.xClientBaseB64u);
  return {
    rpId,
    relayerKeyId,
    participantIds,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    sessionKind,
    ...(obj.runtimePolicyScope && typeof obj.runtimePolicyScope === 'object'
      ? { runtimePolicyScope: obj.runtimePolicyScope }
      : {}),
    ...(xClientBaseB64u ? { xClientBaseB64u } : {}),
  };
}

type SealedRecordStoreKeyInput =
  | {
      walletSigningSessionId: string;
      authMethod: 'passkey' | 'email_otp';
      curve: 'ed25519';
    }
  | {
      walletSigningSessionId: string;
      authMethod: 'passkey' | 'email_otp';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

function makeSealedRecordStoreKey(args: SealedRecordStoreKeyInput): string {
  if (args.curve === 'ecdsa') {
    return [
      args.walletSigningSessionId,
      args.authMethod,
      args.curve,
      thresholdEcdsaChainTargetKey(args.chainTarget),
    ]
      .map(sealedStoreKeyPart)
      .join(':');
  }
  return [args.walletSigningSessionId, args.authMethod, args.curve]
    .map(sealedStoreKeyPart)
    .join(':');
}

function sealedStoreKeyPart(value: unknown): string {
  return encodeURIComponent(String(value || '').trim());
}

function makeResolvedIdentityKey(identity: ResolvedSigningSessionIdentity): string {
  const chainKey =
    identity.curve === 'ecdsa' ? thresholdEcdsaChainTargetKey(identity.chainTarget) : identity.chain;
  return [
    identity.walletId,
    identity.authMethod,
    identity.curve,
    chainKey,
    identity.walletSigningSessionId,
    identity.thresholdSessionId,
  ]
    .map(sealedStoreKeyPart)
    .join(':');
}

type ResolvedIdentityListKeyInput =
  | {
      walletId: string;
      authMethod?: 'passkey' | 'email_otp';
      curve: 'ed25519';
    }
  | {
      walletId: string;
      authMethod?: 'passkey' | 'email_otp';
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
    };

function makeResolvedIdentityListKey(args: ResolvedIdentityListKeyInput): string {
  return [
    args.walletId,
    args.authMethod || '*',
    args.curve,
    args.curve === 'ecdsa' ? thresholdEcdsaChainTargetKey(args.chainTarget) : 'near',
  ]
    .map(sealedStoreKeyPart)
    .join(':');
}

function resolvedIdentityIndexKeys(identity: ResolvedSigningSessionIdentity): string[] {
  if (identity.curve === 'ecdsa') {
    const base = {
      walletId: identity.walletId,
      curve: identity.curve,
      chainTarget: identity.chainTarget,
    } as const;
    return [
      makeResolvedIdentityListKey(base),
      makeResolvedIdentityListKey({ ...base, authMethod: identity.authMethod }),
    ];
  }
  const base = {
    walletId: identity.walletId,
    curve: identity.curve,
  } as const;
  return [
    makeResolvedIdentityListKey(base),
    makeResolvedIdentityListKey({ ...base, authMethod: identity.authMethod }),
  ];
}

function indexResolvedIdentity(key: string, identity: ResolvedSigningSessionIdentity): void {
  for (const listKey of resolvedIdentityIndexKeys(identity)) {
    const keys = resolvedIdentityKeysByListKey.get(listKey) || new Set<string>();
    keys.add(key);
    resolvedIdentityKeysByListKey.set(listKey, keys);
  }
}

function unindexResolvedIdentity(key: string, identity: ResolvedSigningSessionIdentity): void {
  for (const listKey of resolvedIdentityIndexKeys(identity)) {
    const keys = resolvedIdentityKeysByListKey.get(listKey);
    if (!keys) continue;
    keys.delete(key);
    if (!keys.size) resolvedIdentityKeysByListKey.delete(listKey);
  }
}

function setResolvedIdentity(key: string, identity: ResolvedSigningSessionIdentity): void {
  const existing = resolvedIdentitiesByPurposeKey.get(key);
  if (existing) unindexResolvedIdentity(key, existing);
  resolvedIdentitiesByPurposeKey.set(key, identity);
  indexResolvedIdentity(key, identity);
}

function deleteResolvedIdentityByKey(key: string): void {
  const existing = resolvedIdentitiesByPurposeKey.get(key);
  if (!existing) return;
  unindexResolvedIdentity(key, existing);
  resolvedIdentitiesByPurposeKey.delete(key);
}

function sameResolvedIdentityLane(
  a: ResolvedSigningSessionIdentity,
  b: ResolvedSigningSessionIdentity,
): boolean {
  return (
    a.walletId === b.walletId &&
    a.authMethod === b.authMethod &&
    a.curve === b.curve &&
    (a.curve !== 'ecdsa' ||
      b.curve !== 'ecdsa' ||
      thresholdEcdsaChainTargetsEqual(a.chainTarget, b.chainTarget))
  );
}

function cloneResolvedIdentity(
  identity: ResolvedSigningSessionIdentity,
): ResolvedSigningSessionIdentity {
  return { ...identity } as ResolvedSigningSessionIdentity;
}

function normalizeAuthMethod(value: unknown): 'passkey' | 'email_otp' | undefined {
  const authMethod = String(value || '').trim();
  return authMethod === 'passkey' || authMethod === 'email_otp' ? authMethod : undefined;
}

function normalizeEcdsaChain(value: unknown): 'tempo' | 'evm' | undefined {
  const chain = String(value || '').trim();
  return chain === 'tempo' || chain === 'evm' ? chain : undefined;
}

function normalizeResolvedIdentity(
  value: PublishResolvedIdentityInput,
): ResolvedSigningSessionIdentity | null {
  const walletId = normalizeOptionalNonEmptyString(value.walletId);
  const authMethod = normalizeAuthMethod(value.authMethod);
  const curve = normalizeCurve(value.curve);
  const walletSigningSessionId = normalizeOptionalNonEmptyString(value.walletSigningSessionId);
  const thresholdSessionId = normalizeOptionalNonEmptyString(value.thresholdSessionId);
  const updatedAtMs = normalizeInteger(value.updatedAtMs ?? Date.now());
  if (
    !walletId ||
    !authMethod ||
    !curve ||
    !walletSigningSessionId ||
    !thresholdSessionId ||
    updatedAtMs == null ||
    updatedAtMs <= 0
  ) {
    return null;
  }
  if (curve === 'ed25519') {
    return {
      walletId,
      authMethod,
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId,
      thresholdSessionId,
      updatedAtMs,
    };
  }
  const ecdsaValue = value as Extract<PublishResolvedIdentityInput, { curve: 'ecdsa' }>;
  let chainTarget: ThresholdEcdsaChainTarget | null = null;
  try {
    chainTarget = thresholdEcdsaChainTargetFromRequest(
      ecdsaValue.chainTarget &&
        typeof ecdsaValue.chainTarget === 'object' &&
        !Array.isArray(ecdsaValue.chainTarget)
        ? (ecdsaValue.chainTarget as Record<string, unknown>)
        : {},
    );
  } catch {
    chainTarget = null;
  }
  if (!chainTarget) return null;
  return {
    walletId,
    authMethod,
    curve: 'ecdsa',
    chainTarget,
    walletSigningSessionId,
    thresholdSessionId,
    updatedAtMs,
  };
}

function resolvedIdentitiesForSealedRecord(
  record: SigningSessionSealedStoreRecord,
): PublishResolvedIdentityInput[] {
  const walletId = normalizeOptionalNonEmptyString(record.walletId || record.userId);
  if (!walletId) return [];
  const identities: PublishResolvedIdentityInput[] = [];
  const ecdsaThresholdSessionId = normalizeOptionalNonEmptyString(record.thresholdSessionIds.ecdsa);
  const ecdsaChainTarget = record.ecdsaRestore?.chainTarget;
  if (ecdsaThresholdSessionId && ecdsaChainTarget) {
    identities.push({
      walletId,
      authMethod: record.authMethod,
      curve: 'ecdsa',
      chainTarget: ecdsaChainTarget,
      walletSigningSessionId: record.walletSigningSessionId,
      thresholdSessionId: ecdsaThresholdSessionId,
      updatedAtMs: record.updatedAtMs,
    });
  }
  const ed25519ThresholdSessionId = normalizeOptionalNonEmptyString(
    record.thresholdSessionIds.ed25519,
  );
  if (ed25519ThresholdSessionId) {
    identities.push({
      walletId,
      authMethod: record.authMethod,
      curve: 'ed25519',
      chain: 'near',
      walletSigningSessionId: record.walletSigningSessionId,
      thresholdSessionId: ed25519ThresholdSessionId,
      updatedAtMs: record.updatedAtMs,
    });
  }
  return identities;
}

function publishResolvedIdentityForSealedRecord(record: SigningSessionSealedStoreRecord): void {
  // A durable seal can carry both the ECDSA lane and its Ed25519 companion.
  // The sealed store is the single local owner for publishing those runtime
  // identities so snapshot reads do not reconstruct them from volatile records.
  for (const identity of resolvedIdentitiesForSealedRecord(record)) {
    publishResolvedIdentity(identity);
  }
}

function deleteResolvedIdentityForSealedRecord(record: SigningSessionSealedStoreRecord): void {
  for (const identity of resolvedIdentitiesForSealedRecord(record)) {
    deleteResolvedIdentity(identity);
  }
}

function sealedRecordAccountKeys(record: SigningSessionSealedStoreRecord): Set<string> {
  const keys = new Set<string>();
  const walletId = normalizeOptionalNonEmptyString(record.walletId);
  const userId = normalizeOptionalNonEmptyString(record.userId);
  if (walletId) keys.add(walletId);
  if (userId) keys.add(userId);
  return keys;
}

function sealedRecordsShareAccount(
  left: SigningSessionSealedStoreRecord,
  right: SigningSessionSealedStoreRecord,
): boolean {
  const leftKeys = sealedRecordAccountKeys(left);
  if (!leftKeys.size) return false;
  for (const key of sealedRecordAccountKeys(right)) {
    if (leftKeys.has(key)) return true;
  }
  return false;
}

function sealedRecordsHaveSamePurpose(
  left: SigningSessionSealedStoreRecord,
  right: SigningSessionSealedStoreRecord,
): boolean {
  if (!sealedRecordsShareAccount(left, right)) return false;
  if (left.authMethod !== right.authMethod || left.curve !== right.curve) return false;
  if (left.curve === 'ecdsa') {
    const leftTarget = left.ecdsaRestore?.chainTarget;
    const rightTarget = right.ecdsaRestore?.chainTarget;
    if (!leftTarget || !rightTarget) return false;
    if (!thresholdEcdsaChainTargetsEqual(leftTarget, rightTarget)) return false;
  }

  const leftSigningRootId = normalizeOptionalNonEmptyString(left.signingRootId);
  const rightSigningRootId = normalizeOptionalNonEmptyString(right.signingRootId);
  // Missing signingRootId is legacy/incomplete metadata. Treat it as same scope
  // so old durable seals cannot keep polluting exact lane selection.
  if (leftSigningRootId && rightSigningRootId && leftSigningRootId !== rightSigningRootId) {
    return false;
  }
  return true;
}

export function publishResolvedIdentity(
  input: PublishResolvedIdentityInput,
): ResolvedSigningSessionIdentity | null {
  const identity = normalizeResolvedIdentity(input);
  if (!identity) return null;
  // A wallet/auth/curve/chain has exactly one selected runtime identity. Reauth
  // may mint a new threshold session without rewriting durable seals, so replace
  // stale selections here instead of letting lane resolution see both.
  const listKey =
    identity.curve === 'ecdsa'
      ? makeResolvedIdentityListKey({
          walletId: identity.walletId,
          authMethod: identity.authMethod,
          curve: 'ecdsa',
          chainTarget: identity.chainTarget,
        })
      : makeResolvedIdentityListKey({
          walletId: identity.walletId,
          authMethod: identity.authMethod,
          curve: 'ed25519',
        });
  for (const key of [...(resolvedIdentityKeysByListKey.get(listKey) || [])]) {
    const existing = resolvedIdentitiesByPurposeKey.get(key);
    if (existing && sameResolvedIdentityLane(existing, identity)) {
      deleteResolvedIdentityByKey(key);
    }
  }
  setResolvedIdentity(makeResolvedIdentityKey(identity), identity);
  return cloneResolvedIdentity(identity);
}

function deleteResolvedIdentity(input: PublishResolvedIdentityInput): void {
  const identity = normalizeResolvedIdentity(input);
  if (!identity) return;
  deleteResolvedIdentityByKey(makeResolvedIdentityKey(identity));
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

  const authMethod = String(obj.authMethod || '').trim();
  const walletSigningSessionId = normalizeOptionalNonEmptyString(obj.walletSigningSessionId);
  const thresholdSessionIds = normalizeThresholdSessionIds(obj.thresholdSessionIds);
  const sealedSecretB64u = normalizeOptionalNonEmptyString(obj.sealedSecretB64u);
  const curve = normalizeCurve(obj.curve);
  const subjectId = normalizeOptionalNonEmptyString(obj.subjectId);
  const walletId = normalizeOptionalNonEmptyString(obj.walletId);
  const userId = normalizeOptionalNonEmptyString(obj.userId);
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const relayerUrl = normalizeOptionalNonEmptyString(obj.relayerUrl);
  const keyVersion = normalizeOptionalNonEmptyString(obj.keyVersion);
  const shamirPrimeB64u = normalizeOptionalNonEmptyString(obj.shamirPrimeB64u);
  const ecdsaRestore = normalizeEcdsaRestoreMetadata(obj.ecdsaRestore);
  const ed25519Restore = normalizeEd25519RestoreMetadata(obj.ed25519Restore);
  const issuedAtMs = normalizeInteger(obj.issuedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs);

  if (!walletSigningSessionId || !sealedSecretB64u) return null;
  if (authMethod !== 'passkey' && authMethod !== 'email_otp') return null;
  if (!thresholdSessionIds.ed25519 && !thresholdSessionIds.ecdsa) return null;
  const recordCurve = resolveSealedRecordCurve({ curve, thresholdSessionIds });
  if (!recordCurve) return null;
  if (recordCurve === 'ecdsa' && !ecdsaRestore?.chainTarget) return null;
  if (recordCurve === 'ecdsa' && !subjectId) return null;
  if (issuedAtMs == null || issuedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= 0) return null;
  if (remainingUses == null || remainingUses < 0) return null;
  if (updatedAtMs == null || updatedAtMs <= 0) return null;
  const storeKey =
    recordCurve === 'ecdsa'
      ? (() => {
          const chainTarget = ecdsaRestore?.chainTarget;
          if (!chainTarget) return null;
          return makeSealedRecordStoreKey({
            walletSigningSessionId,
            authMethod,
            curve: 'ecdsa',
            chainTarget,
          });
        })()
      : makeSealedRecordStoreKey({
          walletSigningSessionId,
          authMethod,
          curve: 'ed25519',
        });
  if (!storeKey) return null;
  const providedStoreKey = normalizeOptionalNonEmptyString(obj.storeKey);
  if (providedStoreKey && providedStoreKey !== storeKey) return null;

  return {
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    authMethod,
    secretKind: SIGNING_SESSION_SECRET_KIND,
    storeKey,
    walletSigningSessionId,
    thresholdSessionIds,
    sealedSecretB64u,
    curve: recordCurve,
    ...(subjectId ? { subjectId } : {}),
    ...(walletId ? { walletId } : {}),
    ...(userId ? { userId } : {}),
    ...(signingRootId ? { signingRootId } : {}),
    ...(signingRootVersion ? { signingRootVersion } : {}),
    ...(relayerUrl ? { relayerUrl } : {}),
    ...(keyVersion ? { keyVersion } : {}),
    ...(shamirPrimeB64u ? { shamirPrimeB64u } : {}),
    ...(ecdsaRestore ? { ecdsaRestore } : {}),
    ...(ed25519Restore ? { ed25519Restore } : {}),
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
  const leaseKey = normalizeOptionalNonEmptyString(obj.leaseKey);
  const walletSigningSessionId = normalizeOptionalNonEmptyString(obj.walletSigningSessionId);
  const ownerId = normalizeOptionalNonEmptyString(obj.ownerId);
  const attemptId = normalizeOptionalNonEmptyString(obj.attemptId);
  const startedAtMs = normalizeInteger(obj.startedAtMs);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  if (!leaseKey || !walletSigningSessionId || !ownerId || !attemptId) return null;
  if (startedAtMs == null || startedAtMs <= 0) return null;
  if (expiresAtMs == null || expiresAtMs <= startedAtMs) return null;
  return {
    v: 1,
    leaseKey,
    walletSigningSessionId,
    ownerId,
    attemptId,
    startedAtMs,
    expiresAtMs,
  };
}

function makeSigningSessionRestoreLease(args: {
  leaseKey: string;
  walletSigningSessionId: string;
  ownerId: string;
  nowMs: number;
  ttlMs: number;
}): SigningSessionRestoreLease {
  return {
    v: 1,
    leaseKey: args.leaseKey,
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
  if (
    filter.curve === 'ecdsa' &&
    (!record.ecdsaRestore?.chainTarget ||
      !thresholdEcdsaChainTargetsEqual(record.ecdsaRestore.chainTarget, filter.chainTarget))
  ) {
    return false;
  }
  return true;
}

function requireSealedRecordPurpose(
  filter: SigningSessionSealedRecordFilter | undefined,
  operation: string,
): SigningSessionSealedRecordFilter {
  if (filter?.authMethod && filter.curve === 'ed25519') return filter;
  if (
    filter?.authMethod &&
    filter.curve === 'ecdsa' &&
    filter.chainTarget
  ) {
    return filter;
  }
  console.warn('[SigningSessionSealedStore] rejected ambiguous sealed record access', {
    operation,
  });
  throw new Error(
    `[SigningSessionSealedStore] ${operation} requires an explicit authMethod, curve, and ECDSA chain target`,
  );
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

async function listSameScopeRecords(
  db: IDBDatabase,
  record: SigningSessionSealedStoreRecord,
): Promise<SigningSessionSealedStoreRecord[]> {
  if (!sealedRecordAccountKeys(record).size || !record.authMethod) return [];
  try {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const store = tx.objectStore(STORE_NAME);
    const all = await requestToPromise<unknown[]>(store.getAll());
    const records: SigningSessionSealedStoreRecord[] = [];
    for (const entry of all) {
      const existing = normalizeSigningSessionSealedStoreRecord(entry);
      if (!existing) continue;
      if (existing.storeKey === record.storeKey) continue;
      if (sealedRecordsHaveSamePurpose(existing, record)) {
        records.push(existing);
      }
    }
    await transactionDone(tx).catch(() => undefined);
    return records;
  } catch {
    return [];
  }
}

export async function readExactSealedSession(
  thresholdSessionIdRaw: string,
  filter: SigningSessionSealedRecordFilter,
): Promise<SigningSessionSealedStoreRecord | null> {
  const purpose = requireSealedRecordPurpose(filter, 'read');
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const db = await openSigningSessionSealsDb();
  if (!db) return null;
  try {
    const record = await readRecordByThresholdSessionId(db, thresholdSessionId, purpose, 'read');
    return record;
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function listExactSealedSessionsForAccount(args: {
  accountId: string;
  filter: ListExactSigningSessionSealedRecordsForAccountFilter;
}): Promise<SigningSessionSealedStoreRecord[]> {
  const accountId = normalizeOptionalNonEmptyString(args.accountId);
  if (!accountId) return [];
  const purpose = requireSealedRecordPurpose(args.filter, 'list exact account records');
  const chainTarget = args.filter.curve === 'ecdsa' ? args.filter.chainTarget : undefined;
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
      if (record.walletId !== accountId && record.userId !== accountId) continue;
      if (record.authMethod !== purpose.authMethod) continue;
      if (!record.thresholdSessionIds[purpose.curve]) continue;
      if (
        chainTarget &&
        (!record.ecdsaRestore?.chainTarget ||
          !thresholdEcdsaChainTargetsEqual(record.ecdsaRestore.chainTarget, chainTarget))
      ) {
        continue;
      }
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

export async function writeExactSealedSession(
  args: WriteExactSealedSessionInput,
): Promise<void> {
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
  const subjectId = normalizeOptionalNonEmptyString(args.subjectId);
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
  const ed25519Restore = normalizeEd25519RestoreMetadata(args.ed25519Restore);
  if (curve === 'ecdsa' && !ecdsaRestore?.chainTarget) {
    console.warn('[SigningSessionSealedStore] rejected ECDSA sealed record write without chain target', {
      thresholdSessionId,
      authMethod,
    });
    return;
  }
  if (curve === 'ecdsa' && !subjectId) {
    console.warn('[SigningSessionSealedStore] rejected ECDSA sealed record write without subject id', {
      thresholdSessionId,
      authMethod,
    });
    return;
  }

  const record = normalizeSigningSessionSealedStoreRecord({
    v: SIGNING_SESSION_SEALED_RECORD_VERSION,
    alg: SIGNING_SESSION_SEAL_ALG,
    storageScope: SIGNING_SESSION_SEAL_STORAGE_SCOPE,
    authMethod,
    secretKind: SIGNING_SESSION_SECRET_KIND,
    walletSigningSessionId,
    thresholdSessionIds,
    sealedSecretB64u,
    ...(curve ? { curve } : {}),
    ...(subjectId ? { subjectId } : {}),
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
    ...(ed25519Restore ? { ed25519Restore } : {}),
    issuedAtMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  });
  if (!record) return;

  const db = await openSigningSessionSealsDb();
  if (!db) return;
  try {
    const staleRecords = await listSameScopeRecords(db, record);
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store = tx.objectStore(STORE_NAME);
    for (const staleRecord of staleRecords) {
      deleteResolvedIdentityForSealedRecord(staleRecord);
      store.delete(staleRecord.storeKey);
    }
    store.put(record);
    await transactionDone(tx).catch(() => undefined);
    publishResolvedIdentityForSealedRecord(record);
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function updateExactSealedSessionPolicy(args: {
  thresholdSessionId: string;
  filter: SigningSessionSealedRecordFilter;
  expiresAtMs?: number;
  remainingUses?: number;
  updatedAtMs?: number;
}): Promise<void> {
  const purpose = requireSealedRecordPurpose(args.filter, 'update policy');
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const existing = await readExactSealedSession(thresholdSessionId, purpose);
  if (!existing) return;
  const expiresAtMs = normalizeInteger(args.expiresAtMs ?? existing.expiresAtMs);
  const remainingUses = normalizeInteger(args.remainingUses ?? existing.remainingUses);
  const updatedAtMs = normalizeInteger(args.updatedAtMs ?? Date.now());
  if (expiresAtMs == null || expiresAtMs <= 0) return;
  if (remainingUses == null || remainingUses < 0) return;
  if (updatedAtMs == null || updatedAtMs <= 0) return;
  const base = {
    thresholdSessionId,
    sealedSecretB64u: existing.sealedSecretB64u,
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
    ed25519Restore: existing.ed25519Restore,
    issuedAtMs: existing.issuedAtMs,
    expiresAtMs,
    remainingUses,
    updatedAtMs,
  };
  if (purpose.curve === 'ecdsa') {
    const subjectId = normalizeOptionalNonEmptyString(existing.subjectId);
    if (!subjectId) return;
    await writeExactSealedSession({
      ...base,
      curve: 'ecdsa',
      subjectId,
    });
    return;
  }
  await writeExactSealedSession({
    ...base,
    curve: 'ed25519',
  });
}

export async function deleteExactSealedSession(
  thresholdSessionIdRaw: string,
  filter: SigningSessionSealedRecordFilter,
  options?: {
    deleteResolvedIdentity?: boolean;
  },
): Promise<void> {
  const purpose = requireSealedRecordPurpose(filter, 'delete');
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return;
  const db = await openSigningSessionSealsDb();
  if (!db) return;
  try {
    const record = await readRecordByThresholdSessionId(db, thresholdSessionId, purpose, 'delete');
    await deleteRecordByThresholdSessionId(db, thresholdSessionId, purpose);
    if (record?.walletSigningSessionId && options?.deleteResolvedIdentity !== false) {
      deleteResolvedIdentityForSealedRecord(record);
      const tx = db.transaction(LEASE_STORE_NAME, 'readwrite');
      tx.objectStore(LEASE_STORE_NAME).delete(record.storeKey);
      await transactionDone(tx).catch(() => undefined);
    }
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function acquireSigningSessionRestoreLease(
  args: {
    thresholdSessionId: string;
    ownerId?: string;
    nowMs?: number;
    ttlMs?: number;
  } & SigningSessionSealedRecordFilter,
): Promise<SigningSessionRestoreLeaseHandle | null> {
  const purpose = requireSealedRecordPurpose(args, 'acquire restore lease');
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const nowMs = normalizeInteger(args.nowMs ?? Date.now()) ?? Date.now();
  const ttlMs = Math.max(
    1,
    normalizeInteger(args.ttlMs ?? DEFAULT_RESTORE_LEASE_TTL_MS) ?? DEFAULT_RESTORE_LEASE_TTL_MS,
  );
  const ownerId = normalizeOptionalNonEmptyString(args.ownerId) || createRandomId('restore-owner');
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
      tx.abort();
      return null;
    }

    const leaseStore = tx.objectStore(LEASE_STORE_NAME);
    const existing = normalizeSigningSessionRestoreLease(
      await requestToPromise(leaseStore.get(record.storeKey)),
    );
    if (existing && existing.expiresAtMs > nowMs && existing.ownerId !== ownerId) {
      tx.abort();
      return null;
    }

    const lease = makeSigningSessionRestoreLease({
      leaseKey: record.storeKey,
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
      await requestToPromise(store.get(lease.leaseKey)),
    );
    if (existing?.ownerId === lease.ownerId && existing.attemptId === lease.attemptId) {
      store.delete(lease.leaseKey);
    }
    await transactionDone(tx).catch(() => undefined);
  } finally {
    try {
      db.close();
    } catch {}
  }
}

export async function clearAllSealedSessions(): Promise<void> {
  resolvedIdentitiesByPurposeKey.clear();
  resolvedIdentityKeysByListKey.clear();
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
