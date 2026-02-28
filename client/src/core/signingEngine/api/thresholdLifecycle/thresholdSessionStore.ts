import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeInteger,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { normalizeThresholdEcdsaSessionKind } from './normalization';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';

export type ThresholdSessionCurve = 'ed25519' | 'ecdsa';

export type ThresholdEcdsaSessionStoreSource = 'login' | 'registration' | 'manual-bootstrap';

export type ThresholdEcdsaSessionRecord = {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  relayerUrl: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  participantIds: number[];
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  thresholdSessionJwt?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  groupPublicKeyB64u?: string;
  relayerVerifyingShareB64u?: string;
  updatedAtMs: number;
  source: ThresholdEcdsaSessionStoreSource;
};

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

export type ThresholdSessionRecordByCurve = {
  ed25519: ThresholdEd25519SessionRecord;
  ecdsa: ThresholdEcdsaSessionRecord;
};

export type ThresholdEcdsaSessionStoreDeps = {
  recordsByAccount: Map<string, ThresholdEcdsaSessionRecord>;
  now?: () => number;
};

type SessionStoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

type VersionedRecord<TRecord> = {
  v: 1;
  record: TRecord;
};

const ECDSA_STORAGE_KEY_PREFIX = 'tatchi:threshold-ecdsa-session:v1';
const ECDSA_STORAGE_INDEX_KEY = `${ECDSA_STORAGE_KEY_PREFIX}:index`;

const ED25519_STORAGE_KEY_PREFIX = 'tatchi:threshold-ed25519-session:v1';
const ED25519_STORAGE_INDEX_KEY = `${ED25519_STORAGE_KEY_PREFIX}:index`;

function getSessionStorageSafe(probeKey: string): SessionStoragePort | null {
  const globalObj = globalThis as { sessionStorage?: SessionStoragePort };
  if (!globalObj?.sessionStorage) return null;
  try {
    const storage = globalObj.sessionStorage;
    storage.getItem(probeKey);
    return storage;
  } catch {
    return null;
  }
}

function storageKeyForAccount(storageKeyPrefix: string, nearAccountId: AccountId): string {
  return `${storageKeyPrefix}:${String(nearAccountId)}`;
}

function readStorageIndex(storage: SessionStoragePort, storageIndexKey: string): string[] {
  try {
    const raw = storage.getItem(storageIndexKey);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.map((value) => String(value || '').trim()).filter(Boolean);
  } catch {
    return [];
  }
}

function writeStorageIndex(
  storage: SessionStoragePort,
  storageIndexKey: string,
  accounts: string[],
): void {
  try {
    storage.setItem(storageIndexKey, JSON.stringify(accounts));
  } catch {}
}

function addToStorageIndex(
  storage: SessionStoragePort,
  storageIndexKey: string,
  nearAccountId: AccountId,
): void {
  const accountId = String(nearAccountId || '').trim();
  if (!accountId) return;
  const current = readStorageIndex(storage, storageIndexKey);
  if (current.includes(accountId)) return;
  writeStorageIndex(storage, storageIndexKey, [...current, accountId]);
}

function removeFromStorageIndex(
  storage: SessionStoragePort,
  storageIndexKey: string,
  nearAccountId: AccountId,
): void {
  const accountId = String(nearAccountId || '').trim();
  if (!accountId) return;
  const current = readStorageIndex(storage, storageIndexKey);
  const next = current.filter((entry) => entry !== accountId);
  if (next.length === current.length) return;
  writeStorageIndex(storage, storageIndexKey, next);
}

function writeStoredRecord<TRecord>(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  storageIndexKey: string;
  nearAccountId: AccountId;
  record: TRecord;
}): void {
  try {
    const payload: VersionedRecord<TRecord> = {
      v: 1,
      record: args.record,
    };
    args.storage.setItem(
      storageKeyForAccount(args.storageKeyPrefix, args.nearAccountId),
      JSON.stringify(payload),
    );
    addToStorageIndex(args.storage, args.storageIndexKey, args.nearAccountId);
  } catch {}
}

function readStoredRecord<TRecord>(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  nearAccountId: AccountId;
  normalize: (value: unknown) => TRecord;
}): TRecord | null {
  try {
    const raw = args.storage.getItem(storageKeyForAccount(args.storageKeyPrefix, args.nearAccountId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as VersionedRecord<TRecord>;
    if (!parsed || parsed.v !== 1 || typeof parsed !== 'object') return null;
    return args.normalize(parsed.record);
  } catch {
    return null;
  }
}

function clearStoredRecord(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  storageIndexKey: string;
  nearAccountId: AccountId;
}): void {
  try {
    args.storage.removeItem(storageKeyForAccount(args.storageKeyPrefix, args.nearAccountId));
  } catch {}
  removeFromStorageIndex(args.storage, args.storageIndexKey, args.nearAccountId);
}

function clearAllStoredRecords(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  storageIndexKey: string;
}): void {
  const index = readStorageIndex(args.storage, args.storageIndexKey);
  for (const accountId of index) {
    try {
      args.storage.removeItem(storageKeyForAccount(args.storageKeyPrefix, toAccountId(accountId)));
    } catch {}
  }
  try {
    args.storage.removeItem(args.storageIndexKey);
  } catch {}
}

function getEcdsaSessionStorageSafe(): SessionStoragePort | null {
  return getSessionStorageSafe('__tatchi_threshold_ecdsa_probe__');
}

function getEd25519SessionStorageSafe(): SessionStoragePort | null {
  return getSessionStorageSafe('__tatchi_threshold_ed25519_session_probe__');
}

function normalizeThresholdEcdsaSessionRecord(value: unknown): ThresholdEcdsaSessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const nearAccountId = toAccountId(String(obj.nearAccountId || '').trim());
  const chainRaw = String(obj.chain || '').trim();
  const chain: ThresholdEcdsaActivationChain = chainRaw === 'evm' ? 'evm' : 'tempo';
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const clientVerifyingShareB64u = String(obj.clientVerifyingShareB64u || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const thresholdSessionKind = normalizeThresholdEcdsaSessionKind(obj.thresholdSessionKind);
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(obj.thresholdSessionJwt);
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEcdsaSessionStoreSource =
    sourceRaw === 'login' || sourceRaw === 'registration' || sourceRaw === 'manual-bootstrap'
      ? sourceRaw
      : 'manual-bootstrap';
  const updatedAtMs = normalizeInteger(obj.updatedAtMs) || Date.now();
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const groupPublicKeyB64u = normalizeOptionalNonEmptyString(obj.groupPublicKeyB64u);
  const relayerVerifyingShareB64u = normalizeOptionalNonEmptyString(obj.relayerVerifyingShareB64u);

  if (
    !relayerUrl ||
    !relayerKeyId ||
    !clientVerifyingShareB64u ||
    !participantIds ||
    !thresholdSessionId
  ) {
    throw new Error('Invalid threshold ECDSA canonical session record');
  }
  if (thresholdSessionKind === 'jwt' && !thresholdSessionJwt) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing JWT');
  }

  return {
    nearAccountId,
    chain,
    relayerUrl,
    relayerKeyId,
    clientVerifyingShareB64u,
    participantIds,
    thresholdSessionKind,
    thresholdSessionId,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    ...(expiresAtMs != null ? { expiresAtMs } : {}),
    ...(remainingUses != null ? { remainingUses } : {}),
    ...(groupPublicKeyB64u ? { groupPublicKeyB64u } : {}),
    ...(relayerVerifyingShareB64u ? { relayerVerifyingShareB64u } : {}),
    updatedAtMs,
    source,
  };
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

function buildEcdsaRecordFromBootstrap(args: {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  source: ThresholdEcdsaSessionStoreSource;
  nowMs: number;
}): ThresholdEcdsaSessionRecord {
  const accountId = toAccountId(args.nearAccountId);
  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const participantIds = normalizeThresholdEd25519ParticipantIds(keyRef.participantIds);
  if (!participantIds) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide participantIds');
  }
  const thresholdSessionId = String(
    keyRef.thresholdSessionId || args.bootstrap.session.sessionId || '',
  ).trim();
  if (!thresholdSessionId) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide thresholdSessionId');
  }
  const thresholdSessionKind = normalizeThresholdEcdsaSessionKind(keyRef.thresholdSessionKind || 'jwt');
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(
    keyRef.thresholdSessionJwt || args.bootstrap.session.jwt,
  );
  if (thresholdSessionKind === 'jwt' && !thresholdSessionJwt) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide thresholdSessionJwt');
  }

  return normalizeThresholdEcdsaSessionRecord({
    nearAccountId: accountId,
    chain: args.chain,
    relayerUrl: keyRef.relayerUrl,
    relayerKeyId: keyRef.relayerKeyId,
    clientVerifyingShareB64u: keyRef.clientVerifyingShareB64u,
    participantIds,
    thresholdSessionKind,
    thresholdSessionId,
    thresholdSessionJwt,
    expiresAtMs: args.bootstrap.session.expiresAtMs,
    remainingUses: args.bootstrap.session.remainingUses,
    groupPublicKeyB64u: keyRef.groupPublicKeyB64u,
    relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
    updatedAtMs: args.nowMs,
    source: args.source,
  });
}

export function upsertThresholdEcdsaSessionFromBootstrap(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord {
  const nowMs = Math.max(0, Math.floor((deps.now || Date.now)()));
  const record = buildEcdsaRecordFromBootstrap({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    bootstrap: args.bootstrap,
    source: args.source,
    nowMs,
  });
  const accountKey = String(record.nearAccountId);
  deps.recordsByAccount.set(accountKey, record);
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    writeStoredRecord({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
      nearAccountId: record.nearAccountId,
      record,
    });
  }
  return record;
}

export function getThresholdEcdsaSessionRecordForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain?: ThresholdEcdsaActivationChain;
  },
): ThresholdEcdsaSessionRecord {
  const accountId = toAccountId(args.nearAccountId);
  const accountKey = String(accountId);
  const inMemory = deps.recordsByAccount.get(accountKey);
  if (inMemory) return inMemory;

  const storage = getEcdsaSessionStorageSafe();
  const stored = storage
    ? readStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        nearAccountId: accountId,
        normalize: normalizeThresholdEcdsaSessionRecord,
      })
    : null;
  if (stored) {
    deps.recordsByAccount.set(accountKey, stored);
    return stored;
  }

  throw new Error(
    `[SigningEngine] missing canonical threshold ECDSA session for ${accountKey}; reconnect threshold session via bootstrapEcdsaSession`,
  );
}

export function getThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain?: ThresholdEcdsaActivationChain;
  },
): ThresholdEcdsaSecp256k1KeyRef {
  const record = getThresholdEcdsaSessionRecordForSigning(deps, args);
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: String(record.nearAccountId),
    relayerUrl: record.relayerUrl,
    relayerKeyId: record.relayerKeyId,
    clientVerifyingShareB64u: record.clientVerifyingShareB64u,
    participantIds: record.participantIds,
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    ...(record.thresholdSessionJwt ? { thresholdSessionJwt: record.thresholdSessionJwt } : {}),
    ...(record.groupPublicKeyB64u ? { groupPublicKeyB64u: record.groupPublicKeyB64u } : {}),
    ...(record.relayerVerifyingShareB64u
      ? { relayerVerifyingShareB64u: record.relayerVerifyingShareB64u }
      : {}),
  };
}

export function clearThresholdEcdsaSessionRecordForAccount(
  deps: ThresholdEcdsaSessionStoreDeps,
  nearAccountId: AccountId | string,
): void {
  const accountId = toAccountId(nearAccountId);
  const accountKey = String(accountId);
  deps.recordsByAccount.delete(accountKey);
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    clearStoredRecord({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
      nearAccountId: accountId,
    });
  }
}

export function clearAllThresholdEcdsaSessionRecords(deps: ThresholdEcdsaSessionStoreDeps): void {
  deps.recordsByAccount.clear();
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    clearAllStoredRecords({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
    });
  }
}

export function getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const storage = getEcdsaSessionStorageSafe();
  if (!storage) return null;
  const accountIds = readStorageIndex(storage, ECDSA_STORAGE_INDEX_KEY);
  for (const accountIdRaw of accountIds) {
    try {
      const nearAccountId = toAccountId(accountIdRaw);
      const record = readStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        nearAccountId,
        normalize: normalizeThresholdEcdsaSessionRecord,
      });
      if (!record) continue;
      if (String(record.thresholdSessionId || '').trim() === thresholdSessionId) {
        return record;
      }
    } catch {}
  }
  return null;
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
  const storage = getEd25519SessionStorageSafe();
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
  writeStoredRecord({
    storage,
    storageKeyPrefix: ED25519_STORAGE_KEY_PREFIX,
    storageIndexKey: ED25519_STORAGE_INDEX_KEY,
    nearAccountId: record.nearAccountId,
    record,
  });
  return record;
}

export function getStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  const storage = getEd25519SessionStorageSafe();
  if (!storage) return null;
  try {
    const nearAccountId = toAccountId(nearAccountIdRaw);
    return readStoredRecord({
      storage,
      storageKeyPrefix: ED25519_STORAGE_KEY_PREFIX,
      nearAccountId,
      normalize: normalizeThresholdEd25519SessionRecord,
    });
  } catch {
    return null;
  }
}

export function getStoredThresholdEd25519SessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const storage = getEd25519SessionStorageSafe();
  if (!storage) return null;
  const accountIds = readStorageIndex(storage, ED25519_STORAGE_INDEX_KEY);
  for (const accountIdRaw of accountIds) {
    try {
      const nearAccountId = toAccountId(accountIdRaw);
      const record = readStoredRecord({
        storage,
        storageKeyPrefix: ED25519_STORAGE_KEY_PREFIX,
        nearAccountId,
        normalize: normalizeThresholdEd25519SessionRecord,
      });
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
  const storage = getEd25519SessionStorageSafe();
  if (!storage) return;
  try {
    const nearAccountId = toAccountId(nearAccountIdRaw);
    clearStoredRecord({
      storage,
      storageKeyPrefix: ED25519_STORAGE_KEY_PREFIX,
      storageIndexKey: ED25519_STORAGE_INDEX_KEY,
      nearAccountId,
    });
  } catch {}
}

export function clearAllStoredThresholdEd25519SessionRecords(): void {
  const storage = getEd25519SessionStorageSafe();
  if (!storage) return;
  clearAllStoredRecords({
    storage,
    storageKeyPrefix: ED25519_STORAGE_KEY_PREFIX,
    storageIndexKey: ED25519_STORAGE_INDEX_KEY,
  });
}

export function getStoredThresholdSessionRecordForAccount<TCurve extends ThresholdSessionCurve>(args: {
  curve: TCurve;
  nearAccountId: AccountId | string;
}): ThresholdSessionRecordByCurve[TCurve] | null {
  if (args.curve === 'ecdsa') {
    const storage = getEcdsaSessionStorageSafe();
    if (!storage) return null;
    try {
      return readStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        nearAccountId: toAccountId(args.nearAccountId),
        normalize: normalizeThresholdEcdsaSessionRecord,
      }) as ThresholdSessionRecordByCurve[TCurve] | null;
    } catch {
      return null;
    }
  }
  return getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId) as
    | ThresholdSessionRecordByCurve[TCurve]
    | null;
}

export function getStoredThresholdSessionRecordByThresholdSessionId<TCurve extends ThresholdSessionCurve>(
  args: {
    curve: TCurve;
    thresholdSessionId: string;
  },
): ThresholdSessionRecordByCurve[TCurve] | null {
  if (args.curve === 'ecdsa') {
    return getStoredThresholdEcdsaSessionRecordByThresholdSessionId(args.thresholdSessionId) as
      | ThresholdSessionRecordByCurve[TCurve]
      | null;
  }
  return getStoredThresholdEd25519SessionRecordByThresholdSessionId(args.thresholdSessionId) as
    | ThresholdSessionRecordByCurve[TCurve]
    | null;
}

export function clearAllStoredThresholdSessionRecords(curve?: ThresholdSessionCurve): void {
  if (!curve || curve === 'ed25519') {
    clearAllStoredThresholdEd25519SessionRecords();
  }
  if (!curve || curve === 'ecdsa') {
    const storage = getEcdsaSessionStorageSafe();
    if (!storage) return;
    clearAllStoredRecords({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
    });
  }
}
