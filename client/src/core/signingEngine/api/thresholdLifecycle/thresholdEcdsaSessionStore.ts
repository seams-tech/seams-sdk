import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import { normalizeInteger, normalizeOptionalNonEmptyString } from '@shared/utils/normalize';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import { normalizeThresholdEcdsaSessionKind } from './normalization';
import type { ThresholdEcdsaSecp256k1KeyRef } from '../../interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';

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

export type ThresholdEcdsaSessionStoreDeps = {
  recordsByAccount: Map<string, ThresholdEcdsaSessionRecord>;
  now?: () => number;
};

type ThresholdEcdsaSessionStoreValue = {
  v: 1;
  record: ThresholdEcdsaSessionRecord;
};

type SessionStoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

const STORAGE_KEY_PREFIX = 'tatchi:threshold-ecdsa-session:v1';
const STORAGE_INDEX_KEY = `${STORAGE_KEY_PREFIX}:index`;

function getSessionStorageSafe(): SessionStoragePort | null {
  const globalObj = globalThis as { sessionStorage?: SessionStoragePort };
  if (!globalObj?.sessionStorage) return null;
  try {
    const storage = globalObj.sessionStorage;
    storage.getItem('__tatchi_threshold_ecdsa_probe__');
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
  const accountId = String(nearAccountId);
  const current = readStorageIndex(storage);
  if (current.includes(accountId)) return;
  writeStorageIndex(storage, [...current, accountId]);
}

function removeFromStorageIndex(storage: SessionStoragePort, nearAccountId: AccountId): void {
  const accountId = String(nearAccountId);
  const current = readStorageIndex(storage);
  const next = current.filter((entry) => entry !== accountId);
  if (next.length === current.length) return;
  writeStorageIndex(storage, next);
}

function readStoredRecord(
  storage: SessionStoragePort,
  nearAccountId: AccountId,
): ThresholdEcdsaSessionRecord | null {
  try {
    const raw = storage.getItem(storageKeyForAccount(nearAccountId));
    if (!raw) return null;
    const parsed = JSON.parse(raw) as ThresholdEcdsaSessionStoreValue;
    if (!parsed || parsed.v !== 1 || typeof parsed !== 'object') return null;
    return normalizeThresholdEcdsaSessionRecord(parsed.record);
  } catch {
    return null;
  }
}

function writeStoredRecord(storage: SessionStoragePort, record: ThresholdEcdsaSessionRecord): void {
  try {
    const payload: ThresholdEcdsaSessionStoreValue = {
      v: 1,
      record,
    };
    storage.setItem(storageKeyForAccount(record.nearAccountId), JSON.stringify(payload));
    addToStorageIndex(storage, record.nearAccountId);
  } catch {}
}

function clearStoredRecord(storage: SessionStoragePort, nearAccountId: AccountId): void {
  try {
    storage.removeItem(storageKeyForAccount(nearAccountId));
  } catch {}
  removeFromStorageIndex(storage, nearAccountId);
}

function clearAllStoredRecords(storage: SessionStoragePort): void {
  const index = readStorageIndex(storage);
  for (const accountId of index) {
    try {
      storage.removeItem(storageKeyForAccount(toAccountId(accountId)));
    } catch {}
  }
  try {
    storage.removeItem(STORAGE_INDEX_KEY);
  } catch {}
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

function buildRecordFromBootstrap(args: {
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
    throw new Error(
      '[SigningEngine] threshold ECDSA bootstrap did not provide thresholdSessionJwt',
    );
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
  const record = buildRecordFromBootstrap({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    bootstrap: args.bootstrap,
    source: args.source,
    nowMs,
  });
  const accountKey = String(record.nearAccountId);
  deps.recordsByAccount.set(accountKey, record);
  const storage = getSessionStorageSafe();
  if (storage) {
    writeStoredRecord(storage, record);
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

  const storage = getSessionStorageSafe();
  const stored = storage ? readStoredRecord(storage, accountId) : null;
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
  const storage = getSessionStorageSafe();
  if (storage) {
    clearStoredRecord(storage, accountId);
  }
}

export function clearAllThresholdEcdsaSessionRecords(deps: ThresholdEcdsaSessionStoreDeps): void {
  deps.recordsByAccount.clear();
  const storage = getSessionStorageSafe();
  if (storage) {
    clearAllStoredRecords(storage);
  }
}

export function getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
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
