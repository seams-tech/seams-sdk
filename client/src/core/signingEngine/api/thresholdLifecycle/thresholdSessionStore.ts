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

export type ThresholdEcdsaSessionJwtSource = 'ecdsa' | 'ed25519' | 'none';

export type ThresholdEcdsaSessionAuthMaterial = {
  record: ThresholdEcdsaSessionRecord;
  thresholdSessionJwt?: string;
  thresholdSessionJwtSource: ThresholdEcdsaSessionJwtSource;
};

export type ThresholdSessionSealTransportAuthMaterial = {
  curve: ThresholdSessionCurve;
  relayerUrl: string;
  thresholdSessionJwt?: string;
  thresholdSessionJwtSource: ThresholdEcdsaSessionJwtSource;
};

export type ThresholdEcdsaSessionStoreDeps = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  now?: () => number;
};

type SessionStoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

type VersionedRecord<TRecord> = {
  v: 1;
  record: TRecord;
};

const ECDSA_STORAGE_KEY_PREFIX_V1 = 'tatchi:threshold-ecdsa-session:v1';
const ECDSA_STORAGE_INDEX_KEY_V1 = `${ECDSA_STORAGE_KEY_PREFIX_V1}:index`;
const ECDSA_STORAGE_SESSION_INDEX_KEY_V1 = `${ECDSA_STORAGE_KEY_PREFIX_V1}:session-index`;
const ECDSA_STORAGE_KEY_PREFIX = 'tatchi:threshold-ecdsa-session:v2';
const ECDSA_STORAGE_INDEX_KEY = `${ECDSA_STORAGE_KEY_PREFIX}:index`;
const ECDSA_STORAGE_SESSION_INDEX_KEY = `${ECDSA_STORAGE_KEY_PREFIX}:session-index`;
const ECDSA_STORAGE_MIGRATION_KEY = `${ECDSA_STORAGE_KEY_PREFIX}:migrated-from-v1`;

const ED25519_STORAGE_KEY_PREFIX = 'tatchi:threshold-ed25519-session:v1';
const ED25519_STORAGE_INDEX_KEY = `${ED25519_STORAGE_KEY_PREFIX}:index`;
const ED25519_STORAGE_SESSION_INDEX_KEY = `${ED25519_STORAGE_KEY_PREFIX}:session-index`;

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

function storageKeyForRecord(storageKeyPrefix: string, recordKeyRaw: string): string {
  const recordKey = String(recordKeyRaw || '').trim();
  return `${storageKeyPrefix}:${recordKey}`;
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

function readStorageSessionIndex(
  storage: SessionStoragePort,
  storageSessionIndexKey: string,
): Record<string, string> {
  try {
    const raw = storage.getItem(storageSessionIndexKey);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    const out: Record<string, string> = {};
    for (const [sessionIdRaw, accountIdRaw] of Object.entries(parsed)) {
      const sessionId = String(sessionIdRaw || '').trim();
      const accountId = String(accountIdRaw || '').trim();
      if (!sessionId || !accountId) continue;
      out[sessionId] = accountId;
    }
    return out;
  } catch {
    return {};
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

function writeStorageSessionIndex(
  storage: SessionStoragePort,
  storageSessionIndexKey: string,
  index: Record<string, string>,
): void {
  try {
    storage.setItem(storageSessionIndexKey, JSON.stringify(index));
  } catch {}
}

function setStorageSessionIndexEntry(args: {
  storage: SessionStoragePort;
  storageSessionIndexKey: string;
  thresholdSessionId: string;
  recordKey: string;
}): void {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const recordKey = String(args.recordKey || '').trim();
  if (!thresholdSessionId || !recordKey) return;
  const current = readStorageSessionIndex(args.storage, args.storageSessionIndexKey);
  if (current[thresholdSessionId] === recordKey) return;
  current[thresholdSessionId] = recordKey;
  writeStorageSessionIndex(args.storage, args.storageSessionIndexKey, current);
}

function removeStorageSessionIndexEntry(args: {
  storage: SessionStoragePort;
  storageSessionIndexKey: string;
  thresholdSessionId: string;
}): void {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return;
  const current = readStorageSessionIndex(args.storage, args.storageSessionIndexKey);
  if (!(thresholdSessionId in current)) return;
  delete current[thresholdSessionId];
  writeStorageSessionIndex(args.storage, args.storageSessionIndexKey, current);
}

function removeStorageSessionIndexEntriesForRecordKey(args: {
  storage: SessionStoragePort;
  storageSessionIndexKey: string;
  recordKey: string;
}): void {
  const recordKey = String(args.recordKey || '').trim();
  if (!recordKey) return;
  const current = readStorageSessionIndex(args.storage, args.storageSessionIndexKey);
  let changed = false;
  for (const [sessionId, indexedRecordKey] of Object.entries(current)) {
    if (indexedRecordKey !== recordKey) continue;
    delete current[sessionId];
    changed = true;
  }
  if (!changed) return;
  writeStorageSessionIndex(args.storage, args.storageSessionIndexKey, current);
}

function addToStorageIndex(
  storage: SessionStoragePort,
  storageIndexKey: string,
  recordKey: string,
): void {
  const normalized = String(recordKey || '').trim();
  if (!normalized) return;
  const current = readStorageIndex(storage, storageIndexKey);
  if (current.includes(normalized)) return;
  writeStorageIndex(storage, storageIndexKey, [...current, normalized]);
}

function removeFromStorageIndex(
  storage: SessionStoragePort,
  storageIndexKey: string,
  recordKeyRaw: string,
): void {
  const recordKey = String(recordKeyRaw || '').trim();
  if (!recordKey) return;
  const current = readStorageIndex(storage, storageIndexKey);
  const next = current.filter((entry) => entry !== recordKey);
  if (next.length === current.length) return;
  writeStorageIndex(storage, storageIndexKey, next);
}

function writeStoredRecord<TRecord>(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  storageIndexKey: string;
  storageSessionIndexKey?: string;
  recordKey: string;
  record: TRecord;
  thresholdSessionId?: string;
}): void {
  const recordKey = String(args.recordKey || '').trim();
  if (!recordKey) return;
  try {
    const payload: VersionedRecord<TRecord> = {
      v: 1,
      record: args.record,
    };
    args.storage.setItem(
      storageKeyForRecord(args.storageKeyPrefix, recordKey),
      JSON.stringify(payload),
    );
    addToStorageIndex(args.storage, args.storageIndexKey, recordKey);
    if (args.storageSessionIndexKey && String(args.thresholdSessionId || '').trim()) {
      setStorageSessionIndexEntry({
        storage: args.storage,
        storageSessionIndexKey: args.storageSessionIndexKey,
        thresholdSessionId: String(args.thresholdSessionId || '').trim(),
        recordKey,
      });
    }
  } catch {}
}

function readStoredRecord<TRecord>(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  recordKey: string;
  normalize: (value: unknown) => TRecord;
}): TRecord | null {
  const recordKey = String(args.recordKey || '').trim();
  if (!recordKey) return null;
  try {
    const raw = args.storage.getItem(storageKeyForRecord(args.storageKeyPrefix, recordKey));
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
  storageSessionIndexKey?: string;
  recordKey: string;
}): void {
  const recordKey = String(args.recordKey || '').trim();
  if (!recordKey) return;
  try {
    args.storage.removeItem(storageKeyForRecord(args.storageKeyPrefix, recordKey));
  } catch {}
  removeFromStorageIndex(args.storage, args.storageIndexKey, recordKey);
  if (args.storageSessionIndexKey) {
    removeStorageSessionIndexEntriesForRecordKey({
      storage: args.storage,
      storageSessionIndexKey: args.storageSessionIndexKey,
      recordKey,
    });
  }
}

function clearAllStoredRecords(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  storageIndexKey: string;
  storageSessionIndexKey?: string;
}): void {
  const index = readStorageIndex(args.storage, args.storageIndexKey);
  for (const recordKey of index) {
    try {
      args.storage.removeItem(storageKeyForRecord(args.storageKeyPrefix, recordKey));
    } catch {}
  }
  try {
    args.storage.removeItem(args.storageIndexKey);
  } catch {}
  if (args.storageSessionIndexKey) {
    try {
      args.storage.removeItem(args.storageSessionIndexKey);
    } catch {}
  }
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
  const chain = normalizeThresholdEcdsaActivationChain(obj.chain);
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
    !chain ||
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

export type ThresholdEcdsaSessionLane = {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  relayerKeyId: string;
};

function normalizeThresholdEcdsaActivationChain(
  chainRaw: unknown,
): ThresholdEcdsaActivationChain | null {
  const chain = String(chainRaw || '')
    .trim()
    .toLowerCase();
  if (chain === 'tempo' || chain === 'evm') return chain;
  return null;
}

function encodeLaneToken(value: string): string {
  return encodeURIComponent(String(value || '').trim());
}

function decodeLaneToken(value: string): string | null {
  try {
    const decoded = decodeURIComponent(String(value || '').trim());
    return decoded || null;
  } catch {
    return null;
  }
}

export function serializeThresholdEcdsaSessionLaneKey(args: {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  relayerKeyId: string;
}): string {
  const nearAccountId = String(toAccountId(args.nearAccountId)).trim();
  const chain = normalizeThresholdEcdsaActivationChain(args.chain);
  const relayerKeyId = String(args.relayerKeyId || '').trim();
  if (!nearAccountId || !chain || !relayerKeyId) {
    throw new Error('[SigningEngine] invalid threshold ECDSA lane key input');
  }
  return [
    encodeLaneToken(nearAccountId),
    encodeLaneToken(chain),
    encodeLaneToken(relayerKeyId),
  ].join('|');
}

export function parseThresholdEcdsaSessionLaneKey(
  laneKeyRaw: string,
): ThresholdEcdsaSessionLane | null {
  const laneKey = String(laneKeyRaw || '').trim();
  if (!laneKey) return null;
  const parts = laneKey.split('|');
  if (parts.length !== 3) return null;
  const nearAccountDecoded = decodeLaneToken(parts[0] || '');
  const chainDecoded = decodeLaneToken(parts[1] || '');
  const relayerKeyIdDecoded = decodeLaneToken(parts[2] || '');
  if (!nearAccountDecoded || !chainDecoded || !relayerKeyIdDecoded) return null;
  const chain = normalizeThresholdEcdsaActivationChain(chainDecoded);
  if (!chain) return null;
  try {
    return {
      nearAccountId: toAccountId(nearAccountDecoded),
      chain,
      relayerKeyId: relayerKeyIdDecoded,
    };
  } catch {
    return null;
  }
}

function getThresholdEcdsaSessionLaneKeyForRecord(record: ThresholdEcdsaSessionRecord): string {
  return serializeThresholdEcdsaSessionLaneKey({
    nearAccountId: record.nearAccountId,
    chain: record.chain,
    relayerKeyId: record.relayerKeyId,
  });
}

function pickPreferredThresholdEcdsaSessionRecord(
  a: ThresholdEcdsaSessionRecord | null,
  b: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaSessionRecord {
  if (!a) return b;
  const aUpdatedAtMs = normalizeInteger(a.updatedAtMs) || 0;
  const bUpdatedAtMs = normalizeInteger(b.updatedAtMs) || 0;
  if (bUpdatedAtMs !== aUpdatedAtMs) {
    return bUpdatedAtMs > aUpdatedAtMs ? b : a;
  }
  const aExpiresAtMs = normalizeInteger(a.expiresAtMs) || 0;
  const bExpiresAtMs = normalizeInteger(b.expiresAtMs) || 0;
  if (bExpiresAtMs !== aExpiresAtMs) {
    return bExpiresAtMs > aExpiresAtMs ? b : a;
  }
  return String(b.thresholdSessionId || '').localeCompare(String(a.thresholdSessionId || '')) > 0
    ? b
    : a;
}

let ecdsaStorageMigrationAttempted = false;

function importCanonicalEcdsaRecordsFromStorage(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  storageIndexKey: string;
}): Map<string, ThresholdEcdsaSessionRecord> {
  const recordsByLane = new Map<string, ThresholdEcdsaSessionRecord>();
  const recordKeys = readStorageIndex(args.storage, args.storageIndexKey);
  for (const recordKey of recordKeys) {
    const stored = readStoredRecord({
      storage: args.storage,
      storageKeyPrefix: args.storageKeyPrefix,
      recordKey,
      normalize: normalizeThresholdEcdsaSessionRecord,
    });
    if (!stored) continue;
    const canonicalLaneKey = getThresholdEcdsaSessionLaneKeyForRecord(stored);
    const next = pickPreferredThresholdEcdsaSessionRecord(
      recordsByLane.get(canonicalLaneKey) || null,
      stored,
    );
    recordsByLane.set(canonicalLaneKey, next);
  }
  return recordsByLane;
}

function deleteStoredRecordsByIndex(args: {
  storage: SessionStoragePort;
  storageKeyPrefix: string;
  storageIndexKey: string;
  storageSessionIndexKey?: string;
}): void {
  const recordKeys = readStorageIndex(args.storage, args.storageIndexKey);
  for (const recordKey of recordKeys) {
    try {
      args.storage.removeItem(storageKeyForRecord(args.storageKeyPrefix, recordKey));
    } catch {}
  }
  try {
    args.storage.removeItem(args.storageIndexKey);
  } catch {}
  if (args.storageSessionIndexKey) {
    try {
      args.storage.removeItem(args.storageSessionIndexKey);
    } catch {}
  }
}

function writeCanonicalEcdsaRecords(args: {
  storage: SessionStoragePort;
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
}): void {
  for (const [laneKey, record] of args.recordsByLane.entries()) {
    writeStoredRecord({
      storage: args.storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
      recordKey: laneKey,
      record,
      thresholdSessionId: record.thresholdSessionId,
    });
  }
}

function ensureEcdsaStorageMigrated(storage: SessionStoragePort): void {
  if (ecdsaStorageMigrationAttempted) return;
  ecdsaStorageMigrationAttempted = true;
  const migrationMarker = String(storage.getItem(ECDSA_STORAGE_MIGRATION_KEY) || '').trim();
  if (migrationMarker) return;

  const mergedByLane = importCanonicalEcdsaRecordsFromStorage({
    storage,
    storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
    storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
  });
  const legacyByLane = importCanonicalEcdsaRecordsFromStorage({
    storage,
    storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX_V1,
    storageIndexKey: ECDSA_STORAGE_INDEX_KEY_V1,
  });
  for (const [laneKey, record] of legacyByLane.entries()) {
    const winner = pickPreferredThresholdEcdsaSessionRecord(
      mergedByLane.get(laneKey) || null,
      record,
    );
    mergedByLane.set(laneKey, winner);
  }

  deleteStoredRecordsByIndex({
    storage,
    storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
    storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
    storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
  });
  if (mergedByLane.size > 0) {
    writeCanonicalEcdsaRecords({ storage, recordsByLane: mergedByLane });
  }
  deleteStoredRecordsByIndex({
    storage,
    storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX_V1,
    storageIndexKey: ECDSA_STORAGE_INDEX_KEY_V1,
    storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY_V1,
  });
  try {
    storage.setItem(ECDSA_STORAGE_MIGRATION_KEY, String(Date.now()));
  } catch {}
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
  const thresholdSessionKind = normalizeThresholdEcdsaSessionKind(
    keyRef.thresholdSessionKind || 'jwt',
  );
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
  const record = buildEcdsaRecordFromBootstrap({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    bootstrap: args.bootstrap,
    source: args.source,
    nowMs,
  });
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  deps.recordsByLane.set(laneKey, record);
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    ensureEcdsaStorageMigrated(storage);
    const previousRecord = readStoredRecord({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      recordKey: laneKey,
      normalize: normalizeThresholdEcdsaSessionRecord,
    });
    if (
      previousRecord &&
      String(previousRecord.thresholdSessionId || '').trim() &&
      String(previousRecord.thresholdSessionId || '').trim() !==
        String(record.thresholdSessionId || '').trim()
    ) {
      removeStorageSessionIndexEntry({
        storage,
        storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
        thresholdSessionId: previousRecord.thresholdSessionId,
      });
    }
    writeStoredRecord({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
      recordKey: laneKey,
      record,
      thresholdSessionId: record.thresholdSessionId,
    });
  }
  return record;
}

function pickThresholdEcdsaRecordForChain(
  records: ThresholdEcdsaSessionRecord[],
): ThresholdEcdsaSessionRecord | null {
  let selected: ThresholdEcdsaSessionRecord | null = null;
  for (const candidate of records) {
    selected = pickPreferredThresholdEcdsaSessionRecord(selected, candidate);
  }
  return selected;
}

function listInMemoryThresholdEcdsaRecordsForLane(args: {
  deps: ThresholdEcdsaSessionStoreDeps;
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
}): ThresholdEcdsaSessionRecord[] {
  const out: ThresholdEcdsaSessionRecord[] = [];
  for (const record of args.deps.recordsByLane.values()) {
    if (String(record.nearAccountId) !== String(args.nearAccountId)) continue;
    if (record.chain !== args.chain) continue;
    out.push(record);
  }
  return out;
}

function listStoredThresholdEcdsaRecordsForLane(args: {
  storage: SessionStoragePort;
  deps: ThresholdEcdsaSessionStoreDeps;
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
}): ThresholdEcdsaSessionRecord[] {
  const out: ThresholdEcdsaSessionRecord[] = [];
  ensureEcdsaStorageMigrated(args.storage);
  const laneKeys = readStorageIndex(args.storage, ECDSA_STORAGE_INDEX_KEY);
  for (const laneKey of laneKeys) {
    const parsedLane = parseThresholdEcdsaSessionLaneKey(laneKey);
    if (!parsedLane) continue;
    if (String(parsedLane.nearAccountId) !== String(args.nearAccountId)) continue;
    if (parsedLane.chain !== args.chain) continue;
    const record = readStoredRecord({
      storage: args.storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      recordKey: laneKey,
      normalize: normalizeThresholdEcdsaSessionRecord,
    });
    if (!record) continue;
    const canonicalLaneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    args.deps.recordsByLane.set(canonicalLaneKey, record);
    out.push(record);
  }
  return out;
}

export function getThresholdEcdsaSessionRecordForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  },
): ThresholdEcdsaSessionRecord {
  const accountId = toAccountId(args.nearAccountId);
  const inMemory = pickThresholdEcdsaRecordForChain(
    listInMemoryThresholdEcdsaRecordsForLane({
      deps,
      nearAccountId: accountId,
      chain: args.chain,
    }),
  );
  if (inMemory) return inMemory;

  const storage = getEcdsaSessionStorageSafe();
  const stored = storage
    ? pickThresholdEcdsaRecordForChain(
        listStoredThresholdEcdsaRecordsForLane({
          storage,
          deps,
          nearAccountId: accountId,
          chain: args.chain,
        }),
      )
    : null;
  if (stored) {
    return stored;
  }

  throw new Error(
    `[SigningEngine] missing canonical threshold ECDSA session for ${String(accountId)}; reconnect threshold session via bootstrapEcdsaSession`,
  );
}

export function getThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
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
  for (const [laneKey, record] of deps.recordsByLane.entries()) {
    if (String(record.nearAccountId) !== accountKey) continue;
    deps.recordsByLane.delete(laneKey);
  }
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    ensureEcdsaStorageMigrated(storage);
    const laneKeys = readStorageIndex(storage, ECDSA_STORAGE_INDEX_KEY);
    for (const laneKey of laneKeys) {
      const parsedLane = parseThresholdEcdsaSessionLaneKey(laneKey);
      if (!parsedLane) continue;
      if (String(parsedLane.nearAccountId) !== accountKey) continue;
      clearStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
        storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
        recordKey: laneKey,
      });
    }
  }
}

export function clearAllThresholdEcdsaSessionRecords(deps: ThresholdEcdsaSessionStoreDeps): void {
  deps.recordsByLane.clear();
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    ensureEcdsaStorageMigrated(storage);
    clearAllStoredRecords({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
    });
    deleteStoredRecordsByIndex({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX_V1,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY_V1,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY_V1,
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
  ensureEcdsaStorageMigrated(storage);
  const sessionIndex = readStorageSessionIndex(storage, ECDSA_STORAGE_SESSION_INDEX_KEY);
  const indexedLaneKey = String(sessionIndex[thresholdSessionId] || '').trim();
  if (indexedLaneKey) {
    try {
      const indexedRecord = readStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        recordKey: indexedLaneKey,
        normalize: normalizeThresholdEcdsaSessionRecord,
      });
      if (
        indexedRecord &&
        String(indexedRecord.thresholdSessionId || '').trim() === thresholdSessionId
      ) {
        return indexedRecord;
      }
      removeStorageSessionIndexEntry({
        storage,
        storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
        thresholdSessionId,
      });
    } catch {
      removeStorageSessionIndexEntry({
        storage,
        storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
        thresholdSessionId,
      });
    }
  }
  const laneKeys = readStorageIndex(storage, ECDSA_STORAGE_INDEX_KEY);
  for (const laneKey of laneKeys) {
    try {
      const record = readStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        recordKey: laneKey,
        normalize: normalizeThresholdEcdsaSessionRecord,
      });
      if (!record) continue;
      if (String(record.thresholdSessionId || '').trim() === thresholdSessionId) {
        setStorageSessionIndexEntry({
          storage,
          storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
          thresholdSessionId,
          recordKey: getThresholdEcdsaSessionLaneKeyForRecord(record),
        });
        return record;
      }
    } catch {}
  }
  return null;
}

export function resolveThresholdEcdsaSessionAuthMaterialByThresholdSessionId(args: {
  thresholdSessionId: string;
  nearAccountIdFallback?: AccountId | string;
}): ThresholdEcdsaSessionAuthMaterial | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;

  const record = getStoredThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
  if (!record) return null;

  const recordJwt = normalizeOptionalNonEmptyString(record.thresholdSessionJwt);
  if (recordJwt) {
    return {
      record,
      thresholdSessionJwt: recordJwt,
      thresholdSessionJwtSource: 'ecdsa',
    };
  }

  const nearAccountIdFallback = String(
    record.nearAccountId || args.nearAccountIdFallback || '',
  ).trim();
  if (!nearAccountIdFallback) {
    return {
      record,
      thresholdSessionJwtSource: 'none',
    };
  }

  const ed25519Record = getStoredThresholdEd25519SessionRecordForAccount(nearAccountIdFallback);
  if (!ed25519Record || ed25519Record.thresholdSessionKind !== 'jwt') {
    return {
      record,
      thresholdSessionJwtSource: 'none',
    };
  }

  const ed25519Jwt = normalizeOptionalNonEmptyString(ed25519Record.thresholdSessionJwt);
  if (!ed25519Jwt) {
    return {
      record,
      thresholdSessionJwtSource: 'none',
    };
  }

  return {
    record,
    thresholdSessionJwt: ed25519Jwt,
    thresholdSessionJwtSource: 'ed25519',
  };
}

export function resolveThresholdSessionSealTransportByThresholdSessionId(args: {
  thresholdSessionId: string;
  nearAccountIdFallback?: AccountId | string;
}): ThresholdSessionSealTransportAuthMaterial | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;

  const ecdsa = resolveThresholdEcdsaSessionAuthMaterialByThresholdSessionId({
    thresholdSessionId,
    nearAccountIdFallback: args.nearAccountIdFallback,
  });
  if (ecdsa) {
    const relayerUrl = String(ecdsa.record.relayerUrl || '').trim();
    if (!relayerUrl) return null;
    return {
      curve: 'ecdsa',
      relayerUrl,
      ...(String(ecdsa.thresholdSessionJwt || '').trim()
        ? { thresholdSessionJwt: String(ecdsa.thresholdSessionJwt || '').trim() }
        : {}),
      thresholdSessionJwtSource: ecdsa.thresholdSessionJwtSource,
    };
  }

  const ed25519Record =
    getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
  if (!ed25519Record) return null;
  const relayerUrl = String(ed25519Record.relayerUrl || '').trim();
  if (!relayerUrl) return null;
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(ed25519Record.thresholdSessionJwt);
  return {
    curve: 'ed25519',
    relayerUrl,
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    thresholdSessionJwtSource: thresholdSessionJwt ? 'ed25519' : 'none',
  };
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
    thresholdSessionKind: String(args.thresholdSessionKind || 'jwt')
      .trim()
      .toLowerCase(),
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
    storageSessionIndexKey: ED25519_STORAGE_SESSION_INDEX_KEY,
    recordKey: String(record.nearAccountId),
    record,
    thresholdSessionId: record.thresholdSessionId,
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
      recordKey: String(nearAccountId),
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
  const sessionIndex = readStorageSessionIndex(storage, ED25519_STORAGE_SESSION_INDEX_KEY);
  const indexedAccountIdRaw = String(sessionIndex[thresholdSessionId] || '').trim();
  if (indexedAccountIdRaw) {
    try {
      const indexedAccountId = toAccountId(indexedAccountIdRaw);
      const indexedRecord = readStoredRecord({
        storage,
        storageKeyPrefix: ED25519_STORAGE_KEY_PREFIX,
        recordKey: String(indexedAccountId),
        normalize: normalizeThresholdEd25519SessionRecord,
      });
      if (
        indexedRecord &&
        String(indexedRecord.thresholdSessionId || '').trim() === thresholdSessionId
      ) {
        return indexedRecord;
      }
      removeStorageSessionIndexEntry({
        storage,
        storageSessionIndexKey: ED25519_STORAGE_SESSION_INDEX_KEY,
        thresholdSessionId,
      });
    } catch {
      removeStorageSessionIndexEntry({
        storage,
        storageSessionIndexKey: ED25519_STORAGE_SESSION_INDEX_KEY,
        thresholdSessionId,
      });
    }
  }
  const accountIds = readStorageIndex(storage, ED25519_STORAGE_INDEX_KEY);
  for (const accountIdRaw of accountIds) {
    try {
      const nearAccountId = toAccountId(accountIdRaw);
      const record = readStoredRecord({
        storage,
        storageKeyPrefix: ED25519_STORAGE_KEY_PREFIX,
        recordKey: String(nearAccountId),
        normalize: normalizeThresholdEd25519SessionRecord,
      });
      if (!record) continue;
      if (String(record.thresholdSessionId || '').trim() === thresholdSessionId) {
        setStorageSessionIndexEntry({
          storage,
          storageSessionIndexKey: ED25519_STORAGE_SESSION_INDEX_KEY,
          thresholdSessionId,
          recordKey: String(record.nearAccountId),
        });
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
      storageSessionIndexKey: ED25519_STORAGE_SESSION_INDEX_KEY,
      recordKey: String(nearAccountId),
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
    storageSessionIndexKey: ED25519_STORAGE_SESSION_INDEX_KEY,
  });
}

export function getStoredThresholdSessionRecordForAccount<
  TCurve extends ThresholdSessionCurve,
>(args: {
  curve: TCurve;
  nearAccountId: AccountId | string;
  chain?: ThresholdEcdsaActivationChain;
}): ThresholdSessionRecordByCurve[TCurve] | null {
  if (args.curve === 'ecdsa') {
    const storage = getEcdsaSessionStorageSafe();
    if (!storage) return null;
    ensureEcdsaStorageMigrated(storage);
    const nearAccountId = toAccountId(args.nearAccountId);
    const laneKeys = readStorageIndex(storage, ECDSA_STORAGE_INDEX_KEY);
    let selected: ThresholdEcdsaSessionRecord | null = null;
    for (const laneKey of laneKeys) {
      const parsedLane = parseThresholdEcdsaSessionLaneKey(laneKey);
      if (!parsedLane) continue;
      if (String(parsedLane.nearAccountId) !== String(nearAccountId)) continue;
      if (args.chain && parsedLane.chain !== args.chain) continue;
      const record = readStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        recordKey: laneKey,
        normalize: normalizeThresholdEcdsaSessionRecord,
      });
      if (!record) continue;
      selected = pickPreferredThresholdEcdsaSessionRecord(selected, record);
    }
    return selected as ThresholdSessionRecordByCurve[TCurve] | null;
  }
  return getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId) as
    | ThresholdSessionRecordByCurve[TCurve]
    | null;
}

export function getStoredThresholdSessionRecordByThresholdSessionId<
  TCurve extends ThresholdSessionCurve,
>(args: {
  curve: TCurve;
  thresholdSessionId: string;
}): ThresholdSessionRecordByCurve[TCurve] | null {
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
    ensureEcdsaStorageMigrated(storage);
    clearAllStoredRecords({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
    });
    deleteStoredRecordsByIndex({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX_V1,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY_V1,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY_V1,
    });
  }
}
