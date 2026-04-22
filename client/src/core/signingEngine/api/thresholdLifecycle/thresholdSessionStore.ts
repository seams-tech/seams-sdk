import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeInteger,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy } from '@/core/types/tatchi';
import { normalizeThresholdEcdsaSessionKind } from './normalization';
import type {
  ThresholdEcdsaClientAdditiveShareHandle,
  EcdsaThresholdKeyId,
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import type {
  ThresholdEcdsaActivationChain,
  ThresholdEcdsaSessionBootstrapResult,
} from '../../orchestration/thresholdActivation';
import {
  normalizeThresholdRuntimePolicyScope,
  parseThresholdRuntimePolicyScopeFromJwt,
  type ThresholdRuntimePolicyScope,
} from '../../threshold/session/sessionPolicy';
import { signingRootScopeFromRuntimePolicyScope } from '@shared/threshold/signingRootScope';

export type ThresholdSessionCurve = 'ed25519' | 'ecdsa';

export type ThresholdEcdsaSessionStoreSource =
  | 'login'
  | 'registration'
  | 'manual-bootstrap'
  | 'email_otp';

export const THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES = [
  'login',
  'registration',
  'manual-bootstrap',
] as const satisfies readonly ThresholdEcdsaSessionStoreSource[];

export type ThresholdEcdsaEmailOtpAuthContext = {
  policy: EmailOtpAuthPolicy;
  retention: 'session' | 'single_use';
  reason: 'login' | 'sign';
  authMethod: 'email_otp';
  consumedAtMs?: number;
};

export type ThresholdEcdsaSessionRecord = {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  relayerUrl: string;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion?: string;
  relayerKeyId: string;
  clientVerifyingShareB64u: string;
  clientAdditiveShare32B64u?: string;
  clientAdditiveShareHandle?: ThresholdEcdsaClientAdditiveShareHandle;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  walletSigningSessionId?: string;
  thresholdSessionJwt?: string;
  signingSessionSealKeyVersion?: string;
  signingSessionSealShamirPrimeB64u?: string;
  expiresAtMs?: number;
  remainingUses?: number;
  thresholdEcdsaPublicKeyB64u?: string;
  ethereumAddress?: string;
  relayerVerifyingShareB64u?: string;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs: number;
  source: ThresholdEcdsaSessionStoreSource;
};

export type ThresholdEd25519SessionStoreSource =
  | 'login'
  | 'registration'
  | 'manual-connect'
  | 'bootstrap'
  | 'email_otp';

export type ThresholdEd25519SessionRecord = {
  nearAccountId: AccountId;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  xClientBaseB64u?: string;
  thresholdSessionKind: 'jwt' | 'cookie';
  thresholdSessionId: string;
  walletSigningSessionId?: string;
  thresholdSessionJwt?: string;
  expiresAtMs: number;
  remainingUses: number;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs: number;
  source: ThresholdEd25519SessionStoreSource;
};

export type ThresholdSessionRecordByCurve = {
  ed25519: ThresholdEd25519SessionRecord;
  ecdsa: ThresholdEcdsaSessionRecord;
};

export type ThresholdEcdsaSessionJwtSource = 'ecdsa' | 'ed25519' | 'none';

export type ThresholdSessionSealTransportAuthMaterial = {
  curve: ThresholdSessionCurve;
  relayerUrl: string;
  thresholdSessionJwt?: string;
  thresholdSessionJwtSource: ThresholdEcdsaSessionJwtSource;
  keyVersion?: string;
  shamirPrimeB64u?: string;
};

export type ThresholdEcdsaSessionStoreDeps = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane?: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
  now?: () => number;
};

type SessionStoragePort = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

type VersionedRecord<TRecord> = {
  v: 1;
  record: TRecord;
};

const ECDSA_STORAGE_KEY_PREFIX = 'tatchi:threshold-ecdsa-session:v3';
const ECDSA_STORAGE_INDEX_KEY = `${ECDSA_STORAGE_KEY_PREFIX}:index`;
const ECDSA_STORAGE_SESSION_INDEX_KEY = `${ECDSA_STORAGE_KEY_PREFIX}:session-index`;

const ED25519_STORAGE_KEY_PREFIX = 'tatchi:threshold-ed25519-session:v1';
const ED25519_STORAGE_INDEX_KEY = `${ED25519_STORAGE_KEY_PREFIX}:index`;
const ED25519_STORAGE_SESSION_INDEX_KEY = `${ED25519_STORAGE_KEY_PREFIX}:session-index`;
const inMemoryEd25519RecordsByAccount = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519AccountBySessionId = new Map<string, string>();

function normalizeThresholdEcdsaCanonicalExportArtifact(
  value: unknown,
): ThresholdEcdsaCanonicalExportArtifact | null {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!obj) return null;
  const artifactKind = String(obj.artifactKind || '').trim();
  const chain = String(obj.chain || '').trim();
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const publicKeyHex = String(obj.publicKeyHex || '').trim();
  const privateKeyHex = String(obj.privateKeyHex || '').trim();
  const ethereumAddress = String(obj.ethereumAddress || '').trim();
  if (
    artifactKind !== 'ecdsa-hss-secp256k1-key-v1' ||
    (chain !== 'evm' && chain !== 'tempo') ||
    !signingRootId ||
    !publicKeyHex ||
    !privateKeyHex ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    artifactKind: 'ecdsa-hss-secp256k1-key-v1',
    chain,
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    publicKeyHex,
    privateKeyHex,
    ethereumAddress,
  };
}

function getSessionStorageSafe(
  probeKey: string,
  curve: 'ecdsa' | 'ed25519',
): SessionStoragePort | null {
  const globalObj = globalThis as {
    sessionStorage?: SessionStoragePort;
  };
  const storage = globalObj?.sessionStorage;
  if (!storage) return null;
  try {
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
      removeStorageSessionIndexEntriesForRecordKey({
        storage: args.storage,
        storageSessionIndexKey: args.storageSessionIndexKey,
        recordKey,
      });
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
  return getSessionStorageSafe('__tatchi_threshold_ecdsa_probe__', 'ecdsa');
}

function getEd25519SessionStorageSafe(): SessionStoragePort | null {
  return getSessionStorageSafe('__tatchi_threshold_ed25519_session_probe__', 'ed25519');
}

function normalizeStoredRuntimePolicyScope(
  obj: Record<string, unknown>,
  jwt?: string,
): ThresholdRuntimePolicyScope | undefined {
  if (Object.prototype.hasOwnProperty.call(obj, 'runtimeSnapshotScope')) {
    throw new Error('Invalid threshold session record: stale runtimeSnapshotScope');
  }
  if (Object.prototype.hasOwnProperty.call(obj, 'runtimePolicyScope')) {
    const runtimePolicyScope = normalizeThresholdRuntimePolicyScope(obj.runtimePolicyScope);
    if (!runtimePolicyScope) {
      throw new Error('Invalid threshold session record: stale runtimePolicyScope');
    }
    return runtimePolicyScope;
  }
  return parseThresholdRuntimePolicyScopeFromJwt(jwt);
}

function getSigningRootBindingFromRuntimePolicyScope(
  runtimePolicyScope: ThresholdRuntimePolicyScope | undefined,
): { signingRootId: string; signingRootVersion?: string } | null {
  if (!runtimePolicyScope) return null;
  try {
    const scope = signingRootScopeFromRuntimePolicyScope(runtimePolicyScope);
    const signingRootId = normalizeOptionalNonEmptyString(scope.signingRootId);
    const signingRootVersion = normalizeOptionalNonEmptyString(scope.signingRootVersion);
    if (!signingRootId) return null;
    return {
      signingRootId,
      ...(signingRootVersion ? { signingRootVersion } : {}),
    };
  } catch {
    return null;
  }
}

function normalizeStoredSigningRootBinding(
  obj: Record<string, unknown>,
  runtimePolicyScope: ThresholdRuntimePolicyScope | undefined,
): { signingRootId: string; signingRootVersion?: string } {
  const explicitSigningRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const explicitSigningRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const scopeBinding = getSigningRootBindingFromRuntimePolicyScope(runtimePolicyScope);
  if (
    explicitSigningRootId &&
    scopeBinding?.signingRootId &&
    explicitSigningRootId !== scopeBinding.signingRootId
  ) {
    throw new Error('Invalid threshold ECDSA canonical session record: signingRootId mismatch');
  }
  if (
    explicitSigningRootVersion &&
    scopeBinding?.signingRootVersion &&
    explicitSigningRootVersion !== scopeBinding.signingRootVersion
  ) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: signingRootVersion mismatch',
    );
  }

  const signingRootId = explicitSigningRootId || scopeBinding?.signingRootId || '';
  const signingRootVersion = explicitSigningRootVersion || scopeBinding?.signingRootVersion || '';
  if (!signingRootId) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing signingRootId');
  }
  return {
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
  };
}

function matchesExpectedSigningRootBinding(
  record: ThresholdEcdsaSessionRecord,
  expected?: { signingRootId?: string; signingRootVersion?: string },
): boolean {
  const expectedSigningRootId = normalizeOptionalNonEmptyString(expected?.signingRootId);
  const expectedSigningRootVersion = normalizeOptionalNonEmptyString(expected?.signingRootVersion);
  if (expectedSigningRootId && record.signingRootId !== expectedSigningRootId) return false;
  if (expectedSigningRootVersion) {
    return (
      normalizeOptionalNonEmptyString(record.signingRootVersion) === expectedSigningRootVersion
    );
  }
  return true;
}

function normalizeThresholdEcdsaSessionRecord(value: unknown): ThresholdEcdsaSessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const nearAccountId = toAccountId(String(obj.nearAccountId || '').trim());
  const chain = normalizeThresholdEcdsaActivationChain(obj.chain);
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const ecdsaThresholdKeyId = normalizeOptionalNonEmptyString(obj.ecdsaThresholdKeyId);
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const clientVerifyingShareB64u = String(obj.clientVerifyingShareB64u || '').trim();
  const clientAdditiveShare32B64u = normalizeOptionalNonEmptyString(obj.clientAdditiveShare32B64u);
  const clientAdditiveShareHandle = normalizeThresholdEcdsaClientAdditiveShareHandle(
    obj.clientAdditiveShareHandle,
  );
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const thresholdSessionKind = normalizeThresholdEcdsaSessionKind(obj.thresholdSessionKind);
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const walletSigningSessionId = normalizeOptionalNonEmptyString(obj.walletSigningSessionId);
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(obj.thresholdSessionJwt);
  const signingSessionSealKeyVersion = normalizeOptionalNonEmptyString(
    obj.signingSessionSealKeyVersion,
  );
  const signingSessionSealShamirPrimeB64u = normalizeOptionalNonEmptyString(
    obj.signingSessionSealShamirPrimeB64u,
  );
  const runtimePolicyScope = normalizeStoredRuntimePolicyScope(obj, thresholdSessionJwt);
  const signingRootBinding = normalizeStoredSigningRootBinding(obj, runtimePolicyScope);
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEcdsaSessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
    sourceRaw === 'manual-bootstrap' ||
    sourceRaw === 'email_otp'
      ? sourceRaw
      : 'manual-bootstrap';
  const updatedAtMs = normalizeInteger(obj.updatedAtMs) || Date.now();
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const thresholdEcdsaPublicKeyB64u = normalizeOptionalNonEmptyString(
    obj.thresholdEcdsaPublicKeyB64u,
  );
  const ethereumAddress = normalizeOptionalNonEmptyString(obj.ethereumAddress);
  const relayerVerifyingShareB64u = normalizeOptionalNonEmptyString(obj.relayerVerifyingShareB64u);
  const emailOtpAuthContext =
    source === 'email_otp'
      ? normalizeThresholdEcdsaEmailOtpAuthContext(obj.emailOtpAuthContext)
      : null;

  if (
    !relayerUrl ||
    !chain ||
    !ecdsaThresholdKeyId ||
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
    ecdsaThresholdKeyId,
    signingRootId: signingRootBinding.signingRootId,
    ...(signingRootBinding.signingRootVersion
      ? { signingRootVersion: signingRootBinding.signingRootVersion }
      : {}),
    relayerKeyId,
    clientVerifyingShareB64u,
    ...(source !== 'email_otp' && clientAdditiveShare32B64u ? { clientAdditiveShare32B64u } : {}),
    ...(source === 'email_otp' && clientAdditiveShareHandle ? { clientAdditiveShareHandle } : {}),
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    thresholdSessionKind,
    thresholdSessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
    ...(signingSessionSealShamirPrimeB64u ? { signingSessionSealShamirPrimeB64u } : {}),
    ...(expiresAtMs != null ? { expiresAtMs } : {}),
    ...(remainingUses != null ? { remainingUses } : {}),
    ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
    ...(ethereumAddress ? { ethereumAddress } : {}),
    ...(relayerVerifyingShareB64u ? { relayerVerifyingShareB64u } : {}),
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    updatedAtMs,
    source,
  };
}

function normalizeThresholdEcdsaClientAdditiveShareHandle(
  value: unknown,
): ThresholdEcdsaClientAdditiveShareHandle | null {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const kind = String(obj.kind || '').trim();
  const sessionId = String(obj.sessionId || '').trim();
  if (kind !== 'email_otp_worker_session' || !sessionId) return null;
  return {
    kind: 'email_otp_worker_session',
    sessionId,
  };
}

function normalizeThresholdEcdsaEmailOtpAuthContext(
  value: unknown,
): ThresholdEcdsaEmailOtpAuthContext {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const policyRaw = String(obj.policy || '')
    .trim()
    .toLowerCase();
  const policy: EmailOtpAuthPolicy = policyRaw === 'per_operation' ? 'per_operation' : 'session';
  const retentionRaw = String(obj.retention || '')
    .trim()
    .toLowerCase();
  const retention: 'session' | 'single_use' =
    retentionRaw === 'single_use'
      ? 'single_use'
      : policy === 'per_operation'
        ? 'single_use'
        : 'session';
  const reasonRaw = String(obj.reason || '')
    .trim()
    .toLowerCase();
  const reason: 'login' | 'sign' = reasonRaw === 'sign' ? 'sign' : 'login';
  const consumedAtMs = normalizePositiveInteger(obj.consumedAtMs);
  return {
    policy,
    retention,
    reason,
    authMethod: 'email_otp',
    ...(consumedAtMs ? { consumedAtMs } : {}),
  };
}

function normalizeThresholdEd25519SessionRecord(value: unknown): ThresholdEd25519SessionRecord {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : {};
  const nearAccountId = toAccountId(String(obj.nearAccountId || '').trim());
  const rpId = String(obj.rpId || '').trim();
  const relayerUrl = String(obj.relayerUrl || '').trim();
  const relayerKeyId = String(obj.relayerKeyId || '').trim();
  const participantIds = normalizeThresholdEd25519ParticipantIds(obj.participantIds);
  const runtimePolicyScope = normalizeStoredRuntimePolicyScope(obj);
  const xClientBaseB64u = normalizeOptionalNonEmptyString(obj.xClientBaseB64u);
  const thresholdSessionKindRaw = String(obj.thresholdSessionKind || 'jwt')
    .trim()
    .toLowerCase();
  const thresholdSessionKind: 'jwt' | 'cookie' =
    thresholdSessionKindRaw === 'cookie' ? 'cookie' : 'jwt';
  const thresholdSessionId = String(obj.thresholdSessionId || '').trim();
  const walletSigningSessionId = normalizeOptionalNonEmptyString(obj.walletSigningSessionId);
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(obj.thresholdSessionJwt);
  const expiresAtMs = normalizeInteger(obj.expiresAtMs);
  const remainingUses = normalizeInteger(obj.remainingUses);
  const updatedAtMs = normalizeInteger(obj.updatedAtMs) || Date.now();
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEd25519SessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
    sourceRaw === 'manual-connect' ||
    sourceRaw === 'bootstrap' ||
    sourceRaw === 'email_otp'
      ? sourceRaw
      : 'manual-connect';
  const emailOtpAuthContext =
    source === 'email_otp'
      ? normalizeThresholdEcdsaEmailOtpAuthContext(obj.emailOtpAuthContext)
      : null;

  if (!rpId || !relayerUrl || !relayerKeyId || !participantIds || !thresholdSessionId) {
    throw new Error('Invalid threshold Ed25519 canonical session record');
  }
  if (thresholdSessionKind === 'jwt' && !thresholdSessionJwt) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing JWT');
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing expiresAtMs');
  }
  if (remainingUses == null || remainingUses < 0) {
    throw new Error('Invalid threshold Ed25519 canonical session record: missing remainingUses');
  }

  return {
    nearAccountId,
    rpId,
    relayerUrl,
    relayerKeyId,
    participantIds,
    ...(runtimePolicyScope ? { runtimePolicyScope } : {}),
    ...(xClientBaseB64u ? { xClientBaseB64u } : {}),
    thresholdSessionKind,
    thresholdSessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    ...(thresholdSessionJwt ? { thresholdSessionJwt } : {}),
    expiresAtMs,
    remainingUses,
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    updatedAtMs,
    source,
  };
}

function rememberInMemoryThresholdEd25519Record(record: ThresholdEd25519SessionRecord): void {
  const accountKey = String(record.nearAccountId || '').trim();
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  if (!accountKey || !thresholdSessionId) return;

  const previous = inMemoryEd25519RecordsByAccount.get(accountKey);
  const previousSessionId = String(previous?.thresholdSessionId || '').trim();
  if (previousSessionId && previousSessionId !== thresholdSessionId) {
    inMemoryEd25519AccountBySessionId.delete(previousSessionId);
  }

  inMemoryEd25519RecordsByAccount.set(accountKey, record);
  inMemoryEd25519AccountBySessionId.set(thresholdSessionId, accountKey);
}

function getInMemoryThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  try {
    const accountKey = String(toAccountId(nearAccountIdRaw)).trim();
    return inMemoryEd25519RecordsByAccount.get(accountKey) || null;
  } catch {
    return null;
  }
}

function getInMemoryThresholdEd25519SessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;

  const indexedAccountKey = String(
    inMemoryEd25519AccountBySessionId.get(thresholdSessionId) || '',
  ).trim();
  if (indexedAccountKey) {
    const indexedRecord = inMemoryEd25519RecordsByAccount.get(indexedAccountKey) || null;
    if (
      indexedRecord &&
      String(indexedRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      return indexedRecord;
    }
    inMemoryEd25519AccountBySessionId.delete(thresholdSessionId);
  }

  for (const [accountKey, record] of inMemoryEd25519RecordsByAccount.entries()) {
    if (String(record.thresholdSessionId || '').trim() !== thresholdSessionId) continue;
    inMemoryEd25519AccountBySessionId.set(thresholdSessionId, accountKey);
    return record;
  }

  return null;
}

export type ThresholdEcdsaSessionLane = {
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  source: ThresholdEcdsaSessionStoreSource;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion?: string;
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

function normalizeThresholdEcdsaSessionStoreSource(
  sourceRaw: unknown,
): ThresholdEcdsaSessionStoreSource | null {
  const source = String(sourceRaw || '').trim();
  if (
    source === 'login' ||
    source === 'registration' ||
    source === 'manual-bootstrap' ||
    source === 'email_otp'
  ) {
    return source;
  }
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
  source: ThresholdEcdsaSessionStoreSource;
  ecdsaThresholdKeyId: EcdsaThresholdKeyId;
  signingRootId: string;
  signingRootVersion?: string;
}): string {
  const nearAccountId = String(toAccountId(args.nearAccountId)).trim();
  const chain = normalizeThresholdEcdsaActivationChain(args.chain);
  const source = normalizeThresholdEcdsaSessionStoreSource(args.source);
  const ecdsaThresholdKeyId = String(args.ecdsaThresholdKeyId || '').trim();
  const signingRootId = normalizeOptionalNonEmptyString(args.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(args.signingRootVersion) || '';
  if (!nearAccountId || !chain || !source || !ecdsaThresholdKeyId || !signingRootId) {
    throw new Error('[SigningEngine] invalid threshold ECDSA lane key input');
  }
  return [
    encodeLaneToken(nearAccountId),
    encodeLaneToken(chain),
    encodeLaneToken(source),
    encodeLaneToken(ecdsaThresholdKeyId),
    encodeLaneToken(signingRootId),
    encodeLaneToken(signingRootVersion),
  ].join('|');
}

export function parseThresholdEcdsaSessionLaneKey(
  laneKeyRaw: string,
): ThresholdEcdsaSessionLane | null {
  const laneKey = String(laneKeyRaw || '').trim();
  if (!laneKey) return null;
  const parts = laneKey.split('|');
  if (parts.length !== 6) return null;
  const nearAccountDecoded = decodeLaneToken(parts[0] || '');
  const chainDecoded = decodeLaneToken(parts[1] || '');
  const sourceDecoded = decodeLaneToken(parts[2] || '');
  const ecdsaThresholdKeyIdDecoded = decodeLaneToken(parts[3] || '');
  const signingRootIdDecoded = decodeLaneToken(parts[4] || '');
  const signingRootVersionDecoded = decodeLaneToken(parts[5] || '') || '';
  if (
    !nearAccountDecoded ||
    !chainDecoded ||
    !sourceDecoded ||
    !ecdsaThresholdKeyIdDecoded ||
    !signingRootIdDecoded
  )
    return null;
  const chain = normalizeThresholdEcdsaActivationChain(chainDecoded);
  const source = normalizeThresholdEcdsaSessionStoreSource(sourceDecoded);
  if (!chain) return null;
  if (!source) return null;
  try {
    return {
      nearAccountId: toAccountId(nearAccountDecoded),
      chain,
      source,
      ecdsaThresholdKeyId: ecdsaThresholdKeyIdDecoded,
      signingRootId: signingRootIdDecoded,
      ...(signingRootVersionDecoded ? { signingRootVersion: signingRootVersionDecoded } : {}),
    };
  } catch {
    return null;
  }
}

function getThresholdEcdsaSessionLaneKeyForRecord(record: ThresholdEcdsaSessionRecord): string {
  return serializeThresholdEcdsaSessionLaneKey({
    nearAccountId: record.nearAccountId,
    chain: record.chain,
    source: record.source,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    signingRootId: record.signingRootId,
    ...(record.signingRootVersion ? { signingRootVersion: record.signingRootVersion } : {}),
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

function buildEcdsaRecordFromBootstrap(args: {
  nearAccountId: AccountId | string;
  chain: ThresholdEcdsaActivationChain;
  bootstrap: ThresholdEcdsaSessionBootstrapResult;
  source: ThresholdEcdsaSessionStoreSource;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  nowMs: number;
  signingSessionSeal?: {
    keyVersion?: string;
    shamirPrimeB64u?: string;
  };
}): ThresholdEcdsaSessionRecord {
  const accountId = toAccountId(args.nearAccountId);
  const keyRef = args.bootstrap.thresholdEcdsaKeyRef;
  const ecdsaThresholdKeyId = String(keyRef.ecdsaThresholdKeyId || '').trim();
  if (!ecdsaThresholdKeyId) {
    throw new Error(
      '[SigningEngine] threshold ECDSA bootstrap did not provide ecdsaThresholdKeyId',
    );
  }
  const signingRootId = normalizeOptionalNonEmptyString(keyRef.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(keyRef.signingRootVersion);
  if (!signingRootId) {
    throw new Error('[SigningEngine] threshold ECDSA bootstrap did not provide signingRootId');
  }
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
  const walletSigningSessionId = normalizeOptionalNonEmptyString(
    keyRef.walletSigningSessionId ||
      (args.bootstrap.session as { walletSigningSessionId?: unknown }).walletSigningSessionId,
  );
  const thresholdSessionJwt = normalizeOptionalNonEmptyString(
    keyRef.thresholdSessionJwt || args.bootstrap.session.jwt,
  );
  const clientAdditiveShare32B64u =
    args.source === 'email_otp'
      ? undefined
      : normalizeOptionalNonEmptyString(keyRef.backendBinding?.clientAdditiveShare32B64u);
  const clientAdditiveShareHandle =
    args.source === 'email_otp'
      ? normalizeThresholdEcdsaClientAdditiveShareHandle(
          keyRef.backendBinding?.clientAdditiveShareHandle,
        )
      : null;
  const signingSessionSealKeyVersion = normalizeOptionalNonEmptyString(
    args.signingSessionSeal?.keyVersion,
  );
  const signingSessionSealShamirPrimeB64u = normalizeOptionalNonEmptyString(
    args.signingSessionSeal?.shamirPrimeB64u,
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
    ecdsaThresholdKeyId,
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    relayerKeyId: keyRef.backendBinding?.relayerKeyId,
    clientVerifyingShareB64u: keyRef.backendBinding?.clientVerifyingShareB64u,
    ...(clientAdditiveShare32B64u ? { clientAdditiveShare32B64u } : {}),
    ...(clientAdditiveShareHandle ? { clientAdditiveShareHandle } : {}),
    participantIds,
    thresholdSessionKind,
    thresholdSessionId,
    ...(walletSigningSessionId ? { walletSigningSessionId } : {}),
    thresholdSessionJwt,
    ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
    ...(signingSessionSealShamirPrimeB64u ? { signingSessionSealShamirPrimeB64u } : {}),
    expiresAtMs: args.bootstrap.session.expiresAtMs,
    remainingUses: args.bootstrap.session.remainingUses,
    thresholdEcdsaPublicKeyB64u: keyRef.thresholdEcdsaPublicKeyB64u,
    ethereumAddress: keyRef.ethereumAddress,
    relayerVerifyingShareB64u: keyRef.relayerVerifyingShareB64u,
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: args.nowMs,
    source: args.source,
  });
}

function setEcdsaExportArtifactForLane(args: {
  deps: ThresholdEcdsaSessionStoreDeps;
  laneKey: string;
  artifact?: ThresholdEcdsaCanonicalExportArtifact;
}): void {
  if (!args.deps.exportArtifactsByLane) return;
  if (args.artifact) {
    args.deps.exportArtifactsByLane.set(args.laneKey, args.artifact);
    return;
  }
  args.deps.exportArtifactsByLane.delete(args.laneKey);
}

export function upsertThresholdEcdsaSessionFromBootstrap(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    bootstrap: ThresholdEcdsaSessionBootstrapResult;
    source: ThresholdEcdsaSessionStoreSource;
    emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
    signingSessionSeal?: {
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };
  },
): ThresholdEcdsaSessionRecord {
  const nowMs = Math.max(0, Math.floor((deps.now || Date.now)()));
  const record = buildEcdsaRecordFromBootstrap({
    nearAccountId: args.nearAccountId,
    chain: args.chain,
    bootstrap: args.bootstrap,
    source: args.source,
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    nowMs,
    ...(args.signingSessionSeal ? { signingSessionSeal: args.signingSessionSeal } : {}),
  });
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  deps.recordsByLane.set(laneKey, record);
  setEcdsaExportArtifactForLane({
    deps,
    laneKey,
    artifact:
      normalizeThresholdEcdsaCanonicalExportArtifact(
        args.bootstrap.thresholdEcdsaKeyRef.ecdsaHssExportArtifact,
      ) || undefined,
  });
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
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

export function upsertStoredThresholdEcdsaSessionRecord(
  deps: ThresholdEcdsaSessionStoreDeps,
  recordRaw: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaSessionRecord {
  const record = normalizeThresholdEcdsaSessionRecord({
    ...recordRaw,
    updatedAtMs: Math.max(0, Math.floor((deps.now || Date.now)())),
  });
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  deps.recordsByLane.set(laneKey, record);
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
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
  signingRootId?: string;
  signingRootVersion?: string;
  source?: ThresholdEcdsaSessionStoreSource;
}): ThresholdEcdsaSessionRecord[] {
  const out: ThresholdEcdsaSessionRecord[] = [];
  for (const record of args.deps.recordsByLane.values()) {
    if (String(record.nearAccountId) !== String(args.nearAccountId)) continue;
    if (record.chain !== args.chain) continue;
    if (args.source && record.source !== args.source) continue;
    if (!matchesExpectedSigningRootBinding(record, args)) continue;
    out.push(record);
  }
  return out;
}

function listStoredThresholdEcdsaRecordsForLane(args: {
  storage: SessionStoragePort;
  deps: ThresholdEcdsaSessionStoreDeps;
  nearAccountId: AccountId;
  chain: ThresholdEcdsaActivationChain;
  signingRootId?: string;
  signingRootVersion?: string;
  source?: ThresholdEcdsaSessionStoreSource;
}): ThresholdEcdsaSessionRecord[] {
  const out: ThresholdEcdsaSessionRecord[] = [];
  const laneKeys = readStorageIndex(args.storage, ECDSA_STORAGE_INDEX_KEY);
  for (const laneKey of laneKeys) {
    const parsedLane = parseThresholdEcdsaSessionLaneKey(laneKey);
    if (!parsedLane) continue;
    if (String(parsedLane.nearAccountId) !== String(args.nearAccountId)) continue;
    if (parsedLane.chain !== args.chain) continue;
    if (
      args.signingRootId &&
      parsedLane.signingRootId !== normalizeOptionalNonEmptyString(args.signingRootId)
    )
      continue;
    if (
      args.signingRootVersion &&
      normalizeOptionalNonEmptyString(parsedLane.signingRootVersion) !==
        normalizeOptionalNonEmptyString(args.signingRootVersion)
    )
      continue;
    const record = readStoredRecord({
      storage: args.storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      recordKey: laneKey,
      normalize: normalizeThresholdEcdsaSessionRecord,
    });
    if (!record) continue;
    if (args.source && record.source !== args.source) continue;
    if (parsedLane.signingRootId !== record.signingRootId) continue;
    if (
      normalizeOptionalNonEmptyString(parsedLane.signingRootVersion) !==
      normalizeOptionalNonEmptyString(record.signingRootVersion)
    )
      continue;
    if (!matchesExpectedSigningRootBinding(record, args)) continue;
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
    signingRootId?: string;
    signingRootVersion?: string;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord {
  const accountId = toAccountId(args.nearAccountId);
  const inMemory = pickThresholdEcdsaRecordForChain(
    listInMemoryThresholdEcdsaRecordsForLane({
      deps,
      nearAccountId: accountId,
      chain: args.chain,
      ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
      ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
      ...(args.source ? { source: args.source } : {}),
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
          ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
          ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
          ...(args.source ? { source: args.source } : {}),
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

function thresholdEcdsaKeyRefFromRecord(
  deps: ThresholdEcdsaSessionStoreDeps,
  record: ThresholdEcdsaSessionRecord,
): ThresholdEcdsaSecp256k1KeyRef {
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  const ecdsaHssExportArtifact = deps.exportArtifactsByLane?.get(laneKey);
  return {
    type: 'threshold-ecdsa-secp256k1',
    userId: String(record.nearAccountId),
    relayerUrl: record.relayerUrl,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    signingRootId: record.signingRootId,
    ...(record.signingRootVersion ? { signingRootVersion: record.signingRootVersion } : {}),
    backendBinding: {
      relayerKeyId: record.relayerKeyId,
      clientVerifyingShareB64u: record.clientVerifyingShareB64u,
      ...(record.clientAdditiveShare32B64u
        ? { clientAdditiveShare32B64u: record.clientAdditiveShare32B64u }
        : {}),
      ...(record.clientAdditiveShareHandle
        ? { clientAdditiveShareHandle: record.clientAdditiveShareHandle }
        : {}),
    },
    ...(ecdsaHssExportArtifact ? { ecdsaHssExportArtifact } : {}),
    participantIds: record.participantIds,
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    ...(record.thresholdSessionJwt ? { thresholdSessionJwt: record.thresholdSessionJwt } : {}),
    ...(record.walletSigningSessionId
      ? { walletSigningSessionId: record.walletSigningSessionId }
      : {}),
    ...(record.thresholdEcdsaPublicKeyB64u
      ? { thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u }
      : {}),
    ...(record.ethereumAddress ? { ethereumAddress: record.ethereumAddress } : {}),
    ...(record.relayerVerifyingShareB64u
      ? { relayerVerifyingShareB64u: record.relayerVerifyingShareB64u }
      : {}),
  };
}

export function getThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    signingRootId?: string;
    signingRootVersion?: string;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSecp256k1KeyRef {
  const record = getThresholdEcdsaSessionRecordForSigning(deps, args);
  return thresholdEcdsaKeyRefFromRecord(deps, record);
}

export function getEmailOtpThresholdEcdsaSessionRecordForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    signingRootId?: string;
    signingRootVersion?: string;
  },
): ThresholdEcdsaSessionRecord {
  return getThresholdEcdsaSessionRecordForSigning(deps, {
    ...args,
    source: 'email_otp',
  });
}

export function getEmailOtpThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    signingRootId?: string;
    signingRootVersion?: string;
  },
): ThresholdEcdsaSecp256k1KeyRef {
  const record = getEmailOtpThresholdEcdsaSessionRecordForSigning(deps, args);
  return thresholdEcdsaKeyRefFromRecord(deps, record);
}

export function getPasskeyThresholdEcdsaSessionRecordForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    signingRootId?: string;
    signingRootVersion?: string;
    source?: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  },
): ThresholdEcdsaSessionRecord {
  if (args.source) {
    return getThresholdEcdsaSessionRecordForSigning(deps, {
      ...args,
      source: args.source,
    });
  }

  const accountId = toAccountId(args.nearAccountId);
  const records: ThresholdEcdsaSessionRecord[] = [];
  for (const source of THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES) {
    records.push(
      ...listInMemoryThresholdEcdsaRecordsForLane({
        deps,
        nearAccountId: accountId,
        chain: args.chain,
        ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
        ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
        source,
      }),
    );
  }
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    for (const source of THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES) {
      records.push(
        ...listStoredThresholdEcdsaRecordsForLane({
          storage,
          deps,
          nearAccountId: accountId,
          chain: args.chain,
          ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
          ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
          source,
        }),
      );
    }
  }
  const selected = pickThresholdEcdsaRecordForChain(records);
  if (selected) return selected;
  throw new Error(
    `[SigningEngine] missing canonical passkey threshold ECDSA session for ${String(accountId)}; reconnect threshold session via bootstrapEcdsaSession`,
  );
}

export function getPasskeyThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    signingRootId?: string;
    signingRootVersion?: string;
    source?: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  },
): ThresholdEcdsaSecp256k1KeyRef {
  const record = getPasskeyThresholdEcdsaSessionRecordForSigning(deps, args);
  return thresholdEcdsaKeyRefFromRecord(deps, record);
}

export function clearEmailOtpThresholdEcdsaSessionRecordForLane(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  },
): void {
  clearThresholdEcdsaSessionRecordForLane(deps, {
    ...args,
    source: 'email_otp',
  });
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
    deps.exportArtifactsByLane?.delete(laneKey);
  }
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
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

export function clearThresholdEcdsaSessionRecordForLane(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): void {
  const accountId = toAccountId(args.nearAccountId);
  const laneKeysToClear: string[] = [];
  for (const [laneKey, record] of deps.recordsByLane.entries()) {
    if (String(record.nearAccountId) !== String(accountId)) continue;
    if (record.chain !== args.chain) continue;
    if (args.source && record.source !== args.source) continue;
    laneKeysToClear.push(laneKey);
  }
  for (const laneKey of laneKeysToClear) {
    deps.recordsByLane.delete(laneKey);
    deps.exportArtifactsByLane?.delete(laneKey);
  }
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    const laneKeys = readStorageIndex(storage, ECDSA_STORAGE_INDEX_KEY);
    for (const laneKey of laneKeys) {
      const parsedLane = parseThresholdEcdsaSessionLaneKey(laneKey);
      if (!parsedLane) continue;
      if (String(parsedLane.nearAccountId) !== String(accountId)) continue;
      if (parsedLane.chain !== args.chain) continue;
      if (args.source && parsedLane.source !== args.source) continue;
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

export function markThresholdEcdsaEmailOtpSessionConsumedForAccount(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    nearAccountId: AccountId | string;
    chain: ThresholdEcdsaActivationChain;
  },
): ThresholdEcdsaSessionRecord | null {
  const accountId = toAccountId(args.nearAccountId);
  const nowMs = Math.max(0, Math.floor((deps.now || Date.now)()));
  let updatedRecord: ThresholdEcdsaSessionRecord | null = null;
  const storage = getEcdsaSessionStorageSafe();

  for (const [laneKey, record] of deps.recordsByLane.entries()) {
    if (String(record.nearAccountId) !== String(accountId)) continue;
    if (record.chain !== args.chain) continue;
    if (record.source !== 'email_otp' || !record.emailOtpAuthContext) continue;
    const nextRecord: ThresholdEcdsaSessionRecord = {
      ...record,
      emailOtpAuthContext: {
        ...record.emailOtpAuthContext,
        consumedAtMs: nowMs,
      },
      updatedAtMs: nowMs,
    };
    deps.recordsByLane.set(laneKey, nextRecord);
    if (storage) {
      writeStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
        storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
        recordKey: laneKey,
        record: nextRecord,
        thresholdSessionId: nextRecord.thresholdSessionId,
      });
    }
    updatedRecord = nextRecord;
  }

  return updatedRecord;
}

export function clearAllThresholdEcdsaSessionRecords(deps: ThresholdEcdsaSessionStoreDeps): void {
  deps.recordsByLane.clear();
  deps.exportArtifactsByLane?.clear();
  const storage = getEcdsaSessionStorageSafe();
  if (storage) {
    clearAllStoredRecords({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
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
  const sessionIndex = readStorageSessionIndex(storage, ECDSA_STORAGE_SESSION_INDEX_KEY);
  const indexedLaneKey = String(sessionIndex[thresholdSessionId] || '').trim();
  if (!indexedLaneKey) return null;
  const parsedLane = parseThresholdEcdsaSessionLaneKey(indexedLaneKey);
  if (!parsedLane) {
    removeStorageSessionIndexEntry({
      storage,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
      thresholdSessionId,
    });
    return null;
  }
  try {
    const indexedRecord = readStoredRecord({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      recordKey: indexedLaneKey,
      normalize: normalizeThresholdEcdsaSessionRecord,
    });
    if (
      indexedRecord &&
      String(indexedRecord.thresholdSessionId || '').trim() === thresholdSessionId &&
      parsedLane.signingRootId === indexedRecord.signingRootId &&
      normalizeOptionalNonEmptyString(parsedLane.signingRootVersion) ===
        normalizeOptionalNonEmptyString(indexedRecord.signingRootVersion)
    ) {
      return indexedRecord;
    }
  } catch {}
  removeStorageSessionIndexEntry({
    storage,
    storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
    thresholdSessionId,
  });
  return null;
}

export function upsertStoredThresholdEd25519SessionRecord(args: {
  nearAccountId: AccountId | string;
  rpId: string;
  relayerUrl: string;
  relayerKeyId: string;
  participantIds: number[];
  runtimePolicyScope?: ThresholdRuntimePolicyScope;
  xClientBaseB64u?: string;
  thresholdSessionKind?: 'jwt' | 'cookie';
  thresholdSessionId: string;
  walletSigningSessionId?: string;
  thresholdSessionJwt?: string;
  expiresAtMs: number;
  remainingUses: number;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs?: number;
  source?: ThresholdEd25519SessionStoreSource;
}): ThresholdEd25519SessionRecord | null {
  const record = normalizeThresholdEd25519SessionRecord({
    nearAccountId: toAccountId(args.nearAccountId),
    rpId: String(args.rpId || '').trim(),
    relayerUrl: String(args.relayerUrl || '').trim(),
    relayerKeyId: String(args.relayerKeyId || '').trim(),
    participantIds: args.participantIds,
    ...(args.runtimePolicyScope ? { runtimePolicyScope: args.runtimePolicyScope } : {}),
    ...(String(args.xClientBaseB64u || '').trim()
      ? { xClientBaseB64u: String(args.xClientBaseB64u || '').trim() }
      : {}),
    thresholdSessionKind: String(args.thresholdSessionKind || 'jwt')
      .trim()
      .toLowerCase(),
    thresholdSessionId: String(args.thresholdSessionId || '').trim(),
    ...(String(args.walletSigningSessionId || '').trim()
      ? { walletSigningSessionId: String(args.walletSigningSessionId || '').trim() }
      : {}),
    ...(String(args.thresholdSessionJwt || '').trim()
      ? { thresholdSessionJwt: String(args.thresholdSessionJwt || '').trim() }
      : {}),
    expiresAtMs: Math.floor(Number(args.expiresAtMs) || 0),
    remainingUses: Math.floor(Number(args.remainingUses) || 0),
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source: args.source || 'manual-connect',
  });
  rememberInMemoryThresholdEd25519Record(record);
  const storage = getEd25519SessionStorageSafe();
  if (!storage) return record;
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

export function persistStoredThresholdEd25519SessionClientBase(args: {
  thresholdSessionId: string;
  xClientBaseB64u: string;
  updatedAtMs?: number;
}): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  const xClientBaseB64u = String(args.xClientBaseB64u || '').trim();
  if (!thresholdSessionId || !xClientBaseB64u) return null;
  const existing = getStoredThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
  if (!existing) return null;
  return upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: existing.nearAccountId,
    rpId: existing.rpId,
    relayerUrl: existing.relayerUrl,
    relayerKeyId: existing.relayerKeyId,
    participantIds: existing.participantIds,
    ...(existing.runtimePolicyScope ? { runtimePolicyScope: existing.runtimePolicyScope } : {}),
    xClientBaseB64u,
    thresholdSessionKind: existing.thresholdSessionKind,
    thresholdSessionId: existing.thresholdSessionId,
    ...(existing.walletSigningSessionId
      ? { walletSigningSessionId: existing.walletSigningSessionId }
      : {}),
    thresholdSessionJwt: existing.thresholdSessionJwt,
    expiresAtMs: existing.expiresAtMs,
    remainingUses: existing.remainingUses,
    ...(existing.emailOtpAuthContext ? { emailOtpAuthContext: existing.emailOtpAuthContext } : {}),
    updatedAtMs: args.updatedAtMs ?? Date.now(),
    source: existing.source,
  });
}

export function getStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord | null {
  const inMemory = getInMemoryThresholdEd25519SessionRecordForAccount(nearAccountIdRaw);
  if (inMemory) return inMemory;
  const storage = getEd25519SessionStorageSafe();
  if (!storage) return null;
  try {
    const nearAccountId = toAccountId(nearAccountIdRaw);
    const stored = readStoredRecord({
      storage,
      storageKeyPrefix: ED25519_STORAGE_KEY_PREFIX,
      recordKey: String(nearAccountId),
      normalize: normalizeThresholdEd25519SessionRecord,
    });
    if (stored) {
      rememberInMemoryThresholdEd25519Record(stored);
      return stored;
    }
    return null;
  } catch {
    return null;
  }
}

export function markThresholdEd25519EmailOtpSessionConsumedForAccount(args: {
  nearAccountId: AccountId | string;
  thresholdSessionId?: string;
  uses?: number;
  nowMs?: number;
}): ThresholdEd25519SessionRecord | null {
  const record = getStoredThresholdEd25519SessionRecordForAccount(args.nearAccountId);
  if (!record || record.source !== 'email_otp' || !record.emailOtpAuthContext) return null;
  const expectedSessionId = String(args.thresholdSessionId || '').trim();
  const actualSessionId = String(record.thresholdSessionId || '').trim();
  if (expectedSessionId && actualSessionId && expectedSessionId !== actualSessionId) {
    return null;
  }
  const nowMs = Math.max(0, Math.floor(Number(args.nowMs ?? Date.now()) || 0));
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  const remainingUses = Math.max(0, Math.floor(Number(record.remainingUses) || 0) - uses);
  const clearClientBase = record.emailOtpAuthContext.retention === 'single_use';
  return upsertStoredThresholdEd25519SessionRecord({
    nearAccountId: record.nearAccountId,
    rpId: record.rpId,
    relayerUrl: record.relayerUrl,
    relayerKeyId: record.relayerKeyId,
    participantIds: record.participantIds,
    ...(record.runtimePolicyScope ? { runtimePolicyScope: record.runtimePolicyScope } : {}),
    ...(record.xClientBaseB64u && !clearClientBase
      ? { xClientBaseB64u: record.xClientBaseB64u }
      : {}),
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    ...(record.walletSigningSessionId
      ? { walletSigningSessionId: record.walletSigningSessionId }
      : {}),
    ...(record.thresholdSessionJwt ? { thresholdSessionJwt: record.thresholdSessionJwt } : {}),
    expiresAtMs: record.expiresAtMs,
    remainingUses,
    emailOtpAuthContext: {
      ...record.emailOtpAuthContext,
      consumedAtMs: nowMs,
    },
    updatedAtMs: nowMs,
    source: 'email_otp',
  });
}

export function getStoredThresholdEd25519SessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEd25519SessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const inMemory = getInMemoryThresholdEd25519SessionRecordByThresholdSessionId(thresholdSessionId);
  if (inMemory) return inMemory;
  const storage = getEd25519SessionStorageSafe();
  if (!storage) return null;
  const sessionIndex = readStorageSessionIndex(storage, ED25519_STORAGE_SESSION_INDEX_KEY);
  const indexedAccountIdRaw = String(sessionIndex[thresholdSessionId] || '').trim();
  if (!indexedAccountIdRaw) return null;
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
      rememberInMemoryThresholdEd25519Record(indexedRecord);
      return indexedRecord;
    }
  } catch {}
  removeStorageSessionIndexEntry({
    storage,
    storageSessionIndexKey: ED25519_STORAGE_SESSION_INDEX_KEY,
    thresholdSessionId,
  });
  return null;
}

export function clearStoredThresholdEd25519SessionRecordForAccount(
  nearAccountIdRaw: AccountId | string,
): void {
  const inMemory = getInMemoryThresholdEd25519SessionRecordForAccount(nearAccountIdRaw);
  const inMemorySessionId = String(inMemory?.thresholdSessionId || '').trim();
  if (inMemorySessionId) {
    inMemoryEd25519AccountBySessionId.delete(inMemorySessionId);
  }
  try {
    const nearAccountId = toAccountId(nearAccountIdRaw);
    inMemoryEd25519RecordsByAccount.delete(String(nearAccountId));
  } catch {}
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
  inMemoryEd25519RecordsByAccount.clear();
  inMemoryEd25519AccountBySessionId.clear();
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
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdSessionRecordByCurve[TCurve] | null {
  if (args.curve === 'ecdsa') {
    const storage = getEcdsaSessionStorageSafe();
    if (!storage) return null;
    const nearAccountId = toAccountId(args.nearAccountId);
    const laneKeys = readStorageIndex(storage, ECDSA_STORAGE_INDEX_KEY);
    let selected: ThresholdEcdsaSessionRecord | null = null;
    for (const laneKey of laneKeys) {
      const parsedLane = parseThresholdEcdsaSessionLaneKey(laneKey);
      if (!parsedLane) continue;
      if (String(parsedLane.nearAccountId) !== String(nearAccountId)) continue;
      if (args.chain && parsedLane.chain !== args.chain) continue;
      if (
        args.signingRootId &&
        parsedLane.signingRootId !== normalizeOptionalNonEmptyString(args.signingRootId)
      )
        continue;
      if (
        args.signingRootVersion &&
        normalizeOptionalNonEmptyString(parsedLane.signingRootVersion) !==
          normalizeOptionalNonEmptyString(args.signingRootVersion)
      )
        continue;
      const record = readStoredRecord({
        storage,
        storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
        recordKey: laneKey,
        normalize: normalizeThresholdEcdsaSessionRecord,
      });
      if (!record) continue;
      if (parsedLane.signingRootId !== record.signingRootId) continue;
      if (
        normalizeOptionalNonEmptyString(parsedLane.signingRootVersion) !==
        normalizeOptionalNonEmptyString(record.signingRootVersion)
      )
        continue;
      if (!matchesExpectedSigningRootBinding(record, args)) continue;
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
    clearAllStoredRecords({
      storage,
      storageKeyPrefix: ECDSA_STORAGE_KEY_PREFIX,
      storageIndexKey: ECDSA_STORAGE_INDEX_KEY,
      storageSessionIndexKey: ECDSA_STORAGE_SESSION_INDEX_KEY,
    });
  }
}
