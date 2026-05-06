import { normalizeThresholdEd25519ParticipantIds } from '@shared/threshold/participants';
import {
  normalizeInteger,
  normalizeOptionalNonEmptyString,
  normalizePositiveInteger,
} from '@shared/utils/normalize';
import { toAccountId, type AccountId } from '@/core/types/accountIds';
import type { EmailOtpAuthPolicy } from '@/core/types/seams';
import { normalizeThresholdEcdsaSessionKind } from './normalization';
import type {
  ThresholdEcdsaClientAdditiveShareHandle,
  EcdsaThresholdKeyId,
  ThresholdEcdsaCanonicalExportArtifact,
  ThresholdEcdsaSecp256k1KeyRef,
} from '../../interfaces/signing';
import type { ThresholdEcdsaSessionBootstrapResult } from '../../orchestration/thresholdActivation';
import {
  thresholdEcdsaChainTargetKey,
  thresholdEcdsaChainTargetFromRequest,
  thresholdEcdsaLaneKey,
  toWalletSubjectId,
  type EcdsaLaneIdentity,
  type ThresholdEcdsaChainTarget,
  type ThresholdEcdsaRuntimeLane,
  type WalletSubjectId,
} from '../../session/signingSession/ecdsaChainTarget';
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

export const THRESHOLD_ECDSA_SESSION_STORE_SOURCES = [
  'email_otp',
  ...THRESHOLD_ECDSA_PASSKEY_SESSION_STORE_SOURCES,
] as const satisfies readonly ThresholdEcdsaSessionStoreSource[];

export type ThresholdEcdsaEmailOtpAuthContext = {
  policy: EmailOtpAuthPolicy;
  retention: 'session' | 'single_use';
  reason: 'login' | 'sign';
  authMethod: 'email_otp';
  authSubjectId?: string;
  consumedAtMs?: number;
};

export type ThresholdEcdsaSessionRecord = {
  nearAccountId: AccountId;
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
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
  walletSigningSessionId: string;
  thresholdSessionAuthToken?: string;
  signingSessionSealKeyVersion?: string;
  signingSessionSealShamirPrimeB64u?: string;
  expiresAtMs: number;
  remainingUses: number;
  thresholdEcdsaPublicKeyB64u?: string;
  ethereumAddress?: string;
  relayerVerifyingShareB64u?: string;
  emailOtpAuthContext?: ThresholdEcdsaEmailOtpAuthContext;
  updatedAtMs: number;
  source: ThresholdEcdsaSessionStoreSource;
};

export type ConcreteThresholdEcdsaSessionRecord = ThresholdEcdsaSessionRecord & {
  subjectId: WalletSubjectId;
  chainTarget: ThresholdEcdsaChainTarget;
  walletSigningSessionId: string;
  thresholdSessionId: string;
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
  thresholdSessionAuthToken?: string;
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

export type ThresholdEcdsaSessionAuthTokenSource = 'ecdsa' | 'ed25519' | 'none';

export type ThresholdSessionSealTransportAuthMaterial =
  | {
      curve: 'ed25519';
      relayerUrl: string;
      walletSigningSessionId?: string;
      thresholdSessionAuthToken?: string;
      thresholdSessionAuthTokenSource: ThresholdEcdsaSessionAuthTokenSource;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    }
  | {
      curve: 'ecdsa';
      chainTarget: ThresholdEcdsaChainTarget;
      relayerUrl: string;
      walletSigningSessionId?: string;
      thresholdSessionAuthToken?: string;
      thresholdSessionAuthTokenSource: ThresholdEcdsaSessionAuthTokenSource;
      keyVersion?: string;
      shamirPrimeB64u?: string;
    };

export type ThresholdEcdsaSessionStoreDeps = {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  exportArtifactsByLane?: Map<string, ThresholdEcdsaCanonicalExportArtifact>;
  now?: () => number;
};

export type ThresholdEcdsaKeyRefLookupResult = {
  source: ThresholdEcdsaSessionStoreSource;
  keyRef: ThresholdEcdsaSecp256k1KeyRef;
};

function thresholdEcdsaAuthMethodForRecord(
  record: ThresholdEcdsaSessionRecord,
): 'email_otp' | 'passkey' {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

function normalizeOptionalRuntimeSubjectId(value: unknown): WalletSubjectId | null {
  const subjectId = normalizeOptionalNonEmptyString(value);
  return subjectId ? toWalletSubjectId(subjectId) : null;
}

function normalizeOptionalRuntimeChainTarget(value: unknown): ThresholdEcdsaChainTarget | null {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!obj) return null;
  try {
    return thresholdEcdsaChainTargetFromRequest({
      kind: obj.kind,
      chain: obj.chain,
      namespace: obj.namespace,
      chainId: obj.chainId,
      networkSlug: obj.networkSlug,
    });
  } catch {
    return null;
  }
}

export type ThresholdSessionStoreInvalidRecordReason =
  | 'invalid_json'
  | 'invalid_version'
  | 'invalid_shape';

export class ThresholdSessionStoreInvalidRecordError extends Error {
  readonly code = 'invalid_threshold_session_record';
  readonly curve: ThresholdSessionCurve;
  readonly recordKey: string;
  readonly reason: ThresholdSessionStoreInvalidRecordReason;
  readonly cause?: unknown;

  constructor(args: {
    curve: ThresholdSessionCurve;
    recordKey: string;
    reason: ThresholdSessionStoreInvalidRecordReason;
    cause?: unknown;
  }) {
    super(
      `[threshold-session-store] invalid ${args.curve} session record ${args.recordKey}: ${args.reason}`,
    );
    this.name = 'ThresholdSessionStoreInvalidRecordError';
    this.curve = args.curve;
    this.recordKey = args.recordKey;
    this.reason = args.reason;
    if ('cause' in args) {
      this.cause = args.cause;
    }
  }
}

const inMemoryEcdsaRecordsByLane = new Map<string, ThresholdEcdsaSessionRecord>();
const inMemoryEd25519RecordsByAccount = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519AccountBySessionId = new Map<string, string>();
const inMemoryEd25519RecordsByLane = new Map<string, ThresholdEd25519SessionRecord>();
const inMemoryEd25519LaneBySessionId = new Map<string, string>();

type ThresholdEcdsaRuntimeRecordIndex = {
  laneKeysByAccount: Map<string, Set<string>>;
  laneKeysBySubject: Map<string, Set<string>>;
  laneKeysBySubjectTarget: Map<string, Set<string>>;
  laneKeysBySubjectTargetSource: Map<string, Set<string>>;
  laneKeysBySubjectAuthMethod: Map<string, Set<string>>;
  laneKeysByThresholdSessionId: Map<string, Set<string>>;
};

const inMemoryEcdsaRecordIndex: ThresholdEcdsaRuntimeRecordIndex =
  createThresholdEcdsaRuntimeRecordIndex();
const ecdsaRecordIndexesByMap = new WeakMap<
  Map<string, ThresholdEcdsaSessionRecord>,
  ThresholdEcdsaRuntimeRecordIndex
>();

function createThresholdEcdsaRuntimeRecordIndex(): ThresholdEcdsaRuntimeRecordIndex {
  return {
    laneKeysByAccount: new Map(),
    laneKeysBySubject: new Map(),
    laneKeysBySubjectTarget: new Map(),
    laneKeysBySubjectTargetSource: new Map(),
    laneKeysBySubjectAuthMethod: new Map(),
    laneKeysByThresholdSessionId: new Map(),
  };
}

function clearThresholdEcdsaRuntimeRecordIndex(index: ThresholdEcdsaRuntimeRecordIndex): void {
  index.laneKeysByAccount.clear();
  index.laneKeysBySubject.clear();
  index.laneKeysBySubjectTarget.clear();
  index.laneKeysBySubjectTargetSource.clear();
  index.laneKeysBySubjectAuthMethod.clear();
  index.laneKeysByThresholdSessionId.clear();
}

function getThresholdEcdsaRuntimeRecordIndex(
  deps: ThresholdEcdsaSessionStoreDeps,
): ThresholdEcdsaRuntimeRecordIndex {
  const existing = ecdsaRecordIndexesByMap.get(deps.recordsByLane);
  if (existing) return existing;
  const index = createThresholdEcdsaRuntimeRecordIndex();
  for (const [storedLaneKey, record] of deps.recordsByLane.entries()) {
    const canonicalLaneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    if (!canonicalLaneKey || canonicalLaneKey !== storedLaneKey) {
      deps.recordsByLane.delete(storedLaneKey);
      deps.exportArtifactsByLane?.delete(storedLaneKey);
      continue;
    }
    indexThresholdEcdsaRecord(index, canonicalLaneKey, record);
  }
  ecdsaRecordIndexesByMap.set(deps.recordsByLane, index);
  return index;
}

function ecdsaIndexPart(value: unknown): string {
  return encodeURIComponent(String(value ?? '').trim());
}

function ecdsaIndexKey(parts: readonly unknown[]): string {
  return parts.map(ecdsaIndexPart).join('|');
}

function addIndexedLaneKey(
  indexMap: Map<string, Set<string>>,
  indexKey: string | null,
  laneKey: string,
): void {
  if (!indexKey) return;
  const existing = indexMap.get(indexKey);
  if (existing) {
    existing.add(laneKey);
    return;
  }
  indexMap.set(indexKey, new Set([laneKey]));
}

function deleteIndexedLaneKey(
  indexMap: Map<string, Set<string>>,
  indexKey: string | null,
  laneKey: string,
): void {
  if (!indexKey) return;
  const existing = indexMap.get(indexKey);
  if (!existing) return;
  existing.delete(laneKey);
  if (!existing.size) indexMap.delete(indexKey);
}

function thresholdEcdsaAccountIndexKey(record: ThresholdEcdsaSessionRecord): string {
  return ecdsaIndexKey([String(record.nearAccountId || '').trim()]);
}

function thresholdEcdsaThresholdSessionIndexKey(
  record: ThresholdEcdsaSessionRecord,
): string | null {
  const thresholdSessionId = normalizeOptionalNonEmptyString(record.thresholdSessionId);
  return thresholdSessionId ? ecdsaIndexKey([thresholdSessionId]) : null;
}

function thresholdEcdsaSubjectIndexKey(record: ThresholdEcdsaSessionRecord): string | null {
  return ecdsaIndexKey([record.subjectId]);
}

function thresholdEcdsaSubjectTargetIndexKey(
  record: ThresholdEcdsaSessionRecord,
): string | null {
  return ecdsaIndexKey([record.subjectId, thresholdEcdsaChainTargetKey(record.chainTarget)]);
}

function thresholdEcdsaSubjectTargetSourceIndexKey(
  record: ThresholdEcdsaSessionRecord,
): string | null {
  return ecdsaIndexKey([
    record.subjectId,
    thresholdEcdsaChainTargetKey(record.chainTarget),
    record.source,
  ]);
}

function thresholdEcdsaSubjectAuthMethodIndexKey(
  record: ThresholdEcdsaSessionRecord,
): string | null {
  return ecdsaIndexKey([record.subjectId, thresholdEcdsaAuthMethodForRecord(record)]);
}

function indexThresholdEcdsaRecord(
  index: ThresholdEcdsaRuntimeRecordIndex,
  laneKey: string,
  record: ThresholdEcdsaSessionRecord,
): void {
  addIndexedLaneKey(index.laneKeysByAccount, thresholdEcdsaAccountIndexKey(record), laneKey);
  addIndexedLaneKey(
    index.laneKeysByThresholdSessionId,
    thresholdEcdsaThresholdSessionIndexKey(record),
    laneKey,
  );
  addIndexedLaneKey(index.laneKeysBySubject, thresholdEcdsaSubjectIndexKey(record), laneKey);
  addIndexedLaneKey(
    index.laneKeysBySubjectTarget,
    thresholdEcdsaSubjectTargetIndexKey(record),
    laneKey,
  );
  addIndexedLaneKey(
    index.laneKeysBySubjectTargetSource,
    thresholdEcdsaSubjectTargetSourceIndexKey(record),
    laneKey,
  );
  addIndexedLaneKey(
    index.laneKeysBySubjectAuthMethod,
    thresholdEcdsaSubjectAuthMethodIndexKey(record),
    laneKey,
  );
}

function deindexThresholdEcdsaRecord(
  index: ThresholdEcdsaRuntimeRecordIndex,
  laneKey: string,
  record: ThresholdEcdsaSessionRecord,
): void {
  deleteIndexedLaneKey(index.laneKeysByAccount, thresholdEcdsaAccountIndexKey(record), laneKey);
  deleteIndexedLaneKey(
    index.laneKeysByThresholdSessionId,
    thresholdEcdsaThresholdSessionIndexKey(record),
    laneKey,
  );
  deleteIndexedLaneKey(index.laneKeysBySubject, thresholdEcdsaSubjectIndexKey(record), laneKey);
  deleteIndexedLaneKey(
    index.laneKeysBySubjectTarget,
    thresholdEcdsaSubjectTargetIndexKey(record),
    laneKey,
  );
  deleteIndexedLaneKey(
    index.laneKeysBySubjectTargetSource,
    thresholdEcdsaSubjectTargetSourceIndexKey(record),
    laneKey,
  );
  deleteIndexedLaneKey(
    index.laneKeysBySubjectAuthMethod,
    thresholdEcdsaSubjectAuthMethodIndexKey(record),
    laneKey,
  );
}

function getIndexedThresholdEcdsaRecord(
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>,
  laneKey: string,
): ThresholdEcdsaSessionRecord | null {
  return recordsByLane.get(laneKey) || null;
}

function indexedThresholdEcdsaRecords(args: {
  recordsByLane: Map<string, ThresholdEcdsaSessionRecord>;
  laneKeys: Iterable<string> | undefined;
}): ThresholdEcdsaSessionRecord[] {
  if (!args.laneKeys) return [];
  const records: ThresholdEcdsaSessionRecord[] = [];
  const seen = new Set<string>();
  for (const laneKey of args.laneKeys) {
    if (!laneKey || seen.has(laneKey)) continue;
    seen.add(laneKey);
    const record = getIndexedThresholdEcdsaRecord(args.recordsByLane, laneKey);
    if (record) records.push(record);
  }
  return records;
}

function normalizeThresholdEcdsaCanonicalExportArtifact(
  value: unknown,
): ThresholdEcdsaCanonicalExportArtifact | null {
  const obj = value && typeof value === 'object' ? (value as Record<string, unknown>) : null;
  if (!obj) return null;
  const artifactKind = String(obj.artifactKind || '').trim();
  const chainTargetRaw =
    obj.chainTarget && typeof obj.chainTarget === 'object' && !Array.isArray(obj.chainTarget)
      ? (obj.chainTarget as Record<string, unknown>)
      : null;
  const chainTarget = (() => {
    if (!chainTargetRaw) return null;
    try {
      return thresholdEcdsaChainTargetFromRequest(chainTargetRaw);
    } catch {
      return null;
    }
  })();
  const signingRootId = normalizeOptionalNonEmptyString(obj.signingRootId);
  const signingRootVersion = normalizeOptionalNonEmptyString(obj.signingRootVersion);
  const publicKeyHex = String(obj.publicKeyHex || '').trim();
  const privateKeyHex = String(obj.privateKeyHex || '').trim();
  const ethereumAddress = String(obj.ethereumAddress || '').trim();
  if (
    artifactKind !== 'ecdsa-hss-secp256k1-key-v1' ||
    !chainTarget ||
    !signingRootId ||
    !publicKeyHex ||
    !privateKeyHex ||
    !ethereumAddress
  ) {
    return null;
  }
  return {
    artifactKind: 'ecdsa-hss-secp256k1-key-v1',
    chainTarget,
    signingRootId,
    ...(signingRootVersion ? { signingRootVersion } : {}),
    publicKeyHex,
    privateKeyHex,
    ethereumAddress,
  };
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
  const thresholdSessionAuthToken = normalizeOptionalNonEmptyString(obj.thresholdSessionAuthToken);
  const signingSessionSealKeyVersion = normalizeOptionalNonEmptyString(
    obj.signingSessionSealKeyVersion,
  );
  const signingSessionSealShamirPrimeB64u = normalizeOptionalNonEmptyString(
    obj.signingSessionSealShamirPrimeB64u,
  );
  const runtimePolicyScope = normalizeStoredRuntimePolicyScope(obj, thresholdSessionAuthToken);
  const signingRootBinding = normalizeStoredSigningRootBinding(obj, runtimePolicyScope);
  const sourceRaw = String(obj.source || '').trim();
  const source: ThresholdEcdsaSessionStoreSource =
    sourceRaw === 'login' ||
    sourceRaw === 'registration' ||
    sourceRaw === 'manual-bootstrap' ||
    sourceRaw === 'email_otp'
      ? sourceRaw
      : 'manual-bootstrap';
  const subjectId = normalizeOptionalRuntimeSubjectId(obj.subjectId);
  const chainTarget = normalizeOptionalRuntimeChainTarget(obj.chainTarget);
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
    !ecdsaThresholdKeyId ||
    !relayerKeyId ||
    !clientVerifyingShareB64u ||
    !participantIds ||
    !thresholdSessionId ||
    !walletSigningSessionId ||
    !subjectId ||
    !chainTarget
  ) {
    throw new Error('Invalid threshold ECDSA canonical session record');
  }
  if (thresholdSessionKind === 'jwt' && !thresholdSessionAuthToken) {
    throw new Error(
      'Invalid threshold ECDSA canonical session record: missing threshold session auth token',
    );
  }
  if (expiresAtMs == null || expiresAtMs <= 0) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing expiresAtMs');
  }
  if (remainingUses == null || remainingUses < 0) {
    throw new Error('Invalid threshold ECDSA canonical session record: missing remainingUses');
  }

  return {
    nearAccountId,
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
    walletSigningSessionId,
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
    ...(signingSessionSealKeyVersion ? { signingSessionSealKeyVersion } : {}),
    ...(signingSessionSealShamirPrimeB64u ? { signingSessionSealShamirPrimeB64u } : {}),
    expiresAtMs,
    remainingUses,
    ...(thresholdEcdsaPublicKeyB64u ? { thresholdEcdsaPublicKeyB64u } : {}),
    ...(ethereumAddress ? { ethereumAddress } : {}),
    ...(relayerVerifyingShareB64u ? { relayerVerifyingShareB64u } : {}),
    ...(emailOtpAuthContext ? { emailOtpAuthContext } : {}),
    updatedAtMs,
    source,
    subjectId,
    chainTarget,
  } as ThresholdEcdsaSessionRecord;
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
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Invalid Email OTP auth context: missing context');
  }
  const obj = value as Record<string, unknown>;
  const policyRaw = String(obj.policy || '')
    .trim()
    .toLowerCase();
  if (policyRaw !== 'session' && policyRaw !== 'per_operation') {
    throw new Error('Invalid Email OTP auth context: invalid policy');
  }
  const policy: EmailOtpAuthPolicy = policyRaw;
  const retentionRaw = String(obj.retention || '')
    .trim()
    .toLowerCase();
  if (retentionRaw !== 'session' && retentionRaw !== 'single_use') {
    throw new Error('Invalid Email OTP auth context: invalid retention');
  }
  const retention: 'session' | 'single_use' = retentionRaw;
  if (policy === 'per_operation' && retention !== 'single_use') {
    throw new Error('Invalid Email OTP auth context: per-operation sessions must be single-use');
  }
  const reasonRaw = String(obj.reason || '')
    .trim()
    .toLowerCase();
  if (reasonRaw !== 'login' && reasonRaw !== 'sign') {
    throw new Error('Invalid Email OTP auth context: invalid reason');
  }
  const authMethodRaw = String(obj.authMethod || '')
    .trim()
    .toLowerCase();
  if (authMethodRaw !== 'email_otp') {
    throw new Error('Invalid Email OTP auth context: invalid authMethod');
  }
  const reason: 'login' | 'sign' = reasonRaw;
  const authSubjectId = normalizeOptionalNonEmptyString(obj.authSubjectId);
  const consumedAtMs = normalizePositiveInteger(obj.consumedAtMs);
  return {
    policy,
    retention,
    reason,
    authMethod: 'email_otp',
    ...(authSubjectId ? { authSubjectId } : {}),
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
  const thresholdSessionAuthToken = normalizeOptionalNonEmptyString(obj.thresholdSessionAuthToken);
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
  if (thresholdSessionKind === 'jwt' && !thresholdSessionAuthToken) {
    throw new Error(
      'Invalid threshold Ed25519 canonical session record: missing threshold session auth token',
    );
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
    ...(thresholdSessionAuthToken ? { thresholdSessionAuthToken } : {}),
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

  const laneKey = getThresholdEd25519SessionLaneKeyForRecord(record);
  if (!laneKey) return;
  pruneSupersededInMemoryThresholdEd25519Lanes({
    accountKey,
    activeLaneKey: laneKey,
  });
  const previousLaneRecord = inMemoryEd25519RecordsByLane.get(laneKey);
  const previousLaneSessionId = String(previousLaneRecord?.thresholdSessionId || '').trim();
  if (previousLaneSessionId && previousLaneSessionId !== thresholdSessionId) {
    inMemoryEd25519LaneBySessionId.delete(previousLaneSessionId);
  }
  inMemoryEd25519RecordsByLane.set(laneKey, record);
  inMemoryEd25519LaneBySessionId.set(thresholdSessionId, laneKey);
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

  const indexedLaneKey = String(inMemoryEd25519LaneBySessionId.get(thresholdSessionId) || '').trim();
  if (indexedLaneKey) {
    const indexedLaneRecord = inMemoryEd25519RecordsByLane.get(indexedLaneKey) || null;
    if (
      indexedLaneRecord &&
      String(indexedLaneRecord.thresholdSessionId || '').trim() === thresholdSessionId
    ) {
      return indexedLaneRecord;
    }
    inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
  }

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

type ThresholdEd25519SessionAuthMethod = 'email_otp' | 'passkey';

export type ThresholdEd25519SessionLane = {
  nearAccountId: AccountId;
  authMethod: ThresholdEd25519SessionAuthMethod;
  walletSigningSessionId: string;
  thresholdSessionId: string;
};

function thresholdEd25519AuthMethodForRecord(
  record: ThresholdEd25519SessionRecord,
): ThresholdEd25519SessionAuthMethod {
  return record.source === 'email_otp' ? 'email_otp' : 'passkey';
}

export function serializeThresholdEd25519SessionLaneKey(args: {
  nearAccountId: AccountId | string;
  authMethod: ThresholdEd25519SessionAuthMethod;
  walletSigningSessionId: string;
  thresholdSessionId: string;
}): string {
  const nearAccountId = String(toAccountId(args.nearAccountId)).trim();
  const authMethod = String(args.authMethod || '').trim();
  const walletSigningSessionId = normalizeOptionalNonEmptyString(args.walletSigningSessionId);
  const thresholdSessionId = normalizeOptionalNonEmptyString(args.thresholdSessionId);
  if (
    !nearAccountId ||
    (authMethod !== 'email_otp' && authMethod !== 'passkey') ||
    !walletSigningSessionId ||
    !thresholdSessionId
  ) {
    throw new Error('[SigningEngine] invalid threshold Ed25519 lane key input');
  }
  return [
    encodeLaneToken(nearAccountId),
    encodeLaneToken(authMethod),
    encodeLaneToken(walletSigningSessionId),
    encodeLaneToken(thresholdSessionId),
  ].join('|');
}

function getThresholdEd25519SessionLaneKeyForRecord(
  record: ThresholdEd25519SessionRecord,
): string | null {
  const walletSigningSessionId = normalizeOptionalNonEmptyString(record.walletSigningSessionId);
  const thresholdSessionId = normalizeOptionalNonEmptyString(record.thresholdSessionId);
  if (!walletSigningSessionId || !thresholdSessionId) return null;
  try {
    return serializeThresholdEd25519SessionLaneKey({
      nearAccountId: record.nearAccountId,
      authMethod: thresholdEd25519AuthMethodForRecord(record),
      walletSigningSessionId,
      thresholdSessionId,
    });
  } catch {
    return null;
  }
}

function thresholdEd25519RecordMatchesLane(
  record: ThresholdEd25519SessionRecord,
  lane: ThresholdEd25519SessionLane,
): boolean {
  return (
    String(record.nearAccountId) === String(lane.nearAccountId) &&
    thresholdEd25519AuthMethodForRecord(record) === lane.authMethod &&
    String(record.walletSigningSessionId || '').trim() === lane.walletSigningSessionId &&
    String(record.thresholdSessionId || '').trim() === lane.thresholdSessionId
  );
}

function deleteInMemoryThresholdEd25519LaneRecord(
  laneKey: string,
  record: ThresholdEd25519SessionRecord | null | undefined,
): void {
  inMemoryEd25519RecordsByLane.delete(laneKey);
  const thresholdSessionId = String(record?.thresholdSessionId || '').trim();
  if (thresholdSessionId && inMemoryEd25519LaneBySessionId.get(thresholdSessionId) === laneKey) {
    inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
  }
}

function pruneSupersededInMemoryThresholdEd25519Lanes(args: {
  accountKey: string;
  activeLaneKey: string;
}): void {
  for (const [laneKey, record] of inMemoryEd25519RecordsByLane.entries()) {
    if (laneKey === args.activeLaneKey) continue;
    if (String(record.nearAccountId || '').trim() !== args.accountKey) continue;
    deleteInMemoryThresholdEd25519LaneRecord(laneKey, record);
  }
}

function rememberInMemoryThresholdEcdsaRecord(record: ThresholdEcdsaSessionRecord): void {
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  const thresholdSessionId = String(record.thresholdSessionId || '').trim();
  if (!laneKey || !thresholdSessionId) return;

  const previous = inMemoryEcdsaRecordsByLane.get(laneKey);
  if (previous) {
    deindexThresholdEcdsaRecord(inMemoryEcdsaRecordIndex, laneKey, previous);
  }

  inMemoryEcdsaRecordsByLane.set(laneKey, record);
  indexThresholdEcdsaRecord(inMemoryEcdsaRecordIndex, laneKey, record);
}

function forgetInMemoryThresholdEcdsaRecord(laneKey: string): void {
  const record = inMemoryEcdsaRecordsByLane.get(laneKey);
  if (record) {
    deindexThresholdEcdsaRecord(inMemoryEcdsaRecordIndex, laneKey, record);
  }
  inMemoryEcdsaRecordsByLane.delete(laneKey);
}

function getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;

  const laneKeys = inMemoryEcdsaRecordIndex.laneKeysByThresholdSessionId.get(
    ecdsaIndexKey([thresholdSessionId]),
  );
  return (
    indexedThresholdEcdsaRecords({
      recordsByLane: inMemoryEcdsaRecordsByLane,
      laneKeys,
    })[0] || null
  );
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

function getThresholdEcdsaSessionLaneKeyForRecord(record: ThresholdEcdsaSessionRecord): string {
  return thresholdEcdsaLaneKey({
    subjectId: record.subjectId,
    authMethod: thresholdEcdsaAuthMethodForRecord(record),
    curve: 'ecdsa',
    chainTarget: record.chainTarget,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    signingRootId: record.signingRootId,
    signingRootVersion: record.signingRootVersion || 'default',
    walletSigningSessionId: record.walletSigningSessionId,
    thresholdSessionId: record.thresholdSessionId,
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
  chainTarget: ThresholdEcdsaChainTarget;
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
  const thresholdSessionAuthToken = normalizeOptionalNonEmptyString(
    keyRef.thresholdSessionAuthToken || args.bootstrap.session.jwt,
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
  if (thresholdSessionKind === 'jwt' && !thresholdSessionAuthToken) {
    throw new Error(
      '[SigningEngine] threshold ECDSA bootstrap did not provide thresholdSessionAuthToken',
    );
  }

  return normalizeThresholdEcdsaSessionRecord({
    nearAccountId: accountId,
    subjectId: keyRef.subjectId,
    chainTarget: args.chainTarget,
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
    thresholdSessionAuthToken,
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
    chainTarget: ThresholdEcdsaChainTarget;
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
    chainTarget: args.chainTarget,
    bootstrap: args.bootstrap,
    source: args.source,
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    nowMs,
    ...(args.signingSessionSeal ? { signingSessionSeal: args.signingSessionSeal } : {}),
  });
  const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  const previous = deps.recordsByLane.get(laneKey);
  if (previous) {
    deindexThresholdEcdsaRecord(depsIndex, laneKey, previous);
  }
  deps.recordsByLane.set(laneKey, record);
  indexThresholdEcdsaRecord(depsIndex, laneKey, record);
  rememberInMemoryThresholdEcdsaRecord(record);
  setEcdsaExportArtifactForLane({
    deps,
    laneKey,
    artifact:
      normalizeThresholdEcdsaCanonicalExportArtifact(
        args.bootstrap.thresholdEcdsaKeyRef.ecdsaHssExportArtifact,
      ) || undefined,
  });
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
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  const previous = deps.recordsByLane.get(laneKey);
  if (previous) {
    deindexThresholdEcdsaRecord(depsIndex, laneKey, previous);
  }
  deps.recordsByLane.set(laneKey, record);
  indexThresholdEcdsaRecord(depsIndex, laneKey, record);
  rememberInMemoryThresholdEcdsaRecord(record);
  return record;
}

export function listThresholdEcdsaSessionRecordsForTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    signingRootId?: string;
    signingRootVersion?: string;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord[] {
  const subjectId = toWalletSubjectId(args.subjectId);
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const indexKey = args.source
    ? ecdsaIndexKey([subjectId, targetKey, args.source])
    : ecdsaIndexKey([subjectId, targetKey]);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  const depsMap = args.source
    ? depsIndex.laneKeysBySubjectTargetSource
    : depsIndex.laneKeysBySubjectTarget;
  const memoryMap = args.source
    ? inMemoryEcdsaRecordIndex.laneKeysBySubjectTargetSource
    : inMemoryEcdsaRecordIndex.laneKeysBySubjectTarget;
  const recordsByLane = new Map<string, ThresholdEcdsaSessionRecord>();
  for (const record of [
    ...indexedThresholdEcdsaRecords({
      recordsByLane: deps.recordsByLane,
      laneKeys: depsMap.get(indexKey),
    }),
    ...indexedThresholdEcdsaRecords({
      recordsByLane: inMemoryEcdsaRecordsByLane,
      laneKeys: memoryMap.get(indexKey),
    }),
  ]) {
    if (record.subjectId !== subjectId) continue;
    if (thresholdEcdsaChainTargetKey(record.chainTarget) !== targetKey) continue;
    if (args.source && record.source !== args.source) continue;
    if (!matchesExpectedSigningRootBinding(record, args)) continue;
    recordsByLane.set(getThresholdEcdsaSessionLaneKeyForRecord(record), record);
  }
  return Array.from(recordsByLane, ([, record]) => record).sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
  );
}

export function getThresholdEcdsaSessionRecordForTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    signingRootId?: string;
    signingRootVersion?: string;
    source: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaSessionRecord {
  const candidates = listThresholdEcdsaSessionRecordsForTarget(deps, args);
  if (candidates.length === 1) return candidates[0]!;
  if (candidates.length > 1) {
    throw new Error(
      `[SigningEngine] ambiguous threshold ECDSA session for ${String(args.subjectId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}; exact lane identity is required`,
    );
  }

  throw new Error(
    `[SigningEngine] missing concrete threshold ECDSA session for ${String(args.subjectId)} ${thresholdEcdsaChainTargetKey(args.chainTarget)}; reconnect threshold session via bootstrapEcdsaSession`,
  );
}

export function getThresholdEcdsaSessionRecordByIdentity(
  deps: ThresholdEcdsaSessionStoreDeps,
  identity: EcdsaLaneIdentity,
): ThresholdEcdsaSessionRecord | null {
  const laneKey = thresholdEcdsaLaneKey(identity);
  return deps.recordsByLane.get(laneKey) || inMemoryEcdsaRecordsByLane.get(laneKey) || null;
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
    subjectId: record.subjectId,
    chainTarget: record.chainTarget,
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
    walletSigningSessionId: record.walletSigningSessionId,
    ...(record.thresholdSessionAuthToken ? { thresholdSessionAuthToken: record.thresholdSessionAuthToken } : {}),
    ...(record.thresholdEcdsaPublicKeyB64u
      ? { thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u }
      : {}),
    ...(record.ethereumAddress ? { ethereumAddress: record.ethereumAddress } : {}),
    ...(record.relayerVerifyingShareB64u
      ? { relayerVerifyingShareB64u: record.relayerVerifyingShareB64u }
      : {}),
  };
}

export function listThresholdEcdsaKeyRefsForTarget(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    signingRootId?: string;
    signingRootVersion?: string;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): ThresholdEcdsaKeyRefLookupResult[] {
  return listThresholdEcdsaSessionRecordsForTarget(deps, args).map((record) => ({
    source: record.source,
    keyRef: thresholdEcdsaKeyRefFromRecord(deps, record),
  }));
}

export function getThresholdEcdsaKeyRefByIdentity(
  deps: ThresholdEcdsaSessionStoreDeps,
  identity: EcdsaLaneIdentity,
): ThresholdEcdsaKeyRefLookupResult | null {
  const record = getThresholdEcdsaSessionRecordByIdentity(deps, identity);
  return record
    ? {
        source: record.source,
        keyRef: thresholdEcdsaKeyRefFromRecord(deps, record),
      }
    : null;
}

export function getEmailOtpThresholdEcdsaSessionRecordForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    signingRootId?: string;
    signingRootVersion?: string;
  },
): ThresholdEcdsaSessionRecord {
  return getThresholdEcdsaSessionRecordForTarget(deps, {
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
    ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
    source: 'email_otp',
  });
}

export function getEmailOtpThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
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
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    signingRootId?: string;
    signingRootVersion?: string;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  },
): ThresholdEcdsaSessionRecord {
  return getThresholdEcdsaSessionRecordForTarget(deps, {
    subjectId: args.subjectId,
    chainTarget: args.chainTarget,
    ...(args.signingRootId ? { signingRootId: args.signingRootId } : {}),
    ...(args.signingRootVersion ? { signingRootVersion: args.signingRootVersion } : {}),
    source: args.source,
  });
}

export function getPasskeyThresholdEcdsaKeyRefForSigning(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    signingRootId?: string;
    signingRootVersion?: string;
    source: Exclude<ThresholdEcdsaSessionStoreSource, 'email_otp'>;
  },
): ThresholdEcdsaSecp256k1KeyRef {
  const record = getPasskeyThresholdEcdsaSessionRecordForSigning(deps, args);
  return thresholdEcdsaKeyRefFromRecord(deps, record);
}

export function clearThresholdEcdsaSessionRecordForAccount(
  deps: ThresholdEcdsaSessionStoreDeps,
  nearAccountId: AccountId | string,
): void {
  const accountId = toAccountId(nearAccountId);
  const accountKey = String(accountId);
  const indexKey = ecdsaIndexKey([accountKey]);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  for (const laneKey of [...(depsIndex.laneKeysByAccount.get(indexKey) || [])]) {
    const record = deps.recordsByLane.get(laneKey);
    if (record) deindexThresholdEcdsaRecord(depsIndex, laneKey, record);
    deps.recordsByLane.delete(laneKey);
    deps.exportArtifactsByLane?.delete(laneKey);
  }
  for (const laneKey of [...(inMemoryEcdsaRecordIndex.laneKeysByAccount.get(indexKey) || [])]) {
    forgetInMemoryThresholdEcdsaRecord(laneKey);
  }
}

export function clearThresholdEcdsaSessionRecordForLane(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
  },
): void {
  const subjectId = toWalletSubjectId(args.subjectId);
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const indexKey = args.source
    ? ecdsaIndexKey([subjectId, targetKey, args.source])
    : ecdsaIndexKey([subjectId, targetKey]);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  const depsMap = args.source
    ? depsIndex.laneKeysBySubjectTargetSource
    : depsIndex.laneKeysBySubjectTarget;
  const memoryMap = args.source
    ? inMemoryEcdsaRecordIndex.laneKeysBySubjectTargetSource
    : inMemoryEcdsaRecordIndex.laneKeysBySubjectTarget;
  for (const laneKey of [...(depsMap.get(indexKey) || [])]) {
    const record = deps.recordsByLane.get(laneKey);
    if (record) deindexThresholdEcdsaRecord(depsIndex, laneKey, record);
    deps.recordsByLane.delete(laneKey);
    deps.exportArtifactsByLane?.delete(laneKey);
    forgetInMemoryThresholdEcdsaRecord(laneKey);
  }
  for (const laneKey of [...(memoryMap.get(indexKey) || [])]) {
    forgetInMemoryThresholdEcdsaRecord(laneKey);
  }
}

export function markThresholdEcdsaEmailOtpSessionConsumedForAccount(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTarget: ThresholdEcdsaChainTarget;
    uses?: number;
  },
): ThresholdEcdsaSessionRecord | null {
  const subjectId = toWalletSubjectId(args.subjectId);
  const targetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const nowMs = Math.max(0, Math.floor((deps.now || Date.now)()));
  const uses = Math.max(1, Math.floor(Number(args.uses) || 1));
  let updatedRecord: ThresholdEcdsaSessionRecord | null = null;
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  const laneKeys = [
    ...(depsIndex.laneKeysBySubjectTargetSource.get(
      ecdsaIndexKey([subjectId, targetKey, 'email_otp']),
    ) || []),
  ];

  for (const laneKey of laneKeys) {
    const record = deps.recordsByLane.get(laneKey);
    if (!record) continue;
    if (record.source !== 'email_otp' || !record.emailOtpAuthContext) continue;
    const nextRecord: ThresholdEcdsaSessionRecord = {
      ...record,
      remainingUses: Math.max(0, Math.floor(Number(record.remainingUses) || 0) - uses),
      emailOtpAuthContext: {
        ...record.emailOtpAuthContext,
        consumedAtMs: nowMs,
      },
      updatedAtMs: nowMs,
    };
    deindexThresholdEcdsaRecord(depsIndex, laneKey, record);
    deps.recordsByLane.set(laneKey, nextRecord);
    indexThresholdEcdsaRecord(depsIndex, laneKey, nextRecord);
    rememberInMemoryThresholdEcdsaRecord(nextRecord);
    updatedRecord = nextRecord;
  }

  return updatedRecord;
}

export function clearAllThresholdEcdsaSessionRecords(deps: ThresholdEcdsaSessionStoreDeps): void {
  deps.recordsByLane.clear();
  deps.exportArtifactsByLane?.clear();
  clearThresholdEcdsaRuntimeRecordIndex(getThresholdEcdsaRuntimeRecordIndex(deps));
  inMemoryEcdsaRecordsByLane.clear();
  clearThresholdEcdsaRuntimeRecordIndex(inMemoryEcdsaRecordIndex);
}

export function getStoredThresholdEcdsaSessionRecordByThresholdSessionId(
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  return getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
}

export function getStoredThresholdEcdsaSessionRecordByThresholdSessionIdForTarget(args: {
  thresholdSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
}): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(args.thresholdSessionId || '').trim();
  if (!thresholdSessionId) return null;
  const expectedTargetKey = thresholdEcdsaChainTargetKey(args.chainTarget);
  const laneKeys = inMemoryEcdsaRecordIndex.laneKeysByThresholdSessionId.get(
    ecdsaIndexKey([thresholdSessionId]),
  );
  const candidates = indexedThresholdEcdsaRecords({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    laneKeys,
  }).filter(
    (record) =>
      String(record.thresholdSessionId || '').trim() === thresholdSessionId &&
      thresholdEcdsaChainTargetKey(record.chainTarget) === expectedTargetKey,
  );
  const unique = new Map<string, ThresholdEcdsaSessionRecord>();
  for (const candidate of candidates) {
    unique.set(getThresholdEcdsaSessionLaneKeyForRecord(candidate), candidate);
  }
  return unique.size === 1 ? [...unique.values()][0] : null;
}

export function getThresholdEcdsaSessionRecordByThresholdSessionId(
  deps: ThresholdEcdsaSessionStoreDeps,
  thresholdSessionIdRaw: string,
): ThresholdEcdsaSessionRecord | null {
  const thresholdSessionId = String(thresholdSessionIdRaw || '').trim();
  if (!thresholdSessionId) return null;
  const indexKey = ecdsaIndexKey([thresholdSessionId]);
  const depsRecord =
    indexedThresholdEcdsaRecords({
      recordsByLane: deps.recordsByLane,
      laneKeys: getThresholdEcdsaRuntimeRecordIndex(deps).laneKeysByThresholdSessionId.get(indexKey),
    })[0] || null;
  if (depsRecord) return depsRecord;
  return getInMemoryThresholdEcdsaSessionRecordByThresholdSessionId(thresholdSessionId);
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
  thresholdSessionAuthToken?: string;
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
    ...(String(args.thresholdSessionAuthToken || '').trim()
      ? { thresholdSessionAuthToken: String(args.thresholdSessionAuthToken || '').trim() }
      : {}),
    expiresAtMs: Math.floor(Number(args.expiresAtMs) || 0),
    remainingUses: Math.floor(Number(args.remainingUses) || 0),
    ...(args.emailOtpAuthContext ? { emailOtpAuthContext: args.emailOtpAuthContext } : {}),
    updatedAtMs: Math.floor(Number(args.updatedAtMs ?? Date.now()) || 0),
    source: args.source || 'manual-connect',
  });
  rememberInMemoryThresholdEd25519Record(record);
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
    thresholdSessionAuthToken: existing.thresholdSessionAuthToken,
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
  return null;
}

export function listStoredThresholdEd25519SessionRecordsForAccount(
  nearAccountIdRaw: AccountId | string,
): ThresholdEd25519SessionRecord[] {
  try {
    const accountKey = String(toAccountId(nearAccountIdRaw)).trim();
    const record = accountKey ? inMemoryEd25519RecordsByAccount.get(accountKey) || null : null;
    return record ? [record] : [];
  } catch {
    return [];
  }
}

export function listStoredThresholdEcdsaSessionRecordsForAccount(
  nearAccountIdRaw: AccountId | string,
  filter: {
    chainTarget?: ThresholdEcdsaChainTarget;
    source?: ThresholdEcdsaSessionStoreSource;
    signingRootId?: string;
    signingRootVersion?: string;
  } = {},
): ThresholdEcdsaSessionRecord[] {
  let accountKey = '';
  try {
    accountKey = String(toAccountId(nearAccountIdRaw)).trim();
  } catch {
    return [];
  }
  if (!accountKey) return [];

  const records: ThresholdEcdsaSessionRecord[] = [];
  const seen = new Set<string>();
  const laneKeys = inMemoryEcdsaRecordIndex.laneKeysByAccount.get(ecdsaIndexKey([accountKey]));
  const filterTargetKey = filter.chainTarget
    ? thresholdEcdsaChainTargetKey(filter.chainTarget)
    : null;
  for (const record of indexedThresholdEcdsaRecords({
    recordsByLane: inMemoryEcdsaRecordsByLane,
    laneKeys,
  })) {
    if (filterTargetKey && thresholdEcdsaChainTargetKey(record.chainTarget) !== filterTargetKey) {
      continue;
    }
    if (filter.source && record.source !== filter.source) continue;
    if (!matchesExpectedSigningRootBinding(record, filter)) continue;
    const laneKey = getThresholdEcdsaSessionLaneKeyForRecord(record);
    if (!laneKey || seen.has(laneKey)) continue;
    seen.add(laneKey);
    records.push(record);
  }

  return records.sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
  );
}

function concreteRuntimeRecord(
  record: ThresholdEcdsaSessionRecord,
): ConcreteThresholdEcdsaSessionRecord {
  return record;
}

function ecdsaRuntimeLaneFromRecord(args: {
  record: ThresholdEcdsaSessionRecord;
  subjectId: WalletSubjectId;
}): ThresholdEcdsaRuntimeLane | null {
  const concreteRecord = concreteRuntimeRecord(args.record);
  if (concreteRecord.subjectId !== args.subjectId) return null;
  return {
    subjectId: args.subjectId,
    authMethod: thresholdEcdsaAuthMethodForRecord(concreteRecord),
    curve: 'ecdsa',
    chainTarget: concreteRecord.chainTarget,
    ecdsaThresholdKeyId: concreteRecord.ecdsaThresholdKeyId,
    signingRootId: concreteRecord.signingRootId,
    signingRootVersion: concreteRecord.signingRootVersion || 'default',
    walletSigningSessionId: concreteRecord.walletSigningSessionId,
    thresholdSessionId: concreteRecord.thresholdSessionId,
    source: 'runtime_session_record',
    remainingUses: concreteRecord.remainingUses,
    expiresAtMs: concreteRecord.expiresAtMs,
    updatedAtMs: concreteRecord.updatedAtMs,
  };
}

export function listThresholdEcdsaRuntimeLanesForSnapshot(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
    chainTargets: readonly ThresholdEcdsaChainTarget[];
  },
): ThresholdEcdsaRuntimeLane[] {
  const targetKeys = new Set(args.chainTargets.map(thresholdEcdsaChainTargetKey));
  return listThresholdEcdsaRuntimeLanesForSubject(deps, { subjectId: args.subjectId }).filter(
    (lane) => targetKeys.has(thresholdEcdsaChainTargetKey(lane.chainTarget)),
  );
}

export function listThresholdEcdsaRuntimeLanesForSubject(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: {
    subjectId: WalletSubjectId;
  },
): ThresholdEcdsaRuntimeLane[] {
  const lanes: ThresholdEcdsaRuntimeLane[] = [];
  const seen = new Set<string>();
  const indexKey = ecdsaIndexKey([args.subjectId]);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  for (const record of [
    ...indexedThresholdEcdsaRecords({
      recordsByLane: deps.recordsByLane,
      laneKeys: depsIndex.laneKeysBySubject.get(indexKey),
    }),
    ...indexedThresholdEcdsaRecords({
      recordsByLane: inMemoryEcdsaRecordsByLane,
      laneKeys: inMemoryEcdsaRecordIndex.laneKeysBySubject.get(indexKey),
    }),
  ]) {
    const lane = ecdsaRuntimeLaneFromRecord({
      record,
      subjectId: args.subjectId,
    });
    if (!lane) continue;
    const laneKey = thresholdEcdsaLaneKey(lane);
    if (seen.has(laneKey)) continue;
    seen.add(laneKey);
    lanes.push(lane);
  }
  return lanes.sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
  );
}

export function getThresholdEcdsaRuntimeLaneByIdentity(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: { identity: EcdsaLaneIdentity },
): ThresholdEcdsaRuntimeLane | null {
  const expectedKey = thresholdEcdsaLaneKey(args.identity);
  const record =
    deps.recordsByLane.get(expectedKey) || inMemoryEcdsaRecordsByLane.get(expectedKey) || null;
  if (!record) return null;
  const lane = ecdsaRuntimeLaneFromRecord({
    record,
    subjectId: args.identity.subjectId,
  });
  return lane && thresholdEcdsaLaneKey(lane) === expectedKey ? lane : null;
}

export function listConcreteThresholdEcdsaSessionRecordsForSubject(
  deps: ThresholdEcdsaSessionStoreDeps,
  args: { subjectId: WalletSubjectId },
): ConcreteThresholdEcdsaSessionRecord[] {
  const recordsByKey = new Map<string, ConcreteThresholdEcdsaSessionRecord>();
  const indexKey = ecdsaIndexKey([args.subjectId]);
  const depsIndex = getThresholdEcdsaRuntimeRecordIndex(deps);
  for (const record of [
    ...indexedThresholdEcdsaRecords({
      recordsByLane: deps.recordsByLane,
      laneKeys: depsIndex.laneKeysBySubject.get(indexKey),
    }),
    ...indexedThresholdEcdsaRecords({
      recordsByLane: inMemoryEcdsaRecordsByLane,
      laneKeys: inMemoryEcdsaRecordIndex.laneKeysBySubject.get(indexKey),
    }),
  ]) {
    const concreteRecord = concreteRuntimeRecord(record);
    if (concreteRecord.subjectId !== args.subjectId) continue;
    recordsByKey.set(getThresholdEcdsaSessionLaneKeyForRecord(concreteRecord), concreteRecord);
  }
  return [...recordsByKey.values()].sort(
    (left, right) =>
      Math.floor(Number(right.updatedAtMs) || 0) - Math.floor(Number(left.updatedAtMs) || 0),
  );
}

export function getStoredThresholdEd25519SessionRecordForLane(args: {
  nearAccountId: AccountId | string;
  authMethod: ThresholdEd25519SessionAuthMethod;
  walletSigningSessionId: string;
  thresholdSessionId: string;
}): ThresholdEd25519SessionRecord | null {
  let lane: ThresholdEd25519SessionLane;
  let laneKey: string;
  try {
    lane = {
      nearAccountId: toAccountId(args.nearAccountId),
      authMethod: args.authMethod,
      walletSigningSessionId: String(args.walletSigningSessionId || '').trim(),
      thresholdSessionId: String(args.thresholdSessionId || '').trim(),
    };
    laneKey = serializeThresholdEd25519SessionLaneKey(lane);
  } catch {
    return null;
  }
  const record = inMemoryEd25519RecordsByLane.get(laneKey) || null;
  if (record && thresholdEd25519RecordMatchesLane(record, lane)) return record;
  if (record) {
    inMemoryEd25519RecordsByLane.delete(laneKey);
    const thresholdSessionId = String(record.thresholdSessionId || '').trim();
    if (thresholdSessionId && inMemoryEd25519LaneBySessionId.get(thresholdSessionId) === laneKey) {
      inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
    }
  }
  return null;
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
    ...(record.thresholdSessionAuthToken ? { thresholdSessionAuthToken: record.thresholdSessionAuthToken } : {}),
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
    const accountKey = String(nearAccountId);
    inMemoryEd25519RecordsByAccount.delete(accountKey);
    for (const [laneKey, record] of inMemoryEd25519RecordsByLane.entries()) {
      if (String(record.nearAccountId || '').trim() !== accountKey) continue;
      const thresholdSessionId = String(record.thresholdSessionId || '').trim();
      inMemoryEd25519RecordsByLane.delete(laneKey);
      if (thresholdSessionId && inMemoryEd25519LaneBySessionId.get(thresholdSessionId) === laneKey) {
        inMemoryEd25519LaneBySessionId.delete(thresholdSessionId);
      }
    }
  } catch {}
}

export function clearAllStoredThresholdEd25519SessionRecords(): void {
  inMemoryEd25519RecordsByAccount.clear();
  inMemoryEd25519AccountBySessionId.clear();
  inMemoryEd25519RecordsByLane.clear();
  inMemoryEd25519LaneBySessionId.clear();
}

export function getStoredThresholdSessionRecordForAccount<
  TCurve extends ThresholdSessionCurve,
>(args: {
  curve: TCurve;
  nearAccountId: AccountId | string;
  chainTarget?: ThresholdEcdsaChainTarget;
  signingRootId?: string;
  signingRootVersion?: string;
}): ThresholdSessionRecordByCurve[TCurve] | null {
  if (args.curve === 'ecdsa') {
    const nearAccountId = toAccountId(args.nearAccountId);
    let selected: ThresholdEcdsaSessionRecord | null = null;
    const targetKey = args.chainTarget ? thresholdEcdsaChainTargetKey(args.chainTarget) : null;
    for (const record of indexedThresholdEcdsaRecords({
      recordsByLane: inMemoryEcdsaRecordsByLane,
      laneKeys: inMemoryEcdsaRecordIndex.laneKeysByAccount.get(ecdsaIndexKey([String(nearAccountId)])),
    })) {
      if (targetKey && thresholdEcdsaChainTargetKey(record.chainTarget) !== targetKey) continue;
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
    inMemoryEcdsaRecordsByLane.clear();
    clearThresholdEcdsaRuntimeRecordIndex(inMemoryEcdsaRecordIndex);
  }
}
