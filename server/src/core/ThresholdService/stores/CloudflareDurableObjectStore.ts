import type { NormalizedLogger } from '../../logger';
import type { CloudflareDurableObjectNamespaceLike, ThresholdStoreConfigInput } from '../../types';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from '../../defaultConfigsServer';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  parseEcdsaHssRoleLocalKeyRecord,
  isObject,
  parseThresholdEcdsaPresignSessionRecord,
  parseThresholdEcdsaPresignatureRelayerShareRecord,
  parseThresholdEcdsaSigningSessionRecord,
  parseEd25519AuthSessionRecord,
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseThresholdEd25519KeyRecord,
  parseThresholdEd25519MpcSessionRecord,
  parseThresholdEd25519PresignRecord,
  parseThresholdEd25519SigningSessionRecord,
  toThresholdEcdsaAuthPrefix,
  toThresholdEcdsaKeyPrefix,
  toThresholdEcdsaPresignPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEcdsaSessionPrefix,
  toThresholdEcdsaSigningPrefix,
  toThresholdEd25519AuthPrefix,
  toThresholdEd25519KeyPrefix,
  toThresholdEd25519PrefixFromBase,
  toThresholdEd25519SessionPrefix,
} from '../validation';
import type {
  ThresholdAuthReplayGuardResult,
  ThresholdEd25519AuthConsumeUsesResult,
  Ed25519AuthSessionRecord,
  Ed25519AuthSessionStore,
} from './AuthSessionStore';
import type {
  ThresholdEcdsaIntegratedKeyStore,
  ThresholdEd25519KeyRecord,
  ThresholdEd25519KeyStore,
} from './KeyStore';
import type { EcdsaHssRoleLocalKeyRecord } from '../../types';
import type {
  ThresholdEd25519CoordinatorSigningSessionRecord,
  ThresholdEd25519ConsumePresignRefillRateLimitResult,
  ThresholdEd25519MpcSessionRecord,
  ThresholdEd25519PresignCapacity,
  ThresholdEd25519CheckPresignCapacityResult,
  ThresholdEd25519PresignExpectedScope,
  ThresholdEd25519PresignRefillRateLimitBucket,
  ThresholdEd25519PresignRefillRateLimitPolicy,
  ThresholdEd25519PutPresignWithCapacityResult,
  ThresholdEd25519PresignRecord,
  ThresholdEd25519ClaimMpcSessionResult,
  ThresholdEd25519ReadMpcSessionResult,
  ThresholdEd25519SessionStore,
  ThresholdEd25519SigningSessionRecord,
  ThresholdEd25519TakePresignForFinalizeResult,
} from './SessionStore';
import type {
  ThresholdEcdsaPresignSessionCasResult,
  ThresholdEcdsaPresignSessionRecord,
  ThresholdEcdsaPresignSessionStore,
  ThresholdEcdsaPresignaturePool,
  ThresholdEcdsaPresignatureRelayerShareRecord,
  ThresholdEcdsaSigningSessionRecord,
  ThresholdEcdsaSigningSessionStore,
} from './EcdsaSigningStore';

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };

type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

type DoGetRequest = { op: 'get'; key: string };
type DoSetRequest = { op: 'set'; key: string; value: unknown; ttlMs?: number };
type DoDelRequest = { op: 'del'; key: string };
type DoReadVersionedRequest = { op: 'readVersioned'; key: string };
type DoClaimVersionedRequest = { op: 'claimVersioned'; key: string; expectedVersion: string };
type DoSetWithIdentityGuardRequest = {
  op: 'setWithIdentityGuard';
  key: string;
  identityKey: string;
  identityValue: string;
  keyHandleKey: string;
  keyHandleValue: string;
  value: unknown;
  ttlMs?: number;
};
type DoDelWithIdentityGuardRequest = {
  op: 'delWithIdentityGuard';
  key: string;
  identityKey: string;
  identityValue: string;
  keyHandleKey: string;
  keyHandleValue: string;
};
type DoGetDelRequest = { op: 'getdel'; key: string };
type DoAuthConsumeUseCountRequest = { op: 'authConsumeUseCount'; key: string };
type DoAuthConsumeUseCountOnceRequest = {
  op: 'authConsumeUseCountOnce';
  key: string;
  idempotencyKey: string;
};
type DoAuthHasConsumedUseCountOnceRequest = {
  op: 'authHasConsumedUseCountOnce';
  key: string;
  idempotencyKey: string;
};
type DoAuthReserveReplayGuardRequest = {
  op: 'authReserveReplayGuard';
  key: string;
  expiresAtMs: number;
};
type DoEcdsaPresignPutRequest = { op: 'ecdsaPresignPut'; listKey: string; value: unknown };
type DoEcdsaPresignReserveRequest = {
  op: 'ecdsaPresignReserve';
  listKey: string;
  reservedKeyPrefix: string;
  ttlMs?: number;
};
type DoEcdsaPresignReserveByIdRequest = {
  op: 'ecdsaPresignReserveById';
  listKey: string;
  reservedKeyPrefix: string;
  presignatureId: string;
  ttlMs?: number;
};
type DoEcdsaPresignSessionCreateRequest = {
  op: 'ecdsaPresignSessionCreate';
  key: string;
  value: unknown;
  ttlMs?: number;
};
type DoEcdsaPresignSessionAdvanceCasRequest = {
  op: 'ecdsaPresignSessionAdvanceCas';
  key: string;
  expectedVersion: number;
  value: unknown;
  ttlMs?: number;
};
type DoEd25519PresignTakeRequest = {
  op: 'ed25519PresignTake';
  key: string;
  presignId: string;
  expectedScope: ThresholdEd25519PresignExpectedScope;
  walletIndexKey: string;
  globalIndexKey: string;
};
type DoEd25519PresignPutWithCapacityRequest = {
  op: 'ed25519PresignPutWithCapacity';
  key: string;
  presignId: string;
  value: ThresholdEd25519PresignRecord;
  ttlMs: number;
  capacity: ThresholdEd25519PresignCapacity;
  walletIndexKey: string;
  globalIndexKey: string;
};
type DoEd25519PresignCheckCapacityRequest = {
  op: 'ed25519PresignCheckCapacity';
  capacity: ThresholdEd25519PresignCapacity;
  walletIndexKey: string;
  globalIndexKey: string;
};
type DoEd25519PresignConsumeRateLimitRequest = {
  op: 'ed25519PresignConsumeRateLimit';
  key: string;
  cost: number;
  policy: ThresholdEd25519PresignRefillRateLimitPolicy;
};
type DoRequest =
  | DoGetRequest
  | DoSetRequest
  | DoDelRequest
  | DoReadVersionedRequest
  | DoClaimVersionedRequest
  | DoSetWithIdentityGuardRequest
  | DoDelWithIdentityGuardRequest
  | DoGetDelRequest
  | DoAuthConsumeUseCountRequest
  | DoAuthConsumeUseCountOnceRequest
  | DoAuthHasConsumedUseCountOnceRequest
  | DoAuthReserveReplayGuardRequest
  | DoEcdsaPresignPutRequest
  | DoEcdsaPresignReserveRequest
  | DoEcdsaPresignReserveByIdRequest
  | DoEcdsaPresignSessionCreateRequest
  | DoEcdsaPresignSessionAdvanceCasRequest
  | DoEd25519PresignCheckCapacityRequest
  | DoEd25519PresignConsumeRateLimitRequest
  | DoEd25519PresignPutWithCapacityRequest
  | DoEd25519PresignTakeRequest;

type DoAuthEntry = {
  record: Ed25519AuthSessionRecord;
  remainingUses: number;
  expiresAtMs: number;
};

type ThresholdEcdsaSharedIdentityGuard = {
  contextKey: string;
  identityValue: string;
};
type ThresholdEcdsaStoredKeyRecord = EcdsaHssRoleLocalKeyRecord;

function ecdsaIdentityPart(value: unknown): string {
  return encodeURIComponent(String(value ?? '').trim());
}

function ecdsaSigningRootVersion(record: ThresholdEcdsaStoredKeyRecord): string {
  return String(record.signingRootVersion || '').trim() || 'default';
}

async function withEcdsaHssRoleLocalRecordKeyHandle(
  record: EcdsaHssRoleLocalKeyRecord,
): Promise<EcdsaHssRoleLocalKeyRecord & { keyHandle: string }> {
  const parsed = parseEcdsaHssRoleLocalKeyRecord(record);
  if (!parsed) throw new Error('Invalid threshold-ecdsa role-local key record');
  const keyHandle = String(
    await deriveThresholdEcdsaKeyHandle({
      ecdsaThresholdKeyId: parsed.ecdsaThresholdKeyId,
      signingRootId: parsed.signingRootId,
      signingRootVersion: ecdsaSigningRootVersion(parsed),
    }),
  );
  if (parsed.keyHandle !== keyHandle) {
    throw new Error('[threshold-ecdsa] ECDSA key handle does not match threshold key identity');
  }
  return { ...parsed, keyHandle };
}

async function parseStoredEcdsaHssRoleLocalKeyRecord(
  raw: unknown,
): Promise<(EcdsaHssRoleLocalKeyRecord & { keyHandle: string }) | null> {
  const parsed = parseEcdsaHssRoleLocalKeyRecord(raw);
  return parsed ? await withEcdsaHssRoleLocalRecordKeyHandle(parsed) : null;
}

function thresholdEcdsaSharedIdentityGuard(
  record: ThresholdEcdsaStoredKeyRecord,
): ThresholdEcdsaSharedIdentityGuard {
  return {
    contextKey: [
      'evm-family',
      record.walletId,
      record.rpId,
      record.signingRootId,
      ecdsaSigningRootVersion(record),
    ]
      .map(ecdsaIdentityPart)
      .join('|'),
    identityValue: [
      record.ecdsaThresholdKeyId,
      String(record.ethereumAddress || '')
        .trim()
        .toLowerCase(),
      record.relayerKeyId,
    ]
      .map(ecdsaIdentityPart)
      .join('|'),
  };
}

function thresholdEcdsaSharedIdentityIndexKey(
  keyPrefix: string,
  guard: ThresholdEcdsaSharedIdentityGuard,
): string {
  return `${keyPrefix}shared-identity:${guard.contextKey}`;
}

function thresholdEcdsaKeyHandleIndexKey(keyPrefix: string, keyHandle: string): string {
  return `${keyPrefix}key-handle:${ecdsaIdentityPart(keyHandle)}`;
}

function isDurableObjectNamespaceLike(v: unknown): v is CloudflareDurableObjectNamespaceLike {
  return (
    Boolean(v) &&
    typeof v === 'object' &&
    !Array.isArray(v) &&
    typeof (v as CloudflareDurableObjectNamespaceLike).idFromName === 'function' &&
    typeof (v as CloudflareDurableObjectNamespaceLike).get === 'function'
  );
}

function resolveDoNamespaceFromConfig(
  config: Record<string, unknown>,
): CloudflareDurableObjectNamespaceLike | null {
  const direct = (config as { namespace?: unknown }).namespace;
  if (isDurableObjectNamespaceLike(direct)) return direct;

  const alt = (config as { durableObjectNamespace?: unknown }).durableObjectNamespace;
  if (isDurableObjectNamespaceLike(alt)) return alt;

  const envStyle = (config as { THRESHOLD_DO_NAMESPACE?: unknown }).THRESHOLD_DO_NAMESPACE;
  if (isDurableObjectNamespaceLike(envStyle)) return envStyle;

  return null;
}

function resolveDoStub(input: {
  namespace: CloudflareDurableObjectNamespaceLike;
  objectName: string;
}): DurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id) as unknown as DurableObjectStubLike;
}

async function callDo<T>(stub: DurableObjectStubLike, req: DoRequest): Promise<DoResp<T>> {
  const resp = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(req),
  });
  const text = await resp.text();
  if (!resp.ok) {
    throw new Error(`Threshold DO store HTTP ${resp.status}: ${text}`);
  }
  let json: unknown;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`Threshold DO store returned non-JSON response: ${text.slice(0, 200)}`);
  }
  if (!isObject(json)) {
    throw new Error('Threshold DO store returned invalid JSON shape');
  }
  const ok = (json as { ok?: unknown }).ok;
  if (ok === true) return json as DoOk<T>;
  const code = toOptionalTrimmedString((json as { code?: unknown }).code);
  const message = toOptionalTrimmedString((json as { message?: unknown }).message);
  return { ok: false, code: code || 'internal', message: message || 'Threshold DO store error' };
}

function computeAuthPrefix(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ED25519_AUTH_PREFIX);
  return toThresholdEd25519AuthPrefix(
    explicit || toThresholdEd25519PrefixFromBase(basePrefix, 'auth'),
  );
}

function computeSessionPrefix(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ED25519_SESSION_PREFIX);
  return toThresholdEd25519SessionPrefix(
    explicit || toThresholdEd25519PrefixFromBase(basePrefix, 'sess'),
  );
}

function computeKeyPrefix(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ED25519_KEYSTORE_PREFIX);
  return toThresholdEd25519KeyPrefix(
    explicit || toThresholdEd25519PrefixFromBase(basePrefix, 'key'),
  );
}

function computeAuthPrefixEcdsa(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ECDSA_AUTH_PREFIX);
  return toThresholdEcdsaAuthPrefix(explicit || toThresholdEcdsaPrefixFromBase(basePrefix, 'auth'));
}

function computeSessionPrefixEcdsa(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ECDSA_SESSION_PREFIX);
  return toThresholdEcdsaSessionPrefix(
    explicit || toThresholdEcdsaPrefixFromBase(basePrefix, 'sess'),
  );
}

function computeKeyPrefixEcdsa(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ECDSA_KEYSTORE_PREFIX);
  return toThresholdEcdsaKeyPrefix(explicit || toThresholdEcdsaPrefixFromBase(basePrefix, 'key'));
}

function computePresignPrefixEcdsa(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ECDSA_PRESIGN_PREFIX);
  return toThresholdEcdsaPresignPrefix(
    explicit || toThresholdEcdsaPrefixFromBase(basePrefix, 'presign'),
  );
}

function computeSigningPrefixEcdsa(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ECDSA_SIGNING_PREFIX);
  return toThresholdEcdsaSigningPrefix(
    explicit || toThresholdEcdsaPrefixFromBase(basePrefix, 'signing'),
  );
}

export class CloudflareDurableObjectEd25519AuthSessionStore implements Ed25519AuthSessionStore {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private replayGuardKey(scopeId: string, replayKey: string): string {
    return `${this.keyPrefix}replay:${toOptionalTrimmedString(scopeId) || 'missing'}:${toOptionalTrimmedString(replayKey) || 'missing'}`;
  }

  async putSession(
    id: string,
    record: Ed25519AuthSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    const expiresAtMs = Date.now() + ttlMs;
    const entry: DoAuthEntry = {
      record,
      remainingUses: Math.max(0, Number(opts.remainingUses) || 0),
      expiresAtMs,
    };
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key(id),
      value: entry,
      ttlMs,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async getSession(id: string): Promise<Ed25519AuthSessionRecord | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(id) });
    if (!resp.ok) return null;
    const raw = resp.value;
    const entry = isObject(raw) ? (raw as Record<string, unknown>) : null;
    const record = entry
      ? parseEd25519AuthSessionRecord((entry as { record?: unknown }).record)
      : null;
    const expiresAtMs = entry ? (entry as { expiresAtMs?: unknown }).expiresAtMs : null;
    if (!record || typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs)) return null;
    if (Date.now() > expiresAtMs) return null;
    return record;
  }

  async getSessionStatus(id: string) {
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(id) });
    if (!resp.ok) return null;
    const raw = resp.value;
    const entry = isObject(raw) ? (raw as Record<string, unknown>) : null;
    const record = entry
      ? parseEd25519AuthSessionRecord((entry as { record?: unknown }).record)
      : null;
    const expiresAtMs = entry ? Number((entry as { expiresAtMs?: unknown }).expiresAtMs) : NaN;
    const remainingUses = entry
      ? Number((entry as { remainingUses?: unknown }).remainingUses)
      : NaN;
    if (!record || !Number.isFinite(expiresAtMs) || !Number.isFinite(remainingUses)) return null;
    if (Date.now() > expiresAtMs) return null;
    return {
      record,
      expiresAtMs,
      remainingUses,
    };
  }

  async consumeUseCount(id: string): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    const resp = await callDo<{ remainingUses: number }>(this.stub, {
      op: 'authConsumeUseCount',
      key: this.key(id),
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return { ok: true, remainingUses: resp.value.remainingUses };
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<ThresholdEd25519AuthConsumeUsesResult> {
    const resp = await callDo<{ remainingUses: number }>(this.stub, {
      op: 'authConsumeUseCountOnce',
      key: this.key(id),
      idempotencyKey,
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return { ok: true, remainingUses: resp.value.remainingUses };
  }

  async hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<{ ok: true; consumed: boolean } | { ok: false; code: string; message: string }> {
    const resp = await callDo<{ consumed: boolean }>(this.stub, {
      op: 'authHasConsumedUseCountOnce',
      key: this.key(id),
      idempotencyKey,
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return { ok: true, consumed: resp.value.consumed };
  }

  async reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<ThresholdAuthReplayGuardResult> {
    const resp = await callDo<{ reserved: true }>(this.stub, {
      op: 'authReserveReplayGuard',
      key: this.replayGuardKey(scopeId, replayKey),
      expiresAtMs,
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return { ok: true };
  }
}

export class CloudflareDurableObjectThresholdEd25519SessionStore implements ThresholdEd25519SessionStore {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;
  private readonly presignPrefix: string;
  private readonly presignRateLimitPrefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
    this.presignPrefix = `${this.keyPrefix}presign:`;
    this.presignRateLimitPrefix = `${this.keyPrefix}presign-rate:`;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private coordKey(id: string): string {
    return `${this.coordinatorPrefix}${id}`;
  }

  private presignKey(id: string): string {
    return `${this.presignPrefix}${id}`;
  }

  private presignGlobalIndexKey(): string {
    return `${this.presignPrefix}idx:global`;
  }

  private presignWalletIndexKey(walletSigningSessionId: string): string {
    return `${this.presignPrefix}idx:wallet:${encodeURIComponent(walletSigningSessionId)}`;
  }

  private presignRateLimitKey(
    bucket: ThresholdEd25519PresignRefillRateLimitBucket,
    policy: ThresholdEd25519PresignRefillRateLimitPolicy,
  ): string {
    const key = toOptionalTrimmedString(bucket.key);
    if (!key) throw new Error('presign refill rate limit bucket key is required');
    const windowMs = Math.floor(Number(policy.windowMs));
    if (!Number.isSafeInteger(windowMs) || windowMs < 1) {
      throw new Error('windowMs must be a positive integer');
    }
    const windowStartMs = Math.floor(Date.now() / windowMs) * windowMs;
    return `${this.presignRateLimitPrefix}${bucket.kind}:${encodeURIComponent(key)}:${windowStartMs}`;
  }

  async putMpcSession(
    id: string,
    record: ThresholdEd25519MpcSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key(id),
      value: record,
      ttlMs,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async readMpcSession(id: string): Promise<ThresholdEd25519ReadMpcSessionResult | null> {
    const resp = await callDo<{ value?: unknown; version?: unknown } | null>(this.stub, {
      op: 'readVersioned',
      key: this.key(id),
    });
    if (!resp.ok || !resp.value) return null;
    const record = parseThresholdEd25519MpcSessionRecord(resp.value.value);
    const version = toOptionalTrimmedString(resp.value.version);
    return record && version ? { record, version } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdEd25519ClaimMpcSessionResult> {
    const expectedVersion = toOptionalTrimmedString(version);
    if (!expectedVersion) return { ok: false, code: 'version_mismatch' };
    const resp = await callDo<{ status?: unknown; value?: unknown }>(this.stub, {
      op: 'claimVersioned',
      key: this.key(id),
      expectedVersion,
    });
    if (!resp.ok) return { ok: false, code: 'not_found' };
    const status = toOptionalTrimmedString(resp.value?.status);
    if (status === 'not_found') return { ok: false, code: 'not_found' };
    if (status === 'expired') return { ok: false, code: 'expired' };
    if (status === 'version_mismatch') return { ok: false, code: 'version_mismatch' };
    const record = parseThresholdEd25519MpcSessionRecord(resp.value?.value);
    return record ? { ok: true, record } : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<ThresholdEd25519MpcSessionRecord | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'getdel', key: this.key(id) });
    if (!resp.ok) return null;
    return parseThresholdEd25519MpcSessionRecord(resp.value);
  }

  async putSigningSession(
    id: string,
    record: ThresholdEd25519SigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key(id),
      value: record,
      ttlMs,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async takeSigningSession(id: string): Promise<ThresholdEd25519SigningSessionRecord | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'getdel', key: this.key(id) });
    if (!resp.ok) return null;
    return parseThresholdEd25519SigningSessionRecord(resp.value);
  }

  async putCoordinatorSigningSession(
    id: string,
    record: ThresholdEd25519CoordinatorSigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.coordKey(id),
      value: record,
      ttlMs,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async takeCoordinatorSigningSession(
    id: string,
  ): Promise<ThresholdEd25519CoordinatorSigningSessionRecord | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'getdel', key: this.coordKey(id) });
    if (!resp.ok) return null;
    return parseThresholdEd25519CoordinatorSigningSessionRecord(resp.value);
  }

  async putPresign(
    id: string,
    record: ThresholdEd25519PresignRecord,
    ttlMs: number,
  ): Promise<void> {
    const parsed = parseThresholdEd25519PresignRecord(record);
    if (!parsed) throw new Error('Invalid threshold ed25519 presign record');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.presignKey(id),
      value: { ...parsed, expiresAtMs },
      ttlMs,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async putPresignWithCapacity(
    id: string,
    record: ThresholdEd25519PresignRecord,
    ttlMs: number,
    capacity: ThresholdEd25519PresignCapacity,
  ): Promise<ThresholdEd25519PutPresignWithCapacityResult> {
    const parsed = parseThresholdEd25519PresignRecord(record);
    if (!parsed) throw new Error('Invalid threshold ed25519 presign record');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const value = { ...parsed, expiresAtMs };
    const resp = await callDo<ThresholdEd25519PutPresignWithCapacityResult>(this.stub, {
      op: 'ed25519PresignPutWithCapacity',
      key: this.presignKey(id),
      presignId: id,
      value,
      ttlMs,
      capacity,
      walletIndexKey: this.presignWalletIndexKey(parsed.walletSigningSessionId),
      globalIndexKey: this.presignGlobalIndexKey(),
    });
    if (!resp.ok) return { ok: false, code: 'capacity_exceeded' };
    return resp.value;
  }

  async checkPresignCapacity(
    walletSigningSessionId: string,
    capacity: ThresholdEd25519PresignCapacity,
  ): Promise<ThresholdEd25519CheckPresignCapacityResult> {
    const walletId = toOptionalTrimmedString(walletSigningSessionId);
    if (!walletId) return { ok: false, code: 'capacity_exceeded' };
    const resp = await callDo<ThresholdEd25519CheckPresignCapacityResult>(this.stub, {
      op: 'ed25519PresignCheckCapacity',
      capacity,
      walletIndexKey: this.presignWalletIndexKey(walletId),
      globalIndexKey: this.presignGlobalIndexKey(),
    });
    if (!resp.ok) return { ok: false, code: 'capacity_exceeded' };
    return resp.value;
  }

  async consumePresignRefillRateLimit(
    bucket: ThresholdEd25519PresignRefillRateLimitBucket,
    policy: ThresholdEd25519PresignRefillRateLimitPolicy,
    cost: number,
  ): Promise<ThresholdEd25519ConsumePresignRefillRateLimitResult> {
    const resp = await callDo<ThresholdEd25519ConsumePresignRefillRateLimitResult>(this.stub, {
      op: 'ed25519PresignConsumeRateLimit',
      key: this.presignRateLimitKey(bucket, policy),
      cost,
      policy,
    });
    if (!resp.ok) return { ok: false, code: 'rate_limited' };
    return resp.value;
  }

  async takePresignForFinalize(
    id: string,
    expectedScope: ThresholdEd25519PresignExpectedScope,
  ): Promise<ThresholdEd25519TakePresignForFinalizeResult> {
    const resp = await callDo<ThresholdEd25519TakePresignForFinalizeResult>(this.stub, {
      op: 'ed25519PresignTake',
      key: this.presignKey(id),
      presignId: id,
      expectedScope,
      walletIndexKey: this.presignWalletIndexKey(expectedScope.walletSigningSessionId),
      globalIndexKey: this.presignGlobalIndexKey(),
    });
    if (!resp.ok) return { ok: false, code: 'not_found' };
    return resp.value;
  }
}

export class CloudflareDurableObjectThresholdEd25519KeyStore implements ThresholdEd25519KeyStore {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
  }

  private key(relayerKeyId: string): string {
    return `${this.keyPrefix}${relayerKeyId}`;
  }

  async get(relayerKeyId: string): Promise<ThresholdEd25519KeyRecord | null> {
    const id = toOptionalTrimmedString(relayerKeyId);
    if (!id) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(id) });
    if (!resp.ok) return null;
    return parseThresholdEd25519KeyRecord(resp.value);
  }

  async put(relayerKeyId: string, record: ThresholdEd25519KeyRecord): Promise<void> {
    const id = toOptionalTrimmedString(relayerKeyId);
    if (!id) throw new Error('Missing relayerKeyId');
    const resp = await callDo<void>(this.stub, { op: 'set', key: this.key(id), value: record });
    if (!resp.ok) throw new Error(resp.message);
  }

  async del(relayerKeyId: string): Promise<void> {
    const id = toOptionalTrimmedString(relayerKeyId);
    if (!id) return;
    const resp = await callDo<void>(this.stub, { op: 'del', key: this.key(id) });
    if (!resp.ok) throw new Error(resp.message);
  }
}

export class CloudflareDurableObjectThresholdEcdsaIntegratedKeyStore implements ThresholdEcdsaIntegratedKeyStore {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
  }

  private recordKey(keyHandle: string): string {
    return `${this.keyPrefix}${keyHandle}`;
  }

  async getRoleLocalByKeyHandle(keyHandle: string): Promise<EcdsaHssRoleLocalKeyRecord | null> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return null;
    const directResp = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.recordKey(handle),
    });
    if (directResp.ok) {
      const direct = await parseStoredEcdsaHssRoleLocalKeyRecord(directResp.value);
      if (direct) {
        if (direct.keyHandle !== handle) {
          throw new Error(
            '[threshold-ecdsa] ECDSA key handle does not match threshold key identity',
          );
        }
        return direct;
      }
    }
    const indexResp = await callDo<string | null>(this.stub, {
      op: 'get',
      key: thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, handle),
    });
    if (!indexResp.ok) return null;
    const recordKey = toOptionalTrimmedString(indexResp.value);
    if (!recordKey) return null;
    const recordResp = await callDo<unknown | null>(this.stub, { op: 'get', key: recordKey });
    if (!recordResp.ok) return null;
    return await parseStoredEcdsaHssRoleLocalKeyRecord(recordResp.value);
  }

  async putRoleLocalByKeyHandle(record: EcdsaHssRoleLocalKeyRecord): Promise<void> {
    const parsed = await withEcdsaHssRoleLocalRecordKeyHandle(record);
    const guard = thresholdEcdsaSharedIdentityGuard(parsed);
    const recordKey = this.recordKey(parsed.keyHandle);
    const resp = await callDo<void>(this.stub, {
      op: 'setWithIdentityGuard',
      key: recordKey,
      identityKey: thresholdEcdsaSharedIdentityIndexKey(this.keyPrefix, guard),
      identityValue: guard.identityValue,
      keyHandleKey: thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, parsed.keyHandle),
      keyHandleValue: recordKey,
      value: parsed,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async deleteByKeyHandle(keyHandle: string): Promise<void> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return;
    const keyHandleKey = thresholdEcdsaKeyHandleIndexKey(this.keyPrefix, handle);
    const canonicalRecordKey = this.recordKey(handle);
    const canonicalRecordResp = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: canonicalRecordKey,
    });
    const canonicalRecord = canonicalRecordResp.ok
      ? await parseStoredEcdsaHssRoleLocalKeyRecord(canonicalRecordResp.value)
      : null;
    const indexResp = canonicalRecord
      ? null
      : await callDo<string | null>(this.stub, { op: 'get', key: keyHandleKey });
    const recordKey = canonicalRecord
      ? canonicalRecordKey
      : toOptionalTrimmedString(indexResp?.ok ? indexResp.value : null);
    if (!recordKey) {
      const resp = await callDo<void>(this.stub, { op: 'del', key: canonicalRecordKey });
      if (!resp.ok) throw new Error(resp.message);
      return;
    }
    const recordResp = canonicalRecord
      ? null
      : await callDo<unknown | null>(this.stub, { op: 'get', key: recordKey });
    if (recordResp && !recordResp.ok) return;
    const record =
      canonicalRecord ||
      (await parseStoredEcdsaHssRoleLocalKeyRecord(recordResp ? recordResp.value : null));
    if (!record) {
      const resp = await callDo<void>(this.stub, { op: 'del', key: keyHandleKey });
      if (!resp.ok) throw new Error(resp.message);
      const canonicalDel = await callDo<void>(this.stub, { op: 'del', key: canonicalRecordKey });
      if (!canonicalDel.ok) throw new Error(canonicalDel.message);
      return;
    }
    const guard = thresholdEcdsaSharedIdentityGuard(record);
    const resp = await callDo<void>(this.stub, {
      op: 'delWithIdentityGuard',
      key: recordKey,
      identityKey: thresholdEcdsaSharedIdentityIndexKey(this.keyPrefix, guard),
      identityValue: guard.identityValue,
      keyHandleKey,
      keyHandleValue: recordKey,
    });
    if (!resp.ok) throw new Error(resp.message);
  }
}

export class CloudflareDurableObjectThresholdEcdsaSigningSessionStore implements ThresholdEcdsaSigningSessionStore {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async putSigningSession(
    id: string,
    record: ThresholdEcdsaSigningSessionRecord,
    ttlMs: number,
  ): Promise<void> {
    const ttl = Math.max(0, Number(ttlMs) || 0);
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key(id),
      value: record,
      ttlMs: ttl,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async takeSigningSession(id: string): Promise<ThresholdEcdsaSigningSessionRecord | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'getdel', key: this.key(id) });
    if (!resp.ok) return null;
    return parseThresholdEcdsaSigningSessionRecord(
      resp.value,
    ) as ThresholdEcdsaSigningSessionRecord | null;
  }
}

export class CloudflareDurableObjectThresholdEcdsaPresignSessionStore implements ThresholdEcdsaPresignSessionStore {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  async createSession(
    id: string,
    record: ThresholdEcdsaPresignSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseThresholdEcdsaPresignSessionRecord(record);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');
    const resp = await callDo<{ status?: unknown }>(this.stub, {
      op: 'ecdsaPresignSessionCreate',
      key: this.key(key),
      value: parsed,
      ttlMs: Math.max(0, Number(ttlMs) || 0),
    });
    if (!resp.ok) throw new Error(resp.message);
    const status = toOptionalTrimmedString(resp.value?.status);
    if (status === 'ok') return { ok: true };
    if (status === 'exists') return { ok: false, code: 'exists' };
    throw new Error(
      `[threshold-ecdsa] Durable Object presign session create returned unexpected status: ${String(status || 'null')}`,
    );
  }

  async getSession(id: string): Promise<ThresholdEcdsaPresignSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(key) });
    if (!resp.ok) return null;
    const parsed = parseThresholdEcdsaPresignSessionRecord(
      resp.value,
    ) as ThresholdEcdsaPresignSessionRecord | null;
    if (!parsed) return null;
    if (Date.now() > parsed.expiresAtMs) {
      await this.deleteSession(key);
      return null;
    }
    return parsed;
  }

  async advanceSessionCas(input: {
    id: string;
    expectedVersion: number;
    nextRecord: ThresholdEcdsaPresignSessionRecord;
    ttlMs: number;
  }): Promise<ThresholdEcdsaPresignSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1)
      return { ok: false, code: 'version_mismatch' };
    const parsed = parseThresholdEcdsaPresignSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid threshold-ecdsa presign session record');
    const resp = await callDo<{ status?: unknown; record?: unknown }>(this.stub, {
      op: 'ecdsaPresignSessionAdvanceCas',
      key: this.key(key),
      expectedVersion,
      value: parsed,
      ttlMs: Math.max(0, Number(input.ttlMs) || 0),
    });
    if (!resp.ok) throw new Error(resp.message);
    const status = toOptionalTrimmedString(resp.value?.status);
    if (status === 'not_found') return { ok: false, code: 'not_found' };
    if (status === 'expired') return { ok: false, code: 'expired' };
    if (status === 'version_mismatch') return { ok: false, code: 'version_mismatch' };
    if (status !== 'ok') {
      throw new Error(
        `[threshold-ecdsa] Durable Object presign session CAS returned unexpected status: ${String(status || 'null')}`,
      );
    }
    const record = parseThresholdEcdsaPresignSessionRecord(
      resp.value?.record,
    ) as ThresholdEcdsaPresignSessionRecord | null;
    if (!record)
      throw new Error(
        '[threshold-ecdsa] Durable Object presign session CAS returned invalid record',
      );
    return { ok: true, record };
  }

  async deleteSession(id: string): Promise<void> {
    const key = toOptionalTrimmedString(id);
    if (!key) return;
    const resp = await callDo<void>(this.stub, { op: 'del', key: this.key(key) });
    if (!resp.ok) throw new Error(resp.message);
  }
}

export class CloudflareDurableObjectThresholdEcdsaPresignaturePool implements ThresholdEcdsaPresignaturePool {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;
  private readonly reservationTtlMs: number;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
    reservationTtlMs?: number;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
    this.reservationTtlMs = Math.max(1, Math.floor(Number(input.reservationTtlMs) || 120_000));
  }

  private listKey(relayerKeyId: string): string {
    return `${this.keyPrefix}avail:${relayerKeyId}`;
  }

  private reservedKeyPrefix(relayerKeyId: string): string {
    return `${this.keyPrefix}res:${relayerKeyId}:`;
  }

  private reservedKey(relayerKeyId: string, presignatureId: string): string {
    return `${this.reservedKeyPrefix(relayerKeyId)}${presignatureId}`;
  }

  async put(record: ThresholdEcdsaPresignatureRelayerShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    if (!relayerKeyId) throw new Error('Missing relayerKeyId');
    const resp = await callDo<void>(this.stub, {
      op: 'ecdsaPresignPut',
      listKey: this.listKey(relayerKeyId),
      value: record,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async reserve(
    relayerKeyId: string,
  ): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    const resp = await callDo<unknown | null>(this.stub, {
      op: 'ecdsaPresignReserve',
      listKey: this.listKey(key),
      reservedKeyPrefix: this.reservedKeyPrefix(key),
      ttlMs: this.reservationTtlMs,
    });
    if (!resp.ok) return null;
    return parseThresholdEcdsaPresignatureRelayerShareRecord(
      resp.value,
    ) as ThresholdEcdsaPresignatureRelayerShareRecord | null;
  }

  async reserveById(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const resp = await callDo<unknown | null>(this.stub, {
      op: 'ecdsaPresignReserveById',
      listKey: this.listKey(key),
      reservedKeyPrefix: this.reservedKeyPrefix(key),
      presignatureId: id,
      ttlMs: this.reservationTtlMs,
    });
    if (!resp.ok) return null;
    return parseThresholdEcdsaPresignatureRelayerShareRecord(
      resp.value,
    ) as ThresholdEcdsaPresignatureRelayerShareRecord | null;
  }

  async consume(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<ThresholdEcdsaPresignatureRelayerShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const resp = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.reservedKey(key, id),
    });
    if (!resp.ok) return null;
    return parseThresholdEcdsaPresignatureRelayerShareRecord(
      resp.value,
    ) as ThresholdEcdsaPresignatureRelayerShareRecord | null;
  }

  async discard(relayerKeyId: string, presignatureId: string): Promise<void> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return;
    const resp = await callDo<void>(this.stub, { op: 'del', key: this.reservedKey(key, id) });
    if (!resp.ok) throw new Error(resp.message);
  }
}

export function createCloudflareDurableObjectThresholdEd25519Stores(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
}): {
  keyStore: ThresholdEd25519KeyStore;
  sessionStore: ThresholdEd25519SessionStore;
  authSessionStore: Ed25519AuthSessionStore;
} | null {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const kind = toOptionalTrimmedString(config.kind);
  if (kind !== 'cloudflare-do') return null;

  const namespace = resolveDoNamespaceFromConfig(config);
  if (!namespace) {
    throw new Error(
      'cloudflare-do threshold store selected but no Durable Object namespace was provided (expected config.namespace)',
    );
  }

  const objectName =
    toOptionalTrimmedString((config as { objectName?: unknown }).objectName) ||
    toOptionalTrimmedString((config as { name?: unknown }).name) ||
    THRESHOLD_DO_OBJECT_NAME_DEFAULT;

  const authPrefix = computeAuthPrefix(config);
  const sessionPrefix = computeSessionPrefix(config);
  const keyPrefix = computeKeyPrefix(config);

  input.logger.info(
    '[threshold-ed25519] Using Cloudflare Durable Object store for threshold session persistence',
  );

  return {
    keyStore: new CloudflareDurableObjectThresholdEd25519KeyStore({
      namespace,
      objectName,
      keyPrefix,
    }),
    sessionStore: new CloudflareDurableObjectThresholdEd25519SessionStore({
      namespace,
      objectName,
      keyPrefix: sessionPrefix,
    }),
    authSessionStore: new CloudflareDurableObjectEd25519AuthSessionStore({
      namespace,
      objectName,
      keyPrefix: authPrefix,
    }),
  };
}

export function createCloudflareDurableObjectThresholdEcdsaStores(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
}): {
  keyStore: ThresholdEcdsaIntegratedKeyStore;
  sessionStore: ThresholdEd25519SessionStore;
  authSessionStore: Ed25519AuthSessionStore;
  signingSessionStore: ThresholdEcdsaSigningSessionStore;
  presignSessionStore: ThresholdEcdsaPresignSessionStore;
  presignaturePool: ThresholdEcdsaPresignaturePool;
} | null {
  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const kind = toOptionalTrimmedString(config.kind);
  if (kind !== 'cloudflare-do') return null;

  const namespace = resolveDoNamespaceFromConfig(config);
  if (!namespace) {
    throw new Error(
      'cloudflare-do threshold store selected but no Durable Object namespace was provided (expected config.namespace)',
    );
  }

  const objectName =
    toOptionalTrimmedString((config as { objectName?: unknown }).objectName) ||
    toOptionalTrimmedString((config as { name?: unknown }).name) ||
    'threshold-ecdsa-store';

  const authPrefix = computeAuthPrefixEcdsa(config);
  const sessionPrefix = computeSessionPrefixEcdsa(config);
  const keyPrefix = computeKeyPrefixEcdsa(config);
  const signingPrefix = computeSigningPrefixEcdsa(config);
  const presignPrefix = computePresignPrefixEcdsa(config);

  input.logger.info(
    '[threshold-ecdsa] Using Cloudflare Durable Object store for threshold session persistence',
  );

  return {
    keyStore: new CloudflareDurableObjectThresholdEcdsaIntegratedKeyStore({
      namespace,
      objectName,
      keyPrefix,
    }),
    sessionStore: new CloudflareDurableObjectThresholdEd25519SessionStore({
      namespace,
      objectName,
      keyPrefix: sessionPrefix,
    }),
    authSessionStore: new CloudflareDurableObjectEd25519AuthSessionStore({
      namespace,
      objectName,
      keyPrefix: authPrefix,
    }),
    signingSessionStore: new CloudflareDurableObjectThresholdEcdsaSigningSessionStore({
      namespace,
      objectName,
      keyPrefix: signingPrefix,
    }),
    presignSessionStore: new CloudflareDurableObjectThresholdEcdsaPresignSessionStore({
      namespace,
      objectName,
      keyPrefix: presignPrefix,
    }),
    presignaturePool: new CloudflareDurableObjectThresholdEcdsaPresignaturePool({
      namespace,
      objectName,
      keyPrefix: presignPrefix,
    }),
  };
}
