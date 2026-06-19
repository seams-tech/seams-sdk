import type { NormalizedLogger } from '../../logger';
import type { CloudflareDurableObjectNamespaceLike, ThresholdStoreConfigInput } from '../../types';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from '../../defaultConfigsServer';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  parseEcdsaHssRoleLocalKeyRecord,
  isObject,
  parseRouterAbEcdsaHssPoolFillSessionRecord,
  parseRouterAbEcdsaHssServerPresignatureShareRecord,
  parseEd25519WalletSessionRecord,
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseThresholdEd25519KeyRecord,
  parseThresholdEd25519MpcSessionRecord,
  parseRouterAbEd25519PresignRecord,
  parseThresholdEd25519SigningSessionRecord,
  toThresholdEcdsaWalletSessionPrefix,
  toThresholdEcdsaKeyPrefix,
  toThresholdEcdsaPresignPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEcdsaSessionPrefix,
  toThresholdEd25519WalletSessionPrefix,
  toThresholdEd25519KeyPrefix,
  toThresholdEd25519PrefixFromBase,
  toThresholdEd25519SessionPrefix,
} from '../validation';
import type {
  WalletSessionReplayGuardResult,
  WalletSessionConsumeUsesResult,
  WalletSessionBudgetCommitReservedUseCountInput,
  WalletSessionBudgetReleaseReservedUseCountInput,
  WalletSessionBudgetReleaseResult,
  WalletSessionBudgetReservationResult,
  WalletSessionBudgetReserveUseCountInput,
  WalletSigningBudgetReservation,
  Ed25519WalletSessionRecord,
  Ed25519WalletSessionStore,
} from './WalletSessionStore';
import type {
  ThresholdEcdsaIntegratedKeyStore,
  ThresholdEd25519KeyRecord,
  ThresholdEd25519KeyStore,
} from './KeyStore';
import type { EcdsaHssRoleLocalKeyRecord } from '../../types';
import type {
  ThresholdEd25519CoordinatorSigningSessionRecord,
  RouterAbEd25519ConsumePresignRefillRateLimitResult,
  ThresholdEd25519MpcSessionRecord,
  RouterAbEd25519PresignCapacity,
  RouterAbEd25519CheckPresignCapacityResult,
  RouterAbEd25519PresignExpectedScope,
  RouterAbEd25519PresignRefillRateLimitBucket,
  RouterAbEd25519PresignRefillRateLimitPolicy,
  RouterAbEd25519PutPresignWithCapacityResult,
  RouterAbEd25519PresignRecord,
  ThresholdEd25519ClaimMpcSessionResult,
  ThresholdEd25519ReadMpcSessionResult,
  ThresholdEd25519SessionStore,
  ThresholdEd25519SigningSessionRecord,
  RouterAbEd25519TakePresignForFinalizeResult,
} from './SessionStore';
import type {
  RouterAbEcdsaHssPoolFillSessionCasResult,
  RouterAbEcdsaHssPoolFillSessionRecord,
  RouterAbEcdsaHssPoolFillSessionStore,
  RouterAbEcdsaHssPresignaturePool,
  RouterAbEcdsaHssServerPresignatureShareRecord,
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
type DoAuthGetBudgetStatusRequest = {
  op: 'authGetBudgetStatus';
  key: string;
};
type DoAuthReserveBudgetUseCountRequest = {
  op: 'authReserveBudgetUseCount';
  key: string;
  input: WalletSessionBudgetReserveUseCountInput;
};
type DoAuthCommitReservedBudgetUseCountRequest = {
  op: 'authCommitReservedBudgetUseCount';
  key: string;
  input: WalletSessionBudgetCommitReservedUseCountInput;
};
type DoAuthReleaseReservedBudgetUseCountRequest = {
  op: 'authReleaseReservedBudgetUseCount';
  key: string;
  input: WalletSessionBudgetReleaseReservedUseCountInput;
};
type DoAuthReserveReplayGuardRequest = {
  op: 'authReserveReplayGuard';
  key: string;
  expiresAtMs: number;
};
type DoRouterAbEcdsaHssPresignaturePutRequest = { op: 'routerAbEcdsaHssPresignaturePut'; listKey: string; value: unknown };
type DoRouterAbEcdsaHssPresignatureReserveRequest = {
  op: 'routerAbEcdsaHssPresignatureReserve';
  listKey: string;
  reservedKeyPrefix: string;
  ttlMs?: number;
};
type DoRouterAbEcdsaHssPresignatureReserveByIdRequest = {
  op: 'routerAbEcdsaHssPresignatureReserveById';
  listKey: string;
  reservedKeyPrefix: string;
  presignatureId: string;
  ttlMs?: number;
};
type DoRouterAbEcdsaHssPoolFillSessionCreateRequest = {
  op: 'routerAbEcdsaHssPoolFillSessionCreate';
  key: string;
  value: unknown;
  ttlMs?: number;
};
type DoRouterAbEcdsaHssPoolFillSessionAdvanceCasRequest = {
  op: 'routerAbEcdsaHssPoolFillSessionAdvanceCas';
  key: string;
  expectedVersion: number;
  value: unknown;
  ttlMs?: number;
};
type DoEd25519PresignTakeRequest = {
  op: 'ed25519PresignTake';
  key: string;
  presignId: string;
  expectedScope: RouterAbEd25519PresignExpectedScope;
  walletIndexKey: string;
  globalIndexKey: string;
};
type DoEd25519PresignPutWithCapacityRequest = {
  op: 'ed25519PresignPutWithCapacity';
  key: string;
  presignId: string;
  value: RouterAbEd25519PresignRecord;
  ttlMs: number;
  capacity: RouterAbEd25519PresignCapacity;
  walletIndexKey: string;
  globalIndexKey: string;
};
type DoEd25519PresignCheckCapacityRequest = {
  op: 'ed25519PresignCheckCapacity';
  capacity: RouterAbEd25519PresignCapacity;
  walletIndexKey: string;
  globalIndexKey: string;
};
type DoEd25519PresignConsumeRateLimitRequest = {
  op: 'ed25519PresignConsumeRateLimit';
  key: string;
  cost: number;
  policy: RouterAbEd25519PresignRefillRateLimitPolicy;
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
  | DoAuthGetBudgetStatusRequest
  | DoAuthReserveBudgetUseCountRequest
  | DoAuthCommitReservedBudgetUseCountRequest
  | DoAuthReleaseReservedBudgetUseCountRequest
  | DoAuthReserveReplayGuardRequest
  | DoRouterAbEcdsaHssPresignaturePutRequest
  | DoRouterAbEcdsaHssPresignatureReserveRequest
  | DoRouterAbEcdsaHssPresignatureReserveByIdRequest
  | DoRouterAbEcdsaHssPoolFillSessionCreateRequest
  | DoRouterAbEcdsaHssPoolFillSessionAdvanceCasRequest
  | DoEd25519PresignCheckCapacityRequest
  | DoEd25519PresignConsumeRateLimitRequest
  | DoEd25519PresignPutWithCapacityRequest
  | DoEd25519PresignTakeRequest;

type DoAuthEntry = {
  record: Ed25519WalletSessionRecord;
  remainingUses: number;
  expiresAtMs: number;
  reservedUses?: number;
  availableUses?: number;
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

function computeWalletSessionPrefix(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ED25519_WALLET_SESSION_PREFIX);
  return toThresholdEd25519WalletSessionPrefix(
    explicit || toThresholdEd25519PrefixFromBase(basePrefix, 'wallet-session'),
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

function computeWalletSessionPrefixEcdsa(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ECDSA_WALLET_SESSION_PREFIX);
  return toThresholdEcdsaWalletSessionPrefix(
    explicit || toThresholdEcdsaPrefixFromBase(basePrefix, 'wallet-session'),
  );
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

export class CloudflareDurableObjectEd25519WalletSessionStore implements Ed25519WalletSessionStore {
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
    record: Ed25519WalletSessionRecord,
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

  async getSession(id: string): Promise<Ed25519WalletSessionRecord | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(id) });
    if (!resp.ok) return null;
    const raw = resp.value;
    const entry = isObject(raw) ? (raw as Record<string, unknown>) : null;
    const record = entry
      ? parseEd25519WalletSessionRecord((entry as { record?: unknown }).record)
      : null;
    const expiresAtMs = entry ? (entry as { expiresAtMs?: unknown }).expiresAtMs : null;
    if (!record || typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs)) return null;
    if (Date.now() > expiresAtMs) return null;
    return record;
  }

  async getSessionStatus(id: string) {
    const resp = await callDo<{
      record: Ed25519WalletSessionRecord;
      expiresAtMs: number;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    } | null>(this.stub, { op: 'authGetBudgetStatus', key: this.key(id) });
    if (!resp.ok) return null;
    if (!resp.value) return null;
    const record = parseEd25519WalletSessionRecord(resp.value.record);
    if (!record) return null;
    const expiresAtMs = Number(resp.value.expiresAtMs);
    const committedRemainingUses = Math.max(0, Math.floor(Number(resp.value.remainingUses) || 0));
    const activeReservedUses = Math.max(0, Math.floor(Number(resp.value.reservedUses) || 0));
    const activeAvailableUses = Math.max(0, Math.floor(Number(resp.value.availableUses) || 0));
    if (!Number.isFinite(expiresAtMs) || Date.now() > expiresAtMs) return null;
    return {
      record,
      expiresAtMs,
      committedRemainingUses,
      reservedUses: activeReservedUses,
      availableUses: activeAvailableUses,
      remainingUses: activeAvailableUses,
    };
  }

  async consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult> {
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
  ): Promise<WalletSessionConsumeUsesResult> {
    const resp = await callDo<{ remainingUses: number }>(this.stub, {
      op: 'authConsumeUseCountOnce',
      key: this.key(id),
      idempotencyKey,
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return { ok: true, remainingUses: resp.value.remainingUses };
  }

  async reserveUseCountOnce(
    input: WalletSessionBudgetReserveUseCountInput,
  ): Promise<WalletSessionBudgetReservationResult> {
    const resp = await callDo<{
      reservation: WalletSigningBudgetReservation;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }>(this.stub, {
      op: 'authReserveBudgetUseCount',
      key: this.key(input.walletSigningSessionId),
      input,
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return {
      ok: true,
      reservation: resp.value.reservation,
      remainingUses: resp.value.remainingUses,
      reservedUses: resp.value.reservedUses,
      availableUses: resp.value.availableUses,
    };
  }

  async commitReservedUseCountOnce(
    input: WalletSessionBudgetCommitReservedUseCountInput,
  ): Promise<WalletSessionConsumeUsesResult> {
    const resp = await callDo<{ remainingUses: number }>(this.stub, {
      op: 'authCommitReservedBudgetUseCount',
      key: this.key(input.walletSigningSessionId),
      input,
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return { ok: true, remainingUses: resp.value.remainingUses };
  }

  async releaseReservedUseCount(
    input: WalletSessionBudgetReleaseReservedUseCountInput,
  ): Promise<WalletSessionBudgetReleaseResult> {
    const resp = await callDo<{
      released: boolean;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }>(this.stub, {
      op: 'authReleaseReservedBudgetUseCount',
      key: this.key(input.walletSigningSessionId),
      input,
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return {
      ok: true,
      released: resp.value.released,
      remainingUses: resp.value.remainingUses,
      reservedUses: resp.value.reservedUses,
      availableUses: resp.value.availableUses,
    };
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
  ): Promise<WalletSessionReplayGuardResult> {
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
    bucket: RouterAbEd25519PresignRefillRateLimitBucket,
    policy: RouterAbEd25519PresignRefillRateLimitPolicy,
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
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
  ): Promise<void> {
    const parsed = parseRouterAbEd25519PresignRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
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
    record: RouterAbEd25519PresignRecord,
    ttlMs: number,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519PutPresignWithCapacityResult> {
    const parsed = parseRouterAbEd25519PresignRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B Ed25519 presign record');
    const expiresAtMs = Date.now() + Math.max(0, Number(ttlMs) || 0);
    const value = { ...parsed, expiresAtMs };
    const resp = await callDo<RouterAbEd25519PutPresignWithCapacityResult>(this.stub, {
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
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519CheckPresignCapacityResult> {
    const walletId = toOptionalTrimmedString(walletSigningSessionId);
    if (!walletId) return { ok: false, code: 'capacity_exceeded' };
    const resp = await callDo<RouterAbEd25519CheckPresignCapacityResult>(this.stub, {
      op: 'ed25519PresignCheckCapacity',
      capacity,
      walletIndexKey: this.presignWalletIndexKey(walletId),
      globalIndexKey: this.presignGlobalIndexKey(),
    });
    if (!resp.ok) return { ok: false, code: 'capacity_exceeded' };
    return resp.value;
  }

  async consumePresignRefillRateLimit(
    bucket: RouterAbEd25519PresignRefillRateLimitBucket,
    policy: RouterAbEd25519PresignRefillRateLimitPolicy,
    cost: number,
  ): Promise<RouterAbEd25519ConsumePresignRefillRateLimitResult> {
    const resp = await callDo<RouterAbEd25519ConsumePresignRefillRateLimitResult>(this.stub, {
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
    expectedScope: RouterAbEd25519PresignExpectedScope,
  ): Promise<RouterAbEd25519TakePresignForFinalizeResult> {
    const resp = await callDo<RouterAbEd25519TakePresignForFinalizeResult>(this.stub, {
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

export class CloudflareDurableObjectRouterAbEcdsaHssPoolFillSessionStore implements RouterAbEcdsaHssPoolFillSessionStore {
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
    record: RouterAbEcdsaHssPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');
    const resp = await callDo<{ status?: unknown }>(this.stub, {
      op: 'routerAbEcdsaHssPoolFillSessionCreate',
      key: this.key(key),
      value: parsed,
      ttlMs: Math.max(0, Number(ttlMs) || 0),
    });
    if (!resp.ok) throw new Error(resp.message);
    const status = toOptionalTrimmedString(resp.value?.status);
    if (status === 'ok') return { ok: true };
    if (status === 'exists') return { ok: false, code: 'exists' };
    throw new Error(
      `[threshold-ecdsa] Durable Object Router A/B ECDSA-HSS pool-fill session create returned unexpected status: ${String(status || 'null')}`,
    );
  }

  async getSession(id: string): Promise<RouterAbEcdsaHssPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(key) });
    if (!resp.ok) return null;
    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(
      resp.value,
    ) as RouterAbEcdsaHssPoolFillSessionRecord | null;
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
    nextRecord: RouterAbEcdsaHssPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaHssPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1)
      return { ok: false, code: 'version_mismatch' };
    const parsed = parseRouterAbEcdsaHssPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA-HSS pool-fill session record');
    const resp = await callDo<{ status?: unknown; record?: unknown }>(this.stub, {
      op: 'routerAbEcdsaHssPoolFillSessionAdvanceCas',
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
        `[threshold-ecdsa] Durable Object Router A/B ECDSA-HSS pool-fill session CAS returned unexpected status: ${String(status || 'null')}`,
      );
    }
    const record = parseRouterAbEcdsaHssPoolFillSessionRecord(
      resp.value?.record,
    ) as RouterAbEcdsaHssPoolFillSessionRecord | null;
    if (!record)
      throw new Error(
        '[threshold-ecdsa] Durable Object Router A/B ECDSA-HSS pool-fill session CAS returned invalid record',
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

export class CloudflareDurableObjectRouterAbEcdsaHssPresignaturePool implements RouterAbEcdsaHssPresignaturePool {
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

  async put(record: RouterAbEcdsaHssServerPresignatureShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    if (!relayerKeyId) throw new Error('Missing relayerKeyId');
    const resp = await callDo<void>(this.stub, {
      op: 'routerAbEcdsaHssPresignaturePut',
      listKey: this.listKey(relayerKeyId),
      value: record,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async reserve(
    relayerKeyId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    if (!key) return null;
    const resp = await callDo<unknown | null>(this.stub, {
      op: 'routerAbEcdsaHssPresignatureReserve',
      listKey: this.listKey(key),
      reservedKeyPrefix: this.reservedKeyPrefix(key),
      ttlMs: this.reservationTtlMs,
    });
    if (!resp.ok) return null;
    return parseRouterAbEcdsaHssServerPresignatureShareRecord(
      resp.value,
    ) as RouterAbEcdsaHssServerPresignatureShareRecord | null;
  }

  async reserveById(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const resp = await callDo<unknown | null>(this.stub, {
      op: 'routerAbEcdsaHssPresignatureReserveById',
      listKey: this.listKey(key),
      reservedKeyPrefix: this.reservedKeyPrefix(key),
      presignatureId: id,
      ttlMs: this.reservationTtlMs,
    });
    if (!resp.ok) return null;
    return parseRouterAbEcdsaHssServerPresignatureShareRecord(
      resp.value,
    ) as RouterAbEcdsaHssServerPresignatureShareRecord | null;
  }

  async consume(
    relayerKeyId: string,
    presignatureId: string,
  ): Promise<RouterAbEcdsaHssServerPresignatureShareRecord | null> {
    const key = toOptionalTrimmedString(relayerKeyId);
    const id = toOptionalTrimmedString(presignatureId);
    if (!key || !id) return null;
    const resp = await callDo<unknown | null>(this.stub, {
      op: 'getdel',
      key: this.reservedKey(key, id),
    });
    if (!resp.ok) return null;
    return parseRouterAbEcdsaHssServerPresignatureShareRecord(
      resp.value,
    ) as RouterAbEcdsaHssServerPresignatureShareRecord | null;
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
  walletSessionStore: Ed25519WalletSessionStore;
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

  const walletSessionPrefix = computeWalletSessionPrefix(config);
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
    walletSessionStore: new CloudflareDurableObjectEd25519WalletSessionStore({
      namespace,
      objectName,
      keyPrefix: walletSessionPrefix,
    }),
  };
}

export function createCloudflareDurableObjectThresholdEcdsaStores(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
}): {
  keyStore: ThresholdEcdsaIntegratedKeyStore;
  sessionStore: ThresholdEd25519SessionStore;
  walletSessionStore: Ed25519WalletSessionStore;
  poolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
  presignaturePool: RouterAbEcdsaHssPresignaturePool;
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

  const walletSessionPrefix = computeWalletSessionPrefixEcdsa(config);
  const sessionPrefix = computeSessionPrefixEcdsa(config);
  const keyPrefix = computeKeyPrefixEcdsa(config);
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
    walletSessionStore: new CloudflareDurableObjectEd25519WalletSessionStore({
      namespace,
      objectName,
      keyPrefix: walletSessionPrefix,
    }),
    poolFillSessionStore: new CloudflareDurableObjectRouterAbEcdsaHssPoolFillSessionStore({
      namespace,
      objectName,
      keyPrefix: presignPrefix,
    }),
    presignaturePool: new CloudflareDurableObjectRouterAbEcdsaHssPresignaturePool({
      namespace,
      objectName,
      keyPrefix: presignPrefix,
    }),
  };
}
