import type { NormalizedLogger } from '../../logger';
import type { CloudflareDurableObjectNamespaceLike, ThresholdStoreConfigInput } from '../../types';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from '../../defaultConfigsServer';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  parseEcdsaHssRoleLocalKeyRecord,
  isObject,
  parseRouterAbEcdsaHssPoolFillSessionRecord,
  parseRouterAbEcdsaHssServerPresignatureShareRecord,
  parseEcdsaWalletSessionRecord,
  parseEd25519WalletSessionRecord,
  parseWalletSigningBudgetSessionRecord,
  parseThresholdEcdsaMpcSessionRecord,
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseThresholdEd25519KeyRecord,
  parseThresholdEd25519MpcSessionRecord,
  parseRouterAbEd25519PresignRecord,
  parseThresholdEd25519SigningSessionRecord,
  canonicalThresholdEd25519RelayerKeyId,
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
  WalletSessionBudgetReleaseReservedUseCountForIdentityInput,
  WalletSessionBudgetValidateReservedUseCountInput,
  WalletSessionBudgetReleaseReservedUseCountInput,
  WalletSessionBudgetReleaseResult,
  WalletSessionBudgetReservationResult,
  WalletSessionBudgetReserveUseCountInput,
  WalletSigningBudgetReservation,
  WalletSigningBudgetSessionRecord,
  WalletSigningBudgetSessionStore,
  EcdsaWalletSessionRecord,
  EcdsaWalletSessionStore,
  Ed25519WalletSessionRecord,
  Ed25519WalletSessionStore,
  WalletSessionRecord,
  WalletSessionRecordParser,
  WalletSessionStore,
} from './WalletSessionStore';
import type {
  ThresholdEcdsaIntegratedKeyStore,
  ThresholdEd25519ReadyKeyRecord,
  ThresholdEd25519KeyStore,
} from './KeyStore';
import type {
  EcdsaHssRoleLocalKeyRecord,
  ThresholdEd25519HssCanonicalContext,
  ThresholdEd25519HssPreparedSessionEnvelope,
  ThresholdEd25519HssSessionOperation,
  ThresholdEd25519HssStoredPreparedServerSession,
  ThresholdEd25519HssStoredRespondedServerSession,
  ThresholdEd25519HssStoredServerInputs,
  ThresholdEd25519HssStoredStagedEvaluatorArtifact,
} from '../../types';
import type {
  ThresholdEd25519HssCeremonyRecord,
  ThresholdEd25519HssCeremonyStore,
} from '../ThresholdSigningService';
import type {
  ThresholdEd25519CoordinatorSigningSessionRecord,
  ThresholdEcdsaMpcSessionRecord,
  ThresholdEcdsaSessionStore,
  ThresholdMpcSessionRecord,
  ThresholdClaimMpcSessionResult,
  RouterAbEd25519ConsumePresignRefillRateLimitResult,
  ThresholdEd25519MpcSessionRecord,
  ThresholdReadMpcSessionResult,
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
import type {
  RouterAbEcdsaHssPoolFillLiveSessionCreateInput,
  RouterAbEcdsaHssPoolFillLiveSessionCreateValue,
  RouterAbEcdsaHssPoolFillLiveSessionOwner,
  RouterAbEcdsaHssPoolFillLiveSessionStepInput,
  RouterAbEcdsaHssPoolFillParseResult,
  RouterAbEcdsaHssPoolFillPreparedStep,
} from '../routerAb/ecdsaHssPoolFillLiveSession';

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
type DoAuthValidateReservedBudgetUseCountRequest = {
  op: 'authValidateReservedBudgetUseCount';
  key: string;
  input: WalletSessionBudgetValidateReservedUseCountInput;
};
type DoAuthReleaseReservedBudgetUseCountRequest = {
  op: 'authReleaseReservedBudgetUseCount';
  key: string;
  input: WalletSessionBudgetReleaseReservedUseCountInput;
};
type DoAuthReleaseReservedBudgetUseCountForIdentityRequest = {
  op: 'authReleaseReservedBudgetUseCountForIdentity';
  key: string;
  input: WalletSessionBudgetReleaseReservedUseCountForIdentityInput;
};
type DoAuthReserveReplayGuardRequest = {
  op: 'authReserveReplayGuard';
  key: string;
  expiresAtMs: number;
};
type DoRouterAbEcdsaHssPresignaturePutRequest = {
  op: 'routerAbEcdsaHssPresignaturePut';
  listKey: string;
  dedupeKey: string;
  value: unknown;
};
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
type DoRouterAbEcdsaHssPoolFillLiveSessionCreateRequest = {
  op: 'routerAbEcdsaHssPoolFillLiveSessionCreate';
  input: RouterAbEcdsaHssPoolFillLiveSessionCreateInput;
};
type DoRouterAbEcdsaHssPoolFillLiveSessionStepRequest = {
  op: 'routerAbEcdsaHssPoolFillLiveSessionStep';
  input: RouterAbEcdsaHssPoolFillLiveSessionStepInput;
};
type DoRouterAbEcdsaHssPoolFillLiveSessionDeleteRequest = {
  op: 'routerAbEcdsaHssPoolFillLiveSessionDelete';
  presignSessionId: string;
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
  | DoAuthValidateReservedBudgetUseCountRequest
  | DoAuthReleaseReservedBudgetUseCountRequest
  | DoAuthReleaseReservedBudgetUseCountForIdentityRequest
  | DoAuthReserveReplayGuardRequest
  | DoRouterAbEcdsaHssPresignaturePutRequest
  | DoRouterAbEcdsaHssPresignatureReserveRequest
  | DoRouterAbEcdsaHssPresignatureReserveByIdRequest
  | DoRouterAbEcdsaHssPoolFillSessionCreateRequest
  | DoRouterAbEcdsaHssPoolFillSessionAdvanceCasRequest
  | DoRouterAbEcdsaHssPoolFillLiveSessionCreateRequest
  | DoRouterAbEcdsaHssPoolFillLiveSessionStepRequest
  | DoRouterAbEcdsaHssPoolFillLiveSessionDeleteRequest
  | DoEd25519PresignCheckCapacityRequest
  | DoEd25519PresignConsumeRateLimitRequest
  | DoEd25519PresignPutWithCapacityRequest
  | DoEd25519PresignTakeRequest;

type DoAuthEntry<TRecord extends WalletSessionRecord> = {
  record: TRecord;
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
      record.evmFamilySigningKeySlotId,
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

function computeEd25519HssCeremonyPrefix(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ED25519_HSS_CEREMONY_PREFIX);
  if (explicit) return explicit.endsWith(':') ? explicit : `${explicit}:`;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  if (basePrefix) {
    const base = basePrefix.endsWith(':') ? basePrefix : `${basePrefix}:`;
    return `${base}ed25519-hss-ceremony:`;
  }
  return 'w3a:threshold-ed25519:hss-ceremony:';
}

function computeWalletSessionPrefixEcdsa(config: Record<string, unknown>): string {
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const explicit = toOptionalTrimmedString(config.THRESHOLD_ECDSA_WALLET_SESSION_PREFIX);
  return toThresholdEcdsaWalletSessionPrefix(
    explicit || toThresholdEcdsaPrefixFromBase(basePrefix, 'wallet-session'),
  );
}

function computeWalletSigningBudgetSessionPrefix(config: Record<string, unknown>): string {
  const explicit = toOptionalTrimmedString(config.THRESHOLD_WALLET_SIGNING_BUDGET_SESSION_PREFIX);
  if (explicit) return explicit.endsWith(':') ? explicit : `${explicit}:`;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const base = toThresholdEd25519PrefixFromBase(basePrefix, 'wallet-session');
  return base ? `${base}budget:` : 'w3a:threshold-wallet-budget:sess:';
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

export class CloudflareDurableObjectWalletSessionStore<
  TRecord extends WalletSessionRecord,
> implements WalletSessionStore<TRecord> {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;
  private readonly parseRecord: WalletSessionRecordParser<TRecord>;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
    parseRecord: WalletSessionRecordParser<TRecord>;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
    this.parseRecord = input.parseRecord;
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private replayGuardKey(scopeId: string, replayKey: string): string {
    return `${this.keyPrefix}replay:${toOptionalTrimmedString(scopeId) || 'missing'}:${toOptionalTrimmedString(replayKey) || 'missing'}`;
  }

  async putSession(
    id: string,
    record: TRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    const expiresAtMs = Date.now() + ttlMs;
    const entry: DoAuthEntry<TRecord> = {
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

  async getSession(id: string): Promise<TRecord | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(id) });
    if (!resp.ok) return null;
    const raw = resp.value;
    const entry = isObject(raw) ? (raw as Record<string, unknown>) : null;
    const record = entry ? this.parseRecord((entry as { record?: unknown }).record) : null;
    const expiresAtMs = entry ? (entry as { expiresAtMs?: unknown }).expiresAtMs : null;
    if (!record || typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs)) return null;
    if (Date.now() > expiresAtMs) return null;
    return record;
  }

  async getSessionStatus(id: string) {
    const resp = await callDo<{
      record: TRecord;
      expiresAtMs: number;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    } | null>(this.stub, { op: 'authGetBudgetStatus', key: this.key(id) });
    if (!resp.ok) return null;
    if (!resp.value) return null;
    const record = this.parseRecord(resp.value.record);
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
      key: this.key(input.signingGrantId),
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
      key: this.key(input.signingGrantId),
      input,
    });
    if (!resp.ok) return { ok: false, code: resp.code, message: resp.message };
    return { ok: true, remainingUses: resp.value.remainingUses };
  }

  async validateReservedUseCount(
    input: WalletSessionBudgetValidateReservedUseCountInput,
  ): Promise<WalletSessionConsumeUsesResult> {
    const resp = await callDo<{ remainingUses: number }>(this.stub, {
      op: 'authValidateReservedBudgetUseCount',
      key: this.key(input.signingGrantId),
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
      key: this.key(input.signingGrantId),
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

  async releaseReservedUseCountForIdentity(
    input: WalletSessionBudgetReleaseReservedUseCountForIdentityInput,
  ): Promise<WalletSessionBudgetReleaseResult> {
    const resp = await callDo<{
      released: boolean;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }>(this.stub, {
      op: 'authReleaseReservedBudgetUseCountForIdentity',
      key: this.key(input.signingGrantId),
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

type CloudflareDoMpcSessionRecordParser<TRecord extends ThresholdMpcSessionRecord> = (
  raw: unknown,
) => TRecord | null;

export class CloudflareDurableObjectThresholdEd25519SessionStore<
  TMpcRecord extends ThresholdMpcSessionRecord = ThresholdEd25519MpcSessionRecord,
> {
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;
  private readonly coordinatorPrefix: string;
  private readonly presignPrefix: string;
  private readonly presignRateLimitPrefix: string;
  private readonly parseMpcSessionRecord: CloudflareDoMpcSessionRecordParser<TMpcRecord>;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
    keyPrefix: string;
    parseMpcSessionRecord?: CloudflareDoMpcSessionRecordParser<TMpcRecord>;
  }) {
    this.stub = resolveDoStub({ namespace: input.namespace, objectName: input.objectName });
    this.keyPrefix = input.keyPrefix;
    this.coordinatorPrefix = `${this.keyPrefix}coord:`;
    this.presignPrefix = `${this.keyPrefix}presign:`;
    this.presignRateLimitPrefix = `${this.keyPrefix}presign-rate:`;
    this.parseMpcSessionRecord =
      input.parseMpcSessionRecord ||
      (parseThresholdEd25519MpcSessionRecord as CloudflareDoMpcSessionRecordParser<TMpcRecord>);
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

  private presignWalletIndexKey(signingGrantId: string): string {
    return `${this.presignPrefix}idx:wallet:${encodeURIComponent(signingGrantId)}`;
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

  async putMpcSession(id: string, record: TMpcRecord, ttlMs: number): Promise<void> {
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key(id),
      value: record,
      ttlMs,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async readMpcSession(id: string): Promise<ThresholdReadMpcSessionResult<TMpcRecord> | null> {
    const resp = await callDo<{ value?: unknown; version?: unknown } | null>(this.stub, {
      op: 'readVersioned',
      key: this.key(id),
    });
    if (!resp.ok || !resp.value) return null;
    const record = this.parseMpcSessionRecord(resp.value.value);
    const version = toOptionalTrimmedString(resp.value.version);
    return record && version ? { record, version } : null;
  }

  async claimMpcSession(
    id: string,
    version: string,
  ): Promise<ThresholdClaimMpcSessionResult<TMpcRecord>> {
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
    const record = this.parseMpcSessionRecord(resp.value?.value);
    return record ? { ok: true, record } : { ok: false, code: 'invalid_record' };
  }

  async takeMpcSession(id: string): Promise<TMpcRecord | null> {
    const resp = await callDo<unknown | null>(this.stub, { op: 'getdel', key: this.key(id) });
    if (!resp.ok) return null;
    return this.parseMpcSessionRecord(resp.value);
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

  async putPresign(id: string, record: RouterAbEd25519PresignRecord, ttlMs: number): Promise<void> {
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
      walletIndexKey: this.presignWalletIndexKey(parsed.signingGrantId),
      globalIndexKey: this.presignGlobalIndexKey(),
    });
    if (!resp.ok) return { ok: false, code: 'capacity_exceeded' };
    return resp.value;
  }

  async checkPresignCapacity(
    signingGrantId: string,
    capacity: RouterAbEd25519PresignCapacity,
  ): Promise<RouterAbEd25519CheckPresignCapacityResult> {
    const walletId = toOptionalTrimmedString(signingGrantId);
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
      walletIndexKey: this.presignWalletIndexKey(expectedScope.signingGrantId),
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

  async get(relayerKeyId: string): Promise<ThresholdEd25519ReadyKeyRecord | null> {
    const id = canonicalThresholdEd25519RelayerKeyId(relayerKeyId);
    if (!id) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(id) });
    if (!resp.ok) return null;
    return parseThresholdEd25519KeyRecord(resp.value);
  }

  async put(relayerKeyId: string, record: ThresholdEd25519ReadyKeyRecord): Promise<void> {
    const id = canonicalThresholdEd25519RelayerKeyId(relayerKeyId);
    if (!id) throw new Error('Missing relayerKeyId');
    const resp = await callDo<void>(this.stub, { op: 'set', key: this.key(id), value: record });
    if (!resp.ok) throw new Error(resp.message);
  }

  async del(relayerKeyId: string): Promise<void> {
    const id = canonicalThresholdEd25519RelayerKeyId(relayerKeyId);
    if (!id) return;
    const resp = await callDo<void>(this.stub, { op: 'del', key: this.key(id) });
    if (!resp.ok) throw new Error(resp.message);
  }
}

type DurableEd25519HssSessionCeremonyWireRecord = {
  kind: 'session';
  expiresAtMs: number;
  relayerKeyId: string;
  operation: ThresholdEd25519HssSessionOperation;
  context: ThresholdEd25519HssCanonicalContext;
  preparedSession: ThresholdEd25519HssPreparedSessionEnvelope;
  preparedServerSession: {
    evaluatorDriverStateB64u: string;
    garblerDriverStateB64u: string;
    serverEvalStateB64u?: string;
  };
  serverInputs?: {
    yRelayerB64u: string;
    tauRelayerB64u: string;
  };
  advancedServerEval?: {
    contextBindingB64u: string;
    addStageRequestDigestB64u: string;
    advancedServerEvalStateB64u: string;
    priorStageResponseMessageB64u: string;
  };
  evaluationResult?: {
    stagedEvaluatorArtifactB64u: string;
    addStageRequestMessageB64u: string;
  };
};

const ED25519_HSS_SESSION_OPERATIONS: ReadonlySet<string> = new Set([
  'tx_signing',
  'link_device',
  'email_recovery',
  'registration_material_restore',
  'warm_session_reconstruction',
  'explicit_key_export',
]);

function parseDurableEd25519HssSessionOperation(raw: unknown): ThresholdEd25519HssSessionOperation {
  const value = toOptionalTrimmedString(raw);
  if (!ED25519_HSS_SESSION_OPERATIONS.has(value)) {
    throw new Error('durable Ed25519 HSS ceremony operation is invalid');
  }
  return value as ThresholdEd25519HssSessionOperation;
}

function parseDurableEd25519HssContext(raw: unknown): ThresholdEd25519HssCanonicalContext {
  if (!isObject(raw)) throw new Error('durable Ed25519 HSS ceremony context is invalid');
  const applicationBindingDigestB64u = toOptionalTrimmedString(raw.applicationBindingDigestB64u);
  if (!applicationBindingDigestB64u) {
    throw new Error('durable Ed25519 HSS ceremony context digest is required');
  }
  if (!Array.isArray(raw.participantIds)) {
    throw new Error('durable Ed25519 HSS ceremony participantIds are required');
  }
  const participantIds = raw.participantIds.map((id) => Number(id));
  if (
    participantIds.length === 0 ||
    participantIds.some((id) => !Number.isSafeInteger(id) || id <= 0)
  ) {
    throw new Error('durable Ed25519 HSS ceremony participantIds are invalid');
  }
  return { applicationBindingDigestB64u, participantIds };
}

function parseDurableEd25519HssPreparedSession(
  raw: unknown,
): ThresholdEd25519HssPreparedSessionEnvelope {
  if (!isObject(raw)) throw new Error('durable Ed25519 HSS preparedSession is invalid');
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const evaluatorDriverStateB64u = toOptionalTrimmedString(raw.evaluatorDriverStateB64u);
  if (!contextBindingB64u || !evaluatorDriverStateB64u) {
    throw new Error('durable Ed25519 HSS preparedSession is incomplete');
  }
  return { contextBindingB64u, evaluatorDriverStateB64u };
}

function parseDurableEd25519HssPreparedServerSession(
  raw: unknown,
): ThresholdEd25519HssStoredPreparedServerSession | ThresholdEd25519HssStoredRespondedServerSession {
  if (!isObject(raw)) {
    throw new Error('durable Ed25519 HSS preparedServerSession is invalid');
  }
  if (toOptionalTrimmedString(raw.preparedSessionHandle)) {
    throw new Error('durable Ed25519 HSS ceremony cannot store preparedSessionHandle');
  }
  const evaluatorDriverStateB64u = toOptionalTrimmedString(raw.evaluatorDriverStateB64u);
  const garblerDriverStateB64u = toOptionalTrimmedString(raw.garblerDriverStateB64u);
  if (!evaluatorDriverStateB64u || !garblerDriverStateB64u) {
    throw new Error('durable Ed25519 HSS preparedServerSession is incomplete');
  }
  const serverEvalStateB64u =
    typeof raw.serverEvalStateB64u === 'string' ? raw.serverEvalStateB64u.trim() : null;
  return {
    evaluatorDriverStateBytes: base64UrlDecode(evaluatorDriverStateB64u),
    garblerDriverStateBytes: base64UrlDecode(garblerDriverStateB64u),
    ...(serverEvalStateB64u !== null
      ? { serverEvalStateBytes: base64UrlDecode(serverEvalStateB64u) }
      : {}),
  };
}

function parseDurableEd25519HssServerInputs(
  raw: unknown,
): ThresholdEd25519HssStoredServerInputs | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!isObject(raw)) throw new Error('durable Ed25519 HSS serverInputs are invalid');
  const yRelayerB64u = toOptionalTrimmedString(raw.yRelayerB64u);
  const tauRelayerB64u = toOptionalTrimmedString(raw.tauRelayerB64u);
  if (!yRelayerB64u || !tauRelayerB64u) {
    throw new Error('durable Ed25519 HSS serverInputs are incomplete');
  }
  return {
    yRelayerBytes: base64UrlDecode(yRelayerB64u),
    tauRelayerBytes: base64UrlDecode(tauRelayerB64u),
  };
}

function parseDurableEd25519HssEvaluationResult(
  raw: unknown,
): ThresholdEd25519HssStoredStagedEvaluatorArtifact | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!isObject(raw)) throw new Error('durable Ed25519 HSS evaluationResult is invalid');
  if (toOptionalTrimmedString(raw.stagedEvaluatorArtifactHandle)) {
    throw new Error('durable Ed25519 HSS ceremony cannot store stagedEvaluatorArtifactHandle');
  }
  const stagedEvaluatorArtifactB64u = toOptionalTrimmedString(raw.stagedEvaluatorArtifactB64u);
  const addStageRequestMessageB64u = toOptionalTrimmedString(raw.addStageRequestMessageB64u);
  if (!stagedEvaluatorArtifactB64u) {
    throw new Error('durable Ed25519 HSS evaluationResult artifact is required');
  }
  if (!addStageRequestMessageB64u) {
    throw new Error('durable Ed25519 HSS evaluationResult add-stage request is required');
  }
  return {
    stagedEvaluatorArtifactBytes: base64UrlDecode(stagedEvaluatorArtifactB64u),
    addStageRequestMessageBytes: base64UrlDecode(addStageRequestMessageB64u),
  };
}

function parseDurableEd25519HssAdvancedServerEval(raw: unknown):
  | {
      contextBindingB64u: string;
      addStageRequestDigestB64u: string;
      advancedServerEvalStateB64u: string;
      priorStageResponseMessageB64u: string;
    }
  | undefined {
  if (raw === undefined || raw === null) return undefined;
  if (!isObject(raw)) throw new Error('durable Ed25519 HSS advancedServerEval is invalid');
  const contextBindingB64u = toOptionalTrimmedString(raw.contextBindingB64u);
  const addStageRequestDigestB64u = toOptionalTrimmedString(raw.addStageRequestDigestB64u);
  const advancedServerEvalStateB64u = toOptionalTrimmedString(raw.advancedServerEvalStateB64u);
  const priorStageResponseMessageB64u = toOptionalTrimmedString(
    raw.priorStageResponseMessageB64u,
  );
  if (
    !contextBindingB64u ||
    !addStageRequestDigestB64u ||
    !advancedServerEvalStateB64u ||
    !priorStageResponseMessageB64u
  ) {
    throw new Error('durable Ed25519 HSS advancedServerEval is incomplete');
  }
  base64UrlDecode(contextBindingB64u);
  base64UrlDecode(addStageRequestDigestB64u);
  base64UrlDecode(advancedServerEvalStateB64u);
  base64UrlDecode(priorStageResponseMessageB64u);
  return {
    contextBindingB64u,
    addStageRequestDigestB64u,
    advancedServerEvalStateB64u,
    priorStageResponseMessageB64u,
  };
}

function isDurableEd25519HssRespondedServerSession(
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession,
): preparedServerSession is ThresholdEd25519HssStoredRespondedServerSession {
  return (
    'serverEvalStateBytes' in preparedServerSession &&
    preparedServerSession.serverEvalStateBytes instanceof Uint8Array
  );
}

function durableEd25519HssPreparedServerSessionWire(
  preparedServerSession: ThresholdEd25519HssStoredPreparedServerSession,
): DurableEd25519HssSessionCeremonyWireRecord['preparedServerSession'] {
  if (toOptionalTrimmedString(preparedServerSession.preparedSessionHandle)) {
    throw new Error('durable Ed25519 HSS ceremony cannot store preparedSessionHandle');
  }
  const respondedFields = isDurableEd25519HssRespondedServerSession(preparedServerSession)
    ? { serverEvalStateB64u: base64UrlEncode(preparedServerSession.serverEvalStateBytes) }
    : {};
  return {
    evaluatorDriverStateB64u: base64UrlEncode(preparedServerSession.evaluatorDriverStateBytes),
    garblerDriverStateB64u: base64UrlEncode(preparedServerSession.garblerDriverStateBytes),
    ...respondedFields,
  };
}

function durableEd25519HssServerInputsWire(
  serverInputs: ThresholdEd25519HssStoredServerInputs | undefined,
): DurableEd25519HssSessionCeremonyWireRecord['serverInputs'] {
  if (!serverInputs) return undefined;
  return {
    yRelayerB64u: base64UrlEncode(serverInputs.yRelayerBytes),
    tauRelayerB64u: base64UrlEncode(serverInputs.tauRelayerBytes),
  };
}

function durableEd25519HssEvaluationResultWire(
  evaluationResult: ThresholdEd25519HssStoredStagedEvaluatorArtifact | undefined,
): DurableEd25519HssSessionCeremonyWireRecord['evaluationResult'] {
  if (!evaluationResult) return undefined;
  if (toOptionalTrimmedString(evaluationResult.stagedEvaluatorArtifactHandle)) {
    throw new Error('durable Ed25519 HSS ceremony cannot store stagedEvaluatorArtifactHandle');
  }
  if (!evaluationResult.stagedEvaluatorArtifactBytes) {
    throw new Error('durable Ed25519 HSS evaluationResult artifact is required');
  }
  if (!evaluationResult.addStageRequestMessageBytes) {
    throw new Error('durable Ed25519 HSS evaluationResult add-stage request is required');
  }
  return {
    stagedEvaluatorArtifactB64u: base64UrlEncode(evaluationResult.stagedEvaluatorArtifactBytes),
    addStageRequestMessageB64u: base64UrlEncode(evaluationResult.addStageRequestMessageBytes),
  };
}

function durableEd25519HssAdvancedServerEvalWire(
  advancedServerEval: Extract<
    ThresholdEd25519HssCeremonyRecord,
    { kind: 'session' }
  >['advancedServerEval'],
): DurableEd25519HssSessionCeremonyWireRecord['advancedServerEval'] {
  if (!advancedServerEval) return undefined;
  return {
    contextBindingB64u: advancedServerEval.contextBindingB64u,
    addStageRequestDigestB64u: advancedServerEval.addStageRequestDigestB64u,
    advancedServerEvalStateB64u: advancedServerEval.advancedServerEvalStateB64u,
    priorStageResponseMessageB64u: advancedServerEval.priorStageResponseMessageB64u,
  };
}

function durableEd25519HssSessionCeremonyWire(
  record: ThresholdEd25519HssCeremonyRecord,
): DurableEd25519HssSessionCeremonyWireRecord {
  if (record.kind !== 'session') {
    throw new Error('durable Ed25519 HSS ceremony store only accepts session ceremonies');
  }
  const serverInputs = durableEd25519HssServerInputsWire(record.serverInputs);
  const evaluationResult = durableEd25519HssEvaluationResultWire(record.evaluationResult);
  const advancedServerEval = durableEd25519HssAdvancedServerEvalWire(record.advancedServerEval);
  return {
    kind: 'session',
    expiresAtMs: record.expiresAtMs,
    relayerKeyId: record.relayerKeyId,
    operation: record.operation,
    context: record.context,
    preparedSession: record.preparedSession,
    preparedServerSession: durableEd25519HssPreparedServerSessionWire(record.preparedServerSession),
    ...(serverInputs ? { serverInputs } : {}),
    ...(advancedServerEval ? { advancedServerEval } : {}),
    ...(evaluationResult ? { evaluationResult } : {}),
  };
}

function parseDurableEd25519HssSessionCeremonyWire(
  raw: unknown,
): ThresholdEd25519HssCeremonyRecord | null {
  if (raw === undefined || raw === null) return null;
  if (!isObject(raw)) throw new Error('durable Ed25519 HSS ceremony record is invalid');
  if (raw.kind !== 'session') {
    throw new Error('durable Ed25519 HSS ceremony record kind is invalid');
  }
  const expiresAtMs = Number(raw.expiresAtMs);
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= 0) {
    throw new Error('durable Ed25519 HSS ceremony expiry is invalid');
  }
  const relayerKeyId = toOptionalTrimmedString(raw.relayerKeyId);
  if (!relayerKeyId) throw new Error('durable Ed25519 HSS ceremony relayerKeyId is required');
  const serverInputs = parseDurableEd25519HssServerInputs(raw.serverInputs);
  const advancedServerEval = parseDurableEd25519HssAdvancedServerEval(raw.advancedServerEval);
  const evaluationResult = parseDurableEd25519HssEvaluationResult(raw.evaluationResult);
  return {
    kind: 'session',
    expiresAtMs,
    relayerKeyId,
    operation: parseDurableEd25519HssSessionOperation(raw.operation),
    context: parseDurableEd25519HssContext(raw.context),
    preparedSession: parseDurableEd25519HssPreparedSession(raw.preparedSession),
    preparedServerSession: parseDurableEd25519HssPreparedServerSession(raw.preparedServerSession),
    ...(serverInputs ? { serverInputs } : {}),
    ...(advancedServerEval ? { advancedServerEval } : {}),
    ...(evaluationResult ? { evaluationResult } : {}),
  };
}

export class CloudflareDurableObjectThresholdEd25519HssCeremonyStore implements ThresholdEd25519HssCeremonyStore {
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

  private key(handle: string): string {
    return `${this.keyPrefix}${handle}`;
  }

  async cleanupExpired(_nowMs: number): Promise<void> {
    return;
  }

  async put(handle: string, record: ThresholdEd25519HssCeremonyRecord): Promise<void> {
    const id = toOptionalTrimmedString(handle);
    if (!id) throw new Error('Missing Ed25519 HSS ceremony handle');
    const ttlMs = Math.max(1, record.expiresAtMs - Date.now());
    const resp = await callDo<void>(this.stub, {
      op: 'set',
      key: this.key(id),
      value: durableEd25519HssSessionCeremonyWire(record),
      ttlMs,
    });
    if (!resp.ok) throw new Error(resp.message);
  }

  async get(handle: string): Promise<ThresholdEd25519HssCeremonyRecord | null> {
    const id = toOptionalTrimmedString(handle);
    if (!id) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(id) });
    if (!resp.ok) return null;
    const record = parseDurableEd25519HssSessionCeremonyWire(resp.value);
    if (!record) return null;
    if (record.expiresAtMs <= Date.now()) {
      await this.delete(id);
      return null;
    }
    return record;
  }

  async take(handle: string): Promise<ThresholdEd25519HssCeremonyRecord | null> {
    const id = toOptionalTrimmedString(handle);
    if (!id) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'getdel', key: this.key(id) });
    if (!resp.ok) return null;
    const record = parseDurableEd25519HssSessionCeremonyWire(resp.value);
    if (!record) return null;
    if (record.expiresAtMs <= Date.now()) return null;
    return record;
  }

  async delete(handle: string): Promise<void> {
    const id = toOptionalTrimmedString(handle);
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

export class CloudflareDurableObjectRouterAbEcdsaHssPoolFillLiveSessionOwner
  implements RouterAbEcdsaHssPoolFillLiveSessionOwner
{
  private readonly namespace: CloudflareDurableObjectNamespaceLike;
  private readonly objectNamePrefix: string;

  constructor(input: {
    namespace: CloudflareDurableObjectNamespaceLike;
    objectName: string;
  }) {
    this.namespace = input.namespace;
    this.objectNamePrefix = input.objectName;
  }

  private stubForPresignSession(presignSessionId: string): DurableObjectStubLike {
    const id = toOptionalTrimmedString(presignSessionId);
    if (!id) throw new Error('Missing presignSessionId');
    return resolveDoStub({
      namespace: this.namespace,
      objectName: `${this.objectNamePrefix}:ecdsa-pool-fill:${id}`,
    });
  }

  async createSession(
    input: RouterAbEcdsaHssPoolFillLiveSessionCreateInput,
  ): Promise<
    RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillLiveSessionCreateValue>
  > {
    const parsedRecord = parseRouterAbEcdsaHssPoolFillSessionRecord(input.record);
    if (!parsedRecord) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid Router A/B ECDSA-HSS pool-fill session record',
      };
    }
    const resp = await callDo<
      RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillLiveSessionCreateValue>
    >(this.stubForPresignSession(input.presignSessionId), {
      op: 'routerAbEcdsaHssPoolFillLiveSessionCreate',
      input: {
        ...input,
        record: parsedRecord,
      },
    });
    if (!resp.ok) throw new Error(resp.message);
    return resp.value;
  }

  async stepSession(
    input: RouterAbEcdsaHssPoolFillLiveSessionStepInput,
  ): Promise<RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillPreparedStep>> {
    const parsedRecord = parseRouterAbEcdsaHssPoolFillSessionRecord(input.record);
    if (!parsedRecord) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid Router A/B ECDSA-HSS pool-fill session record',
      };
    }
    const resp = await callDo<
      RouterAbEcdsaHssPoolFillParseResult<RouterAbEcdsaHssPoolFillPreparedStep>
    >(this.stubForPresignSession(input.presignSessionId), {
      op: 'routerAbEcdsaHssPoolFillLiveSessionStep',
      input: {
        ...input,
        record: parsedRecord,
      },
    });
    if (!resp.ok) throw new Error(resp.message);
    return resp.value;
  }

  async deleteSession(presignSessionId: string): Promise<void> {
    const id = toOptionalTrimmedString(presignSessionId);
    if (!id) return;
    const resp = await callDo<void>(this.stubForPresignSession(id), {
      op: 'routerAbEcdsaHssPoolFillLiveSessionDelete',
      presignSessionId: id,
    });
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

  private dedupeKey(relayerKeyId: string, presignatureId: string): string {
    return `${this.keyPrefix}done:${relayerKeyId}:${presignatureId}`;
  }

  async put(record: RouterAbEcdsaHssServerPresignatureShareRecord): Promise<void> {
    const relayerKeyId = toOptionalTrimmedString(record.relayerKeyId);
    const presignatureId = toOptionalTrimmedString(record.presignatureId);
    if (!relayerKeyId || !presignatureId) throw new Error('Missing relayerKeyId/presignatureId');
    const resp = await callDo<void>(this.stub, {
      op: 'routerAbEcdsaHssPresignaturePut',
      listKey: this.listKey(relayerKeyId),
      dedupeKey: this.dedupeKey(relayerKeyId, presignatureId),
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
  ed25519HssCeremonyStore: ThresholdEd25519HssCeremonyStore;
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
  const ed25519HssCeremonyPrefix = computeEd25519HssCeremonyPrefix(config);

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
    walletSessionStore: new CloudflareDurableObjectWalletSessionStore<Ed25519WalletSessionRecord>({
      namespace,
      objectName,
      keyPrefix: walletSessionPrefix,
      parseRecord: parseEd25519WalletSessionRecord,
    }),
    ed25519HssCeremonyStore: new CloudflareDurableObjectThresholdEd25519HssCeremonyStore({
      namespace,
      objectName,
      keyPrefix: ed25519HssCeremonyPrefix,
    }),
  };
}

export function createCloudflareDurableObjectWalletSigningBudgetStores(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
}): {
  walletSessionStore: WalletSigningBudgetSessionStore;
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

  const walletSessionPrefix = computeWalletSigningBudgetSessionPrefix(config);

  input.logger.info(
    '[threshold-budget] Using Cloudflare Durable Object store for wallet budget session persistence',
  );

  return {
    walletSessionStore:
      new CloudflareDurableObjectWalletSessionStore<WalletSigningBudgetSessionRecord>({
        namespace,
        objectName,
        keyPrefix: walletSessionPrefix,
        parseRecord: parseWalletSigningBudgetSessionRecord,
      }),
  };
}

export function createCloudflareDurableObjectThresholdEcdsaStores(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
}): {
  keyStore: ThresholdEcdsaIntegratedKeyStore;
  sessionStore: ThresholdEcdsaSessionStore;
  walletSessionStore: EcdsaWalletSessionStore;
  poolFillSessionStore: RouterAbEcdsaHssPoolFillSessionStore;
  poolFillLiveSessionOwner: RouterAbEcdsaHssPoolFillLiveSessionOwner;
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
    sessionStore:
      new CloudflareDurableObjectThresholdEd25519SessionStore<ThresholdEcdsaMpcSessionRecord>({
        namespace,
        objectName,
        keyPrefix: sessionPrefix,
        parseMpcSessionRecord: parseThresholdEcdsaMpcSessionRecord,
      }),
    walletSessionStore: new CloudflareDurableObjectWalletSessionStore<EcdsaWalletSessionRecord>({
      namespace,
      objectName,
      keyPrefix: walletSessionPrefix,
      parseRecord: parseEcdsaWalletSessionRecord,
    }),
    poolFillSessionStore: new CloudflareDurableObjectRouterAbEcdsaHssPoolFillSessionStore({
      namespace,
      objectName,
      keyPrefix: presignPrefix,
    }),
    poolFillLiveSessionOwner: new CloudflareDurableObjectRouterAbEcdsaHssPoolFillLiveSessionOwner({
      namespace,
      objectName,
    }),
    presignaturePool: new CloudflareDurableObjectRouterAbEcdsaHssPresignaturePool({
      namespace,
      objectName,
      keyPrefix: presignPrefix,
    }),
  };
}
