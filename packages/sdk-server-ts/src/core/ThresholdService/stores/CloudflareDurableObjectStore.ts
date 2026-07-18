import type { NormalizedLogger } from '../../logger';
import type { CloudflareDurableObjectNamespaceLike, ThresholdStoreConfigInput } from '../../types';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT } from '../../defaultConfigsServer';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { deriveThresholdEcdsaKeyHandle } from '@shared/utils/thresholdEcdsaKeyHandle';
import {
  parseEcdsaDerivationRoleLocalKeyRecord,
  isObject,
  parseRouterAbEcdsaDerivationPoolFillSessionRecord,
  parseEcdsaWalletSessionRecord,
  parseEd25519WalletSessionRecord,
  parseWalletSigningBudgetSessionRecord,
  parseThresholdEcdsaMpcSessionRecord,
  parseThresholdEd25519CoordinatorSigningSessionRecord,
  parseThresholdEd25519KeyRecord,
  parseThresholdEd25519MpcSessionRecord,
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
import type { EcdsaDerivationRoleLocalKeyRecord } from '../../types';
import type {
  ThresholdEd25519CoordinatorSigningSessionRecord,
  ThresholdEcdsaMpcSessionRecord,
  ThresholdEcdsaSessionStore,
  ThresholdMpcSessionRecord,
  ThresholdClaimMpcSessionResult,
  ThresholdEd25519MpcSessionRecord,
  ThresholdReadMpcSessionResult,
  ThresholdEd25519ClaimMpcSessionResult,
  ThresholdEd25519ReadMpcSessionResult,
  ThresholdEd25519SessionStore,
  ThresholdEd25519SigningSessionRecord,
} from './SessionStore';
import type {
  RouterAbEcdsaDerivationPoolFillSessionCasResult,
  RouterAbEcdsaDerivationPoolFillSessionRecord,
  RouterAbEcdsaDerivationPoolFillSessionStore,
} from './EcdsaSigningStore';
import type {
  RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput,
  RouterAbEcdsaDerivationPoolFillLiveSessionCreateValue,
  RouterAbEcdsaDerivationPoolFillLiveSessionOwner,
  RouterAbEcdsaDerivationPoolFillLiveSessionStepInput,
  RouterAbEcdsaDerivationPoolFillParseResult,
  RouterAbEcdsaDerivationPoolFillPreparedStep,
} from '../routerAb/ecdsaDerivationPoolFillLiveSession';

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
type DoRouterAbEcdsaDerivationPoolFillSessionCreateRequest = {
  op: 'routerAbEcdsaDerivationPoolFillSessionCreate';
  key: string;
  value: unknown;
  ttlMs?: number;
};
type DoRouterAbEcdsaDerivationPoolFillSessionAdvanceCasRequest = {
  op: 'routerAbEcdsaDerivationPoolFillSessionAdvanceCas';
  key: string;
  expectedVersion: number;
  value: unknown;
  ttlMs?: number;
};
type DoRouterAbEcdsaDerivationPoolFillLiveSessionCreateRequest = {
  op: 'routerAbEcdsaDerivationPoolFillLiveSessionCreate';
  input: RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput;
};
type DoRouterAbEcdsaDerivationPoolFillLiveSessionStepRequest = {
  op: 'routerAbEcdsaDerivationPoolFillLiveSessionStep';
  input: RouterAbEcdsaDerivationPoolFillLiveSessionStepInput;
};
type DoRouterAbEcdsaDerivationPoolFillLiveSessionDeleteRequest = {
  op: 'routerAbEcdsaDerivationPoolFillLiveSessionDelete';
  presignSessionId: string;
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
  | DoRouterAbEcdsaDerivationPoolFillSessionCreateRequest
  | DoRouterAbEcdsaDerivationPoolFillSessionAdvanceCasRequest
  | DoRouterAbEcdsaDerivationPoolFillLiveSessionCreateRequest
  | DoRouterAbEcdsaDerivationPoolFillLiveSessionStepRequest
  | DoRouterAbEcdsaDerivationPoolFillLiveSessionDeleteRequest

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
type ThresholdEcdsaStoredKeyRecord = EcdsaDerivationRoleLocalKeyRecord;

function ecdsaIdentityPart(value: unknown): string {
  return encodeURIComponent(String(value ?? '').trim());
}

function ecdsaSigningRootVersion(record: ThresholdEcdsaStoredKeyRecord): string {
  return String(record.signingRootVersion || '').trim() || 'default';
}

async function withEcdsaDerivationRoleLocalRecordKeyHandle(
  record: EcdsaDerivationRoleLocalKeyRecord,
): Promise<EcdsaDerivationRoleLocalKeyRecord & { keyHandle: string }> {
  const parsed = parseEcdsaDerivationRoleLocalKeyRecord(record);
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

async function parseStoredEcdsaDerivationRoleLocalKeyRecord(
  raw: unknown,
): Promise<(EcdsaDerivationRoleLocalKeyRecord & { keyHandle: string }) | null> {
  const parsed = parseEcdsaDerivationRoleLocalKeyRecord(raw);
  return parsed ? await withEcdsaDerivationRoleLocalRecordKeyHandle(parsed) : null;
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

  async getRoleLocalByKeyHandle(keyHandle: string): Promise<EcdsaDerivationRoleLocalKeyRecord | null> {
    const handle = toOptionalTrimmedString(keyHandle);
    if (!handle) return null;
    const directResp = await callDo<unknown | null>(this.stub, {
      op: 'get',
      key: this.recordKey(handle),
    });
    if (directResp.ok) {
      const direct = await parseStoredEcdsaDerivationRoleLocalKeyRecord(directResp.value);
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
    return await parseStoredEcdsaDerivationRoleLocalKeyRecord(recordResp.value);
  }

  async putRoleLocalByKeyHandle(record: EcdsaDerivationRoleLocalKeyRecord): Promise<void> {
    const parsed = await withEcdsaDerivationRoleLocalRecordKeyHandle(record);
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
      ? await parseStoredEcdsaDerivationRoleLocalKeyRecord(canonicalRecordResp.value)
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
      (await parseStoredEcdsaDerivationRoleLocalKeyRecord(recordResp ? recordResp.value : null));
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

export class CloudflareDurableObjectRouterAbEcdsaDerivationPoolFillSessionStore implements RouterAbEcdsaDerivationPoolFillSessionStore {
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
    record: RouterAbEcdsaDerivationPoolFillSessionRecord,
    ttlMs: number,
  ): Promise<{ ok: true } | { ok: false; code: 'exists' }> {
    const key = toOptionalTrimmedString(id);
    if (!key) throw new Error('Missing presignSessionId');
    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(record);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA derivation pool-fill session record');
    const resp = await callDo<{ status?: unknown }>(this.stub, {
      op: 'routerAbEcdsaDerivationPoolFillSessionCreate',
      key: this.key(key),
      value: parsed,
      ttlMs: Math.max(0, Number(ttlMs) || 0),
    });
    if (!resp.ok) throw new Error(resp.message);
    const status = toOptionalTrimmedString(resp.value?.status);
    if (status === 'ok') return { ok: true };
    if (status === 'exists') return { ok: false, code: 'exists' };
    throw new Error(
      `[threshold-ecdsa] Durable Object Router A/B ECDSA derivation pool-fill session create returned unexpected status: ${String(status || 'null')}`,
    );
  }

  async getSession(id: string): Promise<RouterAbEcdsaDerivationPoolFillSessionRecord | null> {
    const key = toOptionalTrimmedString(id);
    if (!key) return null;
    const resp = await callDo<unknown | null>(this.stub, { op: 'get', key: this.key(key) });
    if (!resp.ok) return null;
    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(
      resp.value,
    ) as RouterAbEcdsaDerivationPoolFillSessionRecord | null;
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
    nextRecord: RouterAbEcdsaDerivationPoolFillSessionRecord;
    ttlMs: number;
  }): Promise<RouterAbEcdsaDerivationPoolFillSessionCasResult> {
    const key = toOptionalTrimmedString(input.id);
    if (!key) return { ok: false, code: 'not_found' };
    const expectedVersion = Math.floor(Number(input.expectedVersion));
    if (!Number.isFinite(expectedVersion) || expectedVersion < 1)
      return { ok: false, code: 'version_mismatch' };
    const parsed = parseRouterAbEcdsaDerivationPoolFillSessionRecord(input.nextRecord);
    if (!parsed) throw new Error('Invalid Router A/B ECDSA derivation pool-fill session record');
    const resp = await callDo<{ status?: unknown; record?: unknown }>(this.stub, {
      op: 'routerAbEcdsaDerivationPoolFillSessionAdvanceCas',
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
        `[threshold-ecdsa] Durable Object Router A/B ECDSA derivation pool-fill session CAS returned unexpected status: ${String(status || 'null')}`,
      );
    }
    const record = parseRouterAbEcdsaDerivationPoolFillSessionRecord(
      resp.value?.record,
    ) as RouterAbEcdsaDerivationPoolFillSessionRecord | null;
    if (!record)
      throw new Error(
        '[threshold-ecdsa] Durable Object Router A/B ECDSA derivation pool-fill session CAS returned invalid record',
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

export class CloudflareDurableObjectRouterAbEcdsaDerivationPoolFillLiveSessionOwner
  implements RouterAbEcdsaDerivationPoolFillLiveSessionOwner
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
    input: RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput,
  ): Promise<
    RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillLiveSessionCreateValue>
  > {
    const parsedRecord = parseRouterAbEcdsaDerivationPoolFillSessionRecord(input.record);
    if (!parsedRecord) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid Router A/B ECDSA derivation pool-fill session record',
      };
    }
    const resp = await callDo<
      RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillLiveSessionCreateValue>
    >(this.stubForPresignSession(input.presignSessionId), {
      op: 'routerAbEcdsaDerivationPoolFillLiveSessionCreate',
      input: {
        ...input,
        record: parsedRecord,
      },
    });
    if (!resp.ok) throw new Error(resp.message);
    return resp.value;
  }

  async stepSession(
    input: RouterAbEcdsaDerivationPoolFillLiveSessionStepInput,
  ): Promise<RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillPreparedStep>> {
    const parsedRecord = parseRouterAbEcdsaDerivationPoolFillSessionRecord(input.record);
    if (!parsedRecord) {
      return {
        ok: false,
        code: 'invalid_body',
        message: 'Invalid Router A/B ECDSA derivation pool-fill session record',
      };
    }
    const resp = await callDo<
      RouterAbEcdsaDerivationPoolFillParseResult<RouterAbEcdsaDerivationPoolFillPreparedStep>
    >(this.stubForPresignSession(input.presignSessionId), {
      op: 'routerAbEcdsaDerivationPoolFillLiveSessionStep',
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
      op: 'routerAbEcdsaDerivationPoolFillLiveSessionDelete',
      presignSessionId: id,
    });
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
    walletSessionStore: new CloudflareDurableObjectWalletSessionStore<Ed25519WalletSessionRecord>({
      namespace,
      objectName,
      keyPrefix: walletSessionPrefix,
      parseRecord: parseEd25519WalletSessionRecord,
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
  poolFillSessionStore: RouterAbEcdsaDerivationPoolFillSessionStore;
  poolFillLiveSessionOwner: RouterAbEcdsaDerivationPoolFillLiveSessionOwner;
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
    poolFillSessionStore: new CloudflareDurableObjectRouterAbEcdsaDerivationPoolFillSessionStore({
      namespace,
      objectName,
      keyPrefix: presignPrefix,
    }),
    poolFillLiveSessionOwner: new CloudflareDurableObjectRouterAbEcdsaDerivationPoolFillLiveSessionOwner({
      namespace,
      objectName,
    }),
  };
}
