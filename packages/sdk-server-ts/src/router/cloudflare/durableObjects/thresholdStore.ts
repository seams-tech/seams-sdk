// Durable Object implementation for threshold signing state.
//
// This is exported from the SDK so Cloudflare Worker hosts can bind it directly
// (by re-exporting from their Worker entrypoint) without vendoring the code.

import { base64UrlEncode } from '@shared/utils/encoders';
import { isPlainObject } from '@shared/utils/validation';
import {
  computeSigningRootContextHashB64u,
  parseSigningRootRecord,
  signingRootRecordFromMigrationBundle,
  type SigningRootAuthorityScope,
  type SigningRootRecord,
  type SigningRootRecordResult,
} from '../../../core/ThresholdService/signingRootRecords';
import {
  parseRouterAbEcdsaDerivationPoolFillSessionRecord as parseFullRouterAbEcdsaDerivationPoolFillSessionRecord,
  parseWalletSigningBudgetSessionRecord,
} from '../../../core/ThresholdService/validation';
import type { RouterAbEcdsaDerivationPoolFillSessionRecord } from '../../../core/ThresholdService/stores/EcdsaSigningStore';
import {
  InMemoryRouterAbEcdsaDerivationPoolFillLiveSessionOwner,
  type RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput,
  type RouterAbEcdsaDerivationPoolFillLiveSessionStepInput,
} from '../../../core/ThresholdService/routerAb/ecdsaDerivationPoolFillLiveSession';

type DurableObjectStorageLike = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown, opts?: { expirationTtl?: number }): Promise<void>;
  delete(key: string): Promise<boolean>;
  transaction?<T>(fn: (txn: DurableObjectStorageLike) => Promise<T>): Promise<T>;
};

type DurableObjectStateLike = {
  storage: DurableObjectStorageLike;
};

type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;

const EXPORT_REPLAY_GUARD_CLOCK_SKEW_MS = 5 * 60_000;
const EXPORT_REPLAY_GUARD_MIN_RETENTION_MS = 24 * 60 * 60_000;

type DoReq =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'del'; key: string }
  | { op: 'readVersioned'; key: string }
  | { op: 'claimVersioned'; key: string; expectedVersion: string }
  | {
      op: 'getdelIfRelatedMatches';
      key: string;
      relatedKey: string;
      expectedRelated: unknown;
    }
  | {
      op: 'setWithIdentityGuard';
      key: string;
      identityKey: string;
      identityValue: string;
      keyHandleKey: string;
      keyHandleValue: string;
      value: unknown;
      ttlMs?: number;
    }
  | {
      op: 'delWithIdentityGuard';
      key: string;
      identityKey: string;
      identityValue: string;
      keyHandleKey: string;
      keyHandleValue: string;
    }
  | { op: 'getdel'; key: string }
  | { op: 'authConsumeUseCount'; key: string }
  | { op: 'authConsumeUseCountOnce'; key: string; idempotencyKey: string }
  | { op: 'authHasConsumedUseCountOnce'; key: string; idempotencyKey: string }
  | { op: 'authGetBudgetStatus'; key: string }
  | { op: 'authReserveBudgetUseCount'; key: string; input: unknown }
  | { op: 'authCommitReservedBudgetUseCount'; key: string; input: unknown }
  | { op: 'authValidateReservedBudgetUseCount'; key: string; input: unknown }
  | { op: 'authReleaseReservedBudgetUseCount'; key: string; input: unknown }
  | { op: 'authReleaseReservedBudgetUseCountForIdentity'; key: string; input: unknown }
  | { op: 'authReserveReplayGuard'; key: string; expiresAtMs: number }
  | {
      op: 'registrationReserveWalletId';
      key: string;
      walletId: string;
      expiresAtMs: number;
    }
  | {
      op: 'registrationCancelTerminal';
      ceremonyKey: string;
      registrationCeremonyId: string;
      walletId: string;
      reservation:
        | {
            kind: 'server_allocated_wallet';
            key: string;
          }
        | {
            kind: 'none';
          };
    }
  | {
      op: 'routerAbNormalSigningReserveQuota';
      key: string;
      requestId: string;
      lifecycleId: string;
      expiresAtMs: number;
      nowMs: number;
    }
  | {
      op: 'routerAbEcdsaDerivationPoolFillSessionCreate';
      key: string;
      value: unknown;
      ttlMs?: number;
    }
  | {
      op: 'routerAbEcdsaDerivationPoolFillSessionAdvanceCas';
      key: string;
      expectedVersion: number;
      value: unknown;
      ttlMs?: number;
    }
  | { op: 'routerAbEcdsaDerivationPoolFillLiveSessionCreate'; input: unknown }
  | { op: 'routerAbEcdsaDerivationPoolFillLiveSessionStep'; input: unknown }
  | { op: 'routerAbEcdsaDerivationPoolFillLiveSessionDelete'; presignSessionId: string }
  | { op: 'signingRootPut'; record: unknown }
  | { op: 'signingRootGet'; signingRootId: string; signingRootVersion: string }
  | { op: 'signingRootDelete'; signingRootId: string; signingRootVersion: string }
  | { op: 'signingRootStatus'; signingRootId: string; signingRootVersion: string };

type AuthEntry = {
  record: Record<string, unknown> & { expiresAtMs: number };
  remainingUses: number;
  expiresAtMs: number;
  consumedIdempotencyKeys?: Record<string, true>;
  budgetReservations?: Record<string, AuthBudgetReservation>;
  committedBudgetReservations?: Record<string, AuthBudgetCommit>;
};

type AuthBudgetReservation = {
  kind: 'wallet_signing_budget_reservation_v1';
  signingGrantId: string;
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
  signatureUses: number;
  reservationId: string;
  expiresAtMs: number;
  operationKey: string;
};

type AuthBudgetCommit = {
  operationKey: string;
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
  remainingUses: number;
  expiresAtMs: number;
};

type RouterAbNormalSigningQuotaReservation = {
  kind: 'router_ab_normal_signing_quota_reservation_v1';
  requestId: string;
  lifecycleId: string;
  expiresAtMs: number;
};

type RouterAbNormalSigningQuotaDecision =
  | { kind: 'accepted'; requestId: string }
  | { kind: 'reuse_existing'; requestId: string; existingLifecycleId: string }
  | { kind: 'short_window_saturated' };

const ECDSA_SHARED_IDENTITY_CONFLICT_MESSAGE =
  '[threshold-ecdsa] EVM-family key identity already exists for wallet/subject/rp/signing root';
const ECDSA_KEY_HANDLE_CONFLICT_MESSAGE =
  '[threshold-ecdsa] ECDSA key handle already exists in this namespace';

type SigningRootWireRecord = Omit<SigningRootRecord, 'sealedSigningRootSecretShares'> & {
  sealedSigningRootSecretShares: Array<{
    signingRootId: string;
    signingRootVersion: string;
    shareId: 1 | 2 | 3;
    sealedShareB64u: string;
    storageId?: string;
    kekId?: string;
  }>;
};

type SigningRootStatus = {
  projectId: string;
  envId: string;
  signingRootId: string;
  walletOrigin: string;
  authorityScope: SigningRootAuthorityScope;
  signingRootVersion: string;
  rootShareEpoch: number;
  shareThreshold: 2;
  shareCount: 3;
  shareIds: number[];
  derivationVersion: number;
  createdAtMs: number;
  updatedAtMs: number;
  source: SigningRootRecord['source'];
  contextHashB64u: string;
};

const SIGNING_ROOT_RECORD_KEY_PREFIX = 'threshold-prf:signing-root-record:';
const SIGNING_ROOT_SECRET_SHARE_KEY_PREFIX = 'threshold-prf:signing-root-secret:';

function json(body: unknown, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    status: init?.status ?? 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...(init?.headers || {}),
    },
  });
}

function ok<T>(value: T): DoOk<T> {
  return { ok: true, value };
}

function err(code: string, message: string): DoErr {
  return { ok: false, code, message };
}

function isDoErr(input: unknown): input is DoErr {
  return isPlainObject(input) && input.ok === false;
}

function toKey(input: unknown): string {
  const k = typeof input === 'string' ? input.trim() : '';
  return k;
}

function toTtlSeconds(ttlMs: unknown): number | null {
  if (ttlMs === undefined || ttlMs === null) return null;
  const n = Number(ttlMs);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.max(1, Math.ceil(n / 1000));
}

function jsonValueContains(actual: unknown, expected: unknown): boolean {
  if (Array.isArray(expected)) {
    return (
      Array.isArray(actual) &&
      actual.length === expected.length &&
      expected.every((value, index) => jsonValueContains(actual[index], value))
    );
  }
  if (isPlainObject(expected)) {
    if (!isPlainObject(actual)) return false;
    return Object.entries(expected).every(([key, value]) =>
      jsonValueContains((actual as Record<string, unknown>)[key], value),
    );
  }
  return Object.is(actual, expected);
}

function stableStoreVersion(value: unknown): string {
  return JSON.stringify(value);
}

function signingRootRecordKey(input: {
  readonly signingRootId: string;
  readonly signingRootVersion: string;
}): string {
  return `${SIGNING_ROOT_RECORD_KEY_PREFIX}${input.signingRootId}\0${input.signingRootVersion}`;
}

function signingRootSecretShareIndexKey(input: {
  readonly signingRootId: string;
  readonly signingRootVersion: string;
}): string {
  return `${SIGNING_ROOT_SECRET_SHARE_KEY_PREFIX}idx:${input.signingRootId}\0${input.signingRootVersion}`;
}

function signingRootSecretShareRecordKey(input: {
  readonly signingRootId: string;
  readonly signingRootVersion: string;
  readonly shareId: 1 | 2 | 3;
}): string {
  return `${SIGNING_ROOT_SECRET_SHARE_KEY_PREFIX}rec:${input.signingRootId}\0${input.signingRootVersion}\0${input.shareId}`;
}

function toSigningRootWireRecord(record: SigningRootRecord): SigningRootWireRecord {
  return {
    version: record.version,
    projectId: record.projectId,
    envId: record.envId,
    signingRootId: record.signingRootId,
    walletOrigin: record.walletOrigin,
    authorityScope: record.authorityScope,
    signingRootVersion: record.signingRootVersion,
    rootShareEpoch: record.rootShareEpoch,
    shareThreshold: record.shareThreshold,
    shareCount: record.shareCount,
    sealedSigningRootSecretShares: record.sealedSigningRootSecretShares.map((share) => ({
      signingRootId: share.signingRootId,
      signingRootVersion: share.signingRootVersion || record.signingRootVersion,
      shareId: share.shareId,
      sealedShareB64u: base64UrlEncode(share.sealedShare),
      ...(share.storageId ? { storageId: share.storageId } : {}),
      ...(share.kekId ? { kekId: share.kekId } : {}),
    })),
    derivationVersion: record.derivationVersion,
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
    source: record.source,
  };
}

async function signingRootStatus(record: SigningRootRecord): Promise<SigningRootStatus> {
  return {
    projectId: record.projectId,
    envId: record.envId,
    signingRootId: record.signingRootId,
    walletOrigin: record.walletOrigin,
    authorityScope: record.authorityScope,
    signingRootVersion: record.signingRootVersion,
    rootShareEpoch: record.rootShareEpoch,
    shareThreshold: record.shareThreshold,
    shareCount: record.shareCount,
    shareIds: record.sealedSigningRootSecretShares.map((share) => share.shareId).sort(),
    derivationVersion: record.derivationVersion,
    createdAtMs: record.createdAtMs,
    updatedAtMs: record.updatedAtMs,
    source: record.source,
    contextHashB64u: await computeSigningRootContextHashB64u(record),
  };
}

function parseSigningRootPutRecord(raw: unknown): SigningRootRecordResult<SigningRootRecord> {
  const record = parseSigningRootRecord(raw);
  if (record.ok) return record;
  return signingRootRecordFromMigrationBundle(raw);
}

async function readSigningRootRecord(
  store: DurableObjectStorageLike,
  input: { readonly signingRootId: string; readonly signingRootVersion: string },
): Promise<SigningRootRecord | null | DoErr> {
  const raw = await store.get(signingRootRecordKey(input));
  if (raw === null || raw === undefined) return null;
  const parsed = parseSigningRootRecord(raw);
  if (!parsed.ok) return err('corrupt_signing_root_record', parsed.message);
  return parsed.value;
}

async function writeSigningRootRecord(
  store: DurableObjectStorageLike,
  record: SigningRootRecord,
): Promise<void> {
  const wireRecord = toSigningRootWireRecord(record);
  const signingRootId = record.signingRootId;
  const signingRootVersion = record.signingRootVersion;

  await store.put(signingRootRecordKey({ signingRootId, signingRootVersion }), wireRecord);
  await store.put(
    signingRootSecretShareIndexKey({ signingRootId, signingRootVersion }),
    record.sealedSigningRootSecretShares.map((share) => share.shareId).sort(),
  );
  for (const share of record.sealedSigningRootSecretShares) {
    await store.put(
      signingRootSecretShareRecordKey({
        signingRootId,
        signingRootVersion,
        shareId: share.shareId,
      }),
      {
        signingRootId,
        signingRootVersionKey: signingRootVersion,
        shareId: share.shareId,
        sealedShareB64u: base64UrlEncode(share.sealedShare),
        ...(share.storageId ? { storageId: share.storageId } : {}),
        ...(share.kekId ? { kekId: share.kekId } : {}),
      },
    );
  }
}

async function deleteSigningRootRecord(
  store: DurableObjectStorageLike,
  input: { readonly signingRootId: string; readonly signingRootVersion: string },
): Promise<void> {
  await store.delete(signingRootRecordKey(input));
  await store.delete(signingRootSecretShareIndexKey(input));
  await Promise.all(
    ([1, 2, 3] as const).map((shareId) =>
      store.delete(signingRootSecretShareRecordKey({ ...input, shareId })),
    ),
  );
}

function parseAuthEntry(raw: unknown): AuthEntry | null {
  if (!isPlainObject(raw)) return null;
  const record = (raw as { record?: unknown }).record;
  const remainingUses = (raw as { remainingUses?: unknown }).remainingUses;
  const expiresAtMs = (raw as { expiresAtMs?: unknown }).expiresAtMs;
  if (!isPlainObject(record)) return null;
  if (typeof remainingUses !== 'number' || !Number.isFinite(remainingUses)) return null;
  if (typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs)) return null;
  // Minimal record shape check (full validation happens on the service layer).
  const rec = record as Record<string, unknown>;
  if (typeof rec.expiresAtMs !== 'number' || !Number.isFinite(rec.expiresAtMs)) return null;
  if (rec.participantIds !== undefined && !Array.isArray(rec.participantIds)) return null;
  const isCurveSession = typeof rec.relayerKeyId === 'string';
  const isWalletBudgetSession = parseWalletSigningBudgetSessionRecord(rec) !== null;
  if (!isCurveSession && !isWalletBudgetSession) return null;
  return raw as AuthEntry;
}

function normalizeBudgetField(value: unknown): string {
  return String(value || '').trim();
}

function normalizeBudgetToken(value: unknown): string {
  return normalizeBudgetField(value)
    .replace(/[^A-Za-z0-9._:-]/g, '_')
    .slice(0, 512);
}

function authBudgetOperationKey(input: {
  signingWorkerId: string;
  operationId: string;
  requestDigest: string;
}): string {
  return [
    'wallet-signing-budget',
    normalizeBudgetToken(input.signingWorkerId),
    normalizeBudgetToken(input.operationId),
    normalizeBudgetToken(input.requestDigest),
  ].join(':');
}

function createAuthBudgetReservationId(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return `wbudget_${base64UrlEncode(bytes)}`;
}

function parseFutureEpochMs(value: unknown, floorExclusiveMs: number): number | null {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed <= floorExclusiveMs) return null;
  return parsed;
}

function parseRouterAbNormalSigningQuotaReservation(
  raw: unknown,
): RouterAbNormalSigningQuotaReservation | null {
  if (!isPlainObject(raw)) return null;
  if (raw.kind !== 'router_ab_normal_signing_quota_reservation_v1') return null;
  const requestId = toKey(raw.requestId);
  const lifecycleId = toKey(raw.lifecycleId);
  const expiresAtMs = Number(raw.expiresAtMs);
  if (!requestId || !lifecycleId || !Number.isSafeInteger(expiresAtMs)) return null;
  return {
    kind: 'router_ab_normal_signing_quota_reservation_v1',
    requestId,
    lifecycleId,
    expiresAtMs,
  };
}

async function reserveRouterAbNormalSigningQuota(
  store: DurableObjectStorageLike,
  input: {
    readonly key: string;
    readonly requestId: string;
    readonly lifecycleId: string;
    readonly expiresAtMs: number;
    readonly nowMs: number;
  },
): Promise<DoResp<RouterAbNormalSigningQuotaDecision>> {
  const raw = await store.get(input.key);
  const existing = parseRouterAbNormalSigningQuotaReservation(raw);
  if (existing && existing.expiresAtMs > input.nowMs) {
    if (existing.requestId === input.requestId) {
      return ok({
        kind: 'reuse_existing',
        requestId: input.requestId,
        existingLifecycleId: existing.lifecycleId,
      });
    }
    return ok({ kind: 'short_window_saturated' });
  }
  if (raw !== null && raw !== undefined) {
    await store.delete(input.key);
  }

  const ttl = toTtlSeconds(input.expiresAtMs - input.nowMs);
  await store.put(
    input.key,
    {
      kind: 'router_ab_normal_signing_quota_reservation_v1',
      requestId: input.requestId,
      lifecycleId: input.lifecycleId,
      expiresAtMs: input.expiresAtMs,
    } satisfies RouterAbNormalSigningQuotaReservation,
    ttl ? { expirationTtl: ttl } : undefined,
  );
  return ok({ kind: 'accepted', requestId: input.requestId });
}

function authBudgetProjection(
  entry: AuthEntry,
  nowMs: number,
): {
  remainingUses: number;
  reservedUses: number;
  availableUses: number;
} {
  const reservations = entry.budgetReservations || {};
  let reservedUses = 0;
  Object.entries(reservations).forEach(([reservationId, reservation]) => {
    if (reservation.expiresAtMs <= nowMs) {
      delete reservations[reservationId];
      return;
    }
    reservedUses += reservation.signatureUses;
  });
  entry.budgetReservations = reservations;
  const remainingUses = Math.max(0, Math.floor(Number(entry.remainingUses) || 0));
  return {
    remainingUses,
    reservedUses,
    availableUses: Math.max(0, remainingUses - reservedUses),
  };
}

function authCommittedBudgetOperationExists(
  entry: AuthEntry,
  operationKey: string,
  nowMs: number,
): boolean {
  const committedReservations = entry.committedBudgetReservations || {};
  let found = false;
  Object.entries(committedReservations).forEach(([reservationId, committed]) => {
    if (committed.expiresAtMs <= nowMs) {
      delete committedReservations[reservationId];
      return;
    }
    if (committed.operationKey === operationKey) found = true;
  });
  entry.committedBudgetReservations = committedReservations;
  return found;
}

function parseAuthBudgetReserveInput(
  raw: unknown,
  sessionExpiresAtMs: number,
  nowMs: number,
): { ok: true; value: Omit<AuthBudgetReservation, 'reservationId' | 'operationKey'> } | DoErr {
  if (!isPlainObject(raw)) {
    return err('invalid_budget_request', 'budget reservation input must be an object');
  }
  const signingGrantId = normalizeBudgetField(raw.signingGrantId);
  const curve = raw.curve === 'ed25519' || raw.curve === 'ecdsa' ? raw.curve : null;
  const thresholdSessionId = normalizeBudgetField(raw.thresholdSessionId);
  const signingWorkerId = normalizeBudgetField(raw.signingWorkerId);
  const operationId = normalizeBudgetField(raw.operationId);
  const requestDigest = normalizeBudgetField(raw.requestDigest);
  const signatureUses = Math.floor(Number(raw.signatureUses));
  const expiresAtMs = Math.min(Number(raw.expiresAtMs), sessionExpiresAtMs);
  if (
    !signingGrantId ||
    !curve ||
    !thresholdSessionId ||
    !signingWorkerId ||
    !operationId ||
    !requestDigest ||
    !Number.isSafeInteger(signatureUses) ||
    signatureUses <= 0 ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= nowMs
  ) {
    return err(
      'invalid_budget_request',
      'budget reservation requires session, threshold session, operation, request digest, signature uses, and future expiry',
    );
  }
  return {
    ok: true,
    value: {
      kind: 'wallet_signing_budget_reservation_v1',
      signingGrantId,
      curve,
      thresholdSessionId,
      signingWorkerId,
      operationId,
      requestDigest,
      signatureUses,
      expiresAtMs: Math.floor(expiresAtMs),
    },
  };
}

function parseAuthBudgetCommitInput(raw: unknown):
  | {
      ok: true;
      value: {
        signingGrantId: string;
        reservationId: string;
        signingWorkerId: string;
        operationId: string;
        requestDigest: string;
      };
    }
  | DoErr {
  if (!isPlainObject(raw)) {
    return err('invalid_budget_request', 'budget commit input must be an object');
  }
  const signingGrantId = normalizeBudgetField(raw.signingGrantId);
  const reservationId = normalizeBudgetField(raw.reservationId);
  const signingWorkerId = normalizeBudgetField(raw.signingWorkerId);
  const operationId = normalizeBudgetField(raw.operationId);
  const requestDigest = normalizeBudgetField(raw.requestDigest);
  if (!signingGrantId || !reservationId || !signingWorkerId || !operationId || !requestDigest) {
    return err(
      'invalid_budget_request',
      'budget commit requires signing grant, reservation, SigningWorker, operation, and request digest',
    );
  }
  return {
    ok: true,
    value: { signingGrantId, reservationId, signingWorkerId, operationId, requestDigest },
  };
}

function parseAuthBudgetReleaseInput(
  raw: unknown,
): { ok: true; value: { signingGrantId: string; reservationId: string } } | DoErr {
  if (!isPlainObject(raw)) {
    return err('invalid_budget_request', 'budget release input must be an object');
  }
  const signingGrantId = normalizeBudgetField(raw.signingGrantId);
  const reservationId = normalizeBudgetField(raw.reservationId);
  if (!signingGrantId || !reservationId) {
    return err('invalid_budget_request', 'budget release requires signing grant and reservation');
  }
  return { ok: true, value: { signingGrantId, reservationId } };
}

function authBudgetReservationMismatch(): DoErr {
  return err(
    'wallet_budget_reservation_mismatch',
    'wallet signing budget reservation does not match this operation',
  );
}

function authBudgetOperationAlreadyCommitted(): DoErr {
  return err(
    'wallet_budget_reservation_mismatch',
    'wallet signing budget operation was already committed',
  );
}

function authBudgetReservationExpired(): DoErr {
  return err('wallet_budget_reservation_expired', 'wallet signing budget reservation expired');
}

function parseRouterAbEcdsaDerivationPoolFillSessionRecord(
  raw: unknown,
): RouterAbEcdsaDerivationPoolFillSessionRecord | null {
  return parseFullRouterAbEcdsaDerivationPoolFillSessionRecord(raw);
}

function parsePositiveInteger(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed < 1) return null;
  return parsed;
}

function parseStringArray(raw: unknown): string[] | null {
  if (!Array.isArray(raw)) return null;
  const out: string[] = [];
  for (const item of raw) {
    const value = toKey(item);
    if (!value) return null;
    out.push(value);
  }
  return out;
}

function parseRouterAbEcdsaDerivationPoolFillLiveSessionCreateInput(
  raw: unknown,
): RouterAbEcdsaDerivationPoolFillLiveSessionCreateInput | DoErr {
  if (!isPlainObject(raw)) {
    return err(
      'invalid_body',
      'Router A/B ECDSA derivation pool-fill live session create input must be an object',
    );
  }
  const presignSessionId = toKey(raw.presignSessionId);
  const record = parseRouterAbEcdsaDerivationPoolFillSessionRecord(raw.record);
  const relayerThresholdShare32B64u = toKey(raw.relayerThresholdShare32B64u);
  const groupPublicKey33B64u = toKey(raw.groupPublicKey33B64u);
  if (!presignSessionId || !record || !relayerThresholdShare32B64u || !groupPublicKey33B64u) {
    return err(
      'invalid_body',
      'Invalid Router A/B ECDSA derivation pool-fill live session create input',
    );
  }
  return {
    presignSessionId,
    record,
    relayerThresholdShare32B64u,
    groupPublicKey33B64u,
  };
}

function parseRouterAbEcdsaDerivationPoolFillLiveSessionStepInput(
  raw: unknown,
): RouterAbEcdsaDerivationPoolFillLiveSessionStepInput | DoErr {
  if (!isPlainObject(raw)) {
    return err(
      'invalid_body',
      'Router A/B ECDSA derivation pool-fill live session step input must be an object',
    );
  }
  const presignSessionId = toKey(raw.presignSessionId);
  const record = parseRouterAbEcdsaDerivationPoolFillSessionRecord(raw.record);
  const requestedStageRaw = toKey(raw.requestedStage);
  const requestedStage =
    requestedStageRaw === 'triples' || requestedStageRaw === 'presign' ? requestedStageRaw : null;
  const outgoingMessagesB64u = parseStringArray(raw.outgoingMessagesB64u);
  const thresholdExpiresAtMs = Number(raw.thresholdExpiresAtMs);
  if (
    !presignSessionId ||
    !record ||
    !requestedStage ||
    !outgoingMessagesB64u ||
    !Number.isFinite(thresholdExpiresAtMs)
  ) {
    return err(
      'invalid_body',
      'Invalid Router A/B ECDSA derivation pool-fill live session step input',
    );
  }
  return {
    presignSessionId,
    record,
    requestedStage,
    outgoingMessagesB64u,
    thresholdExpiresAtMs,
  };
}

async function withTxn<T>(
  state: DurableObjectStateLike,
  fn: (store: DurableObjectStorageLike) => Promise<T>,
): Promise<T> {
  if (typeof state.storage.transaction === 'function') {
    return await state.storage.transaction(fn);
  }
  // Fallback: best-effort single-threaded behavior; DO runtime should support transactions,
  // but don't hard-require it in the SDK.
  return await fn(state.storage);
}

async function withRequiredTxn<T>(
  state: DurableObjectStateLike,
  operation: (store: DurableObjectStorageLike) => Promise<T>,
): Promise<T> {
  if (typeof state.storage.transaction !== 'function') {
    throw new Error('Registration wallet lifecycle requires transactional Durable Object storage');
  }
  return await state.storage.transaction(operation);
}

type RegistrationWalletReservation = {
  readonly kind: 'registration_wallet_reservation_v1';
  readonly walletId: string;
  readonly expiresAtMs: number;
};

type RegistrationTerminalCancellationReservation =
  | {
      readonly kind: 'server_allocated_wallet';
      readonly key: string;
    }
  | {
      readonly kind: 'none';
    };

function parseRegistrationWalletReservation(raw: unknown): RegistrationWalletReservation | null {
  if (!isPlainObject(raw)) return null;
  const walletId = toKey(raw.walletId);
  const expiresAtMs = Math.floor(Number(raw.expiresAtMs));
  if (
    raw.kind !== 'registration_wallet_reservation_v1' ||
    !walletId ||
    !Number.isSafeInteger(expiresAtMs)
  ) {
    return null;
  }
  return {
    kind: 'registration_wallet_reservation_v1',
    walletId,
    expiresAtMs,
  };
}

function parseRegistrationTerminalCancellationReservation(
  raw: unknown,
): RegistrationTerminalCancellationReservation | null {
  if (!isPlainObject(raw)) return null;
  if (raw.kind === 'none') return { kind: 'none' };
  if (raw.kind !== 'server_allocated_wallet') return null;
  const key = toKey(raw.key);
  return key ? { kind: 'server_allocated_wallet', key } : null;
}

function registrationCeremonyIdentityMatches(input: {
  readonly raw: unknown;
  readonly registrationCeremonyId: string;
  readonly walletId: string;
}): boolean {
  if (!isPlainObject(input.raw)) return false;
  if (toKey(input.raw.registrationCeremonyId) !== input.registrationCeremonyId) return false;
  if (!isPlainObject(input.raw.intent)) return false;
  return toKey(input.raw.intent.walletId) === input.walletId;
}

export class ThresholdStoreDurableObject {
  private readonly state: DurableObjectStateLike;
  private readonly ecdsaPoolFillLiveSessions =
    new InMemoryRouterAbEcdsaDerivationPoolFillLiveSessionOwner();

  constructor(state: DurableObjectStateLike, _env: unknown) {
    this.state = state;
  }

  async fetch(request: Request): Promise<Response> {
    if (request.method.toUpperCase() !== 'POST') {
      return json(err('method_not_allowed', 'POST required'), { status: 405 });
    }

    let body: unknown;
    try {
      body = await request.json();
    } catch {
      body = null;
    }
    if (!isPlainObject(body)) return json(err('invalid_body', 'Expected JSON object'));
    const op = (body as { op?: unknown }).op;
    if (typeof op !== 'string') return json(err('invalid_body', 'Missing op'));

    const req = body as DoReq;
    if (op === 'get') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const value = await this.state.storage.get(key);
      return json(ok(value ?? null));
    }
    if (op === 'readVersioned') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const value = await this.state.storage.get(key);
      if (value === null || value === undefined) return json(ok(null));
      return json(ok({ value, version: stableStoreVersion(value) }));
    }
    if (op === 'set') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const ttl = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      await this.state.storage.put(
        key,
        (req as { value?: unknown }).value,
        ttl ? { expirationTtl: ttl } : undefined,
      );
      return json(ok(true));
    }
    if (op === 'claimVersioned') {
      const key = toKey((req as { key?: unknown }).key);
      const expectedVersion = toKey((req as { expectedVersion?: unknown }).expectedVersion);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!expectedVersion) return json(err('invalid_body', 'Missing expectedVersion'));
      const result = await withTxn(this.state, async (store) => {
        const value = await store.get(key);
        if (value === null || value === undefined) return { status: 'not_found' };
        const expiresAtMs =
          isPlainObject(value) && typeof value.expiresAtMs === 'number' ? value.expiresAtMs : NaN;
        if (Number.isFinite(expiresAtMs) && expiresAtMs <= Date.now()) {
          await store.delete(key);
          return { status: 'expired' };
        }
        if (stableStoreVersion(value) !== expectedVersion) return { status: 'version_mismatch' };
        await store.delete(key);
        return { status: 'ok', value };
      });
      return json(ok(result));
    }
    if (op === 'setWithIdentityGuard') {
      const key = toKey((req as { key?: unknown }).key);
      const identityKey = toKey((req as { identityKey?: unknown }).identityKey);
      const identityValue = toKey((req as { identityValue?: unknown }).identityValue);
      const keyHandleKey = toKey((req as { keyHandleKey?: unknown }).keyHandleKey);
      const keyHandleValue = toKey((req as { keyHandleValue?: unknown }).keyHandleValue);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!identityKey) return json(err('invalid_body', 'Missing identityKey'));
      if (!identityValue) return json(err('invalid_body', 'Missing identityValue'));
      if (!keyHandleKey) return json(err('invalid_body', 'Missing keyHandleKey'));
      if (!keyHandleValue) return json(err('invalid_body', 'Missing keyHandleValue'));
      const ttl = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      const result = await withTxn(this.state, async (store) => {
        const existing = await store.get(identityKey);
        if (existing !== null && existing !== undefined && existing !== identityValue) {
          return err('conflict', ECDSA_SHARED_IDENTITY_CONFLICT_MESSAGE);
        }
        const existingKeyHandle = await store.get(keyHandleKey);
        if (
          existingKeyHandle !== null &&
          existingKeyHandle !== undefined &&
          existingKeyHandle !== keyHandleValue
        ) {
          return err('conflict', ECDSA_KEY_HANDLE_CONFLICT_MESSAGE);
        }
        await store.put(
          key,
          (req as { value?: unknown }).value,
          ttl ? { expirationTtl: ttl } : undefined,
        );
        await store.put(identityKey, identityValue);
        await store.put(keyHandleKey, keyHandleValue);
        return ok(true);
      });
      return json(result);
    }
    if (op === 'del') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const deleted = await this.state.storage.delete(key);
      return json(ok(deleted));
    }
    if (op === 'delWithIdentityGuard') {
      const key = toKey((req as { key?: unknown }).key);
      const identityKey = toKey((req as { identityKey?: unknown }).identityKey);
      const identityValue = toKey((req as { identityValue?: unknown }).identityValue);
      const keyHandleKey = toKey((req as { keyHandleKey?: unknown }).keyHandleKey);
      const keyHandleValue = toKey((req as { keyHandleValue?: unknown }).keyHandleValue);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!identityKey) return json(err('invalid_body', 'Missing identityKey'));
      if (!identityValue) return json(err('invalid_body', 'Missing identityValue'));
      if (!keyHandleKey) return json(err('invalid_body', 'Missing keyHandleKey'));
      if (!keyHandleValue) return json(err('invalid_body', 'Missing keyHandleValue'));
      await withTxn(this.state, async (store) => {
        await store.delete(key);
        if ((await store.get(identityKey)) === identityValue) {
          await store.delete(identityKey);
        }
        if ((await store.get(keyHandleKey)) === keyHandleValue) {
          await store.delete(keyHandleKey);
        }
      });
      return json(ok(true));
    }
    if (op === 'getdel') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const value = await withTxn(this.state, async (store) => {
        const v = await store.get(key);
        await store.delete(key);
        return v ?? null;
      });
      return json(ok(value));
    }
    if (op === 'getdelIfRelatedMatches') {
      const key = toKey((req as { key?: unknown }).key);
      const relatedKey = toKey((req as { relatedKey?: unknown }).relatedKey);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!relatedKey) return json(err('invalid_body', 'Missing relatedKey'));
      const expectedRelated = (req as { expectedRelated?: unknown }).expectedRelated;
      const value = await withTxn(this.state, async (store) => {
        const related = await store.get(relatedKey);
        if (!jsonValueContains(related, expectedRelated)) {
          return {
            matched: false,
            value: null,
          };
        }
        const v = await store.get(key);
        await store.delete(key);
        return {
          matched: true,
          value: v ?? null,
        };
      });
      return json(ok(value));
    }

    if (op === 'registrationReserveWalletId') {
      const key = toKey((req as { key?: unknown }).key);
      const walletId = toKey((req as { walletId?: unknown }).walletId);
      const expiresAtMs = Math.floor(Number((req as { expiresAtMs?: unknown }).expiresAtMs));
      if (!key) return json(err('invalid_body', 'Missing registration wallet reservation key'));
      if (!walletId) return json(err('invalid_body', 'Missing registration walletId'));
      if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= Date.now()) {
        return json(err('invalid_body', 'Invalid registration wallet reservation expiry'));
      }
      const result = await withRequiredTxn(this.state, async (store) => {
        const existingRaw = await store.get(key);
        if (existingRaw !== null && existingRaw !== undefined) {
          const existing = parseRegistrationWalletReservation(existingRaw);
          if (!existing) {
            return err(
              'registration_wallet_reservation_corrupt',
              'Registration wallet reservation has an invalid stored shape',
            );
          }
          if (existing.expiresAtMs > Date.now()) {
            return err('wallet_id_reserved', 'walletId is already reserved');
          }
          await store.delete(key);
        }
        const reservation: RegistrationWalletReservation = {
          kind: 'registration_wallet_reservation_v1',
          walletId,
          expiresAtMs,
        };
        const ttlSeconds = Math.max(1, Math.ceil((expiresAtMs - Date.now()) / 1000));
        await store.put(key, reservation, { expirationTtl: ttlSeconds });
        return ok({ reserved: true });
      });
      return json(result);
    }

    if (op === 'registrationCancelTerminal') {
      const ceremonyKey = toKey((req as { ceremonyKey?: unknown }).ceremonyKey);
      const registrationCeremonyId = toKey(
        (req as { registrationCeremonyId?: unknown }).registrationCeremonyId,
      );
      const walletId = toKey((req as { walletId?: unknown }).walletId);
      const reservation = parseRegistrationTerminalCancellationReservation(
        (req as { reservation?: unknown }).reservation,
      );
      if (!ceremonyKey) {
        return json(err('invalid_body', 'Missing terminal registration ceremony key'));
      }
      if (!registrationCeremonyId) {
        return json(err('invalid_body', 'Missing terminal registration ceremony ID'));
      }
      if (!walletId) return json(err('invalid_body', 'Missing terminal registration walletId'));
      if (!reservation) {
        return json(err('invalid_body', 'Invalid terminal registration reservation'));
      }
      const result = await withRequiredTxn(this.state, async (store) => {
        const ceremony = await store.get(ceremonyKey);
        if (ceremony === null || ceremony === undefined) {
          return ok({
            kind: 'not_found',
            ceremonyDeleted: false,
            walletReservationReleased: false,
          });
        }
        if (
          !registrationCeremonyIdentityMatches({
            raw: ceremony,
            registrationCeremonyId,
            walletId,
          })
        ) {
          return err(
            'registration_ceremony_identity_mismatch',
            'Terminal registration cancellation does not match the stored ceremony',
          );
        }
        let reservationExists = false;
        if (reservation.kind === 'server_allocated_wallet') {
          const reservationRaw = await store.get(reservation.key);
          if (reservationRaw !== null && reservationRaw !== undefined) {
            const storedReservation = parseRegistrationWalletReservation(reservationRaw);
            if (!storedReservation) {
              return err(
                'registration_wallet_reservation_corrupt',
                'Registration wallet reservation has an invalid stored shape',
              );
            }
            if (storedReservation.walletId !== walletId) {
              return err(
                'registration_wallet_reservation_identity_mismatch',
                'Terminal registration cancellation does not match the wallet reservation',
              );
            }
            reservationExists = true;
          }
        }
        await store.delete(ceremonyKey);
        const walletReservationReleased =
          reservation.kind === 'server_allocated_wallet' && reservationExists
            ? await store.delete(reservation.key)
            : false;
        return ok({
          kind: 'cancelled',
          ceremonyDeleted: true,
          walletReservationReleased,
        });
      });
      return json(result);
    }

    if (op === 'routerAbNormalSigningReserveQuota') {
      const key = toKey((req as { key?: unknown }).key);
      const requestId = toKey((req as { requestId?: unknown }).requestId);
      const lifecycleId = toKey((req as { lifecycleId?: unknown }).lifecycleId);
      const nowMs = Math.floor(Number((req as { nowMs?: unknown }).nowMs));
      const expiresAtMs = parseFutureEpochMs((req as { expiresAtMs?: unknown }).expiresAtMs, nowMs);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!requestId) return json(err('invalid_body', 'Missing requestId'));
      if (!lifecycleId) return json(err('invalid_body', 'Missing lifecycleId'));
      if (!Number.isSafeInteger(nowMs)) return json(err('invalid_body', 'Invalid nowMs'));
      if (expiresAtMs === null) return json(err('invalid_body', 'Invalid expiresAtMs'));

      const result = await withTxn(this.state, (store) =>
        reserveRouterAbNormalSigningQuota(store, {
          key,
          requestId,
          lifecycleId,
          expiresAtMs,
          nowMs,
        }),
      );
      return json(result);
    }

    if (op === 'signingRootPut') {
      const parsed = parseSigningRootPutRecord((req as { record?: unknown }).record);
      if (!parsed.ok) return json(err(parsed.code, parsed.message));

      const result = await withTxn(this.state, async (store) => {
        await writeSigningRootRecord(store, parsed.value);
        return await signingRootStatus(parsed.value);
      });

      return json(ok(result));
    }

    if (op === 'signingRootGet') {
      const signingRootId = toKey((req as { signingRootId?: unknown }).signingRootId);
      const signingRootVersion = toKey(
        (req as { signingRootVersion?: unknown }).signingRootVersion,
      );
      if (!signingRootId) return json(err('invalid_body', 'Missing signingRootId'));
      if (!signingRootVersion) return json(err('invalid_body', 'Missing signingRootVersion'));

      const result: DoResp<SigningRootWireRecord | null> = await withTxn(
        this.state,
        async (store) => {
          const record = await readSigningRootRecord(store, { signingRootId, signingRootVersion });
          if (record === null) return ok(null);
          if (isDoErr(record)) return record;
          return ok(toSigningRootWireRecord(record));
        },
      );

      return json(result);
    }

    if (op === 'signingRootStatus') {
      const signingRootId = toKey((req as { signingRootId?: unknown }).signingRootId);
      const signingRootVersion = toKey(
        (req as { signingRootVersion?: unknown }).signingRootVersion,
      );
      if (!signingRootId) return json(err('invalid_body', 'Missing signingRootId'));
      if (!signingRootVersion) return json(err('invalid_body', 'Missing signingRootVersion'));

      const result: DoResp<SigningRootStatus | null> = await withTxn(this.state, async (store) => {
        const record = await readSigningRootRecord(store, { signingRootId, signingRootVersion });
        if (record === null) return ok(null);
        if (isDoErr(record)) return record;
        return ok(await signingRootStatus(record));
      });

      return json(result);
    }

    if (op === 'signingRootDelete') {
      const signingRootId = toKey((req as { signingRootId?: unknown }).signingRootId);
      const signingRootVersion = toKey(
        (req as { signingRootVersion?: unknown }).signingRootVersion,
      );
      if (!signingRootId) return json(err('invalid_body', 'Missing signingRootId'));
      if (!signingRootVersion) return json(err('invalid_body', 'Missing signingRootVersion'));

      await withTxn(this.state, (store) =>
        deleteSigningRootRecord(store, { signingRootId, signingRootVersion }),
      );

      return json(ok({ deleted: true }));
    }

    if (op === 'authConsumeUseCount') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        if (Date.now() > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }
        const projection = authBudgetProjection(entry, Date.now());
        if (projection.availableUses <= 0) {
          if (projection.remainingUses > 0 && projection.reservedUses > 0) {
            return err(
              'wallet_budget_in_flight',
              'signing grant budget is reserved by another signing operation',
            );
          }
          return err('wallet_budget_exhausted', 'signing grant exhausted');
        }

        entry.remainingUses -= 1;
        authBudgetProjection(entry, Date.now());
        const ttlSeconds = Math.max(
          1,
          Math.ceil(Math.max(0, entry.expiresAtMs - Date.now()) / 1000),
        );
        await store.put(key, entry, { expirationTtl: ttlSeconds });

        return ok({ remainingUses: entry.remainingUses });
      });

      return json(res);
    }

    if (op === 'authConsumeUseCountOnce') {
      const key = toKey((req as { key?: unknown }).key);
      const idempotencyKey = toKey((req as { idempotencyKey?: unknown }).idempotencyKey);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!idempotencyKey) return json(err('invalid_body', 'Missing idempotencyKey'));

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        if (Date.now() > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }

        const consumedIdempotencyKeys = entry.consumedIdempotencyKeys || {};
        if (consumedIdempotencyKeys[idempotencyKey]) {
          return ok({ remainingUses: entry.remainingUses });
        }

        const projection = authBudgetProjection(entry, Date.now());
        if (projection.availableUses <= 0) {
          if (projection.remainingUses > 0 && projection.reservedUses > 0) {
            return err(
              'wallet_budget_in_flight',
              'signing grant budget is reserved by another signing operation',
            );
          }
          return err('wallet_budget_exhausted', 'signing grant exhausted');
        }

        entry.remainingUses -= 1;
        entry.consumedIdempotencyKeys = {
          ...consumedIdempotencyKeys,
          [idempotencyKey]: true,
        };
        authBudgetProjection(entry, Date.now());
        const ttlSeconds = Math.max(
          1,
          Math.ceil(Math.max(0, entry.expiresAtMs - Date.now()) / 1000),
        );
        await store.put(key, entry, { expirationTtl: ttlSeconds });

        return ok({ remainingUses: entry.remainingUses });
      });

      return json(res);
    }

    if (op === 'authHasConsumedUseCountOnce') {
      const key = toKey((req as { key?: unknown }).key);
      const idempotencyKey = toKey((req as { idempotencyKey?: unknown }).idempotencyKey);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!idempotencyKey) return json(err('invalid_body', 'Missing idempotencyKey'));

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        if (Date.now() > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }

        const consumedIdempotencyKeys = entry.consumedIdempotencyKeys || {};
        return ok({ consumed: consumedIdempotencyKeys[idempotencyKey] === true });
      });

      return json(res);
    }

    if (op === 'authGetBudgetStatus') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));

      const res: DoResp<unknown | null> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return ok(null);

        const nowMs = Date.now();
        if (nowMs > entry.expiresAtMs) {
          await store.delete(key);
          return ok(null);
        }
        const projection = authBudgetProjection(entry, nowMs);
        const ttlSeconds = Math.max(1, Math.ceil((entry.expiresAtMs - nowMs) / 1000));
        await store.put(key, entry, { expirationTtl: ttlSeconds });
        return ok({
          record: entry.record,
          expiresAtMs: entry.expiresAtMs,
          remainingUses: projection.remainingUses,
          reservedUses: projection.reservedUses,
          availableUses: projection.availableUses,
        });
      });

      return json(res);
    }

    if (op === 'authReserveBudgetUseCount') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const input = (req as { input?: unknown }).input;

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        const nowMs = Date.now();
        if (nowMs > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }
        const parsed = parseAuthBudgetReserveInput(input, entry.expiresAtMs, nowMs);
        if (!parsed.ok) return parsed;
        const operationKey = authBudgetOperationKey(parsed.value);
        const reservations = entry.budgetReservations || {};
        const existing = Object.values(reservations).find(
          (reservation) =>
            reservation.operationKey === operationKey && reservation.expiresAtMs > nowMs,
        );
        if (existing) {
          const projection = authBudgetProjection(entry, nowMs);
          return ok({
            reservation: existing,
            remainingUses: projection.remainingUses,
            reservedUses: projection.reservedUses,
            availableUses: projection.availableUses,
          });
        }
        if (authCommittedBudgetOperationExists(entry, operationKey, nowMs)) {
          return authBudgetOperationAlreadyCommitted();
        }
        const projection = authBudgetProjection(entry, nowMs);
        if (projection.availableUses < parsed.value.signatureUses) {
          if (
            projection.remainingUses >= parsed.value.signatureUses &&
            projection.reservedUses > 0
          ) {
            return err(
              'wallet_budget_in_flight',
              'signing grant budget is reserved by another signing operation',
            );
          }
          return err('wallet_budget_exhausted', 'signing grant exhausted');
        }
        const reservation: AuthBudgetReservation = {
          ...parsed.value,
          reservationId: createAuthBudgetReservationId(),
          operationKey,
        };
        reservations[reservation.reservationId] = reservation;
        entry.budgetReservations = reservations;
        const nextProjection = authBudgetProjection(entry, nowMs);
        const ttlSeconds = Math.max(1, Math.ceil((entry.expiresAtMs - nowMs) / 1000));
        await store.put(key, entry, { expirationTtl: ttlSeconds });
        return ok({
          reservation,
          remainingUses: nextProjection.remainingUses,
          reservedUses: nextProjection.reservedUses,
          availableUses: nextProjection.availableUses,
        });
      });

      return json(res);
    }

    if (op === 'authCommitReservedBudgetUseCount') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const input = (req as { input?: unknown }).input;

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        const nowMs = Date.now();
        if (nowMs > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }
        const parsed = parseAuthBudgetCommitInput(input);
        if (!parsed.ok) return parsed;
        const operationKey = authBudgetOperationKey(parsed.value);
        const committed = entry.committedBudgetReservations?.[parsed.value.reservationId];
        if (committed) {
          if (
            committed.operationKey !== operationKey ||
            committed.signingWorkerId !== parsed.value.signingWorkerId ||
            committed.operationId !== parsed.value.operationId ||
            committed.requestDigest !== parsed.value.requestDigest
          ) {
            return authBudgetReservationMismatch();
          }
          return ok({ remainingUses: committed.remainingUses });
        }
        const reservation = entry.budgetReservations?.[parsed.value.reservationId];
        if (!reservation) return authBudgetReservationExpired();
        if (
          reservation.operationId !== parsed.value.operationId ||
          reservation.signingWorkerId !== parsed.value.signingWorkerId ||
          reservation.requestDigest !== parsed.value.requestDigest
        ) {
          return authBudgetReservationMismatch();
        }
        if (reservation.expiresAtMs <= nowMs) {
          delete entry.budgetReservations?.[parsed.value.reservationId];
          return authBudgetReservationExpired();
        }
        if (entry.remainingUses < reservation.signatureUses) {
          return err('wallet_budget_exhausted', 'signing grant exhausted');
        }
        entry.remainingUses -= reservation.signatureUses;
        delete entry.budgetReservations?.[parsed.value.reservationId];
        entry.committedBudgetReservations = {
          ...(entry.committedBudgetReservations || {}),
          [parsed.value.reservationId]: {
            operationKey,
            signingWorkerId: parsed.value.signingWorkerId,
            operationId: parsed.value.operationId,
            requestDigest: parsed.value.requestDigest,
            remainingUses: entry.remainingUses,
            expiresAtMs: entry.expiresAtMs,
          },
        };
        authBudgetProjection(entry, nowMs);
        const ttlSeconds = Math.max(1, Math.ceil((entry.expiresAtMs - nowMs) / 1000));
        await store.put(key, entry, { expirationTtl: ttlSeconds });
        return ok({ remainingUses: entry.remainingUses });
      });

      return json(res);
    }

    if (op === 'authValidateReservedBudgetUseCount') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const input = (req as { input?: unknown }).input;

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        const nowMs = Date.now();
        if (nowMs > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }
        const parsed = parseAuthBudgetCommitInput(input);
        if (!parsed.ok) return parsed;
        const operationKey = authBudgetOperationKey(parsed.value);
        const committed = entry.committedBudgetReservations?.[parsed.value.reservationId];
        if (committed) {
          if (
            committed.operationKey !== operationKey ||
            committed.signingWorkerId !== parsed.value.signingWorkerId ||
            committed.operationId !== parsed.value.operationId ||
            committed.requestDigest !== parsed.value.requestDigest
          ) {
            return authBudgetReservationMismatch();
          }
          return ok({ remainingUses: committed.remainingUses });
        }
        const reservation = entry.budgetReservations?.[parsed.value.reservationId];
        if (!reservation) return authBudgetReservationExpired();
        if (
          reservation.operationId !== parsed.value.operationId ||
          reservation.signingWorkerId !== parsed.value.signingWorkerId ||
          reservation.requestDigest !== parsed.value.requestDigest
        ) {
          return authBudgetReservationMismatch();
        }
        if (reservation.expiresAtMs <= nowMs) return authBudgetReservationExpired();
        if (entry.remainingUses < reservation.signatureUses) {
          return err('wallet_budget_exhausted', 'signing grant exhausted');
        }
        return ok({ remainingUses: entry.remainingUses });
      });

      return json(res);
    }

    if (op === 'authReleaseReservedBudgetUseCount') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const input = (req as { input?: unknown }).input;

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        const nowMs = Date.now();
        if (nowMs > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }
        const parsed = parseAuthBudgetReleaseInput(input);
        if (!parsed.ok) return parsed;
        const released = !!entry.budgetReservations?.[parsed.value.reservationId];
        delete entry.budgetReservations?.[parsed.value.reservationId];
        const projection = authBudgetProjection(entry, nowMs);
        const ttlSeconds = Math.max(1, Math.ceil((entry.expiresAtMs - nowMs) / 1000));
        await store.put(key, entry, { expirationTtl: ttlSeconds });
        return ok({ released, ...projection });
      });

      return json(res);
    }

    if (op === 'authReleaseReservedBudgetUseCountForIdentity') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const input = (req as { input?: unknown }).input;

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        const nowMs = Date.now();
        if (nowMs > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }
        const parsed = parseAuthBudgetCommitInput(input);
        if (!parsed.ok) return parsed;
        const reservation = entry.budgetReservations?.[parsed.value.reservationId];
        const released =
          !!reservation &&
          reservation.operationId === parsed.value.operationId &&
          reservation.signingWorkerId === parsed.value.signingWorkerId &&
          reservation.requestDigest === parsed.value.requestDigest;
        if (released) {
          delete entry.budgetReservations?.[parsed.value.reservationId];
        }
        const projection = authBudgetProjection(entry, nowMs);
        const ttlSeconds = Math.max(1, Math.ceil((entry.expiresAtMs - nowMs) / 1000));
        await store.put(key, entry, { expirationTtl: ttlSeconds });
        return ok({ released, ...projection });
      });

      return json(res);
    }

    if (op === 'authReserveReplayGuard') {
      const key = toKey((req as { key?: unknown }).key);
      const expiresAtMs = Number((req as { expiresAtMs?: unknown }).expiresAtMs);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!Number.isFinite(expiresAtMs)) {
        return json(err('invalid_body', 'Invalid expiresAtMs'));
      }

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        if (expiresAtMs <= nowMs) {
          return err('export_authorization_expired', 'Export authorization expired');
        }
        const raw = await store.get(key);
        const existingExpiresAtMs =
          raw && typeof raw === 'object' && 'expiresAtMs' in raw
            ? Number((raw as { expiresAtMs?: unknown }).expiresAtMs)
            : NaN;
        if (Number.isFinite(existingExpiresAtMs) && existingExpiresAtMs > nowMs) {
          return err('export_nonce_replay', 'Export authorization nonce already used');
        }
        const retainedUntilMs = Math.max(
          nowMs + EXPORT_REPLAY_GUARD_MIN_RETENTION_MS,
          expiresAtMs + EXPORT_REPLAY_GUARD_CLOCK_SKEW_MS,
        );
        const ttlSeconds = Math.max(1, Math.ceil((retainedUntilMs - nowMs) / 1000));
        await store.put(key, { expiresAtMs: retainedUntilMs }, { expirationTtl: ttlSeconds });
        return ok({ reserved: true });
      });

      return json(res);
    }

    if (op === 'routerAbEcdsaDerivationPoolFillSessionCreate') {
      const key = toKey((req as { key?: unknown }).key);
      const value = (req as { value?: unknown }).value;
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!parseRouterAbEcdsaDerivationPoolFillSessionRecord(value))
        return json(
          err('invalid_body', 'Invalid Router A/B ECDSA derivation pool-fill session record'),
        );

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const existingRaw = await store.get(key);
        if (existingRaw !== null && existingRaw !== undefined) {
          const existing = parseRouterAbEcdsaDerivationPoolFillSessionRecord(existingRaw);
          if (!existing || existing.expiresAtMs > nowMs) {
            return { status: 'exists' };
          }
        }
        await store.put(key, value, ttlSeconds ? { expirationTtl: ttlSeconds } : undefined);
        return { status: 'ok' };
      });

      return json(ok(result));
    }

    if (op === 'routerAbEcdsaDerivationPoolFillSessionAdvanceCas') {
      const key = toKey((req as { key?: unknown }).key);
      const expectedVersionRaw = (req as { expectedVersion?: unknown }).expectedVersion;
      const value = (req as { value?: unknown }).value;
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const expectedVersion = Math.floor(Number(expectedVersionRaw));
      if (!Number.isFinite(expectedVersion) || expectedVersion < 1) {
        return json(err('invalid_body', 'Invalid expectedVersion'));
      }
      const nextRecord = parseRouterAbEcdsaDerivationPoolFillSessionRecord(value);
      if (!nextRecord)
        return json(
          err('invalid_body', 'Invalid Router A/B ECDSA derivation pool-fill session record'),
        );

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const existingRaw = await store.get(key);
        if (existingRaw === null || existingRaw === undefined) return { status: 'not_found' };
        const existing = parseRouterAbEcdsaDerivationPoolFillSessionRecord(existingRaw);
        if (!existing) return { status: 'not_found' };
        if (existing.expiresAtMs <= nowMs) {
          await store.delete(key);
          return { status: 'expired' };
        }
        if (existing.version !== expectedVersion) return { status: 'version_mismatch' };
        await store.put(key, value, ttlSeconds ? { expirationTtl: ttlSeconds } : undefined);
        return { status: 'ok', record: value };
      });

      return json(ok(result));
    }

    if (op === 'routerAbEcdsaDerivationPoolFillLiveSessionCreate') {
      const parsed = parseRouterAbEcdsaDerivationPoolFillLiveSessionCreateInput(
        (req as { input?: unknown }).input,
      );
      if (isDoErr(parsed)) return json(parsed);
      const result = await this.ecdsaPoolFillLiveSessions.createSession(parsed);
      return json(ok(result));
    }

    if (op === 'routerAbEcdsaDerivationPoolFillLiveSessionStep') {
      const parsed = parseRouterAbEcdsaDerivationPoolFillLiveSessionStepInput(
        (req as { input?: unknown }).input,
      );
      if (isDoErr(parsed)) return json(parsed);
      const result = await this.ecdsaPoolFillLiveSessions.stepSession(parsed);
      return json(ok(result));
    }

    if (op === 'routerAbEcdsaDerivationPoolFillLiveSessionDelete') {
      const presignSessionId = toKey((req as { presignSessionId?: unknown }).presignSessionId);
      if (!presignSessionId) return json(err('invalid_body', 'Missing presignSessionId'));
      await this.ecdsaPoolFillLiveSessions.deleteSession(presignSessionId);
      return json(ok(null));
    }

    return json(err('invalid_body', `Unknown op: ${op}`));
  }
}
