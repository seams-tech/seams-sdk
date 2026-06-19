import type { NormalizedLogger } from '../../logger';
import type { ThresholdEcdsaSigningRootMetadata, ThresholdStoreConfigInput } from '../../types';
import { RedisTcpClient, UpstashRedisRestClient, redisGetJson, redisSetJson } from '../kv';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  getPostgresPool,
  getPostgresUrlFromConfig,
  parsePostgresRow,
} from '../../../storage/postgres';
import {
  parseCurrentThresholdEd25519SessionRecord,
  parseCurrentThresholdEd25519SessionStatusRow,
} from '../postgresRecords';
import {
  isObject,
  toThresholdEcdsaWalletSessionPrefix,
  toThresholdEcdsaPrefixFromBase,
  toThresholdEd25519WalletSessionPrefix,
  toThresholdEd25519PrefixFromBase,
  parseEd25519WalletSessionRecord,
} from '../validation';
import {
  createCloudflareDurableObjectThresholdEcdsaStores,
  createCloudflareDurableObjectThresholdEd25519Stores,
} from './CloudflareDurableObjectStore';
import { secureRandomIdFragment } from '../secureRandomId';

export type WalletSigningBudgetBinding = {
  curve: 'ed25519' | 'ecdsa';
  thresholdSessionId: string;
};

export type Ed25519WalletSessionRecord = {
  expiresAtMs: number;
  relayerKeyId: string;
  userId: string;
  rpId: string;
  participantIds: number[];
  walletBudgetBinding?: WalletSigningBudgetBinding;
} & Partial<ThresholdEcdsaSigningRootMetadata>;

export type WalletSessionConsumeUsesResult =
  | { ok: true; remainingUses: number }
  | { ok: false; code: string; message: string };

export type WalletSessionBudgetCurve = 'ed25519' | 'ecdsa';

export type WalletSigningBudgetReservation = {
  kind: 'wallet_signing_budget_reservation_v1';
  walletSigningSessionId: string;
  curve: WalletSessionBudgetCurve;
  thresholdSessionId: string;
  operationId: string;
  requestDigest: string;
  signatureUses: number;
  reservationId: string;
  expiresAtMs: number;
};

export type WalletSessionBudgetReserveUseCountInput = {
  walletSigningSessionId: string;
  curve: WalletSessionBudgetCurve;
  thresholdSessionId: string;
  operationId: string;
  requestDigest: string;
  signatureUses: number;
  expiresAtMs: number;
};

export type WalletSessionBudgetCommitReservedUseCountInput = {
  walletSigningSessionId: string;
  reservationId: string;
  operationId: string;
  requestDigest: string;
};

export type WalletSessionBudgetReleaseReservedUseCountInput = {
  walletSigningSessionId: string;
  reservationId: string;
};

export type WalletSessionBudgetReservationResult =
  | {
      ok: true;
      reservation: WalletSigningBudgetReservation;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }
  | { ok: false; code: string; message: string };

export type WalletSessionBudgetReleaseResult =
  | {
      ok: true;
      released: boolean;
      remainingUses: number;
      reservedUses: number;
      availableUses: number;
    }
  | { ok: false; code: string; message: string };

export type WalletSessionConsumedUseResult =
  | { ok: true; consumed: boolean }
  | { ok: false; code: string; message: string };

export type WalletSessionReplayGuardResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

export type Ed25519WalletSessionStatus = {
  record: Ed25519WalletSessionRecord;
  expiresAtMs: number;
  committedRemainingUses: number;
  reservedUses: number;
  availableUses: number;
  remainingUses: number;
};

const EXPORT_REPLAY_GUARD_CLOCK_SKEW_MS = 5 * 60_000;
const EXPORT_REPLAY_GUARD_MIN_RETENTION_MS = 24 * 60 * 60_000;

export interface Ed25519WalletSessionStore {
  putSession(
    id: string,
    record: Ed25519WalletSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void>;
  getSession(id: string): Promise<Ed25519WalletSessionRecord | null>;
  getSessionStatus(id: string): Promise<Ed25519WalletSessionStatus | null>;
  /**
   * Consume one use from the session counter without fetching the session record.
   *
   * This enables session-token-only authorization flows where scope/expiry are enforced from
   * signed JWT claims instead of a KV-stored record, reducing KV read-after-write consistency issues.
   */
  consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult>;
  consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumeUsesResult>;
  reserveUseCountOnce(
    input: WalletSessionBudgetReserveUseCountInput,
  ): Promise<WalletSessionBudgetReservationResult>;
  commitReservedUseCountOnce(
    input: WalletSessionBudgetCommitReservedUseCountInput,
  ): Promise<WalletSessionConsumeUsesResult>;
  releaseReservedUseCount(
    input: WalletSessionBudgetReleaseReservedUseCountInput,
  ): Promise<WalletSessionBudgetReleaseResult>;
  hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult>;
  reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult>;
}

class InMemoryEd25519WalletSessionStore implements Ed25519WalletSessionStore {
  private readonly keyPrefix: string;
  private readonly map = new Map<
    string,
    {
      record: Ed25519WalletSessionRecord;
      remainingUses: number;
      expiresAtMs: number;
      consumedIdempotencyKeys: Set<string>;
      budgetReservations: Map<string, WalletSigningBudgetReservation>;
      reservationIdsByOperation: Map<string, string>;
      committedBudgetReservations: Map<
        string,
        {
          operationKey: string;
          operationId: string;
          requestDigest: string;
          remainingUses: number;
          expiresAtMs: number;
        }
      >;
    }
  >();
  private readonly replayGuards = new Map<string, number>();

  constructor(input: { keyPrefix?: string }) {
    this.keyPrefix = toThresholdEd25519WalletSessionPrefix(input.keyPrefix);
  }

  private key(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private replayGuardKey(scopeId: string, replayKey: string): string {
    return `${this.keyPrefix}replay:${normalizeConsumeOnceKey(scopeId)}:${normalizeConsumeOnceKey(replayKey)}`;
  }

  async putSession(
    id: string,
    record: Ed25519WalletSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const key = this.key(id);
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    const expiresAtMs = Date.now() + ttlMs;
    this.map.set(key, {
      record,
      remainingUses: Math.max(0, Number(opts.remainingUses) || 0),
      expiresAtMs,
      consumedIdempotencyKeys: new Set(),
      budgetReservations: new Map(),
      reservationIdsByOperation: new Map(),
      committedBudgetReservations: new Map(),
    });
  }

  async getSession(id: string): Promise<Ed25519WalletSessionRecord | null> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    return entry.record;
  }

  async getSessionStatus(id: string): Promise<Ed25519WalletSessionStatus | null> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return null;
    }
    const budget = inMemoryBudgetProjection(entry);
    return {
      record: entry.record,
      expiresAtMs: entry.expiresAtMs,
      committedRemainingUses: budget.committedRemainingUses,
      reservedUses: budget.reservedUses,
      availableUses: budget.availableUses,
      remainingUses: budget.availableUses,
    };
  }

  async consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry)
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const budget = inMemoryBudgetProjection(entry);
    if (budget.availableUses <= 0) {
      return inMemoryBudgetUnavailable(entry.remainingUses, budget.reservedUses);
    }
    entry.remainingUses -= 1;
    return { ok: true, remainingUses: entry.remainingUses };
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumeUsesResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry)
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const consumeKey = String(idempotencyKey || '').trim();
    if (consumeKey && entry.consumedIdempotencyKeys.has(consumeKey)) {
      return { ok: true, remainingUses: entry.remainingUses };
    }
    const budget = inMemoryBudgetProjection(entry);
    if (budget.availableUses <= 0) {
      return inMemoryBudgetUnavailable(entry.remainingUses, budget.reservedUses);
    }
    entry.remainingUses -= 1;
    if (consumeKey) entry.consumedIdempotencyKeys.add(consumeKey);
    return { ok: true, remainingUses: entry.remainingUses };
  }

  async reserveUseCountOnce(
    input: WalletSessionBudgetReserveUseCountInput,
  ): Promise<WalletSessionBudgetReservationResult> {
    const key = this.key(input.walletSigningSessionId);
    const entry = this.map.get(key);
    const nowMs = Date.now();
    if (!entry)
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    if (nowMs > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const parsed = parseBudgetReservationInput(input, entry.expiresAtMs, nowMs);
    if (!parsed.ok) return parsed;
    const operationKey = budgetOperationKey(parsed.value);
    const existingReservationId = entry.reservationIdsByOperation.get(operationKey);
    if (existingReservationId) {
      const existing = entry.budgetReservations.get(existingReservationId);
      if (existing && existing.expiresAtMs > nowMs) {
        const budget = inMemoryBudgetProjection(entry);
        return {
          ok: true,
          reservation: existing,
          remainingUses: budget.committedRemainingUses,
          reservedUses: budget.reservedUses,
          availableUses: budget.availableUses,
        };
      }
      entry.reservationIdsByOperation.delete(operationKey);
      if (existingReservationId) entry.budgetReservations.delete(existingReservationId);
    }
    const budget = inMemoryBudgetProjection(entry);
    if (budget.availableUses < parsed.value.signatureUses) {
      return inMemoryBudgetReservationUnavailable({
        committedRemainingUses: budget.committedRemainingUses,
        reservedUses: budget.reservedUses,
        signatureUses: parsed.value.signatureUses,
      });
    }
    const reservation: WalletSigningBudgetReservation = {
      kind: 'wallet_signing_budget_reservation_v1',
      walletSigningSessionId: parsed.value.walletSigningSessionId,
      curve: parsed.value.curve,
      thresholdSessionId: parsed.value.thresholdSessionId,
      operationId: parsed.value.operationId,
      requestDigest: parsed.value.requestDigest,
      signatureUses: parsed.value.signatureUses,
      reservationId: createBudgetReservationId(),
      expiresAtMs: parsed.value.expiresAtMs,
    };
    entry.budgetReservations.set(reservation.reservationId, reservation);
    entry.reservationIdsByOperation.set(operationKey, reservation.reservationId);
    const nextBudget = inMemoryBudgetProjection(entry);
    return {
      ok: true,
      reservation,
      remainingUses: nextBudget.committedRemainingUses,
      reservedUses: nextBudget.reservedUses,
      availableUses: nextBudget.availableUses,
    };
  }

  async commitReservedUseCountOnce(
    input: WalletSessionBudgetCommitReservedUseCountInput,
  ): Promise<WalletSessionConsumeUsesResult> {
    const key = this.key(input.walletSigningSessionId);
    const entry = this.map.get(key);
    const nowMs = Date.now();
    if (!entry)
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    if (nowMs > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const parsed = parseBudgetCommitInput(input);
    if (!parsed.ok) return parsed;
    const committed = entry.committedBudgetReservations.get(parsed.value.reservationId);
    const operationKey = budgetOperationKey(parsed.value);
    if (committed) {
      if (
        committed.operationKey !== operationKey ||
        committed.operationId !== parsed.value.operationId ||
        committed.requestDigest !== parsed.value.requestDigest
      ) {
        return budgetReservationMismatch();
      }
      return { ok: true, remainingUses: committed.remainingUses };
    }
    const reservation = entry.budgetReservations.get(parsed.value.reservationId);
    if (!reservation) return budgetReservationExpired();
    if (reservation.expiresAtMs <= nowMs) {
      entry.budgetReservations.delete(reservation.reservationId);
      entry.reservationIdsByOperation.delete(budgetOperationKey(reservation));
      return budgetReservationExpired();
    }
    if (
      reservation.operationId !== parsed.value.operationId ||
      reservation.requestDigest !== parsed.value.requestDigest
    ) {
      return budgetReservationMismatch();
    }
    if (entry.remainingUses < reservation.signatureUses) {
      return budgetExhausted();
    }
    entry.remainingUses -= reservation.signatureUses;
    entry.budgetReservations.delete(reservation.reservationId);
    entry.reservationIdsByOperation.delete(budgetOperationKey(reservation));
    entry.committedBudgetReservations.set(reservation.reservationId, {
      operationKey,
      operationId: parsed.value.operationId,
      requestDigest: parsed.value.requestDigest,
      remainingUses: entry.remainingUses,
      expiresAtMs: entry.expiresAtMs,
    });
    return { ok: true, remainingUses: entry.remainingUses };
  }

  async releaseReservedUseCount(
    input: WalletSessionBudgetReleaseReservedUseCountInput,
  ): Promise<WalletSessionBudgetReleaseResult> {
    const key = this.key(input.walletSigningSessionId);
    const entry = this.map.get(key);
    const nowMs = Date.now();
    if (!entry)
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    if (nowMs > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const reservationId = normalizeBudgetField(input.reservationId);
    if (!reservationId) {
      return { ok: false, code: 'invalid_budget_request', message: 'budget reservation id is required' };
    }
    const existing = entry.budgetReservations.get(reservationId);
    const released = !!existing;
    if (existing) {
      entry.budgetReservations.delete(reservationId);
      entry.reservationIdsByOperation.delete(budgetOperationKey(existing));
    }
    const budget = inMemoryBudgetProjection(entry);
    return {
      ok: true,
      released,
      remainingUses: budget.committedRemainingUses,
      reservedUses: budget.reservedUses,
      availableUses: budget.availableUses,
    };
  }

  async hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult> {
    const key = this.key(id);
    const entry = this.map.get(key);
    if (!entry) {
      return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
    }
    if (Date.now() > entry.expiresAtMs) {
      this.map.delete(key);
      return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
    }
    const consumeKey = String(idempotencyKey || '').trim();
    return { ok: true, consumed: !!consumeKey && entry.consumedIdempotencyKeys.has(consumeKey) };
  }

  async reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult> {
    const key = this.replayGuardKey(scopeId, replayKey);
    if (!key) return replayGuardInvalid();
    const nowMs = Date.now();
    const existingExpiresAtMs = this.replayGuards.get(key);
    if (existingExpiresAtMs !== undefined && existingExpiresAtMs > nowMs) {
      return replayGuardDuplicate();
    }
    if (existingExpiresAtMs !== undefined) this.replayGuards.delete(key);
    const ttlMs = replayGuardTtlMs(expiresAtMs, nowMs);
    if (ttlMs <= 0) return replayGuardExpired();
    this.replayGuards.set(key, nowMs + ttlMs);
    return { ok: true };
  }
}

function normalizeConsumeOnceKey(value: string): string {
  return String(value || '')
    .trim()
    .replace(/[^A-Za-z0-9._:-]/g, '_')
    .slice(0, 512);
}

function normalizeBudgetField(value: unknown): string {
  return String(value || '').trim();
}

function errorMessage(error: unknown): string {
  return String(
    error && typeof error === 'object' && 'message' in error
      ? (error as { message?: unknown }).message
      : error || '',
  );
}

function normalizeBudgetToken(value: unknown): string {
  return normalizeBudgetField(value).replace(/[^A-Za-z0-9._:-]/g, '_').slice(0, 512);
}

function createBudgetReservationId(): string {
  return `wbudget_${secureRandomIdFragment()}`;
}

function budgetOperationKey(input: { operationId: string; requestDigest: string }): string {
  return [
    'wallet-signing-budget',
    normalizeBudgetToken(input.operationId),
    normalizeBudgetToken(input.requestDigest),
  ].join(':');
}

function parseBudgetSignatureUses(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed <= 0) return null;
  return parsed;
}

function parseBudgetReservationInput(
  input: WalletSessionBudgetReserveUseCountInput,
  sessionExpiresAtMs: number,
  nowMs: number,
):
  | { ok: true; value: WalletSessionBudgetReserveUseCountInput }
  | { ok: false; code: string; message: string } {
  const walletSigningSessionId = normalizeBudgetField(input.walletSigningSessionId);
  const thresholdSessionId = normalizeBudgetField(input.thresholdSessionId);
  const operationId = normalizeBudgetField(input.operationId);
  const requestDigest = normalizeBudgetField(input.requestDigest);
  const signatureUses = parseBudgetSignatureUses(input.signatureUses);
  const expiresAtMs = Math.min(Number(input.expiresAtMs), sessionExpiresAtMs);
  if (
    !walletSigningSessionId ||
    !thresholdSessionId ||
    !operationId ||
    !requestDigest ||
    !signatureUses ||
    !Number.isFinite(expiresAtMs) ||
    expiresAtMs <= nowMs
  ) {
    return {
      ok: false,
      code: 'invalid_budget_request',
      message:
        'budget reservation requires session, threshold session, operation, request digest, signature uses, and future expiry',
    };
  }
  return {
    ok: true,
    value: {
      walletSigningSessionId,
      curve: input.curve,
      thresholdSessionId,
      operationId,
      requestDigest,
      signatureUses,
      expiresAtMs: Math.floor(expiresAtMs),
    },
  };
}

function parseBudgetCommitInput(
  input: WalletSessionBudgetCommitReservedUseCountInput,
):
  | { ok: true; value: WalletSessionBudgetCommitReservedUseCountInput }
  | { ok: false; code: string; message: string } {
  const walletSigningSessionId = normalizeBudgetField(input.walletSigningSessionId);
  const reservationId = normalizeBudgetField(input.reservationId);
  const operationId = normalizeBudgetField(input.operationId);
  const requestDigest = normalizeBudgetField(input.requestDigest);
  if (!walletSigningSessionId || !reservationId || !operationId || !requestDigest) {
    return {
      ok: false,
      code: 'invalid_budget_request',
      message:
        'budget commit requires wallet signing session, reservation, operation, and request digest',
    };
  }
  return {
    ok: true,
    value: {
      walletSigningSessionId,
      reservationId,
      operationId,
      requestDigest,
    },
  };
}

function budgetReservationMismatch(): WalletSessionConsumeUsesResult {
  return {
    ok: false,
    code: 'wallet_budget_reservation_mismatch',
    message: 'wallet signing budget reservation does not match this operation',
  };
}

function budgetReservationExpired(): WalletSessionConsumeUsesResult {
  return {
    ok: false,
    code: 'wallet_budget_reservation_expired',
    message: 'wallet signing budget reservation expired',
  };
}

function budgetExhausted(): WalletSessionConsumeUsesResult {
  return {
    ok: false,
    code: 'wallet_budget_exhausted',
    message: 'wallet signing session exhausted',
  };
}

function budgetInFlight(): WalletSessionConsumeUsesResult {
  return {
    ok: false,
    code: 'wallet_budget_in_flight',
    message: 'wallet signing session budget is reserved by another signing operation',
  };
}

function inMemoryBudgetUnavailable(
  committedRemainingUses: number,
  reservedUses: number,
): WalletSessionConsumeUsesResult {
  if (committedRemainingUses > 0 && reservedUses > 0) return budgetInFlight();
  return budgetExhausted();
}

function inMemoryBudgetReservationUnavailable(input: {
  committedRemainingUses: number;
  reservedUses: number;
  signatureUses: number;
}): WalletSessionBudgetReservationResult {
  if (input.committedRemainingUses >= input.signatureUses && input.reservedUses > 0) {
    return {
      ok: false,
      code: 'wallet_budget_in_flight',
      message: 'wallet signing session budget is reserved by another signing operation',
    };
  }
  return {
    ok: false,
    code: 'wallet_budget_exhausted',
    message: 'wallet signing session exhausted',
  };
}

function inMemoryBudgetProjection(entry: {
  remainingUses: number;
  budgetReservations: Map<string, WalletSigningBudgetReservation>;
  reservationIdsByOperation: Map<string, string>;
}): {
  committedRemainingUses: number;
  reservedUses: number;
  availableUses: number;
} {
  const nowMs = Date.now();
  let reservedUses = 0;
  for (const [reservationId, reservation] of [...entry.budgetReservations.entries()]) {
    if (reservation.expiresAtMs <= nowMs) {
      entry.budgetReservations.delete(reservationId);
      entry.reservationIdsByOperation.delete(budgetOperationKey(reservation));
      continue;
    }
    reservedUses += reservation.signatureUses;
  }
  const committedRemainingUses = Math.max(0, Math.floor(Number(entry.remainingUses) || 0));
  return {
    committedRemainingUses,
    reservedUses,
    availableUses: Math.max(0, committedRemainingUses - reservedUses),
  };
}

function replayGuardTtlMs(expiresAtMs: number, nowMs = Date.now()): number {
  const expires = Number(expiresAtMs);
  if (!Number.isFinite(expires)) return 0;
  const retainUntilMs = expires + EXPORT_REPLAY_GUARD_CLOCK_SKEW_MS;
  if (retainUntilMs <= nowMs) return 0;
  return Math.max(
    EXPORT_REPLAY_GUARD_MIN_RETENTION_MS,
    Math.floor(retainUntilMs - nowMs),
  );
}

function replayGuardInvalid(): WalletSessionReplayGuardResult {
  return { ok: false, code: 'invalid_body', message: 'Invalid replay guard key' };
}

function replayGuardExpired(): WalletSessionReplayGuardResult {
  return {
    ok: false,
    code: 'export_authorization_expired',
    message: 'Export authorization expired',
  };
}

function replayGuardDuplicate(): WalletSessionReplayGuardResult {
  return {
    ok: false,
    code: 'export_nonce_replay',
    message: 'Export authorization nonce already used',
  };
}

function parseRedisReplayGuardResult(raw: unknown): WalletSessionReplayGuardResult {
  const text = String(raw ?? '').trim();
  if (text === 'ok') return { ok: true };
  if (text === 'duplicate') return replayGuardDuplicate();
  if (text === 'expired') return replayGuardExpired();
  return { ok: false, code: 'internal', message: 'Redis replay guard returned invalid response' };
}

function parseRedisConsumeOnceResult(raw: unknown): WalletSessionConsumeUsesResult {
  const text = String(raw ?? '').trim();
  if (text.startsWith('ok:')) {
    const remainingUses = Number(text.slice(3));
    if (!Number.isFinite(remainingUses)) {
      return { ok: false, code: 'internal', message: 'Redis consume-once returned invalid uses' };
    }
    return { ok: true, remainingUses };
  }
  if (text.startsWith('err:')) {
    const message = text.slice(4) || 'threshold session authorization failed';
    return { ok: false, code: 'unauthorized', message };
  }
  return { ok: false, code: 'internal', message: 'Redis consume-once returned invalid response' };
}

function parseRedisConsumedUseResult(raw: unknown): WalletSessionConsumedUseResult {
  const value = typeof raw === 'number' ? raw : Number(String(raw ?? '').trim());
  if (!Number.isFinite(value)) {
    return { ok: false, code: 'internal', message: 'Redis consumed-use check returned invalid response' };
  }
  return { ok: true, consumed: value > 0 };
}

function redisRawValue(resp: { type: string; value?: unknown }): unknown {
  if (resp.type === 'integer') return String(resp.value);
  return resp.value;
}

function parseRedisJsonObject(raw: unknown): Record<string, unknown> | null {
  const text = String(raw ?? '').trim();
  if (!text) return null;
  try {
    const parsed = JSON.parse(text);
    return isObject(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function parseRedisBudgetReservation(raw: unknown): WalletSessionBudgetReservationResult {
  const record = parseRedisJsonObject(raw);
  if (!record) {
    return { ok: false, code: 'internal', message: 'Redis budget reserve returned invalid response' };
  }
  if (record.ok === false) {
    return {
      ok: false,
      code: normalizeBudgetField(record.code) || 'internal',
      message: normalizeBudgetField(record.message) || 'Redis budget reserve failed',
    };
  }
  const reservationRaw = isObject(record.reservation)
    ? (record.reservation as Record<string, unknown>)
    : null;
  const reservation = parseWalletSigningBudgetReservation(reservationRaw);
  const remainingUses = Number(record.remainingUses);
  const reservedUses = Number(record.reservedUses);
  const availableUses = Number(record.availableUses);
  if (
    !reservation ||
    !Number.isFinite(remainingUses) ||
    !Number.isFinite(reservedUses) ||
    !Number.isFinite(availableUses)
  ) {
    return { ok: false, code: 'internal', message: 'Redis budget reserve returned invalid payload' };
  }
  return {
    ok: true,
    reservation,
    remainingUses,
    reservedUses,
    availableUses,
  };
}

function parseRedisBudgetCommit(raw: unknown): WalletSessionConsumeUsesResult {
  const record = parseRedisJsonObject(raw);
  if (!record) {
    return { ok: false, code: 'internal', message: 'Redis budget commit returned invalid response' };
  }
  if (record.ok === false) {
    return {
      ok: false,
      code: normalizeBudgetField(record.code) || 'internal',
      message: normalizeBudgetField(record.message) || 'Redis budget commit failed',
    };
  }
  const remainingUses = Number(record.remainingUses);
  if (!Number.isFinite(remainingUses)) {
    return { ok: false, code: 'internal', message: 'Redis budget commit returned invalid uses' };
  }
  return { ok: true, remainingUses };
}

function parseRedisBudgetRelease(raw: unknown): WalletSessionBudgetReleaseResult {
  const record = parseRedisJsonObject(raw);
  if (!record) {
    return { ok: false, code: 'internal', message: 'Redis budget release returned invalid response' };
  }
  if (record.ok === false) {
    return {
      ok: false,
      code: normalizeBudgetField(record.code) || 'internal',
      message: normalizeBudgetField(record.message) || 'Redis budget release failed',
    };
  }
  const remainingUses = Number(record.remainingUses);
  const reservedUses = Number(record.reservedUses);
  const availableUses = Number(record.availableUses);
  if (
    !Number.isFinite(remainingUses) ||
    !Number.isFinite(reservedUses) ||
    !Number.isFinite(availableUses)
  ) {
    return { ok: false, code: 'internal', message: 'Redis budget release returned invalid uses' };
  }
  return {
    ok: true,
    released: record.released === true,
    remainingUses,
    reservedUses,
    availableUses,
  };
}

function parseRedisBudgetProjection(
  raw: unknown,
): { committedRemainingUses: number; reservedUses: number; availableUses: number } | null {
  const record = parseRedisJsonObject(raw);
  if (!record || record.ok === false) return null;
  const committedRemainingUses = Number(record.remainingUses);
  const reservedUses = Number(record.reservedUses);
  const availableUses = Number(record.availableUses);
  if (
    !Number.isFinite(committedRemainingUses) ||
    !Number.isFinite(reservedUses) ||
    !Number.isFinite(availableUses)
  ) {
    return null;
  }
  return { committedRemainingUses, reservedUses, availableUses };
}

function parseWalletSigningBudgetReservation(
  record: Record<string, unknown> | null,
): WalletSigningBudgetReservation | null {
  if (!record || record.kind !== 'wallet_signing_budget_reservation_v1') return null;
  const walletSigningSessionId = normalizeBudgetField(record.walletSigningSessionId);
  const curve = record.curve === 'ed25519' || record.curve === 'ecdsa' ? record.curve : null;
  const thresholdSessionId = normalizeBudgetField(record.thresholdSessionId);
  const operationId = normalizeBudgetField(record.operationId);
  const requestDigest = normalizeBudgetField(record.requestDigest);
  const reservationId = normalizeBudgetField(record.reservationId);
  const signatureUses = parseBudgetSignatureUses(record.signatureUses);
  const expiresAtMs = Number(record.expiresAtMs);
  if (
    !walletSigningSessionId ||
    !curve ||
    !thresholdSessionId ||
    !operationId ||
    !requestDigest ||
    !reservationId ||
    !signatureUses ||
    !Number.isFinite(expiresAtMs)
  ) {
    return null;
  }
  return {
    kind: 'wallet_signing_budget_reservation_v1',
    walletSigningSessionId,
    curve,
    thresholdSessionId,
    operationId,
    requestDigest,
    signatureUses,
    reservationId,
    expiresAtMs: Math.floor(expiresAtMs),
  };
}

function parsePostgresBudgetReservation(
  walletSigningSessionId: string,
  row: Record<string, unknown>,
): WalletSigningBudgetReservation | null {
  return parseWalletSigningBudgetReservation({
    kind: 'wallet_signing_budget_reservation_v1',
    walletSigningSessionId,
    curve: row.curve,
    thresholdSessionId: row.threshold_session_id,
    operationId: row.operation_id,
    requestDigest: row.request_digest,
    reservationId: row.reservation_id,
    signatureUses: row.signature_uses,
    expiresAtMs: row.expires_at_ms,
  });
}

const CONSUME_ONCE_EXISTS_LUA = `
local marker_key = KEYS[1]
return redis.call('EXISTS', marker_key)
`;

const CONSUME_ONCE_LUA = `
local uses_key = KEYS[1]
local marker_key = KEYS[2]
if redis.call('EXISTS', marker_key) == 1 then
  local current = redis.call('GET', uses_key)
  if not current then
    return 'err:threshold session expired or invalid'
  end
  return 'ok:' .. tostring(current)
end
local current = tonumber(redis.call('GET', uses_key) or '')
if current == nil then
  return 'err:threshold session expired or invalid'
end
if current <= 0 then
  return 'err:threshold session exhausted'
end
local remaining = redis.call('INCRBY', uses_key, -1)
local ttl = redis.call('TTL', uses_key)
if ttl and ttl > 0 then
  redis.call('SET', marker_key, '1', 'EX', ttl)
else
  redis.call('SET', marker_key, '1', 'EX', 60)
end
return 'ok:' .. tostring(remaining)
`;

const REPLAY_GUARD_LUA = `
local key = KEYS[1]
local ttl_seconds = tonumber(ARGV[1] or '')
if ttl_seconds == nil or ttl_seconds <= 0 then
  return 'expired'
end
if redis.call('EXISTS', key) == 1 then
  return 'duplicate'
end
redis.call('SET', key, '1', 'EX', ttl_seconds)
return 'ok'
`;

const BUDGET_STATUS_LUA = `
local uses_key = KEYS[1]
local index_key = KEYS[2]
local now_ms = tonumber(ARGV[1] or '')
local current = tonumber(redis.call('GET', uses_key) or '')
if current == nil or now_ms == nil then
  return cjson.encode({ ok = false, code = 'unauthorized', message = 'threshold session expired or invalid' })
end
local reserved = 0
local keys = redis.call('SMEMBERS', index_key)
for _, reservation_key in ipairs(keys) do
  local raw = redis.call('GET', reservation_key)
  if raw then
    local reservation = cjson.decode(raw)
    if tonumber(reservation.expiresAtMs or 0) <= now_ms then
      redis.call('DEL', reservation_key)
      if reservation.operationKey then redis.call('DEL', reservation.operationKey) end
      redis.call('SREM', index_key, reservation_key)
    else
      reserved = reserved + tonumber(reservation.signatureUses or 0)
    end
  else
    redis.call('SREM', index_key, reservation_key)
  end
end
local available = current - reserved
if available < 0 then available = 0 end
return cjson.encode({ ok = true, remainingUses = current, reservedUses = reserved, availableUses = available })
`;

const BUDGET_RESERVE_LUA = `
local uses_key = KEYS[1]
local index_key = KEYS[2]
local operation_key = KEYS[3]
local reservation_key = KEYS[4]
local current = tonumber(redis.call('GET', uses_key) or '')
local now_ms = tonumber(ARGV[9] or '')
if current == nil then
  return cjson.encode({ ok = false, code = 'unauthorized', message = 'threshold session expired or invalid' })
end
if now_ms == nil then
  return cjson.encode({ ok = false, code = 'invalid_budget_request', message = 'invalid budget clock' })
end
local reserved = 0
local keys = redis.call('SMEMBERS', index_key)
for _, active_key in ipairs(keys) do
  local raw = redis.call('GET', active_key)
  if raw then
    local active = cjson.decode(raw)
    if tonumber(active.expiresAtMs or 0) <= now_ms then
      redis.call('DEL', active_key)
      if active.operationKey then redis.call('DEL', active.operationKey) end
      redis.call('SREM', index_key, active_key)
    else
      reserved = reserved + tonumber(active.signatureUses or 0)
    end
  else
    redis.call('SREM', index_key, active_key)
  end
end
local existing_key = redis.call('GET', operation_key)
if existing_key then
  local existing_raw = redis.call('GET', existing_key)
  if existing_raw then
    local existing = cjson.decode(existing_raw)
    if tonumber(existing.expiresAtMs or 0) > now_ms then
      local available = current - reserved
      if available < 0 then available = 0 end
      return cjson.encode({ ok = true, reservation = existing, remainingUses = current, reservedUses = reserved, availableUses = available })
    end
    redis.call('DEL', existing_key)
    redis.call('SREM', index_key, existing_key)
  end
  redis.call('DEL', operation_key)
end
local signature_uses = tonumber(ARGV[7] or '')
if signature_uses == nil or signature_uses <= 0 then
  return cjson.encode({ ok = false, code = 'invalid_budget_request', message = 'invalid budget signature uses' })
end
local available = current - reserved
if available < signature_uses then
  if current >= signature_uses and reserved > 0 then
    return cjson.encode({ ok = false, code = 'wallet_budget_in_flight', message = 'wallet signing session budget is reserved by another signing operation' })
  end
  return cjson.encode({ ok = false, code = 'wallet_budget_exhausted', message = 'wallet signing session exhausted' })
end
local expires_at_ms = tonumber(ARGV[8] or '')
if expires_at_ms == nil or expires_at_ms <= now_ms then
  return cjson.encode({ ok = false, code = 'invalid_budget_request', message = 'budget reservation expiry must be in the future' })
end
local ttl_seconds = math.max(1, math.ceil((expires_at_ms - now_ms) / 1000))
local reservation = {
  kind = 'wallet_signing_budget_reservation_v1',
  walletSigningSessionId = ARGV[1],
  curve = ARGV[2],
  thresholdSessionId = ARGV[3],
  operationId = ARGV[4],
  requestDigest = ARGV[5],
  reservationId = ARGV[6],
  signatureUses = signature_uses,
  expiresAtMs = expires_at_ms,
  operationKey = operation_key
}
local reservation_json = cjson.encode(reservation)
redis.call('SET', reservation_key, reservation_json, 'EX', ttl_seconds)
redis.call('SET', operation_key, reservation_key, 'EX', ttl_seconds)
redis.call('SADD', index_key, reservation_key)
redis.call('EXPIRE', index_key, ttl_seconds)
local next_reserved = reserved + signature_uses
local next_available = current - next_reserved
if next_available < 0 then next_available = 0 end
return cjson.encode({ ok = true, reservation = reservation, remainingUses = current, reservedUses = next_reserved, availableUses = next_available })
`;

const BUDGET_COMMIT_LUA = `
local uses_key = KEYS[1]
local index_key = KEYS[2]
local reservation_key = KEYS[3]
local committed_key = KEYS[4]
local operation_id = ARGV[1]
local request_digest = ARGV[2]
local now_ms = tonumber(ARGV[3] or '')
local session_ttl_seconds = tonumber(redis.call('TTL', uses_key) or '0')
if session_ttl_seconds == nil or session_ttl_seconds <= 0 then
  session_ttl_seconds = tonumber(ARGV[4] or '60')
end
local committed_raw = redis.call('GET', committed_key)
if committed_raw then
  local committed = cjson.decode(committed_raw)
  if committed.operationId ~= operation_id or committed.requestDigest ~= request_digest then
    return cjson.encode({ ok = false, code = 'wallet_budget_reservation_mismatch', message = 'wallet signing budget reservation does not match this operation' })
  end
  return cjson.encode({ ok = true, remainingUses = tonumber(committed.remainingUses or 0) })
end
local reservation_raw = redis.call('GET', reservation_key)
if not reservation_raw then
  return cjson.encode({ ok = false, code = 'wallet_budget_reservation_expired', message = 'wallet signing budget reservation expired' })
end
local reservation = cjson.decode(reservation_raw)
if reservation.operationId ~= operation_id or reservation.requestDigest ~= request_digest then
  return cjson.encode({ ok = false, code = 'wallet_budget_reservation_mismatch', message = 'wallet signing budget reservation does not match this operation' })
end
if now_ms == nil or tonumber(reservation.expiresAtMs or 0) <= now_ms then
  redis.call('DEL', reservation_key)
  if reservation.operationKey then redis.call('DEL', reservation.operationKey) end
  redis.call('SREM', index_key, reservation_key)
  return cjson.encode({ ok = false, code = 'wallet_budget_reservation_expired', message = 'wallet signing budget reservation expired' })
end
local current = tonumber(redis.call('GET', uses_key) or '')
if current == nil then
  return cjson.encode({ ok = false, code = 'unauthorized', message = 'threshold session expired or invalid' })
end
local signature_uses = tonumber(reservation.signatureUses or 0)
if current < signature_uses then
  return cjson.encode({ ok = false, code = 'wallet_budget_exhausted', message = 'wallet signing session exhausted' })
end
local remaining = redis.call('INCRBY', uses_key, -signature_uses)
redis.call('DEL', reservation_key)
if reservation.operationKey then redis.call('DEL', reservation.operationKey) end
redis.call('SREM', index_key, reservation_key)
redis.call('SET', committed_key, cjson.encode({
  operationId = operation_id,
  requestDigest = request_digest,
  remainingUses = remaining
}), 'EX', math.max(1, session_ttl_seconds))
return cjson.encode({ ok = true, remainingUses = remaining })
`;

const BUDGET_RELEASE_LUA = `
local uses_key = KEYS[1]
local index_key = KEYS[2]
local reservation_key = KEYS[3]
local now_ms = tonumber(ARGV[1] or '')
local released = false
local reservation_raw = redis.call('GET', reservation_key)
if reservation_raw then
  local reservation = cjson.decode(reservation_raw)
  redis.call('DEL', reservation_key)
  if reservation.operationKey then redis.call('DEL', reservation.operationKey) end
  redis.call('SREM', index_key, reservation_key)
  released = true
end
local current = tonumber(redis.call('GET', uses_key) or '')
if current == nil or now_ms == nil then
  return cjson.encode({ ok = false, code = 'unauthorized', message = 'threshold session expired or invalid' })
end
local reserved = 0
local keys = redis.call('SMEMBERS', index_key)
for _, active_key in ipairs(keys) do
  local raw = redis.call('GET', active_key)
  if raw then
    local active = cjson.decode(raw)
    if tonumber(active.expiresAtMs or 0) <= now_ms then
      redis.call('DEL', active_key)
      if active.operationKey then redis.call('DEL', active.operationKey) end
      redis.call('SREM', index_key, active_key)
    else
      reserved = reserved + tonumber(active.signatureUses or 0)
    end
  else
    redis.call('SREM', index_key, active_key)
  end
end
local available = current - reserved
if available < 0 then available = 0 end
return cjson.encode({ ok = true, released = released, remainingUses = current, reservedUses = reserved, availableUses = available })
`;

class UpstashRedisRestEd25519WalletSessionStore implements Ed25519WalletSessionStore {
  private readonly client: UpstashRedisRestClient;
  private readonly keyPrefix: string;

  constructor(input: { url: string; token: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.url);
    const token = toOptionalTrimmedString(input.token);
    if (!url) throw new Error('Upstash wallet session store missing url');
    if (!token) throw new Error('Upstash wallet session store missing token');
    this.client = new UpstashRedisRestClient({ url, token });
    this.keyPrefix = toThresholdEd25519WalletSessionPrefix(input.keyPrefix);
  }

  private metaKey(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private usesKey(id: string): string {
    return `${this.keyPrefix}${id}:uses`;
  }

  private consumeOnceKey(id: string, idempotencyKey: string): string {
    return `${this.usesKey(id)}:once:${normalizeConsumeOnceKey(idempotencyKey)}`;
  }

  private budgetReservationIndexKey(id: string): string {
    return `${this.usesKey(id)}:budget-reservations`;
  }

  private budgetReservationKey(id: string, reservationId: string): string {
    return `${this.usesKey(id)}:budget-reservation:${normalizeBudgetToken(reservationId)}`;
  }

  private budgetOperationKey(id: string, operationId: string, requestDigest: string): string {
    return `${this.usesKey(id)}:${budgetOperationKey({ operationId, requestDigest })}`;
  }

  private budgetCommitKey(id: string, reservationId: string): string {
    return `${this.usesKey(id)}:budget-commit:${normalizeBudgetToken(reservationId)}`;
  }

  private replayGuardKey(scopeId: string, replayKey: string): string {
    return `${this.keyPrefix}replay:${normalizeConsumeOnceKey(scopeId)}:${normalizeConsumeOnceKey(replayKey)}`;
  }

  async putSession(
    id: string,
    record: Ed25519WalletSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    await this.client.setJson(this.metaKey(id), record, ttlMs);
    await this.client.setRaw(
      this.usesKey(id),
      String(Math.max(0, Number(opts.remainingUses) || 0)),
      ttlMs,
    );
  }

  async getSession(id: string): Promise<Ed25519WalletSessionRecord | null> {
    const raw = await this.client.getJson(this.metaKey(id));
    return parseEd25519WalletSessionRecord(raw);
  }

  async getSessionStatus(id: string): Promise<Ed25519WalletSessionStatus | null> {
    const record = parseEd25519WalletSessionRecord(await this.client.getJson(this.metaKey(id)));
    if (!record) return null;
    const budget = parseRedisBudgetProjection(
      await this.client.eval(
        BUDGET_STATUS_LUA,
        [this.usesKey(id), this.budgetReservationIndexKey(id)],
        [String(Date.now())],
      ),
    );
    if (!budget) return null;
    return {
      record,
      expiresAtMs: record.expiresAtMs,
      committedRemainingUses: budget.committedRemainingUses,
      reservedUses: budget.reservedUses,
      availableUses: budget.availableUses,
      remainingUses: budget.availableUses,
    };
  }

  async consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult> {
    try {
      const remainingUses = await this.client.incrby(this.usesKey(id), -1);
      if (remainingUses < 0) {
        return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
      }
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumeUsesResult> {
    try {
      const raw = await this.client.eval(
        CONSUME_ONCE_LUA,
        [this.usesKey(id), this.consumeOnceKey(id, idempotencyKey)],
        [],
      );
      return parseRedisConsumeOnceResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async reserveUseCountOnce(
    input: WalletSessionBudgetReserveUseCountInput,
  ): Promise<WalletSessionBudgetReservationResult> {
    const nowMs = Date.now();
    const parsed = parseBudgetReservationInput(input, Number.MAX_SAFE_INTEGER, nowMs);
    if (!parsed.ok) return parsed;
    const reservationId = createBudgetReservationId();
    try {
      const raw = await this.client.eval(
        BUDGET_RESERVE_LUA,
        [
          this.usesKey(parsed.value.walletSigningSessionId),
          this.budgetReservationIndexKey(parsed.value.walletSigningSessionId),
          this.budgetOperationKey(
            parsed.value.walletSigningSessionId,
            parsed.value.operationId,
            parsed.value.requestDigest,
          ),
          this.budgetReservationKey(parsed.value.walletSigningSessionId, reservationId),
        ],
        [
          parsed.value.walletSigningSessionId,
          parsed.value.curve,
          parsed.value.thresholdSessionId,
          parsed.value.operationId,
          parsed.value.requestDigest,
          reservationId,
          String(parsed.value.signatureUses),
          String(parsed.value.expiresAtMs),
          String(nowMs),
        ],
      );
      return parseRedisBudgetReservation(raw);
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Failed to reserve threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async commitReservedUseCountOnce(
    input: WalletSessionBudgetCommitReservedUseCountInput,
  ): Promise<WalletSessionConsumeUsesResult> {
    const parsed = parseBudgetCommitInput(input);
    if (!parsed.ok) return parsed;
    try {
      const raw = await this.client.eval(
        BUDGET_COMMIT_LUA,
        [
          this.usesKey(parsed.value.walletSigningSessionId),
          this.budgetReservationIndexKey(parsed.value.walletSigningSessionId),
          this.budgetReservationKey(
            parsed.value.walletSigningSessionId,
            parsed.value.reservationId,
          ),
          this.budgetCommitKey(parsed.value.walletSigningSessionId, parsed.value.reservationId),
        ],
        [parsed.value.operationId, parsed.value.requestDigest, String(Date.now()), '60'],
      );
      return parseRedisBudgetCommit(raw);
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Failed to commit threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async releaseReservedUseCount(
    input: WalletSessionBudgetReleaseReservedUseCountInput,
  ): Promise<WalletSessionBudgetReleaseResult> {
    const walletSigningSessionId = normalizeBudgetField(input.walletSigningSessionId);
    const reservationId = normalizeBudgetField(input.reservationId);
    if (!walletSigningSessionId || !reservationId) {
      return {
        ok: false,
        code: 'invalid_budget_request',
        message: 'budget release requires wallet signing session and reservation',
      };
    }
    try {
      const raw = await this.client.eval(
        BUDGET_RELEASE_LUA,
        [
          this.usesKey(walletSigningSessionId),
          this.budgetReservationIndexKey(walletSigningSessionId),
          this.budgetReservationKey(walletSigningSessionId, reservationId),
        ],
        [String(Date.now())],
      );
      return parseRedisBudgetRelease(raw);
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Failed to release threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult> {
    const consumeKey = normalizeConsumeOnceKey(idempotencyKey);
    if (!consumeKey) return { ok: true, consumed: false };
    try {
      const raw = await this.client.eval(
        CONSUME_ONCE_EXISTS_LUA,
        [this.consumeOnceKey(id, consumeKey)],
        [],
      );
      return parseRedisConsumedUseResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to check consumed threshold session operation',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult> {
    try {
      const ttlMs = replayGuardTtlMs(expiresAtMs);
      if (ttlMs <= 0) return replayGuardExpired();
      const raw = await this.client.eval(
        REPLAY_GUARD_LUA,
        [this.replayGuardKey(scopeId, replayKey)],
        [String(Math.max(1, Math.ceil(ttlMs / 1000)))],
      );
      return parseRedisReplayGuardResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to reserve replay guard',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

class RedisTcpEd25519WalletSessionStore implements Ed25519WalletSessionStore {
  private readonly client: RedisTcpClient;
  private readonly keyPrefix: string;

  constructor(input: { redisUrl: string; keyPrefix?: string }) {
    const url = toOptionalTrimmedString(input.redisUrl);
    if (!url) throw new Error('redis-tcp wallet session store missing redisUrl');
    this.client = new RedisTcpClient(url);
    this.keyPrefix = toThresholdEd25519WalletSessionPrefix(input.keyPrefix);
  }

  private metaKey(id: string): string {
    return `${this.keyPrefix}${id}`;
  }

  private usesKey(id: string): string {
    return `${this.keyPrefix}${id}:uses`;
  }

  private consumeOnceKey(id: string, idempotencyKey: string): string {
    return `${this.usesKey(id)}:once:${normalizeConsumeOnceKey(idempotencyKey)}`;
  }

  private budgetReservationIndexKey(id: string): string {
    return `${this.usesKey(id)}:budget-reservations`;
  }

  private budgetReservationKey(id: string, reservationId: string): string {
    return `${this.usesKey(id)}:budget-reservation:${normalizeBudgetToken(reservationId)}`;
  }

  private budgetOperationKey(id: string, operationId: string, requestDigest: string): string {
    return `${this.usesKey(id)}:${budgetOperationKey({ operationId, requestDigest })}`;
  }

  private budgetCommitKey(id: string, reservationId: string): string {
    return `${this.usesKey(id)}:budget-commit:${normalizeBudgetToken(reservationId)}`;
  }

  private replayGuardKey(scopeId: string, replayKey: string): string {
    return `${this.keyPrefix}replay:${normalizeConsumeOnceKey(scopeId)}:${normalizeConsumeOnceKey(replayKey)}`;
  }

  async putSession(
    id: string,
    record: Ed25519WalletSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    await redisSetJson(this.client, this.metaKey(id), record, ttlMs);
    const ttlSeconds = Math.max(1, Math.ceil(ttlMs / 1000));
    const uses = String(Math.max(0, Number(opts.remainingUses) || 0));
    const resp = await this.client.send(['SET', this.usesKey(id), uses, 'EX', String(ttlSeconds)]);
    if (resp.type === 'error') throw new Error(`Redis SET error: ${resp.value}`);
  }

  async getSession(id: string): Promise<Ed25519WalletSessionRecord | null> {
    const raw = await redisGetJson(this.client, this.metaKey(id));
    return parseEd25519WalletSessionRecord(raw);
  }

  async getSessionStatus(id: string): Promise<Ed25519WalletSessionStatus | null> {
    const record = parseEd25519WalletSessionRecord(await redisGetJson(this.client, this.metaKey(id)));
    if (!record) return null;
    const resp = await this.client.send(['GET', this.usesKey(id)]);
    if (resp.type === 'error') throw new Error(`Redis GET error: ${resp.value}`);
    if (resp.type !== 'bulk' || resp.value == null) return null;
    const budgetResp = await this.client.send([
      'EVAL',
      BUDGET_STATUS_LUA,
      '2',
      this.usesKey(id),
      this.budgetReservationIndexKey(id),
      String(Date.now()),
    ]);
    if (budgetResp.type === 'error') throw new Error(`Redis EVAL error: ${budgetResp.value}`);
    const budget = parseRedisBudgetProjection(redisRawValue(budgetResp));
    if (!budget) return null;
    return {
      record,
      expiresAtMs: record.expiresAtMs,
      committedRemainingUses: budget.committedRemainingUses,
      reservedUses: budget.reservedUses,
      availableUses: budget.availableUses,
      remainingUses: budget.availableUses,
    };
  }

  async consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult> {
    try {
      const resp = await this.client.send(['INCRBY', this.usesKey(id), '-1']);
      if (resp.type === 'error')
        return { ok: false, code: 'internal', message: `Redis INCRBY error: ${resp.value}` };
      const remainingUses = resp.type === 'integer' ? resp.value : Number(resp.value ?? 0);
      if (!Number.isFinite(remainingUses)) {
        return { ok: false, code: 'internal', message: 'Redis INCRBY returned non-integer value' };
      }
      if (remainingUses < 0) {
        return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
      }
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumeUsesResult> {
    try {
      const resp = await this.client.send([
        'EVAL',
        CONSUME_ONCE_LUA,
        '2',
        this.usesKey(id),
        this.consumeOnceKey(id, idempotencyKey),
      ]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis EVAL error: ${resp.value}` };
      }
      const raw = resp.type === 'integer' ? String(resp.value) : resp.value;
      return parseRedisConsumeOnceResult(raw);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async reserveUseCountOnce(
    input: WalletSessionBudgetReserveUseCountInput,
  ): Promise<WalletSessionBudgetReservationResult> {
    const nowMs = Date.now();
    const parsed = parseBudgetReservationInput(input, Number.MAX_SAFE_INTEGER, nowMs);
    if (!parsed.ok) return parsed;
    const reservationId = createBudgetReservationId();
    try {
      const resp = await this.client.send([
        'EVAL',
        BUDGET_RESERVE_LUA,
        '4',
        this.usesKey(parsed.value.walletSigningSessionId),
        this.budgetReservationIndexKey(parsed.value.walletSigningSessionId),
        this.budgetOperationKey(
          parsed.value.walletSigningSessionId,
          parsed.value.operationId,
          parsed.value.requestDigest,
        ),
        this.budgetReservationKey(parsed.value.walletSigningSessionId, reservationId),
        parsed.value.walletSigningSessionId,
        parsed.value.curve,
        parsed.value.thresholdSessionId,
        parsed.value.operationId,
        parsed.value.requestDigest,
        reservationId,
        String(parsed.value.signatureUses),
        String(parsed.value.expiresAtMs),
        String(nowMs),
      ]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis EVAL error: ${resp.value}` };
      }
      return parseRedisBudgetReservation(redisRawValue(resp));
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Failed to reserve threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async commitReservedUseCountOnce(
    input: WalletSessionBudgetCommitReservedUseCountInput,
  ): Promise<WalletSessionConsumeUsesResult> {
    const parsed = parseBudgetCommitInput(input);
    if (!parsed.ok) return parsed;
    try {
      const resp = await this.client.send([
        'EVAL',
        BUDGET_COMMIT_LUA,
        '4',
        this.usesKey(parsed.value.walletSigningSessionId),
        this.budgetReservationIndexKey(parsed.value.walletSigningSessionId),
        this.budgetReservationKey(
          parsed.value.walletSigningSessionId,
          parsed.value.reservationId,
        ),
        this.budgetCommitKey(parsed.value.walletSigningSessionId, parsed.value.reservationId),
        parsed.value.operationId,
        parsed.value.requestDigest,
        String(Date.now()),
        '60',
      ]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis EVAL error: ${resp.value}` };
      }
      return parseRedisBudgetCommit(redisRawValue(resp));
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Failed to commit threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async releaseReservedUseCount(
    input: WalletSessionBudgetReleaseReservedUseCountInput,
  ): Promise<WalletSessionBudgetReleaseResult> {
    const walletSigningSessionId = normalizeBudgetField(input.walletSigningSessionId);
    const reservationId = normalizeBudgetField(input.reservationId);
    if (!walletSigningSessionId || !reservationId) {
      return {
        ok: false,
        code: 'invalid_budget_request',
        message: 'budget release requires wallet signing session and reservation',
      };
    }
    try {
      const resp = await this.client.send([
        'EVAL',
        BUDGET_RELEASE_LUA,
        '3',
        this.usesKey(walletSigningSessionId),
        this.budgetReservationIndexKey(walletSigningSessionId),
        this.budgetReservationKey(walletSigningSessionId, reservationId),
        String(Date.now()),
      ]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis EVAL error: ${resp.value}` };
      }
      return parseRedisBudgetRelease(redisRawValue(resp));
    } catch (e: unknown) {
      const msg = errorMessage(e) || 'Failed to release threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult> {
    const consumeKey = normalizeConsumeOnceKey(idempotencyKey);
    if (!consumeKey) return { ok: true, consumed: false };
    try {
      const resp = await this.client.send(['EXISTS', this.consumeOnceKey(id, consumeKey)]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis EXISTS error: ${resp.value}` };
      }
      return parseRedisConsumedUseResult(resp.value);
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to check consumed threshold session operation',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult> {
    try {
      const ttlMs = replayGuardTtlMs(expiresAtMs);
      if (ttlMs <= 0) return replayGuardExpired();
      const resp = await this.client.send([
        'SET',
        this.replayGuardKey(scopeId, replayKey),
        '1',
        'NX',
        'EX',
        String(Math.max(1, Math.ceil(ttlMs / 1000))),
      ]);
      if (resp.type === 'error') {
        return { ok: false, code: 'internal', message: `Redis SET error: ${resp.value}` };
      }
      if (resp.type === 'bulk' && resp.value === null) return replayGuardDuplicate();
      if (resp.type === 'simple' && resp.value === 'OK') return { ok: true };
      return {
        ok: false,
        code: 'internal',
        message: 'Redis replay guard returned invalid response',
      };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to reserve replay guard',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

class PostgresEd25519WalletSessionStore implements Ed25519WalletSessionStore {
  private readonly poolPromise: Promise<Awaited<ReturnType<typeof getPostgresPool>>>;
  private readonly namespace: string;

  constructor(input: { postgresUrl: string; namespace: string }) {
    this.poolPromise = getPostgresPool(input.postgresUrl);
    this.namespace = input.namespace;
  }

  private async deleteSessionRow(id: string): Promise<void> {
    const pool = await this.poolPromise;
    await pool.query(
      `
        DELETE FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3
      `,
      [this.namespace, 'wallet_session', id],
    );
  }

  private async cleanupExpiredBudgetReservations(
    client: { query: (text: string, values?: unknown[]) => Promise<{ rows: any[] }> },
    id: string,
    nowMs: number,
  ): Promise<void> {
    await client.query(
      `
        DELETE FROM threshold_wallet_session_budget_reservations
        WHERE namespace = $1 AND session_id = $2 AND status = $3 AND expires_at_ms <= $4
      `,
      [this.namespace, id, 'reserved', nowMs],
    );
  }

  private async activeReservedUses(
    client: { query: (text: string, values?: unknown[]) => Promise<{ rows: any[] }> },
    id: string,
    nowMs: number,
  ): Promise<number> {
    await this.cleanupExpiredBudgetReservations(client, id, nowMs);
    const { rows } = await client.query(
      `
        SELECT COALESCE(SUM(signature_uses), 0) AS reserved_uses
        FROM threshold_wallet_session_budget_reservations
        WHERE namespace = $1 AND session_id = $2 AND status = $3 AND expires_at_ms > $4
      `,
      [this.namespace, id, 'reserved', nowMs],
    );
    const reservedUses = Number(rows[0]?.reserved_uses ?? 0);
    return Number.isFinite(reservedUses) ? Math.max(0, Math.floor(reservedUses)) : 0;
  }

  async putSession(
    id: string,
    record: Ed25519WalletSessionRecord,
    opts: { ttlMs: number; remainingUses: number },
  ): Promise<void> {
    const ttlMs = Math.max(0, Number(opts.ttlMs) || 0);
    const expiresAtMs = Date.now() + ttlMs;
    const remainingUses = Math.max(0, Number(opts.remainingUses) || 0);
    const storedRecord = { ...record, expiresAtMs };
    const parsed = parseCurrentThresholdEd25519SessionRecord(storedRecord);
    if (!parsed) throw new Error('Invalid Wallet Session record');
    const pool = await this.poolPromise;
    await pool.query(
      `
        INSERT INTO threshold_ed25519_sessions (namespace, kind, session_id, record_json, expires_at_ms, remaining_uses)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (namespace, kind, session_id)
        DO UPDATE SET record_json = EXCLUDED.record_json, expires_at_ms = EXCLUDED.expires_at_ms, remaining_uses = EXCLUDED.remaining_uses
      `,
      [this.namespace, 'wallet_session', id, parsed, expiresAtMs, remainingUses],
    );
  }

  async getSession(id: string): Promise<Ed25519WalletSessionRecord | null> {
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms, remaining_uses
        FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        LIMIT 1
      `,
      [this.namespace, 'wallet_session', id, nowMs],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentThresholdEd25519SessionStatusRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
          remainingUses: row.remaining_uses,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      await this.deleteSessionRow(id);
      return null;
    }
    return parsed.value.record;
  }

  async getSessionStatus(id: string): Promise<Ed25519WalletSessionStatus | null> {
    const pool = await this.poolPromise;
    const nowMs = Date.now();
    const { rows } = await pool.query(
      `
        SELECT record_json, expires_at_ms, remaining_uses
        FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        LIMIT 1
      `,
      [this.namespace, 'wallet_session', id, nowMs],
    );
    const parsed = parsePostgresRow({
      row: rows[0],
      parser: (row) =>
        parseCurrentThresholdEd25519SessionStatusRow({
          recordJson: row.record_json,
          expiresAtMs: row.expires_at_ms,
          remainingUses: row.remaining_uses,
        }),
    });
    if (parsed.kind === 'missing') {
      return null;
    }
    if (parsed.kind === 'malformed') {
      await this.deleteSessionRow(id);
      return null;
    }
    const reservedUses = await this.activeReservedUses(pool, id, nowMs);
    return {
      ...parsed.value,
      committedRemainingUses: parsed.value.remainingUses,
      reservedUses,
      availableUses: Math.max(0, parsed.value.remainingUses - reservedUses),
      remainingUses: Math.max(0, parsed.value.remainingUses - reservedUses),
    };
  }

  private async explainMissing(
    id: string,
    nowMs: number,
  ): Promise<{ code: string; message: string }> {
    const pool = await this.poolPromise;
    const { rows } = await pool.query(
      `
        SELECT expires_at_ms, remaining_uses
        FROM threshold_ed25519_sessions
        WHERE namespace = $1 AND kind = $2 AND session_id = $3
        LIMIT 1
      `,
      [this.namespace, 'wallet_session', id],
    );
    const row = rows[0];
    if (!row) return { code: 'unauthorized', message: 'threshold session expired or invalid' };
    const expiresAtMs =
      typeof row.expires_at_ms === 'number' ? row.expires_at_ms : Number(row.expires_at_ms);
    const remainingUses =
      typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
    if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs)
      return { code: 'unauthorized', message: 'threshold session expired' };
    if (Number.isFinite(remainingUses) && remainingUses <= 0)
      return { code: 'unauthorized', message: 'threshold session exhausted' };
    return { code: 'unauthorized', message: 'threshold session expired or invalid' };
  }

  async consumeUseCount(id: string): Promise<WalletSessionConsumeUsesResult> {
    try {
      const pool = await this.poolPromise;
      const nowMs = Date.now();
      const { rows } = await pool.query(
        `
          UPDATE threshold_ed25519_sessions
          SET remaining_uses = remaining_uses - 1
          WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4 AND remaining_uses > 0
          RETURNING remaining_uses
        `,
        [this.namespace, 'wallet_session', id, nowMs],
      );
      const row = rows[0];
      if (!row) {
        const reason = await this.explainMissing(id, nowMs);
        return { ok: false, code: reason.code, message: reason.message };
      }
      const remainingUses =
        typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
      if (!Number.isFinite(remainingUses))
        return { ok: false, code: 'internal', message: 'Postgres returned invalid remainingUses' };
      return { ok: true, remainingUses };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async consumeUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumeUsesResult> {
    const consumeKey = normalizeConsumeOnceKey(idempotencyKey);
    if (!consumeKey) return await this.consumeUseCount(id);
    const pool = await this.poolPromise;
    const client =
      typeof pool.connect === 'function'
        ? await pool.connect()
        : {
            query: pool.query.bind(pool),
            release: () => undefined,
          };
    const nowMs = Date.now();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `
          SELECT expires_at_ms, remaining_uses
          FROM threshold_ed25519_sessions
          WHERE namespace = $1 AND kind = $2 AND session_id = $3
          FOR UPDATE
        `,
        [this.namespace, 'wallet_session', id],
      );
      const row = rows[0];
      if (!row) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
      }
      const expiresAtMs =
        typeof row.expires_at_ms === 'number' ? row.expires_at_ms : Number(row.expires_at_ms);
      const remainingUses =
        typeof row.remaining_uses === 'number' ? row.remaining_uses : Number(row.remaining_uses);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }
      if (!Number.isFinite(remainingUses)) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'internal', message: 'Postgres returned invalid remainingUses' };
      }

      const existing = await client.query(
        `
          SELECT 1
          FROM threshold_wallet_session_consumptions
          WHERE namespace = $1 AND session_id = $2 AND idempotency_key = $3 AND expires_at_ms > $4
          LIMIT 1
        `,
        [this.namespace, id, consumeKey, nowMs],
      );
      if (existing.rows[0]) {
        await client.query('COMMIT');
        return { ok: true, remainingUses };
      }
      if (remainingUses <= 0) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session exhausted' };
      }
      const updatedRemainingUses = remainingUses - 1;
      await client.query(
        `
          UPDATE threshold_ed25519_sessions
          SET remaining_uses = $5
          WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        `,
        [this.namespace, 'wallet_session', id, nowMs, updatedRemainingUses],
      );
      await client.query(
        `
          INSERT INTO threshold_wallet_session_consumptions (namespace, session_id, idempotency_key, expires_at_ms)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (namespace, session_id, idempotency_key) DO NOTHING
        `,
        [this.namespace, id, consumeKey, expiresAtMs],
      );
      await client.query('COMMIT');
      return { ok: true, remainingUses: updatedRemainingUses };
    } catch (e: unknown) {
      await client.query('ROLLBACK').catch(() => undefined);
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to consume threshold session',
      );
      return { ok: false, code: 'internal', message: msg };
    } finally {
      client.release();
    }
  }

  async reserveUseCountOnce(
    input: WalletSessionBudgetReserveUseCountInput,
  ): Promise<WalletSessionBudgetReservationResult> {
    const pool = await this.poolPromise;
    const client =
      typeof pool.connect === 'function'
        ? await pool.connect()
        : {
            query: pool.query.bind(pool),
            release: () => undefined,
          };
    const nowMs = Date.now();
    try {
      await client.query('BEGIN');
      const { rows } = await client.query(
        `
          SELECT expires_at_ms, remaining_uses
          FROM threshold_ed25519_sessions
          WHERE namespace = $1 AND kind = $2 AND session_id = $3
          FOR UPDATE
        `,
        [this.namespace, 'wallet_session', input.walletSigningSessionId],
      );
      const session = rows[0];
      if (!session) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
      }
      const expiresAtMs = Number(session.expires_at_ms);
      const committedRemainingUses = Number(session.remaining_uses);
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }
      if (!Number.isFinite(committedRemainingUses)) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'internal', message: 'Postgres returned invalid remainingUses' };
      }
      const parsed = parseBudgetReservationInput(input, expiresAtMs, nowMs);
      if (!parsed.ok) {
        await client.query('ROLLBACK');
        return parsed;
      }
      await this.cleanupExpiredBudgetReservations(client, parsed.value.walletSigningSessionId, nowMs);
      const existing = await client.query(
        `
          SELECT reservation_id, operation_id, request_digest, curve, threshold_session_id,
                 signature_uses, expires_at_ms, status, remaining_uses_after_commit
          FROM threshold_wallet_session_budget_reservations
          WHERE namespace = $1 AND session_id = $2 AND operation_id = $3 AND request_digest = $4
          FOR UPDATE
        `,
        [
          this.namespace,
          parsed.value.walletSigningSessionId,
          parsed.value.operationId,
          parsed.value.requestDigest,
        ],
      );
      const existingRow = existing.rows[0];
      if (existingRow && existingRow.status === 'reserved') {
        const reservation = parsePostgresBudgetReservation(parsed.value.walletSigningSessionId, existingRow);
        if (!reservation) {
          await client.query('ROLLBACK');
          return { ok: false, code: 'internal', message: 'Postgres returned invalid reservation' };
        }
        const reservedUses = await this.activeReservedUses(
          client,
          parsed.value.walletSigningSessionId,
          nowMs,
        );
        await client.query('COMMIT');
        return {
          ok: true,
          reservation,
          remainingUses: committedRemainingUses,
          reservedUses,
          availableUses: Math.max(0, committedRemainingUses - reservedUses),
        };
      }
      if (existingRow) {
        await client.query('ROLLBACK');
        return {
          ok: false,
          code: 'wallet_budget_reservation_mismatch',
          message: 'wallet signing budget operation was already committed',
        };
      }
      const reservedUses = await this.activeReservedUses(
        client,
        parsed.value.walletSigningSessionId,
        nowMs,
      );
      const availableUses = Math.max(0, committedRemainingUses - reservedUses);
      if (availableUses < parsed.value.signatureUses) {
        await client.query('ROLLBACK');
        return inMemoryBudgetReservationUnavailable({
          committedRemainingUses,
          reservedUses,
          signatureUses: parsed.value.signatureUses,
        });
      }
      const reservation: WalletSigningBudgetReservation = {
        kind: 'wallet_signing_budget_reservation_v1',
        walletSigningSessionId: parsed.value.walletSigningSessionId,
        curve: parsed.value.curve,
        thresholdSessionId: parsed.value.thresholdSessionId,
        operationId: parsed.value.operationId,
        requestDigest: parsed.value.requestDigest,
        signatureUses: parsed.value.signatureUses,
        reservationId: createBudgetReservationId(),
        expiresAtMs: parsed.value.expiresAtMs,
      };
      await client.query(
        `
          INSERT INTO threshold_wallet_session_budget_reservations
            (namespace, session_id, reservation_id, operation_id, request_digest, curve,
             threshold_session_id, signature_uses, expires_at_ms, status, created_at_ms, updated_at_ms)
          VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $11)
        `,
        [
          this.namespace,
          reservation.walletSigningSessionId,
          reservation.reservationId,
          reservation.operationId,
          reservation.requestDigest,
          reservation.curve,
          reservation.thresholdSessionId,
          reservation.signatureUses,
          reservation.expiresAtMs,
          'reserved',
          nowMs,
        ],
      );
      await client.query('COMMIT');
      const nextReservedUses = reservedUses + reservation.signatureUses;
      return {
        ok: true,
        reservation,
        remainingUses: committedRemainingUses,
        reservedUses: nextReservedUses,
        availableUses: Math.max(0, committedRemainingUses - nextReservedUses),
      };
    } catch (e: unknown) {
      await client.query('ROLLBACK').catch(() => undefined);
      const msg = errorMessage(e) || 'Failed to reserve threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    } finally {
      client.release();
    }
  }

  async commitReservedUseCountOnce(
    input: WalletSessionBudgetCommitReservedUseCountInput,
  ): Promise<WalletSessionConsumeUsesResult> {
    const parsed = parseBudgetCommitInput(input);
    if (!parsed.ok) return parsed;
    const pool = await this.poolPromise;
    const client =
      typeof pool.connect === 'function'
        ? await pool.connect()
        : {
            query: pool.query.bind(pool),
            release: () => undefined,
          };
    const nowMs = Date.now();
    try {
      await client.query('BEGIN');
      const sessionRows = await client.query(
        `
          SELECT expires_at_ms, remaining_uses
          FROM threshold_ed25519_sessions
          WHERE namespace = $1 AND kind = $2 AND session_id = $3
          FOR UPDATE
        `,
        [this.namespace, 'wallet_session', parsed.value.walletSigningSessionId],
      );
      const session = sessionRows.rows[0];
      if (!session) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
      }
      const sessionExpiresAtMs = Number(session.expires_at_ms);
      const committedRemainingUses = Number(session.remaining_uses);
      if (!Number.isFinite(sessionExpiresAtMs) || sessionExpiresAtMs <= nowMs) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired' };
      }
      if (!Number.isFinite(committedRemainingUses)) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'internal', message: 'Postgres returned invalid remainingUses' };
      }
      const reservationRows = await client.query(
        `
          SELECT reservation_id, operation_id, request_digest, curve, threshold_session_id,
                 signature_uses, expires_at_ms, status, remaining_uses_after_commit
          FROM threshold_wallet_session_budget_reservations
          WHERE namespace = $1 AND session_id = $2 AND reservation_id = $3
          FOR UPDATE
        `,
        [this.namespace, parsed.value.walletSigningSessionId, parsed.value.reservationId],
      );
      const reservation = reservationRows.rows[0];
      if (!reservation) {
        await client.query('ROLLBACK');
        return budgetReservationExpired();
      }
      if (
        reservation.operation_id !== parsed.value.operationId ||
        reservation.request_digest !== parsed.value.requestDigest
      ) {
        await client.query('ROLLBACK');
        return budgetReservationMismatch();
      }
      if (reservation.status === 'committed') {
        const remainingUses = Number(reservation.remaining_uses_after_commit);
        await client.query('COMMIT');
        return Number.isFinite(remainingUses)
          ? { ok: true, remainingUses }
          : { ok: false, code: 'internal', message: 'Postgres returned invalid committed budget' };
      }
      const reservationExpiresAtMs = Number(reservation.expires_at_ms);
      if (!Number.isFinite(reservationExpiresAtMs) || reservationExpiresAtMs <= nowMs) {
        await client.query(
          `
            DELETE FROM threshold_wallet_session_budget_reservations
            WHERE namespace = $1 AND session_id = $2 AND reservation_id = $3
          `,
          [this.namespace, parsed.value.walletSigningSessionId, parsed.value.reservationId],
        );
        await client.query('ROLLBACK');
        return budgetReservationExpired();
      }
      const signatureUses = Number(reservation.signature_uses);
      if (!Number.isFinite(signatureUses) || signatureUses <= 0) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'internal', message: 'Postgres returned invalid reservation uses' };
      }
      if (committedRemainingUses < signatureUses) {
        await client.query('ROLLBACK');
        return budgetExhausted();
      }
      const nextRemainingUses = committedRemainingUses - signatureUses;
      await client.query(
        `
          UPDATE threshold_ed25519_sessions
          SET remaining_uses = $5
          WHERE namespace = $1 AND kind = $2 AND session_id = $3 AND expires_at_ms > $4
        `,
        [
          this.namespace,
          'wallet_session',
          parsed.value.walletSigningSessionId,
          nowMs,
          nextRemainingUses,
        ],
      );
      await client.query(
        `
          UPDATE threshold_wallet_session_budget_reservations
          SET status = $5, remaining_uses_after_commit = $6, updated_at_ms = $7
          WHERE namespace = $1 AND session_id = $2 AND reservation_id = $3 AND status = $4
        `,
        [
          this.namespace,
          parsed.value.walletSigningSessionId,
          parsed.value.reservationId,
          'reserved',
          'committed',
          nextRemainingUses,
          nowMs,
        ],
      );
      await client.query('COMMIT');
      return { ok: true, remainingUses: nextRemainingUses };
    } catch (e: unknown) {
      await client.query('ROLLBACK').catch(() => undefined);
      const msg = errorMessage(e) || 'Failed to commit threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    } finally {
      client.release();
    }
  }

  async releaseReservedUseCount(
    input: WalletSessionBudgetReleaseReservedUseCountInput,
  ): Promise<WalletSessionBudgetReleaseResult> {
    const walletSigningSessionId = normalizeBudgetField(input.walletSigningSessionId);
    const reservationId = normalizeBudgetField(input.reservationId);
    if (!walletSigningSessionId || !reservationId) {
      return {
        ok: false,
        code: 'invalid_budget_request',
        message: 'budget release requires wallet signing session and reservation',
      };
    }
    const pool = await this.poolPromise;
    const client =
      typeof pool.connect === 'function'
        ? await pool.connect()
        : {
            query: pool.query.bind(pool),
            release: () => undefined,
          };
    const nowMs = Date.now();
    try {
      await client.query('BEGIN');
      const sessionRows = await client.query(
        `
          SELECT expires_at_ms, remaining_uses
          FROM threshold_ed25519_sessions
          WHERE namespace = $1 AND kind = $2 AND session_id = $3
          FOR UPDATE
        `,
        [this.namespace, 'wallet_session', walletSigningSessionId],
      );
      const session = sessionRows.rows[0];
      if (!session) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'unauthorized', message: 'threshold session expired or invalid' };
      }
      const committedRemainingUses = Number(session.remaining_uses);
      if (!Number.isFinite(committedRemainingUses)) {
        await client.query('ROLLBACK');
        return { ok: false, code: 'internal', message: 'Postgres returned invalid remainingUses' };
      }
      const deleted = await client.query(
        `
          DELETE FROM threshold_wallet_session_budget_reservations
          WHERE namespace = $1 AND session_id = $2 AND reservation_id = $3 AND status = $4
          RETURNING 1
        `,
        [this.namespace, walletSigningSessionId, reservationId, 'reserved'],
      );
      const reservedUses = await this.activeReservedUses(client, walletSigningSessionId, nowMs);
      await client.query('COMMIT');
      return {
        ok: true,
        released: !!deleted.rows[0],
        remainingUses: committedRemainingUses,
        reservedUses,
        availableUses: Math.max(0, committedRemainingUses - reservedUses),
      };
    } catch (e: unknown) {
      await client.query('ROLLBACK').catch(() => undefined);
      const msg = errorMessage(e) || 'Failed to release threshold session budget';
      return { ok: false, code: 'internal', message: msg };
    } finally {
      client.release();
    }
  }

  async hasConsumedUseCountOnce(
    id: string,
    idempotencyKey: string,
  ): Promise<WalletSessionConsumedUseResult> {
    const consumeKey = normalizeConsumeOnceKey(idempotencyKey);
    if (!consumeKey) return { ok: true, consumed: false };
    const nowMs = Date.now();
    try {
      const pool = await this.poolPromise;
      const { rows } = await pool.query(
        `
          SELECT 1
          FROM threshold_wallet_session_consumptions
          WHERE namespace = $1 AND session_id = $2 AND idempotency_key = $3 AND expires_at_ms > $4
          LIMIT 1
        `,
        [this.namespace, id, consumeKey, nowMs],
      );
      return { ok: true, consumed: !!rows[0] };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to check consumed threshold session operation',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }

  async reserveReplayGuard(
    scopeId: string,
    replayKey: string,
    expiresAtMs: number,
  ): Promise<WalletSessionReplayGuardResult> {
    const scopeKey = normalizeConsumeOnceKey(scopeId);
    const consumeKey = normalizeConsumeOnceKey(replayKey);
    if (!scopeKey || !consumeKey) return replayGuardInvalid();
    const nowMs = Date.now();
    const ttlMs = replayGuardTtlMs(expiresAtMs, nowMs);
    if (ttlMs <= 0) return replayGuardExpired();
    try {
      const pool = await this.poolPromise;
      await pool.query(
        `
          DELETE FROM threshold_wallet_session_consumptions
          WHERE namespace = $1 AND session_id = $2 AND idempotency_key = $3 AND expires_at_ms <= $4
        `,
        [this.namespace, scopeKey, consumeKey, nowMs],
      );
      const { rows } = await pool.query(
        `
          INSERT INTO threshold_wallet_session_consumptions (namespace, session_id, idempotency_key, expires_at_ms)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (namespace, session_id, idempotency_key) DO NOTHING
          RETURNING 1
        `,
        [this.namespace, scopeKey, consumeKey, Math.floor(nowMs + ttlMs)],
      );
      if (!rows[0]) return replayGuardDuplicate();
      return { ok: true };
    } catch (e: unknown) {
      const msg = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'Failed to reserve replay guard',
      );
      return { ok: false, code: 'internal', message: msg };
    }
  }
}

export function createEd25519WalletSessionStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): Ed25519WalletSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEd25519Stores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.walletSessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix =
    toOptionalTrimmedString(config.THRESHOLD_ED25519_WALLET_SESSION_PREFIX) ||
    toThresholdEd25519PrefixFromBase(basePrefix, 'wallet-session') ||
    '';

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ed25519] In-memory wallet session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryEd25519WalletSessionStore({ keyPrefix: envPrefix || undefined });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestEd25519WalletSessionStore({
      url:
        toOptionalTrimmedString(config.url) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token:
        toOptionalTrimmedString(config.token) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ed25519] redis-tcp wallet session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ed25519] redis-tcp wallet session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEd25519WalletSessionStore({ keyPrefix: envPrefix || undefined });
    }
    return new RedisTcpEd25519WalletSessionStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ed25519] postgres wallet session store is not supported in this runtime',
      );
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error(
        '[threshold-ed25519] postgres wallet session store enabled but POSTGRES_URL is not set',
      );
    input.logger.info('[threshold-ed25519] Using Postgres store for Wallet Session records');
    return new PostgresEd25519WalletSessionStore({
      postgresUrl,
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  // Env-shaped config: prefer Redis/Upstash for wallet session storage (TTL + counters) to avoid Postgres churn.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash wallet session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[threshold-ed25519] Using Upstash REST store for Wallet Session records');
    return new UpstashRedisRestEd25519WalletSessionStore({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix: envPrefix || undefined,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ed25519] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEd25519WalletSessionStore({ keyPrefix: envPrefix || undefined });
    }
    input.logger.info('[threshold-ed25519] Using redis-tcp store for Wallet Session records');
    return new RedisTcpEd25519WalletSessionStore({ redisUrl, keyPrefix: envPrefix || undefined });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ed25519] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[threshold-ed25519] Using Postgres store for Wallet Session records');
    return new PostgresEd25519WalletSessionStore({ postgresUrl, namespace: envPrefix || '' });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ed25519] Wallet Session records require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info(
    '[threshold-ed25519] Using in-memory Wallet Session store (non-persistent)',
  );
  return new InMemoryEd25519WalletSessionStore({ keyPrefix: envPrefix || undefined });
}

export function createEcdsaWalletSessionStore(input: {
  config?: ThresholdStoreConfigInput | null;
  logger: NormalizedLogger;
  isNode: boolean;
}): Ed25519WalletSessionStore {
  const doStores = createCloudflareDurableObjectThresholdEcdsaStores({
    config: input.config,
    logger: input.logger,
  });
  if (doStores) return doStores.walletSessionStore;

  const config = (isObject(input.config) ? input.config : {}) as Record<string, unknown>;
  const allowInMemory = toOptionalTrimmedString(config.THRESHOLD_ALLOW_IN_MEMORY_STORES) === '1';
  const requirePersistent = !input.isNode && !allowInMemory;
  const basePrefix = toOptionalTrimmedString(config.THRESHOLD_PREFIX);
  const envPrefix = toThresholdEcdsaWalletSessionPrefix(
    toOptionalTrimmedString(config.THRESHOLD_ECDSA_WALLET_SESSION_PREFIX) ||
      toThresholdEcdsaPrefixFromBase(basePrefix, 'wallet-session'),
  );

  const kind = toOptionalTrimmedString(config.kind);
  if (kind === 'in-memory') {
    if (requirePersistent) {
      throw new Error(
        '[threshold-ecdsa] In-memory wallet session store is not supported in this runtime; configure Upstash/Redis or Durable Objects',
      );
    }
    return new InMemoryEd25519WalletSessionStore({ keyPrefix: envPrefix });
  }
  if (kind === 'upstash-redis-rest') {
    return new UpstashRedisRestEd25519WalletSessionStore({
      url:
        toOptionalTrimmedString(config.url) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL),
      token:
        toOptionalTrimmedString(config.token) ||
        toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'redis-tcp') {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] redis-tcp wallet session store is not supported in this runtime; configure Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] redis-tcp wallet session store is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEd25519WalletSessionStore({ keyPrefix: envPrefix });
    }
    return new RedisTcpEd25519WalletSessionStore({
      redisUrl:
        toOptionalTrimmedString(config.redisUrl) || toOptionalTrimmedString(config.REDIS_URL),
      keyPrefix: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }
  if (kind === 'postgres') {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ecdsa] postgres wallet session store is not supported in this runtime',
      );
    }
    const postgresUrl = getPostgresUrlFromConfig(config);
    if (!postgresUrl)
      throw new Error(
        '[threshold-ecdsa] postgres wallet session store enabled but POSTGRES_URL is not set',
      );
    input.logger.info('[threshold-ecdsa] Using Postgres store for Wallet Session records');
    return new PostgresEd25519WalletSessionStore({
      postgresUrl,
      namespace: toOptionalTrimmedString(config.keyPrefix) || envPrefix,
    });
  }

  // Env-shaped config: prefer Redis/Upstash for wallet session storage (TTL + counters) to avoid Postgres churn.
  const upstashUrl = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_URL);
  const upstashToken = toOptionalTrimmedString(config.UPSTASH_REDIS_REST_TOKEN);
  if (upstashUrl || upstashToken) {
    if (!upstashUrl || !upstashToken) {
      throw new Error(
        'Upstash wallet session store enabled but UPSTASH_REDIS_REST_URL / UPSTASH_REDIS_REST_TOKEN are not both set',
      );
    }
    input.logger.info('[threshold-ecdsa] Using Upstash REST store for Wallet Session records');
    return new UpstashRedisRestEd25519WalletSessionStore({
      url: upstashUrl,
      token: upstashToken,
      keyPrefix: envPrefix,
    });
  }

  const redisUrl = toOptionalTrimmedString(config.REDIS_URL);
  if (redisUrl) {
    if (!input.isNode) {
      if (requirePersistent) {
        throw new Error(
          '[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; use Upstash/Redis REST or Durable Objects',
        );
      }
      input.logger.warn(
        '[threshold-ecdsa] REDIS_URL is set but TCP Redis is not supported in this runtime; falling back to in-memory',
      );
      return new InMemoryEd25519WalletSessionStore({ keyPrefix: envPrefix });
    }
    input.logger.info('[threshold-ecdsa] Using redis-tcp store for Wallet Session records');
    return new RedisTcpEd25519WalletSessionStore({ redisUrl, keyPrefix: envPrefix });
  }

  const postgresUrl = getPostgresUrlFromConfig(config);
  if (postgresUrl) {
    if (!input.isNode) {
      throw new Error(
        '[threshold-ecdsa] POSTGRES_URL is set but Postgres is not supported in this runtime',
      );
    }
    input.logger.info('[threshold-ecdsa] Using Postgres store for Wallet Session records');
    return new PostgresEd25519WalletSessionStore({ postgresUrl, namespace: envPrefix });
  }

  if (requirePersistent) {
    throw new Error(
      '[threshold-ecdsa] Wallet Session records require persistent storage in this runtime; configure UPSTASH_REDIS_REST_URL/UPSTASH_REDIS_REST_TOKEN or Durable Objects',
    );
  }
  input.logger.info(
    '[threshold-ecdsa] Using in-memory Wallet Session store (non-persistent)',
  );
  return new InMemoryEd25519WalletSessionStore({ keyPrefix: envPrefix });
}
