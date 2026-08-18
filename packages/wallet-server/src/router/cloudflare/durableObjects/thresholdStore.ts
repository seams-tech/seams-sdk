// Durable Object implementation for threshold signing state.
//
// This is exported from the SDK so Cloudflare Worker hosts can bind it directly
// (by re-exporting from their Worker entrypoint) without vendoring the code.

import { isPlainObject } from '@shared/utils/validation';
import {
  parseEcdsaWalletSessionRecord,
  parseRouterAbEcdsaDerivationPoolFillSessionRecord as parseFullRouterAbEcdsaDerivationPoolFillSessionRecord,
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
  | { op: 'readVersionedJson'; key: string }
  | {
      op: 'putVersionedJson';
      key: string;
      expectedVersion: string | null;
      value: unknown;
      ttlMs?: number;
    }
  | {
      op: 'getdelIfRelatedMatches';
      key: string;
      relatedKey: string;
      expectedRelated: unknown;
    }
  | {
      op: 'walletTakeEcdsaPendingSessionActivationPair';
      recoveryKey: string;
      refreshKey: string;
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
  | { op: 'authGetSessionStatus'; key: string }
  | { op: 'authReserveReplayGuard'; key: string; expiresAtMs: number }
  | {
      op: 'registrationCancelTerminal';
      ceremonyKey: string;
      registrationCeremonyId: string;
      walletId: string;
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
  | { op: 'routerAbEcdsaDerivationPoolFillLiveSessionDelete'; presignSessionId: string };

type AuthEntry = {
  record: Record<string, unknown> & { expiresAtMs: number };
  remainingUses: number;
  expiresAtMs: number;
  consumedIdempotencyKeys?: Record<string, true>;
};

const ECDSA_SHARED_IDENTITY_CONFLICT_MESSAGE =
  '[threshold-ecdsa] EVM-family key identity already exists for wallet/subject/rp/signing root';
const ECDSA_KEY_HANDLE_CONFLICT_MESSAGE =
  '[threshold-ecdsa] ECDSA key handle already exists in this namespace';

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

type VersionedJsonRecordEnvelope = {
  readonly kind: 'cloudflare_versioned_json_record_v1';
  readonly version: string;
  readonly value: unknown;
};

function isJsonValue(value: unknown): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every((entry) => isJsonValue(entry));
  if (!isPlainObject(value)) return false;
  return Object.values(value).every((entry) => isJsonValue(entry));
}

function isVersionedJsonRecordEnvelope(value: unknown): value is VersionedJsonRecordEnvelope {
  return (
    isPlainObject(value) &&
    value.kind === 'cloudflare_versioned_json_record_v1' &&
    typeof value.version === 'string' &&
    value.version.length > 0 &&
    isJsonValue(value.value)
  );
}

function newVersionedJsonRecordVersion(): string {
  const version = crypto.randomUUID();
  if (!version) throw new Error('Unable to create versioned JSON record version');
  return version;
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
  if (typeof rec.relayerKeyId !== 'string') return null;
  return raw as AuthEntry;
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
    if (op === 'readVersionedJson') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const stored = await this.state.storage.get(key);
      if (stored === null || stored === undefined) return json(ok({ status: 'missing' }));
      if (!isVersionedJsonRecordEnvelope(stored)) {
        return json(ok({ status: 'invalid_record' }));
      }
      return json(
        ok({
          status: 'present',
          value: stored.value,
          version: stored.version,
        }),
      );
    }
    if (op === 'putVersionedJson') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const expectedVersion = (req as { expectedVersion?: unknown }).expectedVersion;
      if (expectedVersion !== null && typeof expectedVersion !== 'string') {
        return json(err('invalid_body', 'expectedVersion must be null or a non-empty string'));
      }
      if (typeof expectedVersion === 'string' && !toKey(expectedVersion)) {
        return json(err('invalid_body', 'expectedVersion must be null or a non-empty string'));
      }
      const value = (req as { value?: unknown }).value;
      if (!isJsonValue(value)) return json(err('invalid_body', 'value must be JSON serializable'));
      const ttl = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      const result = await withRequiredTxn(this.state, async (store) => {
        const current = await store.get(key);
        if (current === null || current === undefined) {
          if (expectedVersion !== null) return { status: 'version_mismatch' };
        } else {
          if (!isVersionedJsonRecordEnvelope(current)) return { status: 'invalid_record' };
          if (expectedVersion !== current.version) return { status: 'version_mismatch' };
        }
        const version = newVersionedJsonRecordVersion();
        await store.put(
          key,
          {
            kind: 'cloudflare_versioned_json_record_v1',
            version,
            value,
          } satisfies VersionedJsonRecordEnvelope,
          ttl ? { expirationTtl: ttl } : undefined,
        );
        return { status: 'stored', version };
      });
      return json(ok(result));
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
    if (op === 'walletTakeEcdsaPendingSessionActivationPair') {
      const recoveryKey = toKey((req as { recoveryKey?: unknown }).recoveryKey);
      const refreshKey = toKey((req as { refreshKey?: unknown }).refreshKey);
      if (!recoveryKey) return json(err('invalid_body', 'Missing recoveryKey'));
      if (!refreshKey) return json(err('invalid_body', 'Missing refreshKey'));
      if (recoveryKey === refreshKey) {
        return json(err('invalid_body', 'Recovery and refresh keys must be distinct'));
      }
      const value = await withRequiredTxn(this.state, async (store) => {
        const recovery = await store.get(recoveryKey);
        const refresh = await store.get(refreshKey);
        if (
          recovery === null ||
          recovery === undefined ||
          refresh === null ||
          refresh === undefined
        ) {
          return null;
        }
        await store.delete(recoveryKey);
        await store.delete(refreshKey);
        return { recovery, refresh };
      });
      return json(ok(value));
    }

    if (op === 'registrationCancelTerminal') {
      const ceremonyKey = toKey((req as { ceremonyKey?: unknown }).ceremonyKey);
      const registrationCeremonyId = toKey(
        (req as { registrationCeremonyId?: unknown }).registrationCeremonyId,
      );
      const walletId = toKey((req as { walletId?: unknown }).walletId);
      if (!ceremonyKey) {
        return json(err('invalid_body', 'Missing terminal registration ceremony key'));
      }
      if (!registrationCeremonyId) {
        return json(err('invalid_body', 'Missing terminal registration ceremony ID'));
      }
      if (!walletId) return json(err('invalid_body', 'Missing terminal registration walletId'));
      const result = await withRequiredTxn(this.state, async (store) => {
        const ceremony = await store.get(ceremonyKey);
        if (ceremony === null || ceremony === undefined) {
          return ok({
            kind: 'not_found',
            ceremonyDeleted: false,
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
        await store.delete(ceremonyKey);
        return ok({
          kind: 'cancelled',
          ceremonyDeleted: true,
        });
      });
      return json(result);
    }

    if (op === 'authConsumeUseCount') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));

      const res: DoResp<unknown> = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        const entry = parseAuthEntry(raw);
        if (!entry) return err('wallet_session_missing', 'Wallet Session is missing');

        if (entry.expiresAtMs <= Date.now()) {
          await store.delete(key);
          return err('wallet_session_expired', 'Wallet Session expired');
        }
        if (entry.remainingUses <= 0) {
          return err('wallet_budget_exhausted', 'Wallet Session exhausted');
        }

        entry.remainingUses -= 1;
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
        if (!entry) return err('wallet_session_missing', 'Wallet Session is missing');

        if (entry.expiresAtMs <= Date.now()) {
          await store.delete(key);
          return err('wallet_session_expired', 'Wallet Session expired');
        }

        const consumedIdempotencyKeys = entry.consumedIdempotencyKeys || {};
        if (consumedIdempotencyKeys[idempotencyKey]) {
          return ok({ remainingUses: entry.remainingUses });
        }

        if (entry.remainingUses <= 0) {
          return err('wallet_budget_exhausted', 'Wallet Session exhausted');
        }

        entry.remainingUses -= 1;
        entry.consumedIdempotencyKeys = {
          ...consumedIdempotencyKeys,
          [idempotencyKey]: true,
        };
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
        if (!entry) return err('wallet_session_missing', 'Wallet Session is missing');

        if (entry.expiresAtMs <= Date.now()) {
          await store.delete(key);
          return err('wallet_session_expired', 'Wallet Session expired');
        }

        const consumedIdempotencyKeys = entry.consumedIdempotencyKeys || {};
        return ok({ consumed: consumedIdempotencyKeys[idempotencyKey] === true });
      });

      return json(res);
    }

    if (op === 'authGetSessionStatus') {
      const key = toKey((req as { key?: unknown }).key);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const entry = parseAuthEntry(await this.state.storage.get(key));
      if (!entry) return json(err('wallet_session_missing', 'Wallet Session is missing'));
      if (entry.expiresAtMs <= Date.now()) {
        await this.state.storage.delete(key);
        return json(err('wallet_session_expired', 'Wallet Session expired'));
      }
      return json(ok({
        record: entry.record,
        expiresAtMs: entry.expiresAtMs,
        remainingUses: entry.remainingUses,
      }));
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
