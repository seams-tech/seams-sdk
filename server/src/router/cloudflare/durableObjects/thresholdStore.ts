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
  type SigningRootRecord,
  type SigningRootRecordResult,
} from '../../../core/ThresholdService/signingRootRecords';
import { parseThresholdEd25519PresignRecord } from '../../../core/ThresholdService/validation';

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
  | { op: 'authReserveReplayGuard'; key: string; expiresAtMs: number }
  | { op: 'ecdsaPresignPut'; listKey: string; value: unknown }
  | { op: 'ecdsaPresignReserve'; listKey: string; reservedKeyPrefix: string; ttlMs?: number }
  | {
      op: 'ecdsaPresignReserveById';
      listKey: string;
      reservedKeyPrefix: string;
      presignatureId: string;
      ttlMs?: number;
    }
  | { op: 'ecdsaPresignSessionCreate'; key: string; value: unknown; ttlMs?: number }
  | {
      op: 'ecdsaPresignSessionAdvanceCas';
      key: string;
      expectedVersion: number;
      value: unknown;
      ttlMs?: number;
    }
  | {
      op: 'ed25519PresignCheckCapacity';
      capacity: unknown;
      walletIndexKey: string;
      globalIndexKey: string;
    }
  | {
      op: 'ed25519PresignConsumeRateLimit';
      key: string;
      cost: unknown;
      policy: unknown;
    }
  | {
      op: 'ed25519PresignPutWithCapacity';
      key: string;
      presignId: string;
      value: unknown;
      ttlMs?: number;
      capacity: unknown;
      walletIndexKey: string;
      globalIndexKey: string;
    }
  | {
      op: 'ed25519PresignTake';
      key: string;
      presignId: string;
      expectedScope: unknown;
      walletIndexKey: string;
      globalIndexKey: string;
    }
  | { op: 'signingRootPut'; record: unknown }
  | { op: 'signingRootGet'; signingRootId: string; signingRootVersion: string }
  | { op: 'signingRootDelete'; signingRootId: string; signingRootVersion: string }
  | { op: 'signingRootStatus'; signingRootId: string; signingRootVersion: string };

type AuthEntry = {
  record: {
    expiresAtMs: number;
    relayerKeyId: string;
    userId: string;
    rpId: string;
    participantIds: number[];
  };
  remainingUses: number;
  expiresAtMs: number;
  consumedIdempotencyKeys?: Record<string, true>;
};

type PresignSessionRecord = {
  expiresAtMs: number;
  version: number;
};

type Ed25519PresignIndexEntry = {
  presignId: string;
  key: string;
  expiresAtMs: number;
};

type Ed25519PresignRateLimitEntry = {
  kind: 'threshold_ed25519_presign_refill_rate_limit_v1';
  count: number;
  expiresAtMs: number;
};

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
  rpId: string;
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
    rpId: record.rpId,
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
    rpId: record.rpId,
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
  if (
    typeof rec.userId !== 'string' ||
    typeof rec.rpId !== 'string' ||
    typeof rec.relayerKeyId !== 'string'
  )
    return null;
  if (typeof rec.expiresAtMs !== 'number' || !Number.isFinite(rec.expiresAtMs)) return null;
  if (!Array.isArray(rec.participantIds)) return null;
  return raw as AuthEntry;
}

function parsePresignSessionRecord(raw: unknown): PresignSessionRecord | null {
  if (!isPlainObject(raw)) return null;
  const expiresAtMs = (raw as { expiresAtMs?: unknown }).expiresAtMs;
  const version = (raw as { version?: unknown }).version;
  if (typeof expiresAtMs !== 'number' || !Number.isFinite(expiresAtMs)) return null;
  if (typeof version !== 'number' || !Number.isFinite(version)) return null;
  return { expiresAtMs, version };
}

function parsePositiveInteger(value: unknown): number | null {
  const parsed = Math.floor(Number(value));
  if (!Number.isSafeInteger(parsed) || parsed < 1) return null;
  return parsed;
}

function parseEd25519PresignRateLimitEntry(
  raw: unknown,
  nowMs: number,
): Ed25519PresignRateLimitEntry | null {
  if (!isPlainObject(raw)) return null;
  if (raw.kind !== 'threshold_ed25519_presign_refill_rate_limit_v1') return null;
  const count = Number(raw.count);
  const expiresAtMs = Number(raw.expiresAtMs);
  if (!Number.isFinite(count) || count < 0) return null;
  if (!Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) return null;
  return { kind: 'threshold_ed25519_presign_refill_rate_limit_v1', count, expiresAtMs };
}

function parseEd25519PresignIndex(raw: unknown, nowMs: number): Ed25519PresignIndexEntry[] {
  if (!Array.isArray(raw)) return [];
  const out: Ed25519PresignIndexEntry[] = [];
  for (const item of raw) {
    if (!isPlainObject(item)) continue;
    const presignId = toKey(item.presignId);
    const key = toKey(item.key);
    const expiresAtMs = Number(item.expiresAtMs);
    if (!presignId || !key || !Number.isFinite(expiresAtMs) || expiresAtMs <= nowMs) continue;
    out.push({ presignId, key, expiresAtMs });
  }
  return out;
}

function withoutEd25519PresignIndexEntry(
  entries: readonly Ed25519PresignIndexEntry[],
  presignId: string,
): Ed25519PresignIndexEntry[] {
  return entries.filter((entry) => entry.presignId !== presignId);
}

function scopeString(value: unknown): string {
  return String(value ?? '').trim();
}

function scopeParticipantIdsMatch(left: unknown, right: unknown): boolean {
  if (!Array.isArray(left) || !Array.isArray(right)) return false;
  return (
    left.length === right.length &&
    left.every((id, index) => Number(id) === Number((right as unknown[])[index]))
  );
}

function scopeRuntimePolicyMatches(left: unknown, right: unknown): boolean {
  if (!isPlainObject(left) || !isPlainObject(right)) return false;
  return (
    scopeString(left.orgId) === scopeString(right.orgId) &&
    scopeString(left.projectId) === scopeString(right.projectId) &&
    scopeString(left.envId) === scopeString(right.envId) &&
    scopeString(left.signingRootVersion) === scopeString(right.signingRootVersion)
  );
}

function ed25519PresignRecordMatchesExpectedScope(record: unknown, expected: unknown): boolean {
  if (!isPlainObject(record) || !isPlainObject(expected)) return false;
  return (
    scopeString(record.thresholdSessionId) === scopeString(expected.thresholdSessionId) &&
    scopeString(record.walletSigningSessionId) === scopeString(expected.walletSigningSessionId) &&
    scopeString(record.relayerKeyId) === scopeString(expected.relayerKeyId) &&
    scopeString(record.nearAccountId) === scopeString(expected.nearAccountId) &&
    scopeString(record.nearNetworkId) === scopeString(expected.nearNetworkId) &&
    scopeString(record.signerPublicKey) === scopeString(expected.signerPublicKey) &&
    scopeString(record.rpcPolicyId) === scopeString(expected.rpcPolicyId) &&
    scopeString(record.rpId) === scopeString(expected.rpId) &&
    scopeString(record.groupPublicKey) === scopeString(expected.groupPublicKey) &&
    scopeRuntimePolicyMatches(record.runtimePolicyScope, expected.runtimePolicyScope) &&
    scopeParticipantIdsMatch(record.participantIds, expected.participantIds)
  );
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

export class ThresholdStoreDurableObject {
  private readonly state: DurableObjectStateLike;

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
      await this.state.storage.delete(key);
      return json(ok(true));
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
        if (entry.remainingUses <= 0) return err('unauthorized', 'threshold session exhausted');

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
        if (!entry) return err('unauthorized', 'threshold session expired or invalid');

        if (Date.now() > entry.expiresAtMs) {
          await store.delete(key);
          return err('unauthorized', 'threshold session expired');
        }

        const consumedIdempotencyKeys = entry.consumedIdempotencyKeys || {};
        if (consumedIdempotencyKeys[idempotencyKey]) {
          return ok({ remainingUses: entry.remainingUses });
        }

        if (entry.remainingUses <= 0) return err('unauthorized', 'threshold session exhausted');

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

    if (op === 'ecdsaPresignPut') {
      const listKey = toKey((req as { listKey?: unknown }).listKey);
      if (!listKey) return json(err('invalid_body', 'Missing listKey'));
      const value = (req as { value?: unknown }).value;
      await withTxn(this.state, async (store) => {
        const raw = await store.get(listKey);
        const list = Array.isArray(raw) ? [...raw] : [];
        list.push(value);
        await store.put(listKey, list);
      });
      return json(ok(true));
    }

    if (op === 'ecdsaPresignReserve') {
      const listKey = toKey((req as { listKey?: unknown }).listKey);
      const reservedKeyPrefix = toKey((req as { reservedKeyPrefix?: unknown }).reservedKeyPrefix);
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs) || 120;
      if (!listKey) return json(err('invalid_body', 'Missing listKey'));
      if (!reservedKeyPrefix) return json(err('invalid_body', 'Missing reservedKeyPrefix'));

      const value = await withTxn(this.state, async (store) => {
        const raw = await store.get(listKey);
        const list = Array.isArray(raw) ? [...raw] : [];
        if (!list.length) return null;
        const item = list.shift();
        await store.put(listKey, list);

        const presignatureId = isPlainObject(item)
          ? toKey((item as { presignatureId?: unknown }).presignatureId)
          : '';
        if (presignatureId) {
          await store.put(`${reservedKeyPrefix}${presignatureId}`, item, {
            expirationTtl: ttlSeconds,
          });
        }
        return item ?? null;
      });

      return json(ok(value));
    }

    if (op === 'ecdsaPresignReserveById') {
      const listKey = toKey((req as { listKey?: unknown }).listKey);
      const reservedKeyPrefix = toKey((req as { reservedKeyPrefix?: unknown }).reservedKeyPrefix);
      const presignatureId = toKey((req as { presignatureId?: unknown }).presignatureId);
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs) || 120;
      if (!listKey) return json(err('invalid_body', 'Missing listKey'));
      if (!reservedKeyPrefix) return json(err('invalid_body', 'Missing reservedKeyPrefix'));
      if (!presignatureId) return json(err('invalid_body', 'Missing presignatureId'));

      const value = await withTxn(this.state, async (store) => {
        const raw = await store.get(listKey);
        const list = Array.isArray(raw) ? [...raw] : [];
        if (!list.length) return null;
        let pickedIndex = -1;
        for (let i = 0; i < list.length; i += 1) {
          const item = list[i];
          const itemPresignatureId = isPlainObject(item)
            ? toKey((item as { presignatureId?: unknown }).presignatureId)
            : '';
          if (itemPresignatureId === presignatureId) {
            pickedIndex = i;
            break;
          }
        }
        if (pickedIndex < 0) return null;
        const [item] = list.splice(pickedIndex, 1);
        await store.put(listKey, list);
        await store.put(`${reservedKeyPrefix}${presignatureId}`, item, {
          expirationTtl: ttlSeconds,
        });
        return item ?? null;
      });

      return json(ok(value));
    }

    if (op === 'ecdsaPresignSessionCreate') {
      const key = toKey((req as { key?: unknown }).key);
      const value = (req as { value?: unknown }).value;
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!parsePresignSessionRecord(value))
        return json(err('invalid_body', 'Invalid presign session record'));

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const existingRaw = await store.get(key);
        if (existingRaw !== null && existingRaw !== undefined) {
          const existing = parsePresignSessionRecord(existingRaw);
          if (!existing || existing.expiresAtMs > nowMs) {
            return { status: 'exists' };
          }
        }
        await store.put(key, value, ttlSeconds ? { expirationTtl: ttlSeconds } : undefined);
        return { status: 'ok' };
      });

      return json(ok(result));
    }

    if (op === 'ecdsaPresignSessionAdvanceCas') {
      const key = toKey((req as { key?: unknown }).key);
      const expectedVersionRaw = (req as { expectedVersion?: unknown }).expectedVersion;
      const value = (req as { value?: unknown }).value;
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      if (!key) return json(err('invalid_body', 'Missing key'));
      const expectedVersion = Math.floor(Number(expectedVersionRaw));
      if (!Number.isFinite(expectedVersion) || expectedVersion < 1) {
        return json(err('invalid_body', 'Invalid expectedVersion'));
      }
      const nextRecord = parsePresignSessionRecord(value);
      if (!nextRecord) return json(err('invalid_body', 'Invalid presign session record'));

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const existingRaw = await store.get(key);
        if (existingRaw === null || existingRaw === undefined) return { status: 'not_found' };
        const existing = parsePresignSessionRecord(existingRaw);
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

    if (op === 'ed25519PresignCheckCapacity') {
      const walletIndexKey = toKey((req as { walletIndexKey?: unknown }).walletIndexKey);
      const globalIndexKey = toKey((req as { globalIndexKey?: unknown }).globalIndexKey);
      const capacity = (req as { capacity?: unknown }).capacity;
      const walletMax = isPlainObject(capacity)
        ? parsePositiveInteger(capacity.walletSigningSessionMax)
        : null;
      const globalMax = isPlainObject(capacity) ? parsePositiveInteger(capacity.globalMax) : null;
      if (!walletIndexKey) return json(err('invalid_body', 'Missing walletIndexKey'));
      if (!globalIndexKey) return json(err('invalid_body', 'Missing globalIndexKey'));
      if (!walletMax || !globalMax) return json(err('invalid_body', 'Invalid capacity'));

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const walletIndex = parseEd25519PresignIndex(await store.get(walletIndexKey), nowMs);
        const globalIndex = parseEd25519PresignIndex(await store.get(globalIndexKey), nowMs);
        await store.put(walletIndexKey, walletIndex);
        await store.put(globalIndexKey, globalIndex);
        return walletIndex.length >= walletMax || globalIndex.length >= globalMax
          ? { ok: false as const, code: 'capacity_exceeded' as const }
          : { ok: true as const };
      });

      return json(ok(result));
    }

    if (op === 'ed25519PresignConsumeRateLimit') {
      const key = toKey((req as { key?: unknown }).key);
      const cost = parsePositiveInteger((req as { cost?: unknown }).cost);
      const policy = (req as { policy?: unknown }).policy;
      const windowMs = isPlainObject(policy) ? parsePositiveInteger(policy.windowMs) : null;
      const maxCost = isPlainObject(policy) ? parsePositiveInteger(policy.maxCost) : null;
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!cost) return json(err('invalid_body', 'Invalid cost'));
      if (!windowMs || !maxCost) return json(err('invalid_body', 'Invalid rate limit policy'));

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const existing = parseEd25519PresignRateLimitEntry(await store.get(key), nowMs);
        const nextCount = (existing?.count ?? 0) + cost;
        if (nextCount > maxCost) return { ok: false as const, code: 'rate_limited' as const };
        const expiresAtMs = existing?.expiresAtMs ?? nowMs + windowMs;
        const ttl = toTtlSeconds(expiresAtMs - nowMs);
        await store.put(
          key,
          {
            kind: 'threshold_ed25519_presign_refill_rate_limit_v1',
            count: nextCount,
            expiresAtMs,
          } satisfies Ed25519PresignRateLimitEntry,
          ttl ? { expirationTtl: ttl } : undefined,
        );
        return { ok: true as const };
      });

      return json(ok(result));
    }

    if (op === 'ed25519PresignPutWithCapacity') {
      const key = toKey((req as { key?: unknown }).key);
      const presignId = toKey((req as { presignId?: unknown }).presignId);
      const walletIndexKey = toKey((req as { walletIndexKey?: unknown }).walletIndexKey);
      const globalIndexKey = toKey((req as { globalIndexKey?: unknown }).globalIndexKey);
      const ttlSeconds = toTtlSeconds((req as { ttlMs?: unknown }).ttlMs);
      const parsed = parseThresholdEd25519PresignRecord((req as { value?: unknown }).value);
      const capacity = (req as { capacity?: unknown }).capacity;
      const walletMax = isPlainObject(capacity)
        ? parsePositiveInteger(capacity.walletSigningSessionMax)
        : null;
      const globalMax = isPlainObject(capacity) ? parsePositiveInteger(capacity.globalMax) : null;
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!presignId) return json(err('invalid_body', 'Missing presignId'));
      if (!walletIndexKey) return json(err('invalid_body', 'Missing walletIndexKey'));
      if (!globalIndexKey) return json(err('invalid_body', 'Missing globalIndexKey'));
      if (!parsed) return json(err('invalid_body', 'Invalid Ed25519 presign record'));
      if (!walletMax || !globalMax) return json(err('invalid_body', 'Invalid capacity'));

      const result = await withTxn(this.state, async (store) => {
        const nowMs = Date.now();
        const walletIndex = parseEd25519PresignIndex(await store.get(walletIndexKey), nowMs);
        const globalIndex = parseEd25519PresignIndex(await store.get(globalIndexKey), nowMs);
        const existing = await store.get(key);
        if (existing === null || existing === undefined) {
          if (walletIndex.length >= walletMax || globalIndex.length >= globalMax) {
            await store.put(walletIndexKey, walletIndex);
            await store.put(globalIndexKey, globalIndex);
            return { ok: false as const, code: 'capacity_exceeded' };
          }
        }
        const entry: Ed25519PresignIndexEntry = { presignId, key, expiresAtMs: parsed.expiresAtMs };
        const nextWalletIndex = [...withoutEd25519PresignIndexEntry(walletIndex, presignId), entry];
        const nextGlobalIndex = [...withoutEd25519PresignIndexEntry(globalIndex, presignId), entry];
        await store.put(key, parsed, ttlSeconds ? { expirationTtl: ttlSeconds } : undefined);
        await store.put(
          walletIndexKey,
          nextWalletIndex,
          ttlSeconds ? { expirationTtl: ttlSeconds } : undefined,
        );
        await store.put(
          globalIndexKey,
          nextGlobalIndex,
          ttlSeconds ? { expirationTtl: ttlSeconds } : undefined,
        );
        return { ok: true as const };
      });

      return json(ok(result));
    }

    if (op === 'ed25519PresignTake') {
      const key = toKey((req as { key?: unknown }).key);
      const presignId = toKey((req as { presignId?: unknown }).presignId);
      const walletIndexKey = toKey((req as { walletIndexKey?: unknown }).walletIndexKey);
      const globalIndexKey = toKey((req as { globalIndexKey?: unknown }).globalIndexKey);
      const expectedScope = (req as { expectedScope?: unknown }).expectedScope;
      if (!key) return json(err('invalid_body', 'Missing key'));
      if (!presignId) return json(err('invalid_body', 'Missing presignId'));
      if (!walletIndexKey) return json(err('invalid_body', 'Missing walletIndexKey'));
      if (!globalIndexKey) return json(err('invalid_body', 'Missing globalIndexKey'));
      if (!isPlainObject(expectedScope)) return json(err('invalid_body', 'Invalid expectedScope'));

      const result = await withTxn(this.state, async (store) => {
        const raw = await store.get(key);
        if (raw === null || raw === undefined) return { ok: false as const, code: 'not_found' };

        const parsed = parseThresholdEd25519PresignRecord(raw);
        if (!parsed) {
          await store.delete(key);
          const nowMs = Date.now();
          await store.put(
            walletIndexKey,
            withoutEd25519PresignIndexEntry(
              parseEd25519PresignIndex(await store.get(walletIndexKey), nowMs),
              presignId,
            ),
          );
          await store.put(
            globalIndexKey,
            withoutEd25519PresignIndexEntry(
              parseEd25519PresignIndex(await store.get(globalIndexKey), nowMs),
              presignId,
            ),
          );
          return { ok: false as const, code: 'invalid_record' };
        }
        if (parsed.expiresAtMs <= Date.now()) {
          await store.delete(key);
          const nowMs = Date.now();
          await store.put(
            walletIndexKey,
            withoutEd25519PresignIndexEntry(
              parseEd25519PresignIndex(await store.get(walletIndexKey), nowMs),
              presignId,
            ),
          );
          await store.put(
            globalIndexKey,
            withoutEd25519PresignIndexEntry(
              parseEd25519PresignIndex(await store.get(globalIndexKey), nowMs),
              presignId,
            ),
          );
          return { ok: false as const, code: 'expired' };
        }
        if (!ed25519PresignRecordMatchesExpectedScope(parsed, expectedScope)) {
          return { ok: false as const, code: 'scope_mismatch' };
        }
        await store.delete(key);
        const nowMs = Date.now();
        await store.put(
          walletIndexKey,
          withoutEd25519PresignIndexEntry(
            parseEd25519PresignIndex(await store.get(walletIndexKey), nowMs),
            presignId,
          ),
        );
        await store.put(
          globalIndexKey,
          withoutEd25519PresignIndexEntry(
            parseEd25519PresignIndex(await store.get(globalIndexKey), nowMs),
            presignId,
          ),
        );
        return { ok: true as const, record: parsed };
      });

      return json(ok(result));
    }

    return json(err('invalid_body', `Unknown op: ${op}`));
  }
}
