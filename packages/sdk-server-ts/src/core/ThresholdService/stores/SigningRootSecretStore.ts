import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type { CloudflareDurableObjectNamespaceLike } from '../../types';
import {
  normalizeSigningRootSecretShareId,
  type SigningRootSecretShareId,
  type SealedSigningRootSecretShare,
} from '../signingRootSecretShareWires';
import {
  cloneRecord,
  normalizePutInput,
  normalizeSigningRootVersionKey,
  requireSigningRootId,
  signingRootVersionFromKey,
  storedRecordKey,
  type DeleteSigningRootSecretSharesInput,
  type PutSigningRootSecretShareInput,
  type ResolveSigningRootSecretSharesInput,
  type SigningRootSecretStore,
} from './SigningRootSecretStore.shared';

export class InMemorySigningRootSecretStore implements SigningRootSecretStore {
  readonly adapterKind = 'in-memory';
  private readonly records = new Map<string, SealedSigningRootSecretShare>();

  async listSealedSigningRootSecretShares(
    input: ResolveSigningRootSecretSharesInput,
  ): Promise<readonly SealedSigningRootSecretShare[]> {
    const signingRootId = requireSigningRootId(input.signingRootId);
    const signingRootVersionKey = normalizeSigningRootVersionKey(input.signingRootVersion);
    return [...this.records.values()]
      .filter(
        (record) =>
          record.signingRootId === signingRootId &&
          normalizeSigningRootVersionKey(record.signingRootVersion) === signingRootVersionKey,
      )
      .sort((a, b) => a.shareId - b.shareId)
      .map(cloneRecord);
  }

  async putSealedSigningRootSecretShare(input: PutSigningRootSecretShareInput): Promise<void> {
    const normalized = normalizePutInput(input);
    const record: SealedSigningRootSecretShare = {
      signingRootId: normalized.signingRootId,
      shareId: normalized.shareId,
      sealedShare: normalized.sealedShare,
      ...(normalized.signingRootVersion ? { signingRootVersion: normalized.signingRootVersion } : {}),
      ...(normalized.storageId ? { storageId: normalized.storageId } : {}),
      ...(normalized.kekId ? { kekId: normalized.kekId } : {}),
    };
    this.records.set(storedRecordKey(normalized), record);
  }

  async deleteSigningRootSecretShares(input: DeleteSigningRootSecretSharesInput): Promise<void> {
    const signingRootId = requireSigningRootId(input.signingRootId);
    const signingRootVersionKey = normalizeSigningRootVersionKey(input.signingRootVersion);
    for (const [key, record] of this.records.entries()) {
      if (
        record.signingRootId === signingRootId &&
        normalizeSigningRootVersionKey(record.signingRootVersion) === signingRootVersionKey
      ) {
        this.records.delete(key);
      }
    }
  }
}

type DurableObjectStubLike = { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
type DoOk<T> = { ok: true; value: T };
type DoErr = { ok: false; code: string; message: string };
type DoResp<T> = DoOk<T> | DoErr;
type DoRequest =
  | { op: 'get'; key: string }
  | { op: 'set'; key: string; value: unknown; ttlMs?: number }
  | { op: 'del'; key: string };

type SigningRootSecretShareDoRecord = {
  signingRootId: string;
  signingRootVersionKey: string;
  shareId: SigningRootSecretShareId;
  sealedShareB64u: string;
  storageId?: string;
  kekId?: string;
};

type CachedSigningRootSecretShares = {
  readonly expiresAtMs: number;
  readonly records: readonly SealedSigningRootSecretShare[];
};

function isObject(input: unknown): input is Record<string, unknown> {
  return Boolean(input && typeof input === 'object' && !Array.isArray(input));
}

function resolveDoStub(input: {
  namespace: CloudflareDurableObjectNamespaceLike;
  objectName: string;
}): DurableObjectStubLike {
  const id = input.namespace.idFromName(input.objectName);
  return input.namespace.get(id) as DurableObjectStubLike;
}

async function callDo<T>(stub: DurableObjectStubLike, req: DoRequest): Promise<DoResp<T>> {
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(req),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`signing-root share DO store HTTP ${response.status}: ${text}`);
  }
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    throw new Error(`signing-root share DO store returned non-JSON response: ${text}`);
  }
  if (!isObject(parsed)) {
    throw new Error('signing-root share DO store returned invalid JSON shape');
  }
  if (parsed.ok === true) return parsed as DoOk<T>;
  const code = toOptionalTrimmedString(parsed.code) || 'internal';
  const message = toOptionalTrimmedString(parsed.message) || 'signing-root share DO store error';
  return { ok: false, code, message };
}

function parseSigningRootSecretShareDoRecord(raw: unknown): SigningRootSecretShareDoRecord | null {
  if (!isObject(raw)) return null;
  const signingRootId = toOptionalTrimmedString(raw.signingRootId);
  const signingRootVersionKey = typeof raw.signingRootVersionKey === 'string' ? raw.signingRootVersionKey : null;
  const shareId = normalizeSigningRootSecretShareId(raw.shareId);
  const sealedShareB64u = toOptionalTrimmedString(raw.sealedShareB64u);
  if (!signingRootId || signingRootVersionKey === null || !shareId || !sealedShareB64u) return null;
  return {
    signingRootId,
    signingRootVersionKey,
    shareId,
    sealedShareB64u,
    ...(toOptionalTrimmedString(raw.storageId)
      ? { storageId: toOptionalTrimmedString(raw.storageId) }
      : {}),
    ...(toOptionalTrimmedString(raw.kekId) ? { kekId: toOptionalTrimmedString(raw.kekId) } : {}),
  };
}

function normalizeShareIdIndex(raw: unknown): SigningRootSecretShareId[] {
  if (!Array.isArray(raw)) return [];
  const shareIds = raw
    .map((entry) => normalizeSigningRootSecretShareId(entry))
    .filter((entry): entry is SigningRootSecretShareId => entry !== null);
  const uniqueShareIds = Array.from(new Set<SigningRootSecretShareId>(shareIds));
  return uniqueShareIds.sort((a: SigningRootSecretShareId, b: SigningRootSecretShareId) => a - b);
}

function normalizeCacheTtlMs(input: unknown): number {
  if (input === undefined || input === null) return 0;
  const value = Math.floor(Number(input));
  if (!Number.isFinite(value) || value <= 0) return 0;
  return value;
}

export class CloudflareDurableObjectSigningRootSecretStore implements SigningRootSecretStore {
  readonly adapterKind = 'cloudflare-durable-object';
  private readonly stub: DurableObjectStubLike;
  private readonly keyPrefix: string;
  private readonly cacheTtlMs: number;
  private readonly cache = new Map<string, CachedSigningRootSecretShares>();

  constructor(input: {
    readonly namespace: CloudflareDurableObjectNamespaceLike;
    readonly objectName?: string;
    readonly keyPrefix?: string;
    readonly cacheTtlMs?: number;
  }) {
    this.stub = resolveDoStub({
      namespace: input.namespace,
      objectName: toOptionalTrimmedString(input.objectName) || 'threshold-signing-root-secrets',
    });
    this.keyPrefix =
      toOptionalTrimmedString(input.keyPrefix) || 'threshold-prf:signing-root-secret:';
    this.cacheTtlMs = normalizeCacheTtlMs(input.cacheTtlMs);
  }

  private indexKey(input: { readonly signingRootId: string; readonly signingRootVersionKey: string }): string {
    return `${this.keyPrefix}idx:${input.signingRootId}\0${input.signingRootVersionKey}`;
  }

  private recordKey(input: {
    readonly signingRootId: string;
    readonly signingRootVersionKey: string;
    readonly shareId: SigningRootSecretShareId;
  }): string {
    return `${this.keyPrefix}rec:${input.signingRootId}\0${input.signingRootVersionKey}\0${input.shareId}`;
  }

  private cacheKey(input: { readonly signingRootId: string; readonly signingRootVersionKey: string }): string {
    return `${input.signingRootId}\0${input.signingRootVersionKey}`;
  }

  private getCachedRecords(input: {
    readonly signingRootId: string;
    readonly signingRootVersionKey: string;
  }): readonly SealedSigningRootSecretShare[] | null {
    if (this.cacheTtlMs <= 0) return null;
    const key = this.cacheKey(input);
    const cached = this.cache.get(key);
    if (!cached) return null;
    if (cached.expiresAtMs <= Date.now()) {
      this.cache.delete(key);
      return null;
    }
    return cached.records.map(cloneRecord);
  }

  private setCachedRecords(input: {
    readonly signingRootId: string;
    readonly signingRootVersionKey: string;
    readonly records: readonly SealedSigningRootSecretShare[];
  }): void {
    if (this.cacheTtlMs <= 0) return;
    this.cache.set(this.cacheKey(input), {
      expiresAtMs: Date.now() + this.cacheTtlMs,
      records: input.records.map(cloneRecord),
    });
  }

  private invalidateCachedRecords(input: {
    readonly signingRootId: string;
    readonly signingRootVersionKey: string;
  }): void {
    this.cache.delete(this.cacheKey(input));
  }

  async listSealedSigningRootSecretShares(
    input: ResolveSigningRootSecretSharesInput,
  ): Promise<readonly SealedSigningRootSecretShare[]> {
    const signingRootId = requireSigningRootId(input.signingRootId);
    const signingRootVersionKey = normalizeSigningRootVersionKey(input.signingRootVersion);
    const cached = this.getCachedRecords({ signingRootId, signingRootVersionKey });
    if (cached) return cached;

    const index = await callDo<unknown>(this.stub, {
      op: 'get',
      key: this.indexKey({ signingRootId, signingRootVersionKey }),
    });
    if (!index.ok) throw new Error(index.message);

    const records: SealedSigningRootSecretShare[] = [];
    for (const shareId of normalizeShareIdIndex(index.value)) {
      const stored = await callDo<unknown>(this.stub, {
        op: 'get',
        key: this.recordKey({ signingRootId, signingRootVersionKey, shareId }),
      });
      if (!stored.ok || stored.value === null) continue;
      const parsed = parseSigningRootSecretShareDoRecord(stored.value);
      if (!parsed) throw new Error('stored signing-root share has invalid DO record shape');
      records.push({
        signingRootId: parsed.signingRootId,
        shareId: parsed.shareId,
        sealedShare: base64UrlDecode(parsed.sealedShareB64u),
        ...(signingRootVersionFromKey(parsed.signingRootVersionKey)
          ? { signingRootVersion: signingRootVersionFromKey(parsed.signingRootVersionKey) }
          : {}),
        ...(parsed.storageId ? { storageId: parsed.storageId } : {}),
        ...(parsed.kekId ? { kekId: parsed.kekId } : {}),
      });
    }

    const sorted = records.sort((a, b) => a.shareId - b.shareId);
    this.setCachedRecords({ signingRootId, signingRootVersionKey, records: sorted });
    return sorted.map(cloneRecord);
  }

  async putSealedSigningRootSecretShare(input: PutSigningRootSecretShareInput): Promise<void> {
    const normalized = normalizePutInput(input);
    const record: SigningRootSecretShareDoRecord = {
      signingRootId: normalized.signingRootId,
      signingRootVersionKey: normalized.signingRootVersionKey,
      shareId: normalized.shareId,
      sealedShareB64u: base64UrlEncode(normalized.sealedShare),
      ...(normalized.storageId ? { storageId: normalized.storageId } : {}),
      ...(normalized.kekId ? { kekId: normalized.kekId } : {}),
    };
    const recordKey = this.recordKey(normalized);
    const indexKey = this.indexKey(normalized);

    const current = await callDo<unknown>(this.stub, { op: 'get', key: indexKey });
    if (!current.ok) throw new Error(current.message);
    const shareIds = normalizeShareIdIndex(current.value);
    if (!shareIds.includes(normalized.shareId)) shareIds.push(normalized.shareId);
    shareIds.sort((a, b) => a - b);

    const stored = await callDo<boolean>(this.stub, { op: 'set', key: recordKey, value: record });
    if (!stored.ok) throw new Error(stored.message);
    const indexed = await callDo<boolean>(this.stub, { op: 'set', key: indexKey, value: shareIds });
    if (!indexed.ok) throw new Error(indexed.message);
    this.invalidateCachedRecords(normalized);
  }

  async deleteSigningRootSecretShares(input: DeleteSigningRootSecretSharesInput): Promise<void> {
    const signingRootId = requireSigningRootId(input.signingRootId);
    const signingRootVersionKey = normalizeSigningRootVersionKey(input.signingRootVersion);
    const indexKey = this.indexKey({ signingRootId, signingRootVersionKey });
    const current = await callDo<unknown>(this.stub, { op: 'get', key: indexKey });
    if (!current.ok) throw new Error(current.message);
    for (const shareId of normalizeShareIdIndex(current.value)) {
      const deleted = await callDo<boolean>(this.stub, {
        op: 'del',
        key: this.recordKey({ signingRootId, signingRootVersionKey, shareId }),
      });
      if (!deleted.ok) throw new Error(deleted.message);
    }
    const deletedIndex = await callDo<boolean>(this.stub, { op: 'del', key: indexKey });
    if (!deletedIndex.ok) throw new Error(deletedIndex.message);
    this.invalidateCachedRecords({ signingRootId, signingRootVersionKey });
  }
}
