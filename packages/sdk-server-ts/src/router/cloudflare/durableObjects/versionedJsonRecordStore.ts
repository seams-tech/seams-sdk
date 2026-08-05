import { isPlainObject, toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../../core/types';
import type {
  VersionedJsonObject,
  VersionedJsonRecordPutResult,
  VersionedJsonRecordReadResult,
  VersionedJsonValue,
} from '../../framework/versionedJsonRecordStore';

export type CloudflareVersionedJsonRecordStoreOptions<T> = {
  readonly namespace: CloudflareDurableObjectNamespaceLike;
  /** Return one object name per ceremony key to avoid tenant-wide serialization. */
  readonly objectNameForKey: (key: string) => string;
  readonly encode: (value: T) => VersionedJsonObject;
  readonly parse: (raw: unknown) => T | null;
  readonly keyPrefix?: string;
};

type VersionedJsonReadResponse =
  | { readonly status: 'missing' }
  | { readonly status: 'present'; readonly value: unknown; readonly version: string }
  | { readonly status: 'invalid_record' };

type VersionedJsonPutResponse =
  | { readonly status: 'stored'; readonly version: string }
  | { readonly status: 'version_mismatch' }
  | { readonly status: 'invalid_record' };

type VersionedJsonDoResponse =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly code: string; readonly message: string };

export class CloudflareVersionedJsonRecordStoreError extends Error {
  readonly code: 'invalid_response' | 'invalid_record' | 'request_failed';

  constructor(code: 'invalid_response' | 'invalid_record' | 'request_failed', message: string) {
    super(message);
    this.name = 'CloudflareVersionedJsonRecordStoreError';
    this.code = code;
  }
}

export class CloudflareDurableObjectVersionedJsonRecordStore<T> {
  private readonly namespace: CloudflareDurableObjectNamespaceLike;
  private readonly objectNameForKey: (key: string) => string;
  private readonly encode: (value: T) => VersionedJsonObject;
  private readonly parse: (raw: unknown) => T | null;
  private readonly keyPrefix: string;

  constructor(options: CloudflareVersionedJsonRecordStoreOptions<T>) {
    if (!isDurableObjectNamespaceLike(options.namespace)) {
      throw new Error('Cloudflare Durable Object namespace is required');
    }
    if (typeof options.objectNameForKey !== 'function') {
      throw new Error('Cloudflare versioned JSON object-name resolver is required');
    }
    if (typeof options.encode !== 'function' || typeof options.parse !== 'function') {
      throw new Error('Cloudflare versioned JSON encoder and parser are required');
    }
    this.namespace = options.namespace;
    this.objectNameForKey = options.objectNameForKey;
    this.encode = options.encode;
    this.parse = options.parse;
    this.keyPrefix = normalizeKeyPrefix(options.keyPrefix);
  }

  async read(key: string): Promise<VersionedJsonRecordReadResult<T>> {
    const recordKey = normalizeRecordKey(key);
    const storageKey = this.storageKey(recordKey);
    const response = await this.call(recordKey, {
      op: 'readVersionedJson',
      key: storageKey,
    });
    if (!response.ok) throw requestFailure(response.message);
    const parsed = parseVersionedJsonReadResponse(response.value);
    if (!parsed) throw invalidResponseFailure('Versioned JSON read response is invalid');
    switch (parsed.status) {
      case 'missing':
        return { kind: 'missing' };
      case 'invalid_record':
        throw invalidRecordFailure('Stored versioned JSON record envelope is invalid');
      case 'present': {
        const value = this.parse(parsed.value);
        if (value === null) throw invalidRecordFailure('Stored versioned JSON record is invalid');
        const version = toOptionalTrimmedString(parsed.version);
        if (!version) throw invalidRecordFailure('Stored versioned JSON record version is invalid');
        return { kind: 'present', value, version };
      }
      default:
        return assertNever(parsed);
    }
  }

  async put(
    key: string,
    value: T,
    expectedVersion: string | null,
    options: { readonly ttlMs?: number } = {},
  ): Promise<VersionedJsonRecordPutResult> {
    const recordKey = normalizeRecordKey(key);
    const storageKey = this.storageKey(recordKey);
    if (expectedVersion !== null && !toOptionalTrimmedString(expectedVersion)) {
      throw new Error('Versioned JSON record expectedVersion must be null or non-empty');
    }
    const encoded = this.encode(value);
    if (!isJsonObject(encoded)) {
      throw new Error('Versioned JSON record encoder returned a non-object value');
    }
    const response = await this.call(recordKey, {
      op: 'putVersionedJson',
      key: storageKey,
      expectedVersion,
      value: encoded,
      ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
    });
    if (!response.ok) throw requestFailure(response.message);
    const parsed = parseVersionedJsonPutResponse(response.value);
    if (!parsed) throw invalidResponseFailure('Versioned JSON put response is invalid');
    switch (parsed.status) {
      case 'stored': {
        const version = toOptionalTrimmedString(parsed.version);
        if (!version) throw invalidResponseFailure('Stored version is invalid');
        return { kind: 'stored', version };
      }
      case 'version_mismatch':
        return { kind: 'version_mismatch' };
      case 'invalid_record':
        throw invalidRecordFailure('Stored versioned JSON record envelope is invalid');
      default:
        return assertNever(parsed);
    }
  }

  private storageKey(key: string): string {
    const normalized = normalizeRecordKey(key);
    return `${this.keyPrefix}${normalized}`;
  }

  private stubForKey(key: string): CloudflareDurableObjectStubLike {
    const objectName = this.objectNameForKey(key);
    if (!toOptionalTrimmedString(objectName)) {
      throw new Error('Cloudflare versioned JSON object-name resolver returned an empty name');
    }
    return this.namespace.get(this.namespace.idFromName(objectName));
  }

  private async call(
    objectNameKey: string,
    request: Record<string, unknown>,
  ): Promise<VersionedJsonDoResponse> {
    const stub = this.stubForKey(objectNameKey);
    let response: Response;
    try {
      response = await stub.fetch('https://threshold-store.invalid/', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(request),
      });
    } catch (error) {
      throw requestFailure(
        error instanceof Error ? error.message : 'Versioned JSON request failed',
      );
    }
    const text = await response.text();
    if (!response.ok) throw requestFailure(`Durable Object HTTP ${response.status}: ${text}`);
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      throw invalidResponseFailure('Versioned JSON Durable Object returned invalid JSON');
    }
    if (!isPlainObject(parsed))
      throw invalidResponseFailure('Versioned JSON Durable Object response is not an object');
    if (parsed.ok === true && 'value' in parsed) {
      return { ok: true, value: parsed.value };
    }
    if (parsed.ok === false) {
      const code = toOptionalTrimmedString(parsed.code) || 'request_failed';
      const message =
        toOptionalTrimmedString(parsed.message) || 'Versioned JSON Durable Object request failed';
      return { ok: false, code, message };
    }
    throw invalidResponseFailure('Versioned JSON Durable Object response has invalid status');
  }
}

export function createCloudflareDurableObjectVersionedJsonRecordStore<T>(
  options: CloudflareVersionedJsonRecordStoreOptions<T>,
): CloudflareDurableObjectVersionedJsonRecordStore<T> {
  return new CloudflareDurableObjectVersionedJsonRecordStore(options);
}

function parseVersionedJsonReadResponse(value: unknown): VersionedJsonReadResponse | null {
  if (!isPlainObject(value)) return null;
  const status = toOptionalTrimmedString(value.status);
  if (status === 'missing' || status === 'invalid_record') return { status };
  if (status !== 'present' || !('value' in value)) return null;
  const version = toOptionalTrimmedString(value.version);
  return version ? { status, value: value.value, version } : null;
}

function parseVersionedJsonPutResponse(value: unknown): VersionedJsonPutResponse | null {
  if (!isPlainObject(value)) return null;
  const status = toOptionalTrimmedString(value.status);
  if (status === 'version_mismatch' || status === 'invalid_record') return { status };
  if (status !== 'stored') return null;
  const version = toOptionalTrimmedString(value.version);
  return version ? { status, version } : null;
}

function normalizeKeyPrefix(value: unknown): string {
  const prefix = toOptionalTrimmedString(value);
  if (!prefix) return 'versioned-json:';
  return prefix.endsWith(':') ? prefix : `${prefix}:`;
}

function normalizeRecordKey(value: unknown): string {
  const key = toOptionalTrimmedString(value);
  if (!key) throw new Error('Versioned JSON record key is required');
  if (key.length > 512 || containsControlCharacter(key)) {
    throw new Error('Versioned JSON record key is invalid');
  }
  return key;
}

export function containsControlCharacter(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

function isDurableObjectNamespaceLike(
  value: unknown,
): value is CloudflareDurableObjectNamespaceLike {
  return (
    isPlainObject(value) &&
    typeof value.idFromName === 'function' &&
    typeof value.get === 'function'
  );
}

function isJsonObject(value: unknown): value is VersionedJsonObject {
  return isPlainObject(value) && Object.values(value).every(isJsonValue);
}

function isJsonValue(value: unknown): value is VersionedJsonValue {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (Array.isArray(value)) return value.every(isJsonValue);
  return isJsonObject(value);
}

function requestFailure(message: string): CloudflareVersionedJsonRecordStoreError {
  return new CloudflareVersionedJsonRecordStoreError('request_failed', message);
}

function invalidRecordFailure(message: string): CloudflareVersionedJsonRecordStoreError {
  return new CloudflareVersionedJsonRecordStoreError('invalid_record', message);
}

function invalidResponseFailure(message: string): CloudflareVersionedJsonRecordStoreError {
  return new CloudflareVersionedJsonRecordStoreError('invalid_response', message);
}

function assertNever(value: never): never {
  throw invalidResponseFailure(`Unknown versioned JSON response: ${String(value)}`);
}
