import {
  isPlainObject,
  toOptionalTrimmedString,
} from '@shared/utils/validation';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../core/types';

export type CloudflareVersionedJsonValue =
  | null
  | boolean
  | number
  | string
  | readonly CloudflareVersionedJsonValue[]
  | { readonly [key: string]: CloudflareVersionedJsonValue };

export type CloudflareVersionedJsonObject = {
  readonly [key: string]: CloudflareVersionedJsonValue;
};

export type CloudflareVersionedJsonRecordReadResult<T> =
  | { readonly kind: 'missing' }
  | { readonly kind: 'present'; readonly value: T; readonly version: string };

export type CloudflareVersionedJsonRecordPutResult =
  | { readonly kind: 'stored'; readonly version: string }
  | { readonly kind: 'version_mismatch' };

export type CloudflareVersionedJsonRecordStoreOptions<T> = {
  readonly namespace: CloudflareDurableObjectNamespaceLike;
  /** Return one object name per ceremony key to avoid tenant-wide serialization. */
  readonly objectNameForKey: (key: string) => string;
  readonly encode: (value: T) => CloudflareVersionedJsonObject;
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

type VersionedJsonDoResponse<T> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly code: string; readonly message: string };

export class CloudflareVersionedJsonRecordStoreError extends Error {
  readonly code: 'invalid_response' | 'invalid_record' | 'request_failed';

  constructor(
    code: 'invalid_response' | 'invalid_record' | 'request_failed',
    message: string,
  ) {
    super(message);
    this.name = 'CloudflareVersionedJsonRecordStoreError';
    this.code = code;
  }
}

export class CloudflareDurableObjectVersionedJsonRecordStore<T> {
  private readonly namespace: CloudflareDurableObjectNamespaceLike;
  private readonly objectNameForKey: (key: string) => string;
  private readonly encode: (value: T) => CloudflareVersionedJsonObject;
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

  async read(key: string): Promise<CloudflareVersionedJsonRecordReadResult<T>> {
    const storageKey = this.storageKey(key);
    const response = await this.call<VersionedJsonReadResponse>(storageKey, {
      op: 'readVersionedJson',
      key: storageKey,
    });
    if (!response.ok) throw requestFailure(response.message);
    switch (response.value.status) {
      case 'missing':
        return { kind: 'missing' };
      case 'invalid_record':
        throw invalidRecordFailure('Stored versioned JSON record envelope is invalid');
      case 'present': {
        const value = this.parse(response.value.value);
        if (value === null) throw invalidRecordFailure('Stored versioned JSON record is invalid');
        const version = toOptionalTrimmedString(response.value.version);
        if (!version) throw invalidRecordFailure('Stored versioned JSON record version is invalid');
        return { kind: 'present', value, version };
      }
      default:
        return assertNever(response.value);
    }
  }

  async put(
    key: string,
    value: T,
    expectedVersion: string | null,
    options: { readonly ttlMs?: number } = {},
  ): Promise<CloudflareVersionedJsonRecordPutResult> {
    const storageKey = this.storageKey(key);
    if (expectedVersion !== null && !toOptionalTrimmedString(expectedVersion)) {
      throw new Error('Versioned JSON record expectedVersion must be null or non-empty');
    }
    const encoded = this.encode(value);
    if (!isJsonObject(encoded)) {
      throw new Error('Versioned JSON record encoder returned a non-object value');
    }
    const response = await this.call<VersionedJsonPutResponse>(storageKey, {
      op: 'putVersionedJson',
      key: storageKey,
      expectedVersion,
      value: encoded,
      ...(options.ttlMs === undefined ? {} : { ttlMs: options.ttlMs }),
    });
    if (!response.ok) throw requestFailure(response.message);
    switch (response.value.status) {
      case 'stored': {
        const version = toOptionalTrimmedString(response.value.version);
        if (!version) throw invalidResponseFailure('Stored version is invalid');
        return { kind: 'stored', version };
      }
      case 'version_mismatch':
        return { kind: 'version_mismatch' };
      case 'invalid_record':
        throw invalidRecordFailure('Stored versioned JSON record envelope is invalid');
      default:
        return assertNever(response.value);
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

  private async call<T>(key: string, request: Record<string, unknown>): Promise<VersionedJsonDoResponse<T>> {
    const stub = this.stubForKey(key);
    let response: Response;
    try {
      response = await stub.fetch('https://threshold-store.invalid/', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(request),
      });
    } catch (error) {
      throw requestFailure(error instanceof Error ? error.message : 'Versioned JSON request failed');
    }
    const text = await response.text();
    if (!response.ok) throw requestFailure(`Durable Object HTTP ${response.status}: ${text}`);
    let parsed: unknown;
    try {
      parsed = text ? JSON.parse(text) : null;
    } catch {
      throw invalidResponseFailure('Versioned JSON Durable Object returned invalid JSON');
    }
    if (!isPlainObject(parsed)) throw invalidResponseFailure('Versioned JSON Durable Object response is not an object');
    if (parsed.ok === true && 'value' in parsed) {
      return { ok: true, value: parsed.value as T };
    }
    if (parsed.ok === false) {
      const code = toOptionalTrimmedString(parsed.code) || 'request_failed';
      const message = toOptionalTrimmedString(parsed.message) || 'Versioned JSON Durable Object request failed';
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

function normalizeKeyPrefix(value: unknown): string {
  const prefix = toOptionalTrimmedString(value);
  if (!prefix) return 'versioned-json:';
  return prefix.endsWith(':') ? prefix : `${prefix}:`;
}

function normalizeRecordKey(value: unknown): string {
  const key = toOptionalTrimmedString(value);
  if (!key) throw new Error('Versioned JSON record key is required');
  if (key.length > 512 || /[\u0000-\u001f\u007f]/u.test(key)) {
    throw new Error('Versioned JSON record key is invalid');
  }
  return key;
}

function isDurableObjectNamespaceLike(value: unknown): value is CloudflareDurableObjectNamespaceLike {
  return Boolean(value) && typeof value === 'object' && typeof (value as CloudflareDurableObjectNamespaceLike).idFromName === 'function' && typeof (value as CloudflareDurableObjectNamespaceLike).get === 'function';
}

function isJsonObject(value: unknown): value is CloudflareVersionedJsonObject {
  return isPlainObject(value) && Object.values(value).every(isJsonValue);
}

function isJsonValue(value: unknown): value is CloudflareVersionedJsonValue {
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
