import { base64UrlDecode, base64UrlEncode } from './base64';

type CanonicalPrimitiveBrand<TName extends string> = {
  readonly __canonicalPrimitiveBrand: TName;
};

export type CorrelationId = string & CanonicalPrimitiveBrand<'CorrelationId'>;
export type DigestB64u = string & CanonicalPrimitiveBrand<'DigestB64u'>;
export type IsoTimestamp = string & CanonicalPrimitiveBrand<'IsoTimestamp'>;

export function parseCorrelationId(value: unknown): CorrelationId {
  if (typeof value !== 'string' || value.trim() !== value || value.length === 0) {
    throw new Error('correlation id must be a non-empty canonical string');
  }
  return value as CorrelationId;
}

export function parseDigestB64u(value: unknown): DigestB64u {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error('digest must be unpadded base64url');
  }
  let bytes: Uint8Array;
  try {
    bytes = base64UrlDecode(value);
  } catch {
    throw new Error('digest must be valid base64url');
  }
  if (bytes.length !== 32 || base64UrlEncode(bytes) !== value) {
    throw new Error('digest must be canonical base64url for 32 bytes');
  }
  return value as DigestB64u;
}

export function parseIsoTimestamp(value: unknown): IsoTimestamp {
  if (typeof value !== 'string') {
    throw new Error('timestamp must be an ISO timestamp');
  }
  const timestampMs = Date.parse(value);
  if (!Number.isFinite(timestampMs) || new Date(timestampMs).toISOString() !== value) {
    throw new Error('timestamp must be canonical ISO-8601 UTC');
  }
  return value as IsoTimestamp;
}

export function isoTimestampFromUnixMs(value: unknown): IsoTimestamp {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    throw new Error('timestamp milliseconds must be a positive safe integer');
  }
  return parseIsoTimestamp(new Date(Number(value)).toISOString());
}
