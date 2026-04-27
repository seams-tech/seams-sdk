import { base64UrlEncode } from '@shared/utils/base64';
import { alphabetizeStringify, sha256BytesUtf8 } from '@shared/utils/digests';
import { SigningSessionIds, type SigningOperationFingerprint } from './types';

export async function computeSigningOperationFingerprint(args: {
  kind: string;
  payload: unknown;
}): Promise<SigningOperationFingerprint> {
  const json = alphabetizeStringify({
    kind: String(args.kind || '').trim() || 'unknown',
    payload: normalizeOperationFingerprintValue(args.payload),
  });
  const digest = await sha256BytesUtf8(json);
  return SigningSessionIds.signingOperationFingerprint(`sha256:${base64UrlEncode(digest)}`);
}

function normalizeOperationFingerprintValue(value: unknown): unknown {
  if (typeof value === 'bigint') {
    return value.toString(10);
  }
  if (value instanceof Uint8Array) {
    return { __bytesB64u: base64UrlEncode(value) };
  }
  if (ArrayBuffer.isView(value)) {
    return {
      __bytesB64u: base64UrlEncode(
        new Uint8Array(value.buffer, value.byteOffset, value.byteLength),
      ),
    };
  }
  if (value instanceof ArrayBuffer) {
    return { __bytesB64u: base64UrlEncode(new Uint8Array(value)) };
  }
  if (Array.isArray(value)) {
    return value.map(normalizeOperationFingerprintValue);
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    const next = normalizeOperationFingerprintValue((value as Record<string, unknown>)[key]);
    if (next !== undefined) out[key] = next;
  }
  return out;
}
