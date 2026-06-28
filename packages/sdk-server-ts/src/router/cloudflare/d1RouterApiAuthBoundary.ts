import { parseWalletId, type WalletId } from '@shared/utils/domainIds';

export function isRecordValue(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

export type D1BoundaryWalletIdParseResult =
  | {
      readonly ok: true;
      readonly value: WalletId;
    }
  | {
      readonly ok: false;
      readonly code: 'missing' | 'invalid';
    };

export function parseD1BoundaryWalletIdResult(raw: unknown): D1BoundaryWalletIdParseResult {
  const parsed = parseWalletId(raw);
  if (!parsed.ok) return { ok: false, code: parsed.error.code };
  const value = String(parsed.value);
  if (/[\s\x00-\x1F\x7F]/.test(value)) return { ok: false, code: 'invalid' };
  return { ok: true, value: parsed.value };
}

export function parseD1BoundaryWalletId(raw: unknown): WalletId | null {
  const parsed = parseD1BoundaryWalletIdResult(raw);
  return parsed.ok ? parsed.value : null;
}

export function toRecordValue(value: unknown): Record<string, unknown> | null {
  return isRecordValue(value) ? value : null;
}

export function parseJsonObject(input: unknown): Record<string, unknown> | null {
  if (isRecordValue(input)) return input;
  if (typeof input !== 'string') return null;
  try {
    const parsed: unknown = JSON.parse(input);
    return isRecordValue(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function isB64uString(input: string): boolean {
  return /^[A-Za-z0-9_-]+$/.test(input);
}

export function positiveInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value <= 0) return null;
  return Math.floor(value);
}

export function positiveSafeInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isSafeInteger(value) || value <= 0) return null;
  return Math.floor(value);
}

export function nonNegativeSafeInteger(input: unknown): number | null {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isSafeInteger(value) || value < 0) return null;
  return Math.floor(value);
}

export function optionalNonNegativeInteger(input: unknown): number | undefined {
  const value = typeof input === 'number' ? input : Number(input);
  if (!Number.isFinite(value) || value < 0) return undefined;
  return Math.floor(value);
}

export type D1MutationResultLike = {
  readonly meta?: {
    readonly changes?: unknown;
    readonly rows_written?: unknown;
  } | null;
};

export function parseD1NonNegativeCount(input: unknown): number {
  const value = typeof input === 'number' ? input : Number(input);
  return Number.isFinite(value) && value >= 0 ? Math.floor(value) : 0;
}

export function d1MutationChanges(result: D1MutationResultLike): number {
  const meta = result.meta;
  return parseD1NonNegativeCount(meta?.changes ?? meta?.rows_written);
}

export function toArrayBufferCopy(bytes: Uint8Array): ArrayBuffer {
  const out = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(out).set(bytes);
  return out;
}

export async function sha256BytesPortable(input: Uint8Array): Promise<Uint8Array> {
  const subtle = globalThis.crypto?.subtle;
  if (subtle && typeof subtle.digest === 'function') {
    return new Uint8Array(await subtle.digest('SHA-256', toArrayBufferCopy(input)));
  }
  if (typeof process !== 'undefined' && process.versions?.node) {
    const { createHash } = await import('node:crypto');
    return Uint8Array.from(createHash('sha256').update(input).digest());
  }
  throw new Error('SHA-256 digest is unavailable in this runtime');
}
