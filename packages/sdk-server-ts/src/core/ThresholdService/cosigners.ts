import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import {
  threshold_ed25519_derive_relayer_cosigner_shares,
  threshold_ed25519_lagrange_coefficient_at_zero,
  threshold_ed25519_multiply_scalar_b64u_by_scalar_le32,
} from '../../../../../wasm/near_signer/pkg/wasm_signer_worker.js';

const ED25519_SCALAR_MODULUS =
  (1n << 252n) + 27742317777372353535851937790883648493n;

function scalarLeBytesToBigInt(bytes: Uint8Array): bigint {
  let acc = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) {
    acc = (acc << 8n) + BigInt(bytes[i]);
  }
  return acc;
}

function scalarBigIntToLe32(value: bigint): Uint8Array {
  let v = value % ED25519_SCALAR_MODULUS;
  if (v < 0n) v += ED25519_SCALAR_MODULUS;
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function errorMessage(e: unknown): string {
  return String(
    e && typeof e === 'object' && 'message' in e
      ? (e as { message?: unknown }).message
      : e || 'unknown error',
  );
}

function mapWasmError(message: string): { code: string; message: string } {
  const lower = message.toLowerCase();
  if (lower.includes('zero')) {
    return { code: 'internal', message };
  }
  if (
    lower.includes('invalid') ||
    lower.includes('must ') ||
    lower.includes('required') ||
    lower.includes('include') ||
    lower.includes('empty')
  ) {
    return { code: 'invalid_body', message };
  }
  return { code: 'internal', message };
}

function u16ToScalarBytesLE(id: number): Uint8Array {
  const n = Math.floor(Number(id) || 0);
  if (!Number.isFinite(n) || n <= 0 || n > 65535) {
    throw new Error('cosignerId must be an integer in [1,65535]');
  }
  const bytes = new Uint8Array(32);
  bytes[0] = n & 0xff;
  bytes[1] = (n >>> 8) & 0xff;
  return bytes;
}

export function normalizeCosignerIds(input: unknown): number[] | null {
  if (!Array.isArray(input)) return null;
  const ids: number[] = [];
  for (const item of input) {
    const n = Number(item);
    if (!Number.isFinite(n)) return null;
    const v = Math.floor(n);
    if (v <= 0 || v > 65535) return null;
    ids.push(v);
  }
  ids.sort((a, b) => a - b);
  const unique: number[] = [];
  for (const id of ids) {
    if (unique.length === 0 || unique[unique.length - 1] !== id) unique.push(id);
  }
  return unique.length ? unique : null;
}

export function deriveRelayerCosignerSharesFromRelayerSigningShare(input: {
  relayerSigningShareB64u: string;
  cosignerIds: number[];
  cosignerThreshold: number;
}):
  | {
      ok: true;
      sharesByCosignerId: Record<string, string>;
    }
  | {
      ok: false;
      code: string;
      message: string;
    } {
  const relayerSigningShareB64u = toOptionalTrimmedString(input.relayerSigningShareB64u);
  if (!relayerSigningShareB64u) {
    return { ok: false, code: 'invalid_body', message: 'relayerSigningShareB64u is required' };
  }

  let relayerSigningShareBytes: Uint8Array;
  try {
    relayerSigningShareBytes = base64UrlDecode(relayerSigningShareB64u);
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Invalid relayerSigningShareB64u: ${String(e || 'decode failed')}`,
    };
  }
  if (relayerSigningShareBytes.length !== 32) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `relayerSigningShareB64u must be 32 bytes, got ${relayerSigningShareBytes.length}`,
    };
  }

  const cosignerIds = normalizeCosignerIds(input.cosignerIds);
  if (!cosignerIds) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'cosignerIds must be a non-empty list of u16 ids',
    };
  }

  const t = Math.floor(Number(input.cosignerThreshold) || 0);
  if (!Number.isFinite(t) || t < 1) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'cosignerThreshold must be an integer >= 1',
    };
  }
  if (t > cosignerIds.length) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `cosignerThreshold must be <= cosignerIds.length (got t=${t}, n=${cosignerIds.length})`,
    };
  }

  try {
    const out = threshold_ed25519_derive_relayer_cosigner_shares({
      relayerSigningShareB64u,
      cosignerIds,
      cosignerThreshold: t,
    }) as { sharesByCosignerId?: unknown };
    const sharesRaw = out?.sharesByCosignerId;
    if (!sharesRaw || typeof sharesRaw !== 'object') {
      return { ok: false, code: 'internal', message: 'Missing sharesByCosignerId in WASM output' };
    }
    if (sharesRaw instanceof Map) {
      const sharesByCosignerId: Record<string, string> = {};
      for (const [key, value] of sharesRaw.entries()) {
        if (typeof key === 'string' && typeof value === 'string') {
          sharesByCosignerId[key] = value;
        }
      }
      return { ok: true, sharesByCosignerId };
    }
    return { ok: true, sharesByCosignerId: sharesRaw as Record<string, string> };
  } catch (e: unknown) {
    const mapped = mapWasmError(errorMessage(e));
    return { ok: false, code: mapped.code, message: mapped.message };
  }
}

export function lagrangeCoefficientAtZeroForCosigner(input: {
  cosignerId: number;
  cosignerIds: number[];
}): { ok: true; lambda: Uint8Array } | { ok: false; code: string; message: string } {
  const cosignerIds = normalizeCosignerIds(input.cosignerIds);
  if (!cosignerIds) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'cosignerIds must be a non-empty list of u16 ids',
    };
  }

  const cosignerId = Math.floor(Number(input.cosignerId) || 0);
  if (!Number.isFinite(cosignerId) || cosignerId <= 0 || cosignerId > 65535) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'cosignerId must be an integer in [1,65535]',
    };
  }
  if (!cosignerIds.includes(cosignerId)) {
    return { ok: false, code: 'invalid_body', message: 'cosignerIds must include cosignerId' };
  }

  try {
    const lambda = threshold_ed25519_lagrange_coefficient_at_zero({
      cosignerId,
      cosignerIds,
    }) as Uint8Array;
    if (!(lambda instanceof Uint8Array) || lambda.length !== 32) {
      return { ok: false, code: 'internal', message: 'WASM lagrange coefficient must be 32 bytes' };
    }
    return { ok: true, lambda };
  } catch (e: unknown) {
    const mapped = mapWasmError(errorMessage(e));
    return { ok: false, code: mapped.code, message: mapped.message };
  }
}

export function encodeFrostIdentifierBytesFromU16(id: number): Uint8Array {
  return u16ToScalarBytesLE(id);
}

export function multiplyEd25519ScalarB64uByScalarBytesLE32(input: {
  scalarB64u: string;
  factorBytesLE32: Uint8Array;
}): { ok: true; scalarB64u: string } | { ok: false; code: string; message: string } {
  const scalarB64u = toOptionalTrimmedString(input.scalarB64u);
  if (!scalarB64u) {
    return { ok: false, code: 'invalid_body', message: 'scalarB64u is required' };
  }

  let scalarBytes: Uint8Array;
  try {
    scalarBytes = base64UrlDecode(scalarB64u);
  } catch (e: unknown) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `Invalid scalarB64u: ${String(e || 'decode failed')}`,
    };
  }
  if (scalarBytes.length !== 32) {
    return {
      ok: false,
      code: 'invalid_body',
      message: `scalarB64u must be 32 bytes, got ${scalarBytes.length}`,
    };
  }

  const factorBytes = input.factorBytesLE32;
  if (!(factorBytes instanceof Uint8Array) || factorBytes.length !== 32) {
    return {
      ok: false,
      code: 'invalid_body',
      message: 'factorBytesLE32 must be a 32-byte Uint8Array',
    };
  }

  try {
    const out = threshold_ed25519_multiply_scalar_b64u_by_scalar_le32({
      scalarB64u,
      factorBytesLE32: factorBytes,
    });
    const scalarOut = toOptionalTrimmedString(out);
    if (!scalarOut) {
      return { ok: false, code: 'internal', message: 'Missing scalar output from WASM' };
    }
    return { ok: true, scalarB64u: scalarOut };
  } catch (e: unknown) {
    const mapped = mapWasmError(errorMessage(e));
    return { ok: false, code: mapped.code, message: mapped.message };
  }
}

export function addEd25519ScalarsB64u(input: {
  scalarsB64u: string[];
}): { ok: true; scalarB64u: string } | { ok: false; code: string; message: string } {
  if (!Array.isArray(input.scalarsB64u) || input.scalarsB64u.length === 0) {
    return { ok: false, code: 'invalid_body', message: 'scalarsB64u must be a non-empty array' };
  }

  let sum = 0n;
  for (const item of input.scalarsB64u) {
    const raw = toOptionalTrimmedString(item);
    if (!raw)
      return { ok: false, code: 'invalid_body', message: 'scalarsB64u contains an empty item' };
    let bytes: Uint8Array;
    try {
      bytes = base64UrlDecode(raw);
    } catch (e: unknown) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `Invalid scalar encoding: ${String(e || 'decode failed')}`,
      };
    }
    if (bytes.length !== 32) {
      return {
        ok: false,
        code: 'invalid_body',
        message: `scalar must be 32 bytes, got ${bytes.length}`,
      };
    }
    sum = (sum + scalarLeBytesToBigInt(bytes)) % ED25519_SCALAR_MODULUS;
  }
  if (sum === 0n) {
    return { ok: false, code: 'internal', message: 'Sum of scalars is zero' };
  }
  return { ok: true, scalarB64u: base64UrlEncode(scalarBigIntToLe32(sum)) };
}
