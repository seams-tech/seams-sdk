import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import type {
  SigningSessionSealCipherAdapter,
  SigningSessionSealCipherOperationInput,
  SigningSessionSealCipherOperationResult,
} from '../types';

type HandlerInput = Omit<SigningSessionSealCipherOperationInput, 'operation'>;
type HandlerResult = SigningSessionSealCipherOperationResult;

export interface CreateSigningSessionSealCipherAdapterOptions {
  applyServerSeal: (input: HandlerInput) => Promise<HandlerResult> | HandlerResult;
  removeServerSeal: (input: HandlerInput) => Promise<HandlerResult> | HandlerResult;
}

function toErrorResult(error: unknown): { ok: false; code: string; message: string } {
  if (
    error &&
    typeof error === 'object' &&
    !Array.isArray(error) &&
    (error as { code?: unknown }).code
  ) {
    const code = String((error as { code?: unknown }).code || '').trim() || 'internal';
    const message =
      String((error as { message?: unknown }).message || '').trim() || 'Signing-session seal cipher failed';
    return { ok: false, code, message };
  }
  const message =
    error instanceof Error ? error.message : String(error || 'Signing-session seal cipher failed');
  return { ok: false, code: 'internal', message };
}

function normalizeResult(result: HandlerResult): HandlerResult {
  if (result.ok) {
    return {
      ok: true,
      ciphertext: String(result.ciphertext || ''),
      ...(String(result.keyVersion || '').trim()
        ? { keyVersion: String(result.keyVersion).trim() }
        : {}),
    };
  }
  return {
    ok: false,
    code: String(result.code || 'internal').trim() || 'internal',
    message: String(result.message || 'Signing-session seal cipher failed').trim() || 'Signing-session seal cipher failed',
  };
}

export function createSigningSessionSealCipherAdapter(
  options: CreateSigningSessionSealCipherAdapterOptions,
): SigningSessionSealCipherAdapter {
  return {
    run: async (
      input: SigningSessionSealCipherOperationInput,
    ): Promise<SigningSessionSealCipherOperationResult> => {
      const handlerInput: HandlerInput = {
        thresholdSessionId: input.thresholdSessionId,
        ciphertext: input.ciphertext,
        ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
        ...(input.metadata ? { metadata: input.metadata } : {}),
        auth: input.auth,
      };
      try {
        const output =
          input.operation === 'apply-server-seal'
            ? await options.applyServerSeal(handlerInput)
            : await options.removeServerSeal(handlerInput);
        return normalizeResult(output);
      } catch (error: unknown) {
        return toErrorResult(error);
      }
    },
  };
}

export function createPassthroughSigningSessionSealCipherAdapter(): SigningSessionSealCipherAdapter {
  return createSigningSessionSealCipherAdapter({
    applyServerSeal: async (input) => ({
      ok: true,
      ciphertext: input.ciphertext,
      ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
    }),
    removeServerSeal: async (input) => ({
      ok: true,
      ciphertext: input.ciphertext,
      ...(input.keyVersion ? { keyVersion: input.keyVersion } : {}),
    }),
  });
}

export interface SigningSessionSealShamir3PassRuntimeInput {
  ciphertextB64u: string;
  exponentB64u: string;
  shamirPrimeB64u: string;
}

export interface SigningSessionSealShamir3PassRuntime {
  addServerSeal(input: SigningSessionSealShamir3PassRuntimeInput): Promise<string> | string;
  removeServerSeal(input: SigningSessionSealShamir3PassRuntimeInput): Promise<string> | string;
}

export interface SigningSessionSealShamir3PassKeyMaterial {
  keyVersion: string;
  shamirPrimeB64u: string;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
}

export interface CreateSigningSessionSealShamir3PassCipherAdapterOptions {
  currentKeyVersion: string;
  keys: SigningSessionSealShamir3PassKeyMaterial[];
  runtime?: SigningSessionSealShamir3PassRuntime;
  strictApplyKeyVersion?: boolean;
}

function decodeBigIntB64u(value: string, label: string): bigint {
  const normalized = toOptionalTrimmedString(value);
  if (!normalized) throw new Error(`${label} must be a non-empty base64url string`);
  const bytes = base64UrlDecode(normalized);
  if (!bytes.length) throw new Error(`${label} must decode to non-empty bytes`);
  let output = 0n;
  for (const byte of bytes) {
    output = (output << 8n) | BigInt(byte);
  }
  return output;
}

function encodeBigIntB64u(value: bigint): string {
  if (value <= 0n) throw new Error('ciphertext must be > 0');
  const bytesReversed: number[] = [];
  let cursor = value;
  while (cursor > 0n) {
    bytesReversed.push(Number(cursor & 255n));
    cursor >>= 8n;
  }
  bytesReversed.reverse();
  return base64UrlEncode(Uint8Array.from(bytesReversed));
}

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  if (modulus <= 1n) return 0n;
  let result = 1n;
  let factor = base % modulus;
  let power = exponent;

  while (power > 0n) {
    if ((power & 1n) === 1n) {
      result = (result * factor) % modulus;
    }
    power >>= 1n;
    factor = (factor * factor) % modulus;
  }

  return result;
}

function runShamirModExp(input: SigningSessionSealShamir3PassRuntimeInput): string {
  const shamirPrime = decodeBigIntB64u(input.shamirPrimeB64u, 'shamirPrimeB64u');
  if (shamirPrime <= 2n) throw new Error('shamirPrimeB64u must decode to an integer > 2');

  const ciphertext = decodeBigIntB64u(input.ciphertextB64u, 'ciphertext');
  if (ciphertext <= 0n || ciphertext >= shamirPrime) {
    throw new Error('ciphertext must decode to an integer in range (0, p)');
  }

  const exponent = decodeBigIntB64u(input.exponentB64u, 'exponentB64u');
  if (exponent <= 0n) throw new Error('exponentB64u must decode to an integer > 0');

  const output = modPow(ciphertext, exponent, shamirPrime);
  return encodeBigIntB64u(output);
}

export function createSigningSessionSealShamir3PassBigIntRuntime(): SigningSessionSealShamir3PassRuntime {
  return {
    addServerSeal: (input) => runShamirModExp(input),
    removeServerSeal: (input) => runShamirModExp(input),
  };
}

function normalizeKeyMaterial(
  input: SigningSessionSealShamir3PassKeyMaterial,
  index: number,
): SigningSessionSealShamir3PassKeyMaterial {
  const keyVersion = toOptionalTrimmedString(input.keyVersion);
  if (!keyVersion) throw new Error(`keys[${index}].keyVersion is required`);

  const shamirPrimeB64u = toOptionalTrimmedString(input.shamirPrimeB64u);
  const serverEncryptExponentB64u = toOptionalTrimmedString(input.serverEncryptExponentB64u);
  const serverDecryptExponentB64u = toOptionalTrimmedString(input.serverDecryptExponentB64u);

  decodeBigIntB64u(shamirPrimeB64u, `keys[${index}].shamirPrimeB64u`);
  decodeBigIntB64u(serverEncryptExponentB64u, `keys[${index}].serverEncryptExponentB64u`);
  decodeBigIntB64u(serverDecryptExponentB64u, `keys[${index}].serverDecryptExponentB64u`);

  return {
    keyVersion,
    shamirPrimeB64u,
    serverEncryptExponentB64u,
    serverDecryptExponentB64u,
  };
}

function cipherFailure(code: string, message: string): SigningSessionSealCipherOperationResult {
  return { ok: false, code, message };
}

function mapCipherError(
  error: unknown,
  defaultMessage: string,
): SigningSessionSealCipherOperationResult {
  if (
    error &&
    typeof error === 'object' &&
    !Array.isArray(error) &&
    (error as { code?: unknown }).code
  ) {
    const code = toOptionalTrimmedString((error as { code?: unknown }).code) || 'internal';
    const message =
      toOptionalTrimmedString((error as { message?: unknown }).message) || defaultMessage;
    return cipherFailure(code, message);
  }

  const message =
    toOptionalTrimmedString(error instanceof Error ? error.message : error) || defaultMessage;
  const lowered = message.toLowerCase();
  if (lowered.includes('keyversion')) {
    return cipherFailure('invalid_key_version', message);
  }
  if (
    lowered.includes('ciphertext') ||
    lowered.includes('exponent') ||
    lowered.includes('base64url') ||
    lowered.includes('prime')
  ) {
    return cipherFailure('invalid_ciphertext', message);
  }
  return cipherFailure('internal', message);
}

export function createSigningSessionSealShamir3PassCipherAdapter(
  options: CreateSigningSessionSealShamir3PassCipherAdapterOptions,
): SigningSessionSealCipherAdapter {
  const currentKeyVersion = toOptionalTrimmedString(options.currentKeyVersion);
  if (!currentKeyVersion) throw new Error('currentKeyVersion is required');

  const keyEntries = Array.isArray(options.keys) ? options.keys : [];
  if (!keyEntries.length) throw new Error('keys[] must include at least one key material entry');

  const keyByVersion = new Map<string, SigningSessionSealShamir3PassKeyMaterial>();
  for (let index = 0; index < keyEntries.length; index += 1) {
    const normalized = normalizeKeyMaterial(keyEntries[index], index);
    if (keyByVersion.has(normalized.keyVersion)) {
      throw new Error(`Duplicate keyVersion "${normalized.keyVersion}"`);
    }
    keyByVersion.set(normalized.keyVersion, normalized);
  }

  if (!keyByVersion.has(currentKeyVersion)) {
    throw new Error(`currentKeyVersion "${currentKeyVersion}" is not present in keys[]`);
  }

  const runtime = options.runtime || createSigningSessionSealShamir3PassBigIntRuntime();
  const strictApplyKeyVersion = options.strictApplyKeyVersion !== false;

  return createSigningSessionSealCipherAdapter({
    applyServerSeal: async (input) => {
      const requestedKeyVersion = toOptionalTrimmedString(input.keyVersion);
      if (
        strictApplyKeyVersion &&
        requestedKeyVersion &&
        requestedKeyVersion !== currentKeyVersion
      ) {
        return {
          ok: false,
          code: 'invalid_key_version',
          message: `Requested keyVersion "${requestedKeyVersion}" does not match active keyVersion "${currentKeyVersion}"`,
        };
      }

      const key = keyByVersion.get(currentKeyVersion)!;
      try {
        const ciphertext = await runtime.addServerSeal({
          ciphertextB64u: input.ciphertext,
          exponentB64u: key.serverEncryptExponentB64u,
          shamirPrimeB64u: key.shamirPrimeB64u,
        });
        return {
          ok: true,
          ciphertext: toOptionalTrimmedString(ciphertext),
          keyVersion: key.keyVersion,
        };
      } catch (error: unknown) {
        return mapCipherError(error, 'Failed to apply server seal');
      }
    },

    removeServerSeal: async (input) => {
      const requestedKeyVersion = toOptionalTrimmedString(input.keyVersion) || currentKeyVersion;
      const key = keyByVersion.get(requestedKeyVersion);
      if (!key) {
        return {
          ok: false,
          code: 'invalid_key_version',
          message: `Unknown keyVersion "${requestedKeyVersion}"`,
        };
      }

      try {
        const ciphertext = await runtime.removeServerSeal({
          ciphertextB64u: input.ciphertext,
          exponentB64u: key.serverDecryptExponentB64u,
          shamirPrimeB64u: key.shamirPrimeB64u,
        });
        return {
          ok: true,
          ciphertext: toOptionalTrimmedString(ciphertext),
          keyVersion: key.keyVersion,
        };
      } catch (error: unknown) {
        return mapCipherError(error, 'Failed to remove server seal');
      }
    },
  });
}
