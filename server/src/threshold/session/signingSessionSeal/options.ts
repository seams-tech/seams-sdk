import { createEcdsaAuthSessionStore } from '../../../core/ThresholdService';
import { createEd25519AuthSessionStore } from '../../../core/ThresholdService';
import type { ThresholdStoreConfigInput } from '../../../core/types';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { createSigningSessionSealShamir3PassCipherAdapter } from './crypto/cipher';
import { resolveSigningSessionSealIdempotencyFromEnv } from './idempotencyBackends';
import { createSigningSessionSealPolicyFromThresholdAuthSessionStores } from './policy/sessionPolicy';
import { createSigningSessionSealRoutesOptions } from './routesOptions';

export type CreateSigningSessionSealOptionsInput = {
  enabled?: unknown;
  keyVersion?: unknown;
  shamirPrimeB64u: string;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
  thresholdStoreConfig: ThresholdStoreConfigInput;
  isNode?: boolean;
};

function parseBooleanFlag(value: unknown, defaultValue: boolean): boolean {
  const normalized = String(value ?? '')
    .trim()
    .toLowerCase();
  if (!normalized) return defaultValue;
  if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on')
    return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') {
    return false;
  }
  throw new Error('SIGNING_SESSION_SEAL_ENABLED must be a boolean flag when provided');
}

function createShamir3PassCipher(input: {
  keyVersion: string;
  shamirPrimeB64u: string;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
}) {
  return createSigningSessionSealShamir3PassCipherAdapter({
    currentKeyVersion: input.keyVersion,
    keys: [
      {
        keyVersion: input.keyVersion,
        shamirPrimeB64u: input.shamirPrimeB64u,
        serverEncryptExponentB64u: input.serverEncryptExponentB64u,
        serverDecryptExponentB64u: input.serverDecryptExponentB64u,
      },
    ],
  });
}

function toPositiveInt(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined;
  return Math.floor(parsed);
}

function buildIdempotencyOptions(thresholdStoreConfig: ThresholdStoreConfigInput) {
  const config =
    thresholdStoreConfig && typeof thresholdStoreConfig === 'object'
      ? (thresholdStoreConfig as Record<string, unknown>)
      : {};
  const idempotencyKind = toOptionalTrimmedString(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_KIND) || '';
  if (!idempotencyKind) return undefined;

  return resolveSigningSessionSealIdempotencyFromEnv({
    idempotencyKind,
    upstashUrl: toOptionalTrimmedString(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL) || null,
    upstashToken:
      toOptionalTrimmedString(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN) || null,
    redisUrl: toOptionalTrimmedString(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_REDIS_URL) || null,
    postgresUrl:
      toOptionalTrimmedString(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL) || null,
    postgresNamespace:
      toOptionalTrimmedString(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE) || null,
    keyPrefix: toOptionalTrimmedString(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX) || undefined,
    ttlMs: toPositiveInt(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS),
  });
}

export function createSigningSessionSealOptions(input: CreateSigningSessionSealOptionsInput) {
  const enabled = parseBooleanFlag(input.enabled, true);
  if (!enabled) return null;

  const keyVersion = String(input.keyVersion || '').trim();
  if (!keyVersion) {
    throw new Error(
      'SIGNING_SESSION_SEAL_KEY_VERSION must be a non-empty string when SIGNING_SESSION_SEAL_ENABLED is enabled',
    );
  }

  const authSessionStore = createEd25519AuthSessionStore({
    config: input.thresholdStoreConfig,
    logger: console,
    isNode: input.isNode === true,
  });
  const ecdsaAuthSessionStore = createEcdsaAuthSessionStore({
    config: input.thresholdStoreConfig,
    logger: console,
    isNode: input.isNode === true,
  });

  return createSigningSessionSealRoutesOptions({
    sessionPolicy: createSigningSessionSealPolicyFromThresholdAuthSessionStores({
      ed25519Stores: [authSessionStore],
      ecdsaStores: [ecdsaAuthSessionStore],
      walletBudgetStores: [authSessionStore],
    }),
    cipher: createShamir3PassCipher({
      keyVersion,
      shamirPrimeB64u: input.shamirPrimeB64u,
      serverEncryptExponentB64u: input.serverEncryptExponentB64u,
      serverDecryptExponentB64u: input.serverDecryptExponentB64u,
    }),
    capabilities: {
      mode: 'sealed_refresh_v1',
      keyVersion,
      shamirPrimeB64u: input.shamirPrimeB64u,
    },
    idempotency: buildIdempotencyOptions(input.thresholdStoreConfig),
    logger: console,
  });
}
