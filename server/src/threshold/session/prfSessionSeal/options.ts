import { createEcdsaAuthSessionStore } from '../../../core/ThresholdService';
import { createEd25519AuthSessionStore } from '../../../core/ThresholdService';
import type { ThresholdStoreConfigInput } from '../../../core/types';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { createPrfSessionSealShamir3PassCipherAdapter } from './crypto/cipher';
import { resolvePrfSessionSealIdempotencyFromEnv } from './idempotencyBackends';
import { createPrfSessionSealPolicyFromThresholdAuthSessionStores } from './policy/sessionPolicy';
import { createPrfSessionSealRoutesOptions } from './routesOptions';

export type CreatePrfSessionSealOptionsInput = {
  enabled?: unknown;
  keyVersion?: unknown;
  shamirPrimeB64u: string;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
  thresholdStoreConfig: ThresholdStoreConfigInput;
  isNode?: boolean;
};

function parseBooleanFlag(value: unknown, fallback: boolean): boolean {
  const normalized = String(value ?? '')
    .trim()
    .toLowerCase();
  if (!normalized) return fallback;
  if (normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on')
    return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no' || normalized === 'off') {
    return false;
  }
  return fallback;
}

function createShamir3PassCipher(input: {
  keyVersion: string;
  shamirPrimeB64u: string;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
}) {
  return createPrfSessionSealShamir3PassCipherAdapter({
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
  const idempotencyKind =
    toOptionalTrimmedString(
      config.PRF_SESSION_SEAL_IDEMPOTENCY_KIND || config.prfSessionSealIdempotencyKind,
    ) || '';
  if (!idempotencyKind) return undefined;

  return resolvePrfSessionSealIdempotencyFromEnv({
    idempotencyKind,
    upstashUrl:
      toOptionalTrimmedString(
        config.PRF_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL || config.UPSTASH_REDIS_REST_URL,
      ) || null,
    upstashToken:
      toOptionalTrimmedString(
        config.PRF_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN || config.UPSTASH_REDIS_REST_TOKEN,
      ) || null,
    redisUrl:
      toOptionalTrimmedString(config.PRF_SESSION_SEAL_IDEMPOTENCY_REDIS_URL || config.REDIS_URL) ||
      null,
    postgresUrl:
      toOptionalTrimmedString(
        config.PRF_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL || config.POSTGRES_URL,
      ) || null,
    postgresNamespace:
      toOptionalTrimmedString(config.PRF_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE) || null,
    keyPrefix: toOptionalTrimmedString(config.PRF_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX) || undefined,
    ttlMs: toPositiveInt(
      config.PRF_SESSION_SEAL_IDEMPOTENCY_TTL_MS || config.prfSessionSealIdempotencyTtlMs,
    ),
  });
}

export function createPrfSessionSealOptions(input: CreatePrfSessionSealOptionsInput) {
  const enabled = parseBooleanFlag(input.enabled, true);
  if (!enabled) return null;

  const keyVersion = String(input.keyVersion || 'kek-s-2026-02').trim();
  if (!keyVersion) {
    throw new Error(
      'PRF_SESSION_SEAL_KEY_VERSION must be a non-empty string when PRF_SESSION_SEAL_ENABLED is enabled',
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

  return createPrfSessionSealRoutesOptions({
    sessionPolicy: createPrfSessionSealPolicyFromThresholdAuthSessionStores({
      stores: [authSessionStore, ecdsaAuthSessionStore],
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
