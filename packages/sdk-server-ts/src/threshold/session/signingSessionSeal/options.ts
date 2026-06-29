import { createEcdsaWalletSessionStore } from '../../../core/ThresholdService';
import { createEd25519WalletSessionStore } from '../../../core/ThresholdService';
import { createWalletSigningBudgetSessionStore } from '../../../core/ThresholdService';
import type { ThresholdStoreConfigInput } from '../../../core/types';
import { toOptionalTrimmedString } from '@shared/utils/validation';
import { createSigningSessionSealShamir3PassCipherAdapter } from './crypto/cipher';
import { resolveSigningSessionSealIdempotencyFromEnv } from './idempotencyBackends';
import { createSigningSessionSealPolicyFromWalletSessionStores } from './policy/sessionPolicy';
import { createSigningSessionSealRoutesOptions } from './routesOptions';
import {
  formatSigningSessionSealShamirPrimeB64uForWire,
  formatSigningSessionSealKeyVersionForWire,
  parseSigningSessionSealShamirPrimeB64u,
  parseSigningSessionSealKeyVersion,
  type SigningSessionSealKeyVersion,
  type SigningSessionSealShamirPrimeB64u,
} from '../../../core/keyMaterialBrands';

export type CreateSigningSessionSealOptionsInput = {
  keyVersion?: unknown;
  shamirPrimeB64u: string;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
  thresholdStoreConfig: ThresholdStoreConfigInput;
  isNode?: boolean;
};

function createShamir3PassCipher(input: {
  signingSessionSealKeyVersion: SigningSessionSealKeyVersion;
  shamirPrimeB64u: SigningSessionSealShamirPrimeB64u;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
}) {
  const keyVersion = formatSigningSessionSealKeyVersionForWire(input.signingSessionSealKeyVersion);
  const shamirPrimeB64u = formatSigningSessionSealShamirPrimeB64uForWire(input.shamirPrimeB64u);
  return createSigningSessionSealShamir3PassCipherAdapter({
    currentKeyVersion: keyVersion,
    keys: [
      {
        keyVersion,
        shamirPrimeB64u,
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
    keyPrefix: toOptionalTrimmedString(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX) || undefined,
    ttlMs: toPositiveInt(config.SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS),
  });
}

export function createSigningSessionSealOptions(input: CreateSigningSessionSealOptionsInput) {
  const signingSessionSealKeyVersion = parseSigningSessionSealKeyVersion(input.keyVersion);
  const keyVersion = formatSigningSessionSealKeyVersionForWire(signingSessionSealKeyVersion);
  const signingSessionSealShamirPrimeB64u = parseSigningSessionSealShamirPrimeB64u(
    input.shamirPrimeB64u,
  );
  const shamirPrimeB64u = formatSigningSessionSealShamirPrimeB64uForWire(
    signingSessionSealShamirPrimeB64u,
  );

  const walletSessionStore = createEd25519WalletSessionStore({
    config: input.thresholdStoreConfig,
    logger: console,
    isNode: input.isNode === true,
  });
  const ecdsaWalletSessionStore = createEcdsaWalletSessionStore({
    config: input.thresholdStoreConfig,
    logger: console,
    isNode: input.isNode === true,
  });
  const walletBudgetSessionStore = createWalletSigningBudgetSessionStore({
    config: input.thresholdStoreConfig,
    logger: console,
    isNode: input.isNode === true,
  });

  return createSigningSessionSealRoutesOptions({
    sessionPolicy: createSigningSessionSealPolicyFromWalletSessionStores({
      ed25519Stores: [walletSessionStore],
      ecdsaStores: [ecdsaWalletSessionStore],
      walletBudgetStores: [walletBudgetSessionStore],
    }),
    cipher: createShamir3PassCipher({
      signingSessionSealKeyVersion,
      shamirPrimeB64u: signingSessionSealShamirPrimeB64u,
      serverEncryptExponentB64u: input.serverEncryptExponentB64u,
      serverDecryptExponentB64u: input.serverDecryptExponentB64u,
    }),
    capabilities: {
      mode: 'sealed_refresh_v1',
      keyVersion,
      shamirPrimeB64u,
    },
    idempotency: buildIdempotencyOptions(input.thresholdStoreConfig),
    logger: console,
  });
}
