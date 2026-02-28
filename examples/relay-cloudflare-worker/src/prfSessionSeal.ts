import {
  createEcdsaAuthSessionStore,
  createPrfSessionSealPolicyFromEcdsaAuthSessionStore,
  createPrfSessionSealRoutesOptions,
  createPrfSessionSealShamir3PassCipherAdapter,
} from '@tatchi-xyz/sdk/server';
import type { ThresholdEd25519KeyStoreConfigInput } from '@tatchi-xyz/sdk/server';

type CreatePrfSessionSealOptionsInput = {
  enabled?: string;
  keyVersion?: string;
  shamirPrimeB64u: string;
  serverEncryptExponentB64u: string;
  serverDecryptExponentB64u: string;
  thresholdKeyStoreConfig: ThresholdEd25519KeyStoreConfigInput;
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

export function createPrfSessionSealOptions(input: CreatePrfSessionSealOptionsInput) {
  const enabled = parseBooleanFlag(input.enabled, true);
  if (!enabled) return null;

  const keyVersion = String(input.keyVersion || 'kek-s-2026-02').trim();
  if (!keyVersion) {
    throw new Error(
      'PRF_SESSION_SEAL_KEY_VERSION must be a non-empty string when PRF_SESSION_SEAL_ENABLED is enabled',
    );
  }

  const ecdsaAuthSessionStore = createEcdsaAuthSessionStore({
    config: input.thresholdKeyStoreConfig,
    logger: console,
    isNode: false,
  });

  return createPrfSessionSealRoutesOptions({
    sessionPolicy: createPrfSessionSealPolicyFromEcdsaAuthSessionStore(ecdsaAuthSessionStore),
    cipher: createShamir3PassCipher({
      keyVersion,
      shamirPrimeB64u: input.shamirPrimeB64u,
      serverEncryptExponentB64u: input.serverEncryptExponentB64u,
      serverDecryptExponentB64u: input.serverDecryptExponentB64u,
    }),
    logger: console,
  });
}
