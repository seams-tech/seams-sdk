import { expect, test } from '@playwright/test';
import {
  loadWalletCustodyEd25519MaterialV1,
  WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
} from '../../packages/wallet/src/core/signingEngine/walletCustody/ed25519SeedMaterial';

/**
 * Reading the same-device continuity cache.
 *
 * The distinction under test is absent vs unusable. Absent means a new device
 * and the caller should fetch the envelope; unusable means the cached row is
 * wrong about this wallet and should be discarded. Collapsing them into null
 * would make a stale row look like a fresh device forever — the unlock would
 * silently pay for a Router round every time and nobody would learn why.
 */

const PUBLIC_KEY_B64U = 'A'.repeat(43);

function binding(overrides: Record<string, unknown> = {}) {
  return {
    kind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    applicationBindingDigestB64u: 'B'.repeat(43),
    registeredPublicKeyB64u: PUBLIC_KEY_B64U,
    participantIds: [1, 2],
    stateEpoch: '1',
    walletId: 'alice.testnet',
    nearAccountId: 'alice.testnet',
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    signerSlot: 1,
    signingWorkerId: 'signing-worker-1',
    signingWorkerVerifyingShareB64u: 'C'.repeat(43),
    ...overrides,
  };
}

function storeWith(record: unknown) {
  return {
    resolveProfileAccountContext: async (accountRef: unknown) => ({
      profileId: 'profile-1',
      accountRef,
    }),
    getKeyMaterial: async () => record,
    storeKeyMaterial: async () => {},
  } as never;
}

function cachedRecord(overrides: Record<string, unknown> = {}) {
  return {
    profileId: 'profile-1',
    signerSlot: 1,
    chainIdKey: 'near:testnet',
    accountAddress: 'alice.testnet',
    keyKind: WALLET_CUSTODY_ED25519_MATERIAL_KEY_KIND,
    payload: { binding: binding() },
    payloadEnvelope: {
      encVersion: 1,
      alg: 'chacha20poly1305-hkdf-sha256-wallet-custody-seed-v1',
      nonce: 'D'.repeat(16),
      ciphertext: 'E'.repeat(64),
      aad: 'F'.repeat(43),
    },
    ...overrides,
  };
}

test('no cached row is absent, not a failure', async () => {
  const result = await loadWalletCustodyEd25519MaterialV1({
    store: storeWith(null),
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
  });
  expect(result.kind).toBe('absent');
});

test('a cached row returns its sealed halves without opening them', async () => {
  const result = await loadWalletCustodyEd25519MaterialV1({
    store: storeWith(cachedRecord()),
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
  });
  expect(result.kind).toBe('found');
  if (result.kind !== 'found') return;
  expect(result.material.sealed).toEqual({
    ciphertextB64u: 'E'.repeat(64),
    nonceB64u: 'D'.repeat(16),
  });
  expect(result.material.binding.registeredPublicKeyB64u).toBe(PUBLIC_KEY_B64U);
});

test('a row sealed under a retired per-factor key is unusable, not absent', async () => {
  // It would decrypt to nothing with the seed-derived cache key, and that
  // would surface as a signing failure pointing at the ceremony.
  const result = await loadWalletCustodyEd25519MaterialV1({
    store: storeWith(
      cachedRecord({
        payloadEnvelope: {
          encVersion: 1,
          alg: 'chacha20poly1305-hkdf-sha256-prf-first-v1',
          nonce: 'D'.repeat(16),
          ciphertext: 'E'.repeat(64),
          aad: 'F'.repeat(43),
        },
      }),
    ),
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
  });
  expect(result.kind).toBe('unusable');
});

test('a row for another key set is refused rather than returned', async () => {
  // Importing it would install material for a key this unlock is not
  // performing.
  const result = await loadWalletCustodyEd25519MaterialV1({
    store: storeWith(cachedRecord()),
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
    expectedRegisteredPublicKeyB64u: 'Z'.repeat(43),
  });
  expect(result.kind).toBe('unusable');
});

test('an incomplete binding is unusable', async () => {
  const result = await loadWalletCustodyEd25519MaterialV1({
    store: storeWith(cachedRecord({ payload: { binding: binding({ signingWorkerId: '' }) } })),
    nearAccountId: 'alice.testnet',
    signerSlot: 1,
  });
  expect(result.kind).toBe('unusable');
});
