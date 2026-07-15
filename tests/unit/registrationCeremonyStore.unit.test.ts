import { expect, test } from '@playwright/test';
import {
  createRegistrationCeremonyStore,
  type StoredWalletAddSignerCeremony,
} from '@server/core/RegistrationCeremonyStore';
import {
  requireServerAllocatedWalletId,
  walletIdFromString,
  type AddSignerIntentV1,
} from '@shared/utils/registrationIntent';

const WALLET_ID = walletIdFromString('wallet_registration_store');

const ADD_SIGNER_INTENT = {
  version: 'add_signer_intent_v1',
  walletId: WALLET_ID,
  signerSelection: {
    mode: 'ecdsa',
    ecdsa: {
      chainTargets: [{ kind: 'tempo', chainId: 42431 }],
      participantIds: [1, 2],
    },
  },
  nonceB64u: 'add-signer-nonce',
} satisfies AddSignerIntentV1;

function makeEcdsaAddSignerCeremony(
  expiresAtMs = Date.now() + 60_000,
): StoredWalletAddSignerCeremony {
  return {
    addSignerCeremonyId: 'wasc_registration_store_test',
    intent: ADD_SIGNER_INTENT,
    digestB64u: 'add-signer-digest',
    orgId: 'org_registration_store',
    signingRootId: 'project:dev',
    signingRootVersion: 'default',
    expiresAtMs,
    auth: {
      kind: 'webauthn_assertion',
      rpId: 'wallet.example.test',
      credentialIdB64u: 'credential-id',
    },
    signerState: {
      kind: 'ecdsa_add_signer_prepared',
      hssKind: 'evm_family_ecdsa_keygen',
      chainTargets: [{ kind: 'tempo', chainId: 42431 }],
      prepare: {
        formatVersion: 'ecdsa-hss-role-local',
        walletId: String(WALLET_ID),
        walletKeyId: `wallet-key-${String(WALLET_ID)}`,
        ecdsaThresholdKeyId: 'ek_add_signer',
        signingRootId: 'project:dev',
        signingRootVersion: 'default',
        keyScope: 'evm-family',
        relayerKeyId: 'rk_add_signer',
        requestId: 'request-add-signer',
        thresholdSessionId: 'session-add-signer',
        signingGrantId: 'wallet-session-add-signer',
        ttlMs: 300_000,
        remainingUses: 1,
        participantIds: [1, 2],
      },
    },
  };
}

test('registration ceremony store scopes server-allocated wallet reservations by wallet ID', async () => {
  const store = createRegistrationCeremonyStore({
    config: null,
    logger: undefined,
    isNode: false,
  });
  const walletId = requireServerAllocatedWalletId('frost-vermillion-k7p9m2');
  const otherWalletId = requireServerAllocatedWalletId('frost-giant-h8q2n4');
  const expiresAtMs = Date.now() + 60_000;

  await expect(store.reserveServerAllocatedWalletId({ walletId, expiresAtMs })).resolves.toBe(true);
  await expect(store.reserveServerAllocatedWalletId({ walletId, expiresAtMs })).resolves.toBe(
    false,
  );
  await expect(
    store.reserveServerAllocatedWalletId({ walletId: otherWalletId, expiresAtMs }),
  ).resolves.toBe(true);
  await expect(store.releaseServerAllocatedWalletId({ walletId })).resolves.toBe(true);
  await expect(store.reserveServerAllocatedWalletId({ walletId, expiresAtMs })).resolves.toBe(true);
  await expect(store.releaseServerAllocatedWalletId({ walletId })).resolves.toBe(true);
  await expect(store.releaseServerAllocatedWalletId({ walletId })).resolves.toBe(false);
});

test('registration ceremony store consumes ECDSA add-signer ceremonies once', async () => {
  const store = createRegistrationCeremonyStore({
    config: { kind: 'memory' },
    logger: undefined,
    isNode: true,
  });
  const ceremony = makeEcdsaAddSignerCeremony();

  await store.putAddSignerCeremony(ceremony);
  await expect(store.getAddSignerCeremony(ceremony.addSignerCeremonyId)).resolves.toMatchObject({
    addSignerCeremonyId: ceremony.addSignerCeremonyId,
    signerState: { kind: 'ecdsa_add_signer_prepared' },
  });
  await expect(store.takeAddSignerCeremony(ceremony.addSignerCeremonyId)).resolves.toMatchObject({
    addSignerCeremonyId: ceremony.addSignerCeremonyId,
    signerState: { kind: 'ecdsa_add_signer_prepared' },
  });
  await expect(store.takeAddSignerCeremony(ceremony.addSignerCeremonyId)).resolves.toBeNull();
});
