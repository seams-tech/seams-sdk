import { expect, test } from '@playwright/test';
import { persistAuthenticatedEcdsaInventoryProfileRepairs } from '@/SeamsWeb/operations/auth/login';
import type { AccountSignerRecord } from '@/core/indexedDB/passkeyClientDB.types';
import { buildEvmFamilyEcdsaWalletKey } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { createThresholdEcdsaBootstrapFixture } from './helpers/ecdsaBootstrap.fixtures';
import { testEcdsaChainTarget } from './helpers/ecdsaChainTarget.fixtures';

const WALLET_ID = toWalletId('inventory-repair-wallet');
const OWNER_ADDRESS = `0x${'31'.repeat(20)}`;
const CHAIN_TARGET = testEcdsaChainTarget('tempo');
const KEY_HANDLE = 'ederivation-key-inventory-repair';

function inventoryRepairFixture() {
  const bootstrap = createThresholdEcdsaBootstrapFixture({
    nearAccountId: WALLET_ID,
    chain: 'tempo',
    keyHandle: KEY_HANDLE,
    ethereumAddress: OWNER_ADDRESS,
  });
  const backendBinding = bootstrap.thresholdEcdsaKeyRef.backendBinding;
  if (!backendBinding || backendBinding.materialKind !== 'role_local_ready_state_blob') {
    throw new Error('inventory repair fixture requires role-local public facts');
  }
  const publicCapability = backendBinding.ecdsaRoleLocalReadyRecord.publicFacts.publicCapability;
  const walletKey = buildEvmFamilyEcdsaWalletKey({
    walletId: WALLET_ID,
    evmFamilySigningKeySlotId: bootstrap.thresholdEcdsaKeyRef.evmFamilySigningKeySlotId,
    keyHandle: KEY_HANDLE,
    chainTarget: CHAIN_TARGET,
    ecdsaThresholdKeyId: bootstrap.thresholdEcdsaKeyRef.ecdsaThresholdKeyId,
    signingRootId:
      bootstrap.thresholdEcdsaKeyRef.backendBinding.ecdsaRoleLocalReadyRecord.publicFacts
        .signingRootId,
    signingRootVersion:
      bootstrap.thresholdEcdsaKeyRef.backendBinding.ecdsaRoleLocalReadyRecord.publicFacts
        .signingRootVersion,
    participantIds: bootstrap.thresholdEcdsaKeyRef.participantIds,
    thresholdOwnerAddress: OWNER_ADDRESS,
    thresholdEcdsaPublicKeyB64u: bootstrap.keygen.thresholdEcdsaPublicKeyB64u,
  });
  const signer: AccountSignerRecord = {
    profileId: WALLET_ID,
    chainIdKey: 'tempo:42431',
    accountAddress: OWNER_ADDRESS,
    signerId: OWNER_ADDRESS,
    signerSlot: 1,
    signerType: 'threshold',
    signerKind: 'threshold-ecdsa',
    signerAuthMethod: 'passkey',
    signerSource: 'passkey_registration',
    status: 'active',
    addedAt: 1,
    updatedAt: 1,
    metadata: {
      chainTarget: CHAIN_TARGET,
      keyHandle: KEY_HANDLE,
      displayLabel: 'preserved',
    },
  };
  return {
    publicCapability,
    signer,
    record: {
      accountAddress: OWNER_ADDRESS,
      ownerAddress: OWNER_ADDRESS,
      walletKey,
      publicCapability,
    },
  };
}

test('authenticated inventory repair persists canonical ECDSA profile metadata', async () => {
  const fixture = inventoryRepairFixture();
  const writes: unknown[] = [];

  await persistAuthenticatedEcdsaInventoryProfileRepairs({
    store: {
      activateAccountSigner: async (input) => {
        writes.push(input);
        return { signer: fixture.signer, signerSlot: fixture.signer.signerSlot };
      },
    },
    walletId: WALLET_ID,
    configuredTargets: [CHAIN_TARGET],
    walletSigners: [fixture.signer],
    records: [fixture.record],
  });

  expect(writes).toHaveLength(1);
  expect(writes[0]).toMatchObject({
    account: {
      profileId: WALLET_ID,
      chainIdKey: 'tempo:42431',
      accountAddress: OWNER_ADDRESS,
      accountModel: 'threshold-ecdsa',
    },
    signer: {
      signerId: OWNER_ADDRESS,
      signerKind: 'threshold-ecdsa',
      signerAuthMethod: 'passkey',
      signerSource: 'passkey_registration',
      metadata: {
        displayLabel: 'preserved',
        keyHandle: KEY_HANDLE,
        publicCapability: fixture.publicCapability,
        chainTarget: CHAIN_TARGET,
      },
    },
    activationPolicy: { mode: 'allocate_next_free' },
    preferredSlot: 1,
    selectAsActive: false,
    mutation: { routeThroughOutbox: false },
  });
});
