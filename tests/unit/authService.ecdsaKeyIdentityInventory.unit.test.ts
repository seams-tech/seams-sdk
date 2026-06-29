import { expect, test } from '@playwright/test';
import { AuthService } from '@server/core/AuthService';
import { DEFAULT_TEST_CONFIG } from '../setup/config';

function makeService(): AuthService {
  return new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    logger: null,
  });
}

test('threshold ECDSA key identity inventory rejects threshold-key-id targets', async () => {
  const service = makeService();
  service.setThresholdSigningService({
    getEcdsaKeyIdentityMetadata: async () => {
      throw new Error('threshold key id targets must be rejected before identity lookup');
    },
  } as any);

  const result = await service.listThresholdEcdsaKeyIdentityTargetsForUser({
    userId: 'alice.testnet',
    rpId: 'wallet.example.test',
    keyTargets: [
      {
        ecdsaThresholdKeyId: 'ehss-alice',
        chainTarget: {
          kind: 'tempo',
          chainId: 42431,
          networkSlug: 'tempo-testnet',
        },
      },
    ],
  });

  expect(result.records).toHaveLength(0);
  expect(result.diagnostics.rejected.threshold_key_id_selector).toBe(1);
});

test('threshold ECDSA key identity inventory resolves keyHandle targets', async () => {
  const service = makeService();
  const thresholdOwnerAddress = `0x${'bb'.repeat(20)}`;
  service.setThresholdSigningService({
    getEcdsaKeyIdentityMetadata: async (input: Record<string, unknown>) => {
      expect(input).toEqual({
        walletId: 'alice.testnet',
        keySelector: { kind: 'key_handle', keyHandle: 'ehss-key-alice' },
      });
      return {
        walletId: 'alice.testnet',
        keyScope: 'evm-family' as const,
        keyHandle: 'ehss-key-alice',
        ecdsaThresholdKeyId: 'ehss-alice',
        relayerKeyId: 'rk-1',
        signingRootId: 'project:dev',
        signingRootVersion: 'default',
        participantIds: [1, 2],
        thresholdOwnerAddress,
        thresholdEcdsaPublicKeyB64u: 'group-public-key',
      };
    },
  } as any);

  const result = await service.listThresholdEcdsaKeyIdentityTargetsForUser({
    userId: 'alice.testnet',
    rpId: 'wallet.example.test',
    keyTargets: [
      {
        keyHandle: 'ehss-key-alice',
        chainTarget: {
          kind: 'tempo',
          chainId: 42431,
          networkSlug: 'tempo-testnet',
        },
      },
    ],
  });

  expect(result.records).toHaveLength(1);
  expect(result.records[0]).toMatchObject({
    keyHandle: 'ehss-key-alice',
    ecdsaThresholdKeyId: 'ehss-alice',
    targetKey: 'tempo:42431',
    ownerAddress: thresholdOwnerAddress,
  });
  expect(result.diagnostics.returnedCount).toBe(1);
});
