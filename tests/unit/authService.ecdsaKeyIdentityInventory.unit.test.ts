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

test('threshold ECDSA key identity inventory reads normal threshold key records', async () => {
  const service = makeService();
  const thresholdOwnerAddress = `0x${'aa'.repeat(20)}`;
  service.setThresholdSigningService({
    getEcdsaKeyIdentityMetadata: async (input: Record<string, unknown>) => {
      expect(input).toEqual({
        walletSessionUserId: 'alice.testnet',
        rpId: 'wallet.example.test',
        ecdsaThresholdKeyId: 'ehss-alice',
      });
      return {
        walletId: 'alice.testnet',
        subjectId: 'alice.testnet',
        rpId: 'wallet.example.test',
        keyScope: 'evm-family' as const,
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
        ecdsaThresholdKeyId: 'ehss-alice',
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
    ecdsaThresholdKeyId: 'ehss-alice',
    targetKey: 'tempo:42431',
    accountAddress: thresholdOwnerAddress,
    ownerAddress: thresholdOwnerAddress,
    relayerKeyId: 'rk-1',
    thresholdEcdsaPublicKeyB64u: 'group-public-key',
    key: {
      walletId: 'alice.testnet',
      subjectId: 'alice.testnet',
      rpId: 'wallet.example.test',
      keyScope: 'evm-family',
      ecdsaThresholdKeyId: 'ehss-alice',
      signingRootId: 'project:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress,
    },
  });
  expect(result.diagnostics.returnedCount).toBe(1);
});
