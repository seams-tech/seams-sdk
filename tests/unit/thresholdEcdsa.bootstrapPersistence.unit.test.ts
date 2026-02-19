import { expect, test } from '@playwright/test';
import {
  persistThresholdEcdsaBootstrapChainAccount,
  type ThresholdEcdsaBootstrapIndexedDbPort,
} from '@/core/signing/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';

type UpsertCall = Parameters<ThresholdEcdsaBootstrapIndexedDbPort['upsertChainAccount']>[0];

function createIndexedDbPort(calls: UpsertCall[]): ThresholdEcdsaBootstrapIndexedDbPort {
  return {
    clientDB: {
      resolveNearAccountContext: async () => ({
        profileId: 'profile-1',
        sourceChainId: 'near:testnet',
        sourceAccountAddress: 'alice.testnet',
      }),
    },
    upsertChainAccount: async (input) => {
      calls.push(input);
      return {
        profileId: String(input.profileId),
        chainId: String(input.chainId),
        accountAddress: String(input.accountAddress),
        accountModel: String(input.accountModel) as any,
        isPrimary: !!input.isPrimary,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      } as any;
    },
  };
}

test.describe('threshold ECDSA bootstrap persistence', () => {
  test('persists undeployed bootstrap rows and clears prior deployment metadata', async () => {
    const calls: UpsertCall[] = [];

    await persistThresholdEcdsaBootstrapChainAccount({
      indexedDB: createIndexedDbPort(calls),
      nearAccountId: 'alice.testnet' as any,
      chain: 'evm',
      bootstrap: {
        keygen: {
          chainId: 'eip155:11155111',
          counterfactualAddress: `0x${'ab'.repeat(20)}`,
          ethereumAddress: `0x${'ab'.repeat(20)}`,
          factory: `0x${'cd'.repeat(20)}`,
          entryPoint: `0x${'ef'.repeat(20)}`,
          salt: '0x1234',
        },
      } as any,
    });

    expect(calls.length).toBe(2);

    const primary = calls[0]!;
    expect(primary.chainId).toBe('eip155:11155111');
    expect(primary.accountModel).toBe('erc4337');
    expect(primary.deployed).toBe(false);
    expect(primary.deploymentTxHash).toBeNull();
    expect(primary.lastDeploymentCheckAt).toBeNull();

    const mirror = calls[1]!;
    expect(mirror.chainId).toBe('tempo:unknown');
    expect(mirror.accountModel).toBe('tempo-native');
    expect(mirror.deployed).toBe(false);
    expect(mirror.deploymentTxHash).toBeNull();
    expect(mirror.lastDeploymentCheckAt).toBeNull();
  });

  test('falls back to unknown chain id when bootstrap chain id mismatches requested activation chain', async () => {
    const calls: UpsertCall[] = [];

    await persistThresholdEcdsaBootstrapChainAccount({
      indexedDB: createIndexedDbPort(calls),
      nearAccountId: 'alice.testnet' as any,
      chain: 'evm',
      bootstrap: {
        keygen: {
          chainId: 'tempo:1337',
          counterfactualAddress: `0x${'ab'.repeat(20)}`,
        },
      } as any,
      smartAccount: {
        chainId: 'tempo:42',
      },
    });

    expect(calls.length).toBe(2);
    expect(calls[0]?.chainId).toBe('eip155:unknown');
    expect(calls[1]?.chainId).toBe('tempo:unknown');
  });
});
