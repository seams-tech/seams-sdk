import { expect, test } from '@playwright/test';
import {
  persistThresholdEcdsaBootstrapChainAccount,
  type ThresholdEcdsaBootstrapIndexedDbPort,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdEcdsaBootstrapPersistence';

type UpsertCall = Parameters<ThresholdEcdsaBootstrapIndexedDbPort['upsertChainAccount']>[0];

function createIndexedDbPort(calls: UpsertCall[]): ThresholdEcdsaBootstrapIndexedDbPort {
  return {
    clientDB: {
      resolveProfileAccountContext: async () => ({
        profileId: 'profile-1',
        accountRef: {
          chainIdKey: 'near:testnet',
          accountAddress: 'alice.testnet',
        },
      }),
      upsertProfile: async () => ({}),
      setLastProfileStateForProfile: async () => undefined,
    },
    upsertChainAccount: async (input) => {
      calls.push(input);
      return {
        profileId: String(input.profileId),
        chainIdKey: String(input.chainIdKey),
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
          chainId: 11155111,
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
    expect(primary.chainIdKey).toBe('evm:11155111');
    expect(primary.accountModel).toBe('erc4337');
    expect(primary.deployed).toBe(false);
    expect(primary.deploymentTxHash).toBeNull();
    expect(primary.lastDeploymentCheckAt).toBeNull();
    expect(primary.undeployedSignerSet).toEqual({
      version: 'undeployed_smart_account_signer_set_v1',
      ownerAddresses: [`0x${'ab'.repeat(20)}`],
      activeOwnerAddresses: [`0x${'ab'.repeat(20)}`],
      pendingOwnerAddresses: [],
      owners: [
        {
          signerId: `0x${'ab'.repeat(20)}`,
          signerType: 'threshold',
          status: 'active',
        },
      ],
    });

    const mirror = calls[1]!;
    expect(mirror.chainIdKey).toBe('tempo:42431');
    expect(mirror.accountModel).toBe('tempo-native');
    expect(mirror.deployed).toBe(false);
    expect(mirror.deploymentTxHash).toBeNull();
    expect(mirror.lastDeploymentCheckAt).toBeNull();
    expect(mirror.undeployedSignerSet).toEqual(primary.undeployedSignerSet);
  });

  test('falls back to unknown chain id when bootstrap chain id is invalid', async () => {
    const calls: UpsertCall[] = [];

    await persistThresholdEcdsaBootstrapChainAccount({
      indexedDB: createIndexedDbPort(calls),
      nearAccountId: 'alice.testnet' as any,
      chain: 'evm',
      bootstrap: {
        keygen: {
          chainId: 'invalid',
          counterfactualAddress: `0x${'ab'.repeat(20)}`,
        },
      } as any,
    });

    expect(calls.length).toBe(2);
    expect(calls[0]?.chainIdKey).toBe('evm:unknown');
    expect(calls[1]?.chainIdKey).toBe('tempo:42431');
  });

  test('persists deployed state when registration already deployed the smart account', async () => {
    const calls: UpsertCall[] = [];

    await persistThresholdEcdsaBootstrapChainAccount({
      indexedDB: createIndexedDbPort(calls),
      nearAccountId: 'alice.testnet' as any,
      chain: 'tempo',
      bootstrap: {
        keygen: {
          chainId: 42431,
          counterfactualAddress: `0x${'12'.repeat(20)}`,
          ethereumAddress: `0x${'12'.repeat(20)}`,
        },
      } as any,
      deployment: {
        deployed: true,
        deploymentTxHash: '0xdeploytempo',
      },
    });

    expect(calls.length).toBe(2);

    const primary = calls[0]!;
    expect(primary.chainIdKey).toBe('tempo:42431');
    expect(primary.deployed).toBe(true);
    expect(primary.deploymentTxHash).toBe('0xdeploytempo');
    expect(typeof primary.lastDeploymentCheckAt).toBe('number');
    expect(primary.undeployedSignerSet).toEqual({
      version: 'undeployed_smart_account_signer_set_v1',
      ownerAddresses: [`0x${'12'.repeat(20)}`],
      activeOwnerAddresses: [`0x${'12'.repeat(20)}`],
      pendingOwnerAddresses: [],
      owners: [
        {
          signerId: `0x${'12'.repeat(20)}`,
          signerType: 'threshold',
          status: 'active',
        },
      ],
    });

    const mirror = calls[1]!;
    expect(mirror.chainIdKey).toBe('evm:unknown');
    expect(mirror.deployed).toBe(false);
    expect(mirror.deploymentTxHash).toBeNull();
    expect(mirror.lastDeploymentCheckAt).toBeNull();
    expect(mirror.undeployedSignerSet).toEqual(primary.undeployedSignerSet);
  });

  test('Email OTP bootstrap creates NEAR profile/account projection without a passkey signer', async () => {
    const calls: UpsertCall[] = [];
    const profileCalls: unknown[] = [];
    const lastProfileSelections: unknown[] = [];
    let hasNearProjection = false;
    const port: ThresholdEcdsaBootstrapIndexedDbPort = {
      clientDB: {
        resolveProfileAccountContext: async () =>
          hasNearProjection
            ? {
                profileId: 'near-profile:google-user.testnet',
                accountRef: {
                  chainIdKey: 'near:testnet',
                  accountAddress: 'google-user.testnet',
                },
              }
            : null,
        upsertProfile: async (input) => {
          profileCalls.push(input);
          return {};
        },
        setLastProfileStateForProfile: async (profileId, signerSlot) => {
          lastProfileSelections.push({ profileId, signerSlot });
        },
      },
      upsertChainAccount: async (input) => {
        calls.push(input);
        if (input.chainIdKey === 'near:testnet' && input.accountAddress === 'google-user.testnet') {
          hasNearProjection = true;
        }
        return {
          profileId: String(input.profileId),
          chainIdKey: String(input.chainIdKey),
          accountAddress: String(input.accountAddress),
          accountModel: String(input.accountModel) as any,
          isPrimary: !!input.isPrimary,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        } as any;
      },
    };

    await persistThresholdEcdsaBootstrapChainAccount({
      indexedDB: port,
      nearAccountId: 'google-user.testnet' as any,
      chain: 'tempo',
      ensureEmailOtpNearAccountMapping: true,
      bootstrap: {
        keygen: {
          chainId: 42431,
          counterfactualAddress: `0x${'34'.repeat(20)}`,
          ethereumAddress: `0x${'34'.repeat(20)}`,
        },
      } as any,
    });

    expect(profileCalls).toHaveLength(1);
    expect(profileCalls[0]).toMatchObject({
      profileId: 'near-profile:google-user.testnet',
      defaultSignerSlot: 1,
      preferences: {
        useRelayer: false,
        useNetwork: 'testnet',
      },
    });
    expect((profileCalls[0] as any).passkeyCredential).toBeUndefined();
    expect(calls[0]).toMatchObject({
      profileId: 'near-profile:google-user.testnet',
      chainIdKey: 'near:testnet',
      accountAddress: 'google-user.testnet',
      accountModel: 'near-native',
    });
    expect(lastProfileSelections).toEqual([
      { profileId: 'near-profile:google-user.testnet', signerSlot: 1 },
    ]);
    expect(calls.map((call) => call.chainIdKey)).toEqual([
      'near:testnet',
      'tempo:42431',
      'evm:unknown',
    ]);
  });
});
