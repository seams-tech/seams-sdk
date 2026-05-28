import { expect, test } from '@playwright/test';
import {
  persistThresholdEcdsaBootstrapForWalletTarget,
  type ThresholdEcdsaBootstrapIndexedDbPort,
} from '@/core/signingEngine/session/warmCapabilities/ecdsaBootstrapPersistence';

type UpsertCall = Parameters<ThresholdEcdsaBootstrapIndexedDbPort['upsertChainAccount']>[0];

const EVM_TARGET = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
} as const;

const TEMPO_TARGET = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
} as const;

function createIndexedDbPort(calls: UpsertCall[]): ThresholdEcdsaBootstrapIndexedDbPort {
  return {
    resolveProfileAccountContext: async () => ({
      profileId: 'profile-1',
      accountRef: {
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
      },
    }),
    upsertProfile: async () => ({}),
    setLastProfileStateForProfile: async () => undefined,
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
  test('persists threshold ECDSA owner-address rows', async () => {
    const calls: UpsertCall[] = [];

    await persistThresholdEcdsaBootstrapForWalletTarget({
      indexedDB: createIndexedDbPort(calls),
      walletId: 'alice.testnet' as any,
      chainTarget: EVM_TARGET,
      bootstrap: {
        keygen: {
          chainId: 11155111,
          ethereumAddress: `0x${'ab'.repeat(20)}`,
        },
      } as any,
    });

    expect(calls.length).toBe(1);

    const primary = calls[0]!;
    expect(primary.chainIdKey).toBe('evm:eip155:11155111');
    expect(primary.accountAddress).toBe(`0x${'ab'.repeat(20)}`);
    expect(primary.accountModel).toBe('threshold-ecdsa');
  });

  test('uses requested chain target when bootstrap chain id is invalid', async () => {
    const calls: UpsertCall[] = [];

    await persistThresholdEcdsaBootstrapForWalletTarget({
      indexedDB: createIndexedDbPort(calls),
      walletId: 'alice.testnet' as any,
      chainTarget: EVM_TARGET,
      bootstrap: {
        keygen: {
          chainId: 'invalid',
          ethereumAddress: `0x${'ab'.repeat(20)}`,
        },
      } as any,
    });

    expect(calls.length).toBe(1);
    expect(calls[0]?.chainIdKey).toBe('evm:eip155:11155111');
  });

  test('Email OTP bootstrap creates NEAR profile/account projection without a passkey signer', async () => {
    const calls: UpsertCall[] = [];
    const profileCalls: unknown[] = [];
    const lastProfileSelections: unknown[] = [];
    let hasNearProjection = false;
    const port: ThresholdEcdsaBootstrapIndexedDbPort = {
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
      setLastProfileStateForProfile: async (profileId: string, signerSlot: number) => {
        lastProfileSelections.push({ profileId, signerSlot });
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

    await persistThresholdEcdsaBootstrapForWalletTarget({
      indexedDB: port,
      walletId: 'google-user.testnet' as any,
      chainTarget: TEMPO_TARGET,
      ensureEmailOtpNearAccountMapping: true,
      bootstrap: {
        keygen: {
          chainId: 42431,
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
    ]);
  });
});
