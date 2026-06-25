import { expect, test } from '@playwright/test';
import {
  exportEcdsaHssThresholdKeyArtifactWithUI,
  exportNearEd25519SeedArtifactWithUI,
} from '@/core/signingEngine/flows/recovery/privateKeyExportRecovery';

test.describe('privateKeyExportRecovery method binding', () => {
  test('invokes requestExportPrivateKeysWithUi with single-key HSS seed export payload', async () => {
    const requestExportState = {
      callCount: 0,
      lastPayload: null as Record<string, unknown> | null,
    };
    const requestExportPrivateKeysWithUi = async (payload: Record<string, unknown>) => {
      requestExportState.callCount += 1;
      requestExportState.lastPayload = payload;
      const chain = String(payload.chain || '');
      return {
        ok: true,
        accountId: String(payload.nearAccountId || ''),
        exportedSchemes: chain === 'near' ? ['ed25519'] : ['secp256k1'],
      };
    };

    const result = await exportNearEd25519SeedArtifactWithUI(
      {
        keyMaterialStore: {
          resolveProfileAccountContext: async () => ({
            profileId: 'profile-1',
            accountRef: { chainIdKey: 'near:testnet', accountAddress: 'alice.testnet' },
          }),
          getLastProfileState: async () => ({ profileId: 'profile-1', activeSignerSlot: 9 }),
        } as any,
        requestExportPrivateKeysWithUi: requestExportPrivateKeysWithUi as any,
        getTheme: () => 'dark',
        relayerUrl: 'https://relay.example.test',
        getRpId: () => 'wallet.example.test',
      },
      {
        nearAccountId: 'alice.testnet' as any,
        seedB64u: Buffer.alloc(32, 7).toString('base64url'),
        expectedPublicKey: 'ed25519:operational-pub',
        options: { variant: 'drawer' },
      },
    );

    expect(result).toEqual({
      accountId: 'alice.testnet',
      exportedSchemes: ['ed25519'],
    });
    expect(requestExportState.callCount).toBe(1);
    expect(requestExportState.lastPayload).toMatchObject({
      nearAccountId: 'alice.testnet',
      signerSlot: 9,
      chain: 'near',
      variant: 'drawer',
      artifactKind: 'near-ed25519-seed-v1',
      expectedPublicKey: 'ed25519:operational-pub',
      seedB64u: Buffer.alloc(32, 7).toString('base64url'),
      theme: 'dark',
    });
  });

  test('invokes requestExportPrivateKeysWithUi with canonical ecdsa-hss EVM export payload', async () => {
    const requestExportState = {
      callCount: 0,
      lastPayload: null as Record<string, unknown> | null,
    };
    const requestExportPrivateKeysWithUi = async (payload: Record<string, unknown>) => {
      requestExportState.callCount += 1;
      requestExportState.lastPayload = payload;
      return {
        ok: true,
        accountId: String(payload.walletId || ''),
        exportedSchemes: ['secp256k1'],
      };
    };

    const result = await exportEcdsaHssThresholdKeyArtifactWithUI(
      {
        keyMaterialStore: {
          resolveProfileAccountContext: async () => ({
            profileId: 'profile-1',
            accountRef: { chainIdKey: 'near:testnet', accountAddress: 'alice.testnet' },
          }),
          getLastProfileState: async () => ({ profileId: 'profile-1', activeSignerSlot: 4 }),
        } as any,
        requestExportPrivateKeysWithUi: requestExportPrivateKeysWithUi as any,
        getTheme: () => 'light',
        relayerUrl: 'https://relay.example.test',
        getRpId: () => 'wallet.example.test',
      },
      {
        walletId: 'alice.testnet',
        artifact: {
          artifactKind: 'ecdsa-hss-secp256k1-export',
          chainTarget: {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 5042002,
            networkSlug: 'arc-testnet',
          },
          publicKeyHex: `0x${'02'}${'11'.repeat(32)}`,
          privateKeyHex: `0x${'22'.repeat(32)}`,
          ethereumAddress: `0x${'33'.repeat(20)}`,
        },
        options: { variant: 'modal' },
      },
    );

    expect(result).toEqual({
      accountId: 'alice.testnet',
      exportedSchemes: ['secp256k1'],
    });
    expect(requestExportState.callCount).toBe(1);
    expect(requestExportState.lastPayload).toMatchObject({
      walletId: 'alice.testnet',
      artifactKind: 'ecdsa-hss-secp256k1-export',
      chainTarget: {
        kind: 'evm',
        namespace: 'eip155',
        chainId: 5042002,
        networkSlug: 'arc-testnet',
      },
      publicKeyHex: `0x${'02'}${'11'.repeat(32)}`,
      privateKeyHex: `0x${'22'.repeat(32)}`,
      ethereumAddress: `0x${'33'.repeat(20)}`,
      variant: 'modal',
      theme: 'light',
    });
  });

  test('rejects retired ecdsa-hss secp256k1 key artifact kind before worker dispatch', async () => {
    let requestExportCallCount = 0;
    await expect(
      exportEcdsaHssThresholdKeyArtifactWithUI(
        {
          keyMaterialStore: {
            resolveProfileAccountContext: async () => ({
              profileId: 'profile-1',
              accountRef: { chainIdKey: 'near:testnet', accountAddress: 'alice.testnet' },
            }),
            getLastProfileState: async () => ({ profileId: 'profile-1', activeSignerSlot: 4 }),
          } as any,
          requestExportPrivateKeysWithUi: (async () => {
            requestExportCallCount += 1;
            return { ok: true, accountId: 'alice.testnet', exportedSchemes: ['secp256k1'] };
          }) as any,
          getTheme: () => 'light',
          relayerUrl: 'https://relay.example.test',
          getRpId: () => 'wallet.example.test',
        },
        {
          walletId: 'alice.testnet',
          artifact: {
            artifactKind: 'ecdsa-hss-secp256k1-key-v1',
            chainTarget: {
              kind: 'evm',
              namespace: 'eip155',
              chainId: 5042002,
              networkSlug: 'arc-testnet',
            },
            publicKeyHex: `0x${'02'}${'11'.repeat(32)}`,
            privateKeyHex: `0x${'22'.repeat(32)}`,
            ethereumAddress: `0x${'33'.repeat(20)}`,
          } as any,
          options: { variant: 'modal' },
        },
      ),
    ).rejects.toThrow('Missing or invalid ecdsa-hss export artifactKind');
    expect(requestExportCallCount).toBe(0);
  });
});
