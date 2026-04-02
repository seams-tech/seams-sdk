import { expect, test } from '@playwright/test';
import { exportNearEd25519SeedArtifactWithUI } from '@/core/signingEngine/api/recovery/privateKeyExportRecovery';

test.describe('privateKeyExportRecovery method binding', () => {
  test('invokes requestExportPrivateKeysWithUi with Option A seed export payload', async () => {
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
        indexedDB: {
          clientDB: {
            resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
            getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 9 }),
          },
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
      deviceNumber: 9,
      chain: 'near',
      variant: 'drawer',
      artifactKind: 'near-ed25519-seed-v1',
      expectedPublicKey: 'ed25519:operational-pub',
      seedB64u: Buffer.alloc(32, 7).toString('base64url'),
      theme: 'dark',
    });
  });
});
