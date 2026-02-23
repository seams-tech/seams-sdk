import { expect, test } from '@playwright/test';
import { exportKeypairWithUI } from '@/core/signingEngine/api/recovery/privateKeyExportRecovery';

test.describe('privateKeyExportRecovery method binding', () => {
  test('invokes requestExportPrivateKeysWithUi with expected payload', async () => {
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

    const result = await exportKeypairWithUI({
      indexedDB: {
        clientDB: {
          resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
          getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 9 }),
          getNearAccountProjection: async () => ({ clientNearPublicKey: 'ed25519:pub' }),
        },
        getNearLocalKeyMaterial: async () => ({
          publicKey: 'ed25519:pub',
          encryptedSk: 'encrypted-sk',
          chacha20NonceB64u: 'nonce',
          wrapKeySalt: 'salt',
        }),
        getNearThresholdKeyMaterial: async () => null,
      } as any,
      requestExportPrivateKeysWithUi: requestExportPrivateKeysWithUi as any,
      getTheme: () => 'dark',
      signingKeyOps: {
        recoverKeypairFromPasskey: async () => {
          throw new Error('unused');
        },
      },
      createSessionId: () => 'session-unused',
    }, {
      nearAccountId: 'alice.testnet' as any,
      options: { chain: 'near', variant: 'drawer' },
    });

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
      theme: 'dark',
    });
  });
});
