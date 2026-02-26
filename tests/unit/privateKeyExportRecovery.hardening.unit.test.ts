import { expect, test } from '@playwright/test';

const IMPORT_PATHS = {
  privateKeyExportRecovery: '/sdk/esm/core/signingEngine/api/recovery/privateKeyExportRecovery.js',
} as const;

test.describe('private key export recovery hardening', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('fails closed with typed error + telemetry when export worker op is unavailable', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.privateKeyExportRecovery);
        const warnings: unknown[][] = [];
        const originalWarn = console.warn;
        console.warn = (...args: unknown[]) => {
          warnings.push(args);
        };

        try {
          await mod.exportKeypairWithUI(
            {
              indexedDB: {} as any,
              requestExportPrivateKeysWithUi: undefined as any,
              getTheme: () => 'dark',
              signingKeyOps: {
                recoverKeypairFromPasskey: async () => {
                  throw new Error('unused');
                },
              },
              createSessionId: () => 'session-unused',
            },
            {
              nearAccountId: 'alice.testnet',
              options: { chain: 'near' },
            },
          );
          return { ok: true, warnings };
        } catch (error: any) {
          const telemetry =
            warnings.find((entry) => entry[0] === '[signer-export-telemetry]') || [];
          return {
            ok: false,
            name: String(error?.name || ''),
            code: String(error?.code || ''),
            message: String(error?.message || ''),
            telemetryEvent: String((telemetry[1] as any)?.event || ''),
            telemetryReason: String((telemetry[1] as any)?.reason || ''),
            telemetryAccountId: String((telemetry[1] as any)?.nearAccountId || ''),
          };
        } finally {
          console.warn = originalWarn;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.name).toBe('SignerExportHardeningError');
    expect(result.code).toBe('SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT');
    expect(result.message).toContain('SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT');
    expect(result.telemetryEvent).toBe('signer.export.legacy_shortcut_blocked');
    expect(result.telemetryReason).toBe('missing_export_worker_operation');
    expect(result.telemetryAccountId).toBe('alice.testnet');
  });

  test('fails closed with typed error + telemetry on legacy worker message mismatch', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.privateKeyExportRecovery);
        const warnings: unknown[][] = [];
        const originalWarn = console.warn;
        console.warn = (...args: unknown[]) => {
          warnings.push(args);
        };

        try {
          await mod.exportKeypairWithUI(
            {
              indexedDB: {
                clientDB: {
                  resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
                  getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 7 }),
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
              requestExportPrivateKeysWithUi: async () => {
                throw new Error(
                  'Unsupported UserConfirm worker message type: EXPORT_PRIVATE_KEYS_WITH_UI',
                );
              },
              getTheme: () => 'dark',
              signingKeyOps: {
                recoverKeypairFromPasskey: async () => {
                  throw new Error('unused');
                },
              },
              createSessionId: () => 'session-unused',
            },
            {
              nearAccountId: 'alice.testnet',
              options: { chain: 'near' },
            },
          );
          return { ok: true, warnings };
        } catch (error: any) {
          const telemetry =
            warnings.find((entry) => entry[0] === '[signer-export-telemetry]') || [];
          return {
            ok: false,
            name: String(error?.name || ''),
            code: String(error?.code || ''),
            telemetryEvent: String((telemetry[1] as any)?.event || ''),
            telemetryReason: String((telemetry[1] as any)?.reason || ''),
            telemetryDeviceNumber: Number((telemetry[1] as any)?.deviceNumber || 0),
          };
        } finally {
          console.warn = originalWarn;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.name).toBe('SignerExportHardeningError');
    expect(result.code).toBe('SIGNER_EXPORT_TEMP_DISABLED_LEGACY_SHORTCUT');
    expect(result.telemetryEvent).toBe('signer.export.legacy_shortcut_blocked');
    expect(result.telemetryReason).toBe('worker_missing_export_operation');
    expect(result.telemetryDeviceNumber).toBe(7);
  });

  test('routes successful export through worker operation with chain-scoped payload', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.privateKeyExportRecovery);
        const calls: Array<Record<string, unknown>> = [];

        const exportResult = await mod.exportKeypairWithUI(
          {
            indexedDB: {
              clientDB: {
                resolveNearAccountContext: async () => ({ profileId: 'profile-1' }),
                getLastProfileState: async () => ({ profileId: 'profile-1', deviceNumber: 3 }),
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
            requestExportPrivateKeysWithUi: async (payload: Record<string, unknown>) => {
              calls.push(payload);
              const chain = String(payload.chain || '');
              return {
                ok: true,
                accountId: 'alice.testnet',
                exportedSchemes: chain === 'near' ? ['ed25519'] : ['secp256k1'],
              };
            },
            getTheme: () => 'light',
            signingKeyOps: {
              recoverKeypairFromPasskey: async () => {
                throw new Error('unused');
              },
            },
            createSessionId: () => 'session-unused',
          },
          {
            nearAccountId: 'alice.testnet',
            options: {
              chain: 'evm',
              variant: 'drawer',
            },
          },
        );

        return {
          exportResult,
          payload: calls[0] || null,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.exportResult).toEqual({
      accountId: 'alice.testnet',
      exportedSchemes: ['secp256k1'],
    });
    expect(result.payload).toMatchObject({
      nearAccountId: 'alice.testnet',
      deviceNumber: 3,
      chain: 'evm',
      variant: 'drawer',
      theme: 'light',
    });
  });
});
