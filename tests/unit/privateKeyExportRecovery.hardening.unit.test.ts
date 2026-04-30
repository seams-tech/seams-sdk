import { expect, test } from '@playwright/test';

const IMPORT_PATHS = {
  privateKeyExportRecovery: '/sdk/esm/core/signingEngine/api/recovery/privateKeyExportRecovery.js',
} as const;

test.describe('private key export recovery hardening', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('fails closed with typed error + telemetry when single-key HSS seed export worker op is unavailable', async ({
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
          await mod.exportNearEd25519SeedArtifactWithUI(
            {
              indexedDB: {} as any,
              relayerUrl: 'https://relay.example.test',
              getRpId: () => 'wallet.example.test',
              requestExportPrivateKeysWithUi: undefined as any,
              getTheme: () => 'dark',
            },
            {
              nearAccountId: 'alice.testnet',
              seedB64u: 'AQ',
              expectedPublicKey: 'ed25519:expected-public-key',
              options: {},
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
    expect(result.name).toBe('SignerExportRecoveryError');
    expect(result.code).toBe('SIGNER_EXPORT_WORKER_BOUNDARY_REQUIRED');
    expect(result.message).toContain('SIGNER_EXPORT_WORKER_BOUNDARY_REQUIRED');
    expect(result.telemetryEvent).toBe('signer.export.worker_boundary_required');
    expect(result.telemetryReason).toBe('missing_export_worker_operation');
    expect(result.telemetryAccountId).toBe('alice.testnet');
  });

  test('fails closed with typed error + telemetry on missing single-key HSS seed export worker message', async ({
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
          await mod.exportNearEd25519SeedArtifactWithUI(
            {
              indexedDB: {
                clientDB: {
                  resolveProfileAccountContext: async () => ({
                    profileId: 'profile-1',
                    accountRef: { chainIdKey: 'near:testnet', accountAddress: 'alice.testnet' },
                  }),
                  getLastProfileState: async () => ({
                    profileId: 'profile-1',
                    activeSignerSlot: 7,
                  }),
                },
              } as any,
              relayerUrl: 'https://relay.example.test',
              getRpId: () => 'wallet.example.test',
              requestExportPrivateKeysWithUi: async () => {
                throw new Error(
                  'Unsupported UserConfirm worker message type: EXPORT_PRIVATE_KEYS_WITH_UI',
                );
              },
              getTheme: () => 'dark',
            },
            {
              nearAccountId: 'alice.testnet',
              seedB64u: 'AQ',
              expectedPublicKey: 'ed25519:expected-public-key',
              options: {},
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
            telemetrySignerSlot: Number((telemetry[1] as any)?.signerSlot || 0),
          };
        } finally {
          console.warn = originalWarn;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ok).toBe(false);
    expect(result.name).toBe('SignerExportRecoveryError');
    expect(result.code).toBe('SIGNER_EXPORT_WORKER_BOUNDARY_REQUIRED');
    expect(result.telemetryEvent).toBe('signer.export.worker_boundary_required');
    expect(result.telemetryReason).toBe('worker_missing_export_operation');
    expect(result.telemetrySignerSlot).toBe(7);
  });

  test('routes successful single-key HSS seed export through the worker with canonical payload', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.privateKeyExportRecovery);
        const calls: Array<Record<string, unknown>> = [];

        const exportResult = await mod.exportNearEd25519SeedArtifactWithUI(
          {
            indexedDB: {
              clientDB: {
                resolveProfileAccountContext: async () => ({
                  profileId: 'profile-1',
                  accountRef: { chainIdKey: 'near:testnet', accountAddress: 'alice.testnet' },
                }),
                getLastProfileState: async () => ({
                  profileId: 'profile-1',
                  activeSignerSlot: 3,
                }),
              },
            } as any,
            relayerUrl: 'https://relay.example.test',
            getRpId: () => 'wallet.example.test',
            requestExportPrivateKeysWithUi: async (payload: Record<string, unknown>) => {
              calls.push(payload);
              return {
                ok: true,
                accountId: 'alice.testnet',
                exportedSchemes: ['ed25519'],
              };
            },
            getTheme: () => 'light',
          },
          {
            nearAccountId: 'alice.testnet',
            seedB64u: 'AQ',
            expectedPublicKey: 'ed25519:op-pub',
            options: {
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
      exportedSchemes: ['ed25519'],
    });
    expect(result.payload).toMatchObject({
      nearAccountId: 'alice.testnet',
      signerSlot: 3,
      chain: 'near',
      artifactKind: 'near-ed25519-seed-v1',
      expectedPublicKey: 'ed25519:op-pub',
      seedB64u: 'AQ',
      variant: 'drawer',
      theme: 'light',
    });
  });
});
