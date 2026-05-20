import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  linkDeviceThresholdEcdsa: '/sdk/esm/core/SeamsPasskey/evm/linkDeviceThresholdEcdsa.js',
  ecdsaChainTarget: '/sdk/esm/core/signingEngine/interfaces/ecdsaChainTarget.js',
} as const;

test.describe('link-device threshold-ecdsa bootstrap', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('builds and persists a normal threshold ECDSA bootstrap for one concrete target', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          const { persistLinkDeviceThresholdEcdsaBootstrap } = await import(
            paths.linkDeviceThresholdEcdsa
          );
          const { thresholdEcdsaChainTargetFromChainFamily, toWalletId } = await import(
            paths.ecdsaChainTarget
          );

          const chainTarget = thresholdEcdsaChainTargetFromChainFamily({
            chain: 'evm',
            chainId: 11155111,
            networkSlug: 'ethereum-sepolia',
          });
          const sessionCalls: Array<Record<string, unknown>> = [];
          const persistCalls: Array<Record<string, unknown>> = [];
          const signingEngine = {
            upsertThresholdEcdsaSessionFromBootstrap(args: Record<string, unknown>) {
              sessionCalls.push(args);
            },
            async persistThresholdEcdsaBootstrapForWalletTarget(args: Record<string, unknown>) {
              persistCalls.push(args);
            },
          };

          await persistLinkDeviceThresholdEcdsaBootstrap({
            signingEngine,
            walletId: toWalletId('alice.testnet'),
            relayerUrl: 'https://relay.example.test',
            chainTarget,
            thresholdEcdsa: {
              ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
              signingRootId: 'project-link-device:env-link-device',
              signingRootVersion: 'default',
              clientVerifyingShareB64u: 'client-share-b64u',
              clientAdditiveShare32B64u: 'client-additive-share-b64u',
              relayerKeyId: 'rk-evm',
              thresholdEcdsaPublicKeyB64u: 'group-public-key',
              ethereumAddress: `0x${'aa'.repeat(20)}`,
              relayerVerifyingShareB64u: 'relayer-share-b64u',
              participantIds: [1, 2],
              session: {
                sessionKind: 'jwt',
                sessionId: 'ecdsa-session-1',
                walletSigningSessionId: 'wallet-session-1',
                expiresAtMs: Date.now() + 60_000,
                participantIds: [1, 2],
                remainingUses: 5,
                jwt: 'jwt:ecdsa-session-1',
                keyHandle: 'ehss-key-link-device-1',
                runtimePolicyScope: {
                  orgId: 'org-link-device',
                  projectId: 'project-link-device',
                  envId: 'env-link-device',
                  signingRootVersion: 'default',
                },
              },
            },
          });

          return { sessionCalls, persistCalls };
        } catch (error: any) {
          return { error: error?.message || String(error) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    const output = result as any;
    expect(output.error).toBeUndefined();
    expect(output.sessionCalls).toHaveLength(1);
    expect(output.persistCalls).toHaveLength(1);
    expect(output.sessionCalls[0]?.source).toBe('manual-bootstrap');
    expect(output.sessionCalls[0]?.chainTarget).toEqual(
      expect.objectContaining({
        kind: 'evm',
        namespace: 'eip155',
        chainId: 11155111,
      }),
    );
    expect(output.sessionCalls[0]?.bootstrap?.thresholdEcdsaKeyRef).toEqual(
      expect.objectContaining({
        keyHandle: 'ehss-key-link-device-1',
        ecdsaThresholdKeyId: 'ehss-link-device-prepare-1',
        signingRootId: 'project-link-device:env-link-device',
        signingRootVersion: 'default',
        thresholdSessionId: 'ecdsa-session-1',
        walletSigningSessionId: 'wallet-session-1',
        ethereumAddress: `0x${'aa'.repeat(20)}`,
      }),
    );
    expect(output.sessionCalls[0]).not.toHaveProperty('linkedAccounts');
    expect(output.persistCalls[0]).not.toHaveProperty('linkedAccounts');
  });
});
