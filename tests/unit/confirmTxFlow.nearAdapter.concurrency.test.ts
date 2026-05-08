import { test, expect } from '@playwright/test';
import { handleInfrastructureErrors } from '../setup';

const IMPORT_PATHS = {
  nonceCoordinator: '/sdk/esm/core/signingEngine/nonce/NonceCoordinator.js',
  nearAdapter: '/sdk/esm/core/signingEngine/uiConfirm/handlers/flows/adapters/adapters.js',
} as const;

test.describe('touchConfirm near adapter – concurrency', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('fetchNearContext returns an isolated transactionContext per call', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        try {
          // @ts-ignore runtime import
          const nonceCoordinatorMod = await import(paths.nonceCoordinator);
          // @ts-ignore runtime import
          const nearAdapter = await import(paths.nearAdapter);

          const ctx = {
            nonceCoordinator: nonceCoordinatorMod.createNonceCoordinator({
              evmNonceBackend: {
                fetchChainNonce: async () => 0n,
              },
              nearClient: {
                viewAccessKey: async () => ({
                  nonce: 10,
                  permission: 'FullAccess',
                  block_height: 1,
                  block_hash: 'access-key-block',
                }),
                viewBlock: async () => ({
                  header: {
                    height: 1000,
                    hash: '11111111111111111111111111111111',
                  },
                }),
              },
            }),
            nearClient: {
              viewAccessKey: async () => ({
                nonce: 10,
                permission: 'FullAccess',
                block_height: 1,
                block_hash: 'access-key-block',
              }),
              viewBlock: async () => ({
                header: {
                  height: 1000,
                  hash: '11111111111111111111111111111111',
                },
              }),
            },
          } as any;
          const adapters = nearAdapter.createConfirmTxFlowAdapters(ctx);

          // Run two reservations "concurrently" to mimic rapid-fire signing requests.
          const [r1, r2] = await Promise.all([
            adapters.near.fetchNearContext({
              nearAccountId: 'test-account.testnet',
              nearPublicKeyStr: 'ed25519:test-public-key',
              txCount: 1,
              reserveNonces: true,
            }),
            adapters.near.fetchNearContext({
              nearAccountId: 'test-account.testnet',
              nearPublicKeyStr: 'ed25519:test-public-key',
              txCount: 1,
              reserveNonces: true,
            }),
          ]);

          return {
            ok: true as const,
            sameObject: r1.transactionContext === r2.transactionContext,
            nonce1: r1.transactionContext?.nextNonce ?? null,
            nonce2: r2.transactionContext?.nextNonce ?? null,
          };
        } catch (e: any) {
          return { ok: false as const, error: e?.message || String(e) };
        }
      },
      { paths: IMPORT_PATHS },
    );

    if (!result.ok) {
      if (handleInfrastructureErrors(result as any)) return;
      expect(result.ok, (result as any).error || 'near adapter test failed').toBe(true);
      return;
    }

    expect(result.sameObject).toBe(false);
    expect(result.nonce1).not.toBeNull();
    expect(result.nonce2).not.toBeNull();
    expect(result.nonce1).not.toBe(result.nonce2);
  });
});
