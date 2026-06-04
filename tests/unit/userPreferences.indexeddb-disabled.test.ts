import { test, expect } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  indexedDBManager: '/sdk/esm/core/indexedDB/index.js',
  userPreferences: '/sdk/esm/core/signingEngine/session/userPreferences.js',
} as const;

test.describe('UserPreferences when IndexedDB is disabled', () => {
  test('wallet-iframe app-origin mode disables SDK IndexedDB persistence', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

    const result = await page.evaluate(
      async ({ paths }) => {
        const { configureIndexedDB, IndexedDBManager, seamsWalletDB } = await import(
          paths.indexedDBManager
        );

        configureIndexedDB({ mode: 'disabled' });

        return {
          indexedDbDisabled: IndexedDBManager.isDisabled(),
          seamsWalletDbDisabled: seamsWalletDB.isDisabled(),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toEqual({
      indexedDbDisabled: true,
      seamsWalletDbDisabled: true,
    });
  });

  test('wallet-iframe app-origin mode does not create app-origin seams_wallet', async ({
    page,
  }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });

    const result = await page.evaluate(
      async ({ paths }) => {
        const { configureIndexedDB, SEAMS_WALLET_DB_NAME } = await import(paths.indexedDBManager);
        const userPreferences = (await import(paths.userPreferences)).default as any;

        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase(SEAMS_WALLET_DB_NAME);
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });

        configureIndexedDB({ mode: 'disabled' });
        userPreferences.setCurrentWallet('alice.testnet' as any);
        await new Promise((resolve) => setTimeout(resolve, 0));

        const databases =
          typeof indexedDB.databases === 'function'
            ? await indexedDB.databases()
            : [];
        return {
          dbNames: databases.flatMap((database) => (database.name ? [database.name] : [])),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.dbNames).not.toContain('seams_wallet');
  });

  test('setCurrentWallet does not cause unhandledrejection', async ({ page }) => {
    await setupBasicPasskeyTest(page);

    const result = await page.evaluate(
      async ({ paths }) => {
        const { seamsWalletDB } = await import(paths.indexedDBManager);
        const userPreferences = (await import(paths.userPreferences)).default as any;

        // Simulate app-origin wallet-iframe mode where IndexedDB is intentionally disabled.
        seamsWalletDB.setDisabled(true);

        const unhandled: string[] = [];
        const onUnhandled = (e: PromiseRejectionEvent) => {
          try {
            const reason: any = (e as any).reason;
            unhandled.push(String(reason?.message || reason || e));
          } catch {
            unhandled.push('unknown');
          }
        };
        window.addEventListener('unhandledrejection', onUnhandled);

        try {
          userPreferences.setCurrentWallet('alice.testnet' as any);
          await new Promise((r) => setTimeout(r, 0));
        } finally {
          seamsWalletDB.setDisabled(false);
          window.removeEventListener('unhandledrejection', onUnhandled);
        }

        return { unhandled };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.unhandled).toEqual([]);
  });
});
