import { execFileSync } from 'node:child_process';
import { unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import { ecdsaCapabilityActivationFixture } from './helpers/ecdsaCapabilityManifest.fixtures';

const STORE_SOURCE = fileURLToPath(
  new URL(
    '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore.ts',
    import.meta.url,
  ),
);
const STORE_BUNDLE_PATH = `${tmpdir()}/seams-ecdsa-capability-store-${process.pid}.mjs`;
const STORE_MODULE = '/__ecdsa-capability-manifest-store-test.mjs';

test.describe('canonical ECDSA capability manifest store', () => {
  test.beforeAll(() => {
    execFileSync(
      'bun',
      [
        'build',
        STORE_SOURCE,
        '--target=browser',
        '--format=esm',
        `--outfile=${STORE_BUNDLE_PATH}`,
      ],
      { stdio: 'pipe' },
    );
  });

  test.afterAll(() => {
    try {
      unlinkSync(STORE_BUNDLE_PATH);
    } catch {}
  });

  test('atomically finalizes material, manifest, pointer, and journal deletion', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    await page.route(`**${STORE_MODULE}`, async (route) => {
      await route.fulfill({
        path: STORE_BUNDLE_PATH,
        contentType: 'application/javascript',
      });
    });
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
    const result = await page.evaluate(
      async ({ storeModule, fixture }) => {
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.open('seams_wallet', 9);
          request.onupgradeneeded = () => {
            const db = request.result;
            db.createObjectStore('ecdsa_role_local_active_material', {
              keyPath: 'durableMaterialRef',
            }).put({
              durableMaterialRef: 'pre-v10-material',
              marker: 'preserved',
            });
          };
          request.onsuccess = () => {
            request.result.close();
            resolve();
          };
          request.onerror = () => reject(request.error);
        });
        const module = await import(storeModule);
        const store = new module.IndexedDbEcdsaCapabilityManifestStore();
        const sealingKey = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt'],
        );
        await store.storeMaterialSealingKey({
          keyId: fixture.readyMaterial.sealingKeyId,
          key: sealingKey,
        });
        const preparedWrite = await store.putActivationJournal(fixture.preparedJournal);
        const committedWrite = await store.putActivationJournal(fixture.committedJournal);
        const beforeFinalize = await store.readActivationJournal(
          fixture.preparedJournal.journalId,
        );
        const finalization = await store.finalizeActivation({
          committedJournal: fixture.committedJournal,
          readyMaterial: fixture.readyMaterial,
          activeManifest: fixture.activeManifest,
        });
        const afterFinalize = await store.readActivationJournal(
          fixture.preparedJournal.journalId,
        );
        const lookup = await store.lookup({
          capability: fixture.activeManifest.signer.capability,
          authority: fixture.activeManifest.signer.authority,
        });
        const legacyMarker = await new Promise<string | null>((resolve, reject) => {
          const request = indexedDB.open('seams_wallet');
          request.onsuccess = () => {
            const db = request.result;
            const transaction = db.transaction('ecdsa_role_local_active_material', 'readonly');
            const get = transaction.objectStore('ecdsa_role_local_active_material').get(
              'pre-v10-material',
            );
            get.onsuccess = () => {
              const marker =
                get.result && typeof get.result.marker === 'string' ? get.result.marker : null;
              db.close();
              resolve(marker);
            };
            get.onerror = () => {
              db.close();
              reject(get.error);
            };
          };
          request.onerror = () => reject(request.error);
        });
        return {
          preparedWriteKind: preparedWrite.kind,
          committedWriteKind: committedWrite.kind,
          beforeFinalizeKind: beforeFinalize.kind,
          finalizationKind: finalization.kind,
          afterFinalizeKind: afterFinalize.kind,
          lookupKind: lookup.kind,
          legacyMarker,
        };
      },
      {
        storeModule: STORE_MODULE,
        fixture,
      },
    );

    expect(result).toEqual({
      preparedWriteKind: 'stored',
      committedWriteKind: 'stored',
      beforeFinalizeKind: 'found',
      finalizationKind: 'committed',
      afterFinalizeKind: 'missing',
      lookupKind: 'active',
      legacyMarker: 'preserved',
    });
  });
});
