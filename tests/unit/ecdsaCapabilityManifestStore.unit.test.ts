import { execFileSync } from 'node:child_process';
import { unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  ecdsaCapabilityActivationFixture,
  ecdsaCapabilityGenerationMismatchReplacementFixture,
  ecdsaCapabilityReplacementFixture,
  type EcdsaCapabilityReplacementFixture,
} from './helpers/ecdsaCapabilityManifest.fixtures';

const STORE_SOURCE = fileURLToPath(
  new URL(
    '../../packages/sdk-web/src/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore.ts',
    import.meta.url,
  ),
);
const STORE_BUNDLE_PATH = `${tmpdir()}/seams-ecdsa-capability-store-${process.pid}.mjs`;
const STORE_MODULE = '/__ecdsa-capability-manifest-store-test.mjs';

async function prepareStoreModulePage(page: Page): Promise<void> {
  await page.route(`**${STORE_MODULE}`, async (route) => {
    await route.fulfill({
      path: STORE_BUNDLE_PATH,
      contentType: 'application/javascript',
    });
  });
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
}

async function exerciseReplacementActivation(input: {
  readonly storeModule: string;
  readonly fixture: EcdsaCapabilityReplacementFixture;
}) {
  await new Promise<void>((resolve) => {
    const request = indexedDB.deleteDatabase('seams_wallet');
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
  const module = await import(input.storeModule);
  const store = new module.IndexedDbEcdsaCapabilityManifestStore();
  const priorSealingKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const replacementSealingKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
  await store.storeMaterialSealingKey({
    keyId: input.fixture.prior.readyMaterial.sealingKeyId,
    key: priorSealingKey,
  });
  await store.putActivationJournal(input.fixture.prior.preparedJournal);
  await store.putActivationJournal(input.fixture.prior.committedJournal);
  const priorFinalization = await store.finalizeActivation({
    committedJournal: input.fixture.prior.committedJournal,
    readyMaterial: input.fixture.prior.readyMaterial,
    activeManifest: input.fixture.prior.activeManifest,
  });
  await store.storeMaterialSealingKey({
    keyId: input.fixture.replacement.readyMaterial.sealingKeyId,
    key: replacementSealingKey,
  });
  await store.putActivationJournal(input.fixture.replacement.preparedJournal);
  await store.putActivationJournal(input.fixture.replacement.committedJournal);
  const replacementFinalization = await store.finalizeActivation({
    committedJournal: input.fixture.replacement.committedJournal,
    readyMaterial: input.fixture.replacement.readyMaterial,
    activeManifest: input.fixture.replacement.activeManifest,
  });
  const lookup = await store.lookup({
    capability: input.fixture.prior.activeManifest.signer.capability,
    authority: input.fixture.prior.activeManifest.signer.authority,
  });
  const replacementJournal = await store.readActivationJournal(
    input.fixture.replacement.committedJournal.journalId,
  );
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('seams_wallet');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const transaction = db.transaction(
    [
      'ecdsa_capability_manifests',
      'ecdsa_current_capability_manifests',
      'ecdsa_role_local_material',
    ],
    'readonly',
  );
  const priorManifestRequest = transaction
    .objectStore('ecdsa_capability_manifests')
    .get(input.fixture.prior.activeManifest.identity.manifestId);
  const replacementManifestRequest = transaction
    .objectStore('ecdsa_capability_manifests')
    .get(input.fixture.replacement.activeManifest.identity.manifestId);
  const pointerRequest = transaction
    .objectStore('ecdsa_current_capability_manifests')
    .get([
      input.fixture.replacement.activeManifest.signer.capability,
      input.fixture.replacement.activeManifest.signer.walletId,
      input.fixture.replacement.activeManifest.signer.authority.authorityDigest,
    ]);
  const priorMaterialRequest = transaction
    .objectStore('ecdsa_role_local_material')
    .get(input.fixture.prior.readyMaterial.binding.durableMaterialRef);
  const replacementMaterialRequest = transaction
    .objectStore('ecdsa_role_local_material')
    .get(input.fixture.replacement.readyMaterial.binding.durableMaterialRef);
  const rawState = await new Promise<{
    priorManifest: Record<string, unknown> | undefined;
    replacementManifest: Record<string, unknown> | undefined;
    pointer: Record<string, unknown> | undefined;
    priorMaterial: Record<string, unknown> | undefined;
    replacementMaterial: Record<string, unknown> | undefined;
  }>((resolve, reject) => {
    transaction.oncomplete = () => {
      resolve({
        priorManifest: priorManifestRequest.result,
        replacementManifest: replacementManifestRequest.result,
        pointer: pointerRequest.result,
        priorMaterial: priorMaterialRequest.result,
        replacementMaterial: replacementMaterialRequest.result,
      });
    };
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();

  return {
    priorFinalizationKind: priorFinalization.kind,
    replacementFinalizationKind: replacementFinalization.kind,
    lookupKind: lookup.kind,
    lookupManifestId: lookup.kind === 'active' ? lookup.manifest.identity.manifestId : null,
    replacementJournalKind: replacementJournal.kind,
    priorManifestState: rawState.priorManifest?.manifest_state ?? null,
    replacementManifestState: rawState.replacementManifest?.manifest_state ?? null,
    pointerManifestId: rawState.pointer?.manifest_id ?? null,
    pointerManifestRevision: rawState.pointer?.manifest_revision ?? null,
    priorMaterialPresent: rawState.priorMaterial !== undefined,
    replacementMaterialPresent: rawState.replacementMaterial !== undefined,
  };
}

test.describe('canonical ECDSA capability manifest store', () => {
  test.beforeAll(() => {
    execFileSync(
      'bun',
      ['build', STORE_SOURCE, '--target=browser', '--format=esm', `--outfile=${STORE_BUNDLE_PATH}`],
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
        const beforeFinalize = await store.readActivationJournal(fixture.preparedJournal.journalId);
        const finalization = await store.finalizeActivation({
          committedJournal: fixture.committedJournal,
          readyMaterial: fixture.readyMaterial,
          activeManifest: fixture.activeManifest,
        });
        const afterFinalize = await store.readActivationJournal(fixture.preparedJournal.journalId);
        const lookup = await store.lookup({
          capability: fixture.activeManifest.signer.capability,
          authority: fixture.activeManifest.signer.authority,
        });
        const legacyMarker = await new Promise<string | null>((resolve, reject) => {
          const request = indexedDB.open('seams_wallet');
          request.onsuccess = () => {
            const db = request.result;
            const transaction = db.transaction('ecdsa_role_local_active_material', 'readonly');
            const get = transaction
              .objectStore('ecdsa_role_local_active_material')
              .get('pre-v10-material');
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

  test('atomically replaces the exact prior manifest and material', async ({ page }) => {
    const fixture = ecdsaCapabilityReplacementFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(exerciseReplacementActivation, {
      storeModule: STORE_MODULE,
      fixture,
    });

    expect(result).toEqual({
      priorFinalizationKind: 'committed',
      replacementFinalizationKind: 'committed',
      lookupKind: 'active',
      lookupManifestId: fixture.replacement.activeManifest.identity.manifestId,
      priorManifestState: 'replaced',
      replacementManifestState: 'active',
      pointerManifestId: fixture.replacement.activeManifest.identity.manifestId,
      pointerManifestRevision: fixture.replacement.activeManifest.identity.manifestRevision,
      priorMaterialPresent: false,
      replacementMaterialPresent: true,
      replacementJournalKind: 'missing',
    });
  });

  test('leaves the prior state unchanged when the server-generation CAS mismatches', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityGenerationMismatchReplacementFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(exerciseReplacementActivation, {
      storeModule: STORE_MODULE,
      fixture,
    });

    expect(result).toEqual({
      priorFinalizationKind: 'committed',
      replacementFinalizationKind: 'exact_record_conflict',
      lookupKind: 'active',
      lookupManifestId: fixture.prior.activeManifest.identity.manifestId,
      replacementJournalKind: 'found',
      priorManifestState: 'active',
      replacementManifestState: null,
      pointerManifestId: fixture.prior.activeManifest.identity.manifestId,
      pointerManifestRevision: fixture.prior.activeManifest.identity.manifestRevision,
      priorMaterialPresent: true,
      replacementMaterialPresent: false,
    });
  });
});
