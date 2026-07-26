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
  const priorPreparation = await store.prepareActivation(input.fixture.prior.prepareInput);
  if (
    priorPreparation.kind !== 'stored' ||
    priorPreparation.journal.kind !== 'activation_prepared'
  ) {
    throw new Error(`prior preparation failed: ${priorPreparation.kind}`);
  }
  const priorSealingKeyId = priorPreparation.journal.candidate.encryptedPending.sealingKeyId;
  const priorCommit = await store.recordServerActivation({
    preparedJournal: priorPreparation.journal,
    serverCommit: input.fixture.prior.serverCommit,
  });
  if (priorCommit.kind !== 'stored' || priorCommit.journal.kind !== 'server_activation_committed') {
    throw new Error(`prior server commit failed: ${priorCommit.kind}`);
  }
  const priorFinalization = await store.sealAndFinalizeActivation({
    committedJournal: priorCommit.journal,
    ...input.fixture.prior.sealInput,
  });
  const replacementPreparation = await store.prepareActivation(
    input.fixture.replacement.prepareInput,
  );
  if (
    replacementPreparation.kind !== 'stored' ||
    replacementPreparation.journal.kind !== 'activation_prepared'
  ) {
    throw new Error(`replacement preparation failed: ${replacementPreparation.kind}`);
  }
  const replacementSealingKeyId =
    replacementPreparation.journal.candidate.encryptedPending.sealingKeyId;
  const replacementCommit = await store.recordServerActivation({
    preparedJournal: replacementPreparation.journal,
    serverCommit: input.fixture.replacement.serverCommit,
  });
  if (
    replacementCommit.kind !== 'stored' ||
    replacementCommit.journal.kind !== 'server_activation_committed'
  ) {
    throw new Error(`replacement server commit failed: ${replacementCommit.kind}`);
  }
  const replacementFinalization = await store.sealAndFinalizeActivation({
    committedJournal: replacementCommit.journal,
    ...input.fixture.replacement.sealInput,
  });
  const lookup = await store.lookup({
    capability: input.fixture.prior.prepareInput.activationBinding.signer.capability,
    authority: input.fixture.prior.prepareInput.activationBinding.signer.authority,
  });
  const opened = await store.openActiveMaterial({
    capability: input.fixture.prior.prepareInput.activationBinding.signer.capability,
    authority: input.fixture.prior.prepareInput.activationBinding.signer.authority,
  });
  const replacementJournal = await store.readActivationJournal(replacementCommit.journal.journalId);
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
      'ecdsa_material_sealing_keys',
    ],
    'readonly',
  );
  const priorManifestRequest = transaction
    .objectStore('ecdsa_capability_manifests')
    .get(input.fixture.prior.prepareInput.activationBinding.targetManifest.manifestId);
  const replacementManifestRequest = transaction
    .objectStore('ecdsa_capability_manifests')
    .get(input.fixture.replacement.prepareInput.activationBinding.targetManifest.manifestId);
  const pointerRequest = transaction
    .objectStore('ecdsa_current_capability_manifests')
    .get([
      input.fixture.replacement.prepareInput.activationBinding.signer.capability,
      input.fixture.replacement.prepareInput.activationBinding.signer.walletId,
      input.fixture.replacement.prepareInput.activationBinding.signer.authority.authorityDigest,
    ]);
  const priorMaterialRequest = transaction
    .objectStore('ecdsa_role_local_material')
    .get(input.fixture.prior.prepareInput.activationBinding.durableMaterialRef);
  const replacementMaterialRequest = transaction
    .objectStore('ecdsa_role_local_material')
    .get(input.fixture.replacement.prepareInput.activationBinding.durableMaterialRef);
  const priorSealingKeyRequest = transaction
    .objectStore('ecdsa_material_sealing_keys')
    .get(priorSealingKeyId);
  const replacementSealingKeyRequest = transaction
    .objectStore('ecdsa_material_sealing_keys')
    .get(replacementSealingKeyId);
  const rawState = await new Promise<{
    priorManifest: Record<string, unknown> | undefined;
    replacementManifest: Record<string, unknown> | undefined;
    pointer: Record<string, unknown> | undefined;
    priorMaterial: Record<string, unknown> | undefined;
    replacementMaterial: Record<string, unknown> | undefined;
    priorSealingKey: Record<string, unknown> | undefined;
    replacementSealingKey: Record<string, unknown> | undefined;
  }>((resolve, reject) => {
    transaction.oncomplete = () => {
      resolve({
        priorManifest: priorManifestRequest.result,
        replacementManifest: replacementManifestRequest.result,
        pointer: pointerRequest.result,
        priorMaterial: priorMaterialRequest.result,
        replacementMaterial: replacementMaterialRequest.result,
        priorSealingKey: priorSealingKeyRequest.result,
        replacementSealingKey: replacementSealingKeyRequest.result,
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
    openKind: opened.kind,
    openedStateBlobB64u: opened.kind === 'active' ? opened.readyStateBlobB64u : null,
    replacementJournalKind: replacementJournal.kind,
    priorManifestState: rawState.priorManifest?.manifest_state ?? null,
    replacementManifestState: rawState.replacementManifest?.manifest_state ?? null,
    pointerManifestId: rawState.pointer?.manifest_id ?? null,
    pointerManifestRevision: rawState.pointer?.manifest_revision ?? null,
    priorMaterialPresent: rawState.priorMaterial !== undefined,
    replacementMaterialPresent: rawState.replacementMaterial !== undefined,
    priorSealingKeyPresent: rawState.priorSealingKey !== undefined,
    replacementSealingKeyPresent: rawState.replacementSealingKey !== undefined,
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
        const preparedWrite = await store.prepareActivation(fixture.prepareInput);
        if (
          preparedWrite.kind !== 'stored' ||
          preparedWrite.journal.kind !== 'activation_prepared'
        ) {
          throw new Error(`preparation failed: ${preparedWrite.kind}`);
        }
        const beforeCommitOpen = await store.openPreparedActivation(
          preparedWrite.journal.journalId,
        );
        const committedWrite = await store.recordServerActivation({
          preparedJournal: preparedWrite.journal,
          serverCommit: fixture.serverCommit,
        });
        if (
          committedWrite.kind !== 'stored' ||
          committedWrite.journal.kind !== 'server_activation_committed'
        ) {
          throw new Error(`server commit failed: ${committedWrite.kind}`);
        }
        const beforeFinalize = await store.readActivationJournal(preparedWrite.journal.journalId);
        const finalization = await store.sealAndFinalizeActivation({
          committedJournal: committedWrite.journal,
          ...fixture.sealInput,
        });
        const afterFinalize = await store.readActivationJournal(preparedWrite.journal.journalId);
        const opened = await store.openActiveMaterial({
          capability: fixture.prepareInput.activationBinding.signer.capability,
          authority: fixture.prepareInput.activationBinding.signer.authority,
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
          beforeCommitOpenKind: beforeCommitOpen.kind,
          pendingStateBlobB64u:
            beforeCommitOpen.kind === 'found' ? beforeCommitOpen.pendingStateBlobB64u : null,
          beforeFinalizeKind: beforeFinalize.kind,
          finalizationKind: finalization.kind,
          afterFinalizeKind: afterFinalize.kind,
          openKind: opened.kind,
          readyStateBlobB64u: opened.kind === 'active' ? opened.readyStateBlobB64u : null,
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
      beforeCommitOpenKind: 'found',
      pendingStateBlobB64u: fixture.prepareInput.pendingStateBlobB64u,
      beforeFinalizeKind: 'found',
      finalizationKind: 'committed',
      afterFinalizeKind: 'missing',
      openKind: 'active',
      readyStateBlobB64u: fixture.sealInput.readyStateBlobB64u,
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
      lookupManifestId:
        fixture.replacement.prepareInput.activationBinding.targetManifest.manifestId,
      openKind: 'active',
      openedStateBlobB64u: fixture.replacement.sealInput.readyStateBlobB64u,
      priorManifestState: 'replaced',
      replacementManifestState: 'active',
      pointerManifestId:
        fixture.replacement.prepareInput.activationBinding.targetManifest.manifestId,
      pointerManifestRevision:
        fixture.replacement.prepareInput.activationBinding.targetManifest.manifestRevision,
      priorMaterialPresent: false,
      replacementMaterialPresent: true,
      priorSealingKeyPresent: false,
      replacementSealingKeyPresent: true,
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
      lookupManifestId: fixture.prior.prepareInput.activationBinding.targetManifest.manifestId,
      openKind: 'active',
      openedStateBlobB64u: fixture.prior.sealInput.readyStateBlobB64u,
      replacementJournalKind: 'found',
      priorManifestState: 'active',
      replacementManifestState: null,
      pointerManifestId: fixture.prior.prepareInput.activationBinding.targetManifest.manifestId,
      pointerManifestRevision:
        fixture.prior.prepareInput.activationBinding.targetManifest.manifestRevision,
      priorMaterialPresent: true,
      replacementMaterialPresent: false,
      priorSealingKeyPresent: true,
      replacementSealingKeyPresent: true,
    });
  });

  test('rejects a forged pending ciphertext before recording the server commit', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(
      async ({ storeModule, fixture }) => {
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        const module = await import(storeModule);
        const store = new module.IndexedDbEcdsaCapabilityManifestStore();
        const preparation = await store.prepareActivation(fixture.prepareInput);
        if (preparation.kind !== 'stored' || preparation.journal.kind !== 'activation_prepared') {
          throw new Error(`preparation failed: ${preparation.kind}`);
        }
        const forgedPrepared = JSON.parse(JSON.stringify(preparation.journal));
        forgedPrepared.candidate.encryptedPending.ciphertextB64u = 'Zm9yZ2Vk';
        const commit = await store.recordServerActivation({
          preparedJournal: forgedPrepared,
          serverCommit: fixture.serverCommit,
        });
        const persisted = await store.readActivationJournal(preparation.journal.journalId);
        return {
          commitKind: commit.kind,
          persistedKind: persisted.kind,
          persistedState: persisted.kind === 'found' ? persisted.journal.kind : null,
        };
      },
      { storeModule: STORE_MODULE, fixture },
    );

    expect(result).toEqual({
      commitKind: 'corrupt',
      persistedKind: 'found',
      persistedState: 'activation_prepared',
    });
  });

  test('rejects an activation-binding mutation through AES-GCM AAD', async ({ page }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(
      async ({ storeModule, fixture }) => {
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        const module = await import(storeModule);
        const store = new module.IndexedDbEcdsaCapabilityManifestStore();
        const preparation = await store.prepareActivation(fixture.prepareInput);
        if (preparation.kind !== 'stored' || preparation.journal.kind !== 'activation_prepared') {
          throw new Error(`preparation failed: ${preparation.kind}`);
        }
        const forgedPrepared = JSON.parse(JSON.stringify(preparation.journal));
        forgedPrepared.candidate.activationBinding.durableMaterialRef = 'forged-durable-ref';
        const commit = await store.recordServerActivation({
          preparedJournal: forgedPrepared,
          serverCommit: fixture.serverCommit,
        });
        const persisted = await store.readActivationJournal(preparation.journal.journalId);
        return {
          commitKind: commit.kind,
          persistedKind: persisted.kind,
          persistedState: persisted.kind === 'found' ? persisted.journal.kind : null,
        };
      },
      { storeModule: STORE_MODULE, fixture },
    );

    expect(result).toEqual({
      commitKind: 'corrupt',
      persistedKind: 'found',
      persistedState: 'activation_prepared',
    });
  });

  test('rejects registered public facts that disagree with the activation receipt', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(
      async ({ storeModule, fixture }) => {
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        const module = await import(storeModule);
        const store = new module.IndexedDbEcdsaCapabilityManifestStore();
        const preparation = await store.prepareActivation(fixture.prepareInput);
        if (preparation.kind !== 'stored' || preparation.journal.kind !== 'activation_prepared') {
          throw new Error(`preparation failed: ${preparation.kind}`);
        }
        const commit = await store.recordServerActivation({
          preparedJournal: preparation.journal,
          serverCommit: fixture.serverCommit,
        });
        if (commit.kind !== 'stored' || commit.journal.kind !== 'server_activation_committed') {
          throw new Error(`server commit failed: ${commit.kind}`);
        }
        const forgedPublicFacts = JSON.parse(
          JSON.stringify(fixture.sealInput.registeredPublicFacts),
        );
        forgedPublicFacts.publicKeyB64u = fixture.differentPublicKeyB64u;
        const finalization = await store.sealAndFinalizeActivation({
          committedJournal: commit.journal,
          readyStateBlobB64u: fixture.sealInput.readyStateBlobB64u,
          registeredPublicFacts: forgedPublicFacts,
          committedAt: fixture.sealInput.committedAt,
        });
        const persisted = await store.readActivationJournal(commit.journal.journalId);
        return {
          finalizationKind: finalization.kind,
          persistedKind: persisted.kind,
          persistedState: persisted.kind === 'found' ? persisted.journal.kind : null,
        };
      },
      { storeModule: STORE_MODULE, fixture },
    );

    expect(result).toEqual({
      finalizationKind: 'corrupt',
      persistedKind: 'found',
      persistedState: 'server_activation_committed',
    });
  });
});
