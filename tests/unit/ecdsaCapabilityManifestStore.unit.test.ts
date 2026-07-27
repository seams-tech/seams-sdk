import { execFileSync } from 'node:child_process';
import { unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { expect, test, type Page } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';
import {
  ecdsaCapabilityActivationFixture,
  ecdsaCapabilityGenerationMismatchReplacementFixture,
  ecdsaCapabilityLookupOutcomeFixture,
  ecdsaCapabilityReplacementFixture,
  type EcdsaCapabilityActivationFixture,
  type EcdsaCapabilityLookupOutcomeFixture,
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

async function exerciseLookupOutcomeMatrix(input: {
  readonly storeModule: string;
  readonly fixture: EcdsaCapabilityLookupOutcomeFixture;
}) {
  await new Promise<void>((resolve) => {
    const request = indexedDB.deleteDatabase('seams_wallet');
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
  const module = await import(input.storeModule);
  const store = new module.IndexedDbEcdsaCapabilityManifestStore();
  const prior = input.fixture.replacement.prior;
  const replacement = input.fixture.replacement.replacement;
  const priorPreparation = await store.prepareActivation(prior.prepareInput);
  if (
    priorPreparation.kind !== 'stored' ||
    priorPreparation.journal.kind !== 'activation_prepared'
  ) {
    throw new Error(`prior preparation failed: ${priorPreparation.kind}`);
  }
  const priorCommit = await store.recordServerActivation({
    preparedJournal: priorPreparation.journal,
    serverCommit: prior.serverCommit,
  });
  if (priorCommit.kind !== 'stored' || priorCommit.journal.kind !== 'server_activation_committed') {
    throw new Error(`prior server commit failed: ${priorCommit.kind}`);
  }
  const priorFinalization = await store.sealAndFinalizeActivation({
    committedJournal: priorCommit.journal,
    ...prior.sealInput,
  });
  if (priorFinalization.kind !== 'committed') {
    throw new Error(`prior finalization failed: ${priorFinalization.kind}`);
  }
  const replacementPreparation = await store.prepareActivation(replacement.prepareInput);
  if (
    replacementPreparation.kind !== 'stored' ||
    replacementPreparation.journal.kind !== 'activation_prepared'
  ) {
    throw new Error(`replacement preparation failed: ${replacementPreparation.kind}`);
  }
  const replacementCommit = await store.recordServerActivation({
    preparedJournal: replacementPreparation.journal,
    serverCommit: replacement.serverCommit,
  });
  if (
    replacementCommit.kind !== 'stored' ||
    replacementCommit.journal.kind !== 'server_activation_committed'
  ) {
    throw new Error(`replacement server commit failed: ${replacementCommit.kind}`);
  }
  const replacementFinalization = await store.sealAndFinalizeActivation({
    committedJournal: replacementCommit.journal,
    ...replacement.sealInput,
  });
  if (replacementFinalization.kind !== 'committed') {
    throw new Error(`replacement finalization failed: ${replacementFinalization.kind}`);
  }

  const active = await store.lookup(input.fixture.selectors.active);
  const exactBindingMismatch = await store.lookup(input.fixture.selectors.exactBindingMismatch);

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('seams_wallet');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const pointerKey = [
    input.fixture.selectors.active.capability,
    input.fixture.selectors.active.authority.walletId,
    input.fixture.selectors.active.authority.authorityDigest,
  ];
  const pointer = await new Promise<Record<string, unknown>>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_current_capability_manifests', 'readonly');
    const request = transaction.objectStore('ecdsa_current_capability_manifests').get(pointerKey);
    request.onsuccess = () => resolve(request.result as Record<string, unknown>);
    request.onerror = () => reject(request.error);
  });

  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_current_capability_manifests', 'readwrite');
    transaction.objectStore('ecdsa_current_capability_manifests').put({
      ...pointer,
      record_version: 'corrupt-pointer-version',
    });
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  const corrupt = await store.lookup(input.fixture.selectors.active);

  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_current_capability_manifests', 'readwrite');
    transaction.objectStore('ecdsa_current_capability_manifests').delete(pointerKey);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  const exactRecordConflict = await store.lookup(input.fixture.selectors.active);

  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(
      ['ecdsa_current_capability_manifests', 'ecdsa_capability_manifests'],
      'readwrite',
    );
    transaction.objectStore('ecdsa_current_capability_manifests').put({
      ...pointer,
      manifest_id: prior.prepareInput.activationBinding.targetManifest.manifestId,
      manifest_revision: prior.prepareInput.activationBinding.targetManifest.manifestRevision,
    });
    transaction
      .objectStore('ecdsa_capability_manifests')
      .delete(replacement.prepareInput.activationBinding.targetManifest.manifestId);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  const retired = await store.lookup(input.fixture.selectors.active);

  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction(
      ['ecdsa_current_capability_manifests', 'ecdsa_capability_manifests'],
      'readwrite',
    );
    transaction.objectStore('ecdsa_current_capability_manifests').delete(pointerKey);
    transaction
      .objectStore('ecdsa_capability_manifests')
      .delete(prior.prepareInput.activationBinding.targetManifest.manifestId);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();
  const missing = await store.lookup(input.fixture.selectors.missing);

  const unavailableStore = new module.IndexedDbEcdsaCapabilityManifestStore({
    runTransaction() {
      throw new Error('injected persistence failure');
    },
  });
  const persistenceUnavailable = await unavailableStore.lookup(input.fixture.selectors.active);

  return {
    active: active.kind,
    retired: retired.kind,
    missing: missing.kind,
    exactBindingMismatch: exactBindingMismatch.kind,
    exactRecordConflict: exactRecordConflict.kind,
    corrupt: corrupt.kind,
    persistenceUnavailable: persistenceUnavailable.kind,
  };
}

async function exercisePreparedActivationCancellation(input: {
  readonly storeModule: string;
  readonly fixture: EcdsaCapabilityActivationFixture;
}) {
  await new Promise<void>((resolve) => {
    const request = indexedDB.deleteDatabase('seams_wallet');
    request.onsuccess = () => resolve();
    request.onerror = () => resolve();
    request.onblocked = () => resolve();
  });
  const module = await import(input.storeModule);
  const store = new module.IndexedDbEcdsaCapabilityManifestStore();
  const preparation = await store.prepareActivation(input.fixture.prepareInput);
  if (preparation.kind !== 'stored' || preparation.journal.kind !== 'activation_prepared') {
    throw new Error(`preparation failed: ${preparation.kind}`);
  }
  const sealingKeyId = preparation.journal.candidate.encryptedPending.sealingKeyId;
  const conflictingJournal = structuredClone(preparation.journal);
  conflictingJournal.createdAt = '2025-01-02T00:00:00.000Z';
  const conflict = await store.cancelPreparedActivation(conflictingJournal);
  const afterConflict = await store.readActivationJournal(preparation.journal.journalId);
  const cancelled = await store.cancelPreparedActivation(preparation.journal);
  const afterCancellation = await store.readActivationJournal(preparation.journal.journalId);
  const repeated = await store.cancelPreparedActivation(preparation.journal);

  const secondPreparation = await store.prepareActivation(input.fixture.prepareInput);
  if (
    secondPreparation.kind !== 'stored' ||
    secondPreparation.journal.kind !== 'activation_prepared'
  ) {
    throw new Error(`second preparation failed: ${secondPreparation.kind}`);
  }
  const corruptSealingKeyId = secondPreparation.journal.candidate.encryptedPending.sealingKeyId;
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('seams_wallet');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_activation_commit_journals', 'readwrite');
    const journalStore = transaction.objectStore('ecdsa_activation_commit_journals');
    const get = journalStore.get(secondPreparation.journal.journalId);
    get.onsuccess = () => {
      journalStore.put({
        ...get.result,
        record_version: 'corrupt-activation-journal-version',
      });
    };
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  const corrupt = await store.cancelPreparedActivation(secondPreparation.journal);

  const state = await new Promise<{
    cancelledKeyPresent: boolean;
    corruptKeyPresent: boolean;
  }>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_material_sealing_keys', 'readonly');
    const keyStore = transaction.objectStore('ecdsa_material_sealing_keys');
    const cancelledKey = keyStore.get(sealingKeyId);
    const corruptKey = keyStore.get(corruptSealingKeyId);
    transaction.oncomplete = () => {
      resolve({
        cancelledKeyPresent: cancelledKey.result !== undefined,
        corruptKeyPresent: corruptKey.result !== undefined,
      });
    };
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();

  const unavailableStore = new module.IndexedDbEcdsaCapabilityManifestStore({
    runTransaction() {
      throw new Error('injected persistence failure');
    },
  });
  const persistenceUnavailable = await unavailableStore.cancelPreparedActivation(
    secondPreparation.journal,
  );

  return {
    conflict: conflict.kind,
    afterConflict: afterConflict.kind === 'found' ? afterConflict.journal.kind : afterConflict.kind,
    cancelled: cancelled.kind,
    afterCancellation: afterCancellation.kind,
    repeated: repeated.kind,
    corrupt: corrupt.kind,
    persistenceUnavailable: persistenceUnavailable.kind,
    ...state,
  };
}

async function exerciseReplacementActivationCancellation(input: {
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
  const priorCommit = await store.recordServerActivation({
    preparedJournal: priorPreparation.journal,
    serverCommit: input.fixture.prior.serverCommit,
  });
  if (priorCommit.kind !== 'stored' || priorCommit.journal.kind !== 'server_activation_committed') {
    throw new Error(`prior commit failed: ${priorCommit.kind}`);
  }
  const priorFinalization = await store.sealAndFinalizeActivation({
    committedJournal: priorCommit.journal,
    ...input.fixture.prior.sealInput,
  });
  if (priorFinalization.kind !== 'committed') {
    throw new Error(`prior finalization failed: ${priorFinalization.kind}`);
  }
  const priorSealingKeyId = priorFinalization.material.sealingKeyId;

  const replacementPreparation = await store.prepareActivation(
    input.fixture.replacement.prepareInput,
  );
  if (
    replacementPreparation.kind !== 'stored' ||
    replacementPreparation.journal.kind !== 'activation_prepared'
  ) {
    throw new Error(`replacement preparation failed: ${replacementPreparation.kind}`);
  }
  const cancelledReplacementSealingKeyId =
    replacementPreparation.journal.candidate.encryptedPending.sealingKeyId;
  const cancelled = await store.cancelPreparedActivation(replacementPreparation.journal);
  const afterPreparedCancellation = await store.lookup({
    capability: input.fixture.prior.prepareInput.activationBinding.signer.capability,
    authority: input.fixture.prior.prepareInput.activationBinding.signer.authority,
  });

  const committedPreparation = await store.prepareActivation(
    input.fixture.replacement.prepareInput,
  );
  if (
    committedPreparation.kind !== 'stored' ||
    committedPreparation.journal.kind !== 'activation_prepared'
  ) {
    throw new Error(`committed preparation failed: ${committedPreparation.kind}`);
  }
  const committedSealingKeyId =
    committedPreparation.journal.candidate.encryptedPending.sealingKeyId;
  const committedWrite = await store.recordServerActivation({
    preparedJournal: committedPreparation.journal,
    serverCommit: input.fixture.replacement.serverCommit,
  });
  if (
    committedWrite.kind !== 'stored' ||
    committedWrite.journal.kind !== 'server_activation_committed'
  ) {
    throw new Error(`replacement commit failed: ${committedWrite.kind}`);
  }
  const refused = await store.cancelPreparedActivation(committedPreparation.journal);
  const afterRefusal = await store.readActivationJournal(committedPreparation.journal.journalId);
  const finalization = await store.sealAndFinalizeActivation({
    committedJournal: committedWrite.journal,
    ...input.fixture.replacement.sealInput,
  });
  const afterFinalization = await store.lookup({
    capability: input.fixture.replacement.prepareInput.activationBinding.signer.capability,
    authority: input.fixture.replacement.prepareInput.activationBinding.signer.authority,
  });

  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('seams_wallet');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const keyState = await new Promise<{
    priorKeyPresent: boolean;
    cancelledReplacementKeyPresent: boolean;
    committedKeyPresent: boolean;
  }>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_material_sealing_keys', 'readonly');
    const keyStore = transaction.objectStore('ecdsa_material_sealing_keys');
    const priorKey = keyStore.get(priorSealingKeyId);
    const cancelledReplacementKey = keyStore.get(cancelledReplacementSealingKeyId);
    const committedKey = keyStore.get(committedSealingKeyId);
    transaction.oncomplete = () => {
      resolve({
        priorKeyPresent: priorKey.result !== undefined,
        cancelledReplacementKeyPresent: cancelledReplacementKey.result !== undefined,
        committedKeyPresent: committedKey.result !== undefined,
      });
    };
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();

  return {
    cancelled: cancelled.kind,
    afterPreparedCancellation: afterPreparedCancellation.kind,
    refused: refused.kind,
    afterRefusal: afterRefusal.kind === 'found' ? afterRefusal.journal.kind : afterRefusal.kind,
    finalization: finalization.kind,
    afterFinalization: afterFinalization.kind,
    ...keyState,
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
          pendingPayloadB64u:
            beforeCommitOpen.kind === 'found' ? beforeCommitOpen.pendingPayloadB64u : null,
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
      pendingPayloadB64u: fixture.prepareInput.pendingPayloadB64u,
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

  test('classifies every exact lookup outcome without fallback selection', async ({ page }) => {
    const fixture = ecdsaCapabilityLookupOutcomeFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(exerciseLookupOutcomeMatrix, {
      storeModule: STORE_MODULE,
      fixture,
    });

    expect(result).toEqual({
      active: 'active',
      retired: 'retired',
      missing: 'missing',
      exactBindingMismatch: 'exact_binding_mismatch',
      exactRecordConflict: 'exact_record_conflict',
      corrupt: 'corrupt',
      persistenceUnavailable: 'persistence_unavailable',
    });
  });

  test('atomically removes only the exact prepared journal and its sealing key', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(exercisePreparedActivationCancellation, {
      storeModule: STORE_MODULE,
      fixture,
    });

    expect(result).toEqual({
      conflict: 'exact_record_conflict',
      afterConflict: 'activation_prepared',
      cancelled: 'cancelled',
      afterCancellation: 'missing',
      repeated: 'missing',
      corrupt: 'corrupt',
      persistenceUnavailable: 'persistence_unavailable',
      cancelledKeyPresent: false,
      corruptKeyPresent: true,
    });
  });

  test('preserves active state and refuses cancellation after the server commit', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityReplacementFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(exerciseReplacementActivationCancellation, {
      storeModule: STORE_MODULE,
      fixture,
    });

    expect(result).toEqual({
      cancelled: 'cancelled',
      afterPreparedCancellation: 'active',
      refused: 'server_activation_committed',
      afterRefusal: 'server_activation_committed',
      finalization: 'committed',
      afterFinalization: 'active',
      priorKeyPresent: false,
      cancelledReplacementKeyPresent: false,
      committedKeyPresent: true,
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
