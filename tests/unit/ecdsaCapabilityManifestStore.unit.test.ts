import { execFileSync } from 'node:child_process';
import { unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
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
    '../../packages/wallet/src/core/indexedDB/seamsWalletDB/ecdsaCapabilityManifestStore.ts',
    import.meta.url,
  ),
);
const STORE_BUNDLE_PATH = `${tmpdir()}/seams-ecdsa-capability-store-${process.pid}.mjs`;
const STORE_MODULE = '/__ecdsa-capability-manifest-store-test.mjs';
const REPOSITORY_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const DERIVATION_WORKER_PATH = path.join(
  REPOSITORY_ROOT,
  'packages/wallet/dist/workers/ecdsa-derivation-client.worker.js',
);
const DERIVATION_WORKER_URL =
  'https://wallet.example.localhost/sdk/workers/ecdsa-derivation-client.worker.js?refactor90-reconciliation';
const ECDSA_REGISTRATION_CLIENT_WASM_PATH = path.join(
  REPOSITORY_ROOT,
  'packages/wallet/dist/workers/ecdsa_registration_client_bg.wasm',
);
const ECDSA_REGISTRATION_CLIENT_WASM_URL =
  'https://wallet.example.localhost/sdk/workers/ecdsa_registration_client_bg.wasm';
async function prepareStoreModulePage(page: Page): Promise<void> {
  await page.route(`**${STORE_MODULE}`, async (route) => {
    await route.fulfill({
      path: STORE_BUNDLE_PATH,
      contentType: 'application/javascript',
    });
  });
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
}

async function routeDerivationWorkerAssets(page: Page): Promise<void> {
  await page.route(DERIVATION_WORKER_URL, async (route) => {
    await route.fulfill({
      path: DERIVATION_WORKER_PATH,
      contentType: 'application/javascript',
    });
  });
  await page.route(ECDSA_REGISTRATION_CLIENT_WASM_URL, async (route) => {
    await route.fulfill({
      path: ECDSA_REGISTRATION_CLIENT_WASM_PATH,
      contentType: 'application/wasm',
    });
  });
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
  const priorByMaterialRef =
    priorFinalization.kind === 'committed'
      ? await store.lookupByMaterialRef({
          kind: 'ecdsa_role_local_persisted_material_ref_v1',
          durableMaterialRef: input.fixture.prior.prepareInput.activationBinding.durableMaterialRef,
          bindingDigest: input.fixture.prior.prepareInput.activationBinding.bindingDigest,
          materialActivation: priorFinalization.manifest.activation.materialActivation,
        })
      : null;
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
    priorByMaterialRefKind: priorByMaterialRef?.kind,
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

async function exerciseAtomicReplacementRollback(input: {
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
    throw new Error(`prior server commit failed: ${priorCommit.kind}`);
  }
  const priorFinalization = await store.sealAndFinalizeActivation({
    committedJournal: priorCommit.journal,
    ...input.fixture.prior.sealInput,
  });
  if (priorFinalization.kind !== 'committed') {
    throw new Error(`prior finalization failed: ${priorFinalization.kind}`);
  }

  const replacementPreparation = await store.prepareActivation(
    input.fixture.replacement.prepareInput,
  );
  if (
    replacementPreparation.kind !== 'stored' ||
    replacementPreparation.journal.kind !== 'activation_prepared'
  ) {
    throw new Error(`replacement preparation failed: ${replacementPreparation.kind}`);
  }
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

  const replacementManifestId =
    input.fixture.replacement.prepareInput.activationBinding.targetManifest.manifestId;
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('seams_wallet');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_capability_manifests', 'readwrite');
    transaction.objectStore('ecdsa_capability_manifests').add({
      manifest_id: replacementManifestId,
      injected_fault: 'duplicate_replacement_manifest',
    });
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  db.close();

  const replacementFinalization = await store.sealAndFinalizeActivation({
    committedJournal: replacementCommit.journal,
    ...input.fixture.replacement.sealInput,
  });
  const selector = {
    capability: input.fixture.prior.prepareInput.activationBinding.signer.capability,
    authority: input.fixture.prior.prepareInput.activationBinding.signer.authority,
  };
  const active = await store.lookup(selector);
  const opened = await store.openActiveMaterial(selector);
  const journal = await store.readActivationJournal(replacementCommit.journal.journalId);

  const inspectionDb = await new Promise<IDBDatabase>((resolve, reject) => {
    const request = indexedDB.open('seams_wallet');
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
  const inspection = await new Promise<{
    replacementMaterialPresent: boolean;
    faultSentinelPresent: boolean;
  }>((resolve, reject) => {
    const transaction = inspectionDb.transaction(
      ['ecdsa_role_local_material', 'ecdsa_capability_manifests'],
      'readonly',
    );
    const replacementMaterial = transaction
      .objectStore('ecdsa_role_local_material')
      .get(input.fixture.replacement.prepareInput.activationBinding.durableMaterialRef);
    const faultSentinel = transaction
      .objectStore('ecdsa_capability_manifests')
      .get(replacementManifestId);
    transaction.oncomplete = () => {
      resolve({
        replacementMaterialPresent: replacementMaterial.result !== undefined,
        faultSentinelPresent:
          (faultSentinel.result as { injected_fault?: unknown } | undefined)?.injected_fault ===
          'duplicate_replacement_manifest',
      });
    };
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  inspectionDb.close();

  return {
    replacementFinalizationKind: replacementFinalization.kind,
    activeKind: active.kind,
    activeManifestId: active.kind === 'active' ? active.manifest.identity.manifestId : null,
    openedKind: opened.kind,
    openedStateBlobB64u: opened.kind === 'active' ? opened.readyStateBlobB64u : null,
    journalKind: journal.kind,
    journalState: journal.kind === 'found' ? journal.journal.kind : null,
    ...inspection,
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
  const materialKey = replacement.prepareInput.activationBinding.durableMaterialRef;
  const persistedMaterial = await new Promise<Record<string, unknown>>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_role_local_material', 'readonly');
    const request = transaction.objectStore('ecdsa_role_local_material').get(materialKey);
    request.onsuccess = () => resolve(request.result as Record<string, unknown>);
    request.onerror = () => reject(request.error);
  });
  const sealingKeyId = String(persistedMaterial.sealing_key_id);
  const persistedSealingKey = await new Promise<Record<string, unknown>>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_material_sealing_keys', 'readonly');
    const request = transaction.objectStore('ecdsa_material_sealing_keys').get(sealingKeyId);
    request.onsuccess = () => resolve(request.result as Record<string, unknown>);
    request.onerror = () => reject(request.error);
  });
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_role_local_material', 'readwrite');
    transaction.objectStore('ecdsa_role_local_material').delete(materialKey);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  const missingReadyMaterial = await store.lookup(input.fixture.selectors.active);
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_role_local_material', 'readwrite');
    transaction.objectStore('ecdsa_role_local_material').put(persistedMaterial);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_material_sealing_keys', 'readwrite');
    transaction.objectStore('ecdsa_material_sealing_keys').delete(sealingKeyId);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
  });
  const missingSealingKey = await store.lookup(input.fixture.selectors.active);
  await new Promise<void>((resolve, reject) => {
    const transaction = db.transaction('ecdsa_material_sealing_keys', 'readwrite');
    transaction.objectStore('ecdsa_material_sealing_keys').put(persistedSealingKey);
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error);
    transaction.onabort = () => reject(transaction.error);
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
    missingSubject: missing.kind === 'missing' ? missing.subject : null,
    missingReadyMaterial:
      missingReadyMaterial.kind === 'missing'
        ? {
            kind: missingReadyMaterial.kind,
            subject: missingReadyMaterial.subject,
          }
        : { kind: missingReadyMaterial.kind, subject: null },
    missingSealingKey:
      missingSealingKey.kind === 'missing'
        ? {
            kind: missingSealingKey.kind,
            subject: missingSealingKey.subject,
          }
        : { kind: missingSealingKey.kind, subject: null },
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

  test('imports a Router-committed custody activation as canonical readable material', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityActivationFixture({
      targetMemberships: [
        { kind: 'evm', namespace: 'eip155', chainId: 8453, networkSlug: 'base' },
        { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-test' },
      ],
    });
    const roleFacts = fixture.sealInput.roleLocalPublicFacts;
    const receipt = fixture.serverCommit.protocolReceipt;
    const custodyPublicFacts = {
      contextBinding32B64u: roleFacts.contextBinding32B64u,
      derivationClientSharePublicKey33B64u: roleFacts.derivationClientSharePublicKey33B64u,
      clientVerifyingShare33B64u: roleFacts.derivationClientSharePublicKey33B64u,
      relayerPublicKey33B64u: roleFacts.relayerPublicKey33B64u,
      groupPublicKey33B64u: roleFacts.groupPublicKey33B64u,
      ethereumAddress: roleFacts.ethereumAddress,
      clientShareRetryCounter: receipt.ecdsa_activation.public_identity.client_share_retry_counter,
      relayerShareRetryCounter: receipt.ecdsa_activation.public_identity.server_share_retry_counter,
    };
    await prepareStoreModulePage(page);

    const result = await page.evaluate(
      async ({ storeModule, fixture, custodyPublicFacts }) => {
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        const module = await import(storeModule);
        const store = new module.IndexedDbEcdsaCapabilityManifestStore();
        const binding = fixture.prepareInput.activationBinding;
        const roleFacts = fixture.sealInput.roleLocalPublicFacts;
        const imported = await module.importWalletCustodyEcdsaContinuity({
          store,
          authority: binding.signer.authority,
          chainTargets: binding.signer.scope.targetMemberships,
          walletId: String(binding.signer.walletId),
          keyHandle: String(binding.roleLocalBinding.keyHandle),
          ecdsaThresholdKeyId: String(binding.roleLocalBinding.ecdsaThresholdKeyId),
          signingRootId: String(binding.signer.signingRootId),
          signingRootVersion: String(binding.signer.signingRootVersion),
          relayerKeyId: String(binding.roleLocalBinding.relayerKeyId),
          participantIds: [1, 2],
          publicCapability: roleFacts.publicCapability,
          activationReceipt: fixture.serverCommit.protocolReceipt,
          runtimePolicyScope: fixture.sealInput.runtimePolicyScope,
          readyStateBlobB64u: fixture.sealInput.readyStateBlobB64u,
          publicFacts: custodyPublicFacts,
        });
        const selector = {
          capability: binding.signer.capability,
          authority: binding.signer.authority,
        };
        const lookup = await store.lookup(selector);
        const opened = await store.openActiveMaterial(selector);
        return {
          importedKind: imported.kind,
          lookupKind: lookup.kind,
          materialActivation:
            lookup.kind === 'active' ? lookup.manifest.activation.materialActivation : null,
          targetMemberships:
            lookup.kind === 'active' ? lookup.manifest.signer.scope.targetMemberships : null,
          openedKind: opened.kind,
          readyStateBlobB64u: opened.kind === 'active' ? opened.readyStateBlobB64u : null,
        };
      },
      { storeModule: STORE_MODULE, fixture, custodyPublicFacts },
    );

    const wireMaterialActivation =
      fixture.serverCommit.protocolReceipt.ecdsa_activation.material_activation;
    expect(result).toEqual({
      importedKind: 'committed',
      lookupKind: 'active',
      materialActivation: {
        kind: 'mpc_material_activation_ref',
        activationId: wireMaterialActivation.activation_id,
        capability: wireMaterialActivation.capability,
        materialOwner: wireMaterialActivation.material_owner,
        keyBinding: wireMaterialActivation.key_binding,
        lifecycleBinding: wireMaterialActivation.lifecycle_binding,
        signingWorker: wireMaterialActivation.signing_worker,
      },
      targetMemberships: fixture.prepareInput.activationBinding.signer.scope.targetMemberships,
      openedKind: 'active',
      readyStateBlobB64u: fixture.sealInput.readyStateBlobB64u,
    });
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
        const module = await import(storeModule);
        const store = new module.IndexedDbEcdsaCapabilityManifestStore();
        const preparedWrite = await store.prepareActivation(fixture.prepareInput);
        if (
          preparedWrite.kind !== 'stored' ||
          preparedWrite.journal.kind !== 'activation_prepared'
        ) {
          throw new Error(`preparation failed: ${preparedWrite.kind}`);
        }
        const preparedJournalSelectors = await store.listWalletActivationJournalSelectors(
          fixture.prepareInput.activationBinding.signer.authority.walletId,
        );
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
        const committedOpen = await store.openPreparedActivation(committedWrite.journal.journalId);
        const beforeFinalize = await store.readActivationJournal(preparedWrite.journal.journalId);
        const finalization = await store.sealAndFinalizeActivation({
          committedJournal: committedWrite.journal,
          ...fixture.sealInput,
        });
        if (finalization.kind !== 'committed') {
          throw new Error(`finalization failed: ${finalization.kind}`);
        }
        const materialActivation = finalization.manifest.activation.materialActivation;
        const afterFinalize = await store.readActivationJournal(preparedWrite.journal.journalId);
        const opened = await store.openActiveMaterial({
          capability: fixture.prepareInput.activationBinding.signer.capability,
          authority: fixture.prepareInput.activationBinding.signer.authority,
        });
        const openedByMaterialRef = await store.openActiveMaterialByRef({
          kind: 'ecdsa_role_local_persisted_material_ref_v1',
          durableMaterialRef: fixture.prepareInput.activationBinding.durableMaterialRef,
          bindingDigest: fixture.prepareInput.activationBinding.bindingDigest,
          materialActivation,
        });
        const lookupByMaterialRef = await store.lookupByMaterialRef({
          kind: 'ecdsa_role_local_persisted_material_ref_v1',
          durableMaterialRef: fixture.prepareInput.activationBinding.durableMaterialRef,
          bindingDigest: fixture.prepareInput.activationBinding.bindingDigest,
          materialActivation,
        });
        await new Promise<void>((resolve, reject) => {
          const request = indexedDB.open('seams_wallet');
          request.onsuccess = () => {
            const db = request.result;
            const transaction = db.transaction('ecdsa_current_capability_manifests', 'readwrite');
            transaction.objectStore('ecdsa_current_capability_manifests').put({
              record_version: 'obsolete_pointer_version',
              capability_ref: 'capability-for-another-wallet',
              wallet_id: 'another-wallet',
              authority_digest: 'authority-for-another-wallet',
              manifest_id: 'manifest-for-another-wallet',
              manifest_revision: 1,
            });
            transaction.oncomplete = () => {
              db.close();
              resolve();
            };
            transaction.onerror = () => reject(transaction.error);
            transaction.onabort = () => reject(transaction.error);
          };
          request.onerror = () => reject(request.error);
        });
        const activeWalletSubjects = await store.listActiveWalletCapabilitySubjects(
          fixture.prepareInput.activationBinding.signer.authority.walletId,
        );
        const finalizedJournalSelectors = await store.listWalletActivationJournalSelectors(
          fixture.prepareInput.activationBinding.signer.authority.walletId,
        );
        const activationMismatch = await store.lookupByMaterialRef({
          kind: 'ecdsa_role_local_persisted_material_ref_v1',
          durableMaterialRef: fixture.prepareInput.activationBinding.durableMaterialRef,
          bindingDigest: fixture.prepareInput.activationBinding.bindingDigest,
          materialActivation: {
            ...materialActivation,
            signingWorker: `${materialActivation.signingWorker}:mismatch`,
          },
        });
        const mismatchedMaterialRef = await store.openActiveMaterialByRef({
          kind: 'ecdsa_role_local_persisted_material_ref_v1',
          durableMaterialRef: fixture.prepareInput.activationBinding.durableMaterialRef,
          bindingDigest: 'different-binding-digest',
          materialActivation,
        });
        return {
          preparedWriteKind: preparedWrite.kind,
          preparedJournalSelectors,
          committedWriteKind: committedWrite.kind,
          beforeCommitOpenKind: beforeCommitOpen.kind,
          pendingPayloadB64u:
            beforeCommitOpen.kind === 'found' ? beforeCommitOpen.pendingPayloadB64u : null,
          committedOpenKind: committedOpen.kind,
          committedPendingPayloadB64u:
            committedOpen.kind === 'found' ? committedOpen.pendingPayloadB64u : null,
          beforeFinalizeKind: beforeFinalize.kind,
          finalizationKind: finalization.kind,
          afterFinalizeKind: afterFinalize.kind,
          openKind: opened.kind,
          readyStateBlobB64u: opened.kind === 'active' ? opened.readyStateBlobB64u : null,
          openByMaterialRefKind: openedByMaterialRef.kind,
          lookupByMaterialRefKind: lookupByMaterialRef.kind,
          activeWalletSubjects,
          finalizedJournalSelectors,
          activationMismatchKind: activationMismatch.kind,
          materialRefStateBlobB64u:
            openedByMaterialRef.kind === 'active' ? openedByMaterialRef.readyStateBlobB64u : null,
          mismatchedMaterialRefKind: mismatchedMaterialRef.kind,
        };
      },
      {
        storeModule: STORE_MODULE,
        fixture,
      },
    );

    expect(result).toEqual({
      preparedWriteKind: 'stored',
      preparedJournalSelectors: {
        kind: 'resolved',
        selectors: [
          {
            capability: fixture.prepareInput.activationBinding.signer.capability,
            authority: fixture.prepareInput.activationBinding.signer.authority,
          },
        ],
      },
      committedWriteKind: 'stored',
      beforeCommitOpenKind: 'found',
      pendingPayloadB64u: fixture.prepareInput.pendingPayloadB64u,
      committedOpenKind: 'found',
      committedPendingPayloadB64u: fixture.prepareInput.pendingPayloadB64u,
      beforeFinalizeKind: 'found',
      finalizationKind: 'committed',
      afterFinalizeKind: 'missing',
      openKind: 'active',
      readyStateBlobB64u: fixture.sealInput.readyStateBlobB64u,
      openByMaterialRefKind: 'active',
      lookupByMaterialRefKind: 'active',
      activeWalletSubjects: {
        kind: 'resolved',
        subjects: [
          {
            capability: fixture.prepareInput.activationBinding.signer.capability,
            authority: fixture.prepareInput.activationBinding.signer.authority,
            ecdsaThresholdKeyId:
              fixture.prepareInput.activationBinding.roleLocalBinding.ecdsaThresholdKeyId,
          },
        ],
      },
      finalizedJournalSelectors: {
        kind: 'resolved',
        selectors: [],
      },
      activationMismatchKind: 'exact_binding_mismatch',
      materialRefStateBlobB64u: fixture.sealInput.readyStateBlobB64u,
      mismatchedMaterialRefKind: 'binding_mismatch',
    });
  });

  test('converges prepared and server-committed activation journals after reload', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    await prepareStoreModulePage(page);
    await routeDerivationWorkerAssets(page);
    const result = await page.evaluate(
      async ({ storeModule, workerUrl, fixture }) => {
        const requestWorker = async (
          worker: Worker,
          id: string,
          type: number,
          payload: Record<string, unknown>,
        ): Promise<Record<string, unknown>> =>
          await new Promise<Record<string, unknown>>((resolve, reject) => {
            const timeout = window.setTimeout(() => reject(new Error(id + ' timed out')), 10_000);
            worker.addEventListener('message', (event) => {
              const value = event.data as {
                id?: unknown;
                ok?: unknown;
                error?: unknown;
                result?: Record<string, unknown>;
              };
              if (value.id !== id) return;
              window.clearTimeout(timeout);
              if (value.ok !== true || !value.result) {
                reject(new Error(String(value.error || id + ' failed')));
                return;
              }
              resolve(value.result);
            });
            worker.postMessage({ id, type, payload });
          });

        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        const module = await import(storeModule);
        const store = new module.IndexedDbEcdsaCapabilityManifestStore();
        const selector = {
          capability: fixture.prepareInput.activationBinding.signer.capability,
          authority: fixture.prepareInput.activationBinding.signer.authority,
        };
        const preparation = await store.prepareActivation(fixture.prepareInput);
        if (preparation.kind !== 'stored' || preparation.journal.kind !== 'activation_prepared') {
          throw new Error('activation preparation failed');
        }

        const preparedWorker = new Worker(workerUrl, { type: 'module' });
        const preparedResponse = await requestWorker(
          preparedWorker,
          'canonical-activation-reconcile-prepared',
          70_017,
          {
            kind: 'reconcile_canonical_ecdsa_activation_v1',
            ...selector,
          },
        );
        preparedWorker.terminate();
        const preparedJournal = await store.discoverActivationJournal(selector);

        const committed = await store.recordServerActivation({
          preparedJournal: preparation.journal,
          serverCommit: fixture.serverCommit,
        });
        if (
          committed.kind !== 'stored' ||
          committed.journal.kind !== 'server_activation_committed'
        ) {
          throw new Error('server activation commit failed');
        }

        const committedWorker = new Worker(workerUrl, { type: 'module' });
        const committedResponse = await requestWorker(
          committedWorker,
          'canonical-activation-reconcile-committed',
          70_017,
          {
            kind: 'reconcile_canonical_ecdsa_activation_v1',
            ...selector,
          },
        );
        const committedPayload = committedResponse.payload as Record<string, unknown> | undefined;
        if (
          committedPayload?.kind !== 'canonical_ecdsa_activation_committed_finalization_required_v1'
        ) {
          throw new Error('committed reconciliation did not return finalization input');
        }
        const finalizationResponse = await requestWorker(
          committedWorker,
          'canonical-activation-reconcile-finalize',
          70_008,
          {
            kind: 'finalize_router_ab_ecdsa_registration_activation_v1',
            journalId: committedPayload.journalId,
            activationReceipt: committedPayload.activationReceipt,
            routerAbEcdsaDerivationNormalSigning:
              committedPayload.routerAbEcdsaDerivationNormalSigning,
          },
        );
        committedWorker.terminate();

        const journal = await store.discoverActivationJournal(selector);
        const active = await store.lookup(selector);
        return {
          preparedType: preparedResponse.type,
          preparedKind: (preparedResponse.payload as Record<string, unknown> | undefined)?.kind,
          preparedJournal:
            preparedJournal.kind === 'found' ? preparedJournal.journal.kind : preparedJournal.kind,
          committedType: committedResponse.type,
          committedKind: committedPayload.kind,
          finalizationType: finalizationResponse.type,
          activationKind: (finalizationResponse.payload as Record<string, unknown> | undefined)
            ?.kind,
          journal: journal.kind,
          active: active.kind,
        };
      },
      { storeModule: STORE_MODULE, workerUrl: DERIVATION_WORKER_URL, fixture },
    );

    expect(result).toEqual({
      preparedType: 70_117,
      preparedKind: 'canonical_ecdsa_activation_reconciliation_pending_v1',
      preparedJournal: 'activation_prepared',
      committedType: 70_117,
      committedKind: 'canonical_ecdsa_activation_committed_finalization_required_v1',
      finalizationType: 70_108,
      activationKind: 'router_ab_ecdsa_registration_activation_finalized_v1',
      journal: 'missing',
      active: 'active',
    });
  });

  test('rehydrates canonical material through a fresh worker after termination', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityActivationFixture();
    await page.route(DERIVATION_WORKER_URL, async (route) => {
      await route.fulfill({
        path: DERIVATION_WORKER_PATH,
        contentType: 'application/javascript',
      });
    });
    await prepareStoreModulePage(page);

    const result = await page.evaluate(
      async ({ storeModule, workerUrl, fixture }) => {
        await new Promise<void>((resolve) => {
          const request = indexedDB.deleteDatabase('seams_wallet');
          request.onsuccess = () => resolve();
          request.onerror = () => resolve();
          request.onblocked = () => resolve();
        });
        const module = await import(storeModule);
        const store = new module.IndexedDbEcdsaCapabilityManifestStore();
        const prepared = await store.prepareActivation(fixture.prepareInput);
        if (prepared.kind !== 'stored' || prepared.journal.kind !== 'activation_prepared') {
          throw new Error(`preparation failed: ${prepared.kind}`);
        }
        const committed = await store.recordServerActivation({
          preparedJournal: prepared.journal,
          serverCommit: fixture.serverCommit,
        });
        if (
          committed.kind !== 'stored' ||
          committed.journal.kind !== 'server_activation_committed'
        ) {
          throw new Error(`server commit failed: ${committed.kind}`);
        }
        const finalized = await store.sealAndFinalizeActivation({
          committedJournal: committed.journal,
          ...fixture.sealInput,
        });
        if (finalized.kind !== 'committed') {
          throw new Error(`finalization failed: ${finalized.kind}`);
        }
        const binding = fixture.prepareInput.activationBinding;
        const roleFacts = fixture.sealInput.roleLocalPublicFacts;
        const receipt = fixture.serverCommit.protocolReceipt;
        const alternateAuthority = {
          ...finalized.manifest.signer.authority,
          authorityDigest: 'authority-alternate',
          walletAuthMethodId: 'wallet-auth-method-alternate',
        };
        const alternate = await module.importWalletCustodyEcdsaContinuity({
          store,
          authority: alternateAuthority,
          chainTargets: binding.signer.scope.targetMemberships,
          walletId: String(binding.signer.walletId),
          keyHandle: String(binding.roleLocalBinding.keyHandle),
          ecdsaThresholdKeyId: String(binding.roleLocalBinding.ecdsaThresholdKeyId),
          signingRootId: String(binding.signer.signingRootId),
          signingRootVersion: String(binding.signer.signingRootVersion),
          relayerKeyId: String(binding.roleLocalBinding.relayerKeyId),
          participantIds: [1, 2],
          publicCapability: roleFacts.publicCapability,
          activationReceipt: receipt,
          runtimePolicyScope: fixture.sealInput.runtimePolicyScope,
          readyStateBlobB64u: fixture.sealInput.readyStateBlobB64u,
          publicFacts: {
            contextBinding32B64u: roleFacts.contextBinding32B64u,
            derivationClientSharePublicKey33B64u: roleFacts.derivationClientSharePublicKey33B64u,
            clientVerifyingShare33B64u: roleFacts.derivationClientSharePublicKey33B64u,
            relayerPublicKey33B64u: roleFacts.relayerPublicKey33B64u,
            groupPublicKey33B64u: roleFacts.groupPublicKey33B64u,
            ethereumAddress: roleFacts.ethereumAddress,
            clientShareRetryCounter:
              receipt.ecdsa_activation.public_identity.client_share_retry_counter,
            relayerShareRetryCounter:
              receipt.ecdsa_activation.public_identity.server_share_retry_counter,
          },
        });
        if (alternate.kind !== 'committed') {
          throw new Error(`alternate authority import failed: ${alternate.kind}`);
        }
        const materialRef = {
          kind: 'ecdsa_role_local_persisted_material_ref_v1',
          durableMaterialRef: fixture.prepareInput.activationBinding.durableMaterialRef,
          bindingDigest: fixture.prepareInput.activationBinding.bindingDigest,
          materialActivation: finalized.manifest.activation.materialActivation,
        };

        const firstWorker = new Worker(workerUrl, { type: 'module' });
        const firstReady = await new Promise<boolean>((resolve, reject) => {
          const timeout = window.setTimeout(
            () => reject(new Error('first worker ready timeout')),
            10_000,
          );
          firstWorker.addEventListener('message', (event) => {
            const value = event.data as { type?: unknown; ready?: unknown };
            if (value.type !== 'WORKER_READY' && value.ready !== true) return;
            window.clearTimeout(timeout);
            resolve(true);
          });
          firstWorker.addEventListener('error', (event) => reject(new Error(event.message)), {
            once: true,
          });
        });
        const first = await new Promise<Record<string, unknown>>((resolve, reject) => {
          const requestId = 'canonical-rehydrate-first';
          const timeout = window.setTimeout(
            () => reject(new Error('first worker RPC timeout')),
            10_000,
          );
          firstWorker.addEventListener('message', (event) => {
            const value = event.data as {
              id?: unknown;
              ok?: unknown;
              error?: unknown;
              result?: Record<string, unknown>;
            };
            if (value.id !== requestId) return;
            window.clearTimeout(timeout);
            if (value.ok !== true || !value.result) {
              reject(new Error(String(value.error || 'first worker RPC failed')));
              return;
            }
            resolve(value.result);
          });
          firstWorker.postMessage({
            id: requestId,
            type: 70_015,
            payload: {
              kind: 'open_ecdsa_role_local_signing_material_v1',
              authority: finalized.manifest.signer.authority,
              materialActivation: materialRef.materialActivation,
            },
          });
        });

        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const request = indexedDB.open('seams_wallet');
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
        const persistedMaterial = await new Promise<Record<string, unknown>>((resolve, reject) => {
          const transaction = db.transaction('ecdsa_role_local_material', 'readonly');
          const request = transaction
            .objectStore('ecdsa_role_local_material')
            .get(materialRef.durableMaterialRef);
          request.onsuccess = () => resolve(request.result as Record<string, unknown>);
          request.onerror = () => reject(request.error);
        });
        const sealingKeyId = String(persistedMaterial.sealing_key_id);
        const persistedSealingKey = await new Promise<Record<string, unknown>>(
          (resolve, reject) => {
            const transaction = db.transaction('ecdsa_material_sealing_keys', 'readonly');
            const request = transaction
              .objectStore('ecdsa_material_sealing_keys')
              .get(sealingKeyId);
            request.onsuccess = () => resolve(request.result as Record<string, unknown>);
            request.onerror = () => reject(request.error);
          },
        );
        const unusableSealingKey = await crypto.subtle.generateKey(
          { name: 'AES-GCM', length: 256 },
          false,
          ['encrypt', 'decrypt'],
        );
        await new Promise<void>((resolve, reject) => {
          const transaction = db.transaction('ecdsa_material_sealing_keys', 'readwrite');
          transaction.objectStore('ecdsa_material_sealing_keys').put({
            ...persistedSealingKey,
            key: unusableSealingKey,
          });
          transaction.oncomplete = () => resolve();
          transaction.onerror = () => reject(transaction.error);
          transaction.onabort = () => reject(transaction.error);
        });

        const live = await new Promise<Record<string, unknown>>((resolve, reject) => {
          const requestId = 'canonical-rehydrate-live';
          const timeout = window.setTimeout(
            () => reject(new Error('live worker RPC timeout')),
            10_000,
          );
          firstWorker.addEventListener('message', (event) => {
            const value = event.data as {
              id?: unknown;
              ok?: unknown;
              error?: unknown;
              result?: Record<string, unknown>;
            };
            if (value.id !== requestId) return;
            window.clearTimeout(timeout);
            if (value.ok !== true || !value.result) {
              reject(new Error(String(value.error || 'live worker RPC failed')));
              return;
            }
            resolve(value.result);
          });
          firstWorker.postMessage({
            id: requestId,
            type: 70_015,
            payload: {
              kind: 'open_ecdsa_role_local_signing_material_v1',
              authority: finalized.manifest.signer.authority,
              materialActivation: materialRef.materialActivation,
            },
          });
        });
        const mismatch = await new Promise<Record<string, unknown>>((resolve, reject) => {
          const requestId = 'canonical-rehydrate-mismatch';
          const timeout = window.setTimeout(
            () => reject(new Error('mismatch worker RPC timeout')),
            10_000,
          );
          firstWorker.addEventListener('message', (event) => {
            const value = event.data as {
              id?: unknown;
              ok?: unknown;
              error?: unknown;
              result?: Record<string, unknown>;
            };
            if (value.id !== requestId) return;
            window.clearTimeout(timeout);
            if (value.ok !== true || !value.result) {
              reject(new Error(String(value.error || 'mismatch worker RPC failed')));
              return;
            }
            resolve(value.result);
          });
          firstWorker.postMessage({
            id: requestId,
            type: 70_015,
            payload: {
              kind: 'open_ecdsa_role_local_signing_material_v1',
              authority: finalized.manifest.signer.authority,
              materialActivation: {
                ...materialRef.materialActivation,
                signingWorker: `${materialRef.materialActivation.signingWorker}:mismatch`,
              },
            },
          });
        });

        await new Promise<void>((resolve, reject) => {
          const transaction = db.transaction('ecdsa_material_sealing_keys', 'readwrite');
          transaction.objectStore('ecdsa_material_sealing_keys').put(persistedSealingKey);
          transaction.oncomplete = () => resolve();
          transaction.onerror = () => reject(transaction.error);
          transaction.onabort = () => reject(transaction.error);
        });
        db.close();
        firstWorker.terminate();

        const secondWorker = new Worker(workerUrl, { type: 'module' });
        const secondReady = await new Promise<boolean>((resolve, reject) => {
          const timeout = window.setTimeout(
            () => reject(new Error('second worker ready timeout')),
            10_000,
          );
          secondWorker.addEventListener('message', (event) => {
            const value = event.data as { type?: unknown; ready?: unknown };
            if (value.type !== 'WORKER_READY' && value.ready !== true) return;
            window.clearTimeout(timeout);
            resolve(true);
          });
          secondWorker.addEventListener('error', (event) => reject(new Error(event.message)), {
            once: true,
          });
        });
        const second = await new Promise<Record<string, unknown>>((resolve, reject) => {
          const requestId = 'canonical-rehydrate-second';
          const timeout = window.setTimeout(
            () => reject(new Error('second worker RPC timeout')),
            10_000,
          );
          secondWorker.addEventListener('message', (event) => {
            const value = event.data as {
              id?: unknown;
              ok?: unknown;
              error?: unknown;
              result?: Record<string, unknown>;
            };
            if (value.id !== requestId) return;
            window.clearTimeout(timeout);
            if (value.ok !== true || !value.result) {
              reject(new Error(String(value.error || 'second worker RPC failed')));
              return;
            }
            resolve(value.result);
          });
          secondWorker.postMessage({
            id: requestId,
            type: 70_015,
            payload: {
              kind: 'open_ecdsa_role_local_signing_material_v1',
              authority: finalized.manifest.signer.authority,
              materialActivation: materialRef.materialActivation,
            },
          });
        });
        secondWorker.terminate();

        return { firstReady, secondReady, first, live, mismatch, second };
      },
      {
        storeModule: STORE_MODULE,
        workerUrl: DERIVATION_WORKER_URL,
        fixture,
      },
    );

    expect(result.firstReady).toBe(true);
    expect(result.secondReady).toBe(true);
    expect(result.first.type).toBe(70_115);
    expect(result.live).toMatchObject({
      type: result.first.type,
      payload: result.first.payload,
    });
    expect(result.mismatch).toMatchObject({
      type: 70_115,
      payload: {
        kind: 'ecdsa_role_local_signing_material_unavailable_v1',
        ok: false,
        reason: 'binding_mismatch',
      },
    });
    expect(result.second.type).toBe(70_115);
    expect(result.second.payload).toEqual(result.first.payload);
    expect(result.second.payload).toMatchObject({
      kind: 'ecdsa_role_local_signing_material_opened_v1',
      liveHandle: {
        kind: 'ecdsa_role_local_worker_handle_v1',
        materialHandle: fixture.prepareInput.activationBinding.durableMaterialRef,
        durableMaterialRef: fixture.prepareInput.activationBinding.durableMaterialRef,
        bindingDigest: fixture.prepareInput.activationBinding.bindingDigest,
      },
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
      priorByMaterialRefKind: 'retired',
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

  test('rolls back source retirement and replacement writes when finalization faults', async ({
    page,
  }) => {
    const fixture = ecdsaCapabilityReplacementFixture();
    await prepareStoreModulePage(page);
    const result = await page.evaluate(exerciseAtomicReplacementRollback, {
      storeModule: STORE_MODULE,
      fixture,
    });

    expect(result).toEqual({
      replacementFinalizationKind: 'exact_record_conflict',
      activeKind: 'active',
      activeManifestId: fixture.prior.prepareInput.activationBinding.targetManifest.manifestId,
      openedKind: 'active',
      openedStateBlobB64u: fixture.prior.sealInput.readyStateBlobB64u,
      journalKind: 'found',
      journalState: 'server_activation_committed',
      replacementMaterialPresent: false,
      faultSentinelPresent: true,
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
      priorByMaterialRefKind: 'active',
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
      missingSubject: 'capability',
      missingReadyMaterial: {
        kind: 'missing',
        subject: 'material',
      },
      missingSealingKey: {
        kind: 'missing',
        subject: 'material',
      },
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
