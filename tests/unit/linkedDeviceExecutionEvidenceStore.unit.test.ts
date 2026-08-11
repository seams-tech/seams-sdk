import { expect, test } from '@playwright/test';
import { buildLinkedDeviceProvisionedExecutionEvidenceV1 } from '../../packages/sdk-web/src/core/signingEngine/session/lanes/linkedDeviceExecutionBundle';
import { setupBasicPasskeyTest } from '../setup';
import { buildR103ActiveExecutionFixture } from './helpers/deviceLinkContracts.fixtures';

test('persists one exact public linked-device execution evidence record', async ({ page }) => {
  await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  const fixture = await buildR103ActiveExecutionFixture();
  const evidence = await buildLinkedDeviceProvisionedExecutionEvidenceV1({
    approval: fixture.deviceLink.approval,
    targetPreparation: fixture.targetCredential.preparation,
    targetCredentialRegistration: fixture.targetCredential.registration,
    provisioningDeliveries: fixture.provisioning.deliveries,
    enrollmentReceipt: fixture.deviceLink.receipt,
  });
  const result = await page.evaluate(async (input) => {
    const schema = await import('/_test-sdk/esm/core/indexedDB/schemaNames.js');
    const managerModule = await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/manager.js');
    const storeModule =
      await import('/_test-sdk/esm/core/indexedDB/seamsWalletDB/linkedDeviceExecutionEvidenceStore.js');
    const dbName = schema.createSeamsTestWalletDbName(`linked_evidence_${crypto.randomUUID()}`);
    const manager = new managerModule.SeamsWalletDBManager();
    manager.setDbName(dbName);
    const repository = new storeModule.LinkedDeviceExecutionEvidenceRepositoryV1(manager);
    try {
      const persisted = await repository.putExactProvisionedEvidenceV1(input);
      const replayed = await repository.putExactProvisionedEvidenceV1(input);
      const found = await repository.readForEnrollmentV1(input.approval.enrollmentId);
      let replayMismatchRejected = false;
      try {
        await repository.putExactProvisionedEvidenceV1({
          ...input,
          enrollmentReceipt: {
            ...input.enrollmentReceipt,
            aggregateReceiptDigestB64u: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          },
        });
      } catch {
        replayMismatchRejected = true;
      }
      const db = await manager.getDB();
      await db.put(schema.SEAMS_WALLET_STORES.linkedDeviceExecutionEvidence, {
        enrollment_id: input.approval.enrollmentId,
        wallet_id: input.approval.walletId,
        device_id: input.approval.deviceId,
        manifest_digest_b64u: input.enrollmentReceipt.manifestDigestB64u,
        evidence: { ...input, unexpected: true },
      });
      const corrupt = await repository.readForEnrollmentV1(input.approval.enrollmentId);
      await repository.clearEnrollmentV1(input.approval.enrollmentId);
      const cleared = await repository.readForEnrollmentV1(input.approval.enrollmentId);
      return { persisted, replayed, found, replayMismatchRejected, corrupt, cleared };
    } finally {
      manager.close();
      await new Promise<void>((resolve) => {
        const request = indexedDB.deleteDatabase(dbName);
        request.onsuccess = () => resolve();
        request.onerror = () => resolve();
        request.onblocked = () => resolve();
      });
    }
  }, evidence);

  expect(result.persisted).toEqual(evidence);
  expect(result.replayed).toEqual(evidence);
  expect(result.found).toEqual({ kind: 'found', evidence });
  expect(result.replayMismatchRejected).toBe(true);
  expect(result.corrupt).toEqual({ kind: 'corrupt' });
  expect(result.cleared).toEqual({ kind: 'missing' });
  expect(JSON.stringify(evidence)).not.toContain('holderPackage');
  expect(JSON.stringify(evidence)).not.toContain('walletSessionJwt');
});
