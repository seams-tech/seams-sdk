import { expect, test } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setupBasicPasskeyTest } from '../setup';

const TEST_DIRECTORY = path.dirname(fileURLToPath(import.meta.url));
const REPOSITORY_ROOT = path.resolve(TEST_DIRECTORY, '../..');
const STORE_SOURCE = path.join(
  REPOSITORY_ROOT,
  'packages/sdk-web/src/core/signingEngine/workerManager/workers/ecdsaPresignMaterialStore.ts',
);
const STORE_BUNDLE_PATH = path.join(tmpdir(), `seams-ecdsa-presign-store-${process.pid}.mjs`);
const STORE_MODULE = '/__ecdsa-presign-material-store-test.mjs';

test.describe('ECDSA Client presign material store', () => {
  test.beforeAll(() => {
    execFileSync(
      'bun',
      ['build', STORE_SOURCE, '--target=browser', '--format=esm', `--outfile=${STORE_BUNDLE_PATH}`],
      { cwd: REPOSITORY_ROOT, stdio: 'pipe' },
    );
  });

  test.afterAll(() => {
    try {
      unlinkSync(STORE_BUNDLE_PATH);
    } catch {}
  });

  test.beforeEach(async ({ page }) => {
    await page.route(`**${STORE_MODULE}`, async (route) => {
      await route.fulfill({ path: STORE_BUNDLE_PATH, contentType: 'application/javascript' });
    });
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('persists only ciphertext and atomically consumes material once', async ({ page }) => {
    const result = await page.evaluate(async ({ modulePath, dbName }) => {
      const { IndexedDbClientPresignMaterialStore } = await import(modulePath);
      const store = new IndexedDbClientPresignMaterialStore(dbName);
      const bytes = (length: number, value: number): Uint8Array =>
        new Uint8Array(length).fill(value);
      const poolIdentity = {
        poolKey: 'pool-1',
        walletKeyId: 'wallet-key-1',
        walletId: 'wallet-1',
        signingScopeB64u: 'scope-1',
        pairRole: 'client' as const,
        keyEpoch: 'key-epoch-1',
        activationEpoch: 'activation-epoch-1',
        protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
      };
      const input = {
        materialHandle: 'material-1',
        presignSessionId: 'session-1',
        poolIdentity,
        groupPublicKey33: bytes(33, 1),
        bigR33: bytes(33, 2),
        kShare32: bytes(32, 3),
        sigmaShare32: bytes(32, 4),
        createdAtMs: 1_000,
        expiresAtMs: 10_000,
      };
      const presignatureId = await store.putPendingAdmission(input);

      const inspectRecord = async (): Promise<Record<string, unknown>> => {
        const database = await new Promise<IDBDatabase>((resolve, reject) => {
          const request = indexedDB.open(dbName);
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
        const transaction = database.transaction('presign_records', 'readonly');
        const record = await new Promise<Record<string, unknown>>((resolve, reject) => {
          const request = transaction.objectStore('presign_records').get('material-1');
          request.onsuccess = () => resolve(request.result as Record<string, unknown>);
          request.onerror = () => reject(request.error);
        });
        await new Promise<void>((resolve, reject) => {
          transaction.oncomplete = () => resolve();
          transaction.onabort = () => reject(transaction.error);
          transaction.onerror = () => reject(transaction.error);
        });
        database.close();
        return record;
      };

      const pendingAdmission = await inspectRecord();
      const admission = await store.admit({
        materialHandle: 'material-1',
        expectedPresignatureId: presignatureId,
        nowMs: 1_500,
      });
      const available = await inspectRecord();
      await store.reserve({
        materialHandle: 'material-1',
        requestBinding: 'request-1',
        reservationId: 'reservation-1',
        nowMs: 1_600,
        leaseExpiresAtMs: 9_000,
      });
      await store.commit({
        materialHandle: 'material-1',
        requestBinding: 'request-1',
        reservationId: 'reservation-1',
        nowMs: 1_700,
      });
      const [first, second] = await Promise.all([
        store.takeForOnline({
          materialHandle: 'material-1',
          requestBinding: 'request-1',
          reservationId: 'reservation-1',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        }),
        store.takeForOnline({
          materialHandle: 'material-1',
          requestBinding: 'request-1',
          reservationId: 'reservation-1',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        }),
      ]);
      const tombstone = await inspectRecord();
      const winners = [first, second].filter((entry) => entry.ok);
      const losers = [first, second].filter((entry) => !entry.ok);
      const material = winners[0]?.ok ? winners[0].material : null;
      await store.deleteDatabaseForTests();
      return {
        pendingAdmissionState: pendingAdmission.state,
        admissionOk: admission.ok,
        availableState: available.state,
        availableHasCiphertext: available.ciphertext instanceof ArrayBuffer,
        availableHasPlaintextShares: 'kShare32' in available || 'sigmaShare32' in available,
        winnerCount: winners.length,
        loserCodes: losers.map((entry) => (entry.ok ? '' : entry.code)),
        returned: material
          ? {
              bigR33: Array.from(material.bigR33),
              kShare32: Array.from(material.kShare32),
              sigmaShare32: Array.from(material.sigmaShare32),
            }
          : null,
        tombstoneState: tombstone.state,
        tombstoneReason: tombstone.reason,
        tombstoneHasCiphertext: 'ciphertext' in tombstone,
      };
    }, { modulePath: STORE_MODULE, dbName: `ecdsa-presign-once-${Date.now()}` });

    expect(result).toEqual({
      pendingAdmissionState: 'pending_admission',
      admissionOk: true,
      availableState: 'available',
      availableHasCiphertext: true,
      availableHasPlaintextShares: false,
      winnerCount: 1,
      loserCodes: ['already_consumed'],
      returned: {
        bigR33: new Array(33).fill(2),
        kShare32: new Array(32).fill(3),
        sigmaShare32: new Array(32).fill(4),
      },
      tombstoneState: 'tombstone',
      tombstoneReason: 'released_to_online',
      tombstoneHasCiphertext: false,
    });
  });

  test('burns material on binding rejection and expiry', async ({ page }) => {
    const result = await page.evaluate(async ({ modulePath, dbName }) => {
      const { IndexedDbClientPresignMaterialStore } = await import(modulePath);
      const store = new IndexedDbClientPresignMaterialStore(dbName);
      const bytes = (length: number, value: number): Uint8Array =>
        new Uint8Array(length).fill(value);
      const poolIdentity = {
        poolKey: 'pool-1',
        walletKeyId: 'wallet-key-1',
        walletId: 'wallet-1',
        signingScopeB64u: 'scope-1',
        pairRole: 'client' as const,
        keyEpoch: 'key-epoch-1',
        activationEpoch: 'activation-epoch-1',
        protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
      };
      const put = async (materialHandle: string, expiresAtMs: number): Promise<string> => {
        return await store.putPendingAdmission({
          materialHandle,
          presignSessionId: `session-${materialHandle}`,
          poolIdentity,
          groupPublicKey33: bytes(33, 1),
          bigR33: bytes(33, 2),
          kShare32: bytes(32, 3),
          sigmaShare32: bytes(32, 4),
          createdAtMs: 1_000,
          expiresAtMs,
        });
      };
      const bindingId = await put('binding', 10_000);
      const expiredId = await put('expired', 1_500);
      const admissionMismatchId = await put('admission-mismatch', 10_000);
      const destroyedId = await put('destroyed', 10_000);
      const substitutedUseId = await put('substituted-use', 10_000);
      await store.admit({
        materialHandle: 'binding',
        expectedPresignatureId: bindingId,
        nowMs: 1_200,
      });
      await store.admit({
        materialHandle: 'expired',
        expectedPresignatureId: expiredId,
        nowMs: 1_200,
      });
      await store.reserve({
        materialHandle: 'binding',
        requestBinding: 'request-binding',
        reservationId: 'reservation-binding',
        nowMs: 1_250,
        leaseExpiresAtMs: 9_000,
      });
      await store.commit({
        materialHandle: 'binding',
        requestBinding: 'request-binding',
        reservationId: 'reservation-binding',
        nowMs: 1_300,
      });
      await store.reserve({
        materialHandle: 'expired',
        requestBinding: 'request-expired',
        reservationId: 'reservation-expired',
        nowMs: 1_250,
        leaseExpiresAtMs: 1_450,
      });
      await store.commit({
        materialHandle: 'expired',
        requestBinding: 'request-expired',
        reservationId: 'reservation-expired',
        nowMs: 1_300,
      });
      const admissionMismatch = await store.admit({
        materialHandle: 'admission-mismatch',
        expectedPresignatureId: `${admissionMismatchId}-substituted`,
        nowMs: 1_200,
      });
      const admissionMismatchRetry = await store.admit({
        materialHandle: 'admission-mismatch',
        expectedPresignatureId: admissionMismatchId,
        nowMs: 1_300,
      });
      await store.admit({
        materialHandle: 'destroyed',
        expectedPresignatureId: destroyedId,
        nowMs: 1_200,
      });
      await store.admit({
        materialHandle: 'substituted-use',
        expectedPresignatureId: substitutedUseId,
        nowMs: 1_200,
      });
      await store.reserve({
        materialHandle: 'substituted-use',
        requestBinding: 'request-original',
        reservationId: 'reservation-original',
        nowMs: 1_250,
        leaseExpiresAtMs: 9_000,
      });
      const substitutedCommit = await store.commit({
        materialHandle: 'substituted-use',
        requestBinding: 'request-substituted',
        reservationId: 'reservation-original',
        nowMs: 1_300,
      });
      const substitutedRetry = await store.takeForOnline({
        materialHandle: 'substituted-use',
        requestBinding: 'request-original',
        reservationId: 'reservation-original',
        expectedBigR33: bytes(33, 2),
        groupPublicKey33: bytes(33, 1),
        nowMs: 2_000,
      });
      await store.destroy('destroyed', 1_300);
      const destroyedRetry = await store.takeForOnline({
        materialHandle: 'destroyed',
        requestBinding: 'request-destroyed',
        reservationId: 'reservation-destroyed',
        expectedBigR33: bytes(33, 2),
        groupPublicKey33: bytes(33, 1),
        nowMs: 2_000,
      });
      const rejected = await store.takeForOnline({
        materialHandle: 'binding',
        requestBinding: 'request-binding',
        reservationId: 'reservation-binding',
        expectedBigR33: bytes(33, 9),
        groupPublicKey33: bytes(33, 1),
        nowMs: 2_000,
      });
      const rejectedRetry = await store.takeForOnline({
        materialHandle: 'binding',
        requestBinding: 'request-binding',
        reservationId: 'reservation-binding',
        expectedBigR33: bytes(33, 2),
        groupPublicKey33: bytes(33, 1),
        nowMs: 2_000,
      });
      const expired = await store.takeForOnline({
        materialHandle: 'expired',
        requestBinding: 'request-expired',
        reservationId: 'reservation-expired',
        expectedBigR33: bytes(33, 2),
        groupPublicKey33: bytes(33, 1),
        nowMs: 2_000,
      });
      const expiredRetry = await store.takeForOnline({
        materialHandle: 'expired',
        requestBinding: 'request-expired',
        reservationId: 'reservation-expired',
        expectedBigR33: bytes(33, 2),
        groupPublicKey33: bytes(33, 1),
        nowMs: 2_000,
      });
      await store.deleteDatabaseForTests();
      return [
        admissionMismatch,
        admissionMismatchRetry,
        destroyedRetry,
        substitutedCommit,
        substitutedRetry,
        rejected,
        rejectedRetry,
        expired,
        expiredRetry,
      ].map((entry) =>
        entry.ok ? 'unexpected_success' : entry.code,
      );
    }, { modulePath: STORE_MODULE, dbName: `ecdsa-presign-terminal-${Date.now()}` });

    expect(result).toEqual([
      'binding_rejected',
      'already_consumed',
      'already_consumed',
      'binding_rejected',
      'already_consumed',
      'binding_rejected',
      'already_consumed',
      'material_expired',
      'already_consumed',
    ]);
  });

  test('retains one sealing key across racing store instances', async ({ page }) => {
    const result = await page.evaluate(async ({ modulePath, dbName }) => {
      const { IndexedDbClientPresignMaterialStore } = await import(modulePath);
      const firstStore = new IndexedDbClientPresignMaterialStore(dbName);
      const secondStore = new IndexedDbClientPresignMaterialStore(dbName);
      const bytes = (length: number, value: number): Uint8Array =>
        new Uint8Array(length).fill(value);
      const poolIdentity = {
        poolKey: 'pool-1',
        walletKeyId: 'wallet-key-1',
        walletId: 'wallet-1',
        signingScopeB64u: 'scope-1',
        pairRole: 'client' as const,
        keyEpoch: 'key-epoch-1',
        activationEpoch: 'activation-epoch-1',
        protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
      };
      const input = (materialHandle: string, value: number) => ({
        materialHandle,
        presignSessionId: `session-${materialHandle}`,
        poolIdentity,
        groupPublicKey33: bytes(33, 1),
        bigR33: bytes(33, value),
        kShare32: bytes(32, value + 1),
        sigmaShare32: bytes(32, value + 2),
        createdAtMs: 1_000,
        expiresAtMs: 10_000,
      });
      const [firstId, secondId] = await Promise.all([
        firstStore.putPendingAdmission(input('first', 2)),
        secondStore.putPendingAdmission(input('second', 5)),
      ]);
      await Promise.all([
        firstStore.admit({
          materialHandle: 'first',
          expectedPresignatureId: firstId,
          nowMs: 1_500,
        }),
        secondStore.admit({
          materialHandle: 'second',
          expectedPresignatureId: secondId,
          nowMs: 1_500,
        }),
      ]);
      await Promise.all([
        firstStore.reserve({
          materialHandle: 'first',
          requestBinding: 'request-first',
          reservationId: 'reservation-first',
          nowMs: 1_600,
          leaseExpiresAtMs: 9_000,
        }),
        secondStore.reserve({
          materialHandle: 'second',
          requestBinding: 'request-second',
          reservationId: 'reservation-second',
          nowMs: 1_600,
          leaseExpiresAtMs: 9_000,
        }),
      ]);
      await Promise.all([
        firstStore.commit({
          materialHandle: 'first',
          requestBinding: 'request-first',
          reservationId: 'reservation-first',
          nowMs: 1_700,
        }),
        secondStore.commit({
          materialHandle: 'second',
          requestBinding: 'request-second',
          reservationId: 'reservation-second',
          nowMs: 1_700,
        }),
      ]);
      const [first, second] = await Promise.all([
        firstStore.takeForOnline({
          materialHandle: 'first',
          requestBinding: 'request-first',
          reservationId: 'reservation-first',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        }),
        secondStore.takeForOnline({
          materialHandle: 'second',
          requestBinding: 'request-second',
          reservationId: 'reservation-second',
          expectedBigR33: bytes(33, 5),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        }),
      ]);
      firstStore.close();
      await secondStore.deleteDatabaseForTests();
      return [first.ok, second.ok];
    }, { modulePath: STORE_MODULE, dbName: `ecdsa-presign-key-race-${Date.now()}` });

    expect(result).toEqual([true, true]);
  });
});
