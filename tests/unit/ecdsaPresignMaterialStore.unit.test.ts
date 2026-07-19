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
  'packages/sdk-web/src/core/indexedDB/seamsWalletDB/ecdsaPresignMaterialStore.ts',
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
    const result = await page.evaluate(
      async ({ modulePath, dbName }) => {
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
          const transaction = database.transaction('ecdsa_presign_records', 'readonly');
          const record = await new Promise<Record<string, unknown>>((resolve, reject) => {
            const request = transaction.objectStore('ecdsa_presign_records').get('material-1');
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
          poolIdentity,
          expectedPresignatureId: presignatureId,
          nowMs: 1_500,
        });
        const available = await inspectRecord();
        const durableAvailable = await store.listAvailable(poolIdentity, 1_550);
        await store.reserve({
          materialHandle: 'material-1',
          poolIdentity,
          requestBinding: 'request-1',
          reservationId: 'reservation-1',
          nowMs: 1_600,
          leaseExpiresAtMs: 9_000,
        });
        await store.commit({
          materialHandle: 'material-1',
          poolIdentity,
          requestBinding: 'request-1',
          reservationId: 'reservation-1',
          nowMs: 1_700,
        });
        const [first, second] = await Promise.all([
          store.takeForOnline({
            materialHandle: 'material-1',
            poolIdentity,
            requestBinding: 'request-1',
            reservationId: 'reservation-1',
            expectedBigR33: bytes(33, 2),
            groupPublicKey33: bytes(33, 1),
            nowMs: 2_000,
          }),
          store.takeForOnline({
            materialHandle: 'material-1',
            poolIdentity,
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
          durableAvailable: durableAvailable.map((ref) => ({
            presignatureId: ref.presignatureId,
            materialHandle: ref.materialHandle,
            bigR33: Array.from(ref.bigR33),
          })),
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
      },
      { modulePath: STORE_MODULE, dbName: `ecdsa-presign-once-${Date.now()}` },
    );

    expect(result).toEqual({
      pendingAdmissionState: 'pending_admission',
      admissionOk: true,
      availableState: 'available',
      availableHasCiphertext: true,
      availableHasPlaintextShares: false,
      durableAvailable: [
        {
          presignatureId: expect.stringMatching(/^presig-/),
          materialHandle: 'material-1',
          bigR33: new Array(33).fill(2),
        },
      ],
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
    const result = await page.evaluate(
      async ({ modulePath, dbName }) => {
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
        const substitutedIdentityId = await put('substituted-identity', 10_000);
        const substitutedIdentity = {
          poolKey: 'pool-substituted',
          walletKeyId: 'wallet-key-1',
          walletId: 'wallet-1',
          signingScopeB64u: 'scope-1',
          pairRole: 'client' as const,
          keyEpoch: 'key-epoch-1',
          activationEpoch: 'activation-epoch-1',
          protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
        };
        const identityMismatch = await store.admit({
          materialHandle: 'substituted-identity',
          poolIdentity: substitutedIdentity,
          expectedPresignatureId: substitutedIdentityId,
          nowMs: 1_200,
        });
        const identityMismatchRetry = await store.admit({
          materialHandle: 'substituted-identity',
          poolIdentity,
          expectedPresignatureId: substitutedIdentityId,
          nowMs: 1_300,
        });
        await store.admit({
          materialHandle: 'binding',
          poolIdentity,
          expectedPresignatureId: bindingId,
          nowMs: 1_200,
        });
        await store.admit({
          materialHandle: 'expired',
          poolIdentity,
          expectedPresignatureId: expiredId,
          nowMs: 1_200,
        });
        await store.reserve({
          materialHandle: 'binding',
          poolIdentity,
          requestBinding: 'request-binding',
          reservationId: 'reservation-binding',
          nowMs: 1_250,
          leaseExpiresAtMs: 9_000,
        });
        await store.commit({
          materialHandle: 'binding',
          poolIdentity,
          requestBinding: 'request-binding',
          reservationId: 'reservation-binding',
          nowMs: 1_300,
        });
        await store.reserve({
          materialHandle: 'expired',
          poolIdentity,
          requestBinding: 'request-expired',
          reservationId: 'reservation-expired',
          nowMs: 1_250,
          leaseExpiresAtMs: 1_450,
        });
        await store.commit({
          materialHandle: 'expired',
          poolIdentity,
          requestBinding: 'request-expired',
          reservationId: 'reservation-expired',
          nowMs: 1_300,
        });
        const admissionMismatch = await store.admit({
          materialHandle: 'admission-mismatch',
          poolIdentity,
          expectedPresignatureId: `${admissionMismatchId}-substituted`,
          nowMs: 1_200,
        });
        const admissionMismatchRetry = await store.admit({
          materialHandle: 'admission-mismatch',
          poolIdentity,
          expectedPresignatureId: admissionMismatchId,
          nowMs: 1_300,
        });
        await store.admit({
          materialHandle: 'destroyed',
          poolIdentity,
          expectedPresignatureId: destroyedId,
          nowMs: 1_200,
        });
        await store.admit({
          materialHandle: 'substituted-use',
          poolIdentity,
          expectedPresignatureId: substitutedUseId,
          nowMs: 1_200,
        });
        await store.reserve({
          materialHandle: 'substituted-use',
          poolIdentity,
          requestBinding: 'request-original',
          reservationId: 'reservation-original',
          nowMs: 1_250,
          leaseExpiresAtMs: 9_000,
        });
        const substitutedCommit = await store.commit({
          materialHandle: 'substituted-use',
          poolIdentity,
          requestBinding: 'request-substituted',
          reservationId: 'reservation-original',
          nowMs: 1_300,
        });
        const substitutedRetry = await store.takeForOnline({
          materialHandle: 'substituted-use',
          poolIdentity,
          requestBinding: 'request-original',
          reservationId: 'reservation-original',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        });
        await store.destroy('destroyed', poolIdentity, 1_300);
        const destroyedRetry = await store.takeForOnline({
          materialHandle: 'destroyed',
          poolIdentity,
          requestBinding: 'request-destroyed',
          reservationId: 'reservation-destroyed',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        });
        const rejected = await store.takeForOnline({
          materialHandle: 'binding',
          poolIdentity,
          requestBinding: 'request-binding',
          reservationId: 'reservation-binding',
          expectedBigR33: bytes(33, 9),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        });
        const rejectedRetry = await store.takeForOnline({
          materialHandle: 'binding',
          poolIdentity,
          requestBinding: 'request-binding',
          reservationId: 'reservation-binding',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        });
        const expired = await store.takeForOnline({
          materialHandle: 'expired',
          poolIdentity,
          requestBinding: 'request-expired',
          reservationId: 'reservation-expired',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        });
        const expiredRetry = await store.takeForOnline({
          materialHandle: 'expired',
          poolIdentity,
          requestBinding: 'request-expired',
          reservationId: 'reservation-expired',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_000,
        });
        await store.deleteDatabaseForTests();
        return [
          identityMismatch,
          identityMismatchRetry,
          admissionMismatch,
          admissionMismatchRetry,
          destroyedRetry,
          substitutedCommit,
          substitutedRetry,
          rejected,
          rejectedRetry,
          expired,
          expiredRetry,
        ].map((entry) => (entry.ok ? 'unexpected_success' : entry.code));
      },
      { modulePath: STORE_MODULE, dbName: `ecdsa-presign-terminal-${Date.now()}` },
    );

    expect(result).toEqual([
      'binding_rejected',
      'already_consumed',
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

  test('withholds material on persistence failure and burns cancellation', async ({ page }) => {
    const result = await page.evaluate(
      async ({ modulePath, dbName }) => {
        const { IndexedDbClientPresignMaterialStore } = await import(modulePath);
        const store = new IndexedDbClientPresignMaterialStore(dbName);
        const bytes = (length: number, value: number): Uint8Array =>
          new Uint8Array(length).fill(value);
        const poolIdentity = {
          poolKey: 'pool-faults',
          walletKeyId: 'wallet-key-1',
          walletId: 'wallet-1',
          signingScopeB64u: 'scope-1',
          pairRole: 'client' as const,
          keyEpoch: 'key-epoch-1',
          activationEpoch: 'activation-epoch-1',
          protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
        };
        const prepare = async (materialHandle: string): Promise<void> => {
          const presignatureId = await store.putPendingAdmission({
            materialHandle,
            presignSessionId: `session-${materialHandle}`,
            poolIdentity,
            groupPublicKey33: bytes(33, 1),
            bigR33: bytes(33, 2),
            kShare32: bytes(32, 3),
            sigmaShare32: bytes(32, 4),
            createdAtMs: 1_000,
            expiresAtMs: 10_000,
          });
          const admission = await store.admit({
            materialHandle,
            poolIdentity,
            expectedPresignatureId: presignatureId,
            nowMs: 1_100,
          });
          if (!admission.ok) throw new Error(`admission failed: ${admission.code}`);
          const reservation = await store.reserve({
            materialHandle,
            poolIdentity,
            requestBinding: `request-${materialHandle}`,
            reservationId: `reservation-${materialHandle}`,
            nowMs: 1_200,
            leaseExpiresAtMs: 9_000,
          });
          if (!reservation.ok) throw new Error(`reservation failed: ${reservation.code}`);
        };

        await prepare('persist-failure');
        const committed = await store.commit({
          materialHandle: 'persist-failure',
          poolIdentity,
          requestBinding: 'request-persist-failure',
          reservationId: 'reservation-persist-failure',
          nowMs: 1_300,
        });
        if (!committed.ok) throw new Error(`commit failed: ${committed.code}`);

        const originalPutDescriptor = Object.getOwnPropertyDescriptor(
          IDBObjectStore.prototype,
          'put',
        );
        const originalPut = IDBObjectStore.prototype.put;
        const failingPut = function <T>(
          this: IDBObjectStore,
          value: T,
          key?: IDBValidKey,
        ): IDBRequest<IDBValidKey> {
          const candidate = value as {
            readonly materialHandle?: unknown;
            readonly state?: unknown;
          };
          if (candidate.materialHandle === 'persist-failure' && candidate.state === 'tombstone') {
            throw new DOMException('injected terminal persistence failure', 'UnknownError');
          }
          return key === undefined
            ? originalPut.call(this, value)
            : originalPut.call(this, value, key);
        };
        Object.defineProperty(IDBObjectStore.prototype, 'put', {
          configurable: true,
          writable: true,
          value: failingPut,
        });
        let persistenceFailure;
        try {
          persistenceFailure = await store.takeForOnline({
            materialHandle: 'persist-failure',
            poolIdentity,
            requestBinding: 'request-persist-failure',
            reservationId: 'reservation-persist-failure',
            expectedBigR33: bytes(33, 2),
            groupPublicKey33: bytes(33, 1),
            nowMs: 1_400,
          });
        } finally {
          if (originalPutDescriptor) {
            Object.defineProperty(IDBObjectStore.prototype, 'put', originalPutDescriptor);
          }
        }
        const retryAfterPersistenceRecovery = await store.takeForOnline({
          materialHandle: 'persist-failure',
          poolIdentity,
          requestBinding: 'request-persist-failure',
          reservationId: 'reservation-persist-failure',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 1_500,
        });
        const duplicateAfterRelease = await store.takeForOnline({
          materialHandle: 'persist-failure',
          poolIdentity,
          requestBinding: 'request-persist-failure',
          reservationId: 'reservation-persist-failure',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 1_600,
        });

        await prepare('cancelled');
        const cancellationPersisted = await store.destroy('cancelled', poolIdentity, 1_300);
        const cancellationRetry = await store.takeForOnline({
          materialHandle: 'cancelled',
          poolIdentity,
          requestBinding: 'request-cancelled',
          reservationId: 'reservation-cancelled',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 1_400,
        });

        await store.deleteDatabaseForTests();
        return {
          persistenceFailure: persistenceFailure.ok
            ? 'unexpected_success'
            : persistenceFailure.code,
          retryAfterPersistenceRecovery: retryAfterPersistenceRecovery.ok
            ? Array.from(retryAfterPersistenceRecovery.material.kShare32)
            : retryAfterPersistenceRecovery.code,
          duplicateAfterRelease: duplicateAfterRelease.ok
            ? 'unexpected_success'
            : duplicateAfterRelease.code,
          cancellationPersisted,
          cancellationRetry: cancellationRetry.ok ? 'unexpected_success' : cancellationRetry.code,
        };
      },
      { modulePath: STORE_MODULE, dbName: `ecdsa-presign-faults-${Date.now()}` },
    );

    expect(result).toEqual({
      persistenceFailure: 'persistence_failure',
      retryAfterPersistenceRecovery: new Array(32).fill(3),
      duplicateAfterRelease: 'already_consumed',
      cancellationPersisted: true,
      cancellationRetry: 'already_consumed',
    });
  });

  test('recovers expired reserved and committed records destructively', async ({ page }) => {
    const result = await page.evaluate(
      async ({ modulePath, dbName }) => {
        const { IndexedDbClientPresignMaterialStore } = await import(modulePath);
        const store = new IndexedDbClientPresignMaterialStore(dbName);
        const bytes = (length: number, value: number): Uint8Array =>
          new Uint8Array(length).fill(value);
        const poolIdentity = {
          poolKey: 'pool-recovery',
          walletKeyId: 'wallet-key-1',
          walletId: 'wallet-1',
          signingScopeB64u: 'scope-1',
          pairRole: 'client' as const,
          keyEpoch: 'key-epoch-1',
          activationEpoch: 'activation-epoch-1',
          protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
        };
        const prepare = async (materialHandle: string): Promise<string> => {
          const id = await store.putPendingAdmission({
            materialHandle,
            presignSessionId: `session-${materialHandle}`,
            poolIdentity,
            groupPublicKey33: bytes(33, 1),
            bigR33: bytes(33, 2),
            kShare32: bytes(32, 3),
            sigmaShare32: bytes(32, 4),
            createdAtMs: 1_000,
            expiresAtMs: 10_000,
          });
          await store.admit({
            materialHandle,
            poolIdentity,
            expectedPresignatureId: id,
            nowMs: 1_100,
          });
          await store.reserve({
            materialHandle,
            poolIdentity,
            requestBinding: `request-${materialHandle}`,
            reservationId: `reservation-${materialHandle}`,
            nowMs: 1_200,
            leaseExpiresAtMs: 1_500,
          });
          return id;
        };
        await prepare('reserved');
        await prepare('committed');
        await store.commit({
          materialHandle: 'committed',
          poolIdentity,
          requestBinding: 'request-committed',
          reservationId: 'reservation-committed',
          nowMs: 1_300,
        });
        const available = await store.listAvailable(poolIdentity, 2_000);
        const reservedRetry = await store.takeForOnline({
          materialHandle: 'reserved',
          poolIdentity,
          requestBinding: 'request-reserved',
          reservationId: 'reservation-reserved',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_100,
        });
        const committedRetry = await store.takeForOnline({
          materialHandle: 'committed',
          poolIdentity,
          requestBinding: 'request-committed',
          reservationId: 'reservation-committed',
          expectedBigR33: bytes(33, 2),
          groupPublicKey33: bytes(33, 1),
          nowMs: 2_100,
        });
        await store.deleteDatabaseForTests();
        return {
          availableCount: available.length,
          reservedRetry: reservedRetry.ok ? 'unexpected_success' : reservedRetry.code,
          committedRetry: committedRetry.ok ? 'unexpected_success' : committedRetry.code,
        };
      },
      { modulePath: STORE_MODULE, dbName: `ecdsa-presign-recovery-${Date.now()}` },
    );

    expect(result).toEqual({
      availableCount: 0,
      reservedRetry: 'already_consumed',
      committedRetry: 'already_consumed',
    });
  });

  test('retains one sealing key across racing store instances', async ({ page }) => {
    const result = await page.evaluate(
      async ({ modulePath, dbName }) => {
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
            poolIdentity,
            expectedPresignatureId: firstId,
            nowMs: 1_500,
          }),
          secondStore.admit({
            materialHandle: 'second',
            poolIdentity,
            expectedPresignatureId: secondId,
            nowMs: 1_500,
          }),
        ]);
        await Promise.all([
          firstStore.reserve({
            materialHandle: 'first',
            poolIdentity,
            requestBinding: 'request-first',
            reservationId: 'reservation-first',
            nowMs: 1_600,
            leaseExpiresAtMs: 9_000,
          }),
          secondStore.reserve({
            materialHandle: 'second',
            poolIdentity,
            requestBinding: 'request-second',
            reservationId: 'reservation-second',
            nowMs: 1_600,
            leaseExpiresAtMs: 9_000,
          }),
        ]);
        await Promise.all([
          firstStore.commit({
            materialHandle: 'first',
            poolIdentity,
            requestBinding: 'request-first',
            reservationId: 'reservation-first',
            nowMs: 1_700,
          }),
          secondStore.commit({
            materialHandle: 'second',
            poolIdentity,
            requestBinding: 'request-second',
            reservationId: 'reservation-second',
            nowMs: 1_700,
          }),
        ]);
        const [first, second] = await Promise.all([
          firstStore.takeForOnline({
            materialHandle: 'first',
            poolIdentity,
            requestBinding: 'request-first',
            reservationId: 'reservation-first',
            expectedBigR33: bytes(33, 2),
            groupPublicKey33: bytes(33, 1),
            nowMs: 2_000,
          }),
          secondStore.takeForOnline({
            materialHandle: 'second',
            poolIdentity,
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
      },
      { modulePath: STORE_MODULE, dbName: `ecdsa-presign-key-race-${Date.now()}` },
    );

    expect(result).toEqual([true, true]);
  });

  test('retires every live record in one exact activation scope atomically', async ({ page }) => {
    const result = await page.evaluate(
      async ({ modulePath, dbName }) => {
        const { IndexedDbClientPresignMaterialStore } = await import(modulePath);
        const store = new IndexedDbClientPresignMaterialStore(dbName);
        const bytes = (length: number, value: number): Uint8Array =>
          new Uint8Array(length).fill(value);
        const poolIdentity = {
          poolKey: 'pool-retired',
          walletKeyId: 'wallet-key-1',
          walletId: 'wallet-1',
          signingScopeB64u: 'scope-retired',
          pairRole: 'client' as const,
          keyEpoch: 'key-epoch-1',
          activationEpoch: 'activation-epoch-1',
          protocolId: 'seams/router-ab-ecdsa-presign/fixed-2of2/v1' as const,
        };
        const otherPoolIdentity = {
          ...poolIdentity,
          poolKey: 'pool-current',
          signingScopeB64u: 'scope-current',
          activationEpoch: 'activation-epoch-2',
        };
        const putAvailable = async (
          materialHandle: string,
          identity: typeof poolIdentity,
          value: number,
        ): Promise<void> => {
          const presignatureId = await store.putPendingAdmission({
            materialHandle,
            presignSessionId: `session-${materialHandle}`,
            poolIdentity: identity,
            groupPublicKey33: bytes(33, 1),
            bigR33: bytes(33, value),
            kShare32: bytes(32, value + 1),
            sigmaShare32: bytes(32, value + 2),
            createdAtMs: 1_000,
            expiresAtMs: 10_000,
          });
          const admitted = await store.admit({
            materialHandle,
            poolIdentity: identity,
            expectedPresignatureId: presignatureId,
            nowMs: 1_100,
          });
          if (!admitted.ok) throw new Error(`admission failed: ${admitted.code}`);
        };
        await putAvailable('available', poolIdentity, 2);
        await putAvailable('reserved', poolIdentity, 5);
        await putAvailable('committed', poolIdentity, 8);
        await putAvailable('other', otherPoolIdentity, 11);
        await store.reserve({
          materialHandle: 'reserved',
          poolIdentity,
          requestBinding: 'request-reserved',
          reservationId: 'reservation-reserved',
          nowMs: 1_200,
          leaseExpiresAtMs: 9_000,
        });
        await store.reserve({
          materialHandle: 'committed',
          poolIdentity,
          requestBinding: 'request-committed',
          reservationId: 'reservation-committed',
          nowMs: 1_200,
          leaseExpiresAtMs: 9_000,
        });
        await store.commit({
          materialHandle: 'committed',
          poolIdentity,
          requestBinding: 'request-committed',
          reservationId: 'reservation-committed',
          nowMs: 1_300,
        });

        const retiredCount = await store.retirePool(
          poolIdentity,
          'activation_epoch_retired',
          1_400,
        );
        const retiredAvailable = await store.listAvailable(poolIdentity, 1_500);
        const currentAvailable = await store.listAvailable(otherPoolIdentity, 1_500);
        const committedRetry = await store.takeForOnline({
          materialHandle: 'committed',
          poolIdentity,
          requestBinding: 'request-committed',
          reservationId: 'reservation-committed',
          expectedBigR33: bytes(33, 8),
          groupPublicKey33: bytes(33, 1),
          nowMs: 1_500,
        });

        const database = await new Promise<IDBDatabase>((resolve, reject) => {
          const request = indexedDB.open(dbName);
          request.onsuccess = () => resolve(request.result);
          request.onerror = () => reject(request.error);
        });
        const transaction = database.transaction('ecdsa_presign_records', 'readonly');
        const records = await new Promise<Array<Record<string, unknown>>>((resolve, reject) => {
          const request = transaction.objectStore('ecdsa_presign_records').getAll();
          request.onsuccess = () => resolve(request.result as Array<Record<string, unknown>>);
          request.onerror = () => reject(request.error);
        });
        await new Promise<void>((resolve, reject) => {
          transaction.oncomplete = () => resolve();
          transaction.onabort = () => reject(transaction.error);
          transaction.onerror = () => reject(transaction.error);
        });
        database.close();
        const retiredRecords = records
          .filter((record) => record.materialHandle !== 'other')
          .map((record) => ({
            state: record.state,
            reason: record.reason,
            hasCiphertext: 'ciphertext' in record,
          }));
        await store.deleteDatabaseForTests();
        return {
          retiredCount,
          retiredAvailableCount: retiredAvailable.length,
          currentAvailableHandles: currentAvailable.map((entry) => entry.materialHandle),
          committedRetry: committedRetry.ok ? 'unexpected_success' : committedRetry.code,
          retiredRecords,
        };
      },
      { modulePath: STORE_MODULE, dbName: `ecdsa-presign-retire-${Date.now()}` },
    );

    expect(result).toEqual({
      retiredCount: 3,
      retiredAvailableCount: 0,
      currentAvailableHandles: ['other'],
      committedRetry: 'already_consumed',
      retiredRecords: [
        { state: 'tombstone', reason: 'activation_epoch_retired', hasCiphertext: false },
        { state: 'tombstone', reason: 'activation_epoch_retired', hasCiphertext: false },
        { state: 'tombstone', reason: 'activation_epoch_retired', hasCiphertext: false },
      ],
    });
  });
});
