import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  store: '/sdk/esm/core/signingEngine/api/session/emailOtpDeviceEnrollmentEscrowStore.js',
} as const;

test.describe('Email OTP device enrollment escrow store', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('persists device-local enc_s(S) records without plaintext S or signing-session fields', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.store);
        await mod.clearAllEmailOtpDeviceEnrollmentEscrowRecords();
        await mod.writeEmailOtpDeviceEnrollmentEscrowRecord({
          walletId: 'alice.testnet',
          userId: 'user-1',
          authSubjectId: 'google-sub-1',
          enrollmentId: 'enrollment-1',
          enrollmentVersion: '1',
          enrollmentSealKeyVersion: 'seal-v1',
          signingRootId: 'root-1',
          signingRootVersion: 'root-v1',
          shamirPrimeB64u: 'cHJpbWU',
          encSB64u: 'ZW5jX3Nfcy1ieXRlcw',
          issuedAtMs: Date.now(),
          updatedAtMs: Date.now(),
          S: 'plaintext-must-not-persist',
          clientSecretB64u: 'plaintext-must-not-persist',
          signingSessionSecretB64u: 'wrong-store-secret',
          thresholdSessionJwt: 'jwt-must-not-persist',
        });

        const record = await mod.readEmailOtpDeviceEnrollmentEscrowRecord({
          walletId: 'alice.testnet',
          authSubjectId: 'google-sub-1',
          enrollmentId: 'enrollment-1',
        });

        const rawRecord = await new Promise<unknown>((resolve, reject) => {
          const openReq = indexedDB.open('tatchi_email_otp_device_enrollment_escrows_v1');
          openReq.onsuccess = () => {
            const db = openReq.result;
            const tx = db.transaction('email_otp_device_enrollment_escrows_v1', 'readonly');
            const getReq = tx
              .objectStore('email_otp_device_enrollment_escrows_v1')
              .get(['alice.testnet', 'google-sub-1', 'enrollment-1']);
            getReq.onsuccess = () => {
              const value = getReq.result;
              db.close();
              resolve(value);
            };
            getReq.onerror = () => {
              db.close();
              reject(getReq.error);
            };
          };
          openReq.onerror = () => reject(openReq.error);
        });
        const rawRecordJson = JSON.stringify(rawRecord);

        return {
          record,
          rawHasPlaintextS: rawRecordJson.includes('plaintext-must-not-persist'),
          rawHasSigningSessionSecret: rawRecordJson.includes('wrong-store-secret'),
          rawHasJwt: rawRecordJson.includes('jwt-must-not-persist'),
          rawHasSealedSecretField:
            !!rawRecord &&
            Object.prototype.hasOwnProperty.call(
              rawRecord as Record<string, unknown>,
              'sealedSecretB64u',
            ),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.record).toMatchObject({
      v: 1,
      alg: 'shamir3pass-v1',
      storageScope: 'iframe_origin_indexeddb',
      secretKind: 'email_otp_device_enrollment_escrow_enc_s',
      walletId: 'alice.testnet',
      authSubjectId: 'google-sub-1',
      enrollmentId: 'enrollment-1',
      encSB64u: 'ZW5jX3Nfcy1ieXRlcw',
    });
    expect(result.rawHasPlaintextS).toBe(false);
    expect(result.rawHasSigningSessionSecret).toBe(false);
    expect(result.rawHasJwt).toBe(false);
    expect(result.rawHasSealedSecretField).toBe(false);
  });

  test('fails closed on malformed records and deletes by wallet/auth subject/enrollment scope', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.store);
        await mod.clearAllEmailOtpDeviceEnrollmentEscrowRecords();
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = indexedDB.open('tatchi_email_otp_device_enrollment_escrows_v1', 1);
          req.onupgradeneeded = () => {
            if (!req.result.objectStoreNames.contains('email_otp_device_enrollment_escrows_v1')) {
              req.result.createObjectStore('email_otp_device_enrollment_escrows_v1', {
                keyPath: ['walletId', 'authSubjectId', 'enrollmentId'],
              });
            }
          };
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const tx = db.transaction('email_otp_device_enrollment_escrows_v1', 'readwrite');
        const store = tx.objectStore('email_otp_device_enrollment_escrows_v1');
        store.put({
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          secretKind: 'email_otp_device_enrollment_escrow_enc_s',
          walletId: 'alice.testnet',
          authSubjectId: 'google-sub-1',
          authMethod: 'google_sso_email_otp',
          enrollmentId: 'bad-enrollment',
          enrollmentVersion: '1',
          enrollmentSealKeyVersion: 'seal-v1',
          signingRootId: 'root-1',
          signingRootVersion: 'root-v1',
          encSB64u: 'ZW5jX3Nfcy1ieXRlcw',
          issuedAtMs: Date.now(),
          updatedAtMs: Date.now(),
          clientSecretB64u: 'plaintext-s',
        });
        await new Promise<void>((resolve, reject) => {
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
          tx.onabort = () => reject(tx.error);
        });
        db.close();

        const malformed = await mod.readEmailOtpDeviceEnrollmentEscrowRecord({
          walletId: 'alice.testnet',
          authSubjectId: 'google-sub-1',
          enrollmentId: 'bad-enrollment',
        });

        await mod.writeEmailOtpDeviceEnrollmentEscrowRecord({
          walletId: 'alice.testnet',
          authSubjectId: 'google-sub-1',
          enrollmentId: 'good-enrollment',
          enrollmentVersion: '1',
          enrollmentSealKeyVersion: 'seal-v1',
          signingRootId: 'root-1',
          signingRootVersion: 'root-v1',
          encSB64u: 'ZW5jX3Nfcy1ieXRlcw',
          issuedAtMs: Date.now(),
          updatedAtMs: Date.now(),
        });
        const beforeDelete = await mod.readEmailOtpDeviceEnrollmentEscrowRecord({
          walletId: 'alice.testnet',
          authSubjectId: 'google-sub-1',
          enrollmentId: 'good-enrollment',
        });
        await mod.deleteEmailOtpDeviceEnrollmentEscrowRecord({
          walletId: 'alice.testnet',
          authSubjectId: 'google-sub-1',
          enrollmentId: 'good-enrollment',
        });
        const afterDelete = await mod.readEmailOtpDeviceEnrollmentEscrowRecord({
          walletId: 'alice.testnet',
          authSubjectId: 'google-sub-1',
          enrollmentId: 'good-enrollment',
        });

        return { malformed, beforeDelete, afterDelete };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.malformed).toBeNull();
    expect(result.beforeDelete?.enrollmentId).toBe('good-enrollment');
    expect(result.afterDelete).toBeNull();
  });
});
