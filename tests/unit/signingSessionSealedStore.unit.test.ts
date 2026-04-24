import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  signingSessionSealedStore: '/sdk/esm/core/signingEngine/api/session/signingSessionSealedStore.js',
} as const;

test.describe('signing session sealed store', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
  });

  test('writes shamir3pass records to IndexedDB without persisting plaintext secret or JWT auth', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionSealedStore);
        const thresholdSessionId = 'sess-sealed-1';
        const walletSigningSessionId = 'wallet-sess-sealed-1';
        await mod.clearAllSigningSessionSealedRecords();
        await mod.writeSigningSessionSealedRecord({
          thresholdSessionId,
          walletSigningSessionId,
          sealedSecretB64u: 'sealed-secret-b64u',
          thresholdSessionJwt: 'jwt-must-not-persist',
          signingSessionSecretB64u: 'plaintext-k-must-not-persist',
          emailOtpSecretS: 'plaintext-s-must-not-persist',
          enrollmentEscrowB64u: 'enrollment-escrow-must-not-persist',
          keyVersion: 'kek-s-2026-02',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 7,
          updatedAtMs: Date.now(),
        });

        const record = await mod.readSigningSessionSealedRecord(thresholdSessionId);
        const rawRecord = await new Promise<unknown>((resolve, reject) => {
          const openReq = indexedDB.open('tatchi_wallet_v1');
          openReq.onsuccess = () => {
            const db = openReq.result;
            const tx = db.transaction('signing_session_seals_v1', 'readonly');
            const getReq = tx.objectStore('signing_session_seals_v1').get(walletSigningSessionId);
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
        const sessionRaw = sessionStorage.getItem(
          `tatchi:signing-session-sealed:v1:${thresholdSessionId}`,
        );
        const sessionIndex = sessionStorage.getItem('tatchi:signing-session-sealed:v1:index');
        return {
          record,
          sessionRaw,
          sessionIndex,
          rawHasPlaintextSecret:
            !!record &&
            (Object.prototype.hasOwnProperty.call(record, 'prfFirstB64u') ||
              Object.prototype.hasOwnProperty.call(record, 'signingSessionSecretB64u') ||
              Object.prototype.hasOwnProperty.call(record, 'secretSourceB64u')),
          rawHasThresholdSessionJwt:
            !!record && Object.prototype.hasOwnProperty.call(record, 'thresholdSessionJwt'),
          rawHasPlaintextK: rawRecordJson.includes('plaintext-k-must-not-persist'),
          rawHasPlaintextS: rawRecordJson.includes('plaintext-s-must-not-persist'),
          rawHasEnrollmentEscrow: rawRecordJson.includes('enrollment-escrow-must-not-persist'),
          rawHasJwt: rawRecordJson.includes('jwt-must-not-persist'),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.record?.alg).toBe('shamir3pass-v1');
    expect(result.record?.storageScope).toBe('iframe_origin_indexeddb');
    expect(result.record?.secretKind).toBe('signing_session_secret32');
    expect(result.record?.sealedSecretB64u).toBe('sealed-secret-b64u');
    expect(result.record?.keyVersion).toBe('kek-s-2026-02');
    expect(result.record?.thresholdSessionIds.ecdsa).toBe('sess-sealed-1');
    expect(result.sessionRaw).toBeNull();
    expect(result.sessionIndex).toBeNull();
    expect(result.rawHasPlaintextSecret).toBe(false);
    expect(result.rawHasThresholdSessionJwt).toBe(false);
    expect(result.rawHasPlaintextK).toBe(false);
    expect(result.rawHasPlaintextS).toBe(false);
    expect(result.rawHasEnrollmentEscrow).toBe(false);
    expect(result.rawHasJwt).toBe(false);
  });

  test('fails closed on malformed/legacy record payloads', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionSealedStore);
        const thresholdSessionId = 'sess-legacy';
        await mod.clearAllSigningSessionSealedRecords();
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = indexedDB.open('tatchi_wallet_v1');
          req.onupgradeneeded = () => {
            if (!req.result.objectStoreNames.contains('signing_session_seals_v1')) {
              req.result.createObjectStore('signing_session_seals_v1', {
                keyPath: 'walletSigningSessionId',
              });
            }
          };
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const tx = db.transaction('signing_session_seals_v1', 'readwrite');
        tx.objectStore('signing_session_seals_v1').put({
          v: 1,
          alg: 'plain-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: sessionStorage.getItem(
            'tatchi:signing-session-sealed:runtime-session-id:v1',
          ),
          authMethod: 'passkey',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: thresholdSessionId,
          thresholdSessionIds: { ecdsa: thresholdSessionId },
          prfFirstB64u: 'plaintext',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          issuedAtMs: Date.now(),
          updatedAtMs: Date.now(),
        });
        await new Promise<void>((resolve, reject) => {
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
          tx.onabort = () => reject(tx.error);
        });
        db.close();

        const read = await mod.readSigningSessionSealedRecord(thresholdSessionId);
        await mod.deleteSigningSessionSealedRecord(thresholdSessionId);
        const afterDelete = await mod.readSigningSessionSealedRecord(thresholdSessionId);

        return { read, afterDelete };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.read).toBeNull();
    expect(result.afterDelete).toBeNull();
  });

  test('validates Email OTP sealed record schema and rejects malformed Email OTP records', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionSealedStore);
        await mod.clearAllSigningSessionSealedRecords();
        await mod.writeSigningSessionSealedRecord({
          thresholdSessionId: 'email-otp-ecdsa-session',
          walletSigningSessionId: 'email-otp-wallet-session',
          thresholdSessionIds: {
            ecdsa: 'email-otp-ecdsa-session',
            ed25519: 'email-otp-ed25519-session',
          },
          authMethod: 'email_otp',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'signing-root',
          signingRootVersion: 'root-v1',
          relayerUrl: 'https://relay.example',
          keyVersion: 'seal-v1',
          shamirPrimeB64u: 'prime-b64u',
          sealedSecretB64u: 'sealed-email-otp-k',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        });
        const validByEcdsa = await mod.readSigningSessionSealedRecord('email-otp-ecdsa-session');
        const validByEd25519 = await mod.readSigningSessionSealedRecord(
          'email-otp-ed25519-session',
        );

        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = indexedDB.open('tatchi_wallet_v1');
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const tx = db.transaction('signing_session_seals_v1', 'readwrite');
        tx.objectStore('signing_session_seals_v1').put({
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: sessionStorage.getItem(
            'tatchi:signing-session-sealed:runtime-session-id:v1',
          ),
          authMethod: 'email_otp',
          secretKind: 'enrollment_secret_s',
          walletSigningSessionId: 'bad-email-otp-wallet-session',
          thresholdSessionIds: { ecdsa: 'bad-email-otp-ecdsa-session' },
          sealedSecretB64u: 'must-not-read',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        });
        await new Promise<void>((resolve, reject) => {
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
          tx.onabort = () => reject(tx.error);
        });
        db.close();

        const malformed = await mod.readSigningSessionSealedRecord('bad-email-otp-ecdsa-session');
        return { validByEcdsa, validByEd25519, malformed };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.validByEcdsa).toMatchObject({
      authMethod: 'email_otp',
      secretKind: 'signing_session_secret32',
      walletSigningSessionId: 'email-otp-wallet-session',
      thresholdSessionIds: {
        ecdsa: 'email-otp-ecdsa-session',
        ed25519: 'email-otp-ed25519-session',
      },
      walletId: 'alice.testnet',
      signingRootId: 'signing-root',
    });
    expect(result.validByEd25519?.walletSigningSessionId).toBe('email-otp-wallet-session');
    expect(result.malformed).toBeNull();
  });

  test('clearAll removes all IndexedDB sealed records', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionSealedStore);
        await mod.clearAllSigningSessionSealedRecords();
        await mod.writeSigningSessionSealedRecord({
          thresholdSessionId: 'sess-a',
          walletSigningSessionId: 'wallet-sess-a',
          sealedSecretB64u: 'a',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        });
        await mod.writeSigningSessionSealedRecord({
          thresholdSessionId: 'sess-b',
          walletSigningSessionId: 'wallet-sess-b',
          sealedSecretB64u: 'b',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        });
        const before = {
          a: await mod.readSigningSessionSealedRecord('sess-a'),
          b: await mod.readSigningSessionSealedRecord('sess-b'),
        };
        await mod.clearAllSigningSessionSealedRecords();
        const after = {
          a: await mod.readSigningSessionSealedRecord('sess-a'),
          b: await mod.readSigningSessionSealedRecord('sess-b'),
        };
        return { before, after };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.before.a?.sealedSecretB64u).toBe('a');
    expect(result.before.b?.sealedSecretB64u).toBe('b');
    expect(result.after.a).toBeNull();
    expect(result.after.b).toBeNull();
  });

  test('uses IndexedDB in wallet iframe host mode and leaves only runtime marker in sessionStorage', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        (
          globalThis as { __W3A_TEST_WALLET_IFRAME_HOST_MODE__?: boolean }
        ).__W3A_TEST_WALLET_IFRAME_HOST_MODE__ = true;
        try {
          const mod = await import(paths.signingSessionSealedStore);
          const thresholdSessionId = 'sess-host-mode';
          await mod.clearAllSigningSessionSealedRecords();
          await mod.writeSigningSessionSealedRecord({
            thresholdSessionId,
            walletSigningSessionId: 'wallet-sess-host-mode',
            sealedSecretB64u: 'sealed-host',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 2,
            updatedAtMs: Date.now(),
          });
          const record = await mod.readSigningSessionSealedRecord(thresholdSessionId);
          return {
            record,
            localRaw: localStorage.getItem(
              `tatchi:signing-session-sealed:v1:${thresholdSessionId}`,
            ),
            sessionRaw: sessionStorage.getItem(
              `tatchi:signing-session-sealed:v1:${thresholdSessionId}`,
            ),
            localIndex: localStorage.getItem('tatchi:signing-session-sealed:v1:index'),
            sessionIndex: sessionStorage.getItem('tatchi:signing-session-sealed:v1:index'),
            runtimeSessionId: sessionStorage.getItem(
              'tatchi:signing-session-sealed:runtime-session-id:v1',
            ),
          };
        } finally {
          delete (globalThis as { __W3A_TEST_WALLET_IFRAME_HOST_MODE__?: boolean })
            .__W3A_TEST_WALLET_IFRAME_HOST_MODE__;
        }
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.record?.sealedSecretB64u).toBe('sealed-host');
    expect(result.localRaw).toBeNull();
    expect(result.localIndex).toBeNull();
    expect(result.sessionRaw).toBeNull();
    expect(result.sessionIndex).toBeNull();
    expect(result.runtimeSessionId).toEqual(expect.any(String));
  });

  test('deletes IndexedDB record when browser-session marker is missing', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionSealedStore);
        const thresholdSessionId = 'sess-browser-restart';
        await mod.clearAllSigningSessionSealedRecords();
        await mod.writeSigningSessionSealedRecord({
          thresholdSessionId,
          walletSigningSessionId: 'wallet-sess-browser-restart',
          sealedSecretB64u: 'sealed-restart',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        });
        const before = await mod.readSigningSessionSealedRecord(thresholdSessionId);
        sessionStorage.removeItem('tatchi:signing-session-sealed:runtime-session-id:v1');
        const after = await mod.readSigningSessionSealedRecord(thresholdSessionId);
        const secondReadAfterDelete = await mod.readSigningSessionSealedRecord(thresholdSessionId);
        return { before, after, secondReadAfterDelete };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.before?.sealedSecretB64u).toBe('sealed-restart');
    expect(result.after).toBeNull();
    expect(result.secondReadAfterDelete).toBeNull();
  });

  test('leases restore attempts by wallet signing session', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionSealedStore);
        const thresholdSessionId = 'sess-lease';
        await mod.clearAllSigningSessionSealedRecords();
        await mod.writeSigningSessionSealedRecord({
          thresholdSessionId,
          walletSigningSessionId: 'wallet-session-lease',
          sealedSecretB64u: 'sealed-lease',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        });

        const first = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          ownerId: 'tab-a',
          nowMs: 1_000,
          ttlMs: 5_000,
        });
        const blocked = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          ownerId: 'tab-b',
          nowMs: 2_000,
          ttlMs: 5_000,
        });
        await mod.releaseSigningSessionRestoreLease(first);
        const afterRelease = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          ownerId: 'tab-b',
          nowMs: 3_000,
          ttlMs: 5_000,
        });
        const expiredSteal = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          ownerId: 'tab-c',
          nowMs: 9_000,
          ttlMs: 5_000,
        });
        await mod.clearAllSigningSessionSealedRecords();
        const afterClear = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          ownerId: 'tab-d',
          nowMs: 10_000,
          ttlMs: 5_000,
        });

        return {
          first,
          blocked,
          afterRelease,
          expiredSteal,
          afterClear,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.first?.ownerId).toBe('tab-a');
    expect(result.first?.walletSigningSessionId).toBe('wallet-session-lease');
    expect(result.blocked).toBeNull();
    expect(result.afterRelease?.ownerId).toBe('tab-b');
    expect(result.expiredSteal?.ownerId).toBe('tab-c');
    expect(result.afterClear).toBeNull();
  });

  test('operation-scoped session ids do not update or delete a transaction sealed refresh record', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.signingSessionSealedStore);
        await mod.clearAllSigningSessionSealedRecords();
        await mod.writeSigningSessionSealedRecord({
          thresholdSessionId: 'transaction-ecdsa-session',
          walletSigningSessionId: 'transaction-wallet-session',
          thresholdSessionIds: {
            ecdsa: 'transaction-ecdsa-session',
            ed25519: 'transaction-ed25519-session',
          },
          authMethod: 'email_otp',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'signing-root',
          sealedSecretB64u: 'sealed-transaction-k',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 7,
          updatedAtMs: Date.now(),
        });

        await mod.updateSigningSessionSealedRecordPolicy({
          thresholdSessionId: 'export-operation-session',
          expiresAtMs: Date.now() + 10_000,
          remainingUses: 0,
          updatedAtMs: Date.now(),
        });
        await mod.deleteSigningSessionSealedRecord('link-device-operation-session');
        await mod.deleteSigningSessionSealedRecord('add-signer-operation-session');

        return {
          byEcdsa: await mod.readSigningSessionSealedRecord('transaction-ecdsa-session'),
          byEd25519: await mod.readSigningSessionSealedRecord('transaction-ed25519-session'),
          byExport: await mod.readSigningSessionSealedRecord('export-operation-session'),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.byEcdsa?.walletSigningSessionId).toBe('transaction-wallet-session');
    expect(result.byEcdsa?.sealedSecretB64u).toBe('sealed-transaction-k');
    expect(result.byEcdsa?.remainingUses).toBe(7);
    expect(result.byEd25519?.walletSigningSessionId).toBe('transaction-wallet-session');
    expect(result.byExport).toBeNull();
  });
});
