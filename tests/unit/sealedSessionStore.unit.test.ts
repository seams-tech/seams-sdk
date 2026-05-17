import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  indexedDB: '/sdk/esm/core/indexedDB/index.js',
  sealedSessionStore: '/sdk/esm/core/signingEngine/session/persistence/sealedSessionStore.js',
} as const;

const ECDSA_RESTORE = {
  chain: 'tempo',
  chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
  rpId: 'wallet.example.localhost',
  sessionKind: 'jwt',
  ecdsaThresholdKeyId: 'ecdsa-key',
  ethereumAddress: `0x${'33'.repeat(20)}`,
  relayerKeyId: 'relayer-key',
  thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
  participantIds: [1, 2, 3],
} as const;

const EMAIL_OTP_ECDSA_RESTORE = {
  ...ECDSA_RESTORE,
  thresholdSessionAuthToken: 'threshold-session-jwt',
} as const;

const PASSKEY_ED25519_RESTORE = {
  rpId: 'wallet.example.localhost',
  relayerKeyId: 'relayer-key',
  participantIds: [1, 2, 3],
  sessionKind: 'cookie',
  xClientBaseB64u: 'x-client-base-b64u',
} as const;

const EMAIL_OTP_ED25519_RESTORE = {
  ...PASSKEY_ED25519_RESTORE,
  sessionKind: 'jwt',
  thresholdSessionAuthToken: 'threshold-session-jwt',
} as const;

test.describe('signing session sealed store', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipPasskeyManagerInit: true });
    await page.evaluate(
      ({ ecdsaRestore, emailOtpEcdsaRestore, passkeyEd25519Restore, emailOtpEd25519Restore }) => {
        (
          globalThis as {
            ECDSA_RESTORE?: typeof ecdsaRestore;
            EMAIL_OTP_ECDSA_RESTORE?: typeof emailOtpEcdsaRestore;
            PASSKEY_ED25519_RESTORE?: typeof passkeyEd25519Restore;
            EMAIL_OTP_ED25519_RESTORE?: typeof emailOtpEd25519Restore;
          }
        ).ECDSA_RESTORE = ecdsaRestore;
        (
          globalThis as {
            EMAIL_OTP_ECDSA_RESTORE?: typeof emailOtpEcdsaRestore;
          }
        ).EMAIL_OTP_ECDSA_RESTORE = emailOtpEcdsaRestore;
        (
          globalThis as {
            PASSKEY_ED25519_RESTORE?: typeof passkeyEd25519Restore;
          }
        ).PASSKEY_ED25519_RESTORE = passkeyEd25519Restore;
        (
          globalThis as {
            EMAIL_OTP_ED25519_RESTORE?: typeof emailOtpEd25519Restore;
          }
        ).EMAIL_OTP_ED25519_RESTORE = emailOtpEd25519Restore;
      },
      {
        ecdsaRestore: ECDSA_RESTORE,
        emailOtpEcdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
        passkeyEd25519Restore: PASSKEY_ED25519_RESTORE,
        emailOtpEd25519Restore: EMAIL_OTP_ED25519_RESTORE,
      },
    );
  });

  test('writes shamir3pass records to IndexedDB without persisting plaintext secret or JWT auth', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'sess-sealed-1';
        const walletSigningSessionId = 'wallet-sess-sealed-1';
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId,
          walletSigningSessionId,
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'passkey',
          ecdsaRestore: ECDSA_RESTORE,
          walletId: 'sealed-store.testnet',
          userId: 'sealed-store.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-secret-b64u',
          thresholdSessionAuthToken: 'jwt-must-not-persist',
          signingSessionSecretB64u: 'plaintext-k-must-not-persist',
          emailOtpSecretS: 'plaintext-s-must-not-persist',
          enrollmentEscrowB64u: 'enrollment-escrow-must-not-persist',
          keyVersion: 'kek-s-2026-02',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 7,
          updatedAtMs: Date.now(),
        })!);

        const passkeyEcdsa = { authMethod: 'passkey', curve: 'ecdsa', chain: 'tempo', chainTarget: ECDSA_RESTORE.chainTarget };
        const record = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);
        const rawRecord = await new Promise<unknown>((resolve, reject) => {
          const openReq = indexedDB.open('seams_wallet_v1');
          openReq.onsuccess = () => {
            const db = openReq.result;
            const tx = db.transaction('signing_session_seals_v1', 'readonly');
            const getReq = tx.objectStore('signing_session_seals_v1').get(record?.storeKey);
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
          `seams:signing-session-sealed:v1:${thresholdSessionId}`,
        );
        const sessionIndex = sessionStorage.getItem('seams:signing-session-sealed:v1:index');
        return {
          record,
          sessionRaw,
          sessionIndex,
          rawHasPlaintextSecret:
            !!record &&
            (Object.prototype.hasOwnProperty.call(record, 'prfFirstB64u') ||
              Object.prototype.hasOwnProperty.call(record, 'signingSessionSecretB64u') ||
              Object.prototype.hasOwnProperty.call(record, 'secretSourceB64u')),
          rawHasThresholdSessionAuthToken:
            !!record && Object.prototype.hasOwnProperty.call(record, 'thresholdSessionAuthToken'),
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
    expect(result.rawHasThresholdSessionAuthToken).toBe(false);
    expect(result.rawHasPlaintextK).toBe(false);
    expect(result.rawHasPlaintextS).toBe(false);
    expect(result.rawHasEnrollmentEscrow).toBe(false);
    expect(result.rawHasJwt).toBe(false);
  });

  test('fails closed on malformed plaintext record payloads', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'sess-plaintext-record';
        await mod.clearAllSealedSessions();
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = indexedDB.open('seams_wallet_v1');
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
            'seams:signing-session-sealed:runtime-session-id:v1',
          ),
          authMethod: 'passkey',
          secretKind: 'signing_session_secret32',
          storeKey: `plaintext:${thresholdSessionId}:passkey:ecdsa`,
          walletSigningSessionId: thresholdSessionId,
          thresholdSessionIds: { ecdsa: thresholdSessionId },
          curve: 'ecdsa',
          ecdsaRestore: ECDSA_RESTORE,
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

        const passkeyEcdsa = { authMethod: 'passkey', curve: 'ecdsa', chain: 'tempo', chainTarget: ECDSA_RESTORE.chainTarget };
        const read = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);
        await mod.deleteExactSealedSession(thresholdSessionId, passkeyEcdsa, {
          deleteResolvedIdentity: true,
          resolvedIdentityDeleteReason: 'durable_record_deleted',
        });
        const afterDelete = await mod.readExactSealedSession(
          thresholdSessionId,
          passkeyEcdsa,
        );

        return { read, afterDelete };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.read).toBeNull();
    expect(result.afterDelete).toBeNull();
  });

  test('drops chain-only ECDSA sealed records instead of inferring a concrete target', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'legacy-chain-only-session',
          walletSigningSessionId: 'legacy-chain-only-wallet-session',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'email_otp',
          ecdsaRestore: {
            chain: 'evm',
            sessionKind: 'jwt',
            ecdsaThresholdKeyId: 'legacy-ecdsa-key',
            relayerKeyId: 'legacy-relayer-key',
            participantIds: [1, 2],
          },
          sealedSecretB64u: 'sealed-legacy-chain-only',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: Date.now(),
        })!);

        return await mod.readExactSealedSession('legacy-chain-only-session', {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain: 'evm',
          chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 5042002, networkSlug: 'arc-testnet' },
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(result).toBeNull();
  });

  test('validates Email OTP sealed record schema and rejects malformed Email OTP records', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'email-otp-ecdsa-session',
          walletSigningSessionId: 'email-otp-wallet-session',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          thresholdSessionIds: {
            ecdsa: 'email-otp-ecdsa-session',
            ed25519: 'email-otp-ed25519-session',
          },
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
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
        })!);
        const emailOtpEcdsa = { authMethod: 'email_otp', curve: 'ecdsa', chain: 'tempo', chainTarget: ECDSA_RESTORE.chainTarget };
        const emailOtpEd25519 = { authMethod: 'email_otp', curve: 'ed25519' };
        const validByEcdsa = await mod.readExactSealedSession(
          'email-otp-ecdsa-session',
          emailOtpEcdsa,
        );
        const validByEd25519 = await mod.readExactSealedSession(
          'email-otp-ed25519-session',
          emailOtpEd25519,
        );

        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = indexedDB.open('seams_wallet_v1');
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const tx = db.transaction('signing_session_seals_v1', 'readwrite');
        tx.objectStore('signing_session_seals_v1').put({
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: sessionStorage.getItem(
            'seams:signing-session-sealed:runtime-session-id:v1',
          ),
          authMethod: 'email_otp',
          secretKind: 'enrollment_secret_s',
          storeKey: 'bad-email-otp-wallet-session:email_otp:ecdsa',
          walletSigningSessionId: 'bad-email-otp-wallet-session',
          thresholdSessionIds: { ecdsa: 'bad-email-otp-ecdsa-session' },
          curve: 'ecdsa',
          ecdsaRestore: ECDSA_RESTORE,
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

        const malformed = await mod.readExactSealedSession(
          'bad-email-otp-ecdsa-session',
          emailOtpEcdsa,
        );
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

  test('classifies legacy missing-field ECDSA records at the persistence boundary', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();
        const now = Date.now();
        const deleteStoreKey = 'legacy-delete-wallet-session:email_otp:ecdsa:tempo%3A42431';
        const missingSigningRootStoreKey =
          'legacy-missing-signing-root-wallet-session:email_otp:ecdsa:tempo%3A42431';
        const missingTokenStoreKey =
          'legacy-missing-token-wallet-session:email_otp:ecdsa:tempo%3A42431';
        const missingOwnerStoreKey =
          'legacy-missing-owner-wallet-session:email_otp:ecdsa:tempo%3A42431';
        const missingKeyIdStoreKey =
          'legacy-missing-key-id-wallet-session:email_otp:ecdsa:tempo%3A42431';
        const missingWalletSessionStoreKey =
          'legacy-missing-wallet-session:email_otp:ecdsa:tempo%3A42431';

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'legacy-current-ecdsa-session',
          walletSigningSessionId: 'legacy-current-wallet-session',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'email_otp',
          thresholdSessionIds: { ecdsa: 'legacy-current-ecdsa-session' },
          walletId: 'legacy.testnet',
          userId: 'legacy.testnet',
          signingRootId: 'legacy-signing-root',
          relayerUrl: 'https://relay.example',
          ecdsaRestore: {
            ...ECDSA_RESTORE,
            thresholdSessionAuthToken: 'threshold-session-jwt',
          },
          sealedSecretB64u: 'sealed-current',
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          remainingUses: 2,
          updatedAtMs: now,
        })!);

        const deleteRequiredRaw = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          secretKind: 'signing_session_secret32',
          storeKey: deleteStoreKey,
          authMethod: 'email_otp',
          walletSigningSessionId: 'legacy-delete-wallet-session',
          thresholdSessionIds: { ecdsa: 'legacy-delete-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          walletId: 'legacy.testnet',
          userId: 'legacy.testnet',
          signingRootId: 'legacy-signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-delete',
          ecdsaRestore: {
            ...ECDSA_RESTORE,
            thresholdSessionAuthToken: 'threshold-session-jwt',
            participantIds: [],
          },
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          remainingUses: 2,
          updatedAtMs: now,
        };
        const rebuildRequiredRaw = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          secretKind: 'signing_session_secret32',
          storeKey: 'legacy-rebuild-required',
          authMethod: 'email_otp',
          walletSigningSessionId: 'legacy-rebuild-wallet-session',
          thresholdSessionIds: { ecdsa: 'legacy-rebuild-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          walletId: 'legacy.testnet',
          userId: 'legacy.testnet',
          signingRootId: 'legacy-signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-rebuild',
          ecdsaRestore: undefined,
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          remainingUses: 2,
          updatedAtMs: now,
        };
        const missingSigningRootRaw = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          secretKind: 'signing_session_secret32',
          storeKey: missingSigningRootStoreKey,
          authMethod: 'email_otp',
          walletSigningSessionId: 'legacy-missing-signing-root-wallet-session',
          thresholdSessionIds: { ecdsa: 'legacy-missing-signing-root-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          walletId: 'legacy.testnet',
          userId: 'legacy.testnet',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-missing-signing-root',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          remainingUses: 2,
          updatedAtMs: now,
        };
        const missingTokenRaw = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          secretKind: 'signing_session_secret32',
          storeKey: missingTokenStoreKey,
          authMethod: 'email_otp',
          walletSigningSessionId: 'legacy-missing-token-wallet-session',
          thresholdSessionIds: { ecdsa: 'legacy-missing-token-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          walletId: 'legacy.testnet',
          userId: 'legacy.testnet',
          signingRootId: 'legacy-signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-missing-token',
          ecdsaRestore: ECDSA_RESTORE,
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          remainingUses: 2,
          updatedAtMs: now,
        };
        const { ethereumAddress: _missingOwnerAddress, ...restoreWithoutOwner } =
          EMAIL_OTP_ECDSA_RESTORE;
        const { ecdsaThresholdKeyId: _missingEcdsaThresholdKeyId, ...restoreWithoutKeyId } =
          EMAIL_OTP_ECDSA_RESTORE;
        const missingOwnerRaw = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          secretKind: 'signing_session_secret32',
          storeKey: missingOwnerStoreKey,
          authMethod: 'email_otp',
          walletSigningSessionId: 'legacy-missing-owner-wallet-session',
          thresholdSessionIds: { ecdsa: 'legacy-missing-owner-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          walletId: 'legacy.testnet',
          userId: 'legacy.testnet',
          signingRootId: 'legacy-signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-missing-owner',
          ecdsaRestore: restoreWithoutOwner,
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          remainingUses: 2,
          updatedAtMs: now,
        };
        const missingKeyIdRaw = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          secretKind: 'signing_session_secret32',
          storeKey: missingKeyIdStoreKey,
          authMethod: 'email_otp',
          walletSigningSessionId: 'legacy-missing-key-id-wallet-session',
          thresholdSessionIds: { ecdsa: 'legacy-missing-key-id-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          walletId: 'legacy.testnet',
          userId: 'legacy.testnet',
          signingRootId: 'legacy-signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-missing-key-id',
          ecdsaRestore: restoreWithoutKeyId,
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          remainingUses: 2,
          updatedAtMs: now,
        };
        const missingWalletSessionRaw = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          secretKind: 'signing_session_secret32',
          storeKey: missingWalletSessionStoreKey,
          authMethod: 'email_otp',
          thresholdSessionIds: { ecdsa: 'legacy-missing-wallet-session-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          walletId: 'legacy.testnet',
          userId: 'legacy.testnet',
          signingRootId: 'legacy-signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-missing-wallet-session',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          issuedAtMs: now,
          expiresAtMs: now + 60_000,
          remainingUses: 2,
          updatedAtMs: now,
        };

        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = indexedDB.open('seams_wallet_v1');
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const tx = db.transaction('signing_session_seals_v1', 'readwrite');
        tx.objectStore('signing_session_seals_v1').put(deleteRequiredRaw);
        tx.objectStore('signing_session_seals_v1').put(rebuildRequiredRaw);
        tx.objectStore('signing_session_seals_v1').put(missingSigningRootRaw);
        tx.objectStore('signing_session_seals_v1').put(missingTokenRaw);
        tx.objectStore('signing_session_seals_v1').put(missingOwnerRaw);
        tx.objectStore('signing_session_seals_v1').put(missingKeyIdRaw);
        tx.objectStore('signing_session_seals_v1').put(missingWalletSessionRaw);
        await new Promise<void>((resolve, reject) => {
          tx.oncomplete = () => resolve();
          tx.onerror = () => reject(tx.error);
          tx.onabort = () => reject(tx.error);
        });

        const filter = {
          authMethod: 'email_otp' as const,
          curve: 'ecdsa' as const,
          chain: 'tempo' as const,
          chainTarget: ECDSA_RESTORE.chainTarget,
        };
        const currentRead = await mod.readExactSealedSession('legacy-current-ecdsa-session', filter);
        const deleteRead = await mod.readExactSealedSession('legacy-delete-ecdsa-session', filter);
        const rebuildRead = await mod.readExactSealedSession('legacy-rebuild-ecdsa-session', filter);
        const missingSigningRootRead = await mod.readExactSealedSession(
          'legacy-missing-signing-root-ecdsa-session',
          filter,
        );
        const missingTokenRead = await mod.readExactSealedSession(
          'legacy-missing-token-ecdsa-session',
          filter,
        );
        const missingOwnerRead = await mod.readExactSealedSession(
          'legacy-missing-owner-ecdsa-session',
          filter,
        );
        const missingKeyIdRead = await mod.readExactSealedSession(
          'legacy-missing-key-id-ecdsa-session',
          filter,
        );
        const missingWalletSessionRead = await mod.readExactSealedSession(
          'legacy-missing-wallet-session-ecdsa-session',
          filter,
        );

        const remainingKeys = await new Promise<string[]>((resolve, reject) => {
          const readTx = db.transaction('signing_session_seals_v1', 'readonly');
          const getReq = readTx.objectStore('signing_session_seals_v1').getAll();
          getReq.onsuccess = () => {
            resolve(
              (getReq.result as Array<Record<string, unknown>>).map((entry) => String(entry.storeKey)),
            );
          };
          getReq.onerror = () => reject(getReq.error);
        });
        db.close();

        return {
          currentRead,
          deleteRead,
          rebuildRead,
          missingSigningRootRead,
          missingTokenRead,
          missingOwnerRead,
          missingKeyIdRead,
          missingWalletSessionRead,
          remainingKeys,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.currentRead?.signingRootVersion).toBe('default');
    expect(result.deleteRead).toBeNull();
    expect(result.rebuildRead).toBeNull();
    expect(result.missingSigningRootRead).toBeNull();
    expect(result.missingTokenRead).toBeNull();
    expect(result.missingOwnerRead).toBeNull();
    expect(result.missingKeyIdRead).toBeNull();
    expect(result.missingWalletSessionRead).toBeNull();
    expect(result.currentRead?.storeKey).toBe(
      'legacy-current-wallet-session:email_otp:ecdsa:tempo%3A42431',
    );
    expect(result.remainingKeys).toContain(result.currentRead?.storeKey);
    expect(result.remainingKeys).not.toContain(
      'legacy-delete-wallet-session:email_otp:ecdsa:tempo%3A42431',
    );
    expect(result.remainingKeys).not.toContain(
      'legacy-missing-signing-root-wallet-session:email_otp:ecdsa:tempo%3A42431',
    );
    expect(result.remainingKeys).not.toContain(
      'legacy-missing-token-wallet-session:email_otp:ecdsa:tempo%3A42431',
    );
    expect(result.remainingKeys).not.toContain(
      'legacy-missing-wallet-session:email_otp:ecdsa:tempo%3A42431',
    );
    expect(result.remainingKeys).toContain(
      'legacy-missing-owner-wallet-session:email_otp:ecdsa:tempo%3A42431',
    );
    expect(result.remainingKeys).toContain(
      'legacy-missing-key-id-wallet-session:email_otp:ecdsa:tempo%3A42431',
    );
    expect(result.remainingKeys).toContain('legacy-rebuild-required');
  });

  test('filters colliding passkey and Email OTP sealed records by auth method and curve', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'shared-threshold-session';
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId,
          walletSigningSessionId: 'passkey-wallet-session',
          thresholdSessionIds: { ed25519: thresholdSessionId },
          curve: 'ed25519',
          authMethod: 'passkey',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          ed25519Restore: PASSKEY_ED25519_RESTORE,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-passkey-session',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 5,
          updatedAtMs: Date.now(),
        })!);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId,
          walletSigningSessionId: 'email-otp-wallet-session',
          thresholdSessionIds: { ecdsa: thresholdSessionId },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          walletId: 'alice.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          shamirPrimeB64u: 'prime-b64u',
          sealedSecretB64u: 'sealed-email-otp-session',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        })!);

        const generic = await mod
          .readExactSealedSession(thresholdSessionId)
          .then(() => 'resolved')
          .catch((error: unknown) => String((error as Error)?.message || error));
        const emailOtp = await mod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        });
        const passkey = await mod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'passkey',
          curve: 'ed25519',
        });
        const emailLease = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
          ownerId: 'unit-test',
          ttlMs: 15_000,
        });
        await mod.deleteExactSealedSession(
          thresholdSessionId,
          {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          },
          {
            deleteResolvedIdentity: true,
            resolvedIdentityDeleteReason: 'durable_record_deleted',
          },
        );
        const emailAfterDelete = await mod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        });
        const passkeyAfterDelete = await mod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'passkey',
          curve: 'ed25519',
        });

        return {
          generic,
          emailOtp,
          passkey,
          emailLease,
          emailAfterDelete,
          passkeyAfterDelete,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.generic).toContain('requires an explicit authMethod, curve, and ECDSA chain');
    expect(result.emailOtp?.walletSigningSessionId).toBe('email-otp-wallet-session');
    expect(result.passkey?.walletSigningSessionId).toBe('passkey-wallet-session');
    expect(result.emailLease?.walletSigningSessionId).toBe('email-otp-wallet-session');
    expect(result.emailAfterDelete).toBeNull();
    expect(result.passkeyAfterDelete?.walletSigningSessionId).toBe('passkey-wallet-session');
  });

  test('keeps passkey Ed25519 signing-session seals without client-base metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'passkey-ed25519-prf-only-session';
        const walletSigningSessionId = 'passkey-ed25519-prf-only-wallet-session';
        await mod.clearAllSealedSessions();
        const { xClientBaseB64u: _xClientBaseB64u, ...ed25519Restore } =
          PASSKEY_ED25519_RESTORE;

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId,
          walletSigningSessionId,
          thresholdSessionIds: { ed25519: thresholdSessionId },
          curve: 'ed25519',
          authMethod: 'passkey',
          walletId: 'passkey-ed25519-prf-only.testnet',
          userId: 'passkey-ed25519-prf-only.testnet',
          ed25519Restore,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-passkey-prf-first',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 5,
          updatedAtMs: Date.now(),
        })!);

        return await mod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'passkey',
          curve: 'ed25519',
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(result?.sealedSecretB64u).toBe('sealed-passkey-prf-first');
    expect(result?.ed25519Restore?.xClientBaseB64u).toBeUndefined();
  });

  test('lists durable sealed records for an account by auth method and curve', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'email-otp-ecdsa-session',
          walletSigningSessionId: 'email-otp-wallet-session',
          thresholdSessionIds: { ecdsa: 'email-otp-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          shamirPrimeB64u: 'prime-b64u',
          sealedSecretB64u: 'sealed-email-otp-ecdsa',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        })!);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'email-otp-ed25519-session',
          walletSigningSessionId: 'email-otp-ed25519-wallet-session',
          thresholdSessionIds: { ed25519: 'email-otp-ed25519-session' },
          curve: 'ed25519',
          authMethod: 'email_otp',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          ed25519Restore: EMAIL_OTP_ED25519_RESTORE,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-email-otp-ed25519',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        })!);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'passkey-ecdsa-session',
          walletSigningSessionId: 'passkey-wallet-session',
          thresholdSessionIds: { ecdsa: 'passkey-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'passkey',
          ecdsaRestore: ECDSA_RESTORE,
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-passkey-ecdsa',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        })!);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'bob-email-otp-ecdsa-session',
          walletSigningSessionId: 'bob-email-otp-wallet-session',
          thresholdSessionIds: { ecdsa: 'bob-email-otp-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          walletId: 'bob.testnet',
          userId: 'bob.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          shamirPrimeB64u: 'prime-b64u',
          sealedSecretB64u: 'sealed-bob-email-otp-ecdsa',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        })!);

        const records = await mod.listExactSealedSessionsForWallet({
          walletId: 'alice.testnet',
          filter: { authMethod: 'email_otp', curve: 'ecdsa', chain: 'tempo', chainTarget: ECDSA_RESTORE.chainTarget },
        });

        return {
          records,
          walletSigningSessionIds: records.map((record: any) => record.walletSigningSessionId),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.records).toHaveLength(1);
    expect(result.walletSigningSessionIds).toEqual(['email-otp-wallet-session']);
    expect(result.records[0]).toMatchObject({
      authMethod: 'email_otp',
      curve: 'ecdsa',
      walletId: 'alice.testnet',
      thresholdSessionIds: { ecdsa: 'email-otp-ecdsa-session' },
    });
  });

  test('replaces stale same-purpose sealed records before snapshot selection sees them', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'old-email-otp-ed25519-session',
          walletSigningSessionId: 'old-email-otp-ed25519-wallet-session',
          thresholdSessionIds: { ed25519: 'old-email-otp-ed25519-session' },
          curve: 'ed25519',
          authMethod: 'email_otp',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          ed25519Restore: EMAIL_OTP_ED25519_RESTORE,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'old-ed25519',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: Date.now() - 1_000,
        })!);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'new-email-otp-ed25519-session',
          walletSigningSessionId: 'new-email-otp-ed25519-wallet-session',
          thresholdSessionIds: { ed25519: 'new-email-otp-ed25519-session' },
          curve: 'ed25519',
          authMethod: 'email_otp',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          ed25519Restore: EMAIL_OTP_ED25519_RESTORE,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'new-ed25519',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: Date.now(),
        })!);

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'old-email-otp-ecdsa-session',
          walletSigningSessionId: 'old-email-otp-ecdsa-wallet-session',
          thresholdSessionIds: { ecdsa: 'old-email-otp-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'old-ecdsa',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: Date.now() - 1_000,
        })!);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'new-email-otp-ecdsa-session',
          walletSigningSessionId: 'new-email-otp-ecdsa-wallet-session',
          thresholdSessionIds: { ecdsa: 'new-email-otp-ecdsa-session' },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'new-ecdsa',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: Date.now(),
        })!);

        const ed25519Records = await mod.listExactSealedSessionsForWallet({
          walletId: 'alice.testnet',
          filter: { authMethod: 'email_otp', curve: 'ed25519' },
        });
        const ecdsaRecords = await mod.listExactSealedSessionsForWallet({
          walletId: 'alice.testnet',
          filter: { authMethod: 'email_otp', curve: 'ecdsa', chain: ECDSA_RESTORE.chain, chainTarget: ECDSA_RESTORE.chainTarget },
        });

        return {
          ed25519WalletSessionIds: ed25519Records.map(
            (record: any) => record.walletSigningSessionId,
          ),
          ecdsaWalletSessionIds: ecdsaRecords.map((record: any) => record.walletSigningSessionId),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ed25519WalletSessionIds).toEqual(['new-email-otp-ed25519-wallet-session']);
    expect(result.ecdsaWalletSessionIds).toEqual(['new-email-otp-ecdsa-wallet-session']);
  });

  test('keeps passkey and Email OTP sealed records with the same wallet signing session separate', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const sharedWalletSigningSessionId = 'shared-wallet-signing-session';
        const sharedEd25519SessionId = 'shared-ed25519-threshold-session';
        const emailOtpEcdsaSessionId = 'email-otp-ecdsa-threshold-session';
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: sharedEd25519SessionId,
          walletSigningSessionId: sharedWalletSigningSessionId,
          thresholdSessionIds: { ed25519: sharedEd25519SessionId },
          curve: 'ed25519',
          authMethod: 'passkey',
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          ed25519Restore: PASSKEY_ED25519_RESTORE,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-passkey-ed25519',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          updatedAtMs: Date.now(),
        })!);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: emailOtpEcdsaSessionId,
          walletSigningSessionId: sharedWalletSigningSessionId,
          thresholdSessionIds: {
            ed25519: sharedEd25519SessionId,
            ecdsa: emailOtpEcdsaSessionId,
          },
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          walletId: 'alice.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-email-otp-ecdsa',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        })!);

        return {
          passkeyEd25519: await mod.readExactSealedSession(sharedEd25519SessionId, {
            authMethod: 'passkey',
            curve: 'ed25519',
          }),
          emailOtpEd25519: await mod.readExactSealedSession(sharedEd25519SessionId, {
            authMethod: 'email_otp',
            curve: 'ed25519',
          }),
          emailOtpEcdsa: await mod.readExactSealedSession(emailOtpEcdsaSessionId, {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          }),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.passkeyEd25519?.sealedSecretB64u).toBe('sealed-passkey-ed25519');
    expect(result.passkeyEd25519?.storeKey).toBe('shared-wallet-signing-session:passkey:ed25519');
    expect(result.emailOtpEd25519?.sealedSecretB64u).toBe('sealed-email-otp-ecdsa');
    expect(result.emailOtpEcdsa?.sealedSecretB64u).toBe('sealed-email-otp-ecdsa');
    expect(result.emailOtpEcdsa?.storeKey).toBe(
      'shared-wallet-signing-session:email_otp:ecdsa:tempo%3A42431',
    );
  });

  test('clearAll removes all IndexedDB sealed records', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'sess-a',
          walletSigningSessionId: 'wallet-sess-a',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'passkey',
          ecdsaRestore: ECDSA_RESTORE,
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'a',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        })!);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'sess-b',
          walletSigningSessionId: 'wallet-sess-b',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'passkey',
          ecdsaRestore: ECDSA_RESTORE,
          walletId: 'bob.testnet',
          userId: 'bob.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'b',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        })!);
        const before = {
          a: await mod.readExactSealedSession('sess-a', {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          }),
          b: await mod.readExactSealedSession('sess-b', {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          }),
        };
        await mod.clearAllSealedSessions();
        const after = {
          a: await mod.readExactSealedSession('sess-a', {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          }),
          b: await mod.readExactSealedSession('sess-b', {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          }),
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

  test('uses IndexedDB in wallet iframe host mode without writing signing-session identity to sessionStorage', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        (
          globalThis as { __W3A_TEST_WALLET_IFRAME_HOST_MODE__?: boolean }
        ).__W3A_TEST_WALLET_IFRAME_HOST_MODE__ = true;
        try {
          const mod = await import(paths.sealedSessionStore);
          const thresholdSessionId = 'sess-host-mode';
          await mod.clearAllSealedSessions();
          await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
            thresholdSessionId,
            walletSigningSessionId: 'wallet-sess-host-mode',
            curve: 'ecdsa',
            subjectId: 'sealed-store-subject',
            authMethod: 'passkey',
            ecdsaRestore: ECDSA_RESTORE,
            walletId: 'alice.testnet',
            userId: 'alice.testnet',
            signingRootId: 'signing-root',
            relayerUrl: 'https://relay.example',
            sealedSecretB64u: 'sealed-host',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 2,
            updatedAtMs: Date.now(),
          })!);
          const record = await mod.readExactSealedSession(thresholdSessionId, {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          });
          return {
            record,
            localRaw: localStorage.getItem(
              `seams:signing-session-sealed:v1:${thresholdSessionId}`,
            ),
            sessionRaw: sessionStorage.getItem(
              `seams:signing-session-sealed:v1:${thresholdSessionId}`,
            ),
            localIndex: localStorage.getItem('seams:signing-session-sealed:v1:index'),
            sessionIndex: sessionStorage.getItem('seams:signing-session-sealed:v1:index'),
            sessionKeys: Object.keys(sessionStorage).filter((key) =>
              key.includes('signing-session'),
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
    expect(result.sessionKeys).toEqual([]);
  });

  test('does not create seams_wallet_v1 when IndexedDB persistence is disabled', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        await new Promise<void>((resolve) => {
          const req = indexedDB.deleteDatabase('seams_wallet_v1');
          req.onsuccess = () => resolve();
          req.onerror = () => resolve();
          req.onblocked = () => resolve();
        });
        const indexedDbMod = await import(paths.indexedDB);
        indexedDbMod.configureIndexedDB({ mode: 'disabled' });
        const mod = await import(paths.sealedSessionStore);
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'sess-disabled-mode',
          walletSigningSessionId: 'wallet-sess-disabled-mode',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'passkey',
          ecdsaRestore: ECDSA_RESTORE,
          walletId: 'disabled.testnet',
          userId: 'disabled.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-disabled',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: Date.now(),
        })!);
        const record = await mod.readExactSealedSession('sess-disabled-mode', {
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        });
        await mod.clearAllSealedSessions();
        const databaseNames =
          typeof indexedDB.databases === 'function'
            ? (await indexedDB.databases()).map((db) => db.name).filter(Boolean)
            : [];
        return {
          record,
          databaseNames,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.record).toBeNull();
    expect(result.databaseNames).not.toContain('seams_wallet_v1');
  });

  test('reads IndexedDB record when browser-session marker is missing', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'sess-browser-restart';
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId,
          walletSigningSessionId: 'wallet-sess-browser-restart',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'passkey',
          ecdsaRestore: ECDSA_RESTORE,
          walletId: 'restart.testnet',
          userId: 'restart.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-restart',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        })!);
        const passkeyEcdsa = { authMethod: 'passkey', curve: 'ecdsa', chain: 'tempo', chainTarget: ECDSA_RESTORE.chainTarget };
        const before = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);
        sessionStorage.removeItem('seams:signing-session-sealed:runtime-session-id:v1');
        const after = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);
        const exactAfterMarkerRemoved = await mod.listExactSealedSessionsForWallet({
          walletId: 'restart.testnet',
          filter: { authMethod: 'passkey', curve: 'ecdsa', chain: 'tempo', chainTarget: ECDSA_RESTORE.chainTarget },
        });
        const readAfterMarkerRestored = await mod.readExactSealedSession(
          thresholdSessionId,
          passkeyEcdsa,
        );
        return { before, after, exactAfterMarkerRemoved, readAfterMarkerRestored };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.before?.sealedSecretB64u).toBe('sealed-restart');
    expect(result.after?.sealedSecretB64u).toBe('sealed-restart');
    expect(result.exactAfterMarkerRemoved).toHaveLength(1);
    expect(result.exactAfterMarkerRemoved[0]?.sealedSecretB64u).toBe('sealed-restart');
    expect(result.readAfterMarkerRestored?.sealedSecretB64u).toBe('sealed-restart');
  });

  test('leases restore attempts by wallet signing session', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'sess-lease';
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId,
          walletSigningSessionId: 'wallet-session-lease',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          authMethod: 'passkey',
          ecdsaRestore: ECDSA_RESTORE,
          walletId: 'lease.testnet',
          userId: 'lease.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-lease',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 2,
          updatedAtMs: Date.now(),
        })!);

        const first = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
          ownerId: 'tab-a',
          nowMs: 1_000,
          ttlMs: 5_000,
        });
        const blocked = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
          ownerId: 'tab-b',
          nowMs: 2_000,
          ttlMs: 5_000,
        });
        await mod.releaseSigningSessionRestoreLease(first);
        const afterRelease = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
          ownerId: 'tab-b',
          nowMs: 3_000,
          ttlMs: 5_000,
        });
        const expiredSteal = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
          ownerId: 'tab-c',
          nowMs: 9_000,
          ttlMs: 5_000,
        });
        await mod.clearAllSealedSessions();
        const afterClear = await mod.acquireSigningSessionRestoreLease({
          thresholdSessionId,
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
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
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'transaction-ecdsa-session',
          walletSigningSessionId: 'transaction-wallet-session',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          thresholdSessionIds: {
            ecdsa: 'transaction-ecdsa-session',
            ed25519: 'transaction-ed25519-session',
          },
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          walletId: 'alice.testnet',
          userId: 'alice.testnet',
          signingRootId: 'signing-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-transaction-k',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 7,
          updatedAtMs: Date.now(),
        })!);

        await mod.updateExactSealedSessionPolicy({
          thresholdSessionId: 'export-operation-session',
          filter: {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          },
          expiresAtMs: Date.now() + 10_000,
          remainingUses: 0,
          updatedAtMs: Date.now(),
        });
        await mod.deleteExactSealedSession(
          'link-device-operation-session',
          {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          },
          {
            deleteResolvedIdentity: true,
            resolvedIdentityDeleteReason: 'durable_record_deleted',
          },
        );
        await mod.deleteExactSealedSession(
          'add-signer-operation-session',
          {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          },
          {
            deleteResolvedIdentity: true,
            resolvedIdentityDeleteReason: 'durable_record_deleted',
          },
        );

        return {
          byEcdsa: await mod.readExactSealedSession('transaction-ecdsa-session', {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          }),
          byEd25519: await mod.readExactSealedSession('transaction-ed25519-session', {
            authMethod: 'email_otp',
            curve: 'ed25519',
          }),
          byExport: await mod.readExactSealedSession('export-operation-session', {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          }),
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

  test('owns durable sealed identity by exact signing purpose', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'identity-ecdsa-session',
          walletSigningSessionId: 'identity-wallet-session',
          curve: 'ecdsa',
          subjectId: 'sealed-store-subject',
          thresholdSessionIds: {
            ed25519: 'identity-ed25519-session',
            ecdsa: 'identity-ecdsa-session',
          },
          authMethod: 'email_otp',
          ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
          walletId: 'identity.testnet',
          userId: 'identity.testnet',
          signingRootId: 'identity-root',
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-identity-k',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 7,
          updatedAtMs: 12_345,
        })!);

        const ecdsaAfterWrite = await mod.readExactSealedSession('identity-ecdsa-session', {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        });
        const wrongChainRecord = await mod.readExactSealedSession('identity-ecdsa-session', {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain: 'evm',
          chainTarget: {
            kind: 'evm',
            namespace: 'eip155',
            chainId: 5042002,
            networkSlug: 'arc-testnet',
          },
        });
        const companionEd25519Record = await mod.readExactSealedSession(
          'identity-ed25519-session',
          {
            authMethod: 'email_otp',
            curve: 'ed25519',
          },
        );
        const published = mod.publishResolvedIdentity({
          walletId: 'identity.testnet',
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chainTarget: ECDSA_RESTORE.chainTarget,
          walletSigningSessionId: 'identity-wallet-session',
          thresholdSessionId: 'identity-ecdsa-session',
          updatedAtMs: 22_222,
        });
        await mod.clearAllSealedSessions();
        const ecdsaAfterClear = await mod.readExactSealedSession('identity-ecdsa-session', {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        });

        return {
          ecdsaAfterWrite,
          wrongChainRecord,
          companionEd25519Record,
          published,
          ecdsaAfterClear,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ecdsaAfterWrite?.walletSigningSessionId).toBe('identity-wallet-session');
    expect(result.ecdsaAfterWrite?.thresholdSessionIds.ecdsa).toBe('identity-ecdsa-session');
    expect(result.ecdsaAfterWrite?.updatedAtMs).toBe(12_345);
    expect(result.wrongChainRecord).toBeNull();
    expect(result.companionEd25519Record?.thresholdSessionIds.ed25519).toBe(
      'identity-ed25519-session',
    );
    expect(result.published?.updatedAtMs).toBe(22_222);
    expect(result.ecdsaAfterClear).toBeNull();
  });

  test('can delete durable sealed record through explicit exact-purpose options', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'preserve-identity-ed25519-session',
          walletSigningSessionId: 'preserve-identity-wallet-session',
          curve: 'ed25519',
          thresholdSessionIds: {
            ed25519: 'preserve-identity-ed25519-session',
          },
          authMethod: 'passkey',
          walletId: 'preserve-identity.testnet',
          userId: 'preserve-identity.testnet',
          signingRootId: 'preserve-identity-root',
          ed25519Restore: PASSKEY_ED25519_RESTORE,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-preserve-identity-k',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: 44_444,
        })!);

        await mod.deleteExactSealedSession(
          'preserve-identity-ed25519-session',
          {
            authMethod: 'passkey',
            curve: 'ed25519',
          },
          {
            deleteResolvedIdentity: false,
          },
        );

        const durableRecord = await mod.readExactSealedSession(
          'preserve-identity-ed25519-session',
          {
            authMethod: 'passkey',
            curve: 'ed25519',
          },
        );

        await mod.writeExactSealedSession(mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'preserve-identity-ed25519-session',
          walletSigningSessionId: 'preserve-identity-wallet-session',
          curve: 'ed25519',
          thresholdSessionIds: {
            ed25519: 'preserve-identity-ed25519-session',
          },
          authMethod: 'passkey',
          walletId: 'preserve-identity.testnet',
          userId: 'preserve-identity.testnet',
          signingRootId: 'preserve-identity-root',
          ed25519Restore: PASSKEY_ED25519_RESTORE,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-preserve-identity-k-2',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 1,
          updatedAtMs: 55_555,
        })!);

        await mod.deleteExactSealedSession(
          'preserve-identity-ed25519-session',
          {
            authMethod: 'passkey',
            curve: 'ed25519',
          },
          {
            deleteResolvedIdentity: true,
            resolvedIdentityDeleteReason: 'durable_record_deleted',
          },
        );
        const recordAfterExplicitDelete = await mod.readExactSealedSession(
          'preserve-identity-ed25519-session',
          {
            authMethod: 'passkey',
            curve: 'ed25519',
          },
        );

        return {
          durableRecord,
          recordAfterExplicitDelete,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.durableRecord).toBeNull();
    expect(result.recordAfterExplicitDelete).toBeNull();
  });
});
