import { expect, test } from '@playwright/test';
import { setupBasicPasskeyTest } from '../setup';

const IMPORT_PATHS = {
  indexedDB: '/sdk/esm/core/indexedDB/index.js',
  sealedSessionStore: '/sdk/esm/core/signingEngine/session/persistence/sealedSessionStore.js',
  thresholdWarmSessionBootstrap:
    '/sdk/esm/SeamsWeb/operations/session/thresholdWarmSessionBootstrap.js',
  records: '/sdk/esm/core/signingEngine/session/persistence/records.js',
} as const;

const ECDSA_RESTORE = {
  chainTarget: { kind: 'tempo', chainId: 42431, networkSlug: 'tempo-moderato' },
  evmFamilySigningKeySlotId: 'wallet-key:evm-family:passkey-fixture',
  rpId: 'wallet.example.localhost',
  credentialIdB64u: 'passkey-ecdsa-credential',
  sessionKind: 'cookie',
  keyHandle: 'key-handle-ecdsa',
  ethereumAddress: `0x${'33'.repeat(20)}`,
  relayerKeyId: 'relayer-key',
  thresholdEcdsaPublicKeyB64u: 'threshold-public-key',
  participantIds: [1, 2, 3],
} as const;

const EMAIL_OTP_ECDSA_RESTORE = {
  chainTarget: ECDSA_RESTORE.chainTarget,
  evmFamilySigningKeySlotId: 'wallet-key:evm-family:email-otp-fixture',
  providerSubjectId: 'email-otp-subject',
  authSubjectId: 'email:test@example.com',
  sessionKind: 'cookie',
  keyHandle: ECDSA_RESTORE.keyHandle,
  ethereumAddress: ECDSA_RESTORE.ethereumAddress,
  relayerKeyId: ECDSA_RESTORE.relayerKeyId,
  thresholdEcdsaPublicKeyB64u: ECDSA_RESTORE.thresholdEcdsaPublicKeyB64u,
  participantIds: ECDSA_RESTORE.participantIds,
  walletSessionJwt: 'threshold-session-jwt',
} as const;

const PASSKEY_ED25519_RESTORE = {
  nearAccountId: 'sealed-ed25519.testnet',
  nearEd25519SigningKeyId: 'near-ed25519-sealed-ed25519',
  rpId: 'wallet.example.localhost',
  relayerKeyId: 'relayer-key',
  participantIds: [1, 2, 3],
  sessionKind: 'cookie',
  clientVerifyingShareB64u: 'ed25519-client-verifying-share',
  ed25519WorkerMaterialBindingDigest: 'ed25519-worker-material-binding-digest',
  sealedWorkerMaterialRef: 'sealed-worker-material-ref',
  materialFormatVersion: 'ed25519-worker-material-v1',
  materialKeyId: 'ed25519-material-key-id',
  materialCreatedAtMs: 1_789_000_000_000,
  signerSlot: 1,
} as const;

const EMAIL_OTP_ED25519_RESTORE = {
  ...PASSKEY_ED25519_RESTORE,
  sessionKind: 'jwt',
  walletSessionJwt: 'threshold-session-jwt',
} as const;

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test.describe('signing session sealed store', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
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

  test('resolves reusable passkey Ed25519 worker material for a new login session without nested keyVersion', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const sealedStore = await import(paths.sealedSessionStore);
        const records = await import(paths.records);
        const warmBootstrap = await import(paths.thresholdWarmSessionBootstrap);
        await sealedStore.clearAllSealedSessions();
        records.clearAllStoredThresholdEd25519SessionRecords();

        const issuedAtMs = Date.now();
        const passkeyEd25519Restore = (globalThis as any).PASSKEY_ED25519_RESTORE;
        const base64urlJson = (value: unknown) =>
          btoa(JSON.stringify(value))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/g, '');
        const newEd25519LoginJwt = [
          base64urlJson({ alg: 'none', typ: 'JWT' }),
          base64urlJson({
            kind: 'router_ab_ed25519_wallet_session_v1',
            sub: 'sealed-ed25519-wallet',
            walletId: 'sealed-ed25519-wallet',
            nearAccountId: passkeyEd25519Restore.nearAccountId,
            nearEd25519SigningKeyId: passkeyEd25519Restore.nearEd25519SigningKeyId,
            thresholdSessionId: 'new-ed25519-login-threshold-session',
            signingGrantId: 'new-ed25519-login-signing-grant',
          }),
          'fixture',
        ].join('.');
        const ed25519Restore = {
          ...passkeyEd25519Restore,
          credentialIdB64u: 'passkey-credential-ed25519',
          sessionKind: 'jwt',
          walletSessionJwt: 'old-ed25519-wallet-session-jwt',
        };
        await sealedStore.writeExactSealedSession(
          sealedStore.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'old-ed25519-threshold-session',
            signingGrantId: 'old-ed25519-signing-grant',
            thresholdSessionIds: { ed25519: 'old-ed25519-threshold-session' },
            curve: 'ed25519',
            authMethod: 'passkey',
            walletId: 'sealed-ed25519-wallet',
            userId: 'sealed-ed25519-wallet',
            ed25519Restore,
            relayerUrl: 'https://relay.example',
            signingRootId: 'sr-test:dev',
            signingRootVersion: 'default',
            sealedSecretB64u: 'sealed-ed25519-secret',
            keyVersion: 'signing-session-seal-kek-test-r1',
            expiresAtMs: issuedAtMs + 60_000,
            remainingUses: 3,
            updatedAtMs: issuedAtMs,
          })!,
        );
        const currentRecord = records.upsertStoredThresholdEd25519SessionRecord({
          walletId: 'sealed-ed25519-wallet',
          nearAccountId: passkeyEd25519Restore.nearAccountId,
          nearEd25519SigningKeyId: passkeyEd25519Restore.nearEd25519SigningKeyId,
          rpId: passkeyEd25519Restore.rpId,
          passkeyCredentialIdB64u: ed25519Restore.credentialIdB64u,
          relayerUrl: 'https://relay.example',
          relayerKeyId: passkeyEd25519Restore.relayerKeyId,
          participantIds: [...passkeyEd25519Restore.participantIds],
          signingRootId: 'sr-test:dev',
          signingRootVersion: 'default',
          signerSlot: passkeyEd25519Restore.signerSlot,
          routerAbNormalSigning: {
            kind: 'router_ab_ed25519_normal_signing_v1',
            signingWorkerId: 'signing-worker-local',
          },
          thresholdSessionKind: 'jwt',
          thresholdSessionId: 'new-ed25519-login-threshold-session',
          signingGrantId: 'new-ed25519-login-signing-grant',
          walletSessionJwt: newEd25519LoginJwt,
          expiresAtMs: issuedAtMs + 60_000,
          remainingUses: 3,
          updatedAtMs: issuedAtMs,
          source: 'login',
        });
        if (!currentRecord) throw new Error('expected current Ed25519 login record');

        const resolution =
          await warmBootstrap.resolveReusableEd25519WorkerMaterialForLoginSession(currentRecord);
        if (resolution.kind === 'ready_from_reusable_durable_material') {
          warmBootstrap.persistEd25519LoginSessionFromReusableWorkerMaterial({
            record: currentRecord,
            authority: resolution.authority,
            material: resolution.material,
          });
        }
        const stored = records.getStoredThresholdEd25519SessionRecordByThresholdSessionId(
          'new-ed25519-login-threshold-session',
        );

        return {
          resolutionKind: resolution.kind,
          pendingReason: resolution.kind === 'pending_material' ? resolution.reason : undefined,
          pendingDetails: resolution.kind === 'pending_material' ? resolution.details : undefined,
          materialState: stored?.materialState,
          thresholdSessionId: stored?.thresholdSessionId,
          signingGrantId: stored?.signingGrantId,
          sealedWorkerMaterialRef: stored?.sealedWorkerMaterialRef,
          materialKeyId: stored?.materialKeyId,
          materialBindingDigest: stored?.ed25519WorkerMaterialBindingDigest,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.resolutionKind, JSON.stringify(result)).toBe(
      'ready_from_reusable_durable_material',
    );
    expect(result).toMatchObject({
      resolutionKind: 'ready_from_reusable_durable_material',
      materialState: 'restore_available',
      thresholdSessionId: 'new-ed25519-login-threshold-session',
      signingGrantId: 'new-ed25519-login-signing-grant',
      sealedWorkerMaterialRef: 'sealed-worker-material-ref',
      materialKeyId: 'ed25519-material-key-id',
      materialBindingDigest: 'ed25519-worker-material-binding-digest',
    });
  });

  test('writes shamir3pass records to IndexedDB without persisting plaintext secret or JWT auth', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'sess-sealed-1';
        const signingGrantId = 'wallet-sess-sealed-1';
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId,
            signingGrantId,
            curve: 'ecdsa',
            authMethod: 'passkey',
            ecdsaRestore: ECDSA_RESTORE,
            walletId: 'sealed-store.testnet',
            userId: 'sealed-store.testnet',
            signingRootId: 'signing-root',
            relayerUrl: 'https://relay.example',
            sealedSecretB64u: 'sealed-secret-b64u',
            walletSessionJwt: 'jwt-must-not-persist',
            signingSessionSecretB64u: 'plaintext-k-must-not-persist',
            emailOtpSecretS: 'plaintext-s-must-not-persist',
            enrollmentEscrowB64u: 'enrollment-escrow-must-not-persist',
            keyVersion: 'signing-session-seal-kek-2026-02-r1',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 7,
            updatedAtMs: Date.now(),
          })!,
        );

        const passkeyEcdsa = {
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        };
        const record = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);
        const rawRecord = await new Promise<unknown>((resolve, reject) => {
          const openReq = indexedDB.open('seams_wallet');
          openReq.onsuccess = () => {
            const db = openReq.result;
            const tx = db.transaction('signing_session_seals', 'readonly');
            const getReq = tx.objectStore('signing_session_seals').get(record?.storeKey);
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
          recordHasTopLevelSigningRoot:
            !!record &&
            (Object.prototype.hasOwnProperty.call(record, 'signingRootId') ||
              Object.prototype.hasOwnProperty.call(record, 'signingRootVersion')),
          rawHasTopLevelSigningRoot:
            !!rawRecord &&
            typeof rawRecord === 'object' &&
            (Object.prototype.hasOwnProperty.call(rawRecord, 'signingRootId') ||
              Object.prototype.hasOwnProperty.call(rawRecord, 'signingRootVersion')),
          rawHasPlaintextSecret:
            !!record &&
            (Object.prototype.hasOwnProperty.call(record, 'prfFirstB64u') ||
              Object.prototype.hasOwnProperty.call(record, 'signingSessionSecretB64u') ||
              Object.prototype.hasOwnProperty.call(record, 'secretSourceB64u')),
          rawHasThresholdSessionAuthToken:
            !!record && Object.prototype.hasOwnProperty.call(record, 'walletSessionJwt'),
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
    expect(result.record?.keyVersion).toBe('signing-session-seal-kek-2026-02-r1');
    expect(result.record?.thresholdSessionIds.ecdsa).toBe('sess-sealed-1');
    expect(result.recordHasTopLevelSigningRoot).toBe(false);
    expect(result.rawHasTopLevelSigningRoot).toBe(false);
    expect(result.sessionRaw).toBeNull();
    expect(result.sessionIndex).toBeNull();
    expect(result.rawHasPlaintextSecret).toBe(false);
    expect(result.rawHasThresholdSessionAuthToken).toBe(false);
    expect(result.rawHasPlaintextK).toBe(false);
    expect(result.rawHasPlaintextS).toBe(false);
    expect(result.rawHasEnrollmentEscrow).toBe(false);
    expect(result.rawHasJwt).toBe(false);
  });

  test('accepts Router A/B ECDSA-HSS Wallet Session JWTs in passkey sealed restore records', async ({
    page,
  }) => {
    const walletId = 'sealed-store-router-ab.testnet';
    const walletSessionJwt = jwtWithPayload({
      kind: 'router_ab_ecdsa_hss_wallet_session_v1',
      sub: walletId,
      walletId,
      thresholdSessionId: 'router-ab-ecdsa-session',
      signingGrantId: 'router-ab-wallet-session',
      keyScope: 'evm-family',
      keyHandle: ECDSA_RESTORE.keyHandle,
      relayerKeyId: ECDSA_RESTORE.relayerKeyId,
      rpId: ECDSA_RESTORE.rpId,
      thresholdExpiresAtMs: Date.now() + 60_000,
      participantIds: ECDSA_RESTORE.participantIds,
    });

    const result = await page.evaluate(
      async ({ paths, walletId, walletSessionJwt }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();
        const record = mod.buildCurrentSealedSessionRecord({
          thresholdSessionId: 'router-ab-ecdsa-session',
          signingGrantId: 'router-ab-wallet-session',
          curve: 'ecdsa',
          authMethod: 'passkey',
          ecdsaRestore: {
            ...ECDSA_RESTORE,
            sessionKind: 'jwt',
            walletSessionJwt,
          },
          walletId,
          userId: walletId,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-secret-b64u',
          keyVersion: 'signing-session-seal-kek-2026-02-r1',
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 3,
          updatedAtMs: Date.now(),
        });
        if (record) {
          await mod.writeExactSealedSession(record);
        }
        return {
          built: Boolean(record),
          persisted: Boolean(
            await mod.readExactSealedSession('router-ab-ecdsa-session', {
              authMethod: 'passkey',
              curve: 'ecdsa',
              chain: 'tempo',
              chainTarget: ECDSA_RESTORE.chainTarget,
            }),
          ),
        };
      },
      { paths: IMPORT_PATHS, walletId, walletSessionJwt },
    );

    expect(result).toEqual({ built: true, persisted: true });
  });

  test('fails closed on malformed plaintext record payloads', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'sess-plaintext-record';
        await mod.clearAllSealedSessions();
        const db = await new Promise<IDBDatabase>((resolve, reject) => {
          const req = indexedDB.open('seams_wallet');
          req.onupgradeneeded = () => {
            if (!req.result.objectStoreNames.contains('signing_session_seals')) {
              req.result.createObjectStore('signing_session_seals', {
                keyPath: 'store_key',
              });
            }
          };
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const tx = db.transaction('signing_session_seals', 'readwrite');
        tx.objectStore('signing_session_seals').put({
          store_key: `plaintext:${thresholdSessionId}:passkey:ecdsa`,
          v: 1,
          alg: 'plain-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: sessionStorage.getItem(
            'seams:signing-session-sealed:runtime-session-id:v1',
          ),
          authMethod: 'passkey',
          secretKind: 'signing_session_secret32',
          storeKey: `plaintext:${thresholdSessionId}:passkey:ecdsa`,
          signingGrantId: thresholdSessionId,
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

        const passkeyEcdsa = {
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        };
        const read = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);
        await mod.deleteExactSealedSession(thresholdSessionId, passkeyEcdsa, {
          deleteResolvedIdentity: true,
          resolvedIdentityDeleteReason: 'durable_record_deleted',
        });
        const afterDelete = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);

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

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'chain-only-session',
            signingGrantId: 'chain-only-wallet-session',
            curve: 'ecdsa',
            authMethod: 'email_otp',
            ecdsaRestore: {
              chain: 'evm',
              sessionKind: 'jwt',
              keyHandle: 'key-handle-ecdsa',
              ecdsaThresholdKeyId: 'chain-only-ecdsa-key',
              relayerKeyId: 'chain-only-relayer-key',
              participantIds: [1, 2],
            },
            sealedSecretB64u: 'sealed-chain-only',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 1,
            updatedAtMs: Date.now(),
          })!,
        );

        return await mod.readExactSealedSession('chain-only-session', {
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
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'email-otp-ecdsa-session',
            signingGrantId: 'email-otp-wallet-session',
            curve: 'ecdsa',
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
            keyVersion: 'signing-session-seal-kek-test-r1',
            shamirPrimeB64u: 'prime-b64u',
            sealedSecretB64u: 'sealed-email-otp-k',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 2,
            updatedAtMs: Date.now(),
          })!,
        );
        const emailOtpEcdsa = {
          authMethod: 'email_otp',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        };
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
          const req = indexedDB.open('seams_wallet');
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        const tx = db.transaction('signing_session_seals', 'readwrite');
        tx.objectStore('signing_session_seals').put({
          store_key: 'bad-email-otp-wallet-session:email_otp:ecdsa',
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: sessionStorage.getItem(
            'seams:signing-session-sealed:runtime-session-id:v1',
          ),
          authMethod: 'email_otp',
          secretKind: 'enrollment_secret_s',
          storeKey: 'bad-email-otp-wallet-session:email_otp:ecdsa',
          signingGrantId: 'bad-email-otp-wallet-session',
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
      signingGrantId: 'email-otp-wallet-session',
      thresholdSessionIds: {
        ecdsa: 'email-otp-ecdsa-session',
        ed25519: 'email-otp-ed25519-session',
      },
      walletId: 'alice.testnet',
    });
    expect(result.validByEd25519?.signingGrantId).toBe('email-otp-wallet-session');
    expect(result.malformed).toBeNull();
  });

  test('filters colliding passkey and Email OTP sealed records by auth method and curve', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'shared-threshold-session';
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId,
            signingGrantId: 'passkey-wallet-session',
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
          })!,
        );
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId,
            signingGrantId: 'email-otp-wallet-session',
            thresholdSessionIds: { ecdsa: thresholdSessionId },
            curve: 'ecdsa',
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
          })!,
        );

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
    expect(result.emailOtp?.signingGrantId).toBe('email-otp-wallet-session');
    expect(result.passkey?.signingGrantId).toBe('passkey-wallet-session');
    expect(result.emailLease?.signingGrantId).toBe('email-otp-wallet-session');
    expect(result.emailAfterDelete).toBeNull();
    expect(result.passkeyAfterDelete?.signingGrantId).toBe('passkey-wallet-session');
  });

  test('keeps passkey Ed25519 signing-session seals with worker-material metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'passkey-ed25519-prf-only-session';
        const signingGrantId = 'passkey-ed25519-prf-only-wallet-session';
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId,
            signingGrantId,
            thresholdSessionIds: { ed25519: thresholdSessionId },
            curve: 'ed25519',
            authMethod: 'passkey',
            walletId: 'passkey-ed25519-prf-only.testnet',
            userId: 'passkey-ed25519-prf-only.testnet',
            ed25519Restore: PASSKEY_ED25519_RESTORE,
            relayerUrl: 'https://relay.example',
            sealedSecretB64u: 'sealed-passkey-prf-first',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 5,
            updatedAtMs: Date.now(),
          })!,
        );

        return await mod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'passkey',
          curve: 'ed25519',
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(result?.sealedSecretB64u).toBe('sealed-passkey-prf-first');
    expect(result?.ed25519Restore?.xClientBaseB64u).toBeUndefined();
    expect(result?.ed25519Restore?.sealedWorkerMaterialRef).toBe('sealed-worker-material-ref');
  });

  test('rejects passkey Ed25519 signing-session seals without worker-material metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const walletId = 'passkey-ed25519-incomplete.testnet';
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'complete-ed25519-session',
            signingGrantId: 'complete-ed25519-wallet-session',
            thresholdSessionIds: { ed25519: 'complete-ed25519-session' },
            curve: 'ed25519',
            authMethod: 'passkey',
            walletId,
            userId: walletId,
            ed25519Restore: PASSKEY_ED25519_RESTORE,
            relayerUrl: 'https://relay.example',
            sealedSecretB64u: 'sealed-complete-ed25519',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 5,
            updatedAtMs: Date.now() - 1_000,
          })!,
        );
        const incompleteRestore = {
          rpId: PASSKEY_ED25519_RESTORE.rpId,
          relayerKeyId: PASSKEY_ED25519_RESTORE.relayerKeyId,
          participantIds: PASSKEY_ED25519_RESTORE.participantIds,
          sessionKind: PASSKEY_ED25519_RESTORE.sessionKind,
          signerSlot: PASSKEY_ED25519_RESTORE.signerSlot,
        };
        const incompleteRawRecord = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          authMethod: 'passkey',
          secretKind: 'signing_session_secret32',
          signingGrantId: 'incomplete-ed25519-wallet-session',
          thresholdSessionIds: { ed25519: 'incomplete-ed25519-session' },
          curve: 'ed25519',
          walletId,
          userId: walletId,
          ed25519Restore: incompleteRestore,
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-incomplete-ed25519',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 5,
          updatedAtMs: Date.now(),
        };
        const classification = mod.classifyRawSealedSessionRecord(incompleteRawRecord);
        const built = mod.buildCurrentSealedSessionRecord(incompleteRawRecord);
        if (built) {
          await mod.writeExactSealedSession(built);
        }
        const completeAfterRejectedWrite = await mod.readExactSealedSession(
          'complete-ed25519-session',
          {
            authMethod: 'passkey',
            curve: 'ed25519',
          },
        );
        const incompleteAfterRejectedWrite = await mod.readExactSealedSession(
          'incomplete-ed25519-session',
          {
            authMethod: 'passkey',
            curve: 'ed25519',
          },
        );

        return {
          classification,
          built,
          completeAfterRejectedWrite,
          incompleteAfterRejectedWrite,
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.classification).toMatchObject({
      kind: 'rebuild_required',
      reason: 'missing_restore_metadata',
      safeSummary: {
        ed25519WorkerMaterialMissingFields: [
          'nearAccountId',
          'nearEd25519SigningKeyId',
          'clientVerifyingShareB64u',
          'ed25519WorkerMaterialBindingDigest',
          'sealedWorkerMaterialRef',
          'materialFormatVersion',
          'materialKeyId',
          'materialCreatedAtMs',
        ],
      },
    });
    expect(result.built).toBeNull();
    expect(result.completeAfterRejectedWrite?.sealedSecretB64u).toBe('sealed-complete-ed25519');
    expect(result.incompleteAfterRejectedWrite).toBeNull();
  });

  test('rejects passkey Ed25519 signing-session seals with raw client-base metadata', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const rawRecord = {
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          authMethod: 'passkey',
          secretKind: 'signing_session_secret32',
          storeKey: 'passkey-ed25519-raw-wallet-session:passkey:ed25519',
          signingGrantId: 'passkey-ed25519-raw-wallet-session',
          thresholdSessionIds: { ed25519: 'passkey-ed25519-raw-session' },
          curve: 'ed25519',
          walletId: 'passkey-ed25519-raw.testnet',
          userId: 'passkey-ed25519-raw.testnet',
          ed25519Restore: {
            ...PASSKEY_ED25519_RESTORE,
            xClientBaseB64u: 'stale-x-client-base',
            clientVerifyingShareB64u: 'stale-client-verifying-share',
          },
          relayerUrl: 'https://relay.example',
          sealedSecretB64u: 'sealed-passkey-prf-first',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 60_000,
          remainingUses: 5,
          updatedAtMs: Date.now(),
        };

        return {
          classification: mod.classifyRawSealedSessionRecord(rawRecord),
          built: mod.buildCurrentSealedSessionRecord(rawRecord),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.classification).toMatchObject({
      kind: 'delete_required',
      reason: 'missing_restore_metadata',
    });
    expect(result.built).toBeNull();
  });

  test('lists durable sealed records for an account by auth method and curve', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'email-otp-ecdsa-session',
            signingGrantId: 'email-otp-wallet-session',
            thresholdSessionIds: { ecdsa: 'email-otp-ecdsa-session' },
            curve: 'ecdsa',
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
          })!,
        );
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'email-otp-ed25519-session',
            signingGrantId: 'email-otp-ed25519-wallet-session',
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
          })!,
        );
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'passkey-ecdsa-session',
            signingGrantId: 'passkey-wallet-session',
            thresholdSessionIds: { ecdsa: 'passkey-ecdsa-session' },
            curve: 'ecdsa',
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
          })!,
        );
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'bob-email-otp-ecdsa-session',
            signingGrantId: 'bob-email-otp-wallet-session',
            thresholdSessionIds: { ecdsa: 'bob-email-otp-ecdsa-session' },
            curve: 'ecdsa',
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
          })!,
        );

        const records = await mod.listExactSealedSessionsForWallet({
          walletId: 'alice.testnet',
          filter: {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          },
        });

        return {
          records,
          signingGrantIds: records.map((record: any) => record.signingGrantId),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.records).toHaveLength(1);
    expect(result.signingGrantIds).toEqual(['email-otp-wallet-session']);
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

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'old-email-otp-ed25519-session',
            signingGrantId: 'old-email-otp-ed25519-wallet-session',
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
          })!,
        );
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'new-email-otp-ed25519-session',
            signingGrantId: 'new-email-otp-ed25519-wallet-session',
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
          })!,
        );

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'old-email-otp-ecdsa-session',
            signingGrantId: 'old-email-otp-ecdsa-wallet-session',
            thresholdSessionIds: { ecdsa: 'old-email-otp-ecdsa-session' },
            curve: 'ecdsa',
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
          })!,
        );
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'new-email-otp-ecdsa-session',
            signingGrantId: 'new-email-otp-ecdsa-wallet-session',
            thresholdSessionIds: { ecdsa: 'new-email-otp-ecdsa-session' },
            curve: 'ecdsa',
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
          })!,
        );

        const ed25519Records = await mod.listExactSealedSessionsForWallet({
          walletId: 'alice.testnet',
          filter: { authMethod: 'email_otp', curve: 'ed25519' },
        });
        const ecdsaRecords = await mod.listExactSealedSessionsForWallet({
          walletId: 'alice.testnet',
          filter: {
            authMethod: 'email_otp',
            curve: 'ecdsa',
            chain: ECDSA_RESTORE.chain,
            chainTarget: ECDSA_RESTORE.chainTarget,
          },
        });

        return {
          ed25519WalletSessionIds: ed25519Records.map((record: any) => record.signingGrantId),
          ecdsaWalletSessionIds: ecdsaRecords.map((record: any) => record.signingGrantId),
        };
      },
      { paths: IMPORT_PATHS },
    );

    expect(result.ed25519WalletSessionIds).toEqual(['new-email-otp-ed25519-wallet-session']);
    expect(result.ecdsaWalletSessionIds).toEqual(['new-email-otp-ecdsa-wallet-session']);
  });

  test('keeps passkey and Email OTP sealed records with the same signing grant separate', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const sharedSigningGrantId = 'shared-signing-grant';
        const sharedEd25519SessionId = 'shared-ed25519-threshold-session';
        const emailOtpEcdsaSessionId = 'email-otp-ecdsa-threshold-session';
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: sharedEd25519SessionId,
            signingGrantId: sharedSigningGrantId,
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
          })!,
        );
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: emailOtpEcdsaSessionId,
            signingGrantId: sharedSigningGrantId,
            thresholdSessionIds: {
              ed25519: sharedEd25519SessionId,
              ecdsa: emailOtpEcdsaSessionId,
            },
            curve: 'ecdsa',
            authMethod: 'email_otp',
            ecdsaRestore: EMAIL_OTP_ECDSA_RESTORE,
            walletId: 'alice.testnet',
            signingRootId: 'signing-root',
            relayerUrl: 'https://relay.example',
            sealedSecretB64u: 'sealed-email-otp-ecdsa',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 4,
            updatedAtMs: Date.now(),
          })!,
        );

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
    expect(result.passkeyEd25519?.storeKey).toBe('shared-signing-grant:passkey:ed25519');
    expect(result.emailOtpEd25519?.sealedSecretB64u).toBe('sealed-email-otp-ecdsa');
    expect(result.emailOtpEcdsa?.sealedSecretB64u).toBe('sealed-email-otp-ecdsa');
    expect(result.emailOtpEcdsa?.storeKey).toBe(
      'shared-signing-grant:email_otp:ecdsa:tempo%3A42431',
    );
  });

  test('clearAll removes all IndexedDB sealed records', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'sess-a',
            signingGrantId: 'wallet-sess-a',
            curve: 'ecdsa',
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
          })!,
        );
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'sess-b',
            signingGrantId: 'wallet-sess-b',
            curve: 'ecdsa',
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
          })!,
        );
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
          await mod.writeExactSealedSession(
            mod.buildCurrentSealedSessionRecord({
              thresholdSessionId,
              signingGrantId: 'wallet-sess-host-mode',
              curve: 'ecdsa',
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
            })!,
          );
          const record = await mod.readExactSealedSession(thresholdSessionId, {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          });
          return {
            record,
            localRaw: localStorage.getItem(`seams:signing-session-sealed:v1:${thresholdSessionId}`),
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

  test('does not create seams_wallet when IndexedDB persistence is disabled', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        await new Promise<void>((resolve) => {
          const req = indexedDB.deleteDatabase('seams_wallet');
          req.onsuccess = () => resolve();
          req.onerror = () => resolve();
          req.onblocked = () => resolve();
        });
        const indexedDbMod = await import(paths.indexedDB);
        indexedDbMod.configureIndexedDB({ mode: 'disabled' });
        const mod = await import(paths.sealedSessionStore);
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'sess-disabled-mode',
            signingGrantId: 'wallet-sess-disabled-mode',
            curve: 'ecdsa',
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
          })!,
        );
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
    expect(result.databaseNames).not.toContain('seams_wallet');
  });

  test('reads IndexedDB record when browser-session marker is missing', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'sess-browser-restart';
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId,
            signingGrantId: 'wallet-sess-browser-restart',
            curve: 'ecdsa',
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
          })!,
        );
        const passkeyEcdsa = {
          authMethod: 'passkey',
          curve: 'ecdsa',
          chain: 'tempo',
          chainTarget: ECDSA_RESTORE.chainTarget,
        };
        const before = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);
        sessionStorage.removeItem('seams:signing-session-sealed:runtime-session-id:v1');
        const after = await mod.readExactSealedSession(thresholdSessionId, passkeyEcdsa);
        const exactAfterMarkerRemoved = await mod.listExactSealedSessionsForWallet({
          walletId: 'restart.testnet',
          filter: {
            authMethod: 'passkey',
            curve: 'ecdsa',
            chain: 'tempo',
            chainTarget: ECDSA_RESTORE.chainTarget,
          },
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

  test('leases restore attempts by signing grant', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        const thresholdSessionId = 'sess-lease';
        await mod.clearAllSealedSessions();
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId,
            signingGrantId: 'wallet-session-lease',
            curve: 'ecdsa',
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
          })!,
        );

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
    expect(result.first?.signingGrantId).toBe('wallet-session-lease');
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
        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'transaction-ecdsa-session',
            signingGrantId: 'transaction-wallet-session',
            curve: 'ecdsa',
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
          })!,
        );

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

    expect(result.byEcdsa?.signingGrantId).toBe('transaction-wallet-session');
    expect(result.byEcdsa?.sealedSecretB64u).toBe('sealed-transaction-k');
    expect(result.byEcdsa?.remainingUses).toBe(7);
    expect(result.byEd25519?.signingGrantId).toBe('transaction-wallet-session');
    expect(result.byExport).toBeNull();
  });

  test('owns durable sealed identity by exact signing purpose', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'identity-ecdsa-session',
            signingGrantId: 'identity-wallet-session',
            curve: 'ecdsa',
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
          })!,
        );

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
          signingGrantId: 'identity-wallet-session',
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

    expect(result.ecdsaAfterWrite?.signingGrantId).toBe('identity-wallet-session');
    expect(result.ecdsaAfterWrite?.thresholdSessionIds.ecdsa).toBe('identity-ecdsa-session');
    expect(result.ecdsaAfterWrite?.updatedAtMs).toBe(12_345);
    expect(result.wrongChainRecord).toBeNull();
    expect(result.companionEd25519Record?.thresholdSessionIds.ed25519).toBe(
      'identity-ed25519-session',
    );
    expect(result.published?.updatedAtMs).toBe(22_222);
    expect(result.ecdsaAfterClear).toBeNull();
  });

  test('persists split NEAR Ed25519 sealed session identity', async ({ page }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        const walletId = 'frost-vermillion-k7p9m2';
        const nearAccountId =
          '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
        const nearEd25519SigningKeyId = 'near-ed25519-frost-vermillion-k7p9m2';
        const thresholdSessionId = 'split-ed25519-sealed-session';

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId,
            signingGrantId: 'split-ed25519-wallet-session',
            curve: 'ed25519',
            thresholdSessionIds: { ed25519: thresholdSessionId },
            authMethod: 'passkey',
            walletId,
            userId: walletId,
            signingRootId: 'split-ed25519-root',
            ed25519Restore: {
              ...PASSKEY_ED25519_RESTORE,
              nearAccountId,
              nearEd25519SigningKeyId,
            },
            relayerUrl: 'https://relay.example',
            sealedSecretB64u: 'sealed-split-ed25519',
            expiresAtMs: Date.now() + 60_000,
            remainingUses: 5,
            updatedAtMs: 33_333,
          })!,
        );

        return await mod.readExactSealedSession(thresholdSessionId, {
          authMethod: 'passkey',
          curve: 'ed25519',
        });
      },
      { paths: IMPORT_PATHS },
    );

    expect(result?.walletId).toBe('frost-vermillion-k7p9m2');
    expect(result?.ed25519Restore?.nearAccountId).toBe(
      '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef',
    );
    expect(result?.ed25519Restore?.nearEd25519SigningKeyId).toBe(
      'near-ed25519-frost-vermillion-k7p9m2',
    );
    expect(result?.updatedAtMs).toBe(33_333);
  });

  test('can delete durable sealed record through explicit exact-purpose options', async ({
    page,
  }) => {
    const result = await page.evaluate(
      async ({ paths }) => {
        const mod = await import(paths.sealedSessionStore);
        await mod.clearAllSealedSessions();

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'preserve-identity-ed25519-session',
            signingGrantId: 'preserve-identity-wallet-session',
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
          })!,
        );

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

        await mod.writeExactSealedSession(
          mod.buildCurrentSealedSessionRecord({
            thresholdSessionId: 'preserve-identity-ed25519-session',
            signingGrantId: 'preserve-identity-wallet-session',
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
          })!,
        );

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
