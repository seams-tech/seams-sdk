import { expect, test } from '@playwright/test';
import { sdkEsmPath, setupBasicPasskeyTest } from '../setup';
import {
  buildPendingWalletRecoveryCommitV1,
  parsePendingWalletRecoveryCommitAppStateRow,
  parsePendingWalletRecoveryCommitV1,
  toPendingWalletRecoveryCommitAppStateRow,
} from '../../packages/wallet/src/core/indexedDB/pendingWalletRecoveryCommit';
import {
  buildWalletRecoveryCommittedProjectionV1,
  type WalletRecoveryCommittedProjectionV1,
} from '../../packages/shared-ts/src/wallet-recovery/walletRecoveryCommittedProjection';
import { buildFullOwnerDelegatedWalletAuthorityV1 } from '../../packages/shared-ts/src/authorization/delegatedAuthority';
import { buildWalletAuthMethodRecordV2 } from '../../packages/shared-ts/src/utils/registrationIntent';
import { parseEmailOtpProviderUserId } from '../../packages/shared-ts/src/utils/domainIds';
import { base64UrlDecode } from '../../packages/shared-ts/src/utils/base64';
import { buildLinkedDeviceManagementAuthorityFixture } from './helpers/linkedDeviceManagement.fixtures';

const IMPORT_PATHS = {
  indexedDB: sdkEsmPath('core/indexedDB/index.js'),
  pending: sdkEsmPath('core/indexedDB/pendingWalletRecoveryCommit.js'),
} as const;

function required<T>(result: { readonly ok: true; readonly value: T } | { readonly ok: false }): T {
  if (!result.ok) throw new Error('invalid recovery fixture identity');
  return result.value;
}

async function encryptedMaterial(fill: number) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  if (!(key instanceof CryptoKey)) throw new Error('recovery fixture key was not generated');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([fill])),
  );
  return {
    kind: 'wallet_recovery_encrypted_material_v1' as const,
    key,
    iv,
    ciphertext,
  };
}

async function passkeyProjectionFixture(): Promise<{
  readonly authority: Awaited<
    ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>
  >['authority'];
  readonly projection: Extract<WalletRecoveryCommittedProjectionV1, { readonly kind: 'passkey' }>;
}> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'pending-recovery-passkey',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_recovery',
    identity: {
      walletId: 'wallet:pending-recovery-passkey',
      authorityId: 'authority:pending-recovery-passkey',
      walletAuthMethodId: 'auth-method:pending-recovery-passkey',
      rpId: 'wallet.pending-recovery.example',
      credentialIdB64u: 'Y3JlZGVudGlhbC1wZW5kaW5nLXJlY292ZXJ5',
    },
  });
  if (fixture.authority.provenance.kind !== 'wallet_recovery') {
    throw new Error('Passkey recovery fixture lost recovery provenance');
  }
  const projection = buildWalletRecoveryCommittedProjectionV1({
    kind: 'passkey',
    storeVersion: 'store-pending-recovery-passkey',
    walletId: fixture.authority.walletId,
    recoveryOperationId: fixture.authority.provenance.recoveryOperationId,
    targetDeviceId: fixture.authority.principal.deviceId,
    targetAuthorityId: fixture.authority.authorityId,
    targetWalletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    authority: fixture.authority,
    authMethod: fixture.authMethod,
  });
  return { authority: fixture.authority, projection };
}

async function emailProjectionFixture(): Promise<{
  readonly authority: Awaited<
    ReturnType<typeof buildLinkedDeviceManagementAuthorityFixture>
  >['authority'];
  readonly projection: Extract<
    WalletRecoveryCommittedProjectionV1,
    { readonly kind: 'google_email_otp' }
  >;
}> {
  const fixture = await buildLinkedDeviceManagementAuthorityFixture({
    label: 'pending-recovery-email',
    permissions: buildFullOwnerDelegatedWalletAuthorityV1().permissions,
    provenance: 'wallet_recovery',
    identity: {
      walletId: 'wallet:pending-recovery-email',
      authorityId: 'authority:pending-recovery-email',
      walletAuthMethodId: 'auth-method:pending-recovery-email',
      rpId: 'wallet.pending-recovery.example',
    },
  });
  if (fixture.authority.provenance.kind !== 'wallet_recovery') {
    throw new Error('Email OTP recovery fixture lost recovery provenance');
  }
  const authMethod = buildWalletAuthMethodRecordV2({
    version: 'wallet_auth_method_v2',
    walletAuthMethodId: fixture.authMethod.walletAuthMethodId,
    walletId: fixture.authority.walletId,
    walletAuthorityId: fixture.authority.authorityId,
    kind: 'email_otp',
    status: 'active',
    emailHashHex: 'c'.repeat(64),
    registrationAuthorityId: 'challenge:pending-recovery-email',
    createdAtMs: fixture.authMethod.createdAtMs,
    updatedAtMs: fixture.authMethod.updatedAtMs,
    activatedAtMs: fixture.authMethod.activatedAtMs,
  });
  const projection = buildWalletRecoveryCommittedProjectionV1({
    kind: 'google_email_otp',
    storeVersion: 'store-pending-recovery-email',
    walletId: fixture.authority.walletId,
    recoveryOperationId: fixture.authority.provenance.recoveryOperationId,
    targetDeviceId: fixture.authority.principal.deviceId,
    targetAuthorityId: fixture.authority.authorityId,
    targetWalletAuthMethodId: authMethod.walletAuthMethodId,
    authority: fixture.authority,
    authMethod,
    providerSubject: required(parseEmailOtpProviderUserId('google:pending-recovery-email')),
    emailHashHex: authMethod.emailHashHex,
    registrationAuthorityId: authMethod.registrationAuthorityId,
    enrollment: {
      kind: 'email_otp_enrollment_reference_v1',
      enrollmentId: 'enrollment:pending-recovery-email',
      enrollmentSealKeyVersion: 'email-otp-seal-v1',
    },
  });
  return { authority: fixture.authority, projection };
}

async function buildPendingRecord(projection: WalletRecoveryCommittedProjectionV1, fill: number) {
  const localMaterial = await encryptedMaterial(fill);
  if (projection.kind === 'passkey') {
    return await buildPendingWalletRecoveryCommitV1({
      kind: 'pending_wallet_recovery_commit_v1',
      version: 1,
      stage: 'server_promoted',
      recoveryOperationId: projection.recoveryOperationId,
      walletId: projection.walletId,
      reservationId: `reservation:pending-recovery-${fill}`,
      targetDeviceId: projection.targetDeviceId,
      targetAuthorityId: projection.targetAuthorityId,
      targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
      target: {
        kind: 'passkey',
        rpId: projection.target.rpId,
        credentialIdB64u: projection.target.credentialIdB64u,
      },
      localMaterial,
      createdAtMs: 1,
      updatedAtMs: 2,
      projection,
    });
  }
  return await buildPendingWalletRecoveryCommitV1({
    kind: 'pending_wallet_recovery_commit_v1',
    version: 1,
    stage: 'server_promoted',
    recoveryOperationId: projection.recoveryOperationId,
    walletId: projection.walletId,
    reservationId: `reservation:pending-recovery-${fill}`,
    targetDeviceId: projection.targetDeviceId,
    targetAuthorityId: projection.targetAuthorityId,
    targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
    target: {
      kind: 'google_email_otp',
      providerSubject: projection.target.providerSubject,
      emailHashHex: projection.target.emailHashHex,
      registrationAuthorityId: projection.target.registrationAuthorityId,
      enrollment: projection.target.enrollment,
    },
    localMaterial,
    createdAtMs: 1,
    updatedAtMs: 2,
    projection,
  });
}

test('persists strict encrypted pending records for Passkey and Google Email OTP', async () => {
  const passkey = await passkeyProjectionFixture();
  const email = await emailProjectionFixture();
  const passkeyPending = await buildPendingRecord(passkey.projection, 1);
  const emailPending = await buildPendingRecord(email.projection, 2);

  for (const pending of [passkeyPending, emailPending]) {
    const row = await toPendingWalletRecoveryCommitAppStateRow(pending);
    const parsedRow = await parsePendingWalletRecoveryCommitAppStateRow(row);
    expect(parsedRow?.record.stage).toBe('server_promoted');
    expect(parsedRow?.record.target.kind).toBe(pending.target.kind);
    expect(parsedRow?.record.projection?.kind).toBe(pending.projection?.kind);
    expect(JSON.stringify(row)).not.toContain('factorSecret');
    expect(JSON.stringify(row)).not.toContain('operationCredential');
  }

  const rawWithSecret = {
    ...passkeyPending,
    factorSecret: 'raw-secret-must-be-rejected',
  };
  await expect(parsePendingWalletRecoveryCommitV1(rawWithSecret)).resolves.toBeNull();

  const mismatchedBranches = {
    ...emailPending,
    target: passkeyPending.target,
  };
  await expect(parsePendingWalletRecoveryCommitV1(mismatchedBranches)).resolves.toBeNull();
});

test.describe('atomic pending recovery publication', () => {
  test.beforeEach(async ({ page }) => {
    await setupBasicPasskeyTest(page, { skipSeamsWebInit: true });
  });

  test('consumes the exact Passkey pending row while publishing local projections atomically', async ({
    page,
  }) => {
    const fixture = await passkeyProjectionFixture();
    const credentialPublicKey = base64UrlDecode(
      fixture.projection.authMethod.credentialPublicKeyB64u,
    );
    const result = await page.evaluate(
      async ({ paths, authority, projection, credentialPublicKey }) => {
        const { UnifiedIndexedDBManager, SeamsWalletDBManager, createSeamsTestWalletDbName } =
          await import(paths.indexedDB);
        const dbManager = new SeamsWalletDBManager();
        dbManager.setDbName(createSeamsTestWalletDbName(`pending-recovery-${crypto.randomUUID()}`));
        const db = new UnifiedIndexedDBManager({ seamsWalletDB: dbManager });
        const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
          'encrypt',
          'decrypt',
        ]);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = new Uint8Array(
          await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new Uint8Array([7])),
        );
        const { buildPendingWalletRecoveryCommitV1 } = await import(paths.pending);
        const record = await buildPendingWalletRecoveryCommitV1({
          kind: 'pending_wallet_recovery_commit_v1',
          version: 1,
          stage: 'server_promoted',
          recoveryOperationId: projection.recoveryOperationId,
          walletId: projection.walletId,
          reservationId: 'reservation:pending-recovery-atomic',
          targetDeviceId: projection.targetDeviceId,
          targetAuthorityId: projection.targetAuthorityId,
          targetWalletAuthMethodId: projection.targetWalletAuthMethodId,
          target: {
            kind: 'passkey',
            rpId: projection.target.rpId,
            credentialIdB64u: projection.target.credentialIdB64u,
          },
          localMaterial: {
            kind: 'wallet_recovery_encrypted_material_v1',
            key,
            iv,
            ciphertext,
          },
          createdAtMs: 1,
          updatedAtMs: 2,
          projection,
        });
        await db.putPendingWalletRecoveryCommit(record);
        const initialAuthMethod = {
          version: 'wallet_auth_method_v1',
          kind: 'passkey',
          status: 'active',
          localStatus: 'synced',
          walletId: projection.walletId,
          rpId: projection.target.rpId,
          credentialIdB64u: projection.target.credentialIdB64u,
          credentialPublicKeyB64u: projection.authMethod.credentialPublicKeyB64u,
          counter: projection.authMethod.counter,
          createdAtMs: projection.authMethod.createdAtMs,
          updatedAtMs: projection.authMethod.updatedAtMs,
        };
        const published = await db.publishPendingWalletRecoveryCommit({
          pending: record,
          authority,
          authMethod: projection.authMethod,
          registration: {
            profiles: [
              {
                profileId: projection.walletId,
                defaultSignerSlot: 1,
                passkeyCredential: {
                  id: projection.target.credentialIdB64u,
                  rawId: projection.target.credentialIdB64u,
                },
              },
            ],
            initialAuthMethod,
            authenticators: [
              {
                profileId: projection.walletId,
                signerSlot: 1,
                credentialId: projection.target.credentialIdB64u,
                credentialPublicKey,
                registered: new Date(1).toISOString(),
                syncedAt: new Date(2).toISOString(),
              },
            ],
            signerActivations: [],
            keyMaterials: [],
            lastProfileState: {
              profileId: projection.walletId,
              activeSignerSlot: 1,
              scope: null,
            },
          },
        });
        const profile = await db.getProfile(projection.walletId);
        const storedAuthMethod = await db.getWalletAuthMethodV2(
          projection.targetWalletAuthMethodId,
        );
        const storedAuthority = await db.getWalletAuthority(projection.targetAuthorityId);
        const selections = await db.listWalletSelections();
        return {
          signerActivationCount: published.signerActivations.length,
          pendingRemaining:
            (await db.getPendingWalletRecoveryCommit(projection.recoveryOperationId)) !== null,
          profileId: profile?.profileId ?? null,
          authMethodId: storedAuthMethod?.walletAuthMethodId ?? null,
          authorityId: storedAuthority?.authorityId ?? null,
          selection: selections.find((item) => item.walletId === projection.walletId) ?? null,
        };
      },
      {
        paths: IMPORT_PATHS,
        authority: fixture.authority,
        projection: fixture.projection,
        credentialPublicKey,
      },
    );

    expect(result).toMatchObject({
      signerActivationCount: 0,
      pendingRemaining: false,
      profileId: fixture.projection.walletId,
      authMethodId: fixture.projection.targetWalletAuthMethodId,
      authorityId: fixture.projection.targetAuthorityId,
      selection: {
        walletId: fixture.projection.walletId,
        walletAuthMethodId: fixture.projection.targetWalletAuthMethodId,
        lockState: 'locked',
      },
    });
  });
});
