import { expect, test } from '@playwright/test';
import { D1WalletStore } from '../../packages/sdk-server-ts/src/core/d1WalletStore';
import type {
  WalletEd25519SignerRecord,
  WalletEcdsaSignerRecord,
  WalletRecord,
} from '../../packages/sdk-server-ts/src/core/WalletStore';
import { CloudflareD1WalletRegistrationCommitStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/registration/d1WalletRegistrationCommitStore';
import { CloudflareD1WebAuthnStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/webauthn/d1WebAuthnStore';
import { CloudflareD1EmailOtpEnrollmentStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/emailOtp/d1EmailOtpEnrollmentStore';
import type { D1EmailOtpRegistrationCommitPlan } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/emailOtp/d1EmailOtpRegistrationEnrollmentFinalizer';
import type { EmailOtpWalletEnrollmentRecord } from '../../packages/sdk-server-ts/src/core/EmailOtpStores';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  walletIdFromString,
  type RegistrationAuthority,
  type WalletId,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { unknownWebAuthnAuthenticatorDeviceInfo } from '../../packages/shared-ts/src/utils/webauthnDeviceInfo';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import { applySignerMigrations } from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { createWalletEcdsaSignerRecord } from './helpers/walletRegistrationSigner.fixtures';

const TEST_SCOPE = {
  namespace: 'registration-commit-test',
  orgId: 'org-a',
  projectId: 'project-a',
  envId: 'env-a',
} as const;

function testRpId() {
  const parsed = parseWebAuthnRpId('example.com');
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function testWalletRecord(walletId: WalletId, now: number): WalletRecord {
  return {
    version: 'wallet_v1',
    walletId,
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function testEd25519Signer(walletId: WalletId, now: number): WalletEd25519SignerRecord {
  const nearAccountId = '0000000000000000000000000000000000000000000000000000000000000001';
  const runtimePolicyScope = {
    orgId: 'org-a',
    projectId: 'project-a',
    envId: 'env-a',
    signingRootVersion: 'root-v1',
  } as const;
  const activeYao = buildEd25519YaoCapabilityFixture({
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    thresholdSessionId: 'threshold-session-1',
    signerSlot: 1,
    signingWorkerId: 'yao-signing-worker-a',
    participantIds: [1, 2],
    runtimePolicyScope,
    seed: 61,
  });
  return {
    version: 'wallet_signer_ed25519_v1',
    walletId,
    signerId: `ed25519:${nearAccountId}:1`,
    nearAccountId,
    nearEd25519SigningKeyId: 'near-ed25519-key-1',
    thresholdSessionId: 'threshold-session-1',
    signerSlot: 1,
    publicKey: activeYao.publicKey,
    signingWorkerId: 'yao-signing-worker-a',
    keyVersion: 'yao-key-v1',
    recoveryExportCapable: true,
    participantIds: [1, 2],
    signingRootId: 'project-a:env-a',
    signingRootVersion: 'root-v1',
    runtimePolicyScope,
    activeYaoCapability: activeYao.capability,
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function testEcdsaSigner(walletId: WalletId, now: number): WalletEcdsaSignerRecord {
  return createWalletEcdsaSignerRecord({ walletId, now });
}

function testPasskeyAuthority(
  walletId: WalletId,
): Extract<RegistrationAuthority, { readonly kind: 'passkey' }> {
  return {
    kind: 'passkey',
    walletId,
    rpId: testRpId(),
    credentialIdB64u: 'credential-a',
    credentialPublicKeyB64u: 'credential-public-key-a',
    counter: 0,
    device: unknownWebAuthnAuthenticatorDeviceInfo(),
    registrationIntentDigestB64u: 'registration-intent-digest-a',
  };
}

async function countRows(database: D1DatabaseLike, table: string): Promise<number> {
  const row = await database.prepare(`SELECT COUNT(*) AS count FROM ${table}`).first<{
    readonly count?: unknown;
  }>();
  return Number(row?.count || 0);
}

test('D1 registration commit binds the passkey credential before Ed25519 exists', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    // An ECDSA-only passkey wallet: the Ed25519 Yao ceremony has not settled.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, now),
      walletSigners: [testEcdsaSigner(walletId, now)],
      authority: testPasskeyAuthority(walletId),
      now,
    });

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(1);
    await expect(countRows(database, 'webauthn_authenticators')).resolves.toBe(1);
    // The binding must exist, or the next passkey login fails unknown_credential.
    await expect(countRows(database, 'webauthn_credential_bindings')).resolves.toBe(1);
    const signerRow = await database
      .prepare('SELECT record_json FROM wallet_signers LIMIT 1')
      .first<{ readonly record_json?: unknown }>();
    const persistedSigner = JSON.parse(String(signerRow?.record_json)) as Record<string, unknown>;
    expect(persistedSigner).toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId,
      walletKey: { keyHandle: 'ecdsa-key-handle-1' },
    });
    expect(persistedSigner).not.toHaveProperty('evmFamilySigningKeySlotId');
    expect(persistedSigner).not.toHaveProperty('walletKey.evmFamilySigningKeySlotId');

    const webAuthnStore = new CloudflareD1WebAuthnStore({
      database,
      ...TEST_SCOPE,
    });
    const binding = await webAuthnStore.readBindingByCredential({
      rpId: testRpId(),
      credentialIdB64u: 'credential-a',
    });
    expect(binding).toMatchObject({
      userId: String(walletId),
      credentialIdB64u: 'credential-a',
    });
    // Ed25519 facts are absent as a set, not partially populated.
    expect(binding?.nearAccountId).toBeUndefined();
    expect(binding?.nearEd25519SigningKeyId).toBeUndefined();
    expect(binding?.signerSlot).toBeUndefined();
    expect(binding?.publicKey).toBeUndefined();
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 registration commit stores a mixed Ed25519 and ECDSA wallet atomically', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, now),
      walletSigners: [testEd25519Signer(walletId, now), testEcdsaSigner(walletId, now)],
      authority: testPasskeyAuthority(walletId),
      now,
    });

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(2);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(1);
    const walletStore = new D1WalletStore({
      database,
      ...TEST_SCOPE,
      ensureSchema: false,
    });
    await expect(walletStore.listEd25519Signers()).resolves.toMatchObject([
      {
        walletId,
        activeYaoCapability: {
          version: 'wallet_ed25519_yao_registration_capability_v1',
          nearAccountId: '0000000000000000000000000000000000000000000000000000000000000001',
        },
      },
    ]);
    await expect(countRows(database, 'webauthn_authenticators')).resolves.toBe(1);
    await expect(countRows(database, 'webauthn_credential_bindings')).resolves.toBe(1);

    const webAuthnStore = new CloudflareD1WebAuthnStore({
      database,
      ...TEST_SCOPE,
    });
    await expect(
      webAuthnStore.readAuthenticator({
        userId: walletId,
        credentialIdB64u: 'credential-a',
      }),
    ).resolves.toMatchObject({
      credentialIdB64u: 'credential-a',
      credentialPublicKeyB64u: 'credential-public-key-a',
      counter: 0,
    });

    const bindingRow = await database
      .prepare('SELECT record_json FROM webauthn_credential_bindings LIMIT 1')
      .first<{ readonly record_json?: unknown }>();
    expect(JSON.parse(String(bindingRow?.record_json))).toMatchObject({
      version: 'webauthn_credential_binding_v1',
      rpId: 'example.com',
      credentialIdB64u: 'credential-a',
      userId: walletId,
      nearEd25519SigningKeyId: 'near-ed25519-key-1',
      signerSlot: 1,
      relayerKeyId: 'yao-signing-worker-a',
      participantIds: [1, 2],
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 registration commit rolls back every mixed-wallet record when one signer fails', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('brisk-bloom-abcdef');
    const now = 1_900_000_000_000;
    // Deliberately corrupt valid factory output: updatedAtMs earlier than
    // createdAtMs violates the wallet_signers CHECK (updated_at_ms >= created_at_ms).
    const invalidEcdsaSigner = {
      ...createWalletEcdsaSignerRecord({ walletId, now }),
      updatedAtMs: now - 1,
    };
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });

    await expect(
      store.commit({
        kind: 'passkey_wallet_registration_commit_v1',
        wallet: testWalletRecord(walletId, now),
        walletSigners: [testEd25519Signer(walletId, now), invalidEcdsaSigner],
        authority: testPasskeyAuthority(walletId),
        now,
      }),
    ).rejects.toThrow(/CHECK constraint failed/);

    await expect(countRows(database, 'wallets')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(0);
    await expect(countRows(database, 'webauthn_authenticators')).resolves.toBe(0);
    await expect(countRows(database, 'webauthn_credential_bindings')).resolves.toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

function testEmailOtpAuthority(
  walletId: WalletId,
): Extract<RegistrationAuthority, { readonly kind: 'email_otp' }> {
  return {
    kind: 'email_otp',
    walletId,
    emailHashHex: 'a'.repeat(64),
    registrationAuthorityId: 'registration-authority-a',
  } as Extract<RegistrationAuthority, { readonly kind: 'email_otp' }>;
}

function testEnrollmentRecord(walletId: WalletId, now: number): EmailOtpWalletEnrollmentRecord {
  return {
    version: 'email_otp_wallet_enrollment_v1',
    walletId: String(walletId),
    providerUserId: 'provider-user-a',
    orgId: TEST_SCOPE.orgId,
    verifiedEmail: 'registrant@example.com',
    enrollmentId: 'enrollment-a',
    enrollmentVersion: 'v1',
    enrollmentSealKeyVersion: 'seal-v1',
    signingRootId: 'signing-root-a',
    signingRootVersion: 'root-v1',
    recoveryWrappedEnrollmentEscrowCount: 5,
    clientUnlockPublicKeyB64u: 'client-unlock-public-key-a',
    unlockKeyVersion: 'unlock-v1',
    thresholdEcdsaClientVerifyingShareB64u: 'client-verifying-share-a',
    createdAtMs: now,
    updatedAtMs: now,
  };
}

function scopedPrepare(database: D1DatabaseLike) {
  return (sql: string, values: readonly unknown[]) =>
    database
      .prepare(sql)
      .bind(
        TEST_SCOPE.namespace,
        TEST_SCOPE.orgId,
        TEST_SCOPE.projectId,
        TEST_SCOPE.envId,
        ...values,
      );
}

function emailOtpCommitPlan(
  database: D1DatabaseLike,
  walletId: WalletId,
  now: number,
): D1EmailOtpRegistrationCommitPlan {
  const enrollments = new CloudflareD1EmailOtpEnrollmentStore({ prepare: scopedPrepare(database) });
  return {
    kind: 'd1_email_otp_registration_commit_plan_v1',
    statements: [enrollments.preparePutEnrollmentStatement(testEnrollmentRecord(walletId, now))],
  };
}

test('D1 registration commit stores the Email OTP enrollment in the wallet batch', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({ database, ...TEST_SCOPE });

    await store.commit({
      kind: 'email_otp_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, now),
      walletSigners: [testEd25519Signer(walletId, now)],
      authority: testEmailOtpAuthority(walletId),
      emailOtp: emailOtpCommitPlan(database, walletId, now),
      now,
    });

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(1);
    await expect(countRows(database, 'email_otp_wallet_enrollments')).resolves.toBe(1);
    const enrollments = new CloudflareD1EmailOtpEnrollmentStore({
      prepare: scopedPrepare(database),
    });
    await expect(enrollments.readEnrollment(String(walletId))).resolves.toMatchObject({
      walletId: String(walletId),
      verifiedEmail: 'registrant@example.com',
      providerUserId: 'provider-user-a',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('D1 registration commit rolls back the wallet when the Email OTP statement fails', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({ database, ...TEST_SCOPE });

    await expect(
      store.commit({
        kind: 'email_otp_wallet_registration_commit_v1',
        wallet: testWalletRecord(walletId, now),
        walletSigners: [testEd25519Signer(walletId, now)],
        authority: testEmailOtpAuthority(walletId),
        emailOtp: {
          kind: 'd1_email_otp_registration_commit_plan_v1',
          statements: [
            database
              .prepare('INSERT INTO email_otp_wallet_enrollments (namespace) VALUES (?)')
              .bind('only-namespace'),
          ],
        },
        now,
      }),
    ).rejects.toThrow();

    // A visible wallet without its enrollment is the half-applied state the
    // single batch exists to prevent.
    await expect(countRows(database, 'wallets')).resolves.toBe(0);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(0);
    await expect(countRows(database, 'email_otp_wallet_enrollments')).resolves.toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('re-running the Email OTP registration commit converges instead of duplicating', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const now = 1_900_000_000_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({ database, ...TEST_SCOPE });
    const commitInput = () =>
      ({
        kind: 'email_otp_wallet_registration_commit_v1',
        wallet: testWalletRecord(walletId, now),
        walletSigners: [testEd25519Signer(walletId, now)],
        authority: testEmailOtpAuthority(walletId),
        emailOtp: emailOtpCommitPlan(database, walletId, now),
        now,
      }) as const;

    await store.commit(commitInput());
    // A finalize interrupted after the batch re-runs it on retry; every
    // statement is an upsert, so the retry must converge rather than duplicate.
    await store.commit(commitInput());

    await expect(countRows(database, 'wallets')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_signers')).resolves.toBe(1);
    await expect(countRows(database, 'wallet_auth_methods')).resolves.toBe(1);
    await expect(countRows(database, 'email_otp_wallet_enrollments')).resolves.toBe(1);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

/*
 * Refactor 94 Phase 4+5. A wallet planned with both signers commits twice: the
 * ECDSA commit makes it usable, the Ed25519 commit lands when the Yao ceremony
 * settles. Both write the credential binding, so the second write must
 * converge the Ed25519 facts onto the first without rewriting its history.
 *
 * Reads parse `record_json`, not the columns, so the upsert has to reconcile
 * the timestamps inside the JSON too — the columns alone being correct is what
 * made this survivable but wrong.
 */
test('the second credential binding write converges without rewriting history', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const walletId = walletIdFromString('amber-atlas-abcdef');
    const createdAtMs = 1_900_000_000_000;
    const settledAtMs = createdAtMs + 4_000;
    const store = new CloudflareD1WalletRegistrationCommitStore({
      database,
      ...TEST_SCOPE,
    });
    const webAuthnStore = new CloudflareD1WebAuthnStore({ database, ...TEST_SCOPE });
    const readBinding = async () =>
      webAuthnStore.readBindingByCredential({
        rpId: testRpId(),
        credentialIdB64u: 'credential-a',
      });

    // Commit #1: ECDSA only. The wallet is usable; Ed25519 has not settled.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, createdAtMs),
      walletSigners: [testEcdsaSigner(walletId, createdAtMs)],
      authority: testPasskeyAuthority(walletId),
      now: createdAtMs,
    });
    const afterEcdsa = await readBinding();
    expect(afterEcdsa?.createdAtMs).toBe(createdAtMs);
    expect(afterEcdsa?.nearAccountId).toBeUndefined();

    // Commit #2: the Ed25519 signer alone, as the deferred finalize sends it.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, settledAtMs),
      walletSigners: [testEd25519Signer(walletId, settledAtMs)],
      authority: testPasskeyAuthority(walletId),
      now: settledAtMs,
    });
    const afterEd25519 = await readBinding();
    // The Ed25519 facts arrive as a set.
    expect(afterEd25519?.nearAccountId).toBe(
      testEd25519Signer(walletId, settledAtMs).nearAccountId,
    );
    expect(afterEd25519?.signerSlot).toBe(testEd25519Signer(walletId, settledAtMs).signerSlot);
    // The wallet's creation history is not rewritten by the later commit.
    expect(afterEd25519?.createdAtMs).toBe(createdAtMs);
    expect(afterEd25519?.updatedAtMs).toBe(settledAtMs);

    // An exact replay of commit #2 changes nothing.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, settledAtMs),
      walletSigners: [testEd25519Signer(walletId, settledAtMs)],
      authority: testPasskeyAuthority(walletId),
      now: settledAtMs,
    });
    await expect(readBinding()).resolves.toEqual(afterEd25519);

    // An out-of-order replay of commit #1 must not regress the update stamp
    // nor drop the Ed25519 facts that commit #2 established.
    await store.commit({
      kind: 'passkey_wallet_registration_commit_v1',
      wallet: testWalletRecord(walletId, createdAtMs),
      walletSigners: [testEcdsaSigner(walletId, createdAtMs)],
      authority: testPasskeyAuthority(walletId),
      now: createdAtMs,
    });
    const afterStaleReplay = await readBinding();
    expect(afterStaleReplay?.createdAtMs).toBe(createdAtMs);
    expect(afterStaleReplay?.updatedAtMs).toBe(settledAtMs);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
