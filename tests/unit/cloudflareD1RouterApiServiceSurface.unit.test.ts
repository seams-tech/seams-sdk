import { expect, test } from '@playwright/test';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createHash } from 'node:crypto';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssServerBootstrapResponse
} from '../../packages/sdk-server-ts/src/core/types';
import type {
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload
} from '../../packages/sdk-server-ts/src/core/registrationContracts';
import type { ThresholdSigningService } from '../../packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService';
import type {
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { parseGoogleEmailOtpRegistrationAttemptRecord } from '../../packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpRegistrationRecords';
import { parseD1RegistrationIntent } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { buildD1ThresholdEd25519RegistrationSessionPolicy } from '../../packages/sdk-server-ts/src/router/cloudflare/d1NearEd25519RegistrationBranch';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { normalizeRuntimePolicyScope } from '../../packages/shared-ts/src/threshold/signingRootScope';
import {
  implicitNearAccountProvisioning,
  parseServerAllocatedWalletId,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import {
  EMAIL_OTP_RECOVERY_KEY_COUNT,
  EMAIL_OTP_RECOVERY_WRAP_ALG,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_ESCROW_KIND,
  EMAIL_OTP_RECOVERY_WRAPPED_ENROLLMENT_SECRET_KIND,
  buildEmailOtpRecoveryWrapBinding,
  encodeEmailOtpRecoveryWrappedEnrollmentAad,
} from '../../packages/shared-ts/src/utils/emailOtpRecoveryKey';
import {
  secp256k1PrivateKey32ToPublicKey33,
  signSecp256k1Recoverable,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/ethSignerWasm';
import { createSigningSessionSealShamir3PassBigIntRuntime } from '../../packages/sdk-server-ts/src/threshold/session/signingSessionSeal/crypto/cipher';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
} from '../helpers/sqliteD1';
import {
  EMAIL_OTP_SERVER_SEAL_KEY_VERSION,
  EMAIL_OTP_SHAMIR_PRIME_B64U,
  EMAIL_OTP_SERVER_ENCRYPT_EXPONENT_B64U,
  EMAIL_OTP_SERVER_DECRYPT_EXPONENT_B64U,
  EMAIL_OTP_CLIENT_ENCRYPT_EXPONENT_B64U,
  EMAIL_OTP_CLIENT_DECRYPT_EXPONENT_B64U,
  TEST_COMBINED_NEAR_ACCOUNT_ID,
  TEST_ED25519_APPLICATION_BINDING_DIGEST_B64U,
  googleEmailOtpD1RegistrationAttemptBoundaryFixture,
  testEd25519PreparedServerState,
  testEd25519RespondedServerState,
  testEvmFamilyRegistrationSignerSet,
  testCombinedRegistrationSignerSet,
  requireParsedDomainId,
  RecordingEmailOtpDeliveryProvider,
  ThrowingDurableObjectStub,
  ThrowingDurableObjectNamespace,
  RecordingDurableObjectStub,
  RecordingDurableObjectNamespace,
  parseRecordingDurableObjectRequest,
  recordingDurableObjectJson,
  isActiveRecordingReplayGuard,
  isRecordingDurableObjectReplayReservationRequest,
  recordingDurableObjectRequestKey,
  recordingDurableObjectRequestOp,
  countRecordingDurableObjectRequests,
  recordingDurableObjectRequestsIncludeKey,
  walletRegistrationDoKey,
  requireRecordingDurableObjectRecord,
  replaceRecordingDurableObjectRecord,
  recordingDurableObjectKeysWithPrefix,
  requireNestedRecordingDurableObjectRecord,
  requireSingleEcdsaPrepare,
  testEcdsaClientBootstrapTargets,
  testEcdsaServerBootstrapResponse,
  testEd25519PrepareForRegistration,
  testEd25519RespondForRegistration,
  testEd25519FinalizeForRegistration,
  testEd25519RegistrationKeygenFromRegistrationMaterial,
  testEcdsaHssRoleLocalBootstrap,
  testGetCombinedRegistrationSchemeModule,
  testThresholdSchemeHealthz,
  testThresholdSchemeSession,
  testCombinedRegistrationThresholdSigningService,
  utf8Bytes,
  arrayBufferCopy,
  concatBytes,
  derIntegerBytes,
  rawP256SignatureToDer,
  sha256,
  hexBytes,
  createWebAuthnAssertionFixture,
  createWebAuthnAssertion,
  jsonBase64Url,
  fakeWebAuthnRegistrationCredential,
  encodePositiveBigIntB64u,
  addEmailOtpClientSeal,
  removeEmailOtpClientSeal,
  addEmailOtpServerSeal,
  generateGoogleOidcTestKey,
  makeSignedGoogleIdToken,
  googleJwksFetchMockPublicJwk,
  oidcJwksFetchMockUrl,
  oidcJwksFetchMockPublicJwk,
  googleJwksFetchMock,
  installGoogleJwksFetchMock,
  restoreGoogleJwksFetchMock,
  oidcJwksFetchMock,
  installOidcJwksFetchMock,
  restoreOidcJwksFetchMock,
  applySignerMigrations,
  isSqliteJsonRow,
  toInteger,
  insertIdentity,
  insertWebAuthn,
  readWebAuthnChallengeRow,
  readWebAuthnAuthenticatorRow,
  insertNearPublicKey,
  insertSignerWallet,
  testWalletAuthMethodIdentity,
  insertWalletAuthMethod,
  readWalletAuthMethodRecord,
  readSignerWalletRecord,
  readWalletSignerRecord,
  insertEmailOtpEnrollment,
  listGoogleEmailOtpRegistrationAttemptRows,
  registrationAttemptRecordFromRow,
  insertEmailOtpAuthState,
  insertEmailOtpRecoveryEscrow,
  insertEmailOtpGrant,
  emailOtpGrantRecord,
  emailOtpRecoveryEscrowRecord,
  makeRecoveryRotationEscrowInputs,
  recoveryRotationEscrowInput,
  makeRecoveryWrappedEnrollmentEscrows,
  recoveryWrappedEnrollmentEscrowInput,
  recoveryEscrowAadHashB64u,
  readRecoveryEscrowStatusCounts,
  countActiveRecoveryWrappedEnrollmentEscrows,
  insertRecoverySession,
  recoverySessionRecord,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

test('Cloudflare D1 Router API auth service reads signer metadata with tenant scope', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      userId: 'wallet-a',
    };
    await insertIdentity({ database, ...scope, subject: 'google:alice' });
    await insertIdentity({ database, ...scope, orgId: 'org-b', subject: 'google:bob' });
    await insertIdentity({
      database,
      ...scope,
      userId: 'linked.testnet',
      subject: 'wallet:oidc:linked',
    });
    await insertWebAuthn({ database, ...scope });
    await insertNearPublicKey({ database, ...scope });
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-consumed',
      recoveryKeyStatus: 'consumed',
      issuedAtMs: 880,
      updatedAtMs: 920,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-revoked',
      recoveryKeyStatus: 'revoked',
      issuedAtMs: 890,
      updatedAtMs: 930,
    });
    await insertEmailOtpGrant({
      database,
      ...scope,
      grantToken: 'grant-valid',
      appSessionVersion: 'grant-session-v1',
    });
    await insertEmailOtpGrant({
      database,
      ...scope,
      grantToken: 'grant-mismatch',
      appSessionVersion: 'grant-session-v2',
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
      googleOidcClientId: 'google-client',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });

    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:alice'],
    });
    await expect(
      service.identity.linkIdentity({ userId: 'wallet-b', subject: 'google:alice' }),
    ).resolves.toMatchObject({ ok: false, code: 'already_linked' });
    await expect(
      service.identity.linkIdentity({ userId: scope.userId, subject: 'google:carol' }),
    ).resolves.toEqual({ ok: true });
    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:alice', 'google:carol'],
    });
    await expect(
      service.identity.unlinkIdentity({ userId: scope.userId, subject: 'google:alice' }),
    ).resolves.toEqual({ ok: true });
    await expect(service.identity.listIdentities({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      subjects: ['google:carol'],
    });
    await expect(
      service.identity.unlinkIdentity({ userId: scope.userId, subject: 'google:carol' }),
    ).resolves.toMatchObject({ ok: false, code: 'cannot_unlink_last_identity' });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-solo',
      subject: 'google:solo',
    });
    await expect(
      service.identity.linkIdentity({
        userId: scope.userId,
        subject: 'google:solo',
        allowMoveIfSoleIdentity: true,
      }),
    ).resolves.toEqual({ ok: true, movedFromUserId: 'wallet-solo' });
    await expect(service.identity.listIdentities({ userId: 'wallet-solo' })).resolves.toEqual({
      ok: true,
      subjects: [],
    });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-many',
      subject: 'google:many-a',
    });
    await insertIdentity({
      database,
      ...scope,
      userId: 'wallet-many',
      subject: 'google:many-b',
    });
    await expect(
      service.identity.linkIdentity({
        userId: scope.userId,
        subject: 'google:many-a',
        allowMoveIfSoleIdentity: true,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'already_linked' });
    await expect(
      service.identity.resolveOidcWalletId({
        providerSubject: 'oidc:linked',
        runtimePolicyScope: {
          orgId: scope.orgId,
          projectId: scope.projectId,
          envId: scope.envId,
          signingRootVersion: 'v1',
        },
      }),
    ).resolves.toBe('linked.testnet');
    const derivedOidcWalletId = await service.identity.resolveOidcWalletId({
      providerSubject: 'oidc:new-user',
      email: 'new-user@example.test',
      runtimePolicyScope: {
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
        signingRootVersion: 'v1',
      },
    });
    expect(derivedOidcWalletId).toMatch(/^[a-z]+-[a-z]+-[a-z0-9]{10}\.relay\.local$/);
    await expect(
      service.emailOtp.readEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      enrollment: {
        walletId: 'email-wallet.testnet',
        providerUserId: 'google:email-user',
        orgId: scope.orgId,
        verifiedEmail: 'alice@example.test',
      },
    });
    await expect(
      service.emailOtp.readActiveEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        providerUserId: 'google:other-user',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'provider_identity_mismatch' });
    await expect(
      service.emailOtp.readActiveEmailOtpEnrollment({
        walletId: 'email-wallet.testnet',
        orgId: 'org-b',
        providerUserId: 'google:email-user',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'tenant_scope_mismatch' });
    await expect(
      service.emailOtp.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toEqual({
      ok: true,
      required: false,
      walletId: 'email-wallet.testnet',
    });
    await insertEmailOtpAuthState({ database, ...scope });
    await expect(
      service.emailOtp.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toEqual({
      ok: true,
      required: true,
      walletId: 'email-wallet.testnet',
      lastEmailOtpLoginAtMs: 800,
    });
    const strongAuth = await service.emailOtp.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(strongAuth.ok).toBe(true);
    if (!strongAuth.ok) throw new Error(strongAuth.message);
    expect(strongAuth.lastStrongAuthAtMs).toBeGreaterThanOrEqual(800);
    await expect(
      service.emailOtp.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toMatchObject({
      ok: true,
      required: false,
      walletId: 'email-wallet.testnet',
      lastEmailOtpLoginAtMs: 800,
      lastStrongAuthAtMs: strongAuth.lastStrongAuthAtMs,
    });
    await expect(
      service.emailOtp.getEmailOtpRecoveryCodeStatus({
        userId: 'google:not-enrolled',
        walletId: 'missing-email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toEqual({
      ok: true,
      status: 'not_enrolled',
      walletId: 'missing-email-wallet.testnet',
      enrollmentId: '',
      enrollmentSealKeyVersion: '',
      expectedRecoveryCodeCount: 10,
      activeRecoveryCodeCount: 0,
      consumedRecoveryCodeCount: 0,
      revokedRecoveryCodeCount: 0,
      totalRecoveryCodeCount: 0,
      issuedAtMs: null,
    });
    await expect(
      service.emailOtp.getEmailOtpRecoveryCodeStatus({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toEqual({
      ok: true,
      status: 'incomplete',
      walletId: 'email-wallet.testnet',
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      expectedRecoveryCodeCount: 10,
      activeRecoveryCodeCount: 1,
      consumedRecoveryCodeCount: 1,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 3,
      issuedAtMs: 880,
    });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: 'grant-valid',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v1',
      }),
    ).resolves.toEqual({
      ok: true,
      challengeId: 'challenge-grant-valid',
      otpChannel: 'email_otp',
    });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: 'grant-valid',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: 'grant-mismatch',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'wrong-session',
      }),
    ).resolves.toEqual({
      ok: true,
      challengeId: 'challenge-grant-mismatch',
      otpChannel: 'email_otp',
    });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: 'grant-mismatch',
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'grant-session-v2',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
    const session = await service.sessionVersions.getOrCreateAppSessionVersion({ userId: scope.userId });
    expect(session.ok).toBe(true);
    if (!session.ok) throw new Error(session.message);
    await expect(
      service.sessionVersions.validateAppSessionVersion({
        userId: scope.userId,
        appSessionVersion: session.appSessionVersion,
      }),
    ).resolves.toEqual({ ok: true });
    const rotated = await service.sessionVersions.rotateAppSessionVersion({ userId: scope.userId });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) throw new Error(rotated.message);
    await expect(
      service.sessionVersions.validateAppSessionVersion({
        userId: scope.userId,
        appSessionVersion: session.appSessionVersion,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_session_version' });
    await expect(
      service.webAuthn.listWebAuthnAuthenticatorsForUser({ userId: scope.userId, rpId: 'example.com' }),
    ).resolves.toMatchObject({
      ok: true,
      authenticators: [
        {
          credentialIdB64u: 'credential-a',
          signerSlot: 2,
          publicKey: 'ed25519:public',
          createdAtMs: 200,
          updatedAtMs: 300,
        },
      ],
    });
    const webAuthnFixture = await createWebAuthnAssertionFixture();
    await insertWebAuthn({
      database,
      ...scope,
      credentialIdB64u: webAuthnFixture.credentialIdB64u,
      credentialPublicKeyB64u: webAuthnFixture.credentialPublicKeyB64u,
      signerSlot: 4,
    });
    const loginOptions = await service.webAuthn.createWebAuthnLoginOptions({
      userId: scope.userId,
      rpId: 'example.com',
      ttlMs: 60_000,
    });
    expect(loginOptions.ok).toBe(true);
    if (!loginOptions.ok) throw new Error(loginOptions.message);
    const loginChallengeId = String(loginOptions.challengeId || '');
    expect(loginChallengeId).not.toBe('');
    expect(loginOptions.challengeB64u).toEqual(expect.any(String));
    expect(loginOptions.expiresAtMs).toBeGreaterThan(Date.now());
    const loginChallengeRow = await readWebAuthnChallengeRow({
      database,
      ...scope,
      challengeId: loginChallengeId,
    });
    expect(loginChallengeRow?.challenge_kind).toBe('login');
    expect(loginChallengeRow?.created_at_ms).toEqual(expect.any(Number));
    expect(loginChallengeRow?.expires_at_ms).toBe(loginOptions.expiresAtMs);
    const rawLoginChallengeRecord = loginChallengeRow?.record_json;
    if (typeof rawLoginChallengeRecord !== 'string') {
      throw new Error('Expected WebAuthn login challenge record_json');
    }
    const loginChallengeRecord: unknown = JSON.parse(rawLoginChallengeRecord);
    expect(loginChallengeRecord).toMatchObject({
      version: 'webauthn_login_challenge_v1',
      challengeId: loginChallengeId,
      userId: scope.userId,
      rpId: 'example.com',
      challengeB64u: loginOptions.challengeB64u,
      expiresAtMs: loginOptions.expiresAtMs,
    });
    const loginAssertion = await createWebAuthnAssertion({
      fixture: webAuthnFixture,
      rpId: 'example.com',
      origin: 'https://example.com',
      challengeB64u: String(loginOptions.challengeB64u || ''),
      counter: 1,
    });
    await expect(
      service.webAuthn.verifyWebAuthnLogin({
        challengeId: loginChallengeId,
        webauthn_authentication: loginAssertion,
        expected_origin: 'https://example.com',
      }),
    ).resolves.toMatchObject({
      ok: true,
      verified: true,
      userId: scope.userId,
      rpId: 'example.com',
    });
    await expect(
      readWebAuthnAuthenticatorRow({
        database,
        ...scope,
        userId: scope.userId,
        credentialIdB64u: webAuthnFixture.credentialIdB64u,
      }),
    ).resolves.toMatchObject({ counter: 1 });
    await expect(
      service.webAuthn.createWebAuthnLoginOptions({ userId: 'bad user', rpId: 'example.com' }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Invalid userId',
    });
    const syncOptions = await service.webAuthn.createWebAuthnSyncAccountOptions({
      rp_id: 'example.com',
      account_id: scope.userId,
      ttl_ms: 60_000,
    });
    expect(syncOptions.ok).toBe(true);
    if (!syncOptions.ok) throw new Error(syncOptions.message);
    const syncChallengeId = String(syncOptions.challengeId || '');
    expect(syncChallengeId).not.toBe('');
    expect(syncOptions.challengeB64u).toEqual(expect.any(String));
    expect(syncOptions.credentialIds).toEqual(['credential-a', webAuthnFixture.credentialIdB64u]);
    expect(syncOptions.walletBinding).toEqual({
      walletId: scope.userId,
      nearAccountId: 'near.testnet',
      nearEd25519SigningKeyId: 'ed25519:key',
      rpId: 'example.com',
      credentialIdB64u: 'credential-a',
      signerSlot: 2,
    });
    const syncChallengeRow = await readWebAuthnChallengeRow({
      database,
      ...scope,
      challengeId: syncChallengeId,
    });
    expect(syncChallengeRow?.challenge_kind).toBe('sync');
    expect(syncChallengeRow?.expires_at_ms).toBe(syncOptions.expiresAtMs);
    const rawSyncChallengeRecord = syncChallengeRow?.record_json;
    if (typeof rawSyncChallengeRecord !== 'string') {
      throw new Error('Expected WebAuthn sync challenge record_json');
    }
    const syncChallengeRecord: unknown = JSON.parse(rawSyncChallengeRecord);
    expect(syncChallengeRecord).toMatchObject({
      version: 'webauthn_sync_challenge_v1',
      challengeId: syncChallengeId,
      rpId: 'example.com',
      expectedUserId: scope.userId,
      challengeB64u: syncOptions.challengeB64u,
      expiresAtMs: syncOptions.expiresAtMs,
    });
    const syncAssertion = await createWebAuthnAssertion({
      fixture: webAuthnFixture,
      rpId: 'example.com',
      origin: 'https://example.com',
      challengeB64u: String(syncOptions.challengeB64u || ''),
      counter: 2,
    });
    await expect(
      service.webAuthn.verifyWebAuthnSyncAccount({
        challengeId: syncChallengeId,
        webauthn_authentication: syncAssertion,
        expected_origin: 'https://example.com',
      }),
    ).resolves.toMatchObject({
      ok: true,
      verified: true,
      accountId: scope.userId,
      walletId: scope.userId,
      nearAccountId: 'near.testnet',
      nearEd25519SigningKeyId: 'ed25519:key',
      rpId: 'example.com',
      signerSlot: 4,
      publicKey: 'ed25519:public',
      credentialIdB64u: webAuthnFixture.credentialIdB64u,
      credentialPublicKeyB64u: webAuthnFixture.credentialPublicKeyB64u,
    });
    await expect(
      readWebAuthnAuthenticatorRow({
        database,
        ...scope,
        userId: scope.userId,
        credentialIdB64u: webAuthnFixture.credentialIdB64u,
      }),
    ).resolves.toMatchObject({ counter: 2 });
    await expect(
      service.webAuthn.createWebAuthnSyncAccountOptions({
        account_id: scope.userId,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Missing rp_id',
    });
    await expect(service.nearFunding.listNearPublicKeysForUser({ userId: scope.userId })).resolves.toEqual({
      ok: true,
      keys: [
        {
          publicKey: 'ed25519:near-public',
          kind: 'threshold',
          signerSlot: 1,
          createdAtMs: 400,
          updatedAtMs: 500,
          authBinding: {
            kind: 'passkey',
            rpId: 'example.com',
            credentialIdB64u: 'credential-a',
          },
        },
      ],
    });
    await expect(
      service.thresholdRuntime.listThresholdEcdsaKeyIdentityTargetsForUser({
        userId: scope.userId,
        rpId: 'example.com',
        keyTargets: [
          {
            keyHandle: 'ecdsa-key-handle-a',
            chainTarget: { namespace: 'eip155', reference: '1' },
          },
        ],
      }),
    ).resolves.toEqual({
      records: [],
      diagnostics: {
        userId: scope.userId,
        inputCount: 1,
        returnedCount: 0,
        thresholdServicePresent: false,
        rejected: { threshold_service_missing: 1 },
      },
    });
    await expect(
      service.thresholdRuntime.listWalletEcdsaKeyFactsInventory({
        walletId: scope.userId,
        rpId: 'example.com',
        keyTargets: [
          {
            keyHandle: 'ecdsa-key-handle-a',
            chainTarget: { namespace: 'eip155', reference: '1' },
          },
        ],
      }),
    ).resolves.toEqual({
      records: [],
      diagnostics: {
        userId: scope.userId,
        inputCount: 1,
        returnedCount: 0,
        thresholdServicePresent: false,
        rejected: { threshold_service_missing: 1 },
      },
    });
    expect(service.router.getConfiguredRelayerAccount()).toBe('relay.local');
    await expect(service.router.getRelayerAccount()).resolves.toEqual({
      accountId: 'relay.local',
      publicKey: 'relay-public-key',
    });
    expect(service.identity.getGoogleOidcPublicConfig()).toEqual({
      configured: true,
      clientId: 'google-client',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service revokes wallet auth methods through D1', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = 'wallet-auth.testnet';
    const rpId = 'example.com';
    const walletIdValue = walletIdFromString(walletId);
    const rpIdValue = requireParsedDomainId(parseWebAuthnRpId(rpId));
    const email = 'owner@example.test';
    const emailHashHex = hexBytes(await sha256(utf8Bytes(email)));
    const passkeyRecord: TestWalletAuthMethodRecord = {
      version: 'wallet_auth_method_v1',
      kind: 'passkey',
      status: 'active',
      walletId,
      rpId,
      credentialIdB64u: 'credential-a',
      credentialPublicKeyB64u: 'public-key-a',
      counter: 0,
      createdAtMs: 1_000,
      updatedAtMs: 1_000,
    };
    const emailOtpRecord: TestWalletAuthMethodRecord = {
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId,
      emailHashHex,
      registrationAuthorityId: 'google:owner',
      createdAtMs: 1_100,
      updatedAtMs: 1_100,
    };
    await insertSignerWallet({ database, ...scope, walletId });
    await insertWalletAuthMethod({ database, ...scope, record: passkeyRecord });
    await insertWalletAuthMethod({ database, ...scope, record: emailOtpRecord });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
    });

    await expect(
      service.walletAuthMethods.revokeWalletAuthMethod({
        walletId: walletIdValue,
        target: { kind: 'email_otp', email },
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_auth_method_revoke',
            walletId: walletIdValue,
            target: { kind: 'email_otp', email },
            expiresAtMs: Date.now() + 60_000,
          },
        },
      }),
    ).resolves.toEqual({
      ok: true,
      walletId,
      authMethod: {
        kind: 'email_otp',
        status: 'revoked',
      },
    });

    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: `email_otp:${walletId}:${emailHashHex}`,
      }),
    ).resolves.toMatchObject({
      kind: 'email_otp',
      status: 'revoked',
      walletId,
      emailHashHex,
    });

    await expect(
      service.walletAuthMethods.revokeWalletAuthMethod({
        walletId: walletIdValue,
        target: { kind: 'passkey', rpId: rpIdValue, credentialIdB64u: 'credential-a' },
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_auth_method_revoke',
            walletId: walletIdValue,
            target: { kind: 'passkey', rpId: rpIdValue, credentialIdB64u: 'credential-a' },
            expiresAtMs: Date.now() + 60_000,
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_state',
      message: 'wallet must retain at least one active auth method',
    });

    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: 'passkey:example.com:credential-a',
      }),
    ).resolves.toMatchObject({
      kind: 'passkey',
      status: 'active',
      walletId,
      credentialIdB64u: 'credential-a',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service wires threshold signing from Durable Object config', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const withoutThreshold = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
    });
    expect(withoutThreshold.thresholdRuntime.getThresholdSigningService()).toBeNull();

    const withThreshold = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      relayerPublicKey: 'relay-public-key',
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: new ThrowingDurableObjectNamespace(),
        THRESHOLD_PREFIX: 'seams-local-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const threshold = withThreshold.thresholdRuntime.getThresholdSigningService();
    expect(threshold).not.toBeNull();
    expect(withThreshold.thresholdRuntime.getThresholdSigningService()).toBe(threshold);
    expect(threshold?.getRouterAbNormalSigningWorkerId()).toBe('test-threshold-signing-worker');
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
