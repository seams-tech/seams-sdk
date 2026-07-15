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
import type {
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { parseGoogleEmailOtpRegistrationAttemptRecord } from '../../packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpRegistrationRecords';
import { parseD1RegistrationIntent } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { base64UrlDecode, base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { normalizeRuntimePolicyScope } from '../../packages/shared-ts/src/threshold/signingRootScope';
import {
  parseServerAllocatedWalletId,
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
  googleEmailOtpD1RegistrationAttemptBoundaryFixture,
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

test('Cloudflare D1 Router API auth service applies and removes Email OTP server seals', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
      emailOtpServerSeal: {
        keyVersion: EMAIL_OTP_SERVER_SEAL_KEY_VERSION,
        shamirPrimeB64u: EMAIL_OTP_SHAMIR_PRIME_B64U,
        serverEncryptExponentB64u: EMAIL_OTP_SERVER_ENCRYPT_EXPONENT_B64U,
        serverDecryptExponentB64u: EMAIL_OTP_SERVER_DECRYPT_EXPONENT_B64U,
      },
    });
    const plaintextSecretB64u = encodePositiveBigIntB64u(19n);
    const clientWrappedCiphertext = addEmailOtpClientSeal(plaintextSecretB64u);

    const applied = await service.emailOtp.applyEmailOtpServerSeal({
      wrappedCiphertext: clientWrappedCiphertext,
    });
    expect(applied).toMatchObject({
      ok: true,
      enrollmentSealKeyVersion: EMAIL_OTP_SERVER_SEAL_KEY_VERSION,
    });
    if (!applied.ok) return;
    expect(applied.ciphertext).not.toBe(clientWrappedCiphertext);
    expect(removeEmailOtpClientSeal(applied.ciphertext)).toBe(
      addEmailOtpServerSeal(plaintextSecretB64u),
    );

    const removed = await service.emailOtp.removeEmailOtpServerSeal({
      wrappedCiphertext: applied.ciphertext,
    });
    expect(removed).toMatchObject({
      ok: true,
      enrollmentSealKeyVersion: EMAIL_OTP_SERVER_SEAL_KEY_VERSION,
    });
    if (!removed.ok) return;
    expect(removed.ciphertext).not.toBe(applied.ciphertext);
    expect(removeEmailOtpClientSeal(removed.ciphertext)).toBe(plaintextSecretB64u);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service fails closed when Email OTP server seal is unconfigured', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    await expect(
      service.emailOtp.applyEmailOtpServerSeal({
        wrappedCiphertext: addEmailOtpClientSeal(encodePositiveBigIntB64u(23n)),
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'not_configured',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Google Email OTP registration attempt parser rejects legacy auth providers', () => {
  const canonical = parseGoogleEmailOtpRegistrationAttemptRecord(
    googleEmailOtpD1RegistrationAttemptBoundaryFixture({ authProvider: 'google' }),
  );
  expect(canonical).toMatchObject({ authProvider: 'google' });

  const legacy = parseGoogleEmailOtpRegistrationAttemptRecord(
    googleEmailOtpD1RegistrationAttemptBoundaryFixture({ authProvider: 'google_oidc' }),
  );
  expect(legacy).toBeNull();
});

test('Cloudflare D1 Router API auth service starts, reuses, and restarts Google Email OTP registration attempts', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const runtimePolicyScope = {
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    };
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      relayerAccount: 'relay.local',
      accountIdDerivationSecret: 'test-account-id-derivation-secret',
    });
    const appSession = await service.sessionVersions.getOrCreateAppSessionVersion({
      userId: 'google:register-user',
    });
    expect(appSession.ok).toBe(true);
    if (!appSession.ok) throw new Error(appSession.message);

    const rateLimit = await service.identity.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:register-user',
      email: 'Alice@Example.Test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:register-user',
      clientIp: '203.0.113.10',
    });
    expect(rateLimit).toEqual({ ok: true });

    const first = await service.identity.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'Alice@Example.Test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
    });
    expect(first.ok).toBe(true);
    expect(first.mode).toBe('register_started');
    if (!first.ok || first.mode !== 'register_started') return;
    expect(parseServerAllocatedWalletId(first.walletId).ok).toBe(true);
    expect(first.email).toBe('alice@example.test');
    expect(first.offer.candidates).toHaveLength(5);
    expect(first.offer.selectedCandidateId).toBe(first.offer.candidates[0].candidateId);

    const reused = await service.identity.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'alice@example.test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
    });
    expect(reused.ok).toBe(true);
    expect(reused.mode).toBe('register_started');
    if (!reused.ok || reused.mode !== 'register_started') return;
    expect(reused.registrationAttemptId).toBe(first.registrationAttemptId);
    expect(reused.walletId).toBe(first.walletId);

    const rowsAfterReuse = await listGoogleEmailOtpRegistrationAttemptRows({
      database,
      ...scope,
    });
    expect(rowsAfterReuse).toHaveLength(1);
    expect(rowsAfterReuse[0].state).toBe('started');
    expect(rowsAfterReuse[0].app_session_version).toBe(appSession.appSessionVersion);
    expect(rowsAfterReuse[0].runtime_org_id).toBe(scope.orgId);
    expect(rowsAfterReuse[0].runtime_policy_key).toBe(
      `${scope.orgId}\n${scope.projectId}\n${scope.envId}\nroot-v1`,
    );
    const stored = registrationAttemptRecordFromRow(rowsAfterReuse[0]);
    expect(stored.providerSubject).toBe('google:register-user');
    expect(stored.walletId).toBe(first.walletId);
    expect(stored.authProvider).toBe('google');
    expect(stored.runtimePolicyScope).toEqual(runtimePolicyScope);

    const restarted = await service.identity.resolveGoogleEmailOtpSession({
      providerSubject: 'google:register-user',
      email: 'alice@example.test',
      accountMode: 'register',
      appSessionVersion: appSession.appSessionVersion,
      runtimePolicyScope,
      restartRegistrationOffer: true,
    });
    expect(restarted.ok).toBe(true);
    expect(restarted.mode).toBe('register_started');
    if (!restarted.ok || restarted.mode !== 'register_started') return;
    expect(restarted.registrationAttemptId).not.toBe(first.registrationAttemptId);

    const rowsAfterRestart = await listGoogleEmailOtpRegistrationAttemptRows({
      database,
      ...scope,
    });
    expect(rowsAfterRestart).toHaveLength(2);
    const states: unknown[] = [];
    for (const row of rowsAfterRestart) states.push(row.state);
    states.sort();
    expect(states).toEqual(['abandoned', 'started']);

    await expect(
      service.identity.linkIdentity({
        userId: first.walletId,
        subject: 'wallet:google:register-user',
      }),
    ).resolves.toEqual({ ok: true });
    const cleaned = await service.emailOtp.cleanupGoogleEmailOtpDevRegistrationState({
      providerSubject: 'google:register-user',
      walletId: first.walletId,
      orgId: scope.orgId,
      nowMs: Date.now() + 31 * 60_000,
    });
    expect(cleaned).toEqual({
      ok: true,
      providerSubject: 'google:register-user',
      expiredRegistrationAttemptsDeleted: 2,
      linkedWalletId: first.walletId,
      orphanedWalletMappingRemoved: true,
    });
    await expect(service.identity.listIdentities({ userId: first.walletId })).resolves.toEqual({
      ok: true,
      subjects: [],
    });
    await expect(
      listGoogleEmailOtpRegistrationAttemptRows({
        database,
        ...scope,
      }),
    ).resolves.toEqual([]);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rate-limits Google Email OTP registration attempts', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const runtimePolicyScope = {
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    };
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGoogleRegistrationAttemptRateLimitMax: 1,
      emailOtpGoogleRegistrationAttemptRateLimitWindowMs: 60_000,
    });

    const first = await service.identity.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:rate-user',
      email: 'rate@example.test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:rate-user',
      clientIp: '203.0.113.20',
    });
    expect(first).toEqual({ ok: true });

    const second = await service.identity.consumeGoogleEmailOtpRegistrationAttemptRateLimit({
      providerSubject: 'google:rate-user',
      email: 'rate@example.test',
      accountMode: 'register',
      runtimePolicyScope,
      appSessionUserId: 'google:rate-user',
      clientIp: '203.0.113.20',
    });
    expect(second.ok).toBe(false);
    if (second.ok) return;
    expect(second.code).toBe('rate_limited');
    expect(second.retryAfterMs).toBeGreaterThan(0);
    expect(second.resetAtMs).toBeGreaterThan(Date.now());
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rotates Email OTP recovery keys after fresh auth', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-consumed',
      recoveryKeyStatus: 'consumed',
      issuedAtMs: 920,
      updatedAtMs: 930,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    const freshAuth = await service.emailOtp.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(freshAuth.ok).toBe(true);
    if (!freshAuth.ok) throw new Error(freshAuth.message);

    const rotated = await service.emailOtp.rotateEmailOtpRecoveryKeys({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      recoveryWrappedEnrollmentEscrows: makeRecoveryRotationEscrowInputs(),
    });
    expect(rotated.ok).toBe(true);
    if (!rotated.ok) throw new Error(rotated.message);
    expect(rotated).toMatchObject({
      walletId: 'email-wallet.testnet',
      enrollmentId: 'enrollment-a',
      enrollmentSealKeyVersion: 'seal-v1',
      activeRecoveryCodeCount: 10,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 12,
    });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 10, consumed: 1, revoked: 1 });
    await expect(
      service.emailOtp.getEmailOtpRecoveryCodeStatus({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      status: 'ready',
      activeRecoveryCodeCount: 10,
      consumedRecoveryCodeCount: 1,
      revokedRecoveryCodeCount: 1,
      totalRecoveryCodeCount: 12,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects stale Email OTP recovery-key rotation', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    await expect(
      service.emailOtp.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: makeRecoveryRotationEscrowInputs(),
      }),
    ).resolves.toMatchObject({ ok: false, code: 'fresh_auth_required' });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 1 });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects invalid Email OTP recovery-key rotation payloads', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    await insertEmailOtpAuthState({ database, ...scope });
    await insertEmailOtpRecoveryEscrow({
      database,
      ...scope,
      recoveryKeyId: 'recovery-old-active',
      recoveryKeyStatus: 'active',
      issuedAtMs: 900,
      updatedAtMs: 910,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpGrantTtlMs: 60_000,
    });
    const freshAuth = await service.emailOtp.markEmailOtpStrongAuthSatisfied({
      walletId: 'email-wallet.testnet',
    });
    expect(freshAuth.ok).toBe(true);
    if (!freshAuth.ok) throw new Error(freshAuth.message);

    const duplicateInputs = makeRecoveryRotationEscrowInputs();
    duplicateInputs[1] = {
      ...duplicateInputs[1],
      recoveryKeyId: duplicateInputs[0].recoveryKeyId,
      aadHashB64u: duplicateInputs[0].aadHashB64u,
    };
    await expect(
      service.emailOtp.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: duplicateInputs,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_body' });

    const badAadInputs = makeRecoveryRotationEscrowInputs();
    badAadInputs[0] = {
      ...badAadInputs[0],
      aadHashB64u: base64UrlEncode(new Uint8Array(32).fill(250)),
    };
    await expect(
      service.emailOtp.rotateEmailOtpRecoveryKeys({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        enrollmentId: 'enrollment-a',
        enrollmentSealKeyVersion: 'seal-v1',
        recoveryWrappedEnrollmentEscrows: badAadInputs,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_body' });

    const counts = await readRecoveryEscrowStatusCounts({ database, ...scope });
    expect(counts).toEqual({ active: 1 });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service tracks recovery sessions and executions', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertRecoverySession({
      database,
      ...scope,
      sessionId: 'recovery-session-a',
      metadata: { source: 'fixture' },
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
    });

    const initial = await service.recovery.getRecoverySession({ sessionId: 'recovery-session-a' });
    expect(initial.ok).toBe(true);
    if (!initial.ok) throw new Error(initial.message);
    expect(initial.record).toMatchObject({
      sessionId: 'recovery-session-a',
      status: 'prepared',
      nearAccountId: 'alice.testnet',
      metadata: { source: 'fixture' },
    });

    const updated = await service.recovery.updateRecoverySessionStatus({
      sessionId: 'recovery-session-a',
      status: 'verified',
      metadataPatch: {
        verifiedAtMs: 1_250,
      },
    });
    expect(updated.ok).toBe(true);
    if (!updated.ok) throw new Error(updated.message);
    expect(updated.record).toMatchObject({
      sessionId: 'recovery-session-a',
      status: 'verified',
      metadata: { source: 'fixture', verifiedAtMs: 1_250 },
    });
    expect(updated.record.updatedAtMs).toBeGreaterThanOrEqual(updated.record.createdAtMs);

    const pending = await service.recovery.recordRecoveryExecution({
      sessionId: 'recovery-session-a',
      chainIdKey: 'NEAR:TESTNET',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'pending',
      metadata: {
        expectedNewNearPublicKey: 'ed25519:new-public-key',
      },
    });
    expect(pending.ok).toBe(true);
    if (!pending.ok) throw new Error(pending.message);
    expect(pending.record).toMatchObject({
      sessionId: 'recovery-session-a',
      userId: 'recovery-user',
      nearAccountId: 'alice.testnet',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'pending',
    });

    const submitted = await service.recovery.recordRecoveryExecution({
      sessionId: 'recovery-session-a',
      chainIdKey: 'near:testnet',
      accountAddress: 'alice.testnet',
      action: 'near_email_recovery',
      status: 'submitted',
      transactionHash: 'near-tx-a',
    });
    expect(submitted.ok).toBe(true);
    if (!submitted.ok) throw new Error(submitted.message);
    expect(submitted.record).toMatchObject({
      status: 'submitted',
      transactionHash: 'near-tx-a',
    });
    expect(submitted.record.createdAtMs).toBe(pending.record.createdAtMs);

    const executionRow = await database
      .prepare(
        `SELECT status, record_json
           FROM recovery_executions
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND session_id = ?
            AND chain_id_key = ?
            AND account_address = ?
            AND action = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        'recovery-session-a',
        'near:testnet',
        'alice.testnet',
        'near_email_recovery',
      )
      .first<SqliteJsonRow>();
    expect(executionRow?.status).toBe('submitted');
    expect(JSON.parse(String(executionRow?.record_json || '{}'))).toMatchObject({
      transactionHash: 'near-tx-a',
    });

    await expect(
      service.recovery.recordRecoveryExecution({
        sessionId: 'missing-session',
        chainIdKey: 'near:testnet',
        accountAddress: 'alice.testnet',
        action: 'near_email_recovery',
        status: 'pending',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_args' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service issues and verifies login Email OTP challenges', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      emailOtpMaxAttempts: 2,
    });

    const challenge = await service.emailOtp.createEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.delivery).toMatchObject({
      status: 'sent',
      mode: 'dev_d1_outbox',
      emailHint: 'a***e@e***e.test',
    });

    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    expect(outbox.otpCode).toMatch(/^[0-9]{6}$/);

    await expect(
      service.emailOtp.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: '000000' === outbox.otpCode ? '111111' : '000000',
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'invalid_otp', attemptsRemaining: 1 });

    const verified = await service.emailOtp.verifyEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) throw new Error(verified.message);
    expect(verified.challengeId).toBe(challenge.challenge.challengeId);
    expect(verified.loginGrant).toMatch(/^[A-Za-z0-9_-]+$/);

    await expect(
      service.emailOtp.readEmailOtpOutboxEntry({
        challengeId: challenge.challenge.challengeId,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
    await expect(
      service.emailOtp.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });

    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toEqual({
      ok: true,
      challengeId: challenge.challenge.challengeId,
      otpChannel: 'email_otp',
    });
    await expect(
      service.emailOtp.consumeEmailOtpGrant({
        loginGrant: verified.loginGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'login_grant_invalid_or_expired' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service issues registration Email OTP challenges', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
    });

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: 'google:registration-user',
      walletId: 'registration-wallet.testnet',
      orgId: scope.orgId,
      email: 'Register.User@Example.Test',
      otpChannel: 'email_otp',
      sessionHash: 'registration-session-hash',
      appSessionVersion: 'registration-session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.challenge).toMatchObject({
      userId: 'google:registration-user',
      walletId: 'registration-wallet.testnet',
      orgId: scope.orgId,
      action: 'wallet_email_otp_registration',
      operation: 'registration',
    });
    expect(challenge.delivery).toEqual({
      status: 'sent',
      mode: 'dev_d1_outbox',
      emailHint: 'r***r@e***e.test',
    });

    const challengeRow = await database
      .prepare(
        `SELECT action, operation, record_json
           FROM email_otp_challenges
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND challenge_id = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        challenge.challenge.challengeId,
      )
      .first<SqliteJsonRow>();
    expect(challengeRow).toMatchObject({
      action: 'wallet_email_otp_registration',
      operation: 'registration',
    });
    const challengeRecord = JSON.parse(String(challengeRow?.record_json || '{}'));
    expect(challengeRecord).toMatchObject({
      challengeSubjectId: 'google:registration-user',
      walletId: 'registration-wallet.testnet',
      orgId: scope.orgId,
      email: 'register.user@example.test',
      action: 'wallet_email_otp_registration',
      operation: 'registration',
    });

    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: 'google:registration-user',
      walletId: 'registration-wallet.testnet',
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    expect(outbox.otpCode).toMatch(/^[0-9]{6}$/);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service verifies registration Email OTP enrollment', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = 'registration-wallet.testnet';
    const providerSubject = 'google:registration-user';
    const sessionHash = 'registration-session-hash';
    const appSessionVersion = 'registration-session-v1';
    const enrollmentSealKeyVersion = 'seal-v1';
    const unlockKeyVersion = 'unlock-v1';
    await insertSignerWallet({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      walletId,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
    });

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId,
      orgId: scope.orgId,
      email: 'Register.User@Example.Test',
      otpChannel: 'email_otp',
      sessionHash,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);

    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 7;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    const recoveryWrappedEnrollmentEscrows = makeRecoveryWrappedEnrollmentEscrows({
      walletId,
      userId: providerSubject,
      enrollmentId: 'email-otp-device-enrollment-v1:registration-wallet:google-user',
      enrollmentSealKeyVersion,
      signingRootId: 'project-a:env-a',
      signingRootVersion: 'root-v1',
    });

    const verified = await service.emailOtp.verifyEmailOtpEnrollment({
      providerSubject,
      walletId,
      orgId: scope.orgId,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash,
      appSessionVersion,
      proofEmail: 'register.user@example.test',
      recoveryWrappedEnrollmentEscrows,
      enrollmentSealKeyVersion,
      clientUnlockPublicKeyB64u: publicKeyB64u,
      unlockKeyVersion,
      thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) throw new Error(verified.message);
    expect(verified).toMatchObject({
      walletId,
      otpChannel: 'email_otp',
      enrollment: {
        enrollmentSealKeyVersion,
        unlockKeyVersion,
      },
    });

    await expect(
      service.emailOtp.readEmailOtpEnrollment({
        walletId,
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      enrollment: {
        walletId,
        providerUserId: providerSubject,
        orgId: scope.orgId,
        verifiedEmail: 'register.user@example.test',
        recoveryWrappedEnrollmentEscrowCount: EMAIL_OTP_RECOVERY_KEY_COUNT,
        enrollmentSealKeyVersion,
        unlockKeyVersion,
      },
    });
    await expect(
      countActiveRecoveryWrappedEnrollmentEscrows({
        database,
        namespace: scope.namespace,
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
        walletId,
      }),
    ).resolves.toBe(EMAIL_OTP_RECOVERY_KEY_COUNT);
    await expect(
      service.emailOtp.readEmailOtpOutboxEntry({
        challengeId: challenge.challenge.challengeId,
        userId: providerSubject,
        walletId,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
    await expect(
      service.emailOtp.verifyEmailOtpEnrollment({
        providerSubject,
        walletId,
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash,
        appSessionVersion,
        proofEmail: 'register.user@example.test',
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u: publicKeyB64u,
        unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service delivers Email OTP through configured provider', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });
    const provider = new RecordingEmailOtpDeliveryProvider();

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'email_provider',
      emailOtpDeliveryProvider: provider,
      emailOtpProduction: true,
    });

    const challenge = await service.emailOtp.createEmailOtpChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
      operation: 'wallet_unlock',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.delivery).toMatchObject({
      status: 'sent',
      mode: 'email_provider',
      emailHint: 'a***e@e***e.test',
    });
    expect(provider.calls).toHaveLength(1);
    expect(provider.calls[0]).toMatchObject({
      challengeId: challenge.challenge.challengeId,
      walletId: 'email-wallet.testnet',
      userId: 'google:email-user',
      orgId: scope.orgId,
      email: 'alice@example.test',
      emailHint: 'a***e@e***e.test',
      otpChannel: 'email_otp',
      action: 'wallet_email_otp_login',
      operation: 'wallet_unlock',
      expiresAtMs: challenge.challenge.expiresAtMs,
    });
    expect(provider.calls[0]?.otpCode).toMatch(/^[0-9]{6}$/);

    await expect(
      service.emailOtp.readEmailOtpOutboxEntry({
        challengeId: challenge.challenge.challengeId,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'not_found' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service fails closed when Email OTP provider is missing', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'email_provider',
      emailOtpProduction: true,
    });

    await expect(
      service.emailOtp.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'email_otp_delivery_not_configured',
    });

    const challengeRows = await database
      .prepare(
        `SELECT challenge_id
           FROM email_otp_challenges
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?`,
      )
      .bind(scope.namespace, scope.orgId, scope.projectId, scope.envId)
      .all<SqliteJsonRow>();
    expect(challengeRows.results || []).toEqual([]);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service issues and verifies device recovery Email OTP challenges', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
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

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      emailOtpRecoveryKeyAttemptRateLimitMax: 1,
      emailOtpRecoveryKeyAttemptRateLimitWindowMs: 60_000,
    });

    const challenge = await service.emailOtp.createEmailOtpDeviceRecoveryChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.challenge).toMatchObject({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      action: 'wallet_email_otp_device_recovery',
      operation: 'wallet_unlock',
    });

    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);

    await expect(
      service.emailOtp.verifyEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_purpose_mismatch' });

    const verified = await service.emailOtp.verifyEmailOtpDeviceRecoveryChallenge({
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challenge.challengeId,
      otpCode: outbox.otpCode,
      otpChannel: 'email_otp',
      sessionHash: 'session-hash-a',
      appSessionVersion: 'session-v1',
    });
    expect(verified.ok).toBe(true);
    if (!verified.ok) throw new Error(verified.message);
    expect(verified.challengeId).toBe(challenge.challenge.challengeId);
    expect(verified.recoveryConsumeGrant).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(verified.recoveryWrappedEnrollmentEscrows).toHaveLength(1);
    expect(verified.recoveryWrappedEnrollmentEscrows[0]).toMatchObject({
      walletId: 'email-wallet.testnet',
      userId: 'google:email-user',
      enrollmentId: 'enrollment-a',
      nonceB64u: 'nonce-recovery-active',
    });
    expect(
      Object.prototype.hasOwnProperty.call(
        verified.recoveryWrappedEnrollmentEscrows[0],
        'recoveryKeyId',
      ),
    ).toBe(false);
    expect(verified.enrollment).toMatchObject({
      walletId: 'email-wallet.testnet',
      providerUserId: 'google:email-user',
      recoveryWrappedEnrollmentEscrowCount: 3,
    });

    const grantRow = await database
      .prepare(
        `SELECT action
           FROM email_otp_grants
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND grant_token = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        verified.recoveryConsumeGrant,
      )
      .first<SqliteJsonRow>();
    expect(grantRow?.action).toBe('wallet_email_otp_device_recovery');

    const failureReport = await service.emailOtp.recordEmailOtpRecoveryKeyAttemptFailure({
      recoveryConsumeGrant: verified.recoveryConsumeGrant,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      clientIp: '203.0.113.42',
    });
    expect(failureReport.ok).toBe(true);
    if (!failureReport.ok) throw new Error(failureReport.message);
    expect(failureReport.walletId).toBe('email-wallet.testnet');
    expect(failureReport.recordedAtMs).toBeGreaterThan(0);

    await expect(
      service.emailOtp.recordEmailOtpRecoveryKeyAttemptFailure({
        recoveryConsumeGrant: verified.recoveryConsumeGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        clientIp: '203.0.113.42',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'rate_limited' });

    const consumed = await service.emailOtp.consumeEmailOtpRecoveryKey({
      recoveryConsumeGrant: verified.recoveryConsumeGrant,
      userId: 'google:email-user',
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      recoveryKeyId: 'recovery-active',
    });
    expect(consumed.ok).toBe(true);
    if (!consumed.ok) throw new Error(consumed.message);
    expect(consumed).toMatchObject({
      walletId: 'email-wallet.testnet',
      recoveryKeyId: 'recovery-active',
      activeRecoveryWrappedEnrollmentEscrowCount: 0,
    });
    expect(consumed.consumedAtMs).toBeGreaterThan(0);

    const consumedEscrowRow = await database
      .prepare(
        `SELECT recovery_key_status
           FROM email_otp_recovery_wrapped_enrollment_escrows
          WHERE namespace = ?
            AND org_id = ?
            AND project_id = ?
            AND env_id = ?
            AND wallet_id = ?
            AND recovery_key_id = ?
          LIMIT 1`,
      )
      .bind(
        scope.namespace,
        scope.orgId,
        scope.projectId,
        scope.envId,
        'email-wallet.testnet',
        'recovery-active',
      )
      .first<SqliteJsonRow>();
    expect(consumedEscrowRow?.recovery_key_status).toBe('consumed');

    await expect(
      service.emailOtp.consumeEmailOtpRecoveryKey({
        recoveryConsumeGrant: verified.recoveryConsumeGrant,
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        recoveryKeyId: 'recovery-active',
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'recovery_consume_grant_invalid_or_expired',
    });

    await expect(
      service.emailOtp.verifyEmailOtpDeviceRecoveryChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service enforces Email OTP challenge rate limits', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    await insertEmailOtpEnrollment({ database, ...scope });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      emailOtpChallengeRateLimitMax: 1,
      emailOtpChallengeRateLimitWindowMs: 60_000,
    });

    await expect(
      service.emailOtp.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-a',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: true });
    await expect(
      service.emailOtp.createEmailOtpChallenge({
        userId: 'google:email-user',
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        otpChannel: 'email_otp',
        sessionHash: 'session-hash-b',
        appSessionVersion: 'session-v1',
        operation: 'wallet_unlock',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'rate_limited' });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service verifies Email OTP unlock proofs once', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 1;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    await insertEmailOtpEnrollment({
      database,
      ...scope,
      clientUnlockPublicKeyB64u: publicKeyB64u,
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
    });

    const challenge = await service.walletUnlock.createEmailOtpUnlockChallenge({
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    expect(challenge.unlockKeyVersion).toBe('unlock-v1');

    const signature65 = await signSecp256k1Recoverable(
      base64UrlDecode(challenge.challengeB64u),
      privateKey32,
    );
    const verified = await service.walletUnlock.verifyEmailOtpUnlockProof({
      walletId: 'email-wallet.testnet',
      orgId: scope.orgId,
      challengeId: challenge.challengeId,
      unlockProof: {
        publicKey: publicKeyB64u,
        signature: base64UrlEncode(signature65),
      },
    });
    expect(verified).toEqual({
      ok: true,
      verified: true,
      userId: 'email-wallet.testnet',
      walletId: 'email-wallet.testnet',
      unlockKeyVersion: 'unlock-v1',
    });

    await expect(
      service.walletUnlock.verifyEmailOtpUnlockProof({
        walletId: 'email-wallet.testnet',
        orgId: scope.orgId,
        challengeId: challenge.challengeId,
        unlockProof: {
          publicKey: publicKeyB64u,
          signature: base64UrlEncode(signature65),
        },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'challenge_expired_or_invalid' });
    await expect(
      service.emailOtp.isEmailOtpStrongAuthRequired({ walletId: 'email-wallet.testnet' }),
    ).resolves.toMatchObject({
      ok: true,
      required: true,
      walletId: 'email-wallet.testnet',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
