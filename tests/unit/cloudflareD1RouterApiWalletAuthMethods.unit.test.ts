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

test('Cloudflare D1 Router API auth service adds Email OTP wallet auth methods through D1 and Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('add-auth-wallet.testnet');
    const rpId = 'example.com';
    const providerSubject = 'google:add-auth-user';
    const email = 'add.auth@example.test';
    const appSessionVersion = 'add-auth-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    await insertSignerWallet({ database, ...scope, walletId });
    await insertWalletAuthMethod({
      database,
      ...scope,
      record: {
        version: 'wallet_auth_method_v1',
        kind: 'passkey',
        status: 'active',
        walletId,
        rpId,
        credentialIdB64u: 'existing-passkey-credential',
        credentialPublicKeyB64u: 'existing-passkey-public-key',
        counter: 0,
        createdAtMs: 1_000,
        updatedAtMs: 1_000,
      },
    });

    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const intent = await service.walletAuthMethods.createAddAuthMethodIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId,
        authMethod: { kind: 'email_otp', email },
      },
    });
    expect(intent.ok).toBe(true);
    if (!intent.ok) throw new Error(intent.message);
    expect(Object.prototype.hasOwnProperty.call(intent.intent, 'rpId')).toBe(false);
    const runtimePolicyScope = normalizeRuntimePolicyScope(intent.intent.runtimePolicyScope);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: intent.addAuthMethodIntentDigestB64u,
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

    const started = await service.walletAuthMethods.startWalletAddAuthMethod({
      walletId,
      addAuthMethodIntentGrant: intent.addAuthMethodIntentGrant,
      addAuthMethodIntentDigestB64u: intent.addAuthMethodIntentDigestB64u,
      intent: intent.intent,
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_auth_method_provision',
          walletId,
          authMethod: intent.intent.authMethod,
          runtimePolicyScope,
          expiresAtMs: Date.now() + 60_000,
        },
      },
      authority: {
        kind: 'email_otp',
        emailOtpRegistrationProof: {
          version: 'email_otp_registration_proof_v1',
          proofKind: 'otp_challenge',
          providerSubject,
          email,
          challengeId: challenge.challenge.challengeId,
          otpCode: outbox.otpCode,
          otpChannel: 'email_otp',
          registrationIntentDigestB64u: intent.addAuthMethodIntentDigestB64u,
          appSessionVersion,
        },
      },
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.intent).toEqual(intent.intent);

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(
        `${prefix}add-auth-method-intent:${intent.addAuthMethodIntentGrant}`,
      ),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}add-auth-method:${started.addAuthMethodCeremonyId}`),
    ).toMatchObject({
      digestB64u: intent.addAuthMethodIntentDigestB64u,
      orgId: scope.orgId,
      intent: intent.intent,
      auth: { kind: 'app_session' },
      authority: {
        kind: 'email_otp',
        walletId,
        email,
      },
    });

    const emailHashHex = hexBytes(await sha256(utf8Bytes(email)));
    const finalized = await service.walletAuthMethods.finalizeWalletAddAuthMethod({
      addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
    });
    expect(finalized).toEqual({
      ok: true,
      walletId,
      authority: {
        walletId,
        factor: {
          kind: 'email_otp',
          provider: 'email',
          providerUserId: providerSubject,
        },
        verifier: {
          kind: 'email_otp_wallet_auth_method',
          emailHashHex,
        },
        bindingId: `email_otp:${walletId}:${emailHashHex}`,
      },
      authMethod: {
        kind: 'email_otp',
        status: 'active',
      },
    });
    expect(
      durableObjects.stub.values.get(`${prefix}add-auth-method:${started.addAuthMethodCeremonyId}`),
    ).toBeUndefined();

    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: `email_otp:${walletId}:${emailHashHex}`,
      }),
    ).resolves.toMatchObject({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId,
      emailHashHex,
      registrationAuthorityId: challenge.challenge.challengeId,
    });
    await expect(
      service.walletAuthMethods.finalizeWalletAddAuthMethod({
        addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'not_found',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service starts ECDSA add-signer ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('add-signer-wallet.testnet');
    const rpId = 'example.com';
    const durableObjects = new RecordingDurableObjectNamespace();
    await insertSignerWallet({ database, ...scope, walletId });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const intent = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            participantIds: [1, 2, 3],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        },
      },
    });
    expect(intent.ok).toBe(true);
    if (!intent.ok) throw new Error(intent.message);
    expect(Object.prototype.hasOwnProperty.call(intent.intent, 'rpId')).toBe(false);
    const runtimePolicyScope = normalizeRuntimePolicyScope(intent.intent.runtimePolicyScope);

    const started = await service.walletAuthMethods.startWalletAddSigner({
      walletId,
      addSignerIntentGrant: intent.addSignerIntentGrant,
      addSignerIntentDigestB64u: intent.addSignerIntentDigestB64u,
      intent: intent.intent,
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_signer_provision',
          walletId,
          signerSelection: intent.intent.signerSelection,
          runtimePolicyScope,
          expiresAtMs: Date.now() + 60_000,
        },
      },
    });
    if (!started.ok) throw new Error(started.message);
    expect(started.ok).toBe(true);
    expect(started.intent).toEqual(intent.intent);
    expect(started.ecdsa).toMatchObject({
      kind: 'evm_family_ecdsa_keygen',
      targets: [
        {
          chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
          prepare: {
            formatVersion: 'ecdsa-hss-role-local',
            walletId,
            signingRootId: `${scope.projectId}:${scope.envId}`,
            signingRootVersion: 'root-v1',
            keyScope: 'evm-family',
            remainingUses: 3,
            participantIds: [1, 2, 3],
            runtimePolicyScope: {
              orgId: scope.orgId,
              projectId: scope.projectId,
              envId: scope.envId,
              signingRootVersion: 'root-v1',
            },
          },
        },
      ],
    });
    if (!started.ecdsa) throw new Error('Expected ECDSA add-signer start payload');
    const ecdsaPrepare = requireSingleEcdsaPrepare(started.ecdsa);
    expect(ecdsaPrepare.evmFamilySigningKeySlotId).toContain(
      encodeURIComponent(`${scope.projectId}:${scope.envId}`),
    );
    expect(ecdsaPrepare.ecdsaThresholdKeyId).toMatch(/^ehss-/);
    expect(ecdsaPrepare.relayerKeyId).toMatch(/^ehss-relayer-/);

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}add-signer-intent:${intent.addSignerIntentGrant}`),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}add-signer:${started.addSignerCeremonyId}`),
    ).toMatchObject({
      intent: intent.intent,
      digestB64u: intent.addSignerIntentDigestB64u,
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      auth: { kind: 'app_session' },
      signerState: {
        kind: 'ecdsa_add_signer_prepared',
        hssKind: 'evm_family_ecdsa_keygen',
        targets: [
          {
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
            prepare: ecdsaPrepare,
          },
        ],
      },
    });

    await expect(
      service.walletAuthMethods.startWalletAddSigner({
        walletId,
        addSignerIntentGrant: intent.addSignerIntentGrant,
        addSignerIntentDigestB64u: intent.addSignerIntentDigestB64u,
        intent: intent.intent,
        auth: {
          kind: 'app_session',
          policy: {
            permission: 'wallet_signer_provision',
            walletId,
            signerSelection: intent.intent.signerSelection,
            runtimePolicyScope,
            expiresAtMs: Date.now() + 60_000,
          },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_grant',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service responds to and finalizes ECDSA add-signer ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('add-signer-respond-wallet.testnet');
    const rpId = 'example.com';
    const durableObjects = new RecordingDurableObjectNamespace();
    let bootstrapRequest: EcdsaHssClientBootstrapRequest | null = null;
    const thresholdSigningService = {
      async ecdsaHssRoleLocalBootstrap(request: EcdsaHssClientBootstrapRequest) {
        bootstrapRequest = request;
        return {
          ok: true as const,
          value: testEcdsaServerBootstrapResponse(request),
        };
      },
    } as unknown as ThresholdSigningService;
    await insertSignerWallet({ database, ...scope, walletId });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const intent = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            participantIds: [1, 2, 3],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        },
      },
    });
    if (!intent.ok) throw new Error(intent.message);
    const runtimePolicyScope = normalizeRuntimePolicyScope(intent.intent.runtimePolicyScope);

    const started = await service.walletAuthMethods.startWalletAddSigner({
      walletId,
      addSignerIntentGrant: intent.addSignerIntentGrant,
      addSignerIntentDigestB64u: intent.addSignerIntentDigestB64u,
      intent: intent.intent,
      auth: {
        kind: 'app_session',
        policy: {
          permission: 'wallet_signer_provision',
          walletId,
          signerSelection: intent.intent.signerSelection,
          runtimePolicyScope,
          expiresAtMs: Date.now() + 60_000,
        },
      },
    });
    if (!started.ok) throw new Error(started.message);
    if (!started.ecdsa) throw new Error('Expected ECDSA add-signer start payload');

    const ecdsaPrepare = requireSingleEcdsaPrepare(started.ecdsa);
    const clientBootstraps = testEcdsaClientBootstrapTargets(started.ecdsa);
    const clientBootstrap = clientBootstraps[0].clientBootstrap;
    const responded = await service.walletAuthMethods.respondWalletAddSignerHss({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        clientBootstraps,
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(responded.ecdsa?.bootstraps).toMatchObject([
      {
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
        bootstrap: {
          keyHandle: 'test-add-signer-ecdsa-key-handle',
          walletId,
          evmFamilySigningKeySlotId: ecdsaPrepare.evmFamilySigningKeySlotId,
          thresholdSessionId: clientBootstrap.thresholdSessionId,
          signingGrantId: clientBootstrap.signingGrantId,
        },
      },
    ]);
    expect(bootstrapRequest).toMatchObject({
      sessionId: clientBootstrap.thresholdSessionId,
      signingGrantId: clientBootstrap.signingGrantId,
      runtimePolicyScope,
    });

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}add-signer:${started.addSignerCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'ecdsa_add_signer_responded',
        hssKind: 'evm_family_ecdsa_keygen',
        targets: [
          {
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
            prepare: ecdsaPrepare,
          },
        ],
        responded: {
          bootstraps: [
            {
              chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
              bootstrap: {
                keyHandle: 'test-add-signer-ecdsa-key-handle',
                thresholdSessionId: clientBootstrap.thresholdSessionId,
                signingGrantId: clientBootstrap.signingGrantId,
              },
            },
          ],
        },
      },
    });

    await expect(
      service.walletAuthMethods.respondWalletAddSignerHss({
        addSignerCeremonyId: started.addSignerCeremonyId,
        ecdsa: {
          clientBootstraps,
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_state',
    });

    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner({
        addSignerCeremonyId: started.addSignerCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['wrong-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'key_handle_mismatch',
    });

    const finalized = await service.walletAuthMethods.finalizeWalletAddSigner({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
      },
    });
    if (!finalized.ok) throw new Error(finalized.message);
    expect(finalized).toMatchObject({
      walletId,
      ecdsa: {
        walletKeys: [
          {
            keyScope: 'evm-family',
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
            walletId,
            evmFamilySigningKeySlotId: ecdsaPrepare.evmFamilySigningKeySlotId,
            keyHandle: 'test-add-signer-ecdsa-key-handle',
            ecdsaThresholdKeyId: ecdsaPrepare.ecdsaThresholdKeyId,
            signingRootId: `${scope.projectId}:${scope.envId}`,
            signingRootVersion: 'root-v1',
            thresholdOwnerAddress: '0x0000000000000000000000000000000000000001',
            relayerKeyId: ecdsaPrepare.relayerKeyId,
            participantIds: [1, 2, 3],
          },
        ],
      },
    });

    const signerRecord = await readWalletSignerRecord({
      database,
      ...scope,
      walletId,
      signerFamily: 'ecdsa',
      signerId: 'ecdsa:evm:eip155:8453',
    });
    expect(signerRecord).toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId,
      evmFamilySigningKeySlotId: ecdsaPrepare.evmFamilySigningKeySlotId,
      signerId: 'ecdsa:evm:eip155:8453',
      chainTargetKey: 'evm:eip155:8453',
      walletKey: {
        keyHandle: 'test-add-signer-ecdsa-key-handle',
        ecdsaThresholdKeyId: ecdsaPrepare.ecdsaThresholdKeyId,
        thresholdOwnerAddress: '0x0000000000000000000000000000000000000001',
      },
    });
    expect(
      durableObjects.stub.values.get(`${prefix}add-signer:${started.addSignerCeremonyId}`),
    ).toBeUndefined();

    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner({
        addSignerCeremonyId: started.addSignerCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'not_found',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
