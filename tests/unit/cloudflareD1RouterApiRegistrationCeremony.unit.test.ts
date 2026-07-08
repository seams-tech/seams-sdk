import { expect, test } from '@playwright/test';
import { isoCBOR } from '@simplewebauthn/server/helpers';
import { createHash } from 'node:crypto';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  EcdsaHssClientBootstrapRequest,
  EcdsaHssServerBootstrapResponse,
} from '../../packages/sdk-server-ts/src/core/types';
import type {
  CreateRegistrationIntentRequest,
  WalletRegistrationEcdsaClientBootstrap,
  WalletRegistrationEcdsaPreparePayload,
} from '../../packages/sdk-server-ts/src/core/registrationContracts';
import type { ThresholdSigningService } from '../../packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService';
import type {
  CloudflareD1EmailOtpDeliveryProviderInput,
  CloudflareD1EmailOtpDeliveryProviderResult,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { parseGoogleEmailOtpRegistrationAttemptRecord } from '../../packages/sdk-server-ts/src/router/cloudflare/d1GoogleEmailOtpRegistrationRecords';
import {
  buildD1DurableEd25519HssAdvancedEvalRecord,
  buildD1DurableEd25519HssAdvanceClaimRecord,
  buildD1DurableEd25519HssFinalizedReportRecord,
  parseD1DurableEd25519HssAdvancedEvalRecord,
  parseD1DurableEd25519HssAdvanceClaimRecord,
  parseD1DurableEd25519HssFinalizedReportRecord,
  parseD1RegistrationIntent,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { CloudflareD1RegistrationCeremonyIntentStore } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyStore';
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
  createWebAuthnRegistrationCredential,
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

test('D1 Ed25519 HSS durable records reject malformed durable boundaries', () => {
  const contextBindingB64u = base64UrlEncode(new Uint8Array(32).fill(1));
  const addStageRequestDigestB64u = base64UrlEncode(new Uint8Array(32).fill(2));
  const advancedServerEvalStateB64u = base64UrlEncode(new Uint8Array([3, 4, 5]));
  const finalizeContextB64u = base64UrlEncode(new Uint8Array([5, 6, 7]));
  const priorStageResponseMessageB64u = base64UrlEncode(new Uint8Array([4, 5, 6]));
  const clientOutputMessageB64u = base64UrlEncode(new Uint8Array([6, 7, 8]));
  const serverOutputMessageB64u = base64UrlEncode(new Uint8Array([9, 10, 11]));
  const seedOutputMessageB64u = base64UrlEncode(new Uint8Array([12, 13, 14]));
  const createdAtMs = Date.now();
  const expiresAtMs = createdAtMs + 60_000;
  const advancedEval = buildD1DurableEd25519HssAdvancedEvalRecord({
    ceremonyHandle: 'hss-ceremony-1',
    contextBindingB64u,
    addStageRequestDigestB64u,
    projectionMode: 'registration_seed_and_output',
    advancedServerEvalStateB64u,
    finalizeContextB64u,
    priorStageResponseMessageB64u,
    createdAtMs,
    expiresAtMs,
  });
  expect(parseD1DurableEd25519HssAdvancedEvalRecord(advancedEval)).toEqual(advancedEval);
  expect(
    parseD1DurableEd25519HssAdvancedEvalRecord({
      ...advancedEval,
      addStageRequestDigestB64u: base64UrlEncode(new Uint8Array(31).fill(2)),
    }),
  ).toBeNull();
  expect(
    parseD1DurableEd25519HssAdvancedEvalRecord({
      ...advancedEval,
      projectionMode: 'legacy_projection',
    }),
  ).toBeNull();
  expect(
    parseD1DurableEd25519HssAdvancedEvalRecord({
      ...advancedEval,
      expiresAtMs: createdAtMs,
    }),
  ).toBeNull();

  const advanceClaim = buildD1DurableEd25519HssAdvanceClaimRecord({
    state: 'in_flight',
    ceremonyHandle: 'hss-ceremony-1',
    addStageRequestDigestB64u,
    claimId: 'ehss-advclaim_test',
    leaseExpiresAtMs: createdAtMs + 10_000,
    attempt: {
      route: 'wallets_register_hss_advance_state',
      startedAtMs: createdAtMs,
    },
    createdAtMs,
    updatedAtMs: createdAtMs,
    expiresAtMs,
  });
  expect(parseD1DurableEd25519HssAdvanceClaimRecord(advanceClaim)).toEqual(advanceClaim);
  expect(
    parseD1DurableEd25519HssAdvanceClaimRecord({
      ...advanceClaim,
      state: 'fulfilled',
    }),
  ).toBeNull();
  expect(
    parseD1DurableEd25519HssAdvanceClaimRecord({
      ...advanceClaim,
      leaseExpiresAtMs: createdAtMs,
    }),
  ).toBeNull();
  expect(
    parseD1DurableEd25519HssAdvanceClaimRecord({
      ...advanceClaim,
      state: 'fulfilled',
      advancedEval: {
        ceremonyHandle: 'hss-ceremony-1',
        addStageRequestDigestB64u,
      },
    }),
  ).toBeNull();
  const fulfilledAdvanceClaim = buildD1DurableEd25519HssAdvanceClaimRecord({
    state: 'fulfilled',
    ceremonyHandle: 'hss-ceremony-1',
    addStageRequestDigestB64u,
    claimId: 'ehss-advclaim_test',
    advancedEval: {
      ceremonyHandle: 'hss-ceremony-1',
      addStageRequestDigestB64u,
    },
    createdAtMs,
    updatedAtMs: createdAtMs,
    expiresAtMs,
  });
  expect(parseD1DurableEd25519HssAdvanceClaimRecord(fulfilledAdvanceClaim)).toEqual(
    fulfilledAdvanceClaim,
  );
  expect(
    parseD1DurableEd25519HssAdvanceClaimRecord({
      ...fulfilledAdvanceClaim,
      advancedEval: {
        ceremonyHandle: 'hss-ceremony-2',
        addStageRequestDigestB64u,
      },
    }),
  ).toBeNull();

  const finalizedReport = buildD1DurableEd25519HssFinalizedReportRecord({
    ceremonyHandle: 'hss-ceremony-1',
    contextBindingB64u,
    addStageRequestDigestB64u,
    projectionMode: 'registration_seed_and_output',
    finalizedReport: {
      contextBindingB64u,
      clientOutputMessageB64u,
      serverOutputMessageB64u,
      seedOutputMessageB64u,
    },
    createdAtMs,
    expiresAtMs,
  });
  expect(parseD1DurableEd25519HssFinalizedReportRecord(finalizedReport)).toEqual(finalizedReport);
  expect(
    parseD1DurableEd25519HssFinalizedReportRecord({
      ...finalizedReport,
      finalizedReport: {
        ...finalizedReport.finalizedReport,
        contextBindingB64u: base64UrlEncode(new Uint8Array(32).fill(9)),
      },
    }),
  ).toBeNull();
  expect(
    parseD1DurableEd25519HssFinalizedReportRecord({
      ...finalizedReport,
      projectionMode: 'registration_output_only',
    }),
  ).toBeNull();
  expect(
    parseD1DurableEd25519HssFinalizedReportRecord({
      ...finalizedReport,
      projectionMode: 'registration_output_only',
      finalizedReport: {
        contextBindingB64u,
        clientOutputMessageB64u,
        serverOutputMessageB64u,
      },
    }),
  ).toEqual({
    ...finalizedReport,
    projectionMode: 'registration_output_only',
    finalizedReport: {
      contextBindingB64u,
      clientOutputMessageB64u,
      serverOutputMessageB64u,
    },
  });
});

test('D1 Ed25519 HSS advance claims prevent duplicate active advance ownership', async () => {
  const durableObjects = new RecordingDurableObjectNamespace();
  const store = new CloudflareD1RegistrationCeremonyIntentStore({
    namespace: durableObjects,
    objectName: 'registration-claims-test',
    prefix: 'test:',
  });
  const addStageRequestDigestB64u = base64UrlEncode(new Uint8Array(32).fill(7));
  const createdAtMs = Date.now();
  const expiresAtMs = createdAtMs + 60_000;
  const firstClaim = buildD1DurableEd25519HssAdvanceClaimRecord({
    state: 'in_flight',
    ceremonyHandle: 'hss-ceremony-claim',
    addStageRequestDigestB64u,
    claimId: 'ehss-advclaim_first',
    leaseExpiresAtMs: createdAtMs + 30_000,
    attempt: {
      route: 'wallets_register_hss_advance_state',
      startedAtMs: createdAtMs,
    },
    createdAtMs,
    updatedAtMs: createdAtMs,
    expiresAtMs,
  });
  const secondClaim = buildD1DurableEd25519HssAdvanceClaimRecord({
    state: 'in_flight',
    ceremonyHandle: 'hss-ceremony-claim',
    addStageRequestDigestB64u,
    claimId: 'ehss-advclaim_second',
    leaseExpiresAtMs: createdAtMs + 30_000,
    attempt: {
      route: 'wallets_register_hss_advance_state',
      startedAtMs: createdAtMs,
    },
    createdAtMs,
    updatedAtMs: createdAtMs,
    expiresAtMs,
  });

  const firstBegin = await store.beginEd25519HssAdvanceClaim(firstClaim);
  expect(firstBegin.status).toBe('started');
  const secondBegin = await store.beginEd25519HssAdvanceClaim(secondClaim);
  expect(secondBegin.status).toBe('in_flight');
  expect(secondBegin.record.claimId).toBe(firstClaim.claimId);

  const fulfilled = await store.fulfillEd25519HssAdvanceClaim(
    buildD1DurableEd25519HssAdvanceClaimRecord({
      state: 'fulfilled',
      ceremonyHandle: firstClaim.ceremonyHandle,
      addStageRequestDigestB64u,
      claimId: firstClaim.claimId,
      advancedEval: {
        ceremonyHandle: firstClaim.ceremonyHandle,
        addStageRequestDigestB64u,
      },
      createdAtMs,
      updatedAtMs: Date.now(),
      expiresAtMs,
    }),
  );
  expect(fulfilled.status).toBe('fulfilled');
  const thirdBegin = await store.beginEd25519HssAdvanceClaim(secondClaim);
  expect(thirdBegin.status).toBe('fulfilled');
  expect(thirdBegin.record.claimId).toBe(firstClaim.claimId);
});

test('D1 Ed25519 HSS durable store rejects key and record identity mismatch', async () => {
  const durableObjects = new RecordingDurableObjectNamespace();
  const store = new CloudflareD1RegistrationCeremonyIntentStore({
    namespace: durableObjects,
    objectName: 'registration-durable-mismatch-test',
    prefix: 'test:',
  });
  const contextBindingB64u = base64UrlEncode(new Uint8Array(32).fill(1));
  const addStageRequestDigestB64u = base64UrlEncode(new Uint8Array(32).fill(2));
  const otherAddStageRequestDigestB64u = base64UrlEncode(new Uint8Array(32).fill(3));
  const record = buildD1DurableEd25519HssAdvancedEvalRecord({
    ceremonyHandle: 'hss-ceremony-mismatch',
    contextBindingB64u,
    addStageRequestDigestB64u,
    projectionMode: 'registration_seed_and_output',
    advancedServerEvalStateB64u: base64UrlEncode(utf8Bytes('advanced-state')),
    finalizeContextB64u: base64UrlEncode(utf8Bytes('finalize-context')),
    priorStageResponseMessageB64u: base64UrlEncode(utf8Bytes('prior-stage-response')),
    createdAtMs: Date.now(),
    expiresAtMs: Date.now() + 60_000,
  });
  await store.putEd25519HssAdvancedEvalRecord(record);
  await expect(
    store.getEd25519HssAdvancedEvalRecord({
      ceremonyHandle: record.ceremonyHandle,
      addStageRequestDigestB64u,
    }),
  ).resolves.toEqual(record);

  durableObjects.stub.values.set(
    `test:ed25519-hss-advanced-eval:${encodeURIComponent(record.ceremonyHandle)}:${encodeURIComponent(addStageRequestDigestB64u)}`,
    {
      ...record,
      addStageRequestDigestB64u: otherAddStageRequestDigestB64u,
    },
  );
  await expect(
    store.getEd25519HssAdvancedEvalRecord({
      ceremonyHandle: record.ceremonyHandle,
      addStageRequestDigestB64u,
    }),
  ).resolves.toBeNull();
});

test('Cloudflare D1 Router API auth service stores wallet registration intents in Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
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

    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2, 3],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(registration.intent.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: implicitNearAccountProvisioning(),
          signerSlot: 1,
          participantIds: [1, 2, 3],
          derivationVersion: 1,
        },
      ],
    });
    expect(parseServerAllocatedWalletId(registration.intent.walletId).ok).toBe(true);
    expect(String(registration.intent.walletId)).not.toMatch(/^seams-wallet-/);
    expect(Object.prototype.hasOwnProperty.call(registration.intent, 'rpId')).toBe(false);
    expect(registration.intent.authMethod).toMatchObject({ kind: 'passkey', rpId: 'example.com' });
    expect(registration.intent.runtimePolicyScope).toEqual({
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    });
    const parsedStoredSignerSetIntent = parseD1RegistrationIntent({
      version: 'registration_intent_v1',
      walletId: registration.intent.walletId,
      authMethod: { kind: 'passkey', rpId },
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: implicitNearAccountProvisioning(),
            signerSlot: 1,
            participantIds: [1, 2, 3],
            derivationVersion: 1,
          },
        ],
      },
      runtimePolicyScope: registration.intent.runtimePolicyScope,
      nonceB64u: 'stored-nonce',
    });
    expect(parsedStoredSignerSetIntent?.signerSelection).toEqual(
      registration.intent.signerSelection,
    );

    const addSigner = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId: registration.intent.walletId,
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            participantIds: [3, 2, 1],
            chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
          },
        },
      },
    });
    expect(addSigner.ok).toBe(true);
    if (!addSigner.ok) throw new Error(addSigner.message);

    const addAuthMethod = await service.walletAuthMethods.createAddAuthMethodIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId: registration.intent.walletId,
        authMethod: { kind: 'email_otp', email: 'owner@example.test' },
      },
    });
    expect(addAuthMethod.ok).toBe(true);
    if (!addAuthMethod.ok) throw new Error(addAuthMethod.message);

    const prefix = 'intent-test:wallet-registration:';
    const registrationRecord = durableObjects.stub.values.get(
      `${prefix}intent:${registration.registrationIntentGrant}`,
    );
    expect(registrationRecord).toMatchObject({
      kind: 'intent_allocated',
      digestB64u: registration.registrationIntentDigestB64u,
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      intent: registration.intent,
    });
    const serverAllocatedWalletReservationRequest = durableObjects.stub.requests.find(
      isRecordingDurableObjectReplayReservationRequest,
    );
    expect(recordingDurableObjectRequestKey(serverAllocatedWalletReservationRequest || {})).toBe(
      `${prefix}server-allocated-wallet-reservation:${registration.intent.walletId}`,
    );

    const providedWalletId = walletIdFromString('frost-fjord-rgcmpa');
    const providedRegistration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'provided', walletId: providedWalletId },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2, 3],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(providedRegistration.ok).toBe(true);
    if (!providedRegistration.ok) throw new Error(providedRegistration.message);
    expect(providedRegistration.intent.walletId).toBe(providedWalletId);
    expect(parseServerAllocatedWalletId(providedRegistration.intent.walletId).ok).toBe(true);
    expect(
      recordingDurableObjectRequestsIncludeKey(
        durableObjects.stub.requests,
        `${prefix}server-allocated-wallet-reservation:${providedWalletId}`,
      ),
    ).toBe(true);

    const addSignerRecord = durableObjects.stub.values.get(
      `${prefix}add-signer-intent:${addSigner.addSignerIntentGrant}`,
    );
    expect(addSignerRecord).toMatchObject({
      kind: 'add_signer_intent_allocated',
      digestB64u: addSigner.addSignerIntentDigestB64u,
      orgId: scope.orgId,
      intent: addSigner.intent,
    });
    expect(addSigner.intent.signerSelection).toEqual({
      mode: 'ecdsa',
      ecdsa: {
        participantIds: [3, 2, 1],
        chainTargets: [{ kind: 'evm', namespace: 'eip155', chainId: 8453 }],
      },
    });

    const addAuthMethodRecord = durableObjects.stub.values.get(
      `${prefix}add-auth-method-intent:${addAuthMethod.addAuthMethodIntentGrant}`,
    );
    expect(addAuthMethodRecord).toMatchObject({
      kind: 'add_auth_method_intent_allocated',
      digestB64u: addAuthMethod.addAuthMethodIntentDigestB64u,
      orgId: scope.orgId,
      intent: addAuthMethod.intent,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service cancels unconsumed registration intent wallet reservations', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-cancel-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const providedWalletId = walletIdFromString('frost-vermillion-k7p9m2');
    const request = {
      wallet: { kind: 'provided', walletId: providedWalletId },
      authMethod: { kind: 'passkey', rpId },
      signerSelection: {
        kind: 'signer_set',
        signers: [
          {
            kind: 'near_ed25519',
            accountProvisioning: implicitNearAccountProvisioning(),
            signerSlot: 1,
            participantIds: [1, 2, 3],
            derivationVersion: 1,
          },
        ],
      },
    } satisfies CreateRegistrationIntentRequest;
    const createInput = {
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request,
    };

    const registration = await service.walletRegistration.createRegistrationIntent(createInput);
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(parseServerAllocatedWalletId(registration.intent.walletId).ok).toBe(true);

    await expect(
      service.walletRegistration.createRegistrationIntent(createInput),
    ).resolves.toMatchObject({
      ok: false,
      message: 'walletId is already reserved',
    });

    await expect(
      service.walletRegistration.cancelRegistrationIntent({
        request: {
          registrationIntentGrant: registration.registrationIntentGrant,
          registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        },
      }),
    ).resolves.toEqual({
      ok: true,
      cancelled: true,
      releasedServerAllocatedWalletId: true,
    });

    const recreated = await service.walletRegistration.createRegistrationIntent(createInput);
    expect(recreated.ok).toBe(true);
    if (!recreated.ok) throw new Error(recreated.message);
    expect(recreated.intent.walletId).toBe(providedWalletId);

    const prefix = 'intent-cancel-test:wallet-registration:';
    expect(
      countRecordingDurableObjectRequests({
        requests: durableObjects.stub.requests,
        op: 'del',
        key: `${prefix}server-allocated-wallet-reservation:${providedWalletId}`,
      }),
    ).toBe(1);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects passkey registration challenge and origin mismatches before signer state', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdSigningService: {
        async ecdsaHssRoleLocalBootstrap() {
          throw new Error('threshold bootstrap must not run after passkey authority rejection');
        },
      } as unknown as ThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example.com',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: testEvmFamilyRegistrationSignerSet(),
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);

    await expect(
      service.walletRegistration.startWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        intent: registration.intent,
        authority: {
          kind: 'passkey',
          webauthnRegistration: fakeWebAuthnRegistrationCredential({
            challengeB64u: 'wrong-registration-challenge',
            origin: 'https://app.example.com',
          }),
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'challenge_mismatch',
      message: 'Registration challenge mismatch',
    });

    await expect(
      service.walletRegistration.startWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        intent: registration.intent,
        authority: {
          kind: 'passkey',
          webauthnRegistration: fakeWebAuthnRegistrationCredential({
            challengeB64u: registration.registrationIntentDigestB64u,
            origin: 'https://attacker.example.net',
          }),
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_origin',
      message: 'WebAuthn origin is not within rpId',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service finalizes passkey Ed25519 registration from durable advanced eval', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdSigningService: testCombinedRegistrationThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const origin = 'https://app.example.com';
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: origin,
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    const webauthnRegistration = await createWebAuthnRegistrationCredential({
      rpId,
      origin,
      challengeB64u: registration.registrationIntentDigestB64u,
    });
    const credentialIdB64u = String(webauthnRegistration.id || '').trim();
    expect(credentialIdB64u).toBeTruthy();

    const prepared = await service.walletRegistration.prepareWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority: {
        kind: 'passkey',
        webauthnRegistration,
      },
      prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
      work: { kind: 'ed25519_hss' },
    });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error(prepared.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      registrationPreparationId: prepared.registrationPreparationId,
      intent: registration.intent,
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.ed25519).toMatchObject({
      ceremonyHandle: 'ed25519-ceremony-handle',
      clientOtOfferMessageB64u: 'ed25519-client-ot-offer',
    });

    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'passkey-ed25519-client-request',
        },
      },
    });
    expect(responded.ok).toBe(true);
    if (!responded.ok) throw new Error(responded.message);

    const addStageRequestMessageB64u = base64UrlEncode(
      utf8Bytes('passkey-ed25519-add-stage-request'),
    );
    const advanced = await service.walletRegistration.advanceWalletRegistrationHssState({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        addStageRequestMessageB64u,
      },
    });
    expect(advanced.ok).toBe(true);
    if (!advanced.ok) throw new Error(advanced.message);

    const finalized = await service.walletRegistration.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'passkey-ed25519-finalize-replay-a',
      ed25519: {
        evaluationResult: {
          contextBindingB64u: 'ed25519-context-binding',
          stagedEvaluatorArtifactB64u: 'passkey-ed25519-staged-evaluator-artifact',
          addStageRequestMessageB64u,
        },
      },
    });
    expect(finalized.ok).toBe(true);
    if (!finalized.ok) throw new Error(finalized.message);
    expect(finalized.registrationDiagnostics?.ed25519HssFinalize?.source).toBe(
      'durable_advanced_eval',
    );
    expect(finalized).toMatchObject({
      walletId: registration.intent.walletId,
      rpId,
      authMethod: {
        kind: 'passkey',
        credentialIdB64u,
      },
      resolvedAccount: {
        kind: 'implicit_account',
        nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
      },
      ed25519: {
        nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
        publicKey: 'ed25519:combined-test-public-key',
        relayerKeyId: 'combined-test-relayer-key',
      },
    });
    await expect(
      readWebAuthnAuthenticatorRow({
        database,
        ...scope,
        userId: registration.intent.walletId,
        credentialIdB64u,
      }),
    ).resolves.toMatchObject({
      counter: 0,
    });
    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: `passkey:${rpId}:${credentialIdB64u}`,
      }),
    ).resolves.toMatchObject({
      kind: 'passkey',
      walletId: registration.intent.walletId,
      rpId,
      credentialIdB64u,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects stored registration intent wallet mismatch before HSS preparation', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdSigningService: {
        ed25519Hss: {
          async prepareForRegistration() {
            throw new Error('Ed25519 HSS prepare must not run after intent wallet mismatch');
          },
        },
      } as unknown as ThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const rpId = requireParsedDomainId(parseWebAuthnRpId('example.com'));
    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example.com',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: { kind: 'passkey', rpId },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);

    const intentKey = walletRegistrationDoKey({
      prefix: 'intent-test',
      scope: 'intent',
      id: registration.registrationIntentGrant,
    });
    const intentRecord = requireRecordingDurableObjectRecord({ durableObjects, key: intentKey });
    const storedIntent = requireNestedRecordingDurableObjectRecord({
      record: intentRecord,
      field: 'intent',
    });
    replaceRecordingDurableObjectRecord({
      durableObjects,
      key: intentKey,
      record: {
        ...intentRecord,
        intent: {
          ...storedIntent,
          walletId: walletIdFromString('stored-intent-mismatch.testnet'),
        },
      },
    });

    await expect(
      service.walletRegistration.prepareWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        intent: registration.intent,
        authority: {
          kind: 'passkey',
          webauthnRegistration: fakeWebAuthnRegistrationCredential({
            challengeB64u: registration.registrationIntentDigestB64u,
            origin: 'https://app.example.com',
          }),
        },
        prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
        work: { kind: 'ed25519_hss' },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'registration intent walletId mismatch',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service rejects stored registration preparation wallet mismatch before ceremony start', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService: testCombinedRegistrationThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    const authority = {
      kind: 'email_otp' as const,
      emailOtpRegistrationProof: {
        version: 'email_otp_registration_proof_v1' as const,
        proofKind: 'otp_challenge' as const,
        providerSubject,
        email,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp' as const,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        appSessionVersion,
      },
    };

    const prepared = await service.walletRegistration.prepareWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority,
      prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
      work: { kind: 'ed25519_hss' },
    });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error(prepared.message);

    const preparationKey = walletRegistrationDoKey({
      prefix: 'intent-test',
      scope: 'preparation',
      id: prepared.registrationPreparationId,
    });
    const preparationRecord = requireRecordingDurableObjectRecord({
      durableObjects,
      key: preparationKey,
    });
    const preparationAuthority = requireNestedRecordingDurableObjectRecord({
      record: preparationRecord,
      field: 'authority',
    });
    replaceRecordingDurableObjectRecord({
      durableObjects,
      key: preparationKey,
      record: {
        ...preparationRecord,
        authority: {
          ...preparationAuthority,
          walletId: walletIdFromString('registration-preparation-mismatch.testnet'),
        },
      },
    });

    await expect(
      service.walletRegistration.startWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        registrationPreparationId: prepared.registrationPreparationId,
        intent: registration.intent,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'scope_mismatch',
      message: 'registration preparation walletId mismatch',
    });
    expect(
      recordingDurableObjectKeysWithPrefix({
        durableObjects,
        prefix: 'intent-test:wallet-registration:ceremony:',
      }),
    ).toEqual([]);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service starts ECDSA wallet registration ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const rpId = 'example.com';
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
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

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: testEvmFamilyRegistrationSignerSet(),
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(Object.prototype.hasOwnProperty.call(registration.intent, 'rpId')).toBe(false);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
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
          registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
          appSessionVersion,
        },
      },
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.intent).toEqual(registration.intent);
    expect(started.ecdsa).toMatchObject({
      kind: 'evm_family_ecdsa_keygen',
      targets: [
        {
          chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
          prepare: {
            formatVersion: 'ecdsa-hss-role-local',
            walletId: registration.intent.walletId,
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
    if (!started.ecdsa) throw new Error('Expected ECDSA registration start payload');
    const ecdsaPrepare = requireSingleEcdsaPrepare(started.ecdsa);
    expect(ecdsaPrepare.evmFamilySigningKeySlotId).toContain(
      encodeURIComponent(`${scope.projectId}:${scope.envId}`),
    );
    expect(ecdsaPrepare.ecdsaThresholdKeyId).toMatch(/^ehss-/);
    expect(ecdsaPrepare.relayerKeyId).toMatch(/^ehss-relayer-/);

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}intent:${registration.registrationIntentGrant}`),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      intent: registration.intent,
      digestB64u: registration.registrationIntentDigestB64u,
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      authority: {
        kind: 'email_otp',
        proofKind: 'otp_challenge',
        walletId: registration.intent.walletId,
        providerSubject,
        email,
        challengeId: challenge.challenge.challengeId,
      },
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'evm_family_ecdsa_prepared',
            branchKey: 'evm_family_ecdsa:{"chainId":8453,"kind":"evm","namespace":"eip155"}',
            hssKind: 'evm_family_ecdsa_keygen',
            targets: [
              {
                chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
                prepare: ecdsaPrepare,
              },
            ],
          },
        ],
      },
    });

    const ceremonyKey = walletRegistrationDoKey({
      prefix: 'intent-test',
      scope: 'ceremony',
      id: started.registrationCeremonyId,
    });
    const ceremonyRecord = requireRecordingDurableObjectRecord({
      durableObjects,
      key: ceremonyKey,
    });
    const ceremonyAuthority = requireNestedRecordingDurableObjectRecord({
      record: ceremonyRecord,
      field: 'authority',
    });
    replaceRecordingDurableObjectRecord({
      durableObjects,
      key: ceremonyKey,
      record: {
        ...ceremonyRecord,
        authority: {
          ...ceremonyAuthority,
          walletId: walletIdFromString('registration-ceremony-mismatch.testnet'),
        },
      },
    });
    await expect(
      service.walletRegistration.respondWalletRegistrationHss({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          clientBootstraps: testEcdsaClientBootstrapTargets(started.ecdsa),
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'scope_mismatch',
      message: 'registration ceremony walletId mismatch',
    });

    await expect(
      service.walletRegistration.startWalletRegistration({
        registrationIntentGrant: registration.registrationIntentGrant,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        intent: registration.intent,
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
            registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
            appSessionVersion,
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

test('Cloudflare D1 Router API auth service starts and responds to combined Ed25519 and ECDSA registration ceremonies', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService: testCombinedRegistrationThresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: testCombinedRegistrationSignerSet(),
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    const authority = {
      kind: 'email_otp' as const,
      emailOtpRegistrationProof: {
        version: 'email_otp_registration_proof_v1' as const,
        proofKind: 'otp_challenge' as const,
        providerSubject,
        email,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp' as const,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        appSessionVersion,
      },
    };

    const prepared = await service.walletRegistration.prepareWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority,
      prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
      work: { kind: 'ed25519_hss_and_ecdsa' },
    });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error(prepared.message);
    expect(prepared.ed25519).toMatchObject({
      ceremonyHandle: 'ed25519-ceremony-handle',
      clientOtOfferMessageB64u: 'ed25519-client-ot-offer',
    });

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      registrationPreparationId: prepared.registrationPreparationId,
      intent: registration.intent,
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.ed25519).toMatchObject({
      ceremonyHandle: 'ed25519-ceremony-handle',
      clientOtOfferMessageB64u: 'ed25519-client-ot-offer',
    });
    expect(started.registrationDiagnostics?.entries).toEqual(
      expect.arrayContaining([expect.objectContaining({ name: 'registerStartTotalMs' })]),
    );
    expect(started.ecdsa).toMatchObject({
      kind: 'evm_family_ecdsa_keygen',
      targets: [
        {
          chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
          prepare: {
            walletId: registration.intent.walletId,
            signingRootId: `${scope.projectId}:${scope.envId}`,
            signingRootVersion: 'root-v1',
            keyScope: 'evm-family',
          },
        },
      ],
    });
    if (!started.ecdsa) throw new Error('Expected ECDSA registration start payload');
    const ecdsaPrepare = requireSingleEcdsaPrepare(started.ecdsa);

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}intent:${registration.registrationIntentGrant}`),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}preparation:${prepared.registrationPreparationId}`),
    ).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'near_ed25519_prepared',
            branchKey: 'near_ed25519:slot:1',
            ceremonyHandle: 'ed25519-ceremony-handle',
          },
          {
            kind: 'evm_family_ecdsa_prepared',
            branchKey: 'evm_family_ecdsa:{"chainId":8453,"kind":"evm","namespace":"eip155"}',
            targets: [
              {
                chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
                prepare: ecdsaPrepare,
              },
            ],
          },
        ],
      },
    });

    const clientBootstraps = testEcdsaClientBootstrapTargets(started.ecdsa);
    const clientBootstrap = clientBootstraps[0].clientBootstrap;
    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'ed25519-client-request',
        },
      },
      ecdsa: {
        clientBootstraps,
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(responded.ok).toBe(true);
    expect(responded.ed25519).toEqual({
      contextBindingB64u: 'ed25519-context-binding',
      serverInputDeliveryB64u: 'ed25519-server-input-delivery',
    });
    expect(responded.ecdsa?.bootstraps).toMatchObject([
      {
        chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
        bootstrap: {
          walletId: registration.intent.walletId,
          evmFamilySigningKeySlotId: ecdsaPrepare.evmFamilySigningKeySlotId,
          thresholdSessionId: clientBootstrap.thresholdSessionId,
          signingGrantId: clientBootstrap.signingGrantId,
        },
      },
    ]);
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'near_ed25519_responded',
            branchKey: 'near_ed25519:slot:1',
            responded: {
              serverInputDeliveryB64u: 'ed25519-server-input-delivery',
            },
          },
          {
            kind: 'evm_family_ecdsa_responded',
            branchKey: 'evm_family_ecdsa:{"chainId":8453,"kind":"evm","namespace":"eip155"}',
            responded: {
              bootstraps: [
                {
                  chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
                  bootstrap: {
                    thresholdSessionId: clientBootstrap.thresholdSessionId,
                  },
                },
              ],
            },
          },
        ],
      },
    });

    const enrollmentSealKeyVersion = 'combined-registration-seal-v1';
    const unlockKeyVersion = 'combined-registration-unlock-v1';
    const recoveryCodesIssuedAtMs = Date.now();
    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 9;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    const recoveryWrappedEnrollmentEscrows = makeRecoveryWrappedEnrollmentEscrows({
      walletId: registration.intent.walletId,
      userId: providerSubject,
      enrollmentId: `email-otp-device-enrollment-v1:${registration.intent.walletId}`,
      enrollmentSealKeyVersion,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      issuedAtMs: recoveryCodesIssuedAtMs,
    });

    const addStageRequestMessageB64u = base64UrlEncode(utf8Bytes('ed25519-add-stage-request'));
    const advanced = await service.walletRegistration.advanceWalletRegistrationHssState({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        addStageRequestMessageB64u,
      },
    });
    if (!advanced.ok) throw new Error(advanced.message);

    const finalized = await service.walletRegistration.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'combined-registration-finalize-replay-a',
      ed25519: {
        evaluationResult: {
          contextBindingB64u: 'ed25519-context-binding',
          stagedEvaluatorArtifactB64u: 'ed25519-staged-evaluator-artifact',
          addStageRequestMessageB64u,
        },
      },
      ecdsa: {
        expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
      },
      emailOtpEnrollment: {
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u: publicKeyB64u,
        unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
      },
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
        recoveryCodesIssuedAtMs,
        backupActionKind: 'copy',
        acknowledgedAtMs: recoveryCodesIssuedAtMs + 1,
        idempotencyKey: 'combined-registration-backup-ack-a',
      },
    });
    if (!finalized.ok) throw new Error(finalized.message);
    expect(finalized).toMatchObject({
      walletId: registration.intent.walletId,
      authMethod: {
        kind: 'email_otp',
        registrationAuthorityId: challenge.challenge.challengeId,
      },
      resolvedAccount: {
        kind: 'implicit_account',
        nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
      },
      ed25519: {
        nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
        publicKey: 'ed25519:combined-test-public-key',
        relayerKeyId: 'combined-test-relayer-key',
        keyVersion: 'threshold-ed25519-hss-v1',
        participantIds: [1, 2],
      },
      ecdsa: {
        walletKeys: [
          {
            keyScope: 'evm-family',
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
            walletId: registration.intent.walletId,
            evmFamilySigningKeySlotId: ecdsaPrepare.evmFamilySigningKeySlotId,
            keyHandle: 'test-add-signer-ecdsa-key-handle',
          },
        ],
      },
    });
    expect(finalized.registrationDiagnostics?.ed25519HssFinalize?.source).toBe(
      'durable_advanced_eval',
    );
    expect(Object.prototype.hasOwnProperty.call(finalized, 'rpId')).toBe(false);

    await expect(
      readWalletSignerRecord({
        database,
        ...scope,
        walletId: registration.intent.walletId,
        signerFamily: 'ed25519',
        signerId: `ed25519:${TEST_COMBINED_NEAR_ACCOUNT_ID}:1`,
      }),
    ).resolves.toMatchObject({
      version: 'wallet_signer_ed25519_v1',
      walletId: registration.intent.walletId,
      signerSlot: 1,
      nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
      publicKey: 'ed25519:combined-test-public-key',
      relayerKeyId: 'combined-test-relayer-key',
    });
    await expect(
      readWalletSignerRecord({
        database,
        ...scope,
        walletId: registration.intent.walletId,
        signerFamily: 'ecdsa',
        signerId: 'ecdsa:evm:eip155:8453',
      }),
    ).resolves.toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId: registration.intent.walletId,
      evmFamilySigningKeySlotId: ecdsaPrepare.evmFamilySigningKeySlotId,
      signerId: 'ecdsa:evm:eip155:8453',
      chainTargetKey: 'evm:eip155:8453',
      walletKey: {
        keyHandle: 'test-add-signer-ecdsa-key-handle',
        ecdsaThresholdKeyId: ecdsaPrepare.ecdsaThresholdKeyId,
      },
    });
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toBeUndefined();
    const ceremonyKey = `${prefix}ceremony:${started.registrationCeremonyId}`;
    expect(
      countRecordingDurableObjectRequests({
        requests: durableObjects.stub.requests,
        op: 'del',
        key: ceremonyKey,
      }),
    ).toBe(1);
    expect(
      countRecordingDurableObjectRequests({
        requests: durableObjects.stub.requests,
        op: 'getdel',
        key: ceremonyKey,
      }),
    ).toBe(0);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service finalizes Ed25519-only registration from durable finalized report', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const thresholdSigningService = {
      ed25519Hss: {
        async prepareForRegistration() {
          return {
            ok: true as const,
            ceremonyHandle: 'ed25519-only-ceremony-handle',
            preparedSession: {
              contextBindingB64u: 'ed25519-only-context-binding',
              evaluatorDriverStateB64u: 'ed25519-only-evaluator-driver-state',
            },
            clientOtOfferMessageB64u: 'ed25519-only-client-ot-offer',
            serverState: testEd25519PreparedServerState(),
          };
        },
        async respondForRegistration() {
          return {
            ok: true as const,
            contextBindingB64u: 'ed25519-only-context-binding',
            serverInputDeliveryB64u: 'ed25519-only-server-input-delivery',
            serverState: testEd25519RespondedServerState(),
          };
        },
        finalizeForRegistration: testEd25519FinalizeForRegistration,
      },
      getSchemeModule: testGetCombinedRegistrationSchemeModule,
    } as unknown as ThresholdSigningService;
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: {
          kind: 'signer_set',
          signers: [
            {
              kind: 'near_ed25519',
              accountProvisioning: implicitNearAccountProvisioning(),
              signerSlot: 1,
              participantIds: [1, 2],
              derivationVersion: 1,
            },
          ],
        },
      },
    });
    expect(registration.ok).toBe(true);
    if (!registration.ok) throw new Error(registration.message);
    expect(registration.intent.signerSelection).toEqual({
      kind: 'signer_set',
      signers: [
        {
          kind: 'near_ed25519',
          accountProvisioning: implicitNearAccountProvisioning(),
          signerSlot: 1,
          participantIds: [1, 2],
          derivationVersion: 1,
        },
      ],
    });

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    expect(challenge.ok).toBe(true);
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    expect(outbox.ok).toBe(true);
    if (!outbox.ok) throw new Error(outbox.message);
    const authority = {
      kind: 'email_otp' as const,
      emailOtpRegistrationProof: {
        version: 'email_otp_registration_proof_v1' as const,
        proofKind: 'otp_challenge' as const,
        providerSubject,
        email,
        challengeId: challenge.challenge.challengeId,
        otpCode: outbox.otpCode,
        otpChannel: 'email_otp' as const,
        registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
        appSessionVersion,
      },
    };

    const prepared = await service.walletRegistration.prepareWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
      authority,
      prepareGate: { kind: 'source_unavailable', reason: 'direct_service_call' },
      work: { kind: 'ed25519_hss' },
    });
    expect(prepared.ok).toBe(true);
    if (!prepared.ok) throw new Error(prepared.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      registrationPreparationId: prepared.registrationPreparationId,
      intent: registration.intent,
    });
    expect(started.ok).toBe(true);
    if (!started.ok) throw new Error(started.message);
    expect(started.ed25519).toMatchObject({
      ceremonyHandle: 'ed25519-only-ceremony-handle',
      clientOtOfferMessageB64u: 'ed25519-only-client-ot-offer',
    });
    expect(started.ecdsa).toBeUndefined();

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'near_ed25519_prepared',
            branchKey: 'near_ed25519:slot:1',
            ceremonyHandle: 'ed25519-only-ceremony-handle',
          },
        ],
      },
    });

    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ed25519: {
        clientRequest: {
          clientRequestMessageB64u: 'ed25519-only-client-request',
        },
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(responded.ed25519).toEqual({
      contextBindingB64u: 'ed25519-only-context-binding',
      serverInputDeliveryB64u: 'ed25519-only-server-input-delivery',
    });
    expect(responded.ecdsa).toBeUndefined();
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'near_ed25519_responded',
            branchKey: 'near_ed25519:slot:1',
            responded: {
              serverInputDeliveryB64u: 'ed25519-only-server-input-delivery',
            },
          },
        ],
      },
    });

    const addStageRequestMessageB64u = base64UrlEncode(utf8Bytes('ed25519-only-add-stage-request'));
    const addStageRequestDigestB64u = base64UrlEncode(
      await sha256(base64UrlDecode(addStageRequestMessageB64u)),
    );
    const hssContextBindingB64u = base64UrlEncode(new Uint8Array(32).fill(11));
    const store = new CloudflareD1RegistrationCeremonyIntentStore({
      namespace: durableObjects,
      objectName: 'threshold-store',
      prefix,
    });
    const ed25519EvaluationResult = {
      contextBindingB64u: hssContextBindingB64u,
      stagedEvaluatorArtifactB64u: 'ed25519-only-staged-evaluator-artifact',
      addStageRequestMessageB64u,
    };
    await store.putEd25519HssFinalizedReportRecord(
      buildD1DurableEd25519HssFinalizedReportRecord({
        ceremonyHandle: 'ed25519-only-ceremony-handle',
        contextBindingB64u: hssContextBindingB64u,
        addStageRequestDigestB64u,
        projectionMode: 'registration_output_only',
        finalizedReport: {
          contextBindingB64u: hssContextBindingB64u,
          clientOutputMessageB64u: base64UrlEncode(utf8Bytes('durable-finalized-client-output')),
          serverOutputMessageB64u: base64UrlEncode(utf8Bytes('durable-finalized-server-output')),
        },
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 60_000,
      }),
    );
    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        idempotencyKey: 'ed25519-only-output-only-finalized-report-replay-a',
        ed25519: {
          evaluationResult: ed25519EvaluationResult,
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_state',
      message: 'Ed25519 HSS durable finalized report projection mode is invalid',
    });

    await store.putEd25519HssFinalizedReportRecord(
      buildD1DurableEd25519HssFinalizedReportRecord({
        ceremonyHandle: 'ed25519-only-ceremony-handle',
        contextBindingB64u: hssContextBindingB64u,
        addStageRequestDigestB64u,
        projectionMode: 'registration_seed_and_output',
        finalizedReport: {
          contextBindingB64u: hssContextBindingB64u,
          clientOutputMessageB64u: base64UrlEncode(utf8Bytes('durable-finalized-client-output')),
          serverOutputMessageB64u: base64UrlEncode(utf8Bytes('durable-finalized-server-output')),
          seedOutputMessageB64u: base64UrlEncode(utf8Bytes('durable-finalized-seed-output')),
        },
        createdAtMs: Date.now(),
        expiresAtMs: Date.now() + 60_000,
      }),
    );

    const enrollmentSealKeyVersion = 'ed25519-only-registration-seal-v1';
    const unlockKeyVersion = 'ed25519-only-registration-unlock-v1';
    const recoveryCodesIssuedAtMs = Date.now();
    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 10;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    const recoveryWrappedEnrollmentEscrows = makeRecoveryWrappedEnrollmentEscrows({
      walletId: registration.intent.walletId,
      userId: providerSubject,
      enrollmentId: `email-otp-device-enrollment-v1:${registration.intent.walletId}`,
      enrollmentSealKeyVersion,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      issuedAtMs: recoveryCodesIssuedAtMs,
    });

    const finalized = await service.walletRegistration.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'ed25519-only-durable-finalized-report-replay-a',
      ed25519: {
        evaluationResult: ed25519EvaluationResult,
      },
      emailOtpEnrollment: {
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u: publicKeyB64u,
        unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
      },
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
        recoveryCodesIssuedAtMs,
        backupActionKind: 'copy',
        acknowledgedAtMs: recoveryCodesIssuedAtMs + 1,
        idempotencyKey: 'ed25519-only-backup-ack-a',
      },
    });
    if (!finalized.ok) throw new Error(finalized.message);
    expect(finalized.registrationDiagnostics?.ed25519HssFinalize?.source).toBe(
      'durable_finalized_report',
    );
    expect(finalized).toMatchObject({
      walletId: registration.intent.walletId,
      resolvedAccount: {
        kind: 'implicit_account',
        nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
      },
      ed25519: {
        nearAccountId: TEST_COMBINED_NEAR_ACCOUNT_ID,
        publicKey: 'ed25519:combined-test-public-key',
        relayerKeyId: 'combined-test-relayer-key',
      },
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service responds to ECDSA wallet registration ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const rpId = 'example.com';
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
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
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: testEvmFamilyRegistrationSignerSet(),
      },
    });
    if (!registration.ok) throw new Error(registration.message);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    if (!outbox.ok) throw new Error(outbox.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
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
          registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
          appSessionVersion,
        },
      },
    });
    if (!started.ok) throw new Error(started.message);
    if (!started.ecdsa) throw new Error('Expected ECDSA registration start payload');

    const ecdsaPrepare = requireSingleEcdsaPrepare(started.ecdsa);
    const clientBootstraps = testEcdsaClientBootstrapTargets(started.ecdsa);
    const clientBootstrap = clientBootstraps[0].clientBootstrap;
    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
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
          walletId: registration.intent.walletId,
          evmFamilySigningKeySlotId: ecdsaPrepare.evmFamilySigningKeySlotId,
          thresholdSessionId: clientBootstrap.thresholdSessionId,
          signingGrantId: clientBootstrap.signingGrantId,
        },
      },
    ]);
    expect(bootstrapRequest).toMatchObject({
      sessionId: clientBootstrap.thresholdSessionId,
      signingGrantId: clientBootstrap.signingGrantId,
      runtimePolicyScope: registration.intent.runtimePolicyScope,
    });

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toMatchObject({
      signerState: {
        kind: 'signer_set_registration',
        branches: [
          {
            kind: 'evm_family_ecdsa_responded',
            branchKey: 'evm_family_ecdsa:{"chainId":8453,"kind":"evm","namespace":"eip155"}',
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
        ],
      },
    });

    await expect(
      service.walletRegistration.respondWalletRegistrationHss({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          clientBootstraps,
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_state',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service finalizes ECDSA wallet registration ceremonies through Durable Objects', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const rpId = 'example.com';
    const email = 'owner@example.test';
    const providerSubject = 'google:registration-user';
    const appSessionVersion = 'registration-session-v1';
    const durableObjects = new RecordingDurableObjectNamespace();
    const thresholdSigningService = {
      async ecdsaHssRoleLocalBootstrap(request: EcdsaHssClientBootstrapRequest) {
        return {
          ok: true as const,
          value: testEcdsaServerBootstrapResponse(request),
        };
      },
    } as unknown as ThresholdSigningService;
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      thresholdSigningService,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });

    const registration = await service.walletRegistration.createRegistrationIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        wallet: { kind: 'server_allocated' },
        authMethod: {
          kind: 'email_otp',
          proofKind: 'otp_challenge',
          email,
          otpCode: 'intent-otp-placeholder',
          appSessionJwt: 'intent-session-placeholder',
        },
        signerSelection: testEvmFamilyRegistrationSignerSet(),
      },
    });
    if (!registration.ok) throw new Error(registration.message);

    const challenge = await service.emailOtp.createEmailOtpEnrollmentChallenge({
      userId: providerSubject,
      walletId: registration.intent.walletId,
      orgId: scope.orgId,
      email,
      otpChannel: 'email_otp',
      sessionHash: registration.registrationIntentDigestB64u,
      appSessionVersion,
    });
    if (!challenge.ok) throw new Error(challenge.message);
    const outbox = await service.emailOtp.readEmailOtpOutboxEntry({
      challengeId: challenge.challenge.challengeId,
      userId: providerSubject,
      walletId: registration.intent.walletId,
    });
    if (!outbox.ok) throw new Error(outbox.message);

    const started = await service.walletRegistration.startWalletRegistration({
      registrationIntentGrant: registration.registrationIntentGrant,
      registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
      intent: registration.intent,
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
          registrationIntentDigestB64u: registration.registrationIntentDigestB64u,
          appSessionVersion,
        },
      },
    });
    if (!started.ok) throw new Error(started.message);
    if (!started.ecdsa) throw new Error('Expected ECDSA registration start payload');

    const ecdsaPrepare = requireSingleEcdsaPrepare(started.ecdsa);
    const clientBootstraps = testEcdsaClientBootstrapTargets(started.ecdsa);
    const responded = await service.walletRegistration.respondWalletRegistrationHss({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        clientBootstraps,
      },
    });
    if (!responded.ok) throw new Error(responded.message);

    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['wrong-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'key_handle_mismatch',
    });

    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        ecdsa: {
          expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'Email OTP registration finalize requires emailOtpEnrollment',
    });

    const enrollmentSealKeyVersion = 'registration-seal-v1';
    const unlockKeyVersion = 'registration-unlock-v1';
    const recoveryCodesIssuedAtMs = Date.now();
    const privateKey32 = new Uint8Array(32);
    privateKey32[31] = 7;
    const publicKey33 = await secp256k1PrivateKey32ToPublicKey33(privateKey32);
    const publicKeyB64u = base64UrlEncode(publicKey33);
    const recoveryWrappedEnrollmentEscrows = makeRecoveryWrappedEnrollmentEscrows({
      walletId: registration.intent.walletId,
      userId: providerSubject,
      enrollmentId: `email-otp-device-enrollment-v1:${registration.intent.walletId}`,
      enrollmentSealKeyVersion,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      issuedAtMs: recoveryCodesIssuedAtMs,
    });

    const finalized = await service.walletRegistration.finalizeWalletRegistration({
      registrationCeremonyId: started.registrationCeremonyId,
      idempotencyKey: 'registration-finalize-replay-a',
      ecdsa: {
        expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
      },
      emailOtpEnrollment: {
        recoveryWrappedEnrollmentEscrows,
        enrollmentSealKeyVersion,
        clientUnlockPublicKeyB64u: publicKeyB64u,
        unlockKeyVersion,
        thresholdEcdsaClientVerifyingShareB64u: publicKeyB64u,
      },
      emailOtpBackupAck: {
        kind: 'email_otp_recovery_code_backup_ack_v1',
        recoveryCodesIssuedAtMs,
        backupActionKind: 'copy',
        acknowledgedAtMs: recoveryCodesIssuedAtMs + 1,
        idempotencyKey: 'registration-backup-ack-a',
      },
    });
    if (!finalized.ok) throw new Error(finalized.message);
    expect(Object.prototype.hasOwnProperty.call(finalized, 'rpId')).toBe(false);
    expect(finalized).toMatchObject({
      walletId: registration.intent.walletId,
      authMethod: {
        kind: 'email_otp',
        registrationAuthorityId: challenge.challenge.challengeId,
      },
      ecdsa: {
        walletKeys: [
          {
            keyScope: 'evm-family',
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
            walletId: registration.intent.walletId,
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

    const walletRecord = await readSignerWalletRecord({
      database,
      ...scope,
      walletId: registration.intent.walletId,
    });
    expect(walletRecord).toMatchObject({
      version: 'wallet_v1',
      walletId: registration.intent.walletId,
      createdAtMs: expect.any(Number),
      updatedAtMs: expect.any(Number),
    });
    expect(Object.prototype.hasOwnProperty.call(walletRecord, 'rpId')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(walletRecord, 'rp_id')).toBe(false);

    const emailHashHex = hexBytes(await sha256(utf8Bytes(email)));
    await expect(
      readWalletAuthMethodRecord({
        database,
        ...scope,
        walletAuthMethodId: `email_otp:${registration.intent.walletId}:${emailHashHex}`,
      }),
    ).resolves.toMatchObject({
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId: registration.intent.walletId,
      emailHashHex,
      registrationAuthorityId: challenge.challenge.challengeId,
    });
    await expect(
      service.emailOtp.readEmailOtpEnrollment({
        walletId: registration.intent.walletId,
        orgId: scope.orgId,
      }),
    ).resolves.toMatchObject({
      ok: true,
      enrollment: {
        walletId: registration.intent.walletId,
        providerUserId: providerSubject,
        orgId: scope.orgId,
        verifiedEmail: email,
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
        walletId: registration.intent.walletId,
      }),
    ).resolves.toBe(EMAIL_OTP_RECOVERY_KEY_COUNT);

    const signerRecord = await readWalletSignerRecord({
      database,
      ...scope,
      walletId: registration.intent.walletId,
      signerFamily: 'ecdsa',
      signerId: 'ecdsa:evm:eip155:8453',
    });
    expect(signerRecord).toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId: registration.intent.walletId,
      evmFamilySigningKeySlotId: ecdsaPrepare.evmFamilySigningKeySlotId,
      signerId: 'ecdsa:evm:eip155:8453',
      chainTargetKey: 'evm:eip155:8453',
      walletKey: {
        keyHandle: 'test-add-signer-ecdsa-key-handle',
        ecdsaThresholdKeyId: ecdsaPrepare.ecdsaThresholdKeyId,
        thresholdOwnerAddress: '0x0000000000000000000000000000000000000001',
      },
    });

    const prefix = 'intent-test:wallet-registration:';
    expect(
      durableObjects.stub.values.get(`${prefix}ceremony:${started.registrationCeremonyId}`),
    ).toBeUndefined();
    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
        idempotencyKey: 'registration-finalize-replay-a',
        ecdsa: {
          expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: true,
      walletId: registration.intent.walletId,
      ecdsa: {
        walletKeys: [
          {
            keyHandle: 'test-add-signer-ecdsa-key-handle',
          },
        ],
      },
    });
    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        registrationCeremonyId: started.registrationCeremonyId,
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
