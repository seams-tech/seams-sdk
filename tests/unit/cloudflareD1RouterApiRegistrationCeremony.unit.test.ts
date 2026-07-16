import { expect, test } from '@playwright/test';
import type { EcdsaDerivationClientBootstrapRequest } from '../../packages/sdk-server-ts/src/core/types';
import type { CreateRegistrationIntentRequest } from '../../packages/sdk-server-ts/src/core/registrationContracts';
import type { RouterAbSigningRuntimeBundle } from '../../packages/sdk-server-ts/src/core/routerAbSigning/createRouterAbSigningRuntimes';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { parseD1RegistrationIntent } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RegistrationCeremonyRecords';
import { base64UrlEncode } from '../../packages/shared-ts/src/utils/encoders';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import {
  createRouterAbSigningRuntimesForUnitTests,
  FixtureRouterAbEcdsaBootstrapExportPort,
} from '../helpers/routerAbSigningRuntimeTestUtils';
import {
  implicitNearAccountProvisioning,
  parseServerAllocatedWalletId,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import { EMAIL_OTP_RECOVERY_KEY_COUNT } from '../../packages/shared-ts/src/utils/emailOtpRecoveryKey';
import { secp256k1PrivateKey32ToPublicKey33 } from '../../packages/sdk-server-ts/src/core/ThresholdService/evmCryptoWasm';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  testEvmFamilyRegistrationSignerSet,
  requireParsedDomainId,
  RecordingDurableObjectNamespace,
  isRecordingDurableObjectReplayReservationRequest,
  recordingDurableObjectRequestKey,
  countRecordingDurableObjectRequests,
  recordingDurableObjectRequestsIncludeKey,
  walletRegistrationDoKey,
  requireRecordingDurableObjectRecord,
  replaceRecordingDurableObjectRecord,
  requireNestedRecordingDurableObjectRecord,
  requireSingleEcdsaPrepare,
  testEcdsaClientBootstrapTargets,
  testEcdsaServerBootstrapResponse,
  utf8Bytes,
  sha256,
  hexBytes,
  fakeWebAuthnRegistrationCredential,
  applySignerMigrations,
  readWalletAuthMethodRecord,
  readSignerWalletRecord,
  readWalletSignerRecord,
  makeRecoveryWrappedEnrollmentEscrows,
  countActiveRecoveryWrappedEnrollmentEscrows,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

async function successfulFixtureEcdsaBootstrap(
  request: EcdsaDerivationClientBootstrapRequest,
): Promise<{
  readonly ok: true;
  readonly value: ReturnType<typeof testEcdsaServerBootstrapResponse>;
}> {
  return { ok: true, value: testEcdsaServerBootstrapResponse(request) };
}

async function rejectUnexpectedEcdsaBootstrap(): Promise<never> {
  throw new Error('ECDSA bootstrap must not run after passkey authority rejection');
}

function runtimeBundleWithBootstrapPort(input: {
  readonly base: ReturnType<typeof createRouterAbSigningRuntimesForUnitTests>;
  readonly bootstrapPort: FixtureRouterAbEcdsaBootstrapExportPort;
}): RouterAbSigningRuntimeBundle {
  return {
    normalSigning: input.base.normalSigning,
    localSigningSeed: input.base.localSigningSeed,
    ecdsaBootstrapExport: { kind: 'configured', runtime: input.bootstrapPort },
    ecdsaPresign: input.base.ecdsaPresign,
  };
}

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
    const runtimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker' },
    });
    const bootstrapPort = new FixtureRouterAbEcdsaBootstrapExportPort(
      runtimes.ecdsaBootstrapExport,
      rejectUnexpectedEcdsaBootstrap,
    );
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      routerAbSigningRuntimes: runtimeBundleWithBootstrapPort({ base: runtimes, bootstrapPort }),
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
            formatVersion: 'ecdsa-derivation-role-local',
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
    expect(ecdsaPrepare.ecdsaThresholdKeyId).toMatch(/^ederivation-/);
    expect(ecdsaPrepare.relayerKeyId).toMatch(/^ederivation-relayer-/);

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
            derivationKind: 'evm_family_ecdsa_keygen',
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
      service.walletRegistration.respondWalletRegistrationDerivation({
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
    const runtimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker' },
    });
    const bootstrapPort = new FixtureRouterAbEcdsaBootstrapExportPort(
      runtimes.ecdsaBootstrapExport,
      successfulFixtureEcdsaBootstrap,
    );
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      routerAbSigningRuntimes: runtimeBundleWithBootstrapPort({ base: runtimes, bootstrapPort }),
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
    const responded = await service.walletRegistration.respondWalletRegistrationDerivation({
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
    expect(bootstrapPort.bootstrapRequests[0]).toMatchObject({
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
            derivationKind: 'evm_family_ecdsa_keygen',
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
      service.walletRegistration.respondWalletRegistrationDerivation({
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

test('Cloudflare D1 Router API auth service replays finalized ECDSA registration and cleans a ceremony after delete failure', async () => {
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
    const runtimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker' },
    });
    const bootstrapPort = new FixtureRouterAbEcdsaBootstrapExportPort(
      runtimes.ecdsaBootstrapExport,
      successfulFixtureEcdsaBootstrap,
    );
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      emailOtpDeliveryMode: 'dev_d1_outbox',
      routerAbSigningRuntimes: runtimeBundleWithBootstrapPort({ base: runtimes, bootstrapPort }),
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
    const responded = await service.walletRegistration.respondWalletRegistrationDerivation({
      registrationCeremonyId: started.registrationCeremonyId,
      ecdsa: {
        clientBootstraps,
      },
    });
    if (!responded.ok) throw new Error(responded.message);

    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        kind: 'evm_family_ecdsa',
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
        kind: 'evm_family_ecdsa',
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
    const prefix = 'intent-test:wallet-registration:';
    const ceremonyKey = `${prefix}ceremony:${started.registrationCeremonyId}`;
    durableObjects.stub.rejectNextDelete(ceremonyKey);

    const finalized = await service.walletRegistration.finalizeWalletRegistration({
      kind: 'evm_family_ecdsa',
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

    expect(durableObjects.stub.values.get(ceremonyKey)).toBeDefined();
    expect(
      durableObjects.stub.values.get(
        `${prefix}finalize-replay:${started.registrationCeremonyId}:registration-finalize-replay-a`,
      ),
    ).toBeDefined();
    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        kind: 'evm_family_ecdsa',
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
    expect(durableObjects.stub.values.get(ceremonyKey)).toBeUndefined();
    await expect(
      service.walletRegistration.finalizeWalletRegistration({
        kind: 'evm_family_ecdsa',
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
