import { expect, test } from '@playwright/test';
import type { EcdsaHssClientBootstrapRequest } from '../../packages/sdk-server-ts/src/core/types';
import {
  D1WalletStore,
  parseWalletEd25519SignerRecord,
} from '../../packages/sdk-server-ts/src/core/d1WalletStore';
import type { ThresholdSigningService } from '../../packages/sdk-server-ts/src/core/ThresholdService/ThresholdSigningService';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import type {
  RouterAbEd25519YaoProductRegistrationRuntimeV1,
  RouterAbEd25519YaoWalletSessionMintInputV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';
import { normalizeRuntimePolicyScope } from '../../packages/shared-ts/src/threshold/signingRootScope';
import {
  registrationNearEd25519BranchKey,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import type { RouterAbEd25519YaoRegistrationAdmissionRequestV1 } from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import { createThresholdSigningServiceForUnitTests } from '../helpers/thresholdServiceTestUtils';
import {
  RecordingDurableObjectNamespace,
  requireSingleEcdsaPrepare,
  testEcdsaClientBootstrapTargets,
  testEcdsaServerBootstrapResponse,
  utf8Bytes,
  sha256,
  hexBytes,
  applySignerMigrations,
  insertSignerWallet,
  insertWalletAuthMethod,
  readWalletAuthMethodRecord,
  readWalletSignerRecord,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';

const TEST_YAO_SIGNING_WORKER_ID = 'test-yao-signing-worker';
const TEST_YAO_SESSION_ID = new Array<number>(32).fill(7);

function yaoBytes(seed: number): number[] {
  return new Array<number>(32).fill(seed);
}

function yaoRegistrationBinding(
  request: RouterAbEd25519YaoRegistrationAdmissionRequestV1,
): Record<string, unknown> {
  return {
    lifecycle: {
      lifecycle_id: request.scope.lifecycle_id,
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: request.scope.root_share_epoch,
      account_id: request.scope.account_id,
      session_id: request.scope.wallet_session_id,
      signer_set_id: request.scope.signer_set_id,
      selected_server_id: request.scope.signing_worker_id,
    },
    operation: 'registration',
    session_id: TEST_YAO_SESSION_ID,
    stable_key_context_binding: yaoBytes(8),
  };
}

function yaoClientPackage(
  deriver: 'deriver_a' | 'deriver_b',
  ciphertextSeed: number,
): Record<string, unknown> {
  return {
    kind: 'activation_client',
    deriver,
    session: TEST_YAO_SESSION_ID,
    transcript: yaoBytes(11),
    encapsulated_key: yaoBytes(ciphertextSeed + 1),
    ciphertext: yaoBytes(ciphertextSeed),
  };
}

function testWebAuthnAssertionCredential(credentialIdB64u: string) {
  return {
    id: credentialIdB64u,
    rawId: credentialIdB64u,
    type: 'public-key' as const,
    authenticatorAttachment: null,
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature',
      userHandle: null,
    },
    clientExtensionResults: {},
  };
}

type TestEd25519WalletSessionBudget = {
  readonly signingGrantId: string;
  readonly expiresAtMs: number;
  readonly remainingUses: number;
};

function assertNeverTestWalletSessionMintInput(input: never): never {
  throw new Error(`Unexpected test Wallet Session mint kind: ${String(input)}`);
}

function testEd25519WalletSessionBudget(
  input: RouterAbEd25519YaoWalletSessionMintInputV1,
): TestEd25519WalletSessionBudget {
  switch (input.kind) {
    case 'registration_wallet_session_v1':
    case 'add_signer_wallet_session_v1':
      return {
        signingGrantId: 'test-add-signer-signing-grant',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: 3,
      };
    case 'email_otp_recovery_wallet_session_v1':
      return {
        signingGrantId: 'test-email-otp-recovery-signing-grant',
        expiresAtMs: Date.now() + 60_000,
        remainingUses: input.remainingUses,
      };
    case 'shared_registration_wallet_session_v1':
    case 'same_identity_budget_refresh_v1':
      return {
        signingGrantId: input.signingGrantId,
        expiresAtMs: input.expiresAtMs,
        remainingUses: input.remainingUses,
      };
  }
  return assertNeverTestWalletSessionMintInput(input);
}

class TestEd25519YaoAddSignerRuntime implements RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  readonly kind = 'router_ab_ed25519_yao_product_registration_runtime_v1' as const;
  readonly signingWorkerId = TEST_YAO_SIGNING_WORKER_ID;
  private admissionRequest: RouterAbEd25519YaoRegistrationAdmissionRequestV1 | null = null;
  private consumerBinding: string | null = null;
  private consumedActivation: Extract<
    ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']>,
    { ok: true }
  > | null = null;
  consumeCalls = 0;
  freshConsumptions = 0;
  installCalls = 0;
  mintCalls = 0;

  async bindVerifiedIntent(
    input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']>[0],
  ): ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']> {
    this.admissionRequest = input.admissionRequest;
    return { ok: true };
  }

  consumeActivated(
    request: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']>[0],
  ): ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']> {
    this.consumeCalls += 1;
    if (this.consumedActivation) {
      if (request.consumerBinding === this.consumerBinding) return this.consumedActivation;
      return {
        ok: false,
        code: 'activation_consumed',
        message: 'activation belongs to another finalize request',
      };
    }
    const admissionRequest = this.admissionRequest;
    if (
      !admissionRequest ||
      request.reference.lifecycleId !== admissionRequest.scope.lifecycle_id ||
      request.reference.sessionId.some((byte, index) => byte !== TEST_YAO_SESSION_ID[index])
    ) {
      return {
        ok: false,
        code: 'activation_reference_mismatch',
        message: 'activation reference mismatch',
      };
    }
    this.freshConsumptions += 1;
    const binding = yaoRegistrationBinding(admissionRequest);
    const consumed = {
      ok: true,
      activation: {
        admissionRequest,
        admissionReceipt: {
          binding,
          keyset: {
            deriver_a_input_public_key: yaoBytes(1),
            deriver_b_input_public_key: yaoBytes(2),
            signing_worker_recipient_public_key: yaoBytes(3),
          },
        },
        result: {
          binding,
          deriver_a_client_package: yaoClientPackage('deriver_a', 21),
          deriver_b_client_package: yaoClientPackage('deriver_b', 22),
          public_receipt: {
            transcript: yaoBytes(11),
            registered_public_key: yaoBytes(12),
            joined_client_commitment: yaoBytes(13),
            joined_signing_worker_commitment: yaoBytes(14),
            signing_worker_verifying_share: yaoBytes(14),
            state_epoch: 1,
          },
        },
      },
    } as const;
    this.consumerBinding = request.consumerBinding;
    this.consumedActivation = consumed;
    return consumed;
  }

  installRegistrationFinalizeCapability(
    input: Parameters<
      RouterAbEd25519YaoProductRegistrationRuntimeV1['installRegistrationFinalizeCapability']
    >[0],
  ): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['installRegistrationFinalizeCapability']
  > {
    this.installCalls += 1;
    return {
      ok: true,
      disposition: 'installed',
      activeCapabilityBinding: input.activeCapabilityBinding,
      registeredPublicKey: input.registrationResult.public_receipt.registered_public_key,
      stateEpoch: input.registrationResult.public_receipt.state_epoch,
    };
  }

  installPersistedActiveCapability(
    input: Parameters<
      RouterAbEd25519YaoProductRegistrationRuntimeV1['installPersistedActiveCapability']
    >[0],
  ): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['installPersistedActiveCapability']
  > {
    this.installCalls += 1;
    return {
      ok: true,
      disposition: 'installed',
      activeCapabilityBinding: input.activeCapabilityBinding,
      registeredPublicKey: input.activationResult.public_receipt.registered_public_key,
      stateEpoch: input.activationResult.public_receipt.state_epoch,
    };
  }

  resolveActiveCapability(): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['resolveActiveCapability']
  > {
    return { ok: false, code: 'unknown_capability', message: 'not used by add-signer test' };
  }

  async mintWalletSession(
    input: RouterAbEd25519YaoWalletSessionMintInputV1,
  ): ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['mintWalletSession']> {
    this.mintCalls += 1;
    const budget = testEd25519WalletSessionBudget(input);
    return {
      ok: true,
      session: {
        sessionKind: 'jwt',
        walletSessionJwt: 'test.ed25519.yao.wallet.session',
        walletId: input.walletId,
        nearAccountId: input.nearAccountId,
        nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
        authorityScope: { kind: 'passkey_rp', rpId: 'example.com' },
        thresholdSessionId: input.thresholdSessionId,
        signingGrantId: budget.signingGrantId,
        expiresAtMs: budget.expiresAtMs,
        participantIds: [input.participantIds[0], input.participantIds[1]],
        remainingUses: budget.remainingUses,
        signingRootId: `${input.runtimePolicyScope.projectId}:${input.runtimePolicyScope.envId}`,
        signingRootVersion: input.runtimePolicyScope.signingRootVersion,
        runtimePolicyScope: input.runtimePolicyScope,
        routerAbNormalSigning: {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: TEST_YAO_SIGNING_WORKER_ID,
        },
      },
    };
  }
}

test('passkey Ed25519 budget refresh accepts the current grant independently of the durable signer snapshot', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    } as const;
    const walletId = walletIdFromString('passkey-budget-refresh.testnet');
    const nearAccountId = 'passkey-budget-refresh.testnet';
    const nearEd25519SigningKeyId = 'near-ed25519-key-refresh';
    const thresholdSessionId = 'threshold-session-stable';
    const currentSigningGrantId = 'signing-grant-current';
    const rpId = 'example.com';
    const credentialIdB64u = 'passkey-budget-refresh-credential';
    const participantIds = [1, 2] as const;
    const runtimePolicyScope = normalizeRuntimePolicyScope({
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      signingRootVersion: 'root-v1',
    });
    const authority = buildPasskeyWalletAuthAuthority({
      walletId,
      rpId,
      credentialIdB64u,
    });
    const activeYao = buildEd25519YaoCapabilityFixture({
      walletId,
      nearAccountId,
      nearEd25519SigningKeyId,
      thresholdSessionId,
      signerSlot: 1,
      signingWorkerId: TEST_YAO_SIGNING_WORKER_ID,
      participantIds,
      runtimePolicyScope,
      seed: 81,
    });
    const persistedSigner = parseWalletEd25519SignerRecord({
      version: 'wallet_signer_ed25519_v1',
      walletId,
      signerId: `ed25519:${nearAccountId}:1`,
      nearAccountId,
      nearEd25519SigningKeyId,
      thresholdSessionId,
      signingGrantId: 'obsolete-registration-grant',
      signerSlot: 1,
      publicKey: activeYao.publicKey,
      signingWorkerId: TEST_YAO_SIGNING_WORKER_ID,
      keyVersion: 'router-ab-ed25519-yao-v1',
      recoveryExportCapable: true,
      participantIds,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: runtimePolicyScope.signingRootVersion,
      runtimePolicyScope,
      activeYaoCapability: activeYao.capability,
      createdAtMs: 1_000,
      updatedAtMs: 1_000,
    });
    expect(persistedSigner).not.toBeNull();
    if (!persistedSigner) throw new Error('test Ed25519 signer did not parse');
    expect(Object.hasOwn(persistedSigner, 'signingGrantId')).toBe(false);

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
        credentialIdB64u,
        credentialPublicKeyB64u: 'test-passkey-public-key',
        counter: 0,
        createdAtMs: 1_000,
        updatedAtMs: 1_000,
      },
    });
    const walletStore = new D1WalletStore({
      database,
      ...scope,
      ensureSchema: false,
    });
    await walletStore.putSigner(persistedSigner);

    const yaoRuntime = new TestEd25519YaoAddSignerRuntime();
    const thresholdSigningRuntimes = createThresholdSigningServiceForUnitTests({
      config: {
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: TEST_YAO_SIGNING_WORKER_ID,
      },
    });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      ...scope,
      thresholdSigningRuntimes: {
        thresholdSigningService: thresholdSigningRuntimes.svc,
        routerAbNormalSigningRuntime: thresholdSigningRuntimes.routerAbNormalSigningRuntime,
      },
      ed25519YaoProductRegistration: yaoRuntime,
    });

    await expect(
      service.walletRegistration.refreshEd25519YaoWalletSession({
        kind: 'router_ab_ed25519_yao_budget_refresh_v1',
        sessionPolicy: {
          version: 'threshold_session_v1',
          nearAccountId,
          nearEd25519SigningKeyId,
          authority,
          relayerKeyId: TEST_YAO_SIGNING_WORKER_ID,
          thresholdSessionId,
          signingGrantId: currentSigningGrantId,
          runtimePolicyScope,
          routerAbNormalSigning: {
            kind: 'router_ab_ed25519_normal_signing_v1',
            signingWorkerId: TEST_YAO_SIGNING_WORKER_ID,
          },
          participantIds,
          ttlMs: 60_000,
          remainingUses: 1,
        },
        authorization: {
          kind: 'verified_passkey_router_ab_ed25519_yao_budget_refresh_v1',
          authority,
        },
      }),
    ).resolves.toMatchObject({
      ok: true,
      walletId,
      thresholdSessionId,
      signingGrantId: currentSigningGrantId,
      remainingUses: 1,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

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
    const { routerAbNormalSigningRuntime } = createThresholdSigningServiceForUnitTests({
      config: {
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    await insertSignerWallet({ database, ...scope, walletId });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      thresholdSigningRuntimes: {
        thresholdSigningService,
        routerAbNormalSigningRuntime,
      },
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
        kind: 'evm_family_ecdsa',
        addSignerCeremonyId: started.addSignerCeremonyId,
        idempotencyKey: 'ecdsa-add-signer-finalize-wrong-key',
        ecdsa: {
          expectedKeyHandles: ['wrong-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'key_handle_mismatch',
    });

    const finalized = await service.walletAuthMethods.finalizeWalletAddSigner({
      kind: 'evm_family_ecdsa',
      addSignerCeremonyId: started.addSignerCeremonyId,
      idempotencyKey: 'ecdsa-add-signer-finalize-success',
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
        kind: 'evm_family_ecdsa',
        addSignerCeremonyId: started.addSignerCeremonyId,
        idempotencyKey: 'ecdsa-add-signer-finalize-after-cleanup',
        ecdsa: {
          expectedKeyHandles: ['test-add-signer-ecdsa-key-handle'],
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'idempotency_conflict',
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service finalizes and replays Ed25519 Yao add-signer without request substitution', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('ed25519-yao-add-signer.testnet');
    const rpId = 'example.com';
    const credentialIdB64u = 'Y3JlZGVudGlhbC0x';
    const durableObjects = new RecordingDurableObjectNamespace();
    const yaoRuntime = new TestEd25519YaoAddSignerRuntime();
    const thresholdSigningRuntimes = createThresholdSigningServiceForUnitTests({
      config: {
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: TEST_YAO_SIGNING_WORKER_ID,
      },
    });
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
        credentialIdB64u,
        credentialPublicKeyB64u: 'test-passkey-public-key',
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
      thresholdSigningRuntimes: {
        thresholdSigningService: thresholdSigningRuntimes.svc,
        routerAbNormalSigningRuntime: thresholdSigningRuntimes.routerAbNormalSigningRuntime,
      },
      ed25519YaoProductRegistration: yaoRuntime,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'intent-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: TEST_YAO_SIGNING_WORKER_ID,
      },
    });
    const signerSelection = {
      mode: 'ed25519' as const,
      ed25519: {
        mode: 'create_implicit_near_account' as const,
        signerSlot: 3,
        participantIds: [1, 2] as [number, number],
        keyPurpose: 'near_tx' as const,
        keyVersion: 'router-ab-ed25519-yao-v1',
        derivationVersion: 1,
      },
    };
    const intent = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: { walletId, signerSelection },
    });
    if (!intent.ok) throw new Error(intent.message);
    const started = await service.walletAuthMethods.startWalletAddSigner({
      walletId,
      addSignerIntentGrant: intent.addSignerIntentGrant,
      addSignerIntentDigestB64u: intent.addSignerIntentDigestB64u,
      intent: intent.intent,
      auth: {
        kind: 'webauthn_assertion',
        rpId,
        credential: testWebAuthnAssertionCredential(credentialIdB64u),
        expectedChallengeDigestB64u: intent.addSignerIntentDigestB64u,
      },
    });
    if (!started.ok) throw new Error(started.message);
    expect(started).toMatchObject({
      kind: 'near_ed25519',
      intent: intent.intent,
      ed25519: {
        admissionRequest: {
          scope: {
            lifecycle_id: started.addSignerCeremonyId,
            wallet_session_id: started.addSignerCeremonyId,
            signer_set_id: registrationNearEd25519BranchKey(3),
            signing_worker_id: TEST_YAO_SIGNING_WORKER_ID,
          },
          application_binding: {
            wallet_id: walletId,
            signing_root_id: `${scope.projectId}:${scope.envId}`,
            key_creation_signer_slot: 3,
          },
          participant_ids: [1, 2],
        },
      },
    });

    const ceremonyKey = `intent-test:wallet-registration:add-signer:${started.addSignerCeremonyId}`;
    const exactFinalize = {
      kind: 'near_ed25519' as const,
      addSignerCeremonyId: started.addSignerCeremonyId,
      idempotencyKey: 'ed25519-yao-add-signer-finalize-1',
      ed25519: {
        activationReference: {
          kind: 'router_ab_ed25519_yao_activation_reference_v1' as const,
          lifecycle_id: started.addSignerCeremonyId,
          session_id: TEST_YAO_SESSION_ID,
        },
      },
    };
    durableObjects.stub.rejectNextSet(ceremonyKey);
    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner(exactFinalize),
    ).resolves.toMatchObject({ ok: false, code: 'internal' });
    expect(yaoRuntime.consumeCalls).toBe(1);
    expect(yaoRuntime.freshConsumptions).toBe(1);
    expect(yaoRuntime.mintCalls).toBe(0);
    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner({
        ...exactFinalize,
        idempotencyKey: 'ed25519-yao-add-signer-post-consume-takeover',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'activation_consumed' });

    durableObjects.stub.rejectNextGetDel(ceremonyKey);
    const finalized = await service.walletAuthMethods.finalizeWalletAddSigner(exactFinalize);
    if (!finalized.ok) throw new Error(finalized.message);
    expect(finalized).toMatchObject({
      kind: 'near_ed25519',
      walletId,
      rpId,
      credentialIdB64u,
      ed25519: {
        signerSlot: 3,
        relayerKeyId: TEST_YAO_SIGNING_WORKER_ID,
        participantIds: [1, 2],
        session: {
          thresholdSessionId: started.addSignerCeremonyId,
          routerAbNormalSigning: { signingWorkerId: TEST_YAO_SIGNING_WORKER_ID },
        },
      },
    });
    expect(yaoRuntime.consumeCalls).toBe(3);
    expect(yaoRuntime.freshConsumptions).toBe(1);
    expect(yaoRuntime.mintCalls).toBe(1);
    expect(yaoRuntime.installCalls).toBe(1);
    expect(durableObjects.stub.values.get(ceremonyKey)).toBeDefined();

    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner({
        ...exactFinalize,
        ed25519: {
          activationReference: {
            ...exactFinalize.ed25519.activationReference,
            session_id: yaoBytes(31),
          },
        },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'idempotency_conflict' });
    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner({
        ...exactFinalize,
        idempotencyKey: 'ed25519-yao-add-signer-takeover',
      }),
    ).resolves.toMatchObject({ ok: false, code: 'idempotency_conflict' });
    await expect(service.walletAuthMethods.finalizeWalletAddSigner(exactFinalize)).resolves.toEqual(
      finalized,
    );
    expect(yaoRuntime.consumeCalls).toBe(3);
    expect(yaoRuntime.freshConsumptions).toBe(1);
    expect(durableObjects.stub.values.get(ceremonyKey)).toBeUndefined();

    const conflictingIntent = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      request: {
        walletId,
        signerSelection: {
          ...signerSelection,
          ed25519: { ...signerSelection.ed25519, participantIds: [2, 3] },
        },
      },
    });
    if (!conflictingIntent.ok) throw new Error(conflictingIntent.message);
    await expect(
      service.walletAuthMethods.startWalletAddSigner({
        walletId,
        addSignerIntentGrant: conflictingIntent.addSignerIntentGrant,
        addSignerIntentDigestB64u: conflictingIntent.addSignerIntentDigestB64u,
        intent: conflictingIntent.intent,
        auth: {
          kind: 'webauthn_assertion',
          rpId,
          credential: testWebAuthnAssertionCredential(credentialIdB64u),
          expectedChallengeDigestB64u: conflictingIntent.addSignerIntentDigestB64u,
        },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'signer_conflict' });

    const signerId = `ed25519:${finalized.ed25519.nearAccountId}:3`;
    await expect(
      readWalletSignerRecord({
        database,
        ...scope,
        walletId,
        signerFamily: 'ed25519',
        signerId,
      }),
    ).resolves.toMatchObject({
      version: 'wallet_signer_ed25519_v1',
      walletId,
      signerId,
      signerSlot: 3,
      participantIds: [1, 2],
      signingWorkerId: TEST_YAO_SIGNING_WORKER_ID,
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});
