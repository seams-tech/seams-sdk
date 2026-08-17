import { expect, test } from '@playwright/test';
import { parseCorrelationId } from '@shared/utils/canonicalPrimitives';
import {
  D1WalletStore,
  parseWalletEd25519SignerRecord,
} from '../../packages/sdk-server-ts/src/core/d1WalletStore';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1/auth/d1RouterApiAuthService';
import type {
  RouterAbEd25519YaoProductRegistrationRuntimeV1,
  RouterAbEd25519YaoWalletSessionMintInputV1,
} from '../../packages/sdk-server-ts/src/router/domains/ed25519Yao/capabilityLifecycle/routerAbEd25519YaoProductRegistration';
import { normalizeRuntimePolicyScope } from '../../packages/shared-ts/src/threshold/signingRootScope';
import {
  registrationNearEd25519BranchKey,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import type { RouterAbEd25519YaoRegistrationAdmissionRequestV1 } from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import { type RouterAbEcdsaVerifiedClientActivationFactsV1 } from '../../packages/shared-ts/src/utils/routerAbEcdsaDerivation';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import type { D1DatabaseLike } from '../../packages/sdk-server-ts/src/storage/tenantRoute';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import { buildEd25519YaoCapabilityFixture } from '../helpers/ed25519YaoCapabilityFixtures';
import {
  buildFixtureRouterAbEcdsaStrictRegistrationRequest,
  createRouterAbSigningRuntimesForUnitTests,
  fixtureRouterAbEcdsaActivationFacts,
  fixtureRouterAbEcdsaMaterialActivation,
  FixtureRouterAbEcdsaStrictRegistrationPort,
  SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort,
} from '../helpers/routerAbSigningRuntimeTestUtils';
import { base64UrlDecode } from '../../packages/shared-ts/src/utils/encoders';
import { computeWalletAddSignerEcdsaActivationRequestDigestB64u } from '../../packages/shared-ts/src/utils/walletAddSignerActivation';
import {
  RecordingDurableObjectNamespace,
  requireSingleEcdsaPrepare,
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
const TEST_ECDSA_ACTIVATION_FACTS: RouterAbEcdsaVerifiedClientActivationFactsV1 =
  fixtureRouterAbEcdsaActivationFacts();
const TEST_ECDSA_MATERIAL_ACTIVATION = fixtureRouterAbEcdsaMaterialActivation(
  'strict-add-signer-wallet.testnet',
);

function yaoBytes(seed: number): number[] {
  return new Array<number>(32).fill(seed);
}

async function reopenAddSignerFinalizeCompletionAsStaleClaim(input: {
  readonly database: D1DatabaseLike;
  readonly scope: {
    readonly namespace: string;
    readonly orgId: string;
    readonly projectId: string;
    readonly envId: string;
  };
  readonly addSignerCeremonyId: string;
}): Promise<void> {
  await input.database
    .prepare(
      `UPDATE router_ab_yao_versioned_json_records
          SET record_json = json_remove(
            json_set(
              record_json,
              '$.kind',
              'router_ab_ed25519_yao_registration_side_effect_claim_v1',
              '$.claimedAtMs',
              0
            ),
            '$.completedAtMs',
            '$.response'
          )
        WHERE namespace = ?1
          AND org_id = ?2
          AND project_id = ?3
          AND env_id = ?4
          AND record_key = ?5`,
    )
    .bind(
      input.scope.namespace,
      input.scope.orgId,
      input.scope.projectId,
      input.scope.envId,
      `wallet-add-signer-finalize:add-signer-finalize:${input.addSignerCeremonyId}`,
    )
    .run();
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
      session_id: request.scope.threshold_session_id,
      signer_set_id: request.scope.signer_set_id,
      selected_server_id: request.scope.signing_worker_id,
    },
    operation: 'registration',
    session_id: TEST_YAO_SESSION_ID,
    stable_key_context_binding: yaoBytes(8),
    material_activation: request.scope.material_activation,
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

  async bindVerifiedIntent(
    input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']>[0],
  ): ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']> {
    this.admissionRequest = input.admissionRequest;
    return { ok: true };
  }

  bindAndAdmitVerifiedRegistration(): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['bindAndAdmitVerifiedRegistration']
  > {
    throw new Error('wallet registration is outside the add-signer runtime fixture');
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
            material_activation: binding.material_activation,
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
    const expiresAtMs =
      input.kind === 'verified_wallet_unlock_v1' ? input.expiresAtMs : Date.now() + 60_000;
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
        walletSessionId: input.walletSessionId,
        quotaId: input.quotaId,
        expiresAtMs,
        participantIds: [input.participantIds[0], input.participantIds[1]],
        remainingUses: input.remainingUses,
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

test('passkey Ed25519 budget refresh accepts current session identity independently of registration provenance', async () => {
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
    const registrationThresholdSessionId = 'threshold-session-registration';
    const currentThresholdSessionId = 'threshold-session-current';
    const currentWalletSessionId = 'wallet-session-current';
    const currentQuotaId = 'wallet-quota-current';
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
      thresholdSessionId: registrationThresholdSessionId,
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
      thresholdSessionId: registrationThresholdSessionId,
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
      // The signer records the manifest its key set was registered against;
      // the parser has required it since custody commits became mandatory.
      custodyKeyManifestDigestB64u: 'Lcwi4R-zFWWooZJB2zonKJtBMlynySPIjt55tietXWE',
      createdAtMs: 1_000,
      updatedAtMs: 1_000,
    });
    expect(persistedSigner).not.toBeNull();
    if (!persistedSigner) throw new Error('test Ed25519 signer did not parse');

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
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: {
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: TEST_YAO_SIGNING_WORKER_ID,
      },
    });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      ...scope,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ed25519YaoProductRegistration: yaoRuntime,
    });

    const refreshed = await service.walletRegistration.refreshEd25519YaoWalletSession({
      kind: 'router_ab_ed25519_yao_budget_refresh_v1',
      sessionPolicy: {
        version: 'threshold_session_v1',
        nearAccountId,
        nearEd25519SigningKeyId,
        authority,
        relayerKeyId: TEST_YAO_SIGNING_WORKER_ID,
        thresholdSessionId: currentThresholdSessionId,
        walletSessionId: currentWalletSessionId,
        quotaId: currentQuotaId,
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
        kind: 'verified_passkey_assertion_router_ab_ed25519_yao_budget_refresh_v1',
        authority,
        verifiedChallengeId: 'passkey-budget-refresh-challenge',
      },
    });
    expect(refreshed).toMatchObject({
      ok: true,
      walletId,
      thresholdSessionId: currentThresholdSessionId,
      remainingUses: 1,
    });
    if (!refreshed.ok) throw new Error(refreshed.message);
    expect(refreshed.walletSessionId).not.toBe(currentWalletSessionId);
    expect(refreshed.quotaId).not.toBe(currentQuotaId);
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('Cloudflare D1 Router API auth service adds Email OTP wallet auth methods through partitioned D1', async () => {
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
      command: {
        subject: {
          kind: 'wallet_auth_method_management',
          walletId,
        },
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
      subject: {
        kind: 'wallet_auth_method_management',
        walletId,
      },
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

    const emailHashHex = hexBytes(await sha256(utf8Bytes(email)));
    await expect(
      service.walletAuthMethods.finalizeWalletAddAuthMethod({
        authorization: { kind: 'owner' as const },
        subject: {
          kind: 'wallet_auth_method_management',
          walletId: walletIdFromString('different-wallet.testnet'),
        },
        addAuthMethodCeremonyId: started.addAuthMethodCeremonyId,
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'invalid_body',
      message: 'add-auth-method ceremony subject mismatch',
    });
    const finalized = await service.walletAuthMethods.finalizeWalletAddAuthMethod({
      authorization: { kind: 'owner' as const },
      subject: {
        kind: 'wallet_auth_method_management',
        walletId,
      },
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
        authorization: { kind: 'owner' as const },
        subject: {
          kind: 'wallet_auth_method_management',
          walletId,
        },
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

test('partitioned D1 completes and replays the strict ECDSA add-signer lifecycle', async () => {
  const { database, tempDir } = createTemporaryD1Database();
  try {
    await applySignerMigrations(database);
    const scope = {
      namespace: 'seams-local-test',
      orgId: 'org-a',
      projectId: 'project-a',
      envId: 'env-a',
    };
    const walletId = walletIdFromString('strict-add-signer-wallet.testnet');
    const durableObjects = new RecordingDurableObjectNamespace();
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
      config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker' },
    });
    const strictRegistration = new SuccessfulFixtureRouterAbEcdsaStrictRegistrationPort();
    await insertSignerWallet({ database, ...scope, walletId });
    const service = createCloudflareD1RouterApiAuthService({
      database,
      namespace: scope.namespace,
      orgId: scope.orgId,
      projectId: scope.projectId,
      envId: scope.envId,
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
      ecdsaStrictRegistration: strictRegistration,
      thresholdStore: {
        kind: 'cloudflare-do',
        namespace: durableObjects,
        THRESHOLD_PREFIX: 'strict-add-signer-test',
        ROUTER_AB_NORMAL_SIGNING_WORKER_ID: 'test-threshold-signing-worker',
      },
    });
    const intent = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      command: {
        subject: {
          kind: 'wallet_signer_management',
          walletId,
        },
        signerSelection: {
          mode: 'ecdsa',
          ecdsa: {
            participantIds: [1, 2],
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
    if (!started.ok || !started.ecdsa) throw new Error('Expected ECDSA add-signer start');
    expect(started.ecdsa.strictRegistration.registration_purpose).toBe('wallet_add_signer');

    const strictRequest = buildFixtureRouterAbEcdsaStrictRegistrationRequest(
      started.ecdsa.strictRegistration,
    );
    const responded = await service.walletAuthMethods.respondWalletAddSignerEcdsaDerivation({
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_v1',
        strictRegistration: strictRequest,
      },
    });
    if (!responded.ok) throw new Error(responded.message);
    expect(strictRegistration.registrationRequest).toEqual(strictRequest);
    await expect(
      service.walletAuthMethods.respondWalletAddSignerEcdsaDerivation({
        addSignerCeremonyId: started.addSignerCeremonyId,
        ecdsa: {
          kind: 'router_ab_ecdsa_registration_v1',
          strictRegistration: strictRequest,
        },
      }),
    ).resolves.toEqual(responded);

    /* The digest is the client's now: no preparation route hands it back, so
       the commit carries the digest of the canonical add-signer activation
       command and the service recomputes it from the same coordinates. */
    const activationCorrelationId = parseCorrelationId('activation-correlation-add-signer');
    const canonicalActivationDigestB64u =
      await computeWalletAddSignerEcdsaActivationRequestDigestB64u({
        addSignerCeremonyId: started.addSignerCeremonyId,
        activationCorrelationId,
        publicFacts: TEST_ECDSA_ACTIVATION_FACTS,
      });
    const activationCommitRequest = {
      addSignerCeremonyId: started.addSignerCeremonyId,
      ecdsa: {
        kind: 'router_ab_ecdsa_registration_activation_v1' as const,
        activationCorrelationId,
        publicFacts: TEST_ECDSA_ACTIVATION_FACTS,
        expectedActivationRequestDigest: {
          bytes: Array.from(base64UrlDecode(canonicalActivationDigestB64u)),
        },
        materialActivation: TEST_ECDSA_MATERIAL_ACTIVATION,
      },
    };
    await expect(
      service.walletAuthMethods.activateWalletAddSignerEcdsa({
        addSignerCeremonyId: activationCommitRequest.addSignerCeremonyId,
        ecdsa: {
          ...activationCommitRequest.ecdsa,
          expectedActivationRequestDigest: { bytes: new Array<number>(32).fill(13) },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'activation_digest_mismatch',
    });
    /* Crash reconciliation: the Router commits custody and the caller dies
       before the ceremony records it. The claim written before the Router leg
       is what lets the retry below finish the ceremony instead of stranding a
       wallet whose signer the Router already holds. */
    strictRegistration.failAfterNextActivationCommit = true;
    await expect(
      service.walletAuthMethods.activateWalletAddSignerEcdsa(activationCommitRequest),
    ).resolves.toMatchObject({ ok: false });
    const activated =
      await service.walletAuthMethods.activateWalletAddSignerEcdsa(activationCommitRequest);
    if (!activated.ok) throw new Error(activated.message);
    /* Completion is queryable by replaying the commit: same coordinates, same
       receipt, byte for byte. */
    await expect(
      service.walletAuthMethods.activateWalletAddSignerEcdsa(activationCommitRequest),
    ).resolves.toEqual(activated);
    await expect(
      service.walletAuthMethods.activateWalletAddSignerEcdsa({
        addSignerCeremonyId: activationCommitRequest.addSignerCeremonyId,
        ecdsa: {
          ...activationCommitRequest.ecdsa,
          expectedActivationRequestDigest: { bytes: new Array<number>(32).fill(13) },
        },
      }),
    ).resolves.toMatchObject({
      ok: false,
      code: 'activation_digest_mismatch',
    });

    const finalizeRequest = {
      kind: 'evm_family_ecdsa' as const,
      addSignerCeremonyId: started.addSignerCeremonyId,
      idempotencyKey: 'strict-ecdsa-add-signer-finalize',
      ecdsa: { expectedKeyHandles: [activated.ecdsa.bootstrap.keyHandle] },
    };
    const finalized = await service.walletAuthMethods.finalizeWalletAddSigner(finalizeRequest);
    if (!finalized.ok) throw new Error(finalized.message);
    expect(finalized).toMatchObject({
      kind: 'evm_family_ecdsa',
      walletId,
      ecdsa: {
        walletKeys: [
          {
            walletId,
            keyHandle: activated.ecdsa.bootstrap.keyHandle,
            chainTarget: { kind: 'evm', namespace: 'eip155', chainId: 8453 },
          },
        ],
      },
    });
    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner(finalizeRequest),
    ).resolves.toEqual(finalized);
    await expect(
      service.walletAuthMethods.finalizeWalletAddSigner({
        kind: 'evm_family_ecdsa',
        addSignerCeremonyId: finalizeRequest.addSignerCeremonyId,
        idempotencyKey: 'strict-ecdsa-add-signer-conflict',
        ecdsa: { expectedKeyHandles: [activated.ecdsa.bootstrap.keyHandle] },
      }),
    ).resolves.toMatchObject({ ok: false, code: 'idempotency_conflict' });
    await expect(
      readWalletSignerRecord({
        database,
        ...scope,
        walletId,
        signerFamily: 'ecdsa',
        signerId: 'ecdsa:evm:eip155:8453',
      }),
    ).resolves.toMatchObject({
      version: 'wallet_signer_ecdsa_v1',
      walletId,
      walletKey: { keyHandle: activated.ecdsa.bootstrap.keyHandle },
    });
  } finally {
    cleanupTemporaryD1Database(tempDir);
  }
});

test('partitioned D1 finalizes and replays Ed25519 Yao add-signer without request substitution', async () => {
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
    const routerAbSigningRuntimes = createRouterAbSigningRuntimesForUnitTests({
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
      routerAbSigningRuntimes: routerAbSigningRuntimes.runtimes,
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
      command: {
        subject: {
          kind: 'wallet_signer_management',
          walletId,
        },
        signerSelection,
      },
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
            threshold_session_id: started.addSignerCeremonyId,
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
      },
    });
    expect(yaoRuntime.consumeCalls).toBe(1);
    expect(yaoRuntime.freshConsumptions).toBe(1);
    expect(yaoRuntime.installCalls).toBe(1);

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
    await reopenAddSignerFinalizeCompletionAsStaleClaim({
      database,
      scope,
      addSignerCeremonyId: started.addSignerCeremonyId,
    });
    await expect(service.walletAuthMethods.finalizeWalletAddSigner(exactFinalize)).resolves.toEqual(
      finalized,
    );
    expect(yaoRuntime.consumeCalls).toBe(1);
    expect(yaoRuntime.freshConsumptions).toBe(1);

    const conflictingIntent = await service.walletAuthMethods.createAddSignerIntent({
      orgId: scope.orgId,
      signingRootId: `${scope.projectId}:${scope.envId}`,
      signingRootVersion: 'root-v1',
      expectedOrigin: 'https://app.example',
      command: {
        subject: {
          kind: 'wallet_signer_management',
          walletId,
        },
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
