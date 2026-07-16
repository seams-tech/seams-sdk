import { expect, test } from '@playwright/test';
import {
  signingRootScopeFromRuntimePolicyScope,
  type RuntimePolicyScope,
} from '../../packages/shared-ts/src/threshold/signingRootScope';
import {
  registrationNearEd25519BranchKey,
  walletIdFromString,
} from '../../packages/shared-ts/src/utils/registrationIntent';
import {
  parseRouterAbEd25519YaoRegistrationActivationResultV1,
  parseRouterAbEd25519YaoRegistrationAdmissionRequestV1,
} from '../../packages/shared-ts/src/utils/routerAbEd25519Yao';
import { thresholdEd25519AuthorityScopeFromWalletAuthAuthority } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';
import { D1WalletStore } from '../../packages/sdk-server-ts/src/core/d1WalletStore';
import type { RouterApiWalletUnlockService } from '../../packages/sdk-server-ts/src/router/authServicePort';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import {
  buildYaoEd25519WalletSignerRecord,
  ed25519NearPublicKeyFromBytes,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1Ed25519YaoWalletSigner';
import type {
  RouterAbEd25519YaoProductRegistrationRuntimeV1,
  RouterAbEd25519YaoWalletSessionMintInputV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';
import type {
  RouterAbEd25519YaoActiveCapabilityDescriptorV1,
  RouterAbEd25519YaoActiveCapabilityLookupResultV1,
  RouterAbEd25519YaoActiveCapabilityLookupV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import { buildRouterAbEd25519YaoRegistrationCapabilityRecordV1 } from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import type {
  RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1,
  RouterAbEd25519YaoEmailOtpRecoverySessionResponseV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoWalletSession';
import {
  handleWalletUnlockVerifyRoute,
  type EmitWalletUnlockEmailOtpWebhook,
  type EmitWalletUnlockRouterApiWebhook,
} from '../../packages/sdk-server-ts/src/router/walletUnlockRouteHandlers';
import {
  parseWalletUnlockEd25519YaoRequest,
  ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND,
} from '../../packages/sdk-server-ts/src/router/walletUnlockEd25519YaoRequestValidation';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  applySignerMigrations,
  insertSignerWallet,
  insertWalletAuthMethod,
} from './helpers/cloudflareD1RouterApiAuthService.fixtures';
import { createRouterAbSigningRuntimesForUnitTests } from '../helpers/routerAbSigningRuntimeTestUtils';

const WALLET_ID = walletIdFromString('wallet-email-yao-1.testnet');
const ORG_ID = 'org-email-yao';
const PROJECT_ID = 'project-email-yao';
const ENV_ID = 'env-email-yao';
const ROOT_VERSION = 'root-email-yao-v1';
const PROVIDER_USER_ID = 'google:subject-email-yao';
const CHALLENGE_ID = 'unlock-challenge-email-yao';
const NEAR_ACCOUNT_ID = 'wallet-email-yao-1.testnet';
const NEAR_SIGNING_KEY_ID = 'ed25519ks_email_yao_1';
const SIGNING_WORKER_ID = 'signing-worker-email-yao';
const THRESHOLD_SESSION_ID = 'threshold-session-email-yao';
const PARTICIPANT_IDS = [17, 29] as const;
const SIGNER_SLOT = 2;
const REQUESTED_REMAINING_USES = 3;
const REGISTERED_PUBLIC_KEY = new Array<number>(32).fill(47);
const EMAIL_HASH_HEX = 'ab'.repeat(32);

function fixtureBytes(seed: number, length = 32): number[] {
  return new Array<number>(length).fill(seed);
}

function activationClientPackageFixture(
  session: readonly number[],
  deriver: 'deriver_a' | 'deriver_b',
) {
  return {
    kind: 'activation_client',
    deriver,
    session,
    transcript: fixtureBytes(33),
    encapsulated_key: fixtureBytes(deriver === 'deriver_a' ? 34 : 35),
    ciphertext: fixtureBytes(deriver === 'deriver_a' ? 36 : 37, 16),
  };
}

function activeYaoCapabilityRecordFixture() {
  const signingRoot = signingRootScopeFromRuntimePolicyScope(RUNTIME_POLICY_SCOPE);
  const admissionRequest = parseRouterAbEd25519YaoRegistrationAdmissionRequestV1({
    scope: {
      lifecycle_id: 'registration-email-yao-1',
      root_share_epoch: ROOT_VERSION,
      account_id: WALLET_ID,
      wallet_session_id: THRESHOLD_SESSION_ID,
      signer_set_id: String(registrationNearEd25519BranchKey(SIGNER_SLOT)),
      signing_worker_id: SIGNING_WORKER_ID,
    },
    application_binding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: signingRoot.signingRootId,
      key_creation_signer_slot: SIGNER_SLOT,
    },
    participant_ids: PARTICIPANT_IDS,
  });
  if (!admissionRequest.ok) throw new Error(admissionRequest.message);
  const binding = {
    lifecycle: {
      lifecycle_id: 'registration-email-yao-1',
      work_kind: 'registration_prepare',
      primitive_request_kind: 'registration',
      root_share_epoch: ROOT_VERSION,
      account_id: WALLET_ID,
      session_id: THRESHOLD_SESSION_ID,
      signer_set_id: String(registrationNearEd25519BranchKey(SIGNER_SLOT)),
      selected_server_id: SIGNING_WORKER_ID,
    },
    operation: 'registration',
    session_id: fixtureBytes(31),
    stable_key_context_binding: fixtureBytes(32),
  };
  const activationResult = parseRouterAbEd25519YaoRegistrationActivationResultV1({
    binding,
    deriver_a_client_package: activationClientPackageFixture(
      binding.session_id,
      'deriver_a',
    ),
    deriver_b_client_package: activationClientPackageFixture(
      binding.session_id,
      'deriver_b',
    ),
    public_receipt: {
      transcript: fixtureBytes(33),
      registered_public_key: REGISTERED_PUBLIC_KEY,
      joined_client_commitment: fixtureBytes(39),
      joined_signing_worker_commitment: fixtureBytes(40),
      signing_worker_verifying_share: fixtureBytes(40),
      state_epoch: 1,
    },
  });
  if (!activationResult.ok) throw new Error(activationResult.message);
  const built = buildRouterAbEd25519YaoRegistrationCapabilityRecordV1({
    kind: 'router_ab_ed25519_yao_registration_finalize_capability_v1',
    activeCapabilityBinding: binding.session_id,
    nearAccountId: NEAR_ACCOUNT_ID,
    registrationAdmissionRequest: admissionRequest.value,
    registrationResult: activationResult.value,
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
  });
  if (!built.ok) throw new Error(built.message);
  return built.record;
}

const RUNTIME_POLICY_SCOPE: RuntimePolicyScope = {
  orgId: ORG_ID,
  projectId: PROJECT_ID,
  envId: ENV_ID,
  signingRootVersion: ROOT_VERSION,
};

function activeCapabilityFixture(
  substitution: 'none' | 'wallet',
): RouterAbEd25519YaoActiveCapabilityDescriptorV1 {
  const signingRoot = signingRootScopeFromRuntimePolicyScope(RUNTIME_POLICY_SCOPE);
  const capabilityWalletId = substitution === 'wallet' ? 'substituted-wallet.testnet' : WALLET_ID;
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    activeCapabilityBinding: new Array<number>(32).fill(31),
    registeredPublicKey: REGISTERED_PUBLIC_KEY,
    nearAccountId: NEAR_ACCOUNT_ID,
    applicationBinding: {
      wallet_id: capabilityWalletId,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: signingRoot.signingRootId,
      key_creation_signer_slot: SIGNER_SLOT,
    },
    runtimePolicyScope: RUNTIME_POLICY_SCOPE,
    participantIds: PARTICIPANT_IDS,
    lifecycle: {
      lifecycleId: 'wallet-unlock-email-otp-lifecycle',
      rootShareEpoch: ROOT_VERSION,
      accountId: capabilityWalletId,
      walletSessionId: THRESHOLD_SESSION_ID,
      signerSetId: String(registrationNearEd25519BranchKey(SIGNER_SLOT)),
      signingWorkerId: SIGNING_WORKER_ID,
    },
    stateEpoch: 1,
  };
}

function unlockBodyFixture(): Record<string, unknown> {
  return {
    unlockBackend: 'email_otp',
    walletId: WALLET_ID,
    orgId: ORG_ID,
    challengeId: CHALLENGE_ID,
    unlockProof: {
      publicKey: 'unlock-public-key',
      signature: 'unlock-signature',
    },
    ed25519YaoRecovery: {
      kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND,
      signerSlot: SIGNER_SLOT,
      remainingUses: REQUESTED_REMAINING_USES,
    },
  };
}

function recoveryRequestFixture(): RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1 {
  return {
    kind: 'router_ab_ed25519_yao_email_otp_recovery_session_v1',
    walletId: WALLET_ID,
    orgId: ORG_ID,
    signerSlot: SIGNER_SLOT,
    remainingUses: REQUESTED_REMAINING_USES,
    verifiedChallengeId: CHALLENGE_ID,
    verifiedProviderUserId: PROVIDER_USER_ID,
  };
}

class VerifiedEmailOtpUnlockService implements RouterApiWalletUnlockService {
  async createEmailOtpUnlockChallenge(): Promise<never> {
    throw new Error('unused');
  }

  async createWebAuthnLoginOptions(): Promise<never> {
    throw new Error('unused');
  }

  async markEmailOtpStrongAuthSatisfied(): Promise<never> {
    throw new Error('unused');
  }

  async verifyWebAuthnLogin(): Promise<never> {
    throw new Error('unused');
  }

  async verifyEmailOtpUnlockProof() {
    return {
      ok: true,
      verified: true,
      userId: WALLET_ID,
      walletId: WALLET_ID,
      providerUserId: PROVIDER_USER_ID,
      orgId: ORG_ID,
      unlockKeyVersion: 'unlock-key-email-yao-v1',
    } as const;
  }
}

class RecordingRouteRecoveryService {
  readonly calls: RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1[] = [];

  async recoverEd25519YaoEmailOtpWalletSession(
    request: RouterAbEd25519YaoEmailOtpRecoverySessionRequestV1,
  ): Promise<RouterAbEd25519YaoEmailOtpRecoverySessionResponseV1> {
    this.calls.push(request);
    const capability = activeCapabilityFixture('none');
    return {
      ok: true,
      capability,
      session: {
        sessionKind: 'jwt',
        walletSessionJwt: 'fresh-wallet-session-jwt',
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        authorityScope: {
          kind: 'email_otp',
          provider: 'google',
          providerUserId: PROVIDER_USER_ID,
        },
        thresholdSessionId: THRESHOLD_SESSION_ID,
        signingGrantId: 'fresh-signing-grant-route',
        expiresAtMs: Date.now() + 60_000,
        participantIds: PARTICIPANT_IDS,
        remainingUses: REQUESTED_REMAINING_USES,
        signingRootId: capability.applicationBinding.signing_root_id,
        signingRootVersion: ROOT_VERSION,
        runtimePolicyScope: RUNTIME_POLICY_SCOPE,
        routerAbNormalSigning: {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: SIGNING_WORKER_ID,
        },
      },
    };
  }
}

class RecordingRecoveryRuntime implements RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  readonly kind = 'router_ab_ed25519_yao_product_registration_runtime_v1' as const;
  readonly signingWorkerId = SIGNING_WORKER_ID;
  readonly capabilityLookups: RouterAbEd25519YaoActiveCapabilityLookupV1[] = [];
  readonly mintCalls: RouterAbEd25519YaoWalletSessionMintInputV1[] = [];
  private readonly capabilityResult: RouterAbEd25519YaoActiveCapabilityLookupResultV1;

  constructor(capabilityResult: RouterAbEd25519YaoActiveCapabilityLookupResultV1) {
    this.capabilityResult = capabilityResult;
  }

  async bindVerifiedIntent(): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']
  > {
    return { ok: false, code: 'invalid_registration_intent', message: 'unused' };
  }

  consumeActivated(): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']
  > {
    return { ok: false, code: 'unknown_registration', message: 'unused' };
  }

  installRegistrationFinalizeCapability(): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['installRegistrationFinalizeCapability']
  > {
    return { ok: false, code: 'capability_conflict', message: 'unused' };
  }

  installPersistedActiveCapability(): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['installPersistedActiveCapability']
  > {
    return { ok: false, code: 'capability_conflict', message: 'unused' };
  }

  resolveActiveCapability(
    lookup: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ): RouterAbEd25519YaoActiveCapabilityLookupResultV1 {
    this.capabilityLookups.push(lookup);
    return this.capabilityResult;
  }

  async mintWalletSession(
    input: RouterAbEd25519YaoWalletSessionMintInputV1,
  ): ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['mintWalletSession']> {
    this.mintCalls.push(input);
    const signingGrantId = `fresh-signing-grant-${this.mintCalls.length}`;
    const authorityScope = thresholdEd25519AuthorityScopeFromWalletAuthAuthority(input.authority);
    const signingRoot = signingRootScopeFromRuntimePolicyScope(input.runtimePolicyScope);
    return {
      ok: true,
      session: {
        sessionKind: 'jwt',
        walletSessionJwt: `fresh-wallet-session-jwt-${this.mintCalls.length}`,
        walletId: input.walletId,
        nearAccountId: input.nearAccountId,
        nearEd25519SigningKeyId: input.nearEd25519SigningKeyId,
        authorityScope,
        thresholdSessionId: input.thresholdSessionId,
        signingGrantId,
        expiresAtMs: Date.now() + 60_000,
        participantIds: input.participantIds,
        remainingUses:
          input.kind === 'shared_email_otp_recovery_wallet_session_v1' ? input.remainingUses : 3,
        signingRootId: signingRoot.signingRootId,
        signingRootVersion: ROOT_VERSION,
        runtimePolicyScope: input.runtimePolicyScope,
        routerAbNormalSigning: {
          kind: 'router_ab_ed25519_normal_signing_v1',
          signingWorkerId: SIGNING_WORKER_ID,
        },
      },
    };
  }
}

async function ignoreRouterWebhook(
  _input: Parameters<EmitWalletUnlockRouterApiWebhook>[0],
): Promise<void> {}

async function ignoreEmailOtpWebhook(
  _input: Parameters<EmitWalletUnlockEmailOtpWebhook>[0],
): Promise<void> {}

async function seedRecoveryWallet(input: {
  readonly database: ReturnType<typeof createTemporaryD1Database>['database'];
  readonly namespace: string;
}): Promise<void> {
  await applySignerMigrations(input.database);
  await insertSignerWallet({
    database: input.database,
    namespace: input.namespace,
    orgId: ORG_ID,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    walletId: WALLET_ID,
  });
  await insertWalletAuthMethod({
    database: input.database,
    namespace: input.namespace,
    orgId: ORG_ID,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    record: {
      version: 'wallet_auth_method_v1',
      kind: 'email_otp',
      status: 'active',
      walletId: WALLET_ID,
      emailHashHex: EMAIL_HASH_HEX,
      registrationAuthorityId: 'email-otp-authority-1',
      createdAtMs: 1_000,
      updatedAtMs: 1_000,
    },
  });
  const walletStore = new D1WalletStore({
    database: input.database,
    namespace: input.namespace,
    orgId: ORG_ID,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    ensureSchema: false,
  });
  const signingRoot = signingRootScopeFromRuntimePolicyScope(RUNTIME_POLICY_SCOPE);
  await walletStore.putSigner(
    buildYaoEd25519WalletSignerRecord({
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      signerSlot: SIGNER_SLOT,
      publicKey: ed25519NearPublicKeyFromBytes(REGISTERED_PUBLIC_KEY),
      signingWorkerId: SIGNING_WORKER_ID,
      keyVersion: 'router-ab-ed25519-yao-v1',
      participantIds: PARTICIPANT_IDS,
      signingRootId: signingRoot.signingRootId,
      signingRootVersion: ROOT_VERSION,
      runtimePolicyScope: RUNTIME_POLICY_SCOPE,
      activeYaoCapability: activeYaoCapabilityRecordFixture(),
      now: 1_000,
    }),
  );
}

function createRecoveryService(input: {
  readonly database: ReturnType<typeof createTemporaryD1Database>['database'];
  readonly namespace: string;
  readonly runtime: RouterAbEd25519YaoProductRegistrationRuntimeV1;
}) {
  const threshold = createRouterAbSigningRuntimesForUnitTests({
    config: { ROUTER_AB_NORMAL_SIGNING_WORKER_ID: SIGNING_WORKER_ID },
  });
  const service = createCloudflareD1RouterApiAuthService({
    database: input.database,
    namespace: input.namespace,
    orgId: ORG_ID,
    projectId: PROJECT_ID,
    envId: ENV_ID,
    routerAbSigningRuntimes: threshold.runtimes,
    ed25519YaoProductRegistration: input.runtime,
  });
  return {
    service,
    routerAbNormalSigningRuntime: threshold.routerAbNormalSigningRuntime,
  };
}

test('parses only the fresh Email OTP Ed25519 Yao recovery augmentation', () => {
  expect(parseWalletUnlockEd25519YaoRequest(unlockBodyFixture())).toEqual({
    ok: true,
    request: {
      kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND,
      walletId: WALLET_ID,
      orgId: ORG_ID,
      challengeId: CHALLENGE_ID,
      signerSlot: SIGNER_SLOT,
      remainingUses: REQUESTED_REMAINING_USES,
    },
  });

  const obsolete = unlockBodyFixture();
  obsolete.ed25519YaoRecovery = {
    kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND,
    signerSlot: SIGNER_SLOT,
    remainingUses: REQUESTED_REMAINING_USES,
    walletSessionAuth: { walletSessionJwt: 'expired-wallet-session' },
  };
  expect(parseWalletUnlockEd25519YaoRequest(obsolete)).toEqual({
    ok: false,
    status: 400,
    body: {
      ok: false,
      code: 'invalid_body',
      message: 'Unsupported ed25519YaoRecovery field: walletSessionAuth',
    },
  });

  const substitutedBudget = unlockBodyFixture();
  const substitutedRecovery = substitutedBudget.ed25519YaoRecovery as Record<string, unknown>;
  substitutedRecovery.signingBudget = {
    signingGrantId: 'attacker-selected-grant',
    ttlMs: 86_400_000,
    remainingUses: 999,
  };
  expect(parseWalletUnlockEd25519YaoRequest(substitutedBudget)).toEqual({
    ok: false,
    status: 400,
    body: {
      ok: false,
      code: 'invalid_body',
      message: 'Unsupported ed25519YaoRecovery field: signingBudget',
    },
  });
});

test('verified Email OTP recovery forwards the fresh subject without bearer session state', async () => {
  const parsed = parseWalletUnlockEd25519YaoRequest(unlockBodyFixture());
  if (!parsed.ok || !parsed.request) throw new Error('expected parsed recovery request');
  const recovery = new RecordingRouteRecoveryService();
  const response = await handleWalletUnlockVerifyRoute({
    body: unlockBodyFixture(),
    service: new VerifiedEmailOtpUnlockService(),
    ed25519YaoRecovery: {
      kind: 'requested',
      request: parsed.request,
      recoverWalletSession: recovery.recoverEd25519YaoEmailOtpWalletSession.bind(recovery),
    },
    emitRouterApiWebhook: ignoreRouterWebhook,
    emitEmailOtpWebhook: ignoreEmailOtpWebhook,
  });

  expect(recovery.calls).toEqual([recoveryRequestFixture()]);
  expect(response).toMatchObject({
    status: 200,
    body: {
      ok: true,
      unlocked: true,
      ed25519YaoRecovery: {
        kind: ROUTER_AB_ED25519_YAO_EMAIL_OTP_RECOVERY_KIND,
        session: {
          walletSessionJwt: 'fresh-wallet-session-jwt',
          signingGrantId: 'fresh-signing-grant-route',
        },
      },
    },
  });
});

test('D1 recovery issues the authoritative mixed-wallet signing grant', async () => {
  const temporary = createTemporaryD1Database();
  const namespace = 'wallet-unlock-email-yao-success';
  try {
    await seedRecoveryWallet({ database: temporary.database, namespace });
    const runtime = new RecordingRecoveryRuntime({
      ok: true,
      capability: activeCapabilityFixture('none'),
    });
    const fixture = createRecoveryService({
      database: temporary.database,
      namespace,
      runtime,
    });
    const service = fixture.service;

    const first =
      await service.walletRegistration.recoverEd25519YaoEmailOtpWalletSession(
        recoveryRequestFixture(),
      );
    if (!first.ok) throw new Error(JSON.stringify(first));
    expect(first).toMatchObject({
      ok: true,
      session: {
        walletId: WALLET_ID,
        thresholdSessionId: THRESHOLD_SESSION_ID,
        signingGrantId: 'fresh-signing-grant-1',
        remainingUses: REQUESTED_REMAINING_USES,
      },
    });
    expect(runtime.capabilityLookups).toEqual([
      {
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        signerSlot: SIGNER_SLOT,
        signingWorkerId: SIGNING_WORKER_ID,
        participantIds: PARTICIPANT_IDS,
      },
    ]);
    expect(runtime.mintCalls).toHaveLength(1);
    expect(runtime.mintCalls[0]).toMatchObject({
      kind: 'shared_email_otp_recovery_wallet_session_v1',
      walletId: WALLET_ID,
      thresholdSessionId: THRESHOLD_SESSION_ID,
      remainingUses: REQUESTED_REMAINING_USES,
    });
    expect(runtime.mintCalls[0]).not.toHaveProperty('signingGrantId');
    await expect(
      fixture.routerAbNormalSigningRuntime.getSigningGrantBudget('fresh-signing-grant-1'),
    ).resolves.toMatchObject({
      walletId: WALLET_ID,
      bindings: {
        kind: 'ed25519_only',
        ed25519: { participantIds: PARTICIPANT_IDS },
      },
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('D1 recovery fails closed when the exact active capability is missing', async () => {
  const temporary = createTemporaryD1Database();
  const namespace = 'wallet-unlock-email-yao-missing-capability';
  try {
    await seedRecoveryWallet({ database: temporary.database, namespace });
    const runtime = new RecordingRecoveryRuntime({
      ok: false,
      code: 'unknown_capability',
      message: 'capability is unavailable',
    });
    const fixture = createRecoveryService({
      database: temporary.database,
      namespace,
      runtime,
    });
    const service = fixture.service;

    await expect(
      service.walletRegistration.recoverEd25519YaoEmailOtpWalletSession(recoveryRequestFixture()),
    ).resolves.toEqual({
      ok: false,
      code: 'unknown_capability',
      message: 'capability is unavailable',
    });
    expect(runtime.mintCalls).toHaveLength(0);
    await expect(
      fixture.routerAbNormalSigningRuntime.getSigningGrantBudget('fresh-signing-grant-1'),
    ).resolves.toBeNull();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});

test('D1 recovery rejects active-capability wallet substitution before minting', async () => {
  const temporary = createTemporaryD1Database();
  const namespace = 'wallet-unlock-email-yao-substitution';
  try {
    await seedRecoveryWallet({ database: temporary.database, namespace });
    const runtime = new RecordingRecoveryRuntime({
      ok: true,
      capability: activeCapabilityFixture('wallet'),
    });
    const fixture = createRecoveryService({
      database: temporary.database,
      namespace,
      runtime,
    });
    const service = fixture.service;

    await expect(
      service.walletRegistration.recoverEd25519YaoEmailOtpWalletSession(recoveryRequestFixture()),
    ).resolves.toEqual({
      ok: false,
      code: 'capability_conflict',
      message: 'Active Ed25519 Yao capability does not match the registered signer',
    });
    expect(runtime.mintCalls).toHaveLength(0);
    await expect(
      fixture.routerAbNormalSigningRuntime.getSigningGrantBudget('fresh-signing-grant-1'),
    ).resolves.toBeNull();
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
});
