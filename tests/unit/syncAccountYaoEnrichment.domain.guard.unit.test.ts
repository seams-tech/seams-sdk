import { expect, test } from '@playwright/test';
import type {
  RouterApiServiceBag,
  RouterApiWebAuthnService,
} from '../../packages/sdk-server-ts/src/router/authServicePort';
import type { WalletRegistrationEd25519YaoBootstrapSession } from '../../packages/sdk-server-ts/src/core/registrationContracts';
import { ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND } from '../../packages/shared-ts/src/utils/signingSessionSeal';
import { parseWebAuthnRpId } from '../../packages/shared-ts/src/utils/domainIds';
import { walletIdFromString } from '../../packages/shared-ts/src/utils/registrationIntent';
import { buildPasskeyWalletAuthAuthority } from '../../packages/shared-ts/src/utils/walletAuthAuthority';
import { createCloudflareD1RouterApiAuthService } from '../../packages/sdk-server-ts/src/router/cloudflare/d1RouterApiAuthService';
import { createCloudflareRouter } from '../../packages/sdk-server-ts/src/router/cloudflare/createCloudflareRouter';
import type { SessionAdapter } from '../../packages/sdk-server-ts/src/router/routerApi';
import type {
  RouterAbEd25519YaoProductRegistrationRuntimeV1,
  RouterAbEd25519YaoWalletSessionMintInputV1,
  RouterAbEd25519YaoWalletSessionMintResultV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoProductRegistration';
import type {
  RouterAbEd25519YaoActiveCapabilityDescriptorV1,
  RouterAbEd25519YaoActiveCapabilityLookupResultV1,
  RouterAbEd25519YaoActiveCapabilityLookupV1,
} from '../../packages/sdk-server-ts/src/router/routerAbEd25519YaoRecovery';
import { cleanupTemporaryD1Database, createTemporaryD1Database } from '../helpers/sqliteD1';
import {
  createEcdsaWalletSessionStore,
  createEd25519WalletSessionStore,
  createWalletSigningBudgetSessionStore,
} from '../../packages/sdk-server-ts/src/core/ThresholdService/stores/WalletSessionStore';
import {
  parseRouterAbNormalSigningRuntimeConfig,
  RouterAbNormalSigningRuntime,
} from '../../packages/sdk-server-ts/src/core/routerAbSigning/RouterAbNormalSigningRuntime';
import { normalizeLogger } from '../../packages/sdk-server-ts/src/core/logger';

const WALLET_ID = 'wallet-sync-1';
const NEAR_ACCOUNT_ID = 'wallet-sync-1.testnet';
const NEAR_SIGNING_KEY_ID = 'ed25519ks_sync_1';
const SIGNING_WORKER_ID = 'signing-worker-sync-1';
const RP_ID = 'wallet.example.test';
const ORIGIN = `https://${RP_ID}`;
const CREDENTIAL_ID = 'credential-sync-1';
const PARTICIPANT_IDS = [11, 22] as const;

type SyncVerificationInput = Parameters<RouterApiWebAuthnService['verifyWebAuthnSyncAccount']>[0];
type SyncVerificationResult = Awaited<
  ReturnType<RouterApiWebAuthnService['verifyWebAuthnSyncAccount']>
>;

function requireWebAuthnRpId(value: string) {
  const parsed = parseWebAuthnRpId(value);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function bytes32(seed: number): readonly number[] {
  return Object.freeze(new Array<number>(32).fill(seed));
}

function activeCapabilityFixture(): RouterAbEd25519YaoActiveCapabilityDescriptorV1 {
  return {
    kind: 'router_ab_ed25519_yao_active_capability_v1',
    activeCapabilityBinding: bytes32(41),
    registeredPublicKey: bytes32(42),
    nearAccountId: NEAR_ACCOUNT_ID,
    applicationBinding: {
      wallet_id: WALLET_ID,
      near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID,
      signing_root_id: 'project-active:env-active',
      key_creation_signer_slot: 3,
    },
    runtimePolicyScope: {
      orgId: 'org-active',
      projectId: 'project-active',
      envId: 'env-active',
      signingRootVersion: 'root-active-v2',
    },
    participantIds: PARTICIPANT_IDS,
    lifecycle: {
      lifecycleId: 'sync-account-active-lifecycle',
      rootShareEpoch: 'root-active-v2',
      accountId: WALLET_ID,
      walletSessionId: 'active-threshold-session-2',
      signerSetId: 'signer-set-sync-1',
      signingWorkerId: SIGNING_WORKER_ID,
    },
    stateEpoch: 2,
  };
}

function walletSessionFixture(): WalletRegistrationEd25519YaoBootstrapSession {
  return {
    sessionKind: 'jwt',
    walletSessionJwt: 'active.wallet.session.jwt',
    walletId: walletIdFromString(WALLET_ID),
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    authorityScope: {
      kind: 'passkey_rp',
      rpId: requireWebAuthnRpId(RP_ID),
    },
    thresholdSessionId: 'active-threshold-session-2',
    signingGrantId: 'active-signing-grant-2',
    expiresAtMs: 1_900_000_000_000,
    participantIds: PARTICIPANT_IDS,
    remainingUses: 3,
    signingRootId: 'project-active:env-active',
    signingRootVersion: 'root-active-v2',
    runtimePolicyScope: {
      orgId: 'org-active',
      projectId: 'project-active',
      envId: 'env-active',
      signingRootVersion: 'root-active-v2',
    },
    routerAbNormalSigning: {
      kind: ROUTER_AB_ED25519_NORMAL_SIGNING_STATE_KIND,
      signingWorkerId: SIGNING_WORKER_ID,
    },
  };
}

function verifiedEd25519WalletFixture(): SyncVerificationResult {
  return {
    ok: true,
    verified: true,
    walletId: WALLET_ID,
    nearAccountId: NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
    walletBinding: {
      walletId: WALLET_ID,
      nearAccountId: NEAR_ACCOUNT_ID,
      nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
      rpId: RP_ID,
      credentialIdB64u: CREDENTIAL_ID,
      signerSlot: 3,
    },
    rpId: RP_ID,
    signerSlot: 3,
    publicKey: 'ed25519:sync-public-key',
    credentialIdB64u: CREDENTIAL_ID,
    credentialPublicKeyB64u: 'credential-public-key-sync-1',
    thresholdEd25519: {
      relayerKeyId: SIGNING_WORKER_ID,
      authorityScope: {
        kind: 'passkey_rp',
        rpId: requireWebAuthnRpId(RP_ID),
      },
      publicKey: 'ed25519:sync-public-key',
      keyVersion: 'key-v1',
      recoveryExportCapable: true,
      participantIds: [...PARTICIPANT_IDS],
    },
  };
}

class RecordingSyncAccountWebAuthnService implements RouterApiWebAuthnService {
  readonly verificationCalls: SyncVerificationInput[] = [];

  constructor(
    private readonly delegate: RouterApiWebAuthnService,
    private readonly verificationResult: SyncVerificationResult,
  ) {}

  createWebAuthnLoginOptions(
    input: Parameters<RouterApiWebAuthnService['createWebAuthnLoginOptions']>[0],
  ): ReturnType<RouterApiWebAuthnService['createWebAuthnLoginOptions']> {
    return this.delegate.createWebAuthnLoginOptions(input);
  }

  createWebAuthnSyncAccountOptions(
    input: Parameters<RouterApiWebAuthnService['createWebAuthnSyncAccountOptions']>[0],
  ): ReturnType<RouterApiWebAuthnService['createWebAuthnSyncAccountOptions']> {
    return this.delegate.createWebAuthnSyncAccountOptions(input);
  }

  listWebAuthnAuthenticatorsForUser(
    input: Parameters<RouterApiWebAuthnService['listWebAuthnAuthenticatorsForUser']>[0],
  ): ReturnType<RouterApiWebAuthnService['listWebAuthnAuthenticatorsForUser']> {
    return this.delegate.listWebAuthnAuthenticatorsForUser(input);
  }

  verifyWebAuthnAuthenticationLite(
    input: Parameters<RouterApiWebAuthnService['verifyWebAuthnAuthenticationLite']>[0],
  ): ReturnType<RouterApiWebAuthnService['verifyWebAuthnAuthenticationLite']> {
    return this.delegate.verifyWebAuthnAuthenticationLite(input);
  }

  verifyWebAuthnLogin(
    input: Parameters<RouterApiWebAuthnService['verifyWebAuthnLogin']>[0],
  ): ReturnType<RouterApiWebAuthnService['verifyWebAuthnLogin']> {
    return this.delegate.verifyWebAuthnLogin(input);
  }

  async verifyWebAuthnSyncAccount(input: SyncVerificationInput): Promise<SyncVerificationResult> {
    this.verificationCalls.push(input);
    return this.verificationResult;
  }
}

class ThrowingUnexpectedSessionAdapter implements SessionAdapter {
  signJwtCalls = 0;

  async signJwt(): Promise<string> {
    this.signJwtCalls += 1;
    throw new Error('sync-account Yao enrichment must use the product runtime session');
  }

  async parse(): Promise<{ ok: false }> {
    throw new Error('session parsing is outside sync-account Yao enrichment');
  }

  buildSetCookie(): string {
    throw new Error('cookie sessions are outside sync-account Yao enrichment');
  }

  buildClearCookie(): string {
    throw new Error('cookie sessions are outside sync-account Yao enrichment');
  }

  async refresh(): Promise<{ ok: false }> {
    throw new Error('session refresh is outside sync-account Yao enrichment');
  }
}

class RecordingYaoProductRuntime implements RouterAbEd25519YaoProductRegistrationRuntimeV1 {
  readonly kind = 'router_ab_ed25519_yao_product_registration_runtime_v1' as const;
  readonly signingWorkerId = SIGNING_WORKER_ID;
  readonly lookupCalls: RouterAbEd25519YaoActiveCapabilityLookupV1[] = [];
  readonly mintCalls: RouterAbEd25519YaoWalletSessionMintInputV1[] = [];

  constructor(
    private readonly capability: RouterAbEd25519YaoActiveCapabilityDescriptorV1,
    private readonly walletSession: WalletRegistrationEd25519YaoBootstrapSession,
  ) {}

  bindVerifiedIntent(
    _input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']>[0],
  ): ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['bindVerifiedIntent']> {
    throw new Error('registration intent binding is outside sync-account enrichment');
  }

  consumeActivated(
    _input: Parameters<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']>[0],
  ): ReturnType<RouterAbEd25519YaoProductRegistrationRuntimeV1['consumeActivated']> {
    throw new Error('registration activation is outside sync-account enrichment');
  }

  installRegistrationFinalizeCapability(
    _input: Parameters<
      RouterAbEd25519YaoProductRegistrationRuntimeV1['installRegistrationFinalizeCapability']
    >[0],
  ): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['installRegistrationFinalizeCapability']
  > {
    throw new Error('capability installation is outside sync-account enrichment');
  }

  installPersistedActiveCapability(
    _input: Parameters<
      RouterAbEd25519YaoProductRegistrationRuntimeV1['installPersistedActiveCapability']
    >[0],
  ): ReturnType<
    RouterAbEd25519YaoProductRegistrationRuntimeV1['installPersistedActiveCapability']
  > {
    throw new Error('persisted capability installation is outside sync-account enrichment');
  }

  resolveActiveCapability(
    input: RouterAbEd25519YaoActiveCapabilityLookupV1,
  ): RouterAbEd25519YaoActiveCapabilityLookupResultV1 {
    this.lookupCalls.push(input);
    return { ok: true, capability: this.capability };
  }

  async mintWalletSession(
    input: RouterAbEd25519YaoWalletSessionMintInputV1,
  ): Promise<RouterAbEd25519YaoWalletSessionMintResultV1> {
    this.mintCalls.push(input);
    return { ok: true, session: this.walletSession };
  }
}

function replaceWebAuthnService(
  service: RouterApiServiceBag,
  webAuthn: RouterApiWebAuthnService,
): RouterApiServiceBag {
  return {
    walletRegistration: service.walletRegistration,
    walletAuthMethods: service.walletAuthMethods,
    walletUnlock: service.walletUnlock,
    emailOtp: service.emailOtp,
    webAuthn,
    identity: service.identity,
    sessionVersions: service.sessionVersions,
    thresholdRuntime: service.thresholdRuntime,
    nearFunding: service.nearFunding,
    recovery: service.recovery,
    router: service.router,
  };
}

function syncAccountVerifyRequest(): Request {
  return new Request('https://router.example.test/sync-account/verify', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
    },
    body: JSON.stringify({
      challengeId: 'sync-challenge-1',
      webauthn_authentication: {
        id: CREDENTIAL_ID,
        type: 'public-key',
      },
    }),
  });
}

function syncAccountVerifyRequestWithObsoleteSessionPolicy(): Request {
  return new Request('https://router.example.test/sync-account/verify', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      origin: ORIGIN,
    },
    body: JSON.stringify({
      challengeId: 'sync-challenge-1',
      webauthn_authentication: {
        id: CREDENTIAL_ID,
        type: 'public-key',
      },
      threshold_ed25519: {
        session_policy: {},
      },
    }),
  });
}

function createBaseService(
  database: Parameters<typeof createCloudflareD1RouterApiAuthService>[0]['database'],
) {
  return createCloudflareD1RouterApiAuthService({
    database,
    namespace: 'sync-account-yao-test',
    orgId: 'org-active',
    projectId: 'project-active',
    envId: 'env-active',
    relayerAccount: 'relay.testnet',
    relayerPublicKey: 'ed25519:relay-public-key',
    accountIdDerivationSecret: 'sync-account-test-derivation-secret',
  });
}

function createSyncAccountNormalSigningRuntime(): RouterAbNormalSigningRuntime {
  const config = {
    kind: 'in-memory' as const,
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: SIGNING_WORKER_ID,
  };
  const storeInput = { config, logger: normalizeLogger(null), isNode: true };
  return new RouterAbNormalSigningRuntime({
    walletSessionStore: createEd25519WalletSessionStore(storeInput),
    ecdsaWalletSessionStore: createEcdsaWalletSessionStore(storeInput),
    walletBudgetSessionStore: createWalletSigningBudgetSessionStore(storeInput),
    config: parseRouterAbNormalSigningRuntimeConfig(config),
  });
}

async function syncAccountEnrichesFromActiveYaoCapability(): Promise<void> {
  const temporary = createTemporaryD1Database();
  try {
    const baseService = createBaseService(temporary.database);
    const normalSigningRuntime = createSyncAccountNormalSigningRuntime();
    baseService.thresholdRuntime.getRouterAbNormalSigningRuntime = () => normalSigningRuntime;
    const webAuthn = new RecordingSyncAccountWebAuthnService(
      baseService.webAuthn,
      verifiedEd25519WalletFixture(),
    );
    const runtime = new RecordingYaoProductRuntime(
      activeCapabilityFixture(),
      walletSessionFixture(),
    );
    const unexpectedSession = new ThrowingUnexpectedSessionAdapter();
    const router = createCloudflareRouter(replaceWebAuthnService(baseService, webAuthn), {
      session: unexpectedSession,
      routerAbEd25519YaoProduct: runtime,
    });

    const response = await router(syncAccountVerifyRequest());
    expect(response.status).toBe(200);
    expect(webAuthn.verificationCalls).toEqual([
      {
        challengeId: 'sync-challenge-1',
        webauthn_authentication: {
          id: CREDENTIAL_ID,
          type: 'public-key',
        },
        expected_origin: ORIGIN,
      },
    ]);
    expect(webAuthn.verificationCalls[0]).not.toHaveProperty('threshold_ed25519');
    expect(unexpectedSession.signJwtCalls).toBe(0);
    expect(runtime.lookupCalls).toEqual([
      {
        kind: 'router_ab_ed25519_yao_active_capability_lookup_v1',
        walletId: WALLET_ID,
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        signerSlot: 3,
        signingWorkerId: SIGNING_WORKER_ID,
        participantIds: PARTICIPANT_IDS,
      },
    ]);
    expect(runtime.mintCalls).toEqual([
      {
        kind: 'registration_wallet_session_v1',
        walletId: walletIdFromString(WALLET_ID),
        nearAccountId: NEAR_ACCOUNT_ID,
        nearEd25519SigningKeyId: NEAR_SIGNING_KEY_ID,
        authority: buildPasskeyWalletAuthAuthority({
          walletId: WALLET_ID,
          rpId: RP_ID,
          credentialIdB64u: CREDENTIAL_ID,
        }),
        thresholdSessionId: 'active-threshold-session-2',
        participantIds: PARTICIPANT_IDS,
        runtimePolicyScope: {
          orgId: 'org-active',
          projectId: 'project-active',
          envId: 'env-active',
          signingRootVersion: 'root-active-v2',
        },
      },
    ]);
    expect(
      await normalSigningRuntime.getSigningGrantBudget(walletSessionFixture().signingGrantId),
    ).toMatchObject({
      walletId: WALLET_ID,
      bindings: {
        kind: 'ed25519_only',
        ed25519: {
          thresholdSessionId: walletSessionFixture().thresholdSessionId,
          participantIds: PARTICIPANT_IDS,
        },
      },
    });
    expect(await response.json()).toMatchObject({
      ok: true,
      verified: true,
      thresholdEd25519: {
        session: walletSessionFixture(),
      },
      ed25519YaoRecovery: {
        kind: 'router_ab_ed25519_yao_sync_recovery_v1',
        capability: activeCapabilityFixture(),
      },
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
}

async function syncAccountFailsClosedWithoutYaoRuntime(): Promise<void> {
  const temporary = createTemporaryD1Database();
  try {
    const baseService = createBaseService(temporary.database);
    const webAuthn = new RecordingSyncAccountWebAuthnService(
      baseService.webAuthn,
      verifiedEd25519WalletFixture(),
    );
    const unexpectedSession = new ThrowingUnexpectedSessionAdapter();
    const router = createCloudflareRouter(replaceWebAuthnService(baseService, webAuthn), {
      session: unexpectedSession,
    });

    const response = await router(syncAccountVerifyRequest());
    expect(response.status).toBe(500);
    expect(unexpectedSession.signJwtCalls).toBe(0);
    expect(await response.json()).toEqual({
      ok: false,
      code: 'internal',
      message: 'Ed25519 Yao product registration is not configured',
    });
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
}

async function syncAccountRejectsObsoleteSessionPolicy(): Promise<void> {
  const temporary = createTemporaryD1Database();
  try {
    const baseService = createBaseService(temporary.database);
    const webAuthn = new RecordingSyncAccountWebAuthnService(
      baseService.webAuthn,
      verifiedEd25519WalletFixture(),
    );
    const router = createCloudflareRouter(replaceWebAuthnService(baseService, webAuthn));

    const response = await router(syncAccountVerifyRequestWithObsoleteSessionPolicy());

    expect(response.status).toBe(400);
    expect(await response.json()).toEqual({
      ok: false,
      code: 'invalid_body',
      message: 'Unsupported sync-account verify field: threshold_ed25519',
    });
    expect(webAuthn.verificationCalls).toEqual([]);
  } finally {
    cleanupTemporaryD1Database(temporary.tempDir);
  }
}

test(
  'sync-account enriches an Ed25519 wallet only from its active Yao capability',
  syncAccountEnrichesFromActiveYaoCapability,
);
test(
  'sync-account fails closed when an Ed25519 wallet has no Yao runtime',
  syncAccountFailsClosedWithoutYaoRuntime,
);
test(
  'sync-account rejects the obsolete threshold session-policy input at the route boundary',
  syncAccountRejectsObsoleteSessionPolicy,
);
