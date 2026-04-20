import { test, expect } from '@playwright/test';
import { buildCanonicalEvmSmartAccountDeploymentPlan } from '@server/core/evmSmartAccountDeploymentPlan';
import { buildCanonicalSmartAccountDeploymentManifest } from '@server/core/smartAccountDeploymentManifest';
import {
  createConsoleRouter,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleOnboardingService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleTeamRbacService,
  createInMemoryConsoleWalletService,
  createRelayApiKeyAuthAdapter,
  createRelayRouter,
  type ConsoleApiKeyService,
  type ConsoleWallet,
  type RelayUsageMeterEvent,
} from '@server/router/express-adaptor';
import { createEvmSmartAccountDeployHandler } from '@server/router/evmSmartAccountDeploy';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import type { ApiCredentialScope } from '@shared/console/apiKeyScopes';
import {
  callCf,
  fetchJson,
  getPath,
  makeCfCtx,
  makeFakeAuthService,
  startExpressRouter,
} from './helpers';

const apiKeyCtx = {
  orgId: 'org-relay-api-keys',
  actorUserId: 'user-relay-admin',
  roles: ['admin'],
};

function makeRegistrationBody(): Record<string, unknown> {
  return {
    new_account_id: 'alice.testnet',
    rp_id: 'example.localhost',
    webauthn_registration: { id: 'cred-1' },
  };
}

function makeRelayService() {
  return makeFakeAuthService({
    createAccountAndRegisterUser: async () => ({
      success: true,
      transactionHash: 'tx-123',
    }),
  });
}

function makeThresholdEcdsaRelayService() {
  return makeFakeAuthService({
    createAccountAndRegisterUser: async () => ({
      success: true,
      transactionHash: 'tx-123',
      thresholdEcdsa: {
        relayerKeyId: 'rk-registration-1',
        thresholdEcdsaPublicKeyB64u: 'group-public-key',
        ethereumAddress: `0x${'aa'.repeat(20)}`,
        relayerVerifyingShareB64u: 'relayer-share',
      },
    }),
  });
}

function makeRegistrationBodyWithSmartAccountTargets(): Record<string, unknown> {
  return {
    ...makeRegistrationBody(),
    threshold_ecdsa: {
      client_root_share32_b64u: 'client-root-share32-b64u',
      session_policy: {
        version: 'threshold_session_v1',
        userId: 'alice.testnet',
        rpId: 'example.localhost',
        sessionId: 'threshold-session-1',
        participantIds: [1, 2],
        ttlMs: 60_000,
        remainingUses: 10,
      },
      session_kind: 'jwt',
      smart_account_targets: [
        {
          chain: 'evm',
          chain_id: 11155111,
          factory: `0x${'bb'.repeat(20)}`,
          entry_point: `0x${'cc'.repeat(20)}`,
          recovery_authority: `0x${'ff'.repeat(20)}`,
          salt: '0x1234',
          counterfactual_address: `0x${'11'.repeat(20)}`,
        },
        {
          chain: 'tempo',
          chain_id: 42431,
          factory: `0x${'dd'.repeat(20)}`,
          entry_point: `0x${'ee'.repeat(20)}`,
          salt: '0x5678',
          counterfactual_address: `0x${'22'.repeat(20)}`,
        },
      ],
    },
  };
}

function makeCanonicalEvmCounterfactualAddress(): `0x${string}` {
  const manifest = buildCanonicalSmartAccountDeploymentManifest({
    recoverySubject: {
      version: 'smart_account_recovery_subject_v1',
      userId: 'alice.testnet',
      nearAccountId: 'alice.testnet',
      chainIdKey: 'evm:11155111',
      accountAddress: `0x${'11'.repeat(20)}`,
      createdAtMs: 1,
      updatedAtMs: 1,
      metadata: {
        chain: 'evm',
        chainId: 11155111,
        accountModel: 'erc4337',
        deployed: false,
        factory: `0x${'bb'.repeat(20)}`,
        entryPoint: `0x${'cc'.repeat(20)}`,
        recoveryAuthority: `0x${'ff'.repeat(20)}`,
        salt: '0x1234',
        counterfactualAddress: `0x${'11'.repeat(20)}`,
      },
    } as any,
    signers: [
      {
        version: 'account_signer_v1',
        userId: 'alice.testnet',
        chainIdKey: 'evm:11155111',
        accountAddress: `0x${'11'.repeat(20)}`,
        signerType: 'threshold',
        signerId: `0x${'aa'.repeat(20)}`,
        status: 'active',
        createdAtMs: 1,
        updatedAtMs: 1,
        metadata: {
          chain: 'evm',
          chainId: 11155111,
          accountModel: 'erc4337',
        },
      },
    ] as any,
    materializedAtMs: 1,
  });
  if (!manifest) {
    throw new Error('Failed to build canonical EVM manifest fixture');
  }
  const plan = buildCanonicalEvmSmartAccountDeploymentPlan(manifest);
  if (!plan) {
    throw new Error('Failed to build canonical EVM deployment plan fixture');
  }
  return plan.predictedAddress;
}

function makeWallet(overrides: Partial<ConsoleWallet> = {}): ConsoleWallet {
  const id = String(overrides.id || 'wlt_wallet_1');
  const environmentId = String(overrides.environmentId || 'env-prod');
  const projectId = String(
    overrides.projectId ||
      (environmentId.includes(':') ? environmentId.split(':')[0] : 'proj_wallets'),
  );
  return {
    id,
    orgId: 'org-relay-api-keys',
    projectId,
    environmentId,
    userId: String(overrides.userId || 'user-wallet-1'),
    externalRefId: String(overrides.externalRefId || `${id}:external`),
    address: String(overrides.address || `0x${'1'.repeat(40)}`),
    chain: overrides.chain || 'Ethereum',
    walletType: overrides.walletType || 'SMART',
    status: overrides.status || 'ACTIVE',
    policyId: overrides.policyId === undefined ? null : overrides.policyId,
    balanceMinor: overrides.balanceMinor === undefined ? 100 : overrides.balanceMinor,
    lastActivityAt:
      overrides.lastActivityAt === undefined
        ? '2026-03-14T00:00:00.000Z'
        : overrides.lastActivityAt,
    createdAt: overrides.createdAt || '2026-03-14T00:00:00.000Z',
    updatedAt: overrides.updatedAt || '2026-03-14T00:00:00.000Z',
    ...overrides,
  };
}

function makeSerializedRegistrationCredential() {
  return {
    id: 'cred_registration_1',
    rawId: 'raw_registration_1',
    type: 'public-key',
    response: {
      clientDataJSON: 'Y2xpZW50RGF0YQ',
      attestationObject: 'YXR0ZXN0YXRpb24',
      transports: ['internal'],
    },
    clientExtensionResults: {
      prf: {
        results: {},
      },
    },
  };
}

async function createActiveSecret(
  apiKeys: ConsoleApiKeyService,
  input: { scopes: ApiCredentialScope[]; ipAllowlist?: string[]; expiresAt?: string },
): Promise<{ apiKeyId: string; secret: string }> {
  const created = await apiKeys.createApiKey(apiKeyCtx, {
    kind: 'secret_key',
    name: 'registration-key',
    environmentId: 'env-prod',
    scopes: input.scopes,
    ...(input.ipAllowlist ? { ipAllowlist: input.ipAllowlist } : {}),
    ...(input.expiresAt ? { expiresAt: input.expiresAt } : {}),
  });
  return { apiKeyId: created.apiKey.id, secret: created.secret };
}

test.describe('relay API key auth (express)', () => {
  test('rejects missing API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('secret_key_missing');
    } finally {
      await srv.close();
    }
  });

  test('rejects invalid API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer sk_invalidsecret',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(401);
      expect(res.json?.code).toBe('secret_key_invalid');
    } finally {
      await srv.close();
    }
  });

  test('rejects revoked API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { apiKeyId, secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    await apiKeys.revokeApiKey(apiKeyCtx, apiKeyId);
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_revoked');
    } finally {
      await srv.close();
    }
  });

  test('rejects key missing required scope', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: [],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_forbidden_scope');
    } finally {
      await srv.close();
    }
  });

  test('rejects key when environment header mismatches', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'x-tatchi-environment-id': 'env-stage',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_environment_mismatch');
    } finally {
      await srv.close();
    }
  });

  test('rejects key blocked by IP allowlist', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['203.0.113.10/32'],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'x-forwarded-for': '198.51.100.2',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_ip_blocked');
    } finally {
      await srv.close();
    }
  });

  test('rejects expired API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(403);
      expect(res.json?.code).toBe('secret_key_revoked');
    } finally {
      await srv.close();
    }
  });

  test('accepts valid scoped key and records usage', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const meteredEvents: RelayUsageMeterEvent[] = [];
    const { apiKeyId, secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['127.0.0.1/32'],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      apiKeyUsageMeter: {
        recordEvent: async (event) => {
          meteredEvents.push(event);
        },
      },
    });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'x-forwarded-for': '127.0.0.1',
          'x-tatchi-environment-id': 'env-prod',
        },
        body: JSON.stringify(makeRegistrationBody()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.success).toBe(true);

      const keys = await apiKeys.listApiKeys(apiKeyCtx);
      const key = keys.find((entry) => entry.id === apiKeyId);
      expect(key).toBeTruthy();
      expect(key?.lastUsedAt).toBeTruthy();
      expect(Number(key?.endpointUsageCounts['POST /registration/bootstrap'] || 0)).toBe(1);
      expect(meteredEvents.length).toBe(1);
      expect(meteredEvents[0]?.action).toBe('wallet_created');
      expect(meteredEvents[0]?.succeeded).toBe(true);
      expect(meteredEvents[0]?.orgId).toBe('org-relay-api-keys');
      expect(meteredEvents[0]?.environmentId).toBe('env-prod');
      expect(meteredEvents[0]?.walletId).toBe('alice.testnet');
    } finally {
      await srv.close();
    }
  });

  test('dashboard onboarding key works with SDK registration client call', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const apiKeys = createInMemoryConsoleApiKeyService();
    const billing = createInMemoryConsoleBillingService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const onboarding = createInMemoryConsoleOnboardingService({
      orgProjectEnv,
      apiKeys,
      billing,
      teamRbac,
    });

    const consoleRouter = createConsoleRouter({
      auth: {
        authenticate: async () => ({
          ok: true,
          claims: {
            userId: apiKeyCtx.actorUserId,
            orgId: apiKeyCtx.orgId,
            roles: ['admin'],
          },
        }),
      },
      onboarding,
      apiKeys,
      orgProjectEnv,
      billing,
      teamRbac,
    });
    const relayRouter = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    consoleRouter.use(relayRouter);

    const srv = await startExpressRouter(consoleRouter);
    try {
      const organization = await fetchJson(`${srv.baseUrl}/console/onboarding/organization`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          org: { name: 'Dashboard SDK Org', slug: 'dashboard-sdk-org' },
        }),
      });
      expect(organization.status).toBe(201);

      const checkoutSession = await billing.createStripeCheckoutSession(
        {
          orgId: apiKeyCtx.orgId,
          actorUserId: apiKeyCtx.actorUserId,
          roles: ['admin'],
        },
        {
          successUrl: 'https://app.example.com/dashboard/billing/account?checkout=success',
          cancelUrl: 'https://app.example.com/dashboard/billing/account?checkout=cancel',
          creditPackId: 'usd_25',
        },
      );
      const settleResult = await billing.processStripeWebhookEvent({
        eventId: `evt_relay_api_keys_${Date.now()}_${Math.random().toString(16).slice(2)}`,
        eventType: 'checkout.session.completed',
        orgId: apiKeyCtx.orgId,
        checkoutSessionId: checkoutSession.id,
        providerCustomerRef: checkoutSession.customerRef,
        providerRef: checkoutSession.id,
      });
      expect(settleResult.accepted).toBe(true);

      const project = await fetchJson(`${srv.baseUrl}/console/onboarding/project`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          project: { id: 'proj_dashboard_sdk', name: 'Dashboard SDK Project' },
          environment: {
            id: 'proj_dashboard_sdk:prod',
            name: 'Production',
          },
        }),
      });
      expect(project.status).toBe(201);
      const onboardingEnvironmentId = String(
        getPath(project.json, 'result', 'environment', 'id') || '',
      );
      expect(onboardingEnvironmentId.length).toBeGreaterThan(0);

      const apiKeyCreate = await fetchJson(`${srv.baseUrl}/console/api-keys`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          kind: 'secret_key',
          name: 'dashboard-sdk-key',
          environmentId: onboardingEnvironmentId,
          scopes: ['accounts.create'],
        }),
      });
      expect(apiKeyCreate.status).toBe(201);
      const apiKeyId = String(getPath(apiKeyCreate.json, 'apiKey', 'id') || '');
      const apiKeySecret = String(getPath(apiKeyCreate.json, 'secret') || '');
      expect(apiKeyId.length).toBeGreaterThan(0);
      expect(apiKeySecret.length).toBeGreaterThan(0);

      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKeySecret}`,
        },
        body: JSON.stringify({
          new_account_id: 'alice.w3a-relayer.testnet',
          rp_id: 'example.localhost',
          webauthn_registration: makeSerializedRegistrationCredential(),
        }),
      });
      expect(res.status).toBe(200);
      expect(res.json?.success).toBe(true);
      expect(res.json?.transactionHash).toBe('tx-123');

      const keys = await apiKeys.listApiKeys(apiKeyCtx);
      const key = keys.find((entry) => entry.id === apiKeyId);
      expect(key).toBeTruthy();
      expect(Number(key?.endpointUsageCounts['POST /registration/bootstrap'] || 0)).toBe(1);
    } finally {
      await srv.close();
    }
  });

  test('registration bootstrap invokes internal smart-account deploy hook for EVM and Tempo targets', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['127.0.0.1/32'],
    });
    const deployCalls: Array<Record<string, unknown>> = [];
    const recoverySubjectWrites: Array<Record<string, unknown>> = [];
    const router = createRelayRouter(
      makeFakeAuthService({
        createAccountAndRegisterUser: async () => ({
          success: true,
          transactionHash: 'tx-123',
          thresholdEcdsa: {
            relayerKeyId: 'rk-registration-1',
            thresholdEcdsaPublicKeyB64u: 'group-public-key',
            ethereumAddress: `0x${'aa'.repeat(20)}`,
            relayerVerifyingShareB64u: 'relayer-share',
          },
        }),
        getSmartAccountRecoverySubjectByAccount: async ({ chainIdKey, accountAddress }) => ({
          ok: true,
          record: {
            version: 'smart_account_recovery_subject_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey,
            accountAddress,
            createdAtMs: 1,
            updatedAtMs: 1,
            metadata: {
              chain: chainIdKey.startsWith('tempo:') ? 'tempo' : 'evm',
              chainId: chainIdKey.startsWith('tempo:') ? 42431 : 11155111,
              accountModel: chainIdKey.startsWith('tempo:') ? 'tempo-native' : 'erc4337',
              deployed: false,
              ...(chainIdKey.startsWith('tempo:')
                ? {}
                : {
                    factory: `0x${'bb'.repeat(20)}`,
                    entryPoint: `0x${'cc'.repeat(20)}`,
                    recoveryAuthority: `0x${'ff'.repeat(20)}`,
                    salt: '0x1234',
                  }),
              counterfactualAddress: accountAddress,
            },
          } as any,
        }),
        listAccountSignersByAccount: async ({ chainIdKey, accountAddress }) => ({
          ok: true,
          records: [
            {
              version: 'account_signer_v1',
              userId: 'alice.testnet',
              chainIdKey,
              accountAddress,
              signerType: 'threshold',
              signerId: `0x${'aa'.repeat(20)}`,
              status: 'active',
              createdAtMs: 1,
              updatedAtMs: 1,
              metadata: {
                chain: chainIdKey.startsWith('tempo:') ? 'tempo' : 'evm',
                chainId: chainIdKey.startsWith('tempo:') ? 42431 : 11155111,
                accountModel: chainIdKey.startsWith('tempo:') ? 'tempo-native' : 'erc4337',
              },
            },
          ],
        }),
        putSmartAccountRecoverySubject: async (record) => {
          recoverySubjectWrites.push(record as unknown as Record<string, unknown>);
          return { ok: true, record } as any;
        },
      }),
      {
        apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
        smartAccountDeploy: async (request) => {
          deployCalls.push({
            nearAccountId: request.nearAccountId,
            chain: request.chain,
            chainId: request.chainId,
            accountAddress: request.accountAddress,
            accountModel: request.accountModel,
            deploymentManifest: request.deploymentManifest,
            evmDeploymentPlan: request.evmDeploymentPlan,
          });
          return {
            ok: true,
            deploymentTxHash: `0xdeploy-${request.chain}`,
          };
        },
      },
    );
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'x-forwarded-for': '127.0.0.1',
          'x-tatchi-environment-id': 'env-prod',
        },
        body: JSON.stringify(makeRegistrationBodyWithSmartAccountTargets()),
      });
      expect(res.status).toBe(200);
      expect(res.json?.success).toBe(true);
      expect(deployCalls).toEqual([
        expect.objectContaining({
          nearAccountId: 'alice.testnet',
          chain: 'evm',
          chainId: 11155111,
          accountAddress: `0x${'11'.repeat(20)}`,
          accountModel: 'erc4337',
          deploymentManifest: expect.objectContaining({
            counterfactualAddress: `0x${'11'.repeat(20)}`,
            ownerAddresses: [`0x${'aa'.repeat(20)}`],
          }),
          evmDeploymentPlan: expect.objectContaining({
            predictedAddress: expect.stringMatching(/^0x[0-9a-f]{40}$/),
            matchesAccountAddress: false,
            createAccountCalldata: expect.stringMatching(/^0xf8a59370/),
          }),
        }),
        expect.objectContaining({
          nearAccountId: 'alice.testnet',
          chain: 'tempo',
          chainId: 42431,
          accountAddress: `0x${'22'.repeat(20)}`,
          accountModel: 'tempo-native',
          deploymentManifest: expect.objectContaining({
            counterfactualAddress: `0x${'22'.repeat(20)}`,
            ownerAddresses: [`0x${'aa'.repeat(20)}`],
          }),
          evmDeploymentPlan: undefined,
        }),
      ]);
      expect(res.json?.smartAccountDeployments).toEqual([
        {
          chain: 'evm',
          chainId: 11155111,
          accountAddress: `0x${'11'.repeat(20)}`,
          accountModel: 'erc4337',
          deployed: true,
          deploymentTxHash: '0xdeploy-evm',
          counterfactualAddress: `0x${'11'.repeat(20)}`,
        },
        {
          chain: 'tempo',
          chainId: 42431,
          accountAddress: `0x${'22'.repeat(20)}`,
          accountModel: 'tempo-native',
          deployed: true,
          deploymentTxHash: '0xdeploy-tempo',
          counterfactualAddress: `0x${'22'.repeat(20)}`,
        },
      ]);
      expect(recoverySubjectWrites).toHaveLength(4);
      const evmMetadata = recoverySubjectWrites[1]?.metadata as any;
      const tempoMetadata = recoverySubjectWrites[3]?.metadata as any;
      expect(evmMetadata?.deploymentManifest?.ownerAddresses).toEqual([
        `0x${'aa'.repeat(20)}`,
      ]);
      expect(evmMetadata?.evmDeploymentPlan?.predictedAddress).toMatch(
        /^0x[0-9a-f]{40}$/,
      );
      expect(evmMetadata?.evmDeploymentPlan?.createAccountCalldata).toMatch(
        /^0xf8a59370/,
      );
      expect(Number.isFinite(Number(evmMetadata?.evmDeploymentPlanUpdatedAtMs))).toBe(true);
      expect(tempoMetadata?.deploymentManifest?.ownerAddresses).toEqual([
        `0x${'aa'.repeat(20)}`,
      ]);
      expect(tempoMetadata?.evmDeploymentPlan).toBeUndefined();
      expect(tempoMetadata?.evmDeploymentPlanUpdatedAtMs).toBeUndefined();
    } finally {
      await srv.close();
    }
  });

  test('registration bootstrap executes the canonical EVM deploy adapter from the derived deployment plan', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['127.0.0.1/32'],
    });
    const recoverySubjectWrites: Array<Record<string, unknown>> = [];
    const rpcRequests: Array<{ method: string; params: unknown[] }> = [];
    const evmCounterfactualAddress = makeCanonicalEvmCounterfactualAddress();
    const recoverySubjectState = new Map<string, Record<string, unknown>>([
      [
        `evm:11155111:${evmCounterfactualAddress.toLowerCase()}`,
        {
          version: 'smart_account_recovery_subject_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'evm:11155111',
          accountAddress: evmCounterfactualAddress,
          createdAtMs: 1,
          updatedAtMs: 1,
          metadata: {
            chain: 'evm',
            chainId: 11155111,
            accountModel: 'erc4337',
            deployed: false,
            factory: `0x${'bb'.repeat(20)}`,
            entryPoint: `0x${'cc'.repeat(20)}`,
            recoveryAuthority: `0x${'ff'.repeat(20)}`,
            salt: '0x1234',
            counterfactualAddress: evmCounterfactualAddress,
          },
        },
      ],
      [
        `tempo:42431:${`0x${'22'.repeat(20)}`}`,
        {
          version: 'smart_account_recovery_subject_v1',
          userId: 'alice.testnet',
          nearAccountId: 'alice.testnet',
          chainIdKey: 'tempo:42431',
          accountAddress: `0x${'22'.repeat(20)}`,
          createdAtMs: 1,
          updatedAtMs: 1,
          metadata: {
            chain: 'tempo',
            chainId: 42431,
            accountModel: 'tempo-native',
            deployed: false,
            counterfactualAddress: `0x${'22'.repeat(20)}`,
          },
        },
      ],
    ]);
    const router = createRelayRouter(
      makeFakeAuthService({
        createAccountAndRegisterUser: async () => ({
          success: true,
          transactionHash: 'tx-123',
          thresholdEcdsa: {
            relayerKeyId: 'rk-registration-1',
            thresholdEcdsaPublicKeyB64u: 'group-public-key',
            ethereumAddress: `0x${'aa'.repeat(20)}`,
            relayerVerifyingShareB64u: 'relayer-share',
          },
        }),
        getSmartAccountRecoverySubjectByAccount: async ({ chainIdKey, accountAddress }) => ({
          ok: true,
          record:
            (recoverySubjectState.get(
              `${String(chainIdKey).toLowerCase()}:${String(accountAddress).toLowerCase()}`,
            ) as any) || null,
        }),
        listAccountSignersByAccount: async ({ chainIdKey, accountAddress }) => ({
          ok: true,
          records: [
            {
              version: 'account_signer_v1',
              userId: 'alice.testnet',
              chainIdKey,
              accountAddress,
              signerType: 'threshold',
              signerId: `0x${'aa'.repeat(20)}`,
              status: 'active',
              createdAtMs: 1,
              updatedAtMs: 1,
              metadata: {
                chain: chainIdKey.startsWith('tempo:') ? 'tempo' : 'evm',
                chainId: chainIdKey.startsWith('tempo:') ? 42431 : 11155111,
                accountModel: chainIdKey.startsWith('tempo:') ? 'tempo-native' : 'erc4337',
              },
            },
          ],
        }),
        putSmartAccountRecoverySubject: async (record) => {
          recoverySubjectWrites.push(record as unknown as Record<string, unknown>);
          recoverySubjectState.set(
            `${String((record as any).chainIdKey).toLowerCase()}:${String((record as any).accountAddress).toLowerCase()}`,
            record as unknown as Record<string, unknown>,
          );
          return { ok: true, record } as any;
        },
      }),
      {
        apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
        smartAccountDeploy: async (request) => {
          if (request.chain === 'tempo') {
            return {
              ok: true,
              deploymentTxHash: '0xdeploy-tempo',
              code: 'deployed',
            };
          }
          const handler = createEvmSmartAccountDeployHandler({
            config: {
              executorsByChain: new Map([
                [
                  11155111,
                  {
                    chainId: 11155111,
                    rpcUrl: 'https://rpc.example.test',
                    sponsorAddress: '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
                    sponsorPrivateKeyHex:
                      '0x1111111111111111111111111111111111111111111111111111111111111111',
                    maxPriorityFeePerGasFloor: 2_000_000_000n,
                    maxFeePerGasFloor: 40_000_000_000n,
                  },
                ],
              ]),
            },
            logger: null,
          });
          return await handler(request);
        },
      },
    );
    const srv = await startExpressRouter(router);
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url =
        typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      if (url.startsWith(srv.baseUrl)) {
        return await originalFetch(input, init);
      }
      if (url !== 'https://rpc.example.test') {
        throw new Error(`Unexpected fetch url: ${url}`);
      }
      const body = JSON.parse(String(init?.body || '{}')) as {
        id: number;
        method: string;
        params: unknown[];
      };
      rpcRequests.push({ method: body.method, params: body.params });
      const reply = (result: unknown) =>
        new Response(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      switch (body.method) {
        case 'eth_getCode':
          return reply('0x');
        case 'eth_estimateGas':
          return reply('0x61a80');
        case 'eth_getTransactionCount':
          return reply('0x1');
        case 'eth_getBlockByNumber':
          return reply({ number: '0x10', baseFeePerGas: '0x77359400' });
        case 'eth_maxPriorityFeePerGas':
          return reply('0x3b9aca00');
        case 'eth_gasPrice':
          return reply('0x77359400');
        case 'eth_sendRawTransaction':
          return reply(`0x${'ab'.repeat(32)}`);
        case 'eth_getTransactionReceipt':
          return reply({
            status: '0x1',
            blockNumber: '0x10',
            gasUsed: '0x5208',
            effectiveGasPrice: '0x77359400',
          });
        default:
          throw new Error(`Unexpected rpc method: ${body.method}`);
      }
    }) as typeof fetch;

    try {
      const body = makeRegistrationBodyWithSmartAccountTargets();
      (
        (body.threshold_ecdsa as any).smart_account_targets[0] as Record<string, unknown>
      ).counterfactual_address = evmCounterfactualAddress;
      const res = await fetchJson(`${srv.baseUrl}/registration/bootstrap`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${secret}`,
          'x-forwarded-for': '127.0.0.1',
          'x-tatchi-environment-id': 'env-prod',
        },
        body: JSON.stringify(body),
      });

      expect(res.status).toBe(200);
      expect(res.json?.success).toBe(true);
      expect(res.json?.smartAccountDeployments).toEqual([
        {
          chain: 'evm',
          chainId: 11155111,
          accountAddress: evmCounterfactualAddress,
          accountModel: 'erc4337',
          deployed: true,
          deploymentTxHash: `0x${'ab'.repeat(32)}`,
          code: 'deployed',
          counterfactualAddress: evmCounterfactualAddress,
        },
        {
          chain: 'tempo',
          chainId: 42431,
          accountAddress: `0x${'22'.repeat(20)}`,
          accountModel: 'tempo-native',
          deployed: true,
          deploymentTxHash: '0xdeploy-tempo',
          code: 'deployed',
          counterfactualAddress: `0x${'22'.repeat(20)}`,
        },
      ]);
      expect(rpcRequests.map((entry) => entry.method)).toEqual([
        'eth_getCode',
        'eth_estimateGas',
        'eth_getTransactionCount',
        'eth_getBlockByNumber',
        'eth_maxPriorityFeePerGas',
        'eth_gasPrice',
        'eth_sendRawTransaction',
        'eth_getTransactionReceipt',
        'eth_getTransactionReceipt',
      ]);
      expect(rpcRequests[1]?.params[0]).toEqual({
        from: '0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a',
        to: `0x${'bb'.repeat(20)}`,
        value: '0x0',
        data: expect.stringMatching(/^0xf8a59370/),
      });
      expect(recoverySubjectWrites).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            chainIdKey: 'evm:11155111',
            accountAddress: evmCounterfactualAddress,
            metadata: expect.objectContaining({
              deployed: true,
              deploymentTxHash: `0x${'ab'.repeat(32)}`,
              lastDeploymentCode: 'deployed',
              evmDeploymentPlan: expect.objectContaining({
                predictedAddress: evmCounterfactualAddress,
                matchesAccountAddress: true,
                createAccountCalldata: expect.stringMatching(/^0xf8a59370/),
              }),
            }),
          }),
        ]),
      );
    } finally {
      globalThis.fetch = originalFetch;
      await srv.close();
    }
  });

  test('API credential wallet routes require wallets.read scope and stay bound to the key environment', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeWallet({
          id: 'wlt_env_prod_1',
          environmentId: 'env-prod',
          projectId: 'proj_prod',
          userId: 'user-prod',
          externalRefId: 'prod-wallet-1',
          address: `0x${'3'.repeat(40)}`,
        }),
        makeWallet({
          id: 'wlt_env_stage_1',
          environmentId: 'env-stage',
          projectId: 'proj_stage',
          userId: 'user-stage',
          externalRefId: 'stage-wallet-1',
          address: `0x${'4'.repeat(40)}`,
        }),
      ],
    });
    const { secret: limitedSecret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    const { secret: readSecret } = await createActiveSecret(apiKeys, {
      scopes: ['wallets.read'],
      ipAllowlist: ['127.0.0.1/32'],
    });
    const router = createRelayRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      wallets,
    });
    const srv = await startExpressRouter(router);
    try {
      const denied = await fetchJson(`${srv.baseUrl}/v1/wallets`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${limitedSecret}`,
        },
      });
      expect(denied.status).toBe(403);
      expect(denied.json?.code).toBe('secret_key_forbidden_scope');

      const listed = await fetchJson(
        `${srv.baseUrl}/v1/wallets?environmentId=env-stage&userId=user-prod`,
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${readSecret}`,
            'x-forwarded-for': '127.0.0.1',
          },
        },
      );
      expect(listed.status).toBe(200);
      expect(getPath(listed.json, 'wallets', 0, 'id')).toBe('wlt_env_prod_1');
      expect(getPath(listed.json, 'wallets', 1)).toBeUndefined();

      const searched = await fetchJson(`${srv.baseUrl}/v1/wallets/search?q=stage-wallet-1`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${readSecret}`,
          'x-forwarded-for': '127.0.0.1',
        },
      });
      expect(searched.status).toBe(200);
      expect(getPath(searched.json, 'wallets', 0)).toBeUndefined();

      const wallet = await fetchJson(`${srv.baseUrl}/v1/wallets/wlt_env_prod_1`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${readSecret}`,
          'x-forwarded-for': '127.0.0.1',
        },
      });
      expect(wallet.status).toBe(200);
      expect(getPath(wallet.json, 'wallet', 'id')).toBe('wlt_env_prod_1');

      const hidden = await fetchJson(`${srv.baseUrl}/v1/wallets/wlt_env_stage_1`, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${readSecret}`,
          'x-forwarded-for': '127.0.0.1',
        },
      });
      expect(hidden.status).toBe(404);
      expect(hidden.json?.code).toBe('wallet_not_found');
    } finally {
      await srv.close();
    }
  });
});

test.describe('relay API key auth (cloudflare)', () => {
  test('rejects missing API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('secret_key_missing');
  });

  test('rejects invalid API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: { Authorization: 'Bearer sk_invalidsecret' },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(401);
    expect(res.json?.code).toBe('secret_key_invalid');
  });

  test('rejects revoked API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { apiKeyId, secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    await apiKeys.revokeApiKey(apiKeyCtx, apiKeyId);
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_revoked');
  });

  test('rejects key missing required scope', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: [],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_forbidden_scope');
  });

  test('rejects key when environment header mismatches', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: {
        Authorization: `Bearer ${secret}`,
        'x-tatchi-environment-id': 'env-stage',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_environment_mismatch');
  });

  test('rejects key blocked by IP allowlist', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['203.0.113.10/32'],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: {
        Authorization: `Bearer ${secret}`,
        'cf-connecting-ip': '198.51.100.55',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_ip_blocked');
  });

  test('rejects expired API key', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      expiresAt: new Date(Date.now() - 60_000).toISOString(),
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: { Authorization: `Bearer ${secret}` },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(403);
    expect(res.json?.code).toBe('secret_key_revoked');
  });

  test('accepts valid scoped key and records usage', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const meteredEvents: RelayUsageMeterEvent[] = [];
    const { apiKeyId, secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['203.0.113.20/32'],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      apiKeyUsageMeter: {
        recordEvent: async (event) => {
          meteredEvents.push(event);
        },
      },
    });
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: {
        Authorization: `Bearer ${secret}`,
        'cf-connecting-ip': '203.0.113.20',
        'x-tatchi-environment-id': 'env-prod',
      },
      body: makeRegistrationBody(),
      ctx,
    });
    expect(res.status).toBe(200);
    expect(res.json?.success).toBe(true);

    const keys = await apiKeys.listApiKeys(apiKeyCtx);
    const key = keys.find((entry) => entry.id === apiKeyId);
    expect(key).toBeTruthy();
    expect(key?.lastUsedAt).toBeTruthy();
    expect(Number(key?.endpointUsageCounts['POST /registration/bootstrap'] || 0)).toBe(1);
    expect(meteredEvents.length).toBe(1);
    expect(meteredEvents[0]?.action).toBe('wallet_created');
    expect(meteredEvents[0]?.succeeded).toBe(true);
    expect(meteredEvents[0]?.orgId).toBe('org-relay-api-keys');
    expect(meteredEvents[0]?.environmentId).toBe('env-prod');
    expect(meteredEvents[0]?.walletId).toBe('alice.testnet');
  });

  test('registration bootstrap invokes internal smart-account deploy hook for EVM and Tempo targets', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const { secret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
      ipAllowlist: ['203.0.113.20/32'],
    });
    const deployCalls: Array<Record<string, unknown>> = [];
    const recoverySubjectWrites: Array<Record<string, unknown>> = [];
    const handler = createCloudflareRouter(
      makeFakeAuthService({
        createAccountAndRegisterUser: async () => ({
          success: true,
          transactionHash: 'tx-123',
          thresholdEcdsa: {
            relayerKeyId: 'rk-registration-1',
            thresholdEcdsaPublicKeyB64u: 'group-public-key',
            ethereumAddress: `0x${'aa'.repeat(20)}`,
            relayerVerifyingShareB64u: 'relayer-share',
          },
        }),
        getSmartAccountRecoverySubjectByAccount: async ({ chainIdKey, accountAddress }) => ({
          ok: true,
          record: {
            version: 'smart_account_recovery_subject_v1',
            userId: 'alice.testnet',
            nearAccountId: 'alice.testnet',
            chainIdKey,
            accountAddress,
            createdAtMs: 1,
            updatedAtMs: 1,
            metadata: {
              chain: chainIdKey.startsWith('tempo:') ? 'tempo' : 'evm',
              chainId: chainIdKey.startsWith('tempo:') ? 42431 : 11155111,
              accountModel: chainIdKey.startsWith('tempo:') ? 'tempo-native' : 'erc4337',
              deployed: false,
              ...(chainIdKey.startsWith('tempo:')
                ? {}
                : {
                    factory: `0x${'bb'.repeat(20)}`,
                    entryPoint: `0x${'cc'.repeat(20)}`,
                    recoveryAuthority: `0x${'ff'.repeat(20)}`,
                    salt: '0x1234',
                  }),
              counterfactualAddress: accountAddress,
            },
          } as any,
        }),
        listAccountSignersByAccount: async ({ chainIdKey, accountAddress }) => ({
          ok: true,
          records: [
            {
              version: 'account_signer_v1',
              userId: 'alice.testnet',
              chainIdKey,
              accountAddress,
              signerType: 'threshold',
              signerId: `0x${'aa'.repeat(20)}`,
              status: 'active',
              createdAtMs: 1,
              updatedAtMs: 1,
              metadata: {
                chain: chainIdKey.startsWith('tempo:') ? 'tempo' : 'evm',
                chainId: chainIdKey.startsWith('tempo:') ? 42431 : 11155111,
                accountModel: chainIdKey.startsWith('tempo:') ? 'tempo-native' : 'erc4337',
              },
            },
          ],
        }),
        putSmartAccountRecoverySubject: async (record) => {
          recoverySubjectWrites.push(record as unknown as Record<string, unknown>);
          return { ok: true, record } as any;
        },
      }),
      {
        apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
        smartAccountDeploy: async (request) => {
          deployCalls.push({
            nearAccountId: request.nearAccountId,
            chain: request.chain,
            chainId: request.chainId,
            accountAddress: request.accountAddress,
            accountModel: request.accountModel,
            deploymentManifest: request.deploymentManifest,
            evmDeploymentPlan: request.evmDeploymentPlan,
          });
          return {
            ok: true,
            deploymentTxHash: `0xdeploy-${request.chain}`,
          };
        },
      },
    );
    const { ctx } = makeCfCtx();
    const res = await callCf(handler, {
      method: 'POST',
      path: '/registration/bootstrap',
      headers: {
        Authorization: `Bearer ${secret}`,
        'cf-connecting-ip': '203.0.113.20',
        'x-tatchi-environment-id': 'env-prod',
      },
      body: makeRegistrationBodyWithSmartAccountTargets(),
      ctx,
    });
    expect(res.status).toBe(200);
    expect(res.json?.success).toBe(true);
    expect(deployCalls).toEqual([
      expect.objectContaining({
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        chainId: 11155111,
        accountAddress: `0x${'11'.repeat(20)}`,
        accountModel: 'erc4337',
        deploymentManifest: expect.objectContaining({
          counterfactualAddress: `0x${'11'.repeat(20)}`,
          ownerAddresses: [`0x${'aa'.repeat(20)}`],
        }),
        evmDeploymentPlan: expect.objectContaining({
          predictedAddress: expect.stringMatching(/^0x[0-9a-f]{40}$/),
          matchesAccountAddress: false,
          createAccountCalldata: expect.stringMatching(/^0xf8a59370/),
        }),
      }),
      expect.objectContaining({
        nearAccountId: 'alice.testnet',
        chain: 'tempo',
        chainId: 42431,
        accountAddress: `0x${'22'.repeat(20)}`,
        accountModel: 'tempo-native',
        deploymentManifest: expect.objectContaining({
          counterfactualAddress: `0x${'22'.repeat(20)}`,
          ownerAddresses: [`0x${'aa'.repeat(20)}`],
        }),
        evmDeploymentPlan: undefined,
      }),
    ]);
    expect(res.json?.smartAccountDeployments).toEqual([
      {
        chain: 'evm',
        chainId: 11155111,
        accountAddress: `0x${'11'.repeat(20)}`,
        accountModel: 'erc4337',
        deployed: true,
        deploymentTxHash: '0xdeploy-evm',
        counterfactualAddress: `0x${'11'.repeat(20)}`,
      },
      {
        chain: 'tempo',
        chainId: 42431,
        accountAddress: `0x${'22'.repeat(20)}`,
        accountModel: 'tempo-native',
        deployed: true,
        deploymentTxHash: '0xdeploy-tempo',
        counterfactualAddress: `0x${'22'.repeat(20)}`,
      },
    ]);
    expect(recoverySubjectWrites).toHaveLength(4);
    const evmMetadata = recoverySubjectWrites[1]?.metadata as any;
    const tempoMetadata = recoverySubjectWrites[3]?.metadata as any;
    expect(evmMetadata?.deploymentManifest?.ownerAddresses).toEqual([
      `0x${'aa'.repeat(20)}`,
    ]);
    expect(evmMetadata?.evmDeploymentPlan?.predictedAddress).toMatch(
      /^0x[0-9a-f]{40}$/,
    );
    expect(evmMetadata?.evmDeploymentPlan?.createAccountCalldata).toMatch(
      /^0xf8a59370/,
    );
    expect(Number.isFinite(Number(evmMetadata?.evmDeploymentPlanUpdatedAtMs))).toBe(true);
    expect(tempoMetadata?.deploymentManifest?.ownerAddresses).toEqual([
      `0x${'aa'.repeat(20)}`,
    ]);
    expect(tempoMetadata?.evmDeploymentPlan).toBeUndefined();
    expect(tempoMetadata?.evmDeploymentPlanUpdatedAtMs).toBeUndefined();
  });

  test('API credential wallet routes require wallets.read scope and stay bound to the key environment', async () => {
    const apiKeys = createInMemoryConsoleApiKeyService();
    const wallets = createInMemoryConsoleWalletService({
      seedWallets: [
        makeWallet({
          id: 'wlt_env_prod_1',
          environmentId: 'env-prod',
          projectId: 'proj_prod',
          userId: 'user-prod',
          externalRefId: 'prod-wallet-1',
          address: `0x${'3'.repeat(40)}`,
        }),
        makeWallet({
          id: 'wlt_env_stage_1',
          environmentId: 'env-stage',
          projectId: 'proj_stage',
          userId: 'user-stage',
          externalRefId: 'stage-wallet-1',
          address: `0x${'4'.repeat(40)}`,
        }),
      ],
    });
    const { secret: limitedSecret } = await createActiveSecret(apiKeys, {
      scopes: ['accounts.create'],
    });
    const { secret: readSecret } = await createActiveSecret(apiKeys, {
      scopes: ['wallets.read'],
      ipAllowlist: ['203.0.113.20/32'],
    });
    const handler = createCloudflareRouter(makeRelayService(), {
      apiKeyAuth: createRelayApiKeyAuthAdapter(apiKeys),
      wallets,
    });
    const { ctx } = makeCfCtx();

    const denied = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets',
      headers: {
        Authorization: `Bearer ${limitedSecret}`,
      },
      ctx,
    });
    expect(denied.status).toBe(403);
    expect(denied.json?.code).toBe('secret_key_forbidden_scope');

    const listed = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets?environmentId=env-stage&userId=user-prod',
      headers: {
        Authorization: `Bearer ${readSecret}`,
        'cf-connecting-ip': '203.0.113.20',
      },
      ctx,
    });
    expect(listed.status).toBe(200);
    expect(getPath(listed.json, 'wallets', 0, 'id')).toBe('wlt_env_prod_1');
    expect(getPath(listed.json, 'wallets', 1)).toBeUndefined();

    const searched = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets/search?q=stage-wallet-1',
      headers: {
        Authorization: `Bearer ${readSecret}`,
        'cf-connecting-ip': '203.0.113.20',
      },
      ctx,
    });
    expect(searched.status).toBe(200);
    expect(getPath(searched.json, 'wallets', 0)).toBeUndefined();

    const wallet = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets/wlt_env_prod_1',
      headers: {
        Authorization: `Bearer ${readSecret}`,
        'cf-connecting-ip': '203.0.113.20',
      },
      ctx,
    });
    expect(wallet.status).toBe(200);
    expect(getPath(wallet.json, 'wallet', 'id')).toBe('wlt_env_prod_1');

    const hidden = await callCf(handler, {
      method: 'GET',
      path: '/v1/wallets/wlt_env_stage_1',
      headers: {
        Authorization: `Bearer ${readSecret}`,
        'cf-connecting-ip': '203.0.113.20',
      },
      ctx,
    });
    expect(hidden.status).toBe(404);
    expect(hidden.json?.code).toBe('wallet_not_found');
  });
});
