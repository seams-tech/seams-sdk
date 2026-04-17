import type { Page } from '@playwright/test';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import {
  createInMemoryJwtSessionAdapter,
  installCreateAccountAndRegisterUserMock,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupThresholdE2ePage,
} from '../e2e/thresholdEd25519.testUtils';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleOrgProjectEnvService,
  createRelayBootstrapGrantBroker,
  createRelayPublishableKeyAuthAdapter,
  createRelayRouter,
} from '@server/router/express-adaptor';
import { startExpressRouter } from '../relayer/helpers';

export type ThresholdEcdsaTempoFlowOptions = {
  relayerUrl: string;
  signingKind?: 'tempoTransaction' | 'eip1559';
  accountId?: string;
  thresholdEcdsaPresignPool?: {
    enabled?: boolean;
    targetDepth?: number;
    lowWatermark?: number;
    maxRefillInFlight?: number;
    refillAttemptTimeoutMs?: number;
  };
  connectSession?: boolean;
  connectSessionTtlMs?: number;
  connectSessionRemainingUses?: number;
  waitBeforeSignMs?: number;
};

export type ThresholdEcdsaTempoFlowResult = {
  ok: boolean;
  accountId: string;
  keygen?: {
    ok: boolean;
    ecdsaThresholdKeyId?: string;
    // Backend bridge details are still exposed here for low-level harnesses.
    // Product-boundary assertions should prefer ecdsaThresholdKeyId/public key/address.
    relayerKeyId?: string;
    clientVerifyingShareB64u?: string;
    thresholdEcdsaPublicKeyB64u?: string;
    ethereumAddress?: string;
    relayerVerifyingShareB64u?: string;
    participantIds?: number[];
    code?: string;
    message?: string;
  };
  session?: {
    ok: boolean;
    sessionId?: string;
    jwt?: string;
    expiresAtMs?: number;
    remainingUses?: number;
    code?: string;
    message?: string;
  };
  signed?:
    | {
        chain: 'tempo';
        kind: 'tempoTransaction';
        senderHashHex: string;
        rawTxHex: string;
      }
    | {
        chain: 'evm';
        kind: 'eip1559';
        txHashHex: string;
        rawTxHex: string;
      };
  error?: string;
};

export async function setupThresholdEcdsaTempoHarness(page: Page): Promise<{
  baseUrl: string;
  close: () => Promise<void>;
}> {
  await setupThresholdE2ePage(page);

  const keysOnChain = new Set<string>();
  const nonceByPublicKey = new Map<string, number>();

  const { service, threshold } = makeAuthServiceForThreshold(keysOnChain, {
    THRESHOLD_NODE_ROLE: 'coordinator',
  });
  await service.getRelayerAccount();

  const bootstrapTokenStore = createInMemoryConsoleBootstrapTokenService();
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const apiKeys = createInMemoryConsoleApiKeyService();
  const bootstrapAdminCtx = {
    orgId: 'org_threshold_ecdsa_tempo',
    actorUserId: 'user_threshold_ecdsa_tempo',
    roles: ['admin'],
  } as const;
  const bootstrapProjectId = 'proj_threshold_ecdsa_tempo';
  const runtimePolicyScope = {
    orgId: bootstrapAdminCtx.orgId,
    projectId: bootstrapProjectId,
    envId: 'dev',
  } as const;
  const managedRegistrationEnvironmentId = `${bootstrapProjectId}:dev`;
  await orgProjectEnv.upsertOrganization(bootstrapAdminCtx, {
    name: 'Threshold ECDSA Tempo Org',
    slug: 'threshold-ecdsa-tempo-org',
  });
  await orgProjectEnv.createProject(bootstrapAdminCtx, {
    id: bootstrapProjectId,
    name: 'Threshold ECDSA Tempo Project',
    liveEnvironmentsEnabled: true,
  });

  const session = createInMemoryJwtSessionAdapter();
  const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
  const createdPublishableKey = await apiKeys.createApiKey(bootstrapAdminCtx, {
    kind: 'publishable_key',
    name: 'threshold-ecdsa-tempo-browser',
    environmentId: managedRegistrationEnvironmentId,
    allowedOrigins: [frontendOrigin, 'https://example.localhost'],
    rateLimitBucket: 'default_web_v1',
    quotaBucket: 'free_registrations_v1',
  });
  const managedRegistration = {
    environmentId: managedRegistrationEnvironmentId,
    publishableKey: createdPublishableKey.secret,
  } as const;
  const router = createRelayRouter(service, {
    corsOrigins: [frontendOrigin],
    threshold,
    session,
    publishableKeyAuth: createRelayPublishableKeyAuthAdapter(apiKeys),
    bootstrapGrantBroker: createRelayBootstrapGrantBroker({
      apiKeys,
      tokenStore: bootstrapTokenStore,
      orgProjectEnv,
      rateLimitsByBucket: {
        default_web_v1: { windowMs: 60_000, maxIssued: 100 },
      },
      quotasByBucket: {
        free_registrations_v1: { maxIssued: 100 },
      },
    }),
    bootstrapTokenStore,
  });
  const server = await startExpressRouter(router);

  await page.addInitScript((config) => {
    (window as any).__w3aManagedRegistration = config;
  }, managedRegistration);
  await page.evaluate((config) => {
    (window as any).__w3aManagedRegistration = config;
  }, managedRegistration);

  await installCreateAccountAndRegisterUserMock(page, {
    relayerBaseUrl: server.baseUrl,
    session,
    threshold,
    runtimePolicyScope,
    onNewPublicKey: (publicKey) => {
      keysOnChain.add(publicKey);
      nonceByPublicKey.set(publicKey, 0);
    },
  });
  await installFastNearRpcMock(page, {
    keysOnChain,
    nonceByPublicKey,
  });

  return {
    baseUrl: server.baseUrl,
    close: server.close,
  };
}

export async function runThresholdEcdsaTempoFlow(
  page: Page,
  options: ThresholdEcdsaTempoFlowOptions,
): Promise<ThresholdEcdsaTempoFlowResult> {
  return await page.evaluate(async (input) => {
    const sdkMod = await import('/sdk/esm/index.js');

    const { TatchiPasskey } = sdkMod as any;

    const accountId =
      typeof input.accountId === 'string' && input.accountId.trim()
        ? input.accountId.trim()
        : `tempoecdsa${Date.now()}.w3a-v1.testnet`;

    const confirmationConfig = {
      uiMode: 'none' as const,
      behavior: 'skipClick' as const,
      autoProceedDelay: 0,
    };
    const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;

    const pm = new TatchiPasskey({
      nearNetwork: 'testnet',
      nearRpcUrl: 'https://test.rpc.fastnear.com',
      relayerAccount: 'web3-authn-v4.testnet',
      ...(input.thresholdEcdsaPresignPool
        ? { thresholdEcdsaPresignPool: input.thresholdEcdsaPresignPool }
        : {}),
      relayer: {
        url: input.relayerUrl,
        smartAccountDeploymentMode: 'observe',
      },
      ...(managedRegistration
        ? {
            registration: {
              mode: 'managed' as const,
              environmentId: String(managedRegistration.environmentId || ''),
              publishableKey: String(managedRegistration.publishableKey || ''),
            },
          }
        : {}),
      iframeWallet: {
        walletOrigin: '',
        walletServicePath: '/wallet-service',
        sdkBasePath: '/sdk',
        rpIdOverride: 'example.localhost',
      },
    });

    try {
      const registration = await pm.registration.registerPasskeyInternal(
        accountId,
        {
          signerOptions: {
            tempo: {
              enabled: false,
              participantIds: [1, 2],
              signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
            },
            evm: {
              enabled: false,
              participantIds: [1, 2],
              signingSession: { kind: 'jwt', ttlMs: 1, remainingUses: 1 },
            },
          },
        },
        confirmationConfig,
      );
      if (!registration?.success) {
        return {
          ok: false,
          accountId,
          error: String(registration?.error || 'registerPasskeyInternal failed'),
        };
      }

      let keygen: any;
      let session: any = undefined;
      if (input.connectSession !== false) {
        try {
          const boot = await pm.tempo.bootstrapEcdsaSession({
            nearAccountId: accountId,
            options: {
              relayerUrl: input.relayerUrl,
              ...(typeof input.connectSessionTtlMs === 'number'
                ? { ttlMs: input.connectSessionTtlMs }
                : {}),
              ...(typeof input.connectSessionRemainingUses === 'number'
                ? { remainingUses: input.connectSessionRemainingUses }
                : {}),
            },
          });
          keygen = boot.keygen;
          session = boot.session;
        } catch (e: unknown) {
          return {
            ok: false,
            accountId,
            error: String(
              e && typeof e === 'object' && 'message' in e
                ? (e as { message?: unknown }).message
                : e || 'bootstrapEcdsaSession failed',
            ),
          };
        }
      }

      const waitBeforeSignMs = input.waitBeforeSignMs;
      if (typeof waitBeforeSignMs === 'number' && waitBeforeSignMs > 0) {
        await new Promise((resolve) => setTimeout(resolve, Math.floor(waitBeforeSignMs)));
      }

      const request =
        input.signingKind === 'eip1559'
          ? {
              chain: 'evm' as const,
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 11155111,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            }
          : {
              chain: 'tempo' as const,
              kind: 'tempoTransaction' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 42431,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: '0x' }],
                accessList: [],
                nonceKey: 0n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' as const },
                aaAuthorizationList: [],
              },
            };

      try {
        const signed = await pm.tempo.signTempo({
          nearAccountId: accountId,
          request,
          options: { confirmationConfig },
        });

        return {
          ok: true,
          accountId,
          keygen,
          session,
          signed,
        };
      } catch (e: unknown) {
        const message = String(
          e && typeof e === 'object' && 'message' in e
            ? (e as { message?: unknown }).message
            : e || 'signTempo failed',
        );
        return {
          ok: false,
          accountId,
          keygen,
          session,
          error: message,
        };
      }
    } catch (e: unknown) {
      const message = String(
        e && typeof e === 'object' && 'message' in e
          ? (e as { message?: unknown }).message
          : e || 'threshold ecdsa flow failed',
      );
      return {
        ok: false,
        accountId,
        error: message,
      };
    }
  }, options);
}
