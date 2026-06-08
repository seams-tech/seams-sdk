import type { Page } from '@playwright/test';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import {
  createPassthroughSigningSessionSealCipherAdapter,
  createSigningSessionSealPolicyFromThresholdAuthSessionStores,
  createSigningSessionSealRoutesOptions,
} from '@server/threshold/session/signingSessionSeal';
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
import {
  installBrowserSigningBudgetStatusReader,
  type SigningBudgetStatusResult,
} from './signingBudgetStatus';

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

export type ThresholdEcdsaTempoConnectedSession = {
  kind: 'connected';
  ok: true;
  sessionId: string;
  walletSigningSessionId: string;
  jwt: string;
  expiresAtMs: number;
  remainingUses: number;
};

export type ThresholdEcdsaTempoRejectedSession = {
  kind: 'rejected';
  ok: false;
  code: string;
  message: string;
};

export type ThresholdEcdsaTempoFlowSession =
  | ThresholdEcdsaTempoConnectedSession
  | ThresholdEcdsaTempoRejectedSession;

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
  session?: ThresholdEcdsaTempoFlowSession;
  walletSession?: {
    nearAccountId: string | null;
    isLoggedIn: boolean;
    thresholdEcdsaEthereumAddress: string | null;
    thresholdEcdsaPublicKeyB64u: string | null;
  };
  budgetStatus?: SigningBudgetStatusResult;
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
  const thresholdAuthStores = threshold as unknown as {
    authSessionStore?: unknown;
    ecdsaAuthSessionStore?: unknown;
  };
  if (!thresholdAuthStores.authSessionStore || !thresholdAuthStores.ecdsaAuthSessionStore) {
    throw new Error('Missing threshold auth session stores for Tempo signing-session policy');
  }
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
    signingRootVersion: 'default',
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
    orgProjectEnv,
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
    signingSessionSeal: createSigningSessionSealRoutesOptions({
      sessionPolicy: createSigningSessionSealPolicyFromThresholdAuthSessionStores({
        ed25519Stores: [thresholdAuthStores.authSessionStore as any],
        ecdsaStores: [thresholdAuthStores.ecdsaAuthSessionStore as any],
        walletBudgetStores: [thresholdAuthStores.authSessionStore as any],
      }),
      cipher: createPassthroughSigningSessionSealCipherAdapter(),
    }),
  });
  const server = await startExpressRouter(router);

  await page.addInitScript((config) => {
    (window as any).__w3aManagedRegistration = config;
  }, managedRegistration);
  await page.addInitScript(installBrowserSigningBudgetStatusReader());
  await page.addInitScript(() => {
    const w = window as any;
    if (!w.__w3aRegistrationContinuationCaptureInstalled) {
      w.__w3aRegistrationContinuationCaptureInstalled = true;
      w.__w3aRegistrationContinuationToken = '';
      const originalFetch = globalThis.fetch.bind(globalThis);
      globalThis.fetch = async (...args: Parameters<typeof fetch>) => {
        const response = await originalFetch(...args);
        try {
          const cloned = response.clone();
          if (String(cloned.headers.get('content-type') || '').includes('application/json')) {
            const payload = await cloned.json();
            const token = String(payload?.registrationContinuation?.token || '').trim();
            if (token) w.__w3aRegistrationContinuationToken = token;
          }
        } catch {}
        return response;
      };
    }
    w.__w3aTempoChainTarget = {
      kind: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-moderato',
    };
    w.__w3aEvmSepoliaChainTarget = {
      kind: 'evm',
      namespace: 'eip155',
      chainId: 11155111,
      networkSlug: 'ethereum-sepolia',
    };
    w.__w3aChainTargetForTempoRequest = (request: {
      chain?: unknown;
      tx?: { chainId?: unknown };
    }) => {
      const chain = String(request?.chain || '').trim();
      const chainId = Number(request?.tx?.chainId);
      if (chain === 'tempo') return w.__w3aTempoChainTarget;
      if (chain === 'evm' && chainId === 42431) return w.__w3aTempoChainTarget;
      if (chain === 'evm') {
        return {
          kind: 'evm',
          namespace: 'eip155',
          chainId: Number.isSafeInteger(chainId) && chainId > 0 ? chainId : 11155111,
          networkSlug: chainId === 11155111 ? 'ethereum-sepolia' : `evm-${chainId}`,
        };
      }
      throw new Error('unsupported Tempo signing request chain');
    };
    w.__w3aBootstrapFreshTempoEcdsaSession = async (input: {
      pm: any;
      accountId: string;
      relayerUrl: string;
      ttlMs: number;
      remainingUses: number;
      chainTarget?:
        | {
            kind: 'tempo';
            chainId: number;
            networkSlug: string;
          }
        | {
            kind: 'evm';
            namespace: 'eip155';
            chainId: number;
            networkSlug: string;
          };
    }) => {
      const indexedDbMod = await import('/sdk/esm/core/indexedDB/index.js');
      const keyMaterialMod = await import('/sdk/esm/core/accountData/near/keyMaterial.js');
      const recordsMod = await import('/sdk/esm/core/signingEngine/session/persistence/records.js');
      const webauthnCredentialMod =
        await import('/sdk/esm/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u.js');
      const credentialExtensionsMod =
        await import('/sdk/esm/core/signingEngine/webauthnAuth/credentials/credentialExtensions.js');
      const identityMod =
        await import('/sdk/esm/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.js');
      const { IndexedDBManager } = indexedDbMod as any;
      const { getNearThresholdKeyMaterial } = keyMaterialMod as any;
      const { getStoredThresholdEd25519SessionRecordForAccount } = recordsMod as any;
      const { collectAuthenticationCredentialForChallengeB64u } = webauthnCredentialMod as any;
      const { getPrfFirstB64uFromCredential } = credentialExtensionsMod as any;
      const { buildEvmFamilyEcdsaKeyIdentity, buildEvmFamilyEcdsaSessionLanePolicy } =
        identityMod as any;
      const context = input.pm.getContext();
      const signingEngine = context.signingEngine;
      const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
        {
          clientDB: IndexedDBManager,
          keyMaterialStore: IndexedDBManager,
        },
        input.accountId,
        1,
      ).catch(() => null);
      const registrationEd25519Record = getStoredThresholdEd25519SessionRecordForAccount(
        input.accountId,
      );
      const relayerKeyId = String(
        thresholdKeyMaterial?.relayerKeyId || registrationEd25519Record?.relayerKeyId || '',
      ).trim();
      if (!relayerKeyId) {
        throw new Error('relayerKeyId is required for fresh Tempo ECDSA bootstrap');
      }
      const challengeBytes = new Uint8Array(32);
      crypto.getRandomValues(challengeBytes);
      const challengeB64u = btoa(String.fromCharCode(...challengeBytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/g, '');
      const login = await input.pm.auth.unlock(input.accountId, {
        session: {
          kind: 'jwt',
          relayUrl: input.relayerUrl,
          exchange: { type: 'passkey_assertion' },
        },
        signingSession: { ttlMs: 0, remainingUses: 0 },
      });
      if (!login?.success || !String(login.jwt || '').trim()) {
        throw new Error(String(login?.error || 'unlock failed for fresh Tempo ECDSA bootstrap'));
      }
      const localPrfCredential = await collectAuthenticationCredentialForChallengeB64u({
        credentialStore: IndexedDBManager,
        touchIdPrompt: {
          getAuthenticationCredentialsSerializedForChallengeB64u: async ({
            subjectId,
            challengeB64u,
            allowCredentials,
            includeSecondPrfOutput,
          }: {
            subjectId: string;
            challengeB64u: string;
            allowCredentials?: Array<{
              id: string;
              type: string;
              transports: AuthenticatorTransport[];
            }>;
            includeSecondPrfOutput?: boolean;
          }) =>
            await signingEngine.getAuthenticationCredentialsSerialized({
              subjectId,
              challengeB64u,
              allowCredentials: Array.isArray(allowCredentials) ? allowCredentials : [],
              includeSecondPrfOutput,
            }),
        },
        nearAccountId: input.accountId,
        challengeB64u,
      });
      const participantIds = Array.isArray(thresholdKeyMaterial?.participants)
        ? thresholdKeyMaterial.participants
            .map((participant: { id?: unknown }) => Number(participant?.id))
            .filter((id: number) => Number.isFinite(id))
        : Array.isArray(registrationEd25519Record?.participantIds)
          ? registrationEd25519Record.participantIds
              .map((id: unknown) => Number(id))
              .filter((id: number) => Number.isFinite(id))
          : [1, 2];
      const managedRegistration =
        w.__w3aManagedRegistration && typeof w.__w3aManagedRegistration === 'object'
          ? (w.__w3aManagedRegistration as {
              environmentId?: unknown;
              publishableKey?: unknown;
            })
          : null;
      const runtimeScopeBootstrap =
        managedRegistration &&
        String(managedRegistration.environmentId || '').trim() &&
        String(managedRegistration.publishableKey || '').trim()
          ? {
              environmentId: String(managedRegistration.environmentId || '').trim(),
              publishableKey: String(managedRegistration.publishableKey || '').trim(),
            }
          : null;
      const connectedEd25519 = await signingEngine.connectEd25519Session({
        kind: 'fresh_ed25519_provisioning',
        nearAccountId: input.accountId,
        relayerUrl: input.relayerUrl,
        relayerKeyId,
        participantIds,
        sessionKind: 'jwt',
        source: 'login',
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
        appSessionJwt: String(login.jwt || ''),
        ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
        localPrfCredential,
      });
      const walletSigningSessionId = String(connectedEd25519?.walletSigningSessionId || '').trim();
      const passkeyPrfFirstB64u = String(
        connectedEd25519?.ecdsaHssPasskeyPrfFirstB64u ||
          getPrfFirstB64uFromCredential(localPrfCredential) ||
          '',
      ).trim();
      if (!connectedEd25519?.ok || !walletSigningSessionId || !passkeyPrfFirstB64u) {
        throw new Error(
          String(
            connectedEd25519?.message ||
              connectedEd25519?.code ||
              'connectEd25519Session failed for fresh Tempo ECDSA bootstrap',
          ),
        );
      }
      const chainTarget = input.chainTarget || {
        kind: 'tempo' as const,
        chainId: 42431,
        networkSlug: 'tempo-moderato',
      };
      const existingTargetRecord = Array.isArray(
        signingEngine.listThresholdEcdsaSessionRecordsForWalletTarget?.({
          walletId: input.accountId,
          chainTarget,
        }),
      )
        ? signingEngine
            .listThresholdEcdsaSessionRecordsForWalletTarget?.({
              walletId: input.accountId,
              chainTarget,
            })
            ?.find((record: Record<string, unknown>) => {
              const recordChainTarget =
                record?.chainTarget &&
                typeof record.chainTarget === 'object' &&
                !Array.isArray(record.chainTarget)
                  ? (record.chainTarget as { kind?: unknown; chainId?: unknown })
                  : null;
              return (
                recordChainTarget?.kind === chainTarget.kind &&
                Number(recordChainTarget.chainId) === chainTarget.chainId
              );
            }) || null
        : null;
      const existingEcdsaThresholdKeyId = String(
        existingTargetRecord?.ecdsaThresholdKeyId || '',
      ).trim();
      if (existingTargetRecord) {
        signingEngine.clearThresholdEcdsaSessionRecordForWalletTarget?.({
          walletId: input.accountId,
          chainTarget,
        });
      }
      const thresholdSessionId = String(existingTargetRecord?.thresholdSessionId || '').trim()
        ? String(existingTargetRecord?.thresholdSessionId || '').trim()
        : typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
          ? `threshold-ecdsa-browser-${crypto.randomUUID()}`
          : `threshold-ecdsa-browser-${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const sessionIdentity = {
        thresholdSessionId,
        walletSigningSessionId,
      };
      const routeAuth = null;
      const authMaterial = routeAuth
        ? { routeAuth }
        : { webauthnAuthentication: localPrfCredential };
      const existingParticipantIds = Array.isArray(existingTargetRecord?.participantIds)
        ? existingTargetRecord.participantIds
            .map((id: unknown) => Number(id))
            .filter((id: number) => Number.isFinite(id))
        : [];
      const keyIdentityParticipantIds =
        existingParticipantIds.length > 0 ? existingParticipantIds : participantIds;
      const existingThresholdOwnerAddress = String(
        existingTargetRecord?.ethereumAddress || '',
      ).trim();
      const existingKeyHandle = String(existingTargetRecord?.keyHandle || '').trim();
      const existingSigningRootId = String(existingTargetRecord?.signingRootId || '').trim();
      const existingSigningRootVersion =
        String(existingTargetRecord?.signingRootVersion || 'default').trim() || 'default';
      const rpId =
        typeof signingEngine.getRpId === 'function'
          ? String(signingEngine.getRpId() || '').trim() || 'example.localhost'
          : 'example.localhost';
      const exactActivationIdentity =
        routeAuth &&
        existingKeyHandle &&
        existingEcdsaThresholdKeyId &&
        existingSigningRootId &&
        existingThresholdOwnerAddress &&
        keyIdentityParticipantIds.length > 0
          ? (() => {
              try {
                const key = buildEvmFamilyEcdsaKeyIdentity({
                  walletId: input.accountId,
                  rpId,
                  ecdsaThresholdKeyId: existingEcdsaThresholdKeyId,
                  signingRootId: existingSigningRootId,
                  signingRootVersion: existingSigningRootVersion,
                  participantIds: keyIdentityParticipantIds,
                  thresholdOwnerAddress: existingThresholdOwnerAddress,
                });
                const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
                  chainTarget,
                  thresholdSessionId: sessionIdentity.thresholdSessionId,
                  walletSigningSessionId: sessionIdentity.walletSigningSessionId,
                  thresholdSessionKind: 'jwt',
                  ttlMs: input.ttlMs,
                  remainingUses: input.remainingUses,
                });
                return { keyHandle: existingKeyHandle, key, lanePolicy };
              } catch {
                return null;
              }
            })()
          : null;
      const bootstrapRequest = {
        kind: 'passkey_fresh_ecdsa_bootstrap' as const,
        walletId: input.accountId,
        chainTarget,
        source: 'manual-bootstrap' as const,
        relayerUrl: input.relayerUrl,
        ...(existingEcdsaThresholdKeyId && (!routeAuth || exactActivationIdentity)
          ? { ecdsaThresholdKeyId: existingEcdsaThresholdKeyId }
          : {}),
        participantIds,
        sessionKind: 'jwt' as const,
        sessionIdentity,
        passkeyPrfFirstB64u: passkeyPrfFirstB64u,
        ...authMaterial,
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
        ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
        ...(exactActivationIdentity
          ? {
              keyHandle: exactActivationIdentity.keyHandle,
              key: exactActivationIdentity.key,
              lanePolicy: exactActivationIdentity.lanePolicy,
            }
          : {}),
      };
      return await signingEngine.bootstrapEcdsaSession(bootstrapRequest);
    };
    w.__w3aBootstrapFreshEcdsaForRequest = async (input: {
      pm: any;
      accountId: string;
      relayerUrl: string;
      ttlMs: number;
      remainingUses: number;
      request: { chain?: unknown; tx?: { chainId?: unknown } };
    }) =>
      await w.__w3aBootstrapFreshTempoEcdsaSession({
        pm: input.pm,
        accountId: input.accountId,
        relayerUrl: input.relayerUrl,
        ttlMs: input.ttlMs,
        remainingUses: input.remainingUses,
        chainTarget: w.__w3aChainTargetForTempoRequest(input.request),
      });
  });
  await page.reload({ waitUntil: 'domcontentloaded' });
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
    const indexedDbMod = await import('/sdk/esm/core/indexedDB/index.js');
    const keyMaterialMod = await import('/sdk/esm/core/accountData/near/keyMaterial.js');
    const recordsMod = await import('/sdk/esm/core/signingEngine/session/persistence/records.js');
    const webauthnCredentialMod =
      await import('/sdk/esm/core/signingEngine/webauthnAuth/credentials/collectAuthenticationCredentialForChallengeB64u.js');
    const credentialExtensionsMod =
      await import('/sdk/esm/core/signingEngine/webauthnAuth/credentials/credentialExtensions.js');
    const identityMod =
      await import('/sdk/esm/core/signingEngine/session/identity/evmFamilyEcdsaIdentity.js');

    const { SeamsWeb } = sdkMod as any;
    const { IndexedDBManager } = indexedDbMod as any;
    const { getNearThresholdKeyMaterial } = keyMaterialMod as any;
    const { getStoredThresholdEd25519SessionRecordForAccount } = recordsMod as any;
    const { collectAuthenticationCredentialForChallengeB64u } = webauthnCredentialMod as any;
    const { getPrfFirstB64uFromCredential } = credentialExtensionsMod as any;
    const { buildEvmFamilyEcdsaKeyIdentity, buildEvmFamilyEcdsaSessionLanePolicy } =
      identityMod as any;

    const accountId =
      typeof input.accountId === 'string' && input.accountId.trim()
        ? input.accountId.trim()
        : `tempoecdsa${Date.now()}.w3a-v1.testnet`;

    const confirmationConfig = {
      uiMode: 'none' as const,
      behavior: 'skipClick' as const,
      autoProceedDelay: 0,
    };
    const challengeBytes = new Uint8Array(32);
    crypto.getRandomValues(challengeBytes);
    const localPrfChallengeB64u = btoa(String.fromCharCode(...challengeBytes))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/g, '');
    const managedRegistration = (globalThis as any).__w3aManagedRegistration || null;
    const originalFetch = globalThis.fetch.bind(globalThis);
    let registrationContinuationToken = '';
    globalThis.fetch = async (...args: Parameters<typeof fetch>) => {
      const response = await originalFetch(...args);
      try {
        const cloned = response.clone();
        if (String(cloned.headers.get('content-type') || '').includes('application/json')) {
          const payload = await cloned.json();
          const token = String(payload?.registrationContinuation?.token || '').trim();
          if (token) registrationContinuationToken = token;
        }
      } catch {}
      return response;
    };

    const pm = new SeamsWeb({
      nearNetwork: 'testnet',
      nearRpcUrl: 'https://test.rpc.fastnear.com',
      relayerAccount: 'web3-authn-v4.testnet',
      ...(input.thresholdEcdsaPresignPool
        ? { thresholdEcdsaPresignPool: input.thresholdEcdsaPresignPool }
        : {}),
      relayer: {
        url: input.relayerUrl,
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
    (globalThis as any).__w3aTempoHighLevelPm = pm;

    try {
      const registration = await pm.registration.registerPasskey(accountId, {
        signerOptions: {
          tempo: {
            enabled: false,
            participantIds: [1, 2],
            signingSession: { kind: 'jwt', ttlMs: 120_000, remainingUses: 4 },
          },
          evm: {
            enabled: false,
            participantIds: [1, 2],
            signingSession: { kind: 'jwt', ttlMs: 120_000, remainingUses: 4 },
          },
        },
        confirmationConfig: confirmationConfig,
      });
      if (!registration?.success) {
        return {
          ok: false,
          accountId,
          error: String(registration?.error || 'registerPasskey failed'),
        };
      }
      globalThis.fetch = originalFetch;
      const signingEngine = (pm as any).signingEngine as {
        bootstrapEcdsaSession: (args: Record<string, unknown>) => Promise<Record<string, unknown>>;
        connectEd25519Session: (args: Record<string, unknown>) => Promise<Record<string, unknown>>;
        getRpId?: () => string;
        getAuthenticationCredentialsSerialized: (args: {
          subjectId: string;
          challengeB64u: string;
          allowCredentials: Array<{
            id: string;
            type: string;
            transports: AuthenticatorTransport[];
          }>;
          includeSecondPrfOutput?: boolean;
        }) => Promise<unknown>;
        listThresholdEcdsaSessionRecordsForWalletTarget?: (args: {
          walletId: string;
          chainTarget: { kind: string; chainId: number; networkSlug?: string };
        }) => Array<Record<string, unknown>>;
        clearThresholdEcdsaSessionRecordForWalletTarget?: (args: {
          walletId: string;
          chainTarget: { kind: string; chainId: number; networkSlug?: string };
          source?: string;
        }) => void;
      };
      const thresholdKeyMaterial = await getNearThresholdKeyMaterial(
        {
          clientDB: IndexedDBManager,
          keyMaterialStore: IndexedDBManager,
        },
        accountId,
        1,
      ).catch(() => null);
      if (!thresholdKeyMaterial?.relayerKeyId) {
        return {
          ok: false,
          accountId,
          error: 'missing threshold Ed25519 key material after registration',
        };
      }
      const registrationEd25519Record = getStoredThresholdEd25519SessionRecordForAccount(accountId);
      if (!registrationEd25519Record) {
        return {
          ok: false,
          accountId,
          error: 'missing persisted Ed25519 registration session identity after registration',
        };
      }
      const login = await pm.auth.unlock(accountId, {
        session: {
          kind: 'jwt',
          relayUrl: input.relayerUrl,
          exchange: { type: 'passkey_assertion' },
        },
        signingSession: { ttlMs: 0, remainingUses: 0 },
      });
      if (!login?.success || !String(login.jwt || '').trim()) {
        return {
          ok: false,
          accountId,
          error: String(login?.error || 'unlock failed'),
        };
      }
      const localPrfCredential = await collectAuthenticationCredentialForChallengeB64u({
        credentialStore: IndexedDBManager,
        touchIdPrompt: {
          getAuthenticationCredentialsSerializedForChallengeB64u: async ({
            subjectId,
            challengeB64u,
            allowCredentials,
            includeSecondPrfOutput,
          }: {
            subjectId: string;
            challengeB64u: string;
            allowCredentials?: Array<{
              id: string;
              type: string;
              transports: AuthenticatorTransport[];
            }>;
            includeSecondPrfOutput?: boolean;
          }) =>
            await signingEngine.getAuthenticationCredentialsSerialized({
              subjectId,
              challengeB64u,
              allowCredentials: Array.isArray(allowCredentials) ? allowCredentials : [],
              includeSecondPrfOutput,
            }),
        },
        nearAccountId: accountId,
        challengeB64u: localPrfChallengeB64u,
      });
      const runtimeScopeBootstrap =
        managedRegistration &&
        String(managedRegistration.environmentId || '').trim() &&
        String(managedRegistration.publishableKey || '').trim()
          ? {
              environmentId: String(managedRegistration.environmentId || '').trim(),
              publishableKey: String(managedRegistration.publishableKey || '').trim(),
            }
          : null;
      const connectedEd25519 = await signingEngine.connectEd25519Session({
        kind: 'fresh_ed25519_provisioning',
        nearAccountId: accountId,
        relayerUrl: input.relayerUrl,
        relayerKeyId: String(thresholdKeyMaterial.relayerKeyId || ''),
        participantIds: Array.isArray(thresholdKeyMaterial.participants)
          ? thresholdKeyMaterial.participants
              .map((participant: { id?: unknown }) => Number(participant?.id))
              .filter((id: number) => Number.isFinite(id))
          : [1, 2],
        sessionKind: 'jwt',
        source: 'login',
        ttlMs: typeof input.connectSessionTtlMs === 'number' ? input.connectSessionTtlMs : 120_000,
        remainingUses:
          typeof input.connectSessionRemainingUses === 'number'
            ? input.connectSessionRemainingUses
            : 4,
        appSessionJwt: String(login.jwt || ''),
        ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
        localPrfCredential,
      });
      const walletSigningSessionId = String(connectedEd25519?.walletSigningSessionId || '').trim();
      const passkeyPrfFirstB64u = String(
        connectedEd25519?.ecdsaHssPasskeyPrfFirstB64u ||
          getPrfFirstB64uFromCredential(localPrfCredential) ||
          '',
      ).trim();
      if (!connectedEd25519?.ok || !walletSigningSessionId || !passkeyPrfFirstB64u) {
        return {
          ok: false,
          accountId,
          error: String(
            connectedEd25519?.message || connectedEd25519?.code || 'connectEd25519Session failed',
          ),
        };
      }

      const normalizeTempoFlowSession = (raw: any) => {
        const sessionId = String(raw?.sessionId || '').trim();
        const walletSigningSessionId = String(raw?.walletSigningSessionId || '').trim();
        const jwt = String(raw?.jwt || '').trim();
        const expiresAtMs = Number(raw?.expiresAtMs);
        const remainingUses = Number(raw?.remainingUses);
        if (
          raw?.ok === true &&
          sessionId &&
          walletSigningSessionId &&
          jwt &&
          Number.isFinite(expiresAtMs) &&
          Number.isFinite(remainingUses)
        ) {
          return {
            kind: 'connected' as const,
            ok: true as const,
            sessionId,
            walletSigningSessionId,
            jwt,
            expiresAtMs: Math.floor(expiresAtMs),
            remainingUses: Math.max(0, Math.floor(remainingUses)),
          };
        }
        return {
          kind: 'rejected' as const,
          ok: false as const,
          code: String(raw?.code || 'invalid_bootstrap_session'),
          message: String(
            raw?.message ||
              'Threshold ECDSA bootstrap session did not include required session metadata',
          ),
        };
      };

      let keygen: any;
      let session: any = undefined;
      let budgetStatus: any = undefined;
      const signingChainTarget =
        input.signingKind === 'eip1559'
          ? {
              kind: 'evm' as const,
              namespace: 'eip155' as const,
              chainId: 11155111,
              networkSlug: 'ethereum-sepolia',
            }
          : {
              kind: 'tempo' as const,
              chainId: 42431,
              networkSlug: 'tempo-moderato',
            };
      if (input.connectSession !== false) {
        try {
          const existingTargetRecord = Array.isArray(
            signingEngine.listThresholdEcdsaSessionRecordsForWalletTarget?.({
              walletId: accountId,
              chainTarget: signingChainTarget,
            }),
          )
            ? signingEngine
                .listThresholdEcdsaSessionRecordsForWalletTarget?.({
                  walletId: accountId,
                  chainTarget: signingChainTarget,
                })
                ?.find((record: Record<string, unknown>) => {
                  const recordChainTarget =
                    record?.chainTarget &&
                    typeof record.chainTarget === 'object' &&
                    !Array.isArray(record.chainTarget)
                      ? (record.chainTarget as { kind?: unknown; chainId?: unknown })
                      : null;
                  return (
                    recordChainTarget?.kind === signingChainTarget.kind &&
                    Number(recordChainTarget.chainId) === signingChainTarget.chainId
                  );
                }) || null
            : null;
          const existingEcdsaThresholdKeyId = String(
            existingTargetRecord?.ecdsaThresholdKeyId || '',
          ).trim();
          if (existingTargetRecord) {
            signingEngine.clearThresholdEcdsaSessionRecordForWalletTarget?.({
              walletId: accountId,
              chainTarget: signingChainTarget,
              source: 'registration',
            });
          }
          const participantIds = Array.isArray(thresholdKeyMaterial.participants)
            ? thresholdKeyMaterial.participants
                .map((participant: { id?: unknown }) => Number(participant?.id))
                .filter((id: number) => Number.isFinite(id))
            : [1, 2];
          const sessionIdentity = {
            thresholdSessionId: String(existingTargetRecord?.thresholdSessionId || '').trim()
              ? String(existingTargetRecord?.thresholdSessionId || '').trim()
              : typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function'
                ? `threshold-ecdsa-browser-${crypto.randomUUID()}`
                : `threshold-ecdsa-browser-${Date.now()}-${Math.random().toString(16).slice(2)}`,
            walletSigningSessionId,
          };
          const ttlMs =
            typeof input.connectSessionTtlMs === 'number' ? input.connectSessionTtlMs : 120_000;
          const remainingUses =
            typeof input.connectSessionRemainingUses === 'number'
              ? input.connectSessionRemainingUses
              : 4;
          const existingParticipantIds = Array.isArray(existingTargetRecord?.participantIds)
            ? existingTargetRecord.participantIds
                .map((id: unknown) => Number(id))
                .filter((id: number) => Number.isFinite(id))
            : [];
          const keyIdentityParticipantIds =
            existingParticipantIds.length > 0 ? existingParticipantIds : participantIds;
          const existingThresholdOwnerAddress = String(
            existingTargetRecord?.ethereumAddress || '',
          ).trim();
          const existingKeyHandle = String(existingTargetRecord?.keyHandle || '').trim();
          const existingSigningRootId = String(existingTargetRecord?.signingRootId || '').trim();
          const existingSigningRootVersion =
            String(existingTargetRecord?.signingRootVersion || 'default').trim() || 'default';
          const rpId =
            typeof signingEngine.getRpId === 'function'
              ? String(signingEngine.getRpId() || '').trim() || 'example.localhost'
              : 'example.localhost';
          const exactActivationIdentity =
            existingEcdsaThresholdKeyId &&
            existingKeyHandle &&
            existingSigningRootId &&
            existingThresholdOwnerAddress &&
            keyIdentityParticipantIds.length > 0
              ? (() => {
                  try {
                    const key = buildEvmFamilyEcdsaKeyIdentity({
                      walletId: accountId,
                      rpId,
                      ecdsaThresholdKeyId: existingEcdsaThresholdKeyId,
                      signingRootId: existingSigningRootId,
                      signingRootVersion: existingSigningRootVersion,
                      participantIds: keyIdentityParticipantIds,
                      thresholdOwnerAddress: existingThresholdOwnerAddress,
                    });
                    const lanePolicy = buildEvmFamilyEcdsaSessionLanePolicy({
                      chainTarget: signingChainTarget,
                      thresholdSessionId: sessionIdentity.thresholdSessionId,
                      walletSigningSessionId: sessionIdentity.walletSigningSessionId,
                      thresholdSessionKind: 'jwt',
                      ttlMs,
                      remainingUses,
                    });
                    return { keyHandle: existingKeyHandle, key, lanePolicy };
                  } catch {
                    return null;
                  }
                })()
              : null;
          const bootstrapArgs = {
            kind: 'passkey_fresh_ecdsa_bootstrap' as const,
            walletId: accountId,
            chainTarget: signingChainTarget,
            source: 'manual-bootstrap' as const,
            relayerUrl: input.relayerUrl,
            ...(existingEcdsaThresholdKeyId
              ? { ecdsaThresholdKeyId: existingEcdsaThresholdKeyId }
              : {}),
            participantIds,
            sessionKind: 'jwt' as const,
            sessionIdentity,
            passkeyPrfFirstB64u: passkeyPrfFirstB64u,
            webauthnAuthentication: localPrfCredential,
            ttlMs,
            remainingUses,
            ...(runtimeScopeBootstrap ? { runtimeScopeBootstrap } : {}),
            ...(exactActivationIdentity
              ? {
                  keyHandle: exactActivationIdentity.keyHandle,
                  key: exactActivationIdentity.key,
                  lanePolicy: exactActivationIdentity.lanePolicy,
                }
              : {}),
          };
          const boot = await signingEngine.bootstrapEcdsaSession(bootstrapArgs);
          keygen = boot.keygen;
          session = normalizeTempoFlowSession(boot.session);
          if (session.kind === 'connected') {
            const readBudgetStatus = (globalThis as any).__w3aReadSigningBudgetStatus;
            budgetStatus =
              typeof readBudgetStatus === 'function'
                ? await readBudgetStatus({
                    relayerUrl: input.relayerUrl,
                    session: {
                      jwt: session.jwt,
                      thresholdSessionId: session.sessionId,
                      walletSigningSessionId: session.walletSigningSessionId,
                    },
                  })
                : {
                    kind: 'rejected' as const,
                    ok: false as const,
                    code: 'missing_budget_status_reader',
                    message: 'Browser budget-status reader was not installed',
                  };
          }
        } catch (e: unknown) {
          const stack =
            e && typeof e === 'object' && 'stack' in e
              ? String((e as { stack?: unknown }).stack || '').trim()
              : '';
          return {
            ok: false,
            accountId,
            error:
              stack ||
              String(
                e && typeof e === 'object' && 'message' in e
                  ? (e as { message?: unknown }).message
                  : e || 'bootstrapEcdsaSession failed',
              ),
          };
        }
      } else {
        try {
          const bootstrapFreshEcdsaForRequest = (globalThis as any)
            .__w3aBootstrapFreshTempoEcdsaSession;
          if (typeof bootstrapFreshEcdsaForRequest !== 'function') {
            return {
              ok: false,
              accountId,
              error: 'missing fresh ECDSA bootstrap helper',
            };
          }
          const boot = await bootstrapFreshEcdsaForRequest({
            pm,
            accountId,
            relayerUrl: input.relayerUrl,
            ttlMs: 1_000,
            remainingUses: 1,
            chainTarget: signingChainTarget,
          });
          keygen = boot.keygen;
          session = normalizeTempoFlowSession(boot.session);
          await new Promise((resolve) => setTimeout(resolve, 1_100));
        } catch (e: unknown) {
          const stack =
            e && typeof e === 'object' && 'stack' in e
              ? String((e as { stack?: unknown }).stack || '').trim()
              : '';
          return {
            ok: false,
            accountId,
            error:
              stack ||
              String(
                e && typeof e === 'object' && 'message' in e
                  ? (e as { message?: unknown }).message
                  : e || 'bootstrap stale ECDSA session failed',
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
          walletSession: {
            walletId: accountId,
            walletSessionUserId: accountId,
          },
          request,
          chainTarget: signingChainTarget,
          options: { confirmationConfig },
        });

        const walletSession = await pm.auth.getWalletSession(accountId).catch(() => null);
        const walletSessionThresholdOwnerAddress =
          walletSession?.login?.thresholdEcdsaEthereumAddress != null
            ? String(walletSession.login.thresholdEcdsaEthereumAddress).trim() || null
            : null;
        const walletSessionThresholdPublicKey =
          walletSession?.login?.thresholdEcdsaPublicKeyB64u != null
            ? String(walletSession.login.thresholdEcdsaPublicKeyB64u).trim() || null
            : null;
        const walletSessionNearAccountId =
          walletSession?.login?.nearAccountId != null
            ? String(walletSession.login.nearAccountId).trim() || null
            : null;
        const walletSessionIsLoggedIn = walletSession?.login?.isLoggedIn === true;

        return {
          ok: true,
          accountId,
          keygen,
          session,
          walletSession: {
            nearAccountId: walletSessionNearAccountId,
            isLoggedIn: walletSessionIsLoggedIn,
            thresholdEcdsaEthereumAddress: walletSessionThresholdOwnerAddress,
            thresholdEcdsaPublicKeyB64u: walletSessionThresholdPublicKey,
          },
          budgetStatus,
          signed,
        };
      } catch (e: unknown) {
        const stack =
          e && typeof e === 'object' && 'stack' in e
            ? String((e as { stack?: unknown }).stack || '').trim()
            : '';
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
          budgetStatus,
          error: stack || message,
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
    } finally {
      globalThis.fetch = originalFetch;
    }
  }, options);
}
