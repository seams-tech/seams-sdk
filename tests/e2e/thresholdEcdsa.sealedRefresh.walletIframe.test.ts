import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleOrgProjectEnvService,
  createRelayBootstrapGrantBroker,
  createRelayPublishableKeyAuthAdapter,
  createRelayRouter,
} from '@server/router/express-adaptor';
import { deriveThresholdEd25519RegistrationMaterialFromHssFinalize } from '@server/core/ThresholdService/ed25519HssWasm';
import {
  createSigningSessionSealPolicyFromThresholdAuthSessionStores,
  createSigningSessionSealRoutesOptions,
  createSigningSessionSealShamir3PassCipherAdapter,
} from '@server/threshold/session/signingSessionSeal';
import { startExpressRouter } from '../relayer/helpers';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import {
  corsHeadersForRoute,
  createInMemoryJwtSessionAdapter,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupThresholdE2ePage,
} from './thresholdEd25519.testUtils';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import { installRelayServerProxyShim } from '../setup/cross-origin-headers';

const TEST_KEY_VERSION = 'kek-s-2026-02';
const TEST_SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const TEST_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const TEST_SERVER_DECRYPT_EXPONENT_B64U = '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
const TEST_WEBAUTHN_GET_COUNTER_KEY = '__w3a_test_webauthn_get_calls';

type SealedRefreshHarness = {
  baseUrl: string;
  relayerUrl: string;
  managedRegistration: {
    environmentId: string;
    publishableKey: string;
  };
  signingSessionSealRouteCounts: {
    applyServerSealCalls: number;
    removeServerSealCalls: number;
  };
  attachPage: (page: Page) => Promise<void>;
  close: () => Promise<void>;
};

async function installThresholdRegistrationBootstrapMock(
  page: Page,
  input: {
    relayerBaseUrl: string;
    threshold: unknown;
    session: { signJwt: (sub: string, extra?: Record<string, unknown>) => Promise<string> };
    runtimePolicyScope: {
      orgId: string;
      projectId: string;
      envId: string;
    };
    onNewPublicKey: (publicKey: string) => void;
    onNewAccountId?: (accountId: string) => void;
  },
): Promise<void> {
  const threshold = input.threshold as {
    bootstrapEcdsaFromRegistrationMaterial?: (request: {
      userId: string;
      rpId: string;
      clientRootShare32B64u: string;
      sessionPolicy: Record<string, unknown>;
    }) => Promise<Record<string, unknown>>;
  };
  if (typeof threshold.bootstrapEcdsaFromRegistrationMaterial !== 'function') {
    throw new Error('Missing threshold-ecdsa staged bootstrap hook');
  }

  const positiveInt = (value: unknown, fallback: number): number => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
  };
  const asParticipantIds = (value: unknown, fallback: number[]): number[] => {
    if (!Array.isArray(value)) return [...fallback];
    const normalized = value
      .map((id) => Number(id))
      .filter((id) => Number.isFinite(id) && id > 0)
      .map((id) => Math.floor(id));
    return normalized.length >= 2 ? normalized : [...fallback];
  };

  await page.route(`${input.relayerBaseUrl}/registration/bootstrap`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    if (method === 'OPTIONS') {
      await route.fallback();
      return;
    }

    const corsHeaders = corsHeadersForRoute(route);
    const payload = JSON.parse(req.postData() || '{}');
    const accountId = String(payload?.new_account_id || '').trim();
    const rpId = String(payload?.rp_id || '').trim() || 'example.localhost';
    const nowMs = Date.now();

    if (accountId) input.onNewAccountId?.(accountId);

    const resolveRuntimePolicyScope = (policy: Record<string, unknown>): typeof input.runtimePolicyScope => {
      const scope =
        policy.runtimePolicyScope && typeof policy.runtimePolicyScope === 'object'
          ? (policy.runtimePolicyScope as Partial<typeof input.runtimePolicyScope>)
          : {};
      const orgId = String(scope.orgId || input.runtimePolicyScope.orgId || '').trim();
      const projectId = String(scope.projectId || input.runtimePolicyScope.projectId || '').trim();
      const envId = String(scope.envId || input.runtimePolicyScope.envId || '').trim();
      return { orgId, projectId, envId };
    };

    const signThresholdSessionJwt = async (args: {
      kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1';
      sessionId: string;
      relayerKeyId: string;
      participantIds: number[];
      expiresAtMs: number;
      runtimePolicyScope: typeof input.runtimePolicyScope;
    }): Promise<string> => {
      const nowSec = Math.floor(nowMs / 1000);
      const expSec = Math.floor(args.expiresAtMs / 1000);
      return await input.session.signJwt(accountId, {
        kind: args.kind,
        walletId: accountId,
        sessionId: args.sessionId,
        relayerKeyId: args.relayerKeyId,
        rpId,
        participantIds: args.participantIds,
        thresholdExpiresAtMs: args.expiresAtMs,
        runtimePolicyScope: args.runtimePolicyScope,
        iat: nowSec,
        exp: expSec,
      });
    };

    const thresholdEd = payload?.threshold_ed25519 || null;
    const thresholdEdPublicKey = String(thresholdEd?.public_key || '').trim();
    const thresholdEdKeyVersion = String(thresholdEd?.key_version || '').trim();
    // The finalized threshold Ed25519 record is keyed by the derived public key.
    // Keep the mocked registration/bootstrap response on that same seam.
    const thresholdEdRelayerKeyId = thresholdEdPublicKey;
    const thresholdEdRecoveryExportCapable = thresholdEd?.recovery_export_capable === true;
    let thresholdEdResponse: Record<string, unknown> | undefined;
    if (thresholdEdPublicKey && thresholdEdKeyVersion && thresholdEdRecoveryExportCapable) {
      if (thresholdEdPublicKey) input.onNewPublicKey(thresholdEdPublicKey);

      const policy = thresholdEd?.session_policy || {};
      const sessionId = String(policy?.sessionId || policy?.session_id || `ed-session-${nowMs}`);
      const ttlMs = positiveInt(policy?.ttlMs || policy?.ttl_ms, 60_000);
      const remainingUses = positiveInt(policy?.remainingUses || policy?.remaining_uses, 10_000);
      const expiresAtMs = nowMs + ttlMs;
      const participantIds = asParticipantIds(policy?.participantIds, [1, 2]);
      const runtimePolicyScope = resolveRuntimePolicyScope(policy);
      const jwt = await signThresholdSessionJwt({
        kind: 'threshold_ed25519_session_v1',
        sessionId,
        relayerKeyId: thresholdEdRelayerKeyId,
        participantIds,
        expiresAtMs,
        runtimePolicyScope,
      });
      thresholdEdResponse = {
        keyVersion: thresholdEdKeyVersion,
        recoveryExportCapable: true,
        publicKey: thresholdEdPublicKey,
        relayerKeyId: thresholdEdRelayerKeyId,
        clientParticipantId: 1,
        relayerParticipantId: 2,
        participantIds,
        session: {
          sessionKind: 'jwt',
          sessionId,
          expiresAtMs,
          participantIds,
          remainingUses,
          runtimePolicyScope,
          jwt,
        },
      };
    }

    const thresholdEcdsa = payload?.threshold_ecdsa || null;
    const thresholdEcdsaClientRootShare32B64u = String(
      thresholdEcdsa?.client_root_share32_b64u || '',
    ).trim();
    let thresholdEcdsaResponse: Record<string, unknown> | undefined;
    if (thresholdEcdsaClientRootShare32B64u) {
      const bootstrapEcdsaFromRegistrationMaterial =
        threshold.bootstrapEcdsaFromRegistrationMaterial;
      if (!bootstrapEcdsaFromRegistrationMaterial) {
        throw new Error('Missing staged ECDSA bootstrap helper');
      }
      const policy = thresholdEcdsa?.session_policy || {};
      const sessionId = String(policy?.sessionId || policy?.session_id || `ecdsa-session-${nowMs}`);
      const ttlMs = positiveInt(policy?.ttlMs || policy?.ttl_ms, 60_000);
      const remainingUses = positiveInt(policy?.remainingUses || policy?.remaining_uses, 10_000);
      const participantIds = asParticipantIds(policy?.participantIds, [1, 2]);
      const runtimePolicyScope = resolveRuntimePolicyScope(policy);
      const bootstrap = (await bootstrapEcdsaFromRegistrationMaterial({
        userId: accountId,
        rpId,
        clientRootShare32B64u: thresholdEcdsaClientRootShare32B64u,
        sessionPolicy: {
          version: 'threshold_session_v1',
          userId: accountId,
          rpId,
          sessionId,
          ttlMs,
          remainingUses,
          participantIds,
          runtimePolicyScope,
        },
      })) as Record<string, unknown>;
      if (!bootstrap?.ok) {
        await route.fulfill({
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            success: false,
            error: String(bootstrap?.message || 'ecdsa bootstrap'),
          }),
        });
        return;
      }

      thresholdEcdsaResponse = {
        ecdsaThresholdKeyId: String(bootstrap.ecdsaThresholdKeyId || ''),
        relayerKeyId: String(bootstrap.relayerKeyId || ''),
        thresholdEcdsaPublicKeyB64u: String(bootstrap.thresholdEcdsaPublicKeyB64u || ''),
        ethereumAddress: String(bootstrap.ethereumAddress || ''),
        relayerVerifyingShareB64u: String(bootstrap.relayerVerifyingShareB64u || ''),
        participantIds: Array.isArray(bootstrap.participantIds)
          ? bootstrap.participantIds
          : participantIds,
        session: {
          sessionKind: 'jwt',
          sessionId: String(bootstrap.sessionId || sessionId),
          expiresAtMs: Number(bootstrap.expiresAtMs || nowMs + ttlMs),
          participantIds: Array.isArray(bootstrap.participantIds)
            ? bootstrap.participantIds
            : participantIds,
          remainingUses: Number(bootstrap.remainingUses || remainingUses),
          runtimePolicyScope,
          jwt: String(bootstrap.jwt || ''),
        },
      };
    }

    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({
        success: true,
        transactionHash: `mock_atomic_tx_${Date.now()}`,
        ...(thresholdEdResponse ? { thresholdEd25519: thresholdEdResponse } : {}),
        ...(thresholdEcdsaResponse ? { thresholdEcdsa: thresholdEcdsaResponse } : {}),
      }),
    });
  });
}

async function installThresholdRegistrationFinalizeRelayKeyMaterialCapture(
  page: Page,
  input: {
    relayerBaseUrl: string;
    relayUpstreamBaseUrl: string;
    threshold: unknown;
  },
): Promise<void> {
  await page.route(`${input.relayerBaseUrl}/registration/threshold-ed25519/hss/finalize`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    if (method === 'OPTIONS') {
      await route.fallback();
      return;
    }
    if (method !== 'POST') {
      await route.fallback();
      return;
    }

    const upstreamUrl = req.url().replace(input.relayerBaseUrl, input.relayUpstreamBaseUrl);
    const upstreamResponse = await fetch(upstreamUrl, {
      method,
      headers: req.headers(),
      body: req.postData(),
    });
    const upstreamText = await upstreamResponse.text();
    const payload = JSON.parse(req.postData() || '{}');
    const responseJson = JSON.parse(upstreamText || '{}');

    if (
      upstreamResponse.ok &&
      responseJson?.ok === true &&
      responseJson?.finalizedReport &&
      responseJson?.serverOutput
    ) {
      const preparedSession = payload?.preparedSession;
      const finalizedReport = responseJson.finalizedReport;
      const registrationMaterial = await deriveThresholdEd25519RegistrationMaterialFromHssFinalize({
        preparedSession,
        keyVersion: String(responseJson?.keyVersion || TEST_KEY_VERSION).trim(),
        finalizedReport,
        serverOutput: responseJson.serverOutput,
      });
      const keyStore = (
        input.threshold as {
          keyStore?: {
            put: (
              relayerKeyId: string,
              record: {
                nearAccountId: string;
                rpId: string;
                publicKey: string;
                relayerSigningShareB64u: string;
                relayerVerifyingShareB64u: string;
                keyVersion: string;
                recoveryExportCapable: true;
              },
            ) => Promise<void>;
          };
        }
      ).keyStore;
      if (keyStore?.put) {
        await keyStore.put(registrationMaterial.relayerKeyId, {
          nearAccountId: String(payload?.new_account_id || '').trim(),
          rpId: String(payload?.rp_id || '').trim(),
          publicKey: registrationMaterial.publicKey,
          relayerSigningShareB64u: registrationMaterial.relayerSigningShareB64u,
          relayerVerifyingShareB64u: registrationMaterial.relayerVerifyingShareB64u,
          keyVersion: registrationMaterial.keyVersion,
          recoveryExportCapable: true,
        });
      }
    }

    await route.fulfill({
      status: upstreamResponse.status,
      headers: {
        ...corsHeadersForRoute(route),
        ...Object.fromEntries(upstreamResponse.headers.entries()),
      },
      body: upstreamText,
    });
  });
}

async function setupThresholdEcdsaSealedRefreshHarness(page: Page): Promise<SealedRefreshHarness> {
  const keysOnChain = new Set<string>();
  const nonceByPublicKey = new Map<string, number>();
  const accountsOnChain = new Set<string>(
    [DEFAULT_TEST_CONFIG.relayerAccount].filter((value): value is string => !!value),
  );
  const signingSessionSealRouteCounts = {
    applyServerSealCalls: 0,
    removeServerSealCalls: 0,
  };

  const { service, threshold } = makeAuthServiceForThreshold(keysOnChain);
  await service.getRelayerAccount();
  const bootstrapTokenStore = createInMemoryConsoleBootstrapTokenService();
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const apiKeys = createInMemoryConsoleApiKeyService();
  const bootstrapAdminCtx = {
    orgId: 'org_threshold_sealed_refresh',
    actorUserId: 'user_threshold_sealed_refresh',
    roles: ['admin'],
  } as const;
  const bootstrapProjectId = 'proj_threshold_sealed_refresh';
  const bootstrapEnvId = 'dev';
  const runtimePolicyScope = {
    orgId: bootstrapAdminCtx.orgId,
    projectId: bootstrapProjectId,
    envId: bootstrapEnvId,
  } as const;
  const managedRegistrationEnvironmentId = `${bootstrapProjectId}:${bootstrapEnvId}`;
  await orgProjectEnv.upsertOrganization(bootstrapAdminCtx, {
    name: 'Threshold Sealed Refresh Org',
    slug: 'threshold-sealed-refresh-org',
  });
  await orgProjectEnv.createProject(bootstrapAdminCtx, {
    id: bootstrapProjectId,
    name: 'Threshold Sealed Refresh Project',
    liveEnvironmentsEnabled: true,
  });
  const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
  const createdPublishableKey = await apiKeys.createApiKey(bootstrapAdminCtx, {
    kind: 'publishable_key',
    name: 'threshold-sealed-refresh-browser',
    environmentId: managedRegistrationEnvironmentId,
    allowedOrigins: [
      frontendOrigin,
      'https://example.localhost',
      'https://wallet.example.localhost',
    ],
    rateLimitBucket: 'default_web_v1',
    quotaBucket: 'free_registrations_v1',
  });
  const managedRegistration = {
    environmentId: managedRegistrationEnvironmentId,
    publishableKey: createdPublishableKey.secret,
  } as const;

  const session = createInMemoryJwtSessionAdapter();
  const relayerUrl = DEFAULT_TEST_CONFIG.relayer?.url ?? 'https://relay-server.localhost';
  const thresholdAuthStores = threshold as unknown as {
    authSessionStore?: unknown;
    ecdsaAuthSessionStore?: unknown;
  };
  if (!thresholdAuthStores.authSessionStore || !thresholdAuthStores.ecdsaAuthSessionStore) {
    throw new Error('Missing threshold auth session stores for signing-session seal policy');
  }

  const router = createRelayRouter(service, {
    corsOrigins: [frontendOrigin, 'https://example.localhost', 'https://wallet.example.localhost'],
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
    signingSessionSeal: createSigningSessionSealRoutesOptions({
      sessionPolicy: createSigningSessionSealPolicyFromThresholdAuthSessionStores({
        stores: [thresholdAuthStores.authSessionStore as any, thresholdAuthStores.ecdsaAuthSessionStore as any],
      }),
      cipher: createSigningSessionSealShamir3PassCipherAdapter({
        currentKeyVersion: TEST_KEY_VERSION,
        keys: [
          {
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            serverEncryptExponentB64u: TEST_SERVER_ENCRYPT_EXPONENT_B64U,
            serverDecryptExponentB64u: TEST_SERVER_DECRYPT_EXPONENT_B64U,
          },
        ],
      }),
      capabilities: {
        mode: 'sealed_refresh_v1',
        keyVersion: TEST_KEY_VERSION,
        shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
      },
    }),
  });
  const server = await startExpressRouter(router);

  const attachPage = async (targetPage: Page): Promise<void> => {
    await targetPage.addInitScript((config) => {
      (window as any).__w3aManagedRegistration = config;
    }, managedRegistration);
    await setupThresholdE2ePage(targetPage);
    await targetPage.evaluate((config) => {
      (window as any).__w3aManagedRegistration = config;
    }, managedRegistration);
    await installRelayServerProxyShim(targetPage, {
      relayOrigin: relayerUrl,
      relayUpstream: server.baseUrl,
      logStyle: 'silent',
    });
    await installThresholdRegistrationFinalizeRelayKeyMaterialCapture(targetPage, {
      relayerBaseUrl: relayerUrl,
      relayUpstreamBaseUrl: server.baseUrl,
      threshold,
    });
    await targetPage.route(`${relayerUrl}/threshold/signing-session-seal/**`, async (route) => {
      const url = route.request().url();
      if (url.endsWith('/apply-server-seal')) {
        signingSessionSealRouteCounts.applyServerSealCalls += 1;
      } else if (url.endsWith('/remove-server-seal')) {
        signingSessionSealRouteCounts.removeServerSealCalls += 1;
      }
      await route.fallback();
    });
    await installThresholdRegistrationBootstrapMock(targetPage, {
      relayerBaseUrl: relayerUrl,
      threshold,
      session,
      runtimePolicyScope,
      onNewPublicKey: (publicKey) => {
        keysOnChain.add(publicKey);
        nonceByPublicKey.set(publicKey, 0);
      },
      onNewAccountId: (accountId) => {
        accountsOnChain.add(accountId);
      },
    });
    await installFastNearRpcMock(targetPage, {
      keysOnChain,
      nonceByPublicKey,
      accountsOnChain,
    });
  };

  await attachPage(page);

  return {
    baseUrl: server.baseUrl,
    relayerUrl,
    managedRegistration,
    signingSessionSealRouteCounts,
    attachPage,
    close: server.close,
  };
}

async function readWebAuthnGetCallCount(page: Page): Promise<number> {
  const countsByFrame = await Promise.all(
    page.frames().map(async (frame) => {
      return await frame
        .evaluate((storageKey) => {
          const parseCount = (value: unknown): number => {
            const n = Number(value);
            return Number.isFinite(n) && n >= 0 ? Math.floor(n) : 0;
          };

          const globalCount = parseCount((window as any).__w3aTestWebAuthnGetCalls);
          let storedCount = 0;
          try {
            storedCount = parseCount(window.localStorage?.getItem?.(storageKey));
          } catch {}

          return {
            origin: String(window.location?.origin || 'unknown'),
            count: Math.max(globalCount, storedCount),
          };
        }, TEST_WEBAUTHN_GET_COUNTER_KEY)
        .catch(() => ({ origin: 'unknown', count: 0 }));
    }),
  );

  const maxByOrigin = new Map<string, number>();
  for (const entry of countsByFrame) {
    const origin = String(entry?.origin || 'unknown');
    const count = Number.isFinite(Number(entry?.count))
      ? Math.max(0, Math.floor(Number(entry?.count)))
      : 0;
    const previous = maxByOrigin.get(origin) ?? 0;
    if (count > previous) {
      maxByOrigin.set(origin, count);
    }
  }

  let total = 0;
  for (const count of maxByOrigin.values()) {
    total += count;
  }
  return total;
}

async function readWalletIframeThresholdPersistence(page: Page): Promise<
  Array<{
    origin: string;
    localEd25519Index: string | null;
    localSealIndex: string | null;
    sessionEd25519Index: string | null;
    sessionSealIndex: string | null;
  }>
> {
  return await Promise.all(
    page.frames().map(async (frame) => {
      return await frame
        .evaluate(() => {
          return {
            origin: String(window.location?.origin || 'unknown'),
            localEd25519Index:
              window.localStorage?.getItem?.('tatchi:threshold-ed25519-session:v1:index') || null,
            localSealIndex:
              window.localStorage?.getItem?.('tatchi:signing-session-sealed:v1:index') || null,
            sessionEd25519Index:
              window.sessionStorage?.getItem?.('tatchi:threshold-ed25519-session:v1:index') || null,
            sessionSealIndex:
              window.sessionStorage?.getItem?.('tatchi:signing-session-sealed:v1:index') || null,
          };
        })
        .catch(() => ({
          origin: 'unknown',
          localEd25519Index: null,
          localSealIndex: null,
          sessionEd25519Index: null,
          sessionSealIndex: null,
        }));
    }),
  );
}

  test.describe('threshold-ecdsa sealed refresh (wallet iframe)', () => {
  test.setTimeout(180_000);

  test('registration and login can bootstrap sign then export the same one-key ECDSA session', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const flowPromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `ecdsa-export-${Date.now()}.w3a-v1.testnet`;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const registration = await tatchi.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                stage: 'registration',
                error: String(registration?.error || 'registration failed'),
              };
            }

            const login = await tatchi.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                stage: 'login',
                error: String(login?.error || 'unlock failed'),
              };
            }

            const bootstrap = await tatchi.tempo.bootstrapEcdsaSession({
              nearAccountId: accountId,
              options: {
                relayerUrl,
                ttlMs: 120_000,
                remainingUses: 10,
              },
            });
            if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              return {
                ok: false,
                stage: 'bootstrap',
                error: 'threshold ECDSA bootstrap did not return ecdsaThresholdKeyId',
              };
            }

            const signed = await tatchi.tempo.signTempo({
              nearAccountId: accountId,
              request: {
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
              },
              options: { confirmationConfig },
            });
            if (!signed || signed.kind !== 'tempoTransaction') {
              return {
                ok: false,
                stage: 'sign',
                error: 'tempo sign failed',
              };
            }

            await tatchi.keys.exportKeypairWithUI(accountId, {
              chain: 'evm',
              variant: 'modal',
            });

            const session = await tatchi.auth.getWalletSession(accountId);
            return {
              ok: true,
              accountId,
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              stage: 'unexpected',
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'flow failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );

      const flow = await autoConfirmWalletIframeUntil(page, flowPromise, {
        timeoutMs: 180_000,
        intervalMs: 250,
      });

      expect(flow.ok, flow.error || JSON.stringify(flow)).toBe(true);
      expect(flow.sessionStatus).toBe('active');
    } finally {
      await harness.close();
    }
  });

  test('fails closed on startup when sealed refresh keyVersion parity mismatches', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const result = await page.evaluate(
        async ({ relayerUrl, shamirPrimeB64u }) => {
          const mod = await import('/sdk/esm/core/TatchiPasskey/index.js');
          const { TatchiPasskey } = mod as any;
          const accountId = `parity-mismatch-${Date.now()}.testnet`;
          const tatchi = new TatchiPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayerAccount: 'web3-authn-v4.testnet',
            relayer: {
              url: relayerUrl,
              smartAccountDeploymentMode: 'observe',
            },
            registration: {
              mode: 'managed',
              environmentId: String(
                (globalThis as any).__w3aManagedRegistration?.environmentId || '',
              ),
              publishableKey: String(
                (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
              ),
            },
            signingSessionPersistenceMode: 'sealed_refresh_v1',
            signingSessionSeal: {
              keyVersion: 'kek-client-mismatch',
              shamirPrimeB64u,
            },
            iframeWallet: {
              walletOrigin: 'https://wallet.example.localhost',
              servicePath: '/wallet-service',
              sdkBasePath: '/sdk',
              rpIdOverride: 'example.localhost',
            },
          });

          try {
            const loginResult = await tatchi.auth.unlock(accountId, {
              session: { kind: 'jwt', relayUrl: relayerUrl },
            });
            if (!loginResult?.success) {
              return {
                ok: false,
                code: '',
                message: String(loginResult?.error || 'login failed'),
              };
            }
            return { ok: true };
          } catch (error: unknown) {
            return {
              ok: false,
              code: String((error as { code?: unknown })?.code || ''),
              message: String((error as Error)?.message || error),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );

      expect(result.ok).toBe(false);
      expect(result.message).toContain('keyVersion');
    } finally {
      await harness.close();
    }
  });

  test('same-tab refresh reuses sealed signing session without extra TouchID prompt', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const loginPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `sealedrefresh${Date.now()}.w3a-v1.testnet`;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const registration = await tatchi.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registration failed'),
              };
            }

            const login = await tatchi.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }

            const session = await tatchi.auth.getWalletSession(accountId);
            return {
              ok: true,
              accountId,
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const loginPhase = await autoConfirmWalletIframeUntil(page, loginPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(loginPhase.ok, loginPhase.error || JSON.stringify(loginPhase)).toBe(true);
      expect(loginPhase.sessionStatus).toBe('active');
      const getCallsAfterLogin = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterLogin).toBeGreaterThan(0);

      const firstSignPromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);
            const firstSign = await tatchi.near.executeAction({
              nearAccountId: accountId,
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-before-refresh-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });
            return {
              ok: !!firstSign?.success,
              error: String(firstSign?.error || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first sign failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: loginPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const firstSign = await autoConfirmWalletIframeUntil(page, firstSignPromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });
      expect(firstSign.ok, JSON.stringify({ firstSign })).toBe(true);
      const getCallsAfterLoginAndFirstSign = await readWebAuthnGetCallCount(page);
      const persistenceBeforeReload = await readWalletIframeThresholdPersistence(page);
      await page.waitForTimeout(400);
      expect(harness.signingSessionSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

      await page.reload();
      await page.waitForTimeout(300);

      const secondPhasePromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const session = await tatchi.auth.getWalletSession(accountId);

            const refreshedSign = await tatchi.near.executeAction({
              nearAccountId: accountId,
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-after-refresh-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });

            return {
              ok: !!refreshedSign?.success,
              error: String(refreshedSign?.error || ''),
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'second phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: loginPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const secondPhase = await autoConfirmWalletIframeUntil(page, secondPhasePromise, {
        timeoutMs: 90_000,
        intervalMs: 250,
      });
      const persistenceAfterReload = await readWalletIframeThresholdPersistence(page);

      expect(secondPhase.ok, JSON.stringify({ secondPhase })).toBe(true);
      expect(
        secondPhase.sessionStatus,
        JSON.stringify({ secondPhase, persistenceBeforeReload, persistenceAfterReload }),
      ).toBe('active');
      expect(
        harness.signingSessionSealRouteCounts.removeServerSealCalls,
        JSON.stringify({ secondPhase, persistenceBeforeReload, persistenceAfterReload }),
      ).toBeGreaterThan(0);
      await page.waitForTimeout(300);
      const finalGetCalls = await readWebAuthnGetCallCount(page);
      expect(
        finalGetCalls,
        JSON.stringify({
          getCallsAfterLoginAndFirstSign,
          finalGetCalls,
          secondPhase,
          persistenceBeforeReload,
          persistenceAfterReload,
        }),
      ).toBe(getCallsAfterLoginAndFirstSign);
    } finally {
      await harness.close();
    }
  });

  test('passkey reload prompts WebAuthn after restored session exhaustion', async ({ page }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const firstPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `sealedrefreshexhaust${Date.now()}.w3a-v1.testnet`;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionDefaults: {
                ttlMs: 120_000,
                remainingUses: 1,
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const registration = await tatchi.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registration failed'),
              };
            }

            const login = await tatchi.unlock(accountId, {
              signingSession: { ttlMs: 120_000, remainingUses: 1 },
            });
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }

            const session = await tatchi.auth.getWalletSession(accountId);
            return {
              ok: true,
              accountId,
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const firstPhase = await autoConfirmWalletIframeUntil(page, firstPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      expect(firstPhase.sessionStatus).toBe('active');
      const getCallsAfterFirstPhase = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterFirstPhase).toBeGreaterThan(0);
      await page.waitForTimeout(400);
      expect(harness.signingSessionSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

      await page.reload();
      await page.waitForTimeout(300);

      const restoredSignPromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionDefaults: {
                ttlMs: 120_000,
                remainingUses: 2,
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const sign = await tatchi.near.executeAction({
              nearAccountId: accountId,
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-restored-exhaustion-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });
            return {
              ok: !!sign?.success,
              error: String(sign?.error || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'restored sign failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: firstPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const restoredSign = await autoConfirmWalletIframeUntil(page, restoredSignPromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });
      expect(restoredSign.ok, JSON.stringify({ restoredSign })).toBe(true);
      expect(harness.signingSessionSealRouteCounts.removeServerSealCalls).toBeGreaterThan(0);
      const getCallsAfterRestoredSign = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterRestoredSign).toBe(getCallsAfterFirstPhase);

      const reauthSignPromise = page.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const actionsMod = await import('/sdk/esm/core/types/actions.js');
            const { TatchiPasskey } = sdkMod as any;
            const { ActionType } = actionsMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionDefaults: {
                ttlMs: 120_000,
                remainingUses: 2,
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const sign = await tatchi.near.executeAction({
              nearAccountId: accountId,
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-reauth-exhaustion-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });
            const session = await tatchi.auth.getWalletSession(accountId);
            return {
              ok: !!sign?.success,
              error: String(sign?.error || ''),
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'reauth sign failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: firstPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const reauthSign = await autoConfirmWalletIframeUntil(page, reauthSignPromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });
      expect(reauthSign.ok, JSON.stringify({ reauthSign })).toBe(true);
      expect(reauthSign.sessionStatus).toBe('active');
      const finalGetCalls = await readWebAuthnGetCallCount(page);
      expect(
        finalGetCalls,
        JSON.stringify({ getCallsAfterFirstPhase, getCallsAfterRestoredSign, finalGetCalls }),
      ).toBeGreaterThan(getCallsAfterRestoredSign);
    } finally {
      await harness.close();
    }
  });

  test('same-tab sealed refresh preserves Tempo/EVM prompt parity after ECDSA bootstrap in both orderings', async ({
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    try {
      const firstPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { TatchiPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `sealedrefreshmultichain${Date.now()}.w3a-v1.testnet`;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);

            const registration = await tatchi.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registration failed'),
              };
            }

            const login = await tatchi.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }

            const bootstrap = await tatchi.tempo.bootstrapEcdsaSession({
              nearAccountId: accountId,
              options: {
                relayerUrl,
                ttlMs: 120_000,
                remainingUses: 10,
              },
            });
            if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              return {
                ok: false,
                error: 'threshold ECDSA bootstrap did not return ecdsaThresholdKeyId',
              };
            }

            const warmTempo = await tatchi.tempo.signTempo({
              nearAccountId: accountId,
              request: {
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
                  nonce: 1n,
                  validBefore: null,
                  validAfter: null,
                  feePayerSignature: { kind: 'none' as const },
                  aaAuthorizationList: [],
                },
              },
              options: { confirmationConfig },
            });
            if (!warmTempo || warmTempo.kind !== 'tempoTransaction') {
              return {
                ok: false,
                error: 'tempo warm sign failed',
              };
            }

            const session = await tatchi.auth.getWalletSession(accountId);
            return {
              ok: true,
              accountId,
              sessionStatus: String(session?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const firstPhase = await autoConfirmWalletIframeUntil(page, firstPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      expect(firstPhase.sessionStatus).toBe('active');
      const getCallsAfterFirstPhase = await readWebAuthnGetCallCount(page);
      expect(getCallsAfterFirstPhase).toBeGreaterThan(0);
      await page.waitForTimeout(300);
      expect(harness.signingSessionSealRouteCounts.applyServerSealCalls).toBeGreaterThan(0);

      const runOrderingAfterRefresh = async (order: Array<'tempo' | 'evm'>) => {
        await page.reload();
        await page.waitForTimeout(300);

        const phasePromise = page.evaluate(
          async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u, order }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { TatchiPasskey } = sdkMod as any;

            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });
            tatchi.setConfirmationConfig(confirmationConfig as any);

            const login = await tatchi.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock after refresh failed'),
              };
            }

            const tempoRequest = {
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
                nonce: 2n,
                validBefore: null,
                validAfter: null,
                feePayerSignature: { kind: 'none' as const },
                aaAuthorizationList: [],
              },
            };
            const evmRequest = {
              chain: 'evm' as const,
              kind: 'eip1559' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 11155111,
                nonce: 7n,
                maxPriorityFeePerGas: 1_500_000_000n,
                maxFeePerGas: 3_000_000_000n,
                gasLimit: 21_000n,
                to: '0x' + '22'.repeat(20),
                value: 12_345n,
                data: '0x',
                accessList: [],
              },
            };
            const requestByChain = {
              tempo: tempoRequest,
              evm: evmRequest,
            } as const;

            const bootstrapOptions = {
              relayerUrl,
              ttlMs: 120_000,
              remainingUses: 10,
            } as const;
            const tempoBootstrap = await tatchi.tempo.bootstrapEcdsaSession({
              nearAccountId: accountId,
              options: bootstrapOptions,
            });
            if (!tempoBootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              throw new Error('threshold ECDSA bootstrap did not return ecdsaThresholdKeyId');
            }
            const evmBootstrap = await tatchi.evm.bootstrapEcdsaSession({
              nearAccountId: accountId,
              options: bootstrapOptions,
            });
            if (!evmBootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              throw new Error('threshold ECDSA EVM bootstrap did not return ecdsaThresholdKeyId');
            }

            const orderedResults: Array<{
              requestedChain: 'tempo' | 'evm';
              resultChain: string;
              kind: string;
            }> = [];
            for (const requestedChain of order) {
              const signed = await tatchi.tempo.signTempo({
                nearAccountId: accountId,
                request: requestByChain[requestedChain],
                options: { confirmationConfig },
              });
              orderedResults.push({
                requestedChain,
                resultChain: String(signed?.chain || ''),
                kind: String(signed?.kind || ''),
              });
            }
            const session = await tatchi.auth.getWalletSession(accountId);

            return {
              ok: true,
              sessionStatus: String(session?.signingSession?.status || ''),
              orderedResults,
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'second phase failed',
              ),
            };
          }
        },
          {
            relayerUrl: harness.relayerUrl,
            accountId: firstPhase.accountId,
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            order,
          },
        );
        return await autoConfirmWalletIframeUntil(page, phasePromise, {
          timeoutMs: 120_000,
          intervalMs: 250,
        });
      };

      const tempoThenEvmPhase = await runOrderingAfterRefresh(['tempo', 'evm']);
      expect(
        tempoThenEvmPhase.ok,
        tempoThenEvmPhase.error || JSON.stringify(tempoThenEvmPhase),
      ).toBe(true);
      expect(tempoThenEvmPhase.sessionStatus).toBe('active');
      expect(tempoThenEvmPhase.orderedResults).toEqual([
        {
          requestedChain: 'tempo',
          resultChain: 'tempo',
          kind: 'tempoTransaction',
        },
        {
          requestedChain: 'evm',
          resultChain: 'evm',
          kind: 'eip1559',
        },
      ]);

      const evmThenTempoPhase = await runOrderingAfterRefresh(['evm', 'tempo']);
      expect(
        evmThenTempoPhase.ok,
        evmThenTempoPhase.error || JSON.stringify(evmThenTempoPhase),
      ).toBe(true);
      expect(evmThenTempoPhase.sessionStatus).toBe('active');
      expect(evmThenTempoPhase.orderedResults).toEqual([
        {
          requestedChain: 'evm',
          resultChain: 'evm',
          kind: 'eip1559',
        },
        {
          requestedChain: 'tempo',
          resultChain: 'tempo',
          kind: 'tempoTransaction',
        },
      ]);
      const finalGetCalls = await readWebAuthnGetCallCount(page);
      expect(
        finalGetCalls - getCallsAfterFirstPhase,
        JSON.stringify({
          getCallsAfterFirstPhase,
          finalGetCalls,
          firstPhase,
          tempoThenEvmPhase,
          evmThenTempoPhase,
        }),
      ).toBe(2);
    } finally {
      await harness.close();
    }
  });

  test('tab close requires TouchID re-auth even with sealed refresh enabled', async ({
    context,
    page,
  }) => {
    const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
    let secondPage: Page | null = null;
    try {
      const firstPhasePromise = page.evaluate(
        async ({ relayerUrl, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { TatchiPasskey } = sdkMod as any;
            const confirmationConfig = {
              uiMode: 'none' as const,
              behavior: 'skipClick' as const,
              autoProceedDelay: 0,
            };
            const accountId = `tabclose${Date.now()}.w3a-v1.testnet`;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            tatchi.setConfirmationConfig(confirmationConfig as any);
            const registration = await tatchi.registration.registerPasskeyInternal(
              accountId,
              {},
              confirmationConfig as any,
            );
            if (!registration?.success) {
              return {
                ok: false,
                error: String(registration?.error || 'registration failed'),
              };
            }
            const login = await tatchi.unlock(accountId);
            if (!login?.success) {
              return {
                ok: false,
                error: String(login?.error || 'unlock failed'),
              };
            }
            return { ok: true, accountId };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'first phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const firstPhase = await autoConfirmWalletIframeUntil(page, firstPhasePromise, {
        timeoutMs: 120_000,
        intervalMs: 250,
      });

      expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
      const getCallsBeforeTabClose = await readWebAuthnGetCallCount(page);
      expect(getCallsBeforeTabClose).toBeGreaterThan(0);

      await page.close();
      secondPage = await context.newPage();
      await harness.attachPage(secondPage);

      const secondPhasePromise = secondPage.evaluate(
        async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u }) => {
          try {
            const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
            const { TatchiPasskey } = sdkMod as any;
            const tatchi = new TatchiPasskey({
              nearNetwork: 'testnet',
              nearRpcUrl: 'https://test.rpc.fastnear.com',
              relayerAccount: 'web3-authn-v4.testnet',
              relayer: {
                url: relayerUrl,
                smartAccountDeploymentMode: 'observe',
              },
              registration: {
                mode: 'managed',
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              },
              signingSessionPersistenceMode: 'sealed_refresh_v1',
              signingSessionSeal: {
                keyVersion,
                shamirPrimeB64u,
              },
              iframeWallet: {
                walletOrigin: 'https://wallet.example.localhost',
                servicePath: '/wallet-service',
                sdkBasePath: '/sdk',
                rpIdOverride: 'example.localhost',
              },
            });

            const login = await tatchi.unlock(accountId);
            return {
              ok: !!login?.success,
              error: String(login?.error || ''),
              signingStatus: String(login?.signingSession?.status || ''),
            };
          } catch (error: unknown) {
            return {
              ok: false,
              error: String(
                error && typeof error === 'object' && 'message' in error
                  ? (error as { message?: unknown }).message
                  : error || 'second phase failed',
              ),
            };
          }
        },
        {
          relayerUrl: harness.relayerUrl,
          accountId: firstPhase.accountId,
          keyVersion: TEST_KEY_VERSION,
          shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
        },
      );
      const secondPhase = await autoConfirmWalletIframeUntil(secondPage, secondPhasePromise, {
        timeoutMs: 90_000,
        intervalMs: 250,
      });

      expect(secondPhase.ok, secondPhase.error || JSON.stringify(secondPhase)).toBe(true);
      expect(secondPhase.signingStatus).toBe('active');
      await secondPage.waitForTimeout(300);
      const getCallsAfterTabClose = await readWebAuthnGetCallCount(secondPage);
      expect(getCallsAfterTabClose).toBeGreaterThan(getCallsBeforeTabClose);
    } finally {
      if (secondPage) {
        await secondPage.close().catch(() => undefined);
      }
      await harness.close();
    }
  });
});

type ThresholdRefreshCurve = 'ed25519' | 'ecdsa';
type ThresholdRefreshSessionKind = 'jwt' | 'cookie';

const THRESHOLD_REFRESH_MATRIX: ReadonlyArray<{
  curve: ThresholdRefreshCurve;
  sessionKind: ThresholdRefreshSessionKind;
}> = [
  { curve: 'ed25519', sessionKind: 'jwt' },
  { curve: 'ed25519', sessionKind: 'cookie' },
  { curve: 'ecdsa', sessionKind: 'jwt' },
  { curve: 'ecdsa', sessionKind: 'cookie' },
];

for (const matrixCase of THRESHOLD_REFRESH_MATRIX) {
  test.describe('threshold refresh matrix (wallet iframe)', () => {
    test.setTimeout(240_000);

    test(`rehydrates ${matrixCase.curve} with sessionKind=${matrixCase.sessionKind} after refresh`, async ({
      page,
    }) => {
      const harness = await setupThresholdEcdsaSealedRefreshHarness(page);
      try {
        const firstPhasePromise = page.evaluate(
          async ({ relayerUrl, keyVersion, shamirPrimeB64u, curve, sessionKind }) => {
            try {
              const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
              const actionsMod = await import('/sdk/esm/core/types/actions.js');
              const indexedDbMod = await import('/sdk/esm/core/indexedDB/index.js');
              const { TatchiPasskey } = sdkMod as any;
              const { ActionType } = actionsMod as any;
              const { IndexedDBManager } = indexedDbMod as any;

              const confirmationConfig = {
                uiMode: 'none' as const,
                behavior: 'skipClick' as const,
                autoProceedDelay: 0,
              };
              const managedRuntimeScopeBootstrap = {
                environmentId: String(
                  (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                ),
                publishableKey: String(
                  (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                ),
              };
              const accountId =
                `refreshmatrix-${curve}-${sessionKind}-${Date.now()}.w3a-v1.testnet`.toLowerCase();
              const tatchi = new TatchiPasskey({
                nearNetwork: 'testnet',
                nearRpcUrl: 'https://test.rpc.fastnear.com',
                relayerAccount: 'web3-authn-v4.testnet',
                relayer: {
                  url: relayerUrl,
                  smartAccountDeploymentMode: 'observe',
                },
                registration: {
                  mode: 'managed',
                  environmentId: String(
                    (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                  ),
                  publishableKey: String(
                    (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                  ),
                },
                signingSessionPersistenceMode: 'sealed_refresh_v1',
                signingSessionSeal: {
                  keyVersion,
                  shamirPrimeB64u,
                },
              });

              tatchi.setConfirmationConfig(confirmationConfig as any);

              const registration = await tatchi.registration.registerPasskeyInternal(
                accountId,
                {},
                confirmationConfig as any,
              );
              if (!registration?.success) {
                return {
                  ok: false,
                  error: String(registration?.error || 'registration failed'),
                };
              }

              const login = await tatchi.unlock(accountId);
              if (!login?.success) {
                return {
                  ok: false,
                  error: String(login?.error || 'unlock failed'),
                };
              }

              const signingEngine = tatchi.getContext().signingEngine as any;
              const accountAddress = String(accountId || '').trim().toLowerCase();
              const nearCandidates = ['near:testnet', 'near:mainnet'];
              let accountContext: { profileId: string; accountRef: { chainIdKey: string } } | null =
                null;
              for (const chainIdKey of nearCandidates) {
                accountContext = await IndexedDBManager.clientDB
                  .resolveProfileAccountContext({
                    chainIdKey,
                    accountAddress,
                  })
                  .catch(() => null);
                if (accountContext?.profileId) break;
              }
              if (!accountContext?.profileId || !accountContext?.accountRef?.chainIdKey) {
                return {
                  ok: false,
                  error: 'Missing generic profile/account mapping after login',
                };
              }

              const [profile, lastProfileState] = await Promise.all([
                IndexedDBManager.clientDB.getProfile(accountContext.profileId).catch(() => null),
                IndexedDBManager.clientDB.getLastProfileState().catch(() => null),
              ]);
              const preferredSignerSlot =
                lastProfileState?.profileId === accountContext.profileId
                  ? Number(lastProfileState.signerSlot)
                  : Number(profile?.defaultSignerSlot);
              const signerSlot =
                Number.isFinite(preferredSignerSlot) && preferredSignerSlot >= 1
                  ? Math.max(1, Math.floor(preferredSignerSlot))
                  : 1;
              const thresholdKeyMaterial = await IndexedDBManager.accountKeyMaterialDB.getKeyMaterial(
                accountContext.profileId,
                signerSlot,
                accountContext.accountRef.chainIdKey,
                'threshold_share_v1',
              );
              const thresholdPayload = (thresholdKeyMaterial?.payload || {}) as any;
              const relayerKeyId = String(thresholdPayload?.relayerKeyId || '').trim();
              const participantIds = Array.isArray(thresholdPayload?.participants)
                ? thresholdPayload.participants
                    .map((participant: any) => Number(participant?.id))
                    .filter((id: number) => Number.isFinite(id) && id > 0)
                    .map((id: number) => Math.floor(id))
                : [];
              if (!relayerKeyId || participantIds.length < 2) {
                return {
                  ok: false,
                  error: 'Missing threshold key material after login',
                };
              }

              const ecdsaBootstrap = await signingEngine.bootstrapEcdsaSession({
                nearAccountId: accountId,
                chain: 'tempo',
                source: 'manual-bootstrap',
                relayerUrl,
                participantIds,
                sessionKind: curve === 'ecdsa' ? sessionKind : 'jwt',
                ttlMs: 120_000,
                remainingUses: 8,
              });
              const thresholdSessionId = String(
                ecdsaBootstrap?.thresholdEcdsaKeyRef?.thresholdSessionId ||
                  ecdsaBootstrap?.session?.sessionId ||
                  '',
              ).trim();
              if (!thresholdSessionId) {
                return {
                  ok: false,
                  error: 'bootstrapEcdsaSession did not return thresholdSessionId',
                };
              }

              if (curve === 'ed25519') {
                const connected = await signingEngine.connectEd25519Session({
                  nearAccountId: accountId,
                  relayerUrl,
                  relayerKeyId,
                  ...(managedRuntimeScopeBootstrap.environmentId &&
                  managedRuntimeScopeBootstrap.publishableKey
                    ? { runtimeScopeBootstrap: managedRuntimeScopeBootstrap }
                    : {}),
                  participantIds,
                  sessionKind,
                  ttlMs: 120_000,
                  remainingUses: 8,
                  sessionId: thresholdSessionId,
                });
                if (!connected?.ok) {
                  return {
                    ok: false,
                    error: String(
                      connected?.message || connected?.code || 'connectEd25519Session failed',
                    ),
                  };
                }
                if (sessionKind === 'jwt') {
                  const firstSign = await tatchi.near.executeAction({
                    nearAccountId: accountId,
                    receiverId: 'w3a-v1.testnet',
                    actionArgs: {
                      type: ActionType.FunctionCall,
                      methodName: 'set_greeting',
                      args: { greeting: `hello-first-${curve}-${sessionKind}-${Date.now()}` },
                      gas: '30000000000000',
                      deposit: '0',
                    },
                    options: {
                      waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                      confirmationConfig,
                    },
                  });
                  if (!firstSign?.success) {
                    return {
                      ok: false,
                      error: String(firstSign?.error || 'first near sign failed'),
                    };
                  }
                }
              } else {
                if (sessionKind === 'jwt') {
                  const firstSign = await tatchi.tempo.signTempo({
                    nearAccountId: accountId,
                    request: {
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
                    },
                    options: { confirmationConfig },
                  });
                  if (!firstSign || firstSign.kind !== 'tempoTransaction') {
                    return {
                      ok: false,
                      error: 'first tempo sign failed',
                    };
                  }
                }
              }

              const session = await tatchi.auth.getWalletSession(accountId);
              return {
                ok: true,
                accountId,
                sessionStatus: String(session?.signingSession?.status || ''),
              };
            } catch (error: unknown) {
              return {
                ok: false,
                error: String(
                  error && typeof error === 'object' && 'message' in error
                    ? (error as { message?: unknown }).message
                    : error || 'first phase failed',
                ),
              };
            }
          },
          {
            relayerUrl: harness.relayerUrl,
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            curve: matrixCase.curve,
            sessionKind: matrixCase.sessionKind,
          },
        );
        const firstPhase = await autoConfirmWalletIframeUntil(page, firstPhasePromise, {
          timeoutMs: 150_000,
          intervalMs: 250,
        });

        expect(firstPhase.ok, firstPhase.error || JSON.stringify(firstPhase)).toBe(true);
        expect(firstPhase.sessionStatus).toBe('active');
        const getCallsAfterFirstPhase = await readWebAuthnGetCallCount(page);

        await page.reload();
        await page.waitForTimeout(300);

        const secondPhasePromise = page.evaluate(
          async ({ relayerUrl, accountId, keyVersion, shamirPrimeB64u, curve, sessionKind }) => {
            try {
              const sdkMod = await import('/sdk/esm/core/TatchiPasskey/index.js');
              const actionsMod = await import('/sdk/esm/core/types/actions.js');
              const { TatchiPasskey } = sdkMod as any;
              const { ActionType } = actionsMod as any;

              const confirmationConfig = {
                uiMode: 'none' as const,
                behavior: 'skipClick' as const,
                autoProceedDelay: 0,
              };
              const tatchi = new TatchiPasskey({
                nearNetwork: 'testnet',
                nearRpcUrl: 'https://test.rpc.fastnear.com',
                relayerAccount: 'web3-authn-v4.testnet',
                relayer: {
                  url: relayerUrl,
                  smartAccountDeploymentMode: 'observe',
                },
                registration: {
                  mode: 'managed',
                  environmentId: String(
                    (globalThis as any).__w3aManagedRegistration?.environmentId || '',
                  ),
                  publishableKey: String(
                    (globalThis as any).__w3aManagedRegistration?.publishableKey || '',
                  ),
                },
                signingSessionPersistenceMode: 'sealed_refresh_v1',
                signingSessionSeal: {
                  keyVersion,
                  shamirPrimeB64u,
                },
              });

              tatchi.setConfirmationConfig(confirmationConfig as any);

              if (curve === 'ed25519') {
                if (sessionKind === 'jwt') {
                  const refreshedSign = await tatchi.near.executeAction({
                    nearAccountId: accountId,
                    receiverId: 'w3a-v1.testnet',
                    actionArgs: {
                      type: ActionType.FunctionCall,
                      methodName: 'set_greeting',
                      args: { greeting: `hello-refresh-${curve}-${Date.now()}` },
                      gas: '30000000000000',
                      deposit: '0',
                    },
                    options: {
                      waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                      confirmationConfig,
                    },
                  });
                  if (!refreshedSign?.success) {
                    return {
                      ok: false,
                      error: String(refreshedSign?.error || 'near sign after refresh failed'),
                    };
                  }
                }
              } else {
                if (sessionKind === 'jwt') {
                  const refreshedSign = await tatchi.tempo.signTempo({
                    nearAccountId: accountId,
                    request: {
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
                    },
                    options: { confirmationConfig },
                  });
                  if (!refreshedSign || refreshedSign.kind !== 'tempoTransaction') {
                    return {
                      ok: false,
                      error: 'tempo sign after refresh failed',
                    };
                  }
                }
              }

              const session = await tatchi.auth.getWalletSession(accountId);
              return {
                ok: true,
                sessionStatus: String(session?.signingSession?.status || ''),
              };
            } catch (error: unknown) {
              return {
                ok: false,
                error: String(
                  error && typeof error === 'object' && 'message' in error
                    ? (error as { message?: unknown }).message
                    : error || 'second phase failed',
                ),
              };
            }
          },
          {
            relayerUrl: harness.relayerUrl,
            accountId: firstPhase.accountId,
            keyVersion: TEST_KEY_VERSION,
            shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
            curve: matrixCase.curve,
            sessionKind: matrixCase.sessionKind,
          },
        );
        const secondPhase = await autoConfirmWalletIframeUntil(page, secondPhasePromise, {
          timeoutMs: 120_000,
          intervalMs: 250,
        });

        expect(secondPhase.ok, secondPhase.error || JSON.stringify(secondPhase)).toBe(true);
        expect(secondPhase.sessionStatus).toBe('active');
        const finalGetCalls = await readWebAuthnGetCallCount(page);
        expect(
          finalGetCalls,
          JSON.stringify({
            matrixCase,
            getCallsAfterFirstPhase,
            finalGetCalls,
            firstPhase,
            secondPhase,
          }),
        ).toBe(getCallsAfterFirstPhase);
      } finally {
        await harness.close();
      }
    });
  });
}
