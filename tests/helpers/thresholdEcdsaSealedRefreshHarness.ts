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
import { walletSigningBudgetSessionId } from '@server/core/ThresholdService/walletSigningBudget';
import { startExpressRouter } from '../relayer/helpers';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import {
  corsHeadersForRoute,
  createInMemoryJwtSessionAdapter,
  installFastNearRpcMock,
  makeAuthServiceForThreshold,
  setupThresholdE2ePage,
} from '../e2e/thresholdEd25519.testUtils';
import { autoConfirmWalletIframeUntil } from '../setup/flows';
import { installRelayServerProxyShim } from '../setup/cross-origin-headers';

export const TEST_KEY_VERSION = 'kek-s-2026-02';
export const TEST_SHAMIR_PRIME_B64U = '_____________________________________v___C8';
const TEST_SERVER_ENCRYPT_EXPONENT_B64U = 'AQAB';
const TEST_SERVER_DECRYPT_EXPONENT_B64U = '6LQXS-i0F0votBdL6LQXS-i0F0votBdL6LQXSv___Ic';
export const TEST_WEBAUTHN_GET_COUNTER_KEY = '__w3a_test_webauthn_get_calls';
const TEST_SESSION_COOKIE_NAME =
  String(process.env.SESSION_COOKIE_NAME || 'seams-jwt').trim() || 'seams-jwt';

export type SealedRefreshHarness = {
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

function createThresholdAwareSealedRefreshSessionAdapter(): ReturnType<
  typeof createInMemoryJwtSessionAdapter
> {
  const base = createInMemoryJwtSessionAdapter();
  const readBearerToken = (headers: Record<string, string | string[] | undefined>): string => {
    const raw = headers.authorization ?? headers.Authorization;
    const header = Array.isArray(raw) ? raw[0] : raw;
    return typeof header === 'string' ? header.replace(/^Bearer\s+/i, '').trim() : '';
  };
  const decodeUnsignedJwtClaims = (token: string): Record<string, unknown> | null => {
    const payload = String(token || '').split('.')[1];
    if (!payload) return null;
    try {
      const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
      return decoded && typeof decoded === 'object' && !Array.isArray(decoded) ? decoded : null;
    } catch {
      return null;
    }
  };
  return {
    ...base,
    buildSetCookie: (token: string) =>
      `${TEST_SESSION_COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=None`,
    parse: async (headers) => {
      const parsed = await base.parse(headers);
      if (parsed.ok) return parsed;
      const claims = decodeUnsignedJwtClaims(readBearerToken(headers));
      const kind = String(claims?.kind || '').trim();
      if (kind === 'threshold_ed25519_session_v1' || kind === 'threshold_ecdsa_session_v1') {
        return { ok: true as const, claims: claims as Record<string, unknown> };
      }
      return parsed;
    },
  };
}

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
      signingRootVersion: string;
    };
    onNewPublicKey: (publicKey: string) => void;
    onNewAccountId?: (accountId: string) => void;
  },
): Promise<void> {
  const threshold = input.threshold as {
    bootstrapEcdsaFromRegistrationMaterial?: (request: {
      walletSessionUserId: string;
      rpId: string;
      clientRootShare32B64u: string;
      sessionPolicy: Record<string, unknown>;
    }) => Promise<Record<string, unknown>>;
    authSessionStore?: {
      putSession: (
        id: string,
        record: {
          expiresAtMs: number;
          relayerKeyId: string;
          userId: string;
          rpId: string;
          participantIds: number[];
        },
        opts: { ttlMs: number; remainingUses: number },
      ) => Promise<void>;
    };
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

    const resolveRuntimePolicyScope = (
      policy: Record<string, unknown>,
    ): typeof input.runtimePolicyScope => {
      const scope =
        policy.runtimePolicyScope && typeof policy.runtimePolicyScope === 'object'
          ? (policy.runtimePolicyScope as Partial<typeof input.runtimePolicyScope>)
          : {};
      const orgId = String(scope.orgId || input.runtimePolicyScope.orgId || '').trim();
      const projectId = String(scope.projectId || input.runtimePolicyScope.projectId || '').trim();
      const envId = String(scope.envId || input.runtimePolicyScope.envId || '').trim();
      const signingRootVersion = String(
        scope.signingRootVersion || input.runtimePolicyScope.signingRootVersion || 'default',
      ).trim();
      return { orgId, projectId, envId, signingRootVersion };
    };

    const signThresholdSessionAuthToken = async (args: {
      kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1';
      sessionId: string;
      walletSigningSessionId: string;
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
        walletSigningSessionId: args.walletSigningSessionId,
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
      const walletSigningSessionId = String(
        policy?.walletSigningSessionId || policy?.wallet_signing_session_id || sessionId,
      ).trim();
      const ttlMs = positiveInt(policy?.ttlMs || policy?.ttl_ms, 60_000);
      const remainingUses = positiveInt(policy?.remainingUses || policy?.remaining_uses, 10_000);
      const expiresAtMs = nowMs + ttlMs;
      const participantIds = asParticipantIds(policy?.participantIds, [1, 2]);
      const runtimePolicyScope = resolveRuntimePolicyScope(policy);
      const jwt = await signThresholdSessionAuthToken({
        kind: 'threshold_ed25519_session_v1',
        sessionId,
        walletSigningSessionId,
        relayerKeyId: thresholdEdRelayerKeyId,
        participantIds,
        expiresAtMs,
        runtimePolicyScope,
      });
      if (threshold.authSessionStore) {
        const sessionRecord = {
          expiresAtMs,
          relayerKeyId: thresholdEdRelayerKeyId,
          userId: accountId,
          rpId,
          participantIds,
        };
        await threshold.authSessionStore.putSession(sessionId, sessionRecord, {
          ttlMs,
          remainingUses,
        });
        await threshold.authSessionStore.putSession(
          walletSigningBudgetSessionId(walletSigningSessionId),
          sessionRecord,
          {
            ttlMs,
            remainingUses,
          },
        );
      }
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
          walletSigningSessionId,
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
      const walletSigningSessionId = String(
        policy?.walletSigningSessionId || policy?.wallet_signing_session_id || sessionId,
      ).trim();
      const ttlMs = positiveInt(policy?.ttlMs || policy?.ttl_ms, 60_000);
      const remainingUses = positiveInt(policy?.remainingUses || policy?.remaining_uses, 10_000);
      const participantIds = asParticipantIds(policy?.participantIds, [1, 2]);
      const runtimePolicyScope = resolveRuntimePolicyScope(policy);
      const bootstrap = (await bootstrapEcdsaFromRegistrationMaterial({
        walletSessionUserId: accountId,
        rpId,
        clientRootShare32B64u: thresholdEcdsaClientRootShare32B64u,
        sessionPolicy: {
          version: 'threshold_session_v1',
          walletSessionUserId: accountId,
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
          walletSigningSessionId,
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
  await page.route(
    `${input.relayerBaseUrl}/registration/threshold-ed25519/hss/finalize`,
    async (route) => {
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
        const registrationMaterial =
          await deriveThresholdEd25519RegistrationMaterialFromHssFinalize({
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
    },
  );
}

export async function setupThresholdEcdsaSealedRefreshHarness(
  page: Page,
): Promise<SealedRefreshHarness> {
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
    signingRootVersion: 'default',
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

  const session = createThresholdAwareSealedRefreshSessionAdapter();
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
        ed25519Stores: [thresholdAuthStores.authSessionStore as any],
        ecdsaStores: [thresholdAuthStores.ecdsaAuthSessionStore as any],
        walletBudgetStores: [thresholdAuthStores.authSessionStore as any],
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

export async function readWebAuthnGetCallCount(page: Page): Promise<number> {
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

export async function readWalletIframeThresholdPersistence(page: Page): Promise<
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
              window.localStorage?.getItem?.('seams:threshold-ed25519-session:v1:index') || null,
            localSealIndex:
              window.localStorage?.getItem?.('seams:signing-session-sealed:v1:index') || null,
            sessionEd25519Index:
              window.sessionStorage?.getItem?.('seams:threshold-ed25519-session:v1:index') || null,
            sessionSealIndex:
              window.sessionStorage?.getItem?.('seams:signing-session-sealed:v1:index') || null,
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

export type PasskeyLifecycleCurve = 'ed25519' | 'ecdsa';
export type PasskeyLifecyclePhase = 'register_unlock_sign' | 'sign';

export async function runPasskeySigningSessionLifecyclePhase(
  page: Page,
  harness: SealedRefreshHarness,
  input: {
    accountId: string;
    curve: PasskeyLifecycleCurve;
    phase: PasskeyLifecyclePhase;
    tag: string;
    remainingUses: number;
  },
): Promise<{
  ok: boolean;
  accountId?: string;
  curve?: PasskeyLifecycleCurve;
  stage?: string;
  sessionStatus?: string;
  signKind?: string;
  chain?: string;
  error?: string;
}> {
  const phasePromise = page.evaluate(
    async ({
      relayerUrl,
      keyVersion,
      shamirPrimeB64u,
      accountId,
      curve,
      phase,
      tag,
      remainingUses,
    }) => {
      let stage = 'init';
      try {
        const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
        const actionsMod = await import('/sdk/esm/core/types/actions.js');
        const { SeamsPasskey } = sdkMod as any;
        const { ActionType } = actionsMod as any;

        const confirmationConfig = {
          uiMode: 'none' as const,
          behavior: 'skipClick' as const,
          autoProceedDelay: 0,
        };
        const seams = new SeamsPasskey({
          nearNetwork: 'testnet',
          nearRpcUrl: 'https://test.rpc.fastnear.com',
          relayerAccount: 'web3-authn-v4.testnet',
          relayer: {
            url: relayerUrl,
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
            remainingUses,
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

        seams.setConfirmationConfig(confirmationConfig as any);

        if (phase === 'register_unlock_sign') {
          stage = 'registration';
          const registration = await seams.registration.registerPasskeyInternal(
            accountId,
            {},
            confirmationConfig as any,
          );
          if (!registration?.success) {
            return {
              ok: false,
              accountId,
              curve,
              stage,
              error: String(registration?.error || 'registration failed'),
            };
          }

          stage = 'unlock';
          const login = await seams.unlock(accountId, {
            session: {
              kind: 'jwt',
              relayUrl: relayerUrl,
              exchange: { type: 'passkey_assertion' },
            },
            signingSession: { ttlMs: 120_000, remainingUses },
          });
          if (!login?.success) {
            return {
              ok: false,
              accountId,
              curve,
              stage,
              error: String(login?.error || 'unlock failed'),
            };
          }

          if (curve === 'ecdsa') {
            stage = 'bootstrap_ecdsa';
            const bootstrap = await seams.tempo.bootstrapEcdsaSession({
              kind: 'reuse_warm_ecdsa_bootstrap',
              walletSession: {
                walletId: accountId,
                walletSessionUserId: accountId,
              },
              subjectId: accountId,
              chainTarget: {
                kind: 'tempo',
                chainId: 42431,
                networkSlug: 'tempo-moderato',
              },
              relayerUrl,
              ttlMs: 120_000,
              remainingUses,
            });
            if (!bootstrap?.thresholdEcdsaKeyRef?.ecdsaThresholdKeyId) {
              return {
                ok: false,
                accountId,
                curve,
                stage,
                error: 'threshold ECDSA bootstrap did not return ecdsaThresholdKeyId',
              };
            }
          }
        }

        stage = `sign_${curve}`;
        const sign = async (): Promise<
          { ok: true; signKind: string; chain: string } | { ok: false; error: string }
        > => {
          const tagHex = Array.from(new TextEncoder().encode(String(tag || 'x')))
            .map((byte) => byte.toString(16).padStart(2, '0'))
            .join('');
          if (curve === 'ed25519') {
            const signed = await seams.near.executeAction({
              nearAccount: { accountId },
              receiverId: 'w3a-v1.testnet',
              actionArgs: {
                type: ActionType.FunctionCall,
                methodName: 'set_greeting',
                args: { greeting: `hello-lifecycle-${tag}-${Date.now()}` },
                gas: '30000000000000',
                deposit: '0',
              },
              options: {
                waitUntil: 'EXECUTED_OPTIMISTIC' as any,
                confirmationConfig,
              },
            });
            if (!signed?.success) {
              return { ok: false, error: String(signed?.error || 'near sign failed') };
            }
            return { ok: true, signKind: 'nearAction', chain: 'near' };
          }

          const signed = await seams.tempo.signTempo({
            walletSession: {
              walletId: accountId,
              walletSessionUserId: accountId,
            },
            subjectId: accountId,
            chainTarget: {
              kind: 'tempo',
              chainId: 42431,
              networkSlug: 'tempo-moderato',
            },
            request: {
              chain: 'tempo' as const,
              kind: 'tempoTransaction' as const,
              senderSignatureAlgorithm: 'secp256k1' as const,
              tx: {
                chainId: 42431,
                maxPriorityFeePerGas: 1n,
                maxFeePerGas: 2n,
                gasLimit: 21_000n,
                calls: [{ to: '0x' + '11'.repeat(20), value: 0n, input: `0x${tagHex}` }],
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
            return { ok: false, error: 'tempo sign failed' };
          }
          return {
            ok: true,
            signKind: String(signed.kind || ''),
            chain: String(signed.chain || ''),
          };
        };

        const signResult = await sign();
        if (!signResult.ok) {
          return {
            ok: false,
            accountId,
            curve,
            stage,
            error: signResult.error,
          };
        }

        stage = 'get_session';
        const session = await seams.auth.getWalletSession(accountId);
        return {
          ok: true,
          accountId,
          curve,
          stage,
          signKind: signResult.signKind,
          chain: signResult.chain,
          sessionStatus: String(session?.signingSession?.status || ''),
        };
      } catch (error: unknown) {
        let sessionStatus = '';
        try {
          const sdkMod = await import('/sdk/esm/core/SeamsPasskey/index.js');
          const { SeamsPasskey } = sdkMod as any;
          const seams = new SeamsPasskey({
            nearNetwork: 'testnet',
            nearRpcUrl: 'https://test.rpc.fastnear.com',
            relayerAccount: 'web3-authn-v4.testnet',
            relayer: {
              url: relayerUrl,
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
          const session = await seams.auth.getWalletSession(accountId);
          sessionStatus = String(session?.signingSession?.status || '');
        } catch {}
        return {
          ok: false,
          accountId,
          curve,
          stage,
          ...(sessionStatus ? { sessionStatus } : {}),
          error: String(
            error && typeof error === 'object' && 'message' in error
              ? (error as { message?: unknown }).message
              : error || 'passkey lifecycle phase failed',
          ),
          ...(error instanceof Error && error.stack ? { stack: error.stack } : {}),
        };
      }
    },
    {
      relayerUrl: harness.relayerUrl,
      keyVersion: TEST_KEY_VERSION,
      shamirPrimeB64u: TEST_SHAMIR_PRIME_B64U,
      accountId: input.accountId,
      curve: input.curve,
      phase: input.phase,
      tag: input.tag,
      remainingUses: input.remainingUses,
    },
  );

  return await autoConfirmWalletIframeUntil(page, phasePromise, {
    timeoutMs: 150_000,
    intervalMs: 250,
  });
}
