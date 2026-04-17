import type { Page, Route } from '@playwright/test';
import bs58 from 'bs58';
import { setupBasicPasskeyTest, SDK_ESM_PATHS } from '../setup';
import { DEFAULT_TEST_CONFIG } from '../setup/config';
import { AuthService } from '@server/core/AuthService';
import { createThresholdSigningService } from '@server/core/ThresholdService';
import type { ThresholdStoreConfigInput } from '@server/core/types';
import { THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID } from '@server/core/ThresholdService/schemes/schemeIds';
import { makeSessionAdapter, startExpressRouter } from '../relayer/helpers';
import { base64UrlDecode, base64UrlEncode } from '@shared/utils/encoders';
import {
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleBootstrapTokenService,
  createInMemoryConsoleOrgProjectEnvService,
  createRelayBootstrapGrantBroker,
  createRelayPublishableKeyAuthAdapter,
  createRelayRouter,
} from '@server/router/express-adaptor';
import { createFixtureSigningRootShareResolverForUnitTests } from '../helpers/thresholdEd25519TestUtils';

const SESSION_COOKIE_NAME =
  String(process.env.SESSION_COOKIE_NAME || 'tatchi-jwt').trim() || 'tatchi-jwt';

export async function setupThresholdE2ePage(page: Page): Promise<void> {
  const blankPageUrl = new URL('/__test_blank.html', DEFAULT_TEST_CONFIG.frontendUrl).toString();
  await setupBasicPasskeyTest(page, {
    frontendUrl: blankPageUrl,
    skipPasskeyManagerInit: true,
  });

  await page.evaluate(async (base64Path) => {
    const { base64UrlEncode, base64UrlDecode } = await import(base64Path);
    (window as any).base64UrlEncode = base64UrlEncode;
    (window as any).base64UrlDecode = base64UrlDecode;
  }, SDK_ESM_PATHS.base64);
}

const DEFAULT_ACCOUNTS_ON_CHAIN = new Set<string>(
  [DEFAULT_TEST_CONFIG.relayerAccount].filter((id): id is string => !!id),
);
const THRESHOLD_ED25519_KEY_VERSION_V1 = 'threshold-ed25519-hss-v1';

export function makeAuthServiceForThreshold(
  keysOnChain: Set<string>,
  thresholdStore?: ThresholdStoreConfigInput | null,
): {
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
} {
  const providedConfig = (thresholdStore || {}) as Partial<ThresholdStoreConfigInput>;
  const needsFixtureSigningRootResolver = !(
    providedConfig.signingRootShareResolver ||
    providedConfig.signingRootSecretResolverAdapters ||
    providedConfig.signingRootSecretStore ||
    providedConfig.signingRootSecretDecryptAdapter ||
    providedConfig.signingRootSecretShareKekResolver
  );
  const thresholdConfig: ThresholdStoreConfigInput = {
    THRESHOLD_NODE_ROLE: 'coordinator',
    ...providedConfig,
    ...(needsFixtureSigningRootResolver
      ? { signingRootShareResolver: createFixtureSigningRootShareResolverForUnitTests() }
      : {}),
  };

  const svc = new AuthService({
    relayerAccount: 'relayer.testnet',
    relayerPrivateKey: 'ed25519:dummy',
    nearRpcUrl: DEFAULT_TEST_CONFIG.nearRpcUrl,
    networkId: DEFAULT_TEST_CONFIG.nearNetwork,
    accountInitialBalance: '1',
    createAccountAndRegisterGas: '1',
    thresholdStore: thresholdConfig,
    logger: null,
  });

  // For lite threshold flows, we also stub the standard WebAuthn verifier (contract-backed by default).
  (
    svc as unknown as {
      verifyWebAuthnAuthenticationLite: (
        req: unknown,
      ) => Promise<{ success: boolean; verified: boolean }>;
    }
  ).verifyWebAuthnAuthenticationLite = async (_req: unknown) => ({ success: true, verified: true });

  (
    svc as unknown as { nearClient: { viewAccessKeyList: (accountId: string) => Promise<unknown> } }
  ).nearClient.viewAccessKeyList = async (_accountId: string) => {
    const keys = Array.from(keysOnChain).map((publicKey) => ({
      public_key: publicKey,
      access_key: { nonce: 0, permission: 'FullAccess' as const },
    }));
    return { keys };
  };
  const threshold = createThresholdSigningService({
    authService: svc,
    thresholdStore: thresholdConfig,
    logger: null,
  });
  svc.setThresholdSigningService(threshold);

  return { service: svc, threshold };
}

export async function persistThresholdEd25519RegistrationMaterial(input: {
  threshold: ReturnType<typeof createThresholdSigningService>;
  nearAccountId: string;
  rpId: string;
  publicKey: string;
  keyVersion: string;
  relayerKeyId?: string;
}): Promise<void> {
  const relayerKeyId = String(input.relayerKeyId || input.publicKey).trim();
  const existing = await (
    input.threshold as unknown as {
      keyStore?: {
        get: (relayerKeyId: string) => Promise<{
          nearAccountId: string;
          rpId: string;
          publicKey: string;
          keyVersion: string;
          recoveryExportCapable: true;
        } | null>;
      };
    }
  ).keyStore?.get(relayerKeyId);
  if (
    existing?.nearAccountId === input.nearAccountId &&
    existing?.rpId === input.rpId &&
    existing?.publicKey === input.publicKey &&
    existing?.keyVersion === input.keyVersion &&
    existing?.recoveryExportCapable === true
  ) {
    return;
  }

  const schemeAny = input.threshold.getSchemeModule(THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID);
  if (!schemeAny || schemeAny.schemeId !== THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID) {
    throw new Error(
      `threshold scheme ${THRESHOLD_ED25519_FROST_2P_V1_SCHEME_ID} is not enabled on this server`,
    );
  }
  const keygen = await schemeAny.registration.keygenFromRegistrationMaterial({
    nearAccountId: input.nearAccountId,
    rpId: input.rpId,
    keyVersion: input.keyVersion,
    recoveryExportCapable: true,
    publicKey: input.publicKey,
    relayerKeyId,
  });
  if (!keygen.ok) {
    throw new Error(keygen.message || 'threshold-ed25519 registration material keygen failed');
  }
}

export function createInMemoryJwtSessionAdapter(): ReturnType<typeof makeSessionAdapter> {
  const issuedTokens = new Map<string, Record<string, unknown>>();
  const extractCookieToken = (cookieHeader: string | undefined): string => {
    const raw = String(cookieHeader || '').trim();
    if (!raw) return '';
    const parts = raw.split(';');
    for (const part of parts) {
      const [nameRaw, valueRaw] = part.split('=');
      if (String(nameRaw || '').trim() !== SESSION_COOKIE_NAME) continue;
      return String(valueRaw || '').trim();
    }
    return '';
  };
  return makeSessionAdapter({
    signJwt: async (sub: string, extra?: Record<string, unknown>) => {
      const id =
        typeof globalThis.crypto?.randomUUID === 'function'
          ? globalThis.crypto.randomUUID()
          : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
      const token = `testjwt-${id}`;
      issuedTokens.set(token, { sub, ...(extra || {}) });
      return token;
    },
    parse: async (headers: Record<string, string | string[] | undefined>) => {
      const authHeaderRaw = headers['authorization'] ?? headers['Authorization'];
      const authHeader = Array.isArray(authHeaderRaw) ? authHeaderRaw[0] : authHeaderRaw;
      const cookieHeaderRaw = headers['cookie'] ?? headers['Cookie'];
      const cookieHeader = Array.isArray(cookieHeaderRaw) ? cookieHeaderRaw[0] : cookieHeaderRaw;
      const tokenFromAuthorization =
        typeof authHeader === 'string' ? authHeader.replace(/^Bearer\s+/i, '').trim() : '';
      const token = tokenFromAuthorization || extractCookieToken(cookieHeader);
      const claims = token ? issuedTokens.get(token) : undefined;
      return claims ? { ok: true as const, claims } : { ok: false as const };
    },
  });
}

export async function setupManagedThresholdRegistrationHarness(args: {
  page: Page;
  service: AuthService;
  threshold: ReturnType<typeof createThresholdSigningService>;
  session?: ReturnType<typeof makeSessionAdapter>;
  keyName?: string;
  orgId?: string;
  orgSlug?: string;
  orgName?: string;
  projectId?: string;
  projectName?: string;
  allowedOrigins?: string[];
}): Promise<{
  baseUrl: string;
  session: ReturnType<typeof makeSessionAdapter>;
  managedRegistration: {
    environmentId: string;
    publishableKey: string;
  };
  close: () => Promise<void>;
}> {
  const session = args.session || createInMemoryJwtSessionAdapter();
  const bootstrapTokenStore = createInMemoryConsoleBootstrapTokenService();
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const apiKeys = createInMemoryConsoleApiKeyService();
  const frontendOrigin = new URL(DEFAULT_TEST_CONFIG.frontendUrl).origin;
  const allowedOrigins = Array.from(
    new Set(
      (
        args.allowedOrigins || [
          frontendOrigin,
          'https://example.localhost',
          'https://wallet.example.localhost',
        ]
      ).filter((origin): origin is string => !!String(origin || '').trim()),
    ),
  );
  const orgId = String(args.orgId || 'org_threshold_wallet_iframe').trim();
  const projectId = String(args.projectId || 'proj_threshold_wallet_iframe').trim();
  const environmentId = `${projectId}:dev`;
  const bootstrapAdminCtx = {
    orgId,
    actorUserId: `user_${projectId}`,
    roles: ['admin'],
  } as const;

  await orgProjectEnv.upsertOrganization(bootstrapAdminCtx, {
    name: String(args.orgName || 'Threshold Wallet Iframe Org').trim(),
    slug: String(args.orgSlug || 'threshold-wallet-iframe-org').trim(),
  });
  await orgProjectEnv.createProject(bootstrapAdminCtx, {
    id: projectId,
    name: String(args.projectName || 'Threshold Wallet Iframe Project').trim(),
    liveEnvironmentsEnabled: true,
  });

  const createdPublishableKey = await apiKeys.createApiKey(bootstrapAdminCtx, {
    kind: 'publishable_key',
    name: String(args.keyName || `${projectId}-browser`).trim(),
    environmentId,
    allowedOrigins,
    rateLimitBucket: 'default_web_v1',
    quotaBucket: 'free_registrations_v1',
  });
  const managedRegistration = {
    environmentId,
    publishableKey: createdPublishableKey.secret,
  } as const;

  const router = createRelayRouter(args.service, {
    corsOrigins: allowedOrigins,
    threshold: args.threshold,
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

  await args.page.addInitScript((config) => {
    (window as any).__w3aManagedRegistration = config;
  }, managedRegistration);
  await args.page.evaluate((config) => {
    (window as any).__w3aManagedRegistration = config;
  }, managedRegistration);

  return {
    baseUrl: server.baseUrl,
    session,
    managedRegistration,
    close: server.close,
  };
}

export function corsHeadersForRoute(route: Route): Record<string, string> {
  const req = route.request();
  const origin = req.headers()['origin'] || req.headers()['Origin'] || '';
  return {
    ...(origin
      ? { 'Access-Control-Allow-Origin': origin }
      : { 'Access-Control-Allow-Origin': '*' }),
    'Access-Control-Allow-Credentials': 'true',
    'Access-Control-Allow-Methods': 'POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type,Authorization',
  };
}

export async function installCreateAccountAndRegisterUserMock(
  page: Page,
  input: {
    relayerBaseUrl: string;
    onNewPublicKey: (publicKey: string) => void;
    accountsOnChain?: Set<string>;
    onNewAccountId?: (accountId: string) => void;
    session?: {
      signJwt: (sub: string, extra?: Record<string, unknown>) => Promise<string>;
    };
    runtimePolicyScope?: {
      orgId: string;
      projectId: string;
      envId: string;
    };
    threshold?: {
      bootstrapEcdsaFromRegistrationMaterial?: (request: {
        userId: string;
        rpId: string;
        clientRootShare32B64u: string;
        sessionPolicy: Record<string, unknown>;
      }) => Promise<Record<string, unknown>>;
    };
  },
): Promise<void> {
  await page.route(`${input.relayerBaseUrl}/registration/bootstrap`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    if (method === 'OPTIONS') {
      await route.fallback();
      return;
    }

    const corsHeaders = corsHeadersForRoute(route);
    const payload = JSON.parse(req.postData() || '{}');
    const thresholdEd25519 = payload?.threshold_ed25519 || {};
    const thresholdEcdsaClientRootShare32B64u = String(
      payload?.threshold_ecdsa?.client_root_share32_b64u || '',
    ).trim();
    const thresholdPublicKey = String(thresholdEd25519?.public_key || '').trim();
    const thresholdMode = !!thresholdPublicKey;
    const thresholdEcdsaMode = !!thresholdEcdsaClientRootShare32B64u;
    // HSS registration finalize binds the relayer key record to the derived public key.
    // Mirror that current seam here instead of echoing any stale request-time relayer_key_id.
    const relayerKeyId = thresholdPublicKey;
    const registeredPublicKey = thresholdMode ? thresholdPublicKey : '';
    const accountId = String(payload?.new_account_id || '');
    const nowMs = Date.now();
    const nowSec = Math.floor(nowMs / 1000);
    const edSessionPolicy = payload?.threshold_ed25519?.session_policy || null;
    const ecdsaSessionPolicy = payload?.threshold_ecdsa?.session_policy || null;
    const coercePositive = (value: unknown, fallback: number): number => {
      const n = Number(value);
      return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
    };
    const signThresholdSessionJwt = async (args: {
      kind: 'threshold_ed25519_session_v1' | 'threshold_ecdsa_session_v1';
      sessionId: string;
      relayerKeyId: string;
      participantIds: number[];
      expiresAtMs: number;
    }): Promise<string> => {
      if (!input.session?.signJwt) {
        return args.kind === 'threshold_ed25519_session_v1'
          ? 'mock-threshold-ed25519-jwt'
          : 'mock-threshold-ecdsa-jwt';
      }
      const expSec = Math.floor(args.expiresAtMs / 1000);
      return await input.session.signJwt(accountId, {
        kind: args.kind,
        sessionId: args.sessionId,
        relayerKeyId: args.relayerKeyId,
        rpId: String(payload?.rp_id || '').trim() || 'example.localhost',
        participantIds: args.participantIds,
        thresholdExpiresAtMs: args.expiresAtMs,
        ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
        iat: nowSec,
        exp: expSec,
      });
    };
    const edSession =
      thresholdMode && edSessionPolicy
        ? await (async () => {
            const sessionKind =
              String(payload?.threshold_ed25519?.session_kind || 'jwt').toLowerCase() === 'cookie'
                ? ('cookie' as const)
                : ('jwt' as const);
            const sessionId = String(
              edSessionPolicy?.sessionId || edSessionPolicy?.session_id || `ed-session-${nowMs}`,
            );
            const expiresAtMs =
              nowMs + coercePositive(edSessionPolicy?.ttlMs || edSessionPolicy?.ttl_ms, 60_000);
            const participantIds = [1, 2];
            const remainingUses = coercePositive(
              edSessionPolicy?.remainingUses || edSessionPolicy?.remaining_uses,
              10_000,
            );
            return {
              sessionKind,
              sessionId,
              expiresAtMs,
              participantIds,
              remainingUses,
              jwt: await signThresholdSessionJwt({
                kind: 'threshold_ed25519_session_v1',
                sessionId,
                relayerKeyId,
                participantIds,
                expiresAtMs,
              }),
              ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
            };
          })()
        : undefined;
    const ecdsaBootstrap =
      thresholdEcdsaMode &&
      input.threshold?.bootstrapEcdsaFromRegistrationMaterial &&
      ecdsaSessionPolicy
        ? await input.threshold.bootstrapEcdsaFromRegistrationMaterial({
            userId: accountId,
            rpId: String(payload?.rp_id || '').trim() || 'example.localhost',
            clientRootShare32B64u: thresholdEcdsaClientRootShare32B64u,
            sessionPolicy: {
              version: 'threshold_session_v1',
              userId: accountId,
              rpId: String(payload?.rp_id || '').trim() || 'example.localhost',
              sessionId: String(
                ecdsaSessionPolicy?.sessionId ||
                  ecdsaSessionPolicy?.session_id ||
                  `ecdsa-session-${nowMs}`,
              ),
              participantIds: [1, 2],
              ttlMs: coercePositive(
                ecdsaSessionPolicy?.ttlMs || ecdsaSessionPolicy?.ttl_ms,
                60_000,
              ),
              remainingUses: coercePositive(
                ecdsaSessionPolicy?.remainingUses || ecdsaSessionPolicy?.remaining_uses,
                10_000,
              ),
              ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
            },
          })
        : null;
    if (ecdsaBootstrap && ecdsaBootstrap.ok !== true) {
      await route.fulfill({
        status: 400,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          success: false,
          error: String(ecdsaBootstrap.message || 'threshold-ecdsa registration bootstrap'),
        }),
      });
      return;
    }
    const thresholdEcdsaRelayerKeyId =
      String(
        ecdsaBootstrap && ecdsaBootstrap.ok === true ? ecdsaBootstrap.relayerKeyId || '' : '',
      ).trim() || 'secp256k1:mock-relayer-key-id';
    const thresholdEcdsaPublicKeyB64u =
      String(
        ecdsaBootstrap && ecdsaBootstrap.ok === true
          ? ecdsaBootstrap.thresholdEcdsaPublicKeyB64u || ''
          : '',
      ).trim() || base64UrlEncode(new Uint8Array(33).fill(61));
    const thresholdEcdsaRelayerVerifyingShareB64u =
      String(
        ecdsaBootstrap && ecdsaBootstrap.ok === true
          ? ecdsaBootstrap.relayerVerifyingShareB64u || ''
          : '',
      ).trim() || base64UrlEncode(new Uint8Array(33).fill(31));
    const thresholdEcdsaEthereumAddress =
      String(
        ecdsaBootstrap && ecdsaBootstrap.ok === true ? ecdsaBootstrap.ethereumAddress || '' : '',
      ).trim() || `0x${'12'.repeat(20)}`;
    const thresholdEcdsaThresholdKeyId = String(
      ecdsaBootstrap && ecdsaBootstrap.ok === true ? ecdsaBootstrap.ecdsaThresholdKeyId || '' : '',
    ).trim();
    const thresholdEcdsaClientVerifyingShareB64u = String(
      ecdsaBootstrap && ecdsaBootstrap.ok === true
        ? ecdsaBootstrap.clientVerifyingShareB64u || ''
        : '',
    ).trim();

    const ecdsaSession =
      thresholdEcdsaMode && ecdsaSessionPolicy
        ? await (async () => {
            const sessionKind =
              String(payload?.threshold_ecdsa?.session_kind || 'jwt').toLowerCase() === 'cookie'
                ? ('cookie' as const)
                : ('jwt' as const);
            const sessionId = String(
              ecdsaSessionPolicy?.sessionId ||
                ecdsaSessionPolicy?.session_id ||
                `ecdsa-session-${nowMs}`,
            );
            const expiresAtMs =
              nowMs +
              coercePositive(ecdsaSessionPolicy?.ttlMs || ecdsaSessionPolicy?.ttl_ms, 60_000);
            const participantIds = [1, 2];
            const remainingUses = coercePositive(
              ecdsaSessionPolicy?.remainingUses || ecdsaSessionPolicy?.remaining_uses,
              10_000,
            );
            return {
              sessionKind,
              sessionId,
              expiresAtMs,
              participantIds,
              remainingUses,
              jwt: await signThresholdSessionJwt({
                kind: 'threshold_ecdsa_session_v1',
                sessionId,
                relayerKeyId: thresholdEcdsaRelayerKeyId,
                participantIds,
                expiresAtMs,
              }),
            };
          })()
        : undefined;

    if (registeredPublicKey) input.onNewPublicKey(registeredPublicKey);
    if (accountId) {
      input.onNewAccountId?.(accountId);
      const accountsOnChain = input.accountsOnChain ?? DEFAULT_ACCOUNTS_ON_CHAIN;
      accountsOnChain.add(accountId);
    }

    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({
        success: true,
        transactionHash: `mock_atomic_tx_${Date.now()}`,
        ...(thresholdMode
          ? {
              thresholdEd25519: {
                keyVersion: THRESHOLD_ED25519_KEY_VERSION_V1,
                recoveryExportCapable: true,
                publicKey: thresholdPublicKey,
                relayerKeyId,
                clientParticipantId: 1,
                relayerParticipantId: 2,
                participantIds: [1, 2],
                ...(edSession ? { session: edSession } : {}),
              },
            }
          : {}),
        ...(thresholdEcdsaMode
          ? {
              thresholdEcdsa: {
                ...(thresholdEcdsaThresholdKeyId
                  ? { ecdsaThresholdKeyId: thresholdEcdsaThresholdKeyId }
                  : {}),
                relayerKeyId: thresholdEcdsaRelayerKeyId,
                ...(thresholdEcdsaClientVerifyingShareB64u
                  ? { clientVerifyingShareB64u: thresholdEcdsaClientVerifyingShareB64u }
                  : {}),
                thresholdEcdsaPublicKeyB64u: thresholdEcdsaPublicKeyB64u,
                ethereumAddress: thresholdEcdsaEthereumAddress,
                relayerVerifyingShareB64u: thresholdEcdsaRelayerVerifyingShareB64u,
                participantIds: [1, 2],
                ...(ecdsaSession ? { session: ecdsaSession } : {}),
              },
            }
          : {}),
      }),
    });
  });
}

export async function installFastNearRpcMock(
  page: Page,
  input: {
    keysOnChain: Set<string>;
    nonceByPublicKey: Map<string, number>;
    onSendTx?: () => void;
    strictAccessKeyLookup?: boolean;
    accountsOnChain?: Set<string>;
  },
): Promise<void> {
  const strictAccessKeyLookup = input.strictAccessKeyLookup ?? true;
  const accountsOnChain = input.accountsOnChain ?? DEFAULT_ACCOUNTS_ON_CHAIN;
  const isKnownAccount = (accountId: string) =>
    (accountId && accountsOnChain.has(accountId)) || DEFAULT_ACCOUNTS_ON_CHAIN.has(accountId);

  await page.route('**://test.rpc.fastnear.com/**', async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (method === 'OPTIONS') {
      await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
      return;
    }
    if (method !== 'POST') {
      await route.fallback();
      return;
    }

    let body: any = {};
    try {
      body = JSON.parse(req.postData() || '{}');
    } catch {}

    const rpcMethod = body?.method;
    const params = body?.params || {};
    const id = body?.id ?? '1';

    const blockHash = bs58.encode(Buffer.alloc(32, 7));
    const blockHeight = 424242;

    if (rpcMethod === 'block') {
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: { header: { hash: blockHash, height: blockHeight } },
        }),
      });
      return;
    }

    if (rpcMethod === 'query' && params?.request_type === 'call_function') {
      const resultBytes = Array.from(Buffer.from(JSON.stringify({ verified: true }), 'utf8'));
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ jsonrpc: '2.0', id, result: { result: resultBytes, logs: [] } }),
      });
      return;
    }

    const requestType = typeof params?.request_type === 'string' ? params.request_type : '';
    const isViewAccount =
      rpcMethod === 'query' &&
      (requestType === 'view_account' || (!!params?.account_id && !requestType));

    if (isViewAccount) {
      const accountId = String(params?.account_id || '');
      if (!isKnownAccount(accountId)) {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32000,
              message: 'UNKNOWN_ACCOUNT',
              data: 'UNKNOWN_ACCOUNT',
            },
          }),
        });
        return;
      }
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            amount: '0',
            locked: '0',
            code_hash: '11111111111111111111111111111111',
            storage_usage: 0,
            storage_paid_at: 0,
            block_height: blockHeight,
            block_hash: blockHash,
          },
        }),
      });
      return;
    }

    if (rpcMethod === 'query' && params?.request_type === 'view_access_key') {
      const publicKey = String(params?.public_key || '');
      if (strictAccessKeyLookup && publicKey && !input.keysOnChain.has(publicKey)) {
        await route.fulfill({
          status: 200,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id,
            error: {
              code: -32000,
              message: 'Unknown access key',
              data: { public_key: publicKey },
            },
          }),
        });
        return;
      }

      const nonce = input.nonceByPublicKey.get(publicKey) ?? 0;
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            block_hash: blockHash,
            block_height: blockHeight,
            nonce,
            permission: 'FullAccess',
          },
        }),
      });
      return;
    }

    if (rpcMethod === 'query' && params?.request_type === 'view_access_key_list') {
      const keys: any[] = Array.from(input.keysOnChain).map((pk) => ({
        public_key: pk,
        access_key: { nonce: input.nonceByPublicKey.get(pk) ?? 0, permission: 'FullAccess' },
      }));
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({ jsonrpc: '2.0', id, result: { keys } }),
      });
      return;
    }

    if (rpcMethod === 'send_tx') {
      input.onSendTx?.();
      await route.fulfill({
        status: 200,
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id,
          result: {
            status: { SuccessValue: '' },
            transaction: { hash: `mock-tx-${Date.now()}` },
            transaction_outcome: { id: `mock-tx-outcome-${Date.now()}` },
            receipts_outcome: [],
          },
        }),
      });
      return;
    }

    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({ jsonrpc: '2.0', id, result: {} }),
    });
  });
}

export async function installThresholdEd25519RegistrationMocks(
  page: Page,
  input: {
    relayerBaseUrl: string;
    keysOnChain: Set<string>;
    nonceByPublicKey: Map<string, number>;
    accountsOnChain?: Set<string>;
    onBootstrap?: (input: {
      nearAccountId: string;
      rpId: string;
      relayerKeyId: string;
      publicKey: string;
      keyVersion: string;
    }) => void | Promise<void>;
    session?: {
      signJwt: (sub: string, extra?: Record<string, unknown>) => Promise<string>;
    };
    threshold?: ReturnType<typeof createThresholdSigningService>;
    runtimePolicyScope?: {
      orgId: string;
      projectId: string;
      envId: string;
    };
    mutateThresholdEd25519Response?: (
      thresholdEd25519: Record<string, unknown>,
    ) => Record<string, unknown>;
  },
): Promise<void> {
  const accountsOnChain = input.accountsOnChain ?? DEFAULT_ACCOUNTS_ON_CHAIN;
  const coercePositive = (value: unknown, fallback: number): number => {
    const n = Number(value);
    return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
  };

  await page.route(`${input.relayerBaseUrl}/registration/bootstrap`, async (route) => {
    const req = route.request();
    const method = req.method().toUpperCase();
    const corsHeaders = corsHeadersForRoute(route);
    if (method === 'OPTIONS') {
      await route.fulfill({ status: 204, headers: corsHeaders, body: '' });
      return;
    }
    if (method !== 'POST') {
      await route.fallback();
      return;
    }

    const payload = JSON.parse(req.postData() || '{}');
    const accountId = String(payload?.new_account_id || '').trim();
    const rpId = String(payload?.rp_id || '').trim();
    const thresholdEd25519 = payload?.threshold_ed25519 || {};
    const publicKey = String(thresholdEd25519?.public_key || '').trim();
    const relayerKeyId = publicKey || 'ed25519:mock-relayer-key-id';
    const keyVersion =
      String(thresholdEd25519?.key_version || '').trim() || THRESHOLD_ED25519_KEY_VERSION_V1;
    const sessionPolicy = thresholdEd25519?.session_policy || null;
    const sessionId = String(sessionPolicy?.sessionId || sessionPolicy?.session_id || '').trim();
    const ttlMs = coercePositive(sessionPolicy?.ttlMs || sessionPolicy?.ttl_ms, 60_000);
    const remainingUses = coercePositive(
      sessionPolicy?.remainingUses || sessionPolicy?.remaining_uses,
      10_000,
    );
    const expiresAtMs = Date.now() + ttlMs;
    const effectiveExpiresAtMs = expiresAtMs;
    const effectiveRemainingUses = remainingUses;
    const effectiveParticipantIds = [1, 2];
    const thresholdAuthSessionStore = (
      input.threshold as unknown as {
        authSessionStore?: {
          putSession: (
            sessionId: string,
            record: unknown,
            opts: { ttlMs: number; remainingUses: number },
          ) => Promise<void>;
        };
      }
    )?.authSessionStore;
    if (sessionId && thresholdAuthSessionStore?.putSession) {
      await thresholdAuthSessionStore.putSession(
        sessionId,
        {
          expiresAtMs: effectiveExpiresAtMs,
          relayerKeyId,
          userId: accountId,
          rpId,
          participantIds: effectiveParticipantIds,
        },
        {
          ttlMs,
          remainingUses: effectiveRemainingUses,
        },
      );
    }
    const nowSec = Math.floor(Date.now() / 1000);
    const thresholdSessionJwt =
      sessionId && input.session?.signJwt
        ? await input.session.signJwt(accountId, {
            kind: 'threshold_ed25519_session_v1',
            sessionId,
            relayerKeyId,
            rpId,
            participantIds: effectiveParticipantIds,
            thresholdExpiresAtMs: effectiveExpiresAtMs,
            ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
            iat: nowSec,
            exp: Math.floor(effectiveExpiresAtMs / 1000),
          })
        : 'mock-threshold-ed25519-registration-jwt';

    if (accountId) {
      accountsOnChain.add(accountId);
    }
    if (publicKey) {
      input.keysOnChain.add(publicKey);
      input.nonceByPublicKey.set(publicKey, input.nonceByPublicKey.get(publicKey) ?? 0);
    }

    await input.onBootstrap?.({
      nearAccountId: accountId,
      rpId,
      relayerKeyId,
      publicKey,
      keyVersion,
    });

    const responseThresholdEd25519Base: Record<string, unknown> = {
      relayerKeyId,
      publicKey,
      keyVersion,
      recoveryExportCapable: true,
      clientParticipantId: 1,
      relayerParticipantId: 2,
      participantIds: [1, 2],
      ...(sessionId
        ? {
            session: {
              sessionKind: 'jwt',
              sessionId,
              expiresAtMs: effectiveExpiresAtMs,
              participantIds: effectiveParticipantIds,
              remainingUses: effectiveRemainingUses,
              jwt: thresholdSessionJwt,
              ...(input.runtimePolicyScope ? { runtimePolicyScope: input.runtimePolicyScope } : {}),
            },
          }
        : {}),
    };

    const responseThresholdEd25519 = input.mutateThresholdEd25519Response
      ? input.mutateThresholdEd25519Response(responseThresholdEd25519Base)
      : responseThresholdEd25519Base;

    await route.fulfill({
      status: 200,
      headers: { 'Content-Type': 'application/json', ...corsHeaders },
      body: JSON.stringify({
        success: true,
        transactionHash: `mock_atomic_tx_${Date.now()}`,
        thresholdEd25519: responseThresholdEd25519,
      }),
    });
  });
}

export function flipFirstByteB64u(b64u: string): string {
  const bytes = base64UrlDecode(b64u);
  if (!bytes.length) return b64u;
  bytes[0] ^= 1;
  return base64UrlEncode(bytes);
}

export async function proxyPostJsonAndMutate(
  route: Route,
  mutate: (json: any) => any,
): Promise<void> {
  const req = route.request();
  const method = req.method().toUpperCase();
  if (method !== 'POST') {
    await route.fallback();
    return;
  }

  const origin = req.headers()['origin'] || req.headers()['Origin'] || '';
  const contentType =
    req.headers()['content-type'] || req.headers()['Content-Type'] || 'application/json';
  const body = req.postData() || '';

  const res = await fetch(req.url(), {
    method: 'POST',
    headers: {
      'Content-Type': contentType,
      ...(origin ? { Origin: origin } : {}),
    },
    body,
  });
  const text = await res.text();
  let outText = text;
  try {
    const json = JSON.parse(text || '{}');
    outText = JSON.stringify(mutate(json));
  } catch {}

  const headers = Object.fromEntries(res.headers.entries());
  delete (headers as Record<string, string>)['content-length'];
  delete (headers as Record<string, string>)['Content-Length'];

  await route.fulfill({
    status: res.status,
    headers,
    body: outText,
  });
}
