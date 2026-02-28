import express, { Express } from 'express';
import {
  AuthService,
  createEcdsaAuthSessionStore,
  createPostgresPrfSessionSealIdempotencyStore,
  createPrfSessionSealPolicyFromEcdsaAuthSessionStore,
  createPrfSessionSealRoutesOptions,
  createPrfSessionSealShamir3PassCipherAdapter,
  resolvePrfSessionSealRateLimitFromEnv,
  requireEnvVar,
  createThresholdSigningService,
} from '@tatchi-xyz/sdk/server';
import {
  createConsoleRouter,
  createInMemoryConsoleBillingService,
  createInMemoryConsoleWebhookService,
  createPostgresConsoleBillingService,
  createPostgresConsoleWebhookService,
  createRelayRouter,
  type ConsoleBillingService,
  type ConsoleAuthAdapter,
  type ConsoleWebhookService,
} from '@tatchi-xyz/sdk/server/router/express';

import dotenv from 'dotenv';
import jwtSession from './jwtSession.js';

dotenv.config();

let server: ReturnType<Express['listen']> | null = null;

function shutdown(signal: string) {
  console.log(`[shutdown] received ${signal}, closing server...`);
  if (!server) {
    process.exit(0);
  }
  server.close(() => {
    console.log('[shutdown] http server closed');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('[shutdown] force exit after 10s');
    process.exit(1);
  }, 10_000).unref();
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

function hostnameFromOrigin(origin: string): string {
  try {
    return new URL(origin).hostname.toLowerCase();
  } catch {
    return '';
  }
}

function sanitizeOrigins(values: string[]): string[] {
  const out = new Set<string>();
  for (const raw of values) {
    try {
      const u = new URL(String(raw || '').trim());
      const scheme = u.protocol;
      const host = u.hostname.toLowerCase();
      if (!host) continue;
      if (scheme !== 'https:' && !(scheme === 'http:' && host === 'localhost')) continue;
      if ((u.pathname && u.pathname !== '/') || u.search || u.hash) continue;
      const port = u.port ? `:${u.port}` : '';
      out.add(`${scheme}//${host}${port}`);
    } catch {}
  }
  return Array.from(out);
}

function parseOptionalPositiveInteger(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  const integer = Math.floor(parsed);
  return integer > 0 ? integer : undefined;
}

function parseBooleanFlag(value: unknown): boolean {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  return normalized === '1' || normalized === 'true' || normalized === 'yes' || normalized === 'on';
}

function parsePrfSealLimiterKind(value: unknown): 'in-memory' | 'upstash-redis-rest' | 'redis-tcp' {
  const normalized = String(value || '')
    .trim()
    .toLowerCase();
  if (normalized === 'upstash-redis-rest') return 'upstash-redis-rest';
  if (normalized === 'redis-tcp') return 'redis-tcp';
  return 'in-memory';
}

async function main() {
  const env = process.env;
  const redisUrl = typeof env.REDIS_URL === 'string' ? env.REDIS_URL.trim() : '';
  const postgresUrl = typeof env.POSTGRES_URL === 'string' ? env.POSTGRES_URL.trim() : '';
  const ed25519MasterSecretB64u =
    typeof env.THRESHOLD_ED25519_MASTER_SECRET_B64U === 'string'
      ? env.THRESHOLD_ED25519_MASTER_SECRET_B64U.trim()
      : '';
  const secp256k1MasterSecretB64u = requireEnvVar(env, 'THRESHOLD_SECP256K1_MASTER_SECRET_B64U');
  const usePostgresForThreshold = Boolean(postgresUrl);
  const thresholdRedisUrl = usePostgresForThreshold ? '' : redisUrl;

  if (usePostgresForThreshold && redisUrl) {
    console.warn(
      '[threshold] POSTGRES_URL and REDIS_URL are both set; using Postgres for threshold stores and ignoring REDIS_URL.',
    );
  }

  const host =
    typeof env.HOST === 'string' && env.HOST.trim().length > 0 ? env.HOST.trim() : undefined;
  const config = {
    port: Number(env.PORT || 3000),
    host,
    expectedOrigin: env.EXPECTED_ORIGIN || 'https://example.localhost', // Frontend origin
    expectedWalletOrigin: env.EXPECTED_WALLET_ORIGIN || 'https://wallet.example.localhost', // Wallet origin (optional)
  };
  const rorRpId = String(env.ROR_RP_ID || hostnameFromOrigin(config.expectedWalletOrigin))
    .trim()
    .toLowerCase();
  const rorOrigins = sanitizeOrigins([
    config.expectedOrigin,
    config.expectedWalletOrigin,
    ...String(env.ROR_ALLOWED_ORIGINS || '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean),
  ]);

  const thresholdEd25519KeyStore = {
    // Share mode + deterministic relayer share derivation (optional)
    THRESHOLD_ED25519_SHARE_MODE: env.THRESHOLD_ED25519_SHARE_MODE,
    THRESHOLD_ED25519_MASTER_SECRET_B64U: ed25519MasterSecretB64u || undefined,
    THRESHOLD_SECP256K1_MASTER_SECRET_B64U: secp256k1MasterSecretB64u,
    // Node role + coordinator/cosigner wiring (optional)
    THRESHOLD_NODE_ROLE: env.THRESHOLD_NODE_ROLE,
    THRESHOLD_COORDINATOR_SHARED_SECRET_B64U: env.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U,
    THRESHOLD_COORDINATOR_INSTANCE_ID: env.THRESHOLD_COORDINATOR_INSTANCE_ID,
    THRESHOLD_COORDINATOR_PEERS: env.THRESHOLD_COORDINATOR_PEERS,
    // Optional persistence for sessions/shares
    POSTGRES_URL: postgresUrl || undefined,
    UPSTASH_REDIS_REST_URL: env.UPSTASH_REDIS_REST_URL,
    UPSTASH_REDIS_REST_TOKEN: env.UPSTASH_REDIS_REST_TOKEN,
    REDIS_URL: thresholdRedisUrl || undefined,
    // Optional key prefixes (useful when sharing a single database)
    THRESHOLD_ED25519_KEYSTORE_PREFIX: env.THRESHOLD_ED25519_KEYSTORE_PREFIX,
    THRESHOLD_ED25519_SESSION_PREFIX: env.THRESHOLD_ED25519_SESSION_PREFIX,
    THRESHOLD_ED25519_AUTH_PREFIX: env.THRESHOLD_ED25519_AUTH_PREFIX,
  } as const;

  const authService = new AuthService({
    // new accounts with be created with this account: e.g. bob.{relayer-account-id}.near
    relayerAccount: requireEnvVar(env, 'RELAYER_ACCOUNT_ID'),
    relayerPrivateKey: requireEnvVar(env, 'RELAYER_PRIVATE_KEY'),
    // Optional overrides (SDK provides defaults when omitted)
    nearRpcUrl: env.NEAR_RPC_URL,
    networkId: env.NETWORK_ID,
    accountInitialBalance: env.ACCOUNT_INITIAL_BALANCE,
    createAccountAndRegisterGas: env.CREATE_ACCOUNT_AND_REGISTER_GAS,
    logger: console,
    thresholdEd25519KeyStore,
    googleOidc: {
      GOOGLE_OIDC_CLIENT_ID: env.GOOGLE_OIDC_CLIENT_ID,
      GOOGLE_OIDC_CLIENT_IDS: env.GOOGLE_OIDC_CLIENT_IDS,
      GOOGLE_OIDC_HOSTED_DOMAINS: env.GOOGLE_OIDC_HOSTED_DOMAINS,
    },
  });

  await authService.initStorage();

  const threshold = createThresholdSigningService({
    authService,
    thresholdEd25519KeyStore,
    logger: console,
  });

  const prfSessionSealEnabled = parseBooleanFlag(env.PRF_SESSION_SEAL_ENABLED);
  const prfSessionSeal = (() => {
    if (!prfSessionSealEnabled) return null;

    const shamirPrimeB64u = requireEnvVar(env, 'SHAMIR_P_B64U');
    const serverEncryptExponentB64u = requireEnvVar(env, 'SHAMIR_E_S_B64U');
    const serverDecryptExponentB64u = requireEnvVar(env, 'SHAMIR_D_S_B64U');
    const keyVersion = requireEnvVar(env, 'PRF_SESSION_SEAL_KEY_VERSION');
    if (!keyVersion) {
      throw new Error(
        'PRF_SESSION_SEAL_KEY_VERSION must be a non-empty string when PRF_SESSION_SEAL_ENABLED=1',
      );
    }

    const ecdsaAuthSessionStore = createEcdsaAuthSessionStore({
      config: thresholdEd25519KeyStore,
      logger: console,
      isNode: true,
    });

    const limiterKind = parsePrfSealLimiterKind(env.PRF_SESSION_SEAL_RATE_LIMIT_KIND);
    const rateLimit = resolvePrfSessionSealRateLimitFromEnv({
      limiterKind,
      upstashUrl: env.UPSTASH_REDIS_REST_URL,
      upstashToken: env.UPSTASH_REDIS_REST_TOKEN,
      redisUrl: thresholdRedisUrl || redisUrl,
      keyPrefix: String(
        env.PRF_SESSION_SEAL_RATE_LIMIT_KEY_PREFIX || 'threshold:prf-seal:rate:',
      ).trim(),
      limit: parseOptionalPositiveInteger(env.PRF_SESSION_SEAL_RATE_LIMIT) || 30,
      windowMs: parseOptionalPositiveInteger(env.PRF_SESSION_SEAL_RATE_LIMIT_WINDOW_MS) || 60_000,
    });

    const idempotency = (() => {
      if (!postgresUrl) return undefined;
      const namespace = String(
        env.PRF_SESSION_SEAL_IDEMPOTENCY_NAMESPACE || 'threshold-prf-seal',
      ).trim();
      return {
        store: createPostgresPrfSessionSealIdempotencyStore({
          postgresUrl,
          namespace,
        }),
      };
    })();

    return createPrfSessionSealRoutesOptions({
      sessionPolicy: createPrfSessionSealPolicyFromEcdsaAuthSessionStore(ecdsaAuthSessionStore),
      cipher: createPrfSessionSealShamir3PassCipherAdapter({
        currentKeyVersion: keyVersion,
        keys: [
          {
            keyVersion,
            shamirPrimeB64u,
            serverEncryptExponentB64u,
            serverDecryptExponentB64u,
          },
        ],
      }),
      rateLimit,
      ...(idempotency ? { idempotency } : {}),
      requiredRequestKeyVersion: keyVersion,
      requiredRequestShamirPrimeB64u: shamirPrimeB64u,
      logger: console,
    });
  })();

  const app: Express = express();
  const consoleDevToken = String(env.CONSOLE_DEV_TOKEN || 'dev-console-token').trim();
  const rawConsoleBillingBackend = String(
    env.CONSOLE_BILLING_BACKEND || (postgresUrl ? 'postgres' : 'memory'),
  )
    .trim()
    .toLowerCase();
  if (rawConsoleBillingBackend !== 'postgres' && rawConsoleBillingBackend !== 'memory') {
    throw new Error(
      `Invalid CONSOLE_BILLING_BACKEND="${rawConsoleBillingBackend}". Expected "postgres" or "memory".`,
    );
  }
  const consoleBillingBackend: 'postgres' | 'memory' = rawConsoleBillingBackend;
  const consoleBillingNamespace = String(env.CONSOLE_BILLING_NAMESPACE || 'relay-console').trim();
  const rawConsoleWebhooksBackend = String(
    env.CONSOLE_WEBHOOKS_BACKEND || (postgresUrl ? 'postgres' : 'memory'),
  )
    .trim()
    .toLowerCase();
  if (rawConsoleWebhooksBackend !== 'postgres' && rawConsoleWebhooksBackend !== 'memory') {
    throw new Error(
      `Invalid CONSOLE_WEBHOOKS_BACKEND="${rawConsoleWebhooksBackend}". Expected "postgres" or "memory".`,
    );
  }
  const consoleWebhooksBackend: 'postgres' | 'memory' = rawConsoleWebhooksBackend;
  const consoleWebhooksNamespace = String(env.CONSOLE_WEBHOOKS_NAMESPACE || 'relay-console').trim();
  const consoleAuth: ConsoleAuthAdapter = {
    authenticate: async (headers) => {
      const authHeader = String(headers.authorization || headers.Authorization || '').trim();
      const bearerPrefix = 'Bearer ';
      const token = authHeader.startsWith(bearerPrefix)
        ? authHeader.slice(bearerPrefix.length).trim()
        : '';
      if (!token || token !== consoleDevToken) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Missing or invalid console bearer token',
          status: 401,
        };
      }

      const rawOrgId = String(headers['x-console-org-id'] || '').trim();
      const rawUserId = String(headers['x-console-user-id'] || '').trim();
      const rawRoles = String(headers['x-console-roles'] || 'admin').trim();
      const roles = rawRoles
        .split(',')
        .map((entry) => entry.trim())
        .filter(Boolean);

      return {
        ok: true,
        claims: {
          orgId: rawOrgId || 'org-dev',
          userId: rawUserId || 'console-admin',
          roles: roles.length ? roles : ['admin'],
        },
      };
    },
  };
  let consoleBilling: ConsoleBillingService;
  let consoleWebhooks: ConsoleWebhookService;
  if (consoleBillingBackend === 'postgres') {
    if (!postgresUrl) {
      throw new Error('CONSOLE_BILLING_BACKEND=postgres requires POSTGRES_URL');
    }
    consoleBilling = await createPostgresConsoleBillingService({
      postgresUrl,
      namespace: consoleBillingNamespace,
      logger: console as any,
      ensureSchema: true,
    });
  } else {
    consoleBilling = createInMemoryConsoleBillingService();
  }

  if (consoleWebhooksBackend === 'postgres') {
    if (!postgresUrl) {
      throw new Error('CONSOLE_WEBHOOKS_BACKEND=postgres requires POSTGRES_URL');
    }
    consoleWebhooks = await createPostgresConsoleWebhookService({
      postgresUrl,
      namespace: consoleWebhooksNamespace,
      logger: console as any,
      ensureSchema: true,
    });
  } else {
    consoleWebhooks = createInMemoryConsoleWebhookService();
  }

  app.use((_req, res, next) => {
    res.setHeader('referrer-policy', 'no-referrer');
    res.setHeader('permissions-policy', 'geolocation=(), microphone=(), camera=()');
    next();
  });

  app.use(express.json({ limit: '1mb' }));

  // Mount router built from AuthService
  app.use(
    '/',
    createRelayRouter(authService, {
      healthz: true,
      readyz: true,
      corsOrigins: [config.expectedOrigin, config.expectedWalletOrigin],
      ...(rorRpId
        ? {
            ror: {
              rpId: rorRpId,
              provider: {
                getAllowedOrigins: async (input: { rpId: string; host?: string }) =>
                  input.rpId === rorRpId ? rorOrigins : [],
              },
            },
          }
        : {}),
      signedDelegate: { route: '/signed-delegate' },
      session: jwtSession,
      threshold,
      prfSessionSeal,
      logger: console,
    }),
  );

  // Mount console/admin router on /console/*
  app.use(
    '/',
    createConsoleRouter({
      healthz: true,
      readyz: true,
      corsOrigins: [config.expectedOrigin, config.expectedWalletOrigin],
      auth: consoleAuth,
      billing: consoleBilling,
      webhooks: consoleWebhooks,
      logger: console,
    }),
  );

  const onListening = () => {
    const listenHost = config.host || 'localhost';
    console.log(`Server listening on http://${listenHost}:${config.port}`);
    console.log(`Expected Frontend Origin: ${config.expectedOrigin}`);
    if (rorRpId) {
      console.log(`ROR RP ID: ${rorRpId}`);
      console.log(`ROR Origins: ${rorOrigins.join(', ') || '(none)'}`);
    }
    console.log(`PRF session seal routes: ${prfSessionSealEnabled ? 'enabled' : 'disabled'}`);
    console.log(`Console dev token: ${consoleDevToken}`);
    console.log('Console routes mounted at /console/*');
    console.log(`Console billing backend: ${consoleBillingBackend}`);
    if (consoleBillingBackend === 'postgres') {
      console.log(`Console billing namespace: ${consoleBillingNamespace}`);
    }
    console.log(`Console webhooks backend: ${consoleWebhooksBackend}`);
    if (consoleWebhooksBackend === 'postgres') {
      console.log(`Console webhooks namespace: ${consoleWebhooksNamespace}`);
    }
    authService
      .getRelayerAccount()
      .then((relayer) =>
        console.log(`AuthService started with relayer account: ${relayer.accountId}`),
      )
      .catch((err: Error) => console.error('AuthService initial check failed:', err));
  };

  server = config.host
    ? app.listen(config.port, config.host, onListening)
    : app.listen(config.port, onListening);
}

main().catch((err) => {
  console.error('[relay-server] fatal startup error:', err);
  process.exit(1);
});
