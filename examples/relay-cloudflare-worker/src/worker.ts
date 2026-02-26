import { AuthService } from '@tatchi-xyz/sdk/server';
import {
  createCloudflareCron,
  createCloudflareEmailHandler,
  createCloudflareRouter,
} from '@tatchi-xyz/sdk/server/router/cloudflare';
import type {
  CfEmailMessage,
  CfScheduledEvent,
  CfExecutionContext as Ctx,
  RelayCloudflareWorkerEnv,
} from '@tatchi-xyz/sdk/server/router/cloudflare';
import signerWasmModule from '@tatchi-xyz/sdk/server/wasm/signer';
import shamirWasmModule from '@tatchi-xyz/sdk/server/wasm/signer';
import jwtSession from './jwtSession';

export { ThresholdEd25519StoreDurableObject } from '@tatchi-xyz/sdk/server/router/cloudflare';

type Env = RelayCloudflareWorkerEnv & {
  // base env vars
  RELAYER_ACCOUNT_ID: string;
  RELAYER_PRIVATE_KEY: string;
  NEAR_RPC_URL?: string;
  NETWORK_ID?: string;
  ROR_RP_ID?: string;
  ROR_ALLOWED_ORIGINS?: string;
  ACCOUNT_INITIAL_BALANCE?: string;
  CREATE_ACCOUNT_AND_REGISTER_GAS?: string;
  SHAMIR_P_B64U: string;
  SHAMIR_E_S_B64U: string;
  SHAMIR_D_S_B64U: string;
  EXPECTED_ORIGIN?: string;
  EXPECTED_WALLET_ORIGIN?: string;
  ENABLE_ROTATION?: string;
  BILLING_FINALIZATION_ENABLED?: string;
  BILLING_POSTGRES_URL?: string;
  BILLING_NAMESPACE?: string;
  BILLING_FINALIZATION_PERIOD_MONTH_UTC?: string;
  RECOVER_EMAIL_RECIPIENT?: string;
  GOOGLE_OIDC_CLIENT_ID?: string;
  GOOGLE_OIDC_CLIENT_IDS?: string;
  GOOGLE_OIDC_HOSTED_DOMAINS?: string;

  // Threshold signing (optional)
  THRESHOLD_ED25519_MASTER_SECRET_B64U?: string;
  THRESHOLD_ED25519_SHARE_MODE?: string;
  THRESHOLD_PREFIX?: string;

  // Durable Object binding for threshold state
  THRESHOLD_STORE: {
    idFromName(name: string): unknown;
    get(id: unknown): { fetch(input: RequestInfo, init?: RequestInit): Promise<Response> };
  };
};

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

function createAuthService(env: Env): AuthService {
  return new AuthService({
    relayerAccount: env.RELAYER_ACCOUNT_ID,
    relayerPrivateKey: env.RELAYER_PRIVATE_KEY,
    nearRpcUrl: env.NEAR_RPC_URL,
    networkId: env.NETWORK_ID,
    accountInitialBalance: env.ACCOUNT_INITIAL_BALANCE,
    createAccountAndRegisterGas: env.CREATE_ACCOUNT_AND_REGISTER_GAS,
    googleOidc: {
      GOOGLE_OIDC_CLIENT_ID: env.GOOGLE_OIDC_CLIENT_ID,
      GOOGLE_OIDC_CLIENT_IDS: env.GOOGLE_OIDC_CLIENT_IDS,
      GOOGLE_OIDC_HOSTED_DOMAINS: env.GOOGLE_OIDC_HOSTED_DOMAINS,
    },
    thresholdEd25519KeyStore: {
      kind: 'cloudflare-do',
      namespace: env.THRESHOLD_STORE,
      name: 'threshold-ed25519-store',
      THRESHOLD_PREFIX: env.THRESHOLD_PREFIX,
      THRESHOLD_ED25519_SHARE_MODE: env.THRESHOLD_ED25519_SHARE_MODE,
      THRESHOLD_ED25519_MASTER_SECRET_B64U: env.THRESHOLD_ED25519_MASTER_SECRET_B64U,
    },
    shamir: {
      SHAMIR_P_B64U: env.SHAMIR_P_B64U,
      SHAMIR_E_S_B64U: env.SHAMIR_E_S_B64U,
      SHAMIR_D_S_B64U: env.SHAMIR_D_S_B64U,
      graceShamirKeysFile: '', // Do not use FS on Workers
      moduleOrPath: shamirWasmModule, // Pass WASM module for Cloudflare Workers
    },
    signerWasm: {
      moduleOrPath: signerWasmModule, // Pass WASM module for Cloudflare Workers
    },
  });
}

export default {
  /**
   * HTTP entrypoint
   * - Handles REST API routes (/registration/bootstrap, /recover-email, sessions, etc.)
   * - Creates an AuthService per request/event (avoid cross-request I/O errors).
   */
  async fetch(request: Request, env: Env, ctx: Ctx): Promise<Response> {
    const authService = createAuthService(env);
    const expectedOrigin = String(env.EXPECTED_ORIGIN || '').trim();
    const expectedWalletOrigin = String(env.EXPECTED_WALLET_ORIGIN || '').trim();
    const rorRpId = String(env.ROR_RP_ID || hostnameFromOrigin(expectedWalletOrigin)).trim().toLowerCase();
    const rorOrigins = sanitizeOrigins([
      expectedOrigin,
      expectedWalletOrigin,
      ...String(env.ROR_ALLOWED_ORIGINS || '')
        .split(',')
        .map((s) => s.trim())
        .filter(Boolean),
    ]);
    const router = createCloudflareRouter(authService, {
      healthz: true,
      readyz: true,
      // Pass raw env strings; router normalizes CSV/duplicates internally
      corsOrigins: [env.EXPECTED_ORIGIN, env.EXPECTED_WALLET_ORIGIN],
      ...(rorRpId
        ? {
            ror: {
              rpId: rorRpId,
              provider: {
                getAllowedOrigins: async (input: { rpId: string; host?: string }) => (
                  input.rpId === rorRpId ? rorOrigins : []
                ),
              },
            },
          }
        : {}),
      signedDelegate: { route: '/signed-delegate' },
      session: jwtSession,
    });
    return router(request, env, ctx);
  },

  /**
   * Cron entrypoint
   * - Used for optional Shamir key rotation and health heartbeats.
   * - Activated when ENABLE_ROTATION='1' and a cron schedule is configured.
   */
  async scheduled(event: CfScheduledEvent, env: Env, ctx: Ctx) {
    const authService = createAuthService(env);
    const enabled = env.ENABLE_ROTATION === '1';
    const billingFinalizationEnabled = env.BILLING_FINALIZATION_ENABLED === '1';
    const cron = createCloudflareCron(authService, {
      enabled,
      rotate: enabled,
      billingMonthlyFinalization: billingFinalizationEnabled
        ? {
            enabled: true,
            postgresUrl: env.BILLING_POSTGRES_URL,
            namespace: env.BILLING_NAMESPACE,
            periodMonthUtc: env.BILLING_FINALIZATION_PERIOD_MONTH_UTC,
          }
        : undefined,
    });
    await cron(event, env, ctx);
  },

  /**
   * Email entrypoint
   * - Invoked by Cloudflare Email Routing for incoming messages to RECOVER_EMAIL_RECIPIENT.
   * - Normalizes headers/raw body, parses accountId from Subject/headers,
   *   and calls AuthService.emailRecovery for encrypted DKIM/TEE-based recovery.
   */
  async email(message: CfEmailMessage, env: Env, ctx: Ctx): Promise<void> {
    const authService = createAuthService(env);
    const handler = createCloudflareEmailHandler(authService, {
      expectedRecipient: env.RECOVER_EMAIL_RECIPIENT,
      verbose: true,
      logger: console,
    });
    await handler(message, env, ctx);
  }
};
