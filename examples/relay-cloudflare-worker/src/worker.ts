import {
  AuthService,
  createPrfSessionSealOptions,
  createRorOptions,
  type ThresholdEd25519KeyStoreConfigInput,
} from '@tatchi-xyz/sdk/server';
import {
  createCloudflareEmailHandler,
  createCloudflareRouter,
  createInMemoryRelayRuntimeSnapshotConsumer,
} from '@tatchi-xyz/sdk/server/router/cloudflare';
import type {
  CfEmailMessage,
  CfScheduledEvent,
  CfExecutionContext as Ctx,
  RelayCloudflareWorkerEnv,
} from '@tatchi-xyz/sdk/server/router/cloudflare';
import signerWasmModule from '@tatchi-xyz/sdk/server/wasm/signer';
import { createJwtSession } from './jwtSession';
import { createWorkerCronObservabilityIngestion } from './observability';
import { createWorkerScheduledHandler } from './scheduledHandler';

export { ThresholdEd25519StoreDurableObject } from '@tatchi-xyz/sdk/server/router/cloudflare';

type Env = RelayCloudflareWorkerEnv & {
  // base env vars
  RELAYER_ACCOUNT_ID: string;
  RELAYER_PRIVATE_KEY: string;
  NEAR_RPC_URL?: string;
  NETWORK_ID?: string;
  ROR_RP_ID?: string;
  ROR_ALLOWED_ORIGINS?: string;
  SESSION_COOKIE_NAME?: string;
  ACCOUNT_INITIAL_BALANCE?: string;
  CREATE_ACCOUNT_AND_REGISTER_GAS?: string;
  SHAMIR_P_B64U: string;
  SHAMIR_E_S_B64U: string;
  SHAMIR_D_S_B64U: string;
  PRF_SESSION_SEAL_ENABLED?: string;
  PRF_SESSION_SEAL_KEY_VERSION?: string;
  EXPECTED_ORIGIN?: string;
  EXPECTED_WALLET_ORIGIN?: string;
  ENABLE_ROTATION?: string;
  BILLING_FINALIZATION_ENABLED?: string;
  BILLING_POSTGRES_URL?: string;
  BILLING_NAMESPACE?: string;
  BILLING_FINALIZATION_PERIOD_MONTH_UTC?: string;
  BILLING_FINALIZATION_ORG_IDS?: string;
  BILLING_FINALIZATION_CRONS?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ENABLED?: string;
  RUNTIME_SNAPSHOT_OUTBOX_POSTGRES_URL?: string;
  RUNTIME_SNAPSHOT_OUTBOX_NAMESPACE?: string;
  RUNTIME_SNAPSHOT_OUTBOX_ORG_IDS?: string;
  RUNTIME_SNAPSHOT_OUTBOX_LIMIT?: string;
  RUNTIME_SNAPSHOT_OUTBOX_CRONS?: string;
  WEBHOOK_RETRY_ENABLED?: string;
  WEBHOOK_RETRY_POSTGRES_URL?: string;
  WEBHOOK_RETRY_NAMESPACE?: string;
  WEBHOOK_RETRY_ORG_IDS?: string;
  WEBHOOK_RETRY_LIMIT?: string;
  WEBHOOK_RETRY_CRONS?: string;
  WEBHOOK_RETRY_MAX_ATTEMPTS?: string;
  WEBHOOK_RETRY_INITIAL_BACKOFF_MS?: string;
  WEBHOOK_RETRY_MAX_BACKOFF_MS?: string;
  RECOVERY_AUTHORITY_CONTINUATION_ENABLED?: string;
  RECOVERY_AUTHORITY_CONTINUATION_CRONS?: string;
  RECOVERY_AUTHORITY_CONTINUATION_LIMIT?: string;
  SPONSORED_EVM_EXECUTORS_JSON?: string;
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

function createThresholdKeyStoreConfig(env: Env): ThresholdEd25519KeyStoreConfigInput {
  return {
    kind: 'cloudflare-do' as const,
    namespace: env.THRESHOLD_STORE,
    name: 'threshold-ed25519-store',
    THRESHOLD_PREFIX: env.THRESHOLD_PREFIX,
    THRESHOLD_ED25519_SHARE_MODE: env.THRESHOLD_ED25519_SHARE_MODE,
    THRESHOLD_ED25519_MASTER_SECRET_B64U: env.THRESHOLD_ED25519_MASTER_SECRET_B64U,
  };
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
    thresholdEd25519KeyStore: createThresholdKeyStoreConfig(env),
    signerWasm: {
      moduleOrPath: signerWasmModule, // Pass WASM module for Cloudflare Workers
    },
  });
}

const runtimeSnapshotCache = createInMemoryRelayRuntimeSnapshotConsumer();
const scheduledHandler = createWorkerScheduledHandler<Env>({
  createAuthService,
  createObservabilityIngestion: createWorkerCronObservabilityIngestion,
  outboxSink: runtimeSnapshotCache,
});

export default {
  /**
   * HTTP entrypoint
   * - Handles REST API routes (/registration/bootstrap, /recover-email, sessions, etc.)
   * - Creates an AuthService per request/event (avoid cross-request I/O errors).
   */
  async fetch(request: Request, env: Env, ctx: Ctx): Promise<Response> {
    const authService = createAuthService(env);
    const sessionCookieName =
      String(env.SESSION_COOKIE_NAME || 'tatchi-jwt').trim() || 'tatchi-jwt';
    const jwtSession = createJwtSession(sessionCookieName);
    const prfSessionSeal = createPrfSessionSealOptions({
      enabled: env.PRF_SESSION_SEAL_ENABLED,
      keyVersion: env.PRF_SESSION_SEAL_KEY_VERSION,
      shamirPrimeB64u: env.SHAMIR_P_B64U,
      serverEncryptExponentB64u: env.SHAMIR_E_S_B64U,
      serverDecryptExponentB64u: env.SHAMIR_D_S_B64U,
      thresholdKeyStoreConfig: createThresholdKeyStoreConfig(env),
    });
    const router = createCloudflareRouter(authService, {
      healthz: true,
      readyz: true,
      logger: console,
      // Pass raw env strings; router normalizes CSV/duplicates internally
      corsOrigins: [env.EXPECTED_ORIGIN, env.EXPECTED_WALLET_ORIGIN],
      ror: createRorOptions({
        expectedOrigin: env.EXPECTED_ORIGIN,
        expectedWalletOrigin: env.EXPECTED_WALLET_ORIGIN,
        rorRpId: env.ROR_RP_ID,
        rorAllowedOrigins: env.ROR_ALLOWED_ORIGINS,
      }),
      session: jwtSession,
      sessionCookieName,
      runtimeSnapshots: runtimeSnapshotCache.runtimeSnapshots,
      prfSessionSeal,
    });
    return router(request, env, ctx);
  },

  /**
   * Cron entrypoint
   * - Used for optional Shamir key rotation and console operations jobs.
   * - Activated when at least one cron feature flag is enabled.
   */
  async scheduled(event: CfScheduledEvent, env: Env, ctx: Ctx) {
    await scheduledHandler(event, env, ctx);
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
  },
};
