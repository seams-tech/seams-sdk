import type { CloudflareDurableObjectNamespaceLike } from '../../core/types';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import {
  resolveSponsoredEvmCallConfigFromWorkerEnv,
  resolveSponsoredEvmWorkerExecutionAdapter,
} from '../../sponsorship/evmWorkerExecutionAdapter';
import { createCloudflareRouter } from './createCloudflareRouter';
import { createCloudflareD1ConsoleServiceBundle } from './d1ConsoleServices';
import type { CloudflareD1EmailOtpServerSealConfig } from './d1RouterApiAuthConfig';
import { createCloudflareD1RouterApiAuthService } from './d1RouterApiAuthService';
import type { ThresholdStoreConfigInput } from '../../core/types';
import { createSigningSessionSealOptions } from '../../threshold/session/signingSessionSeal/options';
import type { SigningSessionSealRoutesOptions } from '../../threshold/session/signingSessionSeal/signingSessionSeal.types';
import type {
  CloudflareD1OidcExchangeConfig,
  CloudflareD1OidcExchangeIssuerConfig,
} from './d1OidcBoundary';
import type { CfExecutionContext, FetchHandler } from './cloudflare.types';
import { ThresholdStoreDurableObject } from './durableObjects/thresholdStore';
import {
  createCloudflareSecretsStoreKekProviderFromEnv,
  createHmacSessionAdapterFromEnv,
  readCsvList,
  readEnvString,
  requireEnvString,
  type CloudflareD1StagingSecretEnv,
  type CloudflareD1StagingSessionEnv,
} from './d1StagingSession';

export { ThresholdStoreDurableObject };

interface CloudflareD1RouterApiStagingEnv
  extends CloudflareD1StagingSecretEnv,
    CloudflareD1StagingSessionEnv {
  readonly CONSOLE_DB: D1DatabaseLike;
  readonly SIGNER_DB: D1DatabaseLike;
  readonly THRESHOLD_STORE: CloudflareDurableObjectNamespaceLike;
  readonly SEAMS_TENANT_STORAGE_NAMESPACE?: string;
  readonly SEAMS_STAGING_ORG_ID?: string;
  readonly SEAMS_STAGING_PROJECT_ID?: string;
  readonly SEAMS_STAGING_ENV_ID?: string;
  readonly RELAY_SESSION_HMAC_SECRET?: string;
  readonly SESSION_COOKIE_NAME?: string;
  readonly RELAY_SESSION_ISSUER?: string;
  readonly RELAY_SESSION_AUDIENCE?: string;
  readonly RELAY_CORS_ORIGINS?: string;
  readonly RELAYER_ACCOUNT_ID?: string;
  readonly RELAYER_PUBLIC_KEY?: string;
  readonly RELAYER_PRIVATE_KEY?: string;
  readonly NEAR_RPC_URL?: string;
  readonly ACCOUNT_INITIAL_BALANCE?: string;
  readonly ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING?: string;
  readonly GOOGLE_OIDC_CLIENT_ID?: string;
  readonly SEAMS_OIDC_EXCHANGE_JSON?: string;
  readonly ACCOUNT_ID_DERIVATION_SECRET?: string;
  readonly ROUTER_AB_NORMAL_SIGNING_WORKER_ID?: string;
  readonly SIGNING_SESSION_SEAL_KEY_VERSION?: string;
  readonly SIGNING_SESSION_SHAMIR_P_B64U?: string;
  readonly SIGNING_SESSION_SEAL_E_S_B64U?: string;
  readonly SIGNING_SESSION_SEAL_D_S_B64U?: string;
  readonly EMAIL_OTP_DELIVERY_MODE?: string;
  readonly EMAIL_OTP_PRODUCTION?: string;
  readonly EMAIL_OTP_DEV_OUTBOX_ENABLED?: string;
  readonly EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX?: string;
  readonly EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS?: string;
  readonly EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX?: string;
  readonly EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS?: string;
  readonly SPONSORED_EVM_EXECUTORS_JSON?: string;
}

type RouterApiReadyRow = {
  readonly table_count?: unknown;
};

const RELAY_CONSOLE_READY_TABLES = Object.freeze([
  'organizations',
  'projects',
  'environments',
  'api_keys',
  'billing_accounts',
  'billing_prepaid_reservations',
  'sponsorship_spend_cap_reservations',
  'sponsorship_pricing_rules',
  'sponsored_call_records',
]);
const RELAY_SIGNER_READY_TABLES = Object.freeze([
  'wallets',
  'wallet_auth_methods',
  'app_session_versions',
  'email_otp_challenges',
  'email_otp_grants',
  'signing_root_secret_shares',
]);

async function createRouterApiHandler(env: CloudflareD1RouterApiStagingEnv): Promise<FetchHandler> {
  const namespace = requireEnvString(env, 'SEAMS_TENANT_STORAGE_NAMESPACE');
  const sponsoredEvmCallConfig = await resolveSponsoredEvmCallConfigFromWorkerEnv(env);
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: env.CONSOLE_DB,
      signerMetadataDatabase: env.SIGNER_DB,
      thresholdStore: env.THRESHOLD_STORE,
      kekProvider: createCloudflareSecretsStoreKekProviderFromEnv(env),
    },
    route: {
      namespace,
    },
    adapters: {
      ensureSchema: false,
      sponsoredEvmCallConfig,
    },
  });
  const thresholdStoreConfig = stagingThresholdStoreConfig(env, namespace);
  const service = createCloudflareD1RouterApiAuthService({
    database: env.SIGNER_DB,
    namespace,
    orgId: requireEnvString(env, 'SEAMS_STAGING_ORG_ID'),
    projectId: requireEnvString(env, 'SEAMS_STAGING_PROJECT_ID'),
    envId: requireEnvString(env, 'SEAMS_STAGING_ENV_ID'),
    relayerAccount: readEnvString(env, 'RELAYER_ACCOUNT_ID'),
    relayerPublicKey: readEnvString(env, 'RELAYER_PUBLIC_KEY'),
    relayerPrivateKey: readEnvString(env, 'RELAYER_PRIVATE_KEY'),
    nearRpcUrl: readEnvString(env, 'NEAR_RPC_URL'),
    accountInitialBalance: readEnvString(env, 'ACCOUNT_INITIAL_BALANCE'),
    implicitNearAccountTestFundingEnabled: readEnvString(
      env,
      'ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING',
    ),
    googleOidcClientId: readEnvString(env, 'GOOGLE_OIDC_CLIENT_ID'),
    oidcExchange: stagingOidcExchangeConfig(env),
    accountIdDerivationSecret: requireEnvString(env, 'ACCOUNT_ID_DERIVATION_SECRET'),
    emailOtpServerSeal: stagingEmailOtpServerSealConfig(env),
    emailOtpDeliveryMode: readEnvString(env, 'EMAIL_OTP_DELIVERY_MODE'),
    emailOtpProduction: readEnvString(env, 'EMAIL_OTP_PRODUCTION'),
    emailOtpDevOutboxEnabled: readEnvString(env, 'EMAIL_OTP_DEV_OUTBOX_ENABLED'),
    emailOtpRecoveryKeyAttemptRateLimitMax: readEnvString(
      env,
      'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX',
    ),
    emailOtpRecoveryKeyAttemptRateLimitWindowMs: readEnvString(
      env,
      'EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS',
    ),
    emailOtpGoogleRegistrationAttemptRateLimitMax: readEnvString(
      env,
      'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX',
    ),
    emailOtpGoogleRegistrationAttemptRateLimitWindowMs: readEnvString(
      env,
      'EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS',
    ),
    thresholdStore: thresholdStoreConfig,
  });
  const sponsoredEvmCall = bundle.routerApiRouterOptions.sponsoredEvmCall
    ? {
        ...bundle.routerApiRouterOptions.sponsoredEvmCall,
        resolveExecutionAdapter: resolveSponsoredEvmWorkerExecutionAdapter,
      }
    : undefined;
  const session = createHmacSessionAdapterFromEnv({
    env,
    secretName: 'RELAY_SESSION_HMAC_SECRET',
    cookieName: readEnvString(env, 'SESSION_COOKIE_NAME'),
    issuer: readEnvString(env, 'RELAY_SESSION_ISSUER'),
    audience: readEnvString(env, 'RELAY_SESSION_AUDIENCE'),
  });
  return createCloudflareRouter(service, {
    ...bundle.routerApiRouterOptions,
    healthz: true,
    readyz: true,
    corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS),
    session,
    sessionCookieName: readEnvString(env, 'SESSION_COOKIE_NAME'),
    readyCheck: createRouterApiReadyCheck(env),
    ed25519RegistrationPrepare: { authService: service },
    signingSessionSeal: stagingSigningSessionSealOptions(env, thresholdStoreConfig),
    ...(sponsoredEvmCall ? { sponsoredEvmCall } : {}),
  });
}

function stagingThresholdStoreConfig(
  env: CloudflareD1RouterApiStagingEnv,
  namespace: string,
): ThresholdStoreConfigInput {
  return {
    kind: 'cloudflare-do',
    namespace: env.THRESHOLD_STORE,
    THRESHOLD_PREFIX: namespace,
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: requireEnvString(
      env,
      'ROUTER_AB_NORMAL_SIGNING_WORKER_ID',
    ),
  };
}

function stagingSigningSessionSealOptions(
  env: CloudflareD1RouterApiStagingEnv,
  thresholdStoreConfig: ThresholdStoreConfigInput,
): SigningSessionSealRoutesOptions | undefined {
  const seal = stagingEmailOtpServerSealConfig(env);
  if (!seal) return undefined;
  return createSigningSessionSealOptions({
    keyVersion: seal.keyVersion,
    shamirPrimeB64u: seal.shamirPrimeB64u,
    serverEncryptExponentB64u: seal.serverEncryptExponentB64u,
    serverDecryptExponentB64u: seal.serverDecryptExponentB64u,
    thresholdStoreConfig,
  });
}


function routerApiHandler(env: CloudflareD1RouterApiStagingEnv): Promise<FetchHandler> {
  return createRouterApiHandler(env);
}

function createRouterApiReadyCheck(env: CloudflareD1RouterApiStagingEnv): () => Promise<void> {
  const check = new RouterApiStagingReadyCheck(env);
  return check.check.bind(check);
}

class RouterApiStagingReadyCheck {
  constructor(private readonly env: CloudflareD1RouterApiStagingEnv) {}

  async check(): Promise<void> {
    await assertD1Tables({
      database: this.env.CONSOLE_DB,
      label: 'CONSOLE_DB',
      tables: RELAY_CONSOLE_READY_TABLES,
    });
    await assertD1Tables({
      database: this.env.SIGNER_DB,
      label: 'SIGNER_DB',
      tables: RELAY_SIGNER_READY_TABLES,
    });
    this.env.THRESHOLD_STORE.idFromName('seams-d1-relay-staging-readyz');
  }
}

async function assertD1Tables(input: {
  readonly database: D1DatabaseLike;
  readonly label: string;
  readonly tables: readonly string[];
}): Promise<void> {
  const row = await input.database
    .prepare(
      `SELECT COUNT(*) AS table_count
         FROM sqlite_master
        WHERE type = 'table'
          AND name IN (${d1StringList(input.tables)})`,
    )
    .first<RouterApiReadyRow>();
  const count = Number(row?.table_count || 0);
  if (count !== input.tables.length) {
    throw new Error(
      `${input.label} migration has created ${count} of ${input.tables.length} staging-ready tables`,
    );
  }
}

function stagingEmailOtpServerSealConfig(
  env: CloudflareD1RouterApiStagingEnv,
): CloudflareD1EmailOtpServerSealConfig | undefined {
  const keyVersion = readEnvString(env, 'SIGNING_SESSION_SEAL_KEY_VERSION');
  const shamirPrimeB64u = readEnvString(env, 'SIGNING_SESSION_SHAMIR_P_B64U');
  const serverEncryptExponentB64u = readEnvString(env, 'SIGNING_SESSION_SEAL_E_S_B64U');
  const serverDecryptExponentB64u = readEnvString(env, 'SIGNING_SESSION_SEAL_D_S_B64U');
  if (
    !keyVersion &&
    !shamirPrimeB64u &&
    !serverEncryptExponentB64u &&
    !serverDecryptExponentB64u
  ) {
    return undefined;
  }
  if (
    !keyVersion ||
    !shamirPrimeB64u ||
    !serverEncryptExponentB64u ||
    !serverDecryptExponentB64u
  ) {
    throw new Error(
      'Email OTP server seal requires SIGNING_SESSION_SEAL_KEY_VERSION, SIGNING_SESSION_SHAMIR_P_B64U, SIGNING_SESSION_SEAL_E_S_B64U, and SIGNING_SESSION_SEAL_D_S_B64U',
    );
  }
  return {
    keyVersion,
    shamirPrimeB64u,
    serverEncryptExponentB64u,
    serverDecryptExponentB64u,
  };
}

function stagingOidcExchangeConfig(
  env: CloudflareD1RouterApiStagingEnv,
): CloudflareD1OidcExchangeConfig | undefined {
  const source = readEnvString(env, 'SEAMS_OIDC_EXCHANGE_JSON');
  if (!source) return undefined;
  const parsed = parseJsonObject(source);
  if (!parsed) throw new Error('SEAMS_OIDC_EXCHANGE_JSON must be a JSON object');
  const issuers = parseOidcExchangeIssuers(parsed.issuers);
  if (issuers.length === 0) {
    throw new Error('SEAMS_OIDC_EXCHANGE_JSON must define at least one OIDC issuer');
  }
  const clockSkewSec = parseOptionalClockSkewSec(parsed.clockSkewSec);
  return {
    issuers,
    ...(clockSkewSec === undefined ? {} : { clockSkewSec }),
  };
}

function parseOptionalClockSkewSec(input: unknown): string | number | undefined {
  if (typeof input === 'number' && Number.isFinite(input)) return input;
  const value = normalizeString(input);
  return value || undefined;
}

function parseOidcExchangeIssuers(input: unknown): CloudflareD1OidcExchangeIssuerConfig[] {
  if (!Array.isArray(input)) return [];
  const issuers: CloudflareD1OidcExchangeIssuerConfig[] = [];
  for (const raw of input) {
    const issuer = parseOidcExchangeIssuer(raw);
    if (issuer) issuers.push(issuer);
  }
  return issuers;
}

function parseOidcExchangeIssuer(
  input: unknown,
): CloudflareD1OidcExchangeIssuerConfig | null {
  if (!isRecord(input)) return null;
  const issuer = normalizeString(input.issuer);
  const jwksUrl = normalizeString(input.jwksUrl);
  const audiences = parseStringArray(input.audiences);
  const subjectPrefix = normalizeString(input.subjectPrefix);
  if (!issuer || !jwksUrl || audiences.length === 0) return null;
  return {
    issuer,
    jwksUrl,
    audiences,
    ...(subjectPrefix ? { subjectPrefix } : {}),
  };
}

function parseStringArray(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const raw of input) {
    const value = normalizeString(raw);
    if (!value || seen.has(value)) continue;
    out.push(value);
    seen.add(value);
  }
  return out;
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  return isRecord(parsed) ? parsed : null;
}

function isRecord(input: unknown): input is Record<string, unknown> {
  return typeof input === 'object' && input !== null && !Array.isArray(input);
}

function d1StringList(values: readonly string[]): string {
  return values.map(d1StringLiteral).join(', ');
}

function d1StringLiteral(value: string): string {
  if (!/^[a-z0-9_]+$/.test(value)) {
    throw new Error(`invalid D1 table name ${value}`);
  }
  return `'${value}'`;
}

function normalizeString(input: unknown): string {
  return String(input || '').trim();
}

async function fetch(
  request: Request,
  env: CloudflareD1RouterApiStagingEnv,
  ctx: CfExecutionContext,
): Promise<Response> {
  const handler = await routerApiHandler(env);
  return await handler(request, env, ctx);
}

export default { fetch };
