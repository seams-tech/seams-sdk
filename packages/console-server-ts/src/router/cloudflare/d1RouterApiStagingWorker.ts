import type { CloudflareDurableObjectNamespaceLike } from '@seams/sdk-server/internal/core/types';
import type { D1DatabaseLike } from '@seams/sdk-server/internal/storage/tenantRoute';
import {
  resolveSponsoredEvmCallConfigFromWorkerEnv,
  resolveSponsoredEvmWorkerExecutionAdapter,
} from '@seams-internal/console-server/sponsorship/evmWorkerExecutionAdapter';
import { createCloudflareRouter } from '@seams/sdk-server/internal/router/cloudflare/createCloudflareRouter';
import { createCloudflareD1ConsoleServiceBundle } from './d1ConsoleServices';
import type { CloudflareD1EmailOtpServerSealConfig } from '@seams/sdk-server/internal/router/cloudflare/d1RouterApiAuthConfig';
import { createCloudflareD1RouterApiAuthService } from '@seams/sdk-server/internal/router/cloudflare/d1RouterApiAuthService';
import type { ThresholdStoreConfigInput } from '@seams/sdk-server/internal/core/types';
import { createSigningSessionSealOptions } from '@seams/sdk-server/internal/threshold/session/signingSessionSeal/options';
import type { SigningSessionSealRoutesOptions } from '@seams/sdk-server/internal/threshold/session/signingSessionSeal/signingSessionSeal.types';
import type {
  CloudflareD1OidcExchangeConfig,
  CloudflareD1OidcExchangeIssuerConfig,
} from '@seams/sdk-server/internal/router/cloudflare/d1OidcBoundary';
import type {
  CfExecutionContext,
  FetchHandler,
} from '@seams/sdk-server/internal/router/cloudflare/cloudflare.types';
import { ThresholdStoreDurableObject } from '@seams/sdk-server/internal/router/cloudflare/durableObjects/thresholdStore';
import { createRouterAbEd25519YaoHttpRegistrationBackendFromEnv } from '@seams/sdk-server/internal/router/routerAbEd25519YaoHttpRegistrationBackend';
import {
  createRouterAbEd25519YaoProductRegistrationStatefulCompositionV1,
  createRouterAbEd25519YaoProductRegistrationStateV1,
  parseRouterAbEd25519YaoProductRegistrationStateV1,
  type RouterAbEd25519YaoProductRegistrationCompositionV1,
  type RouterAbEd25519YaoProductRegistrationStateV1,
} from '@seams/sdk-server/internal/router/routerAbEd25519YaoProductRegistration';
import type { SessionAdapter } from '@seams/sdk-server/internal/router/routerApi';
import { D1WalletStore } from '@seams/sdk-server/internal/core/d1WalletStore';
import { CloudflareD1RouterAbEd25519YaoCapabilityPersistence } from '@seams/sdk-server/internal/router/cloudflare/d1Ed25519YaoCapabilityPersistence';
import { CloudflareD1WebAuthnAuthService } from '@seams/sdk-server/internal/router/cloudflare/d1WebAuthnAuthService';
import { CloudflareD1WebAuthnStore } from '@seams/sdk-server/internal/router/cloudflare/d1WebAuthnStore';
import {
  createRouterAbEcdsaEd25519CeremonyTokenIssuer,
  createRouterAbEcdsaStrictPostRegistrationPort,
  createRouterAbEcdsaStrictRegistrationPort,
  parseRouterAbEcdsaEd25519PrivateJwk,
  parseRouterAbEcdsaStrictRegistrationTopology,
  type RouterAbEcdsaCeremonyTokenIssuer,
  type RouterAbEcdsaStrictRegistrationTopology,
} from '@seams/sdk-server/internal/router/routerAbEcdsaStrictRegistration';
import {
  createCloudflareSecretsStoreKekProviderFromEnv,
  createHmacSessionAdapterFromEnv,
  readCsvList,
  readEnvString,
  requireEnvString,
  type CloudflareD1StagingSecretEnv,
  type CloudflareD1StagingSessionEnv,
} from './d1StagingSession';
import {
  parseRouterAbPublicKeysetV2,
  type RouterAbPublicKeysetV2,
} from '@seams-internal/shared-ts/utils/routerAbPublicKeyset';
import {
  createRouterAbServiceBindingFetch,
  ROUTER_AB_DERIVER_A_ORIGIN,
  ROUTER_AB_DERIVER_B_ORIGIN,
  ROUTER_AB_SIGNING_WORKER_ORIGIN,
  type RouterAbServiceBindingEnv,
} from './routerAbServiceBindings';

export { ThresholdStoreDurableObject };

interface CloudflareD1RouterApiStagingEnv
  extends CloudflareD1StagingSecretEnv, CloudflareD1StagingSessionEnv, RouterAbServiceBindingEnv {
  readonly CONSOLE_DB: D1DatabaseLike;
  readonly SIGNER_DB: D1DatabaseLike;
  readonly THRESHOLD_STORE: CloudflareDurableObjectNamespaceLike;
  readonly ROUTER_API_RUNTIME: CloudflareDurableObjectNamespaceLike;
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
  readonly SIGNING_WORKER_ID?: string;
  readonly ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET?: string;
  readonly ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK?: string;
  readonly ROUTER_AB_CEREMONY_JWT_ISSUER?: string;
  readonly ROUTER_AB_CEREMONY_JWT_AUDIENCE?: string;
  readonly ROUTER_AB_CEREMONY_JWT_KEY_ID?: string;
  readonly ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON?: string;
  readonly ROUTER_AB_PUBLIC_KEYSET_JSON?: string;
  readonly DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY?: string;
  readonly DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY?: string;
  readonly SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY?: string;
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

type RouterApiTenantScope = {
  readonly namespace: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly envId: string;
};

type RouterApiRuntimeDurableObjectStorage = {
  get(key: string): Promise<unknown>;
  put(key: string, value: unknown): Promise<void>;
};

type RouterApiRuntimeDurableObjectState = {
  readonly storage: RouterApiRuntimeDurableObjectStorage;
  blockConcurrencyWhile<T>(callback: () => Promise<T>): Promise<T>;
};

type RouterApiRuntimeContext = {
  readonly handler: FetchHandler;
  readonly yaoState: RouterAbEd25519YaoProductRegistrationStateV1;
};

const ROUTER_API_YAO_STATE_KEY = 'router-api:ed25519-yao-product-state:v1';

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

const ROUTER_AB_CEREMONY_JWKS_PATH = '/.well-known/router-ab-ceremony-jwks.json';

export function createStagingEd25519YaoBackend(env: CloudflareD1RouterApiStagingEnv) {
  return createRouterAbEd25519YaoHttpRegistrationBackendFromEnv({
    env: {
      DERIVER_A_URL: ROUTER_AB_DERIVER_A_ORIGIN,
      DERIVER_B_URL: ROUTER_AB_DERIVER_B_ORIGIN,
      SIGNING_WORKER_URL: ROUTER_AB_SIGNING_WORKER_ORIGIN,
      SIGNING_WORKER_ID: requireEnvString(env, 'SIGNING_WORKER_ID'),
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: requireEnvString(
        env,
        'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
      ),
      DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY: requireEnvString(
        env,
        'DERIVER_A_ED25519_YAO_INPUT_PUBLIC_KEY',
      ),
      DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY: requireEnvString(
        env,
        'DERIVER_B_ED25519_YAO_INPUT_PUBLIC_KEY',
      ),
      SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY: requireEnvString(
        env,
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
      ),
    },
    fetch: createRouterAbServiceBindingFetch(env),
  });
}

function stagingTenantScope(env: CloudflareD1RouterApiStagingEnv): RouterApiTenantScope {
  return {
    namespace: requireEnvString(env, 'SEAMS_TENANT_STORAGE_NAMESPACE'),
    orgId: requireEnvString(env, 'SEAMS_STAGING_ORG_ID'),
    projectId: requireEnvString(env, 'SEAMS_STAGING_PROJECT_ID'),
    envId: requireEnvString(env, 'SEAMS_STAGING_ENV_ID'),
  };
}

async function createStagingEd25519YaoComposition(
  env: CloudflareD1RouterApiStagingEnv,
  session: SessionAdapter,
  state: RouterAbEd25519YaoProductRegistrationStateV1,
): Promise<RouterAbEd25519YaoProductRegistrationCompositionV1> {
  const scope = stagingTenantScope(env);
  const walletStore = new D1WalletStore({
    database: env.SIGNER_DB,
    namespace: scope.namespace,
    orgId: scope.orgId,
    projectId: scope.projectId,
    envId: scope.envId,
    ensureSchema: false,
  });
  const composition = createRouterAbEd25519YaoProductRegistrationStatefulCompositionV1({
    signingWorkerId: requireEnvString(env, 'SIGNING_WORKER_ID'),
    backend: createStagingEd25519YaoBackend(env),
    session,
    webAuthn: new CloudflareD1WebAuthnAuthService({
      webAuthnStore: new CloudflareD1WebAuthnStore({
        database: env.SIGNER_DB,
        namespace: scope.namespace,
        orgId: scope.orgId,
        projectId: scope.projectId,
        envId: scope.envId,
      }),
    }),
    state,
    capabilityPersistence: new CloudflareD1RouterAbEd25519YaoCapabilityPersistence(walletStore),
  });
  const signers = await walletStore.listEd25519Signers();
  for (const signer of signers) {
    const installed = await composition.runtime.installPersistedActiveCapability(
      signer.activeYaoCapability,
    );
    if (!installed.ok) {
      throw new Error(
        `staging Ed25519 Yao capability hydration failed for ${signer.signerId}: ${installed.message}`,
      );
    }
  }
  return composition;
}

async function createRouterApiHandler(
  env: CloudflareD1RouterApiStagingEnv,
  yaoState: RouterAbEd25519YaoProductRegistrationStateV1,
): Promise<FetchHandler> {
  const scope = stagingTenantScope(env);
  const sponsoredEvmCallConfig = await resolveSponsoredEvmCallConfigFromWorkerEnv(env);
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: env.CONSOLE_DB,
      signerMetadataDatabase: env.SIGNER_DB,
      thresholdStore: env.THRESHOLD_STORE,
      kekProvider: createCloudflareSecretsStoreKekProviderFromEnv(env),
    },
    route: {
      namespace: scope.namespace,
    },
    adapters: {
      ensureSchema: false,
      sponsoredEvmCallConfig,
      resolveSponsoredEvmExecutionAdapter: resolveSponsoredEvmWorkerExecutionAdapter,
    },
  });
  const thresholdStoreConfig = stagingThresholdStoreConfig(env, scope.namespace);
  const session = createHmacSessionAdapterFromEnv({
    env,
    secretName: 'RELAY_SESSION_HMAC_SECRET',
    cookieName: readEnvString(env, 'SESSION_COOKIE_NAME'),
    issuer: readEnvString(env, 'RELAY_SESSION_ISSUER'),
    audience: readEnvString(env, 'RELAY_SESSION_AUDIENCE'),
  });
  const ed25519Yao = await createStagingEd25519YaoComposition(env, session, yaoState);
  const ecdsaCeremonyTokenIssuer = createStagingEcdsaCeremonyTokenIssuer(env);
  const ecdsaStrictRegistration = createRouterAbEcdsaStrictRegistrationPort({
    router: env.MPC_ROUTER,
    tokenIssuer: ecdsaCeremonyTokenIssuer,
    tokenScope: {
      orgId: scope.orgId,
      projectId: scope.projectId,
      environment: scope.envId,
    },
    topology: requireStagingEcdsaRegistrationTopology(env),
  });
  const ecdsaStrictPostRegistration = createRouterAbEcdsaStrictPostRegistrationPort({
    router: env.MPC_ROUTER,
    tokenIssuer: ecdsaCeremonyTokenIssuer,
    tokenScope: {
      orgId: scope.orgId,
      projectId: scope.projectId,
      environment: scope.envId,
    },
    topology: requireStagingEcdsaRegistrationTopology(env),
  });
  const service = createCloudflareD1RouterApiAuthService({
    database: env.SIGNER_DB,
    namespace: scope.namespace,
    orgId: scope.orgId,
    projectId: scope.projectId,
    envId: scope.envId,
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
    ed25519YaoProductRegistration: ed25519Yao.runtime,
    ecdsaStrictRegistration,
  });
  return createCloudflareRouter(service, {
    ...bundle.routerApiRouterOptions,
    healthz: true,
    readyz: true,
    corsOrigins: readCsvList(env.RELAY_CORS_ORIGINS),
    session,
    sessionCookieName: readEnvString(env, 'SESSION_COOKIE_NAME'),
    routerAbPublicKeyset: requireStagingRouterAbPublicKeyset(env),
    routerAbEcdsaStrictPostRegistration: ecdsaStrictPostRegistration,
    readyCheck: createRouterApiReadyCheck(env),
    signingSessionSeal: stagingSigningSessionSealOptions(env, thresholdStoreConfig),
    modules: [ed25519Yao.module],
    routerAbEd25519YaoProduct: ed25519Yao.runtime,
  });
}

function requireStagingRouterAbPublicKeyset(
  env: CloudflareD1RouterApiStagingEnv,
): RouterAbPublicKeysetV2 {
  const source = requireEnvString(env, 'ROUTER_AB_PUBLIC_KEYSET_JSON');
  const parsed = parseJsonObject(source);
  if (!parsed) {
    throw new Error('ROUTER_AB_PUBLIC_KEYSET_JSON must contain a JSON object');
  }
  return parseRouterAbPublicKeysetV2(parsed);
}

function createStagingEcdsaCeremonyTokenIssuer(
  env: CloudflareD1RouterApiStagingEnv,
): RouterAbEcdsaCeremonyTokenIssuer {
  const privateJwkSource = requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK');
  const privateJwk = parseRouterAbEcdsaEd25519PrivateJwk(parseJsonObject(privateJwkSource));
  if (!privateJwk) {
    throw new Error('ROUTER_AB_CEREMONY_JWT_PRIVATE_JWK must be an Ed25519 private JWK');
  }
  return createRouterAbEcdsaEd25519CeremonyTokenIssuer({
    issuer: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_ISSUER'),
    audience: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_AUDIENCE'),
    keyId: requireEnvString(env, 'ROUTER_AB_CEREMONY_JWT_KEY_ID'),
    privateJwk,
  });
}

function requireStagingEcdsaRegistrationTopology(
  env: CloudflareD1RouterApiStagingEnv,
): RouterAbEcdsaStrictRegistrationTopology {
  const source = requireEnvString(env, 'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON');
  const topology = parseRouterAbEcdsaStrictRegistrationTopology(parseJsonObject(source));
  if (!topology) {
    throw new Error(
      'ROUTER_AB_ECDSA_REGISTRATION_TOPOLOGY_JSON must contain the MPCRouter topology',
    );
  }
  return topology;
}

function routerAbCeremonyJwksResponse(env: CloudflareD1RouterApiStagingEnv): Response {
  const issuer = createStagingEcdsaCeremonyTokenIssuer(env);
  return new Response(JSON.stringify(issuer.publicJwks()), {
    status: 200,
    headers: {
      'cache-control': 'public, max-age=300',
      'content-type': 'application/json; charset=utf-8',
    },
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
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID: requireEnvString(env, 'ROUTER_AB_NORMAL_SIGNING_WORKER_ID'),
    ROUTER_AB_SIGNING_WORKER_URL: ROUTER_AB_SIGNING_WORKER_ORIGIN,
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: requireEnvString(
      env,
      'ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET',
    ),
    routerAbSigningWorkerFetch: createRouterAbServiceBindingFetch(env),
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
    this.env.ROUTER_API_RUNTIME.idFromName('seams-d1-router-api-runtime-staging-readyz');
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
  if (!keyVersion && !shamirPrimeB64u && !serverEncryptExponentB64u && !serverDecryptExponentB64u) {
    return undefined;
  }
  if (!keyVersion || !shamirPrimeB64u || !serverEncryptExponentB64u || !serverDecryptExponentB64u) {
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

function parseOidcExchangeIssuer(input: unknown): CloudflareD1OidcExchangeIssuerConfig | null {
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

function readRouterApiYaoState(persisted: unknown): RouterAbEd25519YaoProductRegistrationStateV1 {
  if (persisted === null || persisted === undefined) {
    return createRouterAbEd25519YaoProductRegistrationStateV1();
  }
  const parsed = parseRouterAbEd25519YaoProductRegistrationStateV1(persisted);
  if (!parsed.ok) throw new Error(parsed.message);
  return parsed.value;
}

function routerApiRuntimeInstanceName(env: CloudflareD1RouterApiStagingEnv): string {
  const scope = stagingTenantScope(env);
  return ['router-api-runtime-v1', scope.namespace, scope.orgId, scope.projectId, scope.envId].join(
    ':',
  );
}

function routerApiRuntimeFailureResponse(error: unknown): Response {
  const message = error instanceof Error ? error.message : String(error);
  console.error('[gateway-runtime] request failed', { message });
  return new Response(
    JSON.stringify({
      ok: false,
      code: 'router_api_runtime_failed',
      message: 'Gateway runtime failed',
    }),
    {
      status: 500,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    },
  );
}

export class RouterApiRuntimeDurableObject {
  private runtime: RouterApiRuntimeContext | null = null;

  constructor(
    private readonly state: RouterApiRuntimeDurableObjectState,
    private readonly env: CloudflareD1RouterApiStagingEnv,
  ) {}

  async fetch(request: Request): Promise<Response> {
    try {
      return await this.state.blockConcurrencyWhile(
        this.handleSerializedRequest.bind(this, request),
      );
    } catch (error: unknown) {
      return routerApiRuntimeFailureResponse(error);
    }
  }

  private async handleSerializedRequest(request: Request): Promise<Response> {
    const runtime = await this.requireRuntime();
    try {
      return await runtime.handler(request, this.env);
    } finally {
      await this.state.storage.put(ROUTER_API_YAO_STATE_KEY, runtime.yaoState);
    }
  }

  private async requireRuntime(): Promise<RouterApiRuntimeContext> {
    if (this.runtime) return this.runtime;
    const persisted = await this.state.storage.get(ROUTER_API_YAO_STATE_KEY);
    const yaoState = readRouterApiYaoState(persisted);
    const handler = await createRouterApiHandler(this.env, yaoState);
    this.runtime = { handler, yaoState };
    return this.runtime;
  }
}

async function fetch(
  request: Request,
  env: CloudflareD1RouterApiStagingEnv,
  _ctx: CfExecutionContext,
): Promise<Response> {
  if (request.method === 'GET' && new URL(request.url).pathname === ROUTER_AB_CEREMONY_JWKS_PATH) {
    return routerAbCeremonyJwksResponse(env);
  }
  const id = env.ROUTER_API_RUNTIME.idFromName(routerApiRuntimeInstanceName(env));
  const stub = env.ROUTER_API_RUNTIME.get(id);
  return await stub.fetch(request);
}

export default { fetch };
