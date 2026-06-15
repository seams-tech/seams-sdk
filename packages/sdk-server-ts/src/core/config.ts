import type {
  AuthServiceConfig,
  AuthServiceConfigInput,
  GoogleOidcConfigEnvInput,
  OidcExchangeConfig,
  OidcExchangeIssuerConfig,
} from './types';
import { THRESHOLD_DO_OBJECT_NAME_DEFAULT, THRESHOLD_PREFIX_DEFAULT } from './defaultConfigsServer';
import { toOptionalTrimmedString, toTrimmedString } from '@shared/utils/validation';

export const AUTH_SERVICE_CONFIG_DEFAULTS = {
  // Prefer FastNEAR for testnet by default (more reliable in practice).
  // If you set `networkId: 'mainnet'` and omit `nearRpcUrl`, the default switches to NEAR mainnet RPC.
  nearRpcUrlTestnet: 'https://test.rpc.fastnear.com',
  nearRpcUrlMainnet: 'https://rpc.mainnet.near.org',
  networkId: 'testnet',
  // 0.03 NEAR (typical for examples; adjust based on your app/storage needs).
  accountInitialBalance: '30000000000000000000000',
  // 85 TGas (tested)
  createAccountAndRegisterGas: '85000000000000',
} as const;

function defaultNearRpcUrl(networkId: string): string {
  const net = String(networkId || '')
    .trim()
    .toLowerCase();
  if (net === 'mainnet') return AUTH_SERVICE_CONFIG_DEFAULTS.nearRpcUrlMainnet;
  return AUTH_SERVICE_CONFIG_DEFAULTS.nearRpcUrlTestnet;
}

function parseCsv(input?: string | null): string[] {
  return String(input || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

function normalizeGoogleOidcConfig(
  input: AuthServiceConfigInput['googleOidc'],
): AuthServiceConfig['googleOidc'] | undefined {
  if (!input) return undefined;

  // Full options object
  if (
    typeof input === 'object' &&
    !Array.isArray(input) &&
    Array.isArray((input as any).clientIds)
  ) {
    const clientIds = Array.from(
      new Set(
        ((input as any).clientIds as unknown[]).map((v) => String(v || '').trim()).filter(Boolean),
      ),
    );
    if (!clientIds.length) return undefined;
    const hostedDomains = Array.isArray((input as any).hostedDomains)
      ? Array.from(
          new Set(
            ((input as any).hostedDomains as unknown[])
              .map((v) =>
                String(v || '')
                  .trim()
                  .toLowerCase(),
              )
              .filter(Boolean),
          ),
        )
      : [];
    return {
      clientIds,
      ...(hostedDomains.length ? { hostedDomains } : {}),
    };
  }

  // Env-shaped input
  const envInput = input as GoogleOidcConfigEnvInput;
  const single = toOptionalTrimmedString(envInput.GOOGLE_OIDC_CLIENT_ID);
  const csv = toOptionalTrimmedString(envInput.GOOGLE_OIDC_CLIENT_IDS);
  const hostedRaw = toOptionalTrimmedString(envInput.GOOGLE_OIDC_HOSTED_DOMAINS);

  const anyProvided = Boolean(single || csv || hostedRaw);
  if (!anyProvided) return undefined;

  const clientIds = Array.from(new Set([...(single ? [single] : []), ...parseCsv(csv)]));
  if (!clientIds.length) {
    throw new Error('googleOidc enabled but GOOGLE_OIDC_CLIENT_ID(S) is not set');
  }

  const hostedDomains = hostedRaw
    ? Array.from(new Set(parseCsv(hostedRaw).map((d) => d.toLowerCase())))
    : [];

  return {
    clientIds,
    ...(hostedDomains.length ? { hostedDomains } : {}),
  };
}

function normalizeOidcExchangeConfig(
  input: AuthServiceConfigInput['oidcExchange'],
): AuthServiceConfig['oidcExchange'] | undefined {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return undefined;
  const issuersRaw = Array.isArray((input as any).issuers) ? (input as any).issuers : [];
  const issuers: OidcExchangeIssuerConfig[] = [];
  for (const raw of issuersRaw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) continue;
    const issuer = toOptionalTrimmedString((raw as any).issuer);
    const jwksUrl = toOptionalTrimmedString((raw as any).jwksUrl);
    const audiencesRaw = Array.isArray((raw as any).audiences) ? (raw as any).audiences : [];
    const audiences = Array.from(
      new Set<string>(
        audiencesRaw
          .map((v: unknown): string => String(v || '').trim())
          .filter((v: string) => v.length > 0),
      ),
    );
    const subjectPrefix = toOptionalTrimmedString((raw as any).subjectPrefix);
    if (!issuer || !jwksUrl || !audiences.length) continue;
    issuers.push({
      issuer,
      jwksUrl,
      audiences,
      ...(subjectPrefix ? { subjectPrefix } : {}),
    });
  }
  if (!issuers.length) return undefined;

  const clockSkewRaw = (input as OidcExchangeConfig).clockSkewSec;
  const clockSkewSec = Number.isFinite(Number(clockSkewRaw))
    ? Math.max(0, Math.floor(Number(clockSkewRaw)))
    : undefined;

  return {
    issuers,
    ...(typeof clockSkewSec === 'number' ? { clockSkewSec } : {}),
  };
}

function normalizeThresholdStoreConfig(
  input: AuthServiceConfigInput['thresholdStore'],
): AuthServiceConfig['thresholdStore'] | undefined {
  if (!input) return undefined;
  if (typeof input !== 'object' || Array.isArray(input)) return undefined;

  const c = input as Record<string, unknown>;
  const anyProvided = Boolean(
    // Minimal (env-shaped)
    toOptionalTrimmedString(c.THRESHOLD_NODE_ROLE) ||
    toOptionalTrimmedString(c.THRESHOLD_COORDINATOR_SHARED_SECRET_B64U) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_RELAYER_COSIGNERS) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_RELAYER_COSIGNER_ID) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_RELAYER_COSIGNER_T) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_CLIENT_PARTICIPANT_ID) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_RELAYER_PARTICIPANT_ID) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_SHARE_MODE) ||
    toOptionalTrimmedString(c.THRESHOLD_PREFIX) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_AUTH_PREFIX) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_SESSION_PREFIX) ||
    toOptionalTrimmedString(c.THRESHOLD_ED25519_KEYSTORE_PREFIX) ||
    toOptionalTrimmedString(c.THRESHOLD_ECDSA_AUTH_PREFIX) ||
    toOptionalTrimmedString(c.THRESHOLD_ECDSA_SESSION_PREFIX) ||
    toOptionalTrimmedString(c.THRESHOLD_ECDSA_KEYSTORE_PREFIX) ||
    toOptionalTrimmedString(c.ROUTER_AB_NORMAL_SIGNING_WORKER_ID) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_KEY_VERSION) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SHAMIR_P_B64U) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_E_S_B64U) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_D_S_B64U) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_IDEMPOTENCY_KIND) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_URL) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_IDEMPOTENCY_UPSTASH_TOKEN) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_IDEMPOTENCY_REDIS_URL) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_URL) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_IDEMPOTENCY_POSTGRES_NAMESPACE) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_IDEMPOTENCY_KEY_PREFIX) ||
    toOptionalTrimmedString(c.SIGNING_SESSION_SEAL_IDEMPOTENCY_TTL_MS) ||
    c.signingRootShareResolver ||
    c.signingRootShareResolverAdapters ||
    c.signingRootSharePolicy ||
    c.signingRootShareStore ||
    c.signingRootShareDecryptAdapter ||
    // Explicit store config (kind-shaped)
    toOptionalTrimmedString(c.kind) ||
    toOptionalTrimmedString(c.url) ||
    toOptionalTrimmedString(c.token) ||
    toOptionalTrimmedString(c.redisUrl) ||
    toOptionalTrimmedString(c.postgresUrl) ||
    // Env-shaped store toggles
    toOptionalTrimmedString(c.UPSTASH_REDIS_REST_URL) ||
    toOptionalTrimmedString(c.UPSTASH_REDIS_REST_TOKEN) ||
    toOptionalTrimmedString(c.REDIS_URL) ||
    toOptionalTrimmedString(c.POSTGRES_URL),
  );
  if (!anyProvided) return undefined;

  // Apply sane defaults for common serverless/Worker configurations.
  //
  const normalized: Record<string, unknown> = { ...(input as Record<string, unknown>) };
  const kind = toOptionalTrimmedString(normalized.kind);
  if (kind === 'cloudflare-do') {
    const name = toOptionalTrimmedString(normalized.name);
    if (!name) normalized.name = THRESHOLD_DO_OBJECT_NAME_DEFAULT;

    const thresholdPrefix = toOptionalTrimmedString(normalized.THRESHOLD_PREFIX);
    const anySpecificPrefix = Boolean(
      toOptionalTrimmedString(normalized.THRESHOLD_ED25519_AUTH_PREFIX) ||
      toOptionalTrimmedString(normalized.THRESHOLD_ED25519_SESSION_PREFIX) ||
      toOptionalTrimmedString(normalized.THRESHOLD_ED25519_KEYSTORE_PREFIX),
    );
    if (!thresholdPrefix && !anySpecificPrefix) {
      normalized.THRESHOLD_PREFIX = THRESHOLD_PREFIX_DEFAULT;
    }
  }

  return normalized as AuthServiceConfig['thresholdStore'];
}

export function createAuthServiceConfig(input: AuthServiceConfigInput): AuthServiceConfig {
  const networkId = toTrimmedString(input.networkId) || AUTH_SERVICE_CONFIG_DEFAULTS.networkId;
  const config: AuthServiceConfig = {
    relayerAccount: toTrimmedString(input.relayerAccount),
    relayerPrivateKey: toTrimmedString(input.relayerPrivateKey),
    nearRpcUrl: toTrimmedString(input.nearRpcUrl) || defaultNearRpcUrl(networkId),
    networkId: networkId,
    accountInitialBalance:
      toTrimmedString(input.accountInitialBalance) ||
      AUTH_SERVICE_CONFIG_DEFAULTS.accountInitialBalance,
    createAccountAndRegisterGas:
      toTrimmedString(input.createAccountAndRegisterGas) ||
      AUTH_SERVICE_CONFIG_DEFAULTS.createAccountAndRegisterGas,
    signerWasm: input.signerWasm,
    thresholdStore: normalizeThresholdStoreConfig(input.thresholdStore),
    logger: input.logger,
    googleOidc: normalizeGoogleOidcConfig(input.googleOidc),
    oidcExchange: normalizeOidcExchangeConfig(input.oidcExchange),
  };

  validateConfigs(config);
  return config;
}

export function validateConfigs(config: AuthServiceConfig): void {
  const requiredTop = ['relayerAccount', 'relayerPrivateKey'] as const;
  for (const key of requiredTop) {
    if (!(config as any)[key]) throw new Error(`Missing required config variable: ${key}`);
  }

  // Validate private key format
  if (!config.relayerPrivateKey?.startsWith('ed25519:')) {
    throw new Error('Relayer private key must be in format "ed25519:base58privatekey"');
  }
}

export function parseBool(v: unknown): boolean {
  const s = String(v ?? '')
    .trim()
    .toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'on';
}

export function requireEnvVar<T extends object, K extends keyof T & string>(
  env: T,
  name: K,
): string {
  const raw = (env as any)?.[name] as unknown;
  if (typeof raw !== 'string') throw new Error(`Missing required env var: ${name}`);
  const v = raw.trim();
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}
