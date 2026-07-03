import type { RouterAbNormalSigningAdmissionInput } from '../routerAbPrivateSigningWorker';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import type { ConsoleAuthAdapter, ConsoleAuthClaims, HeaderRecord } from '../consoleAuth';
import {
  createSigningRootSecretShareKekResolver,
  type SigningRootKekProvider,
} from '../../core/ThresholdService/signingRootKekProvider';
import { sealSigningRootSecretShareWireV1 } from '../../core/ThresholdService/signingRootSecretSealing';
import {
  normalizeSigningRootSecretShareId,
  type SigningRootSecretShareWireV1,
} from '../../core/ThresholdService/signingRootSecretShareWires';
import type {
  CreateHostedSigningRootShareResolverInput,
  SealedSigningRootShare as ResolverSealedSigningRootShare,
  SigningRootShareSource,
  ThresholdPrfPolicy,
} from '../../core/ThresholdService/signingRootShareResolver';
import { D1SigningRootSecretStore } from '../../core/ThresholdService/stores/SigningRootSecretStore.d1';
import type { CfExecutionContext, FetchHandler } from './cloudflare.types';
import { ThresholdStoreDurableObject } from './durableObjects/thresholdStore';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
  ThresholdStoreConfigInput,
} from '../../core/types';
import { createSigningSessionSealOptions } from '../../threshold/session/signingSessionSeal/options';
import type { SigningSessionSealRoutesOptions } from '../../threshold/session/signingSessionSeal/signingSessionSeal.types';
import { createCloudflareRouter } from './createCloudflareRouter';
import { createCloudflareConsoleRouter } from './createCloudflareConsoleRouter';
import {
  createCloudflareD1ConsoleServiceBundle,
  createCloudflareD1SigningRootShareDecryptAdapter,
} from './d1ConsoleServices';
import {
  createCloudflareD1RouterApiAuthService,
  type CloudflareD1EmailOtpServerSealConfig,
} from './d1RouterApiAuthService';
import type {
  CloudflareD1OidcExchangeConfig,
  CloudflareD1OidcExchangeIssuerConfig,
} from './d1OidcBoundary';
import { createHmacSessionAdapter } from './d1StagingSession';
import {
  resolveSponsoredEvmCallConfigFromWorkerEnv,
  resolveSponsoredEvmWorkerExecutionAdapter,
} from '../../sponsorship/evmWorkerExecutionAdapter';
import {
  parseRouterAbPublicKeysetV2,
  ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
  type RouterAbPublicKeysetV2,
} from '@shared/utils/routerAbPublicKeyset';
import { parseWebAuthnRpId } from '@shared/utils/domainIds';

export { ThresholdStoreDurableObject };

interface LocalD1DevEnv {
  readonly CONSOLE_DB: D1DatabaseLike;
  readonly SIGNER_DB: D1DatabaseLike;
  readonly THRESHOLD_STORE: CloudflareDurableObjectNamespaceLike;
  readonly SEAMS_TENANT_STORAGE_NAMESPACE?: string;
  readonly SEAMS_LOCAL_CONSOLE_USER_ID?: string;
  readonly SEAMS_LOCAL_CONSOLE_ORG_ID?: string;
  readonly SEAMS_LOCAL_CONSOLE_PROJECT_ID?: string;
  readonly SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID?: string;
  readonly SEAMS_LOCAL_CONSOLE_ROLES?: string;
  readonly SEAMS_LOCAL_RELAYER_ACCOUNT?: string;
  readonly SEAMS_LOCAL_RELAYER_PUBLIC_KEY?: string;
  readonly SEAMS_LOCAL_RELAYER_PRIVATE_KEY?: string;
  readonly RELAYER_ACCOUNT_ID?: string;
  readonly RELAYER_PUBLIC_KEY?: string;
  readonly RELAYER_PRIVATE_KEY?: string;
  readonly NEAR_RPC_URL?: string;
  readonly ACCOUNT_INITIAL_BALANCE?: string;
  readonly ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING?: string;
  readonly SEAMS_LOCAL_GOOGLE_OIDC_CLIENT_ID?: string;
  readonly GOOGLE_OIDC_CLIENT_ID?: string;
  readonly GOOGLE_OIDC_CLIENT_IDS?: string;
  readonly SEAMS_LOCAL_OIDC_EXCHANGE_JSON?: string;
  readonly ROUTER_AB_SIGNING_WORKER_URL?: string;
  readonly ROUTER_AB_ECDSA_HSS_POOL_FILL_SIGNING_WORKER_URL?: string;
  readonly SIGNING_WORKER_URL?: string;
  readonly ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET?: string;
  readonly ROUTER_AB_INTERNAL_SERVICE_AUTH_TOKEN?: string;
  readonly RELAY_SESSION_HMAC_SECRET?: string;
  readonly SESSION_COOKIE_NAME?: string;
  readonly RELAY_SESSION_ISSUER?: string;
  readonly RELAY_SESSION_AUDIENCE?: string;
  readonly ROUTER_AB_NORMAL_SIGNING_WORKER_ID?: string;
  readonly SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH?: string;
  readonly SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY?: string;
  readonly SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH?: string;
  readonly SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY?: string;
  readonly SIGNER_A_PEER_VERIFYING_KEY_HEX?: string;
  readonly SIGNER_B_PEER_VERIFYING_KEY_HEX?: string;
  readonly SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH?: string;
  readonly SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY?: string;
  readonly ACCOUNT_ID_DERIVATION_SECRET?: string;
  readonly SIGNING_SESSION_SEAL_KEY_VERSION?: string;
  readonly SIGNING_SESSION_SHAMIR_P_B64U?: string;
  readonly SIGNING_SESSION_SEAL_E_S_B64U?: string;
  readonly SIGNING_SESSION_SEAL_D_S_B64U?: string;
  readonly EMAIL_OTP_DELIVERY_MODE?: string;
  readonly EMAIL_OTP_DEV_OUTBOX_ENABLED?: string;
  readonly EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX?: string;
  readonly EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS?: string;
  readonly EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX?: string;
  readonly EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS?: string;
  readonly SEAMS_LOCAL_SIGNING_ROOT_KEK_ID?: string;
  readonly SEAMS_LOCAL_SIGNING_ROOT_KEK_B64U?: string;
  readonly SPONSORED_EVM_EXECUTORS_JSON?: string;
}

type TableCountRow = {
  readonly table_count?: unknown;
};

type ReadyD1SchemaResult = {
  readonly consoleTables: number;
  readonly signerTables: number;
};

type ReadyAdmissionResult = {
  readonly durableObject: 'configured';
  readonly quotaReservation: 'accepted' | 'reuse_existing';
};

type LocalD1SigningRootShareRequest = {
  readonly signingRootId: string;
  readonly signingRootVersion: string;
};

type AdmissionDoOk<T> = { readonly ok: true; readonly value: T };
type AdmissionDoErr = { readonly ok: false; readonly code: string; readonly message: string };
type AdmissionDoResp<T> = AdmissionDoOk<T> | AdmissionDoErr;

const DEFAULT_LOCAL_CONSOLE_USER_ID = 'local-console-user';
const DEFAULT_LOCAL_CONSOLE_ORG_ID = 'local-smoke-org';
const DEFAULT_LOCAL_CONSOLE_PROJECT_ID = 'local-smoke-project';
const DEFAULT_LOCAL_CONSOLE_ENVIRONMENT_ID = 'local';
const DEFAULT_LOCAL_RELAY_SESSION_HMAC_SECRET =
  'seams-local-d1-relay-session-secret-change-before-shared-dev';
const DEFAULT_LOCAL_RELAY_SESSION_ISSUER = 'seams-local-d1-relay';
const DEFAULT_LOCAL_RELAY_SESSION_AUDIENCE = 'seams-local-d1';
const DEFAULT_LOCAL_CONSOLE_ROLES = Object.freeze([
  'owner',
  'admin',
  'platform_admin',
  'security_admin',
  'billing_admin',
  'developer',
  'ops',
]);
const DEFAULT_LOCAL_SIGNING_ROOT_KEK_ID = 'signing-root-kek-local-r1';
const DEFAULT_LOCAL_SIGNING_ROOT_KEK_B64U = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const DEFAULT_LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET = 'dev-router-ab-internal-service-auth';
const DEFAULT_LOCAL_ROUTER_AB_SIGNING_WORKER_URL = 'http://127.0.0.1:9093';
const LOCAL_ROUTER_AB_ED25519_SEED_PATH = '/router-ab/dev/ed25519/normal-signing/seed';
const LOCAL_ROUTER_AB_ECDSA_HSS_SEED_PATH = '/router-ab/dev/ecdsa-hss/normal-signing/seed';
const LOCAL_SIGNING_ROOT_SECRET_SHARE_ENVELOPE_VERSION = 'local-d1-signing-root-share-v1';
const LOCAL_SIGNING_ROOT_SECRET_SHARE_AUDIT_EVENT_ID = 'local-dev-signing-root-share-seed';
const LOCAL_SIGNING_ROOT_SHARE_POLICY: ThresholdPrfPolicy = Object.freeze({
  protocol: 'threshold-prf',
  threshold: 2,
  shareCount: 3,
});
const LOCAL_SIGNING_ROOT_SHARE_FIXTURES = Object.freeze([
  {
    shareId: 1,
    wireHex: '0001d73847ea1a0888265782eb6998f3d905b8275fa4e5fda6556ddacc3b28741702',
  },
  {
    shareId: 2,
    wireHex: '0002b3ee4da8422ffeebb66bd0b55afb5d072f55aa324698a89c0a8b234042fd6c0f',
  },
  {
    shareId: 3,
    wireHex: '0003a2d05e0950f3615940b8bd5e3e0903f4a582f5c0a632aae3a73b7a445c86c20c',
  },
] as const);
const LOCAL_ROUTER_API_CORS_ORIGINS = Object.freeze([
  'https://localhost',
  'https://localhost:8443',
  'https://localhost:9444',
  'http://127.0.0.1:9090',
  'http://localhost:9090',
  'http://127.0.0.1:8787',
  'http://localhost:8787',
]);
const CONSOLE_READY_TABLES = Object.freeze([
  'organizations',
  'projects',
  'environments',
  'team_members',
  'user_profiles',
  'user_backup_emails',
  'policies',
  'policy_versions',
  'policy_assignments',
  'wallet_index',
  'api_keys',
  'approvals',
  'key_exports',
  'webhook_endpoints',
  'webhook_endpoint_categories',
  'webhook_deliveries',
  'webhook_attempts',
  'webhook_dead_letters',
  'observability_events',
  'observability_event_dedup',
  'observability_ingest_windows',
  'observability_request_rollups_minute',
  'audit_events',
  'audit_evidence',
  'bootstrap_tokens',
  'billing_accounts',
  'billing_ledger_entries',
  'billing_ledger_postings',
  'billing_monthly_active_wallets',
  'billing_credit_purchases',
  'invoices',
  'invoice_line_items',
  'stripe_webhook_events',
  'billing_prepaid_reservation_summaries',
  'billing_prepaid_reservations',
  'sponsorship_spend_cap_windows',
  'sponsorship_spend_cap_reservations',
  'sponsorship_pricing_rules',
  'sponsored_call_records',
  'runtime_snapshots',
  'runtime_snapshot_outbox',
]);

const SIGNER_READY_TABLES = Object.freeze([
  'signing_root_secret_shares',
  'wallets',
  'wallet_signers',
  'wallet_auth_methods',
  'webauthn_authenticators',
  'webauthn_credential_bindings',
  'webauthn_challenges',
  'identity_links',
  'app_session_versions',
  'recovery_sessions',
  'recovery_executions',
  'near_public_keys',
  'email_recovery_preparations',
  'email_otp_challenges',
  'email_otp_grants',
  'email_otp_wallet_enrollments',
  'email_otp_recovery_wrapped_enrollment_escrows',
  'email_otp_auth_states',
  'email_otp_unlock_challenges',
  'email_otp_registration_attempts',
  'email_otp_rate_limits',
]);

function jsonResponse(body: Record<string, unknown>, init?: ResponseInit): Response {
  return new Response(JSON.stringify(body), {
    ...init,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      ...(init?.headers || {}),
    },
  });
}

function localRouterAbInternalServiceAuthSecret(env: LocalD1DevEnv): string {
  return (
    normalizeLocalString(env.ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET) ||
    DEFAULT_LOCAL_ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET
  );
}

function hasLocalRouterAbInternalServiceAuth(request: Request, env: LocalD1DevEnv): boolean {
  const expected = localRouterAbInternalServiceAuthSecret(env);
  const actual = normalizeLocalString(request.headers.get('x-router-ab-internal-service-auth'));
  return actual !== '' && actual === expected;
}

function parseReadyTableCount(row: TableCountRow | null): number {
  const count = Number(row?.table_count);
  if (!Number.isInteger(count) || count < 0) return 0;
  return count;
}

function localTenantStorageNamespace(env: LocalD1DevEnv): string {
  const namespace = String(env.SEAMS_TENANT_STORAGE_NAMESPACE || '').trim();
  return namespace || 'seams-local';
}

class LocalD1DevConsoleAuthAdapter implements ConsoleAuthAdapter {
  constructor(private readonly env: LocalD1DevEnv) {}

  authenticate(headers: HeaderRecord): { readonly ok: true; readonly claims: ConsoleAuthClaims } {
    return {
      ok: true,
      claims: localConsoleAuthClaims(this.env, headers),
    };
  }
}

class LocalD1DevReadyCheck {
  constructor(private readonly env: LocalD1DevEnv) {}

  async check(): Promise<void> {
    await assertLocalD1DoReady(this.env);
  }
}

function normalizeLocalString(input: unknown): string {
  return typeof input === 'string' ? input.trim() : '';
}

function localStringArray(input: unknown): string[] {
  if (!Array.isArray(input)) return [];
  const values: string[] = [];
  const seen = new Set<string>();
  for (const item of input) {
    const value = normalizeLocalString(item);
    if (!value || seen.has(value)) continue;
    values.push(value);
    seen.add(value);
  }
  return values;
}

function localCsvStringArray(input: unknown): string[] {
  const raw = normalizeLocalString(input);
  if (!raw) return [];
  return localStringArray(raw.split(','));
}

function localGoogleOidcClientId(env: LocalD1DevEnv): string | undefined {
  return (
    normalizeLocalString(env.GOOGLE_OIDC_CLIENT_ID) ||
    localCsvStringArray(env.GOOGLE_OIDC_CLIENT_IDS)[0] ||
    normalizeLocalString(env.SEAMS_LOCAL_GOOGLE_OIDC_CLIENT_ID) ||
    undefined
  );
}

function localRouterApiSessionSecret(env: LocalD1DevEnv): string {
  return (
    normalizeLocalString(env.RELAY_SESSION_HMAC_SECRET) || DEFAULT_LOCAL_RELAY_SESSION_HMAC_SECRET
  );
}

function localRouterApiSessionCookieName(env: LocalD1DevEnv): string | undefined {
  return normalizeLocalString(env.SESSION_COOKIE_NAME) || undefined;
}

function localRouterApiSessionIssuer(env: LocalD1DevEnv): string {
  return normalizeLocalString(env.RELAY_SESSION_ISSUER) || DEFAULT_LOCAL_RELAY_SESSION_ISSUER;
}

function localRouterApiSessionAudience(env: LocalD1DevEnv): string {
  return normalizeLocalString(env.RELAY_SESSION_AUDIENCE) || DEFAULT_LOCAL_RELAY_SESSION_AUDIENCE;
}

function localOidcExchangeIssuerConfig(
  input: unknown,
): CloudflareD1OidcExchangeIssuerConfig | null {
  if (!isRecord(input)) return null;
  const issuer = normalizeLocalString(input.issuer);
  const jwksUrl = normalizeLocalString(input.jwksUrl);
  const audiences = localStringArray(input.audiences);
  const subjectPrefix = normalizeLocalString(input.subjectPrefix);
  if (!issuer || !jwksUrl || audiences.length === 0) return null;
  return {
    issuer,
    jwksUrl,
    audiences,
    ...(subjectPrefix ? { subjectPrefix } : {}),
  };
}

function localClockSkewSec(input: unknown): number | string | undefined {
  if (typeof input === 'number' && Number.isFinite(input)) return input;
  const value = normalizeLocalString(input);
  return value || undefined;
}

function localOidcExchangeConfig(env: LocalD1DevEnv): CloudflareD1OidcExchangeConfig | undefined {
  const raw = normalizeLocalString(env.SEAMS_LOCAL_OIDC_EXCHANGE_JSON);
  if (!raw) return undefined;
  const parsed = parseJsonObject(raw);
  if (!parsed) throw new Error('SEAMS_LOCAL_OIDC_EXCHANGE_JSON must be a JSON object');
  const issuersRaw = Array.isArray(parsed.issuers) ? parsed.issuers : [];
  const issuers: CloudflareD1OidcExchangeIssuerConfig[] = [];
  for (const issuerRaw of issuersRaw) {
    const issuer = localOidcExchangeIssuerConfig(issuerRaw);
    if (issuer) issuers.push(issuer);
  }
  if (issuers.length === 0) {
    throw new Error('SEAMS_LOCAL_OIDC_EXCHANGE_JSON must define at least one OIDC issuer');
  }
  const clockSkewSec = localClockSkewSec(parsed.clockSkewSec);
  return {
    issuers,
    ...(clockSkewSec !== undefined ? { clockSkewSec } : {}),
  };
}

function localEmailOtpServerSealConfig(
  env: LocalD1DevEnv,
): CloudflareD1EmailOtpServerSealConfig | undefined {
  const keyVersion = normalizeLocalString(env.SIGNING_SESSION_SEAL_KEY_VERSION);
  const shamirPrimeB64u = normalizeLocalString(env.SIGNING_SESSION_SHAMIR_P_B64U);
  const serverEncryptExponentB64u = normalizeLocalString(env.SIGNING_SESSION_SEAL_E_S_B64U);
  const serverDecryptExponentB64u = normalizeLocalString(env.SIGNING_SESSION_SEAL_D_S_B64U);
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

function headerString(headers: HeaderRecord, name: string): string {
  const value = headers[name.toLowerCase()] ?? headers[name];
  if (Array.isArray(value)) {
    for (const item of value) {
      const normalized = normalizeLocalString(item);
      if (normalized) return normalized;
    }
    return '';
  }
  return normalizeLocalString(value);
}

function headerOrEnvString(input: {
  readonly headers: HeaderRecord;
  readonly headerName: string;
  readonly envValue: unknown;
  readonly fallback: string;
}): string {
  return (
    headerString(input.headers, input.headerName) ||
    normalizeLocalString(input.envValue) ||
    input.fallback
  );
}

function parseLocalConsoleRoles(input: string): string[] {
  const roles: string[] = [];
  for (const role of input.split(',')) {
    const normalized = role.trim().toLowerCase();
    if (normalized) roles.push(normalized);
  }
  return roles.length > 0 ? roles : [...DEFAULT_LOCAL_CONSOLE_ROLES];
}

function localConsoleAuthClaims(env: LocalD1DevEnv, headers: HeaderRecord): ConsoleAuthClaims {
  const roles = parseLocalConsoleRoles(
    headerOrEnvString({
      headers,
      headerName: 'x-console-roles',
      envValue: env.SEAMS_LOCAL_CONSOLE_ROLES,
      fallback: DEFAULT_LOCAL_CONSOLE_ROLES.join(','),
    }),
  );
  return {
    userId: headerOrEnvString({
      headers,
      headerName: 'x-console-user-id',
      envValue: env.SEAMS_LOCAL_CONSOLE_USER_ID,
      fallback: DEFAULT_LOCAL_CONSOLE_USER_ID,
    }),
    orgId: headerOrEnvString({
      headers,
      headerName: 'x-console-org-id',
      envValue: env.SEAMS_LOCAL_CONSOLE_ORG_ID,
      fallback: DEFAULT_LOCAL_CONSOLE_ORG_ID,
    }),
    projectId: headerOrEnvString({
      headers,
      headerName: 'x-console-project-id',
      envValue: env.SEAMS_LOCAL_CONSOLE_PROJECT_ID,
      fallback: DEFAULT_LOCAL_CONSOLE_PROJECT_ID,
    }),
    environmentId: headerOrEnvString({
      headers,
      headerName: 'x-console-environment-id',
      envValue: env.SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID,
      fallback: DEFAULT_LOCAL_CONSOLE_ENVIRONMENT_ID,
    }),
    roles,
  };
}

function localConsoleOrgId(env: LocalD1DevEnv): string {
  return normalizeLocalString(env.SEAMS_LOCAL_CONSOLE_ORG_ID) || DEFAULT_LOCAL_CONSOLE_ORG_ID;
}

function localConsoleProjectId(env: LocalD1DevEnv): string {
  return (
    normalizeLocalString(env.SEAMS_LOCAL_CONSOLE_PROJECT_ID) || DEFAULT_LOCAL_CONSOLE_PROJECT_ID
  );
}

function localConsoleEnvironmentId(env: LocalD1DevEnv): string {
  return (
    normalizeLocalString(env.SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID) ||
    DEFAULT_LOCAL_CONSOLE_ENVIRONMENT_ID
  );
}

function localSigningRootKekId(env: LocalD1DevEnv): string {
  return (
    normalizeLocalString(env.SEAMS_LOCAL_SIGNING_ROOT_KEK_ID) || DEFAULT_LOCAL_SIGNING_ROOT_KEK_ID
  );
}

function localSigningRootKekProvider(env: LocalD1DevEnv): SigningRootKekProvider {
  const kekId = localSigningRootKekId(env);
  const kekB64u =
    normalizeLocalString(env.SEAMS_LOCAL_SIGNING_ROOT_KEK_B64U) ||
    DEFAULT_LOCAL_SIGNING_ROOT_KEK_B64U;
  return {
    kind: 'worker_secret',
    workerSecretsByKekId: {
      [kekId]: kekB64u,
    },
    encoding: 'base64url',
  };
}

function hexToLocalBytes(hex: string): Uint8Array {
  const normalized = hex.trim();
  if (!/^[0-9a-fA-F]*$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error('local signing-root fixture hex is invalid');
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function parseLocalSigningRootId(signingRootId: string): {
  readonly projectId: string;
  readonly envId: string;
} {
  const value = normalizeLocalString(signingRootId);
  const separator = value.lastIndexOf(':');
  if (separator <= 0 || separator >= value.length - 1) {
    throw new Error('local D1 signingRootId must be projectId:envId');
  }
  return {
    projectId: value.slice(0, separator),
    envId: value.slice(separator + 1),
  };
}

function createLocalD1SigningRootSecretStore(input: {
  readonly env: LocalD1DevEnv;
  readonly signingRootId: string;
}): D1SigningRootSecretStore {
  const scope = parseLocalSigningRootId(input.signingRootId);
  return new D1SigningRootSecretStore({
    database: input.env.SIGNER_DB,
    namespace: localTenantStorageNamespace(input.env),
    orgId: localConsoleOrgId(input.env),
    projectId: scope.projectId,
    envId: scope.envId,
    envelopeVersion: LOCAL_SIGNING_ROOT_SECRET_SHARE_ENVELOPE_VERSION,
    lastAuditEventId: LOCAL_SIGNING_ROOT_SECRET_SHARE_AUDIT_EVENT_ID,
    ensureSchema: false,
  });
}

function normalizeLocalD1SigningRootShareRequest(input: {
  readonly signingRootId: string;
  readonly signingRootVersion?: string;
}): LocalD1SigningRootShareRequest {
  const signingRootId = normalizeLocalString(input.signingRootId);
  const signingRootVersion = normalizeLocalString(input.signingRootVersion);
  if (!signingRootId) throw new Error('local D1 signing-root share request requires signingRootId');
  if (!signingRootVersion) {
    throw new Error('local D1 signing-root share request requires signingRootVersion');
  }

  return {
    signingRootId,
    signingRootVersion,
  };
}

function localSigningRootSeedKey(input: LocalD1SigningRootShareRequest): string {
  return `${input.signingRootId}\0${input.signingRootVersion}`;
}

class LocalD1SigningRootShareSource implements SigningRootShareSource {
  private readonly seedPromises = new Map<string, Promise<void>>();
  private readonly seededKeys = new Set<string>();

  constructor(private readonly env: LocalD1DevEnv) {}

  async listSealedSigningRootShares(input: {
    readonly signingRootId: string;
    readonly signingRootVersion?: string;
  }): Promise<readonly ResolverSealedSigningRootShare[]> {
    const request = normalizeLocalD1SigningRootShareRequest(input);
    const store = createLocalD1SigningRootSecretStore({
      env: this.env,
      signingRootId: request.signingRootId,
    });
    await this.ensureSeeded(store, request);
    return await store.listSealedSigningRootSecretShares(request);
  }

  private async ensureSeeded(
    store: D1SigningRootSecretStore,
    input: LocalD1SigningRootShareRequest,
  ): Promise<void> {
    const key = localSigningRootSeedKey(input);
    if (this.seededKeys.has(key)) return;
    const existing = this.seedPromises.get(key);
    if (existing) {
      await existing;
      return;
    }
    const promise = this.seed(store, input);
    this.seedPromises.set(key, promise);
    try {
      await promise;
      this.seededKeys.add(key);
    } finally {
      this.seedPromises.delete(key);
    }
  }

  private async seed(
    store: D1SigningRootSecretStore,
    input: LocalD1SigningRootShareRequest,
  ): Promise<void> {
    const resolveKek = createSigningRootSecretShareKekResolver(
      localSigningRootKekProvider(this.env),
    );
    const kekId = localSigningRootKekId(this.env);
    for (const fixture of LOCAL_SIGNING_ROOT_SHARE_FIXTURES) {
      const shareId = normalizeSigningRootSecretShareId(fixture.shareId);
      if (!shareId) throw new Error('local signing-root fixture has invalid shareId');
      const plaintextShareWire = hexToLocalBytes(fixture.wireHex) as SigningRootSecretShareWireV1;
      try {
        const sealedShare = await sealSigningRootSecretShareWireV1({
          signingRootId: input.signingRootId,
          signingRootVersion: input.signingRootVersion,
          shareId,
          kekId,
          plaintextShareWire,
          resolveKek,
        });
        await store.putSealedSigningRootSecretShare({
          signingRootId: input.signingRootId,
          signingRootVersion: input.signingRootVersion,
          shareId,
          sealedShare,
          storageId: `local-dev-signing-root-share-${shareId}`,
          kekId,
        });
      } finally {
        plaintextShareWire.fill(0);
      }
    }
  }
}

function createLocalD1SigningRootShareResolverAdapters(
  env: LocalD1DevEnv,
): CreateHostedSigningRootShareResolverInput {
  return {
    policy: LOCAL_SIGNING_ROOT_SHARE_POLICY,
    storageAdapter: new LocalD1SigningRootShareSource(env),
    decryptAdapter: createCloudflareD1SigningRootShareDecryptAdapter(
      localSigningRootKekProvider(env),
    ),
  };
}

function isConsolePath(pathname: string): boolean {
  return pathname === '/console' || pathname.startsWith('/console/');
}

function isRouterApiPath(pathname: string): boolean {
  return (
    pathname === '/relay' ||
    pathname.startsWith('/relay/') ||
    pathname.startsWith('/.well-known/') ||
    pathname.startsWith('/auth/') ||
    pathname.startsWith('/email-recovery/') ||
    pathname.startsWith('/near/') ||
    pathname.startsWith('/recover-email') ||
    pathname.startsWith('/router-ab/') ||
    pathname.startsWith('/session/') ||
    pathname.startsWith('/sponsorships/') ||
    pathname.startsWith('/sync-account/') ||
    pathname.startsWith('/v1/') ||
    pathname.startsWith('/wallet/') ||
    pathname.startsWith('/wallet-session/') ||
    pathname.startsWith('/wallets/') ||
    pathname.startsWith('/webauthn/')
  );
}

async function assertLocalD1DoReady(env: LocalD1DevEnv): Promise<void> {
  await assertLocalD1Schemas(env);
  await runD1DoAdmissionSmoke(env);
}

function createLocalReadyCheck(env: LocalD1DevEnv): () => Promise<void> {
  const readyCheck = new LocalD1DevReadyCheck(env);
  return readyCheck.check.bind(readyCheck);
}

async function createLocalConsoleHandler(env: LocalD1DevEnv): Promise<FetchHandler> {
  const sponsoredEvmCallConfig = await resolveSponsoredEvmCallConfigFromWorkerEnv(env);
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: env.CONSOLE_DB,
      signerMetadataDatabase: env.SIGNER_DB,
      thresholdStore: env.THRESHOLD_STORE,
      kekProvider: localSigningRootKekProvider(env),
    },
    route: {
      namespace: localTenantStorageNamespace(env),
    },
    adapters: {
      ensureSchema: false,
      sponsoredEvmCallConfig,
    },
  });
  return createCloudflareConsoleRouter({
    ...bundle.consoleRouterOptions,
    healthz: true,
    readyz: true,
    auth: new LocalD1DevConsoleAuthAdapter(env),
    readyCheck: createLocalReadyCheck(env),
  });
}

function localConsoleHandler(env: LocalD1DevEnv): Promise<FetchHandler> {
  return createLocalConsoleHandler(env);
}

async function createLocalRouterApiHandler(env: LocalD1DevEnv): Promise<FetchHandler> {
  const sponsoredEvmCallConfig = await resolveSponsoredEvmCallConfigFromWorkerEnv(env);
  const routerAbPublicKeyset = localRouterAbPublicKeyset(env);
  const bundle = await createCloudflareD1ConsoleServiceBundle({
    bindings: {
      consoleDatabase: env.CONSOLE_DB,
      signerMetadataDatabase: env.SIGNER_DB,
      thresholdStore: env.THRESHOLD_STORE,
      kekProvider: localSigningRootKekProvider(env),
    },
    route: {
      namespace: localTenantStorageNamespace(env),
    },
    adapters: {
      ensureSchema: false,
      sponsoredEvmCallConfig,
    },
  });
  const sponsoredEvmCall = bundle.routerApiRouterOptions.sponsoredEvmCall
    ? {
        ...bundle.routerApiRouterOptions.sponsoredEvmCall,
        resolveExecutionAdapter: resolveSponsoredEvmWorkerExecutionAdapter,
      }
    : undefined;
  const sessionCookieName = localRouterApiSessionCookieName(env);
  const routerApiService = createLocalD1RouterApiAuthService(env);
  return createCloudflareRouter(routerApiService, {
    ...bundle.routerApiRouterOptions,
    healthz: true,
    readyz: true,
    corsOrigins: [...LOCAL_ROUTER_API_CORS_ORIGINS],
    ...(routerAbPublicKeyset ? { routerAbPublicKeyset } : {}),
    session: createHmacSessionAdapter({
      secret: localRouterApiSessionSecret(env),
      cookieName: sessionCookieName,
      issuer: localRouterApiSessionIssuer(env),
      audience: localRouterApiSessionAudience(env),
    }),
    ...(sessionCookieName ? { sessionCookieName } : {}),
    ...(sponsoredEvmCall ? { sponsoredEvmCall } : {}),
    signingSessionSeal: localSigningSessionSealOptions(env),
  });
}

function localThresholdStoreConfig(env: LocalD1DevEnv): ThresholdStoreConfigInput {
  return {
    kind: 'cloudflare-do',
    namespace: env.THRESHOLD_STORE,
    THRESHOLD_PREFIX: localTenantStorageNamespace(env),
    ROUTER_AB_NORMAL_SIGNING_WORKER_ID:
      normalizeLocalString(env.ROUTER_AB_NORMAL_SIGNING_WORKER_ID) ||
      'local-d1-threshold-signing-worker',
    ROUTER_AB_SIGNING_WORKER_URL:
      normalizeLocalString(env.ROUTER_AB_SIGNING_WORKER_URL) ||
      DEFAULT_LOCAL_ROUTER_AB_SIGNING_WORKER_URL,
    ROUTER_AB_ECDSA_HSS_POOL_FILL_SIGNING_WORKER_URL: normalizeLocalString(
      env.ROUTER_AB_ECDSA_HSS_POOL_FILL_SIGNING_WORKER_URL,
    ),
    SIGNING_WORKER_URL: normalizeLocalString(env.SIGNING_WORKER_URL),
    ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: localRouterAbInternalServiceAuthSecret(env),
    ROUTER_AB_INTERNAL_SERVICE_AUTH_TOKEN: normalizeLocalString(
      env.ROUTER_AB_INTERNAL_SERVICE_AUTH_TOKEN,
    ),
    signingRootShareResolverAdapters: createLocalD1SigningRootShareResolverAdapters(env),
  };
}

function localSigningSessionSealOptions(
  env: LocalD1DevEnv,
): SigningSessionSealRoutesOptions | undefined {
  const seal = localEmailOtpServerSealConfig(env);
  if (!seal) return undefined;
  return createSigningSessionSealOptions({
    keyVersion: seal.keyVersion,
    shamirPrimeB64u: seal.shamirPrimeB64u,
    serverEncryptExponentB64u: seal.serverEncryptExponentB64u,
    serverDecryptExponentB64u: seal.serverDecryptExponentB64u,
    thresholdStoreConfig: localThresholdStoreConfig(env),
  });
}

function createLocalD1RouterApiAuthService(env: LocalD1DevEnv) {
  const relayerPrivateKey = env.RELAYER_PRIVATE_KEY || env.SEAMS_LOCAL_RELAYER_PRIVATE_KEY;
  const relayerPublicKey =
    env.RELAYER_PUBLIC_KEY ||
    (env.RELAYER_PRIVATE_KEY ? undefined : env.SEAMS_LOCAL_RELAYER_PUBLIC_KEY);
  return createCloudflareD1RouterApiAuthService({
    database: env.SIGNER_DB,
    namespace: localTenantStorageNamespace(env),
    orgId: localConsoleOrgId(env),
    projectId: localConsoleProjectId(env),
    envId: localConsoleEnvironmentId(env),
    relayerAccount: env.RELAYER_ACCOUNT_ID || env.SEAMS_LOCAL_RELAYER_ACCOUNT,
    relayerPublicKey,
    relayerPrivateKey,
    nearRpcUrl: env.NEAR_RPC_URL,
    accountInitialBalance: env.ACCOUNT_INITIAL_BALANCE,
    implicitNearAccountTestFundingEnabled: env.ENABLE_IMPLICIT_NEAR_ACCOUNT_TEST_FUNDING,
    googleOidcClientId: localGoogleOidcClientId(env),
    oidcExchange: localOidcExchangeConfig(env),
    accountIdDerivationSecret: env.ACCOUNT_ID_DERIVATION_SECRET,
    emailOtpServerSeal: localEmailOtpServerSealConfig(env),
    emailOtpDeliveryMode: env.EMAIL_OTP_DELIVERY_MODE || 'dev_d1_outbox',
    emailOtpDevOutboxEnabled: env.EMAIL_OTP_DEV_OUTBOX_ENABLED ?? true,
    emailOtpRecoveryKeyAttemptRateLimitMax: env.EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX,
    emailOtpRecoveryKeyAttemptRateLimitWindowMs:
      env.EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS,
    emailOtpGoogleRegistrationAttemptRateLimitMax:
      env.EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX,
    emailOtpGoogleRegistrationAttemptRateLimitWindowMs:
      env.EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS,
    thresholdStore: localThresholdStoreConfig(env),
  });
}

function localRouterApiHandler(env: LocalD1DevEnv): Promise<FetchHandler> {
  return createLocalRouterApiHandler(env);
}

function routerApiRequest(request: Request, pathname: string): Request {
  const url = new URL(request.url);
  const stripped = pathname.startsWith('/relay')
    ? pathname === '/relay'
      ? '/'
      : pathname.slice('/relay'.length)
    : pathname;
  url.pathname = stripped || '/';
  return new Request(url.toString(), request);
}

function localAdmissionInput(nowMs: number): RouterAbNormalSigningAdmissionInput {
  const rpId = parseWebAuthnRpId('localhost');
  if (!rpId.ok) throw new Error('local D1/DO admission smoke rpId is invalid');
  return {
    curve: 'ed25519',
    phase: 'prepare',
    walletId: 'local-smoke-wallet',
    authorityScope: { kind: 'passkey_rp', rpId: rpId.value },
    thresholdSessionId: 'local-smoke-threshold-session',
    signingGrantId: 'local-smoke-signing-grant',
    requestId: `local-smoke-request-${nowMs}`,
    expiresAtMs: nowMs + 60_000,
    signingWorkerId: 'local-smoke-signing-worker',
    runtimePolicyScope: {
      orgId: 'local-smoke-org',
      projectId: 'local-smoke-project',
      envId: 'local',
      signingRootVersion: 'local-root-v1',
    },
  };
}

async function runD1DoAdmissionSmoke(env: LocalD1DevEnv): Promise<ReadyAdmissionResult> {
  const nowMs = Date.now();
  const input = localAdmissionInput(nowMs);
  const key = [
    'router-ab-normal-signing-admission',
    'namespace',
    localTenantStorageNamespace(env),
    'readyz',
    input.runtimePolicyScope.orgId,
    input.runtimePolicyScope.projectId,
    input.runtimePolicyScope.envId,
    input.walletId,
    input.thresholdSessionId,
    input.requestId,
  ].join(':');
  const response = await callAdmissionDo(env.THRESHOLD_STORE, {
    key,
    requestId: input.requestId,
    lifecycleId: normalSigningLifecycleId(input),
    expiresAtMs: input.expiresAtMs,
    nowMs,
  });
  if (!response.ok) {
    throw new Error(`local D1/DO admission smoke failed: ${response.code}`);
  }
  const quotaReservation = parseAdmissionQuotaReservation(response.value);
  if (!quotaReservation) {
    throw new Error('local D1/DO admission smoke returned an invalid quota decision');
  }
  return {
    durableObject: 'configured',
    quotaReservation,
  };
}

async function callAdmissionDo(
  namespace: CloudflareDurableObjectNamespaceLike,
  input: {
    readonly key: string;
    readonly requestId: string;
    readonly lifecycleId: string;
    readonly expiresAtMs: number;
    readonly nowMs: number;
  },
): Promise<AdmissionDoResp<unknown>> {
  const stub = admissionSmokeStub(namespace);
  const response = await stub.fetch('https://threshold-store.invalid/', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      op: 'routerAbNormalSigningReserveQuota',
      key: input.key,
      requestId: input.requestId,
      lifecycleId: input.lifecycleId,
      expiresAtMs: input.expiresAtMs,
      nowMs: input.nowMs,
    }),
  });
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`local D1/DO admission smoke HTTP ${response.status}: ${text}`);
  }
  return parseAdmissionDoResponse(text);
}

function admissionSmokeStub(
  namespace: CloudflareDurableObjectNamespaceLike,
): CloudflareDurableObjectStubLike {
  const id = namespace.idFromName('seams-local-readyz-router-ab-admission');
  return namespace.get(id);
}

function parseAdmissionDoResponse(text: string): AdmissionDoResp<unknown> {
  const parsed = parseJsonObject(text);
  if (!parsed) {
    throw new Error('local D1/DO admission smoke returned invalid JSON');
  }
  if (parsed.ok === true) {
    return { ok: true, value: parsed.value };
  }
  return {
    ok: false,
    code: requireOptionalString(parsed.code, 'internal'),
    message: requireOptionalString(parsed.message, 'local D1/DO admission smoke failed'),
  };
}

function parseAdmissionQuotaReservation(value: unknown): 'accepted' | 'reuse_existing' | null {
  if (!isRecord(value)) return null;
  if (value.kind === 'accepted') return 'accepted';
  if (value.kind === 'reuse_existing') return 'reuse_existing';
  return null;
}

function parseJsonObject(text: string): Record<string, unknown> | null {
  let parsed: unknown;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    return null;
  }
  return isRecord(parsed) ? parsed : null;
}

function requireOptionalString(value: unknown, fallback: string): string {
  return typeof value === 'string' && value.trim() ? value.trim() : fallback;
}

function requireLocalEnvString(value: unknown, field: string): string {
  const normalized = normalizeLocalString(value);
  if (!normalized) {
    throw new Error(`${field} is required when local Router A/B public keyset is configured`);
  }
  return normalized;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function allLocalStringsEmpty(values: readonly unknown[]): boolean {
  for (const value of values) {
    if (normalizeLocalString(value)) return false;
  }
  return true;
}

function localRouterAbPublicKeyset(env: LocalD1DevEnv): RouterAbPublicKeysetV2 | undefined {
  const fields = [
    env.SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH,
    env.SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY,
    env.SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH,
    env.SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY,
    env.SIGNER_A_PEER_VERIFYING_KEY_HEX,
    env.SIGNER_B_PEER_VERIFYING_KEY_HEX,
    env.SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH,
    env.SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
  ];
  if (allLocalStringsEmpty(fields)) {
    return undefined;
  }
  return parseRouterAbPublicKeysetV2({
    keyset_version: ROUTER_AB_PUBLIC_KEYSET_VERSION_V2,
    signer_envelope_hpke: {
      current: {
        deriver_a: {
          role: 'signer_a',
          key_epoch: requireLocalEnvString(
            env.SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH,
            'SIGNER_A_ENVELOPE_HPKE_KEY_EPOCH',
          ),
          public_key: requireLocalEnvString(
            env.SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY,
            'SIGNER_A_ENVELOPE_HPKE_PUBLIC_KEY',
          ),
        },
        deriver_b: {
          role: 'signer_b',
          key_epoch: requireLocalEnvString(
            env.SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH,
            'SIGNER_B_ENVELOPE_HPKE_KEY_EPOCH',
          ),
          public_key: requireLocalEnvString(
            env.SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY,
            'SIGNER_B_ENVELOPE_HPKE_PUBLIC_KEY',
          ),
        },
      },
    },
    signer_peer_verifying_keys: {
      deriver_a: {
        role: 'signer_a',
        verifying_key_hex: requireLocalEnvString(
          env.SIGNER_A_PEER_VERIFYING_KEY_HEX,
          'SIGNER_A_PEER_VERIFYING_KEY_HEX',
        ),
      },
      deriver_b: {
        role: 'signer_b',
        verifying_key_hex: requireLocalEnvString(
          env.SIGNER_B_PEER_VERIFYING_KEY_HEX,
          'SIGNER_B_PEER_VERIFYING_KEY_HEX',
        ),
      },
    },
    signing_worker_server_output_hpke: {
      key_epoch: requireLocalEnvString(
        env.SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH,
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_KEY_EPOCH',
      ),
      public_key: requireLocalEnvString(
        env.SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY,
        'SIGNING_WORKER_SERVER_OUTPUT_HPKE_PUBLIC_KEY',
      ),
    },
  });
}

async function assertD1Tables(input: {
  readonly database: D1DatabaseLike;
  readonly label: 'CONSOLE_DB' | 'SIGNER_DB';
  readonly tables: readonly string[];
}): Promise<number> {
  const row = await input.database
    .prepare(
      `SELECT COUNT(*) AS table_count
         FROM sqlite_master
        WHERE type = 'table'
          AND name IN (${d1StringList(input.tables)})`,
    )
    .first<TableCountRow>();
  const count = parseReadyTableCount(row);
  if (count !== input.tables.length) {
    throw new Error(
      `local ${input.label} migration has created ${count} of ${input.tables.length} required tables`,
    );
  }
  return count;
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

async function assertLocalD1Schemas(env: LocalD1DevEnv): Promise<ReadyD1SchemaResult> {
  const consoleTables = await assertD1Tables({
    database: env.CONSOLE_DB,
    label: 'CONSOLE_DB',
    tables: CONSOLE_READY_TABLES,
  });
  const signerTables = await assertD1Tables({
    database: env.SIGNER_DB,
    label: 'SIGNER_DB',
    tables: SIGNER_READY_TABLES,
  });
  return { consoleTables, signerTables };
}

function normalSigningLifecycleId(input: RouterAbNormalSigningAdmissionInput): string {
  const authority = normalSigningAuthority(input);
  const base = [
    input.curve,
    input.phase,
    input.walletId,
    authority,
    input.thresholdSessionId,
    input.signingGrantId,
    input.requestId,
    input.signingWorkerId,
  ];
  return input.curve === 'ecdsa-hss' ? [...base, input.keyHandle].join(':') : base.join(':');
}

function normalSigningAuthority(input: RouterAbNormalSigningAdmissionInput): string {
  switch (input.curve) {
    case 'ed25519':
    return input.authorityScope.kind === 'passkey_rp'
      ? `passkey_rp:${input.authorityScope.rpId}`
      : `${input.authorityScope.kind}:${input.authorityScope.provider}:${input.authorityScope.providerUserId}`;
    case 'ecdsa-hss':
      return input.evmFamilySigningKeySlotId;
  }
  input satisfies never;
  throw new Error('Unsupported local D1/DO admission smoke curve');
}

async function handleReady(env: LocalD1DevEnv): Promise<Response> {
  const schemas = await assertLocalD1Schemas(env);
  const admission = await runD1DoAdmissionSmoke(env);
  return jsonResponse({
    ok: true,
    backend: 'cloudflare_d1_do',
    namespace: localTenantStorageNamespace(env),
    schemas,
    bindings: {
      console: 'CONSOLE_DB',
      signer: 'SIGNER_DB',
      thresholdStore: 'THRESHOLD_STORE',
    },
    admission,
  });
}

async function handleLocalRouterAbEd25519Seed(
  request: Request,
  env: LocalD1DevEnv,
): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonResponse(
      { ok: false, code: 'method_not_allowed', message: 'method not allowed' },
      { status: 405 },
    );
  }
  if (!hasLocalRouterAbInternalServiceAuth(request, env)) {
    return jsonResponse(
      {
        ok: false,
        code: 'unauthorized',
        message: 'local Router A/B internal service-auth header is invalid',
      },
      { status: 401 },
    );
  }
  const body = parseJsonObject(await request.text());
  if (!body) {
    return jsonResponse(
      { ok: false, code: 'invalid_body', message: 'seed body must be a JSON object' },
      { status: 400 },
    );
  }
  if (body.recoveryExportCapable !== true) {
    return jsonResponse(
      {
        ok: false,
        code: 'invalid_body',
        message: 'seed body recoveryExportCapable must be true',
      },
      { status: 400 },
    );
  }
  const service = createLocalD1RouterApiAuthService(env);
  const threshold = service.thresholdRuntime.getThresholdSigningService();
  if (!threshold) {
    return jsonResponse(
      { ok: false, code: 'not_configured', message: 'threshold service is not configured' },
      { status: 501 },
    );
  }
  const seeded = await threshold.seedLocalRouterAbEd25519NormalSigningSession({
    relayerKeyId: requireOptionalString(body.relayerKeyId, ''),
    walletId: requireOptionalString(body.walletId, ''),
    nearAccountId: requireOptionalString(body.nearAccountId, ''),
    nearEd25519SigningKeyId: requireOptionalString(body.nearEd25519SigningKeyId, ''),
    rpId: requireOptionalString(body.rpId, ''),
    thresholdSessionId: requireOptionalString(body.thresholdSessionId, ''),
    signingGrantId: requireOptionalString(body.signingGrantId, ''),
    publicKey: requireOptionalString(body.publicKey, ''),
    relayerSigningShareB64u: requireOptionalString(body.relayerSigningShareB64u, ''),
    keyVersion: requireOptionalString(body.keyVersion, ''),
    thresholdExpiresAtMs: Number(body.thresholdExpiresAtMs),
    participantIds: Array.isArray(body.participantIds) ? body.participantIds.map(Number) : [],
    remainingUses: Number(body.remainingUses),
    recoveryExportCapable: true,
  });
  return jsonResponse(seeded, { status: seeded.ok ? 200 : seeded.code === 'internal' ? 500 : 400 });
}

async function handleLocalRouterAbEcdsaHssSeed(
  request: Request,
  env: LocalD1DevEnv,
): Promise<Response> {
  if (request.method !== 'POST') {
    return jsonResponse(
      { ok: false, code: 'method_not_allowed', message: 'method not allowed' },
      { status: 405 },
    );
  }
  if (!hasLocalRouterAbInternalServiceAuth(request, env)) {
    return jsonResponse(
      {
        ok: false,
        code: 'unauthorized',
        message: 'local Router A/B internal service-auth header is invalid',
      },
      { status: 401 },
    );
  }
  const body = parseJsonObject(await request.text());
  if (!body) {
    return jsonResponse(
      { ok: false, code: 'invalid_body', message: 'seed body must be a JSON object' },
      { status: 400 },
    );
  }
  const service = createLocalD1RouterApiAuthService(env);
  const threshold = service.thresholdRuntime.getThresholdSigningService();
  if (!threshold) {
    return jsonResponse(
      { ok: false, code: 'not_configured', message: 'threshold service is not configured' },
      { status: 501 },
    );
  }
  const seeded = await threshold.seedLocalRouterAbEcdsaHssNormalSigningSession({
    walletId: requireOptionalString(body.walletId, ''),
    evmFamilySigningKeySlotId: requireOptionalString(body.evmFamilySigningKeySlotId, ''),
    ecdsaThresholdKeyId: requireOptionalString(body.ecdsaThresholdKeyId, ''),
    signingRootId: requireOptionalString(body.signingRootId, ''),
    signingRootVersion: requireOptionalString(body.signingRootVersion, ''),
    walletKeyVersion: requireOptionalString(body.walletKeyVersion, ''),
    derivationVersion: Number(body.derivationVersion),
    relayerKeyId: requireOptionalString(body.relayerKeyId, ''),
    thresholdSessionId: requireOptionalString(body.thresholdSessionId, ''),
    signingGrantId: requireOptionalString(body.signingGrantId, ''),
    thresholdExpiresAtMs: Number(body.thresholdExpiresAtMs),
    participantIds: Array.isArray(body.participantIds) ? body.participantIds.map(Number) : [],
    remainingUses: Number(body.remainingUses),
  });
  return jsonResponse(seeded, { status: seeded.ok ? 200 : seeded.code === 'internal' ? 500 : 400 });
}

async function fetch(
  request: Request,
  env: LocalD1DevEnv,
  ctx: CfExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === '/healthz') return jsonResponse({ ok: true });
  if (url.pathname === '/readyz') return await handleReady(env);
  if (url.pathname === LOCAL_ROUTER_AB_ED25519_SEED_PATH) {
    return await handleLocalRouterAbEd25519Seed(request, env);
  }
  if (url.pathname === LOCAL_ROUTER_AB_ECDSA_HSS_SEED_PATH) {
    return await handleLocalRouterAbEcdsaHssSeed(request, env);
  }
  if (isConsolePath(url.pathname)) {
    const handler = await localConsoleHandler(env);
    return await handler(request, env, ctx);
  }
  if (isRouterApiPath(url.pathname)) {
    const handler = await localRouterApiHandler(env);
    return await handler(routerApiRequest(request, url.pathname), env, ctx);
  }
  return jsonResponse(
    {
      ok: true,
      service: 'seams-sdk-d1-local',
      endpoints: [
        '/healthz',
        '/readyz',
        '/console/healthz',
        '/console/readyz',
        '/console/*',
        '/relay/healthz',
        '/relay/readyz',
        '/auth/google/options',
        '/session/exchange',
        '/session/state',
        '/sponsorships/evm/call',
        '/wallet-session/seal/apply-server-seal',
        '/wallet-session/seal/remove-server-seal',
        '/v1/registration/bootstrap-grants',
      ],
    },
    { status: 200 },
  );
}

export default { fetch };
