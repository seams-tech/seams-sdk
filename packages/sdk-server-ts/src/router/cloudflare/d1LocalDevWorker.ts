import type { RouterAbNormalSigningAdmissionInput } from '../routerAbPrivateSigningWorker';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import type { ConsoleAuthAdapter, ConsoleAuthClaims, HeaderRecord } from '../console';
import type { SigningRootKekProvider } from '../../core/ThresholdService/signingRootKekProvider';
import type { CfExecutionContext, FetchHandler } from './cloudflare.types';
import { ThresholdStoreDurableObject } from './durableObjects/thresholdStore';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../core/types';
import { createCloudflareRouter } from './createCloudflareRouter';
import { createCloudflareConsoleRouter } from './createCloudflareConsoleRouter';
import { createCloudflareD1ConsoleServiceBundle } from './d1ConsoleServices';
import {
  createCloudflareD1RelayAuthService,
  type CloudflareD1EmailOtpServerSealConfig,
  type CloudflareD1OidcExchangeConfig,
  type CloudflareD1OidcExchangeIssuerConfig,
} from './d1RelayAuthService';
import {
  resolveSponsoredEvmCallConfigFromWorkerEnv,
  resolveSponsoredEvmWorkerExecutionAdapter,
} from '../../sponsorship/evmWorkerExecutionAdapter';

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
  readonly SEAMS_LOCAL_GOOGLE_OIDC_CLIENT_ID?: string;
  readonly SEAMS_LOCAL_OIDC_EXCHANGE_JSON?: string;
  readonly ROUTER_AB_NORMAL_SIGNING_WORKER_ID?: string;
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

type AdmissionDoOk<T> = { readonly ok: true; readonly value: T };
type AdmissionDoErr = { readonly ok: false; readonly code: string; readonly message: string };
type AdmissionDoResp<T> = AdmissionDoOk<T> | AdmissionDoErr;

const DEFAULT_LOCAL_CONSOLE_USER_ID = 'local-console-user';
const DEFAULT_LOCAL_CONSOLE_ORG_ID = 'local-smoke-org';
const DEFAULT_LOCAL_CONSOLE_PROJECT_ID = 'local-smoke-project';
const DEFAULT_LOCAL_CONSOLE_ENVIRONMENT_ID = 'local';
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
const LOCAL_RELAY_CORS_ORIGINS = Object.freeze(['http://127.0.0.1:8787', 'http://localhost:8787']);
const localConsoleHandlers = new WeakMap<LocalD1DevEnv, Promise<FetchHandler>>();
const localRelayHandlers = new WeakMap<LocalD1DevEnv, Promise<FetchHandler>>();

const CONSOLE_READY_TABLES = Object.freeze([
  'console_organizations',
  'console_projects',
  'console_environments',
  'console_team_members',
  'console_user_profiles',
  'console_user_backup_emails',
  'console_policies',
  'console_policy_versions',
  'console_policy_assignments',
  'console_wallet_index',
  'console_api_keys',
  'console_approvals',
  'console_key_exports',
  'console_webhook_endpoints',
  'console_webhook_endpoint_categories',
  'console_webhook_deliveries',
  'console_webhook_attempts',
  'console_webhook_dead_letters',
  'console_observability_events',
  'console_observability_event_dedup',
  'console_observability_ingest_windows',
  'console_observability_request_rollups_minute',
  'console_audit_events',
  'console_audit_evidence',
  'console_bootstrap_tokens',
  'console_billing_accounts',
  'console_billing_ledger_entries',
  'console_billing_ledger_postings',
  'console_billing_monthly_active_wallets',
  'console_billing_credit_purchases',
  'console_invoices',
  'console_invoice_line_items',
  'console_stripe_webhook_events',
  'console_billing_prepaid_reservation_summaries',
  'console_billing_prepaid_reservations',
  'console_sponsorship_spend_cap_windows',
  'console_sponsorship_spend_cap_reservations',
  'console_sponsored_call_records',
  'console_runtime_snapshots',
  'console_runtime_snapshot_outbox',
]);

const SIGNER_READY_TABLES = Object.freeze([
  'signer_signing_root_secret_shares',
  'signer_wallets',
  'signer_wallet_signers',
  'signer_wallet_auth_methods',
  'signer_webauthn_authenticators',
  'signer_webauthn_credential_bindings',
  'signer_webauthn_challenges',
  'signer_identity_links',
  'signer_app_session_versions',
  'signer_recovery_sessions',
  'signer_recovery_executions',
  'signer_near_public_keys',
  'signer_email_recovery_preparations',
  'signer_email_otp_challenges',
  'signer_email_otp_grants',
  'signer_email_otp_wallet_enrollments',
  'signer_email_otp_recovery_wrapped_enrollment_escrows',
  'signer_email_otp_auth_states',
  'signer_email_otp_unlock_challenges',
  'signer_email_otp_registration_attempts',
  'signer_email_otp_rate_limits',
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

function localConsoleAuthClaims(
  env: LocalD1DevEnv,
  headers: HeaderRecord,
): ConsoleAuthClaims {
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

function localSigningRootKekProvider(env: LocalD1DevEnv): SigningRootKekProvider {
  const kekId =
    normalizeLocalString(env.SEAMS_LOCAL_SIGNING_ROOT_KEK_ID) ||
    DEFAULT_LOCAL_SIGNING_ROOT_KEK_ID;
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

function isConsolePath(pathname: string): boolean {
  return pathname === '/console' || pathname.startsWith('/console/');
}

function isRelayPath(pathname: string): boolean {
  return pathname === '/relay' || pathname.startsWith('/relay/');
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
  const existing = localConsoleHandlers.get(env);
  if (existing) return existing;
  const created = createLocalConsoleHandler(env);
  localConsoleHandlers.set(env, created);
  return created;
}

async function createLocalRelayHandler(env: LocalD1DevEnv): Promise<FetchHandler> {
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
  return createCloudflareRouter(createLocalD1RelayAuthService(env), {
    ...bundle.relayRouterOptions,
    healthz: true,
    readyz: true,
    corsOrigins: [...LOCAL_RELAY_CORS_ORIGINS],
    sponsoredEvmCall: {
      ...bundle.relayRouterOptions.sponsoredEvmCall,
      resolveExecutionAdapter: resolveSponsoredEvmWorkerExecutionAdapter,
    },
  });
}

function createLocalD1RelayAuthService(env: LocalD1DevEnv) {
  return createCloudflareD1RelayAuthService({
    database: env.SIGNER_DB,
    namespace: localTenantStorageNamespace(env),
    orgId:
      normalizeLocalString(env.SEAMS_LOCAL_CONSOLE_ORG_ID) || DEFAULT_LOCAL_CONSOLE_ORG_ID,
    projectId:
      normalizeLocalString(env.SEAMS_LOCAL_CONSOLE_PROJECT_ID) ||
      DEFAULT_LOCAL_CONSOLE_PROJECT_ID,
    envId:
      normalizeLocalString(env.SEAMS_LOCAL_CONSOLE_ENVIRONMENT_ID) ||
      DEFAULT_LOCAL_CONSOLE_ENVIRONMENT_ID,
    relayerAccount: env.SEAMS_LOCAL_RELAYER_ACCOUNT,
    relayerPublicKey: env.SEAMS_LOCAL_RELAYER_PUBLIC_KEY,
    googleOidcClientId: env.SEAMS_LOCAL_GOOGLE_OIDC_CLIENT_ID,
    oidcExchange: localOidcExchangeConfig(env),
    accountIdDerivationSecret: env.ACCOUNT_ID_DERIVATION_SECRET,
    emailOtpServerSeal: localEmailOtpServerSealConfig(env),
    emailOtpDeliveryMode: env.EMAIL_OTP_DELIVERY_MODE || 'memory',
    emailOtpDevOutboxEnabled: env.EMAIL_OTP_DEV_OUTBOX_ENABLED ?? true,
    emailOtpRecoveryKeyAttemptRateLimitMax:
      env.EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_MAX,
    emailOtpRecoveryKeyAttemptRateLimitWindowMs:
      env.EMAIL_OTP_RECOVERY_KEY_ATTEMPT_RATE_LIMIT_WINDOW_MS,
    emailOtpGoogleRegistrationAttemptRateLimitMax:
      env.EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_MAX,
    emailOtpGoogleRegistrationAttemptRateLimitWindowMs:
      env.EMAIL_OTP_GOOGLE_REGISTRATION_ATTEMPT_RATE_LIMIT_WINDOW_MS,
    thresholdStore: {
      kind: 'cloudflare-do',
      namespace: env.THRESHOLD_STORE,
      THRESHOLD_PREFIX: localTenantStorageNamespace(env),
      ROUTER_AB_NORMAL_SIGNING_WORKER_ID:
        normalizeLocalString(env.ROUTER_AB_NORMAL_SIGNING_WORKER_ID) ||
        'local-d1-threshold-signing-worker',
    },
  });
}

function localRelayHandler(env: LocalD1DevEnv): Promise<FetchHandler> {
  const existing = localRelayHandlers.get(env);
  if (existing) return existing;
  const created = createLocalRelayHandler(env);
  localRelayHandlers.set(env, created);
  return created;
}

function relayRequest(request: Request, pathname: string): Request {
  const url = new URL(request.url);
  const stripped = pathname === '/relay' ? '/' : pathname.slice('/relay'.length);
  url.pathname = stripped || '/';
  return new Request(url.toString(), request);
}

function localAdmissionInput(nowMs: number): RouterAbNormalSigningAdmissionInput {
  return {
    curve: 'ed25519',
    phase: 'prepare',
    walletId: 'local-smoke-wallet',
    rpId: 'localhost',
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

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
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
      return input.rpId;
    case 'ecdsa-hss':
      return input.walletKeyId;
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

async function fetch(
  request: Request,
  env: LocalD1DevEnv,
  ctx: CfExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === '/healthz') return jsonResponse({ ok: true });
  if (url.pathname === '/readyz') return await handleReady(env);
  if (isConsolePath(url.pathname)) {
    const handler = await localConsoleHandler(env);
    return await handler(request, env, ctx);
  }
  if (isRelayPath(url.pathname)) {
    const handler = await localRelayHandler(env);
    return await handler(relayRequest(request, url.pathname), env, ctx);
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
        '/relay/sponsorships/evm/call',
      ],
    },
    { status: 200 },
  );
}

export default { fetch };
