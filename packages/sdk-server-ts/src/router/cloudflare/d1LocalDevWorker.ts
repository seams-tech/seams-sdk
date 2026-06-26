import type { RouterAbNormalSigningAdmissionInput } from '../routerAbPrivateSigningWorker';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import type { CfExecutionContext } from './cloudflare.types';
import { ThresholdStoreDurableObject } from './durableObjects/thresholdStore';
import type {
  CloudflareDurableObjectNamespaceLike,
  CloudflareDurableObjectStubLike,
} from '../../core/types';

export { ThresholdStoreDurableObject };

interface LocalD1DevEnv {
  readonly CONSOLE_DB: D1DatabaseLike;
  readonly SIGNER_DB: D1DatabaseLike;
  readonly THRESHOLD_STORE: CloudflareDurableObjectNamespaceLike;
  readonly SEAMS_TENANT_STORAGE_NAMESPACE?: string;
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
  'console_billing_prepaid_reservations',
  'console_sponsorship_spend_cap_windows',
  'console_sponsorship_spend_cap_reservations',
  'console_sponsored_call_records',
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
  _ctx: CfExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === '/healthz') return jsonResponse({ ok: true });
  if (url.pathname === '/readyz') return await handleReady(env);
  return jsonResponse(
    {
      ok: true,
      service: 'seams-sdk-d1-local',
      endpoints: ['/healthz', '/readyz'],
    },
    { status: 200 },
  );
}

export default { fetch };
