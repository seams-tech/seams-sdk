import type { ConsoleOrgProjectEnvService } from '@seams-internal/console-server/orgProjectEnv/service';
import type { ConsoleAuthAdapter } from '@seams-internal/console-server/router/consoleAuth';
import { authenticateConsoleRequest } from '@seams-internal/console-server/router/consoleAuth';
import { createConsoleRouteDefinitions } from '@seams-internal/console-server/router/consoleRouteDefinitions';
import { authorizeConsoleRouteRequest } from '@seams-internal/console-server/router/consoleRoutePolicy';
import { headersToRecord } from '@seams/wallet-server/cloud-host';
import { ROUTER_AB_MPC_ROUTER_ORIGIN } from '../router/cloudflare/routerAbServiceBindings';
import {
  randomTenantRootCreationGrantBytesV1,
  signTenantRootCreationGrantV1,
  tenantRootIdentityDigestB64uV1,
} from './grantSigner';
import { isTenantRootCreationGrantStoreError } from './service';
import type { TenantRootCreationGrantServiceV1 } from './service';
import type { TenantRootCreationGrantRecordV1, TenantRootIdentityV1 } from './types';

export const TENANT_ROOT_CREATION_CONSOLE_PATH_V1 = '/console/tenant-root/creation';
export const TENANT_ROOT_REFRESH_CONSOLE_PATH_V1 = '/console/tenant-root/refresh';
const TENANT_ROOT_CREATION_ROUTER_PATH_V1 = '/router-ab/internal/tenant-root/creation/v1/create';
const TENANT_ROOT_REFRESH_ROUTER_PATH_V1 = '/router-ab/internal/tenant-root/refresh/v1/execute';
const INTERNAL_SERVICE_AUTH_HEADER = 'x-router-ab-internal-service-auth';

export interface TenantRootCreationConsoleRouteDependenciesV1 {
  readonly auth: ConsoleAuthAdapter;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly grants: TenantRootCreationGrantServiceV1;
  readonly router: { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
  readonly internalServiceAuthSecret: string;
  readonly grantAuthorityKeyId: string;
  readonly grantAuthoritySigningSeedB64u: string;
  readonly now?: () => Date;
}

export interface TenantRootRefreshConsoleRouteDependenciesV1 {
  readonly auth: ConsoleAuthAdapter;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly grants: Pick<TenantRootCreationGrantServiceV1, 'findActiveLineageByIdentity'>;
  readonly router: { fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> };
  readonly internalServiceAuthSecret: string;
}

type RouterCreationReadyResponseV1 = {
  readonly identityDigestB64u: string;
  readonly custodyLineageB64u: string;
  readonly revision: number;
  readonly journalDigestB64u: string;
  readonly capabilityDigestB64u: string;
  readonly rootCommitmentB64u: string;
  readonly replayed: boolean;
};

type RouterTenantRootRefreshResponseV1 = {
  readonly activationReceiptDigestB64u: string;
  readonly lifecycleRevision: number;
};

export type TenantRootRefreshRouterRequestV1 = {
  readonly refresh_operation_id: string;
  readonly identity_digest_b64u: string;
  readonly custody_lineage_b64u: string;
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

function hasControlCharacters(value: string): boolean {
  for (const character of value) {
    const codePoint = character.codePointAt(0) ?? 0;
    if (codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f)) return true;
  }
  return false;
}

function requiredText(value: unknown, label: string): string {
  const text = typeof value === 'string' ? value : '';
  if (
    !text ||
    text.trim() !== text ||
    new TextEncoder().encode(text).length > 256 ||
    hasControlCharacters(text)
  ) {
    throw new Error(`${label} is invalid`);
  }
  return text;
}

async function parseOperationId(request: Request): Promise<string> {
  const value: unknown = await request.json().catch(() => null);
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('JSON body is required');
  }
  const record = value as Record<string, unknown>;
  if (Object.keys(record).length !== 1 || !Object.hasOwn(record, 'operationId')) {
    throw new Error('Request must contain only operationId');
  }
  return requiredText(record.operationId, 'operationId');
}

function sameIdentity(left: TenantRootIdentityV1, right: TenantRootIdentityV1): boolean {
  return (
    left.orgId === right.orgId &&
    left.projectId === right.projectId &&
    left.envId === right.envId &&
    left.signingRootId === right.signingRootId &&
    left.signingRootVersion === right.signingRootVersion
  );
}

function parseRouterCreationReadyResponse(value: unknown): RouterCreationReadyResponseV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Router returned an invalid tenant-root creation response');
  }
  const record = value as Record<string, unknown>;
  const status = record.status;
  if (!status || typeof status !== 'object' || Array.isArray(status)) {
    throw new Error('Router tenant-root creation did not return a status');
  }
  const statusRecord = status as Record<string, unknown>;
  if (statusRecord.kind !== 'ready') {
    throw new Error('Router tenant-root creation did not reach ready state');
  }
  const revision = Number(record.revision);
  if (!Number.isSafeInteger(revision) || revision <= 0) {
    throw new Error('Router tenant-root creation returned an invalid revision');
  }
  return {
    identityDigestB64u: requiredText(record.identity_digest_b64u, 'identity_digest_b64u'),
    custodyLineageB64u: requiredText(record.custody_lineage_b64u, 'custody_lineage_b64u'),
    revision,
    journalDigestB64u: requiredText(record.journal_digest_b64u, 'journal_digest_b64u'),
    capabilityDigestB64u: requiredText(record.capability_digest_b64u, 'capability_digest_b64u'),
    rootCommitmentB64u: requiredText(statusRecord.root_commitment_b64u, 'root_commitment_b64u'),
    replayed: record.replayed === true,
  };
}

async function resolveIdentity(
  dependencies: Pick<TenantRootCreationConsoleRouteDependenciesV1, 'orgProjectEnv'>,
  claims: Extract<
    Awaited<ReturnType<typeof authenticateConsoleRequest>>,
    { readonly ok: true }
  >['claims'],
): Promise<TenantRootIdentityV1> {
  const projectId = requiredText(claims.projectId, 'authenticated projectId');
  const environmentId = requiredText(claims.environmentId, 'authenticated environmentId');
  const environments = await dependencies.orgProjectEnv.listEnvironments(
    {
      orgId: claims.orgId,
      actorUserId: claims.userId,
      projectId,
      environmentId,
    },
    { projectId, status: 'ACTIVE' },
  );
  const environment = environments.find(
    (candidate) => candidate.id === environmentId && candidate.projectId === projectId,
  );
  if (!environment) {
    throw new Error('Authenticated Console environment is not active');
  }
  return {
    orgId: claims.orgId,
    projectId,
    envId: environment.key,
    signingRootId: `${projectId}:${environment.key}`,
    signingRootVersion: environment.runtimeVersion,
  };
}

function parseRouterTenantRootRefreshResponse(value: unknown): RouterTenantRootRefreshResponseV1 {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Router returned an invalid tenant-root refresh response');
  }
  const record = value as Record<string, unknown>;
  const lifecycleRevision = Number(record.lifecycle_revision);
  if (!Number.isSafeInteger(lifecycleRevision) || lifecycleRevision <= 0) {
    throw new Error('Router tenant-root refresh returned an invalid lifecycle revision');
  }
  return {
    activationReceiptDigestB64u: requiredText(
      record.activation_receipt_digest_b64u,
      'activation_receipt_digest_b64u',
    ),
    lifecycleRevision,
  };
}

async function issueGrant(
  dependencies: TenantRootCreationConsoleRouteDependenciesV1,
  operationId: string,
  identity: TenantRootIdentityV1,
): Promise<{ readonly record: TenantRootCreationGrantRecordV1; readonly replayed: boolean }> {
  const existing = await dependencies.grants.findGrantByOperationId(operationId);
  if (existing) {
    if (!sameIdentity(existing.identity, identity)) {
      throw new Error('Tenant-root creation operation belongs to a different authenticated scope');
    }
    return { record: existing, replayed: true };
  }
  const nowMs = (dependencies.now ?? (() => new Date()))().getTime();
  const issuedAtMs = Math.max(1, nowMs - 1);
  const signed = await signTenantRootCreationGrantV1({
    identity,
    custodyLineage: randomTenantRootCreationGrantBytesV1(16),
    grantNonce: randomTenantRootCreationGrantBytesV1(32),
    issuedAtMs,
    expiresAtMs: issuedAtMs + 300_000,
    grantKeyId: requiredText(dependencies.grantAuthorityKeyId, 'grantAuthorityKeyId'),
    signingSeedB64u: requiredText(
      dependencies.grantAuthoritySigningSeedB64u,
      'grantAuthoritySigningSeedB64u',
    ),
  });
  const record = await dependencies.grants.putOrGetGrant({
    operationId,
    identity,
    ...signed,
  });
  if (!sameIdentity(record.identity, identity)) {
    throw new Error('Tenant-root creation operation resolved to a different authenticated scope');
  }
  return { record, replayed: false };
}

async function createAtRouter(
  dependencies: TenantRootCreationConsoleRouteDependenciesV1,
  record: TenantRootCreationGrantRecordV1,
): Promise<RouterCreationReadyResponseV1> {
  const response = await dependencies.router.fetch(
    `${ROUTER_AB_MPC_ROUTER_ORIGIN}${TENANT_ROOT_CREATION_ROUTER_PATH_V1}`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        [INTERNAL_SERVICE_AUTH_HEADER]: requiredText(
          dependencies.internalServiceAuthSecret,
          'internalServiceAuthSecret',
        ),
      },
      body: JSON.stringify({ creation_grant_b64u: record.grantB64u }),
    },
  );
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      body && typeof body === 'object' && !Array.isArray(body)
        ? String((body as Record<string, unknown>).message ?? response.statusText)
        : response.statusText;
    throw new Error(`Router tenant-root creation failed (HTTP ${response.status}): ${message}`);
  }
  return parseRouterCreationReadyResponse(body);
}

async function refreshAtRouter(
  dependencies: TenantRootRefreshConsoleRouteDependenciesV1,
  operationId: string,
  identityDigestB64u: string,
  custodyLineageB64u: string,
): Promise<RouterTenantRootRefreshResponseV1> {
  const routerRequest: TenantRootRefreshRouterRequestV1 = {
    refresh_operation_id: operationId,
    identity_digest_b64u: identityDigestB64u,
    custody_lineage_b64u: custodyLineageB64u,
  };
  const response = await dependencies.router.fetch(
    `${ROUTER_AB_MPC_ROUTER_ORIGIN}${TENANT_ROOT_REFRESH_ROUTER_PATH_V1}`,
    {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        [INTERNAL_SERVICE_AUTH_HEADER]: requiredText(
          dependencies.internalServiceAuthSecret,
          'internalServiceAuthSecret',
        ),
      },
      body: JSON.stringify(routerRequest),
    },
  );
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message =
      body && typeof body === 'object' && !Array.isArray(body)
        ? String((body as Record<string, unknown>).message ?? response.statusText)
        : response.statusText;
    throw new Error(`Router tenant-root refresh failed (HTTP ${response.status}): ${message}`);
  }
  return parseRouterTenantRootRefreshResponse(body);
}

export function createTenantRootCreationConsoleRouteV1(
  dependencies: TenantRootCreationConsoleRouteDependenciesV1,
): (request: Request) => Promise<Response | null> {
  const definitions = createConsoleRouteDefinitions();
  return async (request) => {
    const url = new URL(request.url);
    if (url.pathname !== TENANT_ROOT_CREATION_CONSOLE_PATH_V1) return null;
    if (request.method !== 'POST') {
      return json({ ok: false, code: 'method_not_allowed', message: 'Method not allowed' }, 405);
    }
    const auth = await authenticateConsoleRequest(
      headersToRecord(request.headers),
      dependencies.auth,
    );
    if (!auth.ok) return json({ ok: false, code: auth.code, message: auth.message }, auth.status);
    const authorization = authorizeConsoleRouteRequest({
      claims: auth.claims,
      definitions,
      method: request.method,
      pathname: url.pathname,
      ...(auth.claims.projectId ? { projectId: auth.claims.projectId } : {}),
    });
    if (!authorization.ok) return json(authorization.body, authorization.status);

    try {
      const operationId = await parseOperationId(request);
      const identity = await resolveIdentity(dependencies, auth.claims);
      const issued = await issueGrant(dependencies, operationId, identity);
      if (issued.record.status === 'ACTIVE') {
        return json({ ok: true, status: 'ACTIVE', replayed: true });
      }
      const ready = await createAtRouter(dependencies, issued.record);
      if (
        ready.identityDigestB64u !== issued.record.identityDigestB64u ||
        ready.custodyLineageB64u !== issued.record.custodyLineageB64u
      ) {
        throw new Error('Router tenant-root creation response changed the issued identity');
      }
      await dependencies.grants.markActiveFromReady({
        operationId,
        identity,
        identityDigestB64u: issued.record.identityDigestB64u,
        custodyLineageB64u: issued.record.custodyLineageB64u,
        ready: {
          revision: ready.revision,
          rootCommitmentB64u: ready.rootCommitmentB64u,
          journalDigestB64u: ready.journalDigestB64u,
          capabilityDigestB64u: ready.capabilityDigestB64u,
        },
      });
      return json({ ok: true, status: 'ACTIVE', replayed: issued.replayed || ready.replayed });
    } catch (error: unknown) {
      if (isTenantRootCreationGrantStoreError(error)) {
        return json({ ok: false, code: error.code, message: error.message }, error.statusCode);
      }
      return json(
        {
          ok: false,
          code: 'tenant_root_creation_failed',
          message: error instanceof Error ? error.message : 'Tenant-root creation failed',
        },
        502,
      );
    }
  };
}

export function createTenantRootRefreshConsoleRouteV1(
  dependencies: TenantRootRefreshConsoleRouteDependenciesV1,
): (request: Request) => Promise<Response | null> {
  const definitions = createConsoleRouteDefinitions();
  return async (request) => {
    const url = new URL(request.url);
    if (url.pathname !== TENANT_ROOT_REFRESH_CONSOLE_PATH_V1) return null;
    if (request.method !== 'POST') {
      return json({ ok: false, code: 'method_not_allowed', message: 'Method not allowed' }, 405);
    }
    const auth = await authenticateConsoleRequest(
      headersToRecord(request.headers),
      dependencies.auth,
    );
    if (!auth.ok) return json({ ok: false, code: auth.code, message: auth.message }, auth.status);
    const authorization = authorizeConsoleRouteRequest({
      claims: auth.claims,
      definitions,
      method: request.method,
      pathname: url.pathname,
      ...(auth.claims.projectId ? { projectId: auth.claims.projectId } : {}),
    });
    if (!authorization.ok) return json(authorization.body, authorization.status);

    let operationId: string;
    try {
      operationId = await parseOperationId(request);
    } catch (error: unknown) {
      return json(
        {
          ok: false,
          code: 'invalid_request',
          message: error instanceof Error ? error.message : 'Refresh operationId is invalid',
        },
        400,
      );
    }

    try {
      const identity = await resolveIdentity(dependencies, auth.claims);
      const identityDigestB64u = await tenantRootIdentityDigestB64uV1(identity);
      const active = await dependencies.grants.findActiveLineageByIdentity({
        identity,
        identityDigestB64u,
      });
      if (!active || active.status !== 'ACTIVE') {
        return json(
          {
            ok: false,
            code: 'tenant_root_not_active',
            message: 'Authenticated Console environment has no active tenant root',
          },
          409,
        );
      }
      const refreshed = await refreshAtRouter(
        dependencies,
        operationId,
        identityDigestB64u,
        active.custodyLineageB64u,
      );
      return json({
        ok: true,
        status: 'ACTIVE',
        activationReceiptDigestB64u: refreshed.activationReceiptDigestB64u,
        lifecycleRevision: refreshed.lifecycleRevision,
      });
    } catch (error: unknown) {
      if (isTenantRootCreationGrantStoreError(error)) {
        return json({ ok: false, code: error.code, message: error.message }, error.statusCode);
      }
      return json(
        {
          ok: false,
          code: 'tenant_root_refresh_failed',
          message: error instanceof Error ? error.message : 'Tenant-root refresh failed',
        },
        502,
      );
    }
  };
}
