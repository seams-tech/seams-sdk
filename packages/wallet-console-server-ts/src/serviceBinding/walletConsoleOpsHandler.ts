import type {
  RouterApiKeyAuthAdapter,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiProjectEnvironmentResolver,
  RouterApiUsageMeterAdapter,
} from '@seams/wallet-server/cloud-host';
import {
  isApiCredentialScope,
  type ApiCredentialScope,
} from '@seams-internal/wallet-console-shared/apiKeyScopes';
import {
  WALLET_CONSOLE_OP_PATHS_V1,
  WALLET_CONSOLE_SERVICE_ORIGIN_V1,
  type WalletConsoleSecretKeyAuthRequestV1,
  type WalletConsolePublishableKeyAuthRequestV1,
  type WalletConsoleTenantRootActiveLineageRequestV1,
  type WalletConsoleTenantRootActiveLineageResolverV1,
  type WalletConsoleUsageEventV1,
} from './walletConsoleOps';

export interface WalletConsoleOpsHandlerServices {
  readonly apiKeyAuth: RouterApiKeyAuthAdapter;
  readonly publishableKeyAuth: RouterApiPublishableKeyAuthAdapter;
  readonly usageMeter: RouterApiUsageMeterAdapter;
  readonly projectEnvironments: RouterApiProjectEnvironmentResolver;
  readonly tenantRootActiveLineage: WalletConsoleTenantRootActiveLineageResolverV1;
}

const TENANT_ROOT_IDENTITY_FIELDS = Object.freeze([
  'orgId',
  'projectId',
  'envId',
  'signingRootId',
  'signingRootVersion',
] as const);

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

async function readJsonBody(request: Request): Promise<Record<string, unknown> | null> {
  const body: unknown = await request.json().catch(() => null);
  if (!body || typeof body !== 'object' || Array.isArray(body)) return null;
  return body as Record<string, unknown>;
}

function stringField(body: Record<string, unknown>, field: string): string {
  return String(body[field] ?? '').trim();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactFields(value: Record<string, unknown>, fields: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === fields.length && fields.every((field) => Object.hasOwn(value, field));
}

function canonicalStringField(value: unknown): string | null {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) return null;
  return value;
}

function parseTenantRootActiveLineageRequest(
  value: unknown,
): WalletConsoleTenantRootActiveLineageRequestV1 | null {
  if (!isRecord(value) || !hasExactFields(value, TENANT_ROOT_IDENTITY_FIELDS)) return null;
  const orgId = canonicalStringField(value.orgId);
  const projectId = canonicalStringField(value.projectId);
  const envId = canonicalStringField(value.envId);
  const signingRootId = canonicalStringField(value.signingRootId);
  const signingRootVersion = canonicalStringField(value.signingRootVersion);
  if (!orgId || !projectId || !envId || !signingRootId || !signingRootVersion) return null;
  return { orgId, projectId, envId, signingRootId, signingRootVersion };
}

function parseRequiredScopes(value: unknown): ApiCredentialScope[] | null {
  if (!Array.isArray(value)) return null;
  const scopes: ApiCredentialScope[] = [];
  for (const candidate of value) {
    if (typeof candidate !== 'string') return null;
    const scope = candidate.trim();
    if (!isApiCredentialScope(scope)) return null;
    scopes.push(scope);
  }
  return scopes;
}

/**
 * Console-side target of the private Wallet Console service binding. Serves
 * exactly the five declared operations; every other path under the internal
 * prefix is a 404 so the surface cannot grow silently.
 */
export function createWalletConsoleOpsHandler(
  services: WalletConsoleOpsHandlerServices,
): (request: Request) => Promise<Response | null> {
  return async (request: Request): Promise<Response | null> => {
    const url = new URL(request.url);
    const pathname = url.pathname;
    if (!pathname.startsWith('/internal/wallet-console/')) return null;
    if (url.origin !== WALLET_CONSOLE_SERVICE_ORIGIN_V1) return null;
    if (request.method !== 'POST') {
      return json({ ok: false, code: 'method_not_allowed', message: 'Method not allowed' }, 405);
    }

    if (pathname === WALLET_CONSOLE_OP_PATHS_V1.secretKeyAuth) {
      const body = await readJsonBody(request);
      if (!body)
        return json({ ok: false, code: 'invalid_body', message: 'JSON body required' }, 400);
      const requiredScopes = parseRequiredScopes(body.requiredScopes);
      if (!requiredScopes) {
        return json(
          { ok: false, code: 'invalid_body', message: 'requiredScopes must contain known scopes' },
          400,
        );
      }
      const input: WalletConsoleSecretKeyAuthRequestV1 = {
        secret: stringField(body, 'secret'),
        endpoint: stringField(body, 'endpoint'),
        requiredScopes,
        ...(stringField(body, 'sourceIp') ? { sourceIp: stringField(body, 'sourceIp') } : {}),
        ...(stringField(body, 'environmentId')
          ? { environmentId: stringField(body, 'environmentId') }
          : {}),
      };
      const result = await services.apiKeyAuth.authenticate({
        secret: input.secret,
        endpoint: input.endpoint,
        requiredScopes: input.requiredScopes,
        ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
        ...(input.environmentId ? { environmentId: input.environmentId } : {}),
      });
      return json(result, result.ok ? 200 : result.status);
    }

    if (pathname === WALLET_CONSOLE_OP_PATHS_V1.publishableKeyAuth) {
      const body = await readJsonBody(request);
      if (!body)
        return json({ ok: false, code: 'invalid_body', message: 'JSON body required' }, 400);
      const input: WalletConsolePublishableKeyAuthRequestV1 = {
        secret: stringField(body, 'secret'),
        origin: stringField(body, 'origin'),
        environmentId: stringField(body, 'environmentId'),
      };
      const result = await services.publishableKeyAuth.authenticate(input);
      return json(result, result.ok ? 200 : result.status);
    }

    if (pathname === WALLET_CONSOLE_OP_PATHS_V1.usageEvents) {
      const body = await readJsonBody(request);
      if (!body)
        return json({ ok: false, code: 'invalid_body', message: 'JSON body required' }, 400);
      const event: WalletConsoleUsageEventV1 = {
        orgId: stringField(body, 'orgId'),
        environmentId: stringField(body, 'environmentId'),
        apiKeyId: stringField(body, 'apiKeyId'),
        endpoint: stringField(body, 'endpoint'),
        walletId: stringField(body, 'walletId'),
        action: 'wallet_created',
        succeeded: body.succeeded === true,
        ...(stringField(body, 'occurredAt') ? { occurredAt: stringField(body, 'occurredAt') } : {}),
        ...(stringField(body, 'sourceEventId')
          ? { sourceEventId: stringField(body, 'sourceEventId') }
          : {}),
      };
      if (!event.orgId || !event.environmentId || !event.apiKeyId || !event.walletId) {
        return json(
          { ok: false, code: 'invalid_body', message: 'Missing required usage event fields' },
          400,
        );
      }
      await services.usageMeter.recordEvent(event);
      return json({ ok: true });
    }

    if (pathname === WALLET_CONSOLE_OP_PATHS_V1.projectEnvironments) {
      const body = await readJsonBody(request);
      const context =
        body && body.context && typeof body.context === 'object' && !Array.isArray(body.context)
          ? (body.context as Record<string, unknown>)
          : null;
      if (!body || !context) {
        return json({ ok: false, code: 'invalid_body', message: 'JSON body required' }, 400);
      }
      const filters =
        body.filters && typeof body.filters === 'object' && !Array.isArray(body.filters)
          ? (body.filters as Record<string, unknown>)
          : undefined;
      const environments = await services.projectEnvironments.listEnvironments(
        {
          orgId: stringField(context, 'orgId'),
          actorUserId: stringField(context, 'actorUserId'),
          roles: Array.isArray(context.roles)
            ? context.roles.map((role) => String(role ?? '').trim()).filter(Boolean)
            : [],
          ...(stringField(context, 'environmentId')
            ? { environmentId: stringField(context, 'environmentId') }
            : {}),
          ...(stringField(context, 'projectId')
            ? { projectId: stringField(context, 'projectId') }
            : {}),
        },
        filters && stringField(filters, 'status')
          ? { status: stringField(filters, 'status') }
          : undefined,
      );
      return json({ ok: true, environments });
    }

    if (pathname === WALLET_CONSOLE_OP_PATHS_V1.tenantRootActiveLineage) {
      const body: unknown = await request.json().catch(() => null);
      const identity = parseTenantRootActiveLineageRequest(body);
      if (!identity) {
        return json(
          {
            ok: false,
            code: 'invalid_body',
            message: 'A complete canonical tenant-root identity is required',
          },
          400,
        );
      }
      const lineage = await services.tenantRootActiveLineage.resolveActiveLineage(identity);
      if (!lineage) {
        return json(
          {
            ok: false,
            code: 'tenant_root_active_lineage_not_found',
            message: 'No active tenant-root lineage exists for this identity',
          },
          404,
        );
      }
      return json({
        ok: true,
        identityDigestB64u: lineage.identityDigestB64u,
        custodyLineageB64u: lineage.custodyLineageB64u,
      });
    }

    return json({ ok: false, code: 'not_found', message: 'Unknown wallet-console operation' }, 404);
  };
}
