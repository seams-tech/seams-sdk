import type {
  RouterApiKeyAuthAdapter,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiProjectEnvironmentResolver,
  RouterApiUsageMeterAdapter,
} from '@seams/wallet-server/cloud-host';
import {
  WALLET_CONSOLE_OP_PATHS_V1,
  WALLET_CONSOLE_SERVICE_ORIGIN_V1,
  type WalletConsoleTenantRootActiveLineageResolverV1,
  type WalletConsoleTenantRootActiveLineageV1,
  type WalletConsoleTenantRootActiveLineageRequestV1,
} from './walletConsoleOps';

/** The shape of a Cloudflare service binding (`Fetcher`). */
export interface WalletConsoleServiceBinding {
  fetch(input: Request | string, init?: RequestInit): Promise<Response>;
}

export interface WalletConsoleOpsClient {
  readonly apiKeyAuth: RouterApiKeyAuthAdapter;
  readonly publishableKeyAuth: RouterApiPublishableKeyAuthAdapter;
  readonly usageMeter: RouterApiUsageMeterAdapter;
  readonly projectEnvironments: RouterApiProjectEnvironmentResolver;
  readonly tenantRootActiveLineage: WalletConsoleTenantRootActiveLineageResolverV1;
}

// The origin is never routable: service bindings dispatch on the bound Worker,
// not DNS. It only namespaces the internal request URL.
async function postJson(
  service: WalletConsoleServiceBinding,
  path: string,
  body: unknown,
): Promise<{ status: number; body: Record<string, unknown> }> {
  const response = await service.fetch(`${WALLET_CONSOLE_SERVICE_ORIGIN_V1}${path}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  const parsed: unknown = await response.json().catch(() => null);
  const record =
    parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  return { status: response.status, body: record };
}

function failureFrom(
  status: number,
  body: Record<string, unknown>,
  fallbackCode: string,
): { ok: false; status: 401 | 403; code: never; message: string } {
  return {
    ok: false,
    status: status === 403 ? 403 : 401,
    code: (String(body.code || fallbackCode) || fallbackCode) as never,
    message: String(body.message || 'Wallet Console authentication failed'),
  };
}

function responseStringField(body: Record<string, unknown>, field: string): string | null {
  const value = body[field];
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) return null;
  return value;
}

function parseTenantRootActiveLineageResponse(
  body: Record<string, unknown>,
): WalletConsoleTenantRootActiveLineageV1 | null {
  if (body.ok !== true) return null;
  const identityDigestB64u = responseStringField(body, 'identityDigestB64u');
  const custodyLineageB64u = responseStringField(body, 'custodyLineageB64u');
  if (!identityDigestB64u || !custodyLineageB64u) return null;
  return { identityDigestB64u, custodyLineageB64u };
}

/**
 * Gateway-side client for the private Wallet Console service binding. The
 * Wallet Gateway composes its Router API key auth and usage metering through
 * this client instead of a Console database binding.
 */
export function createWalletConsoleOpsClient(
  service: WalletConsoleServiceBinding,
): WalletConsoleOpsClient {
  return {
    apiKeyAuth: {
      async authenticate(input) {
        const { status, body } = await postJson(
          service,
          WALLET_CONSOLE_OP_PATHS_V1.secretKeyAuth,
          input,
        );
        if (body.ok === true && body.principal) {
          return { ok: true, principal: body.principal as never };
        }
        return failureFrom(status, body, 'secret_key_invalid');
      },
    },
    publishableKeyAuth: {
      async authenticate(input) {
        const { status, body } = await postJson(
          service,
          WALLET_CONSOLE_OP_PATHS_V1.publishableKeyAuth,
          input,
        );
        if (body.ok === true && body.principal) {
          return { ok: true, principal: body.principal as never };
        }
        return failureFrom(status, body, 'publishable_key_invalid');
      },
    },
    projectEnvironments: {
      async listEnvironments(context, filters) {
        const { status, body } = await postJson(
          service,
          WALLET_CONSOLE_OP_PATHS_V1.projectEnvironments,
          { context, ...(filters ? { filters } : {}) },
        );
        if (body.ok !== true || !Array.isArray(body.environments)) {
          throw new Error(
            `Wallet Console environment resolution failed (HTTP ${status}): ${String(
              body.message || body.code || 'unknown error',
            )}`,
          );
        }
        return body.environments as never;
      },
    },
    tenantRootActiveLineage: {
      async resolveActiveLineage(
        identity: WalletConsoleTenantRootActiveLineageRequestV1,
      ): Promise<WalletConsoleTenantRootActiveLineageV1 | null> {
        const { status, body } = await postJson(
          service,
          WALLET_CONSOLE_OP_PATHS_V1.tenantRootActiveLineage,
          identity,
        );
        if (status === 404 && body.code === 'tenant_root_active_lineage_not_found') {
          return null;
        }
        const lineage = parseTenantRootActiveLineageResponse(body);
        if (lineage) return lineage;
        throw new Error(
          `Wallet Console tenant-root active-lineage resolution failed (HTTP ${status}): ${String(
            body.message || body.code || 'invalid response',
          )}`,
        );
      },
    },
    usageMeter: {
      async recordEvent(input) {
        const { status, body } = await postJson(
          service,
          WALLET_CONSOLE_OP_PATHS_V1.usageEvents,
          input,
        );
        if (body.ok !== true) {
          throw new Error(
            `Wallet Console usage ingestion failed (HTTP ${status}): ${String(
              body.message || body.code || 'unknown error',
            )}`,
          );
        }
      },
    },
  };
}
