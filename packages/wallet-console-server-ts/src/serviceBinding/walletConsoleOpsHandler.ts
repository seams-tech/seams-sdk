import type {
  RouterApiKeyAuthAdapter,
  RouterApiPublishableKeyAuthAdapter,
  RouterApiUsageMeterAdapter,
} from '@seams/wallet-server/cloud-host';
import {
  WALLET_CONSOLE_OP_PATHS_V1,
  type WalletConsoleSecretKeyAuthRequestV1,
  type WalletConsolePublishableKeyAuthRequestV1,
  type WalletConsoleUsageEventV1,
} from './walletConsoleOps';

export interface WalletConsoleOpsHandlerServices {
  readonly apiKeyAuth: RouterApiKeyAuthAdapter;
  readonly publishableKeyAuth: RouterApiPublishableKeyAuthAdapter;
  readonly usageMeter: RouterApiUsageMeterAdapter;
}

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

/**
 * Console-side target of the private Wallet Console service binding. Serves
 * exactly the three declared operations; every other path under the internal
 * prefix is a 404 so the surface cannot grow silently.
 */
export function createWalletConsoleOpsHandler(
  services: WalletConsoleOpsHandlerServices,
): (request: Request) => Promise<Response | null> {
  return async (request: Request): Promise<Response | null> => {
    const pathname = new URL(request.url).pathname;
    if (!pathname.startsWith('/internal/wallet-console/')) return null;
    if (request.method !== 'POST') {
      return json({ ok: false, code: 'method_not_allowed', message: 'Method not allowed' }, 405);
    }

    if (pathname === WALLET_CONSOLE_OP_PATHS_V1.secretKeyAuth) {
      const body = await readJsonBody(request);
      if (!body) return json({ ok: false, code: 'invalid_body', message: 'JSON body required' }, 400);
      const input: WalletConsoleSecretKeyAuthRequestV1 = {
        secret: stringField(body, 'secret'),
        endpoint: stringField(body, 'endpoint'),
        requiredScopes: Array.isArray(body.requiredScopes)
          ? body.requiredScopes.map((scope) => String(scope ?? '').trim()).filter(Boolean)
          : [],
        ...(stringField(body, 'sourceIp') ? { sourceIp: stringField(body, 'sourceIp') } : {}),
        ...(stringField(body, 'environmentId')
          ? { environmentId: stringField(body, 'environmentId') }
          : {}),
      };
      const result = await services.apiKeyAuth.authenticate({
        secret: input.secret,
        endpoint: input.endpoint,
        requiredScopes: input.requiredScopes as never,
        ...(input.sourceIp ? { sourceIp: input.sourceIp } : {}),
        ...(input.environmentId ? { environmentId: input.environmentId } : {}),
      });
      return json(result, result.ok ? 200 : result.status);
    }

    if (pathname === WALLET_CONSOLE_OP_PATHS_V1.publishableKeyAuth) {
      const body = await readJsonBody(request);
      if (!body) return json({ ok: false, code: 'invalid_body', message: 'JSON body required' }, 400);
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
      if (!body) return json({ ok: false, code: 'invalid_body', message: 'JSON body required' }, 400);
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

    return json({ ok: false, code: 'not_found', message: 'Unknown wallet-console operation' }, 404);
  };
}
