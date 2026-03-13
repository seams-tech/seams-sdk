import { expect, test } from '@playwright/test';
import { createCloudflareRouter } from '../../server/src/router/cloudflare/createCloudflareRouter';
import { createRelayRouter } from '../../server/src/router/express/createRelayRouter';
import { getRelayRouteSurface } from '../../server/src/router/relayRouteSurface';
import { makeFakeAuthService } from '../relayer/helpers';

type ExpressRouteEntry = {
  method: string;
  path: string;
};

function listExpressRoutes(router: unknown): ExpressRouteEntry[] {
  const entries: ExpressRouteEntry[] = [];

  const visitStack = (stack: unknown): void => {
    if (!Array.isArray(stack)) return;
    for (const layer of stack) {
      if (!layer || typeof layer !== 'object') continue;
      const route = (layer as { route?: { path?: unknown; methods?: Record<string, boolean> } }).route;
      if (route && typeof route.path === 'string' && route.methods) {
        for (const [method, enabled] of Object.entries(route.methods)) {
          if (!enabled) continue;
          entries.push({ method: method.toUpperCase(), path: route.path });
        }
      }
      const nested = (layer as { handle?: { stack?: unknown } }).handle?.stack;
      if (nested) visitStack(nested);
    }
  };

  visitStack((router as { stack?: unknown })?.stack);
  return entries;
}

function canonicalRouteKeys(input: { method: string; path: string; aliases?: readonly string[] }[]): string[] {
  return input.flatMap((route) => {
    const keys = [`${route.method} ${route.path}`];
    for (const alias of route.aliases || []) {
      keys.push(`${route.method} ${alias}`);
    }
    return keys;
  });
}

test.describe('relay route surface wiring', () => {
  test('attached route surface matches registered express routes', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {
      healthz: true,
      readyz: true,
      prfSessionSeal: {
        enabled: true,
        basePath: '/threshold-ecdsa/custom-prf',
        service: {} as any,
      },
      sessionRoutes: { state: '/session/me' },
      signedDelegate: { route: '/delegate/submit' },
      sponsoredEvmCall: {
        route: '/gas/relay',
        apiKeys: {} as any,
        billing: {} as any,
        ledger: {} as any,
        runtimeSnapshots: {} as any,
        config: null,
      },
    });

    const surface = getRelayRouteSurface(router);
    expect(surface).toBeTruthy();
    expect(surface?.mePath).toBe('/session/me');
    expect(surface?.signedDelegatePath).toBe('/delegate/submit');

    const actualKeys = new Set(
      listExpressRoutes(router)
        .filter((entry) => entry.method !== 'HEAD' && entry.method !== 'OPTIONS')
        .map((entry) => `${entry.method} ${entry.path}`),
    );
    const expectedKeys = new Set(
      canonicalRouteKeys((surface?.routeDefinitions || []).map((route) => ({
        method: route.method,
        path: route.path,
        aliases: route.aliases,
      }))),
    );

    expect([...expectedKeys].filter((key) => !actualKeys.has(key))).toEqual([]);
    expect([...actualKeys].filter((key) => !expectedKeys.has(key))).toEqual([]);
  });

  test('conditional relay route families are only attached when enabled', async () => {
    const service = makeFakeAuthService();
    const router = createRelayRouter(service, {});
    const surface = getRelayRouteSurface(router);
    const ids = new Set((surface?.routeDefinitions || []).map((route) => route.id));

    expect(ids.has('relay_healthz')).toBe(false);
    expect(ids.has('relay_readyz')).toBe(false);
    expect(ids.has('signed_delegate')).toBe(false);
    expect(ids.has('sponsored_evm_call')).toBe(false);
    expect(ids.has('prf_session_seal_apply_server_seal')).toBe(false);
    expect(ids.has('prf_session_seal_remove_server_seal')).toBe(false);
  });

  test('cloudflare and express attach the same configured relay route surface', async () => {
    const service = makeFakeAuthService();
    const options = {
      healthz: true,
      prfSessionSeal: {
        enabled: true,
        basePath: '/threshold-ecdsa/custom-prf',
        service: {} as any,
      },
      readyz: true,
      sessionRoutes: { state: '/session/me' },
      signedDelegate: { route: '/delegate/submit' },
      sponsoredEvmCall: {
        route: '/gas/relay',
        apiKeys: {} as any,
        billing: {} as any,
        ledger: {} as any,
        runtimeSnapshots: {} as any,
        config: null,
      },
    };

    const expressSurface = getRelayRouteSurface(createRelayRouter(service, options));
    const cloudflareSurface = getRelayRouteSurface(createCloudflareRouter(service, options));

    expect(cloudflareSurface).toEqual(expressSurface);
  });
});
