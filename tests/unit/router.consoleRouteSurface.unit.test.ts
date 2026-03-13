import { expect, test } from '@playwright/test';
import { getConsoleRouteSurface } from '../../server/src/router/consoleRouteSurface';
import { createCloudflareConsoleRouter } from '../../server/src/router/cloudflare/createCloudflareConsoleRouter';
import { createConsoleRouter } from '../../server/src/router/express/createConsoleRouter';
import { findRouteDefinitionForRequest } from '../../server/src/router/routeDefinitions';

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

function materializeRoutePath(path: string): string {
  return path.replace(/:([A-Za-z0-9_]+)/g, (_match, name: string) => {
    const normalized = String(name || '').toLowerCase();
    if (normalized.includes('id')) return 'test_id';
    return `test_${normalized}`;
  });
}

const ALLOWLISTED_CONSOLE_ROUTE_KEYS = new Set([
  'GET /console/healthz',
  'GET /console/readyz',
  'POST /console/billing/stripe/webhook',
]);

test.describe('console route surface wiring', () => {
  test('seeded console route surface remains console-only and unmetered in the live express router', async () => {
    const router = createConsoleRouter({});
    const surface = getConsoleRouteSurface(router);
    expect(surface).toBeTruthy();

    const routeDefinitions = surface?.routeDefinitions || [];
    expect(routeDefinitions.length).toBeGreaterThan(0);
    expect(
      routeDefinitions.every(
        (route) =>
          route.path === '/console' ||
          route.path.startsWith('/console/'),
      ),
    ).toBe(true);
    expect(routeDefinitions.every((route) => route.surface === 'console')).toBe(true);
    expect(routeDefinitions.every((route) => route.auth.plane === 'console')).toBe(true);
    expect(routeDefinitions.every((route) => route.metering.kind === 'none')).toBe(true);

    const actualKeys = new Set(
      listExpressRoutes(router)
        .filter((entry) => entry.method !== 'HEAD' && entry.method !== 'OPTIONS')
        .map((entry) => `${entry.method} ${entry.path}`),
    );
    const expectedKeys = new Set(
      canonicalRouteKeys(routeDefinitions.map((route) => ({
        method: route.method,
        path: route.path,
        aliases: route.aliases,
      }))),
    );

    expect([...expectedKeys].filter((key) => !actualKeys.has(key))).toEqual([]);
  });

  test('express and cloudflare attach the same seeded console route surface', async () => {
    const expressSurface = getConsoleRouteSurface(createConsoleRouter({}));
    const cloudflareSurface = getConsoleRouteSurface(createCloudflareConsoleRouter({}));

    expect(expressSurface).toBeTruthy();
    expect(cloudflareSurface).toEqual(expressSurface);
    expect(
      (expressSurface?.routeDefinitions || []).map((route) => `${route.method} ${route.path}`),
    ).toContain('POST /console/billing/usage/events');
    expect(
      (expressSurface?.routeDefinitions || []).map((route) => `${route.method} ${route.path}`),
    ).toContain('POST /console/webhooks/:id/replay');
    expect(
      (expressSurface?.routeDefinitions || []).map((route) => `${route.method} ${route.path}`),
    ).toContain('POST /console/projects/:id/archive');
    expect(
      (expressSurface?.routeDefinitions || []).map((route) => `${route.method} ${route.path}`),
    ).toContain('POST /console/approvals/:id/approve');
    expect(
      (expressSurface?.routeDefinitions || []).map((route) => `${route.method} ${route.path}`),
    ).toContain('POST /console/policies/:id/publish');
    expect(
      (expressSurface?.routeDefinitions || []).map((route) => `${route.method} ${route.path}`),
    ).toContain('POST /console/billing/invoices/generate');
  });

  test('cloudflare handler recognizes every seeded console route definition', async () => {
    const handler = createCloudflareConsoleRouter({});
    const surface = getConsoleRouteSurface(handler);
    expect(surface).toBeTruthy();

    for (const route of surface?.routeDefinitions || []) {
      const response = await handler(
        new Request(`https://example.localhost${materializeRoutePath(route.path)}`, {
          method: route.method,
        }),
      );
      expect(response.status, `${route.method} ${route.path}`).not.toBe(404);
    }
  });

  test('live console routes are policy-defined or explicitly allowlisted', async () => {
    const router = createConsoleRouter({ healthz: true, readyz: true });
    const surface = getConsoleRouteSurface(router);
    expect(surface).toBeTruthy();

    const liveRouteKeys = new Set(
      listExpressRoutes(router)
        .filter((entry) => entry.method !== 'HEAD' && entry.method !== 'OPTIONS')
        .filter((entry) => entry.path === '/console' || entry.path.startsWith('/console/'))
        .map((entry) => `${entry.method} ${entry.path}`),
    );

    for (const key of ALLOWLISTED_CONSOLE_ROUTE_KEYS) {
      expect(liveRouteKeys.has(key), `allowlisted route missing from live router: ${key}`).toBe(true);
      const separatorIndex = key.indexOf(' ');
      const method = key.slice(0, separatorIndex);
      const path = key.slice(separatorIndex + 1);
      expect(findRouteDefinitionForRequest(surface?.routeDefinitions || [], method, path)).toBeNull();
    }

    for (const key of liveRouteKeys) {
      if (ALLOWLISTED_CONSOLE_ROUTE_KEYS.has(key)) continue;
      const separatorIndex = key.indexOf(' ');
      const method = key.slice(0, separatorIndex);
      const path = key.slice(separatorIndex + 1);
      const route = findRouteDefinitionForRequest(surface?.routeDefinitions || [], method, path);
      expect(route, `policy definition missing for ${key}`).toBeTruthy();
      expect(route?.auth.plane, `non-console auth attached to ${key}`).toBe('console');
      expect(route?.metering.kind, `non-none metering attached to ${key}`).toBe('none');
    }
  });
});
