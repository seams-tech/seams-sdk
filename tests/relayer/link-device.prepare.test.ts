import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  callCf,
  fetchJson,
  makeCfCtx,
  makeFakeAuthService,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';

const LINK_DEVICE_REFACTOR_84_MESSAGE =
  'Linked-device lane creation is disabled until refactor 84 lands';

type LinkDeviceRouteCase = {
  name: string;
  method: 'GET' | 'POST';
  path: string;
  body?: Record<string, unknown>;
};

const LINK_DEVICE_ROUTE_CASES: LinkDeviceRouteCase[] = [
  { name: 'session lookup', method: 'GET', path: '/link-device/session/session-1' },
  { name: 'session registration', method: 'POST', path: '/link-device/session', body: {} },
  { name: 'session claim', method: 'POST', path: '/link-device/session/claim', body: {} },
  { name: 'prepare', method: 'POST', path: '/link-device/prepare', body: {} },
  { name: 'ECDSA respond', method: 'POST', path: '/link-device/ecdsa/respond', body: {} },
];

function expectUnsupportedLinkDeviceStubResponse(res: {
  status: number;
  json: Record<string, any> | null;
}): void {
  expect(res.status).toBe(410);
  expect(res.json).toEqual({
    ok: false,
    code: 'unsupported',
    message: LINK_DEVICE_REFACTOR_84_MESSAGE,
  });
}

function makeFetchInit(routeCase: LinkDeviceRouteCase): RequestInit {
  if (routeCase.method === 'GET') {
    return { method: routeCase.method };
  }
  return {
    method: routeCase.method,
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(routeCase.body),
  };
}

test.describe('link-device refactor 84 route stubs', () => {
  for (const routeCase of LINK_DEVICE_ROUTE_CASES) {
    test(`express route returns unsupported for ${routeCase.name}`, async () => {
      const router = createRelayRouter(makeFakeAuthService(), { session: makeSessionAdapter() });
      const srv = await startExpressRouter(router);
      try {
        const res = await fetchJson(`${srv.baseUrl}${routeCase.path}`, makeFetchInit(routeCase));
        expectUnsupportedLinkDeviceStubResponse(res);
      } finally {
        await srv.close();
      }
    });

    test(`cloudflare route returns unsupported for ${routeCase.name}`, async () => {
      const handler = createCloudflareRouter(makeFakeAuthService(), {
        session: makeSessionAdapter(),
      });
      const { ctx } = makeCfCtx();
      const res = await callCf(handler, {
        method: routeCase.method,
        path: routeCase.path,
        headers: routeCase.method === 'POST' ? { 'Content-Type': 'application/json' } : {},
        ctx,
        ...(routeCase.method === 'POST' ? { body: routeCase.body } : {}),
      });

      expectUnsupportedLinkDeviceStubResponse(res);
    });
  }
});
