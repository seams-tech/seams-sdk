import { expect, test } from '@playwright/test';
import {
  createRouterAbServiceBindingFetch,
  type RouterAbServiceBindingEnv,
} from '../../packages/wallet-console-server-ts/src/router/cloudflare/routerAbServiceBindings';
import { runRouterAbPrewarmScheduled } from '../../packages/wallet-console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker';

class RecordingServiceBinding {
  readonly requests: Request[] = [];

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    this.requests.push(request);
    return Response.json({ ok: true, pathname: new URL(request.url).pathname });
  }
}

function createBindings(): {
  readonly env: RouterAbServiceBindingEnv;
  readonly mpcRouter: RecordingServiceBinding;
  readonly signingWorker: RecordingServiceBinding;
} {
  const mpcRouter = new RecordingServiceBinding();
  const signingWorker = new RecordingServiceBinding();
  return {
    env: { MPC_ROUTER: mpcRouter, SIGNING_WORKER: signingWorker },
    mpcRouter,
    signingWorker,
  };
}

test('Gateway exposes only the MPC Router and current SigningWorker service origins', async () => {
  const bindings = createBindings();
  const serviceFetch = createRouterAbServiceBindingFetch(bindings.env);

  await serviceFetch('https://mpc-router.router-ab.internal/router-ab/ed25519-yao/execute', {
    method: 'POST',
    body: '{}',
  });
  await serviceFetch('https://signing-worker.router-ab.internal/router-ab/signing-worker/sign', {
    method: 'POST',
    body: '{}',
  });

  expect(bindings.mpcRouter.requests).toHaveLength(1);
  expect(bindings.signingWorker.requests).toHaveLength(1);
});

test('Gateway rejects retired role origins and arbitrary network origins', async () => {
  const bindings = createBindings();
  const serviceFetch = createRouterAbServiceBindingFetch(bindings.env);

  await expect(
    serviceFetch('https://deriver-a.router-ab.internal/router-ab/deriver-a/start'),
  ).rejects.toThrow('Unsupported Router A/B service-binding origin');
  await expect(serviceFetch('https://example.com/router-ab/deriver-a/start')).rejects.toThrow(
    'Unsupported Router A/B service-binding origin',
  );
});

test('Gateway one-minute schedule calls the authenticated MPC Router prewarm path', async () => {
  const bindings = createBindings();
  await runRouterAbPrewarmScheduled(
    { cron: '* * * * *' },
    {
      MPC_ROUTER: bindings.mpcRouter,
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'prewarm-secret',
      ROUTER_AB_PREWARM_ENABLED: 'true',
    },
  );

  expect(bindings.mpcRouter.requests).toHaveLength(1);
  const request = bindings.mpcRouter.requests[0];
  expect(request.method).toBe('POST');
  expect(new URL(request.url).pathname).toBe('/internal/prewarm');
  expect(request.headers.get('x-router-ab-internal-service-auth')).toBe('prewarm-secret');
});

test('Gateway skips Router prewarm when it is disabled', async () => {
  const bindings = createBindings();
  await runRouterAbPrewarmScheduled(
    { cron: '* * * * *' },
    {
      MPC_ROUTER: bindings.mpcRouter,
      ROUTER_AB_INTERNAL_SERVICE_AUTH_SECRET: 'prewarm-secret',
      ROUTER_AB_PREWARM_ENABLED: 'false',
    },
  );

  expect(bindings.mpcRouter.requests).toHaveLength(0);
});
