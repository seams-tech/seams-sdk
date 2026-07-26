import { expect, test } from '@playwright/test';
import {
  createRouterAbServiceBindingFetch,
  type RouterAbServiceBindingEnv,
} from '../../packages/console-server-ts/src/router/cloudflare/routerAbServiceBindings';

class RecordingServiceBinding {
  readonly requests: Request[] = [];

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    const request = new Request(input, init);
    this.requests.push(request);
    return Response.json({ pathname: new URL(request.url).pathname });
  }
}

function createBindings(): {
  readonly env: RouterAbServiceBindingEnv;
  readonly mpcRouter: RecordingServiceBinding;
  readonly signingWorker: RecordingServiceBinding;
} {
  const mpcRouter = new RecordingServiceBinding();
  const signingWorker = new RecordingServiceBinding();
  return { env: { MPC_ROUTER: mpcRouter, SIGNING_WORKER: signingWorker }, mpcRouter, signingWorker };
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
