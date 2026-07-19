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
    return Response.json({
      method: request.method,
      pathname: new URL(request.url).pathname,
    });
  }
}

function createBindings(): {
  readonly env: RouterAbServiceBindingEnv;
  readonly mpcRouter: RecordingServiceBinding;
  readonly deriverA: RecordingServiceBinding;
  readonly deriverB: RecordingServiceBinding;
  readonly signingWorker: RecordingServiceBinding;
} {
  const mpcRouter = new RecordingServiceBinding();
  const deriverA = new RecordingServiceBinding();
  const deriverB = new RecordingServiceBinding();
  const signingWorker = new RecordingServiceBinding();
  return {
    env: {
      MPC_ROUTER: mpcRouter,
      DERIVER_A: deriverA,
      DERIVER_B: deriverB,
      SIGNING_WORKER: signingWorker,
    },
    mpcRouter,
    deriverA,
    deriverB,
    signingWorker,
  };
}

test('Gateway dispatches each strict Yao origin through its exact Service Binding', async () => {
  const bindings = createBindings();
  const serviceFetch = createRouterAbServiceBindingFetch(bindings.env);

  await serviceFetch('https://deriver-a.router-ab.internal/router-ab/deriver-a/start', {
    method: 'POST',
    body: '{}',
  });
  await serviceFetch('https://deriver-b.router-ab.internal/router-ab/deriver-b/stage', {
    method: 'POST',
    body: '{}',
  });
  await serviceFetch(
    'https://signing-worker.router-ab.internal/router-ab/signing-worker/activate',
    {
      method: 'POST',
      body: '{}',
    },
  );

  expect(bindings.deriverA.requests).toHaveLength(1);
  expect(bindings.deriverB.requests).toHaveLength(1);
  expect(bindings.signingWorker.requests).toHaveLength(1);
  expect(new URL(bindings.deriverA.requests[0]!.url).pathname).toBe('/router-ab/deriver-a/start');
  expect(new URL(bindings.deriverB.requests[0]!.url).pathname).toBe('/router-ab/deriver-b/stage');
  expect(new URL(bindings.signingWorker.requests[0]!.url).pathname).toBe(
    '/router-ab/signing-worker/activate',
  );
});

test('Gateway rejects network origins outside the strict Yao Service Binding set', async () => {
  const bindings = createBindings();
  const serviceFetch = createRouterAbServiceBindingFetch(bindings.env);

  await expect(serviceFetch('https://example.com/router-ab/deriver-a/start')).rejects.toThrow(
    'Unsupported Router A/B service-binding origin',
  );
  expect(bindings.deriverA.requests).toHaveLength(0);
  expect(bindings.deriverB.requests).toHaveLength(0);
  expect(bindings.signingWorker.requests).toHaveLength(0);
});
