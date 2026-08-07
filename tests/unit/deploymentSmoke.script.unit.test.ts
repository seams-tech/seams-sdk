import { expect, test } from '@playwright/test';
import { createServer, type Server } from 'node:http';

import {
  formatFailedCheck,
  isFailedCheck,
  runReadinessChecks,
} from '../../scripts/deployment-smoke.mjs';

/**
 * Serve `failures` responses of 500 before answering 200, mimicking a freshly
 * deployed Worker that is not yet consistent across the edge.
 */
async function startFlakyServer(failures: number): Promise<{
  readonly origin: string;
  readonly requestCount: () => number;
  readonly close: () => Promise<void>;
}> {
  let requests = 0;
  const server: Server = createServer((_request, response) => {
    requests += 1;
    response.writeHead(requests <= failures ? 500 : 200);
    response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no server address');
  return {
    origin: `http://127.0.0.1:${address.port}`,
    requestCount: () => requests,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

async function startCorsServer(): Promise<{
  readonly origin: string;
  readonly close: () => Promise<void>;
}> {
  const server: Server = createServer((request, response) => {
    const origin = String(request.headers.origin || '');
    response.writeHead(204, {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Credentials': 'true',
    });
    response.end();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no server address');
  return {
    origin: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise<void>((resolve, reject) =>
        server.close((error) => (error ? reject(error) : resolve())),
      ),
  };
}

function isConsoleCorsReady(response: Response): boolean {
  return (
    response.status === 204 &&
    response.headers.get('Access-Control-Allow-Origin') === 'https://dashboard.example.test' &&
    response.headers.get('Access-Control-Allow-Credentials') === 'true'
  );
}

test('readiness check retries through a post-deploy propagation window', async () => {
  const server = await startFlakyServer(2);
  try {
    const results = await runReadinessChecks(
      [{ name: '/healthz', url: `${server.origin}/healthz` }],
      {
        budgetMs: 10_000,
        intervalMs: 10,
      },
    );
    expect(results).toHaveLength(1);
    expect(results[0]?.ok, 'a deployment that becomes healthy must not be reported failed').toBe(
      true,
    );
    expect(results[0]?.attempts).toBe(3);
    expect(server.requestCount()).toBe(3);
  } finally {
    await server.close();
  }
});

test('readiness check still fails a deployment that never becomes healthy', async () => {
  const server = await startFlakyServer(Number.MAX_SAFE_INTEGER);
  try {
    const results = await runReadinessChecks(
      [{ name: '/healthz', url: `${server.origin}/healthz` }],
      {
        budgetMs: 120,
        intervalMs: 10,
      },
    );
    expect(results[0]?.ok).toBe(false);
    expect(results[0]?.status).toBe(500);
    expect(results.filter(isFailedCheck).map(formatFailedCheck)).toEqual(['/healthz']);
  } finally {
    await server.close();
  }
});

test('readiness check reports a first-attempt pass without retrying', async () => {
  const server = await startFlakyServer(0);
  try {
    const results = await runReadinessChecks(
      [{ name: '/healthz', url: `${server.origin}/healthz` }],
      {
        budgetMs: 10_000,
        intervalMs: 10,
      },
    );
    expect(results[0]?.ok).toBe(true);
    expect(results[0]?.attempts).toBe(1);
    expect(server.requestCount()).toBe(1);
  } finally {
    await server.close();
  }
});

test('readiness check supports request-specific CORS assertions', async () => {
  const server = await startCorsServer();
  try {
    const results = await runReadinessChecks(
      [
        {
          name: '/console/session CORS preflight',
          url: `${server.origin}/console/session`,
          request: {
            method: 'OPTIONS',
            headers: {
              Origin: 'https://dashboard.example.test',
              'Access-Control-Request-Method': 'GET',
            },
          },
          isReady: isConsoleCorsReady,
        },
      ],
      {
        budgetMs: 10_000,
        intervalMs: 10,
      },
    );
    expect(results[0]?.ok).toBe(true);
    expect(results[0]?.status).toBe(204);
  } finally {
    await server.close();
  }
});
