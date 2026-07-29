import { expect, test } from '@playwright/test';

import {
  ARC_BROWSER_RPC_PROXY_PATH,
  NEAR_BROWSER_RPC_PROXY_PATH,
  handleChainRpcProxyRequest,
} from '../../packages/console-server-ts/src/router/cloudflare/chainRpcProxy';

const STAGING_ORIGIN = 'https://staging.seams.sh';

function rpcRequest(pathname: string, method: string): Request {
  return new Request(`https://gateway.example.test${pathname}`, {
    method: 'POST',
    headers: {
      origin: STAGING_ORIGIN,
      'content-type': 'application/json',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'test', method, params: [] }),
  });
}

test('NEAR proxy falls back from a throttled FastNear response and owns CORS', async () => {
  const upstreams: string[] = [];
  const redirectModes: Array<RequestRedirect | undefined> = [];
  const fetchImpl: typeof fetch = async (input, init) => {
    const url = String(input);
    upstreams.push(url);
    redirectModes.push(init?.redirect);
    if (url === 'https://test.rpc.fastnear.com/') {
      return new Response('rate limited', { status: 429 });
    }
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 'test', result: { ok: true } }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  const response = await handleChainRpcProxyRequest(
    rpcRequest(NEAR_BROWSER_RPC_PROXY_PATH, 'query'),
    {
      corsOrigins: [STAGING_ORIGIN],
      nearRpcUrls: 'https://rpc.testnet.near.org',
      fetchImpl,
    },
  );

  expect(response?.status).toBe(200);
  expect(response?.headers.get('access-control-allow-origin')).toBe(STAGING_ORIGIN);
  expect(upstreams).toEqual([
    'https://test.rpc.fastnear.com/',
    'https://rpc.testnet.near.org/',
  ]);
  expect(redirectModes).toEqual(['manual', 'manual']);
});

test('proxy rejects upstream redirects instead of following outside the allowlist', async () => {
  const fetchImpl: typeof fetch = async () =>
    new Response(null, {
      status: 302,
      headers: { location: 'https://attacker.example/rpc' },
    });
  const response = await handleChainRpcProxyRequest(
    rpcRequest(ARC_BROWSER_RPC_PROXY_PATH, 'eth_call'),
    {
      corsOrigins: [STAGING_ORIGIN],
      fetchImpl,
    },
  );

  expect(response?.status).toBe(502);
  expect(response?.headers.get('location')).toBeNull();
});

test('Arc proxy rejects methods outside the product RPC allowlist', async () => {
  let fetchCalls = 0;
  const fetchImpl: typeof fetch = async () => {
    fetchCalls += 1;
    return new Response('{}');
  };

  const response = await handleChainRpcProxyRequest(
    rpcRequest(ARC_BROWSER_RPC_PROXY_PATH, 'debug_traceTransaction'),
    {
      corsOrigins: [STAGING_ORIGIN],
      fetchImpl,
    },
  );

  expect(response?.status).toBe(403);
  expect(response?.headers.get('access-control-allow-origin')).toBe(STAGING_ORIGIN);
  expect(fetchCalls).toBe(0);
});

test('proxy converts an upstream throttle into a readable browser error', async () => {
  const fetchImpl: typeof fetch = async () => new Response('rate limited', { status: 429 });
  const response = await handleChainRpcProxyRequest(
    rpcRequest(ARC_BROWSER_RPC_PROXY_PATH, 'eth_call'),
    {
      corsOrigins: [STAGING_ORIGIN],
      fetchImpl,
    },
  );

  expect(response?.status).toBe(429);
  expect(response?.headers.get('access-control-allow-origin')).toBe(STAGING_ORIGIN);
  await expect(response?.json()).resolves.toMatchObject({
    error: { message: 'RPC throttled; retry shortly' },
  });
});
