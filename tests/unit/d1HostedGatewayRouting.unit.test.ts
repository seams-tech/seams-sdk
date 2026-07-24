import { expect, test } from '@playwright/test';
import type { FetchHandler } from '../../packages/sdk-server-ts/src/router/cloudflare/cloudflare.types';
import { dispatchHostedGatewayRequest } from '../../packages/console-server-ts/src/router/cloudflare/d1RouterApiStagingWorker';

function markerHandler(marker: string): FetchHandler {
  return buildMarkerResponse.bind(null, marker);
}

async function buildMarkerResponse(marker: string): Promise<Response> {
  return new Response(marker);
}

async function routePath(pathname: string): Promise<string> {
  const response = await dispatchHostedGatewayRequest(
    markerHandler('console'),
    markerHandler('router-api'),
    new Request(`https://gateway.example.test${pathname}`),
  );
  return await response.text();
}

test('hosted gateway dispatches console routes to the console router', async () => {
  await expect(routePath('/console/session')).resolves.toBe('console');
  await expect(routePath('/console/billing/account')).resolves.toBe('console');
});

test('hosted gateway keeps Router API routes on the Router API router', async () => {
  await expect(routePath('/session/exchange')).resolves.toBe('router-api');
  await expect(routePath('/consolex')).resolves.toBe('router-api');
});
