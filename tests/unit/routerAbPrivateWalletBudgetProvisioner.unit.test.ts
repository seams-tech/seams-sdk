import { expect, test } from '@playwright/test';
import { createRouterAbPrivateD1WalletBudgetGrantProvisionerV1 } from '../../packages/sdk-server-ts/src/router/routerAbPrivateSigningWorker';

let capturedUrl = '';
let capturedInit: RequestInit | undefined;

async function privateWalletBudgetFetch(
  input: RequestInfo | URL,
  init?: RequestInit,
): Promise<Response> {
  capturedUrl = input instanceof Request ? input.url : String(input);
  capturedInit = init;
  return Response.json({
    signing_grant_id: 'grant-private-d1-1',
    committed_remaining_uses: 8,
    reserved_uses: 0,
    available_uses: 8,
    expires_at_ms: 1_900_000_000_000,
  });
}

function capturedJsonBody(): Record<string, unknown> {
  if (typeof capturedInit?.body !== 'string') throw new Error('expected JSON request body');
  return JSON.parse(capturedInit.body) as Record<string, unknown>;
}

test('wallet-budget provisioning uses the authenticated private Router route', async () => {
  capturedUrl = '';
  capturedInit = undefined;
  const provisioner = createRouterAbPrivateD1WalletBudgetGrantProvisionerV1({
    routerBaseUrl: 'https://router.internal/',
    internalServiceAuthSecret: 'private-router-secret',
    fetchImpl: privateWalletBudgetFetch,
  });

  const result = await provisioner.provisionGrant({
    signingGrantId: 'grant-private-d1-1',
    walletId: 'wallet-private-d1-1',
    relyingPartyId: 'example.com',
    authorizedSigners: [
      {
        curve: 'ecdsa',
        threshold_session_id: 'threshold-session-1',
        signing_worker_id: 'signing-worker-1',
      },
    ],
    initialSignatureUses: 8,
    expiresAtMs: 1_900_000_000_000,
    issuerIdempotencyKey: 'registration:grant-private-d1-1',
  });

  expect(result).toEqual({
    ok: true,
    signingGrantId: 'grant-private-d1-1',
    remainingUses: 8,
    reservedUses: 0,
    availableUses: 8,
    expiresAtMs: 1_900_000_000_000,
  });
  expect(capturedUrl).toBe('https://router.internal/router-ab/router/wallet-budget/put-grant');
  expect(new Headers(capturedInit?.headers).get('x-router-ab-internal-service-auth')).toBe(
    'private-router-secret',
  );
  expect(capturedJsonBody()).toMatchObject({
    signing_grant_id: 'grant-private-d1-1',
    wallet_id: 'wallet-private-d1-1',
    rp_id: 'example.com',
    initial_signature_uses: 8,
    expires_at_ms: 1_900_000_000_000,
    issuer_jwt_id: 'registration:grant-private-d1-1',
  });
});
