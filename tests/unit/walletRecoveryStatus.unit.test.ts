import { expect, test } from '@playwright/test';
import { handleWalletRecoveryStatus } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';

/**
 * Recovery status, and why it may count when the spend route may not.
 *
 * The difference is authentication, and it is the thing most likely to be
 * "simplified" later by someone noticing two recovery routes with different
 * planes. Counting how many of ten codes remain is an enumeration oracle for
 * a stranger and the entire point of a settings screen for the owner — so the
 * plane is asserted here, not just the payload.
 */

const routeDefinitions = createRouterApiRouteDefinitions();

function context(pathname: string, service: unknown) {
  return {
    routeDefinitions,
    method: 'GET',
    pathname,
    request: new Request(`https://relay.localhost${pathname}`, { method: 'GET' }),
    service,
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

function serviceReturning(result: unknown, seen: string[] = []) {
  return {
    passkeyCustody: {
      readRecoveryStatus: async (request: { walletId: string }) => {
        seen.push(request.walletId);
        return result;
      },
    },
  };
}

test('status is credential-gated while spending is not', () => {
  const status = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_status');
  const spend = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_code_spend');
  // Spending must stay public: recovery exists for when every factor is gone,
  // so there is nothing left to authenticate with. Counting must not.
  expect(status?.auth.plane).toBe('api_credentials');
  expect(spend?.auth.plane).toBe('public');
});

test('status reports counts and the outstanding backup', async () => {
  const seen: string[] = [];
  const response = await handleWalletRecoveryStatus(
    context(
      '/wallets/alice.testnet/recovery/status',
      serviceReturning(
        {
          kind: 'status',
          activeCodeCount: 7,
          totalCodeCount: 10,
          issuedAtMs: 1_000,
          backupOutstanding: true,
        },
        seen,
      ),
    ),
  );

  expect(response?.status).toBe(200);
  const body = await response!.json();
  expect(seen).toEqual(['alice.testnet']);
  // Both counts: "3 left" means something different out of ten than out of
  // three, and a rotation changes which the user is looking at.
  expect(body.activeCodeCount).toBe(7);
  expect(body.totalCodeCount).toBe(10);
  expect(body.backupOutstanding).toBe(true);
});

test('status never returns which codes remain', async () => {
  const response = await handleWalletRecoveryStatus(
    context(
      '/wallets/alice.testnet/recovery/status',
      serviceReturning({
        kind: 'status',
        activeCodeCount: 7,
        totalCodeCount: 10,
        issuedAtMs: 1_000,
        backupOutstanding: false,
      }),
    ),
  );
  const body = await response!.json();
  // Not something even the owner's browser needs, and a list would be one
  // leak away from being useful to someone else.
  expect(JSON.stringify(body)).not.toContain('recoveryKeyId');
  expect(body.recoveryKeyIds).toBeUndefined();
  expect(body.wraps).toBeUndefined();
});

test('a wallet with no codes is a 404, not an empty status', async () => {
  const response = await handleWalletRecoveryStatus(
    context(
      '/wallets/alice.testnet/recovery/status',
      serviceReturning({ kind: 'no_recovery_set' }),
    ),
  );
  // Zero codes and no set are different states: the first is an emergency,
  // the second is a wallet that never issued any.
  expect(response?.status).toBe(404);
});
