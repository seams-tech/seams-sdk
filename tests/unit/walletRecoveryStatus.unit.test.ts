import { expect, test } from '@playwright/test';
import { handleWalletRecoveryStatus } from '../../packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';

/** Recovery status is a narrow Origin-bound public read. */

const routeDefinitions = createRouterApiRouteDefinitions();

function context(pathname: string, service: unknown) {
  return {
    routeDefinitions,
    method: 'GET',
    pathname,
    request: new Request(`https://relay.localhost${pathname}`, {
      method: 'GET',
      headers: { Origin: 'https://wallet.localhost' },
    }),
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

test('status uses the public transport plane while recovery preparation remains public', () => {
  const status = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_status');
  const prepare = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_prepare');
  expect(status?.auth.plane).toBe('public');
  expect(prepare?.auth.plane).toBe('public');
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
          storeVersion: '4',
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
  expect(body.storeVersion).toBe('4');
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
        storeVersion: '4',
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
