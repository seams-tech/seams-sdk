import { expect, test } from '@playwright/test';
import { handleWalletRecoveryBackupAcknowledge } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';

/**
 * The acknowledgement route.
 *
 * The failure worth a test is the convenient one: succeeding for a wallet
 * with no issued codes. That writes an acknowledgement covering an issuance
 * that never happened, and the user is then never asked to save the codes
 * they eventually receive — silent until the day they need to recover.
 */

const routeDefinitions = createRouterApiRouteDefinitions();

function context(body: unknown, service: unknown) {
  return {
    routeDefinitions,
    method: 'POST',
    pathname: '/wallets/recovery/acknowledge-backup',
    request: new Request('https://relay.localhost/wallets/recovery/acknowledge-backup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    service,
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

test('the route is registered', () => {
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_backup_acknowledge');
  expect(route?.path).toBe('/wallets/recovery/acknowledge-backup');
});

test('an acknowledgement echoes the issuance it covered', () => {
  return handleWalletRecoveryBackupAcknowledge(
    context(
      { walletId: 'alice.testnet' },
      {
        passkeyCustody: {
          acknowledgeRecoveryBackup: async () => ({ kind: 'acknowledged', issuedAtMs: 1_700 }),
        },
      },
    ),
  ).then(async (response) => {
    expect(response?.status).toBe(200);
    const body = await response!.json();
    // So a client can tell whether its view of "which codes" matches what the
    // server recorded.
    expect(body.issuedAtMs).toBe(1_700);
  });
});

test('a wallet with no issued codes cannot acknowledge', async () => {
  const response = await handleWalletRecoveryBackupAcknowledge(
    context(
      { walletId: 'alice.testnet' },
      {
        passkeyCustody: {
          acknowledgeRecoveryBackup: async () => ({ kind: 'no_recovery_set' }),
        },
      },
    ),
  );
  expect(response?.status).toBe(404);
  const body = await response!.json();
  expect(body.code).toBe('no_recovery_set');
});

test('a request without a wallet never reaches the service', async () => {
  let called = false;
  const response = await handleWalletRecoveryBackupAcknowledge(
    context(
      {},
      {
        passkeyCustody: {
          acknowledgeRecoveryBackup: async () => {
            called = true;
            return { kind: 'acknowledged', issuedAtMs: 1 };
          },
        },
      },
    ),
  );
  expect(response?.status).toBe(400);
  expect(called).toBe(false);
});
