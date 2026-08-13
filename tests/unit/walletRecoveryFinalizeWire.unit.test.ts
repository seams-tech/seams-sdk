import { expect, test } from '@playwright/test';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';
import { finalizeWalletRecovery } from '../../packages/sdk-web/src/core/rpcClients/relayer/walletRecoveryFinalize';

/**
 * The recovery-finalization client boundary.
 *
 * `retireFailures` is what these tests exist for. It is the field a caller
 * forgets, and forgetting it is silent: the wallet is recovered, the new
 * credential works, and a credential the user was replacing still opens their
 * wallet with nobody aware of it. So the route must surface it and the client
 * must not drop it.
 */

const routeDefinitions = createRouterApiRouteDefinitions();

function respondWith(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

test('the route is registered where the client posts', () => {
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_finalize');
  expect(route?.path).toBe('/wallets/recovery/finalize');
});

test('the client keeps retireFailures, and defaults it to empty', async () => {
  const withFailures = await finalizeWalletRecovery({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    sessionToken: 'app-session',
    reservationId: 'reservation-1',
    replacementEnvelope: {},
    fetchImpl: respondWith(200, {
      ok: true,
      storeVersion: '2',
      retiredEnvelopeIds: ['old-1'],
      retireFailures: ['old-2'],
    }),
  });
  expect(withFailures).toMatchObject({ kind: 'promoted', retireFailures: ['old-2'] });

  const clean = await finalizeWalletRecovery({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    sessionToken: 'app-session',
    reservationId: 'reservation-1',
    replacementEnvelope: {},
    fetchImpl: respondWith(200, { ok: true, storeVersion: '2', retiredEnvelopeIds: ['old-1'] }),
  });
  // Always an array: a caller checking `.length` should not need to know the
  // field is conditional on the wire.
  expect(clean).toMatchObject({ kind: 'promoted', retireFailures: [] });
});

test('a finalization conflict remains distinct from incomplete activation', async () => {
  const result = await finalizeWalletRecovery({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    sessionToken: 'app-session',
    reservationId: 'reservation-1',
    replacementEnvelope: {},
    fetchImpl: respondWith(409, {
      ok: false,
      code: 'recovery_conflict',
      message: 'recovery state changed',
    }),
  });
  expect(result).toEqual({ kind: 'conflict', message: 'recovery state changed' });
});
