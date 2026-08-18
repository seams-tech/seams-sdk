import { expect, test } from '@playwright/test';
import { handleWalletRecoveryRotate } from '../../packages/wallet-server/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/wallet-server/src/router/framework/routeDefinitions';
import { rotateWalletRecoveryCodes } from '../../packages/wallet/src/core/rpcClients/relayer/walletRecoveryRotate';

/**
 * The rotation wire, both ends.
 *
 * `issuedAtMs` is what these tests protect. It re-arms the backup prompt, so
 * a rotation that does not carry it back leaves the client unable to tell
 * whether the user acknowledged the codes now on screen — and the user is
 * either nagged about codes they saved or never asked about codes they did
 * not.
 */

const routeDefinitions = createRouterApiRouteDefinitions();

function context(body: unknown, service: unknown) {
  return {
    routeDefinitions,
    method: 'POST',
    pathname: '/wallets/recovery/rotate',
    request: new Request('https://relay.localhost/wallets/recovery/rotate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    service,
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

function serviceReturning(result: unknown) {
  return { passkeyCustody: { rotateRecoveryCodes: async () => result } };
}

function respondWith(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

const VALID_BODY = {
  walletId: 'alice.testnet',
  manifestKekWraps: Array.from({ length: 10 }, (_, index) => ({ recoveryKeyId: `id-${index}` })),
};

test('the route is registered where the client posts', () => {
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_codes_rotate');
  expect(route?.path).toBe('/wallets/recovery/rotate');
});

test('a rotation returns the new issuance timestamp', async () => {
  const response = await handleWalletRecoveryRotate(
    context(
      VALID_BODY,
      serviceReturning({ kind: 'rotated', issuedAtMs: 9_000, storeVersion: '5' }),
    ),
  );
  expect(response?.status).toBe(200);
  const body = await response!.json();
  expect(body.issuedAtMs).toBe(9_000);
});

test('the client refuses a rotation with no issuance timestamp', async () => {
  const result = await rotateWalletRecoveryCodes({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    manifestKekWraps: [],
    fetchImpl: respondWith(200, { ok: true, storeVersion: '5' }),
  });
  // Reporting success would leave the caller unable to record which issuance
  // the user is about to acknowledge.
  expect(result.kind).toBe('transport_failed');
});

test('each server refusal keeps its own meaning', async () => {
  const missing = await rotateWalletRecoveryCodes({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    manifestKekWraps: [],
    fetchImpl: respondWith(404, { ok: false, code: 'no_recovery_set' }),
  });
  const conflict = await rotateWalletRecoveryCodes({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    manifestKekWraps: [],
    fetchImpl: respondWith(409, { ok: false, code: 'recovery_set_conflict' }),
  });
  const rejected = await rotateWalletRecoveryCodes({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    manifestKekWraps: [],
    fetchImpl: respondWith(400, { ok: false, code: 'rotation_rejected' }),
  });

  // Retry helps the second and never the third; the first is not a failure of
  // the rotation at all.
  expect(missing.kind).toBe('no_recovery_set');
  expect(conflict.kind).toBe('conflict');
  expect(rejected.kind).toBe('rejected');
});

test('a rotation with no wraps never reaches the service', async () => {
  let called = false;
  const response = await handleWalletRecoveryRotate(
    context(
      { walletId: 'alice.testnet', manifestKekWraps: [] },
      {
        passkeyCustody: {
          rotateRecoveryCodes: async () => {
            called = true;
            return { kind: 'rotated', issuedAtMs: 1, storeVersion: '1' };
          },
        },
      },
    ),
  );
  expect(response?.status).toBe(400);
  expect(called).toBe(false);
});
