import { expect, test } from '@playwright/test';
import { handleWalletRecoveryPromote } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';
import { promoteRecoveredWalletCredential } from '../../packages/sdk-web/src/core/rpcClients/relayer/walletRecoveryPromote';

/**
 * The promotion wire, both ends.
 *
 * `retireFailures` is what these tests exist for. It is the field a caller
 * forgets, and forgetting it is silent: the wallet is recovered, the new
 * credential works, and a credential the user was replacing still opens their
 * wallet with nobody aware of it. So the route must surface it and the client
 * must not drop it.
 */

const routeDefinitions = createRouterApiRouteDefinitions();

function context(body: unknown, service: unknown) {
  return {
    routeDefinitions,
    method: 'POST',
    pathname: '/wallets/recovery/promote',
    request: new Request('https://relay.localhost/wallets/recovery/promote', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    service,
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

const VALID_BODY = {
  walletId: 'alice.testnet',
  replacementEnvelope: { envelopeId: 'new-1', walletId: 'alice.testnet' },
  requiredKeySets: ['near_ed25519_v1'],
  outcomes: [{ keySet: 'near_ed25519_v1', kind: 'verified' }],
};

function serviceReturning(result: unknown) {
  return { passkeyCustody: { promoteRecoveredCredential: async () => result } };
}

function respondWith(status: number, body: unknown): typeof fetch {
  return (async () =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'Content-Type': 'application/json' },
    })) as unknown as typeof fetch;
}

test('the route is registered where the client posts', () => {
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_credential_promote');
  expect(route?.path).toBe('/wallets/recovery/promote');
});

test('a retire failure is surfaced rather than swallowed', async () => {
  const response = await handleWalletRecoveryPromote(
    context(
      VALID_BODY,
      serviceReturning({
        kind: 'promoted',
        storeVersion: '2',
        retiredEnvelopeIds: [],
        retireFailures: ['old-1'],
      }),
    ),
  );
  expect(response?.status).toBe(200);
  const body = await response!.json();
  // Without this the wallet looks cleanly recovered while an old credential
  // still opens it.
  expect(body.retireFailures).toEqual(['old-1']);
});

test('the client keeps retireFailures, and defaults it to empty', async () => {
  const withFailures = await promoteRecoveredWalletCredential({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    replacementEnvelope: {},
    requiredKeySets: ['near_ed25519_v1'],
    outcomes: [],
    fetchImpl: respondWith(200, {
      ok: true,
      storeVersion: '2',
      retiredEnvelopeIds: ['old-1'],
      retireFailures: ['old-2'],
    }),
  });
  expect(withFailures).toMatchObject({ kind: 'promoted', retireFailures: ['old-2'] });

  const clean = await promoteRecoveredWalletCredential({
    relayUrl: 'https://relay.localhost',
    walletId: 'alice.testnet',
    replacementEnvelope: {},
    requiredKeySets: ['near_ed25519_v1'],
    outcomes: [],
    fetchImpl: respondWith(200, { ok: true, storeVersion: '2', retiredEnvelopeIds: ['old-1'] }),
  });
  // Always an array: a caller checking `.length` should not need to know the
  // field is conditional on the wire.
  expect(clean).toMatchObject({ kind: 'promoted', retireFailures: [] });
});

test('an incomplete recovery and a rejected envelope stay distinct', async () => {
  const incomplete = await handleWalletRecoveryPromote(
    context(
      VALID_BODY,
      serviceReturning({ kind: 'refused', reason: 'missing evm_family_ecdsa_v1' }),
    ),
  );
  const rejected = await handleWalletRecoveryPromote(
    context(VALID_BODY, serviceReturning({ kind: 'envelope_rejected', reason: 'wrong wallet' })),
  );
  // Finishing the outstanding key sets makes the first valid; repeating will
  // never make the second valid.
  expect(incomplete?.status).toBe(409);
  expect(rejected?.status).toBe(400);
});

test('a promotion without required key sets is refused before the service', async () => {
  let called = false;
  const response = await handleWalletRecoveryPromote(
    context(
      { ...VALID_BODY, requiredKeySets: [] },
      {
        passkeyCustody: {
          promoteRecoveredCredential: async () => {
            called = true;
            return { kind: 'promoted', storeVersion: '2', retiredEnvelopeIds: [] };
          },
        },
      },
    ),
  );
  expect(response?.status).toBe(400);
  // An empty manifest means the caller did not load one, not that there is
  // nothing to verify — promoting on it would promote on no proof at all.
  expect(called).toBe(false);
});
