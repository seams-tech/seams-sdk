import { expect, test } from '@playwright/test';
import { handleWalletRecoverySpend } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/passkeyCustody';
import {
  createRouterApiRouteDefinitions,
  findRouteDefinitionById,
} from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';

/**
 * The recovery spend route's wire behaviour.
 *
 * The property under test is that the transport does not re-separate what the
 * domain deliberately merged. Every "this did not work" — unknown wallet,
 * unknown code, spent code, unparseable code — must leave as the same status
 * and the same body, or the route counts how many of a user's ten codes
 * remain for anyone who asks.
 */

const routeDefinitions = createRouterApiRouteDefinitions();

function context(body: unknown, service: unknown) {
  return {
    routeDefinitions,
    method: 'POST',
    pathname: '/wallets/recovery/spend',
    request: new Request('https://relay.localhost/wallets/recovery/spend', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    }),
    service,
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

function serviceReturning(result: unknown, seen: unknown[] = []) {
  return {
    passkeyCustody: {
      spendRecoveryCode: async (request: unknown) => {
        seen.push(request);
        return result;
      },
    },
  };
}

const VALID_BODY = {
  walletId: 'alice.testnet',
  recoveryCode: 'QUJDREVGR0hJSktMTU5PUFFSU1Q',
  reservationId: 'reservation-1',
};

test('the route is registered where the client will look for it', () => {
  const route = findRouteDefinitionById(routeDefinitions, 'wallet_recovery_code_spend');
  expect(route).toBeTruthy();
  expect(route?.path).toBe('/wallets/recovery/spend');
  expect(route?.method).toBe('POST');
});

test('a successful spend returns the wrapped payload', async () => {
  const response = await handleWalletRecoverySpend(
    context(
      VALID_BODY,
      serviceReturning({
        kind: 'committed',
        wrap: { nonceB64u: 'n', wrappedManifestKekB64u: 'k', aadHashB64u: 'a' },
        entries: [],
        storeVersion: '5',
      }),
    ),
  );
  expect(response?.status).toBe(200);
  const body = await response!.json();
  expect(body.ok).toBe(true);
  expect(body.wrap.wrappedManifestKekB64u).toBe('k');
});

test('a refusal and an unparseable code are byte-identical', async () => {
  const refused = await handleWalletRecoverySpend(
    context(VALID_BODY, serviceReturning({ kind: 'refused', reason: 'nope' })),
  );
  const malformed = await handleWalletRecoverySpend(
    context(
      { ...VALID_BODY, recoveryCode: '!!!not-base64!!!' },
      // Never reached: a code that cannot decode is refused before the call.
      serviceReturning({ kind: 'committed', wrap: {}, entries: [], storeVersion: '5' }),
    ),
  );

  expect(refused?.status).toBe(malformed?.status);
  expect(await refused!.text()).toBe(await malformed!.text());
});

test('a code that cannot decode never reaches the store', async () => {
  const seen: unknown[] = [];
  await handleWalletRecoverySpend(
    context(
      { ...VALID_BODY, recoveryCode: '!!!not-base64!!!' },
      serviceReturning({ kind: 'refused', reason: 'nope' }, seen),
    ),
  );
  expect(seen).toEqual([]);
});

test('a losing concurrent attempt is retryable and says so', async () => {
  const response = await handleWalletRecoverySpend(
    context(VALID_BODY, serviceReturning({ kind: 'conflict' })),
  );
  // 409 rather than the refusal: the code may still be good, and a client
  // that read this as "wrong code" would send the user hunting for another.
  expect(response?.status).toBe(409);
  const body = await response!.json();
  expect(body.code).toBe('recovery_set_conflict');
});
