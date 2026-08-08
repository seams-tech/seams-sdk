import { expect, test } from '@playwright/test';
import { handlePasskeyCustody } from '../../packages/sdk-server-ts/src/router/transport/fetch/routes/passkeyCustody';
import { createRouterApiRouteDefinitions } from '../../packages/sdk-server-ts/src/router/framework/routeDefinitions';

/**
 * Where `expectedOrigin` comes from on the custody retrieval route.
 *
 * Frozen 2026-08-09: the `Origin` header, with no body fallback. The sibling
 * WebAuthn service takes it from its caller because an app server calls it;
 * this route is reachable by a browser, and a value the requester supplies is
 * not evidence — it would let a caller name the origin its own assertion is
 * checked against.
 *
 * The body fallback is the kind of thing re-added for convenience by someone
 * debugging a client, so these tests assert the *absence* of that path rather
 * than only the happy case.
 */

const routeDefinitions = createRouterApiRouteDefinitions();

function context(options: {
  readonly body: unknown;
  readonly originHeader?: string;
  readonly seen: unknown[];
}) {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' };
  if (options.originHeader) headers.Origin = options.originHeader;
  return {
    routeDefinitions,
    method: 'POST',
    pathname: '/wallets/custody/envelope',
    request: new Request('https://relay.localhost/wallets/custody/envelope', {
      method: 'POST',
      headers,
      body: JSON.stringify(options.body),
    }),
    service: {
      passkeyCustody: {
        retrieveEnvelope: async (request: unknown) => {
          options.seen.push(request);
          return { status: 200, body: { ok: true } };
        },
      },
    },
    logger: { error: () => {}, warn: () => {}, info: () => {}, debug: () => {} },
    opts: {},
  } as never;
}

const ASSERTION = {
  id: 'credential-1',
  rawId: 'credential-1',
  type: 'public-key',
  response: { clientDataJSON: 'e30', authenticatorData: 'AA', signature: 'AA' },
};

const BODY = {
  challengeId: 'challenge-1',
  locator: {
    walletId: 'alice.testnet',
    factor: { kind: 'passkey', rpId: 'example.localhost', credentialIdB64u: 'credential-1' },
  },
  webauthnAuthentication: ASSERTION,
};

test('the origin comes from the header', async () => {
  const seen: unknown[] = [];
  await handlePasskeyCustody(
    context({ body: BODY, originHeader: 'https://example.localhost', seen }),
  );
  expect(seen).toHaveLength(1);
  expect((seen[0] as { expectedOrigin: string }).expectedOrigin).toBe('https://example.localhost');
});

test('a body-supplied origin is ignored, not preferred', async () => {
  const seen: unknown[] = [];
  await handlePasskeyCustody(
    context({
      body: { ...BODY, expectedOrigin: 'https://attacker.example' },
      originHeader: 'https://example.localhost',
      seen,
    }),
  );
  // The header wins and the body value never reaches the retrieval, so a
  // caller cannot name the origin its own assertion is checked against.
  expect((seen[0] as { expectedOrigin: string }).expectedOrigin).toBe('https://example.localhost');
});

test('a request with no Origin header is refused, whatever the body says', async () => {
  const seen: unknown[] = [];
  const response = await handlePasskeyCustody(
    context({ body: { ...BODY, expectedOrigin: 'https://attacker.example' }, seen }),
  );

  expect(response?.status).toBe(400);
  // The store is never consulted: absence of the header means the caller is
  // not the browser this route exists for.
  expect(seen).toEqual([]);
});
