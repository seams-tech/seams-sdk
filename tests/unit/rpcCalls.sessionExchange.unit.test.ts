import { expect, test } from '@playwright/test';
import { exchangeSession } from '@/core/rpcClients/near/rpcCalls';

type CapturedFetch = {
  url: string;
  init?: RequestInit;
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

test.describe('exchangeSession', () => {
  const sampleWebauthnCredential = {
    id: 'cred-id-1',
    rawId: 'cred-raw-1',
    type: 'public-key',
    authenticatorAttachment: undefined,
    response: {
      clientDataJSON: 'client-data-json',
      authenticatorData: 'authenticator-data',
      signature: 'signature-b64u',
      userHandle: undefined,
      clientExtensionResults: { shouldRedact: true },
    },
    clientExtensionResults: {
      prf: {
        results: {
          first: 'prf-first',
          second: 'prf-second',
        },
      },
    },
  } as const;

  test('exchanges oidc_jwt and returns app session metadata + jwt', async () => {
    const originalFetch = globalThis.fetch;
    const captured: CapturedFetch[] = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({ url: String(input), init });
        return jsonResponse({
          ok: true,
          session: {
            kind: 'app_session_v1',
            userId: 'alice.testnet',
            expiresAt: '2030-01-01T00:00:00.000Z',
          },
          jwt: 'app-jwt-1',
        });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example/',
        '/session/exchange',
        'jwt',
        { type: 'oidc_jwt', token: 'oidc-token-1' },
      );

      expect(result.success).toBe(true);
      expect(result.sessionUserId).toBe('alice.testnet');
      expect(result.sessionExpiresAt).toBe('2030-01-01T00:00:00.000Z');
      expect(result.jwt).toBe('app-jwt-1');
      expect(captured).toHaveLength(1);
      expect(captured[0]!.url).toBe('https://relay.example/session/exchange');
      const body = JSON.parse(String(captured[0]!.init?.body || '{}')) as Record<string, unknown>;
      expect(body.sessionKind).toBe('jwt');
      expect(body.exchange).toEqual({ type: 'oidc_jwt', token: 'oidc-token-1' });
      expect(captured[0]!.init?.credentials).toBe('omit');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('uses cookie credentials mode and succeeds when jwt is omitted', async () => {
    const originalFetch = globalThis.fetch;
    const captured: CapturedFetch[] = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({ url: String(input), init });
        return jsonResponse({
          ok: true,
          session: { kind: 'app_session_v1', userId: 'bob.testnet' },
        });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        'session/exchange',
        'cookie',
        { type: 'oidc_jwt', token: 'oidc-token-2' },
      );

      expect(result.success).toBe(true);
      expect(result.sessionUserId).toBe('bob.testnet');
      expect(result.sessionExpiresAt).toBeUndefined();
      expect(result.jwt).toBeUndefined();
      expect(captured).toHaveLength(1);
      expect(captured[0]!.url).toBe('https://relay.example/session/exchange');
      expect(captured[0]!.init?.credentials).toBe('include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('maps relay error response message', async () => {
    const originalFetch = globalThis.fetch;
    try {
      globalThis.fetch = (async () =>
        jsonResponse(
          { ok: false, code: 'invalid_claims', message: 'issuer mismatch' },
          401,
        )) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'jwt',
        { type: 'oidc_jwt', token: 'oidc-token-3' },
      );

      expect(result.success).toBe(false);
      expect(result.error).toBe('issuer mismatch');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('exchanges passkey_assertion and redacts extension outputs', async () => {
    const originalFetch = globalThis.fetch;
    const captured: CapturedFetch[] = [];
    try {
      globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
        captured.push({ url: String(input), init });
        return jsonResponse({
          ok: true,
          session: {
            kind: 'app_session_v1',
            userId: 'carol.testnet',
            expiresAt: '2030-01-01T00:00:00.000Z',
          },
        });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'cookie',
        {
          type: 'passkey_assertion',
          challengeId: 'challenge-passkey-1',
          webauthn_authentication: sampleWebauthnCredential as any,
          expected_origin: 'https://wallet.example',
        },
      );

      expect(result.success).toBe(true);
      expect(result.sessionUserId).toBe('carol.testnet');
      expect(captured).toHaveLength(1);
      const body = JSON.parse(String(captured[0]!.init?.body || '{}')) as Record<string, unknown>;
      const exchange = (body.exchange || {}) as Record<string, unknown>;
      expect(exchange.type).toBe('passkey_assertion');
      expect(exchange.challengeId).toBe('challenge-passkey-1');
      expect(exchange.expected_origin).toBe('https://wallet.example');
      const credential = (exchange.webauthn_authentication || {}) as Record<string, unknown>;
      expect(credential.clientExtensionResults).toBeNull();
      expect(
        ((credential.response || {}) as Record<string, unknown>).clientExtensionResults,
      ).toBeNull();
      expect(captured[0]!.init?.credentials).toBe('include');
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('fails fast on missing token and does not call fetch', async () => {
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    try {
      globalThis.fetch = (async () => {
        fetchCalls += 1;
        return jsonResponse({ ok: true });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'jwt',
        { type: 'oidc_jwt', token: '  ' },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('Missing exchange token');
      expect(fetchCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test('fails fast on missing passkey challengeId and does not call fetch', async () => {
    const originalFetch = globalThis.fetch;
    let fetchCalls = 0;
    try {
      globalThis.fetch = (async () => {
        fetchCalls += 1;
        return jsonResponse({ ok: true });
      }) as typeof fetch;

      const result = await exchangeSession(
        'https://relay.example',
        '/session/exchange',
        'jwt',
        {
          type: 'passkey_assertion',
          challengeId: '   ',
          webauthn_authentication: sampleWebauthnCredential as any,
        },
      );

      expect(result.success).toBe(false);
      expect(String(result.error || '')).toContain('Missing passkey challengeId');
      expect(fetchCalls).toBe(0);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
