import { test, expect } from '@playwright/test';
import { createRouterApiRouter } from '@server/router/express-adaptor';
import { fetchJson, makeFakeAuthService, startExpressRouter } from './helpers';

function makePasskeyReplayService() {
  const activeChallengeIds = new Set<string>();
  let challengeCounter = 0;

  return makeFakeAuthService({
    createWebAuthnLoginOptions: async () => {
      challengeCounter += 1;
      const challengeId = `challenge-replay-${challengeCounter}`;
      activeChallengeIds.add(challengeId);
      return {
        ok: true,
        challengeId,
        challengeB64u: 'challenge-b64u',
        expiresAtMs: Date.now() + 60_000,
      };
    },
    verifyWebAuthnLogin: async (request) => {
      const challengeId = String(
        (request as { challengeId?: unknown; challenge_id?: unknown }).challengeId ||
          (request as { challengeId?: unknown; challenge_id?: unknown }).challenge_id ||
          '',
      );
      if (!activeChallengeIds.delete(challengeId)) {
        return {
          ok: false,
          verified: false,
          code: 'challenge_expired_or_invalid',
          message: 'Challenge expired or invalid',
        };
      }
      return {
        ok: true,
        verified: true,
        userId: 'bob.testnet',
        rpId: 'example.localhost',
      };
    },
    verifyWebAuthnAuthenticationLite: async () => ({
      success: true,
      verified: true,
    }),
  });
}

test.describe('relayer login challenge replay', () => {
  test('POST /auth/passkey/verify: replayed challengeId is rejected', async () => {
    const service = makePasskeyReplayService();
    const router = createRouterApiRouter(service, {});
    const srv = await startExpressRouter(router);

    try {
      const options = await fetchJson(`${srv.baseUrl}/auth/passkey/options`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user_id: 'bob.testnet', rp_id: 'example.localhost' }),
      });
      expect(options.status).toBe(200);
      const challengeId = String(options.json?.challengeId || '');
      expect(challengeId.length).toBeGreaterThan(10);

      const verify1 = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.localhost' },
        body: JSON.stringify({
          challengeId,
          webauthn_authentication: { ok: true },
        }),
      });
      expect(verify1.status).toBe(200);
      expect(verify1.json?.verified).toBe(true);
      expect(verify1.json?.jwt).toBeUndefined();

      const verify2 = await fetchJson(`${srv.baseUrl}/auth/passkey/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Origin: 'https://example.localhost' },
        body: JSON.stringify({
          challengeId,
          webauthn_authentication: { ok: true },
        }),
      });
      expect(verify2.status).toBe(400);
      expect(verify2.json?.code).toBe('challenge_expired_or_invalid');
      expect(verify2.json?.verified).toBe(false);
    } finally {
      await srv.close();
    }
  });
});
