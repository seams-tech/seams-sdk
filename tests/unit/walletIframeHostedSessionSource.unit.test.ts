import { expect, test } from '@playwright/test';
import { WalletIframeRouter } from '@/SeamsWeb/walletIframe/client/router';
import { parseAppSessionJwt } from '@shared/utils/domainIds';

function encoded(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function appSessionJwt(sessionId: string): string {
  return `${encoded({ alg: 'none', typ: 'JWT' })}.${encoded({
    kind: 'app_session_v1',
    tenantId: 'tenant-1',
    sub: sessionId,
    seamsSessionId: sessionId,
    deviceId: `device-${sessionId}`,
    exp: Math.floor(Date.now() / 1000) + 3600,
  })}.signature`;
}

function requireAppSessionJwt(sessionId: string) {
  const parsed = parseAppSessionJwt(appSessionJwt(sessionId));
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

test('hosted-wallet exchange uses the router relayer configuration', async () => {
  const originalFetch = globalThis.fetch;
  const originalWindow = Reflect.get(globalThis, 'window');
  const fetchUrls: string[] = [];
  const postedRelays: string[] = [];
  globalThis.fetch = async (input) => {
    fetchUrls.push(String(input));
    return new Response(
      JSON.stringify({
        ok: true,
        delivery: {
          kind: 'hosted_wallet_session_exchange_delivery',
          appOrigin: window.location.origin,
          walletOrigin: 'https://wallet.example.test',
          exchangeCode: `exchange-${fetchUrls.length}`,
          nonce: `nonce-${fetchUrls.length}`,
          expiresAtMs: Date.now() + 60_000,
        },
      }),
      { status: 200, headers: { 'Content-Type': 'application/json' } },
    );
  };
  Reflect.set(globalThis, 'window', {
    location: { origin: 'https://app.example.test' },
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  });

  try {
    const router = new WalletIframeRouter({
      walletOrigin: 'https://wallet.example.test',
      servicePath: '/wallet-service',
      relayer: { url: 'https://relay-configured.example.test' },
      testOptions: { autoMount: false },
    });
    Reflect.set(
      router,
      'post',
      async (envelope: { type: string; payload?: { relayUrl?: string } }) => {
        if (envelope.type === 'PM_REDEEM_HOSTED_WALLET_SEAMS_SESSION') {
          postedRelays.push(String(envelope.payload?.relayUrl || ''));
          return {
            ok: true,
            result: {
              kind: 'redeemed_hosted_wallet_seams_session',
              expiresAtMs: Date.now() + 60_000,
            },
          };
        }
        if (envelope.type === 'PM_REQUEST_EMAIL_OTP_CHALLENGE') {
          return {
            ok: true,
            result: {
              challengeId: 'challenge-configured-relayer',
              otpChannel: 'email_otp',
              delivery: {
                kind: 'provider',
                status: 'sent',
                emailHint: 'a***@example.test',
              },
            },
          };
        }
        throw new Error(`Unexpected wallet iframe request: ${envelope.type}`);
      },
    );

    const ensure = Reflect.get(router, 'ensureHostedWalletSeamsSession');
    if (typeof ensure !== 'function')
      throw new Error('hosted-wallet source resolver is unavailable');

    const sourceA = {
      relayUrl: 'https://relay-a.example.test/',
      appSessionJwt: requireAppSessionJwt('session-a'),
    };
    await ensure.call(router, sourceA);
    await ensure.call(router, { ...sourceA, relayUrl: 'https://relay-a.example.test' });
    await ensure.call(router, {
      relayUrl: 'https://relay-a.example.test',
      appSessionJwt: requireAppSessionJwt('session-b'),
    });
    await ensure.call(router, {
      relayUrl: 'https://relay-b.example.test',
      appSessionJwt: requireAppSessionJwt('session-b'),
    });
    await router.requestEmailOtpChallenge({
      walletId: 'alice.testnet',
      appSessionJwt: requireAppSessionJwt('session-configured-relayer'),
    });

    expect(fetchUrls).toEqual([
      'https://relay-a.example.test/session/exchange',
      'https://relay-a.example.test/session/exchange',
      'https://relay-b.example.test/session/exchange',
      'https://relay-configured.example.test/session/exchange',
    ]);
    expect(postedRelays).toEqual([
      'https://relay-a.example.test',
      'https://relay-a.example.test',
      'https://relay-b.example.test',
      'https://relay-configured.example.test',
    ]);
  } finally {
    globalThis.fetch = originalFetch;
    if (originalWindow === undefined) Reflect.deleteProperty(globalThis, 'window');
    else Reflect.set(globalThis, 'window', originalWindow);
  }
});
