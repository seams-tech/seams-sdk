import { expect, test } from '@playwright/test';
import { createRelayerReusableWalletSessionStatusPort } from '@/core/rpcClients/relayer/walletSessionAuthorizationStatus';
import { walletSessionJwtAuth } from '@shared/utils/sessionTokens';

function jwtWithPayload(payload: Record<string, unknown>): string {
  const encode = (value: unknown): string =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.sig`;
}

test.describe('Wallet Session authorization status client', () => {
  test('uses the exact Wallet Session JWT as Bearer authorization', async () => {
    const walletSessionJwt = jwtWithPayload({ kind: 'router_ab_ed25519_wallet_session_v1' });
    let requestInit: RequestInit | undefined;
    const statusPort = createRelayerReusableWalletSessionStatusPort({
      relayerUrl: 'https://relayer.example.test',
      auth: walletSessionJwtAuth(walletSessionJwt),
      fetchImpl: async (_input, init) => {
        requestInit = init;
        return new Response(
          JSON.stringify({
            ok: true,
            status: 'active',
            walletSessionId: 'wallet-session-1',
            quotaId: 'wallet-quota-1',
            remainingUses: 2,
            expiresAtMs: Date.now() + 60_000,
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      },
    });

    await expect(
      statusPort.read({ walletSessionId: 'wallet-session-1', quotaId: 'wallet-quota-1' }),
    ).resolves.toMatchObject({ status: 'active', remainingUses: 2 });

    expect(requestInit?.credentials).toBe('omit');
    expect(new Headers(requestInit?.headers).get('authorization')).toBe(
      `Bearer ${walletSessionJwt}`,
    );
    expect(new Headers(requestInit?.headers).get('cookie')).toBeNull();
  });

  test('rejects app-session JWTs at the status boundary', () => {
    expect(() =>
      createRelayerReusableWalletSessionStatusPort({
        relayerUrl: 'https://relayer.example.test',
        auth: {
          kind: 'wallet_session',
          jwt: 'eyJhbGciOiJub25lIn0.eyJraW5kIjoiYXBwX3Nlc3Npb25fdjEifQ.sig',
        },
      }),
    ).toThrow('walletSessionJwt must be a Wallet Session JWT');
  });
});
