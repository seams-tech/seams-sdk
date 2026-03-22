import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import {
  callCf,
  fetchJson,
  makeCfCtx,
  makeFakeAuthService,
  makeSessionAdapter,
  startExpressRouter,
} from './helpers';

function makePreparedLinkDeviceService() {
  return makeFakeAuthService({
    prepareLinkDevice: async () => ({
      ok: true,
      accountId: 'alice.testnet',
      deviceNumber: 7,
      credentialIdB64u: 'cred-b64u',
      thresholdEd25519: {
        relayerKeyId: 'rk-near',
        publicKey: 'ed25519:linked-key',
        relayerVerifyingShareB64u: 'near-share',
        participantIds: [1, 2],
        session: {
          sessionKind: 'jwt',
          sessionId: 'near-session-1',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          remainingUses: 5,
        },
      },
      thresholdEcdsa: {
        relayerKeyId: 'rk-evm',
        groupPublicKeyB64u: 'group-public-key',
        ethereumAddress: `0x${'11'.repeat(20)}`,
        relayerVerifyingShareB64u: 'evm-share',
        participantIds: [1, 2],
        session: {
          sessionKind: 'jwt',
          sessionId: 'evm-session-1',
          expiresAtMs: Date.now() + 60_000,
          participantIds: [1, 2],
          remainingUses: 5,
        },
      },
      linkedAccounts: [
        {
          chainIdKey: 'evm:11155111',
          chain: 'evm' as const,
          chainId: 11155111,
          accountAddress: `0x${'22'.repeat(20)}`,
          accountModel: 'erc4337' as const,
          factory: `0x${'33'.repeat(20)}`,
          entryPoint: `0x${'44'.repeat(20)}`,
          salt: '0x1234',
          counterfactualAddress: `0x${'22'.repeat(20)}`,
        },
      ],
    }),
  });
}

test.describe('link-device prepare routing', () => {
  test('express route signs and returns both threshold session JWTs', async () => {
    const session = makeSessionAdapter({
      signJwt: async (sub, claims) => `jwt:${sub}:${String((claims as any)?.sessionId || '')}`,
    });
    const router = createRelayRouter(makePreparedLinkDeviceService(), { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/link-device/prepare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://wallet.example.test',
        },
        body: JSON.stringify({
          account_id: 'alice.testnet',
          device_number: 7,
          rp_id: 'wallet.example.test',
          webauthn_registration: { id: 'cred-1' },
          threshold_ed25519: { client_verifying_share_b64u: 'near-share' },
          threshold_ecdsa: { client_verifying_share_b64u: 'evm-share' },
        }),
      });

      expect(res.status).toBe(200);
      expect((res.json?.thresholdEd25519 as any)?.session?.jwt).toContain('near-session-1');
      expect((res.json?.thresholdEcdsa as any)?.session?.jwt).toContain('evm-session-1');
      expect((res.json?.linkedAccounts as any[])?.[0]?.chainIdKey).toBe('evm:11155111');
    } finally {
      await srv.close();
    }
  });

  test('cloudflare route signs and returns both threshold session JWTs', async () => {
    const session = makeSessionAdapter({
      signJwt: async (sub, claims) => `jwt:${sub}:${String((claims as any)?.sessionId || '')}`,
    });
    const handler = createCloudflareRouter(makePreparedLinkDeviceService(), { session });
    const { ctx } = makeCfCtx();

    const res = await callCf(handler, {
      method: 'POST',
      path: '/link-device/prepare',
      origin: 'https://wallet.example.test',
      headers: { 'Content-Type': 'application/json' },
      ctx,
      body: {
        account_id: 'alice.testnet',
        device_number: 7,
        rp_id: 'wallet.example.test',
        webauthn_registration: { id: 'cred-1' },
        threshold_ed25519: { client_verifying_share_b64u: 'near-share' },
        threshold_ecdsa: { client_verifying_share_b64u: 'evm-share' },
      },
    });

    expect(res.status).toBe(200);
    expect((res.json?.thresholdEd25519 as any)?.session?.jwt).toContain('near-session-1');
    expect((res.json?.thresholdEcdsa as any)?.session?.jwt).toContain('evm-session-1');
    expect((res.json?.linkedAccounts as any[])?.[0]?.accountModel).toBe('erc4337');
  });
});
