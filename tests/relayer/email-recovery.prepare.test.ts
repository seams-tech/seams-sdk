import { test, expect } from '@playwright/test';
import { createRelayRouter } from '@server/router/express-adaptor';
import { createCloudflareRouter } from '@server/router/cloudflare-adaptor';
import { callCf, fetchJson, makeCfCtx, makeFakeAuthService, makeSessionAdapter, startExpressRouter } from './helpers';

function makePreparedRecoveryService() {
  return makeFakeAuthService({
    prepareEmailRecovery: async () => ({
      ok: true,
      accountId: 'alice.testnet',
      requestId: 'ABC123',
      deviceNumber: 7,
      credentialIdB64u: 'cred-b64u',
      thresholdEd25519: {
        relayerKeyId: 'rk-near',
        publicKey: 'ed25519:recovery-key',
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
      recoverySession: {
        sessionId: 'ABC123',
        status: 'prepared' as const,
        expiresAtMs: Date.now() + 30 * 60_000,
      },
    }),
  });
}

test.describe('email-recovery prepare routing', () => {
  test('express route signs and returns both threshold session JWTs', async () => {
    const session = makeSessionAdapter({
      signJwt: async (sub, claims) => `jwt:${sub}:${String((claims as any)?.sessionId || '')}`,
    });
    const router = createRelayRouter(makePreparedRecoveryService(), { session });
    const srv = await startExpressRouter(router);
    try {
      const res = await fetchJson(`${srv.baseUrl}/email-recovery/prepare`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Origin: 'https://wallet.example.test',
        },
        body: JSON.stringify({
          account_id: 'alice.testnet',
          request_id: 'ABC123',
          rp_id: 'wallet.example.test',
          webauthn_registration: { id: 'cred-1' },
          threshold_ed25519: { client_verifying_share_b64u: 'near-share' },
          threshold_ecdsa: { client_verifying_share_b64u: 'evm-share' },
        }),
      });

      expect(res.status).toBe(200);
      expect(res.json?.thresholdEd25519).toBeTruthy();
      expect(res.json?.thresholdEcdsa).toBeTruthy();
      expect((res.json?.thresholdEd25519 as any)?.session?.jwt).toContain('near-session-1');
      expect((res.json?.thresholdEcdsa as any)?.session?.jwt).toContain('evm-session-1');
      expect((res.json?.recoverySession as any)?.sessionId).toBe('ABC123');
    } finally {
      await srv.close();
    }
  });

  test('cloudflare route signs and returns both threshold session JWTs', async () => {
    const session = makeSessionAdapter({
      signJwt: async (sub, claims) => `jwt:${sub}:${String((claims as any)?.sessionId || '')}`,
    });
    const handler = createCloudflareRouter(makePreparedRecoveryService(), { session });
    const { ctx } = makeCfCtx();

    const res = await callCf(handler, {
      method: 'POST',
      path: '/email-recovery/prepare',
      origin: 'https://wallet.example.test',
      headers: { 'Content-Type': 'application/json' },
      ctx,
      body: {
        account_id: 'alice.testnet',
        request_id: 'ABC123',
        rp_id: 'wallet.example.test',
        webauthn_registration: { id: 'cred-1' },
        threshold_ed25519: { client_verifying_share_b64u: 'near-share' },
        threshold_ecdsa: { client_verifying_share_b64u: 'evm-share' },
      },
    });

    expect(res.status).toBe(200);
    expect((res.json?.thresholdEd25519 as any)?.session?.jwt).toContain('near-session-1');
    expect((res.json?.thresholdEcdsa as any)?.session?.jwt).toContain('evm-session-1');
    expect((res.json?.recoverySession as any)?.status).toBe('prepared');
  });
});
