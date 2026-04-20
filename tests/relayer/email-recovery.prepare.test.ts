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

const THRESHOLD_ED25519_TEST_KEY_VERSION = 'threshold-ed25519-v1';

function makeThresholdEd25519PrepareRequest() {
  return {
    key_version: THRESHOLD_ED25519_TEST_KEY_VERSION,
    recovery_export_capable: true,
    public_key: 'ed25519:recovery-key',
    relayer_key_id: 'rk-near',
    session_kind: 'jwt',
    session_policy: {
      version: 'threshold_session_v1',
      nearAccountId: 'alice.testnet',
      rpId: 'wallet.example.test',
      relayerKeyId: 'rk-near',
      sessionId: 'near-session-1',
      participantIds: [1, 2],
      ttlMs: 60_000,
      remainingUses: 5,
    },
  };
}

function makePreparedRecoveryService() {
  return makeFakeAuthService({
    prepareEmailRecovery: async () => ({
      ok: true,
      accountId: 'alice.testnet',
      requestId: 'ABC123',
      signerSlot: 7,
      credentialIdB64u: 'cred-b64u',
      thresholdEd25519: {
        relayerKeyId: 'rk-near',
        publicKey: 'ed25519:recovery-key',
        keyVersion: THRESHOLD_ED25519_TEST_KEY_VERSION,
        recoveryExportCapable: true,
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
        ecdsaThresholdKeyId: 'ehss-email-recovery-prepare-1',
        relayerKeyId: 'rk-evm',
        thresholdEcdsaPublicKeyB64u: 'group-public-key',
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
        deadlineEpochSeconds: 1_893_456_000,
        payloadHash: 'payload-hash',
      },
      recoveryEmail: {
        subject: 'recover-v1 alice.testnet ABC123',
        body: 'body',
        payload: {} as any,
        payloadHash: 'payload-hash',
        deadlineEpochSeconds: 1_893_456_000,
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
          threshold_ed25519: makeThresholdEd25519PrepareRequest(),
          threshold_ecdsa: { client_root_share32_b64u: 'evm-root-share' },
        }),
      });

      expect(res.status).toBe(200);
      expect(res.json?.thresholdEd25519).toBeTruthy();
      expect(res.json?.thresholdEcdsa).toBeTruthy();
      expect((res.json?.thresholdEd25519 as any)?.session?.jwt).toContain('near-session-1');
      expect((res.json?.thresholdEcdsa as any)?.session?.jwt).toContain('evm-session-1');
      expect((res.json?.thresholdEcdsa as any)?.ecdsaThresholdKeyId).toBe(
        'ehss-email-recovery-prepare-1',
      );
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
        threshold_ed25519: makeThresholdEd25519PrepareRequest(),
        threshold_ecdsa: { client_root_share32_b64u: 'evm-root-share' },
      },
    });

    expect(res.status).toBe(200);
    expect((res.json?.thresholdEd25519 as any)?.session?.jwt).toContain('near-session-1');
    expect((res.json?.thresholdEcdsa as any)?.session?.jwt).toContain('evm-session-1');
    expect((res.json?.thresholdEcdsa as any)?.ecdsaThresholdKeyId).toBe(
      'ehss-email-recovery-prepare-1',
    );
    expect((res.json?.recoverySession as any)?.status).toBe('prepared');
  });
});
