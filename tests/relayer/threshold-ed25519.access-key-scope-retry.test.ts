import { test, expect } from '@playwright/test';
import { ensureRelayerKeyIsActiveAccessKey } from '@server/core/ThresholdService/validation';

test.describe('threshold-ed25519 access key scope retries', () => {
  test('retries until relayer key becomes visible in access key list', async () => {
    let calls = 0;
    const out = await ensureRelayerKeyIsActiveAccessKey({
      nearAccountId: 'alice.testnet',
      relayerPublicKey: 'ed25519:relayer-key',
      viewAccessKeyList: async () => {
        calls += 1;
        if (calls < 3) return { keys: [] } as any;
        return {
          keys: [
            {
              public_key: 'ed25519:relayer-key',
              access_key: { nonce: 0, permission: 'FullAccess' },
            },
          ],
        } as any;
      },
      maxAttempts: 4,
      initialDelayMs: 1,
    });

    expect(out).toEqual({ ok: true });
    expect(calls).toBe(3);
  });

  test('returns unauthorized when relayer key never appears within retry budget', async () => {
    let calls = 0;
    const out = await ensureRelayerKeyIsActiveAccessKey({
      nearAccountId: 'alice.testnet',
      relayerPublicKey: 'ed25519:relayer-key',
      viewAccessKeyList: async () => {
        calls += 1;
        return { keys: [] } as any;
      },
      maxAttempts: 3,
      initialDelayMs: 1,
    });

    expect(out).toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'relayerKeyId public key is not an active access key for nearAccountId',
    });
    expect(calls).toBe(3);
  });

  test('returns unauthorized immediately when signing payload key mismatches relayer key', async () => {
    let calls = 0;
    const out = await ensureRelayerKeyIsActiveAccessKey({
      nearAccountId: 'alice.testnet',
      relayerPublicKey: 'ed25519:relayer-key',
      expectedSigningPublicKey: 'ed25519:different-key',
      viewAccessKeyList: async () => {
        calls += 1;
        return { keys: [] } as any;
      },
      maxAttempts: 5,
      initialDelayMs: 1,
    });

    expect(out).toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'relayerKeyId does not match signingPayload public key',
    });
    expect(calls).toBe(0);
  });

  test('returns internal when every access-key lookup attempt throws', async () => {
    let calls = 0;
    const out = await ensureRelayerKeyIsActiveAccessKey({
      nearAccountId: 'alice.testnet',
      relayerPublicKey: 'ed25519:relayer-key',
      viewAccessKeyList: async () => {
        calls += 1;
        throw new Error('rpc unavailable');
      },
      maxAttempts: 3,
      initialDelayMs: 1,
    });

    expect(out).toMatchObject({
      ok: false,
      code: 'internal',
    });
    if (!out.ok) {
      expect(out.message).toContain('rpc unavailable');
    }
    expect(calls).toBe(3);
  });
});
