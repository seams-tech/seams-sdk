import { expect, test } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import {
  clearAllThresholdEcdsaClientPresignatures,
  resolveThresholdEcdsaPresignPoolPolicy,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
} from '@/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator';

test.describe('threshold ECDSA presign pool policy', () => {
  const ECDSA_THRESHOLD_KEY_ID = 'ecdsa-hss-test-key-1';
  const BACKEND_RELAYER_KEY_ID = 'rk-1';
  const BACKEND_CLIENT_VERIFYING_SHARE_B64U = 'backend-client-share';

  test.beforeEach(async () => {
    clearAllThresholdEcdsaClientPresignatures();
  });

  test('applies sane defaults when no policy is provided', async () => {
    const policy = resolveThresholdEcdsaPresignPoolPolicy();
    expect(policy.enabled).toBe(true);
    expect(policy.targetDepth).toBe(3);
    expect(policy.lowWatermark).toBe(1);
    expect(policy.maxRefillInFlight).toBe(1);
    expect(policy.refillAttemptTimeoutMs).toBe(30_000);
  });

  test('clamps invalid policy input values', async () => {
    const policy = resolveThresholdEcdsaPresignPoolPolicy({
      enabled: true,
      targetDepth: -10,
      lowWatermark: 999,
      maxRefillInFlight: 0,
      refillAttemptTimeoutMs: 1,
    });
    expect(policy.targetDepth).toBe(1);
    expect(policy.lowWatermark).toBe(1);
    expect(policy.maxRefillInFlight).toBe(1);
    expect(policy.refillAttemptTimeoutMs).toBe(5_000);
  });

  test('buildConfigsFromEnv rejects invalid threshold ECDSA presign pool config values', async () => {
    expect(() =>
      buildConfigsFromEnv({
        relayer: { url: 'https://relay.example' },
        thresholdEcdsaPresignPool: {
          enabled: false,
          targetDepth: 99,
          lowWatermark: -2,
          maxRefillInFlight: 99,
          refillAttemptTimeoutMs: 999_999,
        },
      }),
    ).toThrow(
      '[configPresets] Invalid config: thresholdEcdsaPresignPool.targetDepth must be in [1, 64]',
    );
  });

  test('accepts larger target depth policy for pooled warm signing', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      thresholdEcdsaPresignPool: {
        enabled: true,
        targetDepth: 12,
        lowWatermark: 4,
      },
    });
    expect(cfg.signing.thresholdEcdsa.presignPool.targetDepth).toBe(12);
    expect(cfg.signing.thresholdEcdsa.presignPool.lowWatermark).toBe(4);
  });

  test('scheduler no-ops cleanly when policy is disabled', async () => {
    const result = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
      // Backend bridge fields remain required by the current signer backend.
      relayerKeyId: BACKEND_RELAYER_KEY_ID,
      clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
      participantIds: [1, 2],
      clientSigningShare32: new Uint8Array(32),
      workerCtx: {} as any,
      poolPolicy: { enabled: false },
    });
    expect(result.scheduled).toBe(false);
    expect(result.reason).toBe('disabled');
  });

  test('scheduler dedupes by pool key when a refill is already in flight', async () => {
    const first = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
      relayerKeyId: BACKEND_RELAYER_KEY_ID,
      clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
      participantIds: [1, 2],
      clientSigningShare32: new Uint8Array(32),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 2 },
    });
    const second = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
      relayerKeyId: BACKEND_RELAYER_KEY_ID,
      clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
      participantIds: [1, 2],
      clientSigningShare32: new Uint8Array(32),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 2 },
    });

    expect(first.scheduled).toBe(true);
    expect(second.scheduled).toBe(false);
    expect(second.reason).toBe('in_flight_for_pool_key');
  });

  test('scheduler enforces global in-flight refill limit', async () => {
    const first = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-hss-test-key-1',
      relayerKeyId: 'backend-rk-1',
      clientVerifyingShareB64u: 'backend-client-share-1',
      participantIds: [1, 2],
      clientSigningShare32: new Uint8Array(32),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
    });
    const second = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      ecdsaThresholdKeyId: 'ecdsa-hss-test-key-2',
      relayerKeyId: 'backend-rk-2',
      clientVerifyingShareB64u: 'backend-client-share-2',
      participantIds: [1, 2],
      clientSigningShare32: new Uint8Array(32),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
    });

    expect(first.scheduled).toBe(true);
    expect(second.scheduled).toBe(false);
    expect(second.reason).toBe('global_in_flight_limit');
  });

  test('scheduler exits quickly when another runtime holds cross-tab refill authority lock', async () => {
    const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    if (navigatorDescriptor && !navigatorDescriptor.configurable) {
      return;
    }
    const hadNavigator = Object.prototype.hasOwnProperty.call(globalThis, 'navigator');
    const originalNavigator = (globalThis as Record<string, unknown>).navigator;
    try {
      Object.defineProperty(globalThis, 'navigator', {
        configurable: true,
        value: {
          locks: {
            request: async (
              _name: string,
              _opts: { mode?: string; ifAvailable?: boolean },
              callback: (lock: unknown) => Promise<void>,
            ): Promise<void> => {
              await callback(null);
            },
          },
        },
      });

      const first = scheduleThresholdEcdsaClientPresignaturePoolRefill({
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: [1, 2],
        clientSigningShare32: new Uint8Array(32),
        workerCtx: {} as any,
        poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
      });
      expect(first.scheduled).toBe(true);

      await new Promise((resolve) => setTimeout(resolve, 0));

      const second = scheduleThresholdEcdsaClientPresignaturePoolRefill({
        relayerUrl: 'https://relay.example',
        ecdsaThresholdKeyId: ECDSA_THRESHOLD_KEY_ID,
        relayerKeyId: BACKEND_RELAYER_KEY_ID,
        clientVerifyingShareB64u: BACKEND_CLIENT_VERIFYING_SHARE_B64U,
        participantIds: [1, 2],
        clientSigningShare32: new Uint8Array(32),
        workerCtx: {} as any,
        poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
      });
      expect(second.scheduled).toBe(true);
    } finally {
      if (hadNavigator) {
        Object.defineProperty(globalThis, 'navigator', {
          configurable: true,
          value: originalNavigator,
        });
      } else {
        delete (globalThis as Record<string, unknown>).navigator;
      }
    }
  });
});
