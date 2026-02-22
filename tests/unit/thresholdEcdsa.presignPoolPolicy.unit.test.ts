import { expect, test } from '@playwright/test';
import { buildConfigsFromEnv } from '@/core/config/defaultConfigs';
import {
  clearAllThresholdEcdsaClientPresignatures,
  resolveThresholdEcdsaPresignPoolPolicy,
  scheduleThresholdEcdsaClientPresignaturePoolRefill,
} from '@/core/signingEngine/orchestration/walletOrigin/thresholdEcdsaCoordinator';

test.describe('threshold ECDSA presign pool policy', () => {
  test.beforeEach(async () => {
    clearAllThresholdEcdsaClientPresignatures();
  });

  test('applies sane defaults when no policy is provided', async () => {
    const policy = resolveThresholdEcdsaPresignPoolPolicy();
    expect(policy.enabled).toBe(true);
    expect(policy.targetDepth).toBe(20);
    expect(policy.lowWatermark).toBe(5);
    expect(policy.maxRefillInFlight).toBe(2);
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

  test('buildConfigsFromEnv merges and clamps threshold ECDSA presign pool config', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      thresholdEcdsaPresignPool: {
        enabled: false,
        targetDepth: 99,
        lowWatermark: -2,
        maxRefillInFlight: 99,
        refillAttemptTimeoutMs: 999_999,
      },
    });
    expect(cfg.thresholdEcdsaPresignPool.enabled).toBe(false);
    expect(cfg.thresholdEcdsaPresignPool.targetDepth).toBe(64);
    expect(cfg.thresholdEcdsaPresignPool.lowWatermark).toBe(0);
    expect(cfg.thresholdEcdsaPresignPool.maxRefillInFlight).toBe(8);
    expect(cfg.thresholdEcdsaPresignPool.refillAttemptTimeoutMs).toBe(120_000);
  });

  test('accepts larger target depth policy for pooled warm signing', async () => {
    const cfg = buildConfigsFromEnv({
      relayer: { url: 'https://relay.example' },
      thresholdEcdsaPresignPool: {
        enabled: true,
        targetDepth: 20,
        lowWatermark: 5,
      },
    });
    expect(cfg.thresholdEcdsaPresignPool.targetDepth).toBe(20);
    expect(cfg.thresholdEcdsaPresignPool.lowWatermark).toBe(5);
  });

  test('scheduler no-ops cleanly when policy is disabled', async () => {
    const result = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      clientVerifyingShareB64u: 'client-share',
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
      relayerKeyId: 'rk-1',
      clientVerifyingShareB64u: 'client-share',
      participantIds: [1, 2],
      clientSigningShare32: new Uint8Array(32),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 2 },
    });
    const second = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-1',
      clientVerifyingShareB64u: 'client-share',
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
      relayerKeyId: 'rk-1',
      clientVerifyingShareB64u: 'client-share-1',
      participantIds: [1, 2],
      clientSigningShare32: new Uint8Array(32),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
    });
    const second = scheduleThresholdEcdsaClientPresignaturePoolRefill({
      relayerUrl: 'https://relay.example',
      relayerKeyId: 'rk-2',
      clientVerifyingShareB64u: 'client-share-2',
      participantIds: [1, 2],
      clientSigningShare32: new Uint8Array(32),
      workerCtx: {} as any,
      poolPolicy: { enabled: true, targetDepth: 2, lowWatermark: 1, maxRefillInFlight: 1 },
    });

    expect(first.scheduled).toBe(true);
    expect(second.scheduled).toBe(false);
    expect(second.reason).toBe('global_in_flight_limit');
  });
});
