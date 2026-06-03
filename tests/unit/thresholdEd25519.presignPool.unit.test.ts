import { expect, test } from '@playwright/test';
import type { PrepareThresholdEd25519PresignPoolPayload } from '@/core/types/signer-worker';
import {
  applyThresholdEd25519PresignRefillResult,
  burnThresholdEd25519ReservedPresign,
  clearAllThresholdEd25519ClientPresigns,
  clearThresholdEd25519ClientPresignPool,
  createThresholdEd25519PresignScopeKey,
  getThresholdEd25519ClientPresignPoolStatus,
  reserveThresholdEd25519ReadyPresign,
  resolveThresholdEd25519PresignPoolPolicy,
  scheduleThresholdEd25519ClientPresignPoolRefill,
  selectThresholdEd25519PresignSigningPath,
} from '@/core/signingEngine/threshold/ed25519/presignPool';
import type {
  Ed25519PresignScopeKey,
  Ed25519PresignOperationIdentity,
} from '@/core/signingEngine/threshold/ed25519/presignPool';
import type {
  SigningOperationFingerprint,
  SigningOperationId,
} from '@/core/signingEngine/session/operationState/types';

const runtimePolicyScope = {
  orgId: 'org-presign-pool',
  projectId: 'project-presign-pool',
  envId: 'test',
  signingRootVersion: 'root-v1',
};

function payload(input?: {
  generation?: number;
  targetDepth?: number;
  lowWatermark?: number;
  offerCount?: number;
  clientVerifyingShareB64u?: string;
}): PrepareThresholdEd25519PresignPoolPayload {
  const offerCount = input?.offerCount ?? 2;
  const clientVerifyingShareB64u =
    input?.clientVerifyingShareB64u || 'client-verifying-share';
  return {
    kind: 'prepare_threshold_ed25519_presign_pool_v1',
    sessionKind: 'jwt',
    thresholdSessionAuthToken: 'threshold-session-token',
    relayUrl: 'https://relay.example',
    thresholdSessionId: 'threshold-session-id',
    walletSigningSessionId: 'wallet-signing-session-id',
    relayerKeyId: 'relayer-key',
    nearAccountId: 'alice.testnet',
    nearNetworkId: 'testnet',
    signerPublicKey: 'ed25519-public-key',
    participantIds: [1, 2],
    runtimePolicyScope,
    policy: {
      targetDepth: input?.targetDepth ?? 2,
      lowWatermark: input?.lowWatermark ?? 1,
      maxAcceptedRefillCount: 8,
      ttlMs: 60_000,
    },
    requestTag: 'background_presign_pool_refill',
    generation: input?.generation ?? 1,
    clientPresigns: Array.from({ length: offerCount }, (_, index) => ({
      clientPresignId: `client-presign-${index + 1}`,
      nonceHandle: `nonce-handle-${index + 1}`,
      clientVerifyingShareB64u,
      clientCommitments: {
        hiding: `client-hiding-${index + 1}`,
        binding: `client-binding-${index + 1}`,
      },
    })),
  };
}

function scopeKeyForPayload(input: PrepareThresholdEd25519PresignPoolPayload): Ed25519PresignScopeKey {
  return createThresholdEd25519PresignScopeKey({
    thresholdSessionId: input.thresholdSessionId,
    walletSigningSessionId: input.walletSigningSessionId,
    relayerKeyId: input.relayerKeyId,
    nearAccountId: input.nearAccountId,
    nearNetworkId: input.nearNetworkId,
    signerPublicKey: input.signerPublicKey,
    participantIds: input.participantIds,
    runtimePolicyScope: input.runtimePolicyScope,
    clientVerifyingShareB64u: input.clientPresigns[0].clientVerifyingShareB64u,
  });
}

const operation: Ed25519PresignOperationIdentity = {
  kind: 'threshold_ed25519_presign_operation_identity_v1',
  operationId: 'operation-1' as SigningOperationId,
  operationFingerprint: 'fingerprint-1' as SigningOperationFingerprint,
  purpose: 'near_transaction',
};

test.describe('threshold Ed25519 client presign pool lifecycle', () => {
  test.beforeEach(() => {
    clearAllThresholdEd25519ClientPresigns();
  });

  test('policy defaults and clamps invalid values', () => {
    expect(resolveThresholdEd25519PresignPoolPolicy(undefined)).toEqual({
      targetDepth: 2,
      lowWatermark: 1,
      maxAcceptedRefillCount: 8,
      ttlMs: 120_000,
    });
    expect(
      resolveThresholdEd25519PresignPoolPolicy({
        targetDepth: -10,
        lowWatermark: 99,
        maxAcceptedRefillCount: 99,
        ttlMs: -5,
      }),
    ).toEqual({
      targetDepth: 1,
      lowWatermark: 1,
      maxAcceptedRefillCount: 8,
      ttlMs: 1,
    });
  });

  test('schedules refill, applies accepted pairs, and follows server expiry', () => {
    const request = payload();
    const scopeKey = scopeKeyForPayload(request);

    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_000)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
      generation: 1,
    });
    expect(getThresholdEd25519ClientPresignPoolStatus({ kind: 'get_threshold_ed25519_presign_pool_status_v1', scopeKey }, 1_001)).toMatchObject({
      offeredCount: 2,
      readyCount: 0,
      refillInFlight: true,
    });

    applyThresholdEd25519PresignRefillResult({
      payload: request,
      nowMs: 1_100,
      result: {
        ok: true,
        kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
        generation: 1,
        accepted: [
          {
            presignId: 'server-presign-1',
            clientPresignId: 'client-presign-1',
            relayerCommitments: { hiding: 'relayer-hiding-1', binding: 'relayer-binding-1' },
            relayerVerifyingShareB64u: 'relayer-verifying-share',
            expiresAtMs: 5_000,
          },
        ],
        rejectedClientPresignIds: ['client-presign-2'],
        expiresAtMs: 5_000,
      },
    });

    expect(getThresholdEd25519ClientPresignPoolStatus({ kind: 'get_threshold_ed25519_presign_pool_status_v1', scopeKey }, 1_200)).toMatchObject({
      offeredCount: 0,
      readyCount: 1,
      burnedCount: 1,
      refillInFlight: false,
      nextExpiryAtMs: 5_000,
    });
    expect(getThresholdEd25519ClientPresignPoolStatus({ kind: 'get_threshold_ed25519_presign_pool_status_v1', scopeKey }, 5_001)).toMatchObject({
      readyCount: 0,
      burnedCount: 2,
      nextExpiryAtMs: null,
    });
  });

  test('stale generation clear prevents old refill result from repopulating the pool', () => {
    const request = payload();
    const scopeKey = scopeKeyForPayload(request);
    scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_000);

    const cleared = clearThresholdEd25519ClientPresignPool({
      kind: 'clear_threshold_ed25519_presign_pool_v1',
      scopeKey,
      generation: 1,
      reason: 'threshold_session_change',
    });
    expect(cleared).toMatchObject({ previousGeneration: 1, nextGeneration: 2, clearedEntries: 2 });

    applyThresholdEd25519PresignRefillResult({
      payload: request,
      nowMs: 1_100,
      result: {
        ok: true,
        kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
        generation: 1,
        accepted: [
          {
            presignId: 'server-presign-stale',
            clientPresignId: 'client-presign-1',
            relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
            relayerVerifyingShareB64u: 'relayer-verifying-share',
            expiresAtMs: 5_000,
          },
        ],
        rejectedClientPresignIds: [],
        expiresAtMs: 5_000,
      },
    });

    expect(getThresholdEd25519ClientPresignPoolStatus({ kind: 'get_threshold_ed25519_presign_pool_status_v1', scopeKey }, 1_200)).toMatchObject({
      generation: 2,
      offeredCount: 0,
      readyCount: 0,
      burnedCount: 0,
    });
  });

  test('scope key changes when generation-defining session fields change', () => {
    const request = payload();
    const base = scopeKeyForPayload(request);
    const variants = [
      { ...request, thresholdSessionId: 'threshold-session-next' },
      { ...request, walletSigningSessionId: 'wallet-signing-session-next' },
      { ...request, relayerKeyId: 'relayer-key-next' },
      { ...request, participantIds: [1, 3] },
      payload({ clientVerifyingShareB64u: 'client-verifying-share-next' }),
    ].map(scopeKeyForPayload);

    for (const variant of variants) {
      expect(variant).not.toBe(base);
    }
  });

  test('suppresses concurrent refill for the same scope', () => {
    const request = payload();

    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_000)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_001)).toMatchObject({
      scheduled: false,
      reason: 'in_flight_for_scope',
    });
  });

  test('backs off after capacity failures', () => {
    const request = payload();

    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_000)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
    applyThresholdEd25519PresignRefillResult({
      payload: request,
      nowMs: 1_100,
      result: {
        ok: false,
        kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
        generation: 1,
        code: 'capacity_exceeded',
        message: 'capacity exhausted',
      },
    });

    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_101)).toMatchObject({
      scheduled: false,
      reason: 'backoff_active',
    });
    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 11_101)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
  });

  test('backs off after repeated wrong-scope refill failures', () => {
    const request = payload();

    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_000)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
    applyThresholdEd25519PresignRefillResult({
      payload: request,
      nowMs: 1_100,
      result: {
        ok: false,
        kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
        generation: 1,
        code: 'wrong_scope',
        message: 'wrong scope',
      },
    });
    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_101)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
    applyThresholdEd25519PresignRefillResult({
      payload: request,
      nowMs: 1_200,
      result: {
        ok: false,
        kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
        generation: 1,
        code: 'wrong_scope',
        message: 'wrong scope',
      },
    });

    expect(scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_201)).toMatchObject({
      scheduled: false,
      reason: 'backoff_active',
    });
  });

  test('reserves a ready presign for one operation and burns the nonce handle state', () => {
    const request = payload({ offerCount: 1, lowWatermark: 0 });
    const scopeKey = scopeKeyForPayload(request);
    scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_000);
    applyThresholdEd25519PresignRefillResult({
      payload: request,
      nowMs: 1_100,
      result: {
        ok: true,
        kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
        generation: 1,
        accepted: [
          {
            presignId: 'server-presign-1',
            clientPresignId: 'client-presign-1',
            relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
            relayerVerifyingShareB64u: 'relayer-verifying-share',
            expiresAtMs: 5_000,
          },
        ],
        rejectedClientPresignIds: [],
        expiresAtMs: 5_000,
      },
    });

    const reservation = reserveThresholdEd25519ReadyPresign({ scopeKey, operation, nowMs: 1_200 });
    expect(reservation).toMatchObject({
      ok: true,
      reservation: {
        state: 'reserved_for_finalize',
        operation,
        entry: { presignId: 'server-presign-1', nonceHandle: 'nonce-handle-1' },
      },
    });
    expect(getThresholdEd25519ClientPresignPoolStatus({ kind: 'get_threshold_ed25519_presign_pool_status_v1', scopeKey }, 1_201)).toMatchObject({
      readyCount: 0,
    });
    if (!reservation.ok) throw new Error('expected reservation');
    burnThresholdEd25519ReservedPresign({
      scopeKey,
      reservation: reservation.reservation,
      reason: 'used',
      nowMs: 1_300,
    });
    expect(getThresholdEd25519ClientPresignPoolStatus({ kind: 'get_threshold_ed25519_presign_pool_status_v1', scopeKey }, 1_301)).toMatchObject({
      readyCount: 0,
      burnedCount: 1,
    });
  });

  test('selector chooses one-RTT on pool hit and preserves operation identity', () => {
    const request = payload({ offerCount: 1, lowWatermark: 0 });
    const scopeKey = scopeKeyForPayload(request);
    scheduleThresholdEd25519ClientPresignPoolRefill(request, 1_000);
    applyThresholdEd25519PresignRefillResult({
      payload: request,
      nowMs: 1_100,
      result: {
        ok: true,
        kind: 'prepare_threshold_ed25519_presign_pool_result_v1',
        generation: 1,
        accepted: [
          {
            presignId: 'server-presign-hit',
            clientPresignId: 'client-presign-1',
            relayerCommitments: { hiding: 'relayer-hiding', binding: 'relayer-binding' },
            relayerVerifyingShareB64u: 'relayer-verifying-share',
            expiresAtMs: 5_000,
          },
        ],
        rejectedClientPresignIds: [],
        expiresAtMs: 5_000,
      },
    });

    const selection = selectThresholdEd25519PresignSigningPath({
      scopeKey,
      operation,
      refillPayload: request,
      nowMs: 1_200,
    });

    expect(selection).toMatchObject({
      kind: 'pool_hit_one_rtt',
      operation,
      reservation: {
        operation,
        entry: { presignId: 'server-presign-hit', nonceHandle: 'nonce-handle-1' },
      },
    });
    expect(getThresholdEd25519ClientPresignPoolStatus({ kind: 'get_threshold_ed25519_presign_pool_status_v1', scopeKey }, 1_201)).toMatchObject({
      readyCount: 0,
      refillInFlight: false,
    });
  });

  test('selector chooses two-RTT fallback on miss and schedules refill', () => {
    const request = payload({ offerCount: 2 });
    const scopeKey = scopeKeyForPayload(request);

    const selection = selectThresholdEd25519PresignSigningPath({
      scopeKey,
      operation,
      refillPayload: request,
      nowMs: 1_000,
    });

    expect(selection).toMatchObject({
      kind: 'pool_miss_two_rtt',
      operation,
      miss: { ok: false, code: 'pool_not_ready' },
      refill: { scheduled: true, reason: 'scheduled', generation: 1 },
    });
    expect(getThresholdEd25519ClientPresignPoolStatus({ kind: 'get_threshold_ed25519_presign_pool_status_v1', scopeKey }, 1_001)).toMatchObject({
      offeredCount: 2,
      readyCount: 0,
      refillInFlight: true,
    });
  });
});
