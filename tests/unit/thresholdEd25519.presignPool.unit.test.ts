import { expect, test } from '@playwright/test';
import type { ThresholdEd25519PresignCommitmentsWire } from '@/core/types/signer-worker';
import {
  applyRouterAbEd25519PresignPoolRefillResult,
  burnThresholdEd25519ReservedPresign,
  clearAllRouterAbEd25519ClientPresigns,
  clearRouterAbEd25519ClientPresignPool,
  createRouterAbEd25519PresignScopeKey,
  getRouterAbEd25519ClientPresignPoolStatus,
  reserveRouterAbEd25519ReadyPresignForScope,
  resolveRouterAbEd25519PresignPoolPolicy,
  scheduleRouterAbEd25519ClientPresignPoolRefill,
} from '@/core/signingEngine/threshold/ed25519/presignPool';
import type {
  Ed25519PresignOperationIdentity,
  Ed25519PresignScopeKey,
  RouterAbEd25519PresignPoolAcceptedEntry,
  RouterAbEd25519PresignPoolRefillPayload,
  RouterAbEd25519PresignPoolRefillResult,
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
  materialBindingDigest?: string;
}): RouterAbEd25519PresignPoolRefillPayload {
  const offerCount = input?.offerCount ?? 2;
  const materialBindingDigest = input?.materialBindingDigest || 'material-binding-digest';
  return {
    kind: 'router_ab_ed25519_presign_pool_refill_v1',
    relayUrl: 'https://relay.example',
    thresholdSessionId: 'threshold-session-id',
    signingGrantId: 'signing-grant-id',
    relayerKeyId: 'relayer-key',
    nearAccountId: 'alice.testnet',
    nearNetworkId: 'testnet',
    signerPublicKey: 'ed25519-public-key',
    participantIds: [1, 2],
    runtimePolicyScope,
    materialBindingDigest,
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
      clientVerifyingShareB64u: 'client-verifying-share',
      clientCommitments: {
        hiding: `client-hiding-${index + 1}`,
        binding: `client-binding-${index + 1}`,
      },
    })),
  };
}

function scopeKeyForPayload(
  input: RouterAbEd25519PresignPoolRefillPayload,
): Ed25519PresignScopeKey {
  return createRouterAbEd25519PresignScopeKey({
    thresholdSessionId: input.thresholdSessionId,
    signingGrantId: input.signingGrantId,
    relayerKeyId: input.relayerKeyId,
    nearAccountId: input.nearAccountId,
    nearNetworkId: input.nearNetworkId,
    signerPublicKey: input.signerPublicKey,
    participantIds: input.participantIds,
    runtimePolicyScope: input.runtimePolicyScope,
    materialBindingDigest: input.materialBindingDigest,
  });
}

function acceptedEntry(input: {
  clientPresignId: string;
  generation?: number;
  index?: number;
  expiresAtMs?: number;
}): RouterAbEd25519PresignPoolAcceptedEntry {
  const index = input.index ?? 1;
  return {
    clientPresignId: input.clientPresignId,
    generation: input.generation ?? 1,
    poolEntryBindingDigest: { bytes: Array.from({ length: 32 }, () => index) },
    signingWorkerId: 'server-a',
    serverRound1Handle: `server-round1-handle-${index}`,
    serverCommitments: {
      hiding: `server-hiding-${index}`,
      binding: `server-binding-${index}`,
    },
    serverVerifyingShareB64u: `server-verifying-share-${index}`,
    expiresAtMs: input.expiresAtMs ?? 5_000,
  };
}

function successResult(input: {
  request: RouterAbEd25519PresignPoolRefillPayload;
  accepted: readonly RouterAbEd25519PresignPoolAcceptedEntry[];
  rejectedClientPresignIds?: readonly string[];
}): RouterAbEd25519PresignPoolRefillResult {
  return {
    ok: true,
    generation: input.request.generation,
    scope: {
      request_id: `router-ab-pool-refill-${input.request.generation}`,
      account_id: input.request.nearAccountId,
      session_id: input.request.thresholdSessionId,
      signing_worker_id: 'server-a',
    },
    accepted: input.accepted,
    rejectedClientPresignIds: input.rejectedClientPresignIds ?? [],
  };
}

function failureResult(input: {
  request: RouterAbEd25519PresignPoolRefillPayload;
  code: string;
  message: string;
}): RouterAbEd25519PresignPoolRefillResult {
  return {
    ok: false,
    generation: input.request.generation,
    code: input.code,
    message: input.message,
  };
}

const operation: Ed25519PresignOperationIdentity = {
  kind: 'router_ab_ed25519_presign_operation_identity_v1',
  operationId: 'operation-1' as SigningOperationId,
  operationFingerprint: 'fingerprint-1' as SigningOperationFingerprint,
  purpose: 'near_transaction',
};

test.describe('Router A/B Ed25519 client presign pool lifecycle', () => {
  test.beforeEach(() => {
    clearAllRouterAbEd25519ClientPresigns();
  });

  test('policy defaults and clamps invalid values', () => {
    expect(resolveRouterAbEd25519PresignPoolPolicy(undefined)).toEqual({
      targetDepth: 2,
      lowWatermark: 1,
      maxAcceptedRefillCount: 8,
      ttlMs: 120_000,
    });
    expect(
      resolveRouterAbEd25519PresignPoolPolicy({
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

  test('schedules refill, applies accepted entries, and follows server expiry', () => {
    const request = payload();
    const scopeKey = scopeKeyForPayload(request);

    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_000)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
      generation: 1,
    });
    expect(
      getRouterAbEd25519ClientPresignPoolStatus(
        {
          kind: 'get_router_ab_ed25519_presign_pool_status_v1',
          scopeKey,
        },
        1_001,
      ),
    ).toMatchObject({
      offeredCount: 2,
      readyCount: 0,
      refillInFlight: true,
    });

    applyRouterAbEd25519PresignPoolRefillResult({
      payload: request,
      nowMs: 1_100,
      result: successResult({
        request,
        accepted: [
          acceptedEntry({
            clientPresignId: 'client-presign-1',
            index: 1,
            expiresAtMs: 5_000,
          }),
        ],
        rejectedClientPresignIds: ['client-presign-2'],
      }),
    });

    expect(
      getRouterAbEd25519ClientPresignPoolStatus(
        {
          kind: 'get_router_ab_ed25519_presign_pool_status_v1',
          scopeKey,
        },
        1_200,
      ),
    ).toMatchObject({
      offeredCount: 0,
      readyCount: 1,
      burnedCount: 1,
      refillInFlight: false,
      nextExpiryAtMs: 5_000,
    });
    expect(
      getRouterAbEd25519ClientPresignPoolStatus(
        {
          kind: 'get_router_ab_ed25519_presign_pool_status_v1',
          scopeKey,
        },
        5_001,
      ),
    ).toMatchObject({
      readyCount: 0,
      burnedCount: 2,
      nextExpiryAtMs: null,
    });
  });

  test('stale generation clear prevents old refill result from repopulating the pool', () => {
    const request = payload();
    const scopeKey = scopeKeyForPayload(request);
    scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_000);

    const cleared = clearRouterAbEd25519ClientPresignPool({
      kind: 'clear_router_ab_ed25519_presign_pool_v1',
      scopeKey,
      generation: 1,
      reason: 'signing_session_change',
    });
    expect(cleared).toMatchObject({ previousGeneration: 1, nextGeneration: 2, clearedEntries: 2 });

    applyRouterAbEd25519PresignPoolRefillResult({
      payload: request,
      nowMs: 1_100,
      result: successResult({
        request,
        accepted: [acceptedEntry({ clientPresignId: 'client-presign-1' })],
      }),
    });

    expect(
      getRouterAbEd25519ClientPresignPoolStatus(
        {
          kind: 'get_router_ab_ed25519_presign_pool_status_v1',
          scopeKey,
        },
        1_200,
      ),
    ).toMatchObject({
      generation: 2,
      offeredCount: 0,
      readyCount: 0,
      burnedCount: 0,
    });
  });

  test('scope key changes when session and material identity fields change', () => {
    const request = payload();
    const base = scopeKeyForPayload(request);
    const variants = [
      { ...request, thresholdSessionId: 'threshold-session-next' },
      { ...request, signingGrantId: 'signing-grant-next' },
      { ...request, relayerKeyId: 'relayer-key-next' },
      { ...request, participantIds: [1, 3] },
      payload({ materialBindingDigest: 'material-binding-digest-next' }),
    ].map(scopeKeyForPayload);

    for (const variant of variants) {
      expect(variant).not.toBe(base);
    }
  });

  test('suppresses concurrent refill for the same scope', () => {
    const request = payload();

    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_000)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_001)).toMatchObject({
      scheduled: false,
      reason: 'in_flight_for_scope',
    });
  });

  test('backs off after capacity failures', () => {
    const request = payload();

    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_000)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
    applyRouterAbEd25519PresignPoolRefillResult({
      payload: request,
      nowMs: 1_100,
      result: failureResult({
        request,
        code: 'capacity_exceeded',
        message: 'capacity exhausted',
      }),
    });

    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_101)).toMatchObject({
      scheduled: false,
      reason: 'backoff_active',
    });
    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 11_101)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
  });

  test('backs off after repeated wrong-scope refill failures', () => {
    const request = payload();

    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_000)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
    applyRouterAbEd25519PresignPoolRefillResult({
      payload: request,
      nowMs: 1_100,
      result: failureResult({ request, code: 'wrong_scope', message: 'wrong scope' }),
    });
    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_101)).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
    });
    applyRouterAbEd25519PresignPoolRefillResult({
      payload: request,
      nowMs: 1_200,
      result: failureResult({ request, code: 'wrong_scope', message: 'wrong scope' }),
    });

    expect(scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_201)).toMatchObject({
      scheduled: false,
      reason: 'backoff_active',
    });
  });

  test('reserves a ready Router A/B presign for one operation and burns the nonce handle state', () => {
    const request = payload({ offerCount: 1, lowWatermark: 0 });
    const scopeKey = scopeKeyForPayload(request);
    scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_000);
    applyRouterAbEd25519PresignPoolRefillResult({
      payload: request,
      nowMs: 1_100,
      result: successResult({
        request,
        accepted: [
          acceptedEntry({
            clientPresignId: 'client-presign-1',
            index: 1,
            expiresAtMs: 5_000,
          }),
        ],
      }),
    });

    const reservation = reserveRouterAbEd25519ReadyPresignForScope({
      thresholdSessionId: request.thresholdSessionId,
      signingGrantId: request.signingGrantId,
      relayerKeyId: request.relayerKeyId,
      nearAccountId: request.nearAccountId,
      nearNetworkId: request.nearNetworkId,
      signerPublicKey: request.signerPublicKey,
      participantIds: request.participantIds,
      runtimePolicyScope: request.runtimePolicyScope,
      materialBindingDigest: request.materialBindingDigest,
      operation,
      nowMs: 1_200,
    });
    expect(reservation).toMatchObject({
      ok: true,
      scopeKey,
      reservation: {
        operation,
        entry: {
          source: 'router_ab_ed25519_presign_pool_v2',
          presignId: 'server-round1-handle-1',
          nonceHandle: 'nonce-handle-1',
        },
      },
    });
    expect(
      getRouterAbEd25519ClientPresignPoolStatus(
        {
          kind: 'get_router_ab_ed25519_presign_pool_status_v1',
          scopeKey,
        },
        1_201,
      ),
    ).toMatchObject({
      readyCount: 0,
    });
    if (!reservation.ok) throw new Error('expected reservation');
    burnThresholdEd25519ReservedPresign({
      scopeKey: reservation.scopeKey,
      reservation: reservation.reservation,
      reason: 'used',
      nowMs: 1_300,
    });
    expect(
      getRouterAbEd25519ClientPresignPoolStatus(
        {
          kind: 'get_router_ab_ed25519_presign_pool_status_v1',
          scopeKey,
        },
        1_301,
      ),
    ).toMatchObject({
      readyCount: 0,
      burnedCount: 1,
    });
  });

  test('pool miss leaves no reservation and schedules Router A/B refill', () => {
    const request = payload({ offerCount: 2 });
    const scopeKey = scopeKeyForPayload(request);

    const miss = reserveRouterAbEd25519ReadyPresignForScope({
      thresholdSessionId: request.thresholdSessionId,
      signingGrantId: request.signingGrantId,
      relayerKeyId: request.relayerKeyId,
      nearAccountId: request.nearAccountId,
      nearNetworkId: request.nearNetworkId,
      signerPublicKey: request.signerPublicKey,
      participantIds: request.participantIds,
      runtimePolicyScope: request.runtimePolicyScope,
      materialBindingDigest: request.materialBindingDigest,
      operation,
      nowMs: 1_000,
    });
    const refill = scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_000);

    expect(miss).toMatchObject({
      ok: false,
      code: 'pool_empty',
    });
    expect(refill).toMatchObject({
      scheduled: true,
      reason: 'scheduled',
      generation: 1,
    });
    expect(
      getRouterAbEd25519ClientPresignPoolStatus(
        {
          kind: 'get_router_ab_ed25519_presign_pool_status_v1',
          scopeKey,
        },
        1_001,
      ),
    ).toMatchObject({
      offeredCount: 2,
      readyCount: 0,
      refillInFlight: true,
    });
  });

  test('does not reserve a ready entry for a different material binding digest', () => {
    const request = payload({ offerCount: 1, lowWatermark: 0 });
    const scopeKey = scopeKeyForPayload(request);
    scheduleRouterAbEd25519ClientPresignPoolRefill(request, 1_000);
    applyRouterAbEd25519PresignPoolRefillResult({
      payload: request,
      nowMs: 1_100,
      result: successResult({
        request,
        accepted: [
          acceptedEntry({
            clientPresignId: 'client-presign-1',
            index: 1,
            expiresAtMs: 5_000,
          }),
        ],
      }),
    });

    const reservation = reserveRouterAbEd25519ReadyPresignForScope({
      thresholdSessionId: request.thresholdSessionId,
      signingGrantId: request.signingGrantId,
      relayerKeyId: request.relayerKeyId,
      nearAccountId: request.nearAccountId,
      nearNetworkId: request.nearNetworkId,
      signerPublicKey: request.signerPublicKey,
      participantIds: request.participantIds,
      runtimePolicyScope: request.runtimePolicyScope,
      materialBindingDigest: 'different-material-binding-digest',
      operation,
      nowMs: 1_200,
    });

    expect(reservation).toMatchObject({
      ok: false,
      code: 'pool_empty',
    });
    expect(
      getRouterAbEd25519ClientPresignPoolStatus(
        {
          kind: 'get_router_ab_ed25519_presign_pool_status_v1',
          scopeKey,
        },
        1_201,
      ),
    ).toMatchObject({
      readyCount: 1,
    });
  });
});
