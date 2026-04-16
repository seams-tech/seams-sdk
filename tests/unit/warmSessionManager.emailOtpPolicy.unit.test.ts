import { expect, test } from '@playwright/test';
import { createWarmSessionManager } from '@/core/signingEngine/session/WarmSessionManager';
import {
  clearThresholdEcdsaSessionRecordForLane,
  markThresholdEcdsaEmailOtpSessionConsumedForAccount,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionStatusReader,
  resetWarmSessionFixtureState,
  seedEcdsaWarmSessionRecord,
} from './helpers/warmSessionManager.fixtures';

test.describe('WarmSessionManager Email OTP policy enforcement', () => {
  test('invalidates expired Email OTP session state and clears local warm material', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'alice.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'alice.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-expired-session',
        sessionJwt: 'jwt:ecdsa-expired-session',
      }),
    });

    const clears: string[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: {
        ...createWarmSessionStatusReader({
          [record.thresholdSessionId]: { state: 'expired' },
        }),
        clearWarmSessionMaterial: async ({ sessionId }) => {
          clears.push(`warm:${sessionId}`);
        },
      },
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) => {
        clears.push(`presign:${String(nearAccountId)}:${chain}`);
      },
      clearThresholdEcdsaSessionRecordForLane: (args) => {
        clears.push(`lane:${String(args.nearAccountId)}:${args.chain}`);
        clearThresholdEcdsaSessionRecordForLane(ecdsaStore, args);
      },
    });

    const status = await manager.getEcdsaSigningSessionStatus({
      nearAccountId: 'alice.testnet',
      chain: 'evm',
    });
    const warmSession = await manager.getWarmSession('alice.testnet');

    expect(status).toEqual({
      sessionId: 'ecdsa-expired-session',
      status: 'expired',
    });
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('missing');
    expect(ecdsaStore.recordsByLane.size).toBe(0);
    expect(clears).toEqual([
      'presign:alice.testnet:evm',
      'lane:alice.testnet:evm',
      'warm:ecdsa-expired-session',
    ]);
  });

  test('discards single-use Email OTP capability after signing', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'bob.testnet',
      chain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'bob.testnet',
        chain: 'tempo',
        sessionId: 'ecdsa-single-use-session',
        sessionJwt: 'jwt:ecdsa-single-use-session',
      }),
    });

    const clears: string[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: {
        clearWarmSessionMaterial: async ({ sessionId }) => {
          clears.push(`warm:${sessionId}`);
        },
      },
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args) => {
        clears.push(`consume:${String(args.nearAccountId)}:${args.chain}`);
        markThresholdEcdsaEmailOtpSessionConsumedForAccount(ecdsaStore, args);
      },
      clearThresholdEcdsaSigningArtifactsForLane: ({ nearAccountId, chain }) => {
        clears.push(`presign:${String(nearAccountId)}:${chain}`);
      },
      clearThresholdEcdsaSessionRecordForLane: (args) => {
        clears.push(`lane:${String(args.nearAccountId)}:${args.chain}`);
        clearThresholdEcdsaSessionRecordForLane(ecdsaStore, args);
      },
    });

    await manager.applyEcdsaPostSignPolicy({
      nearAccountId: 'bob.testnet',
      chain: 'tempo',
      thresholdSessionId: record.thresholdSessionId,
    });

    const persistedRecord = Array.from(ecdsaStore.recordsByLane.values()).find(
      (candidate) => candidate.nearAccountId === 'bob.testnet' && candidate.chain === 'tempo',
    );
    expect(ecdsaStore.recordsByLane.size).toBe(1);
    expect(persistedRecord?.emailOtpAuthContext?.retention).toBe('single_use');
    expect(Number(persistedRecord?.emailOtpAuthContext?.consumedAtMs) || 0).toBeGreaterThan(0);
    expect(clears).toEqual([
      'consume:bob.testnet:tempo',
      'presign:bob.testnet:tempo',
      'warm:ecdsa-single-use-session',
    ]);
  });

  test('blocks implicit reconnect after single-use Email OTP capability is consumed', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'erin.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'erin.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-consumed-single-use-session',
        sessionJwt: 'jwt:ecdsa-consumed-single-use-session',
      }),
    });

    const provisionCalls: string[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: {
        clearWarmSessionMaterial: async () => undefined,
      },
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args) => {
        markThresholdEcdsaEmailOtpSessionConsumedForAccount(ecdsaStore, args);
      },
      clearThresholdEcdsaSigningArtifactsForLane: () => undefined,
      getThresholdEcdsaKeyRefForSigning: () => recordToKeyRef(record),
      provisionThresholdEcdsaSession: async () => {
        provisionCalls.push('provision');
        return createThresholdEcdsaBootstrapFixture({
          nearAccountId: 'erin.testnet',
          chain: 'evm',
          sessionId: 'unexpected-reconnect',
          sessionJwt: 'jwt:unexpected-reconnect',
        });
      },
    });

    await manager.applyEcdsaPostSignPolicy({
      nearAccountId: 'erin.testnet',
      chain: 'evm',
      thresholdSessionId: record.thresholdSessionId,
    });

    await expect(
      manager.ensureEcdsaCapabilityReady({
        nearAccountId: 'erin.testnet',
        chain: 'evm',
      }),
    ).rejects.toThrow(
      '[SigningEngine] evm signing requires fresh Email OTP verification with per_operation policy',
    );
    expect(provisionCalls).toEqual([]);
  });

  test('blocks sensitive operations for Email OTP sessions that still require passkey step-up', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'carol.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'carol.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-sensitive-session',
        sessionJwt: 'jwt:ecdsa-sensitive-session',
      }),
    });

    const manager = createWarmSessionManager();

    await expect(
      manager.assertEcdsaOperationAllowed({
        nearAccountId: 'carol.testnet',
        chain: 'evm',
        operationLabel: 'threshold-ecdsa key export',
        sensitivePolicy: 'passkey',
      }),
    ).rejects.toThrow(
      '[SigningEngine] threshold-ecdsa key export requires fresh passkey authentication after Email OTP login',
    );
  });

  test('requires per-operation Email OTP for operations that force single-use policy', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'dana.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
        stepUpRequired: true,
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'dana.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-session-policy',
        sessionJwt: 'jwt:ecdsa-session-policy',
      }),
    });

    const manager = createWarmSessionManager();

    await expect(
      manager.assertEcdsaOperationAllowed({
        nearAccountId: 'dana.testnet',
        chain: 'evm',
        operationLabel: 'sensitive threshold signing',
        sensitivePolicy: 'per_operation',
      }),
    ).rejects.toThrow(
      '[SigningEngine] sensitive threshold signing requires fresh Email OTP verification with per_operation policy',
    );
  });
});

function recordToKeyRef(
  record: NonNullable<ReturnType<typeof seedEcdsaWarmSessionRecord>>,
) {
  return {
    type: 'threshold-ecdsa-secp256k1' as const,
    userId: record.nearAccountId,
    relayerUrl: record.relayerUrl,
    ecdsaThresholdKeyId: record.ecdsaThresholdKeyId,
    participantIds: [...record.participantIds],
    backendBinding: {
      relayerKeyId: record.relayerKeyId,
      clientVerifyingShareB64u: record.clientVerifyingShareB64u,
    },
    thresholdSessionKind: record.thresholdSessionKind,
    thresholdSessionId: record.thresholdSessionId,
    ...(record.thresholdSessionJwt ? { thresholdSessionJwt: record.thresholdSessionJwt } : {}),
    ...(record.ethereumAddress ? { ethereumAddress: record.ethereumAddress } : {}),
    ...(record.thresholdEcdsaPublicKeyB64u
      ? { thresholdEcdsaPublicKeyB64u: record.thresholdEcdsaPublicKeyB64u }
      : {}),
    ...(record.relayerVerifyingShareB64u
      ? { relayerVerifyingShareB64u: record.relayerVerifyingShareB64u }
      : {}),
  };
}
