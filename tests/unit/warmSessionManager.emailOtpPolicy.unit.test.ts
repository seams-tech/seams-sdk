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
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
  type WarmClaimFixture,
} from './helpers/warmSessionManager.fixtures';

test.describe('WarmSessionManager Email OTP policy enforcement', () => {
  test('restores session-retained Email OTP ECDSA capability from sealed refresh before clearing it', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const bootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId: 'sealed-restore.testnet',
      chain: 'evm',
      sessionId: 'ecdsa-sealed-restore-session',
      sessionJwt: 'jwt:ecdsa-sealed-restore-session',
      walletSigningSessionId: 'wallet-signing-session-sealed-restore',
    });
    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'sealed-restore.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap,
    });
    const claimsBySessionId: Record<string, WarmClaimFixture> = {
      [record.thresholdSessionId]: { state: 'missing' as const },
    };
    const clears: string[] = [];
    const restoreCalls: string[] = [];
    const restoreEvents: string[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: {
        ...createWarmSessionStatusReader(claimsBySessionId),
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
      signingSessionSealedStore: {
        readRecord: async () => ({
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-sealed-restore',
          authMethod: 'email_otp',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: 'wallet-signing-session-sealed-restore',
          thresholdSessionIds: { ecdsa: record.thresholdSessionId },
          sealedSecretB64u: 'sealed-session-secret',
          curve: 'ecdsa',
          walletId: 'sealed-restore.testnet',
          userId: 'sealed-restore.testnet',
          signingRootId: record.signingRootId,
          relayerUrl: record.relayerUrl,
          keyVersion: 'kv-test',
          shamirPrimeB64u: 'prime-test',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 120_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        }),
        acquireRestoreLease: async ({ thresholdSessionId }) => ({
          v: 1,
          walletSigningSessionId: 'wallet-signing-session-sealed-restore',
          thresholdSessionId,
          ownerId: 'owner-test',
          attemptId: 'attempt-test',
          startedAtMs: Date.now(),
          expiresAtMs: Date.now() + 15_000,
        }),
        releaseRestoreLease: async (lease) => {
          restoreCalls.push(`release:${lease?.thresholdSessionId}`);
        },
      },
      rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord: async ({
        sealedRecord,
        ecdsaRecord,
      }) => {
        restoreCalls.push(
          `restore:${sealedRecord.walletSigningSessionId}:${ecdsaRecord.thresholdSessionId}`,
        );
        claimsBySessionId[record.thresholdSessionId] = {
          state: 'warm',
          remainingUses: 4,
          expiresAtMs: Date.now() + 120_000,
        };
        return {
          bootstrap,
          remainingUses: 4,
          expiresAtMs: Date.now() + 120_000,
        };
      },
      onSealedRestore: (event) => {
        restoreEvents.push(`${event.status}:${event.chain}:${event.thresholdSessionId}`);
      },
    });

    const warmSession = await manager.getWarmSession('sealed-restore.testnet');

    expect(warmSession.capabilities.ecdsa.evm.state).toBe('ready');
    expect(warmSession.capabilities.ecdsa.evm.prfClaim).toMatchObject({
      state: 'warm',
      remainingUses: 4,
    });
    expect(clears).toEqual([]);
    expect(restoreCalls).toEqual([
      'restore:wallet-signing-session-sealed-restore:ecdsa-sealed-restore-session',
      'release:ecdsa-sealed-restore-session',
    ]);
    expect(restoreEvents).toEqual([
      'started:evm:ecdsa-sealed-restore-session',
      'restored:evm:ecdsa-sealed-restore-session',
    ]);
  });

  test('deletes failed Email OTP sealed refresh and falls back to OTP unlock', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'sealed-fail.testnet',
      chain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'sealed-fail.testnet',
        chain: 'tempo',
        sessionId: 'ecdsa-sealed-fail-session',
        sessionJwt: 'jwt:ecdsa-sealed-fail-session',
        walletSigningSessionId: 'wallet-signing-session-sealed-fail',
      }),
    });
    const clears: string[] = [];
    const sealedStoreEvents: string[] = [];
    const restoreEvents: string[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: {
        ...createWarmSessionStatusReader({
          [record.thresholdSessionId]: { state: 'missing' },
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
      signingSessionSealedStore: {
        readRecord: async () => ({
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-sealed-fail',
          authMethod: 'email_otp',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: 'wallet-signing-session-sealed-fail',
          thresholdSessionIds: { ecdsa: record.thresholdSessionId },
          sealedSecretB64u: 'sealed-session-secret',
          curve: 'ecdsa',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 120_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        }),
        deleteRecord: async (thresholdSessionId) => {
          sealedStoreEvents.push(`delete:${thresholdSessionId}`);
        },
        acquireRestoreLease: async ({ thresholdSessionId }) => ({
          v: 1,
          walletSigningSessionId: 'wallet-signing-session-sealed-fail',
          thresholdSessionId,
          ownerId: 'owner-test',
          attemptId: 'attempt-test',
          startedAtMs: Date.now(),
          expiresAtMs: Date.now() + 15_000,
        }),
        releaseRestoreLease: async (lease) => {
          sealedStoreEvents.push(`release:${lease?.thresholdSessionId}`);
        },
      },
      rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord: async () => {
        throw new Error('remove-server-seal rejected');
      },
      onSealedRestore: (event) => {
        restoreEvents.push(`${event.status}:${event.chain}:${event.thresholdSessionId}`);
      },
    });

    const warmSession = await manager.getWarmSession('sealed-fail.testnet');

    expect(warmSession.capabilities.ecdsa.tempo.state).toBe('missing');
    expect(sealedStoreEvents).toEqual([
      'delete:ecdsa-sealed-fail-session',
      'release:ecdsa-sealed-fail-session',
    ]);
    expect(clears).toEqual([
      'presign:sealed-fail.testnet:tempo',
      'lane:sealed-fail.testnet:tempo',
      'warm:ecdsa-sealed-fail-session',
    ]);
    expect(restoreEvents).toEqual([
      'started:tempo:ecdsa-sealed-fail-session',
      'failed:tempo:ecdsa-sealed-fail-session',
    ]);
  });

  test('rejects sealed restore when recorded Ed25519 session is missing from same wallet signing session', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'all-curves.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'all-curves.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-all-curves-session',
        sessionJwt: 'jwt:ecdsa-all-curves-session',
        walletSigningSessionId: 'wallet-signing-session-all-curves',
      }),
    });
    const sealedStoreEvents: string[] = [];
    const restoreCalls: string[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: createWarmSessionStatusReader({
        [record.thresholdSessionId]: { state: 'missing' },
      }),
      clearThresholdEcdsaSessionRecordForLane: (args) => {
        clearThresholdEcdsaSessionRecordForLane(ecdsaStore, args);
      },
      signingSessionSealedStore: {
        readRecord: async () => ({
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-all-curves',
          authMethod: 'email_otp',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: 'wallet-signing-session-all-curves',
          thresholdSessionIds: {
            ecdsa: record.thresholdSessionId,
            ed25519: 'ed25519-all-curves-session',
          },
          sealedSecretB64u: 'sealed-session-secret',
          curve: 'ecdsa',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 120_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        }),
        deleteRecord: async (thresholdSessionId) => {
          sealedStoreEvents.push(`delete:${thresholdSessionId}`);
        },
      },
      rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord: async () => {
        restoreCalls.push('restore');
        return null;
      },
    });

    const warmSession = await manager.getWarmSession('all-curves.testnet');

    expect(warmSession.capabilities.ecdsa.evm.state).toBe('missing');
    expect(sealedStoreEvents).toEqual(['delete:ecdsa-all-curves-session']);
    expect(restoreCalls).toEqual([]);
  });

  test('rejects sealed restore when auth method does not match Email OTP', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'auth-mismatch.testnet',
      chain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'auth-mismatch.testnet',
        chain: 'tempo',
        sessionId: 'ecdsa-auth-mismatch-session',
        sessionJwt: 'jwt:ecdsa-auth-mismatch-session',
        walletSigningSessionId: 'wallet-signing-session-auth-mismatch',
      }),
    });
    const sealedStoreEvents: string[] = [];
    const restoreCalls: string[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: createWarmSessionStatusReader({
        [record.thresholdSessionId]: { state: 'missing' },
      }),
      clearThresholdEcdsaSessionRecordForLane: (args) => {
        clearThresholdEcdsaSessionRecordForLane(ecdsaStore, args);
      },
      signingSessionSealedStore: {
        readRecord: async () => ({
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-auth-mismatch',
          authMethod: 'passkey',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: 'wallet-signing-session-auth-mismatch',
          thresholdSessionIds: { ecdsa: record.thresholdSessionId },
          sealedSecretB64u: 'sealed-session-secret',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 120_000,
          remainingUses: 4,
          updatedAtMs: Date.now(),
        }),
        deleteRecord: async (thresholdSessionId) => {
          sealedStoreEvents.push(`delete:${thresholdSessionId}`);
        },
      },
      rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord: async () => {
        restoreCalls.push('restore');
        return null;
      },
    });

    const warmSession = await manager.getWarmSession('auth-mismatch.testnet');

    expect(warmSession.capabilities.ecdsa.tempo.state).toBe('missing');
    expect(sealedStoreEvents).toEqual(['delete:ecdsa-auth-mismatch-session']);
    expect(restoreCalls).toEqual([]);
  });

  test('deletes exhausted sealed restore records and falls back to OTP unlock', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'sealed-exhausted.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'sealed-exhausted.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-sealed-exhausted-session',
        sessionJwt: 'jwt:ecdsa-sealed-exhausted-session',
        walletSigningSessionId: 'wallet-signing-session-sealed-exhausted',
      }),
    });
    const sealedStoreEvents: string[] = [];
    const manager = createWarmSessionManager({
      touchConfirm: createWarmSessionStatusReader({
        [record.thresholdSessionId]: { state: 'exhausted' },
      }),
      clearThresholdEcdsaSessionRecordForLane: (args) => {
        clearThresholdEcdsaSessionRecordForLane(ecdsaStore, args);
      },
      signingSessionSealedStore: {
        readRecord: async () => ({
          v: 1,
          alg: 'shamir3pass-v1',
          storageScope: 'iframe_origin_indexeddb',
          runtimeSessionId: 'runtime-sealed-exhausted',
          authMethod: 'email_otp',
          secretKind: 'signing_session_secret32',
          walletSigningSessionId: 'wallet-signing-session-sealed-exhausted',
          thresholdSessionIds: { ecdsa: record.thresholdSessionId },
          sealedSecretB64u: 'sealed-session-secret',
          issuedAtMs: Date.now(),
          expiresAtMs: Date.now() + 120_000,
          remainingUses: 0,
          updatedAtMs: Date.now(),
        }),
        deleteRecord: async (thresholdSessionId) => {
          sealedStoreEvents.push(`delete:${thresholdSessionId}`);
        },
        acquireRestoreLease: async ({ thresholdSessionId }) => ({
          v: 1,
          walletSigningSessionId: 'wallet-signing-session-sealed-exhausted',
          thresholdSessionId,
          ownerId: 'owner-test',
          attemptId: 'attempt-test',
          startedAtMs: Date.now(),
          expiresAtMs: Date.now() + 15_000,
        }),
        releaseRestoreLease: async (lease) => {
          sealedStoreEvents.push(`release:${lease?.thresholdSessionId}`);
        },
      },
      rehydrateEmailOtpEcdsaSigningSessionFromSealedRecord: async () => {
        throw new Error('Email OTP signing-session seal exhausted');
      },
    });

    const warmSession = await manager.getWarmSession('sealed-exhausted.testnet');

    expect(warmSession.capabilities.ecdsa.evm.state).toBe('missing');
    expect(sealedStoreEvents).toEqual([
      'delete:ecdsa-sealed-exhausted-session',
      'release:ecdsa-sealed-exhausted-session',
    ]);
  });

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
      authMethod: 'email_otp',
      retention: 'session',
    });
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('missing');
    expect(ecdsaStore.recordsByLane.size).toBe(0);
    expect(clears).toEqual([
      'presign:alice.testnet:evm',
      'lane:alice.testnet:evm',
      'warm:ecdsa-expired-session',
    ]);
  });

  test('resolves readiness from shared wallet signing-session budget before curve readiness', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const walletSigningSessionId = 'wallet-session-shared-budget';
    const ed25519Record = seedEd25519WarmSessionRecord({
      nearAccountId: 'shared-budget.testnet',
      thresholdSessionId: 'ed25519-shared-budget-session',
      thresholdSessionJwt: 'jwt:ed25519-shared-budget-session',
      walletSigningSessionId,
    });
    const ecdsaRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'shared-budget.testnet',
      chain: 'evm',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'shared-budget.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-shared-budget-session',
        sessionJwt: 'jwt:ecdsa-shared-budget-session',
        walletSigningSessionId,
      }),
    });

    const manager = createWarmSessionManager({
      touchConfirm: createWarmSessionStatusReader({
        [ed25519Record.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 5,
          expiresAtMs: Date.now() + 120_000,
        },
        [ecdsaRecord.thresholdSessionId]: {
          state: 'exhausted',
        },
      }),
    });

    const warmSession = await manager.getWarmSession('shared-budget.testnet');
    const ed25519Status = await manager.getEd25519SigningSessionStatus('shared-budget.testnet');
    const ecdsaStatus = await manager.getEcdsaSigningSessionStatus({
      nearAccountId: 'shared-budget.testnet',
      chain: 'evm',
    });

    expect(warmSession.capabilities.ed25519.prfClaim).toMatchObject({
      state: 'exhausted',
      sessionId: ed25519Record.thresholdSessionId,
    });
    expect(warmSession.capabilities.ecdsa.evm.prfClaim).toMatchObject({
      state: 'exhausted',
      sessionId: ecdsaRecord.thresholdSessionId,
    });
    expect(ed25519Status).toMatchObject({
      sessionId: ed25519Record.thresholdSessionId,
      status: 'exhausted',
      authMethod: 'passkey',
    });
    expect(ecdsaStatus).toMatchObject({
      sessionId: ecdsaRecord.thresholdSessionId,
      status: 'exhausted',
      authMethod: 'passkey',
    });
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
    ).rejects.toMatchObject({
      name: 'WalletAuthPolicyError',
      code: 'fresh_email_otp_required',
      policy: 'sensitive_operation_requires_fresh_email_otp',
      message:
        '[SigningEngine] evm signing requires fresh Email OTP verification with per_operation policy',
    });
    expect(provisionCalls).toEqual([]);
  });

  test('blocks implicit Tempo reconnect after single-use Email OTP capability is consumed', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'tempo-erin.testnet',
      chain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'tempo-erin.testnet',
        chain: 'tempo',
        sessionId: 'tempo-ecdsa-consumed-single-use-session',
        sessionJwt: 'jwt:tempo-ecdsa-consumed-single-use-session',
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
          nearAccountId: 'tempo-erin.testnet',
          chain: 'tempo',
          sessionId: 'unexpected-tempo-reconnect',
          sessionJwt: 'jwt:unexpected-tempo-reconnect',
        });
      },
    });

    await manager.applyEcdsaPostSignPolicy({
      nearAccountId: 'tempo-erin.testnet',
      chain: 'tempo',
      thresholdSessionId: record.thresholdSessionId,
    });

    await expect(
      manager.ensureEcdsaCapabilityReady({
        nearAccountId: 'tempo-erin.testnet',
        chain: 'tempo',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthPolicyError',
      code: 'fresh_email_otp_required',
      policy: 'sensitive_operation_requires_fresh_email_otp',
      message:
        '[SigningEngine] tempo signing requires fresh Email OTP verification with per_operation policy',
    });
    expect(provisionCalls).toEqual([]);
  });

  test('allows sensitive operations that inherit a valid Email OTP session policy', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'inherit-policy.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'inherit-policy.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-inherit-policy-session',
        sessionJwt: 'jwt:ecdsa-inherit-policy-session',
      }),
    });

    const manager = createWarmSessionManager();

    await expect(
      manager.assertEcdsaOperationAllowed({
        nearAccountId: 'inherit-policy.testnet',
        chain: 'evm',
        operationLabel: 'ordinary threshold signing',
        sensitivePolicy: 'inherit_session_policy',
      }),
    ).resolves.toBeUndefined();
  });

  test('allows sensitive operations that require fresh same-method auth when Email OTP is single-use', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'fresh-same-method.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'per_operation',
        retention: 'single_use',
        reason: 'sign',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'fresh-same-method.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-fresh-same-method-session',
        sessionJwt: 'jwt:ecdsa-fresh-same-method-session',
      }),
    });

    const manager = createWarmSessionManager();

    await expect(
      manager.assertEcdsaOperationAllowed({
        nearAccountId: 'fresh-same-method.testnet',
        chain: 'evm',
        operationLabel: 'sensitive threshold signing',
        sensitivePolicy: 'require_fresh_same_method',
      }),
    ).resolves.toBeUndefined();
  });

  test('blocks sensitive operations for Email OTP sessions when passkey is required', async () => {
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
        sensitivePolicy: 'require_passkey',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthPolicyError',
      code: 'passkey_step_up_required',
      policy: 'sensitive_operation_requires_passkey',
      message:
        '[SigningEngine] threshold-ecdsa key export requires fresh passkey authentication after Email OTP login',
    });
  });

  test('blocks sensitive operations when Email OTP is denied by policy', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'deny-email-otp.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'deny-email-otp.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-deny-email-otp-session',
        sessionJwt: 'jwt:ecdsa-deny-email-otp-session',
      }),
    });

    const manager = createWarmSessionManager();

    await expect(
      manager.assertEcdsaOperationAllowed({
        nearAccountId: 'deny-email-otp.testnet',
        chain: 'evm',
        operationLabel: 'blocked threshold operation',
        sensitivePolicy: 'deny_email_otp',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthPolicyError',
      code: 'passkey_step_up_required',
      policy: 'sensitive_operation_requires_passkey',
      message:
        '[SigningEngine] blocked threshold operation requires fresh passkey authentication after Email OTP login',
    });
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
        sensitivePolicy: 'require_fresh_same_method',
      }),
    ).rejects.toMatchObject({
      name: 'WalletAuthPolicyError',
      code: 'fresh_email_otp_required',
      policy: 'sensitive_operation_requires_fresh_email_otp',
      message:
        '[SigningEngine] sensitive threshold signing requires fresh Email OTP verification with per_operation policy',
    });
  });
});

function recordToKeyRef(record: NonNullable<ReturnType<typeof seedEcdsaWarmSessionRecord>>) {
  return {
    type: 'threshold-ecdsa-secp256k1' as const,
    userId: record.nearAccountId,
    relayerUrl: record.relayerUrl,
    signingRootId: record.signingRootId,
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
