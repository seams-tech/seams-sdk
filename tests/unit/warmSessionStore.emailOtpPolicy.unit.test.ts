import { expect, test } from '@playwright/test';
import {
  clearThresholdEcdsaSessionRecordForLane,
  listThresholdEcdsaKeyRefsForLookup,
  listThresholdEcdsaSessionRecordsForLookup,
  markThresholdEcdsaEmailOtpSessionConsumedForAccount,
} from '@/core/signingEngine/api/thresholdLifecycle/thresholdSessionStore';
import {
  createWarmSessionTestServices,
  createThresholdEcdsaBootstrapFixture,
  createThresholdEcdsaStoreFixture,
  createWarmSessionStatusReader,
  resetWarmSessionFixtureState,
  seedEd25519WarmSessionRecord,
  seedEcdsaWarmSessionRecord,
  type WarmClaimFixture,
} from './helpers/warmSessionStore.fixtures';

test.describe('WarmSessionStore Email OTP policy enforcement', () => {
  test('warm-session reads do not restore or delete durable sealed Email OTP ECDSA records', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId: 'sealed-read-side.testnet',
      chain: 'evm',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId: 'sealed-read-side.testnet',
        chain: 'evm',
        sessionId: 'ecdsa-sealed-read-side-session',
        sessionJwt: 'jwt:ecdsa-sealed-read-side-session',
        walletSigningSessionId: 'wallet-signing-session-sealed-read-side',
      }),
    });
    const clears: string[] = [];
    const store = createWarmSessionTestServices({
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
    });

    const warmSession = await store.getWarmSession('sealed-read-side.testnet');

    expect(warmSession.capabilities.ecdsa.evm.state).toBe('prf_missing');
    expect(clears).toEqual([]);
    expect(ecdsaStore.recordsByLane.size).toBe(1);
    expect(
      store.resolveEmailOtpSigningSessionAuthLane({
        thresholdSessionId: record.thresholdSessionId,
        curve: 'ecdsa',
        chain: 'evm',
      }),
    ).toMatchObject({
      kind: 'signing_session',
      jwt: 'jwt:ecdsa-sealed-read-side-session',
      thresholdSessionId: record.thresholdSessionId,
      walletSigningSessionId: 'wallet-signing-session-sealed-read-side',
      curve: 'ecdsa',
      chain: 'evm',
    });
  });

  test('reports expired Email OTP local material without read-side cleanup', async () => {
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
        walletSigningSessionId: 'wallet-ecdsa-expired-session',
      }),
    });

    const clears: string[] = [];
    const store = createWarmSessionTestServices({
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

    const status = await store.getEcdsaSigningSessionStatus({
      nearAccountId: 'alice.testnet',
      chain: 'evm',
      thresholdSessionId: record.thresholdSessionId,
    });
    const warmSession = await store.getWarmSession('alice.testnet');

    expect(status).toMatchObject({
      sessionId: 'ecdsa-expired-session',
      status: 'expired',
      authMethod: 'email_otp',
      retention: 'session',
    });
    expect(warmSession.capabilities.ecdsa.evm.state).toBe('prf_missing');
    expect(ecdsaStore.recordsByLane.size).toBe(1);
    expect(clears).toEqual([]);
    expect(
      store.resolveEmailOtpSigningSessionAuthLane({
        thresholdSessionId: record.thresholdSessionId,
        curve: 'ecdsa',
        chain: 'evm',
      }),
    ).toMatchObject({
      kind: 'signing_session',
      jwt: 'jwt:ecdsa-expired-session',
      thresholdSessionId: record.thresholdSessionId,
    });
  });

  test('treats exhausted Email OTP Ed25519 worker material as a local cache miss', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const record = seedEd25519WarmSessionRecord({
      nearAccountId: 'otp-ed25519-cache-race.testnet',
      source: 'email_otp',
      thresholdSessionId: 'otp-ed25519-cache-race-session',
      thresholdSessionJwt: 'jwt:otp-ed25519-cache-race-session',
      walletSigningSessionId: 'wallet-otp-ed25519-cache-race',
      xClientBaseB64u: 'x-client-base-cache-race',
      remainingUses: 1,
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [record.thresholdSessionId]: { state: 'exhausted' },
      }),
    });

    await expect(
      store.getEd25519SigningSessionStatusForSession({
        nearAccountId: 'otp-ed25519-cache-race.testnet',
        thresholdSessionId: record.thresholdSessionId,
      }),
    ).resolves.toMatchObject({
      sessionId: record.thresholdSessionId,
      status: 'active',
      authMethod: 'email_otp',
      remainingUses: 1,
    });
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

    const store = createWarmSessionTestServices({
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

    const warmSession = await store.getWarmSession('shared-budget.testnet');
    const ed25519Status = await store.getEd25519SigningSessionStatus('shared-budget.testnet');
    const ecdsaStatus = await store.getEcdsaSigningSessionStatus({
      nearAccountId: 'shared-budget.testnet',
      chain: 'evm',
      thresholdSessionId: ecdsaRecord.thresholdSessionId,
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

  test('resolves explicit Email OTP ECDSA readiness when generic lookup prefers passkey', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const nearAccountId = 'mixed-lanes.testnet';
    const emailOtpBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId,
      chain: 'tempo',
      ecdsaThresholdKeyId: 'ecdsa-email-otp',
      sessionId: 'ecdsa-email-otp-session',
      sessionJwt: 'jwt:ecdsa-email-otp-session',
      walletSigningSessionId: 'wallet-email-otp-session',
    });
    emailOtpBootstrap.thresholdEcdsaKeyRef.backendBinding!.clientAdditiveShareHandle = {
      kind: 'email_otp_worker_session',
      sessionId: 'email-otp-worker-session',
    };
    ecdsaStore.now = () => 1_000;
    const emailOtpRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId,
      chain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: emailOtpBootstrap,
    });

    ecdsaStore.now = () => 2_000;
    const passkeyRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId,
      chain: 'tempo',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId,
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ecdsa-passkey',
        sessionId: 'ecdsa-passkey-session',
        sessionJwt: 'jwt:ecdsa-passkey-session',
        walletSigningSessionId: 'wallet-passkey-session',
      }),
    });

    const provisionCalls: string[] = [];
    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [passkeyRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 5,
          expiresAtMs: Date.now() + 120_000,
        },
      }),
      getEmailOtpWarmSessionStatus: async (sessionId) => {
        if (sessionId !== 'email-otp-worker-session') {
          return { ok: false, code: 'not_found', message: 'not found' };
        }
        return { ok: true, remainingUses: 4, expiresAtMs: Date.now() + 120_000 };
      },
      provisionThresholdEcdsaSession: async () => {
        provisionCalls.push('provision');
        return createThresholdEcdsaBootstrapFixture({
          nearAccountId,
          chain: 'tempo',
          sessionId: 'unexpected-reconnect',
          sessionJwt: 'jwt:unexpected-reconnect',
        });
      },
      listThresholdEcdsaSessionRecordsForLookup: ({ nearAccountId, chain }) =>
        listThresholdEcdsaSessionRecordsForLookup(ecdsaStore, { nearAccountId, chain }),
    });

    const laneStatuses = await store.listEcdsaSigningSessionStatuses({
      nearAccountId,
      chain: 'tempo',
    });
    const passkeyStatus = laneStatuses.find(
      (status) => status.sessionId === passkeyRecord.thresholdSessionId,
    );
    const explicitStatus = await store.getEcdsaSigningSessionStatus({
      nearAccountId,
      chain: 'tempo',
      thresholdSessionId: emailOtpRecord.thresholdSessionId,
    });
    const ready = await store.ensureEcdsaCapabilityReady({
      nearAccountId,
      chain: 'tempo',
      keyRef: recordToKeyRef(emailOtpRecord),
    });

    expect(passkeyStatus).toMatchObject({
      sessionId: passkeyRecord.thresholdSessionId,
      status: 'active',
      authMethod: 'passkey',
    });
    expect(laneStatuses).toHaveLength(2);
    expect(explicitStatus).toMatchObject({
      sessionId: emailOtpRecord.thresholdSessionId,
      status: 'active',
      authMethod: 'email_otp',
      remainingUses: 4,
    });
    expect(ready.reconnected).toBe(false);
    expect(ready.keyRef.thresholdSessionId).toBe(emailOtpRecord.thresholdSessionId);
    expect(ready.capability.record?.thresholdSessionId).toBe(emailOtpRecord.thresholdSessionId);
    expect(ready.capability.prfClaim).toMatchObject({
      state: 'warm',
      remainingUses: 4,
    });
    expect(provisionCalls).toEqual([]);
  });

  test('ensures source-scoped Email OTP ECDSA readiness without falling back to passkey', async () => {
    const ecdsaStore = createThresholdEcdsaStoreFixture();
    resetWarmSessionFixtureState(ecdsaStore);

    const nearAccountId = 'source-ready.testnet';
    const emailOtpBootstrap = createThresholdEcdsaBootstrapFixture({
      nearAccountId,
      chain: 'tempo',
      ecdsaThresholdKeyId: 'ecdsa-source-email',
      sessionId: 'ecdsa-source-email-session',
      sessionJwt: 'jwt:ecdsa-source-email-session',
      walletSigningSessionId: 'wallet-source-email-session',
    });
    emailOtpBootstrap.thresholdEcdsaKeyRef.backendBinding!.clientAdditiveShareHandle = {
      kind: 'email_otp_worker_session',
      sessionId: 'source-email-worker-session',
    };
    ecdsaStore.now = () => 1_000;
    const emailOtpRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId,
      chain: 'tempo',
      source: 'email_otp',
      emailOtpAuthContext: {
        policy: 'session',
        retention: 'session',
        reason: 'login',
        authMethod: 'email_otp',
      },
      bootstrap: emailOtpBootstrap,
    });

    ecdsaStore.now = () => 2_000;
    const passkeyRecord = seedEcdsaWarmSessionRecord(ecdsaStore, {
      nearAccountId,
      chain: 'tempo',
      bootstrap: createThresholdEcdsaBootstrapFixture({
        nearAccountId,
        chain: 'tempo',
        ecdsaThresholdKeyId: 'ecdsa-source-passkey',
        sessionId: 'ecdsa-source-passkey-session',
        sessionJwt: 'jwt:ecdsa-source-passkey-session',
      }),
    });

    const store = createWarmSessionTestServices({
      touchConfirm: createWarmSessionStatusReader({
        [passkeyRecord.thresholdSessionId]: {
          state: 'warm',
          remainingUses: 5,
          expiresAtMs: Date.now() + 120_000,
        },
      }),
      getEmailOtpWarmSessionStatus: async (sessionId) => {
        if (sessionId !== 'source-email-worker-session') {
          return { ok: false, code: 'not_found', message: 'not found' };
        }
        return { ok: true, remainingUses: 5, expiresAtMs: Date.now() + 120_000 };
      },
      listThresholdEcdsaKeyRefsForLookup: (args) =>
        listThresholdEcdsaKeyRefsForLookup(ecdsaStore, args),
      listThresholdEcdsaSessionRecordsForLookup: (args) =>
        listThresholdEcdsaSessionRecordsForLookup(ecdsaStore, args),
      provisionThresholdEcdsaSession: async () => {
        throw new Error('source-scoped ready Email OTP ECDSA should not reconnect');
      },
    });

    const ready = await store.ensureEcdsaCapabilityReady({
      nearAccountId,
      chain: 'tempo',
      source: 'email_otp',
    });

    expect(ready.reconnected).toBe(false);
    expect(ready.keyRef.thresholdSessionId).toBe(emailOtpRecord.thresholdSessionId);
    expect(ready.capability.record?.thresholdSessionId).toBe(emailOtpRecord.thresholdSessionId);
    expect(ready.capability.record?.source).toBe('email_otp');
    expect(ready.capability.prfClaim).toMatchObject({
      state: 'warm',
      remainingUses: 5,
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
    const store = createWarmSessionTestServices({
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

    await store.applyEcdsaPostSignPolicy({
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
    const store = createWarmSessionTestServices({
      touchConfirm: {
        clearWarmSessionMaterial: async () => undefined,
      },
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args) => {
        markThresholdEcdsaEmailOtpSessionConsumedForAccount(ecdsaStore, args);
      },
      clearThresholdEcdsaSigningArtifactsForLane: () => undefined,
      listThresholdEcdsaKeyRefsForLookup: () => [
        { source: 'email_otp', keyRef: recordToKeyRef(record) },
      ],
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

    await store.applyEcdsaPostSignPolicy({
      nearAccountId: 'erin.testnet',
      chain: 'evm',
      thresholdSessionId: record.thresholdSessionId,
    });

    await expect(
      store.ensureEcdsaCapabilityReady({
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
    const store = createWarmSessionTestServices({
      touchConfirm: {
        clearWarmSessionMaterial: async () => undefined,
      },
      markThresholdEcdsaEmailOtpSessionConsumedForAccount: (args) => {
        markThresholdEcdsaEmailOtpSessionConsumedForAccount(ecdsaStore, args);
      },
      clearThresholdEcdsaSigningArtifactsForLane: () => undefined,
      listThresholdEcdsaKeyRefsForLookup: () => [
        { source: 'email_otp', keyRef: recordToKeyRef(record) },
      ],
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

    await store.applyEcdsaPostSignPolicy({
      nearAccountId: 'tempo-erin.testnet',
      chain: 'tempo',
      thresholdSessionId: record.thresholdSessionId,
    });

    await expect(
      store.ensureEcdsaCapabilityReady({
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

    const store = createWarmSessionTestServices();

    await expect(
      store.assertEcdsaOperationAllowed({
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

    const store = createWarmSessionTestServices();

    await expect(
      store.assertEcdsaOperationAllowed({
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

    const store = createWarmSessionTestServices();

    await expect(
      store.assertEcdsaOperationAllowed({
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

    const store = createWarmSessionTestServices();

    await expect(
      store.assertEcdsaOperationAllowed({
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

    const store = createWarmSessionTestServices();

    await expect(
      store.assertEcdsaOperationAllowed({
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
