import { expect, test } from '@playwright/test';
import { isConcreteAvailableSigningLane } from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  buildCurrentSealedSessionRecord,
  type SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  AVAILABLE_LANES_ECDSA_TARGET as ECDSA_TARGET,
  AVAILABLE_LANES_EXPIRES_AT_MS as EXPIRES_AT_MS,
  AVAILABLE_LANES_TEMPO_TARGET as TEMPO_TARGET,
  AVAILABLE_LANES_WALLET_ID as WALLET_ID,
  readAvailableLanesFixture as readAvailableLanes,
  runtimeEcdsaAvailableLaneRecord as runtimeEcdsaRecord,
  runtimeEd25519RouterAbNormalSigningState,
} from './helpers/availableSigningLanes.fixtures';

function sealedEd25519Record(args: {
  authMethod: 'email_otp' | 'passkey';
  signingGrantId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
}): SigningSessionSealedStoreRecord {
  const issuedAtMs = Date.now();
  const record = buildCurrentSealedSessionRecord({
    curve: 'ed25519',
    authMethod: args.authMethod,
    walletId: WALLET_ID,
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionIds: { ed25519: args.thresholdSessionId },
    sealedSecretB64u: 'sealed',
    relayerUrl: 'https://relay.example.test',
    keyVersion: 'seal-key-v1',
    shamirPrimeB64u: 'shamir-prime',
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
    ed25519Restore: {
      rpId: 'wallet.example.localhost',
      relayerKeyId: 'relayer-key',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ed25519',
      runtimePolicyScope: {
        orgId: 'org-test',
        projectId: 'sr-test',
        envId: 'dev',
        signingRootVersion: 'default',
      },
      xClientBaseB64u: 'x-client-base',
      clientVerifyingShareB64u: 'client-verifying-share',
    },
    issuedAtMs,
    expiresAtMs: issuedAtMs + 60_000,
    remainingUses: 1,
    updatedAtMs: args.updatedAtMs,
  });
  if (!record) {
    throw new Error(`failed to build Ed25519 sealed fixture ${args.thresholdSessionId}`);
  }
  return record;
}

test.describe('Ed25519 available signing lanes duplicate normalization', () => {
  test('rejects branch-mixed missing lanes at the root concrete-lane guard', () => {
    const missingEd25519WithIdentity = {
      authMethod: 'passkey',
      curve: 'ed25519',
      chain: 'near',
      state: 'missing',
      signingGrantId: 'wallet-session-mixed',
      thresholdSessionId: 'threshold-session-mixed',
    } as never;
    const missingEcdsaWithIdentity = {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: ECDSA_TARGET,
      state: 'missing',
      signingGrantId: 'wallet-session-mixed',
      thresholdSessionId: 'threshold-session-mixed',
    } as never;

    expect(isConcreteAvailableSigningLane(missingEd25519WithIdentity)).toBe(false);
    expect(isConcreteAvailableSigningLane(missingEcdsaWithIdentity)).toBe(false);
  });

  test('collapses duplicate durable entries with the same exact lane identity', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'email_otp',
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
        sealedEd25519Record({
          authMethod: 'email_otp',
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 200,
        }),
      ],
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'durable_sealed_record',
      signingGrantId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      updatedAtMs: 200,
    });
  });

  test('uses the runtime lane when runtime and durable entries share exact identity', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'email_otp',
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
      ],
      runtimeEd25519Records: [
        {
          authMethod: 'email_otp',
          curve: 'ed25519',
          chain: 'near',
          routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
        },
      ],
      runtimeClaims: new Map([
        [
          'tsess-1',
          {
            state: 'warm',
            sessionId: 'tsess-1',
            remainingUses: 1,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      authMethod: 'email_otp',
      state: 'ready',
      source: 'runtime_and_durable',
      signingGrantId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      remainingUses: 1,
    });
  });

  test('does not advertise a warm Ed25519 runtime lane without Router A/B normal-signing state', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEd25519Records: [
        {
          authMethod: 'passkey',
          curve: 'ed25519',
          chain: 'near',
          signingGrantId: 'wsess-stale-router-ab',
          thresholdSessionId: 'tsess-stale-router-ab',
        } as never,
      ],
      runtimeClaims: new Map([
        [
          'tsess-stale-router-ab',
          {
            state: 'warm',
            sessionId: 'tsess-stale-router-ab',
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.lanes.ed25519.near.state).toBe('missing');
    expect(availableLanes.candidates.ed25519.near).toEqual([]);
    expect(availableLanes.diagnostics?.invalidLanes).toEqual([
      {
        authMethod: 'passkey',
        curve: 'ed25519',
        reason: 'missing_router_ab_state',
        source: 'runtime_session_record',
        thresholdSessionId: 'tsess-stale-router-ab',
        signingGrantId: 'wsess-stale-router-ab',
      },
    ]);
  });

  test('does not advertise a warm ECDSA runtime lane without Router A/B normal-signing state', async () => {
    const staleEcdsaRecordWithState = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-ecdsa-stale-router-ab',
      signingGrantId: 'wsess-ecdsa-stale-router-ab',
      thresholdOwnerAddress: `0x${'33'.repeat(20)}`,
    });
    const {
      routerAbEcdsaHssNormalSigning: omittedRouterAbEcdsaHssNormalSigning,
      ...staleEcdsaRecord
    } = staleEcdsaRecordWithState;
    expect(omittedRouterAbEcdsaHssNormalSigning).toBeDefined();

    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET],
      runtimeEcdsaRecords: [staleEcdsaRecord as never],
      runtimeEcdsaClaims: new Map([
        [
          thresholdEcdsaChainTargetKey(ECDSA_TARGET),
          {
            state: 'warm',
            sessionId: 'tsess-ecdsa-stale-router-ab',
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(
      availableLanes.ecdsa.candidatesByTarget[thresholdEcdsaChainTargetKey(ECDSA_TARGET)],
    ).toEqual([]);
    expect(availableLanes.diagnostics?.invalidLanes).toEqual([
      {
        authMethod: 'email_otp',
        curve: 'ecdsa',
        reason: 'missing_router_ab_state',
        source: 'runtime_session_record',
        thresholdSessionId: 'tsess-ecdsa-stale-router-ab',
        signingGrantId: 'wsess-ecdsa-stale-router-ab',
      },
    ]);
  });

  test('keeps same session ids with different auth methods as distinct lanes', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEd25519Records: [
        {
          authMethod: 'passkey',
          curve: 'ed25519',
          chain: 'near',
          routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
        },
        {
          authMethod: 'email_otp',
          curve: 'ed25519',
          chain: 'near',
          routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
        },
      ],
      runtimeClaims: new Map([
        [
          'tsess-1',
          {
            state: 'warm',
            sessionId: 'tsess-1',
            remainingUses: 1,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(2);
    expect(availableLanes.candidates.ed25519.near.map((lane) => lane.authMethod).sort()).toEqual([
      'email_otp',
      'passkey',
    ]);
  });

  test('keeps distinct threshold session ids as distinct lanes', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'email_otp',
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
        sealedEd25519Record({
          authMethod: 'email_otp',
          signingGrantId: 'wsess-2',
          thresholdSessionId: 'tsess-2',
          updatedAtMs: 200,
        }),
      ],
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(2);
    expect(availableLanes.candidates.ed25519.near.map((lane) => lane.thresholdSessionId).sort()).toEqual([
      'tsess-1',
      'tsess-2',
    ]);
  });

  test('propagates exhausted Email OTP runtime ECDSA state to shared Tempo lanes', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [],
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-runtime-exhausted',
          signingGrantId: 'wsess-email-otp-runtime-exhausted',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          remainingUses: 0,
        }),
      ],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'runtime_session_record',
      state: 'exhausted',
      remainingUses: 0,
      signingGrantId: 'wsess-email-otp-runtime-exhausted',
      thresholdSessionId: 'tsess-email-otp-runtime-exhausted',
    });
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      state: 'exhausted',
      remainingUses: 0,
      signingGrantId: 'wsess-email-otp-runtime-exhausted',
      thresholdSessionId: 'tsess-email-otp-runtime-exhausted',
    });
  });

  test('propagates ready Email OTP runtime ECDSA state to shared Tempo lanes', async () => {
    const thresholdSessionId = 'tsess-email-otp-runtime-ready';
    const availableLanes = await readAvailableLanes({
      sealedRecords: [],
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId,
          signingGrantId: 'wsess-email-otp-runtime-ready',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          remainingUses: 1,
        }),
      ],
      runtimeClaims: new Map([
        [
          thresholdSessionId,
          {
            state: 'warm',
            sessionId: thresholdSessionId,
            remainingUses: 1,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'runtime_session_record',
      state: 'ready',
      remainingUses: 1,
      signingGrantId: 'wsess-email-otp-runtime-ready',
      thresholdSessionId,
    });
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      state: 'ready',
      remainingUses: 1,
      signingGrantId: 'wsess-email-otp-runtime-ready',
      thresholdSessionId,
    });
  });

  test('rejects EVM-family runtime rows with one key id but different owner addresses', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [],
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-arc',
          signingGrantId: 'wsess-arc',
          thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
        }),
        runtimeEcdsaRecord({
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'tsess-tempo',
          signingGrantId: 'wsess-tempo',
          thresholdOwnerAddress: `0x${'22'.repeat(20)}`,
        }),
      ],
    });

    expect(
      availableLanes.ecdsa.candidatesByTarget[thresholdEcdsaChainTargetKey(ECDSA_TARGET)],
    ).toHaveLength(0);
    expect(
      availableLanes.ecdsa.candidatesByTarget[thresholdEcdsaChainTargetKey(TEMPO_TARGET)],
    ).toHaveLength(0);
  });

  test('rejects EVM-family runtime rows with one signing root but different key ids', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [],
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-arc',
          signingGrantId: 'wsess-arc',
          thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key-1',
        }),
        runtimeEcdsaRecord({
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'tsess-tempo',
          signingGrantId: 'wsess-tempo',
          thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key-2',
        }),
      ],
    });

    expect(
      availableLanes.ecdsa.candidatesByTarget[thresholdEcdsaChainTargetKey(ECDSA_TARGET)],
    ).toHaveLength(0);
    expect(
      availableLanes.ecdsa.candidatesByTarget[thresholdEcdsaChainTargetKey(TEMPO_TARGET)],
    ).toHaveLength(0);
  });
});
