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
  sealedEcdsaAvailableLaneRecord as sealedEcdsaRecord,
} from './helpers/availableSigningLanes.fixtures';

function sealedEd25519Record(args: {
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
  restoreMetadata?: 'valid' | 'missing_x_client_base';
}): SigningSessionSealedStoreRecord {
  const issuedAtMs = Date.now();
  if (args.authMethod === 'email_otp' && args.restoreMetadata === 'missing_x_client_base') {
    return {
      storeKey: `${args.authMethod}:${args.walletSigningSessionId}:${args.thresholdSessionId}:${args.updatedAtMs}`,
      curve: 'ed25519',
      authMethod: args.authMethod,
      walletId: WALLET_ID,
      walletSigningSessionId: args.walletSigningSessionId,
      thresholdSessionId: args.thresholdSessionId,
      thresholdSessionIds: { ed25519: args.thresholdSessionId },
      sealedSecretB64u: 'sealed',
      relayerUrl: 'https://relay.example.test',
      keyVersion: 'seal-key-v1',
      shamirPrimeB64u: 'shamir-prime',
      ed25519Restore: {
        rpId: 'wallet.example.localhost',
        relayerKeyId: 'relayer-key',
        participantIds: [1, 2],
        sessionKind: 'jwt',
        walletSessionJwt: 'jwt-ed25519',
      },
      issuedAtMs,
      expiresAtMs: issuedAtMs + 60_000,
      remainingUses: 1,
      updatedAtMs: args.updatedAtMs,
    } as unknown as SigningSessionSealedStoreRecord;
  }
  const record = buildCurrentSealedSessionRecord({
    curve: 'ed25519',
    authMethod: args.authMethod,
    walletId: WALLET_ID,
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionIds: { ed25519: args.thresholdSessionId },
    sealedSecretB64u: 'sealed',
    relayerUrl: 'https://relay.example.test',
    keyVersion: 'seal-key-v1',
    shamirPrimeB64u: 'shamir-prime',
    ed25519Restore: {
      rpId: 'wallet.example.localhost',
      relayerKeyId: 'relayer-key',
      participantIds: [1, 2],
      sessionKind: args.authMethod === 'email_otp' ? 'jwt' : 'cookie',
      ...(args.authMethod === 'email_otp' ? { walletSessionJwt: 'jwt-ed25519' } : {}),
      ...(args.restoreMetadata === 'missing_x_client_base'
        ? {}
        : { xClientBaseB64u: 'x-client-base' }),
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
      walletSigningSessionId: 'wallet-session-mixed',
      thresholdSessionId: 'threshold-session-mixed',
    } as never;
    const missingEcdsaWithIdentity = {
      authMethod: 'email_otp',
      curve: 'ecdsa',
      chainTarget: ECDSA_TARGET,
      state: 'missing',
      walletSigningSessionId: 'wallet-session-mixed',
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
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 200,
        }),
      ],
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'durable_sealed_record',
      walletSigningSessionId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      updatedAtMs: 200,
    });
  });

  test('uses the runtime lane when runtime and durable entries share exact identity', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-1',
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
          walletSigningSessionId: 'wsess-1',
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
      walletSigningSessionId: 'wsess-1',
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
          walletSigningSessionId: 'wsess-stale-router-ab',
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
  });

  test('keeps same session ids with different auth methods as distinct lanes', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'passkey',
          walletSigningSessionId: 'wsess-1',
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
          walletSigningSessionId: 'wsess-1',
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
          walletSigningSessionId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          updatedAtMs: 100,
        }),
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-2',
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

  test('keeps passkey Ed25519 durable entries without client-base metadata', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'passkey',
          walletSigningSessionId: 'wsess-passkey-ed25519',
          thresholdSessionId: 'tsess-passkey-ed25519',
          updatedAtMs: 300,
          restoreMetadata: 'missing_x_client_base',
        }),
        sealedEd25519Record({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-email-ed25519',
          thresholdSessionId: 'tsess-email-ed25519',
          updatedAtMs: 200,
          restoreMetadata: 'missing_x_client_base',
        }),
      ],
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      authMethod: 'passkey',
      source: 'durable_sealed_record',
      state: 'restorable',
      walletSigningSessionId: 'wsess-passkey-ed25519',
      thresholdSessionId: 'tsess-passkey-ed25519',
    });
  });

  test('ignores durable ECDSA entries that cannot normalize for sealed restore', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-stale-ecdsa',
          thresholdSessionId: 'tsess-stale-ecdsa',
          updatedAtMs: 300,
          restoreMetadata: 'missing',
        }),
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-valid-ecdsa',
          thresholdSessionId: 'tsess-valid-ecdsa',
          updatedAtMs: 200,
          restoreMetadata: 'valid',
        }),
      ],
    });

    const targetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey][0]).toMatchObject({
      authMethod: 'passkey',
      source: 'durable_sealed_record',
      state: 'restorable',
      walletSigningSessionId: 'wsess-valid-ecdsa',
      thresholdSessionId: 'tsess-valid-ecdsa',
      key: {
        ecdsaThresholdKeyId: 'ek-passkey',
      },
    });
  });

  test('rebuilds canonical ECDSA key identity when reading durable sealed lanes', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-normalized-ecdsa',
          thresholdSessionId: 'tsess-normalized-ecdsa',
          updatedAtMs: 400,
          restoreMetadata: 'valid',
          participantIds: [2, 1],
          ethereumAddress: `0x${'CD'.repeat(20)}`,
        }),
      ],
    });

    const targetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey][0]).toMatchObject({
      key: {
        keyScope: 'evm-family',
        rpId: 'wallet.example.localhost',
        participantIds: [1, 2],
        thresholdOwnerAddress: `0x${'cd'.repeat(20)}`,
      },
    });
  });

  test('rejects durable sealed ECDSA lanes missing rpId at readback', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-missing-rpid-ecdsa',
          thresholdSessionId: 'tsess-missing-rpid-ecdsa',
          updatedAtMs: 500,
          restoreMetadata: 'missing_rp_id',
        }),
      ],
    });

    const targetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey]).toHaveLength(0);
  });

  test('preserves Email OTP sealed ECDSA threshold owner address through readback', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-email-otp-ecdsa',
          thresholdSessionId: 'tsess-email-otp-ecdsa',
          updatedAtMs: 600,
          restoreMetadata: 'valid',
          ethereumAddress: `0x${'EF'.repeat(20)}`,
        }),
      ],
    });

    const targetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      key: {
        thresholdOwnerAddress: `0x${'ef'.repeat(20)}`,
      },
    });
  });

  test('keeps exhausted Email OTP sealed ECDSA lanes available for post-refresh reauth', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          authMethod: 'email_otp',
          walletSigningSessionId: 'wsess-email-otp-exhausted',
          thresholdSessionId: 'tsess-email-otp-exhausted',
          updatedAtMs: 650,
          restoreMetadata: 'valid',
          remainingUses: 0,
          sessionKind: 'jwt',
        }),
      ],
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'durable_sealed_record',
      state: 'exhausted',
      remainingUses: 0,
      walletSigningSessionId: 'wsess-email-otp-exhausted',
      thresholdSessionId: 'tsess-email-otp-exhausted',
    });
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      walletSigningSessionId: 'wsess-email-otp-exhausted',
      thresholdSessionId: 'tsess-email-otp-exhausted',
    });
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
          walletSigningSessionId: 'wsess-email-otp-runtime-exhausted',
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
      walletSigningSessionId: 'wsess-email-otp-runtime-exhausted',
      thresholdSessionId: 'tsess-email-otp-runtime-exhausted',
    });
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      state: 'exhausted',
      remainingUses: 0,
      walletSigningSessionId: 'wsess-email-otp-runtime-exhausted',
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
          walletSigningSessionId: 'wsess-email-otp-runtime-ready',
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
      walletSigningSessionId: 'wsess-email-otp-runtime-ready',
      thresholdSessionId,
    });
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      state: 'ready',
      remainingUses: 1,
      walletSigningSessionId: 'wsess-email-otp-runtime-ready',
      thresholdSessionId,
    });
  });

  test('completes a missing configured EVM-family target from one stored shared key', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-arc-ecdsa',
          thresholdSessionId: 'tsess-arc-ecdsa',
          updatedAtMs: 700,
          restoreMetadata: 'valid',
        }),
      ],
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      authMethod: 'passkey',
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      state: 'deferred',
      key: {
        ecdsaThresholdKeyId: 'ek-passkey',
      },
      walletSigningSessionId: 'wsess-arc-ecdsa',
      thresholdSessionId: 'tsess-arc-ecdsa',
    });
  });

  test('completes a Tempo-only read from one wallet-scoped EVM-family shared key', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-arc-ecdsa',
          thresholdSessionId: 'tsess-arc-ecdsa',
          updatedAtMs: 700,
          restoreMetadata: 'valid',
          chainTarget: ECDSA_TARGET,
        }),
      ],
      ecdsaChainTargets: [TEMPO_TARGET],
    });

    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      authMethod: 'passkey',
      chainTarget: TEMPO_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      state: 'deferred',
      walletSigningSessionId: 'wsess-arc-ecdsa',
      thresholdSessionId: 'tsess-arc-ecdsa',
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
          walletSigningSessionId: 'wsess-arc',
          thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
        }),
        runtimeEcdsaRecord({
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'tsess-tempo',
          walletSigningSessionId: 'wsess-tempo',
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
          walletSigningSessionId: 'wsess-arc',
          thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key-1',
        }),
        runtimeEcdsaRecord({
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'tsess-tempo',
          walletSigningSessionId: 'wsess-tempo',
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
