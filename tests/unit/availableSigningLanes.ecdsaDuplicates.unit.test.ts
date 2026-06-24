import { expect, test } from '@playwright/test';
import {
  availableEcdsaSigningLaneAuthMethod,
  buildRuntimeEcdsaAvailableLaneIdentityInput,
  ecdsaAvailableLaneAuthKey,
  ecdsaAvailableLaneIdentityKey,
  runtimeEcdsaAvailableLaneIdentityKey,
  runtimeEcdsaRecordClaimKey,
  type AvailableEcdsaSigningLane,
  type ConcreteAvailableEcdsaSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildPasskeyEcdsaAuthBinding,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  deriveEvmFamilyEcdsaKeyHandle,
  toRpId,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  AVAILABLE_LANES_ECDSA_KEY_HANDLE as TEST_ECDSA_KEY_HANDLE,
  AVAILABLE_LANES_ECDSA_PUBLIC_KEY_B64U as VALID_ECDSA_PUBLIC_KEY_B64U,
  AVAILABLE_LANES_ECDSA_RP_ID as RP_ID,
  AVAILABLE_LANES_ECDSA_WALLET_KEY_ID as WALLET_KEY_ID,
  AVAILABLE_LANES_ECDSA_TARGET as ECDSA_TARGET,
  AVAILABLE_LANES_EXPIRES_AT_MS as EXPIRES_AT_MS,
  AVAILABLE_LANES_PASSKEY_CREDENTIAL_ID as PASSKEY_CREDENTIAL_ID,
  AVAILABLE_LANES_TEMPO_TARGET as TEMPO_TARGET,
  AVAILABLE_LANES_WALLET_ID as WALLET_ID,
  readAvailableLanesFixture as readAvailableLanes,
  runtimeEcdsaAvailableLaneRecord as runtimeEcdsaRecord,
  sealedEcdsaAvailableLaneRecord as sealedEcdsaRecord,
} from './helpers/availableSigningLanes.fixtures';

function expectEcdsaLaneAuthMethod(
  lane: AvailableEcdsaSigningLane | undefined,
  authMethod: 'email_otp' | 'passkey',
): asserts lane is ConcreteAvailableEcdsaSigningLane {
  expect(lane).toBeDefined();
  if (!lane || lane.state === 'missing') {
    throw new Error('expected concrete ECDSA lane');
  }
  expect(availableEcdsaSigningLaneAuthMethod(lane)).toBe(authMethod);
}

test.describe('ECDSA available signing lane duplicate normalization', () => {
  test('restores Email OTP ECDSA durable lanes written through the sealed record builder', async () => {
    const thresholdSessionId = 'tsess-email-otp-durable-builder';
    const signingGrantId = 'wsess-email-otp-durable-builder';
    const keyHandle = 'ehss-key-email-otp-durable-builder';
    const sealedRecord = sealedEcdsaRecord({
      thresholdSessionId,
      signingGrantId,
      keyHandle,
      authMethod: 'email_otp',
      chainTarget: TEMPO_TARGET,
      ecdsaThresholdKeyId: 'ek-email-otp-durable-builder',
      remainingUses: 0,
      sessionKind: 'jwt',
      updatedAtMs: Date.now(),
    });
    const availableLanes = await readAvailableLanes({
      sealedRecords: [sealedRecord],
      ecdsaChainTargets: [TEMPO_TARGET],
    });

    const targetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey]).toHaveLength(1);
    const lane = availableLanes.ecdsa.candidatesByTarget[targetKey][0];
    expectEcdsaLaneAuthMethod(lane, 'email_otp');
    expect(lane).toMatchObject({
      source: 'durable_sealed_record',
      state: 'exhausted',
      remainingUses: 0,
      thresholdSessionId,
      signingGrantId,
    });
  });

  test('collapses duplicate exhausted Email OTP runtime lanes by shared key identity', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-runtime-exhausted-1',
          signingGrantId: 'wsess-email-otp-runtime-exhausted-1',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          remainingUses: 0,
          updatedAtMs: 700,
        }),
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-runtime-exhausted-2',
          signingGrantId: 'wsess-email-otp-runtime-exhausted-2',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          remainingUses: 0,
          updatedAtMs: 800,
        }),
      ],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    const lane = availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0];
    expectEcdsaLaneAuthMethod(lane, 'email_otp');
    expect(lane).toMatchObject({
      source: 'runtime_session_record',
      state: 'exhausted',
      remainingUses: 0,
      signingGrantId: 'wsess-email-otp-runtime-exhausted-2',
      thresholdSessionId: 'tsess-email-otp-runtime-exhausted-2',
      publicFacts: {
        keyHandle: expect.stringMatching(/^ehss-key-/),
        publicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
        thresholdOwnerAddress: `0x${'ef'.repeat(20)}`,
      },
    });
  });

  test('collapses duplicate expired runtime lanes by shared key identity', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-runtime-expired-1',
          signingGrantId: 'wsess-runtime-expired-1',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          expiresAtMs: 1,
          updatedAtMs: 700,
        }),
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-runtime-expired-2',
          signingGrantId: 'wsess-runtime-expired-2',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          expiresAtMs: 1,
          updatedAtMs: 900,
        }),
      ],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0]).toMatchObject({
      source: 'runtime_session_record',
      state: 'expired',
      signingGrantId: 'wsess-runtime-expired-2',
      thresholdSessionId: 'tsess-runtime-expired-2',
    });
  });

  test('uses the runtime lane when durable and runtime entries share exact ECDSA identity', async () => {
    const runtimeRecord = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-runtime-durable',
      signingGrantId: 'wsess-runtime-durable',
      thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
      ecdsaThresholdKeyId: 'shared-ecdsa-key',
      remainingUses: 2,
      updatedAtMs: 800,
    });
    runtimeRecord.keyHandle = await deriveEvmFamilyEcdsaKeyHandle(runtimeRecord.key);
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          authMethod: 'email_otp',
          signingGrantId: 'wsess-runtime-durable',
          thresholdSessionId: 'tsess-runtime-durable',
          updatedAtMs: 500,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: runtimeRecord.keyHandle,
          ethereumAddress: `0x${'EF'.repeat(20)}`,
          remainingUses: 0,
          sessionKind: 'jwt',
        }),
      ],
      runtimeEcdsaRecords: [runtimeRecord],
      runtimeClaims: new Map([
        [
          'tsess-runtime-durable',
          {
            state: 'warm',
            thresholdSessionId: 'tsess-runtime-durable',
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    const lane = availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0];
    expectEcdsaLaneAuthMethod(lane, 'email_otp');
    expect(lane).toMatchObject({
      source: 'runtime_and_durable',
      state: 'ready',
      remainingUses: 2,
      signingGrantId: 'wsess-runtime-durable',
      thresholdSessionId: 'tsess-runtime-durable',
      updatedAtMs: 800,
    });
  });

  test('does not advertise a warm ECDSA runtime lane without Router A/B normal-signing state', async () => {
    const staleRecord = runtimeEcdsaRecord({
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-ecdsa-stale-router-ab',
      signingGrantId: 'wsess-ecdsa-stale-router-ab',
      thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
      remainingUses: 2,
      updatedAtMs: 800,
    }) as Record<string, unknown>;
    delete staleRecord.routerAbEcdsaHssNormalSigning;

    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [staleRecord as never],
      runtimeClaims: new Map([
        [
          'tsess-ecdsa-stale-router-ab',
          {
            state: 'warm',
            thresholdSessionId: 'tsess-ecdsa-stale-router-ab',
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.lanesByTarget[evmTargetKey]?.state).toBe('missing');
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toEqual([]);
  });

  test('prefers a ready shared EVM-family runtime lane over a restorable exact target lane', async () => {
    const tempoThresholdSessionId = 'tsess-email-otp-tempo-ready';
    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      sealedRecords: [
        sealedEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          signingGrantId: 'wsess-email-otp-arc-restorable',
          thresholdSessionId: 'tsess-email-otp-arc-restorable',
          updatedAtMs: 900,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          ethereumAddress: `0x${'EF'.repeat(20)}`,
          remainingUses: 1,
          sessionKind: 'jwt',
        }),
      ],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: tempoThresholdSessionId,
          signingGrantId: 'wsess-email-otp-tempo-ready',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          remainingUses: 2,
          updatedAtMs: 700,
        }),
      ],
      runtimeClaims: new Map([
        [
          tempoThresholdSessionId,
          {
            state: 'warm',
            thresholdSessionId: tempoThresholdSessionId,
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const evmCandidates = availableLanes.ecdsa.candidatesByTarget[evmTargetKey] || [];
    expect(evmCandidates).toHaveLength(2);
    expectEcdsaLaneAuthMethod(evmCandidates[0], 'email_otp');
    expect(evmCandidates[0]).toMatchObject({
      chainTarget: ECDSA_TARGET,
      source: 'evm_family_shared_key',
      sourceChainTarget: TEMPO_TARGET,
      state: 'ready',
      signingGrantId: 'wsess-email-otp-tempo-ready',
      thresholdSessionId: tempoThresholdSessionId,
      remainingUses: 2,
    });
    const selectedLane = availableLanes.ecdsa.lanesByTarget[evmTargetKey];
    expectEcdsaLaneAuthMethod(selectedLane, 'email_otp');
    expect(selectedLane).toMatchObject({
      source: 'evm_family_shared_key',
      state: 'ready',
      thresholdSessionId: tempoThresholdSessionId,
    });
  });

  test('does not share Email OTP runtime claims across ECDSA chain targets with the same threshold session id', async () => {
    const thresholdSessionId = 'tsess-email-otp-shared-session-target-claims';
    const signingGrantId = 'wsess-email-otp-shared-session-target-claims';
    const ecdsaThresholdKeyId = 'shared-ecdsa-key-target-claim';
    const thresholdOwnerAddress = `0x${'EF'.repeat(20)}`;
    const tempoRecord = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: TEMPO_TARGET,
      thresholdSessionId,
      signingGrantId,
      thresholdOwnerAddress,
      ecdsaThresholdKeyId,
      keyHandle: TEST_ECDSA_KEY_HANDLE,
      remainingUses: 2,
      updatedAtMs: 700,
    });
    const arcRecord = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId,
      signingGrantId,
      thresholdOwnerAddress,
      ecdsaThresholdKeyId,
      keyHandle: TEST_ECDSA_KEY_HANDLE,
      remainingUses: 2,
      updatedAtMs: 900,
    });
    const tempoClaimKey = runtimeEcdsaRecordClaimKey(tempoRecord);
    if (!tempoClaimKey) throw new Error('tempo runtime record claim key missing');

    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [arcRecord, tempoRecord],
      runtimeEcdsaClaims: new Map([
        [
          tempoClaimKey,
          {
            state: 'warm',
            thresholdSessionId: thresholdSessionId,
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const selectedLane = availableLanes.ecdsa.lanesByTarget[evmTargetKey];
    expectEcdsaLaneAuthMethod(selectedLane, 'email_otp');
    expect(selectedLane).toMatchObject({
      source: 'evm_family_shared_key',
      sourceChainTarget: TEMPO_TARGET,
      state: 'ready',
      thresholdSessionId,
      signingGrantId,
      remainingUses: 2,
    });
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0]).toMatchObject({
      source: 'evm_family_shared_key',
      state: 'ready',
    });
  });

  test('passkey ECDSA availability lanes carry resolved-key auth binding', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'passkey',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-passkey-runtime',
          signingGrantId: 'wsess-passkey-runtime',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
        }),
      ],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const lane = availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0];

    expect(lane).toMatchObject({
      auth: { kind: 'passkey' },
      resolvedKey: {
        kind: 'resolved_evm_family_ecdsa_key',
        authBinding: {
          kind: 'passkey_ecdsa_auth_binding',
          rpId: RP_ID,
        },
      },
    });
    if (
      !lane ||
      lane.state === 'missing' ||
      availableEcdsaSigningLaneAuthMethod(lane) !== 'passkey' ||
      !lane.resolvedKey
    ) {
      throw new Error('expected passkey ECDSA lane');
    }
    expect(lane.resolvedKey.publicFacts).toBe(lane.publicFacts);
  });

  test('passkey ECDSA availability identity uses auth binding rpId', () => {
    const key = buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId: WALLET_ID,
      walletKeyId: WALLET_KEY_ID,
      ecdsaThresholdKeyId: 'shared-ecdsa-key-auth-binding-rp',
      signingRootId: 'sr-test:dev',
      signingRootVersion: 'default',
      participantIds: [1, 2],
      thresholdOwnerAddress: `0x${'AB'.repeat(20)}`,
    });
    const publicFacts = buildVerifiedEcdsaPublicFacts({
      keyHandle: TEST_ECDSA_KEY_HANDLE,
      publicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      participantIds: key.participantIds,
      thresholdOwnerAddress: key.thresholdOwnerAddress,
    });
    const lane: ConcreteAvailableEcdsaSigningLane = {
      key,
      publicFacts,
      auth: {
        kind: 'passkey',
        rpId: toRpId(RP_ID),
        credentialIdB64u: PASSKEY_CREDENTIAL_ID,
      },
      resolvedKey: buildResolvedEvmFamilyEcdsaKey({
        walletId: key.walletId,
        publicFacts,
        authBinding: buildPasskeyEcdsaAuthBinding({
          rpId: RP_ID,
          credentialIdB64u: PASSKEY_CREDENTIAL_ID,
        }),
      }),
      curve: 'ecdsa',
      chainTarget: ECDSA_TARGET,
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wallet-session-auth-binding-rp',
      thresholdSessionId: 'threshold-session-auth-binding-rp',
    };

    const identityKey = ecdsaAvailableLaneIdentityKey(lane);

    expect(ecdsaAvailableLaneAuthKey(lane.auth)).toBe(`passkey:${RP_ID}:${PASSKEY_CREDENTIAL_ID}`);
    expect(identityKey).toContain(RP_ID);
    expect(identityKey).not.toContain('stale-key-rp.localhost');
  });

  test('runtime ECDSA boundary identity uses canonical availability identity builder', async () => {
    const record = runtimeEcdsaRecord({
      authMethod: 'passkey',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-runtime-boundary-identity',
      signingGrantId: 'wsess-runtime-boundary-identity',
      thresholdOwnerAddress: `0x${'AB'.repeat(20)}`,
      ecdsaThresholdKeyId: 'shared-ecdsa-key-runtime-boundary',
    });
    record.keyHandle = await deriveEvmFamilyEcdsaKeyHandle(record.key);
    const publicFacts = buildVerifiedEcdsaPublicFacts({
      keyHandle: record.keyHandle,
      publicKeyB64u: record.thresholdEcdsaPublicKeyB64u,
      participantIds: record.key.participantIds,
      thresholdOwnerAddress: record.key.thresholdOwnerAddress,
    });
    const canonicalIdentityKey = ecdsaAvailableLaneIdentityKey(
      buildRuntimeEcdsaAvailableLaneIdentityInput({ record, publicFacts }),
    );

    expect(await runtimeEcdsaAvailableLaneIdentityKey(record)).toBe(canonicalIdentityKey);
  });

  test('rejects runtime ECDSA lanes without keyHandle', async () => {
    const recordWithKeyHandle = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-runtime-missing-key-handle',
      signingGrantId: 'wsess-runtime-missing-key-handle',
      thresholdOwnerAddress: `0x${'AB'.repeat(20)}`,
      ecdsaThresholdKeyId: 'shared-ecdsa-key-missing-handle',
    });
    const { keyHandle: omittedKeyHandle, ...record } = recordWithKeyHandle;
    expect(omittedKeyHandle).toBeDefined();

    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [record as never],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(0);
  });

  test('rejects durable and runtime entries with one key id but different owner addresses', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          signingGrantId: 'wsess-owner-drift-durable',
          thresholdSessionId: 'tsess-owner-drift-durable',
          updatedAtMs: 500,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          ethereumAddress: `0x${'11'.repeat(20)}`,
          sessionKind: 'jwt',
        }),
      ],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-owner-drift-runtime',
          signingGrantId: 'wsess-owner-drift-runtime',
          thresholdOwnerAddress: `0x${'22'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          updatedAtMs: 800,
        }),
      ],
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
    });

    expect(
      availableLanes.ecdsa.candidatesByTarget[thresholdEcdsaChainTargetKey(ECDSA_TARGET)],
    ).toHaveLength(0);
    expect(
      availableLanes.ecdsa.candidatesByTarget[thresholdEcdsaChainTargetKey(TEMPO_TARGET)],
    ).toHaveLength(0);
  });
});
