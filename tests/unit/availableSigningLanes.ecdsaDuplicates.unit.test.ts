import { expect, test } from '@playwright/test';
import { selectTransactionLane } from '@/core/signingEngine/session/identity/selectLane';
import {
  availableEcdsaSigningLaneAuthMethod,
  buildRuntimeEcdsaAvailableLaneIdentityInput,
  ecdsaAvailableLaneAuthKey,
  ecdsaAvailableLaneIdentityKey,
  runtimeEcdsaAvailableLaneIdentityKey,
  runtimeEcdsaRecordAdvisoryKey,
  type AvailableEcdsaSigningLane,
  type ConcreteAvailableEcdsaSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  buildCurrentSealedSessionRecord,
  type SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
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
  AVAILABLE_LANES_ECDSA_SIGNING_KEY_SLOT_ID as SIGNING_KEY_SLOT_ID,
  AVAILABLE_LANES_ECDSA_TARGET as ECDSA_TARGET,
  AVAILABLE_LANES_EXPIRES_AT_MS as EXPIRES_AT_MS,
  AVAILABLE_LANES_PASSKEY_CREDENTIAL_ID as PASSKEY_CREDENTIAL_ID,
  AVAILABLE_LANES_TEMPO_TARGET as TEMPO_TARGET,
  AVAILABLE_LANES_WALLET_ID as WALLET_ID,
  readAvailableLanesFixture as readAvailableLanes,
  runtimeEcdsaAvailableLaneRecord as runtimeEcdsaRecord,
} from './helpers/availableSigningLanes.fixtures';

function unsignedEcdsaWalletSessionJwt(args: {
  walletId: string;
  keyHandle: string;
  thresholdSessionId: string;
  signingGrantId: string;
}): string {
  const payload = Buffer.from(
    JSON.stringify({
      kind: 'router_ab_ecdsa_derivation_wallet_session_v1',
      keyScope: 'evm-family',
      walletId: args.walletId,
      keyHandle: args.keyHandle,
      thresholdSessionId: args.thresholdSessionId,
      signingGrantId: args.signingGrantId,
    }),
  ).toString('base64url');
  return `e30.${payload}.signature`;
}

function sealedEmailOtpEcdsaRecord(args: {
  chainTarget: typeof ECDSA_TARGET | typeof TEMPO_TARGET;
  thresholdSessionId: string;
  signingGrantId: string;
  updatedAtMs: number;
}): SigningSessionSealedStoreRecord {
  const runtimeRecord = runtimeEcdsaRecord({
    authMethod: 'email_otp',
    chainTarget: args.chainTarget,
    thresholdSessionId: args.thresholdSessionId,
    signingGrantId: args.signingGrantId,
    thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
    ecdsaThresholdKeyId: 'shared-ecdsa-key',
    keyHandle: TEST_ECDSA_KEY_HANDLE,
    remainingUses: 3,
    updatedAtMs: args.updatedAtMs,
  });
  const record = buildCurrentSealedSessionRecord({
    curve: 'ecdsa',
    authMethod: 'email_otp',
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionIds: { ecdsa: args.thresholdSessionId },
    signingGrantId: args.signingGrantId,
    sealedSecretB64u: `sealed-${args.thresholdSessionId}`,
    keyVersion: 'seal-key-v1',
    shamirPrimeB64u: 'shamir-prime',
    walletId: String(runtimeRecord.key.walletId),
    relayerUrl: 'https://relay.example.test',
    ecdsaRestore: {
      chainTarget: args.chainTarget,
      source: 'email_otp',
      evmFamilySigningKeySlotId: runtimeRecord.key.evmFamilySigningKeySlotId,
      signingRootId: runtimeRecord.key.signingRootId,
      signingRootVersion: runtimeRecord.key.signingRootVersion,
      provider: 'google',
      providerSubjectId: 'google:available-lanes',
      emailHashHex: '11'.repeat(32),
      walletSessionJwt: unsignedEcdsaWalletSessionJwt({
        walletId: String(runtimeRecord.key.walletId),
        keyHandle: String(runtimeRecord.keyHandle),
        thresholdSessionId: args.thresholdSessionId,
        signingGrantId: args.signingGrantId,
      }),
      sessionKind: 'jwt',
      keyHandle: runtimeRecord.keyHandle,
      ecdsaThresholdKeyId: runtimeRecord.key.ecdsaThresholdKeyId,
      ethereumAddress: runtimeRecord.key.thresholdOwnerAddress,
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: Buffer.from(new Uint8Array([2, ...Array(32).fill(3)])).toString(
        'base64url',
      ),
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      participantIds: [...runtimeRecord.key.participantIds],
      routerAbEcdsaDerivationNormalSigning: {
        kind: 'router_ab_ecdsa_derivation_normal_signing_v1',
        scope: {
          wallet_key_id: runtimeRecord.key.evmFamilySigningKeySlotId,
          wallet_id: runtimeRecord.key.walletId,
          ecdsa_threshold_key_id: runtimeRecord.key.ecdsaThresholdKeyId,
          signing_root_id: runtimeRecord.key.signingRootId,
          signing_root_version: runtimeRecord.key.signingRootVersion,
          context: {
            application_binding_digest_b64u: Buffer.from(new Uint8Array(32).fill(6)).toString(
              'base64url',
            ),
          },
          public_identity: {
            context_binding_b64u: Buffer.from(new Uint8Array(32).fill(5)).toString('base64url'),
            derivation_client_share_public_key33_b64u: Buffer.from(
              new Uint8Array([2, ...Array(32).fill(3)]),
            ).toString('base64url'),
            server_public_key33_b64u: Buffer.from(
              new Uint8Array([2, ...Array(32).fill(2)]),
            ).toString('base64url'),
            threshold_public_key33_b64u: VALID_ECDSA_PUBLIC_KEY_B64U,
            ethereum_address20_b64u: Buffer.from(new Uint8Array(20).fill(0xef)).toString(
              'base64url',
            ),
            client_share_retry_counter: 0,
            server_share_retry_counter: 0,
          },
          signing_worker: {
            server_id: 'signing-worker-test',
            key_epoch: 'worker-epoch-test',
            recipient_encryption_key:
              'x25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
          },
          activation_epoch: args.thresholdSessionId,
        },
      },
      runtimePolicyScope: {
        orgId: 'org-test',
        projectId: 'sr-test',
        envId: 'dev',
        signingRootVersion: 'default',
      },
    },
    issuedAtMs: args.updatedAtMs,
    expiresAtMs: EXPIRES_AT_MS,
    remainingUses: 3,
    updatedAtMs: args.updatedAtMs,
  });
  if (!record) throw new Error(`failed to build ${args.thresholdSessionId}`);
  return record;
}

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
  test('preserves durable reauth authority when a matching runtime lane is exhausted', async () => {
    const thresholdSessionId = 'tsess-email-otp-runtime-durable-exhausted';
    const signingGrantId = 'wsess-email-otp-runtime-durable-exhausted';
    const durableRecord = sealedEmailOtpEcdsaRecord({
      chainTarget: ECDSA_TARGET,
      thresholdSessionId,
      signingGrantId,
      updatedAtMs: 700,
    });
    const runtimeRecord = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId,
      signingGrantId,
      thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
      ecdsaThresholdKeyId: 'shared-ecdsa-key',
      keyHandle: TEST_ECDSA_KEY_HANDLE,
      remainingUses: 0,
      updatedAtMs: 800,
    });

    const availableLanes = await readAvailableLanes({
      sealedRecords: [durableRecord],
      runtimeEcdsaRecords: [runtimeRecord],
    });
    const lane = availableLanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(ECDSA_TARGET)];

    expectEcdsaLaneAuthMethod(lane, 'email_otp');
    expect(lane).toMatchObject({
      source: 'durable_sealed_record',
      state: 'exhausted',
      remainingUses: 0,
      thresholdSessionId,
      signingGrantId,
      publicReauthAuthority: {
        source: 'email_otp',
        chainTarget: ECDSA_TARGET,
        providerSubjectId: 'google:available-lanes',
      },
    });
  });

  test('keeps both exact durable Email OTP target authorities after refresh', async () => {
    const signingGrantId = 'wsess-email-otp-durable-family';
    for (const updateOrder of [
      { tempoUpdatedAtMs: 700, arcUpdatedAtMs: 800 },
      { tempoUpdatedAtMs: 800, arcUpdatedAtMs: 700 },
    ]) {
      const tempoRecord = sealedEmailOtpEcdsaRecord({
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'tsess-email-otp-durable-tempo',
        signingGrantId,
        updatedAtMs: updateOrder.tempoUpdatedAtMs,
      });
      const arcRecord = sealedEmailOtpEcdsaRecord({
        chainTarget: ECDSA_TARGET,
        thresholdSessionId: 'tsess-email-otp-durable-arc',
        signingGrantId,
        updatedAtMs: updateOrder.arcUpdatedAtMs,
      });

      for (const ecdsaChainTargets of [
        [TEMPO_TARGET, ECDSA_TARGET],
        [ECDSA_TARGET, TEMPO_TARGET],
      ] as const) {
        const availableLanes = await readAvailableLanes({
          sealedRecords: [tempoRecord, arcRecord],
          ecdsaChainTargets: [...ecdsaChainTargets],
        });
        const tempoLane =
          availableLanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(TEMPO_TARGET)];
        const arcLane =
          availableLanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(ECDSA_TARGET)];

        expectEcdsaLaneAuthMethod(tempoLane, 'email_otp');
        expectEcdsaLaneAuthMethod(arcLane, 'email_otp');
        expect(tempoLane).toMatchObject({
          source: 'durable_sealed_record',
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'tsess-email-otp-durable-tempo',
          signingGrantId,
        });
        expect(arcLane).toMatchObject({
          source: 'durable_sealed_record',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-durable-arc',
          signingGrantId,
        });
      }
    }
  });

  test('projects one durable Email OTP family authority to either missing target order', async () => {
    const arcRecord = sealedEmailOtpEcdsaRecord({
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-email-otp-durable-arc-source',
      signingGrantId: 'wsess-email-otp-durable-arc-source',
      updatedAtMs: 800,
    });

    for (const ecdsaChainTargets of [
      [TEMPO_TARGET, ECDSA_TARGET],
      [ECDSA_TARGET, TEMPO_TARGET],
    ] as const) {
      const availableLanes = await readAvailableLanes({
        sealedRecords: [arcRecord],
        ecdsaChainTargets: [...ecdsaChainTargets],
      });
      const tempoLane =
        availableLanes.ecdsa.lanesByTarget[thresholdEcdsaChainTargetKey(TEMPO_TARGET)];

      expectEcdsaLaneAuthMethod(tempoLane, 'email_otp');
      expect(tempoLane).toMatchObject({
        source: 'evm_family_shared_key',
        sourceChainTarget: ECDSA_TARGET,
        chainTarget: TEMPO_TARGET,
        thresholdSessionId: 'tsess-email-otp-durable-arc-source',
        signingGrantId: 'wsess-email-otp-durable-arc-source',
      });
    }
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
        keyHandle: expect.stringMatching(/^ederivation-key-/),
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

  test('projects a canonical EVM-family authority after discarding an unusable target-local lane', async () => {
    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-exhausted-source',
          signingGrantId: 'wsess-email-otp-exhausted-source',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          remainingUses: 0,
          updatedAtMs: 900,
        }),
        runtimeEcdsaRecord({
          authMethod: 'passkey',
          chainTarget: TEMPO_TARGET,
          thresholdSessionId: 'tsess-passkey-deferred-tempo',
          signingGrantId: 'wsess-passkey-deferred-tempo',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          remainingUses: 2,
          updatedAtMs: 800,
        }),
      ],
    });

    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    const tempoLane = availableLanes.ecdsa.lanesByTarget[tempoTargetKey];
    expectEcdsaLaneAuthMethod(tempoLane, 'email_otp');
    expect(tempoLane).toMatchObject({
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      chainTarget: TEMPO_TARGET,
      state: 'exhausted',
      remainingUses: 0,
      thresholdSessionId: 'tsess-email-otp-exhausted-source',
      signingGrantId: 'wsess-email-otp-exhausted-source',
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
    delete staleRecord.routerAbEcdsaDerivationNormalSigning;

    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [staleRecord as never],
      warmStatusAdvisories: new Map([
        [
          'tsess-ecdsa-stale-router-ab',
          {
            kind: 'warm_status',
            status: 'active',
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

  test('prefers a ready shared EVM-family runtime lane over a deferred exact target lane', async () => {
    const tempoThresholdSessionId = 'tsess-email-otp-tempo-ready';
    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          signingGrantId: 'wsess-email-otp-arc-deferred',
          thresholdSessionId: 'tsess-email-otp-arc-deferred',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          remainingUses: 1,
          updatedAtMs: 900,
        }),
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
      warmStatusAdvisories: new Map([
        [
          tempoThresholdSessionId,
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: tempoThresholdSessionId,
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const evmCandidates = availableLanes.ecdsa.candidatesByTarget[evmTargetKey] || [];
    expect(evmCandidates).toHaveLength(1);
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

  test('preserves a durable-policy Tempo restorable state in the shared Arc projection', async () => {
    const thresholdSessionId = 'tsess-email-otp-tempo-restorable';
    const signingGrantId = 'wsess-email-otp-tempo-restorable';
    const tempoRecord = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: TEMPO_TARGET,
      thresholdSessionId,
      signingGrantId,
      thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
      ecdsaThresholdKeyId: 'shared-ecdsa-key',
      keyHandle: TEST_ECDSA_KEY_HANDLE,
      remainingUses: 2,
      updatedAtMs: 700,
    });
    const tempoAdvisoryKey = runtimeEcdsaRecordAdvisoryKey(tempoRecord);
    if (!tempoAdvisoryKey) throw new Error('Tempo runtime record advisory key missing');

    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [tempoRecord],
      warmEcdsaAdvisories: new Map([
        [
          tempoAdvisoryKey,
          {
            kind: 'durable_policy',
            thresholdSessionId,
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
            state: 'restorable',
          },
        ],
      ]),
    });

    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    const arcTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.lanesByTarget[tempoTargetKey]).toMatchObject({
      source: 'runtime_session_record',
      chainTarget: TEMPO_TARGET,
      state: 'restorable',
      thresholdSessionId,
      signingGrantId,
    });
    expect(availableLanes.ecdsa.lanesByTarget[arcTargetKey]).toMatchObject({
      source: 'evm_family_shared_key',
      sourceChainTarget: TEMPO_TARGET,
      chainTarget: ECDSA_TARGET,
      state: 'restorable',
      thresholdSessionId,
      signingGrantId,
    });
  });

  test('selects the preferred shared EVM-family lane for Tempo transaction signing', async () => {
    const arcThresholdSessionId = 'tsess-email-otp-arc-ready-for-tempo';
    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: TEMPO_TARGET,
          signingGrantId: 'wsess-email-otp-tempo-deferred',
          thresholdSessionId: 'tsess-email-otp-tempo-deferred',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          remainingUses: 1,
          updatedAtMs: 900,
        }),
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: arcThresholdSessionId,
          signingGrantId: 'wsess-email-otp-arc-ready-for-tempo',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          remainingUses: 2,
          updatedAtMs: 700,
        }),
      ],
      warmStatusAdvisories: new Map([
        [
          arcThresholdSessionId,
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: arcThresholdSessionId,
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    const tempoCandidates = availableLanes.ecdsa.candidatesByTarget[tempoTargetKey] || [];
    expect(tempoCandidates).toHaveLength(1);
    const selectedLane = availableLanes.ecdsa.lanesByTarget[tempoTargetKey];
    expectEcdsaLaneAuthMethod(selectedLane, 'email_otp');
    expect(selectedLane).toMatchObject({
      source: 'evm_family_shared_key',
      sourceChainTarget: ECDSA_TARGET,
      state: 'ready',
      thresholdSessionId: arcThresholdSessionId,
    });

    const selected = selectTransactionLane({
      intent: {
        walletId: toWalletId(WALLET_ID),
        curve: 'ecdsa',
        chain: 'tempo',
        chainTarget: TEMPO_TARGET,
        authSelectionPolicy: { kind: 'explicit', authMethod: 'email_otp' },
        operationUsesNeeded: 1,
      },
      availableLanes,
    });

    expect(selected).toMatchObject({
      ok: true,
      availableLane: {
        source: 'evm_family_shared_key',
        sourceChainTarget: ECDSA_TARGET,
        state: 'ready',
        thresholdSessionId: arcThresholdSessionId,
      },
    });
  });

  test('selects the canonical exact ECDSA lane after repeated Email OTP step-up records', async () => {
    const activeThresholdSessionId = 'tsess-email-otp-tempo-stepup-active';
    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: TEMPO_TARGET,
          signingGrantId: 'wsess-email-otp-tempo-stepup-exhausted',
          thresholdSessionId: 'tsess-email-otp-tempo-stepup-exhausted',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          remainingUses: 0,
          updatedAtMs: 1_100,
        }),
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: TEMPO_TARGET,
          signingGrantId: 'wsess-email-otp-tempo-stepup-active',
          thresholdSessionId: activeThresholdSessionId,
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          keyHandle: TEST_ECDSA_KEY_HANDLE,
          remainingUses: 2,
          updatedAtMs: 1_000,
        }),
      ],
      warmStatusAdvisories: new Map([
        [
          activeThresholdSessionId,
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: activeThresholdSessionId,
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const tempoTargetKey = thresholdEcdsaChainTargetKey(TEMPO_TARGET);
    const tempoCandidates = availableLanes.ecdsa.candidatesByTarget[tempoTargetKey] || [];
    expect(tempoCandidates).toHaveLength(1);
    const selectedLane = availableLanes.ecdsa.lanesByTarget[tempoTargetKey];
    expectEcdsaLaneAuthMethod(selectedLane, 'email_otp');
    expect(selectedLane).toMatchObject({
      source: 'runtime_session_record',
      state: 'ready',
      thresholdSessionId: activeThresholdSessionId,
      signingGrantId: 'wsess-email-otp-tempo-stepup-active',
    });

    const selected = selectTransactionLane({
      intent: {
        walletId: toWalletId(WALLET_ID),
        curve: 'ecdsa',
        chain: 'tempo',
        chainTarget: TEMPO_TARGET,
        authSelectionPolicy: { kind: 'explicit', authMethod: 'email_otp' },
        operationUsesNeeded: 1,
      },
      availableLanes,
    });

    expect(selected).toMatchObject({
      ok: true,
      availableLane: {
        source: 'runtime_session_record',
        state: 'ready',
        thresholdSessionId: activeThresholdSessionId,
        signingGrantId: 'wsess-email-otp-tempo-stepup-active',
      },
    });
  });

  test('fails closed for active ECDSA sessions without comparable server generations', async () => {
    const firstRecordWithGeneration = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-ecdsa-active-no-generation-1',
      signingGrantId: 'wsess-ecdsa-active-no-generation-1',
      thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
      ecdsaThresholdKeyId: 'shared-ecdsa-key',
      keyHandle: TEST_ECDSA_KEY_HANDLE,
      updatedAtMs: 300,
    });
    const secondRecordWithGeneration = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-ecdsa-active-no-generation-2',
      signingGrantId: 'wsess-ecdsa-active-no-generation-2',
      thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
      ecdsaThresholdKeyId: 'shared-ecdsa-key',
      keyHandle: TEST_ECDSA_KEY_HANDLE,
      updatedAtMs: 400,
    });
    const { expiresAtMs: firstExpiresAtMs, ...firstRecord } = firstRecordWithGeneration;
    const { expiresAtMs: secondExpiresAtMs, ...secondRecord } = secondRecordWithGeneration;
    expect(firstExpiresAtMs).toBeDefined();
    expect(secondExpiresAtMs).toBeDefined();

    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [firstRecord, secondRecord],
      warmStatusAdvisories: new Map([
        [
          'tsess-ecdsa-active-no-generation-1',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-ecdsa-active-no-generation-1',
            remainingUses: 3,
          },
        ],
        [
          'tsess-ecdsa-active-no-generation-2',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-ecdsa-active-no-generation-2',
            remainingUses: 3,
          },
        ],
      ]),
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(0);
    expect(availableLanes.ecdsa.lanesByTarget[evmTargetKey]?.state).toBe('missing');
    expect(availableLanes.diagnostics?.invalidLanes).toContainEqual(
      expect.objectContaining({
        curve: 'ecdsa',
        source: 'canonical_lane_inventory',
        reason: 'ambiguous_material',
        targetKey: evmTargetKey,
      }),
    );
  });

  test('rejects distinct ECDSA key groups at the availability boundary', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-key-group-1',
          signingGrantId: 'wsess-email-otp-key-group-1',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'ecdsa-key-group-1',
          remainingUses: 2,
          updatedAtMs: 800,
        }),
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-key-group-2',
          signingGrantId: 'wsess-email-otp-key-group-2',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          ecdsaThresholdKeyId: 'ecdsa-key-group-2',
          remainingUses: 2,
          updatedAtMs: 900,
        }),
      ],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(0);
    expect(availableLanes.ecdsa.lanesByTarget[evmTargetKey]?.state).toBe('missing');
    expect(availableLanes.diagnostics?.invalidLanes).toContainEqual(
      expect.objectContaining({
        curve: 'ecdsa',
        source: 'canonical_lane_inventory',
        reason: 'conflicting_key_material',
        targetKey: evmTargetKey,
        conflicts: expect.arrayContaining([
          expect.objectContaining({
            field: 'ecdsaThresholdKeyId',
            values: ['ecdsa-key-group-1', 'ecdsa-key-group-2'],
          }),
        ]),
      }),
    );

    const selected = selectTransactionLane({
      intent: {
        walletId: toWalletId(WALLET_ID),
        curve: 'ecdsa',
        chain: 'evm',
        chainTarget: ECDSA_TARGET,
        authSelectionPolicy: { kind: 'explicit', authMethod: 'email_otp' },
        operationUsesNeeded: 1,
      },
      availableLanes,
    });

    expect(selected).toMatchObject({
      ok: false,
      failure: {
        kind: 'no_candidate',
        authMethod: 'email_otp',
      },
    });
  });

  test('does not share Email OTP runtime advisories across ECDSA chain targets with the same threshold session id', async () => {
    const thresholdSessionId = 'tsess-email-otp-shared-session-target-advisories';
    const signingGrantId = 'wsess-email-otp-shared-session-target-advisories';
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
    const tempoClaimKey = runtimeEcdsaRecordAdvisoryKey(tempoRecord);
    if (!tempoClaimKey) throw new Error('tempo runtime record claim key missing');

    const availableLanes = await readAvailableLanes({
      ecdsaChainTargets: [ECDSA_TARGET, TEMPO_TARGET],
      runtimeEcdsaRecords: [arcRecord, tempoRecord],
      warmEcdsaAdvisories: new Map([
        [
          tempoClaimKey,
          {
            kind: 'warm_status',
            status: 'active',
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
    const thresholdSessionId = 'tsess-passkey-runtime';
    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'passkey',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId,
          signingGrantId: 'wsess-passkey-runtime',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
        }),
      ],
      warmStatusAdvisories: new Map([
        [
          thresholdSessionId,
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId,
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
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
      evmFamilySigningKeySlotId: SIGNING_KEY_SLOT_ID,
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

  test('rejects runtime entries with one key id but different owner addresses', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-owner-drift-runtime-1',
          signingGrantId: 'wsess-owner-drift-runtime-1',
          thresholdOwnerAddress: `0x${'11'.repeat(20)}`,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          updatedAtMs: 500,
        }),
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-owner-drift-runtime-2',
          signingGrantId: 'wsess-owner-drift-runtime-2',
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
