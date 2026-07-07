import { expect, test } from '@playwright/test';
import {
  isConcreteAvailableSigningLane,
  type AvailableEd25519SigningLane,
  type AvailableSigningLanesRuntimeEd25519Record,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  buildCurrentSealedSessionRecord,
  type SigningSessionSealedStoreRecord,
} from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { thresholdEcdsaChainTargetKey } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import {
  AVAILABLE_LANES_ECDSA_TARGET as ECDSA_TARGET,
  AVAILABLE_LANES_ED25519_KEY_SCOPE_ID as ED25519_KEY_SCOPE_ID,
  AVAILABLE_LANES_ED25519_NEAR_ACCOUNT_ID as ED25519_NEAR_ACCOUNT_ID,
  AVAILABLE_LANES_ED25519_WALLET_ID as ED25519_WALLET_ID,
  AVAILABLE_LANES_ECDSA_RP_ID as RP_ID,
  AVAILABLE_LANES_EXPIRES_AT_MS as EXPIRES_AT_MS,
  AVAILABLE_LANES_TEMPO_TARGET as TEMPO_TARGET,
  readAvailableLanesFixture as readAvailableLanes,
  runtimeEcdsaAvailableLaneRecord as runtimeEcdsaRecord,
  runtimeEd25519RouterAbNormalSigningState,
} from './helpers/availableSigningLanes.fixtures';

const PASSKEY_AUTH = {
  kind: 'passkey',
  rpId: toRpId(RP_ID),
  credentialIdB64u: 'credential-ed25519-duplicates',
} as const;
const EMAIL_OTP_AUTH = {
  kind: 'email_otp',
  providerSubjectId: 'google:ed25519-duplicates',
} as const;
const ED25519_MATERIAL_BINDING_DIGEST = 'material-binding-ed25519';
const ED25519_MATERIAL_KEY_ID = 'material-key-ed25519';

function concreteEd25519AuthKinds(lanes: AvailableEd25519SigningLane[]): string[] {
  const authKinds: string[] = [];
  for (const lane of lanes) {
    if (!isConcreteAvailableSigningLane(lane) || lane.curve !== 'ed25519') continue;
    authKinds.push(lane.auth.kind);
  }
  return authKinds.sort();
}

function sealedEd25519Record(args: {
  authMethod: 'email_otp' | 'passkey';
  signingGrantId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
  expiresAtMs?: number;
  remainingUses?: number;
}): SigningSessionSealedStoreRecord {
  const issuedAtMs = Date.now();
  const record = buildCurrentSealedSessionRecord({
    curve: 'ed25519',
    authMethod: args.authMethod,
    walletId: String(ED25519_WALLET_ID),
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
      nearAccountId: String(ED25519_NEAR_ACCOUNT_ID),
      nearEd25519SigningKeyId: String(ED25519_KEY_SCOPE_ID),
      rpId: 'wallet.example.localhost',
      ...(args.authMethod === 'passkey'
        ? { credentialIdB64u: PASSKEY_AUTH.credentialIdB64u }
        : {
            providerSubjectId: EMAIL_OTP_AUTH.providerSubjectId,
            emailHashHex: 'email-hash-ed25519-duplicates',
          }),
      relayerKeyId: 'relayer-key',
      participantIds: [1, 2],
      sessionKind: 'jwt',
      walletSessionJwt: 'jwt-ed25519',
      clientVerifyingShareB64u: 'client-verifying-share-ed25519',
      ed25519WorkerMaterialBindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
      sealedWorkerMaterialRef: 'sealed-worker-material-ed25519',
      sealedWorkerMaterialB64u: 'sealed-worker-material-blob-ed25519',
      materialFormatVersion: 'ed25519_worker_material_v1',
      materialKeyId: ED25519_MATERIAL_KEY_ID,
      materialCreatedAtMs: issuedAtMs,
      signerSlot: 1,
      routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
      runtimePolicyScope: {
        orgId: 'org-test',
        projectId: 'sr-test',
        envId: 'dev',
        signingRootVersion: 'default',
      },
    },
    issuedAtMs,
    expiresAtMs: args.expiresAtMs ?? issuedAtMs + 60_000,
    remainingUses: args.remainingUses ?? 1,
    updatedAtMs: args.updatedAtMs,
  });
  if (!record) {
    throw new Error(`failed to build Ed25519 sealed fixture ${args.thresholdSessionId}`);
  }
  return record;
}

function runtimeEd25519Record(args: {
  auth?: typeof PASSKEY_AUTH | typeof EMAIL_OTP_AUTH;
  signingGrantId: string;
  thresholdSessionId: string;
  remainingUses?: number;
  expiresAtMs?: number;
  updatedAtMs?: number;
}): AvailableSigningLanesRuntimeEd25519Record {
  return {
    auth: args.auth || EMAIL_OTP_AUTH,
    curve: 'ed25519',
    chain: 'near',
    routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
    walletId: ED25519_WALLET_ID,
    nearAccountId: ED25519_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
    signerSlot: 1,
    signingGrantId: args.signingGrantId,
    thresholdSessionId: args.thresholdSessionId,
    remainingUses: args.remainingUses ?? 3,
    expiresAtMs: args.expiresAtMs ?? EXPIRES_AT_MS,
    updatedAtMs: args.updatedAtMs ?? 700,
    material: {
      kind: 'loaded_worker_material',
      identity: {
        bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
        materialKeyId: ED25519_MATERIAL_KEY_ID,
      },
    },
  };
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
      auth: { kind: 'email_otp' },
      source: 'durable_sealed_record',
      signingGrantId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      updatedAtMs: 200,
    });
  });

  test('classifies expired durable Ed25519 sealed records as stale reauth anchors', async () => {
    const expiresAtMs = Date.now() - 1_000;
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'passkey',
          signingGrantId: 'wsess-expired-ed25519',
          thresholdSessionId: 'tsess-expired-ed25519',
          expiresAtMs,
          remainingUses: 3,
          updatedAtMs: 300,
        }),
      ],
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      auth: { kind: 'passkey' },
      source: 'durable_sealed_record',
      state: 'expired',
      signingGrantId: 'wsess-expired-ed25519',
      thresholdSessionId: 'tsess-expired-ed25519',
      remainingUses: 3,
      expiresAtMs,
      material: {
        kind: 'sealed_worker_material',
        identity: {
          bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
          materialKeyId: ED25519_MATERIAL_KEY_ID,
        },
      },
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
          auth: EMAIL_OTP_AUTH,
          curve: 'ed25519',
          chain: 'near',
          routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
          walletId: ED25519_WALLET_ID,
          nearAccountId: ED25519_NEAR_ACCOUNT_ID,
          nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
          signerSlot: 1,
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          material: {
            kind: 'loaded_worker_material',
            identity: {
              bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
              materialKeyId: ED25519_MATERIAL_KEY_ID,
            },
          },
        },
      ],
      warmStatusAdvisories: new Map([
        [
          'tsess-1',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-1',
            remainingUses: 1,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      auth: { kind: 'email_otp' },
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wsess-1',
      thresholdSessionId: 'tsess-1',
      remainingUses: 1,
      material: {
        kind: 'loaded_worker_material',
        identity: {
          bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
          materialKeyId: ED25519_MATERIAL_KEY_ID,
        },
      },
    });
    expect(availableLanes.lanes.ed25519.near).toMatchObject({
      source: 'runtime_session_record',
      material: {
        kind: 'loaded_worker_material',
        identity: {
          bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
          materialKeyId: ED25519_MATERIAL_KEY_ID,
        },
      },
    });
  });

  test('suppresses stale durable Ed25519 lanes when a fresh runtime lane exists for the same authority', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEd25519Record({
          authMethod: 'passkey',
          signingGrantId: 'wsess-registration',
          thresholdSessionId: 'tsess-registration',
          updatedAtMs: 100,
        }),
      ],
      runtimeEd25519Records: [
        {
          auth: PASSKEY_AUTH,
          curve: 'ed25519',
          chain: 'near',
          routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
          walletId: ED25519_WALLET_ID,
          nearAccountId: ED25519_NEAR_ACCOUNT_ID,
          nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
          signerSlot: 1,
          signingGrantId: 'wsess-unlock',
          thresholdSessionId: 'tsess-unlock',
          material: {
            kind: 'loaded_worker_material',
            identity: {
              bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
              materialKeyId: ED25519_MATERIAL_KEY_ID,
            },
          },
        },
      ],
      warmStatusAdvisories: new Map([
        [
          'tsess-unlock',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-unlock',
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      auth: { kind: 'passkey' },
      state: 'ready',
      source: 'runtime_session_record',
      signingGrantId: 'wsess-unlock',
      thresholdSessionId: 'tsess-unlock',
      remainingUses: 2,
      material: {
        kind: 'loaded_worker_material',
        identity: {
          bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
          materialKeyId: ED25519_MATERIAL_KEY_ID,
        },
      },
    });
    expect(availableLanes.lanes.ed25519.near).toMatchObject({
      source: 'runtime_session_record',
      signingGrantId: 'wsess-unlock',
      thresholdSessionId: 'tsess-unlock',
    });
  });

  test('does not advertise a warm Ed25519 runtime lane without Router A/B normal-signing state', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEd25519Records: [
        {
          auth: PASSKEY_AUTH,
          curve: 'ed25519',
          chain: 'near',
          signingGrantId: 'wsess-stale-router-ab',
          thresholdSessionId: 'tsess-stale-router-ab',
        } as never,
      ],
      warmStatusAdvisories: new Map([
        [
          'tsess-stale-router-ab',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-stale-router-ab',
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.lanes.ed25519.near.state).toBe('missing');
    expect(availableLanes.candidates.ed25519.near).toEqual([]);
    expect(availableLanes.diagnostics?.invalidLanes || []).toEqual([]);
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
      warmEcdsaAdvisories: new Map([
        [
          thresholdEcdsaChainTargetKey(ECDSA_TARGET),
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
          auth: PASSKEY_AUTH,
          curve: 'ed25519',
          chain: 'near',
          routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
          walletId: ED25519_WALLET_ID,
          nearAccountId: ED25519_NEAR_ACCOUNT_ID,
          nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
          signerSlot: 1,
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          material: {
            kind: 'loaded_worker_material',
            identity: {
              bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
              materialKeyId: ED25519_MATERIAL_KEY_ID,
            },
          },
        },
        {
          auth: EMAIL_OTP_AUTH,
          curve: 'ed25519',
          chain: 'near',
          routerAbNormalSigning: runtimeEd25519RouterAbNormalSigningState(),
          walletId: ED25519_WALLET_ID,
          nearAccountId: ED25519_NEAR_ACCOUNT_ID,
          nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
          signerSlot: 1,
          signingGrantId: 'wsess-1',
          thresholdSessionId: 'tsess-1',
          material: {
            kind: 'loaded_worker_material',
            identity: {
              bindingDigest: ED25519_MATERIAL_BINDING_DIGEST,
              materialKeyId: ED25519_MATERIAL_KEY_ID,
            },
          },
        },
      ],
      warmStatusAdvisories: new Map([
        [
          'tsess-1',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-1',
            remainingUses: 1,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(2);
    expect(concreteEd25519AuthKinds(availableLanes.candidates.ed25519.near)).toEqual([
      'email_otp',
      'passkey',
    ]);
  });

  test('collapses same-authority durable Ed25519 sessions to the newest lane', async () => {
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

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      auth: { kind: 'email_otp' },
      source: 'durable_sealed_record',
      signingGrantId: 'wsess-2',
      thresholdSessionId: 'tsess-2',
      updatedAtMs: 200,
    });
    expect(availableLanes.lanes.ed25519.near).toMatchObject({
      signingGrantId: 'wsess-2',
      thresholdSessionId: 'tsess-2',
    });
  });

  test('collapses exhausted runtime Ed25519 session after fresh step-up', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEd25519Records: [
        runtimeEd25519Record({
          signingGrantId: 'wsess-old-step-up',
          thresholdSessionId: 'tsess-old-step-up',
          remainingUses: 0,
          updatedAtMs: 100,
        }),
        runtimeEd25519Record({
          signingGrantId: 'wsess-fresh-step-up',
          thresholdSessionId: 'tsess-fresh-step-up',
          remainingUses: 3,
          updatedAtMs: 200,
        }),
      ],
      warmStatusAdvisories: new Map([
        [
          'tsess-old-step-up',
          {
            kind: 'warm_status',
            status: 'exhausted',
            thresholdSessionId: 'tsess-old-step-up',
            remainingUses: 0,
          },
        ],
        [
          'tsess-fresh-step-up',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-fresh-step-up',
            remainingUses: 3,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      auth: { kind: 'email_otp' },
      source: 'runtime_session_record',
      state: 'ready',
      signingGrantId: 'wsess-fresh-step-up',
      thresholdSessionId: 'tsess-fresh-step-up',
      remainingUses: 3,
    });
    expect(availableLanes.lanes.ed25519.near).toMatchObject({
      signingGrantId: 'wsess-fresh-step-up',
      thresholdSessionId: 'tsess-fresh-step-up',
    });
  });

  test('collapses concurrent active runtime Ed25519 sessions to the newest expiry', async () => {
    const oldExpiresAtMs = EXPIRES_AT_MS - 30_000;
    const newExpiresAtMs = EXPIRES_AT_MS;
    const availableLanes = await readAvailableLanes({
      runtimeEd25519Records: [
        runtimeEd25519Record({
          signingGrantId: 'wsess-active-old',
          thresholdSessionId: 'tsess-active-old',
          expiresAtMs: oldExpiresAtMs,
          updatedAtMs: 300,
        }),
        runtimeEd25519Record({
          signingGrantId: 'wsess-active-new',
          thresholdSessionId: 'tsess-active-new',
          expiresAtMs: newExpiresAtMs,
          updatedAtMs: 200,
        }),
      ],
      warmStatusAdvisories: new Map([
        [
          'tsess-active-old',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-active-old',
            remainingUses: 3,
            expiresAtMs: oldExpiresAtMs,
          },
        ],
        [
          'tsess-active-new',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-active-new',
            remainingUses: 3,
            expiresAtMs: newExpiresAtMs,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(1);
    expect(availableLanes.candidates.ed25519.near[0]).toMatchObject({
      signingGrantId: 'wsess-active-new',
      thresholdSessionId: 'tsess-active-new',
      expiresAtMs: newExpiresAtMs,
    });
  });

  test('fails closed for active Ed25519 sessions without comparable server generations', async () => {
    const firstRecordWithGeneration = runtimeEd25519Record({
      signingGrantId: 'wsess-active-no-generation-1',
      thresholdSessionId: 'tsess-active-no-generation-1',
      updatedAtMs: 300,
    });
    const secondRecordWithGeneration = runtimeEd25519Record({
      signingGrantId: 'wsess-active-no-generation-2',
      thresholdSessionId: 'tsess-active-no-generation-2',
      updatedAtMs: 400,
    });
    const { expiresAtMs: firstExpiresAtMs, ...firstRecord } = firstRecordWithGeneration;
    const { expiresAtMs: secondExpiresAtMs, ...secondRecord } = secondRecordWithGeneration;
    expect(firstExpiresAtMs).toBeDefined();
    expect(secondExpiresAtMs).toBeDefined();

    const availableLanes = await readAvailableLanes({
      runtimeEd25519Records: [firstRecord, secondRecord],
      warmStatusAdvisories: new Map([
        [
          'tsess-active-no-generation-1',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-active-no-generation-1',
            remainingUses: 3,
          },
        ],
        [
          'tsess-active-no-generation-2',
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: 'tsess-active-no-generation-2',
            remainingUses: 3,
          },
        ],
      ]),
    });

    expect(availableLanes.candidates.ed25519.near).toHaveLength(0);
    expect(availableLanes.lanes.ed25519.near.state).toBe('missing');
    expect(availableLanes.diagnostics?.invalidLanes).toContainEqual(
      expect.objectContaining({
        curve: 'ed25519',
        source: 'canonical_lane_inventory',
        reason: 'ambiguous_material',
      }),
    );
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
      auth: { kind: 'email_otp' },
      source: 'runtime_session_record',
      state: 'exhausted',
      remainingUses: 0,
      signingGrantId: 'wsess-email-otp-runtime-exhausted',
      thresholdSessionId: 'tsess-email-otp-runtime-exhausted',
    });
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      auth: { kind: 'email_otp' },
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
      warmStatusAdvisories: new Map([
        [
          thresholdSessionId,
          {
            kind: 'warm_status',
            status: 'active',
            thresholdSessionId: thresholdSessionId,
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
      auth: { kind: 'email_otp' },
      source: 'runtime_session_record',
      state: 'ready',
      remainingUses: 1,
      signingGrantId: 'wsess-email-otp-runtime-ready',
      thresholdSessionId,
    });
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[tempoTargetKey][0]).toMatchObject({
      auth: { kind: 'email_otp' },
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
