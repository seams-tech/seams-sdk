import { expect, test } from '@playwright/test';
import {
  isConcreteAvailableSigningLane,
  readAvailableSigningLanes,
  type AvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanesRuntimeEcdsaRecord,
  type AvailableSigningLanesRuntimeEd25519Record,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { buildBaseEvmFamilyEcdsaKeyIdentity } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyEcdsaKeyHandle } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND } from '@shared/utils/sessionTokens';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';

const WALLET_ID = 'alice.testnet';
const EXPIRES_AT_MS = 2_000_000_000_000;
const VALID_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const ECDSA_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'evm',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
});
const TEMPO_TARGET = thresholdEcdsaChainTargetFromChainFamily({
  chain: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-moderato',
});

function unsignedJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `${header}.${body}.`;
}

function thresholdEcdsaSessionJwt(args: {
  thresholdSessionId: string;
  walletSigningSessionId: string;
  chainTarget: ThresholdEcdsaChainTarget;
  keyHandle: string;
}): string {
  return unsignedJwt({
    kind: THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND,
    sub: WALLET_ID,
    walletId: WALLET_ID,
    keyScope: 'evm-family',
    keyHandle: args.keyHandle,
    chainTarget: args.chainTarget,
    sessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
  });
}

function sealedEd25519Record(args: {
  authMethod: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
  restoreMetadata?: 'valid' | 'missing_x_client_base';
}): SigningSessionSealedStoreRecord {
  const issuedAtMs = Date.now();
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
      sessionKind: args.authMethod === 'email_otp' ? 'jwt' : 'cookie',
      ...(args.authMethod === 'email_otp' ? { thresholdSessionAuthToken: 'jwt-ed25519' } : {}),
      ...(args.restoreMetadata === 'missing_x_client_base'
        ? {}
        : { xClientBaseB64u: 'x-client-base' }),
    },
    issuedAtMs,
    expiresAtMs: issuedAtMs + 60_000,
    remainingUses: 1,
    updatedAtMs: args.updatedAtMs,
  } as unknown as SigningSessionSealedStoreRecord;
}

function sealedEcdsaRecord(args: {
  authMethod?: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
  restoreMetadata: 'valid' | 'missing' | 'missing_rp_id';
  chainTarget?: ThresholdEcdsaChainTarget;
  participantIds?: number[];
  ethereumAddress?: string;
  remainingUses?: number;
  sessionKind?: 'cookie' | 'jwt';
}): SigningSessionSealedStoreRecord {
  const issuedAtMs = Date.now();
  const authMethod = args.authMethod || 'passkey';
  const chainTarget = args.chainTarget || ECDSA_TARGET;
  const sessionKind = args.sessionKind || 'cookie';
  return {
    storeKey: `${authMethod}:${args.walletSigningSessionId}:${args.thresholdSessionId}:${args.updatedAtMs}:ecdsa`,
    curve: 'ecdsa',
    authMethod,
    walletId: WALLET_ID,
    walletSigningSessionId: args.walletSigningSessionId,
    thresholdSessionId: args.thresholdSessionId,
    thresholdSessionIds: { ecdsa: args.thresholdSessionId },
    sealedSecretB64u: 'sealed',
    relayerUrl: 'https://relay.example.test',
    keyVersion: 'seal-key-v1',
    shamirPrimeB64u: 'shamir-prime',
    ecdsaRestore:
      args.restoreMetadata === 'missing'
        ? {
            chainTarget,
            sessionKind: 'cookie',
            ecdsaThresholdKeyId: 'ek-passkey',
          }
        : {
            chainTarget,
            ...(args.restoreMetadata === 'missing_rp_id'
              ? {}
              : { rpId: 'wallet.example.localhost' }),
            sessionKind,
            ...(sessionKind === 'jwt'
              ? {
                  thresholdSessionAuthToken: thresholdEcdsaSessionJwt({
                    thresholdSessionId: args.thresholdSessionId,
                    walletSigningSessionId: args.walletSigningSessionId,
                    chainTarget,
                    keyHandle: 'ehss-key-available-lane-ed25519-test',
                  }),
                }
              : {}),
            ecdsaThresholdKeyId: 'ek-passkey',
            keyHandle: 'ehss-key-available-lane-ed25519-test',
            thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
            ethereumAddress: args.ethereumAddress || `0x${'AB'.repeat(20)}`,
            relayerKeyId: 'relayer-key',
            clientVerifyingShareB64u: 'client-verifying-share',
            participantIds: args.participantIds || [1, 2],
            runtimePolicyScope: {
              orgId: 'org-test',
              projectId: 'sr-test',
              envId: 'dev',
              signingRootVersion: 'default',
            },
          },
    issuedAtMs,
    expiresAtMs: issuedAtMs + 60_000,
    remainingUses: args.remainingUses ?? 1,
    updatedAtMs: args.updatedAtMs,
  } as unknown as SigningSessionSealedStoreRecord;
}

async function readAvailableLanes(args: {
  sealedRecords: SigningSessionSealedStoreRecord[];
  ecdsaChainTargets?: [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  runtimeEcdsaRecords?: AvailableSigningLanesRuntimeEcdsaRecord[];
  runtimeRecords?: AvailableSigningLanesRuntimeEd25519Record[];
  runtimeClaims?: Map<string, AvailableSigningLanesRuntimeClaim>;
}) {
  return await readAvailableSigningLanes(
    {
      walletId: WALLET_ID,
      ecdsaChainTargets: args.ecdsaChainTargets || [ECDSA_TARGET],
    },
    {
      listSealedRecordsForWallet: async ({ filter }) =>
        args.sealedRecords.filter((record) => {
          if (record.curve !== filter.curve) return false;
          if (filter.authMethod && record.authMethod !== filter.authMethod) return false;
          if (filter.curve !== 'ecdsa') return true;
          return (
            Boolean(record.ecdsaRestore?.chainTarget) &&
            thresholdEcdsaChainTargetKey(record.ecdsaRestore!.chainTarget) ===
              thresholdEcdsaChainTargetKey(filter.chainTarget)
          );
        }),
      listEcdsaSealedRecordsForWallet: async ({ filter }) =>
        args.sealedRecords.filter((record) => {
          if (record.curve !== 'ecdsa') return false;
          if (filter.authMethod && record.authMethod !== filter.authMethod) return false;
          return Boolean(record.ecdsaRestore?.chainTarget);
        }),
      listRuntimeEcdsaLanesForWallet: async () => args.runtimeEcdsaRecords || [],
      listRuntimeEd25519RecordsForAccount: async () => args.runtimeRecords || [],
      readRuntimeClaimsForSessions: async (sessionIds) => {
        const claims = new Map<string, AvailableSigningLanesRuntimeClaim | null>();
        for (const sessionId of sessionIds) {
          claims.set(sessionId, args.runtimeClaims?.get(sessionId) || null);
        }
        return claims;
      },
    },
  );
}

function runtimeEcdsaRecord(args: {
  chainTarget: ThresholdEcdsaChainTarget;
  thresholdSessionId: string;
  walletSigningSessionId: string;
  thresholdOwnerAddress: string;
  authMethod?: 'email_otp' | 'passkey';
  ecdsaThresholdKeyId?: string;
  keyHandle?: EvmFamilyEcdsaKeyHandle;
  remainingUses?: number;
  updatedAtMs?: number;
}): AvailableSigningLanesRuntimeEcdsaRecord {
  const keyId = args.ecdsaThresholdKeyId || 'shared-ecdsa-key';
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: WALLET_ID,
    rpId: 'wallet.example.localhost',
    ecdsaThresholdKeyId: keyId,
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress: args.thresholdOwnerAddress,
  });
  const base = {
    key,
    keyHandle: args.keyHandle || (`ehss-key-${keyId}` as EvmFamilyEcdsaKeyHandle),
    thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    remainingUses: args.remainingUses ?? 3,
    expiresAtMs: EXPIRES_AT_MS,
    updatedAtMs: args.updatedAtMs ?? 700,
  } as const;
  return (args.authMethod || 'passkey') === 'email_otp'
    ? { ...base, authMethod: 'email_otp' }
    : { ...base, authMethod: 'passkey' };
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
      runtimeRecords: [
        {
          authMethod: 'email_otp',
          curve: 'ed25519',
          chain: 'near',
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
      runtimeRecords: [
        {
          authMethod: 'email_otp',
          curve: 'ed25519',
          chain: 'near',
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

  test('ignores legacy chain-only ECDSA sealed records during available-lane rebuild', async () => {
    const validRecord = sealedEcdsaRecord({
      walletSigningSessionId: 'wsess-valid-ecdsa',
      thresholdSessionId: 'tsess-valid-ecdsa',
      updatedAtMs: 200,
      restoreMetadata: 'valid',
    });
    const legacyChainOnlyRecord = {
      ...sealedEcdsaRecord({
        walletSigningSessionId: 'wsess-legacy-chain-only',
        thresholdSessionId: 'tsess-legacy-chain-only',
        updatedAtMs: 300,
        restoreMetadata: 'valid',
      }),
      ecdsaRestore: {
        chain: 'evm',
        sessionKind: 'cookie',
        ecdsaThresholdKeyId: 'ek-legacy-chain-only',
        rpId: 'wallet.example.localhost',
        ethereumAddress: `0x${'EF'.repeat(20)}`,
        relayerKeyId: 'legacy-relayer-key',
        clientVerifyingShareB64u: 'legacy-client-verifying-share',
        participantIds: [1, 2],
      },
    } as unknown as SigningSessionSealedStoreRecord;
    const availableLanes = await readAvailableLanes({
      sealedRecords: [legacyChainOnlyRecord, validRecord],
    });

    const targetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[targetKey][0]).toMatchObject({
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
