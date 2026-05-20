import { expect, test } from '@playwright/test';
import {
  buildRuntimeEcdsaAvailableLaneIdentityInput,
  ecdsaAvailableLaneAuthRpId,
  ecdsaAvailableLaneIdentityKey,
  readAvailableSigningLanes,
  runtimeEcdsaAvailableLaneIdentityKey,
  type AvailableSigningLanesRuntimeClaim,
  type AvailableSigningLanesRuntimeEcdsaRecord,
  type ConcreteAvailableEcdsaSigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  thresholdEcdsaChainTargetFromChainFamily,
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  buildBaseEvmFamilyEcdsaKeyIdentity,
  buildPasskeyEcdsaAuthBinding,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  deriveEvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { EvmFamilyEcdsaKeyHandle } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import type { SigningSessionSealedStoreRecord } from '@/core/signingEngine/session/persistence/sealedSessionStore';
import { THRESHOLD_ECDSA_SESSION_AUTH_TOKEN_KIND } from '@shared/utils/sessionTokens';

const WALLET_ID = 'alice.testnet';
const RP_ID = 'wallet.example.localhost';
const EXPIRES_AT_MS = 2_000_000_000_000;
const VALID_ECDSA_PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const TEST_ECDSA_KEY_HANDLE = 'ehss-key-available-lane-test' as EvmFamilyEcdsaKeyHandle;
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
    keyHandle: args.keyHandle,
    chainTarget: args.chainTarget,
    sessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
  });
}

function sealedEcdsaRecord(args: {
  authMethod?: 'email_otp' | 'passkey';
  walletSigningSessionId: string;
  thresholdSessionId: string;
  updatedAtMs: number;
  chainTarget?: ThresholdEcdsaChainTarget;
  ecdsaThresholdKeyId?: string;
  keyHandle?: string;
  ethereumAddress?: string;
  remainingUses?: number;
  expiresAtMs?: number;
  sessionKind?: 'cookie' | 'jwt';
}): SigningSessionSealedStoreRecord {
  const issuedAtMs = Date.now();
  const authMethod = args.authMethod || 'passkey';
  const chainTarget = args.chainTarget || ECDSA_TARGET;
  const ecdsaThresholdKeyId = args.ecdsaThresholdKeyId || 'ek-passkey';
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
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
    relayerUrl: 'https://relay.example.test',
    keyVersion: 'seal-key-v1',
    shamirPrimeB64u: 'shamir-prime',
    ecdsaRestore: {
      chainTarget,
      rpId: RP_ID,
      sessionKind,
      ...(sessionKind === 'jwt'
        ? {
            thresholdSessionAuthToken: thresholdEcdsaSessionJwt({
              thresholdSessionId: args.thresholdSessionId,
              walletSigningSessionId: args.walletSigningSessionId,
              chainTarget,
              keyHandle: args.keyHandle || TEST_ECDSA_KEY_HANDLE,
            }),
          }
        : {}),
      ecdsaThresholdKeyId,
      keyHandle: args.keyHandle || TEST_ECDSA_KEY_HANDLE,
      thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
      ethereumAddress: args.ethereumAddress || `0x${'AB'.repeat(20)}`,
      relayerKeyId: 'relayer-key',
      clientVerifyingShareB64u: 'client-verifying-share',
      participantIds: [1, 2],
    },
    issuedAtMs,
    expiresAtMs: args.expiresAtMs ?? issuedAtMs + 60_000,
    remainingUses: args.remainingUses ?? 1,
    updatedAtMs: args.updatedAtMs,
  } as unknown as SigningSessionSealedStoreRecord;
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
  expiresAtMs?: number;
  updatedAtMs?: number;
}): AvailableSigningLanesRuntimeEcdsaRecord {
  const keyId = args.ecdsaThresholdKeyId || 'shared-ecdsa-key';
  const key = buildBaseEvmFamilyEcdsaKeyIdentity({
    walletId: WALLET_ID,
    rpId: RP_ID,
    ecdsaThresholdKeyId: keyId,
    signingRootId: 'sr-test:dev',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress: args.thresholdOwnerAddress,
  });
  return {
    key,
    keyHandle: args.keyHandle || TEST_ECDSA_KEY_HANDLE,
    thresholdEcdsaPublicKeyB64u: VALID_ECDSA_PUBLIC_KEY_B64U,
    authMethod: args.authMethod || 'passkey',
    curve: 'ecdsa',
    chainTarget: args.chainTarget,
    thresholdSessionId: args.thresholdSessionId,
    walletSigningSessionId: args.walletSigningSessionId,
    remainingUses: args.remainingUses ?? 3,
    expiresAtMs: args.expiresAtMs ?? EXPIRES_AT_MS,
    updatedAtMs: args.updatedAtMs ?? 700,
  };
}

async function readAvailableLanes(args: {
  sealedRecords?: SigningSessionSealedStoreRecord[];
  ecdsaChainTargets?: [ThresholdEcdsaChainTarget, ...ThresholdEcdsaChainTarget[]];
  runtimeEcdsaRecords?: AvailableSigningLanesRuntimeEcdsaRecord[];
  runtimeClaims?: Map<string, AvailableSigningLanesRuntimeClaim>;
}) {
  return await readAvailableSigningLanes(
    {
      walletId: WALLET_ID,
      ecdsaChainTargets: args.ecdsaChainTargets || [ECDSA_TARGET],
    },
    {
      listSealedRecordsForWallet: async ({ filter }) =>
        (args.sealedRecords || []).filter((record) => {
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
        (args.sealedRecords || []).filter((record) => {
          if (record.curve !== 'ecdsa') return false;
          if (filter.authMethod && record.authMethod !== filter.authMethod) return false;
          return Boolean(record.ecdsaRestore?.chainTarget);
        }),
      listRuntimeEcdsaLanesForWallet: async () => args.runtimeEcdsaRecords || [],
      listRuntimeEd25519RecordsForAccount: async () => [],
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

test.describe('ECDSA available signing lane duplicate normalization', () => {
  test('collapses duplicate exhausted Email OTP runtime lanes by shared key identity', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-runtime-exhausted-1',
          walletSigningSessionId: 'wsess-email-otp-runtime-exhausted-1',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          remainingUses: 0,
          updatedAtMs: 700,
        }),
        runtimeEcdsaRecord({
          authMethod: 'email_otp',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-email-otp-runtime-exhausted-2',
          walletSigningSessionId: 'wsess-email-otp-runtime-exhausted-2',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          remainingUses: 0,
          updatedAtMs: 800,
        }),
      ],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'runtime_session_record',
      state: 'exhausted',
      remainingUses: 0,
      walletSigningSessionId: 'wsess-email-otp-runtime-exhausted-2',
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
          walletSigningSessionId: 'wsess-runtime-expired-1',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
          expiresAtMs: 1,
          updatedAtMs: 700,
        }),
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-runtime-expired-2',
          walletSigningSessionId: 'wsess-runtime-expired-2',
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
      walletSigningSessionId: 'wsess-runtime-expired-2',
      thresholdSessionId: 'tsess-runtime-expired-2',
    });
  });

  test('uses the runtime lane when durable and runtime entries share exact ECDSA identity', async () => {
    const runtimeRecord = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-runtime-durable',
      walletSigningSessionId: 'wsess-runtime-durable',
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
          walletSigningSessionId: 'wsess-runtime-durable',
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
            sessionId: 'tsess-runtime-durable',
            remainingUses: 2,
            expiresAtMs: EXPIRES_AT_MS,
          },
        ],
      ]),
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(1);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0]).toMatchObject({
      authMethod: 'email_otp',
      source: 'runtime_and_durable',
      state: 'ready',
      remainingUses: 2,
      walletSigningSessionId: 'wsess-runtime-durable',
      thresholdSessionId: 'tsess-runtime-durable',
      updatedAtMs: 800,
    });
  });

  test('passkey ECDSA availability lanes carry resolved-key auth binding', async () => {
    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          authMethod: 'passkey',
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-passkey-runtime',
          walletSigningSessionId: 'wsess-passkey-runtime',
          thresholdOwnerAddress: `0x${'EF'.repeat(20)}`,
        }),
      ],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    const lane = availableLanes.ecdsa.candidatesByTarget[evmTargetKey][0];

    expect(lane).toMatchObject({
      authMethod: 'passkey',
      resolvedKey: {
        kind: 'resolved_evm_family_ecdsa_key',
        authBinding: {
          kind: 'passkey_ecdsa_auth_binding',
          rpId: RP_ID,
        },
      },
    });
    if (!lane || lane.state === 'missing' || lane.authMethod !== 'passkey') {
      throw new Error('expected passkey ECDSA lane');
    }
    expect(lane.resolvedKey.publicFacts).toBe(lane.publicFacts);
  });

  test('passkey ECDSA availability identity uses auth binding rpId', () => {
    const key = buildBaseEvmFamilyEcdsaKeyIdentity({
      walletId: WALLET_ID,
      rpId: 'stale-key-rp.localhost',
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
      authMethod: 'passkey',
      resolvedKey: buildResolvedEvmFamilyEcdsaKey({
        walletId: key.walletId,
        publicFacts,
        authBinding: buildPasskeyEcdsaAuthBinding({ rpId: RP_ID }),
      }),
      curve: 'ecdsa',
      chainTarget: ECDSA_TARGET,
      state: 'ready',
      source: 'runtime_session_record',
      walletSigningSessionId: 'wallet-session-auth-binding-rp',
      thresholdSessionId: 'threshold-session-auth-binding-rp',
    };

    const identityKey = ecdsaAvailableLaneIdentityKey(lane);

    expect(ecdsaAvailableLaneAuthRpId(lane)).toBe(RP_ID);
    expect(identityKey).toContain(RP_ID);
    expect(identityKey).not.toContain('stale-key-rp.localhost');
  });

  test('runtime ECDSA boundary identity uses canonical availability identity builder', async () => {
    const record = runtimeEcdsaRecord({
      authMethod: 'passkey',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-runtime-boundary-identity',
      walletSigningSessionId: 'wsess-runtime-boundary-identity',
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
    const record = runtimeEcdsaRecord({
      authMethod: 'email_otp',
      chainTarget: ECDSA_TARGET,
      thresholdSessionId: 'tsess-runtime-missing-key-handle',
      walletSigningSessionId: 'wsess-runtime-missing-key-handle',
      thresholdOwnerAddress: `0x${'AB'.repeat(20)}`,
      ecdsaThresholdKeyId: 'shared-ecdsa-key-missing-handle',
    });
    delete record.keyHandle;

    const availableLanes = await readAvailableLanes({
      runtimeEcdsaRecords: [record],
    });

    const evmTargetKey = thresholdEcdsaChainTargetKey(ECDSA_TARGET);
    expect(availableLanes.ecdsa.candidatesByTarget[evmTargetKey]).toHaveLength(0);
  });

  test('rejects durable and runtime entries with one key id but different owner addresses', async () => {
    const availableLanes = await readAvailableLanes({
      sealedRecords: [
        sealedEcdsaRecord({
          walletSigningSessionId: 'wsess-owner-drift-durable',
          thresholdSessionId: 'tsess-owner-drift-durable',
          updatedAtMs: 500,
          ecdsaThresholdKeyId: 'shared-ecdsa-key',
          ethereumAddress: `0x${'11'.repeat(20)}`,
        }),
      ],
      runtimeEcdsaRecords: [
        runtimeEcdsaRecord({
          chainTarget: ECDSA_TARGET,
          thresholdSessionId: 'tsess-owner-drift-runtime',
          walletSigningSessionId: 'wsess-owner-drift-runtime',
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
