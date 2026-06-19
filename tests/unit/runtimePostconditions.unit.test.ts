import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEcdsaSigningLane,
  ConcreteAvailableEd25519SigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  assertWalletRuntimePostconditions,
  compareWalletRuntimeInventories,
  readWalletRuntimePostconditions,
  type RuntimePostconditionAuthMethod,
} from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import {
  buildPasskeyEcdsaAuthBinding,
  buildEvmFamilyEcdsaKeyIdentity,
  buildResolvedEvmFamilyEcdsaKey,
  buildVerifiedEcdsaPublicFacts,
  type EvmFamilyEcdsaKeyHandle,
} from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';

const WALLET_ID = 'runtime-postconditions.testnet';
const TARGET: ThresholdEcdsaChainTarget = {
  kind: 'tempo',
  chainId: 42431,
  networkSlug: 'tempo-testnet',
};
const TARGET_KEY = thresholdEcdsaChainTargetKey(TARGET);
const ARC_TARGET: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 5042002,
  networkSlug: 'arc-testnet',
};
const ARC_TARGET_KEY = thresholdEcdsaChainTargetKey(ARC_TARGET);
const THRESHOLD_OWNER_ADDRESS = '0x1111111111111111111111111111111111111111';
const PUBLIC_KEY_B64U = 'AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
const REQUIRED_TARGETS = [
  { curve: 'ed25519' as const },
  { curve: 'ecdsa' as const, chainTarget: TARGET },
  { curve: 'ecdsa' as const, chainTarget: ARC_TARGET },
] as const;
type TestLaneSource = 'durable_sealed_record' | 'runtime_session_record' | 'runtime_and_durable';
type TestLaneOptions = {
  state?: 'ready' | 'restorable' | 'deferred' | 'expired' | 'exhausted';
  source?: TestLaneSource;
  remainingUses?: number;
  expiresAtMs?: number;
};

function ed25519Lane(
  suffix: string,
  authMethod: RuntimePostconditionAuthMethod = 'email_otp',
  options: TestLaneOptions = {},
): ConcreteAvailableEd25519SigningLane {
  return {
    authMethod,
    curve: 'ed25519',
    chain: 'near',
    state: options.state ?? 'ready',
    signingGrantId: `wss-ed25519-${suffix}`,
    thresholdSessionId: `tsess-ed25519-${suffix}`,
    remainingUses: options.remainingUses ?? 3,
    expiresAtMs: options.expiresAtMs ?? 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: options.source ?? 'runtime_session_record',
  };
}

function ecdsaLane(
  suffix: string,
  chainTarget: ThresholdEcdsaChainTarget,
  authMethod: RuntimePostconditionAuthMethod = 'email_otp',
  options: TestLaneOptions = {},
): ConcreteAvailableEcdsaSigningLane {
  const key = buildEvmFamilyEcdsaKeyIdentity({
    walletId: WALLET_ID,
    rpId: 'localhost',
    ecdsaThresholdKeyId: 'ecdsa-key-runtime-postconditions',
    signingRootId: 'root-runtime-postconditions',
    signingRootVersion: 'default',
    participantIds: [1, 2],
    thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
  });
  const publicFacts = buildVerifiedEcdsaPublicFacts({
    keyHandle: `ehss-runtime-postconditions-${suffix}` as EvmFamilyEcdsaKeyHandle,
    publicKeyB64u: PUBLIC_KEY_B64U,
    participantIds: key.participantIds,
    thresholdOwnerAddress: key.thresholdOwnerAddress,
  });
  const laneBase = {
    authMethod,
    curve: 'ecdsa' as const,
    chainTarget,
    state: options.state ?? 'ready',
    signingGrantId: `wss-ecdsa-${suffix}`,
    thresholdSessionId: `tehss-${suffix}`,
    remainingUses: options.remainingUses ?? 3,
    expiresAtMs: options.expiresAtMs ?? 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: options.source ?? 'runtime_session_record',
    key,
    publicFacts,
  };
  if (authMethod === 'passkey') {
    return {
      ...laneBase,
      authMethod: 'passkey',
      resolvedKey: buildResolvedEvmFamilyEcdsaKey({
        walletId: WALLET_ID,
        publicFacts,
        authBinding: buildPasskeyEcdsaAuthBinding({ rpId: 'localhost' }),
      }),
    };
  }
  return {
    ...laneBase,
    authMethod: 'email_otp',
  };
}

function availableLanes(
  suffix: string,
  authMethod: RuntimePostconditionAuthMethod = 'email_otp',
  options: TestLaneOptions = {},
): AvailableSigningLanes {
  const tempoEcdsa = ecdsaLane(`${suffix}-tempo`, TARGET, authMethod, options);
  const arcEcdsa = ecdsaLane(`${suffix}-arc`, ARC_TARGET, authMethod, options);
  const ed25519 = ed25519Lane(suffix, authMethod, options);
  return {
    walletId: toAccountId(WALLET_ID),
    generation: 1,
    ecdsa: {
      targets: [TARGET, ARC_TARGET],
      lanesByTarget: {
        [TARGET_KEY]: tempoEcdsa,
        [ARC_TARGET_KEY]: arcEcdsa,
      },
      candidatesByTarget: {
        [TARGET_KEY]: [tempoEcdsa],
        [ARC_TARGET_KEY]: [arcEcdsa],
      },
    },
    lanes: { ed25519: { near: ed25519 } },
    candidates: { ed25519: { near: [ed25519] } },
  };
}

test.describe('wallet runtime postconditions', () => {
  test('accepts ready exact Email OTP Ed25519 and ECDSA lanes', async () => {
    const inventory = await assertWalletRuntimePostconditions({
      source: 'registration_finalize',
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      requiredTargets: REQUIRED_TARGETS,
      readPersistedAvailableSigningLanes: async () => availableLanes('registration'),
    });

    expect(inventory.ed25519).toMatchObject({
      authMethod: 'email_otp',
      target: { curve: 'ed25519' },
      remainingSignatureUses: 3,
      material: { kind: 'runtime_session_record' },
    });
    expect(inventory.ecdsaByTarget.get(TARGET_KEY)).toMatchObject({
      authMethod: 'email_otp',
      target: { curve: 'ecdsa', chainTarget: TARGET },
      remainingSignatureUses: 3,
      material: { kind: 'runtime_session_record' },
    });
    expect(inventory.ecdsaByTarget.get(ARC_TARGET_KEY)).toMatchObject({
      authMethod: 'email_otp',
      target: { curve: 'ecdsa', chainTarget: ARC_TARGET },
      remainingSignatureUses: 3,
      material: { kind: 'runtime_session_record' },
    });
  });

  test('rejects auth-method route mismatches before reporting unlock success', async () => {
    const result = await readWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'passkey',
      requiredTargets: [{ curve: 'ed25519' }],
      readPersistedAvailableSigningLanes: async () => availableLanes('unlock'),
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'auth_method_route_mismatch',
    });
  });

  test('rejects Email OTP unlock when a sibling ECDSA target is missing', async () => {
    const lanesWithMissingArc = availableLanes('unlock-missing-arc');
    delete lanesWithMissingArc.ecdsa.lanesByTarget[ARC_TARGET_KEY];
    lanesWithMissingArc.ecdsa.candidatesByTarget[ARC_TARGET_KEY] = [];

    const result = await readWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      requiredTargets: REQUIRED_TARGETS,
      readPersistedAvailableSigningLanes: async () => lanesWithMissingArc,
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'ecdsa_lane_missing',
      details: {
        targetKey: ARC_TARGET_KEY,
        state: 'missing',
        candidateCount: 0,
      },
    });
  });

  test('compares registration and unlock lane shape without requiring identical session ids', async () => {
    const registration = await assertWalletRuntimePostconditions({
      source: 'registration_finalize',
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      requiredTargets: REQUIRED_TARGETS,
      readPersistedAvailableSigningLanes: async () => availableLanes('registration'),
    });
    const unlock = await assertWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      requiredTargets: REQUIRED_TARGETS,
      readPersistedAvailableSigningLanes: async () => availableLanes('unlock'),
    });

    expect(compareWalletRuntimeInventories({ registration, unlock })).toMatchObject({
      ok: true,
    });
  });

  test('compares passkey registration and unlock lane shape without requiring identical session ids', async () => {
    const registration = await assertWalletRuntimePostconditions({
      source: 'registration_finalize',
      walletId: WALLET_ID,
      authMethod: 'passkey',
      requiredTargets: REQUIRED_TARGETS,
      readPersistedAvailableSigningLanes: async () =>
        availableLanes('registration-passkey', 'passkey'),
    });
    const unlock = await assertWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'passkey',
      requiredTargets: REQUIRED_TARGETS,
      readPersistedAvailableSigningLanes: async () => availableLanes('unlock-passkey', 'passkey'),
    });

    expect(compareWalletRuntimeInventories({ registration, unlock })).toMatchObject({
      ok: true,
    });
  });

  test('accepts durable sealed exact lanes after page refresh', async () => {
    const inventory = await assertWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      requiredTargets: REQUIRED_TARGETS,
      readPersistedAvailableSigningLanes: async () =>
        availableLanes('page-refresh', 'email_otp', { source: 'durable_sealed_record' }),
    });

    expect(inventory.ed25519).toMatchObject({
      material: { kind: 'durable_sealed_record' },
    });
    expect(inventory.ecdsaByTarget.get(TARGET_KEY)).toMatchObject({
      material: { kind: 'durable_sealed_record' },
    });
    expect(inventory.ecdsaByTarget.get(ARC_TARGET_KEY)).toMatchObject({
      material: { kind: 'durable_sealed_record' },
    });
  });

  test('rejects expired exact lanes after page refresh', async () => {
    const result = await readWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      requiredTargets: [{ curve: 'ecdsa', chainTarget: ARC_TARGET }],
      readPersistedAvailableSigningLanes: async () =>
        availableLanes('page-refresh-expired', 'email_otp', {
          state: 'expired',
          source: 'durable_sealed_record',
          expiresAtMs: 1,
        }),
      nowMs: 1_800_000_000_000,
    });

    expect(result).toMatchObject({
      ok: false,
      code: 'ecdsa_lane_missing',
    });
  });
});
