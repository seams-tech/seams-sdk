import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import {
  thresholdEcdsaChainTargetKey,
  toWalletId,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableSigningLanes,
  ConcreteAvailableEd25519SigningLane,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  assertWalletRuntimePostconditions,
  compareWalletRuntimeInventories,
  readWalletRuntimePostconditions,
} from '@/core/signingEngine/session/postconditions/runtimePostconditions';
import type { SigningSessionSealAuthMethod } from '@shared/utils/signingSessionSeal';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import {
  availableLaneEd25519Authorization,
  canonicalEcdsaAvailableLane,
} from './helpers/availableSigningLanes.fixtures';
import { buildMpcMaterialActivationRefFixture } from './helpers/ecdsaMaterialRef.fixtures';

const WALLET_ID = 'runtime-postconditions.testnet';
const ED25519_WALLET_ID = toWalletId('frost-vermillion-k7p9m2');
const ED25519_NEAR_ACCOUNT_ID = toAccountId('runtime-postconditions.testnet');
const ED25519_KEY_SCOPE_ID = nearEd25519SigningKeyIdFromString('scope-frost-vermillion-k7p9m2');
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
const PASSKEY_AUTH = {
  kind: 'passkey' as const,
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-runtime-postconditions',
};
const EMAIL_OTP_AUTH = {
  kind: 'email_otp' as const,
  providerSubjectId: 'google:runtime-postconditions',
};
const REQUIRED_TARGETS = [
  { curve: 'ed25519' as const },
  { curve: 'ecdsa' as const, chainTarget: TARGET },
  { curve: 'ecdsa' as const, chainTarget: ARC_TARGET },
] as const;
type TestLaneSource = 'durable_sealed_record';
type TestLaneOptions = {
  state?: 'ready' | 'restorable' | 'deferred' | 'expired' | 'exhausted';
  source?: TestLaneSource;
  remainingUses?: number;
  expiresAtMs?: number;
};

function ed25519Lane(
  suffix: string,
  authMethod: SigningSessionSealAuthMethod = 'email_otp',
  options: TestLaneOptions = {},
): ConcreteAvailableEd25519SigningLane {
  return {
    auth: authMethod === 'passkey' ? PASSKEY_AUTH : EMAIL_OTP_AUTH,
    curve: 'ed25519',
    chain: 'near',
    walletId: ED25519_WALLET_ID,
    nearAccountId: ED25519_NEAR_ACCOUNT_ID,
    nearEd25519SigningKeyId: ED25519_KEY_SCOPE_ID,
    signerSlot: 1,
    state: options.state ?? 'ready',
    authorizationState: 'authorized',
    authorization: availableLaneEd25519Authorization({
      walletId: String(ED25519_WALLET_ID),
      identitySeed: suffix,
      authMethod,
      expiresAtMs: options.expiresAtMs,
    }),
    materialActivation: buildMpcMaterialActivationRefFixture(
      `runtime-postcondition:${suffix}`,
      String(ED25519_WALLET_ID),
    ),
    thresholdSessionId: `tsess-ed25519-${suffix}`,
    remainingUses: options.remainingUses ?? 3,
    expiresAtMs: options.expiresAtMs ?? 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
    source: 'durable_sealed_record',
  };
}

function ecdsaLane(
  _suffix: string,
  chainTarget: ThresholdEcdsaChainTarget,
  authMethod: SigningSessionSealAuthMethod = 'email_otp',
  options: TestLaneOptions = {},
): ReturnType<typeof canonicalEcdsaAvailableLane> {
  return canonicalEcdsaAvailableLane({
    walletId: WALLET_ID,
    chainTarget,
    ecdsaThresholdKeyId: 'ecdsa-key-runtime-postconditions',
    thresholdOwnerAddress: THRESHOLD_OWNER_ADDRESS,
    authMethod,
    state: options.state ?? 'ready',
    remainingUses: options.remainingUses ?? 3,
    expiresAtMs: options.expiresAtMs ?? 1_900_000_000_000,
    updatedAtMs: 1_800_000_000_000,
  });
}

function availableLanes(
  suffix: string,
  authMethod: SigningSessionSealAuthMethod = 'email_otp',
  options: TestLaneOptions = {},
): AvailableSigningLanes {
  const tempoEcdsa = ecdsaLane(`${suffix}-tempo`, TARGET, authMethod, options);
  const arcEcdsa = ecdsaLane(`${suffix}-arc`, ARC_TARGET, authMethod, options);
  const ed25519 = ed25519Lane(suffix, authMethod, options);
  return {
    walletId: toWalletId(WALLET_ID),
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

function moveLanePolicyToDurableHint(lanes: AvailableSigningLanes): void {
  const ed25519 = lanes.lanes.ed25519.near;
  if (ed25519.state !== 'missing') {
    ed25519.policyHint = {
      remainingUses: ed25519.remainingUses,
      expiresAtMs: ed25519.expiresAtMs,
    };
    delete ed25519.remainingUses;
    delete ed25519.expiresAtMs;
  }
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
      material: { kind: 'durable_sealed_record' },
    });
    expect(inventory.ecdsaByTarget.get(TARGET_KEY)).toMatchObject({
      authMethod: 'email_otp',
      target: { curve: 'ecdsa', chainTarget: TARGET },
      remainingSignatureUses: 3,
      material: { kind: 'canonical_capability' },
    });
    expect(inventory.ecdsaByTarget.get(ARC_TARGET_KEY)).toMatchObject({
      authMethod: 'email_otp',
      target: { curve: 'ecdsa', chainTarget: ARC_TARGET },
      remainingSignatureUses: 3,
      material: { kind: 'canonical_capability' },
    });
  });

  test('accepts candidate-backed Ed25519 lanes when the aggregate slot is stale', async () => {
    const lanes = availableLanes('candidate-backed-unlock', 'passkey');
    lanes.lanes.ed25519.near = {
      curve: 'ed25519',
      chain: 'near',
      state: 'missing',
    };

    const inventory = await assertWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'passkey',
      requiredTargets: [{ curve: 'ed25519' }],
      readPersistedAvailableSigningLanes: async () => lanes,
    });

    expect(inventory.ed25519).toMatchObject({
      authMethod: 'passkey',
      target: { curve: 'ed25519' },
      walletSessionId: 'available-lane-wallet-session:candidate-backed-unlock',
      quotaId: 'available-lane-quota:candidate-backed-unlock',
      material: { kind: 'durable_sealed_record' },
    });
  });

  test('accepts an authorized public Email OTP lane with its issued session budget', async () => {
    const lanes = availableLanes('email-otp-public-unlock');
    const ed25519 = lanes.lanes.ed25519.near;
    if (ed25519.state === 'missing') throw new Error('expected concrete Ed25519 lane');
    ed25519.source = 'public_capability_reference';
    lanes.candidates.ed25519.near = [ed25519];

    const inventory = await assertWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      requiredTargets: [{ curve: 'ed25519' }],
      readPersistedAvailableSigningLanes: async () => lanes,
    });

    expect(inventory.ed25519).toMatchObject({
      authMethod: 'email_otp',
      remainingSignatureUses: 3,
      material: { kind: 'public_capability_reference' },
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

  test('accepts canonical exact lanes after page refresh', async () => {
    const lanes = availableLanes('page-refresh');
    const ed25519 = lanes.lanes.ed25519.near;
    if (ed25519.state === 'missing') throw new Error('expected concrete Ed25519 lane');
    ed25519.state = 'restorable';
    ed25519.source = 'durable_sealed_record';
    moveLanePolicyToDurableHint(lanes);

    const inventory = await assertWalletRuntimePostconditions({
      source: 'wallet_unlock',
      walletId: WALLET_ID,
      authMethod: 'email_otp',
      requiredTargets: REQUIRED_TARGETS,
      readPersistedAvailableSigningLanes: async () => lanes,
    });

    expect(inventory.ed25519).toMatchObject({
      state: 'restorable',
      material: { kind: 'durable_sealed_record' },
    });
    expect(inventory.ecdsaByTarget.get(TARGET_KEY)).toMatchObject({
      state: 'ready',
      material: { kind: 'canonical_capability' },
    });
    expect(inventory.ecdsaByTarget.get(ARC_TARGET_KEY)).toMatchObject({
      state: 'ready',
      material: { kind: 'canonical_capability' },
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
