import { expect, test } from '@playwright/test';
import { canonicalEcdsaAvailableLane } from './helpers/availableSigningLanes.fixtures';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { ensureEcdsaPrfSealPersisted } from '@/core/signingEngine/session/passkey/runtime';
import type { WarmSessionSealAndPersistResult } from '@/core/types/secure-confirm-worker';
import {
  thresholdEcdsaChainTargetKey,
  type ThresholdEcdsaChainTarget,
} from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { buildPasskeyEcdsaSealedRuntimeRecordFixture } from './helpers/sealedSigningSession.fixtures';

const chainTarget: ThresholdEcdsaChainTarget = {
  kind: 'evm',
  namespace: 'eip155',
  chainId: 11155111,
  networkSlug: 'sepolia',
};

test('persists the threshold session identity separately from material activation', async () => {
  const available = canonicalEcdsaAvailableLane({
    chainTarget,
    thresholdOwnerAddress: '0x1111111111111111111111111111111111111111',
    authMethod: 'passkey',
  });
  if (!available.authorization || !available.resolvedKey) {
    throw new Error('passkey ECDSA fixture must have authorization and resolved key');
  }
  const lane = exactEcdsaSigningLaneIdentity({
    signer: buildEvmFamilyEcdsaSignerBinding({
      walletId: available.key.walletId,
      chainTarget: available.chainTarget,
      keyHandle: available.resolvedKey.keyHandle,
      key: available.key,
      materialActivation: available.materialActivation,
    }),
    auth: available.auth,
  });
  const restoreMetadata = buildPasskeyEcdsaSealedRuntimeRecordFixture({
    manifest: available.capability.manifest,
  }).ecdsaRestore;
  const calls: Array<{ thresholdSessionId: string }> = [];
  const persisted: WarmSessionSealAndPersistResult = {
    ok: true,
    sealedSecretB64u: 'sealed-secret',
    remainingUses: 2,
    expiresAtMs: Date.now() + 60_000,
  };

  await ensureEcdsaPrfSealPersisted({
    lane,
    authorization: available.authorization,
    thresholdSessionId: 'threshold-session-real',
    restoreMetadata,
    sealPersistence: {
      persistSigningSessionSealForThresholdSession: async (input) => {
        calls.push({ thresholdSessionId: input.thresholdSessionId });
        return persisted;
      },
    },
    sealPersistInFlightByMaterialActivation: new Map(),
    resolveSealTransport: async () => ({
      curve: 'ecdsa',
      walletId: String(restoreMetadata.authority.walletId),
      chainTarget,
      relayerUrl: 'https://relay.example',
    }),
  });

  expect(calls).toEqual([{ thresholdSessionId: 'threshold-session-real' }]);
  expect(calls[0]?.thresholdSessionId).not.toBe(available.materialActivation.activationId);

  await expect(
    ensureEcdsaPrfSealPersisted({
      lane,
      authorization: available.authorization,
      thresholdSessionId: 'threshold-session-mismatched-wallet',
      restoreMetadata,
      required: true,
      sealPersistence: {
        persistSigningSessionSealForThresholdSession: async () => persisted,
      },
      sealPersistInFlightByMaterialActivation: new Map(),
      resolveSealTransport: async () => ({
        curve: 'ecdsa',
        walletId: 'foreign-wallet',
        chainTarget,
        relayerUrl: 'https://relay.example',
      }),
    }),
  ).rejects.toThrow('does not match restore metadata');
});

test('persists one exact ECDSA seal record for every registration target', async () => {
  const walletId = 'registration-two-target-wallet';
  const targets: readonly [ThresholdEcdsaChainTarget, ThresholdEcdsaChainTarget] = [
    {
      kind: 'tempo',
      chainId: 42431,
      networkSlug: 'tempo-testnet',
    },
    {
      kind: 'evm',
      namespace: 'eip155',
      chainId: 5042002,
      networkSlug: 'arc-testnet',
    },
  ];
  const lanes = targets.map((chainTarget, index) =>
    canonicalEcdsaAvailableLane({
      walletId,
      chainTarget,
      thresholdOwnerAddress: `0x${String(index + 1).padStart(40, '0')}`,
      ecdsaThresholdKeyId: 'registration-family-key',
      authMethod: 'passkey',
    }),
  );
  const calls: Array<{
    thresholdSessionId: string;
    chainTarget: ThresholdEcdsaChainTarget;
    restoreChainTarget: ThresholdEcdsaChainTarget;
  }> = [];
  const persisted: WarmSessionSealAndPersistResult = {
    ok: true,
    sealedSecretB64u: 'sealed-registration-secret',
    remainingUses: 2,
    expiresAtMs: Date.now() + 60_000,
  };
  const inFlight = new Map<string, Promise<void>>();

  for (const [index, available] of lanes.entries()) {
    if (!available.authorization || !available.resolvedKey) {
      throw new Error('passkey ECDSA registration fixture must have an exact lane');
    }
    const lane = exactEcdsaSigningLaneIdentity({
      signer: buildEvmFamilyEcdsaSignerBinding({
        walletId: available.key.walletId,
        chainTarget: available.chainTarget,
        keyHandle: available.resolvedKey.keyHandle,
        key: available.key,
        materialActivation: available.materialActivation,
      }),
      auth: available.auth,
    });
    const restoreMetadata = buildPasskeyEcdsaSealedRuntimeRecordFixture({
      manifest: available.capability.manifest,
    }).ecdsaRestore;
    await ensureEcdsaPrfSealPersisted({
      lane,
      authorization: available.authorization,
      thresholdSessionId: `registration-threshold-session-${index}`,
      restoreMetadata,
      required: true,
      sealPersistence: {
        persistSigningSessionSealForThresholdSession: async (input) => {
          calls.push({
            thresholdSessionId: input.thresholdSessionId,
            chainTarget: input.transport.chainTarget,
            restoreChainTarget: input.transport.ecdsaRestore.chainTarget,
          });
          return persisted;
        },
      },
      sealPersistInFlightByMaterialActivation: inFlight,
      resolveSealTransport: async ({ lane: exactLane }) => ({
        curve: 'ecdsa',
        walletId: String(restoreMetadata.authority.walletId),
        chainTarget: exactLane.signer.chainTarget,
        relayerUrl: 'https://relay.example',
      }),
    });
  }

  expect(calls.map((call) => call.thresholdSessionId)).toEqual([
    'registration-threshold-session-0',
    'registration-threshold-session-1',
  ]);
  expect(calls.map((call) => thresholdEcdsaChainTargetKey(call.chainTarget))).toEqual([
    'tempo:42431',
    'evm:eip155:5042002',
  ]);
  expect(calls.map((call) => thresholdEcdsaChainTargetKey(call.restoreChainTarget))).toEqual([
    'tempo:42431',
    'evm:eip155:5042002',
  ]);
});
