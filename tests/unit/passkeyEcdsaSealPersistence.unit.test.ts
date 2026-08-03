import { expect, test } from '@playwright/test';
import { canonicalEcdsaAvailableLane } from './helpers/availableSigningLanes.fixtures';
import {
  buildEvmFamilyEcdsaSignerBinding,
  exactEcdsaSigningLaneIdentity,
} from '@/core/signingEngine/session/identity/exactSigningLaneIdentity';
import { ensureEcdsaPrfSealPersisted } from '@/core/signingEngine/session/passkey/runtime';
import type { WarmSessionSealAndPersistResult } from '@/core/types/secure-confirm-worker';
import type { ThresholdEcdsaChainTarget } from '@/core/signingEngine/interfaces/ecdsaChainTarget';

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
    sealPersistence: {
      persistSigningSessionSealForThresholdSession: async (input) => {
        calls.push({ thresholdSessionId: input.thresholdSessionId });
        return persisted;
      },
    },
    sealPersistInFlightByMaterialActivation: new Map(),
    resolveSealTransport: async () => ({
      curve: 'ecdsa',
      chainTarget,
      relayerUrl: 'https://relay.example',
    }),
  });

  expect(calls).toEqual([{ thresholdSessionId: 'threshold-session-real' }]);
  expect(calls[0]?.thresholdSessionId).not.toBe(available.materialActivation.activationId);
});
