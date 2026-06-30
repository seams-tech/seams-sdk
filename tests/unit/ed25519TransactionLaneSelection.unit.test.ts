import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import type {
  AvailableEd25519SigningLane,
  AvailableSigningLanes,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import { selectTransactionLane } from '@/core/signingEngine/session/identity/selectLane';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';

const walletId = toWalletId('cedar-zenith-pghgtw');
const nearAccountId = toAccountId('cedar-zenith-pghgtw.testnet');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString(
  'ed25519ks_cedar-zenith-pghgtw',
);
const auth = {
  kind: 'passkey',
  rpId: toRpId('localhost'),
  credentialIdB64u: 'credential-ed25519-transaction-selection',
} as const;

function ed25519Lane(input: {
  source: 'runtime_session_record' | 'durable_sealed_record';
  state: 'ready' | 'restorable';
  includeMaterial: boolean;
}): AvailableEd25519SigningLane {
  return {
    auth,
    curve: 'ed25519',
    chain: 'near',
    walletId,
    nearAccountId,
    nearEd25519SigningKeyId,
    signerSlot: 1,
    state: input.state,
    source: input.source,
    signingGrantId: 'wss_ed25519_transaction_selection',
    thresholdSessionId: 'tsess_ed25519_transaction_selection',
    remainingUses: 3,
    expiresAtMs: Date.now() + 60_000,
    updatedAtMs: Date.now(),
    ...(input.includeMaterial
      ? {
          ed25519WorkerMaterialBindingDigest: 'ed25519-material-binding-digest',
          materialKeyId: 'ed25519-material-key-id',
        }
      : {}),
  };
}

function availableSigningLanes(
  near: AvailableEd25519SigningLane[],
): AvailableSigningLanes {
  return {
    walletId,
    generation: 1,
    ecdsa: {
      targets: [],
      lanesByTarget: {},
      candidatesByTarget: {},
    },
    lanes: {
      ed25519: {
        near: near[0] || { curve: 'ed25519', chain: 'near', state: 'missing' },
      },
    },
    candidates: {
      ed25519: {
        near,
      },
    },
  };
}

test('NEAR Ed25519 transaction selection ignores runtime lanes without worker material', () => {
  const runtimeWithoutMaterial = ed25519Lane({
    source: 'runtime_session_record',
    state: 'ready',
    includeMaterial: false,
  });
  const durableWithMaterial = ed25519Lane({
    source: 'durable_sealed_record',
    state: 'restorable',
    includeMaterial: true,
  });

  const selected = selectTransactionLane({
    intent: {
      walletId,
      curve: 'ed25519',
      chain: 'near',
      authSelectionPolicy: { kind: 'any' },
      operationUsesNeeded: 1,
    },
    availableLanes: availableSigningLanes([runtimeWithoutMaterial, durableWithMaterial]),
    currentRuntimeLane: runtimeWithoutMaterial,
  });

  expect(selected).toMatchObject({
    ok: true,
    availableLane: {
      source: 'durable_sealed_record',
      ed25519WorkerMaterialBindingDigest: 'ed25519-material-binding-digest',
      materialKeyId: 'ed25519-material-key-id',
    },
  });
});
