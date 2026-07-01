import { expect, test } from '@playwright/test';
import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import {
  ed25519AvailableLaneIdentityKey,
  type AvailableEd25519SigningLane,
  type AvailableSigningLanes,
} from '@/core/signingEngine/session/availability/availableSigningLanes';
import {
  listNearEd25519TransactionReadyLanes,
  selectTransactionLane,
  toNearEd25519TransactionReadyLane,
} from '@/core/signingEngine/session/identity/selectLane';
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
  state: 'ready' | 'restorable' | 'deferred' | 'expired' | 'exhausted';
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
  });

  expect(selected).toMatchObject({
    ok: true,
    availableLane: {
      state: 'restorable',
      signingGrantId: 'wss_ed25519_transaction_selection',
      thresholdSessionId: 'tsess_ed25519_transaction_selection',
    },
  });
  if (!selected.ok) throw new Error('expected a selected Ed25519 transaction lane');
  expect(selected.selectionCandidate).toMatchObject({
    kind: 'near_ed25519_transaction_ready_lane',
    material: {
      kind: 'sealed_worker_material',
      identity: {
        bindingDigest: 'ed25519-material-binding-digest',
        materialKeyId: 'ed25519-material-key-id',
      },
    },
  });
});

test('NEAR Ed25519 transaction ready lane carries exact lane and worker material', () => {
  const lane = ed25519Lane({
    source: 'runtime_session_record',
    state: 'ready',
    includeMaterial: true,
  });

  const readyLane = toNearEd25519TransactionReadyLane(lane);

  expect(readyLane).toMatchObject({
    kind: 'near_ed25519_transaction_ready_lane',
    selectedLane: {
      kind: 'selected_lane',
      curve: 'ed25519',
      chain: 'near',
      signingGrantId: 'wss_ed25519_transaction_selection',
      thresholdSessionId: 'tsess_ed25519_transaction_selection',
    },
    material: {
      kind: 'loaded_worker_material',
      identity: {
        bindingDigest: 'ed25519-material-binding-digest',
        materialKeyId: 'ed25519-material-key-id',
      },
    },
  });
  expect(readyLane?.authorityKey).toBe(ed25519AvailableLaneIdentityKey(lane));
});

test('NEAR Ed25519 transaction ready lanes model restorable lanes as sealed material', () => {
  const durableRestorable = ed25519Lane({
    source: 'durable_sealed_record',
    state: 'restorable',
    includeMaterial: true,
  });
  const deferredWithMaterial = ed25519Lane({
    source: 'durable_sealed_record',
    state: 'deferred',
    includeMaterial: true,
  });

  const readyLanes = listNearEd25519TransactionReadyLanes([
    durableRestorable,
    deferredWithMaterial,
  ]);

  expect(readyLanes).toHaveLength(1);
  expect(readyLanes[0]?.availableLane).toMatchObject({
    state: 'restorable',
    signingGrantId: 'wss_ed25519_transaction_selection',
    thresholdSessionId: 'tsess_ed25519_transaction_selection',
  });
  expect(readyLanes[0]?.material).toMatchObject({
    kind: 'sealed_worker_material',
    identity: {
      bindingDigest: 'ed25519-material-binding-digest',
      materialKeyId: 'ed25519-material-key-id',
    },
  });
  expect(toNearEd25519TransactionReadyLane(deferredWithMaterial)).toBeNull();
});

test('NEAR Ed25519 transaction selection accepts restorable runtime lanes with worker material', () => {
  const runtimeRestorable = ed25519Lane({
    source: 'runtime_session_record',
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
    availableLanes: availableSigningLanes([runtimeRestorable]),
  });

  expect(selected).toMatchObject({
    ok: true,
    lane: {
      curve: 'ed25519',
      chain: 'near',
      signingGrantId: 'wss_ed25519_transaction_selection',
      thresholdSessionId: 'tsess_ed25519_transaction_selection',
    },
    availableLane: {
      state: 'restorable',
      signingGrantId: 'wss_ed25519_transaction_selection',
      thresholdSessionId: 'tsess_ed25519_transaction_selection',
    },
  });
  if (!selected.ok) throw new Error('expected a selected Ed25519 transaction lane');
  expect(selected.selectionCandidate.material.kind).toBe('sealed_worker_material');
});

test('NEAR Ed25519 transaction ready lane rejects lanes without worker material', () => {
  const lane = ed25519Lane({
    source: 'runtime_session_record',
    state: 'ready',
    includeMaterial: false,
  });

  expect(toNearEd25519TransactionReadyLane(lane)).toBeNull();
});

test('NEAR Ed25519 available lane identity includes signer identity', () => {
  const base = ed25519Lane({
    source: 'runtime_session_record',
    state: 'ready',
    includeMaterial: true,
  });

  expect(ed25519AvailableLaneIdentityKey(base)).not.toBe(
    ed25519AvailableLaneIdentityKey({
      ...base,
      nearAccountId: toAccountId('other-ed25519-account.testnet'),
    }),
  );
  expect(ed25519AvailableLaneIdentityKey(base)).not.toBe(
    ed25519AvailableLaneIdentityKey({
      ...base,
      nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('ed25519ks_other-key'),
    }),
  );
  expect(ed25519AvailableLaneIdentityKey(base)).not.toBe(
    ed25519AvailableLaneIdentityKey({
      ...base,
      signerSlot: 2,
    }),
  );
});
