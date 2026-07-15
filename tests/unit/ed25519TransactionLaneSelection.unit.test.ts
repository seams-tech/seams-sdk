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
  toNearEd25519TransactionSelectableLane,
  toNearEd25519TransactionReadyLane,
} from '@/core/signingEngine/session/identity/selectLane';
import { toRpId } from '@/core/signingEngine/session/identity/evmFamilyEcdsaIdentity';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { parseSignerSlot } from '@shared/utils/signerSlot';

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

function signerSlot(value: number) {
  const parsed = parseSignerSlot(value);
  if (parsed === null) throw new Error(`Invalid signer slot fixture: ${value}`);
  return parsed;
}

function ed25519Lane(input: {
  source: 'runtime_session_record' | 'durable_sealed_record';
  state: 'ready' | 'restorable' | 'deferred' | 'expired' | 'exhausted';
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

test('NEAR Ed25519 transaction ready lane carries exact lane authority', () => {
  const lane = ed25519Lane({
    source: 'runtime_session_record',
    state: 'ready',
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
  });
  expect(readyLane?.authorityKey).toBe(ed25519AvailableLaneIdentityKey(lane));
});

test('NEAR Ed25519 transaction ready lanes admit restorable lanes and reject deferred lanes', () => {
  const durableRestorable = ed25519Lane({
    source: 'durable_sealed_record',
    state: 'restorable',
  });
  const deferred = ed25519Lane({
    source: 'durable_sealed_record',
    state: 'deferred',
  });

  const readyLanes = listNearEd25519TransactionReadyLanes([durableRestorable, deferred]);

  expect(readyLanes).toHaveLength(1);
  expect(readyLanes[0]?.availableLane).toMatchObject({
    state: 'restorable',
    signingGrantId: 'wss_ed25519_transaction_selection',
    thresholdSessionId: 'tsess_ed25519_transaction_selection',
  });
  expect(toNearEd25519TransactionReadyLane(deferred)).toBeNull();
});

test('NEAR Ed25519 transaction selection carries expired durable lanes as reauth anchors', () => {
  const expiredDurableLane = {
    ...ed25519Lane({
      source: 'durable_sealed_record',
      state: 'expired',
    }),
    expiresAtMs: Date.now() - 1_000,
  };

  const selected = selectTransactionLane({
    intent: {
      walletId,
      curve: 'ed25519',
      chain: 'near',
      signerSelection: { kind: 'near_account', nearAccountId },
      authSelectionPolicy: { kind: 'any' },
      operationUsesNeeded: 1,
    },
    availableLanes: availableSigningLanes([expiredDurableLane]),
  });

  expect(toNearEd25519TransactionReadyLane(expiredDurableLane)).toBeNull();
  expect(toNearEd25519TransactionSelectableLane(expiredDurableLane)).toMatchObject({
    kind: 'near_ed25519_transaction_reauth_lane',
    availableLane: {
      state: 'expired',
      signingGrantId: 'wss_ed25519_transaction_selection',
      thresholdSessionId: 'tsess_ed25519_transaction_selection',
    },
  });
  expect(selected).toMatchObject({
    ok: true,
    availableLane: {
      state: 'expired',
      signingGrantId: 'wss_ed25519_transaction_selection',
      thresholdSessionId: 'tsess_ed25519_transaction_selection',
    },
    selectionCandidate: {
      kind: 'near_ed25519_transaction_reauth_lane',
    },
  });
});

test('NEAR Ed25519 transaction selection accepts restorable runtime lanes', () => {
  const runtimeRestorable = ed25519Lane({
    source: 'runtime_session_record',
    state: 'restorable',
  });

  const selected = selectTransactionLane({
    intent: {
      walletId,
      curve: 'ed25519',
      chain: 'near',
      signerSelection: { kind: 'near_account', nearAccountId },
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
});

test('NEAR Ed25519 available lane identity includes signer identity', () => {
  const base = ed25519Lane({
    source: 'runtime_session_record',
    state: 'ready',
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

test('NEAR Ed25519 transaction selection binds the requested account before resolving a lane', () => {
  const first = ed25519Lane({ source: 'runtime_session_record', state: 'ready' });
  const requestedNearAccountId = toAccountId('second-ed25519-account.testnet');
  const second = {
    ...first,
    nearAccountId: requestedNearAccountId,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('ed25519ks_second-key'),
    signerSlot: 2,
    signingGrantId: 'wss_ed25519_transaction_selection_second',
    thresholdSessionId: 'tsess_ed25519_transaction_selection_second',
  } satisfies AvailableEd25519SigningLane;

  const selected = selectTransactionLane({
    intent: {
      walletId,
      curve: 'ed25519',
      chain: 'near',
      signerSelection: { kind: 'near_account', nearAccountId: requestedNearAccountId },
      authSelectionPolicy: { kind: 'any' },
      operationUsesNeeded: 1,
    },
    availableLanes: availableSigningLanes([first, second]),
  });

  expect(selected).toMatchObject({
    ok: true,
    candidate: {
      nearAccountId: requestedNearAccountId,
      signerSlot: 2,
      thresholdSessionId: 'tsess_ed25519_transaction_selection_second',
    },
  });
});

test('NEAR Ed25519 transaction selection binds an explicit signer slot within one account', () => {
  const first = ed25519Lane({ source: 'runtime_session_record', state: 'ready' });
  const second = {
    ...first,
    nearEd25519SigningKeyId: nearEd25519SigningKeyIdFromString('ed25519ks_same-account-slot-two'),
    signerSlot: 2,
    signingGrantId: 'wss_ed25519_transaction_selection_slot_two',
    thresholdSessionId: 'tsess_ed25519_transaction_selection_slot_two',
  } satisfies AvailableEd25519SigningLane;

  const selected = selectTransactionLane({
    intent: {
      walletId,
      curve: 'ed25519',
      chain: 'near',
      signerSelection: { kind: 'signer_slot', nearAccountId, signerSlot: signerSlot(2) },
      authSelectionPolicy: { kind: 'any' },
      operationUsesNeeded: 1,
    },
    availableLanes: availableSigningLanes([first, second]),
  });

  expect(selected).toMatchObject({
    ok: true,
    candidate: {
      nearAccountId,
      signerSlot: 2,
      thresholdSessionId: 'tsess_ed25519_transaction_selection_slot_two',
    },
  });
});
