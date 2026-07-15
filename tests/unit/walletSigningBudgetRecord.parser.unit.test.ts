import { expect, test } from '@playwright/test';
import { deriveEvmFamilySigningKeySlotId } from '@shared/signing-lanes';
import { parseWalletSigningBudgetSessionRecord } from '../../packages/sdk-server-ts/src/core/ThresholdService/validation';

const evmFamilySigningKeySlotId = deriveEvmFamilySigningKeySlotId({
  walletId: 'wallet-budget-parser',
  signingRootId: 'wallet-budget-parser-root',
  signingRootVersion: 'v1',
});

function exactEd25519BudgetRecord(): Record<string, unknown> {
  return {
    kind: 'wallet_signing_budget_session',
    expiresAtMs: 123_456,
    walletId: 'wallet-budget-parser',
    bindings: {
      kind: 'ed25519_only',
      ed25519: {
        thresholdSessionId: 'threshold-session-budget-parser',
        authorityScope: { kind: 'passkey_rp', rpId: 'wallet.example.test' },
        participantIds: [1, 2],
      },
    },
  };
}

function exactEcdsaBudgetRecord(): Record<string, unknown> {
  return {
    kind: 'wallet_signing_budget_session',
    expiresAtMs: 123_456,
    walletId: 'wallet-budget-parser',
    bindings: {
      kind: 'ecdsa_only',
      ecdsa: [
        {
          thresholdSessionId: 'threshold-session-budget-ecdsa-one',
          evmFamilySigningKeySlotId,
          participantIds: [1, 2, 3],
        },
        {
          thresholdSessionId: 'threshold-session-budget-ecdsa-two',
          evmFamilySigningKeySlotId,
          participantIds: [1, 2, 3],
        },
      ],
    },
  };
}

function acceptsExactCurveBinding(): void {
  expect(parseWalletSigningBudgetSessionRecord(exactEd25519BudgetRecord())).toEqual(
    exactEd25519BudgetRecord(),
  );
}

function acceptsMultipleExactEcdsaSessionBindingsForOneKeySlot(): void {
  const record = exactEcdsaBudgetRecord();
  expect(parseWalletSigningBudgetSessionRecord(record)).toEqual(record);
}

function rejectsLegacyFlatBudgetIdentity(): void {
  const legacy = exactEd25519BudgetRecord();
  delete legacy.bindings;
  legacy.relayerKeyId = 'legacy-relayer-key';
  expect(parseWalletSigningBudgetSessionRecord(legacy)).toBeNull();
}

function rejectsLegacyTopLevelParticipants(): void {
  const legacy = exactEd25519BudgetRecord();
  legacy.participantIds = [1, 2];
  expect(parseWalletSigningBudgetSessionRecord(legacy)).toBeNull();
}

function rejectsMixedFieldsInSingleCurveBranch(): void {
  const invalid = exactEd25519BudgetRecord();
  invalid.bindings = {
    kind: 'ed25519_only',
    ed25519: {
      thresholdSessionId: 'threshold-session-budget-parser',
      authorityScope: { kind: 'passkey_rp', rpId: 'wallet.example.test' },
      participantIds: [1, 2],
    },
    ecdsa: [
      {
        thresholdSessionId: 'threshold-session-substituted-ecdsa',
        evmFamilySigningKeySlotId,
        participantIds: [1, 2, 3],
      },
    ],
  };
  expect(parseWalletSigningBudgetSessionRecord(invalid)).toBeNull();
}

function rejectsScalarEcdsaBinding(): void {
  const invalid = exactEcdsaBudgetRecord();
  invalid.bindings = {
    kind: 'ecdsa_only',
    ecdsa: {
      thresholdSessionId: 'threshold-session-budget-ecdsa-one',
      evmFamilySigningKeySlotId,
      participantIds: [1, 2, 3],
    },
  };
  expect(parseWalletSigningBudgetSessionRecord(invalid)).toBeNull();
}

function rejectsEmptyEcdsaBindings(): void {
  const invalid = exactEcdsaBudgetRecord();
  invalid.bindings = { kind: 'ecdsa_only', ecdsa: [] };
  expect(parseWalletSigningBudgetSessionRecord(invalid)).toBeNull();
}

function rejectsDuplicateEcdsaThresholdSession(): void {
  const invalid = exactEcdsaBudgetRecord();
  invalid.bindings = {
    kind: 'ecdsa_only',
    ecdsa: [
      {
        thresholdSessionId: 'threshold-session-budget-ecdsa-one',
        evmFamilySigningKeySlotId,
        participantIds: [1, 2, 3],
      },
      {
        thresholdSessionId: 'threshold-session-budget-ecdsa-one',
        evmFamilySigningKeySlotId,
        participantIds: [1, 2, 3],
      },
    ],
  };
  expect(parseWalletSigningBudgetSessionRecord(invalid)).toBeNull();
}

function rejectsEcdsaBindingsAcrossKeySlots(): void {
  const invalid = exactEcdsaBudgetRecord();
  invalid.bindings = {
    kind: 'ecdsa_only',
    ecdsa: [
      {
        thresholdSessionId: 'threshold-session-budget-ecdsa-one',
        evmFamilySigningKeySlotId,
        participantIds: [1, 2, 3],
      },
      {
        thresholdSessionId: 'threshold-session-budget-ecdsa-two',
        evmFamilySigningKeySlotId: deriveEvmFamilySigningKeySlotId({
          walletId: 'wallet-budget-parser',
          signingRootId: 'substituted-wallet-budget-parser-root',
          signingRootVersion: 'v1',
        }),
        participantIds: [1, 2, 3],
      },
    ],
  };
  expect(parseWalletSigningBudgetSessionRecord(invalid)).toBeNull();
}

function rejectsEcdsaBindingsAcrossParticipantSets(): void {
  const invalid = exactEcdsaBudgetRecord();
  invalid.bindings = {
    kind: 'ecdsa_only',
    ecdsa: [
      {
        thresholdSessionId: 'threshold-session-budget-ecdsa-one',
        evmFamilySigningKeySlotId,
        participantIds: [1, 2, 3],
      },
      {
        thresholdSessionId: 'threshold-session-budget-ecdsa-two',
        evmFamilySigningKeySlotId,
        participantIds: [1, 2],
      },
    ],
  };
  expect(parseWalletSigningBudgetSessionRecord(invalid)).toBeNull();
}

test('wallet signing budget parser accepts an exact Ed25519 binding', acceptsExactCurveBinding);
test(
  'wallet signing budget parser accepts multiple exact ECDSA sessions for one key slot',
  acceptsMultipleExactEcdsaSessionBindingsForOneKeySlot,
);
test(
  'wallet signing budget parser rejects the legacy flat identity',
  rejectsLegacyFlatBudgetIdentity,
);
test(
  'wallet signing budget parser rejects legacy top-level participants',
  rejectsLegacyTopLevelParticipants,
);
test(
  'wallet signing budget parser rejects mixed fields in a single-curve branch',
  rejectsMixedFieldsInSingleCurveBranch,
);
test('wallet signing budget parser rejects a scalar ECDSA binding', rejectsScalarEcdsaBinding);
test('wallet signing budget parser rejects empty ECDSA bindings', rejectsEmptyEcdsaBindings);
test(
  'wallet signing budget parser rejects duplicate ECDSA threshold sessions',
  rejectsDuplicateEcdsaThresholdSession,
);
test(
  'wallet signing budget parser rejects ECDSA bindings across key slots',
  rejectsEcdsaBindingsAcrossKeySlots,
);
test(
  'wallet signing budget parser rejects ECDSA bindings across participant sets',
  rejectsEcdsaBindingsAcrossParticipantSets,
);
