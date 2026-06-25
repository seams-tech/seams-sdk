import { toAccountId } from '@/core/types/accountIds';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { nearEd25519SigningKeyIdFromString } from '@shared/utils/registrationIntent';
import { buildNearTransactionSigningLane } from './lanes';
import { SigningOperationIntent, SigningSessionIds } from './types';
import {
  buildFreshStepUpRequired,
  buildFreshStepUpSatisfied,
  buildFreshStepUpSatisfiedForAdmission,
} from './stepUpFreshness';
import { exactSigningLaneIdentityFromSelectedLane } from '../identity/exactSigningLaneIdentity';
import { toRpId } from '../identity/evmFamilyEcdsaIdentity';
import {
  recordPreparedTransactionBudgetAdmissionFromFreshness,
  signPreparedTransactionOperation,
  type BudgetAdmittedOperation,
  type ReauthAnchorIdentity,
  type TransactionBudgetAdmission,
} from './transactionState';

const accountId = toAccountId('transaction-state.testnet');
const walletId = toWalletId('frost-vermillion-k7p9m2');
const nearEd25519SigningKeyId = nearEd25519SigningKeyIdFromString('scope-frost-vermillion-k7p9m2');
const lane = buildNearTransactionSigningLane({
  walletId,
  nearAccountId: accountId,
  nearEd25519SigningKeyId,
  signerSlot: 1,
  auth: {
    kind: 'passkey',
      rpId: toRpId('localhost'),
    credentialIdB64u: 'credential-id',
  },
  signingGrantId: SigningSessionIds.signingGrant('wallet-session-1'),
  thresholdSessionId: SigningSessionIds.thresholdEd25519Session('threshold-session-1'),
  storageSource: 'login',
});
const preparedOperation = {
  intent: {
    curve: 'ed25519',
    chain: 'near',
    walletId,
    authSelectionPolicy: { kind: 'explicit', authMethod: 'passkey' },
    operationUsesNeeded: 1,
  },
  lane,
  readiness: {
    status: 'ready',
    remainingUses: 1,
    expiresAtMs: 1_900_000_000_000,
  },
} satisfies Parameters<typeof recordPreparedTransactionBudgetAdmissionFromFreshness>[0];
const budgetAdmission = {
  budgetIdentity: {
    signingGrantId: String(lane.signingGrantId),
    projectionVersion: 'projection-1',
    status: {
      sessionId: String(lane.signingGrantId),
      status: 'active',
      projectionVersion: 'projection-1',
      remainingUses: 1,
      expiresAtMs: 1_900_000_000_000,
    },
  },
} satisfies TransactionBudgetAdmission;
const satisfied = buildFreshStepUpSatisfied({
  walletId,
  operationId: SigningSessionIds.signingOperation('operation-1'),
  operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
  laneIdentity: exactSigningLaneIdentityFromSelectedLane(lane),
  projection: { kind: 'known', version: 'projection-1' },
  expiry: { kind: 'known', expiresAtMs: 1_900_000_000_000 },
  provenance: {
    kind: 'trusted_server_budget_status',
    projectionVersion: 'projection-1',
    observedAtMs: 1,
  },
  remainingUses: 1,
});
const admissionFreshness = buildFreshStepUpSatisfiedForAdmission(satisfied);

const budgetLifecycle = recordPreparedTransactionBudgetAdmissionFromFreshness(
  preparedOperation,
  budgetAdmission,
  admissionFreshness,
);
void budgetLifecycle;

const requiredFreshness = buildFreshStepUpRequired({
  walletId,
  operationId: SigningSessionIds.signingOperation('operation-1'),
  operationFingerprint: SigningSessionIds.signingOperationFingerprint('fingerprint-1'),
  laneIdentity: exactSigningLaneIdentityFromSelectedLane(lane),
  projection: { kind: 'known', version: 'projection-1' },
  expiry: { kind: 'known', expiresAtMs: 1_900_000_000_000 },
  provenance: {
    kind: 'trusted_server_budget_status',
    projectionVersion: 'projection-1',
    observedAtMs: 1,
  },
  reason: 'threshold_session_exhausted',
});

recordPreparedTransactionBudgetAdmissionFromFreshness(
  preparedOperation,
  budgetAdmission,
  // @ts-expect-error admission builder requires satisfied-for-admission freshness.
  requiredFreshness,
);

// @ts-expect-error exhausted freshness cannot enter signing execution.
void signPreparedTransactionOperation(requiredFreshness, {}, { sign: async () => ({}) });

declare const reauthAnchor: ReauthAnchorIdentity;
// @ts-expect-error reauth anchors are planning inputs, not signing execution material.
const invalidBudgetAdmittedOperation: BudgetAdmittedOperation = reauthAnchor;
void invalidBudgetAdmittedOperation;

void SigningOperationIntent.TransactionSign;
