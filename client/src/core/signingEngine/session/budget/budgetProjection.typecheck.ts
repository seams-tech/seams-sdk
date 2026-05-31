import type { AccountId } from '@/core/types/accountIds';
import type { WalletSigningSessionId } from '../operationState/types';
import type {
  TrustedWalletBudgetStatus,
  WalletBudgetProjection,
  WalletBudgetProjectionState,
  WalletBudgetUnknown,
} from './budgetProjection';

declare const walletId: AccountId;
declare const walletSigningSessionId: WalletSigningSessionId;
declare const activeStatus: Extract<TrustedWalletBudgetStatus, { status: 'active' }>;
declare const unknown: WalletBudgetUnknown;

const knownProjectionState: WalletBudgetProjectionState = {
  kind: 'known',
  trustedStatus: activeStatus,
  effectiveRemainingUses: 1,
  projectionVersion: 'projection-1',
};
void knownProjectionState;

// @ts-expect-error known budget projection requires effectiveRemainingUses.
const knownProjectionWithoutEffectiveUses: WalletBudgetProjectionState = {
  kind: 'known',
  trustedStatus: activeStatus,
  projectionVersion: 'projection-1',
};
void knownProjectionWithoutEffectiveUses;

// @ts-expect-error unknown budget projection rejects trusted status.
const unknownProjectionWithTrustedStatus: WalletBudgetProjectionState = {
  kind: 'unknown',
  unknown,
  trustedStatus: activeStatus,
};
void unknownProjectionWithTrustedStatus;

const projection: WalletBudgetProjection = {
  walletId,
  walletSigningSessionId,
  state: knownProjectionState,
  reservationsByOperationId: new Map(),
  localReservedUses: 0,
};
void projection;

export {};
