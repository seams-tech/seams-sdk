import type { AccountId } from '@/core/types/accountIds';
import type { SigningGrantId } from '../operationState/types';
import type {
  TrustedWalletBudgetStatus,
  WalletBudgetMaterialStatus,
  WalletBudgetPolicyHint,
  WalletBudgetProjection,
  WalletBudgetProjectionState,
  WalletBudgetUnknown,
} from './budgetProjection';

declare const walletId: AccountId;
declare const signingGrantId: SigningGrantId;
declare const activeStatus: Extract<TrustedWalletBudgetStatus, { status: 'active' }>;
declare const unknown: WalletBudgetUnknown;

const trustedStatusWithSigningGrant: Extract<TrustedWalletBudgetStatus, { status: 'active' }> = {
  source: 'server_status',
  signingGrantId,
  status: 'active',
  remainingUses: 1,
  availableUses: 1,
};
void trustedStatusWithSigningGrant;

const invalidTrustedStatusWithSessionId: Extract<TrustedWalletBudgetStatus, { status: 'active' }> =
  {
    source: 'server_status',
    // @ts-expect-error budget projection state carries signingGrantId internally.
    sessionId: signingGrantId,
    status: 'active',
    remainingUses: 1,
    availableUses: 1,
  };
void invalidTrustedStatusWithSessionId;

const unknownWithSigningGrant: WalletBudgetUnknown = {
  source: 'budget_unknown',
  signingGrantId,
  status: 'budget_unknown',
  reason: 'status_unavailable',
};
void unknownWithSigningGrant;

const invalidUnknownWithSessionId: WalletBudgetUnknown = {
  source: 'budget_unknown',
  // @ts-expect-error budget unknown state carries signingGrantId internally.
  sessionId: signingGrantId,
  status: 'budget_unknown',
  reason: 'status_unavailable',
};
void invalidUnknownWithSessionId;

const policyHintWithSigningGrant: WalletBudgetPolicyHint = {
  signingGrantId,
  remainingUses: 1,
};
void policyHintWithSigningGrant;

const invalidPolicyHintWithSessionId: WalletBudgetPolicyHint = {
  // @ts-expect-error budget policy hints carry signingGrantId internally.
  sessionId: signingGrantId,
  remainingUses: 1,
};
void invalidPolicyHintWithSessionId;

const materialStatusWithSigningGrant: WalletBudgetMaterialStatus = {
  signingGrantId: 'signing-grant-1',
  state: 'available',
};
void materialStatusWithSigningGrant;

const invalidMaterialStatusWithSessionId: WalletBudgetMaterialStatus = {
  // @ts-expect-error budget material state carries signingGrantId internally.
  sessionId: 'signing-grant-1',
  state: 'available',
};
void invalidMaterialStatusWithSessionId;

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
  signingGrantId,
  state: knownProjectionState,
  reservationsByOperationId: new Map(),
  localReservedUses: 0,
};
void projection;

export {};
