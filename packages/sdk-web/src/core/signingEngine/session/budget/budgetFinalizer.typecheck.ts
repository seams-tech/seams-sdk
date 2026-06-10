import type {
  BudgetFinalizationSpend,
  SigningSessionBudget,
  SigningSessionPreparedBudgetIdentity,
} from './budget';
import type {
  CreateSigningSessionBudgetFinalizerArgs,
  SigningSessionBudgetFinalizerNoBudgetArgs,
  SigningSessionBudgetFinalizerWithBudgetArgs,
} from './budgetFinalizer';

declare const signingSessionBudget: SigningSessionBudget;
declare const budgetIdentity: SigningSessionPreparedBudgetIdentity;
declare const finalization: BudgetFinalizationSpend;

const finalizerWithBudget: SigningSessionBudgetFinalizerWithBudgetArgs = {
  budgetMode: 'with_budget',
  signingSessionBudget,
  budgetIdentity,
  finalization,
};
void finalizerWithBudget;

// @ts-expect-error with_budget finalizers require a budget instance.
const finalizerWithBudgetMissingBudget: SigningSessionBudgetFinalizerWithBudgetArgs = {
  budgetMode: 'with_budget',
  budgetIdentity,
  finalization,
};
void finalizerWithBudgetMissingBudget;

const finalizerWithoutBudget: SigningSessionBudgetFinalizerNoBudgetArgs = {
  budgetMode: 'no_budget',
  budgetIdentity,
  finalization,
};
void finalizerWithoutBudget;

// @ts-expect-error no_budget finalizers reject a budget instance.
const finalizerNoBudgetWithBudget: CreateSigningSessionBudgetFinalizerArgs = {
  budgetMode: 'no_budget',
  budgetIdentity,
  finalization,
  signingSessionBudget,
};
void finalizerNoBudgetWithBudget;

export {};
