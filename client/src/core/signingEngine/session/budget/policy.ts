import { SigningSessionIds, type SigningOperationId } from '../operationState/types';

export type PositiveRemainingUses = number & {
  readonly __brand: 'PositiveRemainingUses';
};

export const DEV_DEFAULT_UNLOCK_REMAINING_USES = 3 as const;
const DEFAULT_SERVER_ALLOWANCE_POLICY_VERSION = 'server_environment_policy_v1' as const;

export type DevDefaultBudgetAllowance = {
  kind: 'dev_default_budget_allowance';
  remainingUses: typeof DEV_DEFAULT_UNLOCK_REMAINING_USES;
  source: 'sdk_dev_default';
};

export type ServerEnvironmentBudgetAllowance = {
  kind: 'server_environment_budget_allowance';
  remainingUses: PositiveRemainingUses;
  policyVersion: string;
  source: 'server_environment_policy';
};

export type SigningBudgetAllowance = DevDefaultBudgetAllowance | ServerEnvironmentBudgetAllowance;

export type WalletUnlockBudgetPolicy = {
  kind: 'wallet_unlock_budget_policy';
  allowance: SigningBudgetAllowance;
  scope: 'wallet_unlock';
  operationId?: never;
};

export type SingleOperationStepUpBudgetPolicy = {
  kind: 'single_operation_step_up_budget_policy';
  allowance: { kind: 'single_operation_allowance'; remainingUses: PositiveRemainingUses };
  scope: 'single_operation_step_up';
  operationId: SigningOperationId;
};

export type SigningBudgetPolicy =
  | WalletUnlockBudgetPolicy
  | SingleOperationStepUpBudgetPolicy;

export const DEV_DEFAULT_SIGNING_BUDGET_ALLOWANCE: DevDefaultBudgetAllowance = {
  kind: 'dev_default_budget_allowance',
  remainingUses: DEV_DEFAULT_UNLOCK_REMAINING_USES,
  source: 'sdk_dev_default',
};

function parsePositiveRemainingUses(value: unknown, fieldName: string): PositiveRemainingUses {
  const remainingUses = Math.floor(Number(value) || 0);
  if (!Number.isFinite(remainingUses) || remainingUses <= 0) {
    throw new Error(`[SigningBudgetPolicy] ${fieldName} must be a positive integer`);
  }
  return remainingUses as PositiveRemainingUses;
}

function requirePolicyVersion(value: unknown): string {
  const policyVersion = String(value || '').trim();
  if (!policyVersion) {
    throw new Error('[SigningBudgetPolicy] policyVersion is required');
  }
  return policyVersion;
}

export function parseServerEnvironmentBudgetAllowance(args: {
  remainingUses: unknown;
  policyVersion: unknown;
}): ServerEnvironmentBudgetAllowance {
  return {
    kind: 'server_environment_budget_allowance',
    remainingUses: parsePositiveRemainingUses(args.remainingUses, 'remainingUses'),
    policyVersion: requirePolicyVersion(args.policyVersion),
    source: 'server_environment_policy',
  };
}

export function buildWalletUnlockBudgetPolicy(args?: {
  allowance?: SigningBudgetAllowance;
}): WalletUnlockBudgetPolicy {
  return {
    kind: 'wallet_unlock_budget_policy',
    allowance: args?.allowance ?? DEV_DEFAULT_SIGNING_BUDGET_ALLOWANCE,
    scope: 'wallet_unlock',
  };
}

export function resolveWalletUnlockBudgetPolicyFromRequestedUses(args: {
  requestedRemainingUses: unknown;
  policyVersion?: unknown;
}): WalletUnlockBudgetPolicy | null {
  const normalized = Math.floor(Number(args.requestedRemainingUses) || 0);
  if (!Number.isFinite(normalized) || normalized <= 0) return null;
  const clamped = Math.min(normalized, DEV_DEFAULT_UNLOCK_REMAINING_USES);
  if (clamped === DEV_DEFAULT_UNLOCK_REMAINING_USES && !args.policyVersion) {
    return buildWalletUnlockBudgetPolicy();
  }
  return buildWalletUnlockBudgetPolicy({
    allowance: parseServerEnvironmentBudgetAllowance({
      remainingUses: clamped,
      policyVersion: args.policyVersion ?? DEFAULT_SERVER_ALLOWANCE_POLICY_VERSION,
    }),
  });
}

export function buildSingleOperationStepUpBudgetPolicy(args: {
  operationId: SigningOperationId;
  requiredSignatureUses: unknown;
}): SingleOperationStepUpBudgetPolicy {
  return {
    kind: 'single_operation_step_up_budget_policy',
    allowance: {
      kind: 'single_operation_allowance',
      remainingUses: parsePositiveRemainingUses(
        args.requiredSignatureUses,
        'requiredSignatureUses',
      ),
    },
    scope: 'single_operation_step_up',
    operationId: args.operationId,
  };
}

export function resolvePostExhaustionStepUpBudgetPolicy(args: {
  operationId: SigningOperationId;
  requiredSignatureUses: unknown;
}): SingleOperationStepUpBudgetPolicy {
  return buildSingleOperationStepUpBudgetPolicy({
    operationId: args.operationId,
    requiredSignatureUses: args.requiredSignatureUses,
  });
}

export function resolveSigningBudgetPolicyRemainingUses(policy: SigningBudgetPolicy): number {
  switch (policy.kind) {
    case 'wallet_unlock_budget_policy':
      return policy.allowance.remainingUses;
    case 'single_operation_step_up_budget_policy':
      return policy.allowance.remainingUses;
  }
  policy satisfies never;
  throw new Error('[SigningBudgetPolicy] unsupported signing budget policy');
}

export function normalizeStepUpOperationId(operationId: unknown): SigningOperationId {
  return SigningSessionIds.signingOperation(
    String(operationId || '').trim() || 'post-exhaustion-step-up',
  );
}
