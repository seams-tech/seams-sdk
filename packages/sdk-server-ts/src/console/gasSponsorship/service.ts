import { ConsoleGasSponsorshipError } from './errors';
import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipAllowedDelegateAction,
  ConsoleGasSponsorshipPolicyProjection,
  ConsoleGasSponsorshipSpendCap,
} from './types';
import { isConsoleGasSponsorshipPolicyRules } from '../policies/rules';
import type { ConsolePoliciesContext, ConsolePolicyService } from '../policies/service';
import type { ConsolePolicy } from '../policies/types';

function toIso(date: Date): string {
  return date.toISOString();
}

function cloneSpendCap(input: ConsoleGasSponsorshipSpendCap): ConsoleGasSponsorshipSpendCap {
  return {
    mode: input.mode,
    period: input.period,
    capsByChain: input.capsByChain.map((entry) => ({
      chainId: entry.chainId,
      capMinor: entry.capMinor,
    })),
  };
}

function cloneAllowedCalls(
  input: ConsoleGasSponsorshipAllowedCall[],
): ConsoleGasSponsorshipAllowedCall[] {
  return input.map((entry) => ({
    chainId: entry.chainId,
    to: entry.to,
    functionSignature: entry.functionSignature,
    selector: entry.selector,
    maxGasLimit: entry.maxGasLimit,
    maxValueWei: entry.maxValueWei,
  }));
}

function cloneAllowedDelegateActions(
  input: ConsoleGasSponsorshipAllowedDelegateAction[],
): ConsoleGasSponsorshipAllowedDelegateAction[] {
  return input.map((entry) => ({
    receiverId: entry.receiverId,
    methods: [...entry.methods],
    maxDepositYocto: entry.maxDepositYocto,
    allowTransfers: entry.allowTransfers,
  }));
}

function deriveAllowedChainIds(input: ConsoleGasSponsorshipAllowedCall[]): number[] {
  return Array.from(new Set(input.map((entry) => entry.chainId)));
}

async function requireScopePolicyName(
  policies: ConsolePolicyService,
  ctx: ConsolePoliciesContext,
  scopePolicyId: string | null,
): Promise<string | null> {
  if (!scopePolicyId) return null;
  const policy = await policies.getPolicy(ctx, scopePolicyId);
  if (!policy) {
    throw new ConsoleGasSponsorshipError(
      'policy_not_found',
      404,
      `Policy ${scopePolicyId} was not found`,
    );
  }
  return String(policy.name || '').trim() || policy.id;
}

export async function projectConsoleGasSponsorshipPolicyProjection(
  policies: ConsolePolicyService,
  ctx: ConsolePoliciesContext,
  policy: ConsolePolicy,
): Promise<ConsoleGasSponsorshipPolicyProjection | null> {
  if (policy.kind !== 'GAS_SPONSORSHIP') return null;
  if (!isConsoleGasSponsorshipPolicyRules(policy.rules)) {
    throw new ConsoleGasSponsorshipError(
      'invalid_policy_rules',
      500,
      `Gas sponsorship policy ${policy.id} has non-gas rules`,
    );
  }
  const rules = policy.rules;
  const projectionBase = {
    id: policy.id,
    orgId: policy.orgId,
    scopeType: rules.scopeType,
    projectId: rules.projectId,
    environmentId: rules.environmentId,
    scopePolicyId: rules.scopePolicyId,
    scopePolicyName: await requireScopePolicyName(policies, ctx, rules.scopePolicyId),
    walletSegmentId: rules.walletSegmentId,
    name: policy.name,
    templateId: rules.templateId,
    networkClass: rules.networkClass,
    enabled: rules.enabled,
    spendCap: cloneSpendCap(rules.spendCap),
    telemetry: {
      sponsoredTransactionCount: 0,
      failedTransactionCount: 0,
      spendMinor: 0,
      budgetUtilizationPct: 0,
    },
    createdAt: policy.createdAt || toIso(new Date(0)),
    updatedAt: policy.updatedAt || policy.createdAt || toIso(new Date(0)),
  } as const;
  if (rules.kind === 'near_delegate') {
    return {
      ...projectionBase,
      kind: 'near_delegate',
      executionMode: 'near_delegate',
      allowedDelegateActions: cloneAllowedDelegateActions(rules.allowedDelegateActions),
    };
  }
  const allowedCalls = cloneAllowedCalls(rules.allowedCalls);
  return {
    ...projectionBase,
    kind: 'evm_call',
    executionMode: 'evm_eoa',
    allowedChainIds: deriveAllowedChainIds(allowedCalls),
    allowedCalls,
  };
}

export function sortConsoleGasSponsorshipPolicyProjections(
  projections: ConsoleGasSponsorshipPolicyProjection[],
): ConsoleGasSponsorshipPolicyProjection[] {
  return [...projections].sort((a, b) => {
    const updatedCompare = b.updatedAt.localeCompare(a.updatedAt);
    if (updatedCompare !== 0) return updatedCompare;
    return b.createdAt.localeCompare(a.createdAt);
  });
}
