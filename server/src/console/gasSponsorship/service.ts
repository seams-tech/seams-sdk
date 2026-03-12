import { ConsoleGasSponsorshipError } from './errors';
import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipPolicyProjection,
  ConsoleGasSponsorshipSpendCap,
} from './types';
import {
  isConsoleGasSponsorshipPolicyRules,
  type ConsolePolicy,
  type ConsolePoliciesContext,
  type ConsolePolicyService,
} from '../policies';

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
    selector: entry.selector,
  }));
}

function cloneAllowedChainIds(input: number[]): number[] {
  return [...input];
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
  return {
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
    allowedChainIds: cloneAllowedChainIds(rules.allowedChainIds),
    callMode: rules.callMode,
    spendCap: cloneSpendCap(rules.spendCap),
    allowedCalls: cloneAllowedCalls(rules.allowedCalls),
    telemetry: {
      sponsoredTransactionCount: 0,
      failedTransactionCount: 0,
      spendMinor: 0,
      budgetUtilizationPct: 0,
    },
    createdAt: policy.createdAt || toIso(new Date(0)),
    updatedAt: policy.updatedAt || policy.createdAt || toIso(new Date(0)),
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
