import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipCallMode,
  ConsoleGasSponsorshipPolicyProjection,
  ConsoleGasSponsorshipSpendCap,
} from './types';
import { ConsoleGasSponsorshipError } from './errors';
import { projectConsoleGasSponsorshipPolicyProjection } from './service';
import type {
  ConsoleGasSponsorshipPolicyRulesInput,
  ConsolePolicyService,
} from '../policies';

export const TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID = 'tempo_testnet_onboarding';
export const TEMPO_TESTNET_ONBOARDING_POLICY_NAME = 'Tempo Testnet Onboarding';
export const TEMPO_TESTNET_CHAIN_ID = 42_431;
export const TEMPO_DRIP_SELECTOR = '0x428dc451';
export const DEFAULT_TEMPO_ONBOARDING_CONTRACT =
  '0xbb85080E6953f25197ec68798360667140EbAf4b' as `0x${string}`;

export interface ResolvedSponsoredCallPolicy {
  policyId: string;
  policyName: string;
  scopePolicyId: string | null;
  scopePolicyName: string | null;
  templateId: string | null;
  networkClass: 'ANY' | 'TESTNET' | 'MAINNET';
  allowedChainIds: number[];
  callMode: ConsoleGasSponsorshipCallMode;
  allowedCalls: ConsoleGasSponsorshipAllowedCall[];
  spendCap: ConsoleGasSponsorshipSpendCap;
  scopeType: ConsoleGasSponsorshipPolicyProjection['scopeType'];
  projectId: string | null;
  environmentId: string | null;
}

export function buildTempoTestnetOnboardingGasPolicyRules(input: {
  projectId?: string | null;
  environmentId: string;
  contractAddress: `0x${string}`;
}): ConsoleGasSponsorshipPolicyRulesInput {
  return {
    scopeType: 'ENVIRONMENT',
    ...(input.projectId ? { projectId: input.projectId } : {}),
    environmentId: input.environmentId,
    templateId: TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
    networkClass: 'TESTNET',
    enabled: true,
    allowedChainIds: [TEMPO_TESTNET_CHAIN_ID],
    callMode: 'ALLOWLIST',
    spendCap: {
      mode: 'NONE',
      period: 'MONTHLY',
      capsByChain: [],
    },
    allowedCalls: [
      {
        chainId: TEMPO_TESTNET_CHAIN_ID,
        to: input.contractAddress,
        selector: TEMPO_DRIP_SELECTOR,
      },
    ],
  };
}

async function listProjectedGasPolicies(input: {
  policies: ConsolePolicyService;
  ctx: { orgId: string; actorUserId: string; roles: string[] };
}): Promise<ConsoleGasSponsorshipPolicyProjection[]> {
  return (
    await Promise.all(
      (await input.policies.listPolicies(input.ctx, { kind: 'GAS_SPONSORSHIP' })).map(
        async (policy) =>
          await projectConsoleGasSponsorshipPolicyProjection(input.policies, input.ctx, policy),
      ),
    )
  ).filter((projection): projection is ConsoleGasSponsorshipPolicyProjection => projection !== null);
}

export async function ensureTempoTestnetOnboardingPolicyForEnvironment(input: {
  policies: ConsolePolicyService;
  ctx: { orgId: string; actorUserId: string; roles: string[] };
  projectId?: string | null;
  environmentId: string;
  contractAddress: `0x${string}`;
}): Promise<ConsoleGasSponsorshipPolicyProjection> {
  const existing = await listProjectedGasPolicies({
    policies: input.policies,
    ctx: input.ctx,
  });
  const matched = existing.find((policy) => policy.environmentId === input.environmentId);
  if (matched && matched.templateId === TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID) return matched;

  const created = await input.policies.createPolicy(input.ctx, {
    kind: 'GAS_SPONSORSHIP',
    name: TEMPO_TESTNET_ONBOARDING_POLICY_NAME,
    rules: buildTempoTestnetOnboardingGasPolicyRules({
      ...(input.projectId ? { projectId: input.projectId } : {}),
      environmentId: input.environmentId,
      contractAddress: input.contractAddress,
    }),
  });
  const published = await input.policies.publishPolicy(input.ctx, created.id);
  if (!published) {
    throw new ConsoleGasSponsorshipError(
      'internal',
      500,
      `Gas sponsorship policy ${created.id} was not found after creation`,
    );
  }
  const projection = await projectConsoleGasSponsorshipPolicyProjection(
    input.policies,
    input.ctx,
    published.policy,
  );
  if (!projection) {
    throw new ConsoleGasSponsorshipError(
      'internal',
      500,
      `Policy ${published.policy.id} did not project as a gas sponsorship policy`,
    );
  }
  return projection;
}

export function resolveSponsoredCallPoliciesFromProjections(
  projections: readonly ConsoleGasSponsorshipPolicyProjection[],
): ResolvedSponsoredCallPolicy[] {
  return projections
    .filter((policy) => {
      if (!policy.enabled) return false;
      if (!Array.isArray(policy.allowedChainIds) || policy.allowedChainIds.length === 0) return false;
      if (policy.callMode === 'ALLOW_ALL') return true;
      return Array.isArray(policy.allowedCalls) && policy.allowedCalls.length > 0;
    })
    .map((policy) => ({
      policyId: policy.id,
      policyName: policy.name,
      scopePolicyId: policy.scopePolicyId,
      scopePolicyName: policy.scopePolicyName,
      templateId: policy.templateId,
      networkClass: policy.networkClass,
      allowedChainIds: [...policy.allowedChainIds],
      callMode: policy.callMode,
      allowedCalls: policy.allowedCalls.map((entry) => ({ ...entry })),
      spendCap: {
        mode: policy.spendCap.mode,
        period: policy.spendCap.period,
        capsByChain: policy.spendCap.capsByChain.map((entry) => ({ ...entry })),
      },
      scopeType: policy.scopeType,
      projectId: policy.projectId,
      environmentId: policy.environmentId,
    }));
}
