import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipConfig,
  CreateConsoleGasSponsorshipRequest,
} from './types';
import type {
  ConsoleGasSponsorshipContext,
  ConsoleGasSponsorshipService,
} from './service';

export const TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID = 'tempo_testnet_onboarding';
export const TEMPO_TESTNET_ONBOARDING_POLICY_NAME = 'Tempo Testnet Onboarding';
export const TEMPO_TESTNET_CHAIN_ID = 42_431;
export const TEMPO_DRIP_SELECTOR = '0x428dc451';
export const DEFAULT_TEMPO_DRIP_GAS_LIMIT = 300_000n;
export const DEFAULT_TEMPO_ONBOARDING_CONTRACT =
  '0xbb85080E6953f25197ec68798360667140EbAf4b' as `0x${string}`;

export interface ResolvedSponsoredCallPolicy {
  policyId: string;
  policyName: string;
  templateId: string | null;
  networkClass: 'ANY' | 'TESTNET' | 'MAINNET';
  executor: 'RELAY_EOA';
  allowedCalls: ConsoleGasSponsorshipAllowedCall[];
  scopeType: ConsoleGasSponsorshipConfig['scopeType'];
  projectId: string | null;
  environmentId: string | null;
}

export function createTempoTestnetOnboardingGasSponsorshipRequest(input: {
  projectId?: string | null;
  environmentId: string;
  contractAddress: `0x${string}`;
  maxGasLimit?: bigint;
}): CreateConsoleGasSponsorshipRequest {
  return {
    scopeType: 'ENVIRONMENT',
    ...(input.projectId ? { projectId: input.projectId } : {}),
    environmentId: input.environmentId,
    policyName: TEMPO_TESTNET_ONBOARDING_POLICY_NAME,
    templateId: TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
    networkClass: 'TESTNET',
    executor: 'RELAY_EOA',
    enabled: true,
    paymasterMode: 'FORCED',
    fallbackBehavior: 'REJECT',
    chainBudgets: [],
    allowedCalls: [
      {
        chainId: TEMPO_TESTNET_CHAIN_ID,
        to: input.contractAddress,
        selector: TEMPO_DRIP_SELECTOR,
        maxGasLimit: String(input.maxGasLimit ?? DEFAULT_TEMPO_DRIP_GAS_LIMIT),
        maxValueWei: '0',
      },
    ],
  };
}

export async function ensureTempoTestnetOnboardingPolicyForEnvironment(input: {
  gasSponsorship: ConsoleGasSponsorshipService;
  ctx: ConsoleGasSponsorshipContext;
  projectId?: string | null;
  environmentId: string;
  contractAddress: `0x${string}`;
  maxGasLimit?: bigint;
}): Promise<ConsoleGasSponsorshipConfig> {
  const existing = await input.gasSponsorship.listConfigs(input.ctx, {
    scopeType: 'ENVIRONMENT',
    environmentId: input.environmentId,
    templateId: TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
  });
  const matched = existing.find((config) => config.environmentId === input.environmentId);
  if (matched) return matched;
  return await input.gasSponsorship.createConfig(
    input.ctx,
    createTempoTestnetOnboardingGasSponsorshipRequest({
      ...(input.projectId ? { projectId: input.projectId } : {}),
      environmentId: input.environmentId,
      contractAddress: input.contractAddress,
      ...(input.maxGasLimit !== undefined ? { maxGasLimit: input.maxGasLimit } : {}),
    }),
  );
}

export function resolveSponsoredCallPoliciesFromConfigs(
  configs: readonly ConsoleGasSponsorshipConfig[],
): ResolvedSponsoredCallPolicy[] {
  return configs
    .filter((config) => config.enabled && Array.isArray(config.allowedCalls) && config.allowedCalls.length > 0)
    .map((config) => ({
      policyId: config.id,
      policyName: config.policyName,
      templateId: config.templateId,
      networkClass: config.networkClass,
      executor: config.executor,
      allowedCalls: config.allowedCalls.map((entry) => ({ ...entry })),
      scopeType: config.scopeType,
      projectId: config.projectId,
      environmentId: config.environmentId,
    }));
}
