import type {
  ConsoleGasSponsorshipAllowedCall,
  ConsoleGasSponsorshipCallMode,
  ConsoleGasSponsorshipConfig,
  ConsoleGasSponsorshipSpendCap,
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
export const DEFAULT_TEMPO_ONBOARDING_CONTRACT =
  '0xbb85080E6953f25197ec68798360667140EbAf4b' as `0x${string}`;

export interface ResolvedSponsoredCallPolicy {
  policyId: string;
  policyName: string;
  templateId: string | null;
  networkClass: 'ANY' | 'TESTNET' | 'MAINNET';
  allowedChainIds: number[];
  callMode: ConsoleGasSponsorshipCallMode;
  allowedCalls: ConsoleGasSponsorshipAllowedCall[];
  spendCap: ConsoleGasSponsorshipSpendCap;
  scopeType: ConsoleGasSponsorshipConfig['scopeType'];
  projectId: string | null;
  environmentId: string | null;
}

export function createTempoTestnetOnboardingGasSponsorshipRequest(input: {
  projectId?: string | null;
  environmentId: string;
  contractAddress: `0x${string}`;
}): CreateConsoleGasSponsorshipRequest {
  return {
    scopeType: 'ENVIRONMENT',
    ...(input.projectId ? { projectId: input.projectId } : {}),
    environmentId: input.environmentId,
    policyName: TEMPO_TESTNET_ONBOARDING_POLICY_NAME,
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

export async function ensureTempoTestnetOnboardingPolicyForEnvironment(input: {
  gasSponsorship: ConsoleGasSponsorshipService;
  ctx: ConsoleGasSponsorshipContext;
  projectId?: string | null;
  environmentId: string;
  contractAddress: `0x${string}`;
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
    }),
  );
}

export function resolveSponsoredCallPoliciesFromConfigs(
  configs: readonly ConsoleGasSponsorshipConfig[],
): ResolvedSponsoredCallPolicy[] {
  return configs
    .filter((config) => {
      if (!config.enabled) return false;
      if (!Array.isArray(config.allowedChainIds) || config.allowedChainIds.length === 0) return false;
      if (config.callMode === 'ALLOW_ALL') return true;
      return Array.isArray(config.allowedCalls) && config.allowedCalls.length > 0;
    })
    .map((config) => ({
      policyId: config.id,
      policyName: config.policyName,
      templateId: config.templateId,
      networkClass: config.networkClass,
      allowedChainIds: [...config.allowedChainIds],
      callMode: config.callMode,
      allowedCalls: config.allowedCalls.map((entry) => ({ ...entry })),
      spendCap: {
        mode: config.spendCap.mode,
        period: config.spendCap.period,
        capsByChain: config.spendCap.capsByChain.map((entry) => ({ ...entry })),
      },
      scopeType: config.scopeType,
      projectId: config.projectId,
      environmentId: config.environmentId,
    }));
}
