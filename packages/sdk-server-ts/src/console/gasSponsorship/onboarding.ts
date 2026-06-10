import type {
  ConsoleGasSponsorshipPolicyProjection,
  ResolvedGasSponsorshipPolicy,
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
export const TEMPO_DRIP_TO_FUNCTION_SIGNATURE = 'dripTo(address,address[])';
export const TEMPO_DRIP_TO_SELECTOR = '0x867ae9d4';
export const DEFAULT_TEMPO_ONBOARDING_CONTRACT =
  '0xBB442B54c85efBa2D7B81eA52990ad638cDbA483' as `0x${string}`;

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
    kind: 'evm_call',
    executionMode: 'evm_eoa',
    spendCap: {
      mode: 'NONE',
      period: 'MONTHLY',
      capsByChain: [],
    },
    allowedCalls: [
      {
        chainId: TEMPO_TESTNET_CHAIN_ID,
        to: input.contractAddress,
        functionSignature: TEMPO_DRIP_TO_FUNCTION_SIGNATURE,
        maxGasLimit: '1000000',
        maxValueWei: '0',
      },
    ],
  };
}

function hasDesiredTempoOnboardingProjection(input: {
  policy: ConsoleGasSponsorshipPolicyProjection;
  projectId?: string | null;
  environmentId: string;
  contractAddress: `0x${string}`;
}): boolean {
  if (input.policy.kind !== 'evm_call') return false;
  const allowedCall = input.policy.allowedCalls[0];
  return (
    input.policy.templateId === TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID &&
    input.policy.scopeType === 'ENVIRONMENT' &&
    input.policy.projectId === (input.projectId || null) &&
    input.policy.environmentId === input.environmentId &&
    input.policy.enabled &&
    input.policy.networkClass === 'TESTNET' &&
    input.policy.allowedChainIds.length === 1 &&
    input.policy.allowedChainIds[0] === TEMPO_TESTNET_CHAIN_ID &&
    input.policy.allowedCalls.length === 1 &&
    Boolean(allowedCall) &&
    allowedCall.chainId === TEMPO_TESTNET_CHAIN_ID &&
    String(allowedCall.to || '').toLowerCase() === input.contractAddress.toLowerCase() &&
    String(allowedCall.functionSignature || '') === TEMPO_DRIP_TO_FUNCTION_SIGNATURE &&
    String(allowedCall.selector || '').toLowerCase() === TEMPO_DRIP_TO_SELECTOR
  );
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
  if (matched && matched.templateId === TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID) {
    if (
      hasDesiredTempoOnboardingProjection({
        policy: matched,
        ...(input.projectId ? { projectId: input.projectId } : {}),
        environmentId: input.environmentId,
        contractAddress: input.contractAddress,
      })
    ) {
      return matched;
    }
    const updated = await input.policies.updatePolicy(input.ctx, matched.id, {
      rules: buildTempoTestnetOnboardingGasPolicyRules({
        ...(input.projectId ? { projectId: input.projectId } : {}),
        environmentId: input.environmentId,
        contractAddress: input.contractAddress,
      }),
    });
    if (!updated) {
      throw new ConsoleGasSponsorshipError(
        'internal',
        500,
        `Gas sponsorship policy ${matched.id} was not found for update`,
      );
    }
    const published = await input.policies.publishPolicy(input.ctx, updated.id);
    if (!published) {
      throw new ConsoleGasSponsorshipError(
        'internal',
        500,
        `Gas sponsorship policy ${updated.id} was not found after update`,
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
): ResolvedGasSponsorshipPolicy[] {
  return projections
    .filter((policy) =>
      policy.kind === 'evm_call'
        ? policy.enabled && Array.isArray(policy.allowedCalls) && policy.allowedCalls.length > 0
        : policy.enabled &&
            Array.isArray(policy.allowedDelegateActions) &&
            policy.allowedDelegateActions.length > 0,
    )
    .map((policy) => {
      const common = {
        policyId: policy.id,
        policyName: policy.name,
        scopePolicyId: policy.scopePolicyId,
        scopePolicyName: policy.scopePolicyName,
        templateId: policy.templateId,
        networkClass: policy.networkClass,
        executionMode: policy.executionMode,
        spendCap: {
          mode: policy.spendCap.mode,
          period: policy.spendCap.period,
          capsByChain: policy.spendCap.capsByChain.map((entry) => ({ ...entry })),
        },
        scopeType: policy.scopeType,
        projectId: policy.projectId,
        environmentId: policy.environmentId,
      } as const;
      if (policy.kind === 'near_delegate') {
        return {
          ...common,
          kind: 'near_delegate',
          executionMode: 'near_delegate',
          allowedDelegateActions: policy.allowedDelegateActions.map((entry) => ({
            ...entry,
            methods: [...entry.methods],
          })),
        };
      }
      return {
        ...common,
        kind: 'evm_call',
        executionMode: 'evm_eoa',
        allowedChainIds: [...policy.allowedChainIds],
        allowedCalls: policy.allowedCalls.map((entry) => ({ ...entry })),
      };
    });
}
