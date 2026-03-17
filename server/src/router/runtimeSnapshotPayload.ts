import {
  projectConsoleGasSponsorshipPolicyProjection,
  resolveSponsoredCallPoliciesFromProjections,
  sortConsoleGasSponsorshipPolicyProjections,
} from '../console/gasSponsorship';
import type { ConsolePolicy, ConsolePolicyService } from '../console/policies';
import type { ConsoleRuntimeSnapshotPayload } from '../console/runtimeSnapshots';
import type { ConsoleSmartWalletService } from '../console/smartWallets';

export interface ResolveConsoleRuntimeSnapshotPayloadInput {
  orgId: string;
  actorUserId: string;
  roles: string[];
  environmentId: string;
  projectId?: string;
  policies?: ConsolePolicyService | null;
  smartWallets?: ConsoleSmartWalletService | null;
  now?: () => Date;
}

function isSameScope(
  assignment: { scopeType: string; scopeId: string },
  orgId: string,
  environmentId: string,
  projectId?: string,
): boolean {
  const scopeType = String(assignment.scopeType || '').toUpperCase();
  const scopeId = String(assignment.scopeId || '');
  if (scopeType === 'ORG') return scopeId === orgId;
  if (scopeType === 'ENVIRONMENT') return scopeId === environmentId;
  if (scopeType === 'PROJECT' && projectId) return scopeId === projectId;
  return false;
}

function hasPublishedRuntimePolicy(policy: ConsolePolicy | null | undefined): boolean {
  return Boolean(policy && String(policy.publishedAt || '').trim() && Number(policy.version || 0) > 0);
}

async function resolveLiveRuntimePolicy(input: {
  policies: ConsolePolicyService;
  ctx: { orgId: string; actorUserId: string; roles: string[] };
  policy: ConsolePolicy;
}): Promise<ConsolePolicy | null> {
  if (!hasPublishedRuntimePolicy(input.policy)) return null;
  if (input.policy.status === 'PUBLISHED') return input.policy;
  const versions = await input.policies.listPolicyVersions(input.ctx, input.policy.id);
  const latestPublished =
    versions?.find(
      (entry) => entry.status === 'PUBLISHED' && String(entry.publishedAt || '').trim(),
    ) || null;
  if (!latestPublished) return null;
  return {
    ...input.policy,
    status: 'PUBLISHED',
    version: latestPublished.version,
    rules: latestPublished.rules,
    updatedAt: latestPublished.createdAt,
    publishedAt: latestPublished.publishedAt,
  };
}

function matchesRuntimeGasScope(input: {
  environmentId: string;
  projectId?: string;
  config: {
    environmentId: string | null;
    projectId: string | null;
  };
}): boolean {
  if (input.config.environmentId !== input.environmentId) return false;
  if (input.projectId && input.config.projectId !== input.projectId) return false;
  return true;
}

export async function resolveConsoleRuntimeSnapshotPayload(
  input: ResolveConsoleRuntimeSnapshotPayloadInput,
): Promise<ConsoleRuntimeSnapshotPayload> {
  const now = (input.now || (() => new Date()))().toISOString();
  const ctx = {
    orgId: input.orgId,
    actorUserId: input.actorUserId,
    roles: input.roles,
  };

  const policyPromise = (async () => {
    if (!input.policies) {
      return {
        status: 'not_configured',
        policies: [] as unknown[],
        assignments: [] as unknown[],
      };
    }
    const [policies, assignments] = await Promise.all([
      input.policies.listPolicies(ctx, { kind: 'TRANSACTION' }),
      input.policies.listAssignments(ctx),
    ]);
    const scopedAssignments = assignments.filter((assignment) =>
      isSameScope(assignment, input.orgId, input.environmentId, input.projectId),
    );
    const policyById = new Map(policies.map((policy) => [policy.id, policy]));
    const scopedPolicyIds = [...new Set(scopedAssignments.map((assignment) => assignment.policyId))];
    const livePolicies = (
      await Promise.all(
        scopedPolicyIds.map(async (policyId) => {
          const policy = policyById.get(policyId) || null;
          if (!policy) return null;
          return resolveLiveRuntimePolicy({
            policies: input.policies!,
            ctx,
            policy,
          });
        }),
      )
    ).filter((policy): policy is ConsolePolicy => policy !== null);
    const livePolicyIds = new Set(livePolicies.map((policy) => policy.id));
    const liveAssignments = scopedAssignments.filter((assignment) => livePolicyIds.has(assignment.policyId));
    return {
      status: 'resolved',
      policyCount: livePolicies.length,
      assignmentCount: liveAssignments.length,
      policies: livePolicies,
      assignments: liveAssignments,
    };
  })();

  const gasPromise = (async () => {
    if (!input.policies) {
      return {
        status: 'not_configured',
        policyCount: 0,
        policies: [] as unknown[],
        resolvedPolicies: [] as unknown[],
      };
    }
    const gasPolicies = await input.policies.listPolicies(ctx, { kind: 'GAS_SPONSORSHIP' });
    const livePolicies = (
      await Promise.all(
        gasPolicies.map(async (policy) =>
          await resolveLiveRuntimePolicy({
            policies: input.policies!,
            ctx,
            policy,
          }),
        ),
      )
    ).filter((policy): policy is ConsolePolicy => policy !== null);
    const projectedPolicies = sortConsoleGasSponsorshipPolicyProjections(
      (
        await Promise.all(
          livePolicies.map(
            async (policy) =>
              await projectConsoleGasSponsorshipPolicyProjection(input.policies!, ctx, policy),
          ),
        )
      )
        .filter((policy): policy is NonNullable<typeof policy> => policy !== null)
        .filter((policy) =>
          matchesRuntimeGasScope({
            environmentId: input.environmentId,
            ...(input.projectId ? { projectId: input.projectId } : {}),
            config: policy,
          }),
        ),
    );
    return {
      status: 'resolved',
      policyCount: projectedPolicies.length,
      policies: projectedPolicies,
      resolvedPolicies: resolveSponsoredCallPoliciesFromProjections(projectedPolicies),
    };
  })();

  const smartWalletPromise = (async () => {
    if (!input.smartWallets) {
      return {
        status: 'not_configured',
        configCount: 0,
        configs: [] as unknown[],
      };
    }
    const configs = await input.smartWallets.listConfigs(ctx, {
      environmentId: input.environmentId,
      ...(input.projectId ? { projectId: input.projectId } : {}),
    });
    return {
      status: 'resolved',
      configCount: configs.length,
      configs,
    };
  })();

  const [policy, gasSponsorship, smartWallets] = await Promise.all([
    policyPromise,
    gasPromise,
    smartWalletPromise,
  ]);

  return {
    policy,
    gasSponsorship,
    smartWallets,
    metadata: {
      source: 'server_publish_current_v1',
      generatedAt: now,
      environmentId: input.environmentId,
      ...(input.projectId ? { projectId: input.projectId } : {}),
    },
  };
}
