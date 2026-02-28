import type { ConsoleGasSponsorshipService } from '../console/gasSponsorship';
import type { ConsolePolicyService } from '../console/policies';
import type { ConsoleRuntimeSnapshotPayload } from '../console/runtimeSnapshots';
import type { ConsoleSettingsService } from '../console/settings';
import type { ConsoleSmartWalletService } from '../console/smartWallets';

export interface ResolveConsoleRuntimeSnapshotPayloadInput {
  orgId: string;
  actorUserId: string;
  roles: string[];
  environmentId: string;
  projectId?: string;
  policies?: ConsolePolicyService | null;
  settings?: ConsoleSettingsService | null;
  gasSponsorship?: ConsoleGasSponsorshipService | null;
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
      input.policies.listPolicies(ctx),
      input.policies.listAssignments(ctx),
    ]);
    const scopedAssignments = assignments.filter((assignment) =>
      isSameScope(assignment, input.orgId, input.environmentId, input.projectId),
    );
    return {
      status: 'resolved',
      policyCount: policies.length,
      assignmentCount: scopedAssignments.length,
      policies,
      assignments: scopedAssignments,
    };
  })();

  const settingsPromise = (async () => {
    if (!input.settings) {
      return {
        status: 'not_configured',
      };
    }
    const [appSettings, securitySettings] = await Promise.all([
      input.settings.getAppSettings(ctx, {
        environmentId: input.environmentId,
      }),
      input.settings.getSecuritySettings(ctx, {
        environmentId: input.environmentId,
      }),
    ]);
    return {
      status: 'resolved',
      appSettings,
      securitySettings,
    };
  })();

  const gasPromise = (async () => {
    if (!input.gasSponsorship) {
      return {
        status: 'not_configured',
        configCount: 0,
        configs: [] as unknown[],
      };
    }
    const configs = await input.gasSponsorship.listConfigs(ctx, {
      environmentId: input.environmentId,
      ...(input.projectId ? { projectId: input.projectId } : {}),
    });
    return {
      status: 'resolved',
      configCount: configs.length,
      configs,
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

  const [policy, settings, gasSponsorship, smartWallets] = await Promise.all([
    policyPromise,
    settingsPromise,
    gasPromise,
    smartWalletPromise,
  ]);

  return {
    policy,
    settings,
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
