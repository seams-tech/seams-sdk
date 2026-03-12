import type { ConsoleOrgProjectEnvService, ConsoleOrgProjectEnvContext } from '../orgProjectEnv';
import type { ConsoleRuntimeSnapshotService } from '../runtimeSnapshots';
import type { ConsolePolicyService } from '../policies';
import type { ConsoleSmartWalletService } from '../smartWallets';
import { ensureTempoTestnetOnboardingPolicyForEnvironment } from './onboarding';
import { resolveConsoleRuntimeSnapshotPayload } from '../../router/runtimeSnapshotPayload';

function toSnapshotContext(ctx: ConsoleOrgProjectEnvContext) {
  return {
    orgId: ctx.orgId,
    actorUserId: ctx.actorUserId,
    roles: [...ctx.roles],
  };
}

async function publishCurrentEnvironmentSnapshot(input: {
  ctx: ConsoleOrgProjectEnvContext;
  environment: { id: string; projectId: string };
  runtimeSnapshots: ConsoleRuntimeSnapshotService;
  policies: ConsolePolicyService;
  smartWallets?: ConsoleSmartWalletService | null;
}): Promise<void> {
  const payload = await resolveConsoleRuntimeSnapshotPayload({
    orgId: input.ctx.orgId,
    actorUserId: input.ctx.actorUserId,
    roles: input.ctx.roles,
    environmentId: input.environment.id,
    projectId: input.environment.projectId,
    policies: input.policies,
    ...(input.smartWallets ? { smartWallets: input.smartWallets } : {}),
  });
  await input.runtimeSnapshots.publishSnapshot(toSnapshotContext(input.ctx), {
    environmentId: input.environment.id,
    projectId: input.environment.projectId,
    payload,
  });
}

async function seedEnvironment(input: {
  ctx: ConsoleOrgProjectEnvContext;
  environment: { id: string; projectId: string; status?: string };
  policies: ConsolePolicyService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService;
  faucetContractAddress: `0x${string}`;
  smartWallets?: ConsoleSmartWalletService | null;
}): Promise<void> {
  await ensureTempoTestnetOnboardingPolicyForEnvironment({
    policies: input.policies,
    ctx: {
      orgId: input.ctx.orgId,
      actorUserId: input.ctx.actorUserId,
      roles: input.ctx.roles,
    },
    projectId: input.environment.projectId,
    environmentId: input.environment.id,
    contractAddress: input.faucetContractAddress,
  });
  await publishCurrentEnvironmentSnapshot({
    ctx: input.ctx,
    environment: input.environment,
    runtimeSnapshots: input.runtimeSnapshots,
    policies: input.policies,
    ...(input.smartWallets ? { smartWallets: input.smartWallets } : {}),
  });
}

export function createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship(input: {
  base: ConsoleOrgProjectEnvService;
  policies: ConsolePolicyService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService;
  faucetContractAddress: `0x${string}`;
  smartWallets?: ConsoleSmartWalletService | null;
}): ConsoleOrgProjectEnvService {
  return {
    ...input.base,
    async createProject(ctx, request) {
      const project = await input.base.createProject(ctx, request);
      const environments = await input.base.listEnvironments(ctx, { projectId: project.id });
      for (const environment of environments) {
        if (environment.status === 'ARCHIVED') continue;
        await seedEnvironment({
          ctx,
          environment,
          policies: input.policies,
          runtimeSnapshots: input.runtimeSnapshots,
          faucetContractAddress: input.faucetContractAddress,
          ...(input.smartWallets ? { smartWallets: input.smartWallets } : {}),
        });
      }
      return project;
    },
    async createEnvironment(ctx, request) {
      const environment = await input.base.createEnvironment(ctx, request);
      await seedEnvironment({
        ctx,
        environment,
        policies: input.policies,
        runtimeSnapshots: input.runtimeSnapshots,
        faucetContractAddress: input.faucetContractAddress,
        ...(input.smartWallets ? { smartWallets: input.smartWallets } : {}),
      });
      return environment;
    },
  };
}

export async function ensureTempoOnboardingSponsorshipForExistingEnvironments(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService;
  policies: ConsolePolicyService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService;
  ctx: ConsoleOrgProjectEnvContext;
  faucetContractAddress: `0x${string}`;
  projectId?: string;
  smartWallets?: ConsoleSmartWalletService | null;
}): Promise<void> {
  const environments = await input.orgProjectEnv.listEnvironments(input.ctx, {
    ...(input.projectId ? { projectId: input.projectId } : {}),
  });
  for (const environment of environments) {
    if (environment.status === 'ARCHIVED') continue;
    await seedEnvironment({
      ctx: input.ctx,
      environment,
      policies: input.policies,
      runtimeSnapshots: input.runtimeSnapshots,
      faucetContractAddress: input.faucetContractAddress,
      ...(input.smartWallets ? { smartWallets: input.smartWallets } : {}),
    });
  }
}
