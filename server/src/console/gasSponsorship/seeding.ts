import type { ConsoleOrgProjectEnvService, ConsoleOrgProjectEnvContext } from '../orgProjectEnv';
import type { ConsoleRuntimeSnapshotService } from '../runtimeSnapshots';
import type { ConsolePolicyService } from '../policies';
import type { ConsoleSmartWalletService } from '../smartWallets';
import type { ConsoleGasSponsorshipService } from './service';
import {
  DEFAULT_TEMPO_DRIP_GAS_LIMIT,
  ensureTempoTestnetOnboardingPolicyForEnvironment,
} from './onboarding';
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
  gasSponsorship: ConsoleGasSponsorshipService;
  policies?: ConsolePolicyService | null;
  smartWallets?: ConsoleSmartWalletService | null;
}): Promise<void> {
  const payload = await resolveConsoleRuntimeSnapshotPayload({
    orgId: input.ctx.orgId,
    actorUserId: input.ctx.actorUserId,
    roles: input.ctx.roles,
    environmentId: input.environment.id,
    projectId: input.environment.projectId,
    ...(input.policies ? { policies: input.policies } : {}),
    gasSponsorship: input.gasSponsorship,
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
  gasSponsorship: ConsoleGasSponsorshipService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService;
  faucetContractAddress: `0x${string}`;
  maxGasLimit?: bigint;
  policies?: ConsolePolicyService | null;
  smartWallets?: ConsoleSmartWalletService | null;
}): Promise<void> {
  await ensureTempoTestnetOnboardingPolicyForEnvironment({
    gasSponsorship: input.gasSponsorship,
    ctx: {
      orgId: input.ctx.orgId,
      actorUserId: input.ctx.actorUserId,
      roles: input.ctx.roles,
    },
    projectId: input.environment.projectId,
    environmentId: input.environment.id,
    contractAddress: input.faucetContractAddress,
    maxGasLimit: input.maxGasLimit ?? DEFAULT_TEMPO_DRIP_GAS_LIMIT,
  });
  await publishCurrentEnvironmentSnapshot({
    ctx: input.ctx,
    environment: input.environment,
    runtimeSnapshots: input.runtimeSnapshots,
    gasSponsorship: input.gasSponsorship,
    ...(input.policies ? { policies: input.policies } : {}),
    ...(input.smartWallets ? { smartWallets: input.smartWallets } : {}),
  });
}

export function createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship(input: {
  base: ConsoleOrgProjectEnvService;
  gasSponsorship: ConsoleGasSponsorshipService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService;
  faucetContractAddress: `0x${string}`;
  maxGasLimit?: bigint;
  policies?: ConsolePolicyService | null;
  smartWallets?: ConsoleSmartWalletService | null;
}): ConsoleOrgProjectEnvService {
  return {
    ...input.base,
    async createEnvironment(ctx, request) {
      const environment = await input.base.createEnvironment(ctx, request);
      await seedEnvironment({
        ctx,
        environment,
        gasSponsorship: input.gasSponsorship,
        runtimeSnapshots: input.runtimeSnapshots,
        faucetContractAddress: input.faucetContractAddress,
        ...(input.maxGasLimit !== undefined ? { maxGasLimit: input.maxGasLimit } : {}),
        ...(input.policies ? { policies: input.policies } : {}),
        ...(input.smartWallets ? { smartWallets: input.smartWallets } : {}),
      });
      return environment;
    },
  };
}

export async function ensureTempoOnboardingSponsorshipForExistingEnvironments(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService;
  gasSponsorship: ConsoleGasSponsorshipService;
  runtimeSnapshots: ConsoleRuntimeSnapshotService;
  ctx: ConsoleOrgProjectEnvContext;
  faucetContractAddress: `0x${string}`;
  maxGasLimit?: bigint;
  projectId?: string;
  policies?: ConsolePolicyService | null;
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
      gasSponsorship: input.gasSponsorship,
      runtimeSnapshots: input.runtimeSnapshots,
      faucetContractAddress: input.faucetContractAddress,
      ...(input.maxGasLimit !== undefined ? { maxGasLimit: input.maxGasLimit } : {}),
      ...(input.policies ? { policies: input.policies } : {}),
      ...(input.smartWallets ? { smartWallets: input.smartWallets } : {}),
    });
  }
}
