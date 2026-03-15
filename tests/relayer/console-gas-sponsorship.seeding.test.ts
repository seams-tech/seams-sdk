import { expect, test } from '@playwright/test';
import {
  projectConsoleGasSponsorshipPolicyProjection,
  sortConsoleGasSponsorshipPolicyProjections,
  type ConsoleGasSponsorshipPolicyProjection,
} from '../../server/src/console/gasSponsorship';
import {
  createInMemoryConsolePolicyService,
  type ConsolePolicyService,
} from '../../server/src/console/policies/service';
import {
  createInMemoryConsoleOrgProjectEnvService,
} from '../../server/src/console/orgProjectEnv/service';
import {
  createInMemoryConsoleRuntimeSnapshotService,
} from '../../server/src/console/runtimeSnapshots/service';
import {
  createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship,
  ensureTempoOnboardingSponsorshipForExistingEnvironments,
} from '../../server/src/console/gasSponsorship/seeding';
import {
  DEFAULT_TEMPO_ONBOARDING_CONTRACT,
  TEMPO_DRIP_SELECTOR,
  TEMPO_TESTNET_CHAIN_ID,
  TEMPO_TESTNET_ONBOARDING_POLICY_NAME,
  TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
} from '../../server/src/console/gasSponsorship/onboarding';

const ctx = {
  orgId: 'org-dev',
  actorUserId: 'tempo-onboarding-seed',
  roles: ['owner', 'admin'],
};

async function listProjectedGasPolicies(
  policies: ConsolePolicyService,
  filters: {
    projectId?: string;
    environmentId?: string;
  } = {},
): Promise<ConsoleGasSponsorshipPolicyProjection[]> {
  const projections = (
    await Promise.all(
      (await policies.listPolicies(ctx, { kind: 'GAS_SPONSORSHIP' })).map(
        async (policy) => await projectConsoleGasSponsorshipPolicyProjection(policies, ctx, policy),
      ),
    )
  ).filter(
    (projection): projection is ConsoleGasSponsorshipPolicyProjection => projection !== null,
  );
  return sortConsoleGasSponsorshipPolicyProjections(
    projections.filter((projection) => {
      if (filters.projectId && projection.projectId !== filters.projectId) return false;
      if (filters.environmentId && projection.environmentId !== filters.environmentId) return false;
      return true;
    }),
  );
}

test.describe('console gas sponsorship seeding', () => {
  test('startup seeding reconciles an existing onboarding template policy to the configured contract', async () => {
    const policies = createInMemoryConsolePolicyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();
    const staleContract = '0xbb85080E6953f25197ec68798360667140EbAf4b' as const;

    await orgProjectEnv.upsertOrganization(ctx, {});
    await orgProjectEnv.createProject(ctx, {
      id: 'proj_stale_onboarding',
      name: 'Stale Onboarding',
    });

    await ensureTempoOnboardingSponsorshipForExistingEnvironments({
      orgProjectEnv,
      policies,
      runtimeSnapshots,
      ctx,
      faucetContractAddress: staleContract,
    });

    await ensureTempoOnboardingSponsorshipForExistingEnvironments({
      orgProjectEnv,
      policies,
      runtimeSnapshots,
      ctx,
      faucetContractAddress: DEFAULT_TEMPO_ONBOARDING_CONTRACT,
    });

    const configs = await listProjectedGasPolicies(policies, {
      projectId: 'proj_stale_onboarding',
      environmentId: 'proj_stale_onboarding:dev',
    });

    expect(configs).toHaveLength(1);
    expect(configs[0]?.allowedCalls).toEqual([
      {
        chainId: TEMPO_TESTNET_CHAIN_ID,
        to: DEFAULT_TEMPO_ONBOARDING_CONTRACT.toLowerCase(),
        selector: TEMPO_DRIP_SELECTOR,
      },
    ]);
  });

  test('createProject seeds the Tempo onboarding policy into default project environments', async () => {
    const policies = createInMemoryConsolePolicyService();
    const orgProjectEnv = createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship({
      base: createInMemoryConsoleOrgProjectEnvService(),
      policies,
      runtimeSnapshots: createInMemoryConsoleRuntimeSnapshotService(),
      faucetContractAddress: DEFAULT_TEMPO_ONBOARDING_CONTRACT,
    });

    await orgProjectEnv.upsertOrganization(ctx, {});
    await orgProjectEnv.createProject(ctx, {
      id: 'proj_mmggz8jp_v9pft0',
      name: 'Mock Project',
    });

    const configs = await listProjectedGasPolicies(policies, {
      projectId: 'proj_mmggz8jp_v9pft0',
      environmentId: 'proj_mmggz8jp_v9pft0:dev',
    });

    expect(configs).toHaveLength(1);
    expect(configs[0]).toMatchObject({
      name: TEMPO_TESTNET_ONBOARDING_POLICY_NAME,
      templateId: TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
      networkClass: 'TESTNET',
      scopeType: 'ENVIRONMENT',
      projectId: 'proj_mmggz8jp_v9pft0',
      environmentId: 'proj_mmggz8jp_v9pft0:dev',
      enabled: true,
    });
    expect(configs[0]?.allowedChainIds).toEqual([TEMPO_TESTNET_CHAIN_ID]);
    expect(configs[0]?.allowedCalls).toEqual([
      {
        chainId: TEMPO_TESTNET_CHAIN_ID,
        to: DEFAULT_TEMPO_ONBOARDING_CONTRACT.toLowerCase(),
        selector: TEMPO_DRIP_SELECTOR,
      },
    ]);
  });

  test('startup seeding backfills the Tempo onboarding policy for every existing project environment', async () => {
    const policies = createInMemoryConsolePolicyService();
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const runtimeSnapshots = createInMemoryConsoleRuntimeSnapshotService();

    await orgProjectEnv.upsertOrganization(ctx, {});
    await orgProjectEnv.createProject(ctx, {
      id: 'proj_existing_one',
      name: 'Existing One',
    });
    await orgProjectEnv.createProject(ctx, {
      id: 'proj_existing_two',
      name: 'Existing Two',
    });

    await ensureTempoOnboardingSponsorshipForExistingEnvironments({
      orgProjectEnv,
      policies,
      runtimeSnapshots,
      ctx,
      faucetContractAddress: DEFAULT_TEMPO_ONBOARDING_CONTRACT,
    });

    const firstProjectConfigs = await listProjectedGasPolicies(policies, {
      projectId: 'proj_existing_one',
    });
    const secondProjectConfigs = await listProjectedGasPolicies(policies, {
      projectId: 'proj_existing_two',
    });

    expect(firstProjectConfigs).toHaveLength(3);
    expect(secondProjectConfigs).toHaveLength(3);
    expect(
      firstProjectConfigs.every(
        (config) => config.templateId === TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
      ),
    ).toBe(true);
    expect(
      secondProjectConfigs.every(
        (config) => config.templateId === TEMPO_TESTNET_ONBOARDING_TEMPLATE_ID,
      ),
    ).toBe(true);
  });
});
