import { expect, test } from '@playwright/test';
import {
  createInMemoryConsoleGasSponsorshipService,
} from '../../server/src/console/gasSponsorship/service';
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

test.describe('console gas sponsorship seeding', () => {
  test('createProject seeds the Tempo onboarding policy into default project environments', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
    const orgProjectEnv = createConsoleOrgProjectEnvServiceWithTempoOnboardingSponsorship({
      base: createInMemoryConsoleOrgProjectEnvService(),
      gasSponsorship,
      runtimeSnapshots: createInMemoryConsoleRuntimeSnapshotService(),
      faucetContractAddress: DEFAULT_TEMPO_ONBOARDING_CONTRACT,
    });

    await orgProjectEnv.upsertOrganization(ctx, {});
    await orgProjectEnv.createProject(ctx, {
      id: 'proj_mmggz8jp_v9pft0',
      name: 'Mock Project',
    });

    const configs = await gasSponsorship.listConfigs(ctx, {
      projectId: 'proj_mmggz8jp_v9pft0',
      environmentId: 'proj_mmggz8jp_v9pft0:dev',
    });

    expect(configs).toHaveLength(1);
    expect(configs[0]).toMatchObject({
      policyName: TEMPO_TESTNET_ONBOARDING_POLICY_NAME,
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
        to: DEFAULT_TEMPO_ONBOARDING_CONTRACT,
        selector: TEMPO_DRIP_SELECTOR,
      },
    ]);
  });

  test('startup seeding backfills the Tempo onboarding policy for every existing project environment', async () => {
    const gasSponsorship = createInMemoryConsoleGasSponsorshipService();
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
      gasSponsorship,
      runtimeSnapshots,
      ctx,
      faucetContractAddress: DEFAULT_TEMPO_ONBOARDING_CONTRACT,
    });

    const firstProjectConfigs = await gasSponsorship.listConfigs(ctx, {
      projectId: 'proj_existing_one',
    });
    const secondProjectConfigs = await gasSponsorship.listConfigs(ctx, {
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
