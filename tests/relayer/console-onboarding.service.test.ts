import { expect, test } from '@playwright/test';
import { createInMemoryConsoleApiKeyService } from '../../packages/console-server-ts/src/apiKeys/service';
import { createInMemoryConsoleOnboardingService } from '../../packages/console-server-ts/src/onboarding/service';
import { createInMemoryConsoleOrgProjectEnvService } from '../../packages/console-server-ts/src/orgProjectEnv/service';
import { createInMemoryConsoleOrganizationAccessService } from '../../packages/console-server-ts/src/teamRbac/service';

test('organization onboarding persists the organization before bootstrapping its first owner', async () => {
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const organizationAccess = createInMemoryConsoleOrganizationAccessService();
  const onboarding = createInMemoryConsoleOnboardingService({
    orgProjectEnv,
    organizationAccess,
    apiKeys: createInMemoryConsoleApiKeyService(),
  });
  const ctx = {
    orgId: 'org_onboarding_owner',
    actorUserId: 'user_onboarding_owner',
    actorEmail: 'owner@example.com',
    actorDisplayName: 'Owner',
    projectId: null,
    environmentId: null,
  };

  const first = await onboarding.createOnboardingOrganization(ctx, {
    org: { name: 'Onboarding Organization', slug: 'onboarding-organization' },
  });
  expect(first.created).toEqual({ organization: true, owner: true });
  expect(
    await organizationAccess.lookupAuthorization({
      orgId: ctx.orgId,
      userId: ctx.actorUserId,
    }),
  ).toMatchObject({
    kind: 'authorized',
    role: 'OWNER',
  });

  const repeated = await onboarding.createOnboardingOrganization(ctx, {
    org: { name: 'Onboarding Organization' },
  });
  expect(repeated.created).toEqual({ organization: false, owner: false });
});
