import { test, expect } from '@playwright/test';
import { createInMemoryConsoleOrgProjectEnvService } from '@server/console/orgProjectEnv';

test.describe('console org/project/environment default organization resolution', () => {
  test('in-memory service returns the only persisted organization', async () => {
    const service = createInMemoryConsoleOrgProjectEnvService();
    await service.upsertOrganization(
      {
        orgId: 'org_watchbook',
        actorUserId: 'user-single-org',
        roles: ['admin'],
      },
      {
        name: 'Watchbook',
      },
    );

    await expect(service.findDefaultOrganization()).resolves.toMatchObject({
      id: 'org_watchbook',
      name: 'Watchbook',
    });
  });

  test('in-memory service returns null when persisted organizations are ambiguous', async () => {
    const service = createInMemoryConsoleOrgProjectEnvService();
    for (const orgId of ['org_watchbook', 'org_platform']) {
      await service.upsertOrganization(
        {
          orgId,
          actorUserId: 'user-multi-org',
          roles: ['admin'],
        },
        {
          name: orgId,
        },
      );
    }

    await expect(service.findDefaultOrganization()).resolves.toBeNull();
  });
});
