import { expect, test } from '@playwright/test';
import { createInMemoryConsoleOrgProjectEnvService } from '../../server/src/console/orgProjectEnv/service';
import { createInMemoryConsoleTeamRbacService } from '../../server/src/console/teamRbac/service';
import { isConsoleAccountError } from '../../server/src/console/account/errors';
import {
  parseCreateConsoleAccountOrganizationRequest,
  parsePatchConsoleAccountProfileRequest,
  parseTransferConsoleAccountOrganizationOwnerRequest,
  parseUpdateConsoleAccountOrganizationRequest,
} from '../../server/src/console/account/requests';
import { createInMemoryConsoleAccountService } from '../../server/src/console/account/service';

async function expectAccountError(
  fn: () => unknown | Promise<unknown>,
  expectedCode: string,
): Promise<void> {
  let caught: unknown;
  try {
    await fn();
  } catch (error: unknown) {
    caught = error;
  }
  expect(caught).toBeTruthy();
  expect(isConsoleAccountError(caught)).toBe(true);
  expect(String((caught as { code?: unknown } | null)?.code || '')).toBe(expectedCode);
}

test.describe('console account parser and service semantics', () => {
  test('request parsers normalize mutable inputs and reject invalid bodies', async () => {
    expect(
      parsePatchConsoleAccountProfileRequest({
        displayName: '  Alice  ',
        primaryEmail: ' ALICE@Example.COM ',
        addBackupEmail: ' Recovery@Example.com ',
      }),
    ).toEqual({
      displayName: 'Alice',
      primaryEmail: 'alice@example.com',
      addBackupEmail: 'recovery@example.com',
    });

    await expectAccountError(
      async () => parsePatchConsoleAccountProfileRequest({}),
      'invalid_body',
    );
    await expectAccountError(
      async () => parsePatchConsoleAccountProfileRequest({ primaryEmail: 'not-an-email' }),
      'invalid_body',
    );

    expect(
      parseCreateConsoleAccountOrganizationRequest({
        name: '  Northwind Labs  ',
        id: 'org_northwind:dev',
        slug: ' northwind-labs ',
      }),
    ).toEqual({
      name: 'Northwind Labs',
      id: 'org_northwind:dev',
      slug: 'northwind-labs',
    });
    await expectAccountError(
      async () =>
        parseCreateConsoleAccountOrganizationRequest({
          name: 'Northwind Labs',
          id: 'org invalid id',
        }),
      'invalid_body',
    );

    await expectAccountError(
      async () => parseUpdateConsoleAccountOrganizationRequest({}),
      'invalid_body',
    );
    expect(
      parseUpdateConsoleAccountOrganizationRequest({
        name: '  Northwind Labs Renamed  ',
      }),
    ).toEqual({
      name: 'Northwind Labs Renamed',
    });

    expect(
      parseTransferConsoleAccountOrganizationOwnerRequest({
        targetUserId: '  user_owner_target  ',
      }),
    ).toEqual({
      targetUserId: 'user_owner_target',
    });
    await expectAccountError(
      async () => parseTransferConsoleAccountOrganizationOwnerRequest({}),
      'invalid_body',
    );
  });

  test('in-memory service enforces OIDC primary-email boundaries and list semantics', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const teamRbac = createInMemoryConsoleTeamRbacService();
    const service = createInMemoryConsoleAccountService({
      orgProjectEnv,
      teamRbac,
    });

    const adminCtx = {
      userId: 'user_account_service_admin',
      orgId: 'org_account_service_current',
      roles: ['admin'],
      email: 'oidc-user@example.com',
      name: 'OIDC User',
      provider: 'oidc',
    };

    await orgProjectEnv.upsertOrganization(
      {
        orgId: adminCtx.orgId,
        actorUserId: adminCtx.userId,
        roles: [],
      },
      { name: 'Current Org', slug: 'current-org' },
    );
    await teamRbac.bootstrapOwner({
      orgId: adminCtx.orgId,
      actorUserId: adminCtx.userId,
      roles: ['owner'],
      actorEmail: adminCtx.email,
      actorDisplayName: adminCtx.name,
    });

    await expectAccountError(
      async () =>
        service.updateProfile(adminCtx, {
          primaryEmail: 'new-primary@example.com',
        }),
      'primary_email_read_only',
    );

    const updated = await service.updateProfile(adminCtx, {
      displayName: 'OIDC User Renamed',
      addBackupEmail: ' recovery@example.com ',
    });
    expect(updated.displayName).toBe('OIDC User Renamed');
    expect(updated.primaryEmail).toBe('oidc-user@example.com');
    expect(updated.canEditPrimaryEmail).toBe(false);
    expect(updated.backupEmails).toHaveLength(1);
    expect(updated.backupEmails[0]?.email).toBe('recovery@example.com');

    const beforeCreate = await service.listOrganizations(adminCtx);
    expect(beforeCreate.map((entry) => entry.id)).toEqual([adminCtx.orgId]);

    await service.createOrganization(adminCtx, {
      id: 'org_account_service_created',
      name: 'Created Org',
      slug: 'created-org',
    });

    const afterCreate = await service.listOrganizations(adminCtx);
    expect(afterCreate.some((entry) => entry.id === adminCtx.orgId)).toBe(true);
    expect(afterCreate.some((entry) => entry.id === 'org_account_service_created')).toBe(true);

    const memberClaimsCtx = {
      ...adminCtx,
      roles: ['member'],
    };
    const asMember = await service.listOrganizations(memberClaimsCtx);
    expect(asMember.some((entry) => entry.id === adminCtx.orgId)).toBe(false);
    expect(asMember.some((entry) => entry.id === 'org_account_service_created')).toBe(true);
  });
});
