import { expect, test } from '@playwright/test';
import { isConsoleAccountError } from '../../packages/console-server-ts/src/account/errors';
import {
  parseCreateConsoleAccountOrganizationRequest,
  parsePatchConsoleAccountProfileRequest,
  parseUpdateConsoleAccountOrganizationRequest,
} from '../../packages/console-server-ts/src/account/requests';
import {
  createInMemoryConsoleAccountService,
  type ConsoleAccountContext,
} from '../../packages/console-server-ts/src/account/service';
import { createInMemoryConsoleOrgProjectEnvService } from '../../packages/console-server-ts/src/orgProjectEnv/service';
import {
  createInMemoryConsoleOrganizationAccessService,
  type ConsoleOrganizationAccessService,
} from '../../packages/console-server-ts/src/teamRbac/service';

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

async function buildOwnerAccountContext(input: {
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly name: string;
}): Promise<ConsoleAccountContext> {
  const authorization = await input.organizationAccess.lookupAuthorization({
    orgId: input.orgId,
    userId: input.userId,
  });
  if (!authorization || authorization.kind === 'denied' || authorization.role !== 'OWNER') {
    throw new Error('Expected an active owner authorization');
  }
  return {
    userId: input.userId,
    orgId: input.orgId,
    email: input.email,
    name: input.name,
    provider: 'oidc',
    projectId: null,
    environmentId: null,
    platformSupport: false,
    membershipId: authorization.membershipId,
    authorizationVersion: authorization.authorizationVersion,
    role: 'OWNER',
    adminPermissions: [...authorization.adminPermissions],
    projectAccess: { kind: 'all' },
  };
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
  });

  test('loads current authorization and bootstraps each created organization owner', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const organizationAccess = createInMemoryConsoleOrganizationAccessService();
    const userId = 'user_account_service_owner';
    const orgId = 'org_account_service_current';
    const email = 'oidc-user@example.com';
    const name = 'OIDC User';
    await orgProjectEnv.upsertOrganization(
      { orgId, actorUserId: userId },
      { name: 'Current Org', slug: 'current-org' },
    );
    await organizationAccess.bootstrapInitialOwner({
      orgId,
      userId,
      email,
      displayName: name,
    });
    const ctx = await buildOwnerAccountContext({
      organizationAccess,
      orgId,
      userId,
      email,
      name,
    });
    const service = createInMemoryConsoleAccountService({
      orgProjectEnv,
      organizationAccess,
    });

    await expectAccountError(
      async () =>
        service.updateProfile(ctx, {
          primaryEmail: 'new-primary@example.com',
        }),
      'primary_email_read_only',
    );
    const updated = await service.updateProfile(ctx, {
      displayName: 'OIDC User Renamed',
      addBackupEmail: ' recovery@example.com ',
    });
    expect(updated).toMatchObject({
      displayName: 'OIDC User Renamed',
      primaryEmail: email,
      canEditPrimaryEmail: false,
    });
    expect(updated.backupEmails).toHaveLength(1);

    const created = await service.createOrganization(ctx, {
      id: 'org_account_service_created',
      name: 'Created Org',
      slug: 'created-org',
    });
    expect(created).toMatchObject({
      id: 'org_account_service_created',
      role: 'OWNER',
      projectAccess: { kind: 'all' },
    });
    const createdAuthorization = await organizationAccess.lookupAuthorization({
      orgId: created.id,
      userId,
    });
    expect(createdAuthorization).toMatchObject({
      kind: 'authorized',
      role: 'OWNER',
    });

    const generated = await service.createOrganization(ctx, {
      name: 'Generated Org',
      slug: 'generated-org',
    });
    expect(generated.id).toMatch(/^org_[a-z0-9]{12}$/);

    const organizations = await service.listOrganizations(ctx);
    expect(organizations.map((organization) => organization.id).sort()).toEqual(
      [orgId, created.id, generated.id].sort(),
    );
    expect(organizations.every((organization) => organization.role === 'OWNER')).toBe(true);
  });
});
