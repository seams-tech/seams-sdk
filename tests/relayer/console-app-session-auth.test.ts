import { expect, test } from '@playwright/test';
import { createInMemoryConsoleOrgProjectEnvService } from '../../packages/console-server-ts/src/orgProjectEnv/service';
import {
  createInMemoryConsoleOrganizationAccessService,
  type ConsoleOrganizationAccessService,
} from '../../packages/console-server-ts/src/teamRbac/service';
import { createAppSessionConsoleAuthAdapter } from '../../packages/console-server-ts/src/router/consoleAppSessionAuth';
import { toConsoleSessionResponseClaims } from '../../packages/console-server-ts/src/router/consoleAuth';
import { makeSessionAdapter } from './helpers';

function makeAppSessionClaims(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    kind: 'app_session_v1',
    sub: 'oidc:https://accounts.google.com:user-123',
    appSessionVersion: 'v1',
    provider: 'oidc',
    email: 'user-123@example.com',
    name: 'User 123',
    ...overrides,
  };
}

function validAppSessionVersion() {
  return {
    validateAppSessionVersion: async () => ({ ok: true as const }),
  };
}

async function seedOwner(input: {
  readonly orgProjectEnv: ReturnType<typeof createInMemoryConsoleOrgProjectEnvService>;
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
}): Promise<void> {
  await input.orgProjectEnv.upsertOrganization(
    { orgId: input.orgId, actorUserId: input.userId },
    { name: 'Acme', slug: 'acme' },
  );
  await input.organizationAccess.bootstrapInitialOwner({
    orgId: input.orgId,
    userId: input.userId,
    email: input.email,
    displayName: 'Acme Owner',
  });
}

test.describe('console app-session auth adapter', () => {
  test('preserves app-session validation failures', async () => {
    const organizationAccess = createInMemoryConsoleOrganizationAccessService();
    const parseFailure = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({ ok: false }),
      }),
      authService: validAppSessionVersion(),
      organizationAccess,
    });
    await expect(parseFailure.authenticate({})).resolves.toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'Missing or invalid app session',
      status: 401,
    });

    const versionFailure = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({ orgId: 'org_acme' }),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({
          ok: false,
          code: 'invalid_session_version',
          message: 'Expired app session',
        }),
      },
      organizationAccess,
    });
    await expect(versionFailure.authenticate({})).resolves.toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'Expired app session',
      status: 401,
    });
  });

  test('loads current owner authorization and emits no role array', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const organizationAccess = createInMemoryConsoleOrganizationAccessService();
    const orgId = 'org_acme_owner';
    const userId = 'oidc:https://accounts.google.com:user-123';
    await seedOwner({
      orgProjectEnv,
      organizationAccess,
      orgId,
      userId,
      email: 'user-123@example.com',
    });
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({
            orgId,
            role: 'MEMBER',
            roles: ['member'],
            authorizationVersion: 1,
          }),
        }),
      }),
      authService: validAppSessionVersion(),
      organizationAccess,
      provisioning: { orgProjectEnv },
    });

    const result = await auth.authenticate({});
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.claims).toMatchObject({
      orgId,
      userId,
      role: 'OWNER',
      projectAccess: { kind: 'all' },
      platformSupport: false,
    });
    expect(result.claims.authorizationVersion).toBeGreaterThan(0);
    expect('roles' in result.claims).toBe(false);

    const response = toConsoleSessionResponseClaims(result.claims);
    expect(response).toMatchObject({
      orgId,
      userId,
      role: 'OWNER',
      projectAccess: [],
      platformSupport: false,
    });
  });

  test('enforces current member project access and suspension on every request', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const organizationAccess = createInMemoryConsoleOrganizationAccessService();
    const orgId = 'org_acme_member';
    const ownerUserId = 'owner-user';
    const memberUserId = 'member-user';
    const memberEmail = 'member@example.com';
    await seedOwner({
      orgProjectEnv,
      organizationAccess,
      orgId,
      userId: ownerUserId,
      email: 'owner@example.com',
    });
    await orgProjectEnv.createProject(
      { orgId, actorUserId: ownerUserId },
      {
        id: 'project_allowed',
        name: 'Allowed Project',
        liveEnvironmentsEnabled: false,
      },
    );
    const invitation = await organizationAccess.invite(
      { orgId, actorUserId: ownerUserId },
      {
        email: memberEmail,
        role: 'MEMBER',
        projectAccess: [{ projectId: 'project_allowed', accessLevel: 'viewer' }],
      },
    );
    const membership = await organizationAccess.acceptInvitation(
      { userId: memberUserId, verifiedEmail: memberEmail },
      invitation.invitation.id,
      { token: invitation.token },
    );
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({
            sub: memberUserId,
            email: memberEmail,
            orgId,
            projectId: 'project_not_allowed',
          }),
        }),
      }),
      authService: validAppSessionVersion(),
      organizationAccess,
      provisioning: { orgProjectEnv },
    });

    const activeResult = await auth.authenticate({});
    expect(activeResult.ok).toBe(true);
    if (!activeResult.ok) return;
    expect(activeResult.claims).toMatchObject({
      role: 'MEMBER',
      projectId: 'project_allowed',
      adminPermissions: [],
      projectAccess: {
        kind: 'assigned',
        assignments: [{ projectId: 'project_allowed', accessLevel: 'viewer' }],
      },
    });

    await organizationAccess.suspendMembership(
      { orgId, actorUserId: ownerUserId },
      membership.id,
    );
    await expect(auth.authenticate({})).resolves.toEqual({
      ok: false,
      code: 'forbidden',
      message: 'No active organization membership',
      status: 403,
    });
  });

  test('bootstraps the initial OIDC organization owner and platform-support flag', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const organizationAccess = createInMemoryConsoleOrganizationAccessService();
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({
            sub: 'new-oidc-user',
            email: 'support@example.com',
          }),
        }),
      }),
      authService: validAppSessionVersion(),
      organizationAccess,
      platformSupportEmails: 'support@example.com',
      provisioning: { orgProjectEnv },
    });

    const result = await auth.authenticate({});
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.claims).toMatchObject({
      userId: 'new-oidc-user',
      role: 'OWNER',
      platformSupport: true,
      projectAccess: { kind: 'all' },
    });
    expect(result.claims.orgId).toMatch(/^org_[a-z0-9]{12}$/);

    const authorization = await organizationAccess.lookupAuthorization({
      orgId: result.claims.orgId,
      userId: 'new-oidc-user',
    });
    expect(authorization).toMatchObject({
      kind: 'authorized',
      role: 'OWNER',
    });
  });

  test('bootstraps an allowlisted OIDC owner for an existing ownerless organization', async () => {
    const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
    const organizationAccess = createInMemoryConsoleOrganizationAccessService();
    const orgId = 'org_staging';
    const userId = 'google:owner-subject';
    await orgProjectEnv.upsertOrganization(
      { orgId, actorUserId: 'deployment-bootstrap' },
      { name: 'Staging', slug: 'staging' },
    );
    const rejectedAuth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({
            sub: 'google:unapproved-subject',
            email: 'unapproved@example.com',
            orgId,
          }),
        }),
      }),
      authService: validAppSessionVersion(),
      organizationAccess,
      defaultOrgId: orgId,
      initialOwnerEmails: 'owner@example.com,backup-owner@example.com',
      provisioning: { orgProjectEnv },
    });
    await expect(rejectedAuth.authenticate({})).resolves.toEqual({
      ok: false,
      code: 'forbidden',
      message: 'No active organization membership',
      status: 403,
    });

    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({
            sub: userId,
            email: 'owner@example.com',
            orgId,
          }),
        }),
      }),
      authService: validAppSessionVersion(),
      organizationAccess,
      defaultOrgId: orgId,
      initialOwnerEmails: 'owner@example.com,backup-owner@example.com',
      provisioning: { orgProjectEnv },
    });

    const result = await auth.authenticate({});
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.claims).toMatchObject({
      orgId,
      userId,
      email: 'owner@example.com',
      role: 'OWNER',
    });
    await expect(
      organizationAccess.lookupAuthorization({ orgId, userId }),
    ).resolves.toMatchObject({
      kind: 'authorized',
      role: 'OWNER',
    });
  });
});
