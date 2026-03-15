import { test, expect } from '@playwright/test';
import {
  createAppSessionConsoleAuthAdapter,
  mergeConsoleOrgScopedRoleLists,
  normalizeConsoleOrgScopedRoleList,
} from '@server/router/consoleAppSessionAuth';
import { makeSessionAdapter } from './helpers';

function makeAppSessionClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'app_session_v1',
    sub: 'oidc:https://accounts.google.com:user-123',
    appSessionVersion: 'v1',
    ...overrides,
  };
}

test.describe('console app-session auth adapter', () => {
  test('normalizeConsoleOrgScopedRoleList filters, lowercases, and dedupes', async () => {
    expect(normalizeConsoleOrgScopedRoleList('admin, OWNER, invalid, admin, billing_write')).toEqual([
      'admin',
      'owner',
      'billing_write',
    ]);
    expect(normalizeConsoleOrgScopedRoleList(['owner', 'ADMIN', 'owner', 'x'])).toEqual([
      'owner',
      'admin',
    ]);
  });

  test('mergeConsoleOrgScopedRoleLists merges in order with dedupe', async () => {
    expect(
      mergeConsoleOrgScopedRoleLists(
        ['owner', 'invalid', 'admin'],
        ['admin_manage_members', 'owner', 'ADMIN'],
      ),
    ).toEqual(['owner', 'admin', 'admin_manage_members']);
  });

  test('authenticate returns 401 when session parse fails', async () => {
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({ ok: false }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'Missing or invalid app session',
      status: 401,
    });
  });

  test('authenticate returns 401 when claims are not app_session_v1', async () => {
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: { kind: 'other', sub: 'user-1', appSessionVersion: 'v1' },
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'Invalid app session',
      status: 401,
    });
  });

  test('authenticate returns 401 when app session version validation fails', async () => {
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims(),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({
          ok: false,
          code: 'invalid_session_version',
          message: 'Expired app session',
        }),
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: false,
      code: 'unauthorized',
      message: 'Expired app session',
      status: 401,
    });
  });

  test('authenticate returns 403 when no fallback roles and no provisioning membership', async () => {
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims(),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: false,
      code: 'forbidden',
      message: 'No console roles assigned',
      status: 403,
    });
  });

  test('authenticate returns normalized fallback roles and default scoped ids', async () => {
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims(),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
      defaultOrgId: 'org-dev',
      defaultProjectId: 'proj-dev',
      defaultEnvironmentId: 'env-dev',
      fallbackRoles: ['ADMIN', 'owner', 'admin', 'invalid'],
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: true,
      claims: {
        orgId: 'org-dev',
        userId: 'oidc:https://accounts.google.com:user-123',
        roles: ['admin', 'owner'],
        projectId: 'proj-dev',
        environmentId: 'env-dev',
      },
    });
  });

  test('authenticate resolves default org from storage when there is one persisted organization', async () => {
    const persistedOrg = {
      id: 'org_watchbook',
      name: 'Watchbook',
      slug: 'watchbook',
      status: 'ACTIVE' as const,
      createdAt: new Date(0).toISOString(),
      updatedAt: new Date(0).toISOString(),
    };
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims(),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
      fallbackRoles: ['admin'],
      provisioning: {
        orgProjectEnv: {
          findDefaultOrganization: async () => persistedOrg,
          getOrganization: async () => persistedOrg,
          findOrganizationForScope: async () => null,
          listProjects: async () => [],
          listEnvironments: async () => [],
        } as any,
        logger: { warn() {} },
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: true,
      claims: {
        orgId: 'org_watchbook',
        userId: 'oidc:https://accounts.google.com:user-123',
        roles: ['admin'],
      },
    });
  });

  test('authenticate appends platform_admin for allowlisted SSO email', async () => {
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({
            email: 'n6378056@gmail.com',
          }),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
      defaultOrgId: 'org-dev',
      fallbackRoles: ['admin'],
      platformAdminEmails: 'n6378056@gmail.com, someone@example.com',
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: true,
      claims: {
        orgId: 'org-dev',
        userId: 'oidc:https://accounts.google.com:user-123',
        roles: ['admin', 'platform_admin'],
        email: 'n6378056@gmail.com',
      },
    });
  });

  test('authenticate repairs stale org claims from active scope before provisioning', async () => {
    const resolvedOrgId = 'org_migrated_123';
    const upsertedOrgIds: string[] = [];
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({
            orgId: 'org-dev',
            projectId: 'proj_mmggz8jp_v9pft0',
            environmentId: 'proj_mmggz8jp_v9pft0:dev',
          }),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
      provisioning: {
        bootstrapRoles: ['admin'],
        orgProjectEnv: {
          getOrganization: async (ctx: { orgId: string }) => {
            if (ctx.orgId === resolvedOrgId) {
              return {
                id: resolvedOrgId,
                name: 'tatchi-org-test',
                slug: 'tatchi-org-test',
                status: 'ACTIVE',
                createdAt: new Date(0).toISOString(),
                updatedAt: new Date(0).toISOString(),
              };
            }
            const error = new Error('not found') as Error & { code?: string };
            error.code = 'organization_not_found';
            throw error;
          },
          findOrganizationForScope: async (request: {
            projectId?: string;
            environmentId?: string;
          }) =>
            request.projectId === 'proj_mmggz8jp_v9pft0' &&
            request.environmentId === 'proj_mmggz8jp_v9pft0:dev'
              ? {
                  id: resolvedOrgId,
                  name: 'tatchi-org-test',
                  slug: 'tatchi-org-test',
                  status: 'ACTIVE',
                  createdAt: new Date(0).toISOString(),
                  updatedAt: new Date(0).toISOString(),
                }
              : null,
          listProjects: async (ctx: { orgId: string }) => {
            expect(ctx.orgId).toBe(resolvedOrgId);
            return [
              {
                id: 'proj_mmggz8jp_v9pft0',
                orgId: resolvedOrgId,
                name: 'Project',
                slug: 'project',
                status: 'ACTIVE',
                environmentCount: 1,
                createdAt: new Date(0).toISOString(),
                updatedAt: new Date(0).toISOString(),
              },
            ];
          },
          listEnvironments: async (ctx: { orgId: string }) => {
            expect(ctx.orgId).toBe(resolvedOrgId);
            return [
              {
                id: 'proj_mmggz8jp_v9pft0:dev',
                orgId: resolvedOrgId,
                projectId: 'proj_mmggz8jp_v9pft0',
                key: 'dev',
                name: 'Development',
                status: 'ACTIVE',
                createdAt: new Date(0).toISOString(),
                updatedAt: new Date(0).toISOString(),
              },
            ];
          },
          upsertOrganization: async (ctx: { orgId: string }) => {
            upsertedOrgIds.push(ctx.orgId);
            return {
              id: ctx.orgId,
              name: 'unexpected',
              slug: 'unexpected',
              status: 'ACTIVE',
              createdAt: new Date(0).toISOString(),
              updatedAt: new Date(0).toISOString(),
            };
          },
        } as any,
        teamRbac: {
          listMembers: async (ctx: { orgId: string }) => {
            expect(ctx.orgId).toBe(resolvedOrgId);
            return [];
          },
          inviteMember: async (_ctx: unknown, req: Record<string, unknown>) => ({
            id: 'mbr-1',
            orgId: resolvedOrgId,
            userId: String(req.userId || ''),
            email: String(req.email || ''),
            status: 'ACTIVE',
            roles: req.roles,
          }),
          updateMemberRoles: async () => null,
        } as any,
        logger: { warn() {} },
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: true,
      claims: {
        orgId: resolvedOrgId,
        userId: 'oidc:https://accounts.google.com:user-123',
        roles: ['admin'],
        projectId: 'proj_mmggz8jp_v9pft0',
        environmentId: 'proj_mmggz8jp_v9pft0:dev',
      },
    });
    expect(upsertedOrgIds).toEqual([]);
  });

  test('authenticate repairs stale environment claims against active environments', async () => {
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({
            orgId: 'org-dev',
            projectId: 'proj_mmggz8jp_v9pft0',
            environmentId: 'org-dev:proj_mmggz8jp_v9pft0:dev',
          }),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
      fallbackRoles: ['admin'],
      provisioning: {
        orgProjectEnv: {
          getOrganization: async () => ({
            id: 'org-dev',
            name: 'Org',
            slug: 'org',
            status: 'ACTIVE',
            createdAt: new Date(0).toISOString(),
            updatedAt: new Date(0).toISOString(),
          }),
          findOrganizationForScope: async () => null,
          listProjects: async () => [
            {
              id: 'proj_mmggz8jp_v9pft0',
              orgId: 'org-dev',
              name: 'Project',
              slug: 'project',
              status: 'ACTIVE',
              environmentCount: 3,
              createdAt: new Date(0).toISOString(),
              updatedAt: new Date(0).toISOString(),
            },
          ],
          listEnvironments: async () => [
            {
              id: 'proj_mmggz8jp_v9pft0:dev',
              orgId: 'org-dev',
              projectId: 'proj_mmggz8jp_v9pft0',
              key: 'dev',
              name: 'Development',
              status: 'ACTIVE',
              createdAt: new Date(0).toISOString(),
              updatedAt: new Date(0).toISOString(),
            },
            {
              id: 'proj_mmggz8jp_v9pft0:prod',
              orgId: 'org-dev',
              projectId: 'proj_mmggz8jp_v9pft0',
              key: 'prod',
              name: 'Production',
              status: 'ACTIVE',
              createdAt: new Date(0).toISOString(),
              updatedAt: new Date(0).toISOString(),
            },
          ],
        } as any,
        logger: { warn() {} },
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: true,
      claims: {
        orgId: 'org-dev',
        userId: 'oidc:https://accounts.google.com:user-123',
        roles: ['admin'],
        projectId: 'proj_mmggz8jp_v9pft0',
        environmentId: 'proj_mmggz8jp_v9pft0:dev',
      },
    });
  });

  test('provisioning bootstraps first login membership and appends audit event', async () => {
    let listMembersCalls = 0;
    const auditEvents: Array<Record<string, unknown>> = [];
    const teamRbac = {
      listMembers: async () => {
        listMembersCalls += 1;
        return [];
      },
      inviteMember: async (_ctx: unknown, req: Record<string, unknown>) => ({
        id: 'mbr-1',
        orgId: 'org-dev',
        userId: String(req.userId || ''),
        email: String(req.email || ''),
        status: 'ACTIVE',
        roles: req.roles,
      }),
      updateMemberRoles: async () => null,
    } as any;
    const orgProjectEnv = {
      getOrganization: async () => {
        const error = new Error('not found') as Error & { code?: string };
        error.code = 'organization_not_found';
        throw error;
      },
      upsertOrganization: async () => ({ id: 'org-dev' }),
    } as any;
    const audit = {
      appendEvent: async (_ctx: unknown, req: Record<string, unknown>) => {
        auditEvents.push(req);
      },
    } as any;

    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims({ email: 'alice@example.com', name: 'Alice Example' }),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
      defaultOrgId: 'org-dev',
      defaultProjectId: 'proj-dev',
      defaultEnvironmentId: 'env-dev',
      fallbackRoles: [],
      provisioning: {
        bootstrapRoles: ['owner', 'admin'],
        orgProjectEnv,
        teamRbac,
        audit,
        logger: { warn() {} },
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: true,
      claims: {
        orgId: 'org-dev',
        userId: 'oidc:https://accounts.google.com:user-123',
        roles: ['owner', 'admin'],
        email: 'alice@example.com',
        name: 'Alice Example',
        projectId: 'proj-dev',
        environmentId: 'env-dev',
      },
    });
    expect(listMembersCalls).toBe(1);
    expect(auditEvents).toHaveLength(1);
    expect(auditEvents[0]?.action).toBe('member.owner.bootstrap');
  });

  test('authenticate keeps the session orgless when provisioning cannot resolve an organization from storage', async () => {
    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims(),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
      provisioning: {
        bootstrapRoles: ['admin'],
        orgProjectEnv: {
          findDefaultOrganization: async () => null,
          findOrganizationForScope: async () => null,
        } as any,
        teamRbac: {} as any,
        logger: { warn() {} },
      },
    });

    const out = await auth.authenticate({});
    expect(out).toEqual({
      ok: true,
      claims: {
        orgId: '',
        userId: 'oidc:https://accounts.google.com:user-123',
        roles: [],
      },
    });
  });

  test('concurrent provisioning requests for same user/org use one in-flight invite', async () => {
    let inviteCalls = 0;
    let listMembersCalls = 0;
    const delayMs = 30;
    const teamRbac = {
      listMembers: async () => {
        listMembersCalls += 1;
        return [];
      },
      inviteMember: async (_ctx: unknown, req: Record<string, unknown>) => {
        inviteCalls += 1;
        await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
        return {
          id: 'mbr-1',
          orgId: 'org-dev',
          userId: String(req.userId || ''),
          email: String(req.email || ''),
          status: 'ACTIVE',
          roles: req.roles,
        };
      },
      updateMemberRoles: async () => null,
    } as any;

    const auth = createAppSessionConsoleAuthAdapter({
      session: makeSessionAdapter({
        parse: async () => ({
          ok: true,
          claims: makeAppSessionClaims(),
        }),
      }),
      authService: {
        validateAppSessionVersion: async () => ({ ok: true }),
      },
      defaultOrgId: 'org-dev',
      defaultProjectId: 'proj-dev',
      defaultEnvironmentId: 'env-dev',
      fallbackRoles: [],
      provisioning: {
        bootstrapRoles: ['admin'],
        teamRbac,
        logger: { warn() {} },
      },
    });

    const [first, second] = await Promise.all([auth.authenticate({}), auth.authenticate({})]);
    expect(first).toEqual(second);
    expect(inviteCalls).toBe(1);
    expect(listMembersCalls).toBe(1);
  });
});
