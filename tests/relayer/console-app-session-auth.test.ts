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
        projectId: 'proj-dev',
        environmentId: 'env-dev',
      },
    });
    expect(listMembersCalls).toBe(1);
    expect(auditEvents).toHaveLength(1);
    expect(auditEvents[0]?.action).toBe('member.owner.bootstrap');
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
