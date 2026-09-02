import { expect, test } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleAccountService,
  createInMemoryConsoleOrganizationAccessService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleWalletService,
  type ActiveOrganizationAuthorization,
  type ConsoleAccountService,
  type ConsoleAuthAdapter,
  type ConsoleAuthClaims,
  type ConsoleOrganizationAccessService,
  type ConsoleOrgProjectEnvService,
} from '@seams-internal/wallet-console-server/router/express-adaptor';
import { createCloudflareConsoleRouter } from '@seams-internal/wallet-console-server/router/cloudflare-adaptor';
import type { SessionAdapter } from '@seams/wallet-server/router/express';
import { callCf, fetchJson, makeConsoleAuthAdapter, startExpressRouter } from './helpers';

const CURRENT_USER_ID = 'user_current';
const CURRENT_EMAIL = 'owner@example.com';
const CURRENT_NAME = 'Owner User';

type RouterMode = 'express' | 'cloudflare';

interface AccountRouteFixture {
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly account: ConsoleAccountService;
}

interface ConsoleRouteResponse {
  readonly status: number;
  readonly json: Record<string, unknown> | null;
  readonly cookie: string;
}

class ContextSwitchSession implements SessionAdapter {
  signedSubject: string | null = null;
  signedClaims: Record<string, unknown> | null = null;

  async parse(): Promise<{
    readonly ok: true;
    readonly claims: Record<string, unknown>;
  }> {
    return {
      ok: true,
      claims: {
        sub: CURRENT_USER_ID,
        userId: CURRENT_USER_ID,
        kind: 'app_session_v1',
        appSessionVersion: 'v1',
        email: CURRENT_EMAIL,
        name: CURRENT_NAME,
        orgId: 'org_current',
        roles: ['owner'],
        projectId: 'proj_current',
        environmentId: 'proj_current:dev',
      },
    };
  }

  async signJwt(subject: string, extra: Record<string, unknown> = {}): Promise<string> {
    this.signedSubject = subject;
    this.signedClaims = extra;
    return 'switched-session-token';
  }

  buildSetCookie(token: string): string {
    return `seams-jwt=${token}; Path=/; HttpOnly`;
  }

  buildClearCookie(): string {
    return 'seams-jwt=; Path=/; Max-Age=0';
  }

  async refresh(): Promise<{
    readonly ok: false;
    readonly code: string;
    readonly message: string;
  }> {
    return { ok: false, code: 'not_eligible', message: 'not eligible' };
  }
}

function createAccountRouteFixture(): AccountRouteFixture {
  const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
  const organizationAccess = createInMemoryConsoleOrganizationAccessService();
  const account = createInMemoryConsoleAccountService({
    orgProjectEnv,
    organizationAccess,
    wallets: createInMemoryConsoleWalletService(),
  });
  return { orgProjectEnv, organizationAccess, account };
}

function assertNever(value: never): never {
  throw new Error(`Unhandled authorization role: ${JSON.stringify(value)}`);
}

function toConsoleAuthClaims(authorization: ActiveOrganizationAuthorization): ConsoleAuthClaims {
  switch (authorization.role) {
    case 'OWNER':
      return {
        userId: authorization.userId,
        orgId: authorization.orgId,
        membershipId: authorization.membershipId,
        authorizationVersion: authorization.authorizationVersion,
        role: 'OWNER',
        adminPermissions: authorization.adminPermissions,
        projectAccess: { kind: 'all' },
        platformSupport: false,
        email: CURRENT_EMAIL,
        name: CURRENT_NAME,
        provider: 'password',
      };
    case 'ADMIN':
      return {
        userId: authorization.userId,
        orgId: authorization.orgId,
        membershipId: authorization.membershipId,
        authorizationVersion: authorization.authorizationVersion,
        role: 'ADMIN',
        adminPermissions: authorization.adminPermissions,
        projectAccess: { kind: 'all' },
        platformSupport: false,
        email: CURRENT_EMAIL,
        name: CURRENT_NAME,
        provider: 'password',
      };
    case 'MEMBER':
      return {
        userId: authorization.userId,
        orgId: authorization.orgId,
        membershipId: authorization.membershipId,
        authorizationVersion: authorization.authorizationVersion,
        role: 'MEMBER',
        adminPermissions: [],
        projectAccess: {
          kind: 'assigned',
          assignments: authorization.projectAccess.assignments,
        },
        platformSupport: false,
        email: CURRENT_EMAIL,
        name: CURRENT_NAME,
        provider: 'password',
      };
    default:
      return assertNever(authorization);
  }
}

async function loadCurrentClaims(
  organizationAccess: ConsoleOrganizationAccessService,
): Promise<ConsoleAuthClaims> {
  const authorization = await organizationAccess.lookupAuthorization({
    orgId: 'org_current',
    userId: CURRENT_USER_ID,
  });
  if (!authorization || authorization.kind === 'denied') {
    throw new Error('Expected current organization authorization');
  }
  return toConsoleAuthClaims(authorization);
}

async function seedOwnerOrganization(input: {
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly displayName: string;
  readonly organizationName: string;
}): Promise<string> {
  await input.orgProjectEnv.upsertOrganization(
    { orgId: input.orgId, actorUserId: input.userId },
    { name: input.organizationName },
  );
  const membership = await input.organizationAccess.bootstrapInitialOwner({
    orgId: input.orgId,
    userId: input.userId,
    email: input.email,
    displayName: input.displayName,
  });
  return membership.id;
}

async function createProject(input: {
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly orgId: string;
  readonly actorUserId: string;
  readonly projectId: string;
}): Promise<void> {
  await input.orgProjectEnv.createProject(
    { orgId: input.orgId, actorUserId: input.actorUserId },
    {
      id: input.projectId,
      name: `${input.projectId} Project`,
      liveEnvironmentsEnabled: true,
    },
  );
}

async function addCurrentUserAsProjectMember(input: {
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly orgId: string;
  readonly ownerUserId: string;
  readonly projectId: string;
}): Promise<string> {
  const issued = await input.organizationAccess.invite(
    { orgId: input.orgId, actorUserId: input.ownerUserId },
    {
      email: CURRENT_EMAIL,
      role: 'MEMBER',
      projectAccess: [{ projectId: input.projectId, accessLevel: 'viewer' }],
    },
  );
  const membership = await input.organizationAccess.acceptInvitation(
    { userId: CURRENT_USER_ID, verifiedEmail: CURRENT_EMAIL },
    issued.invitation.id,
    { token: issued.token },
  );
  return membership.id;
}

function readObjectArray(value: unknown, field: string): readonly Record<string, unknown>[] {
  if (
    !Array.isArray(value) ||
    !value.every((entry) => typeof entry === 'object' && entry !== null && !Array.isArray(entry))
  ) {
    throw new Error(`Expected ${field} to be an array of objects`);
  }
  return value;
}

function requireOrganization(
  organizations: readonly Record<string, unknown>[],
  orgId: string,
): Record<string, unknown> {
  const organization = organizations.find((entry) => entry.id === orgId);
  if (!organization) throw new Error(`Expected organization ${orgId}`);
  return organization;
}

async function callConsoleRoute(
  mode: RouterMode,
  input: {
    readonly auth: ConsoleAuthAdapter;
    readonly account: ConsoleAccountService;
    readonly session?: SessionAdapter | null;
    readonly method: string;
    readonly path: string;
    readonly body?: Record<string, unknown>;
  },
): Promise<ConsoleRouteResponse> {
  if (mode === 'express') {
    const router = createConsoleRouter({
      auth: input.auth,
      account: input.account,
      session: input.session ?? null,
    });
    const server = await startExpressRouter(router);
    try {
      const response = await fetchJson(`${server.baseUrl}${input.path}`, {
        method: input.method,
        headers: input.body ? { 'Content-Type': 'application/json' } : undefined,
        body: input.body ? JSON.stringify(input.body) : undefined,
      });
      return {
        status: response.status,
        json: response.json,
        cookie: String(response.headers.get('set-cookie') || ''),
      };
    } finally {
      await server.close();
    }
  }

  const handler = createCloudflareConsoleRouter({
    auth: input.auth,
    account: input.account,
    session: input.session ?? null,
  });
  const response = await callCf(handler, {
    method: input.method,
    path: input.path,
    body: input.body,
  });
  return {
    status: response.status,
    json: response.json,
    cookie: String(response.headers.get('set-cookie') || ''),
  };
}

for (const mode of ['express', 'cloudflare'] as const) {
  test.describe(`console account routes (${mode})`, () => {
    test('returns profile data and lists only organizations with precise access', async () => {
      const fixture = createAccountRouteFixture();
      const currentMembershipId = await seedOwnerOrganization({
        ...fixture,
        orgId: 'org_current',
        userId: CURRENT_USER_ID,
        email: CURRENT_EMAIL,
        displayName: CURRENT_NAME,
        organizationName: 'Current Org',
      });
      await seedOwnerOrganization({
        ...fixture,
        orgId: 'org_shared',
        userId: 'user_shared_owner',
        email: 'shared-owner@example.com',
        displayName: 'Shared Owner',
        organizationName: 'Shared Org',
      });
      await createProject({
        orgProjectEnv: fixture.orgProjectEnv,
        orgId: 'org_shared',
        actorUserId: 'user_shared_owner',
        projectId: 'proj_shared',
      });
      const memberMembershipId = await addCurrentUserAsProjectMember({
        organizationAccess: fixture.organizationAccess,
        orgId: 'org_shared',
        ownerUserId: 'user_shared_owner',
        projectId: 'proj_shared',
      });
      await seedOwnerOrganization({
        ...fixture,
        orgId: 'org_hidden',
        userId: 'user_hidden_owner',
        email: 'hidden-owner@example.com',
        displayName: 'Hidden Owner',
        organizationName: 'Hidden Org',
      });

      const auth = makeConsoleAuthAdapter(await loadCurrentClaims(fixture.organizationAccess));
      const profileResponse = await callConsoleRoute(mode, {
        auth,
        account: fixture.account,
        method: 'GET',
        path: '/console/account/profile',
      });
      expect(profileResponse.status).toBe(200);
      expect(profileResponse.json?.profile).toMatchObject({
        userId: CURRENT_USER_ID,
        displayName: CURRENT_NAME,
        primaryEmail: CURRENT_EMAIL,
      });

      const patchResponse = await callConsoleRoute(mode, {
        auth,
        account: fixture.account,
        method: 'PATCH',
        path: '/console/account/profile',
        body: {
          displayName: 'Updated Owner',
          addBackupEmail: 'backup@example.com',
        },
      });
      expect(patchResponse.status).toBe(200);
      expect(patchResponse.json?.profile).toMatchObject({
        displayName: 'Updated Owner',
        backupEmails: [{ email: 'backup@example.com', status: 'PENDING' }],
      });

      const listResponse = await callConsoleRoute(mode, {
        auth,
        account: fixture.account,
        method: 'GET',
        path: '/console/account/organizations',
      });
      expect(listResponse.status).toBe(200);
      const organizations = readObjectArray(listResponse.json?.organizations, 'organizations');
      expect(organizations.map((entry) => entry.id).sort()).toEqual(['org_current', 'org_shared']);
      expect(requireOrganization(organizations, 'org_current')).toMatchObject({
        membershipId: currentMembershipId,
        role: 'OWNER',
        adminPermissions: ['members.manage', 'projects.manage', 'billing.view', 'billing.manage'],
        projectAccess: { kind: 'all' },
        isCurrentOrg: true,
      });
      const sharedOrganization = requireOrganization(organizations, 'org_shared');
      expect(sharedOrganization).toMatchObject({
        membershipId: memberMembershipId,
        role: 'MEMBER',
        adminPermissions: [],
        projectAccess: {
          kind: 'assigned',
          assignments: [{ projectId: 'proj_shared', accessLevel: 'viewer' }],
        },
        isCurrentOrg: false,
      });
      expect('actorRoles' in sharedOrganization).toBe(false);
    });

    test('switches to member access and signs only current authorization claims', async () => {
      const fixture = createAccountRouteFixture();
      await seedOwnerOrganization({
        ...fixture,
        orgId: 'org_current',
        userId: CURRENT_USER_ID,
        email: CURRENT_EMAIL,
        displayName: CURRENT_NAME,
        organizationName: 'Current Org',
      });
      await seedOwnerOrganization({
        ...fixture,
        orgId: 'org_target',
        userId: 'user_target_owner',
        email: 'target-owner@example.com',
        displayName: 'Target Owner',
        organizationName: 'Target Org',
      });
      await createProject({
        orgProjectEnv: fixture.orgProjectEnv,
        orgId: 'org_target',
        actorUserId: 'user_target_owner',
        projectId: 'proj_target',
      });
      const targetMembershipId = await addCurrentUserAsProjectMember({
        organizationAccess: fixture.organizationAccess,
        orgId: 'org_target',
        ownerUserId: 'user_target_owner',
        projectId: 'proj_target',
      });

      const auth = makeConsoleAuthAdapter(await loadCurrentClaims(fixture.organizationAccess));
      const session = new ContextSwitchSession();
      const response = await callConsoleRoute(mode, {
        auth,
        account: fixture.account,
        session,
        method: 'POST',
        path: '/console/account/organizations/org_target/switch-context',
        body: {},
      });

      expect(response.status).toBe(200);
      expect(response.json?.context).toMatchObject({
        orgId: 'org_target',
        membershipId: targetMembershipId,
        role: 'MEMBER',
        adminPermissions: [],
        projectAccess: {
          kind: 'assigned',
          assignments: [{ projectId: 'proj_target', accessLevel: 'viewer' }],
        },
        platformSupport: false,
        projectId: 'proj_target',
        environmentId: 'proj_target:prod',
      });
      expect(session.signedSubject).toBe(CURRENT_USER_ID);
      expect(session.signedClaims).toMatchObject({
        userId: CURRENT_USER_ID,
        kind: 'app_session_v1',
        appSessionVersion: 'v1',
        email: CURRENT_EMAIL,
        name: CURRENT_NAME,
        orgId: 'org_target',
        membershipId: targetMembershipId,
        role: 'MEMBER',
        adminPermissions: [],
        projectAccess: {
          kind: 'assigned',
          assignments: [{ projectId: 'proj_target', accessLevel: 'viewer' }],
        },
        platformSupport: false,
        projectId: 'proj_target',
        environmentId: 'proj_target:prod',
      });
      if (!session.signedClaims) throw new Error('Expected signed session claims');
      expect('roles' in session.signedClaims).toBe(false);
      expect(response.cookie).toContain('switched-session-token');
    });

    test('allows owner update and delete while transfer-owner remains absent', async () => {
      const fixture = createAccountRouteFixture();
      await seedOwnerOrganization({
        ...fixture,
        orgId: 'org_current',
        userId: CURRENT_USER_ID,
        email: CURRENT_EMAIL,
        displayName: CURRENT_NAME,
        organizationName: 'Current Org',
      });
      await seedOwnerOrganization({
        ...fixture,
        orgId: 'org_target',
        userId: CURRENT_USER_ID,
        email: CURRENT_EMAIL,
        displayName: CURRENT_NAME,
        organizationName: 'Target Org',
      });

      const auth = makeConsoleAuthAdapter(await loadCurrentClaims(fixture.organizationAccess));
      const updateResponse = await callConsoleRoute(mode, {
        auth,
        account: fixture.account,
        method: 'PATCH',
        path: '/console/account/organizations/org_target',
        body: { name: 'Renamed Target', slug: 'renamed-target' },
      });
      expect(updateResponse.status).toBe(200);
      expect(updateResponse.json?.organization).toMatchObject({
        id: 'org_target',
        name: 'Renamed Target',
        slug: 'renamed-target',
        role: 'OWNER',
        projectAccess: { kind: 'all' },
      });

      const transferResponse = await callConsoleRoute(mode, {
        auth,
        account: fixture.account,
        method: 'POST',
        path: '/console/account/organizations/org_target/transfer-owner',
        body: { targetUserId: 'user_other' },
      });
      if (mode === 'express') {
        expect(transferResponse.status).toBe(404);
      } else {
        expect(transferResponse.status).toBe(500);
        expect(transferResponse.json).toMatchObject({
          code: 'route_auth_not_configured',
        });
      }
      expect(transferResponse.json?.transfer).toBeUndefined();

      const deleteResponse = await callConsoleRoute(mode, {
        auth,
        account: fixture.account,
        method: 'DELETE',
        path: '/console/account/organizations/org_target',
      });
      expect(deleteResponse.status).toBe(200);
      expect(deleteResponse.json?.deleted).toEqual({
        orgId: 'org_target',
        organizationName: 'Renamed Target',
      });
      await expect(
        fixture.organizationAccess.lookupAuthorization({
          orgId: 'org_target',
          userId: CURRENT_USER_ID,
        }),
      ).resolves.toBeNull();
    });
  });
}
