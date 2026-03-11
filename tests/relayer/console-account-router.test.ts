import { expect, test } from '@playwright/test';
import {
  createConsoleRouter,
  createInMemoryConsoleAccountService,
  createInMemoryConsoleApiKeyService,
  createInMemoryConsoleOnboardingService,
  createInMemoryConsoleOrgProjectEnvService,
  createInMemoryConsoleTeamRbacService,
  createInMemoryConsoleWalletService,
  type ConsoleAuthAdapter,
  type ConsoleOrgProjectEnvService,
  type ConsoleTeamRbacService,
  type SessionAdapter,
} from '@server/router/express-adaptor';
import { createCloudflareConsoleRouter } from '@server/router/cloudflare-adaptor';
import { callCf, fetchJson, startExpressRouter } from './helpers';

function makeConsoleAuthAdapter(input: {
  userId: string;
  orgId: string;
  roles: string[];
  email?: string;
  name?: string;
  provider?: string;
  projectId?: string;
  environmentId?: string;
}): ConsoleAuthAdapter {
  return {
    authenticate: async () => ({
      ok: true,
      claims: {
        userId: input.userId,
        orgId: input.orgId,
        roles: input.roles,
        ...(input.email ? { email: input.email } : {}),
        ...(input.name ? { name: input.name } : {}),
        ...(input.provider ? { provider: input.provider } : {}),
        ...(input.projectId ? { projectId: input.projectId } : {}),
        ...(input.environmentId ? { environmentId: input.environmentId } : {}),
      },
    }),
  };
}

async function seedOrganization(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService;
  teamRbac: ConsoleTeamRbacService;
  orgId: string;
  actorUserId: string;
  actorEmail: string;
  actorDisplayName: string;
  organizationName: string;
  projectId?: string;
  environmentId?: string;
}): Promise<void> {
  const ctx = {
    orgId: input.orgId,
    actorUserId: input.actorUserId,
    roles: ['owner', 'admin'],
    actorEmail: input.actorEmail,
    actorDisplayName: input.actorDisplayName,
  };
  await input.orgProjectEnv.upsertOrganization(ctx, { name: input.organizationName });
  await input.teamRbac.bootstrapOwner(ctx);
  if (!input.projectId || !input.environmentId) return;
  await input.orgProjectEnv.createProject(ctx, {
    id: input.projectId,
    name: `${input.organizationName} Project`,
    liveEnvironmentsEnabled: true,
  });
}

function buildWalletSeed(input: {
  orgId: string;
  projectId: string;
  environmentId: string;
  walletId: string;
}) {
  const now = new Date('2026-03-10T00:00:00.000Z').toISOString();
  return {
    id: input.walletId,
    orgId: input.orgId,
    projectId: input.projectId,
    environmentId: input.environmentId,
    userId: 'wallet-user',
    externalRefId: `${input.walletId}-external`,
    address: '0x0000000000000000000000000000000000000001',
    chain: 'Ethereum' as const,
    walletType: 'EOA' as const,
    status: 'ACTIVE' as const,
    policyId: null,
    balanceMinor: 0,
    lastActivityAt: now,
    createdAt: now,
    updatedAt: now,
  };
}

type RouterMode = 'express' | 'cloudflare';

async function callConsoleRoute(
  mode: RouterMode,
  input: {
    auth: ConsoleAuthAdapter;
    account: ReturnType<typeof createInMemoryConsoleAccountService>;
    session?: SessionAdapter | null;
    method: string;
    path: string;
    body?: Record<string, unknown>;
  },
): Promise<{ status: number; json: Record<string, unknown> | null; cookie: string }> {
  if (mode === 'express') {
    const router = createConsoleRouter({
      auth: input.auth,
      account: input.account,
      session: input.session || null,
    });
    const srv = await startExpressRouter(router);
    try {
      const response = await fetchJson(`${srv.baseUrl}${input.path}`, {
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
      await srv.close();
    }
  }

  const handler = createCloudflareConsoleRouter({
    auth: input.auth,
    account: input.account,
    session: input.session || null,
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
    test('returns account profile and creates organizations', async () => {
      const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
      const teamRbac = createInMemoryConsoleTeamRbacService();
      const onboarding = createInMemoryConsoleOnboardingService({
        orgProjectEnv,
        apiKeys: createInMemoryConsoleApiKeyService(),
        teamRbac,
      });
      const account = createInMemoryConsoleAccountService({
        orgProjectEnv,
        teamRbac,
        onboarding,
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_current',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Current Org',
      });

      const auth = makeConsoleAuthAdapter({
        userId: 'user_current',
        orgId: 'org_current',
        roles: ['owner', 'admin'],
        email: 'owner@example.com',
        name: 'Owner User',
      });

      const profileResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'GET',
        path: '/console/account/profile',
      });
      expect(profileResponse.status).toBe(200);
      expect(profileResponse.json?.profile).toMatchObject({
        userId: 'user_current',
        displayName: 'Owner User',
        primaryEmail: 'owner@example.com',
      });

      const createResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'POST',
        path: '/console/account/organizations',
        body: { name: 'Created From Account' },
      });
      expect(createResponse.status).toBe(201);
      expect(createResponse.json?.organization).toMatchObject({
        name: 'Created From Account',
        actorIsOwner: true,
        onboardingComplete: false,
      });
      expect(String(createResponse.json?.organization?.id || '')).toMatch(/^org_[a-z0-9]+_[a-z0-9]{5}$/);
      expect(String(createResponse.json?.organization?.id || '')).not.toContain('created_from_account');

      const listResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'GET',
        path: '/console/account/organizations',
      });
      expect(listResponse.status).toBe(200);
      expect(Array.isArray(listResponse.json?.organizations)).toBe(true);
      expect(
        (listResponse.json?.organizations as Array<Record<string, unknown>>).some(
          (entry) => entry.name === 'Created From Account',
        ),
      ).toBe(true);
    });

    test('updates profile fields and backup emails with validation', async () => {
      const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
      const teamRbac = createInMemoryConsoleTeamRbacService();
      const onboarding = createInMemoryConsoleOnboardingService({
        orgProjectEnv,
        apiKeys: createInMemoryConsoleApiKeyService(),
        teamRbac,
      });
      const account = createInMemoryConsoleAccountService({
        orgProjectEnv,
        teamRbac,
        onboarding,
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_current',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Current Org',
      });

      const auth = makeConsoleAuthAdapter({
        userId: 'user_current',
        orgId: 'org_current',
        roles: ['owner', 'admin'],
        email: 'owner@example.com',
        name: 'Owner User',
      });

      const invalidResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'PATCH',
        path: '/console/account/profile',
        body: { addBackupEmail: 'not-an-email' },
      });
      expect(invalidResponse.status).toBe(400);
      expect(invalidResponse.json).toMatchObject({
        ok: false,
        code: 'invalid_body',
      });

      const updateResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'PATCH',
        path: '/console/account/profile',
        body: {
          displayName: 'Updated User',
          primaryEmail: 'updated@example.com',
          addBackupEmail: 'Recovery@Example.com',
        },
      });
      expect(updateResponse.status).toBe(200);
      expect(updateResponse.json?.profile).toMatchObject({
        displayName: 'Updated User',
        primaryEmail: 'updated@example.com',
      });
      expect(updateResponse.json?.profile).toMatchObject({
        backupEmails: [{ email: 'recovery@example.com', status: 'PENDING' }],
      });

      const duplicateBackupResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'PATCH',
        path: '/console/account/profile',
        body: { addBackupEmail: 'recovery@example.com' },
      });
      expect(duplicateBackupResponse.status).toBe(200);
      const duplicateProfile = duplicateBackupResponse.json?.profile as
        | { backupEmails?: unknown }
        | undefined;
      expect(
        Array.isArray(duplicateProfile?.backupEmails) ? duplicateProfile.backupEmails : [],
      ).toHaveLength(1);

      const removeResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'PATCH',
        path: '/console/account/profile',
        body: { removeBackupEmail: 'RECOVERY@example.com' },
      });
      expect(removeResponse.status).toBe(200);
      expect(removeResponse.json?.profile).toMatchObject({
        backupEmails: [],
      });
    });

    test('treats oidc primary email as read-only', async () => {
      const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
      const teamRbac = createInMemoryConsoleTeamRbacService();
      const onboarding = createInMemoryConsoleOnboardingService({
        orgProjectEnv,
        apiKeys: createInMemoryConsoleApiKeyService(),
        teamRbac,
      });
      const account = createInMemoryConsoleAccountService({
        orgProjectEnv,
        teamRbac,
        onboarding,
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_current',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Current Org',
      });

      const auth = makeConsoleAuthAdapter({
        userId: 'user_current',
        orgId: 'org_current',
        roles: ['owner', 'admin'],
        email: 'owner@example.com',
        name: 'Owner User',
        provider: 'oidc',
      });

      const profileResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'GET',
        path: '/console/account/profile',
      });
      expect(profileResponse.status).toBe(200);
      expect(profileResponse.json?.profile).toMatchObject({
        primaryEmail: 'owner@example.com',
        canEditPrimaryEmail: false,
      });

      const deniedResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'PATCH',
        path: '/console/account/profile',
        body: { primaryEmail: 'updated@example.com' },
      });
      expect(deniedResponse.status).toBe(403);
      expect(deniedResponse.json).toMatchObject({
        ok: false,
        code: 'primary_email_read_only',
      });

      const displayNameResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'PATCH',
        path: '/console/account/profile',
        body: { displayName: 'Updated User' },
      });
      expect(displayNameResponse.status).toBe(200);
      expect(displayNameResponse.json?.profile).toMatchObject({
        displayName: 'Updated User',
        primaryEmail: 'owner@example.com',
        canEditPrimaryEmail: false,
      });
    });

    test('limits org directory visibility and forbids owner transfer by non-owner', async () => {
      const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
      const teamRbac = createInMemoryConsoleTeamRbacService();
      const onboarding = createInMemoryConsoleOnboardingService({
        orgProjectEnv,
        apiKeys: createInMemoryConsoleApiKeyService(),
        teamRbac,
      });
      const account = createInMemoryConsoleAccountService({
        orgProjectEnv,
        teamRbac,
        onboarding,
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_current',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Current Org',
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_hidden',
        actorUserId: 'user_hidden_owner',
        actorEmail: 'hidden@example.com',
        actorDisplayName: 'Hidden Owner',
        organizationName: 'Hidden Org',
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_admin_only',
        actorUserId: 'user_target_owner',
        actorEmail: 'target-owner@example.com',
        actorDisplayName: 'Target Owner',
        organizationName: 'Admin Only Org',
      });
      await teamRbac.inviteMember(
        {
          orgId: 'org_admin_only',
          actorUserId: 'user_target_owner',
          roles: ['owner', 'admin'],
          actorEmail: 'target-owner@example.com',
          actorDisplayName: 'Target Owner',
        },
        {
          userId: 'user_current',
          email: 'owner@example.com',
          displayName: 'Owner User',
          roles: [{ role: 'admin', scope: 'ORG' }],
        },
      );

      const auth = makeConsoleAuthAdapter({
        userId: 'user_current',
        orgId: 'org_current',
        roles: ['owner', 'admin'],
        email: 'owner@example.com',
        name: 'Owner User',
      });

      const listResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'GET',
        path: '/console/account/organizations',
      });
      expect(listResponse.status).toBe(200);
      expect(listResponse.json?.organizations).toMatchObject([{ id: 'org_current' }]);
      expect(
        Array.isArray(listResponse.json?.organizations)
          ? listResponse.json?.organizations.some(
              (entry) => String((entry as Record<string, unknown>).id || '') === 'org_hidden',
            )
          : false,
      ).toBe(false);
      expect(
        Array.isArray(listResponse.json?.organizations)
          ? listResponse.json?.organizations.some(
              (entry) => String((entry as Record<string, unknown>).id || '') === 'org_admin_only',
            )
          : false,
      ).toBe(false);

      const transferResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'POST',
        path: '/console/account/organizations/org_admin_only/transfer-owner',
        body: { targetUserId: 'user_target_owner' },
      });
      expect(transferResponse.status).toBe(403);
      expect(transferResponse.json).toMatchObject({
        ok: false,
        code: 'forbidden',
      });
    });

    test('transfers owner and re-signs session on org switch', async () => {
      const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
      const teamRbac = createInMemoryConsoleTeamRbacService();
      const onboarding = createInMemoryConsoleOnboardingService({
        orgProjectEnv,
        apiKeys: createInMemoryConsoleApiKeyService(),
        teamRbac,
      });
      const account = createInMemoryConsoleAccountService({
        orgProjectEnv,
        teamRbac,
        onboarding,
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_current',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Current Org',
        projectId: 'proj_current',
        environmentId: 'proj_current:dev',
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_target',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Target Org',
        projectId: 'proj_target',
        environmentId: 'proj_target:dev',
      });
      await teamRbac.inviteMember(
        {
          orgId: 'org_target',
          actorUserId: 'user_current',
          roles: ['owner', 'admin'],
          actorEmail: 'owner@example.com',
          actorDisplayName: 'Owner User',
        },
        {
          userId: 'user_admin',
          email: 'admin@example.com',
          displayName: 'Admin User',
          roles: [{ role: 'admin', scope: 'ORG' }],
        },
      );

      const auth = makeConsoleAuthAdapter({
        userId: 'user_current',
        orgId: 'org_current',
        roles: ['owner', 'admin'],
        email: 'owner@example.com',
        name: 'Owner User',
        projectId: 'proj_current',
        environmentId: 'proj_current:dev',
      });

      const transferResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'POST',
        path: '/console/account/organizations/org_target/transfer-owner',
        body: { targetUserId: 'user_admin' },
      });
      expect(transferResponse.status).toBe(200);
      expect(transferResponse.json?.transfer).toMatchObject({
        nextOwner: { userId: 'user_admin' },
      });

      let signedSub = '';
      let signedClaims: Record<string, unknown> | null = null;
      const session: SessionAdapter = {
        parse: async () => ({
          ok: true,
          claims: {
            sub: 'user_current',
            userId: 'user_current',
            kind: 'app_session_v1',
            appSessionVersion: 'v1',
            email: 'owner@example.com',
            name: 'Owner User',
            orgId: 'org_current',
            projectId: 'proj_current',
            environmentId: 'proj_current:dev',
          },
        }),
        signJwt: async (sub: string, extra?: Record<string, unknown>) => {
          signedSub = sub;
          signedClaims = extra || null;
          return 'switched-session-token';
        },
        buildSetCookie: (token: string) => `tatchi-jwt=${token}; Path=/; HttpOnly`,
        buildClearCookie: () => 'tatchi-jwt=; Path=/; Max-Age=0',
        refresh: async () => ({ ok: false, code: 'not_eligible', message: 'not eligible' }),
      };

      const switchResponse = await callConsoleRoute(mode, {
        auth,
        account,
        session,
        method: 'POST',
        path: '/console/account/organizations/org_target/switch-context',
        body: {},
      });

      expect(switchResponse.status).toBe(200);
      expect(switchResponse.json?.context).toMatchObject({
        orgId: 'org_target',
        projectId: 'proj_target',
        environmentId: 'proj_target:prod',
        actorRoles: ['admin'],
      });
      expect(signedSub).toBe('user_current');
      expect(signedClaims).toMatchObject({
        kind: 'app_session_v1',
        appSessionVersion: 'v1',
        email: 'owner@example.com',
        name: 'Owner User',
        orgId: 'org_target',
        projectId: 'proj_target',
        environmentId: 'proj_target:prod',
        roles: ['admin'],
      });
      expect(switchResponse.cookie).toContain('switched-session-token');
    });

    test('deletes an empty non-current organization', async () => {
      const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
      const teamRbac = createInMemoryConsoleTeamRbacService();
      const onboarding = createInMemoryConsoleOnboardingService({
        orgProjectEnv,
        apiKeys: createInMemoryConsoleApiKeyService(),
        teamRbac,
      });
      const account = createInMemoryConsoleAccountService({
        orgProjectEnv,
        teamRbac,
        onboarding,
        wallets: createInMemoryConsoleWalletService(),
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_current',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Current Org',
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_empty_delete',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Delete Me',
      });

      const auth = makeConsoleAuthAdapter({
        userId: 'user_current',
        orgId: 'org_current',
        roles: ['owner', 'admin'],
        email: 'owner@example.com',
        name: 'Owner User',
      });

      const deleteResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'DELETE',
        path: '/console/account/organizations/org_empty_delete',
      });
      expect(deleteResponse.status).toBe(200);
      expect(deleteResponse.json?.deleted).toMatchObject({
        orgId: 'org_empty_delete',
      });

      const listResponse = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'GET',
        path: '/console/account/organizations',
      });
      expect(listResponse.status).toBe(200);
      expect(
        Array.isArray(listResponse.json?.organizations)
          ? listResponse.json?.organizations.some(
              (entry) => String((entry as Record<string, unknown>).id || '') === 'org_empty_delete',
            )
          : false,
      ).toBe(false);
    });

    test('blocks organization delete for current org, other members, or wallets', async () => {
      const orgProjectEnv = createInMemoryConsoleOrgProjectEnvService();
      const teamRbac = createInMemoryConsoleTeamRbacService();
      const onboarding = createInMemoryConsoleOnboardingService({
        orgProjectEnv,
        apiKeys: createInMemoryConsoleApiKeyService(),
        teamRbac,
      });
      const account = createInMemoryConsoleAccountService({
        orgProjectEnv,
        teamRbac,
        onboarding,
        wallets: createInMemoryConsoleWalletService({
          seedWallets: [
            buildWalletSeed({
              orgId: 'org_with_wallet',
              projectId: 'proj_wallet',
              environmentId: 'proj_wallet:dev',
              walletId: 'wallet_delete_blocker',
            }),
          ],
        }),
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_current',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Current Org',
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_with_member',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Member Blocked Org',
      });
      await seedOrganization({
        orgProjectEnv,
        teamRbac,
        orgId: 'org_with_wallet',
        actorUserId: 'user_current',
        actorEmail: 'owner@example.com',
        actorDisplayName: 'Owner User',
        organizationName: 'Wallet Blocked Org',
      });
      await teamRbac.inviteMember(
        {
          orgId: 'org_with_member',
          actorUserId: 'user_current',
          roles: ['owner', 'admin'],
          actorEmail: 'owner@example.com',
          actorDisplayName: 'Owner User',
        },
        {
          userId: 'user_other',
          email: 'other@example.com',
          displayName: 'Other User',
          roles: [{ role: 'admin', scope: 'ORG' }],
        },
      );

      const auth = makeConsoleAuthAdapter({
        userId: 'user_current',
        orgId: 'org_current',
        roles: ['owner', 'admin'],
        email: 'owner@example.com',
        name: 'Owner User',
      });

      const currentDelete = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'DELETE',
        path: '/console/account/organizations/org_current',
      });
      expect(currentDelete.status).toBe(409);
      expect(currentDelete.json).toMatchObject({
        ok: false,
        code: 'organization_current_context_active',
      });

      const memberDelete = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'DELETE',
        path: '/console/account/organizations/org_with_member',
      });
      expect(memberDelete.status).toBe(409);
      expect(memberDelete.json).toMatchObject({
        ok: false,
        code: 'organization_delete_has_other_members',
      });

      const walletDelete = await callConsoleRoute(mode, {
        auth,
        account,
        method: 'DELETE',
        path: '/console/account/organizations/org_with_wallet',
      });
      expect(walletDelete.status).toBe(409);
      expect(walletDelete.json).toMatchObject({
        ok: false,
        code: 'organization_delete_has_wallets',
      });
    });
  });
}
