import { expect, test } from '@playwright/test';
import type {
  ConsoleTeamMember,
  ConsoleTeamRoleAssignment,
  InviteConsoleTeamMemberRequest,
  ListConsoleTeamMembersRequest,
  UpdateConsoleTeamMemberRolesRequest,
} from '../../packages/sdk-server-ts/src/console/teamRbac/types';
import type {
  ConsoleTeamRbacContext,
  ConsoleTeamRbacService,
} from '../../packages/sdk-server-ts/src/console/teamRbac/service';
import {
  createCloudflareSecretsStoreKekProviderFromEnv,
  createConsoleSessionAuthAdapter,
  createHmacSessionAdapter,
  secretBindingNameForKekId,
} from '../../packages/sdk-server-ts/src/router/cloudflare/d1StagingSession';

const SESSION_SECRET = '0123456789abcdef0123456789abcdef';

class FakeConsoleTeamRbacService implements ConsoleTeamRbacService {
  constructor(private readonly members: readonly ConsoleTeamMember[]) {}

  async bootstrapOwner(ctx: ConsoleTeamRbacContext): Promise<ConsoleTeamMember> {
    return activeConsoleMember({
      orgId: ctx.orgId,
      userId: ctx.actorUserId,
      email: ctx.actorEmail || `${ctx.actorUserId}@example.test`,
      roles: [{ role: 'owner', scope: 'ORG' }],
    });
  }

  async listMembers(): Promise<ConsoleTeamMember[]> {
    return [...this.members];
  }

  async listOrganizationMembers(
    orgId: string,
    request?: ListConsoleTeamMembersRequest,
  ): Promise<ConsoleTeamMember[]> {
    const status = request?.status || 'ALL';
    return this.members.filter((member) => {
      if (member.orgId !== orgId) return false;
      return status === 'ALL' || member.status === status;
    });
  }

  async purgeOrganization(): Promise<void> {}

  async transferOwner(): Promise<{
    previousOwner: ConsoleTeamMember;
    nextOwner: ConsoleTeamMember;
  }> {
    const [first] = this.members;
    if (!first) throw new Error('missing fake member');
    return { previousOwner: first, nextOwner: first };
  }

  async inviteMember(
    ctx: ConsoleTeamRbacContext,
    request: InviteConsoleTeamMemberRequest,
  ): Promise<ConsoleTeamMember> {
    return activeConsoleMember({
      orgId: ctx.orgId,
      userId: request.userId,
      email: request.email,
      roles: request.roles,
    });
  }

  async updateMemberRoles(
    ctx: ConsoleTeamRbacContext,
    memberId: string,
    request: UpdateConsoleTeamMemberRolesRequest,
  ): Promise<ConsoleTeamMember | null> {
    const member = this.members.find((entry) => entry.id === memberId && entry.orgId === ctx.orgId);
    if (!member) return null;
    return {
      ...member,
      roles: request.roles,
    };
  }

  async removeMember(): Promise<{ removed: boolean; member: ConsoleTeamMember | null }> {
    return { removed: false, member: null };
  }
}

function activeConsoleMember(input: {
  readonly orgId: string;
  readonly userId: string;
  readonly email: string;
  readonly roles: readonly ConsoleTeamRoleAssignment[];
}): ConsoleTeamMember {
  const timestamp = '2026-06-28T00:00:00.000Z';
  return {
    id: `member_${input.userId}`,
    orgId: input.orgId,
    userId: input.userId,
    email: input.email,
    status: 'ACTIVE',
    roles: [...input.roles],
    invitedByUserId: 'system',
    invitedAt: timestamp,
    createdAt: timestamp,
    updatedAt: timestamp,
    lastStatusChangedAt: timestamp,
  };
}

function bearerHeaders(token: string): Record<string, string> {
  return {
    authorization: `Bearer ${token}`,
  };
}

async function signConsoleSession(input: {
  readonly userId: string;
  readonly orgId: string;
  readonly roles?: readonly string[];
}): Promise<string> {
  const session = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    issuer: 'seams-console-staging',
    audience: 'seams-console-dashboard',
  });
  return await session.signJwt(input.userId, {
    kind: 'console_session_v1',
    orgId: input.orgId,
    email: `${input.userId}@example.test`,
    ...(input.roles ? { roles: [...input.roles] } : {}),
  });
}

async function hmacSessionRoundTrip(): Promise<void> {
  const session = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    issuer: 'seams-router-api-staging',
    audience: 'seams-wallet-session',
  });
  const jwt = await session.signJwt('wallet-user', {
    kind: 'app_session_v1',
    appSessionVersion: 'session-v1',
  });
  const parsed = await session.parse(bearerHeaders(jwt));
  expect(parsed.ok).toBe(true);
  if (!parsed.ok) throw new Error('expected signed HMAC session to parse');
  expect(parsed.claims.sub).toBe('wallet-user');
  expect(parsed.claims.kind).toBe('app_session_v1');
  expect(parsed.claims.appSessionVersion).toBe('session-v1');
}

async function hmacSessionRejectsWrongAudience(): Promise<void> {
  const signer = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    issuer: 'seams-router-api-staging',
    audience: 'seams-wallet-session',
  });
  const verifier = createHmacSessionAdapter({
    secret: SESSION_SECRET,
    issuer: 'seams-router-api-staging',
    audience: 'other-audience',
  });
  const jwt = await signer.signJwt('wallet-user', { kind: 'app_session_v1' });
  await expect(verifier.parse(bearerHeaders(jwt))).resolves.toEqual({ ok: false });
}

async function consoleAuthUsesTeamRbacRoles(): Promise<void> {
  const token = await signConsoleSession({
    userId: 'console-user',
    orgId: 'org_staging',
  });
  const auth = createConsoleSessionAuthAdapter({
    session: createHmacSessionAdapter({
      secret: SESSION_SECRET,
      issuer: 'seams-console-staging',
      audience: 'seams-console-dashboard',
    }),
    teamRbac: new FakeConsoleTeamRbacService([
      activeConsoleMember({
        orgId: 'org_staging',
        userId: 'console-user',
        email: 'console-user@example.test',
        roles: [{ role: 'billing_read', scope: 'ORG' }],
      }),
    ]),
  });
  const result = await auth.authenticate(bearerHeaders(token));
  expect(result.ok).toBe(true);
  if (!result.ok) throw new Error('expected console auth to pass');
  expect(result.claims.roles).toEqual(['billing_read']);
}

async function consoleAuthIgnoresTokenRoleEscalation(): Promise<void> {
  const token = await signConsoleSession({
    userId: 'console-user',
    orgId: 'org_staging',
    roles: ['owner', 'platform_admin'],
  });
  const auth = createConsoleSessionAuthAdapter({
    session: createHmacSessionAdapter({
      secret: SESSION_SECRET,
      issuer: 'seams-console-staging',
      audience: 'seams-console-dashboard',
    }),
    teamRbac: new FakeConsoleTeamRbacService([]),
  });
  const result = await auth.authenticate(bearerHeaders(token));
  expect(result).toMatchObject({
    ok: false,
    code: 'forbidden',
    status: 403,
  });
}

async function secretsStoreKekProviderUsesExpectedBindingName(): Promise<void> {
  const secretBinding = {
    get: readSecretValue,
  };
  const provider = createCloudflareSecretsStoreKekProviderFromEnv({
    SIGNING_ROOT_KEK_PROVIDER: 'cloudflare_secrets_store',
    SIGNING_ROOT_KEK_ENCODING: 'base64url',
    SIGNING_ROOT_KEK_IDS: 'signing-root-kek-staging-r1',
    SIGNING_ROOT_KEK_STAGING_R1: secretBinding,
  });
  expect(secretBindingNameForKekId('signing-root-kek-staging-r1')).toBe(
    'SIGNING_ROOT_KEK_STAGING_R1',
  );
  expect(provider.kind).toBe('cloudflare_secrets_store');
  if (provider.kind !== 'cloudflare_secrets_store') {
    throw new Error('expected Cloudflare Secrets Store provider');
  }
  await expect(provider.secretsByKekId['signing-root-kek-staging-r1']?.get()).resolves.toBe(
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
  );
}

async function secretsStoreKekProviderRejectsMissingBinding(): Promise<void> {
  expect(() =>
    createCloudflareSecretsStoreKekProviderFromEnv({
      SIGNING_ROOT_KEK_PROVIDER: 'cloudflare_secrets_store',
      SIGNING_ROOT_KEK_ENCODING: 'base64url',
      SIGNING_ROOT_KEK_IDS: 'signing-root-kek-staging-r1',
    }),
  ).toThrow('Cloudflare Secrets Store binding SIGNING_ROOT_KEK_STAGING_R1 is required');
}

async function readSecretValue(): Promise<string> {
  return 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
}

test('HMAC staging session signs and verifies JWT claims', hmacSessionRoundTrip);
test('HMAC staging session rejects wrong audience', hmacSessionRejectsWrongAudience);
test('console staging auth resolves roles from Team RBAC', consoleAuthUsesTeamRbacRoles);
test('console staging auth rejects token role escalation', consoleAuthIgnoresTokenRoleEscalation);
test('Secrets Store KEK provider resolves upper-snake bindings', secretsStoreKekProviderUsesExpectedBindingName);
test('Secrets Store KEK provider rejects missing bindings', secretsStoreKekProviderRejectsMissingBinding);
