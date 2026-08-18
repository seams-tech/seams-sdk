import { expect, test } from '@playwright/test';
import { createAesGcmConsoleInvitationSecretCipher } from '../../packages/console-server-ts/src/email/secrets';
import { createD1ConsoleOrganizationAccessService } from '../../packages/console-server-ts/src/teamRbac/d1';
import { isConsoleOrganizationAccessError } from '../../packages/console-server-ts/src/teamRbac/errors';
import {
  parseInviteOrganizationMemberRequest,
  parseListOrganizationInvitationsRequest,
  parseSetOrganizationAdminPermissionsRequest,
} from '../../packages/console-server-ts/src/teamRbac/requests';
import {
  createInMemoryConsoleOrganizationAccessService,
  type ConsoleOrganizationAccessService,
} from '../../packages/console-server-ts/src/teamRbac/service';
import {
  applyD1MigrationFiles,
  cleanupTemporaryD1Database,
  createTemporaryD1Database,
  listD1MigrationFiles,
  SqliteCliD1PreparedStatement,
} from '../helpers/sqliteD1';
import type {
  D1DatabaseLike,
  D1PreparedStatementLike,
} from '../../packages/wallet-server/src/storage/tenantRoute';

class RejectingOrganizationEmailBatchDatabase implements D1DatabaseLike {
  readonly batches: string[][] = [];
  private rejectNext = false;

  constructor(private readonly database: D1DatabaseLike) {}

  prepare(query: string): D1PreparedStatementLike {
    return this.database.prepare(query);
  }

  async batch<T = unknown>(statements: readonly D1PreparedStatementLike[]): Promise<readonly T[]> {
    const sql: string[] = [];
    for (const statement of statements) {
      if (!(statement instanceof SqliteCliD1PreparedStatement)) {
        throw new Error('Expected SQLite-backed D1 statement');
      }
      sql.push(statement.toSql());
    }
    this.batches.push(sql);
    if (this.rejectNext) {
      this.rejectNext = false;
      throw new Error('injected organization email batch failure');
    }
    return await this.database.batch<T>(statements);
  }

  async exec(query: string): Promise<unknown> {
    return await this.database.exec(query);
  }

  rejectNextBatch(): void {
    this.rejectNext = true;
  }
}

function createOrganizationEmailTestCipher() {
  return createAesGcmConsoleInvitationSecretCipher({
    keyId: 'organization-email-test-r1',
    keyBytes: new Uint8Array(32).fill(31),
  });
}

async function expectAccessError(
  operation: () => unknown | Promise<unknown>,
  expectedCode: string,
): Promise<void> {
  let caught: unknown = null;
  try {
    await operation();
  } catch (error: unknown) {
    caught = error;
  }
  expect(isConsoleOrganizationAccessError(caught)).toBe(true);
  expect(caught && typeof caught === 'object' && 'code' in caught ? String(caught.code) : '').toBe(
    expectedCode,
  );
}

async function acceptInvitation(
  service: ConsoleOrganizationAccessService,
  input: {
    readonly invitationId: string;
    readonly token: string;
    readonly userId: string;
    readonly email: string;
  },
) {
  return await service.acceptInvitation(
    {
      userId: input.userId,
      verifiedEmail: input.email,
    },
    input.invitationId,
    { token: input.token },
  );
}

test.describe('console organization access', () => {
  test('request boundaries produce role-specific grants', async () => {
    expect(
      parseInviteOrganizationMemberRequest({
        email: ' ADMIN@Example.com ',
        role: 'admin',
        adminPermissions: ['billing.manage', 'members.manage'],
      }),
    ).toEqual({
      email: 'admin@example.com',
      role: 'ADMIN',
      adminPermissions: ['members.manage', 'billing.view', 'billing.manage'],
    });
    expect(
      parseInviteOrganizationMemberRequest({
        email: 'member@example.com',
        role: 'MEMBER',
        projectAccess: [{ projectId: 'project-a', accessLevel: 'VIEWER' }],
      }),
    ).toEqual({
      email: 'member@example.com',
      role: 'MEMBER',
      projectAccess: [{ projectId: 'project-a', accessLevel: 'viewer' }],
    });
    expect(parseListOrganizationInvitationsRequest({})).toEqual({ kind: 'all' });
    expect(
      parseSetOrganizationAdminPermissionsRequest({
        permissions: ['billing.manage'],
      }),
    ).toEqual({
      permissions: ['billing.view', 'billing.manage'],
    });
    await expectAccessError(
      () =>
        parseInviteOrganizationMemberRequest({
          email: 'owner@example.com',
          role: 'OWNER',
          adminPermissions: [],
        }),
      'invalid_body',
    );
  });

  test('in-memory service enforces multi-owner, invitation, and authorization lifecycles', async () => {
    let nowMs = Date.parse('2026-07-26T00:00:00.000Z');
    const service = createInMemoryConsoleOrganizationAccessService({
      now: () => new Date(nowMs),
    });
    const owner = await service.bootstrapInitialOwner({
      orgId: 'org-access-memory',
      userId: 'user-owner-a',
      email: 'owner-a@example.com',
      displayName: 'Owner A',
    });
    const ownerContext = {
      orgId: owner.orgId,
      actorUserId: owner.userId,
    };
    expect(await service.getAuthorizationVersion(owner.orgId)).toBe(1);

    const ownerInvitation = await service.invite(ownerContext, {
      email: 'owner-b@example.com',
      role: 'OWNER',
    });
    expect(ownerInvitation.invitation.kind).toBe('pending');
    expect(await service.listMemberships(ownerContext, { kind: 'all' })).toHaveLength(1);

    await expectAccessError(
      () =>
        acceptInvitation(service, {
          invitationId: ownerInvitation.invitation.id,
          token: ownerInvitation.token,
          userId: 'user-owner-b',
          email: 'different@example.com',
        }),
      'invitation_email_mismatch',
    );
    const secondOwner = await acceptInvitation(service, {
      invitationId: ownerInvitation.invitation.id,
      token: ownerInvitation.token,
      userId: 'user-owner-b',
      email: 'owner-b@example.com',
    });
    expect(secondOwner.role).toBe('OWNER');
    await expectAccessError(
      () =>
        acceptInvitation(service, {
          invitationId: ownerInvitation.invitation.id,
          token: ownerInvitation.token,
          userId: 'user-owner-b-replay',
          email: 'owner-b@example.com',
        }),
      'invitation_not_pending',
    );
    await expectAccessError(
      () =>
        service.changeRole(ownerContext, owner.id, {
          role: 'ADMIN',
          adminPermissions: [],
        }),
      'self_role_change_forbidden',
    );

    const demoted = await service.changeRole(ownerContext, secondOwner.id, {
      role: 'ADMIN',
      adminPermissions: ['members.manage', 'projects.manage'],
    });
    expect(demoted.membership.role).toBe('ADMIN');
    await expectAccessError(
      () =>
        service.leaveOrganization({
          orgId: owner.orgId,
          actorUserId: owner.userId,
        }),
      'last_owner_required',
    );

    const adminContext = {
      orgId: owner.orgId,
      actorUserId: secondOwner.userId,
    };
    await expectAccessError(
      () =>
        service.invite(adminContext, {
          email: 'another-admin@example.com',
          role: 'ADMIN',
          adminPermissions: [],
        }),
      'forbidden',
    );
    const memberInvitation = await service.invite(adminContext, {
      email: 'member@example.com',
      role: 'MEMBER',
      projectAccess: [{ projectId: 'project-a', accessLevel: 'viewer' }],
    });
    const rotated = await service.resendInvitation(adminContext, memberInvitation.invitation.id);
    await expectAccessError(
      () =>
        acceptInvitation(service, {
          invitationId: memberInvitation.invitation.id,
          token: memberInvitation.token,
          userId: 'user-member',
          email: 'member@example.com',
        }),
      'invalid_invitation_token',
    );
    const member = await acceptInvitation(service, {
      invitationId: rotated.invitation.id,
      token: rotated.token,
      userId: 'user-member',
      email: 'member@example.com',
    });
    const memberAuthorization = await service.lookupAuthorization({
      orgId: owner.orgId,
      userId: member.userId,
    });
    expect(memberAuthorization).toEqual(
      expect.objectContaining({
        kind: 'authorized',
        role: 'MEMBER',
        projectAccess: {
          kind: 'assigned',
          assignments: [{ projectId: 'project-a', accessLevel: 'viewer' }],
        },
      }),
    );

    await service.setProjectAccess(adminContext, 'project-a', member.id, { accessLevel: 'editor' });
    await service.suspendMembership(adminContext, member.id);
    expect(
      await service.lookupAuthorization({
        orgId: owner.orgId,
        userId: member.userId,
      }),
    ).toEqual(
      expect.objectContaining({
        kind: 'denied',
        reason: 'membership_suspended',
      }),
    );
    await service.reactivateMembership(adminContext, member.id);
    await service.removeMembership(adminContext, member.id);
    expect(
      await service.lookupAuthorization({
        orgId: owner.orgId,
        userId: member.userId,
      }),
    ).toEqual(
      expect.objectContaining({
        kind: 'denied',
        reason: 'membership_removed',
      }),
    );

    const expiringInvitation = await service.invite(ownerContext, {
      email: 'expires@example.com',
      role: 'MEMBER',
      projectAccess: [],
    });
    nowMs += 8 * 24 * 60 * 60 * 1_000;
    await expectAccessError(
      () =>
        acceptInvitation(service, {
          invitationId: expiringInvitation.invitation.id,
          token: expiringInvitation.token,
          userId: 'user-expired',
          email: 'expires@example.com',
        }),
      'invitation_not_pending',
    );
    const expired = await service.listInvitations(ownerContext, { kind: 'expired' });
    expect(expired.map((invitation) => invitation.id)).toContain(expiringInvitation.invitation.id);
  });

  test('D1 service stores token hashes and preserves access across service instances', async () => {
    const temporary = createTemporaryD1Database();
    try {
      const migrations = listD1MigrationFiles('d1-console').filter((file) =>
        /\/00(?:0[1-9]|1[0-9]|20)_/u.test(file),
      );
      await applyD1MigrationFiles(temporary.database, migrations);
      const createdAtMs = Date.parse('2026-07-26T00:00:00.000Z');
      await temporary.database.exec(`
        INSERT INTO organizations
          (namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms)
        VALUES
          ('access-d1', 'org-access-d1', 'D1 Access', 'd1-access', 'user-owner', 'ACTIVE', ${createdAtMs}, ${createdAtMs});
        INSERT INTO projects
          (namespace, id, org_id, name, slug, status, created_at_ms, updated_at_ms)
        VALUES
          ('access-d1', 'project-d1', 'org-access-d1', 'D1 Project', 'd1-project', 'ACTIVE', ${createdAtMs}, ${createdAtMs});
      `);
      const service = await createD1ConsoleOrganizationAccessService({
        database: temporary.database,
        namespace: 'access-d1',
        ensureSchema: true,
        now: () => new Date(createdAtMs),
      });
      const owner = await service.bootstrapInitialOwner({
        orgId: 'org-access-d1',
        userId: 'user-owner',
        email: 'owner@example.com',
        displayName: 'Owner',
      });
      const ownerContext = {
        orgId: owner.orgId,
        actorUserId: owner.userId,
      };
      const invitation = await service.invite(ownerContext, {
        email: 'member-d1@example.com',
        role: 'MEMBER',
        projectAccess: [{ projectId: 'project-d1', accessLevel: 'viewer' }],
      });
      const invitationRow = await temporary.database
        .prepare(
          `SELECT token_hash, project_access_json
             FROM organization_invitations
            WHERE namespace = ?
              AND id = ?`,
        )
        .bind('access-d1', invitation.invitation.id)
        .first<{ token_hash?: unknown; project_access_json?: unknown }>();
      expect(String(invitationRow?.token_hash)).toMatch(/^sha256:[0-9a-f]{64}$/u);
      expect(String(invitationRow?.token_hash)).not.toContain(invitation.token);
      expect(JSON.parse(String(invitationRow?.project_access_json))).toEqual([
        { projectId: 'project-d1', accessLevel: 'viewer' },
      ]);

      const member = await acceptInvitation(service, {
        invitationId: invitation.invitation.id,
        token: invitation.token,
        userId: 'user-member-d1',
        email: 'member-d1@example.com',
      });
      const recreated = await createD1ConsoleOrganizationAccessService({
        database: temporary.database,
        namespace: 'access-d1',
        ensureSchema: true,
      });
      expect(
        await recreated.lookupAuthorization({
          orgId: owner.orgId,
          userId: member.userId,
        }),
      ).toEqual(
        expect.objectContaining({
          kind: 'authorized',
          role: 'MEMBER',
          projectAccess: {
            kind: 'assigned',
            assignments: [{ projectId: 'project-d1', accessLevel: 'viewer' }],
          },
        }),
      );
      const acceptedRow = await temporary.database
        .prepare(
          `SELECT token_hash, kind
             FROM organization_invitations
            WHERE namespace = ?
              AND id = ?`,
        )
        .bind('access-d1', invitation.invitation.id)
        .first<{ token_hash?: unknown; kind?: unknown }>();
      expect(acceptedRow?.token_hash).toBeNull();
      expect(acceptedRow?.kind).toBe('ACCEPTED');
      await recreated.purgeOrganization(owner.orgId);
      expect(await recreated.getAuthorizationVersion(owner.orgId)).toBeNull();
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('D1 invitation creation batches the domain mutation and email intent atomically', async () => {
    const temporary = createTemporaryD1Database();
    try {
      await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-console'));
      const createdAtMs = Date.parse('2026-07-26T00:00:00.000Z');
      await temporary.database.exec(`
        INSERT INTO organizations
          (namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms)
        VALUES
          ('email-atomic', 'org-email-atomic', 'Email Atomic', 'email-atomic', 'user-owner', 'ACTIVE', ${createdAtMs}, ${createdAtMs});
      `);
      const bootstrapService = await createD1ConsoleOrganizationAccessService({
        database: temporary.database,
        namespace: 'email-atomic',
        now: () => new Date(createdAtMs),
      });
      const owner = await bootstrapService.bootstrapInitialOwner({
        orgId: 'org-email-atomic',
        userId: 'user-owner',
        email: 'owner@example.com',
        displayName: 'Owner',
      });
      const rejectingDatabase = new RejectingOrganizationEmailBatchDatabase(temporary.database);
      const service = await createD1ConsoleOrganizationAccessService({
        database: rejectingDatabase,
        namespace: 'email-atomic',
        now: () => new Date(createdAtMs),
        email: {
          invitationSecretCipher: createOrganizationEmailTestCipher(),
          consoleBaseUrl: 'https://console.example.test',
        },
      });
      rejectingDatabase.rejectNextBatch();
      await expect(
        service.invite(
          {
            orgId: owner.orgId,
            actorUserId: owner.userId,
          },
          {
            email: 'invitee@example.com',
            role: 'MEMBER',
            projectAccess: [],
          },
        ),
      ).rejects.toThrow('injected organization email batch failure');
      expect(rejectingDatabase.batches).toHaveLength(1);
      expect(rejectingDatabase.batches[0]?.join('\n')).toContain(
        'INSERT INTO organization_invitations',
      );
      expect(rejectingDatabase.batches[0]?.join('\n')).toContain(
        'INSERT INTO console_email_outbox',
      );
      const invitationCount = await temporary.database
        .prepare(
          `SELECT COUNT(*) AS row_count
             FROM organization_invitations
            WHERE namespace = 'email-atomic'
              AND org_id = 'org-email-atomic'`,
        )
        .first<{ row_count?: unknown }>();
      const outboxCount = await temporary.database
        .prepare(
          `SELECT COUNT(*) AS row_count
             FROM console_email_outbox
            WHERE namespace = 'email-atomic'
              AND org_id = 'org-email-atomic'`,
        )
        .first<{ row_count?: unknown }>();
      expect(Number(invitationCount?.row_count || 0)).toBe(0);
      expect(Number(outboxCount?.row_count || 0)).toBe(0);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

  test('D1 organization lifecycle emails erase invitation secrets on every terminal path', async () => {
    const temporary = createTemporaryD1Database();
    let nowMs = Date.parse('2026-07-26T00:00:00.000Z');
    try {
      await applyD1MigrationFiles(temporary.database, listD1MigrationFiles('d1-console'));
      await temporary.database.exec(`
        INSERT INTO organizations
          (namespace, id, name, slug, created_by_user_id, status, created_at_ms, updated_at_ms)
        VALUES
          ('email-lifecycle', 'org-email-lifecycle', 'Email Lifecycle', 'email-lifecycle', 'user-owner', 'ACTIVE', ${nowMs}, ${nowMs});
      `);
      const service = await createD1ConsoleOrganizationAccessService({
        database: temporary.database,
        namespace: 'email-lifecycle',
        now: () => new Date(nowMs),
        email: {
          invitationSecretCipher: createOrganizationEmailTestCipher(),
          consoleBaseUrl: 'https://console.example.test',
        },
      });
      const owner = await service.bootstrapInitialOwner({
        orgId: 'org-email-lifecycle',
        userId: 'user-owner',
        email: 'owner@example.com',
        displayName: 'Owner',
      });
      const ownerContext = {
        orgId: owner.orgId,
        actorUserId: owner.userId,
      };

      const acceptedInvitation = await service.invite(ownerContext, {
        email: 'accepted@example.com',
        role: 'MEMBER',
        projectAccess: [],
      });
      const acceptedMember = await acceptInvitation(service, {
        invitationId: acceptedInvitation.invitation.id,
        token: acceptedInvitation.token,
        userId: 'user-accepted',
        email: 'accepted@example.com',
      });
      nowMs += 1;
      await service.suspendMembership(ownerContext, acceptedMember.id);
      nowMs += 1;
      await service.reactivateMembership(ownerContext, acceptedMember.id);
      nowMs += 1;
      await service.removeMembership(ownerContext, acceptedMember.id);

      nowMs += 1;
      const ownerInvitation = await service.invite(ownerContext, {
        email: 'second-owner@example.com',
        role: 'OWNER',
      });
      const secondOwner = await acceptInvitation(service, {
        invitationId: ownerInvitation.invitation.id,
        token: ownerInvitation.token,
        userId: 'user-second-owner',
        email: 'second-owner@example.com',
      });
      nowMs += 1;
      await service.changeRole(ownerContext, secondOwner.id, {
        role: 'ADMIN',
        adminPermissions: [],
      });

      const declinedInvitation = await service.invite(ownerContext, {
        email: 'declined@example.com',
        role: 'MEMBER',
        projectAccess: [],
      });
      await service.declineInvitation(
        {
          userId: 'user-declined',
          verifiedEmail: 'declined@example.com',
        },
        declinedInvitation.invitation.id,
        { token: declinedInvitation.token },
      );

      const revokedInvitation = await service.invite(ownerContext, {
        email: 'revoked@example.com',
        role: 'MEMBER',
        projectAccess: [],
      });
      await service.revokeInvitation(ownerContext, revokedInvitation.invitation.id);

      const resentInvitation = await service.invite(ownerContext, {
        email: 'resent@example.com',
        role: 'MEMBER',
        projectAccess: [],
      });
      const resent = await service.resendInvitation(ownerContext, resentInvitation.invitation.id);
      await service.revokeInvitation(ownerContext, resent.invitation.id);

      const expiringInvitation = await service.invite(ownerContext, {
        email: 'expired@example.com',
        role: 'MEMBER',
        projectAccess: [],
      });
      nowMs += 8 * 24 * 60 * 60 * 1_000;
      await service.listInvitations(ownerContext, { kind: 'expired' });

      const invitationIds = [
        acceptedInvitation.invitation.id,
        ownerInvitation.invitation.id,
        declinedInvitation.invitation.id,
        revokedInvitation.invitation.id,
        resentInvitation.invitation.id,
        expiringInvitation.invitation.id,
      ];
      for (const invitationId of invitationIds) {
        const rows = await temporary.database
          .prepare(
            `SELECT status,
                    invitation_secret_ciphertext_b64u,
                    invitation_secret_key_id,
                    invitation_secret_envelope_version
               FROM console_email_outbox
              WHERE namespace = ?
                AND org_id = ?
                AND invitation_id = ?`,
          )
          .bind('email-lifecycle', owner.orgId, invitationId)
          .all<Record<string, unknown>>();
        expect(rows.results?.length).toBeGreaterThan(0);
        for (const row of rows.results || []) {
          expect(row.status).toBe('CANCELED');
          expect(row.invitation_secret_ciphertext_b64u).toBeNull();
          expect(row.invitation_secret_key_id).toBeNull();
          expect(row.invitation_secret_envelope_version).toBeNull();
        }
      }

      const membershipEmails = await temporary.database
        .prepare(
          `SELECT template_payload_json
             FROM console_email_outbox
            WHERE namespace = ?
              AND org_id = ?
              AND recipient_email = ?
              AND template_family = 'MEMBERSHIP_ACCESS_CHANGED'
            ORDER BY created_at_ms, id`,
        )
        .bind('email-lifecycle', owner.orgId, acceptedMember.email)
        .all<{ template_payload_json?: unknown }>();
      const membershipChanges = (membershipEmails.results || []).map((row) =>
        String(JSON.parse(String(row.template_payload_json)).change),
      );
      expect(membershipChanges).toEqual(['SUSPENDED', 'REMOVED']);

      const ownerEmails = await temporary.database
        .prepare(
          `SELECT template_payload_json
             FROM console_email_outbox
            WHERE namespace = ?
              AND org_id = ?
              AND recipient_email = ?
              AND template_family = 'OWNER_MEMBERSHIP_CHANGED'
            ORDER BY created_at_ms, id`,
        )
        .bind('email-lifecycle', owner.orgId, secondOwner.email)
        .all<{ template_payload_json?: unknown }>();
      const ownerChanges = (ownerEmails.results || []).map((row) =>
        String(JSON.parse(String(row.template_payload_json)).change),
      );
      expect(ownerChanges).toEqual(['ADDED', 'REMOVED']);
    } finally {
      cleanupTemporaryD1Database(temporary.tempDir);
    }
  });

});
