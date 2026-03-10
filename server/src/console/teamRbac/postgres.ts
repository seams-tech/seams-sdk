import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import {
  ensureConsoleTenantRlsPolicies,
  withConsoleTenantContextTx,
} from '../shared/postgresTenantContext';
import { ConsoleTeamRbacError } from './errors';
import type { ConsoleTeamRbacContext, ConsoleTeamRbacService } from './service';
import {
  CONSOLE_ORG_SCOPED_TEAM_ROLES,
  type ConsoleTeamMember,
  type ConsoleTeamRole,
  type ConsoleTeamRoleAssignment,
  type InviteConsoleTeamMemberRequest,
  type ListConsoleTeamMembersRequest,
  type UpdateConsoleTeamMemberRolesRequest,
} from './types';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_TEAM_RBAC_MIGRATION_LOCK_ID = 9452360123587;
const ORG_ROLE_SET = new Set<string>(CONSOLE_ORG_SCOPED_TEAM_ROLES);
const OWNER_ROLE_JSON = JSON.stringify([{ role: 'owner', scope: 'ORG' }]);

function nowMs(now: Date): number {
  return now.getTime();
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeRole(raw: unknown): ConsoleTeamRole | null {
  const role = String(raw || '')
    .trim()
    .toLowerCase();
  if (!ORG_ROLE_SET.has(role)) return null;
  return role as ConsoleTeamRole;
}

function parseRoleAssignments(raw: unknown): ConsoleTeamRoleAssignment[] {
  const source = (() => {
    if (Array.isArray(raw)) return raw;
    if (typeof raw === 'string') {
      try {
        const parsed = JSON.parse(raw);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }
    return [];
  })();

  const out: ConsoleTeamRoleAssignment[] = [];
  const seen = new Set<string>();
  for (const entryRaw of source) {
    if (!entryRaw || typeof entryRaw !== 'object' || Array.isArray(entryRaw)) continue;
    const entry = entryRaw as Record<string, unknown>;
    const role = normalizeRole(entry.role);
    if (!role) continue;
    if (String(entry.projectId || '').trim()) continue;
    const key = `ORG:${role}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({
      role,
      scope: 'ORG',
    });
  }

  return out.sort((a, b) => a.role.localeCompare(b.role));
}

function normalizeRoleAssignments(input: ConsoleTeamRoleAssignment[]): ConsoleTeamRoleAssignment[] {
  return parseRoleAssignments(input);
}

function parseMemberRow(row: PgRow): ConsoleTeamMember {
  return {
    id: String(row.id || ''),
    orgId: String(row.org_id || ''),
    userId: String(row.user_id || row.id || '').trim(),
    email: String(row.email || ''),
    ...(row.display_name ? { displayName: String(row.display_name) } : {}),
    status: String(row.status || 'INVITED') as ConsoleTeamMember['status'],
    roles: parseRoleAssignments(row.roles),
    invitedByUserId: String(row.invited_by_user_id || ''),
    invitedAt: toIso(toNumber(row.invited_at_ms)) || new Date(0).toISOString(),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    lastStatusChangedAt:
      toIso(toNumber(row.last_status_changed_at_ms)) || new Date(0).toISOString(),
  };
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

function hasOwnerClaim(ctx: ConsoleTeamRbacContext): boolean {
  return ctx.roles.some(
    (entry) =>
      String(entry || '')
        .trim()
        .toLowerCase() === 'owner',
  );
}

function isConsoleLocalEmail(value: string): boolean {
  return String(value || '')
    .trim()
    .toLowerCase()
    .endsWith('@console.local');
}

function resolveActorEmail(ctx: ConsoleTeamRbacContext): string {
  const claimed = String(ctx.actorEmail || '')
    .trim()
    .toLowerCase();
  if (claimed && claimed.includes('@')) return claimed;
  return `${String(ctx.actorUserId || '').trim()}@console.local`;
}

function resolveActorDisplayName(ctx: ConsoleTeamRbacContext): string {
  const claimed = String(ctx.actorDisplayName || '').trim();
  if (claimed) return claimed;
  return String(ctx.actorUserId || '').trim();
}

function hasOwnerRole(member: ConsoleTeamMember): boolean {
  return member.roles.some((entry) => entry.role === 'owner');
}

function memberHasAdminEligibility(member: ConsoleTeamMember): boolean {
  return member.roles.some((entry) => entry.role === 'owner' || entry.role === 'admin');
}

function deriveActorRoles(ctx: ConsoleTeamRbacContext): ConsoleTeamRoleAssignment[] {
  const out: ConsoleTeamRoleAssignment[] = [];
  for (const roleRaw of ctx.roles) {
    const role = normalizeRole(roleRaw);
    if (!role) continue;
    out.push({ role, scope: 'ORG' });
  }
  return normalizeRoleAssignments(out);
}

async function countActiveOwners(
  q: Queryable,
  input: { namespace: string; orgId: string },
): Promise<number> {
  const row = await queryOne(
    q,
    `SELECT COUNT(*)::BIGINT AS owner_count
       FROM console_team_members
      WHERE namespace = $1
        AND org_id = $2
        AND status = 'ACTIVE'
        AND roles @> $3::jsonb`,
    [input.namespace, input.orgId, OWNER_ROLE_JSON],
  );
  return toNumber(row?.owner_count, 0);
}

async function findMemberById(
  q: Queryable,
  input: { namespace: string; orgId: string; memberId: string },
): Promise<ConsoleTeamMember | null> {
  const row = await queryOne(
    q,
    `SELECT *
       FROM console_team_members
      WHERE namespace = $1
        AND org_id = $2
        AND id = $3`,
    [input.namespace, input.orgId, input.memberId],
  );
  return row ? parseMemberRow(row) : null;
}

async function findMemberByUserId(
  q: Queryable,
  input: { namespace: string; orgId: string; userId: string },
): Promise<ConsoleTeamMember | null> {
  const row = await queryOne(
    q,
    `SELECT *
       FROM console_team_members
      WHERE namespace = $1
        AND org_id = $2
        AND user_id = $3`,
    [input.namespace, input.orgId, input.userId],
  );
  return row ? parseMemberRow(row) : null;
}

async function findMemberByEmail(
  q: Queryable,
  input: { namespace: string; orgId: string; email: string },
): Promise<ConsoleTeamMember | null> {
  const row = await queryOne(
    q,
    `SELECT *
       FROM console_team_members
      WHERE namespace = $1
        AND org_id = $2
        AND lower(email) = lower($3)`,
    [input.namespace, input.orgId, input.email],
  );
  return row ? parseMemberRow(row) : null;
}

async function ensureActorMembership(
  q: Queryable,
  input: {
    namespace: string;
    ctx: ConsoleTeamRbacContext;
    now: Date;
  },
): Promise<void> {
  const actorUserId = String(input.ctx.actorUserId || '').trim();
  if (!actorUserId) return;
  const actorRoles = deriveActorRoles(input.ctx);
  const actorEmail = resolveActorEmail(input.ctx);
  const actorDisplayName = resolveActorDisplayName(input.ctx);
  const ts = nowMs(input.now);
  const existing = await queryOne(
    q,
    `SELECT *
       FROM console_team_members
      WHERE namespace = $1
        AND org_id = $2
        AND user_id = $3`,
    [input.namespace, input.ctx.orgId, actorUserId],
  );

  if (!existing) {
    await q.query(
      `INSERT INTO console_team_members
        (namespace, id, org_id, user_id, email, display_name, status, roles, invited_by_user_id, invited_at_ms, last_status_changed_at_ms, created_at_ms, updated_at_ms)
       VALUES
        ($1, $2, $3, $4, $5, $6, 'ACTIVE', $7::jsonb, $4, $8, $8, $8, $8)`,
      [
        input.namespace,
        makeId('mbr', input.now),
        input.ctx.orgId,
        actorUserId,
        actorEmail,
        actorDisplayName,
        JSON.stringify(actorRoles),
        ts,
      ],
    );
    return;
  }

  const parsed = parseMemberRow(existing);
  const mergedRoles = normalizeRoleAssignments([...parsed.roles, ...actorRoles]);
  const nextEmail =
    actorEmail && (isConsoleLocalEmail(parsed.email) || !String(parsed.email || '').trim())
      ? actorEmail
      : parsed.email;
  const nextDisplayName =
    actorDisplayName &&
    (!String(parsed.displayName || '').trim() || String(parsed.displayName || '').trim() === actorUserId)
      ? actorDisplayName
      : parsed.displayName || null;
  await q.query(
    `UPDATE console_team_members
        SET status = 'ACTIVE',
            roles = $4::jsonb,
            email = $5,
            display_name = $6,
            updated_at_ms = $7,
            last_status_changed_at_ms = CASE
              WHEN status <> 'ACTIVE' THEN $7
              ELSE last_status_changed_at_ms
            END
      WHERE namespace = $1
        AND org_id = $2
        AND id = $3`,
    [
      input.namespace,
      input.ctx.orgId,
      parsed.id,
      JSON.stringify(mergedRoles),
      nextEmail,
      nextDisplayName,
      ts,
    ],
  );
}

export interface PostgresConsoleTeamRbacSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleTeamRbacPostgresSchema(
  options: PostgresConsoleTeamRbacSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_TEAM_RBAC_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_team_members (
        namespace TEXT NOT NULL,
        id TEXT NOT NULL,
        org_id TEXT NOT NULL,
        user_id TEXT,
        email TEXT NOT NULL,
        display_name TEXT,
        status TEXT NOT NULL,
        roles JSONB NOT NULL,
        invited_by_user_id TEXT NOT NULL,
        invited_at_ms BIGINT NOT NULL,
        last_status_changed_at_ms BIGINT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, id),
        CHECK (status IN ('INVITED', 'ACTIVE', 'SUSPENDED', 'REMOVED')),
        CHECK (jsonb_typeof(roles) = 'array')
      )
    `);

    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_team_members_org_email_uidx
      ON console_team_members (namespace, org_id, lower(email))
    `);
    await pool.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS console_team_members_org_user_uidx
      ON console_team_members (namespace, org_id, user_id)
      WHERE user_id IS NOT NULL
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_team_members_org_updated_idx
      ON console_team_members (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_team_members_org_status_idx
      ON console_team_members (namespace, org_id, status)
    `);

    await ensureConsoleTenantRlsPolicies({
      q: pool,
      table: 'console_team_members',
      policyName: 'console_team_members_tenant_rls',
    });
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_TEAM_RBAC_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-team-rbac][postgres] Schema ready');
}

export interface PostgresConsoleTeamRbacServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
}

export async function createPostgresConsoleTeamRbacService(
  options: PostgresConsoleTeamRbacServiceOptions,
): Promise<ConsoleTeamRbacService> {
  const postgresUrl = String(options.postgresUrl || '').trim();
  if (!postgresUrl) throw new Error('Missing POSTGRES_URL for Postgres console Team RBAC service');

  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const nowFn = options.now || (() => new Date());
  if (options.ensureSchema !== false) {
    await ensureConsoleTeamRbacPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }

  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    ctx: ConsoleTeamRbacContext,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId: ctx.orgId }, fn);

  return {
    async bootstrapOwner(ctx: ConsoleTeamRbacContext): Promise<ConsoleTeamMember> {
      return withTenantTx(ctx, async (q) => {
        const currentNow = nowFn();
        const ts = nowMs(currentNow);
        await ensureActorMembership(q, { namespace, ctx, now: currentNow });
        const actorUserId = String(ctx.actorUserId || '').trim();
        if (!actorUserId) {
          throw new ConsoleTeamRbacError('invalid_body', 400, 'Actor user id is required');
        }
        const actorRow = await queryOne(
          q,
          `SELECT *
             FROM console_team_members
            WHERE namespace = $1
              AND org_id = $2
              AND user_id = $3`,
          [namespace, ctx.orgId, actorUserId],
        );
        if (!actorRow) {
          throw new ConsoleTeamRbacError(
            'member_not_found',
            404,
            `Actor member for user ${actorUserId} was not found`,
          );
        }
        const actorMember = parseMemberRow(actorRow);
        if (hasOwnerRole(actorMember)) {
          const row = await queryOne(
            q,
            `UPDATE console_team_members
                SET status = 'ACTIVE',
                    updated_at_ms = $4,
                    last_status_changed_at_ms = CASE
                      WHEN status <> 'ACTIVE' THEN $4
                      ELSE last_status_changed_at_ms
                    END
              WHERE namespace = $1
                AND org_id = $2
                AND id = $3
            RETURNING *`,
            [namespace, ctx.orgId, actorMember.id, ts],
          );
          if (!row) {
            throw new ConsoleTeamRbacError('internal', 500, 'Failed to update owner membership');
          }
          return parseMemberRow(row);
        }
        const ownerCount = await countActiveOwners(q, { namespace, orgId: ctx.orgId });
        if (ownerCount > 0) {
          throw new ConsoleTeamRbacError(
            'owner_already_exists',
            409,
            'Owner membership already exists for this organization',
          );
        }
        const ownerRoles = normalizeRoleAssignments([
          ...actorMember.roles,
          { role: 'owner', scope: 'ORG' },
        ]);
        const row = await queryOne(
          q,
          `UPDATE console_team_members
              SET status = 'ACTIVE',
                  roles = $4::jsonb,
                  updated_at_ms = $5,
                  last_status_changed_at_ms = CASE
                    WHEN status <> 'ACTIVE' THEN $5
                    ELSE last_status_changed_at_ms
                  END
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
          RETURNING *`,
          [namespace, ctx.orgId, actorMember.id, JSON.stringify(ownerRoles), ts],
        );
        if (!row) {
          throw new ConsoleTeamRbacError('internal', 500, 'Failed to bootstrap owner membership');
        }
        return parseMemberRow(row);
      });
    },

    async listMembers(
      ctx: ConsoleTeamRbacContext,
      request?: ListConsoleTeamMembersRequest,
    ): Promise<ConsoleTeamMember[]> {
      return withTenantTx(ctx, async (q) => {
        const currentNow = nowFn();
        await ensureActorMembership(q, { namespace, ctx, now: currentNow });
        const status = String(request?.status || '').trim();
        const out = await q.query(
          `SELECT *
             FROM console_team_members
            WHERE namespace = $1
              AND org_id = $2
              AND ($3 = '' OR status = $3)
            ORDER BY updated_at_ms DESC, created_at_ms DESC`,
          [namespace, ctx.orgId, status],
        );
        return out.rows.map((row) => parseMemberRow(row as PgRow));
      });
    },

    async purgeOrganization(ctx: ConsoleTeamRbacContext): Promise<void> {
      await withTenantTx(ctx, async (q) => {
        await q.query(
          `DELETE FROM console_team_members
            WHERE namespace = $1
              AND org_id = $2`,
          [namespace, ctx.orgId],
        );
      });
    },

    async transferOwner(
      ctx: ConsoleTeamRbacContext,
      targetMemberId: string,
    ): Promise<{ previousOwner: ConsoleTeamMember; nextOwner: ConsoleTeamMember }> {
      return withTenantTx(ctx, async (q) => {
        const currentNow = nowFn();
        const ts = nowMs(currentNow);
        await ensureActorMembership(q, { namespace, ctx, now: currentNow });

        const actorUserId = String(ctx.actorUserId || '').trim();
        if (!actorUserId) {
          throw new ConsoleTeamRbacError('invalid_body', 400, 'Actor user id is required');
        }
        const actor = await findMemberByUserId(q, { namespace, orgId: ctx.orgId, userId: actorUserId });
        if (!actor) {
          throw new ConsoleTeamRbacError(
            'member_not_found',
            404,
            `Actor member for user ${actorUserId} was not found`,
          );
        }
        if (actor.status !== 'ACTIVE' || !hasOwnerRole(actor)) {
          throw new ConsoleTeamRbacError(
            'forbidden',
            403,
            'Only the current owner can transfer organization ownership',
          );
        }

        const target = await findMemberById(q, { namespace, orgId: ctx.orgId, memberId: targetMemberId });
        if (!target) {
          throw new ConsoleTeamRbacError(
            'member_not_found',
            404,
            `Member ${targetMemberId} was not found`,
          );
        }
        if (target.status !== 'ACTIVE') {
          throw new ConsoleTeamRbacError(
            'invalid_body',
            409,
            'Owner transfer target must be an active organization member',
          );
        }
        if (!memberHasAdminEligibility(target)) {
          throw new ConsoleTeamRbacError(
            'invalid_body',
            409,
            'Owner transfer target must already have admin eligibility',
          );
        }
        if (target.id === actor.id) {
          return {
            previousOwner: actor,
            nextOwner: target,
          };
        }

        const nextTargetRoles = normalizeRoleAssignments([
          ...target.roles,
          { role: 'owner', scope: 'ORG' },
          { role: 'admin', scope: 'ORG' },
        ]);
        const nextActorRoles = normalizeRoleAssignments([
          ...actor.roles.filter((entry) => entry.role !== 'owner'),
          { role: 'admin', scope: 'ORG' },
        ]);

        const targetRow = await queryOne(
          q,
          `UPDATE console_team_members
              SET roles = $4::jsonb,
                  updated_at_ms = $5
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
          RETURNING *`,
          [namespace, ctx.orgId, target.id, JSON.stringify(nextTargetRoles), ts],
        );
        const actorRow = await queryOne(
          q,
          `UPDATE console_team_members
              SET roles = $4::jsonb,
                  updated_at_ms = $5
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
          RETURNING *`,
          [namespace, ctx.orgId, actor.id, JSON.stringify(nextActorRoles), ts],
        );
        if (!targetRow || !actorRow) {
          throw new ConsoleTeamRbacError('internal', 500, 'Failed to transfer owner membership');
        }

        return {
          previousOwner: parseMemberRow(actorRow),
          nextOwner: parseMemberRow(targetRow),
        };
      });
    },

    async inviteMember(
      ctx: ConsoleTeamRbacContext,
      request: InviteConsoleTeamMemberRequest,
    ): Promise<ConsoleTeamMember> {
      return withTenantTx(ctx, async (q) => {
        const currentNow = nowFn();
        const ts = nowMs(currentNow);
        await ensureActorMembership(q, { namespace, ctx, now: currentNow });

        const roles = normalizeRoleAssignments(request.roles);
        if (roles.length === 0) {
          throw new ConsoleTeamRbacError(
            'invalid_body',
            400,
            'At least one role assignment is required',
          );
        }
        if (roles.some((entry) => entry.role === 'owner') && !hasOwnerClaim(ctx)) {
          throw new ConsoleTeamRbacError(
            'forbidden',
            403,
            'Only owner can assign owner role memberships',
          );
        }

        const userId = String(request.userId || '').trim();
        if (!userId) {
          throw new ConsoleTeamRbacError('invalid_body', 400, 'Field userId is required');
        }
        const email = String(request.email || '')
          .trim()
          .toLowerCase();
        if (!email) {
          throw new ConsoleTeamRbacError('invalid_body', 400, 'Field email is required');
        }
        const displayName = String(request.displayName || '').trim();

        const existingByUserId = await findMemberByUserId(q, {
          namespace,
          orgId: ctx.orgId,
          userId,
        });
        if (existingByUserId && existingByUserId.status !== 'REMOVED') {
          throw new ConsoleTeamRbacError(
            'member_already_exists',
            409,
            `Member with userId ${userId} already exists`,
          );
        }

        const existingByEmail = await findMemberByEmail(q, { namespace, orgId: ctx.orgId, email });
        if (
          existingByEmail &&
          existingByEmail.status !== 'REMOVED' &&
          (!existingByUserId || existingByUserId.id !== existingByEmail.id)
        ) {
          throw new ConsoleTeamRbacError(
            'member_already_exists',
            409,
            `Member with email ${email} already exists`,
          );
        }

        const removedMember =
          (existingByUserId && existingByUserId.status === 'REMOVED' ? existingByUserId : null) ||
          (existingByEmail && existingByEmail.status === 'REMOVED' ? existingByEmail : null);
        if (removedMember) {
          const row = await queryOne(
            q,
            `UPDATE console_team_members
                SET user_id = $4,
                    email = $5,
                    display_name = CASE
                      WHEN $6 = '' THEN display_name
                      ELSE $6
                    END,
                    status = 'ACTIVE',
                    roles = $7::jsonb,
                    invited_by_user_id = $8,
                    invited_at_ms = $9,
                    last_status_changed_at_ms = $9,
                    updated_at_ms = $9
              WHERE namespace = $1
                AND org_id = $2
                AND id = $3
            RETURNING *`,
            [
              namespace,
              ctx.orgId,
              removedMember.id,
              userId,
              email,
              displayName,
              JSON.stringify(roles),
              ctx.actorUserId,
              ts,
            ],
          );
          if (!row) {
            throw new ConsoleTeamRbacError('internal', 500, 'Failed to restore removed member');
          }
          return parseMemberRow(row);
        }

        const memberId = makeId('mbr', currentNow);
        const row = await queryOne(
          q,
          `INSERT INTO console_team_members
            (namespace, id, org_id, user_id, email, display_name, status, roles, invited_by_user_id, invited_at_ms, last_status_changed_at_ms, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, NULLIF($6, ''), 'ACTIVE', $7::jsonb, $8, $9, $9, $9, $9)
           RETURNING *`,
          [
            namespace,
            memberId,
            ctx.orgId,
            userId,
            email,
            displayName,
            JSON.stringify(roles),
            ctx.actorUserId,
            ts,
          ],
        );
        if (!row) {
          throw new ConsoleTeamRbacError('internal', 500, 'Failed to create member');
        }
        return parseMemberRow(row);
      });
    },

    async updateMemberRoles(
      ctx: ConsoleTeamRbacContext,
      memberId: string,
      request: UpdateConsoleTeamMemberRolesRequest,
    ): Promise<ConsoleTeamMember | null> {
      return withTenantTx(ctx, async (q) => {
        const currentNow = nowFn();
        const ts = nowMs(currentNow);
        await ensureActorMembership(q, { namespace, ctx, now: currentNow });

        const member = await findMemberById(q, { namespace, orgId: ctx.orgId, memberId });
        if (!member) return null;
        if (member.status === 'REMOVED') {
          throw new ConsoleTeamRbacError(
            'member_removed',
            409,
            `Member ${memberId} is removed and cannot be mutated`,
          );
        }

        const roles = normalizeRoleAssignments(request.roles);
        if (roles.length === 0) {
          throw new ConsoleTeamRbacError(
            'invalid_body',
            400,
            'At least one role assignment is required',
          );
        }
        if (roles.some((entry) => entry.role === 'owner') && !hasOwnerClaim(ctx)) {
          throw new ConsoleTeamRbacError(
            'forbidden',
            403,
            'Only owner can assign owner role memberships',
          );
        }

        const wasOwner = hasOwnerRole(member);
        const willBeOwner = roles.some((entry) => entry.role === 'owner');
        if (wasOwner && !willBeOwner && member.status === 'ACTIVE') {
          const ownerCount = await countActiveOwners(q, { namespace, orgId: ctx.orgId });
          if (ownerCount <= 1) {
            throw new ConsoleTeamRbacError(
              'last_owner_required',
              409,
              'Cannot remove owner role from the last active owner in the organization',
            );
          }
        }

        const nextEmail =
          String(member.userId || '').trim() === String(ctx.actorUserId || '').trim()
            ? (() => {
                const actorEmail = resolveActorEmail(ctx);
                if (actorEmail && (isConsoleLocalEmail(member.email) || !String(member.email || '').trim())) {
                  return actorEmail;
                }
                return member.email;
              })()
            : member.email;
        const nextDisplayName =
          String(member.userId || '').trim() === String(ctx.actorUserId || '').trim()
            ? (() => {
                const actorDisplayName = resolveActorDisplayName(ctx);
                if (
                  actorDisplayName &&
                  (!String(member.displayName || '').trim() ||
                    String(member.displayName || '').trim() === String(ctx.actorUserId || '').trim())
                ) {
                  return actorDisplayName;
                }
                return member.displayName || null;
              })()
            : member.displayName || null;
        const row = await queryOne(
          q,
          `UPDATE console_team_members
              SET roles = $4::jsonb,
                  email = $5,
                  display_name = $6,
                  updated_at_ms = $7
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
          RETURNING *`,
          [namespace, ctx.orgId, memberId, JSON.stringify(roles), nextEmail, nextDisplayName, ts],
        );
        return row ? parseMemberRow(row) : null;
      });
    },

    async removeMember(
      ctx: ConsoleTeamRbacContext,
      memberId: string,
    ): Promise<{ removed: boolean; member: ConsoleTeamMember | null }> {
      return withTenantTx(ctx, async (q) => {
        const currentNow = nowFn();
        const ts = nowMs(currentNow);
        await ensureActorMembership(q, { namespace, ctx, now: currentNow });

        const member = await findMemberById(q, { namespace, orgId: ctx.orgId, memberId });
        if (!member) return { removed: false, member: null };
        if (member.status === 'REMOVED') return { removed: true, member };

        if (hasOwnerRole(member) && member.status === 'ACTIVE') {
          const ownerCount = await countActiveOwners(q, { namespace, orgId: ctx.orgId });
          if (ownerCount <= 1) {
            throw new ConsoleTeamRbacError(
              'last_owner_required',
              409,
              'Cannot remove the last active owner in the organization',
            );
          }
        }

        const row = await queryOne(
          q,
          `UPDATE console_team_members
              SET status = 'REMOVED',
                  roles = '[]'::jsonb,
                  updated_at_ms = $4,
                  last_status_changed_at_ms = $4
            WHERE namespace = $1
              AND org_id = $2
              AND id = $3
          RETURNING *`,
          [namespace, ctx.orgId, memberId, ts],
        );
        return { removed: true, member: row ? parseMemberRow(row) : null };
      });
    },
  };
}
