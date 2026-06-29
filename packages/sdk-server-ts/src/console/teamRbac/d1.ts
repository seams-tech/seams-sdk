import { secureRandomBase36 } from '@shared/utils/secureRandomId';
import {
  d1Number as toNumber,
  d1ChangedRows,
  formatD1ExecStatement,
  parseD1JsonArrayColumn,
  queryD1All,
  queryD1One,
  type D1Row,
} from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import { ConsoleTeamRbacError } from './errors';
import type { ConsoleTeamRbacContext, ConsoleTeamRbacService } from './service';
import {
  CONSOLE_ORG_SCOPED_TEAM_ROLES,
  type ConsoleTeamMember,
  type ConsoleTeamMembershipStatus,
  type ConsoleTeamRole,
  type ConsoleTeamRoleAssignment,
  type InviteConsoleTeamMemberRequest,
  type ListConsoleTeamMembersRequest,
  type UpdateConsoleTeamMemberRolesRequest,
} from './types';

const ORG_ROLE_SET = new Set<string>(CONSOLE_ORG_SCOPED_TEAM_ROLES);

export const CONSOLE_TEAM_RBAC_D1_RUNTIME = Symbol('consoleTeamRbacD1Runtime');

export interface ConsoleTeamRbacD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export type ConsoleTeamRbacD1Service = ConsoleTeamRbacService & {
  [CONSOLE_TEAM_RBAC_D1_RUNTIME]: ConsoleTeamRbacD1Runtime;
};

export interface D1ConsoleTeamRbacSchemaOptions {
  database: D1DatabaseLike;
}

export interface D1ConsoleTeamRbacServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  ensureSchema?: boolean;
  now?: () => Date;
}

interface D1TeamRbacState {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export const CONSOLE_TEAM_RBAC_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS team_members (
      namespace TEXT NOT NULL,
      id TEXT NOT NULL,
      org_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      email TEXT NOT NULL,
      email_normalized TEXT NOT NULL,
      display_name TEXT,
      status TEXT NOT NULL,
      roles_json TEXT NOT NULL,
      invited_by_user_id TEXT NOT NULL,
      invited_at_ms INTEGER NOT NULL,
      last_status_changed_at_ms INTEGER NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, id),
      CHECK (status IN ('INVITED', 'ACTIVE', 'SUSPENDED', 'REMOVED')),
      CHECK (json_valid(roles_json))
    )
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS team_members_org_email_uidx
      ON team_members (namespace, org_id, email_normalized)
  `,
  `
    CREATE UNIQUE INDEX IF NOT EXISTS team_members_org_user_uidx
      ON team_members (namespace, org_id, user_id)
  `,
  `
    CREATE INDEX IF NOT EXISTS team_members_org_updated_idx
      ON team_members (namespace, org_id, updated_at_ms DESC, created_at_ms DESC)
  `,
  `
    CREATE INDEX IF NOT EXISTS team_members_org_status_idx
      ON team_members (namespace, org_id, status)
  `,
] as const);

export async function ensureConsoleTeamRbacD1Schema(
  options: D1ConsoleTeamRbacSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_TEAM_RBAC_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleTeamRbacD1Runtime(
  service: ConsoleTeamRbacService | null | undefined,
): ConsoleTeamRbacD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleTeamRbacD1Service>)[CONSOLE_TEAM_RBAC_D1_RUNTIME] || null
  );
}

function defaultNow(): Date {
  return new Date();
}

function ensureNamespace(namespace: string | undefined): string {
  const normalized = String(namespace || 'default').trim();
  return normalized || 'default';
}

function nowMs(now: Date): number {
  return now.getTime();
}

function toIso(ms: number): string {
  return new Date(ms).toISOString();
}


function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function normalizeLower(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function makeId(prefix: string, now: Date): string {
  return `${prefix}_${now.getTime().toString(36)}_${secureRandomBase36(8, 'console IDs')}`;
}


function normalizeRole(raw: unknown): ConsoleTeamRole | null {
  const role = normalizeLower(raw);
  if (!ORG_ROLE_SET.has(role)) return null;
  return role as ConsoleTeamRole;
}

function parseRoleAssignments(raw: unknown): ConsoleTeamRoleAssignment[] {
  const out: ConsoleTeamRoleAssignment[] = [];
  const seen = new Set<string>();
  for (const entryRaw of parseD1JsonArrayColumn(raw)) {
    if (!entryRaw || typeof entryRaw !== 'object' || Array.isArray(entryRaw)) continue;
    const entry = entryRaw as Record<string, unknown>;
    const role = normalizeRole(entry.role);
    if (!role) continue;
    if (normalizeString(entry.projectId)) continue;
    const key = `ORG:${role}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push({ role, scope: 'ORG' });
  }
  return out.sort((left, right) => left.role.localeCompare(right.role));
}

function normalizeRoleAssignments(input: ConsoleTeamRoleAssignment[]): ConsoleTeamRoleAssignment[] {
  return parseRoleAssignments(input);
}

function parseMembershipStatus(value: unknown): ConsoleTeamMembershipStatus {
  const normalized = normalizeString(value);
  switch (normalized) {
    case 'INVITED':
    case 'ACTIVE':
    case 'SUSPENDED':
    case 'REMOVED':
      return normalized;
    default:
      throw new Error(`Invalid console team member status row: ${normalized || 'empty'}`);
  }
}

function normalizeListStatus(
  request: ListConsoleTeamMembersRequest | undefined,
): ConsoleTeamMembershipStatus | undefined {
  if (!request?.status || request.status === 'ALL') return undefined;
  return request.status;
}

function parseMemberRow(row: D1Row): ConsoleTeamMember {
  return {
    id: normalizeString(row.id),
    orgId: normalizeString(row.org_id),
    userId: normalizeString(row.user_id || row.id),
    email: normalizeString(row.email),
    ...(normalizeString(row.display_name)
      ? { displayName: normalizeString(row.display_name) }
      : {}),
    status: parseMembershipStatus(row.status || 'INVITED'),
    roles: parseRoleAssignments(row.roles_json || row.roles),
    invitedByUserId: normalizeString(row.invited_by_user_id),
    invitedAt: toIso(toNumber(row.invited_at_ms)),
    createdAt: toIso(toNumber(row.created_at_ms)),
    updatedAt: toIso(toNumber(row.updated_at_ms)),
    lastStatusChangedAt: toIso(toNumber(row.last_status_changed_at_ms)),
  };
}

function rolesJson(roles: readonly ConsoleTeamRoleAssignment[]): string {
  return JSON.stringify(roles.map((entry) => ({ role: entry.role, scope: 'ORG' })));
}

function hasOwnerClaim(ctx: ConsoleTeamRbacContext): boolean {
  return ctx.roles.some((entry) => normalizeLower(entry) === 'owner');
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

function isConsoleLocalEmail(value: string): boolean {
  return normalizeLower(value).endsWith('@console.local');
}

function resolveActorEmail(ctx: ConsoleTeamRbacContext): string {
  const claimed = normalizeLower(ctx.actorEmail);
  if (claimed && claimed.includes('@')) return claimed;
  return `${normalizeString(ctx.actorUserId)}@console.local`;
}

function resolveActorDisplayName(ctx: ConsoleTeamRbacContext): string {
  const claimed = normalizeString(ctx.actorDisplayName);
  if (claimed) return claimed;
  return normalizeString(ctx.actorUserId);
}

async function findMemberById(input: {
  state: D1TeamRbacState;
  orgId: string;
  memberId: string;
}): Promise<ConsoleTeamMember | null> {
  const row = await queryD1One(
    input.state.database,
    `SELECT *
       FROM team_members
      WHERE namespace = ?
        AND org_id = ?
        AND id = ?
      LIMIT 1`,
    [input.state.namespace, input.orgId, input.memberId],
  );
  return row ? parseMemberRow(row) : null;
}

async function findMemberByUserId(input: {
  state: D1TeamRbacState;
  orgId: string;
  userId: string;
}): Promise<ConsoleTeamMember | null> {
  const row = await queryD1One(
    input.state.database,
    `SELECT *
       FROM team_members
      WHERE namespace = ?
        AND org_id = ?
        AND user_id = ?
      LIMIT 1`,
    [input.state.namespace, input.orgId, input.userId],
  );
  return row ? parseMemberRow(row) : null;
}

async function findMemberByEmail(input: {
  state: D1TeamRbacState;
  orgId: string;
  email: string;
}): Promise<ConsoleTeamMember | null> {
  const row = await queryD1One(
    input.state.database,
    `SELECT *
       FROM team_members
      WHERE namespace = ?
        AND org_id = ?
        AND email_normalized = ?
      LIMIT 1`,
    [input.state.namespace, input.orgId, normalizeLower(input.email)],
  );
  return row ? parseMemberRow(row) : null;
}

async function listMembersForOrg(input: {
  state: D1TeamRbacState;
  orgId: string;
  status?: ConsoleTeamMembershipStatus;
}): Promise<ConsoleTeamMember[]> {
  const values: unknown[] = [input.state.namespace, input.orgId];
  let statusFilter = '';
  if (input.status) {
    values.push(input.status);
    statusFilter = ' AND status = ?';
  }
  const rows = await queryD1All(
    input.state.database,
    `SELECT *
       FROM team_members
      WHERE namespace = ?
        AND org_id = ?${statusFilter}
      ORDER BY updated_at_ms DESC, created_at_ms DESC`,
    values,
  );
  return rows.map(parseMemberRow);
}

async function countActiveOwners(input: {
  state: D1TeamRbacState;
  orgId: string;
}): Promise<number> {
  const members = await listMembersForOrg({
    state: input.state,
    orgId: input.orgId,
    status: 'ACTIVE',
  });
  let count = 0;
  for (const member of members) {
    if (hasOwnerRole(member)) count += 1;
  }
  return count;
}

async function insertActorMembership(input: {
  state: D1TeamRbacState;
  ctx: ConsoleTeamRbacContext;
  actorUserId: string;
  actorEmail: string;
  actorDisplayName: string;
  actorRoles: ConsoleTeamRoleAssignment[];
  nowMsValue: number;
}): Promise<void> {
  await input.state.database
    .prepare(
      `INSERT INTO team_members
        (namespace, id, org_id, user_id, email, email_normalized, display_name, status, roles_json, invited_by_user_id, invited_at_ms, last_status_changed_at_ms, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.state.namespace,
      makeId('mbr', input.state.now()),
      input.ctx.orgId,
      input.actorUserId,
      input.actorEmail,
      normalizeLower(input.actorEmail),
      input.actorDisplayName,
      rolesJson(input.actorRoles),
      input.actorUserId,
      input.nowMsValue,
      input.nowMsValue,
      input.nowMsValue,
      input.nowMsValue,
    )
    .run();
}

async function updateActorMembership(input: {
  state: D1TeamRbacState;
  ctx: ConsoleTeamRbacContext;
  existing: ConsoleTeamMember;
  actorEmail: string;
  actorDisplayName: string;
  actorRoles: ConsoleTeamRoleAssignment[];
  nowMsValue: number;
}): Promise<void> {
  const mergedRoles = normalizeRoleAssignments([
    ...input.existing.roles,
    ...input.actorRoles,
  ]);
  const nextEmail =
    input.actorEmail &&
    (isConsoleLocalEmail(input.existing.email) || !normalizeString(input.existing.email))
      ? input.actorEmail
      : input.existing.email;
  const nextDisplayName =
    input.actorDisplayName &&
    (!normalizeString(input.existing.displayName) ||
      normalizeString(input.existing.displayName) === normalizeString(input.ctx.actorUserId))
      ? input.actorDisplayName
      : input.existing.displayName || null;
  await input.state.database
    .prepare(
      `UPDATE team_members
          SET status = 'ACTIVE',
              roles_json = ?,
              email = ?,
              email_normalized = ?,
              display_name = ?,
              updated_at_ms = ?,
              last_status_changed_at_ms = CASE
                WHEN status <> 'ACTIVE' THEN ?
                ELSE last_status_changed_at_ms
              END
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?`,
    )
    .bind(
      rolesJson(mergedRoles),
      nextEmail,
      normalizeLower(nextEmail),
      nextDisplayName,
      input.nowMsValue,
      input.nowMsValue,
      input.state.namespace,
      input.ctx.orgId,
      input.existing.id,
    )
    .run();
}

async function ensureActorMembership(input: {
  state: D1TeamRbacState;
  ctx: ConsoleTeamRbacContext;
}): Promise<void> {
  const actorUserId = normalizeString(input.ctx.actorUserId);
  if (!actorUserId) return;
  const actorRoles = deriveActorRoles(input.ctx);
  const actorEmail = resolveActorEmail(input.ctx);
  const actorDisplayName = resolveActorDisplayName(input.ctx);
  const nowMsValue = nowMs(input.state.now());
  const existing = await findMemberByUserId({
    state: input.state,
    orgId: input.ctx.orgId,
    userId: actorUserId,
  });
  if (!existing) {
    await insertActorMembership({
      state: input.state,
      ctx: input.ctx,
      actorUserId,
      actorEmail,
      actorDisplayName,
      actorRoles,
      nowMsValue,
    });
    return;
  }
  await updateActorMembership({
    state: input.state,
    ctx: input.ctx,
    existing,
    actorEmail,
    actorDisplayName,
    actorRoles,
    nowMsValue,
  });
}

async function loadActorMember(input: {
  state: D1TeamRbacState;
  ctx: ConsoleTeamRbacContext;
}): Promise<ConsoleTeamMember> {
  const actorUserId = normalizeString(input.ctx.actorUserId);
  if (!actorUserId) {
    throw new ConsoleTeamRbacError('invalid_body', 400, 'Actor user id is required');
  }
  const actor = await findMemberByUserId({
    state: input.state,
    orgId: input.ctx.orgId,
    userId: actorUserId,
  });
  if (!actor) {
    throw new ConsoleTeamRbacError(
      'member_not_found',
      404,
      `Actor member for user ${actorUserId} was not found`,
    );
  }
  return actor;
}

async function updateMemberRolesJson(input: {
  state: D1TeamRbacState;
  orgId: string;
  memberId: string;
  roles: readonly ConsoleTeamRoleAssignment[];
  nowMsValue: number;
}): Promise<ConsoleTeamMember | null> {
  const result = await input.state.database
    .prepare(
      `UPDATE team_members
          SET roles_json = ?,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?`,
    )
    .bind(
      rolesJson(input.roles),
      input.nowMsValue,
      input.state.namespace,
      input.orgId,
      input.memberId,
    )
    .run();
  if (d1ChangedRows(result) !== 1) return null;
  return await findMemberById({
    state: input.state,
    orgId: input.orgId,
    memberId: input.memberId,
  });
}

async function restoreRemovedMember(input: {
  state: D1TeamRbacState;
  ctx: ConsoleTeamRbacContext;
  removedMember: ConsoleTeamMember;
  userId: string;
  email: string;
  displayName: string;
  roles: readonly ConsoleTeamRoleAssignment[];
  nowMsValue: number;
}): Promise<ConsoleTeamMember> {
  await input.state.database
    .prepare(
      `UPDATE team_members
          SET user_id = ?,
              email = ?,
              email_normalized = ?,
              display_name = CASE
                WHEN ? = '' THEN display_name
                ELSE ?
              END,
              status = 'ACTIVE',
              roles_json = ?,
              invited_by_user_id = ?,
              invited_at_ms = ?,
              last_status_changed_at_ms = ?,
              updated_at_ms = ?
        WHERE namespace = ?
          AND org_id = ?
          AND id = ?`,
    )
    .bind(
      input.userId,
      input.email,
      normalizeLower(input.email),
      input.displayName,
      input.displayName,
      rolesJson(input.roles),
      input.ctx.actorUserId,
      input.nowMsValue,
      input.nowMsValue,
      input.nowMsValue,
      input.state.namespace,
      input.ctx.orgId,
      input.removedMember.id,
    )
    .run();
  const member = await findMemberById({
    state: input.state,
    orgId: input.ctx.orgId,
    memberId: input.removedMember.id,
  });
  if (!member) {
    throw new ConsoleTeamRbacError('internal', 500, 'Failed to restore removed member');
  }
  return member;
}

async function insertMember(input: {
  state: D1TeamRbacState;
  ctx: ConsoleTeamRbacContext;
  userId: string;
  email: string;
  displayName: string;
  roles: readonly ConsoleTeamRoleAssignment[];
  now: Date;
}): Promise<ConsoleTeamMember> {
  const memberId = makeId('mbr', input.now);
  const ts = nowMs(input.now);
  await input.state.database
    .prepare(
      `INSERT INTO team_members
        (namespace, id, org_id, user_id, email, email_normalized, display_name, status, roles_json, invited_by_user_id, invited_at_ms, last_status_changed_at_ms, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, ?, ?, ?, ?, NULLIF(?, ''), 'ACTIVE', ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      input.state.namespace,
      memberId,
      input.ctx.orgId,
      input.userId,
      input.email,
      normalizeLower(input.email),
      input.displayName,
      rolesJson(input.roles),
      input.ctx.actorUserId,
      ts,
      ts,
      ts,
      ts,
    )
    .run();
  const member = await findMemberById({
    state: input.state,
    orgId: input.ctx.orgId,
    memberId,
  });
  if (!member) {
    throw new ConsoleTeamRbacError('internal', 500, 'Failed to create member');
  }
  return member;
}

export async function createD1ConsoleTeamRbacService(
  options: D1ConsoleTeamRbacServiceOptions,
): Promise<ConsoleTeamRbacService> {
  if (options.ensureSchema) {
    await ensureConsoleTeamRbacD1Schema({ database: options.database });
  }
  const state: D1TeamRbacState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
  };
  const runtime: ConsoleTeamRbacD1Runtime = {
    database: state.database,
    namespace: state.namespace,
    now: state.now,
  };

  const service: ConsoleTeamRbacD1Service = {
    async bootstrapOwner(ctx): Promise<ConsoleTeamMember> {
      await ensureActorMembership({ state, ctx });
      const actor = await loadActorMember({ state, ctx });
      const currentNow = state.now();
      const ts = nowMs(currentNow);
      if (hasOwnerRole(actor)) {
        await state.database
          .prepare(
            `UPDATE team_members
                SET status = 'ACTIVE',
                    updated_at_ms = ?,
                    last_status_changed_at_ms = CASE
                      WHEN status <> 'ACTIVE' THEN ?
                      ELSE last_status_changed_at_ms
                    END
              WHERE namespace = ?
                AND org_id = ?
                AND id = ?`,
          )
          .bind(ts, ts, state.namespace, ctx.orgId, actor.id)
          .run();
        const refreshed = await findMemberById({ state, orgId: ctx.orgId, memberId: actor.id });
        if (!refreshed) {
          throw new ConsoleTeamRbacError('internal', 500, 'Failed to update owner membership');
        }
        return refreshed;
      }

      const ownerCount = await countActiveOwners({ state, orgId: ctx.orgId });
      if (ownerCount > 0) {
        throw new ConsoleTeamRbacError(
          'owner_already_exists',
          409,
          'Owner membership already exists for this organization',
        );
      }
      const ownerRoles = normalizeRoleAssignments([
        ...actor.roles,
        { role: 'owner', scope: 'ORG' },
      ]);
      const updated = await updateMemberRolesJson({
        state,
        orgId: ctx.orgId,
        memberId: actor.id,
        roles: ownerRoles,
        nowMsValue: ts,
      });
      if (!updated) {
        throw new ConsoleTeamRbacError('internal', 500, 'Failed to bootstrap owner membership');
      }
      return updated;
    },

    async listMembers(ctx, request?: ListConsoleTeamMembersRequest): Promise<ConsoleTeamMember[]> {
      await ensureActorMembership({ state, ctx });
      return await listMembersForOrg({
        state,
        orgId: ctx.orgId,
        status: normalizeListStatus(request),
      });
    },

    async listOrganizationMembers(
      orgId: string,
      request?: ListConsoleTeamMembersRequest,
    ): Promise<ConsoleTeamMember[]> {
      return await listMembersForOrg({
        state,
        orgId,
        status: normalizeListStatus(request),
      });
    },

    async purgeOrganization(ctx): Promise<void> {
      await state.database
        .prepare(
          `DELETE FROM team_members
            WHERE namespace = ?
              AND org_id = ?`,
        )
        .bind(state.namespace, ctx.orgId)
        .run();
    },

    async transferOwner(ctx, targetMemberId): Promise<{
      previousOwner: ConsoleTeamMember;
      nextOwner: ConsoleTeamMember;
    }> {
      await ensureActorMembership({ state, ctx });
      const actor = await loadActorMember({ state, ctx });
      if (actor.status !== 'ACTIVE' || !hasOwnerRole(actor)) {
        throw new ConsoleTeamRbacError(
          'forbidden',
          403,
          'Only the current owner can transfer organization ownership',
        );
      }
      const target = await findMemberById({ state, orgId: ctx.orgId, memberId: targetMemberId });
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
        return { previousOwner: actor, nextOwner: target };
      }

      const ts = nowMs(state.now());
      const nextTargetRoles = normalizeRoleAssignments([
        ...target.roles,
        { role: 'owner', scope: 'ORG' },
        { role: 'admin', scope: 'ORG' },
      ]);
      const nextActorRoles = normalizeRoleAssignments([
        ...actor.roles.filter((entry) => entry.role !== 'owner'),
        { role: 'admin', scope: 'ORG' },
      ]);
      await state.database.batch([
        state.database
          .prepare(
            `UPDATE team_members
                SET roles_json = ?,
                    updated_at_ms = ?
              WHERE namespace = ?
                AND org_id = ?
                AND id = ?`,
          )
          .bind(rolesJson(nextTargetRoles), ts, state.namespace, ctx.orgId, target.id),
        state.database
          .prepare(
            `UPDATE team_members
                SET roles_json = ?,
                    updated_at_ms = ?
              WHERE namespace = ?
                AND org_id = ?
                AND id = ?`,
          )
          .bind(rolesJson(nextActorRoles), ts, state.namespace, ctx.orgId, actor.id),
      ]);
      const previousOwner = await findMemberById({
        state,
        orgId: ctx.orgId,
        memberId: actor.id,
      });
      const nextOwner = await findMemberById({
        state,
        orgId: ctx.orgId,
        memberId: target.id,
      });
      if (!previousOwner || !nextOwner) {
        throw new ConsoleTeamRbacError('internal', 500, 'Failed to transfer owner membership');
      }
      return { previousOwner, nextOwner };
    },

    async inviteMember(
      ctx,
      request: InviteConsoleTeamMemberRequest,
    ): Promise<ConsoleTeamMember> {
      await ensureActorMembership({ state, ctx });
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

      const userId = normalizeString(request.userId);
      if (!userId) {
        throw new ConsoleTeamRbacError('invalid_body', 400, 'Field userId is required');
      }
      const email = normalizeLower(request.email);
      if (!email) {
        throw new ConsoleTeamRbacError('invalid_body', 400, 'Field email is required');
      }
      const displayName = normalizeString(request.displayName);
      const existingByUserId = await findMemberByUserId({ state, orgId: ctx.orgId, userId });
      if (existingByUserId && existingByUserId.status !== 'REMOVED') {
        throw new ConsoleTeamRbacError(
          'member_already_exists',
          409,
          `Member with userId ${userId} already exists`,
        );
      }
      const existingByEmail = await findMemberByEmail({ state, orgId: ctx.orgId, email });
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
        return await restoreRemovedMember({
          state,
          ctx,
          removedMember,
          userId,
          email,
          displayName,
          roles,
          nowMsValue: nowMs(state.now()),
        });
      }
      return await insertMember({
        state,
        ctx,
        userId,
        email,
        displayName,
        roles,
        now: state.now(),
      });
    },

    async updateMemberRoles(
      ctx,
      memberId: string,
      request: UpdateConsoleTeamMemberRolesRequest,
    ): Promise<ConsoleTeamMember | null> {
      await ensureActorMembership({ state, ctx });
      const member = await findMemberById({ state, orgId: ctx.orgId, memberId });
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
        const ownerCount = await countActiveOwners({ state, orgId: ctx.orgId });
        if (ownerCount <= 1) {
          throw new ConsoleTeamRbacError(
            'last_owner_required',
            409,
            'Cannot remove owner role from the last active owner in the organization',
          );
        }
      }

      const actorIsTarget = normalizeString(member.userId) === normalizeString(ctx.actorUserId);
      const actorEmail = actorIsTarget ? resolveActorEmail(ctx) : '';
      const actorDisplayName = actorIsTarget ? resolveActorDisplayName(ctx) : '';
      const nextEmail =
        actorEmail && (isConsoleLocalEmail(member.email) || !normalizeString(member.email))
          ? actorEmail
          : member.email;
      const nextDisplayName =
        actorDisplayName &&
        (!normalizeString(member.displayName) ||
          normalizeString(member.displayName) === normalizeString(ctx.actorUserId))
          ? actorDisplayName
          : member.displayName || null;
      const result = await state.database
        .prepare(
          `UPDATE team_members
              SET roles_json = ?,
                  email = ?,
                  email_normalized = ?,
                  display_name = ?,
                  updated_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(
          rolesJson(roles),
          nextEmail,
          normalizeLower(nextEmail),
          nextDisplayName,
          nowMs(state.now()),
          state.namespace,
          ctx.orgId,
          memberId,
        )
        .run();
      if (d1ChangedRows(result) !== 1) return null;
      return await findMemberById({ state, orgId: ctx.orgId, memberId });
    },

    async removeMember(ctx, memberId): Promise<{
      removed: boolean;
      member: ConsoleTeamMember | null;
    }> {
      await ensureActorMembership({ state, ctx });
      const member = await findMemberById({ state, orgId: ctx.orgId, memberId });
      if (!member) return { removed: false, member: null };
      if (member.status === 'REMOVED') return { removed: true, member };

      if (hasOwnerRole(member) && member.status === 'ACTIVE') {
        const ownerCount = await countActiveOwners({ state, orgId: ctx.orgId });
        if (ownerCount <= 1) {
          throw new ConsoleTeamRbacError(
            'last_owner_required',
            409,
            'Cannot remove the last active owner in the organization',
          );
        }
      }

      const ts = nowMs(state.now());
      const result = await state.database
        .prepare(
          `UPDATE team_members
              SET status = 'REMOVED',
                  roles_json = '[]',
                  updated_at_ms = ?,
                  last_status_changed_at_ms = ?
            WHERE namespace = ?
              AND org_id = ?
              AND id = ?`,
        )
        .bind(ts, ts, state.namespace, ctx.orgId, memberId)
        .run();
      if (d1ChangedRows(result) !== 1) return { removed: false, member: null };
      return {
        removed: true,
        member: await findMemberById({ state, orgId: ctx.orgId, memberId }),
      };
    },

    [CONSOLE_TEAM_RBAC_D1_RUNTIME]: runtime,
  };

  return service;
}
