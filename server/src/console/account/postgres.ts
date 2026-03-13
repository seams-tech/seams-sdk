import type { NormalizedLogger } from '../../core/logger';
import { getPostgresPool } from '../../storage/postgres';
import { generateConsoleOrganizationId } from '@shared/console/organizationIdentity';
import {
  ensureConsoleNamespace as ensureNamespace,
  toConsoleIso as toIso,
  toConsoleNumber as toNumber,
} from '../shared/postgresNormalize';
import { withConsoleTenantContextTx } from '../shared/postgresTenantContext';
import type { ConsoleOnboardingService } from '../onboarding';
import type { ConsoleOrgProjectEnvService } from '../orgProjectEnv';
import type { ConsoleTeamMember, ConsoleTeamRbacService } from '../teamRbac';
import { ConsoleAccountError } from './errors';
import { type ConsoleAccountContext, type ConsoleAccountService } from './service';
import type {
  ConsoleAccountBackupEmail,
  DeleteConsoleAccountOrganizationResult,
  ConsoleAccountOrganization,
  ConsoleAccountOrganizationAdminCandidate,
  ConsoleAccountProfile,
  SwitchConsoleAccountOrganizationContextResult,
  TransferConsoleAccountOrganizationOwnerResult,
} from './types';
import type { ConsoleWalletService } from '../wallets';

type PgPool = Awaited<ReturnType<typeof getPostgresPool>>;
type Queryable = Pick<PgPool, 'query'>;
type PgRow = Record<string, unknown>;

const CONSOLE_ACCOUNT_MIGRATION_LOCK_ID = 9452360123599;

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function normalizeLower(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function hasAdminEligibility(member: ConsoleTeamMember): boolean {
  return member.roles.some((entry) => entry.role === 'owner' || entry.role === 'admin');
}

function parseRoleAssignments(raw: unknown): ConsoleAccountOrganizationAdminCandidate['roles'] {
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
  return source
    .filter((entry) => entry && typeof entry === 'object' && !Array.isArray(entry))
    .map((entry) => ({
      role:
        normalizeString((entry as Record<string, unknown>).role) as
          ConsoleAccountOrganizationAdminCandidate['roles'][number]['role'],
      scope: 'ORG' as const,
    }));
}

function parseMemberRow(row: PgRow): ConsoleTeamMember {
  return {
    id: normalizeString(row.id),
    orgId: normalizeString(row.org_id),
    userId: normalizeString(row.user_id),
    email: normalizeString(row.email),
    ...(normalizeString(row.display_name)
      ? { displayName: normalizeString(row.display_name) }
      : {}),
    status: normalizeString(row.status) as ConsoleTeamMember['status'],
    roles: parseRoleAssignments(row.roles),
    invitedByUserId: normalizeString(row.invited_by_user_id),
    invitedAt: toIso(toNumber(row.invited_at_ms)) || new Date(0).toISOString(),
    createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
    updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    lastStatusChangedAt:
      toIso(toNumber(row.last_status_changed_at_ms)) || new Date(0).toISOString(),
  };
}

function toAdminCandidate(member: ConsoleTeamMember): ConsoleAccountOrganizationAdminCandidate {
  return {
    memberId: member.id,
    userId: member.userId,
    email: member.email,
    displayName: normalizeString(member.displayName) || member.userId,
    isOwner: member.roles.some((entry) => entry.role === 'owner'),
    roles: member.roles.map((entry) => ({ ...entry })),
  };
}

function accountError(code: string, status: number, message: string): ConsoleAccountError {
  return new ConsoleAccountError(code, status, message);
}

function canEditPrimaryEmail(ctx: ConsoleAccountContext): boolean {
  return normalizeLower(ctx.provider) !== 'oidc';
}

async function queryOne(q: Queryable, text: string, values: unknown[]): Promise<PgRow | null> {
  const out = await q.query(text, values);
  return (out.rows[0] as PgRow) || null;
}

async function resolveOnboardingState(input: {
  ctx: ConsoleAccountContext;
  orgId: string;
  onboarding?: ConsoleOnboardingService | null;
  orgProjectEnv: ConsoleOrgProjectEnvService;
}): Promise<SwitchConsoleAccountOrganizationContextResult> {
  const targetCtx = {
    orgId: input.orgId,
    actorUserId: input.ctx.userId,
    roles: [],
    ...(input.ctx.email ? { actorEmail: input.ctx.email } : {}),
    ...(input.ctx.name ? { actorDisplayName: input.ctx.name } : {}),
  };
  if (input.onboarding) {
    try {
      const state = await input.onboarding.getOnboardingState(
        {
          orgId: input.orgId,
          actorUserId: input.ctx.userId,
          roles: [],
          ...(input.ctx.projectId ? { projectId: input.ctx.projectId } : {}),
          ...(input.ctx.environmentId ? { environmentId: input.ctx.environmentId } : {}),
        },
        {},
      );
      return {
        orgId: input.orgId,
        projectId: state.selectedProjectId,
        environmentId: state.selectedEnvironmentId,
        actorRoles: [],
        onboardingComplete: state.onboardingComplete === true,
      };
    } catch {
      // fall through
    }
  }

  const projects = await input.orgProjectEnv.listProjects(targetCtx, { status: 'ACTIVE' });
  const environments = await input.orgProjectEnv.listEnvironments(targetCtx, { status: 'ACTIVE' });
  const projectId = projects[0]?.id || null;
  const environmentId =
    (projectId ? environments.find((entry) => entry.projectId === projectId)?.id : undefined) ||
    environments[0]?.id ||
    null;
  return {
    orgId: input.orgId,
    projectId,
    environmentId,
    actorRoles: [],
    onboardingComplete: Boolean(projectId && environmentId),
  };
}

async function resolveSelectedScopeLabels(input: {
  ctx: ConsoleAccountContext;
  orgId: string;
  orgProjectEnv: ConsoleOrgProjectEnvService;
  projectId: string | null;
  environmentId: string | null;
}): Promise<{ projectName: string | null; environmentName: string | null }> {
  const targetCtx = {
    orgId: input.orgId,
    actorUserId: input.ctx.userId,
    roles: [],
    ...(input.ctx.email ? { actorEmail: input.ctx.email } : {}),
    ...(input.ctx.name ? { actorDisplayName: input.ctx.name } : {}),
  };
  const [projects, environments] = await Promise.all([
    input.orgProjectEnv.listProjects(targetCtx, { status: 'ACTIVE' }).catch(() => []),
    input.orgProjectEnv.listEnvironments(targetCtx, { status: 'ACTIVE' }).catch(() => []),
  ]);
  const project =
    input.projectId && projects.length
      ? projects.find((entry) => entry.id === input.projectId) || null
      : null;
  const environment =
    input.environmentId && environments.length
      ? environments.find((entry) => entry.id === input.environmentId) || null
      : null;
  return {
    projectName: normalizeString(project?.name) || null,
    environmentName: normalizeString(environment?.name) || null,
  };
}

export interface PostgresConsoleAccountSchemaOptions {
  postgresUrl: string;
  logger: NormalizedLogger;
}

export async function ensureConsoleAccountPostgresSchema(
  options: PostgresConsoleAccountSchemaOptions,
): Promise<void> {
  const pool = await getPostgresPool(options.postgresUrl);
  await pool.query('SELECT pg_advisory_lock($1)', [CONSOLE_ACCOUNT_MIGRATION_LOCK_ID]);
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_user_profiles (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        display_name TEXT,
        primary_email TEXT,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id)
      )
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS console_user_backup_emails (
        namespace TEXT NOT NULL,
        user_id TEXT NOT NULL,
        email TEXT NOT NULL,
        email_normalized TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at_ms BIGINT NOT NULL,
        updated_at_ms BIGINT NOT NULL,
        PRIMARY KEY (namespace, user_id, email_normalized),
        CHECK (status IN ('PENDING', 'VERIFIED'))
      )
    `);
    await pool.query(`
      CREATE INDEX IF NOT EXISTS console_org_created_by_user_idx
      ON console_organizations (namespace, created_by_user_id, updated_at_ms DESC, created_at_ms DESC)
    `);
  } finally {
    try {
      await pool.query('SELECT pg_advisory_unlock($1)', [CONSOLE_ACCOUNT_MIGRATION_LOCK_ID]);
    } catch {
      // no-op
    }
  }
  options.logger.info('[console-account][postgres] Schema ready');
}

export interface PostgresConsoleAccountServiceOptions {
  postgresUrl: string;
  namespace?: string;
  logger?: NormalizedLogger;
  ensureSchema?: boolean;
  now?: () => Date;
  orgProjectEnv: ConsoleOrgProjectEnvService;
  teamRbac: ConsoleTeamRbacService;
  onboarding?: ConsoleOnboardingService | null;
  wallets?: ConsoleWalletService | null;
}

export async function createPostgresConsoleAccountService(
  options: PostgresConsoleAccountServiceOptions,
): Promise<ConsoleAccountService> {
  const postgresUrl = normalizeString(options.postgresUrl);
  if (!postgresUrl) throw new Error('Missing POSTGRES_URL for Postgres console account service');
  const namespace = ensureNamespace(options.namespace);
  const logger = options.logger || console;
  const now = options.now || (() => new Date());
  if (options.ensureSchema !== false) {
    await ensureConsoleAccountPostgresSchema({
      postgresUrl,
      logger: logger as NormalizedLogger,
    });
  }
  const pool = await getPostgresPool(postgresUrl);
  const withTenantTx = <T>(
    orgId: string,
    fn: (q: Queryable) => Promise<T>,
  ): Promise<T> => withConsoleTenantContextTx(pool, { namespace, orgId }, fn);
  async function listActiveMembersForOrg(orgId: string): Promise<ConsoleTeamMember[]> {
    const out = await pool.query(
      `SELECT *
         FROM console_team_members
        WHERE namespace = $1
          AND org_id = $2
          AND status = 'ACTIVE'
        ORDER BY updated_at_ms DESC, created_at_ms DESC`,
      [namespace, orgId],
    );
    return out.rows.map((row) => parseMemberRow(row as PgRow));
  }

  async function listNonRemovedMembersForOrg(orgId: string): Promise<ConsoleTeamMember[]> {
    const out = await pool.query(
      `SELECT *
         FROM console_team_members
        WHERE namespace = $1
          AND org_id = $2
          AND status <> 'REMOVED'
        ORDER BY updated_at_ms DESC, created_at_ms DESC`,
      [namespace, orgId],
    );
    return out.rows.map((row) => parseMemberRow(row as PgRow));
  }

  async function listOrgScopedConsoleTables(q: Queryable): Promise<string[]> {
    const out = await q.query(
      `SELECT table_name
         FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND column_name = 'org_id'
          AND table_name LIKE 'console\\_%' ESCAPE '\\'
          AND table_name IN (
            SELECT table_name
              FROM information_schema.columns
             WHERE table_schema = current_schema()
               AND column_name = 'namespace'
          )
        GROUP BY table_name
        ORDER BY table_name ASC`,
      [],
    );
    return out.rows
      .map((row) => normalizeString((row as PgRow).table_name))
      .filter(
        (tableName) =>
          Boolean(tableName) &&
          tableName !== 'console_organizations' &&
          /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(tableName),
      );
  }

  async function assertOrganizationDeletionAllowed(
    ctx: ConsoleAccountContext,
    orgId: string,
  ): Promise<void> {
    const current = await requireOrganizationAccess(ctx, orgId);
    if (!current.actorIsOwner) {
      throw accountError('forbidden', 403, 'Only the current owner can delete an organization');
    }
    if (orgId === ctx.orgId) {
      throw accountError(
        'organization_current_context_active',
        409,
        'Switch to a different organization before deleting this one',
      );
    }
    const otherMembers = (await listNonRemovedMembersForOrg(orgId)).filter(
      (member) => normalizeString(member.userId) !== ctx.userId,
    );
    if (otherMembers.length > 0) {
      throw accountError(
        'organization_delete_has_other_members',
        409,
        'Remove all other organization members before deleting this organization',
      );
    }
    if (!options.wallets) {
      throw accountError(
        'wallets_not_configured',
        503,
        'Wallet service is required to evaluate organization deletion',
      );
    }
    const walletRow = await queryOne(
      pool,
      `SELECT id
         FROM console_wallet_index
        WHERE namespace = $1
          AND org_id = $2
        LIMIT 1`,
      [namespace, orgId],
    );
    if (walletRow) {
      throw accountError(
        'organization_delete_has_wallets',
        409,
        'Organizations cannot be deleted after wallets have been created',
      );
    }
  }

  async function loadOrganizationSummary(
    ctx: ConsoleAccountContext,
    organization: {
      id: string;
      name: string;
      slug: string;
      status: string;
      createdAt: string;
      updatedAt: string;
    },
  ): Promise<ConsoleAccountOrganization> {
    const members = await listActiveMembersForOrg(organization.id);
    const actorMember =
      members.find((entry) => normalizeString(entry.userId) === normalizeString(ctx.userId)) ||
      null;
    const onboardingState = await resolveOnboardingState({
      ctx,
      orgId: organization.id,
      onboarding: options.onboarding || null,
      orgProjectEnv: options.orgProjectEnv,
    });
    const selectedScope = await resolveSelectedScopeLabels({
      ctx,
      orgId: organization.id,
      orgProjectEnv: options.orgProjectEnv,
      projectId: onboardingState.projectId,
      environmentId: onboardingState.environmentId,
    });
    return {
      id: organization.id,
      name: organization.name,
      slug: organization.slug,
      status: organization.status,
      createdAt: organization.createdAt,
      updatedAt: organization.updatedAt,
      isCurrentOrg: organization.id === ctx.orgId,
      actorRoles: actorMember ? actorMember.roles.map((entry) => entry.role) : [],
      actorIsOwner: actorMember ? actorMember.roles.some((entry) => entry.role === 'owner') : false,
      actorIsAdmin: actorMember ? hasAdminEligibility(actorMember) : false,
      onboardingComplete: onboardingState.onboardingComplete,
      selectedProjectId: onboardingState.projectId,
      selectedProjectName: selectedScope.projectName,
      selectedEnvironmentId: onboardingState.environmentId,
      selectedEnvironmentName: selectedScope.environmentName,
      adminCandidates: members.filter(hasAdminEligibility).map(toAdminCandidate),
    };
  }

  async function getOrganizationById(orgId: string): Promise<{
    id: string;
    name: string;
    slug: string;
    status: string;
    createdAt: string;
    updatedAt: string;
  } | null> {
    const row = await queryOne(
      pool,
      `SELECT id, name, slug, status, created_at_ms, updated_at_ms
         FROM console_organizations
        WHERE namespace = $1
          AND id = $2`,
      [namespace, orgId],
    );
    if (!row) return null;
    return {
      id: normalizeString(row.id),
      name: normalizeString(row.name) || normalizeString(row.id),
      slug: normalizeString(row.slug),
      status: normalizeString(row.status) || 'ACTIVE',
      createdAt: toIso(toNumber(row.created_at_ms)) || new Date(0).toISOString(),
      updatedAt: toIso(toNumber(row.updated_at_ms)) || new Date(0).toISOString(),
    };
  }

  async function requireOrganizationAccess(
    ctx: ConsoleAccountContext,
    orgId: string,
  ): Promise<ConsoleAccountOrganization> {
    const organization = await getOrganizationById(orgId);
    if (!organization) {
      throw accountError('organization_not_found', 404, `Organization ${orgId} was not found`);
    }
    return loadOrganizationSummary(ctx, organization);
  }

  async function getProfile(ctx: ConsoleAccountContext): Promise<ConsoleAccountProfile> {
    const profileRow = await queryOne(
      pool,
      `SELECT *
         FROM console_user_profiles
        WHERE namespace = $1
          AND user_id = $2`,
      [namespace, ctx.userId],
    );
    const emails = await pool.query(
      `SELECT *
         FROM console_user_backup_emails
        WHERE namespace = $1
          AND user_id = $2
        ORDER BY email_normalized ASC`,
      [namespace, ctx.userId],
    );
    const fallbackCreatedAt = now().toISOString();
    const createdAt = toIso(toNumber(profileRow?.created_at_ms)) || fallbackCreatedAt;
    const updatedAt = toIso(toNumber(profileRow?.updated_at_ms)) || createdAt;
    const backupEmails: ConsoleAccountBackupEmail[] = emails.rows.map((row) => ({
      email: normalizeLower((row as PgRow).email),
      status: normalizeString((row as PgRow).status) as ConsoleAccountBackupEmail['status'],
      createdAt: toIso(toNumber((row as PgRow).created_at_ms)) || createdAt,
      updatedAt: toIso(toNumber((row as PgRow).updated_at_ms)) || updatedAt,
    }));
    return {
      userId: ctx.userId,
      displayName:
        normalizeString(profileRow?.display_name) || normalizeString(ctx.name) || ctx.userId,
      primaryEmail: normalizeLower(profileRow?.primary_email) || normalizeLower(ctx.email),
      canEditPrimaryEmail: canEditPrimaryEmail(ctx),
      backupEmails,
      createdAt,
      updatedAt,
    };
  }

  return {
    getProfile,

    async updateProfile(ctx, request): Promise<ConsoleAccountProfile> {
      const nowMsValue = now().getTime();
      if (request.primaryEmail && !canEditPrimaryEmail(ctx)) {
        throw accountError(
          'primary_email_read_only',
          403,
          'Primary email is managed by your identity provider',
        );
      }
      if (request.displayName || request.primaryEmail) {
        await pool.query(
          `INSERT INTO console_user_profiles
            (namespace, user_id, display_name, primary_email, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, $5, $5)
           ON CONFLICT (namespace, user_id)
           DO UPDATE SET
             display_name = COALESCE(EXCLUDED.display_name, console_user_profiles.display_name),
             primary_email = COALESCE(EXCLUDED.primary_email, console_user_profiles.primary_email),
             updated_at_ms = EXCLUDED.updated_at_ms`,
          [
            namespace,
            ctx.userId,
            request.displayName || null,
            request.primaryEmail || null,
            nowMsValue,
          ],
        );
      }
      if (request.addBackupEmail) {
        const email = normalizeLower(request.addBackupEmail);
        await pool.query(
          `INSERT INTO console_user_backup_emails
            (namespace, user_id, email, email_normalized, status, created_at_ms, updated_at_ms)
           VALUES
            ($1, $2, $3, $4, 'PENDING', $5, $5)
           ON CONFLICT (namespace, user_id, email_normalized)
           DO UPDATE SET
             email = EXCLUDED.email,
             updated_at_ms = EXCLUDED.updated_at_ms`,
          [namespace, ctx.userId, email, email, nowMsValue],
        );
      }
      if (request.removeBackupEmail) {
        await pool.query(
          `DELETE FROM console_user_backup_emails
            WHERE namespace = $1
              AND user_id = $2
              AND email_normalized = $3`,
          [namespace, ctx.userId, normalizeLower(request.removeBackupEmail)],
        );
      }
      return getProfile(ctx);
    },

    async listOrganizations(ctx): Promise<ConsoleAccountOrganization[]> {
      const rows = await pool.query(
        `SELECT id, name, slug, status, created_at_ms, updated_at_ms
           FROM console_organizations
          WHERE namespace = $1
            AND created_by_user_id = $2
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
        [namespace, ctx.userId],
      );
      const organizations = rows.rows.map((row) => ({
        id: normalizeString((row as PgRow).id),
        name: normalizeString((row as PgRow).name) || normalizeString((row as PgRow).id),
        slug: normalizeString((row as PgRow).slug),
        status: normalizeString((row as PgRow).status) || 'ACTIVE',
        createdAt: toIso(toNumber((row as PgRow).created_at_ms)) || new Date(0).toISOString(),
        updatedAt: toIso(toNumber((row as PgRow).updated_at_ms)) || new Date(0).toISOString(),
      }));
      if (!organizations.some((entry) => entry.id === ctx.orgId)) {
        const currentOrg = await getOrganizationById(ctx.orgId);
        if (currentOrg && (ctx.roles || []).some((role) => role === 'owner' || role === 'admin')) {
          organizations.unshift(currentOrg);
        }
      }
      const out: ConsoleAccountOrganization[] = [];
      for (const organization of organizations) {
        out.push(await loadOrganizationSummary(ctx, organization));
      }
      return out.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    },

    async createOrganization(ctx, request): Promise<ConsoleAccountOrganization> {
      const orgId = normalizeString(request.id) || generateConsoleOrganizationId();
      const existing = await getOrganizationById(orgId);
      if (existing) {
        throw accountError(
          'organization_already_exists',
          409,
          `Organization ${orgId} already exists`,
        );
      }
      const targetCtx = {
        orgId,
        actorUserId: ctx.userId,
        roles: [],
        ...(ctx.email ? { actorEmail: ctx.email } : {}),
        ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
      };
      if (options.onboarding && !request.id) {
        await options.onboarding.createOnboardingOrganization(
          {
            ...targetCtx,
            projectId: undefined,
            environmentId: undefined,
          },
          {
            org: {
              name: request.name,
              ...(request.slug ? { slug: request.slug } : {}),
            },
          },
        );
      } else {
        await options.orgProjectEnv.upsertOrganization(targetCtx, {
          name: request.name,
          ...(request.slug ? { slug: request.slug } : {}),
        });
        await options.teamRbac.bootstrapOwner(targetCtx);
      }
      const created = await getOrganizationById(orgId);
      if (!created) {
        throw accountError('internal', 500, 'Failed to read created organization');
      }
      return loadOrganizationSummary(ctx, created);
    },

    async updateOrganization(ctx, orgId, request): Promise<ConsoleAccountOrganization> {
      const current = await requireOrganizationAccess(ctx, orgId);
      if (!current.actorIsAdmin) {
        throw accountError(
          'forbidden',
          403,
          'Only owner or admin can update organization settings',
        );
      }
      const targetCtx = {
        orgId,
        actorUserId: ctx.userId,
        roles: [],
        ...(ctx.email ? { actorEmail: ctx.email } : {}),
        ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
      };
      await options.orgProjectEnv.upsertOrganization(targetCtx, request);
      const updated = await getOrganizationById(orgId);
      if (!updated) {
        throw accountError('organization_not_found', 404, `Organization ${orgId} was not found`);
      }
      return loadOrganizationSummary(ctx, updated);
    },

    async deleteOrganization(ctx, orgId): Promise<DeleteConsoleAccountOrganizationResult> {
      await assertOrganizationDeletionAllowed(ctx, orgId);
      const deleted = await withTenantTx(orgId, async (q) => {
        const tables = await listOrgScopedConsoleTables(q);
        for (const tableName of tables) {
          await q.query(`DELETE FROM "${tableName}" WHERE namespace = $1 AND org_id = $2`, [
            namespace,
            orgId,
          ]);
        }
        const row = await queryOne(
          q,
          `DELETE FROM console_organizations
            WHERE namespace = $1
              AND id = $2
          RETURNING id`,
          [namespace, orgId],
        );
        return row;
      });
      if (!deleted) {
        throw accountError('organization_not_found', 404, `Organization ${orgId} was not found`);
      }
      return { orgId };
    },

    async transferOrganizationOwner(
      ctx,
      orgId,
      request,
    ): Promise<TransferConsoleAccountOrganizationOwnerResult> {
      const current = await requireOrganizationAccess(ctx, orgId);
      if (!current.actorIsOwner) {
        throw accountError(
          'forbidden',
          403,
          'Only the current owner can transfer organization ownership',
        );
      }
      const targetCandidate =
        (request.targetMemberId
          ? current.adminCandidates.find((entry) => entry.memberId === request.targetMemberId)
          : undefined) ||
        (request.targetUserId
          ? current.adminCandidates.find((entry) => entry.userId === request.targetUserId)
          : undefined) ||
        null;
      if (!targetCandidate) {
        throw accountError('member_not_found', 404, 'Transfer owner target was not found');
      }
      await options.teamRbac.transferOwner(
        {
          orgId,
          actorUserId: ctx.userId,
          roles: [],
          ...(ctx.email ? { actorEmail: ctx.email } : {}),
          ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
        },
        targetCandidate.memberId,
      );
      const updated = await requireOrganizationAccess(ctx, orgId);
      const nextOwner =
        updated.adminCandidates.find((entry) => entry.memberId === targetCandidate.memberId) ||
        targetCandidate;
      const previousOwner = updated.adminCandidates.find(
        (entry) => entry.userId === ctx.userId,
      ) || {
        memberId: '',
        userId: ctx.userId,
        email: normalizeLower(ctx.email),
        displayName: normalizeString(ctx.name) || ctx.userId,
        isOwner: false,
        roles: [],
      };
      return {
        organization: updated,
        previousOwner,
        nextOwner,
      };
    },

    async switchOrganizationContext(
      ctx,
      orgId: string,
    ): Promise<SwitchConsoleAccountOrganizationContextResult> {
      const current = await requireOrganizationAccess(ctx, orgId);
      if (!current.actorRoles.length) {
        throw accountError(
          'forbidden',
          403,
          'You are not an active member of the selected organization',
        );
      }
      return resolveOnboardingState({
        ctx,
        orgId,
        onboarding: options.onboarding || null,
        orgProjectEnv: options.orgProjectEnv,
      }).then((result) => ({
        ...result,
        actorRoles: [...current.actorRoles],
      }));
    },
  };
}
