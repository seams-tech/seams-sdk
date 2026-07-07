import { generateConsoleOrganizationId } from '../../../../console-shared-ts/src/organizationIdentity';
import { d1Number as toNumber, formatD1ExecStatement, queryD1All, queryD1One, type D1Row } from '../../storage/d1Sql';
import type { D1DatabaseLike } from '../../storage/tenantRoute';
import type { ConsoleOnboardingService } from '../onboarding';
import type { ConsoleOrgProjectEnvService } from '../orgProjectEnv';
import type { ConsoleTeamMember, ConsoleTeamRbacService } from '../teamRbac';
import type { ConsoleWalletService } from '../wallets';
import { ConsoleAccountError } from './errors';
import type { ConsoleAccountContext, ConsoleAccountService } from './service';
import type {
  ConsoleAccountBackupEmail,
  ConsoleAccountOrganization,
  ConsoleAccountOrganizationAdminCandidate,
  ConsoleAccountProfile,
  DeleteConsoleAccountOrganizationResult,
  SwitchConsoleAccountOrganizationContextResult,
  TransferConsoleAccountOrganizationOwnerResult,
} from './types';

export const CONSOLE_ACCOUNT_D1_RUNTIME = Symbol('consoleAccountD1Runtime');

export interface ConsoleAccountD1Runtime {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
}

export type ConsoleAccountD1Service = ConsoleAccountService & {
  [CONSOLE_ACCOUNT_D1_RUNTIME]: ConsoleAccountD1Runtime;
};

export interface D1ConsoleAccountSchemaOptions {
  database: D1DatabaseLike;
}

export interface D1ConsoleAccountServiceOptions {
  database: D1DatabaseLike;
  namespace?: string;
  ensureSchema?: boolean;
  now?: () => Date;
  orgProjectEnv: ConsoleOrgProjectEnvService;
  teamRbac: ConsoleTeamRbacService;
  onboarding?: ConsoleOnboardingService | null;
  wallets?: ConsoleWalletService | null;
}

interface D1ConsoleAccountServiceState {
  database: D1DatabaseLike;
  namespace: string;
  now: () => Date;
  orgProjectEnv: ConsoleOrgProjectEnvService;
  teamRbac: ConsoleTeamRbacService;
  onboarding: ConsoleOnboardingService | null;
  wallets: ConsoleWalletService | null;
}

interface AccountOrganizationRow {
  id: string;
  name: string;
  slug: string;
  status: string;
  createdAt: string;
  updatedAt: string;
}

export const CONSOLE_ACCOUNT_D1_SCHEMA_SQL = Object.freeze([
  `
    CREATE TABLE IF NOT EXISTS user_profiles (
      namespace TEXT NOT NULL,
      user_id TEXT NOT NULL,
      display_name TEXT,
      primary_email TEXT,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, user_id)
    )
  `,
  `
    CREATE TABLE IF NOT EXISTS user_backup_emails (
      namespace TEXT NOT NULL,
      user_id TEXT NOT NULL,
      email TEXT NOT NULL,
      email_normalized TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (namespace, user_id, email_normalized),
      CHECK (status IN ('PENDING', 'VERIFIED'))
    )
  `,
  `
    CREATE INDEX IF NOT EXISTS org_created_by_user_idx
      ON organizations (namespace, created_by_user_id, updated_at_ms DESC, created_at_ms DESC)
  `,
] as const);

export async function ensureConsoleAccountD1Schema(
  options: D1ConsoleAccountSchemaOptions,
): Promise<void> {
  for (const statement of CONSOLE_ACCOUNT_D1_SCHEMA_SQL) {
    await options.database.exec(formatD1ExecStatement(statement));
  }
}

export function getConsoleAccountD1Runtime(
  service: ConsoleAccountService | null | undefined,
): ConsoleAccountD1Runtime | null {
  if (!service || typeof service !== 'object') return null;
  return (
    (service as Partial<ConsoleAccountD1Service>)[CONSOLE_ACCOUNT_D1_RUNTIME] || null
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

function canEditPrimaryEmail(ctx: ConsoleAccountContext): boolean {
  return normalizeLower(ctx.provider) !== 'oidc';
}

function accountError(code: string, status: number, message: string): ConsoleAccountError {
  return new ConsoleAccountError(code, status, message);
}

function hasAdminEligibility(member: ConsoleTeamMember): boolean {
  return member.roles.some((entry) => entry.role === 'owner' || entry.role === 'admin');
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

function toOrgProjectEnvContext(ctx: ConsoleAccountContext, orgId: string) {
  return {
    orgId,
    actorUserId: ctx.userId,
    roles: [],
    ...(ctx.email ? { actorEmail: ctx.email } : {}),
    ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
  };
}

function toTeamRbacContext(ctx: ConsoleAccountContext, orgId: string) {
  return {
    orgId,
    actorUserId: ctx.userId,
    roles: [],
    ...(ctx.email ? { actorEmail: ctx.email } : {}),
    ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
  };
}

function parseOrganizationRow(row: D1Row): AccountOrganizationRow {
  const createdAtMs = toNumber(row.created_at_ms);
  const updatedAtMs = toNumber(row.updated_at_ms);
  return {
    id: normalizeString(row.id),
    name: normalizeString(row.name) || normalizeString(row.id),
    slug: normalizeString(row.slug),
    status: normalizeString(row.status) || 'ACTIVE',
    createdAt: toIso(createdAtMs),
    updatedAt: toIso(updatedAtMs),
  };
}

function parseBackupEmailRow(row: D1Row, fallback: {
  createdAt: string;
  updatedAt: string;
}): ConsoleAccountBackupEmail {
  return {
    email: normalizeLower(row.email),
    status: normalizeString(row.status) as ConsoleAccountBackupEmail['status'],
    createdAt: toIso(toNumber(row.created_at_ms)) || fallback.createdAt,
    updatedAt: toIso(toNumber(row.updated_at_ms)) || fallback.updatedAt,
  };
}

async function getOrganizationById(
  state: D1ConsoleAccountServiceState,
  orgId: string,
): Promise<AccountOrganizationRow | null> {
  const row = await queryD1One(
    state.database,
    `SELECT id, name, slug, status, created_at_ms, updated_at_ms
       FROM organizations
      WHERE namespace = ?
        AND id = ?
      LIMIT 1`,
    [state.namespace, orgId],
  );
  return row ? parseOrganizationRow(row) : null;
}

async function resolveOnboardingState(input: {
  state: D1ConsoleAccountServiceState;
  ctx: ConsoleAccountContext;
  orgId: string;
}): Promise<SwitchConsoleAccountOrganizationContextResult> {
  if (input.state.onboarding) {
    try {
      const state = await input.state.onboarding.getOnboardingState(
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
      // fall through to org/project/env derivation
    }
  }

  const targetCtx = toOrgProjectEnvContext(input.ctx, input.orgId);
  const projects = await input.state.orgProjectEnv.listProjects(targetCtx, { status: 'ACTIVE' });
  const environments = await input.state.orgProjectEnv.listEnvironments(targetCtx, {
    status: 'ACTIVE',
  });
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
  state: D1ConsoleAccountServiceState;
  ctx: ConsoleAccountContext;
  orgId: string;
  projectId: string | null;
  environmentId: string | null;
}): Promise<{ projectName: string | null; environmentName: string | null }> {
  const targetCtx = toOrgProjectEnvContext(input.ctx, input.orgId);
  const [projects, environments] = await Promise.all([
    input.state.orgProjectEnv.listProjects(targetCtx, { status: 'ACTIVE' }).catch(() => []),
    input.state.orgProjectEnv.listEnvironments(targetCtx, { status: 'ACTIVE' }).catch(() => []),
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

async function loadOrganizationSummary(input: {
  state: D1ConsoleAccountServiceState;
  ctx: ConsoleAccountContext;
  organization: AccountOrganizationRow;
}): Promise<ConsoleAccountOrganization> {
  const teamCtx = toTeamRbacContext(input.ctx, input.organization.id);
  const members = await input.state.teamRbac
    .listMembers(teamCtx, { status: 'ACTIVE' })
    .catch(() => []);
  const actorMember =
    members.find((entry) => normalizeString(entry.userId) === normalizeString(input.ctx.userId)) ||
    null;
  const onboardingState = await resolveOnboardingState({
    state: input.state,
    ctx: input.ctx,
    orgId: input.organization.id,
  });
  const selectedScope = await resolveSelectedScopeLabels({
    state: input.state,
    ctx: input.ctx,
    orgId: input.organization.id,
    projectId: onboardingState.projectId,
    environmentId: onboardingState.environmentId,
  });
  return {
    id: input.organization.id,
    name: input.organization.name,
    slug: input.organization.slug,
    status: input.organization.status,
    createdAt: input.organization.createdAt,
    updatedAt: input.organization.updatedAt,
    isCurrentOrg: input.organization.id === input.ctx.orgId,
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

async function requireOrganizationAccess(input: {
  state: D1ConsoleAccountServiceState;
  ctx: ConsoleAccountContext;
  orgId: string;
}): Promise<ConsoleAccountOrganization> {
  const organization = await getOrganizationById(input.state, input.orgId);
  if (!organization) {
    throw accountError(
      'organization_not_found',
      404,
      `Organization ${input.orgId} was not found`,
    );
  }
  return loadOrganizationSummary({
    state: input.state,
    ctx: input.ctx,
    organization,
  });
}

async function assertOrganizationDeletionAllowed(input: {
  state: D1ConsoleAccountServiceState;
  ctx: ConsoleAccountContext;
  orgId: string;
}): Promise<ConsoleAccountOrganization> {
  const current = await requireOrganizationAccess(input);
  if (!current.actorIsOwner) {
    throw accountError('forbidden', 403, 'Only the current owner can delete an organization');
  }
  if (input.orgId === input.ctx.orgId) {
    throw accountError(
      'organization_current_context_active',
      409,
      'Switch to a different organization before deleting this one',
    );
  }
  const members = await input.state.teamRbac.listMembers(toTeamRbacContext(input.ctx, input.orgId));
  const otherMembers = members.filter(
    (member) =>
      member.status !== 'REMOVED' && normalizeString(member.userId) !== input.ctx.userId,
  );
  if (otherMembers.length > 0) {
    throw accountError(
      'organization_delete_has_other_members',
      409,
      'Remove all other organization members before deleting this organization',
    );
  }
  if (!input.state.wallets) {
    throw accountError(
      'wallets_not_configured',
      503,
      'Wallet service is required to evaluate organization deletion',
    );
  }
  const walletPage = await input.state.wallets.listWallets(
    {
      orgId: input.orgId,
      actorUserId: input.ctx.userId,
      roles: [],
    },
    { limit: 1 },
  );
  if (walletPage.items.length > 0) {
    throw accountError(
      'organization_delete_has_wallets',
      409,
      'Organizations cannot be deleted after wallets have been created',
    );
  }
  return current;
}

async function getProfile(
  state: D1ConsoleAccountServiceState,
  ctx: ConsoleAccountContext,
): Promise<ConsoleAccountProfile> {
  const profileRow = await queryD1One(
    state.database,
    `SELECT *
       FROM user_profiles
      WHERE namespace = ?
        AND user_id = ?
      LIMIT 1`,
    [state.namespace, ctx.userId],
  );
  const emailRows = await queryD1All(
    state.database,
    `SELECT *
       FROM user_backup_emails
      WHERE namespace = ?
        AND user_id = ?
      ORDER BY email_normalized ASC`,
    [state.namespace, ctx.userId],
  );
  const fallbackCreatedAt = state.now().toISOString();
  const createdAt = profileRow
    ? toIso(toNumber(profileRow.created_at_ms))
    : fallbackCreatedAt;
  const updatedAt = profileRow ? toIso(toNumber(profileRow.updated_at_ms)) : createdAt;
  return {
    userId: ctx.userId,
    displayName: normalizeString(profileRow?.display_name) || normalizeString(ctx.name) || ctx.userId,
    primaryEmail: normalizeLower(profileRow?.primary_email) || normalizeLower(ctx.email),
    canEditPrimaryEmail: canEditPrimaryEmail(ctx),
    backupEmails: emailRows.map((row) => parseBackupEmailRow(row, { createdAt, updatedAt })),
    createdAt,
    updatedAt,
  };
}

async function upsertProfile(input: {
  state: D1ConsoleAccountServiceState;
  ctx: ConsoleAccountContext;
  displayName: string | null;
  primaryEmail: string | null;
  nowMsValue: number;
}): Promise<void> {
  await input.state.database
    .prepare(
      `INSERT INTO user_profiles
        (namespace, user_id, display_name, primary_email, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, ?, ?, ?, ?)
       ON CONFLICT(namespace, user_id)
       DO UPDATE SET
         display_name = COALESCE(excluded.display_name, user_profiles.display_name),
         primary_email = COALESCE(excluded.primary_email, user_profiles.primary_email),
         updated_at_ms = excluded.updated_at_ms`,
    )
    .bind(
      input.state.namespace,
      input.ctx.userId,
      input.displayName,
      input.primaryEmail,
      input.nowMsValue,
      input.nowMsValue,
    )
    .run();
}

async function upsertBackupEmail(input: {
  state: D1ConsoleAccountServiceState;
  ctx: ConsoleAccountContext;
  email: string;
  nowMsValue: number;
}): Promise<void> {
  await input.state.database
    .prepare(
      `INSERT INTO user_backup_emails
        (namespace, user_id, email, email_normalized, status, created_at_ms, updated_at_ms)
       VALUES
        (?, ?, ?, ?, 'PENDING', ?, ?)
       ON CONFLICT(namespace, user_id, email_normalized)
       DO UPDATE SET
         email = excluded.email,
         updated_at_ms = excluded.updated_at_ms`,
    )
    .bind(
      input.state.namespace,
      input.ctx.userId,
      input.email,
      input.email,
      input.nowMsValue,
      input.nowMsValue,
    )
    .run();
}

async function removeBackupEmail(input: {
  state: D1ConsoleAccountServiceState;
  ctx: ConsoleAccountContext;
  email: string;
}): Promise<void> {
  await input.state.database
    .prepare(
      `DELETE FROM user_backup_emails
        WHERE namespace = ?
          AND user_id = ?
          AND email_normalized = ?`,
    )
    .bind(input.state.namespace, input.ctx.userId, input.email)
    .run();
}

export async function createD1ConsoleAccountService(
  options: D1ConsoleAccountServiceOptions,
): Promise<ConsoleAccountService> {
  if (options.ensureSchema) {
    await ensureConsoleAccountD1Schema({ database: options.database });
  }
  const state: D1ConsoleAccountServiceState = {
    database: options.database,
    namespace: ensureNamespace(options.namespace),
    now: options.now || defaultNow,
    orgProjectEnv: options.orgProjectEnv,
    teamRbac: options.teamRbac,
    onboarding: options.onboarding || null,
    wallets: options.wallets || null,
  };
  const runtime: ConsoleAccountD1Runtime = {
    database: state.database,
    namespace: state.namespace,
    now: state.now,
  };

  const service: ConsoleAccountD1Service = {
    async getProfile(ctx): Promise<ConsoleAccountProfile> {
      return getProfile(state, ctx);
    },

    async updateProfile(ctx, request): Promise<ConsoleAccountProfile> {
      const nowMsValue = nowMs(state.now());
      if (request.primaryEmail && !canEditPrimaryEmail(ctx)) {
        throw accountError(
          'primary_email_read_only',
          403,
          'Primary email is managed by your identity provider',
        );
      }
      if (request.displayName || request.primaryEmail) {
        await upsertProfile({
          state,
          ctx,
          displayName: request.displayName ? normalizeString(request.displayName) : null,
          primaryEmail: request.primaryEmail ? normalizeLower(request.primaryEmail) : null,
          nowMsValue,
        });
      }
      if (request.addBackupEmail) {
        await upsertBackupEmail({
          state,
          ctx,
          email: normalizeLower(request.addBackupEmail),
          nowMsValue,
        });
      }
      if (request.removeBackupEmail) {
        await removeBackupEmail({
          state,
          ctx,
          email: normalizeLower(request.removeBackupEmail),
        });
      }
      return getProfile(state, ctx);
    },

    async listOrganizations(ctx): Promise<ConsoleAccountOrganization[]> {
      const rows = await queryD1All(
        state.database,
        `SELECT id, name, slug, status, created_at_ms, updated_at_ms
           FROM organizations
          WHERE namespace = ?
            AND created_by_user_id = ?
          ORDER BY updated_at_ms DESC, created_at_ms DESC`,
        [state.namespace, ctx.userId],
      );
      const organizations = rows.map(parseOrganizationRow);
      if (!organizations.some((entry) => entry.id === ctx.orgId)) {
        const currentOrg = await getOrganizationById(state, ctx.orgId);
        if (currentOrg && (ctx.roles || []).some((role) => role === 'owner' || role === 'admin')) {
          organizations.unshift(currentOrg);
        }
      }
      const out: ConsoleAccountOrganization[] = [];
      for (const organization of organizations) {
        out.push(await loadOrganizationSummary({ state, ctx, organization }));
      }
      return out.sort((left, right) => right.updatedAt.localeCompare(left.updatedAt));
    },

    async createOrganization(ctx, request): Promise<ConsoleAccountOrganization> {
      const orgId = normalizeString(request.id) || generateConsoleOrganizationId();
      const existing = await getOrganizationById(state, orgId);
      if (existing) {
        throw accountError(
          'organization_already_exists',
          409,
          `Organization ${orgId} already exists`,
        );
      }
      const targetCtx = toOrgProjectEnvContext(ctx, orgId);
      if (state.onboarding && !request.id) {
        await state.onboarding.createOnboardingOrganization(
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
        await state.orgProjectEnv.upsertOrganization(targetCtx, {
          name: request.name,
          ...(request.slug ? { slug: request.slug } : {}),
        });
        await state.teamRbac.bootstrapOwner(toTeamRbacContext(ctx, orgId));
      }
      const created = await getOrganizationById(state, orgId);
      if (!created) {
        throw accountError('internal', 500, 'Failed to read created organization');
      }
      return loadOrganizationSummary({ state, ctx, organization: created });
    },

    async updateOrganization(ctx, orgId, request): Promise<ConsoleAccountOrganization> {
      const current = await requireOrganizationAccess({ state, ctx, orgId });
      if (!current.actorIsAdmin) {
        throw accountError(
          'forbidden',
          403,
          'Only owner or admin can update organization settings',
        );
      }
      await state.orgProjectEnv.upsertOrganization(toOrgProjectEnvContext(ctx, orgId), request);
      const updated = await getOrganizationById(state, orgId);
      if (!updated) {
        throw accountError('organization_not_found', 404, `Organization ${orgId} was not found`);
      }
      return loadOrganizationSummary({ state, ctx, organization: updated });
    },

    async deleteOrganization(ctx, orgId): Promise<DeleteConsoleAccountOrganizationResult> {
      const current = await assertOrganizationDeletionAllowed({ state, ctx, orgId });
      await state.teamRbac.purgeOrganization(toTeamRbacContext(ctx, orgId));
      const deleted = await state.orgProjectEnv.deleteOrganization(toOrgProjectEnvContext(ctx, orgId));
      if (!deleted.deleted) {
        throw accountError('organization_not_found', 404, `Organization ${orgId} was not found`);
      }
      return {
        orgId,
        organizationName: current.name || orgId,
      };
    },

    async transferOrganizationOwner(
      ctx,
      orgId,
      request,
    ): Promise<TransferConsoleAccountOrganizationOwnerResult> {
      const current = await requireOrganizationAccess({ state, ctx, orgId });
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
      const transfer = await state.teamRbac.transferOwner(
        toTeamRbacContext(ctx, orgId),
        targetCandidate.memberId,
      );
      const updated = await requireOrganizationAccess({ state, ctx, orgId });
      return {
        organization: updated,
        previousOwner: toAdminCandidate(transfer.previousOwner),
        nextOwner: toAdminCandidate(transfer.nextOwner),
      };
    },

    async switchOrganizationContext(
      ctx,
      orgId: string,
    ): Promise<SwitchConsoleAccountOrganizationContextResult> {
      const current = await requireOrganizationAccess({ state, ctx, orgId });
      if (!current.actorRoles.length) {
        throw accountError(
          'forbidden',
          403,
          'You are not an active member of the selected organization',
        );
      }
      const result = await resolveOnboardingState({ state, ctx, orgId });
      return {
        ...result,
        actorRoles: [...current.actorRoles],
      };
    },

    [CONSOLE_ACCOUNT_D1_RUNTIME]: runtime,
  };

  return service;
}
