import { ConsoleAccountError } from './errors';
import type {
  DeleteConsoleAccountOrganizationResult,
  ConsoleAccountOrganization,
  ConsoleAccountOrganizationAdminCandidate,
  ConsoleAccountProfile,
  CreateConsoleAccountOrganizationRequest,
  PatchConsoleAccountProfileRequest,
  SwitchConsoleAccountOrganizationContextResult,
  TransferConsoleAccountOrganizationOwnerResult,
  UpdateConsoleAccountOrganizationRequest,
} from './types';
import type { ConsoleOnboardingService } from '../onboarding';
import type { ConsoleOrgProjectEnvService, ConsoleOrganization } from '../orgProjectEnv';
import type { ConsoleTeamMember, ConsoleTeamRbacService } from '../teamRbac';
import type { ConsoleWalletService } from '../wallets';

export interface ConsoleAccountContext {
  userId: string;
  orgId: string;
  roles: string[];
  email?: string;
  name?: string;
  provider?: string;
  projectId?: string;
  environmentId?: string;
}

export interface ConsoleAccountService {
  getProfile(ctx: ConsoleAccountContext): Promise<ConsoleAccountProfile>;
  updateProfile(
    ctx: ConsoleAccountContext,
    request: PatchConsoleAccountProfileRequest,
  ): Promise<ConsoleAccountProfile>;
  listOrganizations(ctx: ConsoleAccountContext): Promise<ConsoleAccountOrganization[]>;
  createOrganization(
    ctx: ConsoleAccountContext,
    request: CreateConsoleAccountOrganizationRequest,
  ): Promise<ConsoleAccountOrganization>;
  updateOrganization(
    ctx: ConsoleAccountContext,
    orgId: string,
    request: UpdateConsoleAccountOrganizationRequest,
  ): Promise<ConsoleAccountOrganization>;
  deleteOrganization(
    ctx: ConsoleAccountContext,
    orgId: string,
  ): Promise<DeleteConsoleAccountOrganizationResult>;
  transferOrganizationOwner(
    ctx: ConsoleAccountContext,
    orgId: string,
    request: { targetMemberId?: string; targetUserId?: string },
  ): Promise<TransferConsoleAccountOrganizationOwnerResult>;
  switchOrganizationContext(
    ctx: ConsoleAccountContext,
    orgId: string,
  ): Promise<SwitchConsoleAccountOrganizationContextResult>;
}

export interface InMemoryConsoleAccountServiceOptions {
  orgProjectEnv: ConsoleOrgProjectEnvService;
  teamRbac: ConsoleTeamRbacService;
  onboarding?: ConsoleOnboardingService | null;
  wallets?: ConsoleWalletService | null;
  now?: () => Date;
}

interface ProfileRecord {
  displayName?: string;
  primaryEmail?: string;
  createdAt: string;
  updatedAt: string;
}

interface BackupEmailRecord {
  email: string;
  status: 'PENDING' | 'VERIFIED';
  createdAt: string;
  updatedAt: string;
}

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function normalizeLower(value: unknown): string {
  return normalizeString(value).toLowerCase();
}

function toIso(date: Date): string {
  return date.toISOString();
}

function makeOrgId(now: Date): string {
  return `org_${now.getTime().toString(36)}_${Math.random().toString(36).slice(2, 7)}`;
}

function isAdminEligibleMember(member: ConsoleTeamMember): boolean {
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

function createAccountContextError(
  code: string,
  status: number,
  message: string,
): ConsoleAccountError {
  return new ConsoleAccountError(code, status, message);
}

function canEditPrimaryEmail(ctx: ConsoleAccountContext): boolean {
  return normalizeLower(ctx.provider) !== 'oidc';
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
      // fall through to org/project/env derivation
    }
  }

  const projects = await input.orgProjectEnv.listProjects(targetCtx, { status: 'ACTIVE' });
  const environments = await input.orgProjectEnv.listEnvironments(targetCtx, { status: 'ACTIVE' });
  const selectedProjectId = projects[0]?.id || null;
  const selectedEnvironmentId =
    (selectedProjectId
      ? environments.find((entry) => entry.projectId === selectedProjectId)?.id
      : undefined) ||
    environments[0]?.id ||
    null;
  return {
    orgId: input.orgId,
    projectId: selectedProjectId,
    environmentId: selectedEnvironmentId,
    actorRoles: [],
    onboardingComplete: Boolean(selectedProjectId && selectedEnvironmentId),
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

export function createInMemoryConsoleAccountService(
  options: InMemoryConsoleAccountServiceOptions,
): ConsoleAccountService {
  const now = options.now || (() => new Date());
  const profiles = new Map<string, ProfileRecord>();
  const backupEmails = new Map<string, Map<string, BackupEmailRecord>>();
  const createdOrgIdsByUser = new Map<string, Set<string>>();

  function requireCreatedOrgSet(userId: string): Set<string> {
    let set = createdOrgIdsByUser.get(userId);
    if (!set) {
      set = new Set<string>();
      createdOrgIdsByUser.set(userId, set);
    }
    return set;
  }

  function getProfileRecord(userId: string): ProfileRecord | null {
    return profiles.get(userId) || null;
  }

  function requireBackupStore(userId: string): Map<string, BackupEmailRecord> {
    let store = backupEmails.get(userId);
    if (!store) {
      store = new Map<string, BackupEmailRecord>();
      backupEmails.set(userId, store);
    }
    return store;
  }

  async function buildProfile(ctx: ConsoleAccountContext): Promise<ConsoleAccountProfile> {
    const currentNowIso = toIso(now());
    const profile = getProfileRecord(ctx.userId);
    const backupStore = backupEmails.get(ctx.userId) || new Map<string, BackupEmailRecord>();
    return {
      userId: ctx.userId,
      displayName: normalizeString(profile?.displayName) || normalizeString(ctx.name) || ctx.userId,
      primaryEmail: normalizeLower(profile?.primaryEmail) || normalizeLower(ctx.email),
      canEditPrimaryEmail: canEditPrimaryEmail(ctx),
      backupEmails: Array.from(backupStore.values())
        .sort((a, b) => a.email.localeCompare(b.email))
        .map((entry) => ({
          email: entry.email,
          status: entry.status,
          createdAt: entry.createdAt,
          updatedAt: entry.updatedAt,
        })),
      createdAt: profile?.createdAt || currentNowIso,
      updatedAt: profile?.updatedAt || currentNowIso,
    };
  }

  async function buildOrganizationSummary(
    ctx: ConsoleAccountContext,
    organization: ConsoleOrganization,
  ): Promise<ConsoleAccountOrganization> {
    const teamCtx = {
      orgId: organization.id,
      actorUserId: ctx.userId,
      roles: [],
      ...(ctx.email ? { actorEmail: ctx.email } : {}),
      ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
    };
    const members = await options.teamRbac
      .listMembers(teamCtx, { status: 'ACTIVE' })
      .catch(() => []);
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
      actorIsAdmin: actorMember ? isAdminEligibleMember(actorMember) : false,
      onboardingComplete: onboardingState.onboardingComplete,
      selectedProjectId: onboardingState.projectId,
      selectedProjectName: selectedScope.projectName,
      selectedEnvironmentId: onboardingState.environmentId,
      selectedEnvironmentName: selectedScope.environmentName,
      adminCandidates: members.filter(isAdminEligibleMember).map(toAdminCandidate),
    };
  }

  async function requireOrganizationAccess(
    ctx: ConsoleAccountContext,
    orgId: string,
  ): Promise<ConsoleAccountOrganization> {
    const orgCtx = {
      orgId,
      actorUserId: ctx.userId,
      roles: [],
      ...(ctx.email ? { actorEmail: ctx.email } : {}),
      ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
    };
    const organization = await options.orgProjectEnv.getOrganization(orgCtx).catch(() => null);
    if (!organization) {
      throw createAccountContextError(
        'organization_not_found',
        404,
        `Organization ${orgId} was not found`,
      );
    }
    return buildOrganizationSummary(ctx, organization);
  }

  async function assertOrganizationDeletionAllowed(
    ctx: ConsoleAccountContext,
    orgId: string,
  ): Promise<void> {
    const current = await requireOrganizationAccess(ctx, orgId);
    if (!current.actorIsOwner) {
      throw createAccountContextError(
        'forbidden',
        403,
        'Only the current owner can delete an organization',
      );
    }
    if (orgId === ctx.orgId) {
      throw createAccountContextError(
        'organization_current_context_active',
        409,
        'Switch to a different organization before deleting this one',
      );
    }
    const teamCtx = {
      orgId,
      actorUserId: ctx.userId,
      roles: [],
      ...(ctx.email ? { actorEmail: ctx.email } : {}),
      ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
    };
    const members = await options.teamRbac.listMembers(teamCtx);
    const otherMembers = members.filter(
      (member) => member.status !== 'REMOVED' && normalizeString(member.userId) !== ctx.userId,
    );
    if (otherMembers.length > 0) {
      throw createAccountContextError(
        'organization_delete_has_other_members',
        409,
        'Remove all other organization members before deleting this organization',
      );
    }
    if (!options.wallets) {
      throw createAccountContextError(
        'wallets_not_configured',
        503,
        'Wallet service is required to evaluate organization deletion',
      );
    }
    const walletPage = await options.wallets.listWallets(
      {
        orgId,
        actorUserId: ctx.userId,
        roles: [],
      },
      { limit: 1 },
    );
    if (walletPage.items.length > 0) {
      throw createAccountContextError(
        'organization_delete_has_wallets',
        409,
        'Organizations cannot be deleted after wallets have been created',
      );
    }
  }

  return {
    async getProfile(ctx): Promise<ConsoleAccountProfile> {
      return buildProfile(ctx);
    },

    async updateProfile(ctx, request): Promise<ConsoleAccountProfile> {
      const currentNowIso = toIso(now());
      const currentProfile = getProfileRecord(ctx.userId);
      if (request.primaryEmail && !canEditPrimaryEmail(ctx)) {
        throw createAccountContextError(
          'primary_email_read_only',
          403,
          'Primary email is managed by your identity provider',
        );
      }
      if (request.displayName || request.primaryEmail) {
        profiles.set(ctx.userId, {
          displayName: normalizeString(request.displayName) || currentProfile?.displayName,
          primaryEmail: normalizeLower(request.primaryEmail) || currentProfile?.primaryEmail,
          createdAt: currentProfile?.createdAt || currentNowIso,
          updatedAt: currentNowIso,
        });
      }
      const backupStore = requireBackupStore(ctx.userId);
      if (request.addBackupEmail) {
        const email = normalizeLower(request.addBackupEmail);
        const existing = backupStore.get(email);
        backupStore.set(email, {
          email,
          status: existing?.status || 'PENDING',
          createdAt: existing?.createdAt || currentNowIso,
          updatedAt: currentNowIso,
        });
      }
      if (request.removeBackupEmail) {
        backupStore.delete(normalizeLower(request.removeBackupEmail));
      }
      return buildProfile(ctx);
    },

    async listOrganizations(ctx): Promise<ConsoleAccountOrganization[]> {
      const orgIds = new Set<string>(createdOrgIdsByUser.get(ctx.userId) || []);
      if ((ctx.roles || []).some((role) => role === 'owner' || role === 'admin')) {
        orgIds.add(ctx.orgId);
      }
      const rows: ConsoleAccountOrganization[] = [];
      for (const orgId of orgIds) {
        const summary = await requireOrganizationAccess(ctx, orgId).catch(() => null);
        if (summary) rows.push(summary);
      }
      return rows.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    },

    async createOrganization(ctx, request): Promise<ConsoleAccountOrganization> {
      const targetOrgId = normalizeString(request.id) || makeOrgId(now());
      const targetCtx = {
        orgId: targetOrgId,
        actorUserId: ctx.userId,
        roles: [],
        ...(ctx.email ? { actorEmail: ctx.email } : {}),
        ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
      };
      const existing = await options.orgProjectEnv.getOrganization(targetCtx).catch(() => null);
      if (existing) {
        throw createAccountContextError(
          'organization_already_exists',
          409,
          `Organization ${targetOrgId} already exists`,
        );
      }
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
      requireCreatedOrgSet(ctx.userId).add(targetOrgId);
      return requireOrganizationAccess(ctx, targetOrgId);
    },

    async updateOrganization(ctx, orgId, request): Promise<ConsoleAccountOrganization> {
      const current = await requireOrganizationAccess(ctx, orgId);
      if (!current.actorIsAdmin) {
        throw createAccountContextError(
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
      return requireOrganizationAccess(ctx, orgId);
    },

    async deleteOrganization(ctx, orgId): Promise<DeleteConsoleAccountOrganizationResult> {
      await assertOrganizationDeletionAllowed(ctx, orgId);
      const teamRbac = options.teamRbac as ConsoleTeamRbacService & {
        purgeOrganization?: (ctx: {
          orgId: string;
          actorUserId: string;
          roles: string[];
          actorEmail?: string;
          actorDisplayName?: string;
        }) => Promise<void>;
      };
      const orgProjectEnv = options.orgProjectEnv as ConsoleOrgProjectEnvService & {
        deleteOrganization?: (ctx: {
          orgId: string;
          actorUserId: string;
          roles: string[];
        }) => Promise<{ deleted: boolean }>;
      };
      if (!teamRbac.purgeOrganization || !orgProjectEnv.deleteOrganization) {
        throw createAccountContextError(
          'internal',
          500,
          'Organization deletion is not supported by the configured storage backend',
        );
      }
      const targetCtx = {
        orgId,
        actorUserId: ctx.userId,
        roles: [],
        ...(ctx.email ? { actorEmail: ctx.email } : {}),
        ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
      };
      await teamRbac.purgeOrganization(targetCtx);
      const deleted = await orgProjectEnv.deleteOrganization(targetCtx);
      if (!deleted.deleted) {
        throw createAccountContextError(
          'organization_not_found',
          404,
          `Organization ${orgId} was not found`,
        );
      }
      for (const orgIds of createdOrgIdsByUser.values()) {
        orgIds.delete(orgId);
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
        throw createAccountContextError(
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
        throw createAccountContextError(
          'member_not_found',
          404,
          'Transfer owner target was not found',
        );
      }
      const teamCtx = {
        orgId,
        actorUserId: ctx.userId,
        roles: [],
        ...(ctx.email ? { actorEmail: ctx.email } : {}),
        ...(ctx.name ? { actorDisplayName: ctx.name } : {}),
      };
      const transfer = await options.teamRbac.transferOwner(teamCtx, targetCandidate.memberId);
      const updated = await requireOrganizationAccess(ctx, orgId);
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
      const current = await requireOrganizationAccess(ctx, orgId);
      if (!current.actorRoles.length) {
        throw createAccountContextError(
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
