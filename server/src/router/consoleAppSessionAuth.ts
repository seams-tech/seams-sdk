import type { ConsoleAuditService } from '../console/audit';
import type { ConsoleOrgProjectEnvService } from '../console/orgProjectEnv';
import { type ConsoleTeamRbacService } from '../console/teamRbac';
import {
  CONSOLE_ORG_SCOPED_TEAM_ROLES,
  type ConsoleOrgScopedTeamRole,
  type ConsoleTeamRoleAssignment,
} from '../console/teamRbac/types';
import type { ConsoleAuthAdapter } from './console';
import type { SessionAdapter } from './relay';

type AppSessionVersionValidationResult =
  | { ok: true }
  | { ok: false; code?: string; message?: string };

interface AppSessionVersionValidator {
  validateAppSessionVersion(input: {
    userId: string;
    appSessionVersion: string;
  }): Promise<AppSessionVersionValidationResult>;
}

export interface ConsoleSsoProvisioningOptions {
  bootstrapRoles?: ReadonlyArray<unknown>;
  orgProjectEnv?: ConsoleOrgProjectEnvService | null;
  teamRbac?: ConsoleTeamRbacService | null;
  audit?: ConsoleAuditService | null;
  logger?: { warn(message?: unknown, ...optionalParams: unknown[]): void } | null;
}

export interface AppSessionConsoleAuthAdapterOptions {
  session: SessionAdapter;
  authService: AppSessionVersionValidator;
  defaultOrgId?: string;
  defaultProjectId?: string;
  defaultEnvironmentId?: string;
  fallbackRoles?: ReadonlyArray<unknown>;
  platformAdminEmails?: ReadonlyArray<unknown> | string;
  provisioning?: ConsoleSsoProvisioningOptions | null;
}

const CONSOLE_ORG_ROLE_SET = new Set<string>(CONSOLE_ORG_SCOPED_TEAM_ROLES);

function parseCsvValues(value: unknown): string[] {
  return String(value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeConsolePlatformAdminEmailList(input: unknown): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const values = Array.isArray(input) ? input : parseCsvValues(input);
  for (const raw of values) {
    const email = String(raw || '')
      .trim()
      .toLowerCase();
    if (!email || !email.includes('@')) continue;
    if (seen.has(email)) continue;
    seen.add(email);
    out.push(email);
  }
  return out;
}

function hasConsoleErrorCode(error: unknown, code: string): boolean {
  if (!error || typeof error !== 'object') return false;
  return String((error as { code?: unknown }).code || '').trim() === code;
}

export function normalizeConsoleOrgScopedRoleList(input: unknown): ConsoleOrgScopedTeamRole[] {
  const out: ConsoleOrgScopedTeamRole[] = [];
  const seen = new Set<ConsoleOrgScopedTeamRole>();

  const values = Array.isArray(input) ? input : parseCsvValues(input);
  for (const raw of values) {
    const role = String(raw || '')
      .trim()
      .toLowerCase() as ConsoleOrgScopedTeamRole;
    if (!CONSOLE_ORG_ROLE_SET.has(role)) continue;
    if (seen.has(role)) continue;
    seen.add(role);
    out.push(role);
  }
  return out;
}

export function mergeConsoleOrgScopedRoleLists(
  ...lists: ReadonlyArray<ReadonlyArray<unknown>>
): ConsoleOrgScopedTeamRole[] {
  const out: ConsoleOrgScopedTeamRole[] = [];
  const seen = new Set<ConsoleOrgScopedTeamRole>();
  for (const list of lists) {
    for (const raw of list) {
      const role = String(raw || '')
        .trim()
        .toLowerCase() as ConsoleOrgScopedTeamRole;
      if (!CONSOLE_ORG_ROLE_SET.has(role)) continue;
      if (seen.has(role)) continue;
      seen.add(role);
      out.push(role);
    }
  }
  return out;
}

function extractConsoleOrgScopedRoleClaims(
  assignments: ReadonlyArray<{ role: unknown }>,
): ConsoleOrgScopedTeamRole[] {
  const out: ConsoleOrgScopedTeamRole[] = [];
  const seen = new Set<ConsoleOrgScopedTeamRole>();
  for (const assignment of assignments) {
    const role = String(assignment.role || '')
      .trim()
      .toLowerCase() as ConsoleOrgScopedTeamRole;
    if (!CONSOLE_ORG_ROLE_SET.has(role)) continue;
    if (seen.has(role)) continue;
    seen.add(role);
    out.push(role);
  }
  return out;
}

function toConsoleRoleAssignments(
  roles: ReadonlyArray<ConsoleOrgScopedTeamRole>,
): ConsoleTeamRoleAssignment[] {
  return roles.map((role) => ({
    role,
    scope: 'ORG',
  }));
}

function resolveConsoleSsoEmail(userId: string, claims: Record<string, unknown>): string {
  const claimed = String(claims.email || claims.email_address || '')
    .trim()
    .toLowerCase();
  if (claimed && claimed.includes('@')) return claimed;
  const normalized = String(userId || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._+-]/g, '_');
  return `${normalized || 'user'}@console.local`;
}

function resolveConsoleSsoDisplayName(
  userId: string,
  claims: Record<string, unknown>,
): string | undefined {
  const displayName = String(claims.name || claims.preferred_username || '').trim();
  if (displayName) return displayName;
  const given = String(claims.given_name || '').trim();
  const family = String(claims.family_name || '').trim();
  const full = `${given} ${family}`.trim();
  if (full) return full;
  const fallback = String(userId || '').trim();
  return fallback || undefined;
}

function readConsoleSsoEmailClaim(claims: Record<string, unknown>): string | undefined {
  const claimed = String(claims.email || claims.email_address || '')
    .trim()
    .toLowerCase();
  if (claimed && claimed.includes('@')) return claimed;
  return undefined;
}

function readConsoleSsoDisplayNameClaim(claims: Record<string, unknown>): string | undefined {
  const displayName = String(claims.name || claims.preferred_username || '').trim();
  if (displayName) return displayName;
  const given = String(claims.given_name || '').trim();
  const family = String(claims.family_name || '').trim();
  const full = `${given} ${family}`.trim();
  return full || undefined;
}

function readEnvironmentKeyCandidate(environmentId: string): 'dev' | 'staging' | 'prod' | null {
  const candidate = String(environmentId || '')
    .trim()
    .split(':')
    .pop()
    ?.toLowerCase();
  if (candidate === 'dev' || candidate === 'staging' || candidate === 'prod') {
    return candidate;
  }
  return null;
}

function createConsoleScopeReadContext(input: {
  orgId: string;
  userId: string;
  claims: Record<string, unknown>;
}) {
  return {
    orgId: input.orgId,
    actorUserId: input.userId,
    roles: [],
    ...(readConsoleSsoEmailClaim(input.claims)
      ? { actorEmail: readConsoleSsoEmailClaim(input.claims) }
      : {}),
    ...(readConsoleSsoDisplayNameClaim(input.claims)
      ? { actorDisplayName: readConsoleSsoDisplayNameClaim(input.claims) }
      : {}),
  };
}

async function reconcileConsoleScopeClaims(input: {
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
  userId: string;
  claims: Record<string, unknown>;
  defaultOrgId: string;
  orgId: string;
  projectId: string;
  environmentId: string;
}): Promise<{ orgId: string; projectId: string; environmentId: string }> {
  if (!input.orgProjectEnv) {
    return {
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: input.environmentId,
    };
  }

  try {
    let orgId = String(input.orgId || '').trim();
    if (orgId) {
      try {
        await input.orgProjectEnv.getOrganization(
          createConsoleScopeReadContext({
            orgId,
            userId: input.userId,
            claims: input.claims,
          }),
        );
      } catch (error: unknown) {
        if (!hasConsoleErrorCode(error, 'organization_not_found')) {
          throw error;
        }
        orgId = '';
      }
    }

    if (!orgId) {
      const resolvedOrganization = await input.orgProjectEnv.findOrganizationForScope({
        ...(input.projectId ? { projectId: input.projectId } : {}),
        ...(input.environmentId ? { environmentId: input.environmentId } : {}),
      });
      orgId = String(resolvedOrganization?.id || '').trim();
    }

    if (!orgId) {
      const fallbackOrgId = String(input.defaultOrgId || '').trim();
      if (fallbackOrgId) {
        try {
          await input.orgProjectEnv.getOrganization(
            createConsoleScopeReadContext({
              orgId: fallbackOrgId,
              userId: input.userId,
              claims: input.claims,
            }),
          );
          orgId = fallbackOrgId;
        } catch (error: unknown) {
          if (!hasConsoleErrorCode(error, 'organization_not_found')) {
            throw error;
          }
        }
      }
    }

    if (!orgId) {
      return {
        orgId: input.orgId,
        projectId: input.projectId,
        environmentId: input.environmentId,
      };
    }

    const readCtx = createConsoleScopeReadContext({
      orgId,
      userId: input.userId,
      claims: input.claims,
    });
    const [projects, environments] = await Promise.all([
      input.orgProjectEnv.listProjects(readCtx, { status: 'ACTIVE' }),
      input.orgProjectEnv.listEnvironments(readCtx, { status: 'ACTIVE' }),
    ]);
    if (!projects.length && !environments.length) {
      return {
        orgId,
        projectId: input.projectId,
        environmentId: input.environmentId,
      };
    }

    let projectId = input.projectId;
    let environmentId = input.environmentId;
    let environment =
      environments.find((entry) => entry.id === environmentId) || null;
    const project =
      projectId && projects.find((entry) => entry.id === projectId)
        ? projects.find((entry) => entry.id === projectId) || null
        : null;

    if (environment) {
      projectId = environment.projectId;
      environmentId = environment.id;
    } else {
      const keyCandidate = readEnvironmentKeyCandidate(environmentId);
      environment =
        (projectId && keyCandidate
          ? environments.find(
              (entry) => entry.projectId === projectId && entry.key === keyCandidate,
            ) || null
          : null) ||
        (projectId
          ? environments.find((entry) => entry.projectId === projectId) || null
          : null) ||
        (keyCandidate
          ? environments.find((entry) => entry.key === keyCandidate) || null
          : null) ||
        environments[0] ||
        null;
      if (environment) {
        projectId = environment.projectId;
        environmentId = environment.id;
      }
    }

    if (!projectId || !project) {
      projectId =
        (environment && environment.projectId) ||
        projects[0]?.id ||
        '';
    }

    return {
      orgId,
      projectId,
      environmentId,
    };
  } catch {
    return {
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: input.environmentId,
    };
  }
}

async function resolveDefaultConsoleOrgId(input: {
  defaultOrgId: string;
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
}): Promise<string> {
  const configuredOrgId = String(input.defaultOrgId || '').trim();
  if (configuredOrgId || !input.orgProjectEnv) return configuredOrgId;
  try {
    return String((await input.orgProjectEnv.findDefaultOrganization())?.id || '').trim();
  } catch {
    return '';
  }
}

const consoleSsoProvisioningLocks = new Map<string, Promise<ConsoleOrgScopedTeamRole[]>>();

async function runConsoleSsoProvisioningWithLock(
  key: string,
  task: () => Promise<ConsoleOrgScopedTeamRole[]>,
): Promise<ConsoleOrgScopedTeamRole[]> {
  const existing = consoleSsoProvisioningLocks.get(key);
  if (existing) return existing;
  const inFlight = task().finally(() => {
    if (consoleSsoProvisioningLocks.get(key) === inFlight) {
      consoleSsoProvisioningLocks.delete(key);
    }
  });
  consoleSsoProvisioningLocks.set(key, inFlight);
  return inFlight;
}

async function ensureConsoleSsoProvisioning(input: {
  userId: string;
  orgId: string;
  projectId: string;
  environmentId: string;
  claims: Record<string, unknown>;
  bootstrapRoles: ConsoleOrgScopedTeamRole[];
  orgProjectEnv: ConsoleOrgProjectEnvService | null;
  teamRbac: ConsoleTeamRbacService | null;
  audit: ConsoleAuditService | null;
  logger: { warn(message?: unknown, ...optionalParams: unknown[]): void };
}): Promise<ConsoleOrgScopedTeamRole[]> {
  const teamRbac = input.teamRbac;
  if (!teamRbac) return [];
  if (!String(input.orgId || '').trim()) return [];

  const lockKey = `${input.orgId}:${input.userId}`;
  return runConsoleSsoProvisioningWithLock(lockKey, async () => {
    const actorEmail = resolveConsoleSsoEmail(input.userId, input.claims);
    const actorDisplayName = resolveConsoleSsoDisplayName(input.userId, input.claims);
    const readCtx = {
      orgId: input.orgId,
      actorUserId: input.userId,
      roles: [],
      actorEmail,
      ...(actorDisplayName ? { actorDisplayName } : {}),
      projectId: input.projectId,
      environmentId: input.environmentId,
    };
    const provisionCtx = {
      ...readCtx,
      roles: input.bootstrapRoles,
    };
    const ownerProvisionCtx = {
      ...provisionCtx,
      roles: mergeConsoleOrgScopedRoleLists(['owner', 'admin'], input.bootstrapRoles),
    };

    let organizationCreated = false;
    if (input.orgProjectEnv) {
      let organizationExists = true;
      try {
        await input.orgProjectEnv.getOrganization(readCtx);
      } catch (error: unknown) {
        if (hasConsoleErrorCode(error, 'organization_not_found')) {
          organizationExists = false;
        } else {
          throw error;
        }
      }

      if (!organizationExists) {
        await input.orgProjectEnv.upsertOrganization(provisionCtx, {});
        organizationCreated = true;
      }
    }

    const activeMembers = await teamRbac.listMembers(readCtx, { status: 'ACTIVE' });
    const currentMember = activeMembers.find(
      (entry) => String(entry.userId || '').trim() === input.userId,
    );
    let roles = currentMember ? extractConsoleOrgScopedRoleClaims(currentMember.roles) : [];
    let firstLoginProvisioned = false;

    if (!currentMember && input.bootstrapRoles.length > 0) {
      try {
        const invited = await teamRbac.inviteMember(provisionCtx, {
          userId: input.userId,
          email: actorEmail,
          ...(actorDisplayName ? { displayName: actorDisplayName } : {}),
          roles: toConsoleRoleAssignments(input.bootstrapRoles),
        });
        roles = extractConsoleOrgScopedRoleClaims(invited.roles);
        firstLoginProvisioned = roles.length > 0;
      } catch (error: unknown) {
        if (!hasConsoleErrorCode(error, 'member_already_exists')) throw error;
        const refreshed = await teamRbac.listMembers(readCtx, { status: 'ACTIVE' });
        const matched = refreshed.find(
          (entry) => String(entry.userId || '').trim() === input.userId,
        );
        roles = matched ? extractConsoleOrgScopedRoleClaims(matched.roles) : [];
      }
    } else if (currentMember && roles.length === 0 && input.bootstrapRoles.length > 0) {
      const updated = await teamRbac.updateMemberRoles(ownerProvisionCtx, currentMember.id, {
        roles: toConsoleRoleAssignments(input.bootstrapRoles),
      });
      roles = extractConsoleOrgScopedRoleClaims((updated || currentMember).roles);
      firstLoginProvisioned = roles.length > 0;
    }

    if (firstLoginProvisioned && input.audit) {
      try {
        await input.audit.appendEvent(provisionCtx, {
          category: 'TEAM',
          action: 'member.owner.bootstrap',
          outcome: 'SUCCESS',
          summary: `Provisioned first-login SSO membership for ${input.userId}`,
          metadata: {
            source: 'console_auth_sso',
            organizationCreated,
            userId: input.userId,
            provider: String(input.claims.provider || '').trim() || 'unknown',
            roles,
          },
        });
      } catch (error: unknown) {
        input.logger.warn(
          `[console-auth] failed to append first-login SSO audit event for ${input.userId}: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
    }

    return roles;
  });
}

export function createAppSessionConsoleAuthAdapter(
  options: AppSessionConsoleAuthAdapterOptions,
): ConsoleAuthAdapter {
  const defaultOrgId = String(options.defaultOrgId || '').trim();
  const defaultProjectId = String(options.defaultProjectId || '').trim();
  const defaultEnvironmentId = String(options.defaultEnvironmentId || '').trim();
  const fallbackRoles = normalizeConsoleOrgScopedRoleList(options.fallbackRoles || []);
  const platformAdminEmails = normalizeConsolePlatformAdminEmailList(
    options.platformAdminEmails || [],
  );
  const provisioning = options.provisioning || null;
  const bootstrapRoles = normalizeConsoleOrgScopedRoleList(provisioning?.bootstrapRoles || []);
  const logger = provisioning?.logger || console;

  return {
    authenticate: async (headers) => {
      const parsedSession = await options.session.parse(headers);
      if (!parsedSession.ok) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Missing or invalid app session',
          status: 401,
        };
      }

      const claims = (parsedSession as { claims?: Record<string, unknown> }).claims || {};
      const kind = String(claims.kind || '').trim();
      const userId = String(claims.sub || '').trim();
      const appSessionVersion = String(claims.appSessionVersion || '').trim();
      if (kind !== 'app_session_v1' || !userId || !appSessionVersion) {
        return {
          ok: false,
          code: 'unauthorized',
          message: 'Invalid app session',
          status: 401,
        };
      }

      const appSessionVersionValidation = await options.authService.validateAppSessionVersion({
        userId,
        appSessionVersion,
      });
      if (!appSessionVersionValidation.ok) {
        return {
          ok: false,
          code: 'unauthorized',
          message: appSessionVersionValidation.message || 'Expired app session',
          status: 401,
        };
      }

      const resolvedDefaultOrgId = await resolveDefaultConsoleOrgId({
        defaultOrgId,
        orgProjectEnv: provisioning?.orgProjectEnv || null,
      });
      const scopedClaims = await reconcileConsoleScopeClaims({
        orgProjectEnv: provisioning?.orgProjectEnv || null,
        userId,
        claims,
        defaultOrgId: resolvedDefaultOrgId,
        orgId: String(claims.orgId || '').trim() || resolvedDefaultOrgId,
        projectId: String(claims.projectId || '').trim() || defaultProjectId,
        environmentId: String(claims.environmentId || '').trim() || defaultEnvironmentId,
      });
      const orgId = scopedClaims.orgId;
      const projectId = scopedClaims.projectId;
      const environmentId = scopedClaims.environmentId;
      const claimedEmail = readConsoleSsoEmailClaim(claims);

      const hasOrgScope = Boolean(orgId);
      let roles: string[] = hasOrgScope ? [...fallbackRoles] : [];
      if (provisioning?.teamRbac) {
        roles = hasOrgScope
          ? await ensureConsoleSsoProvisioning({
              userId,
              orgId,
              projectId,
              environmentId,
              claims,
              bootstrapRoles,
              orgProjectEnv: provisioning.orgProjectEnv || null,
              teamRbac: provisioning.teamRbac || null,
              audit: provisioning.audit || null,
              logger,
            }).catch((error: unknown) => {
              logger.warn(
                `[console-auth] failed to provision Team RBAC membership for ${userId}: ${
                  error instanceof Error ? error.message : String(error)
                }`,
              );
              return [] as ConsoleOrgScopedTeamRole[];
            })
          : [];
      }

      if (claimedEmail && platformAdminEmails.includes(claimedEmail)) {
        roles = roles.includes('platform_admin') ? roles : [...roles, 'platform_admin'];
      }

      if (!roles.length && hasOrgScope) {
        return {
          ok: false,
          code: 'forbidden',
          message: 'No console roles assigned',
          status: 403,
        };
      }

      return {
        ok: true,
        claims: {
          orgId,
          userId,
          roles,
          ...(String(claims.provider || '').trim()
            ? { provider: String(claims.provider).trim() }
            : {}),
          ...(readConsoleSsoEmailClaim(claims) ? { email: readConsoleSsoEmailClaim(claims) } : {}),
          ...(readConsoleSsoDisplayNameClaim(claims)
            ? { name: readConsoleSsoDisplayNameClaim(claims) }
            : {}),
          ...(projectId ? { projectId } : {}),
          ...(environmentId ? { environmentId } : {}),
        },
      };
    },
  };
}
