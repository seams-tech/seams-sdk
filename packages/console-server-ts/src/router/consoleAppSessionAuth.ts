import type { ConsoleAuditService } from '../audit/service';
import type {
  ConsoleOrgProjectEnvContext,
  ConsoleOrgProjectEnvService,
} from '../orgProjectEnv/service';
import type {
  ActiveOrganizationAuthorization,
  ConsoleOrganizationAccessService,
} from '../teamRbac';
import type { SessionAdapter } from '@seams/sdk-server/cloud-host';
import type { ConsoleAuthAdapter, ConsoleAuthClaims, HeaderRecord } from './consoleAuth';

export interface ConsoleSsoProvisioningOptions {
  readonly orgProjectEnv?: ConsoleOrgProjectEnvService | null;
  readonly audit?: ConsoleAuditService | null;
  readonly logger?: { warn(message?: unknown, ...optionalParams: unknown[]): void } | null;
}

export interface AppSessionConsoleAuthAdapterOptions {
  readonly session: SessionAdapter;
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly defaultOrgId?: string;
  readonly defaultProjectId?: string;
  readonly defaultEnvironmentId?: string;
  readonly initialOwnerEmail?: string;
  readonly platformSupportEmails?: ReadonlyArray<unknown> | string;
  readonly provisioning?: ConsoleSsoProvisioningOptions | null;
}

interface ReconciledConsoleScope {
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
  readonly derivedOrganization: boolean;
}

type ConsoleIdentityProfile =
  | {
      readonly kind: 'google_oidc';
      readonly email: string;
      readonly displayName: string;
      readonly provider: 'oidc';
      readonly emailVerified: boolean;
      readonly hostedDomain: string | null;
    }
  | {
      readonly kind: 'other';
      readonly email: string;
      readonly displayName: string;
      readonly provider: string;
    };

const CONSOLE_SSO_ORG_ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789';

function normalizeString(value: unknown): string {
  return String(value ?? '').trim();
}

function parseCsvValues(value: unknown): string[] {
  return normalizeString(value)
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeConsoleEmailList(input: unknown): readonly string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const values = Array.isArray(input) ? input : parseCsvValues(input);
  for (const raw of values) {
    const email = normalizeConsoleEmail(raw);
    if (!email || seen.has(email)) continue;
    seen.add(email);
    out.push(email);
  }
  return out;
}

function normalizeConsoleEmail(value: unknown): string | null {
  const email = normalizeString(value).toLowerCase();
  const separator = email.indexOf('@');
  if (
    !email ||
    separator <= 0 ||
    separator === email.length - 1 ||
    email.indexOf('@', separator + 1) !== -1 ||
    /\s/u.test(email)
  ) {
    return null;
  }
  return email;
}

function normalizeInitialOwnerEmail(value: unknown): string | null {
  const raw = normalizeString(value);
  if (!raw) return null;
  const email = normalizeConsoleEmail(raw);
  if (!email || raw.includes(',')) {
    throw new Error('initialOwnerEmail must contain exactly one valid email address');
  }
  return email;
}

function hasConsoleErrorCode(error: unknown, code: string): boolean {
  if (!error || typeof error !== 'object' || !('code' in error)) return false;
  return normalizeString(error.code) === code;
}

function readConsoleEmailClaim(claims: Record<string, unknown>): string | null {
  const claimed = normalizeString(claims.email || claims.email_address).toLowerCase();
  return claimed && claimed.includes('@') ? claimed : null;
}

function readConsoleDisplayNameClaim(claims: Record<string, unknown>): string | null {
  const displayName = normalizeString(claims.name || claims.preferred_username);
  if (displayName) return displayName;
  const fullName = `${normalizeString(claims.given_name)} ${normalizeString(
    claims.family_name,
  )}`.trim();
  return fullName || null;
}

function resolveConsoleIdentityProfile(
  userId: string,
  claims: Record<string, unknown>,
): ConsoleIdentityProfile {
  const claimedEmail = readConsoleEmailClaim(claims);
  const emailUser = normalizeString(userId)
    .toLowerCase()
    .replace(/[^a-z0-9._+-]/gu, '_');
  const email = claimedEmail ?? `${emailUser || 'user'}@console.local`;
  const displayName = readConsoleDisplayNameClaim(claims) ?? userId;
  const provider = normalizeString(claims.provider) || 'unknown';
  if (provider === 'oidc' && normalizeString(claims.oidcProvider).toLowerCase() === 'google') {
    return {
      kind: 'google_oidc',
      email,
      displayName,
      provider,
      emailVerified: claims.oidcEmailVerified === true,
      hostedDomain: normalizeConsoleEmailDomain(claims.oidcHostedDomain),
    };
  }
  return { kind: 'other', email, displayName, provider };
}

function normalizeConsoleEmailDomain(value: unknown): string | null {
  const domain = normalizeString(value).toLowerCase();
  if (!domain || domain.includes('@') || /\s/u.test(domain)) return null;
  return domain;
}

function isAuthoritativeGoogleEmail(profile: ConsoleIdentityProfile): boolean {
  if (profile.kind !== 'google_oidc' || !profile.emailVerified) return false;
  const domain = profile.email.slice(profile.email.lastIndexOf('@') + 1);
  return domain === 'gmail.com' || profile.hostedDomain === domain;
}

function matchesInitialOwnerEmail(input: {
  readonly profile: ConsoleIdentityProfile;
  readonly initialOwnerEmail: string | null;
}): boolean {
  return (
    Boolean(input.initialOwnerEmail) &&
    input.profile.email === input.initialOwnerEmail &&
    isAuthoritativeGoogleEmail(input.profile)
  );
}

function readEnvironmentKeyCandidate(environmentId: string): 'dev' | 'staging' | 'prod' | null {
  const candidate = normalizeString(environmentId).split(':').pop()?.toLowerCase();
  if (candidate === 'dev' || candidate === 'staging' || candidate === 'prod') {
    return candidate;
  }
  return null;
}

function deriveConsoleSsoOrganizationId(input: {
  readonly userId: string;
  readonly claims: Record<string, unknown>;
}): string {
  const source =
    normalizeString(input.claims.providerSubject) ||
    normalizeString(input.claims.oidcSub) ||
    normalizeString(input.userId);
  let h1 = 0x811c9dc5;
  let h2 = 0x9e3779b9;
  for (let index = 0; index < source.length; index += 1) {
    const code = source.charCodeAt(index);
    h1 = Math.imul(h1 ^ code, 0x01000193) >>> 0;
    h2 = Math.imul(h2 + code + index, 0x85ebca6b) >>> 0;
  }
  let suffix = '';
  for (let index = 0; index < 12; index += 1) {
    h1 = Math.imul(h1 ^ (h2 + index), 0x01000193) >>> 0;
    h2 = Math.imul(h2 ^ (h1 + index), 0xc2b2ae35) >>> 0;
    const alphabetIndex = ((h1 ^ h2) >>> 0) % CONSOLE_SSO_ORG_ID_ALPHABET.length;
    suffix += CONSOLE_SSO_ORG_ID_ALPHABET[alphabetIndex] ?? '0';
  }
  return `org_${suffix}`;
}

function createConsoleScopeReadContext(input: {
  readonly orgId: string;
  readonly userId: string;
  readonly projectId?: string;
  readonly environmentId?: string;
}): ConsoleOrgProjectEnvContext {
  return {
    orgId: input.orgId,
    actorUserId: input.userId,
    ...(input.projectId ? { projectId: input.projectId } : {}),
    ...(input.environmentId ? { environmentId: input.environmentId } : {}),
  };
}

async function organizationExists(input: {
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly orgId: string;
  readonly userId: string;
}): Promise<boolean> {
  try {
    await input.orgProjectEnv.getOrganization(
      createConsoleScopeReadContext({ orgId: input.orgId, userId: input.userId }),
    );
    return true;
  } catch (error: unknown) {
    if (hasConsoleErrorCode(error, 'organization_not_found')) return false;
    throw error;
  }
}

async function resolveDefaultConsoleOrgId(input: {
  readonly defaultOrgId: string;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService | null;
}): Promise<string> {
  if (input.defaultOrgId || !input.orgProjectEnv) return input.defaultOrgId;
  try {
    return normalizeString((await input.orgProjectEnv.findDefaultOrganization())?.id);
  } catch {
    return '';
  }
}

async function reconcileConsoleScopeClaims(input: {
  readonly orgProjectEnv: ConsoleOrgProjectEnvService | null;
  readonly userId: string;
  readonly claims: Record<string, unknown>;
  readonly defaultOrgId: string;
  readonly orgId: string;
  readonly projectId: string;
  readonly environmentId: string;
}): Promise<ReconciledConsoleScope> {
  if (!input.orgProjectEnv) {
    const derivedOrganization = !input.orgId && normalizeString(input.claims.provider) === 'oidc';
    return {
      orgId: derivedOrganization
        ? deriveConsoleSsoOrganizationId({ userId: input.userId, claims: input.claims })
        : input.orgId,
      projectId: input.projectId,
      environmentId: input.environmentId,
      derivedOrganization,
    };
  }

  try {
    let orgId = input.orgId;
    let derivedOrganization = false;
    if (
      orgId &&
      !(await organizationExists({
        orgProjectEnv: input.orgProjectEnv,
        orgId,
        userId: input.userId,
      }))
    ) {
      orgId = '';
    }
    if (!orgId) {
      const organization = await input.orgProjectEnv.findOrganizationForScope({
        ...(input.projectId ? { projectId: input.projectId } : {}),
        ...(input.environmentId ? { environmentId: input.environmentId } : {}),
      });
      orgId = normalizeString(organization?.id);
    }
    if (
      !orgId &&
      input.defaultOrgId &&
      (await organizationExists({
        orgProjectEnv: input.orgProjectEnv,
        orgId: input.defaultOrgId,
        userId: input.userId,
      }))
    ) {
      orgId = input.defaultOrgId;
    }
    if (!orgId && normalizeString(input.claims.provider) === 'oidc') {
      orgId = deriveConsoleSsoOrganizationId({
        userId: input.userId,
        claims: input.claims,
      });
      derivedOrganization = true;
    }
    if (!orgId || derivedOrganization) {
      return {
        orgId,
        projectId: input.projectId,
        environmentId: input.environmentId,
        derivedOrganization,
      };
    }

    const readCtx = createConsoleScopeReadContext({
      orgId,
      userId: input.userId,
      projectId: input.projectId,
      environmentId: input.environmentId,
    });
    const [projects, environments] = await Promise.all([
      input.orgProjectEnv.listProjects(readCtx, { status: 'ACTIVE' }),
      input.orgProjectEnv.listEnvironments(readCtx, { status: 'ACTIVE' }),
    ]);
    let projectId = input.projectId;
    let environmentId = input.environmentId;
    const exactEnvironment = environments.find((environment) => environment.id === environmentId);
    if (exactEnvironment) {
      projectId = exactEnvironment.projectId;
      environmentId = exactEnvironment.id;
    } else {
      const environmentKey = readEnvironmentKeyCandidate(environmentId);
      const environment =
        (projectId && environmentKey
          ? environments.find(
              (entry) => entry.projectId === projectId && entry.key === environmentKey,
            )
          : undefined) ??
        (projectId ? environments.find((entry) => entry.projectId === projectId) : undefined) ??
        (environmentKey ? environments.find((entry) => entry.key === environmentKey) : undefined) ??
        environments[0];
      if (environment) {
        projectId = environment.projectId;
        environmentId = environment.id;
      }
    }
    if (!projectId || !projects.some((project) => project.id === projectId)) {
      projectId = projects[0]?.id ?? '';
    }
    return {
      orgId,
      projectId,
      environmentId,
      derivedOrganization: false,
    };
  } catch {
    return {
      orgId: input.orgId,
      projectId: input.projectId,
      environmentId: input.environmentId,
      derivedOrganization: false,
    };
  }
}

async function appendInitialOwnerAudit(input: {
  readonly audit: ConsoleAuditService | null;
  readonly logger: { warn(message?: unknown, ...optionalParams: unknown[]): void };
  readonly authorization: ActiveOrganizationAuthorization;
  readonly profile: ConsoleIdentityProfile;
}): Promise<void> {
  if (!input.audit) return;
  try {
    await input.audit.appendEvent(
      {
        orgId: input.authorization.orgId,
        actorUserId: input.authorization.userId,
      },
      {
        category: 'TEAM',
        action: 'member.owner.bootstrap',
        outcome: 'SUCCESS',
        summary: `Provisioned initial owner ${input.authorization.userId}`,
        metadata: {
          source: 'console_auth_sso',
          membershipId: input.authorization.membershipId,
          provider: input.profile.provider,
        },
      },
    );
  } catch (error: unknown) {
    input.logger.warn(
      `[console-auth] failed to append initial-owner audit event for ${
        input.authorization.userId
      }: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

async function provisionInitialOidcOwner(input: {
  readonly orgId: string;
  readonly userId: string;
  readonly profile: ConsoleIdentityProfile;
  readonly organizationAccess: ConsoleOrganizationAccessService;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService;
  readonly audit: ConsoleAuditService | null;
  readonly logger: { warn(message?: unknown, ...optionalParams: unknown[]): void };
}): Promise<void> {
  const existingAuthorization = await input.organizationAccess.lookupAuthorization({
    orgId: input.orgId,
    userId: input.userId,
  });
  if (existingAuthorization?.kind === 'authorized') return;
  const exists = await organizationExists({
    orgProjectEnv: input.orgProjectEnv,
    orgId: input.orgId,
    userId: input.userId,
  });
  if (!exists) {
    await input.orgProjectEnv.upsertOrganization(
      createConsoleScopeReadContext({ orgId: input.orgId, userId: input.userId }),
      {},
    );
  }
  let ownerId = '';
  try {
    const owner = await input.organizationAccess.bootstrapInitialOwner({
      orgId: input.orgId,
      userId: input.userId,
      email: input.profile.email,
      displayName: input.profile.displayName,
    });
    ownerId = owner.id;
  } catch (error: unknown) {
    if (hasConsoleErrorCode(error, 'owner_already_exists')) return;
    throw error;
  }
  const authorization = await input.organizationAccess.lookupAuthorization({
    orgId: input.orgId,
    userId: input.userId,
  });
  if (!authorization || authorization.kind === 'denied' || authorization.role !== 'OWNER') {
    throw new Error(`Initial owner ${ownerId} could not be authorized`);
  }
  await appendInitialOwnerAudit({
    audit: input.audit,
    logger: input.logger,
    authorization,
    profile: input.profile,
  });
}

async function restrictScopeToAuthorization(input: {
  readonly scope: ReconciledConsoleScope;
  readonly authorization: ActiveOrganizationAuthorization;
  readonly userId: string;
  readonly orgProjectEnv: ConsoleOrgProjectEnvService | null;
}): Promise<ReconciledConsoleScope> {
  if (input.authorization.role !== 'MEMBER') return input.scope;
  const assignments = input.authorization.projectAccess.assignments;
  const assignedProjectIds = new Set(assignments.map((assignment) => assignment.projectId));
  if (!input.orgProjectEnv) {
    const projectId = assignedProjectIds.has(input.scope.projectId)
      ? input.scope.projectId
      : (assignments[0]?.projectId ?? '');
    return {
      orgId: input.scope.orgId,
      projectId,
      environmentId: projectId === input.scope.projectId ? input.scope.environmentId : '',
      derivedOrganization: input.scope.derivedOrganization,
    };
  }
  const readCtx = createConsoleScopeReadContext({
    orgId: input.scope.orgId,
    userId: input.userId,
  });
  const [projects, environments] = await Promise.all([
    input.orgProjectEnv.listProjects(readCtx, { status: 'ACTIVE' }),
    input.orgProjectEnv.listEnvironments(readCtx, { status: 'ACTIVE' }),
  ]);
  const accessibleProjects = projects.filter((project) => assignedProjectIds.has(project.id));
  const exactEnvironment = environments.find(
    (environment) =>
      environment.id === input.scope.environmentId && assignedProjectIds.has(environment.projectId),
  );
  if (exactEnvironment) {
    return {
      orgId: input.scope.orgId,
      projectId: exactEnvironment.projectId,
      environmentId: exactEnvironment.id,
      derivedOrganization: input.scope.derivedOrganization,
    };
  }
  const projectId = assignedProjectIds.has(input.scope.projectId)
    ? input.scope.projectId
    : (accessibleProjects[0]?.id ?? '');
  const environmentId =
    environments.find((environment) => environment.projectId === projectId)?.id ?? '';
  return {
    orgId: input.scope.orgId,
    projectId,
    environmentId,
    derivedOrganization: input.scope.derivedOrganization,
  };
}

function buildConsoleAuthClaims(input: {
  readonly authorization: ActiveOrganizationAuthorization;
  readonly scope: ReconciledConsoleScope;
  readonly profile: ConsoleIdentityProfile;
  readonly platformSupport: boolean;
}): ConsoleAuthClaims {
  const identity = {
    userId: input.authorization.userId,
    orgId: input.authorization.orgId,
    platformSupport: input.platformSupport,
    email: input.profile.email,
    name: input.profile.displayName,
    provider: input.profile.provider,
    ...(input.scope.projectId ? { projectId: input.scope.projectId } : {}),
    ...(input.scope.environmentId ? { environmentId: input.scope.environmentId } : {}),
  };
  switch (input.authorization.role) {
    case 'OWNER':
      return {
        ...identity,
        membershipId: input.authorization.membershipId,
        authorizationVersion: input.authorization.authorizationVersion,
        role: 'OWNER',
        adminPermissions: [...input.authorization.adminPermissions],
        projectAccess: { kind: 'all' },
      };
    case 'ADMIN':
      return {
        ...identity,
        membershipId: input.authorization.membershipId,
        authorizationVersion: input.authorization.authorizationVersion,
        role: 'ADMIN',
        adminPermissions: [...input.authorization.adminPermissions],
        projectAccess: { kind: 'all' },
      };
    case 'MEMBER':
      return {
        ...identity,
        membershipId: input.authorization.membershipId,
        authorizationVersion: input.authorization.authorizationVersion,
        role: 'MEMBER',
        adminPermissions: [],
        projectAccess: {
          kind: 'assigned',
          assignments: input.authorization.projectAccess.assignments.map((assignment) => ({
            projectId: assignment.projectId,
            accessLevel: assignment.accessLevel,
          })),
        },
      };
  }
}

interface AppSessionConsoleAuthRuntime {
  readonly options: AppSessionConsoleAuthAdapterOptions;
  readonly defaultOrgId: string;
  readonly defaultProjectId: string;
  readonly defaultEnvironmentId: string;
  readonly initialOwnerEmail: string | null;
  readonly platformSupportEmails: readonly string[];
  readonly orgProjectEnv: ConsoleOrgProjectEnvService | null;
  readonly audit: ConsoleAuditService | null;
  readonly logger: { warn(message?: unknown, ...optionalParams: unknown[]): void };
}

class AppSessionConsoleAuthAdapter implements ConsoleAuthAdapter {
  readonly #runtime: AppSessionConsoleAuthRuntime;

  constructor(options: AppSessionConsoleAuthAdapterOptions) {
    this.#runtime = {
      options,
      defaultOrgId: normalizeString(options.defaultOrgId),
      defaultProjectId: normalizeString(options.defaultProjectId),
      defaultEnvironmentId: normalizeString(options.defaultEnvironmentId),
      initialOwnerEmail: normalizeInitialOwnerEmail(options.initialOwnerEmail),
      platformSupportEmails: normalizeConsoleEmailList(options.platformSupportEmails ?? []),
      orgProjectEnv: options.provisioning?.orgProjectEnv ?? null,
      audit: options.provisioning?.audit ?? null,
      logger: options.provisioning?.logger ?? console,
    };
  }

  async authenticate(headers: HeaderRecord) {
    const parsedSession = await this.#runtime.options.session.parse(headers);
    if (!parsedSession.ok) {
      return {
        ok: false as const,
        code: 'unauthorized' as const,
        message: 'Missing or invalid app session',
        status: 401 as const,
      };
    }
    const claims = parsedSession.claims;
    const kind = normalizeString(claims.kind);
    const userId = normalizeString(claims.sub);
    const appSessionVersion = normalizeString(claims.appSessionVersion);
    if (kind !== 'app_session_v1' || !userId || !appSessionVersion) {
      return {
        ok: false as const,
        code: 'unauthorized' as const,
        message: 'Invalid app session',
        status: 401 as const,
      };
    }
    const profile = resolveConsoleIdentityProfile(userId, claims);
    const resolvedDefaultOrgId = await resolveDefaultConsoleOrgId({
      defaultOrgId: this.#runtime.defaultOrgId,
      orgProjectEnv: this.#runtime.orgProjectEnv,
    });
    let scope = await reconcileConsoleScopeClaims({
      orgProjectEnv: this.#runtime.orgProjectEnv,
      userId,
      claims,
      defaultOrgId: resolvedDefaultOrgId,
      orgId: normalizeString(claims.orgId) || resolvedDefaultOrgId,
      projectId: normalizeString(claims.projectId) || this.#runtime.defaultProjectId,
      environmentId: normalizeString(claims.environmentId) || this.#runtime.defaultEnvironmentId,
    });
    if (!scope.orgId) {
      return {
        ok: false as const,
        code: 'forbidden' as const,
        message: 'No console organization assigned',
        status: 403 as const,
      };
    }
    if (
      profile.provider === 'oidc' &&
      this.#runtime.orgProjectEnv &&
      (scope.derivedOrganization ||
        matchesInitialOwnerEmail({
          profile,
          initialOwnerEmail: this.#runtime.initialOwnerEmail,
        }))
    ) {
      await provisionInitialOidcOwner({
        orgId: scope.orgId,
        userId,
        profile,
        organizationAccess: this.#runtime.options.organizationAccess,
        orgProjectEnv: this.#runtime.orgProjectEnv,
        audit: this.#runtime.audit,
        logger: this.#runtime.logger,
      });
    }
    const authorization = await this.#runtime.options.organizationAccess.lookupAuthorization({
      orgId: scope.orgId,
      userId,
    });
    if (!authorization || authorization.kind === 'denied') {
      return {
        ok: false as const,
        code: 'forbidden' as const,
        message: 'No active organization membership',
        status: 403 as const,
      };
    }
    scope = await restrictScopeToAuthorization({
      scope,
      authorization,
      userId,
      orgProjectEnv: this.#runtime.orgProjectEnv,
    });
    return {
      ok: true as const,
      claims: buildConsoleAuthClaims({
        authorization,
        scope,
        profile,
        platformSupport:
          isAuthoritativeGoogleEmail(profile) &&
          this.#runtime.platformSupportEmails.includes(profile.email),
      }),
    };
  }
}

export function createAppSessionConsoleAuthAdapter(
  options: AppSessionConsoleAuthAdapterOptions,
): ConsoleAuthAdapter {
  return new AppSessionConsoleAuthAdapter(options);
}
