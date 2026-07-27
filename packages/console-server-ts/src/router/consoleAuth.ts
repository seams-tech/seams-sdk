import {
  ORGANIZATION_ADMIN_PERMISSIONS,
  type ActiveOrganizationAuthorization,
  type OrganizationAdminPermission,
  type ProjectAccessAssignment,
} from '../teamRbac';

export type HeaderRecord = Record<string, string | string[] | undefined>;

interface ConsoleAuthIdentityClaims {
  readonly userId: string;
  readonly orgId: string;
  readonly platformSupport: boolean;
  readonly email?: string;
  readonly name?: string;
  readonly provider?: string;
  readonly projectId?: string;
  readonly environmentId?: string;
}

type ConsoleAuthorizationClaims<T extends ActiveOrganizationAuthorization> =
  T extends ActiveOrganizationAuthorization
    ? Omit<T, 'kind' | 'orgId' | 'userId'>
    : never;

export type ConsoleAuthClaims =
  ConsoleAuthIdentityClaims & ConsoleAuthorizationClaims<ActiveOrganizationAuthorization>;

export interface ConsoleSessionResponseClaims {
  readonly userId: string;
  readonly orgId: string;
  readonly membershipId: string;
  readonly authorizationVersion: number;
  readonly role: ConsoleAuthClaims['role'];
  readonly adminPermissions: readonly OrganizationAdminPermission[];
  readonly projectAccess: readonly ProjectAccessAssignment[];
  readonly platformSupport: boolean;
  readonly email?: string;
  readonly name?: string;
  readonly provider?: string;
  readonly projectId?: string;
  readonly environmentId?: string;
}

export type ConsoleAuthAdapterResult =
  | { readonly ok: true; readonly claims: ConsoleAuthClaims }
  | {
      readonly ok: false;
      readonly code?: 'unauthorized' | 'forbidden';
      readonly message?: string;
      readonly status?: 401 | 403;
    };

export interface ConsoleAuthAdapter {
  authenticate(headers: HeaderRecord): Promise<ConsoleAuthAdapterResult> | ConsoleAuthAdapterResult;
}

export type ConsoleAuthResult =
  | { readonly ok: true; readonly claims: ConsoleAuthClaims }
  | {
      readonly ok: false;
      readonly status: 401 | 403 | 503;
      readonly code: 'unauthorized' | 'forbidden' | 'console_auth_not_configured';
      readonly message: string;
    };

function normalizeRequiredString(value: string, field: string): string {
  const normalized = String(value ?? '').trim();
  if (!normalized) throw new Error(`Console auth claim ${field} is required`);
  return normalized;
}

function normalizeOptionalString(value: string | undefined): string | undefined {
  const normalized = String(value ?? '').trim();
  return normalized || undefined;
}

function normalizeAdminPermissions(
  permissions: readonly OrganizationAdminPermission[],
): readonly OrganizationAdminPermission[] {
  const supported = new Set<OrganizationAdminPermission>();
  for (const permission of permissions) {
    if (ORGANIZATION_ADMIN_PERMISSIONS.includes(permission)) supported.add(permission);
  }
  if (supported.has('billing.manage')) supported.add('billing.view');
  return ORGANIZATION_ADMIN_PERMISSIONS.filter((permission) => supported.has(permission));
}

function normalizeProjectAssignments(
  assignments: readonly ProjectAccessAssignment[],
): readonly ProjectAccessAssignment[] {
  const byProjectId = new Map<string, ProjectAccessAssignment>();
  for (const assignment of assignments) {
    const projectId = String(assignment.projectId ?? '').trim();
    if (!projectId) continue;
    if (assignment.accessLevel !== 'viewer' && assignment.accessLevel !== 'editor') continue;
    byProjectId.set(projectId, { projectId, accessLevel: assignment.accessLevel });
  }
  return Array.from(byProjectId.values()).sort((left, right) =>
    left.projectId.localeCompare(right.projectId),
  );
}

function normalizeIdentityClaims(claims: ConsoleAuthClaims): ConsoleAuthIdentityClaims {
  const email = normalizeOptionalString(claims.email);
  const name = normalizeOptionalString(claims.name);
  const provider = normalizeOptionalString(claims.provider);
  const projectId = normalizeOptionalString(claims.projectId);
  const environmentId = normalizeOptionalString(claims.environmentId);
  return {
    userId: normalizeRequiredString(claims.userId, 'userId'),
    orgId: normalizeRequiredString(claims.orgId, 'orgId'),
    platformSupport: claims.platformSupport === true,
    ...(email ? { email } : {}),
    ...(name ? { name } : {}),
    ...(provider ? { provider } : {}),
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
  };
}

function normalizeClaims(claims: ConsoleAuthClaims): ConsoleAuthClaims {
  if (!Number.isSafeInteger(claims.authorizationVersion) || claims.authorizationVersion < 1) {
    throw new Error('Console auth claim authorizationVersion must be a positive integer');
  }
  const identity = normalizeIdentityClaims(claims);
  const membershipId = normalizeRequiredString(claims.membershipId, 'membershipId');
  switch (claims.role) {
    case 'OWNER':
      if (claims.projectAccess.kind !== 'all') {
        throw new Error('Owner projectAccess must be all');
      }
      return {
        ...identity,
        membershipId,
        authorizationVersion: claims.authorizationVersion,
        role: 'OWNER',
        adminPermissions: normalizeAdminPermissions(claims.adminPermissions),
        projectAccess: { kind: 'all' },
      };
    case 'ADMIN':
      if (claims.projectAccess.kind !== 'all') {
        throw new Error('Administrator projectAccess must be all');
      }
      return {
        ...identity,
        membershipId,
        authorizationVersion: claims.authorizationVersion,
        role: 'ADMIN',
        adminPermissions: normalizeAdminPermissions(claims.adminPermissions),
        projectAccess: { kind: 'all' },
      };
    case 'MEMBER':
      if (claims.projectAccess.kind !== 'assigned') {
        throw new Error('Member projectAccess must be assigned');
      }
      return {
        ...identity,
        membershipId,
        authorizationVersion: claims.authorizationVersion,
        role: 'MEMBER',
        adminPermissions: [],
        projectAccess: {
          kind: 'assigned',
          assignments: normalizeProjectAssignments(claims.projectAccess.assignments),
        },
      };
  }
}

export function toConsoleSessionResponseClaims(
  claims: ConsoleAuthClaims,
): ConsoleSessionResponseClaims {
  const common = {
    userId: claims.userId,
    orgId: claims.orgId,
    membershipId: claims.membershipId,
    authorizationVersion: claims.authorizationVersion,
    role: claims.role,
    adminPermissions: [...claims.adminPermissions],
    platformSupport: claims.platformSupport,
    ...(claims.email ? { email: claims.email } : {}),
    ...(claims.name ? { name: claims.name } : {}),
    ...(claims.provider ? { provider: claims.provider } : {}),
    ...(claims.projectId ? { projectId: claims.projectId } : {}),
    ...(claims.environmentId ? { environmentId: claims.environmentId } : {}),
  };
  if (claims.role !== 'MEMBER') {
    return { ...common, projectAccess: [] };
  }
  return {
    ...common,
    projectAccess: claims.projectAccess.assignments.map((assignment) => ({
      projectId: assignment.projectId,
      accessLevel: assignment.accessLevel,
    })),
  };
}

export async function authenticateConsoleRequest(
  headers: HeaderRecord,
  auth: ConsoleAuthAdapter | null | undefined,
): Promise<ConsoleAuthResult> {
  if (!auth) {
    return {
      ok: false,
      status: 503,
      code: 'console_auth_not_configured',
      message: 'Console auth adapter is not configured on this server',
    };
  }

  const result = await auth.authenticate(headers);
  if (!result.ok) {
    const status = result.status || (result.code === 'forbidden' ? 403 : 401);
    const code = result.code || (status === 403 ? 'forbidden' : 'unauthorized');
    return {
      ok: false,
      status,
      code,
      message: result.message || (code === 'forbidden' ? 'Forbidden' : 'Unauthorized'),
    };
  }

  try {
    return { ok: true, claims: normalizeClaims(result.claims) };
  } catch {
    return {
      ok: false,
      status: 401,
      code: 'unauthorized',
      message: 'Console session claims are invalid',
    };
  }
}
