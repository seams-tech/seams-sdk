import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  fetchConsoleEndpoint,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export interface DashboardAccountBackupEmail {
  email: string;
  status: 'PENDING' | 'VERIFIED';
  createdAt: string;
  updatedAt: string;
}

export interface DashboardAccountProfile {
  userId: string;
  displayName: string;
  primaryEmail: string;
  canEditPrimaryEmail: boolean;
  backupEmails: DashboardAccountBackupEmail[];
  createdAt: string;
  updatedAt: string;
}

export type DashboardAccountAdminPermission =
  | 'members.manage'
  | 'projects.manage'
  | 'billing.view'
  | 'billing.manage';

export interface DashboardAccountProjectAccessAssignment {
  projectId: string;
  accessLevel: 'viewer' | 'editor';
}

type DashboardAccountOrganizationAccess =
  | {
      membershipId: string;
      authorizationVersion: number;
      role: 'OWNER';
      adminPermissions: DashboardAccountAdminPermission[];
      projectAccess: { kind: 'all' };
    }
  | {
      membershipId: string;
      authorizationVersion: number;
      role: 'ADMIN';
      adminPermissions: DashboardAccountAdminPermission[];
      projectAccess: { kind: 'all' };
    }
  | {
      membershipId: string;
      authorizationVersion: number;
      role: 'MEMBER';
      adminPermissions: [];
      projectAccess: {
        kind: 'assigned';
        assignments: DashboardAccountProjectAccessAssignment[];
      };
    };

interface DashboardAccountOrganizationIdentity {
  id: string;
  name: string;
  slug: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  isCurrentOrg: boolean;
  onboardingComplete: boolean;
  selectedProjectId: string | null;
  selectedProjectName: string | null;
  selectedEnvironmentId: string | null;
  selectedEnvironmentName: string | null;
}

export type DashboardAccountOrganization =
  DashboardAccountOrganizationIdentity & DashboardAccountOrganizationAccess;

interface DashboardSwitchOrganizationContextIdentity {
  orgId: string;
  projectId: string | null;
  environmentId: string | null;
  onboardingComplete: boolean;
  platformSupport: boolean;
}

export type DashboardSwitchOrganizationContextResult =
  DashboardSwitchOrganizationContextIdentity & DashboardAccountOrganizationAccess;

export interface DashboardAccountApiErrorBody {
  ok?: boolean;
  code?: unknown;
  message?: unknown;
  details?: unknown;
}

export class DashboardAccountApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details: unknown;

  constructor(input: { status: number; code?: unknown; message: string; details?: unknown }) {
    super(input.message);
    this.name = 'DashboardAccountApiError';
    this.status = input.status;
    this.code = String(input.code || '').trim();
    this.details = input.details;
  }
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return Boolean(raw) && typeof raw === 'object' && !Array.isArray(raw);
}

function readString(raw: unknown): string {
  return String(raw || '').trim();
}

function readBoolean(raw: unknown): boolean {
  return raw === true;
}

function parseBackupEmail(raw: unknown): DashboardAccountBackupEmail | null {
  if (!isRecord(raw)) return null;
  const email = readString(raw.email).toLowerCase();
  if (!email) return null;
  const status = readString(raw.status).toUpperCase();
  return {
    email,
    status: status === 'VERIFIED' ? 'VERIFIED' : 'PENDING',
    createdAt: readString(raw.createdAt),
    updatedAt: readString(raw.updatedAt),
  };
}

function parseProfile(raw: unknown): DashboardAccountProfile | null {
  if (!isRecord(raw)) return null;
  const userId = readString(raw.userId);
  if (!userId) return null;
  const backupEmails = Array.isArray(raw.backupEmails)
    ? raw.backupEmails
        .map((entry) => parseBackupEmail(entry))
        .filter((entry): entry is DashboardAccountBackupEmail => entry !== null)
    : [];
  return {
    userId,
    displayName: readString(raw.displayName),
    primaryEmail: readString(raw.primaryEmail).toLowerCase(),
    canEditPrimaryEmail: raw.canEditPrimaryEmail !== false,
    backupEmails,
    createdAt: readString(raw.createdAt),
    updatedAt: readString(raw.updatedAt),
  };
}

function parseAdminPermissions(raw: unknown): DashboardAccountAdminPermission[] {
  if (!Array.isArray(raw)) return [];
  const permissions = new Set<DashboardAccountAdminPermission>();
  for (const entry of raw) {
    const permission = readString(entry);
    if (
      permission === 'members.manage' ||
      permission === 'projects.manage' ||
      permission === 'billing.view' ||
      permission === 'billing.manage'
    ) {
      permissions.add(permission);
    }
  }
  if (permissions.has('billing.manage')) permissions.add('billing.view');
  return ['members.manage', 'projects.manage', 'billing.view', 'billing.manage'].filter(
    (permission): permission is DashboardAccountAdminPermission =>
      permissions.has(permission as DashboardAccountAdminPermission),
  );
}

function parseProjectAssignments(raw: unknown): DashboardAccountProjectAccessAssignment[] {
  if (!Array.isArray(raw)) return [];
  return raw.flatMap((entry) => {
    if (!isRecord(entry)) return [];
    const projectId = readString(entry.projectId);
    const accessLevel = readString(entry.accessLevel).toLowerCase();
    if (!projectId || (accessLevel !== 'viewer' && accessLevel !== 'editor')) return [];
    return [{ projectId, accessLevel }];
  });
}

function parseOrganizationAccess(raw: Record<string, unknown>): DashboardAccountOrganizationAccess | null {
  const membershipId = readString(raw.membershipId);
  const authorizationVersion = Number(raw.authorizationVersion);
  const role = readString(raw.role).toUpperCase();
  if (
    !membershipId ||
    !Number.isSafeInteger(authorizationVersion) ||
    authorizationVersion < 1
  ) {
    return null;
  }
  if (role === 'OWNER' || role === 'ADMIN') {
    if (!isRecord(raw.projectAccess) || raw.projectAccess.kind !== 'all') return null;
    const common = {
      membershipId,
      authorizationVersion,
      adminPermissions: parseAdminPermissions(raw.adminPermissions),
      projectAccess: { kind: 'all' as const },
    };
    return role === 'OWNER'
      ? { ...common, role: 'OWNER' }
      : { ...common, role: 'ADMIN' };
  }
  if (
    role !== 'MEMBER' ||
    !isRecord(raw.projectAccess) ||
    raw.projectAccess.kind !== 'assigned'
  ) {
    return null;
  }
  return {
    membershipId,
    authorizationVersion,
    role: 'MEMBER',
    adminPermissions: [],
    projectAccess: {
      kind: 'assigned',
      assignments: parseProjectAssignments(raw.projectAccess.assignments),
    },
  };
}

function parseOrganization(raw: unknown): DashboardAccountOrganization | null {
  if (!isRecord(raw)) return null;
  const id = readString(raw.id);
  const access = parseOrganizationAccess(raw);
  if (!id || !access) return null;
  return {
    ...access,
    id,
    name: readString(raw.name) || id,
    slug: readString(raw.slug),
    status: readString(raw.status) || 'ACTIVE',
    createdAt: readString(raw.createdAt),
    updatedAt: readString(raw.updatedAt),
    isCurrentOrg: readBoolean(raw.isCurrentOrg),
    onboardingComplete: readBoolean(raw.onboardingComplete),
    selectedProjectId: readString(raw.selectedProjectId) || null,
    selectedProjectName: readString(raw.selectedProjectName) || null,
    selectedEnvironmentId: readString(raw.selectedEnvironmentId) || null,
    selectedEnvironmentName: readString(raw.selectedEnvironmentName) || null,
  };
}

function parseSwitchContext(raw: unknown): DashboardSwitchOrganizationContextResult | null {
  if (!isRecord(raw)) return null;
  const orgId = readString(raw.orgId);
  const access = parseOrganizationAccess(raw);
  if (!orgId || !access) return null;
  return {
    ...access,
    orgId,
    projectId: readString(raw.projectId) || null,
    environmentId: readString(raw.environmentId) || null,
    onboardingComplete: readBoolean(raw.onboardingComplete),
    platformSupport: readBoolean(raw.platformSupport),
  };
}

function buildAccountApiError(
  response: Response,
  body: DashboardAccountApiErrorBody | null | undefined,
  fallbackPrefix: string,
): DashboardAccountApiError {
  return new DashboardAccountApiError({
    status: response.status,
    code: body?.code,
    message: consoleErrorMessage(response, body, fallbackPrefix),
    details: body?.details,
  });
}

async function requestJson(
  path: string,
  init: RequestInit,
  fallbackPrefix: string,
): Promise<Record<string, unknown>> {
  const base = requireConsoleBaseUrl();
  const response = await fetchConsoleEndpoint(
    `${base}${path}`,
    {
      credentials: 'include',
      cache: 'no-store',
      ...init,
    },
    {
      baseUrl: base,
      path,
      operation: fallbackPrefix,
    },
  );
  const body = (await parseConsoleJson(response)) as DashboardAccountApiErrorBody | null;
  if (!response.ok || body?.ok !== true) {
    throw buildAccountApiError(response, body, fallbackPrefix);
  }
  return isRecord(body) ? body : {};
}

export function isDashboardAccountApiErrorCode(error: unknown, code: string): boolean {
  return error instanceof DashboardAccountApiError && error.code === code;
}

export async function getDashboardAccountProfile(): Promise<DashboardAccountProfile> {
  const body = await requestJson(
    '/console/account/profile',
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
    },
    'Account profile request failed',
  );
  const profile = parseProfile(body.profile);
  if (!profile) throw new Error('Account profile response was invalid');
  return profile;
}

export async function updateDashboardAccountProfile(input: {
  displayName?: string;
  primaryEmail?: string;
  addBackupEmail?: string;
  removeBackupEmail?: string;
}): Promise<DashboardAccountProfile> {
  const body = await requestJson(
    '/console/account/profile',
    {
      method: 'PATCH',
      headers: buildConsoleJsonHeaders(),
      body: JSON.stringify(input),
    },
    'Account profile update failed',
  );
  const profile = parseProfile(body.profile);
  if (!profile) throw new Error('Account profile update response was invalid');
  return profile;
}

export async function listDashboardAccountOrganizations(): Promise<DashboardAccountOrganization[]> {
  const body = await requestJson(
    '/console/account/organizations',
    {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
    },
    'Account organizations request failed',
  );
  const rows = Array.isArray(body.organizations) ? body.organizations : [];
  return rows
    .map((entry) => parseOrganization(entry))
    .filter((entry): entry is DashboardAccountOrganization => entry !== null);
}

export async function createDashboardAccountOrganization(input: {
  id?: string;
  name: string;
  slug?: string;
}): Promise<DashboardAccountOrganization> {
  const body = await requestJson(
    '/console/account/organizations',
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      body: JSON.stringify(input),
    },
    'Account organization create failed',
  );
  const organization = parseOrganization(body.organization);
  if (!organization) throw new Error('Account organization create response was invalid');
  return organization;
}

export async function updateDashboardAccountOrganization(
  orgId: string,
  input: { name?: string; slug?: string },
): Promise<DashboardAccountOrganization> {
  const normalizedOrgId = readString(orgId);
  if (!normalizedOrgId) throw new Error('Organization id is required');
  const body = await requestJson(
    `/console/account/organizations/${encodeURIComponent(normalizedOrgId)}`,
    {
      method: 'PATCH',
      headers: buildConsoleJsonHeaders(),
      body: JSON.stringify(input),
    },
    'Account organization update failed',
  );
  const organization = parseOrganization(body.organization);
  if (!organization) throw new Error('Account organization update response was invalid');
  return organization;
}

export async function deleteDashboardAccountOrganization(orgId: string): Promise<void> {
  const normalizedOrgId = readString(orgId);
  if (!normalizedOrgId) throw new Error('Organization id is required');
  await requestJson(
    `/console/account/organizations/${encodeURIComponent(normalizedOrgId)}`,
    {
      method: 'DELETE',
      headers: buildConsoleAcceptHeaders(),
    },
    'Account organization delete failed',
  );
}

export async function leaveDashboardAccountOrganization(): Promise<void> {
  await requestJson(
    '/console/organization/leave',
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      body: JSON.stringify({}),
    },
    'Leave organization failed',
  );
}

export async function switchDashboardAccountOrganizationContext(
  orgId: string,
): Promise<DashboardSwitchOrganizationContextResult> {
  const normalizedOrgId = readString(orgId);
  if (!normalizedOrgId) throw new Error('Organization id is required');
  const body = await requestJson(
    `/console/account/organizations/${encodeURIComponent(normalizedOrgId)}/switch-context`,
    {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      body: JSON.stringify({}),
    },
    'Account organization context switch failed',
  );
  const context = parseSwitchContext(body.context);
  if (!context) throw new Error('Account organization context switch response was invalid');
  return context;
}
