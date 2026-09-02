import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  normalizeConsoleFetchError,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export const DASHBOARD_ORGANIZATION_ADMIN_PERMISSIONS = [
  'members.manage',
  'projects.manage',
  'billing.view',
  'billing.manage',
] as const;

export type DashboardOrganizationRole = 'OWNER' | 'ADMIN' | 'MEMBER';
export type DashboardOrganizationMembershipKind = 'active' | 'suspended' | 'removed';
export type DashboardOrganizationInvitationKind =
  | 'pending'
  | 'accepted'
  | 'declined'
  | 'revoked'
  | 'expired';
export type DashboardOrganizationAdminPermission =
  (typeof DASHBOARD_ORGANIZATION_ADMIN_PERMISSIONS)[number];
export type DashboardProjectAccessLevel = 'viewer' | 'editor';

export interface DashboardProjectAccessAssignment {
  projectId: string;
  accessLevel: DashboardProjectAccessLevel;
}

export interface DashboardOrganizationMembership {
  id: string;
  orgId: string;
  userId: string;
  email: string;
  displayName: string | null;
  kind: DashboardOrganizationMembershipKind;
  role: DashboardOrganizationRole;
  adminPermissions: DashboardOrganizationAdminPermission[];
  projectAccess: DashboardProjectAccessAssignment[];
  createdAt: string;
  updatedAt: string;
  suspendedAt: string | null;
  removedAt: string | null;
}

export interface DashboardOrganizationInvitation {
  id: string;
  orgId: string;
  email: string;
  invitedByUserId: string;
  kind: DashboardOrganizationInvitationKind;
  role: DashboardOrganizationRole;
  adminPermissions: DashboardOrganizationAdminPermission[];
  projectAccess: DashboardProjectAccessAssignment[];
  createdAt: string;
  updatedAt: string;
  expiresAt: string | null;
}

export type DashboardOrganizationGrant =
  | {
      role: 'OWNER';
    }
  | {
      role: 'ADMIN';
      adminPermissions: DashboardOrganizationAdminPermission[];
    }
  | {
      role: 'MEMBER';
      projectAccess: DashboardProjectAccessAssignment[];
    };

interface ConsoleResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  memberships?: unknown;
  membership?: unknown;
  invitations?: unknown;
  invitation?: unknown;
  removed?: unknown;
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return Boolean(raw) && typeof raw === 'object' && !Array.isArray(raw);
}

function readRole(raw: unknown): DashboardOrganizationRole | null {
  const role = String(raw ?? '').trim().toUpperCase();
  if (role === 'OWNER' || role === 'ADMIN' || role === 'MEMBER') return role;
  return null;
}

function readMembershipKind(raw: unknown): DashboardOrganizationMembershipKind | null {
  const kind = String(raw ?? '').trim().toLowerCase();
  if (kind === 'active' || kind === 'suspended' || kind === 'removed') return kind;
  return null;
}

function readInvitationKind(raw: unknown): DashboardOrganizationInvitationKind | null {
  const kind = String(raw ?? '').trim().toLowerCase();
  switch (kind) {
    case 'pending':
    case 'accepted':
    case 'declined':
    case 'revoked':
    case 'expired':
      return kind;
    default:
      return null;
  }
}

function readAdminPermission(raw: unknown): DashboardOrganizationAdminPermission | null {
  const permission = String(raw ?? '').trim();
  for (const supported of DASHBOARD_ORGANIZATION_ADMIN_PERMISSIONS) {
    if (permission === supported) return supported;
  }
  return null;
}

function readAdminPermissions(raw: unknown): DashboardOrganizationAdminPermission[] {
  if (!Array.isArray(raw)) return [];
  const permissions = new Set<DashboardOrganizationAdminPermission>();
  for (const entry of raw) {
    const permission = readAdminPermission(entry);
    if (permission) permissions.add(permission);
  }
  if (permissions.has('billing.manage')) permissions.add('billing.view');
  return DASHBOARD_ORGANIZATION_ADMIN_PERMISSIONS.filter((permission) =>
    permissions.has(permission),
  );
}

function readProjectAccessLevel(raw: unknown): DashboardProjectAccessLevel | null {
  const accessLevel = String(raw ?? '').trim().toLowerCase();
  if (accessLevel === 'viewer' || accessLevel === 'editor') return accessLevel;
  return null;
}

function decodeProjectAccess(raw: unknown): DashboardProjectAccessAssignment[] {
  if (!Array.isArray(raw)) return [];
  const assignments = new Map<string, DashboardProjectAccessAssignment>();
  for (const entry of raw) {
    if (!isRecord(entry)) continue;
    const projectId = String(entry.projectId ?? '').trim();
    const accessLevel = readProjectAccessLevel(entry.accessLevel);
    if (!projectId || !accessLevel) continue;
    assignments.set(projectId, { projectId, accessLevel });
  }
  return Array.from(assignments.values()).sort((left, right) =>
    left.projectId.localeCompare(right.projectId),
  );
}

function decodeMembership(raw: unknown): DashboardOrganizationMembership | null {
  if (!isRecord(raw)) return null;
  const source = isRecord(raw.membership) ? raw.membership : raw;
  const id = String(source.id ?? '').trim();
  const orgId = String(source.orgId ?? '').trim();
  const userId = String(source.userId ?? '').trim();
  const email = String(source.email ?? '').trim();
  const kind = readMembershipKind(source.kind);
  const role = readRole(source.role);
  if (!id || !orgId || !userId || !email || !kind || !role) return null;

  return {
    id,
    orgId,
    userId,
    email,
    displayName: String(source.displayName ?? '').trim() || null,
    kind,
    role,
    adminPermissions: readAdminPermissions(raw.adminPermissions),
    projectAccess: decodeProjectAccess(raw.projectAccess),
    createdAt: String(source.createdAt ?? '').trim(),
    updatedAt: String(source.updatedAt ?? '').trim(),
    suspendedAt: String(source.suspendedAt ?? '').trim() || null,
    removedAt: String(source.removedAt ?? '').trim() || null,
  };
}

function decodeInvitation(raw: unknown): DashboardOrganizationInvitation | null {
  if (!isRecord(raw)) return null;
  const id = String(raw.id ?? '').trim();
  const orgId = String(raw.orgId ?? '').trim();
  const email = String(raw.email ?? '').trim();
  const invitedByUserId = String(raw.invitedByUserId ?? '').trim();
  const kind = readInvitationKind(raw.kind);
  const role = readRole(raw.role);
  if (!id || !orgId || !email || !invitedByUserId || !kind || !role) return null;

  return {
    id,
    orgId,
    email,
    invitedByUserId,
    kind,
    role,
    adminPermissions: readAdminPermissions(raw.adminPermissions),
    projectAccess: decodeProjectAccess(raw.projectAccess),
    createdAt: String(raw.createdAt ?? '').trim(),
    updatedAt: String(raw.updatedAt ?? '').trim(),
    expiresAt: String(raw.expiresAt ?? '').trim() || null,
  };
}

function normalizeGrant(grant: DashboardOrganizationGrant): DashboardOrganizationGrant {
  switch (grant.role) {
    case 'OWNER':
      return { role: grant.role };
    case 'ADMIN':
      return {
        role: grant.role,
        adminPermissions: readAdminPermissions(grant.adminPermissions),
      };
    case 'MEMBER':
      return {
        role: grant.role,
        projectAccess: decodeProjectAccess(grant.projectAccess),
      };
  }
}

async function consoleRequest(input: {
  path: string;
  method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
  body?: unknown;
  operation: string;
}): Promise<ConsoleResponse> {
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}${input.path}`, {
      method: input.method,
      headers:
        input.body === undefined ? buildConsoleAcceptHeaders() : buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: input.path,
      operation: input.operation,
    });
  }

  const body = (await parseConsoleJson(response)) as ConsoleResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, `${input.operation} failed`));
  }
  return body;
}

export async function listDashboardOrganizationMemberships(
  kind: DashboardOrganizationMembershipKind | 'all' = 'all',
): Promise<DashboardOrganizationMembership[]> {
  const query = kind === 'all' ? '' : `?kind=${encodeURIComponent(kind)}`;
  const body = await consoleRequest({
    path: `/console/organization/memberships${query}`,
    method: 'GET',
    operation: 'List organization memberships',
  });
  const rows = Array.isArray(body.memberships) ? body.memberships : [];
  return rows
    .map(decodeMembership)
    .filter((entry): entry is DashboardOrganizationMembership => entry !== null);
}

export async function listDashboardOrganizationInvitations(
  kind: DashboardOrganizationInvitationKind | 'all' = 'all',
): Promise<DashboardOrganizationInvitation[]> {
  const query = kind === 'all' ? '' : `?kind=${encodeURIComponent(kind)}`;
  const body = await consoleRequest({
    path: `/console/organization/invitations${query}`,
    method: 'GET',
    operation: 'List organization invitations',
  });
  const rows = Array.isArray(body.invitations) ? body.invitations : [];
  return rows
    .map(decodeInvitation)
    .filter((entry): entry is DashboardOrganizationInvitation => entry !== null);
}

export async function inviteDashboardOrganizationMember(
  input: { email: string } & DashboardOrganizationGrant,
): Promise<DashboardOrganizationInvitation> {
  const body = await consoleRequest({
    path: '/console/organization/invitations',
    method: 'POST',
    body: {
      email: input.email.trim().toLowerCase(),
      ...normalizeGrant(input),
    },
    operation: 'Invite organization member',
  });
  const invitation = decodeInvitation(body.invitation);
  if (!invitation) throw new Error('Invitation response was invalid');
  return invitation;
}

export async function resendDashboardOrganizationInvitation(
  invitationId: string,
): Promise<DashboardOrganizationInvitation> {
  const body = await consoleRequest({
    path: `/console/organization/invitations/${encodeURIComponent(invitationId)}/resend`,
    method: 'POST',
    body: {},
    operation: 'Resend organization invitation',
  });
  const invitation = decodeInvitation(body.invitation);
  if (!invitation) throw new Error('Resend invitation response was invalid');
  return invitation;
}

export async function revokeDashboardOrganizationInvitation(
  invitationId: string,
): Promise<DashboardOrganizationInvitation> {
  const body = await consoleRequest({
    path: `/console/organization/invitations/${encodeURIComponent(invitationId)}`,
    method: 'DELETE',
    operation: 'Revoke organization invitation',
  });
  const invitation = decodeInvitation(body.invitation);
  if (!invitation) throw new Error('Revoke invitation response was invalid');
  return invitation;
}

export async function changeDashboardOrganizationMembershipRole(
  membershipId: string,
  grant: DashboardOrganizationGrant,
): Promise<DashboardOrganizationMembership> {
  const body = await consoleRequest({
    path: `/console/organization/memberships/${encodeURIComponent(membershipId)}/change-role`,
    method: 'POST',
    body: normalizeGrant(grant),
    operation: 'Change organization membership role',
  });
  const membership = decodeMembership(body.membership);
  if (!membership) throw new Error('Change role response was invalid');
  return membership;
}

export async function setDashboardOrganizationAdminPermissions(
  membershipId: string,
  permissions: DashboardOrganizationAdminPermission[],
): Promise<DashboardOrganizationMembership> {
  const body = await consoleRequest({
    path: `/console/organization/memberships/${encodeURIComponent(membershipId)}/admin-permissions`,
    method: 'PATCH',
    body: { permissions: readAdminPermissions(permissions) },
    operation: 'Update administrator permissions',
  });
  const membership = decodeMembership(body.membership);
  if (!membership) throw new Error('Administrator permission response was invalid');
  return membership;
}

export async function suspendDashboardOrganizationMembership(
  membershipId: string,
): Promise<DashboardOrganizationMembership> {
  const body = await consoleRequest({
    path: `/console/organization/memberships/${encodeURIComponent(membershipId)}/suspend`,
    method: 'POST',
    body: {},
    operation: 'Suspend organization membership',
  });
  const membership = decodeMembership(body.membership);
  if (!membership) throw new Error('Suspend membership response was invalid');
  return membership;
}

export async function reactivateDashboardOrganizationMembership(
  membershipId: string,
): Promise<DashboardOrganizationMembership> {
  const body = await consoleRequest({
    path: `/console/organization/memberships/${encodeURIComponent(membershipId)}/reactivate`,
    method: 'POST',
    body: {},
    operation: 'Reactivate organization membership',
  });
  const membership = decodeMembership(body.membership);
  if (!membership) throw new Error('Reactivate membership response was invalid');
  return membership;
}

export async function removeDashboardOrganizationMembership(
  membershipId: string,
): Promise<DashboardOrganizationMembership> {
  const body = await consoleRequest({
    path: `/console/organization/memberships/${encodeURIComponent(membershipId)}`,
    method: 'DELETE',
    operation: 'Remove organization membership',
  });
  const membership = decodeMembership(body.membership);
  if (!membership) throw new Error('Remove membership response was invalid');
  return membership;
}

export async function setDashboardProjectMemberAccess(input: {
  projectId: string;
  membershipId: string;
  accessLevel: DashboardProjectAccessLevel;
}): Promise<DashboardOrganizationMembership> {
  const body = await consoleRequest({
    path:
      `/console/organization/projects/${encodeURIComponent(input.projectId)}` +
      `/members/${encodeURIComponent(input.membershipId)}`,
    method: 'PUT',
    body: { accessLevel: input.accessLevel },
    operation: 'Set project member access',
  });
  const membership = decodeMembership(body.membership);
  if (!membership) throw new Error('Project access response was invalid');
  return membership;
}

export async function removeDashboardProjectMemberAccess(input: {
  projectId: string;
  membershipId: string;
}): Promise<DashboardOrganizationMembership> {
  const body = await consoleRequest({
    path:
      `/console/organization/projects/${encodeURIComponent(input.projectId)}` +
      `/members/${encodeURIComponent(input.membershipId)}`,
    method: 'DELETE',
    operation: 'Remove project member access',
  });
  const membership = decodeMembership(body.membership);
  if (!membership) throw new Error('Project access removal response was invalid');
  return membership;
}

export async function leaveDashboardOrganization(): Promise<void> {
  await consoleRequest({
    path: '/console/organization/leave',
    method: 'POST',
    body: {},
    operation: 'Leave organization',
  });
}
