import {
  readOptionalQueryStringField,
  readRequiredStringField,
  requireBodyObject,
  requireQueryObject,
} from '../shared/requestParse';
import { ConsoleOrganizationAccessError } from './errors';
import {
  ORGANIZATION_ADMIN_PERMISSIONS,
  ORGANIZATION_INVITATION_KINDS,
  ORGANIZATION_MEMBERSHIP_KINDS,
  type ChangeOrganizationMembershipRoleRequest,
  type InviteOrganizationMemberRequest,
  type ListOrganizationInvitationsRequest,
  type ListOrganizationMembershipsRequest,
  type OrganizationAdminPermission,
  type OrganizationInvitationGrant,
  type ProjectAccessAssignment,
  type ProjectAccessLevel,
  type RedeemOrganizationInvitationRequest,
  type SetOrganizationAdminPermissionsRequest,
  type SetProjectMemberAccessRequest,
} from './types';

function requestError(
  code: string,
  status: number,
  message: string,
): ConsoleOrganizationAccessError {
  return new ConsoleOrganizationAccessError(code, status, message);
}

function invalidBody(message: string): never {
  throw requestError('invalid_body', 400, message);
}

function normalizeEmail(raw: string): string {
  const email = raw.trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/u.test(email)) {
    invalidBody('Field email must be a valid email address');
  }
  return email;
}

function parseMembershipRole(raw: unknown): 'OWNER' | 'ADMIN' | 'MEMBER' {
  const role = String(raw ?? '')
    .trim()
    .toUpperCase();
  switch (role) {
    case 'OWNER':
    case 'ADMIN':
    case 'MEMBER':
      return role;
    default:
      return invalidBody('Field role must be OWNER, ADMIN, or MEMBER');
  }
}

function parseAdminPermission(raw: unknown): OrganizationAdminPermission {
  const permission = String(raw ?? '')
    .trim()
    .toLowerCase();
  switch (permission) {
    case 'members.manage':
    case 'projects.manage':
    case 'billing.view':
    case 'billing.manage':
      return permission;
    default:
      return invalidBody(`Unsupported administrator permission: ${permission || 'empty'}`);
  }
}

function sortAdminPermissions(
  permissions: ReadonlySet<OrganizationAdminPermission>,
): readonly OrganizationAdminPermission[] {
  return ORGANIZATION_ADMIN_PERMISSIONS.filter((permission) => permissions.has(permission));
}

function parseAdminPermissions(raw: unknown): readonly OrganizationAdminPermission[] {
  if (!Array.isArray(raw)) {
    return invalidBody('Field adminPermissions must be an array');
  }
  const permissions = new Set<OrganizationAdminPermission>();
  for (const entry of raw) {
    permissions.add(parseAdminPermission(entry));
  }
  if (permissions.has('billing.manage')) {
    permissions.add('billing.view');
  }
  return sortAdminPermissions(permissions);
}

function parseProjectAccessLevel(raw: unknown): ProjectAccessLevel {
  const accessLevel = String(raw ?? '')
    .trim()
    .toLowerCase();
  switch (accessLevel) {
    case 'viewer':
    case 'editor':
      return accessLevel;
    default:
      return invalidBody('Field accessLevel must be viewer or editor');
  }
}

function parseProjectAccessEntry(raw: unknown): ProjectAccessAssignment {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return invalidBody('Each projectAccess entry must be an object');
  }
  const entry = raw as Record<string, unknown>;
  return {
    projectId: readRequiredStringField(entry, 'projectId', requestError),
    accessLevel: parseProjectAccessLevel(entry.accessLevel),
  };
}

function parseProjectAccess(raw: unknown): readonly ProjectAccessAssignment[] {
  if (!Array.isArray(raw)) {
    return invalidBody('Field projectAccess must be an array');
  }
  const assignments = new Map<string, ProjectAccessAssignment>();
  for (const entry of raw) {
    const assignment = parseProjectAccessEntry(entry);
    if (assignments.has(assignment.projectId)) {
      return invalidBody(`Project ${assignment.projectId} appears more than once`);
    }
    assignments.set(assignment.projectId, assignment);
  }
  return Array.from(assignments.values()).sort((left, right) =>
    left.projectId.localeCompare(right.projectId),
  );
}

function rejectPresentField(source: Record<string, unknown>, key: string, role: string): void {
  if (source[key] !== undefined && source[key] !== null) {
    invalidBody(`Field ${key} is not valid for role ${role}`);
  }
}

function parseInvitationGrant(source: Record<string, unknown>): OrganizationInvitationGrant {
  const role = parseMembershipRole(source.role);
  switch (role) {
    case 'OWNER':
      rejectPresentField(source, 'adminPermissions', role);
      rejectPresentField(source, 'projectAccess', role);
      return { role };
    case 'ADMIN':
      rejectPresentField(source, 'projectAccess', role);
      return {
        role,
        adminPermissions: parseAdminPermissions(source.adminPermissions),
      };
    case 'MEMBER':
      rejectPresentField(source, 'adminPermissions', role);
      return {
        role,
        projectAccess: parseProjectAccess(source.projectAccess),
      };
  }
}

export function parseListOrganizationMembershipsRequest(
  query: unknown,
): ListOrganizationMembershipsRequest {
  const input = requireQueryObject(query, requestError);
  const rawKind = readOptionalQueryStringField(input, 'kind');
  if (!rawKind || rawKind.toLowerCase() === 'all') return { kind: 'all' };
  const kind = rawKind.toLowerCase();
  for (const supported of ORGANIZATION_MEMBERSHIP_KINDS) {
    if (kind === supported) return { kind: supported };
  }
  throw requestError(
    'invalid_query',
    400,
    `Query parameter kind must be one of: all, ${ORGANIZATION_MEMBERSHIP_KINDS.join(', ')}`,
  );
}

export function parseListOrganizationInvitationsRequest(
  query: unknown,
): ListOrganizationInvitationsRequest {
  const input = requireQueryObject(query, requestError);
  const rawKind = readOptionalQueryStringField(input, 'kind');
  if (!rawKind || rawKind.toLowerCase() === 'all') return { kind: 'all' };
  const kind = rawKind.toLowerCase();
  for (const supported of ORGANIZATION_INVITATION_KINDS) {
    if (kind === supported) return { kind: supported };
  }
  throw requestError(
    'invalid_query',
    400,
    `Query parameter kind must be one of: all, ${ORGANIZATION_INVITATION_KINDS.join(', ')}`,
  );
}

export function parseInviteOrganizationMemberRequest(
  body: unknown,
): InviteOrganizationMemberRequest {
  const input = requireBodyObject(body, requestError);
  const email = normalizeEmail(readRequiredStringField(input, 'email', requestError));
  const grant = parseInvitationGrant(input);
  switch (grant.role) {
    case 'OWNER':
      return { email, role: grant.role };
    case 'ADMIN':
      return {
        email,
        role: grant.role,
        adminPermissions: grant.adminPermissions,
      };
    case 'MEMBER':
      return {
        email,
        role: grant.role,
        projectAccess: grant.projectAccess,
      };
  }
}

export function parseChangeOrganizationMembershipRoleRequest(
  body: unknown,
): ChangeOrganizationMembershipRoleRequest {
  return parseInvitationGrant(requireBodyObject(body, requestError));
}

export function parseSetOrganizationAdminPermissionsRequest(
  body: unknown,
): SetOrganizationAdminPermissionsRequest {
  const input = requireBodyObject(body, requestError);
  return { permissions: parseAdminPermissions(input.permissions) };
}

export function parseSetProjectMemberAccessRequest(body: unknown): SetProjectMemberAccessRequest {
  const input = requireBodyObject(body, requestError);
  return { accessLevel: parseProjectAccessLevel(input.accessLevel) };
}

export function parseRedeemOrganizationInvitationRequest(
  body: unknown,
): RedeemOrganizationInvitationRequest {
  const input = requireBodyObject(body, requestError);
  return {
    token: readRequiredStringField(input, 'token', requestError),
  };
}
