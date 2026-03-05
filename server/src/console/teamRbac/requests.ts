import {
  readOptionalQueryStringField as readOptionalQueryString,
  readOptionalStringField as readOptionalString,
  readRequiredStringField as readRequiredString,
  requireBodyObject as requireObject,
  requireQueryObject,
} from '../shared/requestParse';
import { ConsoleTeamRbacError } from './errors';
import {
  CONSOLE_ORG_SCOPED_TEAM_ROLES,
  type ConsoleTeamMemberListStatusFilter,
  type ConsoleTeamRole,
  type ConsoleTeamRoleAssignment,
  type InviteConsoleTeamMemberRequest,
  type ListConsoleTeamMembersRequest,
  type UpdateConsoleTeamMemberRolesRequest,
} from './types';

const ORG_ROLE_SET = new Set<string>(CONSOLE_ORG_SCOPED_TEAM_ROLES);
const MEMBER_STATUS_SET = new Set<ConsoleTeamMemberListStatusFilter>([
  'ALL',
  'INVITED',
  'ACTIVE',
  'SUSPENDED',
  'REMOVED',
]);

function normalizeRoleOrThrow(raw: unknown): ConsoleTeamRole {
  const role = String(raw || '')
    .trim()
    .toLowerCase();
  if (ORG_ROLE_SET.has(role)) {
    return role as ConsoleTeamRole;
  }
  throw new ConsoleTeamRbacError('invalid_body', 400, `Unsupported role: ${role || 'unknown'}`);
}

function parseRoleAssignmentsOrThrow(raw: unknown): ConsoleTeamRoleAssignment[] {
  if (!Array.isArray(raw) || raw.length === 0) {
    throw new ConsoleTeamRbacError(
      'invalid_body',
      400,
      'Field roles must be a non-empty array of role assignments',
    );
  }

  const out: ConsoleTeamRoleAssignment[] = [];
  const seen = new Set<string>();
  for (const entryRaw of raw) {
    if (!entryRaw || typeof entryRaw !== 'object' || Array.isArray(entryRaw)) {
      throw new ConsoleTeamRbacError('invalid_body', 400, 'Each role assignment must be an object');
    }
    const entry = entryRaw as Record<string, unknown>;
    const role = normalizeRoleOrThrow(entry.role);
    const scopeRaw = readOptionalString(entry, 'scope');
    if (scopeRaw) {
      const normalizedScope = scopeRaw.toUpperCase();
      if (normalizedScope !== 'ORG') {
        throw new ConsoleTeamRbacError('invalid_body', 400, `Role ${role} must use ORG scope`);
      }
    }

    const projectId = readOptionalString(entry, 'projectId');
    if (projectId) {
      throw new ConsoleTeamRbacError('invalid_body', 400, `Role ${role} cannot include projectId`);
    }

    const dedupeKey = `ORG:${role}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({
      role,
      scope: 'ORG',
    });
  }

  if (out.length === 0) {
    throw new ConsoleTeamRbacError(
      'invalid_body',
      400,
      'Field roles must include at least one unique role assignment',
    );
  }
  return out;
}

export function parseListConsoleTeamMembersRequest(query: unknown): ListConsoleTeamMembersRequest {
  const input = requireQueryObject(
    query,
    (code, status, message) => new ConsoleTeamRbacError(code, status, message),
  );
  const statusRaw = readOptionalQueryString(input, 'status');
  if (!statusRaw) return {};
  const status = statusRaw.toUpperCase() as ConsoleTeamMemberListStatusFilter;
  if (!MEMBER_STATUS_SET.has(status)) {
    throw new ConsoleTeamRbacError(
      'invalid_query',
      400,
      `Query parameter status must be one of: ${Array.from(MEMBER_STATUS_SET).join(', ')}`,
    );
  }
  return status === 'ALL' ? {} : { status };
}

export function parseInviteConsoleTeamMemberRequest(body: unknown): InviteConsoleTeamMemberRequest {
  const obj = requireObject(
    body,
    (code, status, message) => new ConsoleTeamRbacError(code, status, message),
  );
  const userId = readRequiredString(
    obj,
    'userId',
    (code, status, message) => new ConsoleTeamRbacError(code, status, message),
  );
  const email = readRequiredString(
    obj,
    'email',
    (code, status, message) => new ConsoleTeamRbacError(code, status, message),
  );
  const roles = parseRoleAssignmentsOrThrow(obj.roles);
  const displayName = readOptionalString(obj, 'displayName');
  return {
    userId,
    ...(displayName ? { displayName } : {}),
    email,
    roles,
  };
}

export function parseUpdateConsoleTeamMemberRolesRequest(
  body: unknown,
): UpdateConsoleTeamMemberRolesRequest {
  const obj = requireObject(
    body,
    (code, status, message) => new ConsoleTeamRbacError(code, status, message),
  );
  return {
    roles: parseRoleAssignmentsOrThrow(obj.roles),
  };
}
