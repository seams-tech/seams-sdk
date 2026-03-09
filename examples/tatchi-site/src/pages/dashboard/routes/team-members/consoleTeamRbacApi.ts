import {
  buildConsoleAcceptHeaders,
  buildConsoleJsonHeaders,
  consoleErrorMessage,
  normalizeConsoleFetchError,
  parseConsoleJson,
  requireConsoleBaseUrl,
} from '../../consoleHttp';

export type DashboardConsoleTeamPermissionCategory =
  | 'overview'
  | 'administration'
  | 'wallet_operations'
  | 'integrations'
  | 'billing';

export type DashboardConsoleTeamRole =
  | 'owner'
  | 'admin'
  | 'admin_manage_admins'
  | 'admin_manage_members'
  | 'overview_read'
  | 'overview_write'
  | 'administration_read'
  | 'administration_write'
  | 'wallet_operations_read'
  | 'wallet_operations_write'
  | 'integrations_read'
  | 'integrations_write'
  | 'billing_read'
  | 'billing_write';

export type DashboardConsoleTeamRoleScope = 'ORG';
export type DashboardConsoleTeamMembershipStatus = 'INVITED' | 'ACTIVE' | 'SUSPENDED' | 'REMOVED';

export interface DashboardConsoleTeamRoleAssignment {
  role: DashboardConsoleTeamRole;
  scope: DashboardConsoleTeamRoleScope;
}

export interface DashboardConsoleTeamMember {
  id: string;
  orgId: string;
  userId: string;
  email: string;
  displayName?: string;
  status: DashboardConsoleTeamMembershipStatus;
  roles: DashboardConsoleTeamRoleAssignment[];
  invitedByUserId: string;
  invitedAt: string;
  createdAt: string;
  updatedAt: string;
  lastStatusChangedAt: string;
}

interface ConsoleTeamMembersResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  members?: unknown;
}

interface ConsoleTeamMemberMutationResponse {
  ok?: boolean;
  code?: string;
  message?: string;
  member?: unknown;
  removed?: unknown;
}

const ORG_ROLE_SET = new Set<string>([
  'owner',
  'admin',
  'admin_manage_admins',
  'admin_manage_members',
  'overview_read',
  'overview_write',
  'administration_read',
  'administration_write',
  'wallet_operations_read',
  'wallet_operations_write',
  'integrations_read',
  'integrations_write',
  'billing_read',
  'billing_write',
]);
const STATUS_SET = new Set<DashboardConsoleTeamMembershipStatus>([
  'INVITED',
  'ACTIVE',
  'SUSPENDED',
  'REMOVED',
]);

function readRole(raw: unknown): DashboardConsoleTeamRole | null {
  const role = String(raw || '')
    .trim()
    .toLowerCase();
  if (ORG_ROLE_SET.has(role)) {
    return role as DashboardConsoleTeamRole;
  }
  return null;
}

function readRoleAssignments(raw: unknown): DashboardConsoleTeamRoleAssignment[] {
  if (!Array.isArray(raw)) return [];
  const out: DashboardConsoleTeamRoleAssignment[] = [];
  const seen = new Set<string>();
  for (const entryRaw of raw) {
    if (!entryRaw || typeof entryRaw !== 'object' || Array.isArray(entryRaw)) continue;
    const row = entryRaw as Record<string, unknown>;
    const role = readRole(row.role);
    if (!role) continue;
    const scopeRaw = String(row.scope || '')
      .trim()
      .toUpperCase();
    if (scopeRaw && scopeRaw !== 'ORG') continue;
    const dedupeKey = `ORG:${role}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({
      role,
      scope: 'ORG',
    });
  }
  return out;
}

function decodeMember(raw: unknown): DashboardConsoleTeamMember | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const row = raw as Record<string, unknown>;
  const id = String(row.id || '').trim();
  const userId = String(row.userId || row.id || '').trim();
  const orgId = String(row.orgId || '').trim();
  const email = String(row.email || '').trim();
  const statusRaw = String(row.status || '')
    .trim()
    .toUpperCase();
  if (
    !id ||
    !userId ||
    !orgId ||
    !email ||
    !STATUS_SET.has(statusRaw as DashboardConsoleTeamMembershipStatus)
  ) {
    return null;
  }
  return {
    id,
    orgId,
    userId,
    email,
    ...(row.displayName ? { displayName: String(row.displayName || '').trim() } : {}),
    status: statusRaw as DashboardConsoleTeamMembershipStatus,
    roles: readRoleAssignments(row.roles),
    invitedByUserId: String(row.invitedByUserId || '').trim(),
    invitedAt: String(row.invitedAt || '').trim(),
    createdAt: String(row.createdAt || '').trim(),
    updatedAt: String(row.updatedAt || '').trim(),
    lastStatusChangedAt: String(row.lastStatusChangedAt || '').trim(),
  };
}

function encodeRoleAssignments(
  input: DashboardConsoleTeamRoleAssignment[],
): DashboardConsoleTeamRoleAssignment[] {
  const out: DashboardConsoleTeamRoleAssignment[] = [];
  const seen = new Set<string>();
  for (const entry of input) {
    const role = readRole(entry.role);
    if (!role) continue;
    const dedupeKey = `ORG:${role}`;
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    out.push({
      role,
      scope: 'ORG',
    });
  }
  return out.sort((a, b) => a.role.localeCompare(b.role));
}

export async function listDashboardTeamMembers(input?: {
  status?: DashboardConsoleTeamMembershipStatus;
}): Promise<DashboardConsoleTeamMember[]> {
  const base = requireConsoleBaseUrl();
  const url = new URL('/console/members', base);
  const status = String(input?.status || '')
    .trim()
    .toUpperCase();
  if (status && status !== 'ALL') {
    url.searchParams.set('status', status);
  }
  let response: Response;
  try {
    response = await fetch(url.toString(), {
      method: 'GET',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/members',
      operation: 'Console team members request',
    });
  }
  const body = (await parseConsoleJson(response)) as ConsoleTeamMembersResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Console team members request failed'));
  }
  const rows = Array.isArray(body?.members) ? body.members : [];
  return rows
    .map((entry) => decodeMember(entry))
    .filter((entry): entry is DashboardConsoleTeamMember => entry !== null);
}

export async function inviteDashboardTeamMember(input: {
  userId: string;
  email: string;
  displayName?: string;
  roles: DashboardConsoleTeamRoleAssignment[];
}): Promise<DashboardConsoleTeamMember> {
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}/console/members/invite`, {
      method: 'POST',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({
        userId: input.userId,
        ...(input.displayName ? { displayName: input.displayName } : {}),
        email: input.email,
        roles: encodeRoleAssignments(input.roles),
      }),
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: '/console/members/invite',
      operation: 'Invite member request',
    });
  }
  const body = (await parseConsoleJson(response)) as ConsoleTeamMemberMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Invite member request failed'));
  }
  const member = decodeMember(body?.member);
  if (!member) {
    throw new Error('Invite member response was missing member payload');
  }
  return member;
}

export async function updateDashboardTeamMemberRoles(input: {
  memberId: string;
  roles: DashboardConsoleTeamRoleAssignment[];
}): Promise<DashboardConsoleTeamMember> {
  const memberId = String(input.memberId || '').trim();
  if (!memberId) throw new Error('Member ID is required');
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}/console/members/${encodeURIComponent(memberId)}/roles`, {
      method: 'PATCH',
      headers: buildConsoleJsonHeaders(),
      credentials: 'include',
      cache: 'no-store',
      body: JSON.stringify({
        roles: encodeRoleAssignments(input.roles),
      }),
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: `/console/members/${encodeURIComponent(memberId)}/roles`,
      operation: 'Update member roles request',
    });
  }
  const body = (await parseConsoleJson(response)) as ConsoleTeamMemberMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Update member roles request failed'));
  }
  const member = decodeMember(body?.member);
  if (!member) {
    throw new Error('Update member roles response was missing member payload');
  }
  return member;
}

export async function removeDashboardTeamMember(input: {
  memberId: string;
}): Promise<{ removed: boolean; member: DashboardConsoleTeamMember | null }> {
  const memberId = String(input.memberId || '').trim();
  if (!memberId) throw new Error('Member ID is required');
  const base = requireConsoleBaseUrl();
  let response: Response;
  try {
    response = await fetch(`${base}/console/members/${encodeURIComponent(memberId)}`, {
      method: 'DELETE',
      headers: buildConsoleAcceptHeaders(),
      credentials: 'include',
      cache: 'no-store',
    });
  } catch (error: unknown) {
    throw normalizeConsoleFetchError({
      error,
      baseUrl: base,
      path: `/console/members/${encodeURIComponent(memberId)}`,
      operation: 'Remove member request',
    });
  }
  const body = (await parseConsoleJson(response)) as ConsoleTeamMemberMutationResponse | null;
  if (!response.ok || body?.ok !== true) {
    throw new Error(consoleErrorMessage(response, body, 'Remove member request failed'));
  }
  return {
    removed: body?.removed === true,
    member: decodeMember(body?.member),
  };
}
