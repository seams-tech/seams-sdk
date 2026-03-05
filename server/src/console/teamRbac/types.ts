export const CONSOLE_TEAM_PERMISSION_CATEGORIES = [
  'overview',
  'administration',
  'wallet_operations',
  'integrations',
  'billing',
] as const;

export const CONSOLE_ORG_SCOPED_TEAM_ROLES = [
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
] as const;

export type ConsoleTeamPermissionCategory = (typeof CONSOLE_TEAM_PERMISSION_CATEGORIES)[number];
export type ConsoleOrgScopedTeamRole = (typeof CONSOLE_ORG_SCOPED_TEAM_ROLES)[number];
export type ConsoleTeamRole = ConsoleOrgScopedTeamRole;

export type ConsoleTeamRoleScope = 'ORG';
export type ConsoleTeamMembershipStatus = 'INVITED' | 'ACTIVE' | 'SUSPENDED' | 'REMOVED';
export type ConsoleTeamMemberListStatusFilter = ConsoleTeamMembershipStatus | 'ALL';

export interface ConsoleTeamRoleAssignment {
  role: ConsoleTeamRole;
  scope: ConsoleTeamRoleScope;
}

export interface ConsoleTeamMember {
  id: string;
  orgId: string;
  userId: string;
  email: string;
  displayName?: string;
  status: ConsoleTeamMembershipStatus;
  roles: ConsoleTeamRoleAssignment[];
  invitedByUserId: string;
  invitedAt: string;
  createdAt: string;
  updatedAt: string;
  lastStatusChangedAt: string;
}

export interface ListConsoleTeamMembersRequest {
  status?: ConsoleTeamMemberListStatusFilter;
}

export interface InviteConsoleTeamMemberRequest {
  userId: string;
  email: string;
  displayName?: string;
  roles: ConsoleTeamRoleAssignment[];
}

export interface UpdateConsoleTeamMemberRolesRequest {
  roles: ConsoleTeamRoleAssignment[];
}
