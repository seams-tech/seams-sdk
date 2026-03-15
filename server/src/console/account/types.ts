import type { ConsoleTeamRoleAssignment } from '../teamRbac';

export type ConsoleAccountBackupEmailStatus = 'PENDING' | 'VERIFIED';

export interface ConsoleAccountBackupEmail {
  email: string;
  status: ConsoleAccountBackupEmailStatus;
  createdAt: string;
  updatedAt: string;
}

export interface ConsoleAccountProfile {
  userId: string;
  displayName: string;
  primaryEmail: string;
  canEditPrimaryEmail: boolean;
  backupEmails: ConsoleAccountBackupEmail[];
  createdAt: string;
  updatedAt: string;
}

export interface PatchConsoleAccountProfileRequest {
  displayName?: string;
  primaryEmail?: string;
  addBackupEmail?: string;
  removeBackupEmail?: string;
}

export interface ConsoleAccountOrganizationAdminCandidate {
  memberId: string;
  userId: string;
  email: string;
  displayName: string;
  isOwner: boolean;
  roles: ConsoleTeamRoleAssignment[];
}

export interface ConsoleAccountOrganization {
  id: string;
  name: string;
  slug: string;
  status: string;
  createdAt: string;
  updatedAt: string;
  isCurrentOrg: boolean;
  actorRoles: string[];
  actorIsOwner: boolean;
  actorIsAdmin: boolean;
  onboardingComplete: boolean;
  selectedProjectId: string | null;
  selectedProjectName: string | null;
  selectedEnvironmentId: string | null;
  selectedEnvironmentName: string | null;
  adminCandidates: ConsoleAccountOrganizationAdminCandidate[];
}

export interface CreateConsoleAccountOrganizationRequest {
  id?: string;
  name: string;
  slug?: string;
}

export interface UpdateConsoleAccountOrganizationRequest {
  name?: string;
  slug?: string;
}

export interface TransferConsoleAccountOrganizationOwnerRequest {
  targetMemberId?: string;
  targetUserId?: string;
}

export interface TransferConsoleAccountOrganizationOwnerResult {
  organization: ConsoleAccountOrganization;
  previousOwner: ConsoleAccountOrganizationAdminCandidate;
  nextOwner: ConsoleAccountOrganizationAdminCandidate;
}

export interface DeleteConsoleAccountOrganizationResult {
  orgId: string;
  organizationName: string;
}

export interface SwitchConsoleAccountOrganizationContextResult {
  orgId: string;
  projectId: string | null;
  environmentId: string | null;
  actorRoles: string[];
  onboardingComplete: boolean;
}
