import type { ActiveOrganizationAuthorization } from '../teamRbac';

export type ConsoleAccountBackupEmailStatus = 'PENDING' | 'VERIFIED';

export interface ConsoleAccountBackupEmail {
  readonly email: string;
  readonly status: ConsoleAccountBackupEmailStatus;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface ConsoleAccountProfile {
  readonly userId: string;
  readonly displayName: string;
  readonly primaryEmail: string;
  readonly canEditPrimaryEmail: boolean;
  readonly backupEmails: readonly ConsoleAccountBackupEmail[];
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface PatchConsoleAccountProfileRequest {
  readonly displayName?: string;
  readonly primaryEmail?: string;
  readonly addBackupEmail?: string;
  readonly removeBackupEmail?: string;
}

type AccountAccessFromAuthorization<T extends ActiveOrganizationAuthorization> =
  T extends ActiveOrganizationAuthorization
    ? Omit<T, 'kind' | 'orgId' | 'userId'>
    : never;

export type ConsoleAccountOrganizationAccess =
  AccountAccessFromAuthorization<ActiveOrganizationAuthorization>;

interface ConsoleAccountOrganizationIdentity {
  readonly id: string;
  readonly name: string;
  readonly slug: string;
  readonly status: string;
  readonly createdAt: string;
  readonly updatedAt: string;
  readonly isCurrentOrg: boolean;
  readonly onboardingComplete: boolean;
  readonly selectedProjectId: string | null;
  readonly selectedProjectName: string | null;
  readonly selectedEnvironmentId: string | null;
  readonly selectedEnvironmentName: string | null;
}

export type ConsoleAccountOrganization =
  ConsoleAccountOrganizationIdentity & ConsoleAccountOrganizationAccess;

export interface CreateConsoleAccountOrganizationRequest {
  readonly id?: string;
  readonly name: string;
  readonly slug?: string;
}

export interface UpdateConsoleAccountOrganizationRequest {
  readonly name?: string;
  readonly slug?: string;
}

export interface DeleteConsoleAccountOrganizationResult {
  readonly orgId: string;
  readonly organizationName: string;
}

interface SwitchedOrganizationScope {
  readonly orgId: string;
  readonly projectId: string | null;
  readonly environmentId: string | null;
  readonly onboardingComplete: boolean;
  readonly platformSupport: boolean;
}

export type SwitchConsoleAccountOrganizationContextResult =
  SwitchedOrganizationScope & ConsoleAccountOrganizationAccess;
