export type ConsoleOrganizationStatus = 'ACTIVE';
export type ConsoleProjectStatus = 'ACTIVE' | 'ARCHIVED';
export type ConsoleEnvironmentStatus = 'ACTIVE' | 'DISABLED' | 'ARCHIVED';

export interface ConsoleOrganization {
  id: string;
  name: string;
  slug: string;
  status: ConsoleOrganizationStatus;
  createdAt: string;
  updatedAt: string;
}

export interface ConsoleProject {
  id: string;
  orgId: string;
  name: string;
  slug: string;
  status: ConsoleProjectStatus;
  environmentCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface ConsoleEnvironment {
  id: string;
  orgId: string;
  projectId: string;
  key: 'dev' | 'staging' | 'prod';
  name: string;
  status: ConsoleEnvironmentStatus;
  createdAt: string;
  updatedAt: string;
}

export interface ListConsoleProjectsRequest {
  status?: ConsoleProjectStatus;
}

export interface ListConsoleEnvironmentsRequest {
  projectId?: string;
  status?: ConsoleEnvironmentStatus;
}

export interface SearchConsoleOrganizationsRequest {
  query: string;
  limit?: number;
}

export interface UpsertConsoleOrganizationRequest {
  name?: string;
  slug?: string;
}

export interface CreateConsoleProjectRequest {
  id?: string;
  name: string;
  liveEnvironmentsEnabled?: boolean;
}

export interface UpdateConsoleProjectRequest {
  name?: string;
}

export interface CreateConsoleEnvironmentRequest {
  id?: string;
  projectId: string;
  key: ConsoleEnvironment['key'];
  name?: string;
  status?: Exclude<ConsoleEnvironmentStatus, 'ARCHIVED'>;
}

export interface UpdateConsoleEnvironmentRequest {
  name?: string;
}
