export const ALL_PROJECTS_SCOPE = '__all_projects__';

export interface ContextProjectLike {
  id: string;
  status?: string;
}

export interface ListProjectsRequest {
  status?: 'ACTIVE';
}

export interface ListEnvironmentsRequest {
  projectId?: string;
  status?: 'ACTIVE' | 'ARCHIVED';
}

interface BuildEnvironmentsListRequestInput {
  requestedScopeProjectId: string;
  selectedProjectId: string;
  projects: ContextProjectLike[];
  showArchivedEnvironments: boolean;
}

function isArchivedStatus(value: string | undefined): boolean {
  return String(value || '')
    .trim()
    .toUpperCase() === 'ARCHIVED';
}

function projectExists(projects: ContextProjectLike[], projectId: string): boolean {
  return projects.some((entry) => entry.id === projectId);
}

export function filterActiveProjects<T extends ContextProjectLike>(projects: T[]): T[] {
  return projects.filter((entry) => !isArchivedStatus(entry.status));
}

export function buildProjectsListRequest(showArchivedProjects: boolean): ListProjectsRequest {
  if (showArchivedProjects) return {};
  return { status: 'ACTIVE' };
}

export function buildEnvironmentsListRequest(
  input: BuildEnvironmentsListRequestInput,
): {
  resolvedScopeProjectId: string;
  request: ListEnvironmentsRequest;
} {
  const requestedScopeProjectId = String(input.requestedScopeProjectId || '').trim();
  const selectedProjectId = String(input.selectedProjectId || '').trim();

  const resolvedScopeProjectId =
    requestedScopeProjectId === ALL_PROJECTS_SCOPE ||
    projectExists(input.projects, requestedScopeProjectId)
      ? requestedScopeProjectId
      : selectedProjectId && projectExists(input.projects, selectedProjectId)
        ? selectedProjectId
        : (input.projects[0]?.id || '');

  const request: ListEnvironmentsRequest = {};
  if (resolvedScopeProjectId && resolvedScopeProjectId !== ALL_PROJECTS_SCOPE) {
    request.projectId = resolvedScopeProjectId;
  }
  if (!input.showArchivedEnvironments) {
    request.status = 'ACTIVE';
  }

  return {
    resolvedScopeProjectId,
    request,
  };
}

interface ResolveCreateEnvironmentProjectIdInput {
  currentProjectId: string;
  selectedProjectId: string;
  activeProjects: ContextProjectLike[];
}

export function resolveCreateEnvironmentProjectId(
  input: ResolveCreateEnvironmentProjectIdInput,
): string {
  const currentProjectId = String(input.currentProjectId || '').trim();
  if (currentProjectId && projectExists(input.activeProjects, currentProjectId)) {
    return currentProjectId;
  }
  const selectedProjectId = String(input.selectedProjectId || '').trim();
  if (selectedProjectId && projectExists(input.activeProjects, selectedProjectId)) {
    return selectedProjectId;
  }
  return input.activeProjects[0]?.id || '';
}

export function canCreateEnvironmentInProject(
  projectId: string,
  activeProjects: ContextProjectLike[],
): boolean {
  const normalizedProjectId = String(projectId || '').trim();
  if (!normalizedProjectId) return false;
  return projectExists(activeProjects, normalizedProjectId);
}
