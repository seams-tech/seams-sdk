import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import {
  archiveDashboardEnvironment,
  archiveDashboardProject,
  createDashboardEnvironment,
  createDashboardProject,
  getDashboardOrganization,
  listDashboardEnvironments,
  listDashboardProjects,
  updateDashboardEnvironment,
  updateDashboardProject,
  type DashboardConsoleEnvironment,
  type DashboardConsoleOrganization,
  type DashboardConsoleProject,
} from '../../consoleContextApi';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  ALL_PROJECTS_SCOPE,
  buildEnvironmentsListRequest,
  buildProjectsListRequest,
  canCreateEnvironmentInProject,
  filterActiveProjects,
  resolveCreateEnvironmentProjectId,
} from './contextHierarchyModel';

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

export function AppSettingsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [mutating, setMutating] = React.useState<boolean>(false);
  const [organization, setOrganization] = React.useState<DashboardConsoleOrganization | null>(null);
  const [projects, setProjects] = React.useState<DashboardConsoleProject[]>([]);
  const [environments, setEnvironments] = React.useState<DashboardConsoleEnvironment[]>([]);
  const [showArchivedProjects, setShowArchivedProjects] = React.useState<boolean>(false);
  const [createProjectId, setCreateProjectId] = React.useState<string>('');
  const [createProjectName, setCreateProjectName] = React.useState<string>('');
  const [projectActionId, setProjectActionId] = React.useState<string>('');
  const [projectRenameName, setProjectRenameName] = React.useState<string>('');
  const [createEnvironmentId, setCreateEnvironmentId] = React.useState<string>('');
  const [createEnvironmentProjectId, setCreateEnvironmentProjectId] = React.useState<string>('');
  const [createEnvironmentKey, setCreateEnvironmentKey] = React.useState<'dev' | 'staging' | 'prod'>(
    'dev',
  );
  const [createEnvironmentName, setCreateEnvironmentName] = React.useState<string>('');
  const [environmentScopeProjectId, setEnvironmentScopeProjectId] = React.useState<string>('');
  const [showArchivedEnvironments, setShowArchivedEnvironments] = React.useState<boolean>(false);
  const [environmentActionId, setEnvironmentActionId] = React.useState<string>('');
  const [environmentRenameName, setEnvironmentRenameName] = React.useState<string>('');

  const canMutateContext = React.useMemo(
    () =>
      Array.isArray(session.claims?.roles) &&
      session.claims.roles.some((role) => {
        const normalized = String(role || '').toLowerCase();
        return normalized === 'admin' || normalized === 'owner';
      }),
    [session.claims?.roles],
  );

  const activeProjects = React.useMemo(
    () => filterActiveProjects(projects),
    [projects],
  );

  const loadContextData = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setOrganization(null);
      setProjects([]);
      setEnvironments([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    Promise.all([
      getDashboardOrganization(),
      listDashboardProjects(buildProjectsListRequest(showArchivedProjects)),
    ])
      .then(async ([nextOrg, nextProjects]) => {
        const sortedProjects = [...nextProjects].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        const selectedProjectId = String(selectedContext.project || '').trim();
        const { resolvedScopeProjectId, request: environmentRequest } =
          buildEnvironmentsListRequest({
            requestedScopeProjectId: environmentScopeProjectId,
            selectedProjectId,
            projects: sortedProjects,
            showArchivedEnvironments,
          });
        const nextEnvironments = await listDashboardEnvironments(environmentRequest);
        if (cancelled) return;
        const sortedEnvironments = [...nextEnvironments].sort((a, b) =>
          b.createdAt.localeCompare(a.createdAt),
        );
        setOrganization(nextOrg);
        setProjects(sortedProjects);
        setEnvironmentScopeProjectId(resolvedScopeProjectId);
        setEnvironments(sortedEnvironments);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setOrganization(null);
        setProjects([]);
        setEnvironments([]);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [
    environmentScopeProjectId,
    selectedContext.project,
    session.claims,
    session.errorMessage,
    showArchivedProjects,
    showArchivedEnvironments,
  ]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadContextData();
    return cleanup;
  }, [loadContextData, session.loading]);

  React.useEffect(() => {
    if (projects.length === 0) {
      setProjectActionId('');
      setCreateEnvironmentProjectId('');
      setEnvironmentScopeProjectId('');
      return;
    }
    const selectedProject = String(selectedContext.project || '').trim();
    if (!projectActionId || !projects.some((entry) => entry.id === projectActionId)) {
      setProjectActionId(
        projects.some((entry) => entry.id === selectedProject)
          ? selectedProject
          : (projects[0]?.id || ''),
      );
    }
    if (
      !createEnvironmentProjectId ||
      !activeProjects.some((entry) => entry.id === createEnvironmentProjectId)
    ) {
      setCreateEnvironmentProjectId(
        resolveCreateEnvironmentProjectId({
          currentProjectId: createEnvironmentProjectId,
          selectedProjectId: selectedProject,
          activeProjects,
        }),
      );
    }
    if (
      !environmentScopeProjectId ||
      (environmentScopeProjectId !== ALL_PROJECTS_SCOPE &&
        !projects.some((entry) => entry.id === environmentScopeProjectId))
    ) {
      setEnvironmentScopeProjectId(
        projects.some((entry) => entry.id === selectedProject)
          ? selectedProject
          : (projects[0]?.id || ''),
      );
    }
  }, [
    activeProjects,
    createEnvironmentProjectId,
    environmentScopeProjectId,
    projectActionId,
    projects,
    selectedContext.project,
  ]);

  const scopedEnvironments = React.useMemo(() => {
    const scopeProjectId = String(environmentScopeProjectId || '').trim();
    if (!scopeProjectId || scopeProjectId === ALL_PROJECTS_SCOPE) return environments;
    return environments.filter((environment) => environment.projectId === scopeProjectId);
  }, [environmentScopeProjectId, environments]);

  const selectedEnvironmentForAction = React.useMemo(
    () => scopedEnvironments.find((entry) => entry.id === environmentActionId) || null,
    [environmentActionId, scopedEnvironments],
  );

  const selectedProjectForAction = React.useMemo(
    () => projects.find((entry) => entry.id === projectActionId) || null,
    [projectActionId, projects],
  );

  React.useEffect(() => {
    if (scopedEnvironments.length === 0) {
      setEnvironmentActionId('');
      return;
    }
    const selectedEnvironment = String(selectedContext.environment || '').trim();
    if (!environmentActionId || !scopedEnvironments.some((entry) => entry.id === environmentActionId)) {
      setEnvironmentActionId(
        scopedEnvironments.some((entry) => entry.id === selectedEnvironment)
          ? selectedEnvironment
          : (scopedEnvironments[0]?.id || ''),
      );
    }
  }, [environmentActionId, scopedEnvironments, selectedContext.environment]);

  const projectNameById = React.useMemo(() => {
    const map = new Map<string, string>();
    projects.forEach((project) => {
      map.set(project.id, project.name || project.id);
    });
    return map;
  }, [projects]);

  const onCreateProject = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateContext) {
        setMutationError('Only owner/admin roles can create projects.');
        return;
      }
      const name = String(createProjectName || '').trim();
      const id = String(createProjectId || '').trim();
      if (!name) {
        setMutationError('Project name is required.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        await createDashboardProject({
          name,
          ...(id ? { id } : {}),
        });
        setCreateProjectId('');
        setCreateProjectName('');
        await loadContextData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [canMutateContext, createProjectId, createProjectName, loadContextData, session.claims, session.errorMessage],
  );

  const onRenameProject = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateContext) {
        setMutationError('Only owner/admin roles can update projects.');
        return;
      }
      const projectId = String(projectActionId || '').trim();
      const name = String(projectRenameName || '').trim();
      if (!projectId || !name) {
        setMutationError('Project and new name are required.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        await updateDashboardProject(projectId, { name });
        setProjectRenameName('');
        await loadContextData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [canMutateContext, loadContextData, projectActionId, projectRenameName, session.claims, session.errorMessage],
  );

  const onArchiveProject = React.useCallback(async () => {
    if (!session.claims) {
      setMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canMutateContext) {
      setMutationError('Only owner/admin roles can archive projects.');
      return;
    }
    const projectId = String(projectActionId || '').trim();
    if (!projectId) {
      setMutationError('Project is required.');
      return;
    }
    if (!window.confirm(`Archive project ${projectId}? This archives all environments under it.`)) {
      return;
    }
    setMutating(true);
    setMutationError('');
    try {
      await archiveDashboardProject(projectId);
      await loadContextData();
    } catch (error: unknown) {
      setMutationError(error instanceof Error ? error.message : String(error));
    } finally {
      setMutating(false);
    }
  }, [canMutateContext, loadContextData, projectActionId, session.claims, session.errorMessage]);

  const onCreateEnvironment = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateContext) {
        setMutationError('Only owner/admin roles can create environments.');
        return;
      }
      const id = String(createEnvironmentId || '').trim();
      const projectId = String(createEnvironmentProjectId || '').trim();
      const name = String(createEnvironmentName || '').trim();
      if (!projectId) {
        setMutationError('Project is required to create an environment.');
        return;
      }
      if (!canCreateEnvironmentInProject(projectId, activeProjects)) {
        setMutationError('Environment can only be created under an active project.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        await createDashboardEnvironment({
          projectId,
          key: createEnvironmentKey,
          ...(id ? { id } : {}),
          ...(name ? { name } : {}),
        });
        setCreateEnvironmentId('');
        setCreateEnvironmentName('');
        await loadContextData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      canMutateContext,
      createEnvironmentId,
      createEnvironmentKey,
      createEnvironmentName,
      createEnvironmentProjectId,
      activeProjects,
      loadContextData,
      session.claims,
      session.errorMessage,
    ],
  );

  const onRenameEnvironment = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateContext) {
        setMutationError('Only owner/admin roles can update environments.');
        return;
      }
      const environmentId = String(environmentActionId || '').trim();
      const name = String(environmentRenameName || '').trim();
      if (!environmentId || !name) {
        setMutationError('Environment and new name are required.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        await updateDashboardEnvironment(environmentId, { name });
        setEnvironmentRenameName('');
        await loadContextData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      canMutateContext,
      environmentActionId,
      environmentRenameName,
      loadContextData,
      session.claims,
      session.errorMessage,
    ],
  );

  const onArchiveEnvironment = React.useCallback(async () => {
    if (!session.claims) {
      setMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canMutateContext) {
      setMutationError('Only owner/admin roles can archive environments.');
      return;
    }
    const environmentId = String(environmentActionId || '').trim();
    if (!environmentId) {
      setMutationError('Environment is required.');
      return;
    }
    if (!window.confirm(`Archive environment ${environmentId}?`)) return;
    setMutating(true);
    setMutationError('');
    try {
      await archiveDashboardEnvironment(environmentId);
      await loadContextData();
    } catch (error: unknown) {
      setMutationError(error instanceof Error ? error.message : String(error));
    } finally {
      setMutating(false);
    }
  }, [canMutateContext, environmentActionId, loadContextData, session.claims, session.errorMessage]);

  return (
    <div className="dashboard-view" aria-label="App settings page">
      <section className="dashboard-view__section" aria-label="Context management">
        <h2>Org, projects, and environments</h2>
        <p>
          Manage hierarchy under org {selectedContext.organization || '-'} and keep project and
          environment topology aligned with runtime wallet context.
        </p>
        <button type="button" className="dashboard-pagination-button" onClick={() => loadContextData()}>
          Refresh hierarchy
        </button>
      </section>

      {session.loading || loading ? (
        <section className="dashboard-view__section">
          <p>Loading context data...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Context management unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : errorMessage ? (
        <section className="dashboard-view__section">
          <p>Context data unavailable: {errorMessage}</p>
        </section>
      ) : (
        <>
          <section className="dashboard-table-wrapper" aria-label="Organization details">
            <div className="dashboard-table-header" role="row">
              <span>Org ID</span>
              <span>Name</span>
              <span>Slug</span>
              <span>Status</span>
              <span>Created</span>
              <span>Updated</span>
              <span>Current topbar project</span>
              <span>Current topbar environment</span>
            </div>
            {organization ? (
              <div className="dashboard-table-row" role="row">
                <span>{organization.id}</span>
                <span>{organization.name}</span>
                <span>{organization.slug || '-'}</span>
                <span>{organization.status}</span>
                <span>{formatTimestamp(organization.createdAt)}</span>
                <span>{formatTimestamp(organization.updatedAt)}</span>
                <span>{selectedContext.project || '-'}</span>
                <span>{selectedContext.environment || '-'}</span>
              </div>
            ) : (
              <p className="dashboard-table-limit">No organization details found.</p>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Project management">
            <div className="dashboard-table-limit">
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateProject}>
                <label className="dashboard-form-field">
                  <span>New project ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createProjectId}
                    onChange={(event) => setCreateProjectId(event.target.value)}
                    placeholder="proj_prod"
                    disabled={!canMutateContext}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>New project name</span>
                  <input
                    className="dashboard-input"
                    value={createProjectName}
                    onChange={(event) => setCreateProjectName(event.target.value)}
                    placeholder="Production"
                    disabled={!canMutateContext}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={!canMutateContext || mutating}
                  >
                    {mutating ? 'Applying...' : 'Create project'}
                  </button>
                </div>
              </form>
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onRenameProject}>
                <label className="dashboard-form-field">
                  <span>Include archived</span>
                  <input
                    className="dashboard-input"
                    type="checkbox"
                    checked={showArchivedProjects}
                    onChange={(event) => setShowArchivedProjects(event.target.checked)}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Project</span>
                  <select
                    className="dashboard-input"
                    value={projectActionId}
                    onChange={(event) => setProjectActionId(event.target.value)}
                  >
                    {projects.map((project) => (
                      <option key={project.id} value={project.id}>
                        {project.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Rename project to</span>
                  <input
                    className="dashboard-input"
                    value={projectRenameName}
                    onChange={(event) => setProjectRenameName(event.target.value)}
                    placeholder="Project display name"
                    disabled={!canMutateContext}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={
                      !canMutateContext ||
                      mutating ||
                      !projectActionId ||
                      selectedProjectForAction?.status === 'ARCHIVED'
                    }
                  >
                    {mutating ? 'Applying...' : 'Rename project'}
                  </button>
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={onArchiveProject}
                    disabled={
                      !canMutateContext ||
                      mutating ||
                      !projectActionId ||
                      selectedProjectForAction?.status === 'ARCHIVED'
                    }
                  >
                    {mutating ? 'Applying...' : 'Archive project'}
                  </button>
                </div>
              </form>
              {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
              <p className="dashboard-pagination-note">
                {canMutateContext
                  ? 'Owner/admin role enabled for project and environment mutations.'
                  : 'Only owner/admin roles can mutate project and environment records.'}
              </p>
            </div>
            <p className="dashboard-table-limit">
              Project status filter: {showArchivedProjects ? 'ACTIVE + ARCHIVED' : 'ACTIVE only'}.
            </p>
            <div className="dashboard-table-header" role="row">
              <span>Project ID</span>
              <span>Name</span>
              <span>Slug</span>
              <span>Status</span>
              <span>Created</span>
              <span>Updated</span>
              <span>Environment count</span>
              <span>Topbar selected</span>
            </div>
            {projects.length === 0 ? (
              <p className="dashboard-table-limit">No projects found.</p>
            ) : (
              <>
                {projects.map((project) => (
                  <div className="dashboard-table-row" key={project.id} role="row">
                    <span>{project.id}</span>
                    <span>{project.name || '-'}</span>
                    <span>{project.slug || '-'}</span>
                    <span>{project.status}</span>
                    <span>{formatTimestamp(project.createdAt)}</span>
                    <span>{formatTimestamp(project.updatedAt)}</span>
                    <span>
                      {String(project.environmentCount || 0)}
                    </span>
                    <span>{selectedContext.project === project.id ? 'Yes' : 'No'}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {projects.length} project{projects.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Environment management">
            <div className="dashboard-table-limit">
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateEnvironment}>
                <label className="dashboard-form-field">
                  <span>New environment ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createEnvironmentId}
                    onChange={(event) => setCreateEnvironmentId(event.target.value)}
                    placeholder="env_prod"
                    disabled={!canMutateContext}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Project</span>
                  <select
                    className="dashboard-input"
                    value={createEnvironmentProjectId}
                    onChange={(event) => setCreateEnvironmentProjectId(event.target.value)}
                    disabled={activeProjects.length === 0}
                  >
                    {activeProjects.length === 0 ? <option value="">No active projects</option> : null}
                    {activeProjects.map((project) => (
                      <option key={project.id} value={project.id}>
                        {project.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Environment key</span>
                  <select
                    className="dashboard-input"
                    value={createEnvironmentKey}
                    onChange={(event) =>
                      setCreateEnvironmentKey(event.target.value as 'dev' | 'staging' | 'prod')
                    }
                  >
                    <option value="dev">dev</option>
                    <option value="staging">staging</option>
                    <option value="prod">prod</option>
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Environment name (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createEnvironmentName}
                    onChange={(event) => setCreateEnvironmentName(event.target.value)}
                    placeholder="Production"
                    disabled={!canMutateContext}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={!canMutateContext || mutating || activeProjects.length === 0}
                  >
                    {mutating ? 'Applying...' : 'Create environment'}
                  </button>
                </div>
              </form>
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onRenameEnvironment}>
                <label className="dashboard-form-field">
                  <span>Include archived</span>
                  <input
                    className="dashboard-input"
                    type="checkbox"
                    checked={showArchivedEnvironments}
                    onChange={(event) => setShowArchivedEnvironments(event.target.checked)}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Project scope</span>
                  <select
                    className="dashboard-input"
                    value={environmentScopeProjectId}
                    onChange={(event) => setEnvironmentScopeProjectId(event.target.value)}
                  >
                    <option value={ALL_PROJECTS_SCOPE}>All projects</option>
                    {projects.map((project) => (
                      <option key={project.id} value={project.id}>
                        {project.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Environment</span>
                  <select
                    className="dashboard-input"
                    value={environmentActionId}
                    onChange={(event) => setEnvironmentActionId(event.target.value)}
                  >
                    {scopedEnvironments.length === 0 ? <option value="">No environments</option> : null}
                    {scopedEnvironments.map((environment) => (
                      <option key={environment.id} value={environment.id}>
                        {environment.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Rename environment to</span>
                  <input
                    className="dashboard-input"
                    value={environmentRenameName}
                    onChange={(event) => setEnvironmentRenameName(event.target.value)}
                    placeholder="Environment display name"
                    disabled={!canMutateContext}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={
                      !canMutateContext ||
                      mutating ||
                      !environmentActionId ||
                      selectedEnvironmentForAction?.status === 'ARCHIVED'
                    }
                  >
                    {mutating ? 'Applying...' : 'Rename environment'}
                  </button>
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={onArchiveEnvironment}
                    disabled={
                      !canMutateContext ||
                      mutating ||
                      !environmentActionId ||
                      selectedEnvironmentForAction?.status === 'ARCHIVED'
                    }
                  >
                    {mutating ? 'Applying...' : 'Archive environment'}
                  </button>
                </div>
              </form>
            </div>
            <p className="dashboard-table-limit">
              Environment status filter: {showArchivedEnvironments ? 'ACTIVE + ARCHIVED' : 'ACTIVE only'}.
            </p>
            <p className="dashboard-table-limit">
              Environment scope project:{' '}
              {environmentScopeProjectId === ALL_PROJECTS_SCOPE
                ? 'All projects'
                : (projectNameById.get(environmentScopeProjectId) || environmentScopeProjectId || '-')}.
            </p>
            <div className="dashboard-table-header" role="row">
              <span>Environment ID</span>
              <span>Project</span>
              <span>Key</span>
              <span>Name</span>
              <span>Status</span>
              <span>Created</span>
              <span>Updated</span>
              <span>Topbar selected</span>
            </div>
            {scopedEnvironments.length === 0 ? (
              <p className="dashboard-table-limit">
                {environments.length === 0
                  ? 'No environments found.'
                  : 'No environments found for selected project scope.'}
              </p>
            ) : (
              <>
                {scopedEnvironments.map((environment) => (
                  <div className="dashboard-table-row" key={environment.id} role="row">
                    <span>{environment.id}</span>
                    <span>{projectNameById.get(environment.projectId) || environment.projectId}</span>
                    <span>{environment.key}</span>
                    <span>{environment.name || '-'}</span>
                    <span>{environment.status}</span>
                    <span>{formatTimestamp(environment.createdAt)}</span>
                    <span>{formatTimestamp(environment.updatedAt)}</span>
                    <span>{selectedContext.environment === environment.id ? 'Yes' : 'No'}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {scopedEnvironments.length} environment
                  {scopedEnvironments.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default AppSettingsPage;
