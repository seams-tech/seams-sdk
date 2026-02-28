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
import {
  getDashboardAppSettings,
  getDashboardSecuritySettings,
  updateDashboardAppSettings,
  updateDashboardSecuritySettings,
  type DashboardAppSettings,
  type DashboardSecuritySettings,
} from './consoleSettingsApi';

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function normalizeString(value: string): string {
  return String(value || '').trim();
}

function parseCsvList(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of String(raw || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)) {
    const key = entry.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(entry);
  }
  return out;
}

function joinCsv(values: string[]): string {
  return Array.isArray(values) ? values.join(', ') : '';
}

function parsePositiveInteger(raw: string, field: string): number {
  const value = normalizeString(raw);
  if (!/^\d+$/.test(value)) {
    throw new Error(`${field} must be a positive integer.`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${field} must be a positive integer.`);
  }
  return parsed;
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
  const [settingsEnvironmentId, setSettingsEnvironmentId] = React.useState<string>('');
  const [settingsLoading, setSettingsLoading] = React.useState<boolean>(false);
  const [settingsError, setSettingsError] = React.useState<string>('');
  const [settingsMutationError, setSettingsMutationError] = React.useState<string>('');
  const [settingsMutating, setSettingsMutating] = React.useState<boolean>(false);
  const [appSettings, setAppSettings] = React.useState<DashboardAppSettings | null>(null);
  const [securitySettings, setSecuritySettings] = React.useState<DashboardSecuritySettings | null>(null);
  const [allowedOriginsInput, setAllowedOriginsInput] = React.useState<string>('');
  const [allowedDomainsInput, setAllowedDomainsInput] = React.useState<string>('');
  const [cookieHttpOnlyInput, setCookieHttpOnlyInput] = React.useState<boolean>(true);
  const [cookieSecureInput, setCookieSecureInput] = React.useState<boolean>(true);
  const [cookieSameSiteInput, setCookieSameSiteInput] = React.useState<'LAX' | 'STRICT' | 'NONE'>(
    'LAX',
  );
  const [cookieDomainInput, setCookieDomainInput] = React.useState<string>('');
  const [cookiePathInput, setCookiePathInput] = React.useState<string>('/');
  const [cookieMaxAgeInput, setCookieMaxAgeInput] = React.useState<string>('86400');
  const [jwtIssuerInput, setJwtIssuerInput] = React.useState<string>('');
  const [jwtAudienceInput, setJwtAudienceInput] = React.useState<string>('');
  const [jwtKeyIdsInput, setJwtKeyIdsInput] = React.useState<string>('');
  const [jwtAccessTtlInput, setJwtAccessTtlInput] = React.useState<string>('900');
  const [jwtRefreshTtlInput, setJwtRefreshTtlInput] = React.useState<string>('2592000');
  const [ssoMetadataUrlInput, setSsoMetadataUrlInput] = React.useState<string>('');
  const [ipAllowlistInput, setIpAllowlistInput] = React.useState<string>('');
  const [enforceIpAllowlistInput, setEnforceIpAllowlistInput] = React.useState<boolean>(false);
  const [requireMfaForRiskyChangesInput, setRequireMfaForRiskyChangesInput] =
    React.useState<boolean>(true);
  const [riskyApprovalsRequiredInput, setRiskyApprovalsRequiredInput] = React.useState<string>('1');
  const [riskyRequireAdminInput, setRiskyRequireAdminInput] = React.useState<boolean>(true);
  const [riskyRequireMfaInput, setRiskyRequireMfaInput] = React.useState<boolean>(true);

  const canMutateContext = React.useMemo(
    () =>
      Array.isArray(session.claims?.roles) &&
      session.claims.roles.some((role) => {
        const normalized = String(role || '').toLowerCase();
        return normalized === 'admin' || normalized === 'owner';
      }),
    [session.claims?.roles],
  );

  const canMutateConsoleSettings = React.useMemo(
    () =>
      Array.isArray(session.claims?.roles) &&
      session.claims.roles.some((role) => {
        const normalized = String(role || '').toLowerCase();
        return normalized === 'owner' || normalized === 'admin' || normalized === 'security_admin';
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

  React.useEffect(() => {
    if (environments.length === 0) {
      setSettingsEnvironmentId('');
      return;
    }
    const selectedEnvironment = normalizeString(selectedContext.environment || '');
    if (selectedEnvironment && environments.some((entry) => entry.id === selectedEnvironment)) {
      if (settingsEnvironmentId !== selectedEnvironment) {
        setSettingsEnvironmentId(selectedEnvironment);
      }
      return;
    }
    if (!settingsEnvironmentId || !environments.some((entry) => entry.id === settingsEnvironmentId)) {
      setSettingsEnvironmentId(environments[0]?.id || '');
    }
  }, [environments, selectedContext.environment, settingsEnvironmentId]);

  const applyAppSettingsToForm = React.useCallback((input: DashboardAppSettings) => {
    setAllowedOriginsInput(joinCsv(input.allowedOrigins));
    setAllowedDomainsInput(joinCsv(input.allowedDomains));
    setCookieHttpOnlyInput(input.cookie.httpOnly);
    setCookieSecureInput(input.cookie.secure);
    setCookieSameSiteInput(
      input.cookie.sameSite === 'STRICT' || input.cookie.sameSite === 'NONE'
        ? input.cookie.sameSite
        : 'LAX',
    );
    setCookieDomainInput(input.cookie.domain || '');
    setCookiePathInput(input.cookie.path || '/');
    setCookieMaxAgeInput(String(input.cookie.maxAgeSeconds || 0));
    setJwtIssuerInput(input.jwt.issuer || '');
    setJwtAudienceInput(joinCsv(input.jwt.audience));
    setJwtKeyIdsInput(joinCsv(input.jwt.keyIds));
    setJwtAccessTtlInput(String(input.jwt.accessTokenTtlSeconds || 0));
    setJwtRefreshTtlInput(String(input.jwt.refreshTokenTtlSeconds || 0));
    setSsoMetadataUrlInput(input.ssoMetadataUrl || '');
  }, []);

  const applySecuritySettingsToForm = React.useCallback((input: DashboardSecuritySettings) => {
    setIpAllowlistInput(joinCsv(input.ipAllowlist));
    setEnforceIpAllowlistInput(input.enforceIpAllowlist);
    setRequireMfaForRiskyChangesInput(input.requireMfaForRiskyChanges);
    setRiskyApprovalsRequiredInput(String(input.riskyChangeApproval.approvalsRequired || 1));
    setRiskyRequireAdminInput(input.riskyChangeApproval.requireAdmin);
    setRiskyRequireMfaInput(input.riskyChangeApproval.requireMfa);
  }, []);

  const loadSettingsData = React.useCallback(() => {
    if (!session.claims) {
      setSettingsLoading(false);
      setSettingsError(session.errorMessage || 'Console session is unavailable');
      setAppSettings(null);
      setSecuritySettings(null);
      return;
    }
    const environmentId = normalizeString(settingsEnvironmentId);
    if (!environmentId) {
      setSettingsLoading(false);
      setSettingsError('Select an environment to manage app/security settings.');
      setAppSettings(null);
      setSecuritySettings(null);
      return;
    }
    let cancelled = false;
    setSettingsLoading(true);
    setSettingsError('');
    Promise.all([
      getDashboardAppSettings(environmentId),
      getDashboardSecuritySettings(environmentId),
    ])
      .then(([nextAppSettings, nextSecuritySettings]) => {
        if (cancelled) return;
        setAppSettings(nextAppSettings);
        setSecuritySettings(nextSecuritySettings);
        applyAppSettingsToForm(nextAppSettings);
        applySecuritySettingsToForm(nextSecuritySettings);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setAppSettings(null);
        setSecuritySettings(null);
        setSettingsError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setSettingsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [
    applyAppSettingsToForm,
    applySecuritySettingsToForm,
    session.claims,
    session.errorMessage,
    settingsEnvironmentId,
  ]);

  React.useEffect(() => {
    if (session.loading || loading) return;
    const cleanup = loadSettingsData();
    return cleanup;
  }, [loadSettingsData, loading, session.loading]);

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

  const onUpdateAppSettings = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setSettingsMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateConsoleSettings) {
        setSettingsMutationError(
          'Only owner/admin/security_admin can update app and security settings.',
        );
        return;
      }
      const environmentId = normalizeString(settingsEnvironmentId);
      if (!environmentId) {
        setSettingsMutationError('Environment is required.');
        return;
      }
      setSettingsMutating(true);
      setSettingsMutationError('');
      try {
        const cookiePath = normalizeString(cookiePathInput);
        if (!cookiePath) {
          throw new Error('Cookie path is required.');
        }
        const updated = await updateDashboardAppSettings({
          environmentId,
          allowedOrigins: parseCsvList(allowedOriginsInput),
          allowedDomains: parseCsvList(allowedDomainsInput),
          cookie: {
            httpOnly: cookieHttpOnlyInput,
            secure: cookieSecureInput,
            sameSite: cookieSameSiteInput,
            domain: normalizeString(cookieDomainInput) || null,
            path: cookiePath,
            maxAgeSeconds: parsePositiveInteger(cookieMaxAgeInput, 'Cookie max age'),
          },
          jwt: {
            issuer: normalizeString(jwtIssuerInput),
            audience: parseCsvList(jwtAudienceInput),
            keyIds: parseCsvList(jwtKeyIdsInput),
            accessTokenTtlSeconds: parsePositiveInteger(jwtAccessTtlInput, 'JWT access token TTL'),
            refreshTokenTtlSeconds: parsePositiveInteger(
              jwtRefreshTtlInput,
              'JWT refresh token TTL',
            ),
          },
          ssoMetadataUrl: normalizeString(ssoMetadataUrlInput) || null,
        });
        setAppSettings(updated);
        applyAppSettingsToForm(updated);
      } catch (error: unknown) {
        setSettingsMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setSettingsMutating(false);
      }
    },
    [
      allowedDomainsInput,
      allowedOriginsInput,
      applyAppSettingsToForm,
      canMutateConsoleSettings,
      cookieDomainInput,
      cookieHttpOnlyInput,
      cookieMaxAgeInput,
      cookiePathInput,
      cookieSameSiteInput,
      cookieSecureInput,
      jwtAccessTtlInput,
      jwtAudienceInput,
      jwtIssuerInput,
      jwtKeyIdsInput,
      jwtRefreshTtlInput,
      session.claims,
      session.errorMessage,
      settingsEnvironmentId,
      ssoMetadataUrlInput,
    ],
  );

  const onUpdateSecuritySettings = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setSettingsMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateConsoleSettings) {
        setSettingsMutationError(
          'Only owner/admin/security_admin can update app and security settings.',
        );
        return;
      }
      const environmentId = normalizeString(settingsEnvironmentId);
      if (!environmentId) {
        setSettingsMutationError('Environment is required.');
        return;
      }
      setSettingsMutating(true);
      setSettingsMutationError('');
      try {
        const updated = await updateDashboardSecuritySettings({
          environmentId,
          ipAllowlist: parseCsvList(ipAllowlistInput),
          enforceIpAllowlist: enforceIpAllowlistInput,
          requireMfaForRiskyChanges: requireMfaForRiskyChangesInput,
          riskyChangeApproval: {
            approvalsRequired: parsePositiveInteger(
              riskyApprovalsRequiredInput,
              'Risky change approvals required',
            ),
            requireAdmin: riskyRequireAdminInput,
            requireMfa: riskyRequireMfaInput,
          },
        });
        setSecuritySettings(updated);
        applySecuritySettingsToForm(updated);
      } catch (error: unknown) {
        setSettingsMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setSettingsMutating(false);
      }
    },
    [
      applySecuritySettingsToForm,
      canMutateConsoleSettings,
      enforceIpAllowlistInput,
      ipAllowlistInput,
      requireMfaForRiskyChangesInput,
      riskyApprovalsRequiredInput,
      riskyRequireAdminInput,
      riskyRequireMfaInput,
      session.claims,
      session.errorMessage,
      settingsEnvironmentId,
    ],
  );

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

          <section className="dashboard-view__section" aria-label="App and security settings controls">
            <h2>App and security settings</h2>
            <p>
              Backed by `GET/PATCH /console/settings/app` and `GET/PATCH /console/settings/security`.
              Choose an environment to manage origin, cookie, JWT, and security policy settings.
            </p>
            <div className="dashboard-view-grid dashboard-view-grid--two">
              <label className="dashboard-form-field">
                <span>Settings environment</span>
                <select
                  className="dashboard-input"
                  value={settingsEnvironmentId}
                  onChange={(event) => setSettingsEnvironmentId(event.target.value)}
                >
                  {environments.length === 0 ? <option value="">No environments</option> : null}
                  {environments.map((environment) => (
                    <option key={environment.id} value={environment.id}>
                      {environment.id}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <button type="button" className="dashboard-pagination-button" onClick={() => loadSettingsData()}>
              Refresh app/security settings
            </button>
            <p className="dashboard-pagination-note">
              {canMutateConsoleSettings
                ? 'Owner/admin/security_admin role enabled for settings mutations.'
                : 'Only owner/admin/security_admin can mutate settings.'}
            </p>
            {settingsMutationError ? (
              <p className="dashboard-pagination-note">{settingsMutationError}</p>
            ) : null}
          </section>

          {settingsLoading ? (
            <section className="dashboard-view__section">
              <p>Loading app/security settings...</p>
            </section>
          ) : settingsError ? (
            <section className="dashboard-view__section">
              <p>App/security settings unavailable: {settingsError}</p>
            </section>
          ) : !appSettings || !securitySettings ? (
            <section className="dashboard-view__section">
              <p>App/security settings unavailable for selected environment.</p>
            </section>
          ) : (
            <>
              <section className="dashboard-table-wrapper" aria-label="Update app settings">
                <div className="dashboard-table-limit">
                  <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onUpdateAppSettings}>
                    <label className="dashboard-form-field">
                      <span>Allowed origins (csv)</span>
                      <input
                        className="dashboard-input"
                        value={allowedOriginsInput}
                        onChange={(event) => setAllowedOriginsInput(event.target.value)}
                        placeholder="https://app.example.com, https://admin.example.com"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Allowed domains (csv)</span>
                      <input
                        className="dashboard-input"
                        value={allowedDomainsInput}
                        onChange={(event) => setAllowedDomainsInput(event.target.value)}
                        placeholder="example.com, example.org"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Cookie sameSite</span>
                      <select
                        className="dashboard-input"
                        value={cookieSameSiteInput}
                        onChange={(event) =>
                          setCookieSameSiteInput(event.target.value as 'LAX' | 'STRICT' | 'NONE')
                        }
                      >
                        <option value="LAX">LAX</option>
                        <option value="STRICT">STRICT</option>
                        <option value="NONE">NONE</option>
                      </select>
                    </label>
                    <label className="dashboard-form-field">
                      <span>Cookie domain (optional)</span>
                      <input
                        className="dashboard-input"
                        value={cookieDomainInput}
                        onChange={(event) => setCookieDomainInput(event.target.value)}
                        placeholder=".example.com"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Cookie path</span>
                      <input
                        className="dashboard-input"
                        value={cookiePathInput}
                        onChange={(event) => setCookiePathInput(event.target.value)}
                        placeholder="/"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Cookie max age (seconds)</span>
                      <input
                        className="dashboard-input"
                        value={cookieMaxAgeInput}
                        onChange={(event) => setCookieMaxAgeInput(event.target.value)}
                        placeholder="86400"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>JWT issuer</span>
                      <input
                        className="dashboard-input"
                        value={jwtIssuerInput}
                        onChange={(event) => setJwtIssuerInput(event.target.value)}
                        placeholder="https://console.example.com/org/env"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>JWT audience (csv)</span>
                      <input
                        className="dashboard-input"
                        value={jwtAudienceInput}
                        onChange={(event) => setJwtAudienceInput(event.target.value)}
                        placeholder="dashboard, api"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>JWT key IDs (csv)</span>
                      <input
                        className="dashboard-input"
                        value={jwtKeyIdsInput}
                        onChange={(event) => setJwtKeyIdsInput(event.target.value)}
                        placeholder="kid-1, kid-2"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>JWT access TTL (seconds)</span>
                      <input
                        className="dashboard-input"
                        value={jwtAccessTtlInput}
                        onChange={(event) => setJwtAccessTtlInput(event.target.value)}
                        placeholder="900"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>JWT refresh TTL (seconds)</span>
                      <input
                        className="dashboard-input"
                        value={jwtRefreshTtlInput}
                        onChange={(event) => setJwtRefreshTtlInput(event.target.value)}
                        placeholder="2592000"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>SSO metadata URL (optional)</span>
                      <input
                        className="dashboard-input"
                        value={ssoMetadataUrlInput}
                        onChange={(event) => setSsoMetadataUrlInput(event.target.value)}
                        placeholder="https://idp.example.com/metadata"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Cookie httpOnly</span>
                      <input
                        className="dashboard-input"
                        type="checkbox"
                        checked={cookieHttpOnlyInput}
                        onChange={(event) => setCookieHttpOnlyInput(event.target.checked)}
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Cookie secure</span>
                      <input
                        className="dashboard-input"
                        type="checkbox"
                        checked={cookieSecureInput}
                        onChange={(event) => setCookieSecureInput(event.target.checked)}
                      />
                    </label>
                    <div className="dashboard-form-actions">
                      <button
                        type="submit"
                        className="dashboard-pagination-button"
                        disabled={!canMutateConsoleSettings || settingsMutating}
                      >
                        {settingsMutating ? 'Applying...' : 'Update app settings'}
                      </button>
                    </div>
                  </form>
                </div>
              </section>

              <section className="dashboard-table-wrapper" aria-label="Update security settings">
                <div className="dashboard-table-limit">
                  <form
                    className="dashboard-view-grid dashboard-view-grid--two"
                    onSubmit={onUpdateSecuritySettings}
                  >
                    <label className="dashboard-form-field">
                      <span>IP allowlist (csv)</span>
                      <input
                        className="dashboard-input"
                        value={ipAllowlistInput}
                        onChange={(event) => setIpAllowlistInput(event.target.value)}
                        placeholder="192.168.1.1, 10.0.0.0/24"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Risky change approvals required</span>
                      <input
                        className="dashboard-input"
                        value={riskyApprovalsRequiredInput}
                        onChange={(event) => setRiskyApprovalsRequiredInput(event.target.value)}
                        placeholder="1"
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Enforce IP allowlist</span>
                      <input
                        className="dashboard-input"
                        type="checkbox"
                        checked={enforceIpAllowlistInput}
                        onChange={(event) => setEnforceIpAllowlistInput(event.target.checked)}
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Require MFA for risky changes</span>
                      <input
                        className="dashboard-input"
                        type="checkbox"
                        checked={requireMfaForRiskyChangesInput}
                        onChange={(event) => setRequireMfaForRiskyChangesInput(event.target.checked)}
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Risky changes require admin</span>
                      <input
                        className="dashboard-input"
                        type="checkbox"
                        checked={riskyRequireAdminInput}
                        onChange={(event) => setRiskyRequireAdminInput(event.target.checked)}
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Risky changes require MFA</span>
                      <input
                        className="dashboard-input"
                        type="checkbox"
                        checked={riskyRequireMfaInput}
                        onChange={(event) => setRiskyRequireMfaInput(event.target.checked)}
                      />
                    </label>
                    <div className="dashboard-form-actions">
                      <button
                        type="submit"
                        className="dashboard-pagination-button"
                        disabled={!canMutateConsoleSettings || settingsMutating}
                      >
                        {settingsMutating ? 'Applying...' : 'Update security settings'}
                      </button>
                    </div>
                  </form>
                </div>
              </section>

              <section className="dashboard-table-wrapper" aria-label="Current settings snapshot">
                <div className="dashboard-table-header" role="row">
                  <span>Environment</span>
                  <span>App updated</span>
                  <span>Security updated</span>
                  <span>Allowed origins</span>
                  <span>Allowed domains</span>
                  <span>IP allowlist entries</span>
                  <span>Require risky-change MFA</span>
                  <span>Approvals required</span>
                </div>
                <div className="dashboard-table-row" role="row">
                  <span>{settingsEnvironmentId || '-'}</span>
                  <span>{formatTimestamp(appSettings.updatedAt)}</span>
                  <span>{formatTimestamp(securitySettings.updatedAt)}</span>
                  <span>{appSettings.allowedOrigins.length}</span>
                  <span>{appSettings.allowedDomains.length}</span>
                  <span>{securitySettings.ipAllowlist.length}</span>
                  <span>{securitySettings.requireMfaForRiskyChanges ? 'true' : 'false'}</span>
                  <span>{securitySettings.riskyChangeApproval.approvalsRequired}</span>
                </div>
              </section>
            </>
          )}
        </>
      )}
    </div>
  );
}

export default AppSettingsPage;
