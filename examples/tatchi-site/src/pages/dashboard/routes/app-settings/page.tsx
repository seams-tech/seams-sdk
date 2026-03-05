import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import {
  archiveDashboardProject,
  createDashboardProject,
  getDashboardOrganization,
  listDashboardEnvironments,
  listDashboardProjects,
  updateDashboardProject,
  type DashboardConsoleEnvironment,
  type DashboardConsoleOrganization,
  type DashboardConsoleProject,
} from '../../consoleContextApi';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  getDashboardAppSettings,
  getDashboardSecuritySettings,
  updateDashboardAppSettings,
  updateDashboardSecuritySettings,
  type DashboardAppSettings,
  type DashboardSecuritySettings,
} from './consoleSettingsApi';
import {
  getLatestDashboardRuntimeSnapshot,
  listDashboardRuntimeSnapshots,
  publishCurrentDashboardRuntimeSnapshot,
  type DashboardRuntimeSnapshot,
} from './consoleRuntimeSnapshotsApi';

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

type RuntimeSnapshotPayloadModule = 'policy' | 'settings' | 'gasSponsorship' | 'smartWallets';

function readRuntimeSnapshotModuleStatus(
  snapshot: DashboardRuntimeSnapshot,
  key: RuntimeSnapshotPayloadModule,
): string {
  const module = snapshot.payload[key];
  if (!module || typeof module !== 'object' || Array.isArray(module)) return '-';
  const status = String((module as Record<string, unknown>).status || '').trim();
  return status || '-';
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
  const [settingsEnvironmentId, setSettingsEnvironmentId] = React.useState<string>('');
  const [settingsLoading, setSettingsLoading] = React.useState<boolean>(false);
  const [settingsError, setSettingsError] = React.useState<string>('');
  const [settingsMutationError, setSettingsMutationError] = React.useState<string>('');
  const [settingsMutating, setSettingsMutating] = React.useState<boolean>(false);
  const [securityApprovalIdInput, setSecurityApprovalIdInput] = React.useState<string>('');
  const [appSettings, setAppSettings] = React.useState<DashboardAppSettings | null>(null);
  const [securitySettings, setSecuritySettings] = React.useState<DashboardSecuritySettings | null>(null);
  const [runtimeSnapshotsLoading, setRuntimeSnapshotsLoading] = React.useState<boolean>(false);
  const [runtimeSnapshotsError, setRuntimeSnapshotsError] = React.useState<string>('');
  const [runtimeSnapshotsMutationError, setRuntimeSnapshotsMutationError] = React.useState<string>('');
  const [runtimeSnapshotsMutating, setRuntimeSnapshotsMutating] = React.useState<boolean>(false);
  const [latestRuntimeSnapshot, setLatestRuntimeSnapshot] =
    React.useState<DashboardRuntimeSnapshot | null>(null);
  const [runtimeSnapshotHistory, setRuntimeSnapshotHistory] = React.useState<DashboardRuntimeSnapshot[]>([]);
  const [runtimeSnapshotIdInput, setRuntimeSnapshotIdInput] = React.useState<string>('');
  const [runtimeSnapshotEffectiveAtInput, setRuntimeSnapshotEffectiveAtInput] = React.useState<string>('');
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

  const selectedProjectId = React.useMemo(
    () => normalizeString(selectedContext.project || ''),
    [selectedContext.project],
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
      listDashboardProjects(showArchivedProjects ? {} : { status: 'ACTIVE' }),
    ])
      .then(async ([nextOrg, nextProjects]) => {
        const sortedProjects = [...nextProjects].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        const currentProjectId = normalizeString(selectedContext.project || '');
        const scopeProjectId =
          currentProjectId && sortedProjects.some((entry) => entry.id === currentProjectId)
            ? currentProjectId
            : (sortedProjects[0]?.id || '');
        const nextEnvironments = await listDashboardEnvironments(
          scopeProjectId ? { projectId: scopeProjectId } : {},
        );
        if (cancelled) return;
        const sortedEnvironments = [...nextEnvironments]
          .filter((entry) => String(entry.status || '').toUpperCase() !== 'ARCHIVED')
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        setOrganization(nextOrg);
        setProjects(sortedProjects);
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
    selectedContext.project,
    session.claims,
    session.errorMessage,
    showArchivedProjects,
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
  }, [projectActionId, projects, selectedContext.project]);

  const selectedProjectForAction = React.useMemo(
    () => projects.find((entry) => entry.id === projectActionId) || null,
    [projectActionId, projects],
  );

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

  const loadRuntimeSnapshotsData = React.useCallback(() => {
    if (!session.claims) {
      setRuntimeSnapshotsLoading(false);
      setRuntimeSnapshotsError(session.errorMessage || 'Console session is unavailable');
      setLatestRuntimeSnapshot(null);
      setRuntimeSnapshotHistory([]);
      return;
    }
    const environmentId = normalizeString(settingsEnvironmentId);
    if (!environmentId) {
      setRuntimeSnapshotsLoading(false);
      setRuntimeSnapshotsError('Select an environment to inspect runtime snapshots.');
      setLatestRuntimeSnapshot(null);
      setRuntimeSnapshotHistory([]);
      return;
    }
    let cancelled = false;
    setRuntimeSnapshotsLoading(true);
    setRuntimeSnapshotsError('');
    const scope = {
      environmentId,
      ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
    };
    Promise.all([
      getLatestDashboardRuntimeSnapshot(scope),
      listDashboardRuntimeSnapshots({ ...scope, limit: 10 }),
    ])
      .then(([latestSnapshot, history]) => {
        if (cancelled) return;
        setLatestRuntimeSnapshot(latestSnapshot);
        setRuntimeSnapshotHistory(history);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setLatestRuntimeSnapshot(null);
        setRuntimeSnapshotHistory([]);
        setRuntimeSnapshotsError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setRuntimeSnapshotsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId, session.claims, session.errorMessage, settingsEnvironmentId]);

  React.useEffect(() => {
    if (session.loading || loading) return;
    const cleanup = loadRuntimeSnapshotsData();
    return cleanup;
  }, [loadRuntimeSnapshotsData, loading, session.loading]);

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
        const approvalId = normalizeString(securityApprovalIdInput);
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
          ...(approvalId ? { approvalId } : {}),
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
      securityApprovalIdInput,
      session.claims,
      session.errorMessage,
      settingsEnvironmentId,
    ],
  );

  const onPublishCurrentRuntimeSnapshot = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setRuntimeSnapshotsMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateConsoleSettings) {
        setRuntimeSnapshotsMutationError(
          'Only owner/admin/security_admin can publish runtime snapshots.',
        );
        return;
      }
      const environmentId = normalizeString(settingsEnvironmentId);
      if (!environmentId) {
        setRuntimeSnapshotsMutationError('Environment is required.');
        return;
      }
      const effectiveAt = normalizeString(runtimeSnapshotEffectiveAtInput);
      if (effectiveAt) {
        const parsed = new Date(effectiveAt);
        if (!Number.isFinite(parsed.getTime())) {
          setRuntimeSnapshotsMutationError('Effective at must be an ISO-8601 timestamp.');
          return;
        }
      }
      setRuntimeSnapshotsMutating(true);
      setRuntimeSnapshotsMutationError('');
      try {
        const created = await publishCurrentDashboardRuntimeSnapshot({
          environmentId,
          ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
          ...(normalizeString(runtimeSnapshotIdInput)
            ? { snapshotId: normalizeString(runtimeSnapshotIdInput) }
            : {}),
          ...(effectiveAt ? { effectiveAt } : {}),
        });
        setLatestRuntimeSnapshot(created);
        setRuntimeSnapshotIdInput('');
        setRuntimeSnapshotEffectiveAtInput('');
        await loadRuntimeSnapshotsData();
      } catch (error: unknown) {
        setRuntimeSnapshotsMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setRuntimeSnapshotsMutating(false);
      }
    },
    [
      canMutateConsoleSettings,
      loadRuntimeSnapshotsData,
      runtimeSnapshotEffectiveAtInput,
      runtimeSnapshotIdInput,
      selectedProjectId,
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
                  ? 'Owner/admin role enabled for project mutations.'
                  : 'Only owner/admin roles can mutate project records.'}
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

          <section className="dashboard-table-wrapper" aria-label="Environment inventory">
            <p className="dashboard-table-limit">
              Environments are provisioned automatically for each project (`dev`, `staging`, and `prod`).
              Production remains disabled until billing is attached.
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
            {environments.length === 0 ? (
              <p className="dashboard-table-limit">No environments found for the active project scope.</p>
            ) : (
              <>
                {environments.map((environment) => (
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
                  Showing {environments.length} environment{environments.length === 1 ? '' : 's'}.
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
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={() => loadRuntimeSnapshotsData()}
            >
              Refresh runtime snapshots
            </button>
            <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onPublishCurrentRuntimeSnapshot}>
              <label className="dashboard-form-field">
                <span>Snapshot ID (optional)</span>
                <input
                  className="dashboard-input"
                  value={runtimeSnapshotIdInput}
                  onChange={(event) => setRuntimeSnapshotIdInput(event.target.value)}
                  placeholder="runtime_snapshot_env_active_v3"
                />
              </label>
              <label className="dashboard-form-field">
                <span>Effective at (optional ISO-8601)</span>
                <input
                  className="dashboard-input"
                  value={runtimeSnapshotEffectiveAtInput}
                  onChange={(event) => setRuntimeSnapshotEffectiveAtInput(event.target.value)}
                  placeholder="2026-03-01T00:00:00.000Z"
                />
              </label>
              <div className="dashboard-form-actions">
                <button
                  type="submit"
                  className="dashboard-pagination-button"
                  disabled={!canMutateConsoleSettings || runtimeSnapshotsMutating}
                >
                  {runtimeSnapshotsMutating ? 'Publishing...' : 'Publish current runtime snapshot'}
                </button>
              </div>
            </form>
            <p className="dashboard-pagination-note">
              {canMutateConsoleSettings
                ? 'Owner/admin/security_admin role enabled for settings mutations.'
                : 'Only owner/admin/security_admin can mutate settings.'}
            </p>
            {settingsMutationError ? (
              <p className="dashboard-pagination-note">{settingsMutationError}</p>
            ) : null}
            {runtimeSnapshotsMutationError ? (
              <p className="dashboard-pagination-note">{runtimeSnapshotsMutationError}</p>
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
                      <span>Security approval request ID (optional)</span>
                      <input
                        className="dashboard-input"
                        value={securityApprovalIdInput}
                        onChange={(event) => setSecurityApprovalIdInput(event.target.value)}
                        placeholder="apr_security_change_001"
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

              {runtimeSnapshotsLoading ? (
                <section className="dashboard-view__section">
                  <p>Loading runtime snapshots...</p>
                </section>
              ) : runtimeSnapshotsError ? (
                <section className="dashboard-view__section">
                  <p>Runtime snapshots unavailable: {runtimeSnapshotsError}</p>
                </section>
              ) : (
                <>
                  <section className="dashboard-table-wrapper" aria-label="Latest runtime snapshot">
                    <div className="dashboard-table-header" role="row">
                      <span>Snapshot ID</span>
                      <span>Version</span>
                      <span>Environment</span>
                      <span>Project</span>
                      <span>Effective at</span>
                      <span>Created at</span>
                      <span>Created by</span>
                      <span>Policy status</span>
                      <span>Settings status</span>
                      <span>Gas status</span>
                      <span>Smart wallet status</span>
                    </div>
                    {!latestRuntimeSnapshot ? (
                      <p className="dashboard-table-limit">No runtime snapshots published for this scope.</p>
                    ) : (
                      <div className="dashboard-table-row" role="row">
                        <span>{latestRuntimeSnapshot.snapshotId}</span>
                        <span>{latestRuntimeSnapshot.version}</span>
                        <span>{latestRuntimeSnapshot.environmentId}</span>
                        <span>{latestRuntimeSnapshot.projectId || '-'}</span>
                        <span>{formatTimestamp(latestRuntimeSnapshot.effectiveAt)}</span>
                        <span>{formatTimestamp(latestRuntimeSnapshot.createdAt)}</span>
                        <span>{latestRuntimeSnapshot.createdBy}</span>
                        <span>{readRuntimeSnapshotModuleStatus(latestRuntimeSnapshot, 'policy')}</span>
                        <span>{readRuntimeSnapshotModuleStatus(latestRuntimeSnapshot, 'settings')}</span>
                        <span>{readRuntimeSnapshotModuleStatus(latestRuntimeSnapshot, 'gasSponsorship')}</span>
                        <span>{readRuntimeSnapshotModuleStatus(latestRuntimeSnapshot, 'smartWallets')}</span>
                      </div>
                    )}
                  </section>

                  <section className="dashboard-table-wrapper" aria-label="Runtime snapshots history">
                    <div className="dashboard-table-header" role="row">
                      <span>Snapshot ID</span>
                      <span>Version</span>
                      <span>Effective at</span>
                      <span>Checksum</span>
                    </div>
                    {runtimeSnapshotHistory.length === 0 ? (
                      <p className="dashboard-table-limit">No runtime snapshot history found.</p>
                    ) : (
                      <>
                        {runtimeSnapshotHistory.map((snapshot) => (
                          <div className="dashboard-table-row" role="row" key={`${snapshot.snapshotId}:${snapshot.version}`}>
                            <span>{snapshot.snapshotId}</span>
                            <span>{snapshot.version}</span>
                            <span>{formatTimestamp(snapshot.effectiveAt)}</span>
                            <span>{snapshot.checksum}</span>
                          </div>
                        ))}
                        <p className="dashboard-table-limit">
                          Showing {runtimeSnapshotHistory.length} runtime snapshot
                          {runtimeSnapshotHistory.length === 1 ? '' : 's'}.
                        </p>
                      </>
                    )}
                  </section>
                </>
              )}
            </>
          )}
        </>
      )}
    </div>
  );
}

export default AppSettingsPage;
