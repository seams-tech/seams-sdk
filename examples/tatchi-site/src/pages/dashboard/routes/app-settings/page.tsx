import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import {
  archiveDashboardProject,
  createDashboardProject,
  getDashboardOrganization,
  listDashboardProjects,
  updateDashboardProject,
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
import { FRONTEND_CONFIG } from '../../../../config';
import { UriListEditor } from '../../components/UriListEditor';

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

function parseEditableList(values: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of Array.isArray(values) ? values : []) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
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
  const [createProjectId, setCreateProjectId] = React.useState<string>('');
  const [createProjectName, setCreateProjectName] = React.useState<string>('');
  const [isCreateProjectModalOpen, setIsCreateProjectModalOpen] = React.useState<boolean>(false);
  const [isEditProjectModalOpen, setIsEditProjectModalOpen] = React.useState<boolean>(false);
  const [editingProjectId, setEditingProjectId] = React.useState<string>('');
  const [editingProjectName, setEditingProjectName] = React.useState<string>('');
  const [settingsLoading, setSettingsLoading] = React.useState<boolean>(false);
  const [settingsError, setSettingsError] = React.useState<string>('');
  const [settingsMutationError, setSettingsMutationError] = React.useState<string>('');
  const [settingsMutating, setSettingsMutating] = React.useState<boolean>(false);
  const [securityApprovalIdInput, setSecurityApprovalIdInput] = React.useState<string>('');
  const [appSettings, setAppSettings] = React.useState<DashboardAppSettings | null>(null);
  const [securitySettings, setSecuritySettings] = React.useState<DashboardSecuritySettings | null>(null);
  const [allowedOriginsInput, setAllowedOriginsInput] = React.useState<string[]>([]);
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
  const walletOriginHint = normalizeString(FRONTEND_CONFIG.walletOrigin || 'https://localhost:8443');
  const allowedOriginsDraft = React.useMemo(
    () => parseEditableList(allowedOriginsInput).map((origin) => normalizeString(origin).toLowerCase()),
    [allowedOriginsInput],
  );
  const walletOriginMissingFromDraft = React.useMemo(() => {
    const walletOrigin = normalizeString(walletOriginHint).toLowerCase();
    if (!walletOrigin) return false;
    return !allowedOriginsDraft.includes(walletOrigin);
  }, [allowedOriginsDraft, walletOriginHint]);

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

  const loadContextData = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setOrganization(null);
      setProjects([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    Promise.all([getDashboardOrganization(), listDashboardProjects({ status: 'ACTIVE' })])
      .then(([nextOrg, nextProjects]) => {
        const sortedProjects = [...nextProjects].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        if (cancelled) return;
        setOrganization(nextOrg);
        setProjects(sortedProjects);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setOrganization(null);
        setProjects([]);
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
    session.claims,
    session.errorMessage,
  ]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadContextData();
    return cleanup;
  }, [loadContextData, session.loading]);

  const editingProject = React.useMemo(
    () => projects.find((project) => project.id === editingProjectId) || null,
    [editingProjectId, projects],
  );

  const selectedEnvironmentId = React.useMemo(
    () => normalizeString(selectedContext.environment || ''),
    [selectedContext.environment],
  );

  const applyAppSettingsToForm = React.useCallback((input: DashboardAppSettings) => {
    setAllowedOriginsInput([...input.allowedOrigins]);
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
    const environmentId = selectedEnvironmentId;
    if (!environmentId) {
      setSettingsLoading(false);
      setSettingsError('Select an environment from the top bar to manage app/security settings.');
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
    selectedEnvironmentId,
  ]);

  React.useEffect(() => {
    if (session.loading || loading) return;
    const cleanup = loadSettingsData();
    return cleanup;
  }, [loadSettingsData, loading, session.loading]);

  React.useEffect(() => {
    if (!isEditProjectModalOpen) return;
    if (!editingProject) {
      setIsEditProjectModalOpen(false);
      setEditingProjectId('');
      setEditingProjectName('');
    }
  }, [editingProject, isEditProjectModalOpen]);

  const onOpenCreateProjectModal = React.useCallback(() => {
    setMutationError('');
    setCreateProjectId('');
    setCreateProjectName('');
    setIsCreateProjectModalOpen(true);
  }, []);

  const onCloseCreateProjectModal = React.useCallback(() => {
    if (mutating) return;
    setIsCreateProjectModalOpen(false);
  }, [mutating]);

  const onOpenEditProjectModal = React.useCallback((project: DashboardConsoleProject) => {
    setMutationError('');
    setEditingProjectId(project.id);
    setEditingProjectName(project.name || '');
    setIsEditProjectModalOpen(true);
  }, []);

  const onCloseEditProjectModal = React.useCallback(() => {
    if (mutating) return;
    setIsEditProjectModalOpen(false);
  }, [mutating]);

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
        setIsCreateProjectModalOpen(false);
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

  const onSaveProjectEdits = React.useCallback(
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
      const projectId = normalizeString(editingProjectId);
      const name = normalizeString(editingProjectName);
      if (!projectId || !name) {
        setMutationError('Project and new name are required.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        await updateDashboardProject(projectId, { name });
        setIsEditProjectModalOpen(false);
        await loadContextData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      canMutateContext,
      editingProjectId,
      editingProjectName,
      loadContextData,
      session.claims,
      session.errorMessage,
    ],
  );

  const onArchiveEditingProject = React.useCallback(async () => {
    if (!session.claims) {
      setMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canMutateContext) {
      setMutationError('Only owner/admin roles can archive projects.');
      return;
    }
    const projectId = normalizeString(editingProjectId);
    if (!projectId) {
      setMutationError('Project is required.');
      return;
    }
    if (editingProject?.status === 'ARCHIVED') {
      setMutationError('Project is already archived.');
      return;
    }
    if (!window.confirm(`Archive project ${projectId}? This archives all environments under it.`)) {
      return;
    }
    setMutating(true);
    setMutationError('');
    try {
      await archiveDashboardProject(projectId);
      setIsEditProjectModalOpen(false);
      await loadContextData();
    } catch (error: unknown) {
      setMutationError(error instanceof Error ? error.message : String(error));
    } finally {
      setMutating(false);
    }
  }, [
    canMutateContext,
    editingProject?.status,
    editingProjectId,
    loadContextData,
    session.claims,
    session.errorMessage,
  ]);

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
      const environmentId = selectedEnvironmentId;
      if (!environmentId) {
        setSettingsMutationError('Select an environment from the top bar.');
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
          allowedOrigins: parseEditableList(allowedOriginsInput),
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
      selectedEnvironmentId,
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
      const environmentId = selectedEnvironmentId;
      if (!environmentId) {
        setSettingsMutationError('Select an environment from the top bar.');
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
      selectedEnvironmentId,
    ],
  );

  return (
    <div className="dashboard-view" aria-label="App settings page">
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
            <div className="dashboard-table-limit dashboard-project-table__toolbar">
              <p className="dashboard-project-table__status">Showing ACTIVE projects only.</p>
              <button
                type="button"
                className="dashboard-pagination-button"
                onClick={onOpenCreateProjectModal}
                disabled={!canMutateContext || mutating}
              >
                Create project
              </button>
            </div>
            {mutationError ? <p className="dashboard-table-limit dashboard-project-table__error">{mutationError}</p> : null}
            <div className="dashboard-table-header dashboard-table-header--projects" role="row">
              <span>Project ID</span>
              <span>Name</span>
              <span>Status</span>
              <span>Environment count</span>
              <span>Updated</span>
              <span>Actions</span>
            </div>
            {projects.length === 0 ? (
              <p className="dashboard-table-limit">No projects found.</p>
            ) : (
              <>
                {projects.map((project) => (
                  <div className="dashboard-table-row dashboard-table-row--projects" key={project.id} role="row">
                    <span>{project.id}</span>
                    <span>{project.name || '-'}</span>
                    <span>{project.status}</span>
                    <span>{String(project.environmentCount || 0)}</span>
                    <span>{formatTimestamp(project.updatedAt)}</span>
                    <span className="dashboard-project-table__actions">
                      <button
                        type="button"
                        className="dashboard-pagination-button dashboard-pagination-button--secondary"
                        onClick={() => onOpenEditProjectModal(project)}
                        disabled={!canMutateContext || mutating}
                      >
                        Edit
                      </button>
                    </span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {projects.length} project{projects.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
            <p className="dashboard-table-limit">
              {canMutateContext
                ? 'Owner/admin role enabled for project mutations.'
                : 'Only owner/admin roles can mutate project records.'}
            </p>
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
              <p>App/security settings unavailable for topbar-selected environment.</p>
            </section>
          ) : (
            <>
              <section className="dashboard-table-wrapper" aria-label="Update app settings">
                <div className="dashboard-table-limit">
                  <p className="dashboard-pagination-note">
                    Editing app/security settings for <code>{selectedEnvironmentId}</code>.
                  </p>
                  <p className="dashboard-pagination-note">
                    {canMutateConsoleSettings
                      ? 'Owner/admin/security_admin role enabled for settings mutations.'
                      : 'Only owner/admin/security_admin can mutate settings.'}
                  </p>
                  {settingsMutationError ? (
                    <p className="dashboard-pagination-note">{settingsMutationError}</p>
                  ) : null}
                  <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onUpdateAppSettings}>
                    <div className="dashboard-form-field dashboard-form-field--full">
                      <UriListEditor
                        label="Allowed origins"
                        description={
                          <>
                            <p className="dashboard-pagination-note">
                              Use exact browser origins only. Managed registration runs from the
                              wallet origin, not the app origin.
                            </p>
                            <p className="dashboard-pagination-note">
                              In this local dev setup, include <code>{walletOriginHint}</code>.
                            </p>
                            {walletOriginMissingFromDraft ? (
                              <p className="dashboard-pagination-note">
                                Current draft is missing <code>{walletOriginHint}</code>, so
                                publishable_key registration will be rejected.
                              </p>
                            ) : null}
                          </>
                        }
                        values={allowedOriginsInput}
                        onChange={setAllowedOriginsInput}
                        placeholder="https://app.example.com"
                        addLabel="Add URI"
                        disabled={!canMutateConsoleSettings || settingsMutating}
                      />
                    </div>
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
                  <span>IP allowlist entries</span>
                  <span>Require risky-change MFA</span>
                  <span>Approvals required</span>
                </div>
                <div className="dashboard-table-row" role="row">
                  <span>{selectedEnvironmentId || '-'}</span>
                  <span>{formatTimestamp(appSettings.updatedAt)}</span>
                  <span>{formatTimestamp(securitySettings.updatedAt)}</span>
                  <span>{appSettings.allowedOrigins.length}</span>
                  <span>{securitySettings.ipAllowlist.length}</span>
                  <span>{securitySettings.requireMfaForRiskyChanges ? 'true' : 'false'}</span>
                  <span>{securitySettings.riskyChangeApproval.approvalsRequired}</span>
                </div>
              </section>

            </>
          )}

          {isCreateProjectModalOpen ? (
            <div
              className="dashboard-modal-backdrop"
              role="presentation"
              onClick={onCloseCreateProjectModal}
            >
              <section
                className="dashboard-modal"
                role="dialog"
                aria-modal="true"
                aria-label="Create project modal"
                onClick={(event) => event.stopPropagation()}
              >
                <h2>Create project</h2>
                <form className="dashboard-view-grid" onSubmit={onCreateProject}>
                  <label className="dashboard-form-field">
                    <span>Project ID (optional)</span>
                    <input
                      className="dashboard-input"
                      value={createProjectId}
                      onChange={(event) => setCreateProjectId(event.target.value)}
                      placeholder="proj_prod"
                      disabled={!canMutateContext || mutating}
                    />
                  </label>
                  <label className="dashboard-form-field">
                    <span>Project name</span>
                    <input
                      className="dashboard-input"
                      value={createProjectName}
                      onChange={(event) => setCreateProjectName(event.target.value)}
                      placeholder="Production"
                      disabled={!canMutateContext || mutating}
                    />
                  </label>
                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={onCloseCreateProjectModal}
                      disabled={mutating}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="dashboard-pagination-button"
                      disabled={!canMutateContext || mutating}
                    >
                      {mutating ? 'Applying...' : 'Create project'}
                    </button>
                  </div>
                </form>
              </section>
            </div>
          ) : null}

          {isEditProjectModalOpen && editingProject ? (
            <div
              className="dashboard-modal-backdrop"
              role="presentation"
              onClick={onCloseEditProjectModal}
            >
              <section
                className="dashboard-modal"
                role="dialog"
                aria-modal="true"
                aria-label="Edit project modal"
                onClick={(event) => event.stopPropagation()}
              >
                <h2>Edit project</h2>
                <p className="dashboard-pagination-note">Project ID: {editingProject.id}</p>
                <p className="dashboard-pagination-note">Status: {editingProject.status}</p>
                <form className="dashboard-view-grid" onSubmit={onSaveProjectEdits}>
                  <label className="dashboard-form-field">
                    <span>Project name</span>
                    <input
                      className="dashboard-input"
                      value={editingProjectName}
                      onChange={(event) => setEditingProjectName(event.target.value)}
                      placeholder="Project display name"
                      disabled={!canMutateContext || mutating}
                    />
                  </label>
                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={onCloseEditProjectModal}
                      disabled={mutating}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="dashboard-pagination-button"
                      disabled={!canMutateContext || mutating || editingProject.status === 'ARCHIVED'}
                    >
                      {mutating ? 'Applying...' : 'Save changes'}
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={onArchiveEditingProject}
                      disabled={!canMutateContext || mutating || editingProject.status === 'ARCHIVED'}
                    >
                      {mutating ? 'Applying...' : 'Archive project'}
                    </button>
                  </div>
                </form>
              </section>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

export default AppSettingsPage;
