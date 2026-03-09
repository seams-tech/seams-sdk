import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { useDashboardConsoleSession } from '../../consoleSession';
import { persistDashboardSelectedContext } from '../../useDashboardUiPreferences';
import {
  createDashboardOnboardingOrganization,
  createDashboardOnboardingProject,
  getDashboardOnboardingState,
  DashboardConsoleApiError,
  type DashboardCreateOnboardingOrganizationResult,
  type DashboardCreateOnboardingProjectResult,
  type DashboardOnboardingState,
  type DashboardOnboardingStep,
} from './consoleOnboardingApi';

const RESOURCE_ID_PATTERN = /^[A-Za-z0-9:_-]+$/;
const ONBOARDING_DRAFT_STORAGE_PREFIX = 'tatchi-dashboard-onboarding-draft-v1:';
const DEFAULT_DEVELOPMENT_ENVIRONMENT_NAME = 'Development';
const ONBOARDING_STATE_UPDATED_EVENT = 'dashboard:onboarding-state-updated';

type OnboardingMutationAction = 'organization' | 'project';

type OnboardingDraft = {
  orgNameInput: string;
  orgSlugInput: string;
  orgNameConfirmed: boolean;
  projectNameInput: string;
  projectIdInput: string;
  environmentIdInput: string;
  showOrganizationOptionalFields: boolean;
  showProjectOptionalFields: boolean;
};

type OnboardingStepperStatus = 'current' | 'done' | 'locked';

function buildDefaultState(orgId: string): DashboardOnboardingState {
  return {
    orgId,
    organization: null,
    activeProjectCount: 0,
    activeEnvironmentCount: 0,
    activeApiKeyCount: 0,
    hasOrganization: false,
    hasProject: false,
    hasEnvironment: false,
    hasApiKey: false,
    accountReady: true,
    organizationReady: false,
    billingReady: false,
    projectReady: false,
    onboardingComplete: false,
    currentStep: 'organization',
    complete: false,
    selectedProjectId: null,
    selectedEnvironmentId: null,
  };
}

function hasConfiguredOrganizationName(state: DashboardOnboardingState | null): boolean {
  if (!state) return false;
  const organizationName = String(state.organization?.name || '').trim();
  if (!organizationName) return false;
  return organizationName !== String(state.orgId || '').trim();
}

function resolveCurrentStep(state: DashboardOnboardingState | null): DashboardOnboardingStep {
  if (!state) return 'organization';
  const onboardingComplete =
    state.onboardingComplete === undefined ? state.complete === true : state.onboardingComplete;
  if (onboardingComplete) return 'complete';
  if (!state.organizationReady || !hasConfiguredOrganizationName(state)) return 'organization';
  return 'project';
}

function readOnboardingDraft(storageKey: string): OnboardingDraft | null {
  if (typeof window === 'undefined') return null;
  if (!storageKey) return null;
  try {
    const raw = window.localStorage.getItem(storageKey);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const row = parsed as Record<string, unknown>;
    return {
      orgNameInput: String(row.orgNameInput || '').trim(),
      orgSlugInput: String(row.orgSlugInput || '').trim(),
      orgNameConfirmed: row.orgNameConfirmed === true,
      projectNameInput: String(row.projectNameInput || '').trim(),
      projectIdInput: String(row.projectIdInput || '').trim(),
      environmentIdInput: String(row.environmentIdInput || '').trim(),
      showOrganizationOptionalFields: row.showOrganizationOptionalFields === true,
      showProjectOptionalFields: row.showProjectOptionalFields === true,
    };
  } catch {
    return null;
  }
}

function writeOnboardingDraft(storageKey: string, draft: OnboardingDraft): void {
  if (typeof window === 'undefined') return;
  if (!storageKey) return;
  try {
    window.localStorage.setItem(storageKey, JSON.stringify(draft));
  } catch {}
}

function clearOnboardingDraft(storageKey: string): void {
  if (typeof window === 'undefined') return;
  if (!storageKey) return;
  try {
    window.localStorage.removeItem(storageKey);
  } catch {}
}

function validateOrganizationName(value: string): string {
  const trimmed = String(value || '').trim();
  if (!trimmed) return 'Organization name is required.';
  if (trimmed.length < 2) return 'Organization name must be at least 2 characters.';
  if (trimmed.length > 80) return 'Organization name must be 80 characters or fewer.';
  return '';
}

function validateProjectName(value: string): string {
  const trimmed = String(value || '').trim();
  if (!trimmed) return 'Project name is required.';
  if (trimmed.length > 80) return 'Project name must be 80 characters or fewer.';
  return '';
}

function validateOptionalResourceId(value: string, label: string): string {
  const trimmed = String(value || '').trim();
  if (!trimmed) return '';
  if (!RESOURCE_ID_PATTERN.test(trimmed)) {
    return `${label} may only contain letters, numbers, colon (:), underscore (_), and hyphen (-).`;
  }
  return '';
}

function resolveActionableMutationError(error: unknown): string {
  if (error instanceof DashboardConsoleApiError) {
    if (error.code === 'forbidden' || error.status === 403) {
      return 'Permission missing. Ask an organization owner/admin for onboarding access and retry.';
    }
    if (error.code === 'invalid_body') {
      return 'Invalid ID format. Use only letters, numbers, colon (:), underscore (_), and hyphen (-).';
    }
    if (error.code === 'project_already_exists' || error.code === 'environment_already_exists') {
      return 'Name already used. Choose a different project or environment ID and retry.';
    }
    if (error.code === 'environment_key_conflict') {
      return 'Name already used. Development environment already exists for this project.';
    }
    if (error.code === 'organization_required') {
      return 'Name your organization before creating your first project.';
    }
    if (error.code === 'project_archived' || error.code === 'environment_archived') {
      return 'Name already used. That ID belongs to an archived resource, so choose a new ID.';
    }
  }

  const message =
    error instanceof Error ? String(error.message || '').trim() : String(error || '').trim();
  if (!message) return 'Request failed. Update the inputs and retry.';
  if (/already exists|already used|conflict/i.test(message)) {
    return 'Name already used. Choose a different value and retry.';
  }
  if (/invalid|may only contain/i.test(message)) {
    return 'Invalid ID format. Use only letters, numbers, colon (:), underscore (_), and hyphen (-).';
  }
  if (/forbidden|permission|unauthorized/i.test(message)) {
    return 'Permission missing. Ask an organization owner/admin for onboarding access and retry.';
  }
  return message;
}

function stepperStatusLabel(status: OnboardingStepperStatus): string {
  if (status === 'current') return 'Current';
  if (status === 'done') return 'Done';
  return 'Locked';
}

function publishOnboardingStateUpdate(state: DashboardOnboardingState): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(
    new CustomEvent<DashboardOnboardingState>(ONBOARDING_STATE_UPDATED_EVENT, {
      detail: state,
    }),
  );
}

export function DashboardOnboardingPage(): React.JSX.Element {
  const { go } = useSiteRouter();
  const session = useDashboardConsoleSession();
  const sessionOrgId = String(session.claims?.orgId || '').trim();
  const [loading, setLoading] = React.useState<boolean>(true);
  const [state, setState] = React.useState<DashboardOnboardingState | null>(null);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [lastFailedAction, setLastFailedAction] = React.useState<OnboardingMutationAction | null>(
    null,
  );
  const [submitting, setSubmitting] = React.useState<boolean>(false);
  const [organizationResult, setOrganizationResult] =
    React.useState<DashboardCreateOnboardingOrganizationResult | null>(null);
  const [projectResult, setProjectResult] =
    React.useState<DashboardCreateOnboardingProjectResult | null>(null);
  const [orgNameInput, setOrgNameInput] = React.useState<string>('');
  const [orgSlugInput, setOrgSlugInput] = React.useState<string>('');
  const [orgNameConfirmed, setOrgNameConfirmed] = React.useState<boolean>(false);
  const [projectIdInput, setProjectIdInput] = React.useState<string>('');
  const [projectNameInput, setProjectNameInput] = React.useState<string>('');
  const [environmentIdInput, setEnvironmentIdInput] = React.useState<string>('');
  const [showOrganizationOptionalFields, setShowOrganizationOptionalFields] =
    React.useState<boolean>(false);
  const [showProjectOptionalFields, setShowProjectOptionalFields] = React.useState<boolean>(false);
  const [loadedDraftStorageKey, setLoadedDraftStorageKey] = React.useState<string>('');

  const draftStorageKey = React.useMemo(() => {
    if (!sessionOrgId) return '';
    return `${ONBOARDING_DRAFT_STORAGE_PREFIX}${sessionOrgId}`;
  }, [sessionOrgId]);

  const loadState = React.useCallback(() => {
    if (!sessionOrgId) {
      setState(null);
      setLoading(false);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    getDashboardOnboardingState()
      .then((nextState) => {
        if (cancelled) return;
        setState(nextState);
        setOrgNameInput((current) => current || String(nextState.organization?.name || '').trim());
        setOrgSlugInput((current) => current || String(nextState.organization?.slug || '').trim());
        setProjectIdInput((current) => current || String(nextState.selectedProjectId || '').trim());
        setEnvironmentIdInput(
          (current) => current || String(nextState.selectedEnvironmentId || '').trim(),
        );
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setState(buildDefaultState(sessionOrgId));
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [session.errorMessage, sessionOrgId]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadState();
    return cleanup;
  }, [loadState, session.loading]);

  React.useEffect(() => {
    if (!draftStorageKey) {
      setLoadedDraftStorageKey('');
      return;
    }
    if (loadedDraftStorageKey === draftStorageKey) return;
    const draft = readOnboardingDraft(draftStorageKey);
    if (draft) {
      setOrgNameInput(draft.orgNameInput);
      setOrgSlugInput(draft.orgSlugInput);
      setOrgNameConfirmed(draft.orgNameConfirmed);
      setProjectNameInput(draft.projectNameInput);
      setProjectIdInput(draft.projectIdInput);
      setEnvironmentIdInput(draft.environmentIdInput);
      setShowOrganizationOptionalFields(draft.showOrganizationOptionalFields);
      setShowProjectOptionalFields(draft.showProjectOptionalFields);
    }
    setLoadedDraftStorageKey(draftStorageKey);
  }, [draftStorageKey, loadedDraftStorageKey]);

  const orgNameValidationMessage = validateOrganizationName(orgNameInput);
  const projectNameValidationMessage = validateProjectName(projectNameInput);
  const projectIdValidationMessage = validateOptionalResourceId(projectIdInput, 'Project ID');
  const environmentIdValidationMessage = validateOptionalResourceId(
    environmentIdInput,
    'Environment ID',
  );

  const submitOrganizationStep = React.useCallback(async () => {
    if (!session.claims) {
      setMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (orgNameValidationMessage) {
      setMutationError(orgNameValidationMessage);
      return;
    }
    if (!orgNameConfirmed) {
      setMutationError('Confirm the organization name before continuing.');
      return;
    }
    const orgName = String(orgNameInput || '').trim();
    const orgSlug = String(orgSlugInput || '').trim();

    setSubmitting(true);
    setMutationError('');
    try {
      const next = await createDashboardOnboardingOrganization({
        org: { name: orgName, ...(orgSlug ? { slug: orgSlug } : {}) },
      });
      setOrganizationResult(next);
      setProjectResult(null);
      setLastFailedAction(null);
      setState(next.state);
      publishOnboardingStateUpdate(next.state);
      loadState();
    } catch (error: unknown) {
      setMutationError(resolveActionableMutationError(error));
      setLastFailedAction('organization');
    } finally {
      setSubmitting(false);
    }
  }, [
    loadState,
    orgNameConfirmed,
    orgNameInput,
    orgNameValidationMessage,
    orgSlugInput,
    session.claims,
    session.errorMessage,
  ]);

  const submitProjectStep = React.useCallback(async () => {
    if (!session.claims) {
      setMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (projectNameValidationMessage) {
      setMutationError(projectNameValidationMessage);
      return;
    }
    if (projectIdValidationMessage) {
      setMutationError(projectIdValidationMessage);
      return;
    }
    if (environmentIdValidationMessage) {
      setMutationError(environmentIdValidationMessage);
      return;
    }

    const projectName = String(projectNameInput || '').trim();
    const projectId = String(projectIdInput || '').trim();
    const environmentId = String(environmentIdInput || '').trim();

    setSubmitting(true);
    setMutationError('');
    try {
      const next = await createDashboardOnboardingProject({
        project: {
          ...(projectId ? { id: projectId } : {}),
          name: projectName,
        },
        ...(environmentId
          ? {
              environment: {
                id: environmentId,
                name: DEFAULT_DEVELOPMENT_ENVIRONMENT_NAME,
              },
            }
          : {}),
      });
      setProjectResult(next);
      setLastFailedAction(null);
      setState(next.state);
      publishOnboardingStateUpdate(next.state);
      loadState();
    } catch (error: unknown) {
      setMutationError(resolveActionableMutationError(error));
      setLastFailedAction('project');
    } finally {
      setSubmitting(false);
    }
  }, [
    environmentIdInput,
    environmentIdValidationMessage,
    loadState,
    projectIdInput,
    projectIdValidationMessage,
    projectNameInput,
    projectNameValidationMessage,
    session.claims,
    session.errorMessage,
  ]);

  const onSubmitOrganization = React.useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      void submitOrganizationStep();
    },
    [submitOrganizationStep],
  );

  const onSubmitProjectStep = React.useCallback(
    (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      void submitProjectStep();
    },
    [submitProjectStep],
  );

  const onRetryFailedMutation = React.useCallback(() => {
    if (lastFailedAction === 'organization') {
      void submitOrganizationStep();
      return;
    }
    if (lastFailedAction === 'project') {
      void submitProjectStep();
    }
  }, [lastFailedAction, submitOrganizationStep, submitProjectStep]);

  const onboardingComplete = state
    ? state.onboardingComplete === undefined
      ? state.complete === true
      : state.onboardingComplete
    : false;

  React.useEffect(() => {
    if (!draftStorageKey) return;
    if (onboardingComplete) {
      clearOnboardingDraft(draftStorageKey);
      return;
    }
    if (loadedDraftStorageKey !== draftStorageKey) return;
    writeOnboardingDraft(draftStorageKey, {
      orgNameInput: String(orgNameInput || '').trim(),
      orgSlugInput: String(orgSlugInput || '').trim(),
      orgNameConfirmed,
      projectNameInput: String(projectNameInput || '').trim(),
      projectIdInput: String(projectIdInput || '').trim(),
      environmentIdInput: String(environmentIdInput || '').trim(),
      showOrganizationOptionalFields,
      showProjectOptionalFields,
    });
  }, [
    draftStorageKey,
    environmentIdInput,
    loadedDraftStorageKey,
    onboardingComplete,
    orgNameConfirmed,
    orgNameInput,
    orgSlugInput,
    projectIdInput,
    projectNameInput,
    showOrganizationOptionalFields,
    showProjectOptionalFields,
  ]);

  const currentStep = resolveCurrentStep(state);
  const organizationProfileReady =
    state?.organizationReady === true && hasConfiguredOrganizationName(state);
  const projectProfileReady = state?.projectReady === true;
  const completionProjectId = String(
    state?.selectedProjectId || projectResult?.project.id || '',
  ).trim();
  const completionEnvironmentId = String(
    state?.selectedEnvironmentId || projectResult?.environment.id || '',
  ).trim();
  const completionOrgId = String(state?.orgId || session.claims?.orgId || '').trim();
  const completionOrgName = String(
    state?.organization?.name || organizationResult?.organization.name || completionOrgId,
  ).trim();

  const persistCompletionContextSelection = React.useCallback(() => {
    persistDashboardSelectedContext({
      organization: completionOrgId,
      project: completionProjectId,
      environment: completionEnvironmentId,
    });
  }, [completionEnvironmentId, completionOrgId, completionProjectId]);

  const showOrganizationStep = !onboardingComplete && currentStep === 'organization';
  const showProjectStep = !onboardingComplete && currentStep === 'project';

  const stepper: Array<{
    key: DashboardOnboardingStep;
    label: string;
    status: OnboardingStepperStatus;
  }> = [
    {
      key: 'organization',
      label: 'Organization',
      status: organizationProfileReady
        ? 'done'
        : currentStep === 'organization'
          ? 'current'
          : 'locked',
    },
    {
      key: 'project',
      label: 'Project',
      status: projectProfileReady ? 'done' : currentStep === 'project' ? 'current' : 'locked',
    },
    {
      key: 'complete',
      label: 'Complete',
      status: onboardingComplete ? 'current' : 'locked',
    },
  ];

  const organizationSubmitDisabled =
    submitting || Boolean(orgNameValidationMessage) || !orgNameConfirmed;
  const projectSubmitDisabled =
    submitting ||
    Boolean(projectNameValidationMessage) ||
    Boolean(projectIdValidationMessage) ||
    Boolean(environmentIdValidationMessage) ||
    state?.projectReady === true;

  return (
    <div className="dashboard-view" aria-label="Onboarding wizard page">
      <section className="dashboard-view__section" aria-label="Onboarding summary">
        <h2>Set up your workspace</h2>
        <p>Complete organization and project setup to unlock full dashboard navigation.</p>
        {session.loading || loading ? (
          <p className="dashboard-pagination-note">Loading onboarding status...</p>
        ) : !session.claims ? (
          <p className="dashboard-pagination-note">
            Onboarding unavailable: {session.errorMessage || 'unauthorized'}.
          </p>
        ) : errorMessage ? (
          <p className="dashboard-pagination-note">Onboarding status unavailable: {errorMessage}</p>
        ) : state ? (
          <>
            <ol className="dashboard-onboarding-stepper" aria-label="Onboarding progress">
              {stepper.map((entry, index) => (
                <li
                  key={entry.key}
                  className={`dashboard-onboarding-stepper__item dashboard-onboarding-stepper__item--${entry.status}`}
                >
                  <span className="dashboard-onboarding-stepper__index" aria-hidden="true">
                    {index + 1}
                  </span>
                  <span className="dashboard-onboarding-stepper__label">{entry.label}</span>
                  <span className="dashboard-onboarding-stepper__status">
                    {stepperStatusLabel(entry.status)}
                  </span>
                </li>
              ))}
            </ol>
            <p className="dashboard-pagination-note">
              Billing is optional during onboarding. Add billing later to unlock staging and
              production environments.
            </p>
          </>
        ) : null}
      </section>

      {onboardingComplete ? (
        <section className="dashboard-view__section" aria-label="Onboarding completed">
          <h2>Onboarding complete</h2>
          <p>Your organization and first Development environment are ready.</p>
          <ul className="dashboard-metadata-list">
            <li>Organization: {completionOrgName || completionOrgId || '—'}</li>
            <li>Project: {completionProjectId || '—'}</li>
            <li>Environment: {completionEnvironmentId || '—'}</li>
          </ul>
          <div className="dashboard-form-actions">
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={() => {
                persistCompletionContextSelection();
                go('/dashboard/wallets-list');
              }}
            >
              Go to wallets
            </button>
            <button
              type="button"
              className="dashboard-pagination-button dashboard-pagination-button--secondary"
              onClick={() => {
                persistCompletionContextSelection();
                go('/dashboard/api-keys');
              }}
            >
              Go to credentials
            </button>
          </div>
        </section>
      ) : (
        <section className="dashboard-view__section" aria-label="Onboarding form">
          {showOrganizationStep ? (
            <>
              <h2>Name your organization</h2>
              <p>Confirm the organization name your team will use in the dashboard.</p>
              <form
                className="dashboard-view-grid dashboard-view-grid--two"
                onSubmit={onSubmitOrganization}
              >
                <label className="dashboard-form-field">
                  <span>Organization name</span>
                  <input
                    className="dashboard-input"
                    value={orgNameInput}
                    onChange={(event) => {
                      setOrgNameInput(event.target.value);
                      setOrgNameConfirmed(false);
                    }}
                    placeholder="Acme Wallets"
                    aria-invalid={Boolean(orgNameValidationMessage)}
                  />
                  <p
                    className={`dashboard-form-hint${orgNameValidationMessage ? ' dashboard-form-hint--error' : ''}`}
                  >
                    {orgNameValidationMessage || 'Use the name customers and teammates recognize.'}
                  </p>
                </label>

                <div className="dashboard-onboarding-optional">
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => setShowOrganizationOptionalFields((current) => !current)}
                  >
                    {showOrganizationOptionalFields
                      ? 'Hide optional organization details'
                      : 'Add optional organization details'}
                  </button>
                  {showOrganizationOptionalFields ? (
                    <label className="dashboard-form-field">
                      <span>Organization slug (optional)</span>
                      <input
                        className="dashboard-input"
                        value={orgSlugInput}
                        onChange={(event) => setOrgSlugInput(event.target.value)}
                        placeholder="acme-wallets"
                      />
                      <p className="dashboard-form-hint">
                        Optional URL-safe slug for organization settings.
                      </p>
                    </label>
                  ) : (
                    <p className="dashboard-form-hint">Optional fields are hidden until needed.</p>
                  )}
                </div>

                <label className="dashboard-onboarding-confirm">
                  <input
                    type="checkbox"
                    checked={orgNameConfirmed}
                    onChange={(event) => setOrgNameConfirmed(event.target.checked)}
                  />
                  <span>I confirm this organization name is correct.</span>
                </label>

                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={organizationSubmitDisabled}
                  >
                    {submitting ? 'Saving organization...' : 'Continue to project setup'}
                  </button>
                </div>
              </form>
              {organizationResult ? (
                <p className="dashboard-pagination-note">
                  Organization configured: <strong>{organizationResult.organization.name}</strong>.
                </p>
              ) : null}
            </>
          ) : null}

          {showProjectStep ? (
            <>
              <h2>Create your first project</h2>
              <p>
                Add your first project. A default <strong>Development</strong> environment will be
                created automatically.
              </p>
              <form
                className="dashboard-view-grid dashboard-view-grid--two"
                onSubmit={onSubmitProjectStep}
              >
                <label className="dashboard-form-field">
                  <span>Project name</span>
                  <input
                    className="dashboard-input"
                    value={projectNameInput}
                    onChange={(event) => setProjectNameInput(event.target.value)}
                    placeholder="Consumer App"
                    aria-invalid={Boolean(projectNameValidationMessage)}
                  />
                  <p
                    className={`dashboard-form-hint${projectNameValidationMessage ? ' dashboard-form-hint--error' : ''}`}
                  >
                    {projectNameValidationMessage ||
                      'Required. You can rename this later from the project dashboard.'}
                  </p>
                </label>

                <div className="dashboard-onboarding-optional">
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => setShowProjectOptionalFields((current) => !current)}
                  >
                    {showProjectOptionalFields ? 'Hide optional IDs' : 'Add optional IDs'}
                  </button>
                  {showProjectOptionalFields ? (
                    <div className="dashboard-view-grid">
                      <label className="dashboard-form-field">
                        <span>Project ID (optional)</span>
                        <input
                          className="dashboard-input"
                          value={projectIdInput}
                          onChange={(event) => setProjectIdInput(event.target.value)}
                          placeholder="proj_consumer"
                          aria-invalid={Boolean(projectIdValidationMessage)}
                        />
                        <p
                          className={`dashboard-form-hint${projectIdValidationMessage ? ' dashboard-form-hint--error' : ''}`}
                        >
                          {projectIdValidationMessage ||
                            'Optional stable identifier for API and automation usage.'}
                        </p>
                      </label>
                      <label className="dashboard-form-field">
                        <span>Environment ID (optional)</span>
                        <input
                          className="dashboard-input"
                          value={environmentIdInput}
                          onChange={(event) => setEnvironmentIdInput(event.target.value)}
                          placeholder="proj_consumer:dev"
                          aria-invalid={Boolean(environmentIdValidationMessage)}
                        />
                        <p
                          className={`dashboard-form-hint${environmentIdValidationMessage ? ' dashboard-form-hint--error' : ''}`}
                        >
                          {environmentIdValidationMessage ||
                            'Optional ID for the default Development environment.'}
                        </p>
                      </label>
                    </div>
                  ) : (
                    <p className="dashboard-form-hint">
                      Optional IDs are collapsed to keep setup focused.
                    </p>
                  )}
                </div>

                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={projectSubmitDisabled}
                  >
                    {submitting ? 'Creating project...' : 'Finish onboarding'}
                  </button>
                </div>
              </form>
              <p className="dashboard-pagination-note">
                Billing is optional for onboarding. Add billing later to create staging/production
                environments.
              </p>
              {projectResult ? (
                <p className="dashboard-pagination-note">
                  Project configured: <strong>{projectResult.project.name}</strong> /{' '}
                  <strong>{projectResult.environment.id}</strong>.
                </p>
              ) : null}
            </>
          ) : null}

          {mutationError ? (
            <div className="dashboard-form-alert" role="alert">
              <span>{mutationError}</span>
              {lastFailedAction ? (
                <button
                  type="button"
                  className="dashboard-inline-link"
                  onClick={onRetryFailedMutation}
                  disabled={submitting}
                >
                  {submitting ? 'Retrying...' : 'Retry'}
                </button>
              ) : null}
            </div>
          ) : null}
        </section>
      )}
    </div>
  );
}

export default DashboardOnboardingPage;
