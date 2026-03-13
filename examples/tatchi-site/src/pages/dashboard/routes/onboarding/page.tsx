import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { useDashboardConsoleSession } from '../../consoleSession';
import {
  clearDashboardUiState,
  persistDashboardSelectedContext,
  replaceDashboardSelectedContext,
} from '../../useDashboardUiPreferences';
import {
  deriveDashboardOrganizationSlug,
  isDashboardDefaultOrganizationName,
} from '../../utils/organizationIdentity';
import {
  createDashboardAccountOrganization,
  switchDashboardAccountOrganizationContext,
} from '../account-settings/consoleAccountApi';
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

const ONBOARDING_DRAFT_STORAGE_PREFIX = 'tatchi-dashboard-onboarding-draft-v1:';
const ONBOARDING_STATE_UPDATED_EVENT = 'dashboard:onboarding-state-updated';
const CREATE_ORGANIZATION_QUERY_PARAM = 'createOrganization';

type OnboardingMutationAction = 'organization' | 'project';

type OnboardingDraft = {
  orgNameInput: string;
  orgNameExplicitlySelected: boolean;
  projectNameInput: string;
};

type OnboardingStepperStatus = 'current' | 'done' | 'locked';
type OnboardingVisibleStep = 'organization' | 'project';

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

function hasConfiguredOrganizationName(
  state: DashboardOnboardingState | null,
  orgNameExplicitlySelected: boolean,
): boolean {
  if (!state) return false;
  const organizationName = String(state.organization?.name || '').trim();
  if (!organizationName) return false;
  if (orgNameExplicitlySelected) return true;
  return !isDashboardDefaultOrganizationName({
    name: organizationName,
    orgId: String(state.orgId || '').trim(),
  });
}

function resolveCurrentStep(
  state: DashboardOnboardingState | null,
  orgNameExplicitlySelected: boolean,
): DashboardOnboardingStep {
  if (!state) return 'organization';
  const onboardingComplete =
    state.onboardingComplete === undefined ? state.complete === true : state.onboardingComplete;
  if (onboardingComplete) return 'complete';
  if (!state.organizationReady || !hasConfiguredOrganizationName(state, orgNameExplicitlySelected))
    return 'organization';
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
      orgNameExplicitlySelected: row.orgNameExplicitlySelected === true,
      projectNameInput: String(row.projectNameInput || '').trim(),
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

function resolveActionableMutationError(error: unknown): string {
  if (error instanceof DashboardConsoleApiError) {
    if (error.code === 'forbidden' || error.status === 403) {
      return 'Permission missing. Ask an organization owner/admin for onboarding access and retry.';
    }
    if (error.code === 'invalid_body') {
      return 'Invalid input format. Update the form values and retry.';
    }
    if (error.code === 'project_already_exists' || error.code === 'environment_already_exists') {
      return 'Name already used. Choose a different project or environment name and retry.';
    }
    if (error.code === 'environment_key_conflict') {
      return 'Name already used. Development environment already exists for this project.';
    }
    if (error.code === 'organization_required') {
      return 'Name your organization before creating your first project.';
    }
    if (error.code === 'project_archived' || error.code === 'environment_archived') {
      return 'Name already used. That name belongs to an archived resource, so choose a new name.';
    }
  }

  const message =
    error instanceof Error ? String(error.message || '').trim() : String(error || '').trim();
  if (!message) return 'Request failed. Update the inputs and retry.';
  if (/already exists|already used|conflict/i.test(message)) {
    return 'Name already used. Choose a different value and retry.';
  }
  if (/invalid|may only contain/i.test(message)) {
    return 'Invalid input format. Update the form values and retry.';
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

function readCreateOrganizationIntent(): boolean {
  if (typeof window === 'undefined') return false;
  const searchParams = new URLSearchParams(window.location.search);
  return String(searchParams.get(CREATE_ORGANIZATION_QUERY_PARAM) || '').trim() === '1';
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
  const [orgNameExplicitlySelected, setOrgNameExplicitlySelected] = React.useState<boolean>(false);
  const [projectNameInput, setProjectNameInput] = React.useState<string>('');
  const [visibleStep, setVisibleStep] = React.useState<OnboardingVisibleStep>('organization');
  const [manualOrganizationStepSelection, setManualOrganizationStepSelection] =
    React.useState<boolean>(false);
  const [loadedDraftStorageKey, setLoadedDraftStorageKey] = React.useState<string>('');
  const [createOrganizationIntent, setCreateOrganizationIntent] = React.useState<boolean>(() =>
    readCreateOrganizationIntent(),
  );

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const syncCreateOrganizationIntent = () => {
      setCreateOrganizationIntent(readCreateOrganizationIntent());
    };
    window.addEventListener('popstate', syncCreateOrganizationIntent);
    window.addEventListener('site:navigate', syncCreateOrganizationIntent as EventListener);
    return () => {
      window.removeEventListener('popstate', syncCreateOrganizationIntent);
      window.removeEventListener('site:navigate', syncCreateOrganizationIntent as EventListener);
    };
  }, []);

  const draftStorageKey = React.useMemo(() => {
    if (!sessionOrgId) return '';
    return `${ONBOARDING_DRAFT_STORAGE_PREFIX}${sessionOrgId}${createOrganizationIntent ? ':create-organization' : ''}`;
  }, [createOrganizationIntent, sessionOrgId]);

  const loadState = React.useCallback(() => {
    if (!sessionOrgId) {
      setState(null);
      setLoading(false);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (createOrganizationIntent) {
      setState(buildDefaultState(sessionOrgId));
      setLoading(false);
      setErrorMessage('');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    getDashboardOnboardingState()
      .then((nextState) => {
        if (cancelled) return;
        setState(nextState);
        const onboardingOrganizationName = String(nextState.organization?.name || '').trim();
        const onboardingOrganizationId = String(nextState.orgId || '').trim();
        const nextOrganizationNameInput =
          onboardingOrganizationName &&
          isDashboardDefaultOrganizationName({
            name: onboardingOrganizationName,
            orgId: onboardingOrganizationId,
          })
            ? ''
            : onboardingOrganizationName;
        setOrgNameInput((current) => {
          const currentName = String(current || '').trim();
          if (!currentName || currentName === 'Acme Corp') {
            return nextOrganizationNameInput;
          }
          return currentName;
        });
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
  }, [createOrganizationIntent, session.errorMessage, sessionOrgId]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadState();
    return cleanup;
  }, [loadState, session.loading]);

  React.useEffect(() => {
    setOrgNameInput('');
    setProjectNameInput('');
    setOrgNameExplicitlySelected(false);
    setOrganizationResult(null);
    setProjectResult(null);
    setMutationError('');
    setLastFailedAction(null);
  }, [sessionOrgId]);

  React.useEffect(() => {
    if (!draftStorageKey) {
      setLoadedDraftStorageKey('');
      return;
    }
    if (loadedDraftStorageKey === draftStorageKey) return;
    const draft = readOnboardingDraft(draftStorageKey);
    if (draft) {
      setOrgNameInput(draft.orgNameInput);
      setOrgNameExplicitlySelected(draft.orgNameExplicitlySelected);
      setProjectNameInput(draft.projectNameInput);
    }
    setLoadedDraftStorageKey(draftStorageKey);
  }, [draftStorageKey, loadedDraftStorageKey]);

  const orgNameValidationMessage = validateOrganizationName(orgNameInput);
  const orgSlugInput = React.useMemo(
    () => deriveDashboardOrganizationSlug(orgNameInput),
    [orgNameInput],
  );
  const projectNameValidationMessage = validateProjectName(projectNameInput);

  const submitOrganizationStep = React.useCallback(async () => {
    if (!session.claims) {
      setMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (orgNameValidationMessage) {
      setMutationError(orgNameValidationMessage);
      return;
    }
    const orgName = String(orgNameInput || '').trim();
    const orgSlug = deriveDashboardOrganizationSlug(orgName);

    setSubmitting(true);
    setMutationError('');
    try {
      if (createOrganizationIntent) {
        const createdOrganization = await createDashboardAccountOrganization({
          name: orgName,
          ...(orgSlug ? { slug: orgSlug } : {}),
        });
        const nextContext = await switchDashboardAccountOrganizationContext(createdOrganization.id);
        clearDashboardUiState();
        replaceDashboardSelectedContext({
          organization: nextContext.orgId,
          project: nextContext.projectId || '',
          environment: nextContext.environmentId || '',
        });
        if (typeof window !== 'undefined') {
          window.location.assign('/dashboard/onboarding');
          return;
        }
        go('/dashboard/onboarding');
        return;
      }
      const next = await createDashboardOnboardingOrganization({
        org: { name: orgName, ...(orgSlug ? { slug: orgSlug } : {}) },
      });
      setOrganizationResult(next);
      setProjectResult(null);
      setLastFailedAction(null);
      setOrgNameExplicitlySelected(true);
      setManualOrganizationStepSelection(false);
      setVisibleStep('project');
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
    createOrganizationIntent,
    go,
    loadState,
    orgNameInput,
    orgNameValidationMessage,
    session.claims,
    session.errorMessage,
  ]);

  const submitProjectStep = React.useCallback(async () => {
    if (!session.claims) {
      setMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (
      !state?.organizationReady ||
      !hasConfiguredOrganizationName(state, orgNameExplicitlySelected)
    ) {
      setMutationError('Complete organization setup before creating your first project.');
      return;
    }
    if (projectNameValidationMessage) {
      setMutationError(projectNameValidationMessage);
      return;
    }

    const projectName = String(projectNameInput || '').trim();

    setSubmitting(true);
    setMutationError('');
    try {
      const next = await createDashboardOnboardingProject({
        project: {
          name: projectName,
        },
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
    loadState,
    orgNameExplicitlySelected,
    projectNameInput,
    projectNameValidationMessage,
    session.claims,
    session.errorMessage,
    state,
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

  const onBackToOrganizationStep = React.useCallback(() => {
    if (submitting) return;
    setMutationError('');
    setLastFailedAction(null);
    setManualOrganizationStepSelection(true);
    setVisibleStep('organization');
  }, [submitting]);

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
      orgNameExplicitlySelected,
      projectNameInput: String(projectNameInput || '').trim(),
    });
  }, [
    draftStorageKey,
    loadedDraftStorageKey,
    onboardingComplete,
    orgNameExplicitlySelected,
    orgNameInput,
    projectNameInput,
  ]);

  const currentStep = resolveCurrentStep(state, orgNameExplicitlySelected);
  const organizationProfileReady =
    state?.organizationReady === true &&
    hasConfiguredOrganizationName(state, orgNameExplicitlySelected);
  const projectStepLocked = !organizationProfileReady;
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

  React.useEffect(() => {
    setVisibleStep('organization');
    setManualOrganizationStepSelection(false);
  }, [createOrganizationIntent, sessionOrgId]);

  React.useEffect(() => {
    if (onboardingComplete) return;
    if (currentStep === 'organization') {
      setVisibleStep('organization');
      setManualOrganizationStepSelection(false);
      return;
    }
    if (!manualOrganizationStepSelection) {
      setVisibleStep('project');
    }
  }, [currentStep, manualOrganizationStepSelection, onboardingComplete]);

  const persistCompletionContextSelection = React.useCallback(() => {
    persistDashboardSelectedContext({
      organization: completionOrgId,
      project: completionProjectId,
      environment: completionEnvironmentId,
    });
  }, [completionEnvironmentId, completionOrgId, completionProjectId]);

  const showOrganizationStep = !onboardingComplete && visibleStep === 'organization';
  const showProjectStep = !onboardingComplete && visibleStep === 'project';
  const projectNameValidationMessageForUi = projectStepLocked ? '' : projectNameValidationMessage;

  const stepper: Array<{
    key: DashboardOnboardingStep;
    label: string;
    status: OnboardingStepperStatus;
  }> = [
    {
      key: 'organization',
      label: 'Organization',
      status: organizationProfileReady
        ? visibleStep === 'organization'
          ? 'current'
          : 'done'
        : 'current',
    },
    {
      key: 'project',
      label: 'Project',
      status: projectProfileReady ? 'done' : visibleStep === 'project' ? 'current' : 'locked',
    },
  ];

  const organizationSubmitDisabled = submitting || Boolean(orgNameValidationMessage);
  const projectSubmitDisabled =
    submitting ||
    projectStepLocked ||
    Boolean(projectNameValidationMessage) ||
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
            <section className="dashboard-onboarding-panel" aria-label="Create organization">
              <h2>Name your organization</h2>
              <p className="dashboard-onboarding-panel__lead">
                Confirm the organization name your team will use in the dashboard.
              </p>
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
                      setOrgNameExplicitlySelected(false);
                    }}
                    placeholder="Acme Wallets"
                    aria-invalid={Boolean(orgNameValidationMessage)}
                  />
                  {orgNameValidationMessage ? (
                    <p className="dashboard-form-hint dashboard-form-hint--error">
                      {orgNameValidationMessage}
                    </p>
                  ) : null}
                </label>

                <div className="dashboard-onboarding-optional">
                  <label className="dashboard-form-field">
                    <span>Organization slug</span>
                    <input
                      className="dashboard-input"
                      value={orgSlugInput}
                      disabled
                      placeholder="acme-wallets"
                    />
                  </label>
                </div>

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
            </section>
          ) : null}

          {showProjectStep ? (
            <section
              className={`dashboard-onboarding-panel${projectStepLocked ? ' dashboard-onboarding-panel--locked' : ''}`}
              aria-label="Create project"
              aria-disabled={projectStepLocked}
            >
              <h2>Create your first project</h2>
              <p className="dashboard-onboarding-panel__lead">
                Add your first project. A default <strong>Development</strong> environment will be
                created automatically.
              </p>
              <form
                className="dashboard-view-grid dashboard-view-grid--two"
                onSubmit={onSubmitProjectStep}
              >
                <fieldset
                  className="dashboard-onboarding-panel__fieldset dashboard-view-grid"
                  disabled={projectStepLocked || state?.projectReady === true}
                >
                  <label className="dashboard-form-field dashboard-form-field--full">
                    <span>Project name</span>
                    <input
                      className="dashboard-input"
                      value={projectNameInput}
                      onChange={(event) => setProjectNameInput(event.target.value)}
                      placeholder="Consumer App"
                      aria-invalid={Boolean(projectNameValidationMessageForUi)}
                    />
                    <p
                      className={`dashboard-form-hint${projectNameValidationMessageForUi ? ' dashboard-form-hint--error' : ''}`}
                    >
                      {projectNameValidationMessageForUi ||
                        'Required. You can rename this later from the project dashboard.'}
                    </p>
                  </label>

                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={onBackToOrganizationStep}
                      disabled={submitting}
                    >
                      Back
                    </button>
                    <button
                      type="submit"
                      className="dashboard-pagination-button"
                      disabled={projectSubmitDisabled}
                    >
                      {submitting ? 'Creating project...' : 'Finish onboarding'}
                    </button>
                  </div>
                </fieldset>
              </form>
              {projectResult ? (
                <p className="dashboard-pagination-note">
                  Project configured: <strong>{projectResult.project.name}</strong> /{' '}
                  <strong>{projectResult.environment.id}</strong>.
                </p>
              ) : null}
            </section>
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
