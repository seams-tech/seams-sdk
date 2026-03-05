import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { useDashboardConsoleSession } from '../../consoleSession';
import { persistDashboardSelectedContext } from '../../useDashboardUiPreferences';
import {
  createDashboardOnboardingOrganization,
  createDashboardOnboardingProject,
  getDashboardOnboardingState,
  type DashboardCreateOnboardingOrganizationResult,
  type DashboardCreateOnboardingProjectResult,
  type DashboardOnboardingState,
  type DashboardOnboardingStep,
} from './consoleOnboardingApi';

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

function resolveCurrentStep(state: DashboardOnboardingState | null): DashboardOnboardingStep {
  if (!state) return 'organization';
  const onboardingComplete =
    state.onboardingComplete === undefined ? state.complete === true : state.onboardingComplete;
  if (onboardingComplete) return 'complete';
  if (!state.organizationReady) return 'organization';
  return 'project';
}

export function DashboardOnboardingPage(): React.JSX.Element {
  const { go } = useSiteRouter();
  const session = useDashboardConsoleSession();
  const completionRedirectStartedRef = React.useRef<boolean>(false);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [state, setState] = React.useState<DashboardOnboardingState | null>(null);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [submitting, setSubmitting] = React.useState<boolean>(false);
  const [organizationResult, setOrganizationResult] =
    React.useState<DashboardCreateOnboardingOrganizationResult | null>(null);
  const [projectResult, setProjectResult] =
    React.useState<DashboardCreateOnboardingProjectResult | null>(null);
  const [orgNameInput, setOrgNameInput] = React.useState<string>('');
  const [orgSlugInput, setOrgSlugInput] = React.useState<string>('');
  const [projectIdInput, setProjectIdInput] = React.useState<string>('');
  const [projectNameInput, setProjectNameInput] = React.useState<string>('');
  const [environmentIdInput, setEnvironmentIdInput] = React.useState<string>('');
  const [environmentNameInput, setEnvironmentNameInput] = React.useState<string>('');

  const loadState = React.useCallback(() => {
    const claims = session.claims;
    if (!claims) {
      setState(null);
      setLoading(false);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    const orgId = String(claims.orgId || '').trim();
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    getDashboardOnboardingState()
      .then((nextState) => {
        if (cancelled) return;
        setState(nextState);
        if (!projectIdInput && nextState.selectedProjectId) {
          setProjectIdInput(nextState.selectedProjectId);
        }
        if (!environmentIdInput && nextState.selectedEnvironmentId) {
          setEnvironmentIdInput(nextState.selectedEnvironmentId);
        }
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setState(buildDefaultState(orgId));
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [environmentIdInput, projectIdInput, session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadState();
    return cleanup;
  }, [loadState, session.loading]);

  const onSubmitOrganization = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const orgName = String(orgNameInput || '').trim();
      const orgSlug = String(orgSlugInput || '').trim();
      if (!orgName) {
        setMutationError('Organization name is required.');
        return;
      }
      setSubmitting(true);
      setMutationError('');
      try {
        const next = await createDashboardOnboardingOrganization({
          org: { name: orgName, ...(orgSlug ? { slug: orgSlug } : {}) },
        });
        setOrganizationResult(next);
        setProjectResult(null);
        setState(next.state);
        loadState();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setSubmitting(false);
      }
    },
    [loadState, orgNameInput, orgSlugInput, session.claims, session.errorMessage],
  );

  const onSubmitProjectStep = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const projectName = String(projectNameInput || '').trim();
      const projectId = String(projectIdInput || '').trim();
      const environmentId = String(environmentIdInput || '').trim();
      const environmentName = String(environmentNameInput || '').trim();
      if (!projectName) {
        setMutationError('Project name is required.');
        return;
      }

      setSubmitting(true);
      setMutationError('');
      try {
        const next = await createDashboardOnboardingProject({
          project: {
            ...(projectId ? { id: projectId } : {}),
            name: projectName,
          },
          ...(environmentId || environmentName
            ? {
                environment: {
                  ...(environmentId ? { id: environmentId } : {}),
                  ...(environmentName ? { name: environmentName } : {}),
                },
              }
            : {}),
        });
        setProjectResult(next);
        setState(next.state);
        loadState();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setSubmitting(false);
      }
    },
    [
      environmentIdInput,
      environmentNameInput,
      loadState,
      projectIdInput,
      projectNameInput,
      session.claims,
      session.errorMessage,
    ],
  );

  const onboardingComplete =
    state?.onboardingComplete === undefined ? state?.complete === true : state?.onboardingComplete;
  const currentStep = resolveCurrentStep(state);
  const completionProjectId = String(state?.selectedProjectId || projectResult?.project.id || '').trim();
  const completionEnvironmentId = String(
    state?.selectedEnvironmentId || projectResult?.environment.id || '',
  ).trim();
  const completionOrgId = String(state?.orgId || session.claims?.orgId || '').trim();
  const completionWalletRedirectPath = '/dashboard/wallets-list';
  const persistCompletionContextSelection = React.useCallback(() => {
    persistDashboardSelectedContext({
      organization: completionOrgId,
      project: completionProjectId,
      environment: completionEnvironmentId,
    });
  }, [completionEnvironmentId, completionOrgId, completionProjectId]);

  React.useEffect(() => {
    if (!onboardingComplete || session.loading || loading || submitting) {
      if (!onboardingComplete) completionRedirectStartedRef.current = false;
      return;
    }
    if (completionRedirectStartedRef.current) return;
    completionRedirectStartedRef.current = true;
    persistCompletionContextSelection();
    go(completionWalletRedirectPath);
  }, [
    completionWalletRedirectPath,
    go,
    loading,
    onboardingComplete,
    persistCompletionContextSelection,
    session.loading,
    submitting,
  ]);

  const showOrganizationStep = !onboardingComplete && currentStep === 'organization';
  const showProjectStep = !onboardingComplete && currentStep === 'project';

  return (
    <div className="dashboard-view" aria-label="Onboarding wizard page">
      <section className="dashboard-view__section" aria-label="Onboarding summary">
        <h2>First-run onboarding wizard</h2>
        <p>Set up organization and first project. Billing can be added later to unlock live environments.</p>
        {session.loading || loading ? (
          <p className="dashboard-pagination-note">Loading onboarding status...</p>
        ) : !session.claims ? (
          <p className="dashboard-pagination-note">
            Onboarding unavailable: {session.errorMessage || 'unauthorized'}.
          </p>
        ) : errorMessage ? (
          <p className="dashboard-pagination-note">Onboarding status unavailable: {errorMessage}</p>
        ) : state ? (
          <ul className="dashboard-metadata-list">
            <li>Organization: {state.organizationReady ? 'done' : currentStep === 'organization' ? 'current' : 'locked'}</li>
            <li>Development project: {state.projectReady ? 'done' : currentStep === 'project' ? 'current' : 'locked'}</li>
            <li>Billing (unlocks staging/production): {state.billingReady ? 'done' : 'optional'}</li>
            <li>Current step: {currentStep}</li>
          </ul>
        ) : null}
      </section>

      {onboardingComplete ? (
        <section className="dashboard-view__section" aria-label="Onboarding completed">
          <h2>Onboarding completed</h2>
          <p>Organization and first development environment are ready. Redirecting to wallets...</p>
          {!state?.billingReady ? (
            <p className="dashboard-pagination-note">
              Add a billing method to unlock staging and production environments.
            </p>
          ) : null}
          <div className="dashboard-form-actions">
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={() => {
                persistCompletionContextSelection();
                go(completionWalletRedirectPath);
              }}
            >
              Continue to wallets now
            </button>
            <button
              type="button"
              className="dashboard-inline-link"
              onClick={() => go('/dashboard/billing')}
            >
              Open billing
            </button>
          </div>
        </section>
      ) : (
        <section className="dashboard-view__section" aria-label="Onboarding form">
          {showOrganizationStep ? (
            <>
              <h2>Organization step</h2>
              <p>Configure organization profile details for your org.</p>
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onSubmitOrganization}>
                <label className="dashboard-form-field">
                  <span>Organization name</span>
                  <input
                    className="dashboard-input"
                    value={orgNameInput}
                    onChange={(event) => setOrgNameInput(event.target.value)}
                    placeholder="Acme Wallets"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Organization slug (optional)</span>
                  <input
                    className="dashboard-input"
                    value={orgSlugInput}
                    onChange={(event) => setOrgSlugInput(event.target.value)}
                    placeholder="acme-wallets"
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={submitting || state?.organizationReady === true}
                  >
                    {submitting ? 'Saving organization...' : 'Save organization'}
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
              <h2>Project step</h2>
              <p>Create the first project and default Development environment.</p>
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onSubmitProjectStep}>
                <label className="dashboard-form-field">
                  <span>Project name</span>
                  <input
                    className="dashboard-input"
                    value={projectNameInput}
                    onChange={(event) => setProjectNameInput(event.target.value)}
                    placeholder="Consumer App"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Project ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={projectIdInput}
                    onChange={(event) => setProjectIdInput(event.target.value)}
                    placeholder="proj_consumer"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Environment ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={environmentIdInput}
                    onChange={(event) => setEnvironmentIdInput(event.target.value)}
                    placeholder="proj_consumer:dev"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Environment name (optional)</span>
                  <input
                    className="dashboard-input"
                    value={environmentNameInput}
                    onChange={(event) => setEnvironmentNameInput(event.target.value)}
                    placeholder="Development"
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={submitting || state?.projectReady === true}
                  >
                    {submitting ? 'Creating project...' : 'Create first project'}
                  </button>
                </div>
              </form>
              <p className="dashboard-pagination-note">
                Billing is optional for onboarding. Add billing later to create staging/production environments.
              </p>
              {projectResult ? (
                <p className="dashboard-pagination-note">
                  Project configured: <strong>{projectResult.project.name}</strong> /{' '}
                  <strong>{projectResult.environment.id}</strong>.
                </p>
              ) : null}
            </>
          ) : null}

          {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
        </section>
      )}
    </div>
  );
}

export default DashboardOnboardingPage;
