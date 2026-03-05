import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  getDashboardEnterpriseIsolationStatus,
  triggerDashboardEnterpriseIsolation,
  type DashboardEnterpriseIsolationScope,
  type DashboardEnterpriseIsolationState,
  type DashboardEnterpriseIsolationTrigger,
} from './consoleEnterpriseIsolationApi';

const SCOPE_OPTIONS: readonly DashboardEnterpriseIsolationScope[] = ['ORG', 'PROJECT', 'ENVIRONMENT'];
const TRIGGER_OPTIONS: readonly DashboardEnterpriseIsolationTrigger[] = [
  'MANUAL',
  'COMPLIANCE',
  'SLA_BREACH',
];

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

export function EnterpriseIsolationPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [isolation, setIsolation] = React.useState<DashboardEnterpriseIsolationState | null>(null);
  const [scopeInput, setScopeInput] = React.useState<DashboardEnterpriseIsolationScope>('ORG');
  const [triggerInput, setTriggerInput] = React.useState<DashboardEnterpriseIsolationTrigger>('MANUAL');
  const [reasonInput, setReasonInput] = React.useState<string>('');
  const [ticketIdInput, setTicketIdInput] = React.useState<string>('');
  const [submitting, setSubmitting] = React.useState<boolean>(false);
  const selectedProjectId = String(selectedContext.project || '').trim();
  const selectedEnvironmentId = String(selectedContext.environment || '').trim();

  const loadIsolation = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setIsolation(null);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    getDashboardEnterpriseIsolationStatus({
      scope: scopeInput,
      ...(scopeInput !== 'ORG' && selectedProjectId ? { projectId: selectedProjectId } : {}),
      ...(scopeInput === 'ENVIRONMENT' && selectedEnvironmentId
        ? { environmentId: selectedEnvironmentId }
        : {}),
    })
      .then((row) => {
        if (cancelled) return;
        setIsolation(row);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setIsolation(null);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [scopeInput, selectedEnvironmentId, selectedProjectId, session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadIsolation();
    return cleanup;
  }, [loadIsolation, session.loading]);

  return (
    <div className="dashboard-view" aria-label="Enterprise isolation page">
      <section className="dashboard-view__section" aria-label="Isolation overview">
        <h2>Enterprise isolation controls</h2>
        <p>
          Trigger and inspect shared-to-dedicated isolation state. This phase ships API and dashboard scaffolding;
          migration orchestration is intentionally deferred.
        </p>

        <div className="dashboard-view-grid dashboard-view-grid--two">
          <label className="dashboard-form-field">
            <span>Scope</span>
            <select
              className="dashboard-select"
              value={scopeInput}
              onChange={(event) => setScopeInput(event.target.value as DashboardEnterpriseIsolationScope)}
            >
              {SCOPE_OPTIONS.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </select>
          </label>

          <label className="dashboard-form-field">
            <span>Trigger type</span>
            <select
              className="dashboard-select"
              value={triggerInput}
              onChange={(event) =>
                setTriggerInput(event.target.value as DashboardEnterpriseIsolationTrigger)
              }
            >
              {TRIGGER_OPTIONS.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </select>
          </label>

          <label className="dashboard-form-field">
            <span>Reason</span>
            <input
              className="dashboard-input"
              placeholder="Compliance or SLA reason"
              value={reasonInput}
              onChange={(event) => setReasonInput(event.target.value)}
            />
          </label>

          <label className="dashboard-form-field">
            <span>Ticket ID (optional)</span>
            <input
              className="dashboard-input"
              placeholder="OPS-1234"
              value={ticketIdInput}
              onChange={(event) => setTicketIdInput(event.target.value)}
            />
          </label>
        </div>

        <div className="dashboard-form-actions">
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={() => loadIsolation()}
            disabled={loading || submitting}
          >
            {loading ? 'Loading...' : 'Reload status'}
          </button>
          <button
            type="button"
            className="dashboard-pagination-button"
            disabled={loading || submitting || !reasonInput.trim()}
            onClick={async () => {
              setSubmitting(true);
              setErrorMessage('');
              try {
                const next = await triggerDashboardEnterpriseIsolation({
                  scope: scopeInput,
                  ...(scopeInput !== 'ORG' && selectedProjectId ? { projectId: selectedProjectId } : {}),
                  ...(scopeInput === 'ENVIRONMENT' && selectedEnvironmentId
                    ? { environmentId: selectedEnvironmentId }
                    : {}),
                  trigger: triggerInput,
                  reason: reasonInput.trim(),
                  ...(ticketIdInput.trim() ? { ticketId: ticketIdInput.trim() } : {}),
                });
                setIsolation(next);
              } catch (error: unknown) {
                setErrorMessage(error instanceof Error ? error.message : String(error));
              } finally {
                setSubmitting(false);
              }
            }}
          >
            {submitting ? 'Submitting...' : 'Trigger isolation'}
          </button>
        </div>
        {errorMessage ? <p className="dashboard-pagination-note">{errorMessage}</p> : null}
      </section>

      <section className="dashboard-view__section" aria-label="Isolation status">
        <h2>Isolation state</h2>
        {!isolation ? (
          <p className="dashboard-empty-state">{loading ? 'Loading isolation state...' : 'No isolation state.'}</p>
        ) : (
          <section className="dashboard-table-wrapper" aria-label="Isolation state table">
            <div className="dashboard-table-header" role="row">
              <span>Scope</span>
              <span>Status</span>
              <span>Mode</span>
              <span>Trigger</span>
              <span>Requested by</span>
              <span>Requested at</span>
            </div>
            <div className="dashboard-table-row" role="row">
              <span>
                {[isolation.scope, isolation.projectId || '-', isolation.environmentId || '-'].join(' / ')}
              </span>
              <span>{isolation.status}</span>
              <span>{isolation.mode}</span>
              <span>{isolation.trigger || '-'}</span>
              <span>{isolation.requestedByUserId || '-'}</span>
              <span>{formatTimestamp(isolation.requestedAt)}</span>
            </div>
          </section>
        )}
      </section>
    </div>
  );
}
