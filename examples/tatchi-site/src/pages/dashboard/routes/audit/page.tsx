import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  listDashboardAuditEvents,
  type DashboardConsoleAuditCategory,
  type DashboardConsoleAuditEvent,
  type DashboardConsoleAuditOutcome,
} from './consoleAuditApi';

const CATEGORY_OPTIONS: readonly DashboardConsoleAuditCategory[] = [
  'POLICY',
  'SETTINGS',
  'KEY_EXPORT',
  'BILLING',
  'WEBHOOK',
  'API_KEY',
  'TEAM',
  'APPROVAL',
  'ORG_PROJECT_ENV',
  'RUNTIME_SNAPSHOT',
  'SYSTEM',
];

const OUTCOME_OPTIONS: readonly DashboardConsoleAuditOutcome[] = ['SUCCESS', 'FAILURE', 'PENDING'];

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function toIsoTimestamp(value: string): string | undefined {
  const normalized = String(value || '').trim();
  if (!normalized) return undefined;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toISOString();
}

function metadataSummary(metadata: Record<string, unknown>): string {
  const keys = Object.keys(metadata || {});
  if (keys.length === 0) return '-';
  const preview = keys
    .slice(0, 3)
    .map((key) => `${key}=${String(metadata[key])}`)
    .join(', ');
  return keys.length > 3 ? `${preview}, +${keys.length - 3} more` : preview;
}

function scopeSummary(row: DashboardConsoleAuditEvent): string {
  const project = String(row.projectId || '').trim();
  const environment = String(row.environmentId || '').trim();
  if (project && environment) return `${project} / ${environment}`;
  if (project) return project;
  if (environment) return environment;
  return 'Organization';
}

function outcomeClassName(outcome: DashboardConsoleAuditOutcome): string {
  if (outcome === 'SUCCESS') return 'dashboard-audit-events-table__outcome--success';
  if (outcome === 'FAILURE') return 'dashboard-audit-events-table__outcome--failure';
  return 'dashboard-audit-events-table__outcome--pending';
}

export function AuditLogsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const selectedProjectId = String(selectedContext.project || '').trim();
  const selectedEnvironmentId = String(selectedContext.environment || '').trim();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [events, setEvents] = React.useState<DashboardConsoleAuditEvent[]>([]);
  const [searchInput, setSearchInput] = React.useState<string>('');
  const [debouncedSearchInput, setDebouncedSearchInput] = React.useState<string>('');
  const [eventCategoryFilter, setEventCategoryFilter] = React.useState<string>('');
  const [eventOutcomeFilter, setEventOutcomeFilter] = React.useState<string>('');
  const [fromInput, setFromInput] = React.useState<string>('');
  const [toInput, setToInput] = React.useState<string>('');
  const [expandedEventId, setExpandedEventId] = React.useState<string>('');

  React.useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      setDebouncedSearchInput(String(searchInput || '').trim());
    }, 250);
    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [searchInput]);

  const loadAuditEvents = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setEvents([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMessage('');

    listDashboardAuditEvents({
      ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
      ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
      ...(eventCategoryFilter ? { category: eventCategoryFilter as DashboardConsoleAuditCategory } : {}),
      ...(eventOutcomeFilter ? { outcome: eventOutcomeFilter as DashboardConsoleAuditOutcome } : {}),
      ...(debouncedSearchInput ? { q: debouncedSearchInput } : {}),
      ...(toIsoTimestamp(fromInput) ? { from: toIsoTimestamp(fromInput) } : {}),
      ...(toIsoTimestamp(toInput) ? { to: toIsoTimestamp(toInput) } : {}),
      limit: 100,
    })
      .then((nextEvents) => {
        if (cancelled) return;
        setEvents(nextEvents);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setEvents([]);
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
    debouncedSearchInput,
    eventCategoryFilter,
    eventOutcomeFilter,
    fromInput,
    selectedEnvironmentId,
    selectedProjectId,
    session.claims,
    session.errorMessage,
    toInput,
  ]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadAuditEvents();
    return cleanup;
  }, [loadAuditEvents, session.loading]);

  return (
    <div className="dashboard-view" aria-label="Audit logs page">
      <section
        className="dashboard-view__section dashboard-audit-section--plain"
        aria-label="Audit event filters"
      >
        <section className="dashboard-audit-filter-group" aria-label="Event filters">
          <div className="dashboard-view-grid dashboard-view-grid--two dashboard-audit-controls-grid">
            <div className="dashboard-form-field dashboard-form-field--full">
              <input
                className="dashboard-input dashboard-input--audit"
                aria-label="Search events"
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder="Search user id, action, summary, event id, approval id, API key id, metadata"
              />
            </div>
            <label className="dashboard-form-field">
              <span>Category</span>
              <select
                className="dashboard-select dashboard-select--audit"
                value={eventCategoryFilter}
                onChange={(event) => setEventCategoryFilter(event.target.value)}
              >
                <option value="">All categories</option>
                {CATEGORY_OPTIONS.map((entry) => (
                  <option key={entry} value={entry}>
                    {entry}
                  </option>
                ))}
              </select>
            </label>

            <label className="dashboard-form-field">
              <span>Outcome</span>
              <select
                className="dashboard-select dashboard-select--audit"
                value={eventOutcomeFilter}
                onChange={(event) => setEventOutcomeFilter(event.target.value)}
              >
                <option value="">All outcomes</option>
                {OUTCOME_OPTIONS.map((entry) => (
                  <option key={entry} value={entry}>
                    {entry}
                  </option>
                ))}
              </select>
            </label>

            <label className="dashboard-form-field">
              <span>From</span>
              <input
                className="dashboard-input dashboard-input--audit"
                type="datetime-local"
                value={fromInput}
                onChange={(event) => setFromInput(event.target.value)}
              />
            </label>

            <label className="dashboard-form-field">
              <span>To</span>
              <input
                className="dashboard-input dashboard-input--audit"
                type="datetime-local"
                value={toInput}
                onChange={(event) => setToInput(event.target.value)}
              />
            </label>
          </div>
        </section>

        {errorMessage ? <p className="dashboard-pagination-note">{errorMessage}</p> : null}
      </section>

      <section
        className="dashboard-view__section dashboard-audit-section--plain"
        aria-label="Audit events table"
      >
        <h2>Events</h2>
        <section
          className="dashboard-table-wrapper dashboard-audit-events-table"
          aria-label="Audit events"
        >
          <div className="dashboard-audit-events-table__header" role="row">
            <span>Timestamp</span>
            <span>Event</span>
            <span>Actor</span>
            <span>Scope</span>
            <span>Outcome</span>
            <span>Details</span>
          </div>
          {events.length === 0 ? (
            <p className="dashboard-empty-state dashboard-empty-state--audit">
              {loading ? 'Loading audit events...' : 'No audit events matched the current scope and filters.'}
            </p>
          ) : (
            events.map((row) => {
              const isExpanded = expandedEventId === row.id;
              return (
                <React.Fragment key={row.id}>
                  <div className="dashboard-audit-events-table__row" role="row">
                    <div className="dashboard-audit-events-table__cell">
                      <span>{formatTimestamp(row.createdAt)}</span>
                    </div>
                    <div className="dashboard-audit-events-table__cell dashboard-audit-events-table__cell--event">
                      <strong className="dashboard-audit-events-table__summary">
                        {row.summary || row.action || row.id}
                      </strong>
                      <span className="dashboard-audit-events-table__subline">
                        <span className="dashboard-audit-events-table__badge">{row.category}</span>
                        <span>{row.action || '-'}</span>
                      </span>
                      <span
                        className="dashboard-audit-events-table__subline dashboard-audit-events-table__subline--muted"
                        title={JSON.stringify(row.metadata)}
                      >
                        Metadata: {metadataSummary(row.metadata)}
                      </span>
                    </div>
                    <div className="dashboard-audit-events-table__cell">
                      <span>{row.actorUserId}</span>
                      <span className="dashboard-audit-events-table__subline dashboard-audit-events-table__subline--muted">
                        {row.actorType}
                      </span>
                    </div>
                    <div className="dashboard-audit-events-table__cell">
                      <span>{scopeSummary(row)}</span>
                    </div>
                    <div className="dashboard-audit-events-table__cell">
                      <span
                        className={`dashboard-audit-events-table__outcome ${outcomeClassName(row.outcome)}`}
                      >
                        {row.outcome}
                      </span>
                    </div>
                    <div className="dashboard-audit-events-table__cell dashboard-audit-events-table__cell--details">
                      <button
                        type="button"
                        className="dashboard-audit-events-table__details-toggle"
                        onClick={() =>
                          setExpandedEventId((current) => (current === row.id ? '' : row.id))
                        }
                      >
                        {isExpanded ? 'Hide' : 'View'}
                      </button>
                    </div>
                  </div>
                  {isExpanded ? (
                    <div className="dashboard-audit-events-table__details-panel">
                      <div className="dashboard-audit-events-table__details-grid">
                        <div className="dashboard-audit-events-table__details-item">
                          <span className="dashboard-audit-events-table__details-label">Event ID</span>
                          <span>{row.id}</span>
                        </div>
                        <div className="dashboard-audit-events-table__details-item">
                          <span className="dashboard-audit-events-table__details-label">Action</span>
                          <span>{row.action || '-'}</span>
                        </div>
                        <div className="dashboard-audit-events-table__details-item">
                          <span className="dashboard-audit-events-table__details-label">Project</span>
                          <span>{row.projectId || '-'}</span>
                        </div>
                        <div className="dashboard-audit-events-table__details-item">
                          <span className="dashboard-audit-events-table__details-label">
                            Environment
                          </span>
                          <span>{row.environmentId || '-'}</span>
                        </div>
                      </div>
                      <pre className="dashboard-audit-events-table__metadata-json">
                        {JSON.stringify(row.metadata, null, 2)}
                      </pre>
                    </div>
                  ) : null}
                </React.Fragment>
              );
            })
          )}
        </section>
      </section>
    </div>
  );
}
