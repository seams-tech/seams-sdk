import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  DashboardConsoleObservabilityApiError,
  type DashboardConsoleObservabilityLevel,
  type DashboardConsoleObservabilityModuleStatus,
  type DashboardConsoleObservabilitySnapshot,
  getDashboardObservabilitySnapshot,
  isDashboardConsoleObservabilityApiErrorCode,
} from './consoleObservabilityApi';

const DEFAULT_OBSERVABILITY_EVENTS_PAGE_SIZE = 50;
const OBSERVABILITY_EVENTS_PAGE_SIZES = [25, 50, 100] as const;

function formatTimestamp(value: string | undefined | null): string {
  const normalized = String(value || '').trim();
  if (!normalized) return '-';
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function formatPercent(value: number): string {
  if (!Number.isFinite(value) || value <= 0) return '0%';
  const normalized = value <= 1 ? value * 100 : value;
  return `${normalized.toFixed(normalized >= 10 ? 1 : 2)}%`;
}

function metadataSummary(metadata: Record<string, unknown>): string {
  const keys = Object.keys(metadata || {});
  if (keys.length === 0) return '-';
  const first = keys
    .slice(0, 3)
    .map((key) => `${key}=${String(metadata[key])}`)
    .join(', ');
  return keys.length > 3 ? `${first}, +${keys.length - 3} more` : first;
}

function toStatusWarning(label: string, status: DashboardConsoleObservabilityModuleStatus): string | null {
  if (status.state === 'ok') return null;
  const detail = status.message ? `: ${status.message}` : '';
  if (status.state === 'not_configured') return `${label} is not configured${detail}`;
  if (status.state === 'forbidden') return `${label} is not available for this role${detail}`;
  return `${label} is degraded${detail}`;
}

function toErrorMessage(error: unknown): string {
  if (isDashboardConsoleObservabilityApiErrorCode(error, 'observability_not_configured')) {
    return 'Observability service is not configured on this server.';
  }
  if (isDashboardConsoleObservabilityApiErrorCode(error, 'forbidden')) {
    return 'Observability is not available for this role.';
  }
  if (error instanceof DashboardConsoleObservabilityApiError) return error.message;
  if (error instanceof Error) return error.message;
  return String(error || 'Unknown error');
}

export function ObservabilityPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [warnings, setWarnings] = React.useState<string[]>([]);
  const [data, setData] = React.useState<DashboardConsoleObservabilitySnapshot | null>(null);
  const [eventsQueryInput, setEventsQueryInput] = React.useState<string>('');
  const [eventsLevelFilter, setEventsLevelFilter] = React.useState<
    DashboardConsoleObservabilityLevel | ''
  >('');
  const [eventsServiceFilter, setEventsServiceFilter] = React.useState<string>('');
  const [eventsEventTypeFilter, setEventsEventTypeFilter] = React.useState<string>('');
  const [eventsPageSize, setEventsPageSize] = React.useState<number>(
    DEFAULT_OBSERVABILITY_EVENTS_PAGE_SIZE,
  );
  const [eventsCursor, setEventsCursor] = React.useState<string | null>(null);
  const [previousEventCursors, setPreviousEventCursors] = React.useState<Array<string | null>>([]);
  const deferredEventsQueryInput = React.useDeferredValue(eventsQueryInput);
  const deferredEventsServiceFilter = React.useDeferredValue(eventsServiceFilter);
  const deferredEventsEventTypeFilter = React.useDeferredValue(eventsEventTypeFilter);

  const scope = React.useMemo(
    () => ({
      ...(String(selectedContext.project || '').trim()
        ? { projectId: String(selectedContext.project || '').trim() }
        : {}),
      ...(String(selectedContext.environment || '').trim()
        ? { environmentId: String(selectedContext.environment || '').trim() }
        : {}),
    }),
    [selectedContext.environment, selectedContext.project],
  );
  const normalizedEventsQuery = React.useMemo(
    () => String(deferredEventsQueryInput || '').trim(),
    [deferredEventsQueryInput],
  );
  const normalizedEventsServiceFilter = React.useMemo(
    () => String(deferredEventsServiceFilter || '').trim(),
    [deferredEventsServiceFilter],
  );
  const normalizedEventsEventTypeFilter = React.useMemo(
    () => String(deferredEventsEventTypeFilter || '').trim(),
    [deferredEventsEventTypeFilter],
  );

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }

    if (!session.claims) {
      setLoading(false);
      setData(null);
      setWarnings([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMessage('');

    getDashboardObservabilitySnapshot({
      ...scope,
      ...(eventsCursor ? { eventsCursor } : {}),
      eventsLimit: eventsPageSize,
      ...(normalizedEventsQuery ? { eventsQuery: normalizedEventsQuery } : {}),
      ...(eventsLevelFilter ? { eventsLevel: eventsLevelFilter } : {}),
      ...(normalizedEventsServiceFilter ? { eventsService: normalizedEventsServiceFilter } : {}),
      ...(normalizedEventsEventTypeFilter
        ? { eventsEventType: normalizedEventsEventTypeFilter }
        : {}),
    })
      .then((snapshot) => {
        if (cancelled) return;
        const nextWarnings = [
          toStatusWarning('Summary', snapshot.summary.status),
          toStatusWarning('Events', snapshot.events.status),
          toStatusWarning('Service health', snapshot.services.status),
        ].filter((entry): entry is string => Boolean(entry));
        setWarnings(nextWarnings);
        setData(snapshot);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setData(null);
        setWarnings([]);
        setErrorMessage(toErrorMessage(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [
    eventsCursor,
    eventsLevelFilter,
    eventsPageSize,
    normalizedEventsEventTypeFilter,
    normalizedEventsQuery,
    normalizedEventsServiceFilter,
    scope,
    session.claims,
    session.errorMessage,
    session.loading,
  ]);

  const summary = data?.summary || null;
  const events = data?.events.events || [];
  const services = data?.services.services || [];
  const hasNextEventsPage = Boolean(data?.events.nextCursor);
  const eventsTotalPages = Math.max(1, Number(data?.events.totalPages || 1));
  const hasPreviousEventsPage = previousEventCursors.length > 0;
  const eventsPageNumber = Math.min(previousEventCursors.length + 1, eventsTotalPages);
  const hasEventsFilters =
    Boolean(normalizedEventsQuery) ||
    Boolean(eventsLevelFilter) ||
    Boolean(normalizedEventsServiceFilter) ||
    Boolean(normalizedEventsEventTypeFilter);

  React.useEffect(() => {
    setEventsCursor(null);
    setPreviousEventCursors([]);
  }, [
    eventsLevelFilter,
    normalizedEventsEventTypeFilter,
    normalizedEventsQuery,
    normalizedEventsServiceFilter,
    scope.environmentId,
    scope.projectId,
  ]);

  const onNextEventsPage = React.useCallback(() => {
    const nextCursor = String(data?.events.nextCursor || '').trim();
    if (!nextCursor || loading) return;
    setPreviousEventCursors((current) => [...current, eventsCursor]);
    setEventsCursor(nextCursor);
  }, [data?.events.nextCursor, eventsCursor, loading]);
  const onPreviousEventsPage = React.useCallback(() => {
    if (loading || previousEventCursors.length === 0) return;
    const nextHistory = previousEventCursors.slice(0, -1);
    const previousCursor = previousEventCursors[previousEventCursors.length - 1] ?? null;
    setPreviousEventCursors(nextHistory);
    setEventsCursor(previousCursor);
  }, [loading, previousEventCursors]);
  const onSelectEventsPageSize = React.useCallback(
    (nextPageSize: number) => {
      if (loading || nextPageSize === eventsPageSize) return;
      setPreviousEventCursors([]);
      setEventsCursor(null);
      setEventsPageSize(nextPageSize);
    },
    [eventsPageSize, loading],
  );

  return (
    <div className="dashboard-view" aria-label="Observability page">
      <p className="dashboard-visually-hidden" role="status" aria-live="polite" aria-atomic="true">
        {loading ? 'Refreshing observability...' : ''}
      </p>
      {errorMessage ? (
        <p className="dashboard-pagination-note" role="alert">
          {errorMessage}
        </p>
      ) : null}
      {warnings.length > 0 ? (
        <ul className="dashboard-view-list" aria-label="Observability status warnings">
          {warnings.map((warning) => (
            <li key={warning}>{warning}</li>
          ))}
        </ul>
      ) : null}

      <section
        className="dashboard-view__section dashboard-observability-section--plain"
        aria-label="Observability service health table"
      >
        <h2>Service health</h2>
        {summary ? (
          <section
            className="dashboard-observability-summary"
            aria-label="Observability summary metrics"
          >
            <article className="dashboard-observability-summary__item">
              <p className="dashboard-observability-summary__label">error rate</p>
              <p className="dashboard-observability-summary__value">
                {formatPercent(summary.errorRate)}
              </p>
            </article>
            <article className="dashboard-observability-summary__item">
              <p className="dashboard-observability-summary__label">p95 latency</p>
              <p className="dashboard-observability-summary__value">
                {Math.max(0, Number(summary.p95LatencyMs || 0)).toFixed(0)}ms
              </p>
            </article>
            <article className="dashboard-observability-summary__item">
              <p className="dashboard-observability-summary__label">failing services</p>
              <p className="dashboard-observability-summary__value">{summary.failingServices}</p>
            </article>
            <article className="dashboard-observability-summary__item">
              <p className="dashboard-observability-summary__label">dead letters</p>
              <p className="dashboard-observability-summary__value">{summary.deadLetterCount}</p>
            </article>
          </section>
        ) : null}
        <section className="dashboard-table-wrapper" aria-label="Observability service health">
          <div className="dashboard-table-header" role="row">
            <span>Service</span>
            <span>Status</span>
            <span>Recent failures</span>
            <span>Latest incident</span>
            <span>Scope project</span>
            <span>Scope environment</span>
            <span>Summary state</span>
            <span>Notes</span>
          </div>
          {services.length === 0 ? (
            <p className="dashboard-table-limit">
              {loading ? 'Loading service health...' : 'No service health records for this scope.'}
            </p>
          ) : (
            services.map((entry) => (
              <div className="dashboard-table-row" key={entry.service} role="row">
                <span>{entry.service}</span>
                <span>{entry.status}</span>
                <span>{entry.recentFailureCount}</span>
                <span>{formatTimestamp(entry.latestIncidentAt)}</span>
                <span>{scope.projectId || '-'}</span>
                <span>{scope.environmentId || '-'}</span>
                <span>{summary?.status.state || '-'}</span>
                <span>{entry.recentFailureCount > 0 ? 'Investigate recent failures' : '-'}</span>
              </div>
            ))
          )}
        </section>
      </section>

      <section
        className="dashboard-view__section dashboard-observability-section--plain"
        aria-label="Observability events table"
      >
        <h2>Recent events</h2>
        <div className="dashboard-filters dashboard-observability-filters" aria-label="Observability event filters">
          <label className="dashboard-search-control dashboard-search-control--compact">
            <span className="dashboard-search-icon" aria-hidden="true" />
            <input
              type="search"
              aria-label="Search observability events"
              placeholder="Search event ID, message, request, trace, or metadata"
              value={eventsQueryInput}
              onChange={(event) => setEventsQueryInput(event.target.value)}
            />
          </label>
          <label className="dashboard-form-field dashboard-form-field--observability-select">
            <select
              className="dashboard-input dashboard-select--observability"
              aria-label="Filter observability events by level"
              value={eventsLevelFilter}
              onChange={(event) =>
                setEventsLevelFilter(event.target.value as DashboardConsoleObservabilityLevel | '')
              }
            >
              <option value="">Level: All</option>
              <option value="DEBUG">Level: Debug</option>
              <option value="INFO">Level: Info</option>
              <option value="WARN">Level: Warn</option>
              <option value="ERROR">Level: Error</option>
              <option value="FATAL">Level: Fatal</option>
            </select>
          </label>
          <label className="dashboard-form-field">
            <input
              type="search"
              className="dashboard-input"
              aria-label="Filter observability events by service"
              placeholder="Service exact match"
              value={eventsServiceFilter}
              onChange={(event) => setEventsServiceFilter(event.target.value)}
            />
          </label>
          <label className="dashboard-form-field">
            <input
              type="search"
              className="dashboard-input"
              aria-label="Filter observability events by event type"
              placeholder="Event type exact match"
              value={eventsEventTypeFilter}
              onChange={(event) => setEventsEventTypeFilter(event.target.value)}
            />
          </label>
        </div>
        <section className="dashboard-table-wrapper" aria-label="Observability events">
          <div className="dashboard-table-header" role="row">
            <span>Timestamp</span>
            <span>Service</span>
            <span>Level</span>
            <span>Event type</span>
            <span>Message</span>
            <span>Request</span>
            <span>Trace</span>
            <span>Metadata</span>
          </div>
          {events.length === 0 ? (
            <p className="dashboard-table-limit">
              {loading
                ? 'Loading observability events...'
                : hasEventsFilters
                  ? 'No observability events match the current filters.'
                  : 'No observability events for this scope.'}
            </p>
          ) : (
            events.map((entry) => (
              <div className="dashboard-table-row" key={entry.id} role="row">
                <span>{formatTimestamp(entry.timestamp)}</span>
                <span title={`${entry.service}/${entry.component}`}>
                  {entry.service || '-'} {entry.component ? `(${entry.component})` : ''}
                </span>
                <span>{entry.level}</span>
                <span>{entry.eventType || '-'}</span>
                <span title={entry.message}>{entry.message || '-'}</span>
                <span>{entry.requestId || '-'}</span>
                <span>{entry.traceId || '-'}</span>
                <span title={JSON.stringify(entry.metadata)}>{metadataSummary(entry.metadata)}</span>
              </div>
            ))
          )}
        </section>
        <div className="dashboard-form-actions dashboard-observability-pagination">
          <button
            type="button"
            className="dashboard-pagination-button"
            disabled={loading || !hasPreviousEventsPage}
            onClick={onPreviousEventsPage}
          >
            Previous page
          </button>
          <button
            type="button"
            className="dashboard-pagination-button"
            disabled={loading || !hasNextEventsPage}
            onClick={onNextEventsPage}
          >
            Next page
          </button>
          <span
            className="dashboard-observability-pagination__page"
            aria-label={`Current page ${eventsPageNumber} of ${eventsTotalPages}`}
          >
            Page {eventsPageNumber} / {eventsTotalPages}
          </span>
          <div className="dashboard-observability-page-size" aria-label="Events per page">
            <span className="dashboard-pagination-note">Show</span>
            {OBSERVABILITY_EVENTS_PAGE_SIZES.map((pageSize, index) => (
              <React.Fragment key={pageSize}>
                <button
                  type="button"
                  className={[
                    'dashboard-observability-page-size__button',
                    eventsPageSize === pageSize
                      ? 'dashboard-observability-page-size__button--active'
                      : '',
                  ]
                    .filter(Boolean)
                    .join(' ')}
                  aria-pressed={eventsPageSize === pageSize}
                  disabled={loading && eventsPageSize !== pageSize}
                  onClick={() => onSelectEventsPageSize(pageSize)}
                >
                  {pageSize}
                </button>
                {index < OBSERVABILITY_EVENTS_PAGE_SIZES.length - 1 ? (
                  <span
                    className="dashboard-observability-page-size__separator"
                    aria-hidden="true"
                  >
                    |
                  </span>
                ) : null}
              </React.Fragment>
            ))}
            <span className="dashboard-pagination-note">events per page</span>
          </div>
        </div>
      </section>
    </div>
  );
}

export default ObservabilityPage;
