import React from 'react';
import {
  DashboardTable,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  DashboardConsoleObservabilityApiError,
  type DashboardConsoleObservabilityLevel,
  type DashboardConsoleObservabilityModuleStatus,
  type DashboardConsoleObservabilitySnapshot,
  getDashboardObservabilitySummary,
  isDashboardConsoleObservabilityApiErrorCode,
  listDashboardObservabilityEvents,
  listDashboardObservabilityServices,
} from './consoleObservabilityApi';

const OBSERVABILITY_EVENTS_FETCH_LIMIT = 100;
const DEFAULT_OBSERVABILITY_WINDOW_MS = 1000 * 60 * 60 * 24;
const OBSERVABILITY_SERVICE_TABLE_COLUMNS = dashboardTableColumns(
  1,
  0.8,
  0.75,
  0.95,
  0.85,
  0.95,
  0.8,
  1.1,
);
const OBSERVABILITY_EVENTS_TABLE_COLUMNS = dashboardTableColumns(
  1,
  1,
  0.65,
  0.85,
  1.55,
  0.8,
  0.8,
  1.15,
);

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

function buildDefaultObservabilityScopeWindow(): { from: string; to: string } {
  const to = new Date();
  const from = new Date(to.getTime() - DEFAULT_OBSERVABILITY_WINDOW_MS);
  return {
    from: from.toISOString(),
    to: to.toISOString(),
  };
}

function toStatusWarning(
  label: string,
  status: DashboardConsoleObservabilityModuleStatus,
): string | null {
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
  const [loadingMoreEvents, setLoadingMoreEvents] = React.useState<boolean>(false);
  const [loadMoreEventsError, setLoadMoreEventsError] = React.useState<string>('');
  const [eventsQueryInput, setEventsQueryInput] = React.useState<string>('');
  const [eventsLevelFilter, setEventsLevelFilter] = React.useState<
    DashboardConsoleObservabilityLevel | ''
  >('');
  const [eventsServiceFilter, setEventsServiceFilter] = React.useState<string>('');
  const [eventsEventTypeFilter, setEventsEventTypeFilter] = React.useState<string>('');
  const deferredEventsQueryInput = React.useDeferredValue(eventsQueryInput);
  const deferredEventsServiceFilter = React.useDeferredValue(eventsServiceFilter);
  const deferredEventsEventTypeFilter = React.useDeferredValue(eventsEventTypeFilter);

  const defaultScopeWindow = React.useMemo(() => buildDefaultObservabilityScopeWindow(), []);
  const scope = React.useMemo(
    () => ({
      ...defaultScopeWindow,
      ...(String(selectedContext.project || '').trim()
        ? { projectId: String(selectedContext.project || '').trim() }
        : {}),
      ...(String(selectedContext.environment || '').trim()
        ? { environmentId: String(selectedContext.environment || '').trim() }
        : {}),
    }),
    [defaultScopeWindow, selectedContext.environment, selectedContext.project],
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
      setLoadingMoreEvents(false);
      setLoadMoreEventsError('');
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    setLoadingMoreEvents(false);
    setLoadMoreEventsError('');

    Promise.all([
      getDashboardObservabilitySummary(scope),
      listDashboardObservabilityServices({ ...scope, limit: 25 }),
      listDashboardObservabilityEvents({
        ...scope,
        ...(normalizedEventsQuery ? { query: normalizedEventsQuery } : {}),
        ...(eventsLevelFilter ? { level: eventsLevelFilter } : {}),
        ...(normalizedEventsServiceFilter ? { service: normalizedEventsServiceFilter } : {}),
        ...(normalizedEventsEventTypeFilter
          ? { eventType: normalizedEventsEventTypeFilter }
          : {}),
        limit: OBSERVABILITY_EVENTS_FETCH_LIMIT,
      }),
    ])
      .then(([summary, services, events]) => {
        if (cancelled) return;
        const nextWarnings = [
          toStatusWarning('Summary', summary.status),
          toStatusWarning('Events', events.status),
          toStatusWarning('Service health', services.status),
        ].filter((entry): entry is string => Boolean(entry));
        setWarnings(nextWarnings);
        setData({
          summary,
          events,
          services,
        } satisfies DashboardConsoleObservabilitySnapshot);
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
    eventsLevelFilter,
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
  const eventsNextCursor = React.useMemo(
    () => String(data?.events.nextCursor || '').trim(),
    [data?.events.nextCursor],
  );
  const services = data?.services.services || [];
  const hasEventsFilters =
    Boolean(normalizedEventsQuery) ||
    Boolean(eventsLevelFilter) ||
    Boolean(normalizedEventsServiceFilter) ||
    Boolean(normalizedEventsEventTypeFilter);
  const servicesPagination = useDashboardTablePagination(services, {
    disabled: loading,
    itemLabel: 'service',
    itemLabelPlural: 'services',
  });
  const eventsPagination = useDashboardTablePagination(events, {
    disabled: loading,
    itemLabel: 'event',
    itemLabelPlural: 'events',
  });
  const handleLoadMoreEvents = React.useCallback(async () => {
    if (!session.claims) return;
    if (!eventsNextCursor) return;
    if (loading || loadingMoreEvents) return;

    setLoadingMoreEvents(true);
    setLoadMoreEventsError('');
    try {
      const nextPage = await listDashboardObservabilityEvents({
        ...scope,
        ...(normalizedEventsQuery ? { query: normalizedEventsQuery } : {}),
        ...(eventsLevelFilter ? { level: eventsLevelFilter } : {}),
        ...(normalizedEventsServiceFilter ? { service: normalizedEventsServiceFilter } : {}),
        ...(normalizedEventsEventTypeFilter
          ? { eventType: normalizedEventsEventTypeFilter }
          : {}),
        cursor: eventsNextCursor,
        limit: OBSERVABILITY_EVENTS_FETCH_LIMIT,
      });
      setData((current) => {
        if (!current) return current;
        const seen = new Set<string>(current.events.events.map((entry) => entry.id));
        const mergedEvents = [...current.events.events];
        for (const next of nextPage.events) {
          if (seen.has(next.id)) continue;
          seen.add(next.id);
          mergedEvents.push(next);
        }
        return {
          ...current,
          events: {
            ...nextPage,
            events: mergedEvents,
            totalPages: Math.max(current.events.totalPages, nextPage.totalPages),
          },
        };
      });
    } catch (error: unknown) {
      setLoadMoreEventsError(toErrorMessage(error));
    } finally {
      setLoadingMoreEvents(false);
    }
  }, [
    eventsLevelFilter,
    eventsNextCursor,
    loading,
    loadingMoreEvents,
    normalizedEventsEventTypeFilter,
    normalizedEventsQuery,
    normalizedEventsServiceFilter,
    scope,
    session.claims,
  ]);

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
        <DashboardTable
          ariaLabel="Observability service health"
          columns={OBSERVABILITY_SERVICE_TABLE_COLUMNS}
          pagination={servicesPagination.pagination}
        >
          <DashboardTableHeader>
            <DashboardTableHeaderCell>Service</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Recent failures</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Latest incident</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Scope project</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Scope environment</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Summary state</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Notes</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {services.length === 0 ? (
            <DashboardTableState>
              {loading ? 'Loading service health...' : 'No service health records for this scope.'}
            </DashboardTableState>
          ) : (
            servicesPagination.rows.map((entry) => (
              <DashboardTableRow key={entry.service}>
                <DashboardTableCell>{entry.service}</DashboardTableCell>
                <DashboardTableCell>{entry.status}</DashboardTableCell>
                <DashboardTableCell>{entry.recentFailureCount}</DashboardTableCell>
                <DashboardTableCell truncate>
                  {formatTimestamp(entry.latestIncidentAt)}
                </DashboardTableCell>
                <DashboardTableCell>{scope.projectId || '-'}</DashboardTableCell>
                <DashboardTableCell>{scope.environmentId || '-'}</DashboardTableCell>
                <DashboardTableCell>{summary?.status.state || '-'}</DashboardTableCell>
                <DashboardTableCell>
                  {entry.recentFailureCount > 0 ? 'Investigate recent failures' : '-'}
                </DashboardTableCell>
              </DashboardTableRow>
            ))
          )}
        </DashboardTable>
      </section>

      <section
        className="dashboard-view__section dashboard-observability-section--plain"
        aria-label="Observability events table"
      >
        <h2>Recent events</h2>
        <p className="dashboard-pagination-note">Default window: last 24 hours.</p>
        <div
          className="dashboard-filters dashboard-observability-filters"
          aria-label="Observability event filters"
        >
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
        <DashboardTable
          ariaLabel="Observability events"
          columns={OBSERVABILITY_EVENTS_TABLE_COLUMNS}
          pagination={eventsPagination.pagination}
        >
          <DashboardTableHeader>
            <DashboardTableHeaderCell>Timestamp</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Service</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Level</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Event type</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Message</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Request</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Trace</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Metadata</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {events.length === 0 ? (
            <DashboardTableState>
              {loading
                ? 'Loading observability events...'
                : hasEventsFilters
                  ? 'No observability events match the current filters.'
                  : 'No observability events for this scope.'}
            </DashboardTableState>
          ) : (
            eventsPagination.rows.map((entry) => (
              <DashboardTableRow key={entry.id}>
                <DashboardTableCell truncate>{formatTimestamp(entry.timestamp)}</DashboardTableCell>
                <DashboardTableCell title={`${entry.service}/${entry.component}`}>
                  {entry.service || '-'} {entry.component ? `(${entry.component})` : ''}
                </DashboardTableCell>
                <DashboardTableCell>{entry.level}</DashboardTableCell>
                <DashboardTableCell>{entry.eventType || '-'}</DashboardTableCell>
                <DashboardTableCell title={entry.message}>
                  {entry.message || '-'}
                </DashboardTableCell>
                <DashboardTableCell>{entry.requestId || '-'}</DashboardTableCell>
                <DashboardTableCell>{entry.traceId || '-'}</DashboardTableCell>
                <DashboardTableCell title={JSON.stringify(entry.metadata)}>
                  {metadataSummary(entry.metadata)}
                </DashboardTableCell>
              </DashboardTableRow>
            ))
          )}
        </DashboardTable>
        {loadMoreEventsError ? (
          <p className="dashboard-pagination-note" role="alert">
            {loadMoreEventsError}
          </p>
        ) : null}
        {eventsNextCursor ? (
          <p>
            <button
              type="button"
              className="dashboard-pagination-button dashboard-pagination-button--secondary"
              onClick={() => {
                void handleLoadMoreEvents();
              }}
              disabled={loading || loadingMoreEvents}
            >
              {loadingMoreEvents ? 'Loading more events...' : 'Load more events'}
            </button>
          </p>
        ) : null}
      </section>
    </div>
  );
}

export default ObservabilityPage;
