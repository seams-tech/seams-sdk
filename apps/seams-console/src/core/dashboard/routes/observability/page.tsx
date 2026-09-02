import React from 'react';
import { formatDashboardTimestamp } from '../../utils/timestamps';
import { ActivityIcon } from '../../icons/SidebarIcons';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableCell,
  DashboardTableDetailsGrid,
  DashboardTableDetailsItem,
  DashboardTableDetailsPanel,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  DashboardTableStatus,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import {
  DASHBOARD_EMPTY_VALUE,
  dashboardStatusLabel,
  dashboardStatusTone,
} from '../../utils/statusTone';
import { DashboardPageActions } from '../../components/DashboardPageActions';
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
type ObservabilityWindowKey = '1h' | '24h' | '7d';
const DEFAULT_OBSERVABILITY_WINDOW_KEY: ObservabilityWindowKey = '24h';
const OBSERVABILITY_WINDOW_OPTIONS: ReadonlyArray<{
  value: ObservabilityWindowKey;
  label: string;
  durationMs: number;
}> = [
  { value: '1h', label: 'Last hour', durationMs: 1000 * 60 * 60 },
  { value: '24h', label: 'Last 24 hours', durationMs: DEFAULT_OBSERVABILITY_WINDOW_MS },
  { value: '7d', label: 'Last 7 days', durationMs: 1000 * 60 * 60 * 24 * 7 },
];
const OBSERVABILITY_SERVICE_TABLE_COLUMNS = dashboardTableColumns(1.9, 0.75, 0.7, 1);
const OBSERVABILITY_EVENTS_TABLE_COLUMNS = dashboardTableColumns(2.4, 0.75, 0.7, 0.95, 0.5);

function formatTimestamp(value: string | undefined | null): string {
  return formatDashboardTimestamp(value, '—');
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

function resolveObservabilityWindowOption(
  value: ObservabilityWindowKey,
): (typeof OBSERVABILITY_WINDOW_OPTIONS)[number] {
  return (
    OBSERVABILITY_WINDOW_OPTIONS.find((entry) => entry.value === value) ||
    OBSERVABILITY_WINDOW_OPTIONS.find((entry) => entry.value === DEFAULT_OBSERVABILITY_WINDOW_KEY)!
  );
}

function buildObservabilityScopeWindow(windowKey: ObservabilityWindowKey): {
  from: string;
  to: string;
} {
  const option = resolveObservabilityWindowOption(windowKey);
  const to = new Date();
  const from = new Date(to.getTime() - option.durationMs);
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
  /* One page-level time window: service health and the event log always
     describe the same period, so a second select was pure duplication. */
  const [windowFilter, setWindowFilter] = React.useState<ObservabilityWindowKey>(
    DEFAULT_OBSERVABILITY_WINDOW_KEY,
  );
  const [eventsQueryInput, setEventsQueryInput] = React.useState<string>('');
  const [eventsLevelFilter, setEventsLevelFilter] = React.useState<
    DashboardConsoleObservabilityLevel | ''
  >('');
  const [expandedEventId, setExpandedEventId] = React.useState<string>('');
  const deferredEventsQueryInput = React.useDeferredValue(eventsQueryInput);

  const scopeWindow = React.useMemo(
    () => buildObservabilityScopeWindow(windowFilter),
    [windowFilter],
  );
  const pageScope = React.useMemo(
    () => ({
      ...scopeWindow,
      ...(String(selectedContext.project || '').trim()
        ? { projectId: String(selectedContext.project || '').trim() }
        : {}),
      ...(String(selectedContext.environment || '').trim()
        ? { environmentId: String(selectedContext.environment || '').trim() }
        : {}),
    }),
    [scopeWindow, selectedContext.environment, selectedContext.project],
  );
  const serviceScope = pageScope;
  const eventsScope = pageScope;
  const normalizedEventsQuery = React.useMemo(
    () => String(deferredEventsQueryInput || '').trim(),
    [deferredEventsQueryInput],
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
      getDashboardObservabilitySummary(serviceScope),
      listDashboardObservabilityServices({ ...serviceScope, limit: 25 }),
      listDashboardObservabilityEvents({
        ...eventsScope,
        ...(normalizedEventsQuery ? { query: normalizedEventsQuery } : {}),
        ...(eventsLevelFilter ? { level: eventsLevelFilter } : {}),
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
    normalizedEventsQuery,
    eventsScope,
    session.claims,
    session.errorMessage,
    session.loading,
    serviceScope,
  ]);

  const summary = data?.summary || null;
  const events = data?.events.events || [];
  const eventsNextCursor = React.useMemo(
    () => String(data?.events.nextCursor || '').trim(),
    [data?.events.nextCursor],
  );
  const services = data?.services.services || [];
  const hasEventsFilters = Boolean(normalizedEventsQuery) || Boolean(eventsLevelFilter);
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
        ...eventsScope,
        ...(normalizedEventsQuery ? { query: normalizedEventsQuery } : {}),
        ...(eventsLevelFilter ? { level: eventsLevelFilter } : {}),
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
    normalizedEventsQuery,
    eventsScope,
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
        aria-label="Observability overview"
      >
        <h2 className="dashboard-visually-hidden">Overview</h2>
        <DashboardPageActions>
          <label className="dashboard-form-field dashboard-form-field--observability-select">
            <select
              className="dashboard-input dashboard-select--observability"
              aria-label="Time window for all observability data"
              value={windowFilter}
              onChange={(event) => setWindowFilter(event.target.value as ObservabilityWindowKey)}
            >
              {OBSERVABILITY_WINDOW_OPTIONS.map((entry) => (
                <option key={entry.value} value={entry.value}>
                  Window: {entry.label}
                </option>
              ))}
            </select>
          </label>
        </DashboardPageActions>
        {summary ? (
          <section
            className="dashboard-observability-summary"
            aria-label="Observability summary metrics"
          >
            <article className="dashboard-observability-summary__item">
              <p className="dashboard-observability-summary__label">Error rate</p>
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
              <p className="dashboard-observability-summary__label">Failing services</p>
              <p className="dashboard-observability-summary__value">{summary.failingServices}</p>
            </article>
            <article className="dashboard-observability-summary__item">
              <p className="dashboard-observability-summary__label">Dead letters</p>
              <p className="dashboard-observability-summary__value">{summary.deadLetterCount}</p>
            </article>
          </section>
        ) : null}
      </section>

      <section
        className="dashboard-view__section dashboard-observability-section--plain"
        aria-label="Observability service health table"
      >
        <h2>Service health</h2>
        <DashboardTable
          ariaLabel="Observability service health"
          columns={OBSERVABILITY_SERVICE_TABLE_COLUMNS}
          pagination={servicesPagination.pagination}
        >
          <DashboardTableHeader>
            <DashboardTableHeaderCell>Service</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
            <DashboardTableHeaderCell className="dashboard-data-table__header-cell--end">
              Recent failures
            </DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Latest incident</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {services.length === 0 ? (
            <DashboardTableState>
              {loading ? 'Loading service health...' : 'No service health records for this scope.'}
            </DashboardTableState>
          ) : (
            servicesPagination.rows.map((entry) => (
              <DashboardTableRow key={entry.service}>
                <DashboardTableCell className="dashboard-data-table__cell--lead">
                  <div className="dashboard-lead">
                    <span className="dashboard-lead__icon" aria-hidden="true">
                      <ActivityIcon size={16} />
                    </span>
                    <span className="dashboard-lead__copy">
                      <span className="dashboard-lead__title">
                        <span className="dashboard-data-table__summary">{entry.service}</span>
                      </span>
                      <span className="dashboard-lead__sub">
                        {entry.recentFailureCount > 0
                          ? 'Investigate recent failures'
                          : 'No recent failures'}
                      </span>
                    </span>
                  </div>
                </DashboardTableCell>
                <DashboardTableCell>
                  <DashboardTableStatus tone={dashboardStatusTone(entry.status)}>
                    {dashboardStatusLabel(entry.status)}
                  </DashboardTableStatus>
                </DashboardTableCell>
                <DashboardTableCell align="end">{entry.recentFailureCount}</DashboardTableCell>
                <DashboardTableCell truncate>
                  {formatTimestamp(entry.latestIncidentAt)}
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
        <h2>Event log</h2>
        <div
          className="dashboard-observability-controls-card dashboard-observability-controls-card--event-log"
          aria-label="Observability event controls"
        >
          <div
            className="dashboard-filters dashboard-observability-filters dashboard-observability-filters--primary"
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
                  setEventsLevelFilter(
                    event.target.value as DashboardConsoleObservabilityLevel | '',
                  )
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
          </div>
        </div>
        <DashboardTable
          ariaLabel="Observability events"
          columns={OBSERVABILITY_EVENTS_TABLE_COLUMNS}
          pagination={eventsPagination.pagination}
        >
          <DashboardTableHeader>
            <DashboardTableHeaderCell>Event</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Level</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Service</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Timestamp</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Details</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {events.length === 0 ? (
            <DashboardTableState>
              {loading
                ? 'Loading observability events...'
                : hasEventsFilters
                  ? 'No observability incidents match the current filters.'
                  : 'No incidents in the selected window. Observability is incident-driven, so healthy periods can be empty.'}
            </DashboardTableState>
          ) : (
            eventsPagination.rows.map((entry) => {
              const isExpanded = expandedEventId === entry.id;
              return (
                <React.Fragment key={entry.id}>
                  <DashboardTableRow>
                    <DashboardTableCell
                      title={`${entry.eventType} · ${entry.message}`}
                      className="dashboard-data-table__cell--lead"
                    >
                      <span className="dashboard-lead__copy">
                        <span className="dashboard-lead__title">
                          <span className="dashboard-data-table__summary">
                            {entry.eventType || DASHBOARD_EMPTY_VALUE}
                          </span>
                        </span>
                        <span className="dashboard-lead__sub">
                          {entry.message || DASHBOARD_EMPTY_VALUE}
                        </span>
                      </span>
                    </DashboardTableCell>
                    <DashboardTableCell>
                      <DashboardTableStatus tone={dashboardStatusTone(entry.level)}>
                        {dashboardStatusLabel(entry.level)}
                      </DashboardTableStatus>
                    </DashboardTableCell>
                    <DashboardTableCell className="dashboard-data-table__cell--nowrap">
                      {entry.service || DASHBOARD_EMPTY_VALUE}
                    </DashboardTableCell>
                    <DashboardTableCell truncate>
                      {formatTimestamp(entry.timestamp)}
                    </DashboardTableCell>
                    <DashboardTableCell align="center">
                      <DashboardTableActionButton
                        aria-expanded={isExpanded}
                        onClick={() =>
                          setExpandedEventId((current) => (current === entry.id ? '' : entry.id))
                        }
                      >
                        {isExpanded ? 'Hide' : 'View'}
                      </DashboardTableActionButton>
                    </DashboardTableCell>
                  </DashboardTableRow>
                  {isExpanded ? (
                    <DashboardTableDetailsPanel>
                      <DashboardTableDetailsGrid>
                        <DashboardTableDetailsItem label="Component">
                          <span>{entry.component || DASHBOARD_EMPTY_VALUE}</span>
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Request ID">
                          {entry.requestId ? <code>{entry.requestId}</code> : <span>{DASHBOARD_EMPTY_VALUE}</span>}
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Trace ID">
                          {entry.traceId ? <code>{entry.traceId}</code> : <span>{DASHBOARD_EMPTY_VALUE}</span>}
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Metadata">
                          <span>{metadataSummary(entry.metadata)}</span>
                        </DashboardTableDetailsItem>
                      </DashboardTableDetailsGrid>
                    </DashboardTableDetailsPanel>
                  ) : null}
                </React.Fragment>
              );
            })
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
