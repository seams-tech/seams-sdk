import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  DashboardConsoleObservabilityApiError,
  type DashboardConsoleObservabilityModuleStatus,
  type DashboardConsoleObservabilitySnapshot,
  getDashboardObservabilitySnapshot,
  isDashboardConsoleObservabilityApiErrorCode,
} from './consoleObservabilityApi';

const OBSERVABILITY_EVENTS_PAGE_SIZE = 50;

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
  const [eventsCursor, setEventsCursor] = React.useState<string | null>(null);
  const [previousEventCursors, setPreviousEventCursors] = React.useState<Array<string | null>>([]);

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

  const loadObservability = React.useCallback(() => {
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
      eventsLimit: OBSERVABILITY_EVENTS_PAGE_SIZE,
    })
      .then((snapshot) => {
        if (cancelled) return;
        const nextWarnings = [
          toStatusWarning('Summary', snapshot.summary.status),
          toStatusWarning('Events', snapshot.events.status),
          toStatusWarning('Timeseries', snapshot.timeseries.status),
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
  }, [eventsCursor, scope, session.claims, session.errorMessage]);

  React.useEffect(() => {
    setEventsCursor(null);
    setPreviousEventCursors([]);
  }, [scope.environmentId, scope.projectId]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadObservability();
    return cleanup;
  }, [loadObservability, session.loading]);

  const summary = data?.summary || null;
  const events = data?.events.events || [];
  const timeseries = data?.timeseries.buckets || [];
  const services = data?.services.services || [];
  const hasNextEventsPage = Boolean(data?.events.nextCursor);
  const hasPreviousEventsPage = previousEventCursors.length > 0;
  const eventsPageNumber = previousEventCursors.length + 1;
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

  return (
    <div className="dashboard-view" aria-label="Observability page">
      <section className="dashboard-view__section" aria-label="Observability overview">
        <h2>Observability overview</h2>
        <p>
          Inspect service-level failures, recent events, and latency trends for the currently selected
          project/environment scope.
        </p>
        <div className="dashboard-form-actions">
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={() => loadObservability()}
            disabled={loading}
          >
            {loading ? 'Loading...' : 'Reload observability'}
          </button>
          <span className="dashboard-pagination-note">
            Project: {scope.projectId || '-'} | Environment: {scope.environmentId || '-'}
          </span>
        </div>
        {errorMessage ? <p className="dashboard-pagination-note">{errorMessage}</p> : null}
        {warnings.length > 0 ? (
          <ul className="dashboard-view-list" aria-label="Observability status warnings">
            {warnings.map((warning) => (
              <li key={warning}>{warning}</li>
            ))}
          </ul>
        ) : null}
      </section>

      <section
        className="dashboard-observability-summary"
        aria-label="Observability summary metrics"
      >
        <article className="dashboard-observability-summary__item">
          <p className="dashboard-observability-summary__label">error rate</p>
          <p className="dashboard-observability-summary__value">
            {formatPercent(summary?.errorRate || 0)}
          </p>
        </article>
        <article className="dashboard-observability-summary__item">
          <p className="dashboard-observability-summary__label">p95 latency</p>
          <p className="dashboard-observability-summary__value">
            {Math.max(0, Number(summary?.p95LatencyMs || 0)).toFixed(0)}ms
          </p>
        </article>
        <article className="dashboard-observability-summary__item">
          <p className="dashboard-observability-summary__label">failing services</p>
          <p className="dashboard-observability-summary__value">{summary?.failingServices || 0}</p>
        </article>
        <article className="dashboard-observability-summary__item">
          <p className="dashboard-observability-summary__label">dead letters</p>
          <p className="dashboard-observability-summary__value">{summary?.deadLetterCount || 0}</p>
        </article>
      </section>

      <section className="dashboard-view__section" aria-label="Observability events table">
        <h2>Recent events</h2>
        <p className="dashboard-pagination-note">
          Showing up to {OBSERVABILITY_EVENTS_PAGE_SIZE} events per page.
        </p>
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
              {loading ? 'Loading observability events...' : 'No observability events for this scope.'}
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
        <div className="dashboard-form-actions">
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
          <span className="dashboard-pagination-note">
            Page {eventsPageNumber} | {events.length} events
          </span>
        </div>
      </section>

      <section className="dashboard-view__section" aria-label="Observability service health table">
        <h2>Service health</h2>
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

      <section className="dashboard-view__section" aria-label="Observability timeseries table">
        <h2>Latency and error trends</h2>
        <section className="dashboard-table-wrapper" aria-label="Observability timeseries">
          <div className="dashboard-table-header" role="row">
            <span>Bucket start</span>
            <span>Bucket end</span>
            <span>Errors</span>
            <span>Requests</span>
            <span>p50 latency</span>
            <span>p95 latency</span>
            <span>Summary state</span>
            <span>Trend note</span>
          </div>
          {timeseries.length === 0 ? (
            <p className="dashboard-table-limit">
              {loading ? 'Loading timeseries buckets...' : 'No timeseries data for this scope.'}
            </p>
          ) : (
            timeseries.map((entry) => (
              <div
                className="dashboard-table-row"
                key={`${entry.start}:${entry.end}`}
                role="row"
              >
                <span>{formatTimestamp(entry.start)}</span>
                <span>{formatTimestamp(entry.end)}</span>
                <span>{entry.errorCount}</span>
                <span>{entry.requestCount}</span>
                <span>{entry.p50LatencyMs.toFixed(0)}ms</span>
                <span>{entry.p95LatencyMs.toFixed(0)}ms</span>
                <span>{summary?.status.state || '-'}</span>
                <span>{entry.errorCount > 0 ? 'Errors present' : '-'}</span>
              </div>
            ))
          )}
        </section>
      </section>
    </div>
  );
}

export default ObservabilityPage;
