import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  createDashboardAuditExport,
  listDashboardAuditEvents,
  listDashboardAuditEvidence,
  listDashboardAuditExports,
  type DashboardConsoleAuditCategory,
  type DashboardConsoleAuditEvidenceDomain,
  type DashboardConsoleAuditExportDomain,
  type DashboardConsoleAuditExportFormat,
  type DashboardConsoleAuditExportRecord,
  type DashboardConsoleAuditEvent,
  type DashboardConsoleAuditEvidenceRecord,
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
const EVIDENCE_DOMAIN_OPTIONS: readonly DashboardConsoleAuditEvidenceDomain[] = [
  'POLICY',
  'BILLING',
  'KEY_EXPORT',
  'SECURITY',
];
const EXPORT_DOMAIN_OPTIONS: readonly DashboardConsoleAuditExportDomain[] = [
  'ALL',
  'POLICY',
  'BILLING',
  'KEY_EXPORT',
  'SECURITY',
];
const EXPORT_FORMAT_OPTIONS: readonly DashboardConsoleAuditExportFormat[] = ['JSONL', 'CSV'];

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
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

export function AuditLogsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const selectedProjectId = String(selectedContext.project || '').trim();
  const selectedEnvironmentId = String(selectedContext.environment || '').trim();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [events, setEvents] = React.useState<DashboardConsoleAuditEvent[]>([]);
  const [evidence, setEvidence] = React.useState<DashboardConsoleAuditEvidenceRecord[]>([]);
  const [exportJobs, setExportJobs] = React.useState<DashboardConsoleAuditExportRecord[]>([]);
  const [eventCategoryFilter, setEventCategoryFilter] = React.useState<string>('');
  const [eventOutcomeFilter, setEventOutcomeFilter] = React.useState<string>('');
  const [eventActorFilter, setEventActorFilter] = React.useState<string>('');
  const [evidenceDomainFilter, setEvidenceDomainFilter] = React.useState<string>('');
  const [exportDomainInput, setExportDomainInput] = React.useState<DashboardConsoleAuditExportDomain>('ALL');
  const [exportFormatInput, setExportFormatInput] = React.useState<DashboardConsoleAuditExportFormat>('JSONL');
  const [exportRequestError, setExportRequestError] = React.useState<string>('');
  const [creatingExport, setCreatingExport] = React.useState<boolean>(false);

  const loadAudit = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setEvents([]);
      setEvidence([]);
      setExportJobs([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    setExportRequestError('');
    Promise.all([
      listDashboardAuditEvents({
        ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
        ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
        ...(eventCategoryFilter
          ? { category: eventCategoryFilter as DashboardConsoleAuditCategory }
          : {}),
        ...(eventOutcomeFilter
          ? { outcome: eventOutcomeFilter as DashboardConsoleAuditOutcome }
          : {}),
        ...(eventActorFilter ? { actorUserId: eventActorFilter } : {}),
        limit: 100,
      }),
      listDashboardAuditEvidence({
        ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
        ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
        ...(evidenceDomainFilter
          ? { domain: evidenceDomainFilter as DashboardConsoleAuditEvidenceDomain }
          : {}),
        limit: 100,
      }),
      listDashboardAuditExports({ limit: 50 }),
    ])
      .then(([nextEvents, nextEvidence, nextExports]) => {
        if (cancelled) return;
        setEvents(nextEvents);
        setEvidence(nextEvidence);
        setExportJobs(nextExports);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setEvents([]);
        setEvidence([]);
        setExportJobs([]);
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
    evidenceDomainFilter,
    eventActorFilter,
    eventCategoryFilter,
    eventOutcomeFilter,
    selectedEnvironmentId,
    selectedProjectId,
    session.claims,
    session.errorMessage,
  ]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadAudit();
    return cleanup;
  }, [loadAudit, session.loading]);

  return (
    <div className="dashboard-view" aria-label="Audit logs page">
      <section className="dashboard-view__section" aria-label="Audit log filters">
        <h2>Audit logs</h2>
        <p>
          Review who did what across approvals, policy changes, key exports, billing events, and
          related operations.
        </p>

        <div className="dashboard-view-grid dashboard-view-grid--two">
          <label className="dashboard-form-field">
            <span>Category</span>
            <select
              className="dashboard-select"
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
              className="dashboard-select"
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
            <span>Actor user ID</span>
            <input
              className="dashboard-input"
              value={eventActorFilter}
              onChange={(event) => setEventActorFilter(event.target.value)}
              placeholder="console-admin"
            />
          </label>

          <label className="dashboard-form-field">
            <span>Evidence domain (optional)</span>
            <select
              className="dashboard-select"
              value={evidenceDomainFilter}
              onChange={(event) => setEvidenceDomainFilter(event.target.value)}
            >
              <option value="">All domains</option>
              {EVIDENCE_DOMAIN_OPTIONS.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="dashboard-form-actions">
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={() => loadAudit()}
            disabled={loading}
          >
            {loading ? 'Loading...' : 'Reload audit logs'}
          </button>
          <span className="dashboard-pagination-note">
            Events: {events.length} | Evidence records: {evidence.length} | Exports: {exportJobs.length}
          </span>
        </div>
        {errorMessage ? <p className="dashboard-pagination-note">{errorMessage}</p> : null}
      </section>

      <section className="dashboard-view__section" aria-label="Audit events table">
        <h2>Audit events</h2>
        <section className="dashboard-table-wrapper" aria-label="Audit events">
          <div className="dashboard-table-header" role="row">
            <span>Timestamp</span>
            <span>Category</span>
            <span>Action</span>
            <span>Outcome</span>
            <span>Actor</span>
            <span>Metadata</span>
          </div>
          {events.length === 0 ? (
            <p className="dashboard-empty-state">
              {loading ? 'Loading audit events...' : 'No audit events for current filters.'}
            </p>
          ) : (
            events.map((row) => (
              <div className="dashboard-table-row" key={row.id} role="row">
                <span>{formatTimestamp(row.createdAt)}</span>
                <span>{row.category}</span>
                <span title={row.summary}>{row.action || '-'}</span>
                <span>{row.outcome}</span>
                <span>{row.actorUserId}</span>
                <span title={JSON.stringify(row.metadata)}>{metadataSummary(row.metadata)}</span>
              </div>
            ))
          )}
        </section>
      </section>

      <section className="dashboard-view__section" aria-label="Audit evidence table">
        <h2>Evidence records</h2>
        <section className="dashboard-table-wrapper" aria-label="Evidence records">
          <div className="dashboard-table-header" role="row">
            <span>Timestamp</span>
            <span>Domain</span>
            <span>Title</span>
            <span>Summary</span>
            <span>Event IDs</span>
            <span>References</span>
          </div>
          {evidence.length === 0 ? (
            <p className="dashboard-empty-state">
              {loading ? 'Loading evidence records...' : 'No evidence records for current filters.'}
            </p>
          ) : (
            evidence.map((row) => (
              <div className="dashboard-table-row" key={row.id} role="row">
                <span>{formatTimestamp(row.createdAt)}</span>
                <span>{row.domain}</span>
                <span>{row.title || '-'}</span>
                <span title={row.summary}>{row.summary || '-'}</span>
                <span>{row.eventIds.join(', ') || '-'}</span>
                <span>
                  {row.references.map((entry) => `${entry.kind}:${entry.referenceId}`).join(', ') || '-'}
                </span>
              </div>
            ))
          )}
        </section>
      </section>

      <section className="dashboard-view__section" aria-label="Audit export controls">
        <h2>Evidence export artifacts</h2>
        <p>
          Queue high-level evidence exports for audit investigations. Export materialization and immutable
          archival are intentionally scaffolded in this phase.
        </p>

        <div className="dashboard-view-grid dashboard-view-grid--two">
          <label className="dashboard-form-field">
            <span>Export domain</span>
            <select
              className="dashboard-select"
              value={exportDomainInput}
              onChange={(event) =>
                setExportDomainInput(event.target.value as DashboardConsoleAuditExportDomain)
              }
            >
              {EXPORT_DOMAIN_OPTIONS.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </select>
          </label>

          <label className="dashboard-form-field">
            <span>Export format</span>
            <select
              className="dashboard-select"
              value={exportFormatInput}
              onChange={(event) =>
                setExportFormatInput(event.target.value as DashboardConsoleAuditExportFormat)
              }
            >
              {EXPORT_FORMAT_OPTIONS.map((entry) => (
                <option key={entry} value={entry}>
                  {entry}
                </option>
              ))}
            </select>
          </label>
        </div>

        <div className="dashboard-form-actions">
          <button
            type="button"
            className="dashboard-pagination-button"
            disabled={creatingExport}
            onClick={async () => {
              setCreatingExport(true);
              setExportRequestError('');
              try {
                const created = await createDashboardAuditExport({
                  format: exportFormatInput,
                  ...(exportDomainInput !== 'ALL' ? { domain: exportDomainInput } : {}),
                  ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
                  ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
                });
                setExportJobs((prev) => [created, ...prev.filter((entry) => entry.id !== created.id)]);
              } catch (error: unknown) {
                setExportRequestError(error instanceof Error ? error.message : String(error));
              } finally {
                setCreatingExport(false);
              }
            }}
          >
            {creatingExport ? 'Queueing...' : 'Queue evidence export'}
          </button>
          {exportRequestError ? <span className="dashboard-pagination-note">{exportRequestError}</span> : null}
        </div>

        <section className="dashboard-table-wrapper" aria-label="Audit export queue">
          <div className="dashboard-table-header" role="row">
            <span>Created</span>
            <span>Export ID</span>
            <span>Status</span>
            <span>Format</span>
            <span>Scope filters</span>
            <span>Failure</span>
          </div>
          {exportJobs.length === 0 ? (
            <p className="dashboard-empty-state">
              {loading ? 'Loading exports...' : 'No exports queued yet.'}
            </p>
          ) : (
            exportJobs.map((row) => (
              <div className="dashboard-table-row" key={row.id} role="row">
                <span>{formatTimestamp(row.createdAt)}</span>
                <span>{row.id}</span>
                <span>{row.status}</span>
                <span>{row.format}</span>
                <span>
                  {[
                    row.filters.domain || 'ALL',
                    row.filters.projectId || '-',
                    row.filters.environmentId || '-',
                  ].join(' / ')}
                </span>
                <span>{row.failureMessage || '-'}</span>
              </div>
            ))
          )}
        </section>
      </section>
    </div>
  );
}
