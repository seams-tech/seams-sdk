import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  getDashboardExportGovernance,
  type DashboardExportGovernance,
} from '../consoleInsightsApi';

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function joinOrDash(values: string[]): string {
  return values.length > 0 ? values.join(', ') : '-';
}

export function ExportKeysSettingsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [governance, setGovernance] = React.useState<DashboardExportGovernance | null>(null);

  const loadExportData = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setGovernance(null);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    getDashboardExportGovernance({
      ...(selectedContext.environment ? { environmentId: selectedContext.environment } : {}),
    })
      .then((nextGovernance) => {
        if (cancelled) return;
        setGovernance(nextGovernance);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setGovernance(null);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedContext.environment, session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadExportData();
    return cleanup;
  }, [loadExportData, session.loading]);

  const summaryMetrics = React.useMemo(
    () => [
      {
        label: 'API keys',
        value: String(governance?.totals.apiKeyCount || 0),
        hint: 'Total keys in org scope',
      },
      {
        label: 'Export-scoped',
        value: String(governance?.totals.exportScopedKeyCount || 0),
        hint: 'Scopes containing "export"',
      },
      {
        label: 'Active export keys',
        value: String(governance?.totals.activeExportScopedKeyCount || 0),
        hint: 'Status equals ACTIVE',
      },
      {
        label: 'Selected environment',
        value: String(governance?.totals.selectedEnvironmentExportScopedKeyCount || 0),
        hint: governance?.scope.environmentId
          ? `Environment ${governance.scope.environmentId}`
          : 'No environment filter',
      },
    ],
    [governance],
  );

  return (
    <div className="dashboard-view" aria-label="Export keys settings page">
      <section className="dashboard-view__section" aria-label="Export scope overview">
        <h2>Export governance</h2>
        <p>
          Backed by `GET /console/export/governance`. Environment filter{' '}
          {selectedContext.environment || '-'}.
        </p>
        <button type="button" className="dashboard-pagination-button" onClick={() => loadExportData()}>
          Refresh export governance
        </button>
      </section>

      {session.loading || loading ? (
        <section className="dashboard-view__section">
          <p>Loading export governance data...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Export governance unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : errorMessage ? (
        <section className="dashboard-view__section">
          <p>Export governance unavailable: {errorMessage}</p>
        </section>
      ) : (
        <>
          <section className="dashboard-kpi-grid dashboard-kpi-grid--content" aria-label="Export key summary metrics">
            {summaryMetrics.map((metric) => (
              <article className="dashboard-kpi-card" key={metric.label}>
                <p className="dashboard-kpi-card__label">{metric.label}</p>
                <p className="dashboard-kpi-card__value">{metric.value}</p>
                <p className="dashboard-kpi-card__hint">{metric.hint}</p>
              </article>
            ))}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Export-scoped API keys">
            <div className="dashboard-table-header" role="row">
              <span>Key ID</span>
              <span>Name</span>
              <span>Environment</span>
              <span>Status</span>
              <span>Scopes</span>
              <span>Last used</span>
              <span>Anomalies</span>
              <span>Secret version</span>
            </div>
            {(governance?.exportScopedKeys.length || 0) === 0 ? (
              <p className="dashboard-table-limit">No export-scoped API keys found.</p>
            ) : (
              <>
                {governance?.exportScopedKeys.map((key) => (
                  <div className="dashboard-table-row" key={key.id} role="row">
                    <span>{key.id}</span>
                    <span>{key.name || '-'}</span>
                    <span>{key.environmentId || '-'}</span>
                    <span>{key.status || '-'}</span>
                    <span>{joinOrDash(key.scopes)}</span>
                    <span>{formatTimestamp(key.lastUsedAt)}</span>
                    <span>{joinOrDash(key.anomalyFlags)}</span>
                    <span>{String(key.secretVersion)}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {governance?.exportScopedKeys.length || 0} export-scoped key
                  {(governance?.exportScopedKeys.length || 0) === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Selected environment export keys">
            <div className="dashboard-table-header" role="row">
              <span>Environment</span>
              <span>Key ID</span>
              <span>Status</span>
              <span>Scopes</span>
              <span>Anomalies</span>
              <span>Created</span>
              <span>Updated</span>
              <span>Last used</span>
            </div>
            {(governance?.selectedEnvironmentKeys.length || 0) === 0 ? (
              <p className="dashboard-table-limit">No selected-environment export key rows.</p>
            ) : (
              <>
                {governance?.selectedEnvironmentKeys.map((key) => (
                  <div className="dashboard-table-row" key={key.id} role="row">
                    <span>{key.environmentId || '-'}</span>
                    <span>{key.id}</span>
                    <span>{key.status || '-'}</span>
                    <span>{joinOrDash(key.scopes)}</span>
                    <span>{joinOrDash(key.anomalyFlags)}</span>
                    <span>{formatTimestamp(key.createdAt)}</span>
                    <span>{formatTimestamp(key.updatedAt)}</span>
                    <span>{formatTimestamp(key.lastUsedAt)}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {governance?.selectedEnvironmentKeys.length || 0} selected-environment key
                  {(governance?.selectedEnvironmentKeys.length || 0) === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default ExportKeysSettingsPage;
