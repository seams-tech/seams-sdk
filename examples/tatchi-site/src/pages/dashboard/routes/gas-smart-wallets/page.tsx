import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  getDashboardGasReadiness,
  type DashboardGasReadiness,
} from '../consoleInsightsApi';

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function formatUsdMinor(value: number): string {
  const n = Number(value || 0);
  return `$${(n / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

export function GasSponsorshipSmartWalletsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [readiness, setReadiness] = React.useState<DashboardGasReadiness | null>(null);

  const loadGasData = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setReadiness(null);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    getDashboardGasReadiness({
      ...(selectedContext.project ? { projectId: selectedContext.project } : {}),
      ...(selectedContext.environment ? { environmentId: selectedContext.environment } : {}),
    })
      .then((nextReadiness) => {
        if (cancelled) return;
        setReadiness(nextReadiness);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setReadiness(null);
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
    selectedContext.environment,
    selectedContext.project,
    session.claims,
    session.errorMessage,
  ]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadGasData();
    return cleanup;
  }, [loadGasData, session.loading]);

  const summaryMetrics = React.useMemo(
    () => [
      {
        label: 'Wallets in scope',
        value: String(readiness?.totals.walletCount || 0),
        hint: readiness?.truncated ? 'Result truncated by backend pagination budget' : 'Full scope',
      },
      {
        label: 'Chains covered',
        value: String(readiness?.totals.chainCount || 0),
        hint: 'Distinct wallet.chain values',
      },
      {
        label: `Recent active (${String(readiness?.totals.recentWindowDays || 7)}d)`,
        value: String(readiness?.totals.recentActiveWalletCount || 0),
        hint: 'ACTIVE wallets with recent activity',
      },
      {
        label: 'Total balance',
        value: formatUsdMinor(readiness?.totals.totalBalanceMinor || 0),
        hint: 'Aggregated from wallet inventory',
      },
    ],
    [readiness],
  );

  return (
    <div className="dashboard-view" aria-label="Gas sponsorship and smart wallets page">
      <section className="dashboard-view__section" aria-label="Gas and smart-wallet scope">
        <h2>Gas readiness telemetry</h2>
        <p>
          Backed by `GET /console/gas/readiness`. Scope project{' '}
          {selectedContext.project || '-'}, environment {selectedContext.environment || '-'}.
        </p>
        <button type="button" className="dashboard-pagination-button" onClick={() => loadGasData()}>
          Refresh gas data
        </button>
      </section>

      {session.loading || loading ? (
        <section className="dashboard-view__section">
          <p>Loading gas data...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Gas data unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : errorMessage ? (
        <section className="dashboard-view__section">
          <p>Gas data unavailable: {errorMessage}</p>
        </section>
      ) : (
        <>
          <section className="dashboard-kpi-grid dashboard-kpi-grid--content" aria-label="Gas summary metrics">
            {summaryMetrics.map((metric) => (
              <article className="dashboard-kpi-card" key={metric.label}>
                <p className="dashboard-kpi-card__label">{metric.label}</p>
                <p className="dashboard-kpi-card__value">{metric.value}</p>
                <p className="dashboard-kpi-card__hint">{metric.hint}</p>
              </article>
            ))}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Chain readiness table">
            <div className="dashboard-table-header" role="row">
              <span>Chain</span>
              <span>Wallets</span>
              <span>Active</span>
              <span>Recent activity</span>
              <span>Total balance</span>
              <span>Avg balance</span>
              <span>Scope project</span>
              <span>Scope environment</span>
            </div>
            {(readiness?.chains.length || 0) === 0 ? (
              <p className="dashboard-table-limit">No chain telemetry rows in selected scope.</p>
            ) : (
              <>
                {readiness?.chains.map((chain) => (
                  <div className="dashboard-table-row" key={chain.chain} role="row">
                    <span>{chain.chain}</span>
                    <span>{String(chain.walletCount)}</span>
                    <span>{String(chain.activeWalletCount)}</span>
                    <span>{String(chain.recentActivityCount)}</span>
                    <span>{formatUsdMinor(chain.totalBalanceMinor)}</span>
                    <span>{formatUsdMinor(chain.avgBalanceMinor)}</span>
                    <span>{readiness.scope.projectId || '-'}</span>
                    <span>{readiness.scope.environmentId || '-'}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {readiness?.chains.length || 0} chain aggregate
                  {(readiness?.chains.length || 0) === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Recent wallet activity sample">
            <div className="dashboard-table-header" role="row">
              <span>Wallet ID</span>
              <span>Chain</span>
              <span>Status</span>
              <span>Last activity</span>
              <span>Balance</span>
              <span>Policy ID</span>
              <span>User ID</span>
              <span>Updated</span>
            </div>
            {(readiness?.recentWalletSample.length || 0) === 0 ? (
              <p className="dashboard-table-limit">No recent wallet activity sample rows.</p>
            ) : (
              <>
                {readiness?.recentWalletSample.map((wallet) => (
                  <div className="dashboard-table-row" key={wallet.id} role="row">
                    <span>{wallet.id}</span>
                    <span>{wallet.chain || '-'}</span>
                    <span>{wallet.status || '-'}</span>
                    <span>{formatTimestamp(wallet.lastActivityAt)}</span>
                    <span>{formatUsdMinor(wallet.balanceMinor)}</span>
                    <span>{wallet.policyId || '-'}</span>
                    <span>{wallet.userId || '-'}</span>
                    <span>{formatTimestamp(wallet.updatedAt)}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {readiness?.recentWalletSample.length || 0} wallet
                  {(readiness?.recentWalletSample.length || 0) === 1 ? '' : 's'} sample.
                </p>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default GasSponsorshipSmartWalletsPage;
