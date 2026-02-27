import React from 'react';
import {
  USER_WALLETS_TABLE_COLUMNS,
  USER_WALLETS_TABLE_NOTE,
} from '../../components/dashboardContent';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  formatWalletBalanceMinor,
  getDashboardWallet,
  listDashboardWallets,
  mergeDashboardWalletsById,
  type DashboardConsoleWallet,
} from '../wallets/consoleWalletApi';

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

export function UserWalletsListPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const [wallets, setWallets] = React.useState<DashboardConsoleWallet[]>([]);
  const [nextCursor, setNextCursor] = React.useState<string>('');
  const [loading, setLoading] = React.useState<boolean>(true);
  const [loadingMore, setLoadingMore] = React.useState<boolean>(false);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [paginationError, setPaginationError] = React.useState<string>('');
  const [selectedWalletId, setSelectedWalletId] = React.useState<string>('');
  const [selectedWallet, setSelectedWallet] = React.useState<DashboardConsoleWallet | null>(null);
  const [selectedLoading, setSelectedLoading] = React.useState<boolean>(false);
  const [selectedError, setSelectedError] = React.useState<string>('');
  const walletScope = React.useMemo(
    () => ({
      projectId: String(selectedContext.project || '').trim() || undefined,
      environmentId: String(selectedContext.environment || '').trim() || undefined,
    }),
    [selectedContext.environment, selectedContext.project],
  );

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    if (!session.claims) {
      setLoading(false);
      setWallets([]);
      setNextCursor('');
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      setPaginationError('');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    setPaginationError('');
    listDashboardWallets({ limit: 25, ...walletScope })
      .then((page) => {
        if (cancelled) return;
        setWallets(page.wallets);
        setNextCursor(page.nextCursor || '');
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setWallets([]);
        setNextCursor('');
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [session.claims, session.errorMessage, session.loading, walletScope]);

  const loadMore = React.useCallback(() => {
    if (!nextCursor || loadingMore) return;
    if (!session.claims) {
      setPaginationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setLoadingMore(true);
    setPaginationError('');
    listDashboardWallets({
      limit: 25,
      cursor: nextCursor,
      ...walletScope,
    })
      .then((page) => {
        setWallets((current) => mergeDashboardWalletsById(current, page.wallets));
        setNextCursor(page.nextCursor || '');
      })
      .catch((error: unknown) => {
        setPaginationError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        setLoadingMore(false);
      });
  }, [loadingMore, nextCursor, session.claims, session.errorMessage, walletScope]);

  React.useEffect(() => {
    setSelectedWalletId('');
  }, [walletScope.environmentId, walletScope.projectId]);

  React.useEffect(() => {
    if (!selectedWalletId) {
      setSelectedWallet(null);
      setSelectedLoading(false);
      setSelectedError('');
      return;
    }
    let cancelled = false;
    setSelectedLoading(true);
    setSelectedError('');
    getDashboardWallet(selectedWalletId)
      .then((wallet) => {
        if (cancelled) return;
        setSelectedWallet(wallet);
        if (!wallet) {
          setSelectedError(`Wallet ${selectedWalletId} was not found.`);
        }
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setSelectedWallet(null);
        setSelectedError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setSelectedLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedWalletId]);

  const kpis = React.useMemo(
    () => [
      {
        label: 'Wallets in view',
        value: String(wallets.length),
        hint: 'Current page from /console/wallets',
      },
      {
        label: 'Funded wallets',
        value: String(wallets.filter((wallet) => wallet.balanceMinor > 0).length),
        hint: 'balanceMinor > 0',
      },
      {
        label: 'Recently active',
        value: String(wallets.filter((wallet) => Boolean(wallet.lastActivityAt)).length),
        hint: 'lastActivityAt is present',
      },
      {
        label: 'Chains represented',
        value: String(new Set(wallets.map((wallet) => wallet.chain)).size),
        hint: 'Distinct chain values in current page',
      },
    ],
    [wallets],
  );

  return (
    <div className="dashboard-view" aria-label="User wallets list page">
      <section
        className="dashboard-kpi-grid dashboard-kpi-grid--content"
        aria-label="Wallet KPI summary"
      >
        {kpis.map((metric) => (
          <article className="dashboard-kpi-card" key={metric.label}>
            <p className="dashboard-kpi-card__label">{metric.label}</p>
            <p className="dashboard-kpi-card__value">{metric.value}</p>
            <p className="dashboard-kpi-card__hint">{metric.hint}</p>
          </article>
        ))}
      </section>

      <section className="dashboard-table-wrapper" aria-label="Wallets table">
        <div className="dashboard-table-header" role="row">
          {USER_WALLETS_TABLE_COLUMNS.map((column) => (
            <span key={column}>{column}</span>
          ))}
        </div>
        {loading ? (
          <p className="dashboard-table-limit">Loading wallets from console API...</p>
        ) : errorMessage ? (
          <p className="dashboard-table-limit">Wallet list unavailable: {errorMessage}</p>
        ) : wallets.length === 0 ? (
          <p className="dashboard-table-limit">No wallets returned by /console/wallets.</p>
        ) : (
          <>
            {wallets.map((wallet) => (
              <div className="dashboard-table-row" key={wallet.id} role="row">
                <span title={wallet.id}>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => setSelectedWalletId(wallet.id)}
                  >
                    {wallet.id}
                  </button>
                </span>
                <span title={wallet.address}>{wallet.address}</span>
                <span>{wallet.chain || '-'}</span>
                <span title={wallet.userId}>{wallet.userId || '-'}</span>
                <span title={wallet.policyId || ''}>{wallet.policyId || '-'}</span>
                <span>{formatWalletBalanceMinor(wallet.balanceMinor)}</span>
                <span>{wallet.status || '-'}</span>
                <span>{formatTimestamp(wallet.updatedAt)}</span>
              </div>
            ))}
            <p className="dashboard-table-limit">
              {USER_WALLETS_TABLE_NOTE}
              {nextCursor ? ' More rows are available via nextCursor.' : ''}
              {walletScope.projectId
                ? ` Scope: project ${walletScope.projectId}${
                    walletScope.environmentId ? `, environment ${walletScope.environmentId}` : ''
                  }.`
                : ''}
            </p>
            <div className="dashboard-pagination-controls">
              {nextCursor ? (
                <button
                  type="button"
                  className="dashboard-pagination-button"
                  onClick={loadMore}
                  disabled={loadingMore}
                >
                  {loadingMore ? 'Loading more...' : 'Load more wallets'}
                </button>
              ) : (
                <span className="dashboard-pagination-note">End of wallet results.</span>
              )}
              {paginationError ? (
                <span className="dashboard-pagination-note">{paginationError}</span>
              ) : null}
            </div>
          </>
        )}
      </section>

      {selectedWalletId ? (
        <section className="dashboard-view__section" aria-label="Selected wallet detail">
          <h2>Wallet detail</h2>
          {selectedLoading ? (
            <p>Loading wallet detail...</p>
          ) : selectedError ? (
            <p>{selectedError}</p>
          ) : selectedWallet ? (
            <ul className="dashboard-view-list">
              <li>
                <strong>ID:</strong> {selectedWallet.id}
              </li>
              <li>
                <strong>Address:</strong> {selectedWallet.address}
              </li>
              <li>
                <strong>Chain:</strong> {selectedWallet.chain || '-'}
              </li>
              <li>
                <strong>User:</strong> {selectedWallet.userId || '-'}
              </li>
              <li>
                <strong>Policy:</strong> {selectedWallet.policyId || '-'}
              </li>
              <li>
                <strong>Status:</strong> {selectedWallet.status || '-'}
              </li>
              <li>
                <strong>Balance:</strong> {formatWalletBalanceMinor(selectedWallet.balanceMinor)}
              </li>
              <li>
                <strong>Updated:</strong> {formatTimestamp(selectedWallet.updatedAt)}
              </li>
            </ul>
          ) : (
            <p>No wallet selected.</p>
          )}
        </section>
      ) : null}
    </div>
  );
}

export default UserWalletsListPage;
