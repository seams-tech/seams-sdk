import React from 'react';
import {
  SEARCH_USER_WALLETS_FILTER_CONTROLS,
  SEARCH_USER_WALLETS_PLACEHOLDER,
  USER_WALLETS_TABLE_COLUMNS,
} from '../../components/dashboardContent';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  formatWalletBalanceMinor,
  getDashboardWallet,
  mergeDashboardWalletsById,
  searchDashboardWallets,
  type DashboardConsoleWallet,
} from '../wallets/consoleWalletApi';

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

export function SearchUserWalletsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const [query, setQuery] = React.useState<string>('');
  const [loading, setLoading] = React.useState<boolean>(false);
  const [loadingMore, setLoadingMore] = React.useState<boolean>(false);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [paginationError, setPaginationError] = React.useState<string>('');
  const [wallets, setWallets] = React.useState<DashboardConsoleWallet[]>([]);
  const [nextCursor, setNextCursor] = React.useState<string>('');
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
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      setPaginationError('');
      setWallets([]);
      setNextCursor('');
      return;
    }

    const q = query.trim();
    if (q.length < 2) {
      setLoading(false);
      setErrorMessage('');
      setPaginationError('');
      setWallets([]);
      setNextCursor('');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    setPaginationError('');
    const timer = window.setTimeout(() => {
      searchDashboardWallets({ q, limit: 25, ...walletScope })
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
    }, 200);
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
    };
  }, [query, session.claims, session.errorMessage, session.loading, walletScope]);

  const loadMore = React.useCallback(() => {
    const q = query.trim();
    if (q.length < 2 || !nextCursor || loadingMore) return;
    if (!session.claims) {
      setPaginationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setLoadingMore(true);
    setPaginationError('');
    searchDashboardWallets({
      q,
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
  }, [loadingMore, nextCursor, query, session.claims, session.errorMessage, walletScope]);

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

  return (
    <div className="dashboard-view" aria-label="Search wallets page">
      <section className="dashboard-filters" aria-label="Wallet search controls">
        <label className="dashboard-search-control">
          <span className="dashboard-search-icon" aria-hidden="true" />
          <input
            type="search"
            placeholder={SEARCH_USER_WALLETS_PLACEHOLDER}
            aria-label="Search wallets"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
        </label>

        {SEARCH_USER_WALLETS_FILTER_CONTROLS.map((control) =>
          control.kind === 'select' ? (
            <button type="button" className="dashboard-select-control" key={control.value}>
              <span className="dashboard-select-control__value">{control.value}</span>
              <span className="dashboard-chevron" aria-hidden="true" />
            </button>
          ) : (
            <button type="button" className="dashboard-columns-control" key={control.value}>
              <span className="dashboard-columns-icon" aria-hidden="true" />
              <span>{control.value}</span>
            </button>
          ),
        )}
      </section>

      <section className="dashboard-table-wrapper" aria-label="Wallet search results">
        <div className="dashboard-table-header" role="row">
          {USER_WALLETS_TABLE_COLUMNS.map((column) => (
            <span key={column}>{column}</span>
          ))}
        </div>
        {query.trim().length < 2 ? (
          <p className="dashboard-table-limit">Type at least 2 characters to search wallets.</p>
        ) : loading ? (
          <p className="dashboard-table-limit">Searching wallets...</p>
        ) : errorMessage ? (
          <p className="dashboard-table-limit">Search failed: {errorMessage}</p>
        ) : wallets.length === 0 ? (
          <p className="dashboard-table-limit">No wallets matched this query.</p>
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
              Showing {wallets.length} result{wallets.length === 1 ? '' : 's'}.
              {nextCursor ? ' Additional matches are available via nextCursor.' : ''}
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
                  {loadingMore ? 'Loading more...' : 'Load more results'}
                </button>
              ) : (
                <span className="dashboard-pagination-note">End of search results.</span>
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

export default SearchUserWalletsPage;
