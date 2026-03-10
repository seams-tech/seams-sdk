import React from 'react';
import {
  SEARCH_USER_WALLETS_PLACEHOLDER,
  USER_WALLETS_TABLE_COLUMNS,
  USER_WALLETS_TABLE_NOTE,
} from '../../components/dashboardContent';
import {
  DashboardTable,
  DashboardTableCell,
  DashboardTableFooter,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
} from '../../components/DashboardTable';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import { listDashboardPolicies } from '../policy-engine/consolePoliciesApi';
import {
  formatWalletBalanceMinor,
  getDashboardWallet,
  listDashboardWallets,
  mergeDashboardWalletsById,
  searchDashboardWallets,
  type DashboardConsoleWallet,
  type DashboardConsoleWalletChain,
  type DashboardConsoleWalletListInput,
  type DashboardConsoleWalletSortBy,
  type DashboardConsoleWalletSortOrder,
  type DashboardConsoleWalletType,
} from '../wallets/consoleWalletApi';

type WalletFilterMenuKey = 'chain' | 'policy' | 'walletType' | 'sort';

type WalletFilterOption = {
  value: string;
  label: string;
};

type WalletSortOption = WalletFilterOption & {
  sortBy: DashboardConsoleWalletSortBy;
  sortOrder: DashboardConsoleWalletSortOrder;
};

const CHAIN_OPTIONS: readonly WalletFilterOption[] = [
  { value: '', label: 'All chains' },
  { value: 'Ethereum', label: 'Ethereum' },
  { value: 'Base', label: 'Base' },
  { value: 'Tempo', label: 'Tempo' },
  { value: 'Arc Circle', label: 'Arc Circle' },
  { value: 'NEAR', label: 'NEAR' },
];

const WALLET_TYPE_OPTIONS: readonly WalletFilterOption[] = [
  { value: '', label: 'EOA + Smart' },
  { value: 'EOA', label: 'EOA only' },
  { value: 'SMART', label: 'Smart only' },
];

const SORT_OPTIONS: readonly WalletSortOption[] = [
  { value: 'created-desc', label: 'Newest first', sortBy: 'createdAt', sortOrder: 'desc' },
  { value: 'created-asc', label: 'Oldest first', sortBy: 'createdAt', sortOrder: 'asc' },
  { value: 'balance-desc', label: 'Highest balance', sortBy: 'balance', sortOrder: 'desc' },
  { value: 'balance-asc', label: 'Lowest balance', sortBy: 'balance', sortOrder: 'asc' },
  {
    value: 'last-activity-desc',
    label: 'Recent activity',
    sortBy: 'lastActivity',
    sortOrder: 'desc',
  },
  {
    value: 'last-activity-asc',
    label: 'Oldest activity',
    sortBy: 'lastActivity',
    sortOrder: 'asc',
  },
];
const WALLETS_TABLE_COLUMNS = dashboardTableColumns(1.1, 1.3, 0.7, 0.95, 0.95, 0.8, 0.7, 0.95);

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function WalletFilterDropdown({
  buttonClassName,
  buttonLabel,
  options,
  selectedValue,
  isOpen,
  onToggle,
  onSelect,
  withColumnsIcon = false,
}: {
  buttonClassName: string;
  buttonLabel: string;
  options: readonly WalletFilterOption[];
  selectedValue: string;
  isOpen: boolean;
  onToggle: () => void;
  onSelect: (value: string) => void;
  withColumnsIcon?: boolean;
}): React.JSX.Element {
  return (
    <div className="dashboard-filter-dropdown">
      <button
        type="button"
        className={buttonClassName}
        aria-haspopup="menu"
        aria-expanded={isOpen}
        onClick={onToggle}
      >
        {withColumnsIcon ? <span className="dashboard-columns-icon" aria-hidden="true" /> : null}
        <span className="dashboard-select-control__value">{buttonLabel}</span>
        <span
          className={`dashboard-chevron${isOpen ? ' dashboard-chevron--open' : ''}`}
          aria-hidden="true"
        />
      </button>
      {isOpen ? (
        <div className="dashboard-context-menu dashboard-filter-menu" role="menu">
          {options.map((option) => {
            const isSelected = option.value === selectedValue;
            return (
              <button
                key={`${buttonLabel}-${option.value || 'all'}`}
                type="button"
                className={`dashboard-context-menu__item${isSelected ? ' is-active' : ''}`}
                role="menuitemradio"
                aria-checked={isSelected}
                onClick={() => onSelect(option.value)}
              >
                {option.label}
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}

export function UserWalletsListPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const filtersRef = React.useRef<HTMLElement | null>(null);
  const [query, setQuery] = React.useState<string>('');
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
  const [activeMenu, setActiveMenu] = React.useState<WalletFilterMenuKey | null>(null);
  const [chainFilter, setChainFilter] = React.useState<string>('');
  const [policyFilter, setPolicyFilter] = React.useState<string>('');
  const [walletTypeFilter, setWalletTypeFilter] = React.useState<string>('');
  const [sortValue, setSortValue] = React.useState<string>(SORT_OPTIONS[0].value);
  const [policyOptions, setPolicyOptions] = React.useState<readonly WalletFilterOption[]>([
    { value: '', label: 'Any policy' },
  ]);
  const walletScope = React.useMemo(
    () => ({
      projectId: String(selectedContext.project || '').trim() || undefined,
      environmentId: String(selectedContext.environment || '').trim() || undefined,
    }),
    [selectedContext.environment, selectedContext.project],
  );
  const trimmedQuery = query.trim();
  const searchMode = trimmedQuery.length >= 2;
  const activeSort = SORT_OPTIONS.find((option) => option.value === sortValue) || SORT_OPTIONS[0];
  const walletRequest = React.useMemo<DashboardConsoleWalletListInput>(
    () => ({
      projectId: walletScope.projectId,
      environmentId: walletScope.environmentId,
      chain: (chainFilter || undefined) as DashboardConsoleWalletChain | undefined,
      walletType: (walletTypeFilter || undefined) as DashboardConsoleWalletType | undefined,
      policyId: policyFilter || undefined,
      sortBy: activeSort.sortBy,
      sortOrder: activeSort.sortOrder,
    }),
    [
      activeSort.sortBy,
      activeSort.sortOrder,
      chainFilter,
      policyFilter,
      walletScope,
      walletTypeFilter,
    ],
  );

  React.useEffect(() => {
    if (!activeMenu) return;

    const onPointerDown = (event: PointerEvent) => {
      const next = event.target;
      if (next instanceof Node && filtersRef.current?.contains(next)) return;
      setActiveMenu(null);
    };

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setActiveMenu(null);
    };

    window.addEventListener('pointerdown', onPointerDown);
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('pointerdown', onPointerDown);
      window.removeEventListener('keydown', onKeyDown);
    };
  }, [activeMenu]);

  React.useEffect(() => {
    if (session.loading || !session.claims) {
      setPolicyOptions([{ value: '', label: 'Any policy' }]);
      return;
    }

    let cancelled = false;
    listDashboardPolicies()
      .then((policies) => {
        if (cancelled) return;
        const nextOptions: WalletFilterOption[] = [{ value: '', label: 'Any policy' }];
        const seen = new Set<string>();
        for (const policy of policies) {
          const policyId = String(policy.id || '').trim();
          if (!policyId || seen.has(policyId)) continue;
          seen.add(policyId);
          nextOptions.push({
            value: policyId,
            label: String(policy.name || '').trim() || policyId,
          });
        }
        setPolicyOptions(nextOptions);
      })
      .catch(() => {
        if (cancelled) return;
        setPolicyOptions([{ value: '', label: 'Any policy' }]);
      });

    return () => {
      cancelled = true;
    };
  }, [session.claims, session.loading]);

  React.useEffect(() => {
    setPolicyOptions((current) => {
      const dynamic = new Map(current.map((option) => [option.value, option.label]));
      for (const wallet of wallets) {
        const policyId = String(wallet.policyId || '').trim();
        if (!policyId || dynamic.has(policyId)) continue;
        dynamic.set(policyId, policyId);
      }
      if (policyFilter && !dynamic.has(policyFilter)) {
        dynamic.set(policyFilter, policyFilter);
      }
      const next = [{ value: '', label: 'Any policy' }];
      for (const [value, label] of dynamic.entries()) {
        if (!value) continue;
        next.push({ value, label });
      }
      const unchanged =
        next.length === current.length &&
        next.every(
          (option, index) =>
            current[index] != null &&
            current[index].value === option.value &&
            current[index].label === option.label,
        );
      return unchanged ? current : next;
    });
  }, [policyFilter, wallets]);

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
    const fetchWallets = () => {
      const request = searchMode
        ? searchDashboardWallets({ q: trimmedQuery, limit: 25, ...walletRequest })
        : listDashboardWallets({ limit: 25, ...walletRequest });
      request
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
    };
    const timeoutId = searchMode ? window.setTimeout(fetchWallets, 200) : undefined;
    if (!searchMode) fetchWallets();
    return () => {
      cancelled = true;
      if (timeoutId !== undefined) window.clearTimeout(timeoutId);
    };
  }, [
    searchMode,
    session.claims,
    session.errorMessage,
    session.loading,
    trimmedQuery,
    walletRequest,
  ]);

  const loadMore = React.useCallback(() => {
    if (!nextCursor || loadingMore) return;
    if (!session.claims) {
      setPaginationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setLoadingMore(true);
    setPaginationError('');
    const request = searchMode
      ? searchDashboardWallets({
          q: trimmedQuery,
          limit: 25,
          cursor: nextCursor,
          ...walletRequest,
        })
      : listDashboardWallets({
          limit: 25,
          cursor: nextCursor,
          ...walletRequest,
        });
    request
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
  }, [
    loadingMore,
    nextCursor,
    searchMode,
    session.claims,
    session.errorMessage,
    trimmedQuery,
    walletRequest,
  ]);

  React.useEffect(() => {
    setSelectedWalletId('');
  }, [
    chainFilter,
    policyFilter,
    sortValue,
    walletScope.environmentId,
    walletScope.projectId,
    walletTypeFilter,
  ]);

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

  const summaryMetrics = React.useMemo(
    () => [
      {
        label: '#wallets',
        value: String(wallets.length),
      },
      {
        label: '#funded wallets',
        value: String(wallets.filter((wallet) => wallet.balanceMinor > 0).length),
      },
      {
        label: '#active wallets',
        value: String(
          wallets.filter((wallet) => String(wallet.status || '').toUpperCase() === 'ACTIVE').length,
        ),
      },
    ],
    [wallets],
  );

  const selectedPolicyLabel =
    policyOptions.find((option) => option.value === policyFilter)?.label || 'Any policy';

  return (
    <div className="dashboard-view" aria-label="User wallets list page">
      <section ref={filtersRef} className="dashboard-filters" aria-label="Wallet search controls">
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

        <WalletFilterDropdown
          buttonClassName="dashboard-select-control"
          buttonLabel={
            CHAIN_OPTIONS.find((option) => option.value === chainFilter)?.label || 'All chains'
          }
          options={CHAIN_OPTIONS}
          selectedValue={chainFilter}
          isOpen={activeMenu === 'chain'}
          onToggle={() => setActiveMenu((current) => (current === 'chain' ? null : 'chain'))}
          onSelect={(value) => {
            setChainFilter(value);
            setActiveMenu(null);
          }}
        />

        <WalletFilterDropdown
          buttonClassName="dashboard-select-control"
          buttonLabel={selectedPolicyLabel}
          options={policyOptions}
          selectedValue={policyFilter}
          isOpen={activeMenu === 'policy'}
          onToggle={() => setActiveMenu((current) => (current === 'policy' ? null : 'policy'))}
          onSelect={(value) => {
            setPolicyFilter(value);
            setActiveMenu(null);
          }}
        />

        <WalletFilterDropdown
          buttonClassName="dashboard-select-control"
          buttonLabel={
            WALLET_TYPE_OPTIONS.find((option) => option.value === walletTypeFilter)?.label ||
            'EOA + Smart'
          }
          options={WALLET_TYPE_OPTIONS}
          selectedValue={walletTypeFilter}
          isOpen={activeMenu === 'walletType'}
          onToggle={() =>
            setActiveMenu((current) => (current === 'walletType' ? null : 'walletType'))
          }
          onSelect={(value) => {
            setWalletTypeFilter(value);
            setActiveMenu(null);
          }}
        />

        <WalletFilterDropdown
          buttonClassName="dashboard-columns-control dashboard-columns-control--dropdown"
          buttonLabel={activeSort.label}
          options={SORT_OPTIONS}
          selectedValue={activeSort.value}
          isOpen={activeMenu === 'sort'}
          withColumnsIcon
          onToggle={() => setActiveMenu((current) => (current === 'sort' ? null : 'sort'))}
          onSelect={(value) => {
            setSortValue(value);
            setActiveMenu(null);
          }}
        />
      </section>

      <section className="dashboard-wallet-summary" aria-label="Wallet summary metrics">
        {summaryMetrics.map((metric) => (
          <article className="dashboard-wallet-summary__item" key={metric.label}>
            <p className="dashboard-wallet-summary__label">{metric.label}</p>
            <p className="dashboard-wallet-summary__value">{metric.value}</p>
          </article>
        ))}
      </section>

      <DashboardTable ariaLabel="Wallets table" columns={WALLETS_TABLE_COLUMNS}>
        <DashboardTableHeader>
          {USER_WALLETS_TABLE_COLUMNS.map((column) => (
            <DashboardTableHeaderCell key={column}>{column}</DashboardTableHeaderCell>
          ))}
        </DashboardTableHeader>
        {loading ? (
          <DashboardTableState>
            {searchMode ? 'Searching wallets...' : 'Loading wallets from console API...'}
          </DashboardTableState>
        ) : errorMessage ? (
          <DashboardTableState>
            {searchMode
              ? `Search failed: ${errorMessage}`
              : `Wallet list unavailable: ${errorMessage}`}
          </DashboardTableState>
        ) : wallets.length === 0 ? (
          <DashboardTableState>
            {searchMode
              ? 'No wallets matched this query.'
              : 'No wallets returned by /console/wallets.'}
          </DashboardTableState>
        ) : (
          <>
            {wallets.map((wallet) => (
              <DashboardTableRow key={wallet.id}>
                <DashboardTableCell title={wallet.id}>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => setSelectedWalletId(wallet.id)}
                  >
                    {wallet.id}
                  </button>
                </DashboardTableCell>
                <DashboardTableCell title={wallet.address}>{wallet.address}</DashboardTableCell>
                <DashboardTableCell>{wallet.chain || '-'}</DashboardTableCell>
                <DashboardTableCell title={wallet.userId}>
                  {wallet.userId || '-'}
                </DashboardTableCell>
                <DashboardTableCell title={wallet.policyId || ''}>
                  {wallet.policyId || '-'}
                </DashboardTableCell>
                <DashboardTableCell>
                  {formatWalletBalanceMinor(wallet.balanceMinor)}
                </DashboardTableCell>
                <DashboardTableCell>{wallet.status || '-'}</DashboardTableCell>
                <DashboardTableCell truncate>
                  {formatTimestamp(wallet.updatedAt)}
                </DashboardTableCell>
              </DashboardTableRow>
            ))}
            <DashboardTableFooter>
              {searchMode
                ? `Showing ${wallets.length} result${wallets.length === 1 ? '' : 's'}.`
                : USER_WALLETS_TABLE_NOTE}
              {nextCursor
                ? searchMode
                  ? ' Additional matches are available via nextCursor.'
                  : ' More rows are available via nextCursor.'
                : ''}
              {walletScope.projectId
                ? ` Scope: project ${walletScope.projectId}${
                    walletScope.environmentId ? `, environment ${walletScope.environmentId}` : ''
                  }.`
                : ''}
            </DashboardTableFooter>
            <div className="dashboard-pagination-controls">
              {nextCursor ? (
                <button
                  type="button"
                  className="dashboard-pagination-button"
                  onClick={loadMore}
                  disabled={loadingMore}
                >
                  {loadingMore
                    ? 'Loading more...'
                    : searchMode
                      ? 'Load more results'
                      : 'Load more wallets'}
                </button>
              ) : (
                <span className="dashboard-pagination-note">
                  {searchMode ? 'End of search results.' : 'End of wallet results.'}
                </span>
              )}
              {paginationError ? (
                <span className="dashboard-pagination-note">{paginationError}</span>
              ) : null}
            </div>
          </>
        )}
      </DashboardTable>

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
