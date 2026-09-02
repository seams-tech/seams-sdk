import React from 'react';
import { formatDashboardTimestamp } from '@core/dashboard/utils/timestamps';
import {
  SEARCH_USER_WALLETS_PLACEHOLDER,
  USER_WALLETS_TABLE_COLUMNS,
} from '@core/dashboard/components/dashboardContent';
import {
  DashboardTable,
  DashboardTableCell,
  DashboardTableDetailsPanel,
  DashboardTableFooter,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  DashboardTableStatus,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '@core/dashboard/components/DashboardTable';
import {
  DASHBOARD_EMPTY_VALUE,
  dashboardStatusLabel,
  dashboardStatusTone,
} from '@core/dashboard/utils/statusTone';
import { ChevronRightIcon, WalletCardsIcon } from '@core/dashboard/icons/SidebarIcons';
import { useDashboardConsoleSession } from '@core/dashboard/consoleSession';
import { useDashboardSelectedContext } from '@core/dashboard/selectedContext';
import { listDashboardPolicies } from '../policy-engine/consolePoliciesApi';
import {
  formatWalletBalanceMinor,
  listDashboardWallets,
  mergeDashboardWalletsById,
  refreshDashboardWalletBalances,
  replaceDashboardWalletsById,
  searchDashboardWallets,
  type DashboardConsoleWallet,
  type DashboardConsoleWalletListInput,
  type DashboardConsoleWalletSortBy,
  type DashboardConsoleWalletSortOrder,
  type DashboardConsoleWalletType,
} from '../wallets/consoleWalletApi';

type WalletFilterOption = {
  value: string;
  label: string;
};

type WalletSortOption = WalletFilterOption & {
  sortBy: DashboardConsoleWalletSortBy;
  sortOrder: DashboardConsoleWalletSortOrder;
};

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
const WALLETS_TABLE_COLUMNS = dashboardTableColumns(2, 1.15, 0.6, 0.75, 0.6, 0.9);

function formatTimestamp(value: string): string {
  return formatDashboardTimestamp(value, '—');
}

function formatRawAmount(
  raw: string,
  decimals: number,
  minimumFractionDigits: number,
  maximumFractionDigits: number,
): string {
  const normalized = String(raw || '').trim();
  if (!/^\d+$/.test(normalized)) return DASHBOARD_EMPTY_VALUE;
  const padded = normalized.padStart(decimals + 1, '0');
  const whole = padded.slice(0, -decimals) || '0';
  const rawFraction = decimals > 0 ? padded.slice(-decimals) : '';
  const truncated = rawFraction.slice(0, maximumFractionDigits);
  const fraction = truncated.replace(/0+$/u, '').padEnd(minimumFractionDigits, '0');
  const localizedWhole = BigInt(whole).toLocaleString();
  return fraction ? `${localizedWhole}.${fraction}` : localizedWhole;
}

function formatNearBalance(raw: string): string {
  return formatRawAmount(raw, 24, 2, 6);
}

function formatStablecoinBalance(raw: string, decimals: number): string {
  return `$${formatRawAmount(raw, decimals, 2, 2)}`;
}

function walletBalancesRegionId(walletId: string): string {
  return `wallet-chain-balances-${walletId.replace(/[^a-zA-Z0-9_-]/gu, '-')}`;
}

function WalletChainBalances(props: { wallet: DashboardConsoleWallet }): React.JSX.Element {
  const { wallet } = props;
  const balances = wallet.gasBalances;

  return (
    <DashboardTableDetailsPanel className="dashboard-wallet-balances">
      <section
        id={walletBalancesRegionId(wallet.id)}
        aria-label={`Gas balances for ${wallet.address}`}
      >
        <header className="dashboard-wallet-balances__header">
          <strong>Gas balances</strong>
          {balances ? (
            <time dateTime={balances.observedAt}>
              Updated {formatTimestamp(balances.observedAt)}
            </time>
          ) : (
            <span>Waiting for first balance refresh</span>
          )}
        </header>
        {balances ? (
          <div className="dashboard-wallet-balances__grid">
            <article className="dashboard-wallet-balances__card">
              <header className="dashboard-wallet-balances__network">
                <strong>NEAR</strong>
                <span>Gas currency</span>
              </header>
              <p className="dashboard-wallet-balances__amount">
                <strong>{formatNearBalance(balances.near.balanceYocto)}</strong>
                <span>NEAR</span>
              </p>
              <div className="dashboard-wallet-balances__identity">
                <span>Account</span>
                <code title={balances.near.accountId}>{balances.near.accountId}</code>
              </div>
            </article>
            <article className="dashboard-wallet-balances__card">
              <header className="dashboard-wallet-balances__network">
                <strong>Tempo</strong>
                <span>Gas currency</span>
              </header>
              <p className="dashboard-wallet-balances__amount">
                <strong>{formatStablecoinBalance(balances.tempo.alphaUsdRaw, 6)}</strong>
                <span>AlphaUSD</span>
              </p>
              <div className="dashboard-wallet-balances__identity">
                <span>Address</span>
                <code title={balances.tempo.address}>{balances.tempo.address}</code>
              </div>
            </article>
            <article className="dashboard-wallet-balances__card">
              <header className="dashboard-wallet-balances__network">
                <strong>Arc</strong>
                <span>Gas currency</span>
              </header>
              <p className="dashboard-wallet-balances__amount">
                <strong>{formatStablecoinBalance(balances.arc.usdcRaw, 18)}</strong>
                <span>USDC</span>
              </p>
              <div className="dashboard-wallet-balances__identity">
                <span>Address</span>
                <code title={balances.arc.address}>{balances.arc.address}</code>
              </div>
            </article>
          </div>
        ) : (
          <p className="dashboard-wallet-balances__empty">Balances have not been read yet.</p>
        )}
      </section>
    </DashboardTableDetailsPanel>
  );
}

export function UserWalletsListPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const [query, setQuery] = React.useState<string>('');
  const [wallets, setWallets] = React.useState<DashboardConsoleWallet[]>([]);
  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [expandedWalletId, setExpandedWalletId] = React.useState<string>('');
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
  const walletsPagination = useDashboardTablePagination(wallets, {
    disabled: loading,
    itemLabel: 'wallet',
    itemLabelPlural: 'wallets',
  });
  const activeSort = SORT_OPTIONS.find((option) => option.value === sortValue) || SORT_OPTIONS[0];
  const walletRequest = React.useMemo<DashboardConsoleWalletListInput>(
    () => ({
      projectId: walletScope.projectId,
      environmentId: walletScope.environmentId,
      walletType: (walletTypeFilter || undefined) as DashboardConsoleWalletType | undefined,
      policyId: policyFilter || undefined,
      sortBy: activeSort.sortBy,
      sortOrder: activeSort.sortOrder,
    }),
    [activeSort.sortBy, activeSort.sortOrder, policyFilter, walletScope, walletTypeFilter],
  );

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
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    const fetchWallets = async () => {
      try {
        let cursor: string | undefined;
        let allWallets: DashboardConsoleWallet[] = [];
        for (;;) {
          const page = await (searchMode
            ? searchDashboardWallets({
                q: trimmedQuery,
                limit: 100,
                ...(cursor ? { cursor } : {}),
                ...walletRequest,
              })
            : listDashboardWallets({
                limit: 100,
                ...(cursor ? { cursor } : {}),
                ...walletRequest,
              }));
          if (cancelled) return;
          allWallets = mergeDashboardWalletsById(allWallets, page.wallets);
          cursor = page.nextCursor;
          if (!cursor) break;
        }
        if (cancelled) return;
        setWallets(allWallets);
        void refreshDashboardWalletBalances(allWallets.slice(0, 10).map((wallet) => wallet.id))
          .then((refreshedWallets) => {
            if (cancelled || refreshedWallets.length === 0) return;
            setWallets((current) => replaceDashboardWalletsById(current, refreshedWallets));
          })
          .catch(() => undefined);
      } catch (error: unknown) {
        if (cancelled) return;
        setWallets([]);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    const timeoutId = searchMode ? window.setTimeout(fetchWallets, 200) : undefined;
    if (!searchMode) {
      void fetchWallets();
    }
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

  React.useEffect(() => {
    setExpandedWalletId('');
  }, [policyFilter, sortValue, walletScope.environmentId, walletScope.projectId, walletTypeFilter]);

  const summaryMetrics = React.useMemo(
    () => [
      {
        label: 'Wallets',
        value: String(wallets.length),
      },
      {
        label: 'Funded',
        value: String(wallets.filter((wallet) => wallet.funded).length),
      },
      {
        label: 'Active',
        value: String(
          wallets.filter((wallet) => String(wallet.status || '').toUpperCase() === 'ACTIVE').length,
        ),
      },
    ],
    [wallets],
  );

  return (
    <div className="dashboard-view" aria-label="User wallets list page">
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
        <label className="dashboard-form-field">
          <select
            className="dashboard-input"
            aria-label="Filter wallets by policy"
            value={policyFilter}
            onChange={(event) => setPolicyFilter(event.target.value)}
          >
            {policyOptions.map((option) => (
              <option key={option.value || 'all'} value={option.value}>
                Policy: {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="dashboard-form-field">
          <select
            className="dashboard-input"
            aria-label="Filter wallets by wallet type"
            value={walletTypeFilter}
            onChange={(event) => setWalletTypeFilter(event.target.value)}
          >
            {WALLET_TYPE_OPTIONS.map((option) => (
              <option key={option.value || 'all'} value={option.value}>
                Type: {option.label}
              </option>
            ))}
          </select>
        </label>
        <label className="dashboard-form-field">
          <select
            className="dashboard-input"
            aria-label="Sort wallets"
            value={sortValue}
            onChange={(event) => setSortValue(event.target.value)}
          >
            {SORT_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>
                Sort: {option.label}
              </option>
            ))}
          </select>
        </label>
      </section>

      <section className="dashboard-wallet-summary" aria-label="Wallet summary metrics">
        {summaryMetrics.map((metric) => (
          <article className="dashboard-wallet-summary__item" key={metric.label}>
            <p className="dashboard-wallet-summary__label">{metric.label}</p>
            <p className="dashboard-wallet-summary__value">{metric.value}</p>
          </article>
        ))}
      </section>

      <DashboardTable
        ariaLabel="Wallets table"
        columns={WALLETS_TABLE_COLUMNS}
        pagination={walletsPagination.pagination}
      >
        <DashboardTableHeader>
          {USER_WALLETS_TABLE_COLUMNS.map((column) => (
            <DashboardTableHeaderCell
              key={column}
              className={
                column === 'Balance' ? 'dashboard-data-table__header-cell--end' : undefined
              }
            >
              {column}
            </DashboardTableHeaderCell>
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
              : 'No wallets in this environment yet. Wallets appear here after your first user signs up.'}
          </DashboardTableState>
        ) : (
          <>
            {walletsPagination.rows.map((wallet) => {
              const expanded = expandedWalletId === wallet.id;
              return (
                <React.Fragment key={wallet.id}>
                  <DashboardTableRow
                    className={`dashboard-wallet-row${
                      expanded ? ' dashboard-wallet-row--expanded' : ''
                    }`}
                  >
                    <DashboardTableCell className="dashboard-data-table__cell--lead">
                      <div className="dashboard-lead">
                        <span className="dashboard-lead__icon" aria-hidden="true">
                          <WalletCardsIcon size={16} />
                        </span>
                        <span className="dashboard-lead__copy">
                          <span className="dashboard-lead__title">
                            <button
                              type="button"
                              className="dashboard-inline-link dashboard-data-table__mono dashboard-wallet-row__toggle"
                              aria-expanded={expanded}
                              aria-controls={walletBalancesRegionId(wallet.id)}
                              aria-label={`Toggle chain balances for ${wallet.address}`}
                              onClick={() =>
                                setExpandedWalletId((current) =>
                                  current === wallet.id ? '' : wallet.id,
                                )
                              }
                            >
                              <span className="dashboard-wallet-row__label">{wallet.address}</span>
                              <span className="dashboard-wallet-row__chevron" aria-hidden="true">
                                <ChevronRightIcon size={16} strokeWidth={1.75} />
                              </span>
                            </button>
                          </span>
                          {wallet.id !== wallet.address ? (
                            <span className="dashboard-lead__sub">{wallet.id}</span>
                          ) : null}
                        </span>
                      </div>
                    </DashboardTableCell>
                    <DashboardTableCell
                      title={wallet.userId}
                      className="dashboard-data-table__cell--nowrap"
                    >
                      {wallet.userId || DASHBOARD_EMPTY_VALUE}
                    </DashboardTableCell>
                    <DashboardTableCell title={wallet.policyId || ''}>
                      {wallet.policyId ? <code>{wallet.policyId}</code> : DASHBOARD_EMPTY_VALUE}
                    </DashboardTableCell>
                    <DashboardTableCell align="end">
                      {formatWalletBalanceMinor(wallet.balanceMinor)}
                    </DashboardTableCell>
                    <DashboardTableCell>
                      {wallet.status ? (
                        <DashboardTableStatus tone={dashboardStatusTone(wallet.status)}>
                          {dashboardStatusLabel(wallet.status)}
                        </DashboardTableStatus>
                      ) : (
                        DASHBOARD_EMPTY_VALUE
                      )}
                    </DashboardTableCell>
                    <DashboardTableCell truncate>
                      {formatTimestamp(wallet.updatedAt)}
                    </DashboardTableCell>
                  </DashboardTableRow>
                  {expanded ? <WalletChainBalances wallet={wallet} /> : null}
                </React.Fragment>
              );
            })}
            <DashboardTableFooter>
              {searchMode
                ? `Showing ${wallets.length} result${wallets.length === 1 ? '' : 's'}.`
                : `${wallets.length} wallet${wallets.length === 1 ? '' : 's'}.`}
              {walletScope.projectId
                ? ` Scope: project ${walletScope.projectId}${
                    walletScope.environmentId ? `, environment ${walletScope.environmentId}` : ''
                  }.`
                : ''}
            </DashboardTableFooter>
          </>
        )}
      </DashboardTable>
    </div>
  );
}

export default UserWalletsListPage;
