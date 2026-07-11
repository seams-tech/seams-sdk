import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContextDisplay } from '../../selectedContext';
import { BillingAccountView } from './BillingAccountView';
import { BillingInvoiceDetailView } from './BillingInvoiceDetailView';
import { BillingInvoicesView } from './BillingInvoicesView';
import { PlatformBillingView } from './PlatformBillingView';
import {
  SponsoredExecutionHistorySection,
  SponsoredExecutionReconciliationSection,
} from './billingSections';
import {
  createDashboardStripeCheckoutSession,
  downloadDashboardBillingInvoicePdf,
  formatUsdMinor,
  getDashboardBillingInvoice,
  getDashboardBillingInvoiceActivity,
  getDashboardBillingMonthlyActiveWallets,
  getDashboardBillingOverview,
  listDashboardBillingInvoiceLineItems,
  listDashboardBillingInvoices,
  listDashboardSponsoredExecutionHistory,
  listDashboardSponsoredExecutionReconciliation,
  reconcileDashboardStripeCheckoutSession,
  type DashboardBillingInvoice,
  type DashboardBillingInvoiceActivity,
  type DashboardBillingInvoiceLineItem,
  type DashboardBillingInvoiceListSummary,
  type DashboardBillingOverview,
  type DashboardSponsoredExecutionHistoryEntry,
  type DashboardSponsoredExecutionReconciliationPage,
  type DashboardBillingUsage,
  type DashboardStripeCheckoutSessionRequest,
} from './consoleBillingApi';
import { buildInvoicePdfFilename, parseBillingSubview, type BillingMetric } from './billingShared';

export interface BillingConsoleShellProps {
  defaultPath: '/dashboard/billing/account' | '/dashboard/invoices' | '/platform/billing';
}

const DATE_INPUT_PATTERN = /^(\d{4})-(\d{2})-(\d{2})$/;
const PERIOD_MONTH_PATTERN = /^(\d{4})-(\d{2})$/;
const ONE_DAY_MS = 86_400_000;

function parseDateInputMs(value: string, endOfDay: boolean): number | null {
  const match = DATE_INPUT_PATTERN.exec(String(value || '').trim());
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  if (!Number.isInteger(year) || !Number.isInteger(month) || !Number.isInteger(day)) return null;
  const timestamp = Date.UTC(year, month - 1, day);
  const parsed = new Date(timestamp);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  ) {
    return null;
  }
  return endOfDay ? timestamp + ONE_DAY_MS - 1 : timestamp;
}

function parseInvoicePeriodRange(
  periodMonthUtc: string,
): { startMs: number; endMs: number } | null {
  const match = PERIOD_MONTH_PATTERN.exec(String(periodMonthUtc || '').trim());
  if (!match) return null;
  const year = Number(match[1]);
  const month = Number(match[2]);
  if (!Number.isInteger(year) || !Number.isInteger(month) || month < 1 || month > 12) {
    return null;
  }
  const startMs = Date.UTC(year, month - 1, 1);
  const endMs = Date.UTC(year, month, 1) - 1;
  return { startMs, endMs };
}

function isInvoiceOverdueAt(invoice: DashboardBillingInvoice, referenceNowMs: number): boolean {
  if (invoice.status !== 'OPEN' || !invoice.dueAt) return false;
  const dueAtMs = Date.parse(invoice.dueAt);
  if (!Number.isFinite(dueAtMs)) return false;
  return dueAtMs < referenceNowMs;
}

function buildInvoiceListSummary(
  invoices: readonly DashboardBillingInvoice[],
  referenceNowMs: number,
): DashboardBillingInvoiceListSummary {
  const openCount = invoices.filter((invoice) => invoice.status === 'OPEN').length;
  const overdueCount = invoices.filter((invoice) =>
    isInvoiceOverdueAt(invoice, referenceNowMs),
  ).length;
  const paidCount = invoices.filter((invoice) => invoice.status === 'PAID').length;
  const outstandingAmountMinor = invoices.reduce((total, invoice) => {
    return total + Math.max(invoice.amountDueMinor - invoice.amountPaidMinor, 0);
  }, 0);
  const receiptCount = invoices.filter(
    (invoice) => invoice.documentType === 'PURCHASE_RECEIPT',
  ).length;
  const statementCount = invoices.filter(
    (invoice) => invoice.documentType === 'USAGE_STATEMENT',
  ).length;
  return {
    totalCount: invoices.length,
    openCount,
    overdueCount,
    paidCount,
    outstandingAmountMinor,
    latestPeriodMonthUtc: invoices[0]?.periodMonthUtc || null,
    receiptCount,
    statementCount,
  };
}

function filterInvoices(input: {
  invoices: readonly DashboardBillingInvoice[];
  statusFilter: string;
  documentTypeFilter: string;
  periodStartDate: string;
  periodEndDate: string;
  referenceNowMs: number;
}): DashboardBillingInvoice[] {
  const periodStartMs = parseDateInputMs(input.periodStartDate, false);
  const periodEndMs = parseDateInputMs(input.periodEndDate, true);
  return input.invoices.filter((invoice) => {
    if (input.documentTypeFilter !== 'all' && invoice.documentType !== input.documentTypeFilter) {
      return false;
    }
    if (input.statusFilter === 'overdue') {
      if (!isInvoiceOverdueAt(invoice, input.referenceNowMs)) return false;
    } else if (
      input.statusFilter !== 'all' &&
      invoice.status !== input.statusFilter.toUpperCase()
    ) {
      return false;
    }
    if (periodStartMs === null && periodEndMs === null) return true;
    const periodRange = parseInvoicePeriodRange(invoice.periodMonthUtc);
    if (!periodRange) return false;
    if (periodStartMs !== null && periodRange.endMs < periodStartMs) return false;
    if (periodEndMs !== null && periodRange.startMs > periodEndMs) return false;
    return true;
  });
}

export function BillingConsoleShell(props: BillingConsoleShellProps): React.JSX.Element {
  const { defaultPath } = props;
  const session = useDashboardConsoleSession();
  const selectedContextDisplay = useDashboardSelectedContextDisplay();
  const { go } = useSiteRouter();
  const pathname = typeof window === 'undefined' ? defaultPath : window.location.pathname;
  const subview = React.useMemo(() => parseBillingSubview(pathname), [pathname]);
  const isPlatformBillingPage = pathname === '/platform/billing';
  const activeInvoiceId = subview.kind === 'invoice' ? subview.invoiceId : '';

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [overview, setOverview] = React.useState<DashboardBillingOverview | null>(null);
  const [usage, setUsage] = React.useState<DashboardBillingUsage | null>(null);
  const [sponsoredHistory, setSponsoredHistory] = React.useState<
    DashboardSponsoredExecutionHistoryEntry[]
  >([]);
  const [sponsoredHistoryLoading, setSponsoredHistoryLoading] = React.useState<boolean>(false);
  const [sponsoredHistoryError, setSponsoredHistoryError] = React.useState<string>('');
  const [reconciliationPage, setReconciliationPage] =
    React.useState<DashboardSponsoredExecutionReconciliationPage | null>(null);
  const [reconciliationLoading, setReconciliationLoading] = React.useState<boolean>(false);
  const [reconciliationError, setReconciliationError] = React.useState<string>('');

  const [invoices, setInvoices] = React.useState<DashboardBillingInvoice[]>([]);
  const [invoiceListLoading, setInvoiceListLoading] = React.useState<boolean>(false);
  const [invoiceListError, setInvoiceListError] = React.useState<string>('');

  const [startingCheckoutPackId, setStartingCheckoutPackId] = React.useState<
    DashboardStripeCheckoutSessionRequest['creditPackId'] | ''
  >('');
  const [checkoutActionError, setCheckoutActionError] = React.useState<string>('');
  const [checkoutReturnMessage, setCheckoutReturnMessage] = React.useState<string>('');
  const [billingWarningMessage, setBillingWarningMessage] = React.useState<string>('');
  const [billingWarningDismissed, setBillingWarningDismissed] = React.useState<boolean>(false);

  const [invoiceDetailLoading, setInvoiceDetailLoading] = React.useState<boolean>(false);
  const [invoiceDetailError, setInvoiceDetailError] = React.useState<string>('');
  const [invoiceDetail, setInvoiceDetail] = React.useState<DashboardBillingInvoice | null>(null);
  const [invoiceActivityLoading, setInvoiceActivityLoading] = React.useState<boolean>(false);
  const [invoiceActivityError, setInvoiceActivityError] = React.useState<string>('');
  const [invoiceActivity, setInvoiceActivity] =
    React.useState<DashboardBillingInvoiceActivity | null>(null);
  const [lineItemsLoading, setLineItemsLoading] = React.useState<boolean>(false);
  const [lineItemsError, setLineItemsError] = React.useState<string>('');
  const [lineItems, setLineItems] = React.useState<DashboardBillingInvoiceLineItem[]>([]);
  const [invoiceStatusFilter, setInvoiceStatusFilter] = React.useState<string>('all');
  const [invoiceDocumentTypeFilter, setInvoiceDocumentTypeFilter] = React.useState<string>('all');
  const [invoicePeriodStartDateFilter, setInvoicePeriodStartDateFilter] =
    React.useState<string>('');
  const [invoicePeriodEndDateFilter, setInvoicePeriodEndDateFilter] = React.useState<string>('');
  const [downloadingInvoicePdfId, setDownloadingInvoicePdfId] = React.useState<string>('');
  const [invoiceDownloadError, setInvoiceDownloadError] = React.useState<string>('');
  const checkoutReconcileAttemptedRef = React.useRef<Set<string>>(new Set());

  const refreshBillingShellData = React.useCallback(async () => {
    if (!session.claims) {
      setLoading(false);
      setSponsoredHistoryLoading(false);
      setReconciliationLoading(false);
      setOverview(null);
      setUsage(null);
      setSponsoredHistory([]);
      setSponsoredHistoryError('');
      setReconciliationPage(null);
      setReconciliationError('');
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setLoading(true);
    setSponsoredHistoryLoading(true);
    setReconciliationLoading(true);
    setErrorMessage('');
    setSponsoredHistoryError('');
    setReconciliationError('');
    const environmentId = String(session.claims.environmentId || '').trim();
    const [overviewResult, usageResult, historyResult, reconciliationResult] =
      await Promise.allSettled([
        getDashboardBillingOverview(),
        getDashboardBillingMonthlyActiveWallets(),
        listDashboardSponsoredExecutionHistory({
          ...(environmentId ? { environmentId } : {}),
          limit: 12,
          lookbackDays: 90,
        }),
        listDashboardSponsoredExecutionReconciliation({
          ...(environmentId ? { environmentId } : {}),
          limit: 12,
          lookbackDays: 90,
        }),
      ]);
    if (overviewResult.status === 'fulfilled' && usageResult.status === 'fulfilled') {
      setOverview(overviewResult.value);
      setUsage(usageResult.value);
    } else {
      setOverview(null);
      setUsage(null);
      setErrorMessage(
        overviewResult.status === 'rejected'
          ? overviewResult.reason instanceof Error
            ? overviewResult.reason.message
            : String(overviewResult.reason)
          : usageResult.status === 'rejected'
            ? usageResult.reason instanceof Error
              ? usageResult.reason.message
              : String(usageResult.reason)
            : 'Billing data unavailable',
      );
    }
    if (historyResult.status === 'fulfilled') {
      setSponsoredHistory(historyResult.value.items);
    } else {
      setSponsoredHistory([]);
      setSponsoredHistoryError(
        historyResult.reason instanceof Error
          ? historyResult.reason.message
          : String(historyResult.reason),
      );
    }
    if (reconciliationResult.status === 'fulfilled') {
      setReconciliationPage(reconciliationResult.value);
    } else {
      setReconciliationPage(null);
      setReconciliationError(
        reconciliationResult.reason instanceof Error
          ? reconciliationResult.reason.message
          : String(reconciliationResult.reason),
      );
    }
    setLoading(false);
    setSponsoredHistoryLoading(false);
    setReconciliationLoading(false);
  }, [session.claims, session.errorMessage]);

  const loadInvoiceListPage = React.useCallback(async () => {
    if (!session.claims) return;
    setInvoiceListLoading(true);
    setInvoiceListError('');
    try {
      let cursor: string | null = null;
      const allInvoices: DashboardBillingInvoice[] = [];
      for (;;) {
        const response = await listDashboardBillingInvoices({
          ...(cursor ? { cursor } : {}),
          limit: 100,
        });
        allInvoices.push(...response.invoices);
        cursor = response.nextCursor;
        if (!cursor) break;
      }
      setInvoices(allInvoices);
    } catch (error: unknown) {
      setInvoices([]);
      setInvoiceListError(error instanceof Error ? error.message : String(error));
    } finally {
      setInvoiceListLoading(false);
    }
  }, [session.claims]);

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const legacyInvoiceDetailMatch = pathname.match(/^\/dashboard\/billing\/invoices\/([^/]+)$/);
    const currentUrl = new URL(window.location.href);
    let nextPath = '';
    if (pathname === '/dashboard/billing' || pathname === '/dashboard/billing/') {
      nextPath = '/dashboard/billing/account';
    } else if (
      pathname === '/dashboard/billing/invoices' ||
      pathname === '/dashboard/billing/invoices/'
    ) {
      nextPath = '/dashboard/invoices';
    } else if (legacyInvoiceDetailMatch?.[1]) {
      nextPath = `/dashboard/invoices/${legacyInvoiceDetailMatch[1]}`;
    }
    if (!nextPath) return;
    const nextRelative = `${nextPath}${currentUrl.search}${currentUrl.hash}`;
    window.history.replaceState({}, document.title, nextRelative);
    window.dispatchEvent(new Event('site:navigate'));
  }, [pathname]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    if (subview.kind !== 'account' || isPlatformBillingPage) {
      setLoading(false);
      setErrorMessage('');
      setBillingWarningMessage('');
      return;
    }
    void refreshBillingShellData();
  }, [isPlatformBillingPage, refreshBillingShellData, session.loading, subview.kind]);

  React.useEffect(() => {
    if (!session.claims || subview.kind === 'invoice' || isPlatformBillingPage) return;
    void loadInvoiceListPage();
  }, [isPlatformBillingPage, loadInvoiceListPage, session.claims, subview.kind]);

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    if (isPlatformBillingPage) {
      setCheckoutReturnMessage('');
      return;
    }
    const params = new URLSearchParams(window.location.search);
    const checkout = String(params.get('checkout') || '')
      .trim()
      .toLowerCase();
    const checkoutSessionId = String(params.get('checkout_session_id') || '').trim();
    if (checkout === 'cancel') {
      setCheckoutReturnMessage('Top-up checkout was canceled before settlement.');
      return;
    }
    if (checkout !== 'success') {
      setCheckoutReturnMessage('');
      return;
    }
    if (!checkoutSessionId) {
      setCheckoutReturnMessage(
        'Top-up checkout completed. Balance updates after settlement confirmation.',
      );
      return;
    }
    if (!session.claims || subview.kind !== 'account') {
      setCheckoutReturnMessage('Top-up checkout completed. Verifying settlement...');
      return;
    }
    if (checkoutReconcileAttemptedRef.current.has(checkoutSessionId)) return;
    checkoutReconcileAttemptedRef.current.add(checkoutSessionId);
    let cancelled = false;
    setCheckoutReturnMessage('Top-up checkout completed. Verifying settlement...');
    void (async () => {
      try {
        const result = await reconcileDashboardStripeCheckoutSession({ checkoutSessionId });
        if (cancelled) return;
        if (result.settled) {
          setCheckoutReturnMessage(
            result.settledNow
              ? 'Top-up checkout completed. Balance updated.'
              : 'Top-up checkout is already settled. Balance is up to date.',
          );
          await Promise.all([refreshBillingShellData(), loadInvoiceListPage()]);
          return;
        }
        setCheckoutReturnMessage(
          'Top-up checkout completed. Balance updates after settlement confirmation.',
        );
      } catch {
        if (cancelled) return;
        setCheckoutReturnMessage(
          'Top-up checkout completed, but settlement verification is still pending. Refresh again in a moment.',
        );
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [
    isPlatformBillingPage,
    loadInvoiceListPage,
    pathname,
    refreshBillingShellData,
    session.claims,
    subview.kind,
  ]);

  React.useEffect(() => {
    if (!overview) {
      setBillingWarningMessage('');
      return;
    }
    if (overview.liveEnvironmentState === 'BLOCKED') {
      setBillingWarningDismissed(false);
      setBillingWarningMessage(
        'Prepaid balance is depleted. Add credits before creating or using staging or production environments.',
      );
      return;
    }
    if (overview.liveEnvironmentState === 'LOW_BALANCE') {
      setBillingWarningDismissed(false);
      setBillingWarningMessage(
        `Prepaid balance is at or below the warning threshold (${formatUsdMinor(
          overview.lowBalanceThresholdMinor,
        )}). Add credits before production usage grows further.`,
      );
      return;
    }
    setBillingWarningMessage('');
  }, [overview]);

  React.useEffect(() => {
    if (!activeInvoiceId || subview.kind !== 'invoice' || !session.claims) return;
    let cancelled = false;
    setInvoiceDetailLoading(true);
    setInvoiceDetailError('');
    setInvoiceActivityLoading(true);
    setInvoiceActivityError('');
    setLineItemsLoading(true);
    setLineItemsError('');

    getDashboardBillingInvoice(activeInvoiceId)
      .then((nextInvoice) => {
        if (!cancelled) setInvoiceDetail(nextInvoice);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setInvoiceDetail(null);
        setInvoiceDetailError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (!cancelled) setInvoiceDetailLoading(false);
      });

    getDashboardBillingInvoiceActivity(activeInvoiceId)
      .then((activity) => {
        if (!cancelled) setInvoiceActivity(activity);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setInvoiceActivity(null);
          setInvoiceActivityError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (!cancelled) setInvoiceActivityLoading(false);
      });

    listDashboardBillingInvoiceLineItems(activeInvoiceId)
      .then((rows) => {
        if (!cancelled) setLineItems(rows);
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setLineItems([]);
          setLineItemsError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (!cancelled) setLineItemsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeInvoiceId, session.claims, subview.kind]);

  const filteredInvoices = React.useMemo<DashboardBillingInvoice[]>(() => {
    return filterInvoices({
      invoices,
      statusFilter: invoiceStatusFilter,
      documentTypeFilter: invoiceDocumentTypeFilter,
      periodStartDate: invoicePeriodStartDateFilter,
      periodEndDate: invoicePeriodEndDateFilter,
      referenceNowMs: Date.now(),
    });
  }, [
    invoiceDocumentTypeFilter,
    invoicePeriodEndDateFilter,
    invoicePeriodStartDateFilter,
    invoiceStatusFilter,
    invoices,
  ]);

  const filteredInvoiceSummary = React.useMemo<DashboardBillingInvoiceListSummary>(() => {
    return buildInvoiceListSummary(filteredInvoices, Date.now());
  }, [filteredInvoices]);

  const invoiceSummaryMetrics = React.useMemo<BillingMetric[]>(() => {
    return [
      {
        label: 'Documents',
        value: String(filteredInvoiceSummary.totalCount),
        hint: `${filteredInvoiceSummary.statementCount} statement${
          filteredInvoiceSummary.statementCount === 1 ? '' : 's'
        }`,
      },
      {
        label: 'Purchase receipts',
        value: String(filteredInvoiceSummary.receiptCount),
        hint: `${filteredInvoiceSummary.paidCount} paid document${
          filteredInvoiceSummary.paidCount === 1 ? '' : 's'
        }`,
      },
      {
        label: 'Outstanding',
        value: formatUsdMinor(filteredInvoiceSummary.outstandingAmountMinor),
        hint: `${filteredInvoiceSummary.openCount} open`,
      },
      {
        label: 'Latest period',
        value: filteredInvoiceSummary.latestPeriodMonthUtc || '-',
        hint: 'Most recent billing month',
      },
    ];
  }, [filteredInvoiceSummary]);

  const summaryMetrics = React.useMemo<BillingMetric[]>(
    () => [
      {
        label: 'Balance',
        value: formatUsdMinor(overview?.creditBalanceMinor || 0),
        hint:
          overview?.liveEnvironmentState === 'BLOCKED'
            ? 'Live environments are blocked until balance is positive'
            : overview?.liveEnvironmentState === 'LOW_BALANCE'
              ? `Warning at ${formatUsdMinor(overview?.lowBalanceThresholdMinor || 0)}`
              : 'Live environments enabled',
        tone:
          overview?.liveEnvironmentState === 'BLOCKED'
            ? ('danger' as const)
            : overview?.liveEnvironmentState === 'LOW_BALANCE'
              ? ('warning' as const)
              : ('success' as const),
      },
      {
        label: 'Reserved sponsorship',
        value: formatUsdMinor(overview?.reservedSponsorshipMinor || 0),
        hint: `${overview?.activeSponsorshipReservationCount ?? 0} active reservation${
          overview?.activeSponsorshipReservationCount === 1 ? '' : 's'
        }`,
      },
      {
        label: 'Sponsored spend',
        value: formatUsdMinor(overview?.trailing30DaySponsoredSpendMinor || 0),
        hint: `${formatUsdMinor(
          overview?.trailing90DaySponsoredSpendMinor || 0,
        )} over 90d · ${overview?.trailing30DaySponsoredExecutionCount ?? 0}/${
          overview?.trailing90DaySponsoredExecutionCount ?? 0
        } charged executions`,
      },
      {
        label: 'Monthly active wallets',
        value: String(usage?.monthlyActiveWallets ?? overview?.monthlyActiveWallets ?? 0),
        hint: usage?.monthUtc ? `Billing month ${usage.monthUtc}` : 'No usage data',
      },
      {
        label: 'Recent top-ups',
        value: formatUsdMinor(overview?.recentCreditPurchasedMinor || 0),
        hint: `${overview?.documentCount ?? 0} billing document${overview?.documentCount === 1 ? '' : 's'}`,
      },
    ],
    [overview, usage],
  );

  const invoiceDetailRecord = React.useMemo(() => {
    if (!activeInvoiceId) return null;
    return (
      invoiceDetail ||
      invoiceActivity?.invoice ||
      invoices.find((entry) => entry.id === activeInvoiceId) ||
      null
    );
  }, [activeInvoiceId, invoiceActivity?.invoice, invoiceDetail, invoices]);

  const isPlatformAdmin = React.useMemo(() => {
    return (session.claims?.roles || []).some(
      (role) =>
        String(role || '')
          .trim()
          .toLowerCase() === 'platform_admin',
    );
  }, [session.claims?.roles]);

  const onStartStripeCheckout = React.useCallback(
    async ({
      creditPackId,
      customAmountMinor,
    }: Pick<DashboardStripeCheckoutSessionRequest, 'creditPackId' | 'customAmountMinor'>) => {
      if (!session.claims) {
        setCheckoutActionError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      setStartingCheckoutPackId(creditPackId);
      setCheckoutActionError('');
      try {
        const origin = window.location.origin;
        const checkoutSession = await createDashboardStripeCheckoutSession({
          successUrl: `${origin}/dashboard/billing/account?checkout=success&checkout_session_id={CHECKOUT_SESSION_ID}`,
          cancelUrl: `${origin}/dashboard/billing/account?checkout=cancel`,
          creditPackId,
          ...(customAmountMinor === undefined ? {} : { customAmountMinor }),
        });
        window.location.assign(checkoutSession.url);
      } catch (error: unknown) {
        setCheckoutActionError(error instanceof Error ? error.message : String(error));
      } finally {
        setStartingCheckoutPackId('');
      }
    },
    [session.claims, session.errorMessage],
  );

  const onDownloadInvoicePdf = React.useCallback(
    async (invoiceId: string) => {
      const normalizedInvoiceId = String(invoiceId || '').trim();
      if (!normalizedInvoiceId) return;
      setDownloadingInvoicePdfId(normalizedInvoiceId);
      setInvoiceDownloadError('');
      try {
        await downloadDashboardBillingInvoicePdf(normalizedInvoiceId);
      } catch (error: unknown) {
        const invoice = invoices.find((entry) => entry.id === normalizedInvoiceId) || null;
        const fallbackFilename = buildInvoicePdfFilename(invoice, normalizedInvoiceId);
        const message = error instanceof Error ? error.message : String(error);
        setInvoiceDownloadError(`Failed to download ${fallbackFilename}: ${message}`);
      } finally {
        setDownloadingInvoicePdfId('');
      }
    },
    [invoices],
  );

  const sponsoredScopeDescription = React.useMemo(() => {
    const environmentId = String(session.claims?.environmentId || '').trim();
    if (environmentId) {
      const environmentLabel =
        selectedContextDisplay.environment && selectedContextDisplay.environment !== '-'
          ? selectedContextDisplay.environment
          : environmentId;
      return `Showing the selected environment scope (${environmentLabel}). Billing balance remains organization-scoped.`;
    }
    return 'Showing organization-scoped records for the last 90 days.';
  }, [selectedContextDisplay.environment, session.claims?.environmentId]);

  return (
    <div className="dashboard-view" aria-label="Billing page">
      {billingWarningMessage && !billingWarningDismissed ? (
        <section className="dashboard-view__section">
          <div className="dashboard-warning-banner" role="alert">
            <p>{billingWarningMessage}</p>
            <button
              type="button"
              className="dashboard-warning-banner__dismiss"
              aria-label="Dismiss billing warning"
              onClick={() => setBillingWarningDismissed(true)}
            >
              Dismiss
            </button>
          </div>
        </section>
      ) : null}

      {checkoutReturnMessage ? (
        <section className="dashboard-view__section">
          <p className="dashboard-info-banner">{checkoutReturnMessage}</p>
        </section>
      ) : null}

      {session.loading || loading ? (
        <section className="dashboard-view__section">
          <p>Loading billing data...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Billing unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : errorMessage ? (
        <section className="dashboard-view__section">
          <p>Billing data unavailable: {errorMessage}</p>
        </section>
      ) : subview.kind === 'account' ? (
        isPlatformBillingPage ? (
          isPlatformAdmin ? (
            <PlatformBillingView />
          ) : (
            <section className="dashboard-view__section">
              <p>Customer Accounts is only available to platform admin users.</p>
            </section>
          )
        ) : (
          <>
            <BillingAccountView
              selectedContext={selectedContextDisplay}
              summaryMetrics={summaryMetrics}
              checkoutActionError={checkoutActionError}
              startingCheckoutPackId={startingCheckoutPackId}
              onStartStripeCheckout={(checkoutRequest) => {
                void onStartStripeCheckout(checkoutRequest);
              }}
            />
            <section
              id="billing-sponsored-history"
              className="dashboard-view__section dashboard-view__section--plain"
            >
              <SponsoredExecutionHistorySection
                entries={sponsoredHistory}
                loading={sponsoredHistoryLoading}
                error={sponsoredHistoryError}
                scopeDescription={sponsoredScopeDescription}
              />
            </section>
            <SponsoredExecutionReconciliationSection
              sectionId="billing-sponsored-reconciliation"
              page={reconciliationPage}
              loading={reconciliationLoading}
              error={reconciliationError}
              scopeDescription={sponsoredScopeDescription}
            />
          </>
        )
      ) : subview.kind === 'invoices' ? (
        <BillingInvoicesView
          invoiceMetrics={invoiceSummaryMetrics}
          invoiceListLoading={invoiceListLoading}
          invoiceListError={invoiceListError}
          invoiceStatusFilter={invoiceStatusFilter}
          setInvoiceStatusFilter={setInvoiceStatusFilter}
          invoiceDocumentTypeFilter={invoiceDocumentTypeFilter}
          setInvoiceDocumentTypeFilter={setInvoiceDocumentTypeFilter}
          invoicePeriodStartDateFilter={invoicePeriodStartDateFilter}
          setInvoicePeriodStartDateFilter={setInvoicePeriodStartDateFilter}
          invoicePeriodEndDateFilter={invoicePeriodEndDateFilter}
          setInvoicePeriodEndDateFilter={setInvoicePeriodEndDateFilter}
          invoices={filteredInvoices}
          hasAnyInvoices={invoices.length > 0}
          downloadingInvoicePdfId={downloadingInvoicePdfId}
          invoiceDownloadError={invoiceDownloadError}
          onOpenInvoice={(invoiceId) => go(`/dashboard/invoices/${encodeURIComponent(invoiceId)}`)}
          onDownloadInvoicePdf={onDownloadInvoicePdf}
        />
      ) : (
        <BillingInvoiceDetailView
          invoiceId={activeInvoiceId}
          invoice={invoiceDetailRecord}
          invoiceDetailLoading={invoiceDetailLoading}
          invoiceDetailError={invoiceDetailError}
          invoiceActivityLoading={invoiceActivityLoading}
          invoiceActivityError={invoiceActivityError}
          invoiceActivity={invoiceActivity}
          lineItemsLoading={lineItemsLoading}
          lineItemsError={lineItemsError}
          lineItems={lineItems}
          downloadingInvoicePdfId={downloadingInvoicePdfId}
          invoiceDownloadError={invoiceDownloadError}
          onBackToInvoices={() => go('/dashboard/invoices')}
          onDownloadInvoicePdf={onDownloadInvoicePdf}
        />
      )}
    </div>
  );
}

export default BillingConsoleShell;
