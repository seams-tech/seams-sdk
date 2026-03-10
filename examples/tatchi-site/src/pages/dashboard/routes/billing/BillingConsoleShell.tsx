import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContextDisplay } from '../../selectedContext';
import { BillingAccountView } from './BillingAccountView';
import { BillingInvoiceDetailView } from './BillingInvoiceDetailView';
import { BillingInvoicesView } from './BillingInvoicesView';
import {
  addDashboardCardPaymentMethod,
  createDashboardStripeCheckoutSession,
  createDashboardStripeCustomerPortalSession,
  createDashboardStripeSetupIntent,
  downloadDashboardBillingInvoicePdf,
  formatUsdMinor,
  getDashboardBillingInvoice,
  getDashboardBillingInvoiceActivity,
  getDashboardBillingMonthlyActiveWallets,
  getDashboardBillingOverview,
  listDashboardBillingInvoiceLineItems,
  listDashboardBillingInvoices,
  listDashboardBillingPaymentMethods,
  removeDashboardCardPaymentMethod,
  setDashboardDefaultCardPaymentMethod,
  type DashboardBillingInvoice,
  type DashboardBillingInvoiceActivity,
  type DashboardBillingInvoiceLineItem,
  type DashboardBillingInvoiceListSummary,
  type DashboardBillingOverview,
  type DashboardBillingPaymentMethod,
  type DashboardBillingUsage,
  type DashboardStripeSetupIntent,
} from './consoleBillingApi';
import {
  buildInvoicePdfFilename,
  parseBillingSubview,
  parsePositiveInteger,
  type BillingMetric,
} from './billingShared';

export interface BillingConsoleShellProps {
  defaultPath: '/dashboard/billing/account' | '/dashboard/invoices';
}

export function BillingConsoleShell(props: BillingConsoleShellProps): React.JSX.Element {
  const { defaultPath } = props;
  const session = useDashboardConsoleSession();
  const selectedContextDisplay = useDashboardSelectedContextDisplay();
  const { go } = useSiteRouter();
  const pathname = typeof window === 'undefined' ? defaultPath : window.location.pathname;
  const subview = React.useMemo(() => parseBillingSubview(pathname), [pathname]);
  const activeInvoiceId = subview.kind === 'invoice' ? subview.invoiceId : '';

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [overview, setOverview] = React.useState<DashboardBillingOverview | null>(null);
  const [usage, setUsage] = React.useState<DashboardBillingUsage | null>(null);
  const [paymentMethods, setPaymentMethods] = React.useState<DashboardBillingPaymentMethod[]>([]);

  const [invoices, setInvoices] = React.useState<DashboardBillingInvoice[]>([]);
  const [invoiceListLoading, setInvoiceListLoading] = React.useState<boolean>(false);
  const [invoiceListError, setInvoiceListError] = React.useState<string>('');
  const [invoiceTotalCount, setInvoiceTotalCount] = React.useState<number>(0);
  const [invoiceSummary, setInvoiceSummary] = React.useState<DashboardBillingInvoiceListSummary>({
    totalCount: 0,
    openCount: 0,
    overdueCount: 0,
    paidCount: 0,
    outstandingAmountMinor: 0,
    latestPeriodMonthUtc: null,
    receiptCount: 0,
    statementCount: 0,
  });

  const [startingCheckoutPackId, setStartingCheckoutPackId] = React.useState<string>('');
  const [checkoutActionError, setCheckoutActionError] = React.useState<string>('');
  const [openingCustomerPortal, setOpeningCustomerPortal] = React.useState<boolean>(false);
  const [checkoutReturnMessage, setCheckoutReturnMessage] = React.useState<string>('');
  const [billingWarningMessage, setBillingWarningMessage] = React.useState<string>('');
  const [billingWarningDismissed, setBillingWarningDismissed] = React.useState<boolean>(false);

  const [paymentMutationError, setPaymentMutationError] = React.useState<string>('');
  const [addingPaymentMethod, setAddingPaymentMethod] = React.useState<boolean>(false);
  const [creatingPaymentMethodSetupIntent, setCreatingPaymentMethodSetupIntent] =
    React.useState<boolean>(false);
  const [busyPaymentMethodId, setBusyPaymentMethodId] = React.useState<string>('');
  const [providerRefInput, setProviderRefInput] = React.useState<string>('');
  const [brandInput, setBrandInput] = React.useState<string>('');
  const [last4Input, setLast4Input] = React.useState<string>('');
  const [expMonthInput, setExpMonthInput] = React.useState<string>('');
  const [expYearInput, setExpYearInput] = React.useState<string>('');
  const [paymentMethodSetupIntent, setPaymentMethodSetupIntent] =
    React.useState<DashboardStripeSetupIntent | null>(null);

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
  const [invoicePeriodFilter, setInvoicePeriodFilter] = React.useState<string>('');
  const [downloadingInvoicePdfId, setDownloadingInvoicePdfId] = React.useState<string>('');
  const [invoiceDownloadError, setInvoiceDownloadError] = React.useState<string>('');

  const refreshBillingShellData = React.useCallback(async () => {
    if (!session.claims) {
      setLoading(false);
      setOverview(null);
      setUsage(null);
      setPaymentMethods([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setLoading(true);
    setErrorMessage('');
    try {
      const [nextOverview, nextUsage, nextPaymentMethods] = await Promise.all([
        getDashboardBillingOverview(),
        getDashboardBillingMonthlyActiveWallets(),
        listDashboardBillingPaymentMethods(),
      ]);
      setOverview(nextOverview);
      setUsage(nextUsage);
      setPaymentMethods(nextPaymentMethods);
    } catch (error: unknown) {
      setOverview(null);
      setUsage(null);
      setPaymentMethods([]);
      setErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setLoading(false);
    }
  }, [session.claims, session.errorMessage]);

  const loadInvoiceListPage = React.useCallback(async () => {
    if (!session.claims) return;
    setInvoiceListLoading(true);
    setInvoiceListError('');
    try {
      const statusFilter = invoiceStatusFilter.toLowerCase();
      const invoiceStatus =
        statusFilter === 'open' ||
        statusFilter === 'paid' ||
        statusFilter === 'void' ||
        statusFilter === 'uncollectible'
          ? (statusFilter.toUpperCase() as 'OPEN' | 'PAID' | 'VOID' | 'UNCOLLECTIBLE')
          : undefined;
      let cursor: string | null = null;
      let totalCount = 0;
      let summary: DashboardBillingInvoiceListSummary | null = null;
      const allInvoices: DashboardBillingInvoice[] = [];
      for (;;) {
        const response = await listDashboardBillingInvoices({
          ...(invoiceStatus ? { status: invoiceStatus } : {}),
          ...(statusFilter === 'overdue' ? { overdue: true } : {}),
          ...(invoicePeriodFilter ? { periodMonthUtc: invoicePeriodFilter } : {}),
          ...(invoiceDocumentTypeFilter !== 'all'
            ? { documentType: invoiceDocumentTypeFilter as 'PURCHASE_RECEIPT' | 'USAGE_STATEMENT' }
            : {}),
          ...(cursor ? { cursor } : {}),
          limit: 100,
        });
        allInvoices.push(...response.invoices);
        totalCount = response.totalCount;
        summary = response.summary;
        cursor = response.nextCursor;
        if (!cursor) break;
      }
      setInvoices(allInvoices);
      setInvoiceTotalCount(totalCount);
      if (summary) {
        setInvoiceSummary(summary);
      }
    } catch (error: unknown) {
      setInvoices([]);
      setInvoiceTotalCount(0);
      setInvoiceSummary({
        totalCount: 0,
        openCount: 0,
        overdueCount: 0,
        paidCount: 0,
        outstandingAmountMinor: 0,
        latestPeriodMonthUtc: null,
        receiptCount: 0,
        statementCount: 0,
      });
      setInvoiceListError(error instanceof Error ? error.message : String(error));
    } finally {
      setInvoiceListLoading(false);
    }
  }, [invoiceDocumentTypeFilter, invoicePeriodFilter, invoiceStatusFilter, session.claims]);

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
    void refreshBillingShellData();
  }, [refreshBillingShellData, session.loading]);

  React.useEffect(() => {
    if (!session.claims || subview.kind === 'invoice') return;
    void loadInvoiceListPage();
  }, [
    invoiceDocumentTypeFilter,
    invoicePeriodFilter,
    invoiceStatusFilter,
    loadInvoiceListPage,
    session.claims,
    subview.kind,
  ]);

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const params = new URLSearchParams(window.location.search);
    const checkout = String(params.get('checkout') || '')
      .trim()
      .toLowerCase();
    if (checkout === 'success') {
      setCheckoutReturnMessage(
        'Top-up checkout completed. Balance updates after settlement confirmation.',
      );
    } else if (checkout === 'cancel') {
      setCheckoutReturnMessage('Top-up checkout was canceled before settlement.');
    } else {
      setCheckoutReturnMessage('');
    }
  }, [pathname]);

  React.useEffect(() => {
    if (!overview) {
      setBillingWarningMessage('');
      return;
    }
    if (overview.creditBalanceMinor <= overview.lowBalanceThresholdMinor) {
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

  const isBillingCardAdmin = React.useMemo(
    () =>
      Array.isArray(session.claims?.roles) &&
      session.claims.roles.some((role) => String(role || '').toLowerCase() === 'admin'),
    [session.claims?.roles],
  );

  const invoiceSummaryMetrics = React.useMemo<BillingMetric[]>(() => {
    return [
      {
        label: 'Matched documents',
        value: String(invoiceTotalCount),
        hint: `${invoiceSummary.statementCount} statements`,
      },
      {
        label: 'Purchase receipts',
        value: String(invoiceSummary.receiptCount),
        hint: `${invoiceSummary.paidCount} paid documents`,
      },
      {
        label: 'Outstanding',
        value: formatUsdMinor(invoiceSummary.outstandingAmountMinor),
        hint: `${invoiceSummary.openCount} open`,
      },
      {
        label: 'Latest period',
        value: invoiceSummary.latestPeriodMonthUtc || '-',
        hint: 'Loaded invoice history',
      },
    ];
  }, [invoiceSummary, invoiceTotalCount]);

  const summaryMetrics = React.useMemo<BillingMetric[]>(
    () => [
      {
        label: 'Balance',
        value: formatUsdMinor(overview?.creditBalanceMinor || 0),
        hint: `Warning at ${formatUsdMinor(overview?.lowBalanceThresholdMinor || 0)}`,
      },
      {
        label: 'Current MAW',
        value: String(usage?.monthlyActiveWallets ?? overview?.monthlyActiveWallets ?? 0),
        hint: usage?.monthUtc ? `${usage.monthUtc} (${usage.usageMetricVersion})` : 'No usage data',
      },
      {
        label: 'Recent usage',
        value: formatUsdMinor(overview?.recentUsageDebitMinor || 0),
        hint: 'Current month debit total',
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

  const onAddCardPaymentMethod = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setPaymentMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!isBillingCardAdmin) {
        setPaymentMutationError('Only admin role can add card payment methods.');
        return;
      }
      const providerRef = String(providerRefInput || '').trim();
      const brand = String(brandInput || '').trim();
      const last4 = String(last4Input || '').trim();
      const expMonth = parsePositiveInteger(expMonthInput);
      const expYear = parsePositiveInteger(expYearInput);
      if (!providerRef || !brand || !last4 || expMonth == null || expYear == null) {
        setPaymentMutationError(
          'providerRef, brand, last4, expMonth, and expYear are required for card creation.',
        );
        return;
      }
      setAddingPaymentMethod(true);
      setPaymentMutationError('');
      try {
        await addDashboardCardPaymentMethod({ providerRef, brand, last4, expMonth, expYear });
        setProviderRefInput('');
        setBrandInput('');
        setLast4Input('');
        setExpMonthInput('');
        setExpYearInput('');
        await refreshBillingShellData();
      } catch (error: unknown) {
        setPaymentMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setAddingPaymentMethod(false);
      }
    },
    [
      brandInput,
      expMonthInput,
      expYearInput,
      isBillingCardAdmin,
      last4Input,
      providerRefInput,
      refreshBillingShellData,
      session.claims,
      session.errorMessage,
    ],
  );

  const onCreatePaymentMethodSetupIntent = React.useCallback(async () => {
    if (!session.claims) {
      setPaymentMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setCreatingPaymentMethodSetupIntent(true);
    setPaymentMutationError('');
    setPaymentMethodSetupIntent(null);
    try {
      const setupIntent = await createDashboardStripeSetupIntent({
        returnUrl: window.location.href,
      });
      setPaymentMethodSetupIntent(setupIntent);
    } catch (error: unknown) {
      setPaymentMutationError(error instanceof Error ? error.message : String(error));
    } finally {
      setCreatingPaymentMethodSetupIntent(false);
    }
  }, [session.claims, session.errorMessage]);

  const onSetDefaultPaymentMethod = React.useCallback(
    async (paymentMethodId: string) => {
      if (!session.claims) {
        setPaymentMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!isBillingCardAdmin) {
        setPaymentMutationError('Only admin role can set default card payment methods.');
        return;
      }
      setBusyPaymentMethodId(paymentMethodId);
      setPaymentMutationError('');
      try {
        await setDashboardDefaultCardPaymentMethod(paymentMethodId);
        await refreshBillingShellData();
      } catch (error: unknown) {
        setPaymentMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyPaymentMethodId('');
      }
    },
    [isBillingCardAdmin, refreshBillingShellData, session.claims, session.errorMessage],
  );

  const onRemovePaymentMethod = React.useCallback(
    async (paymentMethodId: string) => {
      if (!session.claims) {
        setPaymentMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!isBillingCardAdmin) {
        setPaymentMutationError('Only admin role can remove card payment methods.');
        return;
      }
      if (!window.confirm(`Remove payment method ${paymentMethodId}?`)) return;
      setBusyPaymentMethodId(paymentMethodId);
      setPaymentMutationError('');
      try {
        await removeDashboardCardPaymentMethod(paymentMethodId);
        await refreshBillingShellData();
      } catch (error: unknown) {
        setPaymentMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyPaymentMethodId('');
      }
    },
    [isBillingCardAdmin, refreshBillingShellData, session.claims, session.errorMessage],
  );

  const onStartStripeCheckout = React.useCallback(
    async (creditPackId: 'usd_50' | 'usd_200' | 'usd_500' | 'usd_1000') => {
      if (!session.claims) {
        setCheckoutActionError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      setStartingCheckoutPackId(creditPackId);
      setCheckoutActionError('');
      try {
        const origin = window.location.origin;
        const checkoutSession = await createDashboardStripeCheckoutSession({
          successUrl: `${origin}/dashboard/billing/account?checkout=success`,
          cancelUrl: `${origin}/dashboard/billing/account?checkout=cancel`,
          creditPackId,
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

  const onOpenPaymentMethodPortal = React.useCallback(async () => {
    if (!session.claims) {
      setPaymentMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setOpeningCustomerPortal(true);
    setPaymentMutationError('');
    try {
      const portalSession = await createDashboardStripeCustomerPortalSession({
        returnUrl: window.location.href,
      });
      window.location.assign(portalSession.url);
    } catch (error: unknown) {
      setPaymentMutationError(error instanceof Error ? error.message : String(error));
    } finally {
      setOpeningCustomerPortal(false);
    }
  }, [session.claims, session.errorMessage]);

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
        <BillingAccountView
          selectedContext={selectedContextDisplay}
          summaryMetrics={summaryMetrics}
          checkoutActionError={checkoutActionError}
          startingCheckoutPackId={startingCheckoutPackId}
          openingCustomerPortal={openingCustomerPortal}
          onStartStripeCheckout={(creditPackId) => {
            void onStartStripeCheckout(creditPackId);
          }}
          onOpenPaymentMethodPortal={() => {
            void onOpenPaymentMethodPortal();
          }}
          providerRefInput={providerRefInput}
          setProviderRefInput={setProviderRefInput}
          brandInput={brandInput}
          setBrandInput={setBrandInput}
          last4Input={last4Input}
          setLast4Input={setLast4Input}
          expMonthInput={expMonthInput}
          setExpMonthInput={setExpMonthInput}
          expYearInput={expYearInput}
          setExpYearInput={setExpYearInput}
          isBillingCardAdmin={isBillingCardAdmin}
          addingPaymentMethod={addingPaymentMethod}
          creatingPaymentMethodSetupIntent={creatingPaymentMethodSetupIntent}
          paymentMutationError={paymentMutationError}
          paymentMethodSetupIntent={paymentMethodSetupIntent}
          paymentMethods={paymentMethods}
          busyPaymentMethodId={busyPaymentMethodId}
          onAddCardPaymentMethod={onAddCardPaymentMethod}
          onCreatePaymentMethodSetupIntent={() => {
            void onCreatePaymentMethodSetupIntent();
          }}
          onSetDefaultPaymentMethod={onSetDefaultPaymentMethod}
          onRemovePaymentMethod={onRemovePaymentMethod}
        />
      ) : subview.kind === 'invoices' ? (
        <BillingInvoicesView
          invoiceMetrics={invoiceSummaryMetrics}
          invoiceListLoading={invoiceListLoading}
          invoiceListError={invoiceListError}
          invoiceStatusFilter={invoiceStatusFilter}
          setInvoiceStatusFilter={setInvoiceStatusFilter}
          invoiceDocumentTypeFilter={invoiceDocumentTypeFilter}
          setInvoiceDocumentTypeFilter={setInvoiceDocumentTypeFilter}
          invoicePeriodFilter={invoicePeriodFilter}
          setInvoicePeriodFilter={setInvoicePeriodFilter}
          invoices={invoices}
          totalInvoices={invoiceTotalCount}
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
