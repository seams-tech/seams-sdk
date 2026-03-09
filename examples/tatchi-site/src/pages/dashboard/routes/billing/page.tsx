import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import { BillingAccountView } from './BillingAccountView';
import { BillingInvoiceDetailView } from './BillingInvoiceDetailView';
import { BillingInvoicesView } from './BillingInvoicesView';
import {
  addDashboardCardPaymentMethod,
  cancelDashboardBillingSubscription,
  cancelDashboardStablecoinPaymentIntent,
  createDashboardStripeCheckoutSession,
  createDashboardStripeCustomerPortalSession,
  createDashboardStablecoinPaymentIntent,
  createDashboardStablecoinQuote,
  createDashboardStripePaymentIntent,
  createDashboardStripeSetupIntent,
  downloadDashboardBillingInvoicePdf,
  formatUsdMinor,
  getDashboardBillingInvoiceActivity,
  getDashboardBillingInvoice,
  getDashboardBillingMonthlyActiveWallets,
  getDashboardBillingOverview,
  getDashboardBillingSubscription,
  getDashboardStablecoinPaymentIntent,
  getDashboardStablecoinAssetSupport,
  isDashboardBillingApiErrorCode,
  listDashboardBillingInvoiceLineItems,
  listDashboardBillingInvoices,
  listDashboardBillingPaymentMethods,
  removeDashboardCardPaymentMethod,
  resumeDashboardBillingSubscription,
  setDashboardDefaultCardPaymentMethod,
  type DashboardBillingInvoiceActivity,
  type DashboardBillingInvoice,
  type DashboardBillingInvoiceLineItem,
  type DashboardBillingInvoiceListSummary,
  type DashboardBillingOverview,
  type DashboardBillingPaymentMethod,
  type DashboardBillingSubscription,
  type DashboardBillingUsage,
  type DashboardStablecoinAssetSupport,
  type DashboardStablecoinPaymentIntent,
  type DashboardStablecoinPaymentQuote,
  type DashboardStripePaymentIntent,
  type DashboardStripeSetupIntent,
} from './consoleBillingApi';
import {
  buildInvoicePdfFilename,
  parseBillingSubview,
  parsePositiveInteger,
  type BillingMetric,
} from './billingShared';

export function BillingPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const { go } = useSiteRouter();
  const pathname =
    typeof window === 'undefined' ? '/dashboard/billing/account' : window.location.pathname;
  const subview = React.useMemo(() => parseBillingSubview(pathname), [pathname]);
  const activeInvoiceId = subview.kind === 'invoice' ? subview.invoiceId : '';

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [overview, setOverview] = React.useState<DashboardBillingOverview | null>(null);
  const [usage, setUsage] = React.useState<DashboardBillingUsage | null>(null);
  const [invoices, setInvoices] = React.useState<DashboardBillingInvoice[]>([]);
  const [invoiceListLoading, setInvoiceListLoading] = React.useState<boolean>(false);
  const [invoiceListError, setInvoiceListError] = React.useState<string>('');
  const [loadingMoreInvoices, setLoadingMoreInvoices] = React.useState<boolean>(false);
  const [invoiceNextCursor, setInvoiceNextCursor] = React.useState<string | null>(null);
  const [invoiceTotalCount, setInvoiceTotalCount] = React.useState<number>(0);
  const [invoiceSummary, setInvoiceSummary] = React.useState<DashboardBillingInvoiceListSummary>({
    totalCount: 0,
    openCount: 0,
    overdueCount: 0,
    paidCount: 0,
    outstandingAmountMinor: 0,
    latestPeriodMonthUtc: null,
  });
  const [paymentMethods, setPaymentMethods] = React.useState<DashboardBillingPaymentMethod[]>([]);
  const [subscription, setSubscription] = React.useState<DashboardBillingSubscription | null>(null);
  const [stablecoinAssets, setStablecoinAssets] = React.useState<DashboardStablecoinAssetSupport[]>(
    [],
  );
  const [subscriptionActionError, setSubscriptionActionError] = React.useState<string>('');
  const [startingCheckout, setStartingCheckout] = React.useState<boolean>(false);
  const [openingCustomerPortal, setOpeningCustomerPortal] = React.useState<boolean>(false);
  const [cancelingSubscription, setCancelingSubscription] = React.useState<boolean>(false);
  const [resumingSubscription, setResumingSubscription] = React.useState<boolean>(false);
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
  const [paymentExecutionError, setPaymentExecutionError] = React.useState<string>('');
  const [creatingStripeSetupIntent, setCreatingStripeSetupIntent] = React.useState<boolean>(false);
  const [creatingStripePaymentIntent, setCreatingStripePaymentIntent] =
    React.useState<boolean>(false);
  const [creatingStablecoinQuote, setCreatingStablecoinQuote] = React.useState<boolean>(false);
  const [creatingStablecoinPaymentIntent, setCreatingStablecoinPaymentIntent] =
    React.useState<boolean>(false);
  const [refreshingStablecoinIntent, setRefreshingStablecoinIntent] =
    React.useState<boolean>(false);
  const [cancelingStablecoinIntent, setCancelingStablecoinIntent] = React.useState<boolean>(false);
  const [stripePaymentMethodIdInput, setStripePaymentMethodIdInput] = React.useState<string>('');
  const [stablecoinAssetInput, setStablecoinAssetInput] = React.useState<string>('');
  const [stablecoinChainInput, setStablecoinChainInput] = React.useState<string>('');
  const [stablecoinQuoteIdInput, setStablecoinQuoteIdInput] = React.useState<string>('');
  const [stablecoinIntentIdInput, setStablecoinIntentIdInput] = React.useState<string>('');
  const [stripeSetupIntent, setStripeSetupIntent] =
    React.useState<DashboardStripeSetupIntent | null>(null);
  const [stripePaymentIntent, setStripePaymentIntent] =
    React.useState<DashboardStripePaymentIntent | null>(null);
  const [stablecoinQuote, setStablecoinQuote] =
    React.useState<DashboardStablecoinPaymentQuote | null>(null);
  const [stablecoinPaymentIntent, setStablecoinPaymentIntent] =
    React.useState<DashboardStablecoinPaymentIntent | null>(null);
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
  const [invoicePeriodFilter, setInvoicePeriodFilter] = React.useState<string>('');
  const [downloadingInvoicePdfId, setDownloadingInvoicePdfId] = React.useState<string>('');
  const [invoiceDownloadError, setInvoiceDownloadError] = React.useState<string>('');
  const [invoiceRefreshNonce, setInvoiceRefreshNonce] = React.useState<number>(0);

  const refreshBillingShellData = React.useCallback(async () => {
    if (!session.claims) {
      setLoading(false);
      setOverview(null);
      setUsage(null);
      setInvoices([]);
      setInvoiceNextCursor(null);
      setInvoiceTotalCount(0);
      setInvoiceSummary({
        totalCount: 0,
        openCount: 0,
        overdueCount: 0,
        paidCount: 0,
        outstandingAmountMinor: 0,
        latestPeriodMonthUtc: null,
      });
      setPaymentMethods([]);
      setSubscription(null);
      setStablecoinAssets([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setLoading(true);
    setErrorMessage('');
    try {
      const [nextOverview, nextUsage, nextPaymentMethods, nextSubscription, nextStablecoinAssets] =
        await Promise.all([
          getDashboardBillingOverview(),
          getDashboardBillingMonthlyActiveWallets(),
          listDashboardBillingPaymentMethods(),
          getDashboardBillingSubscription(),
          getDashboardStablecoinAssetSupport(),
        ]);
      setOverview(nextOverview);
      setUsage(nextUsage);
      setPaymentMethods(nextPaymentMethods);
      setSubscription(nextSubscription);
      setStablecoinAssets(nextStablecoinAssets.assets);
    } catch (error: unknown) {
      setOverview(null);
      setUsage(null);
      setInvoices([]);
      setInvoiceNextCursor(null);
      setInvoiceTotalCount(0);
      setInvoiceSummary({
        totalCount: 0,
        openCount: 0,
        overdueCount: 0,
        paidCount: 0,
        outstandingAmountMinor: 0,
        latestPeriodMonthUtc: null,
      });
      setPaymentMethods([]);
      setSubscription(null);
      setStablecoinAssets([]);
      setErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setLoading(false);
    }
  }, [session.claims, session.errorMessage]);

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
    if (stablecoinAssets.length === 0) {
      setStablecoinAssetInput('');
      setStablecoinChainInput('');
      return;
    }
    const selectedAsset = stablecoinAssets.find((entry) => entry.asset === stablecoinAssetInput);
    if (!selectedAsset) {
      const fallbackAsset = stablecoinAssets[0];
      setStablecoinAssetInput(fallbackAsset.asset);
      setStablecoinChainInput(fallbackAsset.chains[0]?.chain || '');
      return;
    }
    if (!selectedAsset.chains.some((chainPolicy) => chainPolicy.chain === stablecoinChainInput)) {
      setStablecoinChainInput(selectedAsset.chains[0]?.chain || '');
    }
  }, [stablecoinAssetInput, stablecoinAssets, stablecoinChainInput]);

  React.useEffect(() => {
    setStripePaymentMethodIdInput('');
    setStablecoinQuoteIdInput('');
    setStablecoinIntentIdInput('');
    setStripeSetupIntent(null);
    setStripePaymentIntent(null);
    setStablecoinQuote(null);
    setStablecoinPaymentIntent(null);
    setPaymentExecutionError('');
  }, [activeInvoiceId]);

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const currentUrl = new URL(window.location.href);
    const checkoutState = String(currentUrl.searchParams.get('checkout') || '')
      .trim()
      .toLowerCase();
    const billingNotice = String(currentUrl.searchParams.get('billing') || '')
      .trim()
      .toLowerCase();
    if (!checkoutState && !billingNotice) return;

    if (checkoutState) {
      if (checkoutState === 'success') {
        setCheckoutReturnMessage('Stripe Checkout completed. Billing data has been refreshed.');
      } else if (checkoutState === 'cancel') {
        setCheckoutReturnMessage('Stripe Checkout was canceled. No billing changes were applied.');
      } else {
        setCheckoutReturnMessage(`Checkout returned with status "${checkoutState}".`);
      }
    }

    if (billingNotice === 'production_required') {
      setBillingWarningMessage('Billing must be configured for production.');
      setBillingWarningDismissed(false);
    }

    currentUrl.searchParams.delete('checkout');
    currentUrl.searchParams.delete('billing');
    currentUrl.searchParams.delete('session_id');
    const nextRelative =
      `${currentUrl.pathname}${currentUrl.search}${currentUrl.hash}` ||
      '/dashboard/billing/account';
    window.history.replaceState({}, document.title, nextRelative);

    if (checkoutState === 'success' && session.claims) {
      void refreshBillingShellData();
      setInvoiceRefreshNonce((value) => value + 1);
    }
  }, [pathname, refreshBillingShellData, session.claims]);

  const invoiceListRequest = React.useMemo(() => {
    const request: Parameters<typeof listDashboardBillingInvoices>[0] = {
      limit: 25,
    };
    if (invoiceStatusFilter === 'open') {
      request.status = 'OPEN';
    } else if (invoiceStatusFilter === 'overdue') {
      request.status = 'OVERDUE';
      request.overdue = true;
    } else if (invoiceStatusFilter === 'paid') {
      request.status = 'PAID';
    } else if (invoiceStatusFilter === 'void') {
      request.status = 'VOID';
    } else if (invoiceStatusFilter === 'uncollectible') {
      request.status = 'UNCOLLECTIBLE';
    }
    const normalizedPeriodMonthUtc = String(invoicePeriodFilter || '').trim();
    if (/^\d{4}-\d{2}$/.test(normalizedPeriodMonthUtc)) {
      request.periodMonthUtc = normalizedPeriodMonthUtc;
    }
    return request;
  }, [invoicePeriodFilter, invoiceStatusFilter]);

  const loadInvoiceListPage = React.useCallback(
    async (input: { append?: boolean; cursor?: string | null } = {}) => {
      if (!session.claims) {
        setInvoices([]);
        setInvoiceNextCursor(null);
        setInvoiceTotalCount(0);
        setInvoiceSummary({
          totalCount: 0,
          openCount: 0,
          overdueCount: 0,
          paidCount: 0,
          outstandingAmountMinor: 0,
          latestPeriodMonthUtc: null,
        });
        setInvoiceListError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const request = {
        ...invoiceListRequest,
        ...(input.cursor ? { cursor: input.cursor } : {}),
      };
      if (input.append) {
        setLoadingMoreInvoices(true);
      } else {
        setInvoiceListLoading(true);
        setInvoiceListError('');
      }
      try {
        const page = await listDashboardBillingInvoices(request);
        setInvoices((current) => (input.append ? [...current, ...page.invoices] : page.invoices));
        setInvoiceNextCursor(page.nextCursor);
        setInvoiceTotalCount(page.totalCount);
        setInvoiceSummary(page.summary);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        setInvoiceListError(message);
        if (!input.append) {
          setInvoices([]);
          setInvoiceNextCursor(null);
          setInvoiceTotalCount(0);
          setInvoiceSummary({
            totalCount: 0,
            openCount: 0,
            overdueCount: 0,
            paidCount: 0,
            outstandingAmountMinor: 0,
            latestPeriodMonthUtc: null,
          });
        }
      } finally {
        if (input.append) {
          setLoadingMoreInvoices(false);
        } else {
          setInvoiceListLoading(false);
        }
      }
    },
    [invoiceListRequest, session.claims, session.errorMessage],
  );

  React.useEffect(() => {
    if (subview.kind !== 'invoices') {
      setInvoiceListLoading(false);
      setLoadingMoreInvoices(false);
      setInvoiceListError('');
      return;
    }
    void loadInvoiceListPage();
  }, [invoiceRefreshNonce, loadInvoiceListPage, subview.kind]);

  React.useEffect(() => {
    if (subview.kind !== 'invoice' || !session.claims) {
      setInvoiceDetail(null);
      setInvoiceDetailError('');
      setInvoiceDetailLoading(false);
      setInvoiceActivity(null);
      setInvoiceActivityError('');
      setInvoiceActivityLoading(false);
      setLineItems([]);
      setLineItemsError('');
      setLineItemsLoading(false);
      return;
    }
    let cancelled = false;
    const invoiceId = subview.invoiceId;

    setInvoiceDetailLoading(true);
    setInvoiceDetailError('');
    setInvoiceActivityLoading(true);
    setInvoiceActivityError('');
    setLineItemsLoading(true);
    setLineItemsError('');

    getDashboardBillingInvoice(invoiceId)
      .then((nextInvoice) => {
        if (cancelled) return;
        setInvoiceDetail(nextInvoice);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setInvoiceDetail(null);
        setLineItems([]);
        setLineItemsError('');
        if (isDashboardBillingApiErrorCode(error, 'invoice_not_found')) {
          setInvoiceDetailError(`Invoice ${invoiceId} was not found.`);
        } else {
          setInvoiceDetailError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (cancelled) return;
        setInvoiceDetailLoading(false);
      });

    getDashboardBillingInvoiceActivity(invoiceId)
      .then((activity) => {
        if (cancelled) return;
        setInvoiceActivity(activity);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setInvoiceActivity(null);
        if (isDashboardBillingApiErrorCode(error, 'invoice_not_found')) {
          setInvoiceActivityError(`Invoice ${invoiceId} was not found.`);
        } else {
          setInvoiceActivityError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (cancelled) return;
        setInvoiceActivityLoading(false);
      });

    listDashboardBillingInvoiceLineItems(invoiceId)
      .then((rows) => {
        if (cancelled) return;
        setLineItems(rows);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setLineItems([]);
        if (isDashboardBillingApiErrorCode(error, 'invoice_not_found')) {
          setLineItemsError(`Invoice ${invoiceId} was not found.`);
        } else {
          setLineItemsError(error instanceof Error ? error.message : String(error));
        }
      })
      .finally(() => {
        if (cancelled) return;
        setLineItemsLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [activeInvoiceId, invoiceRefreshNonce, session.claims, subview.kind]);

  const isBillingCardAdmin = React.useMemo(
    () =>
      Array.isArray(session.claims?.roles) &&
      session.claims.roles.some((role) => String(role || '').toLowerCase() === 'admin'),
    [session.claims?.roles],
  );

  const canCancelSubscription =
    subscription != null && subscription.status !== 'CANCELED' && !subscription.cancelAtPeriodEnd;
  const canResumeSubscription =
    subscription != null && subscription.status !== 'CANCELED' && subscription.cancelAtPeriodEnd;

  const invoiceSummaryMetrics = React.useMemo<BillingMetric[]>(() => {
    const outstandingMinor = invoices.reduce((total, invoice) => {
      return (
        total +
        Math.max(0, Number(invoice.amountDueMinor || 0) - Number(invoice.amountPaidMinor || 0))
      );
    }, 0);
    return [
      {
        label: 'Matched invoices',
        value: String(invoiceTotalCount),
        hint: `${invoiceSummary.overdueCount} overdue`,
      },
      {
        label: 'Loaded now',
        value: String(invoices.length),
        hint: invoiceNextCursor ? 'More invoices available' : 'All matching invoices loaded',
      },
      {
        label: 'Outstanding',
        value: formatUsdMinor(invoiceSummary.outstandingAmountMinor || outstandingMinor),
        hint: `${invoiceSummary.paidCount} paid invoice${invoiceSummary.paidCount === 1 ? '' : 's'}`,
      },
      {
        label: 'Latest period',
        value: invoiceSummary.latestPeriodMonthUtc || '-',
        hint: overview?.planName || 'No plan data',
      },
    ];
  }, [invoiceNextCursor, invoiceSummary, invoiceTotalCount, invoices, overview?.planName]);

  const summaryMetrics = React.useMemo<BillingMetric[]>(
    () => [
      {
        label: 'Plan',
        value: overview?.planName || '-',
        hint: overview?.planId ? `ID ${overview.planId}` : 'No plan data',
      },
      {
        label: 'MAW',
        value: String(usage?.monthlyActiveWallets ?? overview?.monthlyActiveWallets ?? 0),
        hint: usage?.monthUtc ? `${usage.monthUtc} (${usage.usageMetricVersion})` : 'No usage data',
      },
      {
        label: 'Upcoming charge',
        value: formatUsdMinor(overview?.upcomingChargeEstimateMinor || 0),
        hint: `Open invoices: ${overview?.openInvoiceCount ?? 0}`,
      },
      {
        label: 'Credit balance',
        value: formatUsdMinor(overview?.creditBalanceMinor || 0),
        hint: `${paymentMethods.length} payment method${paymentMethods.length === 1 ? '' : 's'}`,
      },
    ],
    [overview, paymentMethods.length, usage],
  );

  const stablecoinChainOptions = React.useMemo(() => {
    const match = stablecoinAssets.find((entry) => entry.asset === stablecoinAssetInput);
    return match?.chains || [];
  }, [stablecoinAssetInput, stablecoinAssets]);

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
        await addDashboardCardPaymentMethod({
          providerRef,
          brand,
          last4,
          expMonth,
          expYear,
        });
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

  const onStartStripeCheckout = React.useCallback(async () => {
    if (!session.claims) {
      setSubscriptionActionError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setStartingCheckout(true);
    setSubscriptionActionError('');
    try {
      const origin = window.location.origin;
      const checkoutSession = await createDashboardStripeCheckoutSession({
        successUrl: `${origin}/dashboard/billing/account?checkout=success`,
        cancelUrl: `${origin}/pricing?checkout=cancel`,
        planId: subscription?.planId || overview?.planId || 'pro_maw_v1',
      });
      window.location.assign(checkoutSession.url);
    } catch (error: unknown) {
      setSubscriptionActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setStartingCheckout(false);
    }
  }, [overview?.planId, session.claims, session.errorMessage, subscription?.planId]);

  const onOpenCustomerPortal = React.useCallback(async () => {
    if (!session.claims) {
      setSubscriptionActionError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setOpeningCustomerPortal(true);
    setSubscriptionActionError('');
    try {
      const portalSession = await createDashboardStripeCustomerPortalSession({
        returnUrl: window.location.href,
      });
      window.location.assign(portalSession.url);
    } catch (error: unknown) {
      setSubscriptionActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setOpeningCustomerPortal(false);
    }
  }, [session.claims, session.errorMessage]);

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

  const onCancelSubscription = React.useCallback(async () => {
    if (!session.claims) {
      setSubscriptionActionError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canCancelSubscription) {
      setSubscriptionActionError(
        'Subscription cannot be canceled in the current state (already canceled or already scheduled).',
      );
      return;
    }
    if (!window.confirm('Cancel subscription at the end of the current billing period?')) return;
    setCancelingSubscription(true);
    setSubscriptionActionError('');
    try {
      const updated = await cancelDashboardBillingSubscription();
      setSubscription(updated);
      await refreshBillingShellData();
    } catch (error: unknown) {
      setSubscriptionActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setCancelingSubscription(false);
    }
  }, [canCancelSubscription, refreshBillingShellData, session.claims, session.errorMessage]);

  const onResumeSubscription = React.useCallback(async () => {
    if (!session.claims) {
      setSubscriptionActionError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canResumeSubscription) {
      setSubscriptionActionError(
        'Subscription cannot be resumed in the current state (not scheduled for cancellation).',
      );
      return;
    }
    setResumingSubscription(true);
    setSubscriptionActionError('');
    try {
      const updated = await resumeDashboardBillingSubscription();
      setSubscription(updated);
      await refreshBillingShellData();
    } catch (error: unknown) {
      setSubscriptionActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setResumingSubscription(false);
    }
  }, [canResumeSubscription, refreshBillingShellData, session.claims, session.errorMessage]);

  const onCreateStripeSetupIntent = React.useCallback(async () => {
    if (!session.claims) {
      setPaymentExecutionError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setCreatingStripeSetupIntent(true);
    setPaymentExecutionError('');
    try {
      const setupIntent = await createDashboardStripeSetupIntent({
        returnUrl: window.location.href,
      });
      setStripeSetupIntent(setupIntent);
    } catch (error: unknown) {
      setPaymentExecutionError(error instanceof Error ? error.message : String(error));
    } finally {
      setCreatingStripeSetupIntent(false);
    }
  }, [session.claims, session.errorMessage]);

  const onCreateStripePaymentIntent = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setPaymentExecutionError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!activeInvoiceId) {
        setPaymentExecutionError('Invoice id is required to create a Stripe payment intent.');
        return;
      }
      const paymentMethodId = String(stripePaymentMethodIdInput || '').trim();
      setCreatingStripePaymentIntent(true);
      setPaymentExecutionError('');
      try {
        const paymentIntent = await createDashboardStripePaymentIntent({
          invoiceId: activeInvoiceId,
          paymentMethodId: paymentMethodId || undefined,
        });
        setStripePaymentIntent(paymentIntent);
        await refreshBillingShellData();
        setInvoiceRefreshNonce((value) => value + 1);
      } catch (error: unknown) {
        setPaymentExecutionError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreatingStripePaymentIntent(false);
      }
    },
    [
      activeInvoiceId,
      refreshBillingShellData,
      session.claims,
      session.errorMessage,
      stripePaymentMethodIdInput,
    ],
  );

  const onCreateStablecoinQuote = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setPaymentExecutionError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!activeInvoiceId) {
        setPaymentExecutionError('Invoice id is required to create a stablecoin quote.');
        return;
      }
      const asset = String(stablecoinAssetInput || '').trim();
      const chain = String(stablecoinChainInput || '').trim();
      if (!asset || !chain) {
        setPaymentExecutionError('Asset and chain are required to create a stablecoin quote.');
        return;
      }
      setCreatingStablecoinQuote(true);
      setPaymentExecutionError('');
      try {
        const quote = await createDashboardStablecoinQuote({
          invoiceId: activeInvoiceId,
          asset,
          chain,
        });
        setStablecoinQuote(quote);
        setStablecoinQuoteIdInput(quote.id);
      } catch (error: unknown) {
        setPaymentExecutionError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreatingStablecoinQuote(false);
      }
    },
    [
      activeInvoiceId,
      session.claims,
      session.errorMessage,
      stablecoinAssetInput,
      stablecoinChainInput,
    ],
  );

  const onCreateStablecoinPaymentIntent = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setPaymentExecutionError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!activeInvoiceId) {
        setPaymentExecutionError('Invoice id is required to create a stablecoin payment intent.');
        return;
      }
      const quoteId = String(stablecoinQuoteIdInput || '').trim();
      if (!quoteId) {
        setPaymentExecutionError('Quote id is required to create a stablecoin payment intent.');
        return;
      }
      setCreatingStablecoinPaymentIntent(true);
      setPaymentExecutionError('');
      try {
        const paymentIntent = await createDashboardStablecoinPaymentIntent({
          invoiceId: activeInvoiceId,
          quoteId,
        });
        setStablecoinPaymentIntent(paymentIntent);
        setStablecoinIntentIdInput(paymentIntent.id);
        await refreshBillingShellData();
        setInvoiceRefreshNonce((value) => value + 1);
      } catch (error: unknown) {
        setPaymentExecutionError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreatingStablecoinPaymentIntent(false);
      }
    },
    [
      activeInvoiceId,
      refreshBillingShellData,
      session.claims,
      session.errorMessage,
      stablecoinQuoteIdInput,
    ],
  );

  const onRefreshStablecoinIntent = React.useCallback(async () => {
    if (!session.claims) {
      setPaymentExecutionError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    const paymentIntentId = String(stablecoinIntentIdInput || '').trim();
    if (!paymentIntentId) {
      setPaymentExecutionError('Stablecoin payment intent id is required to refresh status.');
      return;
    }
    setRefreshingStablecoinIntent(true);
    setPaymentExecutionError('');
    try {
      const paymentIntent = await getDashboardStablecoinPaymentIntent(paymentIntentId);
      setStablecoinPaymentIntent(paymentIntent);
      setStablecoinIntentIdInput(paymentIntent.id);
      await refreshBillingShellData();
      setInvoiceRefreshNonce((value) => value + 1);
    } catch (error: unknown) {
      setPaymentExecutionError(error instanceof Error ? error.message : String(error));
    } finally {
      setRefreshingStablecoinIntent(false);
    }
  }, [refreshBillingShellData, session.claims, session.errorMessage, stablecoinIntentIdInput]);

  const onCancelStablecoinIntent = React.useCallback(async () => {
    if (!session.claims) {
      setPaymentExecutionError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    const paymentIntentId = String(stablecoinIntentIdInput || '').trim();
    if (!paymentIntentId) {
      setPaymentExecutionError('Stablecoin payment intent id is required to cancel.');
      return;
    }
    if (!window.confirm(`Cancel stablecoin payment intent ${paymentIntentId}?`)) return;
    setCancelingStablecoinIntent(true);
    setPaymentExecutionError('');
    try {
      const paymentIntent = await cancelDashboardStablecoinPaymentIntent(paymentIntentId);
      setStablecoinPaymentIntent(paymentIntent);
      setStablecoinIntentIdInput(paymentIntent.id);
      await refreshBillingShellData();
      setInvoiceRefreshNonce((value) => value + 1);
    } catch (error: unknown) {
      setPaymentExecutionError(error instanceof Error ? error.message : String(error));
    } finally {
      setCancelingStablecoinIntent(false);
    }
  }, [refreshBillingShellData, session.claims, session.errorMessage, stablecoinIntentIdInput]);

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

  const onLoadMoreInvoices = React.useCallback(async () => {
    if (!invoiceNextCursor || loadingMoreInvoices) return;
    await loadInvoiceListPage({ append: true, cursor: invoiceNextCursor });
  }, [invoiceNextCursor, loadInvoiceListPage, loadingMoreInvoices]);

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
          selectedContext={selectedContext}
          summaryMetrics={summaryMetrics}
          subscription={subscription}
          subscriptionActionError={subscriptionActionError}
          startingCheckout={startingCheckout}
          openingCustomerPortal={openingCustomerPortal}
          cancelingSubscription={cancelingSubscription}
          resumingSubscription={resumingSubscription}
          canCancelSubscription={canCancelSubscription}
          canResumeSubscription={canResumeSubscription}
          onStartStripeCheckout={() => {
            void onStartStripeCheckout();
          }}
          onOpenCustomerPortal={() => {
            void onOpenCustomerPortal();
          }}
          onOpenPaymentMethodPortal={() => {
            void onOpenPaymentMethodPortal();
          }}
          onCancelSubscription={() => {
            void onCancelSubscription();
          }}
          onResumeSubscription={() => {
            void onResumeSubscription();
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
          invoicePeriodFilter={invoicePeriodFilter}
          setInvoicePeriodFilter={setInvoicePeriodFilter}
          invoices={invoices}
          totalInvoices={invoiceTotalCount}
          hasMoreInvoices={invoiceNextCursor !== null}
          loadingMoreInvoices={loadingMoreInvoices}
          downloadingInvoicePdfId={downloadingInvoicePdfId}
          invoiceDownloadError={invoiceDownloadError}
          onOpenInvoice={(invoiceId) => go(`/dashboard/invoices/${encodeURIComponent(invoiceId)}`)}
          onLoadMoreInvoices={() => {
            void onLoadMoreInvoices();
          }}
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
          stripePaymentMethodIdInput={stripePaymentMethodIdInput}
          setStripePaymentMethodIdInput={setStripePaymentMethodIdInput}
          creatingStripeSetupIntent={creatingStripeSetupIntent}
          creatingStripePaymentIntent={creatingStripePaymentIntent}
          onCreateStripeSetupIntent={onCreateStripeSetupIntent}
          onCreateStripePaymentIntent={onCreateStripePaymentIntent}
          stripeSetupIntent={stripeSetupIntent}
          stripePaymentIntent={stripePaymentIntent}
          stablecoinAssets={stablecoinAssets}
          stablecoinAssetInput={stablecoinAssetInput}
          setStablecoinAssetInput={setStablecoinAssetInput}
          stablecoinChainInput={stablecoinChainInput}
          setStablecoinChainInput={setStablecoinChainInput}
          stablecoinChainOptions={stablecoinChainOptions}
          creatingStablecoinQuote={creatingStablecoinQuote}
          onCreateStablecoinQuote={onCreateStablecoinQuote}
          stablecoinQuote={stablecoinQuote}
          stablecoinQuoteIdInput={stablecoinQuoteIdInput}
          setStablecoinQuoteIdInput={setStablecoinQuoteIdInput}
          creatingStablecoinPaymentIntent={creatingStablecoinPaymentIntent}
          onCreateStablecoinPaymentIntent={onCreateStablecoinPaymentIntent}
          stablecoinPaymentIntent={stablecoinPaymentIntent}
          stablecoinIntentIdInput={stablecoinIntentIdInput}
          setStablecoinIntentIdInput={setStablecoinIntentIdInput}
          refreshingStablecoinIntent={refreshingStablecoinIntent}
          cancelingStablecoinIntent={cancelingStablecoinIntent}
          onRefreshStablecoinIntent={onRefreshStablecoinIntent}
          onCancelStablecoinIntent={onCancelStablecoinIntent}
          paymentExecutionError={paymentExecutionError}
        />
      )}
    </div>
  );
}

export default BillingPage;
