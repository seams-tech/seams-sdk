import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
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
  formatUsdMinor,
  getDashboardBillingMonthlyActiveWallets,
  getDashboardBillingOverview,
  getDashboardBillingSubscription,
  getDashboardStablecoinPaymentIntent,
  getDashboardStablecoinAssetSupport,
  listDashboardBillingInvoiceLineItems,
  listDashboardBillingInvoices,
  listDashboardBillingPaymentMethods,
  removeDashboardCardPaymentMethod,
  resumeDashboardBillingSubscription,
  setDashboardDefaultCardPaymentMethod,
  type DashboardBillingInvoice,
  type DashboardBillingInvoiceLineItem,
  type DashboardBillingOverview,
  type DashboardBillingPaymentMethod,
  type DashboardBillingSubscription,
  type DashboardBillingUsage,
  type DashboardStablecoinPaymentIntent,
  type DashboardStablecoinPaymentQuote,
  type DashboardStablecoinAssetSupport,
  type DashboardStripePaymentIntent,
  type DashboardStripeSetupIntent,
} from './consoleBillingApi';

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function parsePositiveInteger(value: string): number | null {
  const raw = String(value || '').trim();
  if (!/^\d+$/.test(raw)) return null;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return null;
  return parsed;
}

export function BillingPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [overview, setOverview] = React.useState<DashboardBillingOverview | null>(null);
  const [usage, setUsage] = React.useState<DashboardBillingUsage | null>(null);
  const [invoices, setInvoices] = React.useState<DashboardBillingInvoice[]>([]);
  const [paymentMethods, setPaymentMethods] = React.useState<DashboardBillingPaymentMethod[]>([]);
  const [subscription, setSubscription] = React.useState<DashboardBillingSubscription | null>(null);
  const [stablecoinAssets, setStablecoinAssets] = React.useState<DashboardStablecoinAssetSupport[]>([]);
  const [subscriptionActionError, setSubscriptionActionError] = React.useState<string>('');
  const [startingCheckout, setStartingCheckout] = React.useState<boolean>(false);
  const [openingCustomerPortal, setOpeningCustomerPortal] = React.useState<boolean>(false);
  const [cancelingSubscription, setCancelingSubscription] = React.useState<boolean>(false);
  const [resumingSubscription, setResumingSubscription] = React.useState<boolean>(false);
  const [paymentMutationError, setPaymentMutationError] = React.useState<string>('');
  const [addingPaymentMethod, setAddingPaymentMethod] = React.useState<boolean>(false);
  const [busyPaymentMethodId, setBusyPaymentMethodId] = React.useState<string>('');
  const [providerRefInput, setProviderRefInput] = React.useState<string>('');
  const [brandInput, setBrandInput] = React.useState<string>('');
  const [last4Input, setLast4Input] = React.useState<string>('');
  const [expMonthInput, setExpMonthInput] = React.useState<string>('');
  const [expYearInput, setExpYearInput] = React.useState<string>('');
  const [paymentExecutionError, setPaymentExecutionError] = React.useState<string>('');
  const [creatingStripeSetupIntent, setCreatingStripeSetupIntent] = React.useState<boolean>(false);
  const [creatingStripePaymentIntent, setCreatingStripePaymentIntent] = React.useState<boolean>(false);
  const [creatingStablecoinQuote, setCreatingStablecoinQuote] = React.useState<boolean>(false);
  const [creatingStablecoinPaymentIntent, setCreatingStablecoinPaymentIntent] =
    React.useState<boolean>(false);
  const [refreshingStablecoinIntent, setRefreshingStablecoinIntent] = React.useState<boolean>(false);
  const [cancelingStablecoinIntent, setCancelingStablecoinIntent] = React.useState<boolean>(false);
  const [stripeInvoiceIdInput, setStripeInvoiceIdInput] = React.useState<string>('');
  const [stripePaymentMethodIdInput, setStripePaymentMethodIdInput] = React.useState<string>('');
  const [stablecoinInvoiceIdInput, setStablecoinInvoiceIdInput] = React.useState<string>('');
  const [stablecoinAssetInput, setStablecoinAssetInput] = React.useState<string>('');
  const [stablecoinChainInput, setStablecoinChainInput] = React.useState<string>('');
  const [stablecoinQuoteIdInput, setStablecoinQuoteIdInput] = React.useState<string>('');
  const [stablecoinIntentIdInput, setStablecoinIntentIdInput] = React.useState<string>('');
  const [stripeSetupIntent, setStripeSetupIntent] = React.useState<DashboardStripeSetupIntent | null>(
    null,
  );
  const [stripePaymentIntent, setStripePaymentIntent] =
    React.useState<DashboardStripePaymentIntent | null>(null);
  const [stablecoinQuote, setStablecoinQuote] =
    React.useState<DashboardStablecoinPaymentQuote | null>(null);
  const [stablecoinPaymentIntent, setStablecoinPaymentIntent] =
    React.useState<DashboardStablecoinPaymentIntent | null>(null);
  const [checkoutReturnMessage, setCheckoutReturnMessage] = React.useState<string>('');
  const [billingWarningMessage, setBillingWarningMessage] = React.useState<string>('');
  const [billingWarningDismissed, setBillingWarningDismissed] = React.useState<boolean>(false);

  const [selectedInvoiceId, setSelectedInvoiceId] = React.useState<string>('');
  const [lineItemsLoading, setLineItemsLoading] = React.useState<boolean>(false);
  const [lineItemsError, setLineItemsError] = React.useState<string>('');
  const [lineItems, setLineItems] = React.useState<DashboardBillingInvoiceLineItem[]>([]);

  const loadBillingData = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setOverview(null);
      setUsage(null);
      setInvoices([]);
      setPaymentMethods([]);
      setSubscription(null);
      setStablecoinAssets([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    Promise.all([
      getDashboardBillingOverview(),
      getDashboardBillingMonthlyActiveWallets(),
      listDashboardBillingInvoices(),
      listDashboardBillingPaymentMethods(),
      getDashboardBillingSubscription(),
      getDashboardStablecoinAssetSupport(),
    ])
      .then(
        ([
          nextOverview,
          nextUsage,
          nextInvoices,
          nextPaymentMethods,
          nextSubscription,
          nextStablecoinAssets,
        ]) => {
        if (cancelled) return;
        const sortedInvoices = [...nextInvoices].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        setOverview(nextOverview);
        setUsage(nextUsage);
        setInvoices(sortedInvoices);
        setPaymentMethods(nextPaymentMethods);
        setSubscription(nextSubscription);
        setStablecoinAssets(nextStablecoinAssets.assets);
      },
      )
      .catch((error: unknown) => {
        if (cancelled) return;
        setOverview(null);
        setUsage(null);
        setInvoices([]);
        setPaymentMethods([]);
        setSubscription(null);
        setStablecoinAssets([]);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadBillingData();
    return cleanup;
  }, [loadBillingData, session.loading]);

  React.useEffect(() => {
    if (invoices.length === 0) {
      setSelectedInvoiceId('');
      setLineItems([]);
      setLineItemsError('');
      setLineItemsLoading(false);
      return;
    }
    if (selectedInvoiceId && invoices.some((entry) => entry.id === selectedInvoiceId)) return;
    setSelectedInvoiceId(invoices[0]?.id || '');
  }, [invoices, selectedInvoiceId]);

  React.useEffect(() => {
    if (invoices.length === 0) {
      setStripeInvoiceIdInput('');
      setStablecoinInvoiceIdInput('');
      return;
    }
    if (!stripeInvoiceIdInput || !invoices.some((entry) => entry.id === stripeInvoiceIdInput)) {
      setStripeInvoiceIdInput(invoices[0]?.id || '');
    }
    if (
      !stablecoinInvoiceIdInput ||
      !invoices.some((entry) => entry.id === stablecoinInvoiceIdInput)
    ) {
      setStablecoinInvoiceIdInput(invoices[0]?.id || '');
    }
  }, [invoices, stablecoinInvoiceIdInput, stripeInvoiceIdInput]);

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
    if (!selectedInvoiceId || !session.claims) {
      setLineItems([]);
      setLineItemsError('');
      setLineItemsLoading(false);
      return;
    }
    let cancelled = false;
    setLineItemsLoading(true);
    setLineItemsError('');
    listDashboardBillingInvoiceLineItems(selectedInvoiceId)
      .then((rows) => {
        if (cancelled) return;
        setLineItems(rows);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setLineItems([]);
        setLineItemsError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLineItemsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedInvoiceId, session.claims]);

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
      `${currentUrl.pathname}${currentUrl.search}${currentUrl.hash}` || '/dashboard/billing';
    window.history.replaceState({}, document.title, nextRelative);

    if (checkoutState === 'success' && session.claims) {
      void loadBillingData();
    }
  }, [loadBillingData, session.claims]);

  const summaryMetrics = React.useMemo(
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

  const stripeInvoice = React.useMemo(
    () => invoices.find((entry) => entry.id === stripeInvoiceIdInput) || null,
    [invoices, stripeInvoiceIdInput],
  );

  const stablecoinInvoice = React.useMemo(
    () => invoices.find((entry) => entry.id === stablecoinInvoiceIdInput) || null,
    [invoices, stablecoinInvoiceIdInput],
  );

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
        loadBillingData();
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
      loadBillingData,
      providerRefInput,
      session.claims,
      session.errorMessage,
    ],
  );

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
        loadBillingData();
      } catch (error: unknown) {
        setPaymentMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyPaymentMethodId('');
      }
    },
    [isBillingCardAdmin, loadBillingData, session.claims, session.errorMessage],
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
        loadBillingData();
      } catch (error: unknown) {
        setPaymentMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setBusyPaymentMethodId('');
      }
    },
    [isBillingCardAdmin, loadBillingData, session.claims, session.errorMessage],
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
        successUrl: `${origin}/dashboard/billing?checkout=success`,
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
      loadBillingData();
    } catch (error: unknown) {
      setSubscriptionActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setCancelingSubscription(false);
    }
  }, [canCancelSubscription, loadBillingData, session.claims, session.errorMessage]);

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
      loadBillingData();
    } catch (error: unknown) {
      setSubscriptionActionError(error instanceof Error ? error.message : String(error));
    } finally {
      setResumingSubscription(false);
    }
  }, [canResumeSubscription, loadBillingData, session.claims, session.errorMessage]);

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
      const invoiceId = String(stripeInvoiceIdInput || '').trim();
      if (!invoiceId) {
        setPaymentExecutionError('Invoice id is required to create a Stripe payment intent.');
        return;
      }
      const paymentMethodId = String(stripePaymentMethodIdInput || '').trim();
      setCreatingStripePaymentIntent(true);
      setPaymentExecutionError('');
      try {
        const paymentIntent = await createDashboardStripePaymentIntent({
          invoiceId,
          paymentMethodId: paymentMethodId || undefined,
        });
        setStripePaymentIntent(paymentIntent);
        setStripeInvoiceIdInput(paymentIntent.invoiceId);
        await loadBillingData();
      } catch (error: unknown) {
        setPaymentExecutionError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreatingStripePaymentIntent(false);
      }
    },
    [
      loadBillingData,
      session.claims,
      session.errorMessage,
      stripeInvoiceIdInput,
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
      const invoiceId = String(stablecoinInvoiceIdInput || '').trim();
      const asset = String(stablecoinAssetInput || '').trim();
      const chain = String(stablecoinChainInput || '').trim();
      if (!invoiceId || !asset || !chain) {
        setPaymentExecutionError(
          'Invoice, asset, and chain are required to create a stablecoin quote.',
        );
        return;
      }
      setCreatingStablecoinQuote(true);
      setPaymentExecutionError('');
      try {
        const quote = await createDashboardStablecoinQuote({
          invoiceId,
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
    [session.claims, session.errorMessage, stablecoinAssetInput, stablecoinChainInput, stablecoinInvoiceIdInput],
  );

  const onCreateStablecoinPaymentIntent = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setPaymentExecutionError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const invoiceId = String(stablecoinInvoiceIdInput || '').trim();
      const quoteId = String(stablecoinQuoteIdInput || '').trim();
      if (!invoiceId || !quoteId) {
        setPaymentExecutionError(
          'Invoice id and quote id are required to create a stablecoin payment intent.',
        );
        return;
      }
      setCreatingStablecoinPaymentIntent(true);
      setPaymentExecutionError('');
      try {
        const paymentIntent = await createDashboardStablecoinPaymentIntent({
          invoiceId,
          quoteId,
        });
        setStablecoinPaymentIntent(paymentIntent);
        setStablecoinIntentIdInput(paymentIntent.id);
        setStablecoinInvoiceIdInput(paymentIntent.invoiceId);
        await loadBillingData();
      } catch (error: unknown) {
        setPaymentExecutionError(error instanceof Error ? error.message : String(error));
      } finally {
        setCreatingStablecoinPaymentIntent(false);
      }
    },
    [loadBillingData, session.claims, session.errorMessage, stablecoinInvoiceIdInput, stablecoinQuoteIdInput],
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
      await loadBillingData();
    } catch (error: unknown) {
      setPaymentExecutionError(error instanceof Error ? error.message : String(error));
    } finally {
      setRefreshingStablecoinIntent(false);
    }
  }, [loadBillingData, session.claims, session.errorMessage, stablecoinIntentIdInput]);

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
      await loadBillingData();
    } catch (error: unknown) {
      setPaymentExecutionError(error instanceof Error ? error.message : String(error));
    } finally {
      setCancelingStablecoinIntent(false);
    }
  }, [loadBillingData, session.claims, session.errorMessage, stablecoinIntentIdInput]);

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

      <section className="dashboard-view__section" aria-label="Billing scope and actions">
        <h2>Billing overview</h2>
        <p>
          Billing is org-scoped. Current topbar context: org {selectedContext.organization || '-'},
          project {selectedContext.project || '-'}, environment {selectedContext.environment || '-'}.
        </p>
        <button type="button" className="dashboard-pagination-button" onClick={() => loadBillingData()}>
          Refresh billing data
        </button>
      </section>

      {checkoutReturnMessage ? (
        <section className="dashboard-view__section">
          {checkoutReturnMessage ? (
            <p className="dashboard-info-banner">{checkoutReturnMessage}</p>
          ) : null}
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
      ) : (
        <>
          <section className="dashboard-kpi-grid dashboard-kpi-grid--content" aria-label="Billing summary metrics">
            {summaryMetrics.map((metric) => (
              <article className="dashboard-kpi-card" key={metric.label}>
                <p className="dashboard-kpi-card__label">{metric.label}</p>
                <p className="dashboard-kpi-card__value">{metric.value}</p>
                <p className="dashboard-kpi-card__hint">{metric.hint}</p>
              </article>
            ))}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Subscription management table">
            <div className="dashboard-table-limit">
              <h3>Subscription management</h3>
              <p>
                Start or update plan checkout in Stripe, and use the customer portal for
                subscription/payment management after checkout.
              </p>
              {subscriptionActionError ? (
                <p className="dashboard-pagination-note">{subscriptionActionError}</p>
              ) : null}
            </div>
            <div className="dashboard-view-grid dashboard-view-grid--two">
              <div className="dashboard-view-card dashboard-view-grid">
                <h2>Current subscription</h2>
                {!subscription ? (
                  <p className="dashboard-pagination-note">No subscription returned for this org.</p>
                ) : (
                  <>
                    <p className="dashboard-pagination-note">
                      Plan: {subscription.planName} ({subscription.planId})
                    </p>
                    <p className="dashboard-pagination-note">Status: {subscription.status}</p>
                    <p className="dashboard-pagination-note">
                      Cancel at period end: {subscription.cancelAtPeriodEnd ? 'Yes' : 'No'}
                    </p>
                    <p className="dashboard-pagination-note">
                      Current period: {formatTimestamp(subscription.currentPeriodStart)} to{' '}
                      {formatTimestamp(subscription.currentPeriodEnd)}
                    </p>
                    <p className="dashboard-pagination-note">
                      Cancel at: {formatTimestamp(subscription.cancelAt)}
                    </p>
                    <p className="dashboard-pagination-note">
                      Canceled at: {formatTimestamp(subscription.canceledAt)}
                    </p>
                    <p className="dashboard-pagination-note">
                      Provider refs: customer {subscription.providerCustomerRef || '-'}, subscription{' '}
                      {subscription.providerSubscriptionRef || '-'}
                    </p>
                  </>
                )}
              </div>
              <div className="dashboard-view-card dashboard-view-grid">
                <h2>Subscription actions</h2>
                <div className="dashboard-form-actions">
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={onStartStripeCheckout}
                    disabled={startingCheckout}
                  >
                    {startingCheckout ? 'Starting checkout...' : 'Start Stripe Checkout'}
                  </button>
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={onOpenCustomerPortal}
                    disabled={openingCustomerPortal}
                  >
                    {openingCustomerPortal ? 'Opening portal...' : 'Open Stripe Customer Portal'}
                  </button>
                </div>
                <div className="dashboard-form-actions">
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={onCancelSubscription}
                    disabled={!canCancelSubscription || cancelingSubscription}
                  >
                    {cancelingSubscription ? 'Scheduling cancel...' : 'Cancel at period end'}
                  </button>
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={onResumeSubscription}
                    disabled={!canResumeSubscription || resumingSubscription}
                  >
                    {resumingSubscription ? 'Resuming...' : 'Resume subscription'}
                  </button>
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={() => loadBillingData()}
                  >
                    Refresh subscription
                  </button>
                </div>
                <p className="dashboard-pagination-note">
                  Checkout success returns to <code>/dashboard/billing?checkout=success</code>.
                </p>
              </div>
            </div>
          </section>

          <section className="dashboard-table-wrapper" aria-label="Invoices table">
            <div className="dashboard-table-header" role="row">
              <span>Invoice ID</span>
              <span>Status</span>
              <span>Period</span>
              <span>Due</span>
              <span>Rail lock</span>
              <span>Amount due</span>
              <span>Amount paid</span>
              <span>Created</span>
            </div>
            {invoices.length === 0 ? (
              <p className="dashboard-table-limit">No invoices yet.</p>
            ) : (
              <>
                {invoices.map((invoice) => (
                  <div className="dashboard-table-row" key={invoice.id} role="row">
                    <span title={invoice.id}>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => setSelectedInvoiceId(invoice.id)}
                      >
                        {invoice.id}
                      </button>
                    </span>
                    <span>{invoice.status}</span>
                    <span>{invoice.periodMonthUtc || '-'}</span>
                    <span>{formatTimestamp(invoice.dueAt)}</span>
                    <span>{invoice.railLock || '-'}</span>
                    <span>{formatUsdMinor(invoice.amountDueMinor)}</span>
                    <span>{formatUsdMinor(invoice.amountPaidMinor)}</span>
                    <span>{formatTimestamp(invoice.createdAt)}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {invoices.length} invoice{invoices.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Selected invoice line items">
            <div className="dashboard-table-header" role="row">
              <span>Line item ID</span>
              <span>Type</span>
              <span>Description</span>
              <span>Period</span>
              <span>Quantity</span>
              <span>Unit amount</span>
              <span>Amount</span>
              <span>Invoice</span>
            </div>
            {!selectedInvoiceId ? (
              <p className="dashboard-table-limit">Select an invoice to view line items.</p>
            ) : lineItemsLoading ? (
              <p className="dashboard-table-limit">Loading line items for {selectedInvoiceId}...</p>
            ) : lineItemsError ? (
              <p className="dashboard-table-limit">Line items unavailable: {lineItemsError}</p>
            ) : lineItems.length === 0 ? (
              <p className="dashboard-table-limit">No line items for this invoice.</p>
            ) : (
              <>
                {lineItems.map((lineItem) => (
                  <div className="dashboard-table-row" key={lineItem.id} role="row">
                    <span title={lineItem.id}>{lineItem.id}</span>
                    <span>{lineItem.itemType || '-'}</span>
                    <span title={lineItem.description}>{lineItem.description || '-'}</span>
                    <span>{lineItem.periodMonthUtc || '-'}</span>
                    <span>{String(lineItem.quantity)}</span>
                    <span>{formatUsdMinor(lineItem.unitAmountMinor)}</span>
                    <span>{formatUsdMinor(lineItem.amountMinor)}</span>
                    <span title={lineItem.invoiceId}>{lineItem.invoiceId}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {lineItems.length} line item{lineItems.length === 1 ? '' : 's'} for {selectedInvoiceId}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Payment methods table">
            <div className="dashboard-table-limit">
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onAddCardPaymentMethod}>
                <label className="dashboard-form-field">
                  <span>Provider reference</span>
                  <input
                    className="dashboard-input"
                    value={providerRefInput}
                    onChange={(event) => setProviderRefInput(event.target.value)}
                    placeholder="pm_123..."
                    disabled={!isBillingCardAdmin}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Brand</span>
                  <input
                    className="dashboard-input"
                    value={brandInput}
                    onChange={(event) => setBrandInput(event.target.value)}
                    placeholder="visa"
                    disabled={!isBillingCardAdmin}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Last4</span>
                  <input
                    className="dashboard-input"
                    value={last4Input}
                    onChange={(event) => setLast4Input(event.target.value)}
                    placeholder="4242"
                    disabled={!isBillingCardAdmin}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Expiry month</span>
                  <input
                    className="dashboard-input"
                    value={expMonthInput}
                    onChange={(event) => setExpMonthInput(event.target.value)}
                    placeholder="12"
                    disabled={!isBillingCardAdmin}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Expiry year</span>
                  <input
                    className="dashboard-input"
                    value={expYearInput}
                    onChange={(event) => setExpYearInput(event.target.value)}
                    placeholder="2030"
                    disabled={!isBillingCardAdmin}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={!isBillingCardAdmin || addingPaymentMethod}
                  >
                    {addingPaymentMethod ? 'Adding card...' : 'Add card'}
                  </button>
                  <span className="dashboard-pagination-note">
                    {isBillingCardAdmin
                      ? 'Admin role enabled for add/remove/set-default card actions.'
                      : 'Only admin role can add/remove/set-default cards.'}
                  </span>
                </div>
              </form>
              {paymentMutationError ? (
                <p className="dashboard-pagination-note">{paymentMutationError}</p>
              ) : null}
            </div>
            <div className="dashboard-table-header" role="row">
              <span>Method ID</span>
              <span>Provider</span>
              <span>Type</span>
              <span>Brand</span>
              <span>Last4</span>
              <span>Expiry</span>
              <span>Default</span>
              <span>Actions</span>
            </div>
            {paymentMethods.length === 0 ? (
              <p className="dashboard-table-limit">No card payment methods on file.</p>
            ) : (
              <>
                {paymentMethods.map((method) => (
                  <div className="dashboard-table-row" key={method.id} role="row">
                    <span title={method.id}>{method.id}</span>
                    <span>{method.provider || '-'}</span>
                    <span>{method.type || '-'}</span>
                    <span>{method.brand || '-'}</span>
                    <span>{method.last4 || '-'}</span>
                    <span>
                      {method.expMonth > 0 && method.expYear > 0
                        ? `${String(method.expMonth).padStart(2, '0')}/${String(method.expYear)}`
                        : '-'}
                    </span>
                    <span>{method.isDefault ? 'Yes' : 'No'}</span>
                    <span>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => onSetDefaultPaymentMethod(method.id)}
                        disabled={
                          !isBillingCardAdmin || busyPaymentMethodId === method.id || method.isDefault
                        }
                      >
                        Set default
                      </button>{' '}
                      <button
                        type="button"
                        className="dashboard-inline-link dashboard-inline-link--danger"
                        onClick={() => onRemovePaymentMethod(method.id)}
                        disabled={!isBillingCardAdmin || busyPaymentMethodId === method.id}
                      >
                        Remove
                      </button>
                    </span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {paymentMethods.length} payment method{paymentMethods.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Stablecoin settlement policy table">
            <div className="dashboard-table-limit">
              <h3>Payment execution</h3>
              <p>
                Each invoice must be paid on a single rail. Create either a Stripe card payment
                intent or a stablecoin payment intent for full outstanding balance.
              </p>
              {paymentExecutionError ? (
                <p className="dashboard-pagination-note">{paymentExecutionError}</p>
              ) : null}
            </div>
            <div className="dashboard-view-grid dashboard-view-grid--two">
              <form className="dashboard-view-card dashboard-view-grid" onSubmit={onCreateStripePaymentIntent}>
                <h2>Stripe card payment</h2>
                <label className="dashboard-form-field">
                  <span>Invoice</span>
                  <select
                    className="dashboard-input"
                    value={stripeInvoiceIdInput}
                    onChange={(event) => setStripeInvoiceIdInput(event.target.value)}
                  >
                    {invoices.map((invoice) => (
                      <option key={invoice.id} value={invoice.id}>
                        {invoice.id}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Payment method ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={stripePaymentMethodIdInput}
                    onChange={(event) => setStripePaymentMethodIdInput(event.target.value)}
                    placeholder="pm_..."
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={onCreateStripeSetupIntent}
                    disabled={creatingStripeSetupIntent}
                  >
                    {creatingStripeSetupIntent ? 'Creating setup intent...' : 'Create setup intent'}
                  </button>
                </div>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={creatingStripePaymentIntent}
                  >
                    {creatingStripePaymentIntent
                      ? 'Creating payment intent...'
                      : 'Create Stripe payment intent'}
                  </button>
                </div>
                <p className="dashboard-pagination-note">
                  Invoice rail lock: {stripeInvoice?.railLock || '-'}; outstanding:{' '}
                  {formatUsdMinor(
                    Math.max(
                      0,
                      Number(stripeInvoice?.amountDueMinor || 0) -
                        Number(stripeInvoice?.amountPaidMinor || 0),
                    ),
                  )}
                  .
                </p>
                <p className="dashboard-pagination-note">
                  Setup intent:{' '}
                  {stripeSetupIntent ? `${stripeSetupIntent.id} (expires ${formatTimestamp(stripeSetupIntent.expiresAt)})` : '-'}
                </p>
                <p className="dashboard-pagination-note">
                  Latest card payment intent:{' '}
                  {stripePaymentIntent
                    ? `${stripePaymentIntent.id} state=${stripePaymentIntent.state} amount=${formatUsdMinor(stripePaymentIntent.amountMinor)}`
                    : '-'}
                </p>
              </form>
              <div className="dashboard-view-card dashboard-view-grid">
                <form className="dashboard-view-grid" onSubmit={onCreateStablecoinQuote}>
                  <h2>Stablecoin payment</h2>
                  <label className="dashboard-form-field">
                    <span>Invoice</span>
                    <select
                      className="dashboard-input"
                      value={stablecoinInvoiceIdInput}
                      onChange={(event) => setStablecoinInvoiceIdInput(event.target.value)}
                    >
                      {invoices.map((invoice) => (
                        <option key={invoice.id} value={invoice.id}>
                          {invoice.id}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="dashboard-form-field">
                    <span>Asset</span>
                    <select
                      className="dashboard-input"
                      value={stablecoinAssetInput}
                      onChange={(event) => setStablecoinAssetInput(event.target.value)}
                    >
                      {stablecoinAssets.map((assetSupport) => (
                        <option key={assetSupport.asset} value={assetSupport.asset}>
                          {assetSupport.asset}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="dashboard-form-field">
                    <span>Chain</span>
                    <select
                      className="dashboard-input"
                      value={stablecoinChainInput}
                      onChange={(event) => setStablecoinChainInput(event.target.value)}
                    >
                      {stablecoinChainOptions.map((policy) => (
                        <option key={policy.chain} value={policy.chain}>
                          {policy.chain}
                        </option>
                      ))}
                    </select>
                  </label>
                  <div className="dashboard-form-actions">
                    <button
                      type="submit"
                      className="dashboard-pagination-button"
                      disabled={creatingStablecoinQuote}
                    >
                      {creatingStablecoinQuote ? 'Creating quote...' : 'Create stablecoin quote'}
                    </button>
                  </div>
                </form>
                <form className="dashboard-view-grid" onSubmit={onCreateStablecoinPaymentIntent}>
                  <label className="dashboard-form-field">
                    <span>Quote ID</span>
                    <input
                      className="dashboard-input"
                      value={stablecoinQuoteIdInput}
                      onChange={(event) => setStablecoinQuoteIdInput(event.target.value)}
                      placeholder="scq_..."
                    />
                  </label>
                  <div className="dashboard-form-actions">
                    <button
                      type="submit"
                      className="dashboard-pagination-button"
                      disabled={creatingStablecoinPaymentIntent}
                    >
                      {creatingStablecoinPaymentIntent
                        ? 'Creating payment intent...'
                        : 'Create stablecoin payment intent'}
                    </button>
                  </div>
                </form>
                <div className="dashboard-view-grid">
                  <label className="dashboard-form-field">
                    <span>Stablecoin payment intent ID</span>
                    <input
                      className="dashboard-input"
                      value={stablecoinIntentIdInput}
                      onChange={(event) => setStablecoinIntentIdInput(event.target.value)}
                      placeholder="scpi_..."
                    />
                  </label>
                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={onRefreshStablecoinIntent}
                      disabled={refreshingStablecoinIntent}
                    >
                      {refreshingStablecoinIntent ? 'Refreshing...' : 'Refresh stablecoin status'}
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={onCancelStablecoinIntent}
                      disabled={cancelingStablecoinIntent}
                    >
                      {cancelingStablecoinIntent ? 'Canceling...' : 'Cancel stablecoin intent'}
                    </button>
                  </div>
                </div>
                <p className="dashboard-pagination-note">
                  Invoice rail lock: {stablecoinInvoice?.railLock || '-'}; outstanding:{' '}
                  {formatUsdMinor(
                    Math.max(
                      0,
                      Number(stablecoinInvoice?.amountDueMinor || 0) -
                        Number(stablecoinInvoice?.amountPaidMinor || 0),
                    ),
                  )}
                  .
                </p>
                <p className="dashboard-pagination-note">
                  Latest stablecoin quote:{' '}
                  {stablecoinQuote
                    ? `${stablecoinQuote.id} ${stablecoinQuote.asset}/${stablecoinQuote.chain} amount=${formatUsdMinor(stablecoinQuote.amountMinor)} state=${stablecoinQuote.state}`
                    : '-'}
                </p>
                <p className="dashboard-pagination-note">
                  Latest stablecoin payment intent:{' '}
                  {stablecoinPaymentIntent
                    ? `${stablecoinPaymentIntent.id} state=${stablecoinPaymentIntent.state} amount=${formatUsdMinor(stablecoinPaymentIntent.expectedAmountMinor)} destination=${stablecoinPaymentIntent.destinationAddress || '-'}`
                    : '-'}
                </p>
              </div>
            </div>
          </section>

        </>
      )}
    </div>
  );
}

export default BillingPage;
