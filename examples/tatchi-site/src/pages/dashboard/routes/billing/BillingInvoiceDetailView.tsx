import React from 'react';
import {
  formatUsdMinor,
  type DashboardBillingInvoiceActivity,
  type DashboardBillingInvoice,
  type DashboardBillingInvoiceLineItem,
  type DashboardStablecoinAssetSupport,
  type DashboardStablecoinPaymentIntent,
  type DashboardStablecoinPaymentQuote,
  type DashboardStripePaymentIntent,
  type DashboardStripeSetupIntent,
} from './consoleBillingApi';
import {
  BillingMetricsGrid,
  formatInvoiceStatusLabel,
  formatTimestamp,
  getInvoiceStatusBadgeClassName,
  type BillingMetric,
} from './billingShared';

export interface BillingInvoiceDetailViewProps {
  invoiceId: string;
  invoice: DashboardBillingInvoice | null;
  invoiceDetailLoading: boolean;
  invoiceDetailError: string;
  invoiceActivityLoading: boolean;
  invoiceActivityError: string;
  invoiceActivity: DashboardBillingInvoiceActivity | null;
  lineItemsLoading: boolean;
  lineItemsError: string;
  lineItems: DashboardBillingInvoiceLineItem[];
  downloadingInvoicePdfId: string;
  invoiceDownloadError: string;
  onBackToInvoices: () => void;
  onDownloadInvoicePdf: (invoiceId: string) => Promise<void>;
  stripePaymentMethodIdInput: string;
  setStripePaymentMethodIdInput: React.Dispatch<React.SetStateAction<string>>;
  creatingStripeSetupIntent: boolean;
  creatingStripePaymentIntent: boolean;
  onCreateStripeSetupIntent: () => Promise<void>;
  onCreateStripePaymentIntent: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
  stripeSetupIntent: DashboardStripeSetupIntent | null;
  stripePaymentIntent: DashboardStripePaymentIntent | null;
  stablecoinAssets: DashboardStablecoinAssetSupport[];
  stablecoinAssetInput: string;
  setStablecoinAssetInput: React.Dispatch<React.SetStateAction<string>>;
  stablecoinChainInput: string;
  setStablecoinChainInput: React.Dispatch<React.SetStateAction<string>>;
  stablecoinChainOptions: DashboardStablecoinAssetSupport['chains'];
  creatingStablecoinQuote: boolean;
  onCreateStablecoinQuote: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
  stablecoinQuote: DashboardStablecoinPaymentQuote | null;
  stablecoinQuoteIdInput: string;
  setStablecoinQuoteIdInput: React.Dispatch<React.SetStateAction<string>>;
  creatingStablecoinPaymentIntent: boolean;
  onCreateStablecoinPaymentIntent: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
  stablecoinPaymentIntent: DashboardStablecoinPaymentIntent | null;
  stablecoinIntentIdInput: string;
  setStablecoinIntentIdInput: React.Dispatch<React.SetStateAction<string>>;
  refreshingStablecoinIntent: boolean;
  cancelingStablecoinIntent: boolean;
  onRefreshStablecoinIntent: () => Promise<void>;
  onCancelStablecoinIntent: () => Promise<void>;
  paymentExecutionError: string;
}

export function BillingInvoiceDetailView(props: BillingInvoiceDetailViewProps): React.JSX.Element {
  const {
    invoiceId,
    invoice,
    invoiceDetailLoading,
    invoiceDetailError,
    invoiceActivityLoading,
    invoiceActivityError,
    invoiceActivity,
    lineItemsLoading,
    lineItemsError,
    lineItems,
    downloadingInvoicePdfId,
    invoiceDownloadError,
    onBackToInvoices,
    onDownloadInvoicePdf,
    stripePaymentMethodIdInput,
    setStripePaymentMethodIdInput,
    creatingStripeSetupIntent,
    creatingStripePaymentIntent,
    onCreateStripeSetupIntent,
    onCreateStripePaymentIntent,
    stripeSetupIntent,
    stripePaymentIntent,
    stablecoinAssets,
    stablecoinAssetInput,
    setStablecoinAssetInput,
    stablecoinChainInput,
    setStablecoinChainInput,
    stablecoinChainOptions,
    creatingStablecoinQuote,
    onCreateStablecoinQuote,
    stablecoinQuote,
    stablecoinQuoteIdInput,
    setStablecoinQuoteIdInput,
    creatingStablecoinPaymentIntent,
    onCreateStablecoinPaymentIntent,
    stablecoinPaymentIntent,
    stablecoinIntentIdInput,
    setStablecoinIntentIdInput,
    refreshingStablecoinIntent,
    cancelingStablecoinIntent,
    onRefreshStablecoinIntent,
    onCancelStablecoinIntent,
    paymentExecutionError,
  } = props;

  const outstandingBalanceMinor = Math.max(
    0,
    Number(invoice?.amountDueMinor || 0) - Number(invoice?.amountPaidMinor || 0),
  );
  const canExecutePayment =
    invoice != null && invoice.status === 'OPEN' && outstandingBalanceMinor > 0;

  const detailMetrics: BillingMetric[] = [
    {
      label: 'Status',
      value: invoice ? formatInvoiceStatusLabel(invoice.status) : '-',
      hint: invoice?.railLock ? `Rail lock: ${invoice.railLock}` : 'No rail lock',
    },
    {
      label: 'Outstanding',
      value: formatUsdMinor(outstandingBalanceMinor),
      hint: `Amount due ${formatUsdMinor(Number(invoice?.amountDueMinor || 0))}`,
    },
    {
      label: 'Billing period',
      value: invoice?.periodMonthUtc || '-',
      hint: `Created ${formatTimestamp(invoice?.createdAt || null)}`,
    },
    {
      label: 'Due date',
      value: formatTimestamp(invoice?.dueAt || null),
      hint: `Paid ${formatUsdMinor(Number(invoice?.amountPaidMinor || 0))}`,
    },
  ];

  return (
    <>
      <section
        className="dashboard-view__section dashboard-billing-invoice-hero"
        aria-label="Invoice detail header"
      >
        <div className="dashboard-billing-invoice-hero__actions">
          <button
            type="button"
            className="dashboard-pagination-button dashboard-pagination-button--secondary"
            onClick={onBackToInvoices}
          >
            Back to invoices
          </button>
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={() => {
              void onDownloadInvoicePdf(invoiceId);
            }}
            disabled={downloadingInvoicePdfId === invoiceId}
          >
            {downloadingInvoicePdfId === invoiceId ? 'Downloading PDF...' : 'Download PDF'}
          </button>
        </div>
        <div className="dashboard-billing-invoice-hero__copy">
          <p className="dashboard-billing-invoice-hero__eyebrow">Invoice detail</p>
          <h2>{invoice?.id || invoiceId}</h2>
          <p>View line items, payment state, and settlement actions for this invoice.</p>
        </div>
        {invoiceDownloadError ? (
          <p className="dashboard-pagination-note">{invoiceDownloadError}</p>
        ) : null}
      </section>

      {invoiceDetailLoading ? (
        <section className="dashboard-view__section">
          <p>Loading invoice detail...</p>
        </section>
      ) : invoiceDetailError ? (
        <section className="dashboard-view__section">
          <p>Invoice detail unavailable: {invoiceDetailError}</p>
        </section>
      ) : !invoice ? (
        <section className="dashboard-view__section">
          <p>Invoice {invoiceId} was not found.</p>
        </section>
      ) : (
        <>
          <BillingMetricsGrid metrics={detailMetrics} ariaLabel="Invoice detail summary metrics" />

          <section className="dashboard-table-wrapper" aria-label="Invoice activity timeline">
            <div className="dashboard-table-limit dashboard-billing-table__intro">
              <h3 className="dashboard-billing-table__title">Status timeline</h3>
              <p className="dashboard-billing-table__description">
                Review invoice issuance and payment-state transitions in one chronological feed.
              </p>
              {invoiceActivity?.latestPaymentState ? (
                <p className="dashboard-pagination-note">
                  Latest payment state:{' '}
                  <span
                    className={getInvoiceStatusBadgeClassName(invoiceActivity.latestPaymentState)}
                  >
                    {formatInvoiceStatusLabel(invoiceActivity.latestPaymentState)}
                  </span>
                  {invoiceActivity.latestPaymentRail
                    ? ` via ${invoiceActivity.latestPaymentRail}`
                    : ''}
                </p>
              ) : null}
              {invoiceActivityError ? (
                <p className="dashboard-pagination-note">{invoiceActivityError}</p>
              ) : null}
            </div>
            {invoiceActivityLoading ? (
              <p className="dashboard-table-limit">Loading invoice activity...</p>
            ) : invoiceActivity?.entries.length ? (
              <div className="dashboard-billing-timeline">
                {invoiceActivity.entries.map((entry) => (
                  <article className="dashboard-billing-timeline__item" key={entry.id}>
                    <div className="dashboard-billing-timeline__header">
                      <p className="dashboard-billing-timeline__title">{entry.summary}</p>
                      <span className={getInvoiceStatusBadgeClassName(entry.toState)}>
                        {formatInvoiceStatusLabel(entry.toState)}
                      </span>
                    </div>
                    <p className="dashboard-billing-timeline__meta">
                      {formatTimestamp(entry.occurredAt)}
                      {entry.rail ? ` • ${entry.rail}` : ''}
                      {entry.paymentId ? ` • ${entry.paymentId}` : ''}
                      {entry.actorUserId ? ` • ${entry.actorUserId}` : ''}
                    </p>
                  </article>
                ))}
              </div>
            ) : (
              <p className="dashboard-table-limit">No invoice activity has been recorded yet.</p>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Invoice line items">
            <div className="dashboard-table-limit dashboard-billing-table__intro">
              <h3 className="dashboard-billing-table__title">Line items</h3>
              <p className="dashboard-billing-table__description">
                Review the priced components that make up this invoice.
              </p>
            </div>
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
            {lineItemsLoading ? (
              <p className="dashboard-table-limit">Loading line items...</p>
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
                  Showing {lineItems.length} line item{lineItems.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Payment execution table">
            <div className="dashboard-table-limit dashboard-billing-table__intro">
              <h3 className="dashboard-billing-table__title">Payment execution</h3>
              <p className="dashboard-billing-table__description">
                Settlement actions are invoice-scoped. Card and stablecoin flows both operate
                against the current invoice.
              </p>
              {!canExecutePayment ? (
                <p className="dashboard-pagination-note">
                  This invoice is not currently payable from the dashboard. Open invoices with
                  outstanding balance can create settlement intents.
                </p>
              ) : null}
              {paymentExecutionError ? (
                <p className="dashboard-pagination-note">{paymentExecutionError}</p>
              ) : null}
            </div>
            <div className="dashboard-view-grid dashboard-view-grid--two">
              <form
                className="dashboard-view-card dashboard-view-grid dashboard-billing-execution-card"
                onSubmit={(event) => {
                  void onCreateStripePaymentIntent(event);
                }}
              >
                <h2>Stripe card payment</h2>
                <p className="dashboard-pagination-note">Invoice: {invoice.id}</p>
                <label className="dashboard-form-field">
                  <span>Payment method ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={stripePaymentMethodIdInput}
                    onChange={(event) => setStripePaymentMethodIdInput(event.target.value)}
                    placeholder="pm_..."
                    disabled={!canExecutePayment}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="button"
                    className="dashboard-pagination-button dashboard-pagination-button--secondary"
                    onClick={() => {
                      void onCreateStripeSetupIntent();
                    }}
                    disabled={creatingStripeSetupIntent}
                  >
                    {creatingStripeSetupIntent ? 'Creating setup intent...' : 'Create setup intent'}
                  </button>
                </div>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={!canExecutePayment || creatingStripePaymentIntent}
                  >
                    {creatingStripePaymentIntent
                      ? 'Creating payment intent...'
                      : 'Create Stripe payment intent'}
                  </button>
                </div>
                <p className="dashboard-pagination-note">
                  Invoice rail lock: {invoice.railLock || '-'}; outstanding:{' '}
                  {formatUsdMinor(outstandingBalanceMinor)}.
                </p>
                <p className="dashboard-pagination-note">
                  Setup intent:{' '}
                  {stripeSetupIntent
                    ? `${stripeSetupIntent.id} (expires ${formatTimestamp(stripeSetupIntent.expiresAt)})`
                    : '-'}
                </p>
                <p className="dashboard-pagination-note">
                  Latest card payment intent:{' '}
                  {stripePaymentIntent
                    ? `${stripePaymentIntent.id} state=${stripePaymentIntent.state} amount=${formatUsdMinor(stripePaymentIntent.amountMinor)}`
                    : '-'}
                </p>
              </form>

              <div className="dashboard-view-card dashboard-view-grid dashboard-billing-execution-card">
                <form
                  className="dashboard-view-grid"
                  onSubmit={(event) => {
                    void onCreateStablecoinQuote(event);
                  }}
                >
                  <h2>Stablecoin payment</h2>
                  <p className="dashboard-pagination-note">Invoice: {invoice.id}</p>
                  <label className="dashboard-form-field">
                    <span>Asset</span>
                    <select
                      className="dashboard-input"
                      value={stablecoinAssetInput}
                      onChange={(event) => setStablecoinAssetInput(event.target.value)}
                      disabled={!canExecutePayment}
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
                      disabled={!canExecutePayment}
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
                      disabled={!canExecutePayment || creatingStablecoinQuote}
                    >
                      {creatingStablecoinQuote ? 'Creating quote...' : 'Create stablecoin quote'}
                    </button>
                  </div>
                </form>

                <form
                  className="dashboard-view-grid"
                  onSubmit={(event) => {
                    void onCreateStablecoinPaymentIntent(event);
                  }}
                >
                  <label className="dashboard-form-field">
                    <span>Quote ID</span>
                    <input
                      className="dashboard-input"
                      value={stablecoinQuoteIdInput}
                      onChange={(event) => setStablecoinQuoteIdInput(event.target.value)}
                      placeholder="scq_..."
                      disabled={!canExecutePayment}
                    />
                  </label>
                  <div className="dashboard-form-actions">
                    <button
                      type="submit"
                      className="dashboard-pagination-button"
                      disabled={!canExecutePayment || creatingStablecoinPaymentIntent}
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
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={() => {
                        void onRefreshStablecoinIntent();
                      }}
                      disabled={refreshingStablecoinIntent}
                    >
                      {refreshingStablecoinIntent ? 'Refreshing...' : 'Refresh stablecoin status'}
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={() => {
                        void onCancelStablecoinIntent();
                      }}
                      disabled={cancelingStablecoinIntent}
                    >
                      {cancelingStablecoinIntent ? 'Canceling...' : 'Cancel stablecoin intent'}
                    </button>
                  </div>
                </div>
                <p className="dashboard-pagination-note">
                  Invoice rail lock: {invoice.railLock || '-'}; outstanding:{' '}
                  {formatUsdMinor(outstandingBalanceMinor)}.
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
    </>
  );
}

export default BillingInvoiceDetailView;
