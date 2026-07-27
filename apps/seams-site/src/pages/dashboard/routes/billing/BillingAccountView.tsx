import React from 'react';
import type {
  DashboardBillingRefund,
  DashboardBillingCreditPackId,
  DashboardStripeCheckoutSessionRequest,
} from './consoleBillingApi';
import { formatUsdMinor } from './consoleBillingApi';
import { BillingMetricsGrid, type BillingMetric } from './billingShared';

const PRESET_CREDIT_PACK_OPTIONS = [
  { id: 'usd_10', label: '$10', detail: 'Quick prepaid top-up for test traffic.' },
  { id: 'usd_25', label: '$25', detail: 'Starter prepaid balance for light production.' },
  { id: 'usd_50', label: '$50', detail: 'Larger one-time top-up for ongoing usage.' },
] as const;

function formatRefundStatus(status: DashboardBillingRefund['status']): string {
  switch (status) {
    case 'requested':
      return 'Requested';
    case 'provider_pending':
      return 'Processing';
    case 'succeeded':
      return 'Refunded';
    case 'failed':
      return 'Failed';
    case 'canceled':
      return 'Canceled';
  }
}

function refundStatusBadgeClassName(status: DashboardBillingRefund['status']): string {
  const tone =
    status === 'succeeded'
      ? 'success'
      : status === 'failed' || status === 'canceled'
        ? 'danger'
        : 'warning';
  return `dashboard-data-table__badge dashboard-data-table__badge--${tone}`;
}

export interface BillingAccountViewProps {
  summaryMetrics: BillingMetric[];
  checkoutActionError: string;
  startingCheckoutPackId: DashboardBillingCreditPackId | '';
  refunds: DashboardBillingRefund[];
  refundsLoading: boolean;
  refundsError: string;
  onStartStripeCheckout: (
    request: Pick<DashboardStripeCheckoutSessionRequest, 'creditPackId'>,
  ) => void;
}

export function BillingAccountView(props: BillingAccountViewProps): React.JSX.Element {
  const {
    summaryMetrics,
    checkoutActionError,
    startingCheckoutPackId,
    refunds,
    refundsLoading,
    refundsError,
    onStartStripeCheckout,
  } = props;
  const [selectedPackId, setSelectedPackId] = React.useState<DashboardBillingCreditPackId>(
    PRESET_CREDIT_PACK_OPTIONS[0].id,
  );
  const selectedPreset = PRESET_CREDIT_PACK_OPTIONS.find((pack) => pack.id === selectedPackId);
  const buyDisabled = Boolean(startingCheckoutPackId);
  const buyLabel = startingCheckoutPackId
    ? 'Starting checkout...'
    : `Buy ${selectedPreset?.label || ''}`;

  return (
    <>
      <p className="dashboard-pagination-note">
        Billing is organization-scoped. Use prepaid balance for usage and top up credits with
        one-time checkout.
      </p>

      <BillingMetricsGrid metrics={summaryMetrics} ariaLabel="Billing account summary metrics" />

      <section className="dashboard-view__section" aria-label="Prepaid top-up actions">
        <h2>Top up credits</h2>
        <p className="dashboard-pagination-note">
          Start a one-time Stripe checkout to add prepaid balance. Settled purchases appear in
          billing documents as purchase receipts.
        </p>
        {checkoutActionError ? (
          <p className="dashboard-pagination-note">{checkoutActionError}</p>
        ) : null}
        <div
          className="dashboard-policy-toggle-grid dashboard-billing-top-up-options"
          role="group"
          aria-label="Top-up amount"
        >
          {PRESET_CREDIT_PACK_OPTIONS.map((pack) => (
            <button
              key={pack.id}
              type="button"
              aria-pressed={selectedPackId === pack.id}
              className={[
                'dashboard-policy-segment',
                selectedPackId === pack.id ? 'dashboard-policy-segment--active' : '',
              ]
                .filter(Boolean)
                .join(' ')}
              onClick={() => setSelectedPackId(pack.id)}
            >
              {pack.label}
            </button>
          ))}
        </div>
        <p className="dashboard-pagination-note">{selectedPreset?.detail}</p>
        <div className="dashboard-form-actions">
          <button
            type="button"
            className="dashboard-pagination-button dashboard-pagination-button--primary"
            onClick={() => onStartStripeCheckout({ creditPackId: selectedPackId })}
            disabled={buyDisabled}
          >
            {buyLabel}
          </button>
        </div>
      </section>

      <section className="dashboard-table-wrapper" aria-label="Refund history">
        <div className="dashboard-table-limit dashboard-billing-table__intro">
          <h2 className="dashboard-billing-table__title">Refund history</h2>
          <p className="dashboard-billing-table__description">
            Refunds requested through support appear here as Stripe processes them.
          </p>
          {refundsError ? <p className="dashboard-pagination-note">{refundsError}</p> : null}
        </div>
        {refundsLoading ? (
          <p className="dashboard-table-limit">Loading refund history...</p>
        ) : refunds.length === 0 ? (
          <p className="dashboard-table-limit">No refunds have been issued.</p>
        ) : (
          <div className="dashboard-billing-timeline">
            {refunds.map((refund) => (
              <article className="dashboard-billing-timeline__item" key={refund.id}>
                <div className="dashboard-billing-timeline__header">
                  <p className="dashboard-billing-timeline__title">
                    {formatUsdMinor(refund.amountMinor)} refund
                  </p>
                  <span className={refundStatusBadgeClassName(refund.status)}>
                    {formatRefundStatus(refund.status)}
                  </span>
                </div>
                <p className="dashboard-billing-timeline__meta">
                  {new Date(refund.createdAt).toLocaleString()} • Purchase {refund.purchaseId}
                </p>
                <p className="dashboard-pagination-note">{refund.reason}</p>
              </article>
            ))}
          </div>
        )}
      </section>
    </>
  );
}

export default BillingAccountView;
