import React from 'react';
import type { TopbarContextState } from '../../types';
import type {
  DashboardBillingCreditPackId,
  DashboardStripeCheckoutSessionRequest,
} from './consoleBillingApi';
import { formatUsdMinor } from './consoleBillingApi';
import { BillingMetricsGrid, type BillingMetric } from './billingShared';
import { BillingContextSummarySection } from './billingSections';

const PRESET_CREDIT_PACK_OPTIONS = [
  { id: 'usd_10', label: '$10', detail: 'Quick prepaid top-up for test traffic.' },
  { id: 'usd_25', label: '$25', detail: 'Starter prepaid balance for light production.' },
  { id: 'usd_50', label: '$50', detail: 'Larger one-time top-up for ongoing usage.' },
] as const;
const CUSTOM_CREDIT_PACK_ID = 'usd_custom' as const satisfies DashboardBillingCreditPackId;
const MIN_CUSTOM_CREDIT_PACK_AMOUNT_MINOR = 1000;

function parseUsdAmountInputToMinor(input: string): number | null {
  const normalized = String(input || '').trim();
  if (!normalized) return null;
  if (!/^\d+(?:\.\d{0,2})?$/.test(normalized)) return null;
  const [whole, fraction = ''] = normalized.split('.');
  return Number.parseInt(whole, 10) * 100 + Number.parseInt(fraction.padEnd(2, '0'), 10);
}

export interface BillingAccountViewProps {
  selectedContext: TopbarContextState;
  summaryMetrics: BillingMetric[];
  checkoutActionError: string;
  startingCheckoutPackId: DashboardBillingCreditPackId | '';
  onStartStripeCheckout: (
    request: Pick<DashboardStripeCheckoutSessionRequest, 'creditPackId' | 'customAmountMinor'>,
  ) => void;
}

export function BillingAccountView(props: BillingAccountViewProps): React.JSX.Element {
  const {
    selectedContext,
    summaryMetrics,
    checkoutActionError,
    startingCheckoutPackId,
    onStartStripeCheckout,
  } = props;
  const [customAmountInput, setCustomAmountInput] = React.useState<string>('');
  const customAmountMinor = React.useMemo(
    () => parseUsdAmountInputToMinor(customAmountInput),
    [customAmountInput],
  );
  const isCustomAmountValid =
    customAmountMinor != null && customAmountMinor >= MIN_CUSTOM_CREDIT_PACK_AMOUNT_MINOR;
  const customAmountHint = React.useMemo(() => {
    const normalizedInput = String(customAmountInput || '').trim();
    if (!normalizedInput) {
      return `Choose any one-time amount from ${formatUsdMinor(MIN_CUSTOM_CREDIT_PACK_AMOUNT_MINOR)} and up.`;
    }
    if (customAmountMinor == null) {
      return 'Use a USD amount with up to 2 decimal places.';
    }
    if (!isCustomAmountValid) {
      return `Minimum custom top-up is ${formatUsdMinor(MIN_CUSTOM_CREDIT_PACK_AMOUNT_MINOR)}.`;
    }
    return `Checkout will start for ${formatUsdMinor(customAmountMinor)}.`;
  }, [customAmountInput, customAmountMinor, isCustomAmountValid]);
  const customAmountHintClassName = `dashboard-form-hint${String(customAmountInput || '').trim() && !isCustomAmountValid ? ' dashboard-form-hint--error' : ''}`;
  const customAmountButtonLabel =
    isCustomAmountValid && customAmountMinor != null
      ? `Buy ${formatUsdMinor(customAmountMinor)}`
      : 'Buy custom amount';

  return (
    <>
      <BillingContextSummarySection
        selectedContext={selectedContext}
        title="Billing account"
        description="Billing is organization-scoped. Use prepaid balance for usage and top up credits with one-time checkout."
        ariaLabel="Billing scope and actions"
      />

      <BillingMetricsGrid metrics={summaryMetrics} ariaLabel="Billing account summary metrics" />

      <section className="dashboard-table-wrapper" aria-label="Prepaid top-up actions">
        <div className="dashboard-table-limit dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">Top up credits</h3>
          <p className="dashboard-billing-table__description">
            Start a one-time Stripe checkout to add prepaid balance. Settled purchases appear in
            billing documents as purchase receipts.
          </p>
          {checkoutActionError ? (
            <p className="dashboard-pagination-note">{checkoutActionError}</p>
          ) : null}
        </div>
        <div className="dashboard-billing-top-up-grid">
          <div className="dashboard-billing-top-up-presets">
            {PRESET_CREDIT_PACK_OPTIONS.map((pack) => (
              <article
                className="dashboard-view-card dashboard-view-grid dashboard-billing-meta-card dashboard-billing-top-up-card"
                key={pack.id}
              >
                <h2>{pack.label}</h2>
                <p className="dashboard-pagination-note">{pack.detail}</p>
                <div className="dashboard-form-actions">
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={() => onStartStripeCheckout({ creditPackId: pack.id })}
                    disabled={startingCheckoutPackId === pack.id}
                  >
                    {startingCheckoutPackId === pack.id
                      ? 'Starting checkout...'
                      : `Buy ${pack.label}`}
                  </button>
                </div>
              </article>
            ))}
          </div>
          <article className="dashboard-view-card dashboard-view-grid dashboard-billing-meta-card dashboard-billing-top-up-card dashboard-billing-top-up-card--custom">
            <h2>Custom</h2>
            <p className="dashboard-pagination-note">
              Choose any prepaid balance top-up starting at $10.00.
            </p>
            <label className="dashboard-form-field">
              <span>Amount (USD)</span>
              <input
                className="dashboard-input"
                type="number"
                min="10"
                step="0.01"
                inputMode="decimal"
                placeholder="100.00"
                value={customAmountInput}
                onChange={(event) => setCustomAmountInput(event.target.value)}
              />
            </label>
            <p className={customAmountHintClassName}>{customAmountHint}</p>
            <div className="dashboard-form-actions">
              <button
                type="button"
                className="dashboard-pagination-button"
                onClick={() =>
                  onStartStripeCheckout({
                    creditPackId: CUSTOM_CREDIT_PACK_ID,
                    ...(customAmountMinor == null ? {} : { customAmountMinor }),
                  })
                }
                disabled={!isCustomAmountValid || startingCheckoutPackId === CUSTOM_CREDIT_PACK_ID}
              >
                {startingCheckoutPackId === CUSTOM_CREDIT_PACK_ID
                  ? 'Starting checkout...'
                  : customAmountButtonLabel}
              </button>
            </div>
          </article>
        </div>
      </section>
    </>
  );
}

export default BillingAccountView;
