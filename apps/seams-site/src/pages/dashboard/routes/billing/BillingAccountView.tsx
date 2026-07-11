import React from 'react';
import type { TopbarContextState } from '../../types';
import type {
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
  const { summaryMetrics, checkoutActionError, startingCheckoutPackId, onStartStripeCheckout } =
    props;
  const [selectedPackId, setSelectedPackId] = React.useState<DashboardBillingCreditPackId>(
    PRESET_CREDIT_PACK_OPTIONS[0].id,
  );
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

  const selectedPreset = PRESET_CREDIT_PACK_OPTIONS.find((pack) => pack.id === selectedPackId);
  const isCustomSelected = selectedPackId === CUSTOM_CREDIT_PACK_ID;
  const buyDisabled =
    Boolean(startingCheckoutPackId) || (isCustomSelected && !isCustomAmountValid);
  const buyLabel = startingCheckoutPackId
    ? 'Starting checkout...'
    : isCustomSelected
      ? customAmountButtonLabel
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
          <button
            type="button"
            aria-pressed={isCustomSelected}
            className={[
              'dashboard-policy-segment',
              isCustomSelected ? 'dashboard-policy-segment--active' : '',
            ]
              .filter(Boolean)
              .join(' ')}
            onClick={() => setSelectedPackId(CUSTOM_CREDIT_PACK_ID)}
          >
            Custom
          </button>
        </div>
        {isCustomSelected ? (
          <>
            <label className="dashboard-form-field dashboard-billing-top-up-custom">
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
          </>
        ) : (
          <p className="dashboard-pagination-note">{selectedPreset?.detail}</p>
        )}
        <div className="dashboard-form-actions">
          <button
            type="button"
            className="dashboard-pagination-button dashboard-pagination-button--primary"
            onClick={() =>
              onStartStripeCheckout(
                isCustomSelected
                  ? {
                      creditPackId: CUSTOM_CREDIT_PACK_ID,
                      ...(customAmountMinor == null ? {} : { customAmountMinor }),
                    }
                  : { creditPackId: selectedPackId },
              )
            }
            disabled={buyDisabled}
          >
            {buyLabel}
          </button>
        </div>
      </section>
    </>
  );
}

export default BillingAccountView;
