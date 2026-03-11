import React from 'react';
import type { TopbarContextState } from '../../types';
import type {
  DashboardBillingAccountActivityEntry,
  DashboardBillingCreditPackId,
  DashboardBillingManualAdjustmentKind,
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

function describeAccountActivityType(input: DashboardBillingAccountActivityEntry): string {
  if (input.type === 'MANUAL_ADJUSTMENT') {
    return input.amountMinor >= 0 ? 'Manual support credit' : 'Manual admin debit';
  }
  if (input.type === 'CREDIT_PURCHASE') return 'Credit purchase settled';
  if (input.type === 'USAGE_DEBIT') return 'Usage debit recorded';
  return input.type;
}

function describeManualAdjustmentKind(input: DashboardBillingManualAdjustmentKind): string {
  return input === 'support_credit' ? 'Manual support credit' : 'Manual admin debit';
}

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
  canManageBillingAdjustments: boolean;
  currentCreditBalanceMinor: number;
  startingAdjustmentKind: DashboardBillingManualAdjustmentKind | '';
  adjustmentActionError: string;
  adjustmentActionMessage: string;
  accountActivity: DashboardBillingAccountActivityEntry[];
  accountActivityError: string;
  onStartStripeCheckout: (
    request: Pick<DashboardStripeCheckoutSessionRequest, 'creditPackId' | 'customAmountMinor'>,
  ) => void;
  onSubmitManualAdjustment: (input: {
    kind: DashboardBillingManualAdjustmentKind;
    amountMinor: number;
    reasonCode: string;
    note: string;
    relatedInvoiceId?: string;
  }) => Promise<boolean>;
}

export function BillingAccountView(props: BillingAccountViewProps): React.JSX.Element {
  const {
    selectedContext,
    summaryMetrics,
    checkoutActionError,
    startingCheckoutPackId,
    canManageBillingAdjustments,
    currentCreditBalanceMinor,
    startingAdjustmentKind,
    adjustmentActionError,
    adjustmentActionMessage,
    accountActivity,
    accountActivityError,
    onStartStripeCheckout,
    onSubmitManualAdjustment,
  } = props;
  const [customAmountInput, setCustomAmountInput] = React.useState<string>('');
  const [adjustmentKind, setAdjustmentKind] =
    React.useState<DashboardBillingManualAdjustmentKind>('support_credit');
  const [adjustmentAmountInput, setAdjustmentAmountInput] = React.useState<string>('');
  const [adjustmentReasonCode, setAdjustmentReasonCode] = React.useState<string>('');
  const [adjustmentRelatedInvoiceId, setAdjustmentRelatedInvoiceId] = React.useState<string>('');
  const [adjustmentNote, setAdjustmentNote] = React.useState<string>('');
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
  const adjustmentAmountMinor = React.useMemo(
    () => parseUsdAmountInputToMinor(adjustmentAmountInput),
    [adjustmentAmountInput],
  );
  const isAdjustmentAmountValid = adjustmentAmountMinor != null && adjustmentAmountMinor > 0;
  const normalizedAdjustmentReasonCode = String(adjustmentReasonCode || '').trim();
  const normalizedAdjustmentRelatedInvoiceId = String(adjustmentRelatedInvoiceId || '').trim();
  const normalizedAdjustmentNote = String(adjustmentNote || '').trim();
  const adjustmentDeltaMinor = isAdjustmentAmountValid
    ? adjustmentKind === 'support_credit'
      ? adjustmentAmountMinor
      : -adjustmentAmountMinor
    : 0;
  const projectedBalanceMinor = currentCreditBalanceMinor + adjustmentDeltaMinor;
  const adjustmentDeltaLabel =
    adjustmentDeltaMinor >= 0
      ? `+${formatUsdMinor(Math.abs(adjustmentDeltaMinor))}`
      : `-${formatUsdMinor(Math.abs(adjustmentDeltaMinor))}`;
  const adjustmentPreviewLabel = isAdjustmentAmountValid
    ? `Impact preview: ${formatUsdMinor(currentCreditBalanceMinor)} -> ${formatUsdMinor(projectedBalanceMinor)} (${adjustmentDeltaLabel}).`
    : 'Enter a positive amount to preview projected balance impact.';
  const adjustmentPreviewClassName = `dashboard-form-hint dashboard-billing-adjustment-preview${projectedBalanceMinor < 0 ? ' dashboard-billing-adjustment-preview--warning' : ''}`;
  const canSubmitManualAdjustment =
    canManageBillingAdjustments &&
    isAdjustmentAmountValid &&
    Boolean(normalizedAdjustmentReasonCode) &&
    Boolean(normalizedAdjustmentNote) &&
    !startingAdjustmentKind;
  const adjustmentButtonLabel =
    startingAdjustmentKind === adjustmentKind
      ? 'Applying adjustment...'
      : adjustmentKind === 'support_credit'
        ? 'Apply support credit'
        : 'Apply admin debit';
  const onAdjustmentSubmit = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!canSubmitManualAdjustment || adjustmentAmountMinor == null) return;
      const success = await onSubmitManualAdjustment({
        kind: adjustmentKind,
        amountMinor: adjustmentAmountMinor,
        reasonCode: normalizedAdjustmentReasonCode,
        note: normalizedAdjustmentNote,
        ...(normalizedAdjustmentRelatedInvoiceId
          ? { relatedInvoiceId: normalizedAdjustmentRelatedInvoiceId }
          : {}),
      });
      if (!success) return;
      setAdjustmentAmountInput('');
      setAdjustmentReasonCode('');
      setAdjustmentRelatedInvoiceId('');
      setAdjustmentNote('');
    },
    [
      adjustmentAmountMinor,
      adjustmentKind,
      canSubmitManualAdjustment,
      normalizedAdjustmentNote,
      normalizedAdjustmentRelatedInvoiceId,
      normalizedAdjustmentReasonCode,
      onSubmitManualAdjustment,
    ],
  );

  return (
    <>
      <section
        className="dashboard-view__section dashboard-billing-overview"
        aria-label="Billing scope and actions"
      >
        <div className="dashboard-billing-overview__header">
          <div className="dashboard-billing-overview__copy">
            <h2>Billing account</h2>
            <p>
              Billing is organization-scoped. Use prepaid balance for usage and top up credits with
              one-time checkout.
            </p>
          </div>
        </div>
        <dl className="dashboard-billing-overview__context">
          <div>
            <dt>Organization</dt>
            <dd title={selectedContext.organization || '-'}>
              {selectedContext.organization || '-'}
            </dd>
          </div>
          <div>
            <dt>Project</dt>
            <dd title={selectedContext.project || '-'}>{selectedContext.project || '-'}</dd>
          </div>
          <div>
            <dt>Environment</dt>
            <dd title={selectedContext.environment || '-'}>{selectedContext.environment || '-'}</dd>
          </div>
        </dl>
      </section>

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

      {canManageBillingAdjustments ? (
        <section className="dashboard-table-wrapper" aria-label="Internal billing adjustments">
          <div className="dashboard-table-limit dashboard-billing-table__intro">
            <h3 className="dashboard-billing-table__title">Internal billing adjustments</h3>
            <p className="dashboard-billing-table__description">
              Admin-only controls. Adjustments append immutable ledger entries and must include a
              reason plus operator note.
            </p>
          </div>
          <article className="dashboard-view-card dashboard-view-grid dashboard-billing-meta-card dashboard-billing-adjustment-card">
            <form className="dashboard-billing-adjustment-form" onSubmit={onAdjustmentSubmit}>
              <div className="dashboard-billing-adjustment-grid">
                <label className="dashboard-form-field">
                  <span>Adjustment type</span>
                  <select
                    className="dashboard-input"
                    value={adjustmentKind}
                    onChange={(event) =>
                      setAdjustmentKind(
                        String(event.target.value) === 'admin_debit'
                          ? 'admin_debit'
                          : 'support_credit',
                      )
                    }
                  >
                    <option value="support_credit">Manual support credit</option>
                    <option value="admin_debit">Manual admin debit</option>
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Amount (USD)</span>
                  <input
                    className="dashboard-input"
                    type="number"
                    min="0.01"
                    step="0.01"
                    inputMode="decimal"
                    value={adjustmentAmountInput}
                    onChange={(event) => setAdjustmentAmountInput(event.target.value)}
                    placeholder="25.00"
                  />
                </label>
              </div>
              <label className="dashboard-form-field">
                <span>Reason code</span>
                <input
                  className="dashboard-input"
                  type="text"
                  value={adjustmentReasonCode}
                  onChange={(event) => setAdjustmentReasonCode(event.target.value)}
                  placeholder="incident_credit"
                />
              </label>
              <label className="dashboard-form-field">
                <span>Related document ID (optional)</span>
                <input
                  className="dashboard-input"
                  type="text"
                  value={adjustmentRelatedInvoiceId}
                  onChange={(event) => setAdjustmentRelatedInvoiceId(event.target.value)}
                  placeholder="receipt_bcp_xxx or inv_202603_001"
                />
              </label>
              <label className="dashboard-form-field">
                <span>Operator note</span>
                <textarea
                  className="dashboard-input dashboard-textarea"
                  value={adjustmentNote}
                  onChange={(event) => setAdjustmentNote(event.target.value)}
                  placeholder="Describe why this adjustment is required."
                />
              </label>
              <p className={adjustmentPreviewClassName}>{adjustmentPreviewLabel}</p>
              <p className="dashboard-form-hint">
                Selected action: {describeManualAdjustmentKind(adjustmentKind)}.
              </p>
              <p className="dashboard-form-hint">
                Link a document ID to surface this adjustment on that document timeline.
              </p>
              {adjustmentActionMessage ? (
                <p className="dashboard-info-banner">{adjustmentActionMessage}</p>
              ) : null}
              {adjustmentActionError ? (
                <p className="dashboard-form-alert">{adjustmentActionError}</p>
              ) : null}
              <div className="dashboard-form-actions">
                <button
                  type="submit"
                  className="dashboard-pagination-button"
                  disabled={!canSubmitManualAdjustment}
                >
                  {adjustmentButtonLabel}
                </button>
              </div>
            </form>
          </article>
        </section>
      ) : null}

      <section className="dashboard-table-wrapper" aria-label="Billing account activity">
        <div className="dashboard-table-limit dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">Account activity</h3>
          <p className="dashboard-billing-table__description">
            Review the latest ledger events, including manual support credits and manual admin
            debits.
          </p>
        </div>
        {accountActivityError ? (
          <p className="dashboard-table-limit">{accountActivityError}</p>
        ) : accountActivity.length === 0 ? (
          <p className="dashboard-table-limit">No billing activity has been recorded yet.</p>
        ) : (
          <table className="dashboard-table">
            <thead>
              <tr>
                <th scope="col">When (UTC)</th>
                <th scope="col">Type</th>
                <th scope="col">Amount</th>
                <th scope="col">Document</th>
                <th scope="col">Reason</th>
                <th scope="col">Summary</th>
              </tr>
            </thead>
            <tbody>
              {accountActivity.map((entry) => (
                <tr key={entry.id}>
                  <td>{entry.createdAt || '-'}</td>
                  <td>{describeAccountActivityType(entry)}</td>
                  <td>{formatUsdMinor(entry.amountMinor)}</td>
                  <td>{entry.relatedInvoiceId || '-'}</td>
                  <td>{entry.reasonCode || '-'}</td>
                  <td>{entry.note || entry.description || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}

export default BillingAccountView;
