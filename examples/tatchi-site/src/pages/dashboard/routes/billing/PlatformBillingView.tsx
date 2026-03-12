import React from 'react';
import type { TopbarContextState } from '../../types';
import type {
  DashboardBillingAccountActivityEntry,
  DashboardBillingManualAdjustmentKind,
} from './consoleBillingApi';
import { formatUsdMinor } from './consoleBillingApi';
import { BillingMetricsGrid, type BillingMetric } from './billingShared';
import {
  BillingAccountActivitySection,
  BillingContextSummarySection,
} from './billingSections';

function parseUsdAmountInputToMinor(input: string): number | null {
  const normalized = String(input || '').trim();
  if (!normalized) return null;
  if (!/^\d+(?:\.\d{0,2})?$/.test(normalized)) return null;
  const [whole, fraction = ''] = normalized.split('.');
  return Number.parseInt(whole, 10) * 100 + Number.parseInt(fraction.padEnd(2, '0'), 10);
}

function describeManualAdjustmentKind(input: DashboardBillingManualAdjustmentKind): string {
  return input === 'support_credit' ? 'Manual support credit' : 'Manual admin debit';
}

export interface PlatformBillingViewProps {
  selectedContext: TopbarContextState;
  summaryMetrics: BillingMetric[];
  currentCreditBalanceMinor: number;
  startingAdjustmentKind: DashboardBillingManualAdjustmentKind | '';
  adjustmentActionError: string;
  adjustmentActionMessage: string;
  accountActivity: DashboardBillingAccountActivityEntry[];
  accountActivityError: string;
  onSubmitManualAdjustment: (input: {
    kind: DashboardBillingManualAdjustmentKind;
    amountMinor: number;
    reasonCode: string;
    note: string;
    relatedInvoiceId?: string;
  }) => Promise<boolean>;
}

export function PlatformBillingView(props: PlatformBillingViewProps): React.JSX.Element {
  const {
    selectedContext,
    summaryMetrics,
    currentCreditBalanceMinor,
    startingAdjustmentKind,
    adjustmentActionError,
    adjustmentActionMessage,
    accountActivity,
    accountActivityError,
    onSubmitManualAdjustment,
  } = props;
  const [adjustmentKind, setAdjustmentKind] =
    React.useState<DashboardBillingManualAdjustmentKind>('support_credit');
  const [adjustmentAmountInput, setAdjustmentAmountInput] = React.useState<string>('');
  const [adjustmentReasonCode, setAdjustmentReasonCode] = React.useState<string>('');
  const [adjustmentRelatedInvoiceId, setAdjustmentRelatedInvoiceId] = React.useState<string>('');
  const [adjustmentNote, setAdjustmentNote] = React.useState<string>('');
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
      <BillingContextSummarySection
        selectedContext={selectedContext}
        title="Platform billing"
        description="Platform admins can append internal prepaid-balance adjustments for the active organization."
        ariaLabel="Platform billing scope and actions"
      />

      <BillingMetricsGrid metrics={summaryMetrics} ariaLabel="Platform billing summary metrics" />

      <section className="dashboard-table-wrapper" aria-label="Internal billing adjustments">
        <div className="dashboard-table-limit dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">Internal billing adjustments</h3>
          <p className="dashboard-billing-table__description">
            Platform-admin controls. Adjustments append immutable ledger entries and must include a
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

      <BillingAccountActivitySection
        accountActivity={accountActivity}
        accountActivityError={accountActivityError}
        description="Review the latest ledger events, including manual support credits and manual admin debits."
      />
    </>
  );
}

export default PlatformBillingView;
