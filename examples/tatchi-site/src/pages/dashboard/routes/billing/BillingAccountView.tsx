import React from 'react';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableIntro,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import type { TopbarContextState } from '../../types';
import type {
  DashboardBillingPaymentMethod,
  DashboardStripeSetupIntent,
} from './consoleBillingApi';
import { BillingMetricsGrid, formatTimestamp, type BillingMetric } from './billingShared';

const CREDIT_PACK_OPTIONS = [
  { id: 'usd_50', label: '$50', detail: 'Small prepaid top-up' },
  { id: 'usd_200', label: '$200', detail: 'Starter production balance' },
  { id: 'usd_500', label: '$500', detail: 'Growth top-up' },
  { id: 'usd_1000', label: '$1,000', detail: 'High-volume prepaid balance' },
] as const;
const BILLING_PAYMENT_METHODS_TABLE_COLUMNS = dashboardTableColumns(
  1.05,
  0.85,
  0.75,
  0.75,
  0.65,
  0.7,
  0.65,
  1.1,
);

export interface BillingAccountViewProps {
  selectedContext: TopbarContextState;
  summaryMetrics: BillingMetric[];
  checkoutActionError: string;
  startingCheckoutPackId: string;
  openingCustomerPortal: boolean;
  onStartStripeCheckout: (creditPackId: (typeof CREDIT_PACK_OPTIONS)[number]['id']) => void;
  onOpenPaymentMethodPortal: () => void;
  providerRefInput: string;
  setProviderRefInput: React.Dispatch<React.SetStateAction<string>>;
  brandInput: string;
  setBrandInput: React.Dispatch<React.SetStateAction<string>>;
  last4Input: string;
  setLast4Input: React.Dispatch<React.SetStateAction<string>>;
  expMonthInput: string;
  setExpMonthInput: React.Dispatch<React.SetStateAction<string>>;
  expYearInput: string;
  setExpYearInput: React.Dispatch<React.SetStateAction<string>>;
  isBillingCardAdmin: boolean;
  addingPaymentMethod: boolean;
  creatingPaymentMethodSetupIntent: boolean;
  paymentMutationError: string;
  paymentMethodSetupIntent: DashboardStripeSetupIntent | null;
  paymentMethods: DashboardBillingPaymentMethod[];
  busyPaymentMethodId: string;
  onAddCardPaymentMethod: (event: React.FormEvent<HTMLFormElement>) => Promise<void>;
  onCreatePaymentMethodSetupIntent: () => void;
  onSetDefaultPaymentMethod: (paymentMethodId: string) => Promise<void>;
  onRemovePaymentMethod: (paymentMethodId: string) => Promise<void>;
}

export function BillingAccountView(props: BillingAccountViewProps): React.JSX.Element {
  const {
    selectedContext,
    summaryMetrics,
    checkoutActionError,
    startingCheckoutPackId,
    openingCustomerPortal,
    onStartStripeCheckout,
    onOpenPaymentMethodPortal,
    providerRefInput,
    setProviderRefInput,
    brandInput,
    setBrandInput,
    last4Input,
    setLast4Input,
    expMonthInput,
    setExpMonthInput,
    expYearInput,
    setExpYearInput,
    isBillingCardAdmin,
    addingPaymentMethod,
    creatingPaymentMethodSetupIntent,
    paymentMutationError,
    paymentMethodSetupIntent,
    paymentMethods,
    busyPaymentMethodId,
    onAddCardPaymentMethod,
    onCreatePaymentMethodSetupIntent,
    onSetDefaultPaymentMethod,
    onRemovePaymentMethod,
  } = props;
  const paymentMethodsPagination = useDashboardTablePagination(paymentMethods, {
    itemLabel: 'payment method',
    itemLabelPlural: 'payment methods',
  });

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
              Billing is organization-scoped. Use prepaid balance for usage, top up credits with
              one-time checkout, and manage saved payment methods here.
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
            invoice history as receipts.
          </p>
          {checkoutActionError ? (
            <p className="dashboard-pagination-note">{checkoutActionError}</p>
          ) : null}
        </div>
        <div className="dashboard-view-grid dashboard-view-grid--two">
          {CREDIT_PACK_OPTIONS.map((pack) => (
            <article
              className="dashboard-view-card dashboard-view-grid dashboard-billing-meta-card"
              key={pack.id}
            >
              <h2>{pack.label}</h2>
              <p className="dashboard-pagination-note">{pack.detail}</p>
              <div className="dashboard-form-actions">
                <button
                  type="button"
                  className="dashboard-pagination-button"
                  onClick={() => onStartStripeCheckout(pack.id)}
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
      </section>

      <DashboardTable
        ariaLabel="Payment methods table"
        columns={BILLING_PAYMENT_METHODS_TABLE_COLUMNS}
        pagination={paymentMethodsPagination.pagination}
      >
        <DashboardTableIntro className="dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">Payment methods</h3>
          <p className="dashboard-billing-table__description">
            Use Stripe-managed flows for real card replacement and billing profile updates. The
            manual add form remains available for direct console testing and operator backfills.
          </p>
          <div className="dashboard-form-actions dashboard-billing-payment-method-actions">
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={onCreatePaymentMethodSetupIntent}
              disabled={creatingPaymentMethodSetupIntent}
            >
              {creatingPaymentMethodSetupIntent
                ? 'Creating setup intent...'
                : 'Start Stripe card replacement'}
            </button>
            <button
              type="button"
              className="dashboard-pagination-button dashboard-pagination-button--secondary"
              onClick={onOpenPaymentMethodPortal}
              disabled={openingCustomerPortal}
            >
              {openingCustomerPortal ? 'Opening portal...' : 'Update billing profile in portal'}
            </button>
          </div>
          <p className="dashboard-pagination-note">
            Latest setup intent:{' '}
            {paymentMethodSetupIntent
              ? `${paymentMethodSetupIntent.id} (expires ${formatTimestamp(paymentMethodSetupIntent.expiresAt)})`
              : '-'}
          </p>
          <form
            className="dashboard-view-grid dashboard-view-grid--two"
            onSubmit={(event) => {
              void onAddCardPaymentMethod(event);
            }}
          >
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
        </DashboardTableIntro>
        <DashboardTableHeader>
          <DashboardTableHeaderCell>Method ID</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Provider</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Type</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Brand</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Last4</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Expiry</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Default</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
        </DashboardTableHeader>
        {paymentMethods.length === 0 ? (
          <DashboardTableState>No card payment methods on file.</DashboardTableState>
        ) : (
          <>
            {paymentMethodsPagination.rows.map((method) => (
              <DashboardTableRow key={method.id}>
                <DashboardTableCell title={method.id}>{method.id}</DashboardTableCell>
                <DashboardTableCell>{method.provider || '-'}</DashboardTableCell>
                <DashboardTableCell>{method.type || '-'}</DashboardTableCell>
                <DashboardTableCell>{method.brand || '-'}</DashboardTableCell>
                <DashboardTableCell>{method.last4 || '-'}</DashboardTableCell>
                <DashboardTableCell>
                  {method.expMonth > 0 && method.expYear > 0
                    ? `${String(method.expMonth).padStart(2, '0')}/${method.expYear}`
                    : '-'}
                </DashboardTableCell>
                <DashboardTableCell>{method.isDefault ? 'Yes' : 'No'}</DashboardTableCell>
                <DashboardTableCell>
                  <DashboardTableActionGroup>
                    <DashboardTableActionButton
                      onClick={() => {
                        void onSetDefaultPaymentMethod(method.id);
                      }}
                      disabled={
                        busyPaymentMethodId === method.id || method.isDefault || !isBillingCardAdmin
                      }
                    >
                      {busyPaymentMethodId === method.id && !method.isDefault
                        ? 'Updating...'
                        : method.isDefault
                          ? 'Default'
                          : 'Set default'}
                    </DashboardTableActionButton>
                    <DashboardTableActionButton
                      tone="danger"
                      onClick={() => {
                        void onRemovePaymentMethod(method.id);
                      }}
                      disabled={busyPaymentMethodId === method.id || !isBillingCardAdmin}
                    >
                      {busyPaymentMethodId === method.id ? 'Removing...' : 'Remove'}
                    </DashboardTableActionButton>
                  </DashboardTableActionGroup>
                </DashboardTableCell>
              </DashboardTableRow>
            ))}
          </>
        )}
      </DashboardTable>
    </>
  );
}

export default BillingAccountView;
