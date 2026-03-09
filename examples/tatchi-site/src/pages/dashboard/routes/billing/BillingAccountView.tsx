import React from 'react';
import type { TopbarContextState } from '../../types';
import type {
  DashboardBillingPaymentMethod,
  DashboardBillingSubscription,
  DashboardStripeSetupIntent,
} from './consoleBillingApi';
import {
  BillingMetricsGrid,
  formatInvoiceStatusLabel,
  formatTimestamp,
  type BillingMetric,
} from './billingShared';

export interface BillingAccountViewProps {
  selectedContext: TopbarContextState;
  summaryMetrics: BillingMetric[];
  subscription: DashboardBillingSubscription | null;
  subscriptionActionError: string;
  startingCheckout: boolean;
  openingCustomerPortal: boolean;
  cancelingSubscription: boolean;
  resumingSubscription: boolean;
  canCancelSubscription: boolean;
  canResumeSubscription: boolean;
  onStartStripeCheckout: () => void;
  onOpenCustomerPortal: () => void;
  onOpenPaymentMethodPortal: () => void;
  onCancelSubscription: () => void;
  onResumeSubscription: () => void;
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
    subscription,
    subscriptionActionError,
    startingCheckout,
    openingCustomerPortal,
    cancelingSubscription,
    resumingSubscription,
    canCancelSubscription,
    canResumeSubscription,
    onStartStripeCheckout,
    onOpenCustomerPortal,
    onOpenPaymentMethodPortal,
    onCancelSubscription,
    onResumeSubscription,
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
              Billing is organization-scoped. Use this view for plan lifecycle and payment method
              administration. Invoice settlement actions live in invoice detail.
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

      <section className="dashboard-table-wrapper" aria-label="Subscription management table">
        <div className="dashboard-table-limit dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">Subscriptions</h3>
          <p className="dashboard-billing-table__description">
            Start or update plan checkout in Stripe, then manage renewals and billing profile access
            from the customer portal.
          </p>
          {subscriptionActionError ? (
            <p className="dashboard-pagination-note">{subscriptionActionError}</p>
          ) : null}
        </div>
        <div className="dashboard-view-grid dashboard-view-grid--two">
          <div className="dashboard-view-card dashboard-view-grid dashboard-billing-meta-card">
            <h2>Current subscription</h2>
            {!subscription ? (
              <p className="dashboard-pagination-note">No subscription returned for this org.</p>
            ) : (
              <dl className="dashboard-billing-meta-list">
                <div>
                  <dt>Plan</dt>
                  <dd>
                    {subscription.planName} ({subscription.planId})
                  </dd>
                </div>
                <div>
                  <dt>Status</dt>
                  <dd>{formatInvoiceStatusLabel(subscription.status)}</dd>
                </div>
                <div>
                  <dt>Cancel at period end</dt>
                  <dd>{subscription.cancelAtPeriodEnd ? 'Yes' : 'No'}</dd>
                </div>
                <div>
                  <dt>Current period</dt>
                  <dd>
                    {formatTimestamp(subscription.currentPeriodStart)} to{' '}
                    {formatTimestamp(subscription.currentPeriodEnd)}
                  </dd>
                </div>
                <div>
                  <dt>Cancel at</dt>
                  <dd>{formatTimestamp(subscription.cancelAt)}</dd>
                </div>
                <div>
                  <dt>Canceled at</dt>
                  <dd>{formatTimestamp(subscription.canceledAt)}</dd>
                </div>
                <div>
                  <dt>Customer reference</dt>
                  <dd>{subscription.providerCustomerRef || '-'}</dd>
                </div>
                <div>
                  <dt>Subscription reference</dt>
                  <dd>{subscription.providerSubscriptionRef || '-'}</dd>
                </div>
              </dl>
            )}
          </div>
          <div className="dashboard-view-card dashboard-view-grid dashboard-billing-actions-card">
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
            </div>
            <p className="dashboard-pagination-note">
              Checkout success returns to <code>/dashboard/billing/account?checkout=success</code>.
            </p>
          </div>
        </div>
      </section>

      <section className="dashboard-table-wrapper" aria-label="Payment methods table">
        <div className="dashboard-table-limit dashboard-billing-table__intro">
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
                <span className="dashboard-billing-payment-method-row__actions">
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => {
                      void onSetDefaultPaymentMethod(method.id);
                    }}
                    disabled={
                      !isBillingCardAdmin || busyPaymentMethodId === method.id || method.isDefault
                    }
                  >
                    Set default
                  </button>{' '}
                  <button
                    type="button"
                    className="dashboard-inline-link dashboard-inline-link--danger"
                    onClick={() => {
                      void onRemovePaymentMethod(method.id);
                    }}
                    disabled={!isBillingCardAdmin || busyPaymentMethodId === method.id}
                  >
                    Remove
                  </button>
                </span>
              </div>
            ))}
            <p className="dashboard-table-limit">
              Showing {paymentMethods.length} payment method{paymentMethods.length === 1 ? '' : 's'}
              .
            </p>
          </>
        )}
      </section>
    </>
  );
}

export default BillingAccountView;
