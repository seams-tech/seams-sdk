import React from 'react';
import type { TopbarContextState } from '../../types';
import type { DashboardBillingAccountActivityEntry } from './consoleBillingApi';
import { formatUsdMinor } from './consoleBillingApi';

export function describeAccountActivityType(input: DashboardBillingAccountActivityEntry): string {
  if (input.type === 'MANUAL_ADJUSTMENT') {
    return input.amountMinor >= 0 ? 'Manual support credit' : 'Manual admin debit';
  }
  if (input.type === 'CREDIT_PURCHASE') return 'Credit purchase settled';
  if (input.type === 'USAGE_DEBIT') return 'Usage debit recorded';
  return input.type;
}

export function BillingContextSummarySection(props: {
  selectedContext: TopbarContextState;
  title: string;
  description: string;
  ariaLabel: string;
}): React.JSX.Element {
  const { selectedContext, title, description, ariaLabel } = props;
  return (
    <section className="dashboard-view__section dashboard-billing-overview" aria-label={ariaLabel}>
      <div className="dashboard-billing-overview__header">
        <div className="dashboard-billing-overview__copy">
          <h2>{title}</h2>
          <p>{description}</p>
        </div>
      </div>
      <dl className="dashboard-billing-overview__context">
        <div>
          <dt>Organization</dt>
          <dd title={selectedContext.organization || '-'}>{selectedContext.organization || '-'}</dd>
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
  );
}

export function BillingAccountActivitySection(props: {
  accountActivity: DashboardBillingAccountActivityEntry[];
  accountActivityError: string;
  description: string;
}): React.JSX.Element {
  const { accountActivity, accountActivityError, description } = props;
  return (
    <section className="dashboard-table-wrapper" aria-label="Billing account activity">
      <div className="dashboard-table-limit dashboard-billing-table__intro">
        <h3 className="dashboard-billing-table__title">Account activity</h3>
        <p className="dashboard-billing-table__description">{description}</p>
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
  );
}
