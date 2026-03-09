import React from 'react';
import { formatUsdMinor, type DashboardBillingInvoice } from './consoleBillingApi';
import {
  BillingMetricsGrid,
  formatTimestamp,
  formatInvoiceStatusLabel,
  getInvoiceStatusBadgeClassName,
  type BillingMetric,
} from './billingShared';

export interface BillingInvoicesViewProps {
  invoiceMetrics: BillingMetric[];
  invoiceListLoading: boolean;
  invoiceListError: string;
  invoiceStatusFilter: string;
  setInvoiceStatusFilter: React.Dispatch<React.SetStateAction<string>>;
  invoicePeriodFilter: string;
  setInvoicePeriodFilter: React.Dispatch<React.SetStateAction<string>>;
  invoices: DashboardBillingInvoice[];
  totalInvoices: number;
  hasMoreInvoices: boolean;
  loadingMoreInvoices: boolean;
  downloadingInvoicePdfId: string;
  invoiceDownloadError: string;
  onOpenInvoice: (invoiceId: string) => void;
  onLoadMoreInvoices: () => void;
  onDownloadInvoicePdf: (invoiceId: string) => Promise<void>;
}

export function BillingInvoicesView(props: BillingInvoicesViewProps): React.JSX.Element {
  const {
    invoiceMetrics,
    invoiceListLoading,
    invoiceListError,
    invoiceStatusFilter,
    setInvoiceStatusFilter,
    invoicePeriodFilter,
    setInvoicePeriodFilter,
    invoices,
    totalInvoices,
    hasMoreInvoices,
    loadingMoreInvoices,
    downloadingInvoicePdfId,
    invoiceDownloadError,
    onOpenInvoice,
    onLoadMoreInvoices,
    onDownloadInvoicePdf,
  } = props;

  return (
    <>
      <section
        className="dashboard-view__section dashboard-billing-overview"
        aria-label="Invoice history overview"
      >
        <div className="dashboard-billing-overview__header">
          <div className="dashboard-billing-overview__copy">
            <h2>Bill history</h2>
            <p>
              Review invoice states, open details for settlement actions, and download PDF exports
              for finance workflows.
            </p>
          </div>
        </div>
      </section>

      <BillingMetricsGrid metrics={invoiceMetrics} ariaLabel="Invoice summary metrics" />

      <section
        className="dashboard-view__section dashboard-billing-filters"
        aria-label="Invoice filters"
      >
        <div className="dashboard-billing-filters__copy">
          <h2>Filters</h2>
          <p>Filter bill history by status or billing period month.</p>
        </div>
        <div className="dashboard-billing-filters__controls">
          <label className="dashboard-form-field">
            <span>Status</span>
            <select
              className="dashboard-input"
              value={invoiceStatusFilter}
              onChange={(event) => setInvoiceStatusFilter(event.target.value)}
            >
              <option value="all">All statuses</option>
              <option value="open">Open</option>
              <option value="overdue">Overdue</option>
              <option value="paid">Paid</option>
              <option value="void">Void</option>
              <option value="uncollectible">Uncollectible</option>
            </select>
          </label>
          <label className="dashboard-form-field">
            <span>Billing period</span>
            <input
              className="dashboard-input"
              type="month"
              value={invoicePeriodFilter}
              onChange={(event) => setInvoicePeriodFilter(event.target.value)}
            />
          </label>
        </div>
      </section>

      <section className="dashboard-table-wrapper" aria-label="Invoices table">
        <div className="dashboard-table-limit dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">Invoices</h3>
          <p className="dashboard-billing-table__description">
            Open any invoice to view line items, payment execution, and export actions.
          </p>
          {invoiceDownloadError ? (
            <p className="dashboard-pagination-note">{invoiceDownloadError}</p>
          ) : invoiceListError ? (
            <p className="dashboard-pagination-note">{invoiceListError}</p>
          ) : null}
        </div>
        <div className="dashboard-table-header dashboard-billing-table--invoices" role="row">
          <span>Invoice ID</span>
          <span>Status</span>
          <span>Period</span>
          <span>Created</span>
          <span>Due</span>
          <span>Rail lock</span>
          <span>Amount due</span>
          <span>Amount paid</span>
          <span>Actions</span>
        </div>
        {invoiceListLoading ? (
          <p className="dashboard-table-limit">Loading invoices...</p>
        ) : invoices.length === 0 ? (
          <p className="dashboard-table-limit">
            {totalInvoices === 0 ? 'No invoices yet.' : 'No invoices match the current filters.'}
          </p>
        ) : (
          <>
            {invoices.map((invoice) => (
              <div
                className="dashboard-table-row dashboard-billing-table--invoices"
                key={invoice.id}
                role="row"
              >
                <span title={invoice.id}>{invoice.id}</span>
                <span>
                  <span className={getInvoiceStatusBadgeClassName(invoice.status)}>
                    {formatInvoiceStatusLabel(invoice.status)}
                  </span>
                </span>
                <span>{invoice.periodMonthUtc || '-'}</span>
                <span>{formatTimestamp(invoice.createdAt)}</span>
                <span>{formatTimestamp(invoice.dueAt)}</span>
                <span>{invoice.railLock || '-'}</span>
                <span>{formatUsdMinor(invoice.amountDueMinor)}</span>
                <span>{formatUsdMinor(invoice.amountPaidMinor)}</span>
                <span className="dashboard-billing-table__actions">
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => onOpenInvoice(invoice.id)}
                  >
                    View invoice
                  </button>
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => {
                      void onDownloadInvoicePdf(invoice.id);
                    }}
                    disabled={downloadingInvoicePdfId === invoice.id}
                  >
                    {downloadingInvoicePdfId === invoice.id ? 'Downloading...' : 'Download PDF'}
                  </button>
                </span>
              </div>
            ))}
            <p className="dashboard-table-limit">
              Showing {invoices.length} invoice{invoices.length === 1 ? '' : 's'} of {totalInvoices}
              .
            </p>
            {hasMoreInvoices ? (
              <div className="dashboard-table-limit dashboard-billing-pagination">
                <button
                  type="button"
                  className="dashboard-pagination-button"
                  onClick={onLoadMoreInvoices}
                  disabled={loadingMoreInvoices}
                >
                  {loadingMoreInvoices ? 'Loading more...' : 'Load more invoices'}
                </button>
              </div>
            ) : null}
          </>
        )}
      </section>
    </>
  );
}

export default BillingInvoicesView;
