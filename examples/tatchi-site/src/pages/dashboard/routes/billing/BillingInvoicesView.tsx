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
  invoiceDocumentTypeFilter: string;
  setInvoiceDocumentTypeFilter: React.Dispatch<React.SetStateAction<string>>;
  invoicePeriodFilter: string;
  setInvoicePeriodFilter: React.Dispatch<React.SetStateAction<string>>;
  invoices: DashboardBillingInvoice[];
  totalInvoices: number;
  downloadingInvoicePdfId: string;
  invoiceDownloadError: string;
  onOpenInvoice: (invoiceId: string) => void;
  onDownloadInvoicePdf: (invoiceId: string) => Promise<void>;
}

const BILLING_INVOICES_TABLE_COLUMNS = dashboardTableColumns(
  1.05,
  0.8,
  0.8,
  0.75,
  0.9,
  0.8,
  0.75,
  0.75,
  1,
);

export function BillingInvoicesView(props: BillingInvoicesViewProps): React.JSX.Element {
  const {
    invoiceMetrics,
    invoiceListLoading,
    invoiceListError,
    invoiceStatusFilter,
    setInvoiceStatusFilter,
    invoiceDocumentTypeFilter,
    setInvoiceDocumentTypeFilter,
    invoicePeriodFilter,
    setInvoicePeriodFilter,
    invoices,
    totalInvoices,
    downloadingInvoicePdfId,
    invoiceDownloadError,
    onOpenInvoice,
    onDownloadInvoicePdf,
  } = props;
  const invoicesPagination = useDashboardTablePagination(invoices, {
    disabled: invoiceListLoading,
    itemLabel: 'document',
    itemLabelPlural: 'documents',
  });

  return (
    <>
      <section
        className="dashboard-view__section dashboard-billing-overview"
        aria-label="Invoice history overview"
      >
        <div className="dashboard-billing-overview__header">
          <div className="dashboard-billing-overview__copy">
            <h2>Invoice history</h2>
            <p>
              Review prepaid purchase receipts and usage statements, open document detail, and
              download PDF exports for finance workflows.
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
          <p>Filter history by document type, status, or billing period month.</p>
        </div>
        <div className="dashboard-billing-filters__controls">
          <label className="dashboard-form-field">
            <span>Document type</span>
            <select
              className="dashboard-input"
              value={invoiceDocumentTypeFilter}
              onChange={(event) => setInvoiceDocumentTypeFilter(event.target.value)}
            >
              <option value="all">All documents</option>
              <option value="PURCHASE_RECEIPT">Purchase receipts</option>
              <option value="USAGE_STATEMENT">Usage statements</option>
            </select>
          </label>
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

      <DashboardTable
        ariaLabel="Invoices table"
        columns={BILLING_INVOICES_TABLE_COLUMNS}
        pagination={invoicesPagination.pagination}
      >
        <DashboardTableIntro className="dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">Receipts and statements</h3>
          <p className="dashboard-billing-table__description">
            Open any document to review line items, ledger activity, and export actions.
          </p>
          {invoiceDownloadError ? (
            <p className="dashboard-pagination-note">{invoiceDownloadError}</p>
          ) : invoiceListError ? (
            <p className="dashboard-pagination-note">{invoiceListError}</p>
          ) : null}
        </DashboardTableIntro>
        <DashboardTableHeader>
          <DashboardTableHeaderCell>Document ID</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Type</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Period</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Created</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Amount</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Paid</DashboardTableHeaderCell>
          <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
        </DashboardTableHeader>
        {invoiceListLoading ? (
          <DashboardTableState>Loading invoices...</DashboardTableState>
        ) : invoices.length === 0 ? (
          <DashboardTableState>
            {totalInvoices === 0
              ? 'No billing documents yet.'
              : 'No documents match the current filters.'}
          </DashboardTableState>
        ) : (
          <>
            {invoicesPagination.rows.map((invoice) => (
              <DashboardTableRow key={invoice.id}>
                <DashboardTableCell title={invoice.id}>{invoice.id}</DashboardTableCell>
                <DashboardTableCell>
                  {invoice.documentType === 'PURCHASE_RECEIPT' ? 'Receipt' : 'Statement'}
                </DashboardTableCell>
                <DashboardTableCell>
                  <span className={getInvoiceStatusBadgeClassName(invoice.status)}>
                    {formatInvoiceStatusLabel(invoice.status)}
                  </span>
                </DashboardTableCell>
                <DashboardTableCell>{invoice.periodMonthUtc || '-'}</DashboardTableCell>
                <DashboardTableCell truncate>
                  {formatTimestamp(invoice.createdAt)}
                </DashboardTableCell>
                <DashboardTableCell>{formatUsdMinor(invoice.amountDueMinor)}</DashboardTableCell>
                <DashboardTableCell>{formatUsdMinor(invoice.amountPaidMinor)}</DashboardTableCell>
                <DashboardTableCell>
                  <DashboardTableActionGroup>
                    <DashboardTableActionButton onClick={() => onOpenInvoice(invoice.id)}>
                      View document
                    </DashboardTableActionButton>
                    <DashboardTableActionButton
                      onClick={() => {
                        void onDownloadInvoicePdf(invoice.id);
                      }}
                      disabled={downloadingInvoicePdfId === invoice.id}
                    >
                      {downloadingInvoicePdfId === invoice.id ? 'Downloading...' : 'Download PDF'}
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

export default BillingInvoicesView;
