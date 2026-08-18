import React from 'react';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
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
  invoicePeriodStartDateFilter: string;
  setInvoicePeriodStartDateFilter: React.Dispatch<React.SetStateAction<string>>;
  invoicePeriodEndDateFilter: string;
  setInvoicePeriodEndDateFilter: React.Dispatch<React.SetStateAction<string>>;
  invoices: DashboardBillingInvoice[];
  hasAnyInvoices: boolean;
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
    invoicePeriodStartDateFilter,
    setInvoicePeriodStartDateFilter,
    invoicePeriodEndDateFilter,
    setInvoicePeriodEndDateFilter,
    invoices,
    hasAnyInvoices,
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
      <BillingMetricsGrid metrics={invoiceMetrics} ariaLabel="Billing document summary metrics" />

      <section className="dashboard-view__section dashboard-billing-filters-panel">
        <div className="dashboard-billing-table__intro">
          <h3 className="dashboard-billing-table__title">Receipts and statements</h3>
          <div
            className="dashboard-billing-filters"
            role="group"
            aria-label="Billing document filters"
          >
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
            <div className="dashboard-form-field dashboard-form-field--full dashboard-billing-filters__period">
              <label className="dashboard-form-field dashboard-billing-filters__period-input--start">
                <span>Start date</span>
                <input
                  className="dashboard-input"
                  type="date"
                  value={invoicePeriodStartDateFilter}
                  max={invoicePeriodEndDateFilter || undefined}
                  onChange={(event) => setInvoicePeriodStartDateFilter(event.target.value)}
                />
              </label>
              <label className="dashboard-form-field dashboard-billing-filters__period-input--end">
                <span>End date</span>
                <input
                  className="dashboard-input"
                  type="date"
                  value={invoicePeriodEndDateFilter}
                  min={invoicePeriodStartDateFilter || undefined}
                  onChange={(event) => setInvoicePeriodEndDateFilter(event.target.value)}
                />
              </label>
            </div>
          </div>
          {invoiceDownloadError ? (
            <p className="dashboard-pagination-note">{invoiceDownloadError}</p>
          ) : invoiceListError ? (
            <p className="dashboard-pagination-note">{invoiceListError}</p>
          ) : null}
        </div>
      </section>

      <DashboardTable
        ariaLabel="Billing documents table"
        columns={BILLING_INVOICES_TABLE_COLUMNS}
        pagination={invoicesPagination.pagination}
      >
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
          <DashboardTableState>Loading billing documents...</DashboardTableState>
        ) : invoices.length === 0 ? (
          <DashboardTableState>
            {hasAnyInvoices
              ? 'No documents match the current filters.'
              : 'No billing documents yet.'}
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
