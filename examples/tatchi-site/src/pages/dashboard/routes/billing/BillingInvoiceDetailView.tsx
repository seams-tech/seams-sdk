import React from 'react';
import {
  DashboardTable,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableIntro,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import {
  formatUsdMinor,
  type DashboardBillingInvoiceActivity,
  type DashboardBillingInvoice,
  type DashboardBillingInvoiceLineItem,
} from './consoleBillingApi';
import {
  BillingMetricsGrid,
  formatInvoiceStatusLabel,
  formatTimestamp,
  getInvoiceStatusBadgeClassName,
  type BillingMetric,
} from './billingShared';

const BILLING_INVOICE_LINE_ITEMS_TABLE_COLUMNS = dashboardTableColumns(
  1,
  0.7,
  1.45,
  0.7,
  0.55,
  0.7,
  0.7,
  0.95,
);

export interface BillingInvoiceDetailViewProps {
  invoiceId: string;
  invoice: DashboardBillingInvoice | null;
  invoiceDetailLoading: boolean;
  invoiceDetailError: string;
  invoiceActivityLoading: boolean;
  invoiceActivityError: string;
  invoiceActivity: DashboardBillingInvoiceActivity | null;
  lineItemsLoading: boolean;
  lineItemsError: string;
  lineItems: DashboardBillingInvoiceLineItem[];
  downloadingInvoicePdfId: string;
  invoiceDownloadError: string;
  onBackToInvoices: () => void;
  onDownloadInvoicePdf: (invoiceId: string) => Promise<void>;
}

export function BillingInvoiceDetailView(props: BillingInvoiceDetailViewProps): React.JSX.Element {
  const {
    invoiceId,
    invoice,
    invoiceDetailLoading,
    invoiceDetailError,
    invoiceActivityLoading,
    invoiceActivityError,
    invoiceActivity,
    lineItemsLoading,
    lineItemsError,
    lineItems,
    downloadingInvoicePdfId,
    invoiceDownloadError,
    onBackToInvoices,
    onDownloadInvoicePdf,
  } = props;

  const detailMetrics: BillingMetric[] = [
    {
      label: 'Document type',
      value: invoice?.documentType === 'PURCHASE_RECEIPT' ? 'Purchase receipt' : 'Usage statement',
      hint: invoice?.id || invoiceId,
    },
    {
      label: 'Status',
      value: invoice ? formatInvoiceStatusLabel(invoice.status) : '-',
      hint:
        invoice?.documentType === 'PURCHASE_RECEIPT'
          ? 'Settled prepaid credit purchase'
          : 'Generated from recorded prepaid usage',
    },
    {
      label: 'Amount',
      value: formatUsdMinor(Number(invoice?.amountDueMinor || 0)),
      hint: `Paid ${formatUsdMinor(Number(invoice?.amountPaidMinor || 0))}`,
    },
    {
      label: 'Period',
      value: invoice?.periodMonthUtc || '-',
      hint: `Created ${formatTimestamp(invoice?.createdAt || null)}`,
    },
  ];
  const lineItemsPagination = useDashboardTablePagination(lineItems, {
    disabled: lineItemsLoading,
    itemLabel: 'line item',
    itemLabelPlural: 'line items',
  });
  const hasInternalActivityEntries = Boolean(
    invoiceActivity?.entries.some((entry) => entry.visibility === 'INTERNAL'),
  );

  return (
    <>
      <section
        className="dashboard-view__section dashboard-billing-invoice-hero"
        aria-label="Billing document detail header"
      >
        <div className="dashboard-billing-invoice-hero__actions">
          <button
            type="button"
            className="dashboard-pagination-button dashboard-pagination-button--secondary"
            onClick={onBackToInvoices}
          >
            Back to invoices
          </button>
          <button
            type="button"
            className="dashboard-pagination-button"
            onClick={() => {
              void onDownloadInvoicePdf(invoiceId);
            }}
            disabled={downloadingInvoicePdfId === invoiceId}
          >
            {downloadingInvoicePdfId === invoiceId ? 'Downloading PDF...' : 'Download PDF'}
          </button>
        </div>
        <div className="dashboard-billing-invoice-hero__copy">
          <p className="dashboard-billing-invoice-hero__eyebrow">Billing document</p>
          <h2>{invoice?.id || invoiceId}</h2>
          <p>View document status, line items, and recorded ledger activity.</p>
        </div>
        {invoiceDownloadError ? (
          <p className="dashboard-pagination-note">{invoiceDownloadError}</p>
        ) : null}
      </section>

      {invoiceDetailLoading ? (
        <section className="dashboard-view__section">
          <p>Loading billing document...</p>
        </section>
      ) : invoiceDetailError ? (
        <section className="dashboard-view__section">
          <p>Billing document unavailable: {invoiceDetailError}</p>
        </section>
      ) : !invoice ? (
        <section className="dashboard-view__section">
          <p>Billing document {invoiceId} was not found.</p>
        </section>
      ) : (
        <>
          <BillingMetricsGrid
            metrics={detailMetrics}
            ariaLabel="Billing document summary metrics"
          />

          <section
            className="dashboard-table-wrapper"
            aria-label="Billing document activity timeline"
          >
            <div className="dashboard-table-limit dashboard-billing-table__intro">
              <h3 className="dashboard-billing-table__title">Document activity</h3>
              <p className="dashboard-billing-table__description">
                Review document creation and ledger activity in one chronological feed.
              </p>
              {hasInternalActivityEntries ? (
                <p className="dashboard-pagination-note">
                  Internal manual adjustments are visible in this staff timeline only and are
                  excluded from exported PDFs.
                </p>
              ) : null}
              {invoiceActivityError ? (
                <p className="dashboard-pagination-note">{invoiceActivityError}</p>
              ) : null}
            </div>
            {invoiceActivityLoading ? (
              <p className="dashboard-table-limit">Loading document activity...</p>
            ) : invoiceActivity?.entries.length ? (
              <div className="dashboard-billing-timeline">
                {invoiceActivity.entries.map((entry) => (
                  <article className="dashboard-billing-timeline__item" key={entry.id}>
                    <div className="dashboard-billing-timeline__header">
                      <p className="dashboard-billing-timeline__title">{entry.summary}</p>
                      <span className={getInvoiceStatusBadgeClassName(entry.toState)}>
                        {formatInvoiceStatusLabel(entry.toState)}
                      </span>
                    </div>
                    <p className="dashboard-billing-timeline__meta">
                      {formatTimestamp(entry.occurredAt)}
                      {entry.actorUserId ? ` • ${entry.actorUserId}` : ''}
                      {entry.visibility === 'INTERNAL' ? ' • Internal only' : ''}
                    </p>
                  </article>
                ))}
              </div>
            ) : (
              <p className="dashboard-table-limit">No document activity has been recorded yet.</p>
            )}
          </section>

          <DashboardTable
            ariaLabel="Billing document line items"
            columns={BILLING_INVOICE_LINE_ITEMS_TABLE_COLUMNS}
            pagination={lineItemsPagination.pagination}
          >
            <DashboardTableIntro className="dashboard-billing-table__intro">
              <h3 className="dashboard-billing-table__title">Line items</h3>
              <p className="dashboard-billing-table__description">
                Review the billed or credited components captured in this document snapshot.
              </p>
            </DashboardTableIntro>
            <DashboardTableHeader>
              <DashboardTableHeaderCell>Line item ID</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Type</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Description</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Period</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Quantity</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Unit amount</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Amount</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Document</DashboardTableHeaderCell>
            </DashboardTableHeader>
            {lineItemsLoading ? (
              <DashboardTableState>Loading line items...</DashboardTableState>
            ) : lineItemsError ? (
              <DashboardTableState>Line items unavailable: {lineItemsError}</DashboardTableState>
            ) : lineItems.length === 0 ? (
              <DashboardTableState>No line items for this document.</DashboardTableState>
            ) : (
              <>
                {lineItemsPagination.rows.map((lineItem) => (
                  <DashboardTableRow key={lineItem.id}>
                    <DashboardTableCell title={lineItem.id}>{lineItem.id}</DashboardTableCell>
                    <DashboardTableCell>{lineItem.itemType || '-'}</DashboardTableCell>
                    <DashboardTableCell title={lineItem.description}>
                      {lineItem.description || '-'}
                    </DashboardTableCell>
                    <DashboardTableCell>{lineItem.periodMonthUtc || '-'}</DashboardTableCell>
                    <DashboardTableCell>{String(lineItem.quantity)}</DashboardTableCell>
                    <DashboardTableCell>
                      {formatUsdMinor(lineItem.unitAmountMinor)}
                    </DashboardTableCell>
                    <DashboardTableCell>{formatUsdMinor(lineItem.amountMinor)}</DashboardTableCell>
                    <DashboardTableCell title={lineItem.invoiceId} truncate>
                      {lineItem.invoiceId}
                    </DashboardTableCell>
                  </DashboardTableRow>
                ))}
              </>
            )}
          </DashboardTable>
        </>
      )}
    </>
  );
}

export default BillingInvoiceDetailView;
