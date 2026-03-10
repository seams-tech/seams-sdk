import React from 'react';
import type { DashboardBillingInvoice } from './consoleBillingApi';

export type BillingSubview =
  | { kind: 'account' }
  | { kind: 'invoices' }
  | { kind: 'invoice'; invoiceId: string };

export type BillingMetric = {
  label: string;
  value: string;
  hint: string;
};

export function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

export function parsePositiveInteger(value: string): number | null {
  const raw = String(value || '').trim();
  if (!/^\d+$/.test(raw)) return null;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return null;
  return parsed;
}

export function parseBillingSubview(pathname: string): BillingSubview {
  const normalized = String(pathname || '').trim();
  if (
    normalized === '/dashboard/invoices' ||
    normalized === '/dashboard/invoices/' ||
    normalized === '/dashboard/billing/invoices' ||
    normalized === '/dashboard/billing/invoices/'
  ) {
    return { kind: 'invoices' };
  }
  const invoiceMatch = normalized.match(/^\/dashboard\/(?:billing\/invoices|invoices)\/([^/]+)$/);
  if (invoiceMatch?.[1]) {
    try {
      return { kind: 'invoice', invoiceId: decodeURIComponent(invoiceMatch[1]) };
    } catch {
      return { kind: 'invoice', invoiceId: invoiceMatch[1] };
    }
  }
  return { kind: 'account' };
}

export function isInvoiceOverdue(invoice: DashboardBillingInvoice): boolean {
  if (invoice.status !== 'OPEN' || !invoice.dueAt) return false;
  const dueAtMs = Date.parse(invoice.dueAt);
  if (Number.isNaN(dueAtMs)) return false;
  return dueAtMs < Date.now();
}

export function formatInvoiceStatusLabel(status: string): string {
  const normalized = String(status || '')
    .trim()
    .toUpperCase();
  if (!normalized) return 'Unknown';
  return normalized
    .split(/[_\s-]+/)
    .filter(Boolean)
    .map((part) => `${part[0]}${part.slice(1).toLowerCase()}`)
    .join(' ');
}

export function getInvoiceStatusBadgeClassName(status: string): string {
  const normalized = String(status || '')
    .trim()
    .toLowerCase();
  if (
    normalized === 'action_required' ||
    normalized === 'created' ||
    normalized === 'pending' ||
    normalized === 'confirming' ||
    normalized === 'open' ||
    normalized === 'past_due'
  ) {
    return 'dashboard-data-table__status dashboard-data-table__status--warning';
  }
  if (
    normalized === 'paid' ||
    normalized === 'settled' ||
    normalized === 'partially_settled' ||
    normalized === 'overpaid'
  ) {
    return 'dashboard-data-table__status dashboard-data-table__status--success';
  }
  if (normalized === 'void' || normalized === 'canceled' || normalized === 'expired') {
    return 'dashboard-data-table__status dashboard-data-table__status--neutral';
  }
  if (normalized === 'uncollectible' || normalized === 'failed' || normalized === 'disputed') {
    return 'dashboard-data-table__status dashboard-data-table__status--danger';
  }
  return 'dashboard-data-table__status dashboard-data-table__status--neutral';
}

export function buildInvoicePdfFilename(
  invoice: DashboardBillingInvoice | null,
  invoiceId: string,
): string {
  const safeInvoiceId = String(invoice?.id || invoiceId || 'invoice').trim();
  const safePeriod = String(invoice?.periodMonthUtc || 'unknown')
    .trim()
    .replace(/[^a-zA-Z0-9_-]+/g, '_');
  const prefix = invoice?.documentType === 'PURCHASE_RECEIPT' ? 'receipt' : 'statement';
  return `${prefix}_${safePeriod}_${safeInvoiceId}.pdf`;
}

export function BillingMetricsGrid(props: {
  metrics: BillingMetric[];
  ariaLabel: string;
}): React.JSX.Element {
  const { metrics, ariaLabel } = props;
  return (
    <section className="dashboard-kpi-grid dashboard-kpi-grid--content" aria-label={ariaLabel}>
      {metrics.map((metric) => (
        <article className="dashboard-kpi-card" key={metric.label}>
          <p className="dashboard-kpi-card__label">{metric.label}</p>
          <p className="dashboard-kpi-card__value">{metric.value}</p>
          <p className="dashboard-kpi-card__hint">{metric.hint}</p>
        </article>
      ))}
    </section>
  );
}
