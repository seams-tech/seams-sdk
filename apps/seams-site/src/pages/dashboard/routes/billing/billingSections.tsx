import React from 'react';
import type { BillingMetric } from './billingShared';
import {
  DashboardTable,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableIntro,
  DashboardTableRow,
  DashboardTableState,
  DashboardTableStatus,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import type {
  DashboardBillingAccountActivityEntry,
  DashboardPlatformBillingOrganizationMember,
  DashboardSponsoredExecutionHistoryEntry,
  DashboardSponsoredExecutionReconciliationEntry,
  DashboardSponsoredExecutionReconciliationPage,
} from './consoleBillingApi';
import { formatUsdMinor } from './consoleBillingApi';

const BILLING_ACCOUNT_ACTIVITY_TABLE_COLUMNS = dashboardTableColumns(
  '1.2fr',
  '1.05fr',
  '0.8fr',
  '1.1fr',
  '1fr',
  '1.7fr',
);
const BILLING_SPONSORED_HISTORY_TABLE_COLUMNS = dashboardTableColumns(
  '1.05fr',
  '0.95fr',
  '1.25fr',
  '1.05fr',
  '0.95fr',
  '1.4fr',
);
const BILLING_SPONSORED_RECONCILIATION_TABLE_COLUMNS = dashboardTableColumns(
  '0.95fr',
  '1fr',
  '1.2fr',
  '0.95fr',
  '1.1fr',
  '1.5fr',
);

function formatTimestampUtcParts(value: string): {
  primary: string;
  secondary: string | null;
} {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return {
      primary: '-',
      secondary: null,
    };
  }
  const iso = date.toISOString();
  const [day, time = ''] = iso.split('T');
  return {
    primary: day || '-',
    secondary: `${time.replace('Z', '')} UTC`,
  };
}

function formatSponsoredChainLabel(input: DashboardSponsoredExecutionHistoryEntry): string {
  return input.chainFamily === 'near' ? 'NEAR delegate' : 'EVM call';
}

function describeSponsoredReceiptStatus(input: DashboardSponsoredExecutionHistoryEntry): string {
  if (input.receiptStatus === 'broadcast_failed') return 'Broadcast failed';
  if (input.receiptStatus === 'rpc_rejected') return 'RPC rejected';
  if (input.receiptStatus === 'reverted') return 'Reverted';
  return 'Succeeded';
}

function getSponsoredReceiptTone(
  input: DashboardSponsoredExecutionHistoryEntry,
): 'success' | 'warning' | 'danger' {
  if (input.receiptStatus === 'success') return 'success';
  if (input.receiptStatus === 'reverted') return 'warning';
  return 'danger';
}

function getSponsoredChargeTone(
  input: DashboardSponsoredExecutionHistoryEntry,
): 'success' | 'neutral' {
  return input.charged ? 'success' : 'neutral';
}

function formatSponsoredChargeAmount(input: DashboardSponsoredExecutionHistoryEntry): string {
  if (!input.charged) return '$0.00';
  return formatUsdMinor(input.settledSpendMinor || 0);
}

function describeSponsoredChargeHint(input: DashboardSponsoredExecutionHistoryEntry): string | null {
  if (!input.charged) {
    return input.chargedReason ? `Not charged: ${input.chargedReason}` : 'Not charged';
  }
  if (input.billingLedgerEntryId) return `Ledger ${input.billingLedgerEntryId}`;
  return input.pricingVersion ? `Pricing ${input.pricingVersion}` : null;
}

function describeReconciliationStatus(
  input: DashboardSponsoredExecutionReconciliationEntry,
): string {
  switch (input.status) {
    case 'matched':
      return 'Matched';
    case 'missing_billing_debit':
      return 'Missing debit';
    case 'amount_mismatch':
      return 'Amount mismatch';
    case 'unexpected_billing_debit':
      return 'Unexpected debit';
    case 'not_charged':
      return 'Not charged';
    default:
      return input.status;
  }
}

function getReconciliationTone(
  input: DashboardSponsoredExecutionReconciliationEntry,
): 'success' | 'warning' | 'danger' | 'neutral' {
  if (input.status === 'matched') return 'success';
  if (input.status === 'not_charged') return 'neutral';
  if (input.status === 'amount_mismatch') return 'warning';
  return 'danger';
}

export function describeAccountActivityType(input: DashboardBillingAccountActivityEntry): string {
  if (input.type === 'MANUAL_ADJUSTMENT') {
    return input.amountMinor >= 0 ? 'Manual support credit' : 'Manual admin debit';
  }
  if (input.type === 'CREDIT_PURCHASE') return 'Credit purchase settled';
  if (input.type === 'USAGE_DEBIT') return 'Usage debit recorded';
  if (input.type === 'SPONSORED_EXECUTION_DEBIT') return 'Sponsored execution debit recorded';
  return input.type;
}

function getAccountActivityTone(input: DashboardBillingAccountActivityEntry) {
  if (
    input.type === 'USAGE_DEBIT' ||
    input.type === 'SPONSORED_EXECUTION_DEBIT' ||
    (input.type === 'MANUAL_ADJUSTMENT' && input.amountMinor < 0)
  ) {
    return 'warning' as const;
  }
  if (input.type === 'REFUND' || input.type === 'REVERSAL') {
    return 'neutral' as const;
  }
  return 'success' as const;
}

function getAccountActivityDocument(entry: DashboardBillingAccountActivityEntry): {
  id: string;
  label: string;
} | null {
  if (entry.relatedInvoiceId) {
    return { id: entry.relatedInvoiceId, label: 'Document' };
  }
  if (entry.relatedPurchaseId) {
    return { id: entry.relatedPurchaseId, label: 'Purchase' };
  }
  return null;
}

function getAccountActivityReasonDetail(
  entry: DashboardBillingAccountActivityEntry,
): string | null {
  if (entry.actorUserId) return `Actor ${entry.actorUserId}`;
  if (entry.actorType && entry.actorType !== 'SYSTEM') return `Actor ${entry.actorType}`;
  if (entry.sourceEventId) return `Event ${entry.sourceEventId}`;
  return null;
}

function getAccountActivitySummary(entry: DashboardBillingAccountActivityEntry): {
  primary: string;
  secondary: string | null;
} {
  const primary = entry.description || '-';
  const secondary =
    entry.note && entry.note !== entry.description
      ? entry.note
      : entry.sourceEventId && entry.sourceEventId !== entry.description
        ? entry.sourceEventId
        : null;
  return {
    primary,
    secondary,
  };
}

function getBillingOverviewMemberBadgeTone(
  member: DashboardPlatformBillingOrganizationMember,
): 'neutral' | 'success' | 'warning' {
  if (member.status === 'ACTIVE') {
    return member.access === 'OWNER' ? 'success' : 'neutral';
  }
  return 'warning';
}

function describeBillingOverviewMemberStatus(
  member: DashboardPlatformBillingOrganizationMember,
): string {
  if (member.status === 'ACTIVE') return member.access;
  return `${member.access} · ${member.status === 'INVITED' ? 'Invited' : 'Suspended'}`;
}

function sortBillingOverviewMembers(
  members: DashboardPlatformBillingOrganizationMember[],
): DashboardPlatformBillingOrganizationMember[] {
  const accessRank: Record<DashboardPlatformBillingOrganizationMember['access'], number> = {
    OWNER: 0,
    ADMIN: 1,
    MEMBER: 2,
  };
  const statusRank: Record<DashboardPlatformBillingOrganizationMember['status'], number> = {
    ACTIVE: 0,
    INVITED: 1,
    SUSPENDED: 2,
  };
  return [...members].sort((left, right) => {
    const accessDelta = accessRank[left.access] - accessRank[right.access];
    if (accessDelta !== 0) return accessDelta;
    const statusDelta = statusRank[left.status] - statusRank[right.status];
    if (statusDelta !== 0) return statusDelta;
    const displayDelta = left.displayName.localeCompare(right.displayName);
    if (displayDelta !== 0) return displayDelta;
    return left.email.localeCompare(right.email);
  });
}

function formatBillingOverviewMemberAddedAt(value: string): string | null {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return null;
  return date.toISOString().slice(0, 10);
}

function describeBillingOverviewMemberMeta(
  member: DashboardPlatformBillingOrganizationMember,
): string {
  const addedAt = formatBillingOverviewMemberAddedAt(member.addedAt);
  const dateLabel =
    member.status === 'INVITED'
      ? addedAt
        ? `Invited ${addedAt}`
        : 'Invited'
      : addedAt
        ? `Added ${addedAt}`
        : 'Added';
  return `${dateLabel} • ${member.userId}`;
}

export function BillingContextSummarySection(props: {
  context: {
    organization: string;
    project: string;
    thirdLabel?: string;
    thirdValue?: string;
  };
  title: string;
  description: string;
  ariaLabel: string;
  metrics?: BillingMetric[];
  members?: DashboardPlatformBillingOrganizationMember[];
}): React.JSX.Element {
  const { context, title, description, ariaLabel, metrics = [], members = [] } = props;
  const sortedMembers = React.useMemo(() => sortBillingOverviewMembers(members), [members]);
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
          <dd title={context.organization || '-'}>{context.organization || '-'}</dd>
        </div>
        <div>
          <dt>Project</dt>
          <dd title={context.project || '-'}>{context.project || '-'}</dd>
        </div>
        <div>
          <dt>{context.thirdLabel || 'Environment'}</dt>
          <dd title={context.thirdValue || '-'}>{context.thirdValue || '-'}</dd>
        </div>
      </dl>
      {sortedMembers.length > 0 ? (
        <div className="dashboard-billing-overview__members" aria-label="Organization team members">
          <div className="dashboard-billing-overview__members-header">
            <h3>Team members</h3>
            <p>{sortedMembers.length} associated with this organization</p>
          </div>
          <ul className="dashboard-billing-overview__members-list">
            {sortedMembers.map((member) => (
              <li className="dashboard-billing-overview__member" key={member.id}>
                <div className="dashboard-billing-overview__member-copy">
                  <strong title={member.displayName}>{member.displayName}</strong>
                  <span
                    className="dashboard-data-table__subline dashboard-data-table__subline--muted"
                    title={member.email}
                  >
                    {member.email}
                  </span>
                  <span
                    className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-overview__member-meta"
                    title={describeBillingOverviewMemberMeta(member)}
                  >
                    {describeBillingOverviewMemberMeta(member)}
                  </span>
                </div>
                <span
                  className={`dashboard-data-table__badge dashboard-data-table__badge--${getBillingOverviewMemberBadgeTone(member)}`}
                >
                  {describeBillingOverviewMemberStatus(member)}
                </span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      {metrics.length > 0 ? (
        <div className="dashboard-kpi-grid dashboard-kpi-grid--content dashboard-billing-overview__metrics">
          {metrics.map((metric) => (
            <article className="dashboard-kpi-card" key={metric.label}>
              <p className="dashboard-kpi-card__label">{metric.label}</p>
              <p className="dashboard-kpi-card__value">{metric.value}</p>
              <p className="dashboard-kpi-card__hint">{metric.hint}</p>
            </article>
          ))}
        </div>
      ) : null}
    </section>
  );
}

export function BillingAccountActivitySection(props: {
  accountActivity: DashboardBillingAccountActivityEntry[];
  accountActivityError: string;
  controls?: React.ReactNode;
  emptyStateText?: string;
}): React.JSX.Element {
  const { accountActivity, accountActivityError, controls, emptyStateText } = props;
  const activityPagination = useDashboardTablePagination(accountActivity, {
    initialRowsPerPage: 10,
    itemLabel: 'event',
    itemLabelPlural: 'events',
  });
  return (
    <DashboardTable
      ariaLabel="Customer account activity"
      className="dashboard-billing-activity-table"
      columns={BILLING_ACCOUNT_ACTIVITY_TABLE_COLUMNS}
      pagination={accountActivityError ? undefined : activityPagination.pagination}
    >
      <DashboardTableIntro className="dashboard-billing-table__intro">
        <div className="dashboard-billing-activity-table__heading">
          <h3 className="dashboard-billing-table__title">Customer Account activity</h3>
          <p className="dashboard-billing-table__description">
            Latest ledger events for the resolved billing account.
          </p>
        </div>
        {controls}
      </DashboardTableIntro>
      {accountActivityError ? (
        <DashboardTableState>{accountActivityError}</DashboardTableState>
      ) : accountActivity.length === 0 ? (
        <DashboardTableState>
          {emptyStateText || 'No billing activity has been recorded yet.'}
        </DashboardTableState>
      ) : (
        <>
          <DashboardTableHeader>
            <DashboardTableHeaderCell>When (UTC)</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Type</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Amount</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Document</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Reason</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Summary</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {activityPagination.rows.map((entry) => {
            const document = getAccountActivityDocument(entry);
            const reasonDetail = getAccountActivityReasonDetail(entry);
            const summary = getAccountActivitySummary(entry);
            const createdAt = formatTimestampUtcParts(entry.createdAt);
            return (
              <DashboardTableRow key={entry.id}>
                <DashboardTableCell title={entry.createdAt}>
                  <div className="dashboard-billing-activity-table__stack">
                    <strong className="dashboard-data-table__summary dashboard-billing-activity-table__timestamp">
                      {createdAt.primary}
                    </strong>
                    {createdAt.secondary ? (
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-activity-table__timestamp-detail">
                        {createdAt.secondary}
                      </span>
                    ) : null}
                  </div>
                  {entry.monthUtc ? (
                    <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                      Period {entry.monthUtc}
                    </span>
                  ) : null}
                </DashboardTableCell>
                <DashboardTableCell>
                  <DashboardTableStatus tone={getAccountActivityTone(entry)}>
                    {describeAccountActivityType(entry)}
                  </DashboardTableStatus>
                </DashboardTableCell>
                <DashboardTableCell title={formatUsdMinor(entry.amountMinor)} align="end">
                  <strong className="dashboard-data-table__summary">
                    {formatUsdMinor(entry.amountMinor)}
                  </strong>
                </DashboardTableCell>
                <DashboardTableCell title={document?.id || undefined}>
                  {document ? (
                    <div className="dashboard-billing-activity-table__stack">
                      <code className="dashboard-billing-activity-table__token" title={document.id}>
                        {document.id}
                      </code>
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                        {document.label}
                      </span>
                    </div>
                  ) : (
                    '-'
                  )}
                </DashboardTableCell>
                <DashboardTableCell title={entry.reasonCode || reasonDetail || undefined}>
                  <div className="dashboard-billing-activity-table__stack">
                    <strong className="dashboard-data-table__summary">
                      {entry.reasonCode || '-'}
                    </strong>
                    {reasonDetail ? (
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-activity-table__detail">
                        {reasonDetail}
                      </span>
                    ) : null}
                  </div>
                </DashboardTableCell>
                <DashboardTableCell title={summary.secondary || summary.primary}>
                  <div className="dashboard-billing-activity-table__stack">
                    <strong className="dashboard-data-table__summary">{summary.primary}</strong>
                    {summary.secondary ? (
                      <code
                        className="dashboard-billing-activity-table__token dashboard-billing-activity-table__token--muted"
                        title={summary.secondary}
                      >
                        {summary.secondary}
                      </code>
                    ) : null}
                  </div>
                </DashboardTableCell>
              </DashboardTableRow>
            );
          })}
        </>
      )}
    </DashboardTable>
  );
}

export function SponsoredExecutionHistorySection(props: {
  entries: DashboardSponsoredExecutionHistoryEntry[];
  loading?: boolean;
  error: string;
  scopeDescription?: string;
}): React.JSX.Element {
  const { entries, loading = false, error, scopeDescription } = props;
  const pagination = useDashboardTablePagination(entries, {
    initialRowsPerPage: 10,
    itemLabel: 'execution',
    itemLabelPlural: 'executions',
  });
  return (
    <DashboardTable
      ariaLabel="Sponsored execution history"
      className="dashboard-billing-activity-table dashboard-billing-sponsored-table"
      columns={BILLING_SPONSORED_HISTORY_TABLE_COLUMNS}
      pagination={error || loading ? undefined : pagination.pagination}
    >
      <DashboardTableIntro className="dashboard-billing-table__intro">
        <div className="dashboard-billing-activity-table__heading">
          <h3 className="dashboard-billing-table__title">Sponsored usage history</h3>
          <p className="dashboard-billing-table__description">
            Last 90 days of sponsored executions with receipt outcomes and billed spend.
          </p>
          {scopeDescription ? <p className="dashboard-pagination-note">{scopeDescription}</p> : null}
        </div>
      </DashboardTableIntro>
      {loading ? (
        <DashboardTableState>Loading sponsored execution history...</DashboardTableState>
      ) : error ? (
        <DashboardTableState>{error}</DashboardTableState>
      ) : entries.length === 0 ? (
        <DashboardTableState>No sponsored executions found for this scope yet.</DashboardTableState>
      ) : (
        <>
          <DashboardTableHeader>
            <DashboardTableHeaderCell>When (UTC)</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Network</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Policy</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Charge</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Receipt</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Reference</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {pagination.rows.map((entry) => {
            const createdAt = formatTimestampUtcParts(entry.createdAt);
            const chargeHint = describeSponsoredChargeHint(entry);
            return (
              <DashboardTableRow key={entry.id}>
                <DashboardTableCell title={entry.createdAt}>
                  <div className="dashboard-billing-activity-table__stack">
                    <strong className="dashboard-data-table__summary">{createdAt.primary}</strong>
                    {createdAt.secondary ? (
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-activity-table__timestamp-detail">
                        {createdAt.secondary}
                      </span>
                    ) : null}
                  </div>
                </DashboardTableCell>
                <DashboardTableCell title={formatSponsoredChainLabel(entry)}>
                  <div className="dashboard-billing-activity-table__stack">
                    <strong className="dashboard-data-table__summary">
                      {formatSponsoredChainLabel(entry)}
                    </strong>
                    <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                      {entry.route}
                    </span>
                  </div>
                </DashboardTableCell>
                <DashboardTableCell title={entry.policyNameAtEvent || entry.policyId}>
                  <div className="dashboard-billing-activity-table__stack">
                    <strong className="dashboard-data-table__summary">
                      {entry.policyNameAtEvent || entry.policyId}
                    </strong>
                    <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                      {entry.environmentId}
                    </span>
                  </div>
                </DashboardTableCell>
                <DashboardTableCell title={formatSponsoredChargeAmount(entry)} align="end">
                  <div className="dashboard-billing-activity-table__stack">
                    <strong className="dashboard-data-table__summary">
                      {formatSponsoredChargeAmount(entry)}
                    </strong>
                    <DashboardTableStatus tone={getSponsoredChargeTone(entry)}>
                      {entry.charged ? 'Charged' : 'Not charged'}
                    </DashboardTableStatus>
                    {chargeHint ? (
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-activity-table__detail">
                        {chargeHint}
                      </span>
                    ) : null}
                  </div>
                </DashboardTableCell>
                <DashboardTableCell title={describeSponsoredReceiptStatus(entry)}>
                  <div className="dashboard-billing-activity-table__stack">
                    <DashboardTableStatus tone={getSponsoredReceiptTone(entry)}>
                      {describeSponsoredReceiptStatus(entry)}
                    </DashboardTableStatus>
                    {entry.errorCode ? (
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-activity-table__detail">
                        {entry.errorCode}
                      </span>
                    ) : null}
                  </div>
                </DashboardTableCell>
                <DashboardTableCell title={entry.targetRef}>
                  <div className="dashboard-billing-activity-table__stack">
                    <code className="dashboard-billing-activity-table__token" title={entry.targetRef}>
                      {entry.targetRef}
                    </code>
                    {(entry.txOrExecutionRef || entry.accountRef) ? (
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-activity-table__detail">
                        {entry.txOrExecutionRef || entry.accountRef}
                      </span>
                    ) : null}
                  </div>
                </DashboardTableCell>
              </DashboardTableRow>
            );
          })}
        </>
      )}
    </DashboardTable>
  );
}

export function SponsoredExecutionReconciliationSection(props: {
  sectionId?: string;
  page: DashboardSponsoredExecutionReconciliationPage | null;
  loading?: boolean;
  error: string;
  scopeDescription?: string;
}): React.JSX.Element {
  const { sectionId, page, loading = false, error } = props;
  const items = page?.items || [];
  const summary = page?.summary || null;
  const pagination = useDashboardTablePagination(items, {
    initialRowsPerPage: 10,
    itemLabel: 'reconciliation row',
    itemLabelPlural: 'reconciliation rows',
  });
  /* Reconciliation is an operations-grade audit view; collapse it by default
     so the billing page leads with balance and top-up. The scope note is
     already shown once on the usage-history section above. */
  return (
    <details
      id={sectionId}
      className="dashboard-view__section dashboard-billing-execution-card"
      aria-label="Sponsored execution reconciliation"
    >
      <summary>Reconciliation</summary>
      <div className="dashboard-billing-table__intro">
        <p className="dashboard-billing-table__description">
          Compare sponsored execution records against linked billing debits.
        </p>
      </div>
      {summary ? (
        <div className="dashboard-kpi-grid dashboard-kpi-grid--content dashboard-billing-reconciliation-summary">
          <article className="dashboard-kpi-card">
            <p className="dashboard-kpi-card__label">Matched</p>
            <p className="dashboard-kpi-card__value">{summary.matchedCount}</p>
            <p className="dashboard-kpi-card__hint">Records aligned with billing</p>
          </article>
          <article className="dashboard-kpi-card">
            <p className="dashboard-kpi-card__label">Mismatches</p>
            <p className="dashboard-kpi-card__value">{summary.mismatchCount}</p>
            <p className="dashboard-kpi-card__hint">
              Missing, unexpected, or amount-mismatched debits
            </p>
          </article>
          <article className="dashboard-kpi-card">
            <p className="dashboard-kpi-card__label">Not charged</p>
            <p className="dashboard-kpi-card__value">{summary.notChargedCount}</p>
            <p className="dashboard-kpi-card__hint">Execution records intentionally left unbilled</p>
          </article>
        </div>
      ) : null}
      <DashboardTable
        ariaLabel="Sponsored execution reconciliation rows"
        className="dashboard-billing-activity-table dashboard-billing-sponsored-table"
        columns={BILLING_SPONSORED_RECONCILIATION_TABLE_COLUMNS}
        pagination={error || loading ? undefined : pagination.pagination}
      >
        {loading ? (
          <DashboardTableState>Loading reconciliation data...</DashboardTableState>
        ) : error ? (
          <DashboardTableState>{error}</DashboardTableState>
        ) : items.length === 0 ? (
          <DashboardTableState>No reconciliation records found for this scope yet.</DashboardTableState>
        ) : (
          <>
            <DashboardTableHeader>
              <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>When (UTC)</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Policy</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Settled spend</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Billing debit</DashboardTableHeaderCell>
              <DashboardTableHeaderCell>Notes</DashboardTableHeaderCell>
            </DashboardTableHeader>
            {pagination.rows.map((entry) => {
              const createdAt = formatTimestampUtcParts(entry.record.createdAt);
              const settledSpend = entry.record.settledSpendMinor || 0;
              return (
                <DashboardTableRow key={entry.record.id}>
                  <DashboardTableCell title={describeReconciliationStatus(entry)}>
                    <DashboardTableStatus tone={getReconciliationTone(entry)}>
                      {describeReconciliationStatus(entry)}
                    </DashboardTableStatus>
                  </DashboardTableCell>
                  <DashboardTableCell title={entry.record.createdAt}>
                    <div className="dashboard-billing-activity-table__stack">
                      <strong className="dashboard-data-table__summary">{createdAt.primary}</strong>
                      {createdAt.secondary ? (
                        <span className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-activity-table__timestamp-detail">
                          {createdAt.secondary}
                        </span>
                      ) : null}
                    </div>
                  </DashboardTableCell>
                  <DashboardTableCell title={entry.record.policyNameAtEvent || entry.record.policyId}>
                    <div className="dashboard-billing-activity-table__stack">
                      <strong className="dashboard-data-table__summary">
                        {entry.record.policyNameAtEvent || entry.record.policyId}
                      </strong>
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                        {formatSponsoredChainLabel(entry.record)}
                      </span>
                    </div>
                  </DashboardTableCell>
                  <DashboardTableCell title={formatUsdMinor(settledSpend)} align="end">
                    <div className="dashboard-billing-activity-table__stack">
                      <strong className="dashboard-data-table__summary">
                        {formatUsdMinor(settledSpend)}
                      </strong>
                      <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                        {entry.record.charged ? 'Charged execution' : 'Not charged'}
                      </span>
                    </div>
                  </DashboardTableCell>
                  <DashboardTableCell title={entry.billingDebit?.id || entry.record.billingLedgerEntryId || '-'}>
                    {entry.billingDebit || entry.record.billingLedgerEntryId ? (
                      <div className="dashboard-billing-activity-table__stack">
                        <code className="dashboard-billing-activity-table__token">
                          {entry.billingDebit?.id || entry.record.billingLedgerEntryId}
                        </code>
                        {entry.billingDebit ? (
                          <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                            {formatUsdMinor(entry.billingDebit.amountMinor)}
                          </span>
                        ) : null}
                      </div>
                    ) : (
                      '-'
                    )}
                  </DashboardTableCell>
                  <DashboardTableCell title={entry.mismatchReasons.join(', ') || undefined}>
                    <div className="dashboard-billing-activity-table__stack">
                      <strong className="dashboard-data-table__summary">
                        {entry.mismatchReasons[0] || 'Billing debit linked'}
                      </strong>
                      {entry.mismatchReasons.length > 1 ? (
                        <span className="dashboard-data-table__subline dashboard-data-table__subline--muted dashboard-billing-activity-table__detail">
                          {entry.mismatchReasons.slice(1).join(', ')}
                        </span>
                      ) : null}
                    </div>
                  </DashboardTableCell>
                </DashboardTableRow>
              );
            })}
          </>
        )}
      </DashboardTable>
    </details>
  );
}
