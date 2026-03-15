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

export function describeAccountActivityType(input: DashboardBillingAccountActivityEntry): string {
  if (input.type === 'MANUAL_ADJUSTMENT') {
    return input.amountMinor >= 0 ? 'Manual support credit' : 'Manual admin debit';
  }
  if (input.type === 'CREDIT_PURCHASE') return 'Credit purchase settled';
  if (input.type === 'USAGE_DEBIT') return 'Usage debit recorded';
  return input.type;
}

function getAccountActivityTone(input: DashboardBillingAccountActivityEntry) {
  if (
    input.type === 'USAGE_DEBIT' ||
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
        <div className="dashboard-billing-overview__members" aria-label="Organisation team members">
          <div className="dashboard-billing-overview__members-header">
            <h3>Team members</h3>
            <p>{sortedMembers.length} associated with this organisation</p>
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
