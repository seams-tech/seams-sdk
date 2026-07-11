import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import { formatDashboardTimestamp } from '../../utils/timestamps';
import {
  ActivityIcon,
  CreditCardIcon,
  FuelIcon,
  KeyRoundIcon,
  ScaleIcon,
  ScrollTextIcon,
  UserCogIcon,
  WalletCardsIcon,
  WebhookIcon,
} from '../../icons/SidebarIcons';
import { useDashboardConsoleSession } from '../../consoleSession';
import {
  getDashboardOpsCockpitSummary,
  type DashboardOpsCockpitDeadLetterEntry,
  type DashboardOpsCockpitPendingApproval,
  type DashboardOpsCockpitSectionStatus,
  type DashboardOpsCockpitSummary,
} from './consoleOpsCockpitApi';
import {
  approveDashboardApproval,
  rejectDashboardApproval,
} from '../approvals/consoleApprovalsApi';
import { createDashboardAuditExport, listDashboardAuditExports } from '../audit/consoleAuditApi';
import { replayDashboardWebhookDelivery } from '../webhooks/consoleWebhooksApi';

type OpsCockpitData = {
  summary: DashboardOpsCockpitSummary | null;
  warnings: string[];
};

const OPS_COCKPIT_APPROVE_REASON = 'Approved from Ops Cockpit';
const OPS_COCKPIT_REJECT_REASON = 'Rejected from Ops Cockpit';

function formatTimestamp(value: string | null | undefined): string {
  return formatDashboardTimestamp(value, '-');
}

function formatApprovalLabel(value: string | null | undefined): string {
  const normalized = String(value || '').trim().toUpperCase();
  if (normalized === 'KEY_EXPORT') return 'Key export';
  if (normalized === 'POLICY_PUBLISH') return 'Policy publish';
  if (!normalized) return 'Approval';
  return normalized
    .toLowerCase()
    .split('_')
    .filter(Boolean)
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error || 'Unknown error');
}

function toSectionWarning(label: string, status: DashboardOpsCockpitSectionStatus): string | null {
  if (status.state === 'ok') return null;
  /* Unconfigured queues hide their panels entirely; a warning would just
     re-surface the noise the hidden panel avoids. */
  if (status.state === 'not_configured') return null;
  const detail = status.message ? `: ${status.message}` : '';
  if (status.state === 'forbidden') return `${label} is not available for this role${detail}`;
  return `${label} failed${detail}`;
}

const OVERVIEW_HERO_ACTIONS = [
  {
    title: 'Create a policy',
    description: 'Set signing rules and spend caps for your wallets.',
    path: '/dashboard/policy-engine',
    icon: ScaleIcon,
    tone: 'green',
  },
  {
    title: 'Create an API key',
    description: 'Issue secret or publishable credentials for this environment.',
    path: '/dashboard/api-keys',
    icon: KeyRoundIcon,
    tone: 'amber',
  },
  {
    title: 'Top up credits',
    description: 'Add prepaid balance for sponsored usage.',
    path: '/dashboard/billing/account',
    icon: CreditCardIcon,
    tone: 'violet',
  },
] as const;

const OVERVIEW_HERO_TOOLS = [
  { label: 'User wallets', path: '/dashboard/wallets-list', icon: WalletCardsIcon },
  { label: 'Gas sponsorship', path: '/dashboard/gas-sponsorship', icon: FuelIcon },
  { label: 'Observability', path: '/dashboard/observability', icon: ActivityIcon },
  { label: 'Audit logs', path: '/dashboard/audit', icon: ScrollTextIcon },
  { label: 'Webhooks', path: '/dashboard/webhooks', icon: WebhookIcon },
  { label: 'Team members', path: '/dashboard/team-members', icon: UserCogIcon },
] as const;

function OpsCockpitQueuePanel(props: {
  ariaLabel: string;
  title: string;
  badge: string;
  children: React.ReactNode;
}): React.JSX.Element {
  const { ariaLabel, title, badge, children } = props;
  return (
    <section className="dashboard-ops-cockpit-panel" aria-label={ariaLabel}>
      <div className="dashboard-ops-cockpit-panel__summary">
        <h3 className="dashboard-ops-cockpit-panel__title">{title}</h3>
        <span className="dashboard-ops-cockpit-panel__badge">{badge}</span>
      </div>
      <div className="dashboard-ops-cockpit-panel__body">{children}</div>
    </section>
  );
}

export function OpsCockpitPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const { linkProps } = useSiteRouter();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [approvingApprovalId, setApprovingApprovalId] = React.useState<string>('');
  const [rejectingApprovalId, setRejectingApprovalId] = React.useState<string>('');
  const [approvalMutationErrorMessage, setApprovalMutationErrorMessage] =
    React.useState<string>('');
  const [approvalMutationNotice, setApprovalMutationNotice] = React.useState<string>('');
  const [requeueingAuditExportId, setRequeueingAuditExportId] = React.useState<string>('');
  const [auditExportMutationErrorMessage, setAuditExportMutationErrorMessage] =
    React.useState<string>('');
  const [auditExportMutationNotice, setAuditExportMutationNotice] = React.useState<string>('');
  const [replayingDeadLetterId, setReplayingDeadLetterId] = React.useState<string>('');
  const [mutationErrorMessage, setMutationErrorMessage] = React.useState<string>('');
  const [mutationNotice, setMutationNotice] = React.useState<string>('');
  const [data, setData] = React.useState<OpsCockpitData>({
    summary: null,
    warnings: [],
  });

  const loadOpsCockpit = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setData({
        summary: null,
        warnings: [],
      });
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMessage('');

    (async () => {
      const summary = await getDashboardOpsCockpitSummary({ windowMinutes: 60 });
      const warnings = [
        toSectionWarning('Approvals queue', summary.approvals.status),
        toSectionWarning('Billing failure queue', summary.billing.status),
        toSectionWarning('Webhook dead letters', summary.webhooks.status),
        toSectionWarning('Audit export queue', summary.auditExports.status),
      ].filter((entry): entry is string => Boolean(entry));
      if (summary.webhooks.endpointCount > summary.webhooks.scannedEndpointCount) {
        warnings.push(
          `Webhook dead-letter scan capped at ${summary.webhooks.scannedEndpointCount} endpoints (total ${summary.webhooks.endpointCount}).`,
        );
      }

      if (cancelled) return;
      setData({
        summary,
        warnings,
      });
      setLoading(false);
    })().catch((error: unknown) => {
      if (cancelled) return;
      setLoading(false);
      setErrorMessage(toErrorMessage(error));
    });

    return () => {
      cancelled = true;
    };
  }, [session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadOpsCockpit();
    return cleanup;
  }, [loadOpsCockpit, session.loading]);

  const onReplayDeadLetter = React.useCallback(
    async (entry: DashboardOpsCockpitDeadLetterEntry) => {
      if (!session.claims) {
        setMutationErrorMessage(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const deliveryId = String(entry.deadLetter.deliveryId || '').trim();
      if (!deliveryId) {
        setMutationErrorMessage('Replay unavailable: delivery id is missing for this dead letter.');
        return;
      }
      setReplayingDeadLetterId(entry.deadLetter.id);
      setMutationErrorMessage('');
      setMutationNotice('');
      try {
        await replayDashboardWebhookDelivery({
          endpointId: entry.endpointId,
          deliveryId,
        });
        setMutationNotice(`Replay queued for delivery ${deliveryId}.`);
        loadOpsCockpit();
      } catch (error: unknown) {
        setMutationErrorMessage(toErrorMessage(error));
      } finally {
        setReplayingDeadLetterId('');
      }
    },
    [loadOpsCockpit, session.claims, session.errorMessage],
  );

  const onApprovePendingApproval = React.useCallback(
    async (entry: DashboardOpsCockpitPendingApproval) => {
      if (!session.claims) {
        setApprovalMutationErrorMessage(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (entry.requireMfa) {
        setApprovalMutationErrorMessage(
          'Approve unavailable in overview: this request requires MFA verification.',
        );
        return;
      }
      const approvalId = String(entry.id || '').trim();
      if (!approvalId) {
        setApprovalMutationErrorMessage('Approval id is required.');
        return;
      }
      setApprovingApprovalId(approvalId);
      setApprovalMutationErrorMessage('');
      setApprovalMutationNotice('');
      try {
        const updated = await approveDashboardApproval({
          approvalId,
          reason: OPS_COCKPIT_APPROVE_REASON,
          mfaVerified: false,
        });
        setApprovalMutationNotice(`Approval request ${approvalId} is now ${updated.status}.`);
        loadOpsCockpit();
      } catch (error: unknown) {
        setApprovalMutationErrorMessage(toErrorMessage(error));
      } finally {
        setApprovingApprovalId('');
      }
    },
    [loadOpsCockpit, session.claims, session.errorMessage],
  );

  const onRejectPendingApproval = React.useCallback(
    async (entry: DashboardOpsCockpitPendingApproval) => {
      if (!session.claims) {
        setApprovalMutationErrorMessage(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const approvalId = String(entry.id || '').trim();
      if (!approvalId) {
        setApprovalMutationErrorMessage('Approval id is required.');
        return;
      }
      setRejectingApprovalId(approvalId);
      setApprovalMutationErrorMessage('');
      setApprovalMutationNotice('');
      try {
        const updated = await rejectDashboardApproval({
          approvalId,
          reason: OPS_COCKPIT_REJECT_REASON,
        });
        setApprovalMutationNotice(`Approval request ${approvalId} is now ${updated.status}.`);
        loadOpsCockpit();
      } catch (error: unknown) {
        setApprovalMutationErrorMessage(toErrorMessage(error));
      } finally {
        setRejectingApprovalId('');
      }
    },
    [loadOpsCockpit, session.claims, session.errorMessage],
  );

  const onRequeueAuditExport = React.useCallback(
    async (exportId: string) => {
      if (!session.claims) {
        setAuditExportMutationErrorMessage(
          session.errorMessage || 'Console session is unavailable',
        );
        return;
      }
      const normalizedExportId = String(exportId || '').trim();
      if (!normalizedExportId) {
        setAuditExportMutationErrorMessage('Export id is required.');
        return;
      }
      setRequeueingAuditExportId(normalizedExportId);
      setAuditExportMutationErrorMessage('');
      setAuditExportMutationNotice('');
      try {
        const exports = await listDashboardAuditExports({ limit: 200 });
        const sourceExport = exports.find((entry) => entry.id === normalizedExportId);
        if (!sourceExport) {
          throw new Error(`Audit export ${normalizedExportId} was not found.`);
        }
        const requeued = await createDashboardAuditExport({
          format: sourceExport.format,
          ...(sourceExport.filters.domain && sourceExport.filters.domain !== 'ALL'
            ? { domain: sourceExport.filters.domain }
            : {}),
          ...(sourceExport.filters.projectId ? { projectId: sourceExport.filters.projectId } : {}),
          ...(sourceExport.filters.environmentId
            ? { environmentId: sourceExport.filters.environmentId }
            : {}),
          ...(sourceExport.filters.from ? { from: sourceExport.filters.from } : {}),
          ...(sourceExport.filters.to ? { to: sourceExport.filters.to } : {}),
        });
        setAuditExportMutationNotice(
          `Queued replacement export ${requeued.id} from ${normalizedExportId}.`,
        );
        loadOpsCockpit();
      } catch (error: unknown) {
        setAuditExportMutationErrorMessage(toErrorMessage(error));
      } finally {
        setRequeueingAuditExportId('');
      }
    },
    [loadOpsCockpit, session.claims, session.errorMessage],
  );

  const summary = data.summary;
  const pendingApprovals = summary?.approvals.pending || [];
  const failedInvoices = summary?.billing.failedInvoices || [];
  const failedWebhooks = summary?.webhooks.deadLetters || [];
  const queuedAuditExports = summary?.auditExports.queuedExports || [];
  const showAuditExportQueue = summary?.auditExports.status.state !== 'not_configured';
  const showWebhookQueue = summary?.webhooks.status.state !== 'not_configured';
  const showBillingQueue = summary?.billing.status.state !== 'not_configured';
  const summaryWarnings = data.warnings;

  return (
    <div className="dashboard-view dashboard-ops-cockpit-view" aria-label="Ops cockpit page">
      <section className="dashboard-hero" aria-label="Quick actions">
        <h2 className="dashboard-hero__title">What would you like to do?</h2>
        <div className="dashboard-hero__cards">
          {OVERVIEW_HERO_ACTIONS.map((action) => {
            const ActionIcon = action.icon;
            const navProps = linkProps(action.path);
            return (
              <a
                key={action.path}
                className="dashboard-hero__card"
                href={navProps.href}
                onClick={navProps.onClick}
              >
                <span
                  className={`dashboard-hero__card-icon dashboard-hero__card-icon--${action.tone}`}
                  aria-hidden="true"
                >
                  <ActionIcon size={20} />
                </span>
                <span className="dashboard-hero__card-title">{action.title}</span>
                <span className="dashboard-hero__card-description">{action.description}</span>
              </a>
            );
          })}
        </div>
        <div className="dashboard-hero__chips">
          {OVERVIEW_HERO_TOOLS.map((tool) => {
            const ToolIcon = tool.icon;
            const navProps = linkProps(tool.path);
            return (
              <a
                key={tool.path}
                className="dashboard-hero__chip"
                href={navProps.href}
                onClick={navProps.onClick}
              >
                <ToolIcon size={16} />
                <span>{tool.label}</span>
              </a>
            );
          })}
        </div>
        <a
          className="dashboard-hero__promo"
          href={linkProps('/dashboard/gas-sponsorship').href}
          onClick={linkProps('/dashboard/gas-sponsorship').onClick}
        >
          <span className="dashboard-hero__promo-copy">
            <span className="dashboard-hero__promo-title">Sponsor gas for your users</span>
            <span className="dashboard-hero__promo-description">
              Cover transaction fees with policies and spend caps — no user top-ups required.
            </span>
          </span>
          <span className="dashboard-pagination-button dashboard-pagination-button--primary">
            Set up sponsorship
          </span>
        </a>
      </section>

      <section
        className="dashboard-view__section dashboard-ops-cockpit-summary--plain"
        aria-label="Ops cockpit summary"
      >
        {loading ? <p className="dashboard-pagination-note">Refreshing queue snapshot...</p> : null}
        {errorMessage ? <p className="dashboard-pagination-note">{errorMessage}</p> : null}
        {summaryWarnings.length > 0 ? (
          <div className="dashboard-view-grid">
            {summaryWarnings.map((warning) => (
              <p className="dashboard-pagination-note" key={warning}>
                {warning}
              </p>
            ))}
          </div>
        ) : null}
      </section>

      <section
        className="dashboard-view__section"
        aria-label="Pending approvals summary"
      >
        <h2>Pending approvals</h2>
        {approvalMutationNotice ? (
          <p className="dashboard-pagination-note">{approvalMutationNotice}</p>
        ) : null}
        {approvalMutationErrorMessage ? (
          <p className="dashboard-pagination-note">{approvalMutationErrorMessage}</p>
        ) : null}
        {pendingApprovals.length === 0 ? (
          <p className="dashboard-pagination-note">No pending approvals.</p>
        ) : (
          <ul className="dashboard-view-list">
            {pendingApprovals.slice(0, 6).map((row) => (
              <li key={row.id}>
                <p>
                  <strong>{formatApprovalLabel(row.operationType)}</strong> for{' '}
                  {formatApprovalLabel(row.resourceType || 'resource').toLowerCase()}{' '}
                  <code>{row.resourceId || row.id}</code> by <code>{row.requestedByUserId}</code> at{' '}
                  {formatTimestamp(row.createdAt)}
                </p>
                {row.reason ? (
                  <p className="dashboard-pagination-note">Requested reason: {row.reason}</p>
                ) : null}
                <p className="dashboard-pagination-note">
                  {row.requiredApprovals === 1
                    ? '1 approval required.'
                    : `${row.requiredApprovals} approvals required.`}{' '}
                  {row.requireMfa ? 'MFA verification is required to approve.' : ''}
                </p>
                {row.requireMfa ? (
                  <p className="dashboard-pagination-note">
                    Approve unavailable in overview: this request requires MFA verification.
                  </p>
                ) : null}
                <p>
                  {!row.requireMfa ? (
                    <>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => onApprovePendingApproval(row)}
                        disabled={
                          approvingApprovalId === row.id || rejectingApprovalId === row.id
                        }
                      >
                        {approvingApprovalId === row.id ? 'Approving...' : 'Approve'}
                      </button>{' '}
                    </>
                  ) : null}
                  <button
                    type="button"
                    className="dashboard-inline-link dashboard-inline-link--danger"
                    onClick={() => onRejectPendingApproval(row)}
                    disabled={approvingApprovalId === row.id || rejectingApprovalId === row.id}
                  >
                    {rejectingApprovalId === row.id ? 'Rejecting...' : 'Reject'}
                  </button>
                </p>
              </li>
            ))}
          </ul>
        )}
      </section>

      <div className="dashboard-ops-cockpit-grid" aria-label="Ops cockpit queues">
        {showWebhookQueue ? (
        <OpsCockpitQueuePanel
          ariaLabel="Failed webhook summary"
          title="Failed webhooks (dead letters)"
          badge={`${failedWebhooks.length}`}
        >
          {mutationNotice ? <p className="dashboard-pagination-note">{mutationNotice}</p> : null}
          {mutationErrorMessage ? (
            <p className="dashboard-pagination-note">{mutationErrorMessage}</p>
          ) : null}
          {failedWebhooks.length === 0 ? (
            <p className="dashboard-pagination-note">No unresolved webhook dead letters.</p>
          ) : (
            <ul className="dashboard-view-list">
              {failedWebhooks.slice(0, 8).map((entry) => (
                <li key={entry.deadLetter.id}>
                  Endpoint <code>{entry.endpointId}</code> event{' '}
                  <code>{entry.deadLetter.eventType || entry.deadLetter.eventId}</code> failed{' '}
                  <strong>{entry.deadLetter.failedAttempts}</strong> attempts; last error:{' '}
                  {entry.deadLetter.lastErrorMessage || 'n/a'} (
                  {formatTimestamp(entry.deadLetter.movedToDlqAt)}){' '}
                  <button
                    type="button"
                    className="dashboard-inline-link"
                    onClick={() => onReplayDeadLetter(entry)}
                    disabled={
                      replayingDeadLetterId === entry.deadLetter.id ||
                      !String(entry.deadLetter.deliveryId || '').trim()
                    }
                  >
                    {replayingDeadLetterId === entry.deadLetter.id ? 'Replaying...' : 'Replay'}
                  </button>
                </li>
              ))}
            </ul>
          )}
        </OpsCockpitQueuePanel>
        ) : null}

        {showBillingQueue ? (
        <OpsCockpitQueuePanel
          ariaLabel="Billing failure summary"
          title="Failed or overdue invoices"
          badge={`${failedInvoices.length}`}
        >
          {failedInvoices.length === 0 ? (
            <p className="dashboard-pagination-note">No failed or overdue invoices.</p>
          ) : (
            <ul className="dashboard-view-list">
              {failedInvoices.slice(0, 6).map((row) => (
                <li key={row.id}>
                  Invoice <code>{row.id}</code> is <strong>{row.status}</strong> with due date{' '}
                  {formatTimestamp(row.dueAt)}.
                </li>
              ))}
            </ul>
          )}
        </OpsCockpitQueuePanel>
        ) : null}

        {showAuditExportQueue ? (
          <OpsCockpitQueuePanel
            ariaLabel="Audit export queue summary"
            title="Queued audit exports"
            badge={`${queuedAuditExports.length}`}
          >
            {auditExportMutationNotice ? (
              <p className="dashboard-pagination-note">{auditExportMutationNotice}</p>
            ) : null}
            {auditExportMutationErrorMessage ? (
              <p className="dashboard-pagination-note">{auditExportMutationErrorMessage}</p>
            ) : null}
            {queuedAuditExports.length === 0 ? (
              <p className="dashboard-pagination-note">No queued or processing audit exports.</p>
            ) : (
              <ul className="dashboard-view-list">
                {queuedAuditExports.slice(0, 6).map((row) => (
                  <li key={row.id}>
                    Export <code>{row.id}</code> is <strong>{row.status}</strong> ({row.format})
                    since {formatTimestamp(row.createdAt)}{' '}
                    <button
                      type="button"
                      className="dashboard-inline-link"
                      onClick={() => onRequeueAuditExport(row.id)}
                      disabled={requeueingAuditExportId === row.id}
                    >
                      {requeueingAuditExportId === row.id ? 'Requeueing...' : 'Requeue'}
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </OpsCockpitQueuePanel>
        ) : null}
      </div>
    </div>
  );
}
