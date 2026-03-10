import React from 'react';
import { useSiteRouter } from '@/app/router/useSiteRouter';
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
  const normalized = String(value || '').trim();
  if (!normalized) return '-';
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
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
  const detail = status.message ? `: ${status.message}` : '';
  if (status.state === 'not_configured') return `${label} is not configured${detail}`;
  if (status.state === 'forbidden') return `${label} is not available for this role${detail}`;
  return `${label} failed${detail}`;
}

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

function OpsCockpitStatusPanel(props: {
  ariaLabel: string;
  title: string;
  detail?: string;
}): React.JSX.Element {
  const { ariaLabel, title, detail } = props;
  return (
    <OpsCockpitQueuePanel ariaLabel={ariaLabel} title={title} badge="!">
      <p className="dashboard-pagination-note">
        {String(detail || '').trim() || 'This queue is not configured for the current server.'}
      </p>
    </OpsCockpitQueuePanel>
  );
}

export function OpsCockpitPage(): React.JSX.Element {
  const { go } = useSiteRouter();
  const session = useDashboardConsoleSession();
  const pendingApprovalsSectionRef = React.useRef<HTMLElement | null>(null);

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
        toSectionWarning('Enterprise isolation queue', summary.enterpriseIsolation.status),
        toSectionWarning('Onboarding telemetry', summary.onboardingTelemetry.status),
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
  const activeIsolation = summary?.enterpriseIsolation.activeRequests[0] || null;
  const onboardingAlerts = summary?.onboardingTelemetry.alerts || [];
  const auditExportsNotConfigured = summary?.auditExports.status.state === 'not_configured';
  const enterpriseIsolationNotConfigured =
    summary?.enterpriseIsolation.status.state === 'not_configured';
  const summaryWarnings = data.warnings.filter(
    (warning) =>
      !warning.startsWith('Audit export queue is not configured') &&
      !warning.startsWith('Enterprise isolation queue is not configured'),
  );

  const summaryCards = [
    {
      title: 'Pending approvals',
      value: summary?.approvals.pendingCount || 0,
      description: 'Requests awaiting approval decisions.',
      actionLabel: 'View pending',
      action: () =>
        pendingApprovalsSectionRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }),
    },
    {
      title: 'Failed or overdue invoices',
      value: summary?.billing.failedInvoiceCount || 0,
      description: 'Uncollectible invoices and overdue open balances.',
      actionLabel: 'Open invoices',
      action: () => go('/dashboard/invoices'),
    },
    {
      title: 'Failed webhooks',
      value: summary?.webhooks.deadLetterCount || 0,
      description: 'Unresolved dead-letter deliveries across webhook endpoints.',
      actionLabel: 'Open webhooks',
      action: () => go('/dashboard/webhooks'),
    },
    {
      title: 'Queued audit exports',
      value: summary?.auditExports.queuedExportCount || 0,
      description: 'Evidence exports waiting or processing.',
      actionLabel: 'Open audit',
      action: () => go('/dashboard/audit'),
    },
    {
      title: 'Isolation requests',
      value: summary?.enterpriseIsolation.activeRequestCount || 0,
      description: 'Org isolation currently in REQUESTED or MIGRATING state.',
      actionLabel: 'Open migration plan',
      action: () => go('/dashboard/integrations/self-hosting'),
    },
    {
      title: 'Onboarding SLO alerts',
      value: summary?.onboardingTelemetry.alertCount || 0,
      description: 'Active onboarding latency/error-rate SLO breaches.',
      actionLabel: 'Open onboarding',
      action: () => go('/dashboard/onboarding'),
    },
  ];

  return (
    <div className="dashboard-view dashboard-ops-cockpit-view" aria-label="Ops cockpit page">
      <section
        className="dashboard-view__section dashboard-ops-cockpit-summary--plain"
        aria-label="Ops cockpit summary"
      >
        <p>
          Daily queues for approvals, billing, webhooks, audit exports, isolation, and onboarding
          alerts.
        </p>
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

        <div className="dashboard-view-grid dashboard-view-grid--two">
          {summaryCards.map((card) => (
            <article key={card.title} className="dashboard-view-card">
              <h2>{card.title}</h2>
              <p className="dashboard-empty-state">{card.value}</p>
              <p className="dashboard-pagination-note">{card.description}</p>
              <button type="button" className="dashboard-pagination-button" onClick={card.action}>
                {card.actionLabel}
              </button>
            </article>
          ))}
        </div>
      </section>

      <section
        ref={pendingApprovalsSectionRef}
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

        {auditExportsNotConfigured ? (
          <OpsCockpitStatusPanel
            ariaLabel="Audit export queue status"
            title="Audit export queue is not configured"
            detail={summary?.auditExports.status.message}
          />
        ) : (
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
        )}

        {enterpriseIsolationNotConfigured ? (
          <>
            <OpsCockpitStatusPanel
              ariaLabel="Enterprise isolation queue status"
              title="Enterprise isolation queue is not configured"
              detail={summary?.enterpriseIsolation.status.message}
            />
            <OpsCockpitQueuePanel
              ariaLabel="Onboarding telemetry summary"
              title="Onboarding telemetry"
              badge={`${onboardingAlerts.length}`}
            >
              <p className="dashboard-pagination-note">
                Onboarding telemetry window:{' '}
                <strong>
                  {summary?.onboardingTelemetry
                    ? `${summary.onboardingTelemetry.windowMinutes}m`
                    : '-'}
                </strong>
              </p>
              {onboardingAlerts.length === 0 ? (
                <p className="dashboard-pagination-note">No active onboarding SLO alerts.</p>
              ) : (
                <ul className="dashboard-view-list">
                  {onboardingAlerts.map((alert, index) => (
                    <li key={`${alert.code}:${alert.operation}:${index}`}>
                      <strong>{alert.severity}</strong> {alert.code} on{' '}
                      <code>{alert.operation}</code>: {alert.message}
                    </li>
                  ))}
                </ul>
              )}
            </OpsCockpitQueuePanel>
          </>
        ) : (
          <OpsCockpitQueuePanel
            ariaLabel="Isolation and onboarding telemetry summary"
            title="Isolation + onboarding telemetry"
            badge={`${(activeIsolation ? 1 : 0) + onboardingAlerts.length}`}
          >
            <p className="dashboard-pagination-note">
              Isolation status:{' '}
              <strong>{activeIsolation ? activeIsolation.status : 'No pending request'}</strong>
              {activeIsolation ? ` (${activeIsolation.trigger || 'unknown trigger'})` : ''}
            </p>
            <p className="dashboard-pagination-note">
              Onboarding telemetry window:{' '}
              <strong>
                {summary?.onboardingTelemetry
                  ? `${summary.onboardingTelemetry.windowMinutes}m`
                  : '-'}
              </strong>
            </p>
            {onboardingAlerts.length === 0 ? (
              <p className="dashboard-pagination-note">No active onboarding SLO alerts.</p>
            ) : (
              <ul className="dashboard-view-list">
                {onboardingAlerts.map((alert, index) => (
                  <li key={`${alert.code}:${alert.operation}:${index}`}>
                    <strong>{alert.severity}</strong> {alert.code} on <code>{alert.operation}</code>
                    : {alert.message}
                  </li>
                ))}
              </ul>
            )}
          </OpsCockpitQueuePanel>
        )}
      </div>
    </div>
  );
}
