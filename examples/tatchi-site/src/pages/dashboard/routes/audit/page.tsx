import React from 'react';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableBadge,
  DashboardTableCell,
  DashboardTableDetailsGrid,
  DashboardTableDetailsItem,
  DashboardTableDetailsPanel,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  DashboardTableStatus,
  dashboardTableColumns,
  useDashboardTablePagination,
  type DashboardTableTone,
} from '../../components/DashboardTable';
import {
  useDashboardConsoleSession,
  type DashboardConsoleSessionClaims,
} from '../../consoleSession';
import {
  useDashboardSelectedContext,
  useDashboardSelectedContextDisplay,
} from '../../selectedContext';
import {
  listDashboardEnvironments,
  listDashboardProjects,
} from '../../consoleContextApi';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import {
  listDashboardAuditEvents,
  type DashboardConsoleAuditCategory,
  type DashboardConsoleAuditEvent,
  type DashboardConsoleAuditOutcome,
} from './consoleAuditApi';
import { listDashboardApprovals, type DashboardConsoleApprovalRequest } from '../approvals/consoleApprovalsApi';
import { listDashboardTeamMembers } from '../team-members/consoleTeamRbacApi';
import {
  resolveDashboardIdentityPrimaryLabel,
  type DashboardIdentitySource,
} from '../../utils/userIdentity';

const CATEGORY_OPTIONS: readonly DashboardConsoleAuditCategory[] = [
  'POLICY',
  'SETTINGS',
  'KEY_EXPORT',
  'BILLING',
  'WEBHOOK',
  'API_KEY',
  'TEAM',
  'APPROVAL',
  'ORG_PROJECT_ENV',
  'RUNTIME_SNAPSHOT',
  'SYSTEM',
];

const OUTCOME_OPTIONS: readonly DashboardConsoleAuditOutcome[] = ['SUCCESS', 'FAILURE', 'PENDING'];
const AUDIT_EVENTS_TABLE_COLUMNS = dashboardTableColumns(1.05, 2.1, 0.95, 1.1, 0.8, 0.75);
const AUDIT_EVENTS_LIMIT = 100;

function formatTimestamp(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function toIsoTimestamp(value: string): string | undefined {
  const normalized = String(value || '').trim();
  if (!normalized) return undefined;
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) return undefined;
  return date.toISOString();
}

function readText(value: unknown): string {
  return String(value || '').trim();
}

function humanizeMachineLabel(value: string): string {
  const tokens = readText(value)
    .split(/[._\-\s]+/g)
    .map((entry) => entry.trim())
    .filter(Boolean)
    .map((entry) => {
      const normalized = entry.toLowerCase();
      if (normalized === 'api' || normalized === 'id' || normalized === 'mfa') {
        return normalized.toUpperCase();
      }
      return normalized;
    });
  if (tokens.length === 0) return '';
  const [first, ...rest] = tokens;
  const firstWord = first === first.toUpperCase() ? first : `${first.charAt(0).toUpperCase()}${first.slice(1)}`;
  return [firstWord, ...rest].join(' ');
}

function formatPolicyKindLabel(value: string): string {
  const normalized = readText(value).toUpperCase();
  if (normalized === 'GAS_SPONSORSHIP') return 'Gas sponsorship';
  if (normalized === 'TRANSACTION') return 'Transaction';
  return humanizeMachineLabel(value);
}

function formatVersionLabel(value: unknown): string {
  const version = Number(value);
  if (!Number.isFinite(version) || version < 0) return '';
  return `v${Math.floor(version)}`;
}

function formatAmountMinorLabel(amountMinorRaw: unknown, currencyRaw: unknown): string {
  const amountMinor = Number(amountMinorRaw);
  const currency = readText(currencyRaw).toUpperCase() || 'USD';
  if (!Number.isFinite(amountMinor)) return '';
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency',
      currency,
    }).format(amountMinor / 100);
  } catch {
    return `${(amountMinor / 100).toFixed(2)} ${currency}`;
  }
}

function appendDetail(details: string[], value: unknown): void {
  const normalized = readText(value);
  if (!normalized || details.includes(normalized)) return;
  details.push(normalized);
}

function readFirstText(...values: unknown[]): string {
  for (const value of values) {
    const normalized = readText(value);
    if (normalized) return normalized;
  }
  return '';
}

function buildDashboardPath(basePath: string, query: Record<string, unknown>): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    const normalized = readText(value);
    if (!normalized) continue;
    searchParams.set(key, normalized);
  }
  const queryString = searchParams.toString();
  return queryString ? `${basePath}?${queryString}` : basePath;
}

function formatPolicyAuditEventTitle(row: DashboardConsoleAuditEvent): {
  title: string;
  detailParts: string[];
} | null {
  const action = readText(row.action).toLowerCase();
  if (!action.startsWith('policy.')) return null;

  const policyName = readText(row.policyName) || readText(row.metadata?.policyName);
  const policyKind = formatPolicyKindLabel(readText(row.policyKind) || readText(row.metadata?.policyKind));
  const versionLabel = formatVersionLabel(row.metadata?.version);
  const details: string[] = [];

  if (action === 'policy.create') {
    appendDetail(details, policyName);
    appendDetail(details, policyKind);
    appendDetail(details, versionLabel);
    return {
      title: 'Created policy',
      detailParts: details,
    };
  }

  if (action === 'policy.update') {
    appendDetail(details, policyName);
    appendDetail(details, policyKind);
    appendDetail(details, versionLabel);
    return {
      title: 'Updated policy',
      detailParts: details,
    };
  }

  if (action === 'policy.delete') {
    appendDetail(details, policyName);
    appendDetail(details, policyKind);
    appendDetail(details, versionLabel);
    return {
      title: 'Deleted policy',
      detailParts: details,
    };
  }

  if (action === 'policy.publish') {
    appendDetail(details, policyName);
    appendDetail(details, policyKind);
    appendDetail(details, versionLabel);
    appendDetail(details, readText(row.metadata?.status));
    return {
      title: 'Published policy',
      detailParts: details,
    };
  }

  if (action === 'policy.assignment.upsert') {
    appendDetail(details, policyName);
    appendDetail(details, policyKind);
    appendDetail(details, humanizeMachineLabel(readText(row.metadata?.assignmentScopeType)));
    return {
      title: 'Updated policy assignment',
      detailParts: details,
    };
  }

  if (action === 'policy.assignment.delete') {
    appendDetail(details, policyName);
    appendDetail(details, policyKind);
    appendDetail(details, humanizeMachineLabel(readText(row.metadata?.assignmentScopeType)));
    return {
      title: 'Removed policy assignment',
      detailParts: details,
    };
  }

  return null;
}

function formatBillingAuditEventTitle(row: DashboardConsoleAuditEvent): {
  title: string;
  detailParts: string[];
} | null {
  const action = readText(row.action).toLowerCase();
  if (!action.startsWith('billing.')) return null;

  const details: string[] = [];

  if (action === 'billing.credit_purchase.settled') {
    appendDetail(details, readText(row.metadata?.purchaseId));
    appendDetail(
      details,
      formatAmountMinorLabel(row.metadata?.amountMinor, row.metadata?.currency),
    );
    appendDetail(details, readText(row.metadata?.receiptId));
    appendDetail(details, readText(row.metadata?.providerCheckoutSessionRef));
    appendDetail(details, humanizeMachineLabel(readText(row.metadata?.settlementSource)));
    return {
      title: 'Settled Stripe credit purchase',
      detailParts: details,
    };
  }

  if (action === 'billing.invoice.generated') {
    appendDetail(details, readText(row.metadata?.invoiceId));
    appendDetail(details, readText(row.metadata?.periodMonthUtc));
    appendDetail(
      details,
      formatAmountMinorLabel(row.metadata?.amountDueMinor, row.metadata?.currency),
    );
    appendDetail(details, humanizeMachineLabel(readText(row.metadata?.invoiceDocumentType)));
    return {
      title: readText(row.metadata?.generated) === 'true' ? 'Generated invoice' : 'Refreshed invoice',
      detailParts: details,
    };
  }

  if (action === 'billing.invoice.pdf_export') {
    appendDetail(details, readText(row.metadata?.invoiceId));
    appendDetail(details, readText(row.metadata?.periodMonthUtc));
    return {
      title: 'Exported invoice PDF',
      detailParts: details,
    };
  }

  if (action === 'billing.adjustment.support_credit') {
    appendDetail(
      details,
      formatAmountMinorLabel(row.metadata?.amountMinor, row.metadata?.currency),
    );
    appendDetail(details, readText(row.metadata?.reasonCode));
    appendDetail(details, readText(row.metadata?.adjustmentId));
    return {
      title: 'Granted support credit',
      detailParts: details,
    };
  }

  if (action === 'billing.adjustment.admin_debit') {
    appendDetail(
      details,
      formatAmountMinorLabel(row.metadata?.amountMinor, row.metadata?.currency),
    );
    appendDetail(details, readText(row.metadata?.reasonCode));
    appendDetail(details, readText(row.metadata?.adjustmentId));
    return {
      title: 'Applied admin debit',
      detailParts: details,
    };
  }

  return null;
}

function formatWebhookAuditEventTitle(row: DashboardConsoleAuditEvent): {
  title: string;
  detailParts: string[];
} | null {
  const action = readText(row.action).toLowerCase();
  if (!action.startsWith('webhook.')) return null;
  const details: string[] = [];
  appendDetail(details, readText(row.metadata?.endpointId));
  appendDetail(details, readText(row.metadata?.deliveryId));

  if (action === 'webhook.endpoint.create') {
    return { title: 'Created webhook endpoint', detailParts: details };
  }
  if (action === 'webhook.endpoint.update') {
    return { title: 'Updated webhook endpoint', detailParts: details };
  }
  if (action === 'webhook.endpoint.delete') {
    return { title: 'Deleted webhook endpoint', detailParts: details };
  }
  if (action === 'webhook.delivery.replay_requested') {
    return { title: 'Requested webhook replay', detailParts: details };
  }
  return null;
}

function formatAuditEventTitle(row: DashboardConsoleAuditEvent): {
  title: string;
  detailParts: string[];
} {
  const action = readText(row.action).toLowerCase();
  const approvalId = readText(row.metadata?.approvalId);
  const operationType = readText(row.metadata?.operationType);
  if (action.startsWith('approval.request.')) {
    const verb =
      action === 'approval.request.create'
        ? 'Created'
        : action === 'approval.request.approve'
          ? 'Approved'
          : action === 'approval.request.reject'
            ? 'Rejected'
            : 'Updated';
    return {
      title: `${verb} approval request`,
      detailParts: [humanizeMachineLabel(operationType), approvalId].filter(Boolean),
    };
  }

  const policyDisplay = formatPolicyAuditEventTitle(row);
  if (policyDisplay) return policyDisplay;

  const billingDisplay = formatBillingAuditEventTitle(row);
  if (billingDisplay) return billingDisplay;

  const webhookDisplay = formatWebhookAuditEventTitle(row);
  if (webhookDisplay) return webhookDisplay;

  const title = readText(row.summary) || humanizeMachineLabel(row.action) || row.id;
  const detail = humanizeMachineLabel(row.action);
  return {
    title,
    detailParts: detail && detail.toLowerCase() !== title.toLowerCase() ? [detail] : [],
  };
}

function formatAuditActor(
  row: DashboardConsoleAuditEvent,
  memberDirectory: Record<string, DashboardIdentitySource>,
  sessionClaims: DashboardConsoleSessionClaims | null,
): {
  primary: string;
  secondary: string;
} {
  const userId = readText(row.actorUserId);
  const identity = memberDirectory[userId] || { userId };
  const primary = resolveDashboardIdentityPrimaryLabel(identity, sessionClaims);
  if (row.actorType === 'SYSTEM') {
    return {
      primary,
      secondary: 'System',
    };
  }
  return {
    primary,
    secondary: userId && userId !== primary ? userId : '',
  };
}

function outcomeTone(outcome: DashboardConsoleAuditOutcome): DashboardTableTone {
  if (outcome === 'SUCCESS') return 'success';
  if (outcome === 'FAILURE') return 'danger';
  return 'warning';
}

function resolveAuditProjectLabel(input: {
  projectId: string;
  projectDirectory: Record<string, string>;
  selectedProjectId: string;
  selectedProjectLabel: string;
}): string {
  if (!input.projectId) return '-';
  if (input.projectDirectory[input.projectId]) return input.projectDirectory[input.projectId]!;
  if (input.selectedProjectId === input.projectId && input.selectedProjectLabel) {
    return input.selectedProjectLabel;
  }
  return input.projectId;
}

function resolveAuditEnvironmentLabel(input: {
  environmentId: string;
  environmentDirectory: Record<string, string>;
  selectedEnvironmentId: string;
  selectedEnvironmentLabel: string;
}): string {
  if (!input.environmentId) return '-';
  if (input.environmentDirectory[input.environmentId]) {
    return input.environmentDirectory[input.environmentId]!;
  }
  if (input.selectedEnvironmentId === input.environmentId && input.selectedEnvironmentLabel) {
    return input.selectedEnvironmentLabel;
  }
  return input.environmentId;
}

function resolveAuditScopeLabels(input: {
  row: DashboardConsoleAuditEvent;
  projectDirectory: Record<string, string>;
  environmentDirectory: Record<string, string>;
  selectedProjectId: string;
  selectedProjectLabel: string;
  selectedEnvironmentId: string;
  selectedEnvironmentLabel: string;
}): {
  projectLabel: string;
  environmentLabel: string;
} {
  const projectId = readText(input.row.projectId);
  const environmentId = readText(input.row.environmentId);
  const projectLabel = projectId
    ? resolveAuditProjectLabel({
        projectId,
        projectDirectory: input.projectDirectory,
        selectedProjectId: input.selectedProjectId,
        selectedProjectLabel: input.selectedProjectLabel,
      })
    : '';
  const environmentLabel = environmentId
    ? resolveAuditEnvironmentLabel({
        environmentId,
        environmentDirectory: input.environmentDirectory,
        selectedEnvironmentId: input.selectedEnvironmentId,
        selectedEnvironmentLabel: input.selectedEnvironmentLabel,
      })
    : '';
  return {
    projectLabel,
    environmentLabel,
  };
}

function parseAuditEventTimestamp(value: string): number {
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function isOrgScopedAuditEvent(row: DashboardConsoleAuditEvent): boolean {
  return !readText(row.projectId) && !readText(row.environmentId);
}

function mergeAuditEvents(
  batches: ReadonlyArray<ReadonlyArray<DashboardConsoleAuditEvent>>,
): DashboardConsoleAuditEvent[] {
  const deduped = new Map<string, DashboardConsoleAuditEvent>();
  for (const batch of batches) {
    for (const row of batch) {
      const id = readText(row.id);
      if (!id || deduped.has(id)) continue;
      deduped.set(id, row);
    }
  }
  return [...deduped.values()]
    .sort((a, b) => {
      const tsDiff = parseAuditEventTimestamp(b.createdAt) - parseAuditEventTimestamp(a.createdAt);
      if (tsDiff !== 0) return tsDiff;
      return b.id.localeCompare(a.id);
    })
    .slice(0, AUDIT_EVENTS_LIMIT);
}

function renderAuditLinkedIdentifier(input: {
  id: string;
  label?: string;
  href?: string;
  onClick?: React.MouseEventHandler<HTMLAnchorElement>;
}): React.JSX.Element {
  const id = readText(input.id);
  if (!id) return <span>-</span>;
  const label = readText(input.label) || id;
  return (
    <div>
      {input.href ? (
        <a className="dashboard-inline-link" href={input.href} onClick={input.onClick} title={id}>
          {label}
        </a>
      ) : (
        <span>{label}</span>
      )}
      {label !== id ? (
        <>
          <br />
          <code>{id}</code>
        </>
      ) : null}
    </div>
  );
}

export function AuditLogsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const selectedContextDisplay = useDashboardSelectedContextDisplay();
  const { linkProps } = useSiteRouter();
  const selectedProjectId = String(selectedContext.project || '').trim();
  const selectedEnvironmentId = String(selectedContext.environment || '').trim();
  const selectedProjectLabel = String(selectedContextDisplay.project || '').trim();
  const selectedEnvironmentLabel = String(selectedContextDisplay.environment || '').trim();

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [events, setEvents] = React.useState<DashboardConsoleAuditEvent[]>([]);
  const [searchInput, setSearchInput] = React.useState<string>('');
  const [debouncedSearchInput, setDebouncedSearchInput] = React.useState<string>('');
  const [eventCategoryFilter, setEventCategoryFilter] = React.useState<string>('');
  const [eventOutcomeFilter, setEventOutcomeFilter] = React.useState<string>('');
  const [fromInput, setFromInput] = React.useState<string>('');
  const [toInput, setToInput] = React.useState<string>('');
  const [expandedEventId, setExpandedEventId] = React.useState<string>('');
  const [memberDirectory, setMemberDirectory] = React.useState<Record<string, DashboardIdentitySource>>(
    {},
  );
  const [projectDirectory, setProjectDirectory] = React.useState<Record<string, string>>({});
  const [environmentDirectory, setEnvironmentDirectory] = React.useState<Record<string, string>>({});
  const [approvalDirectory, setApprovalDirectory] = React.useState<
    Record<string, DashboardConsoleApprovalRequest>
  >({});
  const [copyNotice, setCopyNotice] = React.useState<string>('');
  const eventsPagination = useDashboardTablePagination(events, {
    disabled: loading,
    initialRowsPerPage: 10,
    itemLabel: 'event',
    itemLabelPlural: 'events',
  });
  const setEventsPage = eventsPagination.setPage;
  const auditTablePagination = React.useMemo(
    () => ({
      ...eventsPagination.pagination,
      onPageChange: (page: number) => {
        setExpandedEventId('');
        eventsPagination.setPage(page);
      },
      onRowsPerPageChange: (rowsPerPage: number) => {
        setExpandedEventId('');
        eventsPagination.setRowsPerPage(rowsPerPage);
      },
    }),
    [eventsPagination, setExpandedEventId],
  );

  React.useEffect(() => {
    const timeoutId = window.setTimeout(() => {
      setDebouncedSearchInput(String(searchInput || '').trim());
    }, 250);
    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [searchInput]);

  React.useEffect(() => {
    if (!copyNotice) return;
    const timeoutId = window.setTimeout(() => {
      setCopyNotice('');
    }, 1800);
    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [copyNotice]);

  React.useEffect(() => {
    if (session.loading) return;
    if (!session.claims) {
      setMemberDirectory({});
      return;
    }
    let cancelled = false;
    listDashboardTeamMembers()
      .then((members) => {
        if (cancelled) return;
        const nextDirectory: Record<string, DashboardIdentitySource> = {};
        for (const member of members) {
          const userId = readText(member.userId);
          if (!userId) continue;
          nextDirectory[userId] = {
            userId,
            email: readText(member.email),
            displayName: readText(member.displayName),
          };
        }
        setMemberDirectory(nextDirectory);
      })
      .catch(() => {
        if (cancelled) return;
        setMemberDirectory({});
      });
    return () => {
      cancelled = true;
    };
  }, [session.claims?.orgId, session.loading]);

  React.useEffect(() => {
    if (session.loading) return;
    if (!session.claims) {
      setApprovalDirectory({});
      return;
    }
    let cancelled = false;
    listDashboardApprovals({
      ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
      ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
    })
      .then((approvals) => {
        if (cancelled) return;
        const nextDirectory: Record<string, DashboardConsoleApprovalRequest> = {};
        for (const approval of approvals) {
          const approvalId = readText(approval.id);
          if (!approvalId) continue;
          nextDirectory[approvalId] = approval;
        }
        setApprovalDirectory(nextDirectory);
      })
      .catch(() => {
        if (cancelled) return;
        setApprovalDirectory({});
      });
    return () => {
      cancelled = true;
    };
  }, [selectedEnvironmentId, selectedProjectId, session.claims?.orgId, session.loading]);

  React.useEffect(() => {
    if (session.loading) return;
    if (!session.claims) {
      setProjectDirectory({});
      setEnvironmentDirectory({});
      return;
    }
    let cancelled = false;
    Promise.allSettled([
      listDashboardProjects(),
      listDashboardEnvironments(selectedProjectId ? { projectId: selectedProjectId } : {}),
    ])
      .then((results) => {
        if (cancelled) return;
        const projects =
          results[0]?.status === 'fulfilled' && Array.isArray(results[0].value) ? results[0].value : [];
        const environments =
          results[1]?.status === 'fulfilled' && Array.isArray(results[1].value) ? results[1].value : [];
        const nextProjects: Record<string, string> = {};
        for (const project of projects) {
          const projectId = readText(project.id);
          if (!projectId) continue;
          nextProjects[projectId] = readText(project.name) || projectId;
        }
        const nextEnvironments: Record<string, string> = {};
        for (const environment of environments) {
          const environmentId = readText(environment.id);
          if (!environmentId) continue;
          nextEnvironments[environmentId] = readText(environment.name) || environmentId;
        }
        setProjectDirectory(nextProjects);
        setEnvironmentDirectory(nextEnvironments);
      })
      .catch(() => {
        if (cancelled) return;
      });
    return () => {
      cancelled = true;
    };
  }, [selectedProjectId, session.claims?.orgId, session.loading]);

  const copyAuditScopeValue = React.useCallback(async (value: string, label: 'Project' | 'Environment') => {
    const normalized = readText(value);
    if (!normalized) return;
    try {
      if (!window.navigator?.clipboard?.writeText) {
        throw new Error('clipboard_unavailable');
      }
      await window.navigator.clipboard.writeText(normalized);
      setCopyNotice(`${label} ID copied.`);
    } catch {
      setCopyNotice(`Clipboard copy failed. Copy ${label.toLowerCase()} ID manually.`);
    }
  }, []);

  const loadAuditEvents = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setEvents([]);
      setEventsPage(1);
      setExpandedEventId('');
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }

    let cancelled = false;
    setLoading(true);
    setErrorMessage('');

    const baseRequest = {
      ...(eventCategoryFilter
        ? { category: eventCategoryFilter as DashboardConsoleAuditCategory }
        : {}),
      ...(eventOutcomeFilter
        ? { outcome: eventOutcomeFilter as DashboardConsoleAuditOutcome }
        : {}),
      ...(debouncedSearchInput ? { q: debouncedSearchInput } : {}),
      ...(toIsoTimestamp(fromInput) ? { from: toIsoTimestamp(fromInput) } : {}),
      ...(toIsoTimestamp(toInput) ? { to: toIsoTimestamp(toInput) } : {}),
      limit: AUDIT_EVENTS_LIMIT,
    };
    const scopedRequest = {
      ...baseRequest,
      ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
      ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
    };
    const shouldIncludeOrgScopedRows = Boolean(selectedProjectId || selectedEnvironmentId);
    const request = shouldIncludeOrgScopedRows
      ? Promise.all([
          listDashboardAuditEvents(scopedRequest),
          listDashboardAuditEvents(baseRequest).then((rows) => rows.filter(isOrgScopedAuditEvent)),
        ]).then(([scopedRows, orgScopedRows]) => mergeAuditEvents([scopedRows, orgScopedRows]))
      : listDashboardAuditEvents(scopedRequest);

    request
      .then((nextEvents) => {
        if (cancelled) return;
        setEvents(nextEvents);
        setEventsPage(1);
        setExpandedEventId('');
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setEvents([]);
        setEventsPage(1);
        setExpandedEventId('');
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [
    debouncedSearchInput,
    eventCategoryFilter,
    eventOutcomeFilter,
    setEventsPage,
    fromInput,
    selectedEnvironmentId,
    selectedProjectId,
    session.claims,
    session.errorMessage,
    toInput,
  ]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadAuditEvents();
    return cleanup;
  }, [loadAuditEvents, session.loading]);

  return (
    <div className="dashboard-view" aria-label="Audit logs page">
      <section
        className="dashboard-view__section dashboard-audit-section--plain"
        aria-label="Audit event filters"
      >
        <section className="dashboard-audit-filter-group" aria-label="Event filters">
          <div className="dashboard-view-grid dashboard-view-grid--two dashboard-audit-controls-grid">
            <div className="dashboard-form-field dashboard-form-field--full">
              <input
                className="dashboard-input dashboard-input--audit"
                aria-label="Search events"
                value={searchInput}
                onChange={(event) => setSearchInput(event.target.value)}
                placeholder="Search user id, action, summary, event id, approval id, API key id, metadata"
              />
            </div>
            <label className="dashboard-form-field dashboard-form-field--audit-inline dashboard-form-field--full">
              <span>Category</span>
              <select
                className="dashboard-select dashboard-select--audit"
                value={eventCategoryFilter}
                onChange={(event) => setEventCategoryFilter(event.target.value)}
              >
                <option value="">All categories</option>
                {CATEGORY_OPTIONS.map((entry) => (
                  <option key={entry} value={entry}>
                    {entry}
                  </option>
                ))}
              </select>
            </label>

            <label className="dashboard-form-field dashboard-form-field--audit-inline dashboard-form-field--full">
              <span>Outcome</span>
              <select
                className="dashboard-select dashboard-select--audit"
                value={eventOutcomeFilter}
                onChange={(event) => setEventOutcomeFilter(event.target.value)}
              >
                <option value="">All outcomes</option>
                {OUTCOME_OPTIONS.map((entry) => (
                  <option key={entry} value={entry}>
                    {entry}
                  </option>
                ))}
              </select>
            </label>

            <label className="dashboard-form-field dashboard-form-field--audit-inline dashboard-form-field--audit-period dashboard-form-field--full">
              <span>Period</span>
              <div className="dashboard-audit-period-inputs">
                <input
                  className="dashboard-input dashboard-input--audit"
                  type="datetime-local"
                  aria-label="Period start"
                  value={fromInput}
                  onChange={(event) => setFromInput(event.target.value)}
                />
                <span className="dashboard-audit-period-separator" aria-hidden="true">
                  to
                </span>
                <input
                  className="dashboard-input dashboard-input--audit"
                  type="datetime-local"
                  aria-label="Period end"
                  value={toInput}
                  onChange={(event) => setToInput(event.target.value)}
                />
              </div>
            </label>
          </div>
        </section>

        {errorMessage ? <p className="dashboard-pagination-note">{errorMessage}</p> : null}
      </section>

      <section
        className="dashboard-view__section dashboard-audit-section--plain"
        aria-label="Audit events table"
      >
        <h2>Events</h2>
        <DashboardTable
          ariaLabel="Audit events"
          columns={AUDIT_EVENTS_TABLE_COLUMNS}
          pagination={auditTablePagination}
        >
          <DashboardTableHeader>
            <DashboardTableHeaderCell>Timestamp</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Event</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>User</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Scope</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Outcome</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Details</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {events.length === 0 ? (
            <DashboardTableState>
              {loading
                ? 'Loading audit events...'
                : 'No audit events matched the current scope and filters.'}
            </DashboardTableState>
          ) : (
            eventsPagination.rows.map((row) => {
              const isExpanded = expandedEventId === row.id;
              const eventDisplay = formatAuditEventTitle(row);
              const actorDisplay = formatAuditActor(row, memberDirectory, session.claims);
              const scopeDisplay = resolveAuditScopeLabels({
                row,
                projectDirectory,
                environmentDirectory,
                selectedProjectId,
                selectedProjectLabel,
                selectedEnvironmentId,
                selectedEnvironmentLabel,
              });
              const actorUserId = readText(row.actorUserId);
              const approvalId = readText(row.metadata?.approvalId);
              const approval = approvalId ? approvalDirectory[approvalId] : null;
              const linkedPolicyId = readFirstText(
                row.policyId,
                row.metadata?.policyId,
                approval?.policyId,
                approval?.resourceId,
              );
              const linkedPolicyLabel =
                readFirstText(row.policyName, row.metadata?.policyName, approval?.policyName) ||
                linkedPolicyId;
              const policyLink = linkedPolicyId
                ? linkProps(buildDashboardPath('/dashboard/policy-engine', { policyId: linkedPolicyId }))
                : null;
              const approvalLink =
                approvalId && linkedPolicyId
                  ? linkProps(
                      buildDashboardPath('/dashboard/policy-engine', {
                        policyId: linkedPolicyId,
                        approvalId,
                      }),
                    )
                  : null;
              const invoiceId = readText(row.metadata?.invoiceId);
              const invoiceLink = invoiceId
                ? linkProps(`/dashboard/invoices/${encodeURIComponent(invoiceId)}`)
                : null;
              const receiptId = readText(row.metadata?.receiptId);
              const receiptLink = receiptId
                ? linkProps(`/dashboard/invoices/${encodeURIComponent(receiptId)}`)
                : null;
              const purchaseId = readText(row.metadata?.purchaseId);
              const webhookEndpointId = readText(row.metadata?.endpointId);
              const webhookDeliveryId = readText(row.metadata?.deliveryId);
              const webhookEndpointLink = webhookEndpointId
                ? linkProps(
                    buildDashboardPath('/dashboard/webhooks', {
                      endpointId: webhookEndpointId,
                    }),
                  )
                : null;
              const webhookDeliveryLink =
                webhookEndpointId && webhookDeliveryId
                  ? linkProps(
                      buildDashboardPath('/dashboard/webhooks', {
                        endpointId: webhookEndpointId,
                        deliveryId: webhookDeliveryId,
                      }),
                    )
                  : null;
              const scopeType =
                readFirstText(row.metadata?.scopeType, row.metadata?.assignmentScopeType) ||
                (readText(row.environmentId)
                  ? 'ENVIRONMENT'
                  : readText(row.projectId)
                    ? 'PROJECT'
                    : 'ORG');
              const scopeId =
                readFirstText(
                  row.metadata?.scopeId,
                  row.metadata?.assignmentScopeId,
                  row.environmentId,
                  row.projectId,
                  row.orgId,
                ) || '';
              const projectLabel = row.projectId
                ? resolveAuditProjectLabel({
                    projectId: readText(row.projectId),
                    projectDirectory,
                    selectedProjectId,
                    selectedProjectLabel,
                  })
                : '';
              const environmentLabel = row.environmentId
                ? resolveAuditEnvironmentLabel({
                    environmentId: readText(row.environmentId),
                    environmentDirectory,
                    selectedEnvironmentId,
                    selectedEnvironmentLabel,
                  })
                : '';
              return (
                <React.Fragment key={row.id}>
                  <DashboardTableRow
                    className={
                      isExpanded
                        ? 'dashboard-audit-events__row dashboard-audit-events__row--expanded'
                        : 'dashboard-audit-events__row'
                    }
                  >
                    <DashboardTableCell truncate>
                      <span>{formatTimestamp(row.createdAt)}</span>
                    </DashboardTableCell>
                    <DashboardTableCell className="dashboard-data-table__cell--event">
                      <strong className="dashboard-data-table__summary">
                        {eventDisplay.title}
                      </strong>
                      <span className="dashboard-data-table__subline">
                        <DashboardTableBadge>{row.category}</DashboardTableBadge>
                        {eventDisplay.detailParts.map((detail, index) => (
                          <span key={`${detail}-${index}`}>{detail}</span>
                        ))}
                      </span>
                    </DashboardTableCell>
                    <DashboardTableCell>
                      <strong className="dashboard-data-table__summary">{actorDisplay.primary}</strong>
                      {actorDisplay.secondary ? (
                        <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                          {actorDisplay.secondary}
                        </span>
                      ) : null}
                    </DashboardTableCell>
                    <DashboardTableCell>
                      {scopeDisplay.projectLabel ? (
                        <span>
                          <strong>Project:</strong> {scopeDisplay.projectLabel}
                        </span>
                      ) : null}
                      {scopeDisplay.environmentLabel ? (
                        <span>
                          <strong>Env:</strong> {scopeDisplay.environmentLabel}
                        </span>
                      ) : null}
                      {!scopeDisplay.projectLabel && !scopeDisplay.environmentLabel ? (
                        <span>Organization</span>
                      ) : null}
                    </DashboardTableCell>
                    <DashboardTableCell>
                      <DashboardTableStatus tone={outcomeTone(row.outcome)}>
                        {row.outcome}
                      </DashboardTableStatus>
                    </DashboardTableCell>
                    <DashboardTableCell
                      className="dashboard-data-table__cell--details"
                      align="center"
                    >
                      <DashboardTableActionButton
                        className="dashboard-audit-events__toggle"
                        aria-expanded={isExpanded}
                        onClick={() =>
                          setExpandedEventId((current) => (current === row.id ? '' : row.id))
                        }
                      >
                        {isExpanded ? 'Hide' : 'View'}
                      </DashboardTableActionButton>
                    </DashboardTableCell>
                  </DashboardTableRow>
                  <DashboardTableDetailsPanel
                    className={
                      isExpanded
                        ? 'dashboard-audit-events__details-panel is-expanded'
                        : 'dashboard-audit-events__details-panel'
                    }
                    aria-hidden={!isExpanded}
                  >
                    <div className="dashboard-audit-events__details-content">
                      <DashboardTableDetailsGrid>
                        <DashboardTableDetailsItem label="Event ID">
                          <span>{row.id}</span>
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Action">
                          <span>{row.action || '-'}</span>
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Actor">
                          <span>{actorDisplay.primary || '-'}</span>
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Actor ID">
                          {actorUserId ? <code>{actorUserId}</code> : <span>-</span>}
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Actor Type">
                          <span>{row.actorType || '-'}</span>
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Policy">
                          {renderAuditLinkedIdentifier({
                            id: linkedPolicyId,
                            label: linkedPolicyLabel,
                            href: policyLink?.href,
                            onClick: policyLink?.onClick,
                          })}
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Approval">
                          {renderAuditLinkedIdentifier({
                            id: approvalId,
                            href: approvalLink?.href,
                            onClick: approvalLink?.onClick,
                          })}
                        </DashboardTableDetailsItem>
                        {purchaseId ? (
                          <DashboardTableDetailsItem label="Purchase">
                            <code>{purchaseId}</code>
                          </DashboardTableDetailsItem>
                        ) : null}
                        {invoiceId ? (
                          <DashboardTableDetailsItem label="Invoice">
                            {renderAuditLinkedIdentifier({
                              id: invoiceId,
                              href: invoiceLink?.href,
                              onClick: invoiceLink?.onClick,
                            })}
                          </DashboardTableDetailsItem>
                        ) : null}
                        {receiptId ? (
                          <DashboardTableDetailsItem label="Receipt">
                            {renderAuditLinkedIdentifier({
                              id: receiptId,
                              href: receiptLink?.href,
                              onClick: receiptLink?.onClick,
                            })}
                          </DashboardTableDetailsItem>
                        ) : null}
                        {webhookEndpointId ? (
                          <DashboardTableDetailsItem label="Webhook Endpoint">
                            {renderAuditLinkedIdentifier({
                              id: webhookEndpointId,
                              href: webhookEndpointLink?.href,
                              onClick: webhookEndpointLink?.onClick,
                            })}
                          </DashboardTableDetailsItem>
                        ) : null}
                        {webhookDeliveryId ? (
                          <DashboardTableDetailsItem label="Webhook Delivery">
                            {renderAuditLinkedIdentifier({
                              id: webhookDeliveryId,
                              href: webhookDeliveryLink?.href,
                              onClick: webhookDeliveryLink?.onClick,
                            })}
                          </DashboardTableDetailsItem>
                        ) : null}
                        <DashboardTableDetailsItem label="Scope Type">
                          <span>
                            {scopeType === 'ORG'
                              ? 'Organization'
                              : scopeType
                                ? humanizeMachineLabel(scopeType)
                                : 'Organization'}
                          </span>
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Scope ID">
                          {scopeId ? <code>{scopeId}</code> : <span>-</span>}
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Project">
                          {row.projectId ? (
                            <div>
                              <button
                                type="button"
                                className="dashboard-audit-events__copy-value"
                                title={row.projectId}
                                onClick={() => void copyAuditScopeValue(row.projectId || '', 'Project')}
                              >
                                {projectLabel}
                              </button>
                              {projectLabel !== readText(row.projectId) ? (
                                <>
                                  <br />
                                  <code>{row.projectId}</code>
                                </>
                              ) : null}
                            </div>
                          ) : (
                            <span>-</span>
                          )}
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Environment">
                          {row.environmentId ? (
                            <div>
                              <button
                                type="button"
                                className="dashboard-audit-events__copy-value"
                                title={row.environmentId}
                                onClick={() =>
                                  void copyAuditScopeValue(row.environmentId || '', 'Environment')
                                }
                              >
                                {environmentLabel}
                              </button>
                              {environmentLabel !== readText(row.environmentId) ? (
                                <>
                                  <br />
                                  <code>{row.environmentId}</code>
                                </>
                              ) : null}
                            </div>
                          ) : (
                            <span>-</span>
                          )}
                        </DashboardTableDetailsItem>
                      </DashboardTableDetailsGrid>
                      {copyNotice ? (
                        <p className="dashboard-pagination-note" aria-live="polite">
                          {copyNotice}
                        </p>
                      ) : null}
                      <pre className="dashboard-data-table__metadata-json">
                        {JSON.stringify(row.metadata, null, 2)}
                      </pre>
                    </div>
                  </DashboardTableDetailsPanel>
                </React.Fragment>
              );
            })
          )}
        </DashboardTable>
      </section>
    </div>
  );
}
