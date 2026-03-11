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

    listDashboardAuditEvents({
      ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
      ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
      ...(eventCategoryFilter
        ? { category: eventCategoryFilter as DashboardConsoleAuditCategory }
        : {}),
      ...(eventOutcomeFilter
        ? { outcome: eventOutcomeFilter as DashboardConsoleAuditOutcome }
        : {}),
      ...(debouncedSearchInput ? { q: debouncedSearchInput } : {}),
      ...(toIsoTimestamp(fromInput) ? { from: toIsoTimestamp(fromInput) } : {}),
      ...(toIsoTimestamp(toInput) ? { to: toIsoTimestamp(toInput) } : {}),
      limit: 100,
    })
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
              const approvalId = readText(row.metadata?.approvalId);
              const approval = approvalId ? approvalDirectory[approvalId] : null;
              const linkedPolicyId = readText(row.policyId) || (approval ? readText(approval.policyId) : '');
              const linkedPolicyLabel =
                readText(row.policyName) ||
                (approval ? readText(approval.policyName) : '') ||
                linkedPolicyId;
              const policyLink = linkedPolicyId
                ? linkProps(`/dashboard/policy-engine?policyId=${encodeURIComponent(linkedPolicyId)}`)
                : null;
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
                        <DashboardTableDetailsItem label="Policy">
                          {linkedPolicyId && policyLink ? (
                            <a
                              className="dashboard-inline-link"
                              href={policyLink.href}
                              onClick={policyLink.onClick}
                              title={linkedPolicyId}
                            >
                              {linkedPolicyLabel}
                            </a>
                          ) : (
                            <span>-</span>
                          )}
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Project">
                          {row.projectId ? (
                            <button
                              type="button"
                              className="dashboard-audit-events__copy-value"
                              title={row.projectId}
                              onClick={() => void copyAuditScopeValue(row.projectId || '', 'Project')}
                            >
                              {resolveAuditProjectLabel({
                                projectId: readText(row.projectId),
                                projectDirectory,
                                selectedProjectId,
                                selectedProjectLabel,
                              })}
                            </button>
                          ) : (
                            <span>-</span>
                          )}
                        </DashboardTableDetailsItem>
                        <DashboardTableDetailsItem label="Environment">
                          {row.environmentId ? (
                            <button
                              type="button"
                              className="dashboard-audit-events__copy-value"
                              title={row.environmentId}
                              onClick={() =>
                                void copyAuditScopeValue(row.environmentId || '', 'Environment')
                              }
                            >
                              {resolveAuditEnvironmentLabel({
                                environmentId: readText(row.environmentId),
                                environmentDirectory,
                                selectedEnvironmentId,
                                selectedEnvironmentLabel,
                              })}
                            </button>
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
