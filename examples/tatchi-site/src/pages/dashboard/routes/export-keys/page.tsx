import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  approveDashboardKeyExport,
  createDashboardKeyExport,
  listDashboardKeyExports,
  type DashboardKeyExportRequest,
} from './consoleKeyExportsApi';

const KEY_EXPORT_MODES = ['DISABLED', 'APPROVAL_REQUIRED', 'ALLOWED_WITH_CONSTRAINTS'] as const;
type KeyExportMode = (typeof KEY_EXPORT_MODES)[number];

const KEY_EXPORT_STATUS_VALUES = [
  'PENDING_APPROVAL',
  'APPROVED',
  'REJECTED',
  'EXECUTED',
  'CANCELED',
] as const;
type KeyExportStatus = (typeof KEY_EXPORT_STATUS_VALUES)[number];

function normalizeString(value: string): string {
  return String(value || '').trim();
}

function parseCsvList(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const part of String(raw || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)) {
    const key = part.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(part);
  }
  return out;
}

function hasAdminRole(rolesRaw: unknown): boolean {
  if (!Array.isArray(rolesRaw)) return false;
  return rolesRaw.some((role) => String(role || '').trim().toLowerCase() === 'admin');
}

function formatTimestamp(value: string): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function joinOrDash(values: string[]): string {
  return values.length > 0 ? values.join(', ') : '-';
}

function countByStatus(rows: DashboardKeyExportRequest[], status: KeyExportStatus): number {
  return rows.reduce((acc, row) => (row.status === status ? acc + 1 : acc), 0);
}

function parsePositiveInteger(raw: string, field: string): number {
  const value = normalizeString(raw);
  if (!/^\d+$/.test(value)) {
    throw new Error(`${field} must be a positive integer.`);
  }
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`${field} must be a positive integer.`);
  }
  return parsed;
}

export function ExportKeysSettingsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const selectedEnvironmentId = normalizeString(selectedContext.environment || '');

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [mutating, setMutating] = React.useState<boolean>(false);
  const [rows, setRows] = React.useState<DashboardKeyExportRequest[]>([]);
  const [filterEnvironmentId, setFilterEnvironmentId] = React.useState<string>(selectedEnvironmentId);
  const [filterStatus, setFilterStatus] = React.useState<string>('');

  const [createRequestId, setCreateRequestId] = React.useState<string>('');
  const [createEnvironmentId, setCreateEnvironmentId] = React.useState<string>(selectedEnvironmentId);
  const [createWalletId, setCreateWalletId] = React.useState<string>('');
  const [createMode, setCreateMode] = React.useState<KeyExportMode>('APPROVAL_REQUIRED');
  const [createReason, setCreateReason] = React.useState<string>('');
  const [createRequiredApprovals, setCreateRequiredApprovals] = React.useState<string>('2');
  const [createRoles, setCreateRoles] = React.useState<string>('');
  const [createChains, setCreateChains] = React.useState<string>('');
  const [createWalletTypes, setCreateWalletTypes] = React.useState<string>('');
  const [createConstraintEnvironmentIds, setCreateConstraintEnvironmentIds] =
    React.useState<string>('');

  const [approveExportId, setApproveExportId] = React.useState<string>('');
  const [approveReason, setApproveReason] = React.useState<string>('Approved by admin review');
  const [approveMfaVerified, setApproveMfaVerified] = React.useState<boolean>(true);

  const canApprove = React.useMemo(() => hasAdminRole(session.claims?.roles), [session.claims?.roles]);

  React.useEffect(() => {
    if (!filterEnvironmentId) setFilterEnvironmentId(selectedEnvironmentId);
    if (!createEnvironmentId) setCreateEnvironmentId(selectedEnvironmentId);
  }, [createEnvironmentId, filterEnvironmentId, selectedEnvironmentId]);

  const loadKeyExports = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setRows([]);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    const environmentId = normalizeString(filterEnvironmentId);
    const status = normalizeString(filterStatus);
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    listDashboardKeyExports({
      ...(environmentId ? { environmentId } : {}),
      ...(status ? { status } : {}),
    })
      .then((nextRows) => {
        if (cancelled) return;
        const sorted = [...nextRows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
        setRows(sorted);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setRows([]);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filterEnvironmentId, filterStatus, session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadKeyExports();
    return cleanup;
  }, [loadKeyExports, session.loading]);

  React.useEffect(() => {
    const pendingRows = rows.filter((row) => row.status === 'PENDING_APPROVAL');
    if (pendingRows.length === 0) {
      setApproveExportId('');
      return;
    }
    if (pendingRows.some((row) => row.id === approveExportId)) return;
    setApproveExportId(pendingRows[0]?.id || '');
  }, [approveExportId, rows]);

  const onCreateRequest = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const environmentId = normalizeString(createEnvironmentId);
      const reason = normalizeString(createReason);
      if (!environmentId) {
        setMutationError('Environment ID is required.');
        return;
      }
      if (!reason) {
        setMutationError('Reason is required.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        const requiredApprovals = parsePositiveInteger(
          createRequiredApprovals,
          'Required approvals',
        );
        const constraints = {
          roles: parseCsvList(createRoles),
          chains: parseCsvList(createChains),
          walletTypes: parseCsvList(createWalletTypes),
          environmentIds: parseCsvList(createConstraintEnvironmentIds),
        };
        await createDashboardKeyExport({
          ...(normalizeString(createRequestId) ? { id: normalizeString(createRequestId) } : {}),
          environmentId,
          ...(normalizeString(createWalletId) ? { walletId: normalizeString(createWalletId) } : {}),
          mode: createMode,
          reason,
          requiredApprovals,
          constraints,
        });
        setCreateRequestId('');
        setCreateWalletId('');
        setCreateReason('');
        setCreateRequiredApprovals('2');
        setCreateRoles('');
        setCreateChains('');
        setCreateWalletTypes('');
        setCreateConstraintEnvironmentIds('');
        await loadKeyExports();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      createChains,
      createConstraintEnvironmentIds,
      createEnvironmentId,
      createMode,
      createReason,
      createRequestId,
      createRequiredApprovals,
      createRoles,
      createWalletId,
      createWalletTypes,
      loadKeyExports,
      session.claims,
      session.errorMessage,
    ],
  );

  const onApproveRequest = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canApprove) {
        setMutationError('Only admin can approve key export requests.');
        return;
      }
      const exportId = normalizeString(approveExportId);
      const reason = normalizeString(approveReason);
      if (!exportId) {
        setMutationError('Select a pending request to approve.');
        return;
      }
      if (!reason) {
        setMutationError('Approval reason is required.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        await approveDashboardKeyExport(exportId, {
          reason,
          mfaVerified: approveMfaVerified,
        });
        await loadKeyExports();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      approveExportId,
      approveMfaVerified,
      approveReason,
      canApprove,
      loadKeyExports,
      session.claims,
      session.errorMessage,
    ],
  );

  const summaryMetrics = React.useMemo(
    () => [
      {
        label: 'Total requests',
        value: String(rows.length),
      },
      {
        label: 'Pending approvals',
        value: String(countByStatus(rows, 'PENDING_APPROVAL')),
      },
      {
        label: 'Approved',
        value: String(countByStatus(rows, 'APPROVED')),
      },
      {
        label: 'Executed',
        value: String(countByStatus(rows, 'EXECUTED')),
      },
    ],
    [rows],
  );

  return (
    <div className="dashboard-view" aria-label="Export keys settings page">
      <section className="dashboard-view__section" aria-label="Key export request controls">
        <h2>Key export requests and approvals</h2>
        <p>
          Backed by `GET/POST /console/key-exports` and `POST /console/key-exports/:id/approve`.
          Context environment {selectedContext.environment || '-'}.
        </p>
        <div className="dashboard-view-grid dashboard-view-grid--two">
          <label className="dashboard-form-field">
            <span>Filter environment ID</span>
            <input
              className="dashboard-input"
              value={filterEnvironmentId}
              onChange={(event) => setFilterEnvironmentId(event.target.value)}
              placeholder="env_prod"
            />
          </label>
          <label className="dashboard-form-field">
            <span>Filter status</span>
            <select
              className="dashboard-input"
              value={filterStatus}
              onChange={(event) => setFilterStatus(event.target.value)}
            >
              <option value="">All statuses</option>
              {KEY_EXPORT_STATUS_VALUES.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </label>
        </div>
        <button type="button" className="dashboard-pagination-button" onClick={() => loadKeyExports()}>
          Refresh requests
        </button>
        <p className="dashboard-pagination-note">
          {canApprove
            ? 'Admin role enabled for approvals.'
            : 'Approvals require admin role. You can still create requests.'}
        </p>
        {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
      </section>

      {session.loading || loading ? (
        <section className="dashboard-view__section">
          <p>Loading key export requests...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Key exports unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : errorMessage ? (
        <section className="dashboard-view__section">
          <p>Key exports unavailable: {errorMessage}</p>
        </section>
      ) : (
        <>
          <section className="dashboard-kpi-grid dashboard-kpi-grid--content" aria-label="Key export summary metrics">
            {summaryMetrics.map((metric) => (
              <article className="dashboard-kpi-card" key={metric.label}>
                <p className="dashboard-kpi-card__label">{metric.label}</p>
                <p className="dashboard-kpi-card__value">{metric.value}</p>
              </article>
            ))}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Create key export request">
            <div className="dashboard-table-limit">
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateRequest}>
                <label className="dashboard-form-field">
                  <span>Request ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createRequestId}
                    onChange={(event) => setCreateRequestId(event.target.value)}
                    placeholder="ke_wallet_001"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Environment ID</span>
                  <input
                    className="dashboard-input"
                    value={createEnvironmentId}
                    onChange={(event) => setCreateEnvironmentId(event.target.value)}
                    placeholder="env_prod"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Wallet ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createWalletId}
                    onChange={(event) => setCreateWalletId(event.target.value)}
                    placeholder="wallet_123"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Mode</span>
                  <select
                    className="dashboard-input"
                    value={createMode}
                    onChange={(event) => setCreateMode(event.target.value as KeyExportMode)}
                  >
                    {KEY_EXPORT_MODES.map((mode) => (
                      <option key={mode} value={mode}>
                        {mode}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Required approvals</span>
                  <input
                    className="dashboard-input"
                    value={createRequiredApprovals}
                    onChange={(event) => setCreateRequiredApprovals(event.target.value)}
                    placeholder="2"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Reason</span>
                  <input
                    className="dashboard-input"
                    value={createReason}
                    onChange={(event) => setCreateReason(event.target.value)}
                    placeholder="Export required for incident response"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Constraint roles (csv)</span>
                  <input
                    className="dashboard-input"
                    value={createRoles}
                    onChange={(event) => setCreateRoles(event.target.value)}
                    placeholder="admin,security_admin"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Constraint chains (csv)</span>
                  <input
                    className="dashboard-input"
                    value={createChains}
                    onChange={(event) => setCreateChains(event.target.value)}
                    placeholder="ethereum,base"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Constraint wallet types (csv)</span>
                  <input
                    className="dashboard-input"
                    value={createWalletTypes}
                    onChange={(event) => setCreateWalletTypes(event.target.value)}
                    placeholder="smart_account,eoa"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Constraint environment IDs (csv)</span>
                  <input
                    className="dashboard-input"
                    value={createConstraintEnvironmentIds}
                    onChange={(event) => setCreateConstraintEnvironmentIds(event.target.value)}
                    placeholder="env_prod,env_staging"
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button type="submit" className="dashboard-pagination-button" disabled={mutating}>
                    {mutating ? 'Applying...' : 'Create export request'}
                  </button>
                </div>
              </form>
            </div>
          </section>

          <section className="dashboard-table-wrapper" aria-label="Approve key export request">
            <div className="dashboard-table-limit">
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onApproveRequest}>
                <label className="dashboard-form-field">
                  <span>Pending request</span>
                  <select
                    className="dashboard-input"
                    value={approveExportId}
                    onChange={(event) => setApproveExportId(event.target.value)}
                  >
                    {rows.filter((row) => row.status === 'PENDING_APPROVAL').length === 0 ? (
                      <option value="">No pending requests</option>
                    ) : null}
                    {rows
                      .filter((row) => row.status === 'PENDING_APPROVAL')
                      .map((row) => (
                        <option key={row.id} value={row.id}>
                          {row.id}
                        </option>
                      ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Approval reason</span>
                  <input
                    className="dashboard-input"
                    value={approveReason}
                    onChange={(event) => setApproveReason(event.target.value)}
                    placeholder="Approved after review"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>MFA verified</span>
                  <input
                    className="dashboard-input"
                    type="checkbox"
                    checked={approveMfaVerified}
                    onChange={(event) => setApproveMfaVerified(event.target.checked)}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={!canApprove || mutating || !approveExportId}
                  >
                    {mutating ? 'Applying...' : 'Approve request'}
                  </button>
                </div>
              </form>
            </div>
          </section>

          <section className="dashboard-table-wrapper" aria-label="Key export requests table">
            <div className="dashboard-table-header" role="row">
              <span>Request ID</span>
              <span>Environment</span>
              <span>Wallet</span>
              <span>Mode</span>
              <span>Status</span>
              <span>Approvals</span>
              <span>Requested by</span>
              <span>Reason</span>
              <span>Constraints</span>
              <span>Updated</span>
            </div>
            {rows.length === 0 ? (
              <p className="dashboard-table-limit">No key export requests found for current filter.</p>
            ) : (
              <>
                {rows.map((row) => (
                  <div className="dashboard-table-row" key={row.id} role="row">
                    <span>{row.id}</span>
                    <span>{row.environmentId || '-'}</span>
                    <span>{row.walletId || '-'}</span>
                    <span>{row.mode}</span>
                    <span>{row.status}</span>
                    <span>
                      {row.approvals.length}/{row.requiredApprovals}
                    </span>
                    <span>{row.requestedByUserId || '-'}</span>
                    <span title={row.reason}>{row.reason || '-'}</span>
                    <span
                      title={[
                        `roles=${joinOrDash(row.constraints.roles)}`,
                        `chains=${joinOrDash(row.constraints.chains)}`,
                        `walletTypes=${joinOrDash(row.constraints.walletTypes)}`,
                        `environmentIds=${joinOrDash(row.constraints.environmentIds)}`,
                      ].join(' | ')}
                    >
                      roles:{joinOrDash(row.constraints.roles)} | chains:{joinOrDash(row.constraints.chains)}
                    </span>
                    <span>{formatTimestamp(row.updatedAt)}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {rows.length} key export request{rows.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default ExportKeysSettingsPage;
