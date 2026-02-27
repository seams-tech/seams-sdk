import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  getDashboardPolicyCoverage,
  type DashboardPolicyCoverage,
} from '../consoleInsightsApi';
import {
  createDashboardPolicy,
  deleteDashboardPolicyAssignment,
  listDashboardPolicyAssignments,
  listDashboardPolicies,
  publishDashboardPolicy,
  simulateDashboardPolicy,
  upsertDashboardPolicyAssignment,
  type DashboardConsolePolicyAssignment,
  updateDashboardPolicy,
  type DashboardConsolePolicy,
  type DashboardConsolePolicySimulation,
} from './consolePoliciesApi';

function formatTimestamp(value: string | null): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function formatUsdMinor(value: number): string {
  const n = Number(value || 0);
  return `$${(n / 100).toLocaleString(undefined, {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  })}`;
}

function parseCsvList(raw: string): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of String(raw || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean)) {
    const key = entry.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(entry);
  }
  return out;
}

function readNumberRule(raw: unknown): string {
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return '';
  return String(Math.floor(n));
}

function readStringRuleList(raw: unknown): string {
  if (!Array.isArray(raw)) return '';
  const out: string[] = [];
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) continue;
    out.push(value);
  }
  return out.join(', ');
}

export function PolicyEnginePage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  const [coverageLoading, setCoverageLoading] = React.useState<boolean>(true);
  const [coverageErrorMessage, setCoverageErrorMessage] = React.useState<string>('');
  const [coverage, setCoverage] = React.useState<DashboardPolicyCoverage | null>(null);

  const [policiesLoading, setPoliciesLoading] = React.useState<boolean>(true);
  const [policiesErrorMessage, setPoliciesErrorMessage] = React.useState<string>('');
  const [policies, setPolicies] = React.useState<DashboardConsolePolicy[]>([]);
  const [selectedPolicyId, setSelectedPolicyId] = React.useState<string>('');
  const [assignmentsLoading, setAssignmentsLoading] = React.useState<boolean>(true);
  const [assignmentsErrorMessage, setAssignmentsErrorMessage] = React.useState<string>('');
  const [assignments, setAssignments] = React.useState<DashboardConsolePolicyAssignment[]>([]);

  const [mutationBusy, setMutationBusy] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [mutationNote, setMutationNote] = React.useState<string>('');

  const [newPolicyId, setNewPolicyId] = React.useState<string>('');
  const [newPolicyName, setNewPolicyName] = React.useState<string>('');
  const [newPolicyDescription, setNewPolicyDescription] = React.useState<string>('');
  const [newBlockedActions, setNewBlockedActions] = React.useState<string>('');
  const [newAllowedChains, setNewAllowedChains] = React.useState<string>('');
  const [newMaxAmountMinor, setNewMaxAmountMinor] = React.useState<string>('');

  const [rulesBlockedActions, setRulesBlockedActions] = React.useState<string>('');
  const [rulesAllowedChains, setRulesAllowedChains] = React.useState<string>('');
  const [rulesMaxAmountMinor, setRulesMaxAmountMinor] = React.useState<string>('');

  const [simulateAction, setSimulateAction] = React.useState<string>('transfer');
  const [simulateChain, setSimulateChain] = React.useState<string>('Ethereum');
  const [simulateAmountMinor, setSimulateAmountMinor] = React.useState<string>('1000');
  const [simulation, setSimulation] = React.useState<DashboardConsolePolicySimulation | null>(null);
  const [assignmentScopeType, setAssignmentScopeType] = React.useState<
    'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET'
  >('PROJECT');
  const [assignmentScopeId, setAssignmentScopeId] = React.useState<string>('');
  const [assignmentPolicyId, setAssignmentPolicyId] = React.useState<string>('');

  const selectedPolicy = React.useMemo(
    () => policies.find((entry) => entry.id === selectedPolicyId) || null,
    [policies, selectedPolicyId],
  );

  const canMutatePolicies = React.useMemo(() => {
    if (!session.claims) return false;
    const roles = Array.isArray(session.claims.roles)
      ? session.claims.roles.map((role) => String(role || '').toLowerCase())
      : [];
    return roles.includes('owner') || roles.includes('admin') || roles.includes('security_admin');
  }, [session.claims]);

  const defaultAssignmentScopeId = React.useMemo(() => {
    if (assignmentScopeType === 'ORG') {
      return String(session.claims?.orgId || '').trim();
    }
    if (assignmentScopeType === 'PROJECT') {
      return String(selectedContext.project || '').trim();
    }
    if (assignmentScopeType === 'ENVIRONMENT') {
      return String(selectedContext.environment || '').trim();
    }
    return '';
  }, [
    assignmentScopeType,
    selectedContext.environment,
    selectedContext.project,
    session.claims?.orgId,
  ]);

  const loadCoverage = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setCoverageLoading(false);
      setCoverage(null);
      setCoverageErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setCoverageLoading(true);
    setCoverageErrorMessage('');
    try {
      const nextCoverage = await getDashboardPolicyCoverage({
        ...(selectedContext.project ? { projectId: selectedContext.project } : {}),
        ...(selectedContext.environment ? { environmentId: selectedContext.environment } : {}),
      });
      setCoverage(nextCoverage);
    } catch (error: unknown) {
      setCoverage(null);
      setCoverageErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setCoverageLoading(false);
    }
  }, [
    selectedContext.environment,
    selectedContext.project,
    session.claims,
    session.errorMessage,
  ]);

  const loadPolicies = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setPoliciesLoading(false);
      setPolicies([]);
      setPoliciesErrorMessage(session.errorMessage || 'Console session is unavailable');
      setSelectedPolicyId('');
      return;
    }
    setPoliciesLoading(true);
    setPoliciesErrorMessage('');
    try {
      const rows = await listDashboardPolicies();
      const sorted = [...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
      setPolicies(sorted);
      setSelectedPolicyId((current) => {
        if (current && sorted.some((entry) => entry.id === current)) return current;
        return sorted[0]?.id || '';
      });
    } catch (error: unknown) {
      setPolicies([]);
      setSelectedPolicyId('');
      setPoliciesErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setPoliciesLoading(false);
    }
  }, [session.claims, session.errorMessage]);

  const loadAssignments = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setAssignmentsLoading(false);
      setAssignments([]);
      setAssignmentsErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setAssignmentsLoading(true);
    setAssignmentsErrorMessage('');
    try {
      const rows = await listDashboardPolicyAssignments();
      const sorted = [...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
      setAssignments(sorted);
    } catch (error: unknown) {
      setAssignments([]);
      setAssignmentsErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setAssignmentsLoading(false);
    }
  }, [session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setCoverageLoading(true);
      setPoliciesLoading(true);
      return;
    }
    void loadCoverage();
    void loadPolicies();
    void loadAssignments();
  }, [loadAssignments, loadCoverage, loadPolicies, session.loading]);

  React.useEffect(() => {
    if (!selectedPolicy) {
      setRulesBlockedActions('');
      setRulesAllowedChains('');
      setRulesMaxAmountMinor('');
      return;
    }
    setRulesBlockedActions(readStringRuleList(selectedPolicy.rules.blockedActions));
    setRulesAllowedChains(readStringRuleList(selectedPolicy.rules.allowedChains));
    setRulesMaxAmountMinor(readNumberRule(selectedPolicy.rules.maxAmountMinor));
  }, [selectedPolicy]);

  const onRefreshAll = React.useCallback(() => {
    void loadCoverage();
    void loadPolicies();
    void loadAssignments();
  }, [loadAssignments, loadCoverage, loadPolicies]);

  const onCreatePolicy = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      const name = String(newPolicyName || '').trim();
      if (!name) {
        setMutationError('Policy name is required.');
        return;
      }
      setMutationBusy('create');
      setMutationError('');
      setMutationNote('');
      try {
        const blockedActions = parseCsvList(newBlockedActions);
        const allowedChains = parseCsvList(newAllowedChains);
        const maxAmountMinorRaw = String(newMaxAmountMinor || '').trim();
        const maxAmountMinor = maxAmountMinorRaw ? Number(maxAmountMinorRaw) : undefined;
        if (maxAmountMinorRaw && (!Number.isInteger(maxAmountMinor) || Number(maxAmountMinor) < 0)) {
          throw new Error('Max amount minor must be a non-negative integer.');
        }
        const rules: Record<string, unknown> = {};
        if (blockedActions.length > 0) rules.blockedActions = blockedActions;
        if (allowedChains.length > 0) rules.allowedChains = allowedChains;
        if (maxAmountMinor !== undefined) rules.maxAmountMinor = maxAmountMinor;
        const created = await createDashboardPolicy({
          ...(String(newPolicyId || '').trim() ? { id: String(newPolicyId || '').trim() } : {}),
          name,
          ...(String(newPolicyDescription || '').trim()
            ? { description: String(newPolicyDescription || '').trim() }
            : {}),
          ...(Object.keys(rules).length > 0 ? { rules } : {}),
        });
        setMutationNote(`Created policy ${created.id}.`);
        setNewPolicyId('');
        setNewPolicyName('');
        setNewPolicyDescription('');
        setNewBlockedActions('');
        setNewAllowedChains('');
        setNewMaxAmountMinor('');
        await loadPolicies();
        setSelectedPolicyId(created.id);
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [
      loadPolicies,
      newAllowedChains,
      newBlockedActions,
      newMaxAmountMinor,
      newPolicyDescription,
      newPolicyId,
      newPolicyName,
      session.claims,
      session.errorMessage,
      loadCoverage,
    ],
  );

  const onUpdatePolicyRules = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!selectedPolicyId) {
        setMutationError('Select a policy first.');
        return;
      }
      setMutationBusy('update');
      setMutationError('');
      setMutationNote('');
      try {
        const blockedActions = parseCsvList(rulesBlockedActions);
        const allowedChains = parseCsvList(rulesAllowedChains);
        const maxAmountMinorRaw = String(rulesMaxAmountMinor || '').trim();
        const maxAmountMinor = maxAmountMinorRaw ? Number(maxAmountMinorRaw) : undefined;
        if (maxAmountMinorRaw && (!Number.isInteger(maxAmountMinor) || Number(maxAmountMinor) < 0)) {
          throw new Error('Max amount minor must be a non-negative integer.');
        }
        const rules: Record<string, unknown> = {
          blockedActions,
          allowedChains,
          ...(maxAmountMinor !== undefined ? { maxAmountMinor } : {}),
        };
        const updated = await updateDashboardPolicy({
          policyId: selectedPolicyId,
          rules,
        });
        setMutationNote(`Updated rules for ${updated.id}.`);
        await loadPolicies();
        await loadCoverage();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [
      loadPolicies,
      rulesAllowedChains,
      rulesBlockedActions,
      rulesMaxAmountMinor,
      selectedPolicyId,
      session.claims,
      session.errorMessage,
      loadCoverage,
    ],
  );

  const onPublishPolicy = React.useCallback(
    async (policyId: string) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      setMutationBusy(`publish:${policyId}`);
      setMutationError('');
      setMutationNote('');
      try {
        const published = await publishDashboardPolicy({ policyId });
        setMutationNote(`Published ${published.id} (v${published.version}).`);
        await loadPolicies();
        await loadCoverage();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [loadCoverage, loadPolicies, session.claims, session.errorMessage],
  );

  const onSimulatePolicy = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!selectedPolicyId) {
        setMutationError('Select a policy first.');
        return;
      }
      const action = String(simulateAction || '').trim();
      if (!action) {
        setMutationError('Simulation action is required.');
        return;
      }
      setMutationBusy('simulate');
      setMutationError('');
      setMutationNote('');
      try {
        const amountRaw = String(simulateAmountMinor || '').trim();
        const amountMinor = amountRaw ? Number(amountRaw) : undefined;
        if (amountRaw && (!Number.isInteger(amountMinor) || Number(amountMinor) < 0)) {
          throw new Error('Simulation amount must be a non-negative integer.');
        }
        const result = await simulateDashboardPolicy({
          policyId: selectedPolicyId,
          action,
          ...(String(simulateChain || '').trim() ? { chain: String(simulateChain || '').trim() } : {}),
          ...(amountMinor !== undefined ? { amountMinor } : {}),
        });
        setSimulation(result);
      } catch (error: unknown) {
        setSimulation(null);
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [
      selectedPolicyId,
      session.claims,
      session.errorMessage,
      simulateAction,
      simulateAmountMinor,
      simulateChain,
    ],
  );

  const onApplyAssignment = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutatePolicies) {
        setMutationError('Owner, admin, or security_admin is required for assignment changes.');
        return;
      }
      const scopeId = String(assignmentScopeId || '').trim() || defaultAssignmentScopeId;
      const policyId = String(assignmentPolicyId || '').trim() || selectedPolicyId;
      if (!scopeId) {
        setMutationError('Assignment scope id is required.');
        return;
      }
      if (!policyId) {
        setMutationError('Assignment policy id is required.');
        return;
      }
      setMutationBusy('assignment:upsert');
      setMutationError('');
      setMutationNote('');
      try {
        const assignment = await upsertDashboardPolicyAssignment({
          scopeType: assignmentScopeType,
          scopeId,
          policyId,
        });
        setMutationNote(
          `Assigned policy ${assignment.policyId} to ${assignment.scopeType}:${assignment.scopeId}.`,
        );
        setAssignmentScopeId(scopeId);
        setAssignmentPolicyId(policyId);
        await loadAssignments();
        await loadCoverage();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [
      assignmentPolicyId,
      assignmentScopeId,
      assignmentScopeType,
      canMutatePolicies,
      defaultAssignmentScopeId,
      loadAssignments,
      loadCoverage,
      selectedPolicyId,
      session.claims,
      session.errorMessage,
    ],
  );

  const onDeleteAssignment = React.useCallback(
    async (assignment: DashboardConsolePolicyAssignment) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutatePolicies) {
        setMutationError('Owner, admin, or security_admin is required for assignment changes.');
        return;
      }
      if (!window.confirm(`Delete assignment ${assignment.id}?`)) return;
      setMutationBusy(`assignment:delete:${assignment.id}`);
      setMutationError('');
      setMutationNote('');
      try {
        await deleteDashboardPolicyAssignment({
          assignmentId: assignment.id,
        });
        setMutationNote(`Deleted assignment ${assignment.id}.`);
        await loadAssignments();
        await loadCoverage();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [canMutatePolicies, loadAssignments, loadCoverage, session.claims, session.errorMessage],
  );

  const summaryMetrics = React.useMemo(
    () => [
      {
        label: 'Wallets in scope',
        value: String(coverage?.totals.walletCount || 0),
        hint: coverage?.truncated ? 'Result truncated by backend pagination budget' : 'Full scope',
      },
      {
        label: 'Policy buckets',
        value: String(coverage?.totals.policyCount || 0),
        hint: 'Includes unassigned bucket',
      },
      {
        label: 'Unassigned wallets',
        value: String(coverage?.totals.unassignedWalletCount || 0),
        hint: 'Missing policyId',
      },
      {
        label: 'Active wallets',
        value: String(coverage?.totals.activeWalletCount || 0),
        hint: `Archived: ${String(coverage?.totals.archivedWalletCount || 0)}`,
      },
    ],
    [coverage],
  );

  return (
    <div className="dashboard-view" aria-label="Policy engine page">
      <section className="dashboard-view__section" aria-label="Policy scope">
        <h2>Policy coverage</h2>
        <p>
          Backed by `GET /console/policy/coverage` and `GET/POST/PATCH /console/policies`.
          Scope project {selectedContext.project || '-'}, environment {selectedContext.environment || '-'}.
        </p>
        <button type="button" className="dashboard-pagination-button" onClick={onRefreshAll}>
          Refresh policy data
        </button>
      </section>

      <section className="dashboard-view__section" aria-label="Policy lifecycle controls">
        <h2>Policy lifecycle controls</h2>
        {!session.claims ? (
          <p>Policy mutations unavailable: {session.errorMessage || 'unauthorized'}.</p>
        ) : (
          <>
            {!canMutatePolicies ? (
              <p>
                Your role is read-only for policy mutations. Owner, admin, or security_admin is
                required for create/update/publish.
              </p>
            ) : null}
            <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreatePolicy}>
              <label className="dashboard-form-field">
                <span>Policy ID (optional)</span>
                <input
                  className="dashboard-input"
                  value={newPolicyId}
                  onChange={(event) => setNewPolicyId(event.target.value)}
                  placeholder="policy_prod_default"
                  disabled={!canMutatePolicies || mutationBusy === 'create'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Policy name</span>
                <input
                  className="dashboard-input"
                  value={newPolicyName}
                  onChange={(event) => setNewPolicyName(event.target.value)}
                  placeholder="Production policy"
                  disabled={!canMutatePolicies || mutationBusy === 'create'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Description</span>
                <input
                  className="dashboard-input"
                  value={newPolicyDescription}
                  onChange={(event) => setNewPolicyDescription(event.target.value)}
                  placeholder="Policy for production wallets"
                  disabled={!canMutatePolicies || mutationBusy === 'create'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Blocked actions (CSV)</span>
                <input
                  className="dashboard-input"
                  value={newBlockedActions}
                  onChange={(event) => setNewBlockedActions(event.target.value)}
                  placeholder="export_key,transfer"
                  disabled={!canMutatePolicies || mutationBusy === 'create'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Allowed chains (CSV)</span>
                <input
                  className="dashboard-input"
                  value={newAllowedChains}
                  onChange={(event) => setNewAllowedChains(event.target.value)}
                  placeholder="Ethereum,Base,NEAR"
                  disabled={!canMutatePolicies || mutationBusy === 'create'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Max amount (minor units)</span>
                <input
                  className="dashboard-input"
                  value={newMaxAmountMinor}
                  onChange={(event) => setNewMaxAmountMinor(event.target.value)}
                  placeholder="100000"
                  disabled={!canMutatePolicies || mutationBusy === 'create'}
                />
              </label>
              <div className="dashboard-form-actions">
                <button
                  type="submit"
                  className="dashboard-pagination-button"
                  disabled={!canMutatePolicies || mutationBusy === 'create'}
                >
                  {mutationBusy === 'create' ? 'Creating...' : 'Create draft policy'}
                </button>
              </div>
            </form>

            <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onUpdatePolicyRules}>
              <label className="dashboard-form-field">
                <span>Selected policy</span>
                <select
                  className="dashboard-input"
                  value={selectedPolicyId}
                  onChange={(event) => setSelectedPolicyId(event.target.value)}
                  disabled={policiesLoading || policies.length === 0 || mutationBusy === 'update'}
                >
                  {policies.length === 0 ? <option value="">No policies</option> : null}
                  {policies.map((policy) => (
                    <option value={policy.id} key={policy.id}>
                      {policy.id} ({policy.status})
                    </option>
                  ))}
                </select>
              </label>
              <label className="dashboard-form-field">
                <span>Blocked actions (CSV)</span>
                <input
                  className="dashboard-input"
                  value={rulesBlockedActions}
                  onChange={(event) => setRulesBlockedActions(event.target.value)}
                  placeholder="transfer,export_key"
                  disabled={!canMutatePolicies || mutationBusy === 'update'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Allowed chains (CSV)</span>
                <input
                  className="dashboard-input"
                  value={rulesAllowedChains}
                  onChange={(event) => setRulesAllowedChains(event.target.value)}
                  placeholder="Ethereum,Base,NEAR"
                  disabled={!canMutatePolicies || mutationBusy === 'update'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Max amount (minor units)</span>
                <input
                  className="dashboard-input"
                  value={rulesMaxAmountMinor}
                  onChange={(event) => setRulesMaxAmountMinor(event.target.value)}
                  placeholder="100000"
                  disabled={!canMutatePolicies || mutationBusy === 'update'}
                />
              </label>
              <div className="dashboard-form-actions">
                <button
                  type="submit"
                  className="dashboard-pagination-button"
                  disabled={!canMutatePolicies || !selectedPolicyId || mutationBusy === 'update'}
                >
                  {mutationBusy === 'update' ? 'Updating...' : 'Update selected policy rules'}
                </button>
              </div>
            </form>

            <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onSimulatePolicy}>
              <label className="dashboard-form-field">
                <span>Simulation action</span>
                <input
                  className="dashboard-input"
                  value={simulateAction}
                  onChange={(event) => setSimulateAction(event.target.value)}
                  placeholder="transfer"
                  disabled={mutationBusy === 'simulate'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Simulation chain</span>
                <input
                  className="dashboard-input"
                  value={simulateChain}
                  onChange={(event) => setSimulateChain(event.target.value)}
                  placeholder="Ethereum"
                  disabled={mutationBusy === 'simulate'}
                />
              </label>
              <label className="dashboard-form-field">
                <span>Simulation amount (minor units)</span>
                <input
                  className="dashboard-input"
                  value={simulateAmountMinor}
                  onChange={(event) => setSimulateAmountMinor(event.target.value)}
                  placeholder="1000"
                  disabled={mutationBusy === 'simulate'}
                />
              </label>
              <div className="dashboard-form-actions">
                <button
                  type="submit"
                  className="dashboard-pagination-button"
                  disabled={!selectedPolicyId || mutationBusy === 'simulate'}
                >
                  {mutationBusy === 'simulate' ? 'Simulating...' : 'Simulate selected policy'}
                </button>
              </div>
            </form>

            {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
            {mutationNote ? <p className="dashboard-pagination-note">{mutationNote}</p> : null}
            {simulation ? (
              <p className="dashboard-pagination-note">
                Simulation result for {simulation.policyId}: {simulation.decision} (v
                {String(simulation.policyVersion)}) at {formatTimestamp(simulation.evaluatedAt)}.
              </p>
            ) : null}
          </>
        )}
      </section>

      <section className="dashboard-view__section" aria-label="Policy assignment controls">
        <h2>Policy assignments</h2>
        <p>
          Canonical precedence order: `WALLET` -&gt; `ENVIRONMENT` -&gt; `PROJECT` -&gt; `ORG`.
        </p>
        <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onApplyAssignment}>
          <label className="dashboard-form-field">
            <span>Scope type</span>
            <select
              className="dashboard-input"
              value={assignmentScopeType}
              onChange={(event) =>
                setAssignmentScopeType(
                  String(event.target.value || '').toUpperCase() as
                    | 'ORG'
                    | 'PROJECT'
                    | 'ENVIRONMENT'
                    | 'WALLET',
                )
              }
              disabled={!canMutatePolicies || mutationBusy === 'assignment:upsert'}
            >
              <option value="ORG">ORG</option>
              <option value="PROJECT">PROJECT</option>
              <option value="ENVIRONMENT">ENVIRONMENT</option>
              <option value="WALLET">WALLET</option>
            </select>
          </label>
          <label className="dashboard-form-field">
            <span>Scope id</span>
            <input
              className="dashboard-input"
              value={assignmentScopeId}
              onChange={(event) => setAssignmentScopeId(event.target.value)}
              placeholder={defaultAssignmentScopeId || 'scope identifier'}
              disabled={!canMutatePolicies || mutationBusy === 'assignment:upsert'}
            />
          </label>
          <label className="dashboard-form-field">
            <span>Policy id</span>
            <select
              className="dashboard-input"
              value={assignmentPolicyId || selectedPolicyId}
              onChange={(event) => setAssignmentPolicyId(event.target.value)}
              disabled={!canMutatePolicies || mutationBusy === 'assignment:upsert' || policies.length === 0}
            >
              <option value="">Select policy</option>
              {policies.map((policy) => (
                <option value={policy.id} key={policy.id}>
                  {policy.id} ({policy.status})
                </option>
              ))}
            </select>
          </label>
          <div className="dashboard-form-actions">
            <button
              type="submit"
              className="dashboard-pagination-button"
              disabled={!canMutatePolicies || mutationBusy === 'assignment:upsert'}
            >
              {mutationBusy === 'assignment:upsert' ? 'Applying...' : 'Apply assignment'}
            </button>
          </div>
        </form>

        <div className="dashboard-table-wrapper" aria-label="Policy assignments table">
          <div className="dashboard-table-header" role="row">
            <span>Assignment ID</span>
            <span>Scope type</span>
            <span>Scope ID</span>
            <span>Policy ID</span>
            <span>Updated</span>
            <span>Created</span>
            <span>Actions</span>
          </div>
          {session.loading || assignmentsLoading ? (
            <p className="dashboard-table-limit">Loading assignments...</p>
          ) : !session.claims ? (
            <p className="dashboard-table-limit">
              Assignments unavailable: {session.errorMessage || 'unauthorized'}.
            </p>
          ) : assignmentsErrorMessage ? (
            <p className="dashboard-table-limit">Assignments unavailable: {assignmentsErrorMessage}</p>
          ) : assignments.length === 0 ? (
            <p className="dashboard-table-limit">No policy assignments configured yet.</p>
          ) : (
            <>
              {assignments.map((assignment) => (
                <div className="dashboard-table-row" key={assignment.id} role="row">
                  <span>{assignment.id}</span>
                  <span>{assignment.scopeType}</span>
                  <span>{assignment.scopeId}</span>
                  <span>{assignment.policyId}</span>
                  <span>{formatTimestamp(assignment.updatedAt)}</span>
                  <span>{formatTimestamp(assignment.createdAt)}</span>
                  <span>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      disabled={
                        !canMutatePolicies || mutationBusy === `assignment:delete:${assignment.id}`
                      }
                      onClick={() => onDeleteAssignment(assignment)}
                    >
                      {mutationBusy === `assignment:delete:${assignment.id}`
                        ? 'Deleting...'
                        : 'Delete'}
                    </button>
                  </span>
                </div>
              ))}
              <p className="dashboard-table-limit">
                Showing {String(assignments.length)} assignment
                {assignments.length === 1 ? '' : 's'}.
              </p>
            </>
          )}
        </div>
      </section>

      <section className="dashboard-table-wrapper" aria-label="Policy lifecycle registry">
        <div className="dashboard-table-header" role="row">
          <span>Policy ID</span>
          <span>Name</span>
          <span>Status</span>
          <span>Version</span>
          <span>Published</span>
          <span>Updated</span>
          <span>Rules</span>
          <span>Actions</span>
        </div>
        {session.loading || policiesLoading ? (
          <p className="dashboard-table-limit">Loading policy registry...</p>
        ) : !session.claims ? (
          <p className="dashboard-table-limit">
            Policy registry unavailable: {session.errorMessage || 'unauthorized'}.
          </p>
        ) : policiesErrorMessage ? (
          <p className="dashboard-table-limit">Policy registry unavailable: {policiesErrorMessage}</p>
        ) : policies.length === 0 ? (
          <p className="dashboard-table-limit">No policies configured yet.</p>
        ) : (
          <>
            {policies.map((policy) => (
              <div className="dashboard-table-row" key={policy.id} role="row">
                <span>{policy.id}</span>
                <span>{policy.name || '-'}</span>
                <span>{policy.status}</span>
                <span>{String(policy.version)}</span>
                <span>{formatTimestamp(policy.publishedAt)}</span>
                <span>{formatTimestamp(policy.updatedAt)}</span>
                <span>
                  blocked={readStringRuleList(policy.rules.blockedActions) || '-'}; chains=
                  {readStringRuleList(policy.rules.allowedChains) || '-'}; max=
                  {readNumberRule(policy.rules.maxAmountMinor) || '-'}
                </span>
                <span>
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    disabled={
                      !canMutatePolicies ||
                      policy.status === 'PUBLISHED' ||
                      mutationBusy === `publish:${policy.id}`
                    }
                    onClick={() => onPublishPolicy(policy.id)}
                  >
                    {mutationBusy === `publish:${policy.id}` ? 'Publishing...' : 'Publish'}
                  </button>
                </span>
              </div>
            ))}
            <p className="dashboard-table-limit">
              Showing {String(policies.length)} polic{policies.length === 1 ? 'y' : 'ies'}.
            </p>
          </>
        )}
      </section>

      {session.loading || coverageLoading ? (
        <section className="dashboard-view__section">
          <p>Loading policy coverage...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Policy coverage unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : coverageErrorMessage ? (
        <section className="dashboard-view__section">
          <p>Policy coverage unavailable: {coverageErrorMessage}</p>
        </section>
      ) : (
        <>
          <section className="dashboard-kpi-grid dashboard-kpi-grid--content" aria-label="Policy summary metrics">
            {summaryMetrics.map((metric) => (
              <article className="dashboard-kpi-card" key={metric.label}>
                <p className="dashboard-kpi-card__label">{metric.label}</p>
                <p className="dashboard-kpi-card__value">{metric.value}</p>
                <p className="dashboard-kpi-card__hint">{metric.hint}</p>
              </article>
            ))}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Policy aggregates">
            <div className="dashboard-table-header" role="row">
              <span>Policy ID</span>
              <span>Wallet count</span>
              <span>Active</span>
              <span>Archived</span>
              <span>Total balance</span>
              <span>Last activity</span>
              <span>Scope project</span>
              <span>Scope environment</span>
            </div>
            {(coverage?.policies.length || 0) === 0 ? (
              <p className="dashboard-table-limit">No policy aggregates in selected scope.</p>
            ) : (
              <>
                {coverage?.policies.map((policy) => (
                  <div className="dashboard-table-row" key={policy.policyId} role="row">
                    <span>{policy.policyId}</span>
                    <span>{String(policy.walletCount)}</span>
                    <span>{String(policy.activeWalletCount)}</span>
                    <span>{String(policy.archivedWalletCount)}</span>
                    <span>{formatUsdMinor(policy.totalBalanceMinor)}</span>
                    <span>{formatTimestamp(policy.lastActivityAt)}</span>
                    <span>{coverage.scope.projectId || '-'}</span>
                    <span>{coverage.scope.environmentId || '-'}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {coverage?.policies.length || 0} policy aggregate
                  {(coverage?.policies.length || 0) === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Unassigned wallets sample">
            <div className="dashboard-table-header" role="row">
              <span>Wallet ID</span>
              <span>Address</span>
              <span>Chain</span>
              <span>Status</span>
              <span>Balance</span>
              <span>Last activity</span>
              <span>Updated</span>
              <span>User ID</span>
            </div>
            {(coverage?.unassignedWalletSample.length || 0) === 0 ? (
              <p className="dashboard-table-limit">No unassigned wallet sample rows.</p>
            ) : (
              <>
                {coverage?.unassignedWalletSample.map((wallet) => (
                  <div className="dashboard-table-row" key={wallet.id} role="row">
                    <span>{wallet.id}</span>
                    <span>{wallet.address}</span>
                    <span>{wallet.chain || '-'}</span>
                    <span>{wallet.status || '-'}</span>
                    <span>{formatUsdMinor(wallet.balanceMinor)}</span>
                    <span>{formatTimestamp(wallet.lastActivityAt)}</span>
                    <span>{formatTimestamp(wallet.updatedAt)}</span>
                    <span>{wallet.userId || '-'}</span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {coverage?.unassignedWalletSample.length || 0} unassigned wallet
                  {(coverage?.unassignedWalletSample.length || 0) === 1 ? '' : 's'} sample.
                </p>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default PolicyEnginePage;
