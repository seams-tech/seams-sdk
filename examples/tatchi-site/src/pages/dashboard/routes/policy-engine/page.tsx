import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  createDashboardPolicy,
  listDashboardPolicies,
  listDashboardPolicyAssignments,
  publishDashboardPolicy,
  updateDashboardPolicy,
  upsertDashboardPolicyAssignment,
  type DashboardConsolePolicy,
  type DashboardConsolePolicyAssignment,
} from './consolePoliciesApi';

type PolicyScopeType = 'PROJECT' | 'WALLET';

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

function parseOptionalNonNegativeInt(raw: string, label: string): number | undefined {
  const trimmed = String(raw || '').trim();
  if (!trimmed) return undefined;
  const value = Number(trimmed);
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer.`);
  }
  return value;
}

function defaultPolicyName(scopeType: PolicyScopeType): string {
  return scopeType === 'PROJECT' ? 'Project signing policy' : 'Wallet signing override';
}

export function PolicyEnginePage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  const [scopeType, setScopeType] = React.useState<PolicyScopeType>('PROJECT');
  const [walletId, setWalletId] = React.useState<string>('');
  const [publishApprovalId, setPublishApprovalId] = React.useState<string>('');

  const [policiesLoading, setPoliciesLoading] = React.useState<boolean>(true);
  const [policiesErrorMessage, setPoliciesErrorMessage] = React.useState<string>('');
  const [policies, setPolicies] = React.useState<DashboardConsolePolicy[]>([]);

  const [scopeAssignmentLoading, setScopeAssignmentLoading] = React.useState<boolean>(true);
  const [scopeAssignmentErrorMessage, setScopeAssignmentErrorMessage] = React.useState<string>('');
  const [scopeAssignment, setScopeAssignment] = React.useState<DashboardConsolePolicyAssignment | null>(
    null,
  );

  const [selectedPolicyId, setSelectedPolicyId] = React.useState<string>('');
  const [policyName, setPolicyName] = React.useState<string>(defaultPolicyName('PROJECT'));
  const [allowedChains, setAllowedChains] = React.useState<string>('Ethereum, Base, NEAR');
  const [blockedActions, setBlockedActions] = React.useState<string>('export_key');
  const [maxAmountMinor, setMaxAmountMinor] = React.useState<string>('');
  const [maxTransactionsPerHour, setMaxTransactionsPerHour] = React.useState<string>('');
  const [minSecondsBetweenTransactions, setMinSecondsBetweenTransactions] = React.useState<string>('');

  const [mutationBusy, setMutationBusy] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [mutationNote, setMutationNote] = React.useState<string>('');

  const projectScopeId = String(selectedContext.project || '').trim();
  const scopeId = scopeType === 'PROJECT' ? projectScopeId : String(walletId || '').trim();

  const canMutatePolicies = React.useMemo(() => {
    if (!session.claims) return false;
    const roles = Array.isArray(session.claims.roles)
      ? session.claims.roles.map((role) => String(role || '').toLowerCase())
      : [];
    return roles.includes('owner') || roles.includes('admin') || roles.includes('security_admin');
  }, [session.claims]);

  const assignedPolicy = React.useMemo(() => {
    if (!scopeAssignment) return null;
    return policies.find((entry) => entry.id === scopeAssignment.policyId) || null;
  }, [policies, scopeAssignment]);

  const selectedPolicy = React.useMemo(() => {
    if (!selectedPolicyId) return null;
    return policies.find((entry) => entry.id === selectedPolicyId) || null;
  }, [policies, selectedPolicyId]);

  const loadPolicies = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setPoliciesLoading(false);
      setPolicies([]);
      setPoliciesErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setPoliciesLoading(true);
    setPoliciesErrorMessage('');
    try {
      const rows = await listDashboardPolicies();
      const sorted = [...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
      setPolicies(sorted);
    } catch (error: unknown) {
      setPolicies([]);
      setPoliciesErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setPoliciesLoading(false);
    }
  }, [session.claims, session.errorMessage]);

  const loadScopeAssignment = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setScopeAssignmentLoading(false);
      setScopeAssignment(null);
      setScopeAssignmentErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!scopeId) {
      setScopeAssignmentLoading(false);
      setScopeAssignment(null);
      setScopeAssignmentErrorMessage('');
      return;
    }
    setScopeAssignmentLoading(true);
    setScopeAssignmentErrorMessage('');
    try {
      const rows = await listDashboardPolicyAssignments({ scopeType, scopeId });
      const sorted = [...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
      setScopeAssignment(sorted[0] || null);
    } catch (error: unknown) {
      setScopeAssignment(null);
      setScopeAssignmentErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setScopeAssignmentLoading(false);
    }
  }, [scopeId, scopeType, session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setPoliciesLoading(true);
      return;
    }
    void loadPolicies();
  }, [loadPolicies, session.loading]);

  React.useEffect(() => {
    if (session.loading) {
      setScopeAssignmentLoading(true);
      return;
    }
    void loadScopeAssignment();
  }, [loadScopeAssignment, session.loading]);

  React.useEffect(() => {
    if (assignedPolicy) {
      setSelectedPolicyId(assignedPolicy.id);
      setPolicyName(assignedPolicy.name || defaultPolicyName(scopeType));
      setAllowedChains(readStringRuleList(assignedPolicy.rules.allowedChains));
      setBlockedActions(readStringRuleList(assignedPolicy.rules.blockedActions));
      setMaxAmountMinor(readNumberRule(assignedPolicy.rules.maxAmountMinor));
      setMaxTransactionsPerHour(readNumberRule(assignedPolicy.rules.maxTransactionsPerHour));
      setMinSecondsBetweenTransactions(readNumberRule(assignedPolicy.rules.minSecondsBetweenTransactions));
      return;
    }
    setSelectedPolicyId('');
    setPolicyName(defaultPolicyName(scopeType));
    setAllowedChains('Ethereum, Base, NEAR');
    setBlockedActions('export_key');
    setMaxAmountMinor('');
    setMaxTransactionsPerHour('');
    setMinSecondsBetweenTransactions('');
  }, [assignedPolicy, scopeType]);

  const onSavePolicy = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutatePolicies) {
        setMutationError('Owner, admin, or security_admin is required for policy changes.');
        return;
      }
      if (!scopeId) {
        setMutationError(
          scopeType === 'PROJECT'
            ? 'Select a project before configuring project policy.'
            : 'Wallet ID is required for wallet override policy.',
        );
        return;
      }
      const name = String(policyName || '').trim();
      if (!name) {
        setMutationError('Policy name is required.');
        return;
      }
      setMutationBusy('save');
      setMutationError('');
      setMutationNote('');
      try {
        const nextRules: Record<string, unknown> = {};
        const nextBlockedActions = parseCsvList(blockedActions);
        const nextAllowedChains = parseCsvList(allowedChains);
        const nextMaxAmountMinor = parseOptionalNonNegativeInt(
          maxAmountMinor,
          'Max amount per transaction',
        );
        const nextMaxTransactionsPerHour = parseOptionalNonNegativeInt(
          maxTransactionsPerHour,
          'Max transactions per hour',
        );
        const nextMinSecondsBetweenTransactions = parseOptionalNonNegativeInt(
          minSecondsBetweenTransactions,
          'Minimum seconds between transactions',
        );
        if (nextBlockedActions.length > 0) nextRules.blockedActions = nextBlockedActions;
        if (nextAllowedChains.length > 0) nextRules.allowedChains = nextAllowedChains;
        if (nextMaxAmountMinor !== undefined) nextRules.maxAmountMinor = nextMaxAmountMinor;
        if (nextMaxTransactionsPerHour !== undefined) {
          nextRules.maxTransactionsPerHour = nextMaxTransactionsPerHour;
        }
        if (nextMinSecondsBetweenTransactions !== undefined) {
          nextRules.minSecondsBetweenTransactions = nextMinSecondsBetweenTransactions;
        }

        const policy = selectedPolicyId
          ? await updateDashboardPolicy({
              policyId: selectedPolicyId,
              name,
              rules: nextRules,
            })
          : await createDashboardPolicy({
              name,
              rules: nextRules,
            });
        await upsertDashboardPolicyAssignment({
          scopeType,
          scopeId,
          policyId: policy.id,
        });
        setSelectedPolicyId(policy.id);
        setMutationNote(
          `Saved ${policy.id} and applied it to ${scopeType.toLowerCase()} scope ${scopeId}.`,
        );
        await Promise.all([loadPolicies(), loadScopeAssignment()]);
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [
      allowedChains,
      blockedActions,
      canMutatePolicies,
      loadPolicies,
      loadScopeAssignment,
      maxAmountMinor,
      maxTransactionsPerHour,
      minSecondsBetweenTransactions,
      policyName,
      scopeId,
      scopeType,
      selectedPolicyId,
      session.claims,
      session.errorMessage,
    ],
  );

  const onPublishPolicy = React.useCallback(async () => {
    if (!session.claims) {
      setMutationError(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canMutatePolicies) {
      setMutationError('Owner, admin, or security_admin is required for policy publish.');
      return;
    }
    if (!selectedPolicyId) {
      setMutationError('Save a policy first before publishing.');
      return;
    }
    setMutationBusy('publish');
    setMutationError('');
    setMutationNote('');
    try {
      const approvalId = String(publishApprovalId || '').trim();
      const published = await publishDashboardPolicy({
        policyId: selectedPolicyId,
        ...(approvalId ? { approvalId } : {}),
      });
      setMutationNote(`Published ${published.id} (v${published.version}).`);
      await loadPolicies();
    } catch (error: unknown) {
      setMutationError(error instanceof Error ? error.message : String(error));
    } finally {
      setMutationBusy('');
    }
  }, [
    canMutatePolicies,
    loadPolicies,
    publishApprovalId,
    selectedPolicyId,
    session.claims,
    session.errorMessage,
  ]);

  const onRefresh = React.useCallback(() => {
    void loadPolicies();
    void loadScopeAssignment();
  }, [loadPolicies, loadScopeAssignment]);

  const currentAssignmentSummary = React.useMemo(() => {
    if (!scopeId) {
      return scopeType === 'PROJECT'
        ? 'Project scope is not selected yet.'
        : 'Enter a wallet ID to configure override rules.';
    }
    if (scopeAssignmentLoading) return 'Loading assignment...';
    if (scopeAssignmentErrorMessage) return `Assignment unavailable: ${scopeAssignmentErrorMessage}`;
    if (!scopeAssignment || !assignedPolicy) {
      return `No policy assigned to ${scopeType.toLowerCase()} scope ${scopeId}.`;
    }
    return `Assigned policy: ${assignedPolicy.name || assignedPolicy.id} (${assignedPolicy.status}, v${assignedPolicy.version}).`;
  }, [assignedPolicy, scopeAssignment, scopeAssignmentErrorMessage, scopeAssignmentLoading, scopeId, scopeType]);

  return (
    <div className="dashboard-view" aria-label="Policy engine page">
      <section className="dashboard-view__section" aria-label="Policy page summary">
        <h2>Signing policy</h2>
        <p>
          Configure guardrails for wallet signing: transaction types, allowed chains, per-transaction
          limits, and transaction frequency.
        </p>
        <p>
          Current context: project {selectedContext.project || '-'}, environment{' '}
          {selectedContext.environment || '-'}.
        </p>
        <button type="button" className="dashboard-pagination-button" onClick={onRefresh}>
          Refresh policy data
        </button>
      </section>

      <section className="dashboard-view__section" aria-label="Policy scope controls">
        <h2>Apply to scope</h2>
        <div className="dashboard-view-grid dashboard-view-grid--two">
          <label className="dashboard-form-field">
            <span>Scope</span>
            <select
              className="dashboard-input"
              value={scopeType}
              onChange={(event) =>
                setScopeType(String(event.target.value || '').toUpperCase() as PolicyScopeType)
              }
            >
              <option value="PROJECT">Project default</option>
              <option value="WALLET">Individual wallet override</option>
            </select>
          </label>
          {scopeType === 'PROJECT' ? (
            <label className="dashboard-form-field">
              <span>Project ID</span>
              <input
                className="dashboard-input"
                value={projectScopeId}
                readOnly
                placeholder="Select a project from the topbar"
              />
            </label>
          ) : (
            <label className="dashboard-form-field">
              <span>Wallet ID</span>
              <input
                className="dashboard-input"
                value={walletId}
                onChange={(event) => setWalletId(event.target.value)}
                placeholder="wallet_..."
              />
            </label>
          )}
        </div>
        <p className="dashboard-pagination-note">{currentAssignmentSummary}</p>
      </section>

      <section className="dashboard-view__section" aria-label="Policy rule editor">
        <h2>Rules</h2>
        {session.loading || policiesLoading ? (
          <p>Loading policy editor...</p>
        ) : !session.claims ? (
          <p>Policy editor unavailable: {session.errorMessage || 'unauthorized'}.</p>
        ) : policiesErrorMessage ? (
          <p>Policy editor unavailable: {policiesErrorMessage}</p>
        ) : (
          <>
            {!canMutatePolicies ? (
              <p>
                You have read-only access. Owner, admin, or security_admin is required to change
                policy rules.
              </p>
            ) : null}

            <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onSavePolicy}>
              <label className="dashboard-form-field">
                <span>Policy name</span>
                <input
                  className="dashboard-input"
                  value={policyName}
                  onChange={(event) => setPolicyName(event.target.value)}
                  placeholder={defaultPolicyName(scopeType)}
                  disabled={!canMutatePolicies || mutationBusy === 'save'}
                />
              </label>

              <label className="dashboard-form-field">
                <span>Allowed chains (CSV)</span>
                <input
                  className="dashboard-input"
                  value={allowedChains}
                  onChange={(event) => setAllowedChains(event.target.value)}
                  placeholder="Ethereum, Base, NEAR"
                  disabled={!canMutatePolicies || mutationBusy === 'save'}
                />
              </label>

              <label className="dashboard-form-field">
                <span>Blocked transaction types/actions (CSV)</span>
                <input
                  className="dashboard-input"
                  value={blockedActions}
                  onChange={(event) => setBlockedActions(event.target.value)}
                  placeholder="export_key, transfer"
                  disabled={!canMutatePolicies || mutationBusy === 'save'}
                />
              </label>

              <label className="dashboard-form-field">
                <span>Max amount per transaction (minor units)</span>
                <input
                  className="dashboard-input"
                  value={maxAmountMinor}
                  onChange={(event) => setMaxAmountMinor(event.target.value)}
                  placeholder="100000"
                  disabled={!canMutatePolicies || mutationBusy === 'save'}
                />
              </label>

              <label className="dashboard-form-field">
                <span>Max transactions per hour (optional)</span>
                <input
                  className="dashboard-input"
                  value={maxTransactionsPerHour}
                  onChange={(event) => setMaxTransactionsPerHour(event.target.value)}
                  placeholder="30"
                  disabled={!canMutatePolicies || mutationBusy === 'save'}
                />
              </label>

              <label className="dashboard-form-field">
                <span>Minimum seconds between transactions (optional)</span>
                <input
                  className="dashboard-input"
                  value={minSecondsBetweenTransactions}
                  onChange={(event) => setMinSecondsBetweenTransactions(event.target.value)}
                  placeholder="10"
                  disabled={!canMutatePolicies || mutationBusy === 'save'}
                />
              </label>

              <label className="dashboard-form-field">
                <span>Publish approval ID (optional)</span>
                <input
                  className="dashboard-input"
                  value={publishApprovalId}
                  onChange={(event) => setPublishApprovalId(event.target.value)}
                  placeholder="apr_policy_publish_001"
                  disabled={!canMutatePolicies}
                />
              </label>

              <div className="dashboard-form-actions">
                <button
                  type="submit"
                  className="dashboard-pagination-button"
                  disabled={!canMutatePolicies || mutationBusy === 'save'}
                >
                  {mutationBusy === 'save' ? 'Saving...' : 'Save policy'}
                </button>
                <button
                  type="button"
                  className="dashboard-pagination-button"
                  onClick={() => void onPublishPolicy()}
                  disabled={
                    !canMutatePolicies ||
                    !selectedPolicyId ||
                    selectedPolicy?.status === 'PUBLISHED' ||
                    mutationBusy === 'publish'
                  }
                >
                  {mutationBusy === 'publish' ? 'Publishing...' : 'Publish policy'}
                </button>
              </div>
            </form>

            {selectedPolicy ? (
              <p className="dashboard-pagination-note">
                Editing policy {selectedPolicy.id} ({selectedPolicy.status}, v
                {String(selectedPolicy.version)}).
              </p>
            ) : (
              <p className="dashboard-pagination-note">
                No saved policy for this scope yet. Save to create and assign one.
              </p>
            )}

            {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
            {mutationNote ? <p className="dashboard-pagination-note">{mutationNote}</p> : null}
          </>
        )}
      </section>
    </div>
  );
}

export default PolicyEnginePage;
