import React from 'react';
import {
  approveDashboardApproval,
  createDashboardApproval,
  listDashboardApprovals,
  rejectDashboardApproval,
  type DashboardConsoleApprovalRequest,
} from '../approvals/consoleApprovalsApi';
import {
  getDashboardPolicyCoverage,
  type DashboardPolicyCoverage,
} from '../consoleInsightsApi';
import {
  formatWalletBalanceMinor,
  listDashboardWallets,
  type DashboardConsoleWallet,
} from '../wallets/consoleWalletApi';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  createDashboardPolicy,
  deleteDashboardPolicy,
  listDashboardPolicies,
  listDashboardPolicyAssignments,
  publishDashboardPolicy,
  simulateDashboardPolicy,
  updateDashboardPolicy,
  upsertDashboardPolicyAssignment,
  type DashboardConsolePolicy,
  type DashboardConsolePolicyAssignment,
  type DashboardConsolePolicySimulation,
} from './consolePoliciesApi';

type PolicyScopeType = 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
type PolicyModalKind = 'create' | 'view' | 'edit' | 'assign' | 'delete' | 'simulate' | 'publish';
type PolicyStatusFilter = 'ALL' | 'DRAFT' | 'PUBLISHED';
type PolicyImpactFilter = 'ALL' | 'USED' | 'UNUSED';

interface PolicyModalState {
  kind: PolicyModalKind;
  policyId?: string;
}

interface PolicyContractRuleDraft {
  id: string;
  contractAddress: string;
  functions: string[];
}

const POLICY_ACTIONS = [
  'transfer',
  'contract_call',
  'deploy_contract',
  'add_key',
  'delete_key',
  'sign_message',
  'export_key',
] as const;

const POLICY_CHAINS = ['Ethereum', 'Base', 'NEAR', 'Tempo', 'Arc Circle'] as const;

const EMPTY_ASSIGNMENTS: Record<PolicyScopeType, DashboardConsolePolicyAssignment | null> = {
  ORG: null,
  PROJECT: null,
  ENVIRONMENT: null,
  WALLET: null,
};

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function defaultPolicyName(scopeType: PolicyScopeType): string {
  if (scopeType === 'ORG') return 'Organization signing policy';
  if (scopeType === 'ENVIRONMENT') return 'Environment signing policy';
  if (scopeType === 'WALLET') return 'Wallet signing override';
  return 'Project signing policy';
}

function readStringRuleList(raw: unknown): string[] {
  if (!Array.isArray(raw)) return [];
  const out: string[] = [];
  const seen = new Set<string>();
  for (const entry of raw) {
    const value = String(entry || '').trim();
    if (!value) continue;
    const key = value.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(value);
  }
  return out;
}

function readNumberRule(raw: unknown): string {
  const value = Number(raw);
  if (!Number.isFinite(value) || value < 0) return '';
  return String(Math.floor(value));
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

function toggleStringValue(current: string[], value: string): string[] {
  const key = value.toLowerCase();
  if (current.some((entry) => entry.toLowerCase() === key)) {
    return current.filter((entry) => entry.toLowerCase() !== key);
  }
  return [...current, value];
}

function makeDraftId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeDraftString(value: string): string {
  return String(value || '').trim();
}

function createEmptyContractRuleDraft(): PolicyContractRuleDraft {
  return {
    id: makeDraftId('contract'),
    contractAddress: '',
    functions: [''],
  };
}

function readContractCallRuleDrafts(raw: unknown): PolicyContractRuleDraft[] {
  if (!Array.isArray(raw)) return [];
  const out: PolicyContractRuleDraft[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const row = entry as Record<string, unknown>;
    const contractAddress = normalizeDraftString(String(row.contractAddress || ''));
    const functions = Array.isArray(row.functions)
      ? row.functions
          .map((value) => normalizeDraftString(String(value || '')))
          .filter(Boolean)
      : [];
    out.push({
      id: makeDraftId('contract'),
      contractAddress,
      functions: functions.length > 0 ? functions : [''],
    });
  }
  return out;
}

function rulesSummary(policy: DashboardConsolePolicy): string {
  const chains = readStringRuleList(policy.rules.allowedChains);
  const blockedActions = readStringRuleList(policy.rules.blockedActions);
  const maxAmountMinor = readNumberRule(policy.rules.maxAmountMinor);
  const contractCalls = readContractCallRuleDrafts(policy.rules.allowedContractCalls);
  return [
    chains.length > 0 ? `Chains: ${chains.join(', ')}` : 'Chains: all',
    blockedActions.length > 0 ? `Blocked: ${blockedActions.join(', ')}` : 'Blocked: none',
    contractCalls.length > 0 ? `Contract calls: ${contractCalls.length} contract${contractCalls.length === 1 ? '' : 's'}` : 'Contract calls: all',
    maxAmountMinor ? `Max amount: ${maxAmountMinor}` : 'Max amount: none',
  ].join(' | ');
}

function simulationSummary(result: DashboardConsolePolicySimulation): string {
  const chainLabel = result.normalizedRequest.chain || 'any-chain';
  const amountLabel =
    result.normalizedRequest.amountMinor == null
      ? 'no amount'
      : `${result.normalizedRequest.amountMinor}`;
  const contractLabel = result.normalizedRequest.contractAddress
    ? ` for contract ${result.normalizedRequest.contractAddress}${
        result.normalizedRequest.functionSelector
          ? ` function ${result.normalizedRequest.functionSelector}`
          : ''
      }`
    : '';
  if (result.decision === 'ALLOW') {
    return `Allowed ${result.normalizedRequest.action} on ${chainLabel} with amount ${amountLabel}${contractLabel}.`;
  }
  const denySummary = result.denyReasons.map((entry) => `${entry.code}: ${entry.message}`).join(' ');
  return `Denied ${result.normalizedRequest.action} on ${chainLabel} with amount ${amountLabel}${contractLabel}. ${denySummary}`;
}

function resolveScopeLabel(scopeType: PolicyScopeType, scopeId: string): string {
  if (!scopeId) return `${scopeType} scope not selected`;
  return `${scopeType.toLowerCase()} scope ${scopeId}`;
}

function policyCoverageSummary(
  entry: DashboardPolicyCoverage['policies'][number] | null,
): string {
  if (!entry) return 'Not currently covering wallets in this scope.';
  return `${entry.walletCount} wallet${entry.walletCount === 1 ? '' : 's'}, total balance ${formatWalletBalanceMinor(entry.totalBalanceMinor)}, last activity ${formatTimestamp(entry.lastActivityAt)}`;
}

export function PolicyEnginePage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();

  const orgScopeId =
    String(selectedContext.organization || session.claims?.orgId || '').trim() ||
    String(session.claims?.orgId || '').trim();
  const projectScopeId =
    String(selectedContext.project || session.claims?.projectId || '').trim() || '';
  const environmentScopeId =
    String(selectedContext.environment || session.claims?.environmentId || '').trim() || '';

  const [scopeType, setScopeType] = React.useState<PolicyScopeType>('PROJECT');
  const [walletId, setWalletId] = React.useState<string>('');

  const [policiesLoading, setPoliciesLoading] = React.useState<boolean>(true);
  const [policiesErrorMessage, setPoliciesErrorMessage] = React.useState<string>('');
  const [policies, setPolicies] = React.useState<DashboardConsolePolicy[]>([]);

  const [assignmentsLoading, setAssignmentsLoading] = React.useState<boolean>(true);
  const [assignmentsErrorMessage, setAssignmentsErrorMessage] = React.useState<string>('');
  const [assignmentsByScope, setAssignmentsByScope] =
    React.useState<Record<PolicyScopeType, DashboardConsolePolicyAssignment | null>>(EMPTY_ASSIGNMENTS);

  const [coverageLoading, setCoverageLoading] = React.useState<boolean>(true);
  const [coverageErrorMessage, setCoverageErrorMessage] = React.useState<string>('');
  const [coverage, setCoverage] = React.useState<DashboardPolicyCoverage | null>(null);

  const [walletsLoading, setWalletsLoading] = React.useState<boolean>(true);
  const [walletsErrorMessage, setWalletsErrorMessage] = React.useState<string>('');
  const [wallets, setWallets] = React.useState<DashboardConsoleWallet[]>([]);

  const [approvalsLoading, setApprovalsLoading] = React.useState<boolean>(true);
  const [approvalsErrorMessage, setApprovalsErrorMessage] = React.useState<string>('');
  const [approvals, setApprovals] = React.useState<DashboardConsoleApprovalRequest[]>([]);

  const [activeModal, setActiveModal] = React.useState<PolicyModalState | null>(null);
  const [creatingNewPolicy, setCreatingNewPolicy] = React.useState<boolean>(false);
  const [selectedPolicyId, setSelectedPolicyId] = React.useState<string>('');
  const [policyQuery, setPolicyQuery] = React.useState<string>('');
  const [statusFilter, setStatusFilter] = React.useState<PolicyStatusFilter>('ALL');
  const [impactFilter, setImpactFilter] = React.useState<PolicyImpactFilter>('ALL');
  const [policyName, setPolicyName] = React.useState<string>(defaultPolicyName('PROJECT'));
  const [blockedActions, setBlockedActions] = React.useState<string[]>(['export_key']);
  const [contractCallBlocked, setContractCallBlocked] = React.useState<boolean>(false);
  const [contractCallRules, setContractCallRules] = React.useState<PolicyContractRuleDraft[]>([]);
  const [allowedChains, setAllowedChains] = React.useState<string[]>(['Ethereum', 'Base', 'NEAR']);
  const [maxAmountMinor, setMaxAmountMinor] = React.useState<string>('');

  const [simulationAction, setSimulationAction] = React.useState<string>('transfer');
  const [simulationChain, setSimulationChain] = React.useState<string>('Ethereum');
  const [simulationAmountMinor, setSimulationAmountMinor] = React.useState<string>('10000');
  const [simulationContractAddress, setSimulationContractAddress] = React.useState<string>('');
  const [simulationFunctionSelector, setSimulationFunctionSelector] = React.useState<string>('');
  const [simulationBusy, setSimulationBusy] = React.useState<boolean>(false);
  const [simulationErrorMessage, setSimulationErrorMessage] = React.useState<string>('');
  const [simulationResult, setSimulationResult] =
    React.useState<DashboardConsolePolicySimulation | null>(null);

  const [approvalCreateReason, setApprovalCreateReason] = React.useState<string>(
    'Policy reviewed for publish.',
  );
  const [approvalDecisionReason, setApprovalDecisionReason] = React.useState<string>(
    'Reviewed in policy engine.',
  );
  const [selectedApprovalId, setSelectedApprovalId] = React.useState<string>('');

  const [mutationBusy, setMutationBusy] = React.useState<string>('');
  const [mutationErrorMessage, setMutationErrorMessage] = React.useState<string>('');
  const [mutationNotice, setMutationNotice] = React.useState<string>('');

  const scopeId = React.useMemo(() => {
    if (scopeType === 'ORG') return orgScopeId;
    if (scopeType === 'ENVIRONMENT') return environmentScopeId;
    if (scopeType === 'WALLET') return String(walletId || '').trim();
    return projectScopeId;
  }, [environmentScopeId, orgScopeId, projectScopeId, scopeType, walletId]);

  const canMutatePolicies = React.useMemo(() => {
    if (!session.claims) return false;
    const roles = Array.isArray(session.claims.roles)
      ? session.claims.roles.map((role) => String(role || '').toLowerCase())
      : [];
    return roles.includes('owner') || roles.includes('admin') || roles.includes('security_admin');
  }, [session.claims]);

  const selectedPolicy = React.useMemo(
    () => policies.find((entry) => entry.id === selectedPolicyId) || null,
    [policies, selectedPolicyId],
  );

  const policyById = React.useMemo(() => {
    const out = new Map<string, DashboardConsolePolicy>();
    for (const policy of policies) out.set(policy.id, policy);
    return out;
  }, [policies]);

  const directAssignment = assignmentsByScope[scopeType];

  const effectiveAssignment = React.useMemo(() => {
    if (scopeType === 'WALLET') {
      return (
        assignmentsByScope.WALLET ||
        assignmentsByScope.ENVIRONMENT ||
        assignmentsByScope.PROJECT ||
        assignmentsByScope.ORG
      );
    }
    if (scopeType === 'ENVIRONMENT') {
      return assignmentsByScope.ENVIRONMENT || assignmentsByScope.PROJECT || assignmentsByScope.ORG;
    }
    if (scopeType === 'PROJECT') {
      return assignmentsByScope.PROJECT || assignmentsByScope.ORG;
    }
    return assignmentsByScope.ORG;
  }, [assignmentsByScope, scopeType]);

  const coverageByPolicyId = React.useMemo(() => {
    const out = new Map<string, DashboardPolicyCoverage['policies'][number]>();
    for (const entry of coverage?.policies || []) out.set(entry.policyId, entry);
    return out;
  }, [coverage]);

  const visiblePolicies = React.useMemo(() => {
    const scopedPolicyIds = new Set<string>();
    for (const assignment of Object.values(assignmentsByScope)) {
      if (assignment?.policyId) scopedPolicyIds.add(assignment.policyId);
    }
    for (const entry of coverage?.policies || []) {
      if (entry.policyId) scopedPolicyIds.add(entry.policyId);
    }
    for (const policy of policies) {
      if (policy.status === 'DRAFT') scopedPolicyIds.add(policy.id);
    }
    const rows = policies.filter((policy) => scopedPolicyIds.has(policy.id));
    return rows.length > 0 ? rows : policies;
  }, [assignmentsByScope, coverage, policies]);

  const relevantApprovals = React.useMemo(() => {
    if (!selectedPolicyId) return [];
    return approvals.filter(
      (entry) => entry.operationType === 'POLICY_PUBLISH' && entry.resourceId === selectedPolicyId,
    );
  }, [approvals, selectedPolicyId]);

  const approvedApprovals = React.useMemo(
    () => relevantApprovals.filter((entry) => entry.status === 'APPROVED'),
    [relevantApprovals],
  );

  const loadPolicies = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setPolicies([]);
      setPoliciesLoading(false);
      setPoliciesErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setPoliciesLoading(true);
    setPoliciesErrorMessage('');
    try {
      const rows = await listDashboardPolicies();
      setPolicies([...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)));
    } catch (error: unknown) {
      setPolicies([]);
      setPoliciesErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setPoliciesLoading(false);
    }
  }, [session.claims, session.errorMessage]);

  const loadAssignments = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setAssignmentsByScope(EMPTY_ASSIGNMENTS);
      setAssignmentsLoading(false);
      setAssignmentsErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setAssignmentsLoading(true);
    setAssignmentsErrorMessage('');
    try {
      const nextAssignments: Record<PolicyScopeType, DashboardConsolePolicyAssignment | null> = {
        ORG: null,
        PROJECT: null,
        ENVIRONMENT: null,
        WALLET: null,
      };
      const targets: Array<{ scopeType: PolicyScopeType; scopeId: string }> = [];
      if (orgScopeId) targets.push({ scopeType: 'ORG', scopeId: orgScopeId });
      if (projectScopeId) targets.push({ scopeType: 'PROJECT', scopeId: projectScopeId });
      if (environmentScopeId) targets.push({ scopeType: 'ENVIRONMENT', scopeId: environmentScopeId });
      if (walletId) targets.push({ scopeType: 'WALLET', scopeId: walletId });

      await Promise.all(
        targets.map(async (target) => {
          const rows = await listDashboardPolicyAssignments(target);
          nextAssignments[target.scopeType] =
            [...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt))[0] || null;
        }),
      );
      setAssignmentsByScope(nextAssignments);
    } catch (error: unknown) {
      setAssignmentsByScope(EMPTY_ASSIGNMENTS);
      setAssignmentsErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setAssignmentsLoading(false);
    }
  }, [environmentScopeId, orgScopeId, projectScopeId, session.claims, session.errorMessage, walletId]);

  const loadCoverage = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setCoverage(null);
      setCoverageLoading(false);
      setCoverageErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setCoverageLoading(true);
    setCoverageErrorMessage('');
    try {
      const next = await getDashboardPolicyCoverage({
        ...(projectScopeId ? { projectId: projectScopeId } : {}),
        ...(environmentScopeId ? { environmentId: environmentScopeId } : {}),
      });
      setCoverage(next);
    } catch (error: unknown) {
      setCoverage(null);
      setCoverageErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setCoverageLoading(false);
    }
  }, [environmentScopeId, projectScopeId, session.claims, session.errorMessage]);

  const loadWallets = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setWallets([]);
      setWalletsLoading(false);
      setWalletsErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setWalletsLoading(true);
    setWalletsErrorMessage('');
    try {
      const page = await listDashboardWallets({
        limit: 25,
        ...(projectScopeId ? { projectId: projectScopeId } : {}),
        ...(environmentScopeId ? { environmentId: environmentScopeId } : {}),
      });
      setWallets(page.wallets);
    } catch (error: unknown) {
      setWallets([]);
      setWalletsErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setWalletsLoading(false);
    }
  }, [environmentScopeId, projectScopeId, session.claims, session.errorMessage]);

  const loadApprovals = React.useCallback(async (): Promise<void> => {
    if (!session.claims) {
      setApprovals([]);
      setApprovalsLoading(false);
      setApprovalsErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    setApprovalsLoading(true);
    setApprovalsErrorMessage('');
    try {
      const rows = await listDashboardApprovals({
        operationType: 'POLICY_PUBLISH',
        ...(projectScopeId ? { projectId: projectScopeId } : {}),
        ...(environmentScopeId ? { environmentId: environmentScopeId } : {}),
      });
      setApprovals(rows);
    } catch (error: unknown) {
      setApprovals([]);
      setApprovalsErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setApprovalsLoading(false);
    }
  }, [environmentScopeId, projectScopeId, session.claims, session.errorMessage]);

  const refreshWorkspace = React.useCallback(() => {
    void Promise.all([loadPolicies(), loadAssignments(), loadCoverage(), loadWallets(), loadApprovals()]);
  }, [loadApprovals, loadAssignments, loadCoverage, loadPolicies, loadWallets]);

  React.useEffect(() => {
    if (session.loading) return;
    refreshWorkspace();
  }, [refreshWorkspace, session.loading]);

  React.useEffect(() => {
    if (!walletId && wallets.length > 0) {
      setWalletId(wallets[0].id);
    }
  }, [walletId, wallets]);

  React.useEffect(() => {
    if (creatingNewPolicy) return;
    if (selectedPolicyId && policies.some((entry) => entry.id === selectedPolicyId)) return;
    const nextPolicyId =
      directAssignment?.policyId ||
      effectiveAssignment?.policyId ||
      policies.find((entry) => entry.status === 'DRAFT')?.id ||
      policies[0]?.id ||
      '';
    setSelectedPolicyId(nextPolicyId);
  }, [creatingNewPolicy, directAssignment, effectiveAssignment, policies, selectedPolicyId]);

  React.useEffect(() => {
    if (!selectedPolicyId) {
      const fallbackApprovalId = approvedApprovals[0]?.id || '';
      if (selectedApprovalId !== fallbackApprovalId) setSelectedApprovalId(fallbackApprovalId);
      return;
    }
    const stillSelected = relevantApprovals.some((entry) => entry.id === selectedApprovalId);
    if (stillSelected) return;
    setSelectedApprovalId(approvedApprovals[0]?.id || '');
  }, [approvedApprovals, relevantApprovals, selectedApprovalId, selectedPolicyId]);

  React.useEffect(() => {
    if (creatingNewPolicy || !selectedPolicy) {
      setPolicyName(defaultPolicyName(scopeType));
      setBlockedActions(['export_key']);
      setContractCallBlocked(false);
      setContractCallRules([]);
      setAllowedChains(['Ethereum', 'Base', 'NEAR']);
      setMaxAmountMinor('');
      return;
    }
    setPolicyName(selectedPolicy.name || defaultPolicyName(scopeType));
    const nextBlockedActions = readStringRuleList(selectedPolicy.rules.blockedActions);
    setContractCallBlocked(
      nextBlockedActions.some((entry) => entry.toLowerCase() === 'contract_call'),
    );
    setBlockedActions(
      nextBlockedActions.filter((entry) => entry.toLowerCase() !== 'contract_call'),
    );
    setContractCallRules(readContractCallRuleDrafts(selectedPolicy.rules.allowedContractCalls));
    setAllowedChains(readStringRuleList(selectedPolicy.rules.allowedChains));
    setMaxAmountMinor(readNumberRule(selectedPolicy.rules.maxAmountMinor));
  }, [creatingNewPolicy, scopeType, selectedPolicy]);

  const openCreatePolicyModal = React.useCallback(() => {
    setCreatingNewPolicy(true);
    setSelectedPolicyId('');
    setSimulationResult(null);
    setSimulationErrorMessage('');
    setMutationErrorMessage('');
    setMutationNotice('');
    setActiveModal({ kind: 'create' });
  }, []);

  const openPolicyModal = React.useCallback((kind: Exclude<PolicyModalKind, 'create'>, policyId: string) => {
    setCreatingNewPolicy(false);
    setSelectedPolicyId(policyId);
    setSimulationResult(null);
    setSimulationErrorMessage('');
    setMutationErrorMessage('');
    setMutationNotice('');
    setActiveModal({ kind, policyId });
  }, []);

  const closePolicyModal = React.useCallback(() => {
    setActiveModal(null);
    setSimulationErrorMessage('');
    setSimulationResult(null);
    if (creatingNewPolicy) {
      setCreatingNewPolicy(false);
    }
  }, [creatingNewPolicy]);

  const savePolicy = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationErrorMessage(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutatePolicies) {
        setMutationErrorMessage('Owner, admin, or security_admin is required for policy changes.');
        return;
      }

      const trimmedName = String(policyName || '').trim();
      if (!trimmedName) {
        setMutationErrorMessage('Policy name is required.');
        return;
      }

      setMutationBusy('save');
      setMutationErrorMessage('');
      setMutationNotice('');
      try {
        const nextRules: Record<string, unknown> = {};
        if (allowedChains.length > 0) nextRules.allowedChains = allowedChains;
        const nextBlockedActions = contractCallBlocked
          ? [...blockedActions, 'contract_call']
          : [...blockedActions];
        if (nextBlockedActions.length > 0) nextRules.blockedActions = nextBlockedActions;
        const nextContractCallRules = contractCallRules
          .map((entry) => ({
            contractAddress: normalizeDraftString(entry.contractAddress).toLowerCase(),
            functions: entry.functions
              .map((value) => normalizeDraftString(value).toLowerCase())
              .filter(Boolean),
          }))
          .filter((entry) => entry.contractAddress);
        if (nextContractCallRules.length > 0) nextRules.allowedContractCalls = nextContractCallRules;
        const nextMaxAmountMinor = parseOptionalNonNegativeInt(
          maxAmountMinor,
          'Max amount per transaction',
        );
        if (nextMaxAmountMinor !== undefined) nextRules.maxAmountMinor = nextMaxAmountMinor;

        const policy =
          creatingNewPolicy || !selectedPolicyId
            ? await createDashboardPolicy({
                name: trimmedName,
                rules: nextRules,
              })
            : await updateDashboardPolicy({
                policyId: selectedPolicyId,
                name: trimmedName,
                rules: nextRules,
              });

        setCreatingNewPolicy(false);
        setSelectedPolicyId(policy.id);
        setActiveModal(null);
        setMutationNotice(`Saved policy ${policy.id} (${policy.status}, v${policy.version}).`);
        await loadPolicies();
      } catch (error: unknown) {
        setMutationErrorMessage(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [
      allowedChains,
      blockedActions,
      canMutatePolicies,
      contractCallBlocked,
      contractCallRules,
      creatingNewPolicy,
      loadPolicies,
      maxAmountMinor,
      policyName,
      selectedPolicyId,
      session.claims,
      session.errorMessage,
    ],
  );

  const deleteSelectedPolicy = React.useCallback(async () => {
    if (!session.claims) {
      setMutationErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canMutatePolicies) {
      setMutationErrorMessage('Owner, admin, or security_admin is required for policy deletion.');
      return;
    }
    if (!selectedPolicyId) {
      setMutationErrorMessage('Select a policy before deleting it.');
      return;
    }
    setMutationBusy('delete');
    setMutationErrorMessage('');
    setMutationNotice('');
    try {
      const deleted = await deleteDashboardPolicy({ policyId: selectedPolicyId });
      if (deleted.removed) {
        setMutationNotice(`Deleted policy ${selectedPolicyId}.`);
      }
      setSelectedPolicyId('');
      setActiveModal(null);
      await Promise.all([loadPolicies(), loadAssignments(), loadCoverage()]);
    } catch (error: unknown) {
      setMutationErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setMutationBusy('');
    }
  }, [
    canMutatePolicies,
    loadAssignments,
    loadCoverage,
    loadPolicies,
    selectedPolicyId,
    session.claims,
    session.errorMessage,
  ]);

  const assignPolicyToSelectedScope = React.useCallback(
    async (policyId: string) => {
      if (!session.claims) {
        setMutationErrorMessage(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutatePolicies) {
        setMutationErrorMessage('Owner, admin, or security_admin is required for assignments.');
        return;
      }
      if (!scopeId) {
        setMutationErrorMessage(
          scopeType === 'WALLET'
            ? 'Select or enter a wallet before assigning a wallet override.'
            : `${scopeType.toLowerCase()} scope is not selected.`,
        );
        return;
      }

      setMutationBusy('assign');
      setMutationErrorMessage('');
      setMutationNotice('');
      try {
        const assignment = await upsertDashboardPolicyAssignment({
          scopeType,
          scopeId,
          policyId,
        });
        setCreatingNewPolicy(false);
        setSelectedPolicyId(policyId);
        setMutationNotice(`Assigned ${assignment.policyId} to ${resolveScopeLabel(scopeType, scopeId)}.`);
        await Promise.all([loadAssignments(), loadCoverage()]);
      } catch (error: unknown) {
        setMutationErrorMessage(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [
      canMutatePolicies,
      loadAssignments,
      loadCoverage,
      scopeId,
      scopeType,
      session.claims,
      session.errorMessage,
    ],
  );

  const publishSelectedPolicy = React.useCallback(async () => {
    if (!session.claims) {
      setMutationErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canMutatePolicies) {
      setMutationErrorMessage('Owner, admin, or security_admin is required for policy publish.');
      return;
    }
    if (!selectedPolicyId) {
      setMutationErrorMessage('Select or save a policy before publishing.');
      return;
    }

    setMutationBusy('publish');
    setMutationErrorMessage('');
    setMutationNotice('');
    try {
      const published = await publishDashboardPolicy({
        policyId: selectedPolicyId,
        ...(selectedApprovalId ? { approvalId: selectedApprovalId } : {}),
      });
      setActiveModal(null);
      setMutationNotice(`Published ${published.id} (v${published.version}).`);
      await Promise.all([loadPolicies(), loadApprovals()]);
    } catch (error: unknown) {
      setMutationErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setMutationBusy('');
    }
  }, [
    canMutatePolicies,
    loadApprovals,
    loadPolicies,
    selectedApprovalId,
    selectedPolicyId,
    session.claims,
    session.errorMessage,
  ]);

  const createPublishApproval = React.useCallback(async () => {
    if (!session.claims) {
      setMutationErrorMessage(session.errorMessage || 'Console session is unavailable');
      return;
    }
    if (!canMutatePolicies) {
      setMutationErrorMessage('Owner, admin, or security_admin is required to create approvals.');
      return;
    }
    if (!selectedPolicyId) {
      setMutationErrorMessage('Select a saved policy before requesting approval.');
      return;
    }
    const reason = String(approvalCreateReason || '').trim();
    if (!reason) {
      setMutationErrorMessage('Approval request reason is required.');
      return;
    }

    setMutationBusy('approval-create');
    setMutationErrorMessage('');
    setMutationNotice('');
    try {
      const approval = await createDashboardApproval({
        operationType: 'POLICY_PUBLISH',
        reason,
        ...(projectScopeId ? { projectId: projectScopeId } : {}),
        ...(environmentScopeId ? { environmentId: environmentScopeId } : {}),
        resourceType: 'policy',
        resourceId: selectedPolicyId,
        metadata: {
          policyId: selectedPolicyId,
        },
      });
      setApprovalCreateReason('Policy reviewed for publish.');
      setSelectedApprovalId(approval.status === 'APPROVED' ? approval.id : selectedApprovalId);
      setMutationNotice(`Created approval request ${approval.id} for ${selectedPolicyId}.`);
      await loadApprovals();
    } catch (error: unknown) {
      setMutationErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setMutationBusy('');
    }
  }, [
    approvalCreateReason,
    canMutatePolicies,
    environmentScopeId,
    loadApprovals,
    projectScopeId,
    selectedApprovalId,
    selectedPolicyId,
    session.claims,
    session.errorMessage,
  ]);

  const approveRequest = React.useCallback(
    async (approval: DashboardConsoleApprovalRequest) => {
      if (!canMutatePolicies) {
        setMutationErrorMessage('Owner, admin, or security_admin is required to approve requests.');
        return;
      }
      setMutationBusy(`approve:${approval.id}`);
      setMutationErrorMessage('');
      setMutationNotice('');
      try {
        const updated = await approveDashboardApproval({
          approvalId: approval.id,
          reason: String(approvalDecisionReason || '').trim() || 'Approved in policy engine.',
          mfaVerified: false,
        });
        if (updated.status === 'APPROVED') setSelectedApprovalId(updated.id);
        setMutationNotice(`Approval request ${updated.id} is now ${updated.status}.`);
        await loadApprovals();
      } catch (error: unknown) {
        setMutationErrorMessage(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [approvalDecisionReason, canMutatePolicies, loadApprovals],
  );

  const rejectRequest = React.useCallback(
    async (approval: DashboardConsoleApprovalRequest) => {
      if (!canMutatePolicies) {
        setMutationErrorMessage('Owner, admin, or security_admin is required to reject requests.');
        return;
      }
      setMutationBusy(`reject:${approval.id}`);
      setMutationErrorMessage('');
      setMutationNotice('');
      try {
        const updated = await rejectDashboardApproval({
          approvalId: approval.id,
          reason: String(approvalDecisionReason || '').trim() || 'Rejected in policy engine.',
        });
        if (selectedApprovalId === updated.id) setSelectedApprovalId('');
        setMutationNotice(`Approval request ${updated.id} is now ${updated.status}.`);
        await loadApprovals();
      } catch (error: unknown) {
        setMutationErrorMessage(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [approvalDecisionReason, canMutatePolicies, loadApprovals, selectedApprovalId],
  );

  const runSimulation = React.useCallback(async () => {
    if (!selectedPolicyId) {
      setSimulationErrorMessage('Save or select a policy before running simulation.');
      setSimulationResult(null);
      return;
    }
    setSimulationBusy(true);
    setSimulationErrorMessage('');
    setSimulationResult(null);
    try {
      const amountMinor = parseOptionalNonNegativeInt(
        simulationAmountMinor,
        'Simulation amount',
      );
      const result = await simulateDashboardPolicy({
        policyId: selectedPolicyId,
        action: simulationAction,
        ...(simulationChain ? { chain: simulationChain } : {}),
        ...(amountMinor !== undefined ? { amountMinor } : {}),
        ...(simulationContractAddress
          ? { contractAddress: simulationContractAddress.trim() }
          : {}),
        ...(simulationFunctionSelector
          ? { functionSelector: simulationFunctionSelector.trim() }
          : {}),
      });
      setSimulationResult(result);
    } catch (error: unknown) {
      setSimulationErrorMessage(error instanceof Error ? error.message : String(error));
    } finally {
      setSimulationBusy(false);
    }
  }, [
    selectedPolicyId,
    simulationAction,
    simulationAmountMinor,
    simulationChain,
    simulationContractAddress,
    simulationFunctionSelector,
  ]);

  const policyContextUsage = React.useCallback(
    (policy: DashboardConsolePolicy): string => {
      const labels: string[] = [];
      if (assignmentsByScope.ORG?.policyId === policy.id) labels.push('org default');
      if (assignmentsByScope.PROJECT?.policyId === policy.id) labels.push('project default');
      if (assignmentsByScope.ENVIRONMENT?.policyId === policy.id) labels.push('environment override');
      if (assignmentsByScope.WALLET?.policyId === policy.id) labels.push('selected wallet override');
      const coverageEntry = coverageByPolicyId.get(policy.id);
      const walletCoverage = coverageEntry
        ? `${coverageEntry.walletCount} wallet${coverageEntry.walletCount === 1 ? '' : 's'}`
        : '0 wallets';
      return `${labels.length > 0 ? labels.join(', ') : 'draft or unassigned'} | ${walletCoverage}`;
    },
    [assignmentsByScope, coverageByPolicyId],
  );
  const filteredPolicies = React.useMemo(() => {
    const query = String(policyQuery || '').trim().toLowerCase();
    return visiblePolicies.filter((policy) => {
      if (statusFilter !== 'ALL' && policy.status !== statusFilter) return false;
      const coverageEntry = coverageByPolicyId.get(policy.id) || null;
      const used = Boolean(coverageEntry && coverageEntry.walletCount > 0);
      if (impactFilter === 'USED' && !used) return false;
      if (impactFilter === 'UNUSED' && used) return false;
      if (!query) return true;
      const haystack = [
        policy.id,
        policy.name,
        rulesSummary(policy),
        policyContextUsage(policy),
      ]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [coverageByPolicyId, impactFilter, policyContextUsage, policyQuery, statusFilter, visiblePolicies]);
  const activeModalPolicy =
    activeModal?.policyId ? policyById.get(activeModal.policyId) || null : creatingNewPolicy ? null : selectedPolicy;
  const defaultPolicyId = orgScopeId ? `${orgScopeId}:policy:default` : '';
  const policyActionToggleOptions = POLICY_ACTIONS.filter((entry) => entry !== 'contract_call');
  const addContractCallRule = React.useCallback(() => {
    setContractCallRules((current) => [...current, createEmptyContractRuleDraft()]);
  }, []);
  const removeContractCallRule = React.useCallback((ruleId: string) => {
    setContractCallRules((current) => current.filter((entry) => entry.id !== ruleId));
  }, []);
  const updateContractCallRuleAddress = React.useCallback((ruleId: string, value: string) => {
    setContractCallRules((current) =>
      current.map((entry) =>
        entry.id === ruleId ? { ...entry, contractAddress: value } : entry,
      ),
    );
  }, []);
  const addContractFunction = React.useCallback((ruleId: string) => {
    setContractCallRules((current) =>
      current.map((entry) =>
        entry.id === ruleId ? { ...entry, functions: [...entry.functions, ''] } : entry,
      ),
    );
  }, []);
  const updateContractFunction = React.useCallback(
    (ruleId: string, functionIndex: number, value: string) => {
      setContractCallRules((current) =>
        current.map((entry) =>
          entry.id === ruleId
            ? {
                ...entry,
                functions: entry.functions.map((functionEntry, index) =>
                  index === functionIndex ? value : functionEntry,
                ),
              }
            : entry,
        ),
      );
    },
    [],
  );
  const removeContractFunction = React.useCallback((ruleId: string, functionIndex: number) => {
    setContractCallRules((current) =>
      current.map((entry) => {
        if (entry.id !== ruleId) return entry;
        const nextFunctions = entry.functions.filter((_, index) => index !== functionIndex);
        return {
          ...entry,
          functions: nextFunctions.length > 0 ? nextFunctions : [''],
        };
      }),
    );
  }, []);
  const renderScopeFields = (): React.JSX.Element => (
    <>
      <label className="dashboard-form-field">
        <span>Target scope</span>
        <select
          className="dashboard-input"
          value={scopeType}
          onChange={(event) =>
            setScopeType(String(event.target.value || '').toUpperCase() as PolicyScopeType)
          }
        >
          <option value="ORG">Organization default</option>
          <option value="PROJECT">Project default</option>
          <option value="ENVIRONMENT">Environment override</option>
          <option value="WALLET">Wallet override</option>
        </select>
      </label>

      {scopeType === 'WALLET' ? (
        <div className="dashboard-view-grid dashboard-view-grid--two dashboard-form-field dashboard-form-field--full">
          <label className="dashboard-form-field">
            <span>Wallet override target</span>
            <input
              className="dashboard-input"
              list="policy-engine-wallets"
              value={walletId}
              onChange={(event) => setWalletId(event.target.value)}
              placeholder="wallet_..."
            />
            <datalist id="policy-engine-wallets">
              {wallets.map((wallet) => (
                <option key={wallet.id} value={wallet.id}>
                  {wallet.address}
                </option>
              ))}
            </datalist>
          </label>
          <div className="dashboard-form-field">
            <span>Wallet preview</span>
            {walletsLoading ? (
              <p className="dashboard-pagination-note">Loading wallets...</p>
            ) : walletsErrorMessage ? (
              <p className="dashboard-pagination-note">{walletsErrorMessage}</p>
            ) : walletId ? (
              <p className="dashboard-pagination-note">
                {(() => {
                  const wallet = wallets.find((entry) => entry.id === walletId) || null;
                  if (!wallet) return `Wallet ${walletId}`;
                  return `${wallet.id} (${wallet.chain}, ${wallet.address})`;
                })()}
              </p>
            ) : (
              <p className="dashboard-pagination-note">Choose a wallet for the override target.</p>
            )}
          </div>
        </div>
      ) : null}
    </>
  );

  return (
    <div className="dashboard-view" aria-label="Policy engine page">
      <section className="dashboard-view__section" aria-label="Policy engine summary">
        <h2>Policy engine</h2>
        {mutationNotice ? <p className="dashboard-pagination-note">{mutationNotice}</p> : null}
        {mutationErrorMessage ? (
          <p className="dashboard-pagination-note">{mutationErrorMessage}</p>
        ) : null}
      </section>

      <section className="dashboard-view__section" aria-label="Policy setup">
        <h2>Create policy</h2>
        <p className="dashboard-pagination-note">
          Create draft signing policies for the current dashboard context, then assign, simulate, and
          schedule them for live rollout from the policy table.
        </p>
        <button
          type="button"
          className="dashboard-pagination-button"
          onClick={openCreatePolicyModal}
          disabled={!canMutatePolicies}
        >
          Create policy
        </button>
      </section>

      <section
        className="dashboard-view__section dashboard-policy-section--plain"
        aria-label="Policies table"
      >
        <h2>Policies</h2>
        <div className="dashboard-filters dashboard-policy-filters" aria-label="Policy filters">
          <label className="dashboard-search-control dashboard-search-control--compact">
            <span className="dashboard-search-icon" aria-hidden="true" />
            <input
              type="search"
              aria-label="Search policies"
              placeholder="Search policy name, ID, rules, or usage"
              value={policyQuery}
              onChange={(event) => setPolicyQuery(event.target.value)}
            />
          </label>
          <label className="dashboard-form-field dashboard-policy-filter">
            <select
              className="dashboard-input"
              aria-label="Filter policies by status"
              value={statusFilter}
              onChange={(event) =>
                setStatusFilter(event.target.value as PolicyStatusFilter)
              }
            >
              <option value="ALL">Status: All</option>
              <option value="DRAFT">Status: Draft</option>
              <option value="PUBLISHED">Status: Published</option>
            </select>
          </label>
          <label className="dashboard-form-field dashboard-policy-filter">
            <select
              className="dashboard-input"
              aria-label="Filter policies by impact"
              value={impactFilter}
              onChange={(event) =>
                setImpactFilter(event.target.value as PolicyImpactFilter)
              }
            >
              <option value="ALL">Impact: All</option>
              <option value="USED">Impact: Used by wallets</option>
              <option value="UNUSED">Impact: Unused</option>
            </select>
          </label>
        </div>
        {!coverageLoading && !coverageErrorMessage && coverage && coverage.totals.unassignedWalletCount > 0 ? (
          <p className="dashboard-pagination-note">
            {coverage.totals.unassignedWalletCount} wallet
            {coverage.totals.unassignedWalletCount === 1 ? '' : 's'} unassigned in the current scope.
          </p>
        ) : null}
        <section className="dashboard-table-wrapper dashboard-policy-table" aria-label="Policies rows">
          <div className="dashboard-table-header dashboard-policy-table__header" role="row">
            <span>Policy</span>
            <span>Status</span>
            <span>Current scope</span>
            <span>Used by</span>
            <span>Updated</span>
            <span>Actions</span>
          </div>
          {policiesLoading ? (
            <p className="dashboard-table-limit">Loading policies...</p>
          ) : policiesErrorMessage ? (
            <p className="dashboard-table-limit">Policies unavailable: {policiesErrorMessage}</p>
          ) : filteredPolicies.length === 0 ? (
            <p className="dashboard-table-limit">No policies matched the current search and filters.</p>
          ) : (
            <>
              {filteredPolicies.map((policy) => {
                const isDefaultPolicy = policy.id === defaultPolicyId;
                const coverageEntry = coverageByPolicyId.get(policy.id) || null;
                return (
                  <div
                    className="dashboard-table-row dashboard-policy-table__row"
                    key={policy.id}
                    role="row"
                  >
                    <span title={policy.id}>
                      <strong>{policy.name || policy.id}</strong>
                      <br />
                      <code>{policy.id}</code>
                    </span>
                    <span>
                      {policy.status} v{policy.version}
                    </span>
                    <span title={policyContextUsage(policy)}>{policyContextUsage(policy)}</span>
                    <span>
                      {coverageEntry
                        ? `${coverageEntry.walletCount} wallet${
                            coverageEntry.walletCount === 1 ? '' : 's'
                          }`
                        : 'Unused'}
                    </span>
                    <span>{formatTimestamp(policy.updatedAt)}</span>
                    <span className="dashboard-policy-table__actions">
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => openPolicyModal('view', policy.id)}
                      >
                        View
                      </button>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => openPolicyModal('edit', policy.id)}
                        disabled={!canMutatePolicies}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => openPolicyModal('simulate', policy.id)}
                      >
                        Simulate
                      </button>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => {
                          setCreatingNewPolicy(false);
                          setSelectedPolicyId(policy.id);
                          openPolicyModal('assign', policy.id);
                        }}
                        disabled={!canMutatePolicies}
                      >
                        Assign
                      </button>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => openPolicyModal('publish', policy.id)}
                        disabled={!canMutatePolicies}
                      >
                        Schedule live change
                      </button>
                      <button
                        type="button"
                        className="dashboard-inline-link dashboard-inline-link--danger"
                        onClick={() => openPolicyModal('delete', policy.id)}
                        disabled={!canMutatePolicies || isDefaultPolicy}
                        title={isDefaultPolicy ? 'The organization default policy cannot be deleted.' : ''}
                      >
                        Delete
                      </button>
                    </span>
                  </div>
                );
              })}
              <p className="dashboard-table-limit">
                Showing {filteredPolicies.length} of {visiblePolicies.length} loaded policy
                {visiblePolicies.length === 1 ? '' : 'ies'}.
              </p>
            </>
          )}
        </section>
      </section>

      {activeModal ? (
        <div
          className="dashboard-inline-modal-backdrop"
          role="presentation"
          onClick={closePolicyModal}
        >
          <section
            className="dashboard-modal dashboard-modal--wide"
            role="dialog"
            aria-modal="true"
            aria-label={
              activeModal.kind === 'create'
                ? 'Create policy modal'
                : activeModal.kind === 'view'
                  ? 'View policy modal'
                  : activeModal.kind === 'edit'
                    ? 'Edit policy modal'
                    : activeModal.kind === 'assign'
                      ? 'Assign policy modal'
                    : activeModal.kind === 'delete'
                      ? 'Delete policy modal'
                      : activeModal.kind === 'simulate'
                        ? 'Simulate policy modal'
                        : 'Schedule live policy change modal'
            }
            onClick={(event) => event.stopPropagation()}
          >
            {activeModal.kind === 'create' || activeModal.kind === 'edit' ? (
              <>
                <h2>{activeModal.kind === 'create' ? 'Create policy' : 'Edit policy'}</h2>
                <p className="dashboard-pagination-note">
                  The builder currently reflects live backend enforcement for blocked actions,
                  allowed chains, max amount per transaction, and contract-call allowlists.
                </p>
                <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={savePolicy}>
                  <div className="dashboard-form-field dashboard-form-field--full">
                    <span>Scope and inheritance</span>
                    <p className="dashboard-pagination-note">
                      Choose where this draft is intended to be used. Assignment still happens
                      explicitly from the table.
                    </p>
                  </div>
                  {renderScopeFields()}
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
                    <span>Max amount per transaction (minor units)</span>
                    <input
                      className="dashboard-input"
                      value={maxAmountMinor}
                      onChange={(event) => setMaxAmountMinor(event.target.value)}
                      placeholder="100000"
                      disabled={!canMutatePolicies || mutationBusy === 'save'}
                    />
                  </label>

                  <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Blocked actions</span>
                      <p className="dashboard-pagination-note">
                        Deny high-risk operations entirely.
                      </p>
                    </div>
                    <div className="dashboard-policy-toggle-grid">
                      {policyActionToggleOptions.map((action) => {
                        const checked = blockedActions.some(
                          (entry) => entry.toLowerCase() === action.toLowerCase(),
                        );
                        return (
                          <button
                            key={action}
                            type="button"
                            aria-pressed={checked}
                            className={[
                              'dashboard-policy-segment',
                              checked ? 'dashboard-policy-segment--active' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                            onClick={() =>
                              setBlockedActions((current) => toggleStringValue(current, action))
                            }
                            disabled={!canMutatePolicies || mutationBusy === 'save'}
                          >
                            {action}
                          </button>
                        );
                      })}
                    </div>
                  </section>

                  <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Allowed chains</span>
                      <p className="dashboard-pagination-note">
                        Limit the policy to specific networks.
                      </p>
                    </div>
                    <div className="dashboard-policy-toggle-grid">
                      {POLICY_CHAINS.map((chain) => {
                        const checked = allowedChains.some(
                          (entry) => entry.toLowerCase() === chain.toLowerCase(),
                        );
                        return (
                          <button
                            key={chain}
                            type="button"
                            aria-pressed={checked}
                            className={[
                              'dashboard-policy-segment',
                              checked ? 'dashboard-policy-segment--active' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                            onClick={() =>
                              setAllowedChains((current) => toggleStringValue(current, chain))
                            }
                            disabled={!canMutatePolicies || mutationBusy === 'save'}
                          >
                            {chain}
                          </button>
                        );
                      })}
                    </div>
                  </section>

                  <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Contract calls</span>
                      <p className="dashboard-pagination-note">
                        Control whether contract calls are blocked entirely, and optionally whitelist
                        which contracts and functions are reachable.
                      </p>
                    </div>
                    <div className="dashboard-policy-contract-call-mode">
                      <button
                        type="button"
                        aria-pressed={!contractCallBlocked}
                        className={[
                          'dashboard-policy-segment',
                          !contractCallBlocked ? 'dashboard-policy-segment--active' : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        onClick={() => setContractCallBlocked(false)}
                        disabled={!canMutatePolicies || mutationBusy === 'save'}
                      >
                        Allowed
                      </button>
                      <button
                        type="button"
                        aria-pressed={contractCallBlocked}
                        className={[
                          'dashboard-policy-segment',
                          contractCallBlocked ? 'dashboard-policy-segment--active' : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        onClick={() => setContractCallBlocked(true)}
                        disabled={!canMutatePolicies || mutationBusy === 'save'}
                      >
                        Blocked
                      </button>
                    </div>

                    {!contractCallBlocked ? (
                      <div className="dashboard-policy-contract-calls">
                        {contractCallRules.length === 0 ? (
                          <p className="dashboard-pagination-note">
                            No contract allowlist configured. Leaving this empty allows contract calls
                            on any contract for the selected chains.
                          </p>
                        ) : null}
                        {contractCallRules.map((rule) => (
                          <div key={rule.id} className="dashboard-policy-contract-card">
                            <div className="dashboard-policy-contract-card__header">
                              <strong>Allowed contract</strong>
                              <button
                                type="button"
                                className="dashboard-inline-link dashboard-inline-link--danger"
                                onClick={() => removeContractCallRule(rule.id)}
                                disabled={!canMutatePolicies || mutationBusy === 'save'}
                              >
                                Remove
                              </button>
                            </div>
                            <label className="dashboard-form-field">
                              <span>Contract address</span>
                              <input
                                className="dashboard-input"
                                value={rule.contractAddress}
                                onChange={(event) =>
                                  updateContractCallRuleAddress(rule.id, event.target.value)
                                }
                                placeholder="0x..."
                                disabled={!canMutatePolicies || mutationBusy === 'save'}
                              />
                            </label>
                            <div className="dashboard-uri-list-editor__rows">
                              {rule.functions.map((functionEntry, index) => (
                                <div key={`${rule.id}:${index}`} className="dashboard-uri-list-editor__row">
                                  <label className="dashboard-form-field dashboard-uri-list-editor__field">
                                    <span>{index === 0 ? 'Allowed functions' : 'Function'}</span>
                                    <input
                                      className="dashboard-input"
                                      value={functionEntry}
                                      onChange={(event) =>
                                        updateContractFunction(rule.id, index, event.target.value)
                                      }
                                      placeholder="transfer(address,uint256) or 0xa9059cbb"
                                      disabled={!canMutatePolicies || mutationBusy === 'save'}
                                    />
                                  </label>
                                  <div className="dashboard-uri-list-editor__actions">
                                    <button
                                      type="button"
                                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                                      onClick={() => removeContractFunction(rule.id, index)}
                                      disabled={!canMutatePolicies || mutationBusy === 'save'}
                                    >
                                      Remove
                                    </button>
                                  </div>
                                </div>
                              ))}
                            </div>
                            <button
                              type="button"
                              className="dashboard-inline-link"
                              onClick={() => addContractFunction(rule.id)}
                              disabled={!canMutatePolicies || mutationBusy === 'save'}
                            >
                              Add function
                            </button>
                          </div>
                        ))}
                        <button
                          type="button"
                          className="dashboard-pagination-button dashboard-pagination-button--secondary"
                          onClick={addContractCallRule}
                          disabled={!canMutatePolicies || mutationBusy === 'save'}
                        >
                          Add contract
                        </button>
                      </div>
                    ) : (
                      <p className="dashboard-pagination-note">
                        All contract calls are blocked by this policy.
                      </p>
                    )}
                  </section>

                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={closePolicyModal}
                      disabled={mutationBusy === 'save'}
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      className="dashboard-pagination-button"
                      disabled={!canMutatePolicies || mutationBusy === 'save'}
                    >
                      {mutationBusy === 'save'
                        ? 'Saving...'
                        : activeModal.kind === 'create'
                          ? 'Create draft'
                          : 'Save draft'}
                    </button>
                  </div>
                </form>
              </>
            ) : null}

            {activeModal.kind === 'view' ? (
              activeModalPolicy ? (
                <>
                  <h2>Policy details</h2>
                  <p className="dashboard-pagination-note">
                    <code>{activeModalPolicy.id}</code>
                  </p>
                  <ul className="dashboard-view-list">
                    <li>
                      <strong>Name</strong> {activeModalPolicy.name || activeModalPolicy.id}
                    </li>
                    <li>
                      <strong>Status</strong> {activeModalPolicy.status} v{activeModalPolicy.version}
                    </li>
                    <li>
                      <strong>Current scope usage</strong> {policyContextUsage(activeModalPolicy)}
                    </li>
                    <li>
                      <strong>Rules</strong> {rulesSummary(activeModalPolicy)}
                    </li>
                    <li>
                      <strong>Published</strong> {formatTimestamp(activeModalPolicy.publishedAt)}
                    </li>
                    <li>
                      <strong>Updated</strong> {formatTimestamp(activeModalPolicy.updatedAt)}
                    </li>
                    <li>
                      <strong>Coverage</strong>{' '}
                      {coverageLoading
                        ? 'Loading current impact...'
                        : coverageErrorMessage
                          ? `Unavailable: ${coverageErrorMessage}`
                          : policyCoverageSummary(coverageByPolicyId.get(activeModalPolicy.id) || null)}
                    </li>
                  </ul>
                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={closePolicyModal}
                    >
                      Close
                    </button>
                  </div>
                </>
              ) : (
                <p className="dashboard-pagination-note">Policy details are unavailable.</p>
              )
            ) : null}

            {activeModal.kind === 'simulate' ? (
              activeModalPolicy ? (
                <>
                  <h2>Simulate policy</h2>
                  <p className="dashboard-pagination-note">
                    Test {activeModalPolicy.name || activeModalPolicy.id} before assigning or publishing it.
                  </p>
                  <div className="dashboard-view-grid dashboard-view-grid--two">
                    <label className="dashboard-form-field">
                      <span>Action</span>
                      <select
                        className="dashboard-input"
                        value={simulationAction}
                        onChange={(event) => setSimulationAction(event.target.value)}
                      >
                        {POLICY_ACTIONS.map((action) => (
                          <option key={action} value={action}>
                            {action}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="dashboard-form-field">
                      <span>Chain</span>
                      <select
                        className="dashboard-input"
                        value={simulationChain}
                        onChange={(event) => setSimulationChain(event.target.value)}
                      >
                        {POLICY_CHAINS.map((chain) => (
                          <option key={chain} value={chain}>
                            {chain}
                          </option>
                        ))}
                      </select>
                    </label>
                    <label className="dashboard-form-field">
                      <span>Amount (minor units)</span>
                      <input
                        className="dashboard-input"
                        value={simulationAmountMinor}
                        onChange={(event) => setSimulationAmountMinor(event.target.value)}
                        placeholder="10000"
                      />
                    </label>
                    {simulationAction === 'contract_call' ? (
                      <>
                        <label className="dashboard-form-field">
                          <span>Contract address</span>
                          <input
                            className="dashboard-input"
                            value={simulationContractAddress}
                            onChange={(event) =>
                              setSimulationContractAddress(event.target.value)
                            }
                            placeholder="0x..."
                          />
                        </label>
                        <label className="dashboard-form-field">
                          <span>Function selector</span>
                          <input
                            className="dashboard-input"
                            value={simulationFunctionSelector}
                            onChange={(event) =>
                              setSimulationFunctionSelector(event.target.value)
                            }
                            placeholder="transfer(address,uint256) or 0xa9059cbb"
                          />
                        </label>
                      </>
                    ) : null}
                  </div>
                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={closePolicyModal}
                      disabled={simulationBusy}
                    >
                      Close
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={() => void runSimulation()}
                      disabled={simulationBusy || !selectedPolicyId}
                    >
                      {simulationBusy ? 'Simulating...' : 'Run simulation'}
                    </button>
                  </div>
                  {simulationErrorMessage ? (
                    <p className="dashboard-pagination-note">{simulationErrorMessage}</p>
                  ) : null}
                  {simulationResult ? (
                    <p className="dashboard-pagination-note">
                      Decision {simulationResult.decision} on policy {simulationResult.policyId} v
                      {simulationResult.policyVersion}. {simulationSummary(simulationResult)}
                    </p>
                  ) : null}
                </>
              ) : (
                <p className="dashboard-pagination-note">Select a policy before simulating it.</p>
              )
            ) : null}

            {activeModal.kind === 'assign' ? (
              activeModalPolicy ? (
                <>
                  <h2>Assign policy</h2>
                  <p className="dashboard-pagination-note">
                    Assign <strong>{activeModalPolicy.name || activeModalPolicy.id}</strong> to an
                    organization, project, environment, or wallet scope.
                  </p>
                  <div className="dashboard-view-grid dashboard-view-grid--two">
                    {renderScopeFields()}
                  </div>
                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={closePolicyModal}
                      disabled={mutationBusy === 'assign'}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={() => void assignPolicyToSelectedScope(activeModalPolicy.id)}
                      disabled={!canMutatePolicies || mutationBusy === 'assign'}
                    >
                      {mutationBusy === 'assign' ? 'Assigning...' : 'Assign policy'}
                    </button>
                  </div>
                </>
              ) : (
                <p className="dashboard-pagination-note">Policy details are unavailable.</p>
              )
            ) : null}

            {activeModal.kind === 'delete' ? (
              activeModalPolicy ? (
                <>
                  <h2>Delete policy</h2>
                  <p className="dashboard-pagination-note">
                    Delete <strong>{activeModalPolicy.name || activeModalPolicy.id}</strong> and remove it
                    from the registry. This does not delete wallet activity history.
                  </p>
                  {activeModalPolicy.id === defaultPolicyId ? (
                    <p className="dashboard-pagination-note">
                      The organization default policy is protected and cannot be deleted.
                    </p>
                  ) : null}
                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={closePolicyModal}
                      disabled={mutationBusy === 'delete'}
                    >
                      Cancel
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={() => void deleteSelectedPolicy()}
                      disabled={
                        !canMutatePolicies ||
                        mutationBusy === 'delete' ||
                        activeModalPolicy.id === defaultPolicyId
                      }
                    >
                      {mutationBusy === 'delete' ? 'Deleting...' : 'Delete policy'}
                    </button>
                  </div>
                </>
              ) : (
                <p className="dashboard-pagination-note">Policy details are unavailable.</p>
              )
            ) : null}

            {activeModal.kind === 'publish' ? (
              activeModalPolicy ? (
                <>
                  <h2>Schedule live policy change</h2>
                  <p className="dashboard-pagination-note">
                    Queue this policy change for admin approvals before it is published and deployed live.
                  </p>
                  <p className="dashboard-pagination-note">
                    Policy: <strong>{activeModalPolicy.name || activeModalPolicy.id}</strong> ·{' '}
                    <code>{activeModalPolicy.id}</code> · {activeModalPolicy.status} v
                    {activeModalPolicy.version}
                  </p>
                  <p className="dashboard-pagination-note">
                    Impact:{' '}
                    {coverageLoading
                      ? 'Loading current impact...'
                      : coverageErrorMessage
                        ? `Unavailable: ${coverageErrorMessage}`
                        : policyCoverageSummary(coverageByPolicyId.get(activeModalPolicy.id) || null)}
                  </p>
                  <div className="dashboard-view-grid dashboard-view-grid--two">
                    <label className="dashboard-form-field">
                      <span>New approval request reason</span>
                      <input
                        className="dashboard-input"
                        value={approvalCreateReason}
                        onChange={(event) => setApprovalCreateReason(event.target.value)}
                        placeholder="Policy reviewed for publish."
                        disabled={!canMutatePolicies || mutationBusy === 'approval-create'}
                      />
                    </label>
                    <label className="dashboard-form-field">
                      <span>Approval decision reason</span>
                      <input
                        className="dashboard-input"
                        value={approvalDecisionReason}
                        onChange={(event) => setApprovalDecisionReason(event.target.value)}
                        placeholder="Reviewed in policy engine."
                        disabled={!canMutatePolicies}
                      />
                    </label>
                    <label className="dashboard-form-field dashboard-form-field--full">
                      <span>Approved request for live publish</span>
                      <select
                        className="dashboard-input"
                        value={selectedApprovalId}
                        onChange={(event) => setSelectedApprovalId(event.target.value)}
                        disabled={approvalsLoading || approvedApprovals.length === 0}
                      >
                        <option value="">No approved request selected</option>
                        {approvedApprovals.map((approval) => (
                          <option key={approval.id} value={approval.id}>
                            {approval.id} ({approval.status})
                          </option>
                        ))}
                      </select>
                    </label>
                  </div>

                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={closePolicyModal}
                      disabled={mutationBusy === 'approval-create' || mutationBusy === 'publish'}
                    >
                      Close
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={() => void createPublishApproval()}
                      disabled={
                        !canMutatePolicies || !selectedPolicyId || mutationBusy === 'approval-create'
                      }
                    >
                      {mutationBusy === 'approval-create'
                        ? 'Creating request...'
                        : 'Create approval request'}
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={() => void publishSelectedPolicy()}
                      disabled={
                        !canMutatePolicies ||
                        !selectedPolicyId ||
                        activeModalPolicy.status === 'PUBLISHED' ||
                        mutationBusy === 'publish' ||
                        (!approvalsErrorMessage &&
                          relevantApprovals.length > 0 &&
                          approvedApprovals.length === 0)
                      }
                    >
                      {mutationBusy === 'publish' ? 'Publishing...' : 'Publish live'}
                    </button>
                  </div>

                  {approvalsLoading ? (
                    <p className="dashboard-pagination-note">Loading live-change approvals...</p>
                  ) : approvalsErrorMessage ? (
                    <p className="dashboard-pagination-note">
                      Approvals unavailable: {approvalsErrorMessage}
                    </p>
                  ) : relevantApprovals.length === 0 ? (
                    <p className="dashboard-pagination-note">
                      No approval requests are linked to this policy yet.
                    </p>
                  ) : (
                    <ul className="dashboard-view-list">
                      {relevantApprovals.map((approval) => (
                        <li key={approval.id}>
                          <strong>{approval.id}</strong> {approval.status} requested by{' '}
                          <code>{approval.requestedByUserId}</code> at{' '}
                          {formatTimestamp(approval.createdAt)}. {approval.reason}
                          {approval.status === 'PENDING' ? (
                            <>
                              {' '}
                              <button
                                type="button"
                                className="dashboard-inline-link"
                                onClick={() => void approveRequest(approval)}
                                disabled={
                                  !canMutatePolicies || mutationBusy === `approve:${approval.id}`
                                }
                              >
                                {mutationBusy === `approve:${approval.id}`
                                  ? 'Approving...'
                                  : 'Approve'}
                              </button>{' '}
                              <button
                                type="button"
                                className="dashboard-inline-link dashboard-inline-link--danger"
                                onClick={() => void rejectRequest(approval)}
                                disabled={
                                  !canMutatePolicies || mutationBusy === `reject:${approval.id}`
                                }
                              >
                                {mutationBusy === `reject:${approval.id}`
                                  ? 'Rejecting...'
                                  : 'Reject'}
                              </button>
                            </>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  )}
                </>
              ) : (
                <p className="dashboard-pagination-note">Select a policy before scheduling it live.</p>
              )
            ) : null}
          </section>
        </div>
      ) : null}
    </div>
  );
}

export default PolicyEnginePage;
