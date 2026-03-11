import React from 'react';
import { toast } from 'sonner';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableBadge,
  DashboardTableCell,
  DashboardTableDetailsGrid,
  DashboardTableDetailsItem,
  DashboardTableDetailsPanel,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import { DashboardInlineModal } from '../../components/DashboardInlineModal';
import {
  approveDashboardApproval,
  createDashboardApproval,
  listDashboardApprovals,
  rejectDashboardApproval,
  type DashboardConsoleApprovalRequest,
} from '../approvals/consoleApprovalsApi';
import { getDashboardPolicyCoverage, type DashboardPolicyCoverage } from '../consoleInsightsApi';
import {
  formatWalletBalanceMinor,
  listDashboardWallets,
  type DashboardConsoleWallet,
} from '../wallets/consoleWalletApi';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useSessionDraft } from '../../drafts/useSessionDraft';
import type { DashboardDraftIdentity } from '../../drafts/sessionDraftStore';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  createDashboardPolicy,
  deleteDashboardPolicy,
  listDashboardPolicies,
  listDashboardPolicyVersions,
  listDashboardPolicyAssignments,
  publishDashboardPolicy,
  simulateDashboardPolicy,
  updateDashboardPolicy,
  type DashboardConsolePolicy,
  type DashboardConsolePolicyVersion,
  type DashboardConsolePolicyAssignment,
  type DashboardConsolePolicySimulation,
} from './consolePoliciesApi';

type PolicyScopeType = 'ORG' | 'PROJECT' | 'ENVIRONMENT' | 'WALLET';
type PolicyCreateMode = 'STANDARD' | 'WALLET_OVERRIDE';
type PolicyModalKind = 'create' | 'edit' | 'delete' | 'simulate' | 'publish';
type PolicyStatusFilter = 'ALL' | 'DRAFT' | 'PUBLISHED';
type PolicyImpactFilter = 'ALL' | 'USED' | 'UNUSED';
const POLICY_TABLE_COLUMNS = dashboardTableColumns(1.2, 0.8, 1.2, 0.75, 0.85, 1.3);

interface PolicyModalState {
  kind: PolicyModalKind;
  policyId?: string;
}

interface PolicyContractRuleDraft {
  id: string;
  contractAddress: string;
  functions: string[];
}

type PolicyContractCallMode = 'ALLOW_ALL' | 'ALLOWLIST';

interface PolicyContractCallsDraft {
  mode: PolicyContractCallMode;
  rules: PolicyContractRuleDraft[];
}

interface PolicyEditorFormState {
  walletId: string;
  policyName: string;
  blockedActions: string[];
  contractCalls: PolicyContractCallsDraft;
  allowedChains: string[];
  maxAmountMinor: string;
}

interface PolicyDraftScope {
  orgId: string;
  projectId: string;
  environmentId: string;
}

interface PolicyRuleReviewRow {
  label: string;
  live: string;
  next: string;
  changed: boolean;
}

interface PolicyReviewTableRow {
  label: string;
  value: React.ReactNode;
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

const POLICY_CHAINS = ['Ethereum', 'NEAR', 'Tempo', 'Arc Circle'] as const;

function allPolicyChains(): string[] {
  return [...POLICY_CHAINS];
}

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

function formatPolicyStatusLabel(status: DashboardConsolePolicy['status']): string {
  switch (status) {
    case 'PUBLISHED':
      return 'Published';
    case 'DRAFT':
      return 'Draft';
    case 'ARCHIVED':
      return 'Archived';
    default:
      return status;
  }
}

function policyStatusBadgeTone(
  status: DashboardConsolePolicy['status'],
): 'success' | 'warning' | 'danger' | 'neutral' {
  switch (status) {
    case 'PUBLISHED':
      return 'success';
    case 'DRAFT':
      return 'warning';
    case 'ARCHIVED':
      return 'danger';
    default:
      return 'neutral';
  }
}

function defaultPolicyName(createMode: PolicyCreateMode): string {
  if (createMode === 'WALLET_OVERRIDE') return 'Wallet signing override';
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

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return Boolean(raw) && typeof raw === 'object' && !Array.isArray(raw);
}

function createInitialPolicyEditorForm(
  createMode: PolicyCreateMode,
  walletId: string,
): PolicyEditorFormState {
  return {
    walletId: String(walletId || '').trim(),
    policyName: defaultPolicyName(createMode),
    blockedActions: ['delete_key'],
    contractCalls: {
      mode: 'ALLOW_ALL',
      rules: [],
    },
    allowedChains: allPolicyChains(),
    maxAmountMinor: '',
  };
}

function createPolicyEditorFormFromPolicy(
  policy: DashboardConsolePolicy,
  walletId: string,
): PolicyEditorFormState {
  const nextBlockedActions = readStringRuleList(policy.rules.blockedActions).filter(
    (entry) => entry.toLowerCase() !== 'contract_call',
  );
  const nextContractCallRules = readContractCallRuleDrafts(policy.rules.allowedContractCalls);
  return {
    walletId: String(walletId || '').trim(),
    policyName: policy.name || defaultPolicyName('STANDARD'),
    blockedActions: nextBlockedActions,
    contractCalls: {
      mode: nextContractCallRules.length > 0 ? 'ALLOWLIST' : 'ALLOW_ALL',
      rules: nextContractCallRules,
    },
    allowedChains: (() => {
      const configuredChains = readStringRuleList(policy.rules.allowedChains);
      return configuredChains.length > 0 ? configuredChains : allPolicyChains();
    })(),
    maxAmountMinor: readNumberRule(policy.rules.maxAmountMinor),
  };
}

function readContractCallsDraft(raw: unknown): PolicyContractCallsDraft {
  if (!isRecord(raw)) {
    return {
      mode: 'ALLOW_ALL',
      rules: [],
    };
  }
  const mode =
    String(raw.mode || '')
      .trim()
      .toUpperCase() === 'ALLOWLIST'
      ? 'ALLOWLIST'
      : 'ALLOW_ALL';
  return {
    mode,
    rules: readContractCallRuleDrafts(raw.rules),
  };
}

function parsePolicyEditorDraft(
  raw: unknown,
  fallback: PolicyEditorFormState,
): PolicyEditorFormState | null {
  if (!isRecord(raw)) return null;
  return {
    walletId: normalizeDraftString(String(raw.walletId ?? fallback.walletId)),
    policyName: normalizeDraftString(String(raw.policyName ?? fallback.policyName)),
    blockedActions: readStringRuleList(raw.blockedActions),
    contractCalls: readContractCallsDraft(raw.contractCalls),
    allowedChains: readStringRuleList(raw.allowedChains),
    maxAmountMinor: normalizeDraftString(String(raw.maxAmountMinor ?? fallback.maxAmountMinor)),
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
      ? row.functions.map((value) => normalizeDraftString(String(value || ''))).filter(Boolean)
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
    contractCalls.length > 0
      ? `Contract calls: ${contractCalls.length} contract${contractCalls.length === 1 ? '' : 's'}`
      : 'Contract calls: all',
    maxAmountMinor ? `Max amount: ${maxAmountMinor}` : 'Max amount: none',
  ].join(' | ');
}

function summarizeRuleList(values: string[], emptyLabel: string): string {
  return values.length > 0 ? values.join(', ') : emptyLabel;
}

function summarizeContractCallRules(raw: unknown): string {
  const rules = readContractCallRuleDrafts(raw);
  if (rules.length === 0) return 'Allow all';
  return rules
    .map((rule) => {
      const contractAddress = normalizeDraftString(rule.contractAddress).toLowerCase();
      const functions = rule.functions.map((entry) => normalizeDraftString(entry)).filter(Boolean);
      if (functions.length === 0) return `${contractAddress} (all functions)`;
      const preview = functions.slice(0, 2).join(', ');
      const suffix = functions.length > 2 ? ` +${functions.length - 2} more` : '';
      return `${contractAddress} (${preview}${suffix})`;
    })
    .join('; ');
}

function buildPolicyRuleReviewRows(
  liveRules: Record<string, unknown> | null,
  nextRules: Record<string, unknown>,
): PolicyRuleReviewRow[] {
  const liveBlockedActions = summarizeRuleList(
    readStringRuleList(liveRules?.blockedActions),
    'None',
  );
  const nextBlockedActions = summarizeRuleList(
    readStringRuleList(nextRules.blockedActions),
    'None',
  );
  const liveAllowedChains = summarizeRuleList(
    readStringRuleList(liveRules?.allowedChains),
    'All chains',
  );
  const nextAllowedChains = summarizeRuleList(
    readStringRuleList(nextRules.allowedChains),
    'All chains',
  );
  const liveContractCalls = summarizeContractCallRules(liveRules?.allowedContractCalls);
  const nextContractCalls = summarizeContractCallRules(nextRules.allowedContractCalls);
  const liveMaxAmountMinor = readNumberRule(liveRules?.maxAmountMinor) || 'No limit';
  const nextMaxAmountMinor = readNumberRule(nextRules.maxAmountMinor) || 'No limit';
  return [
    {
      label: 'Blocked actions',
      live: liveBlockedActions,
      next: nextBlockedActions,
      changed: liveBlockedActions !== nextBlockedActions,
    },
    {
      label: 'Allowed chains',
      live: liveAllowedChains,
      next: nextAllowedChains,
      changed: liveAllowedChains !== nextAllowedChains,
    },
    {
      label: 'Contract calls',
      live: liveContractCalls,
      next: nextContractCalls,
      changed: liveContractCalls !== nextContractCalls,
    },
    {
      label: 'Max amount',
      live: liveMaxAmountMinor,
      next: nextMaxAmountMinor,
      changed: liveMaxAmountMinor !== nextMaxAmountMinor,
    },
  ];
}

function PolicyReviewTable(props: {
  ariaLabel: string;
  rows: PolicyReviewTableRow[];
}): React.JSX.Element {
  return (
    <div className="dashboard-policy-go-live__table-wrap">
      <table className="dashboard-policy-go-live__table" aria-label={props.ariaLabel}>
        <tbody>
          {props.rows.map((row) => (
            <tr key={row.label}>
              <th scope="row">{row.label}</th>
              <td>{row.value}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PolicyRuleComparisonTable(props: {
  ariaLabel: string;
  rows: PolicyRuleReviewRow[];
  nextColumnLabel: string;
  showLiveColumn: boolean;
}): React.JSX.Element {
  return (
    <div className="dashboard-policy-go-live__table-wrap">
      <table
        className="dashboard-policy-go-live__table dashboard-policy-go-live__table--comparison"
        aria-label={props.ariaLabel}
      >
        <thead>
          <tr>
            <th scope="col">Rule</th>
            {props.showLiveColumn ? <th scope="col">Live now</th> : null}
            <th scope="col">{props.nextColumnLabel}</th>
          </tr>
        </thead>
        <tbody>
          {props.rows.map((entry) => (
            <tr
              key={entry.label}
              className={entry.changed ? 'dashboard-policy-go-live__comparison-row--changed' : ''}
            >
              <th scope="row">
                <div className="dashboard-policy-go-live__comparison-label">
                  <span>{entry.label}</span>
                  <DashboardTableBadge tone={entry.changed ? 'warning' : 'neutral'}>
                    {entry.changed ? 'Changed' : 'Current'}
                  </DashboardTableBadge>
                </div>
              </th>
              {props.showLiveColumn ? <td>{entry.live}</td> : null}
              <td>{entry.next}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
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
  const denySummary = result.denyReasons
    .map((entry) => `${entry.code}: ${entry.message}`)
    .join(' ');
  return `Denied ${result.normalizedRequest.action} on ${chainLabel} with amount ${amountLabel}${contractLabel}. ${denySummary}`;
}

function policyCoverageSummary(entry: DashboardPolicyCoverage['policies'][number] | null): string {
  if (!entry) return 'Not currently covering wallets in this scope.';
  return `${entry.walletCount} wallet${entry.walletCount === 1 ? '' : 's'}, total balance ${formatWalletBalanceMinor(entry.totalBalanceMinor)}, last activity ${formatTimestamp(entry.lastActivityAt)}`;
}

function describePolicyDraftComparison(input: {
  policy: DashboardConsolePolicy;
  latestPublishedVersion: DashboardConsolePolicyVersion | null;
  changedRows: PolicyRuleReviewRow[];
}): string {
  if (input.policy.status === 'PUBLISHED') return 'This policy is already live.';
  if (!input.latestPublishedVersion) return 'This draft has not been published yet.';
  if (input.changedRows.length === 0) return 'This draft matches the current live rules.';
  return `This draft changes ${input.changedRows.length} rule section${
    input.changedRows.length === 1 ? '' : 's'
  } from the live version.`;
}

export function PolicyEnginePage(): React.JSX.Element {
  const viewRef = React.useRef<HTMLDivElement | null>(null);
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const { go } = useSiteRouter();
  const [requestedPolicyId, setRequestedPolicyId] = React.useState<string>(() => {
    if (typeof window === 'undefined') return '';
    return String(new URLSearchParams(window.location.search).get('policyId') || '').trim();
  });

  const orgScopeId =
    String(selectedContext.organization || session.claims?.orgId || '').trim() ||
    String(session.claims?.orgId || '').trim();
  const projectScopeId =
    String(selectedContext.project || session.claims?.projectId || '').trim() || '';
  const environmentScopeId =
    String(selectedContext.environment || session.claims?.environmentId || '').trim() || '';

  const [policiesLoading, setPoliciesLoading] = React.useState<boolean>(true);
  const [policiesErrorMessage, setPoliciesErrorMessage] = React.useState<string>('');
  const [policies, setPolicies] = React.useState<DashboardConsolePolicy[]>([]);

  const [assignmentsByScope, setAssignmentsByScope] =
    React.useState<Record<PolicyScopeType, DashboardConsolePolicyAssignment | null>>(
      EMPTY_ASSIGNMENTS,
    );

  const [coverageLoading, setCoverageLoading] = React.useState<boolean>(true);
  const [coverageErrorMessage, setCoverageErrorMessage] = React.useState<string>('');
  const [coverage, setCoverage] = React.useState<DashboardPolicyCoverage | null>(null);

  const [walletsLoading, setWalletsLoading] = React.useState<boolean>(true);
  const [walletsErrorMessage, setWalletsErrorMessage] = React.useState<string>('');
  const [wallets, setWallets] = React.useState<DashboardConsoleWallet[]>([]);

  const [approvalsLoading, setApprovalsLoading] = React.useState<boolean>(true);
  const [approvalsErrorMessage, setApprovalsErrorMessage] = React.useState<string>('');
  const [approvals, setApprovals] = React.useState<DashboardConsoleApprovalRequest[]>([]);

  const [policyVersionsLoading, setPolicyVersionsLoading] = React.useState<boolean>(false);
  const [policyVersionsErrorMessage, setPolicyVersionsErrorMessage] = React.useState<string>('');
  const [activePolicyVersions, setActivePolicyVersions] = React.useState<
    DashboardConsolePolicyVersion[]
  >([]);

  const [activeModal, setActiveModal] = React.useState<PolicyModalState | null>(null);
  const [creatingNewPolicy, setCreatingNewPolicy] = React.useState<boolean>(false);
  const [policyCreateMode, setPolicyCreateMode] = React.useState<PolicyCreateMode>('STANDARD');
  const [selectedPolicyId, setSelectedPolicyId] = React.useState<string>('');
  const [expandedPolicyId, setExpandedPolicyId] = React.useState<string>('');
  const [policyQuery, setPolicyQuery] = React.useState<string>('');
  const [statusFilter, setStatusFilter] = React.useState<PolicyStatusFilter>('ALL');
  const [impactFilter, setImpactFilter] = React.useState<PolicyImpactFilter>('ALL');
  const [policyDraftScope, setPolicyDraftScope] = React.useState<PolicyDraftScope | null>(null);
  const [policyEditorInitialForm, setPolicyEditorInitialForm] =
    React.useState<PolicyEditorFormState>(() => createInitialPolicyEditorForm('STANDARD', ''));

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

  React.useEffect(() => {
    if (typeof window === 'undefined') return;
    const syncRequestedPolicyId = () => {
      setRequestedPolicyId(String(new URLSearchParams(window.location.search).get('policyId') || '').trim());
    };
    window.addEventListener('popstate', syncRequestedPolicyId);
    window.addEventListener('site:navigate', syncRequestedPolicyId as EventListener);
    return () => {
      window.removeEventListener('popstate', syncRequestedPolicyId);
      window.removeEventListener('site:navigate', syncRequestedPolicyId as EventListener);
    };
  }, []);

  const currentContextScopeType = React.useMemo<PolicyScopeType>(() => {
    if (environmentScopeId) return 'ENVIRONMENT';
    if (projectScopeId) return 'PROJECT';
    return 'ORG';
  }, [environmentScopeId, projectScopeId]);

  const currentContextScopeId = React.useMemo(() => {
    if (currentContextScopeType === 'ENVIRONMENT') return environmentScopeId;
    if (currentContextScopeType === 'PROJECT') return projectScopeId;
    return orgScopeId;
  }, [currentContextScopeType, environmentScopeId, orgScopeId, projectScopeId]);

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
  const expandedPolicy = React.useMemo(
    () => policies.find((entry) => entry.id === expandedPolicyId) || null,
    [expandedPolicyId, policies],
  );

  const policyById = React.useMemo(() => {
    const out = new Map<string, DashboardConsolePolicy>();
    for (const policy of policies) out.set(policy.id, policy);
    return out;
  }, [policies]);

  const policyEditorModalOpen = activeModal?.kind === 'create' || activeModal?.kind === 'edit';

  const policyEditorDraftIdentity = React.useMemo<DashboardDraftIdentity | null>(() => {
    if (!policyEditorModalOpen || !policyDraftScope || !activeModal) return null;
    return {
      route: '/dashboard/policy-engine',
      builderId: 'policy-engine-policy-modal',
      mode: activeModal.kind === 'edit' ? 'edit' : 'create',
      orgId: policyDraftScope.orgId,
      projectId: policyDraftScope.projectId,
      environmentId: policyDraftScope.environmentId,
      resourceId:
        activeModal.kind === 'edit'
          ? String(activeModal.policyId || selectedPolicyId || '')
          : policyCreateMode === 'WALLET_OVERRIDE'
            ? 'wallet-override'
            : 'standard',
    };
  }, [activeModal, policyCreateMode, policyDraftScope, policyEditorModalOpen, selectedPolicyId]);

  const parsePolicyEditorFormDraft = React.useCallback(
    (raw: unknown): PolicyEditorFormState | null =>
      parsePolicyEditorDraft(raw, policyEditorInitialForm),
    [policyEditorInitialForm],
  );

  const {
    form: policyEditorForm,
    setForm: setPolicyEditorForm,
    restoreState: policyEditorRestoreState,
    clearDraft: clearPolicyEditorDraft,
    resetToInitial: resetPolicyEditorDraftToInitial,
  } = useSessionDraft<PolicyEditorFormState>({
    identity: policyEditorDraftIdentity,
    initialForm: policyEditorInitialForm,
    isOpen: policyEditorModalOpen,
    parseForm: parsePolicyEditorFormDraft,
  });
  const restoredDraftToastKeyRef = React.useRef<string>('');

  const directAssignment = assignmentsByScope[currentContextScopeType];

  const effectiveAssignment = React.useMemo(() => {
    if (currentContextScopeType === 'ENVIRONMENT') {
      return assignmentsByScope.ENVIRONMENT || assignmentsByScope.PROJECT || assignmentsByScope.ORG;
    }
    if (currentContextScopeType === 'PROJECT') {
      return assignmentsByScope.PROJECT || assignmentsByScope.ORG;
    }
    return assignmentsByScope.ORG;
  }, [assignmentsByScope, currentContextScopeType]);

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
    if (requestedPolicyId) scopedPolicyIds.add(requestedPolicyId);
    if (expandedPolicyId) scopedPolicyIds.add(expandedPolicyId);
    for (const policy of policies) {
      if (policy.status === 'DRAFT') scopedPolicyIds.add(policy.id);
    }
    const rows = policies.filter((policy) => scopedPolicyIds.has(policy.id));
    return rows.length > 0 ? rows : policies;
  }, [assignmentsByScope, coverage, expandedPolicyId, policies, requestedPolicyId]);

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

  React.useEffect(() => {
    if (
      !policyEditorModalOpen ||
      policyEditorRestoreState !== 'restored' ||
      !policyEditorDraftIdentity
    )
      return;
    const toastKey = [
      policyEditorDraftIdentity.mode,
      policyEditorDraftIdentity.orgId,
      policyEditorDraftIdentity.projectId,
      policyEditorDraftIdentity.environmentId,
      policyEditorDraftIdentity.resourceId || '',
    ].join(':');
    if (restoredDraftToastKeyRef.current === toastKey) return;
    restoredDraftToastKeyRef.current = toastKey;
    toast('Restored unsaved draft.', {
      id: `policy-engine-draft:${toastKey}`,
      description: null,
    });
  }, [policyEditorDraftIdentity, policyEditorModalOpen, policyEditorRestoreState]);

  React.useEffect(() => {
    if (policyEditorModalOpen) return;
    restoredDraftToastKeyRef.current = '';
  }, [policyEditorModalOpen]);

  React.useEffect(() => {
    const policyId = String(expandedPolicyId || '').trim();
    if (!policyId) {
      setPolicyVersionsLoading(false);
      setPolicyVersionsErrorMessage('');
      setActivePolicyVersions([]);
      return;
    }
    let cancelled = false;
    setPolicyVersionsLoading(true);
    setPolicyVersionsErrorMessage('');
    setActivePolicyVersions([]);
    listDashboardPolicyVersions(policyId)
      .then((versions) => {
        if (cancelled) return;
        setActivePolicyVersions(versions);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setActivePolicyVersions([]);
        setPolicyVersionsErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setPolicyVersionsLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [expandedPolicyId]);

  React.useEffect(() => {
    const scrollHost = viewRef.current?.closest('.dashboard-main');
    if (!scrollHost) return undefined;
    if (activeModal) {
      scrollHost.classList.add('dashboard-main--modal-open');
    } else {
      scrollHost.classList.remove('dashboard-main--modal-open');
    }
    return () => {
      scrollHost.classList.remove('dashboard-main--modal-open');
    };
  }, [activeModal]);

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
      return;
    }
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
      if (environmentScopeId)
        targets.push({ scopeType: 'ENVIRONMENT', scopeId: environmentScopeId });

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
    }
  }, [
    environmentScopeId,
    orgScopeId,
    projectScopeId,
    session.claims,
    session.errorMessage,
  ]);

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
    void Promise.all([
      loadPolicies(),
      loadAssignments(),
      loadCoverage(),
      loadWallets(),
      loadApprovals(),
    ]);
  }, [loadApprovals, loadAssignments, loadCoverage, loadPolicies, loadWallets]);

  React.useEffect(() => {
    if (session.loading) return;
    refreshWorkspace();
  }, [refreshWorkspace, session.loading]);

  React.useEffect(() => {
    if (creatingNewPolicy) return;
    if (requestedPolicyId && policies.some((entry) => entry.id === requestedPolicyId)) {
      if (selectedPolicyId !== requestedPolicyId) {
        setSelectedPolicyId(requestedPolicyId);
      }
      return;
    }
    if (selectedPolicyId && policies.some((entry) => entry.id === selectedPolicyId)) return;
    const nextPolicyId =
      directAssignment?.policyId ||
      effectiveAssignment?.policyId ||
      policies.find((entry) => entry.status === 'DRAFT')?.id ||
      policies[0]?.id ||
      '';
    setSelectedPolicyId(nextPolicyId);
  }, [
    creatingNewPolicy,
    directAssignment,
    effectiveAssignment,
    policies,
    requestedPolicyId,
    selectedPolicyId,
  ]);

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
    if (!requestedPolicyId) return;
    setPolicyQuery((current) => (current === requestedPolicyId ? current : requestedPolicyId));
    setStatusFilter('ALL');
    setImpactFilter('ALL');
    setExpandedPolicyId((current) => (current === requestedPolicyId ? current : requestedPolicyId));
    setSelectedPolicyId((current) => (current === requestedPolicyId ? current : requestedPolicyId));
  }, [requestedPolicyId]);

  const openCreatePolicyModal = React.useCallback(() => {
    setCreatingNewPolicy(true);
    setPolicyCreateMode('STANDARD');
    setSelectedPolicyId('');
    setPolicyDraftScope({
      orgId: orgScopeId,
      projectId: projectScopeId,
      environmentId: environmentScopeId,
    });
    setPolicyEditorInitialForm(createInitialPolicyEditorForm('STANDARD', ''));
    setSimulationResult(null);
    setSimulationErrorMessage('');
    setMutationErrorMessage('');
    setMutationNotice('');
    setActiveModal({ kind: 'create' });
  }, [environmentScopeId, orgScopeId, projectScopeId]);

  const openCreateWalletOverrideModal = React.useCallback(() => {
    setCreatingNewPolicy(true);
    setPolicyCreateMode('WALLET_OVERRIDE');
    setSelectedPolicyId('');
    setPolicyDraftScope({
      orgId: orgScopeId,
      projectId: projectScopeId,
      environmentId: environmentScopeId,
    });
    setPolicyEditorInitialForm(createInitialPolicyEditorForm('WALLET_OVERRIDE', ''));
    setSimulationResult(null);
    setSimulationErrorMessage('');
    setMutationErrorMessage('');
    setMutationNotice('');
    setActiveModal({ kind: 'create' });
  }, [environmentScopeId, orgScopeId, projectScopeId]);

  const setPolicyModalState = React.useCallback(
    (kind: Exclude<PolicyModalKind, 'create'>, policyId: string) => {
      setCreatingNewPolicy(false);
      setPolicyCreateMode('STANDARD');
      setSelectedPolicyId(policyId);
      setExpandedPolicyId(policyId);
      if (kind === 'edit') {
        setPolicyDraftScope({
          orgId: orgScopeId,
          projectId: projectScopeId,
          environmentId: environmentScopeId,
        });
        const selected = policyById.get(policyId) || null;
        setPolicyEditorInitialForm(
          selected
            ? createPolicyEditorFormFromPolicy(selected, '')
            : createInitialPolicyEditorForm('STANDARD', ''),
        );
      } else {
        setPolicyDraftScope(null);
      }
      setSimulationResult(null);
      setSimulationErrorMessage('');
      setMutationErrorMessage('');
      setMutationNotice('');
      setActiveModal({ kind, policyId });
    },
    [environmentScopeId, orgScopeId, policyById, projectScopeId],
  );

  const clearPolicyModalState = React.useCallback(() => {
    setActiveModal(null);
    setSimulationErrorMessage('');
    setSimulationResult(null);
    if (creatingNewPolicy) {
      setCreatingNewPolicy(false);
    }
  }, [creatingNewPolicy]);

  const closePolicyModal = React.useCallback(() => {
    clearPolicyModalState();
  }, [clearPolicyModalState]);

  const toggleExpandedPolicy = React.useCallback(
    (policyId: string) => {
      setSelectedPolicyId(policyId);
      setExpandedPolicyId((current) => {
        const nextExpandedPolicyId = current === policyId ? '' : policyId;
        return nextExpandedPolicyId;
      });
      if (requestedPolicyId) {
        go('/dashboard/policy-engine');
      }
    },
    [go, requestedPolicyId],
  );

  const selectedContextScopeKey = `${orgScopeId}:${projectScopeId}:${environmentScopeId}`;
  const previousSelectedContextScopeKeyRef = React.useRef<string>(selectedContextScopeKey);
  React.useEffect(() => {
    if (previousSelectedContextScopeKeyRef.current === selectedContextScopeKey) return;
    previousSelectedContextScopeKeyRef.current = selectedContextScopeKey;
    if (!policyEditorModalOpen) return;
    closePolicyModal();
  }, [closePolicyModal, policyEditorModalOpen, selectedContextScopeKey]);

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

      const trimmedName = String(policyEditorForm.policyName || '').trim();
      if (!trimmedName) {
        setMutationErrorMessage('Policy name is required.');
        return;
      }
      if (
        creatingNewPolicy &&
        policyCreateMode === 'WALLET_OVERRIDE' &&
        !String(policyEditorForm.walletId || '').trim()
      ) {
        setMutationErrorMessage('Select or enter a wallet before creating a wallet override.');
        return;
      }

      setMutationBusy('save');
      setMutationErrorMessage('');
      setMutationNotice('');
      try {
        const nextRules: Record<string, unknown> = {};
        if (
          policyEditorForm.allowedChains.length > 0 &&
          policyEditorForm.allowedChains.length < POLICY_CHAINS.length
        ) {
          nextRules.allowedChains = policyEditorForm.allowedChains;
        }
        const nextBlockedActions = [...policyEditorForm.blockedActions];
        if (nextBlockedActions.length > 0) nextRules.blockedActions = nextBlockedActions;
        const nextContractCallRules = policyEditorForm.contractCalls.rules
          .map((entry) => ({
            contractAddress: normalizeDraftString(entry.contractAddress),
            functions: entry.functions.map((value) => normalizeDraftString(value)).filter(Boolean),
          }))
          .filter((entry) => entry.contractAddress);
        if (
          policyEditorForm.contractCalls.mode === 'ALLOWLIST' &&
          nextContractCallRules.length === 0
        ) {
          throw new Error('Add at least one contract before saving a contract-call allowlist.');
        }
        if (policyEditorForm.contractCalls.mode === 'ALLOWLIST') {
          nextRules.allowedContractCalls = nextContractCallRules;
        }
        const nextMaxAmountMinor = parseOptionalNonNegativeInt(
          policyEditorForm.maxAmountMinor,
          'Max amount per transaction',
        );
        if (nextMaxAmountMinor !== undefined) nextRules.maxAmountMinor = nextMaxAmountMinor;

        const policy =
          creatingNewPolicy || !selectedPolicyId
            ? await createDashboardPolicy({
                name: trimmedName,
                rules: nextRules,
                assignment:
                  policyCreateMode === 'WALLET_OVERRIDE'
                    ? {
                        scopeType: 'WALLET',
                        scopeId: String(policyEditorForm.walletId || '').trim(),
                      }
                    : {
                        scopeType: currentContextScopeType,
                        scopeId: currentContextScopeId,
                      },
              })
            : await updateDashboardPolicy({
                policyId: selectedPolicyId,
                name: trimmedName,
                rules: nextRules,
              });

        setCreatingNewPolicy(false);
        setSelectedPolicyId(policy.id);
        clearPolicyEditorDraft();
        setActiveModal(null);
        setMutationNotice(`Saved policy ${policy.id} (${policy.status}, v${policy.version}).`);
        await Promise.all([loadPolicies(), loadAssignments(), loadCoverage()]);
      } catch (error: unknown) {
        setMutationErrorMessage(error instanceof Error ? error.message : String(error));
      } finally {
        setMutationBusy('');
      }
    },
    [
      canMutatePolicies,
      clearPolicyEditorDraft,
      creatingNewPolicy,
      currentContextScopeId,
      currentContextScopeType,
      loadAssignments,
      loadCoverage,
      loadPolicies,
      policyCreateMode,
      policyEditorForm,
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
      const amountMinor = parseOptionalNonNegativeInt(simulationAmountMinor, 'Simulation amount');
      const result = await simulateDashboardPolicy({
        policyId: selectedPolicyId,
        action: simulationAction,
        ...(simulationChain ? { chain: simulationChain } : {}),
        ...(amountMinor !== undefined ? { amountMinor } : {}),
        ...(simulationContractAddress ? { contractAddress: simulationContractAddress.trim() } : {}),
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

  const policyScopeUsageLabels = React.useCallback(
    (policy: DashboardConsolePolicy): string[] => {
      const labels: string[] = [];
      if (assignmentsByScope.ORG?.policyId === policy.id) labels.push('org default');
      if (assignmentsByScope.PROJECT?.policyId === policy.id) labels.push('project default');
      if (assignmentsByScope.ENVIRONMENT?.policyId === policy.id)
        labels.push('environment override');
      if (assignmentsByScope.WALLET?.policyId === policy.id)
        labels.push('selected wallet override');
      return labels;
    },
    [assignmentsByScope],
  );

  const policyContextUsage = React.useCallback(
    (policy: DashboardConsolePolicy): string => {
      const labels = policyScopeUsageLabels(policy);
      const coverageEntry = coverageByPolicyId.get(policy.id);
      const walletCoverage = coverageEntry
        ? `${coverageEntry.walletCount} wallet${coverageEntry.walletCount === 1 ? '' : 's'}`
        : '0 wallets';
      return `${labels.length > 0 ? labels.join(', ') : 'draft or not attached'} | ${walletCoverage}`;
    },
    [coverageByPolicyId, policyScopeUsageLabels],
  );
  const filteredPolicies = React.useMemo(() => {
    const query = String(policyQuery || '')
      .trim()
      .toLowerCase();
    return visiblePolicies.filter((policy) => {
      if (statusFilter !== 'ALL' && policy.status !== statusFilter) return false;
      const coverageEntry = coverageByPolicyId.get(policy.id) || null;
      const used = Boolean(coverageEntry && coverageEntry.walletCount > 0);
      if (impactFilter === 'USED' && !used) return false;
      if (impactFilter === 'UNUSED' && used) return false;
      if (!query) return true;
      const haystack = [policy.id, policy.name, rulesSummary(policy), policyContextUsage(policy)]
        .filter(Boolean)
        .join(' ')
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [
    coverageByPolicyId,
    impactFilter,
    policyContextUsage,
    policyQuery,
    statusFilter,
    visiblePolicies,
  ]);
  const activeModalPolicy = activeModal?.policyId
    ? policyById.get(activeModal.policyId) || null
    : creatingNewPolicy
      ? null
      : selectedPolicy;
  const policiesPagination = useDashboardTablePagination(filteredPolicies, {
    disabled: policiesLoading,
    itemLabel: 'policy',
    itemLabelPlural: 'policies',
  });
  const latestPublishedVersion = React.useMemo(
    () => activePolicyVersions.find((entry) => entry.status === 'PUBLISHED') || null,
    [activePolicyVersions],
  );
  const activeModalRuleReviewRows = React.useMemo(
    () =>
      activeModalPolicy
        ? buildPolicyRuleReviewRows(latestPublishedVersion?.rules || null, activeModalPolicy.rules)
        : [],
    [activeModalPolicy, latestPublishedVersion],
  );
  const changedActiveModalRuleReviewRows = React.useMemo(
    () => activeModalRuleReviewRows.filter((entry) => entry.changed),
    [activeModalRuleReviewRows],
  );
  const activeModalDraftComparisonSummary = React.useMemo(
    () =>
      activeModalPolicy
        ? describePolicyDraftComparison({
            policy: activeModalPolicy,
            latestPublishedVersion,
            changedRows: changedActiveModalRuleReviewRows,
          })
        : '',
    [activeModalPolicy, changedActiveModalRuleReviewRows, latestPublishedVersion],
  );
  const activeModalScopeUsageLabels = React.useMemo(
    () => (activeModalPolicy ? policyScopeUsageLabels(activeModalPolicy) : []),
    [activeModalPolicy, policyScopeUsageLabels],
  );
  const activeModalCoverageEntry = React.useMemo(
    () => (activeModalPolicy ? coverageByPolicyId.get(activeModalPolicy.id) || null : null),
    [activeModalPolicy, coverageByPolicyId],
  );
  const nextLiveVersion = React.useMemo(() => {
    if (!activeModalPolicy) return 0;
    if (activeModalPolicy.status === 'PUBLISHED') return activeModalPolicy.version;
    return latestPublishedVersion ? latestPublishedVersion.version + 1 : 1;
  }, [activeModalPolicy, latestPublishedVersion]);
  const activeModalReviewRows = React.useMemo<PolicyReviewTableRow[]>(
    () =>
      activeModalPolicy
        ? [
            {
              label: 'Policy',
              value: (
                <span className="dashboard-policy-go-live__value-stack">
                  <strong>{activeModalPolicy.name || activeModalPolicy.id}</strong>
                  <code>{activeModalPolicy.id}</code>
                </span>
              ),
            },
            {
              label: 'Current live version',
              value: policyVersionsLoading
                ? 'Loading current live version...'
                : policyVersionsErrorMessage
                  ? `Unavailable: ${policyVersionsErrorMessage}`
                  : latestPublishedVersion
                    ? `v${latestPublishedVersion.version} published ${formatTimestamp(
                        latestPublishedVersion.publishedAt,
                      )}`
                    : 'Not live yet',
            },
            {
              label: 'Next live version',
              value: `v${nextLiveVersion}`,
            },
            {
              label: 'Scope affected',
              value:
                activeModalScopeUsageLabels.length > 0
                  ? activeModalScopeUsageLabels.join(', ')
                  : 'Not attached in the current org, project, and environment selection',
            },
            {
              label: 'Wallet impact',
              value: coverageLoading
                ? 'Loading current impact...'
                : coverageErrorMessage
                  ? `Unavailable: ${coverageErrorMessage}`
                  : activeModalCoverageEntry
                    ? `${activeModalCoverageEntry.walletCount} wallet${
                        activeModalCoverageEntry.walletCount === 1 ? '' : 's'
                      } currently use this policy`
                    : 'Unused in the current scope',
            },
          ]
        : [],
    [
      activeModalCoverageEntry,
      activeModalPolicy,
      activeModalScopeUsageLabels,
      coverageErrorMessage,
      coverageLoading,
      latestPublishedVersion,
      nextLiveVersion,
      policyVersionsErrorMessage,
      policyVersionsLoading,
    ],
  );
  const expandedPolicyRuleReviewRows = React.useMemo(
    () =>
      expandedPolicy
        ? buildPolicyRuleReviewRows(latestPublishedVersion?.rules || null, expandedPolicy.rules)
        : [],
    [expandedPolicy, latestPublishedVersion],
  );
  const changedExpandedPolicyRuleReviewRows = React.useMemo(
    () => expandedPolicyRuleReviewRows.filter((entry) => entry.changed),
    [expandedPolicyRuleReviewRows],
  );
  const expandedPolicyScopeUsageLabels = React.useMemo(
    () => (expandedPolicy ? policyScopeUsageLabels(expandedPolicy) : []),
    [expandedPolicy, policyScopeUsageLabels],
  );
  const expandedPolicyCoverageEntry = React.useMemo(
    () => (expandedPolicy ? coverageByPolicyId.get(expandedPolicy.id) || null : null),
    [coverageByPolicyId, expandedPolicy],
  );
  const expandedPolicyDraftComparisonSummary = React.useMemo(
    () =>
      expandedPolicy
        ? describePolicyDraftComparison({
            policy: expandedPolicy,
            latestPublishedVersion,
            changedRows: changedExpandedPolicyRuleReviewRows,
          })
        : '',
    [changedExpandedPolicyRuleReviewRows, expandedPolicy, latestPublishedVersion],
  );
  const policyActionToggleOptions = POLICY_ACTIONS.filter((entry) => entry !== 'contract_call');
  const addContractCallRule = React.useCallback(() => {
    setPolicyEditorForm((current) => ({
      ...current,
      contractCalls: {
        mode: 'ALLOWLIST',
        rules: [...current.contractCalls.rules, createEmptyContractRuleDraft()],
      },
    }));
  }, [setPolicyEditorForm]);
  const removeContractCallRule = React.useCallback(
    (ruleId: string) => {
      setPolicyEditorForm((current) => ({
        ...current,
        contractCalls: {
          ...current.contractCalls,
          rules: current.contractCalls.rules.filter((entry) => entry.id !== ruleId),
        },
      }));
    },
    [setPolicyEditorForm],
  );
  const updateContractCallRuleAddress = React.useCallback(
    (ruleId: string, value: string) => {
      setPolicyEditorForm((current) => ({
        ...current,
        contractCalls: {
          ...current.contractCalls,
          rules: current.contractCalls.rules.map((entry) =>
            entry.id === ruleId ? { ...entry, contractAddress: value } : entry,
          ),
        },
      }));
    },
    [setPolicyEditorForm],
  );
  const addContractFunction = React.useCallback(
    (ruleId: string) => {
      setPolicyEditorForm((current) => ({
        ...current,
        contractCalls: {
          ...current.contractCalls,
          rules: current.contractCalls.rules.map((entry) =>
            entry.id === ruleId ? { ...entry, functions: [...entry.functions, ''] } : entry,
          ),
        },
      }));
    },
    [setPolicyEditorForm],
  );
  const updateContractFunction = React.useCallback(
    (ruleId: string, functionIndex: number, value: string) => {
      setPolicyEditorForm((current) => ({
        ...current,
        contractCalls: {
          ...current.contractCalls,
          rules: current.contractCalls.rules.map((entry) =>
            entry.id === ruleId
              ? {
                  ...entry,
                  functions: entry.functions.map((functionEntry, index) =>
                    index === functionIndex ? value : functionEntry,
                  ),
                }
              : entry,
          ),
        },
      }));
    },
    [setPolicyEditorForm],
  );
  const removeContractFunction = React.useCallback(
    (ruleId: string, functionIndex: number) => {
      setPolicyEditorForm((current) => ({
        ...current,
        contractCalls: {
          ...current.contractCalls,
          rules: current.contractCalls.rules.map((entry) => {
            if (entry.id !== ruleId) return entry;
            const nextFunctions = entry.functions.filter((_, index) => index !== functionIndex);
            return {
              ...entry,
              functions: nextFunctions.length > 0 ? nextFunctions : [''],
            };
          }),
        },
      }));
    },
    [setPolicyEditorForm],
  );
  const renderWalletOverrideFields = (
    walletIdValue: string,
    onWalletIdChange: (nextWalletId: string) => void,
  ): React.JSX.Element => (
    <div className="dashboard-view-grid dashboard-view-grid--two dashboard-form-field dashboard-form-field--full">
      <label className="dashboard-form-field">
        <span>Wallet override target</span>
        <input
          className="dashboard-input"
          list="policy-engine-wallets"
          value={walletIdValue}
          onChange={(event) => onWalletIdChange(event.target.value)}
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
        ) : walletIdValue ? (
          <p className="dashboard-pagination-note">
            {(() => {
              const wallet = wallets.find((entry) => entry.id === walletIdValue) || null;
              if (!wallet) return `Wallet ${walletIdValue}`;
              return `${wallet.id} (${wallet.chain}, ${wallet.address})`;
            })()}
          </p>
        ) : (
          <p className="dashboard-pagination-note">Choose a wallet for the override target.</p>
        )}
      </div>
    </div>
  );

  const onPolicyEditorWalletIdChange = React.useCallback(
    (nextWalletId: string) => {
      setPolicyEditorForm((current) => ({
        ...current,
        walletId: nextWalletId,
      }));
    },
    [setPolicyEditorForm],
  );

  const policyEditorDraftDiffersFromInitial = React.useMemo(
    () => JSON.stringify(policyEditorForm) !== JSON.stringify(policyEditorInitialForm),
    [policyEditorForm, policyEditorInitialForm],
  );

  const discardPolicyEditorDraft = React.useCallback(() => {
    if (policyEditorDraftDiffersFromInitial && typeof window !== 'undefined') {
      const confirmed = window.confirm('Discard this unsaved draft?');
      if (!confirmed) return;
    }
    resetPolicyEditorDraftToInitial();
    closePolicyModal();
  }, [closePolicyModal, policyEditorDraftDiffersFromInitial, resetPolicyEditorDraftToInitial]);

  return (
    <div ref={viewRef} className="dashboard-view" aria-label="Policy engine page">
      <section className="dashboard-view__section" aria-label="Policy setup">
        <h2>Create policy</h2>
        <p className="dashboard-pagination-note">
          Create draft policies that stay attached to the current dashboard context, then manage
          them from the policy table.
        </p>
        <p className="dashboard-pagination-note">
          A wallet-specific override wins over inherited defaults, including environment policies.
        </p>
        <div className="dashboard-policy-setup-actions">
          <div className="dashboard-policy-setup-action">
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={openCreatePolicyModal}
              disabled={!canMutatePolicies}
            >
              Create policy
            </button>
            <p className="dashboard-pagination-note">
              Create a policy for all wallets in the current dashboard context.
            </p>
          </div>
          <div className="dashboard-policy-setup-action">
            <button
              type="button"
              className="dashboard-pagination-button dashboard-pagination-button--secondary"
              onClick={openCreateWalletOverrideModal}
              disabled={!canMutatePolicies}
            >
              Create wallet override
            </button>
            <p className="dashboard-pagination-note">
              Create a wallet-specific override for one wallet in the current dashboard context.
            </p>
          </div>
        </div>
      </section>

      <section className="dashboard-policy-section--plain" aria-label="Policies table">
        <h2>Current Policies</h2>
        {mutationNotice ? <p className="dashboard-pagination-note">{mutationNotice}</p> : null}
        {!policyEditorModalOpen && mutationErrorMessage ? (
          <p className="dashboard-pagination-note">{mutationErrorMessage}</p>
        ) : null}
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
              onChange={(event) => setStatusFilter(event.target.value as PolicyStatusFilter)}
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
              onChange={(event) => setImpactFilter(event.target.value as PolicyImpactFilter)}
            >
              <option value="ALL">Impact: All</option>
              <option value="USED">Impact: Used by wallets</option>
              <option value="UNUSED">Impact: Unused</option>
            </select>
          </label>
        </div>
        {!coverageLoading &&
        !coverageErrorMessage &&
        coverage &&
        coverage.totals.unassignedWalletCount > 0 ? (
          <p className="dashboard-pagination-note">
            {coverage.totals.unassignedWalletCount} wallet
            {coverage.totals.unassignedWalletCount === 1 ? '' : 's'} unassigned in the current
            scope.
          </p>
        ) : null}
        <DashboardTable
          ariaLabel="Policies rows"
          className="dashboard-policy-table"
          columns={POLICY_TABLE_COLUMNS}
          pagination={policiesPagination.pagination}
        >
          <DashboardTableHeader className="dashboard-policy-table__header">
            <DashboardTableHeaderCell>Policy</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Status</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Current scope</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Used by</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Updated</DashboardTableHeaderCell>
            <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
          </DashboardTableHeader>
          {policiesLoading ? (
            <DashboardTableState>Loading policies...</DashboardTableState>
          ) : policiesErrorMessage ? (
            <DashboardTableState>Policies unavailable: {policiesErrorMessage}</DashboardTableState>
          ) : filteredPolicies.length === 0 ? (
            <DashboardTableState>
              No policies matched the current search and filters.
            </DashboardTableState>
          ) : (
            <>
              {policiesPagination.rows.map((policy) => {
                const isDefaultPolicy = policy.isSystemDefault;
                const coverageEntry = coverageByPolicyId.get(policy.id) || null;
                const isExpanded = expandedPolicyId === policy.id;
                return (
                  <React.Fragment key={policy.id}>
                    <DashboardTableRow
                      className={
                        isExpanded
                          ? 'dashboard-policy-table__row dashboard-policy-table__row--expanded'
                          : 'dashboard-policy-table__row'
                      }
                    >
                      <DashboardTableCell title={policy.id}>
                        <div className="dashboard-policy-table__policy">
                          <strong className="dashboard-data-table__summary">
                            {policy.name || policy.id}
                          </strong>
                          <code className="dashboard-policy-table__policy-id">{policy.id}</code>
                        </div>
                      </DashboardTableCell>
                      <DashboardTableCell>
                        <DashboardTableBadge tone={policyStatusBadgeTone(policy.status)}>
                          {formatPolicyStatusLabel(policy.status)}
                        </DashboardTableBadge>
                        <span className="dashboard-data-table__subline dashboard-data-table__subline--muted">
                          v{policy.version}
                        </span>
                      </DashboardTableCell>
                      <DashboardTableCell title={policyContextUsage(policy)}>
                        {policyContextUsage(policy)}
                      </DashboardTableCell>
                      <DashboardTableCell>
                        {coverageEntry
                          ? `${coverageEntry.walletCount} wallet${
                              coverageEntry.walletCount === 1 ? '' : 's'
                            }`
                          : 'Unused'}
                      </DashboardTableCell>
                      <DashboardTableCell truncate>
                        {formatTimestamp(policy.updatedAt)}
                      </DashboardTableCell>
                      <DashboardTableCell>
                        <DashboardTableActionGroup>
                          <DashboardTableActionButton
                            className="dashboard-policy-table__toggle"
                            aria-expanded={isExpanded}
                            onClick={() => toggleExpandedPolicy(policy.id)}
                          >
                            {isExpanded ? 'Hide' : 'Details'}
                          </DashboardTableActionButton>
                          <DashboardTableActionButton
                            onClick={() => setPolicyModalState('edit', policy.id)}
                            disabled={!canMutatePolicies}
                          >
                            Edit
                          </DashboardTableActionButton>
                          <DashboardTableActionButton
                            onClick={() => setPolicyModalState('simulate', policy.id)}
                          >
                            Simulate
                          </DashboardTableActionButton>
                          <DashboardTableActionButton
                            onClick={() => setPolicyModalState('publish', policy.id)}
                            disabled={!canMutatePolicies}
                          >
                            Go live
                          </DashboardTableActionButton>
                          <DashboardTableActionButton
                            tone="danger"
                            onClick={() => setPolicyModalState('delete', policy.id)}
                            disabled={!canMutatePolicies || isDefaultPolicy}
                            title={
                              isDefaultPolicy
                                ? 'The organization default policy cannot be deleted.'
                                : ''
                            }
                          >
                            Delete
                          </DashboardTableActionButton>
                        </DashboardTableActionGroup>
                      </DashboardTableCell>
                    </DashboardTableRow>
                    <DashboardTableDetailsPanel
                      className={
                        isExpanded
                          ? 'dashboard-policy-table__details-panel is-expanded'
                          : 'dashboard-policy-table__details-panel'
                      }
                      aria-hidden={!isExpanded}
                    >
                      <div className="dashboard-policy-table__details-content">
                        {expandedPolicy?.id === policy.id ? (
                          <div className="dashboard-policy-view">
                            <header className="dashboard-policy-view__hero">
                              <div className="dashboard-policy-view__hero-copy">
                                <p className="dashboard-policy-view__eyebrow">Policy details</p>
                                <h3>{expandedPolicy.name || expandedPolicy.id}</h3>
                                <p className="dashboard-pagination-note">
                                  {expandedPolicy.description
                                    ? expandedPolicy.description
                                    : expandedPolicy.isSystemDefault
                                      ? 'Default live policy for this organization.'
                                      : expandedPolicyDraftComparisonSummary}
                                </p>
                              </div>
                              <div className="dashboard-policy-view__badges">
                                <DashboardTableBadge
                                  tone={policyStatusBadgeTone(expandedPolicy.status)}
                                >
                                  {formatPolicyStatusLabel(expandedPolicy.status)}
                                </DashboardTableBadge>
                                <DashboardTableBadge tone="neutral">
                                  v{expandedPolicy.version}
                                </DashboardTableBadge>
                                {expandedPolicy.isSystemDefault ? (
                                  <DashboardTableBadge tone="neutral">
                                    System default
                                  </DashboardTableBadge>
                                ) : null}
                              </div>
                            </header>

                            <DashboardTableDetailsGrid>
                              <DashboardTableDetailsItem label="Policy ID">
                                <code>{expandedPolicy.id}</code>
                              </DashboardTableDetailsItem>
                              <DashboardTableDetailsItem label="Live version">
                                <span>
                                  {policyVersionsLoading
                                    ? 'Loading...'
                                    : policyVersionsErrorMessage
                                      ? `Unavailable: ${policyVersionsErrorMessage}`
                                      : latestPublishedVersion
                                        ? `v${latestPublishedVersion.version} published ${formatTimestamp(
                                            latestPublishedVersion.publishedAt,
                                          )}`
                                        : 'Not live yet'}
                                </span>
                              </DashboardTableDetailsItem>
                              <DashboardTableDetailsItem label="Current scope">
                                <span>
                                  {expandedPolicyScopeUsageLabels.length > 0
                                    ? expandedPolicyScopeUsageLabels.join(', ')
                                    : 'Draft only'}
                                </span>
                              </DashboardTableDetailsItem>
                              <DashboardTableDetailsItem label="Coverage">
                                <span>
                                  {coverageLoading
                                    ? 'Loading current impact...'
                                    : coverageErrorMessage
                                      ? `Unavailable: ${coverageErrorMessage}`
                                      : policyCoverageSummary(expandedPolicyCoverageEntry)}
                                </span>
                              </DashboardTableDetailsItem>
                              <DashboardTableDetailsItem label="Published">
                                <span>{formatTimestamp(expandedPolicy.publishedAt)}</span>
                              </DashboardTableDetailsItem>
                              <DashboardTableDetailsItem label="Updated">
                                <span>{formatTimestamp(expandedPolicy.updatedAt)}</span>
                              </DashboardTableDetailsItem>
                            </DashboardTableDetailsGrid>

                            <section className="dashboard-view-card dashboard-policy-view__section">
                              <div className="dashboard-policy-view__section-header">
                                <div>
                                  <h3>Rules</h3>
                                  <p className="dashboard-pagination-note">
                                    Current policy behavior by rule section.
                                  </p>
                                </div>
                                <p className="dashboard-policy-view__summary">
                                  {rulesSummary(expandedPolicy)}
                                </p>
                              </div>
                              <div className="dashboard-policy-view__rule-grid">
                                {expandedPolicyRuleReviewRows.map((entry) => (
                                  <article
                                    key={`${expandedPolicy.id}:${entry.label}`}
                                    className={`dashboard-policy-view__rule-card${
                                      entry.changed
                                        ? ' dashboard-policy-view__rule-card--changed'
                                        : ''
                                    }`}
                                  >
                                    <div className="dashboard-policy-view__rule-card-header">
                                      <p className="dashboard-policy-view__rule-label">
                                        {entry.label}
                                      </p>
                                      <DashboardTableBadge
                                        tone={entry.changed ? 'warning' : 'neutral'}
                                      >
                                        {entry.changed ? 'Changed' : 'Current'}
                                      </DashboardTableBadge>
                                    </div>
                                    <p className="dashboard-policy-view__rule-value">{entry.next}</p>
                                    {expandedPolicy.status !== 'PUBLISHED' &&
                                    latestPublishedVersion ? (
                                      <p className="dashboard-policy-view__rule-compare">
                                        Live: {entry.live}
                                      </p>
                                    ) : null}
                                  </article>
                                ))}
                              </div>
                            </section>

                            <section className="dashboard-view-card dashboard-policy-view__section">
                              <div className="dashboard-policy-view__section-header">
                                <div>
                                  <h3>Change summary</h3>
                                  <p className="dashboard-pagination-note">
                                    {expandedPolicyDraftComparisonSummary}
                                  </p>
                                </div>
                              </div>
                              {expandedPolicy.status !== 'PUBLISHED' &&
                              latestPublishedVersion &&
                              changedExpandedPolicyRuleReviewRows.length > 0 ? (
                                <ul className="dashboard-view-list dashboard-policy-view__changes">
                                  {changedExpandedPolicyRuleReviewRows.map((entry) => (
                                    <li key={`${expandedPolicy.id}:change:${entry.label}`}>
                                      <strong>{entry.label}</strong> {entry.live} {'->'} {entry.next}
                                    </li>
                                  ))}
                                </ul>
                              ) : null}
                            </section>
                          </div>
                        ) : null}
                      </div>
                    </DashboardTableDetailsPanel>
                  </React.Fragment>
                );
              })}
            </>
          )}
        </DashboardTable>
      </section>

      {activeModal ? (
        <DashboardInlineModal
          isOpen
          onRequestClose={closePolicyModal}
          className="dashboard-modal--wide"
          ariaLabel={
            activeModal.kind === 'create'
              ? 'Create policy modal'
              : activeModal.kind === 'edit'
                ? 'Edit policy modal'
                : activeModal.kind === 'delete'
                  ? 'Delete policy modal'
                  : activeModal.kind === 'simulate'
                    ? 'Simulate policy modal'
                    : 'Schedule live policy change modal'
          }
        >
            {activeModal.kind === 'create' || activeModal.kind === 'edit' ? (
              <>
                <h2>
                  {activeModal.kind === 'create'
                    ? policyCreateMode === 'WALLET_OVERRIDE'
                      ? 'Create wallet override'
                      : 'Create policy'
                    : 'Edit policy'}
                </h2>
                <p className="dashboard-pagination-note dashboard-policy-modal-intro">
                  {activeModal.kind === 'create' && policyCreateMode === 'WALLET_OVERRIDE'
                    ? 'Create a wallet-specific draft for one wallet in the current dashboard context, then use Go live to publish it.'
                    : 'Create a draft for the current dashboard context, then use Go live to publish it.'}
                </p>
                {mutationErrorMessage ? (
                  <p className="dashboard-pagination-note">{mutationErrorMessage}</p>
                ) : null}
                <form
                  className="dashboard-view-grid dashboard-view-grid--two"
                  onSubmit={savePolicy}
                >
                  <div className="dashboard-policy-form-row dashboard-form-field dashboard-form-field--full">
                    <label className="dashboard-form-field dashboard-policy-form-row__field">
                      <span>Policy name</span>
                      <input
                        className="dashboard-input"
                        value={policyEditorForm.policyName}
                        onChange={(event) =>
                          setPolicyEditorForm((current) => ({
                            ...current,
                            policyName: event.target.value,
                          }))
                        }
                        placeholder={defaultPolicyName(policyCreateMode)}
                        disabled={!canMutatePolicies || mutationBusy === 'save'}
                      />
                    </label>

                    <label className="dashboard-form-field dashboard-policy-form-row__field">
                      <span>Max amount per transaction (minor units)</span>
                      <input
                        className="dashboard-input"
                        value={policyEditorForm.maxAmountMinor}
                        onChange={(event) =>
                          setPolicyEditorForm((current) => ({
                            ...current,
                            maxAmountMinor: event.target.value,
                          }))
                        }
                        placeholder="100000"
                        disabled={!canMutatePolicies || mutationBusy === 'save'}
                      />
                    </label>
                  </div>
                  {activeModal.kind === 'create' && policyCreateMode === 'WALLET_OVERRIDE'
                    ? renderWalletOverrideFields(
                        policyEditorForm.walletId,
                        onPolicyEditorWalletIdChange,
                      )
                    : null}

                  <section className="dashboard-policy-rule-panel dashboard-policy-rule-panel--first dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Blocked actions</span>
                      <p className="dashboard-pagination-note">
                        Deny high-risk operations entirely.
                      </p>
                    </div>
                    <div className="dashboard-policy-toggle-grid">
                      {policyActionToggleOptions.map((action) => {
                        const checked = policyEditorForm.blockedActions.some(
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
                              setPolicyEditorForm((current) => ({
                                ...current,
                                blockedActions: toggleStringValue(current.blockedActions, action),
                              }))
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
                        const checked = policyEditorForm.allowedChains.some(
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
                              setPolicyEditorForm((current) => ({
                                ...current,
                                allowedChains: toggleStringValue(current.allowedChains, chain),
                              }))
                            }
                            disabled={!canMutatePolicies || mutationBusy === 'save'}
                          >
                            {chain}
                          </button>
                        );
                      })}
                    </div>
                  </section>

                  <section className="dashboard-policy-rule-panel dashboard-policy-rule-panel--contract-calls dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Contract calls</span>
                      <p className="dashboard-pagination-note">
                        Choose whether contract calls stay open, or restrict them to an allowlist of
                        contracts and functions.
                      </p>
                    </div>
                    <div className="dashboard-policy-contract-call-mode">
                      <button
                        type="button"
                        aria-pressed={policyEditorForm.contractCalls.mode === 'ALLOW_ALL'}
                        className={[
                          'dashboard-policy-segment',
                          policyEditorForm.contractCalls.mode === 'ALLOW_ALL'
                            ? 'dashboard-policy-segment--active'
                            : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        onClick={() =>
                          setPolicyEditorForm((current) => ({
                            ...current,
                            contractCalls: {
                              ...current.contractCalls,
                              mode: 'ALLOW_ALL',
                            },
                          }))
                        }
                        disabled={!canMutatePolicies || mutationBusy === 'save'}
                      >
                        Allow All
                      </button>
                      <button
                        type="button"
                        aria-pressed={policyEditorForm.contractCalls.mode === 'ALLOWLIST'}
                        className={[
                          'dashboard-policy-segment',
                          policyEditorForm.contractCalls.mode === 'ALLOWLIST'
                            ? 'dashboard-policy-segment--active'
                            : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        onClick={() =>
                          setPolicyEditorForm((current) => ({
                            ...current,
                            contractCalls: {
                              ...current.contractCalls,
                              mode: 'ALLOWLIST',
                            },
                          }))
                        }
                        disabled={!canMutatePolicies || mutationBusy === 'save'}
                      >
                        Allowlist
                      </button>
                    </div>

                    {policyEditorForm.contractCalls.mode === 'ALLOWLIST' ? (
                      <div className="dashboard-policy-contract-calls">
                        {policyEditorForm.contractCalls.rules.length === 0 ? (
                          <p className="dashboard-pagination-note">
                            Add one or more contracts to define the contract-call allowlist.
                          </p>
                        ) : null}
                        {policyEditorForm.contractCalls.rules.map((rule) => (
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
                                <div
                                  key={`${rule.id}:${index}`}
                                  className="dashboard-uri-list-editor__row"
                                >
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
                          className="dashboard-pagination-button dashboard-policy-contract-add-button"
                          onClick={addContractCallRule}
                          disabled={!canMutatePolicies || mutationBusy === 'save'}
                        >
                          Add contract
                        </button>
                      </div>
                    ) : (
                      <p className="dashboard-pagination-note">
                        Contract calls are allowed on any contract for the selected chains.
                      </p>
                    )}
                  </section>

                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={discardPolicyEditorDraft}
                      disabled={mutationBusy === 'save'}
                    >
                      Discard draft
                    </button>
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

            {activeModal.kind === 'simulate' ? (
              activeModalPolicy ? (
                <>
                  <h2>Simulate policy</h2>
                  <p className="dashboard-pagination-note">
                    Test {activeModalPolicy.name || activeModalPolicy.id} before publishing it.
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
                            onChange={(event) => setSimulationContractAddress(event.target.value)}
                            placeholder="0x..."
                          />
                        </label>
                        <label className="dashboard-form-field">
                          <span>Function selector</span>
                          <input
                            className="dashboard-input"
                            value={simulationFunctionSelector}
                            onChange={(event) => setSimulationFunctionSelector(event.target.value)}
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

            {activeModal.kind === 'delete' ? (
              activeModalPolicy ? (
                <>
                  <h2>Delete policy</h2>
                  <p className="dashboard-pagination-note">
                    Delete <strong>{activeModalPolicy.name || activeModalPolicy.id}</strong> and
                    remove it from the registry. This does not delete wallet activity history.
                  </p>
                  {activeModalPolicy.isSystemDefault ? (
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
                        activeModalPolicy.isSystemDefault
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
                  <h2>Go live review</h2>
                  <p className="dashboard-pagination-note">
                    Review what will change for this policy in the current dashboard context before
                    requesting approvals or publishing it live.
                  </p>
                  <section className="dashboard-policy-view__section dashboard-policy-go-live__section">
                    <div className="dashboard-policy-view__section-header">
                      <div>
                        <h3>Release context</h3>
                        <p className="dashboard-pagination-note">
                          The policy, scope, and current live baseline for this publish.
                        </p>
                      </div>
                    </div>
                    <PolicyReviewTable
                      ariaLabel="Go live review context"
                      rows={activeModalReviewRows}
                    />
                  </section>
                  <div className="dashboard-modal-divider">
                    <div className="dashboard-policy-view__section-header">
                      <div>
                        <h3>Change summary</h3>
                        <p className="dashboard-pagination-note">
                          {activeModalDraftComparisonSummary}
                        </p>
                      </div>
                    </div>
                    {policyVersionsLoading ? (
                      <p className="dashboard-pagination-note">Loading live-rule comparison...</p>
                    ) : policyVersionsErrorMessage ? (
                      <p className="dashboard-pagination-note">
                        Live-rule comparison unavailable: {policyVersionsErrorMessage}
                      </p>
                    ) : latestPublishedVersion ? (
                      changedActiveModalRuleReviewRows.length > 0 ? (
                        <PolicyRuleComparisonTable
                          ariaLabel="Go live rule changes"
                          rows={changedActiveModalRuleReviewRows}
                          nextColumnLabel="Go live"
                          showLiveColumn
                        />
                      ) : (
                        <p className="dashboard-pagination-note">
                          This draft matches the current live rule set. Publishing again will not
                          change the policy rules.
                        </p>
                      )
                    ) : (
                      <PolicyRuleComparisonTable
                        ariaLabel="Initial live rule set"
                        rows={activeModalRuleReviewRows}
                        nextColumnLabel="Go live"
                        showLiveColumn={false}
                      />
                    )}
                  </div>
                  <div className="dashboard-modal-divider">
                    <p className="dashboard-pagination-note">
                      Queue approvals here before the change is allowed to go live.
                    </p>
                  </div>
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
                        !canMutatePolicies ||
                        !selectedPolicyId ||
                        mutationBusy === 'approval-create'
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
                <p className="dashboard-pagination-note">
                  Select a policy before scheduling it live.
                </p>
              )
            ) : null}
        </DashboardInlineModal>
      ) : null}
    </div>
  );
}

export default PolicyEnginePage;
