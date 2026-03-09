import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useSessionDraft } from '../../drafts/useSessionDraft';
import type { DashboardDraftIdentity } from '../../drafts/sessionDraftStore';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  createDashboardGasSponsorship,
  listDashboardGasSponsorship,
  updateDashboardGasSponsorship,
  type DashboardGasSponsorshipConfig,
} from './consoleGasSponsorshipApi';

const SCOPE_TYPES = ['ORG', 'PROJECT', 'ENVIRONMENT', 'POLICY', 'WALLET_SEGMENT'] as const;
type ScopeType = (typeof SCOPE_TYPES)[number];

const GAS_BUDGET_PERIODS = ['DAILY', 'WEEKLY', 'MONTHLY'] as const;
type GasBudgetPeriod = (typeof GAS_BUDGET_PERIODS)[number];

const GAS_PAYMASTER_MODES = ['DISABLED', 'AUTO', 'FORCED'] as const;
type GasPaymasterMode = (typeof GAS_PAYMASTER_MODES)[number];

const GAS_FALLBACK_BEHAVIORS = ['REJECT', 'ALLOW_UNSPONSORED'] as const;
type GasFallbackBehavior = (typeof GAS_FALLBACK_BEHAVIORS)[number];

const GAS_NETWORK_CLASSES = ['ANY', 'TESTNET', 'MAINNET'] as const;
type GasNetworkClass = (typeof GAS_NETWORK_CLASSES)[number];

const GAS_EXECUTORS = ['RELAY_EOA'] as const;
type GasExecutor = (typeof GAS_EXECUTORS)[number];
type GasSponsorshipModalKind = 'create' | 'edit' | 'view';
type GasSponsorshipDraftScope = {
  orgId: string;
  projectId: string;
  environmentId: string;
};

type GasSponsorshipFormState = {
  policyName: string;
  scopeType: ScopeType;
  projectId: string;
  environmentId: string;
  policyId: string;
  walletSegmentId: string;
  enabled: boolean;
  networkClass: GasNetworkClass;
  executor: GasExecutor;
  paymasterMode: GasPaymasterMode;
  fallbackBehavior: GasFallbackBehavior;
  budgetChain: string;
  budgetPeriod: GasBudgetPeriod;
  budgetMinor: string;
  quotaTransactions: string;
  callChainId: string;
  callTo: string;
  callSelector: string;
  callMaxGasLimit: string;
  callMaxValueWei: string;
};

function normalizeString(value: string): string {
  return String(value || '').trim();
}

function formatTimestamp(value: string): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function formatCurrencyMinor(value: number): string {
  if (!Number.isFinite(value)) return '$0.00';
  return new Intl.NumberFormat(undefined, {
    style: 'currency',
    currency: 'USD',
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(value / 100);
}

function parseRequiredNonNegativeInteger(value: string, field: string): number {
  const trimmed = normalizeString(value);
  if (!/^\d+$/.test(trimmed)) {
    throw new Error(`${field} must be a non-negative integer.`);
  }
  return Number.parseInt(trimmed, 10);
}

function parseOptionalBigIntString(value: string, field: string): string | undefined {
  const trimmed = normalizeString(value);
  if (!trimmed) return undefined;
  try {
    const parsed = BigInt(trimmed);
    if (parsed < 0n) throw new Error('negative');
    return parsed.toString(10);
  } catch {
    throw new Error(`${field} must be a non-negative integer string.`);
  }
}

function isRecord(raw: unknown): raw is Record<string, unknown> {
  return Boolean(raw) && typeof raw === 'object' && !Array.isArray(raw);
}

function readEnumValue<TEnum extends readonly string[]>(
  raw: unknown,
  allowedValues: TEnum,
  fallback: TEnum[number],
): TEnum[number] {
  const value = String(raw || '')
    .trim()
    .toUpperCase();
  if (allowedValues.some((entry) => entry === value)) {
    return value as TEnum[number];
  }
  return fallback;
}

function parseGasSponsorshipFormDraft(
  raw: unknown,
  fallback: GasSponsorshipFormState,
): GasSponsorshipFormState | null {
  if (!isRecord(raw)) return null;
  return {
    policyName: normalizeString(String(raw.policyName ?? fallback.policyName)),
    scopeType: readEnumValue(raw.scopeType, SCOPE_TYPES, fallback.scopeType),
    projectId: normalizeString(String(raw.projectId ?? fallback.projectId)),
    environmentId: normalizeString(String(raw.environmentId ?? fallback.environmentId)),
    policyId: normalizeString(String(raw.policyId ?? fallback.policyId)),
    walletSegmentId: normalizeString(String(raw.walletSegmentId ?? fallback.walletSegmentId)),
    enabled: raw.enabled === true || raw.enabled === false ? raw.enabled : fallback.enabled,
    networkClass: readEnumValue(raw.networkClass, GAS_NETWORK_CLASSES, fallback.networkClass),
    executor: readEnumValue(raw.executor, GAS_EXECUTORS, fallback.executor),
    paymasterMode: readEnumValue(raw.paymasterMode, GAS_PAYMASTER_MODES, fallback.paymasterMode),
    fallbackBehavior: readEnumValue(
      raw.fallbackBehavior,
      GAS_FALLBACK_BEHAVIORS,
      fallback.fallbackBehavior,
    ),
    budgetChain: normalizeString(String(raw.budgetChain ?? fallback.budgetChain)),
    budgetPeriod: readEnumValue(raw.budgetPeriod, GAS_BUDGET_PERIODS, fallback.budgetPeriod),
    budgetMinor: normalizeString(String(raw.budgetMinor ?? fallback.budgetMinor)),
    quotaTransactions: normalizeString(String(raw.quotaTransactions ?? fallback.quotaTransactions)),
    callChainId: normalizeString(String(raw.callChainId ?? fallback.callChainId)),
    callTo: normalizeString(String(raw.callTo ?? fallback.callTo)),
    callSelector: normalizeString(String(raw.callSelector ?? fallback.callSelector)),
    callMaxGasLimit: normalizeString(String(raw.callMaxGasLimit ?? fallback.callMaxGasLimit)),
    callMaxValueWei: normalizeString(String(raw.callMaxValueWei ?? fallback.callMaxValueWei)),
  };
}

function resolveDefaultScopeType(projectId: string, environmentId: string): ScopeType {
  if (normalizeString(environmentId)) return 'ENVIRONMENT';
  if (normalizeString(projectId)) return 'PROJECT';
  return 'ORG';
}

function createInitialFormState(projectId: string, environmentId: string): GasSponsorshipFormState {
  return {
    policyName: 'Project gas sponsorship',
    scopeType: resolveDefaultScopeType(projectId, environmentId),
    projectId,
    environmentId,
    policyId: '',
    walletSegmentId: '',
    enabled: true,
    networkClass: 'ANY',
    executor: 'RELAY_EOA',
    paymasterMode: 'AUTO',
    fallbackBehavior: 'REJECT',
    budgetChain: '',
    budgetPeriod: 'MONTHLY',
    budgetMinor: '',
    quotaTransactions: '',
    callChainId: '',
    callTo: '',
    callSelector: '',
    callMaxGasLimit: '',
    callMaxValueWei: '',
  };
}

function buildFormStateFromConfig(
  config: DashboardGasSponsorshipConfig,
  projectId: string,
  environmentId: string,
): GasSponsorshipFormState {
  const budget = config.chainBudgets[0] || null;
  const allowedCall = config.allowedCalls[0] || null;
  return {
    policyName: config.policyName,
    scopeType: String(config.scopeType || 'ENVIRONMENT').toUpperCase() as ScopeType,
    projectId: config.projectId || projectId,
    environmentId: config.environmentId || environmentId,
    policyId: config.policyId || '',
    walletSegmentId: config.walletSegmentId || '',
    enabled: config.enabled,
    networkClass: String(config.networkClass || 'ANY').toUpperCase() as GasNetworkClass,
    executor: String(config.executor || 'RELAY_EOA').toUpperCase() as GasExecutor,
    paymasterMode: String(config.paymasterMode || 'AUTO').toUpperCase() as GasPaymasterMode,
    fallbackBehavior: String(
      config.fallbackBehavior || 'REJECT',
    ).toUpperCase() as GasFallbackBehavior,
    budgetChain: budget?.chain || '',
    budgetPeriod: String(budget?.period || 'MONTHLY').toUpperCase() as GasBudgetPeriod,
    budgetMinor: budget ? String(budget.budgetMinor) : '',
    quotaTransactions: budget ? String(budget.quotaTransactions) : '',
    callChainId: allowedCall ? String(allowedCall.chainId) : '',
    callTo: allowedCall?.to || '',
    callSelector: allowedCall?.selector || '',
    callMaxGasLimit: allowedCall?.maxGasLimit || '',
    callMaxValueWei: allowedCall?.maxValueWei || '',
  };
}

function hasConfigMutationRole(rolesRaw: unknown): boolean {
  if (!Array.isArray(rolesRaw)) return false;
  return rolesRaw.some((role) => {
    const normalized = String(role || '')
      .trim()
      .toLowerCase();
    return normalized === 'owner' || normalized === 'admin' || normalized === 'security_admin';
  });
}

function buildScopePayload(form: GasSponsorshipFormState): Record<string, string> {
  const projectId = normalizeString(form.projectId);
  const environmentId = normalizeString(form.environmentId);
  const policyId = normalizeString(form.policyId);
  const walletSegmentId = normalizeString(form.walletSegmentId);
  if (form.scopeType === 'PROJECT' && !projectId) {
    throw new Error('Project scope requires a project ID.');
  }
  if (form.scopeType === 'ENVIRONMENT' && !environmentId) {
    throw new Error('Environment scope requires an environment ID.');
  }
  if (form.scopeType === 'POLICY' && !policyId) {
    throw new Error('Policy scope requires a policy ID.');
  }
  if (form.scopeType === 'WALLET_SEGMENT' && !walletSegmentId) {
    throw new Error('Wallet segment scope requires a wallet segment ID.');
  }
  return {
    scopeType: form.scopeType,
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
    ...(policyId ? { policyId } : {}),
    ...(walletSegmentId ? { walletSegmentId } : {}),
  };
}

function buildChainBudgets(form: GasSponsorshipFormState) {
  const chain = normalizeString(form.budgetChain);
  const budgetMinor = normalizeString(form.budgetMinor);
  const quotaTransactions = normalizeString(form.quotaTransactions);
  if (!chain && !budgetMinor && !quotaTransactions) return [];
  if (!chain || !budgetMinor || !quotaTransactions) {
    throw new Error('Budget rule requires chain, budget, and transaction quota.');
  }
  return [
    {
      chain,
      period: form.budgetPeriod,
      budgetMinor: parseRequiredNonNegativeInteger(budgetMinor, 'Budget'),
      quotaTransactions: parseRequiredNonNegativeInteger(quotaTransactions, 'Transaction quota'),
    },
  ];
}

function buildAllowedCalls(form: GasSponsorshipFormState) {
  const chainId = normalizeString(form.callChainId);
  const to = normalizeString(form.callTo);
  const selector = normalizeString(form.callSelector).toLowerCase();
  const maxGasLimit = parseOptionalBigIntString(form.callMaxGasLimit, 'Max gas limit');
  const maxValueWei = parseOptionalBigIntString(form.callMaxValueWei, 'Max value');
  if (!chainId && !to && !selector && !maxGasLimit && !maxValueWei) return [];
  if (!chainId || !to || !selector || !maxGasLimit || !maxValueWei) {
    throw new Error(
      'Allowed call rule requires chain ID, contract, selector, max gas limit, and max value.',
    );
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(to)) {
    throw new Error('Allowed contract must be a valid EVM address.');
  }
  if (!/^0x[0-9a-fA-F]{8}$/.test(selector)) {
    throw new Error('Function selector must be a 4-byte selector like 0x428dc451.');
  }
  const parsedChainId = parseRequiredNonNegativeInteger(chainId, 'Chain ID');
  if (parsedChainId <= 0) {
    throw new Error('Chain ID must be greater than zero.');
  }
  return [
    {
      chainId: parsedChainId,
      to,
      selector,
      maxGasLimit,
      maxValueWei,
    },
  ];
}

function buildGasSponsorshipRequest(form: GasSponsorshipFormState): Record<string, unknown> {
  return {
    ...buildScopePayload(form),
    policyName: normalizeString(form.policyName) || 'Gas Sponsorship Policy',
    networkClass: form.networkClass,
    executor: form.executor,
    enabled: form.enabled,
    paymasterMode: form.paymasterMode,
    fallbackBehavior: form.fallbackBehavior,
    chainBudgets: buildChainBudgets(form),
    allowedCalls: buildAllowedCalls(form),
  };
}

function describeScopeTarget(
  scopeTypeRaw: string,
  ids: {
    projectId?: string | null;
    environmentId?: string | null;
    policyId?: string | null;
    walletSegmentId?: string | null;
  },
): string {
  const scopeType = String(scopeTypeRaw || 'ENVIRONMENT').toUpperCase();
  if (scopeType === 'ORG') return 'Organization';
  if (scopeType === 'PROJECT') return `Project ${ids.projectId || '-'}`;
  if (scopeType === 'POLICY') return `Policy ${ids.policyId || '-'}`;
  if (scopeType === 'WALLET_SEGMENT') return `Wallet segment ${ids.walletSegmentId || '-'}`;
  return `Environment ${ids.environmentId || '-'}`;
}

function describeScope(config: DashboardGasSponsorshipConfig): string {
  return describeScopeTarget(config.scopeType, {
    projectId: config.projectId,
    environmentId: config.environmentId,
    policyId: config.policyId,
    walletSegmentId: config.walletSegmentId,
  });
}

function describeFormScope(form: GasSponsorshipFormState): string {
  return describeScopeTarget(form.scopeType, {
    projectId: form.projectId,
    environmentId: form.environmentId,
    policyId: form.policyId,
    walletSegmentId: form.walletSegmentId,
  });
}

function formatBudgetSummary(config: DashboardGasSponsorshipConfig): string {
  const budget = config.chainBudgets[0];
  if (!budget) return 'No budget rule';
  return `${budget.chain} ${budget.period.toLowerCase()} budget ${formatCurrencyMinor(
    budget.budgetMinor,
  )} / ${budget.quotaTransactions} tx`;
}

function formatAllowedCallSummary(config: DashboardGasSponsorshipConfig): string {
  const allowedCall = config.allowedCalls[0];
  if (!allowedCall) return 'No allowed-call rule';
  return `${allowedCall.chainId} ${allowedCall.selector} on ${allowedCall.to}`;
}

function formatRuleSummary(config: DashboardGasSponsorshipConfig): string {
  return [
    config.networkClass,
    config.executor,
    config.paymasterMode,
    config.fallbackBehavior,
    config.enabled ? 'enabled' : 'disabled',
  ].join(' / ');
}

function formatAllowedCallCoverageEntry(
  call: DashboardGasSponsorshipConfig['allowedCalls'][number],
): string {
  return `${call.chainId} ${call.selector} on ${call.to} (gas ${call.maxGasLimit}, value ${call.maxValueWei})`;
}

function formatBudgetCoverageEntry(
  budget: DashboardGasSponsorshipConfig['chainBudgets'][number],
): string {
  return `${budget.chain} ${budget.period.toLowerCase()} cap ${formatCurrencyMinor(
    budget.budgetMinor,
  )} / ${budget.quotaTransactions} tx`;
}

export function GasSponsorshipPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const selectedOrgId = normalizeString(
    selectedContext.organization || session.claims?.orgId || '',
  );
  const selectedProjectId = normalizeString(
    selectedContext.project || session.claims?.projectId || '',
  );
  const selectedEnvironmentId = normalizeString(
    selectedContext.environment || session.claims?.environmentId || '',
  );

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [mutationNotice, setMutationNotice] = React.useState<string>('');
  const [mutating, setMutating] = React.useState<boolean>(false);
  const [activeModal, setActiveModal] = React.useState<GasSponsorshipModalKind | null>(null);
  const [editingConfigId, setEditingConfigId] = React.useState<string>('');
  const [selectedConfigId, setSelectedConfigId] = React.useState<string>('');
  const [gasConfigs, setGasConfigs] = React.useState<DashboardGasSponsorshipConfig[]>([]);
  const [modalScope, setModalScope] = React.useState<GasSponsorshipDraftScope | null>(null);
  const [modalInitialForm, setModalInitialForm] = React.useState<GasSponsorshipFormState>(() =>
    createInitialFormState(selectedProjectId, selectedEnvironmentId),
  );

  const policyModalOpen = activeModal === 'create' || activeModal === 'edit';

  const draftIdentity = React.useMemo<DashboardDraftIdentity | null>(() => {
    if (!policyModalOpen || !modalScope) return null;
    return {
      route: '/dashboard/gas-sponsorship',
      builderId: 'gas-sponsorship-policy-modal',
      mode: activeModal === 'edit' ? 'edit' : 'create',
      orgId: modalScope.orgId,
      projectId: modalScope.projectId,
      environmentId: modalScope.environmentId,
      resourceId: activeModal === 'edit' ? editingConfigId : '',
    };
  }, [activeModal, editingConfigId, modalScope, policyModalOpen]);

  const parseDraftForm = React.useCallback(
    (raw: unknown): GasSponsorshipFormState | null =>
      parseGasSponsorshipFormDraft(raw, modalInitialForm),
    [modalInitialForm],
  );

  const { form, setForm, restoreState, clearDraft, resetToInitial } =
    useSessionDraft<GasSponsorshipFormState>({
      identity: draftIdentity,
      initialForm: modalInitialForm,
      isOpen: policyModalOpen,
      parseForm: parseDraftForm,
    });

  const currentScopeKey = `${selectedOrgId}:${selectedProjectId}:${selectedEnvironmentId}`;
  const previousScopeKeyRef = React.useRef<string>(currentScopeKey);
  React.useEffect(() => {
    if (previousScopeKeyRef.current === currentScopeKey) return;
    previousScopeKeyRef.current = currentScopeKey;
    if (!policyModalOpen) return;
    setEditingConfigId('');
    setSelectedConfigId('');
    setActiveModal(null);
    setMutationError('');
  }, [currentScopeKey, policyModalOpen]);

  const canMutateConfig = React.useMemo(
    () => hasConfigMutationRole(session.claims?.roles),
    [session.claims?.roles],
  );

  const selectedConfig = React.useMemo(
    () => gasConfigs.find((config) => config.id === selectedConfigId) || null,
    [gasConfigs, selectedConfigId],
  );

  const loadGasConfigs = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      setGasConfigs([]);
      return;
    }
    const query = {
      ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
      ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
    };
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    listDashboardGasSponsorship(query)
      .then((rows) => {
        if (cancelled) return;
        setGasConfigs([...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)));
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setGasConfigs([]);
        setErrorMessage(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [selectedEnvironmentId, selectedProjectId, session.claims, session.errorMessage]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadGasConfigs();
    return cleanup;
  }, [loadGasConfigs, session.loading]);

  const onResetForm = React.useCallback(() => {
    setEditingConfigId('');
    setSelectedConfigId('');
    setModalScope(null);
    setActiveModal(null);
    setMutationError('');
    setModalInitialForm(createInitialFormState(selectedProjectId, selectedEnvironmentId));
  }, [selectedEnvironmentId, selectedProjectId]);

  const openCreateModal = React.useCallback(() => {
    setEditingConfigId('');
    setSelectedConfigId('');
    setModalScope({
      orgId: selectedOrgId,
      projectId: selectedProjectId,
      environmentId: selectedEnvironmentId,
    });
    setModalInitialForm(createInitialFormState(selectedProjectId, selectedEnvironmentId));
    setActiveModal('create');
    setMutationError('');
    setMutationNotice('');
  }, [selectedEnvironmentId, selectedOrgId, selectedProjectId]);

  const onEditConfig = React.useCallback(
    (config: DashboardGasSponsorshipConfig) => {
      setEditingConfigId(config.id);
      setSelectedConfigId(config.id);
      setModalScope({
        orgId: selectedOrgId,
        projectId: selectedProjectId,
        environmentId: selectedEnvironmentId,
      });
      setModalInitialForm(
        buildFormStateFromConfig(config, selectedProjectId, selectedEnvironmentId),
      );
      setActiveModal('edit');
      setMutationError('');
      setMutationNotice('');
    },
    [selectedEnvironmentId, selectedOrgId, selectedProjectId],
  );

  const onViewConfig = React.useCallback((config: DashboardGasSponsorshipConfig) => {
    setEditingConfigId('');
    setSelectedConfigId(config.id);
    setModalScope(null);
    setActiveModal('view');
    setMutationError('');
  }, []);

  const onSubmit = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateConfig) {
        setMutationError('Only owner/admin/security_admin can mutate gas sponsorship settings.');
        return;
      }
      setMutating(true);
      setMutationError('');
      setMutationNotice('');
      try {
        const request = buildGasSponsorshipRequest(form);
        if (editingConfigId) {
          await updateDashboardGasSponsorship(editingConfigId, request);
          setMutationNotice('Gas sponsorship policy updated.');
        } else {
          await createDashboardGasSponsorship(request);
          setMutationNotice('Gas sponsorship policy created.');
        }
        await loadGasConfigs();
        clearDraft();
        onResetForm();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      canMutateConfig,
      editingConfigId,
      form,
      clearDraft,
      loadGasConfigs,
      onResetForm,
      session.claims,
      session.errorMessage,
    ],
  );

  const formDiffersFromInitial = React.useMemo(
    () => JSON.stringify(form) !== JSON.stringify(modalInitialForm),
    [form, modalInitialForm],
  );

  const onDiscardDraft = React.useCallback(() => {
    if (formDiffersFromInitial && typeof window !== 'undefined') {
      const confirmed = window.confirm('Discard this unsaved draft?');
      if (!confirmed) return;
    }
    resetToInitial();
    onResetForm();
  }, [formDiffersFromInitial, onResetForm, resetToInitial]);

  const onToggleEnabled = React.useCallback(
    async (config: DashboardGasSponsorshipConfig) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateConfig) {
        setMutationError('Only owner/admin/security_admin can mutate gas sponsorship settings.');
        return;
      }
      setMutating(true);
      setMutationError('');
      setMutationNotice('');
      try {
        await updateDashboardGasSponsorship(config.id, {
          enabled: !config.enabled,
        });
        await loadGasConfigs();
        setMutationNotice(
          `${config.policyName || config.id} ${config.enabled ? 'disabled' : 'enabled'}.`,
        );
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [canMutateConfig, loadGasConfigs, session.claims, session.errorMessage],
  );

  return (
    <div className="dashboard-view" aria-label="Gas sponsorship page">
      <section className="dashboard-view__section" aria-label="Gas sponsorship summary">
        <h2>Gas sponsorship</h2>
        <p>Choose which calls this scope will sponsor.</p>
        <p>
          Scope: {selectedOrgId || '-'} / {selectedProjectId || '-'} /{' '}
          {selectedEnvironmentId || '-'}.
        </p>
        <p className="dashboard-pagination-note">
          {canMutateConfig ? 'You can edit rules here.' : 'View only for this scope.'}
        </p>
        {mutationNotice ? <p className="dashboard-pagination-note">{mutationNotice}</p> : null}
        {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
      </section>

      {session.loading || loading ? (
        <section className="dashboard-view__section">
          <p>Loading gas sponsorship configs...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Gas sponsorship data unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : errorMessage ? (
        <section className="dashboard-view__section">
          <p>Gas sponsorship data unavailable: {errorMessage}</p>
        </section>
      ) : (
        <>
          <section className="dashboard-view__section" aria-label="Gas sponsorship setup">
            <h2>Create policy</h2>
            <p>
              Start a gas sponsorship policy for this scope, then define the budget and allowed-call
              rules in the builder.
            </p>
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={openCreateModal}
              disabled={!canMutateConfig || mutating}
            >
              Create policy
            </button>
          </section>

          <section className="dashboard-view__section" aria-label="Gas sponsorship configs">
            <h2>Existing configs</h2>
            {gasConfigs.length === 0 ? (
              <div className="dashboard-table-wrapper">
                <p className="dashboard-table-limit">
                  No gas sponsorship configs found in this scope yet.
                </p>
              </div>
            ) : (
              <div className="dashboard-view-grid dashboard-view-grid--two">
                {gasConfigs.map((config) => (
                  <section className="dashboard-table-wrapper" key={config.id}>
                    <div className="dashboard-table-limit">
                      <h3>{config.policyName || config.id}</h3>
                      <p>{describeScope(config)}</p>
                      <p>{formatRuleSummary(config)}</p>
                      <p>{formatBudgetSummary(config)}</p>
                      <p>{formatAllowedCallSummary(config)}</p>
                      <p>Updated {formatTimestamp(config.updatedAt)}</p>
                      <div className="dashboard-form-actions">
                        <button
                          type="button"
                          className="dashboard-inline-link"
                          onClick={() => onViewConfig(config)}
                          disabled={mutating}
                        >
                          View
                        </button>
                        <button
                          type="button"
                          className="dashboard-inline-link"
                          onClick={() => onEditConfig(config)}
                          disabled={mutating}
                        >
                          Edit
                        </button>
                        <button
                          type="button"
                          className="dashboard-inline-link"
                          onClick={() => onToggleEnabled(config)}
                          disabled={!canMutateConfig || mutating}
                        >
                          {config.enabled ? 'Disable' : 'Enable'}
                        </button>
                      </div>
                    </div>
                  </section>
                ))}
              </div>
            )}
          </section>
        </>
      )}
      {activeModal ? (
        <div className="dashboard-inline-modal-backdrop" role="presentation" onClick={onResetForm}>
          <section
            className="dashboard-modal dashboard-modal--wide"
            role="dialog"
            aria-modal="true"
            aria-label={
              activeModal === 'create'
                ? 'Create gas sponsorship policy modal'
                : activeModal === 'edit'
                  ? 'Edit gas sponsorship policy modal'
                  : 'View gas sponsorship coverage modal'
            }
            onClick={(event) => event.stopPropagation()}
          >
            {activeModal === 'view' ? (
              <>
                <h2>Coverage</h2>
                <p className="dashboard-pagination-note">
                  {selectedConfig?.policyName ||
                    selectedConfig?.id ||
                    'Selected sponsorship policy'}
                </p>
                {selectedConfig ? (
                  <>
                    <div className="dashboard-view-grid dashboard-view-grid--two">
                      <div className="dashboard-table-wrapper">
                        <div className="dashboard-table-limit">
                          <strong>{describeScope(selectedConfig)}</strong>
                          <p>Scope</p>
                        </div>
                      </div>
                      <div className="dashboard-table-wrapper">
                        <div className="dashboard-table-limit">
                          <strong>{selectedConfig.enabled ? 'Enabled' : 'Disabled'}</strong>
                          <p>Status</p>
                        </div>
                      </div>
                      <div className="dashboard-table-wrapper">
                        <div className="dashboard-table-limit">
                          <strong>{selectedConfig.allowedCalls.length}</strong>
                          <p>Allowed-call rules</p>
                        </div>
                      </div>
                      <div className="dashboard-table-wrapper">
                        <div className="dashboard-table-limit">
                          <strong>{selectedConfig.chainBudgets.length}</strong>
                          <p>Budget guardrails</p>
                        </div>
                      </div>
                    </div>
                    <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                      <div className="dashboard-policy-rule-panel__header">
                        <span>Policy behavior</span>
                        <p className="dashboard-pagination-note">
                          {formatRuleSummary(selectedConfig)}
                        </p>
                      </div>
                    </section>
                    <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                      <div className="dashboard-policy-rule-panel__header">
                        <span>Allowed call coverage</span>
                        <p className="dashboard-pagination-note">
                          Which contract functions this policy can sponsor.
                        </p>
                      </div>
                      {selectedConfig.allowedCalls.length > 0 ? (
                        selectedConfig.allowedCalls.map((call) => (
                          <p
                            className="dashboard-pagination-note"
                            key={`${call.chainId}:${call.to}:${call.selector}`}
                          >
                            {formatAllowedCallCoverageEntry(call)}
                          </p>
                        ))
                      ) : (
                        <p className="dashboard-pagination-note">
                          No allowed-call rules configured.
                        </p>
                      )}
                    </section>
                    <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                      <div className="dashboard-policy-rule-panel__header">
                        <span>Budget coverage</span>
                        <p className="dashboard-pagination-note">
                          Spending guardrails attached to this policy.
                        </p>
                      </div>
                      {selectedConfig.chainBudgets.length > 0 ? (
                        selectedConfig.chainBudgets.map((budget) => (
                          <p
                            className="dashboard-pagination-note"
                            key={`${budget.chain}:${budget.period}`}
                          >
                            {formatBudgetCoverageEntry(budget)}
                          </p>
                        ))
                      ) : (
                        <p className="dashboard-pagination-note">
                          No budget guardrails configured.
                        </p>
                      )}
                    </section>
                  </>
                ) : (
                  <p className="dashboard-pagination-note">
                    This sponsorship policy is no longer available.
                  </p>
                )}
                <div className="dashboard-form-actions">
                  <button
                    type="button"
                    className="dashboard-pagination-button"
                    onClick={onResetForm}
                  >
                    Close
                  </button>
                </div>
              </>
            ) : (
              <>
                <h2>{activeModal === 'create' ? 'Create policy' : 'Edit sponsorship policy'}</h2>
                <p className="dashboard-pagination-note">
                  Set scope, sponsor behavior, and the rule that decides which call gets paid for.
                </p>
                {restoreState === 'restored' ? (
                  <p className="dashboard-pagination-note">Restored unsaved draft.</p>
                ) : null}
                {mutationError ? (
                  <p className="dashboard-pagination-note">{mutationError}</p>
                ) : null}
                <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onSubmit}>
                  <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Scope</span>
                      <p className="dashboard-pagination-note">
                        This policy applies to the current dashboard scope.
                      </p>
                    </div>
                    <div className="dashboard-view-grid dashboard-view-grid--two">
                      <label className="dashboard-form-field">
                        <span>Policy name</span>
                        <input
                          className="dashboard-input"
                          value={form.policyName}
                          onChange={(event) =>
                            setForm((current) => ({ ...current, policyName: event.target.value }))
                          }
                          placeholder="Tempo testnet onboarding"
                          disabled={mutating}
                        />
                      </label>
                      <div className="dashboard-form-field">
                        <span>Applies to</span>
                        <p className="dashboard-pagination-note">{describeFormScope(form)}</p>
                      </div>
                    </div>
                  </section>

                  <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Sponsor behavior</span>
                      <p className="dashboard-pagination-note">
                        Control where sponsorship is active and how execution should behave.
                      </p>
                    </div>
                    <div className="dashboard-view-grid dashboard-view-grid--two">
                      <label className="dashboard-form-field">
                        <span>Network</span>
                        <select
                          className="dashboard-input"
                          value={form.networkClass}
                          onChange={(event) =>
                            setForm((current) => ({
                              ...current,
                              networkClass: event.target.value as GasNetworkClass,
                            }))
                          }
                          disabled={mutating}
                        >
                          {GAS_NETWORK_CLASSES.map((networkClass) => (
                            <option key={networkClass} value={networkClass}>
                              {networkClass}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="dashboard-form-field">
                        <span>Executor</span>
                        <select
                          className="dashboard-input"
                          value={form.executor}
                          onChange={(event) =>
                            setForm((current) => ({
                              ...current,
                              executor: event.target.value as GasExecutor,
                            }))
                          }
                          disabled={mutating}
                        >
                          {GAS_EXECUTORS.map((executor) => (
                            <option key={executor} value={executor}>
                              {executor}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="dashboard-form-field">
                        <span>Paymaster mode</span>
                        <select
                          className="dashboard-input"
                          value={form.paymasterMode}
                          onChange={(event) =>
                            setForm((current) => ({
                              ...current,
                              paymasterMode: event.target.value as GasPaymasterMode,
                            }))
                          }
                          disabled={mutating}
                        >
                          {GAS_PAYMASTER_MODES.map((mode) => (
                            <option key={mode} value={mode}>
                              {mode}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="dashboard-form-field">
                        <span>Fallback behavior</span>
                        <select
                          className="dashboard-input"
                          value={form.fallbackBehavior}
                          onChange={(event) =>
                            setForm((current) => ({
                              ...current,
                              fallbackBehavior: event.target.value as GasFallbackBehavior,
                            }))
                          }
                          disabled={mutating}
                        >
                          {GAS_FALLBACK_BEHAVIORS.map((behavior) => (
                            <option key={behavior} value={behavior}>
                              {behavior}
                            </option>
                          ))}
                        </select>
                      </label>
                      <div className="dashboard-form-field">
                        <span>Enabled</span>
                        <div className="dashboard-policy-contract-call-mode">
                          <button
                            type="button"
                            aria-pressed={form.enabled}
                            className={[
                              'dashboard-policy-segment',
                              form.enabled ? 'dashboard-policy-segment--active' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                            onClick={() => setForm((current) => ({ ...current, enabled: true }))}
                            disabled={mutating}
                          >
                            Enabled
                          </button>
                          <button
                            type="button"
                            aria-pressed={!form.enabled}
                            className={[
                              'dashboard-policy-segment',
                              !form.enabled ? 'dashboard-policy-segment--active' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                            onClick={() => setForm((current) => ({ ...current, enabled: false }))}
                            disabled={mutating}
                          >
                            Disabled
                          </button>
                        </div>
                      </div>
                    </div>
                  </section>

                  <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Budget guardrail</span>
                      <p className="dashboard-pagination-note">
                        Optional spend cap for this sponsorship policy.
                      </p>
                    </div>
                    <div className="dashboard-view-grid dashboard-view-grid--two">
                      <label className="dashboard-form-field">
                        <span>Budget chain</span>
                        <input
                          className="dashboard-input"
                          value={form.budgetChain}
                          onChange={(event) =>
                            setForm((current) => ({ ...current, budgetChain: event.target.value }))
                          }
                          placeholder="Ethereum"
                          disabled={mutating}
                        />
                      </label>
                      <label className="dashboard-form-field">
                        <span>Budget period</span>
                        <select
                          className="dashboard-input"
                          value={form.budgetPeriod}
                          onChange={(event) =>
                            setForm((current) => ({
                              ...current,
                              budgetPeriod: event.target.value as GasBudgetPeriod,
                            }))
                          }
                          disabled={mutating}
                        >
                          {GAS_BUDGET_PERIODS.map((period) => (
                            <option key={period} value={period}>
                              {period}
                            </option>
                          ))}
                        </select>
                      </label>
                      <label className="dashboard-form-field">
                        <span>Budget (minor units)</span>
                        <input
                          className="dashboard-input"
                          value={form.budgetMinor}
                          onChange={(event) =>
                            setForm((current) => ({ ...current, budgetMinor: event.target.value }))
                          }
                          placeholder="50000"
                          disabled={mutating}
                        />
                      </label>
                      <label className="dashboard-form-field">
                        <span>Transaction quota</span>
                        <input
                          className="dashboard-input"
                          value={form.quotaTransactions}
                          onChange={(event) =>
                            setForm((current) => ({
                              ...current,
                              quotaTransactions: event.target.value,
                            }))
                          }
                          placeholder="1200"
                          disabled={mutating}
                        />
                      </label>
                    </div>
                  </section>

                  <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Allowed call</span>
                      <p className="dashboard-pagination-note">
                        Limit sponsorship to one contract function and execution envelope.
                      </p>
                    </div>
                    <div className="dashboard-view-grid dashboard-view-grid--two">
                      <label className="dashboard-form-field">
                        <span>Allowed call chain ID</span>
                        <input
                          className="dashboard-input"
                          value={form.callChainId}
                          onChange={(event) =>
                            setForm((current) => ({ ...current, callChainId: event.target.value }))
                          }
                          placeholder="42431"
                          disabled={mutating}
                        />
                      </label>
                      <label className="dashboard-form-field">
                        <span>Allowed contract</span>
                        <input
                          className="dashboard-input"
                          value={form.callTo}
                          onChange={(event) =>
                            setForm((current) => ({ ...current, callTo: event.target.value }))
                          }
                          placeholder="0xbb85080E6953f25197ec68798360667140EbAf4b"
                          disabled={mutating}
                        />
                      </label>
                      <label className="dashboard-form-field">
                        <span>Function selector</span>
                        <input
                          className="dashboard-input"
                          value={form.callSelector}
                          onChange={(event) =>
                            setForm((current) => ({ ...current, callSelector: event.target.value }))
                          }
                          placeholder="0x428dc451"
                          disabled={mutating}
                        />
                      </label>
                      <label className="dashboard-form-field">
                        <span>Max gas limit</span>
                        <input
                          className="dashboard-input"
                          value={form.callMaxGasLimit}
                          onChange={(event) =>
                            setForm((current) => ({
                              ...current,
                              callMaxGasLimit: event.target.value,
                            }))
                          }
                          placeholder="300000"
                          disabled={mutating}
                        />
                      </label>
                      <label className="dashboard-form-field">
                        <span>Max value (wei)</span>
                        <input
                          className="dashboard-input"
                          value={form.callMaxValueWei}
                          onChange={(event) =>
                            setForm((current) => ({
                              ...current,
                              callMaxValueWei: event.target.value,
                            }))
                          }
                          placeholder="0"
                          disabled={mutating}
                        />
                      </label>
                    </div>
                  </section>

                  <div className="dashboard-modal-divider" aria-hidden="true" />

                  <div className="dashboard-form-actions">
                    <button
                      type="button"
                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                      onClick={onDiscardDraft}
                      disabled={mutating}
                    >
                      Discard draft
                    </button>
                    <button
                      type="submit"
                      className="dashboard-pagination-button"
                      disabled={!canMutateConfig || mutating}
                    >
                      {mutating
                        ? 'Saving...'
                        : editingConfigId
                          ? 'Save sponsorship policy'
                          : 'Create sponsorship policy'}
                    </button>
                    <button
                      type="button"
                      className="dashboard-pagination-button"
                      onClick={onResetForm}
                      disabled={mutating}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              </>
            )}
          </section>
        </div>
      ) : null}
    </div>
  );
}

export default GasSponsorshipPage;
