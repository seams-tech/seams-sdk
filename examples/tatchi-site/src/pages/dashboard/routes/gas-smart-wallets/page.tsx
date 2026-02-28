import React from 'react';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useDashboardSelectedContext } from '../../selectedContext';
import {
  createDashboardGasSponsorship,
  createDashboardSmartWalletConfig,
  listDashboardGasSponsorship,
  listDashboardSmartWallets,
  updateDashboardGasSponsorship,
  updateDashboardSmartWalletConfig,
  type DashboardGasSponsorshipConfig,
  type DashboardSmartWalletConfig,
} from './consoleGasSmartWalletsApi';

const SCOPE_TYPES = ['ORG', 'PROJECT', 'ENVIRONMENT', 'POLICY', 'WALLET_SEGMENT'] as const;
type ScopeType = (typeof SCOPE_TYPES)[number];

const GAS_BUDGET_PERIODS = ['DAILY', 'WEEKLY', 'MONTHLY'] as const;
type GasBudgetPeriod = (typeof GAS_BUDGET_PERIODS)[number];

const GAS_PAYMASTER_MODES = ['DISABLED', 'AUTO', 'FORCED'] as const;
type GasPaymasterMode = (typeof GAS_PAYMASTER_MODES)[number];

const GAS_FALLBACK_BEHAVIORS = ['REJECT', 'ALLOW_UNSPONSORED'] as const;
type GasFallbackBehavior = (typeof GAS_FALLBACK_BEHAVIORS)[number];

const SMART_MODES = ['DISABLED', 'OPTIONAL', 'REQUIRED'] as const;
type SmartMode = (typeof SMART_MODES)[number];

const SMART_ACCOUNT_TYPES = ['EOA', 'SMART_ACCOUNT'] as const;
type SmartAccountType = (typeof SMART_ACCOUNT_TYPES)[number];

const SMART_PAYMASTER_MODES = ['DISABLED', 'AUTO', 'REQUIRED'] as const;
type SmartPaymasterMode = (typeof SMART_PAYMASTER_MODES)[number];

const SMART_FALLBACK_BEHAVIORS = ['FAIL_CLOSED', 'FALLBACK_TO_EOA'] as const;
type SmartFallbackBehavior = (typeof SMART_FALLBACK_BEHAVIORS)[number];

const SMART_ENTRYPOINT_VERSIONS = ['v0.6', 'v0.7'] as const;
type SmartEntrypointVersion = (typeof SMART_ENTRYPOINT_VERSIONS)[number];

function formatTimestamp(value: string): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function formatChainBudgets(config: DashboardGasSponsorshipConfig): string {
  if (!Array.isArray(config.chainBudgets) || config.chainBudgets.length === 0) return '-';
  return config.chainBudgets
    .map((budget) => {
      const chain = String(budget.chain || '').trim() || '?';
      const period = String(budget.period || '').trim() || '?';
      return `${chain} ${period} ${budget.quotaTransactions}tx/$${(budget.budgetMinor / 100).toFixed(2)}`;
    })
    .join(' | ');
}

function normalizeString(value: string): string {
  return String(value || '').trim();
}

function parseNonNegativeInteger(value: string, field: string): number {
  const raw = normalizeString(value);
  if (!/^\d+$/.test(raw)) {
    throw new Error(`${field} must be a non-negative integer.`);
  }
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) {
    throw new Error(`${field} is invalid.`);
  }
  return parsed;
}

function parseNonNegativeNumber(value: string, field: string): number {
  const raw = normalizeString(value);
  if (!raw) {
    throw new Error(`${field} is required.`);
  }
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed < 0) {
    throw new Error(`${field} must be a non-negative number.`);
  }
  return parsed;
}

function resolveDefaultScopeType(projectId: string, environmentId: string): ScopeType {
  if (normalizeString(environmentId)) return 'ENVIRONMENT';
  if (normalizeString(projectId)) return 'PROJECT';
  return 'ORG';
}

function buildScopePayload(input: {
  scopeType: ScopeType;
  projectId: string;
  environmentId: string;
  policyId: string;
  walletSegmentId: string;
}): Record<string, string> {
  const projectId = normalizeString(input.projectId);
  const environmentId = normalizeString(input.environmentId);
  const policyId = normalizeString(input.policyId);
  const walletSegmentId = normalizeString(input.walletSegmentId);
  if (input.scopeType === 'PROJECT' && !projectId) {
    throw new Error('Project scope requires projectId.');
  }
  if (input.scopeType === 'ENVIRONMENT' && !environmentId) {
    throw new Error('Environment scope requires environmentId.');
  }
  if (input.scopeType === 'POLICY' && !policyId) {
    throw new Error('Policy scope requires policyId.');
  }
  if (input.scopeType === 'WALLET_SEGMENT' && !walletSegmentId) {
    throw new Error('Wallet segment scope requires walletSegmentId.');
  }
  return {
    scopeType: input.scopeType,
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
    ...(policyId ? { policyId } : {}),
    ...(walletSegmentId ? { walletSegmentId } : {}),
  };
}

function hasConfigMutationRole(rolesRaw: unknown): boolean {
  if (!Array.isArray(rolesRaw)) return false;
  return rolesRaw.some((role) => {
    const normalized = String(role || '').trim().toLowerCase();
    return normalized === 'owner' || normalized === 'admin' || normalized === 'security_admin';
  });
}

function nextSmartMode(mode: string): SmartMode {
  if (mode === 'DISABLED') return 'OPTIONAL';
  if (mode === 'OPTIONAL') return 'REQUIRED';
  return 'DISABLED';
}

export function GasSponsorshipSmartWalletsPage(): React.JSX.Element {
  const session = useDashboardConsoleSession();
  const selectedContext = useDashboardSelectedContext();
  const selectedProjectId = normalizeString(selectedContext.project || '');
  const selectedEnvironmentId = normalizeString(selectedContext.environment || '');

  const [loading, setLoading] = React.useState<boolean>(true);
  const [errorMessage, setErrorMessage] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [mutating, setMutating] = React.useState<boolean>(false);
  const [gasConfigs, setGasConfigs] = React.useState<DashboardGasSponsorshipConfig[]>([]);
  const [smartWalletConfigs, setSmartWalletConfigs] = React.useState<DashboardSmartWalletConfig[]>([]);

  const [createGasId, setCreateGasId] = React.useState<string>('');
  const [createGasScopeType, setCreateGasScopeType] = React.useState<ScopeType>(
    resolveDefaultScopeType(selectedProjectId, selectedEnvironmentId),
  );
  const [createGasProjectId, setCreateGasProjectId] = React.useState<string>(selectedProjectId);
  const [createGasEnvironmentId, setCreateGasEnvironmentId] = React.useState<string>(
    selectedEnvironmentId,
  );
  const [createGasPolicyId, setCreateGasPolicyId] = React.useState<string>('');
  const [createGasWalletSegmentId, setCreateGasWalletSegmentId] = React.useState<string>('');
  const [createGasEnabled, setCreateGasEnabled] = React.useState<boolean>(true);
  const [createGasPaymasterMode, setCreateGasPaymasterMode] = React.useState<GasPaymasterMode>('AUTO');
  const [createGasFallbackBehavior, setCreateGasFallbackBehavior] =
    React.useState<GasFallbackBehavior>('ALLOW_UNSPONSORED');
  const [createGasBudgetChain, setCreateGasBudgetChain] = React.useState<string>('');
  const [createGasBudgetPeriod, setCreateGasBudgetPeriod] =
    React.useState<GasBudgetPeriod>('MONTHLY');
  const [createGasBudgetMinor, setCreateGasBudgetMinor] = React.useState<string>('0');
  const [createGasQuotaTransactions, setCreateGasQuotaTransactions] = React.useState<string>('0');

  const [createSmartId, setCreateSmartId] = React.useState<string>('');
  const [createSmartScopeType, setCreateSmartScopeType] = React.useState<ScopeType>(
    resolveDefaultScopeType(selectedProjectId, selectedEnvironmentId),
  );
  const [createSmartProjectId, setCreateSmartProjectId] = React.useState<string>(selectedProjectId);
  const [createSmartEnvironmentId, setCreateSmartEnvironmentId] =
    React.useState<string>(selectedEnvironmentId);
  const [createSmartPolicyId, setCreateSmartPolicyId] = React.useState<string>('');
  const [createSmartWalletSegmentId, setCreateSmartWalletSegmentId] = React.useState<string>('');
  const [createSmartEnabled, setCreateSmartEnabled] = React.useState<boolean>(true);
  const [createSmartMode, setCreateSmartMode] = React.useState<SmartMode>('OPTIONAL');
  const [createSmartAccountType, setCreateSmartAccountType] =
    React.useState<SmartAccountType>('SMART_ACCOUNT');
  const [createSmartPaymasterMode, setCreateSmartPaymasterMode] =
    React.useState<SmartPaymasterMode>('AUTO');
  const [createSmartFallbackBehavior, setCreateSmartFallbackBehavior] =
    React.useState<SmartFallbackBehavior>('FALLBACK_TO_EOA');
  const [createSmartBundlerProvider, setCreateSmartBundlerProvider] = React.useState<string>('');
  const [createSmartBundlerEntrypoint, setCreateSmartBundlerEntrypoint] =
    React.useState<SmartEntrypointVersion>('v0.7');
  const [createSmartBundlerMaxFee, setCreateSmartBundlerMaxFee] = React.useState<string>('0');
  const [createSmartBundlerPriorityFee, setCreateSmartBundlerPriorityFee] = React.useState<string>('0');

  React.useEffect(() => {
    if (!createGasProjectId) setCreateGasProjectId(selectedProjectId);
    if (!createGasEnvironmentId) setCreateGasEnvironmentId(selectedEnvironmentId);
    if (!createSmartProjectId) setCreateSmartProjectId(selectedProjectId);
    if (!createSmartEnvironmentId) setCreateSmartEnvironmentId(selectedEnvironmentId);
  }, [
    createGasEnvironmentId,
    createGasProjectId,
    createSmartEnvironmentId,
    createSmartProjectId,
    selectedEnvironmentId,
    selectedProjectId,
  ]);

  const canMutateConfig = React.useMemo(
    () => hasConfigMutationRole(session.claims?.roles),
    [session.claims?.roles],
  );

  const loadConfigData = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      setGasConfigs([]);
      setSmartWalletConfigs([]);
      return;
    }
    const query = {
      ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
      ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
    };
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    Promise.all([listDashboardGasSponsorship(query), listDashboardSmartWallets(query)])
      .then(([gasRows, smartRows]) => {
        if (cancelled) return;
        const sortedGas = [...gasRows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
        const sortedSmart = [...smartRows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
        setGasConfigs(sortedGas);
        setSmartWalletConfigs(sortedSmart);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setGasConfigs([]);
        setSmartWalletConfigs([]);
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
    selectedEnvironmentId,
    selectedProjectId,
    session.claims,
    session.errorMessage,
  ]);

  React.useEffect(() => {
    if (session.loading) {
      setLoading(true);
      return;
    }
    const cleanup = loadConfigData();
    return cleanup;
  }, [loadConfigData, session.loading]);

  const onCreateGasConfig = React.useCallback(
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
      try {
        const scope = buildScopePayload({
          scopeType: createGasScopeType,
          projectId: createGasProjectId,
          environmentId: createGasEnvironmentId,
          policyId: createGasPolicyId,
          walletSegmentId: createGasWalletSegmentId,
        });
        const chain = normalizeString(createGasBudgetChain);
        const chainBudgets = chain
          ? [
              {
                chain,
                period: createGasBudgetPeriod,
                budgetMinor: parseNonNegativeInteger(createGasBudgetMinor, 'Gas budget minor units'),
                quotaTransactions: parseNonNegativeInteger(
                  createGasQuotaTransactions,
                  'Gas quota transactions',
                ),
              },
            ]
          : [];
        await createDashboardGasSponsorship({
          ...(normalizeString(createGasId) ? { id: normalizeString(createGasId) } : {}),
          ...scope,
          enabled: createGasEnabled,
          paymasterMode: createGasPaymasterMode,
          fallbackBehavior: createGasFallbackBehavior,
          ...(chainBudgets.length > 0 ? { chainBudgets } : {}),
        });
        setCreateGasId('');
        setCreateGasPolicyId('');
        setCreateGasWalletSegmentId('');
        setCreateGasBudgetChain('');
        setCreateGasBudgetPeriod('MONTHLY');
        setCreateGasBudgetMinor('0');
        setCreateGasQuotaTransactions('0');
        await loadConfigData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      canMutateConfig,
      createGasBudgetChain,
      createGasBudgetMinor,
      createGasBudgetPeriod,
      createGasEnabled,
      createGasEnvironmentId,
      createGasFallbackBehavior,
      createGasId,
      createGasPaymasterMode,
      createGasPolicyId,
      createGasProjectId,
      createGasQuotaTransactions,
      createGasScopeType,
      createGasWalletSegmentId,
      loadConfigData,
      session.claims,
      session.errorMessage,
    ],
  );

  const onCreateSmartWalletConfig = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateConfig) {
        setMutationError('Only owner/admin/security_admin can mutate smart-wallet settings.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        const scope = buildScopePayload({
          scopeType: createSmartScopeType,
          projectId: createSmartProjectId,
          environmentId: createSmartEnvironmentId,
          policyId: createSmartPolicyId,
          walletSegmentId: createSmartWalletSegmentId,
        });
        const bundlerProvider = normalizeString(createSmartBundlerProvider);
        const bundler = bundlerProvider
          ? {
              provider: bundlerProvider,
              entryPointVersion: createSmartBundlerEntrypoint,
              maxFeePerGasGwei: parseNonNegativeNumber(
                createSmartBundlerMaxFee,
                'Bundler maxFeePerGasGwei',
              ),
              maxPriorityFeePerGasGwei: parseNonNegativeNumber(
                createSmartBundlerPriorityFee,
                'Bundler maxPriorityFeePerGasGwei',
              ),
            }
          : null;
        await createDashboardSmartWalletConfig({
          ...(normalizeString(createSmartId) ? { id: normalizeString(createSmartId) } : {}),
          ...scope,
          enabled: createSmartEnabled,
          mode: createSmartMode,
          accountType: createSmartAccountType,
          paymasterMode: createSmartPaymasterMode,
          fallbackBehavior: createSmartFallbackBehavior,
          ...(bundler ? { bundler } : {}),
        });
        setCreateSmartId('');
        setCreateSmartPolicyId('');
        setCreateSmartWalletSegmentId('');
        setCreateSmartBundlerProvider('');
        setCreateSmartBundlerEntrypoint('v0.7');
        setCreateSmartBundlerMaxFee('0');
        setCreateSmartBundlerPriorityFee('0');
        await loadConfigData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      canMutateConfig,
      createSmartAccountType,
      createSmartBundlerEntrypoint,
      createSmartBundlerMaxFee,
      createSmartBundlerPriorityFee,
      createSmartBundlerProvider,
      createSmartEnabled,
      createSmartEnvironmentId,
      createSmartFallbackBehavior,
      createSmartId,
      createSmartMode,
      createSmartPaymasterMode,
      createSmartPolicyId,
      createSmartProjectId,
      createSmartScopeType,
      createSmartWalletSegmentId,
      loadConfigData,
      session.claims,
      session.errorMessage,
    ],
  );

  const onToggleGasEnabled = React.useCallback(
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
      try {
        await updateDashboardGasSponsorship(config.id, {
          enabled: !config.enabled,
        });
        await loadConfigData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [canMutateConfig, loadConfigData, session.claims, session.errorMessage],
  );

  const onToggleSmartEnabled = React.useCallback(
    async (config: DashboardSmartWalletConfig) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateConfig) {
        setMutationError('Only owner/admin/security_admin can mutate smart-wallet settings.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        await updateDashboardSmartWalletConfig(config.id, {
          enabled: !config.enabled,
        });
        await loadConfigData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [canMutateConfig, loadConfigData, session.claims, session.errorMessage],
  );

  const onCycleSmartMode = React.useCallback(
    async (config: DashboardSmartWalletConfig) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutateConfig) {
        setMutationError('Only owner/admin/security_admin can mutate smart-wallet settings.');
        return;
      }
      setMutating(true);
      setMutationError('');
      try {
        await updateDashboardSmartWalletConfig(config.id, {
          mode: nextSmartMode(config.mode),
        });
        await loadConfigData();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [canMutateConfig, loadConfigData, session.claims, session.errorMessage],
  );

  return (
    <div className="dashboard-view" aria-label="Gas sponsorship and smart wallets page">
      <section className="dashboard-view__section" aria-label="Gas sponsorship and smart-wallet scope">
        <h2>Gas sponsorship and smart-wallet controls</h2>
        <p>
          Backed by `GET/POST/PATCH /console/gas-sponsorship` and `GET/POST/PATCH /console/smart-wallets`.
          Scope project {selectedContext.project || '-'}, environment {selectedContext.environment || '-'}.
        </p>
        <button type="button" className="dashboard-pagination-button" onClick={() => loadConfigData()}>
          Refresh configs
        </button>
        <p className="dashboard-pagination-note">
          {canMutateConfig
            ? 'Owner/admin/security_admin role enabled for config mutations.'
            : 'Only owner/admin/security_admin can create or mutate config rows.'}
        </p>
        {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
      </section>

      {session.loading || loading ? (
        <section className="dashboard-view__section">
          <p>Loading config data...</p>
        </section>
      ) : !session.claims ? (
        <section className="dashboard-view__section">
          <p>Config data unavailable: {session.errorMessage || 'unauthorized'}.</p>
        </section>
      ) : errorMessage ? (
        <section className="dashboard-view__section">
          <p>Config data unavailable: {errorMessage}</p>
        </section>
      ) : (
        <>
          <section className="dashboard-table-wrapper" aria-label="Create gas sponsorship config">
            <div className="dashboard-table-limit">
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateGasConfig}>
                <label className="dashboard-form-field">
                  <span>Config ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createGasId}
                    onChange={(event) => setCreateGasId(event.target.value)}
                    placeholder="gs_prod_main"
                    disabled={!canMutateConfig}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Scope type</span>
                  <select
                    className="dashboard-input"
                    value={createGasScopeType}
                    onChange={(event) => setCreateGasScopeType(event.target.value as ScopeType)}
                  >
                    {SCOPE_TYPES.map((scopeType) => (
                      <option key={scopeType} value={scopeType}>
                        {scopeType}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Project ID</span>
                  <input
                    className="dashboard-input"
                    value={createGasProjectId}
                    onChange={(event) => setCreateGasProjectId(event.target.value)}
                    placeholder="proj_prod"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Environment ID</span>
                  <input
                    className="dashboard-input"
                    value={createGasEnvironmentId}
                    onChange={(event) => setCreateGasEnvironmentId(event.target.value)}
                    placeholder="env_prod"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Policy ID</span>
                  <input
                    className="dashboard-input"
                    value={createGasPolicyId}
                    onChange={(event) => setCreateGasPolicyId(event.target.value)}
                    placeholder="policy_default"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Wallet segment ID</span>
                  <input
                    className="dashboard-input"
                    value={createGasWalletSegmentId}
                    onChange={(event) => setCreateGasWalletSegmentId(event.target.value)}
                    placeholder="segment_vip"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Paymaster mode</span>
                  <select
                    className="dashboard-input"
                    value={createGasPaymasterMode}
                    onChange={(event) => setCreateGasPaymasterMode(event.target.value as GasPaymasterMode)}
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
                    value={createGasFallbackBehavior}
                    onChange={(event) =>
                      setCreateGasFallbackBehavior(event.target.value as GasFallbackBehavior)
                    }
                  >
                    {GAS_FALLBACK_BEHAVIORS.map((behavior) => (
                      <option key={behavior} value={behavior}>
                        {behavior}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Budget chain (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createGasBudgetChain}
                    onChange={(event) => setCreateGasBudgetChain(event.target.value)}
                    placeholder="ethereum"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Budget period</span>
                  <select
                    className="dashboard-input"
                    value={createGasBudgetPeriod}
                    onChange={(event) => setCreateGasBudgetPeriod(event.target.value as GasBudgetPeriod)}
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
                    value={createGasBudgetMinor}
                    onChange={(event) => setCreateGasBudgetMinor(event.target.value)}
                    placeholder="50000"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Quota transactions</span>
                  <input
                    className="dashboard-input"
                    value={createGasQuotaTransactions}
                    onChange={(event) => setCreateGasQuotaTransactions(event.target.value)}
                    placeholder="1000"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Enabled</span>
                  <input
                    className="dashboard-input"
                    type="checkbox"
                    checked={createGasEnabled}
                    onChange={(event) => setCreateGasEnabled(event.target.checked)}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={!canMutateConfig || mutating}
                  >
                    {mutating ? 'Applying...' : 'Create gas sponsorship config'}
                  </button>
                </div>
              </form>
            </div>
          </section>

          <section className="dashboard-table-wrapper" aria-label="Gas sponsorship configs table">
            <div className="dashboard-table-header" role="row">
              <span>Config ID</span>
              <span>Scope</span>
              <span>Project</span>
              <span>Environment</span>
              <span>Enabled</span>
              <span>Paymaster</span>
              <span>Fallback</span>
              <span>Budgets</span>
              <span>Updated</span>
              <span>Actions</span>
            </div>
            {gasConfigs.length === 0 ? (
              <p className="dashboard-table-limit">No gas sponsorship configs found in scope.</p>
            ) : (
              <>
                {gasConfigs.map((config) => (
                  <div className="dashboard-table-row" key={config.id} role="row">
                    <span>{config.id}</span>
                    <span>{config.scopeType}</span>
                    <span>{config.projectId || '-'}</span>
                    <span>{config.environmentId || '-'}</span>
                    <span>{config.enabled ? 'true' : 'false'}</span>
                    <span>{config.paymasterMode}</span>
                    <span>{config.fallbackBehavior}</span>
                    <span title={formatChainBudgets(config)}>{formatChainBudgets(config)}</span>
                    <span>{formatTimestamp(config.updatedAt)}</span>
                    <span>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => onToggleGasEnabled(config)}
                        disabled={!canMutateConfig || mutating}
                      >
                        {config.enabled ? 'Disable' : 'Enable'}
                      </button>
                    </span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {gasConfigs.length} gas sponsorship config{gasConfigs.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>

          <section className="dashboard-table-wrapper" aria-label="Create smart wallet config">
            <div className="dashboard-table-limit">
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onCreateSmartWalletConfig}>
                <label className="dashboard-form-field">
                  <span>Config ID (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createSmartId}
                    onChange={(event) => setCreateSmartId(event.target.value)}
                    placeholder="sw_prod_main"
                    disabled={!canMutateConfig}
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Scope type</span>
                  <select
                    className="dashboard-input"
                    value={createSmartScopeType}
                    onChange={(event) => setCreateSmartScopeType(event.target.value as ScopeType)}
                  >
                    {SCOPE_TYPES.map((scopeType) => (
                      <option key={scopeType} value={scopeType}>
                        {scopeType}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Project ID</span>
                  <input
                    className="dashboard-input"
                    value={createSmartProjectId}
                    onChange={(event) => setCreateSmartProjectId(event.target.value)}
                    placeholder="proj_prod"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Environment ID</span>
                  <input
                    className="dashboard-input"
                    value={createSmartEnvironmentId}
                    onChange={(event) => setCreateSmartEnvironmentId(event.target.value)}
                    placeholder="env_prod"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Policy ID</span>
                  <input
                    className="dashboard-input"
                    value={createSmartPolicyId}
                    onChange={(event) => setCreateSmartPolicyId(event.target.value)}
                    placeholder="policy_default"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Wallet segment ID</span>
                  <input
                    className="dashboard-input"
                    value={createSmartWalletSegmentId}
                    onChange={(event) => setCreateSmartWalletSegmentId(event.target.value)}
                    placeholder="segment_vip"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Mode</span>
                  <select
                    className="dashboard-input"
                    value={createSmartMode}
                    onChange={(event) => setCreateSmartMode(event.target.value as SmartMode)}
                  >
                    {SMART_MODES.map((mode) => (
                      <option key={mode} value={mode}>
                        {mode}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Account type</span>
                  <select
                    className="dashboard-input"
                    value={createSmartAccountType}
                    onChange={(event) => setCreateSmartAccountType(event.target.value as SmartAccountType)}
                  >
                    {SMART_ACCOUNT_TYPES.map((accountType) => (
                      <option key={accountType} value={accountType}>
                        {accountType}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Paymaster mode</span>
                  <select
                    className="dashboard-input"
                    value={createSmartPaymasterMode}
                    onChange={(event) =>
                      setCreateSmartPaymasterMode(event.target.value as SmartPaymasterMode)
                    }
                  >
                    {SMART_PAYMASTER_MODES.map((mode) => (
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
                    value={createSmartFallbackBehavior}
                    onChange={(event) =>
                      setCreateSmartFallbackBehavior(event.target.value as SmartFallbackBehavior)
                    }
                  >
                    {SMART_FALLBACK_BEHAVIORS.map((behavior) => (
                      <option key={behavior} value={behavior}>
                        {behavior}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Bundler provider (optional)</span>
                  <input
                    className="dashboard-input"
                    value={createSmartBundlerProvider}
                    onChange={(event) => setCreateSmartBundlerProvider(event.target.value)}
                    placeholder="alchemy"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Bundler entry point</span>
                  <select
                    className="dashboard-input"
                    value={createSmartBundlerEntrypoint}
                    onChange={(event) =>
                      setCreateSmartBundlerEntrypoint(event.target.value as SmartEntrypointVersion)
                    }
                  >
                    {SMART_ENTRYPOINT_VERSIONS.map((version) => (
                      <option key={version} value={version}>
                        {version}
                      </option>
                    ))}
                  </select>
                </label>
                <label className="dashboard-form-field">
                  <span>Bundler max fee (gwei)</span>
                  <input
                    className="dashboard-input"
                    value={createSmartBundlerMaxFee}
                    onChange={(event) => setCreateSmartBundlerMaxFee(event.target.value)}
                    placeholder="30"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Bundler priority fee (gwei)</span>
                  <input
                    className="dashboard-input"
                    value={createSmartBundlerPriorityFee}
                    onChange={(event) => setCreateSmartBundlerPriorityFee(event.target.value)}
                    placeholder="2"
                  />
                </label>
                <label className="dashboard-form-field">
                  <span>Enabled</span>
                  <input
                    className="dashboard-input"
                    type="checkbox"
                    checked={createSmartEnabled}
                    onChange={(event) => setCreateSmartEnabled(event.target.checked)}
                  />
                </label>
                <div className="dashboard-form-actions">
                  <button
                    type="submit"
                    className="dashboard-pagination-button"
                    disabled={!canMutateConfig || mutating}
                  >
                    {mutating ? 'Applying...' : 'Create smart-wallet config'}
                  </button>
                </div>
              </form>
            </div>
          </section>

          <section className="dashboard-table-wrapper" aria-label="Smart wallet configs table">
            <div className="dashboard-table-header" role="row">
              <span>Config ID</span>
              <span>Scope</span>
              <span>Project</span>
              <span>Environment</span>
              <span>Enabled</span>
              <span>Mode</span>
              <span>Account type</span>
              <span>Paymaster</span>
              <span>Bundler</span>
              <span>Updated</span>
              <span>Actions</span>
            </div>
            {smartWalletConfigs.length === 0 ? (
              <p className="dashboard-table-limit">No smart-wallet configs found in scope.</p>
            ) : (
              <>
                {smartWalletConfigs.map((config) => (
                  <div className="dashboard-table-row" key={config.id} role="row">
                    <span>{config.id}</span>
                    <span>{config.scopeType}</span>
                    <span>{config.projectId || '-'}</span>
                    <span>{config.environmentId || '-'}</span>
                    <span>{config.enabled ? 'true' : 'false'}</span>
                    <span>{config.mode}</span>
                    <span>{config.accountType}</span>
                    <span>{config.paymasterMode}</span>
                    <span>{config.bundler?.provider || '-'}</span>
                    <span>{formatTimestamp(config.updatedAt)}</span>
                    <span>
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => onToggleSmartEnabled(config)}
                        disabled={!canMutateConfig || mutating}
                      >
                        {config.enabled ? 'Disable' : 'Enable'}
                      </button>{' '}
                      <button
                        type="button"
                        className="dashboard-inline-link"
                        onClick={() => onCycleSmartMode(config)}
                        disabled={!canMutateConfig || mutating}
                      >
                        Cycle mode
                      </button>
                    </span>
                  </div>
                ))}
                <p className="dashboard-table-limit">
                  Showing {smartWalletConfigs.length} smart-wallet config
                  {smartWalletConfigs.length === 1 ? '' : 's'}.
                </p>
              </>
            )}
          </section>
        </>
      )}
    </div>
  );
}

export default GasSponsorshipSmartWalletsPage;
