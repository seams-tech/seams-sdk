import React from 'react';
import { toast } from 'sonner';
import { useSiteRouter } from '@/app/router/useSiteRouter';
import {
  GAS_SPONSORSHIP_CHAIN_MATRIX_ROWS,
  GAS_SPONSORSHIP_CHAIN_TARGETS,
  type GasSponsorshipChainMatrixRow,
  type GasSponsorshipChainTarget,
  type GasSponsorshipTargetNetworkClass,
} from '@seams-internal/console-shared/gasSponsorshipChains';
import {
  DashboardTable,
  DashboardTableActionButton,
  DashboardTableActionGroup,
  DashboardTableCell,
  DashboardTableHeader,
  DashboardTableHeaderCell,
  DashboardTableRow,
  DashboardTableState,
  dashboardTableColumns,
  useDashboardTablePagination,
} from '../../components/DashboardTable';
import { DashboardInlineModal } from '../../components/DashboardInlineModal';
import { listDashboardEnvironments, listDashboardProjects } from '../../consoleContextApi';
import { useDashboardConsoleSession } from '../../consoleSession';
import { useSessionDraft } from '../../drafts/useSessionDraft';
import type { DashboardDraftIdentity } from '../../drafts/sessionDraftStore';
import { useDashboardSelectedContext } from '../../selectedContext';
import { getDashboardEnvironmentLabel, getDashboardProjectLabel } from '../../utils/scopeLabels';
import { BillingMetricsGrid, type BillingMetric } from '../billing/billingShared';
import {
  formatUsdMinor,
  getDashboardBillingOverview,
  type DashboardBillingOverview,
} from '../billing/consoleBillingApi';
import {
  createDashboardGasSponsorshipPolicy,
  listDashboardGasSponsorshipPolicies,
  updateDashboardGasSponsorshipPolicy,
  type DashboardGasSponsorshipAllowedCall,
  type DashboardGasSponsorshipAllowedDelegateAction,
  type DashboardGasSponsorshipEvmPolicy,
  type DashboardGasSponsorshipNearPolicy,
  type DashboardGasSponsorshipPolicy,
} from './consoleGasSponsorshipApi';

const SCOPE_TYPES = ['ORG', 'PROJECT', 'ENVIRONMENT', 'POLICY', 'WALLET_SEGMENT'] as const;
type ScopeType = (typeof SCOPE_TYPES)[number];

const GAS_NETWORK_CLASSES = ['ANY', 'TESTNET', 'MAINNET'] as const;
type GasNetworkClass = (typeof GAS_NETWORK_CLASSES)[number];
type GasNetworkToggleClass = Exclude<GasNetworkClass, 'ANY'> & GasSponsorshipTargetNetworkClass;
const GAS_SPEND_CAP_MODES = ['NONE', 'CHAIN_TOTAL', 'WALLET_CHAIN_TOTAL'] as const;
type GasSpendCapMode = (typeof GAS_SPEND_CAP_MODES)[number];
const GAS_SPEND_CAP_PERIODS = ['WEEKLY', 'MONTHLY'] as const;
type GasSpendCapPeriod = (typeof GAS_SPEND_CAP_PERIODS)[number];
const GAS_RULE_KINDS = ['evm_call', 'near_delegate'] as const;
type GasRuleKind = (typeof GAS_RULE_KINDS)[number];
const PRODUCTION_ENVIRONMENT_KEY = 'prod';
type GasSponsorshipModalKind = 'create' | 'edit' | 'view';
type GasSponsorshipDraftScope = {
  orgId: string;
  projectId: string;
  environmentId: string;
};
type GasChainTarget = GasSponsorshipChainTarget;
type GasChainMatrixRow = GasSponsorshipChainMatrixRow;
type GasContractFunctionDraft = {
  id: string;
  functionSignature: string;
  maxGasLimit: string;
  maxValueWei: string;
};
type GasContractRuleDraft = {
  id: string;
  contractAddress: string;
  functions: GasContractFunctionDraft[];
};
type GasNearDelegateActionDraft = {
  id: string;
  receiverId: string;
  methodsText: string;
  maxDepositYocto: string;
  allowTransfers: boolean;
};

const GAS_CHAIN_MATRIX_ROWS: readonly GasChainMatrixRow[] = GAS_SPONSORSHIP_CHAIN_MATRIX_ROWS;
const GAS_CHAIN_TARGETS: readonly GasChainTarget[] = GAS_SPONSORSHIP_CHAIN_TARGETS;
const GAS_CHAIN_TARGETS_BY_ID = new Map(GAS_CHAIN_TARGETS.map((target) => [target.id, target]));
const GAS_CHAIN_TARGETS_BY_CHAIN_ID = new Map(
  GAS_CHAIN_TARGETS.map((target) => [target.chainId, target]),
);
const GAS_CHAIN_TARGET_IDS = new Set(GAS_CHAIN_TARGETS.map((target) => target.id));
const GAS_MAINNET_TARGET_IDS = GAS_CHAIN_TARGETS.filter(
  (target) => target.networkClass === 'MAINNET',
).map((target) => target.id);
const GAS_TESTNET_TARGET_IDS = GAS_CHAIN_TARGETS.filter(
  (target) => target.networkClass === 'TESTNET',
).map((target) => target.id);
const GAS_SPONSORSHIP_TABLE_COLUMNS = dashboardTableColumns(1.15, 1.2, 1, 1, 1.05, 0.85, 1.15);
const SPEND_CAP_DECIMAL_FORMATTERS = new Map<number, Intl.NumberFormat>();

type GasSponsorshipFormState = {
  name: string;
  ruleKind: GasRuleKind;
  scopeType: ScopeType;
  projectId: string;
  environmentId: string;
  scopePolicyId: string;
  walletSegmentId: string;
  enabled: boolean;
  selectedTargets: string[];
  contractCallRules: GasContractRuleDraft[];
  delegateActionRules: GasNearDelegateActionDraft[];
  spendCapMode: GasSpendCapMode;
  spendCapPeriod: GasSpendCapPeriod;
  spendCapAmountByChainName: Record<string, string>;
};

function normalizeString(value: string): string {
  return String(value || '').trim();
}

function makeDraftId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeFunctionSignatureInput(value: string): string | null {
  const normalized = normalizeString(value);
  return /^[A-Za-z_][A-Za-z0-9_]*\([^)]*\)$/.test(normalized) ? normalized : null;
}

function parseRequiredUnsignedIntegerString(value: string, field: string): string {
  const normalized = normalizeString(value);
  if (!/^\d+$/.test(normalized)) {
    throw new Error(`${field} must be a non-negative integer.`);
  }
  return BigInt(normalized).toString(10);
}

function parseRequiredPositiveIntegerString(value: string, field: string): string {
  const normalized = parseRequiredUnsignedIntegerString(value, field);
  if (BigInt(normalized) <= 0n) {
    throw new Error(`${field} must be greater than zero.`);
  }
  return normalized;
}

function createEmptyGasContractFunctionDraft(): GasContractFunctionDraft {
  return {
    id: makeDraftId('gas_function'),
    functionSignature: '',
    maxGasLimit: '',
    maxValueWei: '0',
  };
}

function createEmptyGasContractRuleDraft(): GasContractRuleDraft {
  return {
    id: makeDraftId('gas_contract'),
    contractAddress: '',
    functions: [createEmptyGasContractFunctionDraft()],
  };
}

function createEmptyNearDelegateActionDraft(): GasNearDelegateActionDraft {
  return {
    id: makeDraftId('gas_near_action'),
    receiverId: '',
    methodsText: '',
    maxDepositYocto: '0',
    allowTransfers: false,
  };
}

function formatTimestamp(value: string): string {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString();
}

function normalizeSpendCapDisplayDecimals(value: number): number {
  if (!Number.isInteger(value) || value < 0 || value > 6) return 2;
  return value;
}

function getSpendCapMinorDivisor(displayDecimals: number): number {
  return 10 ** normalizeSpendCapDisplayDecimals(displayDecimals);
}

function getSpendCapDecimalFormatter(displayDecimals: number): Intl.NumberFormat {
  const normalizedDecimals = normalizeSpendCapDisplayDecimals(displayDecimals);
  const existing = SPEND_CAP_DECIMAL_FORMATTERS.get(normalizedDecimals);
  if (existing) return existing;
  const formatter = new Intl.NumberFormat(undefined, {
    minimumFractionDigits: normalizedDecimals,
    maximumFractionDigits: normalizedDecimals,
  });
  SPEND_CAP_DECIMAL_FORMATTERS.set(normalizedDecimals, formatter);
  return formatter;
}

function formatSpendCapInputMinor(valueMinor: number, displayDecimals: number): string {
  if (!Number.isFinite(valueMinor)) return getSpendCapDecimalFormatter(displayDecimals).format(0);
  return (valueMinor / getSpendCapMinorDivisor(displayDecimals)).toFixed(
    normalizeSpendCapDisplayDecimals(displayDecimals),
  );
}

function formatSpendCapAmountMinor(
  valueMinor: number,
  currencyCode: string,
  displayDecimals: number,
): string {
  const normalizedUnit = normalizeString(currencyCode) || 'units';
  const safeValue = Number.isFinite(valueMinor) ? valueMinor : 0;
  return `${getSpendCapDecimalFormatter(displayDecimals).format(
    safeValue / getSpendCapMinorDivisor(displayDecimals),
  )} ${normalizedUnit}`;
}

function parseSpendCapAmountToMinor(value: string, displayDecimals: number): number | null {
  const normalizedDecimals = normalizeSpendCapDisplayDecimals(displayDecimals);
  const trimmed = normalizeString(value).replace(/,/g, '');
  if (!trimmed || trimmed === '.') return null;
  const amountPattern =
    normalizedDecimals === 0
      ? /^\d+$/
      : new RegExp(`^(?:\\d+|\\d*\\.\\d{1,${normalizedDecimals}})$`);
  if (!amountPattern.test(trimmed)) {
    return null;
  }
  const normalized = trimmed.startsWith('.') ? `0${trimmed}` : trimmed;
  const [wholeRaw, fractionRaw = ''] = normalized.split('.');
  const whole = Number.parseInt(wholeRaw || '0', 10);
  const fraction = Number.parseInt(fractionRaw.padEnd(normalizedDecimals, '0') || '0', 10);
  if (!Number.isSafeInteger(whole) || !Number.isSafeInteger(fraction)) return null;
  const result = whole * getSpendCapMinorDivisor(normalizedDecimals) + fraction;
  return Number.isSafeInteger(result) ? result : null;
}

function parseRequiredSpendCapAmountToMinor(
  value: string,
  field: string,
  displayDecimals: number,
): number {
  const normalizedDecimals = normalizeSpendCapDisplayDecimals(displayDecimals);
  const parsed = parseSpendCapAmountToMinor(value, normalizedDecimals);
  if (parsed === null) {
    throw new Error(
      `${field} must be a non-negative amount with up to ${normalizedDecimals} decimal places.`,
    );
  }
  return parsed;
}

function normalizeSpendCapAmountInput(value: string, displayDecimals: number): string {
  const parsed = parseSpendCapAmountToMinor(value, displayDecimals);
  return parsed === null
    ? normalizeString(value)
    : formatSpendCapInputMinor(parsed, displayDecimals);
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

function uniqueGasTargetIds(values: readonly string[]): string[] {
  const out: string[] = [];
  for (const value of values) {
    const normalized = String(value || '').trim();
    if (!normalized || !GAS_CHAIN_TARGET_IDS.has(normalized) || out.includes(normalized)) continue;
    out.push(normalized);
  }
  return out;
}

function readNearDelegateActionDrafts(raw: unknown): GasNearDelegateActionDraft[] {
  if (!Array.isArray(raw)) return [];
  const out: GasNearDelegateActionDraft[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) continue;
    out.push({
      id: normalizeString(String(entry.id || '')) || makeDraftId('gas_near_action'),
      receiverId: normalizeString(String(entry.receiverId || '')),
      methodsText: normalizeString(String(entry.methodsText || '')),
      maxDepositYocto: normalizeString(String(entry.maxDepositYocto || '')) || '0',
      allowTransfers: entry.allowTransfers === true,
    });
  }
  return out;
}

function splitNearMethodsInput(value: string): string[] {
  const parts = normalizeString(value)
    .split(/[\n,]+/)
    .map((entry) => normalizeString(entry))
    .filter(Boolean);
  return Array.from(
    new Map(parts.map((entry) => [entry.toLowerCase(), entry])).values(),
  );
}

function joinNearMethods(methods: readonly string[]): string {
  return methods.join(', ');
}

function readGasContractRuleDrafts(raw: unknown): GasContractRuleDraft[] {
  if (!Array.isArray(raw)) return [];
  const out: GasContractRuleDraft[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) continue;
    const contractAddress = normalizeString(String(entry.contractAddress || ''));
    const functionsRaw = Array.isArray(entry.functions) ? entry.functions : [];
    const functions = functionsRaw
      .map((value) => {
        if (!isRecord(value)) return null;
        return {
          id: normalizeString(String(value.id || '')) || makeDraftId('gas_function'),
          functionSignature: normalizeString(String(value.functionSignature || '')),
          maxGasLimit: normalizeString(String(value.maxGasLimit || '')),
          maxValueWei: normalizeString(String(value.maxValueWei || '')) || '0',
        };
      })
      .filter((value): value is GasContractFunctionDraft => value !== null);
    out.push({
      id: normalizeString(String(entry.id || '')) || makeDraftId('gas_contract'),
      contractAddress,
      functions: functions.length > 0 ? functions : [createEmptyGasContractFunctionDraft()],
    });
  }
  return out;
}

function readSpendCapAmountByChainName(raw: unknown): Record<string, string> {
  if (!isRecord(raw)) return {};
  const out: Record<string, string> = {};
  for (const [chainNameRaw, valueRaw] of Object.entries(raw)) {
    const chainName = normalizeString(chainNameRaw);
    const value = normalizeString(String(valueRaw || ''));
    if (!chainName || !value) continue;
    out[chainName] = value;
  }
  return out;
}

function gasNetworkClassFromEnvironmentKey(environmentKey: string): GasNetworkToggleClass {
  return normalizeString(environmentKey).toLowerCase() === PRODUCTION_ENVIRONMENT_KEY
    ? 'MAINNET'
    : 'TESTNET';
}

function getGasChainTargetForNetwork(
  row: GasChainMatrixRow,
  networkClass: GasNetworkToggleClass,
): GasChainTarget | null {
  return networkClass === 'MAINNET' ? row.mainnet : row.testnet;
}

function getNearSpendCapTargetForNetwork(
  networkClass: GasNetworkToggleClass,
): GasChainTarget | null {
  const nearRow = GAS_CHAIN_MATRIX_ROWS.find((row) => row.chainName === 'NEAR') || null;
  return nearRow ? getGasChainTargetForNetwork(nearRow, networkClass) : null;
}

function remapSelectedTargetsToNetwork(
  selectedTargets: readonly string[],
  networkClass: GasNetworkToggleClass,
): string[] {
  const selectedChainNames = new Set(
    uniqueGasTargetIds(selectedTargets)
      .map((targetId) => GAS_CHAIN_TARGETS_BY_ID.get(targetId)?.chainName || '')
      .filter(Boolean),
  );
  return GAS_CHAIN_MATRIX_ROWS.map((row) =>
    selectedChainNames.has(row.chainName)
      ? getGasChainTargetForNetwork(row, networkClass)?.id || ''
      : '',
  ).filter(Boolean);
}

function groupAllowedCallsByContract(
  allowedCalls: readonly DashboardGasSponsorshipAllowedCall[],
): GasContractRuleDraft[] {
  const byContract = new Map<
    string,
    { contractAddress: string; functions: GasContractFunctionDraft[]; seen: Set<string> }
  >();
  for (const allowedCall of allowedCalls) {
    const contractKey = allowedCall.to.toLowerCase();
    const functionSignature = normalizeString(allowedCall.functionSignature);
    if (!functionSignature) continue;
    let bucket = byContract.get(contractKey);
    if (!bucket) {
      bucket = {
        contractAddress: allowedCall.to,
        functions: [],
        seen: new Set<string>(),
      };
      byContract.set(contractKey, bucket);
    }
    const functionKey = [
      functionSignature.toLowerCase(),
      normalizeString(allowedCall.maxGasLimit),
      normalizeString(allowedCall.maxValueWei),
    ].join(':');
    if (bucket.seen.has(functionKey)) continue;
    bucket.seen.add(functionKey);
    bucket.functions.push({
      id: makeDraftId('gas_function'),
      functionSignature,
      maxGasLimit: normalizeString(allowedCall.maxGasLimit),
      maxValueWei: normalizeString(allowedCall.maxValueWei) || '0',
    });
  }
  return Array.from(byContract.values()).map((entry) => ({
    id: `gas_contract_${entry.contractAddress.toLowerCase()}`,
    contractAddress: entry.contractAddress,
    functions:
      entry.functions.length > 0 ? entry.functions : [createEmptyGasContractFunctionDraft()],
  }));
}

function buildNearDelegateActionDrafts(
  allowedDelegateActions: readonly DashboardGasSponsorshipAllowedDelegateAction[],
): GasNearDelegateActionDraft[] {
  return allowedDelegateActions.map((entry) => ({
    id: makeDraftId('gas_near_action'),
    receiverId: entry.receiverId,
    methodsText: joinNearMethods(entry.methods),
    maxDepositYocto: normalizeString(entry.maxDepositYocto) || '0',
    allowTransfers: entry.allowTransfers === true,
  }));
}

function resolveSelectedTargetsOrThrow(selectedTargetIds: readonly string[]): GasChainTarget[] {
  const targets = uniqueGasTargetIds(selectedTargetIds)
    .map((targetId) => GAS_CHAIN_TARGETS_BY_ID.get(targetId) || null)
    .filter((target): target is GasChainTarget => target !== null);
  if (targets.length === 0) {
    throw new Error('Choose at least one chain target.');
  }
  return targets;
}

function resolveSelectedTargetIdsFromPolicy(policy: DashboardGasSponsorshipEvmPolicy): string[] {
  const targetIdsFromCalls = policy.allowedCalls
    .map((call) => GAS_CHAIN_TARGETS.find((target) => target.chainId === call.chainId)?.id || '')
    .filter(Boolean);
  if (targetIdsFromCalls.length > 0) {
    return uniqueGasTargetIds(targetIdsFromCalls);
  }
  if (policy.networkClass === 'MAINNET') return [...GAS_MAINNET_TARGET_IDS];
  if (policy.networkClass === 'TESTNET') return [...GAS_TESTNET_TARGET_IDS];
  return [];
}

function formatSelectedTargetLabels(targetIds: readonly string[]): string {
  const labels = uniqueGasTargetIds(targetIds)
    .map((targetId) => GAS_CHAIN_TARGETS_BY_ID.get(targetId)?.chainLabel || '')
    .filter(Boolean);
  if (labels.length === 0) return 'No chain targets';
  if (labels.length <= 2) return labels.join(' / ');
  return `${labels.slice(0, 2).join(' / ')} +${labels.length - 2} more`;
}

function parseGasSponsorshipFormDraft(
  raw: unknown,
  fallback: GasSponsorshipFormState,
): GasSponsorshipFormState | null {
  if (!isRecord(raw)) return null;
  const contractCallRules = readGasContractRuleDrafts(raw.contractCallRules);
  const delegateActionRules = readNearDelegateActionDrafts(raw.delegateActionRules);
  return {
    name: normalizeString(String(raw.name ?? fallback.name)),
    ruleKind: readEnumValue(raw.ruleKind, GAS_RULE_KINDS, fallback.ruleKind),
    scopeType: readEnumValue(raw.scopeType, SCOPE_TYPES, fallback.scopeType),
    projectId: normalizeString(String(raw.projectId ?? fallback.projectId)),
    environmentId: normalizeString(String(raw.environmentId ?? fallback.environmentId)),
    scopePolicyId: normalizeString(String(raw.scopePolicyId ?? fallback.scopePolicyId)),
    walletSegmentId: normalizeString(String(raw.walletSegmentId ?? fallback.walletSegmentId)),
    enabled: raw.enabled === true || raw.enabled === false ? raw.enabled : fallback.enabled,
    selectedTargets: Array.isArray(raw.selectedTargets)
      ? uniqueGasTargetIds(raw.selectedTargets.map((value) => String(value || '')))
      : fallback.selectedTargets,
    contractCallRules:
      contractCallRules.length > 0 ? contractCallRules : fallback.contractCallRules,
    delegateActionRules:
      delegateActionRules.length > 0 ? delegateActionRules : fallback.delegateActionRules,
    spendCapMode: readEnumValue(raw.spendCapMode, GAS_SPEND_CAP_MODES, fallback.spendCapMode),
    spendCapPeriod: readEnumValue(
      raw.spendCapPeriod,
      GAS_SPEND_CAP_PERIODS,
      fallback.spendCapPeriod,
    ),
    spendCapAmountByChainName: (() => {
      const parsed = readSpendCapAmountByChainName(raw.spendCapAmountByChainName);
      return Object.keys(parsed).length > 0 ? parsed : fallback.spendCapAmountByChainName;
    })(),
  };
}

function resolveDefaultScopeType(projectId: string, environmentId: string): ScopeType {
  if (normalizeString(environmentId)) return 'ENVIRONMENT';
  if (normalizeString(projectId)) return 'PROJECT';
  return 'ORG';
}

function createInitialFormState(projectId: string, environmentId: string): GasSponsorshipFormState {
  return {
    name: 'Project gas sponsorship',
    ruleKind: 'evm_call',
    scopeType: resolveDefaultScopeType(projectId, environmentId),
    projectId,
    environmentId,
    scopePolicyId: '',
    walletSegmentId: '',
    enabled: true,
    selectedTargets: [],
    contractCallRules: [],
    delegateActionRules: [],
    spendCapMode: 'NONE',
    spendCapPeriod: 'MONTHLY',
    spendCapAmountByChainName: {},
  };
}

function buildFormStateFromPolicy(
  policy: DashboardGasSponsorshipPolicy,
  projectId: string,
  environmentId: string,
): GasSponsorshipFormState {
  const spendCapAmountByChainName = policy.spendCap.capsByChain.reduce<Record<string, string>>(
    (accumulator, entry) => {
      const target = GAS_CHAIN_TARGETS_BY_CHAIN_ID.get(entry.chainId);
      if (!target) return accumulator;
      accumulator[target.chainName] = formatSpendCapInputMinor(
        entry.capMinor,
        target.spendCapDisplayDecimals,
      );
      return accumulator;
    },
    {},
  );
  return {
    name: policy.name,
    ruleKind: policy.kind,
    scopeType: String(policy.scopeType || 'ENVIRONMENT').toUpperCase() as ScopeType,
    projectId: policy.projectId || projectId,
    environmentId: policy.environmentId || environmentId,
    scopePolicyId: policy.scopePolicyId || '',
    walletSegmentId: policy.walletSegmentId || '',
    enabled: policy.enabled,
    selectedTargets: policy.kind === 'evm_call' ? resolveSelectedTargetIdsFromPolicy(policy) : [],
    contractCallRules:
      policy.kind === 'evm_call' ? groupAllowedCallsByContract(policy.allowedCalls) : [],
    delegateActionRules:
      policy.kind === 'near_delegate'
        ? buildNearDelegateActionDrafts(policy.allowedDelegateActions)
        : [],
    spendCapMode: policy.spendCap.mode,
    spendCapPeriod: policy.spendCap.period,
    spendCapAmountByChainName,
  };
}

function hasGasPolicyMutationRole(rolesRaw: unknown): boolean {
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
  const scopePolicyId = normalizeString(form.scopePolicyId);
  const walletSegmentId = normalizeString(form.walletSegmentId);
  if (form.scopeType === 'PROJECT' && !projectId) {
    throw new Error('Project scope requires a project ID.');
  }
  if (form.scopeType === 'ENVIRONMENT' && !environmentId) {
    throw new Error('Environment scope requires an environment ID.');
  }
  if (form.scopeType === 'POLICY' && !scopePolicyId) {
    throw new Error('Policy scope requires a policy ID.');
  }
  if (form.scopeType === 'WALLET_SEGMENT' && !walletSegmentId) {
    throw new Error('Wallet segment scope requires a wallet segment ID.');
  }
  return {
    scopeType: form.scopeType,
    ...(projectId ? { projectId } : {}),
    ...(environmentId ? { environmentId } : {}),
    ...(scopePolicyId ? { scopePolicyId } : {}),
    ...(walletSegmentId ? { walletSegmentId } : {}),
  };
}

function buildSpendCap(form: GasSponsorshipFormState, selectedTargets: readonly GasChainTarget[]) {
  if (form.spendCapMode === 'NONE') {
    return {
      mode: 'NONE' as const,
      period: form.spendCapPeriod,
      capsByChain: [],
    };
  }
  return {
    mode: form.spendCapMode,
    period: form.spendCapPeriod,
    capsByChain: selectedTargets.flatMap((target) => {
      const rawCapAmount = normalizeString(form.spendCapAmountByChainName[target.chainName] || '');
      if (!rawCapAmount) return [];
      return [
        {
          chainId: target.chainId,
          capMinor: parseRequiredSpendCapAmountToMinor(
            rawCapAmount,
            `${target.chainLabel} spend cap`,
            target.spendCapDisplayDecimals,
          ),
        },
      ];
    }),
  };
}

function buildAllowedCalls(
  form: GasSponsorshipFormState,
  selectedTargets: readonly GasChainTarget[],
) {
  if (selectedTargets.length === 0) {
    throw new Error('Choose at least one chain target.');
  }
  if (form.contractCallRules.length === 0) {
    throw new Error('Add at least one allowed contract.');
  }
  const out = new Map<
    string,
    {
      chainId: number;
      to: string;
      functionSignature: string;
      maxGasLimit: string;
      maxValueWei: string;
    }
  >();
  for (const rule of form.contractCallRules) {
    const contractAddress = normalizeString(rule.contractAddress);
    if (!/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
      throw new Error('Allowed contract must be a valid EVM address.');
    }
    const functions = rule.functions.filter(
      (entry) =>
        normalizeString(entry.functionSignature) ||
        normalizeString(entry.maxGasLimit) ||
        normalizeString(entry.maxValueWei),
    );
    if (functions.length === 0) {
      throw new Error('Each allowed contract needs at least one function.');
    }
    for (const functionEntry of functions) {
      const functionSignature = normalizeFunctionSignatureInput(functionEntry.functionSignature);
      if (!functionSignature) {
        throw new Error(
          'Allowed function must be a function signature like transfer(address,uint256).',
        );
      }
      const maxGasLimit = parseRequiredPositiveIntegerString(
        functionEntry.maxGasLimit,
        `${functionSignature} max gas limit`,
      );
      const maxValueWei = parseRequiredUnsignedIntegerString(
        functionEntry.maxValueWei,
        `${functionSignature} max value`,
      );
      for (const target of selectedTargets) {
        out.set(
          `${target.chainId}:${contractAddress.toLowerCase()}:${functionSignature.toLowerCase()}`,
          {
          chainId: target.chainId,
          to: contractAddress,
          functionSignature,
          maxGasLimit,
          maxValueWei,
          },
        );
      }
    }
  }
  return Array.from(out.values());
}

function buildAllowedDelegateActions(
  form: GasSponsorshipFormState,
): DashboardGasSponsorshipAllowedDelegateAction[] {
  const populatedRules = form.delegateActionRules.filter(
    (entry) =>
      normalizeString(entry.receiverId) ||
      normalizeString(entry.methodsText) ||
      normalizeString(entry.maxDepositYocto) ||
      entry.allowTransfers,
  );
  if (populatedRules.length === 0) {
    throw new Error('Add at least one allowed delegate action.');
  }
  const out = new Map<string, DashboardGasSponsorshipAllowedDelegateAction>();
  for (const rule of populatedRules) {
    const receiverId = normalizeString(rule.receiverId);
    if (!receiverId) {
      throw new Error('Delegate action receiver ID is required.');
    }
    const maxDepositYocto = parseRequiredUnsignedIntegerString(
      rule.maxDepositYocto,
      `${receiverId} max deposit`,
    );
    const methods = splitNearMethodsInput(rule.methodsText);
    const dedupeKey = [
      receiverId.toLowerCase(),
      methods.join(',').toLowerCase(),
      rule.allowTransfers ? '1' : '0',
      maxDepositYocto,
    ].join(':');
    out.set(dedupeKey, {
      receiverId,
      methods,
      maxDepositYocto,
      allowTransfers: rule.allowTransfers === true,
    });
  }
  return Array.from(out.values());
}

function buildGasSponsorshipRequest(
  form: GasSponsorshipFormState,
  networkClass: GasNetworkToggleClass,
): Record<string, unknown> {
  if (form.ruleKind === 'near_delegate') {
    const nearTarget = getNearSpendCapTargetForNetwork(networkClass);
    if (form.spendCapMode !== 'NONE' && !nearTarget) {
      throw new Error(`NEAR spend cap target is unavailable for ${networkClass.toLowerCase()}.`);
    }
    return {
      ...buildScopePayload(form),
      name: normalizeString(form.name) || 'Gas Sponsorship Policy',
      kind: 'near_delegate',
      executionMode: 'near_delegate',
      networkClass,
      enabled: form.enabled,
      spendCap:
        form.spendCapMode === 'NONE' || !nearTarget
          ? {
              mode: 'NONE' as const,
              period: form.spendCapPeriod,
              capsByChain: [],
            }
          : buildSpendCap(form, [nearTarget]),
      allowedDelegateActions: buildAllowedDelegateActions(form),
    };
  }
  const selectedTargets = resolveSelectedTargetsOrThrow(
    remapSelectedTargetsToNetwork(form.selectedTargets, networkClass),
  );
  return {
    ...buildScopePayload(form),
    name: normalizeString(form.name) || 'Gas Sponsorship Policy',
    kind: 'evm_call',
    executionMode: 'evm_eoa',
    networkClass,
    enabled: form.enabled,
    spendCap: buildSpendCap(form, selectedTargets),
    allowedCalls: buildAllowedCalls(form, selectedTargets),
  };
}

function describeScopeTarget(
  scopeTypeRaw: string,
  ids: {
    projectId?: string | null;
    environmentId?: string | null;
    scopePolicyId?: string | null;
    scopePolicyName?: string | null;
    walletSegmentId?: string | null;
    projectName?: string | null;
    environmentName?: string | null;
  },
): string {
  const scopeType = String(scopeTypeRaw || 'ENVIRONMENT').toUpperCase();
  if (scopeType === 'ORG') return 'Organization';
  if (scopeType === 'PROJECT') {
    return getDashboardProjectLabel({
      projectId: ids.projectId,
      projectName: ids.projectName,
    });
  }
  if (scopeType === 'POLICY') {
    return `Policy ${ids.scopePolicyName || ids.scopePolicyId || '-'}`;
  }
  if (scopeType === 'WALLET_SEGMENT') return `Wallet segment ${ids.walletSegmentId || '-'}`;
  return getDashboardEnvironmentLabel({
    environmentId: ids.environmentId,
    environmentName: ids.environmentName,
  });
}

function describeScope(
  policy: DashboardGasSponsorshipPolicy,
  labels: {
    projectNamesById: Readonly<Record<string, string>>;
    environmentNamesById: Readonly<Record<string, string>>;
  },
): string {
  return describeScopeTarget(policy.scopeType, {
    projectId: policy.projectId,
    environmentId: policy.environmentId,
    scopePolicyId: policy.scopePolicyId,
    scopePolicyName: policy.scopePolicyName,
    walletSegmentId: policy.walletSegmentId,
    projectName: policy.projectId ? labels.projectNamesById[policy.projectId] || '' : '',
    environmentName: policy.environmentId
      ? labels.environmentNamesById[policy.environmentId] || ''
      : '',
  });
}

function describeCoverageProjectLabel(input: {
  projectName?: string;
  projectId?: string | null;
}): string {
  return (
    normalizeString(String(input.projectName || '')) ||
    normalizeString(String(input.projectId || '')) ||
    '-'
  );
}

function describeCoverageEnvironmentLabel(input: {
  environmentName?: string;
  environmentKey?: string;
  environmentId?: string | null;
}): string {
  const explicitName = normalizeString(String(input.environmentName || ''));
  if (explicitName) return explicitName.toLowerCase();
  const environmentKey = normalizeString(String(input.environmentKey || '')).toLowerCase();
  if (environmentKey === 'dev') return 'development';
  if (environmentKey === 'prod') return 'production';
  if (environmentKey === 'staging') return 'staging';
  return normalizeString(String(input.environmentId || '')) || '-';
}

function describeSpendCapMode(
  mode: GasSpendCapMode | DashboardGasSponsorshipPolicy['spendCap']['mode'],
): string {
  if (mode === 'CHAIN_TOTAL') return 'Per chain total';
  if (mode === 'WALLET_CHAIN_TOTAL') return 'Per wallet, per chain';
  return 'No spend cap';
}

function formatSpendCapCoverageEntry(input: {
  chainId: number;
  capMinor: number;
  mode: DashboardGasSponsorshipPolicy['spendCap']['mode'];
  period: DashboardGasSponsorshipPolicy['spendCap']['period'];
}): string {
  const target = GAS_CHAIN_TARGETS_BY_CHAIN_ID.get(input.chainId);
  const chainLabel = target?.chainLabel || `Chain ${input.chainId}`;
  const scopeLabel = input.mode === 'CHAIN_TOTAL' ? 'total' : 'per wallet';
  return `${chainLabel} ${input.period.toLowerCase()} cap ${formatSpendCapAmountMinor(
    input.capMinor,
    target?.spendCapCurrencyCode || 'units',
    target?.spendCapDisplayDecimals ?? 2,
  )} ${scopeLabel}`;
}

function formatSpendCapSummary(policy: DashboardGasSponsorshipPolicy): string {
  if (policy.spendCap.mode === 'NONE') return 'No spend cap';
  const firstCap = policy.spendCap.capsByChain[0];
  if (!firstCap) {
    return `${describeSpendCapMode(policy.spendCap.mode)} (${policy.spendCap.period.toLowerCase()})`;
  }
  if (policy.spendCap.capsByChain.length > 1) {
    return `${policy.spendCap.capsByChain.length} ${policy.spendCap.period.toLowerCase()} caps · ${describeSpendCapMode(
      policy.spendCap.mode,
    ).toLowerCase()}`;
  }
  return formatSpendCapCoverageEntry({
    chainId: firstCap.chainId,
    capMinor: firstCap.capMinor,
    mode: policy.spendCap.mode,
    period: policy.spendCap.period,
  });
}

function formatAllowedFunctionSummary(input: {
  functionSignature: string;
  maxGasLimit: string;
  maxValueWei: string;
}): string {
  return `${input.functionSignature} · gas <= ${input.maxGasLimit} · value <= ${input.maxValueWei} wei`;
}

function formatAllowedDelegateActionSummary(
  action: DashboardGasSponsorshipAllowedDelegateAction,
): string {
  const methodsLabel = action.methods.length > 0 ? action.methods.join(', ') : 'any method';
  return `${action.receiverId} · ${methodsLabel} · deposit <= ${action.maxDepositYocto} yocto · transfers ${action.allowTransfers ? 'allowed' : 'blocked'}`;
}

function formatAllowedRuleSummary(policy: DashboardGasSponsorshipPolicy): string {
  if (policy.kind === 'near_delegate') {
    const actionCount = policy.allowedDelegateActions.length;
    if (actionCount === 0) return 'No allowed delegate action';
    return `${actionCount} delegate action${actionCount === 1 ? '' : 's'}`;
  }
  const groupedRules = groupAllowedCallsByContract(policy.allowedCalls);
  const contractCount = groupedRules.length;
  const functionCount = groupedRules.reduce((sum, rule) => sum + rule.functions.length, 0);
  if (contractCount === 0 || functionCount === 0) return 'No allowed-call rule';
  return `${contractCount} contract${contractCount === 1 ? '' : 's'} / ${functionCount} function${functionCount === 1 ? '' : 's'}`;
}

function formatNetworkClassLabel(networkClass: DashboardGasSponsorshipPolicy['networkClass']): string {
  if (networkClass === 'MAINNET') return 'Mainnet';
  if (networkClass === 'TESTNET') return 'Testnet';
  return 'Any network';
}

function formatRuleSummary(policy: DashboardGasSponsorshipPolicy): string {
  if (policy.kind === 'near_delegate') {
    return [formatNetworkClassLabel(policy.networkClass), policy.enabled ? 'enabled' : 'disabled'].join(
      ' / ',
    );
  }
  return [
    formatSelectedTargetLabels(resolveSelectedTargetIdsFromPolicy(policy)),
    policy.enabled ? 'enabled' : 'disabled',
  ].join(' / ');
}

export function GasSponsorshipPage(): React.JSX.Element {
  const { go } = useSiteRouter();
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
  const [billingOverview, setBillingOverview] = React.useState<DashboardBillingOverview | null>(
    null,
  );
  const [billingOverviewLoading, setBillingOverviewLoading] = React.useState<boolean>(false);
  const [billingOverviewError, setBillingOverviewError] = React.useState<string>('');
  const [mutationError, setMutationError] = React.useState<string>('');
  const [mutationNotice, setMutationNotice] = React.useState<string>('');
  const [mutating, setMutating] = React.useState<boolean>(false);
  const [activeModal, setActiveModal] = React.useState<GasSponsorshipModalKind | null>(null);
  const [editingPolicyId, setEditingPolicyId] = React.useState<string>('');
  const [selectedPolicyId, setSelectedPolicyId] = React.useState<string>('');
  const [gasPolicies, setGasPolicies] = React.useState<DashboardGasSponsorshipPolicy[]>([]);
  const [modalScope, setModalScope] = React.useState<GasSponsorshipDraftScope | null>(null);
  const [selectedProjectName, setSelectedProjectName] = React.useState<string>('');
  const [selectedEnvironmentKey, setSelectedEnvironmentKey] = React.useState<string>('');
  const [selectedEnvironmentName, setSelectedEnvironmentName] = React.useState<string>('');
  const [projectNamesById, setProjectNamesById] = React.useState<Record<string, string>>({});
  const [environmentNamesById, setEnvironmentNamesById] = React.useState<Record<string, string>>(
    {},
  );
  const [modalInitialForm, setModalInitialForm] = React.useState<GasSponsorshipFormState>(() =>
    createInitialFormState(selectedProjectId, selectedEnvironmentId),
  );

  const policyModalOpen = activeModal === 'create' || activeModal === 'edit';
  const selectedEnvironmentNetworkClass = React.useMemo(
    () => gasNetworkClassFromEnvironmentKey(selectedEnvironmentKey),
    [selectedEnvironmentKey],
  );
  const activeChainColumnLabel =
    selectedEnvironmentNetworkClass === 'MAINNET' ? 'Mainnet' : 'Testnet';
  const activeTargetGroupIds =
    selectedEnvironmentNetworkClass === 'MAINNET' ? GAS_MAINNET_TARGET_IDS : GAS_TESTNET_TARGET_IDS;
  const activeTargetGroupLabel =
    selectedEnvironmentNetworkClass === 'MAINNET' ? 'All mainnets' : 'All testnets';

  const draftIdentity = React.useMemo<DashboardDraftIdentity | null>(() => {
    if (!policyModalOpen || !modalScope) return null;
    return {
      route: '/dashboard/gas-sponsorship',
      builderId: 'gas-sponsorship-policy-modal',
      mode: activeModal === 'edit' ? 'edit' : 'create',
      orgId: modalScope.orgId,
      projectId: modalScope.projectId,
      environmentId: modalScope.environmentId,
      resourceId: activeModal === 'edit' ? editingPolicyId : '',
    };
  }, [activeModal, editingPolicyId, modalScope, policyModalOpen]);

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
  const restoredDraftToastKeyRef = React.useRef<string>('');

  const currentScopeKey = `${selectedOrgId}:${selectedProjectId}:${selectedEnvironmentId}`;
  const previousScopeKeyRef = React.useRef<string>(currentScopeKey);
  React.useEffect(() => {
    if (previousScopeKeyRef.current === currentScopeKey) return;
    previousScopeKeyRef.current = currentScopeKey;
    if (!policyModalOpen) return;
    setEditingPolicyId('');
    setSelectedPolicyId('');
    setActiveModal(null);
    setMutationError('');
  }, [currentScopeKey, policyModalOpen]);

  React.useEffect(() => {
    if (!policyModalOpen || restoreState !== 'restored' || !draftIdentity) return;
    const toastKey = [
      draftIdentity.mode,
      draftIdentity.orgId,
      draftIdentity.projectId,
      draftIdentity.environmentId,
      draftIdentity.resourceId || '',
    ].join(':');
    if (restoredDraftToastKeyRef.current === toastKey) return;
    restoredDraftToastKeyRef.current = toastKey;
    toast('Restored unsaved draft.', {
      id: `gas-sponsorship-draft:${toastKey}`,
      description: null,
    });
  }, [draftIdentity, policyModalOpen, restoreState]);

  React.useEffect(() => {
    if (policyModalOpen) return;
    restoredDraftToastKeyRef.current = '';
  }, [policyModalOpen]);

  React.useEffect(() => {
    if (!policyModalOpen) return;
    setForm((current) => {
      const nextSelectedTargets = remapSelectedTargetsToNetwork(
        current.selectedTargets,
        selectedEnvironmentNetworkClass,
      );
      if (
        nextSelectedTargets.length === current.selectedTargets.length &&
        nextSelectedTargets.every((targetId, index) => current.selectedTargets[index] === targetId)
      ) {
        return current;
      }
      return {
        ...current,
        selectedTargets: nextSelectedTargets,
      };
    });
  }, [policyModalOpen, selectedEnvironmentNetworkClass, setForm]);

  React.useEffect(() => {
    if (!policyModalOpen) return;
    setForm((current) => {
      const selectedChainNames = new Set(
        current.ruleKind === 'near_delegate'
          ? [getNearSpendCapTargetForNetwork(selectedEnvironmentNetworkClass)?.chainName || ''].filter(
              Boolean,
            )
          : uniqueGasTargetIds(current.selectedTargets)
              .map((targetId) => GAS_CHAIN_TARGETS_BY_ID.get(targetId)?.chainName || '')
              .filter(Boolean),
      );
      const nextSpendCapAmountByChainName = Object.fromEntries(
        Object.entries(current.spendCapAmountByChainName).filter(([chainName]) =>
          selectedChainNames.has(chainName),
        ),
      );
      if (
        Object.keys(nextSpendCapAmountByChainName).length ===
          Object.keys(current.spendCapAmountByChainName).length &&
        Object.entries(nextSpendCapAmountByChainName).every(
          ([chainName, value]) => current.spendCapAmountByChainName[chainName] === value,
        )
      ) {
        return current;
      }
      return {
        ...current,
        spendCapAmountByChainName: nextSpendCapAmountByChainName,
      };
    });
  }, [policyModalOpen, selectedEnvironmentNetworkClass, setForm]);

  const canMutatePolicy = React.useMemo(
    () => hasGasPolicyMutationRole(session.claims?.roles),
    [session.claims?.roles],
  );

  const selectedPolicy = React.useMemo(
    () => gasPolicies.find((policy) => policy.id === selectedPolicyId) || null,
    [gasPolicies, selectedPolicyId],
  );
  const gasPoliciesPagination = useDashboardTablePagination(gasPolicies, {
    disabled: session.loading || loading,
    itemLabel: 'policy',
    itemLabelPlural: 'policies',
  });

  React.useEffect(() => {
    if (!session.claims) {
      setSelectedProjectName('');
      setSelectedEnvironmentKey('');
      setSelectedEnvironmentName('');
      setProjectNamesById({});
      setEnvironmentNamesById({});
      return;
    }
    let cancelled = false;
    Promise.all([
      listDashboardProjects({ status: 'ACTIVE' }),
      selectedProjectId
        ? listDashboardEnvironments({ projectId: selectedProjectId })
        : Promise.resolve([]),
    ])
      .then(([projects, environments]) => {
        if (cancelled) return;
        const selectedProject = projects.find((entry) => entry.id === selectedProjectId) || null;
        const selectedEnvironment =
          environments.find((entry) => entry.id === selectedEnvironmentId) || null;
        setProjectNamesById(
          Object.fromEntries(projects.map((entry) => [entry.id, String(entry.name || '')])),
        );
        setEnvironmentNamesById(
          Object.fromEntries(environments.map((entry) => [entry.id, String(entry.name || '')])),
        );
        setSelectedProjectName(String(selectedProject?.name || ''));
        setSelectedEnvironmentKey(String(selectedEnvironment?.key || ''));
        setSelectedEnvironmentName(String(selectedEnvironment?.name || ''));
      })
      .catch(() => {
        if (cancelled) return;
        setSelectedProjectName('');
        setSelectedEnvironmentKey('');
        setSelectedEnvironmentName('');
        setProjectNamesById({});
        setEnvironmentNamesById({});
      });
    return () => {
      cancelled = true;
    };
  }, [selectedEnvironmentId, selectedProjectId, session.claims]);

  const loadBillingOverview = React.useCallback(() => {
    if (!session.claims) {
      setBillingOverview(null);
      setBillingOverviewError(session.errorMessage || 'Console session is unavailable');
      setBillingOverviewLoading(false);
      return;
    }
    let cancelled = false;
    setBillingOverviewLoading(true);
    setBillingOverviewError('');
    getDashboardBillingOverview()
      .then((overview) => {
        if (cancelled) return;
        setBillingOverview(overview);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setBillingOverview(null);
        setBillingOverviewError(error instanceof Error ? error.message : String(error));
      })
      .finally(() => {
        if (cancelled) return;
        setBillingOverviewLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [session.claims, session.errorMessage]);

  const loadGasPolicies = React.useCallback(() => {
    if (!session.claims) {
      setLoading(false);
      setErrorMessage(session.errorMessage || 'Console session is unavailable');
      setGasPolicies([]);
      return;
    }
    const query = {
      ...(selectedProjectId ? { projectId: selectedProjectId } : {}),
      ...(selectedEnvironmentId ? { environmentId: selectedEnvironmentId } : {}),
    };
    let cancelled = false;
    setLoading(true);
    setErrorMessage('');
    listDashboardGasSponsorshipPolicies(query)
      .then((rows) => {
        if (cancelled) return;
        setGasPolicies([...rows].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt)));
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setGasPolicies([]);
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
    const cleanup = loadGasPolicies();
    return cleanup;
  }, [loadGasPolicies, session.loading]);

  React.useEffect(() => {
    if (session.loading) {
      setBillingOverviewLoading(true);
      return;
    }
    const cleanup = loadBillingOverview();
    return cleanup;
  }, [loadBillingOverview, session.loading]);

  const onResetForm = React.useCallback(() => {
    setEditingPolicyId('');
    setSelectedPolicyId('');
    setModalScope(null);
    setActiveModal(null);
    setMutationError('');
    setModalInitialForm(createInitialFormState(selectedProjectId, selectedEnvironmentId));
  }, [selectedEnvironmentId, selectedProjectId]);

  const openCreateModal = React.useCallback(() => {
    setEditingPolicyId('');
    setSelectedPolicyId('');
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

  const onEditPolicy = React.useCallback(
    (policy: DashboardGasSponsorshipPolicy) => {
      setEditingPolicyId(policy.id);
      setSelectedPolicyId(policy.id);
      setModalScope({
        orgId: selectedOrgId,
        projectId: selectedProjectId,
        environmentId: selectedEnvironmentId,
      });
      setModalInitialForm(
        buildFormStateFromPolicy(policy, selectedProjectId, selectedEnvironmentId),
      );
      setActiveModal('edit');
      setMutationError('');
      setMutationNotice('');
    },
    [selectedEnvironmentId, selectedOrgId, selectedProjectId],
  );

  const onViewPolicy = React.useCallback((policy: DashboardGasSponsorshipPolicy) => {
    setEditingPolicyId('');
    setSelectedPolicyId(policy.id);
    setModalScope(null);
    setActiveModal('view');
    setMutationError('');
  }, []);

  const onSetTargetEnabled = React.useCallback(
    (targetId: string, enabled: boolean) => {
      setForm((current) => {
        const target = GAS_CHAIN_TARGETS_BY_ID.get(targetId);
        if (!target) return current;
        const hasTarget = current.selectedTargets.includes(targetId);
        if (enabled && hasTarget) return current;
        if (!enabled && !hasTarget) return current;
        const nextSpendCapAmountByChainName = { ...current.spendCapAmountByChainName };
        if (!enabled) {
          delete nextSpendCapAmountByChainName[target.chainName];
        }
        return {
          ...current,
          selectedTargets: enabled
            ? uniqueGasTargetIds([...current.selectedTargets, targetId])
            : current.selectedTargets.filter((entry) => entry !== targetId),
          spendCapAmountByChainName: nextSpendCapAmountByChainName,
        };
      });
    },
    [setForm],
  );

  const onToggleTargetGroup = React.useCallback(
    (networkClass: GasNetworkToggleClass) => {
      const groupTargetIds =
        networkClass === 'MAINNET' ? GAS_MAINNET_TARGET_IDS : GAS_TESTNET_TARGET_IDS;
      setForm((current) => {
        const hasEntireGroup = groupTargetIds.every((targetId) =>
          current.selectedTargets.includes(targetId),
        );
        const nextSpendCapAmountByChainName = { ...current.spendCapAmountByChainName };
        if (hasEntireGroup) {
          groupTargetIds.forEach((targetId) => {
            const target = GAS_CHAIN_TARGETS_BY_ID.get(targetId);
            if (!target) return;
            delete nextSpendCapAmountByChainName[target.chainName];
          });
        }
        const nextSelectedTargets = hasEntireGroup
          ? current.selectedTargets.filter((targetId) => !groupTargetIds.includes(targetId))
          : uniqueGasTargetIds([...current.selectedTargets, ...groupTargetIds]);
        return {
          ...current,
          selectedTargets: nextSelectedTargets,
          spendCapAmountByChainName: nextSpendCapAmountByChainName,
        };
      });
    },
    [setForm],
  );

  const addContractCallRule = React.useCallback(() => {
    setForm((current) => ({
      ...current,
      contractCallRules: [...current.contractCallRules, createEmptyGasContractRuleDraft()],
    }));
  }, [setForm]);

  const removeContractCallRule = React.useCallback(
    (ruleId: string) => {
      setForm((current) => ({
        ...current,
        contractCallRules: current.contractCallRules.filter((entry) => entry.id !== ruleId),
      }));
    },
    [setForm],
  );

  const updateContractCallRuleAddress = React.useCallback(
    (ruleId: string, contractAddress: string) => {
      setForm((current) => ({
        ...current,
        contractCallRules: current.contractCallRules.map((entry) =>
          entry.id === ruleId ? { ...entry, contractAddress } : entry,
        ),
      }));
    },
    [setForm],
  );

  const addContractFunction = React.useCallback(
    (ruleId: string) => {
      setForm((current) => ({
        ...current,
        contractCallRules: current.contractCallRules.map((entry) =>
          entry.id === ruleId
            ? {
                ...entry,
                functions: [...entry.functions, createEmptyGasContractFunctionDraft()],
              }
            : entry,
        ),
      }));
    },
    [setForm],
  );

  const removeContractFunction = React.useCallback(
    (ruleId: string, functionId: string) => {
      setForm((current) => ({
        ...current,
        contractCallRules: current.contractCallRules.map((entry) => {
          if (entry.id !== ruleId) return entry;
          const nextFunctions = entry.functions.filter(
            (functionEntry) => functionEntry.id !== functionId,
          );
          return {
            ...entry,
            functions:
              nextFunctions.length > 0 ? nextFunctions : [createEmptyGasContractFunctionDraft()],
          };
        }),
      }));
    },
    [setForm],
  );

  const updateContractFunction = React.useCallback(
    (
      ruleId: string,
      functionId: string,
      patch: Partial<Omit<GasContractFunctionDraft, 'id'>>,
    ) => {
      setForm((current) => ({
        ...current,
        contractCallRules: current.contractCallRules.map((entry) =>
          entry.id === ruleId
            ? {
                ...entry,
                functions: entry.functions.map((functionEntry) =>
                  functionEntry.id === functionId
                    ? {
                        ...functionEntry,
                        ...patch,
                      }
                    : functionEntry,
                ),
              }
            : entry,
        ),
      }));
    },
    [setForm],
  );

  const addDelegateActionRule = React.useCallback(() => {
    setForm((current) => ({
      ...current,
      delegateActionRules: [...current.delegateActionRules, createEmptyNearDelegateActionDraft()],
    }));
  }, [setForm]);

  const removeDelegateActionRule = React.useCallback(
    (ruleId: string) => {
      setForm((current) => ({
        ...current,
        delegateActionRules: current.delegateActionRules.filter((entry) => entry.id !== ruleId),
      }));
    },
    [setForm],
  );

  const updateDelegateActionRule = React.useCallback(
    (
      ruleId: string,
      patch: Partial<Omit<GasNearDelegateActionDraft, 'id'>>,
    ) => {
      setForm((current) => ({
        ...current,
        delegateActionRules: current.delegateActionRules.map((entry) =>
          entry.id === ruleId
            ? {
                ...entry,
                ...patch,
              }
            : entry,
        ),
      }));
    },
    [setForm],
  );

  const selectedTargetIds = React.useMemo(
    () => uniqueGasTargetIds(form.selectedTargets),
    [form.selectedTargets],
  );
  const allActiveTargetsSelected = React.useMemo(
    () =>
      activeTargetGroupIds.length > 0 &&
      activeTargetGroupIds.every((targetId) => selectedTargetIds.includes(targetId)),
    [activeTargetGroupIds, selectedTargetIds],
  );

  const onSubmit = React.useCallback(
    async (event: React.FormEvent<HTMLFormElement>) => {
      event.preventDefault();
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutatePolicy) {
        setMutationError('Only owner/admin/security_admin can mutate gas sponsorship settings.');
        return;
      }
      setMutating(true);
      setMutationError('');
      setMutationNotice('');
      try {
        const request = buildGasSponsorshipRequest(form, selectedEnvironmentNetworkClass);
        if (editingPolicyId) {
          await updateDashboardGasSponsorshipPolicy(editingPolicyId, request);
          setMutationNotice('Gas sponsorship policy updated.');
        } else {
          await createDashboardGasSponsorshipPolicy(request);
          setMutationNotice('Gas sponsorship policy created.');
        }
        await loadGasPolicies();
        clearDraft();
        onResetForm();
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [
      canMutatePolicy,
      editingPolicyId,
      form,
      clearDraft,
      loadGasPolicies,
      onResetForm,
      selectedEnvironmentNetworkClass,
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
    async (policy: DashboardGasSponsorshipPolicy) => {
      if (!session.claims) {
        setMutationError(session.errorMessage || 'Console session is unavailable');
        return;
      }
      if (!canMutatePolicy) {
        setMutationError('Only owner/admin/security_admin can mutate gas sponsorship settings.');
        return;
      }
      setMutating(true);
      setMutationError('');
      setMutationNotice('');
      try {
        await updateDashboardGasSponsorshipPolicy(policy.id, {
          enabled: !policy.enabled,
        });
        await loadGasPolicies();
        setMutationNotice(
          `${policy.name || policy.id} ${policy.enabled ? 'disabled' : 'enabled'}.`,
        );
      } catch (error: unknown) {
        setMutationError(error instanceof Error ? error.message : String(error));
      } finally {
        setMutating(false);
      }
    },
    [canMutatePolicy, loadGasPolicies, session.claims, session.errorMessage],
  );

  const gasBalanceMetrics = React.useMemo<BillingMetric[]>(() => {
    if (!billingOverview) return [];
    return [
      {
        label: 'Org prepaid balance',
        value: formatUsdMinor(billingOverview.creditBalanceMinor),
        hint:
          billingOverview.liveEnvironmentState === 'BLOCKED'
            ? 'Sponsorship is blocked until balance is positive again'
            : billingOverview.liveEnvironmentState === 'LOW_BALANCE'
              ? `Warning threshold ${formatUsdMinor(billingOverview.lowBalanceThresholdMinor)}`
              : 'Positive balance available for sponsorship admission',
      },
      {
        label: 'Reserved sponsorship',
        value: formatUsdMinor(billingOverview.reservedSponsorshipMinor),
        hint: `${billingOverview.activeSponsorshipReservationCount} active reservation${
          billingOverview.activeSponsorshipReservationCount === 1 ? '' : 's'
        }`,
      },
      {
        label: '30-day sponsored spend',
        value: formatUsdMinor(billingOverview.trailing30DaySponsoredSpendMinor),
        hint: `${billingOverview.trailing30DaySponsoredExecutionCount} recent sponsored execution${
          billingOverview.trailing30DaySponsoredExecutionCount === 1 ? '' : 's'
        }`,
      },
      {
        label: '90-day sponsored spend',
        value: formatUsdMinor(billingOverview.trailing90DaySponsoredSpendMinor),
        hint: `${billingOverview.trailing90DaySponsoredExecutionCount} execution${
          billingOverview.trailing90DaySponsoredExecutionCount === 1 ? '' : 's'
        } over the full lookback`,
      },
    ];
  }, [billingOverview]);

  const gasBalanceNotice = React.useMemo(() => {
    if (!billingOverview) return null;
    if (billingOverview.liveEnvironmentState === 'BLOCKED') {
      return {
        tone: 'warning' as const,
        message:
          'Sponsored execution is currently blocked because org prepaid balance is depleted. Policy caps can still have room, but no new sponsored requests will be admitted until the balance is refilled.',
      };
    }
    if (billingOverview.liveEnvironmentState === 'LOW_BALANCE') {
      return {
        tone: 'info' as const,
        message: `Sponsored execution is still active, but prepaid balance is at or below the warning threshold (${formatUsdMinor(
          billingOverview.lowBalanceThresholdMinor,
        )}). Refill before live traffic pushes the org into blocked state.`,
      };
    }
    return {
      tone: 'info' as const,
      message:
        'Policy caps and org prepaid balance are enforced independently. Even enabled policies stop admitting sponsorship immediately once the org balance is exhausted.',
    };
  }, [billingOverview]);

  return (
    <div className="dashboard-view" aria-label="Gas sponsorship page">
      {mutationNotice || mutationError ? (
        <section className="dashboard-view__section" aria-label="Gas sponsorship summary">
          {mutationNotice ? <p className="dashboard-pagination-note">{mutationNotice}</p> : null}
          {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
        </section>
      ) : null}

      {session.loading || loading ? (
        <section className="dashboard-view__section">
          <p>Loading gas sponsorship policies...</p>
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
          <section className="dashboard-view__section" aria-label="Gas sponsorship balance readiness">
            <h2>Sponsorship balance readiness</h2>
            <p>
              Policy configuration and prepaid balance are separate controls. Even with enabled
              policies, sponsorship stops immediately when the organization balance is exhausted.
            </p>
            {billingOverviewLoading ? (
              <p>Loading sponsorship balance state...</p>
            ) : billingOverviewError ? (
              <p className="dashboard-pagination-note">
                Sponsorship balance state unavailable: {billingOverviewError}
              </p>
            ) : billingOverview ? (
              <>
                {gasBalanceNotice ? (
                  gasBalanceNotice.tone === 'warning' ? (
                    <div className="dashboard-warning-banner" role="alert">
                      <p>{gasBalanceNotice.message}</p>
                      <button
                        type="button"
                        className="dashboard-warning-banner__dismiss"
                        onClick={() => go('/dashboard/billing/account')}
                      >
                        Top up balance
                      </button>
                    </div>
                  ) : (
                    <div className="dashboard-gas-sponsorship-info-banner">
                      <p>{gasBalanceNotice.message}</p>
                      <button
                        type="button"
                        className="dashboard-pagination-button"
                        onClick={() => go('/dashboard/billing/account')}
                      >
                        Open billing
                      </button>
                    </div>
                  )
                ) : null}
                <BillingMetricsGrid
                  metrics={gasBalanceMetrics}
                  ariaLabel="Gas sponsorship balance readiness metrics"
                />
              </>
            ) : null}
          </section>

          <section className="dashboard-view__section" aria-label="Gas sponsorship setup">
            <h2>Create policy</h2>
            <p>
              Create a gas sponsorship policy: define EVM call templates or NEAR delegate-action
              templates for the selected environment.
            </p>
            <button
              type="button"
              className="dashboard-pagination-button"
              onClick={openCreateModal}
              disabled={!canMutatePolicy || mutating}
            >
              Create policy
            </button>
          </section>

          <section
            className="dashboard-view__section dashboard-view__section--plain"
            aria-label="Gas sponsorship policies"
          >
            <h2>Gas Sponsorship Policies</h2>
            <DashboardTable
              ariaLabel="Gas sponsorship rows"
              className="dashboard-gas-sponsorship-table"
              columns={GAS_SPONSORSHIP_TABLE_COLUMNS}
              pagination={gasPoliciesPagination.pagination}
            >
              <DashboardTableHeader className="dashboard-gas-sponsorship-table__header">
                <DashboardTableHeaderCell>Policy</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Environment</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Behavior</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Spend cap</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Rules</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Updated</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
              </DashboardTableHeader>
              {gasPolicies.length === 0 ? (
                <DashboardTableState>
                  No gas sponsorship policies found for this environment yet.
                </DashboardTableState>
              ) : (
                gasPoliciesPagination.rows.map((policy) => (
                  <DashboardTableRow
                    className="dashboard-gas-sponsorship-table__row"
                    key={policy.id}
                  >
                    <DashboardTableCell title={policy.id}>
                      <strong className="dashboard-data-table__summary">
                        {policy.name || policy.id}
                      </strong>
                    </DashboardTableCell>
                    <DashboardTableCell
                      title={describeScope(policy, {
                        projectNamesById,
                        environmentNamesById,
                      })}
                    >
                      {describeScope(policy, {
                        projectNamesById,
                        environmentNamesById,
                      })}
                    </DashboardTableCell>
                    <DashboardTableCell title={formatRuleSummary(policy)}>
                      {formatRuleSummary(policy)}
                    </DashboardTableCell>
                    <DashboardTableCell title={formatSpendCapSummary(policy)}>
                      {formatSpendCapSummary(policy)}
                    </DashboardTableCell>
                    <DashboardTableCell title={formatAllowedRuleSummary(policy)}>
                      {formatAllowedRuleSummary(policy)}
                    </DashboardTableCell>
                    <DashboardTableCell truncate>
                      {formatTimestamp(policy.updatedAt)}
                    </DashboardTableCell>
                    <DashboardTableCell>
                      <DashboardTableActionGroup>
                        <DashboardTableActionButton
                          onClick={() => onViewPolicy(policy)}
                          disabled={mutating}
                        >
                          View
                        </DashboardTableActionButton>
                        <DashboardTableActionButton
                          onClick={() => onEditPolicy(policy)}
                          disabled={mutating}
                        >
                          Edit
                        </DashboardTableActionButton>
                        <DashboardTableActionButton
                          onClick={() => onToggleEnabled(policy)}
                          disabled={!canMutatePolicy || mutating}
                        >
                          {policy.enabled ? 'Disable' : 'Enable'}
                        </DashboardTableActionButton>
                      </DashboardTableActionGroup>
                    </DashboardTableCell>
                  </DashboardTableRow>
                ))
              )}
            </DashboardTable>
          </section>
        </>
      )}
      {activeModal ? (
        <DashboardInlineModal
          isOpen
          onRequestClose={onResetForm}
          className="dashboard-modal--wide"
          ariaLabel={
            activeModal === 'create'
              ? 'Create gas sponsorship policy modal'
              : activeModal === 'edit'
                ? 'Edit gas sponsorship policy modal'
                : 'View gas sponsorship coverage modal'
          }
        >
          {activeModal === 'view' ? (
            <>
              <h2>Coverage</h2>
              <p className="dashboard-pagination-note dashboard-gas-coverage__subtitle">
                {selectedPolicy?.name || selectedPolicy?.id || 'Selected sponsorship policy'}
              </p>
              {selectedPolicy ? (
                <>
                  <div className="dashboard-gas-coverage__stats">
                    <div className="dashboard-gas-coverage__stat">
                      <span>Environment</span>
                      <strong className="dashboard-gas-coverage__scope-value">
                        <span>
                          project:{' '}
                          {describeCoverageProjectLabel({
                            projectName: selectedProjectName,
                            projectId: selectedPolicy.projectId,
                          })}
                        </span>
                        <span>
                          environment:{' '}
                          {describeCoverageEnvironmentLabel({
                            environmentName: selectedEnvironmentName,
                            environmentKey: selectedEnvironmentKey,
                            environmentId: selectedPolicy.environmentId,
                          })}
                        </span>
                      </strong>
                    </div>
                    <div className="dashboard-gas-coverage__stat">
                      <span>Status</span>
                      <strong>{selectedPolicy.enabled ? 'Enabled' : 'Disabled'}</strong>
                    </div>
                    <div className="dashboard-gas-coverage__stat">
                      <span>{selectedPolicy.kind === 'near_delegate' ? 'Delegate actions' : 'Rules'}</span>
                      <strong>{formatAllowedRuleSummary(selectedPolicy)}</strong>
                    </div>
                    <div className="dashboard-gas-coverage__stat">
                      <span>Execution mode</span>
                      <strong>{selectedPolicy.executionMode}</strong>
                    </div>
                    <div className="dashboard-gas-coverage__stat">
                      <span>Spend cap</span>
                      <strong>{describeSpendCapMode(selectedPolicy.spendCap.mode)}</strong>
                    </div>
                  </div>
                  <section className="dashboard-gas-coverage__section">
                    <div className="dashboard-gas-coverage__section-header">
                      <span>Policy behavior</span>
                    </div>
                    <p className="dashboard-pagination-note">{formatRuleSummary(selectedPolicy)}</p>
                  </section>
                  <section className="dashboard-gas-coverage__section">
                    <div className="dashboard-gas-coverage__section-header">
                      <span>
                        {selectedPolicy.kind === 'near_delegate'
                          ? 'Delegate actions'
                          : 'Contract calls'}
                      </span>
                    </div>
                    {selectedPolicy.kind === 'near_delegate' ? (
                      selectedPolicy.allowedDelegateActions.length > 0 ? (
                        <div className="dashboard-gas-coverage__function-list">
                          {selectedPolicy.allowedDelegateActions.map((action) => (
                            <span
                              className="dashboard-gas-coverage__function-chip"
                              key={[
                                action.receiverId,
                                action.maxDepositYocto,
                                action.allowTransfers ? '1' : '0',
                                action.methods.join(','),
                              ].join(':')}
                            >
                              {formatAllowedDelegateActionSummary(action)}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="dashboard-pagination-note dashboard-gas-coverage__empty">
                          No delegate-action rules configured.
                        </p>
                      )
                    ) : selectedPolicy.allowedCalls.length > 0 ? (
                      <div className="dashboard-gas-coverage__contracts">
                        {groupAllowedCallsByContract(selectedPolicy.allowedCalls).map((rule) => (
                          <div key={rule.id} className="dashboard-gas-coverage__contract">
                            <div className="dashboard-gas-coverage__contract-header">
                              <strong>{rule.contractAddress}</strong>
                            </div>
                            <div className="dashboard-gas-coverage__function-list">
                              {rule.functions.map((functionEntry) => (
                                <span
                                  className="dashboard-gas-coverage__function-chip"
                                  key={functionEntry.id}
                                >
                                  {formatAllowedFunctionSummary(functionEntry)}
                                </span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="dashboard-pagination-note dashboard-gas-coverage__empty">
                        No allowed-call rules configured.
                      </p>
                    )}
                  </section>
                  <section className="dashboard-gas-coverage__section dashboard-gas-coverage__section--spend-caps">
                    <div className="dashboard-gas-coverage__section-header">
                      <span>Spend caps</span>
                    </div>
                    {selectedPolicy.spendCap.capsByChain.length > 0 ? (
                      <div className="dashboard-gas-coverage__function-list">
                        {selectedPolicy.spendCap.capsByChain.map((cap) => (
                          <span
                            className="dashboard-gas-coverage__function-chip"
                            key={`${cap.chainId}:${selectedPolicy.spendCap.period}`}
                          >
                            {formatSpendCapCoverageEntry({
                              chainId: cap.chainId,
                              capMinor: cap.capMinor,
                              mode: selectedPolicy.spendCap.mode,
                              period: selectedPolicy.spendCap.period,
                            })}
                          </span>
                        ))}
                      </div>
                    ) : (
                      <p className="dashboard-pagination-note dashboard-gas-coverage__empty">
                        {selectedPolicy.spendCap.mode === 'NONE'
                          ? 'No spend cap configured.'
                          : 'No per-chain spend caps configured.'}
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
                <button type="button" className="dashboard-pagination-button" onClick={onResetForm}>
                  Close
                </button>
              </div>
            </>
          ) : (
            <>
              <h2>{activeModal === 'create' ? 'Create policy' : 'Edit sponsorship policy'}</h2>
              <p className="dashboard-pagination-note">
                Name the policy, choose its scope, then define either EVM call templates or NEAR
                delegate-action templates.
              </p>
              {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
              <form className="dashboard-view-grid dashboard-view-grid--two" onSubmit={onSubmit}>
                <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                  <div className="dashboard-policy-rule-panel__header">
                    <span>Policy</span>
                  </div>
                  <div className="dashboard-view-grid dashboard-view-grid--two">
                    <label className="dashboard-form-field">
                      <span>Policy name</span>
                      <input
                        className="dashboard-input"
                        value={form.name}
                        onChange={(event) =>
                          setForm((current) => ({ ...current, name: event.target.value }))
                        }
                        placeholder="Tempo testnet onboarding"
                        disabled={mutating}
                      />
                    </label>
                    <div className="dashboard-form-field">
                      <span>Rule kind</span>
                      <div className="dashboard-policy-contract-call-mode">
                        <button
                          type="button"
                          aria-pressed={form.ruleKind === 'evm_call'}
                          className={[
                            'dashboard-policy-segment',
                            form.ruleKind === 'evm_call' ? 'dashboard-policy-segment--active' : '',
                          ]
                            .filter(Boolean)
                            .join(' ')}
                          onClick={() =>
                            setForm((current) => ({
                              ...current,
                              ruleKind: 'evm_call',
                            }))
                          }
                          disabled={mutating}
                        >
                          EVM calls
                        </button>
                        <button
                          type="button"
                          aria-pressed={form.ruleKind === 'near_delegate'}
                          className={[
                            'dashboard-policy-segment',
                            form.ruleKind === 'near_delegate'
                              ? 'dashboard-policy-segment--active'
                              : '',
                          ]
                            .filter(Boolean)
                            .join(' ')}
                          onClick={() =>
                            setForm((current) => ({
                              ...current,
                              ruleKind: 'near_delegate',
                            }))
                          }
                          disabled={mutating}
                        >
                          NEAR delegate
                        </button>
                      </div>
                    </div>
                    <label className="dashboard-form-field">
                      <span>Spend-cap period</span>
                      <select
                        className="dashboard-input"
                        value={form.spendCapPeriod}
                        onChange={(event) =>
                          setForm((current) => ({
                            ...current,
                            spendCapPeriod: event.target.value as GasSpendCapPeriod,
                          }))
                        }
                        disabled={
                          mutating || form.spendCapMode === 'NONE'
                        }
                      >
                        {GAS_SPEND_CAP_PERIODS.map((period) => (
                          <option key={period} value={period}>
                            {period}
                          </option>
                        ))}
                      </select>
                    </label>
                    <div className="dashboard-form-field dashboard-form-field--full">
                      <span>Spend cap</span>
                      <div className="dashboard-policy-contract-call-mode">
                        <button
                          type="button"
                          aria-pressed={form.spendCapMode === 'NONE'}
                          className={[
                            'dashboard-policy-segment',
                            form.spendCapMode === 'NONE'
                              ? 'dashboard-policy-segment--active'
                              : '',
                          ]
                            .filter(Boolean)
                            .join(' ')}
                          onClick={() =>
                            setForm((current) => ({
                              ...current,
                              spendCapMode: 'NONE',
                            }))
                          }
                          disabled={mutating}
                        >
                          No spend cap
                        </button>
                        <button
                          type="button"
                          aria-pressed={form.spendCapMode === 'CHAIN_TOTAL'}
                          className={[
                            'dashboard-policy-segment',
                            form.spendCapMode === 'CHAIN_TOTAL'
                              ? 'dashboard-policy-segment--active'
                              : '',
                          ]
                            .filter(Boolean)
                            .join(' ')}
                          onClick={() =>
                            setForm((current) => ({
                              ...current,
                              spendCapMode: 'CHAIN_TOTAL',
                            }))
                          }
                          disabled={mutating}
                        >
                          Per chain total
                        </button>
                        <button
                          type="button"
                          aria-pressed={form.spendCapMode === 'WALLET_CHAIN_TOTAL'}
                          className={[
                            'dashboard-policy-segment',
                            form.spendCapMode === 'WALLET_CHAIN_TOTAL'
                              ? 'dashboard-policy-segment--active'
                              : '',
                          ]
                            .filter(Boolean)
                            .join(' ')}
                          onClick={() =>
                            setForm((current) => ({
                              ...current,
                              spendCapMode: 'WALLET_CHAIN_TOTAL',
                            }))
                          }
                          disabled={mutating}
                        >
                          Per wallet, per chain
                        </button>
                      </div>
                    </div>
                    {form.ruleKind === 'evm_call' ? (
                      <div className="dashboard-form-field dashboard-form-field--full">
                        <div className="dashboard-gas-target-matrix">
                        <div className="dashboard-gas-target-matrix__header">
                          <span>Chain</span>
                          <span>{activeChainColumnLabel}</span>
                          <span>Spend cap</span>
                        </div>
                        {GAS_CHAIN_MATRIX_ROWS.map((row) => (
                          <div className="dashboard-gas-target-matrix__row" key={row.chainName}>
                            <div className="dashboard-gas-target-matrix__chain">
                              {row.chainName}
                            </div>
                            {(() => {
                              const target = getGasChainTargetForNetwork(
                                row,
                                selectedEnvironmentNetworkClass,
                              );
                              if (!target) {
                                return (
                                  <>
                                    <span className="dashboard-gas-target-matrix__cell">
                                      <span className="dashboard-gas-target-pill dashboard-gas-target-pill--unavailable">
                                        N/A
                                      </span>
                                    </span>
                                    <span className="dashboard-gas-target-matrix__cap">
                                      <span className="dashboard-gas-target-cap__empty">-</span>
                                    </span>
                                  </>
                                );
                              }
                              const pressed = selectedTargetIds.includes(target.id);
                              return (
                                <>
                                  <span className="dashboard-gas-target-matrix__cell">
                                    <span
                                      className="dashboard-gas-target-toggle"
                                      role="group"
                                      aria-label={target.chainLabel}
                                    >
                                      <button
                                        type="button"
                                        aria-pressed={pressed}
                                        className={[
                                          'dashboard-gas-target-toggle__option',
                                          pressed
                                            ? 'dashboard-gas-target-toggle__option--active'
                                            : '',
                                        ]
                                          .filter(Boolean)
                                          .join(' ')}
                                        onClick={() => onSetTargetEnabled(target.id, true)}
                                        disabled={mutating}
                                      >
                                        On
                                      </button>
                                      <button
                                        type="button"
                                        aria-pressed={!pressed}
                                        className={[
                                          'dashboard-gas-target-toggle__option',
                                          !pressed
                                            ? 'dashboard-gas-target-toggle__option--active'
                                            : '',
                                        ]
                                          .filter(Boolean)
                                          .join(' ')}
                                        onClick={() => onSetTargetEnabled(target.id, false)}
                                        disabled={mutating}
                                      >
                                        Off
                                      </button>
                                    </span>
                                  </span>
                                  <span className="dashboard-gas-target-matrix__cap">
                                    {form.spendCapMode === 'NONE' ? (
                                      <span className="dashboard-gas-target-cap__empty">
                                        No cap
                                      </span>
                                    ) : !pressed ? (
                                      <span className="dashboard-gas-target-cap__empty">
                                        Turn on chain
                                      </span>
                                    ) : (
                                      <span className="dashboard-gas-target-cap__input">
                                        <input
                                          className="dashboard-input"
                                          aria-label={`${target.chainLabel} spend cap`}
                                          inputMode="decimal"
                                          value={
                                            form.spendCapAmountByChainName[target.chainName] || ''
                                          }
                                          onChange={(event) =>
                                            setForm((current) => ({
                                              ...current,
                                              spendCapAmountByChainName: {
                                                ...current.spendCapAmountByChainName,
                                                [target.chainName]: event.target.value,
                                              },
                                            }))
                                          }
                                          onBlur={(event) =>
                                            setForm((current) => ({
                                              ...current,
                                              spendCapAmountByChainName: {
                                                ...current.spendCapAmountByChainName,
                                                [target.chainName]: normalizeSpendCapAmountInput(
                                                  event.target.value,
                                                  target.spendCapDisplayDecimals,
                                                ),
                                              },
                                            }))
                                          }
                                          placeholder="0.00"
                                          disabled={mutating}
                                        />
                                        <span className="dashboard-gas-target-cap__unit">
                                          {target.spendCapCurrencyCode}
                                        </span>
                                      </span>
                                    )}
                                  </span>
                                </>
                              );
                            })()}
                          </div>
                        ))}
                        </div>
                        <div className="dashboard-gas-target-bulk">
                          <button
                            type="button"
                            aria-pressed={allActiveTargetsSelected}
                            className={[
                              'dashboard-policy-segment',
                              allActiveTargetsSelected ? 'dashboard-policy-segment--active' : '',
                            ]
                              .filter(Boolean)
                              .join(' ')}
                            onClick={() => onToggleTargetGroup(selectedEnvironmentNetworkClass)}
                            disabled={mutating}
                          >
                            {activeTargetGroupLabel}
                          </button>
                        </div>
                      </div>
                    ) : (
                      <div className="dashboard-form-field dashboard-form-field--full">
                        <p className="dashboard-pagination-note">
                          NEAR delegate sponsorship follows the selected environment network:
                          {' '}
                          {formatNetworkClassLabel(selectedEnvironmentNetworkClass)}.
                        </p>
                        {(() => {
                          const nearTarget =
                            getNearSpendCapTargetForNetwork(selectedEnvironmentNetworkClass);
                          if (!nearTarget) return null;
                          return (
                            <div className="dashboard-gas-target-matrix">
                              <div className="dashboard-gas-target-matrix__header">
                                <span>Chain</span>
                                <span>Network</span>
                                <span>Spend cap</span>
                              </div>
                              <div className="dashboard-gas-target-matrix__row">
                                <div className="dashboard-gas-target-matrix__chain">NEAR</div>
                                <span className="dashboard-gas-target-matrix__cell">
                                  <span className="dashboard-gas-target-pill">
                                    {nearTarget.chainLabel}
                                  </span>
                                </span>
                                <span className="dashboard-gas-target-matrix__cap">
                                  {form.spendCapMode === 'NONE' ? (
                                    <span className="dashboard-gas-target-cap__empty">No cap</span>
                                  ) : (
                                    <span className="dashboard-gas-target-cap__input">
                                      <input
                                        className="dashboard-input"
                                        aria-label={`${nearTarget.chainLabel} spend cap`}
                                        inputMode="decimal"
                                        value={
                                          form.spendCapAmountByChainName[nearTarget.chainName] ||
                                          ''
                                        }
                                        onChange={(event) =>
                                          setForm((current) => ({
                                            ...current,
                                            spendCapAmountByChainName: {
                                              ...current.spendCapAmountByChainName,
                                              [nearTarget.chainName]: event.target.value,
                                            },
                                          }))
                                        }
                                        onBlur={(event) =>
                                          setForm((current) => ({
                                            ...current,
                                            spendCapAmountByChainName: {
                                              ...current.spendCapAmountByChainName,
                                              [nearTarget.chainName]: normalizeSpendCapAmountInput(
                                                event.target.value,
                                                nearTarget.spendCapDisplayDecimals,
                                              ),
                                            },
                                          }))
                                        }
                                        placeholder="0.00"
                                        disabled={mutating}
                                      />
                                      <span className="dashboard-gas-target-cap__unit">
                                        {nearTarget.spendCapCurrencyCode}
                                      </span>
                                    </span>
                                  )}
                                </span>
                              </div>
                            </div>
                          );
                        })()}
                      </div>
                    )}
                  </div>
                </section>

                <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                  <div className="dashboard-policy-rule-panel__header">
                    <span>
                      {form.ruleKind === 'near_delegate' ? 'Delegate actions' : 'Contract calls'}
                    </span>
                    <p className="dashboard-pagination-note">
                      {form.ruleKind === 'near_delegate'
                        ? 'Define the allowlisted NEAR receivers, optional method lists, deposit bounds, and transfer allowance.'
                        : 'Define the allowlisted contract functions and their gas/value bounds for the selected chains.'}
                    </p>
                  </div>
                  {form.ruleKind === 'near_delegate' ? (
                    <div className="dashboard-policy-contract-calls">
                      <p className="dashboard-pagination-note">Execution mode: `near_delegate`.</p>
                      {form.delegateActionRules.length === 0 ? (
                        <p className="dashboard-pagination-note">
                          Add one or more delegate actions to define the sponsored receiver and
                          method templates.
                        </p>
                      ) : null}
                      {form.delegateActionRules.map((rule) => (
                        <div key={rule.id} className="dashboard-policy-contract-card">
                          <div className="dashboard-policy-contract-card__header">
                            <strong>Allowed delegate action</strong>
                            <button
                              type="button"
                              className="dashboard-inline-link dashboard-inline-link--danger"
                              onClick={() => removeDelegateActionRule(rule.id)}
                              disabled={mutating}
                            >
                              Remove
                            </button>
                          </div>
                          <div className="dashboard-view-grid dashboard-view-grid--two">
                            <label className="dashboard-form-field">
                              <span>Receiver ID</span>
                              <input
                                className="dashboard-input"
                                value={rule.receiverId}
                                onChange={(event) =>
                                  updateDelegateActionRule(rule.id, {
                                    receiverId: event.target.value,
                                  })
                                }
                                placeholder="guest-book.testnet"
                                disabled={mutating}
                              />
                            </label>
                            <label className="dashboard-form-field">
                              <span>Max deposit (yoctoNEAR)</span>
                              <input
                                className="dashboard-input"
                                value={rule.maxDepositYocto}
                                onChange={(event) =>
                                  updateDelegateActionRule(rule.id, {
                                    maxDepositYocto: event.target.value,
                                  })
                                }
                                placeholder="0"
                                inputMode="numeric"
                                disabled={mutating}
                              />
                            </label>
                            <label className="dashboard-form-field dashboard-form-field--full">
                              <span>Allowed methods (comma or newline separated)</span>
                              <textarea
                                className="dashboard-input"
                                value={rule.methodsText}
                                onChange={(event) =>
                                  updateDelegateActionRule(rule.id, {
                                    methodsText: event.target.value,
                                  })
                                }
                                placeholder="add_message, vote"
                                disabled={mutating}
                                rows={3}
                              />
                            </label>
                            <label className="dashboard-form-field dashboard-form-field--full">
                              <span className="dashboard-policy-inline-checkbox">
                                <input
                                  type="checkbox"
                                  checked={rule.allowTransfers}
                                  onChange={(event) =>
                                    updateDelegateActionRule(rule.id, {
                                      allowTransfers: event.target.checked,
                                    })
                                  }
                                  disabled={mutating}
                                />
                                Allow native transfers in the delegate action
                              </span>
                            </label>
                          </div>
                        </div>
                      ))}
                      <button
                        type="button"
                        className="dashboard-pagination-button dashboard-policy-contract-add-button"
                        onClick={addDelegateActionRule}
                        disabled={mutating}
                      >
                        Add delegate action
                      </button>
                    </div>
                  ) : (
                    <div className="dashboard-policy-contract-calls">
                      <p className="dashboard-pagination-note">Execution mode: `evm_eoa`.</p>
                      {form.contractCallRules.length === 0 ? (
                        <p className="dashboard-pagination-note">
                          Add one or more contracts to define the sponsored function templates.
                        </p>
                      ) : null}
                      {form.contractCallRules.map((rule) => (
                        <div key={rule.id} className="dashboard-policy-contract-card">
                          <div className="dashboard-policy-contract-card__header">
                            <strong>Allowed contract</strong>
                            <button
                              type="button"
                              className="dashboard-inline-link dashboard-inline-link--danger"
                              onClick={() => removeContractCallRule(rule.id)}
                              disabled={mutating}
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
                              disabled={mutating}
                            />
                          </label>
                          <div className="dashboard-uri-list-editor__rows">
                            {rule.functions.map((functionEntry, index) => (
                              <div key={functionEntry.id} className="dashboard-uri-list-editor__row">
                                <label className="dashboard-form-field dashboard-uri-list-editor__field">
                                  <span className={index === 0 ? '' : 'dashboard-visually-hidden'}>
                                    Function signature
                                  </span>
                                  <input
                                    className="dashboard-input"
                                    value={functionEntry.functionSignature}
                                    onChange={(event) =>
                                      updateContractFunction(rule.id, functionEntry.id, {
                                        functionSignature: event.target.value,
                                      })
                                    }
                                    placeholder="transfer(address,uint256)"
                                    disabled={mutating}
                                  />
                                </label>
                                <label className="dashboard-form-field dashboard-uri-list-editor__field">
                                  <span className={index === 0 ? '' : 'dashboard-visually-hidden'}>
                                    Max gas limit
                                  </span>
                                  <input
                                    className="dashboard-input"
                                    value={functionEntry.maxGasLimit}
                                    onChange={(event) =>
                                      updateContractFunction(rule.id, functionEntry.id, {
                                        maxGasLimit: event.target.value,
                                      })
                                    }
                                    placeholder="300000"
                                    inputMode="numeric"
                                    disabled={mutating}
                                  />
                                </label>
                                <label className="dashboard-form-field dashboard-uri-list-editor__field">
                                  <span className={index === 0 ? '' : 'dashboard-visually-hidden'}>
                                    Max value (wei)
                                  </span>
                                  <input
                                    className="dashboard-input"
                                    value={functionEntry.maxValueWei}
                                    onChange={(event) =>
                                      updateContractFunction(rule.id, functionEntry.id, {
                                        maxValueWei: event.target.value,
                                      })
                                    }
                                    placeholder="0"
                                    inputMode="numeric"
                                    disabled={mutating}
                                  />
                                </label>
                                <div className="dashboard-uri-list-editor__actions">
                                  <button
                                    type="button"
                                    className="dashboard-pagination-button dashboard-pagination-button--secondary"
                                    onClick={() => removeContractFunction(rule.id, functionEntry.id)}
                                    disabled={mutating}
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
                            disabled={mutating}
                          >
                            Add function
                          </button>
                        </div>
                      ))}
                      <button
                        type="button"
                        className="dashboard-pagination-button dashboard-policy-contract-add-button"
                        onClick={addContractCallRule}
                        disabled={mutating}
                      >
                        Add contract
                      </button>
                    </div>
                  )}
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
                    disabled={!canMutatePolicy || mutating}
                  >
                    {mutating
                      ? 'Saving...'
                      : editingPolicyId
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
        </DashboardInlineModal>
      ) : null}
    </div>
  );
}

export default GasSponsorshipPage;
