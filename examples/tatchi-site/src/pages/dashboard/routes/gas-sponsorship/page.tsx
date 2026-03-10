import React from 'react';
import { toast } from 'sonner';
import { keccak256Bytes } from '../../../../../../../shared/src/utils/keccak';
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
import {
  createDashboardGasSponsorship,
  listDashboardGasSponsorship,
  updateDashboardGasSponsorship,
  type DashboardGasSponsorshipConfig,
} from './consoleGasSponsorshipApi';

const SCOPE_TYPES = ['ORG', 'PROJECT', 'ENVIRONMENT', 'POLICY', 'WALLET_SEGMENT'] as const;
type ScopeType = (typeof SCOPE_TYPES)[number];

const GAS_NETWORK_CLASSES = ['ANY', 'TESTNET', 'MAINNET'] as const;
type GasNetworkClass = (typeof GAS_NETWORK_CLASSES)[number];
type GasNetworkToggleClass = Exclude<GasNetworkClass, 'ANY'>;
const GAS_SPEND_CAP_MODES = ['NONE', 'CHAIN_TOTAL', 'WALLET_CHAIN_TOTAL'] as const;
type GasSpendCapMode = (typeof GAS_SPEND_CAP_MODES)[number];
const GAS_SPEND_CAP_PERIODS = ['WEEKLY', 'MONTHLY'] as const;
type GasSpendCapPeriod = (typeof GAS_SPEND_CAP_PERIODS)[number];
const PRODUCTION_ENVIRONMENT_KEY = 'prod';
type GasSponsorshipModalKind = 'create' | 'edit' | 'view';
type GasSponsorshipDraftScope = {
  orgId: string;
  projectId: string;
  environmentId: string;
};
type GasChainTarget = {
  id: string;
  chainName: string;
  chainLabel: string;
  chainId: number;
  networkClass: GasNetworkToggleClass;
};
type GasChainMatrixRow = {
  chainName: string;
  mainnet: GasChainTarget | null;
  testnet: GasChainTarget | null;
};
type GasContractRuleDraft = {
  id: string;
  contractAddress: string;
  functions: string[];
};

const GAS_CHAIN_MATRIX_ROWS: readonly GasChainMatrixRow[] = [
  {
    chainName: 'Ethereum',
    mainnet: {
      id: 'ethereum-mainnet',
      chainName: 'Ethereum',
      chainLabel: 'Ethereum Mainnet',
      chainId: 1,
      networkClass: 'MAINNET',
    },
    testnet: {
      id: 'ethereum-sepolia',
      chainName: 'Ethereum',
      chainLabel: 'Ethereum Testnet',
      chainId: 11_155_111,
      networkClass: 'TESTNET',
    },
  },
  {
    chainName: 'Arc Circle',
    mainnet: {
      id: 'arc-mainnet',
      chainName: 'Arc Circle',
      chainLabel: 'Arc Circle Mainnet',
      chainId: 2415,
      networkClass: 'MAINNET',
    },
    testnet: {
      id: 'arc-testnet',
      chainName: 'Arc Circle',
      chainLabel: 'Arc Circle Testnet',
      chainId: 5_042_002,
      networkClass: 'TESTNET',
    },
  },
  {
    chainName: 'Tempo',
    mainnet: {
      id: 'tempo-mainnet',
      chainName: 'Tempo',
      chainLabel: 'Tempo Mainnet',
      chainId: 4_217,
      networkClass: 'MAINNET',
    },
    testnet: {
      id: 'tempo-testnet',
      chainName: 'Tempo',
      chainLabel: 'Tempo Testnet',
      chainId: 42_431,
      networkClass: 'TESTNET',
    },
  },
] as const;

const GAS_CHAIN_TARGETS: readonly GasChainTarget[] = GAS_CHAIN_MATRIX_ROWS.flatMap((row) =>
  [row.mainnet, row.testnet].filter((entry): entry is GasChainTarget => entry !== null),
);
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

type GasSponsorshipFormState = {
  policyName: string;
  scopeType: ScopeType;
  projectId: string;
  environmentId: string;
  policyId: string;
  walletSegmentId: string;
  enabled: boolean;
  selectedTargets: string[];
  contractCallAllowlistEnabled: boolean;
  contractCallRules: GasContractRuleDraft[];
  spendCapMode: GasSpendCapMode;
  spendCapPeriod: GasSpendCapPeriod;
  spendCapMinorByChainName: Record<string, string>;
};

function normalizeString(value: string): string {
  return String(value || '').trim();
}

function makeDraftId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}`;
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes, (value) => value.toString(16).padStart(2, '0')).join('')}`;
}

function normalizeFunctionSelectorInput(value: string): `0x${string}` | null {
  const normalized = normalizeString(value);
  if (!normalized) return null;
  if (/^0x[0-9a-fA-F]{8}$/.test(normalized)) {
    return normalized.toLowerCase() as `0x${string}`;
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*\([^)]*\)$/.test(normalized)) {
    return null;
  }
  const digest = keccak256Bytes(new TextEncoder().encode(normalized));
  return bytesToHex(digest.slice(0, 4)).toLowerCase() as `0x${string}`;
}

function createEmptyGasContractRuleDraft(): GasContractRuleDraft {
  return {
    id: makeDraftId('gas_contract'),
    contractAddress: '',
    functions: [''],
  };
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

function readGasContractRuleDrafts(raw: unknown): GasContractRuleDraft[] {
  if (!Array.isArray(raw)) return [];
  const out: GasContractRuleDraft[] = [];
  for (const entry of raw) {
    if (!isRecord(entry)) continue;
    const contractAddress = normalizeString(String(entry.contractAddress || ''));
    const functionsRaw = Array.isArray(entry.functions) ? entry.functions : [];
    const functions = functionsRaw.map((value) => normalizeString(String(value || '')));
    out.push({
      id: normalizeString(String(entry.id || '')) || makeDraftId('gas_contract'),
      contractAddress,
      functions: functions.length > 0 ? functions : [''],
    });
  }
  return out;
}

function readSpendCapMinorByChainName(raw: unknown): Record<string, string> {
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

function deriveSelectedTargetsFromLegacyFields(raw: Record<string, unknown>): string[] {
  const chainToken = normalizeString(String(raw.chain || ''));
  if (!chainToken) return [];
  const networkClass = readEnumValue(raw.networkClass, GAS_NETWORK_CLASSES, 'TESTNET');
  const matchingTargets = GAS_CHAIN_TARGETS.filter(
    (target) => String(target.chainId) === chainToken,
  );
  if (matchingTargets.length === 0) return [];
  if (networkClass === 'ANY') {
    return matchingTargets.map((target) => target.id);
  }
  return matchingTargets
    .filter((target) => target.networkClass === networkClass)
    .map((target) => target.id);
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

function deriveLegacyContractCallRules(raw: Record<string, unknown>): GasContractRuleDraft[] {
  const contractAddress = normalizeString(String(raw.callTo || ''));
  const selector = normalizeString(String(raw.callSelector || ''));
  if (!contractAddress && !selector) return [];
  return [
    {
      id: makeDraftId('gas_contract'),
      contractAddress,
      functions: [selector],
    },
  ];
}

function groupAllowedCallsByContract(
  allowedCalls: readonly DashboardGasSponsorshipConfig['allowedCalls'][number][],
): GasContractRuleDraft[] {
  const byContract = new Map<
    string,
    { contractAddress: string; functions: string[]; seen: Set<string> }
  >();
  for (const allowedCall of allowedCalls) {
    const contractKey = allowedCall.to.toLowerCase();
    const selector = normalizeString(allowedCall.selector).toLowerCase();
    if (!selector) continue;
    let bucket = byContract.get(contractKey);
    if (!bucket) {
      bucket = {
        contractAddress: allowedCall.to,
        functions: [],
        seen: new Set<string>(),
      };
      byContract.set(contractKey, bucket);
    }
    if (bucket.seen.has(selector)) continue;
    bucket.seen.add(selector);
    bucket.functions.push(selector);
  }
  return Array.from(byContract.values()).map((entry) => ({
    id: `gas_contract_${entry.contractAddress.toLowerCase()}`,
    contractAddress: entry.contractAddress,
    functions: entry.functions.length > 0 ? entry.functions : [''],
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

function resolveSelectedTargetIdsFromConfig(config: DashboardGasSponsorshipConfig): string[] {
  const targetIdsFromChains = config.allowedChainIds
    .map((chainId) => GAS_CHAIN_TARGETS.find((target) => target.chainId === chainId)?.id || '')
    .filter(Boolean);
  if (targetIdsFromChains.length > 0) {
    return uniqueGasTargetIds(targetIdsFromChains);
  }
  const targetIdsFromCalls = config.allowedCalls
    .map((call) => GAS_CHAIN_TARGETS.find((target) => target.chainId === call.chainId)?.id || '')
    .filter(Boolean);
  if (targetIdsFromCalls.length > 0) {
    return uniqueGasTargetIds(targetIdsFromCalls);
  }
  if (config.networkClass === 'MAINNET') return [...GAS_MAINNET_TARGET_IDS];
  if (config.networkClass === 'TESTNET') return [...GAS_TESTNET_TARGET_IDS];
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
  const legacyContractRules = deriveLegacyContractCallRules(raw);
  const contractCallRules = readGasContractRuleDrafts(raw.contractCallRules);
  return {
    policyName: normalizeString(String(raw.policyName ?? fallback.policyName)),
    scopeType: readEnumValue(raw.scopeType, SCOPE_TYPES, fallback.scopeType),
    projectId: normalizeString(String(raw.projectId ?? fallback.projectId)),
    environmentId: normalizeString(String(raw.environmentId ?? fallback.environmentId)),
    policyId: normalizeString(String(raw.policyId ?? fallback.policyId)),
    walletSegmentId: normalizeString(String(raw.walletSegmentId ?? fallback.walletSegmentId)),
    enabled: raw.enabled === true || raw.enabled === false ? raw.enabled : fallback.enabled,
    selectedTargets: (() => {
      if (Array.isArray(raw.selectedTargets)) {
        return uniqueGasTargetIds(raw.selectedTargets.map((value) => String(value || '')));
      }
      const derivedLegacyTargets = deriveSelectedTargetsFromLegacyFields(raw);
      return derivedLegacyTargets.length > 0 ? derivedLegacyTargets : fallback.selectedTargets;
    })(),
    contractCallAllowlistEnabled:
      raw.contractCallAllowlistEnabled === true || raw.contractCallAllowlistEnabled === false
        ? raw.contractCallAllowlistEnabled
        : contractCallRules.length > 0 || legacyContractRules.length > 0
          ? true
          : fallback.contractCallAllowlistEnabled,
    contractCallRules:
      contractCallRules.length > 0
        ? contractCallRules
        : legacyContractRules.length > 0
          ? legacyContractRules
          : fallback.contractCallRules,
    spendCapMode: readEnumValue(raw.spendCapMode, GAS_SPEND_CAP_MODES, fallback.spendCapMode),
    spendCapPeriod: readEnumValue(
      raw.spendCapPeriod,
      GAS_SPEND_CAP_PERIODS,
      fallback.spendCapPeriod,
    ),
    spendCapMinorByChainName: (() => {
      const parsed = readSpendCapMinorByChainName(raw.spendCapMinorByChainName);
      return Object.keys(parsed).length > 0 ? parsed : fallback.spendCapMinorByChainName;
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
    policyName: 'Project gas sponsorship',
    scopeType: resolveDefaultScopeType(projectId, environmentId),
    projectId,
    environmentId,
    policyId: '',
    walletSegmentId: '',
    enabled: true,
    selectedTargets: [],
    contractCallAllowlistEnabled: false,
    contractCallRules: [],
    spendCapMode: 'NONE',
    spendCapPeriod: 'MONTHLY',
    spendCapMinorByChainName: {},
  };
}

function buildFormStateFromConfig(
  config: DashboardGasSponsorshipConfig,
  projectId: string,
  environmentId: string,
): GasSponsorshipFormState {
  const contractCallRules = groupAllowedCallsByContract(config.allowedCalls);
  const spendCapMinorByChainName = config.spendCap.capsByChain.reduce<Record<string, string>>(
    (accumulator, entry) => {
      const target = GAS_CHAIN_TARGETS_BY_CHAIN_ID.get(entry.chainId);
      if (!target) return accumulator;
      accumulator[target.chainName] = String(entry.capMinor);
      return accumulator;
    },
    {},
  );
  return {
    policyName: config.policyName,
    scopeType: String(config.scopeType || 'ENVIRONMENT').toUpperCase() as ScopeType,
    projectId: config.projectId || projectId,
    environmentId: config.environmentId || environmentId,
    policyId: config.policyId || '',
    walletSegmentId: config.walletSegmentId || '',
    enabled: config.enabled,
    selectedTargets: resolveSelectedTargetIdsFromConfig(config),
    contractCallAllowlistEnabled: config.callMode === 'ALLOWLIST',
    contractCallRules,
    spendCapMode: config.spendCap.mode,
    spendCapPeriod: config.spendCap.period,
    spendCapMinorByChainName,
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
      const rawCapMinor = normalizeString(form.spendCapMinorByChainName[target.chainName] || '');
      if (!rawCapMinor) return [];
      return [
        {
          chainId: target.chainId,
          capMinor: parseRequiredNonNegativeInteger(rawCapMinor, `${target.chainLabel} spend cap`),
        },
      ];
    }),
  };
}

function buildAllowedCalls(
  form: GasSponsorshipFormState,
  selectedTargets: readonly GasChainTarget[],
) {
  if (!form.contractCallAllowlistEnabled) return [];
  if (selectedTargets.length === 0) {
    throw new Error('Allowlist mode requires at least one selected chain.');
  }
  if (form.contractCallRules.length === 0) {
    throw new Error('Allowlist mode requires at least one allowed contract.');
  }
  const out = new Map<string, { chainId: number; to: string; selector: string }>();
  for (const rule of form.contractCallRules) {
    const contractAddress = normalizeString(rule.contractAddress);
    if (!/^0x[0-9a-fA-F]{40}$/.test(contractAddress)) {
      throw new Error('Allowed contract must be a valid EVM address.');
    }
    const functions = rule.functions
      .map((entry) => normalizeString(entry))
      .filter((entry) => entry.length > 0);
    if (functions.length === 0) {
      throw new Error('Each allowed contract needs at least one function.');
    }
    for (const functionEntry of functions) {
      const selector = normalizeFunctionSelectorInput(functionEntry);
      if (!selector) {
        throw new Error(
          'Allowed function must be a function signature like transfer(address,uint256) or a 4-byte selector like 0xa9059cbb.',
        );
      }
      for (const target of selectedTargets) {
        out.set(`${target.chainId}:${contractAddress.toLowerCase()}:${selector}`, {
          chainId: target.chainId,
          to: contractAddress,
          selector,
        });
      }
    }
  }
  return Array.from(out.values());
}

function buildGasSponsorshipRequest(
  form: GasSponsorshipFormState,
  networkClass: GasNetworkToggleClass,
): Record<string, unknown> {
  const selectedTargets = resolveSelectedTargetsOrThrow(
    remapSelectedTargetsToNetwork(form.selectedTargets, networkClass),
  );
  return {
    ...buildScopePayload(form),
    policyName: normalizeString(form.policyName) || 'Gas Sponsorship Policy',
    networkClass,
    enabled: form.enabled,
    allowedChainIds: selectedTargets.map((target) => target.chainId),
    callMode: form.contractCallAllowlistEnabled ? 'ALLOWLIST' : 'ALLOW_ALL',
    spendCap: buildSpendCap(form, selectedTargets),
    allowedCalls: buildAllowedCalls(form, selectedTargets),
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
  mode: GasSpendCapMode | DashboardGasSponsorshipConfig['spendCap']['mode'],
): string {
  if (mode === 'CHAIN_TOTAL') return 'Per chain total';
  if (mode === 'WALLET_CHAIN_TOTAL') return 'Per wallet, per chain';
  return 'No spend cap';
}

function formatSpendCapCoverageEntry(input: {
  chainId: number;
  capMinor: number;
  mode: DashboardGasSponsorshipConfig['spendCap']['mode'];
  period: DashboardGasSponsorshipConfig['spendCap']['period'];
}): string {
  const target = GAS_CHAIN_TARGETS_BY_CHAIN_ID.get(input.chainId);
  const chainLabel = target?.chainLabel || `Chain ${input.chainId}`;
  const scopeLabel = input.mode === 'CHAIN_TOTAL' ? 'total' : 'per wallet';
  return `${chainLabel} ${input.period.toLowerCase()} cap ${formatCurrencyMinor(input.capMinor)} ${scopeLabel}`;
}

function formatSpendCapSummary(config: DashboardGasSponsorshipConfig): string {
  if (config.spendCap.mode === 'NONE') return 'No spend cap';
  const firstCap = config.spendCap.capsByChain[0];
  if (!firstCap) {
    return `${describeSpendCapMode(config.spendCap.mode)} (${config.spendCap.period.toLowerCase()})`;
  }
  if (config.spendCap.capsByChain.length > 1) {
    return `${config.spendCap.capsByChain.length} ${config.spendCap.period.toLowerCase()} caps · ${describeSpendCapMode(
      config.spendCap.mode,
    ).toLowerCase()}`;
  }
  return formatSpendCapCoverageEntry({
    chainId: firstCap.chainId,
    capMinor: firstCap.capMinor,
    mode: config.spendCap.mode,
    period: config.spendCap.period,
  });
}

function formatAllowedCallSummary(config: DashboardGasSponsorshipConfig): string {
  if (config.callMode === 'ALLOW_ALL') return 'Allow all contract calls';
  const groupedRules = groupAllowedCallsByContract(config.allowedCalls);
  const contractCount = groupedRules.length;
  const functionCount = groupedRules.reduce((sum, rule) => sum + rule.functions.length, 0);
  if (contractCount === 0 || functionCount === 0) return 'No allowed-call rule';
  return `${contractCount} contract${contractCount === 1 ? '' : 's'} / ${functionCount} function${functionCount === 1 ? '' : 's'}`;
}

function formatRuleSummary(config: DashboardGasSponsorshipConfig): string {
  return [
    formatSelectedTargetLabels(resolveSelectedTargetIdsFromConfig(config)),
    config.enabled ? 'enabled' : 'disabled',
  ].join(' / ');
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
  const [selectedProjectName, setSelectedProjectName] = React.useState<string>('');
  const [selectedEnvironmentKey, setSelectedEnvironmentKey] = React.useState<string>('');
  const [selectedEnvironmentName, setSelectedEnvironmentName] = React.useState<string>('');
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
  const restoredDraftToastKeyRef = React.useRef<string>('');

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
        uniqueGasTargetIds(current.selectedTargets)
          .map((targetId) => GAS_CHAIN_TARGETS_BY_ID.get(targetId)?.chainName || '')
          .filter(Boolean),
      );
      const nextSpendCapMinorByChainName = Object.fromEntries(
        Object.entries(current.spendCapMinorByChainName).filter(([chainName]) =>
          selectedChainNames.has(chainName),
        ),
      );
      if (
        Object.keys(nextSpendCapMinorByChainName).length ===
          Object.keys(current.spendCapMinorByChainName).length &&
        Object.entries(nextSpendCapMinorByChainName).every(
          ([chainName, value]) => current.spendCapMinorByChainName[chainName] === value,
        )
      ) {
        return current;
      }
      return {
        ...current,
        spendCapMinorByChainName: nextSpendCapMinorByChainName,
      };
    });
  }, [policyModalOpen, setForm]);

  const canMutateConfig = React.useMemo(
    () => hasConfigMutationRole(session.claims?.roles),
    [session.claims?.roles],
  );

  const selectedConfig = React.useMemo(
    () => gasConfigs.find((config) => config.id === selectedConfigId) || null,
    [gasConfigs, selectedConfigId],
  );
  const gasConfigsPagination = useDashboardTablePagination(gasConfigs, {
    disabled: session.loading || loading,
    itemLabel: 'policy',
    itemLabelPlural: 'policies',
  });

  React.useEffect(() => {
    if (!session.claims || !selectedProjectId || !selectedEnvironmentId) {
      setSelectedProjectName('');
      setSelectedEnvironmentKey('');
      setSelectedEnvironmentName('');
      return;
    }
    let cancelled = false;
    Promise.all([
      listDashboardProjects({ status: 'ACTIVE' }),
      listDashboardEnvironments({ projectId: selectedProjectId }),
    ])
      .then(([projects, environments]) => {
        if (cancelled) return;
        const selectedProject = projects.find((entry) => entry.id === selectedProjectId) || null;
        const selectedEnvironment =
          environments.find((entry) => entry.id === selectedEnvironmentId) || null;
        setSelectedProjectName(String(selectedProject?.name || ''));
        setSelectedEnvironmentKey(String(selectedEnvironment?.key || ''));
        setSelectedEnvironmentName(String(selectedEnvironment?.name || ''));
      })
      .catch(() => {
        if (cancelled) return;
        setSelectedProjectName('');
        setSelectedEnvironmentKey('');
        setSelectedEnvironmentName('');
      });
    return () => {
      cancelled = true;
    };
  }, [selectedEnvironmentId, selectedProjectId, session.claims]);

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

  const onSetTargetEnabled = React.useCallback(
    (targetId: string, enabled: boolean) => {
      setForm((current) => {
        const target = GAS_CHAIN_TARGETS_BY_ID.get(targetId);
        if (!target) return current;
        const hasTarget = current.selectedTargets.includes(targetId);
        if (enabled && hasTarget) return current;
        if (!enabled && !hasTarget) return current;
        const nextSpendCapMinorByChainName = { ...current.spendCapMinorByChainName };
        if (!enabled) {
          delete nextSpendCapMinorByChainName[target.chainName];
        }
        return {
          ...current,
          selectedTargets: enabled
            ? uniqueGasTargetIds([...current.selectedTargets, targetId])
            : current.selectedTargets.filter((entry) => entry !== targetId),
          spendCapMinorByChainName: nextSpendCapMinorByChainName,
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
        const nextSpendCapMinorByChainName = { ...current.spendCapMinorByChainName };
        if (hasEntireGroup) {
          groupTargetIds.forEach((targetId) => {
            const target = GAS_CHAIN_TARGETS_BY_ID.get(targetId);
            if (!target) return;
            delete nextSpendCapMinorByChainName[target.chainName];
          });
        }
        const nextSelectedTargets = hasEntireGroup
          ? current.selectedTargets.filter((targetId) => !groupTargetIds.includes(targetId))
          : uniqueGasTargetIds([...current.selectedTargets, ...groupTargetIds]);
        return {
          ...current,
          selectedTargets: nextSelectedTargets,
          spendCapMinorByChainName: nextSpendCapMinorByChainName,
        };
      });
    },
    [setForm],
  );

  const addContractCallRule = React.useCallback(() => {
    setForm((current) => ({
      ...current,
      contractCallAllowlistEnabled: true,
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
          entry.id === ruleId ? { ...entry, functions: [...entry.functions, ''] } : entry,
        ),
      }));
    },
    [setForm],
  );

  const removeContractFunction = React.useCallback(
    (ruleId: string, index: number) => {
      setForm((current) => ({
        ...current,
        contractCallRules: current.contractCallRules.map((entry) => {
          if (entry.id !== ruleId) return entry;
          const nextFunctions = entry.functions.filter(
            (_, functionIndex) => functionIndex !== index,
          );
          return {
            ...entry,
            functions: nextFunctions.length > 0 ? nextFunctions : [''],
          };
        }),
      }));
    },
    [setForm],
  );

  const updateContractFunction = React.useCallback(
    (ruleId: string, index: number, value: string) => {
      setForm((current) => ({
        ...current,
        contractCallRules: current.contractCallRules.map((entry) =>
          entry.id === ruleId
            ? {
                ...entry,
                functions: entry.functions.map((functionEntry, functionIndex) =>
                  functionIndex === index ? value : functionEntry,
                ),
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
      if (!canMutateConfig) {
        setMutationError('Only owner/admin/security_admin can mutate gas sponsorship settings.');
        return;
      }
      setMutating(true);
      setMutationError('');
      setMutationNotice('');
      try {
        const request = buildGasSponsorshipRequest(form, selectedEnvironmentNetworkClass);
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
      {mutationNotice || mutationError ? (
        <section className="dashboard-view__section" aria-label="Gas sponsorship summary">
          {mutationNotice ? <p className="dashboard-pagination-note">{mutationNotice}</p> : null}
          {mutationError ? <p className="dashboard-pagination-note">{mutationError}</p> : null}
        </section>
      ) : null}

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
              Create a gas sponsorship policy: define chain spend caps and whitelisted contract
              calls.
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

          <section
            className="dashboard-view__section dashboard-view__section--plain"
            aria-label="Gas sponsorship configs"
          >
            <h2>Gas Sponsorship Policies</h2>
            <DashboardTable
              ariaLabel="Gas sponsorship rows"
              className="dashboard-gas-sponsorship-table"
              columns={GAS_SPONSORSHIP_TABLE_COLUMNS}
              pagination={gasConfigsPagination.pagination}
            >
              <DashboardTableHeader className="dashboard-gas-sponsorship-table__header">
                <DashboardTableHeaderCell>Policy</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Scope</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Behavior</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Spend cap</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Contract calls</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Updated</DashboardTableHeaderCell>
                <DashboardTableHeaderCell>Actions</DashboardTableHeaderCell>
              </DashboardTableHeader>
              {gasConfigs.length === 0 ? (
                <DashboardTableState>
                  No gas sponsorship configs found in this scope yet.
                </DashboardTableState>
              ) : (
                gasConfigsPagination.rows.map((config) => (
                  <DashboardTableRow
                    className="dashboard-gas-sponsorship-table__row"
                    key={config.id}
                  >
                    <DashboardTableCell title={config.id}>
                      <strong className="dashboard-data-table__summary">
                        {config.policyName || config.id}
                      </strong>
                    </DashboardTableCell>
                    <DashboardTableCell title={describeScope(config)}>
                      {describeScope(config)}
                    </DashboardTableCell>
                    <DashboardTableCell title={formatRuleSummary(config)}>
                      {formatRuleSummary(config)}
                    </DashboardTableCell>
                    <DashboardTableCell title={formatSpendCapSummary(config)}>
                      {formatSpendCapSummary(config)}
                    </DashboardTableCell>
                    <DashboardTableCell title={formatAllowedCallSummary(config)}>
                      {formatAllowedCallSummary(config)}
                    </DashboardTableCell>
                    <DashboardTableCell truncate>
                      {formatTimestamp(config.updatedAt)}
                    </DashboardTableCell>
                    <DashboardTableCell>
                      <DashboardTableActionGroup>
                        <DashboardTableActionButton
                          onClick={() => onViewConfig(config)}
                          disabled={mutating}
                        >
                          View
                        </DashboardTableActionButton>
                        <DashboardTableActionButton
                          onClick={() => onEditConfig(config)}
                          disabled={mutating}
                        >
                          Edit
                        </DashboardTableActionButton>
                        <DashboardTableActionButton
                          onClick={() => onToggleEnabled(config)}
                          disabled={!canMutateConfig || mutating}
                        >
                          {config.enabled ? 'Disable' : 'Enable'}
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
                  {selectedConfig?.policyName ||
                    selectedConfig?.id ||
                    'Selected sponsorship policy'}
                </p>
                {selectedConfig ? (
                  <>
                    <div className="dashboard-gas-coverage__stats">
                      <div className="dashboard-gas-coverage__stat">
                        <span>Scope</span>
                        <strong className="dashboard-gas-coverage__scope-value">
                          <span>
                            project:{' '}
                            {describeCoverageProjectLabel({
                              projectName: selectedProjectName,
                              projectId: selectedConfig.projectId,
                            })}
                          </span>
                          <span>
                            environment:{' '}
                            {describeCoverageEnvironmentLabel({
                              environmentName: selectedEnvironmentName,
                              environmentKey: selectedEnvironmentKey,
                              environmentId: selectedConfig.environmentId,
                            })}
                          </span>
                        </strong>
                      </div>
                      <div className="dashboard-gas-coverage__stat">
                        <span>Status</span>
                        <strong>{selectedConfig.enabled ? 'Enabled' : 'Disabled'}</strong>
                      </div>
                      <div className="dashboard-gas-coverage__stat">
                        <span>Contract calls</span>
                        <strong>
                          {selectedConfig.callMode === 'ALLOW_ALL'
                            ? 'Allow all'
                            : formatAllowedCallSummary(selectedConfig)}
                        </strong>
                      </div>
                      <div className="dashboard-gas-coverage__stat">
                        <span>Spend cap</span>
                        <strong>{describeSpendCapMode(selectedConfig.spendCap.mode)}</strong>
                      </div>
                    </div>
                    <section className="dashboard-gas-coverage__section">
                      <div className="dashboard-gas-coverage__section-header">
                        <span>Policy behavior</span>
                      </div>
                      <p className="dashboard-pagination-note">
                        {formatRuleSummary(selectedConfig)}
                      </p>
                    </section>
                    <section className="dashboard-gas-coverage__section">
                      <div className="dashboard-gas-coverage__section-header">
                        <span>Contract calls</span>
                      </div>
                      {selectedConfig.callMode === 'ALLOW_ALL' ? (
                        <p className="dashboard-pagination-note dashboard-gas-coverage__empty">
                          All contract calls are sponsored on the selected chains.
                        </p>
                      ) : selectedConfig.allowedCalls.length > 0 ? (
                        <div className="dashboard-gas-coverage__contracts">
                          {groupAllowedCallsByContract(selectedConfig.allowedCalls).map((rule) => (
                            <div key={rule.id} className="dashboard-gas-coverage__contract">
                              <div className="dashboard-gas-coverage__contract-header">
                                <strong>{rule.contractAddress}</strong>
                              </div>
                              <div className="dashboard-gas-coverage__function-list">
                                {rule.functions.map((functionEntry) => (
                                  <span
                                    className="dashboard-gas-coverage__function-chip"
                                    key={`${rule.id}:${functionEntry}`}
                                  >
                                    {functionEntry}
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
                      {selectedConfig.spendCap.capsByChain.length > 0 ? (
                        <div className="dashboard-gas-coverage__function-list">
                          {selectedConfig.spendCap.capsByChain.map((cap) => (
                            <span
                              className="dashboard-gas-coverage__function-chip"
                              key={`${cap.chainId}:${selectedConfig.spendCap.period}`}
                            >
                              {formatSpendCapCoverageEntry({
                                chainId: cap.chainId,
                                capMinor: cap.capMinor,
                                mode: selectedConfig.spendCap.mode,
                                period: selectedConfig.spendCap.period,
                              })}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <p className="dashboard-pagination-note dashboard-gas-coverage__empty">
                          {selectedConfig.spendCap.mode === 'NONE'
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
                  Name the policy, choose its chains, then define the spend caps and contract-call
                  rule.
                </p>
                {mutationError ? (
                  <p className="dashboard-pagination-note">{mutationError}</p>
                ) : null}
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
                          value={form.policyName}
                          onChange={(event) =>
                            setForm((current) => ({ ...current, policyName: event.target.value }))
                          }
                          placeholder="Tempo testnet onboarding"
                          disabled={mutating}
                        />
                      </label>
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
                          disabled={mutating || form.spendCapMode === 'NONE'}
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
                      <div className="dashboard-form-field dashboard-form-field--full">
                        <div className="dashboard-gas-target-matrix">
                          <div className="dashboard-gas-target-matrix__header">
                            <span>Chain</span>
                            <span>{activeChainColumnLabel}</span>
                            <span>Spend cap (minor units)</span>
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
                                        <input
                                          className="dashboard-input"
                                          aria-label={`${target.chainLabel} spend cap`}
                                          value={
                                            form.spendCapMinorByChainName[target.chainName] || ''
                                          }
                                          onChange={(event) =>
                                            setForm((current) => ({
                                              ...current,
                                              spendCapMinorByChainName: {
                                                ...current.spendCapMinorByChainName,
                                                [target.chainName]: event.target.value,
                                              },
                                            }))
                                          }
                                          placeholder={
                                            form.spendCapPeriod === 'WEEKLY'
                                              ? 'Weekly cap'
                                              : 'Monthly cap'
                                          }
                                          disabled={mutating}
                                        />
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
                    </div>
                  </section>

                  <section className="dashboard-policy-rule-panel dashboard-form-field dashboard-form-field--full">
                    <div className="dashboard-policy-rule-panel__header">
                      <span>Contract calls</span>
                      <p className="dashboard-pagination-note">
                        Choose whether sponsorship stays open, or restrict it to an allowlist of
                        contracts and functions.
                      </p>
                    </div>
                    <div className="dashboard-policy-contract-call-mode">
                      <button
                        type="button"
                        aria-pressed={!form.contractCallAllowlistEnabled}
                        className={[
                          'dashboard-policy-segment',
                          !form.contractCallAllowlistEnabled
                            ? 'dashboard-policy-segment--active'
                            : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        onClick={() =>
                          setForm((current) => ({
                            ...current,
                            contractCallAllowlistEnabled: false,
                          }))
                        }
                        disabled={mutating}
                      >
                        Allow All
                      </button>
                      <button
                        type="button"
                        aria-pressed={form.contractCallAllowlistEnabled}
                        className={[
                          'dashboard-policy-segment',
                          form.contractCallAllowlistEnabled
                            ? 'dashboard-policy-segment--active'
                            : '',
                        ]
                          .filter(Boolean)
                          .join(' ')}
                        onClick={() =>
                          setForm((current) => ({
                            ...current,
                            contractCallAllowlistEnabled: true,
                          }))
                        }
                        disabled={mutating}
                      >
                        Allowlist
                      </button>
                    </div>
                    {form.contractCallAllowlistEnabled ? (
                      <div className="dashboard-policy-contract-calls">
                        {form.contractCallRules.length === 0 ? (
                          <p className="dashboard-pagination-note">
                            Add one or more contracts to define the allowlist.
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
                                <div
                                  key={`${rule.id}:${index}`}
                                  className="dashboard-uri-list-editor__row"
                                >
                                  <label className="dashboard-form-field dashboard-uri-list-editor__field">
                                    <span
                                      className={index === 0 ? '' : 'dashboard-visually-hidden'}
                                    >
                                      Allowed functions
                                    </span>
                                    <input
                                      className="dashboard-input"
                                      value={functionEntry}
                                      onChange={(event) =>
                                        updateContractFunction(rule.id, index, event.target.value)
                                      }
                                      placeholder="transfer(address,uint256) or 0xa9059cbb"
                                      disabled={mutating}
                                    />
                                  </label>
                                  <div className="dashboard-uri-list-editor__actions">
                                    <button
                                      type="button"
                                      className="dashboard-pagination-button dashboard-pagination-button--secondary"
                                      onClick={() => removeContractFunction(rule.id, index)}
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
                    ) : (
                      <p className="dashboard-pagination-note">
                        Contract calls are allowed on any contract for the selected chains.
                      </p>
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
        </DashboardInlineModal>
      ) : null}
    </div>
  );
}

export default GasSponsorshipPage;
