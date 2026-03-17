import {
  createDashboardPolicy,
  listDashboardPolicies,
  publishDashboardPolicy,
  updateDashboardPolicy,
  type DashboardConsolePolicy,
} from '../policy-engine/consolePoliciesApi';
import { keccak256Bytes } from '../../../../../../../shared/src/utils/keccak';

export interface DashboardGasSponsorshipAllowedCall {
  chainId: number;
  to: string;
  functionSignature: string;
  selector: string;
  maxGasLimit: string;
  maxValueWei: string;
}

export type DashboardGasSponsorshipExecutionMode = 'evm_eoa';
export type DashboardGasSponsorshipSpendCapMode = 'NONE' | 'CHAIN_TOTAL' | 'WALLET_CHAIN_TOTAL';
export type DashboardGasSponsorshipSpendCapPeriod = 'WEEKLY' | 'MONTHLY';

export interface DashboardGasSponsorshipSpendCap {
  mode: DashboardGasSponsorshipSpendCapMode;
  period: DashboardGasSponsorshipSpendCapPeriod;
  capsByChain: Array<{
    chainId: number;
    capMinor: number;
  }>;
}

export interface DashboardGasSponsorshipPolicy {
  id: string;
  kind: 'evm_call';
  scopeType: string;
  projectId: string | null;
  environmentId: string | null;
  scopePolicyId: string | null;
  scopePolicyName: string | null;
  walletSegmentId: string | null;
  name: string;
  templateId: string | null;
  networkClass: string;
  enabled: boolean;
  executionMode: DashboardGasSponsorshipExecutionMode;
  spendCap: DashboardGasSponsorshipSpendCap;
  allowedCalls: DashboardGasSponsorshipAllowedCall[];
  updatedAt: string;
}

function normalizeString(value: unknown): string {
  return String(value || '').trim();
}

function bytesToHex(bytes: Uint8Array): `0x${string}` {
  return `0x${Array.from(bytes)
    .map((entry) => entry.toString(16).padStart(2, '0'))
    .join('')}` as `0x${string}`;
}

function deriveFunctionSelector(functionSignature: string): string {
  const digest = keccak256Bytes(new TextEncoder().encode(functionSignature));
  return bytesToHex(digest.slice(0, 4)).toLowerCase();
}

function readObject(raw: unknown): Record<string, unknown> {
  return raw && typeof raw === 'object' && !Array.isArray(raw)
    ? (raw as Record<string, unknown>)
    : {};
}

function decodeAllowedCalls(raw: unknown): DashboardGasSponsorshipAllowedCall[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
      const row = entry as Record<string, unknown>;
      const to = normalizeString(row.to);
      const functionSignature = normalizeString(row.functionSignature);
      const selector =
        normalizeString(row.selector) || (functionSignature ? deriveFunctionSelector(functionSignature) : '');
      const maxGasLimit = normalizeString(row.maxGasLimit);
      const maxValueWei = normalizeString(row.maxValueWei) || '0';
      const chainId = Number(row.chainId || 0);
      if (
        !to ||
        !selector ||
        !functionSignature ||
        !maxGasLimit ||
        !Number.isFinite(chainId) ||
        chainId <= 0
      ) {
        return null;
      }
      return {
        chainId,
        to,
        functionSignature,
        selector,
        maxGasLimit,
        maxValueWei,
      };
    })
    .filter((entry): entry is DashboardGasSponsorshipAllowedCall => entry !== null);
}

function decodeSpendCap(raw: unknown): DashboardGasSponsorshipSpendCap {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return {
      mode: 'NONE',
      period: 'MONTHLY',
      capsByChain: [],
    };
  }
  const row = raw as Record<string, unknown>;
  const modeRaw = normalizeString(row.mode).toUpperCase();
  const periodRaw = normalizeString(row.period).toUpperCase();
  const capsByChainRaw = Array.isArray(row.capsByChain) ? row.capsByChain : [];
  const mode =
    modeRaw === 'CHAIN_TOTAL' || modeRaw === 'WALLET_CHAIN_TOTAL'
      ? (modeRaw as DashboardGasSponsorshipSpendCapMode)
      : 'NONE';
  return {
    mode,
    period: periodRaw === 'WEEKLY' ? 'WEEKLY' : 'MONTHLY',
    capsByChain:
      mode === 'NONE'
        ? []
        : Array.from(
            new Map(
              capsByChainRaw
                .map((entry) => {
                  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
                  const cap = entry as Record<string, unknown>;
                  const chainId = Number(cap.chainId || 0);
                  const capMinor = Number(cap.capMinor || 0);
                  if (!Number.isFinite(chainId) || chainId <= 0) return null;
                  if (!Number.isFinite(capMinor) || capMinor < 0) return null;
                  return [
                    Math.floor(chainId),
                    {
                      chainId: Math.floor(chainId),
                      capMinor: Math.floor(capMinor),
                    },
                  ] as const;
                })
                .filter(
                  (
                    entry,
                  ): entry is readonly [
                    number,
                    DashboardGasSponsorshipSpendCap['capsByChain'][number],
                  ] => entry !== null,
                ),
            ).values(),
          ),
  };
}

function decodeGasSponsorshipPolicy(
  policy: DashboardConsolePolicy,
  policyNamesById: ReadonlyMap<string, string>,
): DashboardGasSponsorshipPolicy | null {
  if (policy.kind !== 'GAS_SPONSORSHIP') return null;
  const rules = readObject(policy.rules);
  if (normalizeString(rules.kind).toLowerCase() === 'near_delegate') return null;
  const allowedCalls = decodeAllowedCalls(rules.allowedCalls);
  const scopePolicyId = normalizeString(rules.scopePolicyId) || null;
  return {
    id: policy.id,
    kind: 'evm_call',
    scopeType: normalizeString(rules.scopeType) || 'ENVIRONMENT',
    projectId: normalizeString(rules.projectId) || null,
    environmentId: normalizeString(rules.environmentId) || null,
    scopePolicyId,
    scopePolicyName: scopePolicyId ? policyNamesById.get(scopePolicyId) || null : null,
    walletSegmentId: normalizeString(rules.walletSegmentId) || null,
    name: normalizeString(policy.name) || 'Gas Sponsorship Policy',
    templateId: normalizeString(rules.templateId) || null,
    networkClass: normalizeString(rules.networkClass) || 'ANY',
    enabled: rules.enabled !== false,
    executionMode: 'evm_eoa',
    spendCap: decodeSpendCap(rules.spendCap),
    allowedCalls,
    updatedAt: normalizeString(policy.updatedAt),
  };
}

function matchesScopeFilter(
  policy: DashboardGasSponsorshipPolicy,
  input: { environmentId?: string; projectId?: string },
): boolean {
  if (input.environmentId && policy.environmentId !== input.environmentId) return false;
  if (input.projectId && policy.projectId !== input.projectId) return false;
  return true;
}

function splitGasPolicyMutationInput(input: Record<string, unknown>): {
  name: string;
  rules: Record<string, unknown>;
} {
  const name = normalizeString(input.name) || 'Gas Sponsorship Policy';
  const rules: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(input)) {
    if (key === 'name') continue;
    rules[key] = value;
  }
  return { name, rules };
}

async function getDashboardGasSponsorshipPolicyById(
  policyId: string,
): Promise<DashboardGasSponsorshipPolicy> {
  const policies = await listDashboardPolicies();
  const policyNamesById = new Map(
    policies.map((entry) => [entry.id, normalizeString(entry.name) || entry.id]),
  );
  const policy = policies.find((entry) => entry.id === policyId) || null;
  const gasPolicy = policy ? decodeGasSponsorshipPolicy(policy, policyNamesById) : null;
  if (!gasPolicy) {
    throw new Error(`Gas sponsorship policy ${policyId} was not found after publish`);
  }
  return gasPolicy;
}

export async function listDashboardGasSponsorshipPolicies(input: {
  environmentId?: string;
  projectId?: string;
} = {}): Promise<DashboardGasSponsorshipPolicy[]> {
  const policies = await listDashboardPolicies();
  const policyNamesById = new Map(
    policies.map((entry) => [entry.id, normalizeString(entry.name) || entry.id]),
  );
  return policies
    .map((entry) => decodeGasSponsorshipPolicy(entry, policyNamesById))
    .filter((entry): entry is DashboardGasSponsorshipPolicy => entry !== null)
    .filter((entry) => matchesScopeFilter(entry, input));
}

export async function createDashboardGasSponsorshipPolicy(
  input: Record<string, unknown>,
): Promise<DashboardGasSponsorshipPolicy> {
  const { name, rules } = splitGasPolicyMutationInput(input);
  const created = await createDashboardPolicy({
    kind: 'GAS_SPONSORSHIP',
    name,
    rules,
  });
  const published = await publishDashboardPolicy({ policyId: created.id });
  return await getDashboardGasSponsorshipPolicyById(published.id);
}

export async function updateDashboardGasSponsorshipPolicy(
  policyIdRaw: string,
  input: Record<string, unknown>,
): Promise<DashboardGasSponsorshipPolicy> {
  const policyId = normalizeString(policyIdRaw);
  if (!policyId) throw new Error('Gas sponsorship policy id is required');
  const { name, rules } = splitGasPolicyMutationInput(input);
  const updated = await updateDashboardPolicy({
    policyId,
    ...(Object.prototype.hasOwnProperty.call(input, 'name') ? { name } : {}),
    rules,
  });
  const published = await publishDashboardPolicy({ policyId: updated.id });
  return await getDashboardGasSponsorshipPolicyById(published.id);
}
