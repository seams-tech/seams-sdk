import {
  createDashboardPolicy,
  deleteDashboardPolicy,
  listDashboardPolicies,
  publishCurrentDashboardRuntimeSnapshot,
  publishDashboardPolicy,
  updateDashboardPolicy,
  type DashboardConsolePolicy,
} from '../policy-engine/consolePoliciesApi';
import { keccak256Bytes } from '@seams-internal/shared-ts/utils/keccak';

export interface DashboardGasSponsorshipAllowedCall {
  chainId: number;
  to: string;
  functionSignature: string;
  selector: string;
  maxGasLimit: string;
  maxValueWei: string;
}

export interface DashboardGasSponsorshipAllowedDelegateAction {
  receiverId: string;
  methods: string[];
  maxDepositYocto: string;
  allowTransfers: boolean;
}

export type DashboardGasSponsorshipExecutionMode = 'evm_eoa' | 'near_delegate';
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

interface DashboardGasSponsorshipPolicyBase {
  id: string;
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
  updatedAt: string;
}

export interface DashboardGasSponsorshipEvmPolicy extends DashboardGasSponsorshipPolicyBase {
  kind: 'evm_call';
  executionMode: 'evm_eoa';
  allowedCalls: DashboardGasSponsorshipAllowedCall[];
}

export interface DashboardGasSponsorshipNearPolicy extends DashboardGasSponsorshipPolicyBase {
  kind: 'near_delegate';
  executionMode: 'near_delegate';
  allowedDelegateActions: DashboardGasSponsorshipAllowedDelegateAction[];
}

export type DashboardGasSponsorshipPolicy =
  | DashboardGasSponsorshipEvmPolicy
  | DashboardGasSponsorshipNearPolicy;

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

function decodeAllowedDelegateActions(raw: unknown): DashboardGasSponsorshipAllowedDelegateAction[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
      const row = entry as Record<string, unknown>;
      const receiverId = normalizeString(row.receiverId);
      const methods = Array.isArray(row.methods)
        ? Array.from(
            new Set(
              row.methods
                .map((value) => normalizeString(value))
                .filter(Boolean)
                .map((value) => value.toLowerCase()),
            ),
          )
        : [];
      const maxDepositYocto = normalizeString(row.maxDepositYocto) || '0';
      const allowTransfers = row.allowTransfers === true;
      if (!receiverId || !maxDepositYocto) return null;
      return {
        receiverId,
        methods,
        maxDepositYocto,
        allowTransfers,
      };
    })
    .filter((entry): entry is DashboardGasSponsorshipAllowedDelegateAction => entry !== null);
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
  const scopePolicyId = normalizeString(rules.scopePolicyId) || null;
  const common = {
    id: policy.id,
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
    spendCap: decodeSpendCap(rules.spendCap),
    updatedAt: normalizeString(policy.updatedAt),
  };
  if (normalizeString(rules.kind).toLowerCase() === 'near_delegate') {
    return {
      ...common,
      kind: 'near_delegate',
      executionMode: 'near_delegate',
      allowedDelegateActions: decodeAllowedDelegateActions(rules.allowedDelegateActions),
    };
  }
  return {
    ...common,
    kind: 'evm_call',
    executionMode: 'evm_eoa',
    allowedCalls: decodeAllowedCalls(rules.allowedCalls),
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
  await republishRuntimeSnapshotForScope(input);
  return await getDashboardGasSponsorshipPolicyById(published.id);
}

/**
 * A published gas-sponsorship policy only reaches the relayer via the
 * environment's runtime snapshot, which policy publication does not refresh.
 * Republish it so the new/updated policy takes effect immediately. The snapshot
 * is per-environment, so this only runs for environment-scoped mutations.
 */
async function republishRuntimeSnapshotForScope(input: Record<string, unknown>): Promise<void> {
  const environmentId = normalizeString((input as { environmentId?: unknown }).environmentId);
  if (!environmentId) return;
  const projectId = normalizeString((input as { projectId?: unknown }).projectId);
  await publishCurrentDashboardRuntimeSnapshot({
    environmentId,
    ...(projectId ? { projectId } : {}),
  });
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
  await republishRuntimeSnapshotForScope(input);
  return await getDashboardGasSponsorshipPolicyById(published.id);
}

/**
 * Enables/disables a policy by flipping only the `enabled` flag while preserving
 * every other rule. A naive `updateDashboardGasSponsorshipPolicy(id, { enabled })`
 * would replace the whole rules object with `{ enabled }`, wiping the policy's
 * kind/scope/allowed actions so it decodes as invalid and vanishes from the list.
 */
export async function setDashboardGasSponsorshipPolicyEnabled(
  policyIdRaw: string,
  enabled: boolean,
): Promise<DashboardGasSponsorshipPolicy> {
  const policyId = normalizeString(policyIdRaw);
  if (!policyId) throw new Error('Gas sponsorship policy id is required');
  const existing = (await listDashboardPolicies()).find((entry) => entry.id === policyId);
  if (!existing) throw new Error(`Gas sponsorship policy ${policyId} was not found`);
  const rules = { ...readObject(existing.rules), enabled };
  const updated = await updateDashboardPolicy({ policyId, rules });
  const published = await publishDashboardPolicy({ policyId: updated.id });
  await republishRuntimeSnapshotForScope(rules);
  return await getDashboardGasSponsorshipPolicyById(published.id);
}

/**
 * Deletes a gas-sponsorship policy and republishes the environment runtime
 * snapshot so the relayer stops honoring it immediately.
 */
export async function deleteDashboardGasSponsorshipPolicy(policyIdRaw: string): Promise<void> {
  const policyId = normalizeString(policyIdRaw);
  if (!policyId) throw new Error('Gas sponsorship policy id is required');
  const existing = (await listDashboardPolicies()).find((entry) => entry.id === policyId);
  await deleteDashboardPolicy({ policyId });
  if (existing) {
    // Snapshot is resolved from the remaining policies, so this drops the
    // deleted policy from what the relayer sees.
    await republishRuntimeSnapshotForScope(readObject(existing.rules));
  }
}
