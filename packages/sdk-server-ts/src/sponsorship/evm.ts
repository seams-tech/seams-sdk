import type { ResolvedGasSponsorshipEvmPolicy } from '../console/gasSponsorship/types';
import { deriveConsolePolicyFunctionSelector } from '../console/policies/rules';

export type SponsoredEvmCall = {
  to: `0x${string}`;
  data: `0x${string}`;
  gasLimit: bigint;
  value: bigint;
};

export type SponsoredEvmCallRequest = {
  environmentId: string;
  walletId: string;
  walletAddress: `0x${string}`;
  chainId: number;
  call: SponsoredEvmCall;
  idempotencyKey: string;
};

export type ResolvedSponsoredEvmCallPolicy = ResolvedGasSponsorshipEvmPolicy;
export type ResolvedSponsoredEvmCallSpendCap = ResolvedSponsoredEvmCallPolicy['spendCap'];

export type SponsoredEvmPolicyMismatchCode =
  | 'policy_not_matched'
  | 'selector_mismatch'
  | 'gas_limit_exceeded'
  | 'value_exceeded';

export type SponsoredEvmPolicyMismatch = {
  ok: false;
  code: SponsoredEvmPolicyMismatchCode;
  selector: `0x${string}` | null;
  details?: Record<string, unknown>;
};

export type SponsoredEvmPolicyMatch = {
  ok: true;
  policy: ResolvedSponsoredEvmCallPolicy;
  selector: `0x${string}`;
  allowedCall: ResolvedSponsoredEvmCallPolicy['allowedCalls'][number];
};

export type SponsoredEvmPolicyMatchResult = SponsoredEvmPolicyMatch | SponsoredEvmPolicyMismatch;

export function normalizeEvmAddress(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]{40}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

export function normalizeHex32(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim();
  return /^0x[0-9a-fA-F]{64}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

export function normalizeHexData(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim();
  return /^0x(?:[0-9a-fA-F]{2})*$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

export function normalizeEvmSelector(value: unknown): `0x${string}` | null {
  const normalized = String(value || '').trim().toLowerCase();
  return /^0x[0-9a-f]{8}$/.test(normalized) ? (normalized as `0x${string}`) : null;
}

export function parseOptionalPositiveInteger(value: unknown): number | undefined {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return undefined;
  const integer = Math.floor(parsed);
  return integer > 0 ? integer : undefined;
}

export function parseBigIntWithFallback(value: unknown, fallback: bigint): bigint {
  const normalized = String(value || '').trim();
  if (!normalized) return fallback;
  try {
    const parsed = BigInt(normalized);
    return parsed >= 0n ? parsed : fallback;
  } catch {
    return fallback;
  }
}

export function parseRequiredUnsignedBigInt(value: unknown, field: string): bigint {
  try {
    const parsed = BigInt(String(value || '').trim());
    if (parsed < 0n) {
      throw new Error('negative');
    }
    return parsed;
  } catch {
    throw new Error(`Invalid ${field}`);
  }
}

function parseResolvedSponsoredEvmCallSpendCap(raw: unknown): ResolvedSponsoredEvmCallSpendCap {
  const row =
    raw && typeof raw === 'object' && !Array.isArray(raw)
      ? (raw as Record<string, unknown>)
      : {};
  const modeRaw = String(row.mode || '')
    .trim()
    .toUpperCase();
  const periodRaw = String(row.period || '')
    .trim()
    .toUpperCase();
  const mode =
    modeRaw === 'CHAIN_TOTAL' || modeRaw === 'WALLET_CHAIN_TOTAL'
      ? (modeRaw as ResolvedSponsoredEvmCallSpendCap['mode'])
      : 'NONE';
  const period = periodRaw === 'WEEKLY' ? 'WEEKLY' : 'MONTHLY';
  const capsByChainRaw = Array.isArray(row.capsByChain) ? row.capsByChain : [];
  const capsByChain = Array.from(
    new Map(
      capsByChainRaw
        .map((entry) => {
          if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
          const capRow = entry as Record<string, unknown>;
          const chainId = parseOptionalPositiveInteger(capRow.chainId);
          const capMinorRaw = Number(capRow.capMinor);
          const capMinor =
            Number.isFinite(capMinorRaw) && capMinorRaw >= 0 ? Math.floor(capMinorRaw) : undefined;
          if (!chainId || capMinor === undefined) return null;
          return [chainId, { chainId, capMinor }] as const;
        })
        .filter(
          (
            entry,
          ): entry is readonly [number, ResolvedSponsoredEvmCallSpendCap['capsByChain'][number]] =>
            Boolean(entry),
        ),
    ).values(),
  );
  return {
    mode,
    period,
    capsByChain: mode === 'NONE' ? [] : capsByChain,
  };
}

export function extractEvmFunctionSelector(data: `0x${string}`): `0x${string}` | null {
  return data.length >= 10 ? (`0x${data.slice(2, 10).toLowerCase()}` as `0x${string}`) : null;
}

export function parseResolvedSponsoredEvmCallPolicies(snapshot: unknown): ResolvedSponsoredEvmCallPolicy[] {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) return [];
  const payload = snapshot as Record<string, unknown>;
  const gasSponsorship = payload.gasSponsorship;
  if (!gasSponsorship || typeof gasSponsorship !== 'object' || Array.isArray(gasSponsorship)) {
    return [];
  }
  const policiesRaw = (gasSponsorship as Record<string, unknown>).resolvedPolicies;
  if (!Array.isArray(policiesRaw)) return [];
  const out: ResolvedSponsoredEvmCallPolicy[] = [];
  for (const entry of policiesRaw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const row = entry as Record<string, unknown>;
    if (String(row.kind || '').trim().toLowerCase() !== 'evm_call') continue;
    const policyId = String(row.policyId || '').trim();
    const policyName = String(row.policyName || '').trim() || policyId;
    const networkClass = String(row.networkClass || 'ANY').trim().toUpperCase();
    const allowedCallsRaw = Array.isArray(row.allowedCalls) ? row.allowedCalls : [];
    if (!policyId) continue;
    const allowedCalls = allowedCallsRaw
      .map((call): ResolvedSponsoredEvmCallPolicy['allowedCalls'][number] | null => {
        if (!call || typeof call !== 'object' || Array.isArray(call)) return null;
        const callRow = call as Record<string, unknown>;
        const chainId = parseOptionalPositiveInteger(callRow.chainId);
        const to = normalizeEvmAddress(callRow.to);
        const functionSignature = String(callRow.functionSignature || '').trim();
        const maxGasLimit = String(callRow.maxGasLimit || '').trim();
        const maxValueWei = String(callRow.maxValueWei || '').trim();
        if (!chainId || !to || !functionSignature || !maxGasLimit || !maxValueWei) {
          return null;
        }
        const selector = deriveConsolePolicyFunctionSelector(functionSignature);
        return {
          chainId,
          to,
          functionSignature,
          selector,
          maxGasLimit,
          maxValueWei,
        };
      })
      .filter((call): call is ResolvedSponsoredEvmCallPolicy['allowedCalls'][number] => Boolean(call));
    const allowedChainIds = Array.from(new Set(allowedCalls.map((call) => call.chainId)));
    if (allowedCalls.length === 0 || allowedChainIds.length === 0) continue;
    out.push({
      kind: 'evm_call',
      policyId,
      policyName,
      scopePolicyId: String(row.scopePolicyId || '').trim() || null,
      scopePolicyName: String(row.scopePolicyName || '').trim() || null,
      templateId: String(row.templateId || '').trim() || null,
      networkClass:
        networkClass === 'TESTNET' || networkClass === 'MAINNET'
          ? (networkClass as 'TESTNET' | 'MAINNET')
          : 'ANY',
      executionMode: 'evm_eoa',
      allowedChainIds,
      allowedCalls,
      spendCap: parseResolvedSponsoredEvmCallSpendCap(row.spendCap),
      scopeType: 'ENVIRONMENT',
      projectId: String(row.projectId || '').trim() || null,
      environmentId: String(row.environmentId || '').trim() || null,
    });
  }
  return out;
}

export function matchResolvedSponsoredEvmCallPolicy(input: {
  policies: readonly ResolvedSponsoredEvmCallPolicy[];
  chainId: number;
  call: SponsoredEvmCall;
}): SponsoredEvmPolicyMatchResult {
  const selector = extractEvmFunctionSelector(input.call.data);
  if (!selector) {
    return {
      ok: false,
      code: 'policy_not_matched',
      selector: null,
    };
  }
  const targetAddress = input.call.to.toLowerCase();
  let sawSelectorMismatch = false;
  let gasLimitExceeded: {
    policyId: string;
    templateId: string | null;
    maxGasLimit: string;
  } | null = null;
  let valueExceeded: {
    policyId: string;
    templateId: string | null;
    maxValueWei: string;
  } | null = null;
  for (const policy of input.policies) {
    if (!policy.allowedChainIds.includes(input.chainId)) continue;
    for (const allowedCall of policy.allowedCalls) {
      if (allowedCall.chainId !== input.chainId) continue;
      if (allowedCall.to.toLowerCase() !== targetAddress) continue;
      if (allowedCall.selector.toLowerCase() !== selector.toLowerCase()) {
        sawSelectorMismatch = true;
        continue;
      }
      if (input.call.gasLimit > BigInt(allowedCall.maxGasLimit)) {
        gasLimitExceeded = {
          policyId: policy.policyId,
          templateId: policy.templateId,
          maxGasLimit: allowedCall.maxGasLimit,
        };
        continue;
      }
      if (input.call.value > BigInt(allowedCall.maxValueWei)) {
        valueExceeded = {
          policyId: policy.policyId,
          templateId: policy.templateId,
          maxValueWei: allowedCall.maxValueWei,
        };
        continue;
      }
      return { ok: true, policy, selector, allowedCall };
    }
  }
  if (gasLimitExceeded) {
    return {
      ok: false,
      code: 'gas_limit_exceeded',
      selector,
      details: {
        policyId: gasLimitExceeded.policyId,
        templateId: gasLimitExceeded.templateId,
        actualGasLimit: input.call.gasLimit.toString(10),
        maxGasLimit: gasLimitExceeded.maxGasLimit,
      },
    };
  }
  if (valueExceeded) {
    return {
      ok: false,
      code: 'value_exceeded',
      selector,
      details: {
        policyId: valueExceeded.policyId,
        templateId: valueExceeded.templateId,
        actualValueWei: input.call.value.toString(10),
        maxValueWei: valueExceeded.maxValueWei,
      },
    };
  }
  if (sawSelectorMismatch) {
    return {
      ok: false,
      code: 'selector_mismatch',
      selector,
      details: {
        actualSelector: selector,
      },
    };
  }
  return {
    ok: false,
    code: 'policy_not_matched',
    selector,
  };
}

export function parseSponsoredEvmCallRequest(bodyRaw: unknown): SponsoredEvmCallRequest {
  const body =
    bodyRaw && typeof bodyRaw === 'object' && !Array.isArray(bodyRaw)
      ? (bodyRaw as Record<string, unknown>)
      : {};
  const environmentId = String(body.environmentId || '').trim();
  const walletId = String(body.walletId || body.nearAccountId || '').trim();
  const walletAddress = normalizeEvmAddress(body.walletAddress);
  const chainId = parseOptionalPositiveInteger(body.chainId);
  const callRaw =
    body.call && typeof body.call === 'object' && !Array.isArray(body.call)
      ? (body.call as Record<string, unknown>)
      : null;
  const to = normalizeEvmAddress(callRaw?.to);
  const data = normalizeHexData(callRaw?.data);
  const gasLimit = callRaw ? parseRequiredUnsignedBigInt(callRaw.gasLimit, 'call.gasLimit') : null;
  const value = callRaw ? parseRequiredUnsignedBigInt(callRaw.value ?? '0', 'call.value') : null;
  const idempotencyKey = String(body.idempotencyKey || '').trim();
  if (!environmentId) {
    throw new Error('Missing environmentId');
  }
  if (!walletId) {
    throw new Error('Missing walletId');
  }
  if (!walletAddress) {
    throw new Error('Missing or invalid walletAddress');
  }
  if (!chainId) {
    throw new Error('Missing or invalid chainId');
  }
  if (!to || !data || gasLimit === null || value === null) {
    throw new Error('Missing or invalid call');
  }
  if (!idempotencyKey) {
    throw new Error('Field idempotencyKey is required');
  }
  const selector = extractEvmFunctionSelector(data);
  if (!selector) {
    throw new Error('call.data must include a 4-byte selector');
  }
  return {
    environmentId,
    walletId,
    walletAddress,
    chainId,
    call: {
      to,
      data,
      gasLimit,
      value,
    },
    idempotencyKey,
  };
}
