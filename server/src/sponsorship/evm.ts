export type SponsoredEvmCall = {
  to: `0x${string}`;
  data: `0x${string}`;
  gasLimit: bigint;
  value: bigint;
};

export type SponsoredEvmCallRequest = {
  environmentId: string;
  nearAccountId: string;
  walletAddress: `0x${string}`;
  chainId: number;
  call: SponsoredEvmCall;
  idempotencyKey: string;
};

export type ResolvedSponsoredEvmCallSpendCap = {
  mode: 'NONE' | 'CHAIN_TOTAL' | 'WALLET_CHAIN_TOTAL';
  period: 'WEEKLY' | 'MONTHLY';
  capsByChain: Array<{
    chainId: number;
    capMinor: number;
  }>;
};

export type ResolvedSponsoredEvmCallPolicy = {
  policyId: string;
  policyName: string;
  scopePolicyId: string | null;
  scopePolicyName: string | null;
  templateId: string | null;
  networkClass: 'ANY' | 'TESTNET' | 'MAINNET';
  allowedChainIds: number[];
  callMode: 'ALLOW_ALL' | 'ALLOWLIST';
  allowedCalls: Array<{
    chainId: number;
    to: string;
    selector: string;
  }>;
  spendCap: ResolvedSponsoredEvmCallSpendCap;
  scopeType: 'ENVIRONMENT';
  projectId: string | null;
  environmentId: string | null;
};

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
  const policiesRaw = (gasSponsorship as Record<string, unknown>).sponsoredCallPolicies;
  if (!Array.isArray(policiesRaw)) return [];
  const out: ResolvedSponsoredEvmCallPolicy[] = [];
  for (const entry of policiesRaw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
    const row = entry as Record<string, unknown>;
    const policyId = String(row.policyId || '').trim();
    const policyName = String(row.policyName || '').trim() || policyId;
    const networkClass = String(row.networkClass || 'ANY').trim().toUpperCase();
    const callModeRaw = String(row.callMode || '').trim().toUpperCase();
    const allowedCallsRaw = Array.isArray(row.allowedCalls) ? row.allowedCalls : [];
    if (!policyId) continue;
    const allowedCalls = allowedCallsRaw
      .map((call): ResolvedSponsoredEvmCallPolicy['allowedCalls'][number] | null => {
        if (!call || typeof call !== 'object' || Array.isArray(call)) return null;
        const callRow = call as Record<string, unknown>;
        const chainId = parseOptionalPositiveInteger(callRow.chainId);
        const to = normalizeEvmAddress(callRow.to);
        const selector = normalizeEvmSelector(callRow.selector);
        if (!chainId || !to || !selector) return null;
        return {
          chainId,
          to,
          selector,
        };
      })
      .filter((call): call is ResolvedSponsoredEvmCallPolicy['allowedCalls'][number] => Boolean(call));
    const allowedChainIdsRaw = Array.isArray(row.allowedChainIds) ? row.allowedChainIds : [];
    const allowedChainIds = Array.from(
      new Set(
        allowedChainIdsRaw
          .map((entry) => parseOptionalPositiveInteger(entry))
          .filter((entry): entry is number => Boolean(entry)),
      ),
    );
    if (allowedChainIds.length === 0) {
      for (const allowedCall of allowedCalls) {
        if (!allowedChainIds.includes(allowedCall.chainId)) {
          allowedChainIds.push(allowedCall.chainId);
        }
      }
    }
    const callMode =
      callModeRaw === 'ALLOW_ALL' || callModeRaw === 'ALLOWLIST'
        ? (callModeRaw as 'ALLOW_ALL' | 'ALLOWLIST')
        : allowedCalls.length > 0
          ? 'ALLOWLIST'
          : 'ALLOW_ALL';
    if (allowedChainIds.length === 0) continue;
    if (callMode === 'ALLOWLIST' && allowedCalls.length === 0) continue;
    out.push({
      policyId,
      policyName,
      scopePolicyId: String(row.scopePolicyId || '').trim() || null,
      scopePolicyName: String(row.scopePolicyName || '').trim() || null,
      templateId: String(row.templateId || '').trim() || null,
      networkClass:
        networkClass === 'TESTNET' || networkClass === 'MAINNET'
          ? (networkClass as 'TESTNET' | 'MAINNET')
          : 'ANY',
      allowedChainIds,
      callMode,
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
}): { policy: ResolvedSponsoredEvmCallPolicy; selector: `0x${string}` } | null {
  const selector = extractEvmFunctionSelector(input.call.data);
  if (!selector) return null;
  const targetAddress = input.call.to.toLowerCase();
  for (const policy of input.policies) {
    if (!policy.allowedChainIds.includes(input.chainId)) continue;
    if (policy.callMode === 'ALLOW_ALL') {
      return { policy, selector };
    }
    for (const allowedCall of policy.allowedCalls) {
      if (allowedCall.chainId !== input.chainId) continue;
      if (allowedCall.to.toLowerCase() !== targetAddress) continue;
      if (allowedCall.selector.toLowerCase() !== selector.toLowerCase()) continue;
      return { policy, selector };
    }
  }
  return null;
}

export function parseSponsoredEvmCallRequest(bodyRaw: unknown): SponsoredEvmCallRequest {
  const body =
    bodyRaw && typeof bodyRaw === 'object' && !Array.isArray(bodyRaw)
      ? (bodyRaw as Record<string, unknown>)
      : {};
  const environmentId = String(body.environmentId || '').trim();
  const nearAccountId = String(body.nearAccountId || '').trim();
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
  if (!nearAccountId) {
    throw new Error('Missing nearAccountId');
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
    nearAccountId,
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
