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
  sourceEventId: string | null;
};

export type ResolvedSponsoredEvmCallPolicy = {
  policyId: string;
  policyName: string;
  templateId: string | null;
  networkClass: 'ANY' | 'TESTNET' | 'MAINNET';
  executor: 'RELAY_EOA';
  allowedCalls: Array<{
    chainId: number;
    to: string;
    selector: string;
    maxGasLimit: string;
    maxValueWei: string;
  }>;
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

export function extractEvmFunctionSelector(data: `0x${string}`): `0x${string}` | null {
  return data.length >= 10 ? (`0x${data.slice(2, 10).toLowerCase()}` as `0x${string}`) : null;
}

export function createSponsoredEvmSourceEventId(
  nearAccountId: string,
  walletAddress: `0x${string}`,
  chainId: number,
  call: SponsoredEvmCall,
): string {
  return [
    'sponsored_evm_call',
    nearAccountId,
    walletAddress.toLowerCase(),
    String(chainId),
    call.to.toLowerCase(),
    call.data.toLowerCase(),
    call.gasLimit.toString(10),
    call.value.toString(10),
  ].join(':');
}

export function parseResolvedSponsoredEvmCallPolicies(
  snapshot: unknown,
): ResolvedSponsoredEvmCallPolicy[] {
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
    const executor = String(row.executor || '').trim().toUpperCase();
    const networkClass = String(row.networkClass || 'ANY').trim().toUpperCase();
    const allowedCallsRaw = Array.isArray(row.allowedCalls) ? row.allowedCalls : [];
    if (!policyId || executor !== 'RELAY_EOA') continue;
    const allowedCalls = allowedCallsRaw
      .map((call): ResolvedSponsoredEvmCallPolicy['allowedCalls'][number] | null => {
        if (!call || typeof call !== 'object' || Array.isArray(call)) return null;
        const callRow = call as Record<string, unknown>;
        const chainId = parseOptionalPositiveInteger(callRow.chainId);
        const to = normalizeEvmAddress(callRow.to);
        const selector = normalizeEvmSelector(callRow.selector);
        if (!chainId || !to || !selector) return null;
        try {
          return {
            chainId,
            to,
            selector,
            maxGasLimit: parseRequiredUnsignedBigInt(
              callRow.maxGasLimit,
              'allowedCalls[].maxGasLimit',
            ).toString(10),
            maxValueWei: parseRequiredUnsignedBigInt(
              callRow.maxValueWei,
              'allowedCalls[].maxValueWei',
            ).toString(10),
          };
        } catch {
          return null;
        }
      })
      .filter((call): call is ResolvedSponsoredEvmCallPolicy['allowedCalls'][number] => Boolean(call));
    if (allowedCalls.length === 0) continue;
    out.push({
      policyId,
      policyName,
      templateId: String(row.templateId || '').trim() || null,
      networkClass:
        networkClass === 'TESTNET' || networkClass === 'MAINNET' ? (networkClass as any) : 'ANY',
      executor: 'RELAY_EOA',
      allowedCalls,
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
    for (const allowedCall of policy.allowedCalls) {
      if (allowedCall.chainId !== input.chainId) continue;
      if (allowedCall.to.toLowerCase() !== targetAddress) continue;
      if (allowedCall.selector.toLowerCase() !== selector.toLowerCase()) continue;
      if (input.call.gasLimit > BigInt(allowedCall.maxGasLimit)) continue;
      if (input.call.value > BigInt(allowedCall.maxValueWei)) continue;
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
    sourceEventId: String(body.sourceEventId || '').trim() || null,
  };
}
