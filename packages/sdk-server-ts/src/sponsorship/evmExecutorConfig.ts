import {
  normalizeHex32,
  parseOptionalPositiveInteger,
} from './evm';
import type { SponsoredEvmCallExecutorConfig, SponsoredEvmChainExecutorConfig } from './evmExecutorTypes';

export const DEFAULT_SPONSORED_EVM_RPC_URL = 'https://rpc.moderato.tempo.xyz';
export const DEFAULT_SPONSORED_EVM_CHAIN_ID = 42_431;
export const DEFAULT_MAX_PRIORITY_FEE_PER_GAS = 2_000_000_000n;
export const DEFAULT_MAX_FEE_PER_GAS = 40_000_000_000n;

export type SponsoredEvmExecutorConfigEnv = {
  readonly SPONSORED_EVM_EXECUTORS_JSON?: unknown;
};

export type SponsoredEvmSponsorAddressDeriver = (
  privateKeyHex: `0x${string}`,
) => Promise<`0x${string}`>;

function normalizeSponsoredEvmExecutorKind(value: unknown): 'evm_eoa' | null {
  const normalized = String(value || '').trim();
  if (!normalized) return 'evm_eoa';
  return normalized === 'evm_eoa' ? 'evm_eoa' : null;
}

function parseOptionalUnsignedBigIntLiteral(value: unknown): bigint | null {
  if (value === undefined || value === null) return null;
  const normalized = String(value).trim();
  if (!normalized) return null;
  try {
    const parsed = BigInt(normalized);
    return parsed >= 0n ? parsed : null;
  } catch {
    return null;
  }
}

function parseSponsoredEvmExecutorsJson(value: unknown): Record<string, unknown> | null {
  const raw = String(value || '').trim();
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
  return parsed as Record<string, unknown>;
}

async function parseSponsoredEvmExecutorRow(input: {
  readonly chainIdRaw: string;
  readonly value: unknown;
  readonly deriveSponsorAddress: SponsoredEvmSponsorAddressDeriver;
}): Promise<SponsoredEvmChainExecutorConfig | null> {
  if (!input.value || typeof input.value !== 'object' || Array.isArray(input.value)) return null;
  const row = input.value as Record<string, unknown>;
  const kind = normalizeSponsoredEvmExecutorKind(row.kind);
  const chainId =
    parseOptionalPositiveInteger(input.chainIdRaw) ||
    parseOptionalPositiveInteger(row.chainId) ||
    undefined;
  const sponsorPrivateKeyHex = normalizeHex32(row.sponsorPrivateKeyHex);
  if (!kind || !chainId || !sponsorPrivateKeyHex) return null;
  const maxPriorityFeePerGasFloor = parseOptionalUnsignedBigIntLiteral(
    row.maxPriorityFeePerGasFloor,
  );
  if (row.maxPriorityFeePerGasFloor !== undefined && maxPriorityFeePerGasFloor === null) {
    return null;
  }
  const maxFeePerGasFloor = parseOptionalUnsignedBigIntLiteral(row.maxFeePerGasFloor);
  if (row.maxFeePerGasFloor !== undefined && maxFeePerGasFloor === null) return null;
  let sponsorAddress: `0x${string}`;
  try {
    sponsorAddress = await input.deriveSponsorAddress(sponsorPrivateKeyHex);
  } catch {
    return null;
  }
  return {
    chainId,
    rpcUrl:
      String(row.rpcUrl || '').trim() ||
      (chainId === DEFAULT_SPONSORED_EVM_CHAIN_ID ? DEFAULT_SPONSORED_EVM_RPC_URL : ''),
    sponsorAddress,
    sponsorPrivateKeyHex,
    maxPriorityFeePerGasFloor:
      maxPriorityFeePerGasFloor ?? DEFAULT_MAX_PRIORITY_FEE_PER_GAS,
    maxFeePerGasFloor: maxFeePerGasFloor ?? DEFAULT_MAX_FEE_PER_GAS,
  };
}

export async function resolveSponsoredEvmCallConfigFromRecord(input: {
  readonly env: SponsoredEvmExecutorConfigEnv;
  readonly deriveSponsorAddress: SponsoredEvmSponsorAddressDeriver;
}): Promise<SponsoredEvmCallExecutorConfig | null> {
  const parsed = parseSponsoredEvmExecutorsJson(input.env.SPONSORED_EVM_EXECUTORS_JSON);
  if (!parsed) return null;

  const executors = new Map<number, SponsoredEvmChainExecutorConfig>();
  for (const [chainIdRaw, value] of Object.entries(parsed)) {
    const executor = await parseSponsoredEvmExecutorRow({
      chainIdRaw,
      value,
      deriveSponsorAddress: input.deriveSponsorAddress,
    });
    if (!executor) continue;
    if (executors.has(executor.chainId)) return null;
    executors.set(executor.chainId, executor);
  }

  if (executors.size === 0) return null;
  for (const executor of executors.values()) {
    if (!executor.rpcUrl) return null;
  }
  return {
    executorsByChain: executors,
  };
}
