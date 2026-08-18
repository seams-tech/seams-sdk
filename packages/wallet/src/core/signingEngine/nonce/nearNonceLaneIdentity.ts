import type { SeamsChainConfig } from '@/core/types/seams';
import { toAccountId } from '@/core/types/accountIds';
import type { NearNonceLane } from './nonceTypes';

function requiredNearNonceLaneString(value: string, field: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error(`[NonceCoordinator][near] ${field} is required`);
  }
  return normalized;
}

export function resolveNearNonceNetworkKey(chains?: readonly SeamsChainConfig[]): string {
  const nearChain = chains?.find((chain) => String(chain.network || '').startsWith('near-'));
  return String(nearChain?.network || 'near');
}

export function buildNearNonceLane(args: {
  chains?: readonly SeamsChainConfig[];
  walletId: string;
  nearAccountId: string;
  nearPublicKeyStr: string;
}): NearNonceLane {
  return {
    family: 'near',
    networkKey: resolveNearNonceNetworkKey(args.chains),
    walletId: requiredNearNonceLaneString(args.walletId, 'walletId'),
    nearAccountId: toAccountId(args.nearAccountId),
    publicKey: requiredNearNonceLaneString(args.nearPublicKeyStr, 'nearPublicKeyStr'),
  };
}
