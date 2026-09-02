import type { AccountId } from '../../types/accountIds';
import type { AccountRef, UserPreferences } from '../../indexedDB/passkeyClientDB.types';

export function inferNearChainIdKey(
  nearAccountId: AccountId,
  networkHint?: UserPreferences['useNetwork'],
): string {
  if (networkHint === 'mainnet') return 'near:mainnet';
  if (networkHint === 'testnet') return 'near:testnet';
  return String(nearAccountId).endsWith('.testnet') ? 'near:testnet' : 'near:mainnet';
}

export function getNearChainCandidates(accountId: AccountId): string[] {
  const preferred = inferNearChainIdKey(accountId);
  return preferred === 'near:testnet'
    ? ['near:testnet', 'near:mainnet']
    : ['near:mainnet', 'near:testnet'];
}

export function buildNearAccountRefs(nearAccountId: AccountId): AccountRef[] {
  const accountAddress = String(nearAccountId || '').trim().toLowerCase();
  if (!accountAddress) return [];
  return getNearChainCandidates(accountAddress as AccountId).map((chainIdKey) => ({
    chainIdKey,
    accountAddress,
  }));
}
