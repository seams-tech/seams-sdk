import type { GetRecentUnlocksResult } from '@/core/types/seams';
import { WALLET_AUTH_METHODS } from '@shared/utils';
import type { AuthMenuAccountOption } from '../lit-ui/auth-menu/auth-menu-domain';

export function loginAccountOptions(
  recentUnlocks: GetRecentUnlocksResult | null,
  localPasskeyWalletIds: readonly string[] = [],
): AuthMenuAccountOption[] {
  const byWalletId = new Map<string, AuthMenuAccountOption>();
  for (const walletIdValue of localPasskeyWalletIds) {
    const walletId = String(walletIdValue || '').trim();
    if (walletId) byWalletId.set(walletId, { walletId, displayName: walletId });
  }
  for (const account of recentUnlocks?.accounts ?? []) {
    if (
      account.authMethod !== WALLET_AUTH_METHODS.passkey &&
      account.authMethod !== 'linked_device'
    )
      continue;
    const walletId = String(account.walletId || '').trim();
    if (!walletId) continue;
    const displayName = String(account.displayName || walletId).trim() || walletId;
    byWalletId.set(walletId, { walletId, displayName });
  }
  return [...byWalletId.values()];
}

export function defaultLoginWalletId(
  recentUnlocks: GetRecentUnlocksResult | null,
  options: readonly AuthMenuAccountOption[],
): string | null {
  const lastUsedWalletId = String(recentUnlocks?.lastUsedAccount?.walletId || '').trim();
  if (lastUsedWalletId && options.some((option) => option.walletId === lastUsedWalletId)) {
    return lastUsedWalletId;
  }
  return options[0]?.walletId || null;
}

export function passkeyRecentWalletId(recentUnlocks: GetRecentUnlocksResult | null): string | null {
  const account = recentUnlocks?.lastUsedAccount;
  if (
    !account ||
    (account.authMethod !== WALLET_AUTH_METHODS.passkey && account.authMethod !== 'linked_device')
  )
    return null;
  const walletId = String(account.walletId || '').trim();
  return walletId || null;
}
