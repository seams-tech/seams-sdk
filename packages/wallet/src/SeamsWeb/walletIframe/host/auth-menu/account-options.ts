import type { GetRecentUnlocksResult } from '@/core/types/seams';
import { WALLET_AUTH_METHODS } from '@shared/utils';
import type { AuthMenuAccountOption } from '../lit-ui/auth-menu/auth-menu-domain';

function accountOptionKey(option: AuthMenuAccountOption): string {
  return `${option.walletId}:${option.authMethod}`;
}

export function loginAccountOptions(
  recentUnlocks: GetRecentUnlocksResult | null,
  localPasskeyWalletIds: readonly string[] = [],
): AuthMenuAccountOption[] {
  const byWalletAuthMethod = new Map<string, AuthMenuAccountOption>();
  for (const walletIdValue of localPasskeyWalletIds) {
    const walletId = String(walletIdValue || '').trim();
    if (!walletId) continue;
    const option: AuthMenuAccountOption = {
      walletId,
      displayName: walletId,
      authMethod: WALLET_AUTH_METHODS.passkey,
    };
    byWalletAuthMethod.set(accountOptionKey(option), option);
  }
  for (const account of recentUnlocks?.accounts ?? []) {
    if (
      account.authMethod !== WALLET_AUTH_METHODS.passkey &&
      account.authMethod !== WALLET_AUTH_METHODS.emailOtp
    )
      continue;
    const walletId = String(account.walletId || '').trim();
    if (!walletId) continue;
    const displayName = String(account.displayName || walletId).trim() || walletId;
    const option: AuthMenuAccountOption = {
      walletId,
      displayName,
      authMethod: account.authMethod,
    };
    byWalletAuthMethod.set(accountOptionKey(option), option);
  }
  return [...byWalletAuthMethod.values()];
}

export function defaultLoginAccount(
  recentUnlocks: GetRecentUnlocksResult | null,
  options: readonly AuthMenuAccountOption[],
): AuthMenuAccountOption | null {
  const lastUsedAccount = recentUnlocks?.lastUsedAccount;
  if (
    lastUsedAccount?.authMethod === WALLET_AUTH_METHODS.passkey ||
    lastUsedAccount?.authMethod === WALLET_AUTH_METHODS.emailOtp
  ) {
    const lastUsedWalletId = String(lastUsedAccount.walletId || '').trim();
    const exactMatch = options.find(
      (option) =>
        option.walletId === lastUsedWalletId && option.authMethod === lastUsedAccount.authMethod,
    );
    if (exactMatch) return exactMatch;
  }
  return options[0] ?? null;
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
