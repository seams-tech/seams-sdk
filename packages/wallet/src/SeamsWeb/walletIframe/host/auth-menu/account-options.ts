import type { GetRecentUnlocksResult } from '@/core/types/seams';
import type { LocalLoginAuthMethod } from '@/SeamsWeb/operations/auth/login';
import { WALLET_AUTH_METHODS } from '@shared/utils';
import type { AuthMenuAccountOption } from '../lit-ui/auth-menu/auth-menu-domain';

function accountOptionKey(option: AuthMenuAccountOption): string {
  return `${option.walletId}:${option.authMethod}`;
}

function localAuthMethodDisplayName(
  method: LocalLoginAuthMethod,
  existingOption: AuthMenuAccountOption | undefined,
): string {
  switch (method.authMethod) {
    case 'passkey':
      return existingOption?.displayName ?? String(method.walletId);
    case 'email_otp':
      return method.emailAddress ?? existingOption?.displayName ?? String(method.walletId);
  }
}

export function loginAccountOptions(
  recentUnlocks: GetRecentUnlocksResult | null,
  localAuthMethods: readonly LocalLoginAuthMethod[] = [],
): AuthMenuAccountOption[] {
  const byWalletAuthMethod = new Map<string, AuthMenuAccountOption>();
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
  for (const localMethod of localAuthMethods) {
    const walletId = String(localMethod.walletId || '').trim();
    if (!walletId) continue;
    const key = `${walletId}:${localMethod.authMethod}`;
    const option: AuthMenuAccountOption = {
      walletId,
      displayName: localAuthMethodDisplayName(localMethod, byWalletAuthMethod.get(key)),
      authMethod: localMethod.authMethod,
    };
    byWalletAuthMethod.set(key, option);
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
