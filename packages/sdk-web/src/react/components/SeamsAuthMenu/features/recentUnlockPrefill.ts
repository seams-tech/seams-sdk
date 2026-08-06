import type { SeamsWeb } from '@/SeamsWeb';
import { awaitWalletIframeReady } from '@/react/utils/walletIframe';
import {
  NO_LAST_USED_LOGIN_METHOD,
  parseLastUsedLoginMethod,
  type LastUsedLoginMethod,
} from '../controller/lastUsedLoginMethod';

export type RecentUnlockPrefillResult =
  | {
      kind: 'recent_unlock_prefill';
      walletId: string;
      username: string;
      loginMethod: LastUsedLoginMethod;
    }
  | {
      kind: 'no_recent_unlock_prefill';
      loginMethod: typeof NO_LAST_USED_LOGIN_METHOD;
    };

function noRecentUnlockPrefill(): RecentUnlockPrefillResult {
  return {
    kind: 'no_recent_unlock_prefill',
    loginMethod: NO_LAST_USED_LOGIN_METHOD,
  };
}

function recentUnlockPrefill(input: {
  walletId: string;
  loginMethod: LastUsedLoginMethod;
}): RecentUnlockPrefillResult {
  return {
    kind: 'recent_unlock_prefill',
    walletId: input.walletId,
    username: input.walletId,
    loginMethod: input.loginMethod,
  };
}

type RecentUnlockAccountLike = {
  walletId?: unknown;
  authMethod?: unknown;
};

function readRecentUnlockAccountLike(raw: unknown): RecentUnlockAccountLike | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  return raw as RecentUnlockAccountLike;
}

function prefillFromRecentUnlockAccount(raw: unknown): RecentUnlockPrefillResult {
  const account = readRecentUnlockAccountLike(raw);
  if (!account) return noRecentUnlockPrefill();
  const walletId = String(account.walletId || '').trim();
  if (!walletId) return noRecentUnlockPrefill();
  return recentUnlockPrefill({
    walletId,
    loginMethod: parseLastUsedLoginMethod(account.authMethod),
  });
}

/**
 * Best-effort: fetch the most-recently used wallet and its auth method.
 * Intended to be called from a lazily imported "feature island".
 */
export async function getRecentUnlockPrefill(
  seamsWeb: SeamsWeb,
): Promise<RecentUnlockPrefillResult> {
  try {
    await awaitWalletIframeReady(seamsWeb).catch(() => false);
    const { lastUsedAccount } = await seamsWeb.auth.getRecentUnlocks();
    return prefillFromRecentUnlockAccount(lastUsedAccount);
  } catch {
    return noRecentUnlockPrefill();
  }
}

export default getRecentUnlockPrefill;
