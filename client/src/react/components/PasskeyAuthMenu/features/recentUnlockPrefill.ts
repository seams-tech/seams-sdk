import type { SeamsWeb } from '@/web/SeamsWeb';
import { awaitWalletIframeReady } from '@/react/utils/walletIframe';

export interface RecentUnlockPrefillResult {
  username: string;
}

/**
 * Best-effort: fetch the most-recently used account and return its username prefix.
 * Intended to be called from a lazily imported "feature island".
 */
export async function getRecentUnlockPrefill(
  seamsWeb: SeamsWeb,
): Promise<RecentUnlockPrefillResult | null> {
  try {
    await awaitWalletIframeReady(seamsWeb).catch(() => false);
    const { lastUsedAccount } = await seamsWeb.auth.getRecentUnlocks();
    const username = (lastUsedAccount?.nearAccountId ?? '').split('.')[0] || '';
    if (!username) return null;
    return { username };
  } catch {
    return null;
  }
}

export default getRecentUnlockPrefill;
