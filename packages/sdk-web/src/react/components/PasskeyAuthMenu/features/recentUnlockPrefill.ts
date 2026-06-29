import type { SeamsWeb } from '@/SeamsWeb';
import { awaitWalletIframeReady } from '@/react/utils/walletIframe';

export interface RecentUnlockPrefillResult {
  username: string;
}

/**
 * Best-effort: fetch the most-recently used wallet and return its display name.
 * Intended to be called from a lazily imported "feature island".
 */
export async function getRecentUnlockPrefill(
  seamsWeb: SeamsWeb,
): Promise<RecentUnlockPrefillResult | null> {
  try {
    await awaitWalletIframeReady(seamsWeb).catch(() => false);
    const { lastUsedAccount } = await seamsWeb.auth.getRecentUnlocks();
    const username = String(lastUsedAccount?.displayName || lastUsedAccount?.walletId || '').trim();
    if (!username) return null;
    return { username };
  } catch {
    return null;
  }
}

export default getRecentUnlockPrefill;
