import type { TatchiPasskey } from '@/core/TatchiPasskey';
import { awaitWalletIframeReady } from '@/react/utils/walletIframe';

export interface RecentUnlockPrefillResult {
  username: string;
}

/**
 * Best-effort: fetch the most-recently used account and return its username prefix.
 * Intended to be called from a lazily imported "feature island".
 */
export async function getRecentUnlockPrefill(
  tatchiPasskey: TatchiPasskey,
): Promise<RecentUnlockPrefillResult | null> {
  try {
    await awaitWalletIframeReady(tatchiPasskey).catch(() => false);
    const { lastUsedAccount } = await tatchiPasskey.auth.getRecentUnlocks();
    const username = (lastUsedAccount?.nearAccountId ?? '').split('.')[0] || '';
    if (!username) return null;
    return { username };
  } catch {
    return null;
  }
}

export default getRecentUnlockPrefill;
