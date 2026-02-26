// Utilities for coordinating with wallet-iframe readiness from TatchiPasskey.
import type { TatchiPasskey } from '@/core/TatchiPasskey';

/**
 * Await wallet iframe readiness when using TatchiPasskey.
 * - If iframe is already ready, resolves immediately (returns true).
 * - Otherwise waits for onReady/polling up to timeoutMs, then resolves (returns whether it became ready).
 */
export async function awaitWalletIframeReady(
  manager: Pick<TatchiPasskey, 'initWalletIframe' | 'isWalletIframeReady' | 'onWalletIframeReady'>,
  opts?: { timeoutMs?: number },
): Promise<boolean> {
  const timeoutMs = Math.max(500, Math.min(15_000, opts?.timeoutMs ?? 4000));

  if (!manager || (typeof manager !== 'object' && typeof manager !== 'function')) return false;

  const isReadyNow = (): boolean => {
    try {
      if (manager.isWalletIframeReady()) return true;
    } catch {}
    return false;
  };

  // Kick init (idempotent in implementations)
  try {
    await manager.initWalletIframe();
  } catch {}

  if (isReadyNow()) return true;

  return await new Promise<boolean>((resolve) => {
    let done = false;
    const finish = (ok: boolean) => {
      if (done) return;
      done = true;
      try {
        offReady?.();
      } catch {}
      try {
        clearTimeout(timer);
      } catch {}
      resolve(ok);
    };

    // Subscribe to wallet iframe ready events.
    let offReady: (() => void) | undefined;
    try {
      offReady = manager.onWalletIframeReady(() => finish(true));
    } catch {}

    // Poll and keep nudging init as a backup
    const start = Date.now();
    const poll = async () => {
      if (done) return;
      if (isReadyNow()) {
        finish(true);
        return;
      }
      if (Date.now() - start >= timeoutMs) {
        finish(false);
        return;
      }
      // Nudge init (no-op if already initialized)
      try {
        await manager.initWalletIframe();
      } catch {}
      setTimeout(poll, 100);
    };
    poll();

    const timer = setTimeout(() => finish(false), timeoutMs + 50) as unknown as number;
  });
}
