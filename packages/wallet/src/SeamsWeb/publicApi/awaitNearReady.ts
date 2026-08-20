import type { NearProvisioningState } from '@/core/types/seams';
import type { NearProvisioningStateChangedEvent } from '@/core/types/sdkSentEvents';
import type { RegistrationCapability } from '@/SeamsWeb/publicApi/types';

export const DEFAULT_AWAIT_NEAR_READY_TIMEOUT_MS = 120_000;

export type AwaitNearReadyResult =
  | { kind: 'near_ready'; nearAccountId: string }
  | { kind: 'near_failed_retryable'; reason: string }
  | { kind: 'timed_out' };

function outcomeFor(state: NearProvisioningState | null): AwaitNearReadyResult | null {
  if (!state) return null;
  if (state.status === 'near_ready') {
    return { kind: 'near_ready', nearAccountId: state.nearAccountId };
  }
  if (state.status === 'near_failed_retryable') {
    return { kind: 'near_failed_retryable', reason: state.error };
  }
  return null;
}

/**
 * Waits for a mixed registration's NEAR account to finish provisioning.
 *
 * `registerPasskey` can return `ecdsa_wallet_registered_near_pending`, which
 * carries no NEAR account id — but signing NEAR needs one. Subscribing first
 * and then reading the current state closes the race where provisioning
 * completes between the two.
 */
export async function awaitNearReady(
  deps: {
    getNearProvisioningState: RegistrationCapability['getNearProvisioningState'];
    onNearProvisioningStateChanged: RegistrationCapability['onNearProvisioningStateChanged'];
  },
  args: { walletId: string; timeoutMs?: number; signal?: AbortSignal },
): Promise<AwaitNearReadyResult> {
  const walletId = String(args.walletId || '').trim();
  if (!walletId) throw new Error('[seams] awaitNearReady requires a walletId');
  const timeoutMs =
    Math.max(1, Math.floor(Number(args.timeoutMs) || 0)) || DEFAULT_AWAIT_NEAR_READY_TIMEOUT_MS;

  let unsubscribe: null | (() => void) = null;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let onAbort: (() => void) | null = null;
  try {
    return await new Promise<AwaitNearReadyResult>((resolve, reject) => {
      let settled = false;
      const settle = (result: AwaitNearReadyResult): void => {
        if (settled) return;
        settled = true;
        resolve(result);
      };

      if (args.signal?.aborted) {
        reject(args.signal.reason ?? new Error('[seams] awaitNearReady aborted'));
        return;
      }
      if (args.signal) {
        onAbort = () => {
          if (settled) return;
          settled = true;
          reject(args.signal?.reason ?? new Error('[seams] awaitNearReady aborted'));
        };
        args.signal.addEventListener('abort', onAbort, { once: true });
      }

      // Subscribe before the first read so a transition in between is not lost.
      unsubscribe = deps.onNearProvisioningStateChanged(
        (event: NearProvisioningStateChangedEvent) => {
          if (String(event.walletId) !== walletId) return;
          const outcome = outcomeFor(event.state);
          if (outcome) settle(outcome);
        },
      );
      timer = setTimeout(() => settle({ kind: 'timed_out' }), timeoutMs);

      void deps
        .getNearProvisioningState({ walletId })
        .then((state) => {
          const outcome = outcomeFor(state);
          if (outcome) settle(outcome);
        })
        .catch(() => {
          // A failed read is not an outcome: keep waiting for an event or the timeout.
        });
    });
  } finally {
    if (timer) clearTimeout(timer);
    if (onAbort && args.signal) args.signal.removeEventListener('abort', onAbort);
    try {
      const dispose = unsubscribe as null | (() => void);
      dispose?.();
    } catch {}
  }
}
