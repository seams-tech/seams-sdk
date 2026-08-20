import type { WalletFlowEvent } from '@/core/types/sdkSentEvents';

/**
 * A ready-made `onEvent` handler.
 *
 * Every flow event carries the same `phase` / `status` / `message` triple, and
 * every integration starts by logging it. This is that handler, so a call site
 * that only wants progress visibility does not have to write one.
 *
 * @example
 * await wallet.near.signAndSendTransaction({
 *   receiverId,
 *   actions,
 *   options: { onEvent: logWalletEvents() },
 * });
 */
export function logWalletEvents(options?: {
  /** Prefix for each line. Defaults to `[seams]`. */
  label?: string;
  /** Where to write. Defaults to `console.log`. */
  write?: (line: string, event: WalletFlowEvent) => void;
}): (event: WalletFlowEvent) => void {
  const label = options?.label ?? '[seams]';
  const write = options?.write ?? ((line: string): void => console.log(line));
  return (event: WalletFlowEvent): void => {
    try {
      write(`${label} ${event.phase} ${event.status} ${event.message ?? ''}`.trimEnd(), event);
    } catch {}
  };
}
