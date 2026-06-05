import type { AccountId } from '@/core/types/accountIds';
import {
  createSigningFlowEvent,
  type CreateSigningFlowEventInput,
  type SigningFlowEvent,
} from '@/core/types/sdkSentEvents';

export type NearSigningEventInput = Omit<CreateSigningFlowEventInput, 'flowId' | 'accountId'>;

export function emitNearSigningEvent(
  onEvent: ((event: SigningFlowEvent) => void) | undefined,
  accountId: AccountId | string,
  event: NearSigningEventInput,
): void {
  try {
    onEvent?.(
      createSigningFlowEvent({
        ...event,
        flowId: `signing:near:${String(accountId)}:${event.phase}`,
        accountId: String(accountId),
      }),
    );
  } catch {}
}
