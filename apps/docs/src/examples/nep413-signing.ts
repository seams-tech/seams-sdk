import type { SeamsWeb, SignNEP413MessageResult, SigningFlowEvent } from '@seams/sdk';
import { nearAccountRefFromAccountId, walletSessionRefFromSession } from '@seams/sdk/advanced';

function logSigningEvent(event: SigningFlowEvent): void {
  console.log(event.phase, event.status, event.message);
}

export async function signCheckoutMessage(
  seams: SeamsWeb,
  walletId: string,
  nearAccountId: string,
): Promise<SignNEP413MessageResult> {
  const result = await seams.near.signNEP413Message({
    walletSession: walletSessionRefFromSession({
      walletId,
      walletSessionUserId: walletId,
    }),
    nearAccount: nearAccountRefFromAccountId(nearAccountId),
    params: {
      message: 'Approve checkout quote #quote_123',
      recipient: 'merchant.example',
      state: 'quote_123',
    },
    options: { onEvent: logSigningEvent },
  });

  if (!result.success) {
    throw new Error(result.error);
  }
  return result;
}
