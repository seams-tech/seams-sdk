import type { SeamsWeb, SigningFlowEvent } from '@seams/wallet';
import { nearAccountRefFromAccountId, walletSessionRefFromSession } from '@seams/wallet/advanced';

export async function signCheckoutMessage(
  seams: SeamsWeb,
  walletId: string,
  nearAccountId: string,
) {
  const result = await seams.near.signNEP413Message({
    walletSession: walletSessionRefFromSession({ walletId, walletSessionUserId: walletId }),
    nearAccount: nearAccountRefFromAccountId(nearAccountId),
    params: {
      message: 'Approve checkout quote #quote_123',
      recipient: 'merchant.example',
      state: 'quote_123',
    },
    options: {
      onEvent: (event: SigningFlowEvent) => console.log(event.phase, event.status, event.message),
    },
  });

  if (!result.success) {
    throw new Error(result.error);
  }
  return result;
}
