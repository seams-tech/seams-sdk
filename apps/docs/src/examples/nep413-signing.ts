import { logWalletEvents, type SeamsWeb } from '@seams/wallet';

export async function signCheckoutMessage(seams: SeamsWeb) {
  const result = await seams.near.signNEP413Message({
    // Omitting the subject targets the authenticated wallet and its NEAR
    // account; pass `walletSession` (a wallet id is enough) or `nearAccount` to
    // name an exact one.
    params: {
      message: 'Approve checkout quote #quote_123',
      recipient: 'merchant.example',
      state: 'quote_123',
    },
    options: { onEvent: logWalletEvents() },
  });

  if (!result.success) {
    throw new Error(result.error);
  }
  return result;
}
