import type { UnlockFlowEvent } from '@seams/wallet';
import type { SeamsContextType } from '@seams/wallet/react';

export async function unlockWallet(unlock: SeamsContextType['unlock'], walletId: string) {
  const result = await unlock(walletId, {
    onEvent: (event: UnlockFlowEvent) => console.log(event.phase, event.status, event.message),
  });
  if (!result.success) {
    throw new Error(result.error);
  }

  // Read `nearAccountId` only from the NEAR branch.
  if (result.kind === 'near_wallet_unlocked') {
    console.log('NEAR account ready', result.nearAccountId);
  } else {
    console.log('EVM-family wallet ready', result.walletId);
  }
  return result;
}
