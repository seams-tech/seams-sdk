import type { LoginAndCreateSessionResult, UnlockFlowEvent } from '@seams/sdk';
import type { SeamsContextType } from '@seams/sdk/react';

type UnlockWallet = SeamsContextType['unlock'];

function assertNever(value: never): never {
  throw new Error(`Unhandled unlock result: ${String(value)}`);
}

function logUnlockEvent(event: UnlockFlowEvent): void {
  console.log(event.phase, event.status, event.message);
}

export async function unlockWallet(
  unlock: UnlockWallet,
  walletId: string,
): Promise<LoginAndCreateSessionResult> {
  const result = await unlock(walletId, { onEvent: logUnlockEvent });
  if (!result.success) {
    throw new Error(result.error);
  }

  switch (result.kind) {
    case 'near_wallet_unlocked':
      console.log('NEAR account ready', result.nearAccountId);
      return result;
    case 'ecdsa_wallet_unlocked':
      console.log('EVM-family wallet ready', result.walletId);
      return result;
    default:
      return assertNever(result);
  }
}
