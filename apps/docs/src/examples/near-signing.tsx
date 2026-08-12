import { ActionType, TxExecutionStatus, useSeams } from '@seams/sdk/react';
import type { FunctionCallAction } from '@seams/sdk/react';
import type { SeamsWeb, SigningFlowEvent } from '@seams/sdk';
import { nearAccountRefFromAccountId, walletSessionRefFromSession } from '@seams/sdk/advanced';

function logSigningEvent(event: SigningFlowEvent): void {
  console.log(event.phase, event.status, event.message);
}

export async function signGreeting(
  seams: SeamsWeb,
  walletId: string,
  nearAccountId: string,
): Promise<void> {
  const action: FunctionCallAction = {
    type: ActionType.FunctionCall,
    methodName: 'set_greeting',
    args: { greeting: 'Hello from Seams' },
    gas: '30000000000000',
    deposit: '0',
  };

  await seams.near.signAndSendTransaction({
    walletSession: walletSessionRefFromSession({
      walletId,
      walletSessionUserId: walletId,
    }),
    nearAccount: nearAccountRefFromAccountId(nearAccountId),
    receiverId: 'guest-book.testnet',
    actions: [action],
    options: {
      waitUntil: TxExecutionStatus.EXECUTED_OPTIMISTIC,
      onEvent: logSigningEvent,
    },
  });
}

export function SetGreetingButton() {
  const { seams, loginState } = useSeams();

  const onSign = async (): Promise<void> => {
    if (!loginState.isLoggedIn || !loginState.walletId || !loginState.nearAccountId) {
      throw new Error('Unlock a wallet with a NEAR account before signing');
    }
    await signGreeting(seams, loginState.walletId, loginState.nearAccountId);
  };

  return <button onClick={() => void onSign()}>Sign transaction</button>;
}
