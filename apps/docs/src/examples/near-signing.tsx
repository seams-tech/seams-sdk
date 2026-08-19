import type { SigningFlowEvent } from '@seams/wallet';
import { ActionType, TxExecutionStatus, useSeams } from '@seams/wallet/react';
import { nearAccountRefFromAccountId, walletSessionRefFromSession } from '@seams/wallet/advanced';

export function SetGreetingButton() {
  const { seams, loginState } = useSeams();

  const onSign = async (): Promise<void> => {
    if (!loginState.walletId || !loginState.nearAccountId) {
      throw new Error('Create or open a wallet with a NEAR account before signing');
    }

    // Each request opens the wallet confirmation, where the user approves this
    // transaction with the wallet's auth method.
    await seams.near.signAndSendTransaction({
      walletSession: walletSessionRefFromSession({
        walletId: loginState.walletId,
        walletSessionUserId: loginState.walletId,
      }),
      nearAccount: nearAccountRefFromAccountId(loginState.nearAccountId),
      receiverId: 'guest-book.testnet',
      actions: [
        {
          type: ActionType.FunctionCall,
          methodName: 'set_greeting',
          args: { greeting: 'Hello from Seams' },
          gas: '30000000000000',
          deposit: '0',
        },
      ],
      options: {
        waitUntil: TxExecutionStatus.EXECUTED_OPTIMISTIC,
        onEvent: (event: SigningFlowEvent) => console.log(event.phase, event.status, event.message),
      },
    });
  };

  return <button onClick={() => void onSign()}>Sign transaction</button>;
}
