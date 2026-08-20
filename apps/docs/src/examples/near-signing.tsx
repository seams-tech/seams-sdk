import { functionCall, logWalletEvents, TxExecutionStatus, useWallet } from '@seams/wallet/react';

export function SetGreetingButton() {
  const { wallet } = useWallet();

  const onSign = async (): Promise<void> => {
    if (!wallet) throw new Error('Sign in before signing a transaction');
    // `near` is null until the wallet has a NEAR account: it is either EVM-only,
    // or provisioning has not finished.
    if (!wallet.near) {
      throw new Error('Create or open a wallet with a NEAR account before signing');
    }

    // Each request opens the wallet confirmation, where the user approves this
    // transaction with the wallet's auth method.
    await wallet.near.signAndSendTransaction({
      receiverId: 'guest-book.testnet',
      actions: [functionCall({ method: 'set_greeting', args: { greeting: 'Hello from Seams' } })],
      options: {
        waitUntil: TxExecutionStatus.EXECUTED_OPTIMISTIC,
        onEvent: logWalletEvents(),
      },
    });
  };

  return <button onClick={() => void onSign()}>Sign transaction</button>;
}
