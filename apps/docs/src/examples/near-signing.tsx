import { functionCall, logWalletEvents, TxExecutionStatus, useWallet } from '@seams/wallet/react';

export function SetGreetingButton() {
  // `near` is null when nobody is signed in, and when the signed-in wallet has
  // no NEAR account yet. One check covers both; read `status` to tell them apart.
  const { near } = useWallet();
  if (!near) return null;

  const onSign = async (): Promise<void> => {
    // Each request opens the wallet confirmation, where the user approves this
    // transaction with the wallet's auth method.
    await near.signAndSendTransaction({
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
