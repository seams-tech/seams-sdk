import type { RegistrationFlowEvent } from '@seams/wallet';
import { useSeams } from '@seams/wallet/react';

export function CreateWalletButton() {
  const { registerPasskey } = useSeams();

  const onCreateWallet = async (): Promise<void> => {
    const result = await registerPasskey({
      onEvent: (event: RegistrationFlowEvent) =>
        console.log(event.phase, event.status, event.message),
    });
    if (!result.success) {
      console.error('Registration failed:', result.error);
      return;
    }
    // `walletId` is the stable identifier for every later wallet operation.
    console.log(`Wallet ${result.walletId} registered (${result.kind})`);
  };

  return <button onClick={() => void onCreateWallet()}>Create wallet</button>;
}
