import type { RegistrationFlowEvent } from '@seams/wallet';
import { useSeams } from '@seams/wallet/react';

export function CreateWalletButton() {
  const { registerPasskey, seams } = useSeams();

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

    // A mixed registration returns before NEAR provisioning finishes, so the
    // result carries no NEAR account id yet. Wait for one before signing NEAR.
    if (result.kind === 'ecdsa_wallet_registered_near_pending') {
      const near = await seams.registration.awaitNearReady({ walletId: result.walletId });
      console.log('NEAR provisioning finished:', near.kind);
    }
  };

  return <button onClick={() => void onCreateWallet()}>Create wallet</button>;
}
