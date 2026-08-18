import { useSeams } from '@seams/wallet/react';
import type {
  RegistrationHooksOptions,
  RegistrationResult,
  SeamsContextType,
} from '@seams/wallet/react';

type RegisterPasskey = SeamsContextType['registerPasskey'];

function assertNever(value: never): never {
  throw new Error(`Unhandled registration result: ${String(value)}`);
}

function logRegistrationEvent(
  event: Parameters<NonNullable<RegistrationHooksOptions['onEvent']>>[0],
): void {
  console.log(event.phase, event.status, event.message);
}

export function registrationSummary(result: RegistrationResult): string {
  if (!result.success) {
    return `Registration failed: ${result.error}`;
  }

  switch (result.kind) {
    case 'wallet_registered':
      return `Wallet ${result.walletId} registered with ${result.capabilities
        .map((capability) => capability.kind)
        .join(' and ')} capability`;
    case 'wallet_signer_added':
      return `Signer added to wallet ${result.walletId}: ${result.capabilities[0].kind}`;
    case 'ecdsa_wallet_registered_near_pending':
      return `Wallet ${result.walletId} is registered; NEAR provisioning is ${result.nearProvisioning.status}`;
    case 'near_wallet_registered_pending':
      return `Wallet ${result.walletId} is registered; NEAR provisioning is ${result.nearProvisioning.status}`;
    default:
      return assertNever(result);
  }
}

export async function createPasskeyWallet(
  registerPasskey: RegisterPasskey,
): Promise<RegistrationResult> {
  const result = await registerPasskey({ onEvent: logRegistrationEvent });
  if (!result.success) {
    throw new Error(result.error);
  }
  return result;
}

export function CreateWalletButton() {
  const { registerPasskey } = useSeams();

  const onCreateWallet = async (): Promise<void> => {
    const result = await createPasskeyWallet(registerPasskey);
    console.log(registrationSummary(result));
  };

  return <button onClick={() => void onCreateWallet()}>Create wallet</button>;
}
