import type { NearClient } from '@/core/rpcClients/near/NearClient';
import type { WalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { toAccountId } from '@/core/types/accountIds';
import type { NearEd25519SignerBinding } from '@shared/utils/walletCapabilityBindings';

export type EmailOtpWalletPostUnlockActivation =
  | {
      kind: 'near_ed25519_wallet';
      signer: NearEd25519SignerBinding;
      walletId?: never;
    }
  | {
      kind: 'evm_family_ecdsa_wallet';
      walletId: WalletId;
      signer?: never;
    };

export type EmailOtpWalletPostUnlockActivationDeps = {
  signingEngine: {
    activateAuthenticatedWalletState(args: {
      walletId: WalletId;
      nearAccountId: ReturnType<typeof toAccountId>;
      signerSlot: number;
      nearClient?: NearClient;
    }): Promise<void>;
    getUserPreferences(): {
      setCurrentWallet(walletId: WalletId): void;
      reloadUserSettings(): Promise<void>;
    };
  };
  nearClient?: NearClient;
};

function ignoreUserPreferenceReloadError(): undefined {
  return undefined;
}

export async function activateEmailOtpWalletAfterUnlock(
  deps: EmailOtpWalletPostUnlockActivationDeps,
  activation: EmailOtpWalletPostUnlockActivation,
): Promise<void> {
  switch (activation.kind) {
    case 'near_ed25519_wallet':
      await deps.signingEngine.activateAuthenticatedWalletState({
        walletId: activation.signer.account.wallet.walletId,
        nearAccountId: toAccountId(activation.signer.account.nearAccountId),
        signerSlot: activation.signer.signerSlot,
        ...(deps.nearClient ? { nearClient: deps.nearClient } : {}),
      });
      return;
    case 'evm_family_ecdsa_wallet': {
      const preferences = deps.signingEngine.getUserPreferences();
      preferences.setCurrentWallet(activation.walletId);
      await preferences.reloadUserSettings().catch(ignoreUserPreferenceReloadError);
      return;
    }
  }
  activation satisfies never;
}
