import { expect, test } from '@playwright/test';
import {
  activateEmailOtpWalletAfterUnlock,
  type EmailOtpWalletPostUnlockActivationDeps,
} from '@/SeamsWeb/operations/authMethods/emailOtp/walletActivation';
import { toWalletId } from '@/core/signingEngine/interfaces/ecdsaChainTarget';
import { parseNearEd25519SigningKeyId } from '@shared/utils/registrationIntent';
import {
  buildNearEd25519SignerBinding,
  nearAccountBindingFromRaw,
} from '@shared/utils/walletCapabilityBindings';

function testNearSigner() {
  const account = nearAccountBindingFromRaw({
    kind: 'named_near_account',
    wallet: { walletId: 'otp-wallet' },
    nearAccountId: 'alice.testnet',
  });
  if (!account.ok) throw new Error(account.error.message);
  return buildNearEd25519SignerBinding({
    account: account.value,
    nearEd25519SigningKeyId: parseNearEd25519SigningKeyId('ed25519-key-1'),
    signerSlot: 2,
  });
}

class TestActivationPreferences {
  constructor(private readonly calls: string[]) {}

  setCurrentWallet(walletId: ReturnType<typeof toWalletId>): void {
    this.calls.push(`preferences:${walletId}`);
  }

  async reloadUserSettings(): Promise<void> {
    this.calls.push('preferences:reload');
  }
}

class TestActivationSigningEngine {
  constructor(
    private readonly calls: string[],
    private readonly activation: 'succeeds' | 'fails',
  ) {}

  async activateAuthenticatedWalletState(args: {
    walletId: ReturnType<typeof toWalletId>;
    nearAccountId: string;
    signerSlot: number;
  }): Promise<void> {
    if (this.activation === 'fails') throw new Error('profile activation failed');
    this.calls.push(`activate:${args.walletId}:${args.nearAccountId}:${args.signerSlot}`);
  }

  getUserPreferences(): TestActivationPreferences {
    return new TestActivationPreferences(this.calls);
  }
}

function activationDeps(
  calls: string[],
  activation: 'succeeds' | 'fails' = 'succeeds',
): EmailOtpWalletPostUnlockActivationDeps {
  return {
    signingEngine: new TestActivationSigningEngine(calls, activation),
  };
}

test('Email OTP Ed25519 unlock activates the exact NEAR signer', async () => {
  const calls: string[] = [];
  await activateEmailOtpWalletAfterUnlock(activationDeps(calls), {
    kind: 'near_ed25519_wallet',
    signer: testNearSigner(),
  });

  expect(calls).toEqual(['activate:otp-wallet:alice.testnet:2']);
});

test('Email OTP Ed25519 unlock fails when exact signer activation fails', async () => {
  const calls: string[] = [];

  await expect(
    activateEmailOtpWalletAfterUnlock(activationDeps(calls, 'fails'), {
      kind: 'near_ed25519_wallet',
      signer: testNearSigner(),
    }),
  ).rejects.toThrow('profile activation failed');
  expect(calls).toEqual([]);
});

test('Email OTP EVM-family ECDSA unlock activates the wallet preference without a NEAR signer', async () => {
  const calls: string[] = [];
  await activateEmailOtpWalletAfterUnlock(activationDeps(calls), {
    kind: 'evm_family_ecdsa_wallet',
    walletId: toWalletId('otp-wallet'),
  });

  expect(calls).toEqual(['preferences:otp-wallet', 'preferences:reload']);
});
