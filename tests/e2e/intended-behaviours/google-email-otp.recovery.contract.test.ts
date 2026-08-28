import {
  intendedTest as test,
  type IntendedBehaviourHarness,
  type IntendedRecoveryTargetKind,
} from './harness';

type RecoveryOrigin = {
  readonly name: string;
  readonly register: (harness: IntendedBehaviourHarness) => Promise<void>;
  readonly assertExistingInventory?: (harness: IntendedBehaviourHarness) => Promise<void>;
};

async function registerPasskeyFoundedWallet(harness: IntendedBehaviourHarness): Promise<void> {
  await harness.registerPasskeyWallet();
}

async function registerEmailOnlyWallet(harness: IntendedBehaviourHarness): Promise<void> {
  await harness.registerEmailOtpWallet();
}

async function assertEmailOnlyInventoryRemains(harness: IntendedBehaviourHarness): Promise<void> {
  await harness.unlockEmailOtpWallet();
}

const recoveryOrigins: readonly RecoveryOrigin[] = [
  {
    name: 'Passkey-founded',
    register: registerPasskeyFoundedWallet,
  },
  {
    name: 'Email-only',
    register: registerEmailOnlyWallet,
    assertExistingInventory: assertEmailOnlyInventoryRemains,
  },
];

const recoveryTarget: IntendedRecoveryTargetKind = 'google_email_otp';

for (const origin of recoveryOrigins) {
  test(`a fresh browser recovers a ${origin.name} wallet with Google and Email OTP, signs, and refuses reuse`, async ({
    harness,
  }) => {
    await origin.register(harness);
    await harness.awaitNearReady();
    await harness.signTempoTransaction('post_registration');
    await harness.recoverGoogleEmailOtpWalletFromFreshBrowser();
    await harness.assertRecoveryAuthorityIsAdditive(recoveryTarget);
    await harness.assertSourceWalletSessionRemainsActive();
    await harness.refreshPagePreservingWalletStorage();
    await harness.signNearTransaction('post_unlock');
    await harness.signTempoAndArcEvmConcurrently('post_unlock');
    await origin.assertExistingInventory?.(harness);
    await harness.assertConsumedRecoveryCodeRefusedGenerically(recoveryTarget);
  });
}

test('an older passkey does not block adding a passkey to a Google recovery authority', async ({
  harness,
}) => {
  await harness.registerPasskeyWallet();
  await harness.awaitNearReady();
  await harness.recoverGoogleEmailOtpWalletFromFreshBrowser();
  await harness.addPasskeyAuthMethod();
});
