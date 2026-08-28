import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

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
  { name: 'Passkey-founded', register: registerPasskeyFoundedWallet },
  {
    name: 'Email-only',
    register: registerEmailOnlyWallet,
    assertExistingInventory: assertEmailOnlyInventoryRemains,
  },
];

for (const origin of recoveryOrigins) {
  test(`a fresh browser recovers a ${origin.name} wallet with one code, signs, and refuses reuse`, async ({
    harness,
  }) => {
    await origin.register(harness);
    await harness.awaitNearReady();
    await harness.signTempoTransaction('post_registration');
    await harness.recoverPasskeyWalletFromFreshBrowser();
    await harness.assertRecoveryAuthorityIsAdditive('passkey');
    await harness.assertSourceWalletSessionRemainsActive();
    await harness.refreshPagePreservingWalletStorage();
    await harness.signNearTransaction('post_unlock');
    await harness.signTempoAndArcEvmConcurrently('post_unlock');
    await origin.assertExistingInventory?.(harness);
    await harness.assertConsumedRecoveryCodeReportedAsUsed();
  });
}

test('a failed finalization leaves its admitted recovery code reusable', async ({
  harness,
}) => {
  await harness.registerPasskeyWallet();
  await harness.awaitNearReady();
  await harness.signTempoTransaction('post_registration');
  await harness.recoverPasskeyWalletAfterFailedFinalization();
  await harness.assertRecoveryAuthorityIsAdditive('passkey');
  await harness.assertConsumedRecoveryCodeReportedAsUsed();
});

test('a recovered passkey wallet adds Email OTP, locks, unlocks with Google, and signs both families', async ({
  harness,
}) => {
  await harness.registerPasskeyWallet();
  await harness.awaitNearReady();
  await harness.recoverPasskeyWalletFromFreshBrowser();
  await harness.addEmailOtpAuthMethod();
  await harness.assertLockedPageReloadStaysLocked();
  await harness.unlockWithAddedEmailOtp();
  await harness.signTempoTransaction('post_unlock');
  await harness.signNearTransaction('post_unlock');
});
