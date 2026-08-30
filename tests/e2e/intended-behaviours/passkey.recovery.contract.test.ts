import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

type RecoveryOrigin = {
  readonly name: string;
  readonly register: (harness: IntendedBehaviourHarness) => Promise<void>;
};

async function registerPasskeyFoundedWallet(harness: IntendedBehaviourHarness): Promise<void> {
  await harness.registerPasskeyWallet();
}

async function registerEmailOnlyWallet(harness: IntendedBehaviourHarness): Promise<void> {
  await harness.registerEmailOtpWallet();
}

async function registerCombinedWallet(harness: IntendedBehaviourHarness): Promise<void> {
  await harness.registerEmailOtpWallet();
  await harness.awaitNearReady();
  await harness.addPasskeyAuthMethod();
}

async function verifyPasskeyRecoveryCanAddEmailOtp(
  harness: IntendedBehaviourHarness,
  register: (harness: IntendedBehaviourHarness) => Promise<void>,
): Promise<void> {
  await register(harness);
  await harness.awaitNearReady();
  await harness.recoverPasskeyWalletFromFreshBrowser();
  await harness.assertRecoveryAuthorityIsAdditive('passkey');
  await harness.addEmailOtpAuthMethod();
  await harness.assertLockedPageReloadStaysLocked();
  await harness.unlockWithAddedEmailOtp();
  await harness.signTempoTransaction('post_unlock');
  await harness.signNearTransaction('post_unlock');
  await harness.exportEcdsaKey();
  await harness.exportEd25519Key();
  await harness.exhaustSigningBudget();
  await harness.signNearTransaction('step_up_required');
}

const recoveryOrigins: readonly RecoveryOrigin[] = [
  { name: 'Passkey-founded', register: registerPasskeyFoundedWallet },
  {
    name: 'Email-only',
    register: registerEmailOnlyWallet,
  },
  { name: 'Combined', register: registerCombinedWallet },
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
    await harness.assertConsumedRecoveryCodeReportedAsUsed();
  });
}

test('a failed finalization leaves its admitted recovery code reusable', async ({ harness }) => {
  await harness.registerPasskeyWallet();
  await harness.awaitNearReady();
  await harness.signTempoTransaction('post_registration');
  await harness.recoverPasskeyWalletAfterFailedFinalization();
  await harness.assertRecoveryAuthorityIsAdditive('passkey');
  await harness.assertConsumedRecoveryCodeReportedAsUsed();
});

test('a committed Passkey recovery survives a lost finalization response and runtime reset', async ({
  harness,
}) => {
  await harness.registerPasskeyWallet();
  await harness.awaitNearReady();
  await harness.signTempoTransaction('post_registration');
  await harness.recoverPasskeyWalletAfterLostFinalizationResponse();
  await harness.assertRecoveryAuthorityIsAdditive('passkey');
});

test('a Passkey-founded wallet recovers with Passkey, adds Email OTP, then signs, exports, and steps up through it', async ({
  harness,
}) => {
  await verifyPasskeyRecoveryCanAddEmailOtp(harness, registerPasskeyFoundedWallet);
});

test('an Email-founded wallet recovers with Passkey, adds Email OTP to the recovery authority, then signs, exports, and steps up through it', async ({
  harness,
}) => {
  await verifyPasskeyRecoveryCanAddEmailOtp(harness, registerEmailOnlyWallet);
});
