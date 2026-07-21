import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

async function verifyEmailOtpUnlockImmediateLifecycle({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerEmailOtpWallet();
  await harness.unlockEmailOtpWallet();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransaction('post_unlock');
  await harness.signTempoAndArcEvmConcurrently('post_unlock');
  await harness.exhaustSigningBudget();
  await harness.signNearTransaction('after_step_up');
}

test(
  'Email OTP unlock restores immediate export and shared-budget signing',
  verifyEmailOtpUnlockImmediateLifecycle,
);

test('Email OTP unlock lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.unlockEmailOtpWallet();
  await harness.refreshPagePreservingWalletStorage();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransactionAfterRefresh('email_otp_yao_recovery');
  await harness.signTempoTransaction('after_refresh_recovery');
  await harness.signArcEvmTransaction('after_refresh_recovery');
  await harness.exhaustSigningBudget();
  await harness.refreshPagePreservingWalletStorage();
  await harness.signNearTransaction('after_step_up');
  await harness.signTempoTransaction('after_step_up');
  await harness.signArcEvmTransaction('after_step_up');
});
