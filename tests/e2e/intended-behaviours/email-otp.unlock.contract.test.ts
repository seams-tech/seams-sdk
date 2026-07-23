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
  await harness.signNearTransaction('step_up_required');
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
  await harness.signNearTransactionAfterRefresh();
  await harness.signTempoAndArcEvmConcurrently('after_refresh_recovery');
  await harness.refreshPagePreservingWalletStorage();
  await harness.signNearTransaction('step_up_required');
  await harness.signTempoTransaction('step_up_required');
  await harness.signArcEvmTransaction('step_up_required');
});
