import { intendedTest as test } from './harness';

test('Email OTP registration and unlock lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.signTempoTransaction('post_registration');
  await harness.signArcEvmTransaction('post_registration');
  await harness.exportEcdsaKey();
  await harness.awaitNearReady();
  await harness.signNearTransaction('post_registration');
  await harness.exportEd25519Key();

  await harness.unlockEmailOtpWallet();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.refreshPagePreservingWalletStorage();
  await harness.signNearTransactionAfterRefresh();
  await harness.signTempoAndArcEvmConcurrently('after_refresh_recovery');
  await harness.refreshPagePreservingWalletStorage();
  await harness.signNearTransaction('step_up_required');
  await harness.signTempoTransaction('step_up_required');
  await harness.signArcEvmTransaction('step_up_required');
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
});
