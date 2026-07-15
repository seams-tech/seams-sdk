import { intendedTest as test } from './harness';

test('Email OTP unlock lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.unlockEmailOtpWallet();
  await harness.refreshPagePreservingWalletStorage();
  await harness.signNearTransaction('after_refresh_recovery');
  await harness.signTempoTransaction('after_refresh_recovery');
  await harness.signArcEvmTransaction('after_refresh_recovery');
  await harness.exhaustSigningBudget();
  await harness.refreshPagePreservingWalletStorage();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransaction('after_step_up');
  await harness.signTempoTransaction('after_step_up');
  await harness.signArcEvmTransaction('after_step_up');
});
