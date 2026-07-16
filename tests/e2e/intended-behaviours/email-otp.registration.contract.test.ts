import { intendedTest as test } from './harness';

test('Email OTP registration lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.refreshPagePreservingWalletStorage();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransaction('after_refresh_recovery');
  await harness.signTempoAndArcEvmConcurrently('after_refresh_recovery');
  await harness.refreshPagePreservingWalletStorage();
  await harness.signArcEvmTransaction('after_step_up');
  await harness.signTempoTransaction('after_step_up');
  await harness.signNearTransaction('after_step_up');
});

test('Email OTP registration immediately exports and exhausts the shared budget', async ({
  harness,
}) => {
  await harness.registerEmailOtpWallet();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransaction('post_registration');
  await harness.signTempoAndArcEvmConcurrently('post_registration');
  await harness.signNearTransaction('after_step_up');
});
