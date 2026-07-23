import { intendedTest as test } from './harness';

test('Email OTP registration lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.refreshPagePreservingWalletStorage();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransactionAfterRefresh();
  await harness.signTempoAndArcEvmConcurrently('after_refresh_recovery');
  await harness.refreshPagePreservingWalletStorage();
  await harness.signArcEvmTransaction('step_up_required');
  await harness.signTempoTransaction('step_up_required');
  await harness.signNearTransaction('step_up_required');
});

test('Email OTP registration immediately exports, signs EVM concurrently, and exhausts the shared budget', async ({
  harness,
}) => {
  await harness.registerEmailOtpWallet();
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
  await harness.signNearTransaction('post_registration');
  await harness.signTempoAndArcEvmConcurrently('post_registration');
  await harness.signNearTransaction('step_up_required');
});
