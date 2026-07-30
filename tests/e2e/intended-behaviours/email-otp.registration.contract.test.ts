import { intendedTest as test } from './harness';

test('Email OTP registration lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.awaitNearReady();
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

test('Email OTP registration signs EVM before NEAR readiness, then enables Ed25519 operations', async ({
  harness,
}) => {
  await harness.registerEmailOtpWallet();
  await harness.exportEcdsaKey();
  await harness.signTempoAndArcEvmConcurrently('post_registration');
  await harness.awaitNearReady();
  await harness.exportEd25519Key();
  await harness.signNearTransaction('post_registration');
  await harness.signNearTransaction('step_up_required');
});
