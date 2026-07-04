import { intendedTest as test } from './harness';

test('Email OTP unlock lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.unlockEmailOtpWallet();
  await harness.signNearTransaction('post_unlock');
  await harness.signTempoTransaction('post_unlock');
  await harness.signArcEvmTransaction('post_unlock');
  await harness.exhaustSigningBudget();
  await harness.signNearTransaction('after_step_up');
  await harness.signTempoTransaction('after_step_up');
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
});
