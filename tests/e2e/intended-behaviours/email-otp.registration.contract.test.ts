import { intendedTest as test } from './harness';

test('Email OTP registration lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.signNearTransaction('post_registration');
  await harness.signTempoTransaction('post_registration');
  await harness.signArcEvmTransaction('post_registration');
  await harness.exhaustSigningBudget();
  await harness.signNearTransaction('after_step_up');
  await harness.signTempoTransaction('after_step_up');
  await harness.exportEd25519Key();
  await harness.exportEcdsaKey();
});
