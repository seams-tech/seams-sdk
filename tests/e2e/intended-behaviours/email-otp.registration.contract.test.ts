import { intendedTest as test } from './harness';

test('Email OTP registration lifecycle', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.signTempoTransaction('post_registration');
  await harness.signArcEvmTransaction('post_registration');
  await harness.exportEcdsaKey();
  await harness.awaitNearReady();
  await harness.signNearTransaction('post_registration');
  await harness.exportEd25519Key();
});
