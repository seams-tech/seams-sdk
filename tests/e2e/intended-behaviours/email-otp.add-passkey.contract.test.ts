import { intendedTest as test } from './harness';

/**
 * Refactor 109C: one product action, the `email_otp_to_passkey` branch.
 *
 * A wallet that unlocks with Email OTP gains a Passkey method on the same
 * authority. The source Email proof and target credential are independently
 * verified by the wallet.
 */
test('an Email OTP wallet can add a passkey as a second way in', async ({ harness }) => {
  await harness.registerEmailOtpWallet();
  await harness.awaitNearReady();
  await harness.addPasskeyAuthMethod();
});
