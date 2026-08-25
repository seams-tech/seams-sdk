import { intendedTest as test } from './harness';

/**
 * Refactor 109C: one product action, the `passkey_to_email_otp` branch.
 *
 * A wallet that unlocks with a passkey gains an Email OTP method on the same
 * authority. The caller names an address; the wallet asks for the code.
 */
test('a passkey wallet can add an email code as a second way in', async ({ harness }) => {
  await harness.registerPasskeyWallet();
  await harness.addEmailOtpAuthMethod();
});
