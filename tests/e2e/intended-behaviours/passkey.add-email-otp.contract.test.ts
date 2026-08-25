import { intendedTest as test } from './harness';

/**
 * Refactor 109C: one product action, the `passkey_to_email_otp` branch.
 *
 * A wallet that unlocks with a passkey gains an Email OTP method on the same
 * authority. The caller names an address; the wallet asks for the code.
 */
test('a passkey wallet can add an email code as a second way in', async ({ harness }) => {
  await harness.registerPasskeyWallet();
  await harness.awaitNearReady();
  await harness.addEmailOtpAuthMethod();
  /* Both families are active now, so the same addition again must be refused
     off the existing inventory rather than costing another code. */
  await harness.assertRepeatAdditionIsAlreadyConfigured('addEmailOtpAuthMethod');
  /* A method added after registration is still a method: locking must strand it
     across a reload exactly as it strands the one the wallet was created with. */
  await harness.assertLockedPageReloadStaysLocked();
  await harness.unlockWithAddedEmailOtp();
  /* Every signer family the wallet has, then every key family it can export.
     An added method that can only reach one of them is not a second way in -
     and reaching them costs one code, because the method names its own
     authority rather than inheriting whichever one the wallet has selected. */
  await harness.signNearTransaction('post_unlock');
  await harness.exportEd25519Key();
  await harness.signTempoTransaction('post_unlock');
  await harness.exportEcdsaKey();
});
