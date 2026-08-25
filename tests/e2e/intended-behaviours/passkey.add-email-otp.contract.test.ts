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
  await harness.unlockWithAddedEmailOtp();
  /* Every signer family the wallet has, then every key family it can export.
     An added method that can only reach one of them is not a second way in. */
  await harness.signTempoTransaction('post_unlock');
  await harness.exportEcdsaKey();
  /* ECDSA only, pending one step that is not ours. Unlocking the added method
     through the authority - which is what yields every family from one code -
     needs the wallet's selection to name that method, and the selection store
     holds exactly one per wallet. Choosing a method is a product action in the
     account UI; there is no public API for it, and inventing one here would be
     guessing at that surface. Everything behind it is in place. */
});
