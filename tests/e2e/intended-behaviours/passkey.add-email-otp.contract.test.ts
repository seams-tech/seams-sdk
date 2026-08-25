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
  /* ECDSA only, pending one entry point. The Ed25519 request is made by
     `unlockLinkedDeviceEmailOtpWallet`, which today is reachable only as a
     dependency of the Google-backed flow; the address-based path this contract
     uses goes through `loginWithEmailOtpEcdsaCapability`, which never asks for
     Ed25519. The authority-scoped request now exists on the first function and
     starts working the moment an address-based caller can reach it. */
});
