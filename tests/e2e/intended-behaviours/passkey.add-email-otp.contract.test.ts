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
  await harness.unlockWithAddedEmailOtp();
  /* Every signer family the wallet has, then every key family it can export.
     An added method that can only reach one of them is not a second way in. */
  await harness.signTempoTransaction('post_unlock');
  await harness.exportEcdsaKey();
  /* ECDSA only, and the reason is now specific. Ed25519 signing under a
     REGISTERED Email OTP method works (fdf67168b); this wallet's Email OTP
     method was ADDED, and an added method has no Ed25519 Yao public capability
     reference of its own. Those references carry the lane's auth binding, which
     names one exact method, so the passkey's reference cannot serve the email
     sibling. It is the Ed25519 counterpart of the ECDSA continuity copy the
     addition already performs, and it does not exist yet.

     The reverse direction covers both families, because an added passkey gets
     its Ed25519 identity through its credential binding (b81ed4de7). */
});
