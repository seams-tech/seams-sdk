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
  /* ECDSA only, deliberately. The Ed25519 family is not reachable through an
     Email OTP method today, and not because of this refactor:
     `email-otp.unlock.contract.test.ts` fails on its very first
     `signNearTransaction`, before any addition is involved. Asserting NEAR
     signing or Ed25519 export here would report that defect as an R109C one.
     The reverse direction, whose surviving method is a passkey, does cover
     both families. */
});
