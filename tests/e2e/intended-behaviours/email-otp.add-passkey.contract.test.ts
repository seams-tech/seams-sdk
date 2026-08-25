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
  /* The source removes what it just added, before anything has unlocked with
     it. That is the direction whose proof comes from the Email OTP sibling. */
  await harness.revokeSourceAuthMethod('added');
  await harness.addPasskeyAuthMethod();
  await harness.assertRepeatAdditionIsAlreadyConfigured('addPasskeyAuthMethod');
  await harness.assertLockedPageReloadStaysLocked();
  await harness.unlockWithAddedPasskey();
  /* Every signer family the wallet has, then every key family it can export.
     An added method that can only reach one of them is not a second way in. */
  await harness.signTempoTransaction('post_unlock');
  await harness.signNearTransaction('post_unlock');
  await harness.exportEcdsaKey();
  await harness.exportEd25519Key();
  /* Removing the method that did the adding is the case that matters: the
     wallet must not become unopenable because its founding credential is
     gone. Signing again afterwards is the proof it did not. */
  await harness.revokeSourceAuthMethod();
  await harness.signTempoTransaction('post_unlock');
  await harness.assertFinalAuthMethodCannotBeRevoked();
});
