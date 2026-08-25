import { intendedTest as test } from './harness';

/**
 * Refactor 109C, signer-profile matrix.
 *
 * The two transition contracts both run on combined wallets, where every
 * addition has an ECDSA capability to carry forward and an Ed25519 signer to
 * inherit. Those are the easy shapes. A wallet that owns only one family is
 * where the addition can quietly assume the other exists, so each cell here
 * proves the addition completes on a wallet missing a family rather than
 * proving the operating path again.
 */
test('an Ed25519-only wallet gains an Email OTP method', async ({ harness }) => {
  await harness.registerPasskeyEd25519YaoWallet();
  /* No ECDSA capability exists to copy, so the continuity step has nothing to
     carry and must complete rather than fail looking for it. */
  await harness.addEmailOtpAuthMethod();
  /* And the authority still refuses a second method of the family it now has,
     on a wallet whose signer set never included ECDSA. */
  await harness.assertRepeatAdditionIsAlreadyConfigured('addEmailOtpAuthMethod');
});

test('an ECDSA-only wallet gains an Email OTP method', async ({ harness }) => {
  await harness.registerPasskeyEcdsaOnlyWallet();
  /* The mirror of the cell above: the ECDSA capability exists and the Ed25519
     signer does not, so the addition must carry the one and not go looking for
     the other. */
  await harness.addEmailOtpAuthMethod();
  await harness.assertRepeatAdditionIsAlreadyConfigured('addEmailOtpAuthMethod');
});

test('an Ed25519-only Email OTP wallet gains a passkey', async ({ harness }) => {
  await harness.registerEmailOtpEd25519OnlyWallet();
  await harness.awaitNearReady();
  /* The reverse direction on a wallet with no ECDSA: the added passkey must
     inherit the Ed25519 identity and claim no ECDSA, rather than fail on the
     capability the wallet never had. */
  await harness.addPasskeyAuthMethod();
  await harness.assertRepeatAdditionIsAlreadyConfigured('addPasskeyAuthMethod');
});
