import { intendedTest as test, type IntendedBehaviourHarness } from './harness';

async function verifyLocalEd25519YaoRegistrationAndSigning({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyEd25519YaoWallet();
  await harness.assertNearDemoSigningActionable();
  await harness.signNearTransaction('post_registration');
}

test(
  'public Ed25519 Yao registration signs immediately',
  verifyLocalEd25519YaoRegistrationAndSigning,
);

async function verifyLocalEd25519YaoAddSignerAndSigning({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyEd25519YaoWallet();
  await harness.addPasskeyEd25519YaoWalletSigner();
  await harness.signNearTransaction('post_registration');
}

test(
  'public Ed25519 Yao add-signer persists and signs immediately',
  verifyLocalEd25519YaoAddSignerAndSigning,
);

async function verifyPreparedIframeEd25519YaoRegistrationAndSigning({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPreparedIframePasskeyEd25519YaoWallet();
  await harness.signNearTransaction('post_registration');
}

test(
  'public prepared iframe Ed25519 Yao registration signs immediately',
  verifyPreparedIframeEd25519YaoRegistrationAndSigning,
);
