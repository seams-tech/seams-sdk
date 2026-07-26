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

async function verifyExactTransportRetry({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.registerPasskeyEd25519YaoWalletWithExactTransportRetry();
  await harness.assertNearDemoSigningActionable();
  await harness.signNearTransaction('post_registration');
}

test(
  'uncertain Router transport replays the exact admitted request and completes',
  verifyExactTransportRetry,
);

async function verifyTerminalFailureWithoutRetry({
  harness,
}: {
  harness: IntendedBehaviourHarness;
}): Promise<void> {
  await harness.assertPasskeyEd25519YaoTerminalFailureWithoutRetry();
}

test('terminal burned execution fails without retry', verifyTerminalFailureWithoutRetry);
