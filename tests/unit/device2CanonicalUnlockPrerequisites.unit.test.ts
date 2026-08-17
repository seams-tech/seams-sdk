import { expect, test } from '@playwright/test';
import {
  buildDevice2LinkFlowHarnessV1,
  withCapturedLocalWritesV1,
  LINKED_OWNER_SIGNER_SLOT_V1,
} from './helpers/device2LinkFlow.fixtures';

/**
 * What linking has to leave behind for Device 2 to unlock as an ordinary owner.
 *
 * Canonical unlock reads three local records and refuses before it ever consults
 * the server's credential allow-list, so every one of them has to be written by
 * the enrollment itself. This owns the shape of that state — that it is complete,
 * internally consistent, and carries the wallet's real signer slot.
 *
 * It does not own the round trip. Unlocking for real needs a relay, a signing
 * engine, and a reload, and that belongs to the two-device intended-behaviour
 * contract. What this rules out is the failure that contract cannot diagnose
 * cheaply: enrollment that looks successful and leaves a device that can never
 * unlock.
 */
test('linking leaves exactly the local state canonical unlock reads', async () => {
  const harness = await buildDevice2LinkFlowHarnessV1();
  const captured = await withCapturedLocalWritesV1({}, async () => {
    const activation = await harness.reachTargetPasskeyPromptV1();
    // The temporary R102 lane path runs after the canonical commit and is not
    // stubbed here — it is what the cutover deletes. Its failure is downstream
    // of everything this asserts.
    await activation.createPasskey().catch(() => undefined);
  });

  // 1. A profile carrying the wallet's own slot. Unlock parses this with a
  //    minimum of 1 and fails closed, and the profile writer silently defaults
  //    to 1 — so a wallet keyed elsewhere would unlock nothing.
  expect(captured.profiles.length).toBe(1);
  expect(captured.profiles[0]?.defaultSignerSlot).toBe(LINKED_OWNER_SIGNER_SLOT_V1);
  expect(LINKED_OWNER_SIGNER_SLOT_V1).not.toBe(1);

  // 2. An authenticator, at the same slot, that unlock can turn into an
  //    allow-list entry.
  expect(captured.authenticators.length).toBe(1);
  expect(captured.authenticators[0]?.signerSlot).toBe(LINKED_OWNER_SIGNER_SLOT_V1);

  // 3. An active auth method naming that same credential. Unlock intersects the
  //    two, so a mismatch here reads as "no active passkey binding" — which is
  //    indistinguishable from a device someone revoked.
  expect(captured.authMethods.length).toBe(1);
  expect(captured.authMethods[0]?.status).toBe('active');
  expect(captured.authMethods[0]?.credentialIdB64u).toBe(captured.authenticators[0]?.credentialId);

  // All three are keyed on the wallet id, which is the subject unlock looks up.
  const profileId = captured.profiles[0]?.profileId;
  expect(captured.authenticators[0]?.profileId).toBe(profileId);
  expect(captured.authMethods[0]?.walletId).toBe(profileId);
});

test('the canonical enrollment completes before the temporary lane path runs', async () => {
  const harness = await buildDevice2LinkFlowHarnessV1();
  const captured = await withCapturedLocalWritesV1({}, async () => {
    const activation = await harness.reachTargetPasskeyPromptV1();
    await activation.createPasskey().catch(() => undefined);
  });

  // One WebAuthn create, and no assertion: Device 1's approval prompt already
  // produced the PRF that sealed the custody transfer, so linking stays at one
  // prompt per device.
  expect(harness.calls.filter((call) => call === 'target-passkey').length).toBe(1);

  // The R102 lane path is stubbed to fail, and every local record still landed.
  // That is the precondition for the cutover: Device 2's canonical identity does
  // not depend on the lanes about to be deleted.
  expect(harness.calls).toContain('credential');
  expect(captured.profiles.length).toBe(1);
  expect(captured.authenticators.length).toBe(1);
  expect(captured.authMethods.length).toBe(1);
});
