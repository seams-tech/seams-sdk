import { expect, test } from '@playwright/test';
import { collectLinkedDeviceOwnerCustodyMaterialV1 } from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingOwnerCustody';
import { computeLinkedDeviceCustodyTransferChallengeDigestV1 } from '../../packages/shared-ts/src/device-linking/digests';
import {
  passkeyCustodyEnvelope,
  rawPasskeyFactor,
  CREDENTIAL_ID_B64U,
  OTHER_WALLET_ID,
  RP_ID,
  WALLET_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * Device 1 releases the factor secret that opens the wallet custody envelope.
 * The two ways that goes wrong are releasing it for an envelope it does not
 * open, and leaving it in memory when nothing consumed it. These own both.
 */
function recipient(overrides: Record<string, unknown> = {}) {
  return {
    kind: 'linked_device_custody_transfer_recipient_v1' as const,
    linkSessionId: 'link-session:custody',
    walletId: WALLET_ID,
    enrollmentId: 'enrollment:custody',
    deviceId: 'device:custody',
    transferAlg: 'linked_device_custody_transfer_hpke_v1',
    recipientPublicKeyB64u: 'F2gjmLHjMV2Xrfs2Z4A-Wa-HNdXVcZ0JvVowpZ-EdYg',
    registeredAtMs: 1_800_000_000_000,
    ...overrides,
  } as never;
}

function collaborators(resolved: Record<string, unknown>, secret: Uint8Array) {
  return {
    resolveOwnerCustodyForCredentialV1: async () => ({
      envelope: passkeyCustodyEnvelope(),
      credentialIdB64u: CREDENTIAL_ID_B64U,
      rpId: RP_ID,
      factorSecret: secret,
      ...resolved,
    }),
  };
}

test('binds the released material to the exact transfer it was collected for', async () => {
  const secret = new Uint8Array(32).fill(9);
  const material = await collectLinkedDeviceOwnerCustodyMaterialV1(collaborators({}, secret), {
    recipient: recipient(),
    addAuthMethodCeremonyId: 'ceremony:custody',
  });
  expect(material.operationChallengeDigestB64u).toBe(
    await computeLinkedDeviceCustodyTransferChallengeDigestV1({
      kind: 'linked_device_custody_transfer_challenge_v1',
      walletId: WALLET_ID,
      linkSessionId: 'link-session:custody',
      enrollmentId: 'enrollment:custody',
      deviceId: 'device:custody',
      recipientPublicKeyB64u: 'F2gjmLHjMV2Xrfs2Z4A-Wa-HNdXVcZ0JvVowpZ-EdYg',
      addAuthMethodCeremonyId: 'ceremony:custody',
    }),
  );
  // A different recipient key is a different operation, so a different digest.
  const substituted = await collectLinkedDeviceOwnerCustodyMaterialV1(
    collaborators({}, new Uint8Array(32).fill(9)),
    {
      recipient: recipient({
        recipientPublicKeyB64u: 'z3KMzouSmH9mU3LnG8sW6h4muhYGNtxFD3G67ivvDxU',
      }),
      addAuthMethodCeremonyId: 'ceremony:custody',
    },
  );
  expect(substituted.operationChallengeDigestB64u).not.toBe(material.operationChallengeDigestB64u);
});

test('refuses an envelope the asserted credential does not open, and zeroizes', async () => {
  for (const mismatch of [
    { envelope: passkeyCustodyEnvelope({ walletId: OTHER_WALLET_ID }) },
    {
      envelope: passkeyCustodyEnvelope({
        factor: rawPasskeyFactor({ credentialIdB64u: 'Y3JlZGVudGlhbC1vdGhlcg' }),
      }),
    },
    {
      envelope: passkeyCustodyEnvelope({
        factor: rawPasskeyFactor({ rpId: 'attacker.example.localhost' }),
      }),
    },
  ]) {
    const secret = new Uint8Array(32).fill(9);
    await expect(
      collectLinkedDeviceOwnerCustodyMaterialV1(collaborators(mismatch, secret), {
        recipient: recipient(),
        addAuthMethodCeremonyId: 'ceremony:custody',
      }),
    ).rejects.toThrow();
    // Nothing downstream received it, so it must not still be readable.
    expect([...secret].every((byte) => byte === 0)).toBe(true);
  }
});
