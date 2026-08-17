import { expect, test } from '@playwright/test';
import {
  acceptLinkedDeviceCustodyTransferV1,
  publishLinkedDeviceCustodyRecipientV1,
} from '../../packages/sdk-web/src/SeamsWeb/operations/devices/deviceLinkingTargetCustodyTransfer';
import {
  parseWebAuthnCredentialIdB64u,
  parseWebAuthnRpId,
} from '../../packages/shared-ts/src/utils/domainIds';
import {
  ALT_DIGEST_B64U,
  CIPHERTEXT_B64U,
  CIPHERTEXT_DIGEST_B64U,
  CREDENTIAL_ID_B64U,
  NONCE_12_B64U,
  RP_ID,
  WALLET_ID,
} from './helpers/passkeyCustodyEnvelope.fixtures';

/**
 * Device 2 publishes a recipient key, waits for Device 1 to seal the wallet
 * custody seed to it, then reseals under its own new passkey. The failure modes
 * that matter are a live recipient key left behind when nobody will ever seal
 * to it, and accepting a package addressed somewhere else.
 */
const LINK_SESSION_ID = 'linkdev_00000000000000000000000000';
const ENROLLMENT_ID = 'lnkenr_00000000000000000000000000';
const DEVICE_ID = 'lnkdev_00000000000000000000000000';
const RECIPIENT_KEY_B64U = 'F2gjmLHjMV2Xrfs2Z4A-Wa-HNdXVcZ0JvVowpZ-EdYg';
const EPHEMERAL_KEY_B64U = 'z3KMzouSmH9mU3LnG8sW6h4muhYGNtxFD3G67ivvDxU';

function rpId() {
  const parsed = parseWebAuthnRpId(RP_ID);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function credentialId() {
  const parsed = parseWebAuthnCredentialIdB64u(CREDENTIAL_ID_B64U);
  if (!parsed.ok) throw new Error(parsed.error.message);
  return parsed.value;
}

function recipientHandle(overrides: Record<string, unknown> = {}) {
  return {
    recipientHandleId: 'recipient-handle-1',
    registration: {
      kind: 'linked_device_custody_transfer_recipient_v1',
      linkSessionId: LINK_SESSION_ID,
      walletId: WALLET_ID,
      enrollmentId: ENROLLMENT_ID,
      deviceId: DEVICE_ID,
      transferAlg: 'linked_device_custody_transfer_hpke_v1',
      recipientPublicKeyB64u: RECIPIENT_KEY_B64U,
      registeredAtMs: 1_800_000_000_000,
      ...overrides,
    },
  } as never;
}

function transferPackage(overrides: Record<string, unknown> = {}) {
  return {
    kind: 'linked_device_custody_transfer_package_v1',
    walletId: WALLET_ID,
    enrollmentId: ENROLLMENT_ID,
    deviceId: DEVICE_ID,
    transferAlg: 'linked_device_custody_transfer_hpke_v1',
    recipientPublicKeyB64u: RECIPIENT_KEY_B64U,
    ephemeralPublicKeyB64u: EPHEMERAL_KEY_B64U,
    nonceB64u: NONCE_12_B64U,
    sealedCustodySecretB64u: CIPHERTEXT_B64U,
    aadHashB64u: ALT_DIGEST_B64U,
    ciphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
    sealedAtMs: 1_800_000_000_001,
    ...overrides,
  };
}

/** A resealed envelope's ciphertext, as the worker hands it back. */
function resealed() {
  return {
    nonceB64u: NONCE_12_B64U,
    sealedCustodySecretB64u: CIPHERTEXT_B64U,
    aadHashB64u: ALT_DIGEST_B64U,
    ciphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
  };
}

function acceptInput(overrides: Record<string, unknown> = {}) {
  return {
    recipient: recipientHandle(),
    rpId: rpId(),
    credentialIdB64u: credentialId(),
    replacementFactorSecret: new Uint8Array(32).fill(7),
    expiresAtMs: 2_000,
    assertCurrentRun: () => undefined,
    waitForPollV1: async () => undefined,
    nowMs: () => 1_000,
    ...overrides,
  } as never;
}

test('discards the recipient key when nobody will ever be able to seal to it', async () => {
  const discarded: string[] = [];
  await expect(
    publishLinkedDeviceCustodyRecipientV1({
      custodyTransfer: {
        createRecipientV1: async () => recipientHandle(),
        discardRecipientV1: async (recipient) => {
          discarded.push(recipient.recipientHandleId);
        },
      },
      transport: {
        registerCustodyTransferRecipientV1: async () => {
          throw new Error('link session rejected the recipient');
        },
      },
      identity: {
        linkSessionId: LINK_SESSION_ID,
        walletId: WALLET_ID,
        enrollmentId: ENROLLMENT_ID,
        deviceId: DEVICE_ID,
      },
      registeredAtMs: 1_800_000_000_000,
    } as never),
  ).rejects.toThrow('link session rejected the recipient');
  expect(discarded).toEqual(['recipient-handle-1']);
});

test('waits for the seal, then reseals the seed under this device passkey', async () => {
  // Two empty polls first: Device 1 seals on its own approval loop, so an
  // absent package is the normal state rather than a failure.
  const responses = [null, null, transferPackage()];
  let accepted: Record<string, unknown> | null = null;
  const envelope = await acceptLinkedDeviceCustodyTransferV1(
    acceptInput({
      custodyTransfer: {
        acceptTransferV1: async (args: Record<string, unknown>) => {
          accepted = args;
          return resealed();
        },
      },
      transport: {
        getCustodyTransferPackageV1: async () => responses.shift() ?? null,
      },
    }),
  );
  expect(responses).toEqual([]);
  expect(String(envelope.walletId)).toBe(WALLET_ID);
  expect(envelope.factor).toMatchObject({
    kind: 'passkey',
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U,
  });
  expect(envelope.envelopeRevision).toBe(1);
  // The binding is rebuilt locally, never echoed from the relayed package.
  const binding = JSON.parse(String(accepted?.replacementEnvelopeBindingJson));
  expect(binding.binding).toEqual({
    kind: 'wallet_custody_seed_v1',
    derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
  });
  expect(binding.envelopeId).toBe(String(envelope.envelopeId));
});

test('refuses a package addressed elsewhere, and gives up at the deadline', async () => {
  const elsewhere = [
    { walletId: 'mallory.testnet' },
    { deviceId: 'lnkdev_11111111111111111111111111' },
    { recipientPublicKeyB64u: EPHEMERAL_KEY_B64U },
  ];
  for (const substitution of elsewhere) {
    await expect(
      acceptLinkedDeviceCustodyTransferV1(
        acceptInput({
          custodyTransfer: {
            acceptTransferV1: async () => {
              throw new Error('must not open a package addressed elsewhere');
            },
          },
          transport: {
            getCustodyTransferPackageV1: async () => transferPackage(substitution),
          },
        }),
      ),
    ).rejects.toThrow('addressed to another device');
  }

  // Nothing ever seals: the wait ends at the deadline rather than spinning.
  let elapsed = 0;
  await expect(
    acceptLinkedDeviceCustodyTransferV1(
      acceptInput({
        custodyTransfer: {
          acceptTransferV1: async () => {
            throw new Error('nothing was sealed');
          },
        },
        transport: { getCustodyTransferPackageV1: async () => null },
        nowMs: () => 1_000 + elapsed,
        waitForPollV1: async () => {
          elapsed += 400;
        },
      }),
    ),
  ).rejects.toThrow('expired before the wallet custody transfer was sealed');
});
