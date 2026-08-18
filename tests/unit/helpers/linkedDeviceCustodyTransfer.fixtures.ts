/**
 * Builders for the Refactor 103 Phase 8 cross-device custody transfer wire
 * records. Both construct through the production parsers, so a change to the
 * contract surfaces here as a parse failure rather than as a fixture that
 * quietly encodes the old shape.
 */
import {
  LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
  parseLinkedDeviceCustodyTransferPackageV1,
  parseLinkedDeviceCustodyTransferRecipientV1,
  type LinkedDeviceCustodyTransferPackageV1,
  type LinkedDeviceCustodyTransferRecipientV1,
} from '../../../packages/shared-ts/src/device-linking/custodyTransfer';
import type { UnlockedWalletCustodyTransferCapabilityV1 } from '../../../packages/wallet/src/core/signingEngine/workerManager/workerTypes';
import { base64UrlEncode } from '../../../packages/shared-ts/src/utils/base64';

function publicKey(fill: number): string {
  return base64UrlEncode(new Uint8Array(32).fill(fill));
}

export const LINKED_DEVICE_TRANSFER_RECIPIENT_PUBLIC_KEY_B64U = publicKey(21);
export const LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U = publicKey(31);

const NONCE_B64U = base64UrlEncode(new Uint8Array(12).fill(4));
/** 32 bytes of sealed seed plus the 16-byte Poly1305 tag. */
const CIPHERTEXT_B64U = base64UrlEncode(new Uint8Array(48).fill(9));
const AAD_HASH_B64U = base64UrlEncode(new Uint8Array(32).fill(5));
const CIPHERTEXT_DIGEST_B64U = base64UrlEncode(new Uint8Array(32).fill(6));

export const LINKED_DEVICE_TRANSFER_SEALED_AT_MS = 1_800_000_000_000;

/**
 * R103 zero-prompt handoff: Device 1's unlocked custody transfer capability
 * reference. Opaque by construction — a plain record whose facts the worker
 * re-verifies — so the fixture is a literal aligned with the shared session
 * fixtures rather than a parser round-trip.
 */
export function buildUnlockedCustodyCapabilityFixtureV1(
  overrides: Partial<UnlockedWalletCustodyTransferCapabilityV1> = {},
): UnlockedWalletCustodyTransferCapabilityV1 {
  return {
    kind: 'unlocked_wallet_custody_transfer_capability_v1',
    capabilityHandleId: 'unlocked-custody-capability-fixture',
    walletId: 'alice.testnet',
    walletAuthMethodId: 'passkey:wallet.example.test:Y3JlZGVudGlhbC1maXJzdA',
    walletSessionId: 'available-lane-wallet-session:owner-authorization',
    expiresAtMs: LINKED_DEVICE_TRANSFER_SEALED_AT_MS,
    ...overrides,
  };
}

export type LinkedDeviceCustodyTransferFixtureOverridesV1 = {
  readonly walletId?: string;
  readonly enrollmentId?: string;
  readonly deviceId?: string;
  readonly recipientPublicKeyB64u?: string;
};

export function buildLinkedDeviceCustodyTransferRecipientFixtureV1(
  overrides: LinkedDeviceCustodyTransferFixtureOverridesV1 & {
    readonly linkSessionId?: string;
  } = {},
): LinkedDeviceCustodyTransferRecipientV1 {
  return parseLinkedDeviceCustodyTransferRecipientV1({
    kind: 'linked_device_custody_transfer_recipient_v1',
    linkSessionId: overrides.linkSessionId ?? 'link-session:r103p8',
    walletId: overrides.walletId ?? 'alice.testnet',
    enrollmentId: overrides.enrollmentId ?? 'enrollment:device-2',
    deviceId: overrides.deviceId ?? 'device:2',
    transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
    recipientPublicKeyB64u:
      overrides.recipientPublicKeyB64u ?? LINKED_DEVICE_TRANSFER_RECIPIENT_PUBLIC_KEY_B64U,
    registeredAtMs: LINKED_DEVICE_TRANSFER_SEALED_AT_MS,
  });
}

export function buildLinkedDeviceCustodyTransferPackageFixtureV1(
  overrides: LinkedDeviceCustodyTransferFixtureOverridesV1 & {
    readonly ephemeralPublicKeyB64u?: string;
  } = {},
): LinkedDeviceCustodyTransferPackageV1 {
  return parseLinkedDeviceCustodyTransferPackageV1({
    kind: 'linked_device_custody_transfer_package_v1',
    walletId: overrides.walletId ?? 'alice.testnet',
    enrollmentId: overrides.enrollmentId ?? 'enrollment:device-2',
    deviceId: overrides.deviceId ?? 'device:2',
    transferAlg: LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
    recipientPublicKeyB64u:
      overrides.recipientPublicKeyB64u ?? LINKED_DEVICE_TRANSFER_RECIPIENT_PUBLIC_KEY_B64U,
    ephemeralPublicKeyB64u:
      overrides.ephemeralPublicKeyB64u ?? LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U,
    nonceB64u: NONCE_B64U,
    sealedCustodySecretB64u: CIPHERTEXT_B64U,
    aadHashB64u: AAD_HASH_B64U,
    ciphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
    sealedAtMs: LINKED_DEVICE_TRANSFER_SEALED_AT_MS,
  });
}
