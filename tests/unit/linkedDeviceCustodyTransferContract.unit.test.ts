import { expect, test } from '@playwright/test';
import {
  LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1,
  buildLinkedDeviceCustodyTransferBindingV1,
  linkedDeviceCustodyTransferMatchesRecipientV1,
  parseLinkedDeviceCustodyTransferPackageV1,
  parseLinkedDeviceCustodyTransferPublicKeyB64u,
  parseLinkedDeviceCustodyTransferRecipientV1,
  parseLinkedDeviceCustodyTransferSecretBindingV1,
  parseLinkedDeviceCustodyTransferSubmissionV1,
  serializeLinkedDeviceCustodyTransferBindingV1,
} from '../../packages/shared-ts/src/device-linking/custodyTransfer';
import { WALLET_SEED_DERIVATION_SCHEME_V1 } from '../../packages/shared-ts/src/passkey-custody/custodySecretBinding';
import {
  buildLinkedDeviceCustodyTransferPackageFixtureV1,
  buildLinkedDeviceCustodyTransferRecipientFixtureV1,
  LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U,
  LINKED_DEVICE_TRANSFER_RECIPIENT_PUBLIC_KEY_B64U,
} from './helpers/linkedDeviceCustodyTransfer.fixtures';

/**
 * The exact bytes the wasm boundary receives. `LinkedDeviceCustodyTransferBindingV1`
 * is `deny_unknown_fields` in Rust and is authenticated as AEAD additional
 * data, so field names, nesting, and the absence of extras are part of the
 * cryptographic contract rather than a formatting detail. The Rust half pins
 * this same literal in
 * `crates/signer-core/tests/linked_device_custody_transfer_wire.rs`.
 */
const EXPECTED_BINDING_JSON =
  '{"walletId":"alice.testnet","enrollmentId":"enrollment:device-2","deviceId":"device:2",' +
  `"recipientPublicKeyB64u":"${LINKED_DEVICE_TRANSFER_RECIPIENT_PUBLIC_KEY_B64U}",` +
  '"binding":{"kind":"wallet_custody_seed_v1","derivationScheme":"wallet_seed_parallel_hkdf_sha256_v1"}}';

function transferBinding() {
  const recipient = buildLinkedDeviceCustodyTransferRecipientFixtureV1();
  return buildLinkedDeviceCustodyTransferBindingV1({
    walletId: recipient.walletId,
    enrollmentId: recipient.enrollmentId,
    deviceId: recipient.deviceId,
    recipientPublicKeyB64u: recipient.recipientPublicKeyB64u,
    binding: parseLinkedDeviceCustodyTransferSecretBindingV1({
      kind: 'wallet_custody_seed_v1',
      derivationScheme: WALLET_SEED_DERIVATION_SCHEME_V1,
    }),
  });
}

test('the transfer binding serializes to exactly the fields the wasm boundary accepts', () => {
  expect(serializeLinkedDeviceCustodyTransferBindingV1(transferBinding())).toBe(
    EXPECTED_BINDING_JSON,
  );
  // Round-trips as plain JSON with no extra keys on either level.
  const parsed: unknown = JSON.parse(EXPECTED_BINDING_JSON);
  expect(Object.keys(parsed as Record<string, unknown>)).toEqual([
    'walletId',
    'enrollmentId',
    'deviceId',
    'recipientPublicKeyB64u',
    'binding',
  ]);
});

test('the transfer carries the wallet custody seed binding and refuses lane-scoped ones', () => {
  expect(
    parseLinkedDeviceCustodyTransferSecretBindingV1({
      kind: 'wallet_custody_seed_v1',
      derivationScheme: WALLET_SEED_DERIVATION_SCHEME_V1,
    }).kind,
  ).toBe('wallet_custody_seed_v1');

  expect(() =>
    parseLinkedDeviceCustodyTransferSecretBindingV1({
      kind: 'ed25519_lane_holder_share_v1',
      walletKeyId: 'wallet-key:ed25519:alice.testnet:root-1:v1',
      laneId: 'lane:owner:ed25519:1',
      laneShareEpoch: 'lane-share-epoch-1',
      nearEd25519SigningKeyId: 'near-key:1',
      registeredPublicKeyB64u: 'A'.repeat(43),
      participantBindingDigestB64u: 'A'.repeat(43),
    }),
  ).toThrow(/must be the wallet custody seed binding/);
});

test('a recipient registration round-trips and rejects a non-X25519 key', () => {
  const recipient = buildLinkedDeviceCustodyTransferRecipientFixtureV1();
  expect(parseLinkedDeviceCustodyTransferRecipientV1(recipient)).toEqual(recipient);
  expect(recipient.transferAlg).toBe(LINKED_DEVICE_CUSTODY_TRANSFER_ALG_V1);

  expect(() =>
    parseLinkedDeviceCustodyTransferPublicKeyB64u('AAAA', 'recipientPublicKeyB64u'),
  ).toThrow(/32-byte X25519 public key/);
  expect(() =>
    parseLinkedDeviceCustodyTransferRecipientV1({ ...recipient, transferAlg: 'other-alg' }),
  ).toThrow(/must be x25519-hkdf-sha256-chacha20poly1305-v1/);
});

test('a sealed package round-trips and fails closed on shape drift', () => {
  const sealed = buildLinkedDeviceCustodyTransferPackageFixtureV1();
  expect(parseLinkedDeviceCustodyTransferPackageV1(sealed)).toEqual(sealed);

  // An extra field would change the AAD the Rust side recomputes, so the
  // boundary rejects it rather than dropping it.
  expect(() =>
    parseLinkedDeviceCustodyTransferPackageV1({ ...sealed, keyManifestDigestB64u: 'A'.repeat(43) }),
  ).toThrow(/LinkedDeviceCustodyTransferPackageV1/);

  expect(() =>
    parseLinkedDeviceCustodyTransferPackageV1({
      ...sealed,
      ephemeralPublicKeyB64u: sealed.recipientPublicKeyB64u,
    }),
  ).toThrow(/repeats the recipient key/);

  const { sealedAtMs: _omitted, ...withoutTimestamp } = sealed;
  expect(() => parseLinkedDeviceCustodyTransferPackageV1(withoutTimestamp)).toThrow(
    /sealedAtMs is required/,
  );
});

test('a package is matched to its exact recipient registration before decryption', () => {
  const recipient = buildLinkedDeviceCustodyTransferRecipientFixtureV1();
  const sealed = buildLinkedDeviceCustodyTransferPackageFixtureV1();
  expect(linkedDeviceCustodyTransferMatchesRecipientV1(sealed, recipient)).toBe(true);

  const otherDevice = buildLinkedDeviceCustodyTransferRecipientFixtureV1({
    deviceId: 'device:3',
  });
  expect(linkedDeviceCustodyTransferMatchesRecipientV1(sealed, otherDevice)).toBe(false);

  const otherKey = buildLinkedDeviceCustodyTransferRecipientFixtureV1({
    recipientPublicKeyB64u: LINKED_DEVICE_TRANSFER_EPHEMERAL_PUBLIC_KEY_B64U,
  });
  expect(linkedDeviceCustodyTransferMatchesRecipientV1(sealed, otherKey)).toBe(false);
});

test('a submission binds its package to the link session that carried it', () => {
  const sealed = buildLinkedDeviceCustodyTransferPackageFixtureV1();
  const submission = {
    kind: 'linked_device_custody_transfer_submission_v1' as const,
    linkSessionId: 'link-session:r103p8',
    package: sealed,
  };
  expect(parseLinkedDeviceCustodyTransferSubmissionV1(submission)).toEqual(submission);
  expect(() =>
    parseLinkedDeviceCustodyTransferSubmissionV1({ ...submission, linkSessionId: '' }),
  ).toThrow(/linkSessionId must be a non-empty canonical string/);
});
