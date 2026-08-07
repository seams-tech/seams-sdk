import {
  EMAIL_OTP_FACTOR_KEK_VERSION_V1,
  PASSKEY_PRF_KEK_VERSION_V1,
  WALLET_CUSTODY_ENVELOPE_VERSION_V2,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
  type PasskeyCustodySecretKind,
} from '@shared/passkey-custody';

/**
 * Raw boundary shapes for passkey custody records.
 *
 * These are deliberately `Record<string, unknown>` rather than typed records:
 * the tests they serve exercise the parse boundary, which must accept and
 * reject untyped persistence rows and wire payloads. Typed construction is
 * covered by the branch-specific builders and the static fixtures in
 * `packages/shared-ts/src/passkey-custody/passkeyCustody.typecheck.ts`.
 */
export type RawRecord = Record<string, unknown>;

// Canonical unpadded base64url over deterministic byte sequences.
export const DIGEST_B64U = 'AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA';
export const ALT_DIGEST_B64U = 'ZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1-f4CBgoM';
export const NONCE_12_B64U = 'AQIDBAUGBwgJCgsM';
export const CIPHERTEXT_B64U = 'BwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2';
/**
 * SHA-256 over the decoded `CIPHERTEXT_B64U`. Envelopes must be internally
 * consistent so they pass the server store's stored-ciphertext digest check;
 * tests that want a corrupt row pass a mismatched digest explicitly.
 */
export const CIPHERTEXT_DIGEST_B64U = 'GDwUe-76hc4lJXJ3vyFwZWyL0jf_Kk8TXYlyKfS1vHE';
export const ED25519_PUBLIC_KEY_B64U = 'MjM0NTY3ODk6Ozw9Pj9AQUJDREVGR0hJSktMTU5PUFE';
export const SECP256K1_PUBLIC_KEY_B64U = 'AgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4fICEi';
export const ALT_SECP256K1_PUBLIC_KEY_B64U = 'AwkKCwwNDg8QERITFBUWFxgZGhscHR4fICEiIyQlJico';

export const WALLET_ID = 'alice.testnet';
export const OTHER_WALLET_ID = 'mallory.testnet';
export const ENVELOPE_ID = 'passkey-envelope-1';
export const RP_ID = 'wallet.example.localhost';
export const CREDENTIAL_ID_B64U = 'Y3JlZGVudGlhbC0x';
export const NEAR_ED25519_SIGNING_KEY_ID = 'near-ed25519-key-1';
export const ENROLLMENT_ID = 'enrollment-1';
export const THRESHOLD_ECDSA_SESSION_ID = 'threshold-ecdsa-session-1';
export const RECOVERY_KEY_ID = `email-otp-rkid-v1-${DIGEST_B64U}`;

export const ED25519_WALLET_KEY_ID = 'wallet-key:ed25519:alice.testnet:root-1:v1';
export const EVM_WALLET_KEY_ID = 'wallet-key:evm-family:alice.testnet:root-1:v1';
export const EVM_FAMILY_SIGNING_KEY_SLOT_ID = EVM_WALLET_KEY_ID;
export const ED25519_LANE_ID = 'lane:owner:ed25519:1';
export const EVM_LANE_ID = 'lane:owner:evm-family:1';
export const LANE_SHARE_EPOCH = 'lane-share-epoch-1';

/** Owner custody: one wallet-scoped seed every owner root derives from. */
export function rawWalletCustodySeedBinding(overrides: RawRecord = {}): RawRecord {
  return {
    kind: 'wallet_custody_seed_v1',
    derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
    keyManifestDigestB64u: DIGEST_B64U,
    nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
    registeredPublicKeyB64u: ED25519_PUBLIC_KEY_B64U,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    clientRootPublicKey33B64u: SECP256K1_PUBLIC_KEY_B64U,
    ...overrides,
  };
}

export function rawEd25519LaneHolderShareBinding(overrides: RawRecord = {}): RawRecord {
  return {
    kind: 'ed25519_lane_holder_share_v1',
    walletKeyId: ED25519_WALLET_KEY_ID,
    laneId: ED25519_LANE_ID,
    laneShareEpoch: LANE_SHARE_EPOCH,
    nearEd25519SigningKeyId: NEAR_ED25519_SIGNING_KEY_ID,
    registeredPublicKeyB64u: ED25519_PUBLIC_KEY_B64U,
    participantBindingDigestB64u: ALT_DIGEST_B64U,
    ...overrides,
  };
}

export function rawEcdsaLaneHolderShareBinding(overrides: RawRecord = {}): RawRecord {
  return {
    kind: 'ecdsa_lane_holder_share_v1',
    walletKeyId: EVM_WALLET_KEY_ID,
    laneId: EVM_LANE_ID,
    laneShareEpoch: LANE_SHARE_EPOCH,
    evmFamilySigningKeySlotId: EVM_FAMILY_SIGNING_KEY_SLOT_ID,
    thresholdSessionId: THRESHOLD_ECDSA_SESSION_ID,
    thresholdPublicKey33B64u: ALT_SECP256K1_PUBLIC_KEY_B64U,
    ...overrides,
  };
}

export function rawActiveEnvelopeLifecycle(overrides: RawRecord = {}): RawRecord {
  return { state: 'active', activatedAtMs: 1_000, ...overrides };
}

export function rawPasskeyFactor(overrides: RawRecord = {}): RawRecord {
  return {
    kind: 'passkey',
    rpId: RP_ID,
    credentialIdB64u: CREDENTIAL_ID_B64U,
    kekVersion: PASSKEY_PRF_KEK_VERSION_V1,
    ...overrides,
  };
}

export function rawEmailOtpFactor(overrides: RawRecord = {}): RawRecord {
  return {
    kind: 'email_otp',
    enrollmentId: ENROLLMENT_ID,
    enrollmentSealKeyVersion: 'seal-v1',
    kekVersion: EMAIL_OTP_FACTOR_KEK_VERSION_V1,
    ...overrides,
  };
}

export function rawPasskeyCustodyEnvelope(overrides: RawRecord = {}): RawRecord {
  return {
    kind: WALLET_CUSTODY_ENVELOPE_VERSION_V2,
    envelopeId: ENVELOPE_ID,
    walletId: WALLET_ID,
    binding: rawWalletCustodySeedBinding(),
    factor: rawPasskeyFactor(),
    envelopeVersion: WALLET_CUSTODY_ENVELOPE_VERSION_V2,
    envelopeRevision: 1,
    nonceB64u: NONCE_12_B64U,
    sealedCustodySecretB64u: CIPHERTEXT_B64U,
    ciphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
    aadHashB64u: ALT_DIGEST_B64U,
    lifecycle: rawActiveEnvelopeLifecycle(),
    createdAtMs: 1_000,
    updatedAtMs: 2_000,
    ...overrides,
  };
}

export function rawWalletRecoveryEnvelopeEntry(
  custodySecretKind: PasskeyCustodySecretKind = 'wallet_custody_seed_v1',
  overrides: RawRecord = {},
): RawRecord {
  return {
    custodySecretKind,
    nonceB64u: NONCE_12_B64U,
    wrappedCustodySecretB64u: CIPHERTEXT_B64U,
    aadHashB64u: DIGEST_B64U,
    ...overrides,
  };
}

export function rawManifestKekWrap(overrides: RawRecord = {}): RawRecord {
  return {
    recoveryKeyId: RECOVERY_KEY_ID,
    nonceB64u: NONCE_12_B64U,
    wrappedManifestKekB64u: CIPHERTEXT_B64U,
    aadHashB64u: ALT_DIGEST_B64U,
    lifecycle: { state: 'active', issuedAtMs: 1_000 },
    ...overrides,
  };
}

export function rawWalletRecoveryEnvelopeSet(overrides: RawRecord = {}): RawRecord {
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: WALLET_ID,
    keyManifestDigestB64u: DIGEST_B64U,
    manifestKekWraps: [rawManifestKekWrap()],
    entries: [rawWalletRecoveryEnvelopeEntry()],
    issuedAtMs: 1_000,
    updatedAtMs: 2_000,
    ...overrides,
  };
}

/**
 * A parsed envelope record. Built by running the raw shape through the real
 * boundary parser, so a fixture can never encode a record the parser rejects.
 */
export function passkeyCustodyEnvelope(overrides: RawRecord = {}): PasskeyCustodyEnvelopeRecord {
  return parsePasskeyCustodyEnvelopeRecord(rawPasskeyCustodyEnvelope(overrides));
}
