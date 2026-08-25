import {
  EMAIL_OTP_FACTOR_KEK_VERSION_V1,
  PASSKEY_PRF_KEK_VERSION_V1,
  WALLET_CUSTODY_ENVELOPE_VERSION_V2,
  parsePasskeyCustodyEnvelopeRecord,
  type PasskeyCustodyEnvelopeRecord,
  type PasskeyCustodySecretKind,
  type WalletCustodyCeremonyCommitPayload,
  type WalletCustodyKeySetKind,
} from '@shared/passkey-custody';
import { base64UrlEncode } from '@shared/utils/base64';

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
export const COMMIT_WALLET_AUTH_METHOD_ID = 'wallet-auth-method:commit-fixture';
export const OWNING_WALLET_AUTH_METHOD_ID = 'wallet-auth-method:owner-fixture';
export const SIBLING_WALLET_AUTH_METHOD_ID = 'wallet-auth-method:sibling-fixture';
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
export const RECOVERY_KEY_ID = `wallet-rkid-v1-${DIGEST_B64U}`;
export const RECOVERY_LOCATOR_DIGEST_B64U = DIGEST_B64U;

export const ED25519_WALLET_KEY_ID = 'wallet-key:ed25519:alice.testnet:root-1:v1';
export const EVM_WALLET_KEY_ID = 'wallet-key:evm-family:alice.testnet:root-1:v1';
export const EVM_FAMILY_SIGNING_KEY_SLOT_ID = EVM_WALLET_KEY_ID;
export const ED25519_LANE_ID = 'lane:owner:ed25519:1';
export const EVM_LANE_ID = 'lane:owner:evm-family:1';
export const LANE_SHARE_EPOCH = 'lane-share-epoch-1';

/**
 * Owner custody: one wallet-scoped seed every owner root derives from.
 *
 * It names no key set. Key sets are provisioned independently and each records
 * its own manifest on its own registration state.
 */
export function rawWalletCustodySeedBinding(overrides: RawRecord = {}): RawRecord {
  return {
    kind: 'wallet_custody_seed_v1',
    derivationScheme: 'wallet_seed_parallel_hkdf_sha256_v1',
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
    /* Envelopes now record the method that owns them. `unbound` is the
       pre-109C shape, which is what a raw fixture should default to; the
       method-bound builders below are for records a live path would write. */
    ownership: { kind: 'unbound' },
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

export function buildLinkedDevicePasskeyEd25519ExportRootEnvelopeFixture(args: {
  readonly tag: string;
  readonly walletId: string;
  readonly walletKeyId: string;
  readonly registeredPublicKeyB64u: string;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly deviceId: string;
  readonly sealedFill: number;
}): PasskeyCustodyEnvelopeRecord {
  const fill = args.sealedFill & 0xff;
  return parsePasskeyCustodyEnvelopeRecord({
    kind: WALLET_CUSTODY_ENVELOPE_VERSION_V2,
    envelopeId: `envelope:${args.tag}`,
    walletId: args.walletId,
    binding: {
      kind: 'ed25519_yao_client_root_v1',
      linkSessionId: `link-session:${args.tag}`,
      walletKeyId: args.walletKeyId,
      targetFactor: { kind: 'passkey_prf' },
      applicationBindingDigestB64u: base64UrlEncode(new Uint8Array(32).fill(21)),
      registeredPublicKeyB64u: args.registeredPublicKeyB64u,
      enrollmentId: `enrollment:${args.tag}`,
      deviceId: args.deviceId,
      revocationEpoch: 0,
    },
    factor: {
      kind: 'passkey',
      rpId: args.rpId,
      credentialIdB64u: args.credentialIdB64u,
      kekVersion: PASSKEY_PRF_KEK_VERSION_V1,
    },
    envelopeVersion: WALLET_CUSTODY_ENVELOPE_VERSION_V2,
    envelopeRevision: 1,
    nonceB64u: base64UrlEncode(new Uint8Array(12).fill(23)),
    sealedCustodySecretB64u: base64UrlEncode(new Uint8Array(48).fill(fill)),
    ciphertextDigestB64u: base64UrlEncode(new Uint8Array(32).fill(fill)),
    aadHashB64u: base64UrlEncode(new Uint8Array(32).fill(24)),
    lifecycle: { state: 'active', activatedAtMs: 10 },
    createdAtMs: 10,
    updatedAtMs: 10,
  });
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

/**
 * Ten distinct wraps, because a set carries exactly ten.
 *
 * Establishment issues ten and the durable invariant keeps ten: a consumed or
 * revoked code keeps its wrap and changes its lifecycle state rather than
 * disappearing. A fixture with one wrap described a set that cannot exist.
 */
export function rawManifestKekWrapSet(): RawRecord[] {
  return Array.from({ length: 10 }, (_, index) =>
    rawManifestKekWrap({
      recoveryKeyId: `wallet-rkid-v1-${DIGEST_B64U.slice(0, 42)}${'ABCDEFGHIJ'[index]}`,
    }),
  );
}

export function rawWalletRecoveryEnvelopeSet(overrides: RawRecord = {}): RawRecord {
  return {
    kind: 'wallet_recovery_envelope_set_v1',
    walletId: WALLET_ID,
    manifestKekWraps: rawManifestKekWrapSet(),
    entries: [rawWalletRecoveryEnvelopeEntry()],
    issuedAtMs: 1_000,
    updatedAtMs: 2_000,
    ...overrides,
  };
}

export function rawWalletRecoveryCodeLocators(): RawRecord[] {
  return rawManifestKekWrapSet().map((wrap, index) => ({
    locatorB64u: `${String.fromCharCode(65 + index)}${RECOVERY_LOCATOR_DIGEST_B64U.slice(1)}`,
    recoveryKeyId: wrap.recoveryKeyId,
  }));
}

/**
 * A parsed envelope record. Built by running the raw shape through the real
 * boundary parser, so a fixture can never encode a record the parser rejects.
 */
export function passkeyCustodyEnvelope(overrides: RawRecord = {}): PasskeyCustodyEnvelopeRecord {
  return parsePasskeyCustodyEnvelopeRecord(rawPasskeyCustodyEnvelope(overrides));
}

/**
 * One ceremony run's sealed output, as the client sends it.
 *
 * The single builder for this payload: the admission gate, the outcome
 * composer and the registration routes must all be exercised against the same
 * shape, and three hand-written copies would drift apart exactly where the
 * wire contract matters.
 *
 * `origin: 'join'` models a run that opened custody the wallet already had —
 * no envelope, no recovery codes, just this key set's manifest digest.
 */
export function buildWalletCustodyCommitPayloadFixture(input: {
  readonly walletId: string;
  readonly keySet?: WalletCustodyKeySetKind;
  readonly keyManifestDigestB64u?: string;
  readonly origin?: 'establish' | 'join';
}): WalletCustodyCeremonyCommitPayload {
  const walletId = input.walletId;
  const base = {
    walletId,
    keySet: input.keySet ?? 'evm_family_ecdsa_v1',
    keyManifestDigestB64u: input.keyManifestDigestB64u ?? DIGEST_B64U,
  } as const;
  if (input.origin === 'join') {
    return { ...base, registeredPublicKeyB64u: ED25519_PUBLIC_KEY_B64U };
  }
  return {
    ...base,
    establishedCustody: {
      envelopeId: ENVELOPE_ID,
      /* Carried verbatim, as the ceremony serialized it: this is what the AAD
         was computed over, so a reader that rebuilt it would produce an
         envelope that cannot open. */
      envelopeBindingJson: JSON.stringify({
        walletId,
        envelopeId: ENVELOPE_ID,
        factor: rawPasskeyFactor(),
        envelopeRevision: 1,
        binding: rawWalletCustodySeedBinding(),
        /* The ceremony seals method-bound, and the registration commit reads
           the owner back out of this exact string, so a fixture without it
           reproduces a payload no ceremony can now produce. */
        ownership: { methodBound: { walletAuthMethodId: COMMIT_WALLET_AUTH_METHOD_ID } },
      }),
      envelopeNonceB64u: NONCE_12_B64U,
      sealedCustodySecretB64u: CIPHERTEXT_B64U,
      envelopeAadHashB64u: ALT_DIGEST_B64U,
      envelopeCiphertextDigestB64u: CIPHERTEXT_DIGEST_B64U,
      // Ten wraps of one manifest KEK, one per recovery code, with distinct ids.
      recoveryManifestKekWraps: Array.from({ length: 10 }, (_, index) => ({
        recoveryKeyId: `wallet-rkid-v1-${DIGEST_B64U.slice(0, 42)}${'ABCDEFGHIJ'[index]}`,
        nonceB64u: NONCE_12_B64U,
        ciphertextB64u: CIPHERTEXT_B64U,
        aadHashB64u: ALT_DIGEST_B64U,
      })),
      recoveryEntryNonceB64u: NONCE_12_B64U,
      recoveryEntryCiphertextB64u: CIPHERTEXT_B64U,
      recoveryEntryAadHashB64u: DIGEST_B64U,
    },
    clientRootPublicKey33B64u: SECP256K1_PUBLIC_KEY_B64U,
    ecdsaReadyStateBlobB64u: CIPHERTEXT_B64U,
  };
}

/**
 * An active, method-bound custody envelope built through the production
 * builders, for setup that needs a wallet to have live custody.
 *
 * Refactor 109C requires every written envelope to name its owning auth
 * method, so a seed built by hand would either fail the parser or encode a
 * shape no production path can produce.
 */
export function buildActiveMethodBoundPasskeyCustodyEnvelopeFixture(args: {
  readonly walletId: string;
  readonly envelopeId: string;
  readonly rpId: string;
  readonly credentialIdB64u: string;
  readonly walletAuthMethodId: string;
}): PasskeyCustodyEnvelopeRecord {
  return parsePasskeyCustodyEnvelopeRecord(
    rawPasskeyCustodyEnvelope({
      walletId: args.walletId,
      envelopeId: args.envelopeId,
      factor: rawPasskeyFactor({
        rpId: args.rpId,
        credentialIdB64u: args.credentialIdB64u,
      }),
      ownership: { kind: 'method_bound', walletAuthMethodId: args.walletAuthMethodId },
    }),
  );
}

export function buildActiveMethodBoundEmailOtpCustodyEnvelopeFixture(args: {
  readonly walletId: string;
  readonly envelopeId: string;
  readonly enrollmentId: string;
  readonly enrollmentSealKeyVersion: string;
  readonly walletAuthMethodId: string;
}): PasskeyCustodyEnvelopeRecord {
  return parsePasskeyCustodyEnvelopeRecord(
    rawPasskeyCustodyEnvelope({
      walletId: args.walletId,
      envelopeId: args.envelopeId,
      factor: rawEmailOtpFactor({
        enrollmentId: args.enrollmentId,
        enrollmentSealKeyVersion: args.enrollmentSealKeyVersion,
      }),
      ownership: { kind: 'method_bound', walletAuthMethodId: args.walletAuthMethodId },
    }),
  );
}
