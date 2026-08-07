/**
 * What a wallet custody ceremony hands back when it seals.
 *
 * This is the wasm `WalletCustodyCommitPayloadV1` as it crosses the worker
 * boundary and then the wire: ciphertext and public facts only. It lives in
 * shared so the SDK worker channel and the Gateway commit path describe the
 * same shape once — two spellings of it would diverge silently, and the first
 * symptom would be a stored envelope that never opens.
 *
 * Nothing here is a capability. The seed, the owner roots, the manifest KEK,
 * and the manifest proof all stayed inside the ceremony module.
 */

export type WalletCustodyCeremonyRecoveryWrapPayload = {
  readonly recoveryKeyId: string;
  readonly nonceB64u: string;
  readonly ciphertextB64u: string;
  readonly aadHashB64u: string;
};

export type WalletCustodyCeremonyCommitPayload = {
  readonly walletId: string;
  readonly envelopeId: string;
  readonly keyManifestDigestB64u: string;
  /**
   * The envelope binding the ceremony sealed against, serialized verbatim.
   * It is carried rather than rebuilt: this is what the AAD was computed over,
   * so a reader that reassembled it from loose fields would produce an envelope
   * that cannot open.
   */
  readonly envelopeBindingJson: string;
  readonly envelopeNonceB64u: string;
  readonly sealedCustodySecretB64u: string;
  readonly envelopeAadHashB64u: string;
  readonly envelopeCiphertextDigestB64u: string;
  /** Ten wraps of one manifest KEK, one per recovery code. */
  readonly recoveryManifestKekWraps: readonly WalletCustodyCeremonyRecoveryWrapPayload[];
  readonly recoveryEntryNonceB64u: string;
  readonly recoveryEntryCiphertextB64u: string;
  readonly recoveryEntryAadHashB64u: string;
  readonly registeredPublicKeyB64u: string;
  readonly clientRootPublicKey33B64u: string;
  /** Finalized role-local ECDSA material, still sealed to its own boundary. */
  readonly ecdsaReadyStateBlobB64u: string;
};
