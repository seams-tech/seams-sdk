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

/**
 * The owner key sets a ceremony can provision, spelled as the Rust
 * `WalletKeySetKindV1` serializes them.
 *
 * Used where the SDK *chooses* a key set — the worker channel and the ceremony
 * driver. `WalletCustodyCeremonyCommitPayload.keySet` stays a `string`: it
 * arrives over the wire, and narrowing a parsed value to this union without
 * checking it would only move the assumption somewhere harder to see.
 */
export type WalletCustodyKeySetKind = 'near_ed25519_v1' | 'evm_family_ecdsa_v1';

export type WalletCustodyCeremonyRecoveryWrapPayload = {
  readonly recoveryKeyId: string;
  readonly nonceB64u: string;
  readonly ciphertextB64u: string;
  readonly aadHashB64u: string;
};

/**
 * The custody records a run writes when it *establishes* custody — the wallet's
 * first key set. Absent when the run joined custody that already existed, which
 * writes no envelope and issues no codes.
 */
export type EstablishedCustodyRecordsPayload = {
  readonly envelopeId: string;
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
};

export type RecoveryReplacementEnvelopePayload = {
  readonly envelopeId: string;
  readonly envelopeBindingJson: string;
  readonly envelopeNonceB64u: string;
  readonly sealedCustodySecretB64u: string;
  readonly envelopeAadHashB64u: string;
  readonly envelopeCiphertextDigestB64u: string;
};

export type WalletCustodyCeremonyCommitPayload = {
  readonly walletId: string;
  /** `near_ed25519_v1` or `evm_family_ecdsa_v1`: one key set per run. */
  readonly keySet: string;
  /**
   * This key set's manifest digest, to be written onto that key set's own
   * *registration state* — never to a record of its own. A free-standing
   * manifest row could be deleted, and its absence would read as "not
   * provisioned yet", silently narrowing the wallet.
   */
  readonly keyManifestDigestB64u: string;
  /** Present only when this run established custody. */
  readonly establishedCustody?: EstablishedCustodyRecordsPayload;
  /** Present only when a recovery run resealed under the replacement passkey. */
  readonly recoveryReplacementEnvelope?: RecoveryReplacementEnvelopePayload;
  readonly registeredPublicKeyB64u?: string;
  /**
   * The NEAR same-device continuity cache: the activated Yao Client's material,
   * sealed under a key derived from the wallet custody seed.
   *
   * Sealed under the seed rather than the factor that ran the ceremony, so
   * every factor that opens the wallet's custody envelope reaches the same
   * record — a wallet that registered under a passkey and later enrolled Email
   * OTP would otherwise miss its cache on every OTP unlock.
   *
   * A cache and never a source of truth: losing it costs a Router round, not
   * the wallet. It is also the only copy of this key set's signing material the
   * ceremony produces, so a NEAR run that dropped it would register a public
   * key with nothing to sign for it.
   */
  readonly ed25519LocalMaterialB64u?: string;
  /** The nonce that record was sealed with. Generated inside the ceremony. */
  readonly ed25519LocalMaterialNonceB64u?: string;
  /**
   * The application binding digest the cache was sealed against.
   *
   * Reported rather than recomputed at the reader: it is a field of the seal
   * binding, and a reader that rebuilt it from loose application facts could
   * differ by one byte and hold a record that never opens.
   */
  readonly ed25519ApplicationBindingDigestB64u?: string;
  readonly clientRootPublicKey33B64u?: string;
  /** Finalized role-local ECDSA material, still sealed to its own boundary. */
  readonly ecdsaReadyStateBlobB64u?: string;
  /**
   * The EVM-family run's registered public identity, as its own finalize
   * computed it. Absent on a NEAR run.
   *
   * The client's capability manifest is built from exactly these. They are
   * reported rather than re-derived at the install site because re-deriving
   * would mean trusting a second computation to agree with the one that
   * produced the material.
   */
  readonly ecdsaPublicFacts?: WalletCustodyEvmFamilyPublicFacts;
};

export type WalletCustodyEvmFamilyPublicFacts = {
  readonly contextBinding32B64u: string;
  readonly derivationClientSharePublicKey33B64u: string;
  readonly clientVerifyingShare33B64u: string;
  readonly relayerPublicKey33B64u: string;
  readonly groupPublicKey33B64u: string;
  /** Lowercase 0x-prefixed. */
  readonly ethereumAddress: string;
  readonly clientShareRetryCounter: number;
  readonly relayerShareRetryCounter: number;
};

/** Local EVM material returned only after the Router activation receipt. */
export type WalletCustodyEvmFamilyActivationCompletion = {
  readonly walletId: string;
  readonly keyManifestDigestB64u: string;
  readonly clientRootPublicKey33B64u: string;
  readonly ecdsaReadyStateBlobB64u: string;
  readonly ecdsaPublicFacts: WalletCustodyEvmFamilyPublicFacts;
};

/**
 * What the registration leg reports back about the custody it was asked to
 * commit — the response half of the same contract, so both halves stay in one
 * place.
 *
 * **A registration leg never fails because of custody.** The wallet is already
 * committed by the time custody is admitted, and the seed exists only in the
 * client's worker, so the client is the one party that can retry, re-enter as a
 * join, or abandon the run. Every outcome is therefore reported rather than
 * thrown, and a client that sees anything but `committed` or `not_requested`
 * must act on it rather than treat registration as done.
 */
export type WalletCustodyRegistrationOutcome =
  /** No custody payload rode this leg. Registration is unaffected. */
  | { readonly status: 'not_requested' }
  | { readonly status: 'committed' }
  /**
   * A joining run: this key set's manifest digest, with no custody records
   * written because the wallet already has its envelope and recovery set.
   */
  | { readonly status: 'joined'; readonly keyManifestDigestB64u: string }
  /**
   * Another ceremony established this wallet's custody first. The client must
   * discard its run's seed and re-enter as a join of the existing envelope.
   */
  | { readonly status: 'custody_already_established' }
  /** The payload was refused. Nothing was written. */
  | { readonly status: 'rejected'; readonly reason: string };

/**
 * Reads a commit payload off the wire without judging it.
 *
 * Deliberately total: it never throws and never reports a payload as absent
 * when one was sent. Malformed custody must reach the admission gate and come
 * back as a reported `rejected`, because the two outcomes lead the client
 * somewhere completely different — `not_requested` says custody was never
 * asked for, and a client that believed that would treat a wallet with no
 * recoverable seed as fully registered.
 *
 * Nothing here validates. The nested `establishedCustody` is carried through
 * verbatim: every one of its fields is parsed by the commit builder through the
 * same boundary parsers every other reader uses, and anything it cannot parse
 * becomes a rejection there.
 */
export function walletCustodyCeremonyCommitPayloadFromWire(
  value: unknown,
): WalletCustodyCeremonyCommitPayload | undefined {
  if (value === undefined || value === null) return undefined;
  const record: Record<string, unknown> =
    typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
  const custody = record.establishedCustody;
  return {
    walletId: asWireString(record.walletId),
    keySet: asWireString(record.keySet),
    keyManifestDigestB64u: asWireString(record.keyManifestDigestB64u),
    ...(custody === undefined || custody === null
      ? {}
      : { establishedCustody: custody as EstablishedCustodyRecordsPayload }),
    /* `ed25519LocalMaterial*`, `ed25519ApplicationBindingDigestB64u`, and
       `ecdsaReadyStateBlobB64u` are deliberately absent. Both are the ceremony's output to its own client, not part of
       the commit — and the ECDSA blob is the sharper case: it is not
       self-encrypted, and `extract_client_signing_share32_from_ready_state_blob`
       yields the client's signing share from its bytes with no key. Letting it
       cross would hand one share of a 2-of-2 key to the holder of the other
       share. Dropping both here means a client that sends them anyway cannot
       cause them to be stored. (Decision 2026-08-09.) */
    ...(record.registeredPublicKeyB64u === undefined
      ? {}
      : { registeredPublicKeyB64u: asWireString(record.registeredPublicKeyB64u) }),
    ...(record.clientRootPublicKey33B64u === undefined
      ? {}
      : { clientRootPublicKey33B64u: asWireString(record.clientRootPublicKey33B64u) }),
    /* Public identity only, so this crosses. Carried verbatim: the admission
       gate does not read it, and anything that later records it must compare
       it against the activation receipt rather than trust it. */
    ...(record.ecdsaPublicFacts === undefined || record.ecdsaPublicFacts === null
      ? {}
      : { ecdsaPublicFacts: record.ecdsaPublicFacts as WalletCustodyEvmFamilyPublicFacts }),
  };
}

function asWireString(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/**
 * Parses the outcome a registration response carries. Throws, because this runs
 * on the client against its own Gateway's response: an unrecognised custody
 * status is a version skew the client must not paper over by guessing.
 */
export function parseWalletCustodyRegistrationOutcome(
  value: unknown,
  label: string,
): WalletCustodyRegistrationOutcome {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error(`${label} walletCustody must be an object`);
  }
  const record = value as Record<string, unknown>;
  switch (record.status) {
    case 'not_requested':
    case 'committed':
    case 'custody_already_established':
      return { status: record.status };
    case 'joined': {
      const digest = record.keyManifestDigestB64u;
      if (typeof digest !== 'string' || !digest) {
        throw new Error(`${label} joined custody carries no key manifest digest`);
      }
      return { status: 'joined', keyManifestDigestB64u: digest };
    }
    case 'rejected': {
      const reason = record.reason;
      if (typeof reason !== 'string' || !reason) {
        throw new Error(`${label} rejected custody carries no reason`);
      }
      return { status: 'rejected', reason };
    }
    default:
      throw new Error(`${label} walletCustody status is unrecognised`);
  }
}
