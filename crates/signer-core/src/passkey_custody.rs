//! Passkey custody envelope sealing for Refactor 100.
//!
//! A WebAuthn PRF result derives a key-encryption key that opens exactly one
//! custody envelope. The envelope's additional authenticated data is recomputed
//! here from the parsed domain binding — callers pass records, never an opaque
//! AAD blob — so an envelope resealed against a different wallet, credential,
//! lane, or curve cannot open.
//!
//! Frozen wrap: ChaCha20Poly1305 (IETF) with a 12-byte nonce under an
//! HKDF-SHA256 key, matching the Email OTP recovery wrap and the Ed25519 Yao
//! activated-Client seal.

use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreResult, SignerCoreError};

pub const PASSKEY_CUSTODY_WRAP_ALG_V1: &str = "chacha20poly1305-hkdf-sha256-v1";
pub const WALLET_CUSTODY_ENVELOPE_VERSION_V2: &str = "wallet_custody_envelope_v2";
pub const PASSKEY_CUSTODY_KEK_VERSION_V1: &str = "passkey_prf_kek_hkdf_sha256_v1";
pub const EMAIL_OTP_FACTOR_KEK_VERSION_V1: &str = "email_otp_factor_kek_hkdf_sha256_v1";
pub const WALLET_SEED_DERIVATION_SCHEME_V1: &str = "wallet_seed_parallel_hkdf_sha256_v1";

const PASSKEY_CUSTODY_KEK_SALT_V1: &[u8] = b"seams/passkey-custody/kek/salt/v1";
const PASSKEY_CUSTODY_KEK_INFO_V1: &[u8] = b"seams/passkey-custody/kek/info/v1";
const PASSKEY_CUSTODY_AAD_CONTEXT_V1: &[u8] = b"seams/passkey-custody/aad/v1";

pub const PASSKEY_CUSTODY_NONCE_LEN: usize = 12;
pub const PASSKEY_CUSTODY_KEY_LEN: usize = 32;
pub const PASSKEY_CUSTODY_TAG_LEN: usize = 16;
pub const PASSKEY_PRF_LEN: usize = 32;

/// Largest custody secret this envelope carries. Yao client roots and ECDSA
/// shares are scalars; anything larger is a caller error, not a big secret.
const MAX_CUSTODY_SECRET_LEN: usize = 1024;
const MAX_BINDING_FIELD_LEN: usize = 512;

/// The protocol capability an opened envelope restores. This is also the KEK
/// purpose, so a key that opens an Ed25519 root cannot open an ECDSA share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyCustodySecretKind {
    WalletCustodySeed,
    Ed25519LaneHolderShare,
    EcdsaLaneHolderShare,
}

impl PasskeyCustodySecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletCustodySeed => "wallet_custody_seed_v1",
            Self::Ed25519LaneHolderShare => "ed25519_lane_holder_share_v1",
            Self::EcdsaLaneHolderShare => "ecdsa_lane_holder_share_v1",
        }
    }

    /// Parses the wire spelling shared with the TypeScript union. An unknown
    /// kind is rejected rather than defaulted, so a new curve cannot silently
    /// reuse another curve's custody purpose.
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "wallet_custody_seed_v1" => Ok(Self::WalletCustodySeed),
            "ed25519_lane_holder_share_v1" => Ok(Self::Ed25519LaneHolderShare),
            "ecdsa_lane_holder_share_v1" => Ok(Self::EcdsaLaneHolderShare),
            _ => Err(SignerCoreError::invalid_input(
                "unknown passkey custody secret kind",
            )),
        }
    }
}

/// Lane scope carried by every custody-secret branch.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyCustodyLaneScopeV1 {
    pub wallet_key_id: String,
    pub lane_id: String,
    pub lane_share_epoch: String,
}

/// Exactly the branches of the TypeScript `PasskeyCustodySecretBinding` union.
/// `deny_unknown_fields` is the Rust-side twin of the boundary parser: a
/// cross-curve field fails to deserialize rather than being silently dropped.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum PasskeyCustodySecretBindingV1 {
    /// Owner custody: one wallet-scoped seed every owner root derives from.
    /// It carries no lane, because it covers every owner key.
    ///
    /// It carries no key manifest. Key sets are provisioned independently and
    /// each records its own manifest, so binding one here would couple them and
    /// force a reseal every time a key set arrived.
    #[serde(rename = "wallet_custody_seed_v1", rename_all = "camelCase")]
    WalletCustodySeed { derivation_scheme: String },
    #[serde(rename = "ed25519_lane_holder_share_v1", rename_all = "camelCase")]
    Ed25519LaneHolderShare {
        #[serde(flatten)]
        lane: PasskeyCustodyLaneScopeV1,
        near_ed25519_signing_key_id: String,
        registered_public_key_b64u: String,
        participant_binding_digest_b64u: String,
    },
    #[serde(rename = "ecdsa_lane_holder_share_v1", rename_all = "camelCase")]
    EcdsaLaneHolderShare {
        #[serde(flatten)]
        lane: PasskeyCustodyLaneScopeV1,
        evm_family_signing_key_slot_id: String,
        threshold_session_id: String,
        threshold_public_key33_b64u: String,
    },
}

impl PasskeyCustodySecretBindingV1 {
    pub fn kind(&self) -> PasskeyCustodySecretKind {
        match self {
            Self::WalletCustodySeed { .. } => PasskeyCustodySecretKind::WalletCustodySeed,
            Self::Ed25519LaneHolderShare { .. } => PasskeyCustodySecretKind::Ed25519LaneHolderShare,
            Self::EcdsaLaneHolderShare { .. } => PasskeyCustodySecretKind::EcdsaLaneHolderShare,
        }
    }

    /// The lane this binding is scoped to, or `None` for wallet-scoped owner
    /// custody. The absence is meaningful and is encoded into the AAD.
    pub fn lane(&self) -> Option<&PasskeyCustodyLaneScopeV1> {
        match self {
            Self::WalletCustodySeed { .. } => None,
            Self::Ed25519LaneHolderShare { lane, .. } | Self::EcdsaLaneHolderShare { lane, .. } => {
                Some(lane)
            }
        }
    }
}

/// Which enrolled factor sealed this envelope. Factors are interchangeable
/// unwrap paths to the same custody seed, so each derives its own KEK: the
/// factor identity is part of the KEK context and the AAD.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum WalletCustodyEnvelopeFactorV1 {
    #[serde(rename = "passkey", rename_all = "camelCase")]
    Passkey {
        rp_id: String,
        credential_id_b64u: String,
        kek_version: String,
    },
    #[serde(rename = "email_otp", rename_all = "camelCase")]
    EmailOtp {
        enrollment_id: String,
        enrollment_seal_key_version: String,
        kek_version: String,
    },
}

impl WalletCustodyEnvelopeFactorV1 {
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Passkey { .. } => "passkey",
            Self::EmailOtp { .. } => "email_otp",
        }
    }

    pub fn kek_version(&self) -> &str {
        match self {
            Self::Passkey { kek_version, .. } | Self::EmailOtp { kek_version, .. } => kek_version,
        }
    }

    /// Rejects a factor whose declared KEK version belongs to the other kind,
    /// which would otherwise let two factors derive from the same context.
    fn validate(&self) -> CoreResult<()> {
        let expected = match self {
            Self::Passkey { .. } => PASSKEY_CUSTODY_KEK_VERSION_V1,
            Self::EmailOtp { .. } => EMAIL_OTP_FACTOR_KEK_VERSION_V1,
        };
        if self.kek_version() != expected {
            return Err(SignerCoreError::invalid_input(format!(
                "factor kekVersion must be {expected}"
            )));
        }
        Ok(())
    }
}

/// Every public fact one envelope is bound to. This carries no authorization
/// identity and no material-activation reference: those are resolved per
/// operation at the Refactor 90 boundary, never sealed into custody.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasskeyCustodyEnvelopeBindingV1 {
    pub wallet_id: String,
    pub envelope_id: String,
    pub factor: WalletCustodyEnvelopeFactorV1,
    /// Bumped only when the ciphertext changes, so it is safe as AAD: an old
    /// ciphertext cannot be replayed into a newer envelope revision.
    pub envelope_revision: u32,
    pub binding: PasskeyCustodySecretBindingV1,
}

/// A sealed envelope's ciphertext plus the digests the server store and the
/// browser cache compare before an envelope is used.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedPasskeyCustodyEnvelopeV1 {
    pub ciphertext: Vec<u8>,
    pub aad_hash: [u8; 32],
    pub ciphertext_digest: [u8; 32],
}

impl SealedPasskeyCustodyEnvelopeV1 {
    pub fn ciphertext_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ciphertext)
    }

    pub fn aad_hash_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.aad_hash)
    }

    pub fn ciphertext_digest_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.ciphertext_digest)
    }
}

fn require_field(label: &str, value: &str) -> CoreResult<()> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} must not be empty"
        )));
    }
    if value.len() > MAX_BINDING_FIELD_LEN {
        return Err(SignerCoreError::invalid_input(format!(
            "{label} exceeds the maximum custody binding field length"
        )));
    }
    Ok(())
}

fn require_digest_b64u(label: &str, value: &str) -> CoreResult<[u8; 32]> {
    let decoded = Base64UrlUnpadded::decode_vec(value).map_err(|_| {
        SignerCoreError::decode_error(format!("{label} must be unpadded base64url"))
    })?;
    decoded
        .try_into()
        .map_err(|_| SignerCoreError::invalid_length(format!("{label} must decode to 32 bytes")))
}

fn require_public_key_b64u(label: &str, value: &str, len: usize) -> CoreResult<Vec<u8>> {
    let decoded = Base64UrlUnpadded::decode_vec(value).map_err(|_| {
        SignerCoreError::decode_error(format!("{label} must be unpadded base64url"))
    })?;
    if decoded.len() != len {
        return Err(SignerCoreError::invalid_length(format!(
            "{label} must decode to {len} bytes"
        )));
    }
    Ok(decoded)
}

/// Length-delimited labeled field: `len(label) || label || len(value) || value`.
/// Both lengths are big-endian u32, so no field boundary is ambiguous and two
/// different bindings cannot encode to the same bytes.
fn labeled_field(out: &mut Vec<u8>, label: &[u8], value: &[u8]) {
    out.extend_from_slice(&(label.len() as u32).to_be_bytes());
    out.extend_from_slice(label);
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn labeled_str(out: &mut Vec<u8>, label: &[u8], value: &str) {
    labeled_field(out, label, value.as_bytes());
}

/// Canonical KEK context: the exact `hash(rpId, credentialId, walletId,
/// envelopeId, purpose, version)` input from the Refactor 100 plan.
/// Encodes the factor identity. The factor kind is encoded before its fields,
/// so a passkey factor and an Email OTP factor can never produce the same
/// bytes even if their identity strings coincided.
fn encode_factor(out: &mut Vec<u8>, factor: &WalletCustodyEnvelopeFactorV1) -> CoreResult<()> {
    factor.validate()?;
    labeled_str(out, b"factorKind", factor.kind_str());
    match factor {
        WalletCustodyEnvelopeFactorV1::Passkey {
            rp_id,
            credential_id_b64u,
            kek_version,
        } => {
            require_field("rpId", rp_id)?;
            require_field("credentialIdB64u", credential_id_b64u)?;
            labeled_str(out, b"rpId", rp_id);
            labeled_str(out, b"credentialIdB64u", credential_id_b64u);
            labeled_str(out, b"kekVersion", kek_version);
        }
        WalletCustodyEnvelopeFactorV1::EmailOtp {
            enrollment_id,
            enrollment_seal_key_version,
            kek_version,
        } => {
            require_field("enrollmentId", enrollment_id)?;
            require_field("enrollmentSealKeyVersion", enrollment_seal_key_version)?;
            labeled_str(out, b"enrollmentId", enrollment_id);
            labeled_str(
                out,
                b"enrollmentSealKeyVersion",
                enrollment_seal_key_version,
            );
            labeled_str(out, b"kekVersion", kek_version);
        }
    }
    Ok(())
}

fn encode_kek_context(binding: &PasskeyCustodyEnvelopeBindingV1) -> CoreResult<Vec<u8>> {
    require_field("walletId", &binding.wallet_id)?;
    require_field("envelopeId", &binding.envelope_id)?;

    let mut out = Vec::new();
    encode_factor(&mut out, &binding.factor)?;
    labeled_str(&mut out, b"walletId", &binding.wallet_id);
    labeled_str(&mut out, b"envelopeId", &binding.envelope_id);
    labeled_str(&mut out, b"purpose", binding.binding.kind().as_str());
    Ok(out)
}

/// Canonical AAD over every public binding fact. Curve-specific fields appear
/// only on their own branch, so an Ed25519 envelope and an ECDSA envelope can
/// never produce equal AAD even with identical wallet and lane scope.
pub fn encode_passkey_custody_aad_v1(
    binding: &PasskeyCustodyEnvelopeBindingV1,
) -> CoreResult<Vec<u8>> {
    require_field("walletId", &binding.wallet_id)?;
    require_field("envelopeId", &binding.envelope_id)?;

    let mut out = Vec::new();
    labeled_field(&mut out, b"context", PASSKEY_CUSTODY_AAD_CONTEXT_V1);
    labeled_str(
        &mut out,
        b"envelopeVersion",
        WALLET_CUSTODY_ENVELOPE_VERSION_V2,
    );
    labeled_str(&mut out, b"wrapAlg", PASSKEY_CUSTODY_WRAP_ALG_V1);
    encode_factor(&mut out, &binding.factor)?;
    labeled_str(&mut out, b"walletId", &binding.wallet_id);
    labeled_str(&mut out, b"envelopeId", &binding.envelope_id);
    labeled_field(
        &mut out,
        b"envelopeRevision",
        &binding.envelope_revision.to_be_bytes(),
    );
    labeled_str(
        &mut out,
        b"custodySecretKind",
        binding.binding.kind().as_str(),
    );

    // The custody-secret kind above already domain-separates the branches;
    // the explicit scope marker is defense-in-depth so scope stays bound even
    // if a future edit lets two branches share a kind.
    match binding.binding.lane() {
        Some(lane) => {
            require_field("walletKeyId", &lane.wallet_key_id)?;
            require_field("laneId", &lane.lane_id)?;
            require_field("laneShareEpoch", &lane.lane_share_epoch)?;
            labeled_str(&mut out, b"scope", "lane");
            labeled_str(&mut out, b"walletKeyId", &lane.wallet_key_id);
            labeled_str(&mut out, b"laneId", &lane.lane_id);
            labeled_str(&mut out, b"laneShareEpoch", &lane.lane_share_epoch);
        }
        None => labeled_str(&mut out, b"scope", "wallet"),
    }

    match &binding.binding {
        PasskeyCustodySecretBindingV1::WalletCustodySeed { derivation_scheme } => {
            if derivation_scheme != WALLET_SEED_DERIVATION_SCHEME_V1 {
                return Err(SignerCoreError::invalid_input(format!(
                    "derivationScheme must be {WALLET_SEED_DERIVATION_SCHEME_V1}"
                )));
            }
            labeled_str(&mut out, b"derivationScheme", derivation_scheme);
        }
        PasskeyCustodySecretBindingV1::Ed25519LaneHolderShare {
            near_ed25519_signing_key_id,
            registered_public_key_b64u,
            participant_binding_digest_b64u,
            ..
        } => {
            require_field("nearEd25519SigningKeyId", near_ed25519_signing_key_id)?;
            let registered =
                require_public_key_b64u("registeredPublicKeyB64u", registered_public_key_b64u, 32)?;
            let participants = require_digest_b64u(
                "participantBindingDigestB64u",
                participant_binding_digest_b64u,
            )?;
            labeled_str(
                &mut out,
                b"nearEd25519SigningKeyId",
                near_ed25519_signing_key_id,
            );
            labeled_field(&mut out, b"registeredPublicKey", &registered);
            labeled_field(&mut out, b"participantBindingDigest", &participants);
        }
        PasskeyCustodySecretBindingV1::EcdsaLaneHolderShare {
            evm_family_signing_key_slot_id,
            threshold_session_id,
            threshold_public_key33_b64u,
            ..
        } => {
            require_field("evmFamilySigningKeySlotId", evm_family_signing_key_slot_id)?;
            require_field("thresholdSessionId", threshold_session_id)?;
            let threshold_public_key = require_public_key_b64u(
                "thresholdPublicKey33B64u",
                threshold_public_key33_b64u,
                33,
            )?;
            labeled_str(
                &mut out,
                b"evmFamilySigningKeySlotId",
                evm_family_signing_key_slot_id,
            );
            labeled_str(&mut out, b"thresholdSessionId", threshold_session_id);
            labeled_field(&mut out, b"thresholdPublicKey33", &threshold_public_key);
        }
    }

    Ok(out)
}

pub fn sha256_digest(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Derives the envelope's key-encryption key from a WebAuthn PRF result.
///
/// The PRF result never leaves this crate's callers in the secure worker, and
/// the KEK is bound to the exact relying party, credential, wallet, envelope,
/// and custody branch, so one credential's PRF cannot open another envelope.
pub fn derive_passkey_custody_kek_v1(
    prf_first: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
) -> CoreResult<Zeroizing<[u8; PASSKEY_CUSTODY_KEY_LEN]>> {
    if prf_first.len() != PASSKEY_PRF_LEN {
        return Err(SignerCoreError::invalid_length(format!(
            "passkey PRF.first must be {PASSKEY_PRF_LEN} bytes"
        )));
    }
    let context_digest = sha256_digest(&encode_kek_context(binding)?);
    let hkdf = Hkdf::<Sha256>::new(Some(PASSKEY_CUSTODY_KEK_SALT_V1), prf_first);
    let mut kek = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
    hkdf.expand_multi_info(
        &[PASSKEY_CUSTODY_KEK_INFO_V1, &context_digest],
        &mut kek[..],
    )
    .map_err(|_| SignerCoreError::hkdf_error("passkey custody KEK derivation failed"))?;
    Ok(kek)
}

/// Seals a lane holder share under the factor KEK with AAD recomputed here.
///
/// Wallet custody seeds are deliberately not sealable through this entry point:
/// a seed envelope records the key manifest the seed must reproduce, and
/// writing one before that manifest has been verified would publish a claim
/// nothing checked. Seeds go through
/// [`seal_wallet_custody_seed_envelope_v1`], which requires the proof.
pub fn seal_passkey_custody_secret_v1(
    prf_first: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
    nonce: &[u8],
    custody_secret: &[u8],
) -> CoreResult<SealedPasskeyCustodyEnvelopeV1> {
    if binding.binding.kind() == PasskeyCustodySecretKind::WalletCustodySeed {
        return Err(SignerCoreError::invalid_input(
            "a wallet custody seed is sealed through seal_wallet_custody_seed_envelope_v1",
        ));
    }
    seal_custody_secret(prf_first, binding, nonce, custody_secret)
}

/// Seals the wallet custody seed.
///
/// The seed carries no key manifest: key sets are provisioned independently and
/// each records its own, so a seed envelope is sealed once and never resealed
/// as key sets arrive. What a seed may publish capability for is checked
/// per key set at that key set's own gate, not here.
pub fn seal_wallet_custody_seed_envelope_v1(
    prf_first: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
    nonce: &[u8],
    custody_seed: &[u8],
) -> CoreResult<SealedPasskeyCustodyEnvelopeV1> {
    if binding.binding.kind() != PasskeyCustodySecretKind::WalletCustodySeed {
        return Err(SignerCoreError::invalid_input(
            "seal_wallet_custody_seed_envelope_v1 seals the wallet custody seed only",
        ));
    }
    seal_custody_secret(prf_first, binding, nonce, custody_seed)
}

/// Proof that a seed was opened from an envelope that authenticated it to one
/// wallet and one key manifest.
///
/// Minted only by [`open_wallet_custody_seed_envelope_v1`]. Opening is what
/// makes it evidence: the manifest digest and every identity field are inside
/// the envelope's AAD, so a successful open proves the seed was sealed under
/// exactly this description. It does not prove the seed reproduces those keys —
/// that was established when the envelope was first written, and this proof
/// only carries the claim forward unchanged.
///
/// Deliberately a different type from [`VerifiedWalletKeyManifestDigestV1`].
/// Adding a factor and establishing a wallet are different states, and sharing
/// one token would let an admitted seed reach the registration seal, or a fresh
/// verification reach a reseal that is supposed to preserve an existing record.
///
/// Not `Clone` or `Serialize`: it is a within-session capability, and it must
/// not cross the wasm boundary.
pub struct WalletCustodySeedFromSealedEnvelopeV1 {
    wallet_id: String,
    binding: PasskeyCustodySecretBindingV1,
}

impl WalletCustodySeedFromSealedEnvelopeV1 {
    pub fn wallet_id(&self) -> &str {
        &self.wallet_id
    }
}

impl core::fmt::Debug for WalletCustodySeedFromSealedEnvelopeV1 {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("WalletCustodySeedFromSealedEnvelopeV1")
    }
}

/// Opens a wallet custody seed envelope and mints the proof a reseal requires.
///
/// The verified open is the whole check: stored AAD hash and ciphertext digest
/// must match what this binding and ciphertext produce, so a row that drifted
/// from the server revision fails here rather than yielding a seed. Callers
/// that only need the seed can keep using
/// [`open_verified_passkey_custody_secret_v1`]; this one exists for the paths
/// that go on to write a new envelope.
pub fn open_wallet_custody_seed_envelope_v1(
    prf_first: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
    nonce: &[u8],
    ciphertext: &[u8],
    expected_aad_hash: &[u8],
    expected_ciphertext_digest: &[u8],
) -> CoreResult<(Zeroizing<Vec<u8>>, WalletCustodySeedFromSealedEnvelopeV1)> {
    if binding.binding.kind() != PasskeyCustodySecretKind::WalletCustodySeed {
        return Err(SignerCoreError::invalid_input(
            "open_wallet_custody_seed_envelope_v1 opens wallet custody seeds only",
        ));
    }
    let seed = open_verified_passkey_custody_secret_v1(
        prf_first,
        binding,
        nonce,
        ciphertext,
        expected_aad_hash,
        expected_ciphertext_digest,
    )?;
    Ok((
        seed,
        WalletCustodySeedFromSealedEnvelopeV1 {
            wallet_id: binding.wallet_id.clone(),
            binding: binding.binding.clone(),
        },
    ))
}

/// Seals an already-admitted seed under a second factor.
///
/// This is how a wallet ends up with both a passkey and an Email OTP factor.
/// It needs no owner-root derivation and no protocol crate: the seed's key
/// manifest was established when its first envelope was written, and a reseal
/// may only carry that claim forward.
///
/// Everything except the factor and the envelope id must be identical to the
/// admitted envelope. A reseal is therefore incapable of moving a seed to
/// another wallet, relabelling its key manifest, or changing which keys the
/// envelope says it controls — the only degree of freedom is which factor can
/// open it.
pub fn reseal_wallet_custody_seed_under_new_factor_v1(
    new_factor_secret: &[u8],
    new_binding: &PasskeyCustodyEnvelopeBindingV1,
    admitted: &WalletCustodySeedFromSealedEnvelopeV1,
    nonce: &[u8],
    custody_seed: &[u8],
) -> CoreResult<SealedPasskeyCustodyEnvelopeV1> {
    if new_binding.wallet_id != admitted.wallet_id {
        return Err(SignerCoreError::invalid_input(
            "a reseal cannot move a custody seed to another wallet",
        ));
    }
    if new_binding.binding != admitted.binding {
        return Err(SignerCoreError::invalid_input(
            "a reseal may change only the factor and the envelope id",
        ));
    }
    seal_custody_secret(new_factor_secret, new_binding, nonce, custody_seed)
}

pub(crate) fn seal_custody_secret(
    prf_first: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
    nonce: &[u8],
    custody_secret: &[u8],
) -> CoreResult<SealedPasskeyCustodyEnvelopeV1> {
    if custody_secret.is_empty() || custody_secret.len() > MAX_CUSTODY_SECRET_LEN {
        return Err(SignerCoreError::invalid_input(
            "custody secret length is invalid",
        ));
    }
    let nonce = require_nonce(nonce)?;
    let aad = encode_passkey_custody_aad_v1(binding)?;
    let kek = derive_passkey_custody_kek_v1(prf_first, binding)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&kek[..])
        .map_err(|_| SignerCoreError::crypto_error("invalid passkey custody KEK"))?;
    let nonce: Nonce = nonce.into();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: custody_secret,
                aad: &aad,
            },
        )
        .map_err(|_| SignerCoreError::crypto_error("passkey custody seal failed"))?;

    Ok(SealedPasskeyCustodyEnvelopeV1 {
        aad_hash: sha256_digest(&aad),
        ciphertext_digest: sha256_digest(&ciphertext),
        ciphertext,
    })
}

/// Opens one custody secret, rejecting any binding that does not reproduce the
/// exact AAD the ciphertext was sealed under.
pub fn open_passkey_custody_secret_v1(
    prf_first: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
    nonce: &[u8],
    ciphertext: &[u8],
) -> CoreResult<Zeroizing<Vec<u8>>> {
    if ciphertext.len() <= PASSKEY_CUSTODY_TAG_LEN {
        return Err(SignerCoreError::invalid_length(
            "passkey custody ciphertext is shorter than its authentication tag",
        ));
    }
    let nonce = require_nonce(nonce)?;
    let aad = encode_passkey_custody_aad_v1(binding)?;
    let kek = derive_passkey_custody_kek_v1(prf_first, binding)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&kek[..])
        .map_err(|_| SignerCoreError::crypto_error("invalid passkey custody KEK"))?;
    let nonce: Nonce = nonce.into();
    let opened = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| SignerCoreError::crypto_error("passkey custody open failed"))?;
    Ok(Zeroizing::new(opened))
}

/// Opens an envelope only when the stored digests match what this binding and
/// ciphertext actually produce. A browser cache row that drifted from the
/// server revision fails here instead of decrypting into stale material.
pub fn open_verified_passkey_custody_secret_v1(
    prf_first: &[u8],
    binding: &PasskeyCustodyEnvelopeBindingV1,
    nonce: &[u8],
    ciphertext: &[u8],
    expected_aad_hash: &[u8],
    expected_ciphertext_digest: &[u8],
) -> CoreResult<Zeroizing<Vec<u8>>> {
    let aad = encode_passkey_custody_aad_v1(binding)?;
    if sha256_digest(&aad).as_slice() != expected_aad_hash {
        return Err(SignerCoreError::invalid_input(
            "passkey custody AAD hash does not match the envelope binding",
        ));
    }
    if sha256_digest(ciphertext).as_slice() != expected_ciphertext_digest {
        return Err(SignerCoreError::invalid_input(
            "passkey custody ciphertext digest does not match the envelope record",
        ));
    }
    open_passkey_custody_secret_v1(prf_first, binding, nonce, ciphertext)
}

fn require_nonce(nonce: &[u8]) -> CoreResult<[u8; PASSKEY_CUSTODY_NONCE_LEN]> {
    nonce.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!(
            "passkey custody nonce must be {PASSKEY_CUSTODY_NONCE_LEN} bytes"
        ))
    })
}
