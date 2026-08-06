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
pub const PASSKEY_CUSTODY_ENVELOPE_VERSION_V1: &str = "passkey_custody_envelope_v1";
pub const PASSKEY_CUSTODY_KEK_VERSION_V1: &str = "passkey_prf_kek_hkdf_sha256_v1";

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
    Ed25519YaoClientRoot,
    Ed25519LaneHolderShare,
    EcdsaClientRootShare,
    EcdsaLaneHolderShare,
}

impl PasskeyCustodySecretKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519YaoClientRoot => "ed25519_yao_client_root_v1",
            Self::Ed25519LaneHolderShare => "ed25519_lane_holder_share_v1",
            Self::EcdsaClientRootShare => "ecdsa_client_root_share_v1",
            Self::EcdsaLaneHolderShare => "ecdsa_lane_holder_share_v1",
        }
    }

    /// Parses the wire spelling shared with the TypeScript union. An unknown
    /// kind is rejected rather than defaulted, so a new curve cannot silently
    /// reuse another curve's custody purpose.
    pub fn parse(value: &str) -> CoreResult<Self> {
        match value {
            "ed25519_yao_client_root_v1" => Ok(Self::Ed25519YaoClientRoot),
            "ed25519_lane_holder_share_v1" => Ok(Self::Ed25519LaneHolderShare),
            "ecdsa_client_root_share_v1" => Ok(Self::EcdsaClientRootShare),
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
    #[serde(rename = "ed25519_yao_client_root_v1", rename_all = "camelCase")]
    Ed25519YaoClientRoot {
        #[serde(flatten)]
        lane: PasskeyCustodyLaneScopeV1,
        near_ed25519_signing_key_id: String,
        key_creation_signer_slot: u32,
        stable_context_digest_b64u: String,
        participant_binding_digest_b64u: String,
    },
    #[serde(rename = "ed25519_lane_holder_share_v1", rename_all = "camelCase")]
    Ed25519LaneHolderShare {
        #[serde(flatten)]
        lane: PasskeyCustodyLaneScopeV1,
        near_ed25519_signing_key_id: String,
        registered_public_key_b64u: String,
        participant_binding_digest_b64u: String,
    },
    #[serde(rename = "ecdsa_client_root_share_v1", rename_all = "camelCase")]
    EcdsaClientRootShare {
        #[serde(flatten)]
        lane: PasskeyCustodyLaneScopeV1,
        evm_family_signing_key_slot_id: String,
        application_binding_digest_b64u: String,
        client_root_public_key33_b64u: String,
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
            Self::Ed25519YaoClientRoot { .. } => PasskeyCustodySecretKind::Ed25519YaoClientRoot,
            Self::Ed25519LaneHolderShare { .. } => PasskeyCustodySecretKind::Ed25519LaneHolderShare,
            Self::EcdsaClientRootShare { .. } => PasskeyCustodySecretKind::EcdsaClientRootShare,
            Self::EcdsaLaneHolderShare { .. } => PasskeyCustodySecretKind::EcdsaLaneHolderShare,
        }
    }

    pub fn lane(&self) -> &PasskeyCustodyLaneScopeV1 {
        match self {
            Self::Ed25519YaoClientRoot { lane, .. }
            | Self::Ed25519LaneHolderShare { lane, .. }
            | Self::EcdsaClientRootShare { lane, .. }
            | Self::EcdsaLaneHolderShare { lane, .. } => lane,
        }
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
    pub rp_id: String,
    pub credential_id_b64u: String,
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
fn encode_kek_context(binding: &PasskeyCustodyEnvelopeBindingV1) -> CoreResult<Vec<u8>> {
    require_field("rpId", &binding.rp_id)?;
    require_field("credentialIdB64u", &binding.credential_id_b64u)?;
    require_field("walletId", &binding.wallet_id)?;
    require_field("envelopeId", &binding.envelope_id)?;

    let mut out = Vec::new();
    labeled_str(&mut out, b"rpId", &binding.rp_id);
    labeled_str(&mut out, b"credentialIdB64u", &binding.credential_id_b64u);
    labeled_str(&mut out, b"walletId", &binding.wallet_id);
    labeled_str(&mut out, b"envelopeId", &binding.envelope_id);
    labeled_str(&mut out, b"purpose", binding.binding.kind().as_str());
    labeled_str(&mut out, b"kekVersion", PASSKEY_CUSTODY_KEK_VERSION_V1);
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
    require_field("rpId", &binding.rp_id)?;
    require_field("credentialIdB64u", &binding.credential_id_b64u)?;

    let lane = binding.binding.lane();
    require_field("walletKeyId", &lane.wallet_key_id)?;
    require_field("laneId", &lane.lane_id)?;
    require_field("laneShareEpoch", &lane.lane_share_epoch)?;

    let mut out = Vec::new();
    labeled_field(&mut out, b"context", PASSKEY_CUSTODY_AAD_CONTEXT_V1);
    labeled_str(
        &mut out,
        b"envelopeVersion",
        PASSKEY_CUSTODY_ENVELOPE_VERSION_V1,
    );
    labeled_str(&mut out, b"kekVersion", PASSKEY_CUSTODY_KEK_VERSION_V1);
    labeled_str(&mut out, b"wrapAlg", PASSKEY_CUSTODY_WRAP_ALG_V1);
    labeled_str(&mut out, b"walletId", &binding.wallet_id);
    labeled_str(&mut out, b"envelopeId", &binding.envelope_id);
    labeled_field(
        &mut out,
        b"envelopeRevision",
        &binding.envelope_revision.to_be_bytes(),
    );
    labeled_str(&mut out, b"rpId", &binding.rp_id);
    labeled_str(&mut out, b"credentialIdB64u", &binding.credential_id_b64u);
    labeled_str(
        &mut out,
        b"custodySecretKind",
        binding.binding.kind().as_str(),
    );
    labeled_str(&mut out, b"walletKeyId", &lane.wallet_key_id);
    labeled_str(&mut out, b"laneId", &lane.lane_id);
    labeled_str(&mut out, b"laneShareEpoch", &lane.lane_share_epoch);

    match &binding.binding {
        PasskeyCustodySecretBindingV1::Ed25519YaoClientRoot {
            near_ed25519_signing_key_id,
            key_creation_signer_slot,
            stable_context_digest_b64u,
            participant_binding_digest_b64u,
            ..
        } => {
            require_field("nearEd25519SigningKeyId", near_ed25519_signing_key_id)?;
            if *key_creation_signer_slot == 0 {
                return Err(SignerCoreError::invalid_input(
                    "keyCreationSignerSlot must be a positive u32",
                ));
            }
            let stable_context =
                require_digest_b64u("stableContextDigestB64u", stable_context_digest_b64u)?;
            let participants = require_digest_b64u(
                "participantBindingDigestB64u",
                participant_binding_digest_b64u,
            )?;
            labeled_str(
                &mut out,
                b"nearEd25519SigningKeyId",
                near_ed25519_signing_key_id,
            );
            labeled_field(
                &mut out,
                b"keyCreationSignerSlot",
                &key_creation_signer_slot.to_be_bytes(),
            );
            labeled_field(&mut out, b"stableContextDigest", &stable_context);
            labeled_field(&mut out, b"participantBindingDigest", &participants);
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
        PasskeyCustodySecretBindingV1::EcdsaClientRootShare {
            evm_family_signing_key_slot_id,
            application_binding_digest_b64u,
            client_root_public_key33_b64u,
            ..
        } => {
            // The slot id embeds the Router A/B signing-root id and version, so
            // binding it covers the signing-root identity the plan requires.
            require_field("evmFamilySigningKeySlotId", evm_family_signing_key_slot_id)?;
            let application = require_digest_b64u(
                "applicationBindingDigestB64u",
                application_binding_digest_b64u,
            )?;
            let client_root = require_public_key_b64u(
                "clientRootPublicKey33B64u",
                client_root_public_key33_b64u,
                33,
            )?;
            labeled_str(
                &mut out,
                b"evmFamilySigningKeySlotId",
                evm_family_signing_key_slot_id,
            );
            labeled_field(&mut out, b"applicationBindingDigest", &application);
            labeled_field(&mut out, b"clientRootPublicKey33", &client_root);
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

/// Seals one custody secret under the passkey KEK with AAD recomputed here.
pub fn seal_passkey_custody_secret_v1(
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
