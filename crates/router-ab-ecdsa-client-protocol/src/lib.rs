#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Client-safe cryptographic wire protocol for Router A/B ECDSA ceremonies.
//!
//! This crate owns public AAD framing and signer-envelope HPKE. It contains no
//! Router admission, Deriver evaluation, root shares, or threshold-PRF backend.

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "hpke")]
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
#[cfg(feature = "hpke")]
use rand_chacha::ChaCha20Rng;
#[cfg(feature = "hpke")]
use rand_core::SeedableRng;
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;

#[cfg(feature = "hpke")]
mod activation;
#[cfg(feature = "hpke")]
mod export_share;
#[cfg(feature = "hpke")]
mod lane_resharing;
#[cfg(feature = "hpke")]
mod linked_device_source_contribution;
mod material_possession;
#[cfg(feature = "hpke")]
mod post_registration;
#[cfg(feature = "hpke")]
mod recipient_proof;
#[cfg(feature = "hpke")]
mod registration;

#[cfg(feature = "hpke")]
pub use activation::EcdsaVerifiedClientActivationFactsV1;
#[cfg(feature = "hpke")]
pub use export_share::{
    open_ecdsa_signing_worker_export_share_v1, seal_ecdsa_signing_worker_export_share_v1,
    EcdsaSigningWorkerExportShareBindingV1, EcdsaSigningWorkerExportShareEnvelopeV1,
};
#[cfg(feature = "hpke")]
pub use lane_resharing::{
    complete_ecdsa_additive_lane_server_round_v1, ecdsa_lane_public_identity_relation_digest_v1,
    prepare_ecdsa_additive_lane_holder_round_v1, verify_ecdsa_additive_lane_transcript_v1,
    verify_ecdsa_server_retirement_receipt_v1, ActiveEcdsaLaneProtocolSourceV1,
    EcdsaAdditiveLaneHolderRoundV1, EcdsaAdditiveLaneJobV1, EcdsaAdditiveLaneServerRoundV1,
    EcdsaAdditiveLaneTranscriptV1, EcdsaLaneAuthorizationBindingV1, EcdsaLaneChainTargetV1,
    EcdsaLaneEncryptedPayloadV1, EcdsaLaneManifestIdentityV1, EcdsaLaneSourceKindV1,
    EcdsaLaneTargetHolderV1, EcdsaLaneTargetOperationV1, EcdsaLaneTargetSigningWorkerV1,
    EcdsaServerRetirementReceiptV1, EcdsaSourceCapabilityBindingV1, EcdsaTargetCapabilityBindingV1,
    EcdsaTargetThresholdSessionBindingV1, OwnerLaneParticipantContinuityV1,
    ECDSA_ADDITIVE_LANE_ENVELOPE_DOMAIN_V1, ECDSA_ADDITIVE_LANE_HOLDER_ROUND_DOMAIN_V1,
    ECDSA_ADDITIVE_LANE_PREAMBLE_DOMAIN_V1, ECDSA_ADDITIVE_LANE_SERVER_ROUND_DOMAIN_V1,
    ECDSA_ADDITIVE_LANE_TRANSCRIPT_DOMAIN_V1, ECDSA_PUBLIC_IDENTITY_RELATION_DOMAIN_V1,
    ECDSA_SERVER_RETIREMENT_RECEIPT_DOMAIN_V1, ECDSA_TARGET_THRESHOLD_SESSION_SET_DOMAIN_V1,
};
#[cfg(feature = "hpke")]
pub use lane_resharing::{open_ecdsa_lane_payload_v1, seal_ecdsa_lane_payload_v1};
#[cfg(feature = "hpke")]
pub use linked_device_source_contribution::{
    open_linked_device_ecdsa_source_contribution_v1,
    seal_linked_device_ecdsa_source_contribution_v1,
    LinkedDeviceEcdsaEncryptedSourceContributionV1, LinkedDeviceEcdsaSourceContributionBindingV1,
    LinkedDeviceEcdsaSourceContributionPackageV1, LinkedDeviceEcdsaSourceContributionPreparationV1,
    LinkedDeviceEcdsaSourceSignerIdentityV1, LinkedDeviceEcdsaTargetRecipientPreparationV1,
    LINKED_DEVICE_SOURCE_CONTRIBUTION_BINDING_DOMAIN_V1,
    LINKED_DEVICE_SOURCE_CONTRIBUTION_ENVELOPE_DOMAIN_V1,
};
pub use material_possession::{
    sign_ecdsa_wallet_recovery_material_possession_proof_v1,
    verify_ecdsa_client_material_possession_proof_v1,
    verify_ecdsa_wallet_recovery_material_possession_proof_v1,
    EcdsaClientMaterialPossessionChallengeV1, EcdsaClientMaterialPossessionError,
    EcdsaClientMaterialPossessionProofSchemeV1, EcdsaClientMaterialPossessionProofV1,
    EcdsaWalletRecoveryMaterialPossessionChallengeV1,
};
#[cfg(feature = "hpke")]
pub use post_registration::{
    build_ecdsa_post_registration_request_v1, EcdsaMaterialActivationRefKindV1,
    EcdsaMaterialActivationRefV1, EcdsaPostRegistrationCeremonyV1,
    EcdsaPostRegistrationHeaderInputV1, EcdsaPostRegistrationHeaderV1,
    EcdsaPostRegistrationLifecycleV1, EcdsaPostRegistrationLifecycleWireV1,
    EcdsaPostRegistrationOperationV1, EcdsaPostRegistrationRecipientV1,
    EcdsaPostRegistrationRequestV1, EcdsaPublicIdentityInputV1, EcdsaPublicIdentityV1,
};
#[cfg(feature = "hpke")]
pub use recipient_proof::{
    decode_ecdsa_client_proof_bundle_envelope_v1, ecdsa_client_prf_public_context_v1,
    open_ecdsa_client_proof_bundle_v1, open_ecdsa_client_proof_bundle_v2,
    pair_ecdsa_opened_client_proof_bundles_v1, EcdsaClientProofBundleEnvelopeV1,
    EcdsaOpenedClientProofBundlePairV1, EcdsaOpenedClientProofBundleV1,
};
#[cfg(feature = "hpke")]
pub use registration::{
    build_ecdsa_registration_request_v1, derive_ecdsa_client_ephemeral_keypair_v1,
    EcdsaClientEphemeralKeyPairV1, EcdsaRegistrationEncryptedEnvelopeV1,
    EcdsaRegistrationHeaderInputV1, EcdsaRegistrationHeaderV1, EcdsaRegistrationLifecycleV1,
    EcdsaRegistrationLifecycleWireV1, EcdsaRegistrationPurposeV1, EcdsaRegistrationRecipientKeysV1,
    EcdsaRegistrationRequestV1, EcdsaRegistrationSealSeedsV1, EcdsaRegistrationSignerSetV1,
    EcdsaStableKeyContextV1,
};

#[cfg(feature = "hpke")]
type SignerEnvelopeHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

const ROLE_ENVELOPE_AAD_VERSION_V1: &[u8] = b"router-ab-protocol/role-envelope-aad/v1";
#[cfg(feature = "hpke")]
const SIGNER_ENVELOPE_HPKE_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/signer-envelope-hpke/v1";
#[cfg(feature = "hpke")]
const SIGNER_ENVELOPE_HPKE_ALGORITHM_V1: &[u8] = b"hpke-x25519-hkdf-sha256-aes256gcm/v1";
#[cfg(feature = "hpke")]
const SIGNER_ENVELOPE_HPKE_INFO_V1: &[u8] =
    b"router-ab-cloudflare/signer-envelope/hpke-x25519-hkdf-sha256-aes256gcm/v1";
#[cfg(feature = "hpke")]
const SIGNER_ENVELOPE_HPKE_TAG_LEN_V1: usize = 16;
const PRF_INPUT_DOMAIN_V1: &[u8] = b"threshold-prf/input";
const PRF_PARTIAL_CONTEXT_DOMAIN_V1: &[u8] = b"threshold-prf/partial-context";
const PRF_DLEQ_DOMAIN_V1: &[u8] = b"threshold-prf/dleq";
const PRF_DLEQ_BOUND_DOMAIN_V1: &[u8] = b"threshold-prf/dleq-bound/v1";
const PRF_SUITE_V1: &[u8] = b"threshold-prf/ristretto255-sha512";
const ECDSA_STABLE_CONTEXT_DOMAIN_V1: &[u8] = b"router-ab-ecdsa-derivation/context/v1";
const ECDSA_STABLE_CONTEXT_SCHEME_ID_V1: &[u8] = b"router-ab-ecdsa-derivation-v1";
const ECDSA_STABLE_CONTEXT_CURVE_V1: &[u8] = b"secp256k1";

/// One Deriver role in the fixed all(2) protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaDeriverRoleV1 {
    /// Deriver A.
    A,
    /// Deriver B.
    B,
}

impl EcdsaDeriverRoleV1 {
    /// Returns the canonical backend wire label.
    pub fn wire_label(self) -> &'static str {
        match self {
            Self::A => "signer_a",
            Self::B => "signer_b",
        }
    }
}

/// Public signer identity committed into role-envelope AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignerIdentityV1 {
    /// Recipient Deriver role.
    pub role: EcdsaDeriverRoleV1,
    /// Stable signer id.
    pub signer_id: String,
    /// Signer key epoch.
    pub key_epoch: String,
}

/// Public SigningWorker identity committed into role-envelope AAD.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSelectedServerIdentityV1 {
    /// Stable server id.
    pub server_id: String,
    /// Server key epoch.
    pub key_epoch: String,
    /// Recipient encryption key for server output delivery.
    pub recipient_encryption_key: String,
}

/// Exact public fields used as signer-envelope associated data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRoleEnvelopeAadV1 {
    /// Router lifecycle id.
    pub lifecycle_id: String,
    /// Product work-kind wire label.
    pub work_kind: String,
    /// Primitive request-kind wire label.
    pub primitive_request_kind: String,
    /// Selected signer-set id.
    pub signer_set_id: String,
    /// Recipient Deriver identity.
    pub recipient: EcdsaSignerIdentityV1,
    /// Selected SigningWorker identity.
    pub selected_server: EcdsaSelectedServerIdentityV1,
    /// Public derivation transcript digest.
    pub transcript_digest: [u8; 32],
    /// Pre-envelope lifecycle header digest.
    pub router_request_digest: [u8; 32],
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl EcdsaRoleEnvelopeAadV1 {
    /// Validates required identity and lifecycle fields.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        require_non_empty(&self.lifecycle_id)?;
        require_non_empty(&self.work_kind)?;
        require_non_empty(&self.primitive_request_kind)?;
        require_non_empty(&self.signer_set_id)?;
        require_non_empty(&self.recipient.signer_id)?;
        require_non_empty(&self.recipient.key_epoch)?;
        require_non_empty(&self.selected_server.server_id)?;
        require_non_empty(&self.selected_server.key_epoch)?;
        require_non_empty(&self.selected_server.recipient_encryption_key)?;
        if self.expires_at_ms == 0 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(())
    }

    /// Returns canonical backend-compatible AAD bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        self.validate()?;
        let mut out = Vec::new();
        push_bytes(&mut out, ROLE_ENVELOPE_AAD_VERSION_V1);
        push_string(&mut out, &self.lifecycle_id);
        push_bytes(&mut out, self.work_kind.as_bytes());
        push_bytes(&mut out, self.primitive_request_kind.as_bytes());
        push_string(&mut out, &self.signer_set_id);
        push_bytes(&mut out, self.recipient.role.wire_label().as_bytes());
        push_string(&mut out, &self.recipient.signer_id);
        push_string(&mut out, &self.recipient.key_epoch);
        push_string(&mut out, &self.selected_server.server_id);
        push_string(&mut out, &self.selected_server.key_epoch);
        push_string(&mut out, &self.selected_server.recipient_encryption_key);
        push_bytes(&mut out, &self.transcript_digest);
        push_bytes(&mut out, &self.router_request_digest);
        out.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        Ok(out)
    }

    /// Returns the SHA-256 digest of canonical AAD bytes.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes()?)
    }
}

/// Public HPKE recipient key selected from an authenticated deployment keyset.
#[cfg(feature = "hpke")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignerEnvelopePublicKeyV1 {
    /// Recipient Deriver role.
    pub role: EcdsaDeriverRoleV1,
    /// Recipient decrypt-key epoch.
    pub key_epoch: String,
    /// Canonical `x25519:<64 lowercase hex>` public key.
    pub public_key: String,
}

/// Parsed signer-envelope HPKE packet.
#[cfg(feature = "hpke")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignerEnvelopeHpkePayloadV1 {
    /// Recipient Deriver role.
    pub recipient_role: EcdsaDeriverRoleV1,
    /// Recipient decrypt-key epoch.
    pub key_epoch: String,
    /// Canonical X25519 recipient public key.
    pub recipient_public_key: String,
    /// Digest of exact AAD bytes used for sealing.
    pub aad_digest: [u8; 32],
    /// HPKE encapsulated key.
    pub encapped_key: [u8; 32],
    /// Ciphertext followed by the AES-GCM tag.
    pub ciphertext_and_tag: Vec<u8>,
}

#[cfg(feature = "hpke")]
impl EcdsaSignerEnvelopeHpkePayloadV1 {
    /// Returns canonical backend-compatible packet bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        require_non_empty(&self.key_epoch)?;
        decode_x25519_public_key(&self.recipient_public_key)?;
        if self.ciphertext_and_tag.len() <= SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let mut out = Vec::new();
        push_bytes(&mut out, SIGNER_ENVELOPE_HPKE_PAYLOAD_VERSION_V1);
        push_bytes(&mut out, SIGNER_ENVELOPE_HPKE_ALGORITHM_V1);
        push_bytes(&mut out, self.recipient_role.wire_label().as_bytes());
        push_string(&mut out, &self.key_epoch);
        push_string(&mut out, &self.recipient_public_key);
        push_bytes(&mut out, &self.aad_digest);
        push_bytes(&mut out, &self.encapped_key);
        out.extend_from_slice(&(SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 as u32).to_be_bytes());
        push_bytes(&mut out, &self.ciphertext_and_tag);
        Ok(out)
    }
}

/// Decodes one canonical signer-envelope HPKE payload received at the
/// browser worker boundary.
#[cfg(feature = "hpke")]
pub fn decode_ecdsa_signer_envelope_hpke_payload_v1(
    bytes: &[u8],
) -> Result<EcdsaSignerEnvelopeHpkePayloadV1, EcdsaClientProtocolError> {
    let mut decoder = SignerEnvelopeDecoderV1::new(bytes);
    decoder.expect_bytes(SIGNER_ENVELOPE_HPKE_PAYLOAD_VERSION_V1)?;
    decoder.expect_bytes(SIGNER_ENVELOPE_HPKE_ALGORITHM_V1)?;
    let recipient_role = decoder.read_role()?;
    let key_epoch = decoder.read_string()?;
    let recipient_public_key = decoder.read_string()?;
    let aad_digest = decoder.read_fixed::<32>()?;
    let encapped_key = decoder.read_fixed::<32>()?;
    let tag_len = decoder.read_u32()?;
    if tag_len as usize != SIGNER_ENVELOPE_HPKE_TAG_LEN_V1 {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let ciphertext_and_tag = decoder.read_bytes()?.to_vec();
    decoder.finish()?;
    let payload = EcdsaSignerEnvelopeHpkePayloadV1 {
        recipient_role,
        key_epoch,
        recipient_public_key,
        aad_digest,
        encapped_key,
        ciphertext_and_tag,
    };
    payload.canonical_bytes()?;
    Ok(payload)
}

#[cfg(feature = "hpke")]
struct SignerEnvelopeDecoderV1<'a> {
    bytes: &'a [u8],
    offset: usize,
}

#[cfg(feature = "hpke")]
impl<'a> SignerEnvelopeDecoderV1<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> Result<(), EcdsaClientProtocolError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(EcdsaClientProtocolError::InvalidShape)
        }
    }

    fn expect_bytes(&mut self, expected: &[u8]) -> Result<(), EcdsaClientProtocolError> {
        if self.read_bytes()? == expected {
            Ok(())
        } else {
            Err(EcdsaClientProtocolError::InvalidShape)
        }
    }

    fn read_role(&mut self) -> Result<EcdsaDeriverRoleV1, EcdsaClientProtocolError> {
        match self.read_bytes()? {
            b"signer_a" => Ok(EcdsaDeriverRoleV1::A),
            b"signer_b" => Ok(EcdsaDeriverRoleV1::B),
            _ => Err(EcdsaClientProtocolError::InvalidShape),
        }
    }

    fn read_string(&mut self) -> Result<String, EcdsaClientProtocolError> {
        core::str::from_utf8(self.read_bytes()?)
            .map(str::to_owned)
            .map_err(|_| EcdsaClientProtocolError::InvalidShape)
    }

    fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], EcdsaClientProtocolError> {
        self.read_bytes()?
            .try_into()
            .map_err(|_| EcdsaClientProtocolError::InvalidShape)
    }

    fn read_u32(&mut self) -> Result<u32, EcdsaClientProtocolError> {
        let end = self
            .offset
            .checked_add(4)
            .ok_or(EcdsaClientProtocolError::InvalidShape)?;
        if end > self.bytes.len() {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let value = u32::from_be_bytes(
            self.bytes[self.offset..end]
                .try_into()
                .map_err(|_| EcdsaClientProtocolError::InvalidShape)?,
        );
        self.offset = end;
        Ok(value)
    }

    fn read_bytes(&mut self) -> Result<&'a [u8], EcdsaClientProtocolError> {
        let length = self.read_u32()? as usize;
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EcdsaClientProtocolError::InvalidShape)?;
        if end > self.bytes.len() {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
}

/// Client-safe protocol failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaClientProtocolError {
    /// A public identity, key, or wire field was malformed.
    InvalidShape,
    /// HPKE sealing or opening failed.
    HpkeFailed,
    /// Public DLEQ proof verification failed.
    InvalidDleqProof,
    /// Public PRF proof was created for a different canonical context.
    ContextMismatch,
}

/// Fixed public threshold-PRF purpose verified by the browser client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaPrfPurposeV1 {
    /// ECDSA server-share derivation output.
    YServer,
    /// Client recipient base output.
    XClientBase,
    /// SigningWorker recipient base output.
    XServerBase,
}

impl EcdsaPrfPurposeV1 {
    fn wire_label(self) -> &'static [u8] {
        match self {
            Self::YServer => b"router-ab-ecdsa-derivation/y-server/v1",
            Self::XClientBase => b"router-ab/x_client_base/v1",
            Self::XServerBase => b"router-ab/x_server_base/v1",
        }
    }
}

/// Public threshold-PRF context required for proof verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPrfPublicContextV1 {
    /// Fixed output purpose.
    pub purpose: EcdsaPrfPurposeV1,
    /// Canonical transcript context bytes.
    pub context_bytes: Vec<u8>,
}

/// Canonical public proof-bundle wire material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPrfPublicProofBundleV1 {
    /// `share_id(2) || context_tag(32) || partial_point(32)`.
    pub partial_wire: [u8; 66],
    /// `share_id(2) || commitment_point(32)`.
    pub commitment_wire: [u8; 34],
    /// `challenge_scalar(32) || response_scalar(32)`.
    pub proof_wire: [u8; 64],
}

/// One role-bound public proof bundle accepted by the client finalizer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRoleBoundPrfProofV1 {
    /// Deriver role that produced this proof.
    pub role: EcdsaDeriverRoleV1,
    /// Public proof material.
    pub proof: EcdsaPrfPublicProofBundleV1,
}

/// Public stable tenant-root PRF context used for client output verification.
///
/// The context bytes contain only the refresh-invariant application binding.
/// The custody digest is retained separately for the bound DLEQ transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaStablePrfPublicContextV2 {
    stable_context_digest: [u8; 32],
    custody_binding_digest: [u8; 32],
    context_bytes: Vec<u8>,
}

impl EcdsaStablePrfPublicContextV2 {
    /// Builds the canonical stable context and its independent proof binding.
    pub fn new(application_binding_digest: [u8; 32], custody_binding_digest: [u8; 32]) -> Self {
        let context_bytes = stable_context_bytes(&application_binding_digest);
        let stable_context_digest = Sha256::digest(&context_bytes).into();
        Self {
            stable_context_digest,
            custody_binding_digest,
            context_bytes,
        }
    }

    /// Returns the digest of the exact stable context bytes.
    pub fn stable_context_digest(&self) -> [u8; 32] {
        self.stable_context_digest
    }

    /// Returns the independent custody digest bound into the DLEQ proof.
    pub fn custody_binding_digest(&self) -> [u8; 32] {
        self.custody_binding_digest
    }

    /// Returns the exact stable context bytes supplied to threshold-PRF.
    pub fn canonical_context_bytes(&self) -> &[u8] {
        &self.context_bytes
    }
}

/// Canonical public proof material for one stable tenant-root client partial.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaStablePrfPublicProofBundleV2 {
    /// Digest of the exact stable PRF context bytes.
    pub stable_context_digest: [u8; 32],
    /// Digest of the custody record bound into the DLEQ proof.
    pub custody_binding_digest: [u8; 32],
    /// Fixed-width threshold-PRF proof material.
    pub proof: EcdsaPrfPublicProofBundleV1,
}

/// One role-bound stable tenant-root client proof bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaRoleBoundStablePrfProofV2 {
    /// Deriver role that produced this proof.
    pub role: EcdsaDeriverRoleV1,
    /// Stable tenant-root proof material.
    pub proof: EcdsaStablePrfPublicProofBundleV2,
}

/// Decrypted V2 stable tenant-root proof bundle addressed to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaOpenedClientProofBundleV2 {
    /// Exact outer Router transcript digest.
    pub transcript_digest: [u8; 32],
    /// Exact producing signer identity.
    pub signer: EcdsaSignerIdentityV1,
    /// Exact client recipient identity.
    pub recipient_identity: String,
    /// Stable tenant-root proof material.
    pub proof: EcdsaStablePrfPublicProofBundleV2,
}

/// Client-ready recipient-encrypted proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcdsaClientProofBundleDeliveryV1 {
    /// Fixed recipient proof-bundle wire kind.
    pub kind: EcdsaClientProofBundleDeliveryKindV1,
    /// Base64url transcript digest.
    pub transcript_digest_b64u: String,
    /// Base64url recipient-encrypted proof-bundle payload.
    pub payload_b64u: String,
}

/// Fixed client proof-bundle delivery kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EcdsaClientProofBundleDeliveryKindV1 {
    /// Recipient-encrypted proof bundle.
    RecipientProofBundle,
}

/// Exact Deriver A/B client proof bundles for one ceremony transcript.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcdsaClientProofBundlePairDeliveryV1 {
    /// Deriver A client proof bundle.
    pub signer_a: EcdsaClientProofBundleDeliveryV1,
    /// Deriver B client proof bundle.
    pub signer_b: EcdsaClientProofBundleDeliveryV1,
}

/// Verifies both proof-contained commitments and DLEQs, then combines the output.
pub fn finalize_ecdsa_prf_two_party_output_v1(
    context: &EcdsaPrfPublicContextV1,
    deriver_a: &EcdsaRoleBoundPrfProofV1,
    deriver_b: &EcdsaRoleBoundPrfProofV1,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    finalize_role_bound_ecdsa_prf_two_party_output_v1(context, deriver_a, deriver_b)
}

/// Verifies one Deriver partial against its public root-share commitment.
pub fn verify_ecdsa_prf_public_dleq_proof_v1(
    context: &EcdsaPrfPublicContextV1,
    bundle: &EcdsaPrfPublicProofBundleV1,
) -> Result<(), EcdsaClientProtocolError> {
    if context.context_bytes.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let partial_share_id = u16::from_be_bytes([bundle.partial_wire[0], bundle.partial_wire[1]]);
    let commitment_share_id =
        u16::from_be_bytes([bundle.commitment_wire[0], bundle.commitment_wire[1]]);
    if partial_share_id == 0 || partial_share_id != commitment_share_id {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    let expected_context_tag = prf_context_tag(context)?;
    if !bool::from(bundle.partial_wire[2..34].ct_eq(&expected_context_tag)) {
        return Err(EcdsaClientProtocolError::ContextMismatch);
    }
    let partial_point = decompress_ristretto(&bundle.partial_wire[34..66])?;
    let commitment_point = decompress_ristretto(&bundle.commitment_wire[2..34])?;
    let challenge = canonical_scalar(&bundle.proof_wire[0..32])?;
    let response = canonical_scalar(&bundle.proof_wire[32..64])?;
    let input_point = prf_input_point(context)?;
    let nonce_g = (response * RISTRETTO_BASEPOINT_POINT) - (challenge * commitment_point);
    let nonce_p = (response * input_point) - (challenge * partial_point);
    let expected_challenge = prf_dleq_challenge(
        context,
        &expected_context_tag,
        partial_share_id,
        &input_point,
        &commitment_point,
        &partial_point,
        &nonce_g,
        &nonce_p,
    )?;
    if bool::from(challenge.to_bytes().ct_eq(&expected_challenge.to_bytes())) {
        return Ok(());
    }
    Err(EcdsaClientProtocolError::InvalidDleqProof)
}

/// Verifies one stable tenant-root client partial against its bound custody
/// digest and public root-share commitment.
pub fn verify_ecdsa_stable_prf_public_dleq_proof_v2(
    context: &EcdsaStablePrfPublicContextV2,
    bundle: &EcdsaStablePrfPublicProofBundleV2,
) -> Result<(), EcdsaClientProtocolError> {
    if bundle.stable_context_digest != context.stable_context_digest
        || bundle.custody_binding_digest != context.custody_binding_digest
    {
        return Err(EcdsaClientProtocolError::ContextMismatch);
    }
    let proof = &bundle.proof;
    let partial_share_id = u16::from_be_bytes([proof.partial_wire[0], proof.partial_wire[1]]);
    let commitment_share_id =
        u16::from_be_bytes([proof.commitment_wire[0], proof.commitment_wire[1]]);
    if partial_share_id == 0 || partial_share_id != commitment_share_id {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    let expected_context_tag = prf_context_tag_v2(context)?;
    if !bool::from(proof.partial_wire[2..34].ct_eq(&expected_context_tag)) {
        return Err(EcdsaClientProtocolError::ContextMismatch);
    }
    let partial_point = decompress_ristretto(&proof.partial_wire[34..66])?;
    let commitment_point = decompress_ristretto(&proof.commitment_wire[2..34])?;
    let challenge = canonical_scalar(&proof.proof_wire[0..32])?;
    let response = canonical_scalar(&proof.proof_wire[32..64])?;
    let input_point = prf_input_point_v2(context)?;
    let nonce_g = (response * RISTRETTO_BASEPOINT_POINT) - (challenge * commitment_point);
    let nonce_p = (response * input_point) - (challenge * partial_point);
    let expected_challenge = prf_dleq_challenge_v2(
        context,
        &expected_context_tag,
        partial_share_id,
        &input_point,
        &commitment_point,
        &partial_point,
        &nonce_g,
        &nonce_p,
    )?;
    if bool::from(challenge.to_bytes().ct_eq(&expected_challenge.to_bytes())) {
        return Ok(());
    }
    Err(EcdsaClientProtocolError::InvalidDleqProof)
}

/// Verifies and combines the exact Deriver A/B stable tenant-root client
/// proof bundles.
pub fn finalize_ecdsa_stable_prf_two_party_output_v2(
    context: &EcdsaStablePrfPublicContextV2,
    deriver_a: &EcdsaRoleBoundStablePrfProofV2,
    deriver_b: &EcdsaRoleBoundStablePrfProofV2,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    if deriver_a.role != EcdsaDeriverRoleV1::A || deriver_b.role != EcdsaDeriverRoleV1::B {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    if proof_share_id(&deriver_a.proof.proof) != 1 || proof_share_id(&deriver_b.proof.proof) != 2 {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    verify_ecdsa_stable_prf_public_dleq_proof_v2(context, &deriver_a.proof)?;
    verify_ecdsa_stable_prf_public_dleq_proof_v2(context, &deriver_b.proof)?;
    let partial_a = decompress_ristretto(&deriver_a.proof.proof.partial_wire[34..66])?;
    let partial_b = decompress_ristretto(&deriver_b.proof.proof.partial_wire[34..66])?;
    let combined = (Scalar::from(2_u64) * partial_a) - partial_b;
    prf_output_v2(context, &combined)
}

fn finalize_role_bound_ecdsa_prf_two_party_output_v1(
    context: &EcdsaPrfPublicContextV1,
    deriver_a: &EcdsaRoleBoundPrfProofV1,
    deriver_b: &EcdsaRoleBoundPrfProofV1,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    if deriver_a.role != EcdsaDeriverRoleV1::A || deriver_b.role != EcdsaDeriverRoleV1::B {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    if proof_share_id(&deriver_a.proof) != 1 || proof_share_id(&deriver_b.proof) != 2 {
        return Err(EcdsaClientProtocolError::InvalidDleqProof);
    }
    verify_ecdsa_prf_public_dleq_proof_v1(context, &deriver_a.proof)?;
    verify_ecdsa_prf_public_dleq_proof_v1(context, &deriver_b.proof)?;
    let partial_a = decompress_ristretto(&deriver_a.proof.partial_wire[34..66])?;
    let partial_b = decompress_ristretto(&deriver_b.proof.partial_wire[34..66])?;
    let combined = (Scalar::from(2_u64) * partial_a) - partial_b;
    prf_output(context, &combined)
}

/// Seals canonical signer input for exactly one Deriver role.
#[cfg(feature = "hpke")]
pub fn seal_ecdsa_signer_envelope_v1(
    recipient_key: &EcdsaSignerEnvelopePublicKeyV1,
    aad: &EcdsaRoleEnvelopeAadV1,
    plaintext: &[u8],
    seal_seed: [u8; 32],
) -> Result<EcdsaSignerEnvelopeHpkePayloadV1, EcdsaClientProtocolError> {
    aad.validate()?;
    if recipient_key.role != aad.recipient.role || plaintext.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let recipient_public_key_bytes = decode_x25519_public_key(&recipient_key.public_key)?;
    let recipient_public_key = DhKemX25519HkdfSha256::pk_from_bytes(&recipient_public_key_bytes)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let aad_bytes = aad.canonical_bytes()?;
    let mut rng = ChaCha20Rng::from_seed(seal_seed);
    let (encapped_key, ciphertext_and_tag) = SignerEnvelopeHpkeV1::seal_base(
        &mut rng,
        &recipient_public_key,
        SIGNER_ENVELOPE_HPKE_INFO_V1,
        &aad_bytes,
        plaintext,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    let encapped_key = encapped_key
        .as_ref()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    Ok(EcdsaSignerEnvelopeHpkePayloadV1 {
        recipient_role: recipient_key.role,
        key_epoch: recipient_key.key_epoch.clone(),
        recipient_public_key: recipient_key.public_key.clone(),
        aad_digest: aad.digest()?,
        encapped_key,
        ciphertext_and_tag,
    })
}

/// Opens a signer envelope after checking public key and AAD bindings.
#[cfg(feature = "hpke")]
pub fn open_ecdsa_signer_envelope_v1(
    payload: &EcdsaSignerEnvelopeHpkePayloadV1,
    aad: &EcdsaRoleEnvelopeAadV1,
    recipient_private_key: &[u8; 32],
) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    if payload.recipient_role != aad.recipient.role || payload.aad_digest != aad.digest()? {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient_private_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    decode_x25519_public_key(&payload.recipient_public_key)?;
    let encapped_key = DhKemX25519HkdfSha256::enc_from_bytes(&payload.encapped_key)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    SignerEnvelopeHpkeV1::open_base(
        &encapped_key,
        &private_key,
        SIGNER_ENVELOPE_HPKE_INFO_V1,
        &aad.canonical_bytes()?,
        &payload.ciphertext_and_tag,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)
}

fn require_non_empty(value: &str) -> Result<(), EcdsaClientProtocolError> {
    if value.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn push_bytes(out: &mut Vec<u8>, value: &[u8]) {
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_bytes(out, value.as_bytes());
}

fn digest32(bytes: &[u8]) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let digest = Sha256::digest(bytes);
    digest
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn stable_context_bytes(application_binding_digest: &[u8; 32]) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(ECDSA_STABLE_CONTEXT_DOMAIN_V1);
    push_len16(&mut bytes, ECDSA_STABLE_CONTEXT_SCHEME_ID_V1)
        .expect("fixed stable-context scheme id fits u16");
    push_len16(&mut bytes, ECDSA_STABLE_CONTEXT_CURVE_V1)
        .expect("fixed stable-context curve id fits u16");
    bytes.extend_from_slice(application_binding_digest);
    bytes.push(2);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&2_u16.to_be_bytes());
    bytes
}

fn prf_input_point(
    context: &EcdsaPrfPublicContextV1,
) -> Result<RistrettoPoint, EcdsaClientProtocolError> {
    let transcript = prf_transcript(PRF_INPUT_DOMAIN_V1, context, &[])?;
    Ok(RistrettoPoint::hash_from_bytes::<Sha512>(&transcript))
}

fn prf_context_tag(
    context: &EcdsaPrfPublicContextV1,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let transcript = prf_transcript(PRF_PARTIAL_CONTEXT_DOMAIN_V1, context, &[])?;
    let digest = Sha512::digest(transcript);
    digest[..32]
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn proof_share_id(bundle: &EcdsaPrfPublicProofBundleV1) -> u16 {
    u16::from_be_bytes([bundle.partial_wire[0], bundle.partial_wire[1]])
}

fn prf_output(
    context: &EcdsaPrfPublicContextV1,
    point: &RistrettoPoint,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let transcript = prf_transcript(
        b"threshold-prf/output",
        context,
        point.compress().as_bytes(),
    )?;
    let digest = Sha512::digest(transcript);
    let mut output: [u8; 32] = digest[..32]
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    if matches!(
        context.purpose,
        EcdsaPrfPurposeV1::XClientBase | EcdsaPrfPurposeV1::XServerBase
    ) {
        output = Scalar::from_bytes_mod_order(output).to_bytes();
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn prf_dleq_challenge(
    context: &EcdsaPrfPublicContextV1,
    context_tag: &[u8; 32],
    share_id: u16,
    input_point: &RistrettoPoint,
    commitment_point: &RistrettoPoint,
    partial_point: &RistrettoPoint,
    nonce_g: &RistrettoPoint,
    nonce_p: &RistrettoPoint,
) -> Result<Scalar, EcdsaClientProtocolError> {
    prf_dleq_challenge_for(
        context.purpose.wire_label(),
        context_tag,
        None,
        share_id,
        input_point,
        commitment_point,
        partial_point,
        nonce_g,
        nonce_p,
    )
}

fn prf_input_point_v2(
    context: &EcdsaStablePrfPublicContextV2,
) -> Result<RistrettoPoint, EcdsaClientProtocolError> {
    prf_input_point(&stable_prf_context_v1(context))
}

fn prf_context_tag_v2(
    context: &EcdsaStablePrfPublicContextV2,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    prf_context_tag(&stable_prf_context_v1(context))
}

fn prf_output_v2(
    context: &EcdsaStablePrfPublicContextV2,
    point: &RistrettoPoint,
) -> Result<[u8; 32], EcdsaClientProtocolError> {
    prf_output(&stable_prf_context_v1(context), point)
}

#[allow(clippy::too_many_arguments)]
fn prf_dleq_challenge_v2(
    context: &EcdsaStablePrfPublicContextV2,
    context_tag: &[u8; 32],
    share_id: u16,
    input_point: &RistrettoPoint,
    commitment_point: &RistrettoPoint,
    partial_point: &RistrettoPoint,
    nonce_g: &RistrettoPoint,
    nonce_p: &RistrettoPoint,
) -> Result<Scalar, EcdsaClientProtocolError> {
    prf_dleq_challenge_for(
        EcdsaPrfPurposeV1::XClientBase.wire_label(),
        context_tag,
        Some(&context.custody_binding_digest),
        share_id,
        input_point,
        commitment_point,
        partial_point,
        nonce_g,
        nonce_p,
    )
}

#[allow(clippy::too_many_arguments)]
fn prf_dleq_challenge_for(
    purpose_wire_label: &[u8],
    context_tag: &[u8; 32],
    proof_binding_digest: Option<&[u8; 32]>,
    share_id: u16,
    input_point: &RistrettoPoint,
    commitment_point: &RistrettoPoint,
    partial_point: &RistrettoPoint,
    nonce_g: &RistrettoPoint,
    nonce_p: &RistrettoPoint,
) -> Result<Scalar, EcdsaClientProtocolError> {
    let mut transcript = Vec::new();
    let domain = if proof_binding_digest.is_some() {
        PRF_DLEQ_BOUND_DOMAIN_V1
    } else {
        PRF_DLEQ_DOMAIN_V1
    };
    push_len16(&mut transcript, domain)?;
    push_len16(&mut transcript, PRF_SUITE_V1)?;
    push_len16(&mut transcript, purpose_wire_label)?;
    transcript.extend_from_slice(context_tag);
    if let Some(proof_binding_digest) = proof_binding_digest {
        transcript.extend_from_slice(proof_binding_digest);
    }
    transcript.extend_from_slice(&share_id.to_be_bytes());
    transcript.extend_from_slice(RISTRETTO_BASEPOINT_POINT.compress().as_bytes());
    transcript.extend_from_slice(input_point.compress().as_bytes());
    transcript.extend_from_slice(commitment_point.compress().as_bytes());
    transcript.extend_from_slice(partial_point.compress().as_bytes());
    transcript.extend_from_slice(nonce_g.compress().as_bytes());
    transcript.extend_from_slice(nonce_p.compress().as_bytes());
    let digest = Sha512::digest(transcript);
    let wide: [u8; 64] = digest
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    Ok(Scalar::from_bytes_mod_order_wide(&wide))
}

fn stable_prf_context_v1(context: &EcdsaStablePrfPublicContextV2) -> EcdsaPrfPublicContextV1 {
    EcdsaPrfPublicContextV1 {
        purpose: EcdsaPrfPurposeV1::XClientBase,
        context_bytes: context.context_bytes.clone(),
    }
}

fn prf_transcript(
    domain: &[u8],
    context: &EcdsaPrfPublicContextV1,
    payload: &[u8],
) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    let mut transcript = Vec::new();
    push_len16(&mut transcript, domain)?;
    push_len16(&mut transcript, PRF_SUITE_V1)?;
    push_len16(&mut transcript, context.purpose.wire_label())?;
    push_bytes(&mut transcript, &context.context_bytes);
    push_bytes(&mut transcript, payload);
    Ok(transcript)
}

fn push_len16(out: &mut Vec<u8>, value: &[u8]) -> Result<(), EcdsaClientProtocolError> {
    let length = u16::try_from(value.len()).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

fn decompress_ristretto(value: &[u8]) -> Result<RistrettoPoint, EcdsaClientProtocolError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidDleqProof)?;
    CompressedRistretto(bytes)
        .decompress()
        .ok_or(EcdsaClientProtocolError::InvalidDleqProof)
}

fn canonical_scalar(value: &[u8]) -> Result<Scalar, EcdsaClientProtocolError> {
    let bytes: [u8; 32] = value
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidDleqProof)?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
        .ok_or(EcdsaClientProtocolError::InvalidDleqProof)
}

#[cfg(feature = "hpke")]
fn decode_x25519_public_key(value: &str) -> Result<[u8; 32], EcdsaClientProtocolError> {
    let hex = value
        .strip_prefix("x25519:")
        .ok_or(EcdsaClientProtocolError::InvalidShape)?;
    if hex.len() != 64 {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in hex.as_bytes().chunks_exact(2).enumerate() {
        let high = decode_lower_hex_nibble(chunk[0])?;
        let low = decode_lower_hex_nibble(chunk[1])?;
        bytes[index] = (high << 4) | low;
    }
    Ok(bytes)
}

#[cfg(feature = "hpke")]
fn encode_x25519_public_key(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity("x25519:".len() + bytes.len() * 2);
    encoded.push_str("x25519:");
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(feature = "hpke")]
fn decode_lower_hex_nibble(value: u8) -> Result<u8, EcdsaClientProtocolError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(EcdsaClientProtocolError::InvalidShape),
    }
}

#[cfg(all(test, feature = "hpke"))]
fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

#[cfg(all(test, feature = "hpke"))]
mod tests {
    use super::*;

    fn aad() -> EcdsaRoleEnvelopeAadV1 {
        EcdsaRoleEnvelopeAadV1 {
            lifecycle_id: "lifecycle-1".to_owned(),
            work_kind: "registration_prepare".to_owned(),
            primitive_request_kind: "registration".to_owned(),
            signer_set_id: "signer-set-1".to_owned(),
            recipient: EcdsaSignerIdentityV1 {
                role: EcdsaDeriverRoleV1::A,
                signer_id: "deriver-a-1".to_owned(),
                key_epoch: "deriver-a-epoch-1".to_owned(),
            },
            selected_server: EcdsaSelectedServerIdentityV1 {
                server_id: "server-1".to_owned(),
                key_epoch: "server-epoch-1".to_owned(),
                recipient_encryption_key: "x25519:server-output-key".to_owned(),
            },
            transcript_digest: [0x11; 32],
            router_request_digest: [0x22; 32],
            expires_at_ms: 2_000,
        }
    }

    #[test]
    fn signer_envelope_round_trip_rejects_aad_drift() {
        let (private_key, public_key) =
            DhKemX25519HkdfSha256::derive_key_pair(&[0x41; 32]).expect("keypair");
        let private_key: [u8; 32] = DhKemX25519HkdfSha256::sk_to_bytes(&private_key)
            .as_slice()
            .try_into()
            .expect("private key bytes");
        let recipient = EcdsaSignerEnvelopePublicKeyV1 {
            role: EcdsaDeriverRoleV1::A,
            key_epoch: "deriver-a-epoch-1".to_owned(),
            public_key: format!(
                "x25519:{}",
                lower_hex(&DhKemX25519HkdfSha256::pk_to_bytes(&public_key)),
            ),
        };
        let aad = aad();
        let payload =
            seal_ecdsa_signer_envelope_v1(&recipient, &aad, b"canonical-signer-input", [0x52; 32])
                .expect("seal");
        let decoded = decode_ecdsa_signer_envelope_hpke_payload_v1(
            &payload.canonical_bytes().expect("canonical payload"),
        )
        .expect("decode");
        assert_eq!(decoded, payload);
        assert_eq!(
            open_ecdsa_signer_envelope_v1(&payload, &aad, &private_key).expect("open"),
            b"canonical-signer-input",
        );
        let mut drifted = aad;
        drifted.router_request_digest[0] ^= 1;
        assert_eq!(
            open_ecdsa_signer_envelope_v1(&payload, &drifted, &private_key),
            Err(EcdsaClientProtocolError::InvalidShape),
        );
    }

    #[test]
    fn stable_client_prf_combines_bound_proofs_and_rejects_custody_substitution() {
        let context = EcdsaStablePrfPublicContextV2::new([0x17; 32], [0x28; 32]);
        let deriver_a = stable_proof_for_test(
            EcdsaDeriverRoleV1::A,
            Scalar::from_bytes_mod_order([0x31; 32]),
            Scalar::from_bytes_mod_order([0x41; 32]),
            &context,
        );
        let deriver_b = stable_proof_for_test(
            EcdsaDeriverRoleV1::B,
            Scalar::from_bytes_mod_order([0x32; 32]),
            Scalar::from_bytes_mod_order([0x42; 32]),
            &context,
        );
        let output =
            finalize_ecdsa_stable_prf_two_party_output_v2(&context, &deriver_a, &deriver_b)
                .expect("stable client proof pair combines");
        assert_eq!(
            output,
            finalize_ecdsa_stable_prf_two_party_output_v2(
                &EcdsaStablePrfPublicContextV2::new([0x17; 32], [0x28; 32]),
                &deriver_a,
                &deriver_b,
            )
            .expect("same stable context reproduces output"),
        );
        let rotated_custody = EcdsaStablePrfPublicContextV2::new([0x17; 32], [0x29; 32]);
        assert_eq!(
            verify_ecdsa_stable_prf_public_dleq_proof_v2(
                &rotated_custody,
                &EcdsaStablePrfPublicProofBundleV2 {
                    stable_context_digest: context.stable_context_digest(),
                    custody_binding_digest: context.custody_binding_digest(),
                    proof: deriver_a.proof.proof.clone(),
                },
            ),
            Err(EcdsaClientProtocolError::ContextMismatch),
        );
    }

    fn stable_proof_for_test(
        role: EcdsaDeriverRoleV1,
        share: Scalar,
        blind: Scalar,
        context: &EcdsaStablePrfPublicContextV2,
    ) -> EcdsaRoleBoundStablePrfProofV2 {
        let share_id = match role {
            EcdsaDeriverRoleV1::A => 1_u16,
            EcdsaDeriverRoleV1::B => 2_u16,
        };
        let input_point = prf_input_point_v2(context).expect("stable input point");
        let context_tag = prf_context_tag_v2(context).expect("stable context tag");
        let partial_point = share * input_point;
        let commitment_point = share * RISTRETTO_BASEPOINT_POINT;
        let nonce_g = blind * RISTRETTO_BASEPOINT_POINT;
        let nonce_p = blind * input_point;
        let challenge = prf_dleq_challenge_v2(
            context,
            &context_tag,
            share_id,
            &input_point,
            &commitment_point,
            &partial_point,
            &nonce_g,
            &nonce_p,
        )
        .expect("stable challenge");
        let response = blind + (challenge * share);
        let mut partial_wire = [0_u8; 66];
        partial_wire[..2].copy_from_slice(&share_id.to_be_bytes());
        partial_wire[2..34].copy_from_slice(&context_tag);
        partial_wire[34..].copy_from_slice(partial_point.compress().as_bytes());
        let mut commitment_wire = [0_u8; 34];
        commitment_wire[..2].copy_from_slice(&share_id.to_be_bytes());
        commitment_wire[2..].copy_from_slice(commitment_point.compress().as_bytes());
        let mut proof_wire = [0_u8; 64];
        proof_wire[..32].copy_from_slice(&challenge.to_bytes());
        proof_wire[32..].copy_from_slice(&response.to_bytes());
        EcdsaRoleBoundStablePrfProofV2 {
            role,
            proof: EcdsaStablePrfPublicProofBundleV2 {
                stable_context_digest: context.stable_context_digest(),
                custody_binding_digest: context.custody_binding_digest(),
                proof: EcdsaPrfPublicProofBundleV1 {
                    partial_wire,
                    commitment_wire,
                    proof_wire,
                },
            },
        }
    }
}
