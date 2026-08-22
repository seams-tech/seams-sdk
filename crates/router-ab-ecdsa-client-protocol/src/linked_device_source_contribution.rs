//! Ephemeral ECDSA source contribution for R103E linked-device installation.
//!
//! Device 1 keeps both the source client scalar and the sampled target client
//! scalar inside its WASM boundary. Only the additive delta leaves that
//! boundary, encrypted to the admitted SigningWorker recipient. The target
//! client scalar is encrypted independently to Device 2. Neither plaintext is
//! represented by a protocol record.

use base64ct::{Base64UrlUnpadded, Encoding};
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::PublicKey;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{EcdsaClientProtocolError, EcdsaMaterialActivationRefV1};

/// Canonical digest domain for the linked-device source-contribution binding.
pub const LINKED_DEVICE_SOURCE_CONTRIBUTION_BINDING_DOMAIN_V1: &str =
    "seams/linked-device/ecdsa-source-contribution-binding/v1";
/// Canonical envelope domain for linked-device source contributions.
pub const LINKED_DEVICE_SOURCE_CONTRIBUTION_ENVELOPE_DOMAIN_V1: &str =
    "seams/linked-device/ecdsa-source-contribution-envelope/v1";
const LINKED_DEVICE_SOURCE_CONTRIBUTION_HPKE_INFO_V1: &[u8] =
    b"seams/linked-device/ecdsa-source-contribution/hpke-x25519-hkdf-sha256-aes256gcm/v1";

/// Exact source signer and activation identity bound to the contribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedDeviceEcdsaSourceSignerIdentityV1 {
    /// Exact source material activation reference.
    pub activation: EcdsaMaterialActivationRefV1,
    /// Source client verifying share, base64url encoded.
    pub client_public_key33_b64u: String,
    /// Source relayer verifying share, base64url encoded.
    pub relayer_public_key33_b64u: String,
    /// Source threshold public key, base64url encoded.
    pub threshold_public_key33_b64u: String,
    /// Source threshold Ethereum address, base64url encoded.
    pub threshold_ethereum_address20_b64u: String,
}

/// Exact Device 2 recipient and factor preparation bound to the contribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedDeviceEcdsaTargetRecipientPreparationV1 {
    /// Exact target material activation reference.
    pub activation: EcdsaMaterialActivationRefV1,
    /// Device 2 identity.
    pub target_device_id: String,
    /// Verified target-factor digest, base64url encoded.
    pub target_factor_verification_digest_b64u: String,
    /// Device 2 X25519 recipient for its client share, base64url encoded.
    pub client_recipient_public_key_b64u: String,
    /// SigningWorker X25519 recipient for the transient delta, base64url encoded.
    pub signing_worker_recipient_public_key_b64u: String,
}

/// Public Device 2 preparation before Device 1 samples its target client
/// share. The target client verifying key is intentionally absent here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedDeviceEcdsaSourceContributionPreparationV1 {
    /// Link-session identity.
    pub link_session_id: String,
    /// Enrollment identity.
    pub enrollment_id: String,
    /// Exact source authority identity.
    pub source_authority_id: String,
    /// Exact source signer/activation identity.
    pub source: LinkedDeviceEcdsaSourceSignerIdentityV1,
    /// Exact Device 2 target recipient/factor preparation.
    pub target: LinkedDeviceEcdsaTargetRecipientPreparationV1,
}

impl LinkedDeviceEcdsaSourceContributionPreparationV1 {
    /// Validates the public preparation without accepting target key material.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        validate_preparation_fields(
            &self.link_session_id,
            &self.enrollment_id,
            &self.source_authority_id,
            &self.source,
            &self.target,
        )
    }

    /// Binds the sampled target client verifying key to this preparation.
    pub fn bind_target_client_public_key(
        self,
        target_client_public_key33_b64u: String,
    ) -> Result<LinkedDeviceEcdsaSourceContributionBindingV1, EcdsaClientProtocolError> {
        self.validate()?;
        let binding = LinkedDeviceEcdsaSourceContributionBindingV1 {
            link_session_id: self.link_session_id,
            enrollment_id: self.enrollment_id,
            source_authority_id: self.source_authority_id,
            source: self.source,
            target: self.target,
            target_client_public_key33_b64u,
        };
        binding.validate()?;
        Ok(binding)
    }
}

/// Public binding for one linked-device source contribution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedDeviceEcdsaSourceContributionBindingV1 {
    /// Link-session identity.
    pub link_session_id: String,
    /// Enrollment identity.
    pub enrollment_id: String,
    /// Exact source authority identity.
    pub source_authority_id: String,
    /// Exact source signer/activation identity.
    pub source: LinkedDeviceEcdsaSourceSignerIdentityV1,
    /// Exact Device 2 target recipient/factor preparation.
    pub target: LinkedDeviceEcdsaTargetRecipientPreparationV1,
    /// Target client verifying share, base64url encoded.
    pub target_client_public_key33_b64u: String,
}

impl LinkedDeviceEcdsaSourceContributionBindingV1 {
    /// Validates the public binding and all key encodings.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        validate_preparation_fields(
            &self.link_session_id,
            &self.enrollment_id,
            &self.source_authority_id,
            &self.source,
            &self.target,
        )?;
        validate_public_key_b64(&self.target_client_public_key33_b64u)?;
        Ok(())
    }

    /// Returns canonical binding bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        self.validate()?;
        let mut out = Vec::new();
        text(
            &mut out,
            LINKED_DEVICE_SOURCE_CONTRIBUTION_BINDING_DOMAIN_V1,
        );
        text(&mut out, &self.link_session_id);
        text(&mut out, &self.enrollment_id);
        text(&mut out, &self.source_authority_id);
        encode_source(&mut out, &self.source)?;
        encode_target(&mut out, &self.target)?;
        let target_client = decode_fixed_bytes::<33>(&self.target_client_public_key33_b64u)?;
        lp(&mut out, &target_client);
        Ok(out)
    }

    /// Returns the canonical binding digest used as HPKE associated data.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes()?)
    }
}

fn validate_preparation_fields(
    link_session_id: &str,
    enrollment_id: &str,
    source_authority_id: &str,
    source: &LinkedDeviceEcdsaSourceSignerIdentityV1,
    target: &LinkedDeviceEcdsaTargetRecipientPreparationV1,
) -> Result<(), EcdsaClientProtocolError> {
    for value in [
        link_session_id,
        enrollment_id,
        source_authority_id,
        &source.activation.activation_id,
        &source.activation.capability,
        &source.activation.material_owner,
        &source.activation.key_binding,
        &source.activation.lifecycle_binding,
        &source.activation.signing_worker,
        &target.activation.activation_id,
        &target.activation.capability,
        &target.activation.material_owner,
        &target.activation.key_binding,
        &target.activation.lifecycle_binding,
        &target.activation.signing_worker,
        &target.target_device_id,
    ] {
        require_ascii_non_empty(value)?;
    }
    source.activation.validate()?;
    target.activation.validate()?;
    if source.activation == target.activation
        || source.activation.material_owner != target.activation.material_owner
        || source.activation.signing_worker != target.activation.signing_worker
    {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    validate_digest_b64(&source.threshold_ethereum_address20_b64u, 20)?;
    validate_digest_b64(&target.target_factor_verification_digest_b64u, 32)?;
    validate_public_key_b64(&source.client_public_key33_b64u)?;
    validate_public_key_b64(&source.relayer_public_key33_b64u)?;
    validate_public_key_b64(&source.threshold_public_key33_b64u)?;
    validate_x25519_key_b64(&target.client_recipient_public_key_b64u)?;
    validate_x25519_key_b64(&target.signing_worker_recipient_public_key_b64u)?;
    if target.client_recipient_public_key_b64u == target.signing_worker_recipient_public_key_b64u {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

/// One encrypted source contribution envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedDeviceEcdsaEncryptedSourceContributionV1 {
    /// Exact wire discriminator.
    pub kind: String,
    /// HPKE recipient public key, base64url encoded.
    pub recipient_public_key_b64u: String,
    /// Binding digest used as HPKE associated data.
    pub binding_digest_b64u: String,
    /// HPKE encapsulated key.
    pub encapped_key_b64u: String,
    /// HPKE ciphertext and authentication tag.
    pub ciphertext_b64u: String,
}

impl LinkedDeviceEcdsaEncryptedSourceContributionV1 {
    /// Validates envelope shape and returns canonical bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        if self.kind != LINKED_DEVICE_SOURCE_CONTRIBUTION_ENVELOPE_DOMAIN_V1 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let recipient = decode_fixed_bytes::<32>(&self.recipient_public_key_b64u)?;
        let binding = decode_fixed_bytes::<32>(&self.binding_digest_b64u)?;
        let encapped = decode_fixed_bytes::<32>(&self.encapped_key_b64u)?;
        let ciphertext = decode_b64(&self.ciphertext_b64u)?;
        if ciphertext.len() <= 16 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        let mut out = Vec::new();
        text(
            &mut out,
            LINKED_DEVICE_SOURCE_CONTRIBUTION_ENVELOPE_DOMAIN_V1,
        );
        lp(&mut out, &recipient);
        lp(&mut out, &binding);
        lp(&mut out, &encapped);
        lp(&mut out, &ciphertext);
        Ok(out)
    }

    /// Returns the envelope digest.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        digest32(&self.canonical_bytes()?)
    }
}

/// Device 1's one-use source contribution package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LinkedDeviceEcdsaSourceContributionPackageV1 {
    /// Exact public binding.
    pub binding: LinkedDeviceEcdsaSourceContributionBindingV1,
    /// Delta encrypted to the target SigningWorker.
    pub encrypted_delta: LinkedDeviceEcdsaEncryptedSourceContributionV1,
    /// Target client scalar encrypted to Device 2.
    pub encrypted_target_client_share: LinkedDeviceEcdsaEncryptedSourceContributionV1,
}

impl LinkedDeviceEcdsaSourceContributionPackageV1 {
    /// Validates both envelopes against the exact public binding.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        self.binding.validate()?;
        let digest = b64(&self.binding.digest()?);
        for (envelope, expected_recipient) in [
            (
                &self.encrypted_delta,
                &self.binding.target.signing_worker_recipient_public_key_b64u,
            ),
            (
                &self.encrypted_target_client_share,
                &self.binding.target.client_recipient_public_key_b64u,
            ),
        ] {
            envelope.canonical_bytes()?;
            if envelope.binding_digest_b64u != digest
                || envelope.recipient_public_key_b64u != *expected_recipient
            {
                return Err(EcdsaClientProtocolError::InvalidShape);
            }
        }
        Ok(())
    }

    /// Returns the binding digest.
    pub fn binding_digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        self.binding.digest()
    }
}

/// Seals one source contribution plaintext to an exact recipient.
pub fn seal_linked_device_ecdsa_source_contribution_v1(
    recipient_public_key_b64u: &str,
    binding_digest: &[u8; 32],
    plaintext: &[u8],
    seal_seed: [u8; 32],
) -> Result<LinkedDeviceEcdsaEncryptedSourceContributionV1, EcdsaClientProtocolError> {
    if plaintext.is_empty() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let recipient = decode_fixed_bytes::<32>(recipient_public_key_b64u)?;
    let recipient_key = DhKemX25519HkdfSha256::pk_from_bytes(&recipient)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let mut rng = ChaCha20Rng::from_seed(seal_seed);
    let (encapped, ciphertext) = Hpke::<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>::seal_base(
        &mut rng,
        &recipient_key,
        LINKED_DEVICE_SOURCE_CONTRIBUTION_HPKE_INFO_V1,
        binding_digest,
        plaintext,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)?;
    Ok(LinkedDeviceEcdsaEncryptedSourceContributionV1 {
        kind: LINKED_DEVICE_SOURCE_CONTRIBUTION_ENVELOPE_DOMAIN_V1.to_owned(),
        recipient_public_key_b64u: recipient_public_key_b64u.to_owned(),
        binding_digest_b64u: b64(binding_digest),
        encapped_key_b64u: b64(encapped.as_ref()),
        ciphertext_b64u: b64(&ciphertext),
    })
}

/// Opens one source contribution at the exact private recipient boundary.
pub fn open_linked_device_ecdsa_source_contribution_v1(
    envelope: &LinkedDeviceEcdsaEncryptedSourceContributionV1,
    recipient_private_key32: &[u8; 32],
    expected_binding_digest: &[u8; 32],
) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    envelope.canonical_bytes()?;
    if decode_fixed_bytes::<32>(&envelope.binding_digest_b64u)? != *expected_binding_digest {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient_private_key32)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let encapped = decode_fixed_bytes::<32>(&envelope.encapped_key_b64u)?;
    let encapped = DhKemX25519HkdfSha256::enc_from_bytes(&encapped)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    let ciphertext = decode_b64(&envelope.ciphertext_b64u)?;
    Hpke::<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>::open_base(
        &encapped,
        &private_key,
        LINKED_DEVICE_SOURCE_CONTRIBUTION_HPKE_INFO_V1,
        expected_binding_digest,
        &ciphertext,
    )
    .map_err(|_| EcdsaClientProtocolError::HpkeFailed)
}

fn encode_source(
    out: &mut Vec<u8>,
    source: &LinkedDeviceEcdsaSourceSignerIdentityV1,
) -> Result<(), EcdsaClientProtocolError> {
    lp(out, &source.activation.canonical_bytes()?);
    for value in [
        &source.client_public_key33_b64u,
        &source.relayer_public_key33_b64u,
        &source.threshold_public_key33_b64u,
    ] {
        lp(out, &decode_fixed_bytes::<33>(value)?);
    }
    lp(
        out,
        &decode_fixed_bytes::<20>(&source.threshold_ethereum_address20_b64u)?,
    );
    Ok(())
}

fn encode_target(
    out: &mut Vec<u8>,
    target: &LinkedDeviceEcdsaTargetRecipientPreparationV1,
) -> Result<(), EcdsaClientProtocolError> {
    lp(out, &target.activation.canonical_bytes()?);
    text(out, &target.target_device_id);
    lp(
        out,
        &decode_fixed_bytes::<32>(&target.target_factor_verification_digest_b64u)?,
    );
    lp(
        out,
        &decode_fixed_bytes::<32>(&target.client_recipient_public_key_b64u)?,
    );
    lp(
        out,
        &decode_fixed_bytes::<32>(&target.signing_worker_recipient_public_key_b64u)?,
    );
    Ok(())
}

fn validate_public_key_b64(value: &str) -> Result<(), EcdsaClientProtocolError> {
    let bytes = decode_fixed_bytes::<33>(value)?;
    let key =
        PublicKey::from_sec1_bytes(&bytes).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    if key.to_encoded_point(true).as_bytes() != bytes {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn validate_x25519_key_b64(value: &str) -> Result<(), EcdsaClientProtocolError> {
    let bytes = decode_fixed_bytes::<32>(value)?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    DhKemX25519HkdfSha256::pk_from_bytes(&bytes)
        .map(|_| ())
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn validate_digest_b64(value: &str, length: usize) -> Result<(), EcdsaClientProtocolError> {
    let bytes = decode_b64(value)?;
    if bytes.len() == length {
        Ok(())
    } else {
        Err(EcdsaClientProtocolError::InvalidShape)
    }
}

fn require_ascii_non_empty(value: &str) -> Result<(), EcdsaClientProtocolError> {
    if value.is_empty() || value.trim() != value || !value.is_ascii() {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(())
}

fn decode_fixed_bytes<const N: usize>(value: &str) -> Result<[u8; N], EcdsaClientProtocolError> {
    let bytes = decode_b64(value)?;
    bytes
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn decode_b64(value: &str) -> Result<Vec<u8>, EcdsaClientProtocolError> {
    let bytes =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    if Base64UrlUnpadded::encode_string(&bytes) != value {
        return Err(EcdsaClientProtocolError::InvalidShape);
    }
    Ok(bytes)
}

fn digest32(bytes: &[u8]) -> Result<[u8; 32], EcdsaClientProtocolError> {
    Sha256::digest(bytes)
        .as_slice()
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn b64(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

fn text(out: &mut Vec<u8>, value: &str) {
    lp(out, value.as_bytes());
}

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::EcdsaMaterialActivationRefKindV1;
    use k256::SecretKey;
    use rand_core::RngCore;

    fn b64_bytes<const N: usize>(value: u8) -> String {
        b64(&[value; N])
    }

    fn public_key(value: u8) -> String {
        let key = SecretKey::from_slice(&[value; 32]).expect("test scalar");
        b64(key.public_key().to_encoded_point(true).as_bytes())
    }

    fn activation(id: &str) -> EcdsaMaterialActivationRefV1 {
        EcdsaMaterialActivationRefV1 {
            kind: EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
            activation_id: id.to_owned(),
            capability: format!("capability-{id}"),
            material_owner: "wallet-1".to_owned(),
            key_binding: format!("key-binding-{id}"),
            lifecycle_binding: format!("lifecycle-binding-{id}"),
            signing_worker: "worker-1".to_owned(),
        }
    }

    fn binding() -> LinkedDeviceEcdsaSourceContributionBindingV1 {
        LinkedDeviceEcdsaSourceContributionBindingV1 {
            link_session_id: "link-1".to_owned(),
            enrollment_id: "enrollment-1".to_owned(),
            source_authority_id: "authority-1".to_owned(),
            source: LinkedDeviceEcdsaSourceSignerIdentityV1 {
                activation: activation("source-activation"),
                client_public_key33_b64u: public_key(3),
                relayer_public_key33_b64u: public_key(4),
                threshold_public_key33_b64u: public_key(5),
                threshold_ethereum_address20_b64u: b64_bytes::<20>(6),
            },
            target: LinkedDeviceEcdsaTargetRecipientPreparationV1 {
                activation: activation("target-activation"),
                target_device_id: "device-2".to_owned(),
                target_factor_verification_digest_b64u: b64_bytes::<32>(7),
                client_recipient_public_key_b64u: b64_bytes::<32>(8),
                signing_worker_recipient_public_key_b64u: b64_bytes::<32>(9),
            },
            target_client_public_key33_b64u: public_key(10),
        }
    }

    #[test]
    fn binding_digest_is_stable_and_changes_with_target_identity() {
        let mut first = binding();
        let digest = first.digest().expect("digest");
        assert_eq!(digest, first.digest().expect("digest retry"));
        first.target.target_device_id = "device-3".to_owned();
        assert_ne!(digest, first.digest().expect("changed digest"));
        first.target.target_device_id = "device-2".to_owned();
        first.target.activation.lifecycle_binding = "lifecycle-binding-drift".to_owned();
        assert_ne!(digest, first.digest().expect("activation drift digest"));
    }

    #[test]
    fn contribution_round_trip_requires_exact_binding() {
        let binding = binding();
        let digest = binding.digest().expect("digest");
        let (recipient_private_key, recipient_public_key) =
            DhKemX25519HkdfSha256::derive_key_pair(&[11_u8; 32]).expect("recipient keypair");
        let recipient_private: [u8; 32] =
            DhKemX25519HkdfSha256::sk_to_bytes(&recipient_private_key)
                .as_slice()
                .try_into()
                .expect("recipient private key");
        let recipient_public =
            b64(DhKemX25519HkdfSha256::pk_to_bytes(&recipient_public_key).as_ref());
        let envelope = seal_linked_device_ecdsa_source_contribution_v1(
            &recipient_public,
            &digest,
            &[42_u8; 32],
            [12_u8; 32],
        )
        .expect("seal");
        let opened =
            open_linked_device_ecdsa_source_contribution_v1(&envelope, &recipient_private, &digest)
                .expect("open");
        assert_eq!(opened, vec![42_u8; 32]);
        let mut changed = digest;
        changed[0] ^= 1;
        assert!(open_linked_device_ecdsa_source_contribution_v1(
            &envelope,
            &recipient_private,
            &changed,
        )
        .is_err());
    }

    #[test]
    fn package_rejects_swapped_recipients() {
        let mut binding = binding();
        let mut rng = ChaCha20Rng::from_seed([13_u8; 32]);
        let mut client_private = [0_u8; 32];
        let mut worker_private = [0_u8; 32];
        rng.fill_bytes(&mut client_private);
        rng.fill_bytes(&mut worker_private);
        let client_keypair =
            DhKemX25519HkdfSha256::derive_key_pair(&client_private).expect("client keypair");
        let worker_keypair =
            DhKemX25519HkdfSha256::derive_key_pair(&worker_private).expect("worker keypair");
        let client_public = b64(DhKemX25519HkdfSha256::pk_to_bytes(&client_keypair.1).as_ref());
        let worker_public = b64(DhKemX25519HkdfSha256::pk_to_bytes(&worker_keypair.1).as_ref());
        binding.target.client_recipient_public_key_b64u = client_public.clone();
        binding.target.signing_worker_recipient_public_key_b64u = worker_public.clone();
        let digest = binding.digest().expect("digest");
        let package = LinkedDeviceEcdsaSourceContributionPackageV1 {
            binding: binding.clone(),
            encrypted_delta: seal_linked_device_ecdsa_source_contribution_v1(
                &worker_public,
                &digest,
                &[1_u8; 32],
                [14_u8; 32],
            )
            .expect("delta seal"),
            encrypted_target_client_share: seal_linked_device_ecdsa_source_contribution_v1(
                &client_public,
                &digest,
                &[2_u8; 32],
                [15_u8; 32],
            )
            .expect("client seal"),
        };
        package.validate().expect("valid package");
        let mut swapped = package;
        std::mem::swap(
            &mut swapped.encrypted_delta,
            &mut swapped.encrypted_target_client_share,
        );
        assert!(swapped.validate().is_err());
    }
}
