use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::schnorr::{Signature, VerifyingKey};
use k256::PublicKey;
use sha2::{Digest, Sha256};

const CLIENT_MATERIAL_POSSESSION_CHALLENGE_DOMAIN_V1: &[u8] =
    b"router-ab-ecdsa/client-material-possession/challenge/v1";

/// Client-material possession challenge or proof failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaClientMaterialPossessionError {
    /// A challenge field or public key was malformed.
    InvalidShape,
    /// The BIP340 proof was malformed or failed verification.
    InvalidProof,
}

/// Fixed proof scheme for possession of active ECDSA client material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaClientMaterialPossessionProofSchemeV1 {
    /// BIP340 Schnorr proof over the canonical SHA-256 activation challenge.
    Secp256k1Bip340Sha256,
}

impl EcdsaClientMaterialPossessionProofSchemeV1 {
    /// Returns the canonical wire label.
    pub fn wire_label(self) -> &'static str {
        match self {
            Self::Secp256k1Bip340Sha256 => "secp256k1_bip340_sha256_v1",
        }
    }
}

/// Public activation facts bound into a client-material possession challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaClientMaterialPossessionChallengeV1 {
    /// Digest of the exact registered signer identity.
    pub registered_signer_digest32: [u8; 32],
    /// Digest of the exact registered public capability.
    pub public_capability_digest32: [u8; 32],
    /// Digest of the exact registered authority reference.
    pub authority_ref_digest32: [u8; 32],
    /// Canonical material-owner reference.
    pub material_owner_ref: String,
    /// Exact owner or linked-device lane identity.
    pub lane_id: String,
    /// Exact lane share epoch.
    pub lane_epoch: String,
    /// Compressed client-share public key bound to the active lane epoch.
    pub derivation_client_share_public_key33: [u8; 33],
    /// Active threshold material-session identity.
    pub threshold_material_session_id: String,
    /// Server generation expected by the active material session.
    pub expected_server_generation: String,
    /// One-time refresh lifecycle identity.
    pub refresh_lifecycle_id: String,
    /// One-time refresh request identity.
    pub refresh_request_id: String,
    /// Exact refresh transcript accepted by the SigningWorker.
    pub refresh_transcript_digest32: [u8; 32],
    /// Previously active SigningWorker epoch.
    pub previous_activation_epoch: String,
    /// Newly refreshed SigningWorker epoch.
    pub next_activation_epoch: String,
    /// Digest of the normalized runtime policy scope.
    pub runtime_policy_scope_digest32: [u8; 32],
    /// Gateway-generated one-use activation nonce.
    pub server_nonce32: [u8; 32],
    /// Activation request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Idempotency correlation shared by activation and commit reconciliation.
    pub idempotency_correlation_id: String,
}

impl EcdsaClientMaterialPossessionChallengeV1 {
    /// Validates the complete activation challenge.
    pub fn validate(&self) -> Result<(), EcdsaClientMaterialPossessionError> {
        require_non_empty(&self.material_owner_ref)?;
        require_non_empty(&self.lane_id)?;
        require_non_empty(&self.lane_epoch)?;
        require_non_empty(&self.threshold_material_session_id)?;
        require_non_empty(&self.expected_server_generation)?;
        require_non_empty(&self.refresh_lifecycle_id)?;
        require_non_empty(&self.refresh_request_id)?;
        require_non_empty(&self.previous_activation_epoch)?;
        require_non_empty(&self.next_activation_epoch)?;
        require_non_empty(&self.idempotency_correlation_id)?;
        if self.previous_activation_epoch == self.next_activation_epoch || self.expires_at_ms == 0 {
            return Err(EcdsaClientMaterialPossessionError::InvalidShape);
        }
        let public_key =
            PublicKey::from_sec1_bytes(self.derivation_client_share_public_key33.as_slice())
                .map_err(|_| EcdsaClientMaterialPossessionError::InvalidShape)?;
        if public_key.to_encoded_point(true).as_bytes() != self.derivation_client_share_public_key33
        {
            return Err(EcdsaClientMaterialPossessionError::InvalidShape);
        }
        Ok(())
    }

    /// Returns canonical bytes for the possession-proof challenge.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientMaterialPossessionError> {
        self.validate()?;
        let mut output = Vec::new();
        push_bytes(&mut output, CLIENT_MATERIAL_POSSESSION_CHALLENGE_DOMAIN_V1)?;
        push_bytes(
            &mut output,
            EcdsaClientMaterialPossessionProofSchemeV1::Secp256k1Bip340Sha256
                .wire_label()
                .as_bytes(),
        )?;
        push_bytes(&mut output, &self.registered_signer_digest32)?;
        push_bytes(&mut output, &self.public_capability_digest32)?;
        push_bytes(&mut output, &self.authority_ref_digest32)?;
        push_string(&mut output, &self.material_owner_ref)?;
        push_string(&mut output, &self.lane_id)?;
        push_string(&mut output, &self.lane_epoch)?;
        push_bytes(&mut output, &self.derivation_client_share_public_key33)?;
        push_string(&mut output, &self.threshold_material_session_id)?;
        push_string(&mut output, &self.expected_server_generation)?;
        push_string(&mut output, &self.refresh_lifecycle_id)?;
        push_string(&mut output, &self.refresh_request_id)?;
        push_bytes(&mut output, &self.refresh_transcript_digest32)?;
        push_string(&mut output, &self.previous_activation_epoch)?;
        push_string(&mut output, &self.next_activation_epoch)?;
        push_bytes(&mut output, &self.runtime_policy_scope_digest32)?;
        push_bytes(&mut output, &self.server_nonce32)?;
        push_bytes(&mut output, &self.expires_at_ms.to_be_bytes())?;
        push_string(&mut output, &self.idempotency_correlation_id)?;
        Ok(output)
    }

    /// Returns the SHA-256 digest signed by the role-local client material.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientMaterialPossessionError> {
        let digest = Sha256::digest(self.canonical_bytes()?);
        digest
            .as_slice()
            .try_into()
            .map_err(|_| EcdsaClientMaterialPossessionError::InvalidShape)
    }
}

/// BIP340 proof of possession for one exact activation challenge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaClientMaterialPossessionProofV1 {
    /// Fixed proof scheme.
    pub scheme: EcdsaClientMaterialPossessionProofSchemeV1,
    /// Canonical 64-byte BIP340 signature.
    pub signature64: [u8; 64],
}

impl EcdsaClientMaterialPossessionProofV1 {
    /// Creates and validates a fixed-scheme possession proof.
    pub fn new(signature64: [u8; 64]) -> Result<Self, EcdsaClientMaterialPossessionError> {
        Signature::try_from(signature64.as_slice())
            .map_err(|_| EcdsaClientMaterialPossessionError::InvalidProof)?;
        Ok(Self {
            scheme: EcdsaClientMaterialPossessionProofSchemeV1::Secp256k1Bip340Sha256,
            signature64,
        })
    }
}

/// Verifies possession of the active client share for an exact challenge.
pub fn verify_ecdsa_client_material_possession_proof_v1(
    challenge: &EcdsaClientMaterialPossessionChallengeV1,
    proof: &EcdsaClientMaterialPossessionProofV1,
) -> Result<(), EcdsaClientMaterialPossessionError> {
    challenge.validate()?;
    if proof.scheme != EcdsaClientMaterialPossessionProofSchemeV1::Secp256k1Bip340Sha256 {
        return Err(EcdsaClientMaterialPossessionError::InvalidProof);
    }
    let signature = Signature::try_from(proof.signature64.as_slice())
        .map_err(|_| EcdsaClientMaterialPossessionError::InvalidProof)?;
    let verifying_key =
        VerifyingKey::from_bytes(&challenge.derivation_client_share_public_key33[1..])
            .map_err(|_| EcdsaClientMaterialPossessionError::InvalidProof)?;
    verifying_key
        .verify_raw(&challenge.digest()?, &signature)
        .map_err(|_| EcdsaClientMaterialPossessionError::InvalidProof)
}

fn require_non_empty(value: &str) -> Result<(), EcdsaClientMaterialPossessionError> {
    if value.trim().is_empty() {
        return Err(EcdsaClientMaterialPossessionError::InvalidShape);
    }
    Ok(())
}

fn push_bytes(
    output: &mut Vec<u8>,
    value: &[u8],
) -> Result<(), EcdsaClientMaterialPossessionError> {
    let length =
        u32::try_from(value.len()).map_err(|_| EcdsaClientMaterialPossessionError::InvalidShape)?;
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
    Ok(())
}

fn push_string(
    output: &mut Vec<u8>,
    value: &str,
) -> Result<(), EcdsaClientMaterialPossessionError> {
    push_bytes(output, value.as_bytes())
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::schnorr::SigningKey;
    use k256::SecretKey;

    use super::{
        verify_ecdsa_client_material_possession_proof_v1, EcdsaClientMaterialPossessionChallengeV1,
        EcdsaClientMaterialPossessionError, EcdsaClientMaterialPossessionProofV1,
    };

    fn signing_key(secret_byte: u8) -> SigningKey {
        let mut secret32 = [0u8; 32];
        secret32[31] = secret_byte;
        SigningKey::from_bytes(&secret32).expect("signing key")
    }

    fn compressed_public_key33(secret_byte: u8) -> [u8; 33] {
        let mut secret32 = [0u8; 32];
        secret32[31] = secret_byte;
        SecretKey::from_slice(&secret32)
            .expect("secret key")
            .public_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("compressed public key")
    }

    fn challenge() -> EcdsaClientMaterialPossessionChallengeV1 {
        EcdsaClientMaterialPossessionChallengeV1 {
            registered_signer_digest32: [0x10; 32],
            public_capability_digest32: [0x11; 32],
            authority_ref_digest32: [0x12; 32],
            material_owner_ref: "material-owner-1".to_owned(),
            lane_id: "owner-lane-1".to_owned(),
            lane_epoch: "lane-epoch-1".to_owned(),
            derivation_client_share_public_key33: compressed_public_key33(7),
            threshold_material_session_id: "threshold-material-session-1".to_owned(),
            expected_server_generation: "server-generation-1".to_owned(),
            refresh_lifecycle_id: "refresh-lifecycle-1".to_owned(),
            refresh_request_id: "refresh-request-1".to_owned(),
            refresh_transcript_digest32: [0x22; 32],
            previous_activation_epoch: "activation-epoch-1".to_owned(),
            next_activation_epoch: "activation-epoch-2".to_owned(),
            runtime_policy_scope_digest32: [0x33; 32],
            server_nonce32: [0x34; 32],
            expires_at_ms: 1_900_000_000_000,
            idempotency_correlation_id: "activation-correlation-1".to_owned(),
        }
    }

    fn proof_for(
        challenge: &EcdsaClientMaterialPossessionChallengeV1,
        secret_byte: u8,
    ) -> EcdsaClientMaterialPossessionProofV1 {
        let signature = signing_key(secret_byte)
            .sign_prehash_with_aux_rand(&challenge.digest().expect("challenge digest"), &[0x55; 32])
            .expect("signature");
        EcdsaClientMaterialPossessionProofV1::new(signature.to_bytes()).expect("proof")
    }

    fn challenge_substitutions() -> Vec<EcdsaClientMaterialPossessionChallengeV1> {
        let original = challenge();
        let mut substitutions = Vec::new();

        let mut signer = original.clone();
        signer.registered_signer_digest32 = [0x0f; 32];
        substitutions.push(signer);

        let mut capability = original.clone();
        capability.public_capability_digest32 = [0x13; 32];
        substitutions.push(capability);

        let mut authority = original.clone();
        authority.authority_ref_digest32 = [0x14; 32];
        substitutions.push(authority);

        let mut material_owner = original.clone();
        material_owner.material_owner_ref = "material-owner-2".to_owned();
        substitutions.push(material_owner);

        let mut lane = original.clone();
        lane.lane_id = "owner-lane-2".to_owned();
        substitutions.push(lane);

        let mut lane_epoch = original.clone();
        lane_epoch.lane_epoch = "lane-epoch-2".to_owned();
        substitutions.push(lane_epoch);

        let mut client_key = original.clone();
        client_key.derivation_client_share_public_key33 = compressed_public_key33(8);
        substitutions.push(client_key);

        let mut material_session = original.clone();
        material_session.threshold_material_session_id = "threshold-material-session-2".to_owned();
        substitutions.push(material_session);

        let mut server_generation = original.clone();
        server_generation.expected_server_generation = "server-generation-2".to_owned();
        substitutions.push(server_generation);

        let mut lifecycle = original.clone();
        lifecycle.refresh_lifecycle_id = "refresh-lifecycle-2".to_owned();
        substitutions.push(lifecycle);

        let mut request = original.clone();
        request.refresh_request_id = "refresh-request-2".to_owned();
        substitutions.push(request);

        let mut transcript = original.clone();
        transcript.refresh_transcript_digest32 = [0x23; 32];
        substitutions.push(transcript);

        let mut previous_epoch = original.clone();
        previous_epoch.previous_activation_epoch = "activation-epoch-0".to_owned();
        substitutions.push(previous_epoch);

        let mut next_epoch = original.clone();
        next_epoch.next_activation_epoch = "activation-epoch-3".to_owned();
        substitutions.push(next_epoch);

        let mut policy = original.clone();
        policy.runtime_policy_scope_digest32 = [0x35; 32];
        substitutions.push(policy);

        let mut nonce = original.clone();
        nonce.server_nonce32 = [0x36; 32];
        substitutions.push(nonce);

        let mut expiry = original.clone();
        expiry.expires_at_ms += 1;
        substitutions.push(expiry);

        let mut correlation = original;
        correlation.idempotency_correlation_id = "activation-correlation-2".to_owned();
        substitutions.push(correlation);

        substitutions
    }

    #[test]
    fn challenge_digest_vector_is_frozen() {
        assert_eq!(
            challenge().digest().expect("challenge digest"),
            [
                0x37, 0xa3, 0x38, 0xb6, 0xd1, 0x13, 0xd0, 0xb8, 0x0c, 0x3d, 0x81, 0xed, 0x5e, 0x5c,
                0x67, 0xc8, 0x27, 0x02, 0xa0, 0x6f, 0x91, 0x3e, 0xc2, 0xac, 0xc9, 0xe2, 0xe7, 0x5a,
                0x86, 0x36, 0x24, 0x6c,
            ],
        );
    }

    #[test]
    fn proof_verifies_for_exact_active_material_and_challenge() {
        let challenge = challenge();
        let proof = proof_for(&challenge, 7);

        verify_ecdsa_client_material_possession_proof_v1(&challenge, &proof)
            .expect("proof verifies");
    }

    #[test]
    fn proof_verifies_for_both_compressed_public_key_parities() {
        let even_challenge = challenge();
        assert_eq!(even_challenge.derivation_client_share_public_key33[0], 0x02);
        verify_ecdsa_client_material_possession_proof_v1(
            &even_challenge,
            &proof_for(&even_challenge, 7),
        )
        .expect("even public key proof verifies");

        let mut odd_challenge = challenge();
        odd_challenge.derivation_client_share_public_key33 = compressed_public_key33(6);
        assert_eq!(odd_challenge.derivation_client_share_public_key33[0], 0x03);
        verify_ecdsa_client_material_possession_proof_v1(
            &odd_challenge,
            &proof_for(&odd_challenge, 6),
        )
        .expect("odd public key proof verifies");
    }

    #[test]
    fn proof_rejects_every_bound_field_substitution() {
        let challenge = challenge();
        let proof = proof_for(&challenge, 7);
        for substituted in challenge_substitutions() {
            assert_eq!(
                verify_ecdsa_client_material_possession_proof_v1(&substituted, &proof),
                Err(EcdsaClientMaterialPossessionError::InvalidProof),
            );
        }
    }

    #[test]
    fn challenge_rejects_invalid_public_key_and_lifecycle() {
        let mut invalid_key = challenge();
        invalid_key.derivation_client_share_public_key33 = [0u8; 33];
        assert_eq!(
            invalid_key.validate(),
            Err(EcdsaClientMaterialPossessionError::InvalidShape),
        );

        let mut same_epoch = challenge();
        same_epoch.next_activation_epoch = same_epoch.previous_activation_epoch.clone();
        assert_eq!(
            same_epoch.validate(),
            Err(EcdsaClientMaterialPossessionError::InvalidShape),
        );
    }

    #[test]
    fn proof_constructor_rejects_noncanonical_signature() {
        assert_eq!(
            EcdsaClientMaterialPossessionProofV1::new([0u8; 64]),
            Err(EcdsaClientMaterialPossessionError::InvalidProof),
        );
    }
}
