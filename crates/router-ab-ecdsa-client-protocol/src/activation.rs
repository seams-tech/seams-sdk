use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{Deserialize, Serialize};

use crate::EcdsaClientProtocolError;

/// Client-share activation facts produced only after verifying both Deriver proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EcdsaVerifiedClientActivationFactsV1 {
    /// Canonical registration request digest.
    pub registration_request_digest_b64u: String,
    /// Threshold-PRF transcript digest shared by both verified proof bundles.
    pub proof_transcript_digest_b64u: String,
    /// Stable ECDSA derivation context binding.
    pub context_binding32_b64u: String,
    /// Derived client compressed secp256k1 public key.
    pub derivation_client_share_public_key33_b64u: String,
    /// Retry counter used to derive the client share.
    pub client_share_retry_counter: u32,
    /// Fixed client participant identifier.
    pub participant_id: u32,
}

impl EcdsaVerifiedClientActivationFactsV1 {
    /// Validates the exact fixed-circuit client activation shape.
    pub fn validate(&self) -> Result<(), EcdsaClientProtocolError> {
        decode_fixed::<32>(&self.registration_request_digest_b64u)?;
        decode_fixed::<32>(&self.proof_transcript_digest_b64u)?;
        decode_fixed::<32>(&self.context_binding32_b64u)?;
        let public_key = decode_fixed::<33>(&self.derivation_client_share_public_key33_b64u)?;
        if !matches!(public_key[0], 0x02 | 0x03) || self.participant_id != 1 {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        Ok(())
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], EcdsaClientProtocolError> {
    let decoded =
        Base64UrlUnpadded::decode_vec(value).map_err(|_| EcdsaClientProtocolError::InvalidShape)?;
    decoded
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}
