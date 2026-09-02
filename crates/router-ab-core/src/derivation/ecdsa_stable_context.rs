use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::Error as DeError;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
    TenantRootProtocolDigestV1,
};

const ECDSA_STABLE_CONTEXT_DOMAIN_V1: &[u8] = b"router-ab-ecdsa-derivation/context/v1";
const ECDSA_STABLE_CONTEXT_SCHEME_ID_V1: &str = "router-ab-ecdsa-derivation-v1";
const ECDSA_STABLE_CONTEXT_CURVE_V1: &str = "secp256k1";
const ECDSA_STABLE_CONTEXT_PARTICIPANT_IDS_V1: [u16; 2] = [1, 2];

/// Refresh-invariant ECDSA threshold-PRF input for one application binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StableTenantDerivationContextV2 {
    application_binding_digest: [u8; 32],
}

impl StableTenantDerivationContextV2 {
    /// Creates the stable context from the exact SDK application-binding digest.
    pub const fn new(application_binding_digest: [u8; 32]) -> Self {
        Self {
            application_binding_digest,
        }
    }

    /// Parses the canonical unpadded base64url application-binding digest.
    pub fn from_application_binding_digest_b64u(value: &str) -> RouterAbDerivationResult<Self> {
        let mut bytes = [0_u8; 32];
        let decoded = Base64UrlUnpadded::decode(value, &mut bytes).map_err(|_| {
            malformed("stable tenant derivation context digest is invalid base64url")
        })?;
        if decoded.len() != 32 || Base64UrlUnpadded::encode_string(decoded) != value {
            return Err(malformed(
                "stable tenant derivation context digest is not canonical base64url",
            ));
        }
        Ok(Self::new(bytes))
    }

    /// Returns the canonical unpadded base64url digest boundary value.
    pub fn application_binding_digest_b64u(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.application_binding_digest)
    }

    /// Returns the exact stable bytes consumed by threshold-PRF evaluation.
    pub fn canonical_context_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(ECDSA_STABLE_CONTEXT_DOMAIN_V1);
        push_ascii_u16(&mut bytes, ECDSA_STABLE_CONTEXT_SCHEME_ID_V1);
        push_ascii_u16(&mut bytes, ECDSA_STABLE_CONTEXT_CURVE_V1);
        bytes.extend_from_slice(&self.application_binding_digest);
        bytes.push(ECDSA_STABLE_CONTEXT_PARTICIPANT_IDS_V1.len() as u8);
        for participant_id in ECDSA_STABLE_CONTEXT_PARTICIPANT_IDS_V1 {
            bytes.extend_from_slice(&participant_id.to_be_bytes());
        }
        bytes
    }

    /// Returns the digest of the exact bytes supplied to threshold-PRF.
    pub fn digest(&self) -> RouterAbDerivationResult<TenantRootProtocolDigestV1> {
        TenantRootProtocolDigestV1::from_bytes(
            Sha256::digest(self.canonical_context_bytes()).into(),
        )
    }
}

impl Serialize for StableTenantDerivationContextV2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("StableTenantDerivationContextV2", 1)?;
        state.serialize_field(
            "applicationBindingDigestB64u",
            &self.application_binding_digest_b64u(),
        )?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for StableTenantDerivationContextV2 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            application_binding_digest_b64u: String,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::from_application_binding_digest_b64u(&wire.application_binding_digest_b64u)
            .map_err(D::Error::custom)
    }
}

fn push_ascii_u16(bytes: &mut Vec<u8>, value: &'static str) {
    let length = u16::try_from(value.len()).expect("fixed stable-context labels fit u16");
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

fn malformed(message: &'static str) -> RouterAbDerivationError {
    RouterAbDerivationError::new(RouterAbDerivationErrorCode::MalformedInput, message)
}
