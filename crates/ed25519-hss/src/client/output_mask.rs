use std::str::FromStr;

use base64::Engine;
use hkdf::Hkdf;
use serde::Serialize;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::shared::{CanonicalContext, ProtoError, ProtoResult};

pub const CLIENT_OUTPUT_MASK_HKDF_SALT: &str = "ed25519-hss/client-output-mask/v1";
pub const CLIENT_OUTPUT_MASK_INFO_LABEL: &str = "ed25519-hss/client-output-mask/context/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientOutputMaskOperation {
    Registration,
    TxSigning,
    LinkDevice,
    EmailRecovery,
    WarmSessionReconstruction,
    ExplicitKeyExport,
}

impl ClientOutputMaskOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Registration => "registration",
            Self::TxSigning => "tx_signing",
            Self::LinkDevice => "link_device",
            Self::EmailRecovery => "email_recovery",
            Self::WarmSessionReconstruction => "warm_session_reconstruction",
            Self::ExplicitKeyExport => "explicit_key_export",
        }
    }
}

impl FromStr for ClientOutputMaskOperation {
    type Err = ProtoError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim() {
            "registration" => Ok(Self::Registration),
            "tx_signing" => Ok(Self::TxSigning),
            "link_device" => Ok(Self::LinkDevice),
            "email_recovery" => Ok(Self::EmailRecovery),
            "warm_session_reconstruction" => Ok(Self::WarmSessionReconstruction),
            "explicit_key_export" => Ok(Self::ExplicitKeyExport),
            other => Err(ProtoError::InvalidInput(format!(
                "unsupported client output mask operation: {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientOutputMaskContext {
    pub canonical_context: CanonicalContext,
    pub context_binding: [u8; 32],
    pub operation: ClientOutputMaskOperation,
    pub server_key_id: String,
}

#[derive(Serialize)]
struct ClientOutputMaskInfo<'a> {
    label: &'static str,
    #[serde(rename = "projectionMode")]
    projection_mode: &'static str,
    #[serde(rename = "applicationBindingDigestB64u")]
    application_binding_digest_b64u: String,
    #[serde(rename = "participantIds")]
    participant_ids: &'a [u16],
    #[serde(rename = "contextBindingB64u")]
    context_binding_b64u: String,
    operation: &'static str,
    #[serde(rename = "serverKeyId")]
    server_key_id: &'a str,
}

pub fn encode_client_output_mask_info(context: &ClientOutputMaskContext) -> ProtoResult<Vec<u8>> {
    validate_context(context)?;
    let canonical_context = context.canonical_context.normalized()?;
    let application_binding_digest_b64u = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(canonical_context.application_binding_digest);
    let context_binding_b64u =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(context.context_binding);
    let info = ClientOutputMaskInfo {
        label: CLIENT_OUTPUT_MASK_INFO_LABEL,
        projection_mode: "ClientMaskedProjection",
        application_binding_digest_b64u,
        participant_ids: &canonical_context.participant_ids,
        context_binding_b64u,
        operation: context.operation.as_str(),
        server_key_id: &context.server_key_id,
    };
    serde_json::to_vec(&info).map_err(|err| {
        ProtoError::InvalidInput(format!(
            "failed to encode client output mask context: {err}"
        ))
    })
}

pub fn derive_client_output_mask(
    mut ikm: [u8; 32],
    context: &ClientOutputMaskContext,
) -> ProtoResult<[u8; 32]> {
    let info = encode_client_output_mask_info(context)?;
    let mut out = [0u8; 32];
    let result = Hkdf::<Sha256>::new(Some(CLIENT_OUTPUT_MASK_HKDF_SALT.as_bytes()), &ikm)
        .expand(&info, &mut out)
        .map_err(|_| ProtoError::InvalidInput("client output mask HKDF expand failed".into()));
    ikm.zeroize();
    result.map(|()| out)
}

fn validate_context(context: &ClientOutputMaskContext) -> ProtoResult<()> {
    validate_non_empty("serverKeyId", &context.server_key_id)?;
    let _ = context.canonical_context.normalized()?;
    Ok(())
}

fn validate_non_empty(field_name: &str, value: &str) -> ProtoResult<()> {
    if value.trim().is_empty() {
        return Err(ProtoError::InvalidInput(format!(
            "{field_name} must be non-empty"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_context() -> ClientOutputMaskContext {
        ClientOutputMaskContext {
            canonical_context: CanonicalContext {
                application_binding_digest: [9u8; 32],
                participant_ids: vec![1, 2],
            },
            context_binding: [7u8; 32],
            operation: ClientOutputMaskOperation::WarmSessionReconstruction,
            server_key_id: "ed25519:server-key".to_string(),
        }
    }

    #[test]
    fn client_output_mask_info_matches_typescript_canonical_json() {
        let info = encode_client_output_mask_info(&test_context()).expect("encode info");
        assert_eq!(
            std::str::from_utf8(&info).expect("utf8"),
            "{\"label\":\"ed25519-hss/client-output-mask/context/v1\",\"projectionMode\":\"ClientMaskedProjection\",\"applicationBindingDigestB64u\":\"CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk\",\"participantIds\":[1,2],\"contextBindingB64u\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\",\"operation\":\"warm_session_reconstruction\",\"serverKeyId\":\"ed25519:server-key\"}"
        );
    }

    #[test]
    fn client_output_mask_derivation_is_context_bound() {
        let ikm = [13u8; 32];
        let context = test_context();
        let derived = derive_client_output_mask(ikm, &context).expect("derive mask");
        let again = derive_client_output_mask(ikm, &context).expect("derive mask again");
        assert_eq!(derived, again);

        let mut other_context = context;
        other_context.operation = ClientOutputMaskOperation::ExplicitKeyExport;
        let other = derive_client_output_mask(ikm, &other_context).expect("derive other mask");
        assert_ne!(derived, other);
    }
}
