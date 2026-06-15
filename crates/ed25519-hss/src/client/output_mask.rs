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
    #[serde(rename = "signingRootId")]
    signing_root_id: &'a str,
    #[serde(rename = "nearAccountId")]
    near_account_id: &'a str,
    #[serde(rename = "keyPurpose")]
    key_purpose: &'a str,
    #[serde(rename = "keyVersion")]
    key_version: &'a str,
    #[serde(rename = "participantIds")]
    participant_ids: &'a [u16],
    #[serde(rename = "derivationVersion")]
    derivation_version: u32,
    #[serde(rename = "contextBindingB64u")]
    context_binding_b64u: String,
    operation: &'static str,
    #[serde(rename = "serverKeyId")]
    server_key_id: &'a str,
}

pub fn encode_client_output_mask_info(context: &ClientOutputMaskContext) -> ProtoResult<Vec<u8>> {
    validate_context(context)?;
    let context_binding_b64u =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(context.context_binding);
    let info = ClientOutputMaskInfo {
        label: CLIENT_OUTPUT_MASK_INFO_LABEL,
        projection_mode: "ClientMaskedProjection",
        signing_root_id: &context.canonical_context.org_id,
        near_account_id: &context.canonical_context.account_id,
        key_purpose: &context.canonical_context.key_purpose,
        key_version: &context.canonical_context.key_version,
        participant_ids: &context.canonical_context.participant_ids,
        derivation_version: context.canonical_context.derivation_version,
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
    validate_non_empty("signingRootId", &context.canonical_context.org_id)?;
    validate_non_empty("nearAccountId", &context.canonical_context.account_id)?;
    validate_non_empty("keyPurpose", &context.canonical_context.key_purpose)?;
    validate_non_empty("keyVersion", &context.canonical_context.key_version)?;
    validate_non_empty("serverKeyId", &context.server_key_id)?;
    if context.canonical_context.participant_ids.is_empty() {
        return Err(ProtoError::InvalidInput(
            "participantIds must contain at least one identifier".to_string(),
        ));
    }
    if context.canonical_context.derivation_version == 0 {
        return Err(ProtoError::InvalidInput(
            "derivationVersion must be positive".to_string(),
        ));
    }
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
                org_id: "org_threshold_scope_test".to_string(),
                account_id: "alice.testnet".to_string(),
                key_purpose: "near-ed25519-signing".to_string(),
                key_version: "threshold-ed25519-hss-v1".to_string(),
                participant_ids: vec![1, 2],
                derivation_version: 1,
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
            "{\"label\":\"ed25519-hss/client-output-mask/context/v1\",\"projectionMode\":\"ClientMaskedProjection\",\"signingRootId\":\"org_threshold_scope_test\",\"nearAccountId\":\"alice.testnet\",\"keyPurpose\":\"near-ed25519-signing\",\"keyVersion\":\"threshold-ed25519-hss-v1\",\"participantIds\":[1,2],\"derivationVersion\":1,\"contextBindingB64u\":\"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc\",\"operation\":\"warm_session_reconstruction\",\"serverKeyId\":\"ed25519:server-key\"}"
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
