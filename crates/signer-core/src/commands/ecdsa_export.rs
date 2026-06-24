use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[cfg(feature = "threshold-ecdsa-hss")]
use crate::{
    codec::hex_to_bytes,
    error::{CoreResult, SignerCoreError},
    threshold_ecdsa_hss::{
        build_ecdsa_role_local_export_artifact,
        BuildEcdsaRoleLocalExportArtifactCommand as CoreBuildEcdsaRoleLocalExportArtifactCommand,
        EcdsaRoleLocalExportPublicFacts as CoreEcdsaRoleLocalExportPublicFacts,
        EcdsaRoleLocalReadyStateBlob as CoreEcdsaRoleLocalReadyStateBlob,
    },
};
#[cfg(feature = "threshold-ecdsa-hss")]
use base64ct::{Base64UrlUnpadded, Encoding};
#[cfg(feature = "threshold-ecdsa-hss")]
use ecdsa_hss::EcdsaHssStableKeyContext;
#[cfg(feature = "threshold-ecdsa-hss")]
use zeroize::Zeroize;

#[cfg(feature = "threshold-ecdsa-hss")]
use super::ecdsa_bootstrap::{
    Base64UrlEncodingV1, EcdsaClientBootstrapParticipantsV1, ReadyStateBlobKindV1,
    Secp256k1CurveNameV1, SignerCoreProducerV1,
};
use super::ecdsa_bootstrap::{EcdsaClientBootstrapAlgorithmV1, EcdsaRoleLocalReadyStateBlobV1};

#[cfg(feature = "threshold-ecdsa-hss")]
const ECDSA_HSS_CLIENT_PARTICIPANT_ID: u32 = 1;
#[cfg(feature = "threshold-ecdsa-hss")]
const ECDSA_HSS_RELAYER_PARTICIPANT_ID: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "BuildEcdsaRoleLocalExportArtifactCommandKind")]
pub enum BuildEcdsaRoleLocalExportArtifactCommandKindV1 {
    #[serde(rename = "build_ecdsa_role_local_export_artifact_v1")]
    #[ts(rename = "build_ecdsa_role_local_export_artifact_v1")]
    BuildEcdsaRoleLocalExportArtifactV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "EcdsaRoleLocalExportPublicFacts", rename_all = "camelCase")]
pub struct EcdsaRoleLocalExportPublicFactsV1 {
    pub application_binding_digest_b64u: String,
    pub client_participant_id: u32,
    pub relayer_participant_id: u32,
    pub participant_ids: Vec<u32>,
    pub context_binding32_b64u: String,
    pub hss_client_share_public_key33_b64u: String,
    pub relayer_public_key33_b64u: String,
    pub group_public_key33_b64u: String,
    pub ethereum_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "BuildEcdsaRoleLocalExportArtifactCommand",
    rename_all = "camelCase"
)]
pub struct BuildEcdsaRoleLocalExportArtifactCommandV1 {
    pub kind: BuildEcdsaRoleLocalExportArtifactCommandKindV1,
    pub algorithm: EcdsaClientBootstrapAlgorithmV1,
    pub state_blob: EcdsaRoleLocalReadyStateBlobV1,
    pub public_facts: EcdsaRoleLocalExportPublicFactsV1,
    pub server_export_share32_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "BuildEcdsaRoleLocalExportArtifactOutput",
    rename_all = "camelCase"
)]
pub struct BuildEcdsaRoleLocalExportArtifactOutputV1 {
    pub public_key_hex: String,
    pub private_key_hex: String,
    pub ethereum_address: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(
    rename = "BuildEcdsaRoleLocalExportArtifactErrorCode",
    rename_all = "snake_case"
)]
pub enum BuildEcdsaRoleLocalExportArtifactErrorCodeV1 {
    InvalidReadyState,
    InvalidPublicIdentity,
    CryptoFailure,
}

#[cfg(feature = "threshold-ecdsa-hss")]
pub fn build_ecdsa_role_local_export_artifact_command_v1(
    command: BuildEcdsaRoleLocalExportArtifactCommandV1,
) -> CoreResult<BuildEcdsaRoleLocalExportArtifactOutputV1> {
    validate_export_command_header(&command)?;
    validate_ready_state_blob_envelope(&command.state_blob)?;

    let public_facts = core_public_facts_from_command(&command.public_facts)?;
    let mut server_export_share32 = decode_base64_url_fixed::<32>(
        &command.server_export_share32_b64u,
        "serverExportShare32B64u",
    )?;
    let core_output =
        build_ecdsa_role_local_export_artifact(CoreBuildEcdsaRoleLocalExportArtifactCommand {
            ready_state_blob: CoreEcdsaRoleLocalReadyStateBlob {
                state_blob: decode_base64_url(
                    &command.state_blob.state_blob_b64u,
                    "stateBlob.stateBlobB64u",
                )?,
            },
            public_facts,
            server_export_share32,
        });
    server_export_share32.zeroize();
    let output = core_output?;

    Ok(BuildEcdsaRoleLocalExportArtifactOutputV1 {
        public_key_hex: hex_prefixed(&output.public_key33),
        private_key_hex: hex_prefixed(&output.private_key32),
        ethereum_address: hex_prefixed(&output.ethereum_address20),
    })
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn validate_export_command_header(
    command: &BuildEcdsaRoleLocalExportArtifactCommandV1,
) -> CoreResult<()> {
    match command.kind {
        BuildEcdsaRoleLocalExportArtifactCommandKindV1::BuildEcdsaRoleLocalExportArtifactV1 => {}
    }
    match command.algorithm {
        EcdsaClientBootstrapAlgorithmV1::EcdsaHssSecp256k1RoleLocalV1 => {}
    }
    validate_participants(EcdsaClientBootstrapParticipantsV1 {
        client_participant_id: command.public_facts.client_participant_id,
        relayer_participant_id: command.public_facts.relayer_participant_id,
        participant_ids: command.public_facts.participant_ids.clone(),
    })
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn validate_participants(participants: EcdsaClientBootstrapParticipantsV1) -> CoreResult<()> {
    if participants.client_participant_id != ECDSA_HSS_CLIENT_PARTICIPANT_ID {
        return Err(SignerCoreError::invalid_input(
            "publicFacts.clientParticipantId must be 1",
        ));
    }
    if participants.relayer_participant_id != ECDSA_HSS_RELAYER_PARTICIPANT_ID {
        return Err(SignerCoreError::invalid_input(
            "publicFacts.relayerParticipantId must be 2",
        ));
    }
    if participants.participant_ids
        != [
            ECDSA_HSS_CLIENT_PARTICIPANT_ID,
            ECDSA_HSS_RELAYER_PARTICIPANT_ID,
        ]
    {
        return Err(SignerCoreError::invalid_input(
            "publicFacts.participantIds must be [1, 2]",
        ));
    }
    Ok(())
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn validate_ready_state_blob_envelope(blob: &EcdsaRoleLocalReadyStateBlobV1) -> CoreResult<()> {
    match blob.kind {
        ReadyStateBlobKindV1::EcdsaRoleLocalReadyStateBlobV1 => {}
    }
    match blob.curve {
        Secp256k1CurveNameV1::Secp256k1 => {}
    }
    match blob.encoding {
        Base64UrlEncodingV1::Base64url => {}
    }
    match blob.producer {
        SignerCoreProducerV1::SignerCore => {}
    }
    Ok(())
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn core_public_facts_from_command(
    facts: &EcdsaRoleLocalExportPublicFactsV1,
) -> CoreResult<CoreEcdsaRoleLocalExportPublicFacts> {
    let context = EcdsaHssStableKeyContext::new(decode_base64_url_fixed::<32>(
        &facts.application_binding_digest_b64u,
        "publicFacts.applicationBindingDigestB64u",
    )?);
    context
        .validate()
        .map_err(|error| SignerCoreError::invalid_input(error.message))?;

    Ok(CoreEcdsaRoleLocalExportPublicFacts {
        context,
        context_binding32: decode_base64_url_fixed(
            &facts.context_binding32_b64u,
            "publicFacts.contextBinding32B64u",
        )?,
        hss_client_share_public_key33: decode_base64_url_fixed(
            &facts.hss_client_share_public_key33_b64u,
            "publicFacts.hssClientSharePublicKey33B64u",
        )?,
        relayer_public_key33: decode_base64_url_fixed(
            &facts.relayer_public_key33_b64u,
            "publicFacts.relayerPublicKey33B64u",
        )?,
        group_public_key33: decode_base64_url_fixed(
            &facts.group_public_key33_b64u,
            "publicFacts.groupPublicKey33B64u",
        )?,
        ethereum_address20: decode_ethereum_address20(
            &facts.ethereum_address,
            "publicFacts.ethereumAddress",
        )?,
    })
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn decode_base64_url(input: &str, field_name: &str) -> CoreResult<Vec<u8>> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    Base64UrlUnpadded::decode_vec(trimmed)
        .map_err(|error| SignerCoreError::decode_error(format!("{field_name}: {error}")))
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn decode_base64_url_fixed<const N: usize>(input: &str, field_name: &str) -> CoreResult<[u8; N]> {
    let mut bytes = decode_base64_url(input, field_name)?;
    if bytes.len() != N {
        let len = bytes.len();
        bytes.zeroize();
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must decode to {N} bytes (got {len})"
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(out)
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn decode_ethereum_address20(input: &str, field_name: &str) -> CoreResult<[u8; 20]> {
    let trimmed = input.trim();
    if !trimmed.starts_with("0x") {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be 0x-prefixed"
        )));
    }
    let bytes = hex_to_bytes(trimmed)?;
    if bytes.len() != 20 {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must be 20 bytes"
        )));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn hex_prefixed(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
