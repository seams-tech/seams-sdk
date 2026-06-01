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
    Base64UrlEncodingV1, EcdsaClientBootstrapKeyPurposeV1, EcdsaClientBootstrapKeyVersionV1,
    EcdsaClientBootstrapParticipantsV1, EvmNamespaceV1, ReadyStateBlobKindV1, Secp256k1CurveNameV1,
    SignerCoreProducerV1,
};
use super::ecdsa_bootstrap::{
    EcdsaClientBootstrapAlgorithmV1, EcdsaRoleLocalReadyStateBlobV1, ThresholdEcdsaChainTargetV1,
};

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
    pub wallet_id: String,
    pub rp_id: String,
    pub chain_target: ThresholdEcdsaChainTargetV1,
    pub key_handle: String,
    pub ecdsa_threshold_key_id: String,
    pub signing_root_id: String,
    pub signing_root_version: String,
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
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[ts(
    rename = "EcdsaRoleLocalExportAuthorization",
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum EcdsaRoleLocalExportAuthorizationV1 {
    PasskeyExportAuthorized {
        wallet_id: String,
        rp_id: String,
        credential_id_b64u: String,
    },
    EmailOtpExportAuthorized {
        wallet_id: String,
        rp_id: String,
        auth_subject_id: String,
    },
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
    pub authorization: EcdsaRoleLocalExportAuthorizationV1,
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
    ExportNotAuthorized,
    CryptoFailure,
}

#[cfg(feature = "threshold-ecdsa-hss")]
pub fn build_ecdsa_role_local_export_artifact_command_v1(
    command: BuildEcdsaRoleLocalExportArtifactCommandV1,
) -> CoreResult<BuildEcdsaRoleLocalExportArtifactOutputV1> {
    validate_export_command_header(&command)?;
    validate_ready_state_blob_envelope(&command.state_blob)?;
    validate_export_authorization(&command.public_facts, &command.authorization)?;

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
    validate_chain_target(&facts.chain_target)?;
    require_ascii_nonempty_ref(&facts.key_handle, "publicFacts.keyHandle")?;
    let context = EcdsaHssStableKeyContext::new(
        require_ascii_nonempty_ref(&facts.wallet_id, "publicFacts.walletId")?.to_owned(),
        require_ascii_nonempty_ref(&facts.rp_id, "publicFacts.rpId")?.to_owned(),
        require_ascii_nonempty_ref(
            &facts.ecdsa_threshold_key_id,
            "publicFacts.ecdsaThresholdKeyId",
        )?
        .to_owned(),
        require_ascii_nonempty_ref(&facts.signing_root_id, "publicFacts.signingRootId")?.to_owned(),
        require_ascii_nonempty_ref(
            &facts.signing_root_version,
            "publicFacts.signingRootVersion",
        )?
        .to_owned(),
        key_purpose_string(EcdsaClientBootstrapKeyPurposeV1::EvmSigning).to_owned(),
        key_version_string(EcdsaClientBootstrapKeyVersionV1::V1).to_owned(),
    );
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
fn validate_export_authorization(
    facts: &EcdsaRoleLocalExportPublicFactsV1,
    authorization: &EcdsaRoleLocalExportAuthorizationV1,
) -> CoreResult<()> {
    match authorization {
        EcdsaRoleLocalExportAuthorizationV1::PasskeyExportAuthorized {
            wallet_id,
            rp_id,
            credential_id_b64u,
        } => {
            require_authorization_identity_match(facts, wallet_id, rp_id)?;
            let mut credential_id =
                decode_base64_url(credential_id_b64u, "authorization.credentialIdB64u")?;
            if credential_id.is_empty() {
                return Err(SignerCoreError::invalid_input(
                    "authorization.credentialIdB64u must decode to at least one byte",
                ));
            }
            credential_id.zeroize();
        }
        EcdsaRoleLocalExportAuthorizationV1::EmailOtpExportAuthorized {
            wallet_id,
            rp_id,
            auth_subject_id,
        } => {
            require_authorization_identity_match(facts, wallet_id, rp_id)?;
            require_ascii_nonempty_ref(auth_subject_id, "authorization.authSubjectId")?;
        }
    }
    Ok(())
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn require_authorization_identity_match(
    facts: &EcdsaRoleLocalExportPublicFactsV1,
    wallet_id: &str,
    rp_id: &str,
) -> CoreResult<()> {
    let wallet_id = require_ascii_nonempty_ref(wallet_id, "authorization.walletId")?;
    let rp_id = require_ascii_nonempty_ref(rp_id, "authorization.rpId")?;
    if wallet_id != facts.wallet_id {
        return Err(SignerCoreError::invalid_input(
            "authorization.walletId does not match publicFacts.walletId",
        ));
    }
    if rp_id != facts.rp_id {
        return Err(SignerCoreError::invalid_input(
            "authorization.rpId does not match publicFacts.rpId",
        ));
    }
    Ok(())
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn validate_chain_target(target: &ThresholdEcdsaChainTargetV1) -> CoreResult<()> {
    match target {
        ThresholdEcdsaChainTargetV1::Evm {
            namespace,
            chain_id,
            network_slug,
        } => {
            match namespace {
                EvmNamespaceV1::Eip155 => {}
            }
            validate_chain_id(*chain_id)?;
            require_ascii_nonempty_ref(network_slug, "publicFacts.chainTarget.networkSlug")?;
        }
        ThresholdEcdsaChainTargetV1::Tempo {
            chain_id,
            network_slug,
        } => {
            validate_chain_id(*chain_id)?;
            require_ascii_nonempty_ref(network_slug, "publicFacts.chainTarget.networkSlug")?;
        }
    }
    Ok(())
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn validate_chain_id(chain_id: u32) -> CoreResult<()> {
    if chain_id == 0 {
        return Err(SignerCoreError::invalid_input(
            "publicFacts.chainTarget.chainId must be positive",
        ));
    }
    Ok(())
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn key_purpose_string(value: EcdsaClientBootstrapKeyPurposeV1) -> &'static str {
    match value {
        EcdsaClientBootstrapKeyPurposeV1::EvmSigning => "evm-signing",
    }
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn key_version_string(value: EcdsaClientBootstrapKeyVersionV1) -> &'static str {
    match value {
        EcdsaClientBootstrapKeyVersionV1::V1 => "v1",
    }
}

#[cfg(feature = "threshold-ecdsa-hss")]
fn require_ascii_nonempty_ref<'a>(value: &'a str, field_name: &str) -> CoreResult<&'a str> {
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    if !value.is_ascii() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be ASCII-only"
        )));
    }
    Ok(value)
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
