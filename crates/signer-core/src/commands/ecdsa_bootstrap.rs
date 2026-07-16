use serde::{Deserialize, Serialize};
use ts_rs::TS;

#[cfg(feature = "ecdsa-role-local-client")]
use crate::{
    codec::hex_to_bytes,
    ecdsa_role_local_client::{
        derive_passkey_threshold_ecdsa_client_root_share32_from_prf_first,
        finalize_ecdsa_client_bootstrap, prepare_ecdsa_client_bootstrap,
        EcdsaRoleLocalPendingStateBlob as CoreEcdsaRoleLocalPendingStateBlob,
        FinalizeEcdsaClientBootstrapCommand as CoreFinalizeEcdsaClientBootstrapCommand,
        PrepareEcdsaClientBootstrapCommand as CorePrepareEcdsaClientBootstrapCommand,
        RelayerPublicIdentityInput,
    },
    error::{CoreResult, SignerCoreError},
};
#[cfg(feature = "ecdsa-role-local-client")]
use base64ct::{Base64UrlUnpadded, Encoding};
#[cfg(feature = "ecdsa-role-local-client")]
use router_ab_ecdsa_derivation::RouterAbEcdsaDerivationStableKeyContext;
#[cfg(feature = "ecdsa-role-local-client")]
use zeroize::Zeroize;

#[cfg(feature = "ecdsa-role-local-client")]
const ROUTER_AB_ECDSA_DERIVATION_CLIENT_PARTICIPANT_ID: u32 = 1;
#[cfg(feature = "ecdsa-role-local-client")]
const ROUTER_AB_ECDSA_DERIVATION_RELAYER_PARTICIPANT_ID: u32 = 2;
#[cfg(feature = "ecdsa-role-local-client")]
const ROUTER_AB_ECDSA_DERIVATION_RELAYER_SHARE_RETRY_COUNTER_V1: u32 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename_all = "snake_case")]
pub enum SignerCommandVersion {
    V1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "EcdsaClientBootstrapAlgorithm")]
pub enum EcdsaClientBootstrapAlgorithmV1 {
    #[serde(rename = "router_ab_ecdsa_derivation_secp256k1_role_local_v1")]
    #[ts(rename = "router_ab_ecdsa_derivation_secp256k1_role_local_v1")]
    RouterAbEcdsaDerivationSecp256k1RoleLocalV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "EcdsaClientBootstrapContext", rename_all = "camelCase")]
pub struct EcdsaClientBootstrapContextV1 {
    pub application_binding_digest_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "EcdsaClientBootstrapParticipants", rename_all = "camelCase")]
pub struct EcdsaClientBootstrapParticipantsV1 {
    pub client_participant_id: u32,
    pub relayer_participant_id: u32,
    pub participant_ids: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
#[ts(
    rename = "EcdsaBootstrapSecretSource",
    tag = "kind",
    rename_all = "snake_case",
    rename_all_fields = "camelCase"
)]
pub enum EcdsaBootstrapSecretSourceV1 {
    WebauthnPrfFirst {
        prf_first_b64u: String,
        rp_id: String,
        credential_id_b64u: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "PrepareEcdsaClientBootstrapCommandKind")]
pub enum PrepareEcdsaClientBootstrapCommandKindV1 {
    #[serde(rename = "prepare_ecdsa_client_bootstrap_v1")]
    #[ts(rename = "prepare_ecdsa_client_bootstrap_v1")]
    PrepareEcdsaClientBootstrapV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "PrepareEcdsaClientBootstrapCommand",
    rename_all = "camelCase"
)]
pub struct PrepareEcdsaClientBootstrapCommandV1 {
    pub kind: PrepareEcdsaClientBootstrapCommandKindV1,
    pub algorithm: EcdsaClientBootstrapAlgorithmV1,
    pub context: EcdsaClientBootstrapContextV1,
    pub participants: EcdsaClientBootstrapParticipantsV1,
    pub secret_source: EcdsaBootstrapSecretSourceV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "EcdsaRoleLocalPendingStateBlob", rename_all = "camelCase")]
pub struct EcdsaRoleLocalPendingStateBlobV1 {
    pub kind: PendingStateBlobKindV1,
    pub curve: Secp256k1CurveNameV1,
    pub encoding: Base64UrlEncodingV1,
    pub producer: SignerCoreProducerV1,
    pub state_blob_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "EcdsaRoleLocalReadyStateBlob", rename_all = "camelCase")]
pub struct EcdsaRoleLocalReadyStateBlobV1 {
    pub kind: ReadyStateBlobKindV1,
    pub curve: Secp256k1CurveNameV1,
    pub encoding: Base64UrlEncodingV1,
    pub producer: SignerCoreProducerV1,
    pub state_blob_b64u: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "PendingStateBlobKind")]
pub enum PendingStateBlobKindV1 {
    #[serde(rename = "ecdsa_role_local_pending_state_blob_v1")]
    #[ts(rename = "ecdsa_role_local_pending_state_blob_v1")]
    EcdsaRoleLocalPendingStateBlobV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "ReadyStateBlobKind")]
pub enum ReadyStateBlobKindV1 {
    #[serde(rename = "ecdsa_role_local_state_blob_v1")]
    #[ts(rename = "ecdsa_role_local_state_blob_v1")]
    EcdsaRoleLocalReadyStateBlobV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(rename = "Secp256k1CurveName", rename_all = "lowercase")]
pub enum Secp256k1CurveNameV1 {
    Secp256k1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "lowercase")]
#[ts(rename = "Base64UrlEncoding", rename_all = "lowercase")]
pub enum Base64UrlEncodingV1 {
    Base64url,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(rename = "SignerCoreProducer", rename_all = "snake_case")]
pub enum SignerCoreProducerV1 {
    SignerCore,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "EcdsaClientBootstrapFacts", rename_all = "camelCase")]
pub struct EcdsaClientBootstrapFactsV1 {
    pub context_binding32_b64u: String,
    pub derivation_client_share_public_key33_b64u: String,
    pub client_share_retry_counter: u32,
    pub participant_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "EcdsaPreparePublicFacts", rename_all = "camelCase")]
pub struct EcdsaPreparePublicFactsV1 {
    pub derivation_client_share_public_key33_b64u: String,
    pub client_verifying_share_b64u: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "PrepareEcdsaClientBootstrapOutput", rename_all = "camelCase")]
pub struct PrepareEcdsaClientBootstrapOutputV1 {
    pub pending_state_blob: EcdsaRoleLocalPendingStateBlobV1,
    pub client_bootstrap: EcdsaClientBootstrapFactsV1,
    pub public_facts: EcdsaPreparePublicFactsV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(
    rename = "PrepareEcdsaClientBootstrapErrorCode",
    rename_all = "snake_case"
)]
pub enum PrepareEcdsaClientBootstrapErrorCodeV1 {
    UnsupportedSecretSource,
    InvalidSecretSource,
    InvalidContext,
    InvalidThresholdParameters,
    InvalidPublicMaterial,
    CryptoFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(rename = "FinalizeEcdsaClientBootstrapCommandKind")]
pub enum FinalizeEcdsaClientBootstrapCommandKindV1 {
    #[serde(rename = "finalize_ecdsa_client_bootstrap_v1")]
    #[ts(rename = "finalize_ecdsa_client_bootstrap_v1")]
    FinalizeEcdsaClientBootstrapV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "RelayerPublicIdentity", rename_all = "camelCase")]
pub struct RelayerPublicIdentityV1 {
    pub relayer_key_id: String,
    pub relayer_public_key33_b64u: String,
    pub group_public_key33_b64u: String,
    pub ethereum_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "FinalizeEcdsaClientBootstrapCommand",
    rename_all = "camelCase"
)]
pub struct FinalizeEcdsaClientBootstrapCommandV1 {
    pub kind: FinalizeEcdsaClientBootstrapCommandKindV1,
    pub pending_state_blob: EcdsaRoleLocalPendingStateBlobV1,
    pub relayer_public_identity: RelayerPublicIdentityV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(rename = "EcdsaReadyPublicFacts", rename_all = "camelCase")]
pub struct EcdsaReadyPublicFactsV1 {
    pub context_binding32_b64u: String,
    pub derivation_client_share_public_key33_b64u: String,
    pub client_verifying_share_b64u: String,
    pub relayer_public_key33_b64u: String,
    pub group_public_key33_b64u: String,
    pub ethereum_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "camelCase")]
#[ts(
    rename = "FinalizeEcdsaClientBootstrapOutput",
    rename_all = "camelCase"
)]
pub struct FinalizeEcdsaClientBootstrapOutputV1 {
    pub state_blob: EcdsaRoleLocalReadyStateBlobV1,
    pub public_facts: EcdsaReadyPublicFactsV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, TS)]
#[serde(rename_all = "snake_case")]
#[ts(
    rename = "FinalizeEcdsaClientBootstrapErrorCode",
    rename_all = "snake_case"
)]
pub enum FinalizeEcdsaClientBootstrapErrorCodeV1 {
    InvalidPendingState,
    InvalidRelayerPublicIdentity,
    PublicIdentityMismatch,
    CryptoFailure,
}

#[cfg(feature = "ecdsa-role-local-client")]
pub fn prepare_ecdsa_client_bootstrap_command_v1(
    command: PrepareEcdsaClientBootstrapCommandV1,
) -> CoreResult<PrepareEcdsaClientBootstrapOutputV1> {
    validate_prepare_command_header(&command)?;
    let context = stable_key_context_from_prepare_context(command.context)?;
    let mut client_root_share32 = client_root_share_from_secret_source(command.secret_source)?;
    let prepared_result = prepare_ecdsa_client_bootstrap(CorePrepareEcdsaClientBootstrapCommand {
        context,
        client_root_share32,
    });
    client_root_share32.zeroize();
    let prepared = prepared_result?;

    Ok(PrepareEcdsaClientBootstrapOutputV1 {
        pending_state_blob: pending_state_blob_envelope(&prepared.pending_state_blob.state_blob),
        client_bootstrap: EcdsaClientBootstrapFactsV1 {
            context_binding32_b64u: encode_base64_url(&prepared.client_bootstrap.context_binding32),
            derivation_client_share_public_key33_b64u: encode_base64_url(
                &prepared
                    .client_bootstrap
                    .derivation_client_share_public_key33,
            ),
            client_share_retry_counter: prepared.client_bootstrap.client_share_retry_counter,
            participant_id: prepared.client_bootstrap.participant_id,
        },
        public_facts: EcdsaPreparePublicFactsV1 {
            derivation_client_share_public_key33_b64u: encode_base64_url(
                &prepared.public_facts.derivation_client_share_public_key33,
            ),
            client_verifying_share_b64u: encode_base64_url(
                &prepared.public_facts.client_verifying_share33,
            ),
        },
    })
}

#[cfg(feature = "ecdsa-role-local-client")]
pub fn finalize_ecdsa_client_bootstrap_command_v1(
    command: FinalizeEcdsaClientBootstrapCommandV1,
) -> CoreResult<FinalizeEcdsaClientBootstrapOutputV1> {
    validate_pending_state_blob_envelope(&command.pending_state_blob)?;
    let pending_state_blob = CoreEcdsaRoleLocalPendingStateBlob {
        state_blob: decode_base64_url(
            &command.pending_state_blob.state_blob_b64u,
            "pendingStateBlob.stateBlobB64u",
        )?,
    };
    let relayer_key_id = require_ascii_nonempty(
        command.relayer_public_identity.relayer_key_id,
        "relayerPublicIdentity.relayerKeyId",
    )?;
    let finalized = finalize_ecdsa_client_bootstrap(CoreFinalizeEcdsaClientBootstrapCommand {
        pending_state_blob,
        relayer_public_identity: RelayerPublicIdentityInput {
            relayer_key_id,
            relayer_public_key33: decode_base64_url_fixed(
                &command.relayer_public_identity.relayer_public_key33_b64u,
                "relayerPublicIdentity.relayerPublicKey33B64u",
            )?,
            group_public_key33: decode_base64_url_fixed(
                &command.relayer_public_identity.group_public_key33_b64u,
                "relayerPublicIdentity.groupPublicKey33B64u",
            )?,
            ethereum_address20: decode_ethereum_address20(
                &command.relayer_public_identity.ethereum_address,
            )?,
            relayer_share_retry_counter: ROUTER_AB_ECDSA_DERIVATION_RELAYER_SHARE_RETRY_COUNTER_V1,
        },
    })?;

    Ok(FinalizeEcdsaClientBootstrapOutputV1 {
        state_blob: ready_state_blob_envelope(&finalized.ready_state_blob.state_blob),
        public_facts: EcdsaReadyPublicFactsV1 {
            context_binding32_b64u: encode_base64_url(&finalized.public_facts.context_binding32),
            derivation_client_share_public_key33_b64u: encode_base64_url(
                &finalized.public_facts.derivation_client_share_public_key33,
            ),
            client_verifying_share_b64u: encode_base64_url(
                &finalized.public_facts.client_verifying_share33,
            ),
            relayer_public_key33_b64u: encode_base64_url(
                &finalized.public_facts.relayer_public_key33,
            ),
            group_public_key33_b64u: encode_base64_url(&finalized.public_facts.group_public_key33),
            ethereum_address: hex_prefixed(&finalized.public_facts.ethereum_address20),
        },
    })
}

#[cfg(feature = "ecdsa-role-local-client")]
fn validate_prepare_command_header(
    command: &PrepareEcdsaClientBootstrapCommandV1,
) -> CoreResult<()> {
    match command.kind {
        PrepareEcdsaClientBootstrapCommandKindV1::PrepareEcdsaClientBootstrapV1 => {}
    }
    match command.algorithm {
        EcdsaClientBootstrapAlgorithmV1::RouterAbEcdsaDerivationSecp256k1RoleLocalV1 => {}
    }
    validate_participants(&command.participants)
}

#[cfg(feature = "ecdsa-role-local-client")]
fn validate_participants(participants: &EcdsaClientBootstrapParticipantsV1) -> CoreResult<()> {
    if participants.client_participant_id != ROUTER_AB_ECDSA_DERIVATION_CLIENT_PARTICIPANT_ID {
        return Err(SignerCoreError::invalid_input(
            "participants.clientParticipantId must be 1",
        ));
    }
    if participants.relayer_participant_id != ROUTER_AB_ECDSA_DERIVATION_RELAYER_PARTICIPANT_ID {
        return Err(SignerCoreError::invalid_input(
            "participants.relayerParticipantId must be 2",
        ));
    }
    if participants.participant_ids
        != [
            ROUTER_AB_ECDSA_DERIVATION_CLIENT_PARTICIPANT_ID,
            ROUTER_AB_ECDSA_DERIVATION_RELAYER_PARTICIPANT_ID,
        ]
    {
        return Err(SignerCoreError::invalid_input(
            "participants.participantIds must be [1, 2]",
        ));
    }
    Ok(())
}

#[cfg(feature = "ecdsa-role-local-client")]
fn stable_key_context_from_prepare_context(
    context: EcdsaClientBootstrapContextV1,
) -> CoreResult<RouterAbEcdsaDerivationStableKeyContext> {
    let stable_context =
        RouterAbEcdsaDerivationStableKeyContext::new(decode_base64_url_fixed::<32>(
            &context.application_binding_digest_b64u,
            "context.applicationBindingDigestB64u",
        )?);
    stable_context
        .validate()
        .map_err(|error| SignerCoreError::invalid_input(error.message))?;
    Ok(stable_context)
}

#[cfg(feature = "ecdsa-role-local-client")]
fn client_root_share_from_secret_source(
    secret_source: EcdsaBootstrapSecretSourceV1,
) -> CoreResult<[u8; 32]> {
    match secret_source {
        EcdsaBootstrapSecretSourceV1::WebauthnPrfFirst {
            prf_first_b64u,
            rp_id,
            credential_id_b64u,
        } => {
            require_ascii_nonempty(rp_id, "secretSource.rpId")?;
            let mut credential_id =
                decode_base64_url(&credential_id_b64u, "secretSource.credentialIdB64u")?;
            if credential_id.is_empty() {
                return Err(SignerCoreError::invalid_input(
                    "secretSource.credentialIdB64u must decode to at least one byte",
                ));
            }
            credential_id.zeroize();
            let mut prf_first32 =
                decode_base64_url_fixed(&prf_first_b64u, "secretSource.prfFirstB64u")?;
            let derived =
                derive_passkey_threshold_ecdsa_client_root_share32_from_prf_first(&prf_first32);
            prf_first32.zeroize();
            derived
        }
    }
}

#[cfg(feature = "ecdsa-role-local-client")]
fn validate_pending_state_blob_envelope(blob: &EcdsaRoleLocalPendingStateBlobV1) -> CoreResult<()> {
    match blob.kind {
        PendingStateBlobKindV1::EcdsaRoleLocalPendingStateBlobV1 => {}
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

#[cfg(feature = "ecdsa-role-local-client")]
fn pending_state_blob_envelope(bytes: &[u8]) -> EcdsaRoleLocalPendingStateBlobV1 {
    EcdsaRoleLocalPendingStateBlobV1 {
        kind: PendingStateBlobKindV1::EcdsaRoleLocalPendingStateBlobV1,
        curve: Secp256k1CurveNameV1::Secp256k1,
        encoding: Base64UrlEncodingV1::Base64url,
        producer: SignerCoreProducerV1::SignerCore,
        state_blob_b64u: encode_base64_url(bytes),
    }
}

#[cfg(feature = "ecdsa-role-local-client")]
fn ready_state_blob_envelope(bytes: &[u8]) -> EcdsaRoleLocalReadyStateBlobV1 {
    EcdsaRoleLocalReadyStateBlobV1 {
        kind: ReadyStateBlobKindV1::EcdsaRoleLocalReadyStateBlobV1,
        curve: Secp256k1CurveNameV1::Secp256k1,
        encoding: Base64UrlEncodingV1::Base64url,
        producer: SignerCoreProducerV1::SignerCore,
        state_blob_b64u: encode_base64_url(bytes),
    }
}

#[cfg(feature = "ecdsa-role-local-client")]
fn require_ascii_nonempty(value: String, field_name: &str) -> CoreResult<String> {
    let trimmed = value.trim().to_owned();
    require_ascii_nonempty_ref(&trimmed, field_name)?;
    Ok(trimmed)
}

#[cfg(feature = "ecdsa-role-local-client")]
fn require_ascii_nonempty_ref(value: &str, field_name: &str) -> CoreResult<()> {
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
    Ok(())
}

#[cfg(feature = "ecdsa-role-local-client")]
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

#[cfg(feature = "ecdsa-role-local-client")]
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

#[cfg(feature = "ecdsa-role-local-client")]
fn encode_base64_url(input: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(input)
}

#[cfg(feature = "ecdsa-role-local-client")]
fn decode_ethereum_address20(input: &str) -> CoreResult<[u8; 20]> {
    let trimmed = input.trim();
    if !trimmed.starts_with("0x") {
        return Err(SignerCoreError::invalid_input(
            "relayerPublicIdentity.ethereumAddress must be 0x-prefixed",
        ));
    }
    let bytes = hex_to_bytes(trimmed)?;
    if bytes.len() != 20 {
        return Err(SignerCoreError::invalid_length(
            "relayerPublicIdentity.ethereumAddress must be 20 bytes",
        ));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(feature = "ecdsa-role-local-client")]
fn hex_prefixed(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(2 + bytes.len() * 2);
    out.push_str("0x");
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

#[cfg(all(test, feature = "ecdsa-role-local-client"))]
mod command_tests {
    use super::*;
    use crate::ecdsa_role_local_client::{
        derive_passkey_threshold_ecdsa_client_root_share32_from_prf_first,
        prepare_ecdsa_client_bootstrap as prepare_core_ecdsa_client_bootstrap,
        PrepareEcdsaClientBootstrapCommand as CorePrepareEcdsaClientBootstrapCommand,
    };
    use router_ab_ecdsa_derivation::derive_relayer_share_for_client_public;

    fn context() -> EcdsaClientBootstrapContextV1 {
        EcdsaClientBootstrapContextV1 {
            application_binding_digest_b64u: encode_base64_url(&[0x55u8; 32]),
        }
    }

    fn participants() -> EcdsaClientBootstrapParticipantsV1 {
        EcdsaClientBootstrapParticipantsV1 {
            client_participant_id: 1,
            relayer_participant_id: 2,
            participant_ids: vec![1, 2],
        }
    }

    fn prepare_command() -> PrepareEcdsaClientBootstrapCommandV1 {
        PrepareEcdsaClientBootstrapCommandV1 {
            kind: PrepareEcdsaClientBootstrapCommandKindV1::PrepareEcdsaClientBootstrapV1,
            algorithm: EcdsaClientBootstrapAlgorithmV1::RouterAbEcdsaDerivationSecp256k1RoleLocalV1,
            context: context(),
            participants: participants(),
            secret_source: EcdsaBootstrapSecretSourceV1::WebauthnPrfFirst {
                prf_first_b64u: encode_base64_url(&[0x33u8; 32]),
                rp_id: "localhost".to_owned(),
                credential_id_b64u: encode_base64_url(b"credential"),
            },
        }
    }

    #[test]
    fn prepare_command_matches_core_prepare_with_rust_passkey_derivation() {
        let output =
            prepare_ecdsa_client_bootstrap_command_v1(prepare_command()).expect("prepare command");
        let stable_context =
            stable_key_context_from_prepare_context(context()).expect("stable context");
        let client_root_share32 =
            derive_passkey_threshold_ecdsa_client_root_share32_from_prf_first(&[0x33u8; 32])
                .expect("derive client root");
        let direct = prepare_core_ecdsa_client_bootstrap(CorePrepareEcdsaClientBootstrapCommand {
            context: stable_context,
            client_root_share32,
        })
        .expect("core prepare");

        assert_eq!(
            output.client_bootstrap.context_binding32_b64u,
            encode_base64_url(&direct.client_bootstrap.context_binding32)
        );
        assert_eq!(
            output
                .client_bootstrap
                .derivation_client_share_public_key33_b64u,
            encode_base64_url(&direct.client_bootstrap.derivation_client_share_public_key33)
        );
        assert_eq!(output.client_bootstrap.participant_id, 1);
        assert_eq!(
            output.pending_state_blob.kind,
            PendingStateBlobKindV1::EcdsaRoleLocalPendingStateBlobV1
        );
    }

    #[test]
    fn prepare_command_rejects_invalid_participants() {
        let mut command = prepare_command();
        command.participants.participant_ids = vec![2, 1];
        let error = prepare_ecdsa_client_bootstrap_command_v1(command).expect_err("reject");
        assert!(error.message.contains("participantIds"));
    }

    #[test]
    fn finalize_command_round_trips_ready_blob() {
        let prepared =
            prepare_ecdsa_client_bootstrap_command_v1(prepare_command()).expect("prepare command");
        let stable_context =
            stable_key_context_from_prepare_context(context()).expect("stable context");
        let (_relayer_share, identity) = derive_relayer_share_for_client_public(
            &stable_context,
            [0x44u8; 32],
            &decode_base64_url_fixed::<33>(
                &prepared
                    .client_bootstrap
                    .derivation_client_share_public_key33_b64u,
                "client public key",
            )
            .expect("client public key"),
            prepared.client_bootstrap.client_share_retry_counter,
        )
        .expect("relayer identity");

        let finalized =
            finalize_ecdsa_client_bootstrap_command_v1(FinalizeEcdsaClientBootstrapCommandV1 {
                kind: FinalizeEcdsaClientBootstrapCommandKindV1::FinalizeEcdsaClientBootstrapV1,
                pending_state_blob: prepared.pending_state_blob,
                relayer_public_identity: RelayerPublicIdentityV1 {
                    relayer_key_id: "relayer-key".to_owned(),
                    relayer_public_key33_b64u: encode_base64_url(&identity.relayer_public_key33),
                    group_public_key33_b64u: encode_base64_url(&identity.threshold_public_key33),
                    ethereum_address: hex_prefixed(&identity.threshold_ethereum_address20),
                },
            })
            .expect("finalize command");

        assert_eq!(
            finalized.state_blob.kind,
            ReadyStateBlobKindV1::EcdsaRoleLocalReadyStateBlobV1
        );
        assert_eq!(
            finalized.public_facts.group_public_key33_b64u,
            encode_base64_url(&identity.threshold_public_key33)
        );
        assert_eq!(
            finalized.public_facts.ethereum_address,
            hex_prefixed(&identity.threshold_ethereum_address20)
        );
    }
}
