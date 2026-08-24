use base64ct::{Base64UrlUnpadded, Encoding};
use js_sys::{Array, Object, Reflect, Uint8Array};
use rand_core::OsRng;
use router_ab_ecdsa_client_protocol::{
    derive_ecdsa_client_ephemeral_keypair_v1, open_ecdsa_signing_worker_export_share_v1,
    EcdsaClientEphemeralKeyPairV1, EcdsaSigningWorkerExportShareBindingV1,
    EcdsaSigningWorkerExportShareEnvelopeV1, EcdsaWalletRecoveryMaterialPossessionChallengeV1,
    LinkedDeviceEcdsaSourceContributionBindingV1,
};
use router_ab_ecdsa_derivation::shared::secp256k1::{
    add_secp256k1_public_keys_33, secp256k1_public_key_33_to_ethereum_address_20,
    validate_secp256k1_public_key_33,
};
use router_ab_ecdsa_derivation::{
    ecdsa_lane_client_public_key_from_share32_v1, reconstruct_ecdsa_additive_export_key_v1,
};
use router_ab_ecdsa_online::{
    combine_rerandomization_contributions, compute_client_signature_share, ClientPresignMaterial,
    OnlineClientInput,
};
use router_ab_ecdsa_presign::session::{
    derive_presign_pair_context, ClientPresignSession as FixedClientPresignSession,
    PresignSessionError, PresignSessionProgress,
};
use router_ab_ecdsa_presign::{AdditiveKeyShare, PresignOutput};
use router_ab_ecdsa_wire::{CompressedPointBytes, ScalarBytes};
use serde::{Deserialize, Serialize};
use signer_core::ecdsa_role_local_client::command::{
    extract_client_signing_share32_from_ready_state_blob,
    sign_wallet_recovery_material_possession_proof, EcdsaRoleLocalReadyStateBlob,
};
use signer_core::error::{SignerCoreError, SignerCoreErrorCode};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::ceremony::build_explicit_export_request_with_keypair;
use crate::client_proof_verifier::{
    verify_encrypted_client_proof_input_for_export, FinalizeEncryptedClientProofBundlesInputV1,
};

const WALLET_RECOVERY_POSSESSION_CHALLENGE_KIND_V1: &str =
    "seams_wallet_recovery_ecdsa_existing_material_possession_challenge_v1";
const WALLET_RECOVERY_POSSESSION_PROOF_KIND_V1: &str = "wallet_recovery_ecdsa_possession_proof_v1";

#[wasm_bindgen]
pub fn prepare_ecdsa_client_bootstrap_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::PrepareEcdsaClientBootstrapCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::prepare_ecdsa_client_bootstrap_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub fn finalize_ecdsa_client_bootstrap_v1(input_json: &str) -> Result<String, JsValue> {
    let command: signer_core::commands::FinalizeEcdsaClientBootstrapCommandV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let output = signer_core::commands::finalize_ecdsa_client_bootstrap_command_v1(command)
        .map_err(js_signer_core_err)?;
    serde_json::to_string(&output).map_err(js_command_invalid_input_err)
}

#[wasm_bindgen]
pub struct EcdsaRoleLocalPresignSessionV1 {
    inner: FixedClientPresignSession,
    completed: Option<PresignOutput>,
}

#[wasm_bindgen]
pub struct EcdsaLinkedHolderMaterialV1 {
    signing_share32: Zeroizing<[u8; 32]>,
    threshold_public_key33: [u8; 33],
    threshold_ethereum_address20: [u8; 20],
    target_material_activation: router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefV1,
    ecdsa_threshold_key_id: String,
    normal_signing: LinkedEcdsaNormalSigningStateV1,
    export_recipient: EcdsaClientEphemeralKeyPairV1,
    pending_export_request_digest: Option<[u8; 32]>,
    pending_export_transcript_digest: Option<[u8; 32]>,
    export_consumed: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkedEcdsaActivationReceiptV1 {
    state: String,
    binding: LinkedDeviceEcdsaSourceContributionBindingV1,
    source_derivation: LinkedEcdsaSourceDerivationV1,
    target_relayer_public_key33_b64u: String,
    threshold_public_key33_b64u: String,
    threshold_ethereum_address20_b64u: String,
    normal_signing: LinkedEcdsaNormalSigningStateV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkedEcdsaSourceDerivationV1 {
    application_binding_digest_b64u: String,
    client_share_retry_counter: u32,
    ecdsa_threshold_key_id: String,
    source_normal_signing: LinkedEcdsaNormalSigningStateV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedEcdsaNormalSigningStateV1 {
    kind: String,
    scope: LinkedEcdsaNormalSigningScopeV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedEcdsaNormalSigningScopeV1 {
    wallet_id: String,
    ecdsa_threshold_key_id: String,
    signing_root_id: String,
    signing_root_version: String,
    context: LinkedEcdsaNormalSigningContextV1,
    public_identity: LinkedEcdsaNormalSigningPublicIdentityV1,
    material_activation: LinkedEcdsaNormalSigningMaterialActivationV1,
    signing_worker: LinkedEcdsaNormalSigningWorkerV1,
    activation_epoch: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedEcdsaNormalSigningContextV1 {
    application_binding_digest_b64u: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedEcdsaNormalSigningPublicIdentityV1 {
    context_binding_b64u: String,
    derivation_client_share_public_key33_b64u: String,
    server_public_key33_b64u: String,
    threshold_public_key33_b64u: String,
    ethereum_address20_b64u: String,
    client_share_retry_counter: u32,
    server_share_retry_counter: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedEcdsaNormalSigningMaterialActivationV1 {
    kind: String,
    activation_id: String,
    capability: String,
    material_owner: String,
    key_binding: String,
    lifecycle_binding: String,
    signing_worker: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkedEcdsaNormalSigningWorkerV1 {
    server_id: String,
    key_epoch: String,
    recipient_encryption_key: String,
}

fn validate_linked_ecdsa_normal_signing_receipt(
    receipt: &LinkedEcdsaActivationReceiptV1,
) -> Result<(), String> {
    let source = &receipt.source_derivation.source_normal_signing;
    let target = &receipt.normal_signing;
    for (label, state) in [("sourceNormalSigning", source), ("normalSigning", target)] {
        if state.kind != "router_ab_ecdsa_derivation_normal_signing_v1" {
            return Err(format!(
                "{label}.kind is not the canonical Router A/B ECDSA normal-signing kind"
            ));
        }
        require_receipt_text(&state.scope.wallet_id, &format!("{label}.scope.wallet_id"))?;
        require_receipt_text(
            &state.scope.ecdsa_threshold_key_id,
            &format!("{label}.scope.ecdsa_threshold_key_id"),
        )?;
        require_receipt_text(
            &state.scope.signing_root_id,
            &format!("{label}.scope.signing_root_id"),
        )?;
        require_receipt_text(
            &state.scope.signing_root_version,
            &format!("{label}.scope.signing_root_version"),
        )?;
        require_receipt_text(
            &state.scope.activation_epoch,
            &format!("{label}.scope.activation_epoch"),
        )?;
        require_receipt_text(
            &state.scope.context.application_binding_digest_b64u,
            &format!("{label}.scope.context.application_binding_digest_b64u"),
        )?;
        decode_base64_fixed_text::<32>(
            &state.scope.context.application_binding_digest_b64u,
            &format!("{label}.scope.context.application_binding_digest_b64u"),
        )?;
        let context = router_ab_ecdsa_client_protocol::EcdsaStableKeyContextV1::new(
            state.scope.context.application_binding_digest_b64u.clone(),
        )
        .map_err(|error| format!("{label}.scope.context is invalid: {error:?}"))?;
        let expected_context_binding = Base64UrlUnpadded::encode_string(
            &context
                .binding_digest()
                .map_err(|error| format!("{label}.scope.context is invalid: {error:?}"))?,
        );
        if state.scope.public_identity.context_binding_b64u != expected_context_binding {
            return Err(format!(
                "{label}.scope.public_identity.context_binding_b64u does not match scope.context"
            ));
        }
        decode_base64_fixed_text::<32>(
            &state.scope.public_identity.context_binding_b64u,
            &format!("{label}.scope.public_identity.context_binding_b64u"),
        )?;
        for (value, field) in [
            (
                &state
                    .scope
                    .public_identity
                    .derivation_client_share_public_key33_b64u,
                "derivation_client_share_public_key33_b64u",
            ),
            (
                &state.scope.public_identity.server_public_key33_b64u,
                "server_public_key33_b64u",
            ),
            (
                &state.scope.public_identity.threshold_public_key33_b64u,
                "threshold_public_key33_b64u",
            ),
        ] {
            let key = decode_base64_fixed_text::<33>(
                value,
                &format!("{label}.scope.public_identity.{field}"),
            )?;
            validate_secp256k1_public_key_33(&key).map_err(|error| {
                format!("{label}.scope.public_identity.{field} is invalid: {error}")
            })?;
        }
        decode_base64_fixed_text::<20>(
            &state.scope.public_identity.ethereum_address20_b64u,
            &format!("{label}.scope.public_identity.ethereum_address20_b64u"),
        )?;
        require_receipt_text(
            &state.scope.signing_worker.server_id,
            &format!("{label}.scope.signing_worker.server_id"),
        )?;
        require_receipt_text(
            &state.scope.signing_worker.key_epoch,
            &format!("{label}.scope.signing_worker.key_epoch"),
        )?;
        require_receipt_text(
            &state.scope.signing_worker.recipient_encryption_key,
            &format!("{label}.scope.signing_worker.recipient_encryption_key"),
        )?;
        validate_receipt_material_activation(
            &state.scope.material_activation,
            &format!("{label}.scope.material_activation"),
        )?;
    }
    if source.scope.context.application_binding_digest_b64u
        != receipt.source_derivation.application_binding_digest_b64u
        || source.scope.public_identity.client_share_retry_counter
            != receipt.source_derivation.client_share_retry_counter
        || source.scope.ecdsa_threshold_key_id != receipt.source_derivation.ecdsa_threshold_key_id
    {
        return Err("sourceNormalSigning does not match sourceDerivation".to_owned());
    }
    if source.scope.wallet_id != target.scope.wallet_id
        || source.scope.ecdsa_threshold_key_id != target.scope.ecdsa_threshold_key_id
        || source.scope.signing_root_id != target.scope.signing_root_id
        || source.scope.signing_root_version != target.scope.signing_root_version
        || source.scope.context.application_binding_digest_b64u
            != target.scope.context.application_binding_digest_b64u
        || source.scope.activation_epoch != target.scope.activation_epoch
        || source.scope.public_identity.context_binding_b64u
            != target.scope.public_identity.context_binding_b64u
        || source.scope.signing_worker.key_epoch != target.scope.signing_worker.key_epoch
    {
        return Err(
            "source and target normal-signing scopes do not preserve the exact active authority"
                .to_owned(),
        );
    }
    validate_receipt_material_activation_matches(
        &source.scope.material_activation,
        &receipt.binding.source.activation,
        "sourceNormalSigning.scope.material_activation",
    )?;
    validate_receipt_material_activation_matches(
        &target.scope.material_activation,
        &receipt.binding.target.activation,
        "normalSigning.scope.material_activation",
    )?;
    if source.scope.wallet_id != receipt.binding.source.activation.material_owner
        || target.scope.wallet_id != receipt.binding.target.activation.material_owner
        || source.scope.signing_worker.server_id != receipt.binding.source.activation.signing_worker
        || target.scope.signing_worker.server_id != receipt.binding.target.activation.signing_worker
    {
        return Err(
            "normal-signing authority identity does not match material activation".to_owned(),
        );
    }
    let source_identity = &source.scope.public_identity;
    if source_identity.derivation_client_share_public_key33_b64u
        != receipt.binding.source.client_public_key33_b64u
        || source_identity.server_public_key33_b64u
            != receipt.binding.source.relayer_public_key33_b64u
        || source_identity.threshold_public_key33_b64u
            != receipt.binding.source.threshold_public_key33_b64u
        || source_identity.ethereum_address20_b64u
            != receipt.binding.source.threshold_ethereum_address20_b64u
    {
        return Err("sourceNormalSigning public identity does not match source binding".to_owned());
    }
    let target_identity = &target.scope.public_identity;
    if target_identity.derivation_client_share_public_key33_b64u
        != receipt.binding.target_client_public_key33_b64u
        || target_identity.server_public_key33_b64u != receipt.target_relayer_public_key33_b64u
        || target_identity.threshold_public_key33_b64u != receipt.threshold_public_key33_b64u
        || target_identity.ethereum_address20_b64u != receipt.threshold_ethereum_address20_b64u
        || target_identity.client_share_retry_counter != source_identity.client_share_retry_counter
        || target_identity.server_share_retry_counter != source_identity.server_share_retry_counter
    {
        return Err("normalSigning public identity does not match target binding".to_owned());
    }
    if target.scope.signing_worker.recipient_encryption_key
        != x25519_public_key_from_receipt_b64u(
            &receipt
                .binding
                .target
                .signing_worker_recipient_public_key_b64u,
        )?
    {
        return Err(
            "normalSigning signing-worker recipient does not match target binding".to_owned(),
        );
    }
    Ok(())
}

fn validate_receipt_material_activation(
    activation: &LinkedEcdsaNormalSigningMaterialActivationV1,
    label: &str,
) -> Result<(), String> {
    if activation.kind != "mpc_material_activation_ref" {
        return Err(format!("{label}.kind is invalid"));
    }
    for (value, field) in [
        (&activation.activation_id, "activation_id"),
        (&activation.capability, "capability"),
        (&activation.material_owner, "material_owner"),
        (&activation.key_binding, "key_binding"),
        (&activation.lifecycle_binding, "lifecycle_binding"),
        (&activation.signing_worker, "signing_worker"),
    ] {
        require_receipt_text(value, &format!("{label}.{field}"))?;
    }
    Ok(())
}

fn validate_receipt_material_activation_matches(
    actual: &LinkedEcdsaNormalSigningMaterialActivationV1,
    expected: &router_ab_ecdsa_client_protocol::EcdsaMaterialActivationRefV1,
    label: &str,
) -> Result<(), String> {
    if actual.activation_id != expected.activation_id
        || actual.capability != expected.capability
        || actual.material_owner != expected.material_owner
        || actual.key_binding != expected.key_binding
        || actual.lifecycle_binding != expected.lifecycle_binding
        || actual.signing_worker != expected.signing_worker
    {
        return Err(format!("{label} differs from the activation binding"));
    }
    Ok(())
}

fn require_receipt_text(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(format!("{field} must be a trimmed non-empty string"));
    }
    Ok(())
}

fn x25519_public_key_from_receipt_b64u(value: &str) -> Result<String, String> {
    let bytes =
        decode_base64_fixed_text::<32>(value, "target.signingWorkerRecipientPublicKeyB64u")?;
    let mut output = String::from("x25519:");
    for byte in bytes {
        use core::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LinkedEcdsaOrdinaryExportFinalizationInputV1 {
    client_proof_finalization: FinalizeEncryptedClientProofBundlesInputV1,
    signing_worker_export: EcdsaSigningWorkerExportShareEnvelopeV1,
    expected_binding: EcdsaSigningWorkerExportShareBindingV1,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct LinkedEcdsaExportArtifactOutputV1 {
    public_key_hex: String,
    private_key_hex: String,
    ethereum_address: String,
}

#[wasm_bindgen]
impl EcdsaLinkedHolderMaterialV1 {
    #[wasm_bindgen(constructor)]
    pub fn new(signing_share32: &[u8], activation_receipt_json: &str) -> Result<Self, JsValue> {
        let receipt: LinkedEcdsaActivationReceiptV1 = serde_json::from_str(activation_receipt_json)
            .map_err(|error| {
                js_error(format!(
                    "linked ECDSA activation receipt is invalid: {error}"
                ))
            })?;
        if receipt.state != "inactive" {
            return Err(js_error("linked ECDSA activation receipt must be inactive"));
        }
        validate_linked_ecdsa_normal_signing_receipt(&receipt).map_err(js_error)?;
        receipt.binding.validate().map_err(|error| {
            js_error(format!(
                "linked ECDSA activation binding is invalid: {error:?}"
            ))
        })?;
        decode_base64_fixed::<32>(
            &receipt.source_derivation.application_binding_digest_b64u,
            "sourceDerivation.applicationBindingDigestB64u",
        )?;
        let _client_share_retry_counter = receipt.source_derivation.client_share_retry_counter;
        if receipt
            .source_derivation
            .ecdsa_threshold_key_id
            .trim()
            .is_empty()
        {
            return Err(js_error(
                "sourceDerivation.ecdsaThresholdKeyId must be non-empty",
            ));
        }
        if receipt.source_derivation.ecdsa_threshold_key_id.trim()
            != receipt.source_derivation.ecdsa_threshold_key_id
        {
            return Err(js_error(
                "sourceDerivation.ecdsaThresholdKeyId must not have surrounding whitespace",
            ));
        }
        let source_client_public_key33 = decode_base64_fixed::<33>(
            &receipt.binding.source.client_public_key33_b64u,
            "binding.source.clientPublicKey33B64u",
        )?;
        let source_relayer_public_key33 = decode_base64_fixed::<33>(
            &receipt.binding.source.relayer_public_key33_b64u,
            "binding.source.relayerPublicKey33B64u",
        )?;
        let source_threshold_public_key33 = decode_base64_fixed::<33>(
            &receipt.binding.source.threshold_public_key33_b64u,
            "binding.source.thresholdPublicKey33B64u",
        )?;
        for (key, label) in [
            (
                &source_client_public_key33,
                "binding.source.clientPublicKey33B64u",
            ),
            (
                &source_relayer_public_key33,
                "binding.source.relayerPublicKey33B64u",
            ),
            (
                &source_threshold_public_key33,
                "binding.source.thresholdPublicKey33B64u",
            ),
        ] {
            validate_secp256k1_public_key_33(key)
                .map_err(|error| js_error(format!("{label} is invalid: {error}")))?;
        }
        let source_threshold_ethereum_address20 = decode_base64_fixed::<20>(
            &receipt.binding.source.threshold_ethereum_address20_b64u,
            "binding.source.thresholdEthereumAddress20B64u",
        )?;
        let reconstructed_source_threshold_public_key33 =
            add_secp256k1_public_keys_33(&source_client_public_key33, &source_relayer_public_key33)
                .map_err(|error| {
                    js_error(format!(
                        "linked ECDSA source threshold key cannot be reconstructed: {error}"
                    ))
                })?;
        if reconstructed_source_threshold_public_key33.as_slice() != source_threshold_public_key33 {
            return Err(js_error(
                "linked ECDSA source threshold key does not match its client and relayer keys",
            ));
        }
        let reconstructed_source_threshold_ethereum_address20 =
            secp256k1_public_key_33_to_ethereum_address_20(&source_threshold_public_key33)
                .map_err(|error| {
                    js_error(format!(
                        "linked ECDSA source threshold address cannot be derived: {error}"
                    ))
                })?;
        if reconstructed_source_threshold_ethereum_address20.as_slice()
            != source_threshold_ethereum_address20
        {
            return Err(js_error(
                "linked ECDSA source threshold address does not match its threshold key",
            ));
        }
        let expected_client_public_key33 = decode_base64_fixed::<33>(
            &receipt.binding.target_client_public_key33_b64u,
            "binding.targetClientPublicKey33B64u",
        )?;
        validate_secp256k1_public_key_33(&expected_client_public_key33).map_err(|error| {
            js_error(format!(
                "linked holder client public key is invalid: {error}"
            ))
        })?;
        let target_relayer_public_key33 = decode_base64_fixed::<33>(
            &receipt.target_relayer_public_key33_b64u,
            "targetRelayerPublicKey33B64u",
        )?;
        validate_secp256k1_public_key_33(&target_relayer_public_key33)
            .map_err(|error| js_error(format!("target relayer public key is invalid: {error}")))?;
        let threshold_public_key33 = decode_base64_fixed::<33>(
            &receipt.threshold_public_key33_b64u,
            "thresholdPublicKey33B64u",
        )?;
        validate_secp256k1_public_key_33(&threshold_public_key33)
            .map_err(|error| js_error(format!("threshold public key is invalid: {error}")))?;
        let threshold_ethereum_address20 = decode_base64_fixed::<20>(
            &receipt.threshold_ethereum_address20_b64u,
            "thresholdEthereumAddress20B64u",
        )?;
        let reconstructed_threshold_public_key33 = add_secp256k1_public_keys_33(
            &expected_client_public_key33,
            &target_relayer_public_key33,
        )
        .map_err(|error| {
            js_error(format!(
                "linked ECDSA activation threshold key cannot be reconstructed: {error}"
            ))
        })?;
        if reconstructed_threshold_public_key33.as_slice() != threshold_public_key33 {
            return Err(js_error(
                "linked ECDSA activation threshold key does not match its client and relayer keys",
            ));
        }
        if threshold_public_key33 != source_threshold_public_key33 {
            return Err(js_error(
                "linked ECDSA activation threshold key does not preserve its source identity",
            ));
        }
        let reconstructed_threshold_ethereum_address20 =
            secp256k1_public_key_33_to_ethereum_address_20(&threshold_public_key33).map_err(
                |error| {
                    js_error(format!(
                        "linked ECDSA activation threshold address cannot be derived: {error}"
                    ))
                },
            )?;
        if reconstructed_threshold_ethereum_address20.as_slice() != threshold_ethereum_address20 {
            return Err(js_error(
                "linked ECDSA activation threshold address does not match its threshold key",
            ));
        }
        let signing_share32 =
            Zeroizing::new(fixed_bytes(signing_share32, "linked holder signing share")?);
        let actual_client_public_key33 =
            ecdsa_lane_client_public_key_from_share32_v1(*signing_share32)
                .map_err(|error| JsValue::from_str(&error.to_string()))?;
        if actual_client_public_key33 != expected_client_public_key33 {
            return Err(JsValue::from_str(
                "linked holder signing share does not match its public key",
            ));
        }
        let mut export_recipient_seed = [0_u8; 32];
        getrandom::getrandom(&mut export_recipient_seed).map_err(|error| {
            js_error(format!(
                "linked holder export recipient CSPRNG failed: {error}"
            ))
        })?;
        let export_recipient_result =
            derive_ecdsa_client_ephemeral_keypair_v1(export_recipient_seed);
        export_recipient_seed.zeroize();
        let export_recipient = export_recipient_result.map_err(|error| {
            js_error(format!(
                "linked holder export recipient key generation failed: {error:?}"
            ))
        })?;
        Ok(Self {
            signing_share32,
            threshold_public_key33,
            threshold_ethereum_address20,
            target_material_activation: receipt.binding.target.activation,
            ecdsa_threshold_key_id: receipt.source_derivation.ecdsa_threshold_key_id,
            normal_signing: receipt.normal_signing,
            export_recipient,
            pending_export_request_digest: None,
            pending_export_transcript_digest: None,
            export_consumed: false,
        })
    }

    /// Builds the ordinary explicit-export request with this holder's
    /// recipient. The request digest and transcript stay private to WASM.
    pub fn build_ordinary_export_request(&mut self, input_json: &str) -> Result<String, JsValue> {
        if self.export_consumed {
            return Err(js_error(
                "ECDSA holder export recipient was already consumed",
            ));
        }
        if self.pending_export_request_digest.is_some() {
            return Err(js_error("ECDSA holder export request was already built"));
        }
        let (serialized, request_digest, transcript_digest) =
            build_explicit_export_request_with_keypair(input_json, &self.export_recipient)?;
        self.pending_export_request_digest = Some(request_digest);
        self.pending_export_transcript_digest = Some(transcript_digest);
        Ok(serialized)
    }

    /// Returns the canonical ordinary explicit-export request digest.
    pub fn ordinary_export_request_digest_b64u(&self) -> Result<String, JsValue> {
        let digest = self
            .pending_export_request_digest
            .ok_or_else(|| js_error("ECDSA holder export request was not built"))?;
        Ok(Base64UrlUnpadded::encode_string(&digest))
    }

    /// Verifies both ordinary export proof bundles, opens the standard
    /// SigningWorker envelope, and reconstructs the holder's additive key.
    pub fn finalize_ordinary_export(&mut self, input_json: &str) -> Result<String, JsValue> {
        if self.export_consumed {
            return Err(js_error(
                "ECDSA holder export recipient was already consumed",
            ));
        }
        let request_digest = self
            .pending_export_request_digest
            .take()
            .ok_or_else(|| js_error("ECDSA holder export request was not built"))?;
        let transcript_digest = self
            .pending_export_transcript_digest
            .take()
            .ok_or_else(|| js_error("ECDSA holder export transcript was not prepared"))?;
        self.export_consumed = true;
        let input: LinkedEcdsaOrdinaryExportFinalizationInputV1 = parse_json(input_json)?;
        let expected_request_digest = decode_base64_fixed::<32>(
            &input.expected_binding.export_request_digest_b64u,
            "expectedBinding.exportRequestDigestB64u",
        )?;
        if expected_request_digest != request_digest {
            return Err(js_error(
                "ECDSA holder export binding does not match the prepared request",
            ));
        }
        let expected_threshold_public_key33 = decode_base64_fixed::<33>(
            &input.expected_binding.threshold_public_key33_b64u,
            "expectedBinding.thresholdPublicKey33B64u",
        )?;
        if expected_threshold_public_key33 != self.threshold_public_key33 {
            return Err(js_error(
                "ECDSA holder export threshold public key does not match activation",
            ));
        }
        if input.expected_binding.ecdsa_threshold_key_id != self.ecdsa_threshold_key_id
            || input.expected_binding.wallet_id != self.target_material_activation.material_owner
            || input.expected_binding.material_activation != self.target_material_activation
            || input.expected_binding.recipient_public_key != self.export_recipient.public_key()
            || input.expected_binding.context_binding_b64u
                != self
                    .normal_signing
                    .scope
                    .public_identity
                    .context_binding_b64u
            || input.expected_binding.signing_root_id != self.normal_signing.scope.signing_root_id
            || input.expected_binding.signing_root_version
                != self.normal_signing.scope.signing_root_version
            || input.expected_binding.activation_epoch != self.normal_signing.scope.activation_epoch
            || input.expected_binding.signing_worker_id
                != self.normal_signing.scope.signing_worker.server_id
        {
            return Err(js_error(
                "ECDSA holder export binding does not match the exact normal-signing scope",
            ));
        }
        verify_encrypted_client_proof_input_for_export(
            input.client_proof_finalization,
            self.export_recipient.private_key_bytes(),
            transcript_digest,
            &input.expected_binding.recipient_identity,
        )?;
        let mut signing_worker_share32 = open_ecdsa_signing_worker_export_share_v1(
            &input.signing_worker_export,
            &input.expected_binding,
            self.export_recipient.private_key_bytes(),
        )
        .map_err(|error| {
            js_error(format!(
                "ECDSA holder export share could not be opened: {error:?}"
            ))
        })?;
        let reconstruction_result = reconstruct_ecdsa_additive_export_key_v1(
            *self.signing_share32,
            signing_worker_share32,
            self.threshold_public_key33,
            self.threshold_ethereum_address20,
        );
        signing_worker_share32.zeroize();
        let mut private_key32 =
            reconstruction_result.map_err(|error| js_error(error.to_string()))?;
        let output = LinkedEcdsaExportArtifactOutputV1 {
            public_key_hex: hex_prefixed(&self.threshold_public_key33),
            private_key_hex: hex_prefixed(&private_key32),
            ethereum_address: hex_prefixed(&self.threshold_ethereum_address20),
        };
        private_key32.zeroize();
        serde_json::to_string(&output).map_err(|error| js_error(error.to_string()))
    }

    pub fn start_presign(
        &self,
        group_public_key33: &[u8],
        presign_session_id: &str,
    ) -> Result<EcdsaRoleLocalPresignSessionV1, JsValue> {
        let group_public_key33 = fixed_bytes(group_public_key33, "group public key")?;
        if group_public_key33 != self.threshold_public_key33 {
            return Err(js_error(
                "linked ECDSA presign group key does not match its activation receipt",
            ));
        }
        Ok(EcdsaRoleLocalPresignSessionV1 {
            inner: new_presign_session(
                &self.signing_share32,
                &group_public_key33,
                presign_session_id,
            )?,
            completed: None,
        })
    }
}

#[wasm_bindgen]
impl EcdsaRoleLocalPresignSessionV1 {
    #[wasm_bindgen(constructor)]
    pub fn new(
        state_blob_b64u: &str,
        group_public_key33: &[u8],
        presign_session_id: &str,
    ) -> Result<Self, JsValue> {
        let ready_state_blob = EcdsaRoleLocalReadyStateBlob {
            state_blob: Base64UrlUnpadded::decode_vec(state_blob_b64u)
                .map_err(|error| JsValue::from_str(&format!("Invalid stateBlobB64u: {error}")))?,
        };
        let signing_share32 = Zeroizing::new(
            extract_client_signing_share32_from_ready_state_blob(&ready_state_blob)
                .map_err(|error| JsValue::from_str(&error.to_string()))?,
        );
        Ok(Self {
            inner: new_presign_session(&signing_share32, group_public_key33, presign_session_id)?,
            completed: None,
        })
    }

    pub fn stage(&self) -> String {
        self.inner.stage().as_str().to_owned()
    }

    pub fn poll(&mut self) -> Result<JsValue, JsValue> {
        progress_to_js(self.inner.poll())
    }

    pub fn message(&mut self, message: &[u8]) -> Result<(), JsValue> {
        self.inner
            .message(message, &mut OsRng)
            .map_err(js_presign_error)
    }

    pub fn start_presign(&mut self) -> Result<(), JsValue> {
        self.inner.start_presign().map_err(js_presign_error)
    }

    pub fn presignature_big_r_33(&mut self) -> Result<Vec<u8>, JsValue> {
        if self.completed.is_none() {
            self.completed = Some(self.inner.take_presignature().map_err(js_presign_error)?);
        }
        Ok(self
            .completed
            .as_ref()
            .expect("completed presignature was just installed")
            .big_r_bytes()
            .as_bytes()
            .to_vec())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn compute_signature_share(
        &mut self,
        group_public_key33: &[u8],
        expected_presign_big_r33: &[u8],
        digest32: &[u8],
        client_rerandomization_contribution32: &[u8],
        signing_worker_rerandomization_contribution32: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let output = self
            .completed
            .take()
            .ok_or_else(|| JsValue::from_str("presignature is unavailable"))?;
        compute_online_share(
            output,
            group_public_key33,
            expected_presign_big_r33,
            digest32,
            client_rerandomization_contribution32,
            signing_worker_rerandomization_contribution32,
        )
    }
}

fn compute_online_share(
    output: PresignOutput,
    group_public_key33: &[u8],
    expected_presign_big_r33: &[u8],
    digest32: &[u8],
    client_rerandomization_contribution32: &[u8],
    signing_worker_rerandomization_contribution32: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let (big_r33, k_share32, sigma_share32) = output.into_parts();
    let material = ClientPresignMaterial::from_bytes(
        *big_r33.as_bytes(),
        k_share32.into_bytes(),
        sigma_share32.into_bytes(),
    )
    .map_err(|error| JsValue::from_str(&error.to_string()))?;
    let entropy32 = combine_rerandomization_contributions(
        fixed_bytes(
            client_rerandomization_contribution32,
            "client rerandomization contribution",
        )?,
        fixed_bytes(
            signing_worker_rerandomization_contribution32,
            "signing worker rerandomization contribution",
        )?,
    );
    let input = OnlineClientInput::new(
        fixed_bytes(group_public_key33, "group public key")?,
        fixed_bytes(expected_presign_big_r33, "expected presign R")?,
        fixed_bytes(digest32, "signing digest")?,
        entropy32,
    )
    .map_err(|error| JsValue::from_str(&error.to_string()))?;
    compute_client_signature_share(
        material
            .reserve()
            .commit(input)
            .map_err(|error| JsValue::from_str(&error.to_string()))?,
    )
    .map(|share| share.to_vec())
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

fn fixed_bytes<const N: usize>(bytes: &[u8], label: &str) -> Result<[u8; N], JsValue> {
    bytes
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{label} must contain {N} bytes")))
}

fn parse_json<T>(input_json: &str) -> Result<T, JsValue>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(input_json)
        .map_err(|error| js_error(format!("ECDSA holder JSON is invalid: {error}")))
}

fn hex_prefixed(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        use core::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn decode_base64_fixed<const N: usize>(value: &str, label: &str) -> Result<[u8; N], JsValue> {
    decode_base64_fixed_text(value, label).map_err(js_error)
}

fn decode_base64_fixed_text<const N: usize>(value: &str, label: &str) -> Result<[u8; N], String> {
    let decoded = Base64UrlUnpadded::decode_vec(value)
        .map_err(|error| format!("{label} is invalid: {error}"))?;
    if Base64UrlUnpadded::encode_string(&decoded) != value {
        return Err(format!("{label} must use canonical base64url"));
    }
    decoded
        .try_into()
        .map_err(|_| format!("{label} must contain {N} bytes"))
}

fn js_error(message: impl Into<String>) -> JsValue {
    JsValue::from_str(&message.into())
}

fn new_presign_session(
    signing_share32: &[u8; 32],
    group_public_key33: &[u8],
    presign_session_id: &str,
) -> Result<FixedClientPresignSession, JsValue> {
    let group_public_key33: [u8; 33] = group_public_key33
        .try_into()
        .map_err(|_| JsValue::from_str("group public key must contain 33 bytes"))?;
    let wallet_public_key = CompressedPointBytes::new(group_public_key33);
    let context = derive_presign_pair_context(wallet_public_key, presign_session_id)
        .map_err(js_presign_error)?;
    let key_share = AdditiveKeyShare::from_bytes(ScalarBytes::new(*signing_share32))
        .map_err(|error| JsValue::from_str(&error.to_string()))?;
    FixedClientPresignSession::new(context, key_share, wallet_public_key, &mut OsRng)
        .map_err(js_presign_error)
}

fn progress_to_js(progress: PresignSessionProgress) -> Result<JsValue, JsValue> {
    let output = Object::new();
    Reflect::set(
        &output,
        &JsValue::from_str("stage"),
        &JsValue::from_str(progress.stage.as_str()),
    )?;
    Reflect::set(
        &output,
        &JsValue::from_str("event"),
        &JsValue::from_str(progress.event.as_str()),
    )?;
    let outgoing = Array::new();
    for message in progress.outgoing {
        outgoing.push(&Uint8Array::from(message.as_slice()));
    }
    Reflect::set(&output, &JsValue::from_str("outgoing"), &outgoing)?;
    Ok(output.into())
}

fn js_presign_error(error: PresignSessionError) -> JsValue {
    JsValue::from_str(&error.to_string())
}

/// Signs a wallet-recovery no-refresh possession challenge from one exact
/// role-local ready-state blob. The client scalar and BIP340 nonce remain in
/// Rust/WASM for the complete operation.
#[wasm_bindgen]
pub fn sign_ecdsa_wallet_recovery_material_possession_proof_v1(
    input_json: &str,
) -> Result<String, JsValue> {
    let input: WalletRecoveryMaterialPossessionProofInputV1 =
        serde_json::from_str(input_json).map_err(js_command_invalid_input_err)?;
    let WalletRecoveryMaterialPossessionProofInputV1 {
        mut state_blob_b64u,
        challenge: challenge_input,
    } = input;
    let challenge = match challenge_input.into_protocol() {
        Ok(challenge) => challenge,
        Err(error) => {
            state_blob_b64u.zeroize();
            return Err(js_signer_core_err(error));
        }
    };
    let state_blob_result = Base64UrlUnpadded::decode_vec(&state_blob_b64u)
        .map_err(|error| js_command_invalid_input_err(format!("Invalid stateBlobB64u: {error}")));
    state_blob_b64u.zeroize();
    let ready_state_blob = EcdsaRoleLocalReadyStateBlob {
        state_blob: state_blob_result?,
    };
    let mut aux_rand32 = [0u8; 32];
    let random_result = getrandom::getrandom(&mut aux_rand32);
    let result = match random_result {
        Ok(()) => sign_wallet_recovery_material_possession_proof(
            &ready_state_blob,
            &challenge,
            &aux_rand32,
        )
        .map_err(js_signer_core_err)
        .and_then(|proof| {
            let challenge_digest = challenge.digest().map_err(|error| {
                js_command_invalid_input_err(format!("Invalid challenge: {error:?}"))
            })?;
            Ok(WalletRecoveryMaterialPossessionProofOutputV1 {
                kind: WALLET_RECOVERY_POSSESSION_PROOF_KIND_V1,
                scheme: proof.scheme.wire_label(),
                signature64_b64u: Base64UrlUnpadded::encode_string(&proof.signature64),
                challenge_digest_b64u: Base64UrlUnpadded::encode_string(&challenge_digest),
                derivation_client_share_public_key33_b64u: Base64UrlUnpadded::encode_string(
                    &challenge.derivation_client_share_public_key33,
                ),
            })
        }),
        Err(error) => Err(js_command_invalid_input_err(format!(
            "Wallet recovery possession worker CSPRNG failed: {error}"
        ))),
    };
    aux_rand32.zeroize();
    result.and_then(|output| serde_json::to_string(&output).map_err(js_command_invalid_input_err))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletRecoveryMaterialPossessionProofInputV1 {
    state_blob_b64u: String,
    challenge: WalletRecoveryMaterialPossessionChallengeInputV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WalletRecoveryMaterialPossessionChallengeInputV1 {
    kind: String,
    wallet_id: String,
    reservation_id: String,
    replacement_id: String,
    key_set_id: String,
    key_handle: String,
    recorded_key_manifest_digest_b64u: String,
    public_capability_digest_b64u: String,
    authority_ref_digest_b64u: String,
    derivation_client_share_public_key33_b64u: String,
    expected_server_generation: String,
    server_nonce_b64u: String,
    expires_at_ms: u64,
}

impl WalletRecoveryMaterialPossessionChallengeInputV1 {
    fn into_protocol(
        self,
    ) -> Result<EcdsaWalletRecoveryMaterialPossessionChallengeV1, SignerCoreError> {
        if self.kind != WALLET_RECOVERY_POSSESSION_CHALLENGE_KIND_V1 {
            return Err(SignerCoreError::invalid_input(
                "wallet recovery possession challenge kind is invalid",
            ));
        }
        Ok(EcdsaWalletRecoveryMaterialPossessionChallengeV1 {
            wallet_id: require_non_empty(self.wallet_id, "challenge.walletId")?,
            reservation_id: require_non_empty(self.reservation_id, "challenge.reservationId")?,
            replacement_id: require_non_empty(self.replacement_id, "challenge.replacementId")?,
            key_set_id: require_non_empty(self.key_set_id, "challenge.keySetId")?,
            key_handle: require_non_empty(self.key_handle, "challenge.keyHandle")?,
            registered_key_manifest_digest32: decode_fixed_base64(
                &self.recorded_key_manifest_digest_b64u,
                "challenge.recordedKeyManifestDigestB64u",
            )?,
            public_capability_digest32: decode_fixed_base64(
                &self.public_capability_digest_b64u,
                "challenge.publicCapabilityDigestB64u",
            )?,
            authority_ref_digest32: decode_fixed_base64(
                &self.authority_ref_digest_b64u,
                "challenge.authorityRefDigestB64u",
            )?,
            derivation_client_share_public_key33: decode_fixed_base64(
                &self.derivation_client_share_public_key33_b64u,
                "challenge.derivationClientSharePublicKey33B64u",
            )?,
            expected_server_generation: require_non_empty(
                self.expected_server_generation,
                "challenge.expectedServerGeneration",
            )?,
            server_nonce32: decode_fixed_base64(
                &self.server_nonce_b64u,
                "challenge.serverNonceB64u",
            )?,
            expires_at_ms: self.expires_at_ms,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct WalletRecoveryMaterialPossessionProofOutputV1 {
    kind: &'static str,
    scheme: &'static str,
    signature64_b64u: String,
    challenge_digest_b64u: String,
    derivation_client_share_public_key33_b64u: String,
}

fn require_non_empty(value: String, field_name: &str) -> Result<String, SignerCoreError> {
    let value = value.trim().to_owned();
    if value.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    Ok(value)
}

fn decode_fixed_base64<const N: usize>(
    value: &str,
    field_name: &str,
) -> Result<[u8; N], SignerCoreError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(SignerCoreError::invalid_input(format!(
            "{field_name} must be non-empty"
        )));
    }
    let decoded = Base64UrlUnpadded::decode_vec(trimmed)
        .map_err(|error| SignerCoreError::decode_error(format!("{field_name}: {error}")))?;
    if Base64UrlUnpadded::encode_string(&decoded) != trimmed {
        return Err(SignerCoreError::decode_error(format!(
            "{field_name} must use canonical base64url"
        )));
    }
    if decoded.len() != N {
        return Err(SignerCoreError::invalid_length(format!(
            "{field_name} must decode to {N} bytes"
        )));
    }
    decoded.try_into().map_err(|_| {
        SignerCoreError::invalid_length(format!("{field_name} must decode to {N} bytes"))
    })
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SignerWorkerErrorWire {
    code: String,
    core_code: String,
    message: String,
}

fn command_core_code_name(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "InvalidInput",
        SignerCoreErrorCode::InvalidLength => "InvalidLength",
        SignerCoreErrorCode::DecodeError => "DecodeError",
        SignerCoreErrorCode::EncodeError => "EncodeError",
        SignerCoreErrorCode::HkdfError => "HkdfError",
        SignerCoreErrorCode::CryptoError => "CryptoError",
        SignerCoreErrorCode::Utf8Error => "Utf8Error",
        SignerCoreErrorCode::Unsupported => "Unsupported",
        SignerCoreErrorCode::Internal => "Internal",
    }
}

fn command_host_code(code: SignerCoreErrorCode) -> &'static str {
    match code {
        SignerCoreErrorCode::InvalidInput => "SIGNER_INVALID_INPUT",
        SignerCoreErrorCode::InvalidLength => "SIGNER_INVALID_LENGTH",
        SignerCoreErrorCode::DecodeError => "SIGNER_DECODE_ERROR",
        SignerCoreErrorCode::EncodeError => "SIGNER_ENCODE_ERROR",
        SignerCoreErrorCode::HkdfError => "SIGNER_KDF_ERROR",
        SignerCoreErrorCode::CryptoError => "SIGNER_CRYPTO_ERROR",
        SignerCoreErrorCode::Utf8Error => "SIGNER_UTF8_ERROR",
        SignerCoreErrorCode::Unsupported => "SIGNER_UNSUPPORTED",
        SignerCoreErrorCode::Internal => "SIGNER_INTERNAL",
    }
}

fn js_command_error_with_codes(code: &str, core_code: &str, message: String) -> JsValue {
    serde_wasm_bindgen::to_value(&SignerWorkerErrorWire {
        code: code.to_owned(),
        core_code: core_code.to_owned(),
        message,
    })
    .unwrap_or_else(|_| JsValue::from_str("SIGNER_INTERNAL: failed to serialize error"))
}

fn js_signer_core_err(error: SignerCoreError) -> JsValue {
    js_command_error_with_codes(
        command_host_code(error.code),
        command_core_code_name(error.code),
        error.message,
    )
}

fn js_command_invalid_input_err(error: impl core::fmt::Display) -> JsValue {
    js_command_error_with_codes("SIGNER_INVALID_INPUT", "InvalidInput", error.to_string())
}

#[cfg(test)]
mod tests {
    use router_ab_ecdsa_client_protocol::{
        EcdsaMaterialActivationRefKindV1, EcdsaMaterialActivationRefV1,
        LinkedDeviceEcdsaSourceSignerIdentityV1, LinkedDeviceEcdsaTargetRecipientPreparationV1,
    };
    use router_ab_ecdsa_derivation::{
        derive_client_share, derive_relayer_share_for_client_public,
        RouterAbEcdsaDerivationStableKeyContext,
    };

    use super::*;

    fn b64<const N: usize>(bytes: &[u8; N]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    fn activation(id: &str) -> EcdsaMaterialActivationRefV1 {
        EcdsaMaterialActivationRefV1 {
            kind: EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
            activation_id: id.to_owned(),
            capability: format!("capability-{id}"),
            material_owner: "wallet-1".to_owned(),
            key_binding: format!("key-binding-{id}"),
            lifecycle_binding: format!("lifecycle-{id}"),
            signing_worker: "worker-1".to_owned(),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn canonical_normal_signing_state(
        activation: &EcdsaMaterialActivationRefV1,
        application_binding_digest_b64u: &str,
        context_binding_b64u: &str,
        client_public_key33_b64u: &str,
        relayer_public_key33_b64u: &str,
        threshold_public_key33_b64u: &str,
        threshold_ethereum_address20_b64u: &str,
        client_share_retry_counter: u32,
        server_share_retry_counter: u32,
        signing_worker_recipient_key: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "kind": "router_ab_ecdsa_derivation_normal_signing_v1",
            "scope": {
                "wallet_id": "wallet-1",
                "ecdsa_threshold_key_id": "ecdsa-key-1",
                "signing_root_id": "root-1",
                "signing_root_version": "1",
                "context": { "application_binding_digest_b64u": application_binding_digest_b64u },
                "public_identity": {
                    "context_binding_b64u": context_binding_b64u,
                    "derivation_client_share_public_key33_b64u": client_public_key33_b64u,
                    "server_public_key33_b64u": relayer_public_key33_b64u,
                    "threshold_public_key33_b64u": threshold_public_key33_b64u,
                    "ethereum_address20_b64u": threshold_ethereum_address20_b64u,
                    "client_share_retry_counter": client_share_retry_counter,
                    "server_share_retry_counter": server_share_retry_counter
                },
                "material_activation": {
                    "kind": "mpc_material_activation_ref",
                    "activation_id": activation.activation_id,
                    "capability": activation.capability,
                    "material_owner": activation.material_owner,
                    "key_binding": activation.key_binding,
                    "lifecycle_binding": activation.lifecycle_binding,
                    "signing_worker": activation.signing_worker
                },
                "signing_worker": {
                    "server_id": "worker-1",
                    "key_epoch": "epoch-1",
                    "recipient_encryption_key": signing_worker_recipient_key
                },
                "activation_epoch": "root-epoch-1"
            }
        })
    }

    #[test]
    fn canonical_activation_receipt_constructs_a_presign_ready_holder() {
        let application_binding_digest = [0x29; 32];
        let context = RouterAbEcdsaDerivationStableKeyContext::new(application_binding_digest);
        let client = derive_client_share(&context, [0x11; 32]).expect("client share");
        let (relayer, identity) = derive_relayer_share_for_client_public(
            &context,
            [0x22; 32],
            &client.derivation_client_share_public_key33,
            client.retry_counter,
        )
        .expect("relayer share");
        let source_activation = activation("source-activation");
        let target_activation = activation("target-activation");
        let client_public_key33_b64u = b64(&client.derivation_client_share_public_key33);
        let relayer_public_key33_b64u = b64(&relayer.relayer_public_key33);
        let threshold_public_key33_b64u = b64(&identity.threshold_public_key33);
        let threshold_ethereum_address20_b64u = b64(&identity.threshold_ethereum_address20);
        let signing_worker_recipient_key = format!("x25519:{}", "09".repeat(32));
        let source_normal_signing = canonical_normal_signing_state(
            &source_activation,
            &b64(&application_binding_digest),
            &b64(&identity.context_binding32),
            &client_public_key33_b64u,
            &relayer_public_key33_b64u,
            &threshold_public_key33_b64u,
            &threshold_ethereum_address20_b64u,
            identity.client_share_retry_counter,
            identity.relayer_share_retry_counter,
            &signing_worker_recipient_key,
        );
        let target_normal_signing = canonical_normal_signing_state(
            &target_activation,
            &b64(&application_binding_digest),
            &b64(&identity.context_binding32),
            &client_public_key33_b64u,
            &relayer_public_key33_b64u,
            &threshold_public_key33_b64u,
            &threshold_ethereum_address20_b64u,
            identity.client_share_retry_counter,
            identity.relayer_share_retry_counter,
            &signing_worker_recipient_key,
        );
        let binding = LinkedDeviceEcdsaSourceContributionBindingV1 {
            link_session_id: "link-1".to_owned(),
            enrollment_id: "enrollment-1".to_owned(),
            source_authority_id: "authority-1".to_owned(),
            source: LinkedDeviceEcdsaSourceSignerIdentityV1 {
                activation: source_activation,
                client_public_key33_b64u: client_public_key33_b64u.clone(),
                relayer_public_key33_b64u: relayer_public_key33_b64u.clone(),
                threshold_public_key33_b64u: threshold_public_key33_b64u.clone(),
                threshold_ethereum_address20_b64u: threshold_ethereum_address20_b64u.clone(),
            },
            target: LinkedDeviceEcdsaTargetRecipientPreparationV1 {
                activation: target_activation,
                target_device_id: "device-2".to_owned(),
                target_factor_verification_digest_b64u: b64(&[0x71; 32]),
                client_recipient_public_key_b64u: b64(&[0x08; 32]),
                signing_worker_recipient_public_key_b64u: b64(&[0x09; 32]),
            },
            target_client_public_key33_b64u: client_public_key33_b64u,
        };
        binding.validate().expect("linked-device binding");
        let receipt_value = serde_json::json!({
            "state": "inactive",
            "binding": binding,
            "sourceDerivation": {
                "applicationBindingDigestB64u": b64(&application_binding_digest),
                "clientShareRetryCounter": identity.client_share_retry_counter,
                "ecdsaThresholdKeyId": "ecdsa-key-1",
                "sourceNormalSigning": source_normal_signing
            },
            "targetRelayerPublicKey33B64u": relayer_public_key33_b64u,
            "thresholdPublicKey33B64u": threshold_public_key33_b64u,
            "thresholdEthereumAddress20B64u": threshold_ethereum_address20_b64u,
            "normalSigning": target_normal_signing
        });
        let receipt: LinkedEcdsaActivationReceiptV1 = serde_json::from_value(receipt_value.clone())
            .expect("canonical activation receipt with normal-signing state");
        validate_linked_ecdsa_normal_signing_receipt(&receipt).expect("receipt public relations");

        let mut epoch_drift: LinkedEcdsaActivationReceiptV1 =
            serde_json::from_value(receipt_value.clone()).expect("epoch-drift receipt");
        epoch_drift.normal_signing.scope.activation_epoch = "root-epoch-2".to_owned();
        assert!(validate_linked_ecdsa_normal_signing_receipt(&epoch_drift)
            .expect_err("activation epoch drift must fail")
            .contains("exact active authority"));

        let mut public_key_drift: LinkedEcdsaActivationReceiptV1 =
            serde_json::from_value(receipt_value.clone()).expect("public-key-drift receipt");
        public_key_drift
            .normal_signing
            .scope
            .public_identity
            .server_public_key33_b64u =
            b64(&ecdsa_lane_client_public_key_from_share32_v1([0x33; 32])
                .expect("drift public key"));
        assert!(
            validate_linked_ecdsa_normal_signing_receipt(&public_key_drift)
                .expect_err("target public identity drift must fail")
                .contains("target binding")
        );

        let mut recipient_drift: LinkedEcdsaActivationReceiptV1 =
            serde_json::from_value(receipt_value.clone()).expect("recipient-drift receipt");
        recipient_drift
            .normal_signing
            .scope
            .signing_worker
            .recipient_encryption_key = format!("x25519:{}", "0a".repeat(32));
        assert!(
            validate_linked_ecdsa_normal_signing_receipt(&recipient_drift)
                .expect_err("SigningWorker recipient drift must fail")
                .contains("target binding")
        );

        let holder = EcdsaLinkedHolderMaterialV1::new(
            &client.x_client32,
            &serde_json::to_string(&receipt_value).expect("receipt JSON"),
        )
        .expect("linked holder material");
        holder
            .start_presign(&identity.threshold_public_key33, "presign-session-1")
            .expect("presign-ready holder");
    }
}
