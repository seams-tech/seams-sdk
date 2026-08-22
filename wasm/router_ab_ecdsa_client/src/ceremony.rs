use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_ecdsa_client_protocol::{
    build_ecdsa_post_registration_request_v1, build_ecdsa_registration_request_v1,
    decode_ecdsa_signer_envelope_hpke_payload_v1, derive_ecdsa_client_ephemeral_keypair_v1,
    open_ecdsa_signer_envelope_v1, open_ecdsa_signing_worker_export_share_v1,
    EcdsaClientEphemeralKeyPairV1, EcdsaClientProtocolError, EcdsaDeriverRoleV1,
    EcdsaMaterialActivationRefKindV1, EcdsaMaterialActivationRefV1,
    EcdsaPostRegistrationCeremonyV1, EcdsaPostRegistrationHeaderInputV1,
    EcdsaPostRegistrationHeaderV1, EcdsaPostRegistrationLifecycleV1,
    EcdsaPostRegistrationLifecycleWireV1, EcdsaPostRegistrationOperationV1,
    EcdsaPostRegistrationRecipientV1, EcdsaPostRegistrationRequestV1, EcdsaPublicIdentityInputV1,
    EcdsaPublicIdentityV1, EcdsaRegistrationEncryptedEnvelopeV1, EcdsaRegistrationHeaderInputV1,
    EcdsaRegistrationHeaderV1, EcdsaRegistrationLifecycleV1, EcdsaRegistrationLifecycleWireV1,
    EcdsaRegistrationPurposeV1, EcdsaRegistrationRecipientKeysV1, EcdsaRegistrationRequestV1,
    EcdsaRegistrationSealSeedsV1, EcdsaRegistrationSignerSetV1, EcdsaSelectedServerIdentityV1,
    EcdsaSignerEnvelopePublicKeyV1, EcdsaSignerIdentityV1, EcdsaSigningWorkerExportShareBindingV1,
    EcdsaSigningWorkerExportShareEnvelopeV1, EcdsaStableKeyContextV1,
};
use router_ab_ecdsa_derivation::RouterAbEcdsaDerivationStableKeyContext;
use serde::{Deserialize, Serialize};
use signer_core::ecdsa_role_local_client::{
    reconstruct_ecdsa_role_local_export, EcdsaRoleLocalExportPublicFacts,
    EcdsaRoleLocalExportReconstructionInput, EcdsaRoleLocalReadyStateBlob,
};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::client_proof_verifier::finalize_encrypted_client_proof_output_v1;
use crate::encoders::base64_url_encode;

/// Rust-owned client ceremony whose X25519 private key never crosses WASM.
#[wasm_bindgen]
pub struct RouterAbEcdsaClientCeremonyV1 {
    keypair: Option<EcdsaClientEphemeralKeyPairV1>,
    registration_binding: Option<RegistrationBindingV1>,
    explicit_export_request_digest: Option<[u8; 32]>,
    activation_refresh_request_digest: Option<[u8; 32]>,
}

#[wasm_bindgen]
impl RouterAbEcdsaClientCeremonyV1 {
    /// Creates a ceremony with fresh worker-local X25519 material.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<RouterAbEcdsaClientCeremonyV1, JsValue> {
        let mut seed = random_seed().map_err(js_error)?;
        let keypair = derive_ecdsa_client_ephemeral_keypair_v1(seed).map_err(protocol_error);
        seed.zeroize();
        Ok(Self {
            keypair: Some(keypair.map_err(js_error)?),
            registration_binding: None,
            explicit_export_request_digest: None,
            activation_refresh_request_digest: None,
        })
    }

    /// Recreates a ceremony around the exact private recipient key retained
    /// by a browser worker during request preparation.
    #[wasm_bindgen(js_name = fromRecipientPrivateKey)]
    pub fn from_recipient_private_key(
        recipient_private_key: &[u8],
    ) -> Result<RouterAbEcdsaClientCeremonyV1, JsValue> {
        let key_material = parse_32(recipient_private_key, "ECDSA client recipient private key")?;
        let keypair = EcdsaClientEphemeralKeyPairV1::from_private_key_bytes(key_material)
            .map_err(protocol_error)
            .map_err(js_error)?;
        Ok(Self {
            keypair: Some(keypair),
            registration_binding: None,
            explicit_export_request_digest: None,
            activation_refresh_request_digest: None,
        })
    }

    /// Returns the only key material allowed outside the opaque object.
    pub fn public_key(&self) -> Result<String, JsValue> {
        Ok(self.active_keypair()?.public_key().to_owned())
    }

    /// Builds a strict wallet-registration or wallet-add-signer request.
    pub fn build_registration_request(&mut self, input_json: &str) -> Result<String, JsValue> {
        if self.registration_binding.is_some() {
            return Err(JsValue::from_str(
                "Router A/B ECDSA registration request was already built",
            ));
        }
        let input: RegistrationRequestInputV1 = parse_json(input_json)?;
        let purpose = EcdsaRegistrationPurposeV1::from_wire_label(&input.registration_purpose)
            .map_err(protocol_error)
            .map_err(js_error)?;
        let context = parse_context(&input.context)?;
        let lifecycle = EcdsaRegistrationLifecycleV1::from_wire(input.lifecycle.clone().into())
            .map_err(protocol_error)
            .map_err(js_error)?;
        let signer_set = parse_signer_set(&input.signer_set)?;
        let header = EcdsaRegistrationHeaderV1::new(EcdsaRegistrationHeaderInputV1 {
            registration_purpose: purpose,
            context,
            lifecycle,
            signer_set,
            router_id: input.router_id.clone(),
            client_id: input.client_id.clone(),
            client_ephemeral_public_key: self.active_keypair()?.public_key().to_owned(),
            replay_nonce: input.replay_nonce.clone(),
            expires_at_ms: input.expires_at_ms,
        })
        .map_err(protocol_error)
        .map_err(js_error)?;
        let request = build_ecdsa_registration_request_v1(
            header,
            parse_recipient_keys(&input.deriver_recipient_keys)?,
            random_seal_seeds()?,
        )
        .map_err(protocol_error)
        .map_err(js_error)?;
        let registration_binding = RegistrationBindingV1 {
            application_binding_digest_b64u: input.context.application_binding_digest_b64u.clone(),
            request_digest_b64u: base64_url_encode(
                &request.digest().map_err(protocol_error).map_err(js_error)?,
            ),
            transcript_digest_b64u: base64_url_encode(
                &request
                    .header()
                    .transcript_digest()
                    .map_err(protocol_error)
                    .map_err(js_error)?,
            ),
        };
        let serialized =
            serialize_registration_request(input, request, self.active_keypair()?.public_key())?;
        self.registration_binding = Some(registration_binding);
        Ok(serialized)
    }

    /// Returns public registration digests required by the bootstrap owner.
    pub fn registration_binding(&self) -> Result<String, JsValue> {
        let binding = self.registration_binding.as_ref().ok_or_else(|| {
            JsValue::from_str("Router A/B ECDSA registration request was not built")
        })?;
        serde_json::to_string(binding).map_err(|error| js_error(error.to_string()))
    }

    /// Builds a strict explicit client-export request.
    pub fn build_explicit_export_request(&mut self, input_json: &str) -> Result<String, JsValue> {
        let input: ExplicitExportRequestInputV1 = parse_json(input_json)?;
        let header = self.post_registration_header(
            &input.common,
            EcdsaPostRegistrationCeremonyV1::ExplicitExport,
            EcdsaPostRegistrationRecipientV1::ClientProofBundles {
                client_ephemeral_public_key: self.active_keypair()?.public_key().to_owned(),
            },
            EcdsaPostRegistrationOperationV1::ExplicitExport {
                authorization_kind: input.authorization.kind_label().to_owned(),
                authorization_id: input
                    .authorization
                    .authorization_id()
                    .map_err(|error| JsValue::from_str(error))?
                    .to_owned(),
                material_activation: parse_material_activation(&input.material_activation)?,
                authorization_digest_b64u: input.export_authorization_digest_b64u.clone(),
                nonce: input.export_nonce.clone(),
            },
        )?;
        let request = self.build_post_request(header, &input.common.deriver_recipient_keys)?;
        self.explicit_export_request_digest =
            Some(request.digest().map_err(protocol_error).map_err(js_error)?);
        serialize_export_request(input, request, self.active_keypair()?.public_key())
    }

    /// Builds a strict SigningWorker activation-refresh request.
    pub fn build_activation_refresh_request(
        &mut self,
        input_json: &str,
    ) -> Result<String, JsValue> {
        let input: ActivationRefreshRequestInputV1 = parse_json(input_json)?;
        let header = self.post_registration_header(
            &input.common,
            EcdsaPostRegistrationCeremonyV1::ActivationRefresh,
            EcdsaPostRegistrationRecipientV1::SigningWorkerActivation {
                signing_worker_ephemeral_public_key: input
                    .signing_worker_ephemeral_public_key
                    .clone(),
            },
            EcdsaPostRegistrationOperationV1::ActivationRefresh {
                authorization_digest_b64u: input.refresh_authorization_digest_b64u.clone(),
                nonce: input.refresh_nonce.clone(),
                previous_activation_epoch: input.previous_activation_epoch.clone(),
                next_activation_epoch: input.next_activation_epoch.clone(),
                material_activation: parse_material_activation(&input.material_activation)?,
            },
        )?;
        let request = self.build_post_request(header, &input.common.deriver_recipient_keys)?;
        self.activation_refresh_request_digest =
            Some(request.digest().map_err(protocol_error).map_err(js_error)?);
        serialize_refresh_request(input, request)
    }

    /// Verifies strict client proof bundles and discards the protocol output inside wasm.
    pub fn verify_encrypted_proof_bundles(&self, input_json: &str) -> Result<(), JsValue> {
        let mut output = finalize_encrypted_client_proof_output_v1(
            input_json,
            self.active_keypair()?.private_key_bytes(),
        )
        .map_err(js_error)?;
        output.zeroize();
        Ok(())
    }

    /// Opens the two committed role envelopes for one exact registration
    /// request. The browser X25519 private key stays inside this ceremony.
    pub fn open_committed_role_envelopes(
        &self,
        input_json: &str,
    ) -> Result<WasmOrdinaryEcdsaClientMaterialV1, JsValue> {
        let input: OrdinaryRoleEnvelopeOpenInputV1 = parse_json(input_json)?;
        if input.material_activation_id.trim().is_empty()
            || input.material_activation_id.trim() != input.material_activation_id
        {
            return Err(JsValue::from_str(
                "ECDSA committed role envelope activation id is invalid",
            ));
        }
        let keypair = self.active_keypair()?;
        if input.registration_request.client_ephemeral_public_key != keypair.public_key() {
            return Err(JsValue::from_str(
                "ECDSA committed role envelopes target another client ceremony",
            ));
        }
        let purpose = EcdsaRegistrationPurposeV1::from_wire_label(
            &input.registration_request.registration_purpose,
        )
        .map_err(protocol_error)
        .map_err(js_error)?;
        let header = EcdsaRegistrationHeaderV1::new(EcdsaRegistrationHeaderInputV1 {
            registration_purpose: purpose,
            context: parse_context(&input.registration_request.context)?,
            lifecycle: EcdsaRegistrationLifecycleV1::from_wire(
                input.registration_request.lifecycle.clone().into(),
            )
            .map_err(protocol_error)
            .map_err(js_error)?,
            signer_set: parse_signer_set(&input.registration_request.signer_set)?,
            router_id: input.registration_request.router_id.clone(),
            client_id: input.registration_request.client_id.clone(),
            client_ephemeral_public_key: input.registration_request.client_ephemeral_public_key,
            replay_nonce: input.registration_request.replay_nonce.clone(),
            expires_at_ms: input.registration_request.expires_at_ms,
        })
        .map_err(protocol_error)
        .map_err(js_error)?;
        let deriver_a = open_committed_role_envelope(
            &header,
            &input.deriver_a_client_package,
            EcdsaDeriverRoleV1::A,
            keypair.public_key(),
            keypair.private_key_bytes(),
        )?;
        let deriver_b = open_committed_role_envelope(
            &header,
            &input.deriver_b_client_package,
            EcdsaDeriverRoleV1::B,
            keypair.public_key(),
            keypair.private_key_bytes(),
        )?;
        let transcript = header
            .transcript_digest()
            .map_err(protocol_error)
            .map_err(js_error)?;
        Ok(WasmOrdinaryEcdsaClientMaterialV1 {
            deriver_a: Some(deriver_a),
            deriver_b: Some(deriver_b),
            transcript,
            activation_id: input.material_activation_id,
        })
    }

    /// Returns the canonical explicit-export request digest held by this ceremony.
    pub fn explicit_export_request_digest_b64u(&self) -> Result<String, JsValue> {
        let digest = self.explicit_export_request_digest.ok_or_else(|| {
            JsValue::from_str("Router A/B ECDSA explicit export request was not built")
        })?;
        Ok(base64_url_encode(&digest))
    }

    /// Returns the canonical activation-refresh request digest held by this ceremony.
    pub fn activation_refresh_request_digest_b64u(&self) -> Result<String, JsValue> {
        let digest = self.activation_refresh_request_digest.ok_or_else(|| {
            JsValue::from_str("Router A/B ECDSA activation-refresh request was not built")
        })?;
        Ok(base64_url_encode(&digest))
    }

    /// Opens the exact SigningWorker share and reconstructs the final key entirely in Rust.
    pub fn finalize_explicit_export(&self, input_json: &str) -> Result<String, JsValue> {
        let input: ExplicitExportFinalizationInputV1 = parse_json(input_json)?;
        let mut share = open_ecdsa_signing_worker_export_share_v1(
            &input.signing_worker_export,
            &input.expected_binding,
            self.active_keypair()?.private_key_bytes(),
        )
        .map_err(protocol_error)
        .map_err(js_error)?;
        let public_facts = input.public_facts.into_core()?;
        let state_blob = Base64UrlUnpadded::decode_vec(&input.state_blob_b64u)
            .map_err(|error| js_error(format!("stateBlobB64u is invalid: {error}")))?;
        let artifact =
            reconstruct_ecdsa_role_local_export(EcdsaRoleLocalExportReconstructionInput {
                ready_state_blob: EcdsaRoleLocalReadyStateBlob { state_blob },
                public_facts,
                server_export_share32: share,
            })
            .map_err(|error| js_error(error.to_string()))?;
        let output = ExplicitExportArtifactOutputV1 {
            public_key_hex: hex_prefixed(&artifact.public_key33),
            private_key_hex: hex_prefixed(&artifact.private_key32),
            ethereum_address: hex_prefixed(&artifact.ethereum_address20),
        };
        share.zeroize();
        serde_json::to_string(&output).map_err(|error| js_error(error.to_string()))
    }

    /// Explicitly destroys the worker-local key before normal object collection.
    pub fn close(&mut self) {
        self.registration_binding.take();
        self.explicit_export_request_digest.take();
        self.activation_refresh_request_digest.take();
        self.keypair.take();
    }
}

/// Worker-owned plaintext produced by opening one committed ECDSA role pair.
/// The two role payloads stay in WASM until the worker consumes the material.
#[wasm_bindgen]
pub struct WasmOrdinaryEcdsaClientMaterialV1 {
    deriver_a: Option<Zeroizing<Vec<u8>>>,
    deriver_b: Option<Zeroizing<Vec<u8>>>,
    transcript: [u8; 32],
    activation_id: String,
}

#[wasm_bindgen]
impl WasmOrdinaryEcdsaClientMaterialV1 {
    /// Returns the exact registration transcript authenticated by both roles.
    pub fn transcript(&self) -> Vec<u8> {
        self.transcript.to_vec()
    }

    /// Returns the exact planned activation id carried by the worker input.
    pub fn activation_id(&self) -> String {
        self.activation_id.clone()
    }

    /// Consumes both opened role payloads for the worker's factor-sealing
    /// boundary. The returned bytes are held only by the worker caller.
    pub fn take_client_material(&mut self) -> Result<Vec<u8>, JsValue> {
        let deriver_a = self
            .deriver_a
            .take()
            .ok_or_else(|| JsValue::from_str("ECDSA role material was consumed"))?;
        let deriver_b = self
            .deriver_b
            .take()
            .ok_or_else(|| JsValue::from_str("ECDSA role material was consumed"))?;
        let a_len = u32::try_from(deriver_a.len())
            .map_err(|_| JsValue::from_str("ECDSA Deriver A material is too large"))?;
        let b_len = u32::try_from(deriver_b.len())
            .map_err(|_| JsValue::from_str("ECDSA Deriver B material is too large"))?;
        let mut output = Vec::with_capacity(8 + deriver_a.len() + deriver_b.len());
        output.extend_from_slice(&a_len.to_be_bytes());
        output.extend_from_slice(&deriver_a);
        output.extend_from_slice(&b_len.to_be_bytes());
        output.extend_from_slice(&deriver_b);
        Ok(output)
    }

    /// Zeroizes any role material retained by this handle.
    pub fn destroy(&mut self) {
        if let Some(mut deriver_a) = self.deriver_a.take() {
            deriver_a.zeroize();
        }
        if let Some(mut deriver_b) = self.deriver_b.take() {
            deriver_b.zeroize();
        }
        self.activation_id.zeroize();
    }
}

fn open_committed_role_envelope(
    header: &EcdsaRegistrationHeaderV1,
    envelope: &EnvelopeWireV1,
    expected_role: EcdsaDeriverRoleV1,
    expected_recipient_public_key: &str,
    recipient_private_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, JsValue> {
    let aad = header
        .role_aad(expected_role)
        .map_err(protocol_error)
        .map_err(js_error)?;
    if envelope.recipient_role != expected_role.wire_label()
        || envelope.header_digest.bytes
            != header.digest().map_err(protocol_error).map_err(js_error)?
        || envelope.aad_digest.bytes != aad.digest().map_err(protocol_error).map_err(js_error)?
    {
        return Err(JsValue::from_str(
            "ECDSA committed role envelope public binding does not match registration",
        ));
    }
    let payload = decode_ecdsa_signer_envelope_hpke_payload_v1(&envelope.ciphertext.bytes)
        .map_err(protocol_error)
        .map_err(js_error)?;
    let expected_identity = match expected_role {
        EcdsaDeriverRoleV1::A => header.signer_set().signer_a(),
        EcdsaDeriverRoleV1::B => header.signer_set().signer_b(),
    };
    if payload.recipient_role != expected_role
        || payload.key_epoch != expected_identity.key_epoch
        || payload.recipient_public_key != expected_recipient_public_key
        || payload.aad_digest != envelope.aad_digest.bytes
    {
        return Err(JsValue::from_str(
            "ECDSA committed role envelope role or AAD digest is invalid",
        ));
    }
    let plaintext = open_ecdsa_signer_envelope_v1(&payload, &aad, recipient_private_key)
        .map_err(protocol_error)
        .map_err(js_error)?;
    header
        .validate_deriver_plaintext_v1(expected_role, &plaintext)
        .map_err(protocol_error)
        .map_err(js_error)?;
    Ok(Zeroizing::new(plaintext))
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExplicitExportFinalizationInputV1 {
    signing_worker_export: EcdsaSigningWorkerExportShareEnvelopeV1,
    expected_binding: EcdsaSigningWorkerExportShareBindingV1,
    state_blob_b64u: String,
    public_facts: ExplicitExportPublicFactsInputV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExplicitExportPublicFactsInputV1 {
    application_binding_digest_b64u: String,
    context_binding32_b64u: String,
    derivation_client_share_public_key33_b64u: String,
    relayer_public_key33_b64u: String,
    group_public_key33_b64u: String,
    ethereum_address: String,
}

impl ExplicitExportPublicFactsInputV1 {
    fn into_core(self) -> Result<EcdsaRoleLocalExportPublicFacts, JsValue> {
        let context = RouterAbEcdsaDerivationStableKeyContext::new(decode_fixed_base64::<32>(
            &self.application_binding_digest_b64u,
            "applicationBindingDigestB64u",
        )?);
        context
            .validate()
            .map_err(|error| js_error(error.message))?;
        Ok(EcdsaRoleLocalExportPublicFacts {
            context,
            context_binding32: decode_fixed_base64(
                &self.context_binding32_b64u,
                "contextBinding32B64u",
            )?,
            derivation_client_share_public_key33: decode_fixed_base64(
                &self.derivation_client_share_public_key33_b64u,
                "derivationClientSharePublicKey33B64u",
            )?,
            relayer_public_key33: decode_fixed_base64(
                &self.relayer_public_key33_b64u,
                "relayerPublicKey33B64u",
            )?,
            group_public_key33: decode_fixed_base64(
                &self.group_public_key33_b64u,
                "groupPublicKey33B64u",
            )?,
            ethereum_address20: decode_hex_fixed::<20>(&self.ethereum_address, "ethereumAddress")?,
        })
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExplicitExportArtifactOutputV1 {
    public_key_hex: String,
    private_key_hex: String,
    ethereum_address: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RegistrationBindingV1 {
    application_binding_digest_b64u: String,
    request_digest_b64u: String,
    transcript_digest_b64u: String,
}

impl RouterAbEcdsaClientCeremonyV1 {
    fn active_keypair(&self) -> Result<&EcdsaClientEphemeralKeyPairV1, JsValue> {
        self.keypair
            .as_ref()
            .ok_or_else(|| JsValue::from_str("Router A/B ECDSA client ceremony is closed"))
    }

    fn post_registration_header(
        &self,
        input: &PostRegistrationCommonInputV1,
        ceremony: EcdsaPostRegistrationCeremonyV1,
        recipient: EcdsaPostRegistrationRecipientV1,
        operation: EcdsaPostRegistrationOperationV1,
    ) -> Result<EcdsaPostRegistrationHeaderV1, JsValue> {
        let context = parse_context(&input.context)?;
        let public_identity = parse_public_identity(&context, &input.public_identity)?;
        let lifecycle =
            EcdsaPostRegistrationLifecycleV1::from_wire(ceremony, input.lifecycle.clone().into())
                .map_err(protocol_error)
                .map_err(js_error)?;
        EcdsaPostRegistrationHeaderV1::new(EcdsaPostRegistrationHeaderInputV1 {
            context,
            lifecycle,
            public_identity,
            signer_set: parse_signer_set(&input.signer_set)?,
            router_id: input.router_id.clone(),
            client_id: input.client_id.clone(),
            recipient,
            operation,
            expires_at_ms: input.expires_at_ms,
        })
        .map_err(protocol_error)
        .map_err(js_error)
    }

    fn build_post_request(
        &self,
        header: EcdsaPostRegistrationHeaderV1,
        recipient_keys: &RecipientKeysInputV1,
    ) -> Result<EcdsaPostRegistrationRequestV1, JsValue> {
        build_ecdsa_post_registration_request_v1(
            header,
            parse_recipient_keys(recipient_keys)?,
            random_seal_seeds()?,
        )
        .map_err(protocol_error)
        .map_err(js_error)
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ContextInputV1 {
    application_binding_digest_b64u: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LifecycleInputV1 {
    lifecycle_id: String,
    work_kind: String,
    primitive_request_kind: String,
    root_share_epoch: String,
    account_id: String,
    session_id: String,
    signer_set_id: String,
    selected_server_id: String,
}

impl From<LifecycleInputV1> for EcdsaRegistrationLifecycleWireV1 {
    fn from(input: LifecycleInputV1) -> Self {
        Self {
            lifecycle_id: input.lifecycle_id,
            work_kind: input.work_kind,
            primitive_request_kind: input.primitive_request_kind,
            root_share_epoch: input.root_share_epoch,
            account_id: input.account_id,
            session_id: input.session_id,
            signer_set_id: input.signer_set_id,
            selected_server_id: input.selected_server_id,
        }
    }
}

impl From<LifecycleInputV1> for EcdsaPostRegistrationLifecycleWireV1 {
    fn from(input: LifecycleInputV1) -> Self {
        Self {
            lifecycle_id: input.lifecycle_id,
            work_kind: input.work_kind,
            primitive_request_kind: input.primitive_request_kind,
            root_share_epoch: input.root_share_epoch,
            account_id: input.account_id,
            session_id: input.session_id,
            signer_set_id: input.signer_set_id,
            selected_server_id: input.selected_server_id,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignerIdentityInputV1 {
    role: String,
    signer_id: String,
    key_epoch: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServerIdentityInputV1 {
    server_id: String,
    key_epoch: String,
    recipient_encryption_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignerSetInputV1 {
    signer_set_id: String,
    policy: String,
    signer_a: SignerIdentityInputV1,
    signer_b: SignerIdentityInputV1,
    selected_server: ServerIdentityInputV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecipientKeyInputV1 {
    role: String,
    key_epoch: String,
    public_key: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecipientKeysInputV1 {
    deriver_a: RecipientKeyInputV1,
    deriver_b: RecipientKeyInputV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PublicIdentityInputV1 {
    context_binding_b64u: String,
    derivation_client_share_public_key33_b64u: String,
    server_public_key33_b64u: String,
    threshold_public_key33_b64u: String,
    ethereum_address20_b64u: String,
    client_share_retry_counter: u32,
    server_share_retry_counter: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RegistrationRequestInputV1 {
    registration_purpose: String,
    context: ContextInputV1,
    lifecycle: LifecycleInputV1,
    signer_set: SignerSetInputV1,
    router_id: String,
    client_id: String,
    replay_nonce: String,
    expires_at_ms: u64,
    deriver_recipient_keys: RecipientKeysInputV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PostRegistrationCommonInputV1 {
    context: ContextInputV1,
    lifecycle: LifecycleInputV1,
    public_identity: PublicIdentityInputV1,
    signer_set: SignerSetInputV1,
    router_id: String,
    client_id: String,
    expires_at_ms: u64,
    deriver_recipient_keys: RecipientKeysInputV1,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum NormalSigningAuthorizationInputV1 {
    ReusableWalletSession {
        wallet_session_id: String,
    },
    OperationStepUp {
        #[serde(skip_serializing)]
        authorization_id: String,
    },
}

impl NormalSigningAuthorizationInputV1 {
    fn kind_label(&self) -> &'static str {
        match self {
            Self::ReusableWalletSession { .. } => "reusable_wallet_session",
            Self::OperationStepUp { .. } => "operation_step_up",
        }
    }

    fn authorization_id(&self) -> Result<&str, &'static str> {
        match self {
            Self::ReusableWalletSession { wallet_session_id } => Ok(wallet_session_id),
            Self::OperationStepUp { authorization_id } => Ok(authorization_id),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExplicitExportRequestInputV1 {
    #[serde(flatten)]
    common: PostRegistrationCommonInputV1,
    authorization: NormalSigningAuthorizationInputV1,
    material_activation: MaterialActivationRefInputV1,
    export_authorization_digest_b64u: String,
    export_nonce: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct MaterialActivationRefInputV1 {
    kind: String,
    activation_id: String,
    capability: String,
    material_owner: String,
    key_binding: String,
    lifecycle_binding: String,
    signing_worker: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ActivationRefreshRequestInputV1 {
    #[serde(flatten)]
    common: PostRegistrationCommonInputV1,
    signing_worker_ephemeral_public_key: String,
    refresh_authorization_digest_b64u: String,
    refresh_nonce: String,
    previous_activation_epoch: String,
    next_activation_epoch: String,
    material_activation: MaterialActivationRefInputV1,
}

#[derive(Deserialize, Serialize)]
struct DigestWireV1 {
    bytes: [u8; 32],
}

#[derive(Deserialize, Serialize)]
struct EncryptedPayloadWireV1 {
    bytes: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct EnvelopeWireV1 {
    recipient_role: String,
    header_digest: DigestWireV1,
    aad_digest: DigestWireV1,
    ciphertext: EncryptedPayloadWireV1,
}

#[derive(Deserialize, Serialize)]
struct RegistrationRequestWireV1 {
    registration_purpose: String,
    context: ContextInputV1,
    lifecycle: LifecycleInputV1,
    signer_set: SignerSetInputV1,
    router_id: String,
    client_id: String,
    client_ephemeral_public_key: String,
    replay_nonce: String,
    expires_at_ms: u64,
    deriver_a_envelope: EnvelopeWireV1,
    deriver_b_envelope: EnvelopeWireV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OrdinaryRoleEnvelopeOpenInputV1 {
    registration_request: RegistrationRequestWireV1,
    material_activation_id: String,
    deriver_a_client_package: EnvelopeWireV1,
    deriver_b_client_package: EnvelopeWireV1,
}

#[derive(Serialize)]
struct ExplicitExportRequestWireV1 {
    context: ContextInputV1,
    lifecycle: LifecycleInputV1,
    public_identity: PublicIdentityInputV1,
    signer_set: SignerSetInputV1,
    router_id: String,
    client_id: String,
    client_ephemeral_public_key: String,
    authorization: NormalSigningAuthorizationInputV1,
    material_activation: MaterialActivationRefInputV1,
    export_authorization_digest_b64u: String,
    export_nonce: String,
    expires_at_ms: u64,
    deriver_a_export_envelope: EnvelopeWireV1,
    deriver_b_export_envelope: EnvelopeWireV1,
}

#[derive(Serialize)]
struct ActivationRefreshRequestWireV1 {
    context: ContextInputV1,
    lifecycle: LifecycleInputV1,
    public_identity: PublicIdentityInputV1,
    signer_set: SignerSetInputV1,
    router_id: String,
    client_id: String,
    signing_worker_ephemeral_public_key: String,
    refresh_authorization_digest_b64u: String,
    refresh_nonce: String,
    previous_activation_epoch: String,
    next_activation_epoch: String,
    material_activation: MaterialActivationRefInputV1,
    expires_at_ms: u64,
    deriver_a_refresh_envelope: EnvelopeWireV1,
    deriver_b_refresh_envelope: EnvelopeWireV1,
}

fn parse_context(input: &ContextInputV1) -> Result<EcdsaStableKeyContextV1, JsValue> {
    EcdsaStableKeyContextV1::new(input.application_binding_digest_b64u.clone())
        .map_err(protocol_error)
        .map_err(js_error)
}

fn parse_material_activation(
    input: &MaterialActivationRefInputV1,
) -> Result<EcdsaMaterialActivationRefV1, JsValue> {
    if input.kind != "mpc_material_activation_ref" {
        return Err(JsValue::from_str(
            "material_activation.kind must be mpc_material_activation_ref",
        ));
    }
    Ok(EcdsaMaterialActivationRefV1 {
        kind: EcdsaMaterialActivationRefKindV1::MpcMaterialActivationRef,
        activation_id: input.activation_id.clone(),
        capability: input.capability.clone(),
        material_owner: input.material_owner.clone(),
        key_binding: input.key_binding.clone(),
        lifecycle_binding: input.lifecycle_binding.clone(),
        signing_worker: input.signing_worker.clone(),
    })
}

fn parse_public_identity(
    context: &EcdsaStableKeyContextV1,
    input: &PublicIdentityInputV1,
) -> Result<EcdsaPublicIdentityV1, JsValue> {
    EcdsaPublicIdentityV1::new(
        context,
        EcdsaPublicIdentityInputV1 {
            context_binding_b64u: input.context_binding_b64u.clone(),
            derivation_client_share_public_key33_b64u: input
                .derivation_client_share_public_key33_b64u
                .clone(),
            server_public_key33_b64u: input.server_public_key33_b64u.clone(),
            threshold_public_key33_b64u: input.threshold_public_key33_b64u.clone(),
            ethereum_address20_b64u: input.ethereum_address20_b64u.clone(),
            client_share_retry_counter: input.client_share_retry_counter,
            server_share_retry_counter: input.server_share_retry_counter,
        },
    )
    .map_err(protocol_error)
    .map_err(js_error)
}

fn parse_signer_set(input: &SignerSetInputV1) -> Result<EcdsaRegistrationSignerSetV1, JsValue> {
    if input.policy != "all_2" {
        return Err(JsValue::from_str("signer_set.policy must be all_2"));
    }
    EcdsaRegistrationSignerSetV1::new(
        input.signer_set_id.clone(),
        parse_signer_identity(&input.signer_a, EcdsaDeriverRoleV1::A)?,
        parse_signer_identity(&input.signer_b, EcdsaDeriverRoleV1::B)?,
        EcdsaSelectedServerIdentityV1 {
            server_id: input.selected_server.server_id.clone(),
            key_epoch: input.selected_server.key_epoch.clone(),
            recipient_encryption_key: input.selected_server.recipient_encryption_key.clone(),
        },
    )
    .map_err(protocol_error)
    .map_err(js_error)
}

fn parse_signer_identity(
    input: &SignerIdentityInputV1,
    role: EcdsaDeriverRoleV1,
) -> Result<EcdsaSignerIdentityV1, JsValue> {
    if input.role != role.wire_label() {
        return Err(JsValue::from_str("signer identity role is invalid"));
    }
    Ok(EcdsaSignerIdentityV1 {
        role,
        signer_id: input.signer_id.clone(),
        key_epoch: input.key_epoch.clone(),
    })
}

fn parse_recipient_keys(
    input: &RecipientKeysInputV1,
) -> Result<EcdsaRegistrationRecipientKeysV1, JsValue> {
    Ok(EcdsaRegistrationRecipientKeysV1 {
        deriver_a: parse_recipient_key(&input.deriver_a, EcdsaDeriverRoleV1::A)?,
        deriver_b: parse_recipient_key(&input.deriver_b, EcdsaDeriverRoleV1::B)?,
    })
}

fn parse_recipient_key(
    input: &RecipientKeyInputV1,
    role: EcdsaDeriverRoleV1,
) -> Result<EcdsaSignerEnvelopePublicKeyV1, JsValue> {
    if input.role != role.wire_label() {
        return Err(JsValue::from_str("recipient key role is invalid"));
    }
    Ok(EcdsaSignerEnvelopePublicKeyV1 {
        role,
        key_epoch: input.key_epoch.clone(),
        public_key: input.public_key.clone(),
    })
}

fn envelope_wire(input: &EcdsaRegistrationEncryptedEnvelopeV1) -> EnvelopeWireV1 {
    EnvelopeWireV1 {
        recipient_role: input.recipient_role().wire_label().to_owned(),
        header_digest: DigestWireV1 {
            bytes: input.header_digest(),
        },
        aad_digest: DigestWireV1 {
            bytes: input.aad_digest(),
        },
        ciphertext: EncryptedPayloadWireV1 {
            bytes: input.ciphertext().to_vec(),
        },
    }
}

fn serialize_registration_request(
    input: RegistrationRequestInputV1,
    request: EcdsaRegistrationRequestV1,
    public_key: &str,
) -> Result<String, JsValue> {
    serialize_json(&RegistrationRequestWireV1 {
        registration_purpose: input.registration_purpose,
        context: input.context,
        lifecycle: input.lifecycle,
        signer_set: input.signer_set,
        router_id: input.router_id,
        client_id: input.client_id,
        client_ephemeral_public_key: public_key.to_owned(),
        replay_nonce: input.replay_nonce,
        expires_at_ms: input.expires_at_ms,
        deriver_a_envelope: envelope_wire(request.deriver_a_envelope()),
        deriver_b_envelope: envelope_wire(request.deriver_b_envelope()),
    })
}

fn serialize_export_request(
    input: ExplicitExportRequestInputV1,
    request: EcdsaPostRegistrationRequestV1,
    public_key: &str,
) -> Result<String, JsValue> {
    serialize_json(&ExplicitExportRequestWireV1 {
        context: input.common.context,
        lifecycle: input.common.lifecycle,
        public_identity: input.common.public_identity,
        signer_set: input.common.signer_set,
        router_id: input.common.router_id,
        client_id: input.common.client_id,
        client_ephemeral_public_key: public_key.to_owned(),
        authorization: input.authorization,
        material_activation: input.material_activation,
        export_authorization_digest_b64u: input.export_authorization_digest_b64u,
        export_nonce: input.export_nonce,
        expires_at_ms: input.common.expires_at_ms,
        deriver_a_export_envelope: envelope_wire(request.deriver_a_envelope()),
        deriver_b_export_envelope: envelope_wire(request.deriver_b_envelope()),
    })
}

fn serialize_refresh_request(
    input: ActivationRefreshRequestInputV1,
    request: EcdsaPostRegistrationRequestV1,
) -> Result<String, JsValue> {
    serialize_json(&ActivationRefreshRequestWireV1 {
        context: input.common.context,
        lifecycle: input.common.lifecycle,
        public_identity: input.common.public_identity,
        signer_set: input.common.signer_set,
        router_id: input.common.router_id,
        client_id: input.common.client_id,
        signing_worker_ephemeral_public_key: input.signing_worker_ephemeral_public_key,
        refresh_authorization_digest_b64u: input.refresh_authorization_digest_b64u,
        refresh_nonce: input.refresh_nonce,
        previous_activation_epoch: input.previous_activation_epoch,
        next_activation_epoch: input.next_activation_epoch,
        material_activation: input.material_activation,
        expires_at_ms: input.common.expires_at_ms,
        deriver_a_refresh_envelope: envelope_wire(request.deriver_a_envelope()),
        deriver_b_refresh_envelope: envelope_wire(request.deriver_b_envelope()),
    })
}

fn random_seed() -> Result<[u8; 32], String> {
    let mut seed = [0_u8; 32];
    getrandom::getrandom(&mut seed).map_err(|error| format!("worker CSPRNG failed: {error}"))?;
    Ok(seed)
}

fn random_seal_seeds() -> Result<EcdsaRegistrationSealSeedsV1, JsValue> {
    Ok(EcdsaRegistrationSealSeedsV1 {
        deriver_a: random_seed().map_err(js_error)?,
        deriver_b: random_seed().map_err(js_error)?,
    })
}

fn parse_json<T>(input_json: &str) -> Result<T, JsValue>
where
    T: for<'de> Deserialize<'de>,
{
    serde_json::from_str(input_json)
        .map_err(|error| JsValue::from_str(&format!("request JSON is invalid: {error}")))
}

fn serialize_json<T>(value: &T) -> Result<String, JsValue>
where
    T: Serialize,
{
    serde_json::to_string(value)
        .map_err(|error| JsValue::from_str(&format!("request JSON serialization failed: {error}")))
}

fn decode_fixed_base64<const N: usize>(value: &str, field_name: &str) -> Result<[u8; N], JsValue> {
    let decoded = Base64UrlUnpadded::decode_vec(value.trim())
        .map_err(|error| js_error(format!("{field_name} is invalid base64url: {error}")))?;
    decoded
        .try_into()
        .map_err(|_| js_error(format!("{field_name} must decode to {N} bytes")))
}

fn parse_32(value: &[u8], field_name: &str) -> Result<[u8; 32], JsValue> {
    value
        .try_into()
        .map_err(|_| js_error(format!("{field_name} must contain exactly 32 bytes")))
}

fn decode_hex_fixed<const N: usize>(value: &str, field_name: &str) -> Result<[u8; N], JsValue> {
    let value = value
        .trim()
        .strip_prefix("0x")
        .ok_or_else(|| js_error(format!("{field_name} must be 0x-prefixed")))?;
    if value.len() != N * 2 {
        return Err(js_error(format!("{field_name} must contain {N} bytes")));
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| js_error(format!("{field_name} is invalid hex")))?;
    }
    Ok(output)
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

fn protocol_error(error: EcdsaClientProtocolError) -> String {
    format!("Router A/B ECDSA client protocol failed: {error:?}")
}

fn js_error(error: String) -> JsValue {
    JsValue::from_str(&error)
}

#[cfg(test)]
mod tests {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use serde_json::Value;

    use super::*;

    const SIGNER_SET_ID: &str = "ecdsa-signers-v1";
    const SERVER_ID: &str = "signing-worker-1";

    fn b64u<const N: usize>(bytes: &[u8; N]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    fn compressed_public_key(prefix: u8, value: u8) -> String {
        let mut bytes = [value; 33];
        bytes[0] = prefix;
        b64u(&bytes)
    }

    fn x25519_public_key(seed: [u8; 32]) -> String {
        derive_ecdsa_client_ephemeral_keypair_v1(seed)
            .expect("test X25519 keypair")
            .public_key()
            .to_owned()
    }

    fn test_ceremony() -> RouterAbEcdsaClientCeremonyV1 {
        RouterAbEcdsaClientCeremonyV1 {
            keypair: Some(
                derive_ecdsa_client_ephemeral_keypair_v1([0x91; 32])
                    .expect("client ceremony keypair"),
            ),
            registration_binding: None,
            activation_refresh_request_digest: None,
            explicit_export_request_digest: None,
        }
    }

    fn test_context() -> ContextInputV1 {
        ContextInputV1 {
            application_binding_digest_b64u: b64u(&[0x29; 32]),
        }
    }

    fn test_signer_set() -> SignerSetInputV1 {
        SignerSetInputV1 {
            signer_set_id: SIGNER_SET_ID.to_owned(),
            policy: "all_2".to_owned(),
            signer_a: SignerIdentityInputV1 {
                role: "signer_a".to_owned(),
                signer_id: "deriver-a-1".to_owned(),
                key_epoch: "deriver-a-epoch-3".to_owned(),
            },
            signer_b: SignerIdentityInputV1 {
                role: "signer_b".to_owned(),
                signer_id: "deriver-b-1".to_owned(),
                key_epoch: "deriver-b-epoch-4".to_owned(),
            },
            selected_server: ServerIdentityInputV1 {
                server_id: SERVER_ID.to_owned(),
                key_epoch: "signing-worker-epoch-2".to_owned(),
                recipient_encryption_key: x25519_public_key([0x73; 32]),
            },
        }
    }

    fn test_recipient_keys() -> RecipientKeysInputV1 {
        RecipientKeysInputV1 {
            deriver_a: RecipientKeyInputV1 {
                role: "signer_a".to_owned(),
                key_epoch: "deriver-a-epoch-3".to_owned(),
                public_key: x25519_public_key([0xa1; 32]),
            },
            deriver_b: RecipientKeyInputV1 {
                role: "signer_b".to_owned(),
                key_epoch: "deriver-b-epoch-4".to_owned(),
                public_key: x25519_public_key([0xb2; 32]),
            },
        }
    }

    fn test_lifecycle(
        lifecycle_id: &str,
        work_kind: &str,
        primitive_request_kind: &str,
        root_share_epoch: &str,
    ) -> LifecycleInputV1 {
        LifecycleInputV1 {
            lifecycle_id: lifecycle_id.to_owned(),
            work_kind: work_kind.to_owned(),
            primitive_request_kind: primitive_request_kind.to_owned(),
            root_share_epoch: root_share_epoch.to_owned(),
            account_id: "wallet-1".to_owned(),
            session_id: "wallet-session-1".to_owned(),
            signer_set_id: SIGNER_SET_ID.to_owned(),
            selected_server_id: SERVER_ID.to_owned(),
        }
    }

    fn test_public_identity() -> PublicIdentityInputV1 {
        let context = EcdsaStableKeyContextV1::new(b64u(&[0x29; 32])).expect("test context");
        PublicIdentityInputV1 {
            context_binding_b64u: b64u(&context.binding_digest().expect("context binding")),
            derivation_client_share_public_key33_b64u: compressed_public_key(0x02, 0x11),
            server_public_key33_b64u: compressed_public_key(0x03, 0x22),
            threshold_public_key33_b64u: compressed_public_key(0x02, 0x33),
            ethereum_address20_b64u: b64u(&[0x44; 20]),
            client_share_retry_counter: 5,
            server_share_retry_counter: 7,
        }
    }

    fn test_post_common(lifecycle: LifecycleInputV1) -> PostRegistrationCommonInputV1 {
        PostRegistrationCommonInputV1 {
            context: test_context(),
            lifecycle,
            public_identity: test_public_identity(),
            signer_set: test_signer_set(),
            router_id: "router-1".to_owned(),
            client_id: "browser-client-1".to_owned(),
            expires_at_ms: 8_000_000,
            deriver_recipient_keys: test_recipient_keys(),
        }
    }

    fn registration_request_json() -> String {
        let input = RegistrationRequestInputV1 {
            registration_purpose: "wallet_registration".to_owned(),
            context: test_context(),
            lifecycle: LifecycleInputV1 {
                lifecycle_id: "registration-lifecycle-1".to_owned(),
                work_kind: "registration_prepare".to_owned(),
                primitive_request_kind: "registration".to_owned(),
                root_share_epoch: "root-epoch-1".to_owned(),
                account_id: "wallet-1".to_owned(),
                session_id: "registration-session-1".to_owned(),
                signer_set_id: SIGNER_SET_ID.to_owned(),
                selected_server_id: SERVER_ID.to_owned(),
            },
            signer_set: test_signer_set(),
            router_id: "router-1".to_owned(),
            client_id: "browser-client-1".to_owned(),
            replay_nonce: "registration-nonce-1".to_owned(),
            expires_at_ms: 8_000_000,
            deriver_recipient_keys: test_recipient_keys(),
        };
        serde_json::to_string(&input).expect("registration input JSON")
    }

    fn parse_output(output: String) -> Value {
        serde_json::from_str(&output).expect("ceremony output JSON")
    }

    #[test]
    fn operation_step_up_authorization_serializes_without_local_identifier() {
        let value = serde_json::to_value(NormalSigningAuthorizationInputV1::OperationStepUp {
            authorization_id: b64u(&[0x52; 32]),
        })
        .expect("operation step-up authorization JSON");
        assert_eq!(value, serde_json::json!({ "kind": "operation_step_up" }));
        assert!(serde_json::from_value::<NormalSigningAuthorizationInputV1>(value).is_err());
    }

    #[test]
    fn opaque_ceremony_builds_all_strict_request_branches_without_private_material() {
        let mut ceremony = test_ceremony();
        let client_public_key = ceremony
            .active_keypair()
            .expect("active ceremony")
            .public_key()
            .to_owned();
        assert_eq!(client_public_key.len(), 71);
        assert!(client_public_key.starts_with("x25519:"));
        assert!(client_public_key["x25519:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));

        let registration = parse_output(
            ceremony
                .build_registration_request(&registration_request_json())
                .expect("registration request"),
        );
        assert_eq!(
            registration["client_ephemeral_public_key"],
            client_public_key
        );
        let registration_binding = parse_output(
            ceremony
                .registration_binding()
                .expect("registration binding"),
        );
        assert_eq!(
            registration_binding["applicationBindingDigestB64u"],
            test_context().application_binding_digest_b64u,
        );
        assert_eq!(
            registration_binding["requestDigestB64u"]
                .as_str()
                .expect("request digest")
                .len(),
            43,
        );
        assert_eq!(
            registration_binding["transcriptDigestB64u"]
                .as_str()
                .expect("transcript digest")
                .len(),
            43,
        );

        let export_input = ExplicitExportRequestInputV1 {
            common: test_post_common(test_lifecycle(
                "export-lifecycle-1",
                "key_export",
                "export",
                "root-epoch-1",
            )),
            authorization: NormalSigningAuthorizationInputV1::ReusableWalletSession {
                wallet_session_id: "wallet-session-1".to_owned(),
            },
            material_activation: MaterialActivationRefInputV1 {
                kind: "mpc_material_activation_ref".to_owned(),
                activation_id: "material-activation-1".to_owned(),
                capability: "capability-1".to_owned(),
                material_owner: "wallet-1".to_owned(),
                key_binding: "key-binding-1".to_owned(),
                lifecycle_binding: "export-lifecycle-1".to_owned(),
                signing_worker: SERVER_ID.to_owned(),
            },
            export_authorization_digest_b64u: b64u(&[0x51; 32]),
            export_nonce: "export-nonce-1".to_owned(),
        };
        let export = parse_output(
            ceremony
                .build_explicit_export_request(
                    &serde_json::to_string(&export_input).expect("export input JSON"),
                )
                .expect("export request"),
        );
        assert_eq!(export["client_ephemeral_public_key"], client_public_key);
        assert_eq!(export["authorization"]["kind"], "reusable_wallet_session");
        assert_eq!(
            export["authorization"]["wallet_session_id"],
            "wallet-session-1"
        );
        assert_eq!(
            export["material_activation"]["activation_id"],
            "material-activation-1"
        );

        let operation_step_up_input = ExplicitExportRequestInputV1 {
            common: test_post_common(test_lifecycle(
                "export-step-up-lifecycle-1",
                "key_export",
                "export",
                "root-epoch-1",
            )),
            authorization: NormalSigningAuthorizationInputV1::OperationStepUp {
                authorization_id: b64u(&[0x52; 32]),
            },
            material_activation: MaterialActivationRefInputV1 {
                kind: "mpc_material_activation_ref".to_owned(),
                activation_id: "material-activation-1".to_owned(),
                capability: "capability-1".to_owned(),
                material_owner: "wallet-1".to_owned(),
                key_binding: "key-binding-1".to_owned(),
                lifecycle_binding: "export-step-up-lifecycle-1".to_owned(),
                signing_worker: SERVER_ID.to_owned(),
            },
            export_authorization_digest_b64u: b64u(&[0x53; 32]),
            export_nonce: "export-step-up-nonce-1".to_owned(),
        };
        let operation_step_up_export = parse_output(
            ceremony
                .build_explicit_export_request(
                    &serde_json::to_string(&operation_step_up_input)
                        .expect("operation step-up export input JSON"),
                )
                .expect("operation step-up export request"),
        );
        assert_eq!(
            operation_step_up_export["authorization"]["kind"],
            "operation_step_up"
        );
        assert!(operation_step_up_export["authorization"]
            .as_object()
            .expect("operation step-up authorization object")
            .get("authorization_id")
            .is_none());

        let signing_worker_public_key = x25519_public_key([0x81; 32]);
        let refresh_input = ActivationRefreshRequestInputV1 {
            common: test_post_common(test_lifecycle(
                "refresh-lifecycle-1",
                "server_share_refresh",
                "refresh",
                "root-epoch-2",
            )),
            signing_worker_ephemeral_public_key: signing_worker_public_key.clone(),
            refresh_authorization_digest_b64u: b64u(&[0x53; 32]),
            refresh_nonce: "refresh-nonce-1".to_owned(),
            previous_activation_epoch: "root-epoch-1".to_owned(),
            next_activation_epoch: "root-epoch-2".to_owned(),
            material_activation: MaterialActivationRefInputV1 {
                kind: "mpc_material_activation_ref".to_owned(),
                activation_id: "material-activation-2".to_owned(),
                capability: "capability-2".to_owned(),
                material_owner: "wallet-1".to_owned(),
                key_binding: "key-binding-2".to_owned(),
                lifecycle_binding: "refresh-lifecycle-1".to_owned(),
                signing_worker: SERVER_ID.to_owned(),
            },
        };
        let refresh = parse_output(
            ceremony
                .build_activation_refresh_request(
                    &serde_json::to_string(&refresh_input).expect("refresh input JSON"),
                )
                .expect("refresh request"),
        );
        assert_eq!(
            refresh["signing_worker_ephemeral_public_key"],
            signing_worker_public_key
        );
        assert!(refresh.get("client_ephemeral_public_key").is_none());

        let all_outputs = [registration, export, refresh]
            .into_iter()
            .map(|value| value.to_string())
            .collect::<String>()
            .to_ascii_lowercase();
        assert!(!all_outputs.contains("private"));
    }

    #[test]
    fn close_drops_the_only_owned_ephemeral_keypair() {
        let mut ceremony = test_ceremony();
        assert!(ceremony.keypair.is_some());
        ceremony.close();
        assert!(ceremony.keypair.is_none());
    }
}
