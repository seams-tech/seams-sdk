use router_ab_ecdsa_client_protocol::{
    build_ecdsa_post_registration_request_v1, build_ecdsa_registration_request_v1,
    derive_ecdsa_client_ephemeral_keypair_v1, EcdsaClientEphemeralKeyPairV1,
    EcdsaClientProtocolError, EcdsaDeriverRoleV1, EcdsaPostRegistrationCeremonyV1,
    EcdsaPostRegistrationHeaderInputV1, EcdsaPostRegistrationHeaderV1,
    EcdsaPostRegistrationLifecycleV1, EcdsaPostRegistrationLifecycleWireV1,
    EcdsaPostRegistrationOperationV1, EcdsaPostRegistrationRecipientV1,
    EcdsaPostRegistrationRequestV1, EcdsaPublicIdentityInputV1, EcdsaPublicIdentityV1,
    EcdsaRegistrationEncryptedEnvelopeV1, EcdsaRegistrationHeaderInputV1,
    EcdsaRegistrationHeaderV1, EcdsaRegistrationLifecycleV1, EcdsaRegistrationLifecycleWireV1,
    EcdsaRegistrationPurposeV1, EcdsaRegistrationRecipientKeysV1, EcdsaRegistrationRequestV1,
    EcdsaRegistrationSealSeedsV1, EcdsaRegistrationSignerSetV1, EcdsaSelectedServerIdentityV1,
    EcdsaSignerEnvelopePublicKeyV1, EcdsaSignerIdentityV1, EcdsaStableKeyContextV1,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;
use zeroize::Zeroize;

use crate::ecdsa_prf_finalizer::finalize_encrypted_client_proof_bundles_v1;

/// Rust-owned client ceremony whose X25519 private key never crosses WASM.
#[wasm_bindgen]
pub struct RouterAbEcdsaClientCeremonyV1 {
    keypair: Option<EcdsaClientEphemeralKeyPairV1>,
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
        })
    }

    /// Returns the only key material allowed outside the opaque object.
    pub fn public_key(&self) -> Result<String, JsValue> {
        Ok(self.active_keypair()?.public_key().to_owned())
    }

    /// Builds a strict wallet-registration or wallet-add-signer request.
    pub fn build_registration_request(&self, input_json: &str) -> Result<String, JsValue> {
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
            derivation_client_share_public_key33_b64u: input
                .derivation_client_share_public_key33_b64u
                .clone(),
            client_share_retry_counter: input.client_share_retry_counter,
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
        serialize_registration_request(input, request, self.active_keypair()?.public_key())
    }

    /// Builds a strict explicit client-export request.
    pub fn build_explicit_export_request(&self, input_json: &str) -> Result<String, JsValue> {
        let input: ExplicitExportRequestInputV1 = parse_json(input_json)?;
        let header = self.post_registration_header(
            &input.common,
            EcdsaPostRegistrationCeremonyV1::ExplicitExport,
            EcdsaPostRegistrationRecipientV1::ClientProofBundles {
                client_ephemeral_public_key: self.active_keypair()?.public_key().to_owned(),
            },
            EcdsaPostRegistrationOperationV1::ExplicitExport {
                authorization_digest_b64u: input.export_authorization_digest_b64u.clone(),
                nonce: input.export_nonce.clone(),
            },
        )?;
        let request = self.build_post_request(header, &input.common.deriver_recipient_keys)?;
        serialize_export_request(input, request, self.active_keypair()?.public_key())
    }

    /// Builds a strict same-root client recovery request.
    pub fn build_recovery_request(&self, input_json: &str) -> Result<String, JsValue> {
        let input: RecoveryRequestInputV1 = parse_json(input_json)?;
        let header = self.post_registration_header(
            &input.common,
            EcdsaPostRegistrationCeremonyV1::Recovery,
            EcdsaPostRegistrationRecipientV1::ClientProofBundles {
                client_ephemeral_public_key: self.active_keypair()?.public_key().to_owned(),
            },
            EcdsaPostRegistrationOperationV1::Recovery {
                authorization_digest_b64u: input.recovery_authorization_digest_b64u.clone(),
                nonce: input.recovery_nonce.clone(),
            },
        )?;
        let request = self.build_post_request(header, &input.common.deriver_recipient_keys)?;
        serialize_recovery_request(input, request, self.active_keypair()?.public_key())
    }

    /// Builds a strict SigningWorker activation-refresh request.
    pub fn build_activation_refresh_request(&self, input_json: &str) -> Result<String, JsValue> {
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
            },
        )?;
        let request = self.build_post_request(header, &input.common.deriver_recipient_keys)?;
        serialize_refresh_request(input, request)
    }

    /// Opens encrypted A/B client proof bundles and returns only the finalized output.
    pub fn finalize_encrypted_proof_bundles(&self, input_json: &str) -> Result<String, JsValue> {
        finalize_encrypted_client_proof_bundles_v1(
            input_json,
            self.active_keypair()?.private_key_bytes(),
        )
        .map_err(js_error)
    }

    /// Explicitly destroys the worker-local key before normal object collection.
    pub fn close(&mut self) {
        self.keypair.take();
    }
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
    derivation_client_share_public_key33_b64u: String,
    client_share_retry_counter: u32,
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ExplicitExportRequestInputV1 {
    #[serde(flatten)]
    common: PostRegistrationCommonInputV1,
    export_authorization_digest_b64u: String,
    export_nonce: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRequestInputV1 {
    #[serde(flatten)]
    common: PostRegistrationCommonInputV1,
    recovery_authorization_digest_b64u: String,
    recovery_nonce: String,
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
}

#[derive(Serialize)]
struct DigestWireV1 {
    bytes: [u8; 32],
}

#[derive(Serialize)]
struct EncryptedPayloadWireV1 {
    bytes: Vec<u8>,
}

#[derive(Serialize)]
struct EnvelopeWireV1 {
    recipient_role: &'static str,
    header_digest: DigestWireV1,
    aad_digest: DigestWireV1,
    ciphertext: EncryptedPayloadWireV1,
}

#[derive(Serialize)]
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
    derivation_client_share_public_key33_b64u: String,
    client_share_retry_counter: u32,
    deriver_a_envelope: EnvelopeWireV1,
    deriver_b_envelope: EnvelopeWireV1,
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
    export_authorization_digest_b64u: String,
    export_nonce: String,
    expires_at_ms: u64,
    deriver_a_export_envelope: EnvelopeWireV1,
    deriver_b_export_envelope: EnvelopeWireV1,
}

#[derive(Serialize)]
struct RecoveryRequestWireV1 {
    context: ContextInputV1,
    lifecycle: LifecycleInputV1,
    public_identity: PublicIdentityInputV1,
    signer_set: SignerSetInputV1,
    router_id: String,
    client_id: String,
    client_ephemeral_public_key: String,
    recovery_authorization_digest_b64u: String,
    recovery_nonce: String,
    expires_at_ms: u64,
    deriver_a_recovery_envelope: EnvelopeWireV1,
    deriver_b_recovery_envelope: EnvelopeWireV1,
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
    expires_at_ms: u64,
    deriver_a_refresh_envelope: EnvelopeWireV1,
    deriver_b_refresh_envelope: EnvelopeWireV1,
}

fn parse_context(input: &ContextInputV1) -> Result<EcdsaStableKeyContextV1, JsValue> {
    EcdsaStableKeyContextV1::new(input.application_binding_digest_b64u.clone())
        .map_err(protocol_error)
        .map_err(js_error)
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
        recipient_role: input.recipient_role().wire_label(),
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
        derivation_client_share_public_key33_b64u: input.derivation_client_share_public_key33_b64u,
        client_share_retry_counter: input.client_share_retry_counter,
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
        export_authorization_digest_b64u: input.export_authorization_digest_b64u,
        export_nonce: input.export_nonce,
        expires_at_ms: input.common.expires_at_ms,
        deriver_a_export_envelope: envelope_wire(request.deriver_a_envelope()),
        deriver_b_export_envelope: envelope_wire(request.deriver_b_envelope()),
    })
}

fn serialize_recovery_request(
    input: RecoveryRequestInputV1,
    request: EcdsaPostRegistrationRequestV1,
    public_key: &str,
) -> Result<String, JsValue> {
    serialize_json(&RecoveryRequestWireV1 {
        context: input.common.context,
        lifecycle: input.common.lifecycle,
        public_identity: input.common.public_identity,
        signer_set: input.common.signer_set,
        router_id: input.common.router_id,
        client_id: input.common.client_id,
        client_ephemeral_public_key: public_key.to_owned(),
        recovery_authorization_digest_b64u: input.recovery_authorization_digest_b64u,
        recovery_nonce: input.recovery_nonce,
        expires_at_ms: input.common.expires_at_ms,
        deriver_a_recovery_envelope: envelope_wire(request.deriver_a_envelope()),
        deriver_b_recovery_envelope: envelope_wire(request.deriver_b_envelope()),
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

    fn test_lifecycle(ceremony: EcdsaPostRegistrationCeremonyV1) -> LifecycleInputV1 {
        let (work_kind, primitive_request_kind, lifecycle_id, root_share_epoch) = match ceremony {
            EcdsaPostRegistrationCeremonyV1::ExplicitExport => {
                ("key_export", "export", "export-lifecycle-1", "root-epoch-1")
            }
            EcdsaPostRegistrationCeremonyV1::Recovery => (
                "recovery",
                "recovery",
                "recovery-lifecycle-1",
                "root-epoch-1",
            ),
            EcdsaPostRegistrationCeremonyV1::ActivationRefresh => (
                "server_share_refresh",
                "refresh",
                "refresh-lifecycle-1",
                "root-epoch-2",
            ),
        };
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

    fn test_post_common(
        ceremony: EcdsaPostRegistrationCeremonyV1,
    ) -> PostRegistrationCommonInputV1 {
        PostRegistrationCommonInputV1 {
            context: test_context(),
            lifecycle: test_lifecycle(ceremony),
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
            derivation_client_share_public_key33_b64u: compressed_public_key(0x02, 0x11),
            client_share_retry_counter: 5,
            deriver_recipient_keys: test_recipient_keys(),
        };
        serde_json::to_string(&input).expect("registration input JSON")
    }

    fn parse_output(output: String) -> Value {
        serde_json::from_str(&output).expect("ceremony output JSON")
    }

    #[test]
    fn opaque_ceremony_builds_all_strict_request_branches_without_private_material() {
        let ceremony = test_ceremony();
        let client_public_key = ceremony
            .active_keypair()
            .expect("active ceremony")
            .public_key()
            .to_owned();

        let registration = parse_output(
            ceremony
                .build_registration_request(&registration_request_json())
                .expect("registration request"),
        );
        assert_eq!(
            registration["client_ephemeral_public_key"],
            client_public_key
        );

        let export_input = ExplicitExportRequestInputV1 {
            common: test_post_common(EcdsaPostRegistrationCeremonyV1::ExplicitExport),
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

        let recovery_input = RecoveryRequestInputV1 {
            common: test_post_common(EcdsaPostRegistrationCeremonyV1::Recovery),
            recovery_authorization_digest_b64u: b64u(&[0x52; 32]),
            recovery_nonce: "recovery-nonce-1".to_owned(),
        };
        let recovery = parse_output(
            ceremony
                .build_recovery_request(
                    &serde_json::to_string(&recovery_input).expect("recovery input JSON"),
                )
                .expect("recovery request"),
        );
        assert_eq!(recovery["client_ephemeral_public_key"], client_public_key);

        let signing_worker_public_key = x25519_public_key([0x81; 32]);
        let refresh_input = ActivationRefreshRequestInputV1 {
            common: test_post_common(EcdsaPostRegistrationCeremonyV1::ActivationRefresh),
            signing_worker_ephemeral_public_key: signing_worker_public_key.clone(),
            refresh_authorization_digest_b64u: b64u(&[0x53; 32]),
            refresh_nonce: "refresh-nonce-1".to_owned(),
            previous_activation_epoch: "root-epoch-1".to_owned(),
            next_activation_epoch: "root-epoch-2".to_owned(),
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

        let all_outputs = [registration, export, recovery, refresh]
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
