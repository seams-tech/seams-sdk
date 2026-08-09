use router_ab_core::{
    RouterAbEd25519YaoActivationAdmissionReceiptV1, RouterAbEd25519YaoActivationResultV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbEd25519YaoExportAdmissionReceiptV1,
    RouterAbEd25519YaoExportResultV1,
};
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    complete_client_activation_v1, complete_client_export_v1, create_client_signing_share_v1,
    prepare_client_export_from_custody_seed_v1, prepare_client_recovery_from_custody_seed_v1,
    prepare_client_registration_from_custody_seed_v1,
    ClientActivationEntropyV1, ClientActivationStateV1, ClientExportStateV1,
    ClientSigningRequestV1,
};
use crate::{
    ed25519_local_material_binding_v1, import_activated_client_material_v1,
    open_wallet_custody_ed25519_material_v1, seal_activated_client_material_v1,
    LocalMaterialSealDomainV1, OpenWalletCustodyEd25519MaterialV1,
};
use signer_core::near_ed25519_recovery::{
    build_near_ed25519_seed_export_artifact_v1, encode_near_ed25519_public_key_from_seed,
};
use signer_core::near_threshold_ed25519::CommitmentsWire;
use signer_core::passkey_custody::PasskeyCustodyEnvelopeBindingV1;
use signer_core::passkey_custody::open_wallet_custody_seed_envelope_v1;

/// One-use explicit export session opened from the wallet custody envelope.
///
/// The factor authorizes and opens the envelope. The custody seed and the
/// derived Ed25519 root remain inside this Rust boundary for the full export
/// protocol preparation.
#[wasm_bindgen]
pub struct WasmCustodyEnvelopeExportSessionV1 {
    execute_request_json: String,
    state: Option<ClientExportStateV1>,
}

#[wasm_bindgen]
impl WasmCustodyEnvelopeExportSessionV1 {
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        factor_secret: &[u8],
        envelope_binding_json: &str,
        envelope_nonce: &[u8],
        envelope_ciphertext: &[u8],
        envelope_aad_hash: &[u8],
        envelope_ciphertext_digest: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmCustodyEnvelopeExportSessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoExportAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let envelope_binding =
            serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(envelope_binding_json)
                .map_err(js_error)?;
        let factor_secret = Zeroizing::new(parse_32(factor_secret, "custody factor secret")?);
        let (seed, _) = open_wallet_custody_seed_envelope_v1(
            &*factor_secret,
            &envelope_binding,
            envelope_nonce,
            envelope_ciphertext,
            envelope_aad_hash,
            envelope_ciphertext_digest,
        )
        .map_err(js_error)?;
        let custody_seed = Zeroizing::new(
            seed.as_slice()
                .try_into()
                .map_err(|_| JsValue::from_str("wallet custody seed must contain 32 bytes"))?,
        );
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_client_export_from_custody_seed_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            &*custody_seed,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    pub fn complete(&mut self, result_json: &str) -> Result<WasmExportedEd25519SeedV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoExportResultV1>(result_json)
            .map_err(js_error)?;
        let state = self
            .state
            .take()
            .ok_or_else(|| JsValue::from_str("Ed25519 Yao export session was consumed"))?;
        let seed = complete_client_export_v1(state, &result).map_err(js_error)?;
        Ok(WasmExportedEd25519SeedV1 {
            seed: Some(Zeroizing::new(seed.into_bytes())),
        })
    }
}

/// One-use wallet-custody registration session containing only Client-owned secret state.
#[wasm_bindgen]
pub struct WasmCustodySeedRegistrationSessionV1 {
    execute_request_json: String,
    state: Option<ClientActivationStateV1>,
}

#[wasm_bindgen]
impl WasmCustodySeedRegistrationSessionV1 {
    /// Prepares binding-specific A/B inputs from the wallet custody seed.
    #[wasm_bindgen(constructor)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        custody_seed: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmCustodySeedRegistrationSessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoActivationAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let custody_seed = Zeroizing::new(parse_32(custody_seed, "wallet custody seed")?);
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_client_registration_from_custody_seed_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            &*custody_seed,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    /// Returns the canonical opaque Router execution request JSON.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Opens and verifies a terminal Router result exactly once.
    pub fn complete(&mut self, result_json: &str) -> Result<WasmActivatedClientV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(result_json)
            .map_err(js_error)?;
        let state = self
            .state
            .take()
            .ok_or_else(|| JsValue::from_str("Ed25519 Yao registration session was consumed"))?;
        let activated = complete_client_activation_v1(state, &result).map_err(js_error)?;
        Ok(WasmActivatedClientV1 {
            client_scalar_share: Zeroizing::new(*activated.client_scalar_share()),
            registered_public_key: activated.registered_public_key(),
            state_epoch: activated.state_epoch(),
        })
    }
}

/// One-use wallet-custody recovery session containing only Client-owned secret state.
#[wasm_bindgen]
pub struct WasmCustodySeedRecoverySessionV1 {
    execute_request_json: String,
    state: Option<ClientActivationStateV1>,
}

#[wasm_bindgen]
impl WasmCustodySeedRecoverySessionV1 {
    /// Prepares seed-derived recovery inputs bound to the registered public key.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        admission_json: &str,
        application_json: &str,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        custody_seed: &[u8],
        expected_registered_public_key: &[u8],
        recipient_key_material: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<WasmCustodySeedRecoverySessionV1, JsValue> {
        let admission =
            serde_json::from_str::<RouterAbEd25519YaoActivationAdmissionReceiptV1>(admission_json)
                .map_err(js_error)?;
        let application =
            serde_json::from_str::<RouterAbEd25519YaoApplicationBindingFactsV1>(application_json)
                .map_err(js_error)?;
        let custody_seed = Zeroizing::new(parse_32(custody_seed, "wallet custody seed")?);
        let expected_registered_public_key = parse_32(
            expected_registered_public_key,
            "expected registered public key",
        )?;
        let recipient_key_material =
            Zeroizing::new(parse_32(recipient_key_material, "recipient key material")?);
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let entropy = ClientActivationEntropyV1::new(
            *recipient_key_material,
            *deriver_a_seal_seed,
            *deriver_b_seal_seed,
        )
        .map_err(js_error)?;
        let prepared = prepare_client_recovery_from_custody_seed_v1(
            &admission,
            &application,
            [client_participant_id, signing_worker_participant_id],
            &*custody_seed,
            expected_registered_public_key,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, state) = prepared.into_parts();
        let execute_request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        Ok(Self {
            execute_request_json,
            state: Some(state),
        })
    }

    /// Returns the canonical opaque Router execution request JSON.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Opens and verifies a terminal recovery result exactly once.
    pub fn complete(&mut self, result_json: &str) -> Result<WasmActivatedClientV1, JsValue> {
        let result = serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(result_json)
            .map_err(js_error)?;
        let state = self
            .state
            .take()
            .ok_or_else(|| JsValue::from_str("Ed25519 Yao recovery session was consumed"))?;
        let activated = complete_client_activation_v1(state, &result).map_err(js_error)?;
        Ok(WasmActivatedClientV1 {
            client_scalar_share: Zeroizing::new(*activated.client_scalar_share()),
            registered_public_key: activated.registered_public_key(),
            state_epoch: activated.state_epoch(),
        })
    }
}

/// One-use verified Ed25519 seed returned to the secure export viewer boundary.
#[wasm_bindgen]
pub struct WasmExportedEd25519SeedV1 {
    seed: Option<Zeroizing<[u8; 32]>>,
}

#[wasm_bindgen]
impl WasmExportedEd25519SeedV1 {
    /// Builds the standard verified NEAR export artifact exactly once.
    pub fn take_export_artifact_json(&mut self) -> Result<String, JsValue> {
        let mut seed = self
            .seed
            .take()
            .ok_or_else(|| JsValue::from_str("Ed25519 Yao exported seed was consumed"))?;
        let expected_public_key = encode_near_ed25519_public_key_from_seed(*seed);
        let artifact = build_near_ed25519_seed_export_artifact_v1(*seed, &expected_public_key)
            .map_err(js_error)?;
        seed.zeroize();
        serde_json::to_string(&artifact).map_err(js_error)
    }
}

/// Verified Client activation material retained inside the browser WASM boundary.
#[wasm_bindgen]
pub struct WasmActivatedClientV1 {
    client_scalar_share: Zeroizing<[u8; 32]>,
    registered_public_key: [u8; 32],
    state_epoch: u64,
}

#[wasm_bindgen]
impl WasmActivatedClientV1 {
    /// Returns the verified 32-byte Ed25519 public key.
    pub fn registered_public_key(&self) -> Vec<u8> {
        self.registered_public_key.to_vec()
    }

    /// Returns the activated SigningWorker state epoch.
    pub fn state_epoch(&self) -> u64 {
        self.state_epoch
    }

    /// Authenticates and encrypts the active Client material for same-device rehydration.
    pub fn seal_local_material(
        &self,
        passkey_prf_first: &[u8],
        binding: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let wrapping_secret = Zeroizing::new(parse_32(passkey_prf_first, "passkey PRF.first")?);
        seal_activated_client_local_material(
            self,
            &wrapping_secret,
            binding,
            nonce,
            LocalMaterialSealDomainV1::PasskeyPrfFirst,
        )
    }

    /// Authenticates and encrypts active Client material under Email OTP enrollment custody.
    pub fn seal_email_otp_local_material(
        &self,
        owned_enrollment_secret32: &[u8],
        binding: &[u8],
        nonce: &[u8],
    ) -> Result<Vec<u8>, JsValue> {
        let wrapping_secret = Zeroizing::new(parse_32(
            owned_enrollment_secret32,
            "Email OTP enrollment secret",
        )?);
        seal_activated_client_local_material(
            self,
            &wrapping_secret,
            binding,
            nonce,
            LocalMaterialSealDomainV1::EmailOtpEnrollment,
        )
    }

    /// Opens a same-device envelope and re-verifies its public threshold relation.
    #[allow(clippy::too_many_arguments)]
    pub fn import_local_material(
        passkey_prf_first: &[u8],
        binding: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        expected_registered_public_key: &[u8],
        expected_state_epoch: u64,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        signing_worker_verifying_share: &[u8],
    ) -> Result<WasmActivatedClientV1, JsValue> {
        let wrapping_secret = Zeroizing::new(parse_32(passkey_prf_first, "passkey PRF.first")?);
        import_activated_client_local_material(
            &wrapping_secret,
            binding,
            nonce,
            ciphertext,
            expected_registered_public_key,
            expected_state_epoch,
            [client_participant_id, signing_worker_participant_id],
            signing_worker_verifying_share,
            LocalMaterialSealDomainV1::PasskeyPrfFirst,
        )
    }

    /// Opens an Email OTP custody envelope and re-verifies its public threshold relation.
    #[allow(clippy::too_many_arguments)]
    pub fn import_email_otp_local_material(
        owned_enrollment_secret32: &[u8],
        binding: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        expected_registered_public_key: &[u8],
        expected_state_epoch: u64,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        signing_worker_verifying_share: &[u8],
    ) -> Result<WasmActivatedClientV1, JsValue> {
        let wrapping_secret = Zeroizing::new(parse_32(
            owned_enrollment_secret32,
            "Email OTP enrollment secret",
        )?);
        import_activated_client_local_material(
            &wrapping_secret,
            binding,
            nonce,
            ciphertext,
            expected_registered_public_key,
            expected_state_epoch,
            [client_participant_id, signing_worker_participant_id],
            signing_worker_verifying_share,
            LocalMaterialSealDomainV1::EmailOtpEnrollment,
        )
    }

    /// Creates a signature share while retaining the Client scalar inside WASM.
    #[allow(clippy::too_many_arguments)]
    pub fn create_signing_share(
        &self,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        admitted_digest: &[u8],
        signing_worker_commitments_json: &str,
        signing_worker_verifying_share: &[u8],
    ) -> Result<WasmClientSigningShareV1, JsValue> {
        build_client_signing_share(
            &self.client_scalar_share,
            &self.registered_public_key,
            client_participant_id,
            signing_worker_participant_id,
            admitted_digest,
            signing_worker_commitments_json,
            signing_worker_verifying_share,
        )
    }
}

/// Seals under one of the shared wrapping domains.
///
/// The crypto itself lives in `local_material`, because the wallet custody
/// ceremony has to seal the same record shape from its own wasm module and
/// this one is compiled only for `wasm32`. These shims exist to keep the
/// binding surface unchanged while there is a single implementation underneath.
fn seal_activated_client_local_material(
    activated_client: &WasmActivatedClientV1,
    wrapping_secret: &[u8; 32],
    binding: &[u8],
    nonce: &[u8],
    domain: LocalMaterialSealDomainV1,
) -> Result<Vec<u8>, JsValue> {
    seal_activated_client_material_v1(
        &activated_client.client_scalar_share,
        &activated_client.registered_public_key,
        activated_client.state_epoch,
        wrapping_secret,
        binding,
        nonce,
        domain,
    )
    .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[allow(clippy::too_many_arguments)]
fn import_activated_client_local_material(
    wrapping_secret: &[u8; 32],
    binding: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    expected_registered_public_key: &[u8],
    expected_state_epoch: u64,
    participant_ids: [u16; 2],
    signing_worker_verifying_share: &[u8],
    domain: LocalMaterialSealDomainV1,
) -> Result<WasmActivatedClientV1, JsValue> {
    let expected_registered_public_key = parse_32(
        expected_registered_public_key,
        "expected registered Ed25519 public key",
    )?;
    let signing_worker_verifying_share = parse_32(
        signing_worker_verifying_share,
        "SigningWorker verifying share",
    )?;
    let opened = import_activated_client_material_v1(
        wrapping_secret,
        binding,
        nonce,
        ciphertext,
        &expected_registered_public_key,
        expected_state_epoch,
        participant_ids,
        &signing_worker_verifying_share,
        domain,
    )
    .map_err(|error| JsValue::from_str(&error.to_string()))?;
    Ok(WasmActivatedClientV1 {
        client_scalar_share: opened.client_scalar_share,
        registered_public_key: opened.registered_public_key,
        state_epoch: opened.state_epoch,
    })
}

/// Opens the wallet's Ed25519 continuity cache with any enrolled factor.
///
/// **The unlock read side, and deliberately one call.** The custody seed
/// exists only between opening the envelope and deriving the cache key.
/// Splitting this into "open the envelope" and "open the cache" would put the
/// seed in a caller's hands, and every caller here is JavaScript.
///
/// Exported from *this* module rather than the ceremony's because the handle
/// it returns has to be the one the signing path already uses: two wasm
/// modules each define their own `WasmActivatedClientV1`, and a handle from
/// the wrong module cannot sign.
///
/// The caller never assembles the cache seal binding. It is rebuilt here from
/// the record's own fields, because it is both HKDF input and AEAD associated
/// data — a caller that assembled it even slightly differently would hold a
/// record that never opens, and the failure would read as a bad factor.
///
/// Any factor works, which is the point of sealing under the seed: a passkey
/// enrolled long after registration opens the cache the Email OTP enrollment
/// wrote, and the reverse.
#[wasm_bindgen(js_name = openWalletCustodyEd25519MaterialV1)]
#[allow(clippy::too_many_arguments)]
pub fn wasm_open_wallet_custody_ed25519_material_v1(
    factor_secret: &[u8],
    envelope_binding_json: &str,
    envelope_nonce: &[u8],
    envelope_ciphertext: &[u8],
    envelope_aad_hash: &[u8],
    envelope_ciphertext_digest: &[u8],
    application_binding_digest: &[u8],
    registered_public_key: &[u8],
    state_epoch: u64,
    client_participant_id: u16,
    signing_worker_participant_id: u16,
    signing_worker_verifying_share: &[u8],
    cache_nonce: &[u8],
    cache_ciphertext: &[u8],
) -> Result<WasmActivatedClientV1, JsValue> {
    let envelope_binding =
        serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(envelope_binding_json)
            .map_err(js_error)?;
    let application_binding_digest =
        parse_32(application_binding_digest, "application binding digest")?;
    let registered_public_key = parse_32(
        registered_public_key,
        "expected registered Ed25519 public key",
    )?;
    let signing_worker_verifying_share = parse_32(
        signing_worker_verifying_share,
        "SigningWorker verifying share",
    )?;
    let participant_ids = [client_participant_id, signing_worker_participant_id];

    // Rebuilt, never accepted: see above.
    let binding = ed25519_local_material_binding_v1(
        &application_binding_digest,
        &registered_public_key,
        participant_ids,
        state_epoch,
    );

    let opened = open_wallet_custody_ed25519_material_v1(OpenWalletCustodyEd25519MaterialV1 {
        factor_secret,
        envelope_binding: &envelope_binding,
        envelope_nonce,
        envelope_ciphertext,
        envelope_aad_hash,
        envelope_ciphertext_digest,
        application_binding_digest: &application_binding_digest,
        binding: &binding,
        nonce: cache_nonce,
        ciphertext: cache_ciphertext,
        expected_registered_public_key: &registered_public_key,
        expected_state_epoch: state_epoch,
        participant_ids,
        signing_worker_verifying_share: &signing_worker_verifying_share,
    })
    .map_err(js_error)?;

    Ok(WasmActivatedClientV1 {
        client_scalar_share: Zeroizing::new(*opened.client_scalar_share()),
        registered_public_key: opened.registered_public_key(),
        state_epoch: opened.state_epoch(),
    })
}

/// One Client FROST share created from activated Yao material.
#[wasm_bindgen]
pub struct WasmClientSigningShareV1 {
    client_commitments_json: String,
    client_verifying_share: Vec<u8>,
    client_signature_share_b64u: String,
}

#[wasm_bindgen]
impl WasmClientSigningShareV1 {
    /// Returns the Client FROST commitments as canonical JSON.
    pub fn client_commitments_json(&self) -> String {
        self.client_commitments_json.clone()
    }

    /// Returns the public Client verifying share.
    pub fn client_verifying_share(&self) -> Vec<u8> {
        self.client_verifying_share.clone()
    }

    /// Returns the canonical Client signature share.
    pub fn client_signature_share_b64u(&self) -> String {
        self.client_signature_share_b64u.clone()
    }
}

#[allow(clippy::too_many_arguments)]
fn build_client_signing_share(
    client_scalar_share: &[u8; 32],
    registered_public_key: &[u8; 32],
    client_participant_id: u16,
    signing_worker_participant_id: u16,
    admitted_digest: &[u8],
    signing_worker_commitments_json: &str,
    signing_worker_verifying_share: &[u8],
) -> Result<WasmClientSigningShareV1, JsValue> {
    let admitted_digest = parse_32(admitted_digest, "admitted digest")?;
    let signing_worker_verifying_share = parse_32(
        signing_worker_verifying_share,
        "SigningWorker verifying share",
    )?;
    let signing_worker_commitments =
        serde_json::from_str::<CommitmentsWire>(signing_worker_commitments_json)
            .map_err(js_error)?;
    let output = create_client_signing_share_v1(ClientSigningRequestV1 {
        client_scalar_share,
        registered_public_key,
        participant_ids: [client_participant_id, signing_worker_participant_id],
        admitted_digest: &admitted_digest,
        signing_worker_commitments: &signing_worker_commitments,
        signing_worker_verifying_share: &signing_worker_verifying_share,
    })
    .map_err(js_error)?;
    Ok(WasmClientSigningShareV1 {
        client_commitments_json: serde_json::to_string(output.client_commitments())
            .map_err(js_error)?,
        client_verifying_share: output.client_verifying_share().to_vec(),
        client_signature_share_b64u: output.client_signature_share_b64u().to_owned(),
    })
}

fn parse_32(value: &[u8], label: &str) -> Result<[u8; 32], JsValue> {
    value
        .try_into()
        .map_err(|_| JsValue::from_str(&format!("{label} must contain exactly 32 bytes")))
}

fn js_error(error: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
