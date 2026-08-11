use router_ab_core::{
    Ed25519YaoCeremonyBindingV1, Ed25519YaoLaneJobV1, RouterAbEd25519YaoApplicationBindingFactsV1,
    RouterAbEd25519YaoExportAdmissionReceiptV1, RouterAbEd25519YaoExportResultV1,
};
use serde::de::DeserializeOwned;
use wasm_bindgen::prelude::*;
use zeroize::{Zeroize, Zeroizing};

use crate::lane_holder::{
    verify_holder_package, LaneCustodySealV1, LaneHolderRecipientV1, LaneHolderSigningMaterialV1,
};
use crate::{
    complete_client_export_v1, create_client_signing_share_v1,
    prepare_client_export_from_custody_seed_v1, ClientActivationEntropyV1, ClientExportStateV1,
    ClientSigningRequestV1,
};
use crate::{
    complete_client_lane_v1, prepare_client_lane_dispatch_with_root_v1, prepare_client_lane_v1,
    ClientLaneExecutionEntropyV1, Ed25519YaoClientDerivationRootV1, PreparedClientLaneV1,
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
use signer_core::passkey_custody::open_wallet_custody_seed_envelope_v1;
use signer_core::passkey_custody::PasskeyCustodyEnvelopeBindingV1;
use signer_core::wallet_seed_derivation::derive_ed25519_yao_client_root_from_seed_v1;

/// Worker-owned factor context for sealing one target lane share.
///
/// Factor material remains inside Rust memory. The supported branches are the
/// two existing custody factors (`passkey` and `email_otp`); future factor
/// strings fail closed until signer-core defines their KEK context.
#[wasm_bindgen]
pub struct WasmLaneCustodySealV1 {
    inner: LaneCustodySealV1,
}

#[wasm_bindgen]
impl WasmLaneCustodySealV1 {
    /// Loads one already-authorized custody factor into an opaque seal handle.
    #[wasm_bindgen(constructor)]
    pub fn new(
        factor_kind: &str,
        factor_secret: &[u8],
        envelope_binding_json: &str,
        custody_binding_id: &str,
        custody_binding_digest_b64u: &str,
    ) -> Result<WasmLaneCustodySealV1, JsValue> {
        let factor_secret = Zeroizing::new(parse_32(factor_secret, "lane custody factor secret")?);
        let binding =
            serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(envelope_binding_json)
                .map_err(js_error)?;
        Ok(Self {
            inner: LaneCustodySealV1::from_factor(
                factor_kind,
                *factor_secret,
                binding,
                custody_binding_id.to_owned(),
                custody_binding_digest_b64u.to_owned(),
            )
            .map_err(js_error)?,
        })
    }
}

/// One-use target-holder X25519 recipient retained inside the worker WASM.
#[wasm_bindgen]
pub struct WasmLaneHolderRecipientV1 {
    inner: LaneHolderRecipientV1,
}

#[wasm_bindgen]
impl WasmLaneHolderRecipientV1 {
    /// Creates a recipient from worker-generated key material.
    #[wasm_bindgen(constructor)]
    pub fn new(
        operation_id: &str,
        recipient_key_material: &[u8],
    ) -> Result<WasmLaneHolderRecipientV1, JsValue> {
        let key_material = Zeroizing::new(parse_32(
            recipient_key_material,
            "lane holder recipient key material",
        )?);
        Ok(Self {
            inner: LaneHolderRecipientV1::new(operation_id.to_owned(), *key_material)
                .map_err(js_error)?,
        })
    }

    /// Returns the public X25519 recipient key.
    pub fn hpke_public_key_b64u(&self) -> String {
        self.inner.public_key_b64u().to_owned()
    }

    /// Returns the SHA-256 digest of the public recipient key.
    pub fn hpke_public_key_digest_b64u(&self) -> String {
        self.inner.public_key_digest_b64u().to_owned()
    }

    /// Opens one exact committed package and seals the share to custody.
    #[allow(clippy::too_many_arguments)]
    pub fn open_and_seal(
        &mut self,
        custody: &WasmLaneCustodySealV1,
        job_json: &str,
        receipt_json: &str,
        holder_package_json: &str,
        nonce12: &[u8],
    ) -> Result<JsValue, JsValue> {
        let output = self
            .inner
            .open_and_seal(
                &custody.inner,
                job_json,
                receipt_json,
                holder_package_json,
                nonce12,
            )
            .map_err(js_error)?;
        serde_wasm_bindgen::to_value(&output).map_err(js_error)
    }

    /// Immediately zeroizes the recipient private key.
    pub fn destroy(&mut self) {
        self.inner.destroy();
    }
}

/// Verifies a committed holder package without opening recipient ciphertext.
#[wasm_bindgen]
pub fn verify_lane_holder_package_commitment_v1(
    job_json: &str,
    receipt_json: &str,
    holder_package_json: &str,
) -> Result<JsValue, JsValue> {
    let output =
        verify_holder_package(job_json, receipt_json, holder_package_json).map_err(js_error)?;
    serde_wasm_bindgen::to_value(&output).map_err(js_error)
}

/// Opaque lane-holder signing material reopened from one exact custody record.
///
/// The factor and scalar share remain inside the worker WASM. Ed25519 exposes
/// only a signature share. ECDSA remains opaque until a dedicated presign
/// worker bridge consumes it.
#[wasm_bindgen]
pub struct WasmLaneHolderSigningMaterialV1 {
    inner: LaneHolderSigningMaterialV1,
}

#[wasm_bindgen]
impl WasmLaneHolderSigningMaterialV1 {
    /// Opens one digest-verified sealed holder record and binds it to the exact
    /// persisted R102 job and protocol receipt.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        factor_secret: &[u8],
        sealed_holder_material_b64u: &str,
        expected_record_digest_b64u: &str,
        expected_holder_ciphertext_digest_set_b64u: &str,
        job_json: &str,
        receipt_json: &str,
    ) -> Result<Self, JsValue> {
        let factor_secret = Zeroizing::new(factor_secret.to_vec());
        Ok(Self {
            inner: LaneHolderSigningMaterialV1::open(
                &factor_secret,
                sealed_holder_material_b64u,
                expected_record_digest_b64u,
                expected_holder_ciphertext_digest_set_b64u,
                job_json,
                receipt_json,
            )
            .map_err(js_error)?,
        })
    }

    /// Returns the public curve discriminator for the retained share.
    pub fn key_family(&self) -> Result<String, JsValue> {
        self.inner.kind().map(str::to_owned).map_err(js_error)
    }

    /// Creates one Ed25519 Client signature share without releasing the scalar.
    #[allow(clippy::too_many_arguments)]
    pub fn create_ed25519_signing_share(
        &self,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        admitted_digest: &[u8],
        signing_worker_commitments_json: &str,
        signing_worker_verifying_share: &[u8],
    ) -> Result<WasmClientSigningShareV1, JsValue> {
        let (share, registered_public_key) = self.inner.ed25519_material().map_err(js_error)?;
        build_client_signing_share(
            share,
            registered_public_key,
            client_participant_id,
            signing_worker_participant_id,
            admitted_digest,
            signing_worker_commitments_json,
            signing_worker_verifying_share,
        )
    }

    /// Immediately destroys retained holder material.
    pub fn destroy(&mut self) {
        self.inner.destroy();
    }
}

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
    /// Opens the custody envelope and prepares a one-use export request.
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

    /// Returns the serialized request to execute through the Router A/B export protocol.
    pub fn execute_request_json(&self) -> String {
        self.execute_request_json.clone()
    }

    /// Consumes the session and returns the verified exported seed.
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

fn parse_js_domain_value<T: DeserializeOwned>(value: JsValue) -> Result<T, JsValue> {
    if let Some(json) = value.as_string() {
        serde_json::from_str(&json).map_err(js_error)
    } else {
        serde_wasm_bindgen::from_value(value).map_err(js_error)
    }
}

/// Opaque wallet-custody source for Ed25519 Yao lane preparation.
///
/// This handle must be created and retained inside the dedicated signing
/// worker. Neither the custody seed nor stable Client root crosses into JS.
#[wasm_bindgen]
pub struct WasmEd25519YaoLaneSourceV1 {
    root: Ed25519YaoClientDerivationRootV1,
}

#[wasm_bindgen]
impl WasmEd25519YaoLaneSourceV1 {
    /// Opens the custody envelope and retains only the derived Client root.
    #[wasm_bindgen(constructor)]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        factor_secret: &[u8],
        envelope_binding_json: &str,
        envelope_nonce: &[u8],
        envelope_ciphertext: &[u8],
        envelope_aad_hash: &[u8],
        envelope_ciphertext_digest: &[u8],
        application_binding_digest: &[u8],
    ) -> Result<Self, JsValue> {
        let envelope_binding =
            serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(envelope_binding_json)
                .map_err(js_error)?;
        let factor_secret = Zeroizing::new(factor_secret.to_vec());
        let (seed, _) = open_wallet_custody_seed_envelope_v1(
            &factor_secret,
            &envelope_binding,
            envelope_nonce,
            envelope_ciphertext,
            envelope_aad_hash,
            envelope_ciphertext_digest,
        )
        .map_err(js_error)?;
        let application_binding_digest = parse_32(
            application_binding_digest,
            "Ed25519 Yao application binding digest",
        )?;
        let root = derive_ed25519_yao_client_root_from_seed_v1(&seed, &application_binding_digest)
            .map_err(js_error)?;
        Ok(Self {
            root: Ed25519YaoClientDerivationRootV1::from_secret_bytes(*root),
        })
    }
}

#[derive(Debug)]
enum WasmEd25519YaoLaneClientStateV1 {
    Empty,
    Prepared {
        request_json: String,
        completion: PreparedClientLaneV1,
    },
    Consumed,
}

/// One-use WASM typestate client for Ed25519 Yao lane provisioning/refresh.
///
/// The source root and derived contributions remain inside this boundary. The
/// returned request contains only recipient-encrypted Deriver inputs.
#[wasm_bindgen]
pub struct WasmEd25519YaoLaneClientV1 {
    state: WasmEd25519YaoLaneClientStateV1,
}

#[wasm_bindgen]
impl WasmEd25519YaoLaneClientV1 {
    /// Creates an empty one-use lane client.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            state: WasmEd25519YaoLaneClientStateV1::Empty,
        }
    }

    /// Prepares the exact authenticated internal dispatch artifact and returns
    /// `{ requestJson }` for Router execution.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare(
        &mut self,
        job_input: JsValue,
        binding_input: JsValue,
        application_input: JsValue,
        client_participant_id: u16,
        signing_worker_participant_id: u16,
        source: &WasmEd25519YaoLaneSourceV1,
        deriver_a_input_public_key: &[u8],
        deriver_b_input_public_key: &[u8],
        deriver_a_seal_seed: &[u8],
        deriver_b_seal_seed: &[u8],
    ) -> Result<JsValue, JsValue> {
        if !matches!(self.state, WasmEd25519YaoLaneClientStateV1::Empty) {
            return Err(JsValue::from_str(
                "Ed25519 Yao lane client is already prepared",
            ));
        }
        let job = parse_js_domain_value::<Ed25519YaoLaneJobV1>(job_input)?;
        let binding = parse_js_domain_value::<Ed25519YaoCeremonyBindingV1>(binding_input)?;
        let application = parse_js_domain_value::<RouterAbEd25519YaoApplicationBindingFactsV1>(
            application_input,
        )?;
        let deriver_a_input_public_key =
            parse_32(deriver_a_input_public_key, "Deriver A input public key")?;
        let deriver_b_input_public_key =
            parse_32(deriver_b_input_public_key, "Deriver B input public key")?;
        let deriver_a_seal_seed =
            Zeroizing::new(parse_32(deriver_a_seal_seed, "Deriver A seal seed")?);
        let deriver_b_seal_seed =
            Zeroizing::new(parse_32(deriver_b_seal_seed, "Deriver B seal seed")?);
        let prepared = prepare_client_lane_v1(job).map_err(js_error)?;
        let entropy = ClientLaneExecutionEntropyV1::new(*deriver_a_seal_seed, *deriver_b_seal_seed)
            .map_err(js_error)?;
        let dispatch = prepare_client_lane_dispatch_with_root_v1(
            prepared,
            &binding,
            &application,
            [client_participant_id, signing_worker_participant_id],
            &source.root,
            deriver_a_input_public_key,
            deriver_b_input_public_key,
            entropy,
        )
        .map_err(js_error)?;
        let (execute_request, completion) = dispatch.into_parts();
        let request_json = serde_json::to_string(&execute_request).map_err(js_error)?;
        self.state = WasmEd25519YaoLaneClientStateV1::Prepared {
            request_json: request_json.clone(),
            completion,
        };
        let object = js_sys::Object::new();
        js_sys::Reflect::set(
            &object,
            &JsValue::from_str("requestJson"),
            &JsValue::from_str(&request_json),
        )
        .map_err(|_| JsValue::from_str("failed to construct lane request"))?;
        Ok(object.into())
    }

    /// Returns the prepared request JSON for callers that use the Rust-style
    /// getter convention.
    pub fn execute_request_json(&self) -> Result<String, JsValue> {
        match &self.state {
            WasmEd25519YaoLaneClientStateV1::Prepared { request_json, .. } => {
                Ok(request_json.clone())
            }
            WasmEd25519YaoLaneClientStateV1::Empty | WasmEd25519YaoLaneClientStateV1::Consumed => {
                Err(JsValue::from_str("Ed25519 Yao lane client is not prepared"))
            }
        }
    }

    /// Consumes the one-use state and returns the immutable receipt plus the
    /// opaque holder package set required for later delivery.
    pub fn complete(&mut self, result_input: JsValue) -> Result<JsValue, JsValue> {
        let state = core::mem::replace(&mut self.state, WasmEd25519YaoLaneClientStateV1::Consumed);
        let WasmEd25519YaoLaneClientStateV1::Prepared {
            completion: prepared,
            ..
        } = state
        else {
            return Err(JsValue::from_str(
                "Ed25519 Yao lane client was not prepared",
            ));
        };
        let response_json = if let Some(response_json) = result_input.as_string() {
            response_json
        } else {
            let value = js_sys::Reflect::get(&result_input, &JsValue::from_str("responseJson"))
                .map_err(|_| JsValue::from_str("lane responseJson is missing"))?;
            value
                .as_string()
                .ok_or_else(|| JsValue::from_str("lane responseJson must be a string"))?
        };
        let receipt = complete_client_lane_v1(prepared, &response_json).map_err(js_error)?;
        serde_wasm_bindgen::to_value(&receipt).map_err(js_error)
    }
}
