//! The browser boundary for wallet custody ceremonies.
//!
//! Each state is a separate `#[wasm_bindgen]` handle, and each transition takes
//! `self` by value. wasm-bindgen nulls the JavaScript object's pointer when a
//! method consumes it, so a caller physically cannot reuse a state it has
//! already advanced or retry one whose transition failed.
//!
//! What crosses this boundary inbound: public protocol messages, the factor
//! secret whose KEK opens the envelope, and the recovery codes. What crosses
//! outbound: public protocol messages, ciphertext, and public records. Never a
//! seed, an owner root, a KEK, a manifest proof, or the ECDSA pending blob.
//!
//! Yao activation entropy is generated here rather than accepted, so a caller
//! cannot supply the recipient key material or the Deriver seal seeds. The
//! Rust-side inputs still take entropy, because the circuit tests must control
//! it to play the Deriver roles; JavaScript cannot.

use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    RouterAbEd25519YaoActivationAdmissionReceiptV1, RouterAbEd25519YaoApplicationBindingFactsV1,
};
use router_ab_ed25519_yao_client::ClientActivationEntropyV1;
use serde::Deserialize;
use signer_core::commands::RelayerPublicIdentityV1;
use signer_core::ecdsa_role_local_client::command::RelayerPublicIdentityInput;
use signer_core::passkey_custody::{
    PasskeyCustodyEnvelopeBindingV1, WalletCustodyEnvelopeFactorV1,
};
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::ceremony::{
    CeremonyError, CeremonyEvmActivationPendingV1, CeremonyManifestEstablishedV1,
    CeremonyProtocolCompletedV1, CeremonyProtocolPreparedV1, CeremonySeedHeldV1,
    EvmFamilyActivationCompletionV1, FactorSealInputsV1, KeySetIdentityInputsV1,
    KeySetProtocolInputsV1, RecoveryCodeInputV1, RecoveryCustodyOpenInputsV1,
    WalletCustodyCommitPayloadV1,
};

fn js_error(message: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

fn ceremony_error(error: CeremonyError) -> JsValue {
    js_error(error.message())
}

/// Decoders return `String` and convert to `JsValue` only at the edge:
/// `JsValue::from_str` aborts on non-wasm32 targets, which would make these
/// hand-written parsers untestable on the host.
type DecodeResult<T> = Result<T, String>;

fn decode_b64u(value: &str, label: &str) -> DecodeResult<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(value).map_err(|_| format!("{label} must be unpadded base64url"))
}

fn decode_fixed<const N: usize>(value: &str, label: &str) -> DecodeResult<[u8; N]> {
    decode_b64u(value, label)?
        .try_into()
        .map_err(|_| format!("{label} must decode to {N} bytes"))
}

/// A 0x-prefixed Ethereum address, matching `RelayerPublicIdentityV1`'s
/// existing spelling so the TypeScript side keeps one shape for this record.
fn decode_ethereum_address20(value: &str) -> DecodeResult<[u8; 20]> {
    let hex = value
        .trim()
        .strip_prefix("0x")
        .ok_or("ethereumAddress must be 0x-prefixed")?;
    if hex.len() != 40 {
        return Err("ethereumAddress must be 20 bytes".to_string());
    }
    let mut out = [0u8; 20];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
            .map_err(|_| "ethereumAddress must be hexadecimal".to_string())?;
    }
    Ok(out)
}

fn random32(label: &str) -> DecodeResult<[u8; 32]> {
    let mut out = [0u8; 32];
    getrandom::getrandom(&mut out).map_err(|_| format!("{label} randomness is unavailable"))?;
    Ok(out)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NearEd25519ProtocolInputsWireV1 {
    yao_admission: RouterAbEd25519YaoActivationAdmissionReceiptV1,
    yao_application: RouterAbEd25519YaoApplicationBindingFactsV1,
    client_participant_id: u16,
    signing_worker_participant_id: u16,
    /// The registered public key when this key set already has a registration.
    /// Present means the run reproduces it rather than establishing a new one.
    #[serde(default)]
    continuity_registered_public_key_b64u: Option<String>,
    /// No Ed25519 binding digest field: the ceremony computes it from
    /// `yaoApplication`, so a caller cannot bind the root to a digest the
    /// protocol will not verify.
    #[serde(skip)]
    _never: (),
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EvmFamilyProtocolInputsWireV1 {
    /// From the relayer's ECDSA registration bootstrap.
    application_binding_digest_b64u: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FactorSealInputsWireV1 {
    envelope_id: String,
    factor: WalletCustodyEnvelopeFactorV1,
    /// Refactor 109C: the exact auth method this envelope will belong to.
    /// Required — a newly sealed envelope is always method-bound, so there is
    /// no shape in which JavaScript may omit it.
    wallet_auth_method_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryCodeInputWireV1 {
    /* No `recoveryKeyId`. The id is derived inside the ceremony from the
    wallet and these bytes and returned on the sealed wrap, so JavaScript
    cannot supply one — `deny_unknown_fields` makes sending one an error
    rather than a value silently ignored. */
    code_bytes_b64u: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct JoinCustodyWireV1 {
    envelope_binding: PasskeyCustodyEnvelopeBindingV1,
    nonce_b64u: String,
    sealed_custody_secret_b64u: String,
    aad_hash_b64u: String,
    ciphertext_digest_b64u: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryManifestWrapWireV1 {
    nonce_b64u: String,
    wrapped_manifest_kek_b64u: String,
    aad_hash_b64u: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoverySeedEntryWireV1 {
    custody_secret_kind: String,
    nonce_b64u: String,
    wrapped_custody_secret_b64u: String,
    aad_hash_b64u: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryCustodyWireV1 {
    wallet_id: String,
    wrap: RecoveryManifestWrapWireV1,
    entry: RecoverySeedEntryWireV1,
}

fn relayer_identity(wire: RelayerPublicIdentityV1) -> DecodeResult<RelayerPublicIdentityInput> {
    Ok(RelayerPublicIdentityInput {
        relayer_key_id: wire.relayer_key_id,
        relayer_public_key33: decode_fixed(
            &wire.relayer_public_key33_b64u,
            "relayerPublicKey33B64u",
        )?,
        group_public_key33: decode_fixed(&wire.group_public_key33_b64u, "groupPublicKey33B64u")?,
        ethereum_address20: decode_ethereum_address20(&wire.ethereum_address)?,
        relayer_share_retry_counter: wire.relayer_share_retry_counter,
    })
}

fn recorded_manifest_digest(value: Option<String>) -> DecodeResult<Option<[u8; 32]>> {
    value
        .as_deref()
        .map(|digest| decode_fixed::<32>(digest, "recordedKeyManifestDigestB64u"))
        .transpose()
}

fn factor_seal_inputs(factor_json: &str, factor_secret: &[u8]) -> DecodeResult<FactorSealInputsV1> {
    let wire = serde_json::from_str::<FactorSealInputsWireV1>(factor_json)
        .map_err(|error| error.to_string())?;
    Ok(FactorSealInputsV1 {
        envelope_id: wire.envelope_id,
        factor: wire.factor,
        wallet_auth_method_id: wire.wallet_auth_method_id,
        factor_secret: Zeroizing::new(factor_secret.to_vec()),
    })
}

fn recovery_code_inputs(recovery_codes_json: &str) -> DecodeResult<Vec<RecoveryCodeInputV1>> {
    let wires = serde_json::from_str::<Vec<RecoveryCodeInputWireV1>>(recovery_codes_json)
        .map_err(|error| error.to_string())?;
    let mut recovery_codes = Vec::with_capacity(wires.len());
    for wire in wires {
        recovery_codes.push(RecoveryCodeInputV1 {
            code_bytes: Zeroizing::new(decode_b64u(&wire.code_bytes_b64u, "codeBytesB64u")?),
        });
    }
    Ok(recovery_codes)
}

/// State 1. Holds the wallet custody seed and nothing else.
#[wasm_bindgen]
pub struct WasmCeremonySeedHeldV1 {
    inner: CeremonySeedHeldV1,
}

/// State 2. The protocol is prepared; the root is already gone.
#[wasm_bindgen]
pub struct WasmCeremonyProtocolPreparedV1 {
    inner: CeremonyProtocolPreparedV1,
}

/// EVM state after its custody payload is ready and before activation returns.
#[wasm_bindgen]
pub struct WasmCeremonyEvmActivationPendingV1 {
    inner: CeremonyEvmActivationPendingV1,
    commit_payload: WalletCustodyCommitPayloadV1,
}

/// State 3. The protocol returned; its public identity is known.
#[wasm_bindgen]
pub struct WasmCeremonyProtocolCompletedV1 {
    inner: CeremonyProtocolCompletedV1,
}

/// State 4. This key set's manifest is established and its proof exists —
/// inside this handle only. There is deliberately no accessor for it.
#[wasm_bindgen]
pub struct WasmCeremonyManifestEstablishedV1 {
    inner: CeremonyManifestEstablishedV1,
}

/// Establishes custody for a wallet: generates the seed inside wasm.
///
/// Use this for the first key set only. A wallet that already has custody must
/// join it — generating a second seed would split custody permanently.
#[wasm_bindgen]
pub fn wallet_custody_ceremony_establish_v1(
    wallet_id: &str,
) -> Result<WasmCeremonySeedHeldV1, JsValue> {
    Ok(WasmCeremonySeedHeldV1 {
        inner: CeremonySeedHeldV1::establish(wallet_id).map_err(ceremony_error)?,
    })
}

/// Joins custody that already exists, by opening its seed envelope.
///
/// This is how a second key set reaches the same seed. The run that follows
/// writes only its own manifest.
#[wasm_bindgen]
pub fn wallet_custody_ceremony_join_v1(
    factor_secret: &[u8],
    custody_json: &str,
) -> Result<WasmCeremonySeedHeldV1, JsValue> {
    let wire = serde_json::from_str::<JoinCustodyWireV1>(custody_json).map_err(js_error)?;
    let nonce = decode_b64u(&wire.nonce_b64u, "nonceB64u").map_err(js_error)?;
    let ciphertext = decode_b64u(&wire.sealed_custody_secret_b64u, "sealedCustodySecretB64u")
        .map_err(js_error)?;
    let aad_hash: [u8; 32] = decode_fixed(&wire.aad_hash_b64u, "aadHashB64u").map_err(js_error)?;
    let ciphertext_digest: [u8; 32] =
        decode_fixed(&wire.ciphertext_digest_b64u, "ciphertextDigestB64u").map_err(js_error)?;
    Ok(WasmCeremonySeedHeldV1 {
        inner: CeremonySeedHeldV1::join_existing_custody(
            factor_secret,
            &wire.envelope_binding,
            &nonce,
            &ciphertext,
            &aad_hash,
            &ciphertext_digest,
        )
        .map_err(ceremony_error)?,
    })
}

/// Opens a wallet custody seed with a reserved recovery code.
///
/// The wire has no recovery key id. Rust derives it from the wallet and code,
/// checks both stored AAD hashes, and opens exactly the matching wrap. The seed
/// remains inside this typestate and can only proceed into a key-continuity
/// protocol run.
#[wasm_bindgen]
pub fn wallet_custody_ceremony_recover_v1(
    recovery_code_bytes: &[u8],
    custody_json: &str,
) -> Result<WasmCeremonySeedHeldV1, JsValue> {
    let wire = serde_json::from_str::<RecoveryCustodyWireV1>(custody_json).map_err(js_error)?;
    if wire.entry.custody_secret_kind != "wallet_custody_seed_v1" {
        return Err(js_error(
            "recovery entry must contain the wallet custody seed",
        ));
    }
    let input = RecoveryCustodyOpenInputsV1 {
        wallet_id: wire.wallet_id,
        wrap_nonce: decode_b64u(&wire.wrap.nonce_b64u, "wrap.nonceB64u").map_err(js_error)?,
        wrapped_manifest_kek: decode_b64u(
            &wire.wrap.wrapped_manifest_kek_b64u,
            "wrap.wrappedManifestKekB64u",
        )
        .map_err(js_error)?,
        wrap_aad_hash: decode_fixed(&wire.wrap.aad_hash_b64u, "wrap.aadHashB64u")
            .map_err(js_error)?,
        entry_nonce: decode_b64u(&wire.entry.nonce_b64u, "entry.nonceB64u").map_err(js_error)?,
        wrapped_custody_seed: decode_b64u(
            &wire.entry.wrapped_custody_secret_b64u,
            "entry.wrappedCustodySecretB64u",
        )
        .map_err(js_error)?,
        entry_aad_hash: decode_fixed(&wire.entry.aad_hash_b64u, "entry.aadHashB64u")
            .map_err(js_error)?,
    };
    Ok(WasmCeremonySeedHeldV1 {
        inner: CeremonySeedHeldV1::recover_with_code(recovery_code_bytes, input)
            .map_err(ceremony_error)?,
    })
}

#[wasm_bindgen]
impl WasmCeremonySeedHeldV1 {
    /// Reseals the existing wallet seed under a fresh manifest KEK and ten
    /// replacement recovery codes. The return value is opaque ciphertext
    /// records; no seed or KEK crosses the wasm boundary.
    pub fn rotate_recovery_codes(self, recovery_codes_json: &str) -> Result<String, JsValue> {
        let recovery_codes = recovery_code_inputs(recovery_codes_json).map_err(js_error)?;
        let rotated = self
            .inner
            .rotate_recovery_set(recovery_codes)
            .map_err(ceremony_error)?;
        serde_json::to_string(&rotated).map_err(js_error)
    }

    /// Derives the NEAR Ed25519 root and starts the Yao protocol.
    pub fn prepare_near_ed25519(
        self,
        inputs_json: &str,
    ) -> Result<WasmCeremonyProtocolPreparedV1, JsValue> {
        let wire = serde_json::from_str::<NearEd25519ProtocolInputsWireV1>(inputs_json)
            .map_err(js_error)?;
        let entropy = ClientActivationEntropyV1::new(
            random32("recipient key material").map_err(js_error)?,
            random32("Deriver A seal seed").map_err(js_error)?,
            random32("Deriver B seal seed").map_err(js_error)?,
        )
        .map_err(|error| js_error(format!("activation entropy: {error:?}")))?;
        let continuity = match wire.continuity_registered_public_key_b64u.as_deref() {
            Some(value) => Some(
                decode_fixed::<32>(value, "continuityRegisteredPublicKeyB64u").map_err(js_error)?,
            ),
            None => None,
        };
        Ok(WasmCeremonyProtocolPreparedV1 {
            inner: self
                .inner
                .prepare(KeySetProtocolInputsV1::NearEd25519 {
                    yao_admission: wire.yao_admission,
                    yao_application: wire.yao_application,
                    participant_ids: [
                        wire.client_participant_id,
                        wire.signing_worker_participant_id,
                    ],
                    yao_entropy: entropy,
                    continuity,
                })
                .map_err(ceremony_error)?,
        })
    }

    /// Derives the EVM-family root share and starts the ECDSA bootstrap.
    pub fn prepare_evm_family(
        self,
        inputs_json: &str,
    ) -> Result<WasmCeremonyProtocolPreparedV1, JsValue> {
        let wire =
            serde_json::from_str::<EvmFamilyProtocolInputsWireV1>(inputs_json).map_err(js_error)?;
        let digest = decode_fixed(
            &wire.application_binding_digest_b64u,
            "applicationBindingDigestB64u",
        )
        .map_err(js_error)?;
        Ok(WasmCeremonyProtocolPreparedV1 {
            inner: self
                .inner
                .prepare(KeySetProtocolInputsV1::EvmFamilyEcdsa {
                    application_binding_digest: digest,
                })
                .map_err(ceremony_error)?,
        })
    }
}

#[wasm_bindgen]
impl WasmCeremonyProtocolPreparedV1 {
    /// The opaque Router execution request, for a NEAR Ed25519 run.
    pub fn yao_execute_request_json(&self) -> Option<String> {
        self.inner.yao_execute_request_json().map(String::from)
    }

    pub fn ecdsa_context_binding32_b64u(&self) -> Option<String> {
        self.inner.ecdsa_context_binding32_b64u()
    }

    pub fn ecdsa_client_share_public_key33_b64u(&self) -> Option<String> {
        self.inner.ecdsa_client_share_public_key33_b64u()
    }

    pub fn ecdsa_client_share_retry_counter(&self) -> Option<u32> {
        self.inner.ecdsa_client_share_retry_counter()
    }

    pub fn complete_near_ed25519(
        self,
        yao_result_json: &str,
    ) -> Result<WasmCeremonyProtocolCompletedV1, JsValue> {
        Ok(WasmCeremonyProtocolCompletedV1 {
            inner: self
                .inner
                .complete_near_ed25519(yao_result_json)
                .map_err(ceremony_error)?,
        })
    }

    pub fn complete_evm_family(
        self,
        relayer_public_identity_json: &str,
    ) -> Result<WasmCeremonyProtocolCompletedV1, JsValue> {
        let wire = serde_json::from_str::<RelayerPublicIdentityV1>(relayer_public_identity_json)
            .map_err(js_error)?;
        Ok(WasmCeremonyProtocolCompletedV1 {
            inner: self
                .inner
                .complete_evm_family(relayer_identity(wire).map_err(js_error)?)
                .map_err(ceremony_error)?,
        })
    }

    /// Seals new custody before activation while retaining only ECDSA pending state.
    pub fn prepare_evm_activation_establishing_custody(
        self,
        evm_family_signing_key_slot_id: &str,
        factor_json: &str,
        factor_secret: &[u8],
        recovery_codes_json: &str,
    ) -> Result<WasmCeremonyEvmActivationPendingV1, JsValue> {
        let (inner, commit_payload) = self
            .inner
            .prepare_evm_activation(
                evm_family_signing_key_slot_id.to_string(),
                None,
                Some((
                    factor_seal_inputs(factor_json, factor_secret).map_err(js_error)?,
                    recovery_code_inputs(recovery_codes_json).map_err(js_error)?,
                )),
            )
            .map_err(ceremony_error)?;
        Ok(WasmCeremonyEvmActivationPendingV1 {
            inner,
            commit_payload,
        })
    }

    /// Prepares an EVM key set that joins custody already opened at begin.
    pub fn prepare_evm_activation_joining_custody(
        self,
        evm_family_signing_key_slot_id: &str,
        recorded_key_manifest_digest_b64u: Option<String>,
    ) -> Result<WasmCeremonyEvmActivationPendingV1, JsValue> {
        let recorded =
            recorded_manifest_digest(recorded_key_manifest_digest_b64u).map_err(js_error)?;
        let (inner, commit_payload) = self
            .inner
            .prepare_evm_activation(
                evm_family_signing_key_slot_id.to_string(),
                recorded.as_ref().map(|digest| &digest[..]),
                None,
            )
            .map_err(ceremony_error)?;
        Ok(WasmCeremonyEvmActivationPendingV1 {
            inner,
            commit_payload,
        })
    }

    /// Prepares a recovered EVM key set and reseals the wallet seed under the
    /// replacement passkey. A recorded manifest digest is mandatory: recovery
    /// reproduces a registered key and cannot establish a new one.
    pub fn prepare_evm_activation_recovering_custody(
        self,
        evm_family_signing_key_slot_id: &str,
        recorded_key_manifest_digest_b64u: String,
        replacement_factor_json: &str,
        replacement_factor_secret: &[u8],
    ) -> Result<WasmCeremonyEvmActivationPendingV1, JsValue> {
        let recorded = decode_fixed::<32>(
            &recorded_key_manifest_digest_b64u,
            "recordedKeyManifestDigestB64u",
        )
        .map_err(js_error)?;
        let (inner, commit_payload) = self
            .inner
            .prepare_evm_recovery_activation(
                evm_family_signing_key_slot_id.to_string(),
                &recorded,
                factor_seal_inputs(replacement_factor_json, replacement_factor_secret)
                    .map_err(js_error)?,
            )
            .map_err(ceremony_error)?;
        Ok(WasmCeremonyEvmActivationPendingV1 {
            inner,
            commit_payload,
        })
    }
}

#[wasm_bindgen]
impl WasmCeremonyEvmActivationPendingV1 {
    /// Ciphertext and public identity only; ready for the registration request.
    pub fn commit_payload(&self) -> Result<JsValue, JsValue> {
        serde_wasm_bindgen::to_value(&self.commit_payload).map_err(js_error)
    }

    /// Consumes the Router receipt and returns local role material plus public facts.
    pub fn complete(self, relayer_public_identity_json: &str) -> Result<JsValue, JsValue> {
        let wire = serde_json::from_str::<RelayerPublicIdentityV1>(relayer_public_identity_json)
            .map_err(js_error)?;
        let completion: EvmFamilyActivationCompletionV1 = self
            .inner
            .complete(relayer_identity(wire).map_err(js_error)?)
            .map_err(ceremony_error)?;
        serde_wasm_bindgen::to_value(&completion).map_err(js_error)
    }
}

#[wasm_bindgen]
impl WasmCeremonyProtocolCompletedV1 {
    /// Builds this key set's manifest and mints or verifies its proof. The
    /// proof does not cross this boundary.
    ///
    /// `recorded_key_manifest_digest_b64u` is the digest already riding this
    /// key set's registration state, when it has one. Present means the run
    /// must reproduce it.
    pub fn establish_manifest(
        self,
        key_set: &str,
        identity_id: &str,
        recorded_key_manifest_digest_b64u: Option<String>,
    ) -> Result<WasmCeremonyManifestEstablishedV1, JsValue> {
        let identity = match key_set {
            "near_ed25519_v1" => KeySetIdentityInputsV1::NearEd25519 {
                near_ed25519_signing_key_id: identity_id.to_string(),
            },
            "evm_family_ecdsa_v1" => KeySetIdentityInputsV1::EvmFamilyEcdsa {
                evm_family_signing_key_slot_id: identity_id.to_string(),
            },
            _ => return Err(js_error("unknown wallet key set kind")),
        };
        let recorded =
            recorded_manifest_digest(recorded_key_manifest_digest_b64u).map_err(js_error)?;
        Ok(WasmCeremonyManifestEstablishedV1 {
            inner: self
                .inner
                .establish_manifest(identity, recorded.as_ref().map(|d| &d[..]))
                .map_err(ceremony_error)?,
        })
    }
}

#[wasm_bindgen]
impl WasmCeremonyManifestEstablishedV1 {
    /// Finishes a run that established custody: seals the seed under the
    /// factor, issues the recovery set, and returns the records to write.
    pub fn finish_establishing_custody(
        self,
        factor_json: &str,
        factor_secret: &[u8],
        recovery_codes_json: &str,
    ) -> Result<JsValue, JsValue> {
        let payload = self
            .inner
            .finish(Some((
                factor_seal_inputs(factor_json, factor_secret).map_err(js_error)?,
                recovery_code_inputs(recovery_codes_json).map_err(js_error)?,
            )))
            .map_err(ceremony_error)?;
        serde_wasm_bindgen::to_value(&payload).map_err(js_error)
    }

    /// Finishes a run that joined existing custody: returns this key set's
    /// manifest digest and nothing else. No seed is sealed and no codes are
    /// issued, because the wallet already has both.
    pub fn finish_joining_custody(self) -> Result<JsValue, JsValue> {
        let payload = self.inner.finish(None).map_err(ceremony_error)?;
        serde_wasm_bindgen::to_value(&payload).map_err(js_error)
    }

    /// Finishes a recovered NEAR key set and reseals the wallet seed under the
    /// replacement passkey factor. Recovery codes remain on the server.
    pub fn finish_recovering_custody(
        self,
        replacement_factor_json: &str,
        replacement_factor_secret: &[u8],
    ) -> Result<JsValue, JsValue> {
        let payload = self
            .inner
            .finish_recovery(
                factor_seal_inputs(replacement_factor_json, replacement_factor_secret)
                    .map_err(js_error)?,
            )
            .map_err(ceremony_error)?;
        serde_wasm_bindgen::to_value(&payload).map_err(js_error)
    }
}

#[cfg(test)]
mod tests {
    //! The hand-written decoders at this boundary. Everything else here is
    //! serde plus a delegation to `ceremony`, which owns its own tests.

    use super::*;

    #[test]
    fn ethereum_addresses_are_parsed_exactly() {
        let address = decode_ethereum_address20("0x00112233445566778899aabbccddeeff00112233")
            .expect("valid address");
        assert_eq!(address[0], 0x00);
        assert_eq!(address[19], 0x33);
        assert_eq!(
            decode_ethereum_address20("0x00112233445566778899AABBCCDDEEFF00112233")
                .expect("checksummed address"),
            address
        );
        for rejected in [
            "00112233445566778899aabbccddeeff00112233",
            "0x00112233445566778899aabbccddeeff001122",
            "0x00112233445566778899aabbccddeeff001122zz",
            "0x",
            "",
        ] {
            assert!(
                decode_ethereum_address20(rejected).is_err(),
                "{rejected} must not parse as an address"
            );
        }
    }

    #[test]
    fn fixed_width_fields_reject_the_wrong_length() {
        let thirty_three = Base64UrlUnpadded::encode_string(&[2u8; 33]);
        assert!(decode_fixed::<33>(&thirty_three, "key").is_ok());
        assert!(decode_fixed::<32>(&thirty_three, "digest").is_err());
        assert!(decode_fixed::<32>("not base64url!!", "digest").is_err());
    }

    #[test]
    fn near_protocol_inputs_have_no_field_for_the_ed25519_binding_digest() {
        // `deny_unknown_fields` makes this a boundary guarantee: a caller that
        // tries to supply the digest is rejected rather than ignored.
        let json = r#"{
            "ed25519ApplicationBindingDigestB64u": "AAAA",
            "yaoAdmission": {},
            "yaoApplication": {},
            "clientParticipantId": 1,
            "signingWorkerParticipantId": 2
        }"#;
        let error = match serde_json::from_str::<NearEd25519ProtocolInputsWireV1>(json) {
            Ok(_) => panic!("unknown field must be rejected"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("ed25519ApplicationBindingDigestB64u"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn recovery_wire_cannot_supply_a_recovery_key_id() {
        let json = r#"{
            "walletId": "alice.testnet",
            "wrap": {
                "recoveryKeyId": "caller-chosen",
                "nonceB64u": "AAAAAAAAAAAAAAAA",
                "wrappedManifestKekB64u": "AAAA",
                "aadHashB64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            },
            "entry": {
                "custodySecretKind": "wallet_custody_seed_v1",
                "nonceB64u": "AAAAAAAAAAAAAAAA",
                "wrappedCustodySecretB64u": "AAAA",
                "aadHashB64u": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            }
        }"#;
        let error = match serde_json::from_str::<RecoveryCustodyWireV1>(json) {
            Ok(_) => panic!("a recovery key id must not cross this boundary"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("recoveryKeyId"),
            "unexpected error: {error}",
        );
    }
}
