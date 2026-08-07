//! The browser boundary for the registration ceremony.
//!
//! Each state is a separate `#[wasm_bindgen]` handle, and each transition takes
//! `self` by value. wasm-bindgen nulls the JavaScript object's pointer when a
//! method consumes it, so a caller physically cannot reuse a state it has
//! already advanced or retry one whose transition failed. The typestate in
//! `ceremony` and the JavaScript-visible object graph enforce the same rule.
//!
//! What crosses this boundary inbound: public protocol messages, the factor
//! secret whose KEK opens the envelope, and the recovery codes. What crosses
//! outbound: public protocol messages, ciphertext, and public records. Never a
//! seed, an owner root, a KEK, a manifest proof, or the ECDSA pending blob.
//!
//! Yao activation entropy is generated here rather than accepted, so a caller
//! cannot supply the recipient key material or the Deriver seal seeds. The
//! Rust-side `RegistrationProtocolInputsV1` still takes entropy, because the
//! circuit tests must control it to play the Deriver roles; JavaScript cannot.

use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    RouterAbEd25519YaoActivationAdmissionReceiptV1, RouterAbEd25519YaoApplicationBindingFactsV1,
};
use router_ab_ed25519_yao_client::ClientActivationEntropyV1;
use serde::Deserialize;
use signer_core::commands::RelayerPublicIdentityV1;
use signer_core::ecdsa_role_local_client::command::RelayerPublicIdentityInput;
use signer_core::passkey_custody::WalletCustodyEnvelopeFactorV1;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

use crate::ceremony::{
    CeremonyError, CeremonyManifestEstablishedV1, CeremonyProtocolsCompletedV1,
    CeremonyProtocolsPreparedV1, CeremonySeedHeldV1, FactorSealInputsV1, RecoveryCodeInputV1,
    RegistrationIdentityInputsV1, RegistrationProtocolInputsV1,
};

fn js_error(message: impl core::fmt::Display) -> JsValue {
    JsValue::from_str(&message.to_string())
}

fn ceremony_error(error: CeremonyError) -> JsValue {
    js_error(error.message())
}

/// Decoders return `String` rather than `JsValue`, and the `#[wasm_bindgen]`
/// methods convert at the edge. `JsValue::from_str` aborts on non-wasm32
/// targets, so building errors inside these would make them untestable on the
/// host — and these hand-written parsers are exactly the part worth testing.
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
struct RegistrationProtocolInputsWireV1 {
    yao_admission: RouterAbEd25519YaoActivationAdmissionReceiptV1,
    yao_application: RouterAbEd25519YaoApplicationBindingFactsV1,
    client_participant_id: u16,
    signing_worker_participant_id: u16,
    /// From the relayer's ECDSA registration bootstrap. The Ed25519 digest has
    /// no counterpart here: the ceremony computes it from `yaoApplication`.
    ecdsa_application_binding_digest_b64u: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RegistrationIdentityInputsWireV1 {
    near_ed25519_signing_key_id: String,
    evm_family_signing_key_slot_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FactorSealInputsWireV1 {
    envelope_id: String,
    factor: WalletCustodyEnvelopeFactorV1,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecoveryCodeInputWireV1 {
    recovery_key_id: String,
    code_bytes_b64u: String,
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

/// State 1. Holds the wallet custody seed and nothing else.
#[wasm_bindgen]
pub struct WasmCeremonySeedHeldV1 {
    inner: CeremonySeedHeldV1,
}

/// State 2. Both protocols are prepared; the roots are already gone.
#[wasm_bindgen]
pub struct WasmCeremonyProtocolsPreparedV1 {
    inner: CeremonyProtocolsPreparedV1,
}

/// State 3. Both protocols returned; the public identities are known.
#[wasm_bindgen]
pub struct WasmCeremonyProtocolsCompletedV1 {
    inner: CeremonyProtocolsCompletedV1,
}

/// State 4. The key manifest is established and its proof exists — inside this
/// handle only. There is deliberately no accessor for it.
#[wasm_bindgen]
pub struct WasmCeremonyManifestEstablishedV1 {
    inner: CeremonyManifestEstablishedV1,
}

/// Begins a wallet custody registration ceremony.
///
/// The seed is generated inside wasm. JavaScript cannot supply custody
/// material, so a caller cannot register a seed it chose or observed.
#[wasm_bindgen]
pub fn wallet_custody_ceremony_begin_registration_v1(
    wallet_id: &str,
) -> Result<WasmCeremonySeedHeldV1, JsValue> {
    Ok(WasmCeremonySeedHeldV1 {
        inner: CeremonySeedHeldV1::generate(wallet_id).map_err(ceremony_error)?,
    })
}

#[wasm_bindgen]
impl WasmCeremonySeedHeldV1 {
    /// Derives both owner roots and starts both protocols.
    ///
    /// Consumes this handle: a failed preparation leaves no state to retry
    /// from, and the seed is zeroized with it.
    pub fn prepare(self, inputs_json: &str) -> Result<WasmCeremonyProtocolsPreparedV1, JsValue> {
        let wire = serde_json::from_str::<RegistrationProtocolInputsWireV1>(inputs_json)
            .map_err(js_error)?;
        let entropy = ClientActivationEntropyV1::new(
            random32("recipient key material").map_err(js_error)?,
            random32("Deriver A seal seed").map_err(js_error)?,
            random32("Deriver B seal seed").map_err(js_error)?,
        )
        .map_err(|error| js_error(format!("activation entropy: {error:?}")))?;

        let inputs = RegistrationProtocolInputsV1 {
            yao_admission: wire.yao_admission,
            yao_application: wire.yao_application,
            participant_ids: [
                wire.client_participant_id,
                wire.signing_worker_participant_id,
            ],
            yao_entropy: entropy,
            ecdsa_application_binding_digest: decode_fixed(
                &wire.ecdsa_application_binding_digest_b64u,
                "ecdsaApplicationBindingDigestB64u",
            )
            .map_err(js_error)?,
        };
        Ok(WasmCeremonyProtocolsPreparedV1 {
            inner: self.inner.prepare(inputs).map_err(ceremony_error)?,
        })
    }
}

#[wasm_bindgen]
impl WasmCeremonyProtocolsPreparedV1 {
    /// The opaque Router execution request. Public protocol data.
    pub fn yao_execute_request_json(&self) -> String {
        self.inner.yao_execute_request_json().to_string()
    }

    /// The ECDSA bootstrap facts the relayer needs. Public protocol data.
    pub fn ecdsa_context_binding32_b64u(&self) -> String {
        self.inner.ecdsa_context_binding32_b64u()
    }

    pub fn ecdsa_client_share_public_key33_b64u(&self) -> String {
        self.inner.ecdsa_client_share_public_key33_b64u()
    }

    /// Completes both protocols from their terminal results.
    pub fn complete(
        self,
        yao_result_json: &str,
        relayer_public_identity_json: &str,
    ) -> Result<WasmCeremonyProtocolsCompletedV1, JsValue> {
        let wire = serde_json::from_str::<RelayerPublicIdentityV1>(relayer_public_identity_json)
            .map_err(js_error)?;
        Ok(WasmCeremonyProtocolsCompletedV1 {
            inner: self
                .inner
                .complete(yao_result_json, relayer_identity(wire).map_err(js_error)?)
                .map_err(ceremony_error)?,
        })
    }
}

#[wasm_bindgen]
impl WasmCeremonyProtocolsCompletedV1 {
    /// Builds the key manifest from what the protocols returned, and mints its
    /// proof. The proof does not cross this boundary.
    pub fn establish_manifest(
        self,
        identities_json: &str,
    ) -> Result<WasmCeremonyManifestEstablishedV1, JsValue> {
        let wire = serde_json::from_str::<RegistrationIdentityInputsWireV1>(identities_json)
            .map_err(js_error)?;
        Ok(WasmCeremonyManifestEstablishedV1 {
            inner: self
                .inner
                .establish_manifest(RegistrationIdentityInputsV1 {
                    near_ed25519_signing_key_id: wire.near_ed25519_signing_key_id,
                    evm_family_signing_key_slot_id: wire.evm_family_signing_key_slot_id,
                })
                .map_err(ceremony_error)?,
        })
    }
}

#[wasm_bindgen]
impl WasmCeremonyManifestEstablishedV1 {
    /// Seals the seed under the factor and under the recovery set, and returns
    /// the records the server write needs.
    ///
    /// Verification and sealing are one transition. There is no way to obtain
    /// a verified state here and seal later, or to seal twice: this handle is
    /// consumed either way.
    pub fn seal(
        self,
        factor_json: &str,
        factor_secret: &[u8],
        recovery_codes_json: &str,
    ) -> Result<JsValue, JsValue> {
        let factor_wire =
            serde_json::from_str::<FactorSealInputsWireV1>(factor_json).map_err(js_error)?;
        let code_wires = serde_json::from_str::<Vec<RecoveryCodeInputWireV1>>(recovery_codes_json)
            .map_err(js_error)?;

        let mut recovery_codes = Vec::with_capacity(code_wires.len());
        for wire in code_wires {
            recovery_codes.push(RecoveryCodeInputV1 {
                recovery_key_id: wire.recovery_key_id,
                code_bytes: Zeroizing::new(
                    decode_b64u(&wire.code_bytes_b64u, "codeBytesB64u").map_err(js_error)?,
                ),
            });
        }

        let payload = self
            .inner
            .seal(
                FactorSealInputsV1 {
                    envelope_id: factor_wire.envelope_id,
                    factor: factor_wire.factor,
                    factor_secret: Zeroizing::new(factor_secret.to_vec()),
                },
                recovery_codes,
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
        assert_eq!(address[1], 0x11);
        assert_eq!(address[19], 0x33);

        // Uppercase hex is the checksummed spelling and must parse the same.
        assert_eq!(
            decode_ethereum_address20("0x00112233445566778899AABBCCDDEEFF00112233")
                .expect("checksummed address"),
            address
        );

        for rejected in [
            "00112233445566778899aabbccddeeff00112233", // missing 0x
            "0x00112233445566778899aabbccddeeff001122", // 19 bytes
            "0x00112233445566778899aabbccddeeff0011223344", // 21 bytes
            "0x00112233445566778899aabbccddeeff001122zz", // not hexadecimal
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
    fn protocol_inputs_have_no_field_for_the_ed25519_binding_digest() {
        // `deny_unknown_fields` is what makes this a boundary guarantee rather
        // than a convention: a caller that tries to supply the Ed25519 digest
        // is rejected outright instead of having it silently ignored.
        // The unknown field comes first: serde reports fields in document
        // order, so this fails on the rejection under test rather than on the
        // placeholder protocol records that follow it.
        let json = r#"{
            "ed25519ApplicationBindingDigestB64u": "AAAA",
            "yaoAdmission": {},
            "yaoApplication": {},
            "clientParticipantId": 1,
            "signingWorkerParticipantId": 2,
            "ecdsaApplicationBindingDigestB64u": "AAAA"
        }"#;
        let error = match serde_json::from_str::<RegistrationProtocolInputsWireV1>(json) {
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
}
