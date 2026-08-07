//! The wallet custody registration ceremony, as a typestate.
//!
//! ```text
//! seed held → protocols prepared → protocols completed → manifest established
//!           → envelopes sealed → public commit payload
//! ```
//!
//! Every transition consumes `self` by value. A failing transition therefore
//! drops the state it was given, and every secret the state holds is behind
//! `Zeroizing`, so a failure destroys the seed, the derived roots, and the
//! in-flight protocol state rather than leaving them for a caller to retry
//! from. There is no way to hold a half-finished ceremony.
//!
//! Both owner roots are derived here and consumed here. They are never fields
//! of any state: they exist only inside [`CeremonySeedHeldV1::prepare`], where
//! they pass straight into the two protocol preparations. Nothing a caller can
//! reach ever holds a root.
//!
//! The Ed25519 application binding digest is computed inside this module from
//! the typed application facts, so a caller cannot bind the Ed25519 root to a
//! digest the Yao protocol will not verify. The ECDSA binding digest is a
//! protocol input carried in the relayer's bootstrap response and cannot be
//! recomputed here; the ECDSA protocol binds it through `contextBinding32`,
//! which the caller checks against the relayer's copy. That asymmetry is a
//! property of the two protocols, not of this module.

use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    RouterAbEd25519YaoActivationAdmissionReceiptV1, RouterAbEd25519YaoActivationResultV1,
    RouterAbEd25519YaoApplicationBindingFactsV1,
};
use router_ab_ecdsa_derivation::RouterAbEcdsaDerivationStableKeyContext;
use router_ab_ed25519_yao_client::{
    client_application_binding_digest_v1, complete_client_activation_v1,
    prepare_client_registration_with_root_v1, ClientActivationEntropyV1, ClientActivationStateV1,
};
use signer_core::ecdsa_role_local_client::command::{
    finalize_ecdsa_client_bootstrap, prepare_ecdsa_client_bootstrap,
    EcdsaRoleLocalPendingStateBlob, FinalizeEcdsaClientBootstrapCommand,
    PrepareEcdsaClientBootstrapCommand, RelayerPublicIdentityInput,
};
use signer_core::ed25519_yao_derivation::Ed25519YaoClientDerivationRootV1;
use signer_core::passkey_custody::{
    seal_wallet_custody_seed_envelope_v1, PasskeyCustodyEnvelopeBindingV1,
    PasskeyCustodySecretBindingV1, WalletCustodyEnvelopeFactorV1, PASSKEY_CUSTODY_KEY_LEN,
    WALLET_SEED_DERIVATION_SCHEME_V1,
};
use signer_core::wallet_recovery_custody::{
    seal_wallet_recovery_entry_v1, seal_wallet_recovery_manifest_kek_v1, WALLET_RECOVERY_CODE_COUNT,
};
use signer_core::wallet_seed_derivation::{
    derive_wallet_seed_owner_roots_v1, establish_wallet_key_manifest_v1,
    VerifiedWalletKeyManifestDigestV1, WalletKeyManifestV1, WALLET_CUSTODY_SEED_LEN,
};
use zeroize::Zeroizing;

pub const PASSKEY_CUSTODY_NONCE_LEN: usize = 12;

#[derive(Debug)]
pub struct CeremonyError(String);

impl CeremonyError {
    fn new(message: impl core::fmt::Display) -> Self {
        Self(message.to_string())
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for CeremonyError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(&self.0)
    }
}

type CeremonyResult<T> = Result<T, CeremonyError>;

fn random_bytes(out: &mut [u8]) -> CeremonyResult<()> {
    getrandom::getrandom(out).map_err(|_| CeremonyError::new("randomness is unavailable"))
}

fn b64u(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Everything the two protocol preparations need, all of it public.
///
/// The Ed25519 binding digest is deliberately absent: it is computed from
/// `yao_application` and `participant_ids` inside the ceremony.
pub struct RegistrationProtocolInputsV1 {
    pub yao_admission: RouterAbEd25519YaoActivationAdmissionReceiptV1,
    pub yao_application: RouterAbEd25519YaoApplicationBindingFactsV1,
    pub participant_ids: [u16; 2],
    pub yao_entropy: ClientActivationEntropyV1,
    /// From the relayer's ECDSA registration bootstrap. See the module note.
    pub ecdsa_application_binding_digest: [u8; 32],
}

/// The public identities the ceremony records for the wallet.
pub struct RegistrationIdentityInputsV1 {
    pub near_ed25519_signing_key_id: String,
    pub evm_family_signing_key_slot_id: String,
}

/// One recovery code's identity and secret bytes.
pub struct RecoveryCodeInputV1 {
    pub recovery_key_id: String,
    pub code_bytes: Zeroizing<Vec<u8>>,
}

/// What the factor contributes to sealing: its identity, and the secret its KEK
/// derives from — a passkey PRF result, or the Email OTP factor key.
pub struct FactorSealInputsV1 {
    pub envelope_id: String,
    pub factor: WalletCustodyEnvelopeFactorV1,
    pub factor_secret: Zeroizing<Vec<u8>>,
}

/// State 1: a seed exists and nothing else does.
pub struct CeremonySeedHeldV1 {
    wallet_id: String,
    seed: Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]>,
}

/// State 2: both roots were derived and handed to their protocols. The roots
/// are already gone; what remains is per-protocol session state.
pub struct CeremonyProtocolsPreparedV1 {
    wallet_id: String,
    seed: Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]>,
    yao_state: ClientActivationStateV1,
    yao_execute_request_json: String,
    /// Held as `Zeroizing` because the role-local pending blob carries the
    /// client's scalar share in the clear. The blob never crosses the wasm
    /// boundary — that is the whole reason this module exists — so it is kept
    /// here rather than handed to JavaScript between rounds.
    ecdsa_pending_state_blob: Zeroizing<Vec<u8>>,
    ecdsa_context_binding32: [u8; 32],
    ecdsa_client_share_public_key33: [u8; 33],
}

/// State 3: both protocols returned. Public identities are now known.
pub struct CeremonyProtocolsCompletedV1 {
    wallet_id: String,
    seed: Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]>,
    registered_public_key: [u8; 32],
    client_root_public_key33: [u8; 33],
    ecdsa_ready_state_blob: Zeroizing<Vec<u8>>,
}

/// State 4: the key manifest is established, and the proof exists.
pub struct CeremonyManifestEstablishedV1 {
    seed: Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]>,
    manifest: WalletKeyManifestV1,
    verified: VerifiedWalletKeyManifestDigestV1,
    ecdsa_ready_state_blob: Zeroizing<Vec<u8>>,
}

/// One sealed recovery wrap, ready for the server record.
pub struct SealedRecoveryWrapRecordV1 {
    pub recovery_key_id: String,
    pub nonce_b64u: String,
    pub ciphertext_b64u: String,
    pub aad_hash_b64u: String,
}

/// Everything the ceremony hands back: ciphertext and public facts only.
///
/// JavaScript performs the server write with this. Nothing here opens anything,
/// and nothing here is a capability that could be replayed into a later seal.
pub struct WalletCustodyCommitPayloadV1 {
    pub wallet_id: String,
    pub envelope_id: String,
    pub key_manifest_digest_b64u: String,
    pub envelope_binding_json: String,
    pub envelope_nonce_b64u: String,
    pub sealed_custody_secret_b64u: String,
    pub envelope_aad_hash_b64u: String,
    pub envelope_ciphertext_digest_b64u: String,
    pub recovery_manifest_kek_wraps: Vec<SealedRecoveryWrapRecordV1>,
    pub recovery_entry_nonce_b64u: String,
    pub recovery_entry_ciphertext_b64u: String,
    pub recovery_entry_aad_hash_b64u: String,
    pub registered_public_key_b64u: String,
    pub client_root_public_key33_b64u: String,
    /// The finalized role-local material, still sealed to its own boundary.
    pub ecdsa_ready_state_blob_b64u: String,
}

impl CeremonySeedHeldV1 {
    /// Generates the wallet custody seed inside this module.
    ///
    /// This is the only way a seed enters a ceremony: JavaScript cannot supply
    /// custody material, so a caller cannot register a seed it chose or saw.
    pub fn generate(wallet_id: &str) -> CeremonyResult<Self> {
        let wallet_id = wallet_id.trim();
        if wallet_id.is_empty() {
            return Err(CeremonyError::new("walletId must not be empty"));
        }
        let mut seed = Zeroizing::new([0u8; WALLET_CUSTODY_SEED_LEN]);
        random_bytes(&mut seed[..])?;
        Ok(Self {
            wallet_id: wallet_id.to_string(),
            seed,
        })
    }

    /// Builds a ceremony over a fixed seed, for tests only.
    ///
    /// `generate` is the only way in outside tests. The circuit tests need two
    /// ceremonies to start from the *same* seed so they can compare what each
    /// one registers, which random generation cannot express.
    #[cfg(test)]
    pub(crate) fn from_seed_for_test(wallet_id: &str, seed: [u8; WALLET_CUSTODY_SEED_LEN]) -> Self {
        Self {
            wallet_id: wallet_id.to_string(),
            seed: Zeroizing::new(seed),
        }
    }

    /// Derives both owner roots and hands each to its protocol.
    ///
    /// The two derivations and the two protocol preparations happen here with
    /// nothing in between: there is no boundary at which a caller could observe
    /// a root or substitute a binding. The Ed25519 digest comes from
    /// `client_application_binding_digest_v1`, the same function the protocol
    /// verifies against.
    pub fn prepare(
        self,
        inputs: RegistrationProtocolInputsV1,
    ) -> CeremonyResult<CeremonyProtocolsPreparedV1> {
        let ed25519_binding_digest =
            client_application_binding_digest_v1(&inputs.yao_application, inputs.participant_ids)
                .map_err(|error| CeremonyError::new(format!("Ed25519 binding digest: {error:?}")))?;

        let roots = derive_wallet_seed_owner_roots_v1(
            &self.seed[..],
            &ed25519_binding_digest,
            &inputs.ecdsa_application_binding_digest,
        )
        .map_err(|error| CeremonyError::new(format!("owner root derivation: {error}")))?;

        let prepared_yao = prepare_client_registration_with_root_v1(
            &inputs.yao_admission,
            &inputs.yao_application,
            inputs.participant_ids,
            Ed25519YaoClientDerivationRootV1::from_secret_bytes(*roots.ed25519_yao_client_root()),
            inputs.yao_entropy,
        )
        .map_err(|error| CeremonyError::new(format!("Yao registration: {error:?}")))?;
        let (yao_execute_request, yao_state) = prepared_yao.into_parts();
        let yao_execute_request_json = serde_json::to_string(&yao_execute_request)
            .map_err(|error| CeremonyError::new(format!("Yao execute request: {error}")))?;

        let context =
            RouterAbEcdsaDerivationStableKeyContext::new(inputs.ecdsa_application_binding_digest);
        context
            .validate()
            .map_err(|error| CeremonyError::new(format!("ECDSA context: {error}")))?;
        let prepared_ecdsa = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
            context,
            client_root_share32: *roots.ecdsa_client_root_share(),
        })
        .map_err(|error| CeremonyError::new(format!("ECDSA bootstrap: {error}")))?;

        Ok(CeremonyProtocolsPreparedV1 {
            wallet_id: self.wallet_id,
            seed: self.seed,
            yao_state,
            yao_execute_request_json,
            ecdsa_pending_state_blob: Zeroizing::new(
                prepared_ecdsa.pending_state_blob.state_blob.clone(),
            ),
            ecdsa_context_binding32: prepared_ecdsa.public_facts.context_binding32,
            ecdsa_client_share_public_key33: prepared_ecdsa
                .public_facts
                .derivation_client_share_public_key33,
        })
    }
}

impl CeremonyProtocolsPreparedV1 {
    /// The opaque Router execution request. Public protocol data.
    pub fn yao_execute_request_json(&self) -> &str {
        &self.yao_execute_request_json
    }

    /// The ECDSA bootstrap facts the relayer needs. Public protocol data.
    pub fn ecdsa_context_binding32_b64u(&self) -> String {
        b64u(&self.ecdsa_context_binding32)
    }

    pub fn ecdsa_client_share_public_key33_b64u(&self) -> String {
        b64u(&self.ecdsa_client_share_public_key33)
    }

    /// Completes both protocols from their terminal results.
    pub fn complete(
        self,
        yao_result_json: &str,
        relayer_public_identity: RelayerPublicIdentityInput,
    ) -> CeremonyResult<CeremonyProtocolsCompletedV1> {
        let yao_result =
            serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(yao_result_json)
                .map_err(|error| CeremonyError::new(format!("Yao result: {error}")))?;
        let activated = complete_client_activation_v1(self.yao_state, &yao_result)
            .map_err(|error| CeremonyError::new(format!("Yao activation: {error:?}")))?;

        let finalized = finalize_ecdsa_client_bootstrap(FinalizeEcdsaClientBootstrapCommand {
            pending_state_blob: EcdsaRoleLocalPendingStateBlob {
                state_blob: self.ecdsa_pending_state_blob.to_vec(),
            },
            relayer_public_identity,
        })
        .map_err(|error| CeremonyError::new(format!("ECDSA finalize: {error}")))?;

        Ok(CeremonyProtocolsCompletedV1 {
            wallet_id: self.wallet_id,
            seed: self.seed,
            registered_public_key: activated.registered_public_key(),
            client_root_public_key33: self.ecdsa_client_share_public_key33,
            ecdsa_ready_state_blob: Zeroizing::new(finalized.ready_state_blob.state_blob.clone()),
        })
    }
}

impl CeremonyProtocolsCompletedV1 {
    /// Builds the key manifest from what the protocols returned and mints its
    /// proof.
    ///
    /// The two public keys come from the completed protocol state, not from
    /// arguments: a caller supplies only the two identifiers, so it cannot
    /// record a manifest naming keys the protocols did not produce.
    pub fn establish_manifest(
        self,
        identities: RegistrationIdentityInputsV1,
    ) -> CeremonyResult<CeremonyManifestEstablishedV1> {
        let manifest = WalletKeyManifestV1 {
            wallet_id: self.wallet_id,
            near_ed25519_signing_key_id: identities.near_ed25519_signing_key_id,
            registered_public_key: self.registered_public_key,
            evm_family_signing_key_slot_id: identities.evm_family_signing_key_slot_id,
            client_root_public_key33: self.client_root_public_key33,
        };
        let verified = establish_wallet_key_manifest_v1(&manifest)
            .map_err(|error| CeremonyError::new(format!("key manifest: {error}")))?;
        Ok(CeremonyManifestEstablishedV1 {
            seed: self.seed,
            manifest,
            verified,
            ecdsa_ready_state_blob: self.ecdsa_ready_state_blob,
        })
    }
}

impl CeremonyManifestEstablishedV1 {
    /// Seals the seed under the factor and under the recovery set, in one step.
    ///
    /// Verification and sealing are not separable from outside this module: the
    /// proof minted in the previous transition is a private field here and
    /// never crosses the wasm boundary, so there is no verified state a caller
    /// can hold, store, or replay into a later seal.
    ///
    /// Nonces are generated here rather than accepted, so a caller cannot reuse
    /// one across two seals under the same KEK.
    pub fn seal(
        self,
        factor: FactorSealInputsV1,
        recovery_codes: Vec<RecoveryCodeInputV1>,
    ) -> CeremonyResult<WalletCustodyCommitPayloadV1> {
        if recovery_codes.len() != WALLET_RECOVERY_CODE_COUNT {
            return Err(CeremonyError::new(format!(
                "a recovery set carries exactly {WALLET_RECOVERY_CODE_COUNT} codes"
            )));
        }
        let envelope_id = factor.envelope_id.trim().to_string();
        if envelope_id.is_empty() {
            return Err(CeremonyError::new("envelopeId must not be empty"));
        }

        let key_manifest_digest_b64u = self.verified.digest_b64u();
        let binding = PasskeyCustodyEnvelopeBindingV1 {
            wallet_id: self.manifest.wallet_id.clone(),
            envelope_id: envelope_id.clone(),
            factor: factor.factor,
            envelope_revision: 1,
            binding: PasskeyCustodySecretBindingV1::WalletCustodySeed {
                derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.to_string(),
                key_manifest_digest_b64u: key_manifest_digest_b64u.clone(),
                near_ed25519_signing_key_id: self.manifest.near_ed25519_signing_key_id.clone(),
                registered_public_key_b64u: b64u(&self.manifest.registered_public_key),
                evm_family_signing_key_slot_id: self
                    .manifest
                    .evm_family_signing_key_slot_id
                    .clone(),
                client_root_public_key33_b64u: b64u(&self.manifest.client_root_public_key33),
            },
        };

        let mut envelope_nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
        random_bytes(&mut envelope_nonce)?;
        let sealed_envelope = seal_wallet_custody_seed_envelope_v1(
            &factor.factor_secret,
            &binding,
            &self.verified,
            &envelope_nonce,
            &self.seed[..],
        )
        .map_err(|error| CeremonyError::new(format!("seed envelope seal: {error}")))?;

        let mut manifest_kek = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
        random_bytes(&mut manifest_kek[..])?;

        let mut recovery_manifest_kek_wraps = Vec::with_capacity(recovery_codes.len());
        for code in &recovery_codes {
            let mut nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
            random_bytes(&mut nonce)?;
            let wrap = seal_wallet_recovery_manifest_kek_v1(
                &code.code_bytes,
                &self.manifest.wallet_id,
                &code.recovery_key_id,
                &self.verified,
                &nonce,
                &manifest_kek[..],
            )
            .map_err(|error| CeremonyError::new(format!("recovery code wrap: {error}")))?;
            recovery_manifest_kek_wraps.push(SealedRecoveryWrapRecordV1 {
                recovery_key_id: code.recovery_key_id.clone(),
                nonce_b64u: b64u(&nonce),
                ciphertext_b64u: wrap.ciphertext_b64u(),
                aad_hash_b64u: wrap.aad_hash_b64u(),
            });
        }

        let mut entry_nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
        random_bytes(&mut entry_nonce)?;
        let entry = seal_wallet_recovery_entry_v1(
            &manifest_kek[..],
            &self.manifest.wallet_id,
            &self.verified,
            &entry_nonce,
            &self.seed[..],
        )
        .map_err(|error| CeremonyError::new(format!("recovery entry seal: {error}")))?;

        let envelope_binding_json = serde_json::to_string(&binding)
            .map_err(|error| CeremonyError::new(format!("envelope binding: {error}")))?;

        Ok(WalletCustodyCommitPayloadV1 {
            wallet_id: self.manifest.wallet_id.clone(),
            envelope_id,
            key_manifest_digest_b64u,
            envelope_binding_json,
            envelope_nonce_b64u: b64u(&envelope_nonce),
            sealed_custody_secret_b64u: sealed_envelope.ciphertext_b64u(),
            envelope_aad_hash_b64u: sealed_envelope.aad_hash_b64u(),
            envelope_ciphertext_digest_b64u: sealed_envelope.ciphertext_digest_b64u(),
            recovery_manifest_kek_wraps,
            recovery_entry_nonce_b64u: b64u(&entry_nonce),
            recovery_entry_ciphertext_b64u: entry.ciphertext_b64u(),
            recovery_entry_aad_hash_b64u: entry.aad_hash_b64u(),
            registered_public_key_b64u: b64u(&self.manifest.registered_public_key),
            client_root_public_key33_b64u: b64u(&self.manifest.client_root_public_key33),
            ecdsa_ready_state_blob_b64u: b64u(&self.ecdsa_ready_state_blob),
        })
    }
}

#[cfg(test)]
mod tests {
    //! These own the ceremony's output contract: what `seal` produces must be
    //! openable by exactly the factor and recovery codes it was sealed for, and
    //! must reproduce the seed the ceremony generated.
    //!
    //! They start from `CeremonyProtocolsCompletedV1` because they live inside
    //! the module and can build it directly. Driving states 1 and 2 needs a
    //! real Router A/B circuit; that harness is the next step.

    use super::*;
    use signer_core::passkey_custody::{
        open_verified_passkey_custody_secret_v1, EMAIL_OTP_FACTOR_KEK_VERSION_V1,
    };
    use signer_core::wallet_recovery_custody::{
        open_wallet_recovery_entry_v1, open_wallet_recovery_manifest_kek_v1,
        WalletRecoveryCodeScopeV1, WalletRecoveryEntryScopeV1,
    };

    const WALLET_ID: &str = "alice.testnet";
    const FACTOR_SECRET: [u8; 32] = [7u8; 32];

    fn seed() -> Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]> {
        Zeroizing::new([13u8; WALLET_CUSTODY_SEED_LEN])
    }

    fn completed() -> CeremonyProtocolsCompletedV1 {
        let mut client_root_public_key33 = [11u8; 33];
        client_root_public_key33[0] = 0x02;
        CeremonyProtocolsCompletedV1 {
            wallet_id: WALLET_ID.to_string(),
            seed: seed(),
            registered_public_key: [21u8; 32],
            client_root_public_key33,
            ecdsa_ready_state_blob: Zeroizing::new(vec![1, 2, 3]),
        }
    }

    fn identities() -> RegistrationIdentityInputsV1 {
        RegistrationIdentityInputsV1 {
            near_ed25519_signing_key_id: "near-ed25519-key-1".to_string(),
            evm_family_signing_key_slot_id: "wallet-key:evm-family:alice.testnet:root-1:v1"
                .to_string(),
        }
    }

    fn factor() -> FactorSealInputsV1 {
        FactorSealInputsV1 {
            envelope_id: "wallet-custody-envelope-1".to_string(),
            factor: WalletCustodyEnvelopeFactorV1::EmailOtp {
                enrollment_id: "enrollment-1".to_string(),
                enrollment_seal_key_version: "seal-v1".to_string(),
                kek_version: EMAIL_OTP_FACTOR_KEK_VERSION_V1.to_string(),
            },
            factor_secret: Zeroizing::new(FACTOR_SECRET.to_vec()),
        }
    }

    fn recovery_codes(count: usize) -> Vec<RecoveryCodeInputV1> {
        (0..count)
            .map(|index| RecoveryCodeInputV1 {
                recovery_key_id: format!("email-otp-rkid-v1-code-{index}"),
                code_bytes: Zeroizing::new(vec![index as u8 + 1; 20]),
            })
            .collect()
    }

    fn decode(value: &str) -> Vec<u8> {
        Base64UrlUnpadded::decode_vec(value).expect("base64url")
    }

    fn commit() -> WalletCustodyCommitPayloadV1 {
        completed()
            .establish_manifest(identities())
            .expect("manifest")
            .seal(factor(), recovery_codes(WALLET_RECOVERY_CODE_COUNT))
            .expect("seal")
    }

    #[test]
    fn a_generated_seed_is_wallet_scoped_and_non_empty() {
        assert!(CeremonySeedHeldV1::generate("  ").is_err());
        let held = CeremonySeedHeldV1::generate(WALLET_ID).expect("seed held");
        assert_eq!(held.wallet_id, WALLET_ID);
        assert_ne!(held.seed[..], [0u8; WALLET_CUSTODY_SEED_LEN][..]);

        // Two ceremonies never share a seed.
        let other = CeremonySeedHeldV1::generate(WALLET_ID).expect("seed held");
        assert_ne!(held.seed[..], other.seed[..]);
    }

    #[test]
    fn the_sealed_envelope_opens_back_to_the_ceremony_seed() {
        let payload = commit();
        let binding =
            serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(&payload.envelope_binding_json)
                .expect("binding round-trips");

        let opened = open_verified_passkey_custody_secret_v1(
            &FACTOR_SECRET,
            &binding,
            &decode(&payload.envelope_nonce_b64u),
            &decode(&payload.sealed_custody_secret_b64u),
            &decode(&payload.envelope_aad_hash_b64u),
            &decode(&payload.envelope_ciphertext_digest_b64u),
        )
        .expect("envelope opens");
        assert_eq!(opened.as_slice(), &seed()[..]);
    }

    #[test]
    fn every_recovery_code_reaches_the_same_seed() {
        let payload = commit();
        let digest = decode(&payload.key_manifest_digest_b64u);
        let key_manifest_digest: [u8; 32] = digest.as_slice().try_into().expect("digest");
        let codes = recovery_codes(WALLET_RECOVERY_CODE_COUNT);
        assert_eq!(payload.recovery_manifest_kek_wraps.len(), codes.len());

        for (code, wrap) in codes.iter().zip(payload.recovery_manifest_kek_wraps.iter()) {
            assert_eq!(code.recovery_key_id, wrap.recovery_key_id);
            let manifest_kek = open_wallet_recovery_manifest_kek_v1(
                &code.code_bytes,
                &WalletRecoveryCodeScopeV1 {
                    wallet_id: WALLET_ID.to_string(),
                    recovery_key_id: wrap.recovery_key_id.clone(),
                    key_manifest_digest,
                },
                &decode(&wrap.nonce_b64u),
                &decode(&wrap.ciphertext_b64u),
            )
            .expect("manifest KEK opens");

            let recovered = open_wallet_recovery_entry_v1(
                &manifest_kek[..],
                &WalletRecoveryEntryScopeV1 {
                    wallet_id: WALLET_ID.to_string(),
                    key_manifest_digest,
                },
                &decode(&payload.recovery_entry_nonce_b64u),
                &decode(&payload.recovery_entry_ciphertext_b64u),
            )
            .expect("recovery entry opens");
            assert_eq!(recovered.as_slice(), &seed()[..]);
        }
    }

    #[test]
    fn the_envelope_records_the_manifest_the_protocols_produced() {
        let payload = commit();
        let source = completed();
        assert_eq!(
            payload.registered_public_key_b64u,
            b64u(&source.registered_public_key)
        );
        assert_eq!(
            payload.client_root_public_key33_b64u,
            b64u(&source.client_root_public_key33)
        );

        // The digest recorded on the envelope is the digest of that key set,
        // recomputed here from the public facts the payload carries.
        let manifest = WalletKeyManifestV1 {
            wallet_id: WALLET_ID.to_string(),
            near_ed25519_signing_key_id: identities().near_ed25519_signing_key_id,
            registered_public_key: source.registered_public_key,
            evm_family_signing_key_slot_id: identities().evm_family_signing_key_slot_id,
            client_root_public_key33: source.client_root_public_key33,
        };
        assert_eq!(
            payload.key_manifest_digest_b64u,
            establish_wallet_key_manifest_v1(&manifest)
                .unwrap()
                .digest_b64u()
        );
    }

    #[test]
    fn nonces_are_fresh_across_every_wrap_in_one_ceremony() {
        let payload = commit();
        let mut nonces = vec![
            payload.envelope_nonce_b64u.clone(),
            payload.recovery_entry_nonce_b64u.clone(),
        ];
        nonces.extend(
            payload
                .recovery_manifest_kek_wraps
                .iter()
                .map(|wrap| wrap.nonce_b64u.clone()),
        );
        let unique: std::collections::BTreeSet<_> = nonces.iter().collect();
        assert_eq!(unique.len(), nonces.len(), "a nonce was reused");
    }

    #[test]
    fn a_partial_recovery_set_is_refused() {
        for count in [
            0usize,
            1,
            WALLET_RECOVERY_CODE_COUNT - 1,
            WALLET_RECOVERY_CODE_COUNT + 1,
        ] {
            let sealed = completed()
                .establish_manifest(identities())
                .expect("manifest")
                .seal(factor(), recovery_codes(count));
            assert!(
                sealed.is_err(),
                "{count} codes must not produce a recovery set"
            );
        }
    }

    #[test]
    fn a_malformed_manifest_ends_the_ceremony_before_anything_is_sealed() {
        let mut broken = completed();
        // An uncompressed point is not a client root public key.
        broken.client_root_public_key33[0] = 0x04;
        assert!(broken.establish_manifest(identities()).is_err());

        let mut empty_slot = identities();
        empty_slot.evm_family_signing_key_slot_id = String::new();
        assert!(completed().establish_manifest(empty_slot).is_err());
    }
}
