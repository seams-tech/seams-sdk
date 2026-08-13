//! The wallet custody ceremony, as a typestate — one key set per run.
//!
//! ```text
//! seed held → protocol prepared → protocol completed → manifest established
//!           → commit payload
//! ```
//!
//! Every transition consumes `self` by value. A failing transition therefore
//! drops the state it was given, and every secret the state holds is behind
//! `Zeroizing`, so a failure destroys the seed, the derived root, and the
//! in-flight protocol state rather than leaving them for a caller to retry
//! from. There is no way to hold a half-finished ceremony.
//!
//! One run provisions one key set. The EVM-family and NEAR Ed25519 key sets
//! are independent and may be provisioned at different times, so a run either
//! *establishes* custody — generating the seed, sealing its envelope, and
//! issuing the recovery set — or *adds a key set* to custody that already
//! exists, deriving from the same seed and writing nothing but its own
//! manifest. A run never generates a second seed for a wallet: that would
//! split custody permanently, and no recovery set would cover both halves.
//!
//! The derived root is never a field of any state. It exists only inside
//! [`CeremonySeedHeldV1::prepare`], where it passes straight into its protocol.
//!
//! The Ed25519 application binding digest is computed here from the typed
//! application facts, so a caller cannot bind the root to a digest the Yao
//! protocol will not verify. The ECDSA binding digest is a protocol input from
//! the relayer's bootstrap response and cannot be recomputed here; the ECDSA
//! protocol binds it through `contextBinding32`, which the caller checks
//! against the relayer's copy. That asymmetry belongs to the protocols.

use base64ct::{Base64UrlUnpadded, Encoding};
use router_ab_core::{
    RouterAbEd25519YaoActivationAdmissionReceiptV1, RouterAbEd25519YaoActivationResultV1,
    RouterAbEd25519YaoApplicationBindingFactsV1,
};
use router_ab_ecdsa_derivation::RouterAbEcdsaDerivationStableKeyContext;
use router_ab_ed25519_yao_client::{
    client_application_binding_digest_v1, complete_client_activation_v1,
    ed25519_local_material_binding_v1, prepare_client_recovery_with_root_v1,
    prepare_client_registration_with_root_v1, seal_activated_client_under_custody_seed_v1,
    ActivatedClientV1, ClientActivationEntropyV1, ClientActivationStateV1,
};
use signer_core::ecdsa_role_local_client::command::{
    finalize_ecdsa_client_bootstrap, prepare_ecdsa_client_bootstrap,
    EcdsaRoleLocalPendingStateBlob, FinalizeEcdsaClientBootstrapCommand,
    PrepareEcdsaClientBootstrapCommand, RelayerPublicIdentityInput,
};
use signer_core::ed25519_yao_derivation::Ed25519YaoClientDerivationRootV1;
use signer_core::passkey_custody::{
    open_wallet_custody_seed_envelope_v1, seal_wallet_custody_seed_envelope_v1, sha256_digest,
    PasskeyCustodyEnvelopeBindingV1, PasskeyCustodySecretBindingV1, WalletCustodyEnvelopeFactorV1,
    PASSKEY_CUSTODY_KEY_LEN, WALLET_SEED_DERIVATION_SCHEME_V1,
};
use signer_core::wallet_recovery_custody::{
    derive_wallet_recovery_key_id_v1, encode_recovery_entry_aad_v1,
    encode_recovery_manifest_aad_v1, open_wallet_custody_seed_with_recovery_code_v1,
    seal_wallet_recovery_entry_v1, seal_wallet_recovery_manifest_kek_v1, WalletRecoveryCodeScopeV1,
    WalletRecoveryEntryScopeV1, WalletRecoveryManifestKekWrapV1, WALLET_RECOVERY_CODE_COUNT,
};
use signer_core::wallet_seed_derivation::{
    derive_ecdsa_client_root_share_from_seed_v1,
    derive_ed25519_local_material_cache_key_from_seed_v1,
    derive_ed25519_yao_client_root_from_seed_v1, establish_wallet_key_set_manifest_v1,
    verify_registered_wallet_key_set_manifest_v1, VerifiedWalletKeySetManifestDigestV1,
    WalletKeySetKindV1, WalletKeySetManifestV1, WALLET_CUSTODY_SEED_LEN,
};
use std::collections::BTreeSet;
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

/// Whether this run establishes custody or joins custody that already exists.
///
/// The distinction is not cosmetic: establishing writes the seed envelope and
/// the recovery set, and joining must write neither. A run that guessed wrong
/// and generated a fresh seed would leave the wallet with two seeds, only one
/// of which any recovery set covers.
enum CustodyOriginV1 {
    /// First key set for this wallet. The seed is generated here.
    Establish,
    /// Custody exists; the seed came from opening its envelope.
    ///
    /// A unit variant on purpose. The admission proof did its work at
    /// construction — only `join_existing_custody` can produce this, and only a
    /// successful open produces that — so carrying the proof further would be
    /// dead weight rather than extra evidence.
    Join,
    /// Recovery opened the wallet seed with a reserved recovery code.
    ///
    /// This run may reproduce and reactivate a registered key set. It writes
    /// neither a new recovery set nor the replacement factor envelope; the
    /// latter is a separate terminal recovery transition after every key in
    /// the server-resolved manifest has produced its activation receipt.
    Recover,
}

/// Everything one protocol needs, all of it public.
///
/// `continuity` carries the registered public key when this key set already has
/// a registration. Present means the run must reproduce that exact key rather
/// than establish a new one, which is what stops an induced re-run from
/// silently replacing a key set.
#[allow(clippy::large_enum_variant)]
pub enum KeySetProtocolInputsV1 {
    NearEd25519 {
        yao_admission: RouterAbEd25519YaoActivationAdmissionReceiptV1,
        yao_application: RouterAbEd25519YaoApplicationBindingFactsV1,
        participant_ids: [u16; 2],
        yao_entropy: ClientActivationEntropyV1,
        continuity: Option<[u8; 32]>,
    },
    EvmFamilyEcdsa {
        /// From the relayer's ECDSA registration bootstrap. See the module note.
        application_binding_digest: [u8; 32],
    },
}

impl KeySetProtocolInputsV1 {
    pub fn key_set(&self) -> WalletKeySetKindV1 {
        match self {
            Self::NearEd25519 { .. } => WalletKeySetKindV1::NearEd25519,
            Self::EvmFamilyEcdsa { .. } => WalletKeySetKindV1::EvmFamilyEcdsa,
        }
    }
}

/// The public identity this key set records.
pub enum KeySetIdentityInputsV1 {
    NearEd25519 {
        near_ed25519_signing_key_id: String,
    },
    EvmFamilyEcdsa {
        evm_family_signing_key_slot_id: String,
    },
}

/// One recovery code's secret bytes.
///
/// Carries no id. The id is derived here from the wallet and these bytes, so a
/// caller cannot point two codes at one wrap, name a wrap no code opens, or
/// disagree with the reader about what an id is. It comes back on the sealed
/// wrap instead.
pub struct RecoveryCodeInputV1 {
    pub code_bytes: Zeroizing<Vec<u8>>,
}

/// What the factor contributes when custody is established: its identity, and
/// the secret its KEK derives from.
pub struct FactorSealInputsV1 {
    pub envelope_id: String,
    pub factor: WalletCustodyEnvelopeFactorV1,
    pub factor_secret: Zeroizing<Vec<u8>>,
}

/// Opaque recovery-set ciphertext admitted at the wasm boundary.
///
/// The recovery key id is absent by construction. It is derived from the
/// wallet and code bytes inside `recover_with_code`, then used to select the
/// one wrap the code is allowed to open.
pub struct RecoveryCustodyOpenInputsV1 {
    pub wallet_id: String,
    pub wrap_nonce: Vec<u8>,
    pub wrapped_manifest_kek: Vec<u8>,
    pub wrap_aad_hash: [u8; 32],
    pub entry_nonce: Vec<u8>,
    pub wrapped_custody_seed: Vec<u8>,
    pub entry_aad_hash: [u8; 32],
}

/// State 1: a seed is held, and the run knows whether it owns custody.
pub struct CeremonySeedHeldV1 {
    wallet_id: String,
    seed: Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]>,
    origin: CustodyOriginV1,
}

/// State 2: the root was derived and handed to its protocol. The root is gone.
pub struct CeremonyProtocolPreparedV1 {
    wallet_id: String,
    seed: Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]>,
    origin: CustodyOriginV1,
    protocol: PreparedProtocolV1,
}

/// EVM activation state after the custody commit is ready for the registration request.
///
/// The seed and recovery codes are already gone. Only the opaque ECDSA pending
/// state remains, so the client can send the custody payload with `activate`
/// and complete its local share from the Router receipt without holding the
/// seed across the network round.
pub struct CeremonyEvmActivationPendingV1 {
    wallet_id: String,
    verified: VerifiedWalletKeySetManifestDigestV1,
    pending_state_blob: Zeroizing<Vec<u8>>,
    client_root_public_key33: [u8; 33],
}

#[allow(clippy::large_enum_variant)]
enum PreparedProtocolV1 {
    NearEd25519 {
        yao_state: ClientActivationStateV1,
        yao_execute_request_json: String,
        /// Carried forward so the continuity cache can be keyed and bound to
        /// this exact key set without recomputing it from inputs the run has
        /// already consumed.
        application_binding_digest: [u8; 32],
        participant_ids: [u16; 2],
    },
    EvmFamilyEcdsa {
        /// Held as `Zeroizing` because the role-local pending blob carries the
        /// client's scalar share in the clear. It never crosses the wasm
        /// boundary — that is the reason this module exists.
        pending_state_blob: Zeroizing<Vec<u8>>,
        context_binding32: [u8; 32],
        client_share_public_key33: [u8; 33],
        client_share_retry_counter: u32,
    },
}

/// State 3: the protocol returned. Its public identity is known.
pub struct CeremonyProtocolCompletedV1 {
    wallet_id: String,
    seed: Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]>,
    origin: CustodyOriginV1,
    completed: CompletedProtocolV1,
}

enum CompletedProtocolV1 {
    NearEd25519 {
        registered_public_key: [u8; 32],
        /// The digest this key set's root and cache were bound to.
        ///
        /// Reported because opening the cache has to rebuild the exact seal
        /// binding, and this is one of its fields. A reader that recomputed it
        /// from loose application facts could differ by one byte and hold a
        /// record that never opens.
        application_binding_digest: [u8; 32],
        /// The activated Client's material, already sealed as the same-device
        /// continuity cache.
        ///
        /// Sealed at completion rather than carried as live material and
        /// sealed later: the activated Client is the only thing that can sign
        /// for this key set, and holding it across two further state
        /// transitions would widen its lifetime for no gain. This arm once
        /// dropped it entirely, which left a registered key set with nothing
        /// to sign with — the ceremony *is* the registration for a
        /// seed-derived key set, so no other path holds this material.
        local_material_b64u: String,
        local_material_nonce_b64u: String,
    },
    EvmFamilyEcdsa {
        client_root_public_key33: [u8; 33],
        ready_state_blob: Zeroizing<Vec<u8>>,
        /// The public identity the finalize computed.
        ///
        /// Carried rather than dropped because the client's capability
        /// manifest is built from exactly these: the threshold group key, the
        /// address it projects to, and both shares' public keys. A run that
        /// returned only the sealed blob would leave the installer with
        /// material it could not describe, and re-deriving them outside the
        /// ceremony would mean trusting a second computation to agree with the
        /// one that actually produced the material.
        public_facts: EvmFamilyPublicFactsV1,
    },
}

/// The EVM-family run's registered public identity.
struct EvmFamilyPublicFactsV1 {
    context_binding32: [u8; 32],
    derivation_client_share_public_key33: [u8; 33],
    client_verifying_share33: [u8; 33],
    relayer_public_key33: [u8; 33],
    group_public_key33: [u8; 33],
    ethereum_address20: [u8; 20],
    client_share_retry_counter: u32,
    relayer_share_retry_counter: u32,
}

/// State 4: this key set's manifest is established or verified.
pub struct CeremonyManifestEstablishedV1 {
    wallet_id: String,
    seed: Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]>,
    origin: CustodyOriginV1,
    verified: VerifiedWalletKeySetManifestDigestV1,
    completed: CompletedProtocolV1,
}

/// One sealed recovery wrap, ready for the server record.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SealedRecoveryWrapRecordV1 {
    pub recovery_key_id: String,
    pub nonce_b64u: String,
    pub ciphertext_b64u: String,
    pub aad_hash_b64u: String,
}

/// The custody records a run writes when it establishes custody. Absent when
/// the run joined custody that already existed.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EstablishedCustodyRecordsV1 {
    pub envelope_id: String,
    pub envelope_binding_json: String,
    pub envelope_nonce_b64u: String,
    pub sealed_custody_secret_b64u: String,
    pub envelope_aad_hash_b64u: String,
    pub envelope_ciphertext_digest_b64u: String,
    pub recovery_manifest_kek_wraps: Vec<SealedRecoveryWrapRecordV1>,
    pub recovery_entry_nonce_b64u: String,
    pub recovery_entry_ciphertext_b64u: String,
    pub recovery_entry_aad_hash_b64u: String,
}

/// The replacement recovery set produced by an active-factor rotation.
///
/// The seed and manifest KEK remain inside the ceremony. Only the opaque
/// ciphertext records needed by the server's atomic CAS reach JavaScript.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RotatedRecoverySetV1 {
    pub wallet_id: String,
    pub recovery_manifest_kek_wraps: Vec<SealedRecoveryWrapRecordV1>,
    pub recovery_entry_nonce_b64u: String,
    pub recovery_entry_ciphertext_b64u: String,
    pub recovery_entry_aad_hash_b64u: String,
}

/// A recovered seed resealed under the replacement passkey factor.
///
/// Recovery codes remain unchanged and are therefore absent. The server owns
/// code consumption and stores this envelope only after every registered key
/// has an exact activation receipt for the reservation.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoveryReplacementEnvelopeV1 {
    pub envelope_id: String,
    pub envelope_binding_json: String,
    pub envelope_nonce_b64u: String,
    pub sealed_custody_secret_b64u: String,
    pub envelope_aad_hash_b64u: String,
    pub envelope_ciphertext_digest_b64u: String,
}

/// Everything the ceremony hands back: ciphertext and public facts only.
///
/// The key set's manifest digest is here to be written onto that key set's
/// *registration* state, not to a record of its own — a free-standing manifest
/// row could be deleted, and its absence would read as "not provisioned yet".
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WalletCustodyCommitPayloadV1 {
    pub wallet_id: String,
    pub key_set: String,
    pub key_manifest_digest_b64u: String,
    /// Present only when this run established custody.
    pub established_custody: Option<EstablishedCustodyRecordsV1>,
    /// Present only for a recovery continuity run chosen to reseal the seed
    /// under the replacement passkey.
    pub recovery_replacement_envelope: Option<RecoveryReplacementEnvelopeV1>,
    pub registered_public_key_b64u: Option<String>,
    /// The NEAR same-device continuity cache: the activated Client's material,
    /// sealed under a key derived from the wallet custody seed.
    ///
    /// Sealed under the *seed* rather than the factor that ran this ceremony,
    /// so every factor that can open the wallet's custody envelope reaches the
    /// same record. A per-factor wrap would guarantee a cache miss for any
    /// factor enrolled after registration, which is exactly the case this
    /// refactor exists to serve.
    ///
    /// It is a cache and never a source of truth: losing it costs a Router
    /// round, not the wallet.
    pub ed25519_local_material_b64u: Option<String>,
    /// The nonce the cache record was sealed with. Generated here, never
    /// accepted, so one cannot be reused across two seals under the same key.
    pub ed25519_local_material_nonce_b64u: Option<String>,
    /// The application binding digest this key set's cache was sealed against.
    /// Absent on an EVM run.
    pub ed25519_application_binding_digest_b64u: Option<String>,
    pub client_root_public_key33_b64u: Option<String>,
    pub ecdsa_ready_state_blob_b64u: Option<String>,
    /// The EVM-family run's registered public identity, as the client's
    /// capability manifest records it. Absent on a NEAR run.
    pub ecdsa_public_facts: Option<EvmFamilyPublicFactsRecordV1>,
}

/// The EVM-family public identity, base64url-encoded for the wire.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmFamilyPublicFactsRecordV1 {
    pub context_binding32_b64u: String,
    pub derivation_client_share_public_key33_b64u: String,
    pub client_verifying_share33_b64u: String,
    pub relayer_public_key33_b64u: String,
    pub group_public_key33_b64u: String,
    /// Lowercase 0x-prefixed, as every other address surface spells it.
    pub ethereum_address: String,
    pub client_share_retry_counter: u32,
    pub relayer_share_retry_counter: u32,
}

/// Local EVM material produced after the registration activation receipt arrives.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvmFamilyActivationCompletionV1 {
    pub wallet_id: String,
    pub key_manifest_digest_b64u: String,
    pub client_root_public_key33_b64u: String,
    pub ecdsa_ready_state_blob_b64u: String,
    pub ecdsa_public_facts: EvmFamilyPublicFactsRecordV1,
}

impl CeremonySeedHeldV1 {
    /// Establishes custody: generates the wallet custody seed inside this
    /// module. JavaScript cannot supply custody material, so a caller cannot
    /// register a seed it chose or observed.
    pub fn establish(wallet_id: &str) -> CeremonyResult<Self> {
        let wallet_id = require_wallet_id(wallet_id)?;
        let mut seed = Zeroizing::new([0u8; WALLET_CUSTODY_SEED_LEN]);
        random_bytes(&mut seed[..])?;
        Ok(Self {
            wallet_id,
            seed,
            origin: CustodyOriginV1::Establish,
        })
    }

    /// Joins custody that already exists by opening its envelope.
    ///
    /// This is how the second key set reaches the same seed. Opening is what
    /// authorises it: the envelope's AAD binds the seed to this wallet, so a
    /// successful open proves the seed is the wallet's own.
    pub fn join_existing_custody(
        factor_secret: &[u8],
        binding: &PasskeyCustodyEnvelopeBindingV1,
        nonce: &[u8],
        ciphertext: &[u8],
        expected_aad_hash: &[u8],
        expected_ciphertext_digest: &[u8],
    ) -> CeremonyResult<Self> {
        let (seed, admitted) = open_wallet_custody_seed_envelope_v1(
            factor_secret,
            binding,
            nonce,
            ciphertext,
            expected_aad_hash,
            expected_ciphertext_digest,
        )
        .map_err(|error| CeremonyError::new(format!("custody envelope open: {error}")))?;
        let seed: [u8; WALLET_CUSTODY_SEED_LEN] = seed
            .as_slice()
            .try_into()
            .map_err(|_| CeremonyError::new("custody seed has an unexpected length"))?;
        Ok(Self {
            wallet_id: require_wallet_id(admitted.wallet_id())?,
            seed: Zeroizing::new(seed),
            origin: CustodyOriginV1::Join,
        })
    }

    /// Opens the wallet seed through one reserved recovery code.
    ///
    /// Stored AAD hashes are checked before decryption. The code's derived id
    /// selects its wrap, so JavaScript cannot point a code at arbitrary
    /// ciphertext or choose a recovery identity. The resulting seed remains
    /// inside the ceremony and can only enter a registered-key continuity run.
    pub fn recover_with_code(
        recovery_code_bytes: &[u8],
        input: RecoveryCustodyOpenInputsV1,
    ) -> CeremonyResult<Self> {
        let wallet_id = require_wallet_id(&input.wallet_id)?;
        let recovery_key_id = derive_wallet_recovery_key_id_v1(&wallet_id, recovery_code_bytes)
            .map_err(|error| CeremonyError::new(format!("recovery key id: {error}")))?;
        let manifest_aad = encode_recovery_manifest_aad_v1(&WalletRecoveryCodeScopeV1 {
            wallet_id: wallet_id.clone(),
            recovery_key_id: recovery_key_id.clone(),
        })
        .map_err(|error| CeremonyError::new(format!("recovery manifest AAD: {error}")))?;
        if sha256_digest(&manifest_aad) != input.wrap_aad_hash {
            return Err(CeremonyError::new(
                "recovery manifest AAD hash does not match",
            ));
        }
        let entry_aad = encode_recovery_entry_aad_v1(&WalletRecoveryEntryScopeV1 {
            wallet_id: wallet_id.clone(),
        })
        .map_err(|error| CeremonyError::new(format!("recovery entry AAD: {error}")))?;
        if sha256_digest(&entry_aad) != input.entry_aad_hash {
            return Err(CeremonyError::new("recovery entry AAD hash does not match"));
        }

        let wrap = WalletRecoveryManifestKekWrapV1 {
            recovery_key_id: &recovery_key_id,
            nonce: &input.wrap_nonce,
            ciphertext: &input.wrapped_manifest_kek,
        };
        let seed = open_wallet_custody_seed_with_recovery_code_v1(
            &wallet_id,
            recovery_code_bytes,
            &[wrap],
            &input.entry_nonce,
            &input.wrapped_custody_seed,
        )
        .map_err(|error| CeremonyError::new(format!("recovery custody open: {error}")))?
        .ok_or_else(|| CeremonyError::new("that recovery code cannot open this wallet"))?;
        let seed: [u8; WALLET_CUSTODY_SEED_LEN] = seed
            .as_slice()
            .try_into()
            .map_err(|_| CeremonyError::new("recovered custody seed has an unexpected length"))?;
        Ok(Self {
            wallet_id,
            seed: Zeroizing::new(seed),
            origin: CustodyOriginV1::Recover,
        })
    }

    /// Reseals the wallet seed under a fresh manifest KEK and ten new recovery
    /// codes. The active factor has already opened the seed into this handle;
    /// no factor material or seed crosses the boundary.
    pub fn rotate_recovery_set(
        self,
        recovery_codes: Vec<RecoveryCodeInputV1>,
    ) -> CeremonyResult<RotatedRecoverySetV1> {
        let sealed = CeremonyManifestEstablishedV1::seal_recovery_set(
            &self.wallet_id,
            &self.seed,
            recovery_codes,
        )?;
        Ok(RotatedRecoverySetV1 {
            wallet_id: self.wallet_id,
            recovery_manifest_kek_wraps: sealed.recovery_manifest_kek_wraps,
            recovery_entry_nonce_b64u: b64u(&sealed.entry_nonce),
            recovery_entry_ciphertext_b64u: sealed.entry_ciphertext_b64u,
            recovery_entry_aad_hash_b64u: sealed.entry_aad_hash_b64u,
        })
    }

    /// Derives this key set's root and hands it to its protocol.
    ///
    /// The derivation and the protocol preparation happen here with nothing in
    /// between: there is no boundary at which a caller could observe the root
    /// or substitute a binding.
    pub fn prepare(
        self,
        inputs: KeySetProtocolInputsV1,
    ) -> CeremonyResult<CeremonyProtocolPreparedV1> {
        let protocol = match inputs {
            KeySetProtocolInputsV1::NearEd25519 {
                yao_admission,
                yao_application,
                participant_ids,
                yao_entropy,
                continuity,
            } => {
                let binding_digest =
                    client_application_binding_digest_v1(&yao_application, participant_ids)
                        .map_err(|error| {
                            CeremonyError::new(format!("Ed25519 binding digest: {error:?}"))
                        })?;
                let root =
                    derive_ed25519_yao_client_root_from_seed_v1(&self.seed[..], &binding_digest)
                        .map_err(|error| CeremonyError::new(format!("root derivation: {error}")))?;
                let root = Ed25519YaoClientDerivationRootV1::from_secret_bytes(*root);

                // A key set that already has a registration must reproduce it,
                // never establish a new one.
                let prepared = match continuity {
                    Some(expected_registered_public_key) => prepare_client_recovery_with_root_v1(
                        &yao_admission,
                        &yao_application,
                        participant_ids,
                        root,
                        expected_registered_public_key,
                        yao_entropy,
                    ),
                    None => prepare_client_registration_with_root_v1(
                        &yao_admission,
                        &yao_application,
                        participant_ids,
                        root,
                        yao_entropy,
                    ),
                }
                .map_err(|error| CeremonyError::new(format!("Yao preparation: {error:?}")))?;

                let (execute_request, yao_state) = prepared.into_parts();
                PreparedProtocolV1::NearEd25519 {
                    yao_state,
                    yao_execute_request_json: serde_json::to_string(&execute_request).map_err(
                        |error| CeremonyError::new(format!("Yao execute request: {error}")),
                    )?,
                    application_binding_digest: binding_digest,
                    participant_ids,
                }
            }
            KeySetProtocolInputsV1::EvmFamilyEcdsa {
                application_binding_digest,
            } => {
                let share = derive_ecdsa_client_root_share_from_seed_v1(
                    &self.seed[..],
                    &application_binding_digest,
                )
                .map_err(|error| CeremonyError::new(format!("share derivation: {error}")))?;
                let context =
                    RouterAbEcdsaDerivationStableKeyContext::new(application_binding_digest);
                context
                    .validate()
                    .map_err(|error| CeremonyError::new(format!("ECDSA context: {error}")))?;
                let prepared = prepare_ecdsa_client_bootstrap(PrepareEcdsaClientBootstrapCommand {
                    context,
                    client_root_share32: *share,
                })
                .map_err(|error| CeremonyError::new(format!("ECDSA bootstrap: {error}")))?;
                PreparedProtocolV1::EvmFamilyEcdsa {
                    pending_state_blob: Zeroizing::new(
                        prepared.pending_state_blob.state_blob.clone(),
                    ),
                    context_binding32: prepared.public_facts.context_binding32,
                    client_share_public_key33: prepared
                        .public_facts
                        .derivation_client_share_public_key33,
                    client_share_retry_counter: prepared
                        .client_bootstrap
                        .client_share_retry_counter,
                }
            }
        };

        Ok(CeremonyProtocolPreparedV1 {
            wallet_id: self.wallet_id,
            seed: self.seed,
            origin: self.origin,
            protocol,
        })
    }
}

/// Seals the activated Client for same-device rehydration.
///
/// The binding deliberately names no credential and no RP. This record is
/// factor-agnostic by construction — that is the whole reason it is sealed
/// under the seed — so binding it to whichever credential happened to run the
/// ceremony would reintroduce the coupling being removed. What it does name is
/// the key set (through the application binding digest, which already covers
/// the wallet, NEAR signing key, signing root and slot), the registered public
/// key, the participants, and the state epoch.
fn seal_ed25519_local_material_v1(
    seed: &[u8],
    activated: &ActivatedClientV1,
    application_binding_digest: &[u8; 32],
    participant_ids: [u16; 2],
) -> CeremonyResult<(String, String)> {
    let cache_key =
        derive_ed25519_local_material_cache_key_from_seed_v1(seed, application_binding_digest)
            .map_err(|error| CeremonyError::new(format!("cache key derivation: {error}")))?;
    let binding = ed25519_local_material_binding_v1(
        application_binding_digest,
        &activated.registered_public_key(),
        participant_ids,
        activated.state_epoch(),
    );
    // Generated here, never accepted, so a caller cannot reuse a nonce across
    // two seals under the same cache key.
    let mut nonce = [0u8; 12];
    random_bytes(&mut nonce)?;
    let sealed =
        seal_activated_client_under_custody_seed_v1(activated, &cache_key, &binding, &nonce)
            .map_err(|error| CeremonyError::new(format!("local material seal: {error}")))?;
    Ok((b64u(&sealed), b64u(&nonce)))
}

/// Encodes a 20-byte address the way `decode_ethereum_address20` reads one, so
/// the pair round-trips and the TypeScript side sees one spelling.
fn ethereum_address_0x(address20: &[u8; 20]) -> String {
    let mut out = String::with_capacity(42);
    out.push_str("0x");
    for byte in address20 {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn require_wallet_id(wallet_id: &str) -> CeremonyResult<String> {
    let wallet_id = wallet_id.trim();
    if wallet_id.is_empty() {
        return Err(CeremonyError::new("walletId must not be empty"));
    }
    Ok(wallet_id.to_string())
}

fn verify_key_set_manifest(
    manifest: &WalletKeySetManifestV1,
    recorded_key_manifest_digest: Option<&[u8]>,
) -> CeremonyResult<VerifiedWalletKeySetManifestDigestV1> {
    match recorded_key_manifest_digest {
        Some(recorded) => verify_registered_wallet_key_set_manifest_v1(manifest, recorded)
            .map_err(|error| CeremonyError::new(format!("key manifest: {error}"))),
        None => establish_wallet_key_set_manifest_v1(manifest)
            .map_err(|error| CeremonyError::new(format!("key manifest: {error}"))),
    }
}

fn finalize_evm_protocol(
    pending_state_blob: Zeroizing<Vec<u8>>,
    relayer_public_identity: RelayerPublicIdentityInput,
) -> CeremonyResult<(Zeroizing<Vec<u8>>, EvmFamilyPublicFactsV1)> {
    let finalized = finalize_ecdsa_client_bootstrap(FinalizeEcdsaClientBootstrapCommand {
        pending_state_blob: EcdsaRoleLocalPendingStateBlob {
            state_blob: pending_state_blob.to_vec(),
        },
        relayer_public_identity,
    })
    .map_err(|error| CeremonyError::new(format!("ECDSA finalize: {error}")))?;
    Ok((
        Zeroizing::new(finalized.ready_state_blob.state_blob.clone()),
        EvmFamilyPublicFactsV1 {
            context_binding32: finalized.public_facts.context_binding32,
            derivation_client_share_public_key33: finalized
                .public_facts
                .derivation_client_share_public_key33,
            client_verifying_share33: finalized.public_facts.client_verifying_share33,
            relayer_public_key33: finalized.public_facts.relayer_public_key33,
            group_public_key33: finalized.public_facts.group_public_key33,
            ethereum_address20: finalized.public_facts.ethereum_address20,
            client_share_retry_counter: finalized.public_facts.client_share_retry_counter,
            relayer_share_retry_counter: finalized.public_facts.relayer_share_retry_counter,
        },
    ))
}

fn ecdsa_public_facts_record(
    public_facts: &EvmFamilyPublicFactsV1,
) -> EvmFamilyPublicFactsRecordV1 {
    EvmFamilyPublicFactsRecordV1 {
        context_binding32_b64u: b64u(&public_facts.context_binding32),
        derivation_client_share_public_key33_b64u: b64u(
            &public_facts.derivation_client_share_public_key33,
        ),
        client_verifying_share33_b64u: b64u(&public_facts.client_verifying_share33),
        relayer_public_key33_b64u: b64u(&public_facts.relayer_public_key33),
        group_public_key33_b64u: b64u(&public_facts.group_public_key33),
        ethereum_address: ethereum_address_0x(&public_facts.ethereum_address20),
        client_share_retry_counter: public_facts.client_share_retry_counter,
        relayer_share_retry_counter: public_facts.relayer_share_retry_counter,
    }
}

impl CeremonyProtocolPreparedV1 {
    /// The opaque Router execution request, for a NEAR Ed25519 run.
    pub fn yao_execute_request_json(&self) -> Option<&str> {
        match &self.protocol {
            PreparedProtocolV1::NearEd25519 {
                yao_execute_request_json,
                ..
            } => Some(yao_execute_request_json),
            _ => None,
        }
    }

    /// The ECDSA bootstrap facts the relayer needs, for an EVM-family run.
    pub fn ecdsa_context_binding32_b64u(&self) -> Option<String> {
        match &self.protocol {
            PreparedProtocolV1::EvmFamilyEcdsa {
                context_binding32, ..
            } => Some(b64u(context_binding32)),
            _ => None,
        }
    }

    pub fn ecdsa_client_share_public_key33_b64u(&self) -> Option<String> {
        match &self.protocol {
            PreparedProtocolV1::EvmFamilyEcdsa {
                client_share_public_key33,
                ..
            } => Some(b64u(client_share_public_key33)),
            _ => None,
        }
    }

    pub fn ecdsa_client_share_retry_counter(&self) -> Option<u32> {
        match &self.protocol {
            PreparedProtocolV1::EvmFamilyEcdsa {
                client_share_retry_counter,
                ..
            } => Some(*client_share_retry_counter),
            _ => None,
        }
    }

    /// Produces the EVM custody commit before activation and retains only the
    /// opaque pending ECDSA state needed to consume the Router receipt.
    pub fn prepare_evm_activation(
        self,
        evm_family_signing_key_slot_id: String,
        recorded_key_manifest_digest: Option<&[u8]>,
        establish_with: Option<(FactorSealInputsV1, Vec<RecoveryCodeInputV1>)>,
    ) -> CeremonyResult<(CeremonyEvmActivationPendingV1, WalletCustodyCommitPayloadV1)> {
        self.prepare_evm_activation_inner(
            evm_family_signing_key_slot_id,
            recorded_key_manifest_digest,
            establish_with,
            None,
        )
    }

    /// Prepares EVM recovery activation and reseals the recovered seed under
    /// the replacement passkey before the network round. The seed is dropped
    /// here; only the opaque pending ECDSA state survives until the receipt.
    pub fn prepare_evm_recovery_activation(
        self,
        evm_family_signing_key_slot_id: String,
        recorded_key_manifest_digest: &[u8],
        replacement_factor: FactorSealInputsV1,
    ) -> CeremonyResult<(CeremonyEvmActivationPendingV1, WalletCustodyCommitPayloadV1)> {
        self.prepare_evm_activation_inner(
            evm_family_signing_key_slot_id,
            Some(recorded_key_manifest_digest),
            None,
            Some(replacement_factor),
        )
    }

    fn prepare_evm_activation_inner(
        self,
        evm_family_signing_key_slot_id: String,
        recorded_key_manifest_digest: Option<&[u8]>,
        establish_with: Option<(FactorSealInputsV1, Vec<RecoveryCodeInputV1>)>,
        replacement_factor: Option<FactorSealInputsV1>,
    ) -> CeremonyResult<(CeremonyEvmActivationPendingV1, WalletCustodyCommitPayloadV1)> {
        let PreparedProtocolV1::EvmFamilyEcdsa {
            pending_state_blob,
            client_share_public_key33,
            ..
        } = self.protocol
        else {
            return Err(CeremonyError::new("this ceremony is not an EVM-family run"));
        };
        let manifest = WalletKeySetManifestV1::EvmFamilyEcdsa {
            wallet_id: self.wallet_id.clone(),
            evm_family_signing_key_slot_id,
            client_root_public_key33: client_share_public_key33,
        };
        let verified = verify_key_set_manifest(&manifest, recorded_key_manifest_digest)?;
        let established_custody = established_custody_for_origin(
            &self.origin,
            &self.wallet_id,
            &self.seed,
            establish_with,
        )?;
        let recovery_replacement_envelope = recovery_replacement_for_origin(
            &self.origin,
            &self.wallet_id,
            &self.seed,
            replacement_factor,
        )?;
        let payload = WalletCustodyCommitPayloadV1 {
            wallet_id: self.wallet_id.clone(),
            key_set: verified.key_set().as_str().to_string(),
            key_manifest_digest_b64u: verified.digest_b64u(),
            established_custody,
            recovery_replacement_envelope,
            registered_public_key_b64u: None,
            ed25519_local_material_b64u: None,
            ed25519_local_material_nonce_b64u: None,
            ed25519_application_binding_digest_b64u: None,
            client_root_public_key33_b64u: Some(b64u(&client_share_public_key33)),
            ecdsa_ready_state_blob_b64u: None,
            ecdsa_public_facts: None,
        };
        Ok((
            CeremonyEvmActivationPendingV1 {
                wallet_id: self.wallet_id,
                verified,
                pending_state_blob,
                client_root_public_key33: client_share_public_key33,
            },
            payload,
        ))
    }

    /// Completes the NEAR Ed25519 run from its terminal Router result.
    pub fn complete_near_ed25519(
        self,
        yao_result_json: &str,
    ) -> CeremonyResult<CeremonyProtocolCompletedV1> {
        let PreparedProtocolV1::NearEd25519 {
            yao_state,
            application_binding_digest,
            participant_ids,
            ..
        } = self.protocol
        else {
            return Err(CeremonyError::new(
                "this ceremony is not a NEAR Ed25519 run",
            ));
        };
        let result = serde_json::from_str::<RouterAbEd25519YaoActivationResultV1>(yao_result_json)
            .map_err(|error| CeremonyError::new(format!("Yao result: {error}")))?;
        let activated = complete_client_activation_v1(yao_state, &result)
            .map_err(|error| CeremonyError::new(format!("Yao activation: {error:?}")))?;
        let (local_material_b64u, local_material_nonce_b64u) = seal_ed25519_local_material_v1(
            &self.seed[..],
            &activated,
            &application_binding_digest,
            participant_ids,
        )?;
        Ok(CeremonyProtocolCompletedV1 {
            wallet_id: self.wallet_id,
            seed: self.seed,
            origin: self.origin,
            completed: CompletedProtocolV1::NearEd25519 {
                registered_public_key: activated.registered_public_key(),
                application_binding_digest,
                local_material_b64u,
                local_material_nonce_b64u,
            },
        })
    }

    /// Completes the EVM-family run from the relayer's public identity.
    pub fn complete_evm_family(
        self,
        relayer_public_identity: RelayerPublicIdentityInput,
    ) -> CeremonyResult<CeremonyProtocolCompletedV1> {
        let PreparedProtocolV1::EvmFamilyEcdsa {
            pending_state_blob,
            client_share_public_key33,
            ..
        } = self.protocol
        else {
            return Err(CeremonyError::new("this ceremony is not an EVM-family run"));
        };
        let (ready_state_blob, public_facts) =
            finalize_evm_protocol(pending_state_blob, relayer_public_identity)?;
        Ok(CeremonyProtocolCompletedV1 {
            wallet_id: self.wallet_id,
            seed: self.seed,
            origin: self.origin,
            completed: CompletedProtocolV1::EvmFamilyEcdsa {
                client_root_public_key33: client_share_public_key33,
                ready_state_blob,
                public_facts,
            },
        })
    }
}

impl CeremonyEvmActivationPendingV1 {
    /// Completes local EVM material after the Router activation receipt.
    pub fn complete(
        self,
        relayer_public_identity: RelayerPublicIdentityInput,
    ) -> CeremonyResult<EvmFamilyActivationCompletionV1> {
        let (ready_state_blob, public_facts) =
            finalize_evm_protocol(self.pending_state_blob, relayer_public_identity)?;
        Ok(EvmFamilyActivationCompletionV1 {
            wallet_id: self.wallet_id,
            key_manifest_digest_b64u: self.verified.digest_b64u(),
            client_root_public_key33_b64u: b64u(&self.client_root_public_key33),
            ecdsa_ready_state_blob_b64u: b64u(&ready_state_blob),
            ecdsa_public_facts: ecdsa_public_facts_record(&public_facts),
        })
    }
}

impl CeremonyProtocolCompletedV1 {
    /// Builds this key set's manifest from what the protocol returned.
    ///
    /// `recorded_key_manifest_digest` is the digest already riding this key
    /// set's registration state, when it has one. Present means the run must
    /// reproduce it and fails otherwise; absent means the key set is being
    /// provisioned for the first time and the digest is minted here.
    ///
    /// The public key comes from the completed protocol state, not from an
    /// argument, so a caller supplies only the identifier and cannot record a
    /// manifest naming a key the protocol did not produce.
    pub fn establish_manifest(
        self,
        identity: KeySetIdentityInputsV1,
        recorded_key_manifest_digest: Option<&[u8]>,
    ) -> CeremonyResult<CeremonyManifestEstablishedV1> {
        let manifest = match (&self.completed, identity) {
            (
                CompletedProtocolV1::NearEd25519 {
                    registered_public_key,
                    ..
                },
                KeySetIdentityInputsV1::NearEd25519 {
                    near_ed25519_signing_key_id,
                },
            ) => WalletKeySetManifestV1::NearEd25519 {
                wallet_id: self.wallet_id.clone(),
                near_ed25519_signing_key_id,
                registered_public_key: *registered_public_key,
            },
            (
                CompletedProtocolV1::EvmFamilyEcdsa {
                    client_root_public_key33,
                    ..
                },
                KeySetIdentityInputsV1::EvmFamilyEcdsa {
                    evm_family_signing_key_slot_id,
                },
            ) => WalletKeySetManifestV1::EvmFamilyEcdsa {
                wallet_id: self.wallet_id.clone(),
                evm_family_signing_key_slot_id,
                client_root_public_key33: *client_root_public_key33,
            },
            _ => {
                return Err(CeremonyError::new(
                    "identity inputs name a different key set than the completed protocol",
                ))
            }
        };

        let verified = verify_key_set_manifest(&manifest, recorded_key_manifest_digest)?;

        Ok(CeremonyManifestEstablishedV1 {
            wallet_id: self.wallet_id,
            seed: self.seed,
            origin: self.origin,
            verified,
            completed: self.completed,
        })
    }
}

impl CeremonyManifestEstablishedV1 {
    /// Produces the commit payload.
    ///
    /// A run that established custody seals the seed under the factor and
    /// issues the recovery set here. A run that joined existing custody writes
    /// neither: its whole output is this key set's manifest digest, and the
    /// seed it opened stays sealed exactly as it was.
    ///
    /// Nonces are generated here rather than accepted, so a caller cannot reuse
    /// one across two seals under the same KEK.
    pub fn finish(
        self,
        establish_with: Option<(FactorSealInputsV1, Vec<RecoveryCodeInputV1>)>,
    ) -> CeremonyResult<WalletCustodyCommitPayloadV1> {
        self.finish_inner(establish_with, None)
    }

    /// Finishes a verified recovery run and reseals the same seed under the
    /// replacement passkey factor. The recovery set is preserved server-side.
    pub fn finish_recovery(
        self,
        replacement_factor: FactorSealInputsV1,
    ) -> CeremonyResult<WalletCustodyCommitPayloadV1> {
        self.finish_inner(None, Some(replacement_factor))
    }

    fn finish_inner(
        self,
        establish_with: Option<(FactorSealInputsV1, Vec<RecoveryCodeInputV1>)>,
        replacement_factor: Option<FactorSealInputsV1>,
    ) -> CeremonyResult<WalletCustodyCommitPayloadV1> {
        let established_custody = established_custody_for_origin(
            &self.origin,
            &self.wallet_id,
            &self.seed,
            establish_with,
        )?;
        let recovery_replacement_envelope = recovery_replacement_for_origin(
            &self.origin,
            &self.wallet_id,
            &self.seed,
            replacement_factor,
        )?;

        let (
            registered_public_key_b64u,
            ed25519_local_material,
            client_root_public_key33_b64u,
            ecdsa_ready_state_blob_b64u,
        ) = match &self.completed {
            CompletedProtocolV1::NearEd25519 {
                registered_public_key,
                local_material_b64u,
                local_material_nonce_b64u,
                ..
            } => (
                Some(b64u(registered_public_key)),
                Some((
                    local_material_b64u.clone(),
                    local_material_nonce_b64u.clone(),
                )),
                None,
                None,
            ),
            CompletedProtocolV1::EvmFamilyEcdsa {
                client_root_public_key33,
                ready_state_blob,
                ..
            } => (
                None,
                None,
                Some(b64u(client_root_public_key33)),
                Some(b64u(ready_state_blob)),
            ),
        };
        let ecdsa_public_facts = match &self.completed {
            CompletedProtocolV1::EvmFamilyEcdsa { public_facts, .. } => {
                Some(ecdsa_public_facts_record(public_facts))
            }
            CompletedProtocolV1::NearEd25519 { .. } => None,
        };
        let (ed25519_local_material_b64u, ed25519_local_material_nonce_b64u) =
            match ed25519_local_material {
                Some((ciphertext, nonce)) => (Some(ciphertext), Some(nonce)),
                None => (None, None),
            };

        let ed25519_application_binding_digest_b64u = match &self.completed {
            CompletedProtocolV1::NearEd25519 {
                application_binding_digest,
                ..
            } => Some(b64u(application_binding_digest)),
            CompletedProtocolV1::EvmFamilyEcdsa { .. } => None,
        };

        Ok(WalletCustodyCommitPayloadV1 {
            wallet_id: self.wallet_id,
            key_set: self.verified.key_set().as_str().to_string(),
            key_manifest_digest_b64u: self.verified.digest_b64u(),
            established_custody,
            recovery_replacement_envelope,
            registered_public_key_b64u,
            ed25519_local_material_b64u,
            ed25519_local_material_nonce_b64u,
            ed25519_application_binding_digest_b64u,
            client_root_public_key33_b64u,
            ecdsa_ready_state_blob_b64u,
            ecdsa_public_facts,
        })
    }

    fn seal_new_custody(
        wallet_id: &str,
        seed: &[u8; WALLET_CUSTODY_SEED_LEN],
        factor: FactorSealInputsV1,
        recovery_codes: Vec<RecoveryCodeInputV1>,
    ) -> CeremonyResult<EstablishedCustodyRecordsV1> {
        let envelope = Self::seal_factor_envelope(wallet_id, seed, factor)?;
        let recovery = Self::seal_recovery_set(wallet_id, seed, recovery_codes)?;

        Ok(EstablishedCustodyRecordsV1 {
            envelope_id: envelope.envelope_id,
            envelope_binding_json: envelope.envelope_binding_json,
            envelope_nonce_b64u: envelope.envelope_nonce_b64u,
            sealed_custody_secret_b64u: envelope.sealed_custody_secret_b64u,
            envelope_aad_hash_b64u: envelope.envelope_aad_hash_b64u,
            envelope_ciphertext_digest_b64u: envelope.envelope_ciphertext_digest_b64u,
            recovery_manifest_kek_wraps: recovery.recovery_manifest_kek_wraps,
            recovery_entry_nonce_b64u: b64u(&recovery.entry_nonce),
            recovery_entry_ciphertext_b64u: recovery.entry_ciphertext_b64u,
            recovery_entry_aad_hash_b64u: recovery.entry_aad_hash_b64u,
        })
    }

    fn seal_recovery_set(
        wallet_id: &str,
        seed: &[u8; WALLET_CUSTODY_SEED_LEN],
        recovery_codes: Vec<RecoveryCodeInputV1>,
    ) -> CeremonyResult<SealedRecoverySetV1> {
        if recovery_codes.len() != WALLET_RECOVERY_CODE_COUNT {
            return Err(CeremonyError::new(format!(
                "a recovery set carries exactly {WALLET_RECOVERY_CODE_COUNT} codes"
            )));
        }

        let mut manifest_kek = Zeroizing::new([0u8; PASSKEY_CUSTODY_KEY_LEN]);
        random_bytes(&mut manifest_kek[..])?;

        let mut recovery_manifest_kek_wraps = Vec::with_capacity(recovery_codes.len());
        let mut seen_recovery_key_ids = BTreeSet::new();
        for code in &recovery_codes {
            let recovery_key_id = derive_wallet_recovery_key_id_v1(wallet_id, &code.code_bytes)
                .map_err(|error| CeremonyError::new(format!("recovery key id: {error}")))?;
            // Two identical codes derive one id and would silently reduce a
            // ten-code set to fewer usable codes, since a code is found by id.
            if !seen_recovery_key_ids.insert(recovery_key_id.clone()) {
                return Err(CeremonyError::new(
                    "a recovery set carries ten distinct codes",
                ));
            }
            let mut nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
            random_bytes(&mut nonce)?;
            let wrap = seal_wallet_recovery_manifest_kek_v1(
                &code.code_bytes,
                wallet_id,
                &recovery_key_id,
                &nonce,
                &manifest_kek[..],
            )
            .map_err(|error| CeremonyError::new(format!("recovery code wrap: {error}")))?;
            recovery_manifest_kek_wraps.push(SealedRecoveryWrapRecordV1 {
                recovery_key_id,
                nonce_b64u: b64u(&nonce),
                ciphertext_b64u: wrap.ciphertext_b64u(),
                aad_hash_b64u: wrap.aad_hash_b64u(),
            });
        }

        let mut entry_nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
        random_bytes(&mut entry_nonce)?;
        let entry = seal_wallet_recovery_entry_v1(&manifest_kek[..], wallet_id, &entry_nonce, seed)
            .map_err(|error| CeremonyError::new(format!("recovery entry seal: {error}")))?;

        Ok(SealedRecoverySetV1 {
            recovery_manifest_kek_wraps,
            entry_nonce,
            entry_ciphertext_b64u: entry.ciphertext_b64u(),
            entry_aad_hash_b64u: entry.aad_hash_b64u(),
        })
    }

    fn seal_factor_envelope(
        wallet_id: &str,
        seed: &[u8; WALLET_CUSTODY_SEED_LEN],
        factor: FactorSealInputsV1,
    ) -> CeremonyResult<RecoveryReplacementEnvelopeV1> {
        let envelope_id = factor.envelope_id.trim().to_string();
        if envelope_id.is_empty() {
            return Err(CeremonyError::new("envelopeId must not be empty"));
        }
        let binding = PasskeyCustodyEnvelopeBindingV1 {
            wallet_id: wallet_id.to_string(),
            envelope_id: envelope_id.clone(),
            factor: factor.factor,
            envelope_revision: 1,
            binding: PasskeyCustodySecretBindingV1::WalletCustodySeed {
                derivation_scheme: WALLET_SEED_DERIVATION_SCHEME_V1.to_string(),
            },
        };
        let mut nonce = [0u8; PASSKEY_CUSTODY_NONCE_LEN];
        random_bytes(&mut nonce)?;
        let sealed =
            seal_wallet_custody_seed_envelope_v1(&factor.factor_secret, &binding, &nonce, seed)
                .map_err(|error| CeremonyError::new(format!("seed envelope seal: {error}")))?;
        Ok(RecoveryReplacementEnvelopeV1 {
            envelope_id,
            envelope_binding_json: serde_json::to_string(&binding)
                .map_err(|error| CeremonyError::new(format!("envelope binding: {error}")))?,
            envelope_nonce_b64u: b64u(&nonce),
            sealed_custody_secret_b64u: sealed.ciphertext_b64u(),
            envelope_aad_hash_b64u: sealed.aad_hash_b64u(),
            envelope_ciphertext_digest_b64u: sealed.ciphertext_digest_b64u(),
        })
    }
}

struct SealedRecoverySetV1 {
    recovery_manifest_kek_wraps: Vec<SealedRecoveryWrapRecordV1>,
    entry_nonce: [u8; PASSKEY_CUSTODY_NONCE_LEN],
    entry_ciphertext_b64u: String,
    entry_aad_hash_b64u: String,
}

fn established_custody_for_origin(
    origin: &CustodyOriginV1,
    wallet_id: &str,
    seed: &[u8; WALLET_CUSTODY_SEED_LEN],
    establish_with: Option<(FactorSealInputsV1, Vec<RecoveryCodeInputV1>)>,
) -> CeremonyResult<Option<EstablishedCustodyRecordsV1>> {
    match (origin, establish_with) {
        (CustodyOriginV1::Establish, Some((factor, recovery_codes))) => {
            Ok(Some(CeremonyManifestEstablishedV1::seal_new_custody(
                wallet_id,
                seed,
                factor,
                recovery_codes,
            )?))
        }
        (CustodyOriginV1::Establish, None) => Err(CeremonyError::new(
            "a run that establishes custody must seal the seed and issue a recovery set",
        )),
        (CustodyOriginV1::Join, Some(_)) => Err(CeremonyError::new(
            "a run that joined existing custody must not seal a seed or issue codes",
        )),
        (CustodyOriginV1::Recover, Some(_)) => Err(CeremonyError::new(
            "a recovery continuity run must not establish custody or issue codes",
        )),
        (CustodyOriginV1::Join | CustodyOriginV1::Recover, None) => Ok(None),
    }
}

fn recovery_replacement_for_origin(
    origin: &CustodyOriginV1,
    wallet_id: &str,
    seed: &[u8; WALLET_CUSTODY_SEED_LEN],
    replacement_factor: Option<FactorSealInputsV1>,
) -> CeremonyResult<Option<RecoveryReplacementEnvelopeV1>> {
    match (origin, replacement_factor) {
        (CustodyOriginV1::Recover, Some(factor)) => Ok(Some(
            CeremonyManifestEstablishedV1::seal_factor_envelope(wallet_id, seed, factor)?,
        )),
        (CustodyOriginV1::Recover, None)
        | (CustodyOriginV1::Establish | CustodyOriginV1::Join, None) => Ok(None),
        (CustodyOriginV1::Establish, Some(_)) => Err(CeremonyError::new(
            "an establishing run already seals its custody factor",
        )),
        (CustodyOriginV1::Join, Some(_)) => Err(CeremonyError::new(
            "a joining run cannot replace a recovery credential",
        )),
    }
}

#[cfg(test)]
mod tests {
    //! These own the ceremony's output contract: what an establishing run seals
    //! must open back to the seed under exactly the factor and the codes it was
    //! sealed for, a joining run must write nothing but its manifest, and a run
    //! must commit only the key set it provisioned.
    //!
    //! They start from `CeremonyProtocolCompletedV1` because they live inside
    //! the module and can build it directly. Driving states 1 and 2 needs a real
    //! Router A/B circuit; `circuit_tests` owns that half, including the
    //! establish-then-join seam over a genuinely opened envelope.

    use super::*;
    use signer_core::passkey_custody::{
        EMAIL_OTP_FACTOR_KEK_VERSION_V1, PASSKEY_CUSTODY_KEK_VERSION_V1,
    };
    use signer_core::wallet_recovery_custody::{
        open_wallet_recovery_entry_v1, open_wallet_recovery_manifest_kek_v1,
        WalletRecoveryCodeScopeV1, WalletRecoveryEntryScopeV1,
    };

    const WALLET_ID: &str = "alice.testnet";
    const FACTOR_SECRET: [u8; 32] = [7u8; 32];
    const NEAR_SIGNING_KEY_ID: &str = "near-ed25519-key-1";
    const EVM_SLOT_ID: &str = "wallet-key:evm-family:alice.testnet:root-1:v1";

    fn seed() -> Zeroizing<[u8; WALLET_CUSTODY_SEED_LEN]> {
        Zeroizing::new([13u8; WALLET_CUSTODY_SEED_LEN])
    }

    fn client_root_public_key33() -> [u8; 33] {
        let mut key = [11u8; 33];
        key[0] = 0x02;
        key
    }

    const REGISTERED_PUBLIC_KEY: [u8; 32] = [21u8; 32];

    fn evm_completed(origin: CustodyOriginV1) -> CeremonyProtocolCompletedV1 {
        CeremonyProtocolCompletedV1 {
            wallet_id: WALLET_ID.to_string(),
            seed: seed(),
            origin,
            completed: CompletedProtocolV1::EvmFamilyEcdsa {
                client_root_public_key33: client_root_public_key33(),
                ready_state_blob: Zeroizing::new(vec![1, 2, 3]),
                public_facts: EvmFamilyPublicFactsV1 {
                    context_binding32: [31u8; 32],
                    derivation_client_share_public_key33: client_root_public_key33(),
                    client_verifying_share33: client_root_public_key33(),
                    relayer_public_key33: client_root_public_key33(),
                    group_public_key33: client_root_public_key33(),
                    ethereum_address20: [41u8; 20],
                    client_share_retry_counter: 0,
                    relayer_share_retry_counter: 0,
                },
            },
        }
    }

    fn near_completed(origin: CustodyOriginV1) -> CeremonyProtocolCompletedV1 {
        CeremonyProtocolCompletedV1 {
            wallet_id: WALLET_ID.to_string(),
            seed: seed(),
            origin,
            completed: CompletedProtocolV1::NearEd25519 {
                registered_public_key: REGISTERED_PUBLIC_KEY,
                application_binding_digest: [51u8; 32],
                local_material_b64u: b64u(&[9u8; 48]),
                local_material_nonce_b64u: b64u(&[3u8; 12]),
            },
        }
    }

    fn evm_identity() -> KeySetIdentityInputsV1 {
        KeySetIdentityInputsV1::EvmFamilyEcdsa {
            evm_family_signing_key_slot_id: EVM_SLOT_ID.to_string(),
        }
    }

    fn near_identity() -> KeySetIdentityInputsV1 {
        KeySetIdentityInputsV1::NearEd25519 {
            near_ed25519_signing_key_id: NEAR_SIGNING_KEY_ID.to_string(),
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

    fn replacement_passkey_factor() -> FactorSealInputsV1 {
        FactorSealInputsV1 {
            envelope_id: "wallet-custody-recovery-envelope-1".to_string(),
            factor: WalletCustodyEnvelopeFactorV1::Passkey {
                rp_id: "wallet.example".to_string(),
                credential_id_b64u: b64u(&[44u8; 32]),
                kek_version: PASSKEY_CUSTODY_KEK_VERSION_V1.to_string(),
            },
            factor_secret: Zeroizing::new(FACTOR_SECRET.to_vec()),
        }
    }

    fn recovery_codes(count: usize) -> Vec<RecoveryCodeInputV1> {
        (0..count)
            .map(|index| RecoveryCodeInputV1 {
                code_bytes: Zeroizing::new(vec![index as u8 + 1; 20]),
            })
            .collect()
    }

    fn decode(value: &str) -> Vec<u8> {
        Base64UrlUnpadded::decode_vec(value).expect("base64url")
    }

    /// An establishing EVM-family run, committed.
    fn established() -> WalletCustodyCommitPayloadV1 {
        evm_completed(CustodyOriginV1::Establish)
            .establish_manifest(evm_identity(), None)
            .expect("manifest established")
            .finish(Some((factor(), recovery_codes(WALLET_RECOVERY_CODE_COUNT))))
            .expect("custody committed")
    }

    fn custody_records(payload: &WalletCustodyCommitPayloadV1) -> &EstablishedCustodyRecordsV1 {
        payload
            .established_custody
            .as_ref()
            .expect("an establishing run writes custody records")
    }

    #[test]
    fn an_established_seed_is_wallet_scoped_and_never_repeats() {
        assert!(CeremonySeedHeldV1::establish("  ").is_err());

        let held = CeremonySeedHeldV1::establish(WALLET_ID).expect("custody established");
        assert_eq!(held.wallet_id, WALLET_ID);
        assert_ne!(held.seed[..], [0u8; WALLET_CUSTODY_SEED_LEN][..]);

        let other = CeremonySeedHeldV1::establish(WALLET_ID).expect("custody established");
        assert_ne!(held.seed[..], other.seed[..]);
    }

    #[test]
    fn the_sealed_envelope_opens_back_to_the_ceremony_seed() {
        let payload = established();
        let records = custody_records(&payload);
        let binding =
            serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(&records.envelope_binding_json)
                .expect("binding round-trips");

        let (opened, admitted) = open_wallet_custody_seed_envelope_v1(
            &FACTOR_SECRET,
            &binding,
            &decode(&records.envelope_nonce_b64u),
            &decode(&records.sealed_custody_secret_b64u),
            &decode(&records.envelope_aad_hash_b64u),
            &decode(&records.envelope_ciphertext_digest_b64u),
        )
        .expect("envelope opens");
        assert_eq!(opened.as_slice(), &seed()[..]);

        // The AAD names the wallet, so an envelope cannot be replayed onto
        // another wallet's custody.
        assert_eq!(admitted.wallet_id(), WALLET_ID);
    }

    #[test]
    fn every_recovery_code_reaches_the_same_seed() {
        let payload = established();
        let records = custody_records(&payload);
        let codes = recovery_codes(WALLET_RECOVERY_CODE_COUNT);
        assert_eq!(records.recovery_manifest_kek_wraps.len(), codes.len());

        for (code, wrap) in codes.iter().zip(records.recovery_manifest_kek_wraps.iter()) {
            // The wrap reports the id the ceremony derived; a reader looking a
            // code up must reach the same one from the code and wallet alone.
            assert_eq!(
                wrap.recovery_key_id,
                derive_wallet_recovery_key_id_v1(WALLET_ID, &code.code_bytes).expect("key id"),
            );
            let manifest_kek = open_wallet_recovery_manifest_kek_v1(
                &code.code_bytes,
                &WalletRecoveryCodeScopeV1 {
                    wallet_id: WALLET_ID.to_string(),
                    recovery_key_id: wrap.recovery_key_id.clone(),
                },
                &decode(&wrap.nonce_b64u),
                &decode(&wrap.ciphertext_b64u),
            )
            .expect("manifest KEK opens");

            let recovered = open_wallet_recovery_entry_v1(
                &manifest_kek[..],
                &WalletRecoveryEntryScopeV1 {
                    wallet_id: WALLET_ID.to_string(),
                },
                &decode(&records.recovery_entry_nonce_b64u),
                &decode(&records.recovery_entry_ciphertext_b64u),
            )
            .expect("recovery entry opens");
            assert_eq!(recovered.as_slice(), &seed()[..]);
        }
    }

    fn recovery_open_input(
        records: &EstablishedCustodyRecordsV1,
        wrap: &SealedRecoveryWrapRecordV1,
    ) -> RecoveryCustodyOpenInputsV1 {
        RecoveryCustodyOpenInputsV1 {
            wallet_id: WALLET_ID.to_string(),
            wrap_nonce: decode(&wrap.nonce_b64u),
            wrapped_manifest_kek: decode(&wrap.ciphertext_b64u),
            wrap_aad_hash: decode(&wrap.aad_hash_b64u)
                .try_into()
                .expect("manifest AAD hash"),
            entry_nonce: decode(&records.recovery_entry_nonce_b64u),
            wrapped_custody_seed: decode(&records.recovery_entry_ciphertext_b64u),
            entry_aad_hash: decode(&records.recovery_entry_aad_hash_b64u)
                .try_into()
                .expect("entry AAD hash"),
        }
    }

    #[test]
    fn recovery_enters_the_ceremony_only_after_exact_aad_and_code_verification() {
        let payload = established();
        let records = custody_records(&payload);
        let codes = recovery_codes(WALLET_RECOVERY_CODE_COUNT);
        let opened = CeremonySeedHeldV1::recover_with_code(
            &codes[0].code_bytes,
            recovery_open_input(records, &records.recovery_manifest_kek_wraps[0]),
        )
        .expect("recovery enters the ceremony");
        assert_eq!(opened.wallet_id, WALLET_ID);
        assert_eq!(opened.seed.as_slice(), seed().as_slice());
        assert!(matches!(opened.origin, CustodyOriginV1::Recover));

        let mut wrong_wrap_aad =
            recovery_open_input(records, &records.recovery_manifest_kek_wraps[0]);
        wrong_wrap_aad.wrap_aad_hash[0] ^= 1;
        assert!(
            CeremonySeedHeldV1::recover_with_code(&codes[0].code_bytes, wrong_wrap_aad,).is_err()
        );

        let mut wrong_entry_aad =
            recovery_open_input(records, &records.recovery_manifest_kek_wraps[0]);
        wrong_entry_aad.entry_aad_hash[0] ^= 1;
        assert!(
            CeremonySeedHeldV1::recover_with_code(&codes[0].code_bytes, wrong_entry_aad,).is_err()
        );

        assert!(CeremonySeedHeldV1::recover_with_code(
            &codes[1].code_bytes,
            recovery_open_input(records, &records.recovery_manifest_kek_wraps[0]),
        )
        .is_err());
    }

    #[test]
    fn a_verified_recovery_run_reseals_only_the_factor_envelope() {
        let recorded = near_completed(CustodyOriginV1::Establish)
            .establish_manifest(near_identity(), None)
            .expect("manifest established")
            .verified
            .digest_b64u();
        let recovered = near_completed(CustodyOriginV1::Recover)
            .establish_manifest(near_identity(), Some(&decode(&recorded)))
            .expect("registered manifest reproduced")
            .finish_recovery(replacement_passkey_factor())
            .expect("recovered seed resealed");
        assert!(recovered.established_custody.is_none());
        let replacement = recovered
            .recovery_replacement_envelope
            .expect("replacement envelope");
        let binding = serde_json::from_str::<PasskeyCustodyEnvelopeBindingV1>(
            &replacement.envelope_binding_json,
        )
        .expect("replacement binding");
        let (opened, admitted) = open_wallet_custody_seed_envelope_v1(
            &FACTOR_SECRET,
            &binding,
            &decode(&replacement.envelope_nonce_b64u),
            &decode(&replacement.sealed_custody_secret_b64u),
            &decode(&replacement.envelope_aad_hash_b64u),
            &decode(&replacement.envelope_ciphertext_digest_b64u),
        )
        .expect("replacement envelope opens");
        assert_eq!(opened.as_slice(), seed().as_slice());
        assert_eq!(admitted.wallet_id(), WALLET_ID);

        assert!(near_completed(CustodyOriginV1::Join)
            .establish_manifest(near_identity(), Some(&decode(&recorded)))
            .expect("joined manifest")
            .finish_recovery(replacement_passkey_factor())
            .is_err());
    }

    #[test]
    fn nonces_are_fresh_across_every_wrap_in_one_ceremony() {
        let payload = established();
        let records = custody_records(&payload);
        let mut nonces = vec![
            records.envelope_nonce_b64u.clone(),
            records.recovery_entry_nonce_b64u.clone(),
        ];
        nonces.extend(
            records
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
            let committed = evm_completed(CustodyOriginV1::Establish)
                .establish_manifest(evm_identity(), None)
                .expect("manifest established")
                .finish(Some((factor(), recovery_codes(count))));
            assert!(
                committed.is_err(),
                "{count} codes must not produce a recovery set"
            );
        }
    }

    #[test]
    fn a_malformed_manifest_ends_the_run_before_anything_is_sealed() {
        // An uncompressed point is not a client root public key.
        let mut broken = evm_completed(CustodyOriginV1::Establish);
        if let CompletedProtocolV1::EvmFamilyEcdsa {
            client_root_public_key33,
            ..
        } = &mut broken.completed
        {
            client_root_public_key33[0] = 0x04;
        }
        assert!(broken.establish_manifest(evm_identity(), None).is_err());

        assert!(evm_completed(CustodyOriginV1::Establish)
            .establish_manifest(
                KeySetIdentityInputsV1::EvmFamilyEcdsa {
                    evm_family_signing_key_slot_id: String::new(),
                },
                None,
            )
            .is_err());
    }

    #[test]
    fn identity_inputs_for_the_other_key_set_are_refused() {
        // The manifest names a key the protocol did not produce, so there is no
        // pairing of these two the ceremony could record honestly.
        assert!(evm_completed(CustodyOriginV1::Establish)
            .establish_manifest(near_identity(), None)
            .is_err());
        assert!(near_completed(CustodyOriginV1::Establish)
            .establish_manifest(evm_identity(), None)
            .is_err());
    }

    #[test]
    fn a_key_set_that_already_has_a_manifest_must_reproduce_it() {
        let recorded = decode(&established().key_manifest_digest_b64u);

        let reproduced = evm_completed(CustodyOriginV1::Join)
            .establish_manifest(evm_identity(), Some(&recorded))
            .expect("the same key set reproduces its recorded digest")
            .finish(None)
            .expect("committed");
        assert_eq!(decode(&reproduced.key_manifest_digest_b64u), recorded);

        // A run that would record a different key set under this key set's
        // registration state is refused rather than silently replacing it.
        let mut wrong = recorded.clone();
        wrong[0] ^= 0xff;
        assert!(evm_completed(CustodyOriginV1::Join)
            .establish_manifest(evm_identity(), Some(&wrong))
            .is_err());
    }

    #[test]
    fn a_run_that_establishes_custody_must_seal_and_issue_codes() {
        // Committing without the envelope and the recovery set would leave the
        // wallet's only seed held nowhere.
        assert!(evm_completed(CustodyOriginV1::Establish)
            .establish_manifest(evm_identity(), None)
            .expect("manifest established")
            .finish(None)
            .is_err());
    }

    #[test]
    fn a_run_that_joined_existing_custody_must_not_seal() {
        // Sealing here would give the wallet a second seed and a second
        // recovery set, leaving half its keys covered by neither.
        assert!(near_completed(CustodyOriginV1::Join)
            .establish_manifest(near_identity(), None)
            .expect("manifest established")
            .finish(Some((factor(), recovery_codes(WALLET_RECOVERY_CODE_COUNT))))
            .is_err());
    }

    #[test]
    fn a_joining_run_commits_its_manifest_and_no_custody_records() {
        let payload = near_completed(CustodyOriginV1::Join)
            .establish_manifest(near_identity(), None)
            .expect("manifest established")
            .finish(None)
            .expect("committed");

        assert!(payload.established_custody.is_none());
        assert!(!payload.key_manifest_digest_b64u.is_empty());
    }

    #[test]
    fn a_run_commits_only_its_own_key_sets_public_facts() {
        let evm = established();
        assert_eq!(evm.key_set, WalletKeySetKindV1::EvmFamilyEcdsa.as_str());
        assert_eq!(
            evm.client_root_public_key33_b64u.as_deref(),
            Some(b64u(&client_root_public_key33()).as_str())
        );
        assert!(evm.ecdsa_ready_state_blob_b64u.is_some());
        assert!(
            evm.registered_public_key_b64u.is_none(),
            "an EVM-family run has no Ed25519 registration to report"
        );

        let near = near_completed(CustodyOriginV1::Join)
            .establish_manifest(near_identity(), None)
            .expect("manifest established")
            .finish(None)
            .expect("committed");
        assert_eq!(near.key_set, WalletKeySetKindV1::NearEd25519.as_str());
        assert_eq!(
            near.registered_public_key_b64u.as_deref(),
            Some(b64u(&REGISTERED_PUBLIC_KEY).as_str())
        );
        assert!(near.client_root_public_key33_b64u.is_none());
        assert!(near.ecdsa_ready_state_blob_b64u.is_none());

        // Two key sets, two digests: a manifest covers one key set only.
        assert_ne!(evm.key_manifest_digest_b64u, near.key_manifest_digest_b64u);
    }
}
