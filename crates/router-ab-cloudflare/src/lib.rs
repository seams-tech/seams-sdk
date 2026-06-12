#![forbid(unsafe_code)]
//! Cloudflare adapter boundary types for Router/A/B signing.
//!
//! This crate pins role-specific binding and storage-scope rules before the
//! `workers-rs` adapter layer is added.

mod durable_object;
#[cfg(any(
    all(
        feature = "strict-worker-entrypoint",
        feature = "strict-worker-router-entrypoint"
    ),
    all(
        feature = "strict-worker-entrypoint",
        feature = "strict-worker-signer-a-entrypoint"
    ),
    all(
        feature = "strict-worker-entrypoint",
        feature = "strict-worker-signer-b-entrypoint"
    ),
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-signer-a-entrypoint"
    ),
    all(
        feature = "strict-worker-router-entrypoint",
        feature = "strict-worker-signer-b-entrypoint"
    ),
    all(
        feature = "strict-worker-signer-a-entrypoint",
        feature = "strict-worker-signer-b-entrypoint"
    ),
))]
compile_error!("enable exactly one strict Worker entrypoint feature");

#[cfg(any(
    feature = "strict-worker-entrypoint",
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
mod strict_worker;

#[cfg(feature = "workers-rs")]
pub use durable_object::{
    execute_cloudflare_durable_object_call_v1, handle_cloudflare_durable_object_fetch_v1,
    handle_cloudflare_durable_object_worker_request_v1, RouterAbRouterLifecycleDurableObject,
    RouterAbRouterReplayDurableObject, RouterAbSignerARelayerOutputDurableObject,
    RouterAbSignerARootShareDurableObject, RouterAbSignerBRootShareDurableObject,
};
pub use durable_object::{
    handle_cloudflare_durable_object_call_v1, CloudflareDurableObjectCallV1,
    CloudflareDurableObjectMemoryStorageV1, CloudflareDurableObjectOperationKindV1,
    CloudflareDurableObjectRequestV1, CloudflareDurableObjectResponseV1,
    CloudflareDurableObjectStorageV1, CloudflareLifecyclePutReceiptV1,
    CloudflareRelayerOutputActivationReceiptV1, CloudflareReplayReserveRequestV1,
    CloudflareReplayReserveResponseV1, CloudflareRootShareLookupRequestV1,
    CloudflareRootShareStartupMetadataV1, CLOUDFLARE_DURABLE_OBJECT_API_VERSION_V1,
};
#[cfg(any(
    feature = "strict-worker-entrypoint",
    feature = "strict-worker-router-entrypoint",
    feature = "strict-worker-signer-a-entrypoint",
    feature = "strict-worker-signer-b-entrypoint"
))]
pub use strict_worker::{
    handle_cloudflare_strict_worker_fetch_v1, parse_cloudflare_strict_route_profile_v1,
    parse_cloudflare_strict_worker_role_v1, CloudflareStrictRouteProfileV1,
    CloudflareStrictRouterBootstrapRequestV1, ROUTER_AB_ROUTE_PROFILE_ENV,
    ROUTER_AB_STRICT_PROOF_BUNDLE_ROUTE_PROFILE_V1, ROUTER_AB_WORKER_ROLE_ENV,
};

use router_ab_core::{
    build_mpc_prf_threshold_signer_batch_input_v1,
    combine_mpc_prf_output_packages_from_ab_proof_batches_v1, decode_ab_peer_message_payload_v1,
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1,
    decode_and_validate_signer_envelope_aead_payload_v1,
    decode_recipient_proof_bundle_ciphertext_v1, decode_router_to_signer_payload_v1,
    decode_signer_input_plaintext_v1, encode_recipient_output_ciphertext_aad_v1,
    encode_recipient_proof_bundle_ciphertext_aad_v1,
    recipient_proof_bundle_wire_message_from_ab_proof_batch_v1,
    sign_ab_derivation_proof_batch_peer_payload_v1,
    signer_response_wire_message_from_mpc_prf_packages_v1,
    validate_signer_input_plaintext_binding_v1, verify_ab_peer_message_ed25519_signature_v1,
    AbDerivationProofBatchPayloadV1, AbPeerMessagePayloadV1, AbPeerMessageVerifyingKeyV1,
    AuditEventV1, AuditSink, CanonicalWireBytesV1, Clock, Csprng, EncryptedPayloadV1,
    ExpensiveWorkGateContextV1, ExpensiveWorkGateDecisionV1, ExpensiveWorkKindV1,
    GateDeferReasonV1, GatePrincipalV1, GateRejectReasonV1, MpcPrfOutputPackagesV1,
    MpcPrfSigningRootShareWireV1, MpcPrfThresholdSignerBatchOutputV1, OpenedShareKind,
    PeerTransport, PublicDigest32, PublicRouterRequestV1, RecipientOutputCiphertextV1,
    RecipientOutputEncryptionAlgorithmV1, RecipientOutputEncryptionRequestV1,
    RecipientOutputEncryptorV1, RecipientProofBundleCiphertextV1,
    RecipientProofBundleEncryptionRequestV1, RecipientProofBundleEncryptorV1,
    RelayerActivationPayloadV1, Role, RoleEnvelopeAadV1, RootShareEpoch, RouterAbDerivationError,
    RouterAbLifecycleStateV1, RouterToSignerPayloadV1, SignerAEngine, SignerBEngine,
    SignerEnvelopeAeadPayloadV1, SignerIdentityV1, SignerInputPlaintextV1, SignerKeyStore,
    SignerSetV1, SigningRootShareStore, WireMessageKindV1, WireMessageV1,
    MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN,
};
#[cfg(feature = "workers-rs")]
use router_ab_core::{
    sign_ab_peer_message_ed25519_authentication_v1, SIGNER_ENVELOPE_AEAD_TAG_LEN_V1,
};
use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "workers-rs")]
use base64::Engine;
#[cfg(feature = "workers-rs")]
use wasm_bindgen::JsCast;
#[cfg(feature = "workers-rs")]
use worker::send::SendFuture;
#[cfg(feature = "workers-rs")]
use zeroize::Zeroize;

/// Public Router endpoint for derivation-time Router/A/B ceremonies.
pub const CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1: &str = "/v1/hss/split-derivation";
/// Private Signer A service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-a";
/// Private Signer B service-binding endpoint for Router-dispatched work.
pub const CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-b";
/// Private Signer A endpoint for direct B-to-A coordination.
pub const CLOUDFLARE_SIGNER_A_PEER_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-a/peer";
/// Private Signer B endpoint for direct A-to-B coordination.
pub const CLOUDFLARE_SIGNER_B_PEER_REQUEST_PATH_V1: &str = "/router-ab/v1/signer-b/peer";
/// Private Signer A endpoint for strict relayer proof-bundle activation.
pub const CLOUDFLARE_SIGNER_A_RELAYER_PROOF_BUNDLE_ACTIVATION_PATH_V1: &str =
    "/router-ab/v1/signer-a/relayer/proof-bundle-activation";
/// Router replay Durable Object binding env key.
pub const ROUTER_REPLAY_DO_BINDING_ENV: &str = "ROUTER_REPLAY_DO_BINDING";
/// Router replay Durable Object object-name env key.
pub const ROUTER_REPLAY_DO_OBJECT_ENV: &str = "ROUTER_REPLAY_DO_OBJECT";
/// Router replay Durable Object key-prefix env key.
pub const ROUTER_REPLAY_DO_KEY_PREFIX_ENV: &str = "ROUTER_REPLAY_DO_KEY_PREFIX";
/// Router lifecycle Durable Object binding env key.
pub const ROUTER_LIFECYCLE_DO_BINDING_ENV: &str = "ROUTER_LIFECYCLE_DO_BINDING";
/// Router lifecycle Durable Object object-name env key.
pub const ROUTER_LIFECYCLE_DO_OBJECT_ENV: &str = "ROUTER_LIFECYCLE_DO_OBJECT";
/// Router lifecycle Durable Object key-prefix env key.
pub const ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV: &str = "ROUTER_LIFECYCLE_DO_KEY_PREFIX";
/// Signer A root-share Durable Object binding env key.
pub const SIGNER_A_ROOT_SHARE_DO_BINDING_ENV: &str = "SIGNER_A_ROOT_SHARE_DO_BINDING";
/// Signer A root-share Durable Object object-name env key.
pub const SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV: &str = "SIGNER_A_ROOT_SHARE_DO_OBJECT";
/// Signer A root-share Durable Object key-prefix env key.
pub const SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV: &str = "SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX";
/// Signer A relayer-output Durable Object binding env key.
pub const SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV: &str = "SIGNER_A_RELAYER_OUTPUT_DO_BINDING";
/// Signer A relayer-output Durable Object object-name env key.
pub const SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV: &str = "SIGNER_A_RELAYER_OUTPUT_DO_OBJECT";
/// Signer A relayer-output Durable Object key-prefix env key.
pub const SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV: &str = "SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX";
/// Signer B root-share Durable Object binding env key.
pub const SIGNER_B_ROOT_SHARE_DO_BINDING_ENV: &str = "SIGNER_B_ROOT_SHARE_DO_BINDING";
/// Signer B root-share Durable Object object-name env key.
pub const SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV: &str = "SIGNER_B_ROOT_SHARE_DO_OBJECT";
/// Signer B root-share Durable Object key-prefix env key.
pub const SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV: &str = "SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX";
/// Signer A signing-root-share wire Secret binding-name env key.
pub const SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV: &str =
    "SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING";
/// Signer B signing-root-share wire Secret binding-name env key.
pub const SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV: &str =
    "SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING";
/// Signer A peer binding env key.
pub const SIGNER_A_PEER_BINDING_ENV: &str = "SIGNER_A_PEER_BINDING";
/// Signer B peer binding env key.
pub const SIGNER_B_PEER_BINDING_ENV: &str = "SIGNER_B_PEER_BINDING";
/// Signer A signer-envelope AEAD secret binding-name env key.
pub const SIGNER_A_ENVELOPE_AEAD_KEY_BINDING_ENV: &str = "SIGNER_A_ENVELOPE_AEAD_KEY_BINDING";
/// Signer A signer-envelope AEAD key epoch env key.
pub const SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH_ENV: &str = "SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH";
/// Signer B signer-envelope AEAD secret binding-name env key.
pub const SIGNER_B_ENVELOPE_AEAD_KEY_BINDING_ENV: &str = "SIGNER_B_ENVELOPE_AEAD_KEY_BINDING";
/// Signer B signer-envelope AEAD key epoch env key.
pub const SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH_ENV: &str = "SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH";
/// Signer A A/B peer-message Ed25519 signing secret binding-name env key.
pub const SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV: &str = "SIGNER_A_PEER_SIGNING_KEY_BINDING";
/// Signer A A/B peer-message Ed25519 signing key epoch env key.
pub const SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV: &str = "SIGNER_A_PEER_SIGNING_KEY_EPOCH";
/// Signer B A/B peer-message Ed25519 signing secret binding-name env key.
pub const SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV: &str = "SIGNER_B_PEER_SIGNING_KEY_BINDING";
/// Signer B A/B peer-message Ed25519 signing key epoch env key.
pub const SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV: &str = "SIGNER_B_PEER_SIGNING_KEY_EPOCH";
/// Signer A A/B peer-message Ed25519 verifying key env key.
pub const SIGNER_A_PEER_VERIFYING_KEY_HEX_ENV: &str = "SIGNER_A_PEER_VERIFYING_KEY_HEX";
/// Signer B A/B peer-message Ed25519 verifying key env key.
pub const SIGNER_B_PEER_VERIFYING_KEY_HEX_ENV: &str = "SIGNER_B_PEER_VERIFYING_KEY_HEX";
/// Maximum random bytes a single signer-host preload may request.
pub const CLOUDFLARE_SIGNER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1: usize = 65_536;
/// Versioned text prefix for a role-local MPC PRF signing-root-share wire secret.
pub const CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1: &str = "mpc-prf-root-share-wire-v1:";

const ROUTER_FORBIDDEN_ENV_KEYS: &[&str] = &[
    SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV,
    SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_A_ENVELOPE_AEAD_KEY_BINDING_ENV,
    SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH_ENV,
    SIGNER_B_ENVELOPE_AEAD_KEY_BINDING_ENV,
    SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH_ENV,
    SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
    SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV,
];
const SIGNER_A_RELAYER_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_REPLAY_DO_BINDING_ENV,
    ROUTER_REPLAY_DO_OBJECT_ENV,
    ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
    ROUTER_LIFECYCLE_DO_BINDING_ENV,
    ROUTER_LIFECYCLE_DO_OBJECT_ENV,
    ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
    SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_B_ENVELOPE_AEAD_KEY_BINDING_ENV,
    SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH_ENV,
    SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV,
];
const SIGNER_B_FORBIDDEN_ENV_KEYS: &[&str] = &[
    ROUTER_REPLAY_DO_BINDING_ENV,
    ROUTER_REPLAY_DO_OBJECT_ENV,
    ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
    ROUTER_LIFECYCLE_DO_BINDING_ENV,
    ROUTER_LIFECYCLE_DO_OBJECT_ENV,
    ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
    SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
    SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
    SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV,
    SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV,
    SIGNER_A_ENVELOPE_AEAD_KEY_BINDING_ENV,
    SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH_ENV,
    SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
    SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
];

/// Text-reader boundary used before binding descriptors are constructed.
pub trait CloudflareEnvReaderV1 {
    /// Returns a raw environment value if present.
    fn get_text(&self, key: &str) -> RouterAbProtocolResult<Option<String>>;
}

/// Platform-neutral signer logic behind the Cloudflare transport wrapper.
pub trait CloudflareSignerWireHandlerV1 {
    /// Handles one validated Router-to-signer wire message.
    fn handle_signer_wire_message(
        &self,
        message: WireMessageV1,
    ) -> RouterAbProtocolResult<WireMessageV1>;
}

/// Production signer logic after envelope decryption and plaintext validation.
pub trait CloudflareValidatedSignerInputHandlerV1 {
    /// Handles a private signer request that has already passed decrypt and binding checks.
    fn handle_validated_signer_input(
        &self,
        request: &CloudflareValidatedSignerPrivateRequestV1,
    ) -> RouterAbProtocolResult<WireMessageV1>;
}

/// Strict proof-bundle signer logic behind the Cloudflare transport wrapper.
pub trait CloudflareSignerRecipientProofBundleWireHandlerV1 {
    /// Handles one validated Router-to-signer message and returns strict proof-bundle delivery.
    fn handle_signer_recipient_proof_bundle_wire_message(
        &self,
        message: WireMessageV1,
    ) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1>;
}

/// Cloudflare production recipient-output encryptor using HPKE base mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareHpkeRecipientOutputEncryptorV1;

impl CloudflareHpkeRecipientOutputEncryptorV1 {
    /// Creates the default HPKE recipient-output encryptor.
    pub fn new() -> Self {
        Self
    }
}

impl RecipientOutputEncryptorV1 for CloudflareHpkeRecipientOutputEncryptorV1 {
    fn encrypt_recipient_output_v1(
        &mut self,
        request: RecipientOutputEncryptionRequestV1<'_>,
    ) -> RouterAbProtocolResult<RecipientOutputCiphertextV1> {
        request.validate()?;
        let recipient_public_key =
            parse_cloudflare_hpke_x25519_public_key_v1(request.recipient_encryption_key())?;
        let aad = cloudflare_hpke_recipient_output_aad_v1(&request)?;
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &recipient_public_key,
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1,
            &aad,
            request.plaintext().as_bytes(),
        )
        .map_err(map_cloudflare_hpke_error)?;
        let mut ciphertext_and_tag =
            Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        ciphertext_and_tag.extend_from_slice(encapped_key.as_ref());
        ciphertext_and_tag.extend_from_slice(&ciphertext);

        RecipientOutputCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.package_commitment(),
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
            EncryptedPayloadV1::new(ciphertext_and_tag)?,
        )
    }
}

/// Cloudflare production recipient proof-bundle encryptor using HPKE base mode.
#[derive(Debug, Clone, Copy, Default)]
pub struct CloudflareHpkeRecipientProofBundleEncryptorV1;

impl CloudflareHpkeRecipientProofBundleEncryptorV1 {
    /// Creates the default HPKE recipient proof-bundle encryptor.
    pub fn new() -> Self {
        Self
    }
}

impl RecipientProofBundleEncryptorV1 for CloudflareHpkeRecipientProofBundleEncryptorV1 {
    fn encrypt_recipient_proof_bundle_v1(
        &mut self,
        request: RecipientProofBundleEncryptionRequestV1,
    ) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
        request.validate()?;
        let recipient_public_key =
            parse_cloudflare_hpke_x25519_public_key_v1(request.recipient_encryption_key())?;
        let aad = cloudflare_hpke_recipient_proof_bundle_aad_v1(&request)?;
        let mut rng = CloudflareHpkeGetrandomRngV1;
        let (encapped_key, ciphertext) = CloudflareHpkeSuiteV1::seal_base(
            &mut rng,
            &recipient_public_key,
            CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
            &aad,
            request.plaintext(),
        )
        .map_err(map_cloudflare_hpke_error)?;
        let mut ciphertext_and_tag =
            Vec::with_capacity(encapped_key.as_ref().len() + ciphertext.len());
        ciphertext_and_tag.extend_from_slice(encapped_key.as_ref());
        ciphertext_and_tag.extend_from_slice(&ciphertext);

        RecipientProofBundleCiphertextV1::new(
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
            request.signer().clone(),
            request.recipient_role(),
            request.opened_share_kind(),
            request.recipient_identity(),
            request.recipient_encryption_key(),
            request.transcript_digest(),
            request.payload_digest(),
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
            EncryptedPayloadV1::new(ciphertext_and_tag)?,
        )
    }
}

type CloudflareHpkeSuiteV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;
type CloudflareHpkeKemV1 = DhKemX25519HkdfSha256;

const CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1: &[u8] =
    b"router-ab-cloudflare/recipient-output/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1: &[u8] =
    b"router-ab-cloudflare/recipient-proof-bundle/hpke-x25519-hkdf-sha256-aes256gcm/v1";
const CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1: [u8; 12] = [0u8; 12];

struct CloudflareHpkeGetrandomRngV1;

impl RngCore for CloudflareHpkeGetrandomRngV1 {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        getrandom::getrandom(dst).expect("Cloudflare HPKE recipient-output RNG failed");
    }
}

impl CryptoRng for CloudflareHpkeGetrandomRngV1 {}

struct CloudflareSignerProofGetrandomRngV1;

impl rand_core_06::RngCore for CloudflareSignerProofGetrandomRngV1 {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dst: &mut [u8]) {
        getrandom::getrandom(dst).expect("Cloudflare signer proof RNG failed");
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core_06::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}

impl rand_core_06::CryptoRng for CloudflareSignerProofGetrandomRngV1 {}

fn cloudflare_hpke_recipient_output_aad_v1(
    request: &RecipientOutputEncryptionRequestV1<'_>,
) -> RouterAbProtocolResult<Vec<u8>> {
    let placeholder = RecipientOutputCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
        request.recipient_role(),
        request.opened_share_kind(),
        request.recipient_identity(),
        request.recipient_encryption_key(),
        request.transcript_digest(),
        request.package_commitment(),
        CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
        EncryptedPayloadV1::new(vec![0u8])?,
    )?;
    encode_recipient_output_ciphertext_aad_v1(&placeholder)
}

fn cloudflare_hpke_recipient_proof_bundle_aad_v1(
    request: &RecipientProofBundleEncryptionRequestV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    let placeholder = RecipientProofBundleCiphertextV1::new(
        RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1,
        request.signer().clone(),
        request.recipient_role(),
        request.opened_share_kind(),
        request.recipient_identity(),
        request.recipient_encryption_key(),
        request.transcript_digest(),
        request.payload_digest(),
        CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1,
        EncryptedPayloadV1::new(vec![0u8])?,
    )?;
    encode_recipient_proof_bundle_ciphertext_aad_v1(&placeholder)
}

fn parse_cloudflare_hpke_x25519_public_key_v1(
    encoded: &str,
) -> RouterAbProtocolResult<<CloudflareHpkeKemV1 as Kem>::PublicKey> {
    let hex_value = encoded.strip_prefix("x25519:").ok_or_else(|| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key must use x25519:<64 lowercase hex chars> encoding",
        )
    })?;
    let public_key_bytes = decode_cloudflare_hpke_x25519_hex_v1(hex_value)?;
    let public_key =
        CloudflareHpkeKemV1::pk_from_bytes(&public_key_bytes).map_err(map_cloudflare_hpke_error)?;
    if CloudflareHpkeKemV1::pk_to_bytes(&public_key) != public_key_bytes {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key must be canonical X25519 bytes",
        ));
    }
    Ok(public_key)
}

fn decode_cloudflare_hpke_x25519_hex_v1(hex_value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    if hex_value.len() != 64 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key hex must be 64 characters",
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex_value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (decode_cloudflare_lower_hex_nibble_v1(chunk[0])? << 4)
            | decode_cloudflare_lower_hex_nibble_v1(chunk[1])?;
    }
    Ok(out)
}

fn decode_cloudflare_lower_hex_nibble_v1(byte: u8) -> RouterAbProtocolResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "HPKE recipient public key must use lowercase hex",
        )),
    }
}

fn map_cloudflare_hpke_error(err: hpke_ng::HpkeError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("Cloudflare HPKE recipient-output encryption failed: {err}"),
    )
}

/// Transport boundary used to execute a validated public Router plan.
pub trait CloudflareRouterPublicPlanExecutorV1 {
    /// Executes a typed Durable Object call.
    fn execute_durable_object_call(
        &mut self,
        call: &CloudflareDurableObjectCallV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectResponseV1>;

    /// Sends a Router-to-signer wire message.
    fn send_signer_message(
        &mut self,
        peer: &CloudflarePeerBindingV1,
        message: &WireMessageV1,
    ) -> RouterAbProtocolResult<WireMessageV1>;
}

/// Deterministic map-backed Env reader for tests and local adapter validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareEnvMapV1 {
    entries: BTreeMap<String, String>,
}

impl CloudflareEnvMapV1 {
    /// Creates an empty map-backed Env reader.
    pub fn new(entries: Vec<(impl Into<String>, impl Into<String>)>) -> Self {
        let entries = entries
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        Self { entries }
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns whether there are no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl CloudflareEnvReaderV1 for CloudflareEnvMapV1 {
    fn get_text(&self, key: &str) -> RouterAbProtocolResult<Option<String>> {
        Ok(self.entries.get(key).cloned())
    }
}

/// Cloudflare Worker role in the Router/A/B deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudflareWorkerRoleV1 {
    /// Public Router Worker.
    Router,
    /// Signer A Worker, also hosting the initial relayer role.
    SignerARelayer,
    /// Signer B Worker.
    SignerB,
}

impl CloudflareWorkerRoleV1 {
    /// Returns the stable role label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Router => "router",
            Self::SignerARelayer => "signer_a_relayer",
            Self::SignerB => "signer_b",
        }
    }
}

/// Durable Object storage scope for Router/A/B Cloudflare adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum CloudflareDurableObjectScopeV1 {
    /// Router replay and idempotency state.
    RouterReplay,
    /// Router public lifecycle state.
    RouterLifecycle,
    /// Role-local sealed root-share state.
    SignerRootShare {
        /// Signer role that owns this storage scope.
        role: Role,
    },
    /// Relayer-output activation state hosted by Signer A initially.
    RelayerOutput {
        /// Worker role that owns relayer activation state.
        owner_role: Role,
    },
}

impl CloudflareDurableObjectScopeV1 {
    /// Creates a signer root-share scope for Signer A or Signer B.
    pub fn signer_root_share(role: Role) -> RouterAbProtocolResult<Self> {
        require_signer_role(role)?;
        Ok(Self::SignerRootShare { role })
    }

    /// Creates the initial Signer A relayer-output scope.
    pub fn signer_a_relayer_output() -> Self {
        Self::RelayerOutput {
            owner_role: Role::SignerA,
        }
    }

    /// Validates the scope itself.
    pub fn validate(self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RouterReplay | Self::RouterLifecycle => Ok(()),
            Self::SignerRootShare { role } => require_signer_role(role),
            Self::RelayerOutput { owner_role } => {
                if owner_role == Role::SignerA {
                    Ok(())
                } else {
                    Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidRole,
                        "v1 relayer-output Durable Object scope must be owned by Signer A",
                    ))
                }
            }
        }
    }

    /// Returns whether this scope is visible to a Worker role.
    pub fn is_visible_to(self, worker_role: CloudflareWorkerRoleV1) -> bool {
        match (worker_role, self) {
            (CloudflareWorkerRoleV1::Router, Self::RouterReplay | Self::RouterLifecycle) => true,
            (
                CloudflareWorkerRoleV1::SignerARelayer,
                Self::SignerRootShare {
                    role: Role::SignerA,
                },
            ) => true,
            (
                CloudflareWorkerRoleV1::SignerARelayer,
                Self::RelayerOutput {
                    owner_role: Role::SignerA,
                },
            ) => true,
            (
                CloudflareWorkerRoleV1::SignerB,
                Self::SignerRootShare {
                    role: Role::SignerB,
                },
            ) => true,
            _ => false,
        }
    }
}

/// Durable Object binding descriptor after Cloudflare env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareDurableObjectBindingV1 {
    /// Durable Object storage scope.
    pub scope: CloudflareDurableObjectScopeV1,
    /// Cloudflare Env binding name.
    pub binding_name: String,
    /// Durable Object object name.
    pub object_name: String,
    /// Prefix for keys within the Durable Object.
    pub key_prefix: String,
}

impl CloudflareDurableObjectBindingV1 {
    /// Creates a validated Durable Object binding descriptor.
    pub fn new(
        scope: CloudflareDurableObjectScopeV1,
        binding_name: impl Into<String>,
        object_name: impl Into<String>,
        key_prefix: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            scope,
            binding_name: binding_name.into(),
            object_name: object_name.into(),
            key_prefix: key_prefix.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates binding fields and storage scope.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_non_empty("binding_name", &self.binding_name)?;
        require_non_empty("object_name", &self.object_name)?;
        require_non_empty("key_prefix", &self.key_prefix)
    }

    /// Validates this binding is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.scope.is_visible_to(worker_role) {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} Durable Object scope",
                worker_role.as_str(),
                self.scope
            ),
        ))
    }
}

/// Service Binding or HTTPS peer descriptor after Cloudflare env parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflarePeerBindingV1 {
    /// Peer Worker role.
    pub peer_role: CloudflareWorkerRoleV1,
    /// Cloudflare Service Binding name or configured peer endpoint label.
    pub binding_name: String,
}

impl CloudflarePeerBindingV1 {
    /// Creates a validated peer binding descriptor.
    pub fn new(
        peer_role: CloudflareWorkerRoleV1,
        binding_name: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            peer_role,
            binding_name: binding_name.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates peer binding fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("binding_name", &self.binding_name)
    }
}

/// Role-local signing-root-share wire Secret binding descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRootShareWireSecretBindingV1 {
    /// Signer role that owns this root-share wire secret.
    pub role: Role,
    /// Cloudflare Secret binding name that contains the root-share wire.
    pub binding_name: String,
}

impl CloudflareRootShareWireSecretBindingV1 {
    /// Creates a validated root-share wire secret descriptor.
    pub fn new(role: Role, binding_name: impl Into<String>) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            role,
            binding_name: binding_name.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates secret ownership and descriptor fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        require_non_empty("binding_name", &self.binding_name)
    }

    /// Validates this secret descriptor is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        let visible = matches!(
            (worker_role, self.role),
            (CloudflareWorkerRoleV1::SignerARelayer, Role::SignerA)
                | (CloudflareWorkerRoleV1::SignerB, Role::SignerB)
        );
        if visible {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} root-share wire secret",
                worker_role.as_str(),
                self.role
            ),
        ))
    }
}

/// Role-local signer-envelope AEAD secret binding descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerEnvelopeDecryptKeyBindingV1 {
    /// Signer role that owns this envelope decrypt key.
    pub role: Role,
    /// Cloudflare Secret binding name that contains the AEAD key material.
    pub binding_name: String,
    /// Public decrypt-key epoch used for transcript and rotation binding.
    pub key_epoch: String,
}

impl CloudflareSignerEnvelopeDecryptKeyBindingV1 {
    /// Creates a validated signer-envelope decrypt-key descriptor.
    pub fn new(
        role: Role,
        binding_name: impl Into<String>,
        key_epoch: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            role,
            binding_name: binding_name.into(),
            key_epoch: key_epoch.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates key ownership and public descriptor fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        require_non_empty("binding_name", &self.binding_name)?;
        require_non_empty("key_epoch", &self.key_epoch)
    }

    /// Validates this key descriptor is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        let visible = matches!(
            (worker_role, self.role),
            (CloudflareWorkerRoleV1::SignerARelayer, Role::SignerA)
                | (CloudflareWorkerRoleV1::SignerB, Role::SignerB)
        );
        if visible {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} signer-envelope decrypt key",
                worker_role.as_str(),
                self.role
            ),
        ))
    }
}

/// Role-local A/B peer-message Ed25519 signing secret binding descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerSigningKeyBindingV1 {
    /// Signer role that owns this peer signing key.
    pub role: Role,
    /// Cloudflare Secret binding name that contains the Ed25519 signing seed.
    pub binding_name: String,
    /// Public signing-key epoch used for signer identity and rotation binding.
    pub key_epoch: String,
}

impl CloudflareSignerPeerSigningKeyBindingV1 {
    /// Creates a validated A/B peer signing-key descriptor.
    pub fn new(
        role: Role,
        binding_name: impl Into<String>,
        key_epoch: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let binding = Self {
            role,
            binding_name: binding_name.into(),
            key_epoch: key_epoch.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates key ownership and public descriptor fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        require_non_empty("binding_name", &self.binding_name)?;
        require_non_empty("key_epoch", &self.key_epoch)
    }

    /// Validates this key descriptor is visible to the given Worker role.
    pub fn validate_visible_to(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        let visible = matches!(
            (worker_role, self.role),
            (CloudflareWorkerRoleV1::SignerARelayer, Role::SignerA)
                | (CloudflareWorkerRoleV1::SignerB, Role::SignerB)
        );
        if visible {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ForbiddenLocalBinding,
            format!(
                "{} Worker cannot access {:?} A/B peer signing key",
                worker_role.as_str(),
                self.role
            ),
        ))
    }
}

/// Public A/B peer-message Ed25519 verifying key bytes for one signer role.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerVerifyingKeyBytesV1 {
    /// Signer role that owns this verifying key.
    pub role: Role,
    /// Raw Ed25519 verifying key bytes.
    pub verifying_key_bytes: [u8; 32],
}

impl CloudflareSignerPeerVerifyingKeyBytesV1 {
    /// Creates validated role-bound peer verifying key bytes.
    pub fn new(role: Role, verifying_key_bytes: [u8; 32]) -> RouterAbProtocolResult<Self> {
        let key = Self {
            role,
            verifying_key_bytes,
        };
        key.validate()?;
        Ok(key)
    }

    /// Validates role ownership and Ed25519 key shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        let probe_identity = SignerIdentityV1::new(
            self.role,
            "cloudflare-peer-verifying-key-probe",
            "cloudflare-peer-verifying-key-probe",
        )?;
        AbPeerMessageVerifyingKeyV1::new(probe_identity, self.verifying_key_bytes)?;
        Ok(())
    }

    /// Binds these key bytes to a request signer identity.
    pub fn bind_to_signer(
        &self,
        signer: SignerIdentityV1,
    ) -> RouterAbProtocolResult<AbPeerMessageVerifyingKeyV1> {
        self.validate()?;
        signer.validate()?;
        if signer.role != self.role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "Cloudflare peer verifying key role differs from signer identity",
            ));
        }
        AbPeerMessageVerifyingKeyV1::new(signer, self.verifying_key_bytes)
    }
}

/// Trusted public A/B peer verifying-key set loaded by signer Workers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPeerVerifyingKeySetV1 {
    /// Signer A peer-message verifying key bytes.
    pub signer_a: CloudflareSignerPeerVerifyingKeyBytesV1,
    /// Signer B peer-message verifying key bytes.
    pub signer_b: CloudflareSignerPeerVerifyingKeyBytesV1,
}

impl CloudflareSignerPeerVerifyingKeySetV1 {
    /// Creates a validated public A/B verifying-key set.
    pub fn new(
        signer_a: CloudflareSignerPeerVerifyingKeyBytesV1,
        signer_b: CloudflareSignerPeerVerifyingKeyBytesV1,
    ) -> RouterAbProtocolResult<Self> {
        let set = Self { signer_a, signer_b };
        set.validate()?;
        Ok(set)
    }

    /// Validates role ordering and key bytes.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.signer_a.validate()?;
        self.signer_b.validate()?;
        if self.signer_a.role != Role::SignerA || self.signer_b.role != Role::SignerB {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "Cloudflare peer verifying-key set roles must be Signer A and Signer B",
            ));
        }
        Ok(())
    }

    /// Binds configured key bytes to a request signer set.
    pub fn to_protocol_keys(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        self.validate()?;
        signer_set.validate()?;
        Ok(vec![
            self.signer_a.bind_to_signer(signer_set.signer_a.clone())?,
            self.signer_b.bind_to_signer(signer_set.signer_b.clone())?,
        ])
    }
}

/// Router Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterBindingsV1 {
    /// Router replay/idempotency Durable Object.
    pub replay: CloudflareDurableObjectBindingV1,
    /// Router public lifecycle Durable Object.
    pub lifecycle: CloudflareDurableObjectBindingV1,
    /// Signer A peer binding.
    pub signer_a: CloudflarePeerBindingV1,
    /// Signer B peer binding.
    pub signer_b: CloudflarePeerBindingV1,
}

impl CloudflareRouterBindingsV1 {
    /// Creates validated Router Worker bindings.
    pub fn new(
        replay: CloudflareDurableObjectBindingV1,
        lifecycle: CloudflareDurableObjectBindingV1,
        signer_a: CloudflarePeerBindingV1,
        signer_b: CloudflarePeerBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            replay,
            lifecycle,
            signer_a,
            signer_b,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Router Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.replay,
            CloudflareDurableObjectScopeV1::RouterReplay,
            CloudflareWorkerRoleV1::Router,
        )?;
        require_scope(
            &self.lifecycle,
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            CloudflareWorkerRoleV1::Router,
        )?;
        require_peer_role(&self.signer_a, CloudflareWorkerRoleV1::SignerARelayer)?;
        require_peer_role(&self.signer_b, CloudflareWorkerRoleV1::SignerB)
    }
}

/// Signer A plus relayer Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerARelayerBindingsV1 {
    /// Signer A sealed root-share Durable Object.
    pub root_share: CloudflareDurableObjectBindingV1,
    /// Signer A signing-root-share wire Secret.
    pub root_share_wire_secret: CloudflareRootShareWireSecretBindingV1,
    /// Signer A relayer-output Durable Object.
    pub relayer_output: CloudflareDurableObjectBindingV1,
    /// Signer A signer-envelope AEAD decrypt key.
    pub envelope_decrypt_key: CloudflareSignerEnvelopeDecryptKeyBindingV1,
    /// Signer A A/B peer-message Ed25519 signing key.
    pub peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
    /// Trusted A/B peer-message Ed25519 verifying keys.
    pub peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
    /// Signer B peer binding.
    pub signer_b: CloudflarePeerBindingV1,
}

impl CloudflareSignerARelayerBindingsV1 {
    /// Creates validated Signer A/Relayer Worker bindings.
    pub fn new(
        root_share: CloudflareDurableObjectBindingV1,
        root_share_wire_secret: CloudflareRootShareWireSecretBindingV1,
        relayer_output: CloudflareDurableObjectBindingV1,
        envelope_decrypt_key: CloudflareSignerEnvelopeDecryptKeyBindingV1,
        peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
        peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
        signer_b: CloudflarePeerBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            root_share,
            root_share_wire_secret,
            relayer_output,
            envelope_decrypt_key,
            peer_signing_key,
            peer_verifying_keys,
            signer_b,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Signer A/Relayer Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.root_share,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerA,
            },
            CloudflareWorkerRoleV1::SignerARelayer,
        )?;
        self.root_share_wire_secret
            .validate_visible_to(CloudflareWorkerRoleV1::SignerARelayer)?;
        require_scope(
            &self.relayer_output,
            CloudflareDurableObjectScopeV1::signer_a_relayer_output(),
            CloudflareWorkerRoleV1::SignerARelayer,
        )?;
        self.envelope_decrypt_key
            .validate_visible_to(CloudflareWorkerRoleV1::SignerARelayer)?;
        self.peer_signing_key
            .validate_visible_to(CloudflareWorkerRoleV1::SignerARelayer)?;
        self.peer_verifying_keys.validate()?;
        require_peer_role(&self.signer_b, CloudflareWorkerRoleV1::SignerB)
    }
}

/// Signer B Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerBBindingsV1 {
    /// Signer B sealed root-share Durable Object.
    pub root_share: CloudflareDurableObjectBindingV1,
    /// Signer B signing-root-share wire Secret.
    pub root_share_wire_secret: CloudflareRootShareWireSecretBindingV1,
    /// Signer B signer-envelope AEAD decrypt key.
    pub envelope_decrypt_key: CloudflareSignerEnvelopeDecryptKeyBindingV1,
    /// Signer B A/B peer-message Ed25519 signing key.
    pub peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
    /// Trusted A/B peer-message Ed25519 verifying keys.
    pub peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
    /// Signer A/Relayer peer binding.
    pub signer_a_relayer: CloudflarePeerBindingV1,
}

impl CloudflareSignerBBindingsV1 {
    /// Creates validated Signer B Worker bindings.
    pub fn new(
        root_share: CloudflareDurableObjectBindingV1,
        root_share_wire_secret: CloudflareRootShareWireSecretBindingV1,
        envelope_decrypt_key: CloudflareSignerEnvelopeDecryptKeyBindingV1,
        peer_signing_key: CloudflareSignerPeerSigningKeyBindingV1,
        peer_verifying_keys: CloudflareSignerPeerVerifyingKeySetV1,
        signer_a_relayer: CloudflarePeerBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let bindings = Self {
            root_share,
            root_share_wire_secret,
            envelope_decrypt_key,
            peer_signing_key,
            peer_verifying_keys,
            signer_a_relayer,
        };
        bindings.validate()?;
        Ok(bindings)
    }

    /// Validates Signer B Worker bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_scope(
            &self.root_share,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerB,
            },
            CloudflareWorkerRoleV1::SignerB,
        )?;
        self.root_share_wire_secret
            .validate_visible_to(CloudflareWorkerRoleV1::SignerB)?;
        self.envelope_decrypt_key
            .validate_visible_to(CloudflareWorkerRoleV1::SignerB)?;
        self.peer_signing_key
            .validate_visible_to(CloudflareWorkerRoleV1::SignerB)?;
        self.peer_verifying_keys.validate()?;
        require_peer_role(
            &self.signer_a_relayer,
            CloudflareWorkerRoleV1::SignerARelayer,
        )
    }
}

/// Role-specific Cloudflare Worker startup bindings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "worker_role", rename_all = "snake_case")]
pub enum CloudflareWorkerBindingsV1 {
    /// Router Worker bindings.
    Router {
        /// Router bindings.
        bindings: CloudflareRouterBindingsV1,
    },
    /// Signer A/Relayer Worker bindings.
    SignerARelayer {
        /// Signer A/Relayer bindings.
        bindings: CloudflareSignerARelayerBindingsV1,
    },
    /// Signer B Worker bindings.
    SignerB {
        /// Signer B bindings.
        bindings: CloudflareSignerBBindingsV1,
    },
}

impl CloudflareWorkerBindingsV1 {
    /// Creates a Router Worker startup branch.
    pub fn router(bindings: CloudflareRouterBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::Router { bindings })
    }

    /// Creates a Signer A/Relayer Worker startup branch.
    pub fn signer_a_relayer(
        bindings: CloudflareSignerARelayerBindingsV1,
    ) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::SignerARelayer { bindings })
    }

    /// Creates a Signer B Worker startup branch.
    pub fn signer_b(bindings: CloudflareSignerBBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self::SignerB { bindings })
    }

    /// Returns the Worker role.
    pub fn worker_role(&self) -> CloudflareWorkerRoleV1 {
        match self {
            Self::Router { .. } => CloudflareWorkerRoleV1::Router,
            Self::SignerARelayer { .. } => CloudflareWorkerRoleV1::SignerARelayer,
            Self::SignerB { .. } => CloudflareWorkerRoleV1::SignerB,
        }
    }
}

/// Thin Router Worker runtime context after Cloudflare startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterWorkerRuntimeV1 {
    bindings: CloudflareRouterBindingsV1,
}

/// Thin Signer A/Relayer Worker runtime context after startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerARelayerWorkerRuntimeV1 {
    bindings: CloudflareSignerARelayerBindingsV1,
}

/// Thin Signer B Worker runtime context after startup validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerBWorkerRuntimeV1 {
    bindings: CloudflareSignerBBindingsV1,
}

/// Input for loading a synchronous signer host from async Cloudflare resources.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerHostPreloadInputV1 {
    /// Signer set id whose local root-share metadata must be loaded.
    pub signer_set_id: String,
    /// Root-share epoch to load for the local signer role.
    pub root_share_epoch: RootShareEpoch,
    /// Peer responses already fetched by an adapter-specific A/B coordinator.
    pub peer_responses: Vec<WireMessageV1>,
    /// Trusted signer verifying keys used for A/B peer authentication.
    pub signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
    /// Number of random bytes to preload before entering synchronous core code.
    pub random_bytes_len: usize,
}

impl CloudflareSignerHostPreloadInputV1 {
    /// Creates a validated signer-host preload request.
    pub fn new(
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        peer_responses: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes_len: usize,
    ) -> RouterAbProtocolResult<Self> {
        let input = Self {
            signer_set_id: signer_set_id.into(),
            root_share_epoch,
            peer_responses,
            signer_verifying_keys,
            random_bytes_len,
        };
        input.validate()?;
        Ok(input)
    }

    /// Validates preload identity, peer response shape, and random-buffer budget.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        if self.random_bytes_len > CLOUDFLARE_SIGNER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "signer host random preload length exceeds maximum",
            ));
        }
        validate_signer_verifying_keys_v1(&self.signer_verifying_keys)?;
        for response in &self.peer_responses {
            require_preloaded_peer_response_v1(response)?;
            verify_peer_message_authentication_with_keys_v1(&self.signer_verifying_keys, response)?;
        }
        Ok(())
    }
}

/// Input for loading a signer host after fetching direct A/B peer responses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerHostPeerPreloadInputV1 {
    /// Signer set id whose local root-share metadata must be loaded.
    pub signer_set_id: String,
    /// Root-share epoch to load for the local signer role.
    pub root_share_epoch: RootShareEpoch,
    /// Direct A/B peer requests to execute before entering synchronous core code.
    pub peer_requests: Vec<WireMessageV1>,
    /// Trusted signer verifying keys used for A/B peer authentication.
    pub signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
    /// Number of random bytes to preload before entering synchronous core code.
    pub random_bytes_len: usize,
}

impl CloudflareSignerHostPeerPreloadInputV1 {
    /// Creates a validated signer-host peer preload request.
    pub fn new(
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        peer_requests: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes_len: usize,
    ) -> RouterAbProtocolResult<Self> {
        let input = Self {
            signer_set_id: signer_set_id.into(),
            root_share_epoch,
            peer_requests,
            signer_verifying_keys,
            random_bytes_len,
        };
        input.validate()?;
        Ok(input)
    }

    /// Validates preload identity, peer request shape, and random-buffer budget.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        if self.random_bytes_len > CLOUDFLARE_SIGNER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "signer host peer random preload length exceeds maximum",
            ));
        }
        validate_signer_verifying_keys_v1(&self.signer_verifying_keys)?;
        for request in &self.peer_requests {
            require_preloaded_peer_request_v1(request)?;
            verify_peer_message_authentication_with_keys_v1(&self.signer_verifying_keys, request)?;
        }
        Ok(())
    }
}

/// Role-local root-share wire loaded before synchronous signer execution.
#[derive(Clone, PartialEq, Eq)]
pub struct CloudflarePreloadedRootShareWireV1 {
    /// Signer role that owns the root-share wire.
    pub signer_role: Role,
    /// Root-share epoch for this wire.
    pub root_share_epoch: RootShareEpoch,
    signing_root_share_wire: MpcPrfSigningRootShareWireV1,
}

impl core::fmt::Debug for CloudflarePreloadedRootShareWireV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CloudflarePreloadedRootShareWireV1")
            .field("signer_role", &self.signer_role)
            .field("root_share_epoch", &self.root_share_epoch)
            .field("signing_root_share_wire", &"[redacted]")
            .finish()
    }
}

impl CloudflarePreloadedRootShareWireV1 {
    /// Creates a validated preloaded root-share wire record.
    pub fn new(
        signer_role: Role,
        root_share_epoch: RootShareEpoch,
        signing_root_share_wire: MpcPrfSigningRootShareWireV1,
    ) -> RouterAbProtocolResult<Self> {
        let record = Self {
            signer_role,
            root_share_epoch,
            signing_root_share_wire,
        };
        record.validate()?;
        Ok(record)
    }

    /// Validates the public root-share wire binding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.signer_role)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())
    }

    /// Returns a clone of the redacted signer-local root-share wire.
    pub fn signing_root_share_wire(&self) -> MpcPrfSigningRootShareWireV1 {
        self.signing_root_share_wire.clone()
    }
}

/// Decodes a role-local root-share wire secret into a redacted preloaded record.
pub fn decode_cloudflare_root_share_wire_secret_v1(
    metadata: &CloudflareRootShareStartupMetadataV1,
    encoded_secret: &str,
) -> RouterAbProtocolResult<CloudflarePreloadedRootShareWireV1> {
    metadata.validate()?;
    let encoded_secret = encoded_secret.trim();
    let hex_value = encoded_secret
        .strip_prefix(CLOUDFLARE_ROOT_SHARE_WIRE_SECRET_PREFIX_V1)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Cloudflare root-share wire secret has an unsupported encoding prefix",
            )
        })?;
    let wire_bytes = decode_cloudflare_root_share_wire_hex_v1(hex_value)?;
    let signing_root_share_wire =
        MpcPrfSigningRootShareWireV1::new(wire_bytes).map_err(map_root_share_to_protocol)?;
    CloudflarePreloadedRootShareWireV1::new(
        metadata.signer_role,
        metadata.root_share_epoch.clone(),
        signing_root_share_wire,
    )
}

/// Validates binding visibility and decodes a role-local root-share wire Secret value.
pub fn decode_and_validate_cloudflare_root_share_wire_secret_v1(
    worker_role: CloudflareWorkerRoleV1,
    binding: &CloudflareRootShareWireSecretBindingV1,
    metadata: &CloudflareRootShareStartupMetadataV1,
    encoded_secret: &str,
) -> RouterAbProtocolResult<CloudflarePreloadedRootShareWireV1> {
    binding.validate_visible_to(worker_role)?;
    metadata.validate()?;
    if binding.role != metadata.signer_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Cloudflare root-share wire secret binding role does not match startup metadata",
        ));
    }
    decode_cloudflare_root_share_wire_secret_v1(metadata, encoded_secret)
}

fn decode_cloudflare_root_share_wire_hex_v1(hex_value: &str) -> RouterAbProtocolResult<Vec<u8>> {
    let expected_len = MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN * 2;
    if hex_value.len() != expected_len {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare root-share wire secret hex must be {expected_len} characters"),
        ));
    }
    let mut out = Vec::with_capacity(MPC_PRF_SIGNING_ROOT_SHARE_WIRE_V1_LEN);
    for chunk in hex_value.as_bytes().chunks_exact(2) {
        out.push(
            (decode_cloudflare_root_share_hex_nibble_v1(chunk[0])? << 4)
                | decode_cloudflare_root_share_hex_nibble_v1(chunk[1])?,
        );
    }
    Ok(out)
}

fn decode_cloudflare_root_share_hex_nibble_v1(byte: u8) -> RouterAbProtocolResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare root-share wire secret must use lowercase hex",
        )),
    }
}

/// Decodes a lowercase-hex Ed25519 peer verifying key.
pub fn decode_cloudflare_peer_verifying_key_hex_v1(
    hex_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let hex_value = hex_value.trim();
    let expected_len = 64;
    if hex_value.len() != expected_len {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare peer verifying key hex must be 64 characters",
        ));
    }
    let mut out = [0u8; 32];
    for (index, chunk) in hex_value.as_bytes().chunks_exact(2).enumerate() {
        out[index] = (decode_cloudflare_peer_verifying_key_hex_nibble_v1(chunk[0])? << 4)
            | decode_cloudflare_peer_verifying_key_hex_nibble_v1(chunk[1])?;
    }
    Ok(out)
}

fn decode_cloudflare_peer_verifying_key_hex_nibble_v1(byte: u8) -> RouterAbProtocolResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare peer verifying key hex must use lowercase hex",
        )),
    }
}

/// Synchronous signer host built from async Cloudflare adapter preload results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflarePreloadedSignerHostV1 {
    /// Worker-local time captured by the adapter.
    pub now_unix_ms: u64,
    /// Role-local root-share startup metadata loaded before engine execution.
    pub root_share_metadata: Vec<CloudflareRootShareStartupMetadataV1>,
    /// Role-local root-share wires loaded before synchronous engine execution.
    #[serde(skip)]
    pub root_share_wires: Vec<CloudflarePreloadedRootShareWireV1>,
    /// Preloaded peer responses available to synchronous engine code.
    pub peer_responses: Vec<WireMessageV1>,
    /// Trusted signer verifying keys available to synchronous engine code.
    pub signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
    /// Random bytes supplied by the adapter before engine execution.
    pub random_bytes: Vec<u8>,
}

impl CloudflarePreloadedSignerHostV1 {
    /// Creates a validated preloaded signer host.
    pub fn new(
        now_unix_ms: u64,
        root_share_metadata: Vec<CloudflareRootShareStartupMetadataV1>,
        peer_responses: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        Self::new_with_root_share_wires(
            now_unix_ms,
            root_share_metadata,
            Vec::new(),
            peer_responses,
            signer_verifying_keys,
            random_bytes,
        )
    }

    /// Creates a validated preloaded signer host with role-local root-share wires.
    pub fn new_with_root_share_wires(
        now_unix_ms: u64,
        root_share_metadata: Vec<CloudflareRootShareStartupMetadataV1>,
        root_share_wires: Vec<CloudflarePreloadedRootShareWireV1>,
        peer_responses: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes: Vec<u8>,
    ) -> RouterAbProtocolResult<Self> {
        let host = Self {
            now_unix_ms,
            root_share_metadata,
            root_share_wires,
            peer_responses,
            signer_verifying_keys,
            random_bytes,
        };
        host.validate()?;
        Ok(host)
    }

    /// Validates preloaded host material.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        if self.now_unix_ms == 0 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidTimeRange,
                "preloaded signer host now_unix_ms must be greater than zero",
            ));
        }
        for metadata in &self.root_share_metadata {
            metadata.validate()?;
            require_signer_role(metadata.signer_role)?;
        }
        for wire in &self.root_share_wires {
            wire.validate()?;
            if !self.root_share_metadata.iter().any(|metadata| {
                metadata.signer_role == wire.signer_role
                    && metadata.root_share_epoch == wire.root_share_epoch
            }) {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "preloaded root-share wire is missing matching startup metadata",
                ));
            }
        }
        validate_signer_verifying_keys_v1(&self.signer_verifying_keys)?;
        for response in &self.peer_responses {
            require_preloaded_peer_response_v1(response)?;
            verify_peer_message_authentication_with_keys_v1(&self.signer_verifying_keys, response)?;
        }
        Ok(())
    }

    /// Returns the preloaded role-local signing-root share wire.
    pub fn signing_root_share_wire(
        &self,
        role: Role,
        epoch: &RootShareEpoch,
    ) -> RouterAbProtocolResult<MpcPrfSigningRootShareWireV1> {
        require_signer_role(role)?;
        require_non_empty("root_share_epoch", epoch.as_str())?;
        self.root_share_wires
            .iter()
            .find(|wire| wire.signer_role == role && &wire.root_share_epoch == epoch)
            .map(CloudflarePreloadedRootShareWireV1::signing_root_share_wire)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!(
                        "preloaded signer host is missing {} root-share wire",
                        role.as_str()
                    ),
                )
            })
    }

    /// Returns preloaded role-local root-share startup metadata.
    pub fn root_share_startup_metadata(
        &self,
        role: Role,
        epoch: &RootShareEpoch,
    ) -> RouterAbProtocolResult<&CloudflareRootShareStartupMetadataV1> {
        require_signer_role(role)?;
        require_non_empty("root_share_epoch", epoch.as_str())?;
        self.root_share_metadata
            .iter()
            .find(|metadata| metadata.signer_role == role && &metadata.root_share_epoch == epoch)
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!(
                        "preloaded signer host is missing {} root-share metadata",
                        role.as_str()
                    ),
                )
            })
    }
}

/// Builds a synchronous signer host from already loaded Cloudflare resources.
pub fn build_cloudflare_preloaded_signer_host_v1(
    now_unix_ms: u64,
    expected_role: Role,
    input: CloudflareSignerHostPreloadInputV1,
    root_share_metadata: CloudflareRootShareStartupMetadataV1,
    random_bytes: Vec<u8>,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    require_signer_role(expected_role)?;
    input.validate()?;
    root_share_metadata.validate()?;
    if root_share_metadata.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "preloaded root-share metadata role does not match signer host role",
        ));
    }
    if root_share_metadata.signer_set_id != input.signer_set_id
        || root_share_metadata.root_share_epoch != input.root_share_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "preloaded root-share metadata does not match signer host preload input",
        ));
    }
    if random_bytes.len() != input.random_bytes_len {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "preloaded random byte length does not match signer host preload input",
        ));
    }
    CloudflarePreloadedSignerHostV1::new(
        now_unix_ms,
        vec![root_share_metadata],
        input.peer_responses,
        input.signer_verifying_keys,
        random_bytes,
    )
}

/// Builds a synchronous signer host with already unsealed role-local root-share wire.
pub fn build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
    now_unix_ms: u64,
    expected_role: Role,
    input: CloudflareSignerHostPreloadInputV1,
    root_share_metadata: CloudflareRootShareStartupMetadataV1,
    signing_root_share_wire: MpcPrfSigningRootShareWireV1,
    random_bytes: Vec<u8>,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    require_signer_role(expected_role)?;
    input.validate()?;
    root_share_metadata.validate()?;
    let root_share_wire = CloudflarePreloadedRootShareWireV1::new(
        expected_role,
        input.root_share_epoch.clone(),
        signing_root_share_wire,
    )?;
    if root_share_metadata.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "preloaded root-share metadata role does not match signer host role",
        ));
    }
    if root_share_metadata.signer_set_id != input.signer_set_id
        || root_share_metadata.root_share_epoch != input.root_share_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "preloaded root-share metadata does not match signer host preload input",
        ));
    }
    if random_bytes.len() != input.random_bytes_len {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "preloaded random byte length does not match signer host preload input",
        ));
    }
    CloudflarePreloadedSignerHostV1::new_with_root_share_wires(
        now_unix_ms,
        vec![root_share_metadata],
        vec![root_share_wire],
        input.peer_responses,
        input.signer_verifying_keys,
        random_bytes,
    )
}

impl Clock for CloudflarePreloadedSignerHostV1 {
    fn now_unix_ms(&self) -> u64 {
        self.now_unix_ms
    }
}

impl Csprng for CloudflarePreloadedSignerHostV1 {
    fn fill_random(&mut self, out: &mut [u8]) -> RouterAbProtocolResult<()> {
        if self.random_bytes.len() < out.len() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "preloaded signer host random buffer is exhausted",
            ));
        }
        out.copy_from_slice(&self.random_bytes[..out.len()]);
        self.random_bytes.drain(..out.len());
        Ok(())
    }
}

impl SignerKeyStore for CloudflarePreloadedSignerHostV1 {
    fn signer_identity(&self, role: Role) -> RouterAbProtocolResult<String> {
        require_signer_role(role)?;
        self.root_share_metadata
            .iter()
            .find(|metadata| metadata.signer_role == role)
            .map(|metadata| metadata.signer_id.clone())
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!(
                        "preloaded signer host is missing {} identity",
                        role.as_str()
                    ),
                )
            })
    }

    fn signer_verifying_key(
        &self,
        signer: &SignerIdentityV1,
    ) -> RouterAbProtocolResult<AbPeerMessageVerifyingKeyV1> {
        require_signer_role(signer.role)?;
        self.signer_verifying_keys
            .iter()
            .find(|key| &key.signer == signer)
            .cloned()
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    format!(
                        "preloaded signer host is missing {} verifying key",
                        signer.role.as_str()
                    ),
                )
            })
    }
}

impl SigningRootShareStore for CloudflarePreloadedSignerHostV1 {
    fn has_root_share(&self, role: Role, epoch: &RootShareEpoch) -> RouterAbProtocolResult<bool> {
        require_signer_role(role)?;
        require_non_empty("root_share_epoch", epoch.as_str())?;
        Ok(self
            .root_share_metadata
            .iter()
            .any(|metadata| metadata.signer_role == role && &metadata.root_share_epoch == epoch))
    }
}

impl PeerTransport for CloudflarePreloadedSignerHostV1 {
    fn send_peer_message(&self, message: WireMessageV1) -> RouterAbProtocolResult<WireMessageV1> {
        self.peer_responses
            .iter()
            .find(|response| response.transcript_digest == message.transcript_digest)
            .cloned()
            .ok_or_else(|| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MissingLocalBinding,
                    "preloaded signer host is missing a peer response for the transcript",
                )
            })
    }
}

impl AuditSink for CloudflarePreloadedSignerHostV1 {
    fn record_audit_event(&self, _event: AuditEventV1) -> RouterAbProtocolResult<()> {
        Ok(())
    }
}

/// Auth context already verified by the Router boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "auth", rename_all = "snake_case")]
pub enum CloudflareRouterAuthContextV1 {
    /// Fully authenticated user/session.
    AuthenticatedSession {
        /// Canonical subject id from verified auth.
        subject_id: String,
        /// Canonical session id from verified auth.
        session_id: String,
    },
    /// Pre-auth session allowed only for registration prepare.
    PreAuthSession {
        /// Router-derived pre-auth session id.
        pre_auth_session_id: String,
    },
}

impl CloudflareRouterAuthContextV1 {
    /// Creates a validated authenticated-session context.
    pub fn authenticated_session(
        subject_id: impl Into<String>,
        session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self::AuthenticatedSession {
            subject_id: subject_id.into(),
            session_id: session_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Creates a validated pre-auth session context.
    pub fn pre_auth_session(
        pre_auth_session_id: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self::PreAuthSession {
            pre_auth_session_id: pre_auth_session_id.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates auth branch identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::AuthenticatedSession {
                subject_id,
                session_id,
            } => {
                require_non_empty("subject_id", subject_id)?;
                require_non_empty("session_id", session_id)
            }
            Self::PreAuthSession {
                pre_auth_session_id,
            } => require_non_empty("pre_auth_session_id", pre_auth_session_id),
        }
    }

    /// Converts trusted Router auth context into a core gate principal.
    pub fn to_gate_principal(&self) -> RouterAbProtocolResult<GatePrincipalV1> {
        self.validate()?;
        match self {
            Self::AuthenticatedSession {
                subject_id,
                session_id,
            } => GatePrincipalV1::authenticated_session(subject_id.clone(), session_id.clone()),
            Self::PreAuthSession {
                pre_auth_session_id,
            } => GatePrincipalV1::pre_auth_session(pre_auth_session_id.clone()),
        }
    }

    fn session_id(&self) -> &str {
        match self {
            Self::AuthenticatedSession { session_id, .. } => session_id,
            Self::PreAuthSession {
                pre_auth_session_id,
            } => pre_auth_session_id,
        }
    }
}

/// Router-owned request metadata used to derive gate context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterTrustedRequestMetadataV1 {
    /// Protected work class from verified Router routing.
    pub work_kind: ExpensiveWorkKindV1,
    /// Canonical organization id.
    pub org_id: String,
    /// Canonical project id.
    pub project_id: String,
    /// Deployment environment label.
    pub environment: String,
    /// Account, wallet, or root resource id.
    pub account_id: String,
    /// Router-owned auth context.
    pub auth: CloudflareRouterAuthContextV1,
    /// Digest of trusted source metadata, such as edge client address.
    pub trusted_source_digest: PublicDigest32,
}

impl CloudflareRouterTrustedRequestMetadataV1 {
    /// Creates validated trusted request metadata.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        work_kind: ExpensiveWorkKindV1,
        org_id: impl Into<String>,
        project_id: impl Into<String>,
        environment: impl Into<String>,
        account_id: impl Into<String>,
        auth: CloudflareRouterAuthContextV1,
        trusted_source_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            work_kind,
            org_id: org_id.into(),
            project_id: project_id.into(),
            environment: environment.into(),
            account_id: account_id.into(),
            auth,
            trusted_source_digest,
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates trusted request metadata fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("org_id", &self.org_id)?;
        require_non_empty("project_id", &self.project_id)?;
        require_non_empty("environment", &self.environment)?;
        require_non_empty("account_id", &self.account_id)?;
        self.auth.validate()
    }

    /// Validates trusted metadata matches the normalized public request.
    pub fn validate_for_request(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.work_kind != request.lifecycle.work_kind {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata work kind does not match public request lifecycle",
            ));
        }
        if self.account_id != request.lifecycle.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata account id does not match public request lifecycle",
            ));
        }
        if self.auth.session_id() != request.lifecycle.session_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted Router metadata session id does not match public request lifecycle",
            ));
        }
        if matches!(
            self.auth,
            CloudflareRouterAuthContextV1::PreAuthSession { .. }
        ) && self.work_kind != ExpensiveWorkKindV1::RegistrationPrepare
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "pre-auth Router metadata is allowed only for registration prepare",
            ));
        }
        Ok(())
    }

    /// Builds the core gate context from trusted Router metadata.
    pub fn to_gate_context(&self) -> RouterAbProtocolResult<ExpensiveWorkGateContextV1> {
        self.validate()?;
        ExpensiveWorkGateContextV1::new(
            self.work_kind,
            self.org_id.clone(),
            self.project_id.clone(),
            self.environment.clone(),
            self.account_id.clone(),
            self.auth.to_gate_principal()?,
            self.trusted_source_digest,
        )
    }
}

/// Project policy outcome produced by Router-owned policy checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "policy", rename_all = "snake_case")]
pub enum CloudflareRouterProjectPolicyV1 {
    /// Project policy allows this work kind.
    Allowed,
    /// Project policy rejects this work kind before signer capacity is used.
    Rejected {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
}

impl CloudflareRouterProjectPolicyV1 {
    /// Validates project policy branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::Rejected { retry_after_ms } => {
                require_positive_ms("project policy retry_after_ms", *retry_after_ms)
            }
        }
    }
}

/// Abuse-control outcome produced by Router-owned abuse checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "abuse", rename_all = "snake_case")]
pub enum CloudflareRouterAbuseCheckV1 {
    /// Abuse checks allow the request.
    Allowed,
    /// Request is rate-limited before signer capacity is used.
    RateLimited {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
    /// Abuse policy rejects the request before signer capacity is used.
    Rejected {
        /// Retry-after duration in milliseconds.
        retry_after_ms: u64,
    },
}

impl CloudflareRouterAbuseCheckV1 {
    /// Validates abuse-check branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Allowed => Ok(()),
            Self::RateLimited { retry_after_ms } => {
                require_positive_ms("abuse rate-limit retry_after_ms", *retry_after_ms)
            }
            Self::Rejected { retry_after_ms } => {
                require_positive_ms("abuse rejection retry_after_ms", *retry_after_ms)
            }
        }
    }
}

/// Quota and queue outcome produced by Router-owned gate checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "quota", rename_all = "snake_case")]
pub enum CloudflareRouterQuotaCheckV1 {
    /// New expensive work is allowed.
    Accepted {
        /// Router-assigned request id.
        request_id: String,
    },
    /// Existing active lifecycle should be reused.
    ReuseExisting {
        /// Router-assigned request id.
        request_id: String,
        /// Existing lifecycle id.
        existing_lifecycle_id: String,
    },
    /// Short-window quota is saturated.
    ShortWindowSaturated,
    /// Signer queue is saturated.
    SignerQueueSaturated,
}

impl CloudflareRouterQuotaCheckV1 {
    /// Validates quota branch fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Accepted { request_id } => require_non_empty("request_id", request_id),
            Self::ReuseExisting {
                request_id,
                existing_lifecycle_id,
            } => {
                require_non_empty("request_id", request_id)?;
                require_non_empty("existing_lifecycle_id", existing_lifecycle_id)
            }
            Self::ShortWindowSaturated | Self::SignerQueueSaturated => Ok(()),
        }
    }
}

/// Trusted Router admission check results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionChecksV1 {
    /// Project policy result.
    pub project_policy: CloudflareRouterProjectPolicyV1,
    /// Abuse-control result.
    pub abuse: CloudflareRouterAbuseCheckV1,
    /// Quota/queue result.
    pub quota: CloudflareRouterQuotaCheckV1,
}

impl CloudflareRouterAdmissionChecksV1 {
    /// Creates validated admission checks.
    pub fn new(
        project_policy: CloudflareRouterProjectPolicyV1,
        abuse: CloudflareRouterAbuseCheckV1,
        quota: CloudflareRouterQuotaCheckV1,
    ) -> RouterAbProtocolResult<Self> {
        let checks = Self {
            project_policy,
            abuse,
            quota,
        };
        checks.validate()?;
        Ok(checks)
    }

    /// Validates all trusted check results.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.project_policy.validate()?;
        self.abuse.validate()?;
        self.quota.validate()
    }

    /// Converts check results into the core expensive-work gate decision.
    pub fn to_gate_decision(&self) -> RouterAbProtocolResult<ExpensiveWorkGateDecisionV1> {
        self.validate()?;
        match &self.project_policy {
            CloudflareRouterProjectPolicyV1::Rejected { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::AbusePolicy,
                    *retry_after_ms,
                );
            }
            CloudflareRouterProjectPolicyV1::Allowed => {}
        }
        match &self.abuse {
            CloudflareRouterAbuseCheckV1::RateLimited { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::RateLimited,
                    *retry_after_ms,
                );
            }
            CloudflareRouterAbuseCheckV1::Rejected { retry_after_ms } => {
                return ExpensiveWorkGateDecisionV1::rejected(
                    GateRejectReasonV1::AbusePolicy,
                    *retry_after_ms,
                );
            }
            CloudflareRouterAbuseCheckV1::Allowed => {}
        }
        match &self.quota {
            CloudflareRouterQuotaCheckV1::Accepted { request_id } => {
                ExpensiveWorkGateDecisionV1::accepted(request_id.clone())
            }
            CloudflareRouterQuotaCheckV1::ReuseExisting {
                request_id,
                existing_lifecycle_id,
            } => ExpensiveWorkGateDecisionV1::reuse_existing(
                request_id.clone(),
                existing_lifecycle_id.clone(),
            ),
            CloudflareRouterQuotaCheckV1::ShortWindowSaturated => Ok(
                ExpensiveWorkGateDecisionV1::defer(GateDeferReasonV1::ShortWindowSaturated),
            ),
            CloudflareRouterQuotaCheckV1::SignerQueueSaturated => Ok(
                ExpensiveWorkGateDecisionV1::defer(GateDeferReasonV1::SignerQueueSaturated),
            ),
        }
    }
}

/// Typed output from Router-owned auth, policy, abuse, and quota providers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterAdmissionProviderOutputV1 {
    /// Trusted request metadata derived from auth/session context.
    pub metadata: CloudflareRouterTrustedRequestMetadataV1,
    /// Trusted policy, abuse, and quota results.
    pub checks: CloudflareRouterAdmissionChecksV1,
}

impl CloudflareRouterAdmissionProviderOutputV1 {
    /// Creates validated admission-provider output.
    pub fn new(
        metadata: CloudflareRouterTrustedRequestMetadataV1,
        checks: CloudflareRouterAdmissionChecksV1,
    ) -> RouterAbProtocolResult<Self> {
        let output = Self { metadata, checks };
        output.validate()?;
        Ok(output)
    }

    /// Validates provider output independent of a public request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.metadata.validate()?;
        self.checks.validate()
    }

    /// Validates provider output against the normalized public request.
    pub fn validate_for_request(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.metadata.validate_for_request(request)?;
        self.checks.validate()
    }
}

/// Router-owned boundary for auth, session, policy, abuse, and quota checks.
pub trait CloudflareRouterAdmissionProviderV1 {
    /// Evaluates all server-owned admission checks for a normalized public request.
    fn evaluate_public_request_admission(
        &mut self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<CloudflareRouterAdmissionProviderOutputV1>;
}

/// Derives trusted Router admission from a provider-owned admission boundary.
pub fn derive_cloudflare_router_trusted_admission_from_provider_v1(
    request: &PublicRouterRequestV1,
    provider: &mut impl CloudflareRouterAdmissionProviderV1,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
    request.validate()?;
    let output = provider.evaluate_public_request_admission(request)?;
    output.validate_for_request(request)?;
    derive_cloudflare_router_trusted_admission_v1(request, output.metadata, output.checks)
}

/// Derives trusted Router admission from server-owned metadata and checks.
pub fn derive_cloudflare_router_trusted_admission_v1(
    request: &PublicRouterRequestV1,
    metadata: CloudflareRouterTrustedRequestMetadataV1,
    checks: CloudflareRouterAdmissionChecksV1,
) -> RouterAbProtocolResult<CloudflareRouterTrustedAdmissionV1> {
    request.validate()?;
    metadata.validate_for_request(request)?;
    checks.validate()?;
    let admission = CloudflareRouterTrustedAdmissionV1::new(
        metadata.to_gate_context()?,
        checks.to_gate_decision()?,
    )?;
    admission.validate_for_request(request)?;
    Ok(admission)
}

/// Server-derived Router admission data for a public expensive-work request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterTrustedAdmissionV1 {
    /// Trusted Router-owned gate context.
    pub context: ExpensiveWorkGateContextV1,
    /// Trusted Router-owned gate decision.
    pub decision: ExpensiveWorkGateDecisionV1,
}

impl CloudflareRouterTrustedAdmissionV1 {
    /// Creates a validated trusted admission wrapper.
    pub fn new(
        context: ExpensiveWorkGateContextV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let admission = Self { context, decision };
        admission.validate()?;
        Ok(admission)
    }

    /// Validates the admission wrapper itself.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.decision.validate()
    }

    /// Validates server-derived admission data against the normalized request.
    pub fn validate_for_request(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.context.work_kind != request.lifecycle.work_kind {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted admission work kind does not match public request lifecycle",
            ));
        }
        if self.context.resource_id != request.lifecycle.account_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "trusted admission resource id does not match public request account",
            ));
        }
        match &self.context.principal {
            GatePrincipalV1::AuthenticatedSession { session_id, .. } => {
                if session_id != &request.lifecycle.session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "trusted authenticated session does not match public request lifecycle",
                    ));
                }
            }
            GatePrincipalV1::PreAuthSession {
                pre_auth_session_id,
            } => {
                if pre_auth_session_id != &request.lifecycle.session_id {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "trusted pre-auth session does not match public request lifecycle",
                    ));
                }
                if self.context.work_kind != ExpensiveWorkKindV1::RegistrationPrepare {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "pre-auth trusted admission is allowed only for registration prepare",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns whether signer forwarding is allowed for this decision.
    pub fn allows_signer_forwarding(&self) -> RouterAbProtocolResult<bool> {
        self.validate()?;
        Ok(matches!(
            self.decision,
            ExpensiveWorkGateDecisionV1::Accepted { .. }
                | ExpensiveWorkGateDecisionV1::ReuseExisting { .. }
        ))
    }

    /// Returns the lifecycle state that the Router should persist.
    pub fn lifecycle_state_for_request(
        &self,
        request: &PublicRouterRequestV1,
    ) -> RouterAbProtocolResult<RouterAbLifecycleStateV1> {
        self.validate_for_request(request)?;
        RouterAbLifecycleStateV1::apply_gate_decision(
            request.lifecycle.clone(),
            self.decision.clone(),
        )
    }
}

/// Gate-aware Router work plan after public request normalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "admission", rename_all = "snake_case")]
pub enum CloudflareRouterPublicAdmissionPlanV1 {
    /// Gate accepted or selected an existing lifecycle, so signer forwarding is allowed.
    Forward {
        /// Replay reservation call for the public request nonce.
        replay_reserve_call: CloudflareDurableObjectCallV1,
        /// Public lifecycle persistence call after gate application.
        lifecycle_put_call: CloudflareDurableObjectCallV1,
        /// Trusted Router-owned gate data.
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
        /// Canonical Router-to-Signer A wire message.
        signer_a_message: WireMessageV1,
        /// Canonical Router-to-Signer B wire message.
        signer_b_message: WireMessageV1,
    },
    /// Gate deferred or rejected the request before signer forwarding.
    Stop {
        /// Replay reservation call for the public request nonce.
        replay_reserve_call: CloudflareDurableObjectCallV1,
        /// Public lifecycle persistence call after gate application.
        lifecycle_put_call: CloudflareDurableObjectCallV1,
        /// Trusted Router-owned gate data.
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
    },
}

impl CloudflareRouterPublicAdmissionPlanV1 {
    /// Validates Router-only storage calls and admission branch consistency.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.replay_reserve_call().validate()?;
        self.lifecycle_put_call().validate()?;
        self.trusted_admission().validate()?;
        if self.replay_reserve_call().worker_role != CloudflareWorkerRoleV1::Router
            || self.replay_reserve_call().binding.scope
                != CloudflareDurableObjectScopeV1::RouterReplay
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "public Router admission plan replay call must use Router replay scope",
            ));
        }
        if self.lifecycle_put_call().worker_role != CloudflareWorkerRoleV1::Router
            || self.lifecycle_put_call().binding.scope
                != CloudflareDurableObjectScopeV1::RouterLifecycle
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                "public Router admission plan lifecycle call must use Router lifecycle scope",
            ));
        }
        match self {
            Self::Forward {
                signer_a_message,
                signer_b_message,
                trusted_admission,
                ..
            } => {
                if !trusted_admission.allows_signer_forwarding()? {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "public Router admission plan forward branch requires accepted gate decision",
                    ));
                }
                if signer_a_message.kind != WireMessageKindV1::RouterToSignerA {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan Signer A message has wrong branch",
                    ));
                }
                if signer_b_message.kind != WireMessageKindV1::RouterToSignerB {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan Signer B message has wrong branch",
                    ));
                }
                if signer_a_message.transcript_digest != signer_b_message.transcript_digest {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                        "public Router admission plan signer messages must share transcript digest",
                    ));
                }
                Ok(())
            }
            Self::Stop {
                trusted_admission, ..
            } => {
                if trusted_admission.allows_signer_forwarding()? {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::InvalidGateDecision,
                        "public Router admission plan stop branch requires defer or reject gate decision",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Returns the replay reservation call.
    pub fn replay_reserve_call(&self) -> &CloudflareDurableObjectCallV1 {
        match self {
            Self::Forward {
                replay_reserve_call,
                ..
            }
            | Self::Stop {
                replay_reserve_call,
                ..
            } => replay_reserve_call,
        }
    }

    /// Returns the lifecycle persistence call.
    pub fn lifecycle_put_call(&self) -> &CloudflareDurableObjectCallV1 {
        match self {
            Self::Forward {
                lifecycle_put_call, ..
            }
            | Self::Stop {
                lifecycle_put_call, ..
            } => lifecycle_put_call,
        }
    }

    /// Returns trusted admission data.
    pub fn trusted_admission(&self) -> &CloudflareRouterTrustedAdmissionV1 {
        match self {
            Self::Forward {
                trusted_admission, ..
            }
            | Self::Stop {
                trusted_admission, ..
            } => trusted_admission,
        }
    }
}

/// Public Router response after replay/lifecycle checks and signer forwarding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterPublicResponseV1 {
    /// Replay reservation response from the Router replay Durable Object.
    pub replay: CloudflareReplayReserveResponseV1,
    /// Public lifecycle receipt from the Router lifecycle Durable Object.
    pub lifecycle: CloudflareLifecyclePutReceiptV1,
    /// Encrypted, transcript-bound Signer A output package.
    pub signer_a_response: WireMessageV1,
    /// Encrypted, transcript-bound Signer B output package.
    pub signer_b_response: WireMessageV1,
}

impl CloudflareRouterPublicResponseV1 {
    /// Creates a validated public Router response.
    pub fn new(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        signer_a_response: WireMessageV1,
        signer_b_response: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            replay,
            lifecycle,
            signer_a_response,
            signer_b_response,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates response shape and signer response transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.replay.validate()?;
        self.lifecycle.validate()?;
        require_signer_response("signer_a_response", &self.signer_a_response)?;
        require_signer_response("signer_b_response", &self.signer_b_response)?;
        if self.signer_a_response.transcript_digest != self.signer_b_response.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "public Router response signer transcript digests must match",
            ));
        }
        Ok(())
    }

    /// Validates response identity against the gate-aware Router plan that produced it.
    pub fn validate_for_admission_plan(
        &self,
        plan: &CloudflareRouterPublicAdmissionPlanV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        plan.validate()?;
        let CloudflareRouterPublicAdmissionPlanV1::Forward {
            signer_a_message,
            signer_b_message,
            ..
        } = plan
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidGateDecision,
                "public Router signer response validation requires a forward admission plan",
            ));
        };
        if self.signer_a_response.transcript_digest != signer_a_message.transcript_digest
            || self.signer_b_response.transcript_digest != signer_b_message.transcript_digest
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "public Router response signer transcript digest does not match admission plan",
            ));
        }
        Ok(())
    }
}

/// Strict private signer response carrying opaque client and relayer proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerRecipientProofBundleResponseV1 {
    /// Producing signer role.
    pub signer_role: Role,
    /// Opaque client-delivery proof bundle for `x_client_base`.
    pub client_bundle: WireMessageV1,
    /// Opaque relayer-delivery proof bundle for `x_relayer_base`.
    pub relayer_bundle: WireMessageV1,
}

impl CloudflareSignerRecipientProofBundleResponseV1 {
    /// Creates a validated strict private signer response.
    pub fn new(
        signer_role: Role,
        client_bundle: WireMessageV1,
        relayer_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            signer_role,
            client_bundle,
            relayer_bundle,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates role, recipient class, and transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.signer_role)?;
        let client = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "client_bundle",
            &self.client_bundle,
            self.signer_role,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let relayer = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "relayer_bundle",
            &self.relayer_bundle,
            self.signer_role,
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
        )?;
        if client.signer != relayer.signer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "strict signer proof-bundle response signer identities must match",
            ));
        }
        if self.client_bundle.transcript_digest != self.relayer_bundle.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "strict signer proof-bundle response transcripts must match",
            ));
        }
        Ok(())
    }

    /// Validates this signer response against the Router payload that produced it.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        router_payload.validate()?;
        let client = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "client_bundle",
            &self.client_bundle,
            self.signer_role,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let relayer = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "relayer_bundle",
            &self.relayer_bundle,
            self.signer_role,
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
        )?;
        let expected_signer =
            expected_cloudflare_signer_identity_for_role_v1(router_payload, self.signer_role)?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "client_bundle",
            &client,
            router_payload,
            expected_signer,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "relayer_bundle",
            &relayer,
            router_payload,
            expected_signer,
        )
    }
}

/// Strict public Router response carrying only opaque client proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRouterRecipientProofBundleResponseV1 {
    /// Replay reservation response from the Router replay Durable Object.
    pub replay: CloudflareReplayReserveResponseV1,
    /// Public lifecycle receipt from the Router lifecycle Durable Object.
    pub lifecycle: CloudflareLifecyclePutReceiptV1,
    /// Signer A opaque client proof bundle.
    pub signer_a_client_bundle: WireMessageV1,
    /// Signer B opaque client proof bundle.
    pub signer_b_client_bundle: WireMessageV1,
}

impl CloudflareRouterRecipientProofBundleResponseV1 {
    /// Creates a validated strict public Router response.
    pub fn new(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        signer_a_client_bundle: WireMessageV1,
        signer_b_client_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self {
            replay,
            lifecycle,
            signer_a_client_bundle,
            signer_b_client_bundle,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates replay/lifecycle receipts and opaque client bundle shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.replay.validate()?;
        self.lifecycle.validate()?;
        let signer_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signer_a_client_bundle",
            &self.signer_a_client_bundle,
            Role::SignerA,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let signer_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signer_b_client_bundle",
            &self.signer_b_client_bundle,
            Role::SignerB,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        if signer_a.transcript_digest != signer_b.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "strict Router proof-bundle response transcripts must match",
            ));
        }
        Ok(())
    }

    /// Validates opaque client bundles against the Router payload that produced them.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        router_payload.validate()?;
        let signer_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signer_a_client_bundle",
            &self.signer_a_client_bundle,
            Role::SignerA,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        let signer_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signer_b_client_bundle",
            &self.signer_b_client_bundle,
            Role::SignerB,
            Role::Client,
            OpenedShareKind::XClientBase,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "signer_a_client_bundle",
            &signer_a,
            router_payload,
            &router_payload.signer_set().signer_a,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "signer_b_client_bundle",
            &signer_b,
            router_payload,
            &router_payload.signer_set().signer_b,
        )
    }
}

/// Strict Signer A relayer activation package for opaque relayer proof bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRelayerRecipientProofBundleActivationV1 {
    /// Signer A opaque relayer proof bundle.
    pub signer_a_relayer_bundle: WireMessageV1,
    /// Signer B opaque relayer proof bundle.
    pub signer_b_relayer_bundle: WireMessageV1,
}

impl CloudflareRelayerRecipientProofBundleActivationV1 {
    /// Creates a validated strict relayer activation package.
    pub fn new(
        signer_a_relayer_bundle: WireMessageV1,
        signer_b_relayer_bundle: WireMessageV1,
    ) -> RouterAbProtocolResult<Self> {
        let activation = Self {
            signer_a_relayer_bundle,
            signer_b_relayer_bundle,
        };
        activation.validate()?;
        Ok(activation)
    }

    /// Validates opaque relayer bundle shape and transcript agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let signer_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signer_a_relayer_bundle",
            &self.signer_a_relayer_bundle,
            Role::SignerA,
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
        )?;
        let signer_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signer_b_relayer_bundle",
            &self.signer_b_relayer_bundle,
            Role::SignerB,
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
        )?;
        if signer_a.transcript_digest != signer_b.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "strict relayer proof-bundle activation transcripts must match",
            ));
        }
        Ok(())
    }

    /// Validates opaque relayer bundles against the Router payload that produced them.
    pub fn validate_for_router_payload(
        &self,
        router_payload: &RouterToSignerPayloadV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        router_payload.validate()?;
        let signer_a = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signer_a_relayer_bundle",
            &self.signer_a_relayer_bundle,
            Role::SignerA,
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
        )?;
        let signer_b = decode_cloudflare_recipient_proof_bundle_wire_v1(
            "signer_b_relayer_bundle",
            &self.signer_b_relayer_bundle,
            Role::SignerB,
            Role::Relayer,
            OpenedShareKind::XRelayerBase,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "signer_a_relayer_bundle",
            &signer_a,
            router_payload,
            &router_payload.signer_set().signer_a,
        )?;
        validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
            "signer_b_relayer_bundle",
            &signer_b,
            router_payload,
            &router_payload.signer_set().signer_b,
        )
    }
}

/// Signer A relayer activation request for strict opaque proof-bundle delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareRelayerRecipientProofBundleActivationRequestV1 {
    /// Router-to-Signer A payload used as the activation transcript context.
    pub router_payload: RouterToSignerPayloadV1,
    /// Opaque relayer proof bundles from Signer A and Signer B.
    pub activation: CloudflareRelayerRecipientProofBundleActivationV1,
}

impl CloudflareRelayerRecipientProofBundleActivationRequestV1 {
    /// Creates a validated Signer A relayer activation request.
    pub fn new(
        router_payload: RouterToSignerPayloadV1,
        activation: CloudflareRelayerRecipientProofBundleActivationV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            router_payload,
            activation,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the Router payload and opaque relayer bundles.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.router_payload.require_recipient_role(Role::SignerA)?;
        self.activation
            .validate_for_router_payload(&self.router_payload)
    }
}

/// Strict Router result after gate handling and Signer A relayer activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterRecipientProofBundleAdmissionResponseV1 {
    /// Request was accepted, signer client bundles were aggregated, and relayer activation ran.
    Forwarded {
        /// Public client proof-bundle response.
        response: CloudflareRouterRecipientProofBundleResponseV1,
        /// Signer A relayer activation receipt.
        relayer_activation: CloudflareRelayerOutputActivationReceiptV1,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Replay reservation response from the Router replay Durable Object.
        replay: CloudflareReplayReserveResponseV1,
        /// Public lifecycle receipt from the Router lifecycle Durable Object.
        lifecycle: CloudflareLifecyclePutReceiptV1,
        /// Gate decision returned to the caller.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterRecipientProofBundleAdmissionResponseV1 {
    /// Creates a forwarded strict Router result.
    pub fn forwarded(
        response: CloudflareRouterRecipientProofBundleResponseV1,
        relayer_activation: CloudflareRelayerOutputActivationReceiptV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Forwarded {
            response,
            relayer_activation,
        };
        result.validate()?;
        Ok(result)
    }

    /// Creates a stopped strict Router result.
    pub fn stopped(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let result = Self::Stopped {
            replay,
            lifecycle,
            decision,
        };
        result.validate()?;
        Ok(result)
    }

    /// Validates strict Router response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded {
                response,
                relayer_activation,
            } => {
                response.validate()?;
                relayer_activation.validate()
            }
            Self::Stopped {
                replay,
                lifecycle,
                decision,
            } => {
                replay.validate()?;
                lifecycle.validate()?;
                decision.validate()
            }
        }
    }
}

/// Public Router result after gate handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum CloudflareRouterPublicAdmissionResponseV1 {
    /// Request was accepted and forwarded to both signers.
    Forwarded {
        /// Aggregated signer response.
        response: CloudflareRouterPublicResponseV1,
    },
    /// Request stopped at the Router gate before signer forwarding.
    Stopped {
        /// Replay reservation response from the Router replay Durable Object.
        replay: CloudflareReplayReserveResponseV1,
        /// Public lifecycle receipt from the Router lifecycle Durable Object.
        lifecycle: CloudflareLifecyclePutReceiptV1,
        /// Gate decision returned to the caller.
        decision: ExpensiveWorkGateDecisionV1,
    },
}

impl CloudflareRouterPublicAdmissionResponseV1 {
    /// Creates a forwarded public Router result.
    pub fn forwarded(response: CloudflareRouterPublicResponseV1) -> RouterAbProtocolResult<Self> {
        response.validate()?;
        Ok(Self::Forwarded { response })
    }

    /// Creates a stopped public Router result.
    pub fn stopped(
        replay: CloudflareReplayReserveResponseV1,
        lifecycle: CloudflareLifecyclePutReceiptV1,
        decision: ExpensiveWorkGateDecisionV1,
    ) -> RouterAbProtocolResult<Self> {
        let response = Self::Stopped {
            replay,
            lifecycle,
            decision,
        };
        response.validate()?;
        Ok(response)
    }

    /// Validates response fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::Forwarded { response } => response.validate(),
            Self::Stopped {
                replay,
                lifecycle,
                decision,
            } => {
                replay.validate()?;
                lifecycle.validate()?;
                decision.validate()
            }
        }
    }
}

impl CloudflareRouterWorkerRuntimeV1 {
    /// Creates a Router runtime context from already parsed bindings.
    pub fn new(bindings: CloudflareRouterBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for Router startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::Router { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::Router,
                env,
            )?
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Router Worker Env parsing returned non-Router bindings",
            ));
        };
        Self::new(bindings)
    }

    /// Returns validated Router bindings.
    pub fn bindings(&self) -> &CloudflareRouterBindingsV1 {
        &self.bindings
    }

    /// Builds a Router replay Durable Object call.
    pub fn replay_reserve_call(
        &self,
        request: CloudflareReplayReserveRequestV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.replay.clone(),
            CloudflareDurableObjectRequestV1::router_replay_reserve(request)?,
        )
    }

    /// Builds a Router public-lifecycle Durable Object call.
    pub fn lifecycle_put_public_state_call(
        &self,
        state: RouterAbLifecycleStateV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::Router,
            self.bindings.lifecycle.clone(),
            CloudflareDurableObjectRequestV1::router_lifecycle_put_public_state(state)?,
        )
    }

    /// Validates a public request with trusted admission and builds gate-aware work.
    pub fn public_request_admission_plan_at(
        &self,
        now_unix_ms: u64,
        request: PublicRouterRequestV1,
        trusted_admission: CloudflareRouterTrustedAdmissionV1,
    ) -> RouterAbProtocolResult<CloudflareRouterPublicAdmissionPlanV1> {
        request.validate_at(now_unix_ms)?;
        trusted_admission.validate_for_request(&request)?;
        let replay_request = CloudflareReplayReserveRequestV1::new(
            request.request_nonce.clone(),
            request.router_replay_digest(),
            request.expires_at_ms,
        )?;
        let replay_reserve_call = self.replay_reserve_call(replay_request)?;
        let lifecycle_put_call = self.lifecycle_put_public_state_call(
            trusted_admission.lifecycle_state_for_request(&request)?,
        )?;
        let plan = if trusted_admission.allows_signer_forwarding()? {
            let (signer_a_message, signer_b_message) = request.to_signer_wire_messages()?;
            CloudflareRouterPublicAdmissionPlanV1::Forward {
                replay_reserve_call,
                lifecycle_put_call,
                trusted_admission,
                signer_a_message,
                signer_b_message,
            }
        } else {
            CloudflareRouterPublicAdmissionPlanV1::Stop {
                replay_reserve_call,
                lifecycle_put_call,
                trusted_admission,
            }
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Returns the Signer A peer binding used by the Router transport wrapper.
    pub fn signer_a_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.signer_a
    }

    /// Returns the Signer B peer binding used by the Router transport wrapper.
    pub fn signer_b_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.signer_b
    }
}

impl CloudflareSignerARelayerWorkerRuntimeV1 {
    /// Creates a Signer A/Relayer runtime context from parsed bindings.
    pub fn new(bindings: CloudflareSignerARelayerBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for Signer A startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::SignerARelayer { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::SignerARelayer,
                env,
            )?
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Signer A Worker Env parsing returned wrong binding branch",
            ));
        };
        Self::new(bindings)
    }

    /// Returns validated Signer A/Relayer bindings.
    pub fn bindings(&self) -> &CloudflareSignerARelayerBindingsV1 {
        &self.bindings
    }

    /// Builds a Signer A root-share presence check call.
    pub fn root_share_has_call(
        &self,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        let lookup = CloudflareRootShareLookupRequestV1::new(
            signer_set_id,
            Role::SignerA,
            root_share_epoch,
        )?;
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerARelayer,
            self.bindings.root_share.clone(),
            CloudflareDurableObjectRequestV1::root_share_has(lookup)?,
        )
    }

    /// Builds a Signer A root-share startup metadata call.
    pub fn root_share_startup_metadata_call(
        &self,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        let lookup = CloudflareRootShareLookupRequestV1::new(
            signer_set_id,
            Role::SignerA,
            root_share_epoch,
        )?;
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerARelayer,
            self.bindings.root_share.clone(),
            CloudflareDurableObjectRequestV1::root_share_startup_metadata(lookup)?,
        )
    }

    /// Builds a Signer A relayer-output activation call.
    pub fn relayer_output_activate_call(
        &self,
        activation: RelayerActivationPayloadV1,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerARelayer,
            self.bindings.relayer_output.clone(),
            CloudflareDurableObjectRequestV1::relayer_output_activate(activation)?,
        )
    }

    /// Returns Signer B peer binding used by direct A/B coordination.
    pub fn signer_b_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.signer_b
    }

    /// Returns Signer A's role-local root-share wire Secret descriptor.
    pub fn root_share_wire_secret(&self) -> &CloudflareRootShareWireSecretBindingV1 {
        &self.bindings.root_share_wire_secret
    }

    /// Returns Signer A's role-local signer-envelope decrypt-key descriptor.
    pub fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeDecryptKeyBindingV1 {
        &self.bindings.envelope_decrypt_key
    }

    /// Returns Signer A's role-local A/B peer signing-key descriptor.
    pub fn peer_signing_key(&self) -> &CloudflareSignerPeerSigningKeyBindingV1 {
        &self.bindings.peer_signing_key
    }

    /// Returns trusted A/B peer verifying keys bound to a request signer set.
    pub fn peer_verifying_keys_for_signer_set(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        self.bindings
            .peer_verifying_keys
            .to_protocol_keys(signer_set)
    }
}

impl CloudflareSignerBWorkerRuntimeV1 {
    /// Creates a Signer B runtime context from parsed bindings.
    pub fn new(bindings: CloudflareSignerBBindingsV1) -> RouterAbProtocolResult<Self> {
        bindings.validate()?;
        Ok(Self { bindings })
    }

    /// Parses and validates a real Cloudflare Worker Env for Signer B startup.
    #[cfg(feature = "workers-rs")]
    pub fn from_worker_env(env: &worker::Env) -> RouterAbProtocolResult<Self> {
        let CloudflareWorkerBindingsV1::SignerB { bindings } =
            parse_cloudflare_worker_bindings_from_worker_env_v1(
                CloudflareWorkerRoleV1::SignerB,
                env,
            )?
        else {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Signer B Worker Env parsing returned wrong binding branch",
            ));
        };
        Self::new(bindings)
    }

    /// Returns validated Signer B bindings.
    pub fn bindings(&self) -> &CloudflareSignerBBindingsV1 {
        &self.bindings
    }

    /// Builds a Signer B root-share presence check call.
    pub fn root_share_has_call(
        &self,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        let lookup = CloudflareRootShareLookupRequestV1::new(
            signer_set_id,
            Role::SignerB,
            root_share_epoch,
        )?;
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerB,
            self.bindings.root_share.clone(),
            CloudflareDurableObjectRequestV1::root_share_has(lookup)?,
        )
    }

    /// Builds a Signer B root-share startup metadata call.
    pub fn root_share_startup_metadata_call(
        &self,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
    ) -> RouterAbProtocolResult<CloudflareDurableObjectCallV1> {
        let lookup = CloudflareRootShareLookupRequestV1::new(
            signer_set_id,
            Role::SignerB,
            root_share_epoch,
        )?;
        CloudflareDurableObjectCallV1::new(
            CloudflareWorkerRoleV1::SignerB,
            self.bindings.root_share.clone(),
            CloudflareDurableObjectRequestV1::root_share_startup_metadata(lookup)?,
        )
    }

    /// Returns Signer A/Relayer peer binding used by direct A/B coordination.
    pub fn signer_a_relayer_peer(&self) -> &CloudflarePeerBindingV1 {
        &self.bindings.signer_a_relayer
    }

    /// Returns Signer B's role-local root-share wire Secret descriptor.
    pub fn root_share_wire_secret(&self) -> &CloudflareRootShareWireSecretBindingV1 {
        &self.bindings.root_share_wire_secret
    }

    /// Returns Signer B's role-local signer-envelope decrypt-key descriptor.
    pub fn envelope_decrypt_key(&self) -> &CloudflareSignerEnvelopeDecryptKeyBindingV1 {
        &self.bindings.envelope_decrypt_key
    }

    /// Returns Signer B's role-local A/B peer signing-key descriptor.
    pub fn peer_signing_key(&self) -> &CloudflareSignerPeerSigningKeyBindingV1 {
        &self.bindings.peer_signing_key
    }

    /// Returns trusted A/B peer verifying keys bound to a request signer set.
    pub fn peer_verifying_keys_for_signer_set(
        &self,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<Vec<AbPeerMessageVerifyingKeyV1>> {
        self.bindings
            .peer_verifying_keys
            .to_protocol_keys(signer_set)
    }
}

/// Preloads a Signer A/Relayer host from real Cloudflare resources.
#[cfg(feature = "workers-rs")]
pub async fn preload_cloudflare_signer_a_host_v1(
    env: &worker::Env,
    runtime: &CloudflareSignerARelayerWorkerRuntimeV1,
    input: CloudflareSignerHostPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    input.validate()?;
    let metadata_call = runtime.root_share_startup_metadata_call(
        input.signer_set_id.clone(),
        input.root_share_epoch.clone(),
    )?;
    preload_cloudflare_signer_host_from_metadata_call_v1(
        env,
        metadata_call,
        CloudflareWorkerRoleV1::SignerARelayer,
        Role::SignerA,
        runtime.root_share_wire_secret(),
        input,
    )
    .await
}

/// Preloads a Signer B host from real Cloudflare resources.
#[cfg(feature = "workers-rs")]
pub async fn preload_cloudflare_signer_b_host_v1(
    env: &worker::Env,
    runtime: &CloudflareSignerBWorkerRuntimeV1,
    input: CloudflareSignerHostPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    input.validate()?;
    let metadata_call = runtime.root_share_startup_metadata_call(
        input.signer_set_id.clone(),
        input.root_share_epoch.clone(),
    )?;
    preload_cloudflare_signer_host_from_metadata_call_v1(
        env,
        metadata_call,
        CloudflareWorkerRoleV1::SignerB,
        Role::SignerB,
        runtime.root_share_wire_secret(),
        input,
    )
    .await
}

/// Preloads Signer A/Relayer host after direct A/B peer requests are executed.
#[cfg(feature = "workers-rs")]
pub async fn preload_cloudflare_signer_a_host_with_peer_requests_v1(
    env: &worker::Env,
    runtime: &CloudflareSignerARelayerWorkerRuntimeV1,
    input: CloudflareSignerHostPeerPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    input.validate()?;
    let peer_responses = execute_cloudflare_signer_peer_requests_v1(
        env,
        runtime.signer_b_peer(),
        &input.peer_requests,
    )
    .await?;
    let host_input = CloudflareSignerHostPreloadInputV1::new(
        input.signer_set_id,
        input.root_share_epoch,
        peer_responses,
        input.signer_verifying_keys,
        input.random_bytes_len,
    )?;
    preload_cloudflare_signer_a_host_v1(env, runtime, host_input).await
}

/// Preloads Signer B host after direct A/B peer requests are executed.
#[cfg(feature = "workers-rs")]
pub async fn preload_cloudflare_signer_b_host_with_peer_requests_v1(
    env: &worker::Env,
    runtime: &CloudflareSignerBWorkerRuntimeV1,
    input: CloudflareSignerHostPeerPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    input.validate()?;
    let peer_responses = execute_cloudflare_signer_peer_requests_v1(
        env,
        runtime.signer_a_relayer_peer(),
        &input.peer_requests,
    )
    .await?;
    let host_input = CloudflareSignerHostPreloadInputV1::new(
        input.signer_set_id,
        input.root_share_epoch,
        peer_responses,
        input.signer_verifying_keys,
        input.random_bytes_len,
    )?;
    preload_cloudflare_signer_b_host_v1(env, runtime, host_input).await
}

#[cfg(feature = "workers-rs")]
async fn preload_cloudflare_signer_host_from_metadata_call_v1(
    env: &worker::Env,
    metadata_call: CloudflareDurableObjectCallV1,
    worker_role: CloudflareWorkerRoleV1,
    expected_role: Role,
    root_share_wire_secret: &CloudflareRootShareWireSecretBindingV1,
    input: CloudflareSignerHostPreloadInputV1,
) -> RouterAbProtocolResult<CloudflarePreloadedSignerHostV1> {
    let metadata_response = execute_cloudflare_durable_object_call_v1(env, &metadata_call).await?;
    let CloudflareDurableObjectResponseV1::RootShareStartupMetadata { metadata } =
        metadata_response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "root-share metadata preload returned wrong Durable Object response branch",
        ));
    };
    let root_share_wire = load_cloudflare_root_share_wire_secret_v1(
        env,
        worker_role,
        root_share_wire_secret,
        &metadata,
    )?;
    let random_bytes = cloudflare_random_bytes_v1(input.random_bytes_len)?;
    build_cloudflare_preloaded_signer_host_with_root_share_wire_v1(
        cloudflare_now_unix_ms_v1()?,
        expected_role,
        input,
        metadata,
        root_share_wire.signing_root_share_wire(),
        random_bytes,
    )
}

/// Executes a gate-aware public Router plan through injectable transports.
pub fn execute_cloudflare_router_public_admission_plan_v1(
    runtime: &CloudflareRouterWorkerRuntimeV1,
    plan: &CloudflareRouterPublicAdmissionPlanV1,
    executor: &mut impl CloudflareRouterPublicPlanExecutorV1,
) -> RouterAbProtocolResult<CloudflareRouterPublicAdmissionResponseV1> {
    plan.validate()?;
    let replay = require_router_replay_reserve_response_v1(
        plan.replay_reserve_call(),
        executor.execute_durable_object_call(plan.replay_reserve_call())?,
    )?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "public Router request replay reservation already exists",
        ));
    }
    let lifecycle = require_router_lifecycle_put_response_v1(
        plan.lifecycle_put_call(),
        executor.execute_durable_object_call(plan.lifecycle_put_call())?,
    )?;
    match plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            signer_a_message,
            signer_b_message,
            ..
        } => {
            let signer_a_response =
                executor.send_signer_message(runtime.signer_a_peer(), signer_a_message)?;
            let signer_b_response =
                executor.send_signer_message(runtime.signer_b_peer(), signer_b_message)?;
            let response = CloudflareRouterPublicResponseV1::new(
                replay,
                lifecycle,
                signer_a_response,
                signer_b_response,
            )?;
            response.validate_for_admission_plan(plan)?;
            CloudflareRouterPublicAdmissionResponseV1::forwarded(response)
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterPublicAdmissionResponseV1::stopped(
            replay,
            lifecycle,
            trusted_admission.decision.clone(),
        ),
    }
}

/// Handles a parsed public Router request through real Cloudflare bindings.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_public_request_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: PublicRouterRequestV1,
    trusted_admission: CloudflareRouterTrustedAdmissionV1,
) -> RouterAbProtocolResult<CloudflareRouterPublicAdmissionResponseV1> {
    let plan = runtime.public_request_admission_plan_at(now_unix_ms, request, trusted_admission)?;
    let replay =
        execute_cloudflare_router_replay_reserve_v1(env, plan.replay_reserve_call()).await?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "public Router request replay reservation already exists",
        ));
    }
    let lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_put_call()).await?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            signer_a_message,
            signer_b_message,
            ..
        } => {
            let (signer_a_result, signer_b_result) = futures::join!(
                execute_cloudflare_signer_service_call_v1(
                    env,
                    runtime.signer_a_peer(),
                    signer_a_message,
                ),
                execute_cloudflare_signer_service_call_v1(
                    env,
                    runtime.signer_b_peer(),
                    signer_b_message,
                ),
            );
            let response = CloudflareRouterPublicResponseV1::new(
                replay,
                lifecycle,
                signer_a_result?,
                signer_b_result?,
            )?;
            response.validate_for_admission_plan(&plan)?;
            CloudflareRouterPublicAdmissionResponseV1::forwarded(response)
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterPublicAdmissionResponseV1::stopped(
            replay,
            lifecycle,
            trusted_admission.decision.clone(),
        ),
    }
}

/// Handles the public Router route using strict recipient proof-bundle delivery.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_recipient_proof_bundle_public_request_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    request: PublicRouterRequestV1,
    trusted_admission: CloudflareRouterTrustedAdmissionV1,
) -> RouterAbProtocolResult<CloudflareRouterRecipientProofBundleAdmissionResponseV1> {
    let plan = runtime.public_request_admission_plan_at(now_unix_ms, request, trusted_admission)?;
    let replay =
        execute_cloudflare_router_replay_reserve_v1(env, plan.replay_reserve_call()).await?;
    if !replay.reserved {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::ReplayedLocalRequest,
            "public Router request replay reservation already exists",
        ));
    }
    let lifecycle =
        execute_cloudflare_router_lifecycle_put_v1(env, plan.lifecycle_put_call()).await?;
    match &plan {
        CloudflareRouterPublicAdmissionPlanV1::Forward {
            signer_a_message,
            signer_b_message,
            ..
        } => {
            let (signer_a_result, signer_b_result) = futures::join!(
                execute_cloudflare_signer_recipient_proof_bundle_service_call_v1(
                    env,
                    runtime.signer_a_peer(),
                    signer_a_message,
                ),
                execute_cloudflare_signer_recipient_proof_bundle_service_call_v1(
                    env,
                    runtime.signer_b_peer(),
                    signer_b_message,
                ),
            );
            let signer_a_response = signer_a_result?;
            let signer_b_response = signer_b_result?;
            let response = CloudflareRouterRecipientProofBundleResponseV1::new(
                replay,
                lifecycle,
                signer_a_response.client_bundle.clone(),
                signer_b_response.client_bundle.clone(),
            )?;
            let router_payload =
                decode_router_to_signer_payload_v1(signer_a_message.payload.as_bytes())?;
            response.validate_for_router_payload(&router_payload)?;
            let activation = CloudflareRelayerRecipientProofBundleActivationRequestV1::new(
                router_payload,
                CloudflareRelayerRecipientProofBundleActivationV1::new(
                    signer_a_response.relayer_bundle,
                    signer_b_response.relayer_bundle,
                )?,
            )?;
            let relayer_activation =
                execute_cloudflare_signer_a_recipient_proof_bundle_activation_service_call_v1(
                    env,
                    runtime.signer_a_peer(),
                    &activation,
                )
                .await?;
            CloudflareRouterRecipientProofBundleAdmissionResponseV1::forwarded(
                response,
                relayer_activation,
            )
        }
        CloudflareRouterPublicAdmissionPlanV1::Stop {
            trusted_admission, ..
        } => CloudflareRouterRecipientProofBundleAdmissionResponseV1::stopped(
            replay,
            lifecycle,
            trusted_admission.decision.clone(),
        ),
    }
}

/// Activates relayer-output material through Signer A's Cloudflare Durable Object binding.
#[cfg(feature = "workers-rs")]
pub async fn activate_cloudflare_signer_a_relayer_output_v1(
    env: &worker::Env,
    runtime: &CloudflareSignerARelayerWorkerRuntimeV1,
    activation: RelayerActivationPayloadV1,
) -> RouterAbProtocolResult<CloudflareRelayerOutputActivationReceiptV1> {
    let call = runtime.relayer_output_activate_call(activation)?;
    let response = execute_cloudflare_durable_object_call_v1(env, &call).await?;
    require_relayer_output_activate_response_v1(&call, response)
}

/// Handles the public Router split-derivation HTTP route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_public_fetch_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    trusted_admission: CloudflareRouterTrustedAdmissionV1,
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B public route requires POST", 405);
    }
    if request.path() != CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B public request must be served at {}",
                CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request.json::<PublicRouterRequestV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B public request JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_router_public_request_v1(
        env,
        runtime,
        now_unix_ms,
        parsed,
        trusted_admission,
    )
    .await
    {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles the public Router split-derivation HTTP route with strict proof-bundle delivery.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_router_recipient_proof_bundle_public_fetch_v1(
    env: &worker::Env,
    runtime: &CloudflareRouterWorkerRuntimeV1,
    now_unix_ms: u64,
    trusted_admission: CloudflareRouterTrustedAdmissionV1,
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B strict public route requires POST", 405);
    }
    if request.path() != CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B strict public request must be served at {}",
                CLOUDFLARE_ROUTER_PUBLIC_REQUEST_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request.json::<PublicRouterRequestV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B strict public request JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_router_recipient_proof_bundle_public_request_v1(
        env,
        runtime,
        now_unix_ms,
        parsed,
        trusted_admission,
    )
    .await
    {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Validates a private Router-to-signer message for the target Worker role.
pub fn validate_cloudflare_signer_private_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    let expected = expected_signer_private_request_kind_v1(worker_role)?;
    if message.kind != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "{} private signer endpoint expected {} message, received {}",
                worker_role.as_str(),
                expected.as_str(),
                message.kind.as_str()
            ),
        ));
    }
    let payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    if payload.transcript_digest() != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "private signer request payload transcript digest does not match wire message",
        ));
    }
    match (worker_role, payload) {
        (CloudflareWorkerRoleV1::SignerARelayer, RouterToSignerPayloadV1::SignerA { .. })
        | (CloudflareWorkerRoleV1::SignerB, RouterToSignerPayloadV1::SignerB { .. }) => Ok(()),
        (CloudflareWorkerRoleV1::SignerARelayer | CloudflareWorkerRoleV1::SignerB, _) => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "private signer request payload branch does not match Worker role",
            ))
        }
        (CloudflareWorkerRoleV1::Router, _) => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Router Worker has no private signer payload branch",
        )),
    }
}

/// Decodes and validates public signer-envelope AEAD metadata before decryption.
pub fn decode_and_validate_cloudflare_signer_envelope_aead_payload_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeDecryptKeyBindingV1,
) -> RouterAbProtocolResult<SignerEnvelopeAeadPayloadV1> {
    validate_cloudflare_signer_private_request_v1(worker_role, message)?;
    envelope_decrypt_key.validate_visible_to(worker_role)?;
    let expected_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if envelope_decrypt_key.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Cloudflare signer envelope key role does not match Worker role",
        ));
    }
    let payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    let envelope = &payload.assignment().envelope;
    decode_and_validate_signer_envelope_aead_payload_v1(envelope, &envelope_decrypt_key.key_epoch)
}

/// Strict private signer bootstrap body supplied by Router before envelope decryption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerPrivateBootstrapRequestV1 {
    /// Router-to-signer private wire message.
    pub message: WireMessageV1,
    /// Typed role-envelope AAD used by Router during signer-envelope encryption.
    pub aad: RoleEnvelopeAadV1,
    /// Pre-envelope public request-context digest bound inside signer plaintext.
    pub router_request_digest: PublicDigest32,
}

impl CloudflareSignerPrivateBootstrapRequestV1 {
    /// Creates a validated strict private signer bootstrap body.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        message: WireMessageV1,
        aad: RoleEnvelopeAadV1,
        router_request_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let bootstrap = Self {
            message,
            aad,
            router_request_digest,
        };
        bootstrap.validate_for_worker_role(worker_role)?;
        Ok(bootstrap)
    }

    /// Validates that the typed AAD matches the role-local Router payload.
    pub fn validate_for_worker_role(
        &self,
        worker_role: CloudflareWorkerRoleV1,
    ) -> RouterAbProtocolResult<()> {
        validate_cloudflare_signer_private_request_v1(worker_role, &self.message)?;
        self.aad.validate()?;
        let payload = decode_router_to_signer_payload_v1(self.message.payload.as_bytes())?;
        let assignment = payload.assignment();
        if self.aad.digest() != assignment.envelope.aad_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "strict signer bootstrap AAD digest does not match role envelope",
            ));
        }
        if self.aad.recipient != assignment.signer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "strict signer bootstrap AAD recipient does not match assignment signer",
            ));
        }
        if self.aad.signer_set_id != payload.signer_set().signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "strict signer bootstrap AAD signer-set id does not match payload",
            ));
        }
        if self.aad.selected_relayer != payload.signer_set().selected_relayer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "strict signer bootstrap AAD relayer does not match signer set",
            ));
        }
        if self.aad.lifecycle_id != payload.lifecycle().lifecycle_id
            || self.aad.work_kind != payload.lifecycle().work_kind
            || self.aad.primitive_request_kind != payload.lifecycle().primitive_request_kind
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "strict signer bootstrap AAD lifecycle scope does not match payload",
            ));
        }
        if self.aad.transcript_digest != payload.transcript_digest() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "strict signer bootstrap AAD transcript digest does not match payload",
            ));
        }
        if self.aad.router_request_digest != self.router_request_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "strict signer bootstrap AAD Router request digest does not match body",
            ));
        }
        Ok(())
    }
}

/// Public preload coordinates derived from a strict private signer bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerHostPreloadPlanV1 {
    /// Worker role that owns the private signer request.
    pub worker_role: CloudflareWorkerRoleV1,
    /// Signer set id whose local root-share metadata must be loaded.
    pub signer_set_id: String,
    /// Root-share epoch to load for the local signer role.
    pub root_share_epoch: RootShareEpoch,
    /// Local signer identity bound by the Router payload.
    pub local_signer: SignerIdentityV1,
    /// Signer set bound by the Router payload.
    pub signer_set: SignerSetV1,
    /// Transcript digest bound by the Router-to-signer wire message.
    pub transcript_digest: PublicDigest32,
    /// Pre-envelope public request-context digest bound inside signer plaintext.
    pub router_request_digest: PublicDigest32,
}

impl CloudflareSignerHostPreloadPlanV1 {
    /// Creates validated signer-host preload coordinates.
    pub fn new(
        worker_role: CloudflareWorkerRoleV1,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        local_signer: SignerIdentityV1,
        signer_set: SignerSetV1,
        transcript_digest: PublicDigest32,
        router_request_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let plan = Self {
            worker_role,
            signer_set_id: signer_set_id.into(),
            root_share_epoch,
            local_signer,
            signer_set,
            transcript_digest,
            router_request_digest,
        };
        plan.validate()?;
        Ok(plan)
    }

    /// Derives preload coordinates from a validated strict private bootstrap body.
    pub fn from_private_bootstrap(
        worker_role: CloudflareWorkerRoleV1,
        bootstrap: &CloudflareSignerPrivateBootstrapRequestV1,
    ) -> RouterAbProtocolResult<Self> {
        bootstrap.validate_for_worker_role(worker_role)?;
        let payload = decode_router_to_signer_payload_v1(bootstrap.message.payload.as_bytes())?;
        let local_role = cloudflare_worker_signer_role_v1(worker_role)?;
        let local_signer =
            expected_cloudflare_signer_identity_for_role_v1(&payload, local_role)?.clone();
        Self::new(
            worker_role,
            payload.signer_set().signer_set_id.clone(),
            payload.lifecycle().root_share_epoch.clone(),
            local_signer,
            payload.signer_set().clone(),
            bootstrap.message.transcript_digest,
            bootstrap.router_request_digest,
        )
    }

    /// Validates signer-host preload coordinates.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        let expected_role = cloudflare_worker_signer_role_v1(self.worker_role)?;
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        self.local_signer.validate()?;
        self.signer_set.validate()?;
        if self.local_signer.role != expected_role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer-host preload plan local signer does not match Worker role",
            ));
        }
        if self.signer_set.signer_set_id != self.signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer-host preload plan signer-set id does not match signer set",
            ));
        }
        let expected_local = match expected_role {
            Role::SignerA => &self.signer_set.signer_a,
            Role::SignerB => &self.signer_set.signer_b,
            _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
        };
        if &self.local_signer != expected_local {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer-host preload plan local signer does not match signer-set role",
            ));
        }
        Ok(())
    }

    /// Builds signer-host preload input after the adapter supplies peer material.
    pub fn to_host_preload_input(
        &self,
        peer_responses: Vec<WireMessageV1>,
        signer_verifying_keys: Vec<AbPeerMessageVerifyingKeyV1>,
        random_bytes_len: usize,
    ) -> RouterAbProtocolResult<CloudflareSignerHostPreloadInputV1> {
        self.validate()?;
        CloudflareSignerHostPreloadInputV1::new(
            self.signer_set_id.clone(),
            self.root_share_epoch.clone(),
            peer_responses,
            signer_verifying_keys,
            random_bytes_len,
        )
    }

    /// Builds signer-host preload input from a trusted public verifying-key set.
    pub fn to_host_preload_input_with_key_set(
        &self,
        peer_responses: Vec<WireMessageV1>,
        peer_verifying_keys: &CloudflareSignerPeerVerifyingKeySetV1,
        random_bytes_len: usize,
    ) -> RouterAbProtocolResult<CloudflareSignerHostPreloadInputV1> {
        self.validate()?;
        self.to_host_preload_input(
            peer_responses,
            peer_verifying_keys.to_protocol_keys(&self.signer_set)?,
            random_bytes_len,
        )
    }
}

/// Private signer request after envelope decryption and signer-input validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareValidatedSignerPrivateRequestV1 {
    worker_role: CloudflareWorkerRoleV1,
    message: WireMessageV1,
    router_payload: RouterToSignerPayloadV1,
    signer_input: SignerInputPlaintextV1,
}

impl CloudflareValidatedSignerPrivateRequestV1 {
    fn new(
        worker_role: CloudflareWorkerRoleV1,
        message: WireMessageV1,
        router_payload: RouterToSignerPayloadV1,
        signer_input: SignerInputPlaintextV1,
    ) -> RouterAbProtocolResult<Self> {
        validate_cloudflare_signer_private_request_v1(worker_role, &message)?;
        if router_payload.transcript_digest() != message.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "validated signer request payload transcript digest does not match wire message",
            ));
        }
        router_payload.require_recipient_role(cloudflare_worker_signer_role_v1(worker_role)?)?;
        Ok(Self {
            worker_role,
            message,
            router_payload,
            signer_input,
        })
    }

    /// Returns the Cloudflare Worker role handling this request.
    pub fn worker_role(&self) -> CloudflareWorkerRoleV1 {
        self.worker_role
    }

    /// Returns the original private signer wire message.
    pub fn message(&self) -> &WireMessageV1 {
        &self.message
    }

    /// Returns the decoded Router-to-signer payload.
    pub fn router_payload(&self) -> &RouterToSignerPayloadV1 {
        &self.router_payload
    }

    /// Returns the validated signer-input plaintext.
    pub fn signer_input(&self) -> &SignerInputPlaintextV1 {
        &self.signer_input
    }
}

/// Validates decrypted signer plaintext and returns the narrow production handler input.
pub fn validate_cloudflare_signer_private_request_plaintext_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: WireMessageV1,
    plaintext_bytes: &[u8],
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<CloudflareValidatedSignerPrivateRequestV1> {
    let signer_input = decode_and_validate_cloudflare_signer_input_plaintext_v1(
        worker_role,
        &message,
        plaintext_bytes,
        router_request_digest,
        root_share_metadata,
    )?;
    let router_payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    CloudflareValidatedSignerPrivateRequestV1::new(
        worker_role,
        message,
        router_payload,
        signer_input,
    )
}

/// Handles a validated private signer request through a narrow production handler.
pub fn handle_cloudflare_validated_signer_private_request_v1(
    handler: &impl CloudflareValidatedSignerInputHandlerV1,
    request: CloudflareValidatedSignerPrivateRequestV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    let response = handler.handle_validated_signer_input(&request)?;
    validate_cloudflare_signer_private_response_v1(request.message(), &response)?;
    Ok(response)
}

/// Handles a parsed private signer request through a strict proof-bundle handler.
pub fn handle_cloudflare_signer_recipient_proof_bundle_private_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    message: WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    validate_cloudflare_signer_private_request_v1(worker_role, &message)?;
    let response = handler.handle_signer_recipient_proof_bundle_wire_message(message.clone())?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        worker_role,
        &message,
        &response,
    )?;
    Ok(response)
}

/// Evaluates a validated private signer request through the real MPC PRF signer engine.
pub fn evaluate_cloudflare_validated_mpc_prf_batch_output_v1(
    host: &CloudflarePreloadedSignerHostV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
) -> RouterAbProtocolResult<MpcPrfThresholdSignerBatchOutputV1> {
    host.validate()?;
    request.router_payload().validate()?;
    request
        .signer_input()
        .validate()
        .map_err(map_derivation_to_protocol)?;
    let signer_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    if request.signer_input().recipient_role != signer_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "validated signer input role does not match Worker role",
        ));
    }
    let signing_root_share_wire =
        host.signing_root_share_wire(signer_role, &request.signer_input().root_share_epoch)?;
    let batch_input = build_mpc_prf_threshold_signer_batch_input_v1(
        request.router_payload(),
        request.signer_input(),
        signing_root_share_wire,
    )?;
    let mut proof_rng = CloudflareSignerProofGetrandomRngV1;
    match signer_role {
        Role::SignerA => SignerAEngine::new(host.clone())
            .evaluate_mpc_prf_output_batch(batch_input, &mut proof_rng),
        Role::SignerB => SignerBEngine::new(host.clone())
            .evaluate_mpc_prf_output_batch(batch_input, &mut proof_rng),
        _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
    }
    .map_err(map_derivation_to_protocol)
}

/// Builds a signed A/B proof-batch peer wire message from a real signer batch output.
pub fn build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
    signing_key_bytes: &[u8; 32],
    from: SignerIdentityV1,
    to: SignerIdentityV1,
    batch_output: MpcPrfThresholdSignerBatchOutputV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    from.validate()?;
    to.validate()?;
    let kind = match (from.role, to.role) {
        (Role::SignerA, Role::SignerB) => WireMessageKindV1::SignerAToSignerB,
        (Role::SignerB, Role::SignerA) => WireMessageKindV1::SignerBToSignerA,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "Cloudflare proof-batch peer message requires cross-signer A/B direction",
            ));
        }
    };
    let peer_payload =
        sign_ab_derivation_proof_batch_peer_payload_v1(signing_key_bytes, from, to, batch_output)?;
    WireMessageV1::new(
        kind,
        peer_payload.transcript_digest,
        CanonicalWireBytesV1::new(peer_payload.canonical_bytes())?,
    )
}

/// Verifies an authenticated A/B proof-batch peer message and decodes the proof batch.
pub fn decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(
    key_store: &impl SignerKeyStore,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<AbDerivationProofBatchPayloadV1> {
    let peer_payload = verify_cloudflare_signer_peer_message_authentication_v1(key_store, message)?;
    decode_and_validate_ab_derivation_proof_batch_peer_payload_v1(&peer_payload)
}

/// Combines verified Signer A/B proof-batch peer messages into recipient packages.
pub fn combine_cloudflare_mpc_prf_output_packages_from_peer_messages_v1(
    key_store: &impl SignerKeyStore,
    router_payload: &RouterToSignerPayloadV1,
    signer_a_peer_message: &WireMessageV1,
    signer_b_peer_message: &WireMessageV1,
    encryptor: &mut impl RecipientOutputEncryptorV1,
) -> RouterAbProtocolResult<MpcPrfOutputPackagesV1> {
    let proof_batch_a = decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(
        key_store,
        signer_a_peer_message,
    )?;
    let proof_batch_b = decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(
        key_store,
        signer_b_peer_message,
    )?;
    combine_mpc_prf_output_packages_from_ab_proof_batches_v1(
        router_payload,
        proof_batch_a,
        proof_batch_b,
        encryptor,
    )
}

/// Builds a canonical signer response from packaged MPC PRF output material.
pub fn cloudflare_signer_response_from_mpc_prf_packages_v1(
    lifecycle_id: &str,
    signer: SignerIdentityV1,
    packages: &MpcPrfOutputPackagesV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    signer_response_wire_message_from_mpc_prf_packages_v1(lifecycle_id, signer, packages)
}

/// Builds strict opaque client and relayer proof bundles from one signer proof batch.
pub fn cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1(
    router_payload: &RouterToSignerPayloadV1,
    proof_batch: AbDerivationProofBatchPayloadV1,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    router_payload.validate()?;
    proof_batch.validate()?;
    let signer_role = proof_batch.from.role;
    require_signer_role(signer_role)?;
    let client_bundle = recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch.clone(),
        OpenedShareKind::XClientBase,
        Role::Client,
        &router_payload.transcript_metadata().client_id,
        &router_payload
            .transcript_metadata()
            .client_ephemeral_public_key,
        encryptor,
    )?;
    let relayer_bundle = recipient_proof_bundle_wire_message_from_ab_proof_batch_v1(
        &router_payload.lifecycle().lifecycle_id,
        proof_batch,
        OpenedShareKind::XRelayerBase,
        Role::Relayer,
        &router_payload.signer_set().selected_relayer.relayer_id,
        &router_payload
            .signer_set()
            .selected_relayer
            .recipient_encryption_key,
        encryptor,
    )?;
    let response = CloudflareSignerRecipientProofBundleResponseV1::new(
        signer_role,
        client_bundle,
        relayer_bundle,
    )?;
    response.validate_for_router_payload(router_payload)?;
    Ok(response)
}

/// Handles a decrypt-validated signer request through the strict MPC PRF proof-bundle path.
pub fn handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
    host: &CloudflarePreloadedSignerHostV1,
    peer_signing_key_bytes: &[u8; 32],
    request: &CloudflareValidatedSignerPrivateRequestV1,
    encryptor: &mut impl RecipientProofBundleEncryptorV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    let local_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    let (local_signer, peer_signer, _) =
        cloudflare_signer_identities_for_request_v1(request, local_role)?;
    let local_output = evaluate_cloudflare_validated_mpc_prf_batch_output_v1(host, request)?;
    let local_peer_message = build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
        peer_signing_key_bytes,
        local_signer,
        peer_signer,
        local_output,
    )?;
    let local_proof_batch = decode_and_verify_cloudflare_ab_derivation_proof_batch_message_v1(
        host,
        &local_peer_message,
    )?;
    cloudflare_recipient_proof_bundle_response_from_ab_proof_batch_v1(
        request.router_payload(),
        local_proof_batch,
        encryptor,
    )
}

/// Handles a decrypt-validated signer request through the real MPC PRF peer protocol.
pub fn handle_cloudflare_validated_mpc_prf_signer_request_v1(
    host: &CloudflarePreloadedSignerHostV1,
    peer_signing_key_bytes: &[u8; 32],
    request: &CloudflareValidatedSignerPrivateRequestV1,
    encryptor: &mut impl RecipientOutputEncryptorV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    let local_role = cloudflare_worker_signer_role_v1(request.worker_role())?;
    let (local_signer, peer_signer, peer_worker_role) =
        cloudflare_signer_identities_for_request_v1(request, local_role)?;
    let local_output = evaluate_cloudflare_validated_mpc_prf_batch_output_v1(host, request)?;
    let local_peer_message = build_cloudflare_ab_derivation_proof_batch_peer_message_v1(
        peer_signing_key_bytes,
        local_signer.clone(),
        peer_signer,
        local_output,
    )?;
    let peer_response = host.send_peer_message(local_peer_message.clone())?;
    validate_cloudflare_signer_peer_response_v1(
        peer_worker_role,
        &local_peer_message,
        &peer_response,
    )?;
    let (signer_a_peer_message, signer_b_peer_message) = match local_role {
        Role::SignerA => (&local_peer_message, &peer_response),
        Role::SignerB => (&peer_response, &local_peer_message),
        _ => unreachable!("cloudflare_worker_signer_role_v1 returns only signer roles"),
    };
    let packages = combine_cloudflare_mpc_prf_output_packages_from_peer_messages_v1(
        host,
        request.router_payload(),
        signer_a_peer_message,
        signer_b_peer_message,
        encryptor,
    )?;
    cloudflare_signer_response_from_mpc_prf_packages_v1(
        request.signer_input().lifecycle_id.as_str(),
        local_signer,
        &packages,
    )
}

/// Validates that a role-local peer signing key can sign for a validated request.
pub fn validate_cloudflare_peer_signing_key_matches_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    request: &CloudflareValidatedSignerPrivateRequestV1,
) -> RouterAbProtocolResult<SignerIdentityV1> {
    peer_signing_key.validate_visible_to(worker_role)?;
    if request.worker_role() != worker_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "peer signing-key validation Worker role differs from the validated signer request role",
        ));
    }
    let local_role = cloudflare_worker_signer_role_v1(worker_role)?;
    let (local_signer, _, _) = cloudflare_signer_identities_for_request_v1(request, local_role)?;
    if peer_signing_key.role != local_signer.role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare peer signing key role differs from the local signer identity",
        ));
    }
    if peer_signing_key.key_epoch != local_signer.key_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare peer signing key epoch differs from the local signer identity epoch",
        ));
    }
    Ok(local_signer)
}

/// Decrypts a signer-envelope payload through Cloudflare WebCrypto.
#[cfg(feature = "workers-rs")]
pub async fn decrypt_cloudflare_signer_envelope_aead_payload_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeDecryptKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    let payload = decode_and_validate_cloudflare_signer_envelope_aead_payload_v1(
        worker_role,
        message,
        envelope_decrypt_key,
    )?;
    aad.validate()?;
    if aad.digest() != payload.aad_digest || aad.recipient.role != payload.recipient_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Cloudflare signer envelope AAD does not match parsed AEAD payload",
        ));
    }
    let secret = env
        .secret(&envelope_decrypt_key.binding_name)
        .map_err(|err| {
            worker_binding_error(
                worker_binding_error_code(&err, &envelope_decrypt_key.binding_name),
                &envelope_decrypt_key.binding_name,
                "secret",
                err,
            )
        })?;
    let mut secret_value = secret.to_string();
    let key_result = decode_cloudflare_signer_envelope_aead_key_v1(&secret_value);
    secret_value.zeroize();
    let mut key_bytes = key_result?;
    let plaintext = decrypt_cloudflare_aes_256_gcm_v1(&mut key_bytes, &payload, aad).await;
    key_bytes.zeroize();
    plaintext
}

/// Decrypts and validates signer-input plaintext through the production Cloudflare boundary.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_and_validate_cloudflare_signer_input_plaintext_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeDecryptKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<SignerInputPlaintextV1> {
    let plaintext_bytes = decrypt_cloudflare_signer_envelope_aead_payload_v1(
        env,
        worker_role,
        message,
        envelope_decrypt_key,
        aad,
    )
    .await?;
    decode_and_validate_cloudflare_signer_input_plaintext_v1(
        worker_role,
        message,
        &plaintext_bytes,
        router_request_digest,
        root_share_metadata,
    )
}

/// Decrypts and validates a private signer request for the narrow production handler.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_cloudflare_validated_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    message: WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeDecryptKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<CloudflareValidatedSignerPrivateRequestV1> {
    let plaintext_bytes = decrypt_cloudflare_signer_envelope_aead_payload_v1(
        env,
        worker_role,
        &message,
        envelope_decrypt_key,
        aad,
    )
    .await?;
    validate_cloudflare_signer_private_request_plaintext_v1(
        worker_role,
        message,
        &plaintext_bytes,
        router_request_digest,
        root_share_metadata,
    )
}

/// Decrypts, validates, and handles a private signer request.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_and_handle_cloudflare_validated_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    handler: &impl CloudflareValidatedSignerInputHandlerV1,
    message: WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeDecryptKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    let request = decrypt_cloudflare_validated_signer_private_request_v1(
        env,
        worker_role,
        message,
        envelope_decrypt_key,
        aad,
        router_request_digest,
        root_share_metadata,
    )
    .await?;
    handle_cloudflare_validated_signer_private_request_v1(handler, request)
}

/// Decrypts, validates, and handles an MPC PRF private signer request.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_and_handle_cloudflare_mpc_prf_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    message: WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeDecryptKeyBindingV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    let request = decrypt_cloudflare_validated_signer_private_request_v1(
        env,
        worker_role,
        message,
        envelope_decrypt_key,
        aad,
        router_request_digest,
        root_share_metadata,
    )
    .await?;
    validate_cloudflare_peer_signing_key_matches_request_v1(
        worker_role,
        peer_signing_key,
        &request,
    )?;
    let mut peer_signing_key_bytes =
        load_cloudflare_signer_peer_signing_key_bytes_v1(env, peer_signing_key)?;
    let mut encryptor = CloudflareHpkeRecipientOutputEncryptorV1::new();
    let response = handle_cloudflare_validated_mpc_prf_signer_request_v1(
        host,
        &peer_signing_key_bytes,
        &request,
        &mut encryptor,
    );
    peer_signing_key_bytes.zeroize();
    let response = response?;
    validate_cloudflare_signer_private_response_v1(request.message(), &response)?;
    Ok(response)
}

/// Decrypts, validates, and handles an MPC PRF private signer request with strict delivery.
#[cfg(feature = "workers-rs")]
#[allow(clippy::too_many_arguments)]
pub async fn decrypt_and_handle_cloudflare_mpc_prf_recipient_proof_bundle_signer_private_request_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    host: &CloudflarePreloadedSignerHostV1,
    message: WireMessageV1,
    envelope_decrypt_key: &CloudflareSignerEnvelopeDecryptKeyBindingV1,
    peer_signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    aad: &RoleEnvelopeAadV1,
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    let request = decrypt_cloudflare_validated_signer_private_request_v1(
        env,
        worker_role,
        message,
        envelope_decrypt_key,
        aad,
        router_request_digest,
        root_share_metadata,
    )
    .await?;
    validate_cloudflare_peer_signing_key_matches_request_v1(
        worker_role,
        peer_signing_key,
        &request,
    )?;
    let mut peer_signing_key_bytes =
        load_cloudflare_signer_peer_signing_key_bytes_v1(env, peer_signing_key)?;
    let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
    let response = handle_cloudflare_validated_mpc_prf_recipient_proof_bundle_signer_request_v1(
        host,
        &peer_signing_key_bytes,
        &request,
        &mut encryptor,
    );
    peer_signing_key_bytes.zeroize();
    let response = response?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        worker_role,
        request.message(),
        &response,
    )?;
    Ok(response)
}

/// Decodes and validates post-decryption signer-input plaintext for a signer Worker.
pub fn decode_and_validate_cloudflare_signer_input_plaintext_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
    plaintext_bytes: &[u8],
    router_request_digest: PublicDigest32,
    root_share_metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<SignerInputPlaintextV1> {
    validate_cloudflare_signer_private_request_v1(worker_role, message)?;
    root_share_metadata.validate()?;
    let expected_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if root_share_metadata.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Cloudflare signer plaintext metadata role does not match Worker role",
        ));
    }
    let payload = decode_router_to_signer_payload_v1(message.payload.as_bytes())?;
    let plaintext =
        decode_signer_input_plaintext_v1(plaintext_bytes).map_err(map_derivation_to_protocol)?;
    validate_signer_input_plaintext_binding_v1(
        &payload,
        &plaintext,
        router_request_digest,
        &root_share_metadata.root_share_epoch,
    )?;
    if plaintext.signer_set_id != root_share_metadata.signer_set_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare signer plaintext signer-set id does not match root metadata",
        ));
    }
    if plaintext.recipient_signer_id != root_share_metadata.signer_id
        || plaintext.recipient_key_epoch != root_share_metadata.signer_key_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare signer plaintext recipient identity does not match root metadata",
        ));
    }
    Ok(plaintext)
}

/// Validates a private signer response against the Router-dispatched request.
pub fn validate_cloudflare_signer_private_response_v1(
    request: &WireMessageV1,
    response: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    require_signer_response("private signer response", response)?;
    if response.transcript_digest != request.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "private signer response transcript digest does not match request",
        ));
    }
    Ok(())
}

/// Validates a strict private signer proof-bundle response against the Router-dispatched request.
pub fn validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
    worker_role: CloudflareWorkerRoleV1,
    request: &WireMessageV1,
    response: &CloudflareSignerRecipientProofBundleResponseV1,
) -> RouterAbProtocolResult<()> {
    validate_cloudflare_signer_private_request_v1(worker_role, request)?;
    let router_payload = decode_router_to_signer_payload_v1(request.payload.as_bytes())?;
    let expected_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if response.signer_role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "strict private signer proof-bundle response signer role does not match Worker role",
        ));
    }
    response.validate_for_router_payload(&router_payload)
}

/// Handles a strict Signer A relayer proof-bundle activation request.
pub fn handle_cloudflare_signer_a_recipient_proof_bundle_activation_request_v1(
    request: CloudflareRelayerRecipientProofBundleActivationRequestV1,
) -> RouterAbProtocolResult<CloudflareRelayerOutputActivationReceiptV1> {
    request.validate()?;
    CloudflareRelayerOutputActivationReceiptV1::new(
        request.router_payload.lifecycle().lifecycle_id.clone(),
        request
            .router_payload
            .signer_set()
            .selected_relayer
            .relayer_id
            .clone(),
        request.router_payload.transcript_digest(),
        true,
    )
}

/// Validates a direct A/B peer message for the target Worker role.
pub fn validate_cloudflare_signer_peer_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    let expected = expected_signer_peer_request_kind_v1(worker_role)?;
    if message.kind != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "{} peer endpoint expected {} message, received {}",
                worker_role.as_str(),
                expected.as_str(),
                message.kind.as_str()
            ),
        ));
    }
    if message.payload.as_bytes().is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "direct A/B peer request payload must be non-empty",
        ));
    }
    decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
    Ok(())
}

/// Validates a direct A/B peer response against the request and target Worker role.
pub fn validate_cloudflare_signer_peer_response_v1(
    worker_role: CloudflareWorkerRoleV1,
    request: &WireMessageV1,
    response: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    validate_cloudflare_signer_peer_request_v1(worker_role, request)?;
    let expected = expected_signer_peer_response_kind_v1(worker_role)?;
    if response.kind != expected {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "{} peer endpoint expected {} response, received {}",
                worker_role.as_str(),
                expected.as_str(),
                response.kind.as_str()
            ),
        ));
    }
    if response.transcript_digest != request.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "direct A/B peer response transcript digest does not match request",
        ));
    }
    if response.payload.as_bytes().is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "direct A/B peer response payload must be non-empty",
        ));
    }
    decode_and_validate_cloudflare_signer_peer_message_payload_v1(response)?;
    Ok(())
}

/// Decodes and validates the canonical A/B peer payload inside a wire message.
pub fn decode_and_validate_cloudflare_signer_peer_message_payload_v1(
    message: &WireMessageV1,
) -> RouterAbProtocolResult<AbPeerMessagePayloadV1> {
    let payload = decode_ab_peer_message_payload_v1(message.payload.as_bytes())?;
    if payload.transcript_digest != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "direct A/B peer payload transcript digest does not match wire message",
        ));
    }
    let (expected_from, expected_to) = match message.kind {
        WireMessageKindV1::SignerAToSignerB => (Role::SignerA, Role::SignerB),
        WireMessageKindV1::SignerBToSignerA => (Role::SignerB, Role::SignerA),
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalRoute,
                "wire message kind is not a direct A/B peer message",
            ));
        }
    };
    if payload.from.role != expected_from || payload.to.role != expected_to {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "direct A/B peer payload signer identities do not match wire direction",
        ));
    }
    Ok(payload)
}

/// Verifies an authenticated direct A/B peer message with trusted signer keys.
pub fn verify_cloudflare_signer_peer_message_authentication_v1(
    key_store: &impl SignerKeyStore,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<AbPeerMessagePayloadV1> {
    let payload = decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
    let verifying_key = key_store.signer_verifying_key(&payload.from)?;
    verify_ab_peer_message_ed25519_signature_v1(&payload, &verifying_key)?;
    Ok(payload)
}

/// Builds and signs one direct A/B peer wire message with the Worker-local Ed25519 key.
#[cfg(feature = "workers-rs")]
pub fn sign_cloudflare_signer_peer_wire_message_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    signing_key: &CloudflareSignerPeerSigningKeyBindingV1,
    from: SignerIdentityV1,
    to: SignerIdentityV1,
    transcript_digest: PublicDigest32,
    peer_body: CanonicalWireBytesV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    signing_key.validate_visible_to(worker_role)?;
    from.validate()?;
    to.validate()?;
    let local_role = cloudflare_worker_signer_role_v1(worker_role)?;
    if from.role != local_role || signing_key.role != from.role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare peer signing key must match the local sender role",
        ));
    }
    if signing_key.key_epoch != from.key_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "Cloudflare peer signing key epoch must match the sender identity epoch",
        ));
    }
    let kind = match (from.role, to.role) {
        (Role::SignerA, Role::SignerB) => WireMessageKindV1::SignerAToSignerB,
        (Role::SignerB, Role::SignerA) => WireMessageKindV1::SignerBToSignerA,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "Cloudflare peer signing requires a cross-signer A/B direction",
            ));
        }
    };
    let mut signing_key_bytes = load_cloudflare_signer_peer_signing_key_bytes_v1(env, signing_key)?;
    let authentication = sign_ab_peer_message_ed25519_authentication_v1(
        &signing_key_bytes,
        &from,
        &to,
        transcript_digest,
        &peer_body,
    );
    signing_key_bytes.zeroize();
    let payload =
        AbPeerMessagePayloadV1::new(from, to, transcript_digest, peer_body, authentication?)?;
    WireMessageV1::new(
        kind,
        transcript_digest,
        CanonicalWireBytesV1::new(payload.canonical_bytes())?,
    )
}

/// Handles the private Signer A service-binding route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signer_a_private_fetch_v1(
    handler: &impl CloudflareSignerWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_private_fetch_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1,
        handler,
        request,
    )
    .await
}

/// Handles the private Signer B service-binding route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signer_b_private_fetch_v1(
    handler: &impl CloudflareSignerWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_private_fetch_v1(
        CloudflareWorkerRoleV1::SignerB,
        CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1,
        handler,
        request,
    )
    .await
}

/// Handles the strict private Signer A service-binding route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signer_a_recipient_proof_bundle_private_fetch_v1(
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        CLOUDFLARE_SIGNER_A_PRIVATE_REQUEST_PATH_V1,
        handler,
        request,
    )
    .await
}

/// Handles the strict private Signer B service-binding route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signer_b_recipient_proof_bundle_private_fetch_v1(
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1(
        CloudflareWorkerRoleV1::SignerB,
        CLOUDFLARE_SIGNER_B_PRIVATE_REQUEST_PATH_V1,
        handler,
        request,
    )
    .await
}

/// Handles Signer A's strict relayer proof-bundle activation route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signer_a_recipient_proof_bundle_activation_fetch_v1(
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B relayer proof-bundle activation route requires POST",
            405,
        );
    }
    if request.path() != CLOUDFLARE_SIGNER_A_RELAYER_PROOF_BUNDLE_ACTIVATION_PATH_V1 {
        return worker::Response::error(
            format!(
                "Router A/B relayer proof-bundle activation must be served at {}",
                CLOUDFLARE_SIGNER_A_RELAYER_PROOF_BUNDLE_ACTIVATION_PATH_V1
            ),
            404,
        );
    }
    let parsed = match request
        .json::<CloudflareRelayerRecipientProofBundleActivationRequestV1>()
        .await
    {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B relayer proof-bundle activation JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_signer_a_recipient_proof_bundle_activation_request_v1(parsed) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles the direct Signer A peer coordination route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signer_a_peer_fetch_v1(
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_peer_fetch_v1(
        CloudflareWorkerRoleV1::SignerARelayer,
        CLOUDFLARE_SIGNER_A_PEER_REQUEST_PATH_V1,
        key_store,
        handler,
        request,
    )
    .await
}

/// Handles the direct Signer B peer coordination route.
#[cfg(feature = "workers-rs")]
pub async fn handle_cloudflare_signer_b_peer_fetch_v1(
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    request: worker::Request,
) -> worker::Result<worker::Response> {
    handle_cloudflare_signer_peer_fetch_v1(
        CloudflareWorkerRoleV1::SignerB,
        CLOUDFLARE_SIGNER_B_PEER_REQUEST_PATH_V1,
        key_store,
        handler,
        request,
    )
    .await
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_signer_recipient_proof_bundle_private_fetch_v1(
    worker_role: CloudflareWorkerRoleV1,
    expected_path: &str,
    handler: &impl CloudflareSignerRecipientProofBundleWireHandlerV1,
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error(
            "Router A/B strict signer private route requires POST",
            405,
        );
    }
    if request.path() != expected_path {
        return worker::Response::error(
            format!(
                "{} strict private signer request must be served at {}",
                worker_role.as_str(),
                expected_path
            ),
            404,
        );
    }
    let parsed = match request.json::<WireMessageV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B strict signer private request JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_signer_recipient_proof_bundle_private_request_v1(
        worker_role,
        handler,
        parsed,
    ) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_signer_private_fetch_v1(
    worker_role: CloudflareWorkerRoleV1,
    expected_path: &str,
    handler: &impl CloudflareSignerWireHandlerV1,
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B signer private route requires POST", 405);
    }
    if request.path() != expected_path {
        return worker::Response::error(
            format!(
                "{} private signer request must be served at {}",
                worker_role.as_str(),
                expected_path
            ),
            404,
        );
    }
    let parsed = match request.json::<WireMessageV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B signer private request JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_signer_private_request_v1(worker_role, handler, parsed) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

#[cfg(feature = "workers-rs")]
async fn handle_cloudflare_signer_peer_fetch_v1(
    worker_role: CloudflareWorkerRoleV1,
    expected_path: &str,
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    mut request: worker::Request,
) -> worker::Result<worker::Response> {
    if request.method() != worker::Method::Post {
        return worker::Response::error("Router A/B signer peer route requires POST", 405);
    }
    if request.path() != expected_path {
        return worker::Response::error(
            format!(
                "{} peer request must be served at {}",
                worker_role.as_str(),
                expected_path
            ),
            404,
        );
    }
    let parsed = match request.json::<WireMessageV1>().await {
        Ok(parsed) => parsed,
        Err(err) => {
            return worker::Response::error(
                format!("Router A/B signer peer request JSON parse failed: {err}"),
                400,
            );
        }
    };
    match handle_cloudflare_signer_peer_request_v1(worker_role, key_store, handler, parsed) {
        Ok(response) => worker::Response::from_json(&response),
        Err(err) => worker::Response::error(
            format!("{:?}: {}", err.code(), err.message()),
            cloudflare_router_error_status(err.code()),
        ),
    }
}

/// Handles one parsed private signer request through a platform-neutral handler.
pub fn handle_cloudflare_signer_private_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    handler: &impl CloudflareSignerWireHandlerV1,
    message: WireMessageV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    validate_cloudflare_signer_private_request_v1(worker_role, &message)?;
    let response = handler.handle_signer_wire_message(message.clone())?;
    validate_cloudflare_signer_private_response_v1(&message, &response)?;
    Ok(response)
}

/// Handles one parsed direct A/B peer request through a platform-neutral handler.
pub fn handle_cloudflare_signer_peer_request_v1(
    worker_role: CloudflareWorkerRoleV1,
    key_store: &impl SignerKeyStore,
    handler: &impl CloudflareSignerWireHandlerV1,
    message: WireMessageV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    validate_cloudflare_signer_peer_request_v1(worker_role, &message)?;
    verify_cloudflare_signer_peer_message_authentication_v1(key_store, &message)?;
    let response = handler.handle_signer_wire_message(message.clone())?;
    validate_cloudflare_signer_peer_response_v1(worker_role, &message, &response)?;
    verify_cloudflare_signer_peer_message_authentication_v1(key_store, &response)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_replay_reserve_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareReplayReserveResponseV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_replay_reserve_response_v1(call, response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_router_lifecycle_put_v1(
    env: &worker::Env,
    call: &CloudflareDurableObjectCallV1,
) -> RouterAbProtocolResult<CloudflareLifecyclePutReceiptV1> {
    let response = execute_cloudflare_durable_object_call_v1(env, call).await?;
    require_router_lifecycle_put_response_v1(call, response)
}

fn require_router_replay_reserve_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareReplayReserveResponseV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterReplayReserve { response } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router replay Durable Object returned wrong response branch",
        ));
    };
    Ok(response)
}

fn require_router_lifecycle_put_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareLifecyclePutReceiptV1> {
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RouterLifecyclePutPublicState { receipt } = response
    else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router lifecycle Durable Object returned wrong response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
fn require_relayer_output_activate_response_v1(
    call: &CloudflareDurableObjectCallV1,
    response: CloudflareDurableObjectResponseV1,
) -> RouterAbProtocolResult<CloudflareRelayerOutputActivationReceiptV1> {
    call.validate()?;
    response.validate_for_request(&call.request)?;
    let CloudflareDurableObjectResponseV1::RelayerOutputActivate { receipt } = response else {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "relayer-output Durable Object returned wrong response branch",
        ));
    };
    Ok(receipt)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_signer_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    peer.validate()?;
    let fetcher = env.service(&peer.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &peer.binding_name),
            &peer.binding_name,
            "service",
            err,
        )
    })?;
    let request_body = serde_json::to_string(message).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "{} service request serialization failed: {err}",
                peer.peer_role.as_str()
            ),
        )
    })?;
    let headers = worker::Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!(
                    "{} service request header construction failed: {err}",
                    peer.peer_role.as_str()
                ),
            )
        })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let request = worker::Request::new_with_init(cloudflare_signer_service_url_v1(peer)?, &init)
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!(
                    "{} service request construction failed: {err}",
                    peer.peer_role.as_str()
                ),
            )
        })?;
    let mut response = fetcher.fetch_request(request).await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{} service request failed: {err}", peer.peer_role.as_str()),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "{} service returned HTTP status {status}",
                peer.peer_role.as_str()
            ),
        ));
    }
    let response = response.json::<WireMessageV1>().await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "{} service response JSON parse failed: {err}",
                peer.peer_role.as_str()
            ),
        )
    })?;
    require_signer_response("signer service response", &response)?;
    if response.transcript_digest != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "{} service response transcript digest does not match request",
                peer.peer_role.as_str()
            ),
        ));
    }
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_signer_recipient_proof_bundle_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<CloudflareSignerRecipientProofBundleResponseV1> {
    peer.validate()?;
    validate_cloudflare_signer_private_request_v1(peer.peer_role, message)?;
    let fetcher = env.service(&peer.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &peer.binding_name),
            &peer.binding_name,
            "service",
            err,
        )
    })?;
    let request_body = serde_json::to_string(message).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "{} strict service request serialization failed: {err}",
                peer.peer_role.as_str()
            ),
        )
    })?;
    let headers = worker::Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!(
                    "{} strict service request header construction failed: {err}",
                    peer.peer_role.as_str()
                ),
            )
        })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let request = worker::Request::new_with_init(cloudflare_signer_service_url_v1(peer)?, &init)
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!(
                    "{} strict service request construction failed: {err}",
                    peer.peer_role.as_str()
                ),
            )
        })?;
    let mut response = fetcher.fetch_request(request).await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "{} strict service request failed: {err}",
                peer.peer_role.as_str()
            ),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "{} strict service returned HTTP status {status}",
                peer.peer_role.as_str()
            ),
        ));
    }
    let response = response
        .json::<CloudflareSignerRecipientProofBundleResponseV1>()
        .await
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!(
                    "{} strict service response JSON parse failed: {err}",
                    peer.peer_role.as_str()
                ),
            )
        })?;
    validate_cloudflare_signer_recipient_proof_bundle_private_response_v1(
        peer.peer_role,
        message,
        &response,
    )?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_signer_a_recipient_proof_bundle_activation_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    request: &CloudflareRelayerRecipientProofBundleActivationRequestV1,
) -> RouterAbProtocolResult<CloudflareRelayerOutputActivationReceiptV1> {
    peer.validate()?;
    if peer.peer_role != CloudflareWorkerRoleV1::SignerARelayer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "strict relayer proof-bundle activation must target Signer A",
        ));
    }
    request.validate()?;
    let fetcher = env.service(&peer.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &peer.binding_name),
            &peer.binding_name,
            "service",
            err,
        )
    })?;
    let request_body = serde_json::to_string(request).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("Signer A relayer proof-bundle activation serialization failed: {err}"),
        )
    })?;
    let headers = worker::Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!(
                    "Signer A relayer proof-bundle activation header construction failed: {err}"
                ),
            )
        })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let request = worker::Request::new_with_init(
        cloudflare_signer_a_recipient_proof_bundle_activation_service_url_v1(peer)?,
        &init,
    )
    .map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Signer A relayer proof-bundle activation request construction failed: {err}"),
        )
    })?;
    let mut response = fetcher.fetch_request(request).await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Signer A relayer proof-bundle activation request failed: {err}"),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Signer A relayer proof-bundle activation returned HTTP status {status}"),
        ));
    }
    let receipt = response
        .json::<CloudflareRelayerOutputActivationReceiptV1>()
        .await
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("Signer A relayer proof-bundle activation JSON parse failed: {err}"),
            )
        })?;
    receipt.validate()?;
    Ok(receipt)
}

/// Sends one direct A/B peer message over a Cloudflare Service Binding.
#[cfg(feature = "workers-rs")]
pub async fn execute_cloudflare_signer_peer_service_call_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    message: &WireMessageV1,
) -> RouterAbProtocolResult<WireMessageV1> {
    peer.validate()?;
    validate_cloudflare_signer_peer_request_v1(peer.peer_role, message)?;
    let fetcher = env.service(&peer.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &peer.binding_name),
            &peer.binding_name,
            "service",
            err,
        )
    })?;
    let request_body = serde_json::to_string(message).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "{} peer request serialization failed: {err}",
                peer.peer_role.as_str()
            ),
        )
    })?;
    let headers = worker::Headers::new();
    headers
        .set("content-type", "application/json")
        .map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!(
                    "{} peer request header construction failed: {err}",
                    peer.peer_role.as_str()
                ),
            )
        })?;
    let mut init = worker::RequestInit::new();
    init.with_method(worker::Method::Post)
        .with_headers(headers)
        .with_body(Some(worker::wasm_bindgen::JsValue::from_str(&request_body)));
    let request =
        worker::Request::new_with_init(cloudflare_signer_peer_service_url_v1(peer)?, &init)
            .map_err(|err| {
                RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!(
                        "{} peer request construction failed: {err}",
                        peer.peer_role.as_str()
                    ),
                )
            })?;
    let mut response = fetcher.fetch_request(request).await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{} peer request failed: {err}", peer.peer_role.as_str()),
        )
    })?;
    let status = response.status_code();
    if !(200..=299).contains(&status) {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!(
                "{} peer service returned HTTP status {status}",
                peer.peer_role.as_str()
            ),
        ));
    }
    let response = response.json::<WireMessageV1>().await.map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!(
                "{} peer response JSON parse failed: {err}",
                peer.peer_role.as_str()
            ),
        )
    })?;
    validate_cloudflare_signer_peer_response_v1(peer.peer_role, message, &response)?;
    Ok(response)
}

#[cfg(feature = "workers-rs")]
async fn execute_cloudflare_signer_peer_requests_v1(
    env: &worker::Env,
    peer: &CloudflarePeerBindingV1,
    requests: &[WireMessageV1],
) -> RouterAbProtocolResult<Vec<WireMessageV1>> {
    let mut responses = Vec::with_capacity(requests.len());
    for request in requests {
        responses.push(execute_cloudflare_signer_peer_service_call_v1(env, peer, request).await?);
    }
    Ok(responses)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signer_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerARelayer => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b"
        )),
        CloudflareWorkerRoleV1::Router => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Router public handler cannot forward signer work to a Router peer",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signer_peer_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerARelayer => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/peer"
        )),
        CloudflareWorkerRoleV1::SignerB => Ok(concat!(
            "https://router-ab-signer-b.internal",
            "/router-ab/v1/signer-b/peer"
        )),
        CloudflareWorkerRoleV1::Router => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "direct A/B peer handler cannot send peer work to a Router peer",
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_signer_a_recipient_proof_bundle_activation_service_url_v1(
    peer: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<&'static str> {
    match peer.peer_role {
        CloudflareWorkerRoleV1::SignerARelayer => Ok(concat!(
            "https://router-ab-signer-a.internal",
            "/router-ab/v1/signer-a/relayer/proof-bundle-activation"
        )),
        CloudflareWorkerRoleV1::Router | CloudflareWorkerRoleV1::SignerB => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "strict relayer proof-bundle activation can target only Signer A",
            ))
        }
    }
}

/// Parses role-specific Worker bindings from an Env reader.
pub fn parse_cloudflare_worker_bindings_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareWorkerBindingsV1> {
    match worker_role {
        CloudflareWorkerRoleV1::Router => {
            CloudflareWorkerBindingsV1::router(parse_cloudflare_router_bindings_v1(env)?)
        }
        CloudflareWorkerRoleV1::SignerARelayer => CloudflareWorkerBindingsV1::signer_a_relayer(
            parse_cloudflare_signer_a_relayer_bindings_v1(env)?,
        ),
        CloudflareWorkerRoleV1::SignerB => {
            CloudflareWorkerBindingsV1::signer_b(parse_cloudflare_signer_b_bindings_v1(env)?)
        }
    }
}

/// Parses Router Worker bindings from an Env reader.
pub fn parse_cloudflare_router_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareRouterBindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::Router,
        env,
        ROUTER_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareRouterBindingsV1::new(
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::RouterReplay,
            ROUTER_REPLAY_DO_BINDING_ENV,
            ROUTER_REPLAY_DO_OBJECT_ENV,
            ROUTER_REPLAY_DO_KEY_PREFIX_ENV,
        )?,
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::RouterLifecycle,
            ROUTER_LIFECYCLE_DO_BINDING_ENV,
            ROUTER_LIFECYCLE_DO_OBJECT_ENV,
            ROUTER_LIFECYCLE_DO_KEY_PREFIX_ENV,
        )?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SignerARelayer,
            SIGNER_A_PEER_BINDING_ENV,
        )?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SignerB,
            SIGNER_B_PEER_BINDING_ENV,
        )?,
    )
}

/// Parses Signer A/Relayer Worker bindings from an Env reader.
pub fn parse_cloudflare_signer_a_relayer_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerARelayerBindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::SignerARelayer,
        env,
        SIGNER_A_RELAYER_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareSignerARelayerBindingsV1::new(
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerA,
            },
            SIGNER_A_ROOT_SHARE_DO_BINDING_ENV,
            SIGNER_A_ROOT_SHARE_DO_OBJECT_ENV,
            SIGNER_A_ROOT_SHARE_DO_KEY_PREFIX_ENV,
        )?,
        read_root_share_wire_secret_binding(
            env,
            Role::SignerA,
            SIGNER_A_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        )?,
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::signer_a_relayer_output(),
            SIGNER_A_RELAYER_OUTPUT_DO_BINDING_ENV,
            SIGNER_A_RELAYER_OUTPUT_DO_OBJECT_ENV,
            SIGNER_A_RELAYER_OUTPUT_DO_KEY_PREFIX_ENV,
        )?,
        read_signer_envelope_decrypt_key_binding(
            env,
            Role::SignerA,
            SIGNER_A_ENVELOPE_AEAD_KEY_BINDING_ENV,
            SIGNER_A_ENVELOPE_AEAD_KEY_EPOCH_ENV,
        )?,
        read_signer_peer_signing_key_binding(
            env,
            Role::SignerA,
            SIGNER_A_PEER_SIGNING_KEY_BINDING_ENV,
            SIGNER_A_PEER_SIGNING_KEY_EPOCH_ENV,
        )?,
        read_signer_peer_verifying_key_set(env)?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SignerB,
            SIGNER_B_PEER_BINDING_ENV,
        )?,
    )
}

/// Parses Signer B Worker bindings from an Env reader.
pub fn parse_cloudflare_signer_b_bindings_v1(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerBBindingsV1> {
    reject_forbidden_env_keys(
        CloudflareWorkerRoleV1::SignerB,
        env,
        SIGNER_B_FORBIDDEN_ENV_KEYS,
    )?;
    CloudflareSignerBBindingsV1::new(
        read_durable_object_binding(
            env,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: Role::SignerB,
            },
            SIGNER_B_ROOT_SHARE_DO_BINDING_ENV,
            SIGNER_B_ROOT_SHARE_DO_OBJECT_ENV,
            SIGNER_B_ROOT_SHARE_DO_KEY_PREFIX_ENV,
        )?,
        read_root_share_wire_secret_binding(
            env,
            Role::SignerB,
            SIGNER_B_ROOT_SHARE_WIRE_SECRET_BINDING_ENV,
        )?,
        read_signer_envelope_decrypt_key_binding(
            env,
            Role::SignerB,
            SIGNER_B_ENVELOPE_AEAD_KEY_BINDING_ENV,
            SIGNER_B_ENVELOPE_AEAD_KEY_EPOCH_ENV,
        )?,
        read_signer_peer_signing_key_binding(
            env,
            Role::SignerB,
            SIGNER_B_PEER_SIGNING_KEY_BINDING_ENV,
            SIGNER_B_PEER_SIGNING_KEY_EPOCH_ENV,
        )?,
        read_signer_peer_verifying_key_set(env)?,
        read_peer_binding(
            env,
            CloudflareWorkerRoleV1::SignerARelayer,
            SIGNER_A_PEER_BINDING_ENV,
        )?,
    )
}

/// `workers-rs` Env reader for Cloudflare Worker startup parsing.
#[cfg(feature = "workers-rs")]
#[derive(Debug, Clone, Copy)]
pub struct CloudflareWorkerEnvReaderV1<'a> {
    env: &'a worker::Env,
}

#[cfg(feature = "workers-rs")]
impl<'a> CloudflareWorkerEnvReaderV1<'a> {
    /// Creates a reader over a real Cloudflare Worker Env.
    pub fn new(env: &'a worker::Env) -> Self {
        Self { env }
    }
}

#[cfg(feature = "workers-rs")]
impl CloudflareEnvReaderV1 for CloudflareWorkerEnvReaderV1<'_> {
    fn get_text(&self, key: &str) -> RouterAbProtocolResult<Option<String>> {
        match self.env.var(key) {
            Ok(value) => Ok(Some(value.to_string())),
            Err(err) if worker_binding_is_missing(&err, key) => Ok(None),
            Err(err) => Err(worker_binding_error(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                key,
                "text Env",
                err,
            )),
        }
    }
}

/// Parses Worker bindings from a real Cloudflare Env and checks runtime bindings exist.
#[cfg(feature = "workers-rs")]
pub fn parse_cloudflare_worker_bindings_from_worker_env_v1(
    worker_role: CloudflareWorkerRoleV1,
    env: &worker::Env,
) -> RouterAbProtocolResult<CloudflareWorkerBindingsV1> {
    let reader = CloudflareWorkerEnvReaderV1::new(env);
    let bindings = parse_cloudflare_worker_bindings_v1(worker_role, &reader)?;
    validate_cloudflare_worker_env_bindings_v1(env, &bindings)?;
    Ok(bindings)
}

/// Checks the real Worker Env has every Durable Object and service binding required by descriptors.
#[cfg(feature = "workers-rs")]
pub fn validate_cloudflare_worker_env_bindings_v1(
    env: &worker::Env,
    bindings: &CloudflareWorkerBindingsV1,
) -> RouterAbProtocolResult<()> {
    match bindings {
        CloudflareWorkerBindingsV1::Router { bindings } => {
            require_worker_durable_object(env, &bindings.replay)?;
            require_worker_durable_object(env, &bindings.lifecycle)?;
            require_worker_service(env, &bindings.signer_a)?;
            require_worker_service(env, &bindings.signer_b)
        }
        CloudflareWorkerBindingsV1::SignerARelayer { bindings } => {
            require_worker_durable_object(env, &bindings.root_share)?;
            require_worker_root_share_wire_secret(env, &bindings.root_share_wire_secret)?;
            require_worker_durable_object(env, &bindings.relayer_output)?;
            require_worker_secret(env, &bindings.envelope_decrypt_key)?;
            require_worker_peer_signing_secret(env, &bindings.peer_signing_key)?;
            require_worker_service(env, &bindings.signer_b)
        }
        CloudflareWorkerBindingsV1::SignerB { bindings } => {
            require_worker_durable_object(env, &bindings.root_share)?;
            require_worker_root_share_wire_secret(env, &bindings.root_share_wire_secret)?;
            require_worker_secret(env, &bindings.envelope_decrypt_key)?;
            require_worker_peer_signing_secret(env, &bindings.peer_signing_key)?;
            require_worker_service(env, &bindings.signer_a_relayer)
        }
    }
}

/// Expected signer root-share startup check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudflareSignerStartupCheckV1 {
    /// Worker role being checked.
    pub worker_role: CloudflareWorkerRoleV1,
    /// Signer role expected in storage.
    pub signer_role: Role,
    /// Signer set expected in storage.
    pub signer_set_id: String,
    /// Root-share epoch expected in storage.
    pub root_share_epoch: RootShareEpoch,
    /// Root-share Durable Object binding.
    pub root_share_binding: CloudflareDurableObjectBindingV1,
}

impl CloudflareSignerStartupCheckV1 {
    /// Creates a fail-closed Signer A startup check descriptor.
    pub fn signer_a(
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        root_share_binding: CloudflareDurableObjectBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        Self::new(
            CloudflareWorkerRoleV1::SignerARelayer,
            Role::SignerA,
            signer_set_id,
            root_share_epoch,
            root_share_binding,
        )
    }

    /// Creates a fail-closed Signer B startup check descriptor.
    pub fn signer_b(
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        root_share_binding: CloudflareDurableObjectBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        Self::new(
            CloudflareWorkerRoleV1::SignerB,
            Role::SignerB,
            signer_set_id,
            root_share_epoch,
            root_share_binding,
        )
    }

    fn new(
        worker_role: CloudflareWorkerRoleV1,
        signer_role: Role,
        signer_set_id: impl Into<String>,
        root_share_epoch: RootShareEpoch,
        root_share_binding: CloudflareDurableObjectBindingV1,
    ) -> RouterAbProtocolResult<Self> {
        let check = Self {
            worker_role,
            signer_role,
            signer_set_id: signer_set_id.into(),
            root_share_epoch,
            root_share_binding,
        };
        check.validate()?;
        Ok(check)
    }

    /// Validates the startup check descriptor.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_signer_role(self.signer_role)?;
        require_scope(
            &self.root_share_binding,
            CloudflareDurableObjectScopeV1::SignerRootShare {
                role: self.signer_role,
            },
            self.worker_role,
        )
    }
}

fn require_scope(
    binding: &CloudflareDurableObjectBindingV1,
    expected_scope: CloudflareDurableObjectScopeV1,
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<()> {
    binding.validate_visible_to(worker_role)?;
    if binding.scope == expected_scope {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "{} Worker expected {:?} Durable Object scope, received {:?}",
            worker_role.as_str(),
            expected_scope,
            binding.scope
        ),
    ))
}

fn require_peer_role(
    peer: &CloudflarePeerBindingV1,
    expected: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<()> {
    peer.validate()?;
    if peer.peer_role == expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "Cloudflare peer binding expected {} role, received {}",
            expected.as_str(),
            peer.peer_role.as_str()
        ),
    ))
}

fn require_signer_response(field: &str, message: &WireMessageV1) -> RouterAbProtocolResult<()> {
    if message.kind == WireMessageKindV1::SignerResponse {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!("{field} must be a signer_response wire message"),
    ))
}

fn decode_cloudflare_recipient_proof_bundle_wire_v1(
    field: &str,
    message: &WireMessageV1,
    expected_signer_role: Role,
    expected_recipient_role: Role,
    expected_opened_share_kind: OpenedShareKind,
) -> RouterAbProtocolResult<RecipientProofBundleCiphertextV1> {
    require_signer_role(expected_signer_role)?;
    if message.kind != WireMessageKindV1::RecipientProofBundle {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} must be a recipient_proof_bundle wire message"),
        ));
    }
    let envelope = decode_recipient_proof_bundle_ciphertext_v1(message.payload.as_bytes())?;
    if envelope.transcript_digest != message.transcript_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} transcript digest does not match ciphertext envelope"),
        ));
    }
    if envelope.signer.role != expected_signer_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!("{field} proof-bundle signer role is not expected"),
        ));
    }
    if envelope.recipient_role != expected_recipient_role
        || envelope.opened_share_kind != expected_opened_share_kind
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} proof-bundle recipient binding is invalid"),
        ));
    }
    Ok(envelope)
}

fn expected_cloudflare_signer_identity_for_role_v1(
    router_payload: &RouterToSignerPayloadV1,
    role: Role,
) -> RouterAbProtocolResult<&SignerIdentityV1> {
    require_signer_role(role)?;
    match role {
        Role::SignerA => Ok(&router_payload.signer_set().signer_a),
        Role::SignerB => Ok(&router_payload.signer_set().signer_b),
        _ => unreachable!("require_signer_role accepted only signer roles"),
    }
}

fn validate_cloudflare_recipient_proof_bundle_envelope_for_router_payload_v1(
    field: &str,
    envelope: &RecipientProofBundleCiphertextV1,
    router_payload: &RouterToSignerPayloadV1,
    expected_signer: &SignerIdentityV1,
) -> RouterAbProtocolResult<()> {
    envelope.validate()?;
    router_payload.validate()?;
    expected_signer.validate()?;
    if envelope.signer != *expected_signer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            format!("{field} signer identity does not match signer set"),
        ));
    }
    if envelope.transcript_digest != router_payload.transcript_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("{field} transcript digest does not match Router payload"),
        ));
    }
    match (envelope.recipient_role, envelope.opened_share_kind) {
        (Role::Client, OpenedShareKind::XClientBase) => {
            let metadata = router_payload.transcript_metadata();
            if envelope.recipient_identity != metadata.client_id
                || envelope.recipient_encryption_key != metadata.client_ephemeral_public_key
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{field} client recipient binding does not match Router payload"),
                ));
            }
        }
        (Role::Relayer, OpenedShareKind::XRelayerBase) => {
            let relayer = &router_payload.signer_set().selected_relayer;
            if envelope.recipient_identity != relayer.relayer_id
                || envelope.recipient_encryption_key != relayer.recipient_encryption_key
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    format!("{field} relayer recipient binding does not match Router payload"),
                ));
            }
        }
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                format!("{field} recipient proof-bundle binding is invalid"),
            ));
        }
    }
    Ok(())
}

fn require_preloaded_peer_response_v1(message: &WireMessageV1) -> RouterAbProtocolResult<()> {
    match message.kind {
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA
            if !message.payload.as_bytes().is_empty() =>
        {
            decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
            Ok(())
        }
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "preloaded A/B peer response payload must be non-empty",
            ))
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "preloaded signer host peer response must be an A/B peer message, received {}",
                message.kind.as_str()
            ),
        )),
    }
}

fn require_preloaded_peer_request_v1(message: &WireMessageV1) -> RouterAbProtocolResult<()> {
    match message.kind {
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA
            if !message.payload.as_bytes().is_empty() =>
        {
            decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
            Ok(())
        }
        WireMessageKindV1::SignerAToSignerB | WireMessageKindV1::SignerBToSignerA => {
            Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "preloaded A/B peer request payload must be non-empty",
            ))
        }
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalRoute,
            format!(
                "preloaded signer host peer request must be an A/B peer message, received {}",
                message.kind.as_str()
            ),
        )),
    }
}

fn validate_signer_verifying_keys_v1(
    keys: &[AbPeerMessageVerifyingKeyV1],
) -> RouterAbProtocolResult<()> {
    for (index, key) in keys.iter().enumerate() {
        key.validate()?;
        for prior in &keys[..index] {
            if prior.signer == key.signer {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidSignerIdentity,
                    "duplicate A/B peer signer verifying key",
                ));
            }
        }
    }
    Ok(())
}

fn verify_peer_message_authentication_with_keys_v1(
    keys: &[AbPeerMessageVerifyingKeyV1],
    message: &WireMessageV1,
) -> RouterAbProtocolResult<()> {
    let payload = decode_and_validate_cloudflare_signer_peer_message_payload_v1(message)?;
    let verifying_key = keys
        .iter()
        .find(|key| key.signer == payload.from)
        .ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MissingLocalBinding,
                "preloaded A/B peer message sender has no trusted verifying key",
            )
        })?;
    verify_ab_peer_message_ed25519_signature_v1(&payload, verifying_key)
}

fn expected_signer_private_request_kind_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<WireMessageKindV1> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerARelayer => Ok(WireMessageKindV1::RouterToSignerA),
        CloudflareWorkerRoleV1::SignerB => Ok(WireMessageKindV1::RouterToSignerB),
        CloudflareWorkerRoleV1::Router => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Router Worker has no private signer request kind",
        )),
    }
}

fn cloudflare_worker_signer_role_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<Role> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerARelayer => Ok(Role::SignerA),
        CloudflareWorkerRoleV1::SignerB => Ok(Role::SignerB),
        CloudflareWorkerRoleV1::Router => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Router Worker has no signer plaintext role",
        )),
    }
}

fn cloudflare_signer_identities_for_request_v1(
    request: &CloudflareValidatedSignerPrivateRequestV1,
    local_role: Role,
) -> RouterAbProtocolResult<(SignerIdentityV1, SignerIdentityV1, CloudflareWorkerRoleV1)> {
    require_signer_role(local_role)?;
    let assignment = request
        .router_payload()
        .require_recipient_role(local_role)?;
    let signer_set = request.router_payload().signer_set();
    let (expected_local, peer_signer, peer_worker_role) = match local_role {
        Role::SignerA => (
            signer_set.signer_a.clone(),
            signer_set.signer_b.clone(),
            CloudflareWorkerRoleV1::SignerB,
        ),
        Role::SignerB => (
            signer_set.signer_b.clone(),
            signer_set.signer_a.clone(),
            CloudflareWorkerRoleV1::SignerARelayer,
        ),
        _ => unreachable!("require_signer_role accepted only signer roles"),
    };
    if assignment.signer != expected_local {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "validated signer request assignment does not match signer set role",
        ));
    }
    Ok((assignment.signer.clone(), peer_signer, peer_worker_role))
}

fn expected_signer_peer_request_kind_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<WireMessageKindV1> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerARelayer => Ok(WireMessageKindV1::SignerBToSignerA),
        CloudflareWorkerRoleV1::SignerB => Ok(WireMessageKindV1::SignerAToSignerB),
        CloudflareWorkerRoleV1::Router => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Router Worker has no direct A/B peer request kind",
        )),
    }
}

fn expected_signer_peer_response_kind_v1(
    worker_role: CloudflareWorkerRoleV1,
) -> RouterAbProtocolResult<WireMessageKindV1> {
    match worker_role {
        CloudflareWorkerRoleV1::SignerARelayer => Ok(WireMessageKindV1::SignerAToSignerB),
        CloudflareWorkerRoleV1::SignerB => Ok(WireMessageKindV1::SignerBToSignerA),
        CloudflareWorkerRoleV1::Router => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "Router Worker has no direct A/B peer response kind",
        )),
    }
}

fn read_durable_object_binding(
    env: &impl CloudflareEnvReaderV1,
    scope: CloudflareDurableObjectScopeV1,
    binding_name_key: &str,
    object_name_key: &str,
    key_prefix_key: &str,
) -> RouterAbProtocolResult<CloudflareDurableObjectBindingV1> {
    CloudflareDurableObjectBindingV1::new(
        scope,
        read_required_env_text(env, binding_name_key)?,
        read_required_env_text(env, object_name_key)?,
        read_required_env_text(env, key_prefix_key)?,
    )
}

fn read_peer_binding(
    env: &impl CloudflareEnvReaderV1,
    peer_role: CloudflareWorkerRoleV1,
    binding_name_key: &str,
) -> RouterAbProtocolResult<CloudflarePeerBindingV1> {
    CloudflarePeerBindingV1::new(peer_role, read_required_env_text(env, binding_name_key)?)
}

fn read_root_share_wire_secret_binding(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    binding_name_key: &str,
) -> RouterAbProtocolResult<CloudflareRootShareWireSecretBindingV1> {
    CloudflareRootShareWireSecretBindingV1::new(
        role,
        read_required_env_text(env, binding_name_key)?,
    )
}

fn read_signer_envelope_decrypt_key_binding(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    binding_name_key: &str,
    key_epoch_key: &str,
) -> RouterAbProtocolResult<CloudflareSignerEnvelopeDecryptKeyBindingV1> {
    CloudflareSignerEnvelopeDecryptKeyBindingV1::new(
        role,
        read_required_env_text(env, binding_name_key)?,
        read_required_env_text(env, key_epoch_key)?,
    )
}

fn read_signer_peer_signing_key_binding(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    binding_name_key: &str,
    key_epoch_key: &str,
) -> RouterAbProtocolResult<CloudflareSignerPeerSigningKeyBindingV1> {
    CloudflareSignerPeerSigningKeyBindingV1::new(
        role,
        read_required_env_text(env, binding_name_key)?,
        read_required_env_text(env, key_epoch_key)?,
    )
}

fn read_signer_peer_verifying_key_set(
    env: &impl CloudflareEnvReaderV1,
) -> RouterAbProtocolResult<CloudflareSignerPeerVerifyingKeySetV1> {
    CloudflareSignerPeerVerifyingKeySetV1::new(
        read_signer_peer_verifying_key_bytes(
            env,
            Role::SignerA,
            SIGNER_A_PEER_VERIFYING_KEY_HEX_ENV,
        )?,
        read_signer_peer_verifying_key_bytes(
            env,
            Role::SignerB,
            SIGNER_B_PEER_VERIFYING_KEY_HEX_ENV,
        )?,
    )
}

fn read_signer_peer_verifying_key_bytes(
    env: &impl CloudflareEnvReaderV1,
    role: Role,
    key: &str,
) -> RouterAbProtocolResult<CloudflareSignerPeerVerifyingKeyBytesV1> {
    CloudflareSignerPeerVerifyingKeyBytesV1::new(
        role,
        decode_cloudflare_peer_verifying_key_hex_v1(&read_required_env_text(env, key)?)?,
    )
}

fn read_required_env_text(
    env: &impl CloudflareEnvReaderV1,
    key: &str,
) -> RouterAbProtocolResult<String> {
    match env.get_text(key)? {
        Some(value) => {
            let value = value.trim().to_owned();
            require_non_empty(key, &value)?;
            Ok(value)
        }
        None => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MissingLocalBinding,
            format!("Cloudflare Env is missing required key {key}"),
        )),
    }
}

fn reject_forbidden_env_keys(
    worker_role: CloudflareWorkerRoleV1,
    env: &impl CloudflareEnvReaderV1,
    forbidden_keys: &[&str],
) -> RouterAbProtocolResult<()> {
    for key in forbidden_keys {
        if env.get_text(key)?.is_some() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ForbiddenLocalBinding,
                format!(
                    "{} Worker cannot receive Cloudflare Env key {key}",
                    worker_role.as_str()
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(feature = "workers-rs")]
fn require_worker_durable_object(
    env: &worker::Env,
    binding: &CloudflareDurableObjectBindingV1,
) -> RouterAbProtocolResult<()> {
    match env.durable_object(&binding.binding_name) {
        Ok(_) => Ok(()),
        Err(err) => Err(worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "Durable Object",
            err,
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn require_worker_service(
    env: &worker::Env,
    binding: &CloudflarePeerBindingV1,
) -> RouterAbProtocolResult<()> {
    match env.service(&binding.binding_name) {
        Ok(_) => Ok(()),
        Err(err) => Err(worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "service",
            err,
        )),
    }
}

#[cfg(feature = "workers-rs")]
fn require_worker_secret(
    env: &worker::Env,
    binding: &CloudflareSignerEnvelopeDecryptKeyBindingV1,
) -> RouterAbProtocolResult<()> {
    require_worker_secret_binding_name(env, &binding.binding_name)
}

#[cfg(feature = "workers-rs")]
fn require_worker_root_share_wire_secret(
    env: &worker::Env,
    binding: &CloudflareRootShareWireSecretBindingV1,
) -> RouterAbProtocolResult<()> {
    require_worker_secret_binding_name(env, &binding.binding_name)
}

#[cfg(feature = "workers-rs")]
fn require_worker_peer_signing_secret(
    env: &worker::Env,
    binding: &CloudflareSignerPeerSigningKeyBindingV1,
) -> RouterAbProtocolResult<()> {
    require_worker_secret_binding_name(env, &binding.binding_name)
}

#[cfg(feature = "workers-rs")]
fn require_worker_secret_binding_name(
    env: &worker::Env,
    binding_name: &str,
) -> RouterAbProtocolResult<()> {
    match env.secret(binding_name) {
        Ok(_) => Ok(()),
        Err(err) => Err(worker_binding_error(
            worker_binding_error_code(&err, binding_name),
            binding_name,
            "secret",
            err,
        )),
    }
}

/// Loads a role-local root-share wire from a Cloudflare Secret binding.
#[cfg(feature = "workers-rs")]
pub fn load_cloudflare_root_share_wire_secret_v1(
    env: &worker::Env,
    worker_role: CloudflareWorkerRoleV1,
    binding: &CloudflareRootShareWireSecretBindingV1,
    metadata: &CloudflareRootShareStartupMetadataV1,
) -> RouterAbProtocolResult<CloudflarePreloadedRootShareWireV1> {
    binding.validate_visible_to(worker_role)?;
    let secret = env.secret(&binding.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "secret",
            err,
        )
    })?;
    let mut secret_value = secret.to_string();
    let record = decode_and_validate_cloudflare_root_share_wire_secret_v1(
        worker_role,
        binding,
        metadata,
        &secret_value,
    );
    secret_value.zeroize();
    record
}

#[cfg(feature = "workers-rs")]
fn decode_cloudflare_signer_envelope_aead_key_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<Vec<u8>> {
    let mut key_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret_value.trim().as_bytes())
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Cloudflare signer envelope AEAD key secret must be unpadded base64url",
            ));
        }
    };
    if key_bytes.len() != 32 {
        key_bytes.zeroize();
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare signer envelope AEAD key secret must decode to 32 bytes",
        ));
    }
    Ok(key_bytes)
}

#[cfg(feature = "workers-rs")]
fn load_cloudflare_signer_peer_signing_key_bytes_v1(
    env: &worker::Env,
    binding: &CloudflareSignerPeerSigningKeyBindingV1,
) -> RouterAbProtocolResult<[u8; 32]> {
    binding.validate()?;
    let secret = env.secret(&binding.binding_name).map_err(|err| {
        worker_binding_error(
            worker_binding_error_code(&err, &binding.binding_name),
            &binding.binding_name,
            "secret",
            err,
        )
    })?;
    let mut secret_value = secret.to_string();
    let key = decode_cloudflare_signer_peer_signing_key_v1(&secret_value);
    secret_value.zeroize();
    key
}

#[cfg(feature = "workers-rs")]
fn decode_cloudflare_signer_peer_signing_key_v1(
    secret_value: &str,
) -> RouterAbProtocolResult<[u8; 32]> {
    let mut key_bytes = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(secret_value.trim().as_bytes())
    {
        Ok(bytes) => bytes,
        Err(_) => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                "Cloudflare A/B peer signing key secret must be unpadded base64url",
            ));
        }
    };
    if key_bytes.len() != 32 {
        key_bytes.zeroize();
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare A/B peer signing key secret must decode to 32 bytes",
        ));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

#[cfg(feature = "workers-rs")]
async fn decrypt_cloudflare_aes_256_gcm_v1(
    key_bytes: &mut [u8],
    payload: &SignerEnvelopeAeadPayloadV1,
    aad: &RoleEnvelopeAadV1,
) -> RouterAbProtocolResult<Vec<u8>> {
    let worker_global: web_sys::WorkerGlobalScope = js_sys::global().unchecked_into();
    let crypto = worker_global
        .crypto()
        .map_err(|_| cloudflare_webcrypto_error("Cloudflare WebCrypto is unavailable"))?;
    let subtle = crypto.subtle();
    let key_data = js_sys::Uint8Array::from(&key_bytes[..]);
    let key_data_object: &js_sys::Object = key_data.unchecked_ref();
    let usages = js_sys::Array::new();
    usages.push(&wasm_bindgen::JsValue::from_str("decrypt"));
    let import_promise = subtle
        .import_key_with_str("raw", key_data_object, "AES-GCM", false, usages.as_ref())
        .map_err(|_| cloudflare_webcrypto_error("Cloudflare WebCrypto key import failed"))?;
    let imported_key = SendFuture::new(wasm_bindgen_futures::JsFuture::from(import_promise))
        .await
        .map_err(|_| cloudflare_webcrypto_error("Cloudflare WebCrypto key import failed"))?;
    let crypto_key: web_sys::CryptoKey = imported_key
        .dyn_into()
        .map_err(|_| cloudflare_webcrypto_error("Cloudflare WebCrypto imported wrong key type"))?;
    key_bytes.zeroize();

    let nonce = js_sys::Uint8Array::from(payload.nonce().as_slice());
    let params = web_sys::AesGcmParams::new_with_u8_array("AES-GCM", &nonce);
    let aad_bytes = aad.canonical_bytes();
    let aad_array = js_sys::Uint8Array::from(aad_bytes.as_slice());
    params.set_additional_data_u8_array(&aad_array);
    params.set_tag_length((SIGNER_ENVELOPE_AEAD_TAG_LEN_V1 * 8) as u8);
    let ciphertext = js_sys::Uint8Array::from(payload.ciphertext_and_tag());
    let params_object: &js_sys::Object = params.unchecked_ref();
    let decrypt_promise = subtle
        .decrypt_with_object_and_js_u8_array(params_object, &crypto_key, &ciphertext)
        .map_err(|_| cloudflare_webcrypto_error("Cloudflare WebCrypto decrypt failed"))?;
    let plaintext = SendFuture::new(wasm_bindgen_futures::JsFuture::from(decrypt_promise))
        .await
        .map_err(|_| cloudflare_webcrypto_error("Cloudflare WebCrypto decrypt failed"))?;
    Ok(js_sys::Uint8Array::new(&plaintext).to_vec())
}

#[cfg(feature = "workers-rs")]
fn cloudflare_webcrypto_error(message: &'static str) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}

#[cfg(feature = "workers-rs")]
fn worker_binding_error_code(err: &worker::Error, binding_name: &str) -> RouterAbProtocolErrorCode {
    if worker_binding_is_missing(err, binding_name) {
        RouterAbProtocolErrorCode::MissingLocalBinding
    } else {
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig
    }
}

#[cfg(feature = "workers-rs")]
fn worker_binding_error(
    code: RouterAbProtocolErrorCode,
    binding_name: &str,
    binding_kind: &str,
    err: worker::Error,
) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        code,
        format!("Cloudflare {binding_kind} binding `{binding_name}` failed validation: {err}"),
    )
}

#[cfg(feature = "workers-rs")]
fn worker_binding_is_missing(err: &worker::Error, binding_name: &str) -> bool {
    match err {
        worker::Error::BindingError(name) => name == binding_name,
        worker::Error::JsError(message) | worker::Error::RustError(message) => {
            message == &format!("Env does not contain binding `{binding_name}`")
                || message == &format!("Binding `{binding_name}` is undefined.")
                || message == &format!("no binding found for `{binding_name}`")
        }
        _ => false,
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_router_error_status(code: RouterAbProtocolErrorCode) -> u16 {
    match code {
        RouterAbProtocolErrorCode::EmptyField
        | RouterAbProtocolErrorCode::InvalidTimeRange
        | RouterAbProtocolErrorCode::InvalidGateDecision
        | RouterAbProtocolErrorCode::InvalidPrepareHandle
        | RouterAbProtocolErrorCode::InvalidRole
        | RouterAbProtocolErrorCode::InvalidSignerIdentity
        | RouterAbProtocolErrorCode::InvalidLifecycleState
        | RouterAbProtocolErrorCode::DowngradeRejected
        | RouterAbProtocolErrorCode::InvalidLocalHttpRequest
        | RouterAbProtocolErrorCode::InvalidLocalRoute
        | RouterAbProtocolErrorCode::MalformedWirePayload
        | RouterAbProtocolErrorCode::UnsupportedVectorVersion => 400,
        RouterAbProtocolErrorCode::ExpiredLocalRequest => 408,
        RouterAbProtocolErrorCode::ReplayedLocalRequest => 409,
        RouterAbProtocolErrorCode::MissingLocalBinding
        | RouterAbProtocolErrorCode::ForbiddenLocalBinding
        | RouterAbProtocolErrorCode::InvalidLocalServiceConfig => 500,
    }
}

#[cfg(feature = "workers-rs")]
fn cloudflare_now_unix_ms_v1() -> RouterAbProtocolResult<u64> {
    let now = worker::js_sys::Date::now();
    if !now.is_finite() || now <= 0.0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "Cloudflare Worker clock returned invalid Unix milliseconds",
        ));
    }
    Ok(now as u64)
}

#[cfg(feature = "workers-rs")]
fn cloudflare_random_bytes_v1(len: usize) -> RouterAbProtocolResult<Vec<u8>> {
    if len > CLOUDFLARE_SIGNER_HOST_RANDOM_PRELOAD_MAX_BYTES_V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "Cloudflare random preload length exceeds maximum",
        ));
    }
    let mut out = vec![0u8; len];
    getrandom::getrandom(&mut out).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            format!("Cloudflare random preload failed: {err}"),
        )
    })?;
    Ok(out)
}

fn require_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must not be empty"),
        ));
    }
    Ok(())
}

fn map_derivation_to_protocol(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!(
            "Cloudflare signer plaintext boundary rejected input: {:?}",
            error.code()
        ),
    )
}

fn map_root_share_to_protocol(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
        format!(
            "Cloudflare root-share wire boundary rejected input: {:?}",
            error.code()
        ),
    )
}

fn require_positive_ms(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value == 0 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            format!("{field} must be greater than zero"),
        ));
    }
    Ok(())
}

fn require_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            format!(
                "Cloudflare signer root-share scope requires signer role, received {}",
                role.as_str()
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use router_ab_core::{
        decode_recipient_proof_bundle_payload_v1,
        verify_recipient_proof_bundle_ciphertext_payload_v1, AbDerivationProofBatchPayloadV1,
        MpcPrfDleqProofWireV1, MpcPrfPartialBindingV1, MpcPrfPartialProofBundleV1,
        MpcPrfPartialWireV1, MpcPrfShareCommitmentWireV1, MpcPrfSignerPartialV1, MpcPrfSuiteId,
        OpenedShareKind, RecipientProofBundleEncryptionRequestV1, RecipientProofBundlePayloadV1,
        RootShareEpoch, SecretMaterial32, SignerIdentityV1, MPC_PRF_COMMITMENT_WIRE_V1_LEN,
        MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN, MPC_PRF_PARTIAL_WIRE_V1_LEN,
    };

    #[test]
    fn cloudflare_hpke_recipient_output_encryptor_round_trips() {
        let (recipient_private_key, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&[0x42; 32]).expect("recipient keypair derives");
        let recipient_public_key = format!(
            "x25519:{}",
            lower_hex(&CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key))
        );
        let plaintext = SecretMaterial32::new([0x5a; 32]);
        let request = RecipientOutputEncryptionRequestV1::new(
            Role::Client,
            OpenedShareKind::XClientBase,
            "client",
            recipient_public_key,
            digest(0x11),
            digest(0x22),
            &plaintext,
        )
        .expect("recipient output encryption request");
        let mut encryptor = CloudflareHpkeRecipientOutputEncryptorV1::new();
        let envelope = encryptor
            .encrypt_recipient_output_v1(request)
            .expect("hpke recipient output encrypts");

        assert_eq!(
            envelope.algorithm,
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1
        );
        assert_eq!(
            envelope.nonce(),
            &CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1
        );
        let aad = encode_recipient_output_ciphertext_aad_v1(&envelope).expect("hpke aad");
        let ciphertext_and_tag = envelope.ciphertext_and_tag().as_bytes();
        let (encapped_key, ciphertext) =
            ciphertext_and_tag.split_at(CloudflareHpkeKemV1::ENCAPPED_KEY_LEN);
        let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(encapped_key).expect("encapped key");
        let decrypted = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &recipient_private_key,
            CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_INFO_V1,
            &aad,
            ciphertext,
        )
        .expect("hpke recipient output opens");

        assert_eq!(decrypted, plaintext.as_bytes());
    }

    #[test]
    fn cloudflare_hpke_recipient_proof_bundle_encryptor_round_trips() {
        let (recipient_private_key, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&[0x44; 32]).expect("recipient keypair derives");
        let recipient_public_key = format!(
            "x25519:{}",
            lower_hex(&CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key))
        );
        let payload = sample_recipient_proof_bundle_payload();
        let request = RecipientProofBundleEncryptionRequestV1::new(&payload, recipient_public_key)
            .expect("recipient proof-bundle encryption request");
        let mut encryptor = CloudflareHpkeRecipientProofBundleEncryptorV1::new();
        let envelope = encryptor
            .encrypt_recipient_proof_bundle_v1(request)
            .expect("hpke recipient proof bundle encrypts");

        assert_eq!(
            envelope.algorithm,
            RecipientOutputEncryptionAlgorithmV1::HpkeX25519HkdfSha256Aes256GcmV1
        );
        assert_eq!(
            envelope.nonce(),
            &CLOUDFLARE_HPKE_RECIPIENT_OUTPUT_ENVELOPE_NONCE_V1
        );
        assert_eq!(envelope.recipient_role, Role::Client);
        assert_eq!(envelope.opened_share_kind, OpenedShareKind::XClientBase);
        assert_eq!(envelope.recipient_identity, "client");
        assert_eq!(envelope.payload_digest, payload.digest());

        let aad =
            encode_recipient_proof_bundle_ciphertext_aad_v1(&envelope).expect("proof bundle aad");
        let ciphertext_and_tag = envelope.ciphertext_and_tag().as_bytes();
        let (encapped_key, ciphertext) =
            ciphertext_and_tag.split_at(CloudflareHpkeKemV1::ENCAPPED_KEY_LEN);
        let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(encapped_key).expect("encapped key");
        let decrypted = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &recipient_private_key,
            CLOUDFLARE_HPKE_RECIPIENT_PROOF_BUNDLE_INFO_V1,
            &aad,
            ciphertext,
        )
        .expect("hpke recipient proof bundle opens");
        let decoded = decode_recipient_proof_bundle_payload_v1(&decrypted)
            .expect("proof-bundle payload decodes after HPKE open");

        assert_eq!(decoded, payload);
        verify_recipient_proof_bundle_ciphertext_payload_v1(&envelope, &decoded)
            .expect("proof-bundle envelope matches decrypted payload");
    }

    #[test]
    fn cloudflare_hpke_suite_opens_rfc9180_aes256_base_vector() {
        let info = decode_hex("4f6465206f6e2061204772656369616e2055726e");
        let ikm_r = decode_hex("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee");
        let expected_pk_r =
            decode_hex("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
        let enc = decode_hex("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
        let aad = decode_hex("436f756e742d30");
        let ciphertext = decode_hex(
            "e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a",
        );
        let plaintext = decode_hex("4265617574792069732074727574682c20747275746820626561757479");

        let (recipient_private_key, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&ikm_r).expect("recipient keypair derives");
        assert_eq!(
            CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key),
            expected_pk_r
        );

        let encapped_key = CloudflareHpkeKemV1::enc_from_bytes(&enc).expect("encapped key");
        let opened = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &recipient_private_key,
            &info,
            &aad,
            &ciphertext,
        )
        .expect("RFC 9180 AES-256-GCM base vector opens");
        assert_eq!(opened, plaintext);

        let err = CloudflareHpkeSuiteV1::open_base(
            &encapped_key,
            &recipient_private_key,
            &info,
            b"wrong-aad",
            &ciphertext,
        )
        .expect_err("modified AAD must fail");
        assert_eq!(err, hpke_ng::HpkeError::OpenError);
    }

    #[test]
    fn cloudflare_hpke_recipient_output_rejects_uppercase_public_key() {
        let err = parse_cloudflare_hpke_x25519_public_key_v1(
            "x25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .expect_err("uppercase public key hex must fail");

        assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
    }

    #[test]
    fn cloudflare_hpke_recipient_output_rejects_noncanonical_public_key() {
        let (_, recipient_public_key) =
            CloudflareHpkeKemV1::derive_key_pair(&[0x43; 32]).expect("recipient keypair derives");
        let mut public_key_bytes = CloudflareHpkeKemV1::pk_to_bytes(&recipient_public_key);
        public_key_bytes[31] |= 0x80;
        let encoded = format!("x25519:{}", lower_hex(&public_key_bytes));
        let err = parse_cloudflare_hpke_x25519_public_key_v1(&encoded)
            .expect_err("noncanonical public key must fail");

        assert_eq!(err.code(), RouterAbProtocolErrorCode::MalformedWirePayload);
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|chunk| (decode_hex_nibble(chunk[0]) << 4) | decode_hex_nibble(chunk[1]))
            .collect()
    }

    fn decode_hex_nibble(byte: u8) -> u8 {
        match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("test vector hex must be lowercase"),
        }
    }

    fn digest(seed: u8) -> PublicDigest32 {
        PublicDigest32::new([seed; 32])
    }

    fn sample_recipient_proof_bundle_payload() -> RecipientProofBundlePayloadV1 {
        let transcript_digest = digest(0x77);
        let root_share_epoch = RootShareEpoch::new("epoch-1").expect("root epoch");
        let proof_batch = AbDerivationProofBatchPayloadV1::new(
            signer(Role::SignerA, "signer-a"),
            signer(Role::SignerB, "signer-b"),
            transcript_digest,
            root_share_epoch.clone(),
            vec![sample_mpc_prf_proof_bundle(
                transcript_digest,
                root_share_epoch,
                OpenedShareKind::XClientBase,
                Role::Client,
                "client",
                Role::SignerA,
                "signer-a",
                0x77,
            )],
        )
        .expect("proof batch");
        RecipientProofBundlePayloadV1::new(
            "lifecycle-1",
            signer(Role::SignerA, "signer-a"),
            Role::Client,
            OpenedShareKind::XClientBase,
            "client",
            transcript_digest,
            proof_batch,
        )
        .expect("recipient proof-bundle payload")
    }

    fn signer(role: Role, signer_id: &str) -> SignerIdentityV1 {
        SignerIdentityV1::new(role, signer_id, "key-epoch-1").expect("signer identity")
    }

    #[allow(clippy::too_many_arguments)]
    fn sample_mpc_prf_proof_bundle(
        transcript_digest: PublicDigest32,
        root_share_epoch: RootShareEpoch,
        opened_share_kind: OpenedShareKind,
        recipient_role: Role,
        recipient_identity: &str,
        signer_role: Role,
        signer_identity: &str,
        seed: u8,
    ) -> MpcPrfPartialProofBundleV1 {
        let binding = MpcPrfPartialBindingV1 {
            suite_id: MpcPrfSuiteId::ThresholdPrfRistretto255Sha512V1,
            transcript_digest,
            root_share_epoch,
            opened_share_kind,
            recipient_role,
            recipient_identity: recipient_identity.to_owned(),
            signer_role,
            signer_identity: signer_identity.to_owned(),
        };
        let signer_partial = MpcPrfSignerPartialV1::new(
            binding,
            MpcPrfPartialWireV1::new(vec![seed; MPC_PRF_PARTIAL_WIRE_V1_LEN])
                .expect("partial wire"),
        )
        .expect("signer partial");
        MpcPrfPartialProofBundleV1::new(
            signer_partial,
            MpcPrfShareCommitmentWireV1::new(vec![
                seed.wrapping_add(1);
                MPC_PRF_COMMITMENT_WIRE_V1_LEN
            ])
            .expect("commitment wire"),
            MpcPrfDleqProofWireV1::new(vec![seed.wrapping_add(2); MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN])
                .expect("DLEQ proof wire"),
        )
        .expect("proof bundle")
    }

    fn lower_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }
}
