#![forbid(unsafe_code)]
#![deny(missing_docs)]
//! Client-owned preparation and completion for Router A/B Ed25519 Yao activation.

use core::fmt;

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use hpke_ng::{Aes256Gcm, DhKemX25519HkdfSha256, HkdfSha256, Hpke, Kem};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use router_ab_core::{
    Ed25519YaoDeriverRoleV1, Ed25519YaoEncryptedInputV1, Ed25519YaoEncryptedPackageV1,
    Ed25519YaoInputKindV1, Ed25519YaoOperationV1, RouterAbEd25519YaoActivationAdmissionReceiptV1,
    RouterAbEd25519YaoActivationExecuteRequestV1, RouterAbEd25519YaoActivationResultV1,
    RouterAbEd25519YaoApplicationBindingFactsV1, RouterAbEd25519YaoExportAdmissionReceiptV1,
    RouterAbEd25519YaoExportExecuteRequestV1, RouterAbEd25519YaoExportResultV1,
};
use router_ab_ed25519_yao_protocol::{
    combine_client_activation_packages, combine_export_packages, ed25519_yao_input_aad_v1,
    ed25519_yao_recipient_package_aad_v1, stable_key_derivation_context_v1,
    ActivationDeriverAClientPackage, ActivationDeriverBClientPackage, ExportDeriverAClientPackage,
    ExportDeriverBClientPackage, LocalEd25519YaoActivationDeriverARequestV1,
    LocalEd25519YaoActivationDeriverBRequestV1, LocalEd25519YaoActivationRecipientsV1,
    LocalEd25519YaoClientContributionV1, LocalEd25519YaoExportDeriverARequestV1,
    LocalEd25519YaoExportDeriverBRequestV1, LocalEd25519YaoExportRecipientV1,
    ED25519_YAO_INPUT_HPKE_INFO_V1, ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
};
use serde::Serialize;
use signer_core::ed25519_yao_derivation::{
    derive_ed25519_yao_client_contributions_v1,
    derive_ed25519_yao_client_root_from_email_otp_factor_v1,
    derive_ed25519_yao_client_root_from_passkey_prf_first_v1, Ed25519YaoClientDerivationRootV1,
};
use signer_core::near_ed25519_recovery::expand_ed25519_seed;
use signer_core::near_threshold_frost::compute_threshold_ed25519_group_public_key_2p_from_verifying_shares;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod signing;
#[cfg(target_arch = "wasm32")]
mod wasm;

pub use signing::{
    create_client_signing_share_v1, ClientSigningError, ClientSigningRequestV1,
    ClientSigningShareV1,
};
#[cfg(target_arch = "wasm32")]
pub use wasm::{
    WasmActivatedClientV1, WasmClientRecoverySessionV1, WasmClientRegistrationSessionV1,
    WasmClientSigningShareV1, WasmEmailOtpClientExportSessionV1,
    WasmEmailOtpClientRecoverySessionV1, WasmEmailOtpClientRegistrationSessionV1,
    WasmExportedEd25519SeedV1, WasmPasskeyClientExportSessionV1,
};

type InputHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;
type RecipientHpkeV1 = Hpke<DhKemX25519HkdfSha256, HkdfSha256, Aes256Gcm>;

/// Client activation preparation or completion failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientActivationError {
    /// Entropy was zero or reused across distinct purposes.
    InvalidEntropy,
    /// Admission, application facts, or participants did not share one stable binding.
    BindingMismatch,
    /// Client contribution derivation failed.
    DerivationFailed,
    /// HPKE key derivation, sealing, or opening failed.
    HpkeFailed,
    /// A role input could not be encoded.
    EncodingFailed,
    /// A typed Router request or result was inconsistent.
    InvalidProtocolShape,
    /// Recipient package decoding or scalar combination failed.
    InvalidRecipientPackage,
    /// Public activation evidence did not match the opened Client share.
    PublicRelationMismatch,
    /// Recovery or export produced a public key different from the registered identity.
    PublicKeyContinuityMismatch,
}

impl fmt::Display for ClientActivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidEntropy => "Ed25519 Yao Client entropy is invalid",
            Self::BindingMismatch => "Ed25519 Yao registration binding does not match Client facts",
            Self::DerivationFailed => "Ed25519 Yao Client contribution derivation failed",
            Self::HpkeFailed => "Ed25519 Yao Client HPKE operation failed",
            Self::EncodingFailed => "Ed25519 Yao Client role input encoding failed",
            Self::InvalidProtocolShape => "Ed25519 Yao Router protocol shape is invalid",
            Self::InvalidRecipientPackage => "Ed25519 Yao Client package is invalid",
            Self::PublicRelationMismatch => "Ed25519 Yao activation public relation is invalid",
            Self::PublicKeyContinuityMismatch => "Ed25519 Yao public-key continuity check failed",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ClientActivationError {}

/// Three independent random seeds supplied by the Client cryptographic boundary.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientActivationEntropyV1 {
    recipient_key_material: [u8; 32],
    deriver_a_seal_seed: [u8; 32],
    deriver_b_seal_seed: [u8; 32],
}

impl ClientActivationEntropyV1 {
    /// Creates purpose-separated entropy for recipient key derivation and both HPKE senders.
    pub fn new(
        recipient_key_material: [u8; 32],
        deriver_a_seal_seed: [u8; 32],
        deriver_b_seal_seed: [u8; 32],
    ) -> Result<Self, ClientActivationError> {
        let zero = [0_u8; 32];
        let valid = !recipient_key_material.ct_eq(&zero)
            & !deriver_a_seal_seed.ct_eq(&zero)
            & !deriver_b_seal_seed.ct_eq(&zero)
            & !recipient_key_material.ct_eq(&deriver_a_seal_seed)
            & !recipient_key_material.ct_eq(&deriver_b_seal_seed)
            & !deriver_a_seal_seed.ct_eq(&deriver_b_seal_seed);
        if !bool::from(valid) {
            return Err(ClientActivationError::InvalidEntropy);
        }
        Ok(Self {
            recipient_key_material,
            deriver_a_seal_seed,
            deriver_b_seal_seed,
        })
    }
}

impl fmt::Debug for ClientActivationEntropyV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientActivationEntropyV1([REDACTED])")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Zeroize)]
enum ClientActivationContinuityV1 {
    Establish,
    Preserve([u8; 32]),
}

/// Client-owned state retained between activation execution and completion.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientActivationStateV1 {
    #[zeroize(skip)]
    binding: router_ab_core::Ed25519YaoCeremonyBindingV1,
    participant_ids: [u16; 2],
    recipient_private_key: [u8; 32],
    continuity: ClientActivationContinuityV1,
}

impl fmt::Debug for ClientActivationStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientActivationStateV1([REDACTED])")
    }
}

/// Prepared opaque execution plus the Client-only completion state.
#[derive(Debug)]
pub struct PreparedClientActivationV1 {
    execute_request: RouterAbEd25519YaoActivationExecuteRequestV1,
    state: ClientActivationStateV1,
}

/// Client-owned one-use state retained between export execution and completion.
///
/// Completion consumes the state, so a second reconstruction attempt cannot compile.
///
/// ```compile_fail
/// use router_ab_core::RouterAbEd25519YaoExportResultV1;
/// use router_ab_ed25519_yao_client::{complete_client_export_v1, ClientExportStateV1};
///
/// fn complete_twice(state: ClientExportStateV1, result: &RouterAbEd25519YaoExportResultV1) {
///     let _ = complete_client_export_v1(state, result);
///     let _ = complete_client_export_v1(state, result);
/// }
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ClientExportStateV1 {
    #[zeroize(skip)]
    binding: router_ab_core::RouterAbEd25519YaoExportBindingV1,
    recipient_private_key: [u8; 32],
}

impl fmt::Debug for ClientExportStateV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ClientExportStateV1([REDACTED])")
    }
}

/// Prepared opaque export execution plus Client-only completion state.
#[derive(Debug)]
pub struct PreparedClientExportV1 {
    execute_request: RouterAbEd25519YaoExportExecuteRequestV1,
    state: ClientExportStateV1,
}

impl PreparedClientExportV1 {
    /// Returns the opaque export execution request sent to Router.
    pub const fn execute_request(&self) -> &RouterAbEd25519YaoExportExecuteRequestV1 {
        &self.execute_request
    }

    /// Consumes preparation into its public request and Client-only state.
    pub fn into_parts(
        self,
    ) -> (
        RouterAbEd25519YaoExportExecuteRequestV1,
        ClientExportStateV1,
    ) {
        (self.execute_request, self.state)
    }
}

/// Exact Ed25519 seed reconstructed only inside the Client boundary.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ExportedEd25519SeedV1([u8; 32]);

impl ExportedEd25519SeedV1 {
    /// Returns the verified seed inside the trusted Client boundary.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Consumes the secret into its fixed-width seed bytes.
    pub fn into_bytes(mut self) -> [u8; 32] {
        core::mem::take(&mut self.0)
    }
}

impl fmt::Debug for ExportedEd25519SeedV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExportedEd25519SeedV1([REDACTED])")
    }
}

impl PreparedClientActivationV1 {
    /// Returns the opaque A/B execution request sent to the SDK Router.
    pub const fn execute_request(&self) -> &RouterAbEd25519YaoActivationExecuteRequestV1 {
        &self.execute_request
    }

    /// Consumes preparation into the Router request and Client-only completion state.
    pub fn into_parts(
        self,
    ) -> (
        RouterAbEd25519YaoActivationExecuteRequestV1,
        ClientActivationStateV1,
    ) {
        (self.execute_request, self.state)
    }
}

/// Activated Client signing share and its verified public identity.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ActivatedClientV1 {
    client_scalar_share: [u8; 32],
    #[zeroize(skip)]
    registered_public_key: [u8; 32],
    #[zeroize(skip)]
    state_epoch: u64,
}

impl ActivatedClientV1 {
    /// Returns the Client's canonical scalar share within the trusted Client boundary.
    pub const fn client_scalar_share(&self) -> &[u8; 32] {
        &self.client_scalar_share
    }

    /// Returns the verified registered Ed25519 public key.
    pub const fn registered_public_key(&self) -> [u8; 32] {
        self.registered_public_key
    }

    /// Returns the activated SigningWorker state epoch.
    pub const fn state_epoch(&self) -> u64 {
        self.state_epoch
    }
}

impl fmt::Debug for ActivatedClientV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActivatedClientV1")
            .field("client_scalar_share", &"[REDACTED]")
            .field("registered_public_key", &self.registered_public_key)
            .field("state_epoch", &self.state_epoch)
            .finish()
    }
}

/// Derives the Client root inside Rust from passkey PRF.first and prepares registration.
pub fn prepare_passkey_client_registration_v1(
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    passkey_prf_first: [u8; 32],
    entropy: ClientActivationEntropyV1,
) -> Result<PreparedClientActivationV1, ClientActivationError> {
    prepare_passkey_client_activation_v1(
        admission,
        application,
        participant_ids,
        passkey_prf_first,
        entropy,
        Ed25519YaoOperationV1::Registration,
        ClientActivationContinuityV1::Establish,
    )
}

/// Derives the retained Client root from the same passkey PRF.first and prepares recovery.
pub fn prepare_passkey_client_recovery_v1(
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    passkey_prf_first: [u8; 32],
    expected_registered_public_key: [u8; 32],
    entropy: ClientActivationEntropyV1,
) -> Result<PreparedClientActivationV1, ClientActivationError> {
    if expected_registered_public_key.iter().all(|byte| *byte == 0) {
        return Err(ClientActivationError::PublicKeyContinuityMismatch);
    }
    prepare_passkey_client_activation_v1(
        admission,
        application,
        participant_ids,
        passkey_prf_first,
        entropy,
        Ed25519YaoOperationV1::Recovery,
        ClientActivationContinuityV1::Preserve(expected_registered_public_key),
    )
}

/// Derives the Client root from an Email OTP factor and prepares registration.
pub fn prepare_email_otp_client_registration_v1(
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    email_otp_factor: [u8; 32],
    entropy: ClientActivationEntropyV1,
) -> Result<PreparedClientActivationV1, ClientActivationError> {
    prepare_email_otp_client_activation_v1(
        admission,
        application,
        participant_ids,
        email_otp_factor,
        entropy,
        Ed25519YaoOperationV1::Registration,
        ClientActivationContinuityV1::Establish,
    )
}

/// Derives the retained Client root from the Email OTP factor and prepares recovery.
pub fn prepare_email_otp_client_recovery_v1(
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    email_otp_factor: [u8; 32],
    expected_registered_public_key: [u8; 32],
    entropy: ClientActivationEntropyV1,
) -> Result<PreparedClientActivationV1, ClientActivationError> {
    if expected_registered_public_key.iter().all(|byte| *byte == 0) {
        return Err(ClientActivationError::PublicKeyContinuityMismatch);
    }
    prepare_email_otp_client_activation_v1(
        admission,
        application,
        participant_ids,
        email_otp_factor,
        entropy,
        Ed25519YaoOperationV1::Recovery,
        ClientActivationContinuityV1::Preserve(expected_registered_public_key),
    )
}

fn prepare_email_otp_client_activation_v1(
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    email_otp_factor: [u8; 32],
    entropy: ClientActivationEntropyV1,
    operation: Ed25519YaoOperationV1,
    continuity: ClientActivationContinuityV1,
) -> Result<PreparedClientActivationV1, ClientActivationError> {
    let context = stable_key_derivation_context_v1(application, participant_ids)
        .map_err(|_| ClientActivationError::DerivationFailed)?;
    let root = derive_ed25519_yao_client_root_from_email_otp_factor_v1(
        &email_otp_factor,
        context.application_binding_digest(),
    )
    .map_err(|_| ClientActivationError::DerivationFailed)?;
    prepare_client_activation_with_root_v1(
        admission,
        application,
        participant_ids,
        root,
        entropy,
        operation,
        continuity,
    )
}

fn prepare_passkey_client_activation_v1(
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    passkey_prf_first: [u8; 32],
    entropy: ClientActivationEntropyV1,
    operation: Ed25519YaoOperationV1,
    continuity: ClientActivationContinuityV1,
) -> Result<PreparedClientActivationV1, ClientActivationError> {
    let context = stable_key_derivation_context_v1(application, participant_ids)
        .map_err(|_| ClientActivationError::DerivationFailed)?;
    let root = derive_ed25519_yao_client_root_from_passkey_prf_first_v1(
        &passkey_prf_first,
        context.application_binding_digest(),
    )
    .map_err(|_| ClientActivationError::DerivationFailed)?;
    prepare_client_activation_with_root_v1(
        admission,
        application,
        participant_ids,
        root,
        entropy,
        operation,
        continuity,
    )
}

fn prepare_client_activation_with_root_v1(
    admission: &RouterAbEd25519YaoActivationAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    root: Ed25519YaoClientDerivationRootV1,
    mut entropy: ClientActivationEntropyV1,
    operation: Ed25519YaoOperationV1,
    continuity: ClientActivationContinuityV1,
) -> Result<PreparedClientActivationV1, ClientActivationError> {
    let context = stable_key_derivation_context_v1(application, participant_ids)
        .map_err(|_| ClientActivationError::DerivationFailed)?;
    if admission.binding().operation != operation
        || context.binding_digest() != admission.binding().stable_key_context_binding.into_bytes()
    {
        return Err(ClientActivationError::BindingMismatch);
    }
    let contributions = derive_ed25519_yao_client_contributions_v1(&root, &context)
        .map_err(|_| ClientActivationError::DerivationFailed)?;
    let (deriver_a, deriver_b) = contributions.into_parts();
    let (deriver_a_y, deriver_a_tau) = deriver_a.into_parts();
    let (deriver_b_y, deriver_b_tau) = deriver_b.into_parts();
    let (recipient_private_key, recipient_public_key) =
        derive_recipient_key_pair(&entropy.recipient_key_material)?;
    let recipients = LocalEd25519YaoActivationRecipientsV1 {
        client_public_key: recipient_public_key,
        signing_worker_public_key: admission.keyset().signing_worker_recipient_public_key(),
    };
    let request_a = LocalEd25519YaoActivationDeriverARequestV1 {
        binding: admission.binding().clone(),
        application_binding: application.clone(),
        participant_ids,
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: deriver_a_y.into_bytes(),
            tau: deriver_a_tau.into_bytes(),
        },
        recipients,
    };
    let request_b = LocalEd25519YaoActivationDeriverBRequestV1 {
        binding: admission.binding().clone(),
        application_binding: application.clone(),
        participant_ids,
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: deriver_b_y.into_bytes(),
            tau: deriver_b_tau.into_bytes(),
        },
        recipients,
    };
    let deriver_a_input = seal_activation_input(
        Ed25519YaoDeriverRoleV1::DeriverA,
        admission.keyset().deriver_a_input_public_key(),
        &mut entropy.deriver_a_seal_seed,
        admission.binding(),
        &request_a,
    )?;
    let deriver_b_input = seal_activation_input(
        Ed25519YaoDeriverRoleV1::DeriverB,
        admission.keyset().deriver_b_input_public_key(),
        &mut entropy.deriver_b_seal_seed,
        admission.binding(),
        &request_b,
    )?;
    let execute_request = RouterAbEd25519YaoActivationExecuteRequestV1::new(
        admission.binding().clone(),
        deriver_a_input,
        deriver_b_input,
    )
    .map_err(|_| ClientActivationError::InvalidProtocolShape)?;
    Ok(PreparedClientActivationV1 {
        execute_request,
        state: ClientActivationStateV1 {
            binding: admission.binding().clone(),
            participant_ids,
            recipient_private_key,
            continuity,
        },
    })
}

/// Opens the two Client packages and verifies the activation public relation.
pub fn complete_client_activation_v1(
    state: ClientActivationStateV1,
    result: &RouterAbEd25519YaoActivationResultV1,
) -> Result<ActivatedClientV1, ClientActivationError> {
    if result.binding() != &state.binding {
        return Err(ClientActivationError::BindingMismatch);
    }
    let transcript = result.public_receipt().transcript();
    let mut deriver_a_plaintext = open_client_package(
        result.deriver_a_client_package(),
        &state.recipient_private_key,
    )?;
    let mut deriver_b_plaintext = open_client_package(
        result.deriver_b_client_package(),
        &state.recipient_private_key,
    )?;
    let deriver_a =
        ActivationDeriverAClientPackage::from_bytes(core::mem::take(&mut *deriver_a_plaintext))
            .map_err(|_| ClientActivationError::InvalidRecipientPackage)?;
    let deriver_b =
        ActivationDeriverBClientPackage::from_bytes(core::mem::take(&mut *deriver_b_plaintext))
            .map_err(|_| ClientActivationError::InvalidRecipientPackage)?;
    let client_scalar_share = combine_client_activation_packages(
        state.binding.session_id.into_bytes(),
        transcript,
        deriver_a,
        deriver_b,
    )
    .map_err(|_| ClientActivationError::InvalidRecipientPackage)?
    .into_bytes();
    verify_public_relation(&client_scalar_share, state.participant_ids, result)?;
    if let ClientActivationContinuityV1::Preserve(expected) = state.continuity {
        if !bool::from(expected.ct_eq(&result.public_receipt().registered_public_key())) {
            return Err(ClientActivationError::PublicKeyContinuityMismatch);
        }
    }
    Ok(ActivatedClientV1 {
        client_scalar_share,
        registered_public_key: result.public_receipt().registered_public_key(),
        state_epoch: result.public_receipt().state_epoch().get(),
    })
}

/// Derives the retained Client contribution from fresh passkey PRF.first and prepares export.
#[allow(clippy::too_many_arguments)]
pub fn prepare_passkey_client_export_v1(
    admission: &RouterAbEd25519YaoExportAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    passkey_prf_first: [u8; 32],
    entropy: ClientActivationEntropyV1,
) -> Result<PreparedClientExportV1, ClientActivationError> {
    let context = stable_key_derivation_context_v1(application, participant_ids)
        .map_err(|_| ClientActivationError::DerivationFailed)?;
    let ceremony = admission.binding().ceremony();
    if ceremony.operation != Ed25519YaoOperationV1::Export
        || context.binding_digest() != ceremony.stable_key_context_binding.into_bytes()
    {
        return Err(ClientActivationError::BindingMismatch);
    }
    let root = derive_ed25519_yao_client_root_from_passkey_prf_first_v1(
        &passkey_prf_first,
        context.application_binding_digest(),
    )
    .map_err(|_| ClientActivationError::DerivationFailed)?;
    prepare_client_export_with_root_v1(admission, application, participant_ids, root, entropy)
}

/// Derives the retained Client contribution from the Email OTP factor and prepares export.
#[allow(clippy::too_many_arguments)]
pub fn prepare_email_otp_client_export_v1(
    admission: &RouterAbEd25519YaoExportAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    email_otp_factor: [u8; 32],
    entropy: ClientActivationEntropyV1,
) -> Result<PreparedClientExportV1, ClientActivationError> {
    let context = stable_key_derivation_context_v1(application, participant_ids)
        .map_err(|_| ClientActivationError::DerivationFailed)?;
    let ceremony = admission.binding().ceremony();
    if ceremony.operation != Ed25519YaoOperationV1::Export
        || context.binding_digest() != ceremony.stable_key_context_binding.into_bytes()
    {
        return Err(ClientActivationError::BindingMismatch);
    }
    let root = derive_ed25519_yao_client_root_from_email_otp_factor_v1(
        &email_otp_factor,
        context.application_binding_digest(),
    )
    .map_err(|_| ClientActivationError::DerivationFailed)?;
    prepare_client_export_with_root_v1(admission, application, participant_ids, root, entropy)
}

fn prepare_client_export_with_root_v1(
    admission: &RouterAbEd25519YaoExportAdmissionReceiptV1,
    application: &RouterAbEd25519YaoApplicationBindingFactsV1,
    participant_ids: [u16; 2],
    root: Ed25519YaoClientDerivationRootV1,
    mut entropy: ClientActivationEntropyV1,
) -> Result<PreparedClientExportV1, ClientActivationError> {
    let context = stable_key_derivation_context_v1(application, participant_ids)
        .map_err(|_| ClientActivationError::DerivationFailed)?;
    let contributions = derive_ed25519_yao_client_contributions_v1(&root, &context)
        .map_err(|_| ClientActivationError::DerivationFailed)?;
    let (deriver_a, deriver_b) = contributions.into_parts();
    let (deriver_a_y, deriver_a_tau) = deriver_a.into_parts();
    let (deriver_b_y, deriver_b_tau) = deriver_b.into_parts();
    let (recipient_private_key, recipient_public_key) =
        derive_recipient_key_pair(&entropy.recipient_key_material)?;
    let recipients = LocalEd25519YaoExportRecipientV1 {
        client_public_key: recipient_public_key,
    };
    let ceremony = admission.binding().ceremony().clone();
    let request_a = LocalEd25519YaoExportDeriverARequestV1 {
        binding: ceremony.clone(),
        application_binding: application.clone(),
        participant_ids,
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: deriver_a_y.into_bytes(),
            tau: deriver_a_tau.into_bytes(),
        },
        recipients,
    };
    let request_b = LocalEd25519YaoExportDeriverBRequestV1 {
        binding: ceremony.clone(),
        application_binding: application.clone(),
        participant_ids,
        client_contribution: LocalEd25519YaoClientContributionV1 {
            y: deriver_b_y.into_bytes(),
            tau: deriver_b_tau.into_bytes(),
        },
        recipients,
    };
    let deriver_a_input = seal_export_input(
        Ed25519YaoDeriverRoleV1::DeriverA,
        admission.keyset().deriver_a_input_public_key(),
        &mut entropy.deriver_a_seal_seed,
        &ceremony,
        &request_a,
    )?;
    let deriver_b_input = seal_export_input(
        Ed25519YaoDeriverRoleV1::DeriverB,
        admission.keyset().deriver_b_input_public_key(),
        &mut entropy.deriver_b_seal_seed,
        &ceremony,
        &request_b,
    )?;
    let execute_request = RouterAbEd25519YaoExportExecuteRequestV1::new(
        admission.binding().clone(),
        deriver_a_input,
        deriver_b_input,
    )
    .map_err(|_| ClientActivationError::InvalidProtocolShape)?;
    Ok(PreparedClientExportV1 {
        execute_request,
        state: ClientExportStateV1 {
            binding: admission.binding().clone(),
            recipient_private_key,
        },
    })
}

/// Reconstructs and verifies the exact seed inside the Client boundary.
pub fn complete_client_export_v1(
    state: ClientExportStateV1,
    result: &RouterAbEd25519YaoExportResultV1,
) -> Result<ExportedEd25519SeedV1, ClientActivationError> {
    if result.binding() != &state.binding {
        return Err(ClientActivationError::BindingMismatch);
    }
    let mut deriver_a_plaintext = open_client_package(
        result.deriver_a_client_package(),
        &state.recipient_private_key,
    )?;
    let mut deriver_b_plaintext = open_client_package(
        result.deriver_b_client_package(),
        &state.recipient_private_key,
    )?;
    let deriver_a =
        ExportDeriverAClientPackage::from_bytes(core::mem::take(&mut *deriver_a_plaintext))
            .map_err(|_| ClientActivationError::InvalidRecipientPackage)?;
    let deriver_b =
        ExportDeriverBClientPackage::from_bytes(core::mem::take(&mut *deriver_b_plaintext))
            .map_err(|_| ClientActivationError::InvalidRecipientPackage)?;
    let mut seed = Zeroizing::new(
        combine_export_packages(
            state.binding.ceremony().session_id.into_bytes(),
            result.transcript(),
            deriver_a,
            deriver_b,
        )
        .map_err(|_| ClientActivationError::InvalidRecipientPackage)?
        .into_bytes(),
    );
    let expanded = expand_ed25519_seed(*seed);
    if !bool::from(
        expanded
            .public_key_bytes
            .ct_eq(&state.binding.registered_public_key()),
    ) {
        return Err(ClientActivationError::PublicKeyContinuityMismatch);
    }
    Ok(ExportedEd25519SeedV1(core::mem::take(&mut *seed)))
}

fn seal_activation_input<Request: Serialize>(
    deriver: Ed25519YaoDeriverRoleV1,
    public_key: [u8; 32],
    seed: &mut [u8; 32],
    binding: &router_ab_core::Ed25519YaoCeremonyBindingV1,
    request: &Request,
) -> Result<Ed25519YaoEncryptedInputV1, ClientActivationError> {
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(&public_key)
        .map_err(|_| ClientActivationError::HpkeFailed)?;
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(request).map_err(|_| ClientActivationError::EncodingFailed)?,
    );
    let session = binding.session_id.into_bytes();
    let stable_context_binding = binding.stable_key_context_binding.into_bytes();
    let aad = ed25519_yao_input_aad_v1(
        Ed25519YaoInputKindV1::Activation,
        deriver,
        binding.operation,
        session,
        stable_context_binding,
    );
    let mut rng = ChaCha20Rng::from_seed(*seed);
    seed.zeroize();
    let (encapsulated_key, ciphertext) = InputHpkeV1::seal_base(
        &mut rng,
        &public_key,
        ED25519_YAO_INPUT_HPKE_INFO_V1,
        &aad,
        &plaintext,
    )
    .map_err(|_| ClientActivationError::HpkeFailed)?;
    plaintext.zeroize();
    Ed25519YaoEncryptedInputV1::new(
        Ed25519YaoInputKindV1::Activation,
        deriver,
        binding.operation,
        session,
        stable_context_binding,
        encapsulated_key
            .as_ref()
            .try_into()
            .map_err(|_| ClientActivationError::HpkeFailed)?,
        ciphertext,
    )
    .map_err(|_| ClientActivationError::InvalidProtocolShape)
}

fn seal_export_input<Request: Serialize>(
    deriver: Ed25519YaoDeriverRoleV1,
    public_key: [u8; 32],
    seed: &mut [u8; 32],
    binding: &router_ab_core::Ed25519YaoCeremonyBindingV1,
    request: &Request,
) -> Result<Ed25519YaoEncryptedInputV1, ClientActivationError> {
    let public_key = DhKemX25519HkdfSha256::pk_from_bytes(&public_key)
        .map_err(|_| ClientActivationError::HpkeFailed)?;
    let mut plaintext = Zeroizing::new(
        serde_json::to_vec(request).map_err(|_| ClientActivationError::EncodingFailed)?,
    );
    let session = binding.session_id.into_bytes();
    let stable_context_binding = binding.stable_key_context_binding.into_bytes();
    let aad = ed25519_yao_input_aad_v1(
        Ed25519YaoInputKindV1::Export,
        deriver,
        Ed25519YaoOperationV1::Export,
        session,
        stable_context_binding,
    );
    let mut rng = ChaCha20Rng::from_seed(*seed);
    seed.zeroize();
    let (encapsulated_key, ciphertext) = InputHpkeV1::seal_base(
        &mut rng,
        &public_key,
        ED25519_YAO_INPUT_HPKE_INFO_V1,
        &aad,
        &plaintext,
    )
    .map_err(|_| ClientActivationError::HpkeFailed)?;
    plaintext.zeroize();
    Ed25519YaoEncryptedInputV1::new(
        Ed25519YaoInputKindV1::Export,
        deriver,
        Ed25519YaoOperationV1::Export,
        session,
        stable_context_binding,
        encapsulated_key
            .as_ref()
            .try_into()
            .map_err(|_| ClientActivationError::HpkeFailed)?,
        ciphertext,
    )
    .map_err(|_| ClientActivationError::InvalidProtocolShape)
}

fn derive_recipient_key_pair(
    input_key_material: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), ClientActivationError> {
    let (private_key, public_key) = DhKemX25519HkdfSha256::derive_key_pair(input_key_material)
        .map_err(|_| ClientActivationError::HpkeFailed)?;
    let private_key_bytes = Zeroizing::new(DhKemX25519HkdfSha256::sk_to_bytes(&private_key));
    let private_key = private_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| ClientActivationError::HpkeFailed)?;
    let public_key = DhKemX25519HkdfSha256::pk_to_bytes(&public_key)
        .as_slice()
        .try_into()
        .map_err(|_| ClientActivationError::HpkeFailed)?;
    Ok((private_key, public_key))
}

fn open_client_package(
    package: &Ed25519YaoEncryptedPackageV1,
    recipient_private_key: &[u8; 32],
) -> Result<Zeroizing<Vec<u8>>, ClientActivationError> {
    package
        .validate()
        .map_err(|_| ClientActivationError::InvalidProtocolShape)?;
    if !package.kind().is_client() {
        return Err(ClientActivationError::InvalidRecipientPackage);
    }
    let encapsulated_key = DhKemX25519HkdfSha256::enc_from_bytes(package.encapsulated_key())
        .map_err(|_| ClientActivationError::HpkeFailed)?;
    let private_key = DhKemX25519HkdfSha256::sk_from_bytes(recipient_private_key)
        .map_err(|_| ClientActivationError::HpkeFailed)?;
    let aad = ed25519_yao_recipient_package_aad_v1(
        package.kind(),
        package.deriver(),
        package.session(),
        package.transcript(),
    );
    RecipientHpkeV1::open_base(
        &encapsulated_key,
        &private_key,
        ED25519_YAO_RECIPIENT_PACKAGE_HPKE_INFO_V1,
        &aad,
        package.ciphertext(),
    )
    .map(Zeroizing::new)
    .map_err(|_| ClientActivationError::HpkeFailed)
}

fn verify_public_relation(
    client_scalar_share: &[u8; 32],
    participant_ids: [u16; 2],
    result: &RouterAbEd25519YaoActivationResultV1,
) -> Result<(), ClientActivationError> {
    let scalar_option = Scalar::from_canonical_bytes(*client_scalar_share);
    let scalar = scalar_option.unwrap_or(Scalar::ZERO);
    let client_commitment = (ED25519_BASEPOINT_POINT * scalar).compress().to_bytes();
    let receipt = result.public_receipt();
    let mut valid = scalar_option.is_some();
    valid &= client_commitment.ct_eq(&receipt.joined_client_commitment());
    valid &= receipt
        .joined_signing_worker_commitment()
        .ct_eq(&receipt.signing_worker_verifying_share());
    let registered_public_key =
        compute_threshold_ed25519_group_public_key_2p_from_verifying_shares(
            &client_commitment,
            &receipt.signing_worker_verifying_share(),
            participant_ids[0],
            participant_ids[1],
        )
        .map_err(|_| ClientActivationError::PublicRelationMismatch)?;
    valid &= registered_public_key.ct_eq(&receipt.registered_public_key());
    if bool::from(valid) {
        Ok(())
    } else {
        Err(ClientActivationError::PublicRelationMismatch)
    }
}
