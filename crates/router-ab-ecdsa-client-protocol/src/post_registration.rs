use base64ct::{Base64UrlUnpadded, Encoding};

use super::registration::{
    push_bytes, push_signer_identity, push_signer_set, require_ascii_fields,
    require_fields_non_empty, sha256, validate_recipient_key,
};
use super::{
    decode_x25519_public_key, seal_ecdsa_signer_envelope_v1, EcdsaClientProtocolError,
    EcdsaDeriverRoleV1, EcdsaRegistrationEncryptedEnvelopeV1, EcdsaRegistrationRecipientKeysV1,
    EcdsaRegistrationSealSeedsV1, EcdsaRegistrationSignerSetV1, EcdsaRoleEnvelopeAadV1,
    EcdsaSignerEnvelopePublicKeyV1, EcdsaStableKeyContextV1,
};

const EXPORT_REQUEST_VERSION_V1: &[u8] = b"router-ab-ecdsa-derivation/export-request/v1";
const RECOVERY_REQUEST_VERSION_V1: &[u8] = b"router-ab-ecdsa-derivation/recovery-request/v1";
const REFRESH_REQUEST_VERSION_V1: &[u8] = b"router-ab-ecdsa-derivation/refresh-request/v1";
const PUBLIC_IDENTITY_VERSION_V1: &[u8] = b"router-ab-ecdsa-derivation/public-identity/v1";
const DERIVER_PLAINTEXT_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/deriver-envelope-plaintext/v1";
const DERIVATION_CONTEXT_VERSION_V1: &[u8] = b"router-ab-ecdsa-threshold-prf/context/v1";
const DERIVATION_TRANSCRIPT_VERSION_V1: &[u8] = b"router-ab-derivation/transcript/v1";
const THRESHOLD_REQUEST_CONTEXT_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-threshold-prf-request-context/v1";
const CLIENT_EXPORT_OUTPUT_V1: &str = "client_export";
const SIGNING_WORKER_ACTIVATION_OUTPUT_V1: &str = "signing_worker_activation";
const KEY_SCOPE_V1: &str = "evm-family";

/// Exact post-registration ceremony branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcdsaPostRegistrationCeremonyV1 {
    /// Explicit user-authorized client export.
    ExplicitExport,
    /// Same-root client recovery.
    Recovery,
    /// SigningWorker activation refresh.
    ActivationRefresh,
}

impl EcdsaPostRegistrationCeremonyV1 {
    /// Rejects an output-kind label that is invalid for this ceremony.
    pub fn validate_output_kind_wire(
        self,
        output_kind: &str,
    ) -> Result<(), EcdsaClientProtocolError> {
        if output_kind == self.output_kind() {
            return Ok(());
        }
        Err(EcdsaClientProtocolError::InvalidShape)
    }

    fn work_kind(self) -> &'static str {
        match self {
            Self::ExplicitExport => "key_export",
            Self::Recovery => "recovery",
            Self::ActivationRefresh => "server_share_refresh",
        }
    }

    fn primitive_kind(self) -> &'static str {
        match self {
            Self::ExplicitExport => "export",
            Self::Recovery => "recovery",
            Self::ActivationRefresh => "refresh",
        }
    }

    fn request_kind(self) -> &'static str {
        match self {
            Self::ExplicitExport => "explicit_key_export",
            Self::Recovery => "recovery",
            Self::ActivationRefresh => "refresh",
        }
    }

    fn output_kind(self) -> &'static str {
        match self {
            Self::ExplicitExport | Self::Recovery => CLIENT_EXPORT_OUTPUT_V1,
            Self::ActivationRefresh => SIGNING_WORKER_ACTIVATION_OUTPUT_V1,
        }
    }

    fn header_version(self) -> &'static [u8] {
        match self {
            Self::ExplicitExport => EXPORT_REQUEST_VERSION_V1,
            Self::Recovery => RECOVERY_REQUEST_VERSION_V1,
            Self::ActivationRefresh => REFRESH_REQUEST_VERSION_V1,
        }
    }
}

/// Raw post-registration lifecycle fields accepted at the client boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPostRegistrationLifecycleWireV1 {
    /// Router-assigned lifecycle id.
    pub lifecycle_id: String,
    /// Product work-kind label.
    pub work_kind: String,
    /// Primitive request-kind label.
    pub primitive_request_kind: String,
    /// Public signing-root share epoch.
    pub root_share_epoch: String,
    /// Canonical wallet or account id.
    pub account_id: String,
    /// Canonical session id.
    pub session_id: String,
    /// Transcript-bound signer-set id.
    pub signer_set_id: String,
    /// Selected SigningWorker id.
    pub selected_server_id: String,
}

/// Validated lifecycle bound to one exact post-registration ceremony.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPostRegistrationLifecycleV1 {
    ceremony: EcdsaPostRegistrationCeremonyV1,
    lifecycle_id: String,
    root_share_epoch: String,
    account_id: String,
    session_id: String,
    signer_set_id: String,
    selected_server_id: String,
}

impl EcdsaPostRegistrationLifecycleV1 {
    /// Parses lifecycle fields and rejects unknown or mismatched work/primitive labels.
    pub fn from_wire(
        ceremony: EcdsaPostRegistrationCeremonyV1,
        wire: EcdsaPostRegistrationLifecycleWireV1,
    ) -> Result<Self, EcdsaClientProtocolError> {
        if wire.work_kind != ceremony.work_kind()
            || wire.primitive_request_kind != ceremony.primitive_kind()
        {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        require_fields_non_empty(&[
            &wire.lifecycle_id,
            &wire.root_share_epoch,
            &wire.account_id,
            &wire.session_id,
            &wire.signer_set_id,
            &wire.selected_server_id,
        ])?;
        Ok(Self {
            ceremony,
            lifecycle_id: wire.lifecycle_id,
            root_share_epoch: wire.root_share_epoch,
            account_id: wire.account_id,
            session_id: wire.session_id,
            signer_set_id: wire.signer_set_id,
            selected_server_id: wire.selected_server_id,
        })
    }

    /// Returns the ceremony branch.
    pub fn ceremony(&self) -> EcdsaPostRegistrationCeremonyV1 {
        self.ceremony
    }

    /// Returns the lifecycle id.
    pub fn lifecycle_id(&self) -> &str {
        &self.lifecycle_id
    }

    /// Returns the canonical work-kind label.
    pub fn work_kind(&self) -> &'static str {
        self.ceremony.work_kind()
    }

    /// Returns the canonical primitive request-kind label.
    pub fn primitive_request_kind(&self) -> &'static str {
        self.ceremony.primitive_kind()
    }

    /// Returns the root-share epoch.
    pub fn root_share_epoch(&self) -> &str {
        &self.root_share_epoch
    }

    /// Returns the wallet or account id.
    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    /// Returns the session id.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Returns the signer-set id.
    pub fn signer_set_id(&self) -> &str {
        &self.signer_set_id
    }

    /// Returns the selected SigningWorker id.
    pub fn selected_server_id(&self) -> &str {
        &self.selected_server_id
    }
}

/// Raw public-identity fields normalized at the client boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPublicIdentityInputV1 {
    /// Stable-context binding digest in unpadded base64url.
    pub context_binding_b64u: String,
    /// Client compressed secp256k1 public key in unpadded base64url.
    pub derivation_client_share_public_key33_b64u: String,
    /// SigningWorker compressed secp256k1 public key in unpadded base64url.
    pub server_public_key33_b64u: String,
    /// Threshold compressed secp256k1 public key in unpadded base64url.
    pub threshold_public_key33_b64u: String,
    /// Ethereum address bytes in unpadded base64url.
    pub ethereum_address20_b64u: String,
    /// Client-share retry counter.
    pub client_share_retry_counter: u32,
    /// Server-share retry counter.
    pub server_share_retry_counter: u32,
}

/// Validated public ECDSA identity bound to one stable context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPublicIdentityV1 {
    input: EcdsaPublicIdentityInputV1,
    context_binding: [u8; 32],
}

impl EcdsaPublicIdentityV1 {
    /// Parses a public identity and binds it to the exact stable context.
    pub fn new(
        context: &EcdsaStableKeyContextV1,
        input: EcdsaPublicIdentityInputV1,
    ) -> Result<Self, EcdsaClientProtocolError> {
        let context_binding = decode_fixed::<32>(&input.context_binding_b64u)?;
        if context_binding != context.binding_digest()? {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        validate_compressed_public_key(&input.derivation_client_share_public_key33_b64u)?;
        validate_compressed_public_key(&input.server_public_key33_b64u)?;
        validate_compressed_public_key(&input.threshold_public_key33_b64u)?;
        decode_fixed::<20>(&input.ethereum_address20_b64u)?;
        Ok(Self {
            input,
            context_binding,
        })
    }

    /// Returns the context-binding digest string.
    pub fn context_binding_b64u(&self) -> &str {
        &self.input.context_binding_b64u
    }

    /// Returns the client compressed public key.
    pub fn derivation_client_share_public_key33_b64u(&self) -> &str {
        &self.input.derivation_client_share_public_key33_b64u
    }

    /// Returns the SigningWorker compressed public key.
    pub fn server_public_key33_b64u(&self) -> &str {
        &self.input.server_public_key33_b64u
    }

    /// Returns the threshold compressed public key.
    pub fn threshold_public_key33_b64u(&self) -> &str {
        &self.input.threshold_public_key33_b64u
    }

    /// Returns the Ethereum address bytes.
    pub fn ethereum_address20_b64u(&self) -> &str {
        &self.input.ethereum_address20_b64u
    }

    /// Returns the client-share retry counter.
    pub fn client_share_retry_counter(&self) -> u32 {
        self.input.client_share_retry_counter
    }

    /// Returns the server-share retry counter.
    pub fn server_share_retry_counter(&self) -> u32 {
        self.input.server_share_retry_counter
    }

    /// Returns canonical backend-compatible public-identity bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut output = Vec::new();
        push_bytes(&mut output, PUBLIC_IDENTITY_VERSION_V1);
        push_bytes(&mut output, self.input.context_binding_b64u.as_bytes());
        push_bytes(
            &mut output,
            self.input
                .derivation_client_share_public_key33_b64u
                .as_bytes(),
        );
        push_bytes(&mut output, self.input.server_public_key33_b64u.as_bytes());
        push_bytes(
            &mut output,
            self.input.threshold_public_key33_b64u.as_bytes(),
        );
        push_bytes(&mut output, self.input.ethereum_address20_b64u.as_bytes());
        output.extend_from_slice(&self.input.client_share_retry_counter.to_be_bytes());
        output.extend_from_slice(&self.input.server_share_retry_counter.to_be_bytes());
        output
    }

    fn validate_for_context(
        &self,
        context: &EcdsaStableKeyContextV1,
    ) -> Result<(), EcdsaClientProtocolError> {
        if self.context_binding == context.binding_digest()? {
            return Ok(());
        }
        Err(EcdsaClientProtocolError::InvalidShape)
    }
}

/// Recipient class for post-registration output proof bundles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaPostRegistrationRecipientV1 {
    /// Export/recovery proof bundles encrypted to the client.
    ClientProofBundles {
        /// Client ephemeral X25519 public key.
        client_ephemeral_public_key: String,
    },
    /// Refresh proof bundles encrypted to the selected SigningWorker.
    SigningWorkerActivation {
        /// SigningWorker ephemeral X25519 public key.
        signing_worker_ephemeral_public_key: String,
    },
}

impl EcdsaPostRegistrationRecipientV1 {
    fn public_key(&self) -> &str {
        match self {
            Self::ClientProofBundles {
                client_ephemeral_public_key,
            } => client_ephemeral_public_key,
            Self::SigningWorkerActivation {
                signing_worker_ephemeral_public_key,
            } => signing_worker_ephemeral_public_key,
        }
    }
}

/// Ceremony-specific authorization, replay nonce, and refresh epochs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcdsaPostRegistrationOperationV1 {
    /// Explicit export authorization.
    ExplicitExport {
        /// Fresh export authorization digest in unpadded base64url.
        authorization_digest_b64u: String,
        /// Export replay nonce.
        nonce: String,
    },
    /// Recovery authorization.
    Recovery {
        /// Fresh recovery authorization digest in unpadded base64url.
        authorization_digest_b64u: String,
        /// Recovery replay nonce.
        nonce: String,
    },
    /// SigningWorker activation refresh authorization.
    ActivationRefresh {
        /// Fresh refresh authorization digest in unpadded base64url.
        authorization_digest_b64u: String,
        /// Refresh replay nonce.
        nonce: String,
        /// Currently active activation epoch.
        previous_activation_epoch: String,
        /// Next activation epoch installed by this ceremony.
        next_activation_epoch: String,
    },
}

impl EcdsaPostRegistrationOperationV1 {
    fn ceremony(&self) -> EcdsaPostRegistrationCeremonyV1 {
        match self {
            Self::ExplicitExport { .. } => EcdsaPostRegistrationCeremonyV1::ExplicitExport,
            Self::Recovery { .. } => EcdsaPostRegistrationCeremonyV1::Recovery,
            Self::ActivationRefresh { .. } => EcdsaPostRegistrationCeremonyV1::ActivationRefresh,
        }
    }

    fn authorization_digest_b64u(&self) -> &str {
        match self {
            Self::ExplicitExport {
                authorization_digest_b64u,
                ..
            }
            | Self::Recovery {
                authorization_digest_b64u,
                ..
            }
            | Self::ActivationRefresh {
                authorization_digest_b64u,
                ..
            } => authorization_digest_b64u,
        }
    }

    fn nonce(&self) -> &str {
        match self {
            Self::ExplicitExport { nonce, .. }
            | Self::Recovery { nonce, .. }
            | Self::ActivationRefresh { nonce, .. } => nonce,
        }
    }
}

/// Validated fields used to construct one strict post-registration header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPostRegistrationHeaderInputV1 {
    /// Stable ECDSA application context.
    pub context: EcdsaStableKeyContextV1,
    /// Exact ceremony lifecycle.
    pub lifecycle: EcdsaPostRegistrationLifecycleV1,
    /// Stable ECDSA public identity.
    pub public_identity: EcdsaPublicIdentityV1,
    /// Selected strict all(2) signer set.
    pub signer_set: EcdsaRegistrationSignerSetV1,
    /// Router identity bound into the transcript.
    pub router_id: String,
    /// Client or operator identity bound into the transcript.
    pub client_id: String,
    /// Exact output recipient class.
    pub recipient: EcdsaPostRegistrationRecipientV1,
    /// Ceremony-specific authorization and replay fields.
    pub operation: EcdsaPostRegistrationOperationV1,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

/// Canonical explicit-export, recovery, or activation-refresh header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPostRegistrationHeaderV1 {
    input: EcdsaPostRegistrationHeaderInputV1,
}

impl EcdsaPostRegistrationHeaderV1 {
    /// Creates a strict header after validating all cross-branch bindings.
    pub fn new(
        input: EcdsaPostRegistrationHeaderInputV1,
    ) -> Result<Self, EcdsaClientProtocolError> {
        if input.lifecycle.ceremony != input.operation.ceremony()
            || input.lifecycle.signer_set_id != input.signer_set.signer_set_id()
            || input.lifecycle.selected_server_id != input.signer_set.selected_server().server_id
            || input.expires_at_ms == 0
        {
            return Err(EcdsaClientProtocolError::InvalidShape);
        }
        input.public_identity.validate_for_context(&input.context)?;
        require_ascii_fields(&[
            &input.router_id,
            &input.client_id,
            input.recipient.public_key(),
            input.operation.nonce(),
        ])?;
        decode_x25519_public_key(input.recipient.public_key())?;
        decode_fixed::<32>(input.operation.authorization_digest_b64u())?;
        validate_recipient_branch(input.lifecycle.ceremony, &input.recipient)?;
        validate_refresh_epochs(&input.lifecycle, &input.operation)?;
        Ok(Self { input })
    }

    /// Returns the ceremony branch.
    pub fn ceremony(&self) -> EcdsaPostRegistrationCeremonyV1 {
        self.input.lifecycle.ceremony
    }

    /// Returns the stable context.
    pub fn context(&self) -> &EcdsaStableKeyContextV1 {
        &self.input.context
    }

    /// Returns the exact lifecycle.
    pub fn lifecycle(&self) -> &EcdsaPostRegistrationLifecycleV1 {
        &self.input.lifecycle
    }

    /// Returns the stable public identity.
    pub fn public_identity(&self) -> &EcdsaPublicIdentityV1 {
        &self.input.public_identity
    }

    /// Returns the selected signer set.
    pub fn signer_set(&self) -> &EcdsaRegistrationSignerSetV1 {
        &self.input.signer_set
    }

    /// Returns the Router identity.
    pub fn router_id(&self) -> &str {
        &self.input.router_id
    }

    /// Returns the client or operator identity.
    pub fn client_id(&self) -> &str {
        &self.input.client_id
    }

    /// Returns the exact output recipient.
    pub fn recipient(&self) -> &EcdsaPostRegistrationRecipientV1 {
        &self.input.recipient
    }

    /// Returns ceremony authorization and replay fields.
    pub fn operation(&self) -> &EcdsaPostRegistrationOperationV1 {
        &self.input.operation
    }

    /// Returns request expiry.
    pub fn expires_at_ms(&self) -> u64 {
        self.input.expires_at_ms
    }

    /// Returns canonical backend-compatible pre-envelope header bytes.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        let mut output = Vec::new();
        push_bytes(&mut output, self.ceremony().header_version());
        push_bytes(&mut output, &self.input.context.canonical_bytes()?);
        push_lifecycle(&mut output, &self.input.lifecycle);
        push_bytes(&mut output, &self.input.public_identity.canonical_bytes());
        push_signer_set(&mut output, &self.input.signer_set);
        push_bytes(&mut output, self.input.router_id.as_bytes());
        push_bytes(&mut output, self.input.client_id.as_bytes());
        push_bytes(&mut output, self.input.recipient.public_key().as_bytes());
        push_bytes(
            &mut output,
            self.input.operation.authorization_digest_b64u().as_bytes(),
        );
        push_bytes(&mut output, self.input.operation.nonce().as_bytes());
        if let EcdsaPostRegistrationOperationV1::ActivationRefresh {
            previous_activation_epoch,
            next_activation_epoch,
            ..
        } = &self.input.operation
        {
            push_bytes(&mut output, previous_activation_epoch.as_bytes());
            push_bytes(&mut output, next_activation_epoch.as_bytes());
        }
        output.extend_from_slice(&self.input.expires_at_ms.to_be_bytes());
        Ok(output)
    }

    /// Returns the pre-envelope header digest.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        sha256(&self.canonical_bytes()?)
    }

    /// Returns the canonical threshold-PRF transcript digest.
    pub fn transcript_digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        let mut context = Vec::new();
        push_bytes(&mut context, DERIVATION_CONTEXT_VERSION_V1);
        push_bytes(
            &mut context,
            self.input.lifecycle.ceremony.primitive_kind().as_bytes(),
        );
        push_bytes(&mut context, KEY_SCOPE_V1.as_bytes());
        push_bytes(&mut context, self.input.lifecycle.account_id.as_bytes());
        push_bytes(
            &mut context,
            self.input
                .public_identity
                .threshold_public_key33_b64u()
                .as_bytes(),
        );
        push_bytes(
            &mut context,
            self.input.lifecycle.root_share_epoch.as_bytes(),
        );
        push_bytes(&mut context, self.input.lifecycle.lifecycle_id.as_bytes());

        let mut transcript = Vec::new();
        push_bytes(&mut transcript, DERIVATION_TRANSCRIPT_VERSION_V1);
        push_bytes(&mut transcript, &context);
        push_bytes(&mut transcript, self.input.router_id.as_bytes());
        push_bytes(
            &mut transcript,
            self.input.signer_set.signer_set_id().as_bytes(),
        );
        push_bytes(&mut transcript, b"all(2)");
        push_bytes(&mut transcript, b"2");
        push_transcript_signer(&mut transcript, 0, self.input.signer_set.signer_a());
        push_transcript_signer(&mut transcript, 1, self.input.signer_set.signer_b());
        push_bytes(
            &mut transcript,
            self.input.signer_set.selected_server().server_id.as_bytes(),
        );
        push_bytes(
            &mut transcript,
            self.input
                .signer_set
                .selected_server()
                .recipient_encryption_key
                .as_bytes(),
        );
        push_bytes(&mut transcript, self.input.client_id.as_bytes());
        push_bytes(
            &mut transcript,
            self.input.recipient.public_key().as_bytes(),
        );
        sha256(&transcript)
    }

    /// Builds exact role-specific envelope AAD.
    pub fn role_aad(
        &self,
        role: EcdsaDeriverRoleV1,
    ) -> Result<EcdsaRoleEnvelopeAadV1, EcdsaClientProtocolError> {
        let recipient = match role {
            EcdsaDeriverRoleV1::A => self.input.signer_set.signer_a().clone(),
            EcdsaDeriverRoleV1::B => self.input.signer_set.signer_b().clone(),
        };
        Ok(EcdsaRoleEnvelopeAadV1 {
            lifecycle_id: self.input.lifecycle.lifecycle_id.clone(),
            work_kind: self.ceremony().work_kind().to_owned(),
            primitive_request_kind: self.ceremony().primitive_kind().to_owned(),
            signer_set_id: self.input.signer_set.signer_set_id().to_owned(),
            recipient,
            selected_server: self.input.signer_set.selected_server().clone(),
            transcript_digest: self.transcript_digest()?,
            router_request_digest: self.threshold_request_context_digest()?,
            expires_at_ms: self.input.expires_at_ms,
        })
    }

    fn threshold_request_context_digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        let mut output = Vec::new();
        push_bytes(&mut output, THRESHOLD_REQUEST_CONTEXT_VERSION_V1);
        push_bytes(&mut output, b"v1");
        push_bytes(&mut output, self.input.operation.nonce().as_bytes());
        output.extend_from_slice(&self.input.expires_at_ms.to_be_bytes());
        push_lifecycle(&mut output, &self.input.lifecycle);
        push_threshold_signer_set(&mut output, &self.input.signer_set);
        push_bytes(&mut output, KEY_SCOPE_V1.as_bytes());
        push_bytes(
            &mut output,
            self.input
                .public_identity
                .threshold_public_key33_b64u()
                .as_bytes(),
        );
        push_bytes(&mut output, self.input.router_id.as_bytes());
        push_bytes(&mut output, self.input.client_id.as_bytes());
        push_bytes(&mut output, self.input.recipient.public_key().as_bytes());
        sha256(&output)
    }

    fn deriver_plaintext(
        &self,
        role: EcdsaDeriverRoleV1,
        aad_digest: [u8; 32],
    ) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        let signer = match role {
            EcdsaDeriverRoleV1::A => self.input.signer_set.signer_a(),
            EcdsaDeriverRoleV1::B => self.input.signer_set.signer_b(),
        };
        let mut output = Vec::new();
        push_bytes(&mut output, DERIVER_PLAINTEXT_VERSION_V1);
        push_bytes(&mut output, self.ceremony().request_kind().as_bytes());
        push_bytes(&mut output, self.ceremony().output_kind().as_bytes());
        push_bytes(&mut output, &self.input.context.canonical_bytes()?);
        push_lifecycle(&mut output, &self.input.lifecycle);
        push_signer_set(&mut output, &self.input.signer_set);
        push_signer_identity(&mut output, signer);
        push_bytes(&mut output, self.input.router_id.as_bytes());
        push_bytes(&mut output, self.input.client_id.as_bytes());
        push_bytes(&mut output, self.input.recipient.public_key().as_bytes());
        output.extend_from_slice(&self.digest()?);
        output.extend_from_slice(&aad_digest);
        output.extend_from_slice(&self.input.expires_at_ms.to_be_bytes());
        push_bytes(&mut output, &self.input.public_identity.canonical_bytes());
        push_bytes(
            &mut output,
            self.input.operation.authorization_digest_b64u().as_bytes(),
        );
        push_bytes(&mut output, self.input.operation.nonce().as_bytes());
        if let EcdsaPostRegistrationOperationV1::ActivationRefresh {
            previous_activation_epoch,
            next_activation_epoch,
            ..
        } = &self.input.operation
        {
            push_bytes(&mut output, previous_activation_epoch.as_bytes());
            push_bytes(&mut output, next_activation_epoch.as_bytes());
        }
        Ok(output)
    }
}

/// Complete strict post-registration request with sealed A/B envelopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPostRegistrationRequestV1 {
    header: EcdsaPostRegistrationHeaderV1,
    deriver_a_envelope: EcdsaRegistrationEncryptedEnvelopeV1,
    deriver_b_envelope: EcdsaRegistrationEncryptedEnvelopeV1,
}

impl EcdsaPostRegistrationRequestV1 {
    /// Returns the canonical public header.
    pub fn header(&self) -> &EcdsaPostRegistrationHeaderV1 {
        &self.header
    }

    /// Returns the Deriver A envelope.
    pub fn deriver_a_envelope(&self) -> &EcdsaRegistrationEncryptedEnvelopeV1 {
        &self.deriver_a_envelope
    }

    /// Returns the Deriver B envelope.
    pub fn deriver_b_envelope(&self) -> &EcdsaRegistrationEncryptedEnvelopeV1 {
        &self.deriver_b_envelope
    }

    /// Returns canonical request bytes including both envelope digests.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EcdsaClientProtocolError> {
        let mut output = self.header.canonical_bytes()?;
        output.extend_from_slice(&self.deriver_a_envelope.digest()?);
        output.extend_from_slice(&self.deriver_b_envelope.digest()?);
        Ok(output)
    }

    /// Returns the canonical request digest.
    pub fn digest(&self) -> Result<[u8; 32], EcdsaClientProtocolError> {
        sha256(&self.canonical_bytes()?)
    }
}

/// Builds and seals one explicit-export, recovery, or activation-refresh request.
pub fn build_ecdsa_post_registration_request_v1(
    header: EcdsaPostRegistrationHeaderV1,
    recipient_keys: EcdsaRegistrationRecipientKeysV1,
    seal_seeds: EcdsaRegistrationSealSeedsV1,
) -> Result<EcdsaPostRegistrationRequestV1, EcdsaClientProtocolError> {
    validate_recipient_key(&recipient_keys.deriver_a, header.signer_set().signer_a())?;
    validate_recipient_key(&recipient_keys.deriver_b, header.signer_set().signer_b())?;
    let deriver_a_envelope = seal_role(&header, &recipient_keys.deriver_a, seal_seeds.deriver_a)?;
    let deriver_b_envelope = seal_role(&header, &recipient_keys.deriver_b, seal_seeds.deriver_b)?;
    Ok(EcdsaPostRegistrationRequestV1 {
        header,
        deriver_a_envelope,
        deriver_b_envelope,
    })
}

fn seal_role(
    header: &EcdsaPostRegistrationHeaderV1,
    recipient_key: &EcdsaSignerEnvelopePublicKeyV1,
    seed: [u8; 32],
) -> Result<EcdsaRegistrationEncryptedEnvelopeV1, EcdsaClientProtocolError> {
    let aad = header.role_aad(recipient_key.role)?;
    let aad_digest = aad.digest()?;
    let plaintext = header.deriver_plaintext(recipient_key.role, aad_digest)?;
    let payload = seal_ecdsa_signer_envelope_v1(recipient_key, &aad, &plaintext, seed)?;
    Ok(EcdsaRegistrationEncryptedEnvelopeV1 {
        recipient_role: recipient_key.role,
        header_digest: header.digest()?,
        aad_digest,
        ciphertext: payload.canonical_bytes()?,
    })
}

fn validate_recipient_branch(
    ceremony: EcdsaPostRegistrationCeremonyV1,
    recipient: &EcdsaPostRegistrationRecipientV1,
) -> Result<(), EcdsaClientProtocolError> {
    match (ceremony, recipient) {
        (
            EcdsaPostRegistrationCeremonyV1::ExplicitExport
            | EcdsaPostRegistrationCeremonyV1::Recovery,
            EcdsaPostRegistrationRecipientV1::ClientProofBundles { .. },
        )
        | (
            EcdsaPostRegistrationCeremonyV1::ActivationRefresh,
            EcdsaPostRegistrationRecipientV1::SigningWorkerActivation { .. },
        ) => Ok(()),
        _ => Err(EcdsaClientProtocolError::InvalidShape),
    }
}

fn validate_refresh_epochs(
    lifecycle: &EcdsaPostRegistrationLifecycleV1,
    operation: &EcdsaPostRegistrationOperationV1,
) -> Result<(), EcdsaClientProtocolError> {
    match operation {
        EcdsaPostRegistrationOperationV1::ActivationRefresh {
            previous_activation_epoch,
            next_activation_epoch,
            ..
        } => {
            require_ascii_fields(&[previous_activation_epoch, next_activation_epoch])?;
            if previous_activation_epoch == next_activation_epoch
                || lifecycle.root_share_epoch != *next_activation_epoch
            {
                return Err(EcdsaClientProtocolError::InvalidShape);
            }
            Ok(())
        }
        EcdsaPostRegistrationOperationV1::ExplicitExport { .. }
        | EcdsaPostRegistrationOperationV1::Recovery { .. } => Ok(()),
    }
}

fn push_lifecycle(output: &mut Vec<u8>, lifecycle: &EcdsaPostRegistrationLifecycleV1) {
    push_bytes(output, lifecycle.lifecycle_id.as_bytes());
    push_bytes(output, lifecycle.ceremony.work_kind().as_bytes());
    push_bytes(output, lifecycle.ceremony.primitive_kind().as_bytes());
    push_bytes(output, lifecycle.root_share_epoch.as_bytes());
    push_bytes(output, lifecycle.account_id.as_bytes());
    push_bytes(output, lifecycle.session_id.as_bytes());
    push_bytes(output, lifecycle.signer_set_id.as_bytes());
    push_bytes(output, lifecycle.selected_server_id.as_bytes());
}

fn push_transcript_signer(output: &mut Vec<u8>, index: u8, signer: &super::EcdsaSignerIdentityV1) {
    push_bytes(output, index.to_string().as_bytes());
    push_signer_identity(output, signer);
}

fn push_threshold_signer_set(output: &mut Vec<u8>, signer_set: &EcdsaRegistrationSignerSetV1) {
    push_bytes(output, signer_set.signer_set_id().as_bytes());
    push_bytes(output, b"all_2");
    push_signer_identity(output, signer_set.signer_a());
    push_signer_identity(output, signer_set.signer_b());
    push_bytes(output, signer_set.selected_server().server_id.as_bytes());
    push_bytes(output, signer_set.selected_server().key_epoch.as_bytes());
    push_bytes(
        output,
        signer_set
            .selected_server()
            .recipient_encryption_key
            .as_bytes(),
    );
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], EcdsaClientProtocolError> {
    Base64UrlUnpadded::decode_vec(value)
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)?
        .try_into()
        .map_err(|_| EcdsaClientProtocolError::InvalidShape)
}

fn validate_compressed_public_key(value: &str) -> Result<(), EcdsaClientProtocolError> {
    let bytes = decode_fixed::<33>(value)?;
    if matches!(bytes[0], 0x02 | 0x03) {
        return Ok(());
    }
    Err(EcdsaClientProtocolError::InvalidShape)
}
