use crate::derivation::{PublicDigest32, Role};
use crate::protocol::ecdsa_threshold_prf_request::{
    EcdsaThresholdPrfRequestContextV1, EcdsaThresholdPrfRequestV1,
};
use crate::protocol::envelope::{role_encrypted_envelope_digest_v1, RoleEncryptedEnvelopeV1};
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::gate::ExpensiveWorkKindV1;
use crate::protocol::identity::{ServerIdentityV1, SignerIdentityV1, SignerSetV1};
use crate::protocol::lifecycle::LifecycleScopeV1;
use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Frozen Router A/B ECDSA-HSS protocol id.
pub const ROUTER_AB_ECDSA_HSS_SECP256K1_PROTOCOL_VERSION_V1: &str =
    "router_ab_ecdsa_hss_secp256k1_v1";
/// ECDSA-HSS key scope supported by the first Router A/B ECDSA release.
pub const ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1: &str = "evm-family";

const ECDSA_HSS_CONTEXT_DOMAIN_TAG_V1: &[u8] = b"ecdsa-hss:context:v4";
const ECDSA_HSS_CONTEXT_BINDING_DOMAIN_V1: &[u8] = b"ecdsa-hss:role-local:v2:context-binding";
const ECDSA_HSS_SCHEME_ID_V1: &str = "ecdsa-hss-v4";
const ECDSA_HSS_CURVE_V1: &str = "secp256k1";
const ECDSA_HSS_CONTEXT_FIELD_BYTES_V1: u8 = 0x01;
const ECDSA_HSS_PARTICIPANT_IDS_V1: [u16; 2] = [1, 2];
const ROUTER_AB_ECDSA_HSS_PUBLIC_IDENTITY_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/public-identity/v1";
const ROUTER_AB_ECDSA_HSS_REGISTRATION_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/registration-request/v1";
const ROUTER_AB_ECDSA_HSS_EXPORT_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/export-request/v1";
const ROUTER_AB_ECDSA_HSS_RECOVERY_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/recovery-request/v1";
const ROUTER_AB_ECDSA_HSS_REFRESH_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/refresh-request/v1";
const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_SCOPE_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/normal-signing-scope/v1";
const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/normal-signing-request/v1";
const ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_FINALIZE_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/normal-signing-finalize-request/v1";
const ROUTER_AB_ECDSA_HSS_DERIVER_ENVELOPE_PLAINTEXT_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-hss/deriver-envelope-plaintext/v1";

/// ECDSA-HSS Router A/B operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbEcdsaHssRequestKindV1 {
    /// Initial registration/bootstrap that activates SigningWorker state.
    RegistrationBootstrap,
    /// Explicit user-authorized key export.
    ExplicitKeyExport,
    /// Recovery ceremony for an existing ECDSA-HSS identity.
    Recovery,
    /// SigningWorker activation refresh after Deriver A/B root rotation.
    Refresh,
    /// Normal ECDSA signing through an active SigningWorker state.
    NormalSigning,
}

impl RouterAbEcdsaHssRequestKindV1 {
    /// Returns the canonical request kind label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegistrationBootstrap => "registration_bootstrap",
            Self::ExplicitKeyExport => "explicit_key_export",
            Self::Recovery => "recovery",
            Self::Refresh => "refresh",
            Self::NormalSigning => "normal_signing",
        }
    }
}

/// Recipient/output class for ECDSA-HSS Router A/B material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbEcdsaHssOutputKindV1 {
    /// Material encrypted to the active SigningWorker for normal signing.
    SigningWorkerActivation,
    /// Material encrypted to the authorized client export runtime.
    ClientExport,
}

impl RouterAbEcdsaHssOutputKindV1 {
    /// Returns the canonical output kind label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SigningWorkerActivation => "signing_worker_activation",
            Self::ClientExport => "client_export",
        }
    }
}

/// Public metadata decrypted from an ECDSA-HSS Deriver A/B envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request_kind", rename_all = "snake_case")]
pub enum RouterAbEcdsaHssDeriverEnvelopePlaintextV1 {
    /// Registration/bootstrap material for SigningWorker activation.
    RegistrationBootstrap(RouterAbEcdsaHssDeriverRegistrationEnvelopePlaintextV1),
    /// Explicit export material for the client export runtime.
    ExplicitKeyExport(RouterAbEcdsaHssDeriverExportEnvelopePlaintextV1),
    /// Recovery material for the client recovery runtime.
    Recovery(RouterAbEcdsaHssDeriverRecoveryEnvelopePlaintextV1),
    /// Refresh material for the next SigningWorker activation epoch.
    Refresh(RouterAbEcdsaHssDeriverRefreshEnvelopePlaintextV1),
}

impl RouterAbEcdsaHssDeriverEnvelopePlaintextV1 {
    /// Builds registration plaintext for one Deriver envelope.
    pub fn registration_for_request(
        request: &RouterAbEcdsaHssRegistrationBootstrapRequestV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let plaintext = RouterAbEcdsaHssDeriverRegistrationEnvelopePlaintextV1 {
            common: RouterAbEcdsaHssDeriverEnvelopeCommonV1::from_parts(
                request.context.clone(),
                request.lifecycle.clone(),
                request.signer_set.clone(),
                recipient_role,
                request.router_id.clone(),
                request.client_id.clone(),
                request.client_ephemeral_public_key.clone(),
                request.request_digest()?,
                aad_digest,
                request.expires_at_ms,
            )?,
            output_kind: RouterAbEcdsaHssOutputKindV1::SigningWorkerActivation,
            client_public_key33_b64u: request.client_public_key33_b64u.clone(),
            client_share_retry_counter: request.client_share_retry_counter,
        };
        plaintext.validate()?;
        Ok(Self::RegistrationBootstrap(plaintext))
    }

    /// Builds explicit-export plaintext for one Deriver envelope.
    pub fn export_for_request(
        request: &RouterAbEcdsaHssExplicitExportRequestV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let plaintext = RouterAbEcdsaHssDeriverExportEnvelopePlaintextV1 {
            common: RouterAbEcdsaHssDeriverEnvelopeCommonV1::from_parts(
                request.context.clone(),
                request.lifecycle.clone(),
                request.signer_set.clone(),
                recipient_role,
                request.router_id.clone(),
                request.client_id.clone(),
                request.client_ephemeral_public_key.clone(),
                request.request_digest()?,
                aad_digest,
                request.expires_at_ms,
            )?,
            output_kind: RouterAbEcdsaHssOutputKindV1::ClientExport,
            public_identity: request.public_identity.clone(),
            export_authorization_digest_b64u: request.export_authorization_digest_b64u.clone(),
            export_nonce: request.export_nonce.clone(),
        };
        plaintext.validate()?;
        Ok(Self::ExplicitKeyExport(plaintext))
    }

    /// Builds recovery plaintext for one Deriver envelope.
    pub fn recovery_for_request(
        request: &RouterAbEcdsaHssRecoveryRequestV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let plaintext = RouterAbEcdsaHssDeriverRecoveryEnvelopePlaintextV1 {
            common: RouterAbEcdsaHssDeriverEnvelopeCommonV1::from_parts(
                request.context.clone(),
                request.lifecycle.clone(),
                request.signer_set.clone(),
                recipient_role,
                request.router_id.clone(),
                request.client_id.clone(),
                request.client_ephemeral_public_key.clone(),
                request.request_digest()?,
                aad_digest,
                request.expires_at_ms,
            )?,
            output_kind: RouterAbEcdsaHssOutputKindV1::ClientExport,
            public_identity: request.public_identity.clone(),
            recovery_authorization_digest_b64u: request.recovery_authorization_digest_b64u.clone(),
            recovery_nonce: request.recovery_nonce.clone(),
        };
        plaintext.validate()?;
        Ok(Self::Recovery(plaintext))
    }

    /// Builds activation-refresh plaintext for one Deriver envelope.
    pub fn refresh_for_request(
        request: &RouterAbEcdsaHssActivationRefreshRequestV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let plaintext = RouterAbEcdsaHssDeriverRefreshEnvelopePlaintextV1 {
            common: RouterAbEcdsaHssDeriverEnvelopeCommonV1::from_parts(
                request.context.clone(),
                request.lifecycle.clone(),
                request.signer_set.clone(),
                recipient_role,
                request.router_id.clone(),
                request.client_id.clone(),
                request.signing_worker_ephemeral_public_key.clone(),
                request.request_digest()?,
                aad_digest,
                request.expires_at_ms,
            )?,
            output_kind: RouterAbEcdsaHssOutputKindV1::SigningWorkerActivation,
            public_identity: request.public_identity.clone(),
            refresh_authorization_digest_b64u: request.refresh_authorization_digest_b64u.clone(),
            refresh_nonce: request.refresh_nonce.clone(),
            previous_activation_epoch: request.previous_activation_epoch.clone(),
            next_activation_epoch: request.next_activation_epoch.clone(),
        };
        plaintext.validate()?;
        Ok(Self::Refresh(plaintext))
    }

    /// Returns the ECDSA-HSS request kind represented by this plaintext.
    pub fn request_kind(&self) -> RouterAbEcdsaHssRequestKindV1 {
        match self {
            Self::RegistrationBootstrap(_) => RouterAbEcdsaHssRequestKindV1::RegistrationBootstrap,
            Self::ExplicitKeyExport(_) => RouterAbEcdsaHssRequestKindV1::ExplicitKeyExport,
            Self::Recovery(_) => RouterAbEcdsaHssRequestKindV1::Recovery,
            Self::Refresh(_) => RouterAbEcdsaHssRequestKindV1::Refresh,
        }
    }

    /// Returns the output class this Deriver plaintext may produce.
    pub fn output_kind(&self) -> RouterAbEcdsaHssOutputKindV1 {
        match self {
            Self::RegistrationBootstrap(plaintext) => plaintext.output_kind,
            Self::ExplicitKeyExport(plaintext) => plaintext.output_kind,
            Self::Recovery(plaintext) => plaintext.output_kind,
            Self::Refresh(plaintext) => plaintext.output_kind,
        }
    }

    /// Returns shared public Deriver envelope metadata.
    pub fn common(&self) -> &RouterAbEcdsaHssDeriverEnvelopeCommonV1 {
        match self {
            Self::RegistrationBootstrap(plaintext) => &plaintext.common,
            Self::ExplicitKeyExport(plaintext) => &plaintext.common,
            Self::Recovery(plaintext) => &plaintext.common,
            Self::Refresh(plaintext) => &plaintext.common,
        }
    }

    /// Validates this decrypted plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::RegistrationBootstrap(plaintext) => plaintext.validate(),
            Self::ExplicitKeyExport(plaintext) => plaintext.validate(),
            Self::Recovery(plaintext) => plaintext.validate(),
            Self::Refresh(plaintext) => plaintext.validate(),
        }
    }

    /// Validates this plaintext against the outer encrypted envelope metadata.
    pub fn validate_for_envelope(
        &self,
        envelope: &RoleEncryptedEnvelopeV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        envelope.validate()?;
        let common = self.common();
        if envelope.recipient_role != common.recipient_deriver.role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "ECDSA-HSS Deriver plaintext recipient role does not match envelope",
            ));
        }
        if envelope.aad_digest != common.aad_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "ECDSA-HSS Deriver plaintext AAD digest does not match envelope",
            ));
        }
        Ok(())
    }

    /// Returns canonical plaintext bytes for envelope encryption and audit digests.
    pub fn canonical_plaintext_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_HSS_DERIVER_ENVELOPE_PLAINTEXT_VERSION_V1,
        );
        push_len32(&mut out, self.request_kind().as_str().as_bytes());
        push_len32(&mut out, self.output_kind().as_str().as_bytes());
        push_deriver_envelope_common(&mut out, self.common())?;
        match self {
            Self::RegistrationBootstrap(plaintext) => {
                push_len32(&mut out, plaintext.client_public_key33_b64u.as_bytes());
                push_u32(&mut out, plaintext.client_share_retry_counter);
            }
            Self::ExplicitKeyExport(plaintext) => {
                push_len32(
                    &mut out,
                    &plaintext
                        .public_identity
                        .canonical_public_identity_bytes()?,
                );
                push_len32(
                    &mut out,
                    plaintext.export_authorization_digest_b64u.as_bytes(),
                );
                push_len32(&mut out, plaintext.export_nonce.as_bytes());
            }
            Self::Recovery(plaintext) => {
                push_len32(
                    &mut out,
                    &plaintext
                        .public_identity
                        .canonical_public_identity_bytes()?,
                );
                push_len32(
                    &mut out,
                    plaintext.recovery_authorization_digest_b64u.as_bytes(),
                );
                push_len32(&mut out, plaintext.recovery_nonce.as_bytes());
            }
            Self::Refresh(plaintext) => {
                push_len32(
                    &mut out,
                    &plaintext
                        .public_identity
                        .canonical_public_identity_bytes()?,
                );
                push_len32(
                    &mut out,
                    plaintext.refresh_authorization_digest_b64u.as_bytes(),
                );
                push_len32(&mut out, plaintext.refresh_nonce.as_bytes());
                push_len32(&mut out, plaintext.previous_activation_epoch.as_bytes());
                push_len32(&mut out, plaintext.next_activation_epoch.as_bytes());
            }
        }
        Ok(out)
    }

    /// Returns the digest of canonical plaintext bytes.
    pub fn plaintext_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_plaintext_bytes()?))
    }
}

/// Shared public fields bound into every ECDSA-HSS Deriver envelope plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssDeriverEnvelopeCommonV1 {
    /// Stable ECDSA-HSS context.
    pub context: RouterAbEcdsaHssStableKeyContextV1,
    /// Router lifecycle scope.
    pub lifecycle: LifecycleScopeV1,
    /// Router A/B signer set selected for this request.
    pub signer_set: SignerSetV1,
    /// Deriver identity allowed to decrypt this envelope.
    pub recipient_deriver: SignerIdentityV1,
    /// Router identity bound into the transcript.
    pub router_id: String,
    /// Client or operator identity bound into the transcript.
    pub client_id: String,
    /// Recipient public key slot from the originating public request.
    pub recipient_ephemeral_public_key: String,
    /// Digest of the originating public ECDSA-HSS request.
    pub request_digest: PublicDigest32,
    /// Digest of the associated data used to encrypt the outer role envelope.
    pub aad_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl RouterAbEcdsaHssDeriverEnvelopeCommonV1 {
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        context: RouterAbEcdsaHssStableKeyContextV1,
        lifecycle: LifecycleScopeV1,
        signer_set: SignerSetV1,
        recipient_role: Role,
        router_id: String,
        client_id: String,
        recipient_ephemeral_public_key: String,
        request_digest: PublicDigest32,
        aad_digest: PublicDigest32,
        expires_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        let recipient_deriver = recipient_deriver_for_role(&signer_set, recipient_role)?;
        let common = Self {
            context,
            lifecycle,
            signer_set,
            recipient_deriver,
            router_id,
            client_id,
            recipient_ephemeral_public_key,
            request_digest,
            aad_digest,
            expires_at_ms,
        };
        common.validate()?;
        Ok(common)
    }

    fn validate_for_work_kind(&self, expected: ExpensiveWorkKindV1) -> RouterAbProtocolResult<()> {
        self.validate()?;
        validate_lifecycle_work_kind("deriver_plaintext.lifecycle", &self.lifecycle, expected)
    }

    /// Validates shared Deriver envelope metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.lifecycle.validate()?;
        self.signer_set.validate()?;
        self.recipient_deriver.validate()?;
        validate_lifecycle_for_context(
            "deriver_plaintext.lifecycle",
            &self.lifecycle,
            &self.context,
        )?;
        require_ascii_non_empty("deriver_plaintext.router_id", &self.router_id)?;
        require_ascii_non_empty("deriver_plaintext.client_id", &self.client_id)?;
        require_ascii_non_empty(
            "deriver_plaintext.recipient_ephemeral_public_key",
            &self.recipient_ephemeral_public_key,
        )?;
        require_positive_ms("deriver_plaintext.expires_at_ms", self.expires_at_ms)?;
        let expected = recipient_deriver_for_role(&self.signer_set, self.recipient_deriver.role)?;
        if expected != self.recipient_deriver {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "ECDSA-HSS Deriver plaintext recipient does not match signer set",
            ));
        }
        if self.lifecycle.signer_set_id != self.signer_set.signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA-HSS Deriver plaintext lifecycle signer set does not match signer set",
            ));
        }
        if self.lifecycle.selected_server_id != self.signer_set.selected_server.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA-HSS Deriver plaintext lifecycle selected server does not match signer set",
            ));
        }
        Ok(())
    }
}

/// Registration/bootstrap Deriver plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssDeriverRegistrationEnvelopePlaintextV1 {
    /// Shared public Deriver envelope metadata.
    pub common: RouterAbEcdsaHssDeriverEnvelopeCommonV1,
    /// Registration/bootstrap must produce SigningWorker activation material.
    pub output_kind: RouterAbEcdsaHssOutputKindV1,
    /// Client compressed secp256k1 public key encoded as unpadded base64url.
    pub client_public_key33_b64u: String,
    /// Client share retry counter.
    pub client_share_retry_counter: u32,
}

impl RouterAbEcdsaHssDeriverRegistrationEnvelopePlaintextV1 {
    /// Validates registration/bootstrap Deriver plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.common
            .validate_for_work_kind(ExpensiveWorkKindV1::RegistrationPrepare)?;
        require_output_kind(
            "registration_deriver_plaintext.output_kind",
            self.output_kind,
            RouterAbEcdsaHssOutputKindV1::SigningWorkerActivation,
        )?;
        decode_secp256k1_public_key33_b64u(
            "registration_deriver_plaintext.client_public_key33_b64u",
            &self.client_public_key33_b64u,
        )?;
        Ok(())
    }
}

/// Explicit-export Deriver plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssDeriverExportEnvelopePlaintextV1 {
    /// Shared public Deriver envelope metadata.
    pub common: RouterAbEcdsaHssDeriverEnvelopeCommonV1,
    /// Explicit export must produce client-recipient export material.
    pub output_kind: RouterAbEcdsaHssOutputKindV1,
    /// Public identity being exported.
    pub public_identity: RouterAbEcdsaHssPublicIdentityV1,
    /// User-confirmed export authorization digest encoded as unpadded base64url.
    pub export_authorization_digest_b64u: String,
    /// Request-scoped export replay nonce.
    pub export_nonce: String,
}

impl RouterAbEcdsaHssDeriverExportEnvelopePlaintextV1 {
    /// Validates explicit-export Deriver plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.common
            .validate_for_work_kind(ExpensiveWorkKindV1::KeyExport)?;
        require_output_kind(
            "export_deriver_plaintext.output_kind",
            self.output_kind,
            RouterAbEcdsaHssOutputKindV1::ClientExport,
        )?;
        self.public_identity
            .validate_for_context(&self.common.context)?;
        decode_base64url_fixed_32(
            "export_deriver_plaintext.export_authorization_digest_b64u",
            &self.export_authorization_digest_b64u,
        )?;
        require_ascii_non_empty("export_deriver_plaintext.export_nonce", &self.export_nonce)
    }
}

/// Recovery Deriver plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssDeriverRecoveryEnvelopePlaintextV1 {
    /// Shared public Deriver envelope metadata.
    pub common: RouterAbEcdsaHssDeriverEnvelopeCommonV1,
    /// Recovery must produce client-recipient recovery/export material.
    pub output_kind: RouterAbEcdsaHssOutputKindV1,
    /// Public identity being recovered.
    pub public_identity: RouterAbEcdsaHssPublicIdentityV1,
    /// User-confirmed recovery authorization digest encoded as unpadded base64url.
    pub recovery_authorization_digest_b64u: String,
    /// Request-scoped recovery replay nonce.
    pub recovery_nonce: String,
}

impl RouterAbEcdsaHssDeriverRecoveryEnvelopePlaintextV1 {
    /// Validates recovery Deriver plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.common
            .validate_for_work_kind(ExpensiveWorkKindV1::Recovery)?;
        require_output_kind(
            "recovery_deriver_plaintext.output_kind",
            self.output_kind,
            RouterAbEcdsaHssOutputKindV1::ClientExport,
        )?;
        self.public_identity
            .validate_for_context(&self.common.context)?;
        decode_base64url_fixed_32(
            "recovery_deriver_plaintext.recovery_authorization_digest_b64u",
            &self.recovery_authorization_digest_b64u,
        )?;
        require_ascii_non_empty(
            "recovery_deriver_plaintext.recovery_nonce",
            &self.recovery_nonce,
        )
    }
}

/// Activation-refresh Deriver plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssDeriverRefreshEnvelopePlaintextV1 {
    /// Shared public Deriver envelope metadata.
    pub common: RouterAbEcdsaHssDeriverEnvelopeCommonV1,
    /// Refresh must produce SigningWorker activation material for the next epoch.
    pub output_kind: RouterAbEcdsaHssOutputKindV1,
    /// Public identity that must remain stable across refresh.
    pub public_identity: RouterAbEcdsaHssPublicIdentityV1,
    /// Authorization digest for the refresh operation.
    pub refresh_authorization_digest_b64u: String,
    /// Request-scoped refresh replay nonce.
    pub refresh_nonce: String,
    /// Activation epoch currently considered active by the Router.
    pub previous_activation_epoch: String,
    /// Activation epoch to be installed by the SigningWorker.
    pub next_activation_epoch: String,
}

impl RouterAbEcdsaHssDeriverRefreshEnvelopePlaintextV1 {
    /// Validates activation-refresh Deriver plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.common
            .validate_for_work_kind(ExpensiveWorkKindV1::ServerShareRefresh)?;
        require_output_kind(
            "refresh_deriver_plaintext.output_kind",
            self.output_kind,
            RouterAbEcdsaHssOutputKindV1::SigningWorkerActivation,
        )?;
        self.public_identity
            .validate_for_context(&self.common.context)?;
        decode_base64url_fixed_32(
            "refresh_deriver_plaintext.refresh_authorization_digest_b64u",
            &self.refresh_authorization_digest_b64u,
        )?;
        require_ascii_non_empty(
            "refresh_deriver_plaintext.refresh_nonce",
            &self.refresh_nonce,
        )?;
        require_ascii_non_empty(
            "refresh_deriver_plaintext.previous_activation_epoch",
            &self.previous_activation_epoch,
        )?;
        require_ascii_non_empty(
            "refresh_deriver_plaintext.next_activation_epoch",
            &self.next_activation_epoch,
        )?;
        if self.previous_activation_epoch == self.next_activation_epoch {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA-HSS Deriver refresh plaintext must advance activation epoch",
            ));
        }
        if self.common.lifecycle.root_share_epoch.as_str() != self.next_activation_epoch {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA-HSS Deriver refresh plaintext lifecycle root epoch must equal next activation epoch",
            ));
        }
        Ok(())
    }
}

/// Signature algorithm returned by the ECDSA-HSS digest-signing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbEcdsaHssSignatureSchemeV1 {
    /// Recoverable secp256k1 signature bytes: `r(32) || s(32) || recid(1)`.
    EcdsaSecp256k1RecoverableV1,
}

/// ECDSA-HSS stable context bound into registration, export, recovery, and refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssStableKeyContextV1 {
    /// SDK-owned application binding digest encoded as unpadded base64url.
    pub application_binding_digest_b64u: String,
}

impl RouterAbEcdsaHssStableKeyContextV1 {
    /// Creates a validated ECDSA-HSS stable key context.
    pub fn new(application_binding_digest_b64u: impl Into<String>) -> RouterAbProtocolResult<Self> {
        let context = Self {
            application_binding_digest_b64u: application_binding_digest_b64u.into(),
        };
        context.validate()?;
        Ok(context)
    }

    /// Validates context fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        decode_base64url_fixed_32(
            "context.application_binding_digest_b64u",
            &self.application_binding_digest_b64u,
        )?;
        Ok(())
    }

    /// Returns canonical context bytes for protocol binding.
    pub fn canonical_context_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        out.extend_from_slice(ECDSA_HSS_CONTEXT_DOMAIN_TAG_V1);
        push_ascii_u16(&mut out, ECDSA_HSS_SCHEME_ID_V1)?;
        push_ascii_u16(&mut out, ECDSA_HSS_CURVE_V1)?;
        out.extend_from_slice(&decode_base64url_fixed_32(
            "context.application_binding_digest_b64u",
            &self.application_binding_digest_b64u,
        )?);
        out.push(ECDSA_HSS_PARTICIPANT_IDS_V1.len() as u8);
        for participant_id in ECDSA_HSS_PARTICIPANT_IDS_V1 {
            out.extend_from_slice(&participant_id.to_be_bytes());
        }
        Ok(out)
    }

    /// Returns the context-binding digest.
    pub fn context_binding_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        let context_bytes = self.canonical_context_bytes()?;
        Ok(public_digest(&ecdsa_hss_context_binding_frame(
            &context_bytes,
        )?))
    }
}

/// Returns the active SigningWorker session id for one ECDSA-HSS activation epoch.
pub fn router_ab_ecdsa_hss_active_state_session_id_v1(
    ecdsa_threshold_key_id: &str,
    signing_root_id: &str,
    signing_root_version: &str,
    activation_epoch: &str,
) -> RouterAbProtocolResult<String> {
    require_ascii_non_empty("ecdsa_threshold_key_id", ecdsa_threshold_key_id)?;
    require_ascii_non_empty("signing_root_id", signing_root_id)?;
    require_ascii_non_empty("signing_root_version", signing_root_version)?;
    require_ascii_non_empty("activation_epoch", activation_epoch)?;
    Ok(format!(
        "{}:{}:{}:{}",
        ecdsa_threshold_key_id, signing_root_id, signing_root_version, activation_epoch
    ))
}

/// Public ECDSA identity produced by ECDSA-HSS registration/activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssPublicIdentityV1 {
    /// Context-binding digest encoded as unpadded base64url.
    pub context_binding_b64u: String,
    /// Client compressed secp256k1 public key encoded as unpadded base64url.
    pub client_public_key33_b64u: String,
    /// Server/SigningWorker compressed secp256k1 public key encoded as unpadded base64url.
    pub server_public_key33_b64u: String,
    /// Threshold compressed secp256k1 public key encoded as unpadded base64url.
    pub threshold_public_key33_b64u: String,
    /// Ethereum address bytes encoded as unpadded base64url.
    pub ethereum_address20_b64u: String,
    /// Retry counter used by the client-side share derivation.
    pub client_share_retry_counter: u32,
    /// Retry counter used by the server-side share derivation.
    pub server_share_retry_counter: u32,
}

impl RouterAbEcdsaHssPublicIdentityV1 {
    /// Creates a validated public identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context_binding_b64u: impl Into<String>,
        client_public_key33_b64u: impl Into<String>,
        server_public_key33_b64u: impl Into<String>,
        threshold_public_key33_b64u: impl Into<String>,
        ethereum_address20_b64u: impl Into<String>,
        client_share_retry_counter: u32,
        server_share_retry_counter: u32,
    ) -> RouterAbProtocolResult<Self> {
        let identity = Self {
            context_binding_b64u: context_binding_b64u.into(),
            client_public_key33_b64u: client_public_key33_b64u.into(),
            server_public_key33_b64u: server_public_key33_b64u.into(),
            threshold_public_key33_b64u: threshold_public_key33_b64u.into(),
            ethereum_address20_b64u: ethereum_address20_b64u.into(),
            client_share_retry_counter,
            server_share_retry_counter,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Validates public key/address encoding and required counters.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        decode_base64url_fixed_32(
            "public_identity.context_binding_b64u",
            &self.context_binding_b64u,
        )?;
        decode_secp256k1_public_key33_b64u(
            "public_identity.client_public_key33_b64u",
            &self.client_public_key33_b64u,
        )?;
        decode_secp256k1_public_key33_b64u(
            "public_identity.server_public_key33_b64u",
            &self.server_public_key33_b64u,
        )?;
        decode_secp256k1_public_key33_b64u(
            "public_identity.threshold_public_key33_b64u",
            &self.threshold_public_key33_b64u,
        )?;
        decode_base64url_fixed_20(
            "public_identity.ethereum_address20_b64u",
            &self.ethereum_address20_b64u,
        )?;
        Ok(())
    }

    /// Validates that the identity belongs to this stable key context.
    pub fn validate_for_context(
        &self,
        context: &RouterAbEcdsaHssStableKeyContextV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        let expected = context.context_binding_digest()?;
        let actual = PublicDigest32::new(decode_base64url_fixed_32(
            "public_identity.context_binding_b64u",
            &self.context_binding_b64u,
        )?);
        if actual == expected {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "ECDSA-HSS public identity context binding does not match context",
        ))
    }

    /// Returns canonical public identity bytes.
    pub fn canonical_public_identity_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(&mut out, ROUTER_AB_ECDSA_HSS_PUBLIC_IDENTITY_VERSION_V1);
        push_len32(&mut out, self.context_binding_b64u.as_bytes());
        push_len32(&mut out, self.client_public_key33_b64u.as_bytes());
        push_len32(&mut out, self.server_public_key33_b64u.as_bytes());
        push_len32(&mut out, self.threshold_public_key33_b64u.as_bytes());
        push_len32(&mut out, self.ethereum_address20_b64u.as_bytes());
        push_u32(&mut out, self.client_share_retry_counter);
        push_u32(&mut out, self.server_share_retry_counter);
        Ok(out)
    }

    /// Returns the public identity digest.
    pub fn public_identity_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_public_identity_bytes()?))
    }
}

/// Client-facing typed ECDSA-HSS registration/bootstrap request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssRegistrationBootstrapRequestV1 {
    /// Stable ECDSA-HSS context.
    pub context: RouterAbEcdsaHssStableKeyContextV1,
    /// Router lifecycle scope for the A/B registration ceremony.
    pub lifecycle: LifecycleScopeV1,
    /// Router A/B signer set selected for this request.
    pub signer_set: SignerSetV1,
    /// Router identity bound into the A/B transcript.
    pub router_id: String,
    /// Client identity bound into the A/B transcript.
    pub client_id: String,
    /// Client ephemeral public key used for client-output encryption.
    pub client_ephemeral_public_key: String,
    /// Request-scoped replay nonce.
    pub replay_nonce: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Client compressed secp256k1 public key encoded as unpadded base64url.
    pub client_public_key33_b64u: String,
    /// Client share retry counter.
    pub client_share_retry_counter: u32,
    /// Deriver A encrypted ECDSA-HSS bootstrap envelope.
    pub deriver_a_envelope: RoleEncryptedEnvelopeV1,
    /// Deriver B encrypted ECDSA-HSS bootstrap envelope.
    pub deriver_b_envelope: RoleEncryptedEnvelopeV1,
}

impl RouterAbEcdsaHssRegistrationBootstrapRequestV1 {
    /// Creates a validated registration/bootstrap request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context: RouterAbEcdsaHssStableKeyContextV1,
        lifecycle: LifecycleScopeV1,
        signer_set: SignerSetV1,
        router_id: impl Into<String>,
        client_id: impl Into<String>,
        client_ephemeral_public_key: impl Into<String>,
        replay_nonce: impl Into<String>,
        expires_at_ms: u64,
        client_public_key33_b64u: impl Into<String>,
        client_share_retry_counter: u32,
        deriver_a_envelope: RoleEncryptedEnvelopeV1,
        deriver_b_envelope: RoleEncryptedEnvelopeV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            context,
            lifecycle,
            signer_set,
            router_id: router_id.into(),
            client_id: client_id.into(),
            client_ephemeral_public_key: client_ephemeral_public_key.into(),
            replay_nonce: replay_nonce.into(),
            expires_at_ms,
            client_public_key33_b64u: client_public_key33_b64u.into(),
            client_share_retry_counter,
            deriver_a_envelope,
            deriver_b_envelope,
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.lifecycle.validate()?;
        self.signer_set.validate()?;
        require_ascii_non_empty("registration.router_id", &self.router_id)?;
        require_ascii_non_empty("registration.client_id", &self.client_id)?;
        require_ascii_non_empty(
            "registration.client_ephemeral_public_key",
            &self.client_ephemeral_public_key,
        )?;
        validate_lifecycle_for_context("registration.lifecycle", &self.lifecycle, &self.context)?;
        require_ascii_non_empty("registration.replay_nonce", &self.replay_nonce)?;
        require_positive_ms("registration.expires_at_ms", self.expires_at_ms)?;
        decode_secp256k1_public_key33_b64u(
            "registration.client_public_key33_b64u",
            &self.client_public_key33_b64u,
        )?;
        self.deriver_a_envelope.validate()?;
        self.deriver_b_envelope.validate()?;
        require_envelope_role(
            "registration.deriver_a_envelope",
            &self.deriver_a_envelope,
            Role::SignerA,
        )?;
        require_envelope_role(
            "registration.deriver_b_envelope",
            &self.deriver_b_envelope,
            Role::SignerB,
        )?;
        Ok(())
    }

    /// Validates the request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS registration request expired",
            ));
        }
        Ok(())
    }

    /// Returns the canonical registration request bytes.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_HSS_REGISTRATION_REQUEST_VERSION_V1,
        );
        push_len32(&mut out, &self.context.canonical_context_bytes()?);
        push_lifecycle_scope(&mut out, &self.lifecycle);
        push_signer_set(&mut out, &self.signer_set);
        push_len32(&mut out, self.router_id.as_bytes());
        push_len32(&mut out, self.client_id.as_bytes());
        push_len32(&mut out, self.client_ephemeral_public_key.as_bytes());
        push_len32(&mut out, self.replay_nonce.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        push_len32(&mut out, self.client_public_key33_b64u.as_bytes());
        push_u32(&mut out, self.client_share_retry_counter);
        push_digest(
            &mut out,
            role_encrypted_envelope_digest_v1(&self.deriver_a_envelope)?,
        );
        push_digest(
            &mut out,
            role_encrypted_envelope_digest_v1(&self.deriver_b_envelope)?,
        );
        Ok(out)
    }

    /// Returns the registration request digest.
    pub fn request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_bytes()?))
    }

    /// Converts this typed request into the shared Router A/B proof-bundle transport.
    pub fn to_threshold_prf_request(&self) -> RouterAbProtocolResult<EcdsaThresholdPrfRequestV1> {
        self.validate()?;
        let context = EcdsaThresholdPrfRequestContextV1::new(
            self.replay_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1.to_owned(),
            self.client_public_key33_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
        )?;
        EcdsaThresholdPrfRequestV1::new(
            self.replay_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1.to_owned(),
            self.client_public_key33_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
            context.derivation_transcript_digest()?,
            self.deriver_a_envelope.clone(),
            self.deriver_b_envelope.clone(),
        )
    }
}

/// SigningWorker activation receipt for an ECDSA-HSS registration/bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssActivationReceiptV1 {
    /// Stable ECDSA-HSS context.
    pub context: RouterAbEcdsaHssStableKeyContextV1,
    /// Public identity activated for normal signing.
    pub public_identity: RouterAbEcdsaHssPublicIdentityV1,
    /// SigningWorker identity that accepted activation.
    pub signing_worker: ServerIdentityV1,
    /// Activation epoch persisted by the SigningWorker.
    pub activation_epoch: String,
    /// Digest of the activation payload encoded as unpadded base64url.
    pub activation_digest_b64u: String,
    /// Activation timestamp in Unix milliseconds.
    pub activated_at_ms: u64,
}

impl RouterAbEcdsaHssActivationReceiptV1 {
    /// Validates activation receipt fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.public_identity.validate_for_context(&self.context)?;
        self.signing_worker.validate()?;
        require_ascii_non_empty("activation.activation_epoch", &self.activation_epoch)?;
        decode_base64url_fixed_32(
            "activation.activation_digest_b64u",
            &self.activation_digest_b64u,
        )?;
        require_positive_ms("activation.activated_at_ms", self.activated_at_ms)
    }
}

/// Client-facing typed ECDSA-HSS explicit export request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssExplicitExportRequestV1 {
    /// Stable ECDSA-HSS context.
    pub context: RouterAbEcdsaHssStableKeyContextV1,
    /// Router lifecycle scope for the A/B export ceremony.
    pub lifecycle: LifecycleScopeV1,
    /// Public identity being exported.
    pub public_identity: RouterAbEcdsaHssPublicIdentityV1,
    /// Router A/B signer set selected for this request.
    pub signer_set: SignerSetV1,
    /// Router identity bound into the A/B transcript.
    pub router_id: String,
    /// Client identity bound into the A/B transcript.
    pub client_id: String,
    /// Client ephemeral public key used for client-output encryption.
    pub client_ephemeral_public_key: String,
    /// User-confirmed export authorization digest encoded as unpadded base64url.
    pub export_authorization_digest_b64u: String,
    /// Request-scoped export replay nonce.
    pub export_nonce: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Deriver A encrypted ECDSA-HSS export envelope.
    pub deriver_a_export_envelope: RoleEncryptedEnvelopeV1,
    /// Deriver B encrypted ECDSA-HSS export envelope.
    pub deriver_b_export_envelope: RoleEncryptedEnvelopeV1,
}

impl RouterAbEcdsaHssExplicitExportRequestV1 {
    /// Validates the request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.lifecycle.validate()?;
        self.public_identity.validate_for_context(&self.context)?;
        self.signer_set.validate()?;
        require_ascii_non_empty("export.router_id", &self.router_id)?;
        require_ascii_non_empty("export.client_id", &self.client_id)?;
        require_ascii_non_empty(
            "export.client_ephemeral_public_key",
            &self.client_ephemeral_public_key,
        )?;
        validate_lifecycle_for_context("export.lifecycle", &self.lifecycle, &self.context)?;
        decode_base64url_fixed_32(
            "export.export_authorization_digest_b64u",
            &self.export_authorization_digest_b64u,
        )?;
        require_ascii_non_empty("export.export_nonce", &self.export_nonce)?;
        require_positive_ms("export.expires_at_ms", self.expires_at_ms)?;
        self.deriver_a_export_envelope.validate()?;
        self.deriver_b_export_envelope.validate()?;
        require_envelope_role(
            "export.deriver_a_export_envelope",
            &self.deriver_a_export_envelope,
            Role::SignerA,
        )?;
        require_envelope_role(
            "export.deriver_b_export_envelope",
            &self.deriver_b_export_envelope,
            Role::SignerB,
        )?;
        Ok(())
    }

    /// Validates the request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS export request expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical export request bytes.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(&mut out, ROUTER_AB_ECDSA_HSS_EXPORT_REQUEST_VERSION_V1);
        push_len32(&mut out, &self.context.canonical_context_bytes()?);
        push_lifecycle_scope(&mut out, &self.lifecycle);
        push_len32(
            &mut out,
            &self.public_identity.canonical_public_identity_bytes()?,
        );
        push_signer_set(&mut out, &self.signer_set);
        push_len32(&mut out, self.router_id.as_bytes());
        push_len32(&mut out, self.client_id.as_bytes());
        push_len32(&mut out, self.client_ephemeral_public_key.as_bytes());
        push_len32(&mut out, self.export_authorization_digest_b64u.as_bytes());
        push_len32(&mut out, self.export_nonce.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        push_digest(
            &mut out,
            role_encrypted_envelope_digest_v1(&self.deriver_a_export_envelope)?,
        );
        push_digest(
            &mut out,
            role_encrypted_envelope_digest_v1(&self.deriver_b_export_envelope)?,
        );
        Ok(out)
    }

    /// Returns the export request digest.
    pub fn request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_bytes()?))
    }

    /// Converts this typed request into the shared Router A/B proof-bundle transport.
    pub fn to_threshold_prf_request(&self) -> RouterAbProtocolResult<EcdsaThresholdPrfRequestV1> {
        self.validate()?;
        let context = EcdsaThresholdPrfRequestContextV1::new(
            self.export_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1.to_owned(),
            self.public_identity.threshold_public_key33_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
        )?;
        EcdsaThresholdPrfRequestV1::new(
            self.export_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1.to_owned(),
            self.public_identity.threshold_public_key33_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
            context.derivation_transcript_digest()?,
            self.deriver_a_export_envelope.clone(),
            self.deriver_b_export_envelope.clone(),
        )
    }
}

/// Client-facing typed ECDSA-HSS recovery request.
///
/// Recovery uses the same primitive derivation class as export, but its
/// transcript domain, authorization digest, nonce, and envelope labels remain
/// recovery-specific.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssRecoveryRequestV1 {
    /// Stable ECDSA-HSS context.
    pub context: RouterAbEcdsaHssStableKeyContextV1,
    /// Router lifecycle scope for the A/B recovery ceremony.
    pub lifecycle: LifecycleScopeV1,
    /// Public identity being recovered.
    pub public_identity: RouterAbEcdsaHssPublicIdentityV1,
    /// Router A/B signer set selected for this request.
    pub signer_set: SignerSetV1,
    /// Router identity bound into the A/B transcript.
    pub router_id: String,
    /// Client identity bound into the A/B transcript.
    pub client_id: String,
    /// Client ephemeral public key used for recovery-output encryption.
    pub client_ephemeral_public_key: String,
    /// User-confirmed recovery authorization digest encoded as unpadded base64url.
    pub recovery_authorization_digest_b64u: String,
    /// Request-scoped recovery replay nonce.
    pub recovery_nonce: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Deriver A encrypted ECDSA-HSS recovery envelope.
    pub deriver_a_recovery_envelope: RoleEncryptedEnvelopeV1,
    /// Deriver B encrypted ECDSA-HSS recovery envelope.
    pub deriver_b_recovery_envelope: RoleEncryptedEnvelopeV1,
}

impl RouterAbEcdsaHssRecoveryRequestV1 {
    /// Validates the request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.lifecycle.validate()?;
        validate_lifecycle_work_kind(
            "recovery.lifecycle",
            &self.lifecycle,
            ExpensiveWorkKindV1::Recovery,
        )?;
        self.public_identity.validate_for_context(&self.context)?;
        self.signer_set.validate()?;
        require_ascii_non_empty("recovery.router_id", &self.router_id)?;
        require_ascii_non_empty("recovery.client_id", &self.client_id)?;
        require_ascii_non_empty(
            "recovery.client_ephemeral_public_key",
            &self.client_ephemeral_public_key,
        )?;
        validate_lifecycle_for_context("recovery.lifecycle", &self.lifecycle, &self.context)?;
        decode_base64url_fixed_32(
            "recovery.recovery_authorization_digest_b64u",
            &self.recovery_authorization_digest_b64u,
        )?;
        require_ascii_non_empty("recovery.recovery_nonce", &self.recovery_nonce)?;
        require_positive_ms("recovery.expires_at_ms", self.expires_at_ms)?;
        self.deriver_a_recovery_envelope.validate()?;
        self.deriver_b_recovery_envelope.validate()?;
        require_envelope_role(
            "recovery.deriver_a_recovery_envelope",
            &self.deriver_a_recovery_envelope,
            Role::SignerA,
        )?;
        require_envelope_role(
            "recovery.deriver_b_recovery_envelope",
            &self.deriver_b_recovery_envelope,
            Role::SignerB,
        )?;
        Ok(())
    }

    /// Validates the request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS recovery request expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical recovery request bytes.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(&mut out, ROUTER_AB_ECDSA_HSS_RECOVERY_REQUEST_VERSION_V1);
        push_len32(&mut out, &self.context.canonical_context_bytes()?);
        push_lifecycle_scope(&mut out, &self.lifecycle);
        push_len32(
            &mut out,
            &self.public_identity.canonical_public_identity_bytes()?,
        );
        push_signer_set(&mut out, &self.signer_set);
        push_len32(&mut out, self.router_id.as_bytes());
        push_len32(&mut out, self.client_id.as_bytes());
        push_len32(&mut out, self.client_ephemeral_public_key.as_bytes());
        push_len32(&mut out, self.recovery_authorization_digest_b64u.as_bytes());
        push_len32(&mut out, self.recovery_nonce.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        push_digest(
            &mut out,
            role_encrypted_envelope_digest_v1(&self.deriver_a_recovery_envelope)?,
        );
        push_digest(
            &mut out,
            role_encrypted_envelope_digest_v1(&self.deriver_b_recovery_envelope)?,
        );
        Ok(out)
    }

    /// Returns the recovery request digest.
    pub fn request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_bytes()?))
    }

    /// Converts this typed request into the shared Router A/B proof-bundle transport.
    pub fn to_threshold_prf_request(&self) -> RouterAbProtocolResult<EcdsaThresholdPrfRequestV1> {
        self.validate()?;
        let context = EcdsaThresholdPrfRequestContextV1::new(
            self.recovery_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1.to_owned(),
            self.public_identity.threshold_public_key33_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
        )?;
        EcdsaThresholdPrfRequestV1::new(
            self.recovery_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1.to_owned(),
            self.public_identity.threshold_public_key33_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
            context.derivation_transcript_digest()?,
            self.deriver_a_recovery_envelope.clone(),
            self.deriver_b_recovery_envelope.clone(),
        )
    }
}

/// Client-facing typed ECDSA-HSS SigningWorker activation-refresh request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssActivationRefreshRequestV1 {
    /// Stable ECDSA-HSS context.
    pub context: RouterAbEcdsaHssStableKeyContextV1,
    /// Router lifecycle scope for the A/B refresh ceremony.
    pub lifecycle: LifecycleScopeV1,
    /// Public identity that must remain stable across refresh.
    pub public_identity: RouterAbEcdsaHssPublicIdentityV1,
    /// Router A/B signer set selected for this request.
    pub signer_set: SignerSetV1,
    /// Router identity bound into the A/B transcript.
    pub router_id: String,
    /// Client identity or operator actor that authorized the refresh.
    pub client_id: String,
    /// Ephemeral public key bound into the refresh transcript recipient slot.
    pub signing_worker_ephemeral_public_key: String,
    /// Authorization digest for the refresh operation.
    pub refresh_authorization_digest_b64u: String,
    /// Request-scoped refresh replay nonce.
    pub refresh_nonce: String,
    /// Activation epoch currently considered active by the Router.
    pub previous_activation_epoch: String,
    /// Activation epoch to be installed by the SigningWorker.
    pub next_activation_epoch: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Deriver A encrypted ECDSA-HSS refresh envelope.
    pub deriver_a_refresh_envelope: RoleEncryptedEnvelopeV1,
    /// Deriver B encrypted ECDSA-HSS refresh envelope.
    pub deriver_b_refresh_envelope: RoleEncryptedEnvelopeV1,
}

impl RouterAbEcdsaHssActivationRefreshRequestV1 {
    /// Validates the request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.lifecycle.validate()?;
        validate_lifecycle_work_kind(
            "refresh.lifecycle",
            &self.lifecycle,
            ExpensiveWorkKindV1::ServerShareRefresh,
        )?;
        self.public_identity.validate_for_context(&self.context)?;
        self.signer_set.validate()?;
        require_ascii_non_empty("refresh.router_id", &self.router_id)?;
        require_ascii_non_empty("refresh.client_id", &self.client_id)?;
        require_ascii_non_empty(
            "refresh.signing_worker_ephemeral_public_key",
            &self.signing_worker_ephemeral_public_key,
        )?;
        validate_lifecycle_for_context("refresh.lifecycle", &self.lifecycle, &self.context)?;
        decode_base64url_fixed_32(
            "refresh.refresh_authorization_digest_b64u",
            &self.refresh_authorization_digest_b64u,
        )?;
        require_ascii_non_empty("refresh.refresh_nonce", &self.refresh_nonce)?;
        require_ascii_non_empty(
            "refresh.previous_activation_epoch",
            &self.previous_activation_epoch,
        )?;
        require_ascii_non_empty("refresh.next_activation_epoch", &self.next_activation_epoch)?;
        if self.previous_activation_epoch == self.next_activation_epoch {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA-HSS refresh must advance activation epoch",
            ));
        }
        if self.lifecycle.root_share_epoch.as_str() != self.next_activation_epoch {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "ECDSA-HSS refresh lifecycle root epoch must equal next activation epoch",
            ));
        }
        require_positive_ms("refresh.expires_at_ms", self.expires_at_ms)?;
        self.deriver_a_refresh_envelope.validate()?;
        self.deriver_b_refresh_envelope.validate()?;
        require_envelope_role(
            "refresh.deriver_a_refresh_envelope",
            &self.deriver_a_refresh_envelope,
            Role::SignerA,
        )?;
        require_envelope_role(
            "refresh.deriver_b_refresh_envelope",
            &self.deriver_b_refresh_envelope,
            Role::SignerB,
        )?;
        Ok(())
    }

    /// Validates the request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS refresh request expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical refresh request bytes.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(&mut out, ROUTER_AB_ECDSA_HSS_REFRESH_REQUEST_VERSION_V1);
        push_len32(&mut out, &self.context.canonical_context_bytes()?);
        push_lifecycle_scope(&mut out, &self.lifecycle);
        push_len32(
            &mut out,
            &self.public_identity.canonical_public_identity_bytes()?,
        );
        push_signer_set(&mut out, &self.signer_set);
        push_len32(&mut out, self.router_id.as_bytes());
        push_len32(&mut out, self.client_id.as_bytes());
        push_len32(
            &mut out,
            self.signing_worker_ephemeral_public_key.as_bytes(),
        );
        push_len32(&mut out, self.refresh_authorization_digest_b64u.as_bytes());
        push_len32(&mut out, self.refresh_nonce.as_bytes());
        push_len32(&mut out, self.previous_activation_epoch.as_bytes());
        push_len32(&mut out, self.next_activation_epoch.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        push_digest(
            &mut out,
            role_encrypted_envelope_digest_v1(&self.deriver_a_refresh_envelope)?,
        );
        push_digest(
            &mut out,
            role_encrypted_envelope_digest_v1(&self.deriver_b_refresh_envelope)?,
        );
        Ok(out)
    }

    /// Returns the refresh request digest.
    pub fn request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_bytes()?))
    }

    /// Converts this typed request into the shared Router A/B proof-bundle transport.
    pub fn to_threshold_prf_request(&self) -> RouterAbProtocolResult<EcdsaThresholdPrfRequestV1> {
        self.validate()?;
        let context = EcdsaThresholdPrfRequestContextV1::new(
            self.refresh_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1.to_owned(),
            self.public_identity.threshold_public_key33_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.signing_worker_ephemeral_public_key.clone(),
        )?;
        EcdsaThresholdPrfRequestV1::new(
            self.refresh_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_HSS_KEY_SCOPE_V1.to_owned(),
            self.public_identity.threshold_public_key33_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.signing_worker_ephemeral_public_key.clone(),
            context.derivation_transcript_digest()?,
            self.deriver_a_refresh_envelope.clone(),
            self.deriver_b_refresh_envelope.clone(),
        )
    }
}

/// Scope that binds normal ECDSA signing to activated SigningWorker state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssNormalSigningScopeV1 {
    /// Stable wallet key id used by the SDK.
    pub wallet_key_id: String,
    /// Wallet id that owns this ECDSA-HSS key.
    pub wallet_id: String,
    /// Stable threshold ECDSA key id.
    pub ecdsa_threshold_key_id: String,
    /// Signing root id.
    pub signing_root_id: String,
    /// Signing root version.
    pub signing_root_version: String,
    /// Digest-only ECDSA-HSS context.
    pub context: RouterAbEcdsaHssStableKeyContextV1,
    /// Public identity expected for the active signing key.
    pub public_identity: RouterAbEcdsaHssPublicIdentityV1,
    /// SigningWorker identity that owns activation state.
    pub signing_worker: ServerIdentityV1,
    /// Activation epoch persisted by the SigningWorker.
    pub activation_epoch: String,
}

impl RouterAbEcdsaHssNormalSigningScopeV1 {
    /// Creates a validated normal-signing scope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_key_id: impl Into<String>,
        wallet_id: impl Into<String>,
        ecdsa_threshold_key_id: impl Into<String>,
        signing_root_id: impl Into<String>,
        signing_root_version: impl Into<String>,
        context: RouterAbEcdsaHssStableKeyContextV1,
        public_identity: RouterAbEcdsaHssPublicIdentityV1,
        signing_worker: ServerIdentityV1,
        activation_epoch: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let scope = Self {
            wallet_key_id: wallet_key_id.into(),
            wallet_id: wallet_id.into(),
            ecdsa_threshold_key_id: ecdsa_threshold_key_id.into(),
            signing_root_id: signing_root_id.into(),
            signing_root_version: signing_root_version.into(),
            context,
            public_identity,
            signing_worker,
            activation_epoch: activation_epoch.into(),
        };
        scope.validate()?;
        Ok(scope)
    }

    /// Validates the normal-signing scope.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_ascii_non_empty("normal_signing.wallet_key_id", &self.wallet_key_id)?;
        require_ascii_non_empty("normal_signing.wallet_id", &self.wallet_id)?;
        require_ascii_non_empty(
            "normal_signing.ecdsa_threshold_key_id",
            &self.ecdsa_threshold_key_id,
        )?;
        require_ascii_non_empty("normal_signing.signing_root_id", &self.signing_root_id)?;
        require_ascii_non_empty(
            "normal_signing.signing_root_version",
            &self.signing_root_version,
        )?;
        self.context.validate()?;
        self.public_identity.validate_for_context(&self.context)?;
        self.signing_worker.validate()?;
        require_ascii_non_empty("normal_signing.activation_epoch", &self.activation_epoch)
    }

    /// Returns canonical normal-signing scope bytes.
    pub fn canonical_scope_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_SCOPE_VERSION_V1,
        );
        push_len32(&mut out, self.wallet_key_id.as_bytes());
        push_len32(&mut out, self.wallet_id.as_bytes());
        push_len32(&mut out, self.ecdsa_threshold_key_id.as_bytes());
        push_len32(&mut out, self.signing_root_id.as_bytes());
        push_len32(&mut out, self.signing_root_version.as_bytes());
        push_len32(&mut out, &self.context.canonical_context_bytes()?);
        push_len32(
            &mut out,
            &self.public_identity.canonical_public_identity_bytes()?,
        );
        push_server_identity(&mut out, &self.signing_worker);
        push_len32(&mut out, self.activation_epoch.as_bytes());
        Ok(out)
    }

    /// Returns the active SigningWorker session id for this normal-signing scope.
    pub fn active_state_session_id(&self) -> RouterAbProtocolResult<String> {
        self.validate()?;
        router_ab_ecdsa_hss_active_state_session_id_v1(
            &self.ecdsa_threshold_key_id,
            &self.signing_root_id,
            &self.signing_root_version,
            &self.activation_epoch,
        )
    }

    /// Returns the normal-signing scope digest.
    pub fn scope_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_scope_bytes()?))
    }
}

/// Client-facing typed ECDSA-HSS normal-signing request after Router parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssEvmDigestSigningRequestV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaHssNormalSigningScopeV1,
    /// Request id used for replay, quota, and audit correlation.
    pub request_id: String,
    /// Client-held presignature id that must match the SigningWorker server share.
    pub client_presignature_id: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Exact 32-byte EVM/secp256k1 digest encoded as unpadded base64url.
    pub signing_digest_b64u: String,
}

impl RouterAbEcdsaHssEvmDigestSigningRequestV1 {
    /// Creates a validated ECDSA-HSS normal-signing request.
    pub fn new(
        scope: RouterAbEcdsaHssNormalSigningScopeV1,
        request_id: impl Into<String>,
        client_presignature_id: impl Into<String>,
        expires_at_ms: u64,
        signing_digest_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            request_id: request_id.into(),
            client_presignature_id: client_presignature_id.into(),
            expires_at_ms,
            signing_digest_b64u: signing_digest_b64u.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the typed normal-signing request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_ascii_non_empty("normal_signing.request_id", &self.request_id)?;
        require_ascii_non_empty(
            "normal_signing.client_presignature_id",
            &self.client_presignature_id,
        )?;
        require_positive_ms("normal_signing.expires_at_ms", self.expires_at_ms)?;
        self.signing_digest()?;
        Ok(())
    }

    /// Validates the typed normal-signing request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS normal-signing request expired",
            ));
        }
        Ok(())
    }

    /// Returns the exact digest admitted for ECDSA signing.
    pub fn signing_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(PublicDigest32::new(decode_base64url_fixed_32(
            "normal_signing.signing_digest_b64u",
            &self.signing_digest_b64u,
        )?))
    }

    /// Returns canonical request bytes for transcript/replay binding.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_REQUEST_VERSION_V1,
        );
        push_len32(&mut out, &self.scope.canonical_scope_bytes()?);
        push_len32(&mut out, self.request_id.as_bytes());
        push_len32(&mut out, self.client_presignature_id.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        push_digest(&mut out, self.signing_digest()?);
        Ok(out)
    }

    /// Returns the canonical request digest.
    pub fn request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_bytes()?))
    }
}

/// Client-facing ECDSA-HSS finalize request carrying the client signature share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaHssNormalSigningScopeV1,
    /// Request id used for replay, quota, and audit correlation.
    pub request_id: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Exact 32-byte EVM/secp256k1 digest encoded as unpadded base64url.
    pub signing_digest_b64u: String,
    /// SigningWorker-local ECDSA presignature id returned by prepare.
    pub server_presignature_id: String,
    /// Client ECDSA signature share over the same digest encoded as unpadded base64url.
    pub client_signature_share32_b64u: String,
}

impl RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1 {
    /// Creates a validated ECDSA-HSS finalize request.
    pub fn new(
        scope: RouterAbEcdsaHssNormalSigningScopeV1,
        request_id: impl Into<String>,
        expires_at_ms: u64,
        signing_digest_b64u: impl Into<String>,
        server_presignature_id: impl Into<String>,
        client_signature_share32_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            request_id: request_id.into(),
            expires_at_ms,
            signing_digest_b64u: signing_digest_b64u.into(),
            server_presignature_id: server_presignature_id.into(),
            client_signature_share32_b64u: client_signature_share32_b64u.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Validates the typed finalize request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_ascii_non_empty("ecdsa_finalize.request_id", &self.request_id)?;
        require_positive_ms("ecdsa_finalize.expires_at_ms", self.expires_at_ms)?;
        require_ascii_non_empty(
            "ecdsa_finalize.server_presignature_id",
            &self.server_presignature_id,
        )?;
        self.signing_digest()?;
        self.client_signature_share32()?;
        Ok(())
    }

    /// Validates the finalize request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "ECDSA-HSS normal-signing finalize request expired",
            ));
        }
        Ok(())
    }

    /// Returns the corresponding prepare request identity and digest material.
    pub fn prepare_request(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningRequestV1> {
        RouterAbEcdsaHssEvmDigestSigningRequestV1::new(
            self.scope.clone(),
            self.request_id.clone(),
            self.server_presignature_id.clone(),
            self.expires_at_ms,
            self.signing_digest_b64u.clone(),
        )
    }

    /// Returns the canonical prepare request digest this finalize must consume.
    pub fn prepare_request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.prepare_request()?.request_digest()
    }

    /// Returns the exact digest admitted for ECDSA signing.
    pub fn signing_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(PublicDigest32::new(decode_base64url_fixed_32(
            "ecdsa_finalize.signing_digest_b64u",
            &self.signing_digest_b64u,
        )?))
    }

    /// Returns the exact client signature share bytes.
    pub fn client_signature_share32(&self) -> RouterAbProtocolResult<[u8; 32]> {
        decode_base64url_fixed_32(
            "ecdsa_finalize.client_signature_share32_b64u",
            &self.client_signature_share32_b64u,
        )
    }

    /// Returns canonical finalize request bytes for transcript/replay binding.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_HSS_NORMAL_SIGNING_FINALIZE_REQUEST_VERSION_V1,
        );
        push_len32(&mut out, &self.scope.canonical_scope_bytes()?);
        push_len32(&mut out, self.request_id.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        push_digest(&mut out, self.signing_digest()?);
        push_len32(&mut out, self.server_presignature_id.as_bytes());
        push_len32(&mut out, &self.client_signature_share32()?);
        Ok(out)
    }

    /// Returns the canonical finalize request digest.
    pub fn request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_bytes()?))
    }
}

/// Public response for an ECDSA-HSS EVM digest-signing prepare request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaHssNormalSigningScopeV1,
    /// Request id accepted by the Router.
    pub request_id: String,
    /// Canonical prepare request digest accepted by the SigningWorker.
    pub request_digest: PublicDigest32,
    /// Exact digest admitted for ECDSA-HSS signing.
    pub signing_digest: PublicDigest32,
    /// SigningWorker-local presignature id consumed by finalize.
    pub server_presignature_id: String,
    /// Server public presignature point encoded as compressed secp256k1 bytes.
    pub server_big_r33_b64u: String,
    /// Public 32-byte rerandomization entropy both ECDSA parties must use.
    pub rerandomization_entropy32_b64u: String,
    /// Signature algorithm supported by the prepared state.
    pub signature_scheme: RouterAbEcdsaHssSignatureSchemeV1,
    /// Prepare timestamp in Unix milliseconds.
    pub prepared_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1 {
    /// Creates a validated response bound to a typed ECDSA-HSS prepare request.
    pub fn new_for_request(
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        rerandomization_entropy32_b64u: impl Into<String>,
        prepared_at_ms: u64,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let response = Self {
            scope: request.scope.clone(),
            request_id: request.request_id.clone(),
            request_digest: request.request_digest()?,
            signing_digest: request.signing_digest()?,
            server_presignature_id: server_presignature_id.into(),
            server_big_r33_b64u: server_big_r33_b64u.into(),
            rerandomization_entropy32_b64u: rerandomization_entropy32_b64u.into(),
            signature_scheme: RouterAbEcdsaHssSignatureSchemeV1::EcdsaSecp256k1RecoverableV1,
            prepared_at_ms,
            expires_at_ms: request.expires_at_ms,
        };
        response.validate_for_request(request)?;
        Ok(response)
    }

    /// Validates response fields without the originating request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_ascii_non_empty("ecdsa_prepare_response.request_id", &self.request_id)?;
        require_ascii_non_empty(
            "ecdsa_prepare_response.server_presignature_id",
            &self.server_presignature_id,
        )?;
        decode_secp256k1_public_key33_b64u(
            "ecdsa_prepare_response.server_big_r33_b64u",
            &self.server_big_r33_b64u,
        )?;
        decode_base64url_fixed_32(
            "ecdsa_prepare_response.rerandomization_entropy32_b64u",
            &self.rerandomization_entropy32_b64u,
        )?;
        require_positive_ms("ecdsa_prepare_response.prepared_at_ms", self.prepared_at_ms)?;
        require_positive_ms("ecdsa_prepare_response.expires_at_ms", self.expires_at_ms)?;
        if self.expires_at_ms > self.prepared_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "ECDSA-HSS prepare response expiry must be after prepare time",
        ))
    }

    /// Validates the response is bound to the exact prepare request.
    pub fn validate_for_request(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.scope == request.scope
            && self.request_id == request.request_id
            && self.server_presignature_id == request.client_presignature_id
            && self.request_digest == request.request_digest()?
            && self.signing_digest == request.signing_digest()?
            && self.expires_at_ms == request.expires_at_ms
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "ECDSA-HSS prepare response does not match request",
        ))
    }
}

/// Public response for an ECDSA-HSS EVM digest-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaHssEvmDigestSigningResponseV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaHssNormalSigningScopeV1,
    /// Request id accepted by the Router.
    pub request_id: String,
    /// Canonical request digest accepted by the SigningWorker.
    pub request_digest: PublicDigest32,
    /// Exact digest signed by the ECDSA-HSS key.
    pub signing_digest: PublicDigest32,
    /// Signature algorithm used by this response.
    pub signature_scheme: RouterAbEcdsaHssSignatureSchemeV1,
    /// Recoverable signature bytes encoded as unpadded base64url.
    pub signature65_b64u: String,
}

impl RouterAbEcdsaHssEvmDigestSigningResponseV1 {
    /// Creates a validated response bound to a typed ECDSA-HSS signing request.
    pub fn new_for_request(
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
        signature65_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let response = Self {
            scope: request.scope.clone(),
            request_id: request.request_id.clone(),
            request_digest: request.request_digest()?,
            signing_digest: request.signing_digest()?,
            signature_scheme: RouterAbEcdsaHssSignatureSchemeV1::EcdsaSecp256k1RecoverableV1,
            signature65_b64u: signature65_b64u.into(),
        };
        response.validate_for_request(request)?;
        Ok(response)
    }

    /// Validates response fields without the originating request.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.scope.validate()?;
        require_ascii_non_empty("ecdsa_response.request_id", &self.request_id)?;
        decode_base64url_fixed_65("ecdsa_response.signature65_b64u", &self.signature65_b64u)?;
        Ok(())
    }

    /// Validates the response is bound to the exact request and signing digest.
    pub fn validate_for_request(
        &self,
        request: &RouterAbEcdsaHssEvmDigestSigningRequestV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        request.validate()?;
        if self.scope == request.scope
            && self.request_id == request.request_id
            && self.request_digest == request.request_digest()?
            && self.signing_digest == request.signing_digest()?
        {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "ECDSA-HSS signing response does not match request",
        ))
    }
}

/// Parses and validates a raw JSON ECDSA-HSS registration/bootstrap request.
pub fn parse_router_ab_ecdsa_hss_registration_bootstrap_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssRegistrationBootstrapRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaHssRegistrationBootstrapRequestV1>(
        "ECDSA-HSS registration/bootstrap request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates decrypted ECDSA-HSS Deriver envelope plaintext JSON.
pub fn parse_router_ab_ecdsa_hss_deriver_envelope_plaintext_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssDeriverEnvelopePlaintextV1> {
    let plaintext = parse_boundary_json::<RouterAbEcdsaHssDeriverEnvelopePlaintextV1>(
        "ECDSA-HSS Deriver envelope plaintext",
        bytes,
    )?;
    plaintext.validate()?;
    Ok(plaintext)
}

/// Parses and validates a raw JSON ECDSA-HSS explicit export request.
pub fn parse_router_ab_ecdsa_hss_explicit_export_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssExplicitExportRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaHssExplicitExportRequestV1>(
        "ECDSA-HSS explicit export request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON ECDSA-HSS recovery request.
pub fn parse_router_ab_ecdsa_hss_recovery_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssRecoveryRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaHssRecoveryRequestV1>(
        "ECDSA-HSS recovery request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON ECDSA-HSS activation-refresh request.
pub fn parse_router_ab_ecdsa_hss_activation_refresh_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssActivationRefreshRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaHssActivationRefreshRequestV1>(
        "ECDSA-HSS activation refresh request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON ECDSA-HSS normal-signing scope.
pub fn parse_router_ab_ecdsa_hss_normal_signing_scope_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssNormalSigningScopeV1> {
    let scope = parse_boundary_json::<RouterAbEcdsaHssNormalSigningScopeV1>(
        "ECDSA-HSS normal signing scope",
        bytes,
    )?;
    scope.validate()?;
    Ok(scope)
}

/// Parses and validates a raw JSON ECDSA-HSS normal-signing request.
pub fn parse_router_ab_ecdsa_hss_evm_digest_signing_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaHssEvmDigestSigningRequestV1>(
        "ECDSA-HSS normal signing request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON ECDSA-HSS normal-signing finalize request.
pub fn parse_router_ab_ecdsa_hss_evm_digest_signing_finalize_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaHssEvmDigestSigningFinalizeRequestV1>(
        "ECDSA-HSS normal signing finalize request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON ECDSA-HSS normal-signing prepare response.
pub fn parse_router_ab_ecdsa_hss_evm_digest_signing_prepare_response_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1> {
    let response = parse_boundary_json::<RouterAbEcdsaHssEvmDigestSigningPrepareResponseV1>(
        "ECDSA-HSS normal signing prepare response",
        bytes,
    )?;
    response.validate()?;
    Ok(response)
}

fn parse_boundary_json<T>(label: &str, bytes: &[u8]) -> RouterAbProtocolResult<T>
where
    T: DeserializeOwned,
{
    serde_json::from_slice(bytes).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{label} JSON parse failed: {err}"),
        )
    })
}

fn push_signer_set(out: &mut Vec<u8>, signer_set: &SignerSetV1) {
    push_len32(out, signer_set.signer_set_id.as_bytes());
    push_len32(out, signer_set.policy.as_str().as_bytes());
    push_len32(out, signer_set.signer_a.signer_id.as_bytes());
    push_len32(out, signer_set.signer_a.key_epoch.as_bytes());
    push_len32(out, signer_set.signer_b.signer_id.as_bytes());
    push_len32(out, signer_set.signer_b.key_epoch.as_bytes());
    push_server_identity(out, &signer_set.selected_server);
}

fn push_lifecycle_scope(out: &mut Vec<u8>, lifecycle: &LifecycleScopeV1) {
    push_len32(out, lifecycle.lifecycle_id.as_bytes());
    push_len32(out, lifecycle.work_kind.as_str().as_bytes());
    push_len32(out, lifecycle.primitive_request_kind.as_str().as_bytes());
    push_len32(out, lifecycle.root_share_epoch.as_str().as_bytes());
    push_len32(out, lifecycle.account_id.as_bytes());
    push_len32(out, lifecycle.session_id.as_bytes());
    push_len32(out, lifecycle.signer_set_id.as_bytes());
    push_len32(out, lifecycle.selected_server_id.as_bytes());
}

fn push_deriver_envelope_common(
    out: &mut Vec<u8>,
    common: &RouterAbEcdsaHssDeriverEnvelopeCommonV1,
) -> RouterAbProtocolResult<()> {
    common.validate()?;
    push_len32(out, &common.context.canonical_context_bytes()?);
    push_lifecycle_scope(out, &common.lifecycle);
    push_signer_set(out, &common.signer_set);
    push_signer_identity(out, &common.recipient_deriver);
    push_len32(out, common.router_id.as_bytes());
    push_len32(out, common.client_id.as_bytes());
    push_len32(out, common.recipient_ephemeral_public_key.as_bytes());
    push_digest(out, common.request_digest);
    push_digest(out, common.aad_digest);
    push_u64(out, common.expires_at_ms);
    Ok(())
}

fn push_signer_identity(out: &mut Vec<u8>, signer: &SignerIdentityV1) {
    push_len32(out, signer.role.as_str().as_bytes());
    push_len32(out, signer.signer_id.as_bytes());
    push_len32(out, signer.key_epoch.as_bytes());
}

fn push_server_identity(out: &mut Vec<u8>, server: &ServerIdentityV1) {
    push_len32(out, server.server_id.as_bytes());
    push_len32(out, server.key_epoch.as_bytes());
    push_len32(out, server.recipient_encryption_key.as_bytes());
}

fn push_digest(out: &mut Vec<u8>, digest: PublicDigest32) {
    out.extend_from_slice(digest.as_bytes());
}

fn public_digest(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

fn ecdsa_hss_context_binding_frame(context_bytes: &[u8]) -> RouterAbProtocolResult<Vec<u8>> {
    let len = u16::try_from(context_bytes.len()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "ECDSA-HSS context bytes exceed u16 length encoding",
        )
    })?;
    let mut out = Vec::new();
    out.extend_from_slice(ECDSA_HSS_CONTEXT_BINDING_DOMAIN_V1);
    out.push(1);
    out.push(ECDSA_HSS_CONTEXT_FIELD_BYTES_V1);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(context_bytes);
    Ok(out)
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_ascii_u16(out: &mut Vec<u8>, value: &str) -> RouterAbProtocolResult<()> {
    require_ascii_non_empty("ECDSA-HSS context string", value)?;
    let len = u16::try_from(value.len()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "ECDSA-HSS context string exceeds u16 length encoding",
        )
    })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(value.as_bytes());
    Ok(())
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn require_ascii_non_empty(field: &str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} must be non-empty"),
        ));
    }
    if !value.is_ascii() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be ASCII-only"),
        ));
    }
    Ok(())
}

fn require_positive_ms(field: &str, value: u64) -> RouterAbProtocolResult<()> {
    if value > 0 {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidTimeRange,
        format!("{field} must be greater than zero"),
    ))
}

fn require_envelope_role(
    field: &str,
    envelope: &RoleEncryptedEnvelopeV1,
    role: Role,
) -> RouterAbProtocolResult<()> {
    if envelope.recipient_role == role {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidRole,
        format!("{field} must target {}", role.as_str()),
    ))
}

fn require_output_kind(
    field: &str,
    actual: RouterAbEcdsaHssOutputKindV1,
    expected: RouterAbEcdsaHssOutputKindV1,
) -> RouterAbProtocolResult<()> {
    if actual == expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field} must be {}", expected.as_str()),
    ))
}

fn recipient_deriver_for_role(
    signer_set: &SignerSetV1,
    recipient_role: Role,
) -> RouterAbProtocolResult<SignerIdentityV1> {
    signer_set.validate()?;
    match recipient_role {
        Role::SignerA => Ok(signer_set.signer_a.clone()),
        Role::SignerB => Ok(signer_set.signer_b.clone()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "ECDSA-HSS Deriver envelope recipient must be Signer A or Signer B",
        )),
    }
}

fn validate_lifecycle_for_context(
    field: &str,
    lifecycle: &LifecycleScopeV1,
    context: &RouterAbEcdsaHssStableKeyContextV1,
) -> RouterAbProtocolResult<()> {
    lifecycle.validate()?;
    context.validate()?;
    require_ascii_non_empty(field, &lifecycle.session_id)
}

fn validate_lifecycle_work_kind(
    field: &str,
    lifecycle: &LifecycleScopeV1,
    expected: ExpensiveWorkKindV1,
) -> RouterAbProtocolResult<()> {
    lifecycle.validate()?;
    if lifecycle.work_kind == expected {
        return Ok(());
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::InvalidLifecycleState,
        format!("{field} work kind must be {}", expected.as_str()),
    ))
}

fn decode_secp256k1_public_key33_b64u(
    field: &str,
    value: &str,
) -> RouterAbProtocolResult<[u8; 33]> {
    let bytes = decode_base64url_fixed_33(field, value)?;
    if matches!(bytes[0], 0x02 | 0x03) {
        return Ok(bytes);
    }
    Err(RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!("{field} must be a compressed secp256k1 public key"),
    ))
}

fn decode_base64url_fixed_20(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 20]> {
    let bytes = decode_base64url(field, value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 20 bytes, got {}", bytes.len()),
        )
    })
}

fn decode_base64url_fixed_32(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 32]> {
    let bytes = decode_base64url(field, value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 32 bytes, got {}", bytes.len()),
        )
    })
}

fn decode_base64url_fixed_33(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 33]> {
    let bytes = decode_base64url(field, value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 33 bytes, got {}", bytes.len()),
        )
    })
}

fn decode_base64url_fixed_65(field: &str, value: &str) -> RouterAbProtocolResult<[u8; 65]> {
    let bytes = decode_base64url(field, value)?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must decode to 65 bytes, got {}", bytes.len()),
        )
    })
}

fn decode_base64url(field: &str, value: &str) -> RouterAbProtocolResult<Vec<u8>> {
    require_ascii_non_empty(field, value)?;
    Base64UrlUnpadded::decode_vec(value).map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} must be unpadded base64url: {err}"),
        )
    })
}
