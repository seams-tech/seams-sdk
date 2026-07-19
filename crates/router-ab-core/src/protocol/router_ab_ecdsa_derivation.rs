use crate::derivation::{PublicDigest32, Role};
use crate::protocol::ecdsa_threshold_prf_request::{
    EcdsaThresholdPrfRequestContextV1, EcdsaThresholdPrfRequestV1,
};
use crate::protocol::envelope::{
    role_encrypted_envelope_digest_v1, RoleEncryptedEnvelopeV1, RoleEnvelopeAadV1,
};
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

/// Frozen Router A/B ECDSA derivation protocol id.
pub const ROUTER_AB_ECDSA_DERIVATION_PROTOCOL_VERSION_V1: &str = "router_ab_ecdsa_derivation_v1";
/// Router A/B ECDSA derivation key scope supported by the first Router A/B ECDSA release.
pub const ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1: &str = "evm-family";

const ROUTER_AB_ECDSA_DERIVATION_CONTEXT_DOMAIN_TAG_V1: &[u8] =
    b"router-ab-ecdsa-derivation/context/v1";
const ROUTER_AB_ECDSA_DERIVATION_CONTEXT_BINDING_DOMAIN_V1: &[u8] =
    b"router-ab-ecdsa-derivation/role-local/context-binding/v1";
const ROUTER_AB_ECDSA_DERIVATION_SCHEME_ID_V1: &str = "router-ab-ecdsa-derivation-v1";
const ROUTER_AB_ECDSA_DERIVATION_CURVE_V1: &str = "secp256k1";
const ROUTER_AB_ECDSA_DERIVATION_CONTEXT_FIELD_BYTES_V1: u8 = 0x01;
const ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS_V1: [u16; 2] = [1, 2];
const ROUTER_AB_ECDSA_DERIVATION_PUBLIC_IDENTITY_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/public-identity/v1";
const ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/registration-request/v1";
const ROUTER_AB_ECDSA_DERIVATION_EXPORT_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/export-request/v1";
const ROUTER_AB_ECDSA_DERIVATION_RECOVERY_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/recovery-request/v1";
const ROUTER_AB_ECDSA_DERIVATION_REFRESH_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/refresh-request/v1";
const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_SCOPE_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/normal-signing-scope/v1";
const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/normal-signing-request/v1";
const ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_FINALIZE_REQUEST_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/normal-signing-finalize-request/v1";
const ROUTER_AB_ECDSA_DERIVATION_CLIENT_RERANDOMIZATION_COMMITMENT_DOMAIN_V1: &[u8] =
    b"router-ab-ecdsa-derivation/client-rerandomization-commitment/v1";
const ROUTER_AB_ECDSA_DERIVATION_DERIVER_ENVELOPE_PLAINTEXT_VERSION_V1: &[u8] =
    b"router-ab-ecdsa-derivation/deriver-envelope-plaintext/v1";

/// Router A/B ECDSA derivation Router A/B operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbEcdsaDerivationRequestKindV1 {
    /// Initial registration/bootstrap that activates SigningWorker state.
    RegistrationBootstrap,
    /// Explicit user-authorized key export.
    ExplicitKeyExport,
    /// Recovery ceremony for an existing Router A/B ECDSA derivation identity.
    Recovery,
    /// SigningWorker activation refresh after Deriver A/B root rotation.
    Refresh,
    /// Normal ECDSA signing through an active SigningWorker state.
    NormalSigning,
}

/// Product lifecycle purpose for a registration/bootstrap request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbEcdsaDerivationRegistrationPurposeV1 {
    /// Bootstrap the first ECDSA signer while registering a wallet.
    WalletRegistration,
    /// Bootstrap an additional ECDSA signer for an existing wallet.
    WalletAddSigner,
}

impl RouterAbEcdsaDerivationRegistrationPurposeV1 {
    /// Returns the canonical registration-purpose label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WalletRegistration => "wallet_registration",
            Self::WalletAddSigner => "wallet_add_signer",
        }
    }
}

impl RouterAbEcdsaDerivationRequestKindV1 {
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

/// Recipient/output class for Router A/B ECDSA derivation Router A/B material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbEcdsaDerivationOutputKindV1 {
    /// Material encrypted to the active SigningWorker for normal signing.
    SigningWorkerActivation,
    /// Material encrypted to the authorized client export runtime.
    ClientExport,
}

impl RouterAbEcdsaDerivationOutputKindV1 {
    /// Returns the canonical output kind label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SigningWorkerActivation => "signing_worker_activation",
            Self::ClientExport => "client_export",
        }
    }
}

/// Public metadata decrypted from a Router A/B ECDSA derivation Deriver A/B envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request_kind", rename_all = "snake_case")]
pub enum RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1 {
    /// Registration/bootstrap material for SigningWorker activation.
    RegistrationBootstrap(RouterAbEcdsaDerivationDeriverRegistrationEnvelopePlaintextV1),
    /// Explicit export material for the client export runtime.
    ExplicitKeyExport(RouterAbEcdsaDerivationDeriverExportEnvelopePlaintextV1),
    /// Recovery material for the client recovery runtime.
    Recovery(RouterAbEcdsaDerivationDeriverRecoveryEnvelopePlaintextV1),
    /// Refresh material for the next SigningWorker activation epoch.
    Refresh(RouterAbEcdsaDerivationDeriverRefreshEnvelopePlaintextV1),
}

impl RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1 {
    /// Builds registration plaintext for one Deriver envelope.
    pub fn registration_for_request(
        request: &RouterAbEcdsaDerivationRegistrationBootstrapRequestV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        Self::registration_for_header(&request.header(), recipient_role, aad_digest)
    }

    /// Builds registration plaintext from the public header before role envelopes are sealed.
    pub fn registration_for_header(
        header: &RouterAbEcdsaDerivationRegistrationHeaderV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        header.validate()?;
        let plaintext = RouterAbEcdsaDerivationDeriverRegistrationEnvelopePlaintextV1 {
            common: RouterAbEcdsaDerivationDeriverEnvelopeCommonV1::from_parts(
                header.context.clone(),
                header.lifecycle.clone(),
                header.signer_set.clone(),
                recipient_role,
                header.router_id.clone(),
                header.client_id.clone(),
                header.client_ephemeral_public_key.clone(),
                header.digest()?,
                aad_digest,
                header.expires_at_ms,
            )?,
            output_kind: RouterAbEcdsaDerivationOutputKindV1::SigningWorkerActivation,
            registration_purpose: header.registration_purpose,
        };
        plaintext.validate()?;
        Ok(Self::RegistrationBootstrap(plaintext))
    }

    /// Builds explicit-export plaintext for one Deriver envelope.
    pub fn export_for_request(
        request: &RouterAbEcdsaDerivationExplicitExportRequestV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let plaintext = RouterAbEcdsaDerivationDeriverExportEnvelopePlaintextV1 {
            common: RouterAbEcdsaDerivationDeriverEnvelopeCommonV1::from_parts(
                request.context.clone(),
                request.lifecycle.clone(),
                request.signer_set.clone(),
                recipient_role,
                request.router_id.clone(),
                request.client_id.clone(),
                request.client_ephemeral_public_key.clone(),
                request.request_header_digest()?,
                aad_digest,
                request.expires_at_ms,
            )?,
            output_kind: RouterAbEcdsaDerivationOutputKindV1::ClientExport,
            public_identity: request.public_identity.clone(),
            export_authorization_digest_b64u: request.export_authorization_digest_b64u.clone(),
            export_nonce: request.export_nonce.clone(),
        };
        plaintext.validate()?;
        Ok(Self::ExplicitKeyExport(plaintext))
    }

    /// Builds recovery plaintext for one Deriver envelope.
    pub fn recovery_for_request(
        request: &RouterAbEcdsaDerivationRecoveryRequestV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let plaintext = RouterAbEcdsaDerivationDeriverRecoveryEnvelopePlaintextV1 {
            common: RouterAbEcdsaDerivationDeriverEnvelopeCommonV1::from_parts(
                request.context.clone(),
                request.lifecycle.clone(),
                request.signer_set.clone(),
                recipient_role,
                request.router_id.clone(),
                request.client_id.clone(),
                request.client_ephemeral_public_key.clone(),
                request.request_header_digest()?,
                aad_digest,
                request.expires_at_ms,
            )?,
            output_kind: RouterAbEcdsaDerivationOutputKindV1::ClientExport,
            public_identity: request.public_identity.clone(),
            recovery_authorization_digest_b64u: request.recovery_authorization_digest_b64u.clone(),
            recovery_nonce: request.recovery_nonce.clone(),
        };
        plaintext.validate()?;
        Ok(Self::Recovery(plaintext))
    }

    /// Builds activation-refresh plaintext for one Deriver envelope.
    pub fn refresh_for_request(
        request: &RouterAbEcdsaDerivationActivationRefreshRequestV1,
        recipient_role: Role,
        aad_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let plaintext = RouterAbEcdsaDerivationDeriverRefreshEnvelopePlaintextV1 {
            common: RouterAbEcdsaDerivationDeriverEnvelopeCommonV1::from_parts(
                request.context.clone(),
                request.lifecycle.clone(),
                request.signer_set.clone(),
                recipient_role,
                request.router_id.clone(),
                request.client_id.clone(),
                request.signing_worker_ephemeral_public_key.clone(),
                request.request_header_digest()?,
                aad_digest,
                request.expires_at_ms,
            )?,
            output_kind: RouterAbEcdsaDerivationOutputKindV1::SigningWorkerActivation,
            public_identity: request.public_identity.clone(),
            refresh_authorization_digest_b64u: request.refresh_authorization_digest_b64u.clone(),
            refresh_nonce: request.refresh_nonce.clone(),
            previous_activation_epoch: request.previous_activation_epoch.clone(),
            next_activation_epoch: request.next_activation_epoch.clone(),
        };
        plaintext.validate()?;
        Ok(Self::Refresh(plaintext))
    }

    /// Returns the Router A/B ECDSA derivation request kind represented by this plaintext.
    pub fn request_kind(&self) -> RouterAbEcdsaDerivationRequestKindV1 {
        match self {
            Self::RegistrationBootstrap(_) => {
                RouterAbEcdsaDerivationRequestKindV1::RegistrationBootstrap
            }
            Self::ExplicitKeyExport(_) => RouterAbEcdsaDerivationRequestKindV1::ExplicitKeyExport,
            Self::Recovery(_) => RouterAbEcdsaDerivationRequestKindV1::Recovery,
            Self::Refresh(_) => RouterAbEcdsaDerivationRequestKindV1::Refresh,
        }
    }

    /// Returns the output class this Deriver plaintext may produce.
    pub fn output_kind(&self) -> RouterAbEcdsaDerivationOutputKindV1 {
        match self {
            Self::RegistrationBootstrap(plaintext) => plaintext.output_kind,
            Self::ExplicitKeyExport(plaintext) => plaintext.output_kind,
            Self::Recovery(plaintext) => plaintext.output_kind,
            Self::Refresh(plaintext) => plaintext.output_kind,
        }
    }

    /// Returns shared public Deriver envelope metadata.
    pub fn common(&self) -> &RouterAbEcdsaDerivationDeriverEnvelopeCommonV1 {
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
                "Router A/B ECDSA derivation Deriver plaintext recipient role does not match envelope",
            ));
        }
        if envelope.aad_digest != common.aad_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "Router A/B ECDSA derivation Deriver plaintext AAD digest does not match envelope",
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
            ROUTER_AB_ECDSA_DERIVATION_DERIVER_ENVELOPE_PLAINTEXT_VERSION_V1,
        );
        push_len32(&mut out, self.request_kind().as_str().as_bytes());
        push_len32(&mut out, self.output_kind().as_str().as_bytes());
        push_deriver_envelope_common(&mut out, self.common())?;
        match self {
            Self::RegistrationBootstrap(plaintext) => {
                push_len32(&mut out, plaintext.registration_purpose.as_str().as_bytes());
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

/// Shared public fields bound into every Router A/B ECDSA derivation Deriver envelope plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationDeriverEnvelopeCommonV1 {
    /// Stable Router A/B ECDSA derivation context.
    pub context: RouterAbEcdsaDerivationStableKeyContextV1,
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
    /// Digest of the originating public request header before role envelopes are sealed.
    pub request_header_digest: PublicDigest32,
    /// Digest of the associated data used to encrypt the outer role envelope.
    pub aad_digest: PublicDigest32,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl RouterAbEcdsaDerivationDeriverEnvelopeCommonV1 {
    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        context: RouterAbEcdsaDerivationStableKeyContextV1,
        lifecycle: LifecycleScopeV1,
        signer_set: SignerSetV1,
        recipient_role: Role,
        router_id: String,
        client_id: String,
        recipient_ephemeral_public_key: String,
        request_header_digest: PublicDigest32,
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
            request_header_digest,
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
                "Router A/B ECDSA derivation Deriver plaintext recipient does not match signer set",
            ));
        }
        if self.lifecycle.signer_set_id != self.signer_set.signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation Deriver plaintext lifecycle signer set does not match signer set",
            ));
        }
        if self.lifecycle.selected_server_id != self.signer_set.selected_server.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation Deriver plaintext lifecycle selected server does not match signer set",
            ));
        }
        Ok(())
    }
}

/// Registration/bootstrap Deriver plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationDeriverRegistrationEnvelopePlaintextV1 {
    /// Shared public Deriver envelope metadata.
    pub common: RouterAbEcdsaDerivationDeriverEnvelopeCommonV1,
    /// Registration/bootstrap must produce SigningWorker activation material.
    pub output_kind: RouterAbEcdsaDerivationOutputKindV1,
    /// Product lifecycle that requested this activation material.
    pub registration_purpose: RouterAbEcdsaDerivationRegistrationPurposeV1,
}

impl RouterAbEcdsaDerivationDeriverRegistrationEnvelopePlaintextV1 {
    /// Validates registration/bootstrap Deriver plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.common
            .validate_for_work_kind(ExpensiveWorkKindV1::RegistrationPrepare)?;
        require_output_kind(
            "registration_deriver_plaintext.output_kind",
            self.output_kind,
            RouterAbEcdsaDerivationOutputKindV1::SigningWorkerActivation,
        )?;
        Ok(())
    }
}

/// Explicit-export Deriver plaintext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationDeriverExportEnvelopePlaintextV1 {
    /// Shared public Deriver envelope metadata.
    pub common: RouterAbEcdsaDerivationDeriverEnvelopeCommonV1,
    /// Explicit export must produce client-recipient export material.
    pub output_kind: RouterAbEcdsaDerivationOutputKindV1,
    /// Public identity being exported.
    pub public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
    /// User-confirmed export authorization digest encoded as unpadded base64url.
    pub export_authorization_digest_b64u: String,
    /// Request-scoped export replay nonce.
    pub export_nonce: String,
}

impl RouterAbEcdsaDerivationDeriverExportEnvelopePlaintextV1 {
    /// Validates explicit-export Deriver plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.common
            .validate_for_work_kind(ExpensiveWorkKindV1::KeyExport)?;
        require_output_kind(
            "export_deriver_plaintext.output_kind",
            self.output_kind,
            RouterAbEcdsaDerivationOutputKindV1::ClientExport,
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
pub struct RouterAbEcdsaDerivationDeriverRecoveryEnvelopePlaintextV1 {
    /// Shared public Deriver envelope metadata.
    pub common: RouterAbEcdsaDerivationDeriverEnvelopeCommonV1,
    /// Recovery must produce client-recipient recovery/export material.
    pub output_kind: RouterAbEcdsaDerivationOutputKindV1,
    /// Public identity being recovered.
    pub public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
    /// User-confirmed recovery authorization digest encoded as unpadded base64url.
    pub recovery_authorization_digest_b64u: String,
    /// Request-scoped recovery replay nonce.
    pub recovery_nonce: String,
}

impl RouterAbEcdsaDerivationDeriverRecoveryEnvelopePlaintextV1 {
    /// Validates recovery Deriver plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.common
            .validate_for_work_kind(ExpensiveWorkKindV1::Recovery)?;
        require_output_kind(
            "recovery_deriver_plaintext.output_kind",
            self.output_kind,
            RouterAbEcdsaDerivationOutputKindV1::ClientExport,
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
pub struct RouterAbEcdsaDerivationDeriverRefreshEnvelopePlaintextV1 {
    /// Shared public Deriver envelope metadata.
    pub common: RouterAbEcdsaDerivationDeriverEnvelopeCommonV1,
    /// Refresh must produce SigningWorker activation material for the next epoch.
    pub output_kind: RouterAbEcdsaDerivationOutputKindV1,
    /// Public identity that must remain stable across refresh.
    pub public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
    /// Authorization digest for the refresh operation.
    pub refresh_authorization_digest_b64u: String,
    /// Request-scoped refresh replay nonce.
    pub refresh_nonce: String,
    /// Activation epoch currently considered active by the Router.
    pub previous_activation_epoch: String,
    /// Activation epoch to be installed by the SigningWorker.
    pub next_activation_epoch: String,
}

impl RouterAbEcdsaDerivationDeriverRefreshEnvelopePlaintextV1 {
    /// Validates activation-refresh Deriver plaintext.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.common
            .validate_for_work_kind(ExpensiveWorkKindV1::ServerShareRefresh)?;
        require_output_kind(
            "refresh_deriver_plaintext.output_kind",
            self.output_kind,
            RouterAbEcdsaDerivationOutputKindV1::SigningWorkerActivation,
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
                "Router A/B ECDSA derivation Deriver refresh plaintext must advance activation epoch",
            ));
        }
        if self.common.lifecycle.root_share_epoch.as_str() != self.next_activation_epoch {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation Deriver refresh plaintext lifecycle root epoch must equal next activation epoch",
            ));
        }
        Ok(())
    }
}

/// Signature algorithm returned by the Router A/B ECDSA derivation digest-signing path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouterAbEcdsaDerivationSignatureSchemeV1 {
    /// Recoverable secp256k1 signature bytes: `r(32) || s(32) || recid(1)`.
    EcdsaSecp256k1RecoverableV1,
}

/// Router A/B ECDSA derivation stable context bound into registration, export, recovery, and refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationStableKeyContextV1 {
    /// SDK-owned application binding digest encoded as unpadded base64url.
    pub application_binding_digest_b64u: String,
}

impl RouterAbEcdsaDerivationStableKeyContextV1 {
    /// Creates a validated Router A/B ECDSA derivation stable key context.
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
        out.extend_from_slice(ROUTER_AB_ECDSA_DERIVATION_CONTEXT_DOMAIN_TAG_V1);
        push_ascii_u16(&mut out, ROUTER_AB_ECDSA_DERIVATION_SCHEME_ID_V1)?;
        push_ascii_u16(&mut out, ROUTER_AB_ECDSA_DERIVATION_CURVE_V1)?;
        out.extend_from_slice(&decode_base64url_fixed_32(
            "context.application_binding_digest_b64u",
            &self.application_binding_digest_b64u,
        )?);
        out.push(ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS_V1.len() as u8);
        for participant_id in ROUTER_AB_ECDSA_DERIVATION_PARTICIPANT_IDS_V1 {
            out.extend_from_slice(&participant_id.to_be_bytes());
        }
        Ok(out)
    }

    /// Returns the context-binding digest.
    pub fn context_binding_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        let context_bytes = self.canonical_context_bytes()?;
        Ok(public_digest(
            &router_ab_ecdsa_derivation_context_binding_frame(&context_bytes)?,
        ))
    }
}

/// Returns the active SigningWorker session id for one Router A/B ECDSA derivation activation epoch.
pub fn router_ab_ecdsa_derivation_active_state_session_id_v1(
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

/// Public ECDSA identity produced by Router A/B ECDSA derivation registration/activation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationPublicIdentityV1 {
    /// Context-binding digest encoded as unpadded base64url.
    pub context_binding_b64u: String,
    /// Client compressed secp256k1 public key encoded as unpadded base64url.
    pub derivation_client_share_public_key33_b64u: String,
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

impl RouterAbEcdsaDerivationPublicIdentityV1 {
    /// Creates a validated public identity.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context_binding_b64u: impl Into<String>,
        derivation_client_share_public_key33_b64u: impl Into<String>,
        server_public_key33_b64u: impl Into<String>,
        threshold_public_key33_b64u: impl Into<String>,
        ethereum_address20_b64u: impl Into<String>,
        client_share_retry_counter: u32,
        server_share_retry_counter: u32,
    ) -> RouterAbProtocolResult<Self> {
        let identity = Self {
            context_binding_b64u: context_binding_b64u.into(),
            derivation_client_share_public_key33_b64u: derivation_client_share_public_key33_b64u
                .into(),
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
            "public_identity.derivation_client_share_public_key33_b64u",
            &self.derivation_client_share_public_key33_b64u,
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
        context: &RouterAbEcdsaDerivationStableKeyContextV1,
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
            "Router A/B ECDSA derivation public identity context binding does not match context",
        ))
    }

    /// Returns canonical public identity bytes.
    pub fn canonical_public_identity_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_DERIVATION_PUBLIC_IDENTITY_VERSION_V1,
        );
        push_len32(&mut out, self.context_binding_b64u.as_bytes());
        push_len32(
            &mut out,
            self.derivation_client_share_public_key33_b64u.as_bytes(),
        );
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

/// Public registration fields that are committed before role envelopes are sealed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationRegistrationHeaderV1 {
    /// Product lifecycle that owns this registration/bootstrap.
    pub registration_purpose: RouterAbEcdsaDerivationRegistrationPurposeV1,
    /// Stable Router A/B ECDSA derivation context.
    pub context: RouterAbEcdsaDerivationStableKeyContextV1,
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
}

impl RouterAbEcdsaDerivationRegistrationHeaderV1 {
    /// Validates public registration fields before any encryption work is performed.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.context.validate()?;
        self.lifecycle.validate()?;
        validate_lifecycle_work_kind(
            "registration.lifecycle",
            &self.lifecycle,
            ExpensiveWorkKindV1::RegistrationPrepare,
        )?;
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
        Ok(())
    }

    /// Returns canonical pre-envelope header bytes.
    pub fn canonical_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_DERIVATION_REGISTRATION_REQUEST_VERSION_V1,
        );
        push_len32(&mut out, self.registration_purpose.as_str().as_bytes());
        push_len32(&mut out, &self.context.canonical_context_bytes()?);
        push_lifecycle_scope(&mut out, &self.lifecycle);
        push_signer_set(&mut out, &self.signer_set);
        push_len32(&mut out, self.router_id.as_bytes());
        push_len32(&mut out, self.client_id.as_bytes());
        push_len32(&mut out, self.client_ephemeral_public_key.as_bytes());
        push_len32(&mut out, self.replay_nonce.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        Ok(out)
    }

    /// Returns the pre-envelope digest used by HPKE AAD and encrypted plaintext.
    pub fn digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_bytes()?))
    }

    /// Returns the threshold-PRF transcript digest derived from public header fields.
    pub fn transcript_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        EcdsaThresholdPrfRequestContextV1::new(
            self.replay_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
            self.context.application_binding_digest_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
        )?
        .derivation_transcript_digest()
    }

    /// Returns role-specific AAD that commits the pre-envelope header digest.
    pub fn role_aad(&self, role: Role) -> RouterAbProtocolResult<RoleEnvelopeAadV1> {
        let recipient = recipient_deriver_for_role(&self.signer_set, role)?;
        RoleEnvelopeAadV1::new(
            self.lifecycle.lifecycle_id.clone(),
            self.lifecycle.work_kind,
            self.signer_set.signer_set_id.clone(),
            recipient,
            self.signer_set.selected_server.clone(),
            self.transcript_digest()?,
            self.digest()?,
            self.expires_at_ms,
        )
    }
}

/// Client-facing typed Router A/B ECDSA derivation registration/bootstrap request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
    /// Product lifecycle that owns this registration/bootstrap.
    pub registration_purpose: RouterAbEcdsaDerivationRegistrationPurposeV1,
    /// Stable Router A/B ECDSA derivation context.
    pub context: RouterAbEcdsaDerivationStableKeyContextV1,
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
    /// Deriver A encrypted Router A/B ECDSA derivation bootstrap envelope.
    pub deriver_a_envelope: RoleEncryptedEnvelopeV1,
    /// Deriver B encrypted Router A/B ECDSA derivation bootstrap envelope.
    pub deriver_b_envelope: RoleEncryptedEnvelopeV1,
}

impl RouterAbEcdsaDerivationRegistrationBootstrapRequestV1 {
    /// Creates a validated registration/bootstrap request.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        registration_purpose: RouterAbEcdsaDerivationRegistrationPurposeV1,
        context: RouterAbEcdsaDerivationStableKeyContextV1,
        lifecycle: LifecycleScopeV1,
        signer_set: SignerSetV1,
        router_id: impl Into<String>,
        client_id: impl Into<String>,
        client_ephemeral_public_key: impl Into<String>,
        replay_nonce: impl Into<String>,
        expires_at_ms: u64,
        deriver_a_envelope: RoleEncryptedEnvelopeV1,
        deriver_b_envelope: RoleEncryptedEnvelopeV1,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            registration_purpose,
            context,
            lifecycle,
            signer_set,
            router_id: router_id.into(),
            client_id: client_id.into(),
            client_ephemeral_public_key: client_ephemeral_public_key.into(),
            replay_nonce: replay_nonce.into(),
            expires_at_ms,
            deriver_a_envelope,
            deriver_b_envelope,
        };
        request.validate()?;
        Ok(request)
    }

    /// Returns the public header that a client commits before sealing role envelopes.
    pub fn header(&self) -> RouterAbEcdsaDerivationRegistrationHeaderV1 {
        RouterAbEcdsaDerivationRegistrationHeaderV1 {
            registration_purpose: self.registration_purpose,
            context: self.context.clone(),
            lifecycle: self.lifecycle.clone(),
            signer_set: self.signer_set.clone(),
            router_id: self.router_id.clone(),
            client_id: self.client_id.clone(),
            client_ephemeral_public_key: self.client_ephemeral_public_key.clone(),
            replay_nonce: self.replay_nonce.clone(),
            expires_at_ms: self.expires_at_ms,
        }
    }

    /// Validates the request without consulting clock state.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.header().validate()?;
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

    /// Validates the request at a route dedicated to one registration purpose.
    pub fn validate_for_registration_purpose(
        &self,
        expected: RouterAbEcdsaDerivationRegistrationPurposeV1,
    ) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if self.registration_purpose != expected {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                format!(
                    "Router A/B ECDSA derivation registration purpose {} cannot enter the {} route",
                    self.registration_purpose.as_str(),
                    expected.as_str(),
                ),
            ));
        }
        Ok(())
    }

    /// Validates the request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router A/B ECDSA derivation registration request expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical registration header bytes before role envelopes are sealed.
    pub fn canonical_request_header_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.header().canonical_bytes()
    }

    /// Returns the pre-envelope registration header digest used by HPKE AAD and plaintext.
    pub fn request_header_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        self.header().digest()
    }

    /// Returns canonical registration request bytes including sealed role envelopes.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        let mut out = self.canonical_request_header_bytes()?;
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
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
            self.context.application_binding_digest_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
        )?;
        EcdsaThresholdPrfRequestV1::new(
            self.replay_nonce.clone(),
            self.expires_at_ms,
            self.lifecycle.clone(),
            self.signer_set.clone(),
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
            self.context.application_binding_digest_b64u.clone(),
            self.router_id.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
            context.derivation_transcript_digest()?,
            self.deriver_a_envelope.clone(),
            self.deriver_b_envelope.clone(),
        )
    }
}

/// SigningWorker activation receipt for a Router A/B ECDSA derivation registration/bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationActivationReceiptV1 {
    /// Stable Router A/B ECDSA derivation context.
    pub context: RouterAbEcdsaDerivationStableKeyContextV1,
    /// Public identity activated for normal signing.
    pub public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
    /// SigningWorker identity that accepted activation.
    pub signing_worker: ServerIdentityV1,
    /// Activation epoch persisted by the SigningWorker.
    pub activation_epoch: String,
    /// Digest of the activation payload encoded as unpadded base64url.
    pub activation_digest_b64u: String,
    /// Activation timestamp in Unix milliseconds.
    pub activated_at_ms: u64,
}

impl RouterAbEcdsaDerivationActivationReceiptV1 {
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

/// Client-facing typed Router A/B ECDSA derivation explicit export request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationExplicitExportRequestV1 {
    /// Stable Router A/B ECDSA derivation context.
    pub context: RouterAbEcdsaDerivationStableKeyContextV1,
    /// Router lifecycle scope for the A/B export ceremony.
    pub lifecycle: LifecycleScopeV1,
    /// Public identity being exported.
    pub public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
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
    /// Deriver A encrypted Router A/B ECDSA derivation export envelope.
    pub deriver_a_export_envelope: RoleEncryptedEnvelopeV1,
    /// Deriver B encrypted Router A/B ECDSA derivation export envelope.
    pub deriver_b_export_envelope: RoleEncryptedEnvelopeV1,
}

impl RouterAbEcdsaDerivationExplicitExportRequestV1 {
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
                "Router A/B ECDSA derivation export request expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical export header bytes before role envelopes are sealed.
    pub fn canonical_request_header_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_DERIVATION_EXPORT_REQUEST_VERSION_V1,
        );
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
        Ok(out)
    }

    /// Returns the pre-envelope export header digest used by HPKE AAD and plaintext.
    pub fn request_header_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_header_bytes()?))
    }

    /// Returns canonical export request bytes including sealed role envelopes.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        let mut out = self.canonical_request_header_bytes()?;
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
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
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
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
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

/// Client-facing typed Router A/B ECDSA derivation recovery request.
///
/// Recovery uses the same primitive derivation class as export, but its
/// transcript domain, authorization digest, nonce, and envelope labels remain
/// recovery-specific.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationRecoveryRequestV1 {
    /// Stable Router A/B ECDSA derivation context.
    pub context: RouterAbEcdsaDerivationStableKeyContextV1,
    /// Router lifecycle scope for the A/B recovery ceremony.
    pub lifecycle: LifecycleScopeV1,
    /// Public identity being recovered.
    pub public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
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
    /// Deriver A encrypted Router A/B ECDSA derivation recovery envelope.
    pub deriver_a_recovery_envelope: RoleEncryptedEnvelopeV1,
    /// Deriver B encrypted Router A/B ECDSA derivation recovery envelope.
    pub deriver_b_recovery_envelope: RoleEncryptedEnvelopeV1,
}

impl RouterAbEcdsaDerivationRecoveryRequestV1 {
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
                "Router A/B ECDSA derivation recovery request expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical recovery header bytes before role envelopes are sealed.
    pub fn canonical_request_header_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_DERIVATION_RECOVERY_REQUEST_VERSION_V1,
        );
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
        Ok(out)
    }

    /// Returns the pre-envelope recovery header digest used by HPKE AAD and plaintext.
    pub fn request_header_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_header_bytes()?))
    }

    /// Returns canonical recovery request bytes including sealed role envelopes.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        let mut out = self.canonical_request_header_bytes()?;
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
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
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
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
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

/// Client-facing typed Router A/B ECDSA derivation SigningWorker activation-refresh request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationActivationRefreshRequestV1 {
    /// Stable Router A/B ECDSA derivation context.
    pub context: RouterAbEcdsaDerivationStableKeyContextV1,
    /// Router lifecycle scope for the A/B refresh ceremony.
    pub lifecycle: LifecycleScopeV1,
    /// Public identity that must remain stable across refresh.
    pub public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
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
    /// Deriver A encrypted Router A/B ECDSA derivation refresh envelope.
    pub deriver_a_refresh_envelope: RoleEncryptedEnvelopeV1,
    /// Deriver B encrypted Router A/B ECDSA derivation refresh envelope.
    pub deriver_b_refresh_envelope: RoleEncryptedEnvelopeV1,
}

impl RouterAbEcdsaDerivationActivationRefreshRequestV1 {
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
                "Router A/B ECDSA derivation refresh must advance activation epoch",
            ));
        }
        if self.lifecycle.root_share_epoch.as_str() != self.next_activation_epoch {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "Router A/B ECDSA derivation refresh lifecycle root epoch must equal next activation epoch",
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
                "Router A/B ECDSA derivation refresh request expired",
            ));
        }
        Ok(())
    }

    /// Returns canonical refresh header bytes before role envelopes are sealed.
    pub fn canonical_request_header_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_DERIVATION_REFRESH_REQUEST_VERSION_V1,
        );
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
        Ok(out)
    }

    /// Returns the pre-envelope refresh header digest used by HPKE AAD and plaintext.
    pub fn request_header_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_header_bytes()?))
    }

    /// Returns canonical refresh request bytes including sealed role envelopes.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        let mut out = self.canonical_request_header_bytes()?;
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
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
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
            ROUTER_AB_ECDSA_DERIVATION_KEY_SCOPE_V1.to_owned(),
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
pub struct RouterAbEcdsaDerivationNormalSigningScopeV1 {
    /// Stable wallet key id used by the SDK.
    pub wallet_key_id: String,
    /// Wallet id that owns this Router A/B ECDSA derivation key.
    pub wallet_id: String,
    /// Stable threshold ECDSA key id.
    pub ecdsa_threshold_key_id: String,
    /// Signing root id.
    pub signing_root_id: String,
    /// Signing root version.
    pub signing_root_version: String,
    /// Digest-only Router A/B ECDSA derivation context.
    pub context: RouterAbEcdsaDerivationStableKeyContextV1,
    /// Public identity expected for the active signing key.
    pub public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
    /// SigningWorker identity that owns activation state.
    pub signing_worker: ServerIdentityV1,
    /// Activation epoch persisted by the SigningWorker.
    pub activation_epoch: String,
}

impl RouterAbEcdsaDerivationNormalSigningScopeV1 {
    /// Creates a validated normal-signing scope.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        wallet_key_id: impl Into<String>,
        wallet_id: impl Into<String>,
        ecdsa_threshold_key_id: impl Into<String>,
        signing_root_id: impl Into<String>,
        signing_root_version: impl Into<String>,
        context: RouterAbEcdsaDerivationStableKeyContextV1,
        public_identity: RouterAbEcdsaDerivationPublicIdentityV1,
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
            ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_SCOPE_VERSION_V1,
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
        router_ab_ecdsa_derivation_active_state_session_id_v1(
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

/// Commits to the Client contribution before SigningWorker entropy is revealed.
pub fn router_ab_ecdsa_rerandomization_client_commitment_v1(contribution32: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ROUTER_AB_ECDSA_DERIVATION_CLIENT_RERANDOMIZATION_COMMITMENT_DOMAIN_V1);
    hasher.update(contribution32);
    hasher.finalize().into()
}

/// Client-facing typed Router A/B ECDSA derivation normal-signing request after Router parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    /// Request id used for replay, quota, and audit correlation.
    pub request_id: String,
    /// Client-held presignature id that must match the SigningWorker server share.
    pub client_presignature_id: String,
    /// Request expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Exact 32-byte EVM/secp256k1 digest encoded as unpadded base64url.
    pub signing_digest_b64u: String,
    /// Commitment to the Client's hidden 32-byte rerandomization contribution.
    pub client_rerandomization_commitment32_b64u: String,
}

impl RouterAbEcdsaDerivationEvmDigestSigningRequestV1 {
    /// Creates a validated Router A/B ECDSA derivation normal-signing request.
    pub fn new(
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        request_id: impl Into<String>,
        client_presignature_id: impl Into<String>,
        expires_at_ms: u64,
        signing_digest_b64u: impl Into<String>,
        client_rerandomization_commitment32_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            request_id: request_id.into(),
            client_presignature_id: client_presignature_id.into(),
            expires_at_ms,
            signing_digest_b64u: signing_digest_b64u.into(),
            client_rerandomization_commitment32_b64u: client_rerandomization_commitment32_b64u
                .into(),
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
        self.client_rerandomization_commitment32()?;
        Ok(())
    }

    /// Validates the typed normal-signing request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router A/B ECDSA derivation normal-signing request expired",
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

    /// Returns the Client contribution commitment admitted by prepare.
    pub fn client_rerandomization_commitment32(&self) -> RouterAbProtocolResult<[u8; 32]> {
        decode_base64url_fixed_32(
            "normal_signing.client_rerandomization_commitment32_b64u",
            &self.client_rerandomization_commitment32_b64u,
        )
    }

    /// Returns canonical request bytes for transcript/replay binding.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_REQUEST_VERSION_V1,
        );
        push_len32(&mut out, &self.scope.canonical_scope_bytes()?);
        push_len32(&mut out, self.request_id.as_bytes());
        push_len32(&mut out, self.client_presignature_id.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        push_digest(&mut out, self.signing_digest()?);
        push_len32(&mut out, &self.client_rerandomization_commitment32()?);
        Ok(out)
    }

    /// Returns the canonical request digest.
    pub fn request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_bytes()?))
    }
}

/// Client-facing Router A/B ECDSA derivation finalize request carrying the client signature share.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
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
    /// Client's 32-byte rerandomization contribution that opens the prepare commitment.
    pub client_rerandomization_contribution32_b64u: String,
}

impl RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1 {
    /// Creates a validated Router A/B ECDSA derivation finalize request.
    pub fn new(
        scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
        request_id: impl Into<String>,
        expires_at_ms: u64,
        signing_digest_b64u: impl Into<String>,
        server_presignature_id: impl Into<String>,
        client_signature_share32_b64u: impl Into<String>,
        client_rerandomization_contribution32_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let request = Self {
            scope,
            request_id: request_id.into(),
            expires_at_ms,
            signing_digest_b64u: signing_digest_b64u.into(),
            server_presignature_id: server_presignature_id.into(),
            client_signature_share32_b64u: client_signature_share32_b64u.into(),
            client_rerandomization_contribution32_b64u: client_rerandomization_contribution32_b64u
                .into(),
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
        self.client_rerandomization_contribution32()?;
        Ok(())
    }

    /// Validates the finalize request against Router time.
    pub fn validate_at(&self, now_unix_ms: u64) -> RouterAbProtocolResult<()> {
        self.validate()?;
        if now_unix_ms >= self.expires_at_ms {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::ExpiredLocalRequest,
                "Router A/B ECDSA derivation normal-signing finalize request expired",
            ));
        }
        Ok(())
    }

    /// Returns the corresponding prepare request identity and digest material.
    pub fn prepare_request(
        &self,
    ) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningRequestV1> {
        let commitment = router_ab_ecdsa_rerandomization_client_commitment_v1(
            self.client_rerandomization_contribution32()?,
        );
        RouterAbEcdsaDerivationEvmDigestSigningRequestV1::new(
            self.scope.clone(),
            self.request_id.clone(),
            self.server_presignature_id.clone(),
            self.expires_at_ms,
            self.signing_digest_b64u.clone(),
            Base64UrlUnpadded::encode_string(&commitment),
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

    /// Returns the Client contribution that must open the prepare commitment.
    pub fn client_rerandomization_contribution32(&self) -> RouterAbProtocolResult<[u8; 32]> {
        decode_base64url_fixed_32(
            "ecdsa_finalize.client_rerandomization_contribution32_b64u",
            &self.client_rerandomization_contribution32_b64u,
        )
    }

    /// Returns canonical finalize request bytes for transcript/replay binding.
    pub fn canonical_request_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        self.validate()?;
        let mut out = Vec::new();
        push_len32(
            &mut out,
            ROUTER_AB_ECDSA_DERIVATION_NORMAL_SIGNING_FINALIZE_REQUEST_VERSION_V1,
        );
        push_len32(&mut out, &self.scope.canonical_scope_bytes()?);
        push_len32(&mut out, self.request_id.as_bytes());
        push_u64(&mut out, self.expires_at_ms);
        push_digest(&mut out, self.signing_digest()?);
        push_len32(&mut out, self.server_presignature_id.as_bytes());
        push_len32(&mut out, &self.client_signature_share32()?);
        push_len32(&mut out, &self.client_rerandomization_contribution32()?);
        Ok(out)
    }

    /// Returns the canonical finalize request digest.
    pub fn request_digest(&self) -> RouterAbProtocolResult<PublicDigest32> {
        Ok(public_digest(&self.canonical_request_bytes()?))
    }
}

/// Public response for a Router A/B ECDSA derivation EVM digest-signing prepare request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    /// Request id accepted by the Router.
    pub request_id: String,
    /// Canonical prepare request digest accepted by the SigningWorker.
    pub request_digest: PublicDigest32,
    /// Exact digest admitted for Router A/B ECDSA derivation signing.
    pub signing_digest: PublicDigest32,
    /// SigningWorker-local presignature id consumed by finalize.
    pub server_presignature_id: String,
    /// Server public presignature point encoded as compressed secp256k1 bytes.
    pub server_big_r33_b64u: String,
    /// SigningWorker's 32-byte contribution revealed after the Client commitment.
    pub signing_worker_rerandomization_contribution32_b64u: String,
    /// Signature algorithm supported by the prepared state.
    pub signature_scheme: RouterAbEcdsaDerivationSignatureSchemeV1,
    /// Prepare timestamp in Unix milliseconds.
    pub prepared_at_ms: u64,
    /// Expiry timestamp in Unix milliseconds.
    pub expires_at_ms: u64,
}

impl RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1 {
    /// Creates a validated response bound to a typed Router A/B ECDSA derivation prepare request.
    pub fn new_for_request(
        request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
        server_presignature_id: impl Into<String>,
        server_big_r33_b64u: impl Into<String>,
        signing_worker_rerandomization_contribution32_b64u: impl Into<String>,
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
            signing_worker_rerandomization_contribution32_b64u:
                signing_worker_rerandomization_contribution32_b64u.into(),
            signature_scheme: RouterAbEcdsaDerivationSignatureSchemeV1::EcdsaSecp256k1RecoverableV1,
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
            "ecdsa_prepare_response.signing_worker_rerandomization_contribution32_b64u",
            &self.signing_worker_rerandomization_contribution32_b64u,
        )?;
        require_positive_ms("ecdsa_prepare_response.prepared_at_ms", self.prepared_at_ms)?;
        require_positive_ms("ecdsa_prepare_response.expires_at_ms", self.expires_at_ms)?;
        if self.expires_at_ms > self.prepared_at_ms {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidTimeRange,
            "Router A/B ECDSA derivation prepare response expiry must be after prepare time",
        ))
    }

    /// Validates the response is bound to the exact prepare request.
    pub fn validate_for_request(
        &self,
        request: &RouterAbEcdsaDerivationEvmDigestSigningRequestV1,
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
            "Router A/B ECDSA derivation prepare response does not match request",
        ))
    }
}

/// Public response for a Router A/B ECDSA derivation EVM digest-signing request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouterAbEcdsaDerivationEvmDigestSigningResponseV1 {
    /// Normal-signing identity and active SigningWorker scope.
    pub scope: RouterAbEcdsaDerivationNormalSigningScopeV1,
    /// Request id accepted by the Router.
    pub request_id: String,
    /// Canonical request digest accepted by the SigningWorker.
    pub request_digest: PublicDigest32,
    /// Exact digest signed by the Router A/B ECDSA derivation key.
    pub signing_digest: PublicDigest32,
    /// Signature algorithm used by this response.
    pub signature_scheme: RouterAbEcdsaDerivationSignatureSchemeV1,
    /// Recoverable signature bytes encoded as unpadded base64url.
    pub signature65_b64u: String,
}

impl RouterAbEcdsaDerivationEvmDigestSigningResponseV1 {
    /// Creates a validated response bound to a typed Router A/B ECDSA derivation finalize request.
    pub fn new_for_request(
        request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
        signature65_b64u: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        request.validate()?;
        let response = Self {
            scope: request.scope.clone(),
            request_id: request.request_id.clone(),
            request_digest: request.request_digest()?,
            signing_digest: request.signing_digest()?,
            signature_scheme: RouterAbEcdsaDerivationSignatureSchemeV1::EcdsaSecp256k1RecoverableV1,
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
        request: &RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1,
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
            "Router A/B ECDSA derivation signing response does not match request",
        ))
    }
}

/// Parses and validates a raw JSON Router A/B ECDSA derivation registration/bootstrap request.
pub fn parse_router_ab_ecdsa_derivation_registration_bootstrap_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationRegistrationBootstrapRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaDerivationRegistrationBootstrapRequestV1>(
        "Router A/B ECDSA derivation registration/bootstrap request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates decrypted Router A/B ECDSA derivation Deriver envelope plaintext JSON.
pub fn parse_router_ab_ecdsa_derivation_deriver_envelope_plaintext_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1> {
    let plaintext = parse_boundary_json::<RouterAbEcdsaDerivationDeriverEnvelopePlaintextV1>(
        "Router A/B ECDSA derivation Deriver envelope plaintext",
        bytes,
    )?;
    plaintext.validate()?;
    Ok(plaintext)
}

/// Parses and validates a raw JSON Router A/B ECDSA derivation explicit export request.
pub fn parse_router_ab_ecdsa_derivation_explicit_export_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationExplicitExportRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaDerivationExplicitExportRequestV1>(
        "Router A/B ECDSA derivation explicit export request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON Router A/B ECDSA derivation recovery request.
pub fn parse_router_ab_ecdsa_derivation_recovery_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationRecoveryRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaDerivationRecoveryRequestV1>(
        "Router A/B ECDSA derivation recovery request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON Router A/B ECDSA derivation activation-refresh request.
pub fn parse_router_ab_ecdsa_derivation_activation_refresh_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationActivationRefreshRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaDerivationActivationRefreshRequestV1>(
        "Router A/B ECDSA derivation activation refresh request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON Router A/B ECDSA derivation normal-signing scope.
pub fn parse_router_ab_ecdsa_derivation_normal_signing_scope_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationNormalSigningScopeV1> {
    let scope = parse_boundary_json::<RouterAbEcdsaDerivationNormalSigningScopeV1>(
        "Router A/B ECDSA derivation normal signing scope",
        bytes,
    )?;
    scope.validate()?;
    Ok(scope)
}

/// Parses and validates a raw JSON Router A/B ECDSA derivation normal-signing request.
pub fn parse_router_ab_ecdsa_derivation_evm_digest_signing_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaDerivationEvmDigestSigningRequestV1>(
        "Router A/B ECDSA derivation normal signing request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON Router A/B ECDSA derivation normal-signing finalize request.
pub fn parse_router_ab_ecdsa_derivation_evm_digest_signing_finalize_request_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1> {
    let request = parse_boundary_json::<RouterAbEcdsaDerivationEvmDigestSigningFinalizeRequestV1>(
        "Router A/B ECDSA derivation normal signing finalize request",
        bytes,
    )?;
    request.validate()?;
    Ok(request)
}

/// Parses and validates a raw JSON Router A/B ECDSA derivation normal-signing prepare response.
pub fn parse_router_ab_ecdsa_derivation_evm_digest_signing_prepare_response_v1_json(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1> {
    let response = parse_boundary_json::<RouterAbEcdsaDerivationEvmDigestSigningPrepareResponseV1>(
        "Router A/B ECDSA derivation normal signing prepare response",
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
    common: &RouterAbEcdsaDerivationDeriverEnvelopeCommonV1,
) -> RouterAbProtocolResult<()> {
    common.validate()?;
    push_len32(out, &common.context.canonical_context_bytes()?);
    push_lifecycle_scope(out, &common.lifecycle);
    push_signer_set(out, &common.signer_set);
    push_signer_identity(out, &common.recipient_deriver);
    push_len32(out, common.router_id.as_bytes());
    push_len32(out, common.client_id.as_bytes());
    push_len32(out, common.recipient_ephemeral_public_key.as_bytes());
    push_digest(out, common.request_header_digest);
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

fn router_ab_ecdsa_derivation_context_binding_frame(
    context_bytes: &[u8],
) -> RouterAbProtocolResult<Vec<u8>> {
    let len = u16::try_from(context_bytes.len()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router A/B ECDSA derivation context bytes exceed u16 length encoding",
        )
    })?;
    let mut out = Vec::new();
    out.extend_from_slice(ROUTER_AB_ECDSA_DERIVATION_CONTEXT_BINDING_DOMAIN_V1);
    out.push(1);
    out.push(ROUTER_AB_ECDSA_DERIVATION_CONTEXT_FIELD_BYTES_V1);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(context_bytes);
    Ok(out)
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_ascii_u16(out: &mut Vec<u8>, value: &str) -> RouterAbProtocolResult<()> {
    require_ascii_non_empty("Router A/B ECDSA derivation context string", value)?;
    let len = u16::try_from(value.len()).map_err(|_| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "Router A/B ECDSA derivation context string exceeds u16 length encoding",
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
    actual: RouterAbEcdsaDerivationOutputKindV1,
    expected: RouterAbEcdsaDerivationOutputKindV1,
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
            "Router A/B ECDSA derivation Deriver envelope recipient must be Signer A or Signer B",
        )),
    }
}

fn validate_lifecycle_for_context(
    field: &str,
    lifecycle: &LifecycleScopeV1,
    context: &RouterAbEcdsaDerivationStableKeyContextV1,
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
