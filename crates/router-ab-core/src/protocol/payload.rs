use crate::derivation::{
    transcript_digest_v1, verify_mpc_prf_stable_partial_with_threshold_backend_v2, AccountScope,
    DerivationContext, MpcPrfDleqProofWireV1, MpcPrfOutputRequestV1, MpcPrfPartialBindingV1,
    MpcPrfPartialProofBundleV1, MpcPrfPartialWireV1, MpcPrfShareCommitmentWireV1,
    MpcPrfSignerPartialInputV1, MpcPrfSignerPartialV1, MpcPrfStablePartialProofBundleV2,
    MpcPrfStablePurposeBindingPlanV2, MpcPrfThresholdSignerBatchOutputV1, OpenedShareKind,
    PublicDigest32, RequestKind, Role, RootShareEpoch, RouterAbDerivationError,
    SignerInputPlaintextV1, SignerSetBinding, TenantRootProtocolDigestV1, TranscriptBinding,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use threshold_prf::PrfPurpose;

use crate::protocol::envelope::{
    role_encrypted_envelope_digest_v1, EncryptedPayloadV1, RoleEncryptedEnvelopeV1,
};
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::gate::ExpensiveWorkKindV1;
use crate::protocol::identity::{
    RoleEnvelopeAssignmentV1, ServerIdentityV1, SignerIdentityV1, SignerSetPolicyV1, SignerSetV1,
};
use crate::protocol::lifecycle::LifecycleScopeV1;
use crate::protocol::wire::CanonicalWireBytesV1;

const ROUTER_TO_SIGNER_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/router-to-signer-payload/v1";
const AB_PEER_MESSAGE_PAYLOAD_VERSION_V1: &[u8] = b"router-ab-protocol/ab-peer-message-payload/v1";
const AB_PEER_MESSAGE_AUTHENTICATION_INPUT_VERSION_V1: &[u8] =
    b"router-ab-protocol/ab-peer-message-authentication-input/v1";
const ECDSA_THRESHOLD_PRF_PROOF_BATCH_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/ecdsa-threshold-prf-proof-batch-payload/v1";
const RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-proof-bundle-payload/v1";
const MPC_PRF_STABLE_PROOF_BUNDLE_WIRE_VERSION_V2: &[u8] =
    b"router-ab-protocol/mpc-prf-stable-proof-bundle-wire/v2";
const MPC_PRF_STABLE_RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V2: &[u8] =
    b"router-ab-protocol/mpc-prf-stable-recipient-proof-bundle-payload/v2";

/// Public transcript metadata carried to each signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterTranscriptMetadataV1 {
    /// Network namespace bound into account-scoped derivation.
    pub network_id: String,
    /// Account public key bound into account-scoped derivation.
    pub account_public_key: String,
    /// Router identity bound into the transcript.
    pub router_id: String,
    /// Client identity bound into the transcript.
    pub client_id: String,
    /// Client ephemeral public key for client-output encryption.
    pub client_ephemeral_public_key: String,
}

impl RouterTranscriptMetadataV1 {
    /// Creates validated Router transcript metadata.
    pub fn new(
        network_id: impl Into<String>,
        account_public_key: impl Into<String>,
        router_id: impl Into<String>,
        client_id: impl Into<String>,
        client_ephemeral_public_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let metadata = Self {
            network_id: network_id.into(),
            account_public_key: account_public_key.into(),
            router_id: router_id.into(),
            client_id: client_id.into(),
            client_ephemeral_public_key: client_ephemeral_public_key.into(),
        };
        metadata.validate()?;
        Ok(metadata)
    }

    /// Validates required transcript identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("network_id", &self.network_id)?;
        require_non_empty("account_public_key", &self.account_public_key)?;
        require_non_empty("router_id", &self.router_id)?;
        require_non_empty("client_id", &self.client_id)?;
        require_non_empty(
            "client_ephemeral_public_key",
            &self.client_ephemeral_public_key,
        )
    }

    /// Builds the derivation transcript binding from public payload metadata.
    pub fn to_transcript_binding(
        &self,
        context: DerivationContext,
        signer_set: &SignerSetV1,
    ) -> RouterAbProtocolResult<TranscriptBinding> {
        self.validate()?;
        signer_set.validate()?;
        let transcript_signer_set = SignerSetBinding::v1_all2(
            signer_set.signer_set_id.clone(),
            signer_set.signer_a.signer_id.clone(),
            signer_set.signer_a.key_epoch.clone(),
            signer_set.signer_b.signer_id.clone(),
            signer_set.signer_b.key_epoch.clone(),
        )
        .map_err(map_derivation_to_protocol_error)?;
        TranscriptBinding::new(
            context,
            self.router_id.clone(),
            transcript_signer_set,
            signer_set.selected_server.server_id.clone(),
            signer_set.selected_server.recipient_encryption_key.clone(),
            self.client_id.clone(),
            self.client_ephemeral_public_key.clone(),
        )
        .map_err(map_derivation_to_protocol_error)
    }
}

/// Public encrypted-envelope digest set used for Router assignment validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouterEnvelopeDigestSetV1 {
    /// Assignment digest of Signer A's encrypted envelope.
    pub signer_a_envelope_digest: PublicDigest32,
    /// Assignment digest of Signer B's encrypted envelope.
    pub signer_b_envelope_digest: PublicDigest32,
}

impl RouterEnvelopeDigestSetV1 {
    /// Creates the pair of signer envelope digests.
    pub fn new(
        signer_a_envelope_digest: PublicDigest32,
        signer_b_envelope_digest: PublicDigest32,
    ) -> Self {
        Self {
            signer_a_envelope_digest,
            signer_b_envelope_digest,
        }
    }

    /// Returns the expected envelope digest for a signer role.
    pub fn digest_for_role(&self, role: Role) -> RouterAbProtocolResult<PublicDigest32> {
        match role {
            Role::SignerA => Ok(self.signer_a_envelope_digest),
            Role::SignerB => Ok(self.signer_b_envelope_digest),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "envelope digest set expected a signer role",
            )),
        }
    }
}

/// Builds the transcript binding for a Router-to-signer ceremony.
pub fn router_transcript_binding_v1(
    lifecycle: &LifecycleScopeV1,
    signer_set: &SignerSetV1,
    transcript_metadata: &RouterTranscriptMetadataV1,
    root_share_epoch: RootShareEpoch,
) -> RouterAbProtocolResult<TranscriptBinding> {
    lifecycle.validate()?;
    signer_set.validate()?;
    transcript_metadata.validate()?;
    let context = DerivationContext::new(
        lifecycle.primitive_request_kind,
        AccountScope::new(
            transcript_metadata.network_id.clone(),
            lifecycle.account_id.clone(),
            transcript_metadata.account_public_key.clone(),
        )
        .map_err(map_derivation_to_protocol_error)?,
        root_share_epoch,
        lifecycle.lifecycle_id.clone(),
    )
    .map_err(map_derivation_to_protocol_error)?;
    transcript_metadata.to_transcript_binding(context, signer_set)
}

/// Computes the transcript digest for a Router-to-signer ceremony.
pub fn router_transcript_digest_v1(
    lifecycle: &LifecycleScopeV1,
    signer_set: &SignerSetV1,
    transcript_metadata: &RouterTranscriptMetadataV1,
    root_share_epoch: RootShareEpoch,
) -> RouterAbProtocolResult<PublicDigest32> {
    let transcript =
        router_transcript_binding_v1(lifecycle, signer_set, transcript_metadata, root_share_epoch)?;
    transcript_digest_v1(&transcript).map_err(map_derivation_to_protocol_error)
}

/// Router-to-signer payload before canonical transport encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouterToSignerPayloadV1 {
    /// Router payload for Signer A.
    SignerA {
        /// Lifecycle scope.
        lifecycle: LifecycleScopeV1,
        /// Signer set.
        signer_set: SignerSetV1,
        /// Public transcript metadata shared by both signers.
        transcript_metadata: RouterTranscriptMetadataV1,
        /// Public encrypted-envelope digests for assignment validation.
        envelope_digest_set: RouterEnvelopeDigestSetV1,
        /// Public transcript digest bound to the enclosing wire message.
        transcript_digest: PublicDigest32,
        /// Signer A envelope assignment.
        assignment: RoleEnvelopeAssignmentV1,
    },
    /// Router payload for Signer B.
    SignerB {
        /// Lifecycle scope.
        lifecycle: LifecycleScopeV1,
        /// Signer set.
        signer_set: SignerSetV1,
        /// Public transcript metadata shared by both signers.
        transcript_metadata: RouterTranscriptMetadataV1,
        /// Public encrypted-envelope digests for assignment validation.
        envelope_digest_set: RouterEnvelopeDigestSetV1,
        /// Public transcript digest bound to the enclosing wire message.
        transcript_digest: PublicDigest32,
        /// Signer B envelope assignment.
        assignment: RoleEnvelopeAssignmentV1,
    },
}

impl RouterToSignerPayloadV1 {
    /// Creates a Router-to-Signer A payload.
    pub fn signer_a(
        lifecycle: LifecycleScopeV1,
        signer_set: SignerSetV1,
        transcript_metadata: RouterTranscriptMetadataV1,
        envelope_digest_set: RouterEnvelopeDigestSetV1,
        transcript_digest: PublicDigest32,
        assignment: RoleEnvelopeAssignmentV1,
    ) -> RouterAbProtocolResult<Self> {
        let payload = Self::SignerA {
            lifecycle,
            signer_set,
            transcript_metadata,
            envelope_digest_set,
            transcript_digest,
            assignment,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Creates a Router-to-Signer B payload.
    pub fn signer_b(
        lifecycle: LifecycleScopeV1,
        signer_set: SignerSetV1,
        transcript_metadata: RouterTranscriptMetadataV1,
        envelope_digest_set: RouterEnvelopeDigestSetV1,
        transcript_digest: PublicDigest32,
        assignment: RoleEnvelopeAssignmentV1,
    ) -> RouterAbProtocolResult<Self> {
        let payload = Self::SignerB {
            lifecycle,
            signer_set,
            transcript_metadata,
            envelope_digest_set,
            transcript_digest,
            assignment,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Validates signer-set, lifecycle, and branch role consistency.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        match self {
            Self::SignerA {
                lifecycle,
                signer_set,
                transcript_metadata,
                envelope_digest_set,
                transcript_digest: _,
                assignment,
            } => validate_router_to_signer(
                lifecycle,
                signer_set,
                transcript_metadata,
                envelope_digest_set,
                assignment,
                Role::SignerA,
            ),
            Self::SignerB {
                lifecycle,
                signer_set,
                transcript_metadata,
                envelope_digest_set,
                transcript_digest: _,
                assignment,
            } => validate_router_to_signer(
                lifecycle,
                signer_set,
                transcript_metadata,
                envelope_digest_set,
                assignment,
                Role::SignerB,
            ),
        }
    }

    /// Returns the transcript digest bound to this Router-to-signer payload.
    pub fn transcript_digest(&self) -> PublicDigest32 {
        match self {
            Self::SignerA {
                transcript_digest, ..
            }
            | Self::SignerB {
                transcript_digest, ..
            } => *transcript_digest,
        }
    }

    /// Returns the signer role targeted by this payload branch.
    pub fn recipient_role(&self) -> Role {
        match self {
            Self::SignerA { .. } => Role::SignerA,
            Self::SignerB { .. } => Role::SignerB,
        }
    }

    /// Returns the role-specific signer-envelope assignment.
    pub fn assignment(&self) -> &RoleEnvelopeAssignmentV1 {
        match self {
            Self::SignerA { assignment, .. } | Self::SignerB { assignment, .. } => assignment,
        }
    }

    /// Returns the lifecycle scope bound to this payload.
    pub fn lifecycle(&self) -> &LifecycleScopeV1 {
        match self {
            Self::SignerA { lifecycle, .. } | Self::SignerB { lifecycle, .. } => lifecycle,
        }
    }

    /// Returns the signer set bound to this payload.
    pub fn signer_set(&self) -> &SignerSetV1 {
        match self {
            Self::SignerA { signer_set, .. } | Self::SignerB { signer_set, .. } => signer_set,
        }
    }

    /// Returns public transcript metadata bound to this payload.
    pub fn transcript_metadata(&self) -> &RouterTranscriptMetadataV1 {
        match self {
            Self::SignerA {
                transcript_metadata,
                ..
            }
            | Self::SignerB {
                transcript_metadata,
                ..
            } => transcript_metadata,
        }
    }

    /// Returns envelope digests used for role-assignment validation.
    pub fn envelope_digest_set(&self) -> RouterEnvelopeDigestSetV1 {
        match self {
            Self::SignerA {
                envelope_digest_set,
                ..
            }
            | Self::SignerB {
                envelope_digest_set,
                ..
            } => *envelope_digest_set,
        }
    }

    /// Validates that this payload targets the expected signer role.
    pub fn require_recipient_role(
        &self,
        expected_role: Role,
    ) -> RouterAbProtocolResult<&RoleEnvelopeAssignmentV1> {
        require_signer_role(expected_role)?;
        self.validate()?;
        if self.recipient_role() != expected_role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "router-to-signer payload branch does not match local signer role",
            ));
        }
        Ok(self.assignment())
    }

    /// Returns canonical bytes for this payload.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_router_to_signer_payload_v1(self)
    }

    /// Returns the SHA-256 digest of canonical bytes.
    pub fn digest(&self) -> PublicDigest32 {
        router_to_signer_payload_digest_v1(self)
    }
}

/// Public context the SigningWorker needs to activate its recipient output.
///
/// This is derived from the Router-to-deriver payload but intentionally omits the
/// role encrypted-envelope assignment. SigningWorker activation needs the public
/// transcript context, signer set, and transcript digest, not deriver envelope
/// ciphertext.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningWorkerActivationContextV1 {
    /// Lifecycle scope bound into the derivation transcript.
    pub lifecycle: LifecycleScopeV1,
    /// Deriver set and selected SigningWorker identity.
    pub signer_set: SignerSetV1,
    /// Public transcript metadata.
    pub transcript_metadata: RouterTranscriptMetadataV1,
    /// Public transcript digest reconstructed from the context.
    pub transcript_digest: PublicDigest32,
}

impl SigningWorkerActivationContextV1 {
    /// Creates a validated SigningWorker activation context.
    pub fn new(
        lifecycle: LifecycleScopeV1,
        signer_set: SignerSetV1,
        transcript_metadata: RouterTranscriptMetadataV1,
        transcript_digest: PublicDigest32,
    ) -> RouterAbProtocolResult<Self> {
        let context = Self {
            lifecycle,
            signer_set,
            transcript_metadata,
            transcript_digest,
        };
        context.validate()?;
        Ok(context)
    }

    /// Builds the public activation context from a validated Router-to-deriver payload.
    pub fn from_router_payload(payload: &RouterToSignerPayloadV1) -> RouterAbProtocolResult<Self> {
        payload.validate()?;
        Self::new(
            payload.lifecycle().clone(),
            payload.signer_set().clone(),
            payload.transcript_metadata().clone(),
            payload.transcript_digest(),
        )
    }

    /// Validates lifecycle, signer-set, and transcript digest consistency.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.lifecycle.validate()?;
        self.signer_set.validate()?;
        self.transcript_metadata.validate()?;
        if self.lifecycle.signer_set_id != self.signer_set.signer_set_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "SigningWorker activation lifecycle signer-set id does not match signer set",
            ));
        }
        if self.lifecycle.selected_server_id != self.signer_set.selected_server.server_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "SigningWorker activation selected worker does not match signer set",
            ));
        }
        let expected_transcript_digest = router_transcript_digest_v1(
            &self.lifecycle,
            &self.signer_set,
            &self.transcript_metadata,
            self.lifecycle.root_share_epoch.clone(),
        )?;
        if self.transcript_digest != expected_transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "SigningWorker activation transcript digest does not match reconstructed transcript",
            ));
        }
        Ok(())
    }

    /// Returns the lifecycle scope.
    pub fn lifecycle(&self) -> &LifecycleScopeV1 {
        &self.lifecycle
    }

    /// Returns the signer set.
    pub fn signer_set(&self) -> &SignerSetV1 {
        &self.signer_set
    }

    /// Returns public transcript metadata.
    pub fn transcript_metadata(&self) -> &RouterTranscriptMetadataV1 {
        &self.transcript_metadata
    }

    /// Returns the transcript digest.
    pub fn transcript_digest(&self) -> PublicDigest32 {
        self.transcript_digest
    }
}

/// Direct A/B peer payload before canonical transport encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbPeerMessagePayloadV1 {
    /// Sender signer identity.
    pub from: SignerIdentityV1,
    /// Recipient signer identity.
    pub to: SignerIdentityV1,
    /// Transcript digest.
    pub transcript_digest: PublicDigest32,
    /// Canonical peer protocol payload bytes.
    pub payload: CanonicalWireBytesV1,
    /// Authentication over sender, recipient, transcript, and payload bytes.
    pub authentication: AbPeerMessageAuthenticationV1,
}

impl AbPeerMessagePayloadV1 {
    /// Creates a validated A/B peer payload.
    pub fn new(
        from: SignerIdentityV1,
        to: SignerIdentityV1,
        transcript_digest: PublicDigest32,
        payload: CanonicalWireBytesV1,
        authentication: AbPeerMessageAuthenticationV1,
    ) -> RouterAbProtocolResult<Self> {
        let message = Self {
            from,
            to,
            transcript_digest,
            payload,
            authentication,
        };
        message.validate()?;
        Ok(message)
    }

    /// Validates that the peer message crosses signer roles.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.from.validate()?;
        self.to.validate()?;
        match (self.from.role, self.to.role) {
            (Role::SignerA, Role::SignerB) | (Role::SignerB, Role::SignerA) => Ok(()),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "A/B peer message must cross Signer A and Signer B",
            )),
        }?;
        let expected_digest = ab_peer_message_authentication_input_digest_v1(
            &self.from,
            &self.to,
            self.transcript_digest,
            &self.payload,
        );
        self.authentication.validate(expected_digest)
    }

    /// Returns canonical bytes covered by the A/B peer authentication.
    pub fn authentication_input_bytes(&self) -> Vec<u8> {
        encode_ab_peer_message_authentication_input_v1(
            &self.from,
            &self.to,
            self.transcript_digest,
            &self.payload,
        )
    }

    /// Returns the digest covered by the A/B peer authentication.
    pub fn authentication_input_digest(&self) -> PublicDigest32 {
        digest_bytes(&self.authentication_input_bytes())
    }

    /// Returns canonical bytes for this payload.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_ab_peer_message_payload_v1(self)
    }

    /// Returns the SHA-256 digest of canonical bytes.
    pub fn digest(&self) -> PublicDigest32 {
        ab_peer_message_payload_digest_v1(self)
    }
}

/// Inner A/B ECDSA threshold-PRF payload carrying Deriver proof bundles.
#[derive(Clone, PartialEq, Eq)]
pub struct EcdsaThresholdPrfProofBatchPayloadV1 {
    /// Sender signer identity.
    pub from: SignerIdentityV1,
    /// Recipient signer identity.
    pub to: SignerIdentityV1,
    /// Transcript digest shared by every proof bundle.
    pub transcript_digest: PublicDigest32,
    /// Root-share epoch used by the producing signer.
    pub root_share_epoch: RootShareEpoch,
    /// Threshold-PRF proof bundles produced by the sender.
    pub proof_bundles: Vec<MpcPrfPartialProofBundleV1>,
}

impl core::fmt::Debug for EcdsaThresholdPrfProofBatchPayloadV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EcdsaThresholdPrfProofBatchPayloadV1")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("transcript_digest", &self.transcript_digest)
            .field("root_share_epoch", &self.root_share_epoch)
            .field("proof_bundle_count", &self.proof_bundles.len())
            .finish()
    }
}

impl EcdsaThresholdPrfProofBatchPayloadV1 {
    /// Creates a validated A/B ECDSA threshold-PRF proof-batch payload.
    pub fn new(
        from: SignerIdentityV1,
        to: SignerIdentityV1,
        transcript_digest: PublicDigest32,
        root_share_epoch: RootShareEpoch,
        proof_bundles: Vec<MpcPrfPartialProofBundleV1>,
    ) -> RouterAbProtocolResult<Self> {
        let payload = Self {
            from,
            to,
            transcript_digest,
            root_share_epoch,
            proof_bundles,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Validates peer direction, transcript binding, and proof-bundle metadata.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.from.validate()?;
        self.to.validate()?;
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        match (self.from.role, self.to.role) {
            (Role::SignerA, Role::SignerB) | (Role::SignerB, Role::SignerA) => {}
            _ => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidRole,
                    "A/B ECDSA threshold-PRF proof batch must cross Signer A and Signer B",
                ));
            }
        }
        if self.proof_bundles.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "A/B ECDSA threshold-PRF proof batch requires at least one proof bundle",
            ));
        }
        for (index, bundle) in self.proof_bundles.iter().enumerate() {
            let binding = &bundle.signer_partial.binding;
            if binding.signer_role != self.from.role
                || binding.signer_identity != self.from.signer_id
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidSignerIdentity,
                    "A/B ECDSA threshold-PRF proof bundle signer does not match sender",
                ));
            }
            if binding.transcript_digest != self.transcript_digest {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "A/B ECDSA threshold-PRF proof bundle transcript mismatch",
                ));
            }
            if binding.root_share_epoch != self.root_share_epoch {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "A/B ECDSA threshold-PRF proof bundle root-share epoch mismatch",
                ));
            }
            for prior in &self.proof_bundles[..index] {
                let prior_binding = &prior.signer_partial.binding;
                if prior_binding.opened_share_kind == binding.opened_share_kind
                    && prior_binding.recipient_role == binding.recipient_role
                    && prior_binding.recipient_identity == binding.recipient_identity
                {
                    return Err(RouterAbProtocolError::new(
                        RouterAbProtocolErrorCode::MalformedWirePayload,
                        "A/B ECDSA threshold-PRF proof batch contains duplicate output binding",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns canonical bytes for this proof-batch payload.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_ecdsa_threshold_prf_proof_batch_payload_v1(self)
    }

    /// Returns the SHA-256 digest of canonical bytes.
    pub fn digest(&self) -> PublicDigest32 {
        ecdsa_threshold_prf_proof_batch_payload_digest_v1(self)
    }
}

/// Recipient-scoped proof-bundle payload for final client or server delivery.
#[derive(Clone, PartialEq, Eq)]
pub struct RecipientProofBundlePayloadV1 {
    /// Lifecycle id.
    pub lifecycle_id: String,
    /// Producing signer.
    pub signer: SignerIdentityV1,
    /// Intended recipient role.
    pub recipient_role: Role,
    /// Opened share kind carried by the proof bundle.
    pub opened_share_kind: OpenedShareKind,
    /// Intended recipient identity.
    pub recipient_identity: String,
    /// Transcript digest shared by the enclosed proof bundle.
    pub transcript_digest: PublicDigest32,
    /// Recipient-scoped proof batch containing exactly one proof bundle.
    pub proof_batch: EcdsaThresholdPrfProofBatchPayloadV1,
}

impl core::fmt::Debug for RecipientProofBundlePayloadV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecipientProofBundlePayloadV1")
            .field("lifecycle_id", &self.lifecycle_id)
            .field("signer", &self.signer)
            .field("recipient_role", &self.recipient_role)
            .field("opened_share_kind", &self.opened_share_kind)
            .field("recipient_identity", &self.recipient_identity)
            .field("transcript_digest", &self.transcript_digest)
            .field("proof_bundle_count", &self.proof_batch.proof_bundles.len())
            .finish()
    }
}

impl RecipientProofBundlePayloadV1 {
    /// Creates a validated recipient proof-bundle payload.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lifecycle_id: impl Into<String>,
        signer: SignerIdentityV1,
        recipient_role: Role,
        opened_share_kind: OpenedShareKind,
        recipient_identity: impl Into<String>,
        transcript_digest: PublicDigest32,
        proof_batch: EcdsaThresholdPrfProofBatchPayloadV1,
    ) -> RouterAbProtocolResult<Self> {
        let payload = Self {
            lifecycle_id: lifecycle_id.into(),
            signer,
            recipient_role,
            opened_share_kind,
            recipient_identity: recipient_identity.into(),
            transcript_digest,
            proof_batch,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Validates signer, recipient, transcript, and single-bundle bindings.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("lifecycle_id", &self.lifecycle_id)?;
        require_non_empty("recipient_identity", &self.recipient_identity)?;
        self.signer.validate()?;
        match self.signer.role {
            Role::SignerA | Role::SignerB => {}
            _ => {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidRole,
                    "recipient proof bundle payload signer must be Signer A or Signer B",
                ));
            }
        }
        validate_recipient_delivery_policy(self.recipient_role, self.opened_share_kind)?;
        self.proof_batch.validate()?;
        if self.proof_batch.from != self.signer {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "recipient proof bundle sender does not match signer identity",
            ));
        }
        if self.proof_batch.transcript_digest != self.transcript_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "recipient proof bundle transcript mismatch",
            ));
        }
        if self.proof_batch.proof_bundles.len() != 1 {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "recipient proof bundle payload requires exactly one proof bundle",
            ));
        }
        let binding = &self.proof_batch.proof_bundles[0].signer_partial.binding;
        if binding.opened_share_kind != self.opened_share_kind
            || binding.recipient_role != self.recipient_role
            || binding.recipient_identity != self.recipient_identity
            || binding.transcript_digest != self.transcript_digest
            || binding.signer_role != self.signer.role
            || binding.signer_identity != self.signer.signer_id
        {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "recipient proof bundle binding does not match delivery metadata",
            ));
        }
        Ok(())
    }

    /// Returns canonical bytes for this payload.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_recipient_proof_bundle_payload_v1(self)
    }

    /// Returns the SHA-256 digest of canonical bytes.
    pub fn digest(&self) -> PublicDigest32 {
        recipient_proof_bundle_payload_digest_v1(self)
    }
}

/// Canonical public wire for one stable tenant-root threshold-PRF proof bundle.
///
/// The stable PRF bytes are represented by their digest here. The complete
/// plan remains a server-resolved value and is supplied again when a recipient
/// verifies the bundle.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfStableProofBundleWireV2 {
    /// Digest of the exact stable PRF context bytes.
    pub stable_context_digest: TenantRootProtocolDigestV1,
    /// Digest of the epoch-bound custody binding used by the proof.
    pub custody_binding_digest: TenantRootProtocolDigestV1,
    /// Fixed ECDSA threshold-PRF purpose.
    pub purpose: PrfPurpose,
    /// Deriver role that produced the proof bundle.
    pub signer_role: Role,
    /// Canonical threshold-PRF partial wire.
    pub partial_wire: MpcPrfPartialWireV1,
    /// Public commitment to the producing role's root share.
    pub commitment_wire: MpcPrfShareCommitmentWireV1,
    /// DLEQ proof bound to the custody digest.
    pub proof_wire: MpcPrfDleqProofWireV1,
}

impl core::fmt::Debug for MpcPrfStableProofBundleWireV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MpcPrfStableProofBundleWireV2")
            .field("stable_context_digest", &self.stable_context_digest)
            .field("custody_binding_digest", &self.custody_binding_digest)
            .field("purpose", &self.purpose)
            .field("signer_role", &self.signer_role)
            .field("partial_wire", &"[redacted]")
            .field("commitment_wire", &self.commitment_wire)
            .field("proof_wire", &"[redacted]")
            .finish()
    }
}

impl MpcPrfStableProofBundleWireV2 {
    /// Creates a validated canonical proof-bundle wire.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        stable_context_digest: TenantRootProtocolDigestV1,
        custody_binding_digest: TenantRootProtocolDigestV1,
        purpose: PrfPurpose,
        signer_role: Role,
        partial_wire: MpcPrfPartialWireV1,
        commitment_wire: MpcPrfShareCommitmentWireV1,
        proof_wire: MpcPrfDleqProofWireV1,
    ) -> RouterAbProtocolResult<Self> {
        let wire = Self {
            stable_context_digest,
            custody_binding_digest,
            purpose,
            signer_role,
            partial_wire,
            commitment_wire,
            proof_wire,
        };
        wire.validate()?;
        Ok(wire)
    }

    /// Builds a canonical proof-bundle wire from one V2 backend output.
    pub fn from_stable_partial(
        bundle: &MpcPrfStablePartialProofBundleV2,
    ) -> RouterAbProtocolResult<Self> {
        Self::new(
            bundle.purpose_plan.stable_context_digest(),
            bundle.purpose_plan.custody_binding_digest(),
            bundle.purpose_plan.purpose().clone(),
            bundle.signer_role,
            bundle.partial_wire.clone(),
            bundle.commitment_wire.clone(),
            bundle.proof_wire.clone(),
        )
    }

    /// Validates the fixed purpose, role, and proof-wire shape.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        validate_stable_prf_purpose(&self.purpose)?;
        require_signer_role(self.signer_role)?;
        validate_stable_proof_wire_shape(
            self.signer_role,
            &self.partial_wire,
            &self.commitment_wire,
            &self.proof_wire,
        )
    }

    /// Returns the canonical proof-bundle bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_mpc_prf_stable_proof_bundle_wire_v2(self)
    }

    /// Returns the SHA-256 digest of canonical proof-bundle bytes.
    pub fn digest(&self) -> PublicDigest32 {
        mpc_prf_stable_proof_bundle_wire_digest_v2(self)
    }

    /// Converts this public wire into a V2 backend bundle under one expected plan.
    pub fn into_stable_partial_for_plan(
        self,
        expected_plan: &MpcPrfStablePurposeBindingPlanV2,
    ) -> RouterAbProtocolResult<MpcPrfStablePartialProofBundleV2> {
        self.validate()?;
        validate_stable_plan_metadata(
            expected_plan,
            self.stable_context_digest,
            self.custody_binding_digest,
            &self.purpose,
        )?;
        Ok(MpcPrfStablePartialProofBundleV2 {
            purpose_plan: expected_plan.clone(),
            signer_role: self.signer_role,
            partial_wire: self.partial_wire,
            commitment_wire: self.commitment_wire,
            proof_wire: self.proof_wire,
        })
    }
}

/// Recipient-scoped payload for one stable tenant-root threshold-PRF proof.
#[derive(Clone, PartialEq, Eq)]
pub struct MpcPrfStableRecipientProofBundlePayloadV2 {
    /// Producing signer identity.
    pub signer: SignerIdentityV1,
    /// Intended client or server recipient role.
    pub recipient_role: Role,
    /// Canonical recipient identity.
    pub recipient_identity: String,
    /// Stable tenant-root proof bundle delivered to the recipient.
    pub proof_bundle: MpcPrfStableProofBundleWireV2,
}

impl core::fmt::Debug for MpcPrfStableRecipientProofBundlePayloadV2 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MpcPrfStableRecipientProofBundlePayloadV2")
            .field("signer", &self.signer)
            .field("recipient_role", &self.recipient_role)
            .field("recipient_identity", &self.recipient_identity)
            .field("proof_bundle", &self.proof_bundle)
            .finish()
    }
}

impl MpcPrfStableRecipientProofBundlePayloadV2 {
    /// Creates a validated recipient-scoped stable proof payload.
    pub fn new(
        signer: SignerIdentityV1,
        recipient_role: Role,
        recipient_identity: impl Into<String>,
        proof_bundle: MpcPrfStableProofBundleWireV2,
    ) -> RouterAbProtocolResult<Self> {
        let payload = Self {
            signer,
            recipient_role,
            recipient_identity: recipient_identity.into(),
            proof_bundle,
        };
        payload.validate()?;
        Ok(payload)
    }

    /// Builds a recipient payload from one V2 backend output.
    pub fn from_stable_partial(
        signer: SignerIdentityV1,
        recipient_role: Role,
        recipient_identity: impl Into<String>,
        bundle: &MpcPrfStablePartialProofBundleV2,
    ) -> RouterAbProtocolResult<Self> {
        Self::new(
            signer,
            recipient_role,
            recipient_identity,
            MpcPrfStableProofBundleWireV2::from_stable_partial(bundle)?,
        )
    }

    /// Validates recipient policy and sender binding.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.signer.validate()?;
        require_non_empty("recipient_identity", &self.recipient_identity)?;
        self.proof_bundle.validate()?;
        if self.proof_bundle.signer_role != self.signer.role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "stable tenant-root recipient proof bundle role does not match signer",
            ));
        }
        let expected_role = stable_prf_recipient_role(&self.proof_bundle.purpose)?;
        if expected_role != self.recipient_role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "stable tenant-root recipient role does not match threshold-PRF purpose",
            ));
        }
        Ok(())
    }

    /// Returns the V1 envelope binding corresponding to this recipient role.
    pub fn opened_share_kind(&self) -> RouterAbProtocolResult<OpenedShareKind> {
        match self.recipient_role {
            Role::Client => Ok(OpenedShareKind::XClientBase),
            Role::Server => Ok(OpenedShareKind::XServerBase),
            _ => Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "stable tenant-root recipient payload requires a client or server role",
            )),
        }
    }

    /// Returns the canonical recipient payload bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_mpc_prf_stable_recipient_proof_bundle_payload_v2(self)
    }

    /// Returns the SHA-256 digest of canonical recipient payload bytes.
    pub fn digest(&self) -> PublicDigest32 {
        mpc_prf_stable_recipient_proof_bundle_payload_digest_v2(self)
    }

    /// Converts the recipient proof bundle under one expected stable plan.
    pub fn stable_partial_for_plan(
        &self,
        expected_plan: &MpcPrfStablePurposeBindingPlanV2,
    ) -> RouterAbProtocolResult<MpcPrfStablePartialProofBundleV2> {
        self.validate()?;
        self.proof_bundle
            .clone()
            .into_stable_partial_for_plan(expected_plan)
    }
}

/// Encodes one stable tenant-root threshold-PRF proof-bundle wire.
pub fn encode_mpc_prf_stable_proof_bundle_wire_v2(wire: &MpcPrfStableProofBundleWireV2) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, MPC_PRF_STABLE_PROOF_BUNDLE_WIRE_VERSION_V2);
    push_tenant_root_protocol_digest(&mut out, wire.stable_context_digest);
    push_tenant_root_protocol_digest(&mut out, wire.custody_binding_digest);
    push_len32(&mut out, wire.purpose.as_bytes());
    push_role(&mut out, wire.signer_role);
    push_len32(&mut out, wire.partial_wire.as_bytes());
    push_len32(&mut out, wire.commitment_wire.as_bytes());
    push_len32(&mut out, wire.proof_wire.as_bytes());
    out
}

/// Decodes one stable tenant-root threshold-PRF proof-bundle wire.
pub fn decode_mpc_prf_stable_proof_bundle_wire_v2(
    bytes: &[u8],
) -> RouterAbProtocolResult<MpcPrfStableProofBundleWireV2> {
    let mut decoder = PayloadDecoder::new(bytes);
    decoder.expect_bytes(
        MPC_PRF_STABLE_PROOF_BUNDLE_WIRE_VERSION_V2,
        "stable tenant-root proof-bundle wire version",
    )?;
    let stable_context_digest = decoder.read_tenant_root_protocol_digest(
        "stable tenant-root proof-bundle stable-context digest",
    )?;
    let custody_binding_digest = decoder.read_tenant_root_protocol_digest(
        "stable tenant-root proof-bundle custody-binding digest",
    )?;
    let purpose =
        parse_stable_prf_purpose(&decoder.read_string("stable tenant-root proof-bundle purpose")?)?;
    let signer_role = decoder.read_role()?;
    let partial_wire = MpcPrfPartialWireV1::new(
        decoder
            .read_bytes("stable tenant-root proof-bundle partial wire")?
            .to_vec(),
    )
    .map_err(map_derivation_to_protocol_error)?;
    let commitment_wire = MpcPrfShareCommitmentWireV1::new(
        decoder
            .read_bytes("stable tenant-root proof-bundle commitment wire")?
            .to_vec(),
    )
    .map_err(map_derivation_to_protocol_error)?;
    let proof_wire = MpcPrfDleqProofWireV1::new(
        decoder
            .read_bytes("stable tenant-root proof-bundle proof wire")?
            .to_vec(),
    )
    .map_err(map_derivation_to_protocol_error)?;
    decoder.finish()?;
    MpcPrfStableProofBundleWireV2::new(
        stable_context_digest,
        custody_binding_digest,
        purpose,
        signer_role,
        partial_wire,
        commitment_wire,
        proof_wire,
    )
}

/// Computes the public digest of one stable proof-bundle wire.
pub fn mpc_prf_stable_proof_bundle_wire_digest_v2(
    wire: &MpcPrfStableProofBundleWireV2,
) -> PublicDigest32 {
    digest_bytes(&encode_mpc_prf_stable_proof_bundle_wire_v2(wire))
}

/// Encodes a stable tenant-root recipient proof-bundle payload.
pub fn encode_mpc_prf_stable_recipient_proof_bundle_payload_v2(
    payload: &MpcPrfStableRecipientProofBundlePayloadV2,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(
        &mut out,
        MPC_PRF_STABLE_RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V2,
    );
    push_signer_identity(&mut out, &payload.signer);
    push_role(&mut out, payload.recipient_role);
    push_string(&mut out, &payload.recipient_identity);
    push_len32(
        &mut out,
        &encode_mpc_prf_stable_proof_bundle_wire_v2(&payload.proof_bundle),
    );
    out
}

/// Decodes a stable tenant-root recipient proof-bundle payload.
pub fn decode_mpc_prf_stable_recipient_proof_bundle_payload_v2(
    bytes: &[u8],
) -> RouterAbProtocolResult<MpcPrfStableRecipientProofBundlePayloadV2> {
    let mut decoder = PayloadDecoder::new(bytes);
    decoder.expect_bytes(
        MPC_PRF_STABLE_RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V2,
        "stable tenant-root recipient payload version",
    )?;
    let signer = decoder.read_signer_identity()?;
    let recipient_role = decoder.read_role()?;
    let recipient_identity = decoder.read_string("stable tenant-root recipient identity")?;
    let proof_bundle = decode_mpc_prf_stable_proof_bundle_wire_v2(
        decoder.read_bytes("stable tenant-root recipient proof bundle")?,
    )?;
    decoder.finish()?;
    MpcPrfStableRecipientProofBundlePayloadV2::new(
        signer,
        recipient_role,
        recipient_identity,
        proof_bundle,
    )
}

/// Computes the public digest of a stable tenant-root recipient payload.
pub fn mpc_prf_stable_recipient_proof_bundle_payload_digest_v2(
    payload: &MpcPrfStableRecipientProofBundlePayloadV2,
) -> PublicDigest32 {
    digest_bytes(&encode_mpc_prf_stable_recipient_proof_bundle_payload_v2(
        payload,
    ))
}

/// Verifies one stable tenant-root recipient payload against its expected plan.
pub fn verify_mpc_prf_stable_recipient_proof_bundle_payload_v2(
    payload: &MpcPrfStableRecipientProofBundlePayloadV2,
    expected_plan: &MpcPrfStablePurposeBindingPlanV2,
) -> RouterAbProtocolResult<()> {
    let bundle = payload.stable_partial_for_plan(expected_plan)?;
    verify_mpc_prf_stable_partial_with_threshold_backend_v2(expected_plan, &bundle)
        .map_err(map_derivation_to_protocol_error)
}

/// Signature scheme for direct A/B peer messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbPeerMessageSignatureSchemeV1 {
    /// Ed25519 signature over the canonical A/B peer authentication input.
    Ed25519V1,
}

impl AbPeerMessageSignatureSchemeV1 {
    /// Returns the canonical signature-scheme label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519V1 => "ed25519_v1",
        }
    }
}

/// Required authentication material for direct A/B peer messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbPeerMessageAuthenticationV1 {
    /// Signature scheme.
    pub signature_scheme: AbPeerMessageSignatureSchemeV1,
    /// Digest of the canonical bytes signed by the sender.
    pub signed_message_digest: PublicDigest32,
    /// Signature bytes.
    pub signature: CanonicalWireBytesV1,
}

impl AbPeerMessageAuthenticationV1 {
    /// Creates validated A/B peer authentication material.
    pub fn new(
        signature_scheme: AbPeerMessageSignatureSchemeV1,
        signed_message_digest: PublicDigest32,
        signature: CanonicalWireBytesV1,
    ) -> RouterAbProtocolResult<Self> {
        let authentication = Self {
            signature_scheme,
            signed_message_digest,
            signature,
        };
        authentication.validate(signed_message_digest)?;
        Ok(authentication)
    }

    /// Validates the authentication digest binding.
    pub fn validate(&self, expected_signed_digest: PublicDigest32) -> RouterAbProtocolResult<()> {
        if self.signed_message_digest != expected_signed_digest {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "A/B peer authentication digest does not match payload",
            ));
        }
        if self.signature.as_bytes().is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "A/B peer authentication signature must be non-empty",
            ));
        }
        Ok(())
    }
}

/// Sender-bound Ed25519 verifying key for A/B peer authentication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbPeerMessageVerifyingKeyV1 {
    /// Signer identity that owns this verifying key.
    pub signer: SignerIdentityV1,
    /// Raw Ed25519 verifying key bytes.
    pub verifying_key_bytes: [u8; 32],
}

impl AbPeerMessageVerifyingKeyV1 {
    /// Creates a validated peer verifying key.
    pub fn new(
        signer: SignerIdentityV1,
        verifying_key_bytes: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let key = Self {
            signer,
            verifying_key_bytes,
        };
        key.validate()?;
        Ok(key)
    }

    /// Validates signer identity and Ed25519 key bytes.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.signer.validate()?;
        VerifyingKey::from_bytes(&self.verifying_key_bytes).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "A/B peer verifying key bytes are invalid",
            )
        })?;
        Ok(())
    }
}

/// Encodes Router-to-signer payload bytes with fixed field order.
pub fn encode_router_to_signer_payload_v1(payload: &RouterToSignerPayloadV1) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, ROUTER_TO_SIGNER_PAYLOAD_VERSION_V1);
    match payload {
        RouterToSignerPayloadV1::SignerA {
            lifecycle,
            signer_set,
            transcript_metadata,
            envelope_digest_set,
            transcript_digest,
            assignment,
        } => {
            push_len32(&mut out, b"signer_a");
            push_lifecycle_scope(&mut out, lifecycle);
            push_signer_set(&mut out, signer_set);
            push_router_transcript_metadata(&mut out, transcript_metadata);
            push_router_envelope_digest_set(&mut out, envelope_digest_set);
            push_public_digest(&mut out, *transcript_digest);
            push_role_envelope_assignment(&mut out, assignment);
        }
        RouterToSignerPayloadV1::SignerB {
            lifecycle,
            signer_set,
            transcript_metadata,
            envelope_digest_set,
            transcript_digest,
            assignment,
        } => {
            push_len32(&mut out, b"signer_b");
            push_lifecycle_scope(&mut out, lifecycle);
            push_signer_set(&mut out, signer_set);
            push_router_transcript_metadata(&mut out, transcript_metadata);
            push_router_envelope_digest_set(&mut out, envelope_digest_set);
            push_public_digest(&mut out, *transcript_digest);
            push_role_envelope_assignment(&mut out, assignment);
        }
    }
    out
}

/// Decodes Router-to-signer canonical bytes into a validated typed payload.
pub fn decode_router_to_signer_payload_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<RouterToSignerPayloadV1> {
    let mut decoder = PayloadDecoder::new(bytes);
    decoder.expect_bytes(
        ROUTER_TO_SIGNER_PAYLOAD_VERSION_V1,
        "router-to-signer payload version",
    )?;
    let branch = decoder.read_string("router-to-signer payload branch")?;
    let lifecycle = decoder.read_lifecycle_scope()?;
    let signer_set = decoder.read_signer_set()?;
    let transcript_metadata = decoder.read_router_transcript_metadata()?;
    let envelope_digest_set = decoder.read_router_envelope_digest_set()?;
    let transcript_digest = decoder.read_public_digest("transcript_digest")?;
    let assignment = decoder.read_role_envelope_assignment()?;
    decoder.finish()?;
    match branch.as_str() {
        "signer_a" => RouterToSignerPayloadV1::signer_a(
            lifecycle,
            signer_set,
            transcript_metadata,
            envelope_digest_set,
            transcript_digest,
            assignment,
        ),
        "signer_b" => RouterToSignerPayloadV1::signer_b(
            lifecycle,
            signer_set,
            transcript_metadata,
            envelope_digest_set,
            transcript_digest,
            assignment,
        ),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "router-to-signer payload branch is unknown",
        )),
    }
}

/// Computes the public digest of Router-to-signer canonical bytes.
pub fn router_to_signer_payload_digest_v1(payload: &RouterToSignerPayloadV1) -> PublicDigest32 {
    digest_bytes(&encode_router_to_signer_payload_v1(payload))
}

/// Decodes A/B peer canonical bytes into a validated typed payload.
pub fn decode_ab_peer_message_payload_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<AbPeerMessagePayloadV1> {
    let mut decoder = PayloadDecoder::new(bytes);
    decoder.expect_bytes(
        AB_PEER_MESSAGE_PAYLOAD_VERSION_V1,
        "A/B peer message payload version",
    )?;
    let from = decoder.read_signer_identity()?;
    let to = decoder.read_signer_identity()?;
    let transcript_digest = decoder.read_public_digest("transcript_digest")?;
    let payload = CanonicalWireBytesV1::new(decoder.read_bytes("peer_payload")?.to_vec())?;
    let signature_scheme =
        parse_ab_peer_signature_scheme(&decoder.read_string("signature_scheme")?)?;
    let signed_message_digest = decoder.read_public_digest("signed_message_digest")?;
    let signature = CanonicalWireBytesV1::new(decoder.read_bytes("signature")?.to_vec())?;
    decoder.finish()?;
    AbPeerMessagePayloadV1::new(
        from,
        to,
        transcript_digest,
        payload,
        AbPeerMessageAuthenticationV1::new(signature_scheme, signed_message_digest, signature)?,
    )
}

/// Encodes an A/B ECDSA threshold-PRF proof-batch payload with fixed field order.
pub fn encode_ecdsa_threshold_prf_proof_batch_payload_v1(
    payload: &EcdsaThresholdPrfProofBatchPayloadV1,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, ECDSA_THRESHOLD_PRF_PROOF_BATCH_PAYLOAD_VERSION_V1);
    push_signer_identity(&mut out, &payload.from);
    push_signer_identity(&mut out, &payload.to);
    push_public_digest(&mut out, payload.transcript_digest);
    push_string(&mut out, payload.root_share_epoch.as_str());
    push_u32(&mut out, payload.proof_bundles.len() as u32);
    for bundle in &payload.proof_bundles {
        push_mpc_prf_partial_proof_bundle(&mut out, bundle);
    }
    out
}

/// Decodes A/B ECDSA threshold-PRF proof-batch canonical bytes.
pub fn decode_ecdsa_threshold_prf_proof_batch_payload_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<EcdsaThresholdPrfProofBatchPayloadV1> {
    let mut decoder = PayloadDecoder::new(bytes);
    decoder.expect_bytes(
        ECDSA_THRESHOLD_PRF_PROOF_BATCH_PAYLOAD_VERSION_V1,
        "A/B ECDSA threshold-PRF proof-batch payload version",
    )?;
    let from = decoder.read_signer_identity()?;
    let to = decoder.read_signer_identity()?;
    let transcript_digest = decoder.read_public_digest("transcript_digest")?;
    let root_share_epoch = RootShareEpoch::new(decoder.read_string("root_share_epoch")?)
        .map_err(map_derivation_to_protocol_error)?;
    let proof_count = decoder.read_u32("proof_bundle_count")?;
    let mut proof_bundles = Vec::with_capacity(proof_count as usize);
    for _ in 0..proof_count {
        proof_bundles.push(decoder.read_mpc_prf_partial_proof_bundle()?);
    }
    decoder.finish()?;
    EcdsaThresholdPrfProofBatchPayloadV1::new(
        from,
        to,
        transcript_digest,
        root_share_epoch,
        proof_bundles,
    )
}

/// Decodes and validates a proof batch inside an authenticated A/B peer payload.
pub fn decode_and_validate_ecdsa_threshold_prf_proof_batch_peer_payload_v1(
    peer_payload: &AbPeerMessagePayloadV1,
) -> RouterAbProtocolResult<EcdsaThresholdPrfProofBatchPayloadV1> {
    peer_payload.validate()?;
    let proof_batch =
        decode_ecdsa_threshold_prf_proof_batch_payload_v1(peer_payload.payload.as_bytes())?;
    if proof_batch.from != peer_payload.from
        || proof_batch.to != peer_payload.to
        || proof_batch.transcript_digest != peer_payload.transcript_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "A/B ECDSA threshold-PRF proof batch does not match authenticated peer envelope",
        ));
    }
    Ok(proof_batch)
}

/// Builds and signs an A/B ECDSA threshold-PRF proof batch for peer delivery.
pub fn sign_ecdsa_threshold_prf_proof_batch_peer_payload_v1(
    signing_key_bytes: &[u8; 32],
    from: SignerIdentityV1,
    to: SignerIdentityV1,
    batch_output: MpcPrfThresholdSignerBatchOutputV1,
) -> RouterAbProtocolResult<AbPeerMessagePayloadV1> {
    if batch_output.signer_role != from.role || batch_output.signer_identity != from.signer_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "A/B ECDSA threshold-PRF proof batch output does not match sender identity",
        ));
    }
    let proof_batch = EcdsaThresholdPrfProofBatchPayloadV1::new(
        from.clone(),
        to.clone(),
        batch_output.transcript_digest,
        batch_output.root_share_epoch,
        batch_output.proof_bundles,
    )?;
    let payload = CanonicalWireBytesV1::new(proof_batch.canonical_bytes())?;
    let authentication = sign_ab_peer_message_ed25519_authentication_v1(
        signing_key_bytes,
        &from,
        &to,
        proof_batch.transcript_digest,
        &payload,
    )?;
    AbPeerMessagePayloadV1::new(
        from,
        to,
        proof_batch.transcript_digest,
        payload,
        authentication,
    )
}

/// Computes the public digest of A/B ECDSA threshold-PRF proof-batch canonical bytes.
pub fn ecdsa_threshold_prf_proof_batch_payload_digest_v1(
    payload: &EcdsaThresholdPrfProofBatchPayloadV1,
) -> PublicDigest32 {
    digest_bytes(&encode_ecdsa_threshold_prf_proof_batch_payload_v1(payload))
}

/// Encodes a recipient-scoped proof-bundle payload with fixed field order.
pub fn encode_recipient_proof_bundle_payload_v1(
    payload: &RecipientProofBundlePayloadV1,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V1);
    push_string(&mut out, &payload.lifecycle_id);
    push_signer_identity(&mut out, &payload.signer);
    push_role(&mut out, payload.recipient_role);
    push_len32(&mut out, payload.opened_share_kind.as_str().as_bytes());
    push_string(&mut out, &payload.recipient_identity);
    push_public_digest(&mut out, payload.transcript_digest);
    push_len32(&mut out, &payload.proof_batch.canonical_bytes());
    out
}

/// Decodes a recipient-scoped proof-bundle canonical payload.
pub fn decode_recipient_proof_bundle_payload_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<RecipientProofBundlePayloadV1> {
    let mut decoder = PayloadDecoder::new(bytes);
    decoder.expect_bytes(
        RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V1,
        "recipient proof-bundle payload version",
    )?;
    let lifecycle_id = decoder.read_string("lifecycle_id")?;
    let signer = decoder.read_signer_identity()?;
    let recipient_role = decoder.read_role()?;
    let opened_share_kind = parse_opened_share_kind(&decoder.read_string("opened_share_kind")?)?;
    let recipient_identity = decoder.read_string("recipient_identity")?;
    let transcript_digest = decoder.read_public_digest("transcript_digest")?;
    let proof_batch =
        decode_ecdsa_threshold_prf_proof_batch_payload_v1(decoder.read_bytes("proof_batch")?)?;
    decoder.finish()?;
    RecipientProofBundlePayloadV1::new(
        lifecycle_id,
        signer,
        recipient_role,
        opened_share_kind,
        recipient_identity,
        transcript_digest,
        proof_batch,
    )
}

/// Computes the public digest of recipient proof-bundle canonical bytes.
pub fn recipient_proof_bundle_payload_digest_v1(
    payload: &RecipientProofBundlePayloadV1,
) -> PublicDigest32 {
    digest_bytes(&encode_recipient_proof_bundle_payload_v1(payload))
}

/// Validates decrypted signer-input plaintext against its Router-to-signer envelope.
pub fn validate_signer_input_plaintext_binding_v1(
    payload: &RouterToSignerPayloadV1,
    plaintext: &SignerInputPlaintextV1,
    expected_router_request_digest: PublicDigest32,
    expected_root_share_epoch: &RootShareEpoch,
) -> RouterAbProtocolResult<()> {
    payload.validate()?;
    plaintext.validate().map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("signer input plaintext is invalid: {:?}", err.code()),
        )
    })?;
    let assignment = payload.require_recipient_role(plaintext.recipient_role)?;
    let lifecycle = payload.lifecycle();
    let signer_set = payload.signer_set();

    if plaintext.request_kind != lifecycle.primitive_request_kind {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "signer input plaintext request kind does not match lifecycle",
        ));
    }
    if plaintext.lifecycle_id != lifecycle.lifecycle_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "signer input plaintext lifecycle id does not match payload",
        ));
    }
    if plaintext.signer_set_id != signer_set.signer_set_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "signer input plaintext signer-set id does not match payload",
        ));
    }
    if plaintext.recipient_signer_id != assignment.signer.signer_id
        || plaintext.recipient_key_epoch != assignment.signer.key_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "signer input plaintext recipient identity does not match assignment",
        ));
    }
    if plaintext.selected_server_id != signer_set.selected_server.server_id
        || plaintext.selected_server_key_epoch != signer_set.selected_server.key_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "signer input plaintext server identity does not match signer set",
        ));
    }
    if plaintext.transcript_digest != payload.transcript_digest() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "signer input plaintext transcript digest does not match payload",
        ));
    }
    if plaintext.router_request_digest != expected_router_request_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "signer input plaintext Router request digest mismatch",
        ));
    }
    if plaintext.aad_digest != assignment.envelope.aad_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "signer input plaintext AAD digest does not match envelope",
        ));
    }
    if &plaintext.root_share_epoch != expected_root_share_epoch {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
            "signer input plaintext root-share epoch does not match local root metadata",
        ));
    }
    require_plaintext_output_policy(&plaintext.output_requests)
}

/// Builds fixed ECDSA threshold-PRF input after plaintext binding validation.
pub fn build_mpc_prf_signer_partial_input_v1(
    payload: &RouterToSignerPayloadV1,
    plaintext: &SignerInputPlaintextV1,
) -> RouterAbProtocolResult<MpcPrfSignerPartialInputV1> {
    payload.validate()?;
    plaintext.validate().map_err(|err| {
        RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("signer input plaintext is invalid: {:?}", err.code()),
        )
    })?;
    require_plaintext_output_policy(&plaintext.output_requests)?;
    let expected_transcript_digest = router_transcript_digest_v1(
        payload.lifecycle(),
        payload.signer_set(),
        payload.transcript_metadata(),
        plaintext.root_share_epoch.clone(),
    )?;
    if expected_transcript_digest != payload.transcript_digest()
        || expected_transcript_digest != plaintext.transcript_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "signer input plaintext transcript digest does not match reconstructed transcript binding",
        ));
    }
    let transcript = router_transcript_binding_v1(
        payload.lifecycle(),
        payload.signer_set(),
        payload.transcript_metadata(),
        plaintext.root_share_epoch.clone(),
    )?;
    MpcPrfSignerPartialInputV1::new(
        transcript.context().clone(),
        transcript,
        plaintext.recipient_role,
        plaintext.recipient_signer_id.clone(),
        plaintext.root_share_epoch.clone(),
        plaintext.output_requests.clone(),
    )
    .map_err(map_derivation_to_protocol_error)
}

/// Encodes A/B peer message payload bytes with fixed field order.
pub fn encode_ab_peer_message_payload_v1(payload: &AbPeerMessagePayloadV1) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, AB_PEER_MESSAGE_PAYLOAD_VERSION_V1);
    push_signer_identity(&mut out, &payload.from);
    push_signer_identity(&mut out, &payload.to);
    push_public_digest(&mut out, payload.transcript_digest);
    push_len32(&mut out, payload.payload.as_bytes());
    push_len32(
        &mut out,
        payload.authentication.signature_scheme.as_str().as_bytes(),
    );
    push_public_digest(&mut out, payload.authentication.signed_message_digest);
    push_len32(&mut out, payload.authentication.signature.as_bytes());
    out
}

/// Encodes canonical bytes that the peer sender signs.
pub fn encode_ab_peer_message_authentication_input_v1(
    from: &SignerIdentityV1,
    to: &SignerIdentityV1,
    transcript_digest: PublicDigest32,
    payload: &CanonicalWireBytesV1,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, AB_PEER_MESSAGE_AUTHENTICATION_INPUT_VERSION_V1);
    push_signer_identity(&mut out, from);
    push_signer_identity(&mut out, to);
    push_public_digest(&mut out, transcript_digest);
    push_len32(&mut out, payload.as_bytes());
    out
}

/// Computes the digest of canonical bytes that the peer sender signs.
pub fn ab_peer_message_authentication_input_digest_v1(
    from: &SignerIdentityV1,
    to: &SignerIdentityV1,
    transcript_digest: PublicDigest32,
    payload: &CanonicalWireBytesV1,
) -> PublicDigest32 {
    digest_bytes(&encode_ab_peer_message_authentication_input_v1(
        from,
        to,
        transcript_digest,
        payload,
    ))
}

/// Signs canonical A/B peer-message authentication input with an Ed25519 key.
pub fn sign_ab_peer_message_ed25519_authentication_v1(
    signing_key_bytes: &[u8; 32],
    from: &SignerIdentityV1,
    to: &SignerIdentityV1,
    transcript_digest: PublicDigest32,
    payload: &CanonicalWireBytesV1,
) -> RouterAbProtocolResult<AbPeerMessageAuthenticationV1> {
    from.validate()?;
    to.validate()?;
    let signed_bytes =
        encode_ab_peer_message_authentication_input_v1(from, to, transcript_digest, payload);
    let signature = SigningKey::from_bytes(signing_key_bytes).sign(&signed_bytes);
    AbPeerMessageAuthenticationV1::new(
        AbPeerMessageSignatureSchemeV1::Ed25519V1,
        digest_bytes(&signed_bytes),
        CanonicalWireBytesV1::new(signature.to_bytes().to_vec())?,
    )
}

/// Verifies the Ed25519 signature on an authenticated A/B peer message.
pub fn verify_ab_peer_message_ed25519_signature_v1(
    payload: &AbPeerMessagePayloadV1,
    verifying_key: &AbPeerMessageVerifyingKeyV1,
) -> RouterAbProtocolResult<()> {
    payload.validate()?;
    verifying_key.validate()?;
    if payload.authentication.signature_scheme != AbPeerMessageSignatureSchemeV1::Ed25519V1 {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "A/B peer authentication signature scheme is not Ed25519 v1",
        ));
    }
    if payload.from != verifying_key.signer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "A/B peer verifying key signer does not match payload sender",
        ));
    }
    let signature =
        Signature::from_slice(payload.authentication.signature.as_bytes()).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "A/B peer Ed25519 signature must be 64 bytes",
            )
        })?;
    let public_key =
        VerifyingKey::from_bytes(&verifying_key.verifying_key_bytes).map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "A/B peer verifying key bytes are invalid",
            )
        })?;
    public_key
        .verify_strict(&payload.authentication_input_bytes(), &signature)
        .map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "A/B peer Ed25519 signature verification failed",
            )
        })
}

/// Computes the public digest of A/B peer message canonical bytes.
pub fn ab_peer_message_payload_digest_v1(payload: &AbPeerMessagePayloadV1) -> PublicDigest32 {
    digest_bytes(&encode_ab_peer_message_payload_v1(payload))
}

fn validate_router_to_signer(
    lifecycle: &LifecycleScopeV1,
    signer_set: &SignerSetV1,
    transcript_metadata: &RouterTranscriptMetadataV1,
    envelope_digest_set: &RouterEnvelopeDigestSetV1,
    assignment: &RoleEnvelopeAssignmentV1,
    expected_role: Role,
) -> RouterAbProtocolResult<()> {
    lifecycle.validate()?;
    signer_set.validate()?;
    transcript_metadata.validate()?;
    assignment.validate()?;
    if lifecycle.signer_set_id != signer_set.signer_set_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "router-to-signer lifecycle signer-set id does not match signer set",
        ));
    }
    if lifecycle.selected_server_id != signer_set.selected_server.server_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "router-to-signer lifecycle selected server does not match signer set",
        ));
    }
    if assignment.signer.role != expected_role {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "router-to-signer payload branch does not match assignment role",
        ));
    }
    let expected_signer = match expected_role {
        Role::SignerA => &signer_set.signer_a,
        Role::SignerB => &signer_set.signer_b,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "router-to-signer payload expected a signer role",
            ));
        }
    };
    if &assignment.signer != expected_signer {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "router-to-signer assignment identity does not match signer set",
        ));
    }
    let expected_envelope_digest = envelope_digest_set.digest_for_role(expected_role)?;
    let actual_envelope_digest = role_encrypted_envelope_digest_v1(&assignment.envelope)?;
    if actual_envelope_digest != expected_envelope_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "router-to-signer envelope digest does not match assignment envelope",
        ));
    }
    Ok(())
}

fn validate_stable_prf_purpose(purpose: &PrfPurpose) -> RouterAbProtocolResult<()> {
    match purpose {
        PrfPurpose::RouterAbEcdsaDerivationYServer
        | PrfPurpose::RouterAbXClientBaseV1
        | PrfPurpose::RouterAbXServerBaseV1 => Ok(()),
        PrfPurpose::Ed25519DeriverAContributionRoot
        | PrfPurpose::Ed25519DeriverBContributionRoot => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root proof bundle purpose must be an ECDSA purpose",
        )),
    }
}

fn stable_prf_recipient_role(purpose: &PrfPurpose) -> RouterAbProtocolResult<Role> {
    match purpose {
        PrfPurpose::RouterAbEcdsaDerivationYServer | PrfPurpose::RouterAbXServerBaseV1 => {
            Ok(Role::Server)
        }
        PrfPurpose::RouterAbXClientBaseV1 => Ok(Role::Client),
        PrfPurpose::Ed25519DeriverAContributionRoot
        | PrfPurpose::Ed25519DeriverBContributionRoot => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root recipient purpose must be an ECDSA purpose",
        )),
    }
}

fn validate_stable_proof_wire_shape(
    signer_role: Role,
    partial_wire: &MpcPrfPartialWireV1,
    commitment_wire: &MpcPrfShareCommitmentWireV1,
    proof_wire: &MpcPrfDleqProofWireV1,
) -> RouterAbProtocolResult<()> {
    let partial_bytes = partial_wire.as_bytes();
    if partial_bytes.len() != crate::derivation::MPC_PRF_PARTIAL_WIRE_V1_LEN {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root proof bundle partial wire has invalid length",
        ));
    }
    let commitment_bytes = commitment_wire.as_bytes();
    if commitment_bytes.len() != crate::derivation::MPC_PRF_COMMITMENT_WIRE_V1_LEN {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root proof bundle commitment wire has invalid length",
        ));
    }
    if proof_wire.as_bytes().len() != crate::derivation::MPC_PRF_DLEQ_PROOF_WIRE_V1_LEN {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root proof bundle proof wire has invalid length",
        ));
    }
    let partial_share_id = u16::from_be_bytes([partial_bytes[0], partial_bytes[1]]);
    let commitment_share_id = u16::from_be_bytes([commitment_bytes[0], commitment_bytes[1]]);
    if partial_share_id != commitment_share_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root proof bundle partial and commitment share ids differ",
        ));
    }
    let expected_share_id = match signer_role {
        Role::SignerA => 1,
        Role::SignerB => 2,
        _ => {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidRole,
                "stable tenant-root proof bundle requires a signer role",
            ));
        }
    };
    if partial_share_id != expected_share_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "stable tenant-root proof bundle share id does not match signer role",
        ));
    }
    Ok(())
}

fn validate_stable_plan_metadata(
    expected_plan: &MpcPrfStablePurposeBindingPlanV2,
    stable_context_digest: TenantRootProtocolDigestV1,
    custody_binding_digest: TenantRootProtocolDigestV1,
    purpose: &PrfPurpose,
) -> RouterAbProtocolResult<()> {
    if expected_plan.stable_context_digest() != stable_context_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root proof bundle stable-context digest does not match expected plan",
        ));
    }
    if expected_plan.custody_binding_digest() != custody_binding_digest {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root proof bundle custody-binding digest does not match expected plan",
        ));
    }
    if expected_plan.purpose() != purpose {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "stable tenant-root proof bundle purpose does not match expected plan",
        ));
    }
    Ok(())
}

fn require_plaintext_output_policy(
    output_requests: &[MpcPrfOutputRequestV1],
) -> RouterAbProtocolResult<()> {
    for request in output_requests {
        validate_recipient_delivery_policy(request.recipient_role, request.opened_share_kind)?;
    }
    Ok(())
}

fn validate_recipient_delivery_policy(
    recipient_role: Role,
    opened_share_kind: OpenedShareKind,
) -> RouterAbProtocolResult<()> {
    match (opened_share_kind, recipient_role) {
        (OpenedShareKind::XClientBase, Role::Client)
        | (OpenedShareKind::XServerBase, Role::Server) => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "recipient delivery binding violates recipient policy",
        )),
    }
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty() {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}

fn require_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "router-to-signer payload expected a signer role",
        )),
    }
}

fn push_lifecycle_scope(out: &mut Vec<u8>, scope: &LifecycleScopeV1) {
    push_string(out, &scope.lifecycle_id);
    push_len32(out, scope.work_kind.as_str().as_bytes());
    push_len32(out, scope.primitive_request_kind.as_str().as_bytes());
    push_string(out, scope.root_share_epoch.as_str());
    push_string(out, &scope.account_id);
    push_string(out, &scope.session_id);
    push_string(out, &scope.signer_set_id);
    push_string(out, &scope.selected_server_id);
}

fn push_signer_set(out: &mut Vec<u8>, signer_set: &SignerSetV1) {
    push_string(out, &signer_set.signer_set_id);
    push_signer_set_policy(out, signer_set.policy);
    push_signer_identity(out, &signer_set.signer_a);
    push_signer_identity(out, &signer_set.signer_b);
    push_server_identity(out, &signer_set.selected_server);
}

fn push_signer_set_policy(out: &mut Vec<u8>, policy: SignerSetPolicyV1) {
    push_len32(out, policy.as_str().as_bytes());
}

fn push_router_transcript_metadata(out: &mut Vec<u8>, metadata: &RouterTranscriptMetadataV1) {
    push_string(out, &metadata.network_id);
    push_string(out, &metadata.account_public_key);
    push_string(out, &metadata.router_id);
    push_string(out, &metadata.client_id);
    push_string(out, &metadata.client_ephemeral_public_key);
}

fn push_router_envelope_digest_set(out: &mut Vec<u8>, digest_set: &RouterEnvelopeDigestSetV1) {
    push_public_digest(out, digest_set.signer_a_envelope_digest);
    push_public_digest(out, digest_set.signer_b_envelope_digest);
}

fn push_signer_identity(out: &mut Vec<u8>, identity: &SignerIdentityV1) {
    push_role(out, identity.role);
    push_string(out, &identity.signer_id);
    push_string(out, &identity.key_epoch);
}

fn push_server_identity(out: &mut Vec<u8>, identity: &ServerIdentityV1) {
    push_string(out, &identity.server_id);
    push_string(out, &identity.key_epoch);
    push_string(out, &identity.recipient_encryption_key);
}

fn push_role_envelope_assignment(out: &mut Vec<u8>, assignment: &RoleEnvelopeAssignmentV1) {
    push_signer_identity(out, &assignment.signer);
    push_role_encrypted_envelope(out, &assignment.envelope);
}

fn push_role_encrypted_envelope(out: &mut Vec<u8>, envelope: &RoleEncryptedEnvelopeV1) {
    push_role(out, envelope.recipient_role);
    push_public_digest(out, envelope.header_digest);
    push_public_digest(out, envelope.aad_digest);
    push_len32(out, envelope.ciphertext.as_bytes());
}

fn push_mpc_prf_partial_proof_bundle(out: &mut Vec<u8>, bundle: &MpcPrfPartialProofBundleV1) {
    let binding = &bundle.signer_partial.binding;
    push_len32(out, b"threshold_prf_ristretto255_sha512");
    push_public_digest(out, binding.transcript_digest);
    push_string(out, binding.root_share_epoch.as_str());
    push_len32(out, binding.opened_share_kind.as_str().as_bytes());
    push_role(out, binding.recipient_role);
    push_string(out, &binding.recipient_identity);
    push_role(out, binding.signer_role);
    push_string(out, &binding.signer_identity);
    push_len32(out, bundle.signer_partial.partial_wire.as_bytes());
    push_len32(out, bundle.commitment_wire.as_bytes());
    push_len32(out, bundle.proof_wire.as_bytes());
}

fn push_role(out: &mut Vec<u8>, role: Role) {
    push_len32(out, role.as_str().as_bytes());
}

fn push_public_digest(out: &mut Vec<u8>, digest: PublicDigest32) {
    push_len32(out, digest.as_bytes());
}

fn push_tenant_root_protocol_digest(out: &mut Vec<u8>, digest: TenantRootProtocolDigestV1) {
    push_len32(out, digest.as_bytes());
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    push_len32(out, value.as_bytes());
}

fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

fn push_len32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn digest_bytes(bytes: &[u8]) -> PublicDigest32 {
    let digest = Sha256::digest(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    PublicDigest32::new(out)
}

struct PayloadDecoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadDecoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn finish(&self) -> RouterAbProtocolResult<()> {
        if self.offset == self.bytes.len() {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "canonical payload has trailing bytes",
        ))
    }

    fn expect_bytes(&mut self, expected: &[u8], field: &'static str) -> RouterAbProtocolResult<()> {
        let actual = self.read_bytes(field)?;
        if actual == expected {
            return Ok(());
        }
        Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            format!("{field} mismatch"),
        ))
    }

    fn read_lifecycle_scope(&mut self) -> RouterAbProtocolResult<LifecycleScopeV1> {
        let lifecycle_id = self.read_string("lifecycle_id")?;
        let work_kind = parse_work_kind(&self.read_string("work_kind")?)?;
        let primitive_request_kind =
            parse_request_kind(&self.read_string("primitive_request_kind")?)?;
        let root_share_epoch = RootShareEpoch::new(self.read_string("root_share_epoch")?)
            .map_err(map_derivation_to_protocol_error)?;
        let account_id = self.read_string("account_id")?;
        let session_id = self.read_string("session_id")?;
        let signer_set_id = self.read_string("signer_set_id")?;
        let selected_server_id = self.read_string("selected_server_id")?;
        let lifecycle = LifecycleScopeV1::new(
            lifecycle_id,
            work_kind,
            root_share_epoch,
            account_id,
            session_id,
            signer_set_id,
            selected_server_id,
        )?;
        if lifecycle.primitive_request_kind != primitive_request_kind {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "decoded lifecycle primitive request kind does not match work kind",
            ));
        }
        Ok(lifecycle)
    }

    fn read_signer_set(&mut self) -> RouterAbProtocolResult<SignerSetV1> {
        let signer_set_id = self.read_string("signer_set_id")?;
        let policy = parse_signer_set_policy(&self.read_string("signer_set_policy")?)?;
        let signer_a = self.read_signer_identity()?;
        let signer_b = self.read_signer_identity()?;
        let selected_server = self.read_server_identity()?;
        let signer_set = SignerSetV1::v1_all2(signer_set_id, signer_a, signer_b, selected_server)?;
        if signer_set.policy != policy {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "decoded signer-set policy does not match v1 all(2)",
            ));
        }
        Ok(signer_set)
    }

    fn read_router_transcript_metadata(
        &mut self,
    ) -> RouterAbProtocolResult<RouterTranscriptMetadataV1> {
        let network_id = self.read_string("network_id")?;
        let account_public_key = self.read_string("account_public_key")?;
        let router_id = self.read_string("router_id")?;
        let client_id = self.read_string("client_id")?;
        let client_ephemeral_public_key = self.read_string("client_ephemeral_public_key")?;
        RouterTranscriptMetadataV1::new(
            network_id,
            account_public_key,
            router_id,
            client_id,
            client_ephemeral_public_key,
        )
    }

    fn read_router_envelope_digest_set(
        &mut self,
    ) -> RouterAbProtocolResult<RouterEnvelopeDigestSetV1> {
        let signer_a_envelope_digest = self.read_public_digest("signer_a_envelope_digest")?;
        let signer_b_envelope_digest = self.read_public_digest("signer_b_envelope_digest")?;
        Ok(RouterEnvelopeDigestSetV1::new(
            signer_a_envelope_digest,
            signer_b_envelope_digest,
        ))
    }

    fn read_role_envelope_assignment(
        &mut self,
    ) -> RouterAbProtocolResult<RoleEnvelopeAssignmentV1> {
        let signer = self.read_signer_identity()?;
        let envelope = self.read_role_encrypted_envelope()?;
        RoleEnvelopeAssignmentV1::new(signer, envelope)
    }

    fn read_role_encrypted_envelope(&mut self) -> RouterAbProtocolResult<RoleEncryptedEnvelopeV1> {
        let recipient_role = self.read_role()?;
        let header_digest = self.read_public_digest("header_digest")?;
        let aad_digest = self.read_public_digest("aad_digest")?;
        let ciphertext = EncryptedPayloadV1::new(self.read_bytes("ciphertext")?.to_vec())?;
        RoleEncryptedEnvelopeV1::new(recipient_role, header_digest, aad_digest, ciphertext)
    }

    fn read_signer_identity(&mut self) -> RouterAbProtocolResult<SignerIdentityV1> {
        let role = self.read_role()?;
        let signer_id = self.read_string("signer_id")?;
        let key_epoch = self.read_string("key_epoch")?;
        SignerIdentityV1::new(role, signer_id, key_epoch)
    }

    fn read_server_identity(&mut self) -> RouterAbProtocolResult<ServerIdentityV1> {
        let server_id = self.read_string("server_id")?;
        let key_epoch = self.read_string("server_key_epoch")?;
        let recipient_encryption_key = self.read_string("server_recipient_encryption_key")?;
        ServerIdentityV1::new(server_id, key_epoch, recipient_encryption_key)
    }

    fn read_role(&mut self) -> RouterAbProtocolResult<Role> {
        parse_role(&self.read_string("role")?)
    }

    fn read_public_digest(
        &mut self,
        field: &'static str,
    ) -> RouterAbProtocolResult<PublicDigest32> {
        let bytes = self.read_bytes(field)?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} must be 32 bytes"),
            )
        })?;
        Ok(PublicDigest32::new(digest))
    }

    fn read_tenant_root_protocol_digest(
        &mut self,
        field: &'static str,
    ) -> RouterAbProtocolResult<TenantRootProtocolDigestV1> {
        let bytes = self.read_bytes(field)?;
        let digest: [u8; 32] = bytes.try_into().map_err(|_| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} must be 32 bytes"),
            )
        })?;
        TenantRootProtocolDigestV1::from_bytes(digest).map_err(map_derivation_to_protocol_error)
    }

    fn read_mpc_prf_partial_proof_bundle(
        &mut self,
    ) -> RouterAbProtocolResult<MpcPrfPartialProofBundleV1> {
        let suite_label = self.read_string("mpc_prf_suite_id")?;
        if suite_label != "threshold_prf_ristretto255_sha512" {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "unexpected fixed ECDSA threshold-PRF suite label",
            ));
        }
        let transcript_digest = self.read_public_digest("mpc_prf_transcript_digest")?;
        let root_share_epoch = RootShareEpoch::new(self.read_string("mpc_prf_root_share_epoch")?)
            .map_err(map_derivation_to_protocol_error)?;
        let opened_share_kind =
            parse_opened_share_kind(&self.read_string("mpc_prf_opened_share_kind")?)?;
        let recipient_role = self.read_role()?;
        let recipient_identity = self.read_string("mpc_prf_recipient_identity")?;
        let signer_role = self.read_role()?;
        let signer_identity = self.read_string("mpc_prf_signer_identity")?;
        let partial_wire =
            MpcPrfPartialWireV1::new(self.read_bytes("mpc_prf_partial_wire")?.to_vec())
                .map_err(map_derivation_to_protocol_error)?;
        let commitment_wire =
            MpcPrfShareCommitmentWireV1::new(self.read_bytes("mpc_prf_commitment_wire")?.to_vec())
                .map_err(map_derivation_to_protocol_error)?;
        let proof_wire =
            MpcPrfDleqProofWireV1::new(self.read_bytes("mpc_prf_dleq_proof_wire")?.to_vec())
                .map_err(map_derivation_to_protocol_error)?;
        let binding = MpcPrfPartialBindingV1 {
            transcript_digest,
            root_share_epoch,
            opened_share_kind,
            recipient_role,
            recipient_identity,
            signer_role,
            signer_identity,
        };
        let signer_partial = MpcPrfSignerPartialV1::new(binding, partial_wire)
            .map_err(map_derivation_to_protocol_error)?;
        MpcPrfPartialProofBundleV1::new(signer_partial, commitment_wire, proof_wire)
            .map_err(map_derivation_to_protocol_error)
    }

    fn read_string(&mut self, field: &'static str) -> RouterAbProtocolResult<String> {
        let bytes = self.read_bytes(field)?;
        let value = core::str::from_utf8(bytes).map_err(|err| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} is not valid UTF-8: {err}"),
            )
        })?;
        Ok(value.to_owned())
    }

    fn read_u32(&mut self, field: &'static str) -> RouterAbProtocolResult<u32> {
        let end = self.offset.checked_add(4).ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} overflow"),
            )
        })?;
        if end > self.bytes.len() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} is truncated"),
            ));
        }
        let mut value_bytes = [0u8; 4];
        value_bytes.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(u32::from_be_bytes(value_bytes))
    }

    fn read_bytes(&mut self, field: &'static str) -> RouterAbProtocolResult<&'a [u8]> {
        let len = self.read_len(field)?;
        let end = self.offset.checked_add(len).ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} length overflow"),
            )
        })?;
        if end > self.bytes.len() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} length exceeds payload"),
            ));
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn read_len(&mut self, field: &'static str) -> RouterAbProtocolResult<usize> {
        let end = self.offset.checked_add(4).ok_or_else(|| {
            RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} length prefix overflow"),
            )
        })?;
        if end > self.bytes.len() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                format!("{field} length prefix is truncated"),
            ));
        }
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&self.bytes[self.offset..end]);
        self.offset = end;
        Ok(u32::from_be_bytes(len_bytes) as usize)
    }
}

fn parse_work_kind(value: &str) -> RouterAbProtocolResult<ExpensiveWorkKindV1> {
    match value {
        "registration_prepare" => Ok(ExpensiveWorkKindV1::RegistrationPrepare),
        "key_export" => Ok(ExpensiveWorkKindV1::KeyExport),
        "recovery" => Ok(ExpensiveWorkKindV1::Recovery),
        "server_share_refresh" => Ok(ExpensiveWorkKindV1::ServerShareRefresh),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown lifecycle work kind",
        )),
    }
}

fn parse_request_kind(value: &str) -> RouterAbProtocolResult<RequestKind> {
    match value {
        "registration" => Ok(RequestKind::Registration),
        "recovery" => Ok(RequestKind::Recovery),
        "export" => Ok(RequestKind::Export),
        "refresh" => Ok(RequestKind::Refresh),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown lifecycle primitive request kind",
        )),
    }
}

fn parse_opened_share_kind(value: &str) -> RouterAbProtocolResult<OpenedShareKind> {
    match value {
        "x_client_base" => Ok(OpenedShareKind::XClientBase),
        "x_server_base" => Ok(OpenedShareKind::XServerBase),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown opened share kind",
        )),
    }
}

fn parse_stable_prf_purpose(value: &str) -> RouterAbProtocolResult<PrfPurpose> {
    match value {
        "router-ab-ecdsa-derivation/y-server/v1" => Ok(PrfPurpose::RouterAbEcdsaDerivationYServer),
        "router-ab/x_client_base/v1" => Ok(PrfPurpose::RouterAbXClientBaseV1),
        "router-ab/x_server_base/v1" => Ok(PrfPurpose::RouterAbXServerBaseV1),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown stable tenant-root threshold-PRF purpose",
        )),
    }
}

fn parse_signer_set_policy(value: &str) -> RouterAbProtocolResult<SignerSetPolicyV1> {
    match value {
        "all_2" => Ok(SignerSetPolicyV1::All2),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown signer-set policy",
        )),
    }
}

fn map_derivation_to_protocol_error(error: RouterAbDerivationError) -> RouterAbProtocolError {
    RouterAbProtocolError::new(
        RouterAbProtocolErrorCode::MalformedWirePayload,
        format!(
            "A/B derivation payload rejected derivation field: {:?}",
            error.code()
        ),
    )
}

fn parse_role(value: &str) -> RouterAbProtocolResult<Role> {
    match value {
        "router" => Ok(Role::Router),
        "signer_a" => Ok(Role::SignerA),
        "signer_b" => Ok(Role::SignerB),
        "server" => Ok(Role::Server),
        "client" => Ok(Role::Client),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "unknown role label",
        )),
    }
}

fn parse_ab_peer_signature_scheme(
    value: &str,
) -> RouterAbProtocolResult<AbPeerMessageSignatureSchemeV1> {
    match value {
        "ed25519_v1" => Ok(AbPeerMessageSignatureSchemeV1::Ed25519V1),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown A/B peer signature scheme",
        )),
    }
}
