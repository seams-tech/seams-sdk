use crate::derivation::{
    transcript_digest_v1, AccountScope, CandidateId, CorrectnessLevel, DerivationContext,
    MpcPrfDleqProofWireV1, MpcPrfOutputRequestV1, MpcPrfPartialBindingV1,
    MpcPrfPartialProofBundleV1, MpcPrfPartialWireV1, MpcPrfShareCommitmentWireV1,
    MpcPrfSignerPartialInputV1, MpcPrfSignerPartialV1, MpcPrfSuiteId,
    MpcPrfThresholdSignerBatchOutputV1, OpenedShareKind, PublicDigest32, RequestKind, Role,
    RootShareEpoch, RouterAbDerivationError, SignerInputPlaintextV1, SignerSetBinding,
    TranscriptBinding,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::protocol::envelope::{
    role_encrypted_envelope_digest_v1, EncryptedPayloadV1, RoleEncryptedEnvelopeV1,
};
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};
use crate::protocol::gate::ExpensiveWorkKindV1;
use crate::protocol::identity::{
    RelayerIdentityV1, RoleEnvelopeAssignmentV1, SignerIdentityV1, SignerSetPolicyV1, SignerSetV1,
};
use crate::protocol::lifecycle::LifecycleScopeV1;
use crate::protocol::wire::CanonicalWireBytesV1;

const ROUTER_TO_SIGNER_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/router-to-signer-payload/v1";
const AB_PEER_MESSAGE_PAYLOAD_VERSION_V1: &[u8] = b"router-ab-protocol/ab-peer-message-payload/v1";
const AB_PEER_MESSAGE_AUTHENTICATION_INPUT_VERSION_V1: &[u8] =
    b"router-ab-protocol/ab-peer-message-authentication-input/v1";
const AB_DERIVATION_PROOF_BATCH_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/ab-derivation-proof-batch-payload/v1";
const RECIPIENT_PROOF_BUNDLE_PAYLOAD_VERSION_V1: &[u8] =
    b"router-ab-protocol/recipient-proof-bundle-payload/v1";

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
            signer_set.selected_relayer.relayer_id.clone(),
            signer_set.selected_relayer.recipient_encryption_key.clone(),
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
    candidate_id: CandidateId,
    correctness_level: CorrectnessLevel,
    root_share_epoch: RootShareEpoch,
) -> RouterAbProtocolResult<TranscriptBinding> {
    lifecycle.validate()?;
    signer_set.validate()?;
    transcript_metadata.validate()?;
    let context = DerivationContext::new(
        candidate_id,
        lifecycle.primitive_request_kind,
        correctness_level,
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
    candidate_id: CandidateId,
    correctness_level: CorrectnessLevel,
    root_share_epoch: RootShareEpoch,
) -> RouterAbProtocolResult<PublicDigest32> {
    let transcript = router_transcript_binding_v1(
        lifecycle,
        signer_set,
        transcript_metadata,
        candidate_id,
        correctness_level,
        root_share_epoch,
    )?;
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
        if self.lifecycle.selected_relayer_id != self.signer_set.selected_relayer.relayer_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidLifecycleState,
                "SigningWorker activation selected worker does not match signer set",
            ));
        }
        let expected_transcript_digest = router_transcript_digest_v1(
            &self.lifecycle,
            &self.signer_set,
            &self.transcript_metadata,
            CandidateId::MpcThresholdPrfV1,
            CorrectnessLevel::MinimumLevelC,
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

/// Inner A/B derivation payload carrying signer proof bundles.
#[derive(Clone, PartialEq, Eq)]
pub struct AbDerivationProofBatchPayloadV1 {
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

impl core::fmt::Debug for AbDerivationProofBatchPayloadV1 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AbDerivationProofBatchPayloadV1")
            .field("from", &self.from)
            .field("to", &self.to)
            .field("transcript_digest", &self.transcript_digest)
            .field("root_share_epoch", &self.root_share_epoch)
            .field("proof_bundle_count", &self.proof_bundles.len())
            .finish()
    }
}

impl AbDerivationProofBatchPayloadV1 {
    /// Creates a validated A/B proof-batch payload.
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
                    "A/B derivation proof batch must cross Signer A and Signer B",
                ));
            }
        }
        if self.proof_bundles.is_empty() {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::MalformedWirePayload,
                "A/B derivation proof batch requires at least one proof bundle",
            ));
        }
        for (index, bundle) in self.proof_bundles.iter().enumerate() {
            let binding = &bundle.signer_partial.binding;
            if binding.signer_role != self.from.role
                || binding.signer_identity != self.from.signer_id
            {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidSignerIdentity,
                    "A/B derivation proof bundle signer does not match sender",
                ));
            }
            if binding.transcript_digest != self.transcript_digest {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::MalformedWirePayload,
                    "A/B derivation proof bundle transcript mismatch",
                ));
            }
            if binding.root_share_epoch != self.root_share_epoch {
                return Err(RouterAbProtocolError::new(
                    RouterAbProtocolErrorCode::InvalidLocalServiceConfig,
                    "A/B derivation proof bundle root-share epoch mismatch",
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
                        "A/B derivation proof batch contains duplicate output binding",
                    ));
                }
            }
        }
        Ok(())
    }

    /// Returns canonical bytes for this proof-batch payload.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        encode_ab_derivation_proof_batch_payload_v1(self)
    }

    /// Returns the SHA-256 digest of canonical bytes.
    pub fn digest(&self) -> PublicDigest32 {
        ab_derivation_proof_batch_payload_digest_v1(self)
    }
}

/// Recipient-scoped proof-bundle payload for final client or relayer delivery.
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
    pub proof_batch: AbDerivationProofBatchPayloadV1,
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
        proof_batch: AbDerivationProofBatchPayloadV1,
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

/// Encodes an A/B derivation proof-batch payload with fixed field order.
pub fn encode_ab_derivation_proof_batch_payload_v1(
    payload: &AbDerivationProofBatchPayloadV1,
) -> Vec<u8> {
    let mut out = Vec::new();
    push_len32(&mut out, AB_DERIVATION_PROOF_BATCH_PAYLOAD_VERSION_V1);
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

/// Decodes A/B derivation proof-batch canonical bytes.
pub fn decode_ab_derivation_proof_batch_payload_v1(
    bytes: &[u8],
) -> RouterAbProtocolResult<AbDerivationProofBatchPayloadV1> {
    let mut decoder = PayloadDecoder::new(bytes);
    decoder.expect_bytes(
        AB_DERIVATION_PROOF_BATCH_PAYLOAD_VERSION_V1,
        "A/B derivation proof-batch payload version",
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
    AbDerivationProofBatchPayloadV1::new(
        from,
        to,
        transcript_digest,
        root_share_epoch,
        proof_bundles,
    )
}

/// Decodes and validates a proof batch inside an authenticated A/B peer payload.
pub fn decode_and_validate_ab_derivation_proof_batch_peer_payload_v1(
    peer_payload: &AbPeerMessagePayloadV1,
) -> RouterAbProtocolResult<AbDerivationProofBatchPayloadV1> {
    peer_payload.validate()?;
    let proof_batch = decode_ab_derivation_proof_batch_payload_v1(peer_payload.payload.as_bytes())?;
    if proof_batch.from != peer_payload.from
        || proof_batch.to != peer_payload.to
        || proof_batch.transcript_digest != peer_payload.transcript_digest
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "A/B derivation proof batch does not match authenticated peer envelope",
        ));
    }
    Ok(proof_batch)
}

/// Builds and signs an A/B derivation proof batch for peer delivery.
pub fn sign_ab_derivation_proof_batch_peer_payload_v1(
    signing_key_bytes: &[u8; 32],
    from: SignerIdentityV1,
    to: SignerIdentityV1,
    batch_output: MpcPrfThresholdSignerBatchOutputV1,
) -> RouterAbProtocolResult<AbPeerMessagePayloadV1> {
    if batch_output.signer_role != from.role || batch_output.signer_identity != from.signer_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "A/B derivation proof batch output does not match sender identity",
        ));
    }
    let proof_batch = AbDerivationProofBatchPayloadV1::new(
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

/// Computes the public digest of A/B derivation proof-batch canonical bytes.
pub fn ab_derivation_proof_batch_payload_digest_v1(
    payload: &AbDerivationProofBatchPayloadV1,
) -> PublicDigest32 {
    digest_bytes(&encode_ab_derivation_proof_batch_payload_v1(payload))
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
        decode_ab_derivation_proof_batch_payload_v1(decoder.read_bytes("proof_batch")?)?;
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
    if plaintext.selected_relayer_id != signer_set.selected_relayer.relayer_id
        || plaintext.selected_relayer_key_epoch != signer_set.selected_relayer.key_epoch
    {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidSignerIdentity,
            "signer input plaintext relayer identity does not match signer set",
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

/// Builds public Candidate A signer input after signer plaintext binding validation.
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
        plaintext.candidate_id,
        CorrectnessLevel::MinimumLevelC,
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
        plaintext.candidate_id,
        CorrectnessLevel::MinimumLevelC,
        plaintext.root_share_epoch.clone(),
    )?;
    MpcPrfSignerPartialInputV1::new(
        transcript.context().clone(),
        transcript,
        plaintext.mpc_prf_suite_id,
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
    if lifecycle.selected_relayer_id != signer_set.selected_relayer.relayer_id {
        return Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidLifecycleState,
            "router-to-signer lifecycle selected relayer does not match signer set",
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
        | (OpenedShareKind::XRelayerBase, Role::Relayer) => Ok(()),
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
    push_string(out, &scope.selected_relayer_id);
}

fn push_signer_set(out: &mut Vec<u8>, signer_set: &SignerSetV1) {
    push_string(out, &signer_set.signer_set_id);
    push_signer_set_policy(out, signer_set.policy);
    push_signer_identity(out, &signer_set.signer_a);
    push_signer_identity(out, &signer_set.signer_b);
    push_relayer_identity(out, &signer_set.selected_relayer);
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

fn push_relayer_identity(out: &mut Vec<u8>, identity: &RelayerIdentityV1) {
    push_string(out, &identity.relayer_id);
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
    push_len32(out, binding.suite_id.as_str().as_bytes());
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
        let selected_relayer_id = self.read_string("selected_relayer_id")?;
        let lifecycle = LifecycleScopeV1::new(
            lifecycle_id,
            work_kind,
            root_share_epoch,
            account_id,
            session_id,
            signer_set_id,
            selected_relayer_id,
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
        let selected_relayer = self.read_relayer_identity()?;
        let signer_set = SignerSetV1::v1_all2(signer_set_id, signer_a, signer_b, selected_relayer)?;
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

    fn read_relayer_identity(&mut self) -> RouterAbProtocolResult<RelayerIdentityV1> {
        let relayer_id = self.read_string("relayer_id")?;
        let key_epoch = self.read_string("relayer_key_epoch")?;
        let recipient_encryption_key = self.read_string("relayer_recipient_encryption_key")?;
        RelayerIdentityV1::new(relayer_id, key_epoch, recipient_encryption_key)
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

    fn read_mpc_prf_partial_proof_bundle(
        &mut self,
    ) -> RouterAbProtocolResult<MpcPrfPartialProofBundleV1> {
        let suite_id = parse_mpc_prf_suite_id(&self.read_string("mpc_prf_suite_id")?)?;
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
            suite_id,
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
        "relayer_share_refresh" => Ok(ExpensiveWorkKindV1::RelayerShareRefresh),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown lifecycle work kind",
        )),
    }
}

fn parse_request_kind(value: &str) -> RouterAbProtocolResult<RequestKind> {
    match value {
        "registration" => Ok(RequestKind::Registration),
        "export" => Ok(RequestKind::Export),
        "refresh" => Ok(RequestKind::Refresh),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown lifecycle primitive request kind",
        )),
    }
}

fn parse_mpc_prf_suite_id(value: &str) -> RouterAbProtocolResult<MpcPrfSuiteId> {
    match value {
        "threshold_prf_ristretto255_sha512" => Ok(MpcPrfSuiteId::ThresholdPrfRistretto255Sha512),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown MPC PRF suite id",
        )),
    }
}

fn parse_opened_share_kind(value: &str) -> RouterAbProtocolResult<OpenedShareKind> {
    match value {
        "x_client_base" => Ok(OpenedShareKind::XClientBase),
        "x_relayer_base" => Ok(OpenedShareKind::XRelayerBase),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::MalformedWirePayload,
            "unknown opened share kind",
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
        "relayer" => Ok(Role::Relayer),
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
