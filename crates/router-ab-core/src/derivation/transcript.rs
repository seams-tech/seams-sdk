use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::derivation::context::DerivationContext;
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{PublicDigest32, Role};

const TRANSCRIPT_VERSION: &[u8] = b"router-ab-derivation/transcript/v1";

/// Quorum policy bound into the transcript.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum QuorumPolicy {
    /// Every configured signer must participate.
    All { signer_count: u16 },
}

impl QuorumPolicy {
    /// Creates the v1 strict A/B quorum policy.
    pub fn v1_all2() -> Self {
        Self::All { signer_count: 2 }
    }

    /// Returns the canonical policy string.
    pub fn as_canonical_string(&self) -> String {
        match self {
            Self::All { signer_count } => format!("all({signer_count})"),
        }
    }

    fn validate_v1_all2(&self) -> RouterAbDerivationResult<()> {
        match self {
            Self::All { signer_count: 2 } => Ok(()),
            Self::All { .. } => Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "v1 requires quorum policy all(2)",
            )),
        }
    }
}

/// One signer entry in a transcript-bound signer set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedSignerBinding {
    /// Stable signer index inside the signer set.
    pub signer_index: u16,
    /// Signer role for v1.
    pub role: Role,
    /// Canonical signer identity string.
    pub signer_id: String,
    /// Signer key epoch.
    pub key_epoch: String,
}

impl IndexedSignerBinding {
    /// Creates a transcript-bound signer entry.
    pub fn new(
        signer_index: u16,
        role: Role,
        signer_id: impl Into<String>,
        key_epoch: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let signer = Self {
            signer_index,
            role,
            signer_id: signer_id.into(),
            key_epoch: key_epoch.into(),
        };
        signer.validate()?;
        Ok(signer)
    }

    /// Validates signer entry fields.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("signer_id", &self.signer_id)?;
        require_non_empty("signer_key_epoch", &self.key_epoch)?;
        Ok(())
    }
}

/// Signer-set binding for transcript V1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSetBinding {
    /// Stable signer-set identifier.
    pub signer_set_id: String,
    /// Quorum policy.
    pub quorum_policy: QuorumPolicy,
    /// Indexed signer entries.
    pub signers: Vec<IndexedSignerBinding>,
}

impl SignerSetBinding {
    /// Creates the v1 strict all(2) A/B signer set.
    pub fn v1_all2(
        signer_set_id: impl Into<String>,
        signer_a_id: impl Into<String>,
        signer_a_key_epoch: impl Into<String>,
        signer_b_id: impl Into<String>,
        signer_b_key_epoch: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let signer_set = Self {
            signer_set_id: signer_set_id.into(),
            quorum_policy: QuorumPolicy::v1_all2(),
            signers: vec![
                IndexedSignerBinding::new(0, Role::SignerA, signer_a_id, signer_a_key_epoch)?,
                IndexedSignerBinding::new(1, Role::SignerB, signer_b_id, signer_b_key_epoch)?,
            ],
        };
        signer_set.validate_v1_all2()?;
        Ok(signer_set)
    }

    /// Validates the v1 strict all(2) signer-set shape.
    pub fn validate_v1_all2(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        self.quorum_policy.validate_v1_all2()?;

        if self.signers.len() != 2 {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "v1 requires exactly two signers",
            ));
        }

        let signer_a = &self.signers[0];
        let signer_b = &self.signers[1];
        signer_a.validate()?;
        signer_b.validate()?;

        if signer_a.signer_index != 0 || signer_a.role != Role::SignerA {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "v1 signer index 0 must be Signer A",
            ));
        }

        if signer_b.signer_index != 1 || signer_b.role != Role::SignerB {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::MalformedInput,
                "v1 signer index 1 must be Signer B",
            ));
        }

        if signer_a.signer_id == signer_b.signer_id {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::DuplicateSignerIdentity,
                "signer A and signer B identities must differ",
            ));
        }

        Ok(())
    }

    /// Returns the signer entry for a role.
    pub fn signer_for_role(&self, role: Role) -> Option<&IndexedSignerBinding> {
        self.signers.iter().find(|signer| signer.role == role)
    }
}

/// Transcript data bound into split-derivation outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TranscriptBinding {
    /// Canonical derivation context.
    pub context: DerivationContext,
    /// Router identity string.
    pub router_id: String,
    /// Transcript-bound signer set.
    pub signer_set: SignerSetBinding,
    /// Selected relayer identity string.
    pub selected_relayer_id: String,
    /// Selected relayer recipient encryption public key.
    pub selected_relayer_recipient_encryption_key: String,
    /// Client identity string.
    pub client_id: String,
    /// Client ephemeral public key for client-output encryption.
    pub client_ephemeral_public_key: String,
}

impl TranscriptBinding {
    /// Creates a transcript binding.
    pub fn new(
        context: DerivationContext,
        router_id: impl Into<String>,
        signer_set: SignerSetBinding,
        selected_relayer_id: impl Into<String>,
        selected_relayer_recipient_encryption_key: impl Into<String>,
        client_id: impl Into<String>,
        client_ephemeral_public_key: impl Into<String>,
    ) -> RouterAbDerivationResult<Self> {
        let binding = Self {
            context,
            router_id: router_id.into(),
            signer_set,
            selected_relayer_id: selected_relayer_id.into(),
            selected_relayer_recipient_encryption_key: selected_relayer_recipient_encryption_key
                .into(),
            client_id: client_id.into(),
            client_ephemeral_public_key: client_ephemeral_public_key.into(),
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Validates required transcript identity fields.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        self.context.validate()?;
        require_non_empty("router_id", &self.router_id)?;
        self.signer_set.validate_v1_all2()?;
        require_non_empty("selected_relayer_id", &self.selected_relayer_id)?;
        require_non_empty(
            "selected_relayer_recipient_encryption_key",
            &self.selected_relayer_recipient_encryption_key,
        )?;
        require_non_empty("client_id", &self.client_id)?;
        require_non_empty(
            "client_ephemeral_public_key",
            &self.client_ephemeral_public_key,
        )?;

        Ok(())
    }
}

/// Computes the current transcript binding digest.
pub fn transcript_binding_digest(
    binding: &TranscriptBinding,
) -> RouterAbDerivationResult<[u8; 32]> {
    Ok(transcript_digest_v1(binding)?.bytes)
}

/// Computes the V1 transcript digest.
pub fn transcript_digest_v1(
    binding: &TranscriptBinding,
) -> RouterAbDerivationResult<PublicDigest32> {
    binding.validate()?;

    let mut hasher = Sha256::new();
    push_field(&mut hasher, TRANSCRIPT_VERSION);
    push_field(&mut hasher, &binding.context.encode_context_v1()?);
    push_field(&mut hasher, binding.router_id.as_bytes());
    push_field(&mut hasher, binding.signer_set.signer_set_id.as_bytes());
    push_field(
        &mut hasher,
        binding
            .signer_set
            .quorum_policy
            .as_canonical_string()
            .as_bytes(),
    );
    push_field(
        &mut hasher,
        binding.signer_set.signers.len().to_string().as_bytes(),
    );
    for signer in &binding.signer_set.signers {
        push_field(&mut hasher, signer.signer_index.to_string().as_bytes());
        push_field(&mut hasher, signer.role.as_str().as_bytes());
        push_field(&mut hasher, signer.signer_id.as_bytes());
        push_field(&mut hasher, signer.key_epoch.as_bytes());
    }
    push_field(&mut hasher, binding.selected_relayer_id.as_bytes());
    push_field(
        &mut hasher,
        binding.selected_relayer_recipient_encryption_key.as_bytes(),
    );
    push_field(&mut hasher, binding.client_id.as_bytes());
    push_field(&mut hasher, binding.client_ephemeral_public_key.as_bytes());
    Ok(PublicDigest32::new(hasher.finalize().into()))
}

fn push_field(hasher: &mut Sha256, value: &[u8]) {
    let len = value.len() as u32;
    hasher.update(len.to_be_bytes());
    hasher.update(value);
}

fn require_non_empty(field: &'static str, value: &str) -> RouterAbDerivationResult<()> {
    if value.is_empty() {
        return Err(RouterAbDerivationError::new(
            RouterAbDerivationErrorCode::EmptyField,
            format!("{field} is required"),
        ));
    }
    Ok(())
}
