use crate::derivation::Role;
use serde::{Deserialize, Serialize};

use crate::protocol::envelope::RoleEncryptedEnvelopeV1;
use crate::protocol::error::{
    RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult,
};

/// Signer identity and rotation epoch bound into service messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerIdentityV1 {
    /// Signer role.
    pub role: Role,
    /// Canonical signer id.
    pub signer_id: String,
    /// Signer key epoch.
    pub key_epoch: String,
}

impl SignerIdentityV1 {
    /// Creates a validated signer identity.
    pub fn new(
        role: Role,
        signer_id: impl Into<String>,
        key_epoch: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let identity = Self {
            role,
            signer_id: signer_id.into(),
            key_epoch: key_epoch.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Validates signer role and required identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_signer_role(self.role)?;
        require_non_empty("signer_id", &self.signer_id)?;
        require_non_empty("key_epoch", &self.key_epoch)
    }
}

/// Selected server identity and rotation epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerIdentityV1 {
    /// Canonical server id.
    pub server_id: String,
    /// Server key epoch.
    pub key_epoch: String,
    /// Recipient encryption public key used for server-output delivery.
    pub recipient_encryption_key: String,
}

impl ServerIdentityV1 {
    /// Creates a validated server identity.
    pub fn new(
        server_id: impl Into<String>,
        key_epoch: impl Into<String>,
        recipient_encryption_key: impl Into<String>,
    ) -> RouterAbProtocolResult<Self> {
        let identity = Self {
            server_id: server_id.into(),
            key_epoch: key_epoch.into(),
            recipient_encryption_key: recipient_encryption_key.into(),
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Validates required server identity fields.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("server_id", &self.server_id)?;
        require_non_empty("server_key_epoch", &self.key_epoch)?;
        require_non_empty(
            "server_recipient_encryption_key",
            &self.recipient_encryption_key,
        )
    }
}

/// Signer-set quorum policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignerSetPolicyV1 {
    /// Router A/B v1 requires Signer A and Signer B.
    All2,
}

impl SignerSetPolicyV1 {
    /// Returns the canonical signer-set policy label.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::All2 => "all_2",
        }
    }
}

/// Router A/B v1 signer set with selected server identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSetV1 {
    /// Canonical signer-set id.
    pub signer_set_id: String,
    /// Quorum policy.
    pub policy: SignerSetPolicyV1,
    /// Signer A identity.
    pub signer_a: SignerIdentityV1,
    /// Signer B identity.
    pub signer_b: SignerIdentityV1,
    /// Selected server identity.
    pub selected_server: ServerIdentityV1,
}

impl SignerSetV1 {
    /// Creates a v1 all(2) signer set.
    pub fn v1_all2(
        signer_set_id: impl Into<String>,
        signer_a: SignerIdentityV1,
        signer_b: SignerIdentityV1,
        selected_server: ServerIdentityV1,
    ) -> RouterAbProtocolResult<Self> {
        let signer_set = Self {
            signer_set_id: signer_set_id.into(),
            policy: SignerSetPolicyV1::All2,
            signer_a,
            signer_b,
            selected_server,
        };
        signer_set.validate()?;
        Ok(signer_set)
    }

    /// Validates signer roles, ids, epochs, and server identity.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        self.signer_a.validate()?;
        self.signer_b.validate()?;
        self.selected_server.validate()?;
        if self.signer_a.role != Role::SignerA || self.signer_b.role != Role::SignerB {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer set requires Signer A followed by Signer B",
            ));
        }
        if self.signer_a.signer_id == self.signer_b.signer_id {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer set requires distinct signer ids",
            ));
        }
        Ok(())
    }
}

/// Signer identity paired with the role-specific encrypted envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleEnvelopeAssignmentV1 {
    /// Signer identity.
    pub signer: SignerIdentityV1,
    /// Encrypted envelope for the signer.
    pub envelope: RoleEncryptedEnvelopeV1,
}

impl RoleEnvelopeAssignmentV1 {
    /// Creates a validated signer-envelope assignment.
    pub fn new(
        signer: SignerIdentityV1,
        envelope: RoleEncryptedEnvelopeV1,
    ) -> RouterAbProtocolResult<Self> {
        let assignment = Self { signer, envelope };
        assignment.validate()?;
        Ok(assignment)
    }

    /// Validates signer identity and envelope role agreement.
    pub fn validate(&self) -> RouterAbProtocolResult<()> {
        self.signer.validate()?;
        self.envelope.validate()?;
        if self.signer.role != self.envelope.recipient_role {
            return Err(RouterAbProtocolError::new(
                RouterAbProtocolErrorCode::InvalidSignerIdentity,
                "signer role must match encrypted envelope recipient",
            ));
        }
        Ok(())
    }
}

fn require_signer_role(role: Role) -> RouterAbProtocolResult<()> {
    match role {
        Role::SignerA | Role::SignerB => Ok(()),
        _ => Err(RouterAbProtocolError::new(
            RouterAbProtocolErrorCode::InvalidRole,
            "signer identity role must be Signer A or Signer B",
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
