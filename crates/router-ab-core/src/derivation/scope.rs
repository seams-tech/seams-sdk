use serde::{Deserialize, Serialize};

use crate::derivation::context::{AccountScope, RootShareEpoch};
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};

/// Request-kind-specific scope for a derivation ceremony.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RequestScope {
    /// Registration creates an account binding for one root-share epoch.
    Registration(RegistrationScope),
    /// Export derives material for a scoped export request.
    Export(ExportScope),
    /// Refresh binds an old epoch to a new epoch before activation.
    Refresh(RefreshScope),
}

impl RequestScope {
    /// Validates the request scope.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        match self {
            Self::Registration(scope) => scope.validate(),
            Self::Export(scope) => scope.validate(),
            Self::Refresh(scope) => scope.validate(),
        }
    }
}

/// Scope for registration ceremonies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrationScope {
    /// Epoch used for the registration output relation.
    pub root_share_epoch: RootShareEpoch,
    /// Router-assigned registration id.
    pub registration_id: String,
    /// Account scope being registered.
    pub account_scope: AccountScope,
    /// Expected signer-set id.
    pub signer_set_id: String,
    /// Expected Router identity.
    pub expected_router_id: String,
    /// Expected client identity.
    pub expected_client_id: String,
    /// Expected selected server identity.
    pub expected_server_id: String,
}

impl RegistrationScope {
    /// Validates required registration scope fields.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("registration_id", &self.registration_id)?;
        self.account_scope.validate()?;
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        require_non_empty("expected_router_id", &self.expected_router_id)?;
        require_non_empty("expected_client_id", &self.expected_client_id)?;
        require_non_empty("expected_server_id", &self.expected_server_id)?;
        Ok(())
    }
}

/// Scope for export ceremonies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportScope {
    /// Epoch used for the export output relation.
    pub root_share_epoch: RootShareEpoch,
    /// Router-assigned export id.
    pub export_id: String,
    /// Account scope being exported.
    pub account_scope: AccountScope,
    /// Export purpose label.
    pub export_purpose: String,
    /// Export recipient identity.
    pub export_recipient_id: String,
    /// Expected signer-set id.
    pub signer_set_id: String,
}

impl ExportScope {
    /// Validates required export scope fields.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("root_share_epoch", self.root_share_epoch.as_str())?;
        require_non_empty("export_id", &self.export_id)?;
        self.account_scope.validate()?;
        require_non_empty("export_purpose", &self.export_purpose)?;
        require_non_empty("export_recipient_id", &self.export_recipient_id)?;
        require_non_empty("signer_set_id", &self.signer_set_id)?;
        Ok(())
    }
}

/// Scope for refresh ceremonies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshScope {
    /// Epoch currently active for the account.
    pub old_root_share_epoch: RootShareEpoch,
    /// Epoch proposed for activation.
    pub new_root_share_epoch: RootShareEpoch,
    /// Router-assigned refresh id.
    pub refresh_id: String,
    /// Account scope being refreshed.
    pub account_scope: AccountScope,
    /// Old signer-set id.
    pub old_signer_set_id: String,
    /// New signer-set id.
    pub new_signer_set_id: String,
    /// Expected Router identity.
    pub expected_router_id: String,
    /// Expected client identity.
    pub expected_client_id: String,
    /// Expected selected server identity.
    pub expected_server_id: String,
    /// Address verification requirement label.
    pub address_verification_requirement: String,
}

impl RefreshScope {
    /// Validates required refresh scope fields.
    pub fn validate(&self) -> RouterAbDerivationResult<()> {
        require_non_empty("old_root_share_epoch", self.old_root_share_epoch.as_str())?;
        require_non_empty("new_root_share_epoch", self.new_root_share_epoch.as_str())?;

        if self.old_root_share_epoch == self.new_root_share_epoch {
            return Err(RouterAbDerivationError::new(
                RouterAbDerivationErrorCode::RootEpochMismatch,
                "refresh requires distinct old and new root-share epochs",
            ));
        }

        require_non_empty("refresh_id", &self.refresh_id)?;
        self.account_scope.validate()?;
        require_non_empty("old_signer_set_id", &self.old_signer_set_id)?;
        require_non_empty("new_signer_set_id", &self.new_signer_set_id)?;
        require_non_empty("expected_router_id", &self.expected_router_id)?;
        require_non_empty("expected_client_id", &self.expected_client_id)?;
        require_non_empty("expected_server_id", &self.expected_server_id)?;
        require_non_empty(
            "address_verification_requirement",
            &self.address_verification_requirement,
        )?;
        Ok(())
    }
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
