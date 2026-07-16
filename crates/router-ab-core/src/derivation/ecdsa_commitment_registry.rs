use router_ab_ecdsa_client_protocol::{
    EcdsaAuthenticatedCommitmentRegistryV1, EcdsaCommitmentRegistryBindingV1, EcdsaDeriverRoleV1,
    EcdsaSignedCommitmentRecordV1,
};

use crate::derivation::ecdsa_threshold_prf::MpcPrfShareCommitmentWireV1;
use crate::derivation::error::{
    RouterAbDerivationError, RouterAbDerivationErrorCode, RouterAbDerivationResult,
};
use crate::derivation::material::{PublicDigest32, Role};

/// One authority-authenticated commitment record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedRootShareCommitmentV1 {
    role: Role,
    operator_identity: String,
    root_id: String,
    root_version: u64,
    root_share_epoch: String,
    commitment_wire: MpcPrfShareCommitmentWireV1,
    record_digest: PublicDigest32,
}

impl AuthenticatedRootShareCommitmentV1 {
    /// Signer role bound by the record.
    pub fn role(&self) -> Role {
        self.role
    }

    /// Canonical signer/operator identity bound by the record.
    pub fn operator_identity(&self) -> &str {
        &self.operator_identity
    }

    /// Root-share epoch bound by the record.
    pub fn root_share_epoch(&self) -> &str {
        &self.root_share_epoch
    }

    /// Authenticated commitment used for DLEQ verification.
    pub fn commitment_wire(&self) -> &MpcPrfShareCommitmentWireV1 {
        &self.commitment_wire
    }

    /// Authenticated record digest.
    pub fn record_digest(&self) -> PublicDigest32 {
        self.record_digest
    }
}

/// Exact authenticated A/B commitment registry for one root version and epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootShareCommitmentRegistryV1 {
    signer_a: AuthenticatedRootShareCommitmentV1,
    signer_b: AuthenticatedRootShareCommitmentV1,
}

impl RootShareCommitmentRegistryV1 {
    /// Adapts the opaque client-authenticated registry into the core execution shape.
    ///
    /// Runtime policy data cannot construct `EcdsaAuthenticatedCommitmentRegistryV1`;
    /// only the client-safe release/record verifier can produce that capability.
    pub fn from_client_authenticated(
        authenticated: &EcdsaAuthenticatedCommitmentRegistryV1,
        binding: &EcdsaCommitmentRegistryBindingV1,
        signer_a_record: &EcdsaSignedCommitmentRecordV1,
        signer_b_record: &EcdsaSignedCommitmentRecordV1,
    ) -> RouterAbDerivationResult<Self> {
        let signer_a = adapt_client_authenticated_record(
            authenticated,
            binding,
            signer_a_record,
            EcdsaDeriverRoleV1::A,
        )?;
        let signer_b = adapt_client_authenticated_record(
            authenticated,
            binding,
            signer_b_record,
            EcdsaDeriverRoleV1::B,
        )?;
        let a = &signer_a;
        let b = &signer_b;
        if a.root_id != b.root_id
            || a.root_version != b.root_version
            || a.root_share_epoch != b.root_share_epoch
        {
            return Err(registry_rejected(
                "client-authenticated records do not identify the same root version",
            ));
        }
        Ok(Self { signer_a, signer_b })
    }

    /// Returns the authenticated commitment for one Deriver role.
    pub fn commitment_for(
        &self,
        role: Role,
    ) -> RouterAbDerivationResult<&AuthenticatedRootShareCommitmentV1> {
        match role {
            Role::SignerA => Ok(&self.signer_a),
            Role::SignerB => Ok(&self.signer_b),
            _ => Err(registry_rejected(
                "commitment registry lookup requires a Deriver role",
            )),
        }
    }
}

fn adapt_client_authenticated_record(
    authenticated: &EcdsaAuthenticatedCommitmentRegistryV1,
    binding: &EcdsaCommitmentRegistryBindingV1,
    record: &EcdsaSignedCommitmentRecordV1,
    expected_role: EcdsaDeriverRoleV1,
) -> RouterAbDerivationResult<AuthenticatedRootShareCommitmentV1> {
    let (role, expected_identity) = match expected_role {
        EcdsaDeriverRoleV1::A => (Role::SignerA, binding.signer_a_identity.as_str()),
        EcdsaDeriverRoleV1::B => (Role::SignerB, binding.signer_b_identity.as_str()),
    };
    if !authenticated.authenticates_exact_record(binding, expected_role, record)
        || record.statement.role != expected_role
        || record.statement.operator_identity != expected_identity
        || record.statement.root_share_epoch != binding.root_share_epoch
        || record.statement.commitment_wire != *authenticated.commitment_for(expected_role)
    {
        return Err(registry_rejected(
            "client-authenticated commitment adapter detected record drift",
        ));
    }
    if record.statement.share_id != expected_share_id(role)? {
        return Err(registry_rejected(
            "client-authenticated commitment share id does not match Deriver role",
        ));
    }
    let commitment_wire =
        MpcPrfShareCommitmentWireV1::new(record.statement.commitment_wire.to_vec())?;
    if commitment_share_id(&commitment_wire) != record.statement.share_id {
        return Err(registry_rejected(
            "client-authenticated commitment wire share id does not match record",
        ));
    }
    Ok(AuthenticatedRootShareCommitmentV1 {
        role,
        operator_identity: record.statement.operator_identity.clone(),
        root_id: record.statement.root_id.clone(),
        root_version: record.statement.root_version,
        root_share_epoch: record.statement.root_share_epoch.clone(),
        commitment_wire,
        record_digest: PublicDigest32::new(record.signed_digest),
    })
}

fn expected_share_id(role: Role) -> RouterAbDerivationResult<u16> {
    match role {
        Role::SignerA => Ok(1),
        Role::SignerB => Ok(2),
        _ => Err(registry_rejected(
            "commitment record requires a Deriver role",
        )),
    }
}

fn commitment_share_id(commitment: &MpcPrfShareCommitmentWireV1) -> u16 {
    u16::from_be_bytes([commitment.as_bytes()[0], commitment.as_bytes()[1]])
}

fn registry_rejected(message: impl Into<String>) -> RouterAbDerivationError {
    RouterAbDerivationError::new(
        RouterAbDerivationErrorCode::CommitmentRegistryRejected,
        message,
    )
}

#[cfg(test)]
mod client_authenticated_adapter_tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use router_ab_ecdsa_client_protocol::{
        authenticate_ecdsa_commitment_registry_v1, EcdsaCommitmentAuthorityV1,
        EcdsaCommitmentPolicyManifestV1, EcdsaCommitmentPolicyPinsV1, EcdsaCommitmentStatementV1,
        EcdsaSignedCommitmentPolicyV1,
    };

    #[test]
    fn adapter_rejects_every_record_field_drift_after_shared_authentication() {
        let release_key = SigningKey::from_bytes(&[1; 32]);
        let authority_a_key = SigningKey::from_bytes(&[2; 32]);
        let authority_b_key = SigningKey::from_bytes(&[3; 32]);
        let manifest = EcdsaCommitmentPolicyManifestV1 {
            release_epoch: 1,
            minimum_root_version: 1,
            minimum_authority_key_epoch: 1,
            revoked_authority_key_epochs: Vec::new(),
            revoked_record_digests: Vec::new(),
            signer_a_authority: authority(EcdsaDeriverRoleV1::A, "signer-a", &authority_a_key),
            signer_b_authority: authority(EcdsaDeriverRoleV1::B, "signer-b", &authority_b_key),
        };
        let manifest_digest = manifest.digest().expect("manifest digest");
        let policy = EcdsaSignedCommitmentPolicyV1 {
            release_authority_signature: release_key
                .sign(&manifest.signing_bytes().expect("manifest bytes"))
                .to_bytes(),
            manifest,
            manifest_digest,
        };
        let record_a = record(EcdsaDeriverRoleV1::A, "signer-a", 0x11, &authority_a_key);
        let record_b = record(EcdsaDeriverRoleV1::B, "signer-b", 0x22, &authority_b_key);
        let binding = EcdsaCommitmentRegistryBindingV1 {
            now_ms: 1,
            root_share_epoch: "epoch-1".to_owned(),
            signer_a_identity: "signer-a".to_owned(),
            signer_b_identity: "signer-b".to_owned(),
        };
        let authenticated = authenticate_ecdsa_commitment_registry_v1(
            &EcdsaCommitmentPolicyPinsV1 {
                release_authority_public_key: release_key.verifying_key().to_bytes(),
                exact_policy_digest: manifest_digest,
                minimum_release_epoch: 1,
            },
            &policy,
            &binding,
            &record_a,
            &record_b,
        )
        .expect("shared verifier authenticates");
        RootShareCommitmentRegistryV1::from_client_authenticated(
            &authenticated,
            &binding,
            &record_a,
            &record_b,
        )
        .expect("exact adapter succeeds");

        let mut drifted = record_a.clone();
        drifted.statement.role = EcdsaDeriverRoleV1::B;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.share_id = 2;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.root_id.push_str("-drift");
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.root_version += 1;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.root_share_epoch.push_str("-drift");
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.commitment_wire[2] ^= 1;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.operator_identity.push_str("-drift");
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.authority_key_epoch += 1;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.valid_from_ms += 1;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.statement.valid_until_ms -= 1;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.signed_digest[0] ^= 1;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted = record_a.clone();
        drifted.signature[0] ^= 1;
        assert_record_drift_rejected(&authenticated, &binding, &drifted, &record_b);

        let mut drifted_binding = binding.clone();
        drifted_binding.now_ms += 1;
        assert_record_drift_rejected(&authenticated, &drifted_binding, &record_a, &record_b);

        let mut drifted_binding = binding.clone();
        drifted_binding.root_share_epoch.push_str("-drift");
        assert_record_drift_rejected(&authenticated, &drifted_binding, &record_a, &record_b);

        let mut drifted_binding = binding.clone();
        drifted_binding.signer_a_identity.push_str("-drift");
        assert_record_drift_rejected(&authenticated, &drifted_binding, &record_a, &record_b);

        let mut drifted_binding = binding;
        drifted_binding.signer_b_identity.push_str("-drift");
        assert_record_drift_rejected(&authenticated, &drifted_binding, &record_a, &record_b);
    }

    fn assert_record_drift_rejected(
        authenticated: &EcdsaAuthenticatedCommitmentRegistryV1,
        binding: &EcdsaCommitmentRegistryBindingV1,
        signer_a_record: &EcdsaSignedCommitmentRecordV1,
        signer_b_record: &EcdsaSignedCommitmentRecordV1,
    ) {
        assert!(RootShareCommitmentRegistryV1::from_client_authenticated(
            authenticated,
            binding,
            signer_a_record,
            signer_b_record,
        )
        .is_err());
    }

    fn authority(
        role: EcdsaDeriverRoleV1,
        identity: &str,
        key: &SigningKey,
    ) -> EcdsaCommitmentAuthorityV1 {
        EcdsaCommitmentAuthorityV1 {
            role,
            operator_identity: identity.to_owned(),
            authority_key_epoch: 1,
            valid_from_ms: 1,
            valid_until_ms: u64::MAX,
            verifying_key: key.verifying_key().to_bytes(),
        }
    }

    fn record(
        role: EcdsaDeriverRoleV1,
        identity: &str,
        fill: u8,
        key: &SigningKey,
    ) -> EcdsaSignedCommitmentRecordV1 {
        let share_id: u16 = match role {
            EcdsaDeriverRoleV1::A => 1,
            EcdsaDeriverRoleV1::B => 2,
        };
        let mut commitment_wire = [fill; 34];
        commitment_wire[..2].copy_from_slice(&share_id.to_be_bytes());
        let statement = EcdsaCommitmentStatementV1 {
            role,
            share_id,
            root_id: "root-1".to_owned(),
            root_version: 1,
            root_share_epoch: "epoch-1".to_owned(),
            commitment_wire,
            operator_identity: identity.to_owned(),
            authority_key_epoch: 1,
            valid_from_ms: 1,
            valid_until_ms: u64::MAX,
        };
        EcdsaSignedCommitmentRecordV1 {
            signed_digest: statement.digest().expect("record digest"),
            signature: key
                .sign(&statement.signing_bytes().expect("record bytes"))
                .to_bytes(),
            statement,
        }
    }
}
