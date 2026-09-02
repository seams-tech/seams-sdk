use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use router_ab_core::{RouterAbProtocolError, RouterAbProtocolErrorCode, RouterAbProtocolResult};

const REVISION_MANIFEST_DOMAIN_V1: &[u8] = b"seams/r120/revision-manifest/v1";
const ROLE_PRIVATE_MIGRATION_HEAD_V1: &str = "0004_tenant_root_creation_admission";
const MAX_TEXT_BYTES: usize = 256;

/// Public digest of one canonical R120 revision manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct TenantRootRevisionManifestDigestV1([u8; 32]);

impl TenantRootRevisionManifestDigestV1 {
    /// Parses a non-zero canonical manifest digest.
    pub fn from_bytes(bytes: [u8; 32]) -> RouterAbProtocolResult<Self> {
        if bytes.iter().all(|byte| *byte == 0) {
            return Err(invalid("R120 revision manifest digest must be non-zero"));
        }
        Ok(Self(bytes))
    }

    /// Returns the exact digest bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for TenantRootRevisionManifestDigestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = <[u8; 32]>::deserialize(deserializer)?;
        Self::from_bytes(bytes).map_err(D::Error::custom)
    }
}

/// The one R120 derivation profile admitted by the first production cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootDerivationProfileV1 {
    /// Separate A-target and B-target threshold-PRF outputs outside Yao.
    RoleTargetedThresholdPrfV1,
}

impl TenantRootDerivationProfileV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::RoleTargetedThresholdPrfV1 => "role_targeted_threshold_prf_v1",
        }
    }
}

/// Version of the production tenant-root transport and lifecycle contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootProtocolVersionV1 {
    R120V1,
}

impl TenantRootProtocolVersionV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::R120V1 => "r120_v1",
        }
    }
}

/// Fixed participant roles required for one R120 cutover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantRootRevisionParticipantRoleV1 {
    WalletServer,
    Router,
    DeriverA,
    DeriverB,
    SigningWorker,
}

impl TenantRootRevisionParticipantRoleV1 {
    fn as_str(self) -> &'static str {
        match self {
            Self::WalletServer => "wallet_server",
            Self::Router => "router",
            Self::DeriverA => "deriver_a",
            Self::DeriverB => "deriver_b",
            Self::SigningWorker => "signing_worker",
        }
    }

    fn is_deriver(self) -> bool {
        matches!(self, Self::DeriverA | Self::DeriverB)
    }
}

/// Byte-exact Yao artifacts that every derivation participant must report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TenantRootYaoArtifactDigestSetV1 {
    circuit_manifest_digest: [u8; 32],
    circuit_digest: [u8; 32],
    schedule_digest: [u8; 32],
    schema_digest: [u8; 32],
    table_digest: [u8; 32],
    circuit_cache_identity_digest: [u8; 32],
}

impl TenantRootYaoArtifactDigestSetV1 {
    /// Creates one complete artifact digest set.
    pub fn new(
        circuit_manifest_digest: [u8; 32],
        circuit_digest: [u8; 32],
        schedule_digest: [u8; 32],
        schema_digest: [u8; 32],
        table_digest: [u8; 32],
        circuit_cache_identity_digest: [u8; 32],
    ) -> RouterAbProtocolResult<Self> {
        let artifact_set = Self {
            circuit_manifest_digest,
            circuit_digest,
            schedule_digest,
            schema_digest,
            table_digest,
            circuit_cache_identity_digest,
        };
        artifact_set.validate()?;
        Ok(artifact_set)
    }

    fn validate(&self) -> RouterAbProtocolResult<()> {
        require_non_zero_digest(
            "R120 Yao circuit-manifest digest",
            &self.circuit_manifest_digest,
        )?;
        require_non_zero_digest("R120 Yao circuit digest", &self.circuit_digest)?;
        require_non_zero_digest("R120 Yao schedule digest", &self.schedule_digest)?;
        require_non_zero_digest("R120 Yao schema digest", &self.schema_digest)?;
        require_non_zero_digest("R120 Yao table digest", &self.table_digest)?;
        require_non_zero_digest(
            "R120 Yao circuit-cache identity digest",
            &self.circuit_cache_identity_digest,
        )
    }

    fn append_canonical_bytes(self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.circuit_manifest_digest);
        bytes.extend_from_slice(&self.circuit_digest);
        bytes.extend_from_slice(&self.schedule_digest);
        bytes.extend_from_slice(&self.schema_digest);
        bytes.extend_from_slice(&self.table_digest);
        bytes.extend_from_slice(&self.circuit_cache_identity_digest);
    }
}

impl<'de> Deserialize<'de> for TenantRootYaoArtifactDigestSetV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            circuit_manifest_digest: [u8; 32],
            circuit_digest: [u8; 32],
            schedule_digest: [u8; 32],
            schema_digest: [u8; 32],
            table_digest: [u8; 32],
            circuit_cache_identity_digest: [u8; 32],
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.circuit_manifest_digest,
            wire.circuit_digest,
            wire.schedule_digest,
            wire.schema_digest,
            wire.table_digest,
            wire.circuit_cache_identity_digest,
        )
        .map_err(D::Error::custom)
    }
}

/// Persistence state reported by one participant revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TenantRootParticipantStorageRevisionV1 {
    Stateless,
    RolePrivateD1 { migration_head: String },
}

/// Raw values required to build one checked participant report.
pub struct TenantRootRevisionParticipantInputV1 {
    pub role: TenantRootRevisionParticipantRoleV1,
    pub release_id: String,
    pub git_commit: String,
    pub deployed_script_identity: String,
    pub deployment_id: String,
    pub source_build_digest: [u8; 32],
    pub configuration_digest: [u8; 32],
    pub protocol_version: TenantRootProtocolVersionV1,
    pub profile: TenantRootDerivationProfileV1,
    pub yao_artifacts: TenantRootYaoArtifactDigestSetV1,
    pub storage: TenantRootParticipantStorageRevisionV1,
}

/// One exact deployed participant admitted into an R120 revision set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRevisionParticipantV1 {
    role: TenantRootRevisionParticipantRoleV1,
    release_id: String,
    git_commit: String,
    deployed_script_identity: String,
    deployment_id: String,
    source_build_digest: [u8; 32],
    configuration_digest: [u8; 32],
    protocol_version: TenantRootProtocolVersionV1,
    profile: TenantRootDerivationProfileV1,
    yao_artifacts: TenantRootYaoArtifactDigestSetV1,
    storage: TenantRootParticipantStorageRevisionV1,
}

impl TenantRootRevisionParticipantV1 {
    /// Validates one participant report at the deployment boundary.
    pub fn new(input: TenantRootRevisionParticipantInputV1) -> RouterAbProtocolResult<Self> {
        require_text("R120 release id", &input.release_id)?;
        require_lower_hex("R120 git commit", &input.git_commit, 40)?;
        require_text(
            "R120 deployed script identity",
            &input.deployed_script_identity,
        )?;
        require_text("R120 deployment id", &input.deployment_id)?;
        require_non_zero_digest("R120 source-build digest", &input.source_build_digest)?;
        require_non_zero_digest("R120 configuration digest", &input.configuration_digest)?;
        input.yao_artifacts.validate()?;
        validate_storage(input.role, &input.storage)?;
        Ok(Self {
            role: input.role,
            release_id: input.release_id,
            git_commit: input.git_commit,
            deployed_script_identity: input.deployed_script_identity,
            deployment_id: input.deployment_id,
            source_build_digest: input.source_build_digest,
            configuration_digest: input.configuration_digest,
            protocol_version: input.protocol_version,
            profile: input.profile,
            yao_artifacts: input.yao_artifacts,
            storage: input.storage,
        })
    }

    /// Returns the participant's fixed role.
    pub const fn role(&self) -> TenantRootRevisionParticipantRoleV1 {
        self.role
    }

    fn append_canonical_bytes(&self, bytes: &mut Vec<u8>) -> RouterAbProtocolResult<()> {
        push_text(bytes, self.role.as_str())?;
        push_text(bytes, &self.release_id)?;
        push_text(bytes, &self.git_commit)?;
        push_text(bytes, &self.deployed_script_identity)?;
        push_text(bytes, &self.deployment_id)?;
        bytes.extend_from_slice(&self.source_build_digest);
        bytes.extend_from_slice(&self.configuration_digest);
        push_text(bytes, self.protocol_version.as_str())?;
        push_text(bytes, self.profile.as_str())?;
        self.yao_artifacts.append_canonical_bytes(bytes);
        match &self.storage {
            TenantRootParticipantStorageRevisionV1::Stateless => {
                push_text(bytes, "stateless")?;
            }
            TenantRootParticipantStorageRevisionV1::RolePrivateD1 { migration_head } => {
                push_text(bytes, "role_private_d1")?;
                push_text(bytes, migration_head)?;
            }
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for TenantRootRevisionParticipantV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            role: TenantRootRevisionParticipantRoleV1,
            release_id: String,
            git_commit: String,
            deployed_script_identity: String,
            deployment_id: String,
            source_build_digest: [u8; 32],
            configuration_digest: [u8; 32],
            protocol_version: TenantRootProtocolVersionV1,
            profile: TenantRootDerivationProfileV1,
            yao_artifacts: TenantRootYaoArtifactDigestSetV1,
            storage: TenantRootParticipantStorageRevisionV1,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(TenantRootRevisionParticipantInputV1 {
            role: wire.role,
            release_id: wire.release_id,
            git_commit: wire.git_commit,
            deployed_script_identity: wire.deployed_script_identity,
            deployment_id: wire.deployment_id,
            source_build_digest: wire.source_build_digest,
            configuration_digest: wire.configuration_digest,
            protocol_version: wire.protocol_version,
            profile: wire.profile,
            yao_artifacts: wire.yao_artifacts,
            storage: wire.storage,
        })
        .map_err(D::Error::custom)
    }
}

/// Fixed five-participant R120 production revision set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TenantRootRevisionManifestV1 {
    b4_b5_input_commit: String,
    phase0_selection_record_digest: [u8; 32],
    wallet_server: TenantRootRevisionParticipantV1,
    router: TenantRootRevisionParticipantV1,
    deriver_a: TenantRootRevisionParticipantV1,
    deriver_b: TenantRootRevisionParticipantV1,
    signing_worker: TenantRootRevisionParticipantV1,
}

impl TenantRootRevisionManifestV1 {
    /// Creates one complete, internally consistent revision set.
    pub fn new(
        b4_b5_input_commit: impl Into<String>,
        phase0_selection_record_digest: [u8; 32],
        wallet_server: TenantRootRevisionParticipantV1,
        router: TenantRootRevisionParticipantV1,
        deriver_a: TenantRootRevisionParticipantV1,
        deriver_b: TenantRootRevisionParticipantV1,
        signing_worker: TenantRootRevisionParticipantV1,
    ) -> RouterAbProtocolResult<Self> {
        let b4_b5_input_commit = b4_b5_input_commit.into();
        require_lower_hex("R120 B4/B5 input commit", &b4_b5_input_commit, 40)?;
        require_non_zero_digest(
            "R120 Phase 0 selection-record digest",
            &phase0_selection_record_digest,
        )?;
        require_role(
            &wallet_server,
            TenantRootRevisionParticipantRoleV1::WalletServer,
        )?;
        require_role(&router, TenantRootRevisionParticipantRoleV1::Router)?;
        require_role(&deriver_a, TenantRootRevisionParticipantRoleV1::DeriverA)?;
        require_role(&deriver_b, TenantRootRevisionParticipantRoleV1::DeriverB)?;
        require_role(
            &signing_worker,
            TenantRootRevisionParticipantRoleV1::SigningWorker,
        )?;
        let participants = [
            &wallet_server,
            &router,
            &deriver_a,
            &deriver_b,
            &signing_worker,
        ];
        require_common_revision(&participants)?;
        require_unique_deployments(&participants)?;
        require_deriver_role_separation(&deriver_a, &deriver_b)?;
        Ok(Self {
            b4_b5_input_commit,
            phase0_selection_record_digest,
            wallet_server,
            router,
            deriver_a,
            deriver_b,
            signing_worker,
        })
    }

    /// Returns the verifier-committed Phase 0 `approval_payload_sha256`.
    pub const fn phase0_selection_record_digest(&self) -> &[u8; 32] {
        &self.phase0_selection_record_digest
    }

    /// Returns the canonical manifest bytes used for release authorization.
    pub fn canonical_bytes(&self) -> RouterAbProtocolResult<Vec<u8>> {
        let mut bytes = Vec::with_capacity(2048);
        bytes.extend_from_slice(REVISION_MANIFEST_DOMAIN_V1);
        push_text(&mut bytes, &self.b4_b5_input_commit)?;
        bytes.extend_from_slice(&self.phase0_selection_record_digest);
        self.wallet_server.append_canonical_bytes(&mut bytes)?;
        self.router.append_canonical_bytes(&mut bytes)?;
        self.deriver_a.append_canonical_bytes(&mut bytes)?;
        self.deriver_b.append_canonical_bytes(&mut bytes)?;
        self.signing_worker.append_canonical_bytes(&mut bytes)?;
        Ok(bytes)
    }

    /// Returns the SHA-256 digest committed by the cutover activation receipt.
    pub fn digest(&self) -> RouterAbProtocolResult<TenantRootRevisionManifestDigestV1> {
        TenantRootRevisionManifestDigestV1::from_bytes(
            Sha256::digest(self.canonical_bytes()?).into(),
        )
    }
}

impl<'de> Deserialize<'de> for TenantRootRevisionManifestV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            b4_b5_input_commit: String,
            phase0_selection_record_digest: [u8; 32],
            wallet_server: TenantRootRevisionParticipantV1,
            router: TenantRootRevisionParticipantV1,
            deriver_a: TenantRootRevisionParticipantV1,
            deriver_b: TenantRootRevisionParticipantV1,
            signing_worker: TenantRootRevisionParticipantV1,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(
            wire.b4_b5_input_commit,
            wire.phase0_selection_record_digest,
            wire.wallet_server,
            wire.router,
            wire.deriver_a,
            wire.deriver_b,
            wire.signing_worker,
        )
        .map_err(D::Error::custom)
    }
}

fn validate_storage(
    role: TenantRootRevisionParticipantRoleV1,
    storage: &TenantRootParticipantStorageRevisionV1,
) -> RouterAbProtocolResult<()> {
    match (role.is_deriver(), storage) {
        (false, TenantRootParticipantStorageRevisionV1::Stateless) => Ok(()),
        (true, TenantRootParticipantStorageRevisionV1::RolePrivateD1 { migration_head }) => {
            if migration_head != ROLE_PRIVATE_MIGRATION_HEAD_V1 {
                return Err(invalid("R120 Deriver migration head is unsupported"));
            }
            Ok(())
        }
        _ => Err(invalid(
            "R120 participant storage revision does not match its role",
        )),
    }
}

fn require_role(
    participant: &TenantRootRevisionParticipantV1,
    expected: TenantRootRevisionParticipantRoleV1,
) -> RouterAbProtocolResult<()> {
    if participant.role != expected {
        return Err(invalid("R120 revision participant role is out of position"));
    }
    Ok(())
}

fn require_common_revision(
    participants: &[&TenantRootRevisionParticipantV1],
) -> RouterAbProtocolResult<()> {
    let first = participants
        .first()
        .ok_or_else(|| invalid("R120 revision manifest has no participants"))?;
    for participant in &participants[1..] {
        if participant.release_id != first.release_id
            || participant.git_commit != first.git_commit
            || participant.protocol_version != first.protocol_version
            || participant.profile != first.profile
            || participant.yao_artifacts != first.yao_artifacts
        {
            return Err(invalid(
                "R120 revision participants report a mixed release, profile, or artifact set",
            ));
        }
    }
    Ok(())
}

fn require_unique_deployments(
    participants: &[&TenantRootRevisionParticipantV1],
) -> RouterAbProtocolResult<()> {
    for (index, participant) in participants.iter().enumerate() {
        for peer in &participants[index + 1..] {
            if participant.deployed_script_identity == peer.deployed_script_identity
                || participant.deployment_id == peer.deployment_id
            {
                return Err(invalid(
                    "R120 revision participants must use distinct script and deployment identities",
                ));
            }
        }
    }
    Ok(())
}

fn require_deriver_role_separation(
    deriver_a: &TenantRootRevisionParticipantV1,
    deriver_b: &TenantRootRevisionParticipantV1,
) -> RouterAbProtocolResult<()> {
    if deriver_a.storage != deriver_b.storage {
        return Err(invalid(
            "R120 Deriver role-private migration heads do not match",
        ));
    }
    if deriver_a.configuration_digest == deriver_b.configuration_digest {
        return Err(invalid(
            "R120 Deriver roles must use distinct private configuration digests",
        ));
    }
    Ok(())
}

fn require_text(label: &'static str, value: &str) -> RouterAbProtocolResult<()> {
    if value.is_empty()
        || value.len() > MAX_TEXT_BYTES
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "{label} is empty, oversized, padded, or contains controls"
        )));
    }
    Ok(())
}

fn require_lower_hex(
    label: &'static str,
    value: &str,
    exact_len: usize,
) -> RouterAbProtocolResult<()> {
    if value.len() != exact_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid(format!("{label} is not canonical lowercase hex")));
    }
    Ok(())
}

fn require_non_zero_digest(label: &'static str, value: &[u8; 32]) -> RouterAbProtocolResult<()> {
    if value.iter().all(|byte| *byte == 0) {
        return Err(invalid(format!("{label} must be non-zero")));
    }
    Ok(())
}

fn push_text(bytes: &mut Vec<u8>, value: &str) -> RouterAbProtocolResult<()> {
    let len = u32::try_from(value.len()).map_err(|_| invalid("R120 manifest field is too long"))?;
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(value.as_bytes());
    Ok(())
}

fn invalid(message: impl Into<String>) -> RouterAbProtocolError {
    RouterAbProtocolError::new(RouterAbProtocolErrorCode::MalformedWirePayload, message)
}
