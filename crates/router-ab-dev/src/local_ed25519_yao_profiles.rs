use router_ab_core::LocalServiceRoleV1;
use sha2::{Digest, Sha256};

pub const LOCAL_ED25519_YAO_PROTOCOL_ID_V1: &str = "router_ab_ed25519_yao_v1";
pub const LOCAL_ED25519_YAO_ACTIVATION_CIRCUIT_ID_V1: &str = "ed25519_yao_activation_v1";
pub const LOCAL_ED25519_YAO_EXPORT_CIRCUIT_ID_V1: &str = "ed25519_yao_export_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalEd25519YaoOneAccountDevV1(());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalEd25519YaoTwoAdministratorDevV1(());

mod sealed {
    pub trait Sealed {}
}

trait LocalEd25519YaoFixedProfileV1: sealed::Sealed {
    fn role_roots() -> [LocalEd25519YaoRoleRootV1; 3];
}

impl sealed::Sealed for LocalEd25519YaoOneAccountDevV1 {}
impl sealed::Sealed for LocalEd25519YaoTwoAdministratorDevV1 {}

impl LocalEd25519YaoFixedProfileV1 for LocalEd25519YaoOneAccountDevV1 {
    fn role_roots() -> [LocalEd25519YaoRoleRootV1; 3] {
        role_roots(".", ".", ".")
    }
}

impl LocalEd25519YaoFixedProfileV1 for LocalEd25519YaoTwoAdministratorDevV1 {
    fn role_roots() -> [LocalEd25519YaoRoleRootV1; 3] {
        role_roots("administrator-a", "administrator-b", "signing-worker")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalEd25519YaoRoleRootV1 {
    role: LocalServiceRoleV1,
    relative_root: &'static str,
    env_file: &'static str,
}

impl LocalEd25519YaoRoleRootV1 {
    pub const fn role(self) -> LocalServiceRoleV1 {
        self.role
    }

    pub const fn relative_root(self) -> &'static str {
        self.relative_root
    }

    pub const fn env_file(self) -> &'static str {
        self.env_file
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEd25519YaoArtifactIdentityV1 {
    pub protocol_id: &'static str,
    pub activation_circuit_id: &'static str,
    pub export_circuit_id: &'static str,
}

impl Default for LocalEd25519YaoArtifactIdentityV1 {
    fn default() -> Self {
        Self {
            protocol_id: LOCAL_ED25519_YAO_PROTOCOL_ID_V1,
            activation_circuit_id: LOCAL_ED25519_YAO_ACTIVATION_CIRCUIT_ID_V1,
            export_circuit_id: LOCAL_ED25519_YAO_EXPORT_CIRCUIT_ID_V1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalEd25519YaoLocalEvidenceClaimV1 {
    production_eligible: bool,
    administrative_independence_proven: bool,
}

impl LocalEd25519YaoLocalEvidenceClaimV1 {
    pub const fn production_eligible(self) -> bool {
        self.production_eligible
    }

    pub const fn administrative_independence_proven(self) -> bool {
        self.administrative_independence_proven
    }
}

impl Default for LocalEd25519YaoLocalEvidenceClaimV1 {
    fn default() -> Self {
        Self {
            production_eligible: false,
            administrative_independence_proven: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEd25519YaoOneAccountPlanV1 {
    role_roots: [LocalEd25519YaoRoleRootV1; 3],
    artifact_identity: LocalEd25519YaoArtifactIdentityV1,
    evidence_claim: LocalEd25519YaoLocalEvidenceClaimV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEd25519YaoTwoAdministratorPlanV1 {
    role_roots: [LocalEd25519YaoRoleRootV1; 3],
    artifact_identity: LocalEd25519YaoArtifactIdentityV1,
    evidence_claim: LocalEd25519YaoLocalEvidenceClaimV1,
}

macro_rules! impl_plan {
    ($plan:ty) => {
        impl $plan {
            pub const fn role_roots(&self) -> &[LocalEd25519YaoRoleRootV1; 3] {
                &self.role_roots
            }

            pub const fn artifact_identity(&self) -> &LocalEd25519YaoArtifactIdentityV1 {
                &self.artifact_identity
            }

            pub const fn evidence_claim(&self) -> LocalEd25519YaoLocalEvidenceClaimV1 {
                self.evidence_claim
            }

            pub fn root_for(&self, role: LocalServiceRoleV1) -> Option<&'static str> {
                self.role_roots
                    .iter()
                    .find(|entry| entry.role == role)
                    .map(|entry| entry.relative_root)
            }
        }
    };
}

impl_plan!(LocalEd25519YaoOneAccountPlanV1);
impl_plan!(LocalEd25519YaoTwoAdministratorPlanV1);

pub fn build_local_ed25519_yao_one_account_plan_v1() -> LocalEd25519YaoOneAccountPlanV1 {
    LocalEd25519YaoOneAccountPlanV1 {
        role_roots: LocalEd25519YaoOneAccountDevV1::role_roots(),
        artifact_identity: LocalEd25519YaoArtifactIdentityV1::default(),
        evidence_claim: LocalEd25519YaoLocalEvidenceClaimV1::default(),
    }
}

pub fn build_local_ed25519_yao_two_administrator_plan_v1() -> LocalEd25519YaoTwoAdministratorPlanV1
{
    LocalEd25519YaoTwoAdministratorPlanV1 {
        role_roots: LocalEd25519YaoTwoAdministratorDevV1::role_roots(),
        artifact_identity: LocalEd25519YaoArtifactIdentityV1::default(),
        evidence_claim: LocalEd25519YaoLocalEvidenceClaimV1::default(),
    }
}

pub fn local_ed25519_yao_worker_artifact_digest_v1(worker_binary: &[u8]) -> [u8; 32] {
    Sha256::digest(worker_binary).into()
}

const fn role_roots(
    deriver_a: &'static str,
    deriver_b: &'static str,
    signing_worker: &'static str,
) -> [LocalEd25519YaoRoleRootV1; 3] {
    [
        LocalEd25519YaoRoleRootV1 {
            role: LocalServiceRoleV1::DeriverA,
            relative_root: deriver_a,
            env_file: super::LOCAL_DERIVER_A_ENV_FILE_V1,
        },
        LocalEd25519YaoRoleRootV1 {
            role: LocalServiceRoleV1::DeriverB,
            relative_root: deriver_b,
            env_file: super::LOCAL_DERIVER_B_ENV_FILE_V1,
        },
        LocalEd25519YaoRoleRootV1 {
            role: LocalServiceRoleV1::SigningWorker,
            relative_root: signing_worker,
            env_file: super::LOCAL_SIGNING_WORKER_ENV_FILE_V1,
        },
    ]
}
