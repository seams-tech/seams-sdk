//! Strict portable vectors for proof-system-neutral provenance outer bytes.
//!
//! Every digest and artifact preimage in this module is public synthetic test
//! material. The corpus does not provide production provenance evidence.

use ed25519_yao::{CircuitDigest32, InputSchemaDigest32};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ceremony_context::{
    CeremonyAuthorizationV1, CeremonyRequestKindV1, CeremonyValidatedDagV1,
};
use crate::ceremony_fixtures::{
    canonical_ceremony_fixture_dag_v1, canonical_export_ceremony_fixture_for_registered_key_v1,
    canonical_export_ceremony_fixture_v1,
};
use crate::kdf_fixtures::{
    canonical_registered_public_key_v1, canonical_synthetic_kdf_material_v1,
};
use crate::provenance::{
    ActivationCircuitBindingV1, CeremonyProvenanceBindingV1, ClientEnvelopeArtifactDigest32V1,
    ClientEnvelopeSetDigest32V1, ClientInputArtifactDigest32V1, CombinedInputArtifactDigest32V1,
    ComputedProvenanceArtifactDigestV1, DeriverAProvenanceRoleV1, DeriverBProvenanceRoleV1,
    ExportBranchV1, ExportCircuitBindingV1, ExportStatementCommonV1, ProvenanceArtifactKindV1,
    ProvenanceCircuitFamilyV1, ProvenanceRequestKindV1, ProvenanceRoleV1, RecoveryBranchV1,
    RecoveryContinuityArtifactDigest32V1, RecoveryStatementCommonV1, RefreshBranchV1,
    RefreshContinuityArtifactDigest32V1, RefreshStatementCommonV1,
    RegistrationAntiBiasArtifactDigest32V1, RegistrationBranchV1, RegistrationIntentDigest32V1,
    RegistrationStatementCommonV1, RoleInputProvenancePairV1, RoleInputProvenanceStatementV1,
    RoleInputSnapshotV1, RoleInputStateEpochV1, RoleInputStateRecordDigest32V1, RoleRootEpochV1,
    RoleRootRecordDigest32V1, RootBindingArtifactDigest32V1, ServerInputArtifactDigest32V1,
    StableKdfScopeV1,
};
use crate::RegisteredEd25519PublicKey32V1;

/// Schema identifier for the strict provenance outer-byte corpus.
pub const PROVENANCE_VECTOR_CORPUS_SCHEMA_V1: &str =
    "seams:router-ab:ed25519-yao:role-input-provenance-vectors:v1";

/// Evidence-scope label preventing synthetic outer bytes from implying production proofs.
pub const PROVENANCE_VECTOR_EVIDENCE_SCOPE_V1: &str =
    "host_only_proof_system_neutral_outer_contract_v1";

/// Domain used only to derive reproducible public fixture digest slots.
pub const PROVENANCE_SYNTHETIC_DIGEST_FIXTURE_DOMAIN_V1: &[u8] =
    b"seams/router-ab/ed25519-yao/provenance/synthetic-digest-fixture/v1";

/// Complete strict version-one provenance vector corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceVectorCorpusV1 {
    /// Fixed schema identifier.
    pub schema: String,
    /// Fixed protocol identifier.
    pub protocol_id: String,
    /// Explicitly limited host-only evidence scope.
    pub evidence_scope: String,
    /// One generic wrapper golden for each frozen artifact kind.
    pub artifact_wrapper_goldens: Vec<ProvenanceArtifactWrapperGoldenV1>,
    /// Registration, recovery, refresh, and export cases in fixed order.
    pub cases: Vec<ProvenanceLifecycleVectorCaseV1>,
}

/// One independently reproducible artifact-wrapper golden.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceArtifactWrapperGoldenV1 {
    /// Stable artifact-kind name.
    pub kind: String,
    /// Fixed one-byte artifact-kind tag.
    pub kind_tag: u8,
    /// Public canonical artifact preimage.
    pub canonical_artifact_hex: String,
    /// SHA-256 digest of the frozen LP32 wrapper.
    pub digest_sha256_hex: String,
}

/// Branch-tagged provenance vector case; activation is structurally absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "request_kind", content = "vector", rename_all = "snake_case")]
pub enum ProvenanceLifecycleVectorCaseV1 {
    /// Registration statement-pair vector.
    Registration(ProvenanceCaseVectorV1),
    /// Recovery statement-pair vector.
    Recovery(ProvenanceCaseVectorV1),
    /// Refresh statement-pair vector.
    Refresh(ProvenanceCaseVectorV1),
    /// Authorized export statement-pair vector.
    Export(ProvenanceCaseVectorV1),
}

/// One complete A/B statement-pair trace for one evaluation request kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceCaseVectorV1 {
    /// Stable case identifier.
    pub case_id: String,
    /// Circuit family derived from the request branch.
    pub circuit_family: String,
    /// Exact circuit identifier derived from the family.
    pub circuit_id: String,
    /// Public synthetic final circuit digest.
    pub final_circuit_digest_hex: String,
    /// Public synthetic final input-schema digest.
    pub input_schema_digest_hex: String,
    /// Public synthetic request-context digest.
    pub public_request_context_digest_hex: String,
    /// Public synthetic transcript digest.
    pub transcript_digest_hex: String,
    /// Public synthetic lifecycle authorization digest.
    pub authorization_digest_hex: String,
    /// Deriver A client-envelope artifact-wrapper digest.
    pub client_envelope_a_artifact_digest_hex: String,
    /// Deriver B client-envelope artifact-wrapper digest.
    pub client_envelope_b_artifact_digest_hex: String,
    /// Fixed-order A/B envelope-set digest.
    pub client_envelope_set_digest_hex: String,
    /// Canonical Deriver A statement trace.
    pub deriver_a: ProvenanceRoleStatementVectorV1,
    /// Canonical Deriver B statement trace.
    pub deriver_b: ProvenanceRoleStatementVectorV1,
    /// Canonical ordered A/B pair encoding.
    pub pair_encoding_hex: String,
    /// SHA-256 pair digest.
    pub pair_digest_sha256_hex: String,
}

/// Nested encodings and digest for one role statement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceRoleStatementVectorV1 {
    /// Stable role name.
    pub role: String,
    /// Fixed role tag.
    pub role_tag: u8,
    /// Canonical stable-scope encoding.
    pub stable_scope_encoding_hex: String,
    /// Canonical role-specific ceremony encoding.
    pub ceremony_binding_encoding_hex: String,
    /// Canonical lifecycle branch encoding.
    pub branch_encoding_hex: String,
    /// Canonical role snapshots in branch order.
    pub snapshot_encodings_hex: Vec<String>,
    /// Canonical complete statement encoding.
    pub statement_encoding_hex: String,
    /// SHA-256 statement digest.
    pub statement_digest_sha256_hex: String,
}

#[derive(Clone, Copy)]
struct FixtureCommonV1 {
    stable_scope: StableKdfScopeV1,
    ceremony: CeremonyValidatedDagV1,
    envelope_a: ClientEnvelopeArtifactDigest32V1<DeriverAProvenanceRoleV1>,
    envelope_b: ClientEnvelopeArtifactDigest32V1<DeriverBProvenanceRoleV1>,
    envelope_set: ClientEnvelopeSetDigest32V1,
    circuit_digest: CircuitDigest32,
    input_schema_digest: InputSchemaDigest32,
    family: ProvenanceCircuitFamilyV1,
}

impl FixtureCommonV1 {
    fn ceremony_a(self) -> CeremonyProvenanceBindingV1<DeriverAProvenanceRoleV1> {
        CeremonyProvenanceBindingV1::from_validated_ceremony(
            self.ceremony,
            self.envelope_a,
            self.envelope_set,
        )
        .expect("fixture ceremony performs an evaluation")
    }

    fn ceremony_b(self) -> CeremonyProvenanceBindingV1<DeriverBProvenanceRoleV1> {
        CeremonyProvenanceBindingV1::from_validated_ceremony(
            self.ceremony,
            self.envelope_b,
            self.envelope_set,
        )
        .expect("fixture ceremony performs an evaluation")
    }

    const fn activation_binding(self) -> ActivationCircuitBindingV1 {
        ActivationCircuitBindingV1::new(self.circuit_digest, self.input_schema_digest)
    }

    const fn export_binding(self) -> ExportCircuitBindingV1 {
        ExportCircuitBindingV1::new(self.circuit_digest, self.input_schema_digest)
    }
}

struct SnapshotFixtureV1<Role: ProvenanceRoleV1> {
    snapshot: RoleInputSnapshotV1<Role>,
    encoding: Vec<u8>,
}

struct BuiltProvenanceCaseV1 {
    vector: ProvenanceCaseVectorV1,
    pair: RoleInputProvenancePairV1,
}

/// Builds the exact four-case proof-system-neutral provenance corpus.
pub fn canonical_provenance_vector_corpus_v1() -> ProvenanceVectorCorpusV1 {
    ProvenanceVectorCorpusV1 {
        schema: PROVENANCE_VECTOR_CORPUS_SCHEMA_V1.to_owned(),
        protocol_id: ed25519_yao::PROTOCOL_ID_STR.to_owned(),
        evidence_scope: PROVENANCE_VECTOR_EVIDENCE_SCOPE_V1.to_owned(),
        artifact_wrapper_goldens: canonical_artifact_wrapper_goldens(),
        cases: vec![
            ProvenanceLifecycleVectorCaseV1::Registration(registration_case().vector),
            ProvenanceLifecycleVectorCaseV1::Recovery(recovery_case().vector),
            ProvenanceLifecycleVectorCaseV1::Refresh(refresh_case().vector),
            ProvenanceLifecycleVectorCaseV1::Export(export_case().vector),
        ],
    }
}

pub(crate) fn canonical_provenance_fixture_pair_for_registered_key_v1(
    kind: CeremonyRequestKindV1,
    registered_public_key: RegisteredEd25519PublicKey32V1,
) -> RoleInputProvenancePairV1 {
    match kind {
        CeremonyRequestKindV1::Registration => registration_case().pair,
        CeremonyRequestKindV1::Recovery => recovery_case_for_key(registered_public_key).pair,
        CeremonyRequestKindV1::Refresh => refresh_case_for_key(registered_public_key).pair,
        CeremonyRequestKindV1::Export => export_case_for_key(registered_public_key).pair,
        CeremonyRequestKindV1::Activation => {
            panic!("activation has no role-input provenance pair")
        }
    }
}

fn canonical_artifact_wrapper_goldens() -> Vec<ProvenanceArtifactWrapperGoldenV1> {
    [
        (
            "role_root_binding",
            ProvenanceArtifactKindV1::RoleRootBinding,
        ),
        (
            "client_input_binding",
            ProvenanceArtifactKindV1::ClientInputBinding,
        ),
        (
            "server_input_binding",
            ProvenanceArtifactKindV1::ServerInputBinding,
        ),
        (
            "combined_role_input_binding",
            ProvenanceArtifactKindV1::CombinedRoleInputBinding,
        ),
        (
            "client_envelope_commitment",
            ProvenanceArtifactKindV1::ClientEnvelopeCommitment,
        ),
        (
            "registration_anti_bias_evidence",
            ProvenanceArtifactKindV1::RegistrationAntiBiasEvidence,
        ),
        (
            "recovery_same_root_continuity",
            ProvenanceArtifactKindV1::RecoverySameRootContinuity,
        ),
        (
            "refresh_opposite_delta_transition",
            ProvenanceArtifactKindV1::RefreshOppositeDeltaTransition,
        ),
    ]
    .into_iter()
    .map(|(name, kind)| {
        let canonical_artifact = format!("synthetic-provenance-artifact:{name}:v1");
        let digest =
            ComputedProvenanceArtifactDigestV1::compute(kind, canonical_artifact.as_bytes())
                .expect("fixed synthetic artifact fits LP32");
        ProvenanceArtifactWrapperGoldenV1 {
            kind: name.to_owned(),
            kind_tag: kind.tag(),
            canonical_artifact_hex: encode_hex(canonical_artifact.as_bytes()),
            digest_sha256_hex: encode_hex(digest.as_bytes()),
        }
    })
    .collect()
}

fn registration_case() -> BuiltProvenanceCaseV1 {
    let common = fixture_common(ProvenanceRequestKindV1::Registration);
    let a_snapshot =
        snapshot_fixture::<DeriverAProvenanceRoleV1>("registration", "deriver-a", 3, "current", 11);
    let b_snapshot =
        snapshot_fixture::<DeriverBProvenanceRoleV1>("registration", "deriver-b", 9, "current", 41);
    let intent = RegistrationIntentDigest32V1::from_synthetic_fixture_bytes([0x41; 32]);
    let anti_bias = RegistrationAntiBiasArtifactDigest32V1::from_synthetic_artifact_bytes(
        b"synthetic-registration-anti-bias-evidence:v1",
    )
    .expect("fixed anti-bias artifact fits LP32");
    let a_branch = RegistrationBranchV1::new(a_snapshot.snapshot, intent, anti_bias);
    let b_branch = RegistrationBranchV1::new(b_snapshot.snapshot, intent, anti_bias);
    let a_statement = RoleInputProvenanceStatementV1::registration(
        RegistrationStatementCommonV1::new(
            common.stable_scope,
            common.ceremony_a(),
            common.activation_binding(),
        )
        .expect("registration ceremony kind matches"),
        a_branch,
    );
    let b_statement = RoleInputProvenanceStatementV1::registration(
        RegistrationStatementCommonV1::new(
            common.stable_scope,
            common.ceremony_b(),
            common.activation_binding(),
        )
        .expect("registration ceremony kind matches"),
        b_branch,
    );
    case_vector(
        "registration_provenance_outer_v1",
        common,
        a_statement,
        b_statement,
        a_branch.encode().expect("registration branch encodes"),
        b_branch.encode().expect("registration branch encodes"),
        vec![a_snapshot.encoding],
        vec![b_snapshot.encoding],
    )
}

fn recovery_case() -> BuiltProvenanceCaseV1 {
    recovery_case_for_key(canonical_registered_public_key_v1())
}

fn recovery_case_for_key(public_key: RegisteredEd25519PublicKey32V1) -> BuiltProvenanceCaseV1 {
    let common = fixture_common(ProvenanceRequestKindV1::Recovery);
    let a_snapshot =
        snapshot_fixture::<DeriverAProvenanceRoleV1>("recovery", "deriver-a", 3, "current", 11);
    let b_snapshot =
        snapshot_fixture::<DeriverBProvenanceRoleV1>("recovery", "deriver-b", 9, "current", 41);
    let continuity = RecoveryContinuityArtifactDigest32V1::from_synthetic_artifact_bytes(
        b"synthetic-recovery-same-root-evidence:v1",
    )
    .expect("fixed recovery artifact fits LP32");
    let a_branch = RecoveryBranchV1::new(a_snapshot.snapshot, public_key, continuity);
    let b_branch = RecoveryBranchV1::new(b_snapshot.snapshot, public_key, continuity);
    let a_statement = RoleInputProvenanceStatementV1::recovery(
        RecoveryStatementCommonV1::new(
            common.stable_scope,
            common.ceremony_a(),
            common.activation_binding(),
        )
        .expect("recovery ceremony kind matches"),
        a_branch,
    );
    let b_statement = RoleInputProvenanceStatementV1::recovery(
        RecoveryStatementCommonV1::new(
            common.stable_scope,
            common.ceremony_b(),
            common.activation_binding(),
        )
        .expect("recovery ceremony kind matches"),
        b_branch,
    );
    case_vector(
        "recovery_provenance_outer_v1",
        common,
        a_statement,
        b_statement,
        a_branch.encode().expect("recovery branch encodes"),
        b_branch.encode().expect("recovery branch encodes"),
        vec![a_snapshot.encoding],
        vec![b_snapshot.encoding],
    )
}

fn refresh_case() -> BuiltProvenanceCaseV1 {
    refresh_case_for_key(canonical_registered_public_key_v1())
}

fn refresh_case_for_key(public_key: RegisteredEd25519PublicKey32V1) -> BuiltProvenanceCaseV1 {
    let common = fixture_common(ProvenanceRequestKindV1::Refresh);
    let a_root_binding = RootBindingArtifactDigest32V1::from_synthetic_artifact_bytes(
        b"refresh:deriver-a:stable-root-binding",
    )
    .expect("fixed A root artifact fits LP32");
    let a_before = snapshot_fixture_with_root_binding::<DeriverAProvenanceRoleV1>(
        "refresh-before",
        "deriver-a",
        3,
        "current",
        41,
        a_root_binding,
    );
    let a_after = snapshot_fixture_with_root_binding::<DeriverAProvenanceRoleV1>(
        "refresh-after",
        "deriver-a",
        3,
        "next",
        42,
        a_root_binding,
    );
    let b_root_binding = RootBindingArtifactDigest32V1::from_synthetic_artifact_bytes(
        b"refresh:deriver-b:stable-root-binding",
    )
    .expect("fixed B root artifact fits LP32");
    let b_before = snapshot_fixture_with_root_binding::<DeriverBProvenanceRoleV1>(
        "refresh-before",
        "deriver-b",
        9,
        "current",
        51,
        b_root_binding,
    );
    let b_after = snapshot_fixture_with_root_binding::<DeriverBProvenanceRoleV1>(
        "refresh-after",
        "deriver-b",
        9,
        "next",
        53,
        b_root_binding,
    );
    let continuity = RefreshContinuityArtifactDigest32V1::from_synthetic_artifact_bytes(
        b"synthetic-refresh-opposite-delta-evidence:v1",
    )
    .expect("fixed refresh artifact fits LP32");
    let a_branch =
        RefreshBranchV1::new(a_before.snapshot, a_after.snapshot, public_key, continuity)
            .expect("A refresh root is stable and input epoch advances");
    let b_branch =
        RefreshBranchV1::new(b_before.snapshot, b_after.snapshot, public_key, continuity)
            .expect("B refresh root is stable and input epoch advances");
    let a_statement = RoleInputProvenanceStatementV1::refresh(
        RefreshStatementCommonV1::new(
            common.stable_scope,
            common.ceremony_a(),
            common.activation_binding(),
        )
        .expect("refresh ceremony kind matches"),
        a_branch,
    );
    let b_statement = RoleInputProvenanceStatementV1::refresh(
        RefreshStatementCommonV1::new(
            common.stable_scope,
            common.ceremony_b(),
            common.activation_binding(),
        )
        .expect("refresh ceremony kind matches"),
        b_branch,
    );
    case_vector(
        "refresh_provenance_outer_v1",
        common,
        a_statement,
        b_statement,
        a_branch.encode().expect("refresh branch encodes"),
        b_branch.encode().expect("refresh branch encodes"),
        vec![a_before.encoding, a_after.encoding],
        vec![b_before.encoding, b_after.encoding],
    )
}

fn export_case() -> BuiltProvenanceCaseV1 {
    let (request, authorization, transcript) = canonical_export_ceremony_fixture_v1();
    export_case_for_ceremony(
        authorization.registered_public_key(),
        request,
        authorization,
        transcript,
    )
}

fn export_case_for_key(public_key: RegisteredEd25519PublicKey32V1) -> BuiltProvenanceCaseV1 {
    let (request, authorization, transcript) =
        canonical_export_ceremony_fixture_for_registered_key_v1(public_key);
    export_case_for_ceremony(public_key, request, authorization, transcript)
}

fn export_case_for_ceremony(
    public_key: RegisteredEd25519PublicKey32V1,
    request: crate::ceremony_context::CeremonyPublicRequestContextV1,
    authorization: crate::ceremony_context::CeremonyExportAuthorizationV1,
    transcript: crate::ceremony_context::CeremonyTranscriptV1,
) -> BuiltProvenanceCaseV1 {
    let ceremony = CeremonyValidatedDagV1::from_components(
        &request,
        &CeremonyAuthorizationV1::from(authorization),
        &transcript,
    )
    .expect("dynamic export fixture ceremony is coherent");
    let common = fixture_common_for_ceremony(ProvenanceRequestKindV1::Export, ceremony);
    let a_snapshot =
        snapshot_fixture::<DeriverAProvenanceRoleV1>("export", "deriver-a", 3, "current", 11);
    let b_snapshot =
        snapshot_fixture::<DeriverBProvenanceRoleV1>("export", "deriver-b", 9, "current", 41);
    let a_branch = ExportBranchV1::new(a_snapshot.snapshot, public_key);
    let b_branch = ExportBranchV1::new(b_snapshot.snapshot, public_key);
    let a_statement = RoleInputProvenanceStatementV1::export(
        ExportStatementCommonV1::new(
            common.stable_scope,
            common.ceremony_a(),
            common.export_binding(),
        )
        .expect("export ceremony kind matches"),
        a_branch,
    );
    let b_statement = RoleInputProvenanceStatementV1::export(
        ExportStatementCommonV1::new(
            common.stable_scope,
            common.ceremony_b(),
            common.export_binding(),
        )
        .expect("export ceremony kind matches"),
        b_branch,
    );
    case_vector(
        "export_provenance_outer_v1",
        common,
        a_statement,
        b_statement,
        a_branch.encode().expect("export branch encodes"),
        b_branch.encode().expect("export branch encodes"),
        vec![a_snapshot.encoding],
        vec![b_snapshot.encoding],
    )
}

#[allow(clippy::too_many_arguments)]
fn case_vector(
    case_id: &str,
    common: FixtureCommonV1,
    deriver_a: RoleInputProvenanceStatementV1<DeriverAProvenanceRoleV1>,
    deriver_b: RoleInputProvenanceStatementV1<DeriverBProvenanceRoleV1>,
    a_branch_encoding: Vec<u8>,
    b_branch_encoding: Vec<u8>,
    a_snapshot_encodings: Vec<Vec<u8>>,
    b_snapshot_encodings: Vec<Vec<u8>>,
) -> BuiltProvenanceCaseV1 {
    let stable_scope_encoding = common
        .stable_scope
        .encode()
        .expect("fixed stable scope fits LP32");
    let ceremony_a_encoding = common
        .ceremony_a()
        .encode()
        .expect("fixed ceremony fits LP32");
    let ceremony_b_encoding = common
        .ceremony_b()
        .encode()
        .expect("fixed ceremony fits LP32");
    let pair = RoleInputProvenancePairV1::new(deriver_a, deriver_b)
        .expect("fixed A/B statements satisfy outer pair relations");
    let pair_encoding = pair.encode().expect("fixed pair fits LP32");
    let pair_digest = pair.digest().expect("fixed pair digest encodes");
    let vector = ProvenanceCaseVectorV1 {
        case_id: case_id.to_owned(),
        circuit_family: family_name(common.family).to_owned(),
        circuit_id: family_circuit_id(common.family).to_owned(),
        final_circuit_digest_hex: encode_hex(common.circuit_digest.as_bytes()),
        input_schema_digest_hex: encode_hex(common.input_schema_digest.as_bytes()),
        public_request_context_digest_hex: encode_hex(
            common.ceremony.request_context_digest().as_bytes(),
        ),
        transcript_digest_hex: encode_hex(common.ceremony.transcript_digest().as_bytes()),
        authorization_digest_hex: encode_hex(common.ceremony.authorization_digest().as_bytes()),
        client_envelope_a_artifact_digest_hex: encode_hex(common.envelope_a.as_bytes()),
        client_envelope_b_artifact_digest_hex: encode_hex(common.envelope_b.as_bytes()),
        client_envelope_set_digest_hex: encode_hex(common.envelope_set.as_bytes()),
        deriver_a: role_statement_vector(
            "deriver_a",
            &stable_scope_encoding,
            &ceremony_a_encoding,
            &a_branch_encoding,
            &a_snapshot_encodings,
            pair.deriver_a(),
        ),
        deriver_b: role_statement_vector(
            "deriver_b",
            &stable_scope_encoding,
            &ceremony_b_encoding,
            &b_branch_encoding,
            &b_snapshot_encodings,
            pair.deriver_b(),
        ),
        pair_encoding_hex: encode_hex(&pair_encoding),
        pair_digest_sha256_hex: encode_hex(pair_digest.as_bytes()),
    };
    BuiltProvenanceCaseV1 { vector, pair }
}

fn role_statement_vector<Role: ProvenanceRoleV1>(
    role: &str,
    stable_scope_encoding: &[u8],
    ceremony_encoding: &[u8],
    branch_encoding: &[u8],
    snapshot_encodings: &[Vec<u8>],
    statement: &RoleInputProvenanceStatementV1<Role>,
) -> ProvenanceRoleStatementVectorV1 {
    let statement_encoding = statement.encode().expect("fixed statement fits LP32");
    let statement_digest = statement.digest().expect("fixed statement digest encodes");
    ProvenanceRoleStatementVectorV1 {
        role: role.to_owned(),
        role_tag: Role::TAG,
        stable_scope_encoding_hex: encode_hex(stable_scope_encoding),
        ceremony_binding_encoding_hex: encode_hex(ceremony_encoding),
        branch_encoding_hex: encode_hex(branch_encoding),
        snapshot_encodings_hex: snapshot_encodings
            .iter()
            .map(|encoding| encode_hex(encoding))
            .collect(),
        statement_encoding_hex: encode_hex(&statement_encoding),
        statement_digest_sha256_hex: encode_hex(statement_digest.as_bytes()),
    }
}

fn fixture_common(request: ProvenanceRequestKindV1) -> FixtureCommonV1 {
    fixture_common_for_ceremony(
        request,
        canonical_ceremony_fixture_dag_v1(ceremony_request_kind(request)),
    )
}

fn fixture_common_for_ceremony(
    request: ProvenanceRequestKindV1,
    ceremony: CeremonyValidatedDagV1,
) -> FixtureCommonV1 {
    let request_name = request_name(request);
    let stable_scope =
        StableKdfScopeV1::from_context(&canonical_synthetic_kdf_material_v1().context);
    let envelope_a = ClientEnvelopeArtifactDigest32V1::from_synthetic_artifact_bytes(
        format!("{request_name}:client-envelope:deriver-a").as_bytes(),
    )
    .expect("fixed envelope A fits LP32");
    let envelope_b = ClientEnvelopeArtifactDigest32V1::from_synthetic_artifact_bytes(
        format!("{request_name}:client-envelope:deriver-b").as_bytes(),
    )
    .expect("fixed envelope B fits LP32");
    let envelope_set =
        ClientEnvelopeSetDigest32V1::compute(&envelope_a, &envelope_b).expect("set fits LP32");
    let family = match request {
        ProvenanceRequestKindV1::Registration
        | ProvenanceRequestKindV1::Recovery
        | ProvenanceRequestKindV1::Refresh => ProvenanceCircuitFamilyV1::Activation,
        ProvenanceRequestKindV1::Export => ProvenanceCircuitFamilyV1::Export,
    };
    let circuit_digest = CircuitDigest32::new(synthetic_digest(
        format!("{}:final-circuit", family_name(family)).as_bytes(),
    ))
    .expect("synthetic circuit digest is nonzero");
    let input_schema_digest = InputSchemaDigest32::new(synthetic_digest(
        format!("{}:input-schema", family_name(family)).as_bytes(),
    ))
    .expect("synthetic input-schema digest is nonzero");
    FixtureCommonV1 {
        stable_scope,
        ceremony,
        envelope_a,
        envelope_b,
        envelope_set,
        circuit_digest,
        input_schema_digest,
        family,
    }
}

fn ceremony_request_kind(request: ProvenanceRequestKindV1) -> CeremonyRequestKindV1 {
    match request {
        ProvenanceRequestKindV1::Registration => CeremonyRequestKindV1::Registration,
        ProvenanceRequestKindV1::Recovery => CeremonyRequestKindV1::Recovery,
        ProvenanceRequestKindV1::Refresh => CeremonyRequestKindV1::Refresh,
        ProvenanceRequestKindV1::Export => CeremonyRequestKindV1::Export,
    }
}

fn snapshot_fixture<Role: ProvenanceRoleV1>(
    request_name: &str,
    role_name: &str,
    root_epoch: u64,
    state_name: &str,
    input_state_epoch: u64,
) -> SnapshotFixtureV1<Role> {
    let artifact_prefix = format!("{request_name}:{role_name}:{state_name}");
    let root_binding_artifact_digest =
        RootBindingArtifactDigest32V1::from_synthetic_artifact_bytes(
            format!("{artifact_prefix}:root-binding").as_bytes(),
        )
        .expect("fixed root artifact fits LP32");
    snapshot_fixture_with_root_binding(
        request_name,
        role_name,
        root_epoch,
        state_name,
        input_state_epoch,
        root_binding_artifact_digest,
    )
}

fn snapshot_fixture_with_root_binding<Role: ProvenanceRoleV1>(
    request_name: &str,
    role_name: &str,
    root_epoch: u64,
    state_name: &str,
    input_state_epoch: u64,
    root_binding_artifact_digest: RootBindingArtifactDigest32V1<Role>,
) -> SnapshotFixtureV1<Role> {
    let role_root_record_digest = RoleRootRecordDigest32V1::from_synthetic_fixture_bytes(
        synthetic_digest(format!("{role_name}:role-root-record").as_bytes()),
    );
    let role_input_state_record_digest =
        RoleInputStateRecordDigest32V1::from_synthetic_fixture_bytes(synthetic_digest(
            format!("{role_name}:role-input-state:{state_name}").as_bytes(),
        ));
    let artifact_prefix = format!("{request_name}:{role_name}:{state_name}");
    let snapshot = RoleInputSnapshotV1::from_synthetic_fixture(
        role_root_record_digest,
        root_binding_artifact_digest,
        RoleRootEpochV1::new(root_epoch).expect("fixture root epoch is nonzero"),
        role_input_state_record_digest,
        RoleInputStateEpochV1::new(input_state_epoch).expect("fixture state epoch is nonzero"),
        ClientInputArtifactDigest32V1::from_synthetic_artifact_bytes(
            format!("{artifact_prefix}:client-input").as_bytes(),
        )
        .expect("fixed client artifact fits LP32"),
        ServerInputArtifactDigest32V1::from_synthetic_artifact_bytes(
            format!("{artifact_prefix}:server-input").as_bytes(),
        )
        .expect("fixed server artifact fits LP32"),
        CombinedInputArtifactDigest32V1::from_synthetic_artifact_bytes(
            format!("{artifact_prefix}:combined-input").as_bytes(),
        )
        .expect("fixed combined artifact fits LP32"),
    );
    SnapshotFixtureV1 {
        encoding: snapshot.encode().expect("fixed snapshot fits LP32"),
        snapshot,
    }
}

fn synthetic_digest(label: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROVENANCE_SYNTHETIC_DIGEST_FIXTURE_DOMAIN_V1);
    hasher.update([0]);
    hasher.update(label);
    hasher.finalize().into()
}

const fn request_name(request: ProvenanceRequestKindV1) -> &'static str {
    match request {
        ProvenanceRequestKindV1::Registration => "registration",
        ProvenanceRequestKindV1::Recovery => "recovery",
        ProvenanceRequestKindV1::Refresh => "refresh",
        ProvenanceRequestKindV1::Export => "export",
    }
}

const fn family_name(family: ProvenanceCircuitFamilyV1) -> &'static str {
    match family {
        ProvenanceCircuitFamilyV1::Activation => "activation",
        ProvenanceCircuitFamilyV1::Export => "export",
    }
}

const fn family_circuit_id(family: ProvenanceCircuitFamilyV1) -> &'static str {
    match family {
        ProvenanceCircuitFamilyV1::Activation => ed25519_yao::ACTIVATION_CIRCUIT_ID_STR,
        ProvenanceCircuitFamilyV1::Export => ed25519_yao::EXPORT_CIRCUIT_ID_STR,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}
