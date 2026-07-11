use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_yao_generator::ceremony_context::*;
use ed25519_yao_generator::lifecycle_domain::{
    AbortedTerminalStateV1, ExportRequestV1, RecoveryRequestV1, RedactedFailureCodeV1,
    RefreshRequestV1, RegistrationRequestV1, UniformLifecycleAbortV1,
};
use ed25519_yao_generator::{canonical_ceremony_fixture_dag_v1, RegisteredEd25519PublicKey32V1};

#[test]
fn uniform_abort_envelope_has_one_exact_public_shape_for_all_five_branches() {
    for request_kind in [
        CeremonyRequestKindV1::Registration,
        CeremonyRequestKindV1::Activation,
        CeremonyRequestKindV1::Recovery,
        CeremonyRequestKindV1::Refresh,
        CeremonyRequestKindV1::Export,
    ] {
        let dag = canonical_ceremony_fixture_dag_v1(request_kind);
        let abort = UniformLifecycleAbortV1::rejected(&dag);
        assert_eq!(abort.request_kind(), request_kind);
        assert_eq!(abort.public_transcript_digest(), dag.transcript_digest());
        assert_eq!(abort.public_failure_code(), RedactedFailureCodeV1::Rejected);
        assert_eq!(abort.terminal(), AbortedTerminalStateV1::Aborted);
    }
}

fn identifier<T>(value: &str, parse: impl FnOnce(&str) -> Result<T, CeremonyContextErrorV1>) -> T {
    parse(value).expect("canonical test identifier")
}

fn request_context(
    kind: CeremonyRequestKindV1,
    discriminator: u8,
) -> CeremonyPublicRequestContextV1 {
    let identity = CeremonyIdentityScopeV1::new(
        identifier("account", CeremonyAccountIdV1::parse),
        identifier("wallet", CeremonyWalletIdV1::parse),
        identifier("session", CeremonySessionIdV1::parse),
        identifier("organization", CeremonyOrganizationIdV1::parse),
        identifier("project", CeremonyProjectIdV1::parse),
        identifier("environment", CeremonyEnvironmentIdV1::parse),
        identifier("signing-root", CeremonySigningRootIdV1::parse),
        CeremonySigningRootVersionV1::new(7).expect("nonzero signing-root version"),
        identifier("ed25519", CeremonyChainTargetV1::parse),
    );
    let infrastructure = CeremonyInfrastructureV1::new(
        identifier("router", CeremonyRouterIdV1::parse),
        identifier("deriver-set", CeremonyDeriverSetIdV1::parse),
        CeremonyDeriverABindingV1::new(
            identifier("deriver-a", CeremonyDeriverAIdV1::parse),
            CeremonyDeriverAKeyEpochV1::new(11).expect("nonzero Deriver A key epoch"),
        ),
        CeremonyDeriverBBindingV1::new(
            identifier("deriver-b", CeremonyDeriverBIdV1::parse),
            CeremonyDeriverBKeyEpochV1::new(13).expect("nonzero Deriver B key epoch"),
        ),
        CeremonySigningWorkerBindingV1::new(
            identifier("signing-worker", CeremonySigningWorkerIdV1::parse),
            CeremonySigningWorkerKeyEpochV1::new(17).expect("nonzero SigningWorker key epoch"),
        ),
    );
    CeremonyPublicRequestContextV1::new(
        kind,
        identifier(
            &format!("request-{discriminator}"),
            CeremonyRequestIdV1::parse,
        ),
        CeremonyReplayNonce32V1::new([discriminator; 32]),
        identity,
        CeremonyRootShareEpochV1::new(19).expect("nonzero root-share epoch"),
        infrastructure,
        CeremonyClientEphemeralPublicKey32V1::new([discriminator.wrapping_add(1); 32]),
        CeremonyRequestExpiryV1::new(1_900_000_000_000).expect("nonzero request expiry"),
    )
}

fn transcript(
    request: &CeremonyPublicRequestContextV1,
    authorization: &CeremonyAuthorizationV1,
    discriminator: u8,
) -> CeremonyTranscriptV1 {
    CeremonyTranscriptV1::new(
        request,
        authorization,
        CeremonyTranscriptNonce32V1::new([discriminator; 32]),
        CeremonyTransportBindingDigest32V1::new([discriminator.wrapping_add(1); 32])
            .expect("nonzero transport binding"),
        CeremonyArtifactSuiteDigest32V1::new([discriminator.wrapping_add(2); 32])
            .expect("nonzero artifact suite"),
    )
    .expect("canonical transcript")
}

fn registered_public_key() -> RegisteredEd25519PublicKey32V1 {
    let mut bytes = [0x66; 32];
    bytes[0] = 0x58;
    RegisteredEd25519PublicKey32V1::parse(bytes).expect("Ed25519 basepoint encoding")
}

#[test]
fn registration_wrapper_owns_the_matching_canonical_dag() {
    let request_context = request_context(CeremonyRequestKindV1::Registration, 0x21);
    let authorization = CeremonyRegistrationAuthorizationV1::new(
        &request_context,
        CeremonyAuthorizationRecordDigest32V1::new([0x31; 32])
            .expect("nonzero authorization record"),
        CeremonyRegistrationIntentDigest32V1::new([0x41; 32]).expect("nonzero registration intent"),
    )
    .expect("registration authorization");
    let authorization_union = CeremonyAuthorizationV1::from(authorization);
    let transcript = transcript(&request_context, &authorization_union, 0x51);
    let expected = CeremonyValidatedDagV1::from_components(
        &request_context,
        &authorization_union,
        &transcript,
    )
    .expect("canonical registration DAG");

    let request = RegistrationRequestV1::new(request_context, authorization, transcript)
        .expect("matching registration wrapper");

    assert_eq!(request.request_kind(), CeremonyRequestKindV1::Registration);
    assert_eq!(request.authorization(), &authorization);
    assert_eq!(request.transcript(), &transcript);
    assert_eq!(request.validated_dag(), expected);
}

#[test]
fn recovery_wrapper_owns_the_matching_canonical_dag() {
    let request_context = request_context(CeremonyRequestKindV1::Recovery, 0x22);
    let authorization = CeremonyRecoveryAuthorizationV1::new(
        &request_context,
        CeremonyAuthorizationRecordDigest32V1::new([0x32; 32])
            .expect("nonzero authorization record"),
        CeremonyReplacementCredentialBindingDigest32V1::new([0x42; 32])
            .expect("nonzero replacement credential binding"),
    )
    .expect("recovery authorization");
    let authorization_union = CeremonyAuthorizationV1::from(authorization);
    let transcript = transcript(&request_context, &authorization_union, 0x52);
    let expected = CeremonyValidatedDagV1::from_components(
        &request_context,
        &authorization_union,
        &transcript,
    )
    .expect("canonical recovery DAG");

    let request = RecoveryRequestV1::new(request_context, authorization, transcript)
        .expect("matching recovery wrapper");

    assert_eq!(request.request_kind(), CeremonyRequestKindV1::Recovery);
    assert_eq!(request.authorization(), &authorization);
    assert_eq!(request.transcript(), &transcript);
    assert_eq!(request.validated_dag(), expected);
}

#[test]
fn refresh_wrapper_owns_the_matching_canonical_dag() {
    let request_context = request_context(CeremonyRequestKindV1::Refresh, 0x23);
    let authorization = CeremonyRefreshAuthorizationV1::new(
        &request_context,
        CeremonyAuthorizationRecordDigest32V1::new([0x33; 32])
            .expect("nonzero authorization record"),
        CeremonyCurrentDeriverAInputStateEpochV1::new(23).expect("nonzero current Deriver A epoch"),
        CeremonyNextDeriverAInputStateEpochV1::new(29).expect("nonzero next Deriver A epoch"),
        CeremonyCurrentDeriverBInputStateEpochV1::new(31).expect("nonzero current Deriver B epoch"),
        CeremonyNextDeriverBInputStateEpochV1::new(37).expect("nonzero next Deriver B epoch"),
    )
    .expect("refresh authorization");
    let authorization_union = CeremonyAuthorizationV1::from(authorization);
    let transcript = transcript(&request_context, &authorization_union, 0x53);
    let expected = CeremonyValidatedDagV1::from_components(
        &request_context,
        &authorization_union,
        &transcript,
    )
    .expect("canonical refresh DAG");

    let request = RefreshRequestV1::new(request_context, authorization, transcript)
        .expect("matching refresh wrapper");

    assert_eq!(request.request_kind(), CeremonyRequestKindV1::Refresh);
    assert_eq!(request.authorization(), &authorization);
    assert_eq!(request.transcript(), &transcript);
    assert_eq!(request.validated_dag(), expected);
}

#[test]
fn export_wrapper_owns_the_matching_canonical_dag() {
    let request_context = request_context(CeremonyRequestKindV1::Export, 0x24);
    let authorization = CeremonyExportAuthorizationV1::new(
        &request_context,
        CeremonyAuthorizationRecordDigest32V1::new([0x34; 32])
            .expect("nonzero authorization record"),
        registered_public_key(),
    )
    .expect("export authorization");
    let authorization_union = CeremonyAuthorizationV1::from(authorization);
    let transcript = transcript(&request_context, &authorization_union, 0x54);
    let expected = CeremonyValidatedDagV1::from_components(
        &request_context,
        &authorization_union,
        &transcript,
    )
    .expect("canonical export DAG");

    let request = ExportRequestV1::new(request_context, authorization, transcript)
        .expect("matching export wrapper");

    assert_eq!(request.request_kind(), CeremonyRequestKindV1::Export);
    assert_eq!(request.authorization(), &authorization);
    assert_eq!(request.transcript(), &transcript);
    assert_eq!(request.validated_dag(), expected);
}

struct UiHarness {
    directory: PathBuf,
}

static UI_HARNESS_SEQUENCE: AtomicU64 = AtomicU64::new(0);

impl UiHarness {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock follows Unix epoch")
            .as_nanos();
        let sequence = UI_HARNESS_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "ed25519-yao-canonical-lifecycle-ui-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir_all(directory.join("src")).expect("create UI harness source directory");
        let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("canonical generator path");
        let dependency_path = manifest_directory.to_string_lossy().replace('\\', "\\\\");
        fs::write(
            directory.join("Cargo.toml"),
            format!(
                "[package]\nname = \"canonical-lifecycle-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
                 [dependencies]\ned25519-yao-generator = {{ path = \"{dependency_path}\" }}\n"
            ),
        )
        .expect("write UI harness manifest");
        Self { directory }
    }

    fn check(&self, body: &str) -> Output {
        fs::write(self.directory.join("src/main.rs"), body).expect("write UI harness source");
        Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args(["check", "--quiet", "--offline"])
            .current_dir(&self.directory)
            .env("CARGO_TARGET_DIR", self.directory.join("target"))
            .output()
            .expect("execute UI cargo check")
    }
}

impl Drop for UiHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

struct CompileFailure<'a> {
    name: &'a str,
    body: &'a str,
    code: &'a str,
    needles: &'a [&'a str],
}

fn assert_compile_failure(harness: &UiHarness, case: CompileFailure<'_>) {
    let output = harness.check(case.body);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "UI case `{}` unexpectedly compiled",
        case.name
    );
    assert!(
        stderr.contains(case.code),
        "UI case `{}` failed without {}:\n{stderr}",
        case.name,
        case.code
    );
    for needle in case.needles {
        assert!(
            stderr.contains(needle),
            "UI case `{}` omitted `{needle}` from diagnostics:\n{stderr}",
            case.name
        );
    }
}

#[test]
fn external_api_rejects_legacy_construction_and_cross_branch_mixups() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::lifecycle_domain::{\n\
             ExportRequestV1, RecoveryRequestV1, RefreshRequestV1, RegistrationRequestV1,\n\
         };\n\
         fn supported(_: RegistrationRequestV1, _: RecoveryRequestV1, _: RefreshRequestV1, _: ExportRequestV1) {}\n\
         fn main() {}",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    let cases = [
        CompileFailure {
            name: "removed lifecycle model",
            body: "use ed25519_yao_generator::lifecycle_domain::{\n\
                       CommonLifecyclePublicInputV1, SyntheticCommittedActivationManifestV1,\n\
                       SyntheticCommittedActivationPackageRefsV1, RegistrationSuccessV1,\n\
                       RecoverySuccessV1, RefreshSuccessV1, ExportSuccessV1,\n\
                       ReferenceLifecycleSuccessV1,\n\
                   };\n\
                   fn main() {}",
            code: "E0432",
            needles: &["CommonLifecyclePublicInputV1", "RegistrationSuccessV1"],
        },
        CompileFailure {
            name: "removed synthetic-tag constructor",
            body: "use ed25519_yao_generator::ceremony_context::CeremonyRequestIdV1;\n\
                   fn main() { let _ = CeremonyRequestIdV1::from_synthetic_tag(7); }",
            code: "E0599",
            needles: &["from_synthetic_tag"],
        },
        CompileFailure {
            name: "private request fields",
            body: "use ed25519_yao_generator::ceremony_context::{\n\
                       CeremonyPublicRequestContextV1, CeremonyRegistrationAuthorizationV1,\n\
                       CeremonyTranscriptV1, CeremonyValidatedDagV1,\n\
                   };\n\
                   use ed25519_yao_generator::lifecycle_domain::RegistrationRequestV1;\n\
                   fn invalid(request_context: CeremonyPublicRequestContextV1, authorization: CeremonyRegistrationAuthorizationV1, transcript: CeremonyTranscriptV1, validated_dag: CeremonyValidatedDagV1) {\n\
                       let _ = RegistrationRequestV1 { request_context, authorization, transcript, validated_dag };\n\
                   }\n\
                   fn main() {}",
            code: "E0451",
            needles: &["request_context", "validated_dag"],
        },
        CompileFailure {
            name: "registration rejects recovery authorization",
            body: "use ed25519_yao_generator::ceremony_context::{CeremonyPublicRequestContextV1, CeremonyRecoveryAuthorizationV1, CeremonyTranscriptV1};\n\
                   use ed25519_yao_generator::lifecycle_domain::RegistrationRequestV1;\n\
                   fn invalid(context: CeremonyPublicRequestContextV1, authorization: CeremonyRecoveryAuthorizationV1, transcript: CeremonyTranscriptV1) {\n\
                       let _ = RegistrationRequestV1::new(context, authorization, transcript);\n\
                   }\n\
                   fn main() {}",
            code: "E0308",
            needles: &["CeremonyRegistrationAuthorizationV1"],
        },
        CompileFailure {
            name: "recovery rejects refresh authorization",
            body: "use ed25519_yao_generator::ceremony_context::{CeremonyPublicRequestContextV1, CeremonyRefreshAuthorizationV1, CeremonyTranscriptV1};\n\
                   use ed25519_yao_generator::lifecycle_domain::RecoveryRequestV1;\n\
                   fn invalid(context: CeremonyPublicRequestContextV1, authorization: CeremonyRefreshAuthorizationV1, transcript: CeremonyTranscriptV1) {\n\
                       let _ = RecoveryRequestV1::new(context, authorization, transcript);\n\
                   }\n\
                   fn main() {}",
            code: "E0308",
            needles: &["CeremonyRecoveryAuthorizationV1"],
        },
        CompileFailure {
            name: "refresh rejects export authorization",
            body: "use ed25519_yao_generator::ceremony_context::{CeremonyExportAuthorizationV1, CeremonyPublicRequestContextV1, CeremonyTranscriptV1};\n\
                   use ed25519_yao_generator::lifecycle_domain::RefreshRequestV1;\n\
                   fn invalid(context: CeremonyPublicRequestContextV1, authorization: CeremonyExportAuthorizationV1, transcript: CeremonyTranscriptV1) {\n\
                       let _ = RefreshRequestV1::new(context, authorization, transcript);\n\
                   }\n\
                   fn main() {}",
            code: "E0308",
            needles: &["CeremonyRefreshAuthorizationV1"],
        },
        CompileFailure {
            name: "export rejects registration authorization",
            body: "use ed25519_yao_generator::ceremony_context::{CeremonyPublicRequestContextV1, CeremonyRegistrationAuthorizationV1, CeremonyTranscriptV1};\n\
                   use ed25519_yao_generator::lifecycle_domain::ExportRequestV1;\n\
                   fn invalid(context: CeremonyPublicRequestContextV1, authorization: CeremonyRegistrationAuthorizationV1, transcript: CeremonyTranscriptV1) {\n\
                       let _ = ExportRequestV1::new(context, authorization, transcript);\n\
                   }\n\
                   fn main() {}",
            code: "E0308",
            needles: &["CeremonyExportAuthorizationV1"],
        },
        CompileFailure {
            name: "registration origin rejects recovery pending state",
            body: "use ed25519_yao_generator::lifecycle_domain::{PendingActivationPreStateV1, RecoveryPendingActivationV1};\n\
                   fn invalid(pending: RecoveryPendingActivationV1) {\n\
                       let _ = PendingActivationPreStateV1::Registration(pending);\n\
                   }\n\
                   fn main() {}",
            code: "E0308",
            needles: &["RegistrationPendingActivationV1"],
        },
        CompileFailure {
            name: "recovery origin rejects refresh pending state",
            body: "use ed25519_yao_generator::lifecycle_domain::{PendingActivationPreStateV1, RefreshPendingActivationV1};\n\
                   fn invalid(pending: RefreshPendingActivationV1) {\n\
                       let _ = PendingActivationPreStateV1::Recovery(pending);\n\
                   }\n\
                   fn main() {}",
            code: "E0308",
            needles: &["RecoveryPendingActivationV1"],
        },
        CompileFailure {
            name: "refresh origin rejects registration pending state",
            body: "use ed25519_yao_generator::lifecycle_domain::{PendingActivationPreStateV1, RegistrationPendingActivationV1};\n\
                   fn invalid(pending: RegistrationPendingActivationV1) {\n\
                       let _ = PendingActivationPreStateV1::Refresh(pending);\n\
                   }\n\
                   fn main() {}",
            code: "E0308",
            needles: &["RefreshPendingActivationV1"],
        },
        CompileFailure {
            name: "private activation origin fields",
            body: "use ed25519_yao_generator::ceremony_context::{\n\
                       CeremonyActivationOriginV1, CeremonyPublicRequestContextDigest32V1,\n\
                       CeremonyRequestKindV1, CeremonyTranscriptDigest32V1,\n\
                   };\n\
                   fn invalid(context: CeremonyPublicRequestContextDigest32V1, transcript: CeremonyTranscriptDigest32V1) {\n\
                       let _ = CeremonyActivationOriginV1 {\n\
                           request_kind: CeremonyRequestKindV1::Registration,\n\
                           request_context_digest: context,\n\
                           transcript_digest: transcript,\n\
                       };\n\
                   }\n\
                   fn main() {}",
            code: "E0451",
            needles: &["request_kind", "transcript_digest"],
        },
    ];

    for case in cases {
        assert_compile_failure(&harness, case);
    }
}

#[test]
fn external_api_cannot_cross_blocked_lifecycle_boundaries() {
    let harness = UiHarness::create();
    let cases = [
        CompileFailure {
            name: "activation request derivation is internal",
            body: "use ed25519_yao_generator::ceremony_context::{CeremonyPublicRequestContextV1, CeremonyReplayNonce32V1, CeremonyRequestExpiryV1, CeremonyRequestIdV1};\n\
                   fn invalid(request: CeremonyPublicRequestContextV1, id: CeremonyRequestIdV1, expiry: CeremonyRequestExpiryV1) {\n\
                       let _ = request.derive_activation_control_request(id, CeremonyReplayNonce32V1::new([1; 32]), expiry);\n\
                   }\n\
                   fn main() {}",
            code: "E0599",
            needles: &["derive_activation_control_request"],
        },
        CompileFailure {
            name: "activation authorization construction is internal",
            body: "use ed25519_yao_generator::ceremony_context::*;\n\
                   fn invalid(request: &CeremonyPublicRequestContextV1, record: CeremonyAuthorizationRecordDigest32V1, origin: CeremonyActivationOriginV1, packages: CeremonyPackageSetDigest32V1, epoch: CeremonyActivationEpochV1) {\n\
                       let _ = CeremonyActivationAuthorizationV1::new(request, record, origin, packages, epoch);\n\
                   }\n\
                   fn main() {}",
            code: "E0624",
            needles: &["CeremonyActivationAuthorizationV1::new"],
        },
        CompileFailure {
            name: "activation request construction is internal",
            body: "use ed25519_yao_generator::lifecycle_domain::{ActivationControlFreshFieldsV1, ActivationRequestV1, PendingActivationPreStateV1};\n\
                   fn invalid(fresh: ActivationControlFreshFieldsV1, pending: PendingActivationPreStateV1) {\n\
                       let _ = ActivationRequestV1::new(fresh, pending);\n\
                   }\n\
                   fn main() {}",
            code: "E0624",
            needles: &["ActivationRequestV1::new"],
        },
        CompileFailure {
            name: "registered prestate construction is internal",
            body: "use ed25519_yao_generator::lifecycle_domain::RegisteredLifecyclePreStateV1;\n\
                   fn main() { let _ = RegisteredLifecyclePreStateV1::from_host_reference_store_projection; }",
            code: "E0624",
            needles: &["from_host_reference_store_projection"],
        },
        CompileFailure {
            name: "issuance authority types are internal",
            body: "use ed25519_yao_generator::lifecycle_domain::{\n\
                       RegistrationArtifactIssuanceV1, RefreshArtifactIssuanceV1,\n\
                       ExportArtifactIssuanceV1,\n\
                   };\n\
                   fn main() {}",
            code: "E0603",
            needles: &["RegistrationArtifactIssuanceV1", "ExportArtifactIssuanceV1"],
        },
        CompileFailure {
            name: "artifact session types are internal",
            body: "use ed25519_yao_generator::lifecycle_domain::{\n\
                       RegistrationArtifactSessionV1, RecoveryArtifactSessionV1,\n\
                       RefreshArtifactSessionV1, ExportArtifactSessionV1,\n\
                   };\n\
                   fn main() {}",
            code: "E0603",
            needles: &["RegistrationArtifactSessionV1", "ExportArtifactSessionV1"],
        },
        CompileFailure {
            name: "session entry is internal",
            body: "use ed25519_yao_generator::lifecycle_domain::RegistrationRequestV1;\n\
                   fn main() { let _ = RegistrationRequestV1::begin_host_reference_artifact_session; }",
            code: "E0624",
            needles: &["begin_host_reference_artifact_session"],
        },
        CompileFailure {
            name: "metadata consumption is internal",
            body: "use ed25519_yao_generator::lifecycle_domain::consume_activation_metadata_v1;\n\
                   fn main() { let _ = consume_activation_metadata_v1; }",
            code: "E0603",
            needles: &["consume_activation_metadata_v1"],
        },
        CompileFailure {
            name: "receipt evidence construction is internal",
            body: "use ed25519_yao_generator::lifecycle_domain::{ActivationReceiptEvidenceV1, ExportOutputCommitmentEvidenceV1};\n\
                   fn main() {\n\
                       let _ = ActivationReceiptEvidenceV1::new;\n\
                       let _ = ExportOutputCommitmentEvidenceV1::new;\n\
                   }",
            code: "E0624",
            needles: &[
                "ActivationReceiptEvidenceV1::new",
                "ExportOutputCommitmentEvidenceV1::new",
            ],
        },
        CompileFailure {
            name: "semantic receipt construction is internal",
            body: "use ed25519_yao_generator::semantic_artifacts::{ActivationOutputCommittedReceiptBodyV1, ExportOutputCommittedReceiptBodyV1, ExportReleasedReceiptBodyV1};\n\
                   fn main() {\n\
                       let _ = ActivationOutputCommittedReceiptBodyV1::new;\n\
                       let _ = ExportOutputCommittedReceiptBodyV1::new;\n\
                       let _ = ExportReleasedReceiptBodyV1::new;\n\
                   }",
            code: "E0624",
            needles: &[
                "ActivationOutputCommittedReceiptBodyV1::new",
                "ExportOutputCommittedReceiptBodyV1::new",
                "ExportReleasedReceiptBodyV1::new",
            ],
        },
        CompileFailure {
            name: "evaluation failure cause is internal",
            body: "use ed25519_yao_generator::lifecycle_domain::ArtifactEvaluationFailureV1;\n\
                   fn invalid(value: &ArtifactEvaluationFailureV1<()>) { let _ = value.source(); }\n\
                   fn main() {}",
            code: "E0624",
            needles: &["source"],
        },
        CompileFailure {
            name: "activation artifact commitment is internal",
            body: "use ed25519_yao_generator::semantic_artifacts::{\n\
                       ActivationPackageSetV1, CommittedActivationArtifactsV1,\n\
                       OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,\n\
                       OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,\n\
                   };\n\
                   fn invalid(packages: ActivationPackageSetV1, a: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1, b: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1) {\n\
                       let _ = CommittedActivationArtifactsV1::new(packages, a, b);\n\
                   }\n\
                   fn main() {}",
            code: "E0624",
            needles: &["CommittedActivationArtifactsV1::new"],
        },
        CompileFailure {
            name: "evaluator abort persistence construction is internal",
            body: "use ed25519_yao_generator::lifecycle_persistence::EvaluationAbortedPersistenceProjectionV1;\n\
                   fn main() { let _ = EvaluationAbortedPersistenceProjectionV1::from_recovery_failure; }",
            code: "E0624",
            needles: &["from_recovery_failure"],
        },
        CompileFailure {
            name: "export artifact commitment is internal",
            body: "use ed25519_yao_generator::semantic_artifacts::{\n\
                       OutputCommittedExportArtifactsV1, ExportPackageSetV1,\n\
                       OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1,\n\
                       OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1,\n\
                   };\n\
                   fn invalid(packages: ExportPackageSetV1, a: OpaqueHostReferenceDeriverAReceiptEvidenceDigest32V1, b: OpaqueHostReferenceDeriverBReceiptEvidenceDigest32V1) {\n\
                       let _ = OutputCommittedExportArtifactsV1::new(packages, a, b);\n\
                   }\n\
                   fn main() {}",
            code: "E0624",
            needles: &["OutputCommittedExportArtifactsV1::new"],
        },
    ];

    for case in cases {
        assert_compile_failure(&harness, case);
    }
}

#[test]
fn lifecycle_authority_types_are_move_only() {
    let harness = UiHarness::create();
    assert_compile_failure(
        &harness,
        CompileFailure {
            name: "public lifecycle authority types reject Clone",
            body: "use ed25519_yao_generator::lifecycle_domain::*;\n\
                   use ed25519_yao_generator::semantic_artifacts::{\n\
                       ActivationPackageSetV1, CommittedActivationArtifactsV1,\n\
                       OutputCommittedExportArtifactsV1, ExportPackageSetV1,\n\
                   };\n\
                   fn needs_clone<T: Clone>() {}\n\
                   fn main() {\n\
                       needs_clone::<RegistrationRequestV1>();\n\
                       needs_clone::<RecoveryRequestV1>();\n\
                       needs_clone::<RefreshRequestV1>();\n\
                       needs_clone::<ExportRequestV1>();\n\
                       needs_clone::<ActivationRequestV1>();\n\
                       needs_clone::<RegistrationPendingActivationV1>();\n\
                       needs_clone::<RecoveryPendingActivationV1>();\n\
                       needs_clone::<RefreshPendingActivationV1>();\n\
                       needs_clone::<PendingActivationPreStateV1>();\n\
                       needs_clone::<ActivationPackageSetV1>();\n\
                       needs_clone::<ExportPackageSetV1>();\n\
                       needs_clone::<CommittedActivationArtifactsV1>();\n\
                       needs_clone::<OutputCommittedExportArtifactsV1>();\n\
                   }",
            code: "E0277",
            needles: &[
                "RegistrationRequestV1",
                "RecoveryRequestV1",
                "RefreshRequestV1",
                "ExportRequestV1",
                "ActivationRequestV1",
                "RegistrationPendingActivationV1",
                "RecoveryPendingActivationV1",
                "RefreshPendingActivationV1",
                "PendingActivationPreStateV1",
                "ActivationPackageSetV1",
                "ExportPackageSetV1",
                "CommittedActivationArtifactsV1",
                "OutputCommittedExportArtifactsV1",
            ],
        },
    );
    assert_compile_failure(
        &harness,
        CompileFailure {
            name: "public lifecycle authority types reject Copy",
            body: "use ed25519_yao_generator::lifecycle_domain::{PendingActivationPreStateV1, RegistrationRequestV1};\n\
                   use ed25519_yao_generator::semantic_artifacts::{ActivationPackageSetV1, CommittedActivationArtifactsV1};\n\
                   fn needs_copy<T: Copy>() {}\n\
                   fn main() {\n\
                       needs_copy::<RegistrationRequestV1>();\n\
                       needs_copy::<PendingActivationPreStateV1>();\n\
                       needs_copy::<ActivationPackageSetV1>();\n\
                       needs_copy::<CommittedActivationArtifactsV1>();\n\
                   }",
            code: "E0277",
            needles: &[
                "RegistrationRequestV1",
                "PendingActivationPreStateV1",
                "ActivationPackageSetV1",
                "CommittedActivationArtifactsV1",
            ],
        },
    );
    assert_compile_failure(
        &harness,
        CompileFailure {
            name: "move-owned lifecycle values cannot be consumed twice",
            body: "use ed25519_yao_generator::lifecycle_domain::{PendingActivationPreStateV1, RegistrationRequestV1};\n\
                   use ed25519_yao_generator::semantic_artifacts::{ActivationPackageSetV1, CommittedActivationArtifactsV1};\n\
                   fn take_request(_: RegistrationRequestV1) {}\n\
                   fn take_pending(_: PendingActivationPreStateV1) {}\n\
                   fn take_packages(_: ActivationPackageSetV1) {}\n\
                   fn take_committed(_: CommittedActivationArtifactsV1) {}\n\
                   fn duplicate_request(value: RegistrationRequestV1) { take_request(value); take_request(value); }\n\
                   fn duplicate_pending(value: PendingActivationPreStateV1) { take_pending(value); take_pending(value); }\n\
                   fn duplicate_packages(value: ActivationPackageSetV1) { take_packages(value); take_packages(value); }\n\
                   fn duplicate_committed(value: CommittedActivationArtifactsV1) { take_committed(value); take_committed(value); }\n\
                   fn main() {}",
            code: "E0382",
            needles: &["use of moved value"],
        },
    );
}

#[test]
fn private_fields_seal_pending_package_commitment_and_persistence_states() {
    let harness = UiHarness::create();
    let cases = [
        CompileFailure {
            name: "pending state fields are private",
            body: "use ed25519_yao_generator::lifecycle_domain::{HostOnlyActivationOutputCommittedV1, RegistrationPendingActivationV1, RegistrationRequestV1};\n\
                   use ed25519_yao_generator::RegistrationCandidateStateV1;\n\
                   fn invalid(origin: RegistrationRequestV1, candidate: RegistrationCandidateStateV1, output: HostOnlyActivationOutputCommittedV1) {\n\
                       let _ = RegistrationPendingActivationV1 { origin, candidate, output };\n\
                   }\n\
                   fn main() {}",
            code: "E0451",
            needles: &["origin", "candidate", "output"],
        },
        CompileFailure {
            name: "package-set fields are private",
            body: "use ed25519_yao_generator::semantic_artifacts::ActivationPackageSetV1;\n\
                   fn main() {\n\
                       let _ = ActivationPackageSetV1 {\n\
                           context: todo!(),\n\
                           deriver_a_client: todo!(),\n\
                           deriver_b_client: todo!(),\n\
                           deriver_a_signing_worker: todo!(),\n\
                           deriver_b_signing_worker: todo!(),\n\
                           x_client: todo!(),\n\
                           x_server: todo!(),\n\
                           registered_public_key: todo!(),\n\
                       };\n\
                   }",
            code: "E0451",
            needles: &["context", "registered_public_key"],
        },
        CompileFailure {
            name: "committed artifact fields are private",
            body: "use ed25519_yao_generator::semantic_artifacts::{ActivationPackageSetV1, CommittedActivationArtifactsV1};\n\
                   fn invalid(packages: ActivationPackageSetV1) {\n\
                       let _ = CommittedActivationArtifactsV1 { binding: todo!(), packages, receipt: todo!() };\n\
                   }\n\
                   fn main() {}",
            code: "E0451",
            needles: &["binding", "receipt"],
        },
        CompileFailure {
            name: "persistence projection fields are private",
            body: "use ed25519_yao_generator::lifecycle_persistence::{\n\
                       AttemptRejectedActivationProjectionV1, MetadataConsumedActivationProjectionV1,\n\
                       OutputCommittedActivationProjectionV1, OutputCommittedArtifactIdentityV1,\n\
                   };\n\
                   fn main() {\n\
                       let _ = OutputCommittedArtifactIdentityV1 { origin: todo!(), ..todo!() };\n\
                       let _ = OutputCommittedActivationProjectionV1 { identity: todo!() };\n\
                       let _ = AttemptRejectedActivationProjectionV1 { retained: todo!(), abort: todo!() };\n\
                       let _ = MetadataConsumedActivationProjectionV1 {\n\
                           committed: todo!(),\n\
                           activation_request_context_digest: todo!(),\n\
                           activation_authorization_digest: todo!(),\n\
                           activation_transcript_digest: todo!(),\n\
                       };\n\
                   }",
            code: "E0451",
            needles: &["identity", "retained", "activation_authorization_digest"],
        },
        CompileFailure {
            name: "abort exposes no unreviewed diagnostics",
            body: "use ed25519_yao_generator::lifecycle_domain::UniformLifecycleAbortV1;\n\
                   fn invalid_authorization(value: UniformLifecycleAbortV1) { let _ = value.authorization_digest(); }\n\
                   fn invalid_role(value: UniformLifecycleAbortV1) { let _ = value.deriver_role(); }\n\
                   fn invalid_package(value: UniformLifecycleAbortV1) { let _ = value.package_set_digest(); }\n\
                   fn invalid_request_context(value: UniformLifecycleAbortV1) { let _ = value.request_context_digest(); }\n\
                   fn main() {}",
            code: "E0599",
            needles: &[
                "authorization_digest",
                "deriver_role",
                "package_set_digest",
                "request_context_digest",
            ],
        },
    ];

    for case in cases {
        assert_compile_failure(&harness, case);
    }
}

fn declaration_body<'a>(source: &'a str, declaration: &str) -> &'a str {
    let start = source
        .find(declaration)
        .unwrap_or_else(|| panic!("missing declaration `{declaration}`"));
    let open = source[start..]
        .find('{')
        .map(|offset| start + offset)
        .expect("declaration has a body");
    let mut depth = 0_u32;
    for (offset, character) in source[open..].char_indices() {
        match character {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &source[open + 1..open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("unterminated declaration `{declaration}`")
}

#[test]
fn lifecycle_sources_expose_only_profile_neutral_public_metadata() {
    let lifecycle = include_str!("../src/lifecycle_domain.rs");
    let persistence = include_str!("../src/lifecycle_persistence.rs");
    let semantic = include_str!("../src/semantic_artifacts.rs");

    for removed in [
        "from_synthetic_tag",
        "CommonLifecyclePublicInputV1",
        "SyntheticCommittedActivationManifestV1",
        "SyntheticCommittedActivationPackageRefsV1",
        "RegistrationSuccessV1",
        "RecoverySuccessV1",
        "RefreshSuccessV1",
        "ExportSuccessV1",
        "ReferenceLifecycleSuccessV1",
        "ActivatedRegisteredStateV1",
        "SigningWorkerActivatedOutputV1",
        "ConsumedActivationMetadataV1",
        "PromotedRegisteredMetadataStateV1",
        "FailedRegisteredArtifactAttemptV1",
    ] {
        assert!(
            !lifecycle.contains(removed),
            "removed lifecycle surface `{removed}` re-entered the module"
        );
    }

    for secret_field in [
        "seed:",
        "secret:",
        "share:",
        "scalar:",
        "plaintext:",
        "private_key:",
    ] {
        assert!(
            !lifecycle.contains(secret_field),
            "secret-bearing lifecycle field `{secret_field}` entered the module"
        );
        assert!(
            !persistence.contains(secret_field),
            "secret-bearing persistence field `{secret_field}` entered the module"
        );
    }

    for line in lifecycle.lines().chain(persistence.lines()) {
        let declaration = line.trim_start();
        if declaration.starts_with("pub struct ") || declaration.starts_with("pub enum ") {
            assert!(
                !declaration.contains("Activated"),
                "public state overclaims worker activation: `{declaration}`"
            );
            if declaration.contains("Consumed") {
                assert!(
                    declaration.contains("MetadataConsumed"),
                    "public consumed state lacks the metadata-only qualifier: `{declaration}`"
                );
            }
        }
    }

    let abort = declaration_body(lifecycle, "pub struct UniformLifecycleAbortV1");
    let fields = abort
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>();
    assert_eq!(
        fields,
        [
            "request_kind: CeremonyRequestKindV1,",
            "public_transcript_digest: crate::ceremony_context::CeremonyTranscriptDigest32V1,",
            "public_failure_code: RedactedFailureCodeV1,",
            "terminal: AbortedTerminalStateV1,",
        ]
    );

    let evaluation_failure = declaration_body(
        lifecycle,
        "pub struct ArtifactEvaluationFailureV1<Retained>",
    );
    assert!(evaluation_failure.contains("abort: UniformLifecycleAbortV1,"));
    assert!(evaluation_failure.contains("source: SemanticArtifactErrorV1,"));
    let evaluation_failure_impl = declaration_body(
        lifecycle,
        "impl<Retained> ArtifactEvaluationFailureV1<Retained>",
    );
    assert!(evaluation_failure_impl.contains("pub const fn abort("));
    assert!(evaluation_failure_impl.contains("pub(crate) const fn source("));
    let evaluation_failure_debug = declaration_body(
        lifecycle,
        "impl<Retained> fmt::Debug for ArtifactEvaluationFailureV1<Retained>",
    );
    assert!(evaluation_failure_debug.contains(".field(\"abort\""));
    assert!(!evaluation_failure_debug.contains(".field(\"source\""));

    for branch_type in [
        "FailedRegistrationArtifactAttemptV1",
        "FailedRecoveryArtifactAttemptV1",
        "FailedRefreshArtifactAttemptV1",
        "FailedExportArtifactAttemptV1",
    ] {
        assert!(
            lifecycle.contains(branch_type),
            "missing branch type `{branch_type}`"
        );
    }
    let recovery_session_entry = declaration_body(lifecycle, "impl RecoveryRequestV1");
    assert!(recovery_session_entry.contains("admission: AcceptedRecoveryAdmissionV1"));
    assert!(!recovery_session_entry.contains(
        "evaluation_evidence_digest: OpaqueHostReferenceEvaluationEvidenceDigest32V1"
    ));
    assert!(!lifecycle.contains("RecoveryArtifactIssuanceV1"));
    for constructor in [
        "from_registration_failure(",
        "from_recovery_failure(",
        "from_refresh_failure(",
        "from_export_failure(",
    ] {
        assert!(persistence.contains(constructor));
    }
    assert!(!persistence.contains("Option<RegisteredLifecyclePreStateV1>"));

    for session in [
        "RegistrationArtifactSessionV1",
        "RecoveryArtifactSessionV1",
        "RefreshArtifactSessionV1",
        "ExportArtifactSessionV1",
    ] {
        let implementation = declaration_body(lifecycle, &format!("impl {session}"));
        assert!(implementation
            .contains("let abort = UniformLifecycleAbortV1::rejected(&request.validated_dag());"));
        assert!(implementation.contains("Err(source) => Err(ArtifactEvaluationFailureV1"));
        assert!(implementation.contains("abort,"));
    }

    for session in [
        "RegistrationArtifactSessionV1",
        "RecoveryArtifactSessionV1",
        "RefreshArtifactSessionV1",
        "ExportArtifactSessionV1",
    ] {
        let marker = format!("pub(crate) struct {session}");
        let position = lifecycle
            .find(&marker)
            .unwrap_or_else(|| panic!("missing internal session `{session}`"));
        let prefix = &lifecycle[..position];
        let prior_lines = prefix.lines().rev().take(3).collect::<Vec<_>>().join("\n");
        assert!(
            !prior_lines.contains("Clone") && !prior_lines.contains("Copy"),
            "internal session `{session}` became duplicable"
        );
    }

    for constructor in [
        "pub(crate) const fn from_host_reference_store_projection(",
        "pub(crate) fn begin_host_reference_artifact_session(",
        "pub(crate) fn evaluate_and_commit_host_reference(",
        "pub(crate) fn consume_activation_metadata_v1(",
    ] {
        assert!(
            lifecycle.contains(constructor),
            "blocked lifecycle boundary changed visibility or disappeared: `{constructor}`"
        );
    }
    assert!(!lifecycle.contains("pub fn begin_host_reference_artifact_session("));
    assert!(!lifecycle.contains("pub fn evaluate_and_commit_host_reference("));
    assert!(!lifecycle.contains("pub fn consume_activation_metadata_v1("));

    for receipt in [
        "impl ActivationOutputCommittedReceiptBodyV1",
        "impl ExportOutputCommittedReceiptBodyV1",
        "impl ExportReleasedReceiptBodyV1",
    ] {
        let body = declaration_body(semantic, receipt);
        assert!(body.contains("fn new("));
        assert!(!body.contains("pub fn new(") && !body.contains("pub(crate) fn new("));
    }
}
