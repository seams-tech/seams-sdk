use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct UiHarness {
    directory: PathBuf,
}

impl UiHarness {
    fn create() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must follow Unix epoch")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ed25519-yao-output-party-views-ui-{}-{nonce}",
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
                "[package]\nname = \"output-party-views-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
                 [dependencies]\ned25519-yao-generator = {{ path = \"{dependency_path}\" }}\n\
                 serde = {{ version = \"1\", features = [\"derive\"] }}\n"
            ),
        )
        .expect("write UI harness manifest");
        Self { directory }
    }

    fn check(&self, body: &str) -> std::process::Output {
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

fn assert_compile_failure(harness: &UiHarness, body: &str, code: &str) {
    let output = harness.check(body);
    assert!(!output.status.success(), "UI case unexpectedly compiled");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(code),
        "UI case failed without {code}:\n{stderr}"
    );
}

#[test]
fn compile_fail_guards_enforce_consuming_role_and_output_family_boundaries() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::output_party_views::HostOnlyOutputPartyViewStageV1;\n\
         fn main() { let _ = HostOnlyOutputPartyViewStageV1::ExportReleased; }",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    for (body, code) in [
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyActivationPackagePreparedPartyViewSetV1;\n\
             fn invalid(views: HostOnlyActivationPackagePreparedPartyViewSetV1) {\n\
                 let _a = views.observe_deriver_a_v1();\n\
                 let _b = views.observe_deriver_b_v1();\n\
             }\nfn main() {}",
            "E0382",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyActivationPackagePreparedPartyViewSetV1;\n\
             fn invalid(views: HostOnlyActivationPackagePreparedPartyViewSetV1) {\n\
                 let _ = views.observe_deriver_v1(true);\n\
             }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyActivationPackagePreparedPartyViewSetV1;\n\
             fn invalid(views: HostOnlyActivationPackagePreparedPartyViewSetV1) { let _ = views.clone(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyDeriverAActivationOutputPartyViewV1;\n\
             fn invalid(view: HostOnlyDeriverAActivationOutputPartyViewV1) { let _ = view.clone(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyDeriverAActivationOutputPartyViewV1;\n\
             fn invalid(view: HostOnlyDeriverAActivationOutputPartyViewV1) { let _ = format!(\"{view:?}\"); }\n\
             fn main() {}",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyActivationPackagePreparedPartyViewSetV1;\n\
             use serde::Serialize;\n\
             fn require_serialize<T: Serialize>() {}\n\
             fn main() { require_serialize::<HostOnlyActivationPackagePreparedPartyViewSetV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyClientExportOutputPartyViewV1;\n\
             use serde::Serialize;\n\
             fn require_serialize<T: Serialize>() {}\n\
             fn main() { require_serialize::<HostOnlyClientExportOutputPartyViewV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyDeriverAActivationOutputPartyViewV1;\n\
             fn invalid(view: &HostOnlyDeriverAActivationOutputPartyViewV1) { let _ = view.deriver_b(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyDeriverBActivationOutputPartyViewV1;\n\
             fn invalid(view: &HostOnlyDeriverBActivationOutputPartyViewV1) { let _ = view.joined_output(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyClientActivationOutputPartyViewV1;\n\
             fn invalid(view: &HostOnlyClientActivationOutputPartyViewV1) { let _ = view.x_client_base(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlySigningWorkerActivationPackagePreparedPartyViewV1;\n\
             fn invalid(view: &HostOnlySigningWorkerActivationPackagePreparedPartyViewV1) { let _ = view.x_server_base(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyClientActivationMetadataConsumedPartyViewV1;\n\
             fn invalid(view: &HostOnlyClientActivationMetadataConsumedPartyViewV1) { let _ = view.x_client_base(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyClientExportOutputPartyViewV1;\n\
             fn invalid(view: &HostOnlyClientExportOutputPartyViewV1) { let _ = view.x_client_base(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlySigningWorkerExportReleasedPartyViewV1;\n\
             fn invalid(view: &HostOnlySigningWorkerExportReleasedPartyViewV1) { let _ = view.seed(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::{HostOnlyActivationPackagePreparedPartyViewSetV1, HostOnlyCommonOutputPublicLeakageV1};\n\
             use ed25519_yao_generator::{HostOnlyDeriverAActivationOutputSharesV1, HostOnlyDeriverBActivationOutputSharesV1};\n\
             fn invalid(common: HostOnlyCommonOutputPublicLeakageV1, deriver_a: HostOnlyDeriverAActivationOutputSharesV1, deriver_b: HostOnlyDeriverBActivationOutputSharesV1) {\n\
                 let _ = HostOnlyActivationPackagePreparedPartyViewSetV1 { common, deriver_a, deriver_b };\n\
             }\nfn main() {}",
            "E0451",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyEvaluatorAbortPartyViewSetV1;\n\
             fn invalid(views: HostOnlyEvaluatorAbortPartyViewSetV1) {\n\
                 let _a = views.observe_deriver_a_v1();\n\
                 let _b = views.observe_deriver_b_v1();\n\
             }\nfn main() {}",
            "E0382",
        ),
        (
            "use ed25519_yao_generator::output_party_views::HostOnlyClientEvaluatorAbortPartyViewV1;\n\
             fn invalid(view: &HostOnlyClientEvaluatorAbortPartyViewV1) { let _ = view.seed(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::output_party_views::build_host_only_evaluator_abort_party_view_set_v1;\n\
             fn main() { let _ = build_host_only_evaluator_abort_party_view_set_v1; }",
            "E0603",
        ),
        (
            "use ed25519_yao_generator::output_party_views::build_host_only_activation_package_prepared_party_view_set_v1;\n\
             fn main() { let _ = build_host_only_activation_package_prepared_party_view_set_v1; }",
            "E0603",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::HostOnlyActivationOutputCommittedV1;\n\
             fn invalid(output: HostOnlyActivationOutputCommittedV1) { let _ = output.clone(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::lifecycle_domain::HostOnlyExportOutputCommittedV1;\n\
             fn invalid(committed: HostOnlyExportOutputCommittedV1) { let _ = committed.clone(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::export_delivery::HostOnlyExportReleasedV1;\n\
             use serde::Serialize;\n\
             fn require_serialize<T: Serialize>() {}\n\
             fn main() { require_serialize::<HostOnlyExportReleasedV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::export_delivery::HostOnlyExportClientReleaseEvidenceV1;\n\
             fn invalid() { let _ = HostOnlyExportClientReleaseEvidenceV1 {}; }\n\
             fn main() {}",
            "private fields",
        ),
        (
            "use ed25519_yao_generator::output_party_views::build_host_only_export_released_party_view_set_v1;\n\
             fn main() { let _ = build_host_only_export_released_party_view_set_v1; }",
            "E0603",
        ),
    ] {
        assert_compile_failure(&harness, body, code);
    }
}

#[test]
fn source_guards_keep_the_core_nonserializable_and_profile_neutral() {
    let source = include_str!("../src/output_party_views.rs");
    let core = source
        .split("#[cfg(test)]")
        .next()
        .expect("production core source");

    for forbidden in [
        "serde",
        "Serialize",
        "Deserialize",
        "Vec<u8>",
        "HashMap",
        "Ciphertext",
        "wire::",
        "wasm_bindgen",
        "cloudflare",
        "StaticSingleDeriverObservation",
        "StaticDeriverRole",
    ] {
        assert!(
            !core.contains(forbidden),
            "blocked surface `{forbidden}` entered output party views"
        );
    }

    for secret_type in [
        "HostOnlyActivationPackagePreparedPartyViewSetV1",
        "HostOnlyExportReleasedPartyViewSetV1",
        "HostOnlyDeriverAActivationOutputPartyViewV1",
        "HostOnlyDeriverBActivationOutputPartyViewV1",
        "HostOnlyClientActivationOutputPartyViewV1",
        "HostOnlyDeriverAExportOutputPartyViewV1",
        "HostOnlyDeriverBExportOutputPartyViewV1",
        "HostOnlyClientExportOutputPartyViewV1",
    ] {
        let declaration = format!("pub struct {secret_type}");
        let offset = core.find(&declaration).expect("secret-bearing declaration");
        let prefix = &core[..offset];
        let previous = prefix
            .lines()
            .rev()
            .find(|line| !line.trim().is_empty())
            .expect("declaration predecessor")
            .trim();
        assert!(
            !previous.starts_with("#[derive"),
            "secret-bearing type {secret_type} gained derived traits"
        );
    }

    let abort_macro = core
        .split("macro_rules! define_evaluator_abort_party_view")
        .nth(1)
        .expect("evaluator-abort role-view macro");
    let abort_macro = abort_macro
        .split("define_evaluator_abort_party_view!(")
        .next()
        .expect("evaluator-abort role-view macro body");
    assert!(abort_macro.contains("common: HostOnlyPublicAbortViewV1,"));
    for forbidden in ["shares:", "seed:", "scalar:", "source:", "frame:", "blame:"] {
        assert!(
            !abort_macro.contains(forbidden),
            "evaluator-abort role-view macro contains `{forbidden}`"
        );
    }

    for abort_view in [
        "HostOnlyDeriverAEvaluatorAbortPartyViewV1",
        "HostOnlyDeriverBEvaluatorAbortPartyViewV1",
        "HostOnlyClientEvaluatorAbortPartyViewV1",
        "HostOnlySigningWorkerEvaluatorAbortPartyViewV1",
        "HostOnlyRouterEvaluatorAbortPartyViewV1",
        "HostOnlyObserverEvaluatorAbortPartyViewV1",
        "HostOnlyDiagnosticsEvaluatorAbortPartyViewV1",
    ] {
        assert!(
            core.contains(abort_view),
            "missing abort view `{abort_view}`"
        );
    }

    let export_builder = core
        .split("fn build_host_only_export_released_party_view_set_v1(")
        .nth(1)
        .expect("export released party-view builder");
    let export_builder_signature = export_builder
        .split('{')
        .next()
        .expect("export released party-view builder signature");
    assert!(export_builder_signature.contains("released: HostOnlyExportReleasedV1"));
    for forbidden in ["shares:", "artifacts:", "seed:"] {
        assert!(
            !export_builder_signature.contains(forbidden),
            "export release builder accepts substitutable `{forbidden}` input"
        );
    }

    let activation_builder = core
        .split("fn build_host_only_activation_package_prepared_party_view_set_v1(")
        .nth(1)
        .expect("activation package-prepared party-view builder");
    let activation_builder_signature = activation_builder
        .split('{')
        .next()
        .expect("activation package-prepared party-view builder signature");
    assert!(activation_builder_signature.contains("pending: PendingActivationPreStateV1"));
    for forbidden in ["shares:", "artifacts:", "packages:"] {
        assert!(
            !activation_builder_signature.contains(forbidden),
            "activation party-view builder accepts substitutable `{forbidden}` input"
        );
    }
}
