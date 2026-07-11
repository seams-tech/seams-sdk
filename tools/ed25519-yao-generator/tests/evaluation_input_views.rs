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
            "ed25519-yao-evaluation-input-views-ui-{}-{nonce}",
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
                "[package]\nname = \"evaluation-input-views-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
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
fn compile_fail_guards_enforce_input_custody_and_branch_coin_ownership() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::HostOnlyEvaluationInputStageV1;\n\
         fn main() { let _ = HostOnlyEvaluationInputStageV1::ExportEvaluationAccepted; }",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    for (body, code) in [
        (
            "use ed25519_yao_generator::HostOnlyRegistrationEvaluationInputViewSetV1;\n\
             fn invalid(views: HostOnlyRegistrationEvaluationInputViewSetV1) {\n\
                 let _a = views.observe_deriver_a_v1();\n\
                 let _b = views.observe_deriver_b_v1();\n\
             }\nfn main() {}",
            "E0382",
        ),
        (
            "use ed25519_yao_generator::HostOnlyRegistrationEvaluationInputViewSetV1;\n\
             fn invalid(views: HostOnlyRegistrationEvaluationInputViewSetV1) {\n\
                 let _ = views.observe_deriver_v1(true);\n\
             }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyRegistrationEvaluationInputViewSetV1;\n\
             fn invalid(views: &HostOnlyRegistrationEvaluationInputViewSetV1) { let _ = views.common(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::{HostOnlyDeriverAActivationEvaluationInputViewV1, HostOnlyRegistrationEvaluationInputCommonV1};\n\
             fn invalid(view: &HostOnlyDeriverAActivationEvaluationInputViewV1<HostOnlyRegistrationEvaluationInputCommonV1>) { let _ = view.deriver_b(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyDeriverAExportEvaluationInputViewV1;\n\
             fn invalid(view: &HostOnlyDeriverAExportEvaluationInputViewV1) { let _ = view.tau_client(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::{HostOnlyActivationContinuationInputCommonV1, HostOnlyDeriverAEmptyEvaluationInputViewV1};\n\
             fn invalid(view: &HostOnlyDeriverAEmptyEvaluationInputViewV1<HostOnlyActivationContinuationInputCommonV1>) { let _ = view.contribution(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::{HostOnlyClientEmptyEvaluationInputViewV1, HostOnlyRegistrationEvaluationInputCommonV1};\n\
             fn invalid(view: &HostOnlyClientEmptyEvaluationInputViewV1<HostOnlyRegistrationEvaluationInputCommonV1>) { let _ = view.contribution(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyRegistrationEvaluationInputViewSetV1;\n\
             fn invalid(views: HostOnlyRegistrationEvaluationInputViewSetV1) { let _ = views.clone(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::{HostOnlyDeriverAActivationEvaluationInputViewV1, HostOnlyRegistrationEvaluationInputCommonV1};\n\
             fn invalid(view: HostOnlyDeriverAActivationEvaluationInputViewV1<HostOnlyRegistrationEvaluationInputCommonV1>) { let _ = format!(\"{view:?}\"); }\n\
             fn main() {}",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::HostOnlyExportIdealCoinV1;\n\
             fn invalid(coin: HostOnlyExportIdealCoinV1) { let _ = coin.clone(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyRegistrationIdealCoinsV1;\n\
             use serde::Serialize;\n\
             fn require_serialize<T: Serialize>() {}\n\
             fn main() { require_serialize::<HostOnlyRegistrationIdealCoinsV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::{HostOnlyRecoveryIdealCoinsV1, HostOnlyRegistrationIdealCoinsV1};\n\
             fn require_recovery(_: HostOnlyRecoveryIdealCoinsV1) {}\n\
             fn invalid(coins: HostOnlyRegistrationIdealCoinsV1) { require_recovery(coins); }\n\
             fn main() {}",
            "E0308",
        ),
        (
            "use ed25519_yao_generator::{evaluate_host_only_registration_output_sharing_v1, HostOnlyActivationOutputCoinsV1, HostOnlyPreparedRegistrationReferenceV1};\n\
             fn invalid(prepared: HostOnlyPreparedRegistrationReferenceV1, coins: HostOnlyActivationOutputCoinsV1) {\n\
                 let _ = evaluate_host_only_registration_output_sharing_v1(prepared, coins);\n\
             }\nfn main() {}",
            "E0308",
        ),
        (
            "use ed25519_yao_generator::{build_host_only_registration_evaluation_input_view_set_v1, HostOnlyPreparedRecoveryReferenceV1};\n\
             use ed25519_yao_generator::lifecycle_domain::RegistrationRequestV1;\n\
             use ed25519_yao_generator::provenance::RoleInputProvenancePairV1;\n\
             fn invalid(request: &RegistrationRequestV1, provenance: &RoleInputProvenancePairV1, prepared: &HostOnlyPreparedRecoveryReferenceV1) {\n\
                 let _ = build_host_only_registration_evaluation_input_view_set_v1(request, provenance, prepared);\n\
             }\nfn main() {}",
            "E0308",
        ),
        (
            "use ed25519_yao_generator::build_host_only_activation_continuation_input_view_set_v1;\n\
             use ed25519_yao_generator::lifecycle_domain::ActivationRequestV1;\n\
             fn invalid(request: &ActivationRequestV1) { let _ = build_host_only_activation_continuation_input_view_set_v1(request); }\n\
             fn main() {}",
            "E0061",
        ),
        (
            "use ed25519_yao_generator::{HostOnlyRegistrationEvaluationInputCommonV1, HostOnlyRegistrationEvaluationInputViewSetV1};\n\
             use ed25519_yao_generator::{DeriverAContribution, DeriverBContribution};\n\
             fn invalid(common: HostOnlyRegistrationEvaluationInputCommonV1, deriver_a: DeriverAContribution, deriver_b: DeriverBContribution) {\n\
                 let _ = HostOnlyRegistrationEvaluationInputViewSetV1 { common, deriver_a, deriver_b };\n\
             }\nfn main() {}",
            "E0451",
        ),
    ] {
        assert_compile_failure(&harness, body, code);
    }
}

#[test]
fn source_guards_keep_views_host_only_static_and_coin_free() {
    let views = include_str!("../src/evaluation_input_views.rs");
    let core = views
        .split("#[cfg(test)]")
        .next()
        .expect("production evaluation-input source");
    for forbidden in [
        "serde",
        "Serialize",
        "Deserialize",
        "HashMap",
        "Ciphertext",
        "wasm_bindgen",
        "cloudflare",
        "observe_deriver_v1",
        "StaticDeriverRole",
        "HostOnlyActivationOutputCoinsV1",
        "HostOnlySeedOutputCoinV1",
    ] {
        assert!(
            !core.contains(forbidden),
            "blocked surface `{forbidden}` entered evaluation-input views"
        );
    }

    let randomness = include_str!("../src/ideal_function_randomness.rs");
    for forbidden in [
        "#[derive",
        "serde",
        "Serialize",
        "Deserialize",
        "pub fn into_",
        "pub const fn into_",
    ] {
        assert!(
            !randomness.contains(forbidden),
            "ideal-function randomness gained blocked surface `{forbidden}`"
        );
    }
    for wrapper in [
        "HostOnlyRegistrationIdealCoinsV1",
        "HostOnlyActivationNoIdealCoinsV1",
        "HostOnlyRecoveryIdealCoinsV1",
        "HostOnlyRefreshIdealCoinsV1",
        "HostOnlyExportIdealCoinV1",
    ] {
        assert!(
            randomness.contains(&format!("pub struct {wrapper}")),
            "missing branch-owned ideal wrapper {wrapper}"
        );
    }
}
