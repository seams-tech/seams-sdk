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
            "ed25519-yao-joint-refresh-delta-ui-{}-{nonce}",
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
                "[package]\nname = \"joint-refresh-delta-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
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
fn compile_fail_guards_seal_joint_delta_derivation_and_move_ownership() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::{HostOnlyDeriverARefreshDeltaContributionV1, HostOnlyDeriverBRefreshDeltaContributionV1, HostOnlyJointRefreshDeltaCoinsV1};\n\
         fn main() {\n\
             let a = HostOnlyDeriverARefreshDeltaContributionV1::from_host_only_fixture([1; 32], [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();\n\
             let b = HostOnlyDeriverBRefreshDeltaContributionV1::from_host_only_fixture([2; 32], [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();\n\
             let _ = HostOnlyJointRefreshDeltaCoinsV1::new(a, b);\n\
         }",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    for (body, code) in [
        (
            "use ed25519_yao_generator::HostOnlyJointRefreshDeltaV1; fn main() {}",
            "E0432",
        ),
        (
            "use ed25519_yao_generator::derive_host_only_joint_refresh_delta_v1; fn main() {}",
            "E0432",
        ),
        (
            "use ed25519_yao_generator::apply_host_only_joint_refresh_delta_v1; fn main() {}",
            "E0432",
        ),
        (
            "use ed25519_yao_generator::HostOnlyDeriverARefreshDeltaContributionV1;\n\
             fn invalid(value: HostOnlyDeriverARefreshDeltaContributionV1) { let _ = value.clone(); } fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyJointRefreshDeltaCoinsV1;\n\
             fn invalid(value: HostOnlyJointRefreshDeltaCoinsV1) { let _ = value.clone(); } fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlyJointRefreshDeltaCoinsV1; use serde::Serialize;\n\
             fn require_serialize<T: Serialize>() {} fn main() { require_serialize::<HostOnlyJointRefreshDeltaCoinsV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::HostOnlyJointRefreshDeltaCoinsV1;\n\
             fn invalid(value: HostOnlyJointRefreshDeltaCoinsV1) { let _ = value.deriver_a; } fn main() {}",
            "E0616",
        ),
        (
            "use ed25519_yao_generator::{HostOnlyDeriverARefreshDeltaContributionV1, HostOnlyDeriverBRefreshDeltaContributionV1, HostOnlyJointRefreshDeltaCoinsV1};\n\
             fn invalid(a: HostOnlyDeriverARefreshDeltaContributionV1, b: HostOnlyDeriverBRefreshDeltaContributionV1) {\n\
                 let _coins = HostOnlyJointRefreshDeltaCoinsV1::new(a, b); let _ = a.delta_y_fixture_bytes();\n\
             } fn main() {}",
            "E0382",
        ),
    ] {
        assert_compile_failure(&harness, body, code);
    }
}

#[test]
fn root_exports_exclude_combined_delta_construction_and_application() {
    let root = include_str!("../src/lib.rs");
    let lifecycle = include_str!("../src/lifecycle_reference.rs");
    let joint = include_str!("../src/joint_refresh_delta.rs");

    assert!(!root.contains("HostOnlyJointRefreshDeltaV1,"));
    assert!(!root.contains("derive_host_only_joint_refresh_delta_v1,"));
    assert!(!root.contains("apply_host_only_joint_refresh_delta_v1,"));
    assert!(!lifecycle.contains("pub fn apply_host_only_joint_refresh_delta_v1"));
    assert!(joint.contains("pub(crate) struct HostOnlyJointRefreshDeltaV1"));
    assert!(joint.contains("pub(crate) fn derive_host_only_joint_refresh_delta_v1"));
}
