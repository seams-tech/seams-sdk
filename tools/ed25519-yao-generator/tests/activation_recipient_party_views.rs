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
            .expect("system clock")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "ed25519-yao-activation-recipient-party-views-ui-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(directory.join("src")).expect("create UI harness");
        let manifest_directory = Path::new(env!("CARGO_MANIFEST_DIR"))
            .canonicalize()
            .expect("generator path");
        let dependency_path = manifest_directory.to_string_lossy().replace('\\', "\\\\");
        fs::write(
            directory.join("Cargo.toml"),
            format!(
                "[package]\nname = \"activation-recipient-party-views-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
                 [dependencies]\ned25519-yao-generator = {{ path = \"{dependency_path}\" }}\n\
                 serde = {{ version = \"1\", features = [\"derive\"] }}\n"
            ),
        )
        .expect("write UI manifest");
        Self { directory }
    }

    fn check(&self, source: &str) -> std::process::Output {
        fs::write(self.directory.join("src/main.rs"), source).expect("write UI source");
        Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args(["check", "--quiet", "--offline"])
            .current_dir(&self.directory)
            .env("CARGO_TARGET_DIR", self.directory.join("target"))
            .output()
            .expect("run UI check")
    }
}

impl Drop for UiHarness {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.directory);
    }
}

fn assert_compile_failure(harness: &UiHarness, source: &str, code: &str) {
    let output = harness.check(source);
    assert!(!output.status.success(), "UI case unexpectedly compiled");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(code),
        "UI case failed without {code}:\n{stderr}"
    );
}

#[test]
fn compile_fail_guards_enforce_move_only_disjoint_recipient_custody() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::activation_recipient_party_views::HostOnlyActivationRecipientPartyViewStageV1;\n\
         fn main() { let _ = HostOnlyActivationRecipientPartyViewStageV1::RecipientsReleased; }",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    for (source, code) in [
        (
            "use ed25519_yao_generator::activation_recipient_party_views::HostOnlyActivationRecipientsReleasedPartyViewSetV1;\n\
             fn invalid(views: HostOnlyActivationRecipientsReleasedPartyViewSetV1) {\n\
               let _client = views.observe_client_v1();\n\
               let _worker = views.observe_signing_worker_v1();\n\
             }\nfn main() {}",
            "E0382",
        ),
        (
            "use ed25519_yao_generator::activation_recipient_party_views::HostOnlySigningWorkerActivatedPartyViewSetV1;\n\
             fn invalid(views: HostOnlySigningWorkerActivatedPartyViewSetV1) { let _ = views.clone(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::activation_recipient_party_views::HostOnlySigningWorkerActivatedPartyViewSetV1;\n\
             use serde::Serialize;\nfn require_serialize<T: Serialize>() {}\n\
             fn main() { require_serialize::<HostOnlySigningWorkerActivatedPartyViewSetV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::activation_recipient_party_views::HostOnlySigningWorkerActivatedPartyViewV1;\n\
             fn invalid(view: &HostOnlySigningWorkerActivatedPartyViewV1) { let _ = view.x_server_base(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::activation_recipient_party_views::HostOnlySigningWorkerActivationRecipientsReleasedPartyViewV1;\n\
             fn invalid(view: &HostOnlySigningWorkerActivationRecipientsReleasedPartyViewV1) { let _ = view.retained_shares(); }\n\
             fn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::activation_recipient_party_views::build_host_only_signing_worker_activated_party_view_set_v1;\n\
             fn main() { let _ = build_host_only_signing_worker_activated_party_view_set_v1; }",
            "E0603",
        ),
    ] {
        assert_compile_failure(&harness, source, code);
    }
}

#[test]
fn source_guards_exclude_serializable_frames_durable_records_and_worker_scalar_accessors() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let views = fs::read_to_string(manifest.join("src/activation_recipient_party_views.rs"))
        .expect("read recipient views");
    let activation = fs::read_to_string(manifest.join("src/signing_worker_activation.rs"))
        .expect("read worker activation");
    assert!(!views.contains("serde::"));
    assert!(!views.contains("derive(Serialize"));
    assert!(!views.contains("frame_bytes"));
    assert!(!views.contains("durable_record"));
    assert!(!views.contains("ciphertext"));
    assert!(views.contains(
        "pub(crate) fn build_host_only_activation_recipients_released_party_view_set_v1"
    ));
    assert!(
        views.contains("pub(crate) fn build_host_only_signing_worker_activated_party_view_set_v1")
    );
    assert!(!activation.contains("pub const fn x_server_base"));
    assert!(!activation.contains("pub fn x_server_base"));
    assert!(activation.contains("pub(crate) fn host_fixture_opened_signing_worker_shares_v1"));
}
