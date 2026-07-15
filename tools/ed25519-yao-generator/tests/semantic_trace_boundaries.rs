use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_yao_generator::{
    HOST_ONLY_CORRUPTION_GAME_INTERFACE_SHAPES_V1, HOST_ONLY_CORRUPTION_KINDS_V1,
    HOST_ONLY_SEMANTIC_DELIVERY_STATES_V1, HOST_ONLY_SEMANTIC_FRAME_CLASSES_V1,
    HOST_ONLY_SEMANTIC_PRIVATE_VALUE_CLASSES_V1, HOST_ONLY_SEMANTIC_PUBLIC_EVENTS_V1,
    HOST_ONLY_SEMANTIC_ROLES_V1,
};

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
            "ed25519-yao-semantic-trace-ui-{}-{nonce}",
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
                "[package]\nname = \"semantic-trace-ui\"\nversion = \"0.0.0\"\nedition = \"2021\"\n\
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
            .expect("run UI cargo check")
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
fn compile_fail_guards_keep_trace_construction_static_and_closed() {
    let harness = UiHarness::create();
    let control = harness.check(
        "use ed25519_yao_generator::HostOnlySemanticDeliveryStateV1;\n\
         fn main() { let _ = HostOnlySemanticDeliveryStateV1::ExactRedelivery; }",
    );
    assert!(
        control.status.success(),
        "UI control failed:\n{}",
        String::from_utf8_lossy(&control.stderr)
    );

    for (source, code) in [
        (
            "use ed25519_yao_generator::{HostOnlySemanticFrameDirectionV1, HostOnlySemanticFrameEndpointV1};\n\
             fn main() { let _ = HostOnlySemanticFrameDirectionV1 { sender: HostOnlySemanticFrameEndpointV1::Client, receiver: HostOnlySemanticFrameEndpointV1::Router }; }",
            "E0451",
        ),
        (
            "use ed25519_yao_generator::HostOnlySemanticDeliveryViewSetV1;\n\
             fn invalid(view: HostOnlySemanticDeliveryViewSetV1) { let _ = view.clone(); }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlySemanticDeliveryViewSetV1;\n\
             fn invalid(view: HostOnlySemanticDeliveryViewSetV1) { let _ = view.observe_role_v1(true); }\nfn main() {}",
            "E0599",
        ),
        (
            "use ed25519_yao_generator::HostOnlySemanticDeliveryViewSetV1; use serde::Serialize;\n\
             fn require_serialize<T: Serialize>() {}\n\
             fn main() { require_serialize::<HostOnlySemanticDeliveryViewSetV1>(); }",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::HostOnlyCorruptionMarkerV1;\n\
             struct Custom;\nimpl HostOnlyCorruptionMarkerV1 for Custom { const KIND: ed25519_yao_generator::HostOnlyCorruptionKindV1 = ed25519_yao_generator::HostOnlyCorruptionKindV1::RouterOnly; }\nfn main() {}",
            "E0277",
        ),
        (
            "use ed25519_yao_generator::RouterAndDeriverAAndDeriverBV1;\nfn main() {}",
            "E0432",
        ),
        (
            "use ed25519_yao_generator::semantic_delivery_views::build_export_success_semantic_trace_v1;\nfn main() { let _ = build_export_success_semantic_trace_v1; }",
            "E0603",
        ),
    ] {
        assert_compile_failure(&harness, source, code);
    }
}

#[test]
fn source_guards_exclude_runtime_and_serialization_surfaces() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    for file in [
        "src/semantic_frame_classes.rs",
        "src/semantic_delivery_views.rs",
        "src/corruption_game_interfaces.rs",
    ] {
        let source = fs::read_to_string(manifest.join(file)).expect("read semantic core source");
        let core = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in [
            "serde::",
            "derive(Serialize",
            "derive(Deserialize",
            "HashMap",
            "frame_bytes",
            "durable_record",
            "sequence_number",
            "runtime_role",
            "observe_role_v1",
        ] {
            assert!(
                !core.contains(forbidden),
                "blocked surface `{forbidden}` entered {file}"
            );
        }
    }
}

#[test]
fn frozen_orders_export_exact_authoritative_labels() {
    assert_eq!(HOST_ONLY_SEMANTIC_FRAME_CLASSES_V1.len(), 11);
    assert_eq!(HOST_ONLY_SEMANTIC_DELIVERY_STATES_V1.len(), 11);
    assert_eq!(HOST_ONLY_SEMANTIC_ROLES_V1.len(), 7);
    assert_eq!(HOST_ONLY_CORRUPTION_KINDS_V1.len(), 10);

    let public: Vec<_> = HOST_ONLY_SEMANTIC_PUBLIC_EVENTS_V1
        .iter()
        .map(|value| value.as_str())
        .collect();
    assert_eq!(
        public,
        [
            "ceremony_public",
            "evaluation_inputs_accepted_public",
            "peer_progress_public",
            "output_commitment_public",
            "uniform_abort_public",
            "activation_metadata_public",
            "recipient_delivery_uncertainty_public",
            "activation_recipient_release_public",
            "export_release_public",
            "exact_redelivery_identity_public",
            "signing_worker_activation_receipt_public",
        ]
    );

    let private: Vec<_> = HOST_ONLY_SEMANTIC_PRIVATE_VALUE_CLASSES_V1
        .iter()
        .map(|value| value.as_str())
        .collect();
    assert_eq!(
        private,
        [
            "client_role_scoped_inputs",
            "deriver_a_activation_inputs",
            "deriver_b_activation_inputs",
            "deriver_a_export_inputs",
            "deriver_b_export_inputs",
            "deriver_a_peer_local_state",
            "deriver_b_peer_local_state",
            "deriver_a_protocol_randomness",
            "deriver_b_protocol_randomness",
            "deriver_a_activation_output_shares",
            "deriver_b_activation_output_shares",
            "deriver_a_export_seed_share",
            "deriver_b_export_seed_share",
            "client_activation_scalar",
            "signing_worker_activation_authority",
            "client_export_seed",
            "signing_worker_activated_scalar",
            "router_opaque_role_envelope_identities",
            "router_opaque_output_package_identities",
            "router_opaque_recipient_delivery_identities",
            "router_lifecycle_control_knowledge",
            "router_receipt_control_knowledge",
        ]
    );

    let frames: Vec<_> = HOST_ONLY_SEMANTIC_FRAME_CLASSES_V1
        .iter()
        .map(|value| value.as_str())
        .collect();
    assert_eq!(frames[0], "client_to_router_evaluation_request");
    assert_eq!(frames[10], "signing_worker_to_router_activation_receipt");

    let states: Vec<_> = HOST_ONLY_SEMANTIC_DELIVERY_STATES_V1
        .iter()
        .map(|value| value.as_str())
        .collect();
    assert_eq!(states[0], "ceremony_admitted");
    assert_eq!(states[10], "exact_redelivery");

    let roles: Vec<_> = HOST_ONLY_SEMANTIC_ROLES_V1
        .iter()
        .map(|value| value.as_str())
        .collect();
    assert_eq!(
        roles,
        [
            "deriver_a",
            "deriver_b",
            "client",
            "signing_worker",
            "router",
            "observer",
            "diagnostics",
        ]
    );

    let corruptions: Vec<_> = HOST_ONLY_CORRUPTION_KINDS_V1
        .iter()
        .map(|value| value.as_str())
        .collect();
    assert_eq!(corruptions[0], "honest_execution");
    assert_eq!(corruptions[9], "router_and_active_deriver_b");

    let interfaces: Vec<_> = HOST_ONLY_CORRUPTION_GAME_INTERFACE_SHAPES_V1
        .iter()
        .map(|value| value.as_str())
        .collect();
    assert_eq!(
        interfaces,
        [
            "corrupted_view_input",
            "selected_profile_real_execution",
            "selected_profile_ideal_simulator",
            "selected_profile_security_experiment",
        ]
    );
}
