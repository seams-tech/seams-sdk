use std::{env, fs, path::PathBuf};

use ed25519_yao_generator::compile_lane_materialization_v1;
use serde::Serialize;

const UPDATE_ENV: &str = "UPDATE_ED25519_YAO_LANE_MATERIALIZATION_VECTOR";

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LaneMaterializationVectorV1 {
    schema: &'static str,
    circuit_id: &'static str,
    input_schema: &'static str,
    output_schema: &'static str,
    circuit_digest_hex: String,
    schedule_digest_hex: String,
    cases: Vec<LaneMaterializationCaseV1>,
}

#[derive(Serialize)]
#[serde(untagged)]
enum LaneMaterializationCaseV1 {
    Relation {
        name: &'static str,
        source: &'static str,
        #[serde(rename = "privateOutputSharing")]
        private_output_sharing: &'static str,
        offset: &'static str,
        #[serde(rename = "expectedRelation")]
        expected_relation: &'static str,
    },
    Rejection {
        name: &'static str,
        #[serde(rename = "expectedOutcome")]
        expected_outcome: &'static str,
    },
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("vectors/ed25519-yao-lane-materialization-v1.json")
}

fn canonical_fixture() -> String {
    let circuit = compile_lane_materialization_v1();
    let vector = LaneMaterializationVectorV1 {
        schema: "ed25519_yao_lane_materialization_vector_v1",
        circuit_id: "ed25519_yao_lane_materialization_v1",
        input_schema: "seams/router-ab/ed25519-yao/lane_materialization/input/v1",
        output_schema: "seams/router-ab/ed25519-yao/lane_materialization/output/v1",
        circuit_digest_hex: hex::encode(circuit.benchmark_component_digest().expose_public_bytes()),
        schedule_digest_hex: hex::encode(circuit.benchmark_schedule_digest().expose_public_bytes()),
        cases: vec![
            LaneMaterializationCaseV1::Relation {
                name: "activation_base_offset_relation",
                source: "stable_y_tau_contributions",
                private_output_sharing: "joint_role_coins",
                offset: "joint_role_lambda",
                expected_relation: "2*X_holder-X_worker=A_pub",
            },
            rejection(
                "recipient_substitution",
                "reject_lane_package_recipient_mismatch",
            ),
            rejection(
                "package_substitution",
                "reject_lane_package_commitment_mismatch",
            ),
            rejection("lane_substitution", "reject_target_lane_binding_mismatch"),
            rejection(
                "epoch_substitution",
                "reject_target_epoch_or_prior_activation_mismatch",
            ),
            rejection(
                "activation_substitution",
                "reject_source_material_activation_mismatch",
            ),
            rejection("replay", "redeliver_exact_committed_ciphertexts_only"),
        ],
    };
    format!(
        "{}\n",
        serde_json::to_string_pretty(&vector).expect("lane-materialization vector serializes")
    )
}

fn rejection(name: &'static str, expected_outcome: &'static str) -> LaneMaterializationCaseV1 {
    LaneMaterializationCaseV1::Rejection {
        name,
        expected_outcome,
    }
}

#[test]
fn lane_materialization_vector_fixture_matches_distinct_circuit_and_schedule() {
    let path = fixture_path();
    let canonical = canonical_fixture();
    if env::var(UPDATE_ENV).as_deref() == Ok("1") {
        fs::write(&path, &canonical).expect("lane-materialization fixture writes");
    }
    assert_eq!(
        fs::read_to_string(path).expect("lane-materialization fixture reads"),
        canonical,
    );

    let circuit = compile_lane_materialization_v1();
    assert_eq!(circuit.metrics().input_wire_count(), 3584);
    assert_eq!(circuit.metrics().output_wire_count(), 1024);
}
