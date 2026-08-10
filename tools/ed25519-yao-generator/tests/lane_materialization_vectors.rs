use curve25519_dalek::scalar::Scalar;
use ed25519_yao_generator::{
    compile_lane_materialization_v1, PublicSyntheticLaneMaterializationInputsV1,
};

#[test]
fn lane_materialization_vector_fixture_matches_distinct_circuit_and_schedule() {
    let fixture = include_str!("../vectors/ed25519-yao-lane-materialization-v1.json");
    assert!(fixture.contains("ed25519_yao_lane_materialization_v1"));
    assert!(fixture.contains("recipient_substitution"));
    assert!(fixture.contains("activation_substitution"));
    assert!(fixture.contains("replay"));
    let circuit = compile_lane_materialization_v1();
    assert_eq!(
        hex::encode(circuit.benchmark_component_digest().expose_public_bytes()),
        "ba88dcab5c70a308d6e500b6664424d1a7af2668a21d8749878d42b52a486919"
    );
    assert_eq!(
        hex::encode(circuit.benchmark_schedule_digest().expose_public_bytes()),
        "a4ed4617493e0ad7ed46865d4aa866d19e00aeb0d7b9555f3602fa007ba3abaa"
    );
    let inputs = PublicSyntheticLaneMaterializationInputsV1::new(
        Scalar::from(11_u64).to_bytes(),
        Scalar::from(15_u64).to_bytes(),
        Scalar::from(2_u64).to_bytes(),
        Scalar::from(3_u64).to_bytes(),
        Scalar::from(7_u64).to_bytes(),
        Scalar::from(5_u64).to_bytes(),
    )
    .expect("fixture scalars are canonical");
    let outputs = circuit.evaluate_public_synthetic(&inputs);
    assert_eq!(
        Scalar::from_canonical_bytes(outputs.a_target_holder_share).expect("A holder output")
            + Scalar::from_canonical_bytes(outputs.b_target_holder_share).expect("B holder output"),
        Scalar::from(21_u64)
    );
    assert_eq!(
        Scalar::from_canonical_bytes(outputs.a_target_signing_worker_share)
            .expect("A worker output")
            + Scalar::from_canonical_bytes(outputs.b_target_signing_worker_share)
                .expect("B worker output"),
        Scalar::from(36_u64)
    );
}
