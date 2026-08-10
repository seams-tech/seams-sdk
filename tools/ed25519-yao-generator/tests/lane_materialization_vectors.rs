use ed25519_yao_generator::compile_lane_materialization_v1;

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
    assert_eq!(circuit.metrics().input_wire_count(), 1536);
    assert_eq!(circuit.metrics().output_wire_count(), 1024);
}
