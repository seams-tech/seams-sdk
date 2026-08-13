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
        "b82d95991e0d3f91f2d31009cb1558f73abd1d0a667fec99e02ddb751f652d06"
    );
    assert_eq!(
        hex::encode(circuit.benchmark_schedule_digest().expose_public_bytes()),
        "3bbae3843bab644b3b7e7ed6dd379b6b40b7c32133c5094e4b1fc4e966fd57d4"
    );
    assert_eq!(circuit.metrics().input_wire_count(), 3584);
    assert_eq!(circuit.metrics().output_wire_count(), 1024);
}
