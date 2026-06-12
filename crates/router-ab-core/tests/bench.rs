use router_ab_core::{
    candidate_measurement_gate_report_v1, candidate_round_trip_profiles_v1, CandidateId,
    CandidateMeasurementGateStatus, CANDIDATE_MEASUREMENT_GATES_VERSION_V1,
};

#[test]
fn adapter_round_trip_profiles_cover_both_candidates_and_all_operations() {
    let profiles = candidate_round_trip_profiles_v1();

    assert_eq!(profiles.len(), 6);
    for candidate_id in [
        CandidateId::MpcThresholdPrfV1,
        CandidateId::SplitRootDerivationV1,
    ] {
        for operation in ["registration", "export", "refresh"] {
            let profile = profiles
                .iter()
                .find(|profile| {
                    profile.candidate_id == candidate_id && profile.operation == operation
                })
                .unwrap_or_else(|| panic!("missing profile: {candidate_id:?}/{operation}"));
            assert_eq!(profile.router_facing_client_requests, 1);
            assert_eq!(profile.router_invocations, 1);
            assert_eq!(profile.signer_a_invocations, 1);
            assert_eq!(profile.signer_b_invocations, 1);
            assert_eq!(profile.direct_ab_coordination_round_trips, 0);
            assert_eq!(profile.signer_output_packages, 4);
        }
    }
}

#[test]
fn measurement_gate_report_marks_completed_and_blocked_gates() {
    let report = candidate_measurement_gate_report_v1();

    assert_eq!(
        report.report_version,
        CANDIDATE_MEASUREMENT_GATES_VERSION_V1
    );

    for gate_id in [
        "native_adapter_latency_baseline",
        "adapter_round_trip_shape",
        "wasm32_library_build",
        "candidate_a_cryptographic_path_native_latency",
        "candidate_b_cryptographic_path_native_latency",
        "cryptographic_path_native_latency",
    ] {
        let gate = report
            .gates
            .iter()
            .find(|gate| gate.gate_id == gate_id)
            .unwrap_or_else(|| panic!("missing gate: {gate_id}"));
        assert_eq!(gate.status, CandidateMeasurementGateStatus::Complete);
        assert!(gate.blocking_requirement.is_empty(), "{gate_id}");
    }

    for gate_id in [
        "deployable_wasm_or_worker_bundle_size",
        "cloudflare_worker_runtime_latency",
    ] {
        let gate = report
            .gates
            .iter()
            .find(|gate| gate.gate_id == gate_id)
            .unwrap_or_else(|| panic!("missing gate: {gate_id}"));
        assert_eq!(gate.status, CandidateMeasurementGateStatus::Blocked);
        assert!(!gate.blocking_requirement.is_empty(), "{gate_id}");
    }
}
