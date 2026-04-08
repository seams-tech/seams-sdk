use ed25519_hss as production;
use ed25519_hss_verus as mirror;
use serde_json::Value;

fn sample_context() -> production::shared::CanonicalContext {
    production::shared::CanonicalContext {
        org_id: "acme".to_string(),
        account_id: "alice".to_string(),
        key_purpose: "signing".to_string(),
        key_version: "v1".to_string(),
        participant_ids: vec![7, 11],
        derivation_version: 1,
    }
}

fn sample_f_expand_input() -> production::shared::FExpandInput {
    production::shared::FExpandInput {
        context: sample_context(),
        y_client: [
            0x10, 0x22, 0x34, 0x48, 0x50, 0x62, 0x74, 0x86, 0x90, 0xa2, 0xb4, 0xc6, 0xd0, 0xe2,
            0xf4, 0x06, 0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f, 0x91, 0xa3, 0xb5, 0xc7,
            0xd9, 0xeb, 0xfd, 0x0f,
        ],
        y_relayer: [
            0x01, 0x13, 0x25, 0x37, 0x49, 0x5b, 0x6d, 0x7f, 0x81, 0x93, 0xa5, 0xb7, 0xc9, 0xdb,
            0xed, 0xff, 0x02, 0x14, 0x26, 0x38, 0x4a, 0x5c, 0x6e, 0x70, 0x82, 0x94, 0xa6, 0xb8,
            0xca, 0xdc, 0xee, 0x01,
        ],
        tau_client: [
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        tau_relayer: [
            0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
    }
}

fn mirror_f_expand_output_from_production(
    output: &production::shared::FExpandOutput,
) -> mirror::shared::reference::FExpandOutput {
    mirror::shared::reference::FExpandOutput {
        context_binding: output.context_binding,
        m: output.m,
        d: output.d,
        h: output.h,
        a_bytes: output.a_bytes,
        a: output.a,
        tau: output.tau,
        x_client_base: output.x_client_base,
        x_relayer_base: output.x_relayer_base,
        public_key: output.public_key,
    }
}

#[test]
fn anti_drift_candidate_constants_and_shape_match_production() {
    assert_eq!(
        production::candidate::FIXED_HIDDEN_CORE_CANDIDATE_VERSION,
        mirror::candidate::FIXED_HIDDEN_CORE_CANDIDATE_VERSION,
    );
    assert_eq!(
        production::candidate::FIXED_HIDDEN_CORE_FUNCTION_ID,
        mirror::candidate::FIXED_HIDDEN_CORE_FUNCTION_ID,
    );

    let candidate = production::candidate::build_fixed_hidden_core_candidate(&sample_context())
        .expect("production candidate should build");

    assert_eq!(
        candidate.message_flow.len(),
        mirror::candidate::fixed_hidden_core_message_flow_len()
    );
    assert_eq!(candidate.message_flow.first().map(|step| step.actor.as_str()), Some("server"));
    assert_eq!(
        candidate.message_flow.last().map(|step| step.actor.as_str()),
        Some("output-share layer")
    );
    assert_eq!(
        candidate.evaluator_plan.hidden_core_stages.len(),
        mirror::candidate::fixed_hidden_core_hidden_stage_count()
    );
    assert_eq!(candidate.artifact_inventory.line_items.len(), 15);

    let cross_session_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| {
            matches!(
                item.scope,
                production::candidate::ArtifactScope::CrossSessionTemplate
            )
        })
        .count();
    let public_control_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| {
            matches!(
                item.scope,
                production::candidate::ArtifactScope::PerRunPublicControl
            )
        })
        .count();
    let client_private_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| matches!(item.scope, production::candidate::ArtifactScope::ClientPrivateInput))
        .count();
    let server_private_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| matches!(item.scope, production::candidate::ArtifactScope::ServerPrivateInput))
        .count();
    let structural_internal_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| matches!(item.scope, production::candidate::ArtifactScope::StructuralInternal))
        .count();
    let client_output_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| matches!(item.scope, production::candidate::ArtifactScope::ClientOutput))
        .count();
    let server_output_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| matches!(item.scope, production::candidate::ArtifactScope::ServerOutput))
        .count();
    let public_output_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| matches!(item.scope, production::candidate::ArtifactScope::PublicOutput))
        .count();

    assert_eq!(cross_session_count, 4);
    assert_eq!(public_control_count, 3);
    assert_eq!(client_private_count, 2);
    assert_eq!(server_private_count, 2);
    assert_eq!(structural_internal_count, 1);
    assert_eq!(client_output_count, 1);
    assert_eq!(server_output_count, 1);
    assert_eq!(public_output_count, 1);
}

#[test]
fn anti_drift_prime_order_encoder_layout_matches_production() {
    assert_eq!(
        production::artifact::PRIME_ORDER_ENCODER_VERSION,
        mirror::artifact::prime_order_encoder::PRIME_ORDER_ENCODER_VERSION,
    );

    let candidate = production::candidate::build_fixed_hidden_core_candidate(&sample_context())
        .expect("production candidate should build");
    let artifact = production::artifact::build_prime_order_size_optimized_artifact(&candidate)
        .expect("production artifact should build");

    assert_eq!(
        artifact.sections.len(),
        mirror::artifact::prime_order_encoder::prime_order_total_section_count()
    );
    assert_eq!(
        artifact.sections.first().map(|section| section.kind),
        Some(production::artifact::PrimeOrderSectionKind::Header)
    );
    assert_eq!(
        artifact.sections.last().map(|section| section.kind),
        Some(production::artifact::PrimeOrderSectionKind::GroupPublicDataWindows)
    );

    let prefix_lengths: Vec<u64> = artifact
        .sections
        .iter()
        .take(11)
        .map(|section| section.length_bytes)
        .collect();
    assert_eq!(
        prefix_lengths,
        vec![256, 512, 2_048, 12_288, 1_024, 24_576, 24_576, 24_576, 24_576, 4_096, 2_048]
    );
    assert_eq!(
        prefix_lengths.iter().sum::<u64>() as usize,
        mirror::artifact::prime_order_encoder::prime_order_fixed_allocated_prefix_bytes()
    );
}

#[test]
fn anti_drift_hidden_eval_shape_matches_production() {
    assert_eq!(
        production::ddh::HIDDEN_EVAL_PROGRAM_VERSION,
        mirror::ddh::hidden_eval::HIDDEN_EVAL_PROGRAM_VERSION,
    );

    let candidate = production::candidate::build_fixed_hidden_core_candidate(&sample_context())
        .expect("production candidate should build");
    let bytes = production::artifact::materialize_prime_order_size_optimized_bytes(&candidate)
        .expect("production artifact bytes should build");
    let decoded = production::artifact::decode_prime_order_size_optimized_artifact(&bytes)
        .expect("production artifact should decode");
    let program = production::ddh::compile_prime_order_hidden_eval_program(&decoded)
        .expect("production hidden eval program should compile");

    assert_eq!(program.stages.len(), mirror::ddh::hidden_eval::hidden_eval_stage_count());
    assert_eq!(
        program.active_window_records,
        mirror::ddh::hidden_eval::hidden_eval_active_window_count()
    );
    assert_eq!(
        program.preload_round_constant_count,
        mirror::ddh::hidden_eval::hidden_eval_preload_round_constant_count()
    );
    assert_eq!(program.primitive_kind, production::ddh::HssPrimitiveKind::PrimeOrderDdh);

    let stage_kinds: Vec<production::ddh::HiddenEvalStageKind> =
        program.stages.iter().map(|stage| stage.kind).collect();
    assert_eq!(
        stage_kinds,
        vec![
            production::ddh::HiddenEvalStageKind::AddMod2Pow256,
            production::ddh::HiddenEvalStageKind::MessageSchedule,
            production::ddh::HiddenEvalStageKind::RoundState00To19,
            production::ddh::HiddenEvalStageKind::RoundState20To39,
            production::ddh::HiddenEvalStageKind::RoundState40To59,
            production::ddh::HiddenEvalStageKind::RoundState60To79,
            production::ddh::HiddenEvalStageKind::OutputProjector,
        ]
    );
    assert_eq!(program.stages[0].windows.len(), 32);
    assert_eq!(program.stages[1].windows.len(), 64);
    assert_eq!(program.stages[2].windows.len(), 20);
    assert_eq!(program.stages[3].windows.len(), 20);
    assert_eq!(program.stages[4].windows.len(), 20);
    assert_eq!(program.stages[5].windows.len(), 20);
    assert_eq!(program.stages[6].windows.len(), 4);
}

#[test]
fn anti_drift_executor_visible_boundary_shape_matches_verified_mirror() {
    let input = sample_f_expand_input();
    let production_output =
        production::shared::eval_f_expand(&input).expect("production reference should evaluate");
    let bundle_shape = mirror::ddh::hidden_eval_executor::hidden_eval_executor_output_bundle_shape();

    assert_eq!(
        mirror::ddh::hidden_eval_executor::hidden_eval_executor_visible_output_count(),
        3
    );
    assert_eq!(bundle_shape.canonical_seed_bundle_count, 1);
    assert_eq!(bundle_shape.x_client_base_bundle_count, 1);
    assert_eq!(bundle_shape.x_relayer_base_transport_bundle_count, 2);
    assert_eq!(production_output.d.len(), 32);
    assert_eq!(production_output.x_client_base.len(), 32);
    assert_eq!(production_output.x_relayer_base.len(), 32);
}

#[test]
fn anti_drift_output_level_visible_boundary_projection_matches_between_reference_and_executor() {
    let input = sample_f_expand_input();
    let production_output =
        production::shared::eval_f_expand(&input).expect("production reference should evaluate");
    let reference_boundary = mirror::shared::reference::f_expand_visible_boundary_from_output(
        mirror_f_expand_output_from_production(&production_output),
    );
    let executor_boundary = mirror::ddh::hidden_eval_executor::hidden_eval_executor_boundary_from_output(
        mirror_f_expand_output_from_production(&production_output),
    );

    assert_eq!(reference_boundary.canonical_seed, production_output.d);
    assert_eq!(reference_boundary.x_client_base, production_output.x_client_base);
    assert_eq!(reference_boundary.x_relayer_base, production_output.x_relayer_base);
    assert_eq!(reference_boundary.canonical_seed, executor_boundary.canonical_seed);
    assert_eq!(reference_boundary.x_client_base, executor_boundary.x_client_base);
    assert_eq!(reference_boundary.x_relayer_base, executor_boundary.x_relayer_base);
    assert_eq!(executor_boundary.canonical_seed, production_output.d);
    assert_eq!(executor_boundary.x_client_base, production_output.x_client_base);
    assert_eq!(executor_boundary.x_relayer_base, production_output.x_relayer_base);
}

#[test]
fn anti_drift_runtime_output_kind_packet_surface_matches_export_boundary() {
    let client_output = production::wire::WireMessage { bytes: vec![0x01] };
    let seed_output = production::wire::WireMessage { bytes: vec![0x02] };
    let handle = production::wire::ServerEvalHandle { bytes: [0x11; 32] };

    let client_only_finalize = production::wire::ServerFinalizePacket {
        context_binding: [0x22; 32],
        server_eval_handle: handle,
        final_transcript_digest: [0x33; 32],
        allowed_output_kind: production::wire::AllowedOutputKind::ClientOutputOnly,
        client_output: client_output.clone(),
        seed_output: None,
    };
    let export_finalize = production::wire::ServerFinalizePacket {
        context_binding: [0x44; 32],
        server_eval_handle: handle,
        final_transcript_digest: [0x55; 32],
        allowed_output_kind: production::wire::AllowedOutputKind::ClientOutputAndSeedOutput,
        client_output: client_output.clone(),
        seed_output: Some(seed_output.clone()),
    };
    let output_projection_client_only = production::wire::OutputProjectionResponsePayload {
        final_server_digest: [0x66; 32],
        output_release_token: [0x77; 32],
        allowed_output_kind: production::wire::AllowedOutputKind::ClientOutputOnly,
        execution_checkpoint_digest: [0x88; 32],
    };
    let output_projection_export = production::wire::OutputProjectionResponsePayload {
        final_server_digest: [0x99; 32],
        output_release_token: [0xaa; 32],
        allowed_output_kind: production::wire::AllowedOutputKind::ClientOutputAndSeedOutput,
        execution_checkpoint_digest: [0xbb; 32],
    };

    let client_only_finalize_json =
        serde_json::to_value(&client_only_finalize).expect("serialize client-only finalize");
    let export_finalize_json =
        serde_json::to_value(&export_finalize).expect("serialize export finalize");
    let output_projection_client_only_json = serde_json::to_value(&output_projection_client_only)
        .expect("serialize client-only output projection");
    let output_projection_export_json =
        serde_json::to_value(&output_projection_export).expect("serialize export output projection");

    assert_eq!(
        client_only_finalize_json["allowed_output_kind"],
        Value::String("client_output_only".to_string())
    );
    assert_eq!(client_only_finalize_json["seed_output"], Value::Null);

    assert_eq!(
        export_finalize_json["allowed_output_kind"],
        Value::String("client_output_and_seed_output".to_string())
    );
    assert_eq!(
        export_finalize_json["seed_output"]["bytes"],
        Value::Array(vec![Value::from(0x02u64)])
    );

    assert_eq!(
        output_projection_client_only_json["allowed_output_kind"],
        Value::String("client_output_only".to_string())
    );
    assert!(output_projection_client_only_json.get("seed_output").is_none());
    assert_eq!(
        output_projection_export_json["allowed_output_kind"],
        Value::String("client_output_and_seed_output".to_string())
    );
    assert!(output_projection_export_json.get("seed_output").is_none());

    assert_eq!(
        mirror::server::api::finalize_packet_shape_for_operation(
            mirror::server::api::ServerEvalOperation::Registration,
        )
        .has_seed_output,
        false
    );
    assert_eq!(
        mirror::server::api::finalize_packet_shape_for_operation(
            mirror::server::api::ServerEvalOperation::ExplicitKeyExport,
        )
        .has_seed_output,
        true
    );
    assert_eq!(
        mirror::server::api::output_projection_response_shape_for_operation(
            mirror::server::api::ServerEvalOperation::Registration,
        )
        .allowed_output_kind,
        mirror::server::api::AllowedOutputKind::ClientOutputOnly
    );
    assert_eq!(
        mirror::server::api::output_projection_response_shape_for_operation(
            mirror::server::api::ServerEvalOperation::ExplicitKeyExport,
        )
        .allowed_output_kind,
        mirror::server::api::AllowedOutputKind::ClientOutputAndSeedOutput
    );
}

#[test]
fn anti_drift_runtime_delivery_packet_surface_stays_split() {
    let client_output = production::wire::WireMessage { bytes: vec![0x01] };
    let seed_output = production::wire::WireMessage { bytes: vec![0x02] };
    let server_output = production::wire::WireMessage { bytes: vec![0x03] };
    let handle = production::wire::ServerEvalHandle { bytes: [0x11; 32] };

    let finalize = production::wire::ServerFinalizePacket {
        context_binding: [0x22; 32],
        server_eval_handle: handle,
        final_transcript_digest: [0x33; 32],
        allowed_output_kind: production::wire::AllowedOutputKind::ClientOutputOnly,
        client_output: client_output.clone(),
        seed_output: None,
    };
    let delivery = production::wire::OutputDelivery {
        client: client_output,
        seed: seed_output,
        server: server_output,
    };

    let finalize_json = serde_json::to_value(&finalize).expect("serialize finalize packet");
    let delivery_json = serde_json::to_value(&delivery).expect("serialize output delivery");

    assert!(finalize_json.get("client_output").is_some());
    assert!(finalize_json.get("seed_output").is_some());
    assert!(finalize_json.get("server_output").is_none());

    assert!(delivery_json.get("client").is_some());
    assert!(delivery_json.get("seed").is_some());
    assert!(delivery_json.get("server").is_some());
    assert!(delivery_json.get("client_output").is_none());
    assert!(delivery_json.get("seed_output").is_none());
    assert!(delivery_json.get("server_output").is_none());
}
