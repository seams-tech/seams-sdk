use ed25519_hss as production;
use ed25519_hss_verus as mirror;
use serde_json::Value;
use std::{fs, path::PathBuf};

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

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .canonicalize()
        .expect("workspace root should resolve")
}

fn read_workspace_file(path: &str) -> String {
    fs::read_to_string(workspace_root().join(path)).expect("workspace file should be readable")
}

fn assert_ts_export_has_required_string_field(source: &str, export_name: &str, field: &str) {
    let interface_marker = format!("export interface {export_name}");
    let type_marker = format!("export type {export_name}");
    let start = source
        .find(&interface_marker)
        .or_else(|| source.find(&type_marker))
        .expect("exported TypeScript shape should exist");
    let rest = &source[start..];
    let next_export = rest.find("\nexport ").unwrap_or(rest.len());
    let body = &rest[..next_export];
    assert!(
        body.contains(&format!("{field}: string;")),
        "{export_name} should require {field}: string"
    );
    assert!(
        !body.contains(&format!("{field}?:")),
        "{export_name} should not make {field} optional"
    );
}

fn sample_f_expand_input() -> production::shared::FExpandInput {
    production::shared::FExpandInput {
        context: sample_context(),
        y_client: [
            0x10, 0x22, 0x34, 0x48, 0x50, 0x62, 0x74, 0x86, 0x90, 0xa2, 0xb4, 0xc6, 0xd0, 0xe2,
            0xf4, 0x06, 0x11, 0x23, 0x35, 0x47, 0x59, 0x6b, 0x7d, 0x8f, 0x91, 0xa3, 0xb5, 0xc7,
            0xd9, 0xeb, 0xfd, 0x0f,
        ],
        y_server: [
            0x01, 0x13, 0x25, 0x37, 0x49, 0x5b, 0x6d, 0x7f, 0x81, 0x93, 0xa5, 0xb7, 0xc9, 0xdb,
            0xed, 0xff, 0x02, 0x14, 0x26, 0x38, 0x4a, 0x5c, 0x6e, 0x70, 0x82, 0x94, 0xa6, 0xb8,
            0xca, 0xdc, 0xee, 0x01,
        ],
        tau_client: [
            0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        tau_server: [
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
        x_server_base: output.x_server_base,
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
    assert_eq!(
        candidate
            .message_flow
            .first()
            .map(|step| step.actor.as_str()),
        Some("server")
    );
    assert_eq!(
        candidate
            .message_flow
            .last()
            .map(|step| step.actor.as_str()),
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
        .filter(|item| {
            matches!(
                item.scope,
                production::candidate::ArtifactScope::ClientPrivateInput
            )
        })
        .count();
    let server_private_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| {
            matches!(
                item.scope,
                production::candidate::ArtifactScope::ServerPrivateInput
            )
        })
        .count();
    let structural_internal_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| {
            matches!(
                item.scope,
                production::candidate::ArtifactScope::StructuralInternal
            )
        })
        .count();
    let client_output_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| {
            matches!(
                item.scope,
                production::candidate::ArtifactScope::ClientOutput
            )
        })
        .count();
    let server_output_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| {
            matches!(
                item.scope,
                production::candidate::ArtifactScope::ServerOutput
            )
        })
        .count();
    let public_output_count = candidate
        .artifact_inventory
        .line_items
        .iter()
        .filter(|item| {
            matches!(
                item.scope,
                production::candidate::ArtifactScope::PublicOutput
            )
        })
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

    assert_eq!(
        program.stages.len(),
        mirror::ddh::hidden_eval::hidden_eval_stage_count()
    );
    assert_eq!(
        program.active_window_records,
        mirror::ddh::hidden_eval::hidden_eval_active_window_count()
    );
    assert_eq!(
        program.preload_round_constant_count,
        mirror::ddh::hidden_eval::hidden_eval_preload_round_constant_count()
    );
    assert_eq!(
        program.primitive_kind,
        production::ddh::HssPrimitiveKind::PrimeOrderDdh
    );

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
    let bundle_shape =
        mirror::ddh::hidden_eval_executor::hidden_eval_executor_output_bundle_shape();

    assert_eq!(
        mirror::ddh::hidden_eval_executor::hidden_eval_executor_visible_output_count(),
        3
    );
    assert_eq!(bundle_shape.canonical_seed_bundle_count, 1);
    assert_eq!(bundle_shape.x_client_base_bundle_count, 1);
    assert_eq!(bundle_shape.x_server_base_transport_bundle_count, 2);
    assert_eq!(production_output.d.len(), 32);
    assert_eq!(production_output.x_client_base.len(), 32);
    assert_eq!(production_output.x_server_base.len(), 32);
}

#[test]
fn anti_drift_output_level_visible_boundary_projection_matches_between_reference_and_executor() {
    let input = sample_f_expand_input();
    let production_output =
        production::shared::eval_f_expand(&input).expect("production reference should evaluate");
    let reference_boundary = mirror::shared::reference::f_expand_visible_boundary_from_output(
        mirror_f_expand_output_from_production(&production_output),
    );
    let executor_boundary =
        mirror::ddh::hidden_eval_executor::hidden_eval_executor_boundary_from_output(
            mirror_f_expand_output_from_production(&production_output),
        );

    assert_eq!(reference_boundary.canonical_seed, production_output.d);
    assert_eq!(
        reference_boundary.x_client_base,
        production_output.x_client_base
    );
    assert_eq!(
        reference_boundary.x_server_base,
        production_output.x_server_base
    );
    assert_eq!(
        reference_boundary.canonical_seed,
        executor_boundary.canonical_seed
    );
    assert_eq!(
        reference_boundary.x_client_base,
        executor_boundary.x_client_base
    );
    assert_eq!(
        reference_boundary.x_server_base,
        executor_boundary.x_server_base
    );
    assert_eq!(executor_boundary.canonical_seed, production_output.d);
    assert_eq!(
        executor_boundary.x_client_base,
        production_output.x_client_base
    );
    assert_eq!(
        executor_boundary.x_server_base,
        production_output.x_server_base
    );
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
        projection_mode: production::wire::OutputProjectionMode::trusted_server_projection(),
        client_output: client_output.clone(),
        seed_output: None,
    };
    let export_finalize = production::wire::ServerFinalizePacket {
        context_binding: [0x44; 32],
        server_eval_handle: handle,
        final_transcript_digest: [0x55; 32],
        allowed_output_kind: production::wire::AllowedOutputKind::ClientOutputAndSeedOutput,
        projection_mode: production::wire::OutputProjectionMode::trusted_server_projection(),
        client_output: client_output.clone(),
        seed_output: Some(seed_output.clone()),
    };
    let output_projection_client_only = production::wire::OutputProjectionResponsePayload {
        final_server_digest: [0x66; 32],
        output_release_token: [0x77; 32],
        allowed_output_kind: production::wire::AllowedOutputKind::ClientOutputOnly,
        projection_mode: production::wire::OutputProjectionMode::trusted_server_projection(),
        execution_checkpoint_digest: [0x88; 32],
    };
    let output_projection_export = production::wire::OutputProjectionResponsePayload {
        final_server_digest: [0x99; 32],
        output_release_token: [0xaa; 32],
        allowed_output_kind: production::wire::AllowedOutputKind::ClientOutputAndSeedOutput,
        projection_mode: production::wire::OutputProjectionMode::trusted_server_projection(),
        execution_checkpoint_digest: [0xbb; 32],
    };

    let client_only_finalize_json =
        serde_json::to_value(&client_only_finalize).expect("serialize client-only finalize");
    let export_finalize_json =
        serde_json::to_value(&export_finalize).expect("serialize export finalize");
    let output_projection_client_only_json = serde_json::to_value(&output_projection_client_only)
        .expect("serialize client-only output projection");
    let output_projection_export_json = serde_json::to_value(&output_projection_export)
        .expect("serialize export output projection");

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
    assert!(output_projection_client_only_json
        .get("seed_output")
        .is_none());
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
fn anti_drift_projection_mode_and_staged_artifact_boundary_matches_verified_mirror() {
    let client_output = production::wire::WireMessage { bytes: vec![0x01] };
    let seed_output = production::wire::WireMessage { bytes: vec![0x02] };
    let trusted_artifact = production::wire::StagedEvaluatorArtifact {
        backend_version: production::ddh::DdhHssBackendVersion::CURRENT,
        context_binding: [0x10; 32],
        bindings: production::wire::RunBindings {
            client_input_commitment: [0x11; 32],
            server_input_commitment: [0x12; 32],
            run_binding: [0x13; 32],
            evaluation_digest: [0x14; 32],
        },
        projection_mode: production::wire::OutputProjectionMode::trusted_server_projection(),
        output_projector_binding: production::wire::OutputProjectorBinding {
            kind: production::wire::OutputProjectorBindingKind::BindingV1,
            scalar_width_bits: 256,
            modulus_id: production::wire::OutputProjectorModulusId::Ed25519L,
            binding_digest: [0x1b; 32],
        },
        client_output_value_kind: production::wire::ClientOutputValueKind::UnmaskedClientBase,
        client_output_commitment: [0x15; 32],
        evaluator_witness: production::wire::EvaluatorWitness {
            total_steps: 0,
            curve_cost_units: 0,
            evaluator_ops: production::artifact::PrimeOrderEvaluatorOps::default(),
            output_checksum: 0,
            final_point_compressed: [0x16; 32],
        },
        client_output,
        client_output_binding: [0x17; 32],
        seed_output,
        seed_output_binding: [0x18; 32],
        server_output_payload_binding: [0x19; 32],
        server_output_payload: vec![0x1a],
    };
    let masked_projection =
        production::wire::OutputProjectionMode::client_masked_projection([0x22; 32]);
    assert_eq!(
        production::wire::ClientOutputValueKind::for_projection_mode(
            &trusted_artifact.projection_mode,
        ),
        production::wire::ClientOutputValueKind::UnmaskedClientBase,
    );
    assert_eq!(
        production::wire::ClientOutputValueKind::for_projection_mode(&masked_projection),
        production::wire::ClientOutputValueKind::ClientBlindedBase,
    );

    let artifact_json = serde_json::to_value(&trusted_artifact).expect("serialize staged artifact");
    assert!(artifact_json.get("projection_mode").is_some());
    assert!(artifact_json.get("client_output_value_kind").is_some());
    assert!(artifact_json.get("client_output_commitment").is_some());

    assert_eq!(
        mirror::server::api::client_output_value_kind_for_projection_mode(
            mirror::server::api::OutputProjectionMode::TrustedServerProjection,
        ),
        mirror::server::api::ClientOutputValueKind::UnmaskedClientBase,
    );
    assert_eq!(
        mirror::server::api::client_output_value_kind_for_projection_mode(
            mirror::server::api::OutputProjectionMode::ClientMaskedProjection,
        ),
        mirror::server::api::ClientOutputValueKind::ClientBlindedBase,
    );
    let trusted_shape = mirror::server::api::staged_artifact_shape_for_projection(
        mirror::server::api::OutputProjectionMode::TrustedServerProjection,
    );
    assert_eq!(
        trusted_shape.client_output_value_kind,
        mirror::server::api::ClientOutputValueKind::UnmaskedClientBase,
    );
    assert!(trusted_shape.has_client_output_commitment);
    let masked_shape = mirror::server::api::staged_artifact_shape_for_projection(
        mirror::server::api::OutputProjectionMode::ClientMaskedProjection,
    );
    assert_eq!(
        masked_shape.client_output_value_kind,
        mirror::server::api::ClientOutputValueKind::ClientBlindedBase,
    );
    assert!(masked_shape.has_client_output_commitment);
}

#[test]
fn anti_drift_client_owned_wasm_boundary_requires_fixed_client_output_mask() {
    let build_shape = mirror::server::api::client_owned_wasm_request_shape(
        mirror::server::api::ClientOwnedWasmRequestKind::BuildClientOwnedStagedEvaluatorArtifact,
    );
    let open_shape = mirror::server::api::client_owned_wasm_request_shape(
        mirror::server::api::ClientOwnedWasmRequestKind::OpenClientOutput,
    );
    let fixed_len = mirror::server::api::fixed_client_output_mask_bytes();

    assert_eq!(fixed_len, 32);
    assert!(build_shape.has_client_output_mask_b64u);
    assert_eq!(build_shape.client_output_mask_len, 32);
    assert!(open_shape.has_client_output_mask_b64u);
    assert_eq!(open_shape.client_output_mask_len, 32);

    let signer_worker_types = read_workspace_file("packages/sdk-web/src/core/types/signer-worker.ts");
    assert_ts_export_has_required_string_field(
        &signer_worker_types,
        "WasmBuildThresholdEd25519HssClientOwnedStagedEvaluatorArtifactRequest",
        "clientOutputMaskB64u",
    );
    assert_ts_export_has_required_string_field(
        &signer_worker_types,
        "WasmOpenThresholdEd25519HssClientOutputRequest",
        "clientOutputMaskB64u",
    );

    let sdk_wasm_wrapper = read_workspace_file(
        "packages/sdk-web/src/core/signingEngine/threshold/crypto/hssClientSignerWasm.ts",
    );
    assert!(sdk_wasm_wrapper.contains(
        "const clientOutputMaskB64u = requireClientOutputMask32B64u(input.clientOutputMaskB64u);"
    ));
    assert!(sdk_wasm_wrapper.contains("clientOutputMaskB64u must decode to 32 bytes"));

    let browser_wasm = read_workspace_file("wasm/hss_client_signer/src/threshold_hss.rs");
    assert!(browser_wasm
        .contains("pub fn threshold_ed25519_hss_build_client_owned_staged_evaluator_artifact"));
    assert!(browser_wasm.contains("pub fn threshold_ed25519_hss_open_client_output"));
    assert!(browser_wasm.contains("decode_fixed_32("));
    assert!(browser_wasm.contains("get_required_string(&args, \"clientOutputMaskB64u\")"));

    let worker_wasm = read_workspace_file("wasm/near_signer/src/threshold/threshold_hss.rs");
    assert!(worker_wasm.contains("ThresholdEd25519HssBuildClientOwnedStagedArtifactArgs"));
    assert!(worker_wasm.contains("ThresholdEd25519HssOpenClientOutputArgs"));
    assert!(worker_wasm
        .contains("decode_fixed_32(&args.client_output_mask_b64u, \"clientOutputMaskB64u\")"));
}

#[test]
fn anti_drift_server_finalize_retained_state_excludes_client_output_metadata() {
    let left = production::ddh::DdhHssTransportBundle {
        owner: production::ddh::HiddenEvalInputOwner::Server,
        label: "x_server_base".to_string(),
        share_side: production::ddh::DdhHssShareSide::Left,
        words: Vec::new(),
        commitment: [0x31; 32],
    };
    let right = production::ddh::DdhHssTransportBundle {
        owner: production::ddh::HiddenEvalInputOwner::Server,
        label: "x_server_base".to_string(),
        share_side: production::ddh::DdhHssShareSide::Right,
        words: Vec::new(),
        commitment: [0x32; 32],
    };
    let retained = production::server::ServerEvalFinalizeOutput {
        canonical_seed_commitment: [0x30; 32],
        x_server_base_left: left,
        x_server_base_right: right,
    };
    let retained_debug = format!("{retained:?}");
    assert!(retained_debug.contains("canonical_seed_commitment"));
    assert!(retained_debug.contains("x_server_base_left"));
    assert!(retained_debug.contains("x_server_base_right"));
    assert!(!retained_debug.contains("DdhHiddenEvalClientOutputBundle"));
    assert!(!retained_debug.contains("x_client_base"));
    assert!(!retained_debug.contains("client_output_value_kind"));
    assert!(!retained_debug.contains("client_output_commitment"));

    let mirror_retained = mirror::server::api::server_finalize_retained_shape();
    assert!(mirror_retained.has_seed_commitment);
    assert!(mirror_retained.has_server_output_transport);
    assert!(!mirror_retained.has_client_output_bundle);
    assert!(!mirror_retained.has_client_output_value_kind);
    assert!(!mirror_retained.has_client_output_commitment);
    let mirror_validation = mirror::server::api::server_finalize_validation_shape_for_projection(
        mirror::server::api::OutputProjectionMode::ClientMaskedProjection,
    );
    assert!(!mirror_validation.retained.has_client_output_bundle);
    assert!(!mirror_validation.retained.has_client_output_value_kind);
    assert!(!mirror_validation.retained.has_client_output_commitment);
    assert_eq!(
        mirror_validation.artifact.client_output_value_kind,
        mirror::server::api::ClientOutputValueKind::ClientBlindedBase,
    );
    assert!(mirror_validation.artifact.has_client_output_commitment);
    assert_eq!(
        mirror::server::api::client_owned_finalization_projection_mode(),
        mirror::server::api::OutputProjectionMode::ClientMaskedProjection,
    );
    assert_eq!(
        mirror::server::api::staged_artifact_shape_for_projection(
            mirror::server::api::client_owned_finalization_projection_mode(),
        )
        .client_output_value_kind,
        mirror::server::api::ClientOutputValueKind::ClientBlindedBase,
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
        projection_mode: production::wire::OutputProjectionMode::trusted_server_projection(),
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
