use ed25519_hss::artifact::{
    build_prime_order_execution_trace, build_prime_order_size_optimized_artifact,
    decode_prime_order_size_optimized_artifact, materialize_prime_order_size_optimized_bytes,
    PrimeOrderSectionKind, PrimeOrderWindowRecordClass,
};
use ed25519_hss::artifact_stub::{
    build_candidate_artifact_stub, materialize_candidate_artifact_stub_bytes,
    DEFAULT_ARTIFACT_STUB_CHUNK_SIZE_BYTES,
};
use ed25519_hss::benchmark::{
    default_cache_benchmark_config, generate_cache_benchmark_report,
    materialize_cache_benchmark_targets, DEFAULT_CACHED_GC_BASELINE_BYTES,
};
use ed25519_hss::candidate::build_fixed_hidden_core_candidate;
use ed25519_hss::ddh::{
    compile_prime_order_hidden_eval_program, keygen_prime_order_ddh_hss_backend,
    FixedFunctionHssBackend, HiddenEvalInputOwner, HssPrimitiveKind,
};
use ed25519_hss::fixtures::committed_fixture_corpus;
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
use ed25519_hss::runtime::{
    compile_prime_order_cpu_execution_program, default_prime_order_cpu_executor_benchmark_config,
    generate_prime_order_cpu_executor_benchmark_report,
};

use crate::support::{contains_subslice, first_fixture, read_u16_le, section_bytes};

#[test]
fn artifact_stub_matches_default_backend_size_and_is_stable() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");

    let first = build_candidate_artifact_stub(&candidate).expect("artifact stub");
    let second = build_candidate_artifact_stub(&candidate).expect("artifact stub");

    assert_eq!(first, second);
    assert_eq!(first.total_bytes, candidate.backend.public_data_bytes);
    assert_eq!(first.header_bytes, 96);
    assert_eq!(
        first.chunk_size_bytes,
        DEFAULT_ARTIFACT_STUB_CHUNK_SIZE_BYTES
    );

    let bytes = materialize_candidate_artifact_stub_bytes(&candidate).expect("artifact bytes");
    assert_eq!(bytes.len() as u64, candidate.backend.public_data_bytes);
}

#[test]
fn artifact_stub_digest_changes_with_context() {
    let fixtures = committed_fixture_corpus().expect("fixture corpus");
    let first_candidate =
        build_fixed_hidden_core_candidate(&fixtures[0].input.context).expect("first candidate");
    let second_candidate =
        build_fixed_hidden_core_candidate(&fixtures[1].input.context).expect("second candidate");

    let first_stub = build_candidate_artifact_stub(&first_candidate).expect("first stub");
    let second_stub = build_candidate_artifact_stub(&second_candidate).expect("second stub");

    assert_ne!(first_stub.artifact_digest, second_stub.artifact_digest);
    assert_ne!(first_stub.context_binding, second_stub.context_binding);
}

#[test]
fn prime_order_encoder_matches_backend_size_and_has_expected_sections() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
    let artifact =
        build_prime_order_size_optimized_artifact(&candidate).expect("prime-order artifact");
    let bytes =
        materialize_prime_order_size_optimized_bytes(&candidate).expect("prime-order bytes");

    assert_eq!(artifact.total_bytes, candidate.backend.public_data_bytes);
    assert_eq!(bytes.len() as u64, candidate.backend.public_data_bytes);
    assert_eq!(artifact.sections.len(), 12);
    assert_eq!(artifact.sections[0].kind, PrimeOrderSectionKind::Header);
    assert_eq!(
        artifact.sections.last().expect("last section").kind,
        PrimeOrderSectionKind::GroupPublicDataWindows
    );

    let header = section_bytes(&artifact, &bytes, PrimeOrderSectionKind::Header);
    assert_eq!(&header[..8], b"SGPPRM01");

    let context = section_bytes(&artifact, &bytes, PrimeOrderSectionKind::ContextDescriptor);
    assert!(contains_subslice(context, b"org.wraparound"));
    assert!(contains_subslice(context, b"wraparound.test.near"));

    let round_constants = section_bytes(&artifact, &bytes, PrimeOrderSectionKind::RoundConstants);
    assert_eq!(&round_constants[..8], b"RNDCNST1");
    assert!(contains_subslice(
        round_constants,
        &0x428a2f98d728ae22u64.to_be_bytes()
    ));
    assert!(contains_subslice(
        round_constants,
        &0x6c44198c4a475817u64.to_be_bytes()
    ));

    let projector = section_bytes(
        &artifact,
        &bytes,
        PrimeOrderSectionKind::OutputProjectorTemplate,
    );
    assert!(contains_subslice(projector, b"x_client_base = a + tau"));

    let windows = section_bytes(
        &artifact,
        &bytes,
        PrimeOrderSectionKind::GroupPublicDataWindows,
    );
    assert_eq!(&windows[..8], b"GRPWNDW2");
    assert_eq!(read_u16_le(windows, 12), 64);
    assert_eq!(read_u16_le(windows, 14), 262);
    assert_eq!(read_u16_le(windows, 18), 32);
    assert_eq!(read_u16_le(windows, 20), 64);
    assert_eq!(read_u16_le(windows, 22), 80);
    assert_eq!(read_u16_le(windows, 24), 80);
    assert_eq!(read_u16_le(windows, 26), 4);
    assert_eq!(read_u16_le(windows, 28), 2);
}

#[test]
fn prime_order_decoder_recovers_header_and_window_classes() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
    let bytes =
        materialize_prime_order_size_optimized_bytes(&candidate).expect("prime-order bytes");
    let decoded =
        decode_prime_order_size_optimized_artifact(&bytes).expect("decode structured artifact");

    assert_eq!(decoded.total_bytes, candidate.backend.public_data_bytes);
    assert_eq!(
        decoded.header.expected_total_bytes,
        candidate.backend.public_data_bytes
    );
    assert_eq!(
        decoded.header.fixed_function_id,
        candidate.fixed_function_id
    );
    assert_eq!(decoded.header.encoder_version, "prime_order_encoder_v1");
    assert_eq!(decoded.header.context_binding, candidate.context_binding);
    assert_eq!(decoded.windows.record_bytes, 64);
    assert_eq!(decoded.windows.total_records, 262);
    assert_eq!(decoded.windows.class_count, 6);
    assert_eq!(decoded.windows.add_lane_count, 32);
    assert_eq!(decoded.windows.schedule_derived_count, 64);
    assert_eq!(decoded.windows.round_constant_count, 80);
    assert_eq!(decoded.windows.round_state_count, 80);
    assert_eq!(decoded.windows.output_projector_count, 4);
    assert_eq!(decoded.windows.participant_count, 2);

    let first = decoded.windows.records.first().expect("first record");
    assert_eq!(first.class, PrimeOrderWindowRecordClass::AddLane);
    assert_eq!(first.index, 0);
    assert_eq!(first.class_value, 0);
    assert!(first.dependency_left.is_none());

    let derived = decoded
        .windows
        .records
        .iter()
        .find(|record| record.class == PrimeOrderWindowRecordClass::ScheduleDerivedWord)
        .expect("schedule-derived record");
    assert_eq!(derived.class_value, 16);
    assert_eq!(derived.dependency_left, Some(1));
    assert_eq!(derived.dependency_right, Some(14));

    let last = decoded.windows.records.last().expect("last record");
    assert_eq!(last.class, PrimeOrderWindowRecordClass::ContextParticipant);
    assert_eq!(last.class_value, 2);
    assert_eq!(last.class_slot, 1);
}

#[test]
fn prime_order_trace_groups_execution_steps_into_expected_stages() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
    let bytes =
        materialize_prime_order_size_optimized_bytes(&candidate).expect("prime-order bytes");
    let decoded =
        decode_prime_order_size_optimized_artifact(&bytes).expect("decode structured artifact");
    let trace = build_prime_order_execution_trace(&decoded).expect("execution trace");

    assert_eq!(trace.preload_round_constant_count, 80);
    assert_eq!(trace.preload_context_participant_count, 2);
    assert_eq!(trace.total_steps, 180);
    assert_eq!(trace.stage_count, 7);
    assert_eq!(trace.stages[0].label, "add_mod_2pow256");
    assert_eq!(trace.stages[0].step_count, 32);
    assert_eq!(trace.stages[1].label, "message_schedule");
    assert_eq!(trace.stages[1].step_count, 64);
    assert_eq!(trace.stages[2].label, "round_state_00_to_19");
    assert_eq!(trace.stages[2].step_count, 20);
    assert_eq!(trace.stages[5].label, "round_state_60_to_79");
    assert_eq!(trace.stages[5].step_count, 20);
    assert_eq!(trace.stages[6].label, "output_projector");
    assert_eq!(trace.stages[6].step_count, 4);
    assert_eq!(trace.evaluator_ops.recoded_scalar_digits, 1_248);
    assert_eq!(trace.evaluator_ops.precomputed_window_bits_loaded, 16_576);
    assert_eq!(trace.evaluator_ops.bucket_accumulations, 3_296);
    assert_eq!(trace.evaluator_ops.bucket_reductions, 3_980);
    assert_eq!(trace.evaluator_ops.accumulator_curve_additions, 712);
    assert_eq!(trace.evaluator_ops.dependency_merges, 448);
    assert_eq!(trace.evaluator_ops.point_normalizations, 184);
    assert_eq!(trace.estimated_curve_cost_units, 62_748);
    assert_eq!(trace.stages[2].estimated_curve_cost_units, 10_660);
    assert_eq!(trace.stages[6].estimated_curve_cost_units, 1_004);
    assert!(trace.checksum > 0);
}

#[test]
fn prime_order_cpu_executor_executes_compiled_program() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
    let bytes =
        materialize_prime_order_size_optimized_bytes(&candidate).expect("prime-order bytes");
    let decoded =
        decode_prime_order_size_optimized_artifact(&bytes).expect("decode structured artifact");
    let program =
        compile_prime_order_cpu_execution_program(&decoded).expect("compile cpu executor");
    let result = ed25519_hss::runtime::execute_prime_order_cpu_execution_program(&program)
        .expect("execute cpu program");

    assert_eq!(program.trace.total_steps, 180);
    assert_eq!(program.trace.estimated_curve_cost_units, 62_748);
    assert_eq!(result.total_steps, 180);
    assert_eq!(
        format!("{:016x}", result.output_checksum),
        "b075ca5b7bd494fe"
    );
    assert_eq!(
        hex::encode(result.final_point_compressed),
        "21fb5139b5a491423a70a42ff2725b5991cfb110b8ee529b6c532a52b24bee36"
    );
}

#[test]
fn prime_order_cpu_executor_benchmark_smoke_test() {
    let mut config = default_prime_order_cpu_executor_benchmark_config();
    config.warmup_iterations = 0;
    config.sample_iterations = 1;
    config.sample_count = 2;

    let report =
        generate_prime_order_cpu_executor_benchmark_report(&config).expect("cpu benchmark");
    assert_eq!(report.curve_cost_units, 62_748);
    assert_eq!(report.total_steps, 180);
    assert!(report.execution_latency_ns.mean > 0.0);
    assert!(report.throughput_execs_per_sec.mean > 0.0);
    assert_eq!(report.output_checksum_hex.len(), 16);
}

#[test]
fn cache_benchmark_includes_cached_gc_stub_and_structured_prime_order_artifacts() {
    let report =
        generate_cache_benchmark_report(&default_cache_benchmark_config()).expect("report");
    assert_eq!(
        report.cached_gc_baseline_bytes,
        DEFAULT_CACHED_GC_BASELINE_BYTES
    );
    assert_eq!(report.targets.len(), 3);
    assert_eq!(report.targets[0].label, "cached_gc_baseline");
    assert_eq!(report.targets[1].label, "prime_order_stub_artifact");
    assert_eq!(report.targets[2].label, "prime_order_structured_artifact");
    assert!(report.targets[1].bytes < report.targets[0].bytes);
    assert_eq!(report.targets[1].bytes, report.targets[2].bytes);
}

#[test]
fn cache_benchmark_materialized_targets_include_bytes_and_manifests() {
    let targets = materialize_cache_benchmark_targets(&default_cache_benchmark_config())
        .expect("materialized targets");
    assert_eq!(targets.len(), 3);
    assert_eq!(targets[0].label, "cached_gc_baseline");
    assert!(targets[0].manifest_json.is_none());
    assert_eq!(targets[1].label, "prime_order_stub_artifact");
    assert!(targets[1]
        .manifest_json
        .as_deref()
        .is_some_and(|json| json.contains("chunks")));
    assert_eq!(targets[2].label, "prime_order_structured_artifact");
    assert!(targets[2]
        .manifest_json
        .as_deref()
        .is_some_and(|json| json.contains("\"encoder_version\"")));
    assert_eq!(targets[1].bytes.len(), targets[2].bytes.len());
}

#[test]
fn hidden_eval_program_compiles_expected_prime_order_ddh_shape() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
    let bytes =
        materialize_prime_order_size_optimized_bytes(&candidate).expect("prime-order bytes");
    let decoded =
        decode_prime_order_size_optimized_artifact(&bytes).expect("decode structured artifact");
    let program = compile_prime_order_hidden_eval_program(&decoded).expect("hidden-eval IR");

    assert_eq!(program.primitive_kind, HssPrimitiveKind::PrimeOrderDdh);
    assert_eq!(program.total_window_records, 262);
    assert_eq!(program.active_window_records, 180);
    assert_eq!(program.preload_round_constant_count, 80);
    assert_eq!(program.preload_context_participant_count, 2);
    assert_eq!(program.dependency_edge_count, 288);
    assert_eq!(program.stages.len(), 7);
    assert_eq!(program.stages[0].windows.len(), 32);
    assert_eq!(program.stages[1].windows.len(), 64);
    assert_eq!(program.stages[6].windows.len(), 4);
    assert_eq!(program.total_inventory.carry_chain_adders, 336);
    assert_eq!(program.total_inventory.choose_ops, 80);
    assert_eq!(program.total_inventory.majority_ops, 80);
    assert_eq!(program.total_inventory.basepoint_muls, 1);
}

#[test]
fn ddh_hss_backend_shares_adds_multiplies_and_decodes_words() {
    let fixture = first_fixture();
    let candidate =
        build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
    let bytes =
        materialize_prime_order_size_optimized_bytes(&candidate).expect("prime-order bytes");
    let decoded =
        decode_prime_order_size_optimized_artifact(&bytes).expect("decode structured artifact");
    let program = compile_prime_order_hidden_eval_program(&decoded).expect("hidden-eval IR");
    let backend = keygen_prime_order_ddh_hss_backend(
        candidate.context_binding,
        candidate.template.candidate_digest,
        &program,
    )
    .expect("DDH keygen");

    let shared_input = backend
        .share_input(HiddenEvalInputOwner::Client, "client-input", &[0x34, 0xab])
        .expect("share input");
    assert_eq!(
        backend.decode_words(&shared_input).expect("decode input"),
        vec![0x34, 0xab]
    );
    let bundle = backend
        .share_input_bundle(HiddenEvalInputOwner::Client, "client-bundle", &[0x34, 0xab])
        .expect("share input bundle");
    let (local, assist) = backend.split_share_bundle(&bundle);
    let rejoined = backend
        .join_share_bundle(&local, &assist)
        .expect("join transport bundle");
    assert_eq!(rejoined, bundle);

    let left = backend
        .share_word(HiddenEvalInputOwner::Client, "left", 0x34, 8)
        .expect("share left");
    let right = backend
        .share_word(HiddenEvalInputOwner::Server, "right", 0x29, 8)
        .expect("share right");
    let sum = backend.eval_add(&left, &right).expect("eval add");
    let product = backend.eval_mul(&left, &right).expect("eval mul");

    assert_eq!(
        backend.decode_words(&[sum.clone()]).expect("decode sum"),
        vec![0x5d]
    );
    assert_eq!(
        backend
            .decode_words(&[product.clone()])
            .expect("decode product"),
        vec![(0x34u64.wrapping_mul(0x29) & 0xff) as u8]
    );
    assert_eq!(
        backend.evaluation_key().primitive_kind,
        HssPrimitiveKind::PrimeOrderDdh
    );
    assert_eq!(backend.params().scalar_bits, 252);
    assert_ne!(sum.left_commitment, [0u8; 32]);
    assert_ne!(product.provenance_digest, [0u8; 32]);
}

#[test]
fn prime_order_succinct_hss_prepares_ddh_session() {
    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");

    assert_eq!(session.hidden_eval_program().active_window_records, 180);
    assert_eq!(
        session.hidden_eval_program().primitive_kind,
        HssPrimitiveKind::PrimeOrderDdh
    );
    assert_eq!(session.execution_program().trace.total_steps, 180);
}
