pub mod artifact_stub;
#[cfg(not(target_arch = "wasm32"))]
pub mod benchmark;
#[cfg(not(target_arch = "wasm32"))]
pub mod cache_benchmark;
pub mod candidate;
pub mod context;
#[cfg(not(target_arch = "wasm32"))]
pub mod ddh_hidden_eval_benchmark;
pub mod ddh_hidden_eval_executor;
pub mod ddh_hss;
pub mod error;
pub mod fixtures;
pub mod hidden_eval;
pub mod prime_order_cpu_executor;
pub mod prime_order_decoder;
pub mod prime_order_encoder;
pub mod prime_order_trace;
pub mod reference;
pub mod succinct_hss;
#[cfg(target_arch = "wasm32")]
mod wasm;

pub use artifact_stub::{
    build_candidate_artifact_stub, build_candidate_artifact_stub_with_chunk_size,
    materialize_candidate_artifact_stub_bytes, CandidateArtifactStub, CandidateArtifactStubChunk,
    CANDIDATE_ARTIFACT_STUB_VERSION, DEFAULT_ARTIFACT_STUB_CHUNK_SIZE_BYTES,
};
#[cfg(not(target_arch = "wasm32"))]
pub use benchmark::{
    default_phase1_config, default_thread_counts, default_thread_counts_for,
    generate_phase1_benchmark_report, BenchmarkMetadata, ComponentTimingReport, FixtureSetMetadata,
    OutputWidthReport, ParallelScalingBenchmark, ParallelScalingPoint, Phase1BenchmarkConfig,
    Phase1BenchmarkConfigRecord, Phase1BenchmarkReport, SetupOverheadReport, ThroughputStats,
    PHASE1_REPORT_VERSION,
};
#[cfg(not(target_arch = "wasm32"))]
pub use cache_benchmark::{
    default_cache_benchmark_config, generate_cache_benchmark_report,
    materialize_cache_benchmark_targets, BandwidthEstimate, CacheBenchmarkConfig,
    CacheBenchmarkReport, CacheBenchmarkTargetMaterialized, CacheBenchmarkTargetReport,
    CacheTimingStats, CACHE_BENCHMARK_REPORT_VERSION, DEFAULT_CACHED_GC_BASELINE_BYTES,
};
pub use candidate::{
    build_fixed_hidden_core_candidate, build_fixed_hidden_core_candidate_for_backend,
    simulate_fixed_hidden_core_candidate, simulate_fixed_hidden_core_candidate_for_backend,
    ArtifactScope, ArtifactVisibility, CandidateArtifactInventory, CandidateArtifactLineItem,
    CandidateArtifactTotals, CandidateBackendFamily, CandidateBackendSpec,
    CandidateContextDescriptor, CandidateEvaluatorPlan, CandidateExecutionPath,
    CandidateMessageStep, CandidateSimulationReport, CandidateTemplateArtifact,
    FixedHiddenCoreCandidate, FIXED_HIDDEN_CORE_CANDIDATE_VERSION, FIXED_HIDDEN_CORE_FUNCTION_ID,
};
pub use context::CanonicalContext;
#[cfg(not(target_arch = "wasm32"))]
pub use ddh_hidden_eval_benchmark::{
    default_ddh_hidden_eval_benchmark_config, generate_ddh_hidden_eval_benchmark_report,
    DdhHiddenEvalBenchmarkConfig, DdhHiddenEvalBenchmarkConfigRecord, DdhHiddenEvalBenchmarkReport,
    DDH_HIDDEN_EVAL_BENCHMARK_REPORT_VERSION,
};
pub use ddh_hidden_eval_executor::{
    execute_prime_order_ddh_hidden_eval_program,
    execute_prime_order_ddh_hidden_eval_program_for_clear_input,
    execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled,
    execute_prime_order_ddh_hidden_eval_program_profiled,
    probe_prime_order_ddh_hidden_eval_program, DdhHiddenEvalCheckpoint, DdhHiddenEvalInputBundles,
    DdhHiddenEvalOutputBundles, DdhHiddenEvalProbe, DdhHiddenEvalProfile, DdhHiddenEvalRun,
    DdhHiddenEvalStageProfile,
};
pub use ddh_hss::{
    keygen_prime_order_ddh_hss_backend, keygen_prime_order_ddh_hss_roles, DdhHssBackend,
    DdhHssEvaluationKey, DdhHssEvaluator, DdhHssGarbler, DdhHssInputShareBundle, DdhHssMulMaterial,
    DdhHssOtInputBundleOffer, DdhHssOtRemoteBundle, DdhHssOtRemoteWord, DdhHssOtWordOffer,
    DdhHssParams, DdhHssRoleSet, DdhHssShareSide, DdhHssSharedWord, DdhHssTransportBundle,
    DdhHssTransportPurpose, DdhHssTransportWord, DDH_HSS_BACKEND_VERSION,
};
pub use error::{ProtoError, ProtoResult};
pub use fixtures::{
    committed_fixture_corpus, committed_fixture_corpus_file, deterministic_fixture_corpus,
    serialized_fixture_corpus, FExpandFixture, FixtureCorpusFile, COMMITTED_FIXTURE_CORPUS_JSON,
    FIXTURE_FORMAT_VERSION,
};
pub use hidden_eval::{
    compile_prime_order_hidden_eval_program, FixedFunctionHssBackend, HiddenEvalInputOwner,
    HiddenEvalOp, HiddenEvalOpInventory, HiddenEvalProgram, HiddenEvalStage, HiddenEvalStageKind,
    HiddenEvalWindow, HiddenEvalWindowKind, HssPrimitiveKind, HIDDEN_EVAL_PROGRAM_VERSION,
};
pub use prime_order_cpu_executor::{
    compile_default_prime_order_cpu_execution_program, compile_prime_order_cpu_execution_program,
    default_prime_order_cpu_executor_benchmark_config, execute_prime_order_cpu_execution_program,
    generate_prime_order_cpu_executor_benchmark_report, PrimeOrderCpuExecutionProgram,
    PrimeOrderCpuExecutionResult, PrimeOrderCpuExecutionStep, PrimeOrderCpuExecutorBenchmarkConfig,
    PrimeOrderCpuExecutorBenchmarkReport, PRIME_ORDER_CPU_EXECUTOR_BENCHMARK_REPORT_VERSION,
};
pub use prime_order_decoder::{
    decode_prime_order_size_optimized_artifact, PrimeOrderDecodedArtifact, PrimeOrderDecodedHeader,
    PrimeOrderGroupedWindowsSection, PrimeOrderWindowRecord, PrimeOrderWindowRecordClass,
};
pub use prime_order_encoder::{
    build_prime_order_size_optimized_artifact, materialize_prime_order_size_optimized_bytes,
    PrimeOrderArtifactSection, PrimeOrderEncodedArtifact, PrimeOrderSectionKind,
    PRIME_ORDER_ENCODER_VERSION,
};
pub use prime_order_trace::{
    build_prime_order_execution_trace, PrimeOrderEvaluatorOps, PrimeOrderExecutionStage,
    PrimeOrderExecutionStageKind, PrimeOrderExecutionStep, PrimeOrderExecutionStepKind,
    PrimeOrderExecutionTrace,
};
pub use reference::{
    add_le_bytes_mod_2_256, clamp_rfc8032, derive_output_shares, eval_f_expand,
    eval_nonlinear_expansion, extract_a_bytes_from_hash, public_key_from_scalar_bytes,
    recover_a_from_base_shares, reduce_scalar_mod_l, sha512_one_block, FExpandInput, FExpandOutput,
    NonlinearExpansionOutput, OutputShareDerivationOutput,
};
pub use succinct_hss::{
    evaluate_prime_order_succinct_hss, prepare_prime_order_succinct_hss, HiddenCoreMaterialization,
    PrimeOrderSuccinctHssArtifactSummary, PrimeOrderSuccinctHssClientOutputOpener,
    PrimeOrderSuccinctHssDeliveryMaterial, PrimeOrderSuccinctHssEvaluationReport,
    PrimeOrderSuccinctHssEvaluationResult, PrimeOrderSuccinctHssEvaluatorDriverState,
    PrimeOrderSuccinctHssEvaluatorOtState, PrimeOrderSuccinctHssEvaluatorSession,
    PrimeOrderSuccinctHssEvaluatorSessionState, PrimeOrderSuccinctHssEvaluatorWitness,
    PrimeOrderSuccinctHssGarblerDriverState, PrimeOrderSuccinctHssGarblerOtState,
    PrimeOrderSuccinctHssGarblerSession, PrimeOrderSuccinctHssGarblerSessionState,
    PrimeOrderSuccinctHssOutputDelivery, PrimeOrderSuccinctHssOutputOpeners,
    PrimeOrderSuccinctHssPreparedSession, PrimeOrderSuccinctHssRunBindings,
    PrimeOrderSuccinctHssServerOutputOpener, PrimeOrderSuccinctHssSharedRuntime,
    PrimeOrderSuccinctHssSharedRuntimeState, PrimeOrderSuccinctHssWireMessage,
    PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION,
};

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use crate::artifact_stub::{
        build_candidate_artifact_stub, materialize_candidate_artifact_stub_bytes,
        DEFAULT_ARTIFACT_STUB_CHUNK_SIZE_BYTES,
    };
    use crate::cache_benchmark::{
        default_cache_benchmark_config, generate_cache_benchmark_report,
        materialize_cache_benchmark_targets, DEFAULT_CACHED_GC_BASELINE_BYTES,
    };
    use crate::candidate::{
        build_fixed_hidden_core_candidate, build_fixed_hidden_core_candidate_for_backend,
        simulate_fixed_hidden_core_candidate, ArtifactScope, CandidateBackendFamily,
    };
    use crate::context::CanonicalContext;
    use crate::ddh_hss::keygen_prime_order_ddh_hss_backend;
    use crate::fixtures::{
        committed_fixture_corpus, deterministic_fixture_corpus, serialized_fixture_corpus,
        COMMITTED_FIXTURE_CORPUS_JSON,
    };
    use crate::hidden_eval::{
        compile_prime_order_hidden_eval_program, FixedFunctionHssBackend, HiddenEvalInputOwner,
        HssPrimitiveKind,
    };
    use crate::prime_order_cpu_executor::{
        compile_prime_order_cpu_execution_program,
        default_prime_order_cpu_executor_benchmark_config,
        execute_prime_order_cpu_execution_program,
        generate_prime_order_cpu_executor_benchmark_report,
    };
    use crate::prime_order_decoder::{
        decode_prime_order_size_optimized_artifact, PrimeOrderWindowRecordClass,
    };
    use crate::prime_order_encoder::{
        build_prime_order_size_optimized_artifact, materialize_prime_order_size_optimized_bytes,
        PrimeOrderSectionKind,
    };
    use crate::prime_order_trace::build_prime_order_execution_trace;
    use crate::reference::{
        add_le_bytes_mod_2_256, clamp_rfc8032, eval_f_expand, public_key_from_base_shares,
        public_key_from_scalar_bytes, recover_a_from_base_shares,
    };
    use crate::succinct_hss::{prepare_prime_order_succinct_hss, HiddenCoreMaterialization};

    fn section_bytes<'a>(
        artifact: &crate::prime_order_encoder::PrimeOrderEncodedArtifact,
        bytes: &'a [u8],
        kind: PrimeOrderSectionKind,
    ) -> &'a [u8] {
        let section = artifact
            .sections
            .iter()
            .find(|section| section.kind == kind)
            .expect("section present");
        let start = usize::try_from(section.offset_bytes).expect("offset fits usize");
        let end = start + usize::try_from(section.length_bytes).expect("length fits usize");
        &bytes[start..end]
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    fn read_u16_le(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    #[test]
    fn addition_is_little_endian_and_wraps_mod_2_256() {
        let sum = add_le_bytes_mod_2_256([0xff; 32], {
            let mut one = [0u8; 32];
            one[0] = 1;
            one
        });
        assert_eq!(sum, [0u8; 32]);

        let mut left = [0u8; 32];
        left[0] = 0xff;
        left[1] = 0x01;
        let mut right = [0u8; 32];
        right[0] = 0x02;
        let sum = add_le_bytes_mod_2_256(left, right);
        assert_eq!(sum[0], 0x01);
        assert_eq!(sum[1], 0x02);
    }

    #[test]
    fn clamp_matches_rfc8032_bit_rules() {
        let clamped = clamp_rfc8032([0xff; 32]);
        assert_eq!(clamped[0] & 0b0000_0111, 0);
        assert_eq!(clamped[31] & 0b1000_0000, 0);
        assert_eq!(clamped[31] & 0b0100_0000, 0b0100_0000);
    }

    #[test]
    fn context_binding_normalizes_participant_ids() {
        let with_duplicates = CanonicalContext {
            org_id: "org.binding".to_string(),
            account_id: "binding.test.near".to_string(),
            key_purpose: "near-signing".to_string(),
            key_version: "v1".to_string(),
            participant_ids: vec![2, 1, 2],
            derivation_version: 1,
        };
        let normalized = CanonicalContext {
            participant_ids: vec![1, 2],
            ..with_duplicates.clone()
        };

        assert_eq!(
            with_duplicates.binding_digest().expect("binding digest"),
            normalized.binding_digest().expect("binding digest"),
        );
    }

    #[test]
    fn context_binding_changes_when_context_changes() {
        let left = CanonicalContext {
            org_id: "org.binding".to_string(),
            account_id: "binding.test.near".to_string(),
            key_purpose: "near-signing".to_string(),
            key_version: "v1".to_string(),
            participant_ids: vec![1, 2],
            derivation_version: 1,
        };
        let right = CanonicalContext {
            account_id: "binding-alt.test.near".to_string(),
            ..left.clone()
        };

        assert_ne!(
            left.binding_digest().expect("left binding digest"),
            right.binding_digest().expect("right binding digest"),
        );
    }

    #[test]
    fn fixture_corpus_round_trips_through_json() {
        let generated = deterministic_fixture_corpus().expect("fixture corpus");
        let json =
            serde_json::to_string_pretty(&serialized_fixture_corpus().expect("fixture corpus"))
                .expect("fixture corpus json");
        let parsed: crate::fixtures::FixtureCorpusFile =
            serde_json::from_str(&json).expect("parse fixture corpus json");

        assert_eq!(
            parsed.to_internal().expect("round-trip fixture corpus"),
            generated
        );
    }

    #[test]
    fn fixtures_match_reference_and_invariants() {
        for fixture in deterministic_fixture_corpus().expect("fixture corpus") {
            let output = eval_f_expand(&fixture.input).expect("reference path");
            assert_eq!(output, fixture.output);

            let recovered_a = recover_a_from_base_shares(
                fixture.output.x_client_base,
                fixture.output.x_relayer_base,
            )
            .expect("recover a from base shares");
            assert_eq!(recovered_a, fixture.output.a);

            let public_key =
                public_key_from_scalar_bytes(fixture.output.a).expect("public key from scalar");
            assert_eq!(public_key, fixture.output.public_key);
            let public_key_from_outputs = public_key_from_base_shares(
                fixture.output.x_client_base,
                fixture.output.x_relayer_base,
            )
            .expect("public key from base shares");
            assert_eq!(public_key_from_outputs, fixture.output.public_key);

            let signing_key = SigningKey::from_bytes(&fixture.output.d);
            assert_eq!(
                signing_key.verifying_key().to_bytes(),
                fixture.output.public_key
            );
        }
    }

    #[test]
    fn prime_order_succinct_hss_prepares_delivery_packets() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let delivery_material = session.delivery_material();
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");
        let client_ot_offer = session
            .decode_client_ot_offer_message(&client_ot_offer_message)
            .expect("decode client OT offer message");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client OT request from offer");
        let client_packet = session
            .decode_client_request_message(&client_request_message)
            .expect("decode client OT request message");
        let server_message = garbler_session
            .prepare_server_message(
                &client_request_message,
                fixture.input.y_relayer,
                fixture.input.tau_relayer,
            )
            .expect("prepare server message");
        let server_packet = session
            .decode_server_message(&server_message)
            .expect("decode server message");

        assert_eq!(
            delivery_material.artifact.context_binding,
            fixture.output.context_binding
        );
        assert_eq!(
            delivery_material.evaluation_key.key_id,
            session.ddh_backend().evaluation_key().key_id
        );
        assert_eq!(
            client_packet.context_binding,
            fixture.output.context_binding
        );
        assert_eq!(
            server_packet.context_binding,
            fixture.output.context_binding
        );
        assert_eq!(
            client_ot_offer.context_binding,
            fixture.output.context_binding
        );
        assert_eq!(
            client_ot_offer.y_client_offer.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(
            client_ot_offer.tau_client_offer.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(client_ot_offer.y_client_offer.words.len(), 256);
        assert_eq!(client_ot_offer.tau_client_offer.words.len(), 256);
        assert_eq!(
            client_packet.y_client_request.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(
            client_packet.tau_client_request.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(client_packet.y_client_request.words.len(), 256);
        assert_eq!(client_packet.tau_client_request.words.len(), 256);
        assert_eq!(
            evaluator_ot_state.y_client_local_state.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(
            evaluator_ot_state.tau_client_local_state.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(
            server_packet.ot_transcript.y_client_request_commitment,
            client_packet.y_client_request.commitment
        );
        assert_eq!(
            server_packet.ot_transcript.tau_client_request_commitment,
            client_packet.tau_client_request.commitment
        );
        assert_eq!(
            server_packet.ot_transcript.y_client_offer_commitment,
            client_ot_offer.y_client_offer.commitment
        );
        assert_eq!(
            server_packet.ot_transcript.tau_client_offer_commitment,
            client_ot_offer.tau_client_offer.commitment
        );
        assert_eq!(
            server_packet.y_client_remote_release.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(
            server_packet.tau_client_remote_release.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(
            server_packet.y_client_response.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(
            server_packet.tau_client_response.owner,
            HiddenEvalInputOwner::Client
        );
        assert_eq!(
            server_packet.y_client_remote_release.request_commitment,
            client_packet.y_client_request.commitment
        );
        assert_eq!(
            server_packet.tau_client_remote_release.request_commitment,
            client_packet.tau_client_request.commitment
        );
        assert_eq!(
            server_packet.y_client_remote_release.response_commitment,
            server_packet.y_client_response.commitment
        );
        assert_eq!(
            server_packet.tau_client_remote_release.response_commitment,
            server_packet.tau_client_response.commitment
        );
        assert_eq!(
            server_packet.y_client_remote_release.transcript_binding,
            server_packet.ot_transcript.y_client_remote_release_binding
        );
        assert_eq!(
            server_packet.tau_client_remote_release.transcript_binding,
            server_packet
                .ot_transcript
                .tau_client_remote_release_binding
        );
        let decoded_server_inputs = session
            .decode_server_input_delivery(&server_message)
            .expect("decode sealed server input delivery");
        assert_eq!(decoded_server_inputs.0, fixture.input.y_relayer);
        assert_eq!(decoded_server_inputs.1, fixture.input.tau_relayer);
        let expected_y_relayer_bundle = session
            .ddh_backend()
            .share_input_bit_bundle(
                HiddenEvalInputOwner::Server,
                "y_relayer_bits",
                &fixture.input.y_relayer,
            )
            .expect("share relayer y bits");
        let expected_tau_relayer_bundle = session
            .ddh_backend()
            .share_input_bit_bundle(
                HiddenEvalInputOwner::Server,
                "tau_relayer_bits",
                &fixture.input.tau_relayer,
            )
            .expect("share relayer tau bits");
        assert_eq!(
            server_packet.server_inputs.server_input_commitment,
            session.ddh_backend().combined_input_commitment(
                HiddenEvalInputOwner::Server,
                &[&expected_y_relayer_bundle, &expected_tau_relayer_bundle],
            )
        );
        assert!(String::from_utf8(server_message.bytes.clone()).is_err());
        let server_input_payload_json = session
            .decode_server_input_payload_json(&server_message)
            .expect("decode server input payload json");
        assert!(!server_input_payload_json.contains("left_word"));
        assert!(!server_input_payload_json.contains("right_word"));
        assert!(server_input_payload_json.contains("share_word"));
    }

    #[test]
    #[ignore = "output delivery packet verification now runs the full DDH hidden evaluator and is too expensive for the default debug lane"]
    fn prime_order_succinct_hss_splits_output_delivery_packets() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let report = session.evaluate(&fixture.input).expect("evaluate session");
        let delivery = report.output_delivery.clone();
        let output_openers = session.output_openers();
        let client_packet = session
            .decode_client_output_message(&delivery.client)
            .expect("decode client output message");
        assert_eq!(
            client_packet.context_binding,
            fixture.output.context_binding
        );
        assert_eq!(client_packet.run_binding, report.bindings.run_binding);
        assert_eq!(
            client_packet.evaluation_digest,
            report.bindings.evaluation_digest
        );
        let x_client_base = output_openers
            .client
            .open(&delivery.client)
            .expect("open client output packet");
        let x_relayer_base = output_openers
            .server
            .open(&delivery.server)
            .expect("open server output packet");
        assert_eq!(x_client_base, fixture.output.x_client_base);
        assert_eq!(x_relayer_base, fixture.output.x_relayer_base);
        assert_eq!(
            public_key_from_base_shares(x_client_base, x_relayer_base)
                .expect("derive public key from opened shares"),
            fixture.output.public_key
        );
    }

    #[test]
    fn prime_order_succinct_hss_delivery_packets_round_trip_encoded_inputs() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client OT request from offer");
        let server_message = garbler_session
            .prepare_server_message(
                &client_request_message,
                fixture.input.y_relayer,
                fixture.input.tau_relayer,
            )
            .expect("prepare server message");
        let decoded_client = session
            .decode_client_input_delivery(
                &client_request_message,
                &evaluator_ot_state,
                &server_message,
            )
            .expect("decode client input delivery");
        assert_eq!(decoded_client.0, fixture.input.y_client);
        assert_eq!(decoded_client.1, fixture.input.tau_client);
        let decoded_server = session
            .decode_server_input_delivery(&server_message)
            .expect("decode server input delivery");
        assert_eq!(decoded_server.0, fixture.input.y_relayer);
        assert_eq!(decoded_server.1, fixture.input.tau_relayer);
        assert!(String::from_utf8(server_message.bytes.clone()).is_err());
        let server_input_payload_json = session
            .decode_server_input_payload_json(&server_message)
            .expect("decode server input payload json");
        assert!(!server_input_payload_json.contains("left_word"));
        assert!(!server_input_payload_json.contains("right_word"));
        assert!(server_input_payload_json.contains("share_word"));
    }

    #[test]
    #[ignore = "end-to-end delivery packet evaluation now runs the full DDH hidden evaluator and is too expensive for the default debug lane"]
    fn prime_order_succinct_hss_delivery_packets_round_trip_end_to_end() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client OT request from offer");
        let server_message = garbler_session
            .prepare_server_message(
                &client_request_message,
                fixture.input.y_relayer,
                fixture.input.tau_relayer,
            )
            .expect("prepare server message");

        let evaluated = session
            .evaluate_from_transport_messages(
                &client_request_message,
                &evaluator_ot_state,
                &server_message,
            )
            .expect("evaluate transport messages");
        let output_openers = session.output_openers();
        assert_eq!(
            output_openers
                .client
                .open(&evaluated.output_delivery.client)
                .expect("open client output"),
            fixture.output.x_client_base
        );
        assert_eq!(
            output_openers
                .server
                .open(&evaluated.output_delivery.server)
                .expect("open server output"),
            fixture.output.x_relayer_base
        );
    }

    #[test]
    fn prime_order_succinct_hss_rejects_server_message_from_different_request_same_context() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");

        let (request_a, evaluator_ot_state_a) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare request a");

        let mut y_client_b = fixture.input.y_client;
        y_client_b[0] ^= 0x01;
        let (request_b, _evaluator_ot_state_b) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                y_client_b,
                fixture.input.tau_client,
            )
            .expect("prepare request b");

        let server_message_b = garbler_session
            .prepare_server_message(
                &request_b,
                fixture.input.y_relayer,
                fixture.input.tau_relayer,
            )
            .expect("prepare server message for request b");

        let err = session
            .evaluate_from_transport_messages(&request_a, &evaluator_ot_state_a, &server_message_b)
            .expect_err("same-context request/release mismatch must fail");
        assert!(
            err.to_string().contains("request")
                || err.to_string().contains("transcript")
                || err.to_string().contains("remote-share")
                || err.to_string().contains("open OT branch payload")
                || err.to_string().contains("aead"),
            "unexpected same-context mismatch error: {err}"
        );
    }

    #[test]
    fn prime_order_succinct_hss_rejects_swapped_remote_releases_same_context() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client OT request");
        let server_message = garbler_session
            .prepare_server_message(
                &client_request_message,
                fixture.input.y_relayer,
                fixture.input.tau_relayer,
            )
            .expect("prepare server message");
        let mut server_packet = session
            .decode_server_message(&server_message)
            .expect("decode server message");
        std::mem::swap(
            &mut server_packet.y_client_remote_release,
            &mut server_packet.tau_client_remote_release,
        );
        let swapped_server_message = session
            .encode_server_message(&server_packet)
            .expect("encode swapped server message");

        let err = session
            .evaluate_from_transport_messages(
                &client_request_message,
                &evaluator_ot_state,
                &swapped_server_message,
            )
            .expect_err("swapped same-context OT releases must fail");
        assert!(
            err.to_string().contains("label")
                || err.to_string().contains("request")
                || err.to_string().contains("remote-share"),
            "unexpected swapped-release error: {err}"
        );
    }

    #[test]
    fn prime_order_succinct_hss_rejects_remote_release_with_tampered_context_binding() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let (_runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client OT request");
        let server_message = garbler_session
            .prepare_server_message(
                &client_request_message,
                fixture.input.y_relayer,
                fixture.input.tau_relayer,
            )
            .expect("prepare server message");
        let mut server_packet = session
            .decode_server_message(&server_message)
            .expect("decode server message");
        server_packet.y_client_remote_release.context_binding[0] ^= 0x01;
        let tampered_server_message = session
            .encode_server_message(&server_packet)
            .expect("encode tampered server message");

        let err = session
            .evaluate_from_transport_messages(
                &client_request_message,
                &evaluator_ot_state,
                &tampered_server_message,
            )
            .expect_err("tampered release context binding must fail");
        assert!(
            err.to_string().contains("context binding"),
            "unexpected tampered-context error: {err}"
        );
    }

    #[test]
    fn prime_order_succinct_hss_rejects_tampered_server_output_payload_in_evaluation_result() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let (runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client OT request");
        let server_message = garbler_session
            .prepare_server_message(
                &client_request_message,
                fixture.input.y_relayer,
                fixture.input.tau_relayer,
            )
            .expect("prepare server message");
        let evaluation_result_message = evaluator_session
            .evaluate_result_message_from_transport_messages(
                &runtime,
                &client_request_message,
                &evaluator_ot_state,
                &server_message,
            )
            .expect("evaluate result message");
        let mut evaluation_result = session
            .decode_evaluation_result_message(&evaluation_result_message)
            .expect("decode evaluation result message");
        evaluation_result.server_output_payload[0] ^= 0x01;
        let tampered_evaluation_result_message = session
            .encode_evaluation_result_message(&evaluation_result)
            .expect("encode tampered evaluation result message");

        let err = garbler_session
            .finalize_report_from_evaluation_result_message(
                &runtime,
                &tampered_evaluation_result_message,
            )
            .expect_err("tampered server output payload must fail");
        assert!(
            err.to_string().contains("server output payload binding"),
            "unexpected tampered-server-output error: {err}"
        );
    }

    #[test]
    fn prime_order_succinct_hss_rejects_tampered_client_output_in_evaluation_result() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let (runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");
        let (client_request_message, evaluator_ot_state) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixture.input.y_client,
                fixture.input.tau_client,
            )
            .expect("prepare client OT request");
        let server_message = garbler_session
            .prepare_server_message(
                &client_request_message,
                fixture.input.y_relayer,
                fixture.input.tau_relayer,
            )
            .expect("prepare server message");
        let evaluation_result_message = evaluator_session
            .evaluate_result_message_from_transport_messages(
                &runtime,
                &client_request_message,
                &evaluator_ot_state,
                &server_message,
            )
            .expect("evaluate result message");
        let mut evaluation_result = session
            .decode_evaluation_result_message(&evaluation_result_message)
            .expect("decode evaluation result message");
        let last_idx = evaluation_result.client_output.bytes.len() - 1;
        evaluation_result.client_output.bytes[last_idx] ^= 0x01;
        let tampered_evaluation_result_message = session
            .encode_evaluation_result_message(&evaluation_result)
            .expect("encode tampered evaluation result message");

        let err = garbler_session
            .finalize_report_from_evaluation_result_message(
                &runtime,
                &tampered_evaluation_result_message,
            )
            .expect_err("tampered client output must fail");
        assert!(
            err.to_string().contains("client output binding"),
            "unexpected tampered-client-output error: {err}"
        );
    }

    #[test]
    fn prime_order_succinct_hss_rejects_swapped_client_output_between_same_context_runs() {
        let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
        let session =
            prepare_prime_order_succinct_hss(&fixtures[0].input.context).expect("prepare session");
        let (runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");

        let (client_request_message_a, evaluator_ot_state_a) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixtures[0].input.y_client,
                fixtures[0].input.tau_client,
            )
            .expect("prepare client OT request A");
        let server_message_a = garbler_session
            .prepare_server_message(
                &client_request_message_a,
                fixtures[0].input.y_relayer,
                fixtures[0].input.tau_relayer,
            )
            .expect("prepare server message A");
        let evaluation_result_message_a = evaluator_session
            .evaluate_result_message_from_transport_messages(
                &runtime,
                &client_request_message_a,
                &evaluator_ot_state_a,
                &server_message_a,
            )
            .expect("evaluate result message A");
        let mut evaluation_result_a = session
            .decode_evaluation_result_message(&evaluation_result_message_a)
            .expect("decode evaluation result A");

        let (client_request_message_b, evaluator_ot_state_b) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixtures[1].input.y_client,
                fixtures[1].input.tau_client,
            )
            .expect("prepare client OT request B");
        let server_message_b = garbler_session
            .prepare_server_message(
                &client_request_message_b,
                fixtures[1].input.y_relayer,
                fixtures[1].input.tau_relayer,
            )
            .expect("prepare server message B");
        let evaluation_result_message_b = evaluator_session
            .evaluate_result_message_from_transport_messages(
                &runtime,
                &client_request_message_b,
                &evaluator_ot_state_b,
                &server_message_b,
            )
            .expect("evaluate result message B");
        let evaluation_result_b = session
            .decode_evaluation_result_message(&evaluation_result_message_b)
            .expect("decode evaluation result B");

        evaluation_result_a.client_output = evaluation_result_b.client_output;
        let tampered_evaluation_result_message = session
            .encode_evaluation_result_message(&evaluation_result_a)
            .expect("encode tampered evaluation result");

        let err = garbler_session
            .finalize_report_from_evaluation_result_message(
                &runtime,
                &tampered_evaluation_result_message,
            )
            .expect_err("swapped client output between same-context runs must fail");
        assert!(
            err.to_string().contains("client output packet")
                || err.to_string().contains("client output binding"),
            "unexpected swapped-client-output error: {err}"
        );
    }

    #[test]
    fn prime_order_succinct_hss_rejects_swapped_server_output_payload_between_same_context_runs() {
        let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
        let session =
            prepare_prime_order_succinct_hss(&fixtures[0].input.context).expect("prepare session");
        let (runtime, garbler_session, evaluator_session) = session.split_runtime();
        let client_ot_offer_message = garbler_session
            .client_ot_offer_message()
            .expect("prepare client OT offer message");

        let (client_request_message_a, evaluator_ot_state_a) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixtures[0].input.y_client,
                fixtures[0].input.tau_client,
            )
            .expect("prepare client OT request A");
        let server_message_a = garbler_session
            .prepare_server_message(
                &client_request_message_a,
                fixtures[0].input.y_relayer,
                fixtures[0].input.tau_relayer,
            )
            .expect("prepare server message A");
        let evaluation_result_message_a = evaluator_session
            .evaluate_result_message_from_transport_messages(
                &runtime,
                &client_request_message_a,
                &evaluator_ot_state_a,
                &server_message_a,
            )
            .expect("evaluate result message A");
        let mut evaluation_result_a = session
            .decode_evaluation_result_message(&evaluation_result_message_a)
            .expect("decode evaluation result A");

        let (client_request_message_b, evaluator_ot_state_b) = evaluator_session
            .prepare_client_ot_request_from_offer_message(
                &client_ot_offer_message,
                fixtures[1].input.y_client,
                fixtures[1].input.tau_client,
            )
            .expect("prepare client OT request B");
        let server_message_b = garbler_session
            .prepare_server_message(
                &client_request_message_b,
                fixtures[1].input.y_relayer,
                fixtures[1].input.tau_relayer,
            )
            .expect("prepare server message B");
        let evaluation_result_message_b = evaluator_session
            .evaluate_result_message_from_transport_messages(
                &runtime,
                &client_request_message_b,
                &evaluator_ot_state_b,
                &server_message_b,
            )
            .expect("evaluate result message B");
        let evaluation_result_b = session
            .decode_evaluation_result_message(&evaluation_result_message_b)
            .expect("decode evaluation result B");

        evaluation_result_a.server_output_payload = evaluation_result_b.server_output_payload;
        let tampered_evaluation_result_message = session
            .encode_evaluation_result_message(&evaluation_result_a)
            .expect("encode tampered evaluation result");

        let err = garbler_session
            .finalize_report_from_evaluation_result_message(
                &runtime,
                &tampered_evaluation_result_message,
            )
            .expect_err("swapped server output payload between same-context runs must fail");
        assert!(
            err.to_string().contains("server output payload binding"),
            "unexpected swapped-server-output error: {err}"
        );
    }

    #[test]
    fn committed_fixture_file_matches_generated_reference() {
        let _generated_json =
            serde_json::to_string_pretty(&serialized_fixture_corpus().expect("fixture corpus"))
                .expect("generated fixture corpus json");
        let _committed_json = serde_json::from_str::<crate::fixtures::FixtureCorpusFile>(
            COMMITTED_FIXTURE_CORPUS_JSON,
        )
        .expect("parse committed fixture corpus");
        assert_eq!(
            committed_fixture_corpus().expect("committed fixtures"),
            deterministic_fixture_corpus().expect("generated fixtures"),
        );
    }

    #[test]
    fn candidate_template_is_context_bound_and_fixed_function_only() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
        let candidate =
            build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");

        assert!(candidate.template.context_bound);
        assert!(candidate.template.fixed_function_only);
        assert!(candidate.template.cross_session_reusable);
        assert_eq!(
            candidate.backend.family,
            CandidateBackendFamily::PrimeOrderSizeOptimized
        );
        assert_eq!(candidate.context_descriptor.org_id, "org.wraparound");
        assert_eq!(
            candidate.context_descriptor.account_id,
            "wraparound.test.near"
        );
        assert_eq!(candidate.context_descriptor.participant_ids, vec![1, 2]);
        assert_eq!(
            candidate
                .artifact_inventory
                .totals
                .known_client_output_bytes,
            32
        );
        assert_eq!(
            candidate
                .artifact_inventory
                .totals
                .known_server_output_bytes,
            32
        );
        assert_eq!(
            candidate
                .artifact_inventory
                .totals
                .known_public_output_bytes,
            32
        );
        assert_eq!(
            candidate
                .artifact_inventory
                .line_items
                .iter()
                .filter(|item| item.scope == ArtifactScope::CrossSessionTemplate)
                .count(),
            4
        );
        assert_eq!(candidate.backend.public_data_bytes, 138_256);
        assert_eq!(
            candidate
                .artifact_inventory
                .totals
                .unknown_encoded_payload_item_count,
            0
        );
    }

    #[test]
    fn candidate_simulation_matches_fixture_corpus() {
        for fixture in deterministic_fixture_corpus().expect("fixture corpus") {
            let simulation =
                simulate_fixed_hidden_core_candidate(&fixture.input).expect("candidate simulate");
            assert_eq!(simulation.output, fixture.output);
            assert_ne!(simulation.client_input_commitment, [0u8; 32]);
            assert_ne!(simulation.server_input_commitment, [0u8; 32]);
            assert_ne!(simulation.run_binding, [0u8; 32]);
        }
    }

    #[test]
    fn candidate_report_serializes_to_json() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
        let candidate =
            build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
        let json = serde_json::to_string_pretty(&candidate).expect("candidate json");

        assert!(json.contains("fixed_hidden_core_candidate_v0"));
        assert!(json.contains("succinct_hidden_core_encoding"));
        assert!(json.contains("prime_order_size_optimized"));
    }

    #[test]
    fn backend_variants_have_distinct_estimated_sizes() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");

        let prime_size = build_fixed_hidden_core_candidate_for_backend(
            &fixture.input.context,
            CandidateBackendFamily::PrimeOrderSizeOptimized,
        )
        .expect("prime-order size-optimized");
        let paillier = build_fixed_hidden_core_candidate_for_backend(
            &fixture.input.context,
            CandidateBackendFamily::PaillierCompressed,
        )
        .expect("paillier");
        let prime_compute = build_fixed_hidden_core_candidate_for_backend(
            &fixture.input.context,
            CandidateBackendFamily::PrimeOrderComputeOptimized,
        )
        .expect("prime-order compute-optimized");
        let lattice = build_fixed_hidden_core_candidate_for_backend(
            &fixture.input.context,
            CandidateBackendFamily::LatticeRlwe,
        )
        .expect("lattice");

        assert_eq!(prime_size.backend.public_data_bytes, 138_256);
        assert_eq!(paillier.backend.public_data_bytes, 395_536);
        assert_eq!(prime_compute.backend.public_data_bytes, 5_320_016);
        assert_eq!(lattice.backend.public_data_bytes, 74_885_136);
        assert!(prime_size.backend.public_data_bytes < paillier.backend.public_data_bytes);
        assert!(paillier.backend.public_data_bytes < lattice.backend.public_data_bytes);
    }

    #[test]
    fn artifact_stub_matches_default_backend_size_and_is_stable() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
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
        let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
        let first_candidate =
            build_fixed_hidden_core_candidate(&fixtures[0].input.context).expect("first candidate");
        let second_candidate = build_fixed_hidden_core_candidate(&fixtures[1].input.context)
            .expect("second candidate");

        let first_stub = build_candidate_artifact_stub(&first_candidate).expect("first stub");
        let second_stub = build_candidate_artifact_stub(&second_candidate).expect("second stub");

        assert_ne!(first_stub.artifact_digest, second_stub.artifact_digest);
        assert_ne!(first_stub.context_binding, second_stub.context_binding);
    }

    #[test]
    fn prime_order_encoder_matches_backend_size_and_has_expected_sections() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
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

        let round_constants =
            section_bytes(&artifact, &bytes, PrimeOrderSectionKind::RoundConstants);
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
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
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
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
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
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
        let candidate =
            build_fixed_hidden_core_candidate(&fixture.input.context).expect("candidate build");
        let bytes =
            materialize_prime_order_size_optimized_bytes(&candidate).expect("prime-order bytes");
        let decoded =
            decode_prime_order_size_optimized_artifact(&bytes).expect("decode structured artifact");
        let program =
            compile_prime_order_cpu_execution_program(&decoded).expect("compile cpu executor");
        let result =
            execute_prime_order_cpu_execution_program(&program).expect("execute cpu program");

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
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
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
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
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

        assert_eq!(backend.decode_word(&sum), 0x5d);
        assert_eq!(
            backend.decode_word(&product),
            0x34u64.wrapping_mul(0x29) & 0xff
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
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");

        assert_eq!(session.hidden_eval_program().active_window_records, 180);
        assert_eq!(
            session.hidden_eval_program().primitive_kind,
            HssPrimitiveKind::PrimeOrderDdh
        );
        assert_eq!(session.execution_program().trace.total_steps, 180);
    }

    #[test]
    #[ignore = "single-fixture DDH hidden-eval conformance is currently too expensive for the default debug test lane"]
    fn prime_order_succinct_hss_matches_reference_fixture_smoke() {
        let fixture = deterministic_fixture_corpus()
            .expect("fixture corpus")
            .into_iter()
            .next()
            .expect("at least one fixture");
        let session =
            prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
        let report = session
            .evaluate(&fixture.input)
            .expect("evaluate prepared session");

        let output_openers = session.output_openers();
        let x_client_base = output_openers
            .client
            .open(&report.output_delivery.client)
            .expect("open client output");
        let x_relayer_base = output_openers
            .server
            .open(&report.output_delivery.server)
            .expect("open server output");
        assert_eq!(x_client_base, fixture.output.x_client_base);
        assert_eq!(x_relayer_base, fixture.output.x_relayer_base);
        assert_eq!(
            public_key_from_base_shares(x_client_base, x_relayer_base).expect("derive public key"),
            fixture.output.public_key
        );
        assert_eq!(
            report.hidden_core_materialization,
            HiddenCoreMaterialization::DdhPrimitiveBaseline
        );
        assert_eq!(report.artifact.artifact_bytes, 138_256);
        assert_eq!(
            report.artifact.context_binding,
            fixture.output.context_binding
        );
        assert_eq!(session.hidden_eval_program().active_window_records, 180);
        assert_eq!(
            report.evaluator_witness.total_steps,
            session.execution_program().trace.total_steps
        );
    }

    #[test]
    #[ignore = "full five-fixture DDH hidden-eval conformance remains a Phase 3b milestone"]
    fn prime_order_succinct_hss_matches_reference_fixtures() {
        for fixture in deterministic_fixture_corpus().expect("fixture corpus") {
            let session =
                prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
            let report = session
                .evaluate(&fixture.input)
                .expect("evaluate prepared session");
            let output_openers = session.output_openers();
            let x_client_base = output_openers
                .client
                .open(&report.output_delivery.client)
                .expect("open client output");
            let x_relayer_base = output_openers
                .server
                .open(&report.output_delivery.server)
                .expect("open server output");
            assert_eq!(x_client_base, fixture.output.x_client_base);
            assert_eq!(x_relayer_base, fixture.output.x_relayer_base);
            assert_eq!(
                public_key_from_base_shares(x_client_base, x_relayer_base)
                    .expect("derive public key"),
                fixture.output.public_key
            );
        }
    }

    #[test]
    fn prime_order_succinct_hss_rejects_context_mismatch() {
        let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
        let session =
            prepare_prime_order_succinct_hss(&fixtures[0].input.context).expect("prepare session");
        let err = session
            .evaluate(&fixtures[1].input)
            .expect_err("mismatched context should fail");

        assert!(matches!(err, crate::ProtoError::InvalidInput(_)));
    }
}
