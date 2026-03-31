pub mod artifact;
pub mod artifact_stub;
#[cfg(not(target_arch = "wasm32"))]
pub mod benchmark;
pub mod candidate;
pub mod context;
pub mod ddh;
pub mod error;
pub mod fixtures;
pub mod protocol;
pub mod reference;
pub mod runtime;

pub use artifact::{
    build_prime_order_execution_trace, build_prime_order_size_optimized_artifact,
    decode_prime_order_size_optimized_artifact, materialize_prime_order_size_optimized_bytes,
    PrimeOrderArtifactSection, PrimeOrderDecodedArtifact, PrimeOrderDecodedHeader,
    PrimeOrderEncodedArtifact, PrimeOrderEvaluatorOps, PrimeOrderExecutionStage,
    PrimeOrderExecutionStageKind, PrimeOrderExecutionStep, PrimeOrderExecutionStepKind,
    PrimeOrderExecutionTrace, PrimeOrderGroupedWindowsSection, PrimeOrderSectionKind,
    PrimeOrderWindowRecord, PrimeOrderWindowRecordClass, PRIME_ORDER_ENCODER_VERSION,
};
pub use artifact_stub::{
    build_candidate_artifact_stub, build_candidate_artifact_stub_with_chunk_size,
    materialize_candidate_artifact_stub_bytes, CandidateArtifactStub, CandidateArtifactStubChunk,
    CANDIDATE_ARTIFACT_STUB_VERSION, DEFAULT_ARTIFACT_STUB_CHUNK_SIZE_BYTES,
};
#[cfg(not(target_arch = "wasm32"))]
pub use benchmark::{
    default_cache_benchmark_config, default_ddh_hidden_eval_benchmark_config,
    default_phase1_config, default_thread_counts, default_thread_counts_for,
    generate_cache_benchmark_report, generate_ddh_hidden_eval_benchmark_report,
    generate_phase1_benchmark_report, materialize_cache_benchmark_targets, BandwidthEstimate,
    BenchmarkMetadata, CacheBenchmarkConfig, CacheBenchmarkReport,
    CacheBenchmarkTargetMaterialized, CacheBenchmarkTargetReport, CacheTimingStats,
    ComponentTimingReport, DdhHiddenEvalBenchmarkConfig, DdhHiddenEvalBenchmarkConfigRecord,
    DdhHiddenEvalBenchmarkReport, FixtureSetMetadata, OutputWidthReport, ParallelScalingBenchmark,
    ParallelScalingPoint, Phase1BenchmarkConfig, Phase1BenchmarkConfigRecord,
    Phase1BenchmarkReport, SetupOverheadReport, ThroughputStats, CACHE_BENCHMARK_REPORT_VERSION,
    DDH_HIDDEN_EVAL_BENCHMARK_REPORT_VERSION, DEFAULT_CACHED_GC_BASELINE_BYTES,
    PHASE1_REPORT_VERSION,
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
pub use ddh::{
    compile_prime_order_hidden_eval_program, execute_prime_order_ddh_hidden_eval_program,
    execute_prime_order_ddh_hidden_eval_program_for_clear_input,
    execute_prime_order_ddh_hidden_eval_program_for_clear_input_profiled,
    execute_prime_order_ddh_hidden_eval_program_profiled, keygen_prime_order_ddh_hss_backend,
    keygen_prime_order_ddh_hss_roles, probe_prime_order_ddh_hidden_eval_program,
    DdhHiddenEvalCheckpoint, DdhHiddenEvalInputBundles, DdhHiddenEvalOutputBundles,
    DdhHiddenEvalProbe, DdhHiddenEvalProfile, DdhHiddenEvalRun, DdhHiddenEvalStageProfile,
    DdhHssBackend, DdhHssEvaluationKey, DdhHssEvaluator, DdhHssGarbler, DdhHssInputShareBundle,
    DdhHssMulMaterial, DdhHssOtInputBundleOffer, DdhHssOtRemoteBundle, DdhHssOtRemoteWord,
    DdhHssOtWordOffer, DdhHssParams, DdhHssRoleSet, DdhHssShareSide, DdhHssSharedWord,
    DdhHssTransportBundle, DdhHssTransportPurpose, DdhHssTransportWord, FixedFunctionHssBackend,
    HiddenEvalInputOwner, HiddenEvalOp, HiddenEvalOpInventory, HiddenEvalProgram, HiddenEvalStage,
    HiddenEvalStageKind, HiddenEvalWindow, HiddenEvalWindowKind, HssPrimitiveKind,
    DDH_HSS_BACKEND_VERSION, HIDDEN_EVAL_PROGRAM_VERSION,
};
pub use error::{ProtoError, ProtoResult};
pub use fixtures::{
    committed_fixture_corpus, committed_fixture_corpus_file, deterministic_fixture_corpus,
    serialized_fixture_corpus, FExpandFixture, FixtureCorpusFile, COMMITTED_FIXTURE_CORPUS_JSON,
    FIXTURE_FORMAT_VERSION,
};
pub use protocol::{
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
    PrimeOrderSuccinctHssSeedOutputOpener, PrimeOrderSuccinctHssServerOutputOpener,
    PrimeOrderSuccinctHssSharedRuntime, PrimeOrderSuccinctHssSharedRuntimeState,
    PrimeOrderSuccinctHssWireMessage,
    PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION,
};
pub use reference::{
    add_le_bytes_mod_2_256, clamp_rfc8032, derive_output_shares, eval_f_expand,
    eval_nonlinear_expansion, extract_a_bytes_from_hash, public_key_from_scalar_bytes,
    recover_a_from_base_shares, reduce_scalar_mod_l, sha512_one_block, FExpandInput, FExpandOutput,
    NonlinearExpansionOutput, OutputShareDerivationOutput,
};
pub use runtime::{
    compile_default_prime_order_cpu_execution_program, compile_prime_order_cpu_execution_program,
    default_prime_order_cpu_executor_benchmark_config, execute_prime_order_cpu_execution_program,
    generate_prime_order_cpu_executor_benchmark_report, PrimeOrderCpuExecutionProgram,
    PrimeOrderCpuExecutionResult, PrimeOrderCpuExecutionStep, PrimeOrderCpuExecutorBenchmarkConfig,
    PrimeOrderCpuExecutorBenchmarkReport, PRIME_ORDER_CPU_EXECUTOR_BENCHMARK_REPORT_VERSION,
};
