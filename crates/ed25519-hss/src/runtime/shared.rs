use serde::{Deserialize, Serialize};

use crate::artifact::{
    build_prime_order_size_optimized_artifact, decode_prime_order_size_optimized_artifact,
    materialize_prime_order_size_optimized_bytes, PrimeOrderEncodedArtifact,
};
use crate::candidate::FixedHiddenCoreCandidate;
use crate::client::{ClientSession, OutputOpeners};
use crate::ddh::hidden_eval_executor::{
    prepare_ddh_hidden_eval_constant_pool, DdhHiddenEvalConstantPool,
};
use crate::ddh::{compile_prime_order_hidden_eval_program, DdhHssEvaluator, HiddenEvalProgram};
use crate::protocol::report::{
    finalize_report_from_evaluation_result as build_report_from_evaluation_result,
    runtime_output_openers,
};
use crate::runtime::{
    compile_prime_order_cpu_execution_program, execute_prime_order_cpu_execution_program,
    PrimeOrderCpuExecutionProgram, PrimeOrderCpuExecutionResult,
};
use crate::server::ServerSession;
use crate::shared::ProtoResult;
use crate::wire::{ArtifactSummary, EvaluationReport, EvaluationResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRuntime {
    pub(crate) candidate: FixedHiddenCoreCandidate,
    pub(crate) artifact: ArtifactSummary,
    pub(crate) hidden_eval_program: HiddenEvalProgram,
    pub(crate) hidden_eval_constants: DdhHiddenEvalConstantPool,
    pub(crate) ddh_evaluator: DdhHssEvaluator,
    pub(crate) execution_program: PrimeOrderCpuExecutionProgram,
    pub(crate) execution_result: PrimeOrderCpuExecutionResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedRuntimeState {
    pub candidate: FixedHiddenCoreCandidate,
    pub ddh_evaluator: DdhHssEvaluator,
}

pub(crate) fn build_artifact_summary(
    candidate: &FixedHiddenCoreCandidate,
    artifact: &PrimeOrderEncodedArtifact,
) -> ArtifactSummary {
    ArtifactSummary {
        encoder_version: artifact.encoder_version.clone(),
        artifact_bytes: artifact.total_bytes,
        artifact_digest: artifact.artifact_digest,
        section_count: artifact.sections.len(),
        context_binding: candidate.context_binding,
        candidate_digest: candidate.template.candidate_digest,
        round_template_digest: candidate.template.round_template_digest,
    }
}

impl SharedRuntimeState {
    pub fn materialize(&self) -> ProtoResult<SharedRuntime> {
        let artifact = build_prime_order_size_optimized_artifact(&self.candidate)?;
        let artifact_bytes = materialize_prime_order_size_optimized_bytes(&self.candidate)?;
        let decoded = decode_prime_order_size_optimized_artifact(&artifact_bytes)?;
        let hidden_eval_program = compile_prime_order_hidden_eval_program(&decoded)?;
        let execution_program = compile_prime_order_cpu_execution_program(&decoded)?;
        let execution_result = execute_prime_order_cpu_execution_program(&execution_program)?;
        Ok(SharedRuntime {
            candidate: self.candidate.clone(),
            artifact: build_artifact_summary(&self.candidate, &artifact),
            hidden_eval_program,
            hidden_eval_constants: prepare_ddh_hidden_eval_constant_pool(&self.ddh_evaluator)?,
            ddh_evaluator: self.ddh_evaluator.clone(),
            execution_program,
            execution_result,
        })
    }
}

impl SharedRuntime {
    pub fn artifact_summary(&self) -> &ArtifactSummary {
        &self.artifact
    }

    pub fn output_openers(
        &self,
        garbler_session: &ServerSession,
        evaluator_session: &ClientSession,
    ) -> OutputOpeners {
        runtime_output_openers(garbler_session, evaluator_session)
    }

    pub fn finalize_report_from_evaluation_result(
        &self,
        garbler_session: &ServerSession,
        evaluation_result: &EvaluationResult,
    ) -> ProtoResult<EvaluationReport> {
        build_report_from_evaluation_result(self, garbler_session, evaluation_result)
    }
}
