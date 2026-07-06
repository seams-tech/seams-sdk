use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::artifact::{
    build_prime_order_size_optimized_artifact, decode_prime_order_size_optimized_artifact,
    materialize_prime_order_size_optimized_bytes, PrimeOrderEncodedArtifact,
};
use crate::candidate::{build_fixed_hidden_core_candidate, FixedHiddenCoreCandidate};
use crate::client::{ClientSession, OutputOpeners};
use crate::ddh::{compile_prime_order_hidden_eval_program, HiddenEvalProgram};
use crate::protocol::report::{
    finalize_report_from_staged_evaluator_artifact as build_report_from_staged_evaluator_artifact,
    runtime_output_openers,
};
use crate::runtime::{
    compile_prime_order_cpu_execution_program, execute_prime_order_cpu_execution_program,
    PrimeOrderCpuExecutionProgram, PrimeOrderCpuExecutionResult,
};
use crate::server::{ServerEvalFinalizeOutput, ServerSession};
use crate::shared::{CanonicalContext, ProtoResult};
use crate::wire::{
    ArtifactSummary, EvaluationReport, OutputProjectionMode, StagedEvaluatorArtifact,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRuntime {
    pub(crate) candidate: FixedHiddenCoreCandidate,
    pub(crate) projection_mode: OutputProjectionMode,
    pub(crate) artifact: ArtifactSummary,
    pub(crate) hidden_eval_program: HiddenEvalProgram,
    pub(crate) execution_program: PrimeOrderCpuExecutionProgram,
    pub(crate) execution_result: PrimeOrderCpuExecutionResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedRuntimeState {
    pub prepared_context: CanonicalContext,
    pub projection_mode: OutputProjectionMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedRuntimeFinalizeContext {
    pub context_binding: [u8; 32],
    pub fixed_function_id: String,
    pub artifact: ArtifactSummary,
    pub execution_result: PrimeOrderCpuExecutionResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedRuntimeAdvanceContext {
    pub context_binding: [u8; 32],
    pub projection_mode: OutputProjectionMode,
    pub artifact: ArtifactSummary,
    pub program_digest: [u8; 32],
    pub artifact_bytes: Vec<u8>,
    pub finalize_context: SharedRuntimeFinalizeContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SharedRuntimeAdvanceMaterial {
    pub context_binding: [u8; 32],
    pub projection_mode: OutputProjectionMode,
    pub artifact: ArtifactSummary,
    pub program_digest: [u8; 32],
    pub hidden_eval_program: HiddenEvalProgram,
    pub finalize_context: SharedRuntimeFinalizeContext,
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
        let candidate = build_fixed_hidden_core_candidate(&self.prepared_context)?;
        let artifact = build_prime_order_size_optimized_artifact(&candidate)?;
        let artifact_bytes = materialize_prime_order_size_optimized_bytes(&candidate)?;
        let decoded = decode_prime_order_size_optimized_artifact(&artifact_bytes)?;
        let hidden_eval_program = compile_prime_order_hidden_eval_program(&decoded)?;
        let execution_program = compile_prime_order_cpu_execution_program(&decoded)?;
        let execution_result = execute_prime_order_cpu_execution_program(&execution_program)?;
        Ok(SharedRuntime {
            candidate: candidate.clone(),
            projection_mode: self.projection_mode.clone(),
            artifact: build_artifact_summary(&candidate, &artifact),
            hidden_eval_program,
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

    pub fn finalize_context(&self) -> SharedRuntimeFinalizeContext {
        SharedRuntimeFinalizeContext {
            context_binding: self.candidate.context_binding,
            fixed_function_id: self.candidate.fixed_function_id.clone(),
            artifact: self.artifact.clone(),
            execution_result: self.execution_result.clone(),
        }
    }

    pub fn advance_context(
        &self,
        program_digest: [u8; 32],
        artifact_bytes: Vec<u8>,
    ) -> SharedRuntimeAdvanceContext {
        SharedRuntimeAdvanceContext {
            context_binding: self.candidate.context_binding,
            projection_mode: self.projection_mode.clone(),
            artifact: self.artifact.clone(),
            program_digest,
            artifact_bytes,
            finalize_context: self.finalize_context(),
        }
    }

    pub fn finalize_report_from_staged_evaluator_artifact(
        &self,
        garbler_session: &ServerSession,
        artifact: &StagedEvaluatorArtifact,
        server_output: &ServerEvalFinalizeOutput,
    ) -> ProtoResult<EvaluationReport> {
        build_report_from_staged_evaluator_artifact(self, garbler_session, artifact, server_output)
    }
}

impl SharedRuntimeAdvanceContext {
    pub fn materialize(&self) -> ProtoResult<SharedRuntimeAdvanceMaterial> {
        let artifact_digest = Sha256::digest(&self.artifact_bytes);
        let mut artifact_digest_bytes = [0u8; 32];
        artifact_digest_bytes.copy_from_slice(&artifact_digest);
        if artifact_digest_bytes != self.artifact.artifact_digest {
            return Err(crate::shared::ProtoError::InvalidInput(
                "advance runtime artifact bytes do not match artifact digest".to_string(),
            ));
        }

        let decoded = decode_prime_order_size_optimized_artifact(&self.artifact_bytes)?;
        if decoded.total_bytes != self.artifact.artifact_bytes {
            return Err(crate::shared::ProtoError::InvalidInput(
                "advance runtime artifact byte length does not match artifact summary".to_string(),
            ));
        }
        if decoded.header.context_binding != self.artifact.context_binding {
            return Err(crate::shared::ProtoError::InvalidInput(
                "advance runtime artifact context binding does not match artifact summary"
                    .to_string(),
            ));
        }
        if decoded.header.candidate_digest != self.artifact.candidate_digest {
            return Err(crate::shared::ProtoError::InvalidInput(
                "advance runtime artifact candidate digest does not match artifact summary"
                    .to_string(),
            ));
        }
        if decoded.header.round_template_digest != self.artifact.round_template_digest {
            return Err(crate::shared::ProtoError::InvalidInput(
                "advance runtime artifact round template digest does not match artifact summary"
                    .to_string(),
            ));
        }
        if decoded.header.encoder_version != self.artifact.encoder_version {
            return Err(crate::shared::ProtoError::InvalidInput(
                "advance runtime artifact encoder version does not match artifact summary"
                    .to_string(),
            ));
        }
        if decoded.header.section_count as usize != self.artifact.section_count {
            return Err(crate::shared::ProtoError::InvalidInput(
                "advance runtime artifact section count does not match artifact summary"
                    .to_string(),
            ));
        }
        if decoded.header.fixed_function_id != self.finalize_context.fixed_function_id {
            return Err(crate::shared::ProtoError::InvalidInput(
                "advance runtime artifact fixed-function id does not match finalize context"
                    .to_string(),
            ));
        }

        Ok(SharedRuntimeAdvanceMaterial {
            context_binding: self.context_binding,
            projection_mode: self.projection_mode.clone(),
            artifact: self.artifact.clone(),
            program_digest: self.program_digest,
            hidden_eval_program: compile_prime_order_hidden_eval_program(&decoded)?,
            finalize_context: self.finalize_context.clone(),
        })
    }
}
