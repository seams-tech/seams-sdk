use crate::ddh::hidden_eval_executor::DdhHiddenEvalServerInputs;
use crate::ddh::{DdhHssOtReconstructTiming, DdhHssOtReleasedRemoteBundle, DdhHssOtResponseBundle};

pub(crate) struct TrustedServerEval {
    pub(crate) y_client_response: DdhHssOtResponseBundle,
    pub(crate) tau_client_response: DdhHssOtResponseBundle,
    pub(crate) y_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub(crate) tau_client_remote_release: DdhHssOtReleasedRemoteBundle,
    pub(crate) server_input_commitment: [u8; 32],
    pub(crate) trusted_server_inputs: DdhHiddenEvalServerInputs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvaluateTiming {
    pub ot_open_join_duration_ns: u64,
    pub ot_branch_key_derivation_duration_ns: u64,
    pub ot_branch_decrypt_duration_ns: u64,
    pub ot_point_scalar_reconstruction_duration_ns: u64,
    pub ot_commitment_verification_duration_ns: u64,
    pub server_input_open_duration_ns: u64,
    pub server_input_share_duration_ns: u64,
    pub server_input_commitment_duration_ns: u64,
    pub server_input_transcript_duration_ns: u64,
    pub server_input_seal_duration_ns: u64,
    pub output_sealing_finalization_duration_ns: u64,
    pub result_assembly_duration_ns: u64,
}

impl EvaluateTiming {
    pub(crate) fn add_assign(&mut self, other: Self) {
        self.ot_open_join_duration_ns = self
            .ot_open_join_duration_ns
            .saturating_add(other.ot_open_join_duration_ns);
        self.ot_branch_key_derivation_duration_ns = self
            .ot_branch_key_derivation_duration_ns
            .saturating_add(other.ot_branch_key_derivation_duration_ns);
        self.ot_branch_decrypt_duration_ns = self
            .ot_branch_decrypt_duration_ns
            .saturating_add(other.ot_branch_decrypt_duration_ns);
        self.ot_point_scalar_reconstruction_duration_ns = self
            .ot_point_scalar_reconstruction_duration_ns
            .saturating_add(other.ot_point_scalar_reconstruction_duration_ns);
        self.ot_commitment_verification_duration_ns = self
            .ot_commitment_verification_duration_ns
            .saturating_add(other.ot_commitment_verification_duration_ns);
        self.server_input_open_duration_ns = self
            .server_input_open_duration_ns
            .saturating_add(other.server_input_open_duration_ns);
        self.server_input_share_duration_ns = self
            .server_input_share_duration_ns
            .saturating_add(other.server_input_share_duration_ns);
        self.server_input_commitment_duration_ns = self
            .server_input_commitment_duration_ns
            .saturating_add(other.server_input_commitment_duration_ns);
        self.server_input_transcript_duration_ns = self
            .server_input_transcript_duration_ns
            .saturating_add(other.server_input_transcript_duration_ns);
        self.server_input_seal_duration_ns = self
            .server_input_seal_duration_ns
            .saturating_add(other.server_input_seal_duration_ns);
        self.output_sealing_finalization_duration_ns = self
            .output_sealing_finalization_duration_ns
            .saturating_add(other.output_sealing_finalization_duration_ns);
        self.result_assembly_duration_ns = self
            .result_assembly_duration_ns
            .saturating_add(other.result_assembly_duration_ns);
    }

    pub(crate) fn add_ot_reconstruct_timing(&mut self, other: DdhHssOtReconstructTiming) {
        self.ot_branch_key_derivation_duration_ns = self
            .ot_branch_key_derivation_duration_ns
            .saturating_add(other.branch_key_derivation_duration_ns);
        self.ot_branch_decrypt_duration_ns = self
            .ot_branch_decrypt_duration_ns
            .saturating_add(other.branch_decrypt_duration_ns);
        self.ot_point_scalar_reconstruction_duration_ns = self
            .ot_point_scalar_reconstruction_duration_ns
            .saturating_add(other.point_scalar_reconstruction_duration_ns);
        self.ot_commitment_verification_duration_ns = self
            .ot_commitment_verification_duration_ns
            .saturating_add(other.commitment_verification_duration_ns);
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn monotonic_now_ns() -> u128 {
    use std::sync::OnceLock;
    use std::time::Instant;

    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_nanos()
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn monotonic_now_ns() -> u128 {
    web_sys::window()
        .and_then(|window| window.performance())
        .map(|performance| (performance.now() * 1_000_000.0) as u128)
        .unwrap_or_else(|| (js_sys::Date::now() * 1_000_000.0) as u128)
}

pub(crate) fn elapsed_ns_u64(started_ns: u128) -> u64 {
    monotonic_now_ns()
        .saturating_sub(started_ns)
        .min(u64::MAX as u128) as u64
}
