use ed25519_hss::ddh::hidden_eval_executor::{
    compute_output_projection_output_digest,
    execute_prime_order_ddh_hidden_eval_program_profiled_with_pool,
    execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool,
    share_input_bit_bundles_for_clear_input,
    trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool,
};
use ed25519_hss::ddh::{
    DdhHiddenEvalClientOutputProjection, DdhHiddenEvalOperationCounts, DdhHiddenEvalRun,
};
use ed25519_hss::protocol::prepare_prime_order_succinct_hss;
use ed25519_hss::shared::ProtoResult;

use crate::support::{first_fixture, TEST_CLIENT_OUTPUT_MASK};

#[test]
fn production_hidden_eval_matches_checkpoint_trace_for_trusted_projection() {
    assert_hidden_eval_production_matches_checkpoint_trace(
        DdhHiddenEvalClientOutputProjection::trusted_server_projection(),
    )
    .expect("trusted projection equivalence");
}

#[test]
fn production_hidden_eval_matches_checkpoint_trace_for_client_masked_projection() {
    assert_hidden_eval_production_matches_checkpoint_trace(
        DdhHiddenEvalClientOutputProjection::client_masked_projection(TEST_CLIENT_OUTPUT_MASK),
    )
    .expect("client-masked projection equivalence");
}

#[test]
fn hidden_eval_operation_shape_records_current_materialization_baseline() {
    let counts = hidden_eval_operation_counts_for_projection(
        DdhHiddenEvalClientOutputProjection::client_masked_projection(TEST_CLIENT_OUTPUT_MASK),
    )
    .expect("hidden-eval operation counts");

    assert_eq!(
        counts,
        DdhHiddenEvalOperationCounts {
            logical_local_word_materializations: 12_800,
            logical_shared_word_materializations: 1_024,
            logical_transport_word_materializations: 1_536,
            logical_commitment_materializations: 17_928,
            logical_provenance_digest_materializations: 15_360,
            logical_commitment_derivations: 2_048,
            logical_provenance_digest_derivations: 13_824,
            logical_label_writes: 57_128,
            logical_label_format_allocations: 265,
            physical_keyed_digest_derivations: counts.physical_keyed_digest_derivations,
            physical_keyed_digest_eval_xor_local_word: counts
                .physical_keyed_digest_eval_xor_local_word,
            physical_keyed_digest_eval_add_local: counts.physical_keyed_digest_eval_add_local,
            physical_keyed_digest_eval_mul_local_material: counts
                .physical_keyed_digest_eval_mul_local_material,
            physical_keyed_digest_eval_mul_local: counts.physical_keyed_digest_eval_mul_local,
            physical_keyed_digest_phase_a_arith_share_to_bool: counts
                .physical_keyed_digest_phase_a_arith_share_to_bool,
            physical_keyed_digest_phase_a_bool_to_arith_base: counts
                .physical_keyed_digest_phase_a_bool_to_arith_base,
            physical_keyed_digest_phase_a_arith_to_bool_zero: counts
                .physical_keyed_digest_phase_a_arith_to_bool_zero,
            physical_keyed_digest_compose_word_from_share_bits: counts
                .physical_keyed_digest_compose_word_from_share_bits,
            physical_keyed_digest_share_word: counts.physical_keyed_digest_share_word,
            physical_keyed_digest_other: counts.physical_keyed_digest_other,
            physical_derived_commitment_hashes: counts.physical_derived_commitment_hashes,
            physical_derived_commitment_eval_xor_local_word: counts
                .physical_derived_commitment_eval_xor_local_word,
            physical_derived_commitment_eval_add_local: counts
                .physical_derived_commitment_eval_add_local,
            physical_derived_commitment_eval_mul_local_material: counts
                .physical_derived_commitment_eval_mul_local_material,
            physical_derived_commitment_eval_mul_local: counts
                .physical_derived_commitment_eval_mul_local,
            physical_derived_commitment_phase_a_arith_share_to_bool: counts
                .physical_derived_commitment_phase_a_arith_share_to_bool,
            physical_derived_commitment_phase_a_bool_to_arith_base: counts
                .physical_derived_commitment_phase_a_bool_to_arith_base,
            physical_derived_commitment_phase_a_arith_to_bool_zero: counts
                .physical_derived_commitment_phase_a_arith_to_bool_zero,
            physical_derived_commitment_compose_word_from_share_bits: counts
                .physical_derived_commitment_compose_word_from_share_bits,
            physical_derived_commitment_share_word: counts.physical_derived_commitment_share_word,
            physical_derived_commitment_other: counts.physical_derived_commitment_other,
            physical_add_bit_hashes: counts.physical_add_bit_hashes,
            physical_mul_material_hashes: counts.physical_mul_material_hashes,
            physical_mul_output_seed_hashes: counts.physical_mul_output_seed_hashes,
        },
        "current hidden-eval materialization shape changed",
    );
    #[cfg(not(feature = "hss-physical-counters"))]
    assert_eq!(
        [
            counts.physical_keyed_digest_derivations,
            counts.physical_keyed_digest_eval_xor_local_word,
            counts.physical_keyed_digest_eval_add_local,
            counts.physical_keyed_digest_eval_mul_local_material,
            counts.physical_keyed_digest_eval_mul_local,
            counts.physical_keyed_digest_phase_a_arith_share_to_bool,
            counts.physical_keyed_digest_phase_a_bool_to_arith_base,
            counts.physical_keyed_digest_phase_a_arith_to_bool_zero,
            counts.physical_keyed_digest_compose_word_from_share_bits,
            counts.physical_keyed_digest_share_word,
            counts.physical_keyed_digest_other,
            counts.physical_derived_commitment_hashes,
            counts.physical_derived_commitment_eval_xor_local_word,
            counts.physical_derived_commitment_eval_add_local,
            counts.physical_derived_commitment_eval_mul_local_material,
            counts.physical_derived_commitment_eval_mul_local,
            counts.physical_derived_commitment_phase_a_arith_share_to_bool,
            counts.physical_derived_commitment_phase_a_bool_to_arith_base,
            counts.physical_derived_commitment_phase_a_arith_to_bool_zero,
            counts.physical_derived_commitment_compose_word_from_share_bits,
            counts.physical_derived_commitment_share_word,
            counts.physical_derived_commitment_other,
            counts.physical_add_bit_hashes,
            counts.physical_mul_material_hashes,
            counts.physical_mul_output_seed_hashes,
        ],
        [0; 25],
        "physical hash counters should stay disabled in default builds",
    );
    assert!(
        counts.logical_local_word_materializations
            > counts
                .logical_shared_word_materializations
                .saturating_add(counts.logical_transport_word_materializations),
        "packed/arena work should first target local-word storage pressure",
    );

    let fixture = first_fixture();
    let session =
        prepare_prime_order_succinct_hss(&fixture.input.context).expect("prepare session");
    let input_bundles =
        share_input_bit_bundles_for_clear_input(session.ddh_backend(), &fixture.input)
            .expect("share input bundles");
    let (_run, profile) =
        execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool(
            session.hidden_eval_program(),
            session.ddh_backend(),
            session.hidden_eval_constants(),
            &input_bundles.y_client_bits,
            &input_bundles.server_inputs.y_relayer_bits,
            &input_bundles.tau_client_bits,
            &input_bundles.server_inputs.tau_relayer_bits,
            DdhHiddenEvalClientOutputProjection::client_masked_projection(TEST_CLIENT_OUTPUT_MASK),
        )
        .expect("profile hidden eval");
    assert_eq!(
        profile.output_projector_local_word_materializations, 2_560,
        "current output-projector local-word materialization shape changed",
    );
}

fn hidden_eval_operation_counts_for_projection(
    projection: DdhHiddenEvalClientOutputProjection,
) -> ProtoResult<DdhHiddenEvalOperationCounts> {
    let fixture = first_fixture();
    let session = prepare_prime_order_succinct_hss(&fixture.input.context)?;
    let input_bundles =
        share_input_bit_bundles_for_clear_input(session.ddh_backend(), &fixture.input)?;
    let (_run, profile) =
        execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool(
            session.hidden_eval_program(),
            session.ddh_backend(),
            session.hidden_eval_constants(),
            &input_bundles.y_client_bits,
            &input_bundles.server_inputs.y_relayer_bits,
            &input_bundles.tau_client_bits,
            &input_bundles.server_inputs.tau_relayer_bits,
            projection,
        )?;
    Ok(profile.operation_counts)
}

fn assert_hidden_eval_production_matches_checkpoint_trace(
    projection: DdhHiddenEvalClientOutputProjection,
) -> ProtoResult<()> {
    let fixture = first_fixture();
    let session = prepare_prime_order_succinct_hss(&fixture.input.context)?;
    let program = session.hidden_eval_program();
    let backend = session.ddh_backend();
    let constant_pool = session.hidden_eval_constants();
    let input_bundles = share_input_bit_bundles_for_clear_input(backend, &fixture.input)?;

    let (production_run, production_profile) =
        execute_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool(
            program,
            backend,
            constant_pool,
            &input_bundles.y_client_bits,
            &input_bundles.server_inputs.y_relayer_bits,
            &input_bundles.tau_client_bits,
            &input_bundles.server_inputs.tau_relayer_bits,
            projection,
        )?;
    let (checkpoint_trace, checkpoint_profile) =
        trace_prime_order_ddh_hidden_eval_program_with_split_server_inputs_and_client_output_projection_profiled_with_pool(
            program,
            backend,
            constant_pool,
            &input_bundles.y_client_bits,
            &input_bundles.server_inputs.y_relayer_bits,
            &input_bundles.tau_client_bits,
            &input_bundles.server_inputs.tau_relayer_bits,
            projection,
        )?;

    assert_run_equivalent(&production_run, &checkpoint_trace.run);
    assert_eq!(
        logical_operation_shape(production_profile.operation_counts),
        logical_operation_shape(checkpoint_profile.operation_counts),
        "checkpoint capture must not change logical hidden-eval operation shape",
    );
    assert_ne!(
        checkpoint_trace.checkpoint_digests.add_stage, [0u8; 32],
        "add-stage checkpoint digest must be populated",
    );
    assert_ne!(
        checkpoint_trace.checkpoint_digests.message_schedule, [0u8; 32],
        "message-schedule checkpoint digest must be populated",
    );
    assert_ne!(
        checkpoint_trace.checkpoint_digests.round_core, [0u8; 32],
        "round-core checkpoint digest must be populated",
    );
    assert_ne!(
        checkpoint_trace.checkpoint_digests.output_projection, [0u8; 32],
        "output-projection checkpoint digest must be populated",
    );

    if projection == DdhHiddenEvalClientOutputProjection::trusted_server_projection() {
        let joint_profile = execute_prime_order_ddh_hidden_eval_program_profiled_with_pool(
            program,
            backend,
            constant_pool,
            &input_bundles,
        )?;
        assert_run_equivalent(&production_run, &joint_profile.run);
        assert_eq!(
            logical_operation_shape(production_profile.operation_counts),
            logical_operation_shape(joint_profile.stage_profile.operation_counts),
            "split and joint trusted-server execution must keep the same logical operation shape",
        );
    }

    Ok(())
}

fn assert_run_equivalent(left: &DdhHiddenEvalRun, right: &DdhHiddenEvalRun) {
    assert_eq!(
        left.client_input_commitment, right.client_input_commitment,
        "client input commitment changed",
    );
    assert_eq!(
        left.server_input_commitment, right.server_input_commitment,
        "server input commitment changed",
    );
    assert_eq!(
        left.output.client_output.value_kind, right.output.client_output.value_kind,
        "client output value kind changed",
    );
    assert_eq!(
        left.output.canonical_seed.commitment, right.output.canonical_seed.commitment,
        "canonical seed output commitment changed",
    );
    assert_eq!(
        left.output.client_output.bundle.commitment, right.output.client_output.bundle.commitment,
        "client output commitment changed",
    );
    assert_eq!(
        left.output.x_relayer_base_left.commitment, right.output.x_relayer_base_left.commitment,
        "left relayer output commitment changed",
    );
    assert_eq!(
        left.output.x_relayer_base_right.commitment, right.output.x_relayer_base_right.commitment,
        "right relayer output commitment changed",
    );
    assert_eq!(
        compute_output_projection_output_digest(&left.output),
        compute_output_projection_output_digest(&right.output),
        "output projection digest changed",
    );
    assert_eq!(left, right, "hidden-eval run changed");
}

fn logical_operation_shape(
    counts: DdhHiddenEvalOperationCounts,
) -> (u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        counts.logical_local_word_materializations,
        counts.logical_shared_word_materializations,
        counts.logical_transport_word_materializations,
        counts.logical_commitment_materializations,
        counts.logical_provenance_digest_materializations,
        counts.logical_commitment_derivations,
        counts.logical_provenance_digest_derivations,
        counts.logical_label_writes,
        counts.logical_label_format_allocations,
    )
}
