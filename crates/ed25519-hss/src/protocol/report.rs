use crate::client::{ClientSession, OutputOpeners};
use crate::ddh::{DdhHssShareSide, DdhHssTransportPurpose, HiddenEvalInputOwner};
use crate::runtime::SharedRuntime;
use crate::server::ServerSession;
use crate::shared::{ProtoError, ProtoResult};
use crate::wire::{
    ClientOutputPacket, ClientOutputValueKind, EvaluationReport, HiddenCoreMaterialization,
    OutputDelivery, SeedOutputPacket, StagedEvaluatorArtifact, TransportKind,
    PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION,
};

pub(crate) fn runtime_output_openers(
    garbler_session: &ServerSession,
    evaluator_session: &ClientSession,
) -> OutputOpeners {
    OutputOpeners {
        client: evaluator_session.client_output_opener(),
        seed: evaluator_session.seed_output_opener(),
        server: garbler_session.server_output_opener(),
    }
}

impl EvaluationReport {
    pub fn summary_lines(&self) -> Vec<String> {
        vec![
            format!(
                "prime-order succinct HSS: backend={} materialization={:?}",
                self.backend_family.as_str(),
                self.hidden_core_materialization,
            ),
            format!(
                "artifact: {}B sections={} digest={} curve_cost={} steps={}",
                self.artifact.artifact_bytes,
                self.artifact.section_count,
                hex::encode(self.artifact.artifact_digest),
                self.evaluator_witness.curve_cost_units,
                self.evaluator_witness.total_steps,
            ),
            format!(
                "bindings: context={} run={} evaluation={}",
                hex::encode(self.artifact.context_binding),
                hex::encode(self.bindings.run_binding),
                hex::encode(self.bindings.evaluation_digest),
            ),
            format!("projection_mode: {:?}", self.projection_mode),
            format!(
                "evaluator: checksum={:016x} final_point={}",
                self.evaluator_witness.output_checksum,
                hex::encode(self.evaluator_witness.final_point_compressed),
            ),
            format!(
                "output_packets: client={}B seed={}B server={}B",
                self.output_delivery.client.bytes.len(),
                self.output_delivery.seed.bytes.len(),
                self.output_delivery.server.bytes.len(),
            ),
        ]
    }
}

pub(crate) fn finalize_report_from_staged_evaluator_artifact(
    runtime: &SharedRuntime,
    garbler_session: &ServerSession,
    artifact: &StagedEvaluatorArtifact,
) -> ProtoResult<EvaluationReport> {
    debug_assert_eq!(
        artifact.context_binding, runtime.candidate.context_binding,
        "evaluation result context binding should already match shared runtime"
    );
    if artifact.context_binding != runtime.candidate.context_binding {
        return Err(ProtoError::InvalidInput(
            "evaluation result context binding does not match shared runtime".to_string(),
        ));
    }
    if artifact.backend_version != garbler_session.ddh_garbler.evaluation_key().backend_version {
        return Err(ProtoError::InvalidInput(
            "evaluation result backend version does not match garbler session".to_string(),
        ));
    }
    let client_packet: ClientOutputPacket = crate::wire::decode_transport_message(
        runtime.candidate.context_binding,
        TransportKind::ClientOutput,
        &artifact.client_output,
    )?;
    let seed_packet: SeedOutputPacket = crate::wire::decode_transport_message(
        runtime.candidate.context_binding,
        TransportKind::SeedOutput,
        &artifact.seed_output,
    )?;
    if client_packet.run_binding != artifact.bindings.run_binding
        || client_packet.evaluation_digest != artifact.bindings.evaluation_digest
    {
        return Err(ProtoError::InvalidInput(
            "evaluation result client output packet is not bound to the reported run".to_string(),
        ));
    }
    if client_packet.projection_mode != artifact.projection_mode {
        return Err(ProtoError::InvalidInput(
            "evaluation result client output projection mode does not match artifact".to_string(),
        ));
    }
    if client_packet.value_kind != artifact.client_output_value_kind {
        return Err(ProtoError::InvalidInput(
            "evaluation result client output value kind does not match artifact metadata"
                .to_string(),
        ));
    }
    let expected_value_kind = ClientOutputValueKind::for_projection_mode(&artifact.projection_mode);
    if client_packet.value_kind != expected_value_kind {
        return Err(ProtoError::InvalidInput(
            "evaluation result client output value kind does not match projection mode".to_string(),
        ));
    }
    if seed_packet.run_binding != artifact.bindings.run_binding
        || seed_packet.evaluation_digest != artifact.bindings.evaluation_digest
    {
        return Err(ProtoError::InvalidInput(
            "evaluation result seed output packet is not bound to the reported run".to_string(),
        ));
    }
    debug_assert_eq!(
        client_packet.run_binding, artifact.bindings.run_binding,
        "client output packet run binding should match evaluation result bindings"
    );
    debug_assert_eq!(
        client_packet.evaluation_digest, artifact.bindings.evaluation_digest,
        "client output packet evaluation digest should match evaluation result bindings"
    );
    let expected_client_output_binding = crate::protocol::transcript::nested_output_message_binding(
        artifact.context_binding,
        artifact.bindings.run_binding,
        artifact.bindings.evaluation_digest,
        b"client_output_message",
        &artifact.client_output.bytes,
    );
    if artifact.client_output_binding != expected_client_output_binding {
        return Err(ProtoError::InvalidInput(
            "evaluation result client output binding is invalid".to_string(),
        ));
    }
    let expected_seed_output_binding = crate::protocol::transcript::nested_output_message_binding(
        artifact.context_binding,
        artifact.bindings.run_binding,
        artifact.bindings.evaluation_digest,
        b"seed_output_message",
        &artifact.seed_output.bytes,
    );
    if artifact.seed_output_binding != expected_seed_output_binding {
        return Err(ProtoError::InvalidInput(
            "evaluation result seed output binding is invalid".to_string(),
        ));
    }
    let expected_server_output_payload_binding =
        crate::protocol::transcript::server_output_payload_binding(
            artifact.context_binding,
            artifact.bindings.run_binding,
            artifact.bindings.evaluation_digest,
            &artifact.server_output_payload,
        );
    if artifact.server_output_payload_binding != expected_server_output_payload_binding {
        return Err(ProtoError::InvalidInput(
            "evaluation result server output payload binding is invalid".to_string(),
        ));
    }
    let (server_left, server_right) = crate::wire::deserialize_transport_pair_payload(
        DdhHssTransportPurpose::ServerOutput,
        &artifact.server_output_payload,
    )?;
    debug_assert_eq!(
        server_left.owner,
        HiddenEvalInputOwner::Server,
        "server output payload should carry a server-owned hidden shared-value representation"
    );
    debug_assert_eq!(
        server_left.label, "x_relayer_base",
        "server output payload should carry x_relayer_base"
    );
    debug_assert_eq!(server_left.share_side, DdhHssShareSide::Left);
    debug_assert_eq!(server_right.share_side, DdhHssShareSide::Right);
    let server_output = garbler_session.seal_server_output_packet_message(
        artifact.bindings.run_binding,
        artifact.bindings.evaluation_digest,
        &server_left,
        &server_right,
    )?;
    let output_delivery = OutputDelivery {
        client: artifact.client_output.clone(),
        seed: artifact.seed_output.clone(),
        server: server_output,
    };

    Ok(EvaluationReport {
        report_version: PRIME_ORDER_SUCCINCT_HSS_REPORT_VERSION.to_string(),
        backend_version: garbler_session.ddh_garbler.evaluation_key().backend_version,
        backend_family: crate::candidate::CandidateBackendFamily::PrimeOrderSizeOptimized,
        fixed_function_id: runtime.candidate.fixed_function_id.clone(),
        hidden_core_materialization: HiddenCoreMaterialization::DdhPrimitiveBaseline,
        artifact: runtime.artifact.clone(),
        bindings: artifact.bindings.clone(),
        projection_mode: artifact.projection_mode.clone(),
        output_projector_binding: artifact.output_projector_binding,
        evaluator_witness: artifact.evaluator_witness.clone(),
        output_delivery,
        notes: vec![
            "Prepared session is bound to the encoded prime-order artifact and its compiled evaluator program.".to_string(),
            "Per-run input sharing and transcript binding now run through the DDH primitive baseline owned by the prepared session.".to_string(),
            "The DDH transport/output surface is now split into garbler/evaluator role views instead of one undifferentiated transport backend.".to_string(),
            "The hidden evaluator now consumes pre-shared bit bundles instead of reconstructing clear F_expand inputs inside the executor.".to_string(),
            "Evaluator-side execution now emits a staged evaluator artifact that the garbler finalizes into the server output packet and final report.".to_string(),
            "Output delivery now seals the hidden client/server base-share bundles directly; clear output bytes are only materialized through role-gated openers.".to_string(),
            "This report is built on the current DDH primitive foundation; remaining work is final 2-party delivery semantics, security review, and performance hardening.".to_string(),
        ],
    })
}
