mod support;

use support::{extract_braced_block_after_marker, extract_function_body, read_src_file};

#[test]
fn router_ab_ecdsa_derivation_normal_signing_binding_does_not_invoke_derivers() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1",
    );
    for required in [
        "cloudflare_router_ab_ecdsa_derivation_public_identity_from_normal_signing_material_v1",
        "active_signing_worker.activation_transcript_digest",
        "scope.public_identity",
    ] {
        assert!(
            body.contains(required),
            "Router A/B ECDSA derivation normal-signing binding must check `{required}`"
        );
    }
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1",
        "CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1",
        "CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "Router A/B ECDSA derivation normal-signing binding must not call setup/export path `{forbidden}`"
        );
    }
}

#[test]
fn router_ab_ecdsa_derivation_normal_signing_materialized_request_uses_active_material_only() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_braced_block_after_marker(
        &lib_rs,
        "impl CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestSigningRequestV1",
    );
    for required in [
        "self.request.request.validate_at(self.materialized_at_ms)",
        "validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1",
        "&self.request.request.scope",
        "&self.active_signing_worker",
        "&self.material",
    ] {
        assert!(
            body.contains(required),
            "Router A/B ECDSA derivation materialized normal-signing request must check `{required}`"
        );
    }
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1",
        "CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1",
        "CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "Router A/B ECDSA derivation materialized normal-signing request must not call `{forbidden}`"
        );
    }
}

#[test]
fn router_ab_ecdsa_derivation_active_state_lookup_uses_full_scope_session_identity() {
    let durable_object_rs = read_src_file("durable_object.rs");
    let lookup_body = extract_function_body(
        &durable_object_rs,
        "from_router_ab_ecdsa_derivation_normal_signing_scope",
    );
    for required in [
        "scope.wallet_id.clone()",
        "scope.active_state_session_id()?",
        "scope.signing_worker.server_id.clone()",
    ] {
        assert!(
            lookup_body.contains(required),
            "Router A/B ECDSA derivation active-state lookup must bind `{required}`"
        );
    }
    assert!(
        !lookup_body.contains("scope.context.ecdsa_threshold_key_id.clone()"),
        "Router A/B ECDSA derivation active-state lookup must not key only by threshold key id"
    );

    let lib_rs = read_src_file("lib.rs");
    let active_material_body = extract_function_body(
        &lib_rs,
        "validate_cloudflare_router_ab_ecdsa_derivation_normal_signing_active_material_v1",
    );
    assert!(
        active_material_body.contains("cloudflare_router_ab_ecdsa_derivation_active_state_session_id_from_scope_v1"),
        "Router A/B ECDSA derivation active material validation must use the full active-state session id"
    );
    assert!(
        !active_material_body.contains("scope.context.ecdsa_threshold_key_id"),
        "Router A/B ECDSA derivation active material validation must not compare only the threshold key id"
    );
}

#[test]
fn router_ab_ecdsa_derivation_finalize_helper_materializes_presignature_before_handler() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1",
    );
    let materialized = body
        .find("CloudflareSigningWorkerMaterializedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1::new")
        .expect("Router A/B ECDSA derivation finalize helper must materialize active state and presignature");
    let prepare_request = body
        .find("materialized.prepare_request()?")
        .expect("Router A/B ECDSA derivation finalize helper must derive prepare request");
    let handler = body
        .find("handler.handle_router_ab_ecdsa_derivation_evm_digest_finalize_request_v1")
        .expect("Router A/B ECDSA derivation finalize helper must call the handler");
    let response_validation = body
        .find("response.validate_for_request(&prepare_request)?")
        .expect("Router A/B ECDSA derivation finalize helper must validate response binding");
    assert!(
        materialized < prepare_request && prepare_request < handler && handler < response_validation,
        "Router A/B ECDSA derivation finalize helper must materialize, derive prepare binding, call handler, then validate response"
    );
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1",
        "CloudflareRouterAbEcdsaDerivationDeriverExportPrivateRequestV1",
        "CloudflareRouterAbEcdsaDerivationSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "Router A/B ECDSA derivation digest signing helper must not call `{forbidden}`"
        );
    }
}

#[test]
fn router_ab_ecdsa_derivation_finalize_consumes_before_fallible_signing_work() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_fetch_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PATH",
        "CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestFinalizeRequestV1",
        "CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope",
        "active_signing_worker_state_get_call",
        "signing_worker_output_material_get_call",
        "CloudflareSigningWorkerEcdsaPoolCommandV1::Consume",
        "expected_revision: 1",
        "execute_cloudflare_signing_worker_ecdsa_pool_mutation_v1",
        "CloudflareSigningWorkerEcdsaPoolMutationOutcomeV1::Consumed",
        "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1",
        "worker::Response::from_json(&response)",
    ] {
        assert!(
            body.contains(required),
            "Router A/B ECDSA derivation finalize private fetch must include `{required}`"
        );
    }
    let consume = body
        .find("CloudflareSigningWorkerEcdsaPoolCommandV1::Consume")
        .expect("Router A/B ECDSA derivation finalize must consume presignature");
    let state_lookup = body
        .find("active_signing_worker_state_get_call")
        .expect("Router A/B ECDSA derivation finalize must load active state");
    let material_lookup = body
        .find("signing_worker_output_material_get_call")
        .expect("Router A/B ECDSA derivation finalize must load material");
    let handler = body
        .find("handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_finalize_private_request_v1")
        .expect("Router A/B ECDSA derivation finalize must invoke materialized handler");
    assert!(
        consume < state_lookup && state_lookup < material_lookup && material_lookup < handler,
        "Router A/B ECDSA derivation finalize must consume before all later state, material, and signing work"
    );
    let output = body
        .find("worker::Response::from_json(&response)")
        .expect("Router A/B ECDSA derivation finalize must return response");
    assert!(
        handler < output,
        "Router A/B ECDSA derivation finalize must return output only after signing"
    );
    for forbidden in [
        "CloudflareSigningWorkerEcdsaPoolCommandV1::Commit",
        "CloudflareSigningWorkerEcdsaPoolCommandV1::FinishCommitted",
        ".committed_material()",
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_registration_service_call_v1",
        "execute_cloudflare_router_ab_ecdsa_derivation_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_router_ab_ecdsa_derivation_export_signer_private_request_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "Router A/B ECDSA derivation finalize private fetch must not call `{forbidden}`"
        );
    }
}

#[test]
fn router_ab_ecdsa_derivation_prepare_persists_exact_reservation_before_response() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_evm_digest_prepare_private_fetch_from_pool_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_SIGNING_PREPARE_PATH",
        "CloudflareSigningWorkerAdmittedRouterAbEcdsaDerivationEvmDigestSigningRequestV1",
        "CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope",
        "cloudflare_random_bytes_v1(32)",
        "CloudflareSigningWorkerEcdsaPoolCommandV1::Reserve",
        "expected_revision: 0",
        "request_digest: prepare_request_digest",
        "admitted_signing_digest: signing_digest",
        "signing_worker_ecdsa_pool_mutate_call",
        "record.reserved_material()",
        "burn_cloudflare_signing_worker_ecdsa_reservation_after_prepare_failure_v1",
        "worker::Response::from_json(&prepared.response)",
    ] {
        assert!(
            body.contains(required),
            "Router A/B ECDSA derivation pool-backed prepare private fetch must include `{required}`"
        );
    }
    let reserve = body
        .find("CloudflareSigningWorkerEcdsaPoolCommandV1::Reserve")
        .expect("pool-backed prepare must build exact reservation");
    let persist = body
        .find("signing_worker_ecdsa_pool_mutate_call")
        .expect("pool-backed prepare must persist exact reservation");
    let material = body
        .find("record.reserved_material()")
        .expect("pool-backed prepare must read material after durable reservation");
    assert!(
        reserve < persist && persist < material,
        "pool-backed prepare must build, persist, then read request-bound presignature state"
    );
    assert!(
        body.matches("burn_cloudflare_signing_worker_ecdsa_reservation_after_prepare_failure_v1")
            .count()
            >= 4,
        "every fallible post-reservation prepare step must burn the reservation"
    );
    let cleanup = extract_function_body(
        &lib_rs,
        "burn_cloudflare_signing_worker_ecdsa_reservation_after_prepare_failure_v1",
    );
    for required in [
        "CloudflareSigningWorkerEcdsaPoolCommandV1::DestroyReserved",
        "expected_revision: 1",
        "TombstoneReason::Rejected",
    ] {
        assert!(
            cleanup.contains(required),
            "prepare failure cleanup must include `{required}`"
        );
    }
}

#[test]
fn router_ab_ecdsa_derivation_presignature_pool_put_private_fetch_derives_active_state() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_router_ab_ecdsa_derivation_presignature_pool_put_private_fetch_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ROUTER_AB_ECDSA_DERIVATION_PRESIGNATURE_POOL_PUT_PATH",
        "CloudflareSigningWorkerRouterAbEcdsaDerivationPresignaturePoolPutRequestV1",
        "parsed.validate_at(now_unix_ms)",
        "CloudflareActiveSigningWorkerStateLookupV1::from_router_ab_ecdsa_derivation_normal_signing_scope",
        "active_signing_worker_state_get_call",
        "signing_worker_output_material_get_call",
        "parsed.to_pool_record(",
        "&active_material",
        "CloudflareSigningWorkerEcdsaPoolCommandV1::PutAvailable",
        "signing_worker_ecdsa_pool_mutate_call",
        "require_signing_worker_ecdsa_pool_mutate_response_v1",
        "worker::Response::from_json(&receipt)",
    ] {
        assert!(
            body.contains(required),
            "Router A/B ECDSA derivation pool-fill private fetch must include `{required}`"
        );
    }
    assert!(
        !body.contains("CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::new("),
        "pool-fill fetch must delegate record construction to the validated boundary type"
    );
}

#[test]
fn router_ab_ecdsa_derivation_presignature_state_uses_one_absorbing_lifecycle() {
    let durable_object_rs = read_src_file("durable_object.rs");
    let lifecycle_rs = read_src_file("ecdsa_pool_lifecycle.rs");
    for required in [
        "CloudflareSigningWorkerEcdsaPresignatureRecordV1",
        "CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1",
        "signing-worker-ecdsa-pool",
        "SigningWorkerEcdsaPoolMutate",
        "signing_worker_ecdsa_pool_lifecycle",
        "put_signing_worker_ecdsa_pool_lifecycle",
        "signing_worker_rerandomization_contribution32_b64u",
        "handle_cloudflare_signing_worker_ecdsa_pool_alarm_v1",
        "cleanup_expired_cloudflare_signing_worker_ecdsa_pool_records_v1",
        ".set_alarm(",
    ] {
        assert!(
            durable_object_rs.contains(required),
            "Router A/B ECDSA derivation presignature Durable Object state must include `{required}`"
        );
    }
    for required in [
        "Available",
        "Reserved",
        "Consumed",
        "Tombstone",
        "expected_revision",
        "Consume",
        "Expire",
        "Retire",
        "RecoverInterrupted",
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_RESERVATION_LEASE_MS_V1",
    ] {
        assert!(
            lifecycle_rs.contains(required),
            "Router A/B ECDSA lifecycle must include `{required}`"
        );
    }
    for forbidden in ["Committed", "FinishCommitted", "committed_material"] {
        assert!(
            !lifecycle_rs.contains(forbidden),
            "obsolete ECDSA lifecycle must not include `{forbidden}`"
        );
    }
    for forbidden in [
        "SigningWorkerEcdsaPresignaturePut",
        "SigningWorkerEcdsaPresignatureTake",
        "signing-worker-ecdsa-presignature-pool",
        "take_signing_worker_ecdsa_presignature",
    ] {
        assert!(
            !durable_object_rs.contains(forbidden),
            "obsolete delete-based ECDSA storage must not include `{forbidden}`"
        );
    }
}
