mod support;

use support::{extract_braced_block_after_marker, extract_function_body, read_src_file};

#[test]
fn ecdsa_hss_normal_signing_binding_does_not_invoke_derivers() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1",
    );
    for required in [
        "cloudflare_ecdsa_hss_public_identity_from_normal_signing_material_v1",
        "active_signing_worker.activation_transcript_digest",
        "scope.public_identity",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS normal-signing binding must check `{required}`"
        );
    }
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS normal-signing binding must not call setup/export path `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_normal_signing_materialized_request_uses_active_material_only() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_braced_block_after_marker(
        &lib_rs,
        "impl CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestSigningRequestV1",
    );
    for required in [
        "self.request.request.validate_at(self.materialized_at_ms)",
        "validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1",
        "&self.request.request.scope",
        "&self.active_signing_worker",
        "&self.material",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS materialized normal-signing request must check `{required}`"
        );
    }
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS materialized normal-signing request must not call `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_active_state_lookup_uses_full_scope_session_identity() {
    let durable_object_rs = read_src_file("durable_object.rs");
    let lookup_body =
        extract_function_body(&durable_object_rs, "from_ecdsa_hss_normal_signing_scope");
    for required in [
        "scope.wallet_id.clone()",
        "scope.active_state_session_id()?",
        "scope.signing_worker.server_id.clone()",
    ] {
        assert!(
            lookup_body.contains(required),
            "ECDSA-HSS active-state lookup must bind `{required}`"
        );
    }
    assert!(
        !lookup_body.contains("scope.context.ecdsa_threshold_key_id.clone()"),
        "ECDSA-HSS active-state lookup must not key only by threshold key id"
    );

    let lib_rs = read_src_file("lib.rs");
    let active_material_body = extract_function_body(
        &lib_rs,
        "validate_cloudflare_ecdsa_hss_normal_signing_active_material_v1",
    );
    assert!(
        active_material_body.contains("cloudflare_ecdsa_hss_active_state_session_id_from_scope_v1"),
        "ECDSA-HSS active material validation must use the full active-state session id"
    );
    assert!(
        !active_material_body.contains("scope.context.ecdsa_threshold_key_id"),
        "ECDSA-HSS active material validation must not compare only the threshold key id"
    );
}

#[test]
fn ecdsa_hss_finalize_helper_materializes_presignature_before_handler() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1",
    );
    let materialized = body
        .find("CloudflareSigningWorkerMaterializedEcdsaHssEvmDigestFinalizeRequestV1::new")
        .expect("ECDSA-HSS finalize helper must materialize active state and presignature");
    let prepare_request = body
        .find("materialized.prepare_request()?")
        .expect("ECDSA-HSS finalize helper must derive prepare request");
    let handler = body
        .find("handler.handle_ecdsa_hss_evm_digest_finalize_request_v1")
        .expect("ECDSA-HSS finalize helper must call the handler");
    let response_validation = body
        .find("response.validate_for_request(&prepare_request)?")
        .expect("ECDSA-HSS finalize helper must validate response binding");
    assert!(
        materialized < prepare_request && prepare_request < handler && handler < response_validation,
        "ECDSA-HSS finalize helper must materialize, derive prepare binding, call handler, then validate response"
    );
    for forbidden in [
        "execute_cloudflare_signer_recipient_proof_bundle_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareEcdsaHssDeriverExportPrivateRequestV1",
        "CloudflareEcdsaHssSigningWorkerActivationRequestV1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS digest signing helper must not call `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_finalize_private_fetch_takes_one_use_presignature() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_fetch_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PATH",
        "CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestFinalizeRequestV1",
        "CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope",
        "active_signing_worker_state_get_call",
        "signing_worker_output_material_get_call",
        "CloudflareSigningWorkerEcdsaPresignatureLookupV1::new",
        "signing_worker_ecdsa_presignature_take_call",
        "require_signing_worker_ecdsa_presignature_take_response_v1",
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1",
        "worker::Response::from_json(&response)",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS finalize private fetch must include `{required}`"
        );
    }
    let state_lookup = body
        .find("active_signing_worker_state_get_call")
        .expect("ECDSA-HSS finalize must load active state");
    let material_lookup = body
        .find("signing_worker_output_material_get_call")
        .expect("ECDSA-HSS finalize must load material");
    let take = body
        .find("signing_worker_ecdsa_presignature_take_call")
        .expect("ECDSA-HSS finalize must take presignature");
    let handler = body
        .find("handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_finalize_private_request_v1")
        .expect("ECDSA-HSS finalize must invoke materialized handler");
    assert!(
        state_lookup < material_lookup && material_lookup < take && take < handler,
        "ECDSA-HSS finalize must load state/material, take presignature, then invoke handler"
    );
    for forbidden in [
        "execute_cloudflare_ecdsa_hss_deriver_registration_service_call_v1",
        "execute_cloudflare_ecdsa_hss_deriver_export_service_call_v1",
        "decrypt_and_handle_cloudflare_ecdsa_hss_export_signer_private_request_v1",
        "CloudflareSigningWorkerRecipientProofBundleActivationV1",
    ] {
        assert!(
            !body.contains(forbidden),
            "ECDSA-HSS finalize private fetch must not call `{forbidden}`"
        );
    }
}

#[test]
fn ecdsa_hss_prepare_private_fetch_from_pool_reserves_then_binds_presignature() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_ecdsa_hss_evm_digest_prepare_private_fetch_from_pool_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_SIGNING_PREPARE_PATH",
        "CloudflareSigningWorkerAdmittedEcdsaHssEvmDigestSigningRequestV1",
        "CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope",
        "CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1::new",
        "signing_worker_ecdsa_presignature_pool_take_call",
        "require_signing_worker_ecdsa_presignature_pool_take_response_v1",
        "cloudflare_random_bytes_v1(32)",
        "prepare_cloudflare_role_separated_ecdsa_hss_evm_digest_from_pool_record_v1",
        "signing_worker_ecdsa_presignature_put_call",
        "prepared.validate_put_receipt",
        "worker::Response::from_json(&prepared.response)",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS pool-backed prepare private fetch must include `{required}`"
        );
    }
    let pool_take = body
        .find("signing_worker_ecdsa_presignature_pool_take_call")
        .expect("pool-backed prepare must reserve the pool record");
    let bind = body
        .find("prepare_cloudflare_role_separated_ecdsa_hss_evm_digest_from_pool_record_v1")
        .expect("pool-backed prepare must bind reserved pool record");
    let request_bound_put = body
        .find("signing_worker_ecdsa_presignature_put_call")
        .expect("pool-backed prepare must persist the request-bound record");
    assert!(
        pool_take < bind && bind < request_bound_put,
        "pool-backed prepare must reserve, bind, then persist request-bound presignature state"
    );
}

#[test]
fn ecdsa_hss_presignature_pool_put_private_fetch_derives_active_state() {
    let lib_rs = read_src_file("lib.rs");
    let body = extract_function_body(
        &lib_rs,
        "handle_cloudflare_signing_worker_ecdsa_hss_presignature_pool_put_private_fetch_v1",
    );
    for required in [
        "CLOUDFLARE_SIGNING_WORKER_ECDSA_HSS_PRESIGNATURE_POOL_PUT_PATH",
        "CloudflareSigningWorkerEcdsaHssPresignaturePoolPutRequestV1",
        "parsed.validate_at(now_unix_ms)",
        "CloudflareActiveSigningWorkerStateLookupV1::from_ecdsa_hss_normal_signing_scope",
        "active_signing_worker_state_get_call",
        "parsed.to_pool_record(active_signing_worker, now_unix_ms)",
        "signing_worker_ecdsa_presignature_pool_put_call",
        "require_signing_worker_ecdsa_presignature_pool_put_response_v1",
        "worker::Response::from_json(&receipt)",
    ] {
        assert!(
            body.contains(required),
            "ECDSA-HSS pool-fill private fetch must include `{required}`"
        );
    }
    assert!(
        !body.contains("CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1::new("),
        "pool-fill fetch must delegate record construction to the validated boundary type"
    );
}

#[test]
fn ecdsa_hss_presignature_state_uses_distinct_one_use_storage() {
    let durable_object_rs = read_src_file("durable_object.rs");
    for required in [
        "CloudflareSigningWorkerEcdsaPresignatureRecordV1",
        "CloudflareSigningWorkerEcdsaPresignatureLookupV1",
        "CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1",
        "CloudflareSigningWorkerEcdsaPresignaturePoolRecordV1",
        "CloudflareSigningWorkerEcdsaPresignaturePoolLookupV1",
        "CloudflareSigningWorkerEcdsaPresignaturePoolPutReceiptV1",
        "signing-worker-ecdsa-presignature",
        "signing-worker-ecdsa-presignature-pool",
        "SigningWorkerEcdsaPresignaturePut",
        "SigningWorkerEcdsaPresignatureTake",
        "SigningWorkerEcdsaPresignatureCleanupExpired",
        "SigningWorkerEcdsaPresignaturePoolPut",
        "SigningWorkerEcdsaPresignaturePoolTake",
        "SigningWorkerEcdsaPresignaturePoolCleanupExpired",
        "rerandomization_entropy32_b64u",
        "record.validate_for_lookup(lookup)?",
        "take_signing_worker_ecdsa_presignature",
        "take_signing_worker_ecdsa_presignature_pool",
        "worker_storage_delete(storage, &storage_key, call.operation_kind()).await?",
    ] {
        assert!(
            durable_object_rs.contains(required),
            "ECDSA-HSS presignature Durable Object state must include `{required}`"
        );
    }

    let receipt_body = extract_braced_block_after_marker(
        &durable_object_rs,
        "pub struct CloudflareSigningWorkerEcdsaPresignaturePutReceiptV1",
    );
    for forbidden in ["server_k_share32_b64u", "server_sigma_share32_b64u"] {
        assert!(
            !receipt_body.contains(forbidden),
            "ECDSA-HSS presignature put receipt must not expose `{forbidden}`"
        );
    }
}
