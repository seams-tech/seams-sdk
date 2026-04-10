use ecdsa_hss::{
    encode_context_v1,
    hidden_eval_boundary_from_staged_request_and_response_v1, AllowedOutputKindV1,
    EcdsaHssContextV1, HiddenEvalBoundaryV1,
    HiddenEvalInputBoundaryV1, HiddenEvalPersistedStateBoundaryV1,
    HiddenEvalTransportBoundaryV1, PrepareEnvelopeV1, RespondRequestV1,
    ServerEvalOperationV1, ServerPrepareInputsV1, StagedServerSessionV1, VisibleClientBoundaryV1,
    VisibleExplicitExportBoundaryV1, VisibleFinalizeBoundaryV1, VisibleNonExportBoundaryV1,
    VisibleOperationBoundaryV1,
};
use ecdsa_hss::fixtures::{FixtureCorpusFile, COMMITTED_FIXTURE_CORPUS_JSON};
use k256::elliptic_curve::bigint::U512;
use k256::elliptic_curve::ops::Reduce;
use k256::{FieldBytes, NonZeroScalar, SecretKey, WideBytes};
use num_bigint::BigUint;
use num_traits::Num;
use sha2::{Digest, Sha512};

const CANONICAL_X_DOMAIN_TAG: &[u8] = b"ecdsa-hss:v1:canonical-x";
const ADDITIVE_CLIENT_DOMAIN_TAG: &[u8] = b"ecdsa-hss:v1:additive-share:client";
const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn hex_to_array_32(hex: &str) -> [u8; 32] {
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    for idx in (0..hex.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&hex[idx..idx + 2], 16).expect("hex decode"));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn committed_fixture_corpus_file() -> FixtureCorpusFile {
    serde_json::from_str(COMMITTED_FIXTURE_CORPUS_JSON).expect("fixture corpus")
}

fn secp256k1_order() -> BigUint {
    BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16).expect("parse secp256k1 order")
}

fn reduce_digest_formula(digest64: &[u8; 64]) -> [u8; 32] {
    let order = secp256k1_order();
    let one = BigUint::from(1u8);
    let reduced = (BigUint::from_bytes_be(digest64) % (&order - &one)) + &one;
    let bytes = reduced.to_bytes_be();
    let mut out = [0u8; 32];
    out[(32 - bytes.len())..].copy_from_slice(&bytes);
    out
}

fn reduce_digest_k256(digest64: &[u8; 64]) -> [u8; 32] {
    let mut wide = WideBytes::default();
    wide.copy_from_slice(digest64);
    let reduced = <NonZeroScalar as Reduce<U512>>::reduce_bytes(&wide);
    let field_bytes = FieldBytes::from(reduced);
    let mut out = [0u8; 32];
    out.copy_from_slice(field_bytes.as_ref());
    out
}

fn nonzero_scalar_roundtrip_bytes(bytes32: &[u8; 32]) -> [u8; 32] {
    let secret = SecretKey::from_slice(bytes32).expect("valid non-zero scalar");
    let scalar = secret.to_nonzero_scalar();
    let field_bytes = FieldBytes::from(&scalar);
    let mut out = [0u8; 32];
    out.copy_from_slice(field_bytes.as_ref());
    out
}

fn sample_hidden_eval_boundary(operation: ServerEvalOperationV1) -> HiddenEvalBoundaryV1 {
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation,
            context: EcdsaHssContextV1::new("anti-drift.test.near", "evm-signing", "v1"),
        },
        y_relayer32_le: [0x42u8; 32],
    })
    .expect("prepare");
    let request = RespondRequestV1 {
        y_client32_le: [0x24u8; 32],
    };
    let response = staged.clone().respond(&request).expect("respond");
    hidden_eval_boundary_from_staged_request_and_response_v1(&staged, &request, &response)
        .expect("hidden-eval boundary")
}

#[test]
fn anti_drift_hidden_eval_input_boundary_shape_matches_frozen_seam() {
    let boundary = sample_hidden_eval_boundary(ServerEvalOperationV1::NonExportSign);
    let HiddenEvalBoundaryV1 {
        input:
            HiddenEvalInputBoundaryV1 {
                operation,
                allowed_output_kind,
                context,
                y_client32_le,
                y_relayer32_le,
            },
        transport: _,
        persisted: _,
    } = boundary;

    assert_eq!(operation, ServerEvalOperationV1::NonExportSign);
    assert_eq!(allowed_output_kind, AllowedOutputKindV1::ThresholdMaterialOnly);
    assert_eq!(context.near_account_id, "anti-drift.test.near");
    assert_eq!(context.key_purpose, "evm-signing");
    assert_eq!(context.key_version, "v1");
    assert_eq!(y_client32_le, [0x24u8; 32]);
    assert_eq!(y_relayer32_le, [0x42u8; 32]);
}

#[test]
fn anti_drift_hidden_eval_non_export_transport_shape_matches_frozen_seam() {
    let boundary = sample_hidden_eval_boundary(ServerEvalOperationV1::NonExportSign);
    let HiddenEvalBoundaryV1 {
        input: _,
        transport,
        persisted:
            HiddenEvalPersistedStateBoundaryV1 {
                operation: persisted_operation,
                raw_root_material_dropped: persisted_raw_root_material_dropped,
                relayer_threshold_share32: _,
                relayer_public_key33: _,
                threshold_public_key33: persisted_threshold_public_key33,
                threshold_ethereum_address20: persisted_threshold_ethereum_address20,
                retry_counter: persisted_retry_counter,
            },
    } = boundary;
    let HiddenEvalTransportBoundaryV1 {
        operation:
            VisibleOperationBoundaryV1 {
                operation,
                allowed_output_kind,
            },
        client_output,
        finalize:
            VisibleFinalizeBoundaryV1 {
                operation: finalize_operation,
                raw_root_material_dropped,
                threshold_public_key33: finalize_threshold_public_key33,
                threshold_ethereum_address20: finalize_threshold_ethereum_address20,
                retry_counter: finalize_retry_counter,
            },
    } = transport;
    let VisibleClientBoundaryV1::NonExport(VisibleNonExportBoundaryV1 {
        x_client32,
        client_public_key33,
        threshold_public_key33,
        threshold_ethereum_address20,
        retry_counter,
    }) = client_output
    else {
        panic!("non-export operation must use non-export transport boundary");
    };

    assert_eq!(operation, ServerEvalOperationV1::NonExportSign);
    assert_eq!(allowed_output_kind, AllowedOutputKindV1::ThresholdMaterialOnly);
    assert_ne!(x_client32, [0u8; 32]);
    assert_eq!(client_public_key33.len(), 33);
    assert_eq!(threshold_public_key33.len(), 33);
    assert_eq!(threshold_ethereum_address20.len(), 20);
    assert_eq!(finalize_operation, operation);
    assert!(raw_root_material_dropped);
    assert_eq!(persisted_operation, operation);
    assert!(persisted_raw_root_material_dropped);
    assert_eq!(finalize_threshold_public_key33, threshold_public_key33);
    assert_eq!(persisted_threshold_public_key33, threshold_public_key33);
    assert_eq!(
        finalize_threshold_ethereum_address20,
        threshold_ethereum_address20
    );
    assert_eq!(
        persisted_threshold_ethereum_address20,
        threshold_ethereum_address20
    );
    assert_eq!(finalize_retry_counter, retry_counter);
    assert_eq!(persisted_retry_counter, retry_counter);
}

#[test]
fn anti_drift_hidden_eval_explicit_export_transport_shape_matches_frozen_seam() {
    let boundary = sample_hidden_eval_boundary(ServerEvalOperationV1::ExplicitKeyExport);
    let HiddenEvalBoundaryV1 {
        input:
            HiddenEvalInputBoundaryV1 {
                operation: input_operation,
                allowed_output_kind: input_allowed_output_kind,
                context: _,
                y_client32_le: _,
                y_relayer32_le: _,
            },
        transport,
        persisted:
            HiddenEvalPersistedStateBoundaryV1 {
                operation: persisted_operation,
                raw_root_material_dropped: persisted_raw_root_material_dropped,
                relayer_threshold_share32: _,
                relayer_public_key33: _,
                threshold_public_key33: persisted_threshold_public_key33,
                threshold_ethereum_address20: persisted_threshold_ethereum_address20,
                retry_counter: persisted_retry_counter,
            },
    } = boundary;
    let HiddenEvalTransportBoundaryV1 {
        operation:
            VisibleOperationBoundaryV1 {
                operation,
                allowed_output_kind,
            },
        client_output,
        finalize:
            VisibleFinalizeBoundaryV1 {
                operation: finalize_operation,
                raw_root_material_dropped,
                threshold_public_key33: finalize_threshold_public_key33,
                threshold_ethereum_address20: finalize_threshold_ethereum_address20,
                retry_counter: finalize_retry_counter,
            },
    } = transport;
    let VisibleClientBoundaryV1::ExplicitExport(VisibleExplicitExportBoundaryV1 {
        canonical_x32,
        canonical_public_key33,
        canonical_ethereum_address20,
        x_client32,
        client_public_key33,
        threshold_public_key33,
        threshold_ethereum_address20,
        retry_counter,
    }) = client_output
    else {
        panic!("explicit export operation must use explicit-export transport boundary");
    };

    assert_eq!(input_operation, ServerEvalOperationV1::ExplicitKeyExport);
    assert_eq!(
        input_allowed_output_kind,
        AllowedOutputKindV1::ThresholdMaterialAndCanonicalSecret
    );
    assert_eq!(operation, ServerEvalOperationV1::ExplicitKeyExport);
    assert_eq!(
        allowed_output_kind,
        AllowedOutputKindV1::ThresholdMaterialAndCanonicalSecret
    );
    assert_ne!(canonical_x32, [0u8; 32]);
    assert_eq!(canonical_public_key33.len(), 33);
    assert_eq!(canonical_ethereum_address20.len(), 20);
    assert_ne!(x_client32, [0u8; 32]);
    assert_eq!(client_public_key33.len(), 33);
    assert_eq!(threshold_public_key33.len(), 33);
    assert_eq!(threshold_ethereum_address20.len(), 20);
    assert_eq!(finalize_operation, operation);
    assert!(raw_root_material_dropped);
    assert_eq!(persisted_operation, operation);
    assert!(persisted_raw_root_material_dropped);
    assert_eq!(finalize_threshold_public_key33, threshold_public_key33);
    assert_eq!(persisted_threshold_public_key33, threshold_public_key33);
    assert_eq!(
        finalize_threshold_ethereum_address20,
        threshold_ethereum_address20
    );
    assert_eq!(
        persisted_threshold_ethereum_address20,
        threshold_ethereum_address20
    );
    assert_eq!(finalize_retry_counter, retry_counter);
    assert_eq!(persisted_retry_counter, retry_counter);
}

#[test]
fn anti_drift_k256_nonzero_reduction_matches_frozen_v1_formula() {
    let mut digests = vec![[0u8; 64], [0xffu8; 64], [0x80u8; 64]];
    let mut ramp = [0u8; 64];
    for (idx, byte) in ramp.iter_mut().enumerate() {
        *byte = idx as u8;
    }
    digests.push(ramp);

    for digest in digests {
        assert_eq!(reduce_digest_k256(&digest), reduce_digest_formula(&digest));
    }

    let corpus = committed_fixture_corpus_file();
    for fixture in corpus.fixtures {
        let context = EcdsaHssContextV1::new(
            fixture.context.near_account_id,
            fixture.context.key_purpose,
            fixture.context.key_version,
        );
        let context_bytes = encode_context_v1(&context).expect("encode context");
        let d32 = hex_to_array_32(&fixture.outputs.d32_hex);

        let mut canonical_hasher = Sha512::new();
        canonical_hasher.update(CANONICAL_X_DOMAIN_TAG);
        canonical_hasher.update(&context_bytes);
        canonical_hasher.update(d32);
        let canonical_digest: [u8; 64] = canonical_hasher.finalize().into();
        let canonical_formula = reduce_digest_formula(&canonical_digest);
        assert_eq!(reduce_digest_k256(&canonical_digest), canonical_formula);
        assert_eq!(canonical_formula, hex_to_array_32(&fixture.outputs.x32_hex));

        let x32 = hex_to_array_32(&fixture.outputs.x32_hex);
        let mut share_hasher = Sha512::new();
        share_hasher.update(ADDITIVE_CLIENT_DOMAIN_TAG);
        share_hasher.update(&context_bytes);
        share_hasher.update(fixture.outputs.retry_counter.to_be_bytes());
        share_hasher.update(x32);
        let share_digest: [u8; 64] = share_hasher.finalize().into();
        let client_formula = reduce_digest_formula(&share_digest);
        assert_eq!(reduce_digest_k256(&share_digest), client_formula);
        assert_eq!(client_formula, hex_to_array_32(&fixture.outputs.x_client32_hex));
    }
}

#[test]
fn anti_drift_scalar_byte_encoding_roundtrips_for_production_scalars() {
    let corpus = committed_fixture_corpus_file();
    for fixture in corpus.fixtures {
        for scalar_hex in [
            fixture.outputs.x32_hex.as_str(),
            fixture.outputs.x_client32_hex.as_str(),
            fixture.outputs.x_relayer32_hex.as_str(),
            fixture.outputs.mapped_client_share32_hex.as_str(),
            fixture.outputs.mapped_relayer_share32_hex.as_str(),
        ] {
            let bytes32 = hex_to_array_32(scalar_hex);
            assert_eq!(nonzero_scalar_roundtrip_bytes(&bytes32), bytes32);
        }
    }
}
