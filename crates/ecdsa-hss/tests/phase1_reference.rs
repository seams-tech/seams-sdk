use ecdsa_hss::fixtures::{
    deterministic_fixture_corpus, deterministic_hidden_derivation_fixture_corpus,
};
use ecdsa_hss::{
    bootstrap_evm_threshold_v1, bootstrap_registration_evm_threshold_v1,
    bootstrap_session_evm_threshold_v1, compute_client_signature_share_v1,
    derive_additive_shares_v1, derive_canonical_secret_v1, encode_context_v1,
    export_evm_threshold_v1, export_from_respond_response_v1, export_from_session_v1,
    finalize_signature_v1, init_client_presign_session_v1, init_relayer_presign_session_v1,
    hidden_eval_boundary_from_staged_request_and_response_v1,
    parse_presignature97_v1, prepare_explicit_export_session_v1, prepare_signing_session_v1,
    sign_with_session_v1, verify_single_key_invariant_v1,
    visible_boundary_from_respond_response_v1, AllowedOutputKindV1, ClientOutputV1,
    EcdsaHssStableKeyContextV1, EvmThresholdBootstrapAdapterV1, EvmThresholdBootstrapRequestV1,
    EvmThresholdExportRequestV1, EvmThresholdSigningOperationV1, PrepareEnvelopeV1,
    RespondRequestV1, RootShareInputsV1, ServerEvalOperationV1, ServerPrepareInputsV1,
    StagedServerSessionV1, VisibleClientBoundaryV1, VisibleClientBoundaryV1::ExplicitExport,
    VisibleClientBoundaryV1::NonExport,
};
use hex::encode as hex_encode;
use num_bigint::BigUint;
use num_traits::Num;
use signer_core::error::SignerCoreErrorCode;

const SECP256K1_ORDER_HEX: &str =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

fn test_context(
    wallet_session_user_id: &str,
    key_purpose: &str,
    key_version: &str,
) -> EcdsaHssStableKeyContextV1 {
    EcdsaHssStableKeyContextV1::new(
        wallet_session_user_id,
        wallet_session_user_id,
        "evm:eip155:11155111",
        "ehss-test-key",
        "test-root",
        "root-v1",
        key_purpose,
        key_version,
    )
}

fn push_expected_ascii(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn sign_with_evm_threshold_adapter(
    adapter: &EvmThresholdBootstrapAdapterV1,
    digest32: [u8; 32],
    entropy32: [u8; 32],
) -> [u8; 65] {
    let mut client = init_client_presign_session_v1(adapter).expect("client presign init");
    let mut relayer = init_relayer_presign_session_v1(adapter).expect("relayer presign init");
    let mut pending_client_incoming: Vec<Vec<u8>> = Vec::new();
    let mut pending_relayer_incoming: Vec<Vec<u8>> = Vec::new();

    for _ in 0..64 {
        for msg in pending_client_incoming.drain(..) {
            client
                .message(adapter.relayer.participant_id, &msg)
                .expect("deliver relayer->client");
        }
        for msg in pending_relayer_incoming.drain(..) {
            relayer
                .message(adapter.client.participant_id, &msg)
                .expect("deliver client->relayer");
        }

        if client.stage() == "triples_done" && relayer.stage() == "triples_done" {
            client.start_presign().expect("client start presign");
            relayer.start_presign().expect("relayer start presign");
        }

        let client_progress = client.poll().expect("client poll");
        for msg in client_progress.outgoing {
            pending_relayer_incoming.push(msg);
        }

        let relayer_progress = relayer.poll().expect("relayer poll");
        for msg in relayer_progress.outgoing {
            pending_client_incoming.push(msg);
        }

        if client.is_done() && relayer.is_done() {
            break;
        }
    }

    assert!(client.is_done(), "client presign session should complete");
    assert!(relayer.is_done(), "relayer presign session should complete");

    let client_presignature = parse_presignature97_v1(
        &client
            .take_presignature_97()
            .expect("client presignature bytes"),
    )
    .expect("parse client presignature");
    let relayer_presignature = parse_presignature97_v1(
        &relayer
            .take_presignature_97()
            .expect("relayer presignature bytes"),
    )
    .expect("parse relayer presignature");
    assert_eq!(client_presignature.big_r33, relayer_presignature.big_r33);

    let client_signature_share32 =
        compute_client_signature_share_v1(adapter, &client_presignature, &digest32, &entropy32)
            .expect("client signature share");
    finalize_signature_v1(
        adapter,
        &relayer_presignature,
        &digest32,
        &entropy32,
        &client_signature_share32,
    )
    .expect("finalize signature")
}

fn assert_signing_session_roundtrip(
    operation: EvmThresholdSigningOperationV1,
    context: EcdsaHssStableKeyContextV1,
    y_client32_le: [u8; 32],
    y_relayer32_le: [u8; 32],
    digest32: [u8; 32],
    entropy32: [u8; 32],
) {
    let session = prepare_signing_session_v1(operation, context, y_client32_le, y_relayer32_le)
        .expect("prepare signing session");
    let signature65 =
        sign_with_session_v1(&session, &digest32, &entropy32).expect("sign with prepared session");
    assert_eq!(signature65.len(), 65);
}

fn biguint_to_32_be(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    assert!(bytes.len() <= 32, "value must fit into 32 bytes");
    let mut out = [0u8; 32];
    out[(32 - bytes.len())..].copy_from_slice(&bytes);
    out
}

#[test]
fn encode_context_v1_matches_frozen_layout() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let encoded = encode_context_v1(&context).expect("encode context");

    let mut expected = Vec::new();
    expected.extend_from_slice(b"ecdsa-hss:context:v1");
    push_expected_ascii(&mut expected, "ecdsa-hss-v1");
    push_expected_ascii(&mut expected, "secp256k1");
    push_expected_ascii(&mut expected, "alice.test.near");
    push_expected_ascii(&mut expected, "alice.test.near");
    push_expected_ascii(&mut expected, "evm:eip155:11155111");
    push_expected_ascii(&mut expected, "ehss-test-key");
    push_expected_ascii(&mut expected, "test-root");
    push_expected_ascii(&mut expected, "root-v1");
    push_expected_ascii(&mut expected, "evm-signing");
    push_expected_ascii(&mut expected, "v1");
    expected.push(2);
    expected.extend_from_slice(&1u16.to_be_bytes());
    expected.extend_from_slice(&2u16.to_be_bytes());

    assert_eq!(encoded, expected);
}

#[test]
fn canonical_secret_derivation_is_deterministic_and_valid() {
    let context = test_context("alpha.test.near", "evm-signing", "v1");
    let y_client = [0x11u8; 32];
    let y_relayer = [0x22u8; 32];

    let root_shares = RootShareInputsV1::new(y_client, y_relayer);
    let first = derive_canonical_secret_v1(&root_shares, &context).expect("first derive");
    let second = derive_canonical_secret_v1(&root_shares, &context).expect("second derive");

    assert_eq!(first, second);
    assert_ne!(first.x32, [0u8; 32]);
    assert_eq!(first.public_key33.len(), 33);
    assert_eq!(first.ethereum_address20.len(), 20);
}

#[test]
fn additive_share_derivation_is_deterministic_and_preserves_the_secret() {
    let context = test_context("beta.test.near", "evm-signing", "v2");
    let y_client = [0x33u8; 32];
    let y_relayer = [0x44u8; 32];
    let canonical =
        derive_canonical_secret_v1(&RootShareInputsV1::new(y_client, y_relayer), &context)
            .expect("canonical");

    let first = derive_additive_shares_v1(&canonical.x32, &context).expect("first shares");
    let second = derive_additive_shares_v1(&canonical.x32, &context).expect("second shares");
    assert_eq!(first, second);
    assert_ne!(first.x_client32, canonical.x32);
    assert_ne!(first.x_client32, [0u8; 32]);
    assert_ne!(first.x_relayer32, [0u8; 32]);

    let order = BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16).expect("order");
    let x = BigUint::from_bytes_be(&canonical.x32);
    let x_client = BigUint::from_bytes_be(&first.x_client32);
    let x_relayer = BigUint::from_bytes_be(&first.x_relayer32);

    assert_eq!((x_client + x_relayer) % order, x);
    verify_single_key_invariant_v1(&canonical, &first).expect("single-key invariant");
}

#[test]
fn deterministic_fixture_corpus_satisfies_phase1_invariants() {
    let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
    assert!(!fixtures.is_empty(), "fixture corpus should not be empty");

    for fixture in fixtures {
        assert_eq!(
            fixture.canonical.public_key33, fixture.additive_shares.threshold_public_key33,
            "threshold public key mismatch for {}",
            fixture.name
        );
        assert_eq!(
            fixture.canonical.ethereum_address20,
            fixture.additive_shares.threshold_ethereum_address20,
            "threshold address mismatch for {}",
            fixture.name
        );
        assert_eq!(
            fixture.additive_shares.mapped_client_share32.len(),
            32,
            "mapped client share length mismatch for {}",
            fixture.name
        );
        assert_eq!(
            fixture.additive_shares.mapped_relayer_share32.len(),
            32,
            "mapped relayer share length mismatch for {}",
            fixture.name
        );
    }
}

#[test]
fn frozen_fixture_wraparound_case_keeps_zero_d_visible() {
    let fixtures = deterministic_fixture_corpus().expect("fixture corpus");
    let wraparound = fixtures
        .iter()
        .find(|fixture| fixture.name == "wraparound-zero-d")
        .expect("wraparound fixture");

    assert_eq!(wraparound.canonical.d32, [0u8; 32]);
    assert_eq!(
        hex_encode(wraparound.canonical.context_bytes.as_slice()),
        "65636473612d6873733a636f6e746578743a7631000c65636473612d6873732d76310009736563703235366b3100147772617061726f756e642e746573742e6e65617200127772617061726f756e642d7375626a656374001365766d3a6569703135353a3131313535313131000f656873732d7772617061726f756e64001770726f6a6563742d616c7068613a656e762d616c7068610007726f6f742d7631000b65766d2d7369676e696e67000776312d777261700200010002"
    );
}

#[test]
fn encode_context_v1_rejects_non_ascii_fields() {
    let context = test_context("alice.test.near", "evm-signing", "v1-東京");
    let err = encode_context_v1(&context).expect_err("non-ascii key_version should fail");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn additive_share_derivation_rejects_zero_scalar_input() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let err = derive_additive_shares_v1(&[0u8; 32], &context).expect_err("zero scalar should fail");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn additive_share_derivation_rejects_group_order_scalar_input() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let order = BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16).expect("order");
    let mut x32 = [0u8; 32];
    let bytes = order.to_bytes_be();
    x32[(32 - bytes.len())..].copy_from_slice(&bytes);

    let err = derive_additive_shares_v1(&x32, &context)
        .expect_err("scalar equal to secp256k1 group order should fail");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn additive_share_derivation_accepts_scalar_domain_boundaries() {
    let context = test_context("boundary.test.near", "evm-signing", "v1");
    let order = BigUint::from_str_radix(SECP256K1_ORDER_HEX, 16).expect("order");

    for (label, x32) in [
        ("scalar-one", biguint_to_32_be(&BigUint::from(1u8))),
        ("scalar-order-minus-one", biguint_to_32_be(&(&order - BigUint::from(1u8)))),
    ] {
        let shares = derive_additive_shares_v1(&x32, &context)
            .unwrap_or_else(|err| panic!("{label} should derive additive shares: {err}"));

        let x = BigUint::from_bytes_be(&x32);
        let x_client = BigUint::from_bytes_be(&shares.x_client32);
        let x_relayer = BigUint::from_bytes_be(&shares.x_relayer32);

        assert_ne!(shares.x_client32, [0u8; 32], "{label} client share must be non-zero");
        assert_ne!(
            shares.x_relayer32,
            [0u8; 32],
            "{label} relayer share must be non-zero"
        );
        assert_eq!(
            (x_client + x_relayer) % &order,
            x,
            "{label} shares must reconstruct the scalar"
        );
        assert_eq!(
            shares.threshold_public_key33.len(),
            33,
            "{label} threshold public key must stay compressed",
        );
        assert_eq!(
            shares.threshold_ethereum_address20.len(),
            20,
            "{label} threshold address must stay 20 bytes",
        );
    }
}

#[test]
fn canonical_secret_changes_when_context_changes() {
    let y_client = [0x55u8; 32];
    let y_relayer = [0x66u8; 32];
    let root_shares = RootShareInputsV1::new(y_client, y_relayer);

    let left = derive_canonical_secret_v1(
        &root_shares,
        &test_context("alice.test.near", "evm-signing", "v1"),
    )
    .expect("left canonical");
    let right = derive_canonical_secret_v1(
        &root_shares,
        &test_context("alice.test.near", "evm-export", "v1"),
    )
    .expect("right canonical");

    assert_ne!(left.context_bytes, right.context_bytes);
    assert_ne!(left.x32, right.x32);
    assert_ne!(left.public_key33, right.public_key33);
    assert_ne!(left.ethereum_address20, right.ethereum_address20);
}

#[test]
fn canonical_secret_changes_when_stable_key_identity_changes() {
    let root_shares = RootShareInputsV1::new([0x57u8; 32], [0x67u8; 32]);
    let base = EcdsaHssStableKeyContextV1::new(
        "alice.test.near",
        "alice-subject",
        "evm:eip155:11155111",
        "ehss-test-key",
        "test-root",
        "root-v1",
        "evm-signing",
        "v1",
    );
    let base_secret = derive_canonical_secret_v1(&root_shares, &base).expect("base canonical");

    let variants = [
        EcdsaHssStableKeyContextV1::new(
            "alice.test.near",
            "alice-subject",
            "tempo:42431",
            "ehss-test-key",
            "test-root",
            "root-v1",
            "evm-signing",
            "v1",
        ),
        EcdsaHssStableKeyContextV1::new(
            "alice.test.near",
            "alice-subject",
            "evm:eip155:11155111",
            "ehss-other-key",
            "test-root",
            "root-v1",
            "evm-signing",
            "v1",
        ),
        EcdsaHssStableKeyContextV1::new(
            "alice.test.near",
            "alice-subject",
            "evm:eip155:11155111",
            "ehss-test-key",
            "other-root",
            "root-v1",
            "evm-signing",
            "v1",
        ),
        EcdsaHssStableKeyContextV1::new(
            "alice.test.near",
            "alice-subject",
            "evm:eip155:11155111",
            "ehss-test-key",
            "test-root",
            "root-v2",
            "evm-signing",
            "v1",
        ),
    ];

    for variant in variants {
        let variant_secret =
            derive_canonical_secret_v1(&root_shares, &variant).expect("variant canonical");
        assert_ne!(base_secret.context_bytes, variant_secret.context_bytes);
        assert_ne!(base_secret.public_key33, variant_secret.public_key33);
        assert_ne!(
            base_secret.ethereum_address20,
            variant_secret.ethereum_address20
        );
    }
}

#[test]
fn single_key_invariant_rejects_mismatched_canonical_and_share_material() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let left = derive_canonical_secret_v1(
        &RootShareInputsV1::new([0x10u8; 32], [0x20u8; 32]),
        &context,
    )
    .expect("left canonical");
    let right = derive_canonical_secret_v1(
        &RootShareInputsV1::new([0x30u8; 32], [0x40u8; 32]),
        &context,
    )
    .expect("right canonical");
    let shares = derive_additive_shares_v1(&right.x32, &context).expect("shares");

    let err = verify_single_key_invariant_v1(&left, &shares)
        .expect_err("mismatched canonical/share material should fail");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn additive_share_derivation_changes_with_canonical_secret() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let left = derive_canonical_secret_v1(
        &RootShareInputsV1::new([0x01u8; 32], [0x02u8; 32]),
        &context,
    )
    .expect("left canonical");
    let right = derive_canonical_secret_v1(
        &RootShareInputsV1::new([0x03u8; 32], [0x04u8; 32]),
        &context,
    )
    .expect("right canonical");

    let left_shares = derive_additive_shares_v1(&left.x32, &context).expect("left shares");
    let right_shares = derive_additive_shares_v1(&right.x32, &context).expect("right shares");

    assert_ne!(left_shares.x_client32, right_shares.x_client32);
    assert_ne!(left_shares.x_relayer32, right_shares.x_relayer32);
    assert_ne!(
        left_shares.threshold_public_key33,
        right_shares.threshold_public_key33
    );
    assert_ne!(
        left_shares.threshold_ethereum_address20,
        right_shares.threshold_ethereum_address20
    );
}

#[test]
fn staged_server_session_is_deterministic_for_non_export() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let request = RespondRequestV1 {
        y_client32_le: [0x11u8; 32],
    };

    let left = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context: context.clone(),
        },
        y_relayer32_le: [0x22u8; 32],
    })
    .expect("left prepare");
    let right = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context,
        },
        y_relayer32_le: [0x22u8; 32],
    })
    .expect("right prepare");

    let left = left.respond(&request).expect("left respond");
    let right = right.respond(&request).expect("right respond");
    assert_eq!(left, right);
}

#[test]
fn non_export_output_excludes_canonical_secret_and_drops_raw_roots() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let request = RespondRequestV1 {
        y_client32_le: [0x33u8; 32],
    };
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context,
        },
        y_relayer32_le: [0x44u8; 32],
    })
    .expect("prepare");

    let response = staged.respond(&request).expect("respond");
    let output = response.client_output.clone();
    let finalized = response.finalized_server_session.clone();
    assert_eq!(
        output.allowed_output_kind(),
        AllowedOutputKindV1::ThresholdMaterialOnly
    );
    match &output {
        ClientOutputV1::NonExport(output) => {
            assert_ne!(output.x_client32, [0u8; 32]);
            assert_ne!(output.threshold_public_key33, [0u8; 33]);
        }
        ClientOutputV1::ExplicitExport(_) => {
            panic!("non-export operation must not return explicit-export output")
        }
    }
    assert!(finalized.retained.raw_root_material_dropped);
    assert_ne!(finalized.retained.relayer_threshold_share32, [0u8; 32]);
}

#[test]
fn explicit_export_output_includes_canonical_secret_and_keeps_identity_aligned() {
    let context = test_context("alice.test.near", "evm-export", "v1");
    let request = RespondRequestV1 {
        y_client32_le: [0x55u8; 32],
    };
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context: context.clone(),
        },
        y_relayer32_le: [0x66u8; 32],
    })
    .expect("prepare");

    let response = staged.respond(&request).expect("respond");
    let output = response.client_output.clone();
    let finalized = response.finalized_server_session.clone();
    assert_eq!(
        output.allowed_output_kind(),
        AllowedOutputKindV1::ThresholdMaterialAndCanonicalSecret
    );
    let ClientOutputV1::ExplicitExport(output) = &output else {
        panic!("explicit export must return explicit-export output");
    };
    let canonical = derive_canonical_secret_v1(
        &RootShareInputsV1::new(request.y_client32_le, [0x66u8; 32]),
        &context,
    )
    .expect("x");
    assert_eq!(output.canonical_x32, canonical.x32);
    assert_eq!(output.canonical_public_key33, canonical.public_key33);
    assert_eq!(
        output.canonical_ethereum_address20,
        canonical.ethereum_address20
    );
    assert_eq!(
        output.threshold_public_key33,
        finalized.retained.threshold_public_key33
    );
    assert_eq!(
        output.threshold_ethereum_address20,
        finalized.retained.threshold_ethereum_address20
    );
}

#[test]
fn hidden_derivation_fixture_corpus_is_deterministic_and_respects_output_policies() {
    let fixtures = deterministic_hidden_derivation_fixture_corpus().expect("hidden fixtures");
    assert!(
        !fixtures.is_empty(),
        "hidden fixture corpus should not be empty"
    );

    for fixture in fixtures {
        assert!(
            fixture
                .finalized_server_session
                .retained
                .raw_root_material_dropped
        );
        match fixture.operation {
            ServerEvalOperationV1::ExplicitKeyExport => {
                assert_eq!(
                    fixture.client_output.allowed_output_kind(),
                    AllowedOutputKindV1::ThresholdMaterialAndCanonicalSecret
                );
            }
            ServerEvalOperationV1::RegistrationBootstrap
            | ServerEvalOperationV1::SessionBootstrap
            | ServerEvalOperationV1::NonExportSign => {
                assert_eq!(
                    fixture.client_output.allowed_output_kind(),
                    AllowedOutputKindV1::ThresholdMaterialOnly
                );
            }
        }
    }
}

#[test]
fn finalize_envelope_must_match_retained_server_state() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let request = RespondRequestV1 {
        y_client32_le: [0x77u8; 32],
    };
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context,
        },
        y_relayer32_le: [0x88u8; 32],
    })
    .expect("prepare");

    let response = staged.respond(&request).expect("respond");
    response
        .finalized_server_session
        .validate_finalize_envelope(&response.finalize)
        .expect("matching finalize envelope should validate");

    let mut tampered = response.finalize;
    tampered.retry_counter = tampered.retry_counter.wrapping_add(1);
    let err = response
        .finalized_server_session
        .validate_finalize_envelope(&tampered)
        .expect_err("tampered finalize envelope should fail");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn reference_boundary_projects_non_export_response_shape() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let response = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context,
        },
        y_relayer32_le: [0x91u8; 32],
    })
    .expect("prepare")
    .respond(&RespondRequestV1 {
        y_client32_le: [0x92u8; 32],
    })
    .expect("respond");

    let boundary =
        visible_boundary_from_respond_response_v1(&response).expect("reference boundary");

    assert_eq!(
        boundary.operation.operation,
        ServerEvalOperationV1::NonExportSign
    );
    assert_eq!(
        boundary.operation.allowed_output_kind,
        AllowedOutputKindV1::ThresholdMaterialOnly
    );
    let VisibleClientBoundaryV1::NonExport(output) = boundary.client_output else {
        panic!("expected non-export boundary");
    };
    assert_eq!(
        output.threshold_public_key33,
        response
            .finalized_server_session
            .retained
            .threshold_public_key33
    );
    assert_eq!(
        boundary.finalize.threshold_ethereum_address20,
        response
            .finalized_server_session
            .retained
            .threshold_ethereum_address20
    );
    assert!(boundary.retained.raw_root_material_dropped);
}

#[test]
fn reference_boundary_projects_explicit_export_response_shape() {
    let context = test_context("alice.test.near", "evm-export", "v1");
    let response = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context,
        },
        y_relayer32_le: [0xa1u8; 32],
    })
    .expect("prepare")
    .respond(&RespondRequestV1 {
        y_client32_le: [0xa2u8; 32],
    })
    .expect("respond");

    let boundary =
        visible_boundary_from_respond_response_v1(&response).expect("reference boundary");

    assert_eq!(
        boundary.operation.allowed_output_kind,
        AllowedOutputKindV1::ThresholdMaterialAndCanonicalSecret
    );
    let VisibleClientBoundaryV1::ExplicitExport(output) = boundary.client_output else {
        panic!("expected explicit-export boundary");
    };
    assert_ne!(output.canonical_x32, [0u8; 32]);
    assert_eq!(
        output.threshold_public_key33,
        response
            .finalized_server_session
            .retained
            .threshold_public_key33
    );
    assert_eq!(
        boundary.retained.retry_counter,
        response.finalized_server_session.retained.retry_counter
    );
}

#[test]
fn server_owned_state_does_not_gain_canonical_secret_on_export_path() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let y_client32_le = [0xb1u8; 32];
    let y_relayer32_le = [0xb2u8; 32];

    let non_export = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context: context.clone(),
        },
        y_relayer32_le,
    })
    .expect("prepare non-export")
    .respond(&RespondRequestV1 { y_client32_le })
    .expect("respond non-export");

    let explicit_export = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context: context.clone(),
        },
        y_relayer32_le,
    })
    .expect("prepare explicit export")
    .respond(&RespondRequestV1 { y_client32_le })
    .expect("respond explicit export");

    let canonical = derive_canonical_secret_v1(
        &RootShareInputsV1::new(y_client32_le, y_relayer32_le),
        &context,
    )
    .expect("derive canonical secret");

    assert_eq!(
        non_export.finalized_server_session.retained,
        explicit_export.finalized_server_session.retained,
        "server-owned retained state must not become export-capable based on operation",
    );
    assert_eq!(
        non_export.finalize.raw_root_material_dropped,
        explicit_export.finalize.raw_root_material_dropped,
    );
    assert_eq!(
        non_export.finalize.threshold_public_key33,
        explicit_export.finalize.threshold_public_key33,
    );
    assert_eq!(
        non_export.finalize.threshold_ethereum_address20,
        explicit_export.finalize.threshold_ethereum_address20,
    );
    assert_eq!(
        non_export.finalize.retry_counter,
        explicit_export.finalize.retry_counter,
    );

    assert_ne!(
        non_export
            .finalized_server_session
            .retained
            .relayer_threshold_share32,
        canonical.x32,
        "server retained share must not equal the canonical secret",
    );

    let ClientOutputV1::NonExport(non_export_output) = &non_export.client_output else {
        panic!("expected non-export client output");
    };
    assert_ne!(
        non_export_output.x_client32, canonical.x32,
        "client threshold share must not equal the canonical secret on the non-export path",
    );

    let ClientOutputV1::ExplicitExport(explicit_export_output) = &explicit_export.client_output
    else {
        panic!("expected explicit-export client output");
    };
    assert_eq!(explicit_export_output.canonical_x32, canonical.x32);
    assert_eq!(
        explicit_export_output.threshold_public_key33,
        non_export
            .finalized_server_session
            .retained
            .threshold_public_key33,
    );
}

#[test]
fn evm_threshold_adapter_uses_current_backend_seam() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context,
        },
        y_relayer32_le: [0x99u8; 32],
    })
    .expect("prepare");
    let response = staged
        .respond(&RespondRequestV1 {
            y_client32_le: [0xaau8; 32],
        })
        .expect("respond");

    let adapter = EvmThresholdBootstrapAdapterV1::from_respond_response(&response)
        .expect("adapt to current backend seam");

    assert_eq!(adapter.identity.participant_ids, [1, 2]);
    assert_eq!(
        adapter.identity.group_public_key33,
        response
            .finalized_server_session
            .retained
            .threshold_public_key33
    );
    assert_eq!(
        adapter.client.group_public_key33,
        adapter.relayer.group_public_key33
    );
    assert_eq!(
        adapter.client.ethereum_address20,
        adapter.relayer.ethereum_address20
    );
    assert_ne!(adapter.client.threshold_private_share32, [0u8; 32]);
    assert_ne!(adapter.relayer.threshold_private_share32, [0u8; 32]);
}

#[test]
fn hidden_eval_boundary_freezes_input_transport_and_persisted_shapes() {
    let context = test_context("hidden-eval.test.near", "evm-signing", "v1");
    let y_client32_le = [0x41u8; 32];
    let y_relayer32_le = [0x82u8; 32];
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context: context.clone(),
        },
        y_relayer32_le,
    })
    .expect("prepare");
    let request = RespondRequestV1 { y_client32_le };
    let response = staged.clone().respond(&request).expect("respond");

    let boundary = hidden_eval_boundary_from_staged_request_and_response_v1(
        &staged, &request, &response,
    )
    .expect("hidden-eval boundary");

    assert_eq!(boundary.input.operation, ServerEvalOperationV1::NonExportSign);
    assert_eq!(
        boundary.input.allowed_output_kind,
        AllowedOutputKindV1::ThresholdMaterialOnly
    );
    assert_eq!(boundary.input.context, context);
    assert_eq!(boundary.input.y_client32_le, y_client32_le);
    assert_eq!(boundary.input.y_relayer32_le, y_relayer32_le);

    assert_eq!(
        boundary.transport.operation.allowed_output_kind,
        AllowedOutputKindV1::ThresholdMaterialOnly
    );
    assert!(matches!(boundary.transport.client_output, NonExport(_)));
    assert_eq!(
        boundary.transport.finalize.threshold_public_key33,
        response.finalize.threshold_public_key33
    );

    assert!(boundary.persisted.raw_root_material_dropped);
    assert_eq!(
        boundary.persisted.relayer_threshold_share32,
        response
            .finalized_server_session
            .retained
            .relayer_threshold_share32
    );
}

#[test]
fn hidden_eval_boundary_reserves_canonical_secret_to_explicit_export_transport_only() {
    let context = test_context("hidden-eval.test.near", "evm-export", "v1");
    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::ExplicitKeyExport,
            context,
        },
        y_relayer32_le: [0x33u8; 32],
    })
    .expect("prepare");
    let request = RespondRequestV1 {
        y_client32_le: [0x77u8; 32],
    };
    let response = staged.clone().respond(&request).expect("respond");

    let boundary = hidden_eval_boundary_from_staged_request_and_response_v1(
        &staged, &request, &response,
    )
    .expect("hidden-eval boundary");

    let ExplicitExport(explicit_export) = boundary.transport.client_output else {
        panic!("explicit export should surface canonical secret only on export flow");
    };
    assert_ne!(explicit_export.canonical_x32, [0u8; 32]);
    assert_eq!(boundary.persisted.threshold_public_key33, explicit_export.threshold_public_key33);
    assert_eq!(
        boundary.persisted.threshold_ethereum_address20,
        explicit_export.threshold_ethereum_address20
    );
}

#[test]
fn evm_threshold_bootstrap_entrypoint_matches_manual_staged_flow() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let y_client32_le = [0xbbu8; 32];
    let y_relayer32_le = [0xccu8; 32];

    let staged = StagedServerSessionV1::prepare(ServerPrepareInputsV1 {
        prepare: PrepareEnvelopeV1 {
            operation: ServerEvalOperationV1::NonExportSign,
            context: context.clone(),
        },
        y_relayer32_le,
    })
    .expect("manual prepare");
    let manual_response = staged
        .respond(&RespondRequestV1 { y_client32_le })
        .expect("manual respond");
    let manual_adapter = EvmThresholdBootstrapAdapterV1::from_respond_response(&manual_response)
        .expect("manual adapter");

    let bootstrapped = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context,
        y_client32_le,
        y_relayer32_le,
    })
    .expect("bootstrap");

    assert_eq!(bootstrapped.response, manual_response);
    assert_eq!(bootstrapped.adapter, manual_adapter);
}

#[test]
fn evm_threshold_adapter_can_drive_current_presign_and_sign_backend() {
    let bootstrapped = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context: test_context("alice.test.near", "evm-signing", "v1"),
        y_client32_le: [0xddu8; 32],
        y_relayer32_le: [0xeeu8; 32],
    })
    .expect("bootstrap");

    let signature65 =
        sign_with_evm_threshold_adapter(&bootstrapped.adapter, [0x12u8; 32], [0x34u8; 32]);
    assert_eq!(signature65.len(), 65);
}

#[test]
fn export_extractor_rejects_non_export_responses() {
    let response = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context: test_context("alice.test.near", "evm-signing", "v1"),
        y_client32_le: [0x21u8; 32],
        y_relayer32_le: [0x43u8; 32],
    })
    .expect("bootstrap")
    .response
    .clone();

    let err = export_from_respond_response_v1(&response)
        .expect_err("non-export response must not be extractable as canonical export");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn evm_threshold_adapter_rejects_tampered_client_public_key() {
    let mut response = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context: test_context("alice.test.near", "evm-signing", "v1"),
        y_client32_le: [0x24u8; 32],
        y_relayer32_le: [0x68u8; 32],
    })
    .expect("bootstrap")
    .response
    .clone();

    match &mut response.client_output {
        ClientOutputV1::NonExport(output) => output.client_public_key33[10] ^= 0x01,
        ClientOutputV1::ExplicitExport(_) => panic!("expected non-export response"),
    }

    let err = EvmThresholdBootstrapAdapterV1::from_respond_response(&response)
        .expect_err("tampered client public key must be rejected");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn evm_threshold_adapter_rejects_tampered_threshold_identity() {
    let mut response = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context: test_context("alice.test.near", "evm-signing", "v1"),
        y_client32_le: [0x29u8; 32],
        y_relayer32_le: [0x6bu8; 32],
    })
    .expect("bootstrap")
    .response
    .clone();

    response
        .finalized_server_session
        .retained
        .relayer_public_key33[7] ^= 0x01;

    let err = EvmThresholdBootstrapAdapterV1::from_respond_response(&response)
        .expect_err("tampered relayer public key must be rejected");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn export_extractor_rejects_tampered_canonical_public_key() {
    let mut response = export_evm_threshold_v1(EvmThresholdExportRequestV1 {
        context: test_context("alice.test.near", "evm-signing", "v1"),
        y_client32_le: [0x35u8; 32],
        y_relayer32_le: [0x57u8; 32],
    })
    .expect("export")
    .bootstrap
    .response
    .clone();

    match &mut response.client_output {
        ClientOutputV1::ExplicitExport(output) => output.canonical_public_key33[12] ^= 0x01,
        ClientOutputV1::NonExport(_) => panic!("expected explicit-export response"),
    }

    let err = export_from_respond_response_v1(&response)
        .expect_err("tampered canonical export tuple must be rejected");
    assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
}

#[test]
fn explicit_export_entrypoint_returns_same_identity_as_non_export_sign_path() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let y_client32_le = [0x31u8; 32];
    let y_relayer32_le = [0x53u8; 32];

    let sign_bootstrap = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context: context.clone(),
        y_client32_le,
        y_relayer32_le,
    })
    .expect("sign bootstrap");
    let export_result = export_evm_threshold_v1(EvmThresholdExportRequestV1 {
        context,
        y_client32_le,
        y_relayer32_le,
    })
    .expect("explicit export");

    assert_eq!(
        export_result.exported.canonical_public_key33,
        sign_bootstrap.adapter.identity.group_public_key33
    );
    assert_eq!(
        export_result.exported.canonical_ethereum_address20,
        sign_bootstrap.adapter.identity.ethereum_address20
    );
    assert_eq!(
        export_result.bootstrap.adapter.identity.group_public_key33,
        sign_bootstrap.adapter.identity.group_public_key33
    );
    assert_eq!(
        export_result.bootstrap.adapter.identity.ethereum_address20,
        sign_bootstrap.adapter.identity.ethereum_address20
    );
}

#[test]
fn one_key_lifecycle_bootstrap_sign_export_preserves_identity() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let y_client32_le = [0x61u8; 32];
    let y_relayer32_le = [0x71u8; 32];

    let sign_bootstrap = bootstrap_evm_threshold_v1(EvmThresholdBootstrapRequestV1 {
        operation: ServerEvalOperationV1::NonExportSign,
        context: context.clone(),
        y_client32_le,
        y_relayer32_le,
    })
    .expect("sign bootstrap");
    let signature65 =
        sign_with_evm_threshold_adapter(&sign_bootstrap.adapter, [0x91u8; 32], [0xa1u8; 32]);
    assert_eq!(signature65.len(), 65);

    let export_result = export_evm_threshold_v1(EvmThresholdExportRequestV1 {
        context,
        y_client32_le,
        y_relayer32_le,
    })
    .expect("explicit export");

    assert_eq!(
        sign_bootstrap.adapter.identity.group_public_key33,
        export_result.exported.canonical_public_key33
    );
    assert_eq!(
        sign_bootstrap.adapter.identity.ethereum_address20,
        export_result.exported.canonical_ethereum_address20
    );
    assert_eq!(
        sign_bootstrap.adapter.identity.group_public_key33,
        export_result.bootstrap.adapter.identity.group_public_key33
    );
    assert_eq!(
        sign_bootstrap.adapter.identity.ethereum_address20,
        export_result.bootstrap.adapter.identity.ethereum_address20
    );
}

#[test]
fn typed_session_api_binds_signing_and_export_policies() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let y_client32_le = [0x41u8; 32];
    let y_relayer32_le = [0x51u8; 32];

    for operation in [
        EvmThresholdSigningOperationV1::NonExportSign,
        EvmThresholdSigningOperationV1::RegistrationBootstrap,
        EvmThresholdSigningOperationV1::SessionBootstrap,
    ] {
        let sign_session =
            prepare_signing_session_v1(operation, context.clone(), y_client32_le, y_relayer32_le)
                .expect("sign session");
        let err = export_from_respond_response_v1(&sign_session.bootstrap.response)
            .expect_err("signing session response must not be reusable as export");
        assert_eq!(err.code, SignerCoreErrorCode::InvalidInput);
    }

    let export_session = prepare_explicit_export_session_v1(context, y_client32_le, y_relayer32_le)
        .expect("export session");
    let exported = export_from_session_v1(&export_session);
    assert_eq!(
        exported.canonical_public_key33,
        export_session
            .export
            .bootstrap
            .adapter
            .identity
            .group_public_key33
    );
    assert_eq!(
        exported.canonical_ethereum_address20,
        export_session
            .export
            .bootstrap
            .adapter
            .identity
            .ethereum_address20
    );
}

#[test]
fn typed_session_api_supports_registration_and_login_bootstrap_modes() {
    assert_signing_session_roundtrip(
        EvmThresholdSigningOperationV1::RegistrationBootstrap,
        test_context("alice.test.near", "evm-signing", "v1"),
        [0x01u8; 32],
        [0x02u8; 32],
        [0x03u8; 32],
        [0x04u8; 32],
    );
    assert_signing_session_roundtrip(
        EvmThresholdSigningOperationV1::SessionBootstrap,
        test_context("alice.test.near", "evm-signing", "v1"),
        [0x05u8; 32],
        [0x06u8; 32],
        [0x07u8; 32],
        [0x08u8; 32],
    );
}

#[test]
fn registration_bootstrap_sign_export_preserves_identity() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let y_client32_le = [0x81u8; 32];
    let y_relayer32_le = [0x91u8; 32];

    let registration =
        bootstrap_registration_evm_threshold_v1(context.clone(), y_client32_le, y_relayer32_le)
            .expect("registration bootstrap");
    assert_eq!(
        registration.response.finalized_server_session.operation,
        ServerEvalOperationV1::RegistrationBootstrap
    );

    let signature65 =
        sign_with_evm_threshold_adapter(&registration.adapter, [0xb1u8; 32], [0xc1u8; 32]);
    assert_eq!(signature65.len(), 65);

    let export_result = export_evm_threshold_v1(EvmThresholdExportRequestV1 {
        context,
        y_client32_le,
        y_relayer32_le,
    })
    .expect("export");
    assert_eq!(
        registration.adapter.identity.group_public_key33,
        export_result.exported.canonical_public_key33
    );
    assert_eq!(
        registration.adapter.identity.ethereum_address20,
        export_result.exported.canonical_ethereum_address20
    );
}

#[test]
fn session_bootstrap_sign_export_preserves_identity() {
    let context = test_context("alice.test.near", "evm-signing", "v1");
    let y_client32_le = [0xa1u8; 32];
    let y_relayer32_le = [0xb1u8; 32];

    let session =
        bootstrap_session_evm_threshold_v1(context.clone(), y_client32_le, y_relayer32_le)
            .expect("session bootstrap");
    assert_eq!(
        session.response.finalized_server_session.operation,
        ServerEvalOperationV1::SessionBootstrap
    );

    let signature65 = sign_with_evm_threshold_adapter(&session.adapter, [0xd1u8; 32], [0xe1u8; 32]);
    assert_eq!(signature65.len(), 65);

    let export_result = export_evm_threshold_v1(EvmThresholdExportRequestV1 {
        context,
        y_client32_le,
        y_relayer32_le,
    })
    .expect("export");
    assert_eq!(
        session.adapter.identity.group_public_key33,
        export_result.exported.canonical_public_key33
    );
    assert_eq!(
        session.adapter.identity.ethereum_address20,
        export_result.exported.canonical_ethereum_address20
    );
}
